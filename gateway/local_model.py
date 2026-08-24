"""自带本地模型：用官方 llama.cpp 的 llama-server 跑一个本机 OpenAI 兼容端点，
网关再用 openai_compat provider 接它（见 router._build 的 local 自动注册）。

为什么用 llama-server 子进程而不是进程内 llama-cpp-python：官方二进制带「运行时按 CPU
自动选指令集」(ggml-cpu-*.dll 多变体)，在 AVX2/AVX-512/老 CPU 上都能跑；而 PyPI 预编译
wheel 是固定指令集（实测 AVX-512 wheel 在 AVX2 机器上直接非法指令崩），不适合商用分发。

商用/空版可把 llama-server 二进制 + 已审 GGUF 打进包。运行期远程下载默认关闭；只有运维同时
提供不可变 revision、SHA-256 和显式开关时才允许下载。二进制、相邻动态库、模型或其哈希证明
任一缺失则 available()=False、整条功能自动隐身。这样不会把 ModelScope 的浮动 ``master``
变成首启远程代码/模型通道。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import stat as stat_module
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from http.client import HTTPConnection, HTTPException
from pathlib import Path
from typing import Any, Optional

from gateway.runtime_profile import (
    ExternalProgramAuthority,
    RuntimeCapability,
    current_runtime_profile,
)

LOCAL_PORT = int(os.getenv("LOCAL_LLAMA_PORT", "8091"))
_N_CTX = int(os.getenv("LOCAL_LLAMA_CTX", "4096"))

_proc: Optional[subprocess.Popen] = None
_ready_alias: Optional[str] = None
_lock = threading.Lock()
_stop_requested = threading.Event()

_MAX_BINARY_BYTES = 512 * 1024 * 1024
_MAX_DEPENDENCY_BYTES = 512 * 1024 * 1024
_MAX_MODEL_BYTES = 128 * 1024 * 1024 * 1024
_MAX_ACTIVE_BYTES = 1024
_REPARSE_ATTRIBUTE = int(
    getattr(stat_module, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
)


@dataclass(frozen=True)
class _FileIdentity:
    device: int
    inode: int
    mode: int
    size: int
    modified_ns: int
    changed_ns: int


def _identity(info: os.stat_result) -> _FileIdentity:
    return _FileIdentity(
        device=int(info.st_dev),
        inode=int(info.st_ino),
        mode=int(info.st_mode),
        size=int(info.st_size),
        modified_ns=int(info.st_mtime_ns),
        changed_ns=int(info.st_ctime_ns),
    )


def _same_open_file(path_identity: _FileIdentity, handle_identity: _FileIdentity) -> bool:
    # Windows CRT ``fstat`` reports creation time in st_ctime while ``lstat``
    # reports metadata-change time.  The stable file-id fields must agree;
    # path-side ctime is still compared before/after below.
    return (
        path_identity.device,
        path_identity.inode,
        stat_module.S_IFMT(path_identity.mode),
        path_identity.size,
        path_identity.modified_ns,
    ) == (
        handle_identity.device,
        handle_identity.inode,
        stat_module.S_IFMT(handle_identity.mode),
        handle_identity.size,
        handle_identity.modified_ns,
    )


def _is_absolute_clean_path(path: str | os.PathLike[str]) -> bool:
    candidate = Path(path)
    return candidate.is_absolute() and not any(part in {".", ".."} for part in candidate.parts)


def _path_components_are_real(path: str | os.PathLike[str]) -> bool:
    """Reject symlinks, junctions and every other Windows reparse component."""
    candidate = Path(path)
    if not _is_absolute_clean_path(candidate):
        return False
    try:
        for component in reversed((candidate, *candidate.parents)):
            info = os.lstat(component)
            if stat_module.S_ISLNK(info.st_mode):
                return False
            if int(getattr(info, "st_file_attributes", 0)) & _REPARSE_ATTRIBUTE:
                return False
            is_junction = getattr(component, "is_junction", None)
            if is_junction is not None and is_junction():
                return False
        return True
    except (OSError, RuntimeError, ValueError):
        return False


def _safe_directory(path: str | os.PathLike[str]) -> Optional[Path]:
    candidate = Path(path)
    if not _path_components_are_real(candidate):
        return None
    try:
        info = os.lstat(candidate)
        return candidate if stat_module.S_ISDIR(info.st_mode) else None
    except OSError:
        return None


def _safe_directory_target(path: str | os.PathLike[str]) -> Optional[Path]:
    """Validate an absolute create target through its nearest existing parent."""
    candidate = Path(path)
    if not _is_absolute_clean_path(candidate):
        return None
    cursor = candidate
    try:
        while not os.path.lexists(cursor):
            parent = cursor.parent
            if parent == cursor:
                return None
            cursor = parent
        if cursor == candidate:
            return candidate if _safe_directory(candidate) is not None else None
        return candidate if _safe_directory(cursor) is not None else None
    except OSError:
        return None


def _safe_file_identity(
    path: str | os.PathLike[str],
    *,
    min_bytes: int,
    max_bytes: int,
    suffix: str | None = None,
) -> Optional[_FileIdentity]:
    candidate = Path(path)
    if not _path_components_are_real(candidate):
        return None
    if suffix is not None and candidate.suffix.lower() != suffix.lower():
        return None
    try:
        info = os.lstat(candidate)
        if not stat_module.S_ISREG(info.st_mode):
            return None
        if not min_bytes <= int(info.st_size) <= max_bytes:
            return None
        return _identity(info)
    except OSError:
        return None


def _stable_file_read(
    path: str | os.PathLike[str],
    *,
    min_bytes: int,
    max_bytes: int,
    suffix: str | None = None,
    collect: bool = False,
) -> tuple[str, bytes] | None:
    """Hash through one handle and prove the path still names that same file."""
    candidate = Path(path)
    before = _safe_file_identity(
        candidate,
        min_bytes=min_bytes,
        max_bytes=max_bytes,
        suffix=suffix,
    )
    if before is None:
        return None
    flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    fd: int | None = None
    try:
        fd = os.open(candidate, flags)
        opened = _identity(os.fstat(fd))
        if not _same_open_file(before, opened):
            return None
        digest = hashlib.sha256()
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            digest.update(chunk)
            if collect:
                chunks.append(chunk)
        if _identity(os.fstat(fd)) != opened:
            return None
    except OSError:
        return None
    finally:
        if fd is not None:
            os.close(fd)
    after = _safe_file_identity(
        candidate,
        min_bytes=min_bytes,
        max_bytes=max_bytes,
        suffix=suffix,
    )
    if after != before:
        return None
    return digest.hexdigest(), b"".join(chunks) if collect else b""


def _stable_prefix_read(
    path: str | os.PathLike[str],
    count: int,
    *,
    min_bytes: int,
    max_bytes: int,
    suffix: str | None = None,
) -> bytes | None:
    candidate = Path(path)
    before = _safe_file_identity(
        candidate,
        min_bytes=min_bytes,
        max_bytes=max_bytes,
        suffix=suffix,
    )
    if before is None:
        return None
    flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    fd: int | None = None
    try:
        fd = os.open(candidate, flags)
        opened = _identity(os.fstat(fd))
        if not _same_open_file(before, opened):
            return None
        prefix = os.read(fd, count)
        if _identity(os.fstat(fd)) != opened:
            return None
    except OSError:
        return None
    finally:
        if fd is not None:
            os.close(fd)
    after = _safe_file_identity(
        candidate,
        min_bytes=min_bytes,
        max_bytes=max_bytes,
        suffix=suffix,
    )
    return prefix if after == before else None


def _safe_binary_file(path: str | os.PathLike[str]) -> bool:
    candidate = Path(path)
    if sys.platform == "win32" and candidate.suffix.lower() != ".exe":
        return False
    return _safe_file_identity(
        candidate, min_bytes=1, max_bytes=_MAX_BINARY_BYTES
    ) is not None


def _safe_model_file(path: str | os.PathLike[str]) -> bool:
    prefix = _stable_prefix_read(
        path,
        4,
        min_bytes=4,
        max_bytes=_MAX_MODEL_BYTES,
        suffix=".gguf",
    )
    return prefix == b"GGUF"


def _safe_active_name(directory: Path) -> tuple[bool, Optional[str]]:
    """Return (marker_present, selected basename); invalid markers fail closed."""
    marker = directory / ".active"
    try:
        os.lstat(marker)
    except FileNotFoundError:
        return False, None
    except OSError:
        return True, None
    result = _stable_file_read(
        marker,
        min_bytes=1,
        max_bytes=_MAX_ACTIVE_BYTES,
        collect=True,
    )
    if result is None:
        return True, None
    try:
        text = result[1].decode("utf-8")
    except UnicodeError:
        return True, None
    lines = text.splitlines()
    if len(lines) != 1:
        return True, None
    name = lines[0].strip()
    if (
        not name
        or name != Path(name).name
        or "/" in name
        or "\\" in name
        or any(ord(char) < 32 for char in name)
        or any(char in '<>:"|?*' for char in name)
        or Path(name).suffix.lower() != ".gguf"
    ):
        return True, None
    return True, name


def _binary_path() -> Optional[str]:
    """定位 llama-server 可执行：env LLAMA_SERVER_BIN（显式文件）→ env LLAMA_SERVER_DIR 下找。"""
    exe = "llama-server.exe" if sys.platform == "win32" else "llama-server"
    p = str(os.getenv("LLAMA_SERVER_BIN") or "").strip()
    if p:
        return str(Path(p)) if _safe_binary_file(p) else None
    d = str(os.getenv("LLAMA_SERVER_DIR") or "").strip()
    directory = _safe_directory(d) if d else None
    if directory is not None:
        candidate = directory / exe
        if _safe_binary_file(candidate):
            return str(candidate)
    return None


def gguf_path() -> Optional[str]:
    """定位本地 GGUF：env LOCAL_MODEL_PATH（单文件）→ env LOCAL_MODEL_DIR 扫 *.gguf。"""
    p = str(os.getenv("LOCAL_MODEL_PATH") or "").strip()
    if p:
        return str(Path(p)) if _safe_model_file(p) else None
    d = str(os.getenv("LOCAL_MODEL_DIR") or "").strip()
    directory = _safe_directory(d) if d else None
    if directory is not None:
        marker_present, active_name = _safe_active_name(directory)
        if marker_present:
            if active_name is None:
                return None
            selected = directory / active_name
            return str(selected) if _safe_model_file(selected) else None
        try:
            candidates = sorted(os.scandir(directory), key=lambda entry: entry.name.casefold())
            for entry in candidates:
                if not entry.name.lower().endswith(".gguf"):
                    continue
                if not entry.is_file(follow_symlinks=False) or not _safe_model_file(entry.path):
                    return None
                return str(Path(entry.path))
        except OSError:
            return None
    return None


def available() -> bool:
    """二进制、模型及其 SHA-256 证明都有效时才注册 local 模型。"""
    binp, model = _binary_path(), gguf_path()
    return bool(binp and model and _local_runtime_attested(binp, model))


def base_url() -> str:
    return f"http://127.0.0.1:{LOCAL_PORT}/v1" if available() else ""


def ready_model_alias() -> str:
    """Return the nonce-bound upstream model id only while its managed process lives."""
    with _lock:
        if _proc is not None and _proc.poll() is None and _ready_alias:
            return _ready_alias
        return ""


# ── 免费可商用本地模型目录（都是 Apache-2.0；国内 ModelScope 直链免账号；按机器配置选） ──
CATALOG: list[dict[str, Any]] = [
    {"id": "qwen2.5-0.5b", "name": "Qwen2.5 0.5B", "repo": "Qwen/Qwen2.5-0.5B-Instruct-GGUF",
     "file": "qwen2.5-0.5b-instruct-q4_k_m.gguf", "size_mb": 470,
     "desc": "最轻，老机器/低配也能跑；能力有限，建议配联网搜索"},
    {"id": "qwen2.5-1.5b", "name": "Qwen2.5 1.5B", "repo": "Qwen/Qwen2.5-1.5B-Instruct-GGUF",
     "file": "qwen2.5-1.5b-instruct-q4_k_m.gguf", "size_mb": 1070, "desc": "均衡默认，多数机器流畅"},
    {"id": "qwen2.5-3b", "name": "Qwen2.5 3B", "repo": "Qwen/Qwen2.5-3B-Instruct-GGUF",
     "file": "qwen2.5-3b-instruct-q4_k_m.gguf", "size_mb": 2100, "desc": "更强，建议 8G+ 内存"},
    {"id": "qwen2.5-7b", "name": "Qwen2.5 7B", "repo": "Qwen/Qwen2.5-7B-Instruct-GGUF",
     "file": "qwen2.5-7b-instruct-q4_k_m.gguf", "size_mb": 4700, "desc": "强，建议 16G+ 内存/较好 CPU"},
    {"id": "qwen2.5-coder-7b", "name": "Qwen2.5-Coder 7B", "repo": "Qwen/Qwen2.5-Coder-7B-Instruct-GGUF",
     "file": "qwen2.5-coder-7b-instruct-q4_k_m.gguf", "size_mb": 4700, "desc": "编程专用，建议 16G+ 内存"},
]
DEFAULT_MODEL_ID = os.getenv("LOCAL_MODEL_ID", "qwen2.5-1.5b")

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_REVISION_RE = re.compile(r"^[0-9a-fA-F]{40,64}$")
_REMOTE_DOWNLOAD_FLAG = "NACHUAN_ENABLE_VERIFIED_MODEL_DOWNLOAD"
_RUNTIME_MANIFEST_ENV = "NACHUAN_LOCAL_RUNTIME_MANIFEST"
_MAX_MANIFEST_BYTES = 256 * 1024
_DEFAULT_START_TIMEOUT = 90.0
_RUNTIME_ENV_ALLOWLIST = (
    "SYSTEMROOT",
    "WINDIR",
    "SYSTEMDRIVE",
    "COMSPEC",
    "TEMP",
    "TMP",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
)


def _entry(model_id: str) -> Optional[dict[str, Any]]:
    return next((e for e in CATALOG if e["id"] == model_id), None)


def should_autodownload() -> bool:
    """仅在完整供应链证明存在时允许首启下载；官方包默认返回 False。"""
    model_dir = str(os.getenv("LOCAL_MODEL_DIR") or "").strip()
    return bool(
        os.getenv("LOCAL_MODEL_AUTODOWNLOAD") == "1"
        and os.getenv(_REMOTE_DOWNLOAD_FLAG) == "1"
        and model_dir
        and _safe_directory_target(model_dir) is not None
        and _download_pin(_entry(DEFAULT_MODEL_ID))
    )


def _download_pin(entry: Optional[dict[str, Any]]) -> Optional[tuple[str, str]]:
    """返回不可变 (revision, sha256)；缺任一项即拒绝远程下载。"""
    if not entry:
        return None
    revision = str(entry.get("revision") or os.getenv("LOCAL_MODEL_REVISION") or "").strip()
    digest = str(entry.get("sha256") or os.getenv("LOCAL_MODEL_SHA256") or "").strip().lower()
    if not _REVISION_RE.fullmatch(revision) or not _SHA256_RE.fullmatch(digest):
        return None
    return revision, digest


def _sha256(path: str) -> str:
    result = _stable_file_read(
        path,
        min_bytes=1,
        max_bytes=_MAX_MODEL_BYTES,
    )
    if result is None:
        raise OSError("file changed or crossed a redirect while hashing")
    return result[0]


def _matches_digest(path: str, expected: str) -> bool:
    try:
        return hmac.compare_digest(_sha256(path), expected.lower())
    except OSError:
        return False


def _canonical_path(path: str) -> str:
    return os.path.normcase(os.path.realpath(os.path.abspath(path)))


def _is_runtime_library_name(name: str) -> bool:
    lowered = str(name).lower()
    return (
        lowered.endswith((".dll", ".dylib", ".so"))
        or ".so." in lowered
    )


def _load_runtime_manifest() -> Optional[dict[str, tuple[str, str]]]:
    """Load a small, path-bound audit manifest; malformed manifests are unusable."""
    manifest_path = os.getenv(_RUNTIME_MANIFEST_ENV, "").strip()
    if not manifest_path:
        return {}
    try:
        if not _is_absolute_clean_path(manifest_path):
            return None
        manifest_read = _stable_file_read(
            manifest_path,
            min_bytes=2,
            max_bytes=_MAX_MANIFEST_BYTES,
            collect=True,
        )
        if manifest_read is None:
            return None
        payload = json.loads(manifest_read[1].decode("utf-8"))
        if not isinstance(payload, dict) or payload.get("schema") != 1:
            return None
        artifacts = payload.get("artifacts")
        if not isinstance(artifacts, list) or len(artifacts) > 4096:
            return None
        root = os.path.dirname(manifest_path)
        if _safe_directory(root) is None:
            return None
        canonical_root = _canonical_path(root)
        result: dict[str, tuple[str, str]] = {}
        valid_roles = {"llama-server", "runtime-dependency", "model"}
        for artifact in artifacts:
            if not isinstance(artifact, dict):
                return None
            role = artifact.get("role")
            relpath = artifact.get("path")
            digest = str(artifact.get("sha256") or "").strip().lower()
            if role not in valid_roles or not isinstance(relpath, str) or not relpath.strip():
                return None
            if not _SHA256_RE.fullmatch(digest):
                return None
            if (
                os.path.isabs(relpath)
                or "\\" in relpath
                or relpath.startswith("/")
                or any(part in {"", ".", ".."} for part in relpath.split("/"))
            ):
                return None
            parts = relpath.split("/")
            allowed_roots = {
                "llama-server": {"llama", "runtime"},
                "runtime-dependency": {"llama", "runtime"},
                "model": {"models"},
            }
            if parts[0] not in allowed_roots[role]:
                return None
            candidate = os.path.join(root, *parts)
            if role == "llama-server" and not _safe_binary_file(candidate):
                return None
            if role == "runtime-dependency" and (
                not _is_runtime_library_name(parts[-1])
                or _safe_file_identity(
                    candidate,
                    min_bytes=1,
                    max_bytes=_MAX_DEPENDENCY_BYTES,
                )
                is None
            ):
                return None
            if role == "model" and not _safe_model_file(candidate):
                return None
            canonical = _canonical_path(candidate)
            if os.path.commonpath((canonical_root, canonical)) != canonical_root:
                return None
            if canonical in result:
                return None
            result[canonical] = (role, digest)
        return result
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        return None


def _runtime_dependencies(binary: str) -> Optional[list[str]]:
    """Enumerate adjacent native libraries that may be loaded by llama-server."""
    try:
        if not _safe_binary_file(binary):
            return None
        runtime_dir = Path(binary).parent
        before = os.lstat(runtime_dir)
        if _safe_directory(runtime_dir) is None:
            return None
        dependencies = []
        for entry in os.scandir(runtime_dir):
            if not _is_runtime_library_name(entry.name):
                continue
            # A library-looking link/reparse/directory is an attack, not an
            # ignorable non-file.  Never follow it during enumeration.
            if not entry.is_file(follow_symlinks=False):
                return None
            if _safe_file_identity(
                entry.path,
                min_bytes=1,
                max_bytes=_MAX_DEPENDENCY_BYTES,
            ) is None:
                return None
            dependencies.append(entry.path)
        after = os.lstat(runtime_dir)
        if _identity(before) != _identity(after) or _safe_directory(runtime_dir) is None:
            return None
        return sorted(dependencies, key=_canonical_path)
    except OSError:
        return None


def _attested_artifact(
    path: str,
    role: str,
    manifest: dict[str, tuple[str, str]],
    env_name: Optional[str] = None,
) -> bool:
    raw_env = os.getenv(env_name, "").strip() if env_name else ""
    if raw_env:
        expected = raw_env.lower() if _SHA256_RE.fullmatch(raw_env) else None
    else:
        manifest_entry = manifest.get(_canonical_path(path))
        expected = manifest_entry[1] if manifest_entry and manifest_entry[0] == role else None
    if not expected:
        return False
    if role == "llama-server":
        if not _safe_binary_file(path):
            return False
        max_bytes = _MAX_BINARY_BYTES
        suffix = ".exe" if sys.platform == "win32" else None
    elif role == "runtime-dependency":
        if not _is_runtime_library_name(Path(path).name):
            return False
        max_bytes = _MAX_DEPENDENCY_BYTES
        suffix = None
    elif role == "model":
        if not _safe_model_file(path):
            return False
        max_bytes = _MAX_MODEL_BYTES
        suffix = ".gguf"
    else:
        return False
    result = _stable_file_read(
        path,
        min_bytes=1,
        max_bytes=max_bytes,
        suffix=suffix,
    )
    return bool(result and hmac.compare_digest(result[0], expected))


def _artifact_identity(path: str, role: str) -> Optional[_FileIdentity]:
    if role == "llama-server":
        suffix = ".exe" if sys.platform == "win32" else None
        maximum = _MAX_BINARY_BYTES
    elif role == "runtime-dependency":
        suffix = None
        maximum = _MAX_DEPENDENCY_BYTES
    elif role == "model":
        suffix = ".gguf"
        maximum = _MAX_MODEL_BYTES
    else:
        return None
    return _safe_file_identity(path, min_bytes=1, max_bytes=maximum, suffix=suffix)


def _profile_allows_runtime_manifest(
    manifest: dict[str, tuple[str, str]],
) -> bool:
    profile = current_runtime_profile()
    if not profile.allows(RuntimeCapability.PACKAGED_LOCAL_MODEL_PROGRAM):
        return False
    # Source/development runs retain the existing administrator-attested host
    # tool contract (closed absolute paths plus per-artifact SHA-256).  The
    # final-payload manifest is a store-package authority and must not turn an
    # otherwise valid development fixture into an unusable packaged-runtime
    # simulation.
    if profile.name != "store":
        return profile.allows_external_program(
            authority=ExternalProgramAuthority.ATTESTED_HOST_TOOL,
            role="llama-server",
        )
    roles = frozenset(
        str(entry[0] or "").strip().casefold()
        for entry in manifest.values()
        if isinstance(entry, tuple) and len(entry) == 2
    )
    return profile.allows_external_program(
        authority=ExternalProgramAuthority.FINAL_PAYLOAD_MANIFEST,
        role="llama-server",
        manifest_roles=roles,
    )


def _local_runtime_attested(binary: str, model: str) -> bool:
    """Fail closed unless executable, adjacent libraries and GGUF all match review."""
    if not _is_absolute_clean_path(binary) or not _is_absolute_clean_path(model):
        return False
    if not _safe_binary_file(binary) or not _safe_model_file(model):
        return False
    manifest = _load_runtime_manifest()
    dependencies = _runtime_dependencies(binary)
    if (
        manifest is None
        or dependencies is None
        or not _profile_allows_runtime_manifest(manifest)
    ):
        return False
    snapshots: dict[str, _FileIdentity] = {}
    for path, role in (
        (binary, "llama-server"),
        (model, "model"),
        *((dependency, "runtime-dependency") for dependency in dependencies),
    ):
        identity = _artifact_identity(path, role)
        if identity is None:
            return False
        snapshots[_canonical_path(path)] = identity
    if not _attested_artifact(binary, "llama-server", manifest, "LLAMA_SERVER_SHA256"):
        return False
    if not _attested_artifact(model, "model", manifest, "LOCAL_MODEL_SHA256"):
        return False
    if not all(_attested_artifact(path, "runtime-dependency", manifest) for path in dependencies):
        return False
    final_dependencies = _runtime_dependencies(binary)
    if final_dependencies is None or [
        _canonical_path(path) for path in final_dependencies
    ] != [_canonical_path(path) for path in dependencies]:
        return False
    for path, role in (
        (binary, "llama-server"),
        (model, "model"),
        *((dependency, "runtime-dependency") for dependency in final_dependencies),
    ):
        if _artifact_identity(path, role) != snapshots.get(_canonical_path(path)):
            return False
    return True


def _minimal_runtime_env() -> dict[str, str]:
    """Environment needed for process bootstrap only; never inherit app credentials."""
    source = {str(key).upper(): str(value) for key, value in os.environ.items()}
    result = {name: source[name] for name in _RUNTIME_ENV_ALLOWLIST if name in source}
    result["NO_COLOR"] = "1"
    return result


def _start_timeout() -> float:
    try:
        value = float(os.getenv("LOCAL_LLAMA_START_TIMEOUT", str(_DEFAULT_START_TIMEOUT)))
    except ValueError:
        return _DEFAULT_START_TIMEOUT
    return min(600.0, max(0.01, value))


def _loopback_port_occupied() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", LOCAL_PORT), timeout=0.2):
            return True
    except OSError:
        return False


def _models_endpoint_ready(expected_alias: str) -> bool:
    """Require this launch's nonce alias so an older loopback service cannot fake ready."""
    connection: Optional[HTTPConnection] = None
    try:
        connection = HTTPConnection("127.0.0.1", LOCAL_PORT, timeout=0.5)
        connection.request("GET", "/v1/models", headers={"Accept": "application/json"})
        response = connection.getresponse()
        raw = response.read(64 * 1024 + 1)
        if response.status != 200 or len(raw) > 64 * 1024:
            return False
        payload = json.loads(raw)
        models = payload.get("data") if isinstance(payload, dict) else None
        return bool(
            isinstance(models, list)
            and any(isinstance(model, dict) and model.get("id") == expected_alias for model in models)
        )
    except (OSError, HTTPException, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        return False
    finally:
        if connection is not None:
            connection.close()


def _terminate_started_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    try:
        process.terminate()
        process.wait(timeout=5)
        return
    except Exception:  # noqa: BLE001 -- a failed graceful stop must escalate
        pass
    try:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
    except Exception:  # noqa: BLE001 -- process may have concurrently exited
        pass


def _wait_until_ready(
    process: subprocess.Popen,
    expected_alias: str,
    cancel_event: threading.Event | None = None,
) -> bool:
    deadline = time.monotonic() + _start_timeout()
    while time.monotonic() < deadline:
        if _stop_requested.is_set() or (cancel_event is not None and cancel_event.is_set()):
            return False
        if process.poll() is not None:
            return False
        if _models_endpoint_ready(expected_alias) and process.poll() is None:
            return True
        time.sleep(0.05)
    return False


def active_model_id() -> str:
    """当前选定模型 id：.active 标记 → 已下载的第一个 → 默认。"""
    raw = str(os.getenv("LOCAL_MODEL_DIR") or "").strip()
    directory = _safe_directory(raw) if raw else None
    if directory is not None:
        marker_present, selected = _safe_active_name(directory)
        if marker_present and selected is not None:
            entry = next((x for x in CATALOG if x["file"].lower() == selected.lower()), None)
            if entry and _safe_model_file(directory / selected):
                return entry["id"]
        if not marker_present:
            for entry in CATALOG:
                if _safe_model_file(directory / entry["file"]):
                    return entry["id"]
    return DEFAULT_MODEL_ID


def catalog() -> list[dict[str, Any]]:
    """模型目录 + 状态（downloaded/active），供前端"模型选择"。"""
    raw = str(os.getenv("LOCAL_MODEL_DIR") or "").strip()
    directory = _safe_directory(raw) if raw else None
    have = {
        entry["file"].lower()
        for entry in CATALOG
        if directory is not None and _safe_model_file(directory / entry["file"])
    }
    act = active_model_id()
    return [{**e, "downloaded": e["file"].lower() in have, "active": e["id"] == act} for e in CATALOG]


def _set_active(model_id: str) -> None:
    e = _entry(model_id)
    raw = str(os.getenv("LOCAL_MODEL_DIR") or "").strip()
    directory = _safe_directory(raw) if raw else None
    if not e or directory is None or not _safe_model_file(directory / e["file"]):
        return
    marker = directory / ".active"
    temporary = directory / f".active.{secrets.token_hex(8)}.tmp"
    try:
        if os.path.lexists(marker) and _safe_file_identity(
            marker, min_bytes=1, max_bytes=_MAX_ACTIVE_BYTES
        ) is None:
            return
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | int(getattr(os, "O_BINARY", 0))
        flags |= int(getattr(os, "O_NOFOLLOW", 0))
        fd = os.open(temporary, flags, 0o600)
        try:
            os.write(fd, str(e["file"]).encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        if _safe_directory(directory) is None:
            return
        os.replace(temporary, marker)
        _safe_active_name(directory)
    except OSError:
        pass
    finally:
        try:
            if os.path.lexists(temporary):
                os.remove(temporary)
        except OSError:
            pass


def download_model(model_id: Optional[str] = None, dest_dir: Optional[str] = None) -> Optional[str]:
    """下载固定 revision 且 SHA-256 匹配的 ModelScope GGUF。

    已存在的本地 GGUF 仍可由机主显式使用；任何真正的网络下载都必须有显式开关、不可变
    revision 和预先审阅的 SHA-256。失败安全返回 None、不抛。
    """
    dest_dir = str(dest_dir or os.getenv("LOCAL_MODEL_DIR") or "").strip()
    target_dir = _safe_directory_target(dest_dir) if dest_dir else None
    if target_dir is None:
        return None
    existing_dir = _safe_directory(target_dir)
    if model_id is None and existing_dir is not None:  # 首启自动下载的幂等保护
        try:
            for item in sorted(os.scandir(existing_dir), key=lambda value: value.name.casefold()):
                if not item.name.lower().endswith(".gguf"):
                    continue
                if not item.is_file(follow_symlinks=False) or not _safe_model_file(item.path):
                    return None
                return str(Path(item.path))
        except OSError:
            return None
    e = _entry(model_id or DEFAULT_MODEL_ID) or (CATALOG[0] if CATALOG else None)
    if not e:
        return None
    dest = str(target_dir / e["file"])
    if os.path.lexists(dest):
        if not _safe_model_file(dest):
            return None
        pin = _download_pin(e)
        return dest if not pin or _matches_digest(dest, pin[1]) else None
    if os.getenv(_REMOTE_DOWNLOAD_FLAG) != "1":
        return None
    pin = _download_pin(e)
    if not pin:
        return None
    revision, expected_sha256 = pin
    tmp = dest + ".part"  # 下到 .part 完成再原子改名，半截文件不会被当成可用模型
    try:
        os.makedirs(target_dir, exist_ok=True)
        if _safe_directory(target_dir) is None or os.path.lexists(tmp):
            return None
        url = f"https://modelscope.cn/models/{e['repo']}/resolve/{revision}/{e['file']}"
        import httpx

        max_bytes = (int(e.get("size_mb") or 0) + 128) * 1024 * 1024
        total = 0
        with httpx.stream(
            "GET",
            url,
            follow_redirects=True,
            timeout=httpx.Timeout(connect=20, read=120, write=20, pool=20),
        ) as r:
            r.raise_for_status()
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | int(getattr(os, "O_BINARY", 0))
            flags |= int(getattr(os, "O_NOFOLLOW", 0))
            fd = os.open(tmp, flags, 0o600)
            with os.fdopen(fd, "wb") as fp:
                for chunk in r.iter_bytes(1 << 20):
                    total += len(chunk)
                    if total > max_bytes:
                        raise ValueError("model exceeds reviewed size bound")
                    fp.write(chunk)
                # close() flushes Python's buffer, but it does not make the
                # completed download durable.  Publish only bytes that have
                # reached the filesystem cache/device boundary.
                fp.flush()
                os.fsync(fp.fileno())
        if not _matches_digest(tmp, expected_sha256):
            raise ValueError("model SHA-256 mismatch")
        if _stable_prefix_read(
            tmp, 4, min_bytes=4, max_bytes=_MAX_MODEL_BYTES
        ) != b"GGUF":
            raise ValueError("download is not a GGUF file")
        os.replace(tmp, dest)
        if not (_safe_model_file(dest) and _matches_digest(dest, expected_sha256)):
            # A failed post-publish attestation must never leave a file that a
            # later invocation could mistake for a completed model.
            try:
                os.remove(dest)
            except OSError:
                pass
            return None
        return dest
    except Exception:  # noqa: BLE001
        try:
            os.remove(tmp)
        except OSError:
            pass
        return None


def switch(model_id: str) -> bool:
    """切换本地模型：下载（若缺）→ 设 active → 重启 llama-server。成功 True。大模型要先下载、较耗时。"""
    if not _entry(model_id):
        return False
    if not download_model(model_id):
        return False
    _set_active(model_id)
    stop()
    return start()


def start(cancel_event: threading.Event | None = None) -> bool:
    """就绪则后台拉起 llama-server（幂等）。返回是否在运行。不就绪/失败安全返回 False。"""
    global _proc, _ready_alias
    with _lock:
        _stop_requested.clear()
        if cancel_event is not None and cancel_event.is_set():
            return False
        if _proc is None:
            _ready_alias = None
        if _proc is not None:
            if (
                _proc.poll() is None
                and _ready_alias
                and _models_endpoint_ready(_ready_alias)
                and _proc.poll() is None
            ):
                return True
            stale_process = _proc
            _proc = None
            _ready_alias = None
            _terminate_started_process(stale_process)
        binp, gguf = _binary_path(), gguf_path()
        if not binp or not gguf:
            return False
        # 转绝对路径：llama-server 以二进制目录为 cwd（同目录找 ggml-cpu-*.dll），
        # 故 -m 的模型路径必须是绝对的，否则会按二进制目录去找而落空。
        binp, gguf = os.path.abspath(binp), os.path.abspath(gguf)
        if not _local_runtime_attested(binp, gguf):
            return False
        if _loopback_port_occupied():
            return False
        threads = str(min(8, os.cpu_count() or 4))
        launch_alias = f"nachuan-{secrets.token_hex(16)}"
        cmd = [
            binp, "-m", gguf, "--host", "127.0.0.1", "--port", str(LOCAL_PORT),
            "-c", str(_N_CTX), "-t", threads, "--no-webui", "--alias", launch_alias,
        ]
        # The earlier check protects discovery/port setup.  Repeat the whole
        # manifest, executable, model and adjacent-library attestation at the
        # last possible point before CreateProcess reopens these pathnames.
        if not _local_runtime_attested(binp, gguf):
            return False
        try:
            _proc = subprocess.Popen(
                cmd,
                cwd=os.path.dirname(binp),  # 同目录有 ggml-cpu-*.dll，cwd 设此才找得到
                env=_minimal_runtime_env(),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                shell=False,
            )
        except Exception:  # noqa: BLE001
            _proc = None
            _ready_alias = None
            return False
        if not _wait_until_ready(_proc, launch_alias, cancel_event):
            _terminate_started_process(_proc)
            _proc = None
            _ready_alias = None
            return False
        _ready_alias = launch_alias
        return True


def stop() -> None:
    """关停 llama-server（引擎退出时调用）。"""
    global _proc, _ready_alias
    # Set before taking the lock so an in-progress readiness wait exits promptly.
    _stop_requested.set()
    with _lock:
        _ready_alias = None
        if _proc is not None:
            process = _proc
            _proc = None
            _terminate_started_process(process)
