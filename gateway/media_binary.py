"""Attested process boundary for optional ffmpeg/ffprobe binaries.

Media parsing runs on attacker-controlled files.  Never resolve these tools
through PATH: an operator must bind an absolute executable to its SHA-256, and
the digest is checked again immediately before every process launch.
"""

from __future__ import annotations

import math
import json
import os
import re
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path
from collections.abc import Iterator, Mapping, Sequence

from fastapi import HTTPException

from gateway.providers.attested_cli import AttestedCli, from_environment
from gateway.runtime_profile import (
    ExternalProgramAuthority,
    RuntimeCapability,
    current_runtime_profile,
)


_TOOL_ENV = {
    "ffmpeg": ("FFMPEG_BIN", "FFMPEG_SHA256"),
    "ffprobe": ("FFPROBE_BIN", "FFPROBE_SHA256"),
}

_MEDIA_ENV_PASSTHROUGH = {
    # Windows runtime/DLL bootstrap.  PATH and COMSPEC are intentionally absent.
    "SYSTEMROOT",
    "WINDIR",
    "SYSTEMDRIVE",
    # Scratch files and deterministic text handling.
    "TEMP",
    "TMP",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
}

_MAX_ARGUMENTS = 256
_MAX_ARGUMENT_CHARS = 32_768
_MEDIA_RUNTIME_MANIFEST_ENV = "NACHUAN_MEDIA_RUNTIME_MANIFEST"
_MEDIA_RUNTIME_MANIFEST_SCHEMA = "nachuan.media-runtime-manifest.v1"
_MAX_MEDIA_RUNTIME_MANIFEST_BYTES = 256 * 1024


class MediaBinaryUnavailable(HTTPException):
    """HTTP-aware 503 used when no valid production attestation exists."""

    def __init__(self, message: str):
        self.message = str(message)
        super().__init__(status_code=503, detail=self.message)

    def __str__(self) -> str:
        return self.message


def minimal_media_env(source: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return a tiny child environment with no PATH, API keys, or bot tokens."""

    raw = os.environ if source is None else source
    allowed = {name.upper() for name in _MEDIA_ENV_PASSTHROUGH}
    out = {str(key): str(value) for key, value in raw.items() if str(key).upper() in allowed}
    out["NO_COLOR"] = "1"
    return out


def _configuration_error(tool: str, path_variable: str, hash_variable: str) -> str:
    platform_rule = "Windows 仅接受 .exe" if os.name == "nt" else "POSIX 文件必须可执行"
    return (
        f"{tool} 不可用：必须同时配置 {path_variable}（绝对、普通、非重解析文件；"
        f"{platform_rule}）与 {hash_variable}（64 位 SHA-256），且启动前复核必须通过"
    )


def _normalise_tool(tool: str) -> tuple[str, str, str]:
    normalized = str(tool or "").strip().lower()
    variables = _TOOL_ENV.get(normalized)
    if variables is None:
        raise ValueError(f"unsupported media binary: {tool!r}")
    return normalized, variables[0], variables[1]


def _final_manifest_roles(attested: AttestedCli, *, normalized: str) -> frozenset[str]:
    """Bind a store media executable to the final packaged payload manifest."""

    raw_manifest = str(os.environ.get(_MEDIA_RUNTIME_MANIFEST_ENV) or "").strip()
    manifest_path = Path(raw_manifest)
    try:
        if not raw_manifest or not manifest_path.is_absolute():
            raise OSError("manifest path is not absolute")
        manifest_path = manifest_path.resolve(strict=True)
        info = manifest_path.stat()
        if (
            not manifest_path.is_file()
            or manifest_path.is_symlink()
            or int(getattr(info, "st_file_attributes", 0)) & 0x400
            or info.st_size <= 0
            or info.st_size > _MAX_MEDIA_RUNTIME_MANIFEST_BYTES
        ):
            raise OSError("manifest is not a bounded regular file")
        if bool(getattr(sys, "frozen", False)):
            expected = (Path(sys.executable).resolve().parent.parent / manifest_path.name).resolve()
            if manifest_path != expected or manifest_path.name != "media-runtime-manifest.json":
                raise OSError("manifest is outside the packaged resources root")
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        artifacts = payload.get("artifacts") if isinstance(payload, dict) else None
        if (
            not isinstance(payload, dict)
            or payload.get("schema") != _MEDIA_RUNTIME_MANIFEST_SCHEMA
            or not isinstance(artifacts, list)
            or len(artifacts) != 2
        ):
            raise ValueError("manifest schema is invalid")
        roles: set[str] = set()
        matched = False
        root = manifest_path.parent
        for item in artifacts:
            if not isinstance(item, dict) or set(item) != {"path", "role", "sha256", "size"}:
                raise ValueError("manifest artifact is not canonical")
            role = str(item.get("role") or "").strip().casefold()
            if role not in {"ffmpeg", "ffprobe"} or role in roles:
                raise ValueError("manifest roles are not closed")
            relative = str(item.get("path") or "")
            digest = str(item.get("sha256") or "").strip().casefold()
            size = item.get("size")
            if (
                relative != f"media/{role}.exe"
                or not re.fullmatch(r"[0-9a-f]{64}", digest)
                or isinstance(size, bool)
                or not isinstance(size, int)
                or size <= 0
            ):
                raise ValueError("manifest artifact descriptor is invalid")
            artifact_path = (root / "media" / f"{role}.exe").resolve(strict=True)
            roles.add(role)
            if role == normalized:
                matched = (
                    artifact_path == Path(attested.path).resolve(strict=True)
                    and digest == attested.sha256
                    and size == artifact_path.stat().st_size
                )
        if roles != {"ffmpeg", "ffprobe"} or not matched:
            raise ValueError("manifest does not bind the requested executable")
        return frozenset(roles)
    except (OSError, RuntimeError, UnicodeError, ValueError, json.JSONDecodeError):
        raise MediaBinaryUnavailable(
            f"{normalized} 不可用：商店运行配置只接受最终载荷清单绑定的媒体程序"
        ) from None


def _require_profile_authority(attested: AttestedCli, *, normalized: str) -> None:
    profile = current_runtime_profile()
    if not profile.allows(RuntimeCapability.PACKAGED_MEDIA_PROGRAM):
        raise MediaBinaryUnavailable(f"{normalized} 不可用：当前运行配置已关闭媒体程序")
    if profile.name == "store":
        roles = _final_manifest_roles(attested, normalized=normalized)
        allowed = profile.allows_external_program(
            authority=ExternalProgramAuthority.FINAL_PAYLOAD_MANIFEST,
            role=normalized,
            manifest_roles=roles,
        )
    else:
        allowed = profile.allows_external_program(
            authority=ExternalProgramAuthority.ATTESTED_HOST_TOOL,
            role=normalized,
        )
    if not allowed:
        raise MediaBinaryUnavailable(
            f"{normalized} 不可用：当前运行配置没有外部程序执行授权"
        )


def _require_closed_windows_directory(
    attested: AttestedCli,
    *,
    normalized: str,
    path_variable: str,
    hash_variable: str,
) -> None:
    if os.name != "nt":
        return
    # Gyan essentials is a static build.  Reject every adjacent sidecar present
    # at launch.  This is a snapshot, not a same-SID sandbox: a deployment that
    # must resist an already-running process under the runtime identity needs a
    # separately permissioned launcher/service account.
    allowed = {"ffmpeg.exe", "ffprobe.exe", "ffplay.exe"}
    try:
        entries = list(Path(attested.path).parent.iterdir())
        if not entries or any(
            entry.name.lower() not in allowed
            or not entry.is_file()
            or entry.is_symlink()
            or int(getattr(entry.stat(), "st_file_attributes", 0)) & 0x400
            for entry in entries
        ):
            raise OSError("media binary directory is not a closed static set")
    except OSError:
        raise MediaBinaryUnavailable(
            _configuration_error(normalized, path_variable, hash_variable)
            + "；Windows 可执行目录包含未审核 sidecar"
        ) from None


def _close_windows_handle(handle: int | None) -> None:
    if os.name != "nt" or handle is None:
        return
    import ctypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    kernel32.CloseHandle(ctypes.c_void_p(handle))


def _open_windows_read_pin(path: str, *, directory: bool = False) -> int | None:
    """Deny replacement of one file/directory object while its handle is held.

    A directory-object handle blocks renaming that directory on Windows; it
    does not prevent the same identity from creating a new child within it.
    """

    if os.name != "nt":
        return None
    import ctypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    kernel32.CreateFileW.restype = ctypes.c_void_p
    raw_handle = kernel32.CreateFileW(
        path,
        0x80000000,  # GENERIC_READ
        0x00000001,  # FILE_SHARE_READ only: reject writer/deleter races
        None,
        3,  # OPEN_EXISTING
        (
            0x00200000 | 0x02000000  # OPEN_REPARSE_POINT | BACKUP_SEMANTICS
            if directory
            else 0x00200000 | 0x08000000  # OPEN_REPARSE_POINT | SEQUENTIAL_SCAN
        ),
        None,
    )
    handle = int(raw_handle or 0)
    invalid = ctypes.c_void_p(-1).value
    return None if not handle or handle == invalid else handle


def _windows_final_path(handle: int) -> str | None:
    import ctypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetFinalPathNameByHandleW.argtypes = [
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
    ]
    kernel32.GetFinalPathNameByHandleW.restype = ctypes.c_uint32
    required = int(
        kernel32.GetFinalPathNameByHandleW(
            ctypes.c_void_p(handle), None, 0, 0
        )
    )
    if required <= 0 or required > 32_768:
        return None
    buffer = ctypes.create_unicode_buffer(required + 1)
    written = int(
        kernel32.GetFinalPathNameByHandleW(
            ctypes.c_void_p(handle), buffer, len(buffer), 0
        )
    )
    if written <= 0 or written >= len(buffer):
        return None
    value = buffer.value
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    return os.path.normcase(os.path.abspath(value))


@contextmanager
def pin_media_binary(tool: str) -> Iterator[AttestedCli]:
    """Hold a Windows deny-write/delete handle from hash through process exit."""

    normalized, path_variable, hash_variable = _normalise_tool(tool)
    raw_path = str(os.environ.get(path_variable) or "").strip()
    expected = str(os.environ.get(hash_variable) or "").strip().lower()
    if (
        not raw_path
        or not Path(raw_path).is_absolute()
        or not re.fullmatch(r"[0-9a-f]{64}", expected)
    ):
        raise MediaBinaryUnavailable(
            _configuration_error(normalized, path_variable, hash_variable)
        )
    directory_handle = _open_windows_read_pin(
        str(Path(raw_path).parent), directory=True
    )
    handle = _open_windows_read_pin(raw_path)
    if os.name == "nt" and (directory_handle is None or handle is None):
        _close_windows_handle(handle)
        _close_windows_handle(directory_handle)
        raise MediaBinaryUnavailable(
            _configuration_error(normalized, path_variable, hash_variable)
            + "；可执行文件或其封闭目录存在并发写入/替换或无法钉住"
        )
    try:
        # Hashing happens only after the Windows sharing pin is held.  A
        # pre-opened writer makes pin acquisition fail before this point.
        attested = from_environment(path_variable, hash_variable)
        if attested is None:
            raise MediaBinaryUnavailable(
                _configuration_error(normalized, path_variable, hash_variable)
            )
        if handle is not None:
            final_path = _windows_final_path(handle)
            if final_path is None or final_path != os.path.normcase(
                os.path.abspath(attested.path)
            ):
                raise MediaBinaryUnavailable(
                    _configuration_error(normalized, path_variable, hash_variable)
                    + "；钉住句柄与认证路径不一致"
                )
        if directory_handle is not None:
            final_directory = _windows_final_path(directory_handle)
            if final_directory is None or final_directory != os.path.normcase(
                os.path.abspath(str(Path(attested.path).parent))
            ):
                raise MediaBinaryUnavailable(
                    _configuration_error(normalized, path_variable, hash_variable)
                    + "；钉住目录与认证路径不一致"
                )
        _require_closed_windows_directory(
            attested,
            normalized=normalized,
            path_variable=path_variable,
            hash_variable=hash_variable,
        )
        _require_profile_authority(attested, normalized=normalized)
        yield attested
    finally:
        _close_windows_handle(handle)
        _close_windows_handle(directory_handle)


def require_media_binary(tool: str) -> AttestedCli:
    """Resolve and attest one supported binary without any PATH fallback."""

    with pin_media_binary(tool) as attested:
        return attested


def _bounded_arguments(args: Sequence[str | os.PathLike[str]]) -> list[str]:
    if len(args) > _MAX_ARGUMENTS:
        raise ValueError("media command exceeds argument-count bound")
    rendered: list[str] = []
    for raw in args:
        value = os.fspath(raw)
        if not isinstance(value, str):
            value = os.fsdecode(value)
        if "\x00" in value or len(value) > _MAX_ARGUMENT_CHARS:
            raise ValueError("media command contains an invalid or oversized argument")
        rendered.append(value)
    return rendered


def run_media_binary(
    tool: str,
    args: Sequence[str | os.PathLike[str]],
    *,
    input: bytes | str | None = None,
    capture_output: bool = True,
    text: bool = False,
    timeout: float,
    check: bool = False,
    cwd: str | os.PathLike[str] | None = None,
) -> subprocess.CompletedProcess:
    """Re-attest and launch a media tool with a fixed, non-secret environment."""

    total = float(timeout)
    if not math.isfinite(total) or total <= 0:
        raise ValueError("media command timeout must be a positive finite number")
    try:
        # The Windows pin is acquired before hashing and remains held until the
        # child exits, closing the hash-to-CreateProcess replacement window.
        with pin_media_binary(tool) as attested:
            command = [attested.path, *_bounded_arguments(args)]
            kwargs: dict[str, object] = {
                "capture_output": bool(capture_output),
                "text": bool(text),
                "timeout": total,
                "check": bool(check),
                "cwd": os.fspath(cwd) if cwd is not None else None,
                "env": minimal_media_env(),
                "shell": False,
                "close_fds": True,
            }
            if input is None:
                kwargs["stdin"] = subprocess.DEVNULL
            else:
                kwargs["input"] = input
            if os.name == "nt":
                kwargs["creationflags"] = int(
                    getattr(subprocess, "CREATE_NO_WINDOW", 0)
                )
            return subprocess.run(command, **kwargs)  # type: ignore[arg-type]
    except OSError as exc:
        path_variable, hash_variable = _TOOL_ENV[str(tool).strip().lower()]
        raise MediaBinaryUnavailable(
            _configuration_error(str(tool).strip().lower(), path_variable, hash_variable)
            + f"；启动失败：{type(exc).__name__}"
        ) from exc


__all__ = [
    "MediaBinaryUnavailable",
    "minimal_media_env",
    "pin_media_binary",
    "require_media_binary",
    "run_media_binary",
]
