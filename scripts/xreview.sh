#!/usr/bin/env bash
# 纳川四模型异源互审门禁。
# 发起模型只汇总、零投票且绝不参与本轮互审；五个候选家族中排除发起家族后，
# 恰好由四个不同模型家族审查同一份 target commit 冻结快照。
# Kimi Code 与 Codex 是独立 CLI 登录域；GLM/MiniMax/DeepSeek 当前共用
# OpenCode/Volcano 连接域，因此不能冒充四个真正独立的正式票。
# 用法：bash scripts/xreview.sh [commit] [initiator-family]
# initiator-family: codex/openai（默认）、glm/zhipu、kimi/k3/moonshot、
#                   minimax、deepseek
#
# Tool trust is fail-closed. XREVIEW_TOOL_TRUST_MANIFEST must name an absolute
# protected file outside this repository, and XREVIEW_TOOL_TRUST_MANIFEST_SHA256
# must be its reviewed lowercase SHA-256. Canonical TSV schema (LF, final LF):
#   schema<TAB>1
#   mode<TAB>formal|test-only
#   tool<TAB>NAME<TAB>native|bash-script<TAB>ABS_PATH<TAB>SIZE<TAB>SHA256
# Tool rows must be sorted and exactly cover bash/python/git/kimi/codex/
# opencode, plus taskkill on Windows. Bash-script reviewer entries exist solely
# for ineligible tests. Formal execution is intentionally disabled until a
# repository-external, protected, handle-bound launcher/control-plane exists.
# SECURITY: `bash scripts/xreview.sh` is a naked-shell invocation, never a trust
# root.  The caller's BASH_ENV can execute before this script's first line; only
# an outer protected launcher that sanitizes the pre-exec environment can close
# that boundary.
# SECURITY: Kimi Code 0.27.0's verified headless form uses `-p PROMPT`; the
# complete review prompt is therefore present in the child process command line
# and readable by same-SID process enumeration. A separate ACP stdin client has
# only fake-process transport and Windows process-tree evidence; it is not wired
# here and has no real Kimi/actual-served proof, so formal evidence stays closed.

set -uo pipefail
umask 077

script_source="${BASH_SOURCE[0]}"
if [[ "$script_source" != */* ]]; then script_source="./${script_source}"; fi
script_dir="${script_source%/*}"
cd "${script_dir}/.." || exit 1
repo_root="$(pwd -P)"

if [[ "$#" -gt 2 ]]; then
  echo "usage: bash scripts/xreview.sh [commit] [initiator-family]" >&2
  exit 64
fi

requested="${1:-HEAD}"
initiator_raw="${2:-${XREVIEW_INITIATOR_FAMILY:-codex}}"
initiator_raw="${initiator_raw,,}"
case "$initiator_raw" in
  codex|openai|gpt) initiator_family="openai" ;;
  glm|zhipu) initiator_family="zhipu" ;;
  kimi|k3|moonshot) initiator_family="moonshot" ;;
  minimax) initiator_family="minimax" ;;
  deepseek|deepseek-v4|deepseek-v4-pro) initiator_family="deepseek" ;;
  *)
    echo "xreview: unsupported initiator family: ${initiator_raw}" >&2
    exit 64
    ;;
esac

trust_manifest="${XREVIEW_TOOL_TRUST_MANIFEST:-}"
trust_manifest_sha256="${XREVIEW_TOOL_TRUST_MANIFEST_SHA256:-}"
trust_mode="${XREVIEW_TRUST_MODE:-formal}"
if [[ "$trust_mode" == "formal" ]]; then
  echo "xreview: NAKED_BASH_NOT_TRUST_ROOT: BASH_ENV can run before script line 1; only a protected external launcher can authorize formal evidence" >&2
  echo "xreview: FOUR_INDEPENDENT_DOMAINS_UNAVAILABLE: Kimi Code + Codex + shared OpenCode/Volcano provide only three connection domains; no formal four-vote result is possible" >&2
  echo "xreview: KIMI_PROMPT_ARGV_EXPOSURE: this xreview path still uses -p PROMPT and exposes the review prompt to same-SID process enumeration; the separate fake-tested ACP stdin client is not wired or real-model verified" >&2
fi
if [[ -z "$trust_manifest" || -z "$trust_manifest_sha256" ]]; then
  echo "xreview: explicit tool trust manifest and digest are required" >&2
  exit 78
fi
if [[ "$trust_mode" != "formal" && "$trust_mode" != "test-only" ]]; then
  echo "xreview: XREVIEW_TRUST_MODE must be formal or test-only" >&2
  exit 78
fi
if [[ "$trust_mode" == "formal" ]]; then
  external_launch_receipt="${XREVIEW_EXTERNAL_LAUNCH_RECEIPT:-}"
  external_launch_receipt_sha256="${XREVIEW_EXTERNAL_LAUNCH_RECEIPT_SHA256:-}"
  external_control_root="${XREVIEW_EXTERNAL_CONTROL_ROOT:-}"
  if [[ -z "$external_launch_receipt" || -z "$external_launch_receipt_sha256" || -z "$external_control_root" ]]; then
    echo "xreview: external protected launcher receipt/control-plane is required; no model was started" >&2
    exit 78
  fi
  # An environment variable and a file hash supplied to this already-running
  # repository script are not an independent trust root.  In particular, the
  # current Windows path attestation cannot bind the verified file handle to
  # CreateProcess, and this process cannot prove that output/control files are
  # protected from its own administrative identity.  Keep formal review closed
  # until a repository-external launcher owns those handles and emits a receipt
  # that this script can independently validate.
  echo "xreview: formal evidence is disabled: handle-bound external launcher/control-plane verification is not installed; no model was started" >&2
  exit 78
fi
case "$trust_manifest" in
  /*|[A-Za-z]:[\\/]*) ;;
  *) echo "xreview: tool trust manifest path must be absolute" >&2; exit 78 ;;
esac
if [[ ! "$trust_manifest_sha256" =~ ^[0-9a-f]{64}$ || ! -f "$trust_manifest" || -L "$trust_manifest" ]]; then
  echo "xreview: tool trust manifest bootstrap metadata is invalid" >&2
  exit 78
fi

# Bootstrap limitation: this shell cannot hash the Python interpreter before
# executing it.  It only extracts the declared path without consulting PATH or
# a per-tool environment override.  Formal evidence therefore additionally
# requires an external protected launcher/frozen commit; the in-script verifier
# below repeats and records every byte/ACL/identity check without pretending the
# environment digest is an independent root of trust.
python_bin=""
while IFS=$'\t' read -r record name launch path size sha extra; do
  if [[ "$record" == "tool" && "$name" == "python" ]]; then
    if [[ -n "$python_bin" || "$launch" != "native" || -n "$extra" ]]; then
      echo "xreview: duplicate or malformed Python trust entry" >&2
      exit 78
    fi
    python_bin="$path"
  fi
done < "$trust_manifest"
case "$python_bin" in
  /*|[A-Za-z]:[\\/]*) ;;
  *) echo "xreview: trust manifest has no absolute native Python" >&2; exit 78 ;;
esac
if [[ ! -f "$python_bin" || -L "$python_bin" ]]; then
  echo "xreview: declared Python bootstrap is unavailable" >&2
  exit 78
fi

if ! output_dir="$(
  "$python_bin" -I -S -B -X utf8 - "${XREVIEW_OUTPUT_DIR:-}" "${XREVIEW_OUTPUT_ROOT:-${TEMP:-}}" <<'PY'
from pathlib import Path
import os
import sys
import tempfile

requested = sys.argv[1]
root = sys.argv[2]
try:
    if requested:
        output = Path(requested)
        if not output.is_absolute():
            raise RuntimeError("explicit output path must be absolute")
        output.mkdir(exist_ok=False)
    else:
        base = Path(root) if root else Path(tempfile.gettempdir())
        if not base.is_absolute():
            raise RuntimeError("output root must be absolute")
        base.mkdir(parents=True, exist_ok=True)
        output = Path(tempfile.mkdtemp(prefix="nachuan-xreview-", dir=base))
    print(output.resolve(strict=True))
except FileExistsError:
    print(
        f"xreview: output directory must be new and atomically creatable: {requested}",
        file=sys.stderr,
    )
    raise SystemExit(73)
except BaseException as error:
    print(f"xreview output error: {type(error).__name__}: {error}", file=sys.stderr)
    raise SystemExit(73)
PY
)"; then
  exit 73
fi

declare -a supervisor_pids=()
taskkill_bin=""
cleanup_children() {
  local original_rc=$?
  local pid round
  trap - EXIT INT TERM
  for pid in "${supervisor_pids[@]}"; do
    if [[ -z "$pid" ]]; then continue; fi
    if kill -0 "$pid" 2>/dev/null; then
      kill -TERM "$pid" 2>/dev/null || true
    fi
  done
  for round in 1 2 3 4 5 6 7 8 9 10; do
    local alive=0
    for pid in "${supervisor_pids[@]}"; do
      if [[ -z "$pid" ]]; then continue; fi
      if kill -0 "$pid" 2>/dev/null; then alive=1; fi
    done
    if [[ "$alive" -eq 0 ]]; then break; fi
    read -r -t 0.1 _xreview_wait </dev/null || true
  done
  for pid in "${supervisor_pids[@]}"; do
    if [[ -z "$pid" ]]; then continue; fi
    if kill -0 "$pid" 2>/dev/null; then
      if [[ -n "$taskkill_bin" ]]; then
        "$taskkill_bin" //PID "$pid" //T //F >/dev/null 2>&1 || true
      else
        kill -KILL "$pid" 2>/dev/null || true
      fi
    fi
    wait "$pid" 2>/dev/null || true
  done
  exit "$original_rc"
}
trap cleanup_children EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

validate_timeout() {
  local name="$1" value="$2"
  if [[ ! "$value" =~ ^[1-9][0-9]*$ ]] || (( value > 7200 )); then
    echo "xreview: ${name} must be an integer in 1..7200 seconds" >&2
    return 1
  fi
}

kimi_timeout="${XREVIEW_KIMI_TIMEOUT_SECONDS:-2700}"
codex_timeout="${XREVIEW_CODEX_TIMEOUT_SECONDS:-2700}"
opencode_timeout="${XREVIEW_OPENCODE_TIMEOUT_SECONDS:-1800}"
validate_timeout XREVIEW_KIMI_TIMEOUT_SECONDS "$kimi_timeout" || exit 64
validate_timeout XREVIEW_CODEX_TIMEOUT_SECONDS "$codex_timeout" || exit 64
validate_timeout XREVIEW_OPENCODE_TIMEOUT_SECONDS "$opencode_timeout" || exit 64

helper="$output_dir/xreview_helper.py"
while IFS= read -r _xreview_source_line; do
  printf '%s\n' "$_xreview_source_line"
done >"$helper" <<'PY'
from __future__ import annotations

import argparse
from collections.abc import Mapping
import ctypes
import datetime as dt
import hashlib
import hmac
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from ctypes import wintypes


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(value, handle, ensure_ascii=False, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def atomic_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_reparse(info: os.stat_result) -> bool:
    return bool(getattr(info, "st_file_attributes", 0) & 0x400)


TRUST_TOOL_NAMES = frozenset(
    {"bash", "python", "git", "kimi", "codex", "opencode"}
    | ({"taskkill"} if os.name == "nt" else set())
)
REVIEW_TOOL_NAMES = frozenset({"kimi", "codex", "opencode"})
MAX_TRUST_MANIFEST_BYTES = 64 * 1024
MAX_TOOL_BYTES = 1024 * 1024 * 1024


class TrustError(RuntimeError):
    pass


def _identity(info: os.stat_result) -> dict[str, int]:
    return {
        "device": int(info.st_dev),
        "inode": int(info.st_ino),
        "size": int(info.st_size),
        "mtime_ns": int(info.st_mtime_ns),
        "ctime_ns": int(info.st_ctime_ns),
        "file_attributes": int(getattr(info, "st_file_attributes", 0)),
    }


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    # Windows path-stat and handle-fstat can report creation/change time with
    # different rounding for the same file.  File ID, volume, size, content
    # timestamp and attributes are the stable cross-view identity fields.
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns")
    return all(int(getattr(left, field)) == int(getattr(right, field)) for field in fields) and int(
        getattr(left, "st_file_attributes", 0)
    ) == int(getattr(right, "st_file_attributes", 0))


def _absolute_nonredirect_path(raw: str, *, regular: bool) -> Path:
    candidate = Path(raw)
    if not candidate.is_absolute() or ".." in candidate.parts:
        raise TrustError(f"trusted path must be absolute without '..': {raw!r}")
    current = candidate
    while True:
        try:
            info = os.lstat(current)
        except OSError as error:
            raise TrustError(f"trusted path component is unavailable: {current}: {error}") from error
        if stat.S_ISLNK(info.st_mode) or is_reparse(info):
            raise TrustError(f"trusted path contains a link/reparse component: {current}")
        if current == candidate and regular and not stat.S_ISREG(info.st_mode):
            raise TrustError(f"trusted tool is not a regular file: {current}")
        parent = current.parent
        if parent == current:
            break
        current = parent
    return candidate.resolve(strict=True)


if os.name == "nt":
    class ACL_SIZE_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("AceCount", wintypes.DWORD),
            ("AclBytesInUse", wintypes.DWORD),
            ("AclBytesFree", wintypes.DWORD),
        ]


    class ACE_HEADER(ctypes.Structure):
        _fields_ = [
            ("AceType", ctypes.c_ubyte),
            ("AceFlags", ctypes.c_ubyte),
            ("AceSize", wintypes.WORD),
        ]


_WINDOWS_TRUSTED_WRITER_SIDS = frozenset(
    {
        "S-1-5-18",  # LocalSystem
        "S-1-5-32-544",  # Builtin Administrators
        # NT SERVICE\\TrustedInstaller
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
    }
)
_WINDOWS_WRITE_MASK = (
    0x00000002  # FILE_WRITE_DATA / directory create-file
    | 0x00000004  # FILE_APPEND_DATA / directory create-subdir
    | 0x00000010  # FILE_WRITE_EA
    | 0x00000040  # FILE_DELETE_CHILD
    | 0x00000100  # FILE_WRITE_ATTRIBUTES
    | 0x00010000  # DELETE
    | 0x00040000  # WRITE_DAC
    | 0x00080000  # WRITE_OWNER
    | 0x10000000  # GENERIC_ALL
    | 0x40000000  # GENERIC_WRITE
)


def _windows_sid_string(pointer: int) -> str:
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    converted = wintypes.LPWSTR()
    advapi32.ConvertSidToStringSidW.argtypes = (ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR))
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    if not advapi32.ConvertSidToStringSidW(ctypes.c_void_p(pointer), ctypes.byref(converted)):
        raise TrustError(f"cannot convert ACL SID: winerror={ctypes.get_last_error()}")
    try:
        return str(converted.value)
    finally:
        kernel32.LocalFree.argtypes = (ctypes.c_void_p,)
        kernel32.LocalFree(ctypes.cast(converted, ctypes.c_void_p))


def _windows_acl_protected(path: Path) -> dict[str, object]:
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    owner = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    advapi32.GetNamedSecurityInfoW.argtypes = (
        wintypes.LPWSTR,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    )
    advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    rc = advapi32.GetNamedSecurityInfoW(
        str(path),
        1,  # SE_FILE_OBJECT
        0x00000001 | 0x00000004,  # OWNER + DACL
        ctypes.byref(owner),
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(descriptor),
    )
    if rc != 0 or not descriptor.value or not owner.value or not dacl.value:
        raise TrustError(f"cannot prove protected Windows ACL for {path}: error={rc}")
    try:
        owner_sid = _windows_sid_string(int(owner.value))
        if owner_sid not in _WINDOWS_TRUSTED_WRITER_SIDS:
            raise TrustError(f"Windows path owner is not SYSTEM/admin/TrustedInstaller: {path}: {owner_sid}")
        size = ACL_SIZE_INFORMATION()
        advapi32.GetAclInformation.argtypes = (
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.c_int,
        )
        advapi32.GetAclInformation.restype = wintypes.BOOL
        if not advapi32.GetAclInformation(
            dacl, ctypes.byref(size), ctypes.sizeof(size), 2  # AclSizeInformation
        ):
            raise TrustError(f"cannot enumerate Windows ACL for {path}")
        advapi32.GetAce.argtypes = (ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p))
        advapi32.GetAce.restype = wintypes.BOOL
        writers: list[str] = []
        simple_allow = {0x00, 0x09}
        object_allow = {0x05, 0x0B}
        for index in range(int(size.AceCount)):
            ace = ctypes.c_void_p()
            if not advapi32.GetAce(dacl, index, ctypes.byref(ace)) or not ace.value:
                raise TrustError(f"cannot read Windows ACL entry {index} for {path}")
            address = int(ace.value)
            header = ACE_HEADER.from_address(address)
            if header.AceType not in simple_allow | object_allow:
                continue
            mask = ctypes.c_uint32.from_address(address + 4).value
            if not (mask & _WINDOWS_WRITE_MASK):
                continue
            if header.AceType in simple_allow:
                sid_address = address + 8
            else:
                flags = ctypes.c_uint32.from_address(address + 8).value
                sid_address = address + 12
                if flags & 0x1:
                    sid_address += 16
                if flags & 0x2:
                    sid_address += 16
            sid = _windows_sid_string(sid_address)
            if sid not in _WINDOWS_TRUSTED_WRITER_SIDS:
                writers.append(sid)
        if writers:
            raise TrustError(f"Windows path grants write/delete/control to untrusted SID(s): {path}: {sorted(set(writers))}")
        return {"verified": True, "scheme": "windows-conservative-dacl", "owner_sid": owner_sid}
    finally:
        kernel32.LocalFree.argtypes = (ctypes.c_void_p,)
        kernel32.LocalFree(descriptor)


def _posix_chain_protected(path: Path, *, is_file: bool) -> dict[str, object]:
    checked: list[str] = []
    current = path
    while True:
        info = os.lstat(current)
        mode = stat.S_IMODE(info.st_mode)
        if info.st_uid != 0:
            raise TrustError(f"POSIX formal trust path is not root-owned: {current}")
        if mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise TrustError(f"POSIX trust path is group/other writable: {current}")
        checked.append(str(current))
        parent = current.parent
        if parent == current:
            break
        current = parent
    return {"verified": True, "scheme": "posix-mode-chain", "checked_components": len(checked)}


def _protection(path: Path, *, trust_mode: str, is_file: bool) -> dict[str, object]:
    if trust_mode == "test-only":
        return {
            "verified": False,
            "scheme": "test-only-bypass",
            "formal_evidence_eligible": False,
        }
    if os.name == "nt":
        checked = 0
        current = path
        while True:
            _windows_acl_protected(current)
            checked += 1
            parent = current.parent
            if parent == current:
                break
            current = parent
        return {"verified": True, "scheme": "windows-conservative-dacl-chain", "checked_components": checked}
    return _posix_chain_protected(path, is_file=is_file)


def _attest_file(entry: dict[str, object], *, trust_mode: str) -> dict[str, object]:
    expected_path = str(entry["path"])
    path = _absolute_nonredirect_path(expected_path, regular=True)
    if os.path.normcase(str(path)) != os.path.normcase(str(Path(expected_path))):
        raise TrustError(f"trusted path is not canonical: {expected_path}")
    launch = str(entry["launch"])
    if trust_mode == "formal" and launch != "native":
        raise TrustError(f"formal trust permits only native executables: {entry['name']}")
    if launch == "native":
        if os.name == "nt" and path.suffix.lower() != ".exe":
            raise TrustError(f"Windows native trusted tool must be .exe: {path}")
        if os.name != "nt" and not (path.stat().st_mode & 0o111):
            raise TrustError(f"POSIX native trusted tool is not executable: {path}")
    elif launch != "bash-script" or str(entry["name"]) not in REVIEW_TOOL_NAMES:
        raise TrustError(f"unsupported trusted launch mode for {entry['name']}: {launch}")
    before = os.lstat(path)
    expected_size = int(entry["size"])
    if before.st_size != expected_size or expected_size <= 0 or expected_size > MAX_TOOL_BYTES:
        raise TrustError(f"trusted tool size mismatch/out of bounds: {entry['name']}")
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as handle:
        opened = os.fstat(handle.fileno())
        if not _same_identity(before, opened):
            raise TrustError(f"trusted tool changed while opening: {entry['name']}")
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            total += len(chunk)
            if total > MAX_TOOL_BYTES:
                raise TrustError(f"trusted tool grew beyond size bound: {entry['name']}")
            digest.update(chunk)
    after = os.lstat(path)
    if total != expected_size or not _same_identity(before, after):
        raise TrustError(f"trusted tool changed while hashing: {entry['name']}")
    actual_sha256 = digest.hexdigest()
    if not hmac.compare_digest(actual_sha256, str(entry["sha256"])):
        raise TrustError(f"trusted tool SHA-256 mismatch: {entry['name']}")
    return {
        "path": str(path),
        "launch": launch,
        "size": total,
        "sha256": actual_sha256,
        "identity": _identity(after),
        "protection": _protection(path, trust_mode=trust_mode, is_file=True),
    }


def load_tool_trust_manifest(
    path_value: str,
    expected_sha256: str,
    trust_mode: str,
    repo_root: str,
) -> dict[str, object]:
    if trust_mode not in {"formal", "test-only"}:
        raise TrustError("trust mode must be formal or test-only")
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise TrustError("trust manifest digest must be lowercase SHA-256")
    path = _absolute_nonredirect_path(path_value, regular=True)
    repo = Path(repo_root).resolve(strict=True)
    if path == repo or repo in path.parents:
        raise TrustError("tool trust manifest must live outside the mutable repository")
    before = os.lstat(path)
    if before.st_size <= 0 or before.st_size > MAX_TRUST_MANIFEST_BYTES:
        raise TrustError("tool trust manifest size is outside 1..65536 bytes")
    with path.open("rb") as handle:
        opened = os.fstat(handle.fileno())
        if not _same_identity(before, opened):
            raise TrustError("tool trust manifest changed while opening")
        raw = handle.read(MAX_TRUST_MANIFEST_BYTES + 1)
    after = os.lstat(path)
    if len(raw) > MAX_TRUST_MANIFEST_BYTES or not _same_identity(before, after):
        raise TrustError("tool trust manifest changed while reading")
    actual_manifest_sha256 = hashlib.sha256(raw).hexdigest()
    if not hmac.compare_digest(actual_manifest_sha256, expected_sha256):
        raise TrustError("tool trust manifest SHA-256 mismatch")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise TrustError("tool trust manifest must be UTF-8") from error
    if "\r" in text or not text.endswith("\n"):
        raise TrustError("tool trust manifest must use canonical LF and final newline")
    lines = text.splitlines()
    if len(lines) < 3 or lines[0] != "schema\t1" or lines[1] != f"mode\t{trust_mode}":
        raise TrustError("tool trust manifest schema/mode header mismatch")
    tools: dict[str, dict[str, object]] = {}
    for line in lines[2:]:
        fields = line.split("\t")
        if len(fields) != 6 or fields[0] != "tool":
            raise TrustError("tool trust manifest row has missing/unexpected fields")
        _, name, launch, raw_path, raw_size, sha256 = fields
        if name in tools or name not in TRUST_TOOL_NAMES:
            raise TrustError(f"duplicate or unexpected trust tool: {name!r}")
        if launch not in {"native", "bash-script"}:
            raise TrustError(f"invalid launch mode for {name}")
        if not re.fullmatch(r"[1-9][0-9]{0,11}", raw_size):
            raise TrustError(f"invalid size for {name}")
        if not re.fullmatch(r"[0-9a-f]{64}", sha256):
            raise TrustError(f"invalid SHA-256 for {name}")
        tools[name] = {
            "name": name,
            "launch": launch,
            "path": raw_path,
            "size": int(raw_size),
            "sha256": sha256,
        }
    if set(tools) != set(TRUST_TOOL_NAMES) or list(tools) != sorted(tools):
        raise TrustError("tool trust manifest must contain the exact sorted tool closure")
    if trust_mode == "test-only" and any(
        tools[name]["launch"] != "bash-script" for name in REVIEW_TOOL_NAMES
    ):
        raise TrustError("test-only reviewer tools must be bash-script fakes")
    attested = {
        name: {"expected": tools[name], "actual": _attest_file(tools[name], trust_mode=trust_mode)}
        for name in sorted(tools)
    }
    return {
        "schema": 1,
        "trust_mode": trust_mode,
        "formal_evidence_eligible": trust_mode == "formal",
        "manifest": {
            "path": str(path),
            "size": len(raw),
            "expected_sha256": expected_sha256,
            "actual_sha256": actual_manifest_sha256,
            "identity": _identity(after),
            "protection": _protection(path, trust_mode=trust_mode, is_file=True),
        },
        "bootstrap": {
            "inside_script_preflight_verified": True,
            "bash_was_running_before_inside_script_verification": True,
            "python_was_started_from_manifest_before_inside_script_verification": True,
            "environment_digest_is_independent_trust_root": False,
            "formal_requirement": "protected external launcher + frozen reviewed xreview.sh commit",
        },
        "tools": attested,
    }


def _same_attested_actual(left: dict[str, object], right: dict[str, object]) -> bool:
    if any(left.get(key) != right.get(key) for key in ("path", "launch", "size", "sha256")):
        return False
    left_id = dict(left.get("identity") or {})
    right_id = dict(right.get("identity") or {})
    stable = ("device", "inode", "size", "mtime_ns", "file_attributes")
    return all(left_id.get(key) == right_id.get(key) for key in stable)


def _generated_file_actual(path_value: str, expected_sha256: str) -> dict[str, object]:
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise TrustError("generated executable input has invalid expected SHA-256")
    path = _absolute_nonredirect_path(path_value, regular=True)
    before = os.lstat(path)
    if before.st_size <= 0 or before.st_size > MAX_TRUST_MANIFEST_BYTES:
        raise TrustError(f"generated executable input has invalid size: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        opened = os.fstat(handle.fileno())
        if not _same_identity(before, opened):
            raise TrustError(f"generated executable input changed while opening: {path}")
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    after = os.lstat(path)
    actual_sha256 = digest.hexdigest()
    if not _same_identity(before, after) or not hmac.compare_digest(actual_sha256, expected_sha256):
        raise TrustError(f"generated executable input identity/hash mismatch: {path}")
    return {
        "path": str(path),
        "size": int(after.st_size),
        "sha256": actual_sha256,
        "identity": _identity(after),
    }


if os.name == "nt":
    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]


    class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]


    class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoInfo", IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]


class WindowsJob:
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
    JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9

    def __init__(self) -> None:
        if os.name != "nt":
            raise RuntimeError("Windows Job Object requested on a non-Windows host")
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel32 = kernel32
        kernel32.CreateJobObjectW.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.SetInformationJobObject.argtypes = (
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        )
        kernel32.SetInformationJobObject.restype = wintypes.BOOL
        kernel32.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
        kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel32.TerminateJobObject.argtypes = (wintypes.HANDLE, wintypes.UINT)
        kernel32.TerminateJobObject.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        kernel32.CloseHandle.restype = wintypes.BOOL
        self.handle = kernel32.CreateJobObjectW(None, None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        information = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        information.BasicLimitInformation.LimitFlags = self.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not kernel32.SetInformationJobObject(
            self.handle,
            self.JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(information),
            ctypes.sizeof(information),
        ):
            error = ctypes.WinError(ctypes.get_last_error())
            kernel32.CloseHandle(self.handle)
            self.handle = None
            raise error

    def assign(self, process: subprocess.Popen[bytes]) -> None:
        if not self.handle or not self.kernel32.AssignProcessToJobObject(
            self.handle, wintypes.HANDLE(int(process._handle))
        ):
            raise ctypes.WinError(ctypes.get_last_error())

    def terminate(self, exit_code: int) -> bool:
        return bool(self.handle and self.kernel32.TerminateJobObject(self.handle, exit_code))

    def close(self) -> None:
        if self.handle:
            self.kernel32.CloseHandle(self.handle)
            self.handle = None


class WindowsFilePins:
    """Deny write/delete sharing while a trusted Windows command is live."""

    def __init__(self) -> None:
        self.handles: list[int] = []
        self.kernel32 = None
        if os.name == "nt":
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CreateFileW.argtypes = (
                wintypes.LPCWSTR,
                wintypes.DWORD,
                wintypes.DWORD,
                ctypes.c_void_p,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.HANDLE,
            )
            kernel32.CreateFileW.restype = wintypes.HANDLE
            kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
            kernel32.CloseHandle.restype = wintypes.BOOL
            self.kernel32 = kernel32

    def pin(self, path_value: str) -> None:
        if os.name != "nt":
            return
        assert self.kernel32 is not None
        handle = self.kernel32.CreateFileW(
            str(Path(path_value)),
            0x80000000,  # GENERIC_READ
            0x00000001,  # FILE_SHARE_READ only: deny write/delete replacement
            None,
            3,  # OPEN_EXISTING
            0x00000080,  # FILE_ATTRIBUTE_NORMAL
            None,
        )
        invalid = ctypes.c_void_p(-1).value
        value = int(handle) if handle else 0
        if not value or value == invalid:
            raise TrustError(
                f"cannot pin trusted file against replacement: {path_value}: "
                f"winerror={ctypes.get_last_error()}"
            )
        self.handles.append(value)

    def close(self) -> None:
        if self.kernel32 is not None:
            for handle in reversed(self.handles):
                self.kernel32.CloseHandle(wintypes.HANDLE(handle))
        self.handles.clear()


def safe_extract(archive: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=False)
    root = destination.resolve()
    with tarfile.open(archive, "r:") as bundle:
        for member in bundle.getmembers():
            relative = PurePosixPath(member.name)
            if relative.is_absolute() or ".." in relative.parts:
                raise RuntimeError(f"unsafe archive member: {member.name}")
            target = root.joinpath(*relative.parts)
            if target != root and root not in target.parents:
                raise RuntimeError(f"archive member escaped snapshot: {member.name}")
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isreg():
                raise RuntimeError(f"snapshot links/devices are forbidden: {member.name}")
            target.parent.mkdir(parents=True, exist_ok=True)
            source = bundle.extractfile(member)
            if source is None:
                raise RuntimeError(f"missing archive payload: {member.name}")
            with source, target.open("wb") as output:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    output.write(chunk)
            if os.name != "nt":
                os.chmod(target, member.mode & 0o777)


def snapshot_files(root: Path) -> list[dict[str, object]]:
    root = root.resolve()
    files: list[dict[str, object]] = []
    stack: list[tuple[Path, PurePosixPath]] = [(root, PurePosixPath("."))]
    while stack:
        directory, relative_dir = stack.pop()
        entries = sorted(os.scandir(directory), key=lambda item: item.name)
        for entry in entries:
            info = entry.stat(follow_symlinks=False)
            relative = relative_dir / entry.name
            relative_text = str(relative).removeprefix("./")
            if entry.is_symlink() or is_reparse(info):
                raise RuntimeError(f"snapshot contains link/reparse point: {relative_text}")
            if stat.S_ISDIR(info.st_mode):
                stack.append((Path(entry.path), relative))
            elif stat.S_ISREG(info.st_mode):
                path = Path(entry.path)
                files.append(
                    {
                        "path": relative_text,
                        "size": info.st_size,
                        "sha256": sha256_file(path),
                    }
                )
            else:
                raise RuntimeError(f"snapshot contains special file: {relative_text}")
    return sorted(files, key=lambda item: str(item["path"]))


def kill_tree(
    process: subprocess.Popen[bytes], log_handle, windows_job: WindowsJob | None
) -> tuple[bool, bool, str]:
    if process.poll() is not None:
        return False, True, "already-exited"
    if os.name == "nt":
        if windows_job is None:
            return True, False, "windows-job-object-missing"
        try:
            terminated = windows_job.terminate(124)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                return True, False, "job-object-terminate; parent-still-alive"
            confirmed = process.poll() is not None and terminated
            return True, confirmed, "windows-job-object"
        except BaseException as error:
            return True, False, f"job-object-error={type(error).__name__}:{error}"
    try:
        group = os.getpgid(process.pid)
        os.killpg(group, signal.SIGTERM)
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(group, signal.SIGKILL)
            process.wait(timeout=10)
        return True, process.poll() is not None, "posix-process-group"
    except BaseException as error:
        return True, False, f"killpg-error={type(error).__name__}:{error}"


class SupervisorInterrupted(Exception):
    def __init__(self, signum: int) -> None:
        super().__init__(signum)
        self.signum = signum


FORMAL_PROVIDER_CREDENTIAL_ENV_BY_FAMILY = {
    "openai": frozenset(
        {"OPENAI_API_KEY", "OPENAI_BASE_URL", "OPENAI_ORG_ID", "OPENAI_PROJECT_ID"}
    ),
    "zhipu": frozenset(
        {
            "ARK_API_KEY",
            "VOLCENGINE_API_KEY",
            "VOLCENGINE_ACCESS_KEY",
            "VOLCENGINE_SECRET_KEY",
        }
    ),
    "moonshot": frozenset({"KIMI_API_KEY", "KIMI_BASE_URL"}),
    "minimax": frozenset(
        {
            "ARK_API_KEY",
            "VOLCENGINE_API_KEY",
            "VOLCENGINE_ACCESS_KEY",
            "VOLCENGINE_SECRET_KEY",
        }
    ),
    "deepseek": frozenset(
        {
            "ARK_API_KEY",
            "VOLCENGINE_API_KEY",
            "VOLCENGINE_ACCESS_KEY",
            "VOLCENGINE_SECRET_KEY",
        }
    ),
}

# Generic HOME/APPDATA/login directories are never inherited.  A future
# protected launcher must provide a family-scoped source directory, which is
# translated to the CLI's conventional destination name only for that family.
FORMAL_SCOPED_CONFIG_ENV_BY_FAMILY = {
    "openai": {"XREVIEW_OPENAI_CODEX_HOME": "CODEX_HOME"},
    "zhipu": {"XREVIEW_ZHIPU_OPENCODE_CONFIG_DIR": "OPENCODE_CONFIG_DIR"},
    "moonshot": {"XREVIEW_MOONSHOT_KIMI_CODE_HOME": "KIMI_CODE_HOME"},
    "minimax": {"XREVIEW_MINIMAX_OPENCODE_CONFIG_DIR": "OPENCODE_CONFIG_DIR"},
    "deepseek": {"XREVIEW_DEEPSEEK_OPENCODE_CONFIG_DIR": "OPENCODE_CONFIG_DIR"},
}


def formal_provider_environment_allowlist(family: str) -> frozenset[str]:
    credentials = FORMAL_PROVIDER_CREDENTIAL_ENV_BY_FAMILY.get(family, frozenset())
    destinations = frozenset(FORMAL_SCOPED_CONFIG_ENV_BY_FAMILY.get(family, {}).values())
    return credentials | destinations


def project_formal_provider_environment(
    family: str, source_environment: Mapping[str, str]
) -> dict[str, str]:
    credentials = FORMAL_PROVIDER_CREDENTIAL_ENV_BY_FAMILY.get(family)
    if credentials is None:
        return {}
    projected: dict[str, str] = {}
    for name in sorted(credentials):
        value = source_environment.get(name)
        if value:
            projected[name] = value
    for source, destination in sorted(FORMAL_SCOPED_CONFIG_ENV_BY_FAMILY[family].items()):
        value = source_environment.get(source)
        if value:
            projected[destination] = value
    return projected


def _child_path(pre_trust: dict[str, object]) -> str:
    directories: list[str] = []
    for item in pre_trust["tools"].values():
        parent = str(Path(item["actual"]["path"]).parent)
        if os.path.normcase(parent) not in {os.path.normcase(value) for value in directories}:
            directories.append(parent)
    bash_path = Path(pre_trust["tools"]["bash"]["actual"]["path"])
    git_usr_bin = bash_path.parent.parent / "usr" / "bin"
    if git_usr_bin.is_dir():
        directories.append(str(git_usr_bin))
    if os.name == "nt":
        windows = Path(os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows")
        directories.append(str(windows / "System32"))
    return os.pathsep.join(dict.fromkeys(directories))


def child_environment(args: argparse.Namespace, pre_trust: dict[str, object]) -> dict[str, str]:
    environment: dict[str, str] = {
        "PATH": _child_path(pre_trust),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TERM": "dumb",
        "NO_COLOR": "1",
        "CI": "1",
    }
    if os.name == "nt":
        windows = os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows"
        environment.update(
            {
                "SystemRoot": windows,
                "WINDIR": windows,
                "PATHEXT": ".COM;.EXE;.BAT;.CMD",
            }
        )
    if args.trust_mode == "formal":
        if args.reviewer_family not in FORMAL_PROVIDER_CREDENTIAL_ENV_BY_FAMILY:
            raise TrustError(f"formal reviewer family has no credential policy: {args.reviewer_family}")
        environment.update(project_formal_provider_environment(args.reviewer_family, os.environ))
    if args.trust_mode == "test-only":
        # Test doubles need sentinels, but test-only always returns a dedicated
        # non-zero result and can never produce formal evidence.
        for name, value in os.environ.items():
            if name.startswith("FAKE_") and value:
                environment[name] = value
    if args.tool_name == "python":
        environment["XREVIEW_PROBE_PYTHON"] = str(Path(args.tool_path).resolve(strict=True))
    return environment


def supervise(args: argparse.Namespace) -> int:
    output = Path(args.output)
    status_path = Path(args.status)
    startup_marker = args.startup_marker or ""
    if bool(startup_marker) != (args.startup_timeout is not None):
        raise ValueError("startup marker and startup timeout must be configured together")
    if args.startup_timeout is not None and args.startup_timeout <= 0:
        raise ValueError("startup timeout must be positive")
    output.parent.mkdir(parents=True, exist_ok=True)
    started = utc_now()
    process: subprocess.Popen[bytes] | None = None
    windows_job: WindowsJob | None = None
    pins = WindowsFilePins()
    job_assigned = False
    gate_released = False
    startup_ready = not bool(startup_marker)
    startup_timed_out = False
    startup_wait_seconds = 0.0
    timed_out = False
    attempted = False
    confirmed: bool | None = None
    detail = "not-needed"
    reason = "trust-preflight-not-run"
    rc = 126
    pre_trust: dict[str, object] | None = None
    post_trust: dict[str, object] | None = None
    command_pre: dict[str, object] | None = None
    command_post: dict[str, object] | None = None
    wrapper_pre: dict[str, object] | None = None
    wrapper_post: dict[str, object] | None = None
    trust_error = ""

    def interrupted(signum: int, _frame) -> None:
        raise SupervisorInterrupted(signum)

    old_term = signal.signal(signal.SIGTERM, interrupted)
    old_int = signal.signal(signal.SIGINT, interrupted)
    try:
        try:
            pre_trust = load_tool_trust_manifest(
                args.trust_manifest,
                args.trust_manifest_sha256,
                args.trust_mode,
                args.repo_root,
            )
            selected_names = tuple(dict.fromkeys(("python", "bash", args.tool_name)))
            for name in selected_names:
                if name not in pre_trust["tools"]:
                    raise TrustError(f"supervised tool is absent from trust closure: {name}")
            trusted_selected = pre_trust["tools"][args.tool_name]["actual"]
            if os.path.normcase(str(trusted_selected["path"])) != os.path.normcase(
                str(Path(args.tool_path).resolve(strict=True))
            ):
                raise TrustError("supervised command path is not the attested selected tool")
            trusted_bash = pre_trust["tools"]["bash"]["actual"]
            if os.path.normcase(str(trusted_bash["path"])) != os.path.normcase(
                str(Path(args.bash).resolve(strict=True))
            ):
                raise TrustError("supervisor Bash argv is not the attested Bash")
            command_pre = _generated_file_actual(args.script, args.command_sha256)
            wrapper_pre = _generated_file_actual(args.wrapper, args.wrapper_sha256)
            pin_paths = {
                str(pre_trust["manifest"]["path"]),
                str(command_pre["path"]),
                str(wrapper_pre["path"]),
            }
            for name in selected_names:
                pin_paths.add(str(pre_trust["tools"][name]["actual"]["path"]))
            for path in sorted(pin_paths):
                pins.pin(path)

            with output.open("wb", buffering=0) as log_handle:
                creation: dict[str, object] = {}
                if os.name == "nt":
                    creation["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
                else:
                    creation["start_new_session"] = True
                gate = Path(args.gate)
                try:
                    gate.unlink()
                except FileNotFoundError:
                    pass
                if os.name == "nt":
                    windows_job = WindowsJob()
                child_env = child_environment(args, pre_trust)
                process = subprocess.Popen(
                    [args.bash, args.wrapper, args.gate, args.script],
                    cwd=args.cwd,
                    env=child_env,
                    stdin=subprocess.DEVNULL,
                    stdout=log_handle,
                    stderr=subprocess.STDOUT,
                    shell=False,
                    **creation,
                )
                if windows_job is not None:
                    try:
                        windows_job.assign(process)
                        job_assigned = True
                    except BaseException:
                        try:
                            process.terminate()
                            process.wait(timeout=5)
                        except BaseException:
                            pass
                        raise
                gate.touch(exist_ok=False)
                gate_released = True
                if startup_marker:
                    startup_started = time.monotonic()
                    startup_deadline = startup_started + float(args.startup_timeout)
                    marker_bytes = startup_marker.encode("utf-8")
                    while True:
                        try:
                            startup_ready = marker_bytes in output.read_bytes()
                        except OSError:
                            startup_ready = False
                        if startup_ready:
                            break
                        observed = process.poll()
                        if observed is not None:
                            rc = observed
                            reason = "completed-before-startup-ready"
                            break
                        if time.monotonic() >= startup_deadline:
                            startup_timed_out = True
                            attempted, confirmed, detail = kill_tree(
                                process, log_handle, windows_job
                            )
                            rc = 125 if confirmed else 126
                            reason = (
                                "startup-timeout"
                                if confirmed
                                else "startup-timeout-tree-kill-unconfirmed"
                            )
                            break
                        time.sleep(0.05)
                    startup_wait_seconds = time.monotonic() - startup_started
                if startup_ready:
                    try:
                        rc = process.wait(timeout=args.timeout)
                        reason = "completed"
                    except subprocess.TimeoutExpired:
                        timed_out = True
                        attempted, confirmed, detail = kill_tree(process, log_handle, windows_job)
                        rc = 124 if confirmed else 126
                        reason = "timeout" if confirmed else "timeout-tree-kill-unconfirmed"
                    except SupervisorInterrupted as error:
                        attempted, confirmed, detail = kill_tree(process, log_handle, windows_job)
                        rc = 128 + error.signum
                        reason = f"supervisor-signal-{error.signum}"
            post_trust = load_tool_trust_manifest(
                args.trust_manifest,
                args.trust_manifest_sha256,
                args.trust_mode,
                args.repo_root,
            )
            command_post = _generated_file_actual(args.script, args.command_sha256)
            wrapper_post = _generated_file_actual(args.wrapper, args.wrapper_sha256)
            manifest_pre = dict(pre_trust["manifest"])
            manifest_post = dict(post_trust["manifest"])
            manifest_identity_pre = dict(manifest_pre.get("identity") or {})
            manifest_identity_post = dict(manifest_post.get("identity") or {})
            stable_identity = ("device", "inode", "size", "mtime_ns", "file_attributes")
            same = all(
                manifest_identity_pre.get(key) == manifest_identity_post.get(key)
                for key in stable_identity
            ) and manifest_pre.get("actual_sha256") == manifest_post.get("actual_sha256")
            for name in selected_names:
                same = same and _same_attested_actual(
                    pre_trust["tools"][name]["actual"],
                    post_trust["tools"][name]["actual"],
                )
            same = same and _same_attested_actual(
                {**command_pre, "launch": "generated"},
                {**command_post, "launch": "generated"},
            ) and _same_attested_actual(
                {**wrapper_pre, "launch": "generated"},
                {**wrapper_post, "launch": "generated"},
            )
            if not same:
                raise TrustError("trusted manifest/tool/generated command identity changed during execution")
        except TrustError as error:
            trust_error = str(error)
            rc = 126
            reason = "tool-attestation-mismatch"
        except BaseException as error:
            trust_error = f"{type(error).__name__}: {error}"
            rc = 127
            reason = "launch-error"
    except SupervisorInterrupted as error:
        if process is not None:
            with output.open("ab", buffering=0) as log_handle:
                attempted, confirmed, detail = kill_tree(process, log_handle, windows_job)
        rc = 128 + error.signum
        reason = f"supervisor-signal-{error.signum}"
    finally:
        signal.signal(signal.SIGTERM, old_term)
        signal.signal(signal.SIGINT, old_int)
        if windows_job is not None:
            windows_job.close()
        pins.close()

    selected_names = tuple(dict.fromkeys(("python", "bash", args.tool_name)))
    tool_expected = None
    tool_pre = None
    tool_post = None
    bootstrap = None
    formal_eligible = False
    manifest_pre = None
    manifest_post = None
    if pre_trust is not None:
        tool_expected = {name: pre_trust["tools"][name]["expected"] for name in selected_names}
        tool_pre = {name: pre_trust["tools"][name]["actual"] for name in selected_names}
        bootstrap = pre_trust["bootstrap"]
        formal_eligible = bool(pre_trust["formal_evidence_eligible"])
        manifest_pre = pre_trust["manifest"]
    if post_trust is not None:
        tool_post = {name: post_trust["tools"][name]["actual"] for name in selected_names}
        manifest_post = post_trust["manifest"]

    atomic_json(
        status_path,
        {
            "schema": 1,
            "started_at": started,
            "ended_at": utc_now(),
            "pid": None if process is None else process.pid,
            "rc": rc,
            "reason": reason,
            "timed_out": timed_out,
            "tree_kill_attempted": attempted,
            "tree_kill_confirmed": confirmed,
            "tree_kill_detail": detail,
            "containment": "windows-job-object" if os.name == "nt" else "posix-process-group",
            "containment_assigned": job_assigned if os.name == "nt" else True,
            "startup_gate_released": gate_released,
            "startup_marker_required": bool(startup_marker),
            "startup_ready": startup_ready,
            "startup_timed_out": startup_timed_out,
            "startup_wait_seconds": round(startup_wait_seconds, 6),
            "child_environment_keys": sorted(child_environment(args, pre_trust)) if pre_trust is not None else [],
            "provider_environment_policy_family": args.reviewer_family,
            "formal_provider_environment_allowlist": sorted(
                formal_provider_environment_allowlist(args.reviewer_family)
            ),
            "command_script": {"expected_sha256": args.command_sha256, "pre": command_pre, "post": command_post},
            "gate_wrapper": {"expected_sha256": args.wrapper_sha256, "pre": wrapper_pre, "post": wrapper_post},
            "tool_trust": {
                "trust_mode": args.trust_mode,
                "formal_evidence_eligible": formal_eligible,
                "tool_name": args.tool_name,
                "expected": tool_expected,
                "pre": tool_pre,
                "post": tool_post,
                "manifest_pre": manifest_pre,
                "manifest_post": manifest_post,
                "bootstrap": bootstrap,
                "error": trust_error or None,
            },
        },
    )
    return 0


ANSI_CSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
ANSI_OSC = re.compile(r"\x1b\][^\x07]*(?:\x07|\x1b\\)")


def clean_terminal(value: str) -> str:
    return ANSI_CSI.sub("", ANSI_OSC.sub("", value)).replace("\r\n", "\n")


KIMI_SESSION_ID = re.compile(
    r"session_[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z"
)
MAX_KIMI_WIRE_BYTES = 4 * 1024 * 1024


def _stable_directory_identity(info: os.stat_result) -> dict[str, int]:
    return {
        "device": int(info.st_dev),
        "inode": int(info.st_ino),
        "file_attributes": int(getattr(info, "st_file_attributes", 0)),
    }


def _same_stable_directory_identity(
    expected: object, actual: os.stat_result
) -> bool:
    return isinstance(expected, dict) and expected == _stable_directory_identity(actual)


def _kimi_session_directories(code_home: Path) -> list[Path]:
    sessions = code_home / "sessions"
    if not sessions.exists():
        return []
    sessions = _absolute_nonredirect_path(str(sessions), regular=False)
    candidates: list[Path] = []
    for candidate in sessions.glob("*/session_*"):
        verified = _absolute_nonredirect_path(str(candidate), regular=False)
        if not verified.is_dir() or KIMI_SESSION_ID.fullmatch(verified.name) is None:
            raise RuntimeError(f"Kimi session root contains an invalid entry: {verified}")
        candidates.append(verified)
    return sorted(candidates, key=lambda value: os.path.normcase(str(value)))


def write_kimi_baseline(args: argparse.Namespace) -> int:
    raw_home = Path(args.code_home)
    if not raw_home.is_absolute() or ".." in raw_home.parts:
        raise RuntimeError("Kimi code home must be absolute without '..'")
    if raw_home.exists():
        code_home = _absolute_nonredirect_path(str(raw_home), regular=False)
        if not code_home.is_dir():
            raise RuntimeError("Kimi code home is not a directory")
        root_identity: dict[str, int] | None = _stable_directory_identity(
            os.lstat(code_home)
        )
        first = _kimi_session_directories(code_home)
        second = _kimi_session_directories(code_home)
        if [os.path.normcase(str(item)) for item in first] != [
            os.path.normcase(str(item)) for item in second
        ]:
            raise RuntimeError("Kimi session root changed while recording launch baseline")
        sessions = second
    else:
        parent = _absolute_nonredirect_path(str(raw_home.parent), regular=False)
        if not parent.is_dir():
            raise RuntimeError("Kimi code home parent is not a directory")
        code_home = parent / raw_home.name
        root_identity = None
        sessions = []
    captured_at_ns = time.time_ns()
    atomic_json(
        Path(args.output),
        {
            "schema": 1,
            "captured_at_ns": captured_at_ns,
            "code_home": str(code_home),
            "code_home_existed": root_identity is not None,
            "code_home_identity": root_identity,
            "session_ids": [item.name for item in sessions],
            "session_paths": [os.path.normcase(str(item)) for item in sessions],
        },
    )
    return 0


def verify_kimi_session(
    code_home_value: str,
    session_id: str,
    expected_alias: str,
    baseline_value: str,
    baseline_sha256: str,
) -> dict[str, object]:
    if expected_alias != "kimi-code/k3" or KIMI_SESSION_ID.fullmatch(session_id) is None:
        raise RuntimeError("Kimi requested alias/session identity is invalid")
    baseline_path = _absolute_nonredirect_path(baseline_value, regular=True)
    if not re.fullmatch(r"[0-9a-f]{64}", baseline_sha256) or not hmac.compare_digest(
        sha256_file(baseline_path), baseline_sha256
    ):
        raise RuntimeError("Kimi launch baseline digest mismatch")
    baseline = load_json(baseline_path)
    if baseline.get("schema") != 1:
        raise RuntimeError("Kimi launch baseline schema mismatch")
    captured_at_ns = baseline.get("captured_at_ns")
    session_ids = baseline.get("session_ids")
    session_paths = baseline.get("session_paths")
    if (
        not isinstance(captured_at_ns, int)
        or isinstance(captured_at_ns, bool)
        or not isinstance(session_ids, list)
        or not all(isinstance(value, str) for value in session_ids)
        or not isinstance(session_paths, list)
        or not all(isinstance(value, str) for value in session_paths)
    ):
        raise RuntimeError("Kimi launch baseline is malformed")
    code_home = _absolute_nonredirect_path(code_home_value, regular=False)
    if os.path.normcase(str(code_home)) != os.path.normcase(str(baseline.get("code_home"))):
        raise RuntimeError("Kimi launch baseline belongs to another code home")
    code_home_before = os.lstat(code_home)
    if baseline.get("code_home_existed") is True:
        if not _same_stable_directory_identity(
            baseline.get("code_home_identity"), code_home_before
        ):
            raise RuntimeError("Kimi code home identity changed after launch baseline")
    elif baseline.get("code_home_existed") is not False or int(
        code_home_before.st_ctime_ns
    ) < captured_at_ns:
        raise RuntimeError("Kimi code home was not newly created after launch baseline")
    if session_id in session_ids:
        raise RuntimeError("Kimi resume hint points to a session that predated this launch")
    candidates = list(
        (code_home / "sessions").glob(
            f"*/{session_id}/agents/main/wire.jsonl"
        )
    )
    if len(candidates) != 1:
        raise RuntimeError(
            f"Kimi session metadata must resolve to exactly one wire.jsonl, got {len(candidates)}"
        )
    wire = _absolute_nonredirect_path(str(candidates[0]), regular=True)
    session_root = _absolute_nonredirect_path(
        str(wire.parent.parent.parent), regular=False
    )
    if session_root.name != session_id or os.path.normcase(str(session_root)) in session_paths:
        raise RuntimeError("Kimi wire.jsonl is not from a new session root")
    session_before = os.lstat(session_root)
    before = os.lstat(wire)
    if (
        int(session_before.st_ctime_ns) < captured_at_ns
        or int(before.st_ctime_ns) < captured_at_ns
    ):
        raise RuntimeError("Kimi session evidence predates this reviewer launch")
    if before.st_size <= 0 or before.st_size > MAX_KIMI_WIRE_BYTES:
        raise RuntimeError("Kimi wire.jsonl is empty or outside the size bound")
    with wire.open("rb") as handle:
        opened = os.fstat(handle.fileno())
        if not _same_identity(before, opened):
            raise RuntimeError("Kimi wire.jsonl changed while opening")
        raw = handle.read(MAX_KIMI_WIRE_BYTES + 1)
    after = os.lstat(wire)
    session_after = os.lstat(session_root)
    code_home_after = os.lstat(code_home)
    if (
        len(raw) > MAX_KIMI_WIRE_BYTES
        or not _same_identity(before, after)
        or not _same_stable_directory_identity(
            _stable_directory_identity(session_before), session_after
        )
        or not _same_stable_directory_identity(
            _stable_directory_identity(code_home_before), code_home_after
        )
    ):
        raise RuntimeError("Kimi wire.jsonl changed while reading")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise RuntimeError("Kimi wire.jsonl is not UTF-8") from error
    events: list[dict[str, object]] = []
    for line in lines:
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise RuntimeError("Kimi wire.jsonl event is not an object")
        events.append(value)
    alias_events = [
        event
        for event in events
        if event.get("type") == "config.update" and "modelAlias" in event
    ]
    if len(alias_events) != 1:
        raise RuntimeError(
            f"Kimi session must contain exactly one modelAlias event, got {len(alias_events)}"
        )
    aliases = {
        str(event["modelAlias"])
        for event in alias_events
        if event.get("modelAlias")
    }
    request_events = [event for event in events if event.get("type") == "llm.request"]
    if len(request_events) != 1:
        raise RuntimeError(
            f"Kimi session must contain exactly one llm.request event, got {len(request_events)}"
        )
    requested_models = {
        str(event["model"])
        for event in request_events
        if event.get("model")
    }
    usage_events = [event for event in events if event.get("type") == "usage.record"]
    if len(usage_events) != 1:
        raise RuntimeError(
            f"Kimi session must contain exactly one usage.record event, got {len(usage_events)}"
        )
    usage_models = {
        str(event["model"])
        for event in usage_events
        if event.get("model")
    }
    correlation_names = ("requestId", "request_id", "turnId", "turn_id")

    def event_correlation_id(event: dict[str, object]) -> str | None:
        values = [event.get(name) for name in correlation_names if name in event]
        if not values:
            return None
        if (
            any(not isinstance(value, str) or not value.strip() for value in values)
            or len(set(values)) != 1
        ):
            raise RuntimeError("Kimi event contains an ambiguous request identifier")
        return str(values[0])

    request_correlation_id = event_correlation_id(request_events[0])
    usage_correlation_id = event_correlation_id(usage_events[0])
    if (request_correlation_id is None) != (usage_correlation_id is None) or (
        request_correlation_id is not None
        and not hmac.compare_digest(request_correlation_id, str(usage_correlation_id))
    ):
        raise RuntimeError("Kimi llm.request and usage.record identifiers disagree")
    if aliases != {expected_alias} or requested_models != {"k3"} or usage_models != {expected_alias}:
        raise RuntimeError(
            "Kimi session route mismatch: config.update/llm.request/usage.record disagree"
        )
    return {
        "session_id": session_id,
        "session_new_after_launch_baseline": True,
        "launch_baseline_sha256": baseline_sha256,
        "config_model_alias": expected_alias,
        "llm_request_model": "k3",
        "usage_model": expected_alias,
        "event_counts": {
            "model_alias": len(alias_events),
            "llm_request": len(request_events),
            "usage_record": len(usage_events),
        },
        "request_correlation_id": request_correlation_id,
        "request_correlation_evidence": (
            "wire.llm.request+usage.record"
            if request_correlation_id is not None
            else "not-exposed-by-kimi-0.27"
        ),
        "wire_sha256": hashlib.sha256(raw).hexdigest(),
    }


def parse_kimi(
    raw_text: str,
    expected_model: str,
    code_home: str,
    baseline: str,
    baseline_sha256: str,
) -> tuple[str, str, str, dict[str, object]]:
    objects: list[dict[str, object]] = []
    for line in clean_terminal(raw_text).splitlines():
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise RuntimeError("Kimi stream-json line is not an object")
        objects.append(value)
    assistants = [
        item
        for item in objects
        if item.get("role") == "assistant" and isinstance(item.get("content"), str)
    ]
    hints = [
        item
        for item in objects
        if item.get("role") == "meta" and item.get("type") == "session.resume_hint"
    ]
    if len(assistants) != 1 or len(hints) != 1:
        raise RuntimeError(
            "Kimi requires exactly one assistant report and one session.resume_hint"
        )
    report = str(assistants[0]["content"])
    session_id = hints[0].get("session_id")
    if not report.strip() or not isinstance(session_id, str):
        raise RuntimeError("Kimi assistant report/session_id is empty")
    observed_route = verify_kimi_session(
        code_home, session_id, expected_model, baseline, baseline_sha256
    )
    return (
        report,
        "k3",
        "kimi.stream-json:assistant+session.resume_hint+wire.config.update+llm.request+usage.record",
        observed_route,
    )


def parse_marker(report: str, expected_commit: str, expected_tree: str) -> tuple[dict, int]:
    markers = [
        line[len("XREVIEW_VERDICT_JSON=") :]
        for line in clean_terminal(report).splitlines()
        if line.startswith("XREVIEW_VERDICT_JSON=")
    ]
    if len(markers) != 1:
        raise RuntimeError(f"expected exactly one verdict marker, got {len(markers)}")
    payload = json.loads(markers[0])
    if not isinstance(payload, dict) or payload.get("schema") != 1:
        raise RuntimeError("verdict schema must equal 1")
    if payload.get("reviewed_commit") != expected_commit or payload.get("reviewed_tree") != expected_tree:
        raise RuntimeError("verdict is not bound to the requested commit/tree")
    verdict = payload.get("verdict")
    if verdict not in ("pass", "fail"):
        raise RuntimeError("verdict must be pass or fail")
    summary = payload.get("summary")
    if not isinstance(summary, str) or not summary.strip():
        raise RuntimeError("verdict summary is empty")
    findings = payload.get("findings")
    if not isinstance(findings, list):
        raise RuntimeError("findings must be a list")
    blockers = 0
    for finding in findings:
        if not isinstance(finding, dict):
            raise RuntimeError("each finding must be an object")
        severity = str(finding.get("severity") or "").upper()
        if severity not in ("P0", "P1", "P2", "P3"):
            raise RuntimeError(f"invalid finding severity: {severity!r}")
        if severity in ("P0", "P1"):
            blockers += 1
    if blockers and verdict != "fail":
        raise RuntimeError("P0/P1 findings require verdict=fail")
    return payload, blockers


def validate_review(args: argparse.Namespace) -> int:
    raw_path = Path(args.raw)
    raw = raw_path.read_text(encoding="utf-8", errors="replace")
    if not raw.strip():
        raise RuntimeError("reviewer output is empty")
    cleaned = clean_terminal(raw)
    observed_route: dict[str, object]
    if args.kind == "kimi":
        report, observed, route_evidence, observed_route = parse_kimi(
            raw,
            args.expected_model,
            args.kimi_code_home,
            args.kimi_baseline,
            args.kimi_baseline_sha256,
        )
    elif args.kind == "codex":
        model = re.search(r"(?m)^model: ([^\n]+)$", cleaned)
        sandbox = re.search(r"(?m)^sandbox: ([^\n]+)$", cleaned)
        observed = "" if model is None else model.group(1).strip()
        if observed != args.expected_model or sandbox is None or sandbox.group(1).strip() != "read-only":
            raise RuntimeError("Codex route/sandbox header mismatch")
        report = cleaned
        route_evidence = "codex.cli-header:model+sandbox"
        observed_route = {"model": observed, "sandbox": "read-only"}
    elif args.kind == "opencode":
        header = re.search(r"(?m)^> plan · ([^\n]+)$", cleaned)
        observed = "" if header is None else header.group(1).strip()
        if observed != args.expected_model:
            raise RuntimeError(f"OpenCode route mismatch: {observed!r}")
        report = cleaned
        route_evidence = "opencode.plan-header"
        observed_route = {"model": observed, "agent": "plan"}
    else:
        raise RuntimeError(f"unknown reviewer kind: {args.kind}")

    payload, blockers = parse_marker(report, args.expected_commit, args.expected_tree)
    report_path = Path(args.report)
    atomic_text(report_path, report if report.endswith("\n") else report + "\n")
    status = load_json(Path(args.status))
    status_trust = status.get("tool_trust")
    if not isinstance(status_trust, dict) or status_trust.get("error"):
        raise RuntimeError("reviewer status has no successful tool attestation")
    current_trust = load_tool_trust_manifest(
        args.trust_manifest,
        args.trust_manifest_sha256,
        args.trust_mode,
        args.repo_root,
    )
    current_actual = current_trust["tools"][args.tool_name]["actual"]
    expected = dict(status_trust.get("expected") or {}).get(args.tool_name)
    pre_actual = dict(status_trust.get("pre") or {}).get(args.tool_name)
    post_actual = dict(status_trust.get("post") or {}).get(args.tool_name)
    if not all(isinstance(value, dict) for value in (expected, pre_actual, post_actual)):
        raise RuntimeError("reviewer status tool attestation is incomplete")
    if not _same_attested_actual(pre_actual, post_actual) or not _same_attested_actual(
        post_actual, current_actual
    ):
        raise RuntimeError("reviewer tool identity changed before receipt creation")
    if os.path.normcase(str(current_actual["path"])) != os.path.normcase(
        str(Path(args.tool).resolve(strict=True))
    ):
        raise RuntimeError("reviewer receipt path is not the attested tool")
    receipt = {
        "schema": 1,
        "route_id": args.route_id,
        "family": args.family,
        "kind": args.kind,
        "requested_model": args.expected_model,
        "observed_model": observed,
        "connection_domain": args.connection_domain,
        "expected_route": {
            "requested_model": args.expected_model,
            "connection_domain": args.connection_domain,
        },
        "observed_route": observed_route,
        "route_evidence": route_evidence,
        "completion_evidence": "exit=0+structured-verdict-marker",
        "reviewed_commit": args.expected_commit,
        "reviewed_tree": args.expected_tree,
        "verdict": payload["verdict"],
        "summary": payload["summary"],
        "findings": payload["findings"],
        "blocker_count": blockers,
        "raw_sha256": sha256_file(raw_path),
        "report_sha256": sha256_file(report_path),
        "tool": {
            "name": args.tool_name,
            "expected": expected,
            "pre_actual": pre_actual,
            "post_actual": post_actual,
            "receipt_actual": current_actual,
            "same_identity_through_receipt": True,
        },
        "trust_mode": args.trust_mode,
        "formal_evidence_eligible": current_trust["formal_evidence_eligible"],
        "bootstrap": current_trust["bootstrap"],
    }
    atomic_json(Path(args.receipt), receipt)
    return 10 if blockers or payload["verdict"] == "fail" else 0


def load_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"expected JSON object: {path}")
    return value


def write_tool_trust_preflight(args: argparse.Namespace) -> int:
    trust = load_tool_trust_manifest(
        args.trust_manifest,
        args.trust_manifest_sha256,
        args.trust_mode,
        args.repo_root,
    )
    atomic_json(Path(args.output), trust)
    return 0


def _git_environment(git_path: Path) -> dict[str, str]:
    environment = {
        "PATH": str(git_path.parent),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        # These are fixed policy values, not inherited GIT_* controls.
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
    }
    if os.name == "nt":
        windows = os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows"
        environment.update({"SystemRoot": windows, "WINDIR": windows})
    return environment


def run_fixed_git(args: argparse.Namespace) -> int:
    trust = load_tool_trust_manifest(
        args.trust_manifest,
        args.trust_manifest_sha256,
        args.trust_mode,
        args.repo_root,
    )
    git_actual = trust["tools"]["git"]["actual"]
    git_path = Path(git_actual["path"])
    requested_git = Path(args.git).resolve(strict=True)
    if os.path.normcase(str(git_path)) != os.path.normcase(str(requested_git)):
        raise TrustError("fixed Git command is not the attested Git executable")
    repo = _absolute_nonredirect_path(args.repo_root, regular=False)
    values = list(args.values)
    base = [
        str(git_path),
        "--no-replace-objects",
        "-c",
        f"safe.directory={repo}",
        "-c",
        "credential.helper=",
        "-c",
        "core.hooksPath=NUL" if os.name == "nt" else "core.hooksPath=/dev/null",
        "-C",
        str(repo),
    ]
    output_path: Path | None = None
    if args.operation == "resolve-commit" and len(values) == 1:
        command = base + ["rev-parse", "--verify", "--end-of-options", f"{values[0]}^{{commit}}"]
    elif args.operation == "resolve-tree" and len(values) == 1:
        command = base + ["rev-parse", "--verify", "--end-of-options", f"{values[0]}^{{tree}}"]
    elif args.operation == "parent-line" and len(values) == 1:
        command = base + ["rev-list", "--parents", "-n", "1", "--end-of-options", values[0]]
    elif args.operation == "archive" and len(values) == 2:
        target, raw_output = values
        output_path = Path(raw_output)
        if not output_path.is_absolute() or ".." in output_path.parts:
            raise TrustError("Git archive output must be an absolute contained path")
        _absolute_nonredirect_path(str(output_path.parent), regular=False)
        command = base + ["archive", "--format=tar", f"--output={output_path}", "--end-of-options", target]
    elif args.operation == "diff" and len(values) == 3:
        parent, target, raw_output = values
        output_path = Path(raw_output)
        if not output_path.is_absolute() or ".." in output_path.parts:
            raise TrustError("Git diff output must be an absolute contained path")
        _absolute_nonredirect_path(str(output_path.parent), regular=False)
        command = base + [
            "--no-pager",
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--binary",
            "--find-renames",
            parent,
            target,
            "--",
        ]
    else:
        raise TrustError(f"invalid fixed Git operation/arguments: {args.operation}")
    if output_path is not None and output_path.exists():
        raise TrustError(f"fixed Git output already exists: {output_path}")
    stdout_target: int | object = subprocess.PIPE
    output_handle = None
    if args.operation == "diff":
        output_handle = output_path.open("xb")
        stdout_target = output_handle
    try:
        completed = subprocess.run(
            command,
            cwd=str(repo),
            env=_git_environment(git_path),
            stdin=subprocess.DEVNULL,
            stdout=stdout_target,
            stderr=subprocess.PIPE,
            shell=False,
            timeout=60,
        )
    finally:
        if output_handle is not None:
            output_handle.close()
    if completed.returncode != 0:
        if output_path is not None:
            try:
                output_path.unlink()
            except FileNotFoundError:
                pass
        message = completed.stderr.decode("utf-8", errors="replace").strip()
        raise TrustError(f"fixed Git {args.operation} failed ({completed.returncode}): {message}")
    if completed.stdout:
        sys.stdout.buffer.write(completed.stdout)
    return 0


def artifact_inventory(output: Path) -> list[dict[str, object]]:
    artifacts: list[dict[str, object]] = []
    for path in sorted(output.rglob("*")):
        if not path.is_file() or path.name == "audit-manifest.json":
            continue
        relative = path.relative_to(output).as_posix()
        if relative.startswith("review-root/input/"):
            continue
        artifacts.append(
            {"path": relative, "size": path.stat().st_size, "sha256": sha256_file(path)}
        )
    return artifacts


def write_manifest(args: argparse.Namespace) -> int:
    output = Path(args.output)
    reviewers: list[dict[str, object]] = []
    for line in Path(args.roster).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        (
            route_id,
            family,
            kind,
            requested,
            connection_domain,
            tool,
            status_name,
            receipt_name,
            raw_name,
        ) = line.split("\t")
        status_path = output / status_name
        receipt_path = output / receipt_name
        entry: dict[str, object] = {
            "route_id": route_id,
            "family": family,
            "kind": kind,
            "requested_model": requested,
            "connection_domain": connection_domain,
            "tool_path": tool,
            "raw_log": raw_name,
            "status": load_json(status_path) if status_path.exists() else {"reason": "missing-status"},
        }
        if receipt_path.exists():
            entry["receipt"] = load_json(receipt_path)
        reviewers.append(entry)
    domain_counts: dict[str, int] = {}
    for reviewer in reviewers:
        domain = str(reviewer["connection_domain"])
        domain_counts[domain] = domain_counts.get(domain, 0) + 1
    for reviewer in reviewers:
        reviewer["shared_connection_domain"] = (
            domain_counts[str(reviewer["connection_domain"])] > 1
        )
    snapshot_manifest = output / "snapshot-manifest.json"
    diff = output / "review-root" / "input" / ".xreview-evidence" / "target.diff"
    manifest = {
        "schema": 1,
        "generated_at": utc_now(),
        "initiator": {
            "family": args.initiator,
            "invoked_as_reviewer": False,
            "vote_weight": 0,
        },
        "target": {
            "commit": args.target,
            "parent": args.parent,
            "tree": args.tree,
            "diff_sha256": sha256_file(diff),
            "snapshot_manifest_sha256": sha256_file(snapshot_manifest),
        },
        "reviewer_count": len(reviewers),
        "formal_independent_domain_count": len(domain_counts),
        "formal_four_independent_votes_satisfied": len(domain_counts) == 4,
        "reviewers": reviewers,
        "execution_result": args.execution,
        "security_verdict": args.security,
        "tool_trust": load_json(Path(args.tool_trust_preflight)),
        "supervisor_probe": load_json(Path(args.supervisor_status)),
        "artifacts": artifact_inventory(output),
    }
    atomic_json(output / "audit-manifest.json", manifest)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)

    extract = commands.add_parser("extract")
    extract.add_argument("archive")
    extract.add_argument("destination")

    snapshot = commands.add_parser("snapshot")
    snapshot.add_argument("root")
    snapshot.add_argument("output")

    verify = commands.add_parser("verify-snapshot")
    verify.add_argument("root")
    verify.add_argument("manifest")

    run = commands.add_parser("supervise")
    run.add_argument("--timeout", required=True, type=float)
    run.add_argument("--startup-timeout", type=float)
    run.add_argument("--startup-marker")
    run.add_argument("--output", required=True)
    run.add_argument("--status", required=True)
    run.add_argument("--bash", required=True)
    run.add_argument("--wrapper", required=True)
    run.add_argument("--gate", required=True)
    run.add_argument("--script", required=True)
    run.add_argument("--command-sha256", required=True)
    run.add_argument("--wrapper-sha256", required=True)
    run.add_argument("--cwd", required=True)
    run.add_argument("--tool-name", required=True)
    run.add_argument("--tool-path", required=True)
    run.add_argument(
        "--reviewer-family",
        required=True,
        choices=("probe", "openai", "zhipu", "moonshot", "minimax", "deepseek"),
    )
    run.add_argument("--trust-manifest", required=True)
    run.add_argument("--trust-manifest-sha256", required=True)
    run.add_argument("--trust-mode", required=True, choices=("formal", "test-only"))
    run.add_argument("--repo-root", required=True)

    status = commands.add_parser("status-ok")
    status.add_argument("status")

    probe = commands.add_parser("probe-ok")
    probe.add_argument("status")
    probe.add_argument("log")

    unavailable = commands.add_parser("unavailable")
    unavailable.add_argument("status")
    unavailable.add_argument("reason")

    validate = commands.add_parser("validate")
    validate.add_argument("--kind", required=True, choices=("kimi", "codex", "opencode"))
    validate.add_argument("--raw", required=True)
    validate.add_argument("--report", required=True)
    validate.add_argument("--receipt", required=True)
    validate.add_argument("--route-id", required=True)
    validate.add_argument("--family", required=True)
    validate.add_argument("--expected-model", required=True)
    validate.add_argument("--connection-domain", required=True)
    validate.add_argument("--kimi-code-home", default="")
    validate.add_argument("--kimi-baseline", default="")
    validate.add_argument("--kimi-baseline-sha256", default="")
    validate.add_argument("--expected-commit", required=True)
    validate.add_argument("--expected-tree", required=True)
    validate.add_argument("--tool", required=True)
    validate.add_argument("--tool-name", required=True)
    validate.add_argument("--status", required=True)
    validate.add_argument("--trust-manifest", required=True)
    validate.add_argument("--trust-manifest-sha256", required=True)
    validate.add_argument("--trust-mode", required=True, choices=("formal", "test-only"))
    validate.add_argument("--repo-root", required=True)

    manifest = commands.add_parser("manifest")
    manifest.add_argument("--output", required=True)
    manifest.add_argument("--roster", required=True)
    manifest.add_argument("--initiator", required=True)
    manifest.add_argument("--target", required=True)
    manifest.add_argument("--parent", required=True)
    manifest.add_argument("--tree", required=True)
    manifest.add_argument("--execution", required=True)
    manifest.add_argument("--security", required=True)
    manifest.add_argument("--supervisor-status", required=True)
    manifest.add_argument("--tool-trust-preflight", required=True)

    file_hash = commands.add_parser("file-hash")
    file_hash.add_argument("path")

    trust = commands.add_parser("trust-preflight")
    trust.add_argument("--trust-manifest", required=True)
    trust.add_argument("--trust-manifest-sha256", required=True)
    trust.add_argument("--trust-mode", required=True, choices=("formal", "test-only"))
    trust.add_argument("--repo-root", required=True)
    trust.add_argument("--output", required=True)

    git_run = commands.add_parser("git-run")
    git_run.add_argument("--git", required=True)
    git_run.add_argument("--repo-root", required=True)
    git_run.add_argument("--trust-manifest", required=True)
    git_run.add_argument("--trust-manifest-sha256", required=True)
    git_run.add_argument("--trust-mode", required=True, choices=("formal", "test-only"))
    git_run.add_argument(
        "operation", choices=("resolve-commit", "resolve-tree", "parent-line", "archive", "diff")
    )
    git_run.add_argument("values", nargs="*")

    mkdir = commands.add_parser("fs-mkdir")
    mkdir.add_argument("paths", nargs="+")

    unlink = commands.add_parser("fs-unlink")
    unlink.add_argument("path")

    kimi_baseline = commands.add_parser("kimi-baseline")
    kimi_baseline.add_argument("--code-home", required=True)
    kimi_baseline.add_argument("--output", required=True)

    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "extract":
        safe_extract(Path(args.archive), Path(args.destination))
        return 0
    if args.command == "snapshot":
        atomic_json(Path(args.output), {"schema": 1, "files": snapshot_files(Path(args.root))})
        return 0
    if args.command == "verify-snapshot":
        expected = load_json(Path(args.manifest))
        return 0 if expected == {"schema": 1, "files": snapshot_files(Path(args.root))} else 1
    if args.command == "supervise":
        return supervise(args)
    if args.command == "status-ok":
        status = load_json(Path(args.status))
        return 0 if status.get("rc") == 0 and status.get("reason") == "completed" and not status.get("timed_out") else 1
    if args.command == "probe-ok":
        status = load_json(Path(args.status))
        log = Path(args.log).read_text(encoding="utf-8", errors="replace")
        match = re.search(r"(?m)^CHILD_WINPID=([1-9][0-9]*)$", log)
        child_gone = False
        if match is not None:
            try:
                os.kill(int(match.group(1)), 0)
            except ProcessLookupError:
                child_gone = True
            except PermissionError:
                child_gone = False
            except OSError as error:
                child_gone = getattr(error, "winerror", None) in (87, 1168)
        return 0 if (
            status.get("rc") == 124
            and status.get("reason") == "timeout"
            and status.get("startup_ready") is True
            and status.get("startup_timed_out") is False
            and status.get("tree_kill_confirmed") is True
            and child_gone
        ) else 1
    if args.command == "unavailable":
        atomic_json(
            Path(args.status),
            {
                "schema": 1,
                "started_at": utc_now(),
                "ended_at": utc_now(),
                "pid": None,
                "rc": 127,
                "reason": args.reason,
                "timed_out": False,
                "tree_kill_attempted": False,
                "tree_kill_confirmed": None,
            },
        )
        return 0
    if args.command == "validate":
        try:
            return validate_review(args)
        except BaseException as error:
            print(f"xreview validation error: {type(error).__name__}: {error}", file=sys.stderr)
            return 20
    if args.command == "manifest":
        return write_manifest(args)
    if args.command == "file-hash":
        print(sha256_file(Path(args.path)))
        return 0
    if args.command == "trust-preflight":
        try:
            return write_tool_trust_preflight(args)
        except BaseException as error:
            print(f"xreview trust error: {type(error).__name__}: {error}", file=sys.stderr)
            return 78
    if args.command == "git-run":
        try:
            return run_fixed_git(args)
        except BaseException as error:
            print(f"xreview fixed Git error: {type(error).__name__}: {error}", file=sys.stderr)
            return 78
    if args.command == "fs-mkdir":
        for value in args.paths:
            path = Path(value)
            if not path.is_absolute() or ".." in path.parts:
                raise RuntimeError(f"refusing non-absolute mkdir target: {value}")
            path.mkdir(exist_ok=False)
        return 0
    if args.command == "fs-unlink":
        path = _absolute_nonredirect_path(args.path, regular=True)
        path.unlink()
        return 0
    if args.command == "kimi-baseline":
        try:
            return write_kimi_baseline(args)
        except BaseException as error:
            print(
                f"xreview Kimi baseline error: {type(error).__name__}: {error}",
                file=sys.stderr,
            )
            return 78
    raise AssertionError(args.command)


if __name__ == "__main__":
    raise SystemExit(main())
PY

if ! "$python_bin" -I -S -B -X utf8 -m py_compile "$helper"; then
  echo "xreview: generated supervisor failed validation" >&2
  exit 69
fi

trust_preflight="$output_dir/tool-trust-preflight.json"
if ! "$python_bin" -I -S -B -X utf8 "$helper" trust-preflight \
  --trust-manifest "$trust_manifest" \
  --trust-manifest-sha256 "$trust_manifest_sha256" \
  --trust-mode "$trust_mode" --repo-root "$repo_root" \
  --output "$trust_preflight"; then
  echo "xreview: tool trust preflight failed; no model was started" >&2
  exit 78
fi

declare -A trusted_tool_path=()
declare -A trusted_tool_launch=()
declare -A trusted_tool_size=()
declare -A trusted_tool_sha256=()
while IFS=$'\t' read -r record name launch path size sha extra; do
  if [[ "$record" != "tool" ]]; then
    continue
  fi
  if [[ -z "$name" || -n "$extra" || -n "${trusted_tool_path[$name]:-}" ]]; then
    echo "xreview: invalid trusted tool row" >&2
    exit 78
  fi
  trusted_tool_path[$name]="$path"
  trusted_tool_launch[$name]="$launch"
  trusted_tool_size[$name]="$size"
  trusted_tool_sha256[$name]="$sha"
done < "$trust_manifest"

bash_bin="${trusted_tool_path[bash]:-}"
git_bin="${trusted_tool_path[git]:-}"
taskkill_bin="${trusted_tool_path[taskkill]:-}"
if [[ -z "$bash_bin" || -z "$git_bin" || ( "${OS:-}" == "Windows_NT" && -z "$taskkill_bin" ) ]]; then
  echo "xreview: trusted bootstrap tool closure is incomplete" >&2
  exit 78
fi

run_fixed_git() {
  "$python_bin" -I -S -B -X utf8 "$helper" git-run \
    --git "$git_bin" --repo-root "$repo_root" \
    --trust-manifest "$trust_manifest" \
    --trust-manifest-sha256 "$trust_manifest_sha256" \
    --trust-mode "$trust_mode" "$@"
}

if ! target="$(run_fixed_git resolve-commit "$requested")"; then
  echo "xreview: invalid commit: ${requested}" >&2
  exit 64
fi
if ! tree="$(run_fixed_git resolve-tree "$target")"; then
  echo "xreview: target tree is unavailable: ${target}" >&2
  exit 64
fi
read -r -a commit_line <<<"$(run_fixed_git parent-line "$target")"
if [[ "${#commit_line[@]}" -ne 2 ]]; then
  echo "xreview: target must have exactly one parent; root/merge commits require an explicit audit policy" >&2
  exit 64
fi
parent="${commit_line[1]}"
short="${target:0:12}"

# Prove the local supervisor can time out and remove a nested child before any model starts.
gate_wrapper="$output_dir/supervisor-gate-wrapper.sh"
while IFS= read -r _xreview_source_line; do
  printf '%s\n' "$_xreview_source_line"
done >"$gate_wrapper" <<'SH'
#!/usr/bin/env bash
set -uo pipefail
gate="$1"
script="$2"
while [[ ! -f "$gate" ]]; do :; done
exec "$BASH" "$script"
SH
probe_script="$output_dir/supervisor-probe.sh"
probe_log="$output_dir/supervisor-probe.log"
probe_status="$output_dir/supervisor-probe.status.json"
probe_gate="$output_dir/supervisor-probe.gate"
while IFS= read -r _xreview_source_line; do
  printf '%s\n' "$_xreview_source_line"
done >"$probe_script" <<'SH'
#!/usr/bin/env bash
set -uo pipefail
"$XREVIEW_PROBE_PYTHON" -I -S -B -X utf8 -c 'import os,time; print(f"CHILD_WINPID={os.getpid()}", flush=True); time.sleep(60)' &
child=$!
printf 'CHILD_PID=%s\n' "$child"
wait "$child"
SH
gate_wrapper_hash="$("$python_bin" -I -S -B -X utf8 "$helper" file-hash "$gate_wrapper")"
probe_script_hash="$("$python_bin" -I -S -B -X utf8 "$helper" file-hash "$probe_script")"
XREVIEW_PROBE_PYTHON="$python_bin" "$python_bin" -I -S -B -X utf8 "$helper" supervise \
  --startup-timeout 20 --startup-marker CHILD_WINPID= \
  --timeout 3 --output "$probe_log" --status "$probe_status" \
  --bash "$bash_bin" --wrapper "$gate_wrapper" --gate "$probe_gate" \
  --wrapper-sha256 "$gate_wrapper_hash" \
  --script "$probe_script" --command-sha256 "$probe_script_hash" --cwd "$output_dir" \
  --tool-name python --tool-path "$python_bin" --reviewer-family probe \
  --trust-manifest "$trust_manifest" \
  --trust-manifest-sha256 "$trust_manifest_sha256" --trust-mode "$trust_mode" \
  --repo-root "$repo_root"
if ! "$python_bin" -I -S -B -X utf8 "$helper" probe-ok "$probe_status" "$probe_log"; then
  echo "xreview: process-tree timeout self-test failed; no model was started" >&2
  echo "XREVIEW_EXECUTION_RESULT=FAIL"
  echo "XREVIEW_SECURITY_VERDICT=BLOCKED"
  echo "raw_output_dir=${output_dir}"
  exit 1
fi

# Build a clean archive from the Git object database; never checkout and never touch the user's index.
review_root="$output_dir/review-root"
snapshot="$review_root/input"
archive="$output_dir/target.tar"
if ! run_fixed_git archive "$target" "$archive"; then
  echo "xreview: git archive failed" >&2
  exit 1
fi
if ! "$python_bin" -I -S -B -X utf8 "$helper" extract "$archive" "$snapshot"; then
  echo "xreview: unsafe or unreadable target archive" >&2
  exit 1
fi
"$python_bin" -I -S -B -X utf8 "$helper" fs-unlink "$archive" || exit 1
evidence="$snapshot/.xreview-evidence"
if [[ -e "$evidence" ]]; then
  echo "xreview: target collides with reserved evidence directory" >&2
  exit 1
fi
"$python_bin" -I -S -B -X utf8 "$helper" fs-mkdir "$evidence" || exit 1
if ! run_fixed_git diff "$parent" "$target" "$evidence/target.diff"; then
  echo "xreview: cannot freeze target diff" >&2
  exit 1
fi
printf '{"schema":1,"commit":"%s","parent":"%s","tree":"%s"}\n' \
  "$target" "$parent" "$tree" >"$evidence/target.json"
snapshot_manifest="$output_dir/snapshot-manifest.json"
if ! "$python_bin" -I -S -B -X utf8 "$helper" snapshot "$snapshot" "$snapshot_manifest"; then
  echo "xreview: snapshot contains unsafe links or special files" >&2
  exit 1
fi

all_ids=(moonshot-k3 openai-sol zhipu-glm minimax-m3 deepseek-v4)
all_families=(moonshot openai zhipu minimax deepseek)
all_kinds=(kimi codex opencode opencode opencode)
all_requested=(kimi-code/k3 gpt-5.6-sol glm-5.2 minimax-m3 deepseek-v4-pro)
all_provider_models=(kimi-code/k3 gpt-5.6-sol volcengine/glm-5.2 volcengine/minimax-m3 volcengine/deepseek-v4-pro)
all_connection_domains=(kimi-code-login codex-login opencode-volcano-coding opencode-volcano-coding opencode-volcano-coding)

declare -a selected_indexes=()
declare -A selected_families=()
declare -A selected_domains=()
for index in "${!all_ids[@]}"; do
  family="${all_families[$index]}"
  if [[ "$family" == "$initiator_family" ]]; then continue; fi
  if [[ -n "${selected_families[$family]:-}" ]]; then
    echo "xreview: duplicate reviewer family: ${family}" >&2
    exit 1
  fi
  selected_families[$family]=1
  selected_domains["${all_connection_domains[$index]}"]=1
  selected_indexes+=("$index")
done
if [[ "${#selected_indexes[@]}" -ne 4 || "${#selected_families[@]}" -ne 4 ]]; then
  echo "xreview: initiator exclusion must leave exactly four independent families" >&2
  exit 1
fi
if [[ "$trust_mode" == "formal" && "${#selected_domains[@]}" -ne 4 ]]; then
  echo "xreview: four independent connection domains are required; current roster has ${#selected_domains[@]}; no model was started" >&2
  exit 78
fi

verdict_contract="最后一行必须且只能出现一次 XREVIEW_VERDICT_JSON={\"schema\":1,\"reviewed_commit\":\"${target}\",\"reviewed_tree\":\"${tree}\",\"verdict\":\"pass或fail\",\"summary\":\"非空结论\",\"findings\":[{\"severity\":\"P0/P1/P2/P3\",\"file\":\"路径\",\"line\":\"行号\",\"summary\":\"问题\"}]}。有P0/P1时verdict必须为fail；无问题时findings为空数组。"
common_prompt="你是独立发布审查员。唯一允许审查的输入是当前目录下 input/ 冻结快照；input/.xreview-evidence/target.diff 是父提交到目标提交的冻结差异，target.json 给出精确 commit/tree。禁止读取当前机器上的原始仓库、父目录或任何脏工作区；禁止写文件、禁止调用子智能体。只报告可由具体代码路径复现的问题。${verdict_contract}"

commands_dir="$output_dir/commands"
logs_dir="$output_dir/logs"
statuses_dir="$output_dir/statuses"
receipts_dir="$output_dir/receipts"
reports_dir="$output_dir/reports"
"$python_bin" -I -S -B -X utf8 "$helper" fs-mkdir \
  "$commands_dir" "$logs_dir" "$statuses_dir" "$receipts_dir" "$reports_dir" || exit 1
roster="$output_dir/roster.tsv"
: >"$roster"

declare -a reviewer_ids=()
declare -a reviewer_families=()
declare -a reviewer_kinds=()
declare -a reviewer_expected=()
declare -a reviewer_connection_domains=()
declare -a reviewer_kimi_code_homes=()
declare -a reviewer_kimi_baselines=()
declare -a reviewer_kimi_baseline_sha256s=()
declare -a reviewer_tools=()
declare -a reviewer_raws=()
declare -a reviewer_statuses=()
declare -a reviewer_receipts=()
declare -a reviewer_reports=()

declare -A kimi_code_home_by_index=()
declare -A kimi_baseline_by_index=()
declare -A kimi_baseline_sha256_by_index=()
for index in "${selected_indexes[@]}"; do
  if [[ "${all_kinds[$index]}" != "kimi" ]]; then continue; fi
  if [[ "$trust_mode" == "test-only" ]]; then
    kimi_code_home="${FAKE_KIMI_CODE_HOME:-}"
  else
    kimi_code_home="${XREVIEW_MOONSHOT_KIMI_CODE_HOME:-}"
  fi
  if [[ -z "$kimi_code_home" ]]; then
    echo "xreview: Kimi code home is required before reviewer launch" >&2
    exit 78
  fi
  kimi_baseline="$statuses_dir/${all_ids[$index]}.kimi-baseline.json"
  if ! "$python_bin" -I -S -B -X utf8 "$helper" kimi-baseline \
    --code-home "$kimi_code_home" --output "$kimi_baseline"; then
    echo "xreview: Kimi session baseline failed; no model was started" >&2
    exit 78
  fi
  kimi_baseline_sha256="$("$python_bin" -I -S -B -X utf8 "$helper" file-hash "$kimi_baseline")" || exit 78
  kimi_code_home_by_index[$index]="$kimi_code_home"
  kimi_baseline_by_index[$index]="$kimi_baseline"
  kimi_baseline_sha256_by_index[$index]="$kimi_baseline_sha256"
done

write_command_script() {
  local destination="$1"
  shift
  {
    printf '#!/usr/bin/env bash\nset -uo pipefail\n'
    printf 'cd %q || exit 125\n' "$review_root"
    printf 'exec'
    local argument
    for argument in "$@"; do printf ' %q' "$argument"; done
    printf '\n'
  } >"$destination"
}

start_supervised() {
  local seconds="$1" raw="$2" status="$3" command_script="$4" gate="$5" tool_name="$6" tool_path="$7" reviewer_family="$8"
  local command_hash
  command_hash="$("$python_bin" -I -S -B -X utf8 "$helper" file-hash "$command_script")" || return 1
  "$python_bin" -I -S -B -X utf8 "$helper" supervise \
    --timeout "$seconds" --output "$raw" --status "$status" \
    --bash "$bash_bin" --wrapper "$gate_wrapper" --gate "$gate" \
    --wrapper-sha256 "$gate_wrapper_hash" \
    --script "$command_script" --command-sha256 "$command_hash" --cwd "$review_root" \
    --tool-name "$tool_name" --tool-path "$tool_path" --reviewer-family "$reviewer_family" \
    --trust-manifest "$trust_manifest" \
    --trust-manifest-sha256 "$trust_manifest_sha256" --trust-mode "$trust_mode" \
    --repo-root "$repo_root" &
  supervisor_pids+=("$!")
}

for index in "${selected_indexes[@]}"; do
  route_id="${all_ids[$index]}"
  family="${all_families[$index]}"
  kind="${all_kinds[$index]}"
  expected="${all_requested[$index]}"
  provider_model="${all_provider_models[$index]}"
  connection_domain="${all_connection_domains[$index]}"
  raw_rel="logs/${route_id}.log"
  status_rel="statuses/${route_id}.json"
  receipt_rel="receipts/${route_id}.json"
  report_rel="reports/${route_id}.txt"
  raw="$output_dir/$raw_rel"
  status="$output_dir/$status_rel"
  receipt="$output_dir/$receipt_rel"
  report="$output_dir/$report_rel"
  command_script="$commands_dir/${route_id}.sh"
  command_gate="$commands_dir/${route_id}.gate"
  tool_path="${trusted_tool_path[$kind]:-}"
  tool_launch="${trusted_tool_launch[$kind]:-}"

  reviewer_ids+=("$route_id")
  reviewer_families+=("$family")
  reviewer_kinds+=("$kind")
  reviewer_expected+=("$expected")
  reviewer_connection_domains+=("$connection_domain")
  reviewer_kimi_code_homes+=("${kimi_code_home_by_index[$index]:-}")
  reviewer_kimi_baselines+=("${kimi_baseline_by_index[$index]:-}")
  reviewer_kimi_baseline_sha256s+=("${kimi_baseline_sha256_by_index[$index]:-}")
  reviewer_tools+=("${tool_path:-unavailable}")
  reviewer_raws+=("$raw")
  reviewer_statuses+=("$status")
  reviewer_receipts+=("$receipt")
  reviewer_reports+=("$report")

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$route_id" "$family" "$kind" "$expected" "$connection_domain" "${tool_path:-unavailable}" \
    "$status_rel" "$receipt_rel" "$raw_rel" >>"$roster"

  if [[ -z "$tool_path" ]]; then
    printf 'reviewer tool unavailable: %s\n' "$kind" >"$raw"
    "$python_bin" -I -S -B -X utf8 "$helper" unavailable "$status" "tool-unavailable:${kind}"
    continue
  fi

  focus=""
  case "$route_id" in
    moonshot-k3) focus="主审跨模块架构、权限、并发、更新与供应链。" ;;
    openai-sol) focus="交叉复查正确性、安全边界、并发和发布阻断项。" ;;
    zhipu-glm) focus="重点审查 gateway/、bridge/ 消息可达性、超时、身份与重放。" ;;
    minimax-m3) focus="重点审查 desktop/、发布工作流、自动更新与供应链门禁。" ;;
    deepseek-v4) focus="重点审查 orchestrator/ 持久化、租约、审批、撤销和工具边界。" ;;
  esac
  prompt="${common_prompt}${focus}正文用中文，按 文件:行→触发条件→影响→修复；不要在最后结构化行之后输出任何文字。"

  case "$kind" in
    kimi)
      if [[ "$tool_launch" == "bash-script" ]]; then command=("$bash_bin" "$tool_path"); else command=("$tool_path"); fi
      write_command_script "$command_script" "${command[@]}" --plan \
        -m "$provider_model" -p "$prompt" --output-format stream-json
      start_supervised "$kimi_timeout" "$raw" "$status" "$command_script" "$command_gate" kimi "$tool_path" "$family"
      ;;
    codex)
      if [[ "$tool_launch" == "bash-script" ]]; then command=("$bash_bin" "$tool_path"); else command=("$tool_path"); fi
      write_command_script "$command_script" "${command[@]}" exec -s read-only \
        -m "$provider_model" -c model_reasoning_effort=high "$prompt"
      start_supervised "$codex_timeout" "$raw" "$status" "$command_script" "$command_gate" codex "$tool_path" "$family"
      ;;
    opencode)
      if [[ "$tool_launch" == "bash-script" ]]; then command=("$bash_bin" "$tool_path"); else command=("$tool_path"); fi
      write_command_script "$command_script" "${command[@]}" run "$prompt" \
        --pure --agent plan --title "nachuan-xreview-${short}-${route_id}" \
        -m "$provider_model" --dir "$review_root"
      start_supervised "$opencode_timeout" "$raw" "$status" "$command_script" "$command_gate" opencode "$tool_path" "$family"
      ;;
  esac
done

for supervisor_index in "${!supervisor_pids[@]}"; do
  pid="${supervisor_pids[$supervisor_index]}"
  wait "$pid" || true
  supervisor_pids[$supervisor_index]=""
done

operational_failures=0
security_failures=0
for i in "${!reviewer_ids[@]}"; do
  route_id="${reviewer_ids[$i]}"
  raw="${reviewer_raws[$i]}"
  status="${reviewer_statuses[$i]}"
  echo "==== ${route_id} ===="
  if ! "$python_bin" -I -S -B -X utf8 "$helper" status-ok "$status"; then
    echo "route execution failed: ${route_id}" >&2
    operational_failures=$((operational_failures + 1))
    continue
  fi
  "$python_bin" -I -S -B -X utf8 "$helper" validate \
    --kind "${reviewer_kinds[$i]}" --raw "$raw" --report "${reviewer_reports[$i]}" \
    --receipt "${reviewer_receipts[$i]}" --route-id "$route_id" \
    --family "${reviewer_families[$i]}" --expected-model "${reviewer_expected[$i]}" \
    --connection-domain "${reviewer_connection_domains[$i]}" \
    --kimi-code-home "${reviewer_kimi_code_homes[$i]}" \
    --kimi-baseline "${reviewer_kimi_baselines[$i]}" \
    --kimi-baseline-sha256 "${reviewer_kimi_baseline_sha256s[$i]}" \
    --expected-commit "$target" --expected-tree "$tree" --tool "${reviewer_tools[$i]}" \
    --tool-name "${reviewer_kinds[$i]}" --status "$status" \
    --trust-manifest "$trust_manifest" --trust-manifest-sha256 "$trust_manifest_sha256" \
    --trust-mode "$trust_mode" --repo-root "$repo_root"
  validation_rc=$?
  case "$validation_rc" in
    0) ;;
    10) security_failures=$((security_failures + 1)) ;;
    *) operational_failures=$((operational_failures + 1)) ;;
  esac
done

if ! "$python_bin" -I -S -B -X utf8 "$helper" verify-snapshot "$snapshot" "$snapshot_manifest"; then
  echo "xreview: frozen review input changed during review" >&2
  operational_failures=$((operational_failures + 1))
fi

if [[ "$operational_failures" -eq 0 ]]; then
  if [[ "$trust_mode" == "test-only" ]]; then
    execution_result="NON_FORMAL_TEST_COMPLETE"
    if [[ "$security_failures" -eq 0 ]]; then
      security_verdict="NON_FORMAL_TEST_ONLY"
    else
      security_verdict="FAIL"
    fi
  else
    execution_result="PASS"
    if [[ "$security_failures" -eq 0 ]]; then security_verdict="PASS"; else security_verdict="FAIL"; fi
  fi
else
  execution_result="FAIL"
  security_verdict="BLOCKED"
fi

if ! "$python_bin" -I -S -B -X utf8 "$helper" manifest \
  --output "$output_dir" --roster "$roster" --initiator "$initiator_family" \
  --target "$target" --parent "$parent" --tree "$tree" \
  --execution "$execution_result" --security "$security_verdict" \
  --supervisor-status "$probe_status" --tool-trust-preflight "$trust_preflight"; then
  echo "xreview: audit manifest creation failed" >&2
  echo "XREVIEW_EXECUTION_RESULT=FAIL"
  echo "XREVIEW_SECURITY_VERDICT=BLOCKED"
  echo "raw_output_dir=${output_dir}"
  exit 1
fi
manifest_hash="$("$python_bin" -I -S -B -X utf8 "$helper" file-hash "$output_dir/audit-manifest.json")"
printf '%s  audit-manifest.json\n' "$manifest_hash" >"$output_dir/audit-manifest.sha256"

echo "XREVIEW_INITIATOR_FAMILY=${initiator_family} vote_weight=0 reviewer_count=4"
if [[ "$trust_mode" == "formal" ]]; then
  echo "XREVIEW_TRUST_MODE=FORMAL bootstrap=external-protected-launcher-required"
else
  echo "XREVIEW_TRUST_MODE=TEST_ONLY formal_evidence_eligible=false"
fi
echo "XREVIEW_EXECUTION_RESULT=${execution_result}"
echo "XREVIEW_SECURITY_VERDICT=${security_verdict}"
echo "audit_manifest_sha256=${manifest_hash}"
echo "raw_output_dir=${output_dir}"

if [[ "$trust_mode" == "test-only" && "$execution_result" == "NON_FORMAL_TEST_COMPLETE" && "$security_verdict" == "NON_FORMAL_TEST_ONLY" ]]; then
  # Deliberately non-zero: test scaffolding must never satisfy a formal PASS gate.
  exit 3
fi
if [[ "$execution_result" != "PASS" || "$security_verdict" != "PASS" ]]; then
  exit 1
fi
exit 0
