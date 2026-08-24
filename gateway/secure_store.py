"""Windows 当前用户作用域的运行态密钥存储。

文件只保存 DPAPI 密文信封；首次读取旧版明文 JSON 时会原位迁移。迁移前先收紧
父目录 ACL，写入采用同目录临时文件 + 原子替换，任何异常都失败关闭，绝不回退明文。
"""

from __future__ import annotations

import base64
import ctypes
import json
import os
import stat
import tempfile
import threading
import time
from ctypes import wintypes
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Mapping


_SCHEMA = "nachuan.protected-json.v1"
_PROTECTION = "windows-dpapi-current-user"
_DPAPI_DOMAIN = b"nachuan/runtime-secrets/v1\0"
_MAX_DOCUMENT_BYTES = 4 * 1024 * 1024
_ACL_RECHECK_SECONDS = 300.0
_ACL_CACHE: dict[
    tuple[str, bool], tuple[float, tuple[int, int, int]]
] = {}
_ACL_CACHE_LOCK = threading.Lock()

_TOKEN_QUERY = 0x0008
_TOKEN_USER_CLASS = 1
_ERROR_INSUFFICIENT_BUFFER = 122
_SE_FILE_OBJECT = 1
_OWNER_SECURITY_INFORMATION = 0x00000001
_DACL_SECURITY_INFORMATION = 0x00000004
_PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
_SE_DACL_PROTECTED = 0x1000
_ACCESS_ALLOWED_ACE_TYPE = 0x00
_OBJECT_INHERIT_ACE = 0x01
_CONTAINER_INHERIT_ACE = 0x02
_FILE_ALL_ACCESS = 0x001F01FF
_SYSTEM_SID = "S-1-5-18"


class SecureStorageError(RuntimeError):
    """安全存储不可用、密文损坏或不属于当前 Windows 用户。"""


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


class _SidAndAttributes(ctypes.Structure):
    _fields_ = [("Sid", wintypes.LPVOID), ("Attributes", wintypes.DWORD)]


class _TokenUser(ctypes.Structure):
    _fields_ = [("User", _SidAndAttributes)]


class _Acl(ctypes.Structure):
    _fields_ = [
        ("AclRevision", ctypes.c_ubyte),
        ("Sbz1", ctypes.c_ubyte),
        ("AclSize", wintypes.WORD),
        ("AceCount", wintypes.WORD),
        ("Sbz2", wintypes.WORD),
    ]


class _AceHeader(ctypes.Structure):
    _fields_ = [
        ("AceType", ctypes.c_ubyte),
        ("AceFlags", ctypes.c_ubyte),
        ("AceSize", wintypes.WORD),
    ]


class _AccessAllowedAce(ctypes.Structure):
    _fields_ = [
        ("Header", _AceHeader),
        ("Mask", wintypes.DWORD),
        ("SidStart", wintypes.DWORD),
    ]


def _require_windows() -> None:
    if os.name != "nt":
        raise SecureStorageError("运行态密钥存储需要 Windows DPAPI；拒绝回退为明文")


@lru_cache(maxsize=8)
def _trusted_system_executable(name: str) -> Path:
    """只解析 Windows 自带的 System32 程序，永不经由 PATH/PATHEXT。"""
    _require_windows()
    if not name or Path(name).name != name or not name.lower().endswith(".exe"):
        raise SecureStorageError("Windows 系统程序名称无效")

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetSystemDirectoryW.argtypes = [wintypes.LPWSTR, wintypes.UINT]
    kernel32.GetSystemDirectoryW.restype = wintypes.UINT
    buffer = ctypes.create_unicode_buffer(32768)
    length = kernel32.GetSystemDirectoryW(buffer, len(buffer))
    if not length or length >= len(buffer):
        raise SecureStorageError("无法定位可信 Windows 系统目录") from ctypes.WinError(
            ctypes.get_last_error()
        )

    executable = Path(buffer.value) / name
    try:
        stat = executable.lstat()
    except OSError as exc:
        raise SecureStorageError(f"Windows 系统程序不存在：{name}") from exc
    reparse_flag = getattr(stat, "st_file_attributes", 0) & 0x400
    if not executable.is_absolute() or not executable.is_file() or executable.is_symlink() or reparse_flag:
        raise SecureStorageError(f"Windows 系统程序不可信：{name}")
    return executable


def _blob(data: bytes) -> tuple[_DataBlob, ctypes.Array]:
    buf = ctypes.create_string_buffer(data)
    return (
        _DataBlob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_byte))),
        buf,
    )


def _crypt_protect(data: bytes, *, purpose: str) -> bytes:
    _require_windows()
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.LocalFree.argtypes = [wintypes.LPVOID]
    kernel32.LocalFree.restype = wintypes.LPVOID
    crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(_DataBlob),
        wintypes.LPCWSTR,
        ctypes.POINTER(_DataBlob),
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(_DataBlob),
    ]
    crypt32.CryptProtectData.restype = wintypes.BOOL
    source, source_buf = _blob(data)
    entropy, entropy_buf = _blob(_DPAPI_DOMAIN + purpose.encode("utf-8"))
    output = _DataBlob()
    # CRYPTPROTECT_UI_FORBIDDEN：后台服务永不弹交互框；失败就关闭。
    if not crypt32.CryptProtectData(
        ctypes.byref(source),
        "纳川运行态密钥",
        ctypes.byref(entropy),
        None,
        None,
        0x1,
        ctypes.byref(output),
    ):
        raise SecureStorageError("Windows DPAPI 加密失败") from ctypes.WinError(
            ctypes.get_last_error()
        )
    # 保持输入缓冲区存活到 API 返回。
    del source_buf, entropy_buf
    try:
        return ctypes.string_at(output.pbData, output.cbData)
    finally:
        kernel32.LocalFree(ctypes.cast(output.pbData, wintypes.LPVOID))


def _crypt_unprotect(data: bytes, *, purpose: str) -> bytes:
    _require_windows()
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.LocalFree.argtypes = [wintypes.LPVOID]
    kernel32.LocalFree.restype = wintypes.LPVOID
    crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(_DataBlob),
        ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(_DataBlob),
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(_DataBlob),
    ]
    crypt32.CryptUnprotectData.restype = wintypes.BOOL
    source, source_buf = _blob(data)
    entropy, entropy_buf = _blob(_DPAPI_DOMAIN + purpose.encode("utf-8"))
    output = _DataBlob()
    description = wintypes.LPWSTR()
    if not crypt32.CryptUnprotectData(
        ctypes.byref(source),
        ctypes.byref(description),
        ctypes.byref(entropy),
        None,
        None,
        0x1,
        ctypes.byref(output),
    ):
        raise SecureStorageError(
            "DPAPI 密文无法由当前 Windows 用户解密；请用原账号启动或重新配置"
        ) from ctypes.WinError(ctypes.get_last_error())
    del source_buf, entropy_buf
    try:
        return ctypes.string_at(output.pbData, output.cbData)
    finally:
        if description:
            kernel32.LocalFree(ctypes.cast(description, wintypes.LPVOID))
        kernel32.LocalFree(ctypes.cast(output.pbData, wintypes.LPVOID))


@lru_cache(maxsize=1)
def _windows_security_api() -> tuple[Any, Any]:
    """Load and type the small native security API surface once per process."""

    _require_windows()
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [wintypes.LPVOID]
    kernel32.LocalFree.restype = wintypes.LPVOID

    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.LPWSTR),
    ]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    advapi32.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
    ]
    advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.GetSecurityInfo.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
    ]
    advapi32.GetSecurityInfo.restype = wintypes.DWORD
    advapi32.SetSecurityInfo.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.LPVOID,
    ]
    advapi32.SetSecurityInfo.restype = wintypes.DWORD
    advapi32.GetSecurityDescriptorOwner.argtypes = [
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.BOOL),
    ]
    advapi32.GetSecurityDescriptorOwner.restype = wintypes.BOOL
    advapi32.GetSecurityDescriptorDacl.argtypes = [
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.BOOL),
    ]
    advapi32.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    advapi32.GetSecurityDescriptorControl.argtypes = [
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.WORD),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetSecurityDescriptorControl.restype = wintypes.BOOL
    advapi32.IsValidSid.argtypes = [wintypes.LPVOID]
    advapi32.IsValidSid.restype = wintypes.BOOL
    advapi32.GetLengthSid.argtypes = [wintypes.LPVOID]
    advapi32.GetLengthSid.restype = wintypes.DWORD
    advapi32.IsValidAcl.argtypes = [wintypes.LPVOID]
    advapi32.IsValidAcl.restype = wintypes.BOOL
    advapi32.GetAce.argtypes = [
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
    ]
    advapi32.GetAce.restype = wintypes.BOOL
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    advapi32.SetFileSecurityW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.LPVOID,
    ]
    advapi32.SetFileSecurityW.restype = wintypes.BOOL
    return advapi32, kernel32


def _sid_to_string(sid_pointer: wintypes.LPVOID) -> str:
    advapi32, kernel32 = _windows_security_api()
    if not sid_pointer or not advapi32.IsValidSid(sid_pointer):
        raise SecureStorageError("运行态路径含无效 Windows SID")
    rendered = wintypes.LPWSTR()
    if not advapi32.ConvertSidToStringSidW(sid_pointer, ctypes.byref(rendered)):
        raise SecureStorageError("无法解析运行态路径 Windows SID") from ctypes.WinError(
            ctypes.get_last_error()
        )
    try:
        value = str(rendered.value or "").upper()
        if not value.startswith("S-1-"):
            raise SecureStorageError("运行态路径含无效 Windows SID")
        return value
    finally:
        kernel32.LocalFree(ctypes.cast(rendered, wintypes.LPVOID))


@lru_cache(maxsize=1)
def _current_user_sid() -> str:
    """Read the process token SID without PATH, a child process, or localization."""

    _require_windows()
    advapi32, kernel32 = _windows_security_api()
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)
    ):
        raise SecureStorageError(
            "无法取得当前 Windows 用户令牌，拒绝创建弱 ACL 密钥文件"
        ) from ctypes.WinError(ctypes.get_last_error())
    try:
        required = wintypes.DWORD()
        ctypes.set_last_error(0)
        first = advapi32.GetTokenInformation(
            token, _TOKEN_USER_CLASS, None, 0, ctypes.byref(required)
        )
        error = ctypes.get_last_error()
        if (
            first
            or error != _ERROR_INSUFFICIENT_BUFFER
            or required.value < ctypes.sizeof(_TokenUser)
            or required.value > 65536
        ):
            raise SecureStorageError(
                "无法取得当前 Windows 用户 SID，拒绝创建弱 ACL 密钥文件"
            ) from ctypes.WinError(error)
        buffer = ctypes.create_string_buffer(required.value)
        if not advapi32.GetTokenInformation(
            token,
            _TOKEN_USER_CLASS,
            ctypes.cast(buffer, wintypes.LPVOID),
            required.value,
            ctypes.byref(required),
        ):
            raise SecureStorageError(
                "无法取得当前 Windows 用户 SID，拒绝创建弱 ACL 密钥文件"
            ) from ctypes.WinError(ctypes.get_last_error())
        token_user = ctypes.cast(buffer, ctypes.POINTER(_TokenUser)).contents
        return _sid_to_string(token_user.User.Sid)
    finally:
        if token:
            kernel32.CloseHandle(token)


def _path_security_identity(
    path: Path, *, expected_directory: bool | None = None
) -> tuple[bool, tuple[int, int, int]]:
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise SecureStorageError("待验证的运行态路径不存在") from exc
    reparse_flag = int(getattr(metadata, "st_file_attributes", 0)) & 0x400
    if stat.S_ISLNK(metadata.st_mode) or reparse_flag:
        raise SecureStorageError("拒绝验证 reparse 运行态路径")
    directory = stat.S_ISDIR(metadata.st_mode)
    if not directory and not stat.S_ISREG(metadata.st_mode):
        raise SecureStorageError("运行态路径不是普通文件或目录")
    if expected_directory is not None and directory != expected_directory:
        raise SecureStorageError("运行态路径类型与 ACL 策略不一致")
    identity = (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(stat.S_IFMT(metadata.st_mode)),
    )
    return directory, identity


def _read_windows_security_state(
    path: Path,
) -> tuple[str, int, tuple[tuple[int, int, int, str], ...]]:
    """Return owner SID, descriptor control and explicit ACEs via Win32 APIs."""

    advapi32, kernel32 = _windows_security_api()
    owner = wintypes.LPVOID()
    dacl = wintypes.LPVOID()
    descriptor = wintypes.LPVOID()
    result = int(
        advapi32.GetNamedSecurityInfoW(
            str(path),
            _SE_FILE_OBJECT,
            _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
            ctypes.byref(owner),
            None,
            ctypes.byref(dacl),
            None,
            ctypes.byref(descriptor),
        )
    )
    if result != 0 or not descriptor:
        raise SecureStorageError("无法原生读取运行态路径 ACL") from ctypes.WinError(
            result or ctypes.get_last_error()
        )
    try:
        owner_sid = _sid_to_string(owner)
        control = wintypes.WORD()
        revision = wintypes.DWORD()
        if not advapi32.GetSecurityDescriptorControl(
            descriptor, ctypes.byref(control), ctypes.byref(revision)
        ):
            raise SecureStorageError("无法读取运行态路径 ACL 控制位") from ctypes.WinError(
                ctypes.get_last_error()
            )
        if not dacl:
            raise SecureStorageError("运行态密钥 ACL 缺少 DACL")
        if not advapi32.IsValidAcl(dacl):
            raise SecureStorageError("运行态密钥 ACL 无效")
        acl = ctypes.cast(dacl, ctypes.POINTER(_Acl)).contents
        if int(acl.AceCount) > 64:
            raise SecureStorageError("运行态密钥 ACL 含额外主体")
        entries: list[tuple[int, int, int, str]] = []
        sid_offset = int(_AccessAllowedAce.SidStart.offset)
        for index in range(int(acl.AceCount)):
            ace_pointer = wintypes.LPVOID()
            if not advapi32.GetAce(dacl, index, ctypes.byref(ace_pointer)):
                raise SecureStorageError("无法读取运行态密钥 ACL ACE") from ctypes.WinError(
                    ctypes.get_last_error()
                )
            if not ace_pointer:
                raise SecureStorageError("运行态密钥 ACL ACE 无效")
            header = ctypes.cast(ace_pointer, ctypes.POINTER(_AceHeader)).contents
            if (
                int(header.AceType) != _ACCESS_ALLOWED_ACE_TYPE
                or int(header.AceSize) < ctypes.sizeof(_AccessAllowedAce)
            ):
                raise SecureStorageError("运行态密钥 ACL 含非允许型 ACE")
            allowed = ctypes.cast(
                ace_pointer, ctypes.POINTER(_AccessAllowedAce)
            ).contents
            sid_pointer = wintypes.LPVOID(int(ace_pointer.value) + sid_offset)
            sid_length = int(advapi32.GetLengthSid(sid_pointer))
            if (
                sid_length <= 0
                or sid_offset + sid_length > int(header.AceSize)
            ):
                raise SecureStorageError("运行态密钥 ACL ACE SID 越界")
            entries.append(
                (
                    int(header.AceType),
                    int(header.AceFlags),
                    int(allowed.Mask),
                    _sid_to_string(sid_pointer),
                )
            )
        return owner_sid, int(control.value), tuple(entries)
    finally:
        kernel32.LocalFree(descriptor)


def _read_windows_handle_security_state(
    native_handle: int,
) -> tuple[str, int, tuple[tuple[int, int, int, str], ...]]:
    """Read security from the already-open object without resolving its path."""

    advapi32, kernel32 = _windows_security_api()
    owner = wintypes.LPVOID()
    dacl = wintypes.LPVOID()
    descriptor = wintypes.LPVOID()
    result = int(
        advapi32.GetSecurityInfo(
            wintypes.HANDLE(native_handle),
            _SE_FILE_OBJECT,
            _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
            ctypes.byref(owner),
            None,
            ctypes.byref(dacl),
            None,
            ctypes.byref(descriptor),
        )
    )
    if result != 0 or not descriptor:
        raise SecureStorageError(
            "cannot read Windows ACL from the already-open handle"
        ) from ctypes.WinError(result or ctypes.get_last_error())
    try:
        owner_sid = _sid_to_string(owner)
        control = wintypes.WORD()
        revision = wintypes.DWORD()
        if not advapi32.GetSecurityDescriptorControl(
            descriptor, ctypes.byref(control), ctypes.byref(revision)
        ):
            raise SecureStorageError(
                "cannot read Windows ACL control from the already-open handle"
            ) from ctypes.WinError(ctypes.get_last_error())
        if not dacl:
            raise SecureStorageError("already-open Windows handle has no DACL")
        if not advapi32.IsValidAcl(dacl):
            raise SecureStorageError("already-open Windows handle has an invalid DACL")
        acl = ctypes.cast(dacl, ctypes.POINTER(_Acl)).contents
        if int(acl.AceCount) > 64:
            raise SecureStorageError("already-open Windows handle has excess trustees")
        entries: list[tuple[int, int, int, str]] = []
        sid_offset = int(_AccessAllowedAce.SidStart.offset)
        for index in range(int(acl.AceCount)):
            ace_pointer = wintypes.LPVOID()
            if not advapi32.GetAce(dacl, index, ctypes.byref(ace_pointer)):
                raise SecureStorageError(
                    "cannot read an ACE from the already-open Windows handle"
                ) from ctypes.WinError(ctypes.get_last_error())
            if not ace_pointer:
                raise SecureStorageError("already-open Windows handle has an invalid ACE")
            header = ctypes.cast(ace_pointer, ctypes.POINTER(_AceHeader)).contents
            if (
                int(header.AceType) != _ACCESS_ALLOWED_ACE_TYPE
                or int(header.AceSize) < ctypes.sizeof(_AccessAllowedAce)
            ):
                raise SecureStorageError(
                    "already-open Windows handle has a non-allow ACE"
                )
            allowed = ctypes.cast(
                ace_pointer, ctypes.POINTER(_AccessAllowedAce)
            ).contents
            sid_pointer = wintypes.LPVOID(int(ace_pointer.value) + sid_offset)
            sid_length = int(advapi32.GetLengthSid(sid_pointer))
            if sid_length <= 0 or sid_offset + sid_length > int(header.AceSize):
                raise SecureStorageError(
                    "already-open Windows handle has an out-of-bounds ACE SID"
                )
            entries.append(
                (
                    int(header.AceType),
                    int(header.AceFlags),
                    int(allowed.Mask),
                    _sid_to_string(sid_pointer),
                )
            )
        return owner_sid, int(control.value), tuple(entries)
    finally:
        kernel32.LocalFree(descriptor)


def _native_handle_from_descriptor(
    descriptor: int, *, directory: bool
) -> tuple[int, bool]:
    _require_windows()
    if not isinstance(descriptor, int) or isinstance(descriptor, bool) or descriptor < 0:
        raise SecureStorageError("Windows file descriptor is invalid")
    try:
        metadata = os.fstat(descriptor)
    except OSError as exc:
        raise SecureStorageError("Windows file descriptor is unavailable") from exc
    reparse_flag = int(getattr(metadata, "st_file_attributes", 0)) & 0x400
    actual_directory = stat.S_ISDIR(metadata.st_mode)
    if reparse_flag or (not actual_directory and not stat.S_ISREG(metadata.st_mode)):
        raise SecureStorageError("Windows file descriptor is not a plain file object")
    if actual_directory != directory:
        raise SecureStorageError("Windows handle type does not match ACL policy")
    import msvcrt

    try:
        native_handle = int(msvcrt.get_osfhandle(descriptor))
    except OSError as exc:
        raise SecureStorageError("cannot resolve native Windows handle") from exc
    if native_handle in {-1, int(ctypes.c_void_p(-1).value or -1)}:
        raise SecureStorageError("native Windows handle is invalid")
    return native_handle, actual_directory


def _verify_restricted_acl(
    path: Path, *, current_sid: str, directory: bool | None = None
) -> None:
    actual_directory, before_identity = _path_security_identity(
        path, expected_directory=directory
    )
    owner_sid, control, entries = _read_windows_security_state(path)
    _, after_identity = _path_security_identity(
        path, expected_directory=actual_directory
    )
    if before_identity != after_identity:
        raise SecureStorageError("运行态路径在 ACL 验证期间被替换")
    current_sid = current_sid.upper()
    if owner_sid not in {current_sid, _SYSTEM_SID}:
        raise SecureStorageError("运行态路径 owner 不是当前用户或 SYSTEM")
    if not control & _SE_DACL_PROTECTED:
        raise SecureStorageError("运行态密钥 ACL 仍允许继承")
    if len(entries) != 2:
        raise SecureStorageError("运行态密钥 ACL 含额外主体")
    trustees = {entry[3] for entry in entries}
    if _SYSTEM_SID not in trustees:
        raise SecureStorageError("运行态密钥 ACL 缺少 SYSTEM")
    if current_sid not in trustees:
        raise SecureStorageError("运行态密钥 ACL 缺少当前用户")
    expected_flags = (
        _OBJECT_INHERIT_ACE | _CONTAINER_INHERIT_ACE
        if actual_directory
        else 0
    )
    for ace_type, ace_flags, mask, _trustee in entries:
        if ace_type != _ACCESS_ALLOWED_ACE_TYPE:
            raise SecureStorageError("运行态密钥 ACL 含非允许型 ACE")
        if mask != _FILE_ALL_ACCESS:
            raise SecureStorageError("运行态密钥 ACL ACE 不是完全控制")
        if ace_flags != expected_flags:
            raise SecureStorageError("运行态密钥 ACL ACE 继承标志不精确")


def _verify_restricted_handle_acl(
    descriptor: int, *, current_sid: str, directory: bool
) -> None:
    native_handle, actual_directory = _native_handle_from_descriptor(
        descriptor, directory=directory
    )
    owner_sid, control, entries = _read_windows_handle_security_state(native_handle)
    current_sid = current_sid.upper()
    if owner_sid not in {current_sid, _SYSTEM_SID}:
        raise SecureStorageError(
            "already-open Windows handle owner is not current user or SYSTEM"
        )
    if not control & _SE_DACL_PROTECTED:
        raise SecureStorageError("already-open Windows handle DACL is inherited")
    if len(entries) != 2:
        raise SecureStorageError("already-open Windows handle has excess trustees")
    trustees = {entry[3] for entry in entries}
    if trustees != {current_sid, _SYSTEM_SID}:
        raise SecureStorageError(
            "already-open Windows handle trustees are not exactly current user and SYSTEM"
        )
    expected_flags = (
        _OBJECT_INHERIT_ACE | _CONTAINER_INHERIT_ACE
        if actual_directory
        else 0
    )
    for ace_type, ace_flags, mask, _trustee in entries:
        if ace_type != _ACCESS_ALLOWED_ACE_TYPE:
            raise SecureStorageError("already-open Windows handle has a non-allow ACE")
        if mask != _FILE_ALL_ACCESS:
            raise SecureStorageError(
                "already-open Windows handle ACE is not Full Access"
            )
        if ace_flags != expected_flags:
            raise SecureStorageError(
                "already-open Windows handle ACE inheritance flags are not exact"
            )


def _set_exact_acl(path: Path, *, directory: bool, current_sid: str) -> None:
    """Atomically set owner and an exact protected DACL for the target."""

    advapi32, kernel32 = _windows_security_api()

    flags = "OICI" if directory else ""
    sddl = (
        f"O:{current_sid}D:P"
        f"(A;{flags};FA;;;SY)(A;{flags};FA;;;{current_sid})"
    )
    descriptor = wintypes.LPVOID()
    size = wintypes.DWORD()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, 1, ctypes.byref(descriptor), ctypes.byref(size)
    ):
        raise SecureStorageError("无法构建运行态密钥 ACL") from ctypes.WinError(
            ctypes.get_last_error()
        )
    try:
        security_information = (
            _OWNER_SECURITY_INFORMATION
            | _DACL_SECURITY_INFORMATION
            | _PROTECTED_DACL_SECURITY_INFORMATION
        )
        if not advapi32.SetFileSecurityW(
            str(path), security_information, descriptor
        ):
            raise SecureStorageError("无法收紧运行态密钥 ACL；拒绝继续读写") from ctypes.WinError(
                ctypes.get_last_error()
            )
    finally:
        kernel32.LocalFree(descriptor)


def _set_exact_handle_acl(
    descriptor: int, *, directory: bool, current_sid: str
) -> None:
    """Set owner and protected DACL through the caller's already-open handle."""

    native_handle, _actual_directory = _native_handle_from_descriptor(
        descriptor, directory=directory
    )
    advapi32, kernel32 = _windows_security_api()
    flags = "OICI" if directory else ""
    sddl = (
        f"O:{current_sid}D:P"
        f"(A;{flags};FA;;;SY)(A;{flags};FA;;;{current_sid})"
    )
    descriptor_pointer = wintypes.LPVOID()
    size = wintypes.DWORD()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, 1, ctypes.byref(descriptor_pointer), ctypes.byref(size)
    ):
        raise SecureStorageError(
            "cannot build exact ACL for the already-open Windows handle"
        ) from ctypes.WinError(ctypes.get_last_error())
    try:
        owner = wintypes.LPVOID()
        owner_defaulted = wintypes.BOOL()
        if not advapi32.GetSecurityDescriptorOwner(
            descriptor_pointer, ctypes.byref(owner), ctypes.byref(owner_defaulted)
        ) or not owner:
            raise SecureStorageError(
                "cannot resolve owner for the already-open Windows handle"
            ) from ctypes.WinError(ctypes.get_last_error())
        dacl_present = wintypes.BOOL()
        dacl = wintypes.LPVOID()
        dacl_defaulted = wintypes.BOOL()
        if (
            not advapi32.GetSecurityDescriptorDacl(
                descriptor_pointer,
                ctypes.byref(dacl_present),
                ctypes.byref(dacl),
                ctypes.byref(dacl_defaulted),
            )
            or not dacl_present
            or not dacl
        ):
            raise SecureStorageError(
                "cannot resolve DACL for the already-open Windows handle"
            ) from ctypes.WinError(ctypes.get_last_error())
        security_information = (
            _OWNER_SECURITY_INFORMATION
            | _DACL_SECURITY_INFORMATION
            | _PROTECTED_DACL_SECURITY_INFORMATION
        )
        result = int(
            advapi32.SetSecurityInfo(
                wintypes.HANDLE(native_handle),
                _SE_FILE_OBJECT,
                security_information,
                owner,
                None,
                dacl,
                None,
            )
        )
        if result != 0:
            raise SecureStorageError(
                "cannot restrict ACL through the already-open Windows handle"
            ) from ctypes.WinError(result)
    finally:
        kernel32.LocalFree(descriptor_pointer)


def _harden_acl(path: Path, *, directory: bool, force: bool = False) -> None:
    _require_windows()
    actual_directory, before_identity = _path_security_identity(
        path, expected_directory=directory
    )
    del actual_directory
    cache_key = (
        os.path.normcase(os.path.abspath(os.fspath(path))),
        directory,
    )
    now = time.monotonic()
    with _ACL_CACHE_LOCK:
        cached = _ACL_CACHE.get(cache_key)
        if (
            not force
            and cached is not None
            and cached[1] == before_identity
            and now - cached[0] < _ACL_RECHECK_SECONDS
        ):
            return
    sid = _current_user_sid()
    _set_exact_acl(path, directory=directory, current_sid=sid)
    _, after_identity = _path_security_identity(
        path, expected_directory=directory
    )
    if before_identity != after_identity:
        raise SecureStorageError("运行态路径在 ACL 收紧期间被替换")
    _verify_restricted_acl(path, current_sid=sid, directory=directory)
    with _ACL_CACHE_LOCK:
        _ACL_CACHE[cache_key] = (time.monotonic(), after_identity)


def assert_restricted_windows_handle_acl(
    descriptor: int, *, directory: bool
) -> None:
    """Verify an exact ACL on the already-open CRT file descriptor."""

    _require_windows()
    _verify_restricted_handle_acl(
        descriptor, current_sid=_current_user_sid(), directory=directory
    )


def harden_restricted_windows_handle_acl(
    descriptor: int, *, directory: bool
) -> None:
    """Set then verify an exact ACL without reopening or resolving a path."""

    _require_windows()
    current_sid = _current_user_sid()
    _set_exact_handle_acl(
        descriptor, directory=directory, current_sid=current_sid
    )
    _verify_restricted_handle_acl(
        descriptor, directory=directory, current_sid=current_sid
    )


def assert_restricted_windows_acl(path: str | Path) -> None:
    """Assert exact owner, protected DACL, ACE type/mask/flags and trustees."""
    _require_windows()
    _verify_restricted_acl(Path(path), current_sid=_current_user_sid())


def trusted_windows_system_executable(name: str) -> Path:
    """Public read-only resolver for a non-reparse executable in System32."""

    return _trusted_system_executable(name)


def harden_restricted_windows_acl(
    path: str | Path,
    *,
    directory: bool,
) -> None:
    """Fail closed after replacing inheritance with current-user + SYSTEM ACLs."""

    _require_windows()
    target = Path(path)
    try:
        metadata = target.lstat()
    except OSError as exc:
        raise SecureStorageError("待保护的运行态路径不存在") from exc
    reparse_flag = getattr(metadata, "st_file_attributes", 0) & 0x400
    if target.is_symlink() or reparse_flag:
        raise SecureStorageError("拒绝保护 reparse 运行态路径")
    if directory != target.is_dir():
        raise SecureStorageError("运行态路径类型与 ACL 策略不一致")
    _harden_acl(target, directory=directory, force=True)


def _prepare_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _harden_acl(path.parent, directory=True)


def _write_protected_json(
    path: str | Path,
    payload: Mapping[str, Any],
    *,
    purpose: str,
    replace_existing: bool,
) -> bool:
    target = Path(path)
    _prepare_parent(target)
    plaintext = json.dumps(dict(payload), ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )
    if len(plaintext) > _MAX_DOCUMENT_BYTES:
        raise SecureStorageError("运行态密钥数据超过安全大小上限")
    ciphertext = _crypt_protect(plaintext, purpose=purpose)
    envelope = {
        "schema": _SCHEMA,
        "protection": _PROTECTION,
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }
    tmp_name = ""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix=f".{target.name}.",
            suffix=".tmp",
            dir=target.parent,
            delete=False,
        ) as handle:
            tmp_name = handle.name
            json.dump(envelope, handle, ensure_ascii=True, separators=(",", ":"))
            handle.flush()
            os.fsync(handle.fileno())
        _harden_acl(Path(tmp_name), directory=False, force=True)
        if replace_existing:
            os.replace(tmp_name, target)
        else:
            try:
                # Same-directory hard-link creation is an atomic
                # create-if-absent primitive on the Windows/NTFS runtime.
                os.link(tmp_name, target)
            except FileExistsError:
                return False
            except OSError as exc:
                raise SecureStorageError(
                    "无法原子创建运行态密钥文件；拒绝覆盖既有配置"
                ) from exc
            Path(tmp_name).unlink()
        tmp_name = ""
        _harden_acl(target, directory=False, force=True)
        return True
    finally:
        if tmp_name:
            try:
                Path(tmp_name).unlink(missing_ok=True)
            except OSError:
                pass


def write_protected_json(
    path: str | Path, payload: Mapping[str, Any], *, purpose: str
) -> None:
    """把 JSON 对象加密后原子写盘；不提供任何明文回退。"""

    _write_protected_json(
        path,
        payload,
        purpose=purpose,
        replace_existing=True,
    )


def write_protected_json_if_absent(
    path: str | Path, payload: Mapping[str, Any], *, purpose: str
) -> bool:
    """Atomically create one DPAPI document without replacing an existing one."""

    return _write_protected_json(
        path,
        payload,
        purpose=purpose,
        replace_existing=False,
    )


def read_protected_json(
    path: str | Path,
    *,
    purpose: str,
    migrate_plaintext: bool = False,
    plaintext_migrator: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """读取 DPAPI JSON；可把旧版明文对象一次性迁移为密文。"""
    target = Path(path)
    if not target.exists():
        raise FileNotFoundError(target)
    try:
        if target.stat().st_size > _MAX_DOCUMENT_BYTES:
            raise SecureStorageError("运行态密钥文件超过安全大小上限")
    except OSError as exc:
        raise SecureStorageError("无法读取运行态密钥文件元数据") from exc
    _prepare_parent(target)
    # Reads are security-boundary operations.  Do not trust the short write
    # optimization cache: a DACL can be widened after the previous check.
    _harden_acl(target, directory=False, force=True)
    try:
        document = json.loads(target.read_text("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SecureStorageError("运行态密钥文件损坏，拒绝按空配置继续") from exc
    if not isinstance(document, dict):
        raise SecureStorageError("运行态密钥文件格式非法")

    if document.get("schema") == _SCHEMA:
        if document.get("protection") != _PROTECTION:
            raise SecureStorageError("运行态密钥保护方式不受支持")
        try:
            ciphertext = base64.b64decode(document["ciphertext"], validate=True)
            if len(ciphertext) > _MAX_DOCUMENT_BYTES:
                raise SecureStorageError("运行态密钥密文超过安全大小上限")
            plaintext = _crypt_unprotect(ciphertext, purpose=purpose)
            if len(plaintext) > _MAX_DOCUMENT_BYTES:
                raise SecureStorageError("解密后的运行态密钥超过安全大小上限")
            decoded = json.loads(plaintext.decode("utf-8"))
        except SecureStorageError:
            raise
        except (KeyError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
            raise SecureStorageError("运行态密钥密文信封损坏") from exc
        if not isinstance(decoded, dict):
            raise SecureStorageError("解密后的运行态配置不是 JSON 对象")
        return decoded

    # 含保护字段但 schema 不匹配不是旧明文，避免把损坏/未来版本误当明文重写。
    if "schema" in document or "protection" in document or "ciphertext" in document:
        raise SecureStorageError("未知的运行态密钥信封版本")
    if not migrate_plaintext:
        raise SecureStorageError("检测到旧版明文运行态密钥；必须显式迁移")
    migrated = dict(document)
    if plaintext_migrator is not None:
        try:
            migrated = plaintext_migrator(dict(document))
        except Exception as exc:  # noqa: BLE001 - any migration ambiguity fails closed
            raise SecureStorageError("旧版明文密钥迁移失败") from exc
        if not isinstance(migrated, dict):
            raise SecureStorageError("旧版明文密钥迁移结果无效")
    write_protected_json(target, migrated, purpose=purpose)
    return migrated
