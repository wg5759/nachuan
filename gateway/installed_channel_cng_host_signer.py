"""Non-exportable per-installation ECDSA signer backed by Windows CNG."""

from __future__ import annotations

import ctypes
import hashlib
import os
import re
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature,
)

from gateway.installation_root import InstallationRootSnapshot


_ALGORITHM = "ecdsa-p256-sha256"
_CNG_ALGORITHM = "ECDSA_P256"
_PUBLIC_BLOB = "ECCPUBLICBLOB"
_PRIVATE_BLOB = "PKCS8_PRIVATEKEY"
_SOFTWARE_PROVIDER = "Microsoft Software Key Storage Provider"
_PLATFORM_PROVIDER = "Microsoft Platform Crypto Provider"
_MACHINE_KEY_FLAG = 0x00000020
_SILENT_FLAG = 0x00000040
_PERSIST_FLAG = 0x80000000
_ALLOW_SIGNING_FLAG = 0x00000002
_ECDSA_PUBLIC_P256_MAGIC = 0x31534345
_NTE_EXISTS = 0x8009000F
_NTE_BAD_KEYSET = 0x80090016
_NTE_NOT_FOUND = 0x80090011
_KEY_PREFIX = re.compile(r"^[A-Za-z0-9._-]{1,80}$")
_SECURITY_DESCRIPTOR_PROPERTY = "Security Descr"
_OWNER_SECURITY_INFORMATION = 0x00000001
_DACL_SECURITY_INFORMATION = 0x00000004
_KEY_SECURITY_FLAGS = _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION
_KEY_ADMIN_SDDL = (
    "O:BAD:P(A;;0xd01f01ff;;;SY)(A;;0xd01f01ff;;;BA)"
)


class InstalledChannelCngHostSignerError(RuntimeError):
    pass


if os.name == "nt":
    _ncrypt = ctypes.WinDLL("ncrypt.dll", use_last_error=True)
    _ncrypt.NCryptOpenStorageProvider.argtypes = (
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_wchar_p,
        ctypes.c_ulong,
    )
    _ncrypt.NCryptOpenStorageProvider.restype = ctypes.c_long
    _ncrypt.NCryptOpenKey.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_wchar_p,
        ctypes.c_ulong,
        ctypes.c_ulong,
    )
    _ncrypt.NCryptOpenKey.restype = ctypes.c_long
    _ncrypt.NCryptCreatePersistedKey.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_ulong,
        ctypes.c_ulong,
    )
    _ncrypt.NCryptCreatePersistedKey.restype = ctypes.c_long
    _ncrypt.NCryptSetProperty.argtypes = (
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.c_ulong,
    )
    _ncrypt.NCryptSetProperty.restype = ctypes.c_long
    _ncrypt.NCryptGetProperty.argtypes = (
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_ulong),
        ctypes.c_ulong,
    )
    _ncrypt.NCryptGetProperty.restype = ctypes.c_long
    _ncrypt.NCryptFinalizeKey.argtypes = (ctypes.c_void_p, ctypes.c_ulong)
    _ncrypt.NCryptFinalizeKey.restype = ctypes.c_long
    _ncrypt.NCryptExportKey.argtypes = (
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_ulong),
        ctypes.c_ulong,
    )
    _ncrypt.NCryptExportKey.restype = ctypes.c_long
    _ncrypt.NCryptSignHash.argtypes = (
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_ulong),
        ctypes.c_ulong,
    )
    _ncrypt.NCryptSignHash.restype = ctypes.c_long
    _ncrypt.NCryptDeleteKey.argtypes = (ctypes.c_void_p, ctypes.c_ulong)
    _ncrypt.NCryptDeleteKey.restype = ctypes.c_long
    _ncrypt.NCryptFreeObject.argtypes = (ctypes.c_void_p,)
    _ncrypt.NCryptFreeObject.restype = ctypes.c_long
    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = (
        ctypes.c_wchar_p,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_ulong),
    )
    _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = (
        ctypes.c_int
    )
    _advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = (
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_wchar_p),
        ctypes.POINTER(ctypes.c_ulong),
    )
    _advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = (
        ctypes.c_int
    )
    _kernel32.LocalFree.argtypes = (ctypes.c_void_p,)
    _kernel32.LocalFree.restype = ctypes.c_void_p


def _code(status: int) -> int:
    return int(status) & 0xFFFFFFFF


def _check(status: int, message: str) -> None:
    if _code(status) != 0:
        raise InstalledChannelCngHostSignerError(message)


def _flags(machine_scope: bool) -> int:
    return _SILENT_FLAG | (_MACHINE_KEY_FLAG if machine_scope else 0)


def _free(handle: ctypes.c_void_p | None) -> None:
    if os.name == "nt" and handle and handle.value:
        _ncrypt.NCryptFreeObject(handle)
        handle.value = None


def _set_dword(handle: ctypes.c_void_p, name: str, value: int) -> None:
    data = ctypes.c_ulong(value)
    _check(
        _ncrypt.NCryptSetProperty(
            handle,
            name,
            ctypes.byref(data),
            ctypes.sizeof(data),
            _PERSIST_FLAG | _SILENT_FLAG,
        ),
        "CNG host signer policy could not be persisted",
    )


def _get_dword(handle: ctypes.c_void_p, name: str) -> int:
    data = ctypes.c_ulong()
    size = ctypes.c_ulong()
    _check(
        _ncrypt.NCryptGetProperty(
            handle,
            name,
            ctypes.byref(data),
            ctypes.sizeof(data),
            ctypes.byref(size),
            _SILENT_FLAG,
        ),
        "CNG host signer policy is unavailable",
    )
    if int(size.value) != ctypes.sizeof(data):
        raise InstalledChannelCngHostSignerError(
            "CNG host signer policy has an invalid size"
        )
    return int(data.value)


def _get_text(handle: ctypes.c_void_p, name: str) -> str:
    size = ctypes.c_ulong()
    _check(
        _ncrypt.NCryptGetProperty(
            handle,
            name,
            None,
            0,
            ctypes.byref(size),
            _SILENT_FLAG,
        ),
        "CNG host signer identity is unavailable",
    )
    if not 2 <= int(size.value) <= 1024 or int(size.value) % 2:
        raise InstalledChannelCngHostSignerError(
            "CNG host signer identity has an invalid size"
        )
    buffer = (ctypes.c_ubyte * int(size.value))()
    _check(
        _ncrypt.NCryptGetProperty(
            handle,
            name,
            buffer,
            int(size.value),
            ctypes.byref(size),
            _SILENT_FLAG,
        ),
        "CNG host signer identity is unavailable",
    )
    return bytes(buffer).decode("utf-16-le").rstrip("\0")


def _public_spki(handle: ctypes.c_void_p) -> bytes:
    size = ctypes.c_ulong()
    _check(
        _ncrypt.NCryptExportKey(
            handle,
            None,
            _PUBLIC_BLOB,
            None,
            None,
            0,
            ctypes.byref(size),
            _SILENT_FLAG,
        ),
        "CNG host signer public key is unavailable",
    )
    if not 72 <= int(size.value) <= 256:
        raise InstalledChannelCngHostSignerError(
            "CNG host signer public key has an invalid size"
        )
    buffer = (ctypes.c_ubyte * int(size.value))()
    _check(
        _ncrypt.NCryptExportKey(
            handle,
            None,
            _PUBLIC_BLOB,
            None,
            buffer,
            int(size.value),
            ctypes.byref(size),
            _SILENT_FLAG,
        ),
        "CNG host signer public key is unavailable",
    )
    raw = bytes(buffer)[: int(size.value)]
    magic = int.from_bytes(raw[0:4], "little")
    width = int.from_bytes(raw[4:8], "little")
    if magic != _ECDSA_PUBLIC_P256_MAGIC or width != 32 or len(raw) != 8 + 64:
        raise InstalledChannelCngHostSignerError(
            "CNG host signer public key is invalid"
        )
    public = ec.EllipticCurvePublicNumbers(
        int.from_bytes(raw[8:40], "big"),
        int.from_bytes(raw[40:72], "big"),
        ec.SECP256R1(),
    ).public_key()
    return public.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _security_descriptor_bytes(sddl: str) -> bytes:
    pointer = ctypes.c_void_p()
    size = ctypes.c_ulong()
    if not _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl,
        1,
        ctypes.byref(pointer),
        ctypes.byref(size),
    ):
        raise InstalledChannelCngHostSignerError(
            "CNG host signer ACL could not be constructed"
        ) from ctypes.WinError(ctypes.get_last_error())
    try:
        if not pointer.value or not 20 <= int(size.value) <= 4096:
            raise InstalledChannelCngHostSignerError(
                "CNG host signer ACL has an invalid size"
            )
        return ctypes.string_at(pointer, int(size.value))
    finally:
        _kernel32.LocalFree(pointer)


def _set_key_security(handle: ctypes.c_void_p) -> None:
    raw = _security_descriptor_bytes(_KEY_ADMIN_SDDL)
    buffer = (ctypes.c_ubyte * len(raw)).from_buffer_copy(raw)
    _check(
        _ncrypt.NCryptSetProperty(
            handle,
            _SECURITY_DESCRIPTOR_PROPERTY,
            buffer,
            len(raw),
            _PERSIST_FLAG | _SILENT_FLAG | _KEY_SECURITY_FLAGS,
        ),
        "CNG host signer ACL could not be persisted",
    )


def _security_descriptor_sddl(raw: bytes) -> str:
    buffer = (ctypes.c_ubyte * len(raw)).from_buffer_copy(raw)
    text = ctypes.c_wchar_p()
    length = ctypes.c_ulong()
    if not _advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
        buffer,
        1,
        _KEY_SECURITY_FLAGS,
        ctypes.byref(text),
        ctypes.byref(length),
    ):
        raise InstalledChannelCngHostSignerError(
            "CNG host signer ACL could not be normalized"
        ) from ctypes.WinError(ctypes.get_last_error())
    try:
        if not text.value:
            raise InstalledChannelCngHostSignerError(
                "CNG host signer ACL is empty"
            )
        return text.value
    finally:
        _kernel32.LocalFree(ctypes.cast(text, ctypes.c_void_p))


def _get_key_security(handle: ctypes.c_void_p) -> bytes:
    size = ctypes.c_ulong()
    flags = _SILENT_FLAG | _KEY_SECURITY_FLAGS
    _check(
        _ncrypt.NCryptGetProperty(
            handle,
            _SECURITY_DESCRIPTOR_PROPERTY,
            None,
            0,
            ctypes.byref(size),
            flags,
        ),
        "CNG host signer ACL is unavailable",
    )
    if not 20 <= int(size.value) <= 4096:
        raise InstalledChannelCngHostSignerError(
            "CNG host signer ACL has an invalid size"
        )
    buffer = (ctypes.c_ubyte * int(size.value))()
    _check(
        _ncrypt.NCryptGetProperty(
            handle,
            _SECURITY_DESCRIPTOR_PROPERTY,
            buffer,
            int(size.value),
            ctypes.byref(size),
            flags,
        ),
        "CNG host signer ACL is unavailable",
    )
    return bytes(buffer)[: int(size.value)]


def _assert_key_security(handle: ctypes.c_void_p) -> None:
    expected = _security_descriptor_sddl(
        _security_descriptor_bytes(_KEY_ADMIN_SDDL)
    )
    actual = _security_descriptor_sddl(_get_key_security(handle))
    if actual != expected:
        raise InstalledChannelCngHostSignerError(
            "CNG host signer ACL differs from policy"
        )


@dataclass(slots=True, repr=False)
class WindowsCngHostSigner:
    key_id: str
    public_key_spki_der: bytes
    provider: str
    hardware_backed: bool
    private_acl_verified: bool
    _provider_handle: ctypes.c_void_p = field(repr=False)
    _key_handle: ctypes.c_void_p = field(repr=False)
    algorithm: str = _ALGORITHM
    _closed: bool = field(default=False, repr=False)

    def _require_key(self) -> ctypes.c_void_p:
        if self._closed or not self._key_handle.value:
            raise InstalledChannelCngHostSignerError(
                "CNG host signer is closed"
            )
        return self._key_handle

    def sign(self, payload: bytes) -> bytes:
        if not isinstance(payload, bytes) or not 1 <= len(payload) <= 16 * 1024:
            raise InstalledChannelCngHostSignerError(
                "CNG host signer payload is invalid"
            )
        digest = hashlib.sha256(payload).digest()
        digest_buffer = (ctypes.c_ubyte * len(digest)).from_buffer_copy(digest)
        size = ctypes.c_ulong()
        handle = self._require_key()
        _check(
            _ncrypt.NCryptSignHash(
                handle,
                None,
                digest_buffer,
                len(digest),
                None,
                0,
                ctypes.byref(size),
                _SILENT_FLAG,
            ),
            "CNG host signature is unavailable",
        )
        if int(size.value) != 64:
            raise InstalledChannelCngHostSignerError(
                "CNG host signature has an invalid size"
            )
        output = (ctypes.c_ubyte * 64)()
        _check(
            _ncrypt.NCryptSignHash(
                handle,
                None,
                digest_buffer,
                len(digest),
                output,
                len(output),
                ctypes.byref(size),
                _SILENT_FLAG,
            ),
            "CNG host signature is unavailable",
        )
        raw = bytes(output)
        return encode_dss_signature(
            int.from_bytes(raw[:32], "big"),
            int.from_bytes(raw[32:], "big"),
        )

    def verify(self, payload: bytes, signature: bytes) -> bool:
        try:
            public = serialization.load_der_public_key(self.public_key_spki_der)
            if not isinstance(public, ec.EllipticCurvePublicKey):
                return False
            public.verify(signature, payload, ec.ECDSA(hashes.SHA256()))
        except (TypeError, ValueError, InvalidSignature):
            return False
        return True

    def private_export_blocked(self) -> bool:
        size = ctypes.c_ulong()
        status = _ncrypt.NCryptExportKey(
            self._require_key(),
            None,
            _PRIVATE_BLOB,
            None,
            None,
            0,
            ctypes.byref(size),
            _SILENT_FLAG,
        )
        return _code(status) != 0

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        _free(self._key_handle)
        _free(self._provider_handle)

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


class WindowsCngHostSignerStore:
    def __init__(
        self,
        *,
        key_prefix: str = "NachuanHostSigner-v1",
        machine_scope: bool = True,
        provider: str = _PLATFORM_PROVIDER,
        hardware_backed: bool = True,
        test_only_allow_delete: bool = False,
    ) -> None:
        if (
            os.name != "nt"
            or not isinstance(key_prefix, str)
            or _KEY_PREFIX.fullmatch(key_prefix) is None
            or type(machine_scope) is not bool
            or provider not in {_SOFTWARE_PROVIDER, _PLATFORM_PROVIDER}
            or type(hardware_backed) is not bool
            or hardware_backed != (provider == _PLATFORM_PROVIDER)
            or type(test_only_allow_delete) is not bool
        ):
            raise InstalledChannelCngHostSignerError(
                "CNG host signer policy is invalid"
            )
        self.key_prefix = key_prefix
        self.machine_scope = machine_scope
        self.provider = provider
        self.hardware_backed = hardware_backed
        self._allow_delete = test_only_allow_delete

    @staticmethod
    def _snapshot(snapshot: object) -> InstallationRootSnapshot:
        if (
            not isinstance(snapshot, InstallationRootSnapshot)
            or snapshot.status != "active"
            or snapshot.lock_kind != "none"
            or snapshot.reanchor_pending
        ):
            raise InstalledChannelCngHostSignerError(
                "CNG host signer installation is invalid"
            )
        return snapshot

    def _key_name(self, snapshot: InstallationRootSnapshot) -> str:
        digest = hashlib.sha256(
            b"nachuan-cng-host-signer-name-v1\0"
            + snapshot.installation_id.encode("ascii")
        ).hexdigest()
        return f"{self.key_prefix}-{digest}"

    def _open_provider(self) -> ctypes.c_void_p:
        handle = ctypes.c_void_p()
        _check(
            _ncrypt.NCryptOpenStorageProvider(
                ctypes.byref(handle), self.provider, _SILENT_FLAG
            ),
            "CNG host signer provider is unavailable",
        )
        return handle

    def _open_key(
        self, provider: ctypes.c_void_p, name: str
    ) -> tuple[ctypes.c_void_p | None, int]:
        key = ctypes.c_void_p()
        status = _ncrypt.NCryptOpenKey(
            provider,
            ctypes.byref(key),
            name,
            0,
            _flags(self.machine_scope),
        )
        return (key if _code(status) == 0 else None), _code(status)

    def open_or_create(
        self,
        *,
        installation_snapshot: InstallationRootSnapshot,
        allow_create: bool,
    ) -> WindowsCngHostSigner:
        snapshot = self._snapshot(installation_snapshot)
        if type(allow_create) is not bool:
            raise InstalledChannelCngHostSignerError(
                "CNG host signer creation policy is invalid"
            )
        provider = self._open_provider()
        key: ctypes.c_void_p | None = None
        try:
            name = self._key_name(snapshot)
            key, open_status = self._open_key(provider, name)
            if key is None:
                if open_status not in {_NTE_BAD_KEYSET, _NTE_NOT_FOUND}:
                    raise InstalledChannelCngHostSignerError(
                        "CNG host signer could not be opened"
                    )
                if not allow_create:
                    raise InstalledChannelCngHostSignerError(
                        "CNG host signer is unavailable"
                    )
                candidate = ctypes.c_void_p()
                status = _ncrypt.NCryptCreatePersistedKey(
                    provider,
                    ctypes.byref(candidate),
                    _CNG_ALGORITHM,
                    name,
                    0,
                    _flags(self.machine_scope),
                )
                if _code(status) == _NTE_EXISTS:
                    key, open_status = self._open_key(provider, name)
                    if key is None or open_status != 0:
                        raise InstalledChannelCngHostSignerError(
                            "CNG host signer creation raced"
                        )
                else:
                    _check(status, "CNG host signer could not be created")
                    key = candidate
                    try:
                        _set_dword(key, "Export Policy", 0)
                        _set_dword(key, "Key Usage", _ALLOW_SIGNING_FLAG)
                        _set_key_security(key)
                        _check(
                            _ncrypt.NCryptFinalizeKey(key, _SILENT_FLAG),
                            "CNG host signer could not be finalized",
                        )
                    except Exception:
                        _ncrypt.NCryptDeleteKey(key, _SILENT_FLAG)
                        key = None
                        raise
            assert key is not None
            if (
                _get_text(key, "Algorithm Name") != _CNG_ALGORITHM
                or _get_dword(key, "Export Policy") != 0
                or _get_dword(key, "Key Usage") != _ALLOW_SIGNING_FLAG
            ):
                raise InstalledChannelCngHostSignerError(
                    "CNG host signer policy differs from enrollment"
                )
            _assert_key_security(key)
            public_der = _public_spki(key)
            signer = WindowsCngHostSigner(
                key_id=hashlib.sha256(public_der).hexdigest(),
                public_key_spki_der=public_der,
                provider=self.provider,
                hardware_backed=self.hardware_backed,
                private_acl_verified=True,
                _provider_handle=provider,
                _key_handle=key,
            )
            provider = ctypes.c_void_p()
            key = None
            return signer
        finally:
            _free(key)
            _free(provider)

    def delete_for_test_only(
        self, installation_snapshot: InstallationRootSnapshot
    ) -> None:
        if not self._allow_delete:
            raise InstalledChannelCngHostSignerError(
                "CNG host signer deletion is forbidden"
            )
        snapshot = self._snapshot(installation_snapshot)
        provider = self._open_provider()
        key: ctypes.c_void_p | None = None
        try:
            key, status = self._open_key(provider, self._key_name(snapshot))
            if key is None:
                if status in {_NTE_BAD_KEYSET, _NTE_NOT_FOUND}:
                    return
                raise InstalledChannelCngHostSignerError(
                    "CNG test host signer could not be opened"
                )
            _check(
                _ncrypt.NCryptDeleteKey(key, _SILENT_FLAG),
                "CNG test host signer could not be deleted",
            )
            key = None
        finally:
            _free(key)
            _free(provider)


__all__ = [
    "InstalledChannelCngHostSignerError",
    "WindowsCngHostSigner",
    "WindowsCngHostSignerStore",
]
