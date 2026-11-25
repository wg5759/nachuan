"""跨平台加密密钥存储抽象（P2-1：打破 Windows-only，统一 Win/macOS/Linux/无头容器）。

架构设计（统一信封 schema = ``nachuan.protected-json.v1``）：
1. ``windows-dpapi-current-user``：Windows 下委托给 ``gateway.secure_store``
   （原生 DPAPI Current-User + NTFS DACL 加固），100% 二进制兼容既有密文与测试。
2. ``macos-keychain-aesgcm``：macOS 下调用 ``/usr/bin/security``
   （``find-generic-password`` / ``add-generic-password``，
   ``service="com.nachuan.runtime-master-key"``）托管 32 字节主密钥，结合
   HKDF-SHA256 + AES-256-GCM（AAD 绑定 ``schema|protection|purpose``）加密 JSON 信封，
   目录权限 ``0o700``、文件权限 ``0o600``。
3. ``linux-secret-service-aesgcm``：Linux 桌面下调用 ``/usr/bin/secret-tool``
   （``lookup`` / ``store``，携带 ``app=nachuan``）托管 32 字节主密钥，结合
   HKDF-SHA256 + AES-256-GCM 加密信封 + ``0o700``/``0o600`` 权限加固。
4. ``local-kdf-aesgcm-v1``：无头 Linux / 容器 / CI 环境下，仅在显式提供
   ``NACHUAN_SECRET_FALLBACK_PASSPHRASE``（或 ``NACHUAN_MASTER_KEY``）或受控 ``0o600``
   keyfile（显式参数或 ``NACHUAN_SECRET_KEYFILE``）时启用，采用 ``scrypt`` +
   AES-256-GCM 加密信封。

铁律：未配置任何可用后端时严格 fail-closed 报错，绝不静默自建无保护密钥、绝不回退明文！
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any, Callable, Mapping

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ENVELOPE_SCHEMA_V1 = "nachuan.protected-json.v1"
_LEGACY_ENVELOPE_SCHEMA_V2 = "nachuan.crossplatform-secret.v2"
_SUPPORTED_SCHEMAS = frozenset({ENVELOPE_SCHEMA_V1, _LEGACY_ENVELOPE_SCHEMA_V2})

PROTECTION_WINDOWS_DPAPI = "windows-dpapi-current-user"
PROTECTION_MACOS_KEYCHAIN = "macos-keychain-aesgcm"
PROTECTION_LINUX_SECRET_SERVICE = "linux-secret-service-aesgcm"
PROTECTION_LOCAL_KDF = "local-kdf-aesgcm-v1"

# 兼容历史上过渡版本曾写入过的 protection 别名，写入一律使用规范 ID
_LEGACY_PROTECTION_ALIASES: dict[str, str] = {
    "macos-keychain-aes256gcm": PROTECTION_MACOS_KEYCHAIN,
    "linux-libsecret-aes256gcm": PROTECTION_LINUX_SECRET_SERVICE,
    "encrypted-file-aes256gcm": PROTECTION_LOCAL_KDF,
}

_MAX_DOCUMENT_BYTES = 4 * 1024 * 1024
_AES_KEY_BYTES = 32
_AES_NONCE_BYTES = 12
_SALT_BYTES = 16
_SCRYPT_N = 1 << 14  # 16384，兼顾离线暴力破解成本与跨平台启动延迟
_SCRYPT_R = 8
_SCRYPT_P = 1
_LEGACY_PBKDF2_ITERATIONS = 600_000

_KEYCHAIN_SERVICE = "com.nachuan.runtime-master-key"
_KEYCHAIN_ACCOUNT = "master-key-v1"
_SECRET_TOOL_APP = "nachuan"
_PASSPHRASE_ENV_PRIMARY = "NACHUAN_SECRET_FALLBACK_PASSPHRASE"
_PASSPHRASE_ENV_LEGACY = "NACHUAN_MASTER_KEY"
_KEYFILE_ENV = "NACHUAN_SECRET_KEYFILE"


class CrossPlatformSecretError(RuntimeError):
    """跨平台密钥存储不可用、未配置后端、主密钥缺失、密文损坏或认证校验失败。"""


@dataclass(frozen=True)
class SecretBackendInfo:
    platform: str
    backend: str
    protection_id: str
    hardware_or_os_keyring: bool


def _subprocess_kwargs() -> dict[str, Any]:
    return {"creationflags": 0x08000000} if os.name == "nt" else {}


def _canonical_protection(protection: str) -> str:
    raw = str(protection or "").strip()
    return _LEGACY_PROTECTION_ALIASES.get(raw, raw)


def _chmod_owner_only(path: Path, *, directory: bool = False) -> None:
    if os.name == "nt":
        return
    mode = 0o700 if directory else 0o600
    try:
        os.chmod(path, mode)
    except OSError as exc:
        raise CrossPlatformSecretError(f"无法收紧密钥路径权限：{path}") from exc


def _check_not_symlink(path: Path) -> None:
    try:
        if path.exists() or path.is_symlink():
            if path.is_symlink():
                raise CrossPlatformSecretError(f"拒绝访问符号链接密钥路径：{path}")
            st = path.lstat()
            if getattr(st, "st_file_attributes", 0) & 0x400:
                raise CrossPlatformSecretError(f"拒绝访问重解析点密钥路径：{path}")
    except CrossPlatformSecretError:
        raise
    except OSError as exc:
        raise CrossPlatformSecretError(f"无法检查密钥路径属性：{path}") from exc


def _derive_key_hkdf(
    master_key: bytes,
    *,
    schema: str,
    protection: str,
    purpose: str,
    salt: bytes,
) -> bytes:
    """使用 HKDF-SHA256 按 schema + protection + purpose 域分离派生 AES-256 密钥。"""
    if len(master_key) < 16:
        raise CrossPlatformSecretError("主密钥熵不足")
    info = f"{schema}|{protection}|{purpose}".encode("utf-8")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=_AES_KEY_BYTES,
        salt=salt,
        info=info,
    ).derive(master_key)


def _derive_key_scrypt(
    secret_material: bytes,
    *,
    schema: str,
    protection: str,
    purpose: str,
    salt: bytes,
) -> bytes:
    """使用 scrypt 将口令或受控 keyfile 派生为 purpose 隔离的 AES-256 密钥。"""
    if len(secret_material) < 12:
        raise CrossPlatformSecretError("主密钥材料熵不足")
    bound_salt = hashlib.sha256(
        salt + b"\x00" + f"{schema}|{protection}|{purpose}".encode("utf-8")
    ).digest()[:16]
    return hashlib.scrypt(
        secret_material,
        salt=bound_salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_AES_KEY_BYTES,
    )


def _derive_key_legacy_pbkdf2(
    master_key: bytes, *, purpose: str, salt: bytes
) -> bytes:
    if len(master_key) < 16:
        raise CrossPlatformSecretError("主密钥熵不足")
    return hashlib.pbkdf2_hmac(
        "sha256",
        master_key + b"\x00" + purpose.encode("utf-8"),
        salt,
        _LEGACY_PBKDF2_ITERATIONS,
        dklen=_AES_KEY_BYTES,
    )


def _encrypt_aesgcm_envelope(
    plaintext: bytes,
    *,
    secret_material: bytes,
    purpose: str,
    protection: str,
    kdf: str,
) -> dict[str, Any]:
    if len(plaintext) > _MAX_DOCUMENT_BYTES:
        raise CrossPlatformSecretError("密钥文档超过最大允许体积")
    salt = secrets.token_bytes(_SALT_BYTES)
    nonce = secrets.token_bytes(_AES_NONCE_BYTES)
    if kdf == "hkdf-sha256":
        key = _derive_key_hkdf(
            secret_material,
            schema=ENVELOPE_SCHEMA_V1,
            protection=protection,
            purpose=purpose,
            salt=salt,
        )
    elif kdf == "scrypt":
        key = _derive_key_scrypt(
            secret_material,
            schema=ENVELOPE_SCHEMA_V1,
            protection=protection,
            purpose=purpose,
            salt=salt,
        )
    else:
        raise CrossPlatformSecretError(f"不支持的密钥派生算法：{kdf}")
    aad = f"{ENVELOPE_SCHEMA_V1}|{protection}|{purpose}".encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return {
        "schema": ENVELOPE_SCHEMA_V1,
        "protection": protection,
        "kdf": kdf,
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }


def _decrypt_aesgcm_envelope(
    document: Mapping[str, Any],
    *,
    secret_material: bytes,
    purpose: str,
    expected_protection: str,
    default_kdf: str,
) -> bytes:
    schema = str(document.get("schema") or "")
    if schema not in _SUPPORTED_SCHEMAS:
        raise CrossPlatformSecretError("不支持的跨平台密钥信封版本")
    raw_protection = str(document.get("protection") or "")
    if _canonical_protection(raw_protection) != _canonical_protection(expected_protection):
        raise CrossPlatformSecretError(f"密钥信封保护方式不匹配：{raw_protection}")
    try:
        salt = base64.b64decode(str(document["salt"]), validate=True)
        nonce = base64.b64decode(str(document["nonce"]), validate=True)
        ciphertext = base64.b64decode(str(document["ciphertext"]), validate=True)
    except Exception as exc:
        raise CrossPlatformSecretError("密文信封 Base64 格式损坏") from exc
    if (
        len(salt) != _SALT_BYTES
        or len(nonce) != _AES_NONCE_BYTES
        or len(ciphertext) > _MAX_DOCUMENT_BYTES + 64
    ):
        raise CrossPlatformSecretError("密文信封参数长度非法")

    kdf = str(document.get("kdf") or "").strip().lower()
    if schema == _LEGACY_ENVELOPE_SCHEMA_V2 and not kdf:
        kdf = "pbkdf2-sha256"
    elif not kdf:
        kdf = default_kdf

    if kdf == "hkdf-sha256":
        key = _derive_key_hkdf(
            secret_material,
            schema=schema,
            protection=raw_protection,
            purpose=purpose,
            salt=salt,
        )
    elif kdf == "scrypt":
        key = _derive_key_scrypt(
            secret_material,
            schema=schema,
            protection=raw_protection,
            purpose=purpose,
            salt=salt,
        )
    elif kdf == "pbkdf2-sha256":
        # 兼容历史 v2 信封：若是口令材料则先做 SHA-256 归一与旧逻辑一致
        legacy_key = (
            secret_material
            if len(secret_material) == _AES_KEY_BYTES
            else hashlib.sha256(secret_material).digest()
        )
        key = _derive_key_legacy_pbkdf2(legacy_key, purpose=purpose, salt=salt)
    else:
        raise CrossPlatformSecretError(f"不支持的密钥派生算法：{kdf}")

    aad = f"{schema}|{raw_protection}|{purpose}".encode("utf-8")
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise CrossPlatformSecretError(
            "密文认证校验失败：主密钥不匹配、purpose 不一致或密文已被篡改"
        ) from exc
    if len(plaintext) > _MAX_DOCUMENT_BYTES:
        raise CrossPlatformSecretError("解密后文档超过大小上限")
    return plaintext


def _atomic_write_json(
    path: Path,
    data: Mapping[str, Any],
    *,
    replace_existing: bool = True,
) -> bool:
    _check_not_symlink(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    _chmod_owner_only(path.parent, directory=True)
    tmp_name = ""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
            delete=False,
        ) as handle:
            tmp_name = handle.name
            json.dump(dict(data), handle, ensure_ascii=True, separators=(",", ":"))
            handle.flush()
            os.fsync(handle.fileno())
        _chmod_owner_only(Path(tmp_name), directory=False)
        if replace_existing:
            os.replace(tmp_name, path)
            tmp_name = ""
            _chmod_owner_only(path, directory=False)
            return True
        try:
            os.link(tmp_name, path)
        except FileExistsError:
            return False
        except OSError as exc:
            raise CrossPlatformSecretError(
                "无法原子创建受保护密钥文件；拒绝覆盖既有配置"
            ) from exc
        Path(tmp_name).unlink(missing_ok=True)
        tmp_name = ""
        _chmod_owner_only(path, directory=False)
        return True
    finally:
        if tmp_name:
            try:
                Path(tmp_name).unlink(missing_ok=True)
            except OSError:
                pass


class SecretBackend:
    """跨平台受保护 JSON 密钥存储抽象基类。"""

    info: SecretBackendInfo

    @property
    def protection_id(self) -> str:
        return self.info.protection_id

    def encrypt(self, plaintext: bytes, *, purpose: str) -> dict[str, Any]:
        raise NotImplementedError

    def decrypt(self, envelope: Mapping[str, Any], *, purpose: str) -> bytes:
        raise NotImplementedError

    def write_json(
        self, path: str | Path, payload: Mapping[str, Any], *, purpose: str
    ) -> None:
        raise NotImplementedError

    def write_json_if_absent(
        self, path: str | Path, payload: Mapping[str, Any], *, purpose: str
    ) -> bool:
        raise NotImplementedError

    def read_json(
        self,
        path: str | Path,
        *,
        purpose: str,
        migrate_plaintext: bool = False,
        plaintext_migrator: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        raise NotImplementedError


# 向后兼容旧命名
SecretStoreBackend = SecretBackend


class WindowsDPAPIBackend(SecretBackend):
    """Windows 原生 DPAPI 后端：完整委托 gateway.secure_store，100% 兼容既有基线。"""

    info = SecretBackendInfo(
        platform="win32",
        backend="windows-dpapi",
        protection_id=PROTECTION_WINDOWS_DPAPI,
        hardware_or_os_keyring=True,
    )

    def encrypt(self, plaintext: bytes, *, purpose: str) -> dict[str, Any]:
        from gateway.secure_store import SecureStorageError, _crypt_protect

        if len(plaintext) > _MAX_DOCUMENT_BYTES:
            raise CrossPlatformSecretError("运行态密钥数据超过安全大小上限")
        try:
            ciphertext = _crypt_protect(plaintext, purpose=purpose)
        except SecureStorageError as exc:
            raise CrossPlatformSecretError(str(exc)) from exc
        return {
            "schema": ENVELOPE_SCHEMA_V1,
            "protection": PROTECTION_WINDOWS_DPAPI,
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        }

    def decrypt(self, envelope: Mapping[str, Any], *, purpose: str) -> bytes:
        from gateway.secure_store import SecureStorageError, _crypt_unprotect

        if envelope.get("schema") != ENVELOPE_SCHEMA_V1:
            raise CrossPlatformSecretError("未知的运行态密钥信封版本")
        if envelope.get("protection") != PROTECTION_WINDOWS_DPAPI:
            raise CrossPlatformSecretError("运行态密钥保护方式不是 Windows DPAPI")
        try:
            ciphertext = base64.b64decode(str(envelope["ciphertext"]), validate=True)
            if len(ciphertext) > _MAX_DOCUMENT_BYTES:
                raise CrossPlatformSecretError("运行态密钥密文超过安全大小上限")
            plaintext = _crypt_unprotect(ciphertext, purpose=purpose)
        except CrossPlatformSecretError:
            raise
        except (SecureStorageError, KeyError, ValueError) as exc:
            raise CrossPlatformSecretError(str(exc)) from exc
        if len(plaintext) > _MAX_DOCUMENT_BYTES:
            raise CrossPlatformSecretError("解密后的运行态密钥超过安全大小上限")
        return plaintext

    def write_json(
        self, path: str | Path, payload: Mapping[str, Any], *, purpose: str
    ) -> None:
        from gateway.secure_store import SecureStorageError, _write_protected_json

        try:
            _write_protected_json(path, payload, purpose=purpose, replace_existing=True)
        except SecureStorageError as exc:
            raise CrossPlatformSecretError(str(exc)) from exc

    def write_json_if_absent(
        self, path: str | Path, payload: Mapping[str, Any], *, purpose: str
    ) -> bool:
        from gateway.secure_store import SecureStorageError, _write_protected_json

        try:
            return _write_protected_json(
                path, payload, purpose=purpose, replace_existing=False
            )
        except SecureStorageError as exc:
            raise CrossPlatformSecretError(str(exc)) from exc

    def read_json(
        self,
        path: str | Path,
        *,
        purpose: str,
        migrate_plaintext: bool = False,
        plaintext_migrator: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        from gateway.secure_store import SecureStorageError, read_protected_json

        try:
            return read_protected_json(
                path,
                purpose=purpose,
                migrate_plaintext=migrate_plaintext,
                plaintext_migrator=plaintext_migrator,
            )
        except SecureStorageError as exc:
            raise CrossPlatformSecretError(str(exc)) from exc


class _EnvelopeKeyBackend(SecretBackend):
    """以主密钥 + AES-256-GCM 认证加密信封实现的跨平台基类。"""

    _default_kdf: str = "hkdf-sha256"

    def _get_or_create_master_key(self, *, create: bool) -> bytes:
        raise NotImplementedError

    def encrypt(self, plaintext: bytes, *, purpose: str) -> dict[str, Any]:
        secret_material = self._get_or_create_master_key(create=True)
        return _encrypt_aesgcm_envelope(
            plaintext,
            secret_material=secret_material,
            purpose=purpose,
            protection=self.info.protection_id,
            kdf=self._default_kdf,
        )

    def decrypt(self, envelope: Mapping[str, Any], *, purpose: str) -> bytes:
        secret_material = self._get_or_create_master_key(create=False)
        return _decrypt_aesgcm_envelope(
            envelope,
            secret_material=secret_material,
            purpose=purpose,
            expected_protection=self.info.protection_id,
            default_kdf=self._default_kdf,
        )

    def _serialize_payload(self, payload: Mapping[str, Any]) -> bytes:
        plaintext = json.dumps(
            dict(payload), ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        if len(plaintext) > _MAX_DOCUMENT_BYTES:
            raise CrossPlatformSecretError("密钥文档超过最大允许体积")
        return plaintext

    def write_json(
        self, path: str | Path, payload: Mapping[str, Any], *, purpose: str
    ) -> None:
        envelope = self.encrypt(self._serialize_payload(payload), purpose=purpose)
        _atomic_write_json(Path(path), envelope, replace_existing=True)

    def write_json_if_absent(
        self, path: str | Path, payload: Mapping[str, Any], *, purpose: str
    ) -> bool:
        envelope = self.encrypt(self._serialize_payload(payload), purpose=purpose)
        return _atomic_write_json(Path(path), envelope, replace_existing=False)

    def read_json(
        self,
        path: str | Path,
        *,
        purpose: str,
        migrate_plaintext: bool = False,
        plaintext_migrator: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        target = Path(path)
        if not target.exists():
            raise FileNotFoundError(target)
        _check_not_symlink(target)
        if target.stat().st_size > _MAX_DOCUMENT_BYTES:
            raise CrossPlatformSecretError("密钥文件超过最大安全体积")
        try:
            document = json.loads(target.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise CrossPlatformSecretError("密钥文件损坏，拒绝按空配置继续") from exc
        if not isinstance(document, dict):
            raise CrossPlatformSecretError("密钥文件格式非法")

        if document.get("schema") in _SUPPORTED_SCHEMAS:
            plaintext = self.decrypt(document, purpose=purpose)
            try:
                decoded = json.loads(plaintext.decode("utf-8"))
            except (UnicodeError, json.JSONDecodeError) as exc:
                raise CrossPlatformSecretError("解密后的密钥内容不是合法 JSON") from exc
            if not isinstance(decoded, dict):
                raise CrossPlatformSecretError("解密后的密钥文档必须是 JSON 对象")
            return decoded

        if "schema" in document or "protection" in document or "ciphertext" in document:
            raise CrossPlatformSecretError("未知或跨平台不兼容的密钥信封版本")
        if not migrate_plaintext:
            raise CrossPlatformSecretError("检测到旧版明文密钥文件，必须显式开启迁移")
        migrated = dict(document)
        if plaintext_migrator is not None:
            try:
                migrated = plaintext_migrator(dict(document))
            except Exception as exc:
                raise CrossPlatformSecretError("明文密钥迁移失败") from exc
            if not isinstance(migrated, dict):
                raise CrossPlatformSecretError("明文密钥迁移器返回值非法")
        self.write_json(target, migrated, purpose=purpose)
        return migrated


class MacOSKeychainBackend(_EnvelopeKeyBackend):
    """macOS Keychain 后端：通过 /usr/bin/security 托管 32 字节主密钥 + HKDF + AES-256-GCM。"""

    _default_kdf = "hkdf-sha256"
    info = SecretBackendInfo(
        platform="darwin",
        backend="macos-keychain",
        protection_id=PROTECTION_MACOS_KEYCHAIN,
        hardware_or_os_keyring=True,
    )

    def __init__(
        self,
        *,
        security_bin: str = "/usr/bin/security",
        service: str = _KEYCHAIN_SERVICE,
        account: str = _KEYCHAIN_ACCOUNT,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    ) -> None:
        self._security_bin = security_bin
        self._service = service
        self._account = account
        self._runner = runner

    def _get_or_create_master_key(self, *, create: bool) -> bytes:
        try:
            res = self._runner(
                [
                    self._security_bin,
                    "find-generic-password",
                    "-s",
                    self._service,
                    "-a",
                    self._account,
                    "-w",
                ],
                capture_output=True,
                text=True,
                timeout=15,
                **_subprocess_kwargs(),
            )
        except OSError as exc:
            raise CrossPlatformSecretError(
                f"无法调用 macOS Keychain 工具 ({self._security_bin})"
            ) from exc
        if res.returncode == 0 and res.stdout.strip():
            try:
                raw = base64.b64decode(res.stdout.strip(), validate=True)
                if len(raw) == _AES_KEY_BYTES:
                    return raw
            except Exception as exc:
                raise CrossPlatformSecretError("macOS Keychain 主密钥格式损坏") from exc
            raise CrossPlatformSecretError("macOS Keychain 主密钥长度异常")

        if not create:
            raise CrossPlatformSecretError(
                "macOS Keychain 中未找到纳川主密钥，无法解密现有密文"
            )

        new_key = secrets.token_bytes(_AES_KEY_BYTES)
        encoded = base64.b64encode(new_key).decode("ascii")
        try:
            add_res = self._runner(
                [
                    self._security_bin,
                    "add-generic-password",
                    "-U",
                    "-s",
                    self._service,
                    "-a",
                    self._account,
                    "-w",
                    encoded,
                ],
                capture_output=True,
                text=True,
                timeout=15,
                **_subprocess_kwargs(),
            )
        except OSError as exc:
            raise CrossPlatformSecretError(
                f"无法写入 macOS Keychain ({self._security_bin})"
            ) from exc
        if add_res.returncode != 0:
            raise CrossPlatformSecretError(
                f"写入 macOS Keychain 失败（exit={add_res.returncode}）"
            )
        return new_key


class LinuxSecretServiceBackend(_EnvelopeKeyBackend):
    """Linux Secret Service 后端：通过 /usr/bin/secret-tool（app=nachuan）托管 32 字节主密钥。"""

    _default_kdf = "hkdf-sha256"
    info = SecretBackendInfo(
        platform="linux",
        backend="linux-secret-service",
        protection_id=PROTECTION_LINUX_SECRET_SERVICE,
        hardware_or_os_keyring=True,
    )

    def __init__(
        self,
        *,
        secret_tool_bin: str = "/usr/bin/secret-tool",
        app: str = _SECRET_TOOL_APP,
        service: str = _KEYCHAIN_SERVICE,
        account: str = _KEYCHAIN_ACCOUNT,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    ) -> None:
        self._bin = secret_tool_bin
        self._app = app
        self._service = service
        self._account = account
        self._runner = runner

    def _get_or_create_master_key(self, *, create: bool) -> bytes:
        try:
            res = self._runner(
                [
                    self._bin,
                    "lookup",
                    "app",
                    self._app,
                    "service",
                    self._service,
                    "account",
                    self._account,
                ],
                capture_output=True,
                text=True,
                timeout=15,
                **_subprocess_kwargs(),
            )
        except OSError as exc:
            raise CrossPlatformSecretError(
                f"无法调用 Linux secret-tool ({self._bin})"
            ) from exc
        if res.returncode == 0 and res.stdout.strip():
            try:
                raw = base64.b64decode(res.stdout.strip(), validate=True)
                if len(raw) == _AES_KEY_BYTES:
                    return raw
            except Exception as exc:
                raise CrossPlatformSecretError("Linux SecretService 主密钥格式损坏") from exc
            raise CrossPlatformSecretError("Linux SecretService 主密钥长度异常")

        if not create:
            raise CrossPlatformSecretError(
                "Linux SecretService 中未找到纳川主密钥，无法解密现有密文"
            )

        new_key = secrets.token_bytes(_AES_KEY_BYTES)
        encoded = base64.b64encode(new_key).decode("ascii")
        try:
            store_res = self._runner(
                [
                    self._bin,
                    "store",
                    "--label=Nachuan Vault Master Key",
                    "app",
                    self._app,
                    "service",
                    self._service,
                    "account",
                    self._account,
                ],
                input=encoded + "\n",
                capture_output=True,
                text=True,
                timeout=15,
                **_subprocess_kwargs(),
            )
        except OSError as exc:
            raise CrossPlatformSecretError(
                f"无法写入 Linux secret-tool ({self._bin})"
            ) from exc
        if store_res.returncode != 0:
            raise CrossPlatformSecretError(
                f"写入 Linux SecretService 失败（exit={store_res.returncode}）"
            )
        return new_key


class LocalKdfSecretBackend(_EnvelopeKeyBackend):
    """无头 Linux / 容器 / CI 后端：scrypt + AES-256-GCM（``local-kdf-aesgcm-v1``）。

    仅在显式配置以下任一凭据来源时启用：
    1. 显式传入 ``master_passphrase`` 或环境变量
       ``NACHUAN_SECRET_FALLBACK_PASSPHRASE``（兼容 ``NACHUAN_MASTER_KEY``）；
    2. 显式传入 ``key_file`` 或环境变量 ``NACHUAN_SECRET_KEYFILE``（权限必须为 ``0o600``）。

    若均未配置，严格 fail-closed 抛出 ``CrossPlatformSecretError``，绝不回退明文！
    """

    _default_kdf = "scrypt"
    info = SecretBackendInfo(
        platform="posix-headless",
        backend="local-kdf-aesgcm",
        protection_id=PROTECTION_LOCAL_KDF,
        hardware_or_os_keyring=False,
    )

    def __init__(
        self,
        *,
        key_file: str | Path | None = None,
        master_passphrase: str | None = None,
    ) -> None:
        self._explicit_key_file = Path(key_file) if key_file is not None else None
        self._master_passphrase = master_passphrase

    def _resolve_passphrase(self) -> str:
        if self._master_passphrase is not None:
            return self._master_passphrase.strip()
        primary = os.environ.get(_PASSPHRASE_ENV_PRIMARY, "").strip()
        if primary:
            return primary
        return os.environ.get(_PASSPHRASE_ENV_LEGACY, "").strip()

    def _resolve_key_file(self) -> Path | None:
        if self._explicit_key_file is not None:
            return self._explicit_key_file
        env_path = os.environ.get(_KEYFILE_ENV, "").strip()
        if env_path:
            return Path(env_path)
        return None

    def is_configured(self) -> bool:
        return bool(self._resolve_passphrase() or self._resolve_key_file() is not None)

    def _get_or_create_master_key(self, *, create: bool) -> bytes:
        passphrase = self._resolve_passphrase()
        if passphrase:
            if len(passphrase) < 12:
                raise CrossPlatformSecretError(
                    "NACHUAN_SECRET_FALLBACK_PASSPHRASE 长度不足 12 位，拒绝弱口令"
                )
            return passphrase.encode("utf-8")

        kf = self._resolve_key_file()
        if kf is None:
            raise CrossPlatformSecretError(
                "未配置跨平台密钥后端：系统密钥环不可用，且未提供 "
                "NACHUAN_SECRET_FALLBACK_PASSPHRASE 或受控 0600 密钥文件；"
                "按 fail-closed 策略拒绝回退明文"
            )

        if kf.exists():
            _check_not_symlink(kf)
            if os.name != "nt":
                mode = stat.S_IMODE(kf.stat().st_mode)
                if mode & 0o077:
                    raise CrossPlatformSecretError(
                        f"密钥文件权限过宽（{oct(mode)}），须收紧至 0600：{kf}"
                    )
            try:
                raw = base64.b64decode(kf.read_text(encoding="utf-8").strip(), validate=True)
            except Exception as exc:
                raise CrossPlatformSecretError("本机密钥文件损坏") from exc
            if len(raw) != _AES_KEY_BYTES:
                raise CrossPlatformSecretError("本机密钥文件长度非法")
            return raw

        if not create:
            raise CrossPlatformSecretError(f"缺少本机受控主密钥文件：{kf}")

        kf.parent.mkdir(parents=True, exist_ok=True)
        _chmod_owner_only(kf.parent, directory=True)
        new_key = secrets.token_bytes(_AES_KEY_BYTES)
        encoded = base64.b64encode(new_key).decode("ascii")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        try:
            fd = os.open(str(kf), flags, 0o600)
        except FileExistsError:
            return self._get_or_create_master_key(create=False)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(encoded + "\n")
                f.flush()
                os.fsync(f.fileno())
        finally:
            _chmod_owner_only(kf, directory=False)
        return new_key


# 兼容既有类名导入
EncryptedFileSecretBackend = LocalKdfSecretBackend


def select_secret_store_backend(
    *,
    platform_name: str | None = None,
    which_fn: Callable[[str], str | None] = shutil.which,
    key_file: str | Path | None = None,
    master_passphrase: str | None = None,
    strict: bool = False,
) -> SecretBackend:
    """按操作系统自动选择安全密钥后端（Win DPAPI / macOS Keychain / Linux SecretService / local-kdf）。

    当 ``strict=True`` 且无系统密钥环、又未显式配置口令或受控 keyfile 时，立即 fail-closed 报错。
    """
    plat = (platform_name or sys.platform).lower()
    if plat.startswith("win"):
        return WindowsDPAPIBackend()
    if plat == "darwin":
        sec_path = "/usr/bin/security" if Path("/usr/bin/security").exists() else which_fn("security")
        if sec_path:
            return MacOSKeychainBackend(security_bin=str(sec_path))
        fallback = LocalKdfSecretBackend(key_file=key_file, master_passphrase=master_passphrase)
        if strict and not fallback.is_configured():
            raise CrossPlatformSecretError(
                "macOS Keychain 不可用且未配置 NACHUAN_SECRET_FALLBACK_PASSPHRASE 或受控 keyfile；拒绝回退明文"
            )
        return fallback
    if plat.startswith("linux"):
        tool = (
            "/usr/bin/secret-tool"
            if Path("/usr/bin/secret-tool").exists()
            else which_fn("secret-tool")
        )
        if tool and (os.environ.get("DBUS_SESSION_BUS_ADDRESS") or os.environ.get("DISPLAY")):
            return LinuxSecretServiceBackend(secret_tool_bin=str(tool))
        fallback = LocalKdfSecretBackend(key_file=key_file, master_passphrase=master_passphrase)
        if strict and not fallback.is_configured():
            raise CrossPlatformSecretError(
                "Linux Secret Service 不可用且未配置 NACHUAN_SECRET_FALLBACK_PASSPHRASE 或受控 keyfile；拒绝回退明文"
            )
        return fallback
    fallback = LocalKdfSecretBackend(key_file=key_file, master_passphrase=master_passphrase)
    if strict and not fallback.is_configured():
        raise CrossPlatformSecretError(
            "当前平台无受支持密钥环且未配置 NACHUAN_SECRET_FALLBACK_PASSPHRASE 或受控 keyfile；拒绝回退明文"
        )
    return fallback


def backend_for_protection(
    protection: str,
    *,
    key_file: str | Path | None = None,
    master_passphrase: str | None = None,
    security_runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
    secret_tool_runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
) -> SecretBackend:
    """根据信封 ``protection`` 字段精确分发对应解密后端。"""
    canonical = _canonical_protection(protection)
    if canonical == PROTECTION_WINDOWS_DPAPI:
        return WindowsDPAPIBackend()
    if canonical == PROTECTION_MACOS_KEYCHAIN:
        kwargs: dict[str, Any] = {}
        if security_runner is not None:
            kwargs["runner"] = security_runner
        return MacOSKeychainBackend(**kwargs)
    if canonical == PROTECTION_LINUX_SECRET_SERVICE:
        kwargs = {}
        if secret_tool_runner is not None:
            kwargs["runner"] = secret_tool_runner
        return LinuxSecretServiceBackend(**kwargs)
    if canonical == PROTECTION_LOCAL_KDF:
        return LocalKdfSecretBackend(
            key_file=key_file,
            master_passphrase=master_passphrase,
        )
    raise CrossPlatformSecretError(f"运行态密钥保护方式不受支持：{protection}")


def describe_platform_secret_backend(
    *, platform_name: str | None = None
) -> dict[str, Any]:
    backend = select_secret_store_backend(platform_name=platform_name)
    info = backend.info
    return {
        "platform": info.platform,
        "backend": info.backend,
        "protection_id": info.protection_id,
        "hardware_or_os_keyring": info.hardware_or_os_keyring,
    }


def write_secret_json(
    path: str | Path,
    payload: Mapping[str, Any],
    *,
    purpose: str,
    backend: SecretBackend | None = None,
) -> None:
    store = backend or select_secret_store_backend(strict=True)
    store.write_json(path, payload, purpose=purpose)


def write_secret_json_if_absent(
    path: str | Path,
    payload: Mapping[str, Any],
    *,
    purpose: str,
    backend: SecretBackend | None = None,
) -> bool:
    store = backend or select_secret_store_backend(strict=True)
    return store.write_json_if_absent(path, payload, purpose=purpose)


def read_secret_json(
    path: str | Path,
    *,
    purpose: str,
    migrate_plaintext: bool = False,
    plaintext_migrator: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    backend: SecretBackend | None = None,
) -> dict[str, Any]:
    """读取受保护 JSON；若未显式固定 backend，则按信封 ``protection`` 字段自动分发解密。"""
    if backend is not None:
        return backend.read_json(
            path,
            purpose=purpose,
            migrate_plaintext=migrate_plaintext,
            plaintext_migrator=plaintext_migrator,
        )
    target = Path(path)
    if not target.exists():
        raise FileNotFoundError(target)
    _check_not_symlink(target)
    if target.stat().st_size > _MAX_DOCUMENT_BYTES:
        raise CrossPlatformSecretError("密钥文件超过最大安全体积")
    try:
        document = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CrossPlatformSecretError("密钥文件损坏，拒绝按空配置继续") from exc
    if not isinstance(document, dict):
        raise CrossPlatformSecretError("密钥文件格式非法")

    if document.get("schema") in _SUPPORTED_SCHEMAS:
        protection = str(document.get("protection") or "")
        dispatched = backend_for_protection(protection)
        return dispatched.read_json(
            target,
            purpose=purpose,
            migrate_plaintext=False,
            plaintext_migrator=None,
        )

    store = select_secret_store_backend(strict=True)
    return store.read_json(
        target,
        purpose=purpose,
        migrate_plaintext=migrate_plaintext,
        plaintext_migrator=plaintext_migrator,
    )


__all__ = [
    "CrossPlatformSecretError",
    "ENVELOPE_SCHEMA_V1",
    "EncryptedFileSecretBackend",
    "LinuxSecretServiceBackend",
    "LocalKdfSecretBackend",
    "MacOSKeychainBackend",
    "PROTECTION_LINUX_SECRET_SERVICE",
    "PROTECTION_LOCAL_KDF",
    "PROTECTION_MACOS_KEYCHAIN",
    "PROTECTION_WINDOWS_DPAPI",
    "SecretBackend",
    "SecretBackendInfo",
    "SecretStoreBackend",
    "WindowsDPAPIBackend",
    "backend_for_protection",
    "describe_platform_secret_backend",
    "read_secret_json",
    "select_secret_store_backend",
    "write_secret_json",
    "write_secret_json_if_absent",
]
