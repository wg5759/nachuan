"""Source-CLI boundary for local-admin prepared paid-video recovery."""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Iterator, Mapping

from cli.local_web_start import (
    LocalOwnerCredentialError,
    LocalPaidMediaCapabilityError,
    load_local_owner_credentials,
    load_local_paid_media_capability,
)
from gateway.durable_media_requests import (
    DurableMediaRequestStore,
    hash_media_principal,
)
from gateway.installation_bootstrap import windows_process_is_elevated
from gateway.paid_media_asset_store import PaidMediaAssetStore
from gateway.paid_media_operator_receipts import PaidMediaOperatorReceiptStore
from gateway.paid_media_operator_recovery import (
    PaidMediaOperatorRecoveryError,
    PaidMediaOperatorRecoveryService,
)
from gateway.paid_media_web import PaidMediaWebLedger
from gateway.paid_media_web_archive import PaidMediaWebAssetArchive


_MEDIA_SCHEMA = "nachuan.media-binaries.v1"
_MEDIA_KEYS = {
    "schema",
    "ffmpeg_bin",
    "ffmpeg_sha256",
    "ffprobe_bin",
    "ffprobe_sha256",
}
_MEDIA_ENV = {
    "FFMPEG_BIN": "ffmpeg_bin",
    "FFMPEG_SHA256": "ffmpeg_sha256",
    "FFPROBE_BIN": "ffprobe_bin",
    "FFPROBE_SHA256": "ffprobe_sha256",
}
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


class PaidMediaOperatorCliError(RuntimeError):
    """Sanitized source-CLI recovery failure."""


def _assert_local_admin_owner(data_dir: Path) -> None:
    if not windows_process_is_elevated():
        raise PaidMediaOperatorCliError(
            "本机管理员权限不可用；prepared 恢复已拒绝。"
        )
    try:
        load_local_owner_credentials(data_dir)
        load_local_paid_media_capability(data_dir)
    except (
        FileNotFoundError,
        LocalOwnerCredentialError,
        LocalPaidMediaCapabilityError,
    ) as exc:
        raise PaidMediaOperatorCliError(
            "本机 DPAPI owner 或稳定付费能力不可用；prepared 恢复已拒绝。"
        ) from exc


def _recipient_principal(data_dir: Path) -> str:
    _assert_local_admin_owner(data_dir)
    try:
        capability = load_local_paid_media_capability(data_dir)
        return hash_media_principal(capability.key)
    except (
        FileNotFoundError,
        LocalPaidMediaCapabilityError,
        ValueError,
    ) as exc:
        raise PaidMediaOperatorCliError(
            "本机稳定付费能力不可用；prepared 恢复已拒绝。"
        ) from exc


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    return digest.hexdigest()
                digest.update(chunk)
    except OSError as exc:
        raise PaidMediaOperatorCliError(
            "受信媒体程序不可用；prepared 恢复未执行。"
        ) from exc


def _load_media_config(path: Path) -> dict[str, str]:
    try:
        raw = path.read_bytes()
        if not 1 <= len(raw) <= 16 * 1024:
            raise ValueError("media config size")
        payload = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise PaidMediaOperatorCliError(
            "媒体程序证明文件无效；prepared 恢复未执行。"
        ) from exc
    if (
        not isinstance(payload, dict)
        or set(payload) != _MEDIA_KEYS
        or payload.get("schema") != _MEDIA_SCHEMA
    ):
        raise PaidMediaOperatorCliError(
            "媒体程序证明文件无效；prepared 恢复未执行。"
        )
    result: dict[str, str] = {}
    for env_name, config_name in _MEDIA_ENV.items():
        value = payload.get(config_name)
        if not isinstance(value, str) or not value:
            raise PaidMediaOperatorCliError(
                "媒体程序证明文件无效；prepared 恢复未执行。"
            )
        if config_name.endswith("_bin"):
            binary = Path(value)
            try:
                if (
                    not binary.is_absolute()
                    or not binary.is_file()
                    or binary.is_symlink()
                ):
                    raise OSError("media binary identity")
            except OSError as exc:
                raise PaidMediaOperatorCliError(
                    "受信媒体程序不可用；prepared 恢复未执行。"
                ) from exc
            result[env_name] = str(binary)
        elif _DIGEST_RE.fullmatch(value) is None:
            raise PaidMediaOperatorCliError(
                "媒体程序证明文件无效；prepared 恢复未执行。"
            )
        else:
            result[env_name] = value
    for binary_name, digest_name in (
        ("FFMPEG_BIN", "FFMPEG_SHA256"),
        ("FFPROBE_BIN", "FFPROBE_SHA256"),
    ):
        if not hmac_compare_digest(
            _sha256_file(Path(result[binary_name])),
            result[digest_name],
        ):
            raise PaidMediaOperatorCliError(
                "受信媒体程序摘要不匹配；prepared 恢复未执行。"
            )
    return result


def hmac_compare_digest(left: str, right: str) -> bool:
    # Kept local so callers/tests never need either secret-bearing hmac module
    # or an environment value in diagnostic output.
    import hmac

    return hmac.compare_digest(left, right)


@contextmanager
def _media_environment(
    media_config_path: Path | None,
) -> Iterator[None]:
    if media_config_path is None:
        yield
        return
    overlay = _load_media_config(media_config_path)
    before: Mapping[str, str | None] = {
        name: os.environ.get(name) for name in _MEDIA_ENV
    }
    try:
        os.environ.update(overlay)
        yield
    finally:
        for name, value in before.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


@contextmanager
def _service(data_dir: Path) -> Iterator[PaidMediaOperatorRecoveryService]:
    resolved = data_dir.expanduser().resolve(strict=True)
    _assert_local_admin_owner(resolved)
    installation_id = hashlib.sha256(
        b"nachuan-paid-media-development-installation-v1\x00"
        + str(resolved).encode("utf-8")
    ).hexdigest()
    requests: DurableMediaRequestStore | None = None
    assets: PaidMediaAssetStore | None = None
    web: PaidMediaWebLedger | None = None
    archive: PaidMediaWebAssetArchive | None = None
    try:
        requests = DurableMediaRequestStore(resolved / "paid_media_requests.db")
        assets = PaidMediaAssetStore.open_bound(
            resolved / "paid-media-assets",
            installation_id=installation_id,
            epoch=1,
        )
        web = PaidMediaWebLedger(resolved / "paid_media_web_operations.db")
        archive = PaidMediaWebAssetArchive(
            resolved / "paid-media-web-archive"
        )
        receipts = PaidMediaOperatorReceiptStore(
            resolved / "paid_media_operator_recovery.db"
        )
        yield PaidMediaOperatorRecoveryService(
            web_ledger=web,
            media_requests=requests,
            asset_store=assets,
            web_archive=archive,
            receipt_store=receipts,
            installation_id=installation_id,
            installation_epoch=1,
            assert_local_owner=lambda: _assert_local_admin_owner(resolved),
        )
    except PaidMediaOperatorCliError:
        raise
    except Exception as exc:
        raise PaidMediaOperatorCliError(
            "prepared 恢复权威不可用；请先关闭正在使用该 DATA_DIR 的引擎。"
        ) from exc
    finally:
        for resource in (archive, web, assets, requests):
            if resource is not None:
                try:
                    resource.close()
                except Exception:
                    pass


def inspect_prepared_video(
    *,
    data_dir: Path,
    operation_id: str,
) -> dict[str, object]:
    recipient = _recipient_principal(data_dir)
    try:
        with _service(data_dir) as service:
            return service.inspect(
                operation_id=operation_id,
                recipient_principal_hash=recipient,
            ).public_document()
    except PaidMediaOperatorRecoveryError as exc:
        raise PaidMediaOperatorCliError(str(exc)) from exc


async def execute_prepared_video(
    *,
    data_dir: Path,
    operation_id: str,
    decision_id: str,
    confirmation: str,
    media_config_path: Path | None,
) -> dict[str, object]:
    recipient = _recipient_principal(data_dir)
    try:
        with _media_environment(media_config_path):
            with _service(data_dir) as service:
                return (
                    await service.execute(
                        operation_id=operation_id,
                        decision_id=decision_id,
                        confirmation=confirmation,
                        recipient_principal_hash=recipient,
                    )
                ).public_document()
    except PaidMediaOperatorRecoveryError as exc:
        raise PaidMediaOperatorCliError(str(exc)) from exc
