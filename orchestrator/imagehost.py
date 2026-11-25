"""图床（私有桶 + 短期 Signed URL）：把视频衔接帧传到 Supabase Storage 私有桶，签发短期签名链接。

安全策略（P0-3）：
1. 默认私有桶（public=false）+ 短期 Signed URL（`/storage/v1/object/sign/...`，默认 600s，
   可通过 IMAGEHOST_SIGNED_URL_TTL 在 60~3600s 间配置），不再拼接或暴露无鉴权 `/object/public/` URL；
2. 严格尊重无痕隐私模式（incognito=True）与纯离线模式（offline_only=True / NACHUAN_OFFLINE_MODE=1 /
   IMAGEHOST_DISABLE=1 / 仅配置本地模型），离线/无痕状态下强制拒绝外传图床；
3. 上传后签发失败立即尝试回滚删除对象，避免孤儿文件滞留云端；
4. `delete_by_url` 显式重试并记录脱敏日志告警，返回结构化回执（不再静默吞错）。
"""

from __future__ import annotations

import logging
import os
import uuid
from typing import Any
from urllib.parse import urlsplit

from gateway.outbound_guard import (
    OfflineModeBlockedError,
    check_outbound_allowed,
    create_sync_client,
    is_offline_mode,
)

_LOG = logging.getLogger(__name__)
_BUCKET = os.getenv("IMAGEHOST_BUCKET", "studio-frames")
_MIN_SIGNED_TTL_SEC = 60
_MAX_SIGNED_TTL_SEC = 3600
_DEFAULT_SIGNED_TTL_SEC = 600


def _bucket_name() -> str:
    return (os.getenv("IMAGEHOST_BUCKET") or _BUCKET or "studio-frames").strip()


def _signed_url_ttl(expires_in: int | None = None) -> int:
    raw = expires_in if expires_in is not None else os.getenv("IMAGEHOST_SIGNED_URL_TTL", str(_DEFAULT_SIGNED_TTL_SEC))
    try:
        value = int(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        value = _DEFAULT_SIGNED_TTL_SEC
    return max(_MIN_SIGNED_TTL_SEC, min(_MAX_SIGNED_TTL_SEC, value))


def _is_blocked_by_privacy_or_offline(
    *,
    incognito: bool = False,
    offline_only: bool = False,
    router: Any = None,
) -> bool:
    if incognito or offline_only:
        return True
    if os.getenv("IMAGEHOST_DISABLE", "").strip().lower() in {"1", "true", "yes", "on"}:
        return True
    if os.getenv("NACHUAN_OFFLINE_MODE", "").strip().lower() in {"1", "true", "yes", "on"}:
        return True
    if router is not None:
        try:
            from gateway.privacy import is_offline_only_router

            if is_offline_only_router(router):
                return True
        except Exception:  # noqa: BLE001
            pass
    return False


def _sanitize_ext(ext: str) -> str:
    cleaned = "".join(ch for ch in str(ext or "png").lower() if ch.isalnum())
    return cleaned if cleaned in {"png", "jpg", "jpeg", "webp", "gif"} else "png"


def _join_signed_url(base_url: str, signed_path: str) -> str:
    root = base_url.rstrip("/")
    candidate = (signed_path or "").strip()
    if not candidate:
        return ""
    if candidate.startswith(("https://", "http://")):
        return candidate
    if candidate.startswith("/storage/v1/"):
        return f"{root}{candidate}"
    if candidate.startswith("/"):
        return f"{root}/storage/v1{candidate}"
    return f"{root}/storage/v1/{candidate}"


def _extract_object_path(object_url: str, bucket: str) -> str:
    """从 Signed URL（或历史 public URL）中提取对象相对路径，剥离 token 查询参数并防穿越。"""
    if not object_url:
        return ""
    try:
        parsed_path = urlsplit(object_url).path
    except ValueError:
        return ""
    markers = (
        f"/storage/v1/object/sign/{bucket}/",
        f"/object/sign/{bucket}/",
        f"/storage/v1/object/authenticated/{bucket}/",
        f"/object/authenticated/{bucket}/",
        f"/storage/v1/object/public/{bucket}/",
        f"/object/public/{bucket}/",
    )
    rel = ""
    for marker in markers:
        if marker in parsed_path:
            rel = parsed_path.split(marker, 1)[-1].lstrip("/")
            break
    if not rel or ".." in rel.split("/") or rel.startswith("/"):
        return ""
    return rel


def available(*, incognito: bool = False, offline_only: bool = False, router: Any = None) -> bool:
    """图床是否就绪（允许外联 + Supabase 配置 + 登录态齐）。不抛异常。"""
    if _is_blocked_by_privacy_or_offline(
        incognito=incognito, offline_only=offline_only, router=router
    ):
        return False
    try:
        from orchestrator import cloud_sync

        cfg = cloud_sync.load_cfg()
        return bool(cfg.get("url") and cfg.get("anon_key") and cfg.get("access_token"))
    except Exception:  # noqa: BLE001
        return False


def _delete_object_path(
    *,
    url: str,
    anon: str,
    token: str,
    bucket: str,
    path: str,
    retries: int = 2,
) -> dict[str, Any]:
    import httpx

    attempts = 0
    max_attempts = max(1, int(retries) + 1)
    last_status: int | None = None
    last_error = ""
    target = f"{url.rstrip('/')}/storage/v1/object/{bucket}/{path}"
    headers = {"apikey": anon, "Authorization": f"Bearer {token}"}

    for attempts in range(1, max_attempts + 1):
        try:
            check_outbound_allowed(
                target,
                caller="orchestrator.imagehost:_delete_object_path",
                method="DELETE",
            )
            with create_sync_client(
                caller="orchestrator.imagehost:_delete_object_path",
                timeout=15.0,
            ) as client:
                resp = client.delete(target, headers=headers)
            last_status = resp.status_code
            if resp.status_code in (200, 204, 404):
                return {
                    "ok": True,
                    "path": path,
                    "status_code": resp.status_code,
                    "attempts": attempts,
                    "error": "",
                }
            last_error = f"http_{resp.status_code}"
            _LOG.warning(
                "imagehost delete failed (bucket=%s path=%s status=%s attempt=%d/%d)",
                bucket,
                path,
                resp.status_code,
                attempts,
                max_attempts,
            )
        except OfflineModeBlockedError:
            raise
        except Exception as exc:  # noqa: BLE001
            last_error = type(exc).__name__
            _LOG.warning(
                "imagehost delete exception (bucket=%s path=%s error=%s attempt=%d/%d)",
                bucket,
                path,
                last_error,
                attempts,
                max_attempts,
            )

    _LOG.error(
        "imagehost cleanup exhausted retries; object may remain in storage (bucket=%s path=%s status=%s error=%s)",
        bucket,
        path,
        last_status,
        last_error,
    )
    return {
        "ok": False,
        "path": path,
        "status_code": last_status,
        "attempts": attempts,
        "error": last_error or "delete_failed",
    }


def upload_image(
    data: bytes,
    ext: str = "png",
    *,
    expires_in: int | None = None,
    incognito: bool = False,
    offline_only: bool = False,
    router: Any = None,
) -> str:
    """上传图片字节到 Supabase Storage 私有桶，签发短期 Signed URL；失败或离线拦截返回 ''。"""
    if not data:
        return ""
    if _is_blocked_by_privacy_or_offline(
        incognito=incognito, offline_only=offline_only, router=router
    ):
        _LOG.info("imagehost upload skipped: blocked by incognito/offline policy")
        return ""
    if is_offline_mode():
        target_for_audit = f"https://supabase.co/storage/v1/object/{_bucket_name()}/"
        try:
            from orchestrator import cloud_sync

            cfg = cloud_sync.load_cfg()
            if cfg.get("url"):
                target_for_audit = f"{str(cfg['url']).rstrip('/')}/storage/v1/object/{_bucket_name()}/"
        except Exception:  # noqa: BLE001
            pass
        check_outbound_allowed(
            target_for_audit,
            caller="orchestrator.imagehost:upload_image",
            method="POST",
        )
    try:
        from orchestrator import cloud_sync

        cfg = cloud_sync.load_cfg()
        url, anon, token = cfg.get("url"), cfg.get("anon_key"), cfg.get("access_token")
        if not url or not anon or not token:
            return ""

        bucket = _bucket_name()
        safe_ext = _sanitize_ext(ext)
        ttl = _signed_url_ttl(expires_in)
        path = f"{uuid.uuid4().hex}.{safe_ext}"
        root = str(url).rstrip("/")
        auth_headers = {
            "apikey": anon,
            "Authorization": f"Bearer {token}",
        }
        upload_url = f"{root}/storage/v1/object/{bucket}/{path}"
        sign_url = f"{root}/storage/v1/object/sign/{bucket}/{path}"
        check_outbound_allowed(
            upload_url,
            caller="orchestrator.imagehost:upload_image",
            method="POST",
        )
        with create_sync_client(
            caller="orchestrator.imagehost:upload_image",
            timeout=30.0,
        ) as client:
            upload_resp = client.post(
                upload_url,
                headers={
                    **auth_headers,
                    "Content-Type": f"image/{safe_ext}",
                },
                content=data,
            )
            if upload_resp.status_code not in (200, 201):
                _LOG.warning(
                    "imagehost upload rejected (bucket=%s status=%s)",
                    bucket,
                    upload_resp.status_code,
                )
                return ""
            sign_resp = client.post(
                sign_url,
                headers={
                    **auth_headers,
                    "Content-Type": "application/json",
                },
                json={"expiresIn": ttl},
            )
        if sign_resp.status_code not in (200, 201):
            _LOG.warning(
                "imagehost sign url failed (bucket=%s path=%s status=%s); cleaning up orphan object",
                bucket,
                path,
                sign_resp.status_code,
            )
            _delete_object_path(url=root, anon=anon, token=token, bucket=bucket, path=path, retries=1)
            return ""
        payload = sign_resp.json() if sign_resp.content else {}
        signed_rel = ""
        if isinstance(payload, dict):
            signed_rel = str(payload.get("signedURL") or payload.get("signedUrl") or "").strip()
        signed_url = _join_signed_url(root, signed_rel)
        if not signed_url or f"/object/public/{bucket}/" in signed_url:
            _LOG.warning(
                "imagehost sign response missing valid signed url (bucket=%s path=%s); cleaning up",
                bucket,
                path,
            )
            _delete_object_path(url=root, anon=anon, token=token, bucket=bucket, path=path, retries=1)
            return ""
        return signed_url
    except OfflineModeBlockedError:
        raise
    except Exception as exc:  # noqa: BLE001
        _LOG.warning("imagehost upload failed (%s)", type(exc).__name__)
        return ""


def delete_by_url(object_url: str, *, retries: int = 2) -> dict[str, Any]:
    """删掉图床里这个 Signed URL（或历史 public URL）对应的对象。

    不再静默吞错：带重试、记录脱敏告警日志，并返回结构化回执 dict。
    """
    bucket = _bucket_name()
    path = _extract_object_path(object_url, bucket)
    if not path:
        if object_url:
            _LOG.warning("imagehost delete ignored unrecognized object url for bucket=%s", bucket)
        return {
            "ok": False,
            "path": "",
            "status_code": None,
            "attempts": 0,
            "error": "invalid_object_url",
        }
    try:
        from orchestrator import cloud_sync

        cfg = cloud_sync.load_cfg()
        url, anon, token = cfg.get("url"), cfg.get("anon_key"), cfg.get("access_token")
        if not url or not anon or not token:
            _LOG.warning(
                "imagehost delete skipped: missing supabase credentials (bucket=%s path=%s)",
                bucket,
                path,
            )
            return {
                "ok": False,
                "path": path,
                "status_code": None,
                "attempts": 0,
                "error": "missing_credentials",
            }
        return _delete_object_path(
            url=str(url),
            anon=str(anon),
            token=str(token),
            bucket=bucket,
            path=path,
            retries=retries,
        )
    except OfflineModeBlockedError:
        raise
    except Exception as exc:  # noqa: BLE001
        err = type(exc).__name__
        _LOG.error(
            "imagehost delete unexpected error (bucket=%s path=%s error=%s)",
            bucket,
            path,
            err,
        )
        return {
            "ok": False,
            "path": path,
            "status_code": None,
            "attempts": 0,
            "error": err,
        }
