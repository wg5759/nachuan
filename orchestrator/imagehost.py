"""图床：把图片传到 Supabase Storage 的公开桶，返回公网 URL（视频工作室③像素级衔接用）。

复用 cloud_sync 的 Supabase 配置（机主已登录的 url/anon_key/access_token），不另存密钥。
公开桶里：上传需 RLS policy 允许 authenticated 写、public 读（建桶时一并设，见 scripts/_setup_imagehost.py）。
优雅降级：未配置/未登录/任何异常 → 返回 ''，调用方退回「文字级一致」。
"""

from __future__ import annotations

import os
import uuid

_BUCKET = os.getenv("IMAGEHOST_BUCKET", "studio-frames")


def available() -> bool:
    """图床是否就绪（Supabase 配置 + 登录态齐）。不抛异常。"""
    try:
        from orchestrator import cloud_sync

        cfg = cloud_sync.load_cfg()
        return bool(cfg.get("url") and cfg.get("anon_key") and cfg.get("access_token"))
    except Exception:  # noqa: BLE001
        return False


def upload_image(data: bytes, ext: str = "png") -> str:
    """上传图片字节到 Supabase Storage 公开桶，返回公网 URL；失败返回 ''（安全降级）。"""
    if not data:
        return ""
    try:
        from orchestrator import cloud_sync

        cfg = cloud_sync.load_cfg()
        url, anon, token = cfg.get("url"), cfg.get("anon_key"), cfg.get("access_token")
        if not url or not anon or not token:
            return ""
        import httpx

        path = f"{uuid.uuid4().hex}.{ext}"
        with httpx.Client(timeout=30.0) as c:
            r = c.post(
                f"{url}/storage/v1/object/{_BUCKET}/{path}",
                headers={
                    "apikey": anon,
                    "Authorization": f"Bearer {token}",
                    "Content-Type": f"image/{ext}",
                },
                content=data,
            )
        if r.status_code not in (200, 201):
            return ""
        return f"{url}/storage/v1/object/public/{_BUCKET}/{path}"  # 公开桶公网读取 URL
    except Exception:  # noqa: BLE001
        return ""


def delete_by_url(public_url: str) -> None:
    """删掉图床里这个公网 URL 对应的对象（中转帧用完清理；存储不累积）。失败静默。"""
    if not public_url or f"/object/public/{_BUCKET}/" not in public_url:
        return
    try:
        from orchestrator import cloud_sync

        cfg = cloud_sync.load_cfg()
        url, anon, token = cfg.get("url"), cfg.get("anon_key"), cfg.get("access_token")
        if not url or not token:
            return
        path = public_url.split(f"/object/public/{_BUCKET}/", 1)[-1]
        import httpx

        with httpx.Client(timeout=15.0) as c:
            c.delete(
                f"{url}/storage/v1/object/{_BUCKET}/{path}",
                headers={"apikey": anon, "Authorization": f"Bearer {token}"},
            )
    except Exception:  # noqa: BLE001
        pass
