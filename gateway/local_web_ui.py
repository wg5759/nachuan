"""本地 Web UI 静态托管（ADR-0013：CLI + 本地 Web 分发形态）。

网关在未打包/源码形态下可直接托管 Web UI 构建产物，替代 Electron 壳成为
主交互界面。安全闭集：

- 仅 GET/HEAD；未配置或目录无效时不挂载（fail-closed，网关照常工作）；
- 严格根内路径：拒绝 ``..`` 穿越、反斜杠变形、NUL、Windows 设备名、
  任意层级 symlink 与超过 ``_MAX_FILE_BYTES`` 的文件；
- ``/v1`` ``/admin`` ``/internal`` 保留前缀永不 SPA fallback；
- 带扩展名的缺失资源返回 404，不冒充 index.html；
- 全部响应 ``Cache-Control: no-store`` + ``X-Content-Type-Options: nosniff``。

目录来源：``mount_local_web_ui`` 显式参数、环境变量 ``NACHUAN_WEB_UI_DIR``，
二者均未提供时使用 wheel 内 ``gateway/web_ui``。
"""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, Response

_WEB_UI_DIR_ENV = "NACHUAN_WEB_UI_DIR"
_BUNDLED_WEB_UI_DIR = Path(__file__).resolve().parent / "web_ui"
_MAX_FILE_BYTES = 32 * 1024 * 1024
_INDEX = "index.html"

# 网关 API 前缀：这些路径下未命中的请求必须是 404，不能吞进 SPA。
_RESERVED_PREFIXES = frozenset({"v1", "admin", "internal"})

# Windows 设备名：stat/open 可能阻塞或行为异常，直接闭集拒绝。
_WINDOWS_DEVICE_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{i}" for i in range(1, 10)}
    | {f"LPT{i}" for i in range(1, 10)}
)

# 不依赖 Windows 注册表的确定性 content-type（mimetypes 在本机可能被改）。
_CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".htm": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".mjs": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".map": "application/json; charset=utf-8",
    ".webmanifest": "application/manifest+json",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".ico": "image/x-icon",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".ttf": "font/ttf",
    ".txt": "text/plain; charset=utf-8",
    ".mp4": "video/mp4",
    ".webm": "video/webm",
    ".wasm": "application/wasm",
}

_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}


def resolve_web_ui_dir(raw: str | os.PathLike[str] | None) -> Path | None:
    """返回可挂载的 UI 目录；无外置覆盖时使用包内 UI。"""

    value: str | os.PathLike[str]
    if raw is not None:
        value = raw
    else:
        configured = os.environ.get(_WEB_UI_DIR_ENV)
        value = _BUNDLED_WEB_UI_DIR if configured is None else configured
    if isinstance(value, str):
        value = value.strip()
        if not value:
            return None
    try:
        candidate = Path(value)
        if not candidate.is_dir():
            return None
        resolved = candidate.resolve()
        if not (resolved / _INDEX).is_file():
            return None
    except OSError:
        return None
    return resolved


def _split_parts(rel: str) -> list[str] | None:
    """把请求路径切成安全片段；任何穿越/非法形态返回 None。"""

    if "\x00" in rel:
        return None
    parts: list[str] = []
    for piece in rel.replace("\\", "/").split("/"):
        if piece in ("", "."):
            continue
        if piece == "..":
            return None
        stem = piece.split(".")[0].upper()
        if stem in _WINDOWS_DEVICE_NAMES:
            return None
        parts.append(piece)
    return parts


def _resolve_file(root: Path, rel: str) -> Path | None:
    """解析到根内真实文件；不存在/越界/symlink/超限返回 None。

    单 owner localhost 形态下接受 lstat 与 open 之间的残余 TOCTOU 窗口；
    该窗口的恶意利用需要同 SID 写 UI 目录的能力，与 CLI 威胁模型一致（ADR-0013）。
    """

    parts = _split_parts(rel)
    if not parts:
        return None
    current = root
    for part in parts:
        current = current / part
        try:
            if current.is_symlink():
                return None
        except OSError:
            return None
    try:
        resolved = current.resolve()
    except OSError:
        return None
    if resolved != root and root not in resolved.parents:
        return None
    try:
        stat = resolved.stat()
    except OSError:
        return None
    if not resolved.is_file():
        return None
    if stat.st_size > _MAX_FILE_BYTES:
        return None
    return resolved


def _serve(root: Path, rel: str) -> Response:
    parts = _split_parts(rel)
    if parts is None:
        # 穿越/非法形态永不落进 SPA fallback。
        raise HTTPException(status_code=404, detail="Not Found")
    target = _resolve_file(root, rel)
    if target is None:
        first = parts[0] if parts else None
        if first in _RESERVED_PREFIXES:
            raise HTTPException(status_code=404, detail="Not Found")
        # 带扩展名的请求视为静态资源，缺失即 404，不用 index.html 冒充。
        last = parts[-1] if parts else ""
        if not rel or ("." not in last):
            target = _resolve_file(root, _INDEX)
            if target is None:
                raise HTTPException(status_code=404, detail="Not Found")
        else:
            raise HTTPException(status_code=404, detail="Not Found")
    media_type = _CONTENT_TYPES.get(target.suffix.lower(), "application/octet-stream")
    return FileResponse(target, media_type=media_type, headers=_HEADERS)


def mount_local_web_ui(
    app: FastAPI, *, directory: str | os.PathLike[str] | None = None
) -> bool:
    """把本地 Web UI 挂到 ``/{full_path:path}``；目录无效则不挂载并返回 False。

    必须在全部 API 路由注册之后调用（catch-all 最后注册）。
    """

    root = resolve_web_ui_dir(directory)
    if root is None:
        return False

    @app.api_route(
        "/{full_path:path}", methods=["GET", "HEAD"], include_in_schema=False
    )
    async def _local_web_ui(full_path: str) -> Response:
        return _serve(root, full_path)

    return True


__all__ = ["mount_local_web_ui", "resolve_web_ui_dir"]
