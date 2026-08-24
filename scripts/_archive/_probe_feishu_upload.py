"""探针：测试飞书图片上传权限是否就绪（不需公网，直连飞书 API）。

成功→返回 image_key，说明媒体直发可用；失败→打印 code/msg（如缺 im:resource 等权限）。
用法：FEISHU_APP_ID=.. FEISHU_APP_SECRET=.. python scripts/_probe_feishu_upload.py
"""

from __future__ import annotations

import os
import struct
import sys
import zlib
from io import BytesIO

import lark_oapi as lark
from lark_oapi.api.im.v1 import CreateImageRequest, CreateImageRequestBody


def _png_1x1() -> bytes:
    def chunk(tag: bytes, data: bytes) -> bytes:
        body = tag + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
    idat = chunk(b"IDAT", zlib.compress(b"\x00\xff\x00\x00"))
    iend = chunk(b"IEND", b"")
    return sig + ihdr + idat + iend


def main() -> int:
    app_id, secret = os.environ.get("FEISHU_APP_ID", ""), os.environ.get("FEISHU_APP_SECRET", "")
    if not app_id or not secret:
        print("缺 FEISHU_APP_ID / FEISHU_APP_SECRET")
        return 1
    client = lark.Client.builder().app_id(app_id).app_secret(secret).build()
    req = (
        CreateImageRequest.builder()
        .request_body(
            CreateImageRequestBody.builder().image_type("message").image(BytesIO(_png_1x1())).build()
        )
        .build()
    )
    resp = client.im.v1.image.create(req)
    print(f"success={resp.success()} code={resp.code} msg={resp.msg}")
    if resp.success():
        print(f"image_key={resp.data.image_key}")
        print("UPLOAD_OK")
    else:
        print("UPLOAD_FAIL（多半要在飞书后台开 im:resource / 图片上传权限并重发版本）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
