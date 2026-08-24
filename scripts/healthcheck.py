"""快速健康检查：调用网关 /health 与 /v1/models（仅用标准库，无需额外依赖）。

用法（网关已启动时）：
    python scripts/healthcheck.py
可用环境变量 GATEWAY_URL / GATEWAY_KEY 覆盖默认地址与 Key。
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request

BASE = os.environ.get("GATEWAY_URL", "http://127.0.0.1:8080")
KEY = os.environ.get("GATEWAY_KEY", "sk-local-dev-changeme")


def _get(path: str, auth: bool = False):
    req = urllib.request.Request(BASE + path)
    if auth:
        req.add_header("Authorization", f"Bearer {KEY}")
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.status, json.loads(r.read().decode("utf-8"))


def main() -> int:
    try:
        s, h = _get("/health")
        print("health:", s, h)
        s, m = _get("/v1/models", auth=True)
        print("models:", s, [x["id"] for x in m.get("data", [])])
        return 0
    except Exception as e:  # noqa: BLE001
        print("healthcheck failed:", e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
