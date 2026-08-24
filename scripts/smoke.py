"""冒烟测试：对已启动的网关做 health / models / echo(非流式+流式) 验证。

用法（网关已在运行时）：
    python scripts/smoke.py
环境变量 GATEWAY_URL / GATEWAY_KEY 可覆盖默认地址与 Key。
仅用标准库，无需额外依赖。
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.request

# Windows 控制台可能是 GBK 编码，强制 stdout 用 UTF-8，避免打印中文/emoji 报错
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

BASE = os.environ.get("GATEWAY_URL", "http://127.0.0.1:8080")
KEY = os.environ.get("GATEWAY_KEY", "sk-local-dev-changeme")
AUTH = {"Authorization": f"Bearer {KEY}", "Content-Type": "application/json"}


def _open(path: str, method: str = "GET", body: dict | None = None, headers: dict | None = None):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method, headers=headers or {})
    return urllib.request.urlopen(req, timeout=30)


def wait_ready(tries: int = 40, delay: float = 0.5) -> bool:
    for _ in range(tries):
        try:
            with _open("/health") as resp:
                if resp.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(delay)  # Python 级 sleep（非 shell sleep）
    return False


def main() -> int:
    if not wait_ready():
        print("FAIL: 网关未就绪")
        return 1
    print("OK  /health")

    with _open("/v1/models", headers=AUTH) as resp:
        ids = [m["id"] for m in json.loads(resp.read())["data"]]
    print("OK  /v1/models ->", ids)
    assert "echo" in ids, "echo 模型缺失"

    # 非流式
    with _open(
        "/v1/chat/completions",
        "POST",
        {"model": "echo", "messages": [{"role": "user", "content": "你好，世界"}]},
        AUTH,
    ) as resp:
        content = json.loads(resp.read())["choices"][0]["message"]["content"]
    print("OK  chat(non-stream) ->", content)
    assert "你好，世界" in content

    # 流式
    with _open(
        "/v1/chat/completions",
        "POST",
        {"model": "echo", "messages": [{"role": "user", "content": "stream please"}], "stream": True},
        AUTH,
    ) as resp:
        raw = resp.read().decode("utf-8")
    assert "data:" in raw and "[DONE]" in raw, "流式响应格式异常"
    print(f"OK  chat(stream) -> {len(raw)} bytes, [DONE] present")

    print("\nALL SMOKE CHECKS PASSED ✅")
    return 0


if __name__ == "__main__":
    sys.exit(main())
