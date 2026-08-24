"""后台轮询 Agnes key 是否激活；激活后退出 0（供 run_in_background，激活即通知）。

从 data/connections.json 读取已保存的 agnes 连接（避免在命令行再暴露 key）。
每 5 分钟探一次，最多约 8 小时。
"""

from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

CONN = Path(__file__).resolve().parent.parent / "data" / "connections.json"


def _agnes() -> tuple[str, str]:
    d = json.loads(CONN.read_text("utf-8"))
    a = d.get("agnes", {})
    return a.get("api_key", ""), a.get("base_url", "https://api.agnes-ai.com/api/v1")


def _check(key: str, base: str) -> tuple[bool, str]:
    body = json.dumps(
        {"model": "Agnes-2.0-Flash", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 5}
    ).encode("utf-8")
    req = urllib.request.Request(
        base.rstrip("/") + "/chat/completions",
        data=body,
        method="POST",
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            text = r.read().decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        text = e.read().decode("utf-8", "ignore")
    except Exception as e:  # noqa: BLE001
        return False, str(e)[:160]
    # 激活成功的标志：返回里有 choices，且没有 Agnes 的错误码/文案
    bad = ("invalid or expired" in text) or ("route not found" in text) or ('"choices"' not in text)
    return (not bad), text[:200]


def main() -> int:
    key, base = _agnes()
    if not key:
        print("no agnes key in store; abort")
        return 2
    for i in range(96):  # ~8 小时
        ok, msg = _check(key, base)
        if ok:
            print(f"AGNES ACTIVATED on attempt {i + 1}: {msg}")
            return 0
        print(f"attempt {i + 1}: still inactive -> {msg[:120]}", flush=True)
        time.sleep(300)
    print("AGNES still inactive after all retries")
    return 1


if __name__ == "__main__":
    sys.exit(main())
