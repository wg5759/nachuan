"""矩阵测试：多 base_url × 多鉴权头，定位 Agnes 能用的组合。key 从连接读、不明文打印。"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
key = json.loads((Path(__file__).resolve().parent.parent / "data" / "connections.json").read_text("utf-8"))["agnes"]["api_key"]

BASES = [
    "https://api.agnes-ai.com/api/v1",
    "https://api.agnes-ai.com/v1",
    "https://platform.agnes-ai.com/api/v1",
    "https://agnes-ai.com/api/v1",
    "https://api.agnes-ai.com/openai/v1",
]
AUTHS = [
    ("Bearer", {"Authorization": f"Bearer {key}"}),
    ("raw", {"Authorization": key}),
    ("x-api-key", {"x-api-key": key}),
    ("api-key", {"api-key": key}),
]

for base in BASES:
    for name, h in AUTHS:
        body = json.dumps(
            {"model": "Agnes-2.0-Flash", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 5}
        ).encode()
        req = urllib.request.Request(
            base + "/chat/completions", data=body, method="POST",
            headers={**h, "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                print(f"✅ OK  [{base}] [{name}]: {r.read().decode('utf-8')[:120]}")
        except urllib.error.HTTPError as e:
            print(f"❌ {e.code} [{base}] [{name}]: {e.read().decode('utf-8')[:90]}")
        except Exception as e:  # noqa: BLE001
            print(f"⚠️  [{base}] [{name}]: {str(e)[:60]}")
