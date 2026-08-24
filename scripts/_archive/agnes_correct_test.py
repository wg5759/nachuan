"""用官方正确配置 (apihub.agnes-ai.com/v1 + agnes-2.0-flash) 测 Agnes。"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
key = json.loads(
    (Path(__file__).resolve().parent.parent / "data" / "connections.json").read_text("utf-8")
)["agnes"]["api_key"]

body = json.dumps(
    {"model": "agnes-2.0-flash", "messages": [{"role": "user", "content": "say hi in 3 words"}], "max_tokens": 20}
).encode()
req = urllib.request.Request(
    "https://apihub.agnes-ai.com/v1/chat/completions",
    data=body, method="POST",
    headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
)
try:
    with urllib.request.urlopen(req, timeout=25) as r:
        print("✅ Agnes 通了:", r.read().decode("utf-8")[:300])
except urllib.error.HTTPError as e:
    print("❌", e.code, e.read().decode("utf-8")[:200])
except Exception as e:  # noqa: BLE001
    print("⚠️", str(e)[:150])
