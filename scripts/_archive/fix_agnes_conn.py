"""把 agnes 连接改成正确的 apihub base_url + agnes-2.0-flash，并经网关实测。"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
ROOT = Path(__file__).resolve().parent.parent
key = json.loads((ROOT / "data" / "connections.json").read_text("utf-8"))["agnes"]["api_key"]

body = json.dumps(
    {
        "type": "openai_compat",
        "api_key": key,
        "base_url": "https://apihub.agnes-ai.com/v1",
        "enabled_models": [
            {"id": "agnes-flash", "upstream_model": "agnes-2.0-flash", "tier": "free", "description": "Agnes 2.0 Flash · 文本+视觉"}
        ],
    }
).encode()
req = urllib.request.Request(
    "http://127.0.0.1:8080/admin/connections/agnes", data=body, method="POST",
    headers={"Content-Type": "application/json"},
)
with urllib.request.urlopen(req, timeout=15) as r:
    print("连接已更正:", r.read().decode("utf-8"))

test = json.dumps({"model": "agnes-flash", "messages": [{"role": "user", "content": "用一句话自我介绍"}]}).encode()
treq = urllib.request.Request(
    "http://127.0.0.1:8080/v1/chat/completions", data=test, method="POST",
    headers={"Content-Type": "application/json"},
)
try:
    with urllib.request.urlopen(treq, timeout=30) as r:
        d = json.loads(r.read().decode("utf-8"))
        print("✅ 经网关 agnes-flash:", d["choices"][0]["message"]["content"][:150])
except urllib.error.HTTPError as e:
    print("❌", e.code, e.read().decode("utf-8")[:150])
