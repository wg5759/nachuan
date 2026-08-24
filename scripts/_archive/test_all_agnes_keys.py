"""把 docx 里所有 sk- key 用我们的接法(api/v1 + Bearer)各测一遍，看哪些能通。

若 opencode/openclaw 的 key 能通 → 证明接法正确、只是某个 key/账号有问题。
key 只显示首尾掩码。
"""

from __future__ import annotations

import json
import re
import sys
import urllib.error
import urllib.request
import zipfile

sys.stdout.reconfigure(encoding="utf-8")
DOCX = r"E:/公司文件/养生工作流API SKY.docx"
BASE = "https://api.agnes-ai.com/api/v1"

with zipfile.ZipFile(DOCX) as z:
    xml = z.read("word/document.xml").decode("utf-8", "ignore")
lines = [("".join(re.findall(r"<w:t[^>]*>(.*?)</w:t>", p, re.S))).strip() for p in xml.split("</w:p>")]
lines = [l for l in lines if l]

seen: set[str] = set()
for l in lines:
    for m in re.finditer(r"sk-[A-Za-z0-9_\-]{16,}", l):
        key = m.group(0)
        if key in seen:
            continue
        seen.add(key)
        label = re.sub(r"sk-[A-Za-z0-9_\-]{16,}", "sk-…", l).strip()[:42]
        tag = f"{key[:6]}…{key[-4:]}"
        body = json.dumps(
            {"model": "Agnes-2.0-Flash", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 5}
        ).encode()
        req = urllib.request.Request(
            BASE + "/chat/completions", data=body, method="POST",
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                print(f"✅ 通  [{tag}] «{label}»: {r.read().decode('utf-8')[:80]}")
        except urllib.error.HTTPError as e:
            print(f"❌ {e.code} [{tag}] «{label}»: {e.read().decode('utf-8')[:60]}")
        except Exception as e:  # noqa: BLE001
            print(f"⚠️  [{tag}]: {str(e)[:50]}")
