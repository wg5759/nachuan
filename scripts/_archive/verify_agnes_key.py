"""核验从 docx 提取的 Agnes key 是否完整（非截断），并再测两种 base_url。

只显示长度 + 开头8位 + 结尾6位（够你核对是不是你的完整 key），中间不明文输出。
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

with zipfile.ZipFile(DOCX) as z:
    xml = z.read("word/document.xml").decode("utf-8", "ignore")
lines = [("".join(re.findall(r"<w:t[^>]*>(.*?)</w:t>", p, re.S))).strip() for p in xml.split("</w:p>")]
lines = [l for l in lines if l]

idx = next(i for i, l in enumerate(lines) if "第二个聚合大模型" in l)
m = re.search(r"sk-[A-Za-z0-9_\-]{16,}", lines[idx])
key = m.group(0)

print(f"提取的 key：长度={len(key)} 位")
print(f"  开头8位 = {key[:8]}")
print(f"  结尾6位 = {key[-6:]}")
print(f"  含省略号？= {'…' in key or '...' in key}（False 表示完整、未截断）")
print(f"  全部为合法字符？= {bool(re.fullmatch(r'sk-[A-Za-z0-9_\\-]+', key))}")

print("\n=== 用完整 key 再测 ===")
for base in ["https://api.agnes-ai.com/api/v1", "https://api.agnes-ai.com/v1"]:
    body = json.dumps(
        {"model": "Agnes-2.0-Flash", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 5}
    ).encode()
    req = urllib.request.Request(
        base + "/chat/completions", data=body, method="POST",
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            print(f"[{base}] ✅ {r.read().decode('utf-8')[:150]}")
    except urllib.error.HTTPError as e:
        print(f"[{base}] ❌ {e.code}: {e.read().decode('utf-8')[:150]}")
    except Exception as e:  # noqa: BLE001
        print(f"[{base}] ❌ {str(e)[:120]}")
