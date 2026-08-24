"""只打印文档里与 Agnes/聚合 相关的行（key 全掩码），用于核对 key 与 base_url。"""

from __future__ import annotations

import re
import sys
import zipfile

sys.stdout.reconfigure(encoding="utf-8")
DOCX = r"E:/公司文件/养生工作流API SKY.docx"


def _mask(s: str) -> str:
    s = re.sub(r"sk-[A-Za-z0-9_\-]{16,}", lambda m: m.group()[:6] + "…" + m.group()[-4:], s)
    return s


with zipfile.ZipFile(DOCX) as z:
    xml = z.read("word/document.xml").decode("utf-8", "ignore")
lines = [("".join(re.findall(r"<w:t[^>]*>(.*?)</w:t>", p, re.S))).strip() for p in xml.split("</w:p>")]
lines = [l for l in lines if l]

hit: set[int] = set()
for i, l in enumerate(lines):
    if re.search(r"agnes|聚合|api\.agnes", l, re.I):
        for j in range(max(0, i - 1), min(len(lines), i + 3)):
            hit.add(j)
for j in sorted(hit):
    print(f"[{j}] {_mask(lines[j])[:140]}")
