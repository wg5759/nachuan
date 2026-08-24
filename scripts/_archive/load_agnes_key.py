"""从 docx 安全提取「第二个聚合大模型」标注的 Agnes key，更新连接并测试。

只输出掩码，不明文打印任何 key（保护文档里的其它密钥）。
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
ENGINE = "http://127.0.0.1:8080"


def _lines() -> list[str]:
    with zipfile.ZipFile(DOCX) as z:
        xml = z.read("word/document.xml").decode("utf-8", "ignore")
    out: list[str] = []
    for para in xml.split("</w:p>"):
        txt = "".join(re.findall(r"<w:t[^>]*>(.*?)</w:t>", para, re.S))
        if txt.strip():
            out.append(txt.strip())
    return out


def _mask(k: str) -> str:
    return f"{k[:6]}…{k[-4:]} (len {len(k)})" if len(k) > 10 else "****"


def main() -> int:
    lines = _lines()
    idx = next((i for i, l in enumerate(lines) if "第二个聚合大模型" in l or "聚合大模型" in l), None)
    if idx is None:
        print("未找到『第二个聚合大模型』标注")
        return 1
    # 优先取标注同一行上的 key（避免抓到相邻行别的 key）
    m = re.search(r"sk-[A-Za-z0-9_\-]{16,}", lines[idx])
    if not m:
        window = " ".join(lines[max(0, idx - 1) : idx + 2])
        m = re.search(r"sk-[A-Za-z0-9_\-]{16,}", window)
    if not m:
        print("找到标注但附近无 sk- key。附近内容（key 已掩码）：")
        for j in range(max(0, idx - 3), min(len(lines), idx + 4)):
            print("  ", re.sub(r"sk-[A-Za-z0-9_\-]{16,}", lambda x: _mask(x.group()), lines[j])[:90])
        return 1
    key = m.group(0)
    print("提取到 Agnes key:", _mask(key))

    body = json.dumps(
        {
            "type": "openai_compat",
            "api_key": key,
            "base_url": "https://api.agnes-ai.com/api/v1",
            "enabled_models": [
                {"id": "agnes-flash", "upstream_model": "Agnes-2.0-Flash", "tier": "free", "description": "Agnes 2.0 Flash"}
            ],
        }
    ).encode()
    req = urllib.request.Request(
        f"{ENGINE}/admin/connections/agnes", data=body, method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        print("连接已更新:", r.read().decode())

    test = json.dumps(
        {"model": "agnes-flash", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 10}
    ).encode()
    treq = urllib.request.Request(
        f"{ENGINE}/v1/chat/completions", data=test, method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(treq, timeout=40) as r:
            print("✅ Agnes 测试成功:", r.read().decode("utf-8")[:200])
    except urllib.error.HTTPError as e:
        print("❌ Agnes 仍失败:", e.read().decode("utf-8")[:200])
    except Exception as e:  # noqa: BLE001
        print("❌ Agnes 测试异常:", str(e)[:200])
    return 0


if __name__ == "__main__":
    sys.exit(main())
