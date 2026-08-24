"""全链路冒烟自检（万无一失）：把所有关键端点真跑一遍，输出 PASS/FAIL 总表。

用法：引擎在 :8080 跑着 → `uv run python scripts/_smoke.py`。
key 默认 sk-local-dev-changeme（本地 dev）。任何一项 FAIL 都会在末尾汇总。
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:  # noqa: BLE001
    pass

BASE = "http://127.0.0.1:8080"
H = {"Authorization": "Bearer sk-local-dev-changeme", "Content-Type": "application/json"}
results: list[tuple[str, bool, str]] = []


def call(path, body=None, timeout=90, raw: bytes | None = None):
    data = raw if raw is not None else (json.dumps(body).encode("utf-8") if body is not None else None)
    req = urllib.request.Request(BASE + path, data=data, headers=H, method="POST" if data else "GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "ignore")[:120]
    except Exception as e:  # noqa: BLE001
        return -1, str(e)[:120]


def check(name: str, cond: bool, detail: str = "") -> None:
    results.append((name, cond, detail))
    print(f"{'✅' if cond else '❌'} {name}{(' — ' + detail) if detail else ''}")


# 1) 模型表：echo 隐藏、opus4.8 在、数量合理
st, d = call("/v1/models")
ids = [m["id"] for m in d.get("data", [])] if isinstance(d, dict) else []
check("/v1/models 可用", st == 200 and len(ids) >= 10, f"{len(ids)} 个")
check("echo 已隐藏", "echo" not in ids)
check("停用的 Claude 未暴露", all("claude" not in str(model_id).casefold() for model_id in ids))

# 2) 各类模型真实可用
for m in ["echo", "agnes-flash", "glm", "gpt-5.5"]:
    st, d = call("/v1/chat/completions", {"model": m, "messages": [{"role": "user", "content": "只回一个字：好"}]})
    ok = st == 200 and isinstance(d, dict) and bool((d.get("choices") or [{}])[0].get("message", {}).get("content"))
    check(f"模型 {m} 可用", ok, "" if ok else str(d)[:80])

# 3) 意图分类（#17）：误触发防护
st, d = call("/v1/intent", {"message": "画饼充饥是什么意思"})
check("意图分类 画饼充饥→chat", st == 200 and d.get("intent") == "chat", str(d))
st, d = call("/v1/intent", {"message": "画一只猫"})
check("意图分类 画一只猫→image", st == 200 and d.get("intent") == "image", str(d))

# 4) agent_chat（#15）：翻译/普通对话
st, d = call("/v1/agent/chat", {"message": "翻译成英文：你好世界", "chat_id": "smoke", "user_id": "owner"})
check("agent 翻译意图", st == 200 and (d.get("agent_route") or {}).get("label") == "translate", str(d.get("reply", ""))[:50])
st, d = call("/v1/agent/chat", {"message": "你好你是谁", "chat_id": "smoke2", "user_id": "owner"})
check("agent 普通对话", st == 200 and bool(d.get("reply")))

# 5) 翻译 / 知识库 / MCP 预设 / 用量 / 同步
st, d = call("/v1/translate", {"text": "hello world", "target": "zh"})
check("/v1/translate", st == 200 and isinstance(d, dict) and bool(d.get("translated")), str(d)[:60])
st, d = call("/v1/kb/query", {"user_id": "owner", "query": "anything"})
check("/v1/kb/query", st == 200 and isinstance(d, dict) and "answer" in d)
st, d = call("/v1/mcp/presets")
check("/v1/mcp/presets", st == 200 and len(d.get("presets", [])) >= 4)
st, d = call("/admin/usage")
check("/admin/usage", st == 200 and isinstance(d, dict) and "models" in d)
st, d = call("/v1/sync/status")
check("/v1/sync/status", st == 200 and isinstance(d, dict))

# 6) 稳健性（#22 #16）：坏请求 → 干净 400
st, _ = call("/v1/intent", raw=b'{"message": "\xb2\xe2"}')  # GBK 非 UTF-8
check("坏编码→400(不 500)", st == 400, f"got {st}")
st, _ = call("/v1/chat/completions", {"model": "does-not-exist", "messages": [{"role": "user", "content": "x"}]})
check("未知模型→404", st == 404, f"got {st}")

# ── 汇总 ──
failed = [n for n, ok, _ in results if not ok]
print("\n" + "=" * 50)
print(f"总计 {len(results)} 项，PASS {len(results) - len(failed)}，FAIL {len(failed)}")
if failed:
    print("失败项：" + "、".join(failed))
    sys.exit(1)
print("🎉 全链路冒烟全部通过")
