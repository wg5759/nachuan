"""深度跑：实测引擎各端点真实状态（#14，临时诊断脚本）。"""
import json
import sys
import urllib.error
import urllib.request

try:
    sys.stdout.reconfigure(encoding="utf-8")  # Windows 控制台 GBK 会被 emoji 噎死
except Exception:  # noqa: BLE001
    pass

BASE = "http://127.0.0.1:8080"
H = {"Authorization": "Bearer sk-local-dev-changeme", "Content-Type": "application/json"}


def call(path, body=None, timeout=90):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        BASE + path, data=data, headers=H, method="POST" if body is not None else "GET"
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:200]
    except Exception as e:  # noqa: BLE001
        return -1, str(e)[:200]


def chat(model, content, **kw):
    st, d = call("/v1/chat/completions", {"model": model, "messages": [{"role": "user", "content": content}], **kw})
    if isinstance(d, dict):
        msg = (d.get("choices") or [{}])[0].get("message", {}).get("content", "")
        return st, (msg[:90] if msg else json.dumps(d, ensure_ascii=False)[:160])
    return st, str(d)[:160]


print("=== /v1/models ===")
st, d = call("/v1/models")
ids = [m["id"] for m in d.get("data", [])] if isinstance(d, dict) else []
print("status", st, "count", len(ids))
print(
    "echo_hidden=",
    "echo" not in ids,
    "| disabled_claude_hidden=",
    all("claude" not in str(model_id).casefold() for model_id in ids),
)
print("ids:", ids)

print("\n=== echo (联通) ===")
print(chat("echo", "ping"))

print("\n=== agnes-flash (真实·文本) ===")
print(chat("agnes-flash", "只回一个字：好"))

print("\n=== glm (火山·真实) ===")
print(chat("glm", "只回一个字：好"))

print("\n=== gpt-5.5 (codex CLI) ===")
print(chat("gpt-5.5", "只回一个字：好"))

print("\n=== /v1/agent/chat (意图分发·普通对话) ===")
st, d = call("/v1/agent/chat", {"message": "你好你是谁", "chat_id": "t1", "user_id": "owner"})
print("status", st, "reply=", (d.get("reply", "")[:80] if isinstance(d, dict) else str(d)[:120]))

print("\n=== /v1/agent/chat (意图·画图) ===")
st, d = call("/v1/agent/chat", {"message": "画一只猫", "chat_id": "t2", "user_id": "owner"}, timeout=120)
print("status", st, "reply=", (d.get("reply", "")[:120] if isinstance(d, dict) else str(d)[:160]))

print("\n=== /v1/sync/status ===")
print(call("/v1/sync/status"))

print("\n=== /v1/lapian/url (抖音分享口令文本·验证引擎抠不抠链接) ===")
share = "5.89 复制打开抖音，看看【自称嘉豪的作品】真心推荐 https://v.douyin.com/WGLStaiKxX4/ kcN:/ w@F.hB"
st, d = call("/v1/lapian/url", {"url": share}, timeout=30)
print("status", st, "->", str(d)[:160])
