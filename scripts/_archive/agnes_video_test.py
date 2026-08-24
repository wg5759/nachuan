"""更新 agnes 连接(含 image/video 三模型) + 创建一个视频任务并轮询一次（实测形状）。"""

from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
ROOT = Path(__file__).resolve().parent.parent
key = json.loads((ROOT / "data" / "connections.json").read_text("utf-8"))["agnes"]["api_key"]
ENG = "http://127.0.0.1:8080"


def _post(path, payload, timeout=60):
    req = urllib.request.Request(
        ENG + path, data=json.dumps(payload).encode(), method="POST",
        headers={"Content-Type": "application/json"},
    )
    return urllib.request.urlopen(req, timeout=timeout)


# 1. 更新连接含 3 个模型
with _post("/admin/connections/agnes", {
    "type": "openai_compat", "api_key": key, "base_url": "https://apihub.agnes-ai.com/v1",
    "enabled_models": [
        {"id": "agnes-flash", "upstream_model": "agnes-2.0-flash", "tier": "free", "description": "Agnes 2.0 Flash", "modality": "chat"},
        {"id": "agnes-image", "upstream_model": "agnes-image-2.1-flash", "tier": "free", "description": "Agnes 生图", "modality": "image"},
        {"id": "agnes-video", "upstream_model": "agnes-video-v2.0", "tier": "free", "description": "Agnes 生视频", "modality": "video"},
    ],
}, timeout=15) as r:
    print("连接更新:", r.read().decode("utf-8"))

# 2. 创建视频任务
try:
    with _post("/v1/videos/generations", {
        "model": "agnes-video", "prompt": "A cute cat walking on the beach at sunset",
        "num_frames": 121, "frame_rate": 24,
    }, timeout=90) as r:
        created = json.loads(r.read().decode("utf-8"))
    print("✅ 创建任务:", json.dumps(created, ensure_ascii=False)[:250])
except urllib.error.HTTPError as e:
    print("❌ 创建失败:", e.code, e.read().decode("utf-8")[:250])
    sys.exit(0)

# 3. 找 task_id 轮询一次
tid = created.get("task_id") or created.get("id") or (created.get("data") or {}).get("task_id")
if not tid:
    print("⚠️ 创建响应里没直接找到 task_id，完整响应:", json.dumps(created, ensure_ascii=False)[:400])
    sys.exit(0)
time.sleep(3)
try:
    with urllib.request.urlopen(f"{ENG}/v1/videos/{tid}?model=agnes-video", timeout=30) as r:
        print("✅ 轮询:", json.dumps(json.loads(r.read().decode("utf-8")), ensure_ascii=False)[:300])
except urllib.error.HTTPError as e:
    print("❌ 轮询失败:", e.code, e.read().decode("utf-8")[:200])
