"""探针：直连引擎生视频端点，打印 Agnes 原始响应，看 task_id/status/url 的真实字段名。

用法：python scripts/_probe_video.py   （引擎需在 :8080 跑）
"""

from __future__ import annotations

import json
import time
import urllib.request

from gateway.config import get_settings

BASE = "http://127.0.0.1:8080"
EK = next(iter(get_settings().api_keys), "")


def _post(p: str, b: dict) -> dict:
    r = urllib.request.Request(
        BASE + p, data=json.dumps(b).encode(), method="POST",
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + EK},
    )
    return json.loads(urllib.request.urlopen(r, timeout=60).read().decode())


def _get(p: str) -> dict:
    r = urllib.request.Request(BASE + p, headers={"Authorization": "Bearer " + EK})
    return json.loads(urllib.request.urlopen(r, timeout=60).read().decode())


def main() -> int:
    created = _post("/v1/videos/generations", {"model": "agnes-video", "prompt": "一只小猫玩毛线球，10秒"})
    print("CREATE RAW:", json.dumps(created, ensure_ascii=False)[:700])
    tid = (
        created.get("task_id") or created.get("id")
        or (created.get("data") or {}).get("task_id") or (created.get("data") or {}).get("id")
    )
    print("parsed tid:", tid)
    if not tid:
        return 0
    for i in range(60):
        time.sleep(8)
        st = _get(f"/v1/videos/{tid}?model=agnes-video")
        print(f"POLL {i} RAW:", json.dumps(st, ensure_ascii=False)[:600])
        s = json.dumps(st).lower()
        if "http" in s and (".mp4" in s or "video" in s):
            print("LOOKS DONE")
            break
        if any(x in s for x in ("fail", "error", "cancel")):
            print("LOOKS FAILED")
            break
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
