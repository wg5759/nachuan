"""跨设备同步客户端：与共享服务器双向合并案例（各机各存全份=容灾）。

设计要点：
  · 离线优先——每台机器各存一整份、各自能独立工作；服务器只是"汇总/中转站"，不是单点。
  · 双向合并——pull 服务器的并进本地、push 本地的并进服务器；去重保证幂等、不重复堆。
  · 安全降级——网络/服务器抖动一律吞掉，绝不影响本机正常使用。
"""

from __future__ import annotations

import json
import os
import time
from typing import Any, Optional

import httpx


async def sync_cases_once(
    cases: Any,
    base_url: str,
    key: str,
    user_id: str,
    *,
    timeout: float = 30.0,
    client: Optional[httpx.AsyncClient] = None,
) -> dict[str, int]:
    """与共享服务器同步一次：拉取合并 + 推送本地。返回 {pulled, pushed}（各为净新增条数）。"""
    base_url = (base_url or "").rstrip("/")
    if not base_url or not user_id:
        return {"pulled": 0, "pushed": 0}
    headers = {"Authorization": f"Bearer {key}"} if key else {}
    own = client is None
    cl = client or httpx.AsyncClient(timeout=timeout)
    pulled = pushed = 0
    try:
        # pull → 合并进本地
        r = await cl.get(f"{base_url}/v1/sync/cases/pull", params={"user_id": user_id}, headers=headers)
        if r.status_code == 200:
            pulled = cases.import_merge(user_id, r.json().get("items") or [])
        # push 本地 → 服务器
        rp = await cl.post(
            f"{base_url}/v1/sync/cases/push",
            json={"user_id": user_id, "items": cases.export_all(user_id)},
            headers=headers,
        )
        if rp.status_code == 200:
            pushed = int(rp.json().get("added") or 0)
    finally:
        if own:
            await cl.aclose()
    return {"pulled": pulled, "pushed": pushed}


def snapshot_cases(cases: Any, backup_dir: str, user_id: str, *, keep: int = 14) -> str:
    """把案例库导出成带时间戳的 JSON 快照（容灾/点位恢复）；只留最近 keep 份。
    backup_dir 指向网盘同步文件夹即可离线异地。返回快照路径，失败返回空串（安全降级）。"""
    try:
        os.makedirs(backup_dir, exist_ok=True)
        prefix = f"cases-{user_id}-"
        path = os.path.join(backup_dir, f"{prefix}{time.strftime('%Y%m%d-%H%M%S')}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cases.export_all(user_id), f, ensure_ascii=False)
        snaps = sorted(p for p in os.listdir(backup_dir) if p.startswith(prefix) and p.endswith(".json"))
        for old in snaps[:-keep]:  # 清理旧快照，不无限涨
            try:
                os.remove(os.path.join(backup_dir, old))
            except Exception:  # noqa: BLE001
                pass
        return path
    except Exception:  # noqa: BLE001
        return ""
