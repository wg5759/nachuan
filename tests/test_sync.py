"""跨设备同步客户端：与共享服务器双向合并（拉取+推送、去重幂等、容灾降级）。"""

from __future__ import annotations

import asyncio

import httpx

from gateway.app import app
from orchestrator.cases import CaseLibrary
from orchestrator.sync import sync_cases_once


def test_sync_cases_once_bidirectional(tmp_path):
    # 不跑 lifespan：直接给 app 挂一个"服务器"案例库（sync 端点只用 app.state.cases）
    server = CaseLibrary(str(tmp_path / "server.db"))
    server.add("synco", "线上服务怎么快速回滚到上个版本", "甲解", "gpt")
    app.state.cases = server
    local = CaseLibrary(str(tmp_path / "local.db"))
    local.add("synco", "给用户表加一个手机号唯一索引", "乙解", "claude")

    async def run():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
            return await sync_cases_once(local, "http://t", "test-key", "synco", client=client)

    res = asyncio.run(run())
    assert res["pulled"] == 1 and res["pushed"] == 1
    assert local.count("synco") == 2  # 本地拉到了服务器的甲
    assert server.count("synco") == 2  # 服务器收到了本地的乙
    # 再同步一次 → 去重幂等，双方都不再新增
    assert asyncio.run(run()) == {"pulled": 0, "pushed": 0}
    server.close()
    local.close()


def test_sync_cases_once_noop_without_url(tmp_path):
    local = CaseLibrary(str(tmp_path / "l.db"))
    assert asyncio.run(sync_cases_once(local, "", "k", "u")) == {"pulled": 0, "pushed": 0}
    local.close()


def test_snapshot_cases(tmp_path):
    import json
    import os

    from orchestrator.sync import snapshot_cases

    lib = CaseLibrary(str(tmp_path / "c.db"))
    lib.add("u", "快照测试题目一二三四五", "解", "gpt")
    bdir = str(tmp_path / "backup")
    path = snapshot_cases(lib, bdir, "u")
    assert path and os.path.exists(path)
    data = json.load(open(path, encoding="utf-8"))
    assert len(data) == 1 and data[0]["problem"] == "快照测试题目一二三四五"
    lib.close()
