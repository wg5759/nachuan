from __future__ import annotations

import re

from fastapi.testclient import TestClient

from gateway.app import app


def test_trace_id_is_preserved_or_safely_regenerated() -> None:
    with TestClient(app) as client:
        kept = client.get("/health", headers={"X-Request-ID": "wechat.turn-42"})
        replaced = client.get("/health", headers={"X-Request-ID": "bad value\ninjection"})

    assert kept.headers["x-trace-id"] == "wechat.turn-42"
    assert re.fullmatch(r"[0-9a-f]{32}", replaced.headers["x-trace-id"])
    assert "app;dur=" in kept.headers["server-timing"]
