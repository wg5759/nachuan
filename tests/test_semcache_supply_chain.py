from __future__ import annotations

from gateway import semcache


def test_unpatched_gptcache_adapter_stays_fail_closed(monkeypatch) -> None:
    monkeypatch.setenv("SEMCACHE_ENABLED", "1")

    assert semcache.enabled() is False
    assert semcache.lookup("model", "prompt") is None
