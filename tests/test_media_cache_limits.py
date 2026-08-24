"""The media de-duplication cache must itself remain a bounded resource."""

from __future__ import annotations

import json

import pytest

from gateway import media_cache


def test_fingerprint_rejects_unbounded_payload(monkeypatch) -> None:
    monkeypatch.setattr(media_cache, "_MAX_FINGERPRINT_BYTES", 64)
    with pytest.raises(ValueError, match="payload"):
        media_cache.fingerprint("image", {"prompt": "x" * 100})


def test_put_skips_result_larger_than_one_cache_entry(tmp_path, monkeypatch) -> None:
    cache = tmp_path / "media_cache.json"
    monkeypatch.setattr(media_cache, "_path", lambda: str(cache))
    monkeypatch.setattr(media_cache, "_MAX_ENTRY_BYTES", 128)
    media_cache.put("a" * 32, {"data": "x" * 500})
    assert media_cache.get("a" * 32) is None
    assert not cache.exists()


def test_put_prunes_oldest_entries_to_total_byte_budget(tmp_path, monkeypatch) -> None:
    cache = tmp_path / "media_cache.json"
    monkeypatch.setattr(media_cache, "_path", lambda: str(cache))
    monkeypatch.setattr(media_cache, "_MAX_ENTRY_BYTES", 512)
    monkeypatch.setattr(media_cache, "_MAX_CACHE_BYTES", 360)
    monkeypatch.setattr(media_cache, "_MAX_ENTRIES", 10)
    for i in range(6):
        media_cache.put(f"{i:032x}", {"data": "x" * 80, "i": i})
    stored = json.loads(cache.read_text(encoding="utf-8"))
    assert len(stored) < 6
    assert cache.stat().st_size <= media_cache._MAX_CACHE_BYTES
    assert media_cache.get(f"{5:032x}") is not None


def test_load_refuses_oversized_cache_file(tmp_path, monkeypatch) -> None:
    cache = tmp_path / "media_cache.json"
    cache.write_bytes(b"{" + b"x" * 1000)
    monkeypatch.setattr(media_cache, "_path", lambda: str(cache))
    monkeypatch.setattr(media_cache, "_MAX_CACHE_BYTES", 100)
    assert media_cache._load() == {}
