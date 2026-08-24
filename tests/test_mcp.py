"""MCP definitions remain inspectable/removable while all activation is quarantined."""

from __future__ import annotations

import hashlib
import json

import pytest

import gateway.mcp_registry as mcp


def test_registry_roundtrip_is_persistent_but_inactive(tmp_path, monkeypatch):
    registry = tmp_path / "mcp.json"
    monkeypatch.setattr(mcp, "_path", lambda: registry)

    assert mcp.list_servers() == {}
    assert mcp.config_path() is None

    servers = mcp.add_server(
        "fs",
        command="npx",
        args=["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
    )
    assert servers["fs"]["command"] == "npx"
    monkeypatch.setenv("NACHUAN_ENABLE_UNVERIFIED_MCP", "1")
    monkeypatch.setenv("NACHUAN_ENABLE_VERIFIED_MCP", "1")
    assert mcp.config_path() is None
    assert mcp.active_server_names() == []

    saved = json.loads(registry.read_text(encoding="utf-8"))
    assert saved["mcpServers"]["fs"]["args"][0] == "-y"

    monkeypatch.setattr(mcp, "is_public_http_url", lambda _url: True)
    mcp.add_server("web", url="https://example.com/mcp")
    left = mcp.remove_server("fs")
    assert "fs" not in left and "web" in left


def test_config_path_none_when_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(mcp, "_path", lambda: tmp_path / "none.json")
    assert mcp.config_path() is None


def test_presets_and_probe_never_activate_host_processes(monkeypatch):
    assert len(mcp.PRESETS) >= 10
    assert all(p.get("name") and p.get("audited") is False for p in mcp.PRESETS)
    assert all(not p.get("command") for p in mcp.PRESETS)
    names = {p["name"] for p in mcp.PRESETS}
    assert {"filesystem", "fetch", "playwright", "sqlite", "context7"}.issubset(names)

    monkeypatch.setattr(mcp, "is_public_http_url", lambda _url: True)
    monkeypatch.setenv("NACHUAN_ENABLE_VERIFIED_MCP", "1")
    assert mcp.probe({"url": "https://example.test"})["ok"] is False
    assert mcp.probe({"command": ""})["ok"] is False
    assert mcp.probe({"command": "npx", "args": []})["ok"] is False
    assert mcp.runtime_available("node") is False
    assert mcp.runtime_available("python") is False


def test_plaintext_mcp_secrets_and_unsafe_names_are_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(mcp, "_path", lambda: tmp_path / "mcp.json")
    with pytest.raises(ValueError, match="plaintext"):
        mcp.add_server("safe", command="tool", env={"TOKEN": "secret"})
    with pytest.raises(ValueError, match="name"):
        mcp.add_server("../escape", command="tool")


def test_hash_verified_local_mcp_still_cannot_activate(tmp_path, monkeypatch):
    registry = tmp_path / "mcp.json"
    executable = (tmp_path / "reviewed-tool.exe").resolve()
    executable.write_bytes(b"reviewed local MCP")
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    monkeypatch.setattr(mcp, "_path", lambda: registry)
    monkeypatch.setenv("NACHUAN_ENABLE_VERIFIED_MCP", "1")

    mcp.add_server("good", command=str(executable), args=["--stdio"], sha256=digest)

    assert mcp.config_path() is None
    assert mcp.active_server_names() == []
    assert mcp.probe(mcp.list_servers()["good"])["ok"] is False
