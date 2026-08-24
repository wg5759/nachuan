from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from gateway import connections
from gateway import local_model
from gateway.config import get_settings
from gateway.connections import ConnectionStore
from gateway.router import ProviderRetirementCapacityError, Router
from gateway.schemas import ChatCompletionRequest


@pytest.fixture
def portable_store_io(monkeypatch):
    """Keep these policy/atomicity tests portable; DPAPI itself has dedicated tests."""

    def read(path, *, purpose, migrate_plaintext=False):
        del purpose, migrate_plaintext
        return json.loads(Path(path).read_text("utf-8"))

    def write(path, payload, *, purpose):
        del purpose
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_suffix(target.suffix + ".tmp")
        temporary.write_text(json.dumps(dict(payload)), "utf-8")
        temporary.replace(target)

    monkeypatch.setattr(connections, "read_protected_json", read)
    monkeypatch.setattr(connections, "write_protected_json", write)
    monkeypatch.setattr(connections, "is_public_http_url", lambda _url: True)


def _conn(base_url: str, *, key: str = "secret") -> dict:
    return {
        "type": "openai_compat",
        "api_key": key,
        "base_url": base_url,
        "enabled_models": [{"id": "demo"}],
    }


def test_disabled_claude_login_connection_cannot_reenter_the_active_router():
    with pytest.raises(ValueError, match="连接协议尚不可用"):
        connections.normalize_connection_candidate(
            "legacy-claude",
            {
                "type": "claude_code",
                "api_key": "",
                "base_url": "",
                "enabled_models": [
                    {
                        "id": "claude-opus",
                        "upstream_model": "opus",
                        "tier": "premium",
                        "description": "legacy",
                        "modality": "chat",
                        "rank": 1,
                        "flagship": False,
                        "tool_capable": False,
                        "skills": [],
                    }
                ],
            },
            verify_public=False,
        )


@pytest.mark.parametrize(
    "model",
    [
        {"id": "claude-opus", "upstream_model": "legacy-opus"},
        {"id": "custom-reviewer", "upstream_model": "anthropic/claude-opus-4"},
    ],
)
def test_custom_connection_cannot_reintroduce_a_retired_claude_model(model):
    with pytest.raises(ValueError, match="Claude 模型本月已停用"):
        connections.normalize_connection_candidate(
            "custom-provider",
            {
                "type": "openai_compat",
                "api_key": "test-only-key",
                "base_url": "https://api.openai.com/v1",
                "enabled_models": [model],
            },
            verify_public=False,
        )


def test_trusted_https_base_url_is_canonicalized_and_fingerprinted(
    tmp_path, portable_store_io
):
    store = ConnectionStore(tmp_path / "connections.json")
    store.set("openai", _conn("HTTPS://API.OPENAI.COM:443/v1/"))

    saved = store.get("openai")
    assert saved is not None
    assert saved["base_url"] == "https://api.openai.com/v1"
    assert saved["target_fingerprint"] == connections.target_fingerprint(
        "https://api.openai.com/v1"
    )


def test_preserved_credential_is_bound_to_exact_protocol_and_api_root(monkeypatch):
    def fail_network_probe(_url):
        raise AssertionError("credential target comparison must not use the network")

    monkeypatch.setattr(connections, "is_public_http_url", fail_network_probe)
    existing = {
        "type": "openai_compat",
        "base_url": "HTTPS://API.OPENAI.COM:443/v1/",
    }

    assert connections.preserved_credential_target_matches(
        existing,
        candidate_type="OPENAI_COMPAT",
        candidate_base_url="https://api.openai.com/v1",
    )
    for candidate_type, candidate_base_url in (
        ("perplexity", "https://api.openai.com/v1"),
        ("openai_compat", "https://api.moonshot.cn/v1"),
        ("openai_compat", "https://api.openai.com/v2"),
        ("openai_compat", 123),
    ):
        assert not connections.preserved_credential_target_matches(
            existing,
            candidate_type=candidate_type,
            candidate_base_url=candidate_base_url,
        )


@pytest.mark.parametrize(
    "base_url",
    [
        "https://api.moonshot.ai/v1",
        "https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
        "https://dashscope-us.aliyuncs.com/compatible-mode/v1",
        "https://api.z.ai/api/paas/v4",
    ],
)
def test_verified_regional_provider_roots_are_builtin_exact_targets(base_url):
    assert connections.normalize_base_url(base_url) == base_url


@pytest.mark.parametrize("provider_type", ["claude_code", "codex"])
def test_cli_connection_save_discards_unsupported_base_url(
    tmp_path, portable_store_io, provider_type
):
    path = tmp_path / "connections.json"
    store = ConnectionStore(path)

    store.set(
        f"{provider_type}-alias",
        {
            "type": provider_type,
            "base_url": "http://127.0.0.1:9876/not-used",
            "enabled_models": [{"id": "demo"}],
        },
    )

    saved = store.get(f"{provider_type}-alias")
    assert saved is not None
    assert "base_url" not in saved
    assert "target_fingerprint" not in saved
    persisted = json.loads(path.read_text("utf-8"))[f"{provider_type}-alias"]
    assert "base_url" not in persisted
    assert "target_fingerprint" not in persisted


def test_loopback_http_is_allowed_but_lan_and_metadata_are_rejected(
    tmp_path, portable_store_io, monkeypatch
):
    store = ConnectionStore(tmp_path / "connections.json")
    store.set("ollama", _conn("http://127.0.0.1:11434/v1/", key=""))
    assert store.get("ollama")["base_url"] == "http://127.0.0.1:11434/v1"

    monkeypatch.setenv(
        "NACHUAN_CONNECTION_HOST_ALLOWLIST",
        "192.168.1.10,169.254.169.254,metadata.google.internal",
    )
    for target in (
        "http://192.168.1.10:8000/v1",
        "https://192.168.1.10/v1",
        "https://169.254.169.254/latest/meta-data",
        "https://metadata.google.internal/computeMetadata/v1",
    ):
        with pytest.raises(ValueError):
            store.set("blocked", _conn(target))


@pytest.mark.parametrize(
    "unsafe_url",
    [
        "https://user:pass@api.openai.com/v1",
        "https://api.openai.com/v1#other",
        "https://api.openai.com/v1?proxy=http://127.0.0.1",
        "ftp://api.openai.com/v1",
        "http://api.openai.com/v1",
        "http://localhost.evil.example/v1",
    ],
)
def test_base_url_rejects_ambiguous_or_credentialed_targets(
    tmp_path, portable_store_io, unsafe_url
):
    store = ConnectionStore(tmp_path / "connections.json")
    with pytest.raises(ValueError):
        store.set("blocked", _conn(unsafe_url))


def test_arbitrary_https_requires_an_exact_explicit_allowlist(
    tmp_path, portable_store_io, monkeypatch
):
    store = ConnectionStore(tmp_path / "connections.json")
    with pytest.raises(ValueError):
        store.set("custom", _conn("https://gateway.example.com/v1"))

    monkeypatch.setenv("NACHUAN_CONNECTION_HOST_ALLOWLIST", "gateway.example.com")
    store.set("custom", _conn("https://GATEWAY.EXAMPLE.COM/v1/"))
    assert store.get("custom")["base_url"] == "https://gateway.example.com/v1"

    with pytest.raises(ValueError):
        store.set("child", _conn("https://child.gateway.example.com/v1"))


def test_failed_set_keeps_memory_and_disk_on_previous_value(
    tmp_path, portable_store_io, monkeypatch
):
    path = tmp_path / "connections.json"
    store = ConnectionStore(path)
    store.set("openai", _conn("https://api.openai.com/v1", key="old"))
    before_disk = path.read_bytes()
    before_memory = store.all()

    def fail_write(*_args, **_kwargs):
        raise OSError("synthetic persistence failure")

    monkeypatch.setattr(connections, "write_protected_json", fail_write)
    with pytest.raises(OSError, match="synthetic persistence failure"):
        store.set("openai", _conn("https://api.openai.com/v1", key="new"))

    assert store.all() == before_memory
    assert path.read_bytes() == before_disk


def test_failed_delete_keeps_memory_and_disk_on_previous_value(
    tmp_path, portable_store_io, monkeypatch
):
    path = tmp_path / "connections.json"
    store = ConnectionStore(path)
    store.set("openai", _conn("https://api.openai.com/v1"))
    before_disk = path.read_bytes()
    before_memory = store.all()

    monkeypatch.setattr(
        connections,
        "write_protected_json",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("delete failed")),
    )
    with pytest.raises(OSError, match="delete failed"):
        store.delete("openai")

    assert store.all() == before_memory
    assert path.read_bytes() == before_disk


def test_unsafe_persisted_connection_is_quarantined_without_losing_good_routes(
    tmp_path, portable_store_io
):
    path = tmp_path / "connections.json"
    path.write_text(
        json.dumps(
            {
                "good": _conn("https://api.openai.com/v1"),
                "bad": _conn("https://evil.example/v1"),
            }
        ),
        encoding="utf-8",
    )
    before = path.read_bytes()

    store = ConnectionStore(path)

    assert set(store.all()) == {"good"}
    assert set(store.invalid()) == {"bad"}
    assert path.read_bytes() == before

    # An unrelated save preserves the quarantined source record, so startup
    # isolation is not a silent destructive migration.
    store.set("other", _conn("https://api.openai.com/v1"))
    persisted = json.loads(path.read_text("utf-8"))
    assert "bad" in persisted and persisted["bad"]["api_key"] == "secret"

    # The operator can explicitly remove the quarantined provider.
    store.delete("bad")
    assert store.invalid() == {}
    assert "bad" not in json.loads(path.read_text("utf-8"))


def test_invalid_quarantined_provider_has_an_opaque_removal_handle(
    tmp_path, portable_store_io
):
    raw_name = "../invalid-provider-name"
    secret = "quarantined-secret-must-never-leave-main"
    path = tmp_path / "connections.json"
    path.write_text(
        json.dumps(
            {
                raw_name: _conn(
                    "https://api.openai.com/v1",
                    key=secret,
                )
            }
        ),
        encoding="utf-8",
    )
    store = ConnectionStore(path)

    masked = store.masked()
    assert len(masked) == 1
    handle, summary = next(iter(masked.items()))
    assert handle.startswith("quarantine-")
    assert len(handle) == len("quarantine-") + 64
    assert summary == {
        "type": "quarantined",
        "base_url": "",
        "enabled_models": [],
        "state": "disabled",
        "verified_at": None,
    }
    assert raw_name not in json.dumps(masked)
    assert secret not in json.dumps(masked)

    assert store.delete_quarantined(handle) is True
    assert store.invalid() == {}
    assert json.loads(path.read_text("utf-8")) == {}
    assert store.delete_quarantined(handle) is False


def test_connection_document_has_bounded_provider_secret_and_model_manifest(
    tmp_path, portable_store_io
):
    store = ConnectionStore(tmp_path / "connections.json")
    with pytest.raises(ValueError):
        store.set("../escape", _conn("https://api.openai.com/v1"))
    with pytest.raises(ValueError):
        store.set(
            "too-secret",
            _conn("https://api.openai.com/v1", key="x" * (32 * 1024 + 1)),
        )
    oversized = _conn("https://api.openai.com/v1")
    oversized["enabled_models"] = [{"id": f"model-{i}"} for i in range(201)]
    with pytest.raises(ValueError):
        store.set("too-many", oversized)


def test_masked_connection_view_is_rebuilt_from_a_nonsecret_allowlist(
    tmp_path, portable_store_io
):
    legacy = _conn("https://api.openai.com/v1")
    legacy["refresh_token"] = "secondary-secret-must-never-leave-main"
    legacy["password"] = "legacy-password-must-never-leave-main"
    store = ConnectionStore(tmp_path / "connections.json")
    store.set("legacy-extra-fields", legacy)

    masked = store.masked()["legacy-extra-fields"]
    assert set(masked) == {
        "type",
        "base_url",
        "enabled_models",
        "credential_present",
        "state",
        "verified_at",
    }
    assert "secondary-secret" not in json.dumps(masked)
    assert "legacy-password" not in json.dumps(masked)


def test_legacy_and_environment_connections_require_explicit_reverification(
    tmp_path, portable_store_io, monkeypatch
):
    monkeypatch.setattr(local_model, "ready_model_alias", lambda: None)
    monkeypatch.setenv("VOLCANO_API_KEY", "legacy-environment-secret")
    get_settings.cache_clear()
    path = tmp_path / "connections.json"
    path.write_text(
        json.dumps({"legacy": _conn("https://api.openai.com/v1")}),
        encoding="utf-8",
    )
    try:
        store = ConnectionStore(path)
        masked = store.masked()["legacy"]
        assert masked["state"] == "legacy_unverified"
        assert masked["verified_at"] is None
        assert masked["credential_present"] is True
        assert "credential_reverification_available" not in masked
        assert "api_key" not in masked and "api_key_masked" not in masked

        router = Router(models_config={}, store=store)
        assert router.resolve("demo") is None
        assert router.first_route_for("volcano") is None
        assert router.first_route_for("claude_code") is None
        assert router.first_route_for("codex") is None

        verified = store.mark_verified(
            "legacy",
            _conn("https://api.openai.com/v1"),
            verified_at_value="2026-07-16T12:34:56Z",
        )
        store.set("legacy", verified)
        asyncio.run(router.reload())
        assert router.resolve("demo") is not None
        assert store.masked()["legacy"]["verified_at"] == "2026-07-16T12:34:56Z"
        asyncio.run(router.aclose())
    finally:
        get_settings.cache_clear()


def test_verification_receipt_drift_disables_the_route(
    tmp_path, portable_store_io, monkeypatch
):
    monkeypatch.setattr(local_model, "ready_model_alias", lambda: None)
    store = ConnectionStore(tmp_path / "connections.json")
    record = store.mark_verified(
        "openai",
        _conn("https://api.openai.com/v1"),
        verified_at_value="2026-07-16T12:34:56Z",
    )
    record["enabled_models"][0]["upstream_model"] = "unverified-replacement"
    store.set("openai", record)

    router = Router(models_config={}, store=store)
    assert router.resolve("demo") is None
    assert store.masked()["openai"]["state"] == "legacy_unverified"
    asyncio.run(router.aclose())


def test_verification_receipt_binds_the_exact_credential(
    tmp_path, portable_store_io, monkeypatch
):
    """Changing only the secret must never inherit an earlier live probe."""

    monkeypatch.setattr(local_model, "ready_model_alias", lambda: None)
    store = ConnectionStore(tmp_path / "connections.json")
    record = store.mark_verified(
        "openai",
        _conn("https://api.openai.com/v1", key="verified-secret"),
        verified_at_value="2026-07-16T12:34:56Z",
    )
    record["api_key"] = "untested-replacement-secret"
    store.set("openai", record)

    router = Router(models_config={}, store=store)
    assert router.resolve("demo") is None
    assert store.masked()["openai"]["state"] == "legacy_unverified"
    asyncio.run(router.aclose())


def test_verification_receipt_binds_timestamp_and_installation_key(
    tmp_path, portable_store_io, monkeypatch
):
    monkeypatch.setattr(local_model, "ready_model_alias", lambda: None)
    first_store = ConnectionStore(tmp_path / "first" / "connections.json")
    record = first_store.mark_verified(
        "openai",
        _conn("https://api.openai.com/v1"),
        verified_at_value="2026-07-16T12:34:56Z",
    )

    timestamp_tampered = json.loads(json.dumps(record))
    timestamp_tampered["_verification"]["verified_at"] = "2026-07-15T12:34:56Z"
    first_store.set("openai", timestamp_tampered)
    first_router = Router(models_config={}, store=first_store)
    assert first_router.resolve("demo") is None
    asyncio.run(first_router.aclose())

    second_store = ConnectionStore(tmp_path / "second" / "connections.json")
    second_store.set("openai", record)
    second_router = Router(models_config={}, store=second_store)
    assert second_router.resolve("demo") is None
    assert second_store.masked()["openai"]["state"] == "legacy_unverified"
    asyncio.run(second_router.aclose())


@pytest.mark.asyncio
async def test_failed_router_reload_keeps_the_previous_live_route(
    tmp_path, portable_store_io, monkeypatch
):
    class _ProviderClient:
        def __init__(self, *args, **kwargs):
            del args, kwargs

        async def aclose(self):
            return None

    monkeypatch.setattr(
        "gateway.providers.openai_compat.httpx.AsyncClient", _ProviderClient
    )
    monkeypatch.setattr(local_model, "ready_model_alias", lambda: None)
    store = ConnectionStore(tmp_path / "connections.json")
    store.set(
        "openai",
        store.mark_verified(
            "openai",
            _conn("https://api.openai.com/v1"),
            verified_at_value="2026-07-16T12:34:56Z",
        ),
    )
    router = Router(models_config={}, store=store)
    old_route = router.resolve("demo")
    assert old_route is not None

    monkeypatch.setattr(
        store,
        "all",
        lambda: (_ for _ in ()).throw(OSError("synthetic reload failure")),
    )
    with pytest.raises(OSError, match="synthetic reload failure"):
        await router.reload()

    assert router.resolve("demo") is old_route
    await router.aclose()


@pytest.mark.asyncio
async def test_connection_reload_reuses_unrelated_provider_and_retires_old_generation(
    tmp_path, portable_store_io, monkeypatch
):
    class _ProviderClient:
        instances: list["_ProviderClient"] = []

        def __init__(self, *args, **kwargs):
            del args, kwargs
            self.closed = 0
            self.started = asyncio.Event()
            self.release = asyncio.Event()
            self.instances.append(self)

        async def post(self, *args, **kwargs):
            del args, kwargs
            self.started.set()
            await self.release.wait()

            class _Response:
                status_code = 200
                text = ""

                @staticmethod
                def json():
                    return {
                        "choices": [
                            {"message": {"role": "assistant", "content": "ok"}}
                        ]
                    }

            return _Response()

        def stream(self, *args, **kwargs):
            del args, kwargs
            owner = self

            class _Headers:
                @staticmethod
                def get_list(_name):
                    return []

            class _StreamResponse:
                status_code = 200
                headers = _Headers()

                async def __aenter__(self):
                    owner.started.set()
                    await owner.release.wait()
                    return self

                async def __aexit__(self, *_args):
                    return None

                async def aiter_bytes(self):
                    yield json.dumps(
                        {
                            "choices": [
                                {
                                    "message": {
                                        "role": "assistant",
                                        "content": "ok",
                                    }
                                }
                            ]
                        }
                    ).encode("utf-8")

            return _StreamResponse()

        async def aclose(self):
            self.closed += 1

    monkeypatch.setattr(
        "gateway.providers.openai_compat.httpx.AsyncClient", _ProviderClient
    )
    monkeypatch.setattr(local_model, "ready_model_alias", lambda: None)
    store = ConnectionStore(tmp_path / "connections.json")
    for provider, model in (("provider-a", "model-a"), ("provider-b", "model-b")):
        store.set(
            provider,
            store.mark_verified(
                provider,
                {
                    "type": "openai_compat",
                    "api_key": f"secret-{provider}",
                    "base_url": "https://api.openai.com/v1",
                    "enabled_models": [{"id": model, "upstream_model": model}],
                },
                verified_at_value="2026-07-16T12:34:56Z",
            ),
        )
    router = Router(models_config={}, store=store)
    old_a = router.resolve("model-a")
    old_b = router.resolve("model-b")
    assert old_a is not None and old_b is not None
    router._RETIREMENT_HANDOFF_SECONDS = 0.01
    active_chat = asyncio.create_task(
        old_a.provider.chat(
            ChatCompletionRequest(
                model="model-a",
                messages=[{"role": "user", "content": "hello"}],
            ),
            old_a.upstream_model,
        )
    )
    await asyncio.wait_for(old_a.provider._client.started.wait(), timeout=1)

    store.set(
        "provider-a",
        store.mark_verified(
            "provider-a",
            {
                "type": "openai_compat",
                "api_key": "replacement-secret",
                "base_url": "https://api.openai.com/v1",
                "enabled_models": [
                    {"id": "model-a-new", "upstream_model": "model-a-new"}
                ],
            },
            verified_at_value="2026-07-16T12:34:56Z",
        ),
    )
    await router.reload_connection("provider-a")

    new_a = router.resolve("model-a-new")
    new_b = router.resolve("model-b")
    assert new_a is not None and new_b is old_b
    assert router.resolve("model-a") is None
    assert old_a.provider is not new_a.provider
    assert old_a.provider._client.closed == 0
    assert old_b.provider._client.closed == 0

    old_a.provider._client.release.set()
    await asyncio.wait_for(active_chat, timeout=1)
    await asyncio.wait_for(old_a.provider._close_done.wait(), timeout=1)
    assert old_a.provider._client.closed == 1
    assert old_b.provider._client.closed == 0

    await router.aclose()
    assert old_a.provider._client.closed == 1
    assert old_b.provider._client.closed == 1
    assert new_a.provider._client.closed == 1


@pytest.mark.asyncio
async def test_connection_reload_queue_is_bounded_until_old_calls_drain(
    tmp_path, portable_store_io, monkeypatch
):
    class _ProviderClient:
        def __init__(self, *args, **kwargs):
            del args, kwargs
            self.started = asyncio.Event()
            self.release = asyncio.Event()
            self.closed = 0

        async def post(self, *args, **kwargs):
            del args, kwargs
            self.started.set()
            await self.release.wait()

            class _Response:
                status_code = 200
                text = ""

                @staticmethod
                def json():
                    return {
                        "choices": [
                            {"message": {"role": "assistant", "content": "ok"}}
                        ]
                    }

            return _Response()

        def stream(self, *args, **kwargs):
            del args, kwargs
            owner = self

            class _Headers:
                @staticmethod
                def get_list(_name):
                    return []

            class _StreamResponse:
                status_code = 200
                headers = _Headers()

                async def __aenter__(self):
                    owner.started.set()
                    await owner.release.wait()
                    return self

                async def __aexit__(self, *_args):
                    return None

                async def aiter_bytes(self):
                    yield json.dumps(
                        {
                            "choices": [
                                {
                                    "message": {
                                        "role": "assistant",
                                        "content": "ok",
                                    }
                                }
                            ]
                        }
                    ).encode("utf-8")

            return _StreamResponse()

        async def aclose(self):
            self.closed += 1

    monkeypatch.setattr(
        "gateway.providers.openai_compat.httpx.AsyncClient", _ProviderClient
    )
    monkeypatch.setattr(local_model, "ready_model_alias", lambda: None)
    store = ConnectionStore(tmp_path / "connections.json")

    def persist(model: str) -> None:
        store.set(
            "provider-a",
            store.mark_verified(
                "provider-a",
                {
                    "type": "openai_compat",
                    "api_key": "secret",
                    "base_url": "https://api.openai.com/v1",
                    "enabled_models": [{"id": model, "upstream_model": model}],
                },
                verified_at_value="2026-07-16T12:34:56Z",
            ),
        )

    persist("model-a")
    router = Router(models_config={}, store=store)
    router._MAX_RETIRED_GENERATIONS = 1
    router._RETIREMENT_HANDOFF_SECONDS = 0
    route_a = router.resolve("model-a")
    assert route_a is not None
    active_chat = asyncio.create_task(
        route_a.provider.chat(
            ChatCompletionRequest(
                model="model-a", messages=[{"role": "user", "content": "hello"}]
            ),
            route_a.upstream_model,
        )
    )
    await asyncio.wait_for(route_a.provider._client.started.wait(), timeout=1)

    persist("model-b")
    await router.reload_connection("provider-a")
    route_b = router.resolve("model-b")
    assert route_b is not None

    persist("model-c")
    with pytest.raises(ProviderRetirementCapacityError):
        await router.reload_connection("provider-a")
    assert router.resolve("model-b") is route_b
    assert router.resolve("model-c") is None

    route_a.provider._client.release.set()
    await asyncio.wait_for(active_chat, timeout=1)
    await asyncio.wait_for(route_a.provider._close_done.wait(), timeout=1)
    await router.reload_connection("provider-a")
    assert router.resolve("model-b") is None
    assert router.resolve("model-c") is not None
    await router.aclose()
