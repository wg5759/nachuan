from __future__ import annotations

from pathlib import Path

from gateway import local_model
from gateway.router import Router


def test_packaged_desktop_injects_local_runtime_manifest_and_never_enables_legacy_download() -> None:
    source = (Path(__file__).resolve().parents[1] / "desktop" / "src" / "main" / "index.ts").read_text(
        "utf-8"
    )

    assert "NACHUAN_LOCAL_RUNTIME_MANIFEST" in source
    assert "attestPackagedRuntimeManifest" in source
    assert "EXPECTED_LOCAL_RUNTIME_MANIFEST_SHA256" in source
    assert "LOCAL_MODEL_AUTODOWNLOAD" not in source
    assert "PYTHONUTF8: '1'" in source
    assert "PYTHONIOENCODING: 'utf-8'" in source


def test_router_hides_local_runtime_until_managed_alias_is_ready(monkeypatch) -> None:
    monkeypatch.setattr(local_model, "available", lambda: True)
    monkeypatch.setattr(local_model, "base_url", lambda: "http://127.0.0.1:8091/v1")
    monkeypatch.setattr(local_model, "ready_model_alias", lambda: "")

    router = Router(models_config={})

    assert router.resolve("local") is None
    assert all(model["id"] != "local" for model in router.list_models())


def test_router_binds_local_upstream_to_managed_nonce_alias(monkeypatch) -> None:
    alias = "nachuan-0123456789abcdef0123456789abcdef"
    monkeypatch.setattr(local_model, "available", lambda: True)
    monkeypatch.setattr(local_model, "base_url", lambda: "http://127.0.0.1:8091/v1")
    monkeypatch.setattr(local_model, "ready_model_alias", lambda: alias)

    router = Router(models_config={})
    route = router.resolve("local")

    assert route is not None
    assert route.upstream_model == alias
    assert route.upstream_model != "local"
