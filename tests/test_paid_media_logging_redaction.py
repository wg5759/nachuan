from __future__ import annotations

import uvicorn

import gateway.app as appmod


def test_asset_capability_paths_are_strictly_redacted_including_malformed_variants() -> None:
    assert appmod._redacted_request_path("/v1/paid-media/assets/ack") == (
        "/v1/paid-media/assets/ack"
    )
    for path in (
        "/v1/paid-media/assets/nat1_secret-capability",
        "/v1/paid-media/assets/nat1_secret/extra",
        "/v1/paid-media/assets/%6e%61%74%31_secret",
        "/v1/paid-media/assets/ack/extra",
        "/v1/paid-media/assets/",
    ):
        redacted = appmod._redacted_request_path(path)
        assert redacted == "/v1/paid-media/assets/<redacted>"
        assert "secret" not in redacted


def test_gateway_main_disables_uvicorn_raw_access_log(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_run(*args, **kwargs) -> None:
        captured["args"] = args
        captured["kwargs"] = kwargs

    monkeypatch.setattr(uvicorn, "run", fake_run)
    monkeypatch.setattr(
        appmod,
        "get_settings",
        lambda: type(
            "Settings",
            (),
            {
                "gateway_host": "127.0.0.1",
                "gateway_port": 8000,
                "api_keys": frozenset({"test-key"}),
            },
        )(),
    )
    appmod.main()

    assert captured["kwargs"]["access_log"] is False
