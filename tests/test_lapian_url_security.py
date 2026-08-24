from __future__ import annotations

import os
import sys
from types import SimpleNamespace

from fastapi.testclient import TestClient

import gateway.app as appmod
from gateway.app import app


AUTH = {"Authorization": "Bearer test-key"}


def test_lapian_url_rejects_local_and_unreviewed_origins(monkeypatch) -> None:
    calls = 0

    def fake_download(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        return "", "must not run"

    monkeypatch.setattr(appmod, "_ytdlp_download", fake_download)
    with TestClient(app) as client:
        local = client.post(
            "/v1/lapian/url",
            headers=AUTH,
            json={"url": "http://127.0.0.1:8080/private"},
        )
        generic = client.post(
            "/v1/lapian/url",
            headers=AUTH,
            json={"url": "https://example.com/video"},
        )
    assert local.status_code == 422
    assert generic.status_code == 422
    assert calls == 0


def test_ytdlp_never_receives_browser_cookie_options_or_mutates_path(
    monkeypatch, tmp_path
) -> None:
    captured: dict = {}
    required: list[str] = []
    before = os.environ.get("PATH", "")

    class FakeYDL:
        def __init__(self, opts):
            assert os.environ.get("YTDLP_NO_PLUGINS") == "1"
            captured.update(opts)

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def download(self, _urls):
            (tmp_path / "v.mp4").write_bytes(b"\x00\x00\x00\x18ftypmp42")

    def fake_require(tool: str):
        required.append(tool)
        return SimpleNamespace(path=str(tmp_path / f"{tool}.exe"))

    monkeypatch.setenv(
        "NACHUAN_ENABLE_UNPINNED_YTDLP",
        "I_ACCEPT_UNPINNED_YTDLP_NETWORK",
    )
    monkeypatch.setenv("YTDLP_NO_PLUGINS", "")
    monkeypatch.setattr(appmod, "_safe_lapian_url", lambda _url: True)
    monkeypatch.setattr(appmod, "require_media_binary", fake_require)
    monkeypatch.setitem(sys.modules, "yt_dlp", SimpleNamespace(YoutubeDL=FakeYDL))
    path, err = appmod._ytdlp_download(
        "https://youtube.com/watch?v=test", str(tmp_path / "v.%(ext)s")
    )

    assert path.endswith("v.mp4") and err == ""
    assert "cookiesfrombrowser" not in captured
    assert "cookiefile" not in captured
    assert captured["js_runtimes"] == {}
    assert captured["remote_components"] == set()
    assert captured["cachedir"] is False
    assert captured["external_downloader"] == {}
    assert captured["external_downloader_args"] == {}
    assert captured["ffmpeg_location"] == os.path.normcase(os.path.abspath(tmp_path))
    assert required == ["ffmpeg", "ffprobe"]
    assert os.environ.get("PATH", "") == before


def test_lapian_known_host_still_requires_public_dns(monkeypatch) -> None:
    monkeypatch.setattr(
        "gateway.url_safety.socket.getaddrinfo",
        lambda _host, port, **_kwargs: [(2, 1, 6, "", ("93.184.216.34", port))],
    )
    assert appmod._safe_lapian_url("https://www.youtube.com/watch?v=x") is True


def test_lapian_url_policy_is_https_443_exact_hosts_and_not_env_extensible(
    monkeypatch,
) -> None:
    monkeypatch.setenv("NACHUAN_LAPIAN_ALLOWED_HOSTS", "example.com")
    monkeypatch.setattr(
        "gateway.url_safety.socket.getaddrinfo",
        lambda _host, port, **_kwargs: [(2, 1, 6, "", ("93.184.216.34", port))],
    )

    assert appmod._safe_lapian_url("https://youtube.com/watch?v=x") is True
    assert appmod._safe_lapian_url("http://youtube.com/watch?v=x") is False
    assert appmod._safe_lapian_url("https://youtube.com:444/watch?v=x") is False
    assert appmod._safe_lapian_url("https://evil.youtube.com/watch?v=x") is False
    assert appmod._safe_lapian_url("https://example.com/video") is False


def test_lapian_url_default_disabled_without_exact_risk_acceptance(monkeypatch) -> None:
    calls = 0

    def fake_download(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        return "", "must not run"

    monkeypatch.delenv("NACHUAN_ENABLE_UNPINNED_YTDLP", raising=False)
    monkeypatch.setattr(appmod, "_safe_lapian_url", lambda _url: True)
    monkeypatch.setattr(appmod, "_ytdlp_download", fake_download)
    with TestClient(app) as client:
        disabled = client.post(
            "/v1/lapian/url",
            headers=AUTH,
            json={"url": "https://youtube.com/watch?v=test"},
        )

    assert disabled.status_code == 503
    assert calls == 0


def test_lapian_url_mismatched_attested_media_directories_are_503(
    monkeypatch, tmp_path
) -> None:
    one = tmp_path / "one"
    two = tmp_path / "two"
    one.mkdir()
    two.mkdir()

    def fake_require(tool: str):
        parent = one if tool == "ffmpeg" else two
        return SimpleNamespace(path=str(parent / f"{tool}.exe"))

    monkeypatch.setenv(
        "NACHUAN_ENABLE_UNPINNED_YTDLP",
        "I_ACCEPT_UNPINNED_YTDLP_NETWORK",
    )
    monkeypatch.setattr(appmod, "_safe_lapian_url", lambda _url: True)
    monkeypatch.setattr(appmod, "require_media_binary", fake_require)
    with TestClient(app) as client:
        response = client.post(
            "/v1/lapian/url",
            headers=AUTH,
            json={"url": "https://youtube.com/watch?v=test"},
        )

    assert response.status_code == 503


def test_direct_upload_lapian_remains_available_when_url_downloader_is_disabled(
    monkeypatch,
) -> None:
    async def fake_run(*_args, **_kwargs):
        return {"report": "ok", "analyses": []}

    monkeypatch.delenv("NACHUAN_ENABLE_UNPINNED_YTDLP", raising=False)
    monkeypatch.setattr(appmod, "run_lapian", fake_run)
    with TestClient(app) as client:
        response = client.post(
            "/v1/lapian",
            headers={**AUTH, "Content-Type": "video/mp4"},
            content=b"synthetic-video",
        )

    assert response.status_code == 200
    assert response.json()["report"] == "ok"


def test_lapian_endpoints_preserve_media_unavailable_as_503(monkeypatch) -> None:
    unavailable = {
        "error": "ffmpeg attestation missing",
        "unavailable": True,
        "status_code": 503,
    }

    async def fake_run(*_args, **_kwargs):
        return unavailable

    async def fake_url(*_args, **_kwargs):
        return unavailable

    monkeypatch.setattr(appmod, "run_lapian", fake_run)
    monkeypatch.setattr(appmod, "lapian_url_report", fake_url)
    with TestClient(app) as client:
        uploaded = client.post(
            "/v1/lapian",
            headers={**AUTH, "Content-Type": "video/mp4"},
            content=b"synthetic-video",
        )
        linked = client.post(
            "/v1/lapian/url",
            headers=AUTH,
            json={"url": "https://youtube.com/watch?v=test"},
        )
    assert uploaded.status_code == 503
    assert linked.status_code == 503
