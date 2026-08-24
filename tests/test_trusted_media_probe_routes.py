"""Authenticated raw-body boundary for the trusted paid-media decoder."""

from __future__ import annotations

import hashlib
import base64
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

import gateway.app as appmod
from gateway import trusted_media_http as media_http
from gateway.trusted_media_probe import TrustedMediaRejected


RUNTIME_KEY = "trusted-media-runtime-key"
PAID_KEY = "sk-paid-media-" + ("b" * 64)
AUTH = {
    "Authorization": f"Bearer {RUNTIME_KEY}",
    "X-Nachuan-Paid-Media-Key": PAID_KEY,
    "X-Nachuan-Paid-Media-Protocol": "2",
}
REAL_HARDEN_SPOOL = media_http._harden_spool


@pytest.fixture
def probe_client(tmp_path, monkeypatch):
    monkeypatch.setenv("GATEWAY_API_KEYS", RUNTIME_KEY)
    monkeypatch.setenv("NACHUAN_PAID_MEDIA_API_KEY", PAID_KEY)
    monkeypatch.setenv("USAGE_DB_PATH", str(tmp_path / "usage.db"))
    appmod.get_settings.cache_clear()
    media_http._SPOOL_COMPROMISED.clear()
    assert media_http._ACTIVE_SPOOL_RESERVATION_BYTES == 0
    # Route tests exercise the ACL call boundary without repeatedly invoking
    # localized Windows tools.  secure_store has its own exact-DACL tests.
    monkeypatch.setattr(media_http, "_harden_spool", lambda *_a, **_k: None)
    client = TestClient(appmod.app, raise_server_exceptions=False)
    try:
        yield client
    finally:
        client.close()
        media_http._SPOOL_COMPROMISED.clear()
        assert media_http._ACTIVE_SPOOL_RESERVATION_BYTES == 0
        appmod.get_settings.cache_clear()


def _readiness() -> SimpleNamespace:
    return SimpleNamespace(
        schema="nachuan.trusted-media-probe.readiness.v2",
        ready=True,
        validation_policy="nachuan.trusted-media-policy.av-closed.v1",
        validator_version="nachuan.trusted-media-probe.v2",
        ffmpeg_sha256="1" * 64,
        ffprobe_sha256="2" * 64,
    )


def _result(raw: bytes, media_type: str = "image/png") -> SimpleNamespace:
    return SimpleNamespace(
        schema="nachuan.trusted-media-probe.result.v2",
        validator_version="nachuan.trusted-media-probe.v2",
        fully_decoded=True,
        validation_policy="nachuan.trusted-media-policy.av-closed.v1",
        media_type=media_type,
        detected_kind="image" if media_type.startswith("image/") else "video",
        byte_length=len(raw),
        sha256=hashlib.sha256(raw).hexdigest(),
        codec_name="png" if media_type == "image/png" else "h264",
        audio_codec_name=None,
        video_stream_count=1,
        audio_stream_count=0,
        format_name="png_pipe" if media_type == "image/png" else "mp4",
        width=16,
        height=16,
        duration_ms=None if media_type.startswith("image/") else 500,
        decoded_frames=1,
        ffmpeg_sha256="1" * 64,
        ffprobe_sha256="2" * 64,
    )


def _upload_headers(raw: bytes, media_type: str = "image/png") -> dict[str, str]:
    return {
        **AUTH,
        "Content-Type": media_type,
        media_http.EXPECTED_LENGTH_HEADER: str(len(raw)),
        media_http.EXPECTED_SHA256_HEADER: hashlib.sha256(raw).hexdigest(),
    }


def test_probe_readiness_requires_both_runtime_and_paid_authority(
    probe_client, monkeypatch
) -> None:
    calls = 0

    def forbidden():
        nonlocal calls
        calls += 1
        raise AssertionError("unauthorized request reached ffmpeg readiness")

    monkeypatch.setattr(media_http, "preflight_trusted_media_probe", forbidden)
    response = probe_client.get(
        "/v1/paid-media/probe/readiness",
        headers={"Authorization": f"Bearer {RUNTIME_KEY}"},
    )
    assert response.status_code == 401
    assert response.headers["Cache-Control"] == "no-store"
    assert calls == 0


def test_probe_readiness_returns_only_attested_digest_receipt(
    probe_client, monkeypatch
) -> None:
    monkeypatch.setattr(media_http, "preflight_trusted_media_probe", _readiness)
    response = probe_client.get("/v1/paid-media/probe/readiness", headers=AUTH)
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["X-Nachuan-Paid-Media-Protocol"] == "2"
    assert int(response.headers["Content-Length"]) == len(response.content)
    assert response.json() == {
        "schema": "nachuan.trusted-media-probe.readiness.v2",
        "validatorVersion": "nachuan.trusted-media-probe.v2",
        "validationPolicy": "nachuan.trusted-media-policy.av-closed.v1",
        "ready": True,
        "attestedTools": {
            "ffmpegSha256": "1" * 64,
            "ffprobeSha256": "2" * 64,
        },
    }
    assert "path" not in response.text.lower()


def test_raw_upload_is_fsynced_probed_by_private_path_and_removed(
    probe_client, monkeypatch
) -> None:
    raw = b"\x89PNG\r\n\x1a\n" + (b"trusted" * 32)
    observed: dict[str, object] = {}

    def fake_probe(path, **kwargs):
        candidate = Path(path)
        observed["path"] = candidate
        observed["bytes"] = candidate.read_bytes()
        observed["kwargs"] = kwargs
        return _result(raw)

    monkeypatch.setattr(media_http, "probe_trusted_media_staged_file", fake_probe)
    response = probe_client.post(
        "/v1/paid-media/probe",
        headers=_upload_headers(raw),
        content=raw,
    )
    assert response.status_code == 200, response.text
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["X-Nachuan-Paid-Media-Protocol"] == "2"
    assert int(response.headers["Content-Length"]) == len(response.content)
    assert observed["bytes"] == raw
    assert observed["kwargs"] == {
        "expected_media_type": "image/png",
        "max_input_bytes": media_http.MAX_IMAGE_INPUT_BYTES,
        "expected_byte_length": len(raw),
        "expected_sha256": hashlib.sha256(raw).hexdigest(),
    }
    staged = observed["path"]
    assert isinstance(staged, Path)
    assert not staged.exists()
    receipt = response.json()
    assert receipt["schema"] == "nachuan.trusted-media-validation.v2"
    assert receipt["validatorVersion"] == "nachuan.trusted-media-probe.v2"
    assert receipt["validationPolicy"] == "nachuan.trusted-media-policy.av-closed.v1"
    assert receipt["fullyDecoded"] is True
    assert receipt["mediaType"] == "image/png"
    assert receipt["byteLength"] == len(raw)
    assert receipt["sha256"] == hashlib.sha256(raw).hexdigest()
    assert receipt["metadata"]["videoStreamCount"] == 1
    assert receipt["metadata"]["audioStreamCount"] == 0
    assert receipt["metadata"]["audioCodecName"] is None
    assert len(receipt["receiptSha256"]) == 64
    unsigned = {key: value for key, value in receipt.items() if key != "receiptSha256"}
    canonical = json.dumps(
        unsigned, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii")
    assert receipt["receiptSha256"] == hashlib.sha256(
        b"nachuan.trusted-media-validation.v2\0" + canonical
    ).hexdigest()
    assert "path" not in response.text.lower()


@pytest.mark.parametrize(
    ("field", "old_value"),
    [
        ("schema", "nachuan.trusted-media-probe.result.v1"),
        ("validator_version", "nachuan.trusted-media-probe.v1"),
        ("validation_policy", "nachuan.trusted-media-policy.video-only.v1"),
    ],
)
def test_old_or_mixed_probe_receipt_is_rejected_before_validation_receipt(
    field, old_value
) -> None:
    raw = b"strong-v2-only"
    result = _result(raw)
    setattr(result, field, old_value)
    with pytest.raises(media_http.TrustedMediaRequestError) as exc:
        media_http._validation_receipt(result)
    assert exc.value.status_code == 503
    assert exc.value.code == "media_probe_receipt_unavailable"


def test_chunked_upload_is_still_bound_to_explicit_length_and_digest(
    probe_client, monkeypatch
) -> None:
    raw = b"\x89PNG\r\n\x1a\nchunked-private-body"
    monkeypatch.setattr(
        media_http,
        "probe_trusted_media_staged_file",
        lambda _path, **_kwargs: _result(raw),
    )
    headers = _upload_headers(raw)
    with probe_client.stream(
        "POST",
        "/v1/paid-media/probe",
        headers=headers,
        content=iter((raw[:7], raw[7:19], raw[19:])),
    ) as response:
        response.read()
    assert response.status_code == 200, response.text


def test_digest_mismatch_and_json_path_payload_never_reach_decoder(
    probe_client, monkeypatch
) -> None:
    calls = 0

    def forbidden(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        raise AssertionError("invalid wire bytes reached decoder")

    monkeypatch.setattr(media_http, "probe_trusted_media_staged_file", forbidden)
    raw = b"\x89PNG\r\n\x1a\nwrong-digest"
    bad_digest = _upload_headers(raw)
    bad_digest[media_http.EXPECTED_SHA256_HEADER] = "0" * 64
    response = probe_client.post(
        "/v1/paid-media/probe", headers=bad_digest, content=raw
    )
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "media_probe_digest_mismatch"

    path_body = b'{"path":"C:\\\\private\\\\paid.mp4"}'
    response = probe_client.post(
        "/v1/paid-media/probe",
        headers=_upload_headers(path_body, "application/json"),
        content=path_body,
    )
    assert response.status_code == 415
    assert calls == 0


def test_type_limit_and_duplicate_headers_fail_before_spooling_or_decoding(
    probe_client, monkeypatch
) -> None:
    monkeypatch.setattr(
        media_http,
        "_make_private_spool",
        lambda: (_ for _ in ()).throw(AssertionError("invalid request reached spool")),
    )
    oversized_headers = {
        **AUTH,
        "Content-Type": "image/png",
        media_http.EXPECTED_LENGTH_HEADER: str(media_http.MAX_IMAGE_INPUT_BYTES + 1),
        media_http.EXPECTED_SHA256_HEADER: "0" * 64,
    }
    response = probe_client.post(
        "/v1/paid-media/probe", headers=oversized_headers, content=b"x"
    )
    assert response.status_code == 413

    raw = b"x"
    duplicate_headers = [
        ("Authorization", f"Bearer {RUNTIME_KEY}"),
        ("X-Nachuan-Paid-Media-Key", PAID_KEY),
        ("X-Nachuan-Paid-Media-Protocol", "2"),
        ("Content-Type", "image/png"),
        ("Content-Type", "video/mp4"),
        (media_http.EXPECTED_LENGTH_HEADER, "1"),
        (media_http.EXPECTED_SHA256_HEADER, hashlib.sha256(raw).hexdigest()),
    ]
    response = probe_client.post(
        "/v1/paid-media/probe", headers=duplicate_headers, content=raw
    )
    assert response.status_code == 400


def test_private_spool_peak_is_reserved_before_any_upload_bytes(
    probe_client, monkeypatch
) -> None:
    raw = b"\x89PNG\r\n\x1a\ncapacity"
    monkeypatch.setattr(
        media_http.shutil,
        "disk_usage",
        lambda _path: SimpleNamespace(free=media_http.MIN_SPOOL_FREE_FLOOR_BYTES),
    )
    monkeypatch.setattr(
        media_http,
        "_make_private_spool",
        lambda: (_ for _ in ()).throw(AssertionError("insufficient request reached spool")),
    )
    response = probe_client.post(
        "/v1/paid-media/probe", headers=_upload_headers(raw), content=raw
    )
    assert response.status_code == 507
    assert response.json()["detail"] == {
        "code": "media_probe_storage_insufficient",
        "message": "Trusted media probe has insufficient private staging capacity.",
        "retryable": True,
    }
    assert media_http._ACTIVE_SPOOL_RESERVATION_BYTES == 0


def test_full_decode_rejection_is_sanitized_and_spool_is_removed(
    probe_client, monkeypatch
) -> None:
    raw = b"\x89PNG\r\n\x1a\ncontainer-shell"
    observed: dict[str, Path] = {}

    def rejected(path, **_kwargs):
        observed["path"] = Path(path)
        raise TrustedMediaRejected(
            "decoder output C:\\private\\secret paid-api-key must not escape"
        )

    monkeypatch.setattr(media_http, "probe_trusted_media_staged_file", rejected)
    response = probe_client.post(
        "/v1/paid-media/probe", headers=_upload_headers(raw), content=raw
    )
    assert response.status_code == 422
    assert response.headers["Cache-Control"] == "no-store"
    assert response.json()["detail"] == {
        "code": "media_probe_rejected",
        "message": "Trusted media bytes failed full-decode validation.",
        "retryable": False,
    }
    assert "secret" not in response.text.lower()
    assert not observed["path"].exists()


def test_authenticated_raw_route_really_fully_decodes_attested_png(
    probe_client, monkeypatch
) -> None:
    monkeypatch.setattr(media_http, "_harden_spool", REAL_HARDEN_SPOOL)
    manifest_path = Path(__file__).parents[1] / "data" / "media-binaries.json"
    try:
        manifest = json.loads(manifest_path.read_text("utf-8"))
    except (OSError, ValueError):
        pytest.skip("attested media manifest is unavailable")
    if manifest.get("schema") != "nachuan.media-binaries.v1":
        pytest.skip("attested media manifest schema is unavailable")
    for tool in ("ffmpeg", "ffprobe"):
        path = Path(str(manifest.get(f"{tool}_bin") or ""))
        digest = str(manifest.get(f"{tool}_sha256") or "").lower()
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            pytest.skip(f"attested {tool} fixture is unavailable")
        monkeypatch.setenv(f"{tool.upper()}_BIN", str(path.resolve()))
        monkeypatch.setenv(f"{tool.upper()}_SHA256", digest)
    raw = base64.b64decode(
        "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAIAAACQkWg2AAAACXBIWXMAAAABAAAAAQBPJcTW"
        "AAAAIUlEQVR4nGP8y0AaYCFRPcOoBmIAC1GqkMCoBmIAyaEEAGgAATusqEGCAAAAAElFTkSuQmCC",
        validate=True,
    )
    response = probe_client.post(
        "/v1/paid-media/probe", headers=_upload_headers(raw), content=raw
    )
    assert response.status_code == 200, response.text
    receipt = response.json()
    assert receipt["fullyDecoded"] is True
    assert receipt["mediaType"] == "image/png"
    assert receipt["sha256"] == hashlib.sha256(raw).hexdigest()
    assert receipt["metadata"]["decodedFrames"] >= 1


def test_spool_cleanup_failure_fuses_readiness_until_restart(
    probe_client, monkeypatch
) -> None:
    raw = b"\x89PNG\r\n\x1a\ncleanup-fuse"
    observed: dict[str, Path] = {}

    def fake_probe(path, **_kwargs):
        observed["directory"] = Path(path).parent
        return _result(raw)

    real_rmtree = media_http.shutil.rmtree
    monkeypatch.setattr(media_http, "probe_trusted_media_staged_file", fake_probe)
    monkeypatch.setattr(
        media_http.shutil,
        "rmtree",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("locked plaintext")),
    )
    response = probe_client.post(
        "/v1/paid-media/probe", headers=_upload_headers(raw), content=raw
    )
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "media_probe_spool_cleanup_failed"

    calls = 0

    def forbidden_readiness():
        nonlocal calls
        calls += 1
        return _readiness()

    monkeypatch.setattr(media_http, "preflight_trusted_media_probe", forbidden_readiness)
    response = probe_client.get("/v1/paid-media/probe/readiness", headers=AUTH)
    assert response.status_code == 503
    assert response.json()["detail"] == {
        "code": "media_probe_spool_compromised",
        "message": "Trusted media probe staging is disabled until restart.",
        "retryable": False,
    }
    assert calls == 0

    monkeypatch.setattr(media_http.shutil, "rmtree", real_rmtree)
    real_rmtree(observed["directory"])
