from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

import gateway.app as app_mod

AUTH = {"Authorization": "Bearer test-key"}


def test_daily_video_start_has_no_host_python_reference(tmp_path):
    source = Path(app_mod.__file__).read_text(encoding="utf-8")
    assert "DAILY_VIDEO_LAUNCHER" not in source
    assert "_daily_video_manifest" not in source
    assert "subprocess.run" not in source
    with TestClient(app_mod.app) as client:
        for payload in (
            {"root": str(tmp_path), "date": "2026-07-06"},
            {"root": str(tmp_path), "date": "2026-07-06", "approval_id": 1},
        ):
            response = client.post(
                "/v1/workflows/daily-video/start", headers=AUTH, json=payload
            )
            assert response.status_code == 503
            assert "低权限执行 worker" in response.json()["detail"]


def test_daily_video_worker_boundary_precedes_input_discovery(tmp_path):
    with TestClient(app_mod.app) as client:
        response = client.post(
            "/v1/workflows/daily-video/start",
            headers=AUTH,
            json={"root": str(tmp_path / "missing"), "date": "not-a-date"},
        )
    assert response.status_code == 503
