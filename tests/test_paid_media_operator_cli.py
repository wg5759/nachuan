from __future__ import annotations

import io

from cli import nachuan
from cli import paid_media_operator


OPERATION_ID = "desktop-op-123e4567-e89b-42d3-a456-426614174000"


def test_paid_media_recover_prepared_inspect_prints_only_public_decision(
    monkeypatch,
    tmp_path,
) -> None:
    decision = {
        "schema": "nachuan.local-paid-media-operator-inspection.v1",
        "operationId": OPERATION_ID,
        "decisionId": "operator-recovery-decision-v1:" + "1" * 64,
        "candidateSha256": "2" * 64,
        "challenge": "RECOVER PREPARED ABCDEF123456",
        "state": "ready",
        "providerCallsAllowed": False,
    }
    calls: list[dict[str, object]] = []

    def fake_inspect(**kwargs):
        calls.append(kwargs)
        return decision

    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setattr(
        paid_media_operator,
        "inspect_prepared_video",
        fake_inspect,
    )
    out = io.StringIO()
    err = io.StringIO()

    code = nachuan.run(
        [
            "paid-media",
            "recover-prepared",
            "inspect",
            OPERATION_ID,
            "--json",
        ],
        out=out,
        err=err,
    )

    assert code == nachuan.EXIT_OK
    assert err.getvalue() == ""
    assert calls == [
        {
            "data_dir": tmp_path,
            "operation_id": OPERATION_ID,
        }
    ]
    rendered = out.getvalue()
    assert OPERATION_ID in rendered
    assert "providerCallsAllowed" in rendered
    for private_material in (
        "nvt1_",
        "sk-paid-media-",
        "private-upstream",
        "prepared_token",
        "https://media.invalid/",
    ):
        assert private_material not in rendered


def test_paid_media_recover_prepared_execute_passes_only_public_contract(
    monkeypatch,
    tmp_path,
) -> None:
    receipt = {
        "schema": "nachuan.local-paid-media-operator-recovery-receipt.v1",
        "operationId": OPERATION_ID,
        "decisionId": "operator-recovery-decision-v1:" + "1" * 64,
        "candidateSha256": "2" * 64,
        "state": "completed",
        "providerCreateCalls": 0,
        "providerPollCalls": 0,
        "resultSha256": "3" * 64,
        "archiveReceiptSha256": "4" * 64,
        "receiptSha256": "5" * 64,
        "assetSha256": "6" * 64,
        "assetReference": "nachuan-paid-media://sha256/" + "6" * 64,
        "byteLength": 123,
        "mediaType": "video/mp4",
        "replayed": False,
    }
    media_config = tmp_path / "media-binaries.json"
    calls: list[dict[str, object]] = []

    async def fake_execute(**kwargs):
        calls.append(kwargs)
        return receipt

    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setattr(
        paid_media_operator,
        "execute_prepared_video",
        fake_execute,
    )
    out = io.StringIO()
    err = io.StringIO()

    code = nachuan.run(
        [
            "paid-media",
            "recover-prepared",
            "execute",
            OPERATION_ID,
            "--decision-id",
            receipt["decisionId"],
            "--confirm",
            "RECOVER PREPARED ABCDEF123456",
            "--media-config",
            str(media_config),
            "--json",
        ],
        out=out,
        err=err,
    )

    assert code == nachuan.EXIT_OK
    assert err.getvalue() == ""
    assert calls == [
        {
            "data_dir": tmp_path,
            "operation_id": OPERATION_ID,
            "decision_id": receipt["decisionId"],
            "confirmation": "RECOVER PREPARED ABCDEF123456",
            "media_config_path": media_config,
        }
    ]
    rendered = out.getvalue()
    assert '"providerCreateCalls": 0' in rendered
    assert '"providerPollCalls": 0' in rendered
    for private_material in (
        "nvt1_",
        "sk-paid-media-",
        "private-upstream",
        "prepared_token",
        "https://media.invalid/",
    ):
        assert private_material not in rendered
