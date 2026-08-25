from __future__ import annotations

import json
import sys
from types import SimpleNamespace

import httpx

from scripts import installed_subscription_first_turn as acceptance


class _Response:
    def __init__(self, payload, status_code: int = 200):
        self.payload = payload
        self.status_code = status_code

    def json(self):
        return self.payload

    def raise_for_status(self):
        if self.status_code >= 400:
            request = httpx.Request("POST", "http://127.0.0.1:8080/test")
            response = httpx.Response(self.status_code, request=request)
            raise httpx.HTTPStatusError("closed", request=request, response=response)


class _Client:
    def __init__(self, *, connection, completion=None, roster=None, completion_error=None):
        self.connection = connection
        self.completion = completion
        self.roster = roster
        self.completion_error = completion_error
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def get(self, url, **_kwargs):
        self.calls.append(("GET", url))
        if url.endswith("/admin/catalog"):
            return _Response(
                {
                    "providers": [
                        {
                            "name": "kimi-code",
                            "type": "kimi_code",
                            "models": ["kimi-code-subscription"],
                        }
                    ]
                }
            )
        return _Response(self.roster or {"data": []})

    def post(self, url, **_kwargs):
        self.calls.append(("POST", url))
        if url.endswith("/admin/connections/kimi-code"):
            return _Response(self.connection)
        if self.completion_error is not None:
            raise self.completion_error
        return _Response(self.completion)


def _run(monkeypatch, tmp_path, client: _Client, *, prompt="PRIVATE_PROMPT"):
    receipt = tmp_path / "receipt.json"
    monkeypatch.setattr(
        acceptance,
        "load_local_owner_credentials",
        lambda _path: SimpleNamespace(runtime_key="runtime", approval_key="approval"),
    )
    monkeypatch.setattr(acceptance.httpx, "Client", lambda **_kwargs: client)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "installed_subscription_first_turn.py",
            "--data-dir",
            str(tmp_path / "data"),
            "--provider",
            "kimi-code",
            "--prompt",
            prompt,
            "--receipt",
            str(receipt),
        ],
    )
    return acceptance.main(), json.loads(receipt.read_text(encoding="utf-8"))


def test_connection_reason_is_preserved_in_safe_failure_receipt_without_retry(
    monkeypatch, tmp_path, capsys
) -> None:
    client = _Client(
        connection={
            "ok": False,
            "reason_code": "text_contract_rejected",
            "error": "must not be copied",
        }
    )

    result, receipt = _run(monkeypatch, tmp_path, client)

    assert result == 2
    assert receipt["failure_stage"] == "connection_probe"
    assert receipt["error_code"] == "text_contract_rejected"
    assert receipt["submission_outcome"] == "known_failure"
    assert receipt["retry_safe"] is False
    assert "PRIVATE_PROMPT" not in json.dumps(receipt)
    assert [method for method, _url in client.calls] == ["GET", "POST"]
    output = capsys.readouterr().out
    assert "text_contract_rejected" in output
    assert "must not be copied" not in output


def test_first_turn_timeout_is_unknown_and_never_retried(monkeypatch, tmp_path) -> None:
    request = httpx.Request("POST", "http://127.0.0.1:8080/v1/chat/completions")
    client = _Client(
        connection={"ok": True, "models": ["kimi-code-subscription"]},
        completion_error=httpx.ReadTimeout("unknown", request=request),
    )

    result, receipt = _run(monkeypatch, tmp_path, client)

    assert result == 2
    assert receipt["failure_stage"] == "first_turn"
    assert receipt["error_code"] == "first_turn_outcome_unknown"
    assert receipt["submission_outcome"] == "unknown"
    assert receipt["retry_safe"] is False
    assert len([call for call in client.calls if call[0] == "POST"]) == 2


def test_success_receipt_contains_hashes_and_roster_proof_not_plaintext(
    monkeypatch, tmp_path
) -> None:
    client = _Client(
        connection={"ok": True, "models": ["kimi-code-subscription"]},
        completion={
            "choices": [{"message": {"content": "PRIVATE_REPLY"}}]
        },
        roster={"data": [{"id": "kimi-code-subscription"}]},
    )

    result, receipt = _run(monkeypatch, tmp_path, client)

    assert result == 0
    assert receipt["connection_verified"] is True
    assert receipt["first_turn_verified"] is True
    assert receipt["connection_retained"] is True
    encoded = json.dumps(receipt)
    assert "PRIVATE_PROMPT" not in encoded
    assert "PRIVATE_REPLY" not in encoded
