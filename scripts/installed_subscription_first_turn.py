"""Verify one installed subscription connection and first text turn."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from cli.local_web_start import load_local_owner_credentials


_PROVIDERS = {"codex", "kimi-code"}
_CLOSED_CONNECTION_REASONS = {
    "connector_unavailable",
    "invalid_credentials",
    "invalid_request",
    "model_or_endpoint_not_found",
    "network_or_timeout",
    "quota_or_rate_limited",
    "reauth_required",
    "text_contract_rejected",
    "upstream_unavailable",
}


class InstalledSubscriptionAcceptanceError(RuntimeError):
    def __init__(
        self,
        code: str,
        *,
        stage: str,
        submission_outcome: str = "not_started",
        retry_safe: bool = True,
    ) -> None:
        self.code = code
        self.stage = stage
        self.submission_outcome = submission_outcome
        self.retry_safe = retry_safe
        super().__init__(code)


def _gateway_url(value: str) -> str:
    parsed = urlsplit(value)
    try:
        loopback = parsed.hostname == "localhost" or ipaddress.ip_address(
            parsed.hostname or ""
        ).is_loopback
    except ValueError:
        loopback = False
    if (
        parsed.scheme != "http"
        or not loopback
        or parsed.port is None
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("gateway must be credential-free loopback HTTP")
    return value.rstrip("/")


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _write_receipt(path: Path, receipt: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(receipt, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _failure_code(stage: str, error: BaseException) -> tuple[str, str, bool]:
    if isinstance(error, InstalledSubscriptionAcceptanceError):
        return error.code, error.submission_outcome, error.retry_safe
    if stage == "first_turn":
        return "first_turn_outcome_unknown", "unknown", False
    if stage == "connection_probe":
        return "connection_probe_outcome_unknown", "unknown", False
    if isinstance(error, (httpx.TimeoutException, httpx.ConnectError)):
        return "local_gateway_unavailable", "not_started", True
    return f"{stage}_failed", "not_started", True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gateway-url", default="http://127.0.0.1:8080")
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--provider", choices=sorted(_PROVIDERS), required=True)
    parser.add_argument("--prompt", default="请只回复：连接成功")
    parser.add_argument(
        "--connection-only",
        action="store_true",
        help="Stop after exactly one provider connection probe; never submit a first turn.",
    )
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    stage = "initialize"
    try:
        gateway = _gateway_url(args.gateway_url)
        stage = "credentials"
        credentials = load_local_owner_credentials(args.data_dir)
        runtime_headers = {"Authorization": f"Bearer {credentials.runtime_key}"}
        admin_headers = {
            **runtime_headers,
            "X-Nachuan-Approval-Key": credentials.approval_key,
        }
        with httpx.Client(timeout=240.0, trust_env=False) as client:
            stage = "catalog"
            catalog = client.get(f"{gateway}/admin/catalog", headers=runtime_headers)
            catalog.raise_for_status()
            provider = next(
                (
                    item
                    for item in catalog.json().get("providers", [])
                    if item.get("name") == args.provider
                ),
                None,
            )
            if not isinstance(provider, dict):
                raise InstalledSubscriptionAcceptanceError(
                    "provider_not_in_catalog",
                    stage=stage,
                )
            models = list(provider.get("models") or [])
            if len(models) < 1:
                raise InstalledSubscriptionAcceptanceError(
                    "provider_catalog_has_no_model",
                    stage=stage,
                )
            selected = models[0]
            stage = "connection_probe"
            connected = client.post(
                f"{gateway}/admin/connections/{args.provider}",
                headers=admin_headers,
                json={
                    "type": provider["type"],
                    "api_key": "",
                    "base_url": provider.get("default_base_url") or "",
                    "enabled_models": [selected],
                    "preserve_existing_credential": False,
                },
            )
            connected.raise_for_status()
            connection = connected.json()
            if connection.get("ok") is not True or not connection.get("models"):
                raw_reason = connection.get("reason_code")
                reason = (
                    str(raw_reason)
                    if isinstance(raw_reason, str)
                    and raw_reason in _CLOSED_CONNECTION_REASONS
                    else "connector_unavailable"
                )
                raise InstalledSubscriptionAcceptanceError(
                    reason,
                    stage=stage,
                    submission_outcome="known_failure",
                    retry_safe=False,
                )
            model = str(connection["models"][0])
            if args.connection_only:
                receipt = {
                    "schema": "nachuan.installed-subscription-connection-probe.v1",
                    "provider": args.provider,
                    "model": model,
                    "connection_verified": True,
                    "first_turn_attempted": False,
                    "connection_retained": True,
                    "verified_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                }
                _write_receipt(args.receipt, receipt)
                print(
                    "[installed-subscription-first-turn] OK "
                    f"provider={receipt['provider']} model={receipt['model']} "
                    "connection_only=true"
                )
                return 0
            stage = "first_turn"
            completion = client.post(
                f"{gateway}/v1/chat/completions",
                headers=runtime_headers,
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": args.prompt}],
                    "stream": False,
                },
            )
            completion.raise_for_status()
            payload = completion.json()
            reply = str(payload["choices"][0]["message"]["content"])
            if not reply.strip():
                raise InstalledSubscriptionAcceptanceError(
                    "first_turn_empty_reply",
                    stage=stage,
                    submission_outcome="known_failure",
                    retry_safe=False,
                )
            stage = "roster"
            roster = client.get(f"{gateway}/v1/models", headers=runtime_headers)
            roster.raise_for_status()
            ids = {str(item.get("id")) for item in roster.json().get("data", [])}
            if model not in ids:
                raise InstalledSubscriptionAcceptanceError(
                    "model_missing_after_first_turn",
                    stage=stage,
                    submission_outcome="success",
                    retry_safe=False,
                )
        receipt = {
            "schema": "nachuan.installed-subscription-first-turn.v1",
            "provider": args.provider,
            "model": model,
            "prompt_sha256": _digest(args.prompt),
            "reply_sha256": _digest(reply),
            "connection_verified": True,
            "first_turn_verified": True,
            "connection_retained": True,
            "verified_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        }
        _write_receipt(args.receipt, receipt)
    except Exception as exc:
        code, submission_outcome, retry_safe = _failure_code(stage, exc)
        failure = {
            "schema": "nachuan.installed-subscription-first-turn-failure.v1",
            "provider": args.provider,
            "prompt_sha256": _digest(args.prompt),
            "failure_stage": (
                exc.stage
                if isinstance(exc, InstalledSubscriptionAcceptanceError)
                else stage
            ),
            "error_code": code,
            "submission_outcome": submission_outcome,
            "retry_safe": retry_safe,
            "connection_only": bool(args.connection_only),
            "verified_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        }
        try:
            _write_receipt(args.receipt, failure)
        except OSError:
            pass
        print(
            "[installed-subscription-first-turn] FAIL "
            f"stage={failure['failure_stage']} code={code} "
            f"retry_safe={str(retry_safe).lower()}"
        )
        return 2
    print(
        "[installed-subscription-first-turn] OK "
        f"provider={receipt['provider']} model={receipt['model']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
