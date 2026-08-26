"""Exercise installed model onboarding without exposing local owner credentials."""

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


def _loopback_url(value: str, label: str) -> str:
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
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.port is None
    ):
        raise ValueError(f"{label} must be a credential-free loopback HTTP URL")
    return value.rstrip("/")


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def run_acceptance(
    *,
    gateway_url: str,
    data_dir: Path,
    provider: str,
    model: str,
    upstream_url: str,
    prompt: str,
    expected_reply: str,
) -> dict[str, object]:
    gateway = _loopback_url(gateway_url, "gateway_url")
    upstream = _loopback_url(upstream_url, "upstream_url")
    if not provider or len(provider) > 64 or not model or len(model) > 512:
        raise ValueError("provider or model is invalid")
    credentials = load_local_owner_credentials(data_dir)
    runtime_headers = {"Authorization": f"Bearer {credentials.runtime_key}"}
    admin_headers = {
        **runtime_headers,
        "X-Nachuan-Approval-Key": credentials.approval_key,
    }
    connection_removed = False
    connection_created = False
    with httpx.Client(timeout=20.0, trust_env=False) as client:
        try:
            existing = client.get(f"{gateway}/admin/connections", headers=runtime_headers)
            existing.raise_for_status()
            if provider in existing.json():
                raise RuntimeError("acceptance provider already exists; refusing replacement")
            connected = client.post(
                f"{gateway}/admin/connections/{provider}",
                headers=admin_headers,
                json={
                    "type": "openai_compat",
                    "api_key": "",
                    "base_url": upstream,
                    "enabled_models": [
                        {
                            "id": model,
                            "upstream_model": model,
                            "tier": "local",
                            "description": "installed zero-network acceptance",
                        }
                    ],
                    "preserve_existing_credential": False,
                },
            )
            connected.raise_for_status()
            connection_result = connected.json()
            if connection_result.get("ok") is not True or model not in connection_result.get(
                "models", []
            ):
                raise RuntimeError("installed connection verification failed")
            connection_created = True
            roster = client.get(f"{gateway}/v1/models", headers=runtime_headers)
            roster.raise_for_status()
            ids = {str(item.get("id")) for item in roster.json().get("data", [])}
            if model not in ids:
                raise RuntimeError("verified model did not enter the installed roster")
            completion = client.post(
                f"{gateway}/v1/chat/completions",
                headers=runtime_headers,
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": False,
                },
            )
            completion.raise_for_status()
            reply = str(
                completion.json()["choices"][0]["message"]["content"]
            )
            if reply != expected_reply:
                raise RuntimeError("installed first reply differed from the acceptance fixture")
        finally:
            if connection_created:
                removed = client.delete(
                    f"{gateway}/admin/connections/{provider}", headers=admin_headers
                )
                connection_removed = (
                    removed.status_code == 200 and removed.json().get("ok") is True
                )
    if not connection_removed:
        raise RuntimeError("acceptance connection cleanup was not confirmed")
    return {
        "schema": "nachuan.installed-model-onboarding-acceptance.v1",
        "gateway": gateway,
        "provider": provider,
        "model": model,
        "prompt_sha256": _sha256(prompt),
        "reply_sha256": _sha256(expected_reply),
        "connection_verified": True,
        "first_turn_verified": True,
        "connection_removed": True,
        "zero_network_upstream": True,
        "verified_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gateway-url", default="http://127.0.0.1:8080")
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--provider", default="ollama")
    parser.add_argument("--model", default="loopback-e2e-chat")
    parser.add_argument("--upstream-url", default="http://127.0.0.1:11434/v1")
    parser.add_argument("--prompt", default="你好，请完成零外网首回合。")
    parser.add_argument("--expected-reply", default="纳川零外网测试回复。")
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    try:
        receipt = run_acceptance(
            gateway_url=args.gateway_url,
            data_dir=args.data_dir,
            provider=args.provider,
            model=args.model,
            upstream_url=args.upstream_url,
            prompt=args.prompt,
            expected_reply=args.expected_reply,
        )
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        args.receipt.write_text(
            json.dumps(receipt, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    except Exception as exc:
        print(f"[installed-model-onboarding] FAIL {type(exc).__name__}")
        return 2
    print(
        "[installed-model-onboarding] OK "
        f"provider={receipt['provider']} model={receipt['model']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
