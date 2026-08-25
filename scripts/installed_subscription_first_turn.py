"""Verify one installed subscription connection and first text turn."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from cli.local_web_start import load_local_owner_credentials


_PROVIDERS = {"codex", "kimi-code"}


def _gateway_url(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gateway-url", default="http://127.0.0.1:8080")
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--provider", choices=sorted(_PROVIDERS), required=True)
    parser.add_argument("--prompt", default="请只回复：连接成功")
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    try:
        gateway = _gateway_url(args.gateway_url)
        credentials = load_local_owner_credentials(args.data_dir)
        runtime_headers = {"Authorization": f"Bearer {credentials.runtime_key}"}
        admin_headers = {
            **runtime_headers,
            "X-Nachuan-Approval-Key": credentials.approval_key,
        }
        with httpx.Client(timeout=240.0, trust_env=False) as client:
            catalog = client.get(f"{gateway}/admin/catalog", headers=runtime_headers)
            catalog.raise_for_status()
            provider = next(
                item
                for item in catalog.json().get("providers", [])
                if item.get("name") == args.provider
            )
            models = list(provider.get("models") or [])
            if len(models) < 1:
                raise RuntimeError("subscription catalog has no model")
            selected = models[0]
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
                reason = str(connection.get("reason_code") or "unavailable")
                raise RuntimeError(f"subscription connection rejected: {reason}")
            model = str(connection["models"][0])
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
                raise RuntimeError("subscription first turn returned an empty reply")
            roster = client.get(f"{gateway}/v1/models", headers=runtime_headers)
            roster.raise_for_status()
            ids = {str(item.get("id")) for item in roster.json().get("data", [])}
            if model not in ids:
                raise RuntimeError("subscription model did not remain in the installed roster")
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
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        args.receipt.write_text(
            json.dumps(receipt, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    except Exception as exc:
        print(f"[installed-subscription-first-turn] FAIL {type(exc).__name__}")
        return 2
    print(
        "[installed-subscription-first-turn] OK "
        f"provider={receipt['provider']} model={receipt['model']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
