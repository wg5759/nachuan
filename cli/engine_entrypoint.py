"""Production defaults for the pip-installed ``nachuan-engine`` command."""

from __future__ import annotations

import os
import sys
from pathlib import Path


_MANAGED_SUBSCRIPTION_ENVIRONMENT = (
    "CODEX_CLI_PATH",
    "CODEX_CLI_SHA256",
    "CODEX_CLI_TEMP_ROOT",
    "KIMI_CLI_PATH",
    "KIMI_CLI_SHA256",
    "KIMI_CLI_VERSION",
    "KIMI_CLI_TEMP_ROOT",
    "KIMI_CODE_HOME",
    "KIMI_DISABLE_TELEMETRY",
    "KIMI_CODE_NO_AUTO_UPDATE",
)


def _default_data_dir() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA", "").strip()
    if local_app_data:
        return Path(local_app_data) / "Nachuan"
    return Path.home() / ".nachuan"


def main() -> None:
    """Bind accounting paths before importing the Gateway application."""

    configured_data_dir = os.environ.get("DATA_DIR", "").strip()
    using_default_data_dir = not configured_data_dir
    data_dir = (
        Path(configured_data_dir) if configured_data_dir else _default_data_dir()
    ).expanduser().resolve()
    os.environ["DATA_DIR"] = str(data_dir)
    os.environ["USAGE_DB_PATH"] = str(data_dir / "usage.db")
    os.environ["NACHUAN_PROVIDER_CALL_LEDGER_MODE"] = "required"
    os.environ["NACHUAN_PROVIDER_CALL_LEDGER_PATH"] = str(
        data_dir / "provider-calls.db"
    )

    from gateway.subscription_cli_config import (
        SubscriptionCliConfigError,
        load_subscription_cli_environment,
    )

    # These values are authoritative only when restored from the protected
    # binding.  Ambient variables must never name a different subscription
    # binary or data home when no binding exists or its DPAPI document fails.
    for name in _MANAGED_SUBSCRIPTION_ENVIRONMENT:
        os.environ.pop(name, None)
    try:
        subscription_environment = load_subscription_cli_environment(data_dir)
    except SubscriptionCliConfigError:
        sys.stderr.write(
            "Nachuan: protected subscription CLI binding is unavailable; "
            "subscription connectors are disabled.\n"
        )
    else:
        os.environ.update(subscription_environment)

    if using_default_data_dir:
        from gateway.legacy_connections import migrate_legacy_desktop_connections

        migrate_legacy_desktop_connections(
            data_dir,
            roaming_app_data=os.environ.get("APPDATA"),
        )

    from gateway.app import main as gateway_main

    gateway_main()


if __name__ == "__main__":
    main()
