"""Fail-closed checks for Nachuan's shared-core, multi-edition release contract."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any


class DistributionContractError(RuntimeError):
    pass


_SEMVER = re.compile(
    r"^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$"
)
_CHANNEL = re.compile(r"^[a-z0-9][a-z0-9-]{2,63}$")
_EDITIONS = ("community", "desktop", "enterprise")


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise DistributionContractError(f"unreadable JSON: {path.name}") from exc
    if not isinstance(value, dict):
        raise DistributionContractError(f"JSON root must be an object: {path.name}")
    return value


def verify_contract(root: Path) -> dict[str, Any]:
    root = root.resolve(strict=True)
    contract = _load_json(root / "config" / "distribution-channels.v1.json")
    if set(contract) != {
        "schema",
        "core_version",
        "source_repository",
        "editions",
        "synchronization",
    }:
        raise DistributionContractError("distribution contract top-level shape drifted")
    if contract["schema"] != "nachuan.distribution-channels.v1":
        raise DistributionContractError("unsupported distribution contract schema")

    core_version = contract["core_version"]
    if not isinstance(core_version, str) or _SEMVER.fullmatch(core_version) is None:
        raise DistributionContractError("core_version is not strict semver")
    if contract["source_repository"] != "wg5759/nachuan":
        raise DistributionContractError("official source repository drifted")

    with (root / "pyproject.toml").open("rb") as handle:
        python_project = tomllib.load(handle)
    python_version = python_project.get("project", {}).get("version")
    desktop_version = _load_json(root / "desktop" / "package.json").get("version")
    gateway_source = (root / "gateway" / "__init__.py").read_text(encoding="utf-8")
    gateway_match = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']$', gateway_source, re.MULTILINE)
    gateway_version = gateway_match.group(1) if gateway_match else None
    if (
        python_version != core_version
        or desktop_version != core_version
        or gateway_version != core_version
    ):
        raise DistributionContractError(
            "Python, gateway, desktop and distribution core versions must be identical"
        )

    editions = contract["editions"]
    if not isinstance(editions, dict) or tuple(editions) != _EDITIONS:
        raise DistributionContractError("required edition ordering or membership drifted")
    channels: set[str] = set()
    for name in _EDITIONS:
        edition = editions[name]
        expected = {
            "display_name",
            "delivery",
            "channel",
            "core_source",
            "update_entry",
            "requires_authenticode",
            "client_ready",
            "readiness_reason",
        }
        if not isinstance(edition, dict) or set(edition) != expected:
            raise DistributionContractError(f"{name} edition shape drifted")
        if edition["core_source"] != "shared":
            raise DistributionContractError(f"{name} forked away from the shared core")
        channel = edition["channel"]
        if not isinstance(channel, str) or _CHANNEL.fullmatch(channel) is None:
            raise DistributionContractError(f"{name} channel is invalid")
        if channel in channels:
            raise DistributionContractError("distribution channels must be unique")
        channels.add(channel)
        if not isinstance(edition["client_ready"], bool):
            raise DistributionContractError(f"{name} client_ready must be boolean")
        if not isinstance(edition["readiness_reason"], str) or not edition[
            "readiness_reason"
        ].strip():
            raise DistributionContractError(f"{name} readiness reason is required")

    if editions["community"]["delivery"] != "verified-source":
        raise DistributionContractError("community delivery must remain verified source")
    if editions["community"]["requires_authenticode"] is not False:
        raise DistributionContractError("source delivery cannot claim Authenticode")
    for name in ("desktop", "enterprise"):
        if editions[name]["requires_authenticode"] is not True:
            raise DistributionContractError(f"{name} must fail closed without Authenticode")

    sync = contract["synchronization"]
    if not isinstance(sync, dict) or set(sync) != {
        "rule",
        "required_editions",
        "promotion_order",
        "independent_rollout",
        "no_cross_channel_downgrade",
    }:
        raise DistributionContractError("synchronization contract shape drifted")
    if sync["rule"] != "one-core-version-per-release":
        raise DistributionContractError("shared core synchronization rule drifted")
    if sync["required_editions"] != list(_EDITIONS):
        raise DistributionContractError("required edition set drifted")
    if sync["promotion_order"] != list(_EDITIONS):
        raise DistributionContractError("promotion order drifted")
    if sync["independent_rollout"] is not True or sync["no_cross_channel_downgrade"] is not True:
        raise DistributionContractError("rollout isolation must remain enabled")

    return {
        "schema": contract["schema"],
        "core_version": core_version,
        "channels": sorted(channels),
        "client_ready": {
            name: editions[name]["client_ready"] for name in _EDITIONS
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    args = parser.parse_args()
    try:
        receipt = verify_contract(args.root)
    except (DistributionContractError, OSError, tomllib.TOMLDecodeError) as exc:
        print(f"[distribution-contract] FAIL {exc}", file=sys.stderr)
        return 2
    print(
        "[distribution-contract] OK "
        f"core={receipt['core_version']} channels={len(receipt['channels'])}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
