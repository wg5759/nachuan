from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "docs" / "data-lifecycle.v1.json"


def _contract() -> dict:
    return json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))


def test_data_lifecycle_contract_is_closed_and_uses_official_sources() -> None:
    contract = _contract()
    assert set(contract) == {
        "schema",
        "version",
        "status",
        "last_verified",
        "official_sources",
        "defaults",
        "rights_workflow",
        "incident_response",
        "stores",
    }
    assert contract["schema"] == "nachuan.data-lifecycle.v1"
    assert contract["version"] == 1
    assert contract["status"] == "engineering-baseline-not-legal-certification"
    sources = contract["official_sources"]
    assert {source["authority"] for source in sources} == {
        "Cyberspace Administration of China",
        "EUR-Lex",
        "NIST",
    }
    for source in sources:
        assert source["accessed"] == contract["last_verified"]
        assert source["url"].startswith("https://")
    assert sources[0]["url"].startswith("https://www.cac.gov.cn/")
    assert sources[1]["url"].startswith("https://eur-lex.europa.eu/")
    assert sources[2]["url"].startswith("https://csrc.nist.gov/")


def test_every_store_has_fail_closed_training_export_delete_and_restore_rules() -> None:
    contract = _contract()
    expected_fields = {
        "id",
        "category",
        "locations",
        "data",
        "purpose",
        "export_policy",
        "delete_policy",
        "retention_rule",
        "processors",
        "customer_training",
        "restore_policy",
        "incident_tier",
    }
    allowed_export = {
        "include_machine_readable",
        "include_metadata_only",
        "exclude_secret",
        "exclude_system_authority",
        "customer_configurable",
    }
    allowed_delete = {
        "erase_or_tombstone",
        "revoke_then_erase",
        "retain_and_restrict",
        "retire_epoch",
        "expire_and_reapply_tombstones",
        "customer_managed",
    }
    ids: list[str] = []
    for store in contract["stores"]:
        assert set(store) == expected_fields
        assert re.fullmatch(r"[a-z0-9]+(?:_[a-z0-9]+)*", store["id"])
        assert store["id"] not in ids
        ids.append(store["id"])
        assert store["locations"] and store["data"] and store["processors"]
        assert store["export_policy"] in allowed_export
        assert store["delete_policy"] in allowed_delete
        assert store["customer_training"] is False
        assert store["incident_tier"] in {"critical", "high", "medium"}
        for location in store["locations"]:
            assert not re.match(r"^[A-Za-z]:[\\/]", location)
            assert "Administrator" not in location

    assert contract["defaults"]["customer_data_used_for_training"] is False
    assert contract["defaults"]["raw_data_in_support_bundle"] is False
    assert contract["rights_workflow"]["states"] == [
        "received",
        "identity_pending",
        "scoped",
        "executing",
        "partially_completed",
        "completed",
        "rejected_with_reason",
    ]


def test_inventory_covers_known_persistent_authorities_and_content_stores() -> None:
    raw = CONTRACT_PATH.read_text(encoding="utf-8")
    required_locations = {
        "conversations.db",
        "conv_summary.db",
        "knowledge.db",
        "memory.db",
        "cases.db",
        "scoreboard.db",
        "ledger.db",
        "connections.json",
        "ilink_token.json",
        "weixin_access.json",
        "feishu_access.json",
        "sync.json",
        "weixin_outbox.db",
        "weixin_agent_idempotency.db",
        "feishu_bridge.db",
        "usage.db",
        "provider-calls.db",
        "approvals.db",
        "admission.db",
        "undo_receipts.db",
        "privacy_rights.db",
        "paid_media_requests.db",
        "installation-root.db",
        "gateway-paid-media-requests.db",
        "asset-store.db",
        "media_cache.json",
        "desktop-main.jsonl",
        "routing_dataset.jsonl",
        "mcp.json",
        "cache.db",
    }
    missing = sorted(item for item in required_locations if item not in raw)
    assert missing == []

    stores = {store["id"]: store for store in _contract()["stores"]}
    assert stores["connections_and_provider_credentials"]["export_policy"] == "exclude_secret"
    assert stores["channel_credentials_and_access"]["delete_policy"] == "revoke_then_erase"
    assert stores["usage_billing_and_provider_calls"]["delete_policy"] == "retain_and_restrict"
    assert stores["privacy_rights_requests_and_receipts"]["export_policy"] == (
        "include_metadata_only"
    )
    assert "subject digest" in stores["privacy_rights_requests_and_receipts"]["data"][0]
    assert stores["backups_and_restore_evidence"]["delete_policy"] == (
        "expire_and_reapply_tombstones"
    )
    assert "deletion-tombstones" in stores["backups_and_restore_evidence"]["restore_policy"]
    assert stores["model_improvement_and_routing_data"]["customer_training"] is False


def test_support_and_incident_contracts_do_not_normalize_raw_customer_data_export() -> None:
    contract = _contract()
    stores = {store["id"]: store for store in contract["stores"]}
    support = stores["logs_health_and_support_bundles"]
    assert support["export_policy"] == "include_metadata_only"
    assert "customer-content" not in support["data"]
    assert contract["incident_response"]["evidence_rule"].endswith(
        "without-copying-customer-content"
    )
    assert contract["incident_response"]["credential_rule"].startswith(
        "revoke-or-rotate-at-the-upstream"
    )
