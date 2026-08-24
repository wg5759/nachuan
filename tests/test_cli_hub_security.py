from __future__ import annotations

import hashlib
import json

from orchestrator.cli_hub_security import plan_cli_launch, remote_install_reason


def test_cli_hub_launch_fails_closed_without_a_local_allowlist(tmp_path):
    plan = plan_cli_launch("blender", "--version", allowlist_path=tmp_path / "missing.json")

    assert plan.allowed is False
    assert plan.argv == []
    assert "本地白名单" in plan.message


def test_cli_hub_launch_uses_only_a_hash_pinned_local_binary_and_disables_telemetry(tmp_path):
    executable = tmp_path / "trusted-tool.exe"
    executable.write_bytes(b"locally-reviewed-tool")
    allowlist = tmp_path / "cli-allowlist.json"
    allowlist.write_text(
        json.dumps(
            {
                "trusted": {
                    "executable": str(executable),
                    "sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
                }
            }
        ),
        encoding="utf-8",
    )

    plan = plan_cli_launch("trusted", "--version", allowlist_path=allowlist)

    assert plan.allowed is True
    assert plan.argv == [str(executable), "--version"]
    assert plan.env["CLI_HUB_NO_ANALYTICS"] == "1"
    assert plan.env["DO_NOT_TRACK"] == "1"
    assert not any("KEY" in k or "TOKEN" in k or "SECRET" in k for k in plan.env)


def test_cli_hub_launch_rejects_a_changed_binary(tmp_path):
    executable = tmp_path / "trusted-tool.exe"
    executable.write_bytes(b"changed-after-review")
    allowlist = tmp_path / "cli-allowlist.json"
    allowlist.write_text(
        json.dumps({"trusted": {"executable": str(executable), "sha256": "0" * 64}}),
        encoding="utf-8",
    )

    plan = plan_cli_launch("trusted", "", allowlist_path=allowlist)

    assert plan.allowed is False
    assert "哈希不匹配" in plan.message


def test_remote_package_runners_fail_closed_but_locked_sync_is_allowed():
    assert remote_install_reason("npx --yes some-tool")
    assert remote_install_reason("uvx mcp-server-fetch")
    assert remote_install_reason("pip install risky")
    assert remote_install_reason("npm install")
    assert remote_install_reason("npm ci") == ""
    assert remote_install_reason("uv sync --locked") == ""
    assert remote_install_reason("pip install --require-hashes -r requirements.txt") == ""
