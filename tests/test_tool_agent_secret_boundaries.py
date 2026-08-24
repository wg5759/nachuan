from __future__ import annotations

from orchestrator.tool_agent import execute_tool


async def test_read_file_cannot_exfiltrate_runtime_credentials(tmp_path):
    secret_names = (
        "approval_admin_key.txt",
        "data/approval_admin_key.txt",
        "gateway_api_key.txt",
        "ilink_token.json",
        "undo-signing-key.protected.json",
        "sync.json",
    )
    for name in secret_names:
        marker = f"NEVER-LEAK-{name}"
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(marker, encoding="utf-8")
        result = await execute_tool("read_file", {"path": name}, workdir=str(tmp_path))
        assert "拦截" in result
        assert marker not in result


async def test_read_file_still_allows_normal_workspace_source(tmp_path):
    (tmp_path / "README.md").write_text("public documentation", encoding="utf-8")
    result = await execute_tool("read_file", {"path": "README.md"}, workdir=str(tmp_path))
    assert result == "public documentation"
