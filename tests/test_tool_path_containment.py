from __future__ import annotations

import pytest

from orchestrator import tool_agent


@pytest.mark.asyncio
@pytest.mark.parametrize("tool", ["list_dir", "read_file"])
async def test_read_tools_cannot_escape_workdir(tool, tmp_path):
    outside = tmp_path.parent / "outside-secret.txt"
    outside.write_text("secret", encoding="utf-8")

    result = await tool_agent.execute_tool(
        tool, {"path": str(outside)}, workdir=str(tmp_path)
    )

    assert "越出工作区" in result
    assert result.strip() != "secret"
