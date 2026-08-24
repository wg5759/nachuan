"""Repository instruction surfaces must agree on the active review roster."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).parents[1]


def test_claude_instruction_surface_cannot_reactivate_anthropic() -> None:
    text = (ROOT / "CLAUDE.md").read_text("utf-8")

    assert "Claude/Anthropic 已退出现役花名册" in text
    assert "Moonshot/Kimi K3" in text
    assert "Anthropic/Opus" not in text
    assert "Moonshot/Kimi-K2.7" not in text


def test_legacy_claude_xreview_command_is_a_fail_closed_notice() -> None:
    text = (ROOT / ".claude" / "commands" / "xreview.md").read_text("utf-8")

    assert "Claude/Anthropic 已退出现役花名册" in text
    assert "Moonshot/Kimi K3" in text
    assert "正式模式会在启动任何模型前退出 78" in text
    assert "运行 `bash scripts/xreview.sh" not in text
    assert "Kimi-K2.6" not in text
