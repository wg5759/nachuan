"""F6 战绩记分牌：UPSERT 累计 / 胜率 / 摘要行 / None 语义 / 降级。

隔离手法（遵守硬约束「别写死 data/ 路径」）：monkeypatch 模块级 `_db_path` 指到 tmp_path，
再 `reset()` 丢弃旧单例，让下次访问按新路径重建库——每个测试各自一份 sqlite，互不污染。
"""

from __future__ import annotations

import pytest

from orchestrator import scoreboard as sb


@pytest.fixture()
def board(monkeypatch, tmp_path):
    """把记分牌库指到本测试专属 tmp_path，收尾复位（不留常驻连接给下个测试）。"""
    db = tmp_path / "scoreboard.db"
    monkeypatch.setattr(sb, "_db_path", lambda: str(db))
    sb.reset()
    yield sb
    sb.reset()


def test_record_upsert_accumulates(board):
    """同 (model, task_kind) 多次 record 应累计到同一行（UPSERT，不新增行）。"""
    board.record("glm", "code", True)
    board.record("glm", "code", True)
    board.record("glm", "code", False)
    inst = board._get()
    assert inst.stats("glm", "code") == (2, 1)  # 2 胜 1 负累计在一行


def test_win_rate_math_and_none(board):
    """胜率 = wins/(wins+losses)；从未打过该类任务 → None（区别于胜率 0）。"""
    assert board.win_rate("kimi", "code") is None  # 无记录
    board.record("kimi", "code", True)
    board.record("kimi", "code", True)
    board.record("kimi", "code", True)
    board.record("kimi", "code", False)
    assert board.win_rate("kimi", "code") == pytest.approx(0.75)  # 3/4
    board.record("kimi", "code", False)
    board.record("kimi", "code", False)
    assert board.win_rate("kimi", "code") == pytest.approx(0.5)  # 3 胜 3 负 = 3/6


def test_win_rate_zero_is_not_none(board):
    """全败 → 胜率 0.0（是真实数据，不是 None）；确保调用方能分辨『打过但全输』。"""
    board.record("m", "reason", False)
    board.record("m", "reason", False)
    assert board.win_rate("m", "reason") == 0.0


def test_task_kind_is_isolated(board):
    """不同 task_kind 各记各的，互不串味。"""
    board.record("glm", "code", True)
    board.record("glm", "reason", False)
    assert board.win_rate("glm", "code") == 1.0
    assert board.win_rate("glm", "reason") == 0.0


def test_summary_line_orders_by_winrate(board):
    """摘要行：只列有记录的模型，按胜率降序，形如 '历史战绩[code]: a X% · b Y%'。"""
    board.record("glm", "code", True)   # glm 8/10
    for _ in range(7):
        board.record("glm", "code", True)
    board.record("glm", "code", False)
    board.record("glm", "code", False)
    board.record("kimi", "code", True)  # kimi 3/6 = 50%
    board.record("kimi", "code", True)
    board.record("kimi", "code", True)
    board.record("kimi", "code", False)
    board.record("kimi", "code", False)
    board.record("kimi", "code", False)

    line = board.summary_line(["kimi", "glm", "unknown"], "code")
    assert line.startswith("历史战绩[code]: ")
    assert "glm 80%(8/10)" in line
    assert "kimi 50%(3/6)" in line
    assert "unknown" not in line  # 无记录的不列
    # glm 胜率高 → 排在 kimi 之前
    assert line.index("glm") < line.index("kimi")


def test_summary_line_empty_when_no_data(board):
    """全部无记录 → 返回空串（提示词里就不加这行）。"""
    assert board.summary_line(["a", "b"], "code") == ""
    assert board.summary_line([], "code") == ""


def test_empty_model_record_is_noop(board):
    """空 model 不记（防脏数据），不抛异常。"""
    board.record("", "code", True)
    assert board.win_rate("", "code") is None


def test_dump_all_rows_with_win_rate_sorted(board):
    """dump_all：全表每行带 win_rate，按胜率降序（给只读看板用）。"""
    board.record("glm", "code", True)   # glm code 2/3 ≈ 0.667
    board.record("glm", "code", True)
    board.record("glm", "code", False)
    board.record("kimi", "reason", False)  # kimi reason 0/2 = 0.0
    board.record("kimi", "reason", False)
    rows = board.dump_all()
    assert len(rows) == 2
    top = rows[0]
    assert top["model"] == "glm" and top["task_kind"] == "code"
    assert top["wins"] == 2 and top["losses"] == 1
    assert top["win_rate"] == pytest.approx(2 / 3)
    assert top["last_at"]  # 有时间戳
    # 胜率降序：glm(0.667) 在 kimi(0.0) 前
    assert rows[0]["win_rate"] > rows[1]["win_rate"]
    assert rows[1]["model"] == "kimi" and rows[1]["win_rate"] == 0.0


def test_dump_all_empty_when_no_data(board):
    """空库 → dump_all 返回 []（看板显示空态）。"""
    assert board.dump_all() == []


def test_dump_all_module_level_survives_broken(monkeypatch):
    """降级：底层 dump_all 抛错时，模块级 dump_all() 静默返回 []。"""
    class _Boom:
        def dump_all(self):
            raise RuntimeError("io error")

    monkeypatch.setattr(sb, "_get", lambda: _Boom())
    assert sb.dump_all() == []


def test_record_survives_broken_db(monkeypatch, tmp_path):
    """降级：底层建库/写入抛错时，模块级 record/win_rate/summary_line 必须静默降级不炸。"""
    # 让 _get 拿到一个 record 会抛异常的假实例，验证模块级函数吞掉异常。
    class _Boom:
        def record(self, *a, **k):
            raise RuntimeError("disk full")

        def win_rate(self, *a, **k):
            raise RuntimeError("io error")

        def stats(self, *a, **k):
            raise RuntimeError("io error")

    monkeypatch.setattr(sb, "_get", lambda: _Boom())
    # 均不抛、按无数据降级
    sb.record("x", "code", True)
    assert sb.win_rate("x", "code") is None
    assert sb.summary_line(["x"], "code") == ""
