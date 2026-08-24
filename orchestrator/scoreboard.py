"""F6 战绩记分牌（Fugu「零训练学习路由」的在线免费版）。

思路（见 FUGU方案.md 第 25、56-59 行）：不训练 0.6B 协调器，改用**在线 bandit-lite**——
复用编排里既有的验证闸（PASS→win / FAIL→loss）+ 执行停滞（stall→loss），按「任务类别」记
每个模型的胜负；池子快照/点将官提示词消费这份战绩，路由偏向历史赢家。随使用自动进化，
不用「双周重训」。

存储：独立 sqlite 库 `data/scoreboard.db`（与 usage.db/knowledge.db 分开，坏了不牵连主库）。
沿用本项目 usage.py / knowledge.py 的写法：进程内加锁的常驻连接（check_same_thread=False）。

**降级第一**：记分牌是「锦上添花」，绝不能反过来拖垮编排主流程——所有对外 API 一律 try/except
吞掉异常静默降级（写失败当没记，读失败当无数据）。测试用 monkeypatch `_db_path` + `reset()`
把库指到 tmp_path，互不污染。
"""

from __future__ import annotations

import os
import sqlite3
import threading
import time
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
# 与 cloud_sync.py 同一套 data 目录约定（DATA_DIR 可覆盖，默认 仓库根/data）。
_DATA = Path(os.getenv("DATA_DIR") or (_REPO / "data"))


def _db_path() -> str:
    """记分牌库路径（可被测试 monkeypatch 指到 tmp_path，避免污染真实 data/）。"""
    return str(_DATA / "scoreboard.db")


class Scoreboard:
    """按 (model, task_kind) 累计胜负；SQLite + 进程内锁（风格同 usage/knowledge）。"""

    def __init__(self, db_path: str):
        p = Path(db_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(p), check_same_thread=False)
        self._lock = threading.Lock()
        self._init()

    def _init(self) -> None:
        with self._lock:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scoreboard (
                    model TEXT NOT NULL,
                    task_kind TEXT NOT NULL,
                    wins INTEGER NOT NULL DEFAULT 0,
                    losses INTEGER NOT NULL DEFAULT 0,
                    last_at TEXT,
                    PRIMARY KEY (model, task_kind)
                )
                """
            )
            self._conn.commit()

    def record(self, model: str, task_kind: str, win: bool) -> None:
        """记一场战绩（UPSERT）：win=True → wins+1，否则 losses+1，并刷新 last_at。"""
        if not model:
            return
        kind = task_kind or "general"
        now = time.strftime("%Y-%m-%dT%H:%M:%S")
        win_inc = 1 if win else 0
        loss_inc = 0 if win else 1
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO scoreboard (model, task_kind, wins, losses, last_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(model, task_kind) DO UPDATE SET
                    wins = wins + excluded.wins,
                    losses = losses + excluded.losses,
                    last_at = excluded.last_at
                """,
                (model, kind, win_inc, loss_inc, now),
            )
            self._conn.commit()

    def _record_raw(self, model: str, task_kind: str) -> tuple[int, int] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT wins, losses FROM scoreboard WHERE model=? AND task_kind=?",
                (model, task_kind or "general"),
            ).fetchone()
        if row is None:
            return None
        return int(row[0] or 0), int(row[1] or 0)

    def win_rate(self, model: str, task_kind: str) -> float | None:
        """该模型在该类任务的历史胜率 wins/(wins+losses)；无任何记录返回 None。"""
        rec = self._record_raw(model, task_kind)
        if rec is None:
            return None
        wins, losses = rec
        total = wins + losses
        if total <= 0:
            return None
        return wins / total

    def stats(self, model: str, task_kind: str) -> tuple[int, int] | None:
        """(wins, losses)；无记录返回 None。给摘要行拼 "80%(8/10)" 用。"""
        return self._record_raw(model, task_kind)

    def dump_all(self) -> list[dict]:
        """全表快照（给只读战绩看板 GET /v1/scoreboard）：每行含胜率，按胜率降序。

        风格照旧「降级第一」：查询出错返回 []（看板显示空态，不牵连主流程）。
        """
        try:
            with self._lock:
                cur = self._conn.execute(
                    "SELECT model, task_kind, wins, losses, last_at FROM scoreboard"
                )
                raw = cur.fetchall()
        except Exception:  # noqa: BLE001 记分牌库坏了不能拖垮看板/主流程
            return []
        rows: list[dict] = []
        for model, task_kind, wins, losses, last_at in raw:
            w = int(wins or 0)
            l = int(losses or 0)  # noqa: E741 (胜负计数，l=losses 语义清晰)
            total = w + l
            rows.append({
                "model": model,
                "task_kind": task_kind,
                "wins": w,
                "losses": l,
                "win_rate": (w / total) if total > 0 else None,
                "last_at": last_at,
            })
        # 胜率降序（None/无场次垫底），并列按总场次多者靠前——一眼看谁是靠谱主力。
        rows.sort(key=lambda r: (r["win_rate"] if r["win_rate"] is not None else -1.0,
                                 r["wins"] + r["losses"]), reverse=True)
        return rows

    def close(self) -> None:
        with self._lock:
            self._conn.close()


# ── 模块级懒单例：对外函数走它；monkeypatch _db_path 后调 reset() 即切库 ──
_instance: Scoreboard | None = None
_inst_lock = threading.Lock()


def _get() -> Scoreboard | None:
    """取（或懒建）全局记分牌实例；建库失败返回 None（让上层静默降级）。"""
    global _instance
    if _instance is not None:
        return _instance
    with _inst_lock:
        if _instance is None:
            try:
                _instance = Scoreboard(_db_path())
            except Exception:  # noqa: BLE001 建库失败也不能拖垮主流程
                return None
    return _instance


def reset() -> None:
    """丢弃当前实例（测试隔离用：换了 _db_path 后调它，下次 _get 会按新路径重建）。"""
    global _instance
    with _inst_lock:
        if _instance is not None:
            try:
                _instance.close()
            except Exception:  # noqa: BLE001
                pass
        _instance = None


def record(model: str, task_kind: str, win: bool) -> None:
    """记一场战绩（模块级入口，异常全吞——记分牌坏了绝不影响编排）。"""
    try:
        sb = _get()
        if sb is not None:
            sb.record(model, task_kind, win)
    except Exception:  # noqa: BLE001
        pass


def win_rate(model: str, task_kind: str) -> float | None:
    """该模型在该类任务的历史胜率；无记录或出错返回 None。"""
    try:
        sb = _get()
        return sb.win_rate(model, task_kind) if sb is not None else None
    except Exception:  # noqa: BLE001
        return None


def stats(model: str, task_kind: str) -> tuple[int, int] | None:
    """该模型在该类任务的 (wins, losses)；无记录或出错返回 None。

    给「首轮点将短路」（coordinator.pick_by_record）判场次是否够用。模块级入口，异常全吞
    ——记分牌坏了当无数据（返回 None），绝不影响编排/短路降级。
    """
    try:
        sb = _get()
        return sb.stats(model, task_kind) if sb is not None else None
    except Exception:  # noqa: BLE001
        return None


def dump_all() -> list[dict]:
    """全表战绩快照（模块级入口，给只读端点用）；单例未建或出错一律返回 []。"""
    try:
        sb = _get()
        return sb.dump_all() if sb is not None else []
    except Exception:  # noqa: BLE001 记分牌坏了当无数据，绝不炸看板
        return []


def summary_line(models: list[str], task_kind: str) -> str:
    """给点将官/快照提示词的一行历史战绩摘要（按胜率降序，只列有记录的）。

    形如：`历史战绩[code]: glm 80%(8/10) · kimi 50%(3/6)`；全都无记录时返回 ""。
    异常一律吞掉返回 ""（提示词里没这行不影响功能）。
    """
    try:
        sb = _get()
        if sb is None:
            return ""
        kind = task_kind or "general"
        items: list[tuple[str, float, int, int]] = []
        for m in models or []:
            rec = sb.stats(m, kind)
            if rec is None:
                continue
            wins, losses = rec
            total = wins + losses
            if total <= 0:
                continue
            items.append((m, wins / total, wins, total))
        if not items:
            return ""
        items.sort(key=lambda x: x[1], reverse=True)
        parts = [f"{m} {round(rate * 100)}%({wins}/{total})" for m, rate, wins, total in items]
        return f"历史战绩[{kind}]: " + " · ".join(parts)
    except Exception:  # noqa: BLE001
        return ""
