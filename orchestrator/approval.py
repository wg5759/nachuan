"""人工审核分级（P5 成本闸/重大事项 + P6 技能卡入库 共用）。

理念（机主原话）：重大事项要我审核，但"屁大点事"别打扰——所以分级：
  · 只有高风险动作（删除/部署/发布/转账/迁移…）或复盘判定"该你最终拍板"时，才挂起成"待审"。
  · 技能卡入库前先挂"待审"，机主审核通过才进案例库（P6：复盘→技能卡→待审→审核→案例库）。

前端弹窗给三个选择：同意 / 换个方案(带自定义输入) / 取消。本模块只管"待审清单"的存取与裁决，
不替机主做决定。SQLite 持久化，跨重启有效；全程安全降级，存储异常不阻断主流程。
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Optional

# 高风险关键词：命中即"重大事项"，需机主最终审核。中英都覆盖。
# 宁可漏挂（少打扰）也不滥挂——只放真正不可逆/花钱/外部可见的动作。
_HIGH_RISK = (
    "删除", "删库", "格式化", "清空", "卸载", "部署", "上线", "发布", "推送", "迁移",
    "转账", "支付", "付款", "下单", "扣款", "充值", "提现", "授权", "公开", "覆盖", "重置",
    "delete", "drop table", "rm -rf", "deploy", "publish", "release", "git push",
    "migrate", "payment", "transfer", "purchase", "withdraw", "overwrite",
    "format ", "shutdown", "--force", "production", "force push",
)

DECISIONS = ("approve", "reject", "revise")  # 同意 / 取消 / 换个方案
KINDS = ("action", "skill_card")  # 重大动作审核 / 技能卡入库审核
MIN_ACTION_TTL_SEC = 300
MAX_ACTION_TTL_SEC = 900
DEFAULT_ACTION_TTL_SEC = 600
_CAPABILITY_BASE_FIELDS = frozenset({"scope", "task", "workdir", "mode"})


def risk_level(text: str) -> str:
    """粗判风险等级：命中高风险词→high，否则→low。供"是否需要挂起审核"分级用。"""
    t = (text or "").lower()
    return "high" if any(k in t for k in _HIGH_RISK) else "low"


def needs_approval(text: str) -> bool:
    """是否需要人工审核（当前=高风险即需要）。集中此处便于以后接复盘模型判定。"""
    return risk_level(text) == "high"


# ── 硬层：动作级确定性闸（拦在 agent 真执行前，不靠模型判断、不可被绕过）──
# 这些命令在"自动写工作区"的 agent 里绝无正当用途，命中即硬拦（毁灭性、不可逆）。
# 真要做请用全开权限或手动执行。分级里"有时合理"的(普通 git push/部署)走任务级审核弹窗，不在此列。
_CATASTROPHIC: tuple[tuple[str, str], ...] = (
    (r"\bmkfs\b", "格式化磁盘"),
    (r"\bdd\b[^\n]*\bof=/dev/", "dd 写裸设备"),
    (r">\s*/dev/sd", "覆写裸磁盘"),
    (r":\(\)\s*\{", "fork 炸弹"),
    (r"\bdrop\s+(database|table)\b", "删库/删表"),
    (r"\btruncate\s+table\b", "清空表"),
    (r"\bgit\s+push\b[^\n]*(--force|\s-f\b)", "强推改写远端历史"),
    (r"\b(shutdown|reboot|halt)\b", "关机/重启"),
    (r"\bdel\s+/[a-z]", "Windows 强制删除"),
    (r"\brmdir\s+/s", "Windows 递归删目录"),
    (r"\bformat\s+[a-z]:", "格式化盘符"),
    (r"\breg\s+delete\b", "删注册表"),
    (r"remove-item\b[^\n]*-recurse", "PowerShell 递归删除"),
    # ↓ 混淆/远程执行纵深防御（深度混淆仍可绕，真解=沙箱化 run_command，见审计"待机主定"）
    (r"\brmtree\s*\(", "递归删目录(shutil.rmtree)"),  # 要 rmtree( 调用形，放行 grep rmtree 等只读
    (r"\b(curl|wget|iwr|invoke-webrequest)\b[^\n|]*\|\s*(ba|z|k|c)?sh\b", "管道执行远程脚本(curl|bash)"),
    (r"\bbase64\b[^\n]*\|\s*(ba|z|k|c)?sh\b", "base64 解码后管道执行"),
    (r"\binvoke-expression\b|\|\s*iex\b|\biex\s*\(", "PowerShell 执行任意代码(iex)"),  # 只拦 |iex / iex( 执行式，放行 Elixir iex -S mix
    (r"\bpowershell\b[^\n]*-enc(odedcommand)?\b", "PowerShell 编码命令(混淆)"),
)


def catastrophic_command(cmd: str) -> str:
    """命中即"绝不该让 agent 自动跑"的毁灭性命令。返回命中的中文描述，未命中返回空串。"""
    c = " " + (cmd or "").lower() + " "
    # rm 递归/强制删 + 危险目标（根 / 家目录 / 上级 / 通配）
    if re.search(r"\brm\b\s+-\w*[rf]\w*", c) and re.search(r"(\s|=)(/|~|\.\.|\*|\$home)", c):
        return "rm 递归删危险目标"
    for pat, label in _CATASTROPHIC:
        if re.search(pat, c):
            return label
    return ""


def escapes_workdir(workdir: str, path: str) -> bool:
    """写入路径解析后是否跑到 workdir 之外（绝对路径或 ../ 越界）→ 应拦。解析失败按越界处理(宁严勿松)。"""
    try:
        wd = os.path.realpath(workdir)
        full = os.path.realpath(path if os.path.isabs(path) else os.path.join(wd, path))
        return os.path.commonpath([wd, full]) != wd
    except Exception:  # noqa: BLE001
        return True


# ── 硬层：敏感文件读取闸（堵"读密钥→外发"的提示注入外泄链）──
# 只挡凭据/密钥类文件，不影响 agent 读别的本地文件帮用户干活。read_file 传路径、run_command 传整条命令都过它；
# 命令里出现密钥文件名（含 python -c open('connections.json') 这类）也会命中，做纵深防御
# （把文件名也深度混淆/base64 的仍可绕，属已知局限——见审计报告"待机主定"）。
_B = r"(?:^|[\s\"'/(=,;])"  # 前置分隔符：起始/空白/引号/斜杠/括号/等号/逗号/分号
_SECRET_READ_PATTERNS: tuple[str, ...] = (
    _B + r"(?:approval_admin_key|gateway_api_key)\.txt\b",
    _B + r"(?:ilink_token|sync|undo-signing-key\.protected)\.json\b",
    _B + r"connections\.json",                          # 纳川 BYOK 连接密钥（明文存 data/）
    _B + r"\.env(?:\.(?!example|sample|template|dist)[a-z0-9_-]+)?(?:$|[\s\"'/)=,;])",  # .env/.env.*，放行模板 .env.example 等
    r"/\.ssh/",                                         # ~/.ssh 目录
    _B + r"id_rsa\b", _B + r"id_ed25519\b",             # SSH 私钥（都补前置分隔符，防子串误匹配）
    r"\.pem\b", r"\.p12\b", r"\.pfx\b",                 # 证书/私钥
    r"/\.aws/credentials",                              # AWS 凭据
    _B + r"\.npmrc\b", _B + r"\.pypirc\b",              # 含发布/仓库 token
)


def reads_secret(text: str) -> str:
    """路径/命令是否在读取凭据·密钥文件。命中返回中文原因，否则空串。
    防提示注入把 API key / 私钥读出来再外发（read_file 的路径、run_command 的整条命令都传这里过一遍）。"""
    t = (text or "").replace("\\", "/").strip().lower()
    if not t:
        return ""
    for pat in _SECRET_READ_PATTERNS:
        if re.search(pat, t):
            return "凭据/密钥文件"
    return ""


_PROTECTED_BASENAMES = frozenset({
    "approval_admin_key.txt", "gateway_api_key.txt", "ilink_token.json",
    "undo-signing-key.protected.json", "sync.json",
    "connections.json", ".env", ".npmrc", ".pypirc", ".git-credentials",
    "credentials", "id_rsa", "id_ed25519",
})
_PROTECTED_SUFFIXES = (".pem", ".p12", ".pfx", ".protected.json", ".key", ".kdbx")
_RUNTIME_DATA_DIR = os.path.realpath(
    os.path.join(os.path.dirname(__file__), os.pardir, "data")
)


def is_protected_path(path: str) -> str:
    """解析后**真实路径**是否指向凭据/密钥文件。比 reads_secret(命令文本) 强：判 realpath，
    通配符/../ /软链都逃不掉。用于所有碰具体文件的受管工作区工具。
    命中返回中文原因，否则空串。
    注意：仍堵不住 run_command 里"先 copy 成无害名再读"——那需要密钥加密落盘（见审计根治项）。"""
    if not path:
        return ""
    try:
        rp = os.path.realpath(path)
    except Exception:  # noqa: BLE001
        return "路径无法解析(保守拦截)"
    low = rp.replace("\\", "/").lower()
    base = low.rsplit("/", 1)[-1]
    try:
        runtime_data = os.path.normcase(_RUNTIME_DATA_DIR)
        if os.path.commonpath([os.path.normcase(rp), runtime_data]) == runtime_data:
            return "纳川运行态数据/凭据文件"
    except (OSError, ValueError):
        return "路径无法安全归类(保守拦截)"
    # .env.* 拦真实配置，但放行模板（.env.example/.sample/.template/.dist——公开、无密钥）
    _env_tmpl = base.endswith((".example", ".sample", ".template", ".dist"))
    if base in _PROTECTED_BASENAMES or (base.startswith(".env.") and not _env_tmpl):
        return "凭据/密钥文件"
    if low.endswith(_PROTECTED_SUFFIXES):
        return "凭据/密钥文件"
    if "/.ssh/" in low or "/.aws/credentials" in low:
        return "凭据/密钥文件"
    return ""


# ── 软层：复盘模型 escalate-only 顾问（只能加码、永不放行）──
async def should_escalate(router: Any, summary: str) -> tuple[bool, str]:
    """让便宜/免费模型判断一个【待执行动作】是否该请机主最终拍板。**只能加码**——
    调用方用 OR 接：硬层 or 软层，任一要审就审。模型出错/被提示注入绕过，最多=不升级、
    退回硬层兜底，绝不会因此放过硬层已拦的东西（这正是"escalate-only"的安全点）。
    用 free 模型(agnes-flash)，无 token 成本。返回 (是否升级, 一句话原因)。"""
    summary = (summary or "").strip()
    if not summary:
        return False, ""
    # 只读动词短路（机主实测"分析下这个项目"被软层误挂）：分析/查看/总结类只读任务
    # 且不含高风险词 → 直接放行，0 次模型调用。软层只管真正可能不可逆的动作。
    _READONLY = ("分析", "查看", "看看", "看下", "读", "总结", "检查", "审查", "统计", "列出",
                 "对比", "评估", "介绍", "解释", "analyz", "review", "read", "list", "check",
                 "summar", "inspect", "explain")
    head = summary[:60].lower()
    if any(k in head for k in _READONLY) and risk_level(summary) != "high":
        return False, ""
    from gateway.failover import chat_with_fallback
    from gateway.provider_call_ledger import bind_provider_call_scope
    from gateway.schemas import ChatCompletionRequest
    from orchestrator.modes import pick_model

    cheap = "agnes-flash" if router.resolve("agnes-flash") else pick_model(router, "cheap")
    if not cheap:
        return False, ""
    ask = (
        "你是机主的安全复盘官。判断下面这个【即将执行的动作】是否风险高到需要机主本人最终拍板"
        "（重点：不可逆、花真钱、对外发布/发送、删除数据、动生产环境、改权限、影响范围过大）。"
        "日常、只读、可撤销的小事一律放行。只回一行：需要就回 `ESCALATE:<一句话原因>`，否则回 `OK`。\n\n"
        f"动作：{summary}"
    )
    try:
        req = ChatCompletionRequest(model=cheap, messages=[{"role": "user", "content": ask}])  # type: ignore[arg-type]
        with bind_provider_call_scope(role="approval.risk_assessment"):
            res, _served, _route = await chat_with_fallback(router, req)
        out = ((res.get("choices") or [{}])[0].get("message", {}).get("content") or "").strip()
        if out.upper().startswith("ESCALATE"):
            reason = out.split(":", 1)[-1] if ":" in out else (out.split("：", 1)[-1] if "：" in out else "")
            return True, (reason.strip() or "复盘判定需审核")[:80]
    except Exception:  # noqa: BLE001
        pass  # 模型不可用/出错 → 不升级，退回硬层兜底
    return False, ""


class ApprovalStore:
    """待审事项库。kind=action(重大动作) / skill_card(技能卡)。SQLite，进程内加锁。"""

    def __init__(self, db_path: str, *, action_ttl_sec: int = DEFAULT_ACTION_TTL_SEC):
        if (
            isinstance(action_ttl_sec, bool)
            or not isinstance(action_ttl_sec, int)
            or not MIN_ACTION_TTL_SEC <= action_ttl_sec <= MAX_ACTION_TTL_SEC
        ):
            raise ValueError(
                f"action_ttl_sec must be between {MIN_ACTION_TTL_SEC} and "
                f"{MAX_ACTION_TTL_SEC} seconds"
            )
        self._action_ttl_sec = action_ttl_sec
        p = Path(db_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(p), check_same_thread=False)
        self._lock = threading.Lock()
        self._init()

    def _init(self) -> None:
        with self._lock:
            self._conn.execute(
                """CREATE TABLE IF NOT EXISTS approvals (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    payload TEXT,
                    status TEXT NOT NULL DEFAULT 'pending',
                    note TEXT,
                    created_at REAL,
                    resolved_at REAL,
                    expires_at REAL
                )"""
            )
            columns = {
                str(row[1])
                for row in self._conn.execute("PRAGMA table_info(approvals)").fetchall()
            }
            if "expires_at" not in columns:
                self._conn.execute("ALTER TABLE approvals ADD COLUMN expires_at REAL")
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_appr_user ON approvals(user_id, status)"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_appr_expiry "
                "ON approvals(kind, status, expires_at)"
            )
            # Legacy action rows had no expiry and therefore no bounded authority.
            # Invalidate them on migration rather than inventing a fresh lease.
            self._expire_actions_locked(time.time())
            self._conn.commit()

    def _expire_actions_locked(self, now: float, approval_id: int | None = None) -> bool:
        where_id = " AND id=?" if approval_id is not None else ""
        probe_params: tuple[Any, ...] = (
            (now, approval_id) if approval_id is not None else (now,)
        )
        candidate = self._conn.execute(
            "SELECT 1 FROM approvals WHERE kind='action' "
            "AND status IN ('pending','approved','revise') "
            "AND (expires_at IS NULL OR expires_at<=?)" + where_id + " LIMIT 1",
            probe_params,
        ).fetchone()
        if candidate is None:
            return False
        update_params: tuple[Any, ...] = (
            (now, now, approval_id) if approval_id is not None else (now, now)
        )
        self._conn.execute(
            "UPDATE approvals SET status='expired', resolved_at=COALESCE(resolved_at, ?) "
            "WHERE kind='action' AND status IN ('pending','approved','revise') "
            "AND (expires_at IS NULL OR expires_at<=?)" + where_id,
            update_params,
        )
        return True

    @staticmethod
    def _select_columns() -> str:
        return (
            "id,user_id,kind,summary,payload,status,note,created_at,resolved_at,expires_at"
        )

    def _get_locked(self, approval_id: int) -> Optional[dict[str, Any]]:
        r = self._conn.execute(
            f"SELECT {self._select_columns()} FROM approvals WHERE id=?",
            (approval_id,),
        ).fetchone()
        return self._row(r) if r else None

    def create(
        self, user_id: str, kind: str, summary: str, payload: Optional[dict[str, Any]] = None
    ) -> int:
        """挂起一条待审。summary=给机主看的动作摘要/技能卡标题；payload=细节(json)。"""
        summary = (summary or "").strip()
        if not user_id or kind not in KINDS or not summary:
            return 0
        encoded_payload = json.dumps(payload or {}, ensure_ascii=False, sort_keys=True)
        # 防刷屏：技能卡按标题去重；动作 capability 必须连 payload（scope/task/workdir/mode）
        # 一起相同才复用，不能让同标题的另一目录/权限请求拿到错误凭证。
        with self._lock:
            created_at = time.time()
            self._expire_actions_locked(created_at)
            candidates = self._conn.execute(
                "SELECT id,payload FROM approvals WHERE user_id=? AND kind=? AND summary=? AND status='pending'",
                (user_id, kind, summary),
            ).fetchall()
            for dup_id, dup_payload in candidates:
                if kind != "action":
                    self._conn.commit()
                    return int(dup_id)
                try:
                    canonical = json.dumps(
                        json.loads(dup_payload or "{}"), ensure_ascii=False, sort_keys=True
                    )
                except (TypeError, json.JSONDecodeError):
                    continue
                if canonical == encoded_payload:
                    self._conn.commit()
                    return int(dup_id)
            cur = self._conn.execute(
                "INSERT INTO approvals "
                "(user_id, kind, summary, payload, status, created_at, expires_at) "
                "VALUES (?,?,?,?, 'pending', ?, ?)",
                (
                    user_id,
                    kind,
                    summary,
                    encoded_payload,
                    created_at,
                    created_at + self._action_ttl_sec if kind == "action" else None,
                ),
            )
            self._conn.commit()
            return int(cur.lastrowid or 0)

    def _row(self, r: Any) -> dict[str, Any]:
        try:
            payload = json.loads(r[4]) if r[4] else {}
        except Exception:  # noqa: BLE001
            payload = {}
        return {
            "id": r[0], "user_id": r[1], "kind": r[2], "summary": r[3],
            "payload": payload, "status": r[5], "note": r[6],
            "created_at": r[7], "resolved_at": r[8], "expires_at": r[9],
        }

    def list_pending(self, user_id: str, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            changed = self._expire_actions_locked(time.time())
            rows = self._conn.execute(
                f"SELECT {self._select_columns()} "
                "FROM approvals WHERE user_id=? AND status='pending' ORDER BY created_at ASC LIMIT ?",
                (user_id, limit),
            ).fetchall()
            if changed:
                self._conn.commit()
        return [self._row(r) for r in rows]

    def count_pending(self, user_id: str) -> int:
        with self._lock:
            changed = self._expire_actions_locked(time.time())
            count = int(
                self._conn.execute(
                    "SELECT COUNT(*) FROM approvals WHERE user_id=? AND status='pending'",
                    (user_id,),
                ).fetchone()[0]
            )
            if changed:
                self._conn.commit()
            return count

    def get(self, approval_id: int) -> Optional[dict[str, Any]]:
        with self._lock:
            changed = self._expire_actions_locked(time.time(), approval_id)
            record = self._get_locked(approval_id)
            if changed:
                self._conn.commit()
        return record

    def approved_action_spec(
        self, approval_id: int, *, scope: str
    ) -> Optional[dict[str, Any]]:
        """Read a server-persisted action specification before atomically claiming it.

        Callers use this only to reconstruct the exact request fields that were shown
        for approval. ``claim_action`` remains the atomic authority and must still be
        called afterwards; this read never grants permission by itself.
        """
        rec = self.get(approval_id)
        if (
            not rec
            or rec.get("kind") != "action"
            or rec.get("status") != "approved"
        ):
            return None
        payload = rec.get("payload")
        if not isinstance(payload, dict) or str(payload.get("scope") or "agent_exec") != scope:
            return None
        return rec

    def resolve(self, approval_id: int, decision: str, note: str = "") -> Optional[dict[str, Any]]:
        """裁决一条待审：approve(同意)/reject(取消)/revise(换方案，note=机主自定义说明)。
        返回更新后的记录（含原 payload，便于调用方据此执行后续，如技能卡入库）。"""
        if decision not in DECISIONS:
            return None
        status = {"approve": "approved", "reject": "rejected", "revise": "revise"}[decision]
        with self._lock:
            now = time.time()
            self._expire_actions_locked(now, approval_id)
            current = self._get_locked(approval_id)
            if current is None or current["status"] != "pending":
                self._conn.commit()
                return current
            self._conn.execute(
                "UPDATE approvals SET status=?, note=?, resolved_at=? "
                "WHERE id=? AND status='pending'",
                (status, (note or "").strip(), now, approval_id),
            )
            current = self._get_locked(approval_id)
            self._conn.commit()
        return current

    def claim_action(
        self,
        approval_id: int,
        *,
        user_id: str,
        task: str,
        workdir: str,
        scope: str = "agent_exec",
        mode: str = "plan",
        manifest: Optional[dict[str, Any]] = None,
    ) -> bool:
        """Atomically consume an approved capability bound to scope, task and workdir.

        Older rows without a scope belong only to ``agent_exec``; this prevents a token
        approved for one execution surface from being replayed against another.
        """
        with self._lock:
            now = time.time()
            expired_changed = self._expire_actions_locked(now, approval_id)

            def deny() -> bool:
                if expired_changed:
                    self._conn.commit()
                return False

            row = self._conn.execute(
                "SELECT user_id,kind,payload,status,note,expires_at FROM approvals WHERE id=?",
                (approval_id,),
            ).fetchone()
            if not row or row[0] != user_id or row[1] != "action" or row[3] != "approved":
                return deny()
            try:
                payload = json.loads(row[2] or "{}")
            except (TypeError, json.JSONDecodeError):
                return deny()
            if not isinstance(payload, dict):
                return deny()
            expected_scope = str(payload.get("scope") or "agent_exec")
            if expected_scope != str(scope or ""):
                return deny()
            expected_mode = str(payload.get("mode") or "plan")
            if expected_mode != str(mode or ""):
                return deny()
            actual_manifest = {} if manifest is None else manifest
            if not isinstance(actual_manifest, dict):
                return deny()
            expected_manifest = {
                key: value
                for key, value in payload.items()
                if key not in _CAPABILITY_BASE_FIELDS
            }
            # Closed set in both directions: the caller may neither omit a reviewed
            # field nor smuggle in a new one at claim time.
            if set(actual_manifest) != set(expected_manifest):
                return deny()
            for key, actual_value in actual_manifest.items():
                expected_value = expected_manifest[key]
                try:
                    expected_json = json.dumps(expected_value, ensure_ascii=False, sort_keys=True)
                    actual_json = json.dumps(actual_value, ensure_ascii=False, sort_keys=True)
                except (TypeError, ValueError):
                    return deny()
                if expected_json != actual_json:
                    return deny()
            expected_task = str(payload.get("task") or "")
            if expected_task != str(task or ""):
                return deny()
            try:
                expected = os.path.normcase(os.path.realpath(str(payload.get("workdir") or "")))
                actual = os.path.normcase(os.path.realpath(str(workdir or "")))
            except Exception:  # noqa: BLE001
                return deny()
            if expected != actual:
                return deny()
            cur = self._conn.execute(
                "UPDATE approvals SET status='executing' "
                "WHERE id=? AND status=? AND kind='action' "
                "AND expires_at IS NOT NULL AND expires_at>?",
                (approval_id, row[3], now),
            )
            self._conn.commit()
            return cur.rowcount == 1

    def finish_action(self, approval_id: int, *, success: bool) -> None:
        """Close a claimed one-time capability; failure never makes it replayable.

        A tool may have produced an external side effect before the caller observed an
        exception. Retrying requires a newly approved capability (and ideally an
        idempotency key at the external system), never resurrection of this token.
        """
        with self._lock:
            self._conn.execute(
                "UPDATE approvals SET status=?, resolved_at=? WHERE id=? AND status='executing'",
                ("executed" if success else "execution_failed", time.time(), approval_id),
            )
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()
