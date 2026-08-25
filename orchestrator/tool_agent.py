"""Model-agnostic Agent 循环（超级智能体的心脏）。

让**任何会 function-calling 的模型**（Agnes/GLM/Kimi/MiniMax/GPT…，不止 claude/codex）在一个对话里
使用受管工作区文件与纯聊天协作工具。模型返回 tool_calls → 引擎执行 → 结果回喂 → 循环到完成。

claude/codex 是借它们 CLI 自带的 agent 循环；这套是我们自写的、对所有模型通用——这才是统一的超级体。
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import stat
import tempfile
import time
from pathlib import Path
from typing import Any, Optional

from gateway.agent_contract import normalize_legacy_agent_result
from gateway.failover import chat_with_fallback
from gateway.media_call_metering import (
    generate_image_with_accounting,
    generate_video_with_accounting,
)
from gateway.provider_call_ledger import (
    bind_provider_call_scope,
    current_provider_call_context,
)
from gateway.route_attestation import (
    bind_agent_author_receipt,
    canonical_agent_output,
)
from gateway.runtime_profile import RuntimeCapability, current_runtime_profile
from gateway.schemas import ChatCompletionRequest
from orchestrator import skills
from orchestrator.approval import escapes_workdir, is_protected_path, reads_secret
from orchestrator.plugin_kernel import PluginKernel
from orchestrator.workflows.common import route_receipt
from orchestrator.workspace_guard import WorkspaceBoundaryError, resolve_workspace


_WORKSPACE_TOUCHING_TOOLS = frozenset(
    {
        "remember",
        "list_dir",
        "read_file",
        "write_file",
        "generate_video",
    }
)

# ---- 工具 schema（OpenAI function-calling 格式）----
TOOLS: list[dict[str, Any]] = [
    {"type": "function", "function": {"name": "remember", "description": "把一条**该长期记住**的关键信息写进本任务的记忆银行（跨会话保留、续跑时自动带回，借鉴 RooFlow）：kind='决策'（为什么这么选/定了什么）或 '约定'（项目惯例/踩过的坑/规范）。只记**少数真正重要**的，别把流水账/每步进展塞这里。", "parameters": {"type": "object", "properties": {"kind": {"type": "string", "description": "决策 或 约定"}, "text": {"type": "string", "description": "要长期记住的一句话"}}, "required": ["text"]}}},
    {"type": "function", "function": {"name": "list_dir", "description": "列出目录内容。path 可为相对路径或 D:\\ 这类本机绝对路径；recursive=true 可递归列出，目录审查先用它。", "parameters": {"type": "object", "properties": {"path": {"type": "string"}, "recursive": {"type": "boolean"}, "max_entries": {"type": "integer", "description": "最多返回多少项，默认 200，最大 1000"}}, "required": ["path"]}}},
    {"type": "function", "function": {"name": "read_file", "description": "读文本文件内容。path 可为相对路径或 D:\\ 这类本机绝对路径；如果是目录请先用 list_dir。", "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}}},
    {"type": "function", "function": {"name": "write_file", "description": "写文件（覆盖；相对路径基于工作目录）。", "parameters": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}}, "required": ["path", "content"]}}},
    {"type": "function", "function": {"name": "list_models", "description": "列出当前已接入、可咨询的聊天模型 id（如 glm/kimi/minimax/gpt/agnes）。", "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {"name": "ask_model", "description": "把一个明确子问题转给另一个已接入聊天模型审查/回答，并返回它的意见。需要多模型协作时用它，不要假装已经问过。", "parameters": {"type": "object", "properties": {"model": {"type": "string", "description": "模型 id，例如 glm、kimi、minimax、gpt-5.5、gpt-5.4"}, "prompt": {"type": "string", "description": "发给该模型的完整问题和必要上下文"}}, "required": ["model", "prompt"]}}},
    {"type": "function", "function": {"name": "list_skills", "description": "列出当前可用技能（名字+一句话）。不确定有没有现成技能能省事时先看一眼。", "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {"name": "load_skill", "description": "加载某技能的详细步骤（SKILL.md 全文）再照做。先用 list_skills 看有哪些。", "parameters": {"type": "object", "properties": {"name": {"type": "string", "description": "技能名"}}, "required": ["name"]}}},
    {"type": "function", "function": {"name": "generate_image", "description": "任务里需要图片/插画/海报/配图时，用平台的图模型按描述生成一张并贴进对话。", "parameters": {"type": "object", "properties": {"prompt": {"type": "string", "description": "图片内容描述"}}, "required": ["prompt"]}}},
    {"type": "function", "function": {"name": "generate_video", "description": "生成视频（异步，返回任务号，耗时数分钟）。【时长】用户说了几秒/几分钟就**必须传 seconds**（如“20秒”→seconds=20），不传=默认只有5秒；单段上限约18秒。【图】会话中上传/刚生成的图片默认自动带入做图生视频；但**用户要的视频主题与会话图片无关时（如图是人物、用户要小猫跳舞）必须传 no_image=true 做纯文生视频**，别把不相关的图硬塞进视频；用户明说“让这张图/画里的人动起来”才用会话图。不要猜测或编造 image URL。可传 size=分辨率如 720x1280(竖屏)/1280x720(横屏)。⚠️只在用户【明确要做视频】时调用；用户问“做好了没/进度”时**绝不要再调它**（那会重复创建新任务），直接用文字告诉用户仍在后台生成中即可。一次任务只调一次。", "parameters": {"type": "object", "properties": {"prompt": {"type": "string", "description": "视频内容/画面/运镜描述"}, "image": {"type": "string", "description": "仅限用户明确给出的真实本地图片/纯base64；会话图片无需填写，绝不编造 URL。可选"}, "no_image": {"type": "boolean", "description": "true=纯文生视频，忽略会话里的图片（视频主题与会话图片无关时必传 true）。可选"}, "seconds": {"type": "number", "description": "时长秒数（用户说了时长就必须传！），最长约18秒，默认5。"}, "size": {"type": "string", "description": "分辨率 WxH，如 720x1280(竖屏) 或 1280x720(横屏)。可选"}, "negative_prompt": {"type": "string", "description": "不想要的内容。可选"}}, "required": ["prompt"]}}},
    {"type": "function", "function": {"name": "generate_long_video", "description": "生成**长视频**（>18秒~10分钟，如1分钟/5分钟/10分钟）：自动分镜→逐镜生成(末帧接首帧保持画面连贯)→拼接成片。全程引擎后台跑，用户期间可继续聊天干别的，成片自动贴回对话。耗时较长（约每15秒片长需1-3分钟生成）。用户要 ≤18 秒的短视频用 generate_video，别用这个。一次任务只调一次，问进度绝不重复调。", "parameters": {"type": "object", "properties": {"goal": {"type": "string", "description": "视频目标/内容/风格描述（会先自动出分镜再逐镜生成）"}, "total_seconds": {"type": "number", "description": "总时长秒数（19~600）。用户说'5分钟'→300"}, "size": {"type": "string", "description": "分辨率 WxH，如 720x1280(竖屏)/1280x720(横屏)。可选"}}, "required": ["goal", "total_seconds"]}}},
    {"type": "function", "function": {"name": "web_read", "description": "读取网页正文并（可选）按问题总结，适合读文章/文档链接。视频链接请改用 lapian。", "parameters": {"type": "object", "properties": {"url": {"type": "string", "description": "网页地址"}, "question": {"type": "string", "description": "想从这篇网页得到什么，可选；不填则给要点总结"}}, "required": ["url"]}}},
    {"type": "function", "function": {"name": "lapian", "description": "对抖音/B站/YouTube 等视频链接做拆解（拉片）报告：逐帧分析画面/镜头/文字+台词，产出可复刻 SOP。耗时较长（分钟级）。", "parameters": {"type": "object", "properties": {"url": {"type": "string", "description": "视频分享链接（支持粘贴带口令的分享文本）"}}, "required": ["url"]}}},
    {"type": "function", "function": {"name": "kb_query", "description": "查用户个人知识库（此前导入的文档），返回最相关的片段。", "parameters": {"type": "object", "properties": {"query": {"type": "string", "description": "检索问题/关键词"}}, "required": ["query"]}}},
    {"type": "function", "function": {"name": "translate", "description": "把一段文本翻译成目标语言。", "parameters": {"type": "object", "properties": {"text": {"type": "string", "description": "要翻译的文本"}, "target": {"type": "string", "description": "目标语种，如 中文/英文/en/ja"}}, "required": ["text", "target"]}}},
]

_DISABLED_HOST_BROWSER_TOOLS = frozenset({
    "browser_open", "browser_read", "browser_click", "browser_type",
    "browser_scroll", "browser_screenshot", "browser_eval", "browser_upload",
})
# The embedded browser shares the owner's authenticated profile.  Until it has
# an isolated profile plus exact origin/action capabilities, model control is
# disabled.  Old tool names remain recognized only by execute_tool's explicit
# fail-closed branch; no executable implementation or provider schema remains.

# 所有已注册工具名（供 A1 未知工具纠错回喂用；execute_tool 之外唯一权威来源）。
_TOOL_NAMES = frozenset(t["function"]["name"] for t in TOOLS)
_PLUGIN_MIGRATED_TOOL_NAMES = frozenset({"list_skills", "load_skill"})


def _router_plugin_kernel(router: Any) -> PluginKernel | None:
    if router is None:
        return None
    try:
        candidate = getattr(router, "plugin_kernel", None)
    except Exception:  # noqa: BLE001 -- optional legacy router seam
        return None
    return candidate if isinstance(candidate, PluginKernel) else None


def _runtime_tools(router: Any) -> list[dict[str, Any]]:
    """Project legacy schemas plus the exact tools active in this Router kernel."""

    kernel = _router_plugin_kernel(router)
    if kernel is None:
        return list(TOOLS)
    legacy = [
        item
        for item in TOOLS
        if item["function"]["name"] not in _PLUGIN_MIGRATED_TOOL_NAMES
    ]
    plugin_schemas = list(kernel.tool_schemas())
    legacy_names = {item["function"]["name"] for item in legacy}
    plugin_names = [item["function"]["name"] for item in plugin_schemas]
    if len(plugin_names) != len(set(plugin_names)) or legacy_names & set(plugin_names):
        raise RuntimeError("plugin tool schema conflicts with the legacy closed set")
    return [*legacy, *plugin_schemas]

# agent 累积上下文压缩：保留最近这么多条消息不压（含最新一步），更早的 tool 结果才压。
_KEEP_RECENT = 4
# 单条 tool 结果短于此字符数不压（短结果省不下、也更易失真）。
_COMPRESS_TOOL_MIN = 600
_MAX_TOOL_TEXT_BYTES = 2 * 1024 * 1024
_MAX_STARTUP_FILE_BYTES = 256 * 1024
_REPARSE_ATTRIBUTE = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
_STARTUP_SCAN_ENTRIES = 80

# The durable paid-media v2 operation/asset/ACK chain is not connected to the
# generic Agent tool path yet.  Keep this a source-owned closed gate: an
# environment variable or a model-supplied argument must never enable charges.
_TOOL_AGENT_PAID_MEDIA_V2_WIRED = False
_IMAGE_GENERATION_UNAVAILABLE = "图片生成功能暂不可用；本次未生成图片，也不会产生费用。"
_VIDEO_GENERATION_UNAVAILABLE = "视频生成功能暂不可用；本次未创建视频任务，也不会产生费用。"


def _seal_tool_agent_result(
    result: dict[str, Any], *, outcome: str
) -> dict[str, Any]:
    """Attach and validate the truthful terminal contract at the producer."""

    result.update(
        {
            "outcome": outcome,
            "blocked": outcome in {"blocked", "rejected_capacity"},
            "reviewed": False,
            "verified": False,
            "machine_verified": False,
        }
    )
    actual_model = result.get("actual_model")
    if (
        isinstance(actual_model, str)
        and actual_model
        and result.get("model") == actual_model
        and isinstance(result.get("reply"), str)
    ):
        for receipt in reversed(result.get("author_receipts") or []):
            if not isinstance(receipt, dict):
                continue
            if str(receipt.get("actual_model") or "").strip() != actual_model:
                continue
            try:
                result["final_route_receipt"] = bind_agent_author_receipt(
                    receipt,
                    reply=result["reply"],
                )
            except ValueError:
                pass
            break
    return normalize_legacy_agent_result(result)


# ---- A1/A2：可靠性硬化参数 ----
# 同一个工具的参数反复解析失败，最多回喂这么多次纠错提示，超了就带部分成果收尾（防在修复上死循环）。
_MAX_ARG_REPAIRS = 3
# 同一调用签名（工具名+规整化参数）重复达到此次数 → 注入"你在原地打转"提示。
_STALL_REPEAT_LIMIT = 3
# 步数快用完时，剩余步数 ≤ 此值就软提示模型尽快收尾。
_SOFT_WRAPUP_STEPS = 2
# 墙钟硬预算（「422 分钟失控」根修）：步数闸拦不住慢速空转——单跳最长 600s × 最多 200 步
# = 理论 30+ 小时。唯一可靠的总闸是墙钟：到点不硬杀，带部分成果优雅收尾（_finalize("wall_cap")）。
try:
    _WALL_MIN = max(5, int(os.environ.get("NACHUAN_AGENT_WALL_MIN") or 45))
except ValueError:
    _WALL_MIN = 45

# 墙钟策略时钟单独暴露给确定性回归测试；生产仍绑定 time.monotonic，绝不受系统时钟回拨影响。
_wall_now = time.monotonic


def new_wall_deadline() -> float:
    """一次用户请求配一个 deadline（time.monotonic() 秒）。编排的验证轮/升级重跑共享
    同一预算、不重置——否则每次重跑都续命，总闸形同虚设。"""
    return _wall_now() + _WALL_MIN * 60


def _tool_schema_hint(name: str) -> str:
    """给某工具返回一行"正确用法"提示（参数名+required），供 A1 malformed 纠错回喂。

    找不到该工具（未知工具场景）时返回有效工具名清单，引导模型改用正确的名字。
    """
    fn = next((t["function"] for t in TOOLS if t["function"]["name"] == name), None)
    if fn is None:
        return "有效工具名：" + "、".join(sorted(_TOOL_NAMES))
    params = (fn.get("parameters") or {}).get("properties") or {}
    required = set((fn.get("parameters") or {}).get("required") or [])
    if not params:
        return f"{name} 不接受参数，arguments 传 {{}} 即可。"
    cols = []
    for pname, spec in params.items():
        typ = (spec or {}).get("type", "any")
        cols.append(f"{pname}:{typ}" + ("(必填)" if pname in required else ""))
    return f"{name} 的参数应为 JSON 对象：{{{', '.join(cols)}}}。"


def _canon_args(args: Any) -> str:
    """把工具参数规整化成稳定字符串，作为调用签名的一部分（A2 停滞检测）。

    键排序、去掉纯格式差异，让"同一意图不同写法"也能识别为重复。非 dict 安全降级为 repr。
    """
    try:
        return json.dumps(args, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    except Exception:  # noqa: BLE001
        return repr(args)


def _path_is_reparse(path: Path, info: os.stat_result | None = None) -> bool:
    try:
        current = info or os.lstat(path)
        return path.is_symlink() or bool(
            int(getattr(current, "st_file_attributes", 0)) & _REPARSE_ATTRIBUTE
        )
    except OSError:
        return True


def _workspace_target(
    workdir: str,
    requested: str,
    *,
    require_file: bool,
) -> Path:
    """Resolve one lexical workspace target without following any reparse point."""

    root = Path(os.path.abspath(workdir))
    target = Path(
        os.path.abspath(requested if os.path.isabs(requested) else os.path.join(root, requested))
    )
    try:
        if os.path.commonpath(
            [os.path.normcase(str(root)), os.path.normcase(str(target))]
        ) != os.path.normcase(str(root)):
            raise ValueError("workspace target escapes its root")
        relative = os.path.relpath(target, root)
    except (OSError, ValueError) as exc:
        raise ValueError("workspace target escapes its root") from exc

    parts = () if relative in {"", "."} else Path(relative).parts
    try:
        root_info = os.lstat(root)
    except OSError as exc:
        raise ValueError("workspace root is unavailable") from exc
    if _path_is_reparse(root, root_info) or not stat.S_ISDIR(root_info.st_mode):
        raise ValueError("workspace root is a reparse point or is not a directory")
    if not parts:
        if require_file:
            raise IsADirectoryError(str(target))
        return target

    current = root
    for index, part in enumerate(parts):
        current /= part
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            if require_file:
                raise FileNotFoundError(str(target))
            break
        if _path_is_reparse(current, info):
            raise ValueError("workspace target contains a reparse point or symbolic link")
        is_leaf = index == len(parts) - 1
        if is_leaf:
            if require_file and stat.S_ISDIR(info.st_mode):
                raise IsADirectoryError(str(target))
            if require_file and not stat.S_ISREG(info.st_mode):
                raise ValueError("workspace target is not a regular file")
            if require_file and int(getattr(info, "st_nlink", 1)) != 1:
                raise ValueError("workspace target is a hard-linked file")
            if not require_file and not (
                stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)
            ):
                raise ValueError("workspace target is not a regular file")
        elif not stat.S_ISDIR(info.st_mode):
            raise ValueError("workspace target parent is not a directory")
    return target


def _read_bounded_regular_text(path: Path, *, max_bytes: int, errors: str) -> str:
    info = os.lstat(path)
    if _path_is_reparse(path, info) or not stat.S_ISREG(info.st_mode):
        raise ValueError("file is a reparse point or is not regular")
    # A hard link inside the workspace can be another name for a file outside
    # it on the same NTFS volume.  Path containment and reparse checks cannot
    # distinguish that alias, so model-readable files must be single-link.
    if int(getattr(info, "st_nlink", 1)) != 1:
        raise ValueError("file is a hard link")
    if info.st_size < 0 or info.st_size > max_bytes:
        raise ValueError("text file is too large")
    with open(path, "rb") as handle:
        raw = handle.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ValueError("text file is too large")
    return raw.decode("utf-8", errors=errors)


def _read_text_limited(path: Path, limit: int = 12000) -> str:
    try:
        return _read_bounded_regular_text(
            path, max_bytes=_MAX_STARTUP_FILE_BYTES, errors="replace"
        )[:limit]
    except Exception:  # noqa: BLE001
        return ""


def _startup_context(workdir: str) -> tuple[str, list[str]]:
    """Read only user-selected files inside the already validated workspace.

    Machine-global knowledge bases are deliberately excluded: silently sending
    ambient files outside the workspace to a cloud model violates the data
    boundary even when those files are believed not to contain secrets.
    """
    parts: list[str] = []
    logs: list[str] = []
    wd = Path(workdir) if workdir else None
    if wd and wd.exists():
        try:
            inspected, truncated = _scan_dir_bounded(str(wd), _STARTUP_SCAN_ENTRIES)
            names = []
            for entry, info in sorted(inspected, key=lambda item: item[0].name.lower()):
                try:
                    p = Path(entry.path)
                    if info is None or _path_is_reparse(p, info):
                        continue
                    names.append(("[目录] " if stat.S_ISDIR(info.st_mode) else "[文件] ") + p.name)
                except OSError:
                    continue
            if truncated:
                names.append("...(目录清单已按安全上限截断)")
            parts.append(f"【已读取目标目录清单 {wd}】\n" + "\n".join(names))
            logs.append(f"list_dir({wd}) -> 已注入目标目录清单")
        except Exception:  # noqa: BLE001
            pass
        for name in ("AGENTS.md", "RUNBOOK.md", "DAILY_RUN.md", "README.md", "每日自动发布_总计划.md"):
            p = wd / name
            txt = _read_text_limited(p, 9000)
            if txt:
                parts.append(f"【已读取目标目录文件 {p}】\n{txt}")
                logs.append(f"read_file({p}) -> 已注入")
    return "\n\n".join(parts), logs


def _compress_old_tool_msgs(msgs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """把较早的 tool 结果消息有损压缩，省 token；system 与最近若干条原样保留。

    只压 role=='tool' 的“工具输出”（属冗余上下文），不动 system / user / assistant，
    不动最近 _KEEP_RECENT 条（含最新一步）。安全降级：异常/不可用 → 原列表不变。
    """
    try:
        from orchestrator.compress import compress_text, enabled

        if not enabled() or len(msgs) <= _KEEP_RECENT + 1:
            return msgs
        cutoff = len(msgs) - _KEEP_RECENT  # 此下标之后的不压
        out: list[dict[str, Any]] = []
        for i, m in enumerate(msgs):
            c = m.get("content")
            if (
                i < cutoff
                and m.get("role") == "tool"
                and isinstance(c, str)
                and len(c) >= _COMPRESS_TOOL_MIN
            ):
                nc = compress_text(c, rate=0.5)
                out.append({**m, "content": nc} if nc != c else m)
            else:
                out.append(m)
        return out
    except Exception:  # noqa: BLE001
        return msgs


def _wpath(workdir: str, p: str) -> str:
    return p if os.path.isabs(p) else os.path.join(workdir, p)


def _int_arg(v: Any, default: int, *, low: int, high: int) -> int:
    try:
        n = int(v)
    except Exception:  # noqa: BLE001
        n = default
    return max(low, min(high, n))


def _scan_dir_bounded(
    path: str,
    limit: int,
) -> tuple[list[tuple[os.DirEntry[str], os.stat_result | None]], bool]:
    """Inspect at most ``limit`` entries plus one truncation sentinel.

    ``max_entries`` must bound filesystem work as well as rendered output.
    Enumerating and sorting an unbounded directory first can otherwise block
    the gateway event loop before the wall deadline gets a chance to run.
    """
    inspected: list[tuple[os.DirEntry[str], os.stat_result | None]] = []
    truncated = False
    with os.scandir(path) as iterator:
        for index, entry in enumerate(iterator):
            if index >= limit:
                truncated = True
                break
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError:
                info = None
            inspected.append((entry, info))
    return inspected, truncated


def _format_dir(path: str, *, recursive: bool, max_entries: int) -> str:
    try:
        root_info = os.lstat(path)
    except FileNotFoundError:
        return f"路径不存在：{path}"
    except OSError as exc:
        return f"列目录失败：{exc}"
    root_path = Path(path)
    if _path_is_reparse(root_path, root_info):
        return "⛔ 已拦截：目录目标是链接/reparse point"
    if not stat.S_ISDIR(root_info.st_mode):
        return f"不是目录：{path}"

    lines: list[str] = []
    # 自有栈只保存已经 lstat 为真实目录的子项；每次真正 scandir 前仍会复验，
    # 从而不依赖 os.walk/os.path.isdir/os.stat 的跟随链接语义。
    stack: list[tuple[str, str]] = [(os.path.abspath(path), "")]
    while stack:
        current, prefix = stack.pop()
        try:
            current_info = os.lstat(current)
            if _path_is_reparse(Path(current), current_info) or not stat.S_ISDIR(
                current_info.st_mode
            ):
                if prefix:
                    lines.append(f"[X] {prefix.rstrip(os.sep)} (链接/reparse 已阻断)")
                if len(lines) >= max_entries:
                    return "\n".join(lines) + "\n...(已截断)"
                continue
            remaining = max_entries - len(lines)
            if remaining <= 0:
                return "\n".join(lines) + "\n...(已截断)"
            inspected, truncated = _scan_dir_bounded(current, remaining)
        except OSError as exc:
            return f"列目录失败：{exc}"

        def _sort_key(item: tuple[os.DirEntry[str], os.stat_result | None]) -> tuple[bool, str]:
            entry, info = item
            safe_dir = bool(
                info is not None
                and stat.S_ISDIR(info.st_mode)
                and not _path_is_reparse(Path(entry.path), info)
            )
            return (not safe_dir, entry.name.lower())

        child_dirs: list[tuple[str, str]] = []
        for entry, info in sorted(inspected, key=_sort_key):
            display = os.path.join(prefix, entry.name) if prefix else entry.name
            if info is None:
                lines.append(f"[X] {display} (无法安全读取，已阻断)")
            elif _path_is_reparse(Path(entry.path), info):
                lines.append(f"[X] {display} (链接/reparse 已阻断)")
            elif stat.S_ISDIR(info.st_mode):
                lines.append(f"[D] {display}")
                if recursive:
                    child_dirs.append((entry.path, display + os.sep))
            elif stat.S_ISREG(info.st_mode):
                lines.append(f"[F] {display} {info.st_size}B")
            else:
                lines.append(f"[X] {display} (非普通文件，已阻断)")
            if len(lines) >= max_entries:
                return "\n".join(lines) + "\n...(已截断)"
        if truncated:
            return "\n".join(lines) + "\n...(已截断)"
        if recursive:
            stack.extend(reversed(child_dirs))
    return "\n".join(lines) if lines else "(空目录)"


def _models_text(router: Any) -> str:
    if router is None:
        return "(当前环境无法列模型)"
    rows = []
    for m in router.list_models():
        if m.get("modality", "chat") != "chat":
            continue
        rows.append(
            f"{m.get('id')}: {m.get('description') or ''}"
            f"（{m.get('owned_by') or '?'} / {m.get('tier') or '?'}）"
        )
    return "\n".join(rows) if rows else "(没有已接入的聊天模型)"


async def _ask_model(
    router: Any,
    model: str,
    prompt: str,
    *,
    author_receipts: Optional[list[dict[str, Any]]] = None,
    provider_role: str = "tool_agent.delegate",
) -> str:
    if router is None:
        return "(当前环境无法咨询其它模型)"
    model = model.strip()
    prompt = prompt.strip()
    if not model or not prompt:
        return "ask_model 需要 model 和 prompt"
    if router.resolve(model) is None:
        return f"未知模型：{model}。请先调用 list_models 查看可用 id。"
    req = ChatCompletionRequest(model=model, messages=[{"role": "user", "content": prompt[:50000]}])  # type: ignore[arg-type]
    with bind_provider_call_scope(role=provider_role):
        res, served, call_route = await chat_with_fallback(router, req)
    if author_receipts is not None:
        author_receipts.append(
            route_receipt(
                requested_model=model,
                actual_model=str(served or "") or None,
                route=call_route,
                response=res,
            )
        )
    content = (res.get("choices") or [{}])[0].get("message", {}).get("content") or ""
    prefix = f"【{served}】"
    if served != model:
        prefix = f"【{model} 请求失败后由 {served} 回答】"
    return (prefix + "\n" + content)[:6000]


async def _gen_image(router: Any, media: Optional[list], prompt: str,
                     staged_images: Optional[list] = None) -> str:
    """让任何模型经此调用平台的图模型生成图片（生成的 URL 收进 media，前端贴进对话）。
    生成的图也入 staged_images 图池：后续 generate_video 可直接拿它做图生视频。"""
    if not _TOOL_AGENT_PAID_MEDIA_V2_WIRED:
        return _IMAGE_GENERATION_UNAVAILABLE
    if router is None:
        return "(当前环境无法生图)"
    from gateway.schemas import ImageGenerationRequest

    img = next((m["id"] for m in router.list_models() if m.get("modality") == "image"), None)
    if not img:
        return "(没有可用的图模型，请在连接中心接入生图模型)"
    route = router.resolve(img)
    provider = route.provider
    upstream_model = str(route.upstream_model)
    res = await generate_image_with_accounting(
        provider,
        ImageGenerationRequest(model=img, prompt=prompt),
        upstream_model,
        actual_model=img,
    )
    urls = []
    for d in res.get("data") or []:
        u = d.get("url") or (f"data:image/png;base64,{d['b64_json']}" if d.get("b64_json") else "")
        if u:
            urls.append(u)
    if media is not None:
        media.extend(urls)
    if staged_images is not None and urls:  # 最新生成的一组图取代旧组，避免无关历史图混成 keyframes
        staged_images[:] = urls
    return f"已生成图片 {len(urls)} 张并贴进对话。" if urls else "生图失败（无图返回）"


def _valid_image_bytes(data: bytes) -> bool:
    """轻量校验常见图片魔数，挡住“长得像 base64 的任意文本”。"""
    return bool(
        data.startswith((b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF87a", b"GIF89a", b"BM"))
        or (len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP")
    )


def _validated_image_base64(value: str) -> str:
    """返回经完整 base64 + 图片魔数验证的原串；非法/错 padding 返回空。"""
    import base64 as _b64
    import binascii as _binascii

    s = (value or "").strip()
    if not s or any(ch.isspace() for ch in s):
        return ""
    try:
        raw = _b64.b64decode(s, validate=True)
    except (ValueError, _binascii.Error):
        return ""
    return s if _valid_image_bytes(raw) else ""


def _video_image_arg(img: str, *, workdir: Optional[str] = None) -> str:
    """把图生视频的 image 规整成 Agnes 能收的形式。Agnes 直接收**纯 base64**或公网 URL，
    **不需要图床/Supabase**（见 KB agnes-api-实战手册）：
    · http(s) URL → 原样；
    · data:image/...;base64,XXX → 剥前缀返回**纯 base64**（带 data-URI 前缀 Agnes 会报 Incorrect padding）；
    · 本地文件路径 → 读出并 base64；
    · 完整解码且有图片魔数的纯 base64 → 原样；
    · 认不出 → ''（调用方退回文生视频，别吐神秘 404）。"""
    s = (img or "").strip()
    if not s:
        return ""
    if s.startswith(("http://", "https://")):
        return s
    if s.startswith("data:"):  # data:image/png;base64,XXXX → 验证后返回纯 base64 XXXX
        head, sep, payload = s.partition(",")
        if not sep or not head.lower().startswith("data:image/") or ";base64" not in head.lower():
            return ""
        return _validated_image_base64(payload)
    try:
        p = s if os.path.isabs(s) or not workdir else os.path.join(workdir, s)
        # 安全闸：只读工作区内、非受保护路径的图片，防提示注入把工作区外的
        # 隐私图(如 C:\Users\...\Pictures\*.jpg)读出来 base64 外发给视频上游；越界/受保护 → 退文生视频。
        if not escapes_workdir(workdir or "", p) and not is_protected_path(p) and os.path.isfile(p):
            import base64 as _b64
            with open(p, "rb") as _f:
                raw = _f.read()
            return _b64.b64encode(raw).decode() if _valid_image_bytes(raw) else ""
    except Exception:  # noqa: BLE001
        pass
    return _validated_image_base64(s)


def _images_from_history(history: Optional[list]) -> list[str]:
    """取历史里**最近一组**图片（多模态块或舰队贴回的 Markdown），供图生视频。

    只取最近组，避免对话里几轮无关旧图悄悄把“当前单图”升级成 keyframes。
    """
    import re as _re

    latest: list[str] = []
    for m in (history or []):
        content = m.get("content") if isinstance(m, dict) else None
        group: list[str] = []
        if isinstance(content, list):
            for p in content:
                if isinstance(p, dict) and p.get("type") == "image_url":
                    iu = p.get("image_url")
                    u = (iu.get("url") if isinstance(iu, dict) else "") or ""
                    if u:
                        group.append(str(u))
        elif isinstance(content, str):
            group.extend(_re.findall(r"!\[[^\]]*\]\((https?://[^)\s]+)\)", content))
        if group:
            latest = list(dict.fromkeys(group))
    return latest


async def _gen_video(
    router: Any,
    prompt: str,
    *,
    image: Optional[str] = None,
    no_image: bool = False,
    seconds: Optional[float] = None,
    size: Optional[str] = None,
    fps: Optional[int] = None,
    negative_prompt: Optional[str] = None,
    pending: Optional[list] = None,
    staged_images: Optional[list] = None,
    workdir: Optional[str] = None,
) -> str:
    """让任何模型调用平台的视频模型（异步：创建任务并返回 task_id；耗时较长）。

    用足 Agnes/Sapiens 能力（机主实测：以前只传 prompt，图生视频/时长/分辨率全没用上）：
    - image=公网图片URL → **图生视频**（让视频从这张图动起来，更电影级；如先 generate_image 生成的图 URL）；
    - seconds → 时长（换算成 8n+1 的 num_frames，最长 ~18s）；size="WxH" → 分辨率/横竖屏；fps/negative_prompt 可选。
    pending 非 None 时把 {task_id, model, prompt} 登记进去，前端轮询到成片自动贴回对话（#6）。
    """
    if not _TOOL_AGENT_PAID_MEDIA_V2_WIRED:
        return _VIDEO_GENERATION_UNAVAILABLE
    if router is None:
        return "(当前环境无法生视频)"
    from gateway.schemas import VideoGenerationRequest

    vid = next((m["id"] for m in router.list_models() if m.get("modality") == "video"), None)
    if not vid:
        return "(没有可用的视频模型，请在连接中心接入)"
    route = router.resolve(vid)
    # 组装全参数（照 story2video 的 agnes.py 已验证字段：width/height/num_frames/frame_rate/image/negative_prompt）
    req_kw: dict[str, Any] = {"model": vid, "prompt": prompt}
    fr = int(fps) if fps else 24
    if size:
        try:
            w, h = (int(x) for x in str(size).lower().split("x"))
            req_kw["width"], req_kw["height"] = w, h
        except (ValueError, TypeError):
            pass
    _dur_note = ""
    if seconds:
        try:
            want = float(seconds)
            f = max(9, min(441, round(want * fr)))  # 8n+1、[9,441]（~18s@24fps）
            req_kw["num_frames"] = int(max(9, min(441, 8 * round((f - 1) / 8.0) + 1)))
            req_kw["frame_rate"] = fr
            capped = req_kw["num_frames"] / fr
            if want > capped + 0.5:  # 要的超过单段上限：如实告知，别默默缩成短视频
                _dur_note = (f"\n（注：单段视频最长约 {capped:.0f} 秒，已按上限生成；要 {want:.0f} 秒请改用"
                             " generate_long_video 工具——自动分镜/逐镜生成/拼接成片。）")
        except (ValueError, TypeError):
            pass
    elif fps:
        req_kw["frame_rate"] = fr
    # 图片池：会话里最近一组图(上传/AI生成) + 可验证的本地/base64 显式图，去重保序、取最近 ≤4 张。
    # 用户"直接传的/之前传的/AI生成的、单图多图"都吃：1 张→图生视频，≥2 张→关键帧视频。
    # no_image=模型判定"视频主题与会话图无关"（如图是人物、用户要小猫跳舞）→ 纯文生视频，
    # 别把不相关的旧图硬塞进视频（机主实测：说啥都带着那张图）。
    if no_image:
        staged_images, image = [], None
    _raw = list(staged_images or [])
    rejected_explicit = False
    if image:
        explicit = str(image)
        # run_tool_agent 总会传 list（哪怕空）。这时 HTTP URL 只有来自 staged_images 才可信；
        # LLM 自己填写的 URL 无来源可证，最常见就是幻觉，宁可稳退文生视频也不打坏上游。
        if staged_images is None or not explicit.startswith(("http://", "https://")):
            _raw.append(explicit)
        elif explicit not in _raw:
            rejected_explicit = True
    _seen: set[str] = set()
    _imgs: list[str] = []
    for raw in _raw:
        arg = _video_image_arg(str(raw), workdir=workdir)
        if arg and arg not in _seen:
            _seen.add(arg)
            _imgs.append(arg)
    _imgs = _imgs[-4:]
    _img_note = ""
    if len(_imgs) == 1:
        req_kw["image"] = _imgs[0]                                     # 单图 → 图生视频
    elif len(_imgs) >= 2:
        req_kw["extra_body"] = {"image": _imgs, "mode": "keyframes"}   # 多图 → 关键帧视频(首帧起点·尾帧终点)
    elif _raw or rejected_explicit:
        _img_note = "\n（注：没认出可用的图片，本次按描述做文生视频。）"
    if negative_prompt:
        req_kw["negative_prompt"] = str(negative_prompt)
    provider = route.provider
    upstream_model = str(route.upstream_model)
    res = await generate_video_with_accounting(
        provider,
        VideoGenerationRequest(**req_kw),
        upstream_model,
        actual_model=vid,
    )
    # Agnes 创建返回 task_id + video_id 两个；轮询端点 agnesapi?video_id= **只认 video_id**，
    # 拿 task_id 去查会 404「task not found」——视频其实早做好了却取不回。照 agnes.py：video_id 优先。
    tid = next((str(res.get(k)) for k in ("video_id", "task_id", "id", "request_id") if res.get(k)), "")
    if tid and pending is not None:
        pending.append({"task_id": tid, "model": vid, "prompt": prompt[:200]})
    return (f"视频生成任务已创建（task_id={tid}），后台生成中，做好会自动贴回对话，无需再调此工具查询。{_img_note}{_dur_note}"
            if tid else "视频任务创建失败（无 task_id）。")


async def _gen_long_video(
    router: Any, goal: str, total_seconds: float, size: Optional[str] = None,
    pending: Optional[list] = None,
) -> str:
    """长视频（>18s~10min）：复用视频工作室流水线——自动分镜 → 逐镜生成(末帧接首帧) → 拼接。
    引擎后台 job 跑（聊天不阻塞、关窗不断）；pending 登记 studio:{job_id}，前端轮询到成片自动贴回。"""
    if router is None:
        return "(当前环境无法生视频)"
    goal = (goal or "").strip()
    if not goal:
        return "generate_long_video 需要 goal（视频内容描述）"
    try:
        secs = max(19, min(600, int(float(total_seconds))))
    except (ValueError, TypeError):
        return "total_seconds 需要是数字（19~600 秒）"
    from gateway.config import get_settings
    from orchestrator.studio import generate_plan, start_execution
    from pathlib import Path

    ask = goal + f"。总时长约 {secs} 秒" + (f"，分辨率 {size}" if size else "")
    plan = await generate_plan(router, ask)
    shots = plan.get("shots") or []
    if not shots:
        return "分镜方案生成失败（模型没给出可执行分镜），请换个说法再试。"
    out_dir = str(Path(get_settings().usage_db_path).parent / "studio")
    job_id = start_execution(router, plan, out_dir)
    if pending is not None:
        pending.append({"task_id": f"studio:{job_id}", "model": "studio", "prompt": goal[:200]})
    est_lo, est_hi = len(shots), len(shots) * 3  # 每镜约 1-3 分钟
    return (
        f"长视频任务已创建（{len(shots)} 个分镜 · 目标约 {secs} 秒 · job={job_id}）。"
        f"引擎后台逐镜生成中（预计 {est_lo}-{est_hi} 分钟），成片会自动贴回对话；"
        "期间用户可继续聊天/派其它任务。无需再调此工具查询进度。"
    )


async def _web_read(router: Any, url: str, question: str) -> str:
    """读网页正文 + 便宜模型总结（懒 import，失败返回错误文本，绝不炸循环）。"""
    if router is None:
        return "(当前环境无法读取网页)"
    url = (url or "").strip()
    if not url:
        return "web_read 需要 url"
    try:
        from orchestrator.webread import read_and_summarize

        r = await read_and_summarize(router, url, question=(question or "").strip())
        head = f"《{r.get('title') or url}》 {r.get('url') or url}"
        return (head + "\n\n" + (r.get("summary") or "(没抓到正文)"))[:6000]
    except Exception as e:  # noqa: BLE001
        return f"web_read 失败：{e}"


async def _lapian(router: Any, url: str) -> str:
    """视频链接拉片报告（懒 import 网关内部函数；耗时较长；失败返回错误文本）。"""
    if router is None:
        return "(当前环境无法拉片)"
    url = (url or "").strip()
    if not url:
        return "lapian 需要 url"
    try:
        from gateway.app import lapian_url_report

        res = await lapian_url_report(router, url)
        if res.get("error"):
            return f"拉片失败：{res['error']}"
        return (res.get("report") or "(拉片没产出报告)")[:6000]
    except Exception as e:  # noqa: BLE001
        return f"lapian 失败：{e}"


# 知识库单例（tool_agent 无 app.state，按 app.py 同参就地构造一次，懒建、进程内复用）。
_KB_SINGLETON: Any = None


def _kb() -> Any:
    global _KB_SINGLETON
    if _KB_SINGLETON is None:
        from pathlib import Path as _Path

        from gateway.config import get_settings
        from orchestrator.knowledge import KnowledgeBase

        db = _Path(get_settings().usage_db_path).parent / "knowledge.db"
        _KB_SINGLETON = KnowledgeBase(str(db))
    return _KB_SINGLETON


async def _kb_query(query: str) -> str:
    """查用户个人知识库（懒建单例；失败返回错误文本）。"""
    query = (query or "").strip()
    if not query:
        return "kb_query 需要 query"
    try:
        from gateway.config import get_settings
        from orchestrator.knowledge import build_context

        uid = get_settings().agent_user_id or "owner"
        hits = _kb().search(uid, query, k=5)
        if not hits:
            return "(知识库里没有匹配内容，可能尚未导入相关文档)"
        return build_context(hits)[:6000]
    except Exception as e:  # noqa: BLE001
        return f"kb_query 失败：{e}"


async def _translate(router: Any, text: str, target: str) -> str:
    """翻译文本（懒 import；失败返回错误文本）。"""
    if router is None:
        return "(当前环境无法翻译)"
    text = (text or "").strip()
    target = (target or "").strip()
    if not text or not target:
        return "translate 需要 text 和 target"
    try:
        from orchestrator.modes import pick_model
        from orchestrator.translate import translate as _do_translate

        m = "agnes-flash" if router.resolve("agnes-flash") else (pick_model(router, "cheap") or "glm")
        r = await _do_translate(router, text=text, target=target, model=m)
        return (r.get("translated") or "(翻译无输出)")[:6000]
    except Exception as e:  # noqa: BLE001
        return f"translate 失败：{e}"


async def execute_tool(
    name: str, args: dict, *, workdir: str, changes: Optional[list] = None,
    router: Any = None, media: Optional[list] = None, pending_videos: Optional[list] = None,
    staged_images: Optional[list] = None,
    author_receipts: Optional[list[dict[str, Any]]] = None,
    provider_role: str = "tool_agent.delegate",
) -> str:
    """在引擎里真执行一个工具，返回结果文本。changes 非 None 时 write_file 记录 {path,before,after}（给内联动作卡）。
    router/media 供生图/生视频工具用——让任何模型干活时也能生成媒体。pending_videos 收生视频异步任务，回前端轮询。"""
    if name in _DISABLED_HOST_BROWSER_TOOLS:
        return (
            "⛔ 宿主浏览器自动化已关闭：当前浏览器共享机主登录态，"
            "需独立浏览器配置与精确 origin/action capability 后才能启用。"
        )
    plugin_kernel = _router_plugin_kernel(router)
    if name in _PLUGIN_MIGRATED_TOOL_NAMES and plugin_kernel is not None:
        if not plugin_kernel.tools.has_provider(name):
            return f"未知工具：{name}。该插件工具当前未挂载或已撤销。"
        lease = plugin_kernel.borrow_tool(name)
        try:
            return await lease.invoke(args)
        except Exception as exc:  # noqa: BLE001 -- plugin layer already sanitizes cause
            return f"工具 {name} 出错：{exc}"
        finally:
            lease.release()
    if name in _WORKSPACE_TOUCHING_TOOLS:
        if not current_runtime_profile().allows(
            RuntimeCapability.WORKSPACE_FILE_TOOLS
        ):
            return (
                "⛔ 当前运行配置已关闭工作区文件工具；"
                "需要独立低权限 worker 后才能启用。"
            )
        try:
            workdir = str(resolve_workspace(workdir))
        except WorkspaceBoundaryError as exc:
            return f"⛔ 已拦截：{exc}"
    try:
        if name == "remember":
            # 记忆银行（RooFlow 借鉴）：把关键决策/约定写进 workdir 的 记忆.md，续跑自动带回。
            from orchestrator import task_state as _ts
            _ts.record_note(workdir, str(args.get("kind") or "约定"), str(args.get("text") or ""))
            return "已记入记忆银行（关键决策/约定，续跑会自动带回）。"
        if name == "cli_hub":
            return (
                "⛔ 第三方 CLI 启动已关闭：可执行文件哈希不能约束模型提供的参数、文件读取或网络行为。"
                "该能力必须迁入独立低权限、禁网且使用类型化参数策略的 worker。"
            )
        if name == "code_index":
            return (
                "⛔ 第三方代码索引二进制已关闭：哈希校验不等于运行时隔离。"
                "恢复前必须在禁网低权限 worker 中只挂载排除密钥的数据快照。"
            )
        if name == "list_dir":
            requested = str(args.get("path") or ".")
            if escapes_workdir(workdir, requested):
                return f"⛔ 已拦截：读取路径越出工作区（{requested}）。agent 只能读取当前工作区。"
            try:
                target = _workspace_target(workdir, requested, require_file=False)
            except FileNotFoundError:
                return f"路径不存在：{requested}"
            except (OSError, ValueError) as exc:
                return f"⛔ 已拦截：目录目标包含链接/reparse 或不是普通目录（{exc}）"
            return _format_dir(
                str(target),
                recursive=bool(args.get("recursive")),
                max_entries=_int_arg(args.get("max_entries"), 200, low=1, high=1000),
            )
        if name == "read_file":
            requested = str(args["path"])
            if escapes_workdir(workdir, requested):
                return f"⛔ 已拦截：读取路径越出工作区（{requested}）。agent 只能读取当前工作区。"
            # Classify protected names before probing the filesystem.  Besides
            # preserving the public error contract, this avoids turning
            # read_file into an existence oracle for credential paths.
            if (_requested_secret := reads_secret(requested)):
                return (f"⛔ 已拦截：不读取{_requested_secret}（{requested}）——凭据/密钥不经 agent 读取，"
                        "以防被提示注入外泄；确需请你手动查看。")
            try:
                target = _workspace_target(workdir, requested, require_file=True)
            except FileNotFoundError:
                return f"文件不存在：{requested}"
            except IsADirectoryError:
                return f"这是目录不是文件：{requested}"
            except (OSError, ValueError) as exc:
                return f"⛔ 已拦截：读取目标包含链接/reparse 或不是普通文件（{exc}）"
            p = str(target)
            _sec = is_protected_path(p) or reads_secret(str(args.get("path") or ""))
            if _sec:
                return (f"⛔ 已拦截：不读取{_sec}（{args.get('path')}）——凭据/密钥不经 agent 读取，"
                        "以防被提示注入外泄；确需请你手动查看。")
            try:
                return _read_bounded_regular_text(
                    target, max_bytes=_MAX_TOOL_TEXT_BYTES, errors="strict"
                )[:6000]
            except UnicodeDecodeError:
                return f"⛔ 已拦截：{requested} 不是 UTF-8 文本文件"
            except ValueError as exc:
                if "too large" in str(exc):
                    return f"⛔ 已拦截：文本文件过大（上限 {_MAX_TOOL_TEXT_BYTES} 字节）"
                return f"⛔ 已拦截：读取目标包含链接/reparse 或不是普通文件（{exc}）"
        if name == "write_file":
            # P5 硬层：只许改工作区内文件，越界（绝对路径/../）直接拦
            if escapes_workdir(workdir, str(args["path"])):
                return f"⛔ 已拦截：写入路径越出工作区（{args['path']}）。agent 只能改工作区内文件，需动外部请手动操作。"
            requested = str(args["path"])
            try:
                target = _workspace_target(workdir, requested, require_file=False)
            except (OSError, ValueError) as exc:
                return f"⛔ 已拦截：写入目标包含链接/reparse 或不是普通文件（{exc}）"
            p = str(target)
            if (_prot := is_protected_path(p)):
                return f"⛔ 已拦截：不写入/覆盖{_prot}（{args['path']}）——凭据/密钥文件不由 agent 改动。"
            before = ""
            existed = target.exists()
            if existed:
                try:
                    before = _read_bounded_regular_text(
                        target, max_bytes=_MAX_TOOL_TEXT_BYTES, errors="strict"
                    )
                except UnicodeDecodeError:
                    return f"⛔ 已拦截：{requested} 不是 UTF-8 文本文件"
                except ValueError as exc:
                    if "too large" in str(exc):
                        return f"⛔ 已拦截：目标文件过大（上限 {_MAX_TOOL_TEXT_BYTES} 字节）"
                    return f"⛔ 已拦截：写入目标包含链接/reparse 或不是普通文件（{exc}）"
            after = str(args.get("content", ""))
            after_raw = after.encode("utf-8")
            if len(after_raw) > _MAX_TOOL_TEXT_BYTES:
                return f"⛔ 已拦截：写入内容过大（上限 {_MAX_TOOL_TEXT_BYTES} 字节）"
            receipt = ""
            if changes is not None:
                from orchestrator import undo_receipts

                receipt = undo_receipts.issue(
                    workdir=workdir,
                    path=str(args["path"]),
                    before=before,
                    after=after,
                    existed=existed,
                )
                if not receipt:
                    return "⛔ 写入已取消：撤销凭证无法安全签发"
            parent = target.parent
            os.makedirs(parent, exist_ok=True)
            try:
                # Re-check after directory creation and immediately before the
                # atomic replace; an existing symlink/junction is never followed.
                target = _workspace_target(workdir, requested, require_file=False)
            except (OSError, ValueError) as exc:
                return f"⛔ 已拦截：写入目标在准备期间改变（{exc}）"
            tmp_name = ""
            try:
                with tempfile.NamedTemporaryFile(
                    mode="wb",
                    prefix=f".{target.name}.write-",
                    suffix=".tmp",
                    dir=target.parent,
                    delete=False,
                ) as handle:
                    tmp_name = handle.name
                    handle.write(after_raw)
                    handle.flush()
                    os.fsync(handle.fileno())
                _workspace_target(workdir, requested, require_file=False)
                os.replace(tmp_name, target)
                tmp_name = ""
                _workspace_target(workdir, requested, require_file=True)
            finally:
                if tmp_name:
                    try:
                        os.unlink(tmp_name)
                    except OSError:
                        pass
            if changes is not None:
                changes.append({
                    "path": requested, "before": before, "after": after,
                    "undo_receipt": receipt,
                })
            return f"已写入 {args['path']}"
        if name == "run_command":
            # 永不在持有网关/审批/渠道凭据的进程账户下执行模型给出的宿主命令。
            # 正则过滤、一次性 capability 和最小 env 都挡不住子进程读取同一 OS 用户可读的
            # ACL/DPAPI 文件，也挡不住后台进程在 capability 消费后继续存活。恢复该能力必须
            # 先接入独立低权限账户/容器中的执行 worker；不能用一个环境变量绕过。
            return (
                "⛔ 宿主命令执行已关闭：当前引擎没有独立低权限隔离执行器。"
                "可继续使用受工作区约束的文件工具；测试、构建和长流程须由运维在隔离 worker 中运行。"
            )
        if name == "list_models":
            return _models_text(router)
        if name == "ask_model":
            return await _ask_model(
                router,
                str(args.get("model") or ""),
                str(args.get("prompt") or ""),
                author_receipts=author_receipts,
                provider_role=provider_role,
            )
        if name == "list_skills":  # P3 技能层：L1 清单
            return skills.manifest_text() or "(暂无可用技能)"
        if name == "load_skill":  # P3 技能层：L2 按需读全文
            return skills.load_skill(str(args.get("name", "")))[:6000]
        if name == "generate_image":  # 任何模型都能生图
            return await _gen_image(router, media, str(args.get("prompt", "")), staged_images=staged_images)
        if name == "generate_video":  # 任何模型都能生视频（异步任务登记进 pending_videos，回前端轮询）
            return await _gen_video(
                router, str(args.get("prompt", "")),
                image=(args.get("image") or None),
                no_image=bool(args.get("no_image")),
                seconds=(args.get("seconds") or None),
                size=(args.get("size") or None),
                negative_prompt=(args.get("negative_prompt") or None),
                pending=pending_videos,
                staged_images=staged_images,
                workdir=workdir,
            )
        if name == "generate_long_video":  # 长视频：分镜→逐镜→拼接，引擎后台 job
            return await _gen_long_video(
                router, str(args.get("goal", "")),
                float(args.get("total_seconds") or 0),
                size=(args.get("size") or None),
                pending=pending_videos,
            )
        if name == "web_read":  # 读网页正文 +（可选）按问题总结
            return await _web_read(router, str(args.get("url", "")), str(args.get("question", "")))
        if name == "lapian":  # 视频链接拉片报告
            return await _lapian(router, str(args.get("url", "")))
        if name == "kb_query":  # 查用户个人知识库
            return await _kb_query(str(args.get("query", "")))
        if name == "translate":  # 翻译文本
            return await _translate(router, str(args.get("text", "")), str(args.get("target", "")))
    except Exception as e:  # noqa: BLE001
        return f"工具 {name} 出错：{e}"
    return f"未知工具：{name}。" + _tool_schema_hint(name)


# 有些模型会把整段"思考/纠结"写进正文（<think>…</think> 标签形，或误当答复输出）。
# 剥掉标签形思考块，只把最终答复给用户（机主实测：舰队回复吐了一大段 CoT、看懵）。
_THINK_RE = re.compile(
    r"<think>.*?</think>|<thinking>.*?</thinking>|◁think▷.*?◁/think▷|<reasoning>.*?</reasoning>",
    re.I | re.S,
)


def _strip_think(text: str) -> str:
    return canonical_agent_output(text)


def _strip_image_parts(msgs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """把多模态消息里的 image_url 剥成文字占位——喂给纯文本模型防上游 400
    「Model only support text input」（机主实测：舰队带图历史直接炸编排）。
    图早已提进 staged_images 图池，生视频/生图工具照用不误。"""
    out: list[dict[str, Any]] = []
    for m in msgs:
        c = m.get("content")
        if isinstance(c, list):
            texts = [str(p.get("text") or "") for p in c if isinstance(p, dict) and p.get("type") == "text"]
            n = sum(1 for p in c if isinstance(p, dict) and p.get("type") == "image_url")
            txt = "\n".join(t for t in texts if t)
            if n:
                txt = (txt + f"\n[含 {n} 张图片，已省略：当前模型不支持看图；图仍在会话图池，生视频/生图工具可直接用]").strip()
            out.append({**m, "content": txt or "(图片消息)"})
        else:
            out.append(m)
    return out


async def run_tool_agent(
    router: Any,
    model: str,
    task: str,
    *,
    workdir: str,
    max_steps: int = 50,  # 天花板抬高：靠"给出最终答案"自然停+停滞检测兜底，让长任务干到完成
    allow: Optional[set[str]] = None,
    history: Optional[list[dict]] = None,
    preload_context: bool = True,
    on_event: Optional[Any] = None,  # 实时逐步流式：每调一个工具就即时推 {type:step,log} 给前端
    wall_deadline: Optional[float] = None,  # 墙钟预算（monotonic 秒）；None=自配 _WALL_MIN 分钟
) -> dict[str, Any]:
    """通用 agent 循环：任何会 function-calling 的模型都能在此用工具完成 task。

    返回 {reply, steps, tool_log}。allow=None 给全部工具；显式空集合代表零工具；
    非空集合只授予其中列出的能力。
    preload_context=False 跳过工作区/知识库预读（聊天面纯文字任务省几千 token + 几十秒）。
    wall_deadline：编排方传入共享墙钟（升级重跑不重置）；到点 stopped_reason="wall_cap" 优雅收尾。
    """
    if not current_runtime_profile().allows(
        RuntimeCapability.CONTROLLED_AGENT_EXECUTION
    ):
        raise PermissionError(
            "当前运行配置已关闭受控 Agent 执行；需要独立低权限 worker"
        )

    # Start the budget before workspace validation and context preload.  Those
    # are part of the user-visible request and must not receive a free prelude.
    _deadline = wall_deadline if wall_deadline is not None else new_wall_deadline()
    _provider_role_prefix = current_provider_call_context().role or "tool_agent"

    def _provider_role(suffix: str) -> str:
        return f"{_provider_role_prefix}.{suffix}"[:256]

    needs_workspace = (
        preload_context
        or allow is None
        or bool(set(allow or ()) & _WORKSPACE_TOUCHING_TOOLS)
    )
    if needs_workspace:
        workdir = str(resolve_workspace(workdir))
    runtime_tools = _runtime_tools(router)
    tools = runtime_tools if allow is None else [
        t for t in runtime_tools if t["function"]["name"] in allow
    ]
    advisory_only = allow is not None and not tools
    sys = (
        "你是运行在纳川专用工作区里的能动手智能助手。"
        "list_dir/read_file 只读取该专用工作区，write_file 只写该专用工作区，ask_model 可咨询其它已接入模型。"
        "宿主浏览器自动化与宿主命令执行当前关闭；不要声称已操作浏览器，也不要尝试访问工作区外的 D:\\、HOME 或系统路径。"
        "需要多模型协作时，先 list_models，再用 ask_model 逐个咨询，不要假装已经调用过其它模型。"
        "本执行循环会在发送给模型前压缩较早的工具输出以节省上下文；不要声称没有上下文压缩机制。"
        "读文章/文档链接用 web_read（比开浏览器快）；抖音/B站/YouTube 等视频链接用 lapian 出拆解报告；"
        "查用户个人资料/文档用 kb_query；需要翻译用 translate。"
        "信息够了就用文字给出最终结果。"
        "【只给答复·不吐思考】最终回复只写给用户看的结论/结果；**绝不**把你的思考、权衡、纠结、自我对话、"
        "“要不要/其实应该/让我再想想/Wait/Let me reconsider”这类推理过程写进回复正文——那是内部推理，用户看到只会一头雾水、看懵。"
        "【先对话再动手】用户只是**询问**你能不能/会不会/可不可以做某事（能力或意愿提问，"
        "如“能做1分钟长视频吗”“你会画图吗”），先用文字如实回答与商量，**不要**直接调用工具去执行；"
        "只有用户明确要你**去做/开始/生成**时才动手。别把一句问话当成生成指令。"
        "能凭自己知识直接完成的就别滥用工具——少调、准调。"
        "【少造轮子·YAGNI，借鉴 Ponytail】动手前先找现成的：能复用已有代码和已接入模型就别自己写；"
        "只做当前**明确需要**的，别预造“以后也许用得上”的东西；最好的代码是你没写的代码。改动越小越好、可逆优先。"
    )
    if advisory_only:
        sys = (
            "你是纳川的纯建议智能单元。本轮没有本机执行工具：不得声称已经读取文件、运行命令、"
            "操作浏览器、生成媒体或修改任何外部状态。请基于用户提供的内容和模型知识给出可验证的"
            "分析、方案或答复；若确实需要动手，明确说明应切换到执行模式并由用户授权。"
            "最终回复只写给用户看的结论，不输出内部思考过程。"
        )
    sys += (
        "\n\n工作方式：面对需要多步或多工具的任务，先用一两句话列出 3-5 步的简短计划再动手，"
        "每步做完对照计划自检、必要时调整；全部完成后再给最终答案。"
        "只需一个工具或能直接回答的琐碎任务不必强行规划，直接做即可。"
    )
    if router is not None:
        model_lines = _models_text(router)
        if model_lines and not model_lines.startswith("("):
            sys += "\n\n当前可咨询模型：\n" + model_lines[:2000]
    # P3 技能层：仅当 load_skill 可用时，把技能 L1 清单（名字+一句话）注入系统提示，用到才读全文
    if "load_skill" in {t["function"]["name"] for t in tools}:
        _sk = skills.manifest_text()
        if _sk:
            sys = sys + "\n\n" + _sk
    startup_ctx, startup_logs = _startup_context(workdir) if preload_context else ("", [])
    if startup_ctx:
        sys = sys + (
            "\n\n以下是引擎已替你预读的本机上下文。回答或执行前必须优先依据它；"
            "若用户要求按流程/日更/目标目录执行，先遵守 RUNBOOK/目标目录说明，再动手。\n\n"
            + startup_ctx
        )
    msgs: list[dict[str, Any]] = [{"role": "system", "content": sys}]
    if history:
        msgs.extend(history)
    msgs.append({"role": "user", "content": task})
    tool_log: list[str] = list(startup_logs)
    file_changes: list[dict] = []
    media: list[str] = []  # 模型经 generate_image 生成的图片地址，随结果回前端展示
    staged_images: list[str] = _images_from_history(history)  # 会话图池(上传+生成)，供 generate_video 图生视频
    # 喂图前两道瘦身（图已提进 staged_images，生视频/生图工具用图**不受影响**）：
    # ① 话题门控：本轮任务与图无关（"你好/你是谁"这类纯聊天）→ 剥历史图。几 MB base64 每轮
    #    重复上传给上游是"寒暄也要 38 秒"的大头（机主实测），且模型不需要看图也答得了。
    # ② 能力门控：catalog 明确标注 skills 不含 vision 的纯文本模型 → 剥（防上游 400
    #    「Model only support text input」炸编排）；未标注的不猜，交给循环里的 400 兜底重试。
    if any(isinstance(x.get("content"), list) for x in msgs):
        if not re.search(r"图|画|照片|截图|视频|动起来|海报|封面|image|photo|picture|video|img", task, re.I):
            msgs = _strip_image_parts(msgs)
            tool_log.append("(本轮话题与图无关：历史图片转文字占位省上传；图池仍供生视频/生图工具)")
        else:
            try:
                from gateway.catalog import preset_meta

                _sk = preset_meta(model).get("skills") or []
                if _sk and "vision" not in _sk:
                    msgs = _strip_image_parts(msgs)
                    tool_log.append("(当前模型不看图：历史图片转为文字占位；图池仍供生视频/生图工具)")
            except Exception:  # noqa: BLE001  查不到能力标注就不动，兜底重试还在
                pass
    pending_videos: list[dict] = []  # 生视频异步任务，随结果回前端轮询到成片自动贴回对话
    startup_log_count = len(tool_log)
    usage: dict[str, int] = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
    # `model` remains the display/backward-compatible id.  Review authority must use
    # these observed fields only: None means no model call authored output; "" means a
    # call returned but its served identity was unavailable (fail closed upstream).
    actual_model: str | None = None
    actual_models: list[str] = []
    author_receipts: list[dict[str, Any]] = []

    def _remember_actual(
        served: Any,
        route: Any,
        response: dict[str, Any],
        *,
        requested_model: str = model,
    ) -> None:
        nonlocal actual_model
        actual_model = str(served or "")
        if actual_model not in actual_models:
            actual_models.append(actual_model)
        author_receipts.append(
            route_receipt(
                requested_model=requested_model,
                actual_model=actual_model or None,
                route=route,
                response=response,
            )
        )

    # ---- A1/A2 循环状态 ----
    arg_repairs: dict[str, int] = {}          # 每个工具的参数修复回喂次数（malformed / 未知工具）
    sig_repeat: dict[str, int] = {}           # 每个调用签名累计出现次数
    sig_last_out: dict[str, str] = {}         # 每个签名上次的结果（判"连续相同结果"）
    sig_same_out: dict[str, int] = {}         # 每个签名连续返回相同结果的次数
    stall_warned: set[str] = set()            # 已注入过停滞提示的签名
    softwrap_done = False                      # 步数软提示是否已注入（只注一次，免堆积）
    images_stripped = False                    # 剥图重试只做一次（上游报不吃图时）

    def _acc_usage(res: dict) -> None:
        u = res.get("usage") or {}
        for key in ("prompt_tokens", "completion_tokens", "total_tokens", "cached_tokens"):
            usage[key] = int(usage.get(key, 0) or 0) + int(u.get(key, 0) or 0)

    async def _emit_step(entry: str) -> None:
        """实时逐步流式：每步即时推给前端（编排器桥接成 SSE）。无 on_event（非流式调用）则空转。全吞异常。"""
        if on_event is None:
            return
        try:
            await on_event({"type": "step", "log": entry})
        except Exception:  # noqa: BLE001 推事件失败绝不影响主循环
            pass

    async def _finalize(reason: str, hint: str) -> dict[str, Any]:
        """A4 优雅收尾：不返回裸提示，而是让模型基于已有上下文给"已完成什么+还剩什么"的总结。

        reason 记入 stopped_reason；hint 是给模型的收尾指令。任何异常都降级为可读兜底文本，
        绝不因收尾失败而抛错。收尾与主调用共享同一个 wall_deadline；预算耗尽时绝不
        再调用模型，直接从已确认的工具日志生成确定性部分总结。
        """
        summary = ""
        final_actual_model: str | None = None
        summary_from_provider = False
        finalize_budget = _deadline - _wall_now()
        if finalize_budget > 0:
            try:
                wrap_msgs = _compress_old_tool_msgs(msgs) + [{"role": "user", "content": hint}]
                wrap_req = ChatCompletionRequest(model=model, messages=wrap_msgs)  # type: ignore[arg-type]
                with bind_provider_call_scope(
                    role=_provider_role(f"finalize.{reason}")
                ):
                    wres, wserved, wrap_route = await asyncio.wait_for(
                        chat_with_fallback(router, wrap_req),
                        timeout=min(120.0, finalize_budget),
                    )
                _remember_actual(wserved, wrap_route, wres)
                _acc_usage(wres)
                summary = (wres.get("choices") or [{}])[0].get("message", {}).get("content") or ""
                if summary.strip():
                    final_actual_model = str(wserved or "")
                    summary_from_provider = True
            except Exception:  # noqa: BLE001
                summary = ""
        if not summary.strip():
            stop_label = {
                "wall_cap": "墙钟截止时间已到",
                "stall": "模型调用停滞或超时",
                "max_steps": "执行步数已达上限",
                "capability_violation": "上游尝试了未授权能力",
            }.get(reason, "执行已停止")
            if tool_log:
                recorded = "\n".join(f"- {entry[:240]}" for entry in tool_log[-8:])
                summary = (
                    f"{stop_label}；未再调用模型收尾。\n"
                    f"截止前已记录的部分进展：\n{recorded}\n"
                    "未完成事项：原任务尚未得到完整验收，需要在新的受控预算内继续。"
                )
            else:
                summary = (
                    f"{stop_label}；截止前没有可确认的模型答复或工具执行结果。"
                    "原任务尚未完成，需要在新的受控预算内继续。"
                )
        public_reply = _strip_think(summary)
        if not public_reply.strip():
            public_reply = (
                "执行已停止，本轮未形成可显示的收尾结果；"
                "请在新的受控预算内继续。"
            )
            summary_from_provider = False
        stopped_outcome = (
            "blocked"
            if reason == "capability_violation"
            else (
                "partial"
                if (
                    len(tool_log) > startup_log_count
                    or file_changes
                    or media
                    or pending_videos
                )
                else "failed"
            )
        )
        return _seal_tool_agent_result({
            "reply": public_reply,
            "steps": min(step + 1, max_steps),
            "model": final_actual_model if summary_from_provider else "nachuan-engine",
            "actual_model": final_actual_model if summary_from_provider else actual_model,
            "actual_models": list(actual_models),
            "author_receipts": list(author_receipts),
            "usage": {k: v for k, v in usage.items() if v},
            "tool_log": tool_log,
            "file_changes": file_changes,
            "media": media,
            "pending_videos": pending_videos,
            "stopped_reason": reason,
        }, outcome=stopped_outcome)

    step = 0
    for step in range(max_steps):
        # 墙钟硬预算：到点带部分成果收尾（机主实测 422 分钟失控的根修——步数闸+停滞检测都认不出"慢速空转"）。
        _wall_left = _deadline - _wall_now()
        if _wall_left <= 0:
            return await _finalize(
                "wall_cap",
                f"任务总时长预算（{_WALL_MIN} 分钟）已用完。请基于以上已完成的工作，"
                "给出目前成果总结与未完成事项；不要再调用任何工具。",
            )
        # 运行中插话（Claude Code 式 steering）：用户在任务跑着时发的话，这里被吸收成 user 消息——
        # 任务不打断、上下文接上，下一步动作就按新补充干（机主定案：插话=补充信息，不是砍任务）。
        from orchestrator import inject as _inject

        for _extra in _inject.drain(_inject.conv_id_var.get()):
            msgs.append({"role": "user", "content": f"〔用户插话·请立即结合到当前任务〕{_extra}"})
            tool_log.append(f"(收到用户插话，已并入任务：{_extra[:80]})")
            await _emit_step(f"💬 用户插话已并入：{_extra[:60]}")
        # A4 步数软提示：快用完时提醒模型尽快收尾（只注入一次，避免反复堆消息）。
        remaining = max_steps - step
        if not softwrap_done and remaining <= _SOFT_WRAPUP_STEPS:
            msgs.append({
                "role": "system",
                "content": f"你还剩 {remaining} 步就会达到步数上限，请尽快收尾：优先完成最关键的一步，然后用文字给出结论。",
            })
            softwrap_done = True
        # 发送前压缩较早的工具结果（省 token）；in-memory msgs 仍保留全文供后续步骤。
        sent = _compress_old_tool_msgs(msgs)
        if tools:
            req = ChatCompletionRequest(
                model=model, messages=sent, tools=tools, tool_choice="auto"
            )  # type: ignore[arg-type]
        else:
            # 一些 OpenAI-compatible 上游会拒绝 `tools=[]` + `tool_choice=auto`；
            # advisory 零能力请求应完全省略这两个字段。
            req = ChatCompletionRequest(model=model, messages=sent)  # type: ignore[arg-type]
        # 构造请求也会消耗时间，因此在真正创建上游协程前重新计算剩余预算。
        # 不设最小 floor：哪怕只剩几十毫秒，也不能把墙钟硬上限延长成 30 秒。
        call_budget = min(600.0, _deadline - _wall_now())
        if call_budget <= 0:
            return await _finalize(
                "wall_cap",
                "任务墙钟预算已用完。请总结已有进展，不要再调用任何工具。",
            )
        try:
            # 单跳硬超时：CLI 系模型撞限额可能长挂——超时按停滞收尾，绝不让一跳拖死整个循环。
            with bind_provider_call_scope(
                role=_provider_role(f"reasoning.step_{step + 1}")
            ):
                res, _served, _route = await asyncio.wait_for(
                    chat_with_fallback(router, req), timeout=call_budget
                )
        except asyncio.TimeoutError:
            if _deadline - _wall_now() <= 0:
                return await _finalize(
                    "wall_cap",
                    "任务墙钟预算已用完；在途模型调用已取消。请总结已有进展，不要再调用任何工具。",
                )
            return await _finalize(
                "stall",
                "上游模型调用超时（600s，可能挂死/撞限额）。请基于已有进展给出目前结论与未完成事项。",
            )
        except Exception as e:  # noqa: BLE001
            # 兜底：上游报「只支持文本输入」（vision 标注缺失/不准时预剥没兜住）→ 剥图重试一次，
            # 别让一张图炸掉整个编排（机主实测 400 InvalidParameter: Model only support text input）。
            emsg = str(e)
            if (
                not images_stripped
                and any(isinstance(x.get("content"), list) for x in msgs)
                and re.search(r"only support text|not support.*(image|vision)|不支持.*(图|视觉)", emsg, re.I)
            ):
                images_stripped = True
                msgs = _strip_image_parts(msgs)
                tool_log.append("(上游不吃图片输入 → 已把历史图片转文字占位重试)")
                continue
            raise
        _remember_actual(_served, _route, res)
        _acc_usage(res)
        m = (res.get("choices") or [{}])[0].get("message", {})
        tcs = m.get("tool_calls")
        if not tcs:
            public_reply = _strip_think(m.get("content") or "")
            if not public_reply.strip():
                return _seal_tool_agent_result({
                    "reply": "模型未返回可显示内容，本轮未完成；请重试或更换模型。",
                    "steps": step,
                    "model": "nachuan-engine",
                    "actual_model": actual_model,
                    "actual_models": list(actual_models),
                    "author_receipts": list(author_receipts),
                    "usage": {k: v for k, v in usage.items() if v},
                    "tool_log": tool_log,
                    "file_changes": file_changes,
                    "media": media,
                    "pending_videos": pending_videos,
                    "stopped_reason": "empty_response",
                }, outcome="failed")
            return _seal_tool_agent_result({
                "reply": public_reply,
                "steps": step,
                "model": actual_model,
                "actual_model": actual_model,
                "actual_models": list(actual_models),
                "author_receipts": list(author_receipts),
                "usage": {k: v for k, v in usage.items() if v},
                "tool_log": tool_log,
                "file_changes": file_changes,
                "media": media,
                "pending_videos": pending_videos,
            }, outcome="completed_unverified")
        msgs.append({"role": "assistant", "content": m.get("content"), "tool_calls": tcs})
        for tool_index, tc in enumerate(tcs):
            fn = tc.get("function", {})
            name = str(fn.get("name", "") or "")
            raw_args = fn.get("arguments")
            # Capability 必须在执行层再次校验。tools schema 只是给模型的提示，恶意/异常上游
            # 仍可伪造未声明的 tool_call；绝不能因此越权执行。
            if allow is not None and name not in allow:
                denial = f"⛔ 未授权工具：{name or '(empty)'}；本轮 capability 不允许执行。"
                entry = f"{name or '(empty)'}(<denied>) -> {denial}"
                tool_log.append(entry)
                await _emit_step(entry)
                msgs.append({
                    "role": "tool",
                    "tool_call_id": tc.get("id"),
                    "content": denial,
                })
                return await _finalize(
                    "capability_violation",
                    f"上游尝试调用未授权工具 {name or '(empty)'}，本轮已立即停止。"
                    "不要再调用任何工具，只用文字说明未执行任何动作并给出安全建议。",
                )
            # ---- A1：参数解析失败不静默，回喂纠错（带正确 schema），超上限才兜底执行 ----
            try:
                a = json.loads(raw_args or "{}")
                if not isinstance(a, dict):
                    raise ValueError("arguments 不是 JSON 对象")
            except Exception as pe:  # noqa: BLE001
                cnt = arg_repairs.get(name, 0)
                if cnt < _MAX_ARG_REPAIRS:
                    arg_repairs[name] = cnt + 1
                    tip = (
                        f"上一步调用 {name} 的 arguments 不是合法 JSON 对象（{pe}），已忽略。"
                        f"请重发一次：{_tool_schema_hint(name)}"
                    )
                    tool_log.append(f"{name}(<malformed>) -> 参数纠错回喂[{cnt + 1}/{_MAX_ARG_REPAIRS}]")
                    msgs.append({"role": "tool", "tool_call_id": tc.get("id"), "content": tip})
                    continue
                # 修复已达上限：兜底以空参执行，避免卡死在纠错回合。
                a = {}
            # 时长兜底：用户明说了"20秒/1分钟"但模型偷懒没传 seconds → 从任务原话解析补上
            # （机主实测：说了20秒永远只出5秒——别指望模型每次都记得传参）。
            if name == "generate_video" and not a.get("seconds"):
                from orchestrator.media import parse_duration

                _dur = parse_duration(task)
                if _dur:
                    a["seconds"] = _dur
            # ---- A2：调用签名重复/停滞检测 ----
            sig = name + "|" + _canon_args(a)
            sig_repeat[sig] = sig_repeat.get(sig, 0) + 1
            _pv_before = len(pending_videos)  # 生视频任务派发即时推流用（见下）
            tool_budget = _deadline - _wall_now()
            if tool_budget <= 0:
                return await _finalize(
                    "wall_cap",
                    "任务墙钟预算已用完；未启动剩余工具。请总结已有进展。",
                )
            try:
                out = await asyncio.wait_for(
                    execute_tool(
                        name,
                        a,
                        workdir=workdir,
                        changes=file_changes,
                        router=router,
                        media=media,
                        pending_videos=pending_videos,
                        staged_images=staged_images,
                        author_receipts=author_receipts,
                        provider_role=_provider_role(
                            f"delegate.step_{step + 1}.call_{tool_index + 1}"
                        ),
                    ),
                    timeout=min(600.0, tool_budget),
                )
            except asyncio.TimeoutError:
                if _deadline - _wall_now() <= 0:
                    return await _finalize(
                        "wall_cap",
                        "任务墙钟预算已用完；在途工具已取消。请总结已有进展。",
                    )
                return await _finalize(
                    "stall",
                    "单次工具调用超时（600s），已取消；请总结已有进展和未完成事项。",
                )
            # 视频任务**派发即推**给前端登记锚点（不等最终结果）：机主实测点「插队」中止流
            # → 最终结果丢 → 任务其实还在引擎后台跑、前端却再也不知道。即时推就不怕中途打断。
            for _pv in pending_videos[_pv_before:]:
                if on_event is not None:
                    try:
                        await on_event({"type": "pending_video", **_pv})
                    except Exception:  # noqa: BLE001
                        pass
            out_s = str(out)
            # 连续相同结果计数（同一签名且结果与上次一致）。
            if sig_last_out.get(sig) == out_s:
                sig_same_out[sig] = sig_same_out.get(sig, 0) + 1
            else:
                sig_same_out[sig] = 1
            sig_last_out[sig] = out_s
            _entry = f"{name}({a}) -> {out_s[:240]}"
            tool_log.append(_entry)
            await _emit_step(_entry)  # 实时逐步流式：这一步即时推给前端，不再等整批干完
            msgs.append({"role": "tool", "tool_call_id": tc.get("id"), "content": out_s[:6000]})
            # A1：未知工具计入修复计数——execute_tool 已回喂有效工具清单，但要防它一直乱点。
            if out_s.startswith("未知工具："):
                arg_repairs[name] = arg_repairs.get(name, 0) + 1
            stalled = sig_repeat[sig] >= _STALL_REPEAT_LIMIT or sig_same_out[sig] >= _STALL_REPEAT_LIMIT
            if stalled:
                if sig not in stall_warned:
                    stall_warned.add(sig)
                    msgs.append({
                        "role": "system",
                        "content": (
                            f"你在重复调用 {name} 且没有进展（相同调用已 {sig_repeat[sig]} 次）。"
                            "换一种方法、换参数，或直接用文字给出目前能得到的结论，不要再原样重试。"
                        ),
                    })
                else:
                    # 已提示过仍原地打转 → 打断循环，带部分成果优雅收尾。
                    return await _finalize(
                        "stall",
                        f"你已多次重复调用 {name} 仍无进展，现在停止使用工具，直接用文字总结："
                        "已经完成/查明了什么、还差什么、以及给用户的建议。",
                    )
    # A4：步数用尽——让模型给"已完成什么 + 还剩什么"的总结，而非裸提示。
    return await _finalize(
        "max_steps",
        "已达到本次执行的步数上限。现在停止使用工具，直接用文字给出总结："
        "已经完成了什么、还剩什么没做、以及用户可以怎样继续。",
    )
