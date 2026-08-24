"""Claude（订阅）适配器：通过本机 claude CLI 的 headless (-p) 模式驱动，复用 Max/Pro 订阅鉴权。

计费提示（2026-06-15 起）：headless/SDK 用法走独立 Agent SDK 额度池（按 API 价、月度封顶），
不再吃交互订阅额度。便宜走量用火山，高价值用 Claude。

M2a 仅做"纯聊天"模式：`--tools ""` 禁用所有工具（不碰文件/命令）。
同用户的 agent 宿主执行实现已删除，仅保留指向未来隔离 worker 的 fail-closed 方法。
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import ctypes
import json
import logging
import math
import os
import re
import signal
import subprocess
import tempfile
import threading
import time
from typing import Any, AsyncIterator, Callable, Optional

from gateway.providers.base import ChatProvider, ProviderError
from gateway.model_identity import canonical_model_id
from gateway.providers.attested_cli import from_environment, matches_attestation
from gateway.providers.cli_env import sanitized_cli_env
from gateway.public_media import PublicFetchError, fetch_public_bytes
from gateway.secure_store import (
    SecureStorageError,
    harden_restricted_windows_acl,
    trusted_windows_system_executable,
)
from gateway.schemas import (
    ChatCompletionRequest,
    ChatCompletionResponse,
    Usage,
    _gen_id,
    final_chunk,
    text_chunk,
)


_MAX_IMAGES = 4
_MAX_IMAGE_BYTES = 10 * 1024 * 1024
_MAX_MODEL_USAGE_MODELS = 16
_MAX_MODEL_USAGE_ID_CHARS = 160
_MAX_REPORTED_TOKENS = (1 << 63) - 1
_MAX_CLAUDE_SYSTEM_PROMPT_BYTES = 4 * 1024 * 1024
_MAX_CLAUDE_CONVERSATION_BYTES = 20 * 1024 * 1024
_PRIVATE_CLAUDE_ROOT_LOCK = threading.Lock()
_PRIVATE_CLAUDE_ROOT: tempfile.TemporaryDirectory[str] | None = None
_CLAUDE_RUNTIME_COMPROMISED = threading.Event()
_LOG = logging.getLogger(__name__)


def _strict_reported_count(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, float):
        if not math.isfinite(value) or not value.is_integer():
            return None
        parsed = int(value)
    elif isinstance(value, str):
        raw = value.strip()
        if len(raw) > 32 or re.fullmatch(r"[0-9]+", raw) is None:
            return None
        parsed = int(raw)
    else:
        return None
    return parsed if 0 <= parsed <= _MAX_REPORTED_TOKENS else None


def _bounded_cli_input(
    value: str,
    *,
    fallback: str,
    maximum: int,
    label: str,
) -> bytes:
    raw = (value or fallback).encode("utf-8")
    if len(raw) > maximum:
        raise ProviderError(
            f"Claude CLI {label} exceeds the provider safety limit",
            status_code=413,
        )
    return raw


def _write_exclusive_private_file(path: str, payload: bytes) -> None:
    """Create a bounded transient input without following or replacing a path."""

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("short write while preparing Claude CLI input")
            remaining = remaining[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _private_claude_root() -> str:
    """Create and retain one verified ACL boundary for transient CLI inputs."""

    global _PRIVATE_CLAUDE_ROOT
    with _PRIVATE_CLAUDE_ROOT_LOCK:
        current = _PRIVATE_CLAUDE_ROOT
        if current is not None:
            try:
                metadata = os.lstat(current.name)
            except OSError:
                metadata = None
            if (
                metadata is not None
                and not (getattr(metadata, "st_file_attributes", 0) & 0x400)
                and os.path.isdir(current.name)
            ):
                return current.name
            current.cleanup()
            _PRIVATE_CLAUDE_ROOT = None

        candidate = tempfile.TemporaryDirectory(
            prefix="nachuan-claude-private-",
            ignore_cleanup_errors=True,
        )
        try:
            if os.name == "nt":
                harden_restricted_windows_acl(candidate.name, directory=True)
            else:
                os.chmod(candidate.name, 0o700)
        except BaseException:
            candidate.cleanup()
            raise
        _PRIVATE_CLAUDE_ROOT = candidate
        return candidate.name


class _ProtectedPromptDirectory(tempfile.TemporaryDirectory[str]):
    """Preserve the active exception while making cleanup failure fatal."""

    def __exit__(self, exc_type: Any, exc: BaseException | None, tb: Any) -> bool:
        del exc_type, tb
        try:
            self.cleanup()
        except OSError as cleanup_error:
            _CLAUDE_RUNTIME_COMPROMISED.set()
            _LOG.critical(
                "claude protected-input cleanup failed; runtime is disabled "
                "until restart (error_type=%s)",
                type(cleanup_error).__name__,
            )
            if exc is not None:
                exc.add_note(
                    "Claude protected-input cleanup failed; runtime disabled until restart"
                )
                return False
            raise ProviderError(
                "Claude CLI protected-input cleanup failed; runtime disabled until restart",
                status_code=503,
            ) from cleanup_error
        return False


def _prepare_prompt_workspace(
    system: str,
    conversation: str,
) -> tuple[_ProtectedPromptDirectory, bytes]:
    """Encode and write bounded inputs outside the asyncio event loop."""

    system_bytes = _bounded_cli_input(
        system,
        fallback="You are a helpful assistant. Reply in the user's language.",
        maximum=_MAX_CLAUDE_SYSTEM_PROMPT_BYTES,
        label="system prompt",
    )
    conversation_bytes = _bounded_cli_input(
        conversation,
        fallback=" ",
        maximum=_MAX_CLAUDE_CONVERSATION_BYTES,
        label="conversation",
    )
    workspace: _ProtectedPromptDirectory | None = None
    try:
        workspace = _ProtectedPromptDirectory(
            prefix="nachuan-claude-chat-",
            dir=_private_claude_root(),
            ignore_cleanup_errors=False,
        )
        _write_exclusive_private_file(
            os.path.join(workspace.name, "system-prompt.txt"),
            system_bytes,
        )
        return workspace, conversation_bytes
    except BaseException:
        if workspace is not None:
            try:
                workspace.cleanup()
            except OSError as cleanup_error:
                _CLAUDE_RUNTIME_COMPROMISED.set()
                _LOG.critical(
                    "claude failed-input preparation cleanup failed; runtime is "
                    "disabled until restart (error_type=%s)",
                    type(cleanup_error).__name__,
                )
                raise ProviderError(
                    "Claude CLI input preparation cleanup failed; runtime disabled "
                    "until restart",
                    status_code=503,
                ) from cleanup_error
        raise


async def _prepare_prompt_workspace_async(
    system: str,
    conversation: str,
) -> tuple[_ProtectedPromptDirectory, bytes]:
    cancellation_requested = threading.Event()

    def prepare_with_cancellation_ownership(
    ) -> tuple[_ProtectedPromptDirectory, bytes] | None:
        prepared = _prepare_prompt_workspace(system, conversation)
        if cancellation_requested.is_set():
            workspace, _ = prepared
            _cleanup_cancelled_prompt_workspace(workspace)
            return None
        return prepared

    preparation = asyncio.create_task(
        asyncio.to_thread(prepare_with_cancellation_ownership)
    )
    try:
        prepared = await asyncio.shield(preparation)
        if prepared is None:
            raise asyncio.CancelledError
        return prepared
    except asyncio.CancelledError:
        cancellation_requested.set()
        preparation.add_done_callback(_cleanup_cancelled_preparation_result)
        raise


def _cleanup_cancelled_prompt_workspace(
    workspace: _ProtectedPromptDirectory,
) -> None:
    try:
        workspace.cleanup()
    except OSError as cleanup_error:
        _CLAUDE_RUNTIME_COMPROMISED.set()
        _LOG.critical(
            "claude cancelled-input cleanup failed; runtime is disabled until "
            "restart (error_type=%s)",
            type(cleanup_error).__name__,
        )


def _cleanup_cancelled_preparation_result(task: asyncio.Task[Any]) -> None:
    try:
        prepared = task.result()
    except BaseException:
        return
    if prepared is None:
        return
    workspace, _ = prepared
    threading.Thread(
        target=_cleanup_cancelled_prompt_workspace,
        args=(workspace,),
        name="nachuan-claude-cancel-cleanup",
        daemon=True,
    ).start()


def _close_windows_handle(handle: int | None) -> None:
    if os.name != "nt" or handle is None:
        return
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    kernel32.CloseHandle(ctypes.c_void_p(handle))


def _lock_attested_windows_executable(path: str, expected_sha256: str) -> int | None:
    """Lock one exact executable against write/delete while its hash is checked."""

    if os.name != "nt":
        return None
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    kernel32.CreateFileW.restype = ctypes.c_void_p
    # GENERIC_READ + FILE_SHARE_READ intentionally denies any concurrent or
    # future writer/deleter.  A pre-opened writable handle makes this fail.
    raw_handle = kernel32.CreateFileW(
        path,
        0x80000000,
        0x00000001,
        None,
        3,
        0x00000080,
        None,
    )
    handle = int(raw_handle or 0)
    invalid = ctypes.c_void_p(-1).value
    if not handle or handle == invalid:
        return None
    if not matches_attestation(path, expected_sha256):
        _close_windows_handle(handle)
        return None
    return handle


_MAX_IMAGE_TOTAL_BYTES = 20 * 1024 * 1024
_PROCESS_CLEANUP_TIMEOUT_SECONDS = 3.0


def _capture_windows_descendant_handles(root_pid: int) -> tuple[list[int], bool]:
    """Freeze exact descendant process objects before tree termination.

    ``taskkill /T`` can return after the direct parent exits while an orphaned
    descendant is still alive.  Open handles survive PID reuse and let cleanup
    both terminate and verify every descendant that existed at capture time.
    """

    if os.name != "nt":
        return [], True

    from ctypes import wintypes

    class _ProcessEntry32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.c_size_t),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", wintypes.WCHAR * 260),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    kernel32.Process32FirstW.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(_ProcessEntry32W),
    ]
    kernel32.Process32FirstW.restype = wintypes.BOOL
    kernel32.Process32NextW.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(_ProcessEntry32W),
    ]
    kernel32.Process32NextW.restype = wintypes.BOOL
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = ctypes.c_void_p

    snapshot_raw = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
    snapshot = int(snapshot_raw or 0)
    if not snapshot or snapshot == ctypes.c_void_p(-1).value:
        return [], False

    parents: dict[int, list[int]] = {}
    enumeration_verified = True
    try:
        entry = _ProcessEntry32W()
        entry.dwSize = ctypes.sizeof(entry)
        if not kernel32.Process32FirstW(ctypes.c_void_p(snapshot), ctypes.byref(entry)):
            return [], False
        while True:
            pid = int(entry.th32ProcessID)
            parent_pid = int(entry.th32ParentProcessID)
            parents.setdefault(parent_pid, []).append(pid)
            ctypes.set_last_error(0)
            if not kernel32.Process32NextW(
                ctypes.c_void_p(snapshot), ctypes.byref(entry)
            ):
                enumeration_verified = ctypes.get_last_error() == 18
                break
    finally:
        _close_windows_handle(snapshot)

    descendant_pids: list[int] = []
    pending = [int(root_pid)]
    seen = {int(root_pid)}
    while pending:
        parent_pid = pending.pop()
        for pid in parents.get(parent_pid, []):
            if pid in seen:
                continue
            seen.add(pid)
            descendant_pids.append(pid)
            pending.append(pid)

    handles: list[int] = []
    verified = enumeration_verified
    for pid in descendant_pids:
        ctypes.set_last_error(0)
        raw_handle = kernel32.OpenProcess(0x00000001 | 0x00100000, False, pid)
        handle = int(raw_handle or 0)
        if handle:
            handles.append(handle)
            continue
        # ERROR_INVALID_PARAMETER means the snapshotted process exited before
        # OpenProcess; every other failure prevents positive verification.
        if ctypes.get_last_error() != 87:
            verified = False
    return handles, verified


def _terminate_and_verify_windows_handles(handles: list[int], timeout: float) -> bool:
    if os.name != "nt" or not handles:
        return True

    from ctypes import wintypes

    wait_object_0 = 0x00000000
    wait_timeout = 0x00000102
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.TerminateProcess.argtypes = [ctypes.c_void_p, wintypes.UINT]
    kernel32.TerminateProcess.restype = wintypes.BOOL

    for handle in handles:
        if kernel32.WaitForSingleObject(ctypes.c_void_p(handle), 0) == wait_timeout:
            kernel32.TerminateProcess(ctypes.c_void_p(handle), 137)

    deadline = time.monotonic() + max(0.0, timeout)
    verified = True
    for handle in handles:
        remaining_ms = max(0, int((deadline - time.monotonic()) * 1000))
        wait_result = int(
            kernel32.WaitForSingleObject(ctypes.c_void_p(handle), remaining_ms)
        )
        if wait_result != wait_object_0:
            verified = False
    return verified


def _consume_task_result(task: asyncio.Task[Any]) -> None:
    if not task.done():
        return
    try:
        task.result()
    except BaseException:
        pass


async def _wait_process(proc: Any, timeout: float) -> bool:
    if proc.returncode is not None:
        return True
    waiter = asyncio.create_task(proc.wait())
    done, _ = await asyncio.wait({waiter}, timeout=max(0.0, timeout))
    if waiter in done:
        _consume_task_result(waiter)
        return proc.returncode is not None
    waiter.cancel()
    waiter.add_done_callback(_consume_task_result)
    return False


async def _terminate_process_tree(
    proc: Any,
    *,
    cleanup_timeout: float = _PROCESS_CLEANUP_TIMEOUT_SECONDS,
    verdict_observer: Callable[[dict[str, bool | float | int]], None] | None = None,
) -> bool:
    """Terminate and positively verify the direct process and its tree."""

    if proc.returncode is not None:
        # A terminal direct parent is not proof that its Windows descendants
        # stopped.  Without a pre-termination capture, fail closed.
        return os.name != "nt"
    loop = asyncio.get_running_loop()
    deadline = loop.time() + max(0.1, cleanup_timeout)
    descendant_handles: list[int] = []
    descendant_capture_verified = True
    taskkill_verified = os.name != "nt"
    taskkill_started = False
    taskkill_finished = False
    taskkill_returncode_zero = False

    try:
        if os.name == "nt":
            descendant_handles, descendant_capture_verified = await asyncio.to_thread(
                _capture_windows_descendant_handles,
                int(proc.pid),
            )
            # Keep taskkill as the first tree-wide action, but reserve budget
            # for handle-based termination and verification if it returns with
            # an orphan still alive.
            try:
                taskkill = str(trusted_windows_system_executable("taskkill.exe"))
                windows_root = str(os.path.dirname(os.path.dirname(taskkill)))
                killer = await asyncio.create_subprocess_exec(
                    taskkill,
                    "/PID",
                    str(proc.pid),
                    "/T",
                    "/F",
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env={"SystemRoot": windows_root, "WINDIR": windows_root},
                )
                taskkill_started = True
                remaining = max(0.0, deadline - loop.time())
                killer_finished = await _wait_process(
                    killer,
                    remaining,
                )
                taskkill_finished = killer_finished
                taskkill_returncode_zero = killer.returncode == 0
                taskkill_verified = taskkill_finished and taskkill_returncode_zero
                if killer.returncode is None:
                    killer.kill()
            except (FileNotFoundError, OSError, ProcessLookupError):
                pass
        else:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except (OSError, ProcessLookupError):
                try:
                    proc.terminate()
                except ProcessLookupError:
                    pass

        remaining = max(0.0, deadline - loop.time())
        parent_terminated = await _wait_process(proc, min(1.0, remaining / 2))
        if not parent_terminated:
            try:
                if os.name == "nt":
                    proc.kill()
                else:
                    os.killpg(proc.pid, signal.SIGKILL)
            except (OSError, ProcessLookupError):
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
            parent_terminated = await _wait_process(
                proc,
                max(0.0, deadline - loop.time()),
            )

        if os.name == "nt":
            descendants_terminated = await asyncio.to_thread(
                _terminate_and_verify_windows_handles,
                descendant_handles,
                max(0.0, deadline - loop.time()),
            )
            if verdict_observer is not None:
                verdict_observer(
                    {
                        "snapshot_verified": descendant_capture_verified,
                        "captured_handle_count": len(descendant_handles),
                        "taskkill_started": taskkill_started,
                        "taskkill_finished": taskkill_finished,
                        "taskkill_returncode_zero": taskkill_returncode_zero,
                        "parent_terminated": parent_terminated,
                        "descendants_terminated": descendants_terminated,
                        "remaining_budget_seconds": max(0.0, deadline - loop.time()),
                    }
                )
            return (
                parent_terminated
                and descendant_capture_verified
                and descendants_terminated
                and taskkill_verified
            )

        try:
            os.killpg(proc.pid, 0)
        except ProcessLookupError:
            process_group_terminated = True
        except OSError:
            process_group_terminated = False
        else:
            process_group_terminated = False
        return parent_terminated and process_group_terminated
    finally:
        for handle in descendant_handles:
            _close_windows_handle(handle)


async def _cleanup_process_after_interrupt(proc: Any) -> bool:
    cleanup = asyncio.create_task(_terminate_process_tree(proc))
    done, _ = await asyncio.wait(
        {cleanup},
        timeout=_PROCESS_CLEANUP_TIMEOUT_SECONDS + 0.25,
    )
    if cleanup in done:
        try:
            return cleanup.result() is True
        except BaseException:
            return False
    # Do not cancel a timed-out cleanup.  ``asyncio.to_thread`` work cannot be
    # stopped, and cancellation would run _terminate_process_tree's ``finally``
    # while its worker may still be waiting on the captured Windows handles.
    # Fail closed now, but let the cleanup task retain ownership and drain.
    cleanup.add_done_callback(_consume_task_result)
    return False


def _process_cleanup_failure(proc: Any) -> ProviderError:
    _CLAUDE_RUNTIME_COMPROMISED.set()
    _LOG.critical(
        "claude subprocess did not reach a terminal state; runtime is disabled "
        "until restart (pid=%s)",
        getattr(proc, "pid", "unknown"),
    )
    return ProviderError(
        "Claude CLI cleanup could not be verified; runtime disabled until restart",
        status_code=503,
    )


def _observed_claude_model(data: dict[str, Any], upstream_model: str) -> str:
    """Accept one request-aware primary model from Claude CLI usage metadata."""

    raw = data.get("modelUsage") or data.get("model_usage")
    if not isinstance(raw, dict):
        return ""
    all_candidates = {
        str(model).strip()
        for model in raw
        if str(model).strip()
    }
    requested = canonical_model_id(upstream_model)
    if requested == "haiku" or (
        requested is not None and requested.startswith("claude-haiku-")
    ):
        candidates = {
            model for model in all_candidates if "haiku" in model.casefold()
        }
    else:
        # Sonnet/Opus requests can use Haiku as an auxiliary title/router
        # model.  It must not obscure or impersonate the unique primary.
        candidates = {
            model for model in all_candidates if "haiku" not in model.casefold()
        }
    return next(iter(candidates)) if len(candidates) == 1 else ""


def _claude_model_usage_breakdown(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Keep bounded provider evidence for auxiliary-model cost attribution.

    Claude CLI may report one primary model plus auxiliary Haiku work in a
    single process result.  The top-level token/cost totals therefore describe
    the CLI invocation, not necessarily one physical model.  Preserve the
    provider's per-model evidence without attempting an invented allocation.
    """

    raw = data.get("modelUsage") or data.get("model_usage")
    if not isinstance(raw, dict) or len(raw) > _MAX_MODEL_USAGE_MODELS:
        return {}

    def count(value: Any) -> int | None:
        return _strict_reported_count(value)

    output: dict[str, dict[str, Any]] = {}
    field_names = {
        "inputTokens": "input_tokens",
        "input_tokens": "input_tokens",
        "outputTokens": "output_tokens",
        "output_tokens": "output_tokens",
        "cacheReadInputTokens": "cache_read_input_tokens",
        "cache_read_input_tokens": "cache_read_input_tokens",
        "cacheCreationInputTokens": "cache_creation_input_tokens",
        "cache_creation_input_tokens": "cache_creation_input_tokens",
    }
    for raw_model, raw_usage in sorted(raw.items(), key=lambda item: str(item[0])):
        model = str(raw_model).strip()
        if not model or len(model) > _MAX_MODEL_USAGE_ID_CHARS or not isinstance(raw_usage, dict):
            continue
        normalized: dict[str, Any] = {}
        for source, target in field_names.items():
            if source in raw_usage:
                parsed = count(raw_usage.get(source))
                if parsed is not None:
                    normalized[target] = parsed
        raw_cost = raw_usage.get("costUSD", raw_usage.get("cost_usd"))
        if raw_cost is not None and not isinstance(raw_cost, bool):
            try:
                parsed_cost = float(raw_cost)
            except (TypeError, ValueError, OverflowError):
                parsed_cost = None
            if parsed_cost is not None and math.isfinite(parsed_cost) and parsed_cost >= 0:
                normalized["cost_usd"] = parsed_cost
        if normalized:
            output[model] = normalized
    return output


def _fetch_public_image(url: str) -> bytes:
    """Fetch one image with pinned public DNS, redirect, type and byte limits."""

    return fetch_public_bytes(
        url,
        max_bytes=_MAX_IMAGE_BYTES,
        allowed_type_prefixes=("image/",),
        total_timeout=30.0,
        idle_timeout=10.0,
        max_redirects=5,
        headers={"Accept": "image/*"},
    ).data


def _split_messages(req: ChatCompletionRequest) -> tuple[str, str]:
    """拆成 (system_prompt, conversation_text)。"""
    system_parts: list[str] = []
    convo_parts: list[str] = []
    for m in req.messages:
        content = m.content
        if isinstance(content, list):
            text = "".join(str(b.get("text", "")) for b in content if isinstance(b, dict))
        else:
            text = "" if content is None else str(content)
        if m.role == "system":
            system_parts.append(text)
        elif m.role == "assistant":
            convo_parts.append(f"Assistant: {text}")
        else:
            convo_parts.append(f"User: {text}")
    return "\n".join(system_parts).strip(), "\n\n".join(convo_parts).strip()


def _extract_images(req: ChatCompletionRequest) -> list[bytes]:
    """提取受限图片；无效、内网、超大或非图片输入一律忽略。"""

    out: list[bytes] = []
    total = 0
    for m in req.messages:
        if not isinstance(m.content, list):
            continue
        for b in m.content:
            if len(out) >= _MAX_IMAGES:
                return out
            if isinstance(b, dict) and b.get("type") == "image_url":
                url = ((b.get("image_url") or {}).get("url")) or ""
                try:
                    if url.startswith("data:"):
                        header, encoded = url.split(",", 1)
                        mime = header[5:].split(";", 1)[0].lower()
                        if not mime.startswith("image/") or ";base64" not in header.lower():
                            continue
                        if len(encoded) > ((_MAX_IMAGE_BYTES + 2) // 3) * 4 + 4:
                            continue
                        raw = base64.b64decode(encoded, validate=True)
                    elif url.startswith(("http://", "https://")):
                        raw = _fetch_public_image(url)
                    else:
                        continue
                    if not raw or len(raw) > _MAX_IMAGE_BYTES:
                        continue
                    if total + len(raw) > _MAX_IMAGE_TOTAL_BYTES:
                        return out
                    out.append(raw)
                    total += len(raw)
                except (ValueError, OSError, PublicFetchError, binascii.Error):
                    pass
    return out


def _extract_workdir(text: str) -> Optional[str]:
    """从用户消息里抠出一个【真实存在】的绝对路径，返回其目录（文件→父目录）；没有返回 None。
    用于「点名了目录就在那读写、没点名则放开」的判定。只认真实存在的路径，避免误判普通文字。"""
    import os

    if not text:
        return None
    cands = re.findall(r'[A-Za-z]:[\\/][^\s，。、；：:"\'<>|?*\n\r]*', text)  # Windows C:\... / D:\灵犀日签
    cands += re.findall(r'/[^\s，。、；：:"\'<>|?*\n\r]+(?:/[^\s，。、；：:"\'<>|?*\n\r]+)*', text)  # Unix /a/b
    for raw in cands:
        p = raw.rstrip('\\/，。、；:：')
        try:
            if os.path.exists(p):
                return p if os.path.isdir(p) else os.path.dirname(p)
        except OSError:
            continue
    return None


def _parse_result_json(out: str) -> Optional[dict[str, Any]]:
    out = (out or "").strip()
    if not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        for line in reversed(out.splitlines()):
            s = line.strip()
            if s.startswith("{"):
                try:
                    return json.loads(s)
                except json.JSONDecodeError:
                    continue
    return None


def _public_exit_code(value: object) -> str:
    """Keep only a bounded numeric process status in caller-visible errors."""

    if type(value) is int and -(1 << 31) <= value <= (1 << 32) - 1:
        return str(value)
    return "unknown"


def _public_cli_result_error_type(data: dict[str, Any]) -> str:
    """Classify a known condition without returning any upstream text."""

    result = data.get("result")
    sample = result[:4096].casefold() if isinstance(result, str) else ""
    if any(
        marker in sample
        for marker in (
            "not logged in",
            "please run /login",
            "authentication required",
            "login required",
        )
    ):
        return "authentication_required"
    return "upstream_error"


def _usage_from_claude(data: dict[str, Any]) -> Usage:
    raw = data.get("usage")
    if not isinstance(raw, dict):
        model_usage = _claude_model_usage_breakdown(data)
        return Usage(
            cost_basis="subscription_unallocated",
            provider_model_usage=model_usage or None,
            cost_attribution_basis=(
                "cli_invocation_total_includes_provider_internal_models"
                if model_usage
                else "cli_invocation_total"
            ),
        )

    def _count(key: str) -> int | None:
        return _strict_reported_count(raw.get(key)) if key in raw else None

    input_tokens = _count("input_tokens")
    # In a present Claude usage object the cache-read field is optional and an
    # omitted field means this response reported no cache-read tokens.  This is
    # distinct from the entire usage object being absent (handled above).
    cached_tokens = (
        _count("cache_read_input_tokens")
        if "cache_read_input_tokens" in raw
        else 0
    )
    cache_creation_tokens = (
        _count("cache_creation_input_tokens")
        if "cache_creation_input_tokens" in raw
        else 0
    )
    completion_tokens = _count("output_tokens")
    prompt_tokens = (
        input_tokens + cached_tokens + cache_creation_tokens
        if (
            input_tokens is not None
            and cached_tokens is not None
            and cache_creation_tokens is not None
        )
        else None
    )
    total_tokens = (
        prompt_tokens + completion_tokens
        if prompt_tokens is not None and completion_tokens is not None
        else None
    )
    model_usage = _claude_model_usage_breakdown(data)
    return Usage(
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        total_tokens=total_tokens,
        cached_tokens=cached_tokens,
        cache_read_tokens=cached_tokens,
        cache_creation_tokens=cache_creation_tokens,
        cost_basis="subscription_unallocated",
        provider_model_usage=model_usage or None,
        cost_attribution_basis=(
            "cli_invocation_total_includes_provider_internal_models"
            if model_usage
            else "cli_invocation_total"
        ),
    )


class ClaudeCodeProvider(ChatProvider):
    def __init__(
        self,
        name: str = "claude_code",
        *,
        max_budget_usd: Optional[float] = 2.0,
        timeout_s: float = 180.0,
    ):
        self.name = name
        attestation = from_environment("CLAUDE_CLI_PATH", "CLAUDE_CLI_SHA256")
        self._cli = attestation.path if attestation else None
        self._cli_sha256 = attestation.sha256 if attestation else ""
        self.enabled = attestation is not None
        self.max_budget_usd = max_budget_usd
        self.timeout_s = timeout_s
        self._cli_lock_guard = threading.Lock()
        self._cli_lock_handle: int | None = None
        self._cli_lock_identity: tuple[str, str] | None = None
        self._cli_lock_rejected_identity: tuple[str, str] | None = None
        self._lifecycle_guard = threading.Lock()
        self._active_runs = 0
        self._closing = False
        self._active_runs_drained = asyncio.Event()
        self._active_runs_drained.set()

    def _release_cli_lock(self) -> None:
        with self._cli_lock_guard:
            _close_windows_handle(self._cli_lock_handle)
            self._cli_lock_handle = None
            self._cli_lock_identity = None
            self._cli_lock_rejected_identity = None

    def _ensure_cli_attestation(self) -> bool:
        path = str(self._cli or "")
        digest = str(self._cli_sha256 or "").strip().lower()
        identity = (path, digest)
        with self._cli_lock_guard:
            if os.name == "nt":
                if self._cli_lock_rejected_identity == identity:
                    return False
                if self._cli_lock_rejected_identity is not None:
                    self._cli_lock_rejected_identity = None
                if self._cli_lock_handle is not None:
                    if self._cli_lock_identity == identity:
                        return True
                    _close_windows_handle(self._cli_lock_handle)
                    self._cli_lock_handle = None
                    self._cli_lock_identity = None
                handle = _lock_attested_windows_executable(path, digest)
                if handle is None:
                    self._cli_lock_rejected_identity = identity
                    return False
                self._cli_lock_handle = handle
                self._cli_lock_identity = identity
                return True
            return matches_attestation(path, digest)

    def __del__(self) -> None:
        try:
            self._release_cli_lock()
        except BaseException:
            pass

    def _enter_run(self) -> None:
        with self._lifecycle_guard:
            if self._closing:
                raise ProviderError(
                    "Claude CLI provider is closing; retry after reload",
                    status_code=503,
                )
            if self._active_runs == 0:
                self._active_runs_drained.clear()
            self._active_runs += 1

    def _leave_run(self) -> None:
        with self._lifecycle_guard:
            if self._active_runs <= 0:
                _CLAUDE_RUNTIME_COMPROMISED.set()
                _LOG.critical("claude provider lifecycle counter underflow")
                return
            self._active_runs -= 1
            if self._active_runs == 0:
                self._active_runs_drained.set()

    async def aclose(self) -> None:
        """Drain active calls before deterministically releasing the EXE pin."""

        with self._lifecycle_guard:
            self._closing = True
            drained = self._active_runs == 0
        if not drained:
            await self._active_runs_drained.wait()
        self._release_cli_lock()

    def expected_model_family(self, upstream_model: str) -> str | None:
        model = canonical_model_id(upstream_model)
        if model and (
            model in {"sonnet", "opus", "haiku"}
            or model.startswith("claude-")
        ):
            return "anthropic"
        return None

    def verify_model_identity(
        self,
        upstream_model: str,
        observed_model: str,
    ) -> tuple[str, str] | None:
        expected = canonical_model_id(upstream_model)
        observed = canonical_model_id(observed_model)
        if expected is None or observed is None:
            return None
        if expected == observed and observed.startswith("claude-"):
            return str(observed_model).strip(), "anthropic"
        # Claude CLI aliases are documented request selectors.  The actual
        # dated model must still carry the same explicit family token.
        if expected in {"sonnet", "opus", "haiku"} and observed.startswith(
            f"claude-{expected}-"
        ):
            return str(observed_model).strip(), "anthropic"
        return None

    def _args(self, upstream_model: str, system_prompt_path: str) -> list[str]:
        args = [
            self._cli or "claude",
            "-p",
            "--model", upstream_model or "sonnet",
            # Print mode skips the workspace trust dialog.  Explicit safe-mode
            # prevents project/user CLAUDE.md, hooks, plugins, MCP and commands
            # from turning a text-only request into local execution.
            "--safe-mode",
            "--no-chrome",
            "--disable-slash-commands",
            "--tools", "",  # 纯聊天：禁用所有工具
            "--no-session-persistence",
            "--input-format", "text",
            "--output-format", "json",
        ]
        # 纯聊天模式：用受限文件替换 Claude Code 默认的庞大系统提示词（约 7800 tokens），
        # 把每次调用成本从 ~$0.05 降到 ~$0.001（实测）。
        # 内容不得进入 argv；Windows 进程枚举、EDR 和崩溃遥测可能采集命令行。
        args += ["--system-prompt-file", system_prompt_path]
        if self.max_budget_usd:
            args += ["--max-budget-usd", str(self.max_budget_usd)]
        return args

    async def agent_exec(
        self,
        task: str,
        *,
        upstream_model: str,
        workdir: str,
        allowed_tools: str,
        permission_mode: str = "acceptEdits",
        mcp_config: str = "",
    ) -> dict[str, Any]:
        """Fail closed until an OS-isolated execution worker exists."""
        del task, upstream_model, workdir, allowed_tools, permission_mode, mcp_config
        raise ProviderError(
            "Claude 本机执行已关闭：需要与网关凭据隔离的低权限 worker",
            status_code=503,
        )

    async def _run(self, upstream_model: str, system: str, convo: str) -> dict[str, Any]:
        self._enter_run()
        try:
            return await self._run_pinned(upstream_model, system, convo)
        finally:
            self._leave_run()

    async def _run_pinned(
        self,
        upstream_model: str,
        system: str,
        convo: str,
    ) -> dict[str, Any]:
        """Run only the attested, tool-disabled chat CLI in an empty directory."""
        if _CLAUDE_RUNTIME_COMPROMISED.is_set():
            raise ProviderError(
                "Claude CLI runtime is disabled after an unverified cleanup; restart required",
                status_code=503,
            )
        if not self._cli or not await asyncio.to_thread(self._ensure_cli_attestation):
            raise ProviderError(
                "Claude CLI 未通过绝对路径 + SHA-256 证明，已拒绝启动",
                status_code=503,
            )

        try:
            workspace, conversation_bytes = await _prepare_prompt_workspace_async(
                system,
                convo,
            )
        except (OSError, SecureStorageError) as e:
            raise ProviderError(
                "Claude CLI could not prepare its protected input boundary",
                status_code=503,
            ) from e
        with workspace as clean_cwd:
            system_prompt_path = os.path.join(clean_cwd, "system-prompt.txt")
            args = self._args(upstream_model, system_prompt_path)
            kwargs: dict[str, Any] = dict(
                cwd=clean_cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=sanitized_cli_env(),
                stdin=subprocess.PIPE,
            )
            if os.name == "nt":
                kwargs["creationflags"] = (
                    getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                    | getattr(subprocess, "CREATE_NO_WINDOW", 0)
                )
            else:
                kwargs["start_new_session"] = True
            try:
                proc = await asyncio.create_subprocess_exec(*args, **kwargs)
            except FileNotFoundError as e:
                raise ProviderError("未找到 claude 命令行（请先安装并登录 Claude Code）", status_code=502) from e
            except OSError as e:
                raise ProviderError(
                    "Claude CLI 无法启动（error_type=os_error）",
                    status_code=502,
                ) from e

            communicate = asyncio.create_task(
                proc.communicate(input=conversation_bytes)
            )
            try:
                done, _ = await asyncio.wait({communicate}, timeout=self.timeout_s)
            except asyncio.CancelledError:
                communicate.cancel()
                communicate.add_done_callback(_consume_task_result)
                if not await _cleanup_process_after_interrupt(proc):
                    cleanup_error = _process_cleanup_failure(proc)
                    cleanup_error.add_note(
                        "The original Claude request was cancelled during cleanup"
                    )
                    raise cleanup_error
                raise
            if communicate not in done:
                communicate.cancel()
                communicate.add_done_callback(_consume_task_result)
                timeout_error = ProviderError(
                    "Claude CLI 请求超时（error_type=timeout）",
                    status_code=504,
                )
                if not await _cleanup_process_after_interrupt(proc):
                    raise _process_cleanup_failure(proc) from timeout_error
                raise timeout_error
            try:
                stdout_bytes, _stderr_bytes = communicate.result()
            except asyncio.CancelledError as result_error:
                if not await _cleanup_process_after_interrupt(proc):
                    raise _process_cleanup_failure(proc) from result_error
                raise
            except Exception as result_error:
                if not await _cleanup_process_after_interrupt(proc):
                    raise _process_cleanup_failure(proc) from result_error
                raise ProviderError(
                    "Claude CLI 进程结果不可用（error_type=process_io）",
                    status_code=502,
                ) from result_error

            stdout = (
                stdout_bytes.decode("utf-8", errors="ignore")
                if isinstance(stdout_bytes, bytes)
                else str(stdout_bytes or "")
            )
            data = _parse_result_json(stdout)
            if not isinstance(data, dict):
                raise ProviderError(
                    "Claude CLI 输出无法解析"
                    "（error_type=invalid_output, "
                    f"exit_code={_public_exit_code(proc.returncode)}）",
                    status_code=502,
                )
            if data.get("is_error"):
                raise ProviderError(
                    "Claude CLI 调用失败"
                    f"（error_type={_public_cli_result_error_type(data)}, "
                    f"exit_code={_public_exit_code(proc.returncode)}）",
                    status_code=502,
                )
            if proc.returncode != 0:
                raise ProviderError(
                    "Claude CLI 进程异常退出"
                    "（error_type=nonzero_exit, "
                    f"exit_code={_public_exit_code(proc.returncode)}）",
                    status_code=502,
                )
            return data

    def _run_vision(
        self, req: ChatCompletionRequest, upstream_model: str, images: list[bytes]
    ) -> dict[str, Any]:
        """看图：图片存临时文件 → Claude 用 Read 工具看（prompt 走 stdin，图目录走 --add-dir）。"""
        del req, upstream_model, images
        raise ProviderError(
            "Claude CLI 看图已关闭：Read 工具不能在同一 OS 用户下隔离宿主凭据",
            status_code=503,
        )

    async def chat(self, req: ChatCompletionRequest, upstream_model: str) -> dict[str, Any]:
        images = _extract_images(req)
        if images:
            raise ProviderError(
                "Claude CLI 看图已关闭：请选择原生多模态 API 模型",
                status_code=503,
            )
        else:
            system, convo = _split_messages(req)
            # chat 是纯推理 interface：恒定禁用工具，不因文字里出现路径而隐式升级执行权限。
            # 宿主执行已关闭；后续只能接入隔离的低权限 worker。
            data = await self._run(upstream_model, system, convo)
        text = data.get("result") or ""
        usage = _usage_from_claude(data)
        raw_cost = data.get("total_cost_usd") if "total_cost_usd" in data else None
        if raw_cost is not None and not isinstance(raw_cost, bool):
            try:
                parsed_cost = float(raw_cost)
            except (TypeError, ValueError, OverflowError):
                parsed_cost = None
            if parsed_cost is not None and math.isfinite(parsed_cost) and parsed_cost >= 0:
                usage.cost_usd = parsed_cost
                usage.cost_basis = "provider_reported"
        resp = ChatCompletionResponse.from_text(
            model=_observed_claude_model(data, upstream_model),
            text=text,
            usage=usage,
        ).model_dump()
        return resp

    async def stream(
        self, req: ChatCompletionRequest, upstream_model: str
    ) -> AsyncIterator[dict[str, Any]]:
        # M2a：先取完整结果再分块吐出；真实 token 流式（stream-json）待登录后升级
        result = await self.chat(req, upstream_model)
        text = result["choices"][0]["message"]["content"] or ""
        usage = result.get("usage")
        observed_model = str(result.get("model") or "")
        cid = _gen_id("chatcmpl")
        first = True
        for piece in re.findall(r"\S+\s*|\s+", text) or [text]:
            yield text_chunk(
                model=observed_model,
                delta_text=piece,
                chunk_id=cid,
                role="assistant" if first else None,
            )
            first = False
        yield final_chunk(model=observed_model, chunk_id=cid, usage=usage)
