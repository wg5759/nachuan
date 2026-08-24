"""Fail-closed local launcher for optional third-party CLIs.

The application never consumes cli-anything's remote registry or install commands.
Only binaries pinned in a local, hash-verified allowlist may be launched.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import shlex
from dataclasses import dataclass
from pathlib import Path

from gateway.providers.cli_env import sanitized_cli_env


_REMOTE_INSTALL_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"(?:^|[;&|\s])npx(?:\.cmd)?(?:\s|$)", "npx remote package runner"),
    (r"(?:^|[;&|\s])npm(?:\.cmd)?\s+exec(?:\s|$)", "npm exec remote package runner"),
    (r"(?:^|[;&|\s])uvx(?:\.exe)?(?:\s|$)", "uvx remote package runner"),
    (r"(?:^|[;&|\s])pipx(?:\.exe)?\s+run(?:\s|$)", "pipx remote package runner"),
    (r"(?:^|[;&|\s])npm(?:\.cmd)?\s+(?:i|install|add)(?:\s|$)", "unlocked npm install"),
    (r"(?:^|[;&|\s])(?:python(?:\.exe)?\s+-m\s+)?pip(?:\d|\.exe)?\s+install(?![^\n]*--require-hashes)",
     "pip install without --require-hashes"),
    (r"(?:^|[;&|\s])uv(?:\.exe)?\s+pip\s+install(?![^\n]*--require-hashes)",
     "uv pip install without --require-hashes"),
)


def remote_install_reason(command: str) -> str:
    """Identify package-manager commands that download and immediately execute unpinned code."""

    low = str(command or "").lower()
    for pattern, reason in _REMOTE_INSTALL_PATTERNS:
        if re.search(pattern, low):
            return reason
    return ""


@dataclass(frozen=True)
class CliLaunchPlan:
    allowed: bool
    argv: list[str]
    env: dict[str, str]
    message: str


def plan_cli_launch(name: str, args: str, *, allowlist_path: str | Path) -> CliLaunchPlan:
    path = Path(allowlist_path)
    if not path.is_file():
        return CliLaunchPlan(False, [], {}, "未配置本地白名单，已拒绝启动第三方 CLI。")
    try:
        if path.stat().st_size > 256 * 1024:
            raise ValueError("allowlist too large")
        data = json.loads(path.read_text(encoding="utf-8"))
        key = (name or "").strip().lower()
        if not re.fullmatch(r"[a-z0-9._-]{1,64}", key):
            raise ValueError("invalid name")
        spec = data.get(key) if isinstance(data, dict) else None
        if not isinstance(spec, dict):
            raise ValueError("not allowlisted")
        executable = Path(str(spec.get("executable") or ""))
        expected = str(spec.get("sha256") or "").strip().lower()
        if not executable.is_absolute() or not executable.is_file():
            raise ValueError("missing executable")
        if not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise ValueError("missing hash")
        actual = hashlib.sha256(executable.read_bytes()).hexdigest()
        if not hmac.compare_digest(actual, expected):
            return CliLaunchPlan(False, [], {}, "本地白名单中的二进制哈希不匹配，已拒绝启动。")
        argv = [str(executable), *shlex.split(args or "", posix=os.name != "nt")]
        env = sanitized_cli_env()
        env.update(
            {
                "CLI_HUB_NO_ANALYTICS": "1",
                "DO_NOT_TRACK": "1",
                "NO_TELEMETRY": "1",
                "DISABLE_TELEMETRY": "1",
                "HF_HUB_DISABLE_TELEMETRY": "1",
                "SCARF_NO_ANALYTICS": "true",
            }
        )
        return CliLaunchPlan(True, argv, env, "本地白名单校验通过。")
    except (OSError, ValueError, json.JSONDecodeError):
        return CliLaunchPlan(False, [], {}, "本地白名单无有效条目，已拒绝启动第三方 CLI。")
