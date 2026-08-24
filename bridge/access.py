"""渠道调用者授权：生产默认拒绝，开发态全开放必须双重显式开启。"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Mapping


_TRUE = {"1", "true", "yes", "on"}
_DEVELOPMENT_ENVS = {"dev", "development", "local", "test"}


def explicit_development_allow_all(
    channel: str, environ: Mapping[str, str] | None = None
) -> bool:
    """只有开发环境 + 渠道专属开关同时存在时才允许全开放。"""
    env = os.environ if environ is None else environ
    runtime = str(env.get("NACHUAN_ENV", "production")).strip().lower()
    opt_in = str(env.get(f"{channel.upper()}_ALLOW_ALL", "")).strip().lower()
    return runtime in _DEVELOPMENT_ENVS and opt_in in _TRUE


@dataclass(frozen=True)
class ChannelAccessPolicy:
    allowed_users: set[str] = field(default_factory=set)
    allow_all: bool = False

    @property
    def configured(self) -> bool:
        return self.allow_all or bool(self.allowed_users)

    def permits(self, user_id: str | int | None) -> bool:
        if user_id is None:
            return False
        return self.allow_all or str(user_id).strip() in self.allowed_users
