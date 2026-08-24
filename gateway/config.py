"""配置加载：环境变量（.env，pydantic-settings）+ 模型路由表（models.yaml）。"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # 网关
    # 无默认口令：桌面端和 supervisor 都会生成随机 key。裸启动未显式配置时鉴权 fail-closed。
    gateway_api_keys: str = ""
    # A bridge receives only this endpoint-scoped credential.  It is never an
    # ordinary desktop/runtime key and therefore cannot authenticate to the
    # rest of the gateway surface.
    bridge_api_key: str = ""
    # The engine accepts two independently generated channel capabilities.
    # managed_launcher maps one into each child to prevent accidental cross-
    # channel use.  This is defense in depth, not a process-isolation boundary:
    # children running under the same Windows SID can still read one another's
    # protected files/process data and require a separate OS account/AppContainer
    # before a compromised bridge can be treated as isolated.
    nachuan_weixin_bridge_api_key: str = ""
    nachuan_feishu_bridge_api_key: str = ""
    # 审批面与普通 runtime API key 是两个独立信任域；空值时审批端点必须 fail-closed。
    approval_admin_key: str = ""
    # 付费图片/视频创建不能只凭 renderer 可见的普通 runtime Bearer。
    # Electron main 或受信后台代理持有第二把随机 key；空值时付费创建 fail-closed。
    nachuan_paid_media_api_key: str = ""
    # 动作审批/能力从创建起只存活 5~15 分钟；默认 10 分钟。
    approval_action_ttl_sec: int = Field(default=600, ge=300, le=900)
    gateway_host: str = "127.0.0.1"  # 安全默认=仅本机。局域网访问需显式 GATEWAY_HOST=0.0.0.0 且必须设真 key（见 app.py:main 护栏）
    gateway_port: int = 8080
    usage_db_path: str = "./data/usage.db"

    @field_validator("usage_db_path", mode="before")
    @classmethod
    def normalize_usage_db_path(cls, value: Any) -> str:
        """Anchor relative runtime state to the project, never the caller CWD."""

        raw = str(value or "").strip()
        if not raw:
            raise ValueError("USAGE_DB_PATH cannot be empty")
        candidate = Path(raw).expanduser()
        if not candidate.is_absolute():
            candidate = PROJECT_ROOT / candidate
        return str(candidate.resolve(strict=False))
    # 明确昂贵的 POST 请求在进入 handler 前经过稳定性闸。并发/分钟上限不允许
    # 用 0 绕过；只有持久化的每日上限可显式设为 0 关闭。
    admission_max_concurrency_per_key: int = Field(default=8, ge=1, le=64)
    admission_max_concurrency_global: int = Field(default=32, ge=1, le=512)
    admission_rolling_minute_per_key: int = Field(default=120, ge=1, le=10_000)
    admission_daily_expensive_per_key: int = Field(default=2000, ge=0, le=1_000_000)
    # 异步任务会超过 HTTP 响应寿命，因此另用终态 lease 限制真实后台工作。
    admission_background_jobs_global: int = Field(default=8, ge=1, le=256)
    admission_background_jobs_per_key: int = Field(default=4, ge=1, le=64)
    admission_background_job_ttl_sec: int = Field(default=21_600, ge=300, le=86_400)

    # 火山方舟（用户为 Coding Plan 套餐 → 用 coding 专属端点；通用端点为 /api/v3）
    volcano_api_key: str = ""
    volcano_base_url: str = "https://ark.cn-beijing.volces.com/api/coding/v3"

    # 手机桥接（M5）
    telegram_bot_token: str = ""
    telegram_allowed_users: str = ""  # 逗号分隔 Telegram user id；空=默认拒绝
    feishu_app_id: str = ""
    feishu_app_secret: str = ""
    # 渠道默认必须是纯聊天 provider；Codex CLI 是 capability-gated execution-only。
    bridge_model: str = "agnes-flash"
    bridge_engine_url: str = "http://127.0.0.1:8080"

    @field_validator("bridge_engine_url", mode="before")
    @classmethod
    def validate_bridge_engine_url(cls, value: Any) -> str:
        """A channel credential may only be sent to the local HTTP engine."""

        raw = str(value or "").strip()
        try:
            parsed = urlsplit(raw)
            port = parsed.port
        except (UnicodeError, ValueError) as exc:
            raise ValueError("BRIDGE_ENGINE_URL must be an exact loopback URL") from exc
        if (
            parsed.scheme != "http"
            or parsed.hostname != "127.0.0.1"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
            or port is None
            or not (1 <= port <= 65535)
        ):
            raise ValueError("BRIDGE_ENGINE_URL must be http://127.0.0.1:<port>")
        return f"http://127.0.0.1:{port}"
    # Deprecated/fail-closed: gateway lifespan refuses non-empty values because
    # the legacy path reused the inbound runtime bearer for outbound sync.
    sync_server_url: str = ""
    sync_interval_sec: int = 300  # 自动同步间隔（秒）
    backup_dir: str = ""  # 案例库快照目录（空=data/backup；可指向网盘做离线异地）
    backup_interval_sec: int = 21600  # 自动备份间隔（秒，默认 6 小时）

    # 超级智能体桥接策略：白名单/机主归一/限频；桌面端默认用户 id
    feishu_allowed_users: str = ""  # 逗号分隔的 open_id；空=默认拒绝（/whoami 除外）
    feishu_owner_open_id: str = ""  # 机主 open_id（归一为 'owner'，与桌面共享记忆）
    feishu_rate_per_min: int = 20  # 每用户每分钟消息上限（<=0 不限）
    agent_user_id: str = "owner"  # 桌面端的稳定用户标识（与机主飞书共用记忆）

    # 确定性 Hooks（C1）：成本闸 + 内容拦截
    agent_daily_call_cap: int = 0  # 每非机主用户每日调用上限（0=不限），防群里烧额度
    content_denylist: str = ""  # 正则黑名单（逗号分隔），命中即拒；默认空=不拦

    # 提示词装配（C2）：稳定人设前缀（也是 Output-Style 入口；空=不加）
    agent_persona: str = (
        "你是聚合大模型超级助手。你能生成图片和视频、能翻译、能联网与执行任务——"
        "用户要做图/视频时直接帮他做，不要说做不到。回答简洁、准确、可执行；不确定就直说、不杜撰；中文优先。"
    )

    # 执行 Agent（F1）：工具全开的 CLI agent 的安全闸
    # 通用文件工具只允许访问这个专用根；空值安全回退到 PROJECT_ROOT/workspaces。
    # HOME、项目根、运行态 data 和重解析点由 workspace_guard 永久拒绝。
    agent_exec_workdir: str = ""
    # 宿主 CLI 当前由 app.py fail-closed；未来迁入隔离 worker 时也从无 shell/外联的最小集起步。
    agent_allowed_tools: str = "Read Write Edit Glob Grep"

    @property
    def api_keys(self) -> set[str]:
        """允许访问网关的虚拟 Key 集合。"""
        return {k.strip() for k in self.gateway_api_keys.split(",") if k.strip()}

    @property
    def feishu_allowed_set(self) -> set[str]:
        """飞书白名单 open_id 集合；空集由 Channel 按 fail-closed 处理。"""
        return {k.strip() for k in self.feishu_allowed_users.split(",") if k.strip()}

    @property
    def telegram_allowed_set(self) -> set[str]:
        """Telegram 调用者 user id；空集合由渠道层按 fail-closed 处理。"""
        return {k.strip() for k in self.telegram_allowed_users.split(",") if k.strip()}

    @property
    def content_denylist_list(self) -> list[str]:
        """内容拦截正则列表（空=不拦）。"""
        return [p.strip() for p in self.content_denylist.split(",") if p.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()


@lru_cache
def get_isolated_bridge_settings() -> Settings:
    """Load a channel bridge only from its supervisor-filtered environment.

    Channel processes must never parse the project-wide ``.env`` because that
    file may contain provider or approval credentials outside their trust
    domain.  The managed launcher supplies the small service-specific process
    environment instead.
    """

    return Settings(_env_file=None)


@lru_cache(maxsize=1)
def desktop_engine_keys() -> frozenset[str]:
    """Legacy compatibility hook; filesystem key discovery is intentionally disabled.

    Desktop secrets are now DPAPI-encrypted, and accepting every matching
    ``AppData/Roaming/*/config.json`` let an unrelated local app mint a gateway
    credential.  Electron and the supervisor inject their exact key into the
    engine environment, so no ambient filesystem scan is required.
    """
    return frozenset()


def load_models_config(path: str | Path | None = None) -> dict[str, Any]:
    """读取 config/models.yaml。"""
    cfg_path = Path(path) if path else PROJECT_ROOT / "config" / "models.yaml"
    with open(cfg_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}
