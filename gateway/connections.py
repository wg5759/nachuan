"""Durable, fail-closed provider connection storage.

Credentials are protected by the Windows secure store.  A configured base URL
is also a security boundary: HTTPS is limited to built-in provider hosts or an
exact operator allowlist, while plaintext HTTP is accepted only on loopback.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import threading
from base64 import b64decode, b64encode
from binascii import Error as Base64Error
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit, urlunsplit

from gateway.catalog import PROVIDER_PRESETS
from gateway.providers.perplexity import PERPLEXITY_OFFICIAL_BASE_URL
from gateway.runtime_profile import current_runtime_profile
from gateway.secure_store import read_protected_json, write_protected_json
from gateway.url_safety import is_public_http_url


_PURPOSE = "nachuan/connections"
_VERIFICATION_KEY_PURPOSE = "nachuan/connection-verification-key"
_VERIFICATION_KEY_SCHEMA = "nachuan.connection-verification-key.v1"
_VERIFICATION_KEY_BYTES = 32
_VERIFICATION_KEY_LOCK = threading.Lock()
_ALLOWLIST_ENV = "NACHUAN_CONNECTION_HOST_ALLOWLIST"
_PROVIDER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_BLOCKED_NAMES = {
    "metadata",
    "metadata.google.internal",
    "instance-data",
    "instance-data.ec2.internal",
}
_BLOCKED_SUFFIXES = (".local", ".internal", ".lan", ".home")
_LOG = logging.getLogger(__name__)
_VERIFICATION_SCHEMA = "nachuan.connection-verification.v1"
_VERIFICATION_KEY = "_verification"
_LEGACY_DESKTOP_MIGRATION_SCHEMA = "nachuan.legacy-desktop-credential.v1"
_LEGACY_DESKTOP_MIGRATION_KEY = "_legacy_desktop_credential"
_LEGACY_DESKTOP_MIGRATION_SOURCE = "electron-roaming-appdata"
_LEGACY_DESKTOP_MIGRATION_DOMAIN = b"nachuan/legacy-desktop-credential/v1\0"
_VERIFIED_AT_RE = re.compile(
    r"20[0-9]{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T"
    r"(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z\Z"
)
# actual-served 身份回执：连接验证时对官方线文的如实记录。v1 只承认
# "unproven"——两条订阅线（Codex JSONL / Kimi ACP）经上游源码核验均无
# 服役型号字段；任何型号值都必须拒收，绝不拿配置别名冒充。回执用独立
# HMAC 绑定签发它的验证代际（_verification.verified_at + config_hmac），
# 验证失效或配置变更时回执随之失效。
_SERVED_RECEIPT_SCHEMA = "nachuan.actual-served-receipt.v1"
_SERVED_RECEIPT_KEY = "_actual_served"
_SERVED_RECEIPT_DOMAIN = b"nachuan/actual-served-receipt/v1\0"
_SERVED_RECEIPT_STATUSES = frozenset({"unproven"})
_SERVED_RECEIPT_EVIDENCE = frozenset(
    {
        "kimi_acp_prompt_response_has_no_served_model_field",
        "codex_exec_jsonl_turn_has_no_served_model_field",
    }
)
_MODEL_KEYS = frozenset(
    {
        "id",
        "upstream_model",
        "tier",
        "description",
        "modality",
        "rank",
        "flagship",
        "tool_capable",
        "skills",
        "actual_served",
    }
)
_CONNECTABLE_TYPES = frozenset(
    {"codex", "kimi_code", "openai_compat", "perplexity", "volcano"}
)
_KIMI_SUBSCRIPTION_MODEL_ID = "kimi-code-subscription"
_RESERVED_PROVIDER_NAMES = frozenset({"echo", "fleet", "local", "nachuan"})
_RESERVED_MODEL_IDS = frozenset(
    {"echo", "local", "nachuan", "nachuan-ultra", "nachuan-strongest"}
)
_CONNECT_MODEL_LIMIT = 8
_QUARANTINE_HANDLE_PREFIX = "quarantine-"
_QUARANTINE_HANDLE_RE = re.compile(r"quarantine-[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class ConnectionRecordSnapshot:
    """One provider's exact pre-image for compensating durable mutations."""

    provider: str
    active_present: bool
    active: Any
    quarantined_present: bool
    quarantined: Any
    invalid_present: bool
    invalid: str | None

    @property
    def exists(self) -> bool:
        return self.active_present or self.quarantined_present


def normalize_provider_name(provider: str) -> str:
    if not isinstance(provider, str):
        raise ValueError("连接 provider 名称必须是字符串")
    name = (provider or "").strip()
    if not _PROVIDER_RE.fullmatch(name):
        raise ValueError("连接 provider 名称非法")
    if name.casefold() in _RESERVED_PROVIDER_NAMES or name.casefold().startswith(
        _QUARANTINE_HANDLE_PREFIX
    ):
        raise ValueError("连接 provider 名称与系统保留名称冲突")
    return name


def is_reserved_virtual_model_id(model_id: str) -> bool:
    normalized = str(model_id or "").strip().casefold()
    return normalized in _RESERVED_MODEL_IDS or normalized.startswith("nachuan-")


def is_quarantine_handle(value: str) -> bool:
    return isinstance(value, str) and _QUARANTINE_HANDLE_RE.fullmatch(value) is not None


def _verification_key_document(key: bytes) -> dict[str, str]:
    return {
        "schema": _VERIFICATION_KEY_SCHEMA,
        "key_b64": b64encode(key).decode("ascii"),
    }


def _parse_verification_key_document(document: Any) -> bytes:
    if not isinstance(document, dict) or set(document) != {"schema", "key_b64"}:
        raise ValueError("连接验证密钥文档格式非法")
    encoded = document.get("key_b64")
    if document.get("schema") != _VERIFICATION_KEY_SCHEMA or not isinstance(
        encoded, str
    ):
        raise ValueError("连接验证密钥文档格式非法")
    try:
        key = b64decode(encoded.encode("ascii"), validate=True)
    except (UnicodeError, ValueError, Base64Error) as exc:
        raise ValueError("连接验证密钥编码非法") from exc
    if len(key) != _VERIFICATION_KEY_BYTES:
        raise ValueError("连接验证密钥长度非法")
    return key


def _load_or_create_verification_key(path: Path) -> bytes:
    """Load one independent DPAPI-protected installation key, fail closed."""

    # Production admits one Engine process.  This lock also prevents tests or
    # same-process stores racing their first key creation.
    with _VERIFICATION_KEY_LOCK:
        if not path.exists():
            key = secrets.token_bytes(_VERIFICATION_KEY_BYTES)
            write_protected_json(
                path,
                _verification_key_document(key),
                purpose=_VERIFICATION_KEY_PURPOSE,
            )
            return key
        document = read_protected_json(
            path,
            purpose=_VERIFICATION_KEY_PURPOSE,
            migrate_plaintext=False,
        )
    return _parse_verification_key_document(document)


def _clone(value: Any) -> Any:
    """Return a JSON-only deep copy and reject non-persistable objects."""
    try:
        return json.loads(json.dumps(value, ensure_ascii=False))
    except (TypeError, ValueError) as exc:
        raise ValueError("连接配置必须是可持久化的 JSON 对象") from exc


def _canonical_host(raw: str) -> str:
    value = (raw or "").rstrip(".").lower()
    if not value:
        raise ValueError("base_url 缺少主机名")
    try:
        return ipaddress.ip_address(value).compressed.lower()
    except ValueError:
        try:
            encoded = value.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError("base_url 主机名非法") from exc
        if (
            len(encoded) > 253
            or not re.fullmatch(r"[a-z0-9.-]+", encoded)
            or ".." in encoded
            or encoded.startswith("-")
            or encoded.endswith("-")
        ):
            raise ValueError("base_url 主机名非法")
        return encoded


def _ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _is_loopback(host: str) -> bool:
    address = _ip(host)
    return host == "localhost" or bool(address and address.is_loopback)


def _reject_private_or_metadata_name(host: str) -> None:
    address = _ip(host)
    if address is not None:
        if not address.is_global and not address.is_loopback:
            raise ValueError("base_url 不允许内网、链路本地或 metadata 地址")
        return
    if host in _BLOCKED_NAMES or host.endswith(_BLOCKED_SUFFIXES):
        raise ValueError("base_url 不允许内网或 metadata 主机")


def _authority(host: str, port: int) -> str:
    shown = f"[{host}]" if ":" in host else host
    return shown if port == 443 else f"{shown}:{port}"


def _parse_allowlist() -> set[tuple[str, int]]:
    """Parse exact hosts/origins; wildcards and paths are intentionally absent."""
    out: set[tuple[str, int]] = set()
    for token in re.split(r"[,;\s]+", os.getenv(_ALLOWLIST_ENV, "").strip()):
        if not token:
            continue
        candidate = token if "://" in token else f"//{token}"
        try:
            parsed = urlsplit(candidate)
            if parsed.scheme and parsed.scheme.lower() != "https":
                continue
            if (
                not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or parsed.query
                or parsed.fragment
                or parsed.path not in ("", "/")
            ):
                continue
            host = _canonical_host(parsed.hostname)
            port = parsed.port or 443
        except (ValueError, UnicodeError):
            continue
        out.add((host, port))
    return out


def _trusted_https_targets() -> set[tuple[str, int]]:
    trusted: set[tuple[str, int]] = set()
    for preset in PROVIDER_PRESETS:
        raw = str(preset.get("base_url") or "").strip()
        if not raw:
            continue
        try:
            parsed = urlsplit(raw)
            if parsed.scheme.lower() != "https" or not parsed.hostname:
                continue
            trusted.add((_canonical_host(parsed.hostname), parsed.port or 443))
        except (ValueError, UnicodeError):
            continue
    return trusted


def normalize_base_url(base_url: str, *, verify_public: bool = True) -> str:
    """Canonicalize and validate a provider API root.

    Built-in HTTPS provider targets are trusted by exact host and port. Custom
    targets require an exact ``NACHUAN_CONNECTION_HOST_ALLOWLIST`` entry and a
    public-DNS check. HTTP is restricted to literal loopback/``localhost``.
    """
    raw = (base_url or "").strip()
    if not raw:
        return ""
    if any(ch.isspace() or ord(ch) < 0x20 for ch in raw) or "\\" in raw:
        raise ValueError("base_url 包含非法空白或反斜杠")
    try:
        parsed = urlsplit(raw)
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("base_url 必须是 HTTP(S) 地址")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("base_url 不允许嵌入用户名或密码")
        if parsed.query or parsed.fragment:
            raise ValueError("base_url 不允许 query 或 fragment")
        host = _canonical_host(parsed.hostname)
        port = parsed.port or (443 if scheme == "https" else 80)
        if not (1 <= port <= 65535):
            raise ValueError("base_url 端口非法")
    except (UnicodeError, ValueError) as exc:
        if isinstance(exc, ValueError) and str(exc).startswith("base_url"):
            raise
        raise ValueError("base_url 格式非法") from exc

    _reject_private_or_metadata_name(host)
    loopback = _is_loopback(host)
    if scheme == "http" and not loopback:
        raise ValueError("base_url 仅允许回环 HTTP，远程目标必须 HTTPS")

    path = parsed.path.rstrip("/")
    decoded_segments = [unquote(part) for part in path.split("/")]
    if any(part in {".", ".."} or "\\" in part for part in decoded_segments):
        raise ValueError("base_url 路径不允许点段或编码反斜杠")

    if scheme == "https" and not loopback:
        target = (host, port)
        trusted = target in _trusted_https_targets()
        explicitly_allowed = target in _parse_allowlist()
        if not trusted and not explicitly_allowed:
            raise ValueError(
                "base_url 不在内置信任列表；运维须使用精确主机 allowlist"
            )
        # Built-in names are protected by HTTPS hostname verification. Custom
        # names additionally prove that every current DNS answer is public.
        netloc = _authority(host, port)
        candidate = urlunsplit(("https", netloc, path, "", ""))
        if explicitly_allowed and not trusted and verify_public:
            if not is_public_http_url(candidate):
                raise ValueError("allowlist base_url 必须解析为全公网地址")

    default_port = 443 if scheme == "https" else 80
    shown_host = f"[{host}]" if ":" in host else host
    netloc = shown_host if port == default_port else f"{shown_host}:{port}"
    return urlunsplit((scheme, netloc, path, "", ""))


def _fingerprint(normalized_base_url: str) -> str:
    digest = hashlib.sha256(
        b"nachuan/connection-target/v1\0" + normalized_base_url.encode("utf-8")
    ).hexdigest()
    return f"sha256:{digest}"


def target_fingerprint(base_url: str) -> str:
    """Stable, non-secret identifier suitable for endpoint capability binding."""
    normalized = normalize_base_url(base_url)
    return _fingerprint(normalized) if normalized else ""


def preserved_credential_target_matches(
    existing: dict[str, Any],
    *,
    candidate_type: Any,
    candidate_base_url: Any,
) -> bool:
    """Allow a stored secret only for its exact verified protocol and API root.

    The comparison deliberately includes the normalized URL path.  Sharing a
    hostname or a user-visible provider card is not authority to forward an API
    key to a different endpoint.  Public-DNS probing is deferred to candidate
    validation; this pure comparison never makes a network request.
    """

    try:
        existing_type = _bounded_text(
            existing.get("type"),
            label="已有连接 type",
            maximum=128,
            required=True,
        ).casefold()
        requested_type = _bounded_text(
            candidate_type,
            label="连接 type",
            maximum=128,
            required=True,
        ).casefold()
        existing_url = normalize_base_url(
            existing.get("base_url"), verify_public=False
        )
        requested_url = normalize_base_url(
            candidate_base_url, verify_public=False
        )
    except (AttributeError, TypeError, ValueError):
        return False
    if existing_type != requested_type or not existing_url or not requested_url:
        return False
    return hmac.compare_digest(_fingerprint(existing_url), _fingerprint(requested_url))


def _bounded_text(value: Any, *, label: str, maximum: int, required: bool) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} 必须是字符串")
    normalized = value.strip()
    if (required and not normalized) or len(normalized) > maximum:
        raise ValueError(f"{label} 长度非法")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in normalized):
        raise ValueError(f"{label} 包含控制字符")
    return normalized


def _normalize_model(model: dict[str, Any]) -> dict[str, Any]:
    if set(model) - _MODEL_KEYS:
        raise ValueError("模型配置包含未知字段")
    model_id = _bounded_text(
        model.get("id"), label="模型 id", maximum=512, required=True
    )
    if is_reserved_virtual_model_id(model_id):
        raise ValueError("模型 id 与纳川系统保留模型冲突")
    upstream = _bounded_text(
        model.get("upstream_model", model_id),
        label="上游模型 id",
        maximum=512,
        required=True,
    )
    if any("claude" in value.casefold() for value in (model_id, upstream)):
        raise ValueError("Claude 模型本月已停用")
    tier = _bounded_text(
        model.get("tier", "default"), label="模型 tier", maximum=64, required=True
    )
    description = _bounded_text(
        model.get("description", ""),
        label="模型 description",
        maximum=1024,
        required=False,
    )
    modality = _bounded_text(
        model.get("modality", "chat"),
        label="模型 modality",
        maximum=32,
        required=True,
    ).casefold()
    if modality not in {"chat", "image", "video", "audio", "embedding"}:
        raise ValueError("模型 modality 不受支持")

    rank = model.get("rank", 0)
    if isinstance(rank, bool) or not isinstance(rank, int) or not 0 <= rank <= 1_000_000:
        raise ValueError("模型 rank 非法")
    flagship = model.get("flagship", False)
    tool_capable = model.get("tool_capable", True)
    if not isinstance(flagship, bool) or not isinstance(tool_capable, bool):
        raise ValueError("模型布尔元数据非法")
    skills = model.get("skills", [])
    if not isinstance(skills, list) or len(skills) > 32:
        raise ValueError("模型 skills 非法")
    normalized_skills: list[str] = []
    seen_skills: set[str] = set()
    for skill in skills:
        item = _bounded_text(
            skill, label="模型 skill", maximum=64, required=True
        ).casefold()
        if item in seen_skills:
            raise ValueError("模型 skills 不允许重复")
        seen_skills.add(item)
        normalized_skills.append(item)
    # actual_served 是 catalog 的纯展示提示：准入时校验闭集后丢弃，
    # 不进持久化模型条目（服役身份以连接级 _actual_served 回执为准）。
    actual_served_hint = model.get("actual_served")
    if (
        actual_served_hint is not None
        and actual_served_hint not in _SERVED_RECEIPT_STATUSES
    ):
        raise ValueError("模型 actual_served 展示值非法")
    return {
        "id": model_id,
        "upstream_model": upstream,
        "tier": tier,
        "description": description,
        "modality": modality,
        "rank": rank,
        "flagship": flagship,
        "tool_capable": tool_capable,
        "skills": normalized_skills,
    }


def normalize_connection_candidate(
    provider: str, conn: dict[str, Any], *, verify_public: bool = True
) -> dict[str, Any]:
    """Strictly normalize one untrusted Connect candidate.

    This path is intentionally narrower than legacy storage loading.  Codex is
    admitted only through its contained text worker; unsupported native
    protocols remain closed and model discovery is never guessed from an empty
    manifest.
    """

    if not isinstance(conn, dict) or set(conn) != {
        "type",
        "api_key",
        "base_url",
        "enabled_models",
    }:
        raise ValueError("连接候选字段必须严格匹配")
    ptype = _bounded_text(
        conn.get("type"), label="连接 type", maximum=128, required=True
    ).casefold()
    if ptype not in _CONNECTABLE_TYPES:
        raise ValueError("连接协议尚不可用")
    if not current_runtime_profile().allows_connection_type(ptype):
        raise ValueError("当前运行配置不允许该连接协议")
    api_key = _bounded_text(
        conn.get("api_key"), label="连接凭据", maximum=32 * 1024, required=False
    )
    base_url = conn.get("base_url")
    models = conn.get("enabled_models")
    if not isinstance(base_url, str) or not isinstance(models, list):
        raise ValueError("连接目标或模型清单类型非法")
    if ptype == "kimi_code" and base_url.strip():
        raise ValueError("Kimi Code subscription does not accept a base URL")
    if not 1 <= len(models) <= _CONNECT_MODEL_LIMIT:
        raise ValueError(f"连接必须显式选择 1 到 {_CONNECT_MODEL_LIMIT} 个模型")
    if ptype in {"claude_code", "codex", "kimi_code"} and len(models) != 1:
        raise ValueError("本机登录型连接一次只验证一个模型")

    normalized_models: list[dict[str, Any]] = []
    seen_models: set[str] = set()
    for raw_model in models:
        if not isinstance(raw_model, dict):
            raise ValueError("模型配置必须是对象")
        model = _normalize_model(raw_model)
        if model["id"] in seen_models:
            raise ValueError("模型 id 不允许重复")
        seen_models.add(model["id"])
        normalized_models.append(model)
    if not any(model["modality"] == "chat" for model in normalized_models):
        raise ValueError("连接验证需要至少一个聊天模型")

    if ptype == "kimi_code":
        model = normalized_models[0]
        if (
            model["id"] != _KIMI_SUBSCRIPTION_MODEL_ID
            or model["upstream_model"] != _KIMI_SUBSCRIPTION_MODEL_ID
            or model["modality"] != "chat"
            or model["tool_capable"] is not False
        ):
            raise ValueError(
                "Kimi Code subscription only exposes kimi-code-subscription "
                "as a contained text model"
            )

    candidate = validate_connection(
        provider,
        {
            "type": ptype,
            "api_key": api_key,
            "base_url": base_url,
            "enabled_models": normalized_models,
        },
        verify_public=verify_public,
    )
    canonical_url = str(candidate.get("base_url") or "")
    if ptype in {"openai_compat", "perplexity", "volcano"}:
        if not canonical_url:
            raise ValueError("连接目标不能为空")
        parsed = urlsplit(canonical_url)
        host = _canonical_host(parsed.hostname or "")
        if ptype == "perplexity":
            if canonical_url != PERPLEXITY_OFFICIAL_BASE_URL:
                raise ValueError("Perplexity 仅允许官方固定 API 根地址")
        elif host == "api.perplexity.ai":
            # This host has a split path layout.  Treating it as a generic
            # OpenAI base would probe /models instead of /v1/models and makes a
            # broken connection look like an ordinary provider outage.
            raise ValueError("Perplexity 必须使用专用连接协议")
        if not _is_loopback(host) and not api_key:
            raise ValueError("远程连接需要凭据")
    elif api_key:
        raise ValueError("本机登录型连接不接受 API Key")
    return candidate


def _require_verification_key(verification_key: bytes) -> bytes:
    if not isinstance(verification_key, bytes) or len(verification_key) != _VERIFICATION_KEY_BYTES:
        raise ValueError("连接验证密钥非法")
    return verification_key


def _verification_digest(
    provider: str,
    conn: dict[str, Any],
    *,
    verification_key: bytes,
    verified_at_value: str,
) -> str:
    key = _require_verification_key(verification_key)
    candidate = {
        "type": conn.get("type"),
        "api_key": conn.get("api_key"),
        "base_url": conn.get("base_url", ""),
        "enabled_models": conn.get("enabled_models"),
    }
    normalized = normalize_connection_candidate(
        provider, candidate, verify_public=False
    )
    credential = str(normalized.get("api_key") or "").encode("utf-8")
    credential_fingerprint = hmac.new(
        key,
        b"nachuan/connection-credential/v1\0" + credential,
        hashlib.sha256,
    ).hexdigest()
    identity = {
        "schema": _VERIFICATION_SCHEMA,
        "provider": provider.strip(),
        "type": normalized["type"],
        "base_url": normalized.get("base_url", ""),
        "target_fingerprint": normalized.get("target_fingerprint", ""),
        "credential_present": bool(credential),
        "credential_hmac_sha256": credential_fingerprint,
        "enabled_models": normalized["enabled_models"],
        "verified_at": verified_at_value,
    }
    payload = json.dumps(
        identity, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hmac.new(
        key,
        b"nachuan/connection-verification/v1\0" + payload,
        hashlib.sha256,
    ).hexdigest()


def mark_connection_verified(
    provider: str,
    conn: dict[str, Any],
    *,
    verification_key: bytes,
    verified_at: str | None = None,
) -> dict[str, Any]:
    """Return a normalized record with a server-issued verification receipt."""

    normalized = normalize_connection_candidate(
        provider,
        {
            "type": conn.get("type"),
            "api_key": conn.get("api_key"),
            "base_url": conn.get("base_url", ""),
            "enabled_models": conn.get("enabled_models"),
        },
    )
    timestamp = verified_at or datetime.now(timezone.utc).replace(
        microsecond=0
    ).isoformat().replace("+00:00", "Z")
    if _VERIFIED_AT_RE.fullmatch(timestamp) is None:
        raise ValueError("verified_at 格式非法")
    normalized[_VERIFICATION_KEY] = {
        "schema": _VERIFICATION_SCHEMA,
        "state": "verified",
        "config_hmac_sha256": _verification_digest(
            provider,
            normalized,
            verification_key=verification_key,
            verified_at_value=timestamp,
        ),
        "verified_at": timestamp,
    }
    return normalized


def verified_at(
    provider: str, conn: dict[str, Any], *, verification_key: bytes
) -> str | None:
    """Return the receipt timestamp only when the full receipt still matches."""

    receipt = conn.get(_VERIFICATION_KEY)
    if not isinstance(receipt, dict) or set(receipt) != {
        "schema",
        "state",
        "config_hmac_sha256",
        "verified_at",
    }:
        return None
    timestamp = receipt.get("verified_at")
    digest = receipt.get("config_hmac_sha256")
    if (
        receipt.get("schema") != _VERIFICATION_SCHEMA
        or receipt.get("state") != "verified"
        or not isinstance(timestamp, str)
        or _VERIFIED_AT_RE.fullmatch(timestamp) is None
        or not isinstance(digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
    ):
        return None
    try:
        receipt_time = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        return None
    if receipt_time > datetime.now(timezone.utc) + timedelta(minutes=5):
        return None
    try:
        expected = _verification_digest(
            provider,
            conn,
            verification_key=verification_key,
            verified_at_value=timestamp,
        )
    except (TypeError, ValueError):
        return None
    return timestamp if hmac.compare_digest(digest, expected) else None


def is_verified_connection(
    provider: str, conn: dict[str, Any], *, verification_key: bytes
) -> bool:
    return verified_at(provider, conn, verification_key=verification_key) is not None


def _served_receipt_digest(
    provider: str,
    conn: dict[str, Any],
    *,
    verification_key: bytes,
    status: str,
    evidence: str,
    checked_at_value: str,
) -> str:
    key = _require_verification_key(verification_key)
    generation = verified_at(provider, conn, verification_key=key)
    if generation is None:
        raise ValueError("actual-served 回执必须绑定有效的连接验证代际")
    verification = conn[_VERIFICATION_KEY]
    identity = {
        "schema": _SERVED_RECEIPT_SCHEMA,
        "provider": normalize_provider_name(provider),
        "verification_verified_at": generation,
        "verification_config_hmac_sha256": verification["config_hmac_sha256"],
        "status": status,
        "model": None,
        "evidence": evidence,
        "checked_at": checked_at_value,
    }
    payload = json.dumps(
        identity, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hmac.new(
        key, _SERVED_RECEIPT_DOMAIN + payload, hashlib.sha256
    ).hexdigest()


def mark_connection_actual_served(
    provider: str,
    conn: dict[str, Any],
    *,
    verification_key: bytes,
    receipt: Mapping[str, Any],
    checked_at: str | None = None,
) -> dict[str, Any]:
    """Attach the verification-time actual-served receipt to a verified record.

    v1 admits only the honest negative: today's subscription wires (Codex
    exec JSONL / Kimi ACP prompt response) carry no served-model field, so
    ``status`` is ``unproven`` and ``model`` must stay ``None`` — a configured
    or self-reported alias is never accepted as served-model evidence.
    """

    name = normalize_provider_name(provider)
    if not isinstance(receipt, Mapping) or set(receipt) != {
        "status",
        "model",
        "evidence",
    }:
        raise ValueError("actual-served 回执字段必须严格匹配")
    status = receipt.get("status")
    model = receipt.get("model")
    evidence = receipt.get("evidence")
    if (
        not isinstance(status, str)
        or status not in _SERVED_RECEIPT_STATUSES
        or model is not None
        or not isinstance(evidence, str)
        or evidence not in _SERVED_RECEIPT_EVIDENCE
    ):
        raise ValueError("actual-served 回执内容不在闭集内")
    marked = _clone(conn)
    timestamp = checked_at or datetime.now(timezone.utc).replace(
        microsecond=0
    ).isoformat().replace("+00:00", "Z")
    if _VERIFIED_AT_RE.fullmatch(timestamp) is None:
        raise ValueError("checked_at 格式非法")
    marked[_SERVED_RECEIPT_KEY] = {
        "schema": _SERVED_RECEIPT_SCHEMA,
        "status": status,
        "model": None,
        "evidence": evidence,
        "checked_at": timestamp,
        "receipt_hmac_sha256": _served_receipt_digest(
            name,
            marked,
            verification_key=verification_key,
            status=status,
            evidence=evidence,
            checked_at_value=timestamp,
        ),
    }
    return marked


def actual_served_receipt(
    provider: str, conn: dict[str, Any], *, verification_key: bytes
) -> dict[str, Any] | None:
    """Return the public receipt view only while its binding still verifies."""

    receipt = conn.get(_SERVED_RECEIPT_KEY)
    if not isinstance(receipt, dict) or set(receipt) != {
        "schema",
        "status",
        "model",
        "evidence",
        "checked_at",
        "receipt_hmac_sha256",
    }:
        return None
    status = receipt.get("status")
    model = receipt.get("model")
    evidence = receipt.get("evidence")
    timestamp = receipt.get("checked_at")
    digest = receipt.get("receipt_hmac_sha256")
    if (
        receipt.get("schema") != _SERVED_RECEIPT_SCHEMA
        or not isinstance(status, str)
        or status not in _SERVED_RECEIPT_STATUSES
        or model is not None
        or not isinstance(evidence, str)
        or evidence not in _SERVED_RECEIPT_EVIDENCE
        or not isinstance(timestamp, str)
        or _VERIFIED_AT_RE.fullmatch(timestamp) is None
        or not isinstance(digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
    ):
        return None
    try:
        receipt_time = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        return None
    if receipt_time > datetime.now(timezone.utc) + timedelta(minutes=5):
        return None
    try:
        expected = _served_receipt_digest(
            provider,
            conn,
            verification_key=verification_key,
            status=status,
            evidence=evidence,
            checked_at_value=timestamp,
        )
    except (TypeError, ValueError, KeyError):
        return None
    if not hmac.compare_digest(digest, expected):
        return None
    return {
        "status": status,
        "model": None,
        "evidence": evidence,
        "checked_at": timestamp,
    }


def validate_connection(
    provider: str, conn: dict[str, Any], *, verify_public: bool = True
) -> dict[str, Any]:
    """Return a normalized copy or raise without mutating caller/store state."""
    name = normalize_provider_name(provider)
    if not isinstance(conn, dict):
        raise ValueError("连接配置必须是 JSON 对象")
    normalized = _clone(conn)

    ptype = normalized.get("type", name)
    api_key = normalized.get("api_key", "")
    base_url = normalized.get("base_url", "")
    models = normalized.get("enabled_models", [])
    if not isinstance(ptype, str) or not isinstance(api_key, str):
        raise ValueError("连接 type/api_key 必须是字符串")
    if not isinstance(base_url, str) or not isinstance(models, list):
        raise ValueError("连接 base_url 必须是字符串，enabled_models 必须是列表")
    if not ptype.strip() or len(ptype) > 128:
        raise ValueError("连接 type 长度非法")
    if len(api_key) > 32 * 1024 or len(base_url) > 2048:
        raise ValueError("连接凭据或目标地址超过长度限制")
    if len(models) > 200:
        raise ValueError("单个连接最多启用 200 个模型")
    if any(not isinstance(model, dict) for model in models):
        raise ValueError("enabled_models 只能包含 JSON 对象")
    encoded_models = json.dumps(
        models, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    if len(encoded_models) > 512 * 1024:
        raise ValueError("enabled_models 配置超过大小限制")

    # Preserve legacy document shape: validation must not masquerade as a
    # successful persistence migration or make read-only startup dirty state.
    if "type" in normalized:
        normalized["type"] = ptype.strip() or name
    if "api_key" in normalized:
        normalized["api_key"] = api_key.strip()
    cli_login = ptype.strip().casefold() in {
        "claude_code",
        "codex",
        "kimi_code",
    }
    if cli_login:
        # These providers authenticate through one local CLI login and never
        # consume base_url.  Persisting that field would create misleading
        # configuration and previously allowed one login to acquire multiple
        # apparent independence domains.
        normalized.pop("base_url", None)
        normalized.pop("target_fingerprint", None)
        canonical_url = ""
    else:
        canonical_url = normalize_base_url(base_url, verify_public=verify_public)
        if "base_url" in normalized:
            normalized["base_url"] = canonical_url
    if "enabled_models" in normalized:
        normalized["enabled_models"] = models
    if canonical_url:
        normalized["target_fingerprint"] = _fingerprint(canonical_url)
    else:
        normalized.pop("target_fingerprint", None)
    return normalized


def _legacy_desktop_credential_binding(
    provider: str,
    conn: dict[str, Any],
) -> str | None:
    try:
        name = normalize_provider_name(provider)
        normalized = validate_connection(name, conn, verify_public=False)
    except (AttributeError, TypeError, ValueError):
        return None
    credential = normalized.get("api_key")
    provider_type = normalized.get("type", name)
    target = normalized.get("target_fingerprint")
    if (
        not isinstance(credential, str)
        or not credential
        or not isinstance(provider_type, str)
        or provider_type.casefold() in {"claude_code", "codex", "kimi_code"}
        or not isinstance(target, str)
        or not target
    ):
        return None
    public_binding = json.dumps(
        {
            "provider": name,
            "type": provider_type.casefold(),
            "target_fingerprint": target,
        },
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(
        _LEGACY_DESKTOP_MIGRATION_DOMAIN
        + public_binding
        + b"\0"
        + credential.encode("utf-8")
    ).hexdigest()


def mark_legacy_desktop_credential_for_reverification(
    provider: str,
    conn: dict[str, Any],
) -> dict[str, Any]:
    """Bind one imported secret to its original provider protocol/API root."""

    marked = _clone(conn)
    binding = _legacy_desktop_credential_binding(provider, marked)
    if binding is None:
        return marked
    marked[_LEGACY_DESKTOP_MIGRATION_KEY] = {
        "schema": _LEGACY_DESKTOP_MIGRATION_SCHEMA,
        "source": _LEGACY_DESKTOP_MIGRATION_SOURCE,
        "binding_sha256": binding,
    }
    return marked


def legacy_desktop_credential_can_be_reverified(
    provider: str,
    conn: dict[str, Any],
) -> bool:
    receipt = conn.get(_LEGACY_DESKTOP_MIGRATION_KEY)
    if not isinstance(receipt, dict) or set(receipt) != {
        "schema",
        "source",
        "binding_sha256",
    }:
        return False
    binding = _legacy_desktop_credential_binding(provider, conn)
    candidate = receipt.get("binding_sha256")
    return (
        receipt.get("schema") == _LEGACY_DESKTOP_MIGRATION_SCHEMA
        and receipt.get("source") == _LEGACY_DESKTOP_MIGRATION_SOURCE
        and isinstance(candidate, str)
        and isinstance(binding, str)
        and hmac.compare_digest(candidate, binding)
    )


class ConnectionStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._verification_key_path = self.path.with_name(
            f"{self.path.name}.verification-key"
        )
        self._verification_key = _load_or_create_verification_key(
            self._verification_key_path
        )
        self._quarantined: dict[str, Any] = {}
        self._invalid: dict[str, str] = {}
        self._data: dict[str, Any] = self._load()

    def mark_verified(
        self, provider: str, conn: dict[str, Any], *, verified_at_value: str | None = None
    ) -> dict[str, Any]:
        return mark_connection_verified(
            provider,
            conn,
            verification_key=self._verification_key,
            verified_at=verified_at_value,
        )

    def mark_actual_served(
        self,
        provider: str,
        conn: dict[str, Any],
        *,
        receipt: Mapping[str, Any],
        checked_at_value: str | None = None,
    ) -> dict[str, Any]:
        return mark_connection_actual_served(
            provider,
            conn,
            verification_key=self._verification_key,
            receipt=receipt,
            checked_at=checked_at_value,
        )

    def actual_served(self, provider: str, conn: dict[str, Any]) -> dict[str, Any] | None:
        return actual_served_receipt(
            provider, conn, verification_key=self._verification_key
        )

    def is_verified(self, provider: str, conn: dict[str, Any]) -> bool:
        return is_verified_connection(
            provider, conn, verification_key=self._verification_key
        )

    def can_reverify_imported_credential(
        self, provider: str, conn: dict[str, Any]
    ) -> bool:
        return (
            not self.is_verified(provider, conn)
            and legacy_desktop_credential_can_be_reverified(provider, conn)
        )

    def _snapshot_locked(self, provider: str) -> ConnectionRecordSnapshot:
        invalid_key = provider[:64]
        return ConnectionRecordSnapshot(
            provider=provider,
            active_present=provider in self._data,
            active=_clone(self._data.get(provider)),
            quarantined_present=provider in self._quarantined,
            quarantined=_clone(self._quarantined.get(provider)),
            invalid_present=invalid_key in self._invalid,
            invalid=self._invalid.get(invalid_key),
        )

    def _quarantine_handle(self, provider: str) -> str:
        digest = hmac.new(
            self._verification_key,
            b"nachuan/quarantined-connection/v1\0" + provider.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return f"{_QUARANTINE_HANDLE_PREFIX}{digest}"

    def _load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {}
        raw = read_protected_json(
            self.path,
            purpose=_PURPOSE,
            migrate_plaintext=True,
        )
        if not isinstance(raw, dict):
            raise ValueError("连接存储根节点必须是 JSON 对象")
        # A damaged encrypted envelope/root is fatal (handled above), while an
        # unsafe individual provider is isolated.  This keeps healthy routes
        # available without ever exposing or silently deleting the bad entry.
        valid: dict[str, Any] = {}
        quarantined: dict[str, Any] = {}
        invalid: dict[str, str] = {}
        for name, conn in raw.items():
            try:
                valid[name] = validate_connection(name, conn)
            except (AttributeError, TypeError, ValueError) as exc:
                shown_name = str(name)[:64]
                quarantined[name] = _clone(conn)
                invalid[shown_name] = str(exc)[:256]
                _LOG.error("provider connection %r quarantined: %s", shown_name, exc)
        self._quarantined = quarantined
        self._invalid = invalid
        return valid

    def _save(
        self, data: dict[str, Any], quarantined: dict[str, Any] | None = None
    ) -> None:
        document = _clone(self._quarantined if quarantined is None else quarantined)
        document.update(_clone(data))
        write_protected_json(self.path, document, purpose=_PURPOSE)

    def all(self) -> dict[str, Any]:
        with self._lock:
            return _clone(self._data)

    def get(self, provider: str) -> dict[str, Any] | None:
        with self._lock:
            value = self._data.get(provider)
            return _clone(value) if value is not None else None

    def invalid(self) -> dict[str, str]:
        """Non-secret diagnostics for health/UI; quarantined values stay hidden."""
        with self._lock:
            return dict(self._invalid)

    def set(self, provider: str, conn: dict[str, Any]) -> ConnectionRecordSnapshot:
        normalized = validate_connection(provider, conn)
        name = normalize_provider_name(provider)
        with self._lock:
            snapshot = self._snapshot_locked(name)
            candidate = _clone(self._data)
            candidate_quarantined = _clone(self._quarantined)
            candidate_invalid = dict(self._invalid)
            candidate[name] = normalized
            candidate_quarantined.pop(name, None)
            candidate_invalid.pop(name, None)
            # Persist first. A failed atomic write leaves both disk and live
            # Router-facing state on the old configuration.
            self._save(candidate, candidate_quarantined)
            self._data = candidate
            self._quarantined = candidate_quarantined
            self._invalid = candidate_invalid
            return snapshot

    def delete(self, provider: str) -> ConnectionRecordSnapshot:
        name = normalize_provider_name(provider)
        with self._lock:
            snapshot = self._snapshot_locked(name)
            if name not in self._data and name not in self._quarantined:
                return snapshot
            candidate = _clone(self._data)
            candidate_quarantined = _clone(self._quarantined)
            candidate_invalid = dict(self._invalid)
            candidate.pop(name, None)
            candidate_quarantined.pop(name, None)
            candidate_invalid.pop(str(name)[:64], None)
            self._save(candidate, candidate_quarantined)
            self._data = candidate
            self._quarantined = candidate_quarantined
            self._invalid = candidate_invalid
            return snapshot

    def delete_quarantined(self, handle: str) -> bool:
        """Delete one quarantined record by a non-secret installation-bound id."""

        if not is_quarantine_handle(handle):
            raise ValueError("隔离连接句柄非法")
        with self._lock:
            provider = next(
                (
                    name
                    for name in self._quarantined
                    if hmac.compare_digest(self._quarantine_handle(name), handle)
                ),
                None,
            )
            if provider is None:
                return False
            candidate = _clone(self._data)
            candidate_quarantined = _clone(self._quarantined)
            candidate_invalid = dict(self._invalid)
            candidate_quarantined.pop(provider, None)
            candidate_invalid.pop(str(provider)[:64], None)
            self._save(candidate, candidate_quarantined)
            self._data = candidate
            self._quarantined = candidate_quarantined
            self._invalid = candidate_invalid
            return True

    def restore(self, snapshot: ConnectionRecordSnapshot) -> None:
        """Atomically restore a provider pre-image after a failed Router swap."""

        if not isinstance(snapshot, ConnectionRecordSnapshot):
            raise ValueError("连接回滚快照非法")
        name = normalize_provider_name(snapshot.provider)
        if snapshot.active_present and snapshot.quarantined_present:
            raise ValueError("连接回滚快照状态冲突")
        invalid_key = name[:64]
        with self._lock:
            candidate = _clone(self._data)
            candidate_quarantined = _clone(self._quarantined)
            candidate_invalid = dict(self._invalid)
            candidate.pop(name, None)
            candidate_quarantined.pop(name, None)
            candidate_invalid.pop(invalid_key, None)
            if snapshot.active_present:
                candidate[name] = _clone(snapshot.active)
            if snapshot.quarantined_present:
                candidate_quarantined[name] = _clone(snapshot.quarantined)
            if snapshot.invalid_present:
                candidate_invalid[invalid_key] = str(snapshot.invalid or "")[:256]
            self._save(candidate, candidate_quarantined)
            self._data = candidate
            self._quarantined = candidate_quarantined
            self._invalid = candidate_invalid

    def masked(self) -> dict[str, Any]:
        """External view: omit credentials and internal verification receipts."""
        out: dict[str, Any] = {}
        with self._lock:
            for provider, conn in self._data.items():
                timestamp = verified_at(
                    provider, conn, verification_key=self._verification_key
                )
                # Rebuild from a non-secret allowlist.  Legacy and third-party
                # records may contain refresh_token/password/custom auth fields;
                # a blacklist can never safely anticipate them.
                summary = {
                    "type": str(conn.get("type") or provider),
                    "base_url": str(conn.get("base_url") or ""),
                    "enabled_models": _clone(conn.get("enabled_models") or []),
                    "credential_present": bool(conn.get("api_key")),
                    "state": "verified" if timestamp else "legacy_unverified",
                    "verified_at": timestamp,
                }
                if (
                    timestamp is None
                    and legacy_desktop_credential_can_be_reverified(provider, conn)
                ):
                    summary["credential_reverification_available"] = True
                out[provider] = summary
            for provider in self._quarantined:
                out[self._quarantine_handle(provider)] = {
                    "type": "quarantined",
                    "base_url": "",
                    "enabled_models": [],
                    "state": "disabled",
                    "verified_at": None,
                }
        return out
