"""Strict model-id evidence used by independent-review gates.

The registry intentionally recognizes only stable, explicit vendor prefixes.
Unknown identifiers receive no family and therefore no review vote.
"""

from __future__ import annotations

import re
from typing import Any


_MAX_MODEL_ID_CHARS = 256
REVIEW_STRENGTH_REGISTRY_VERSION = "2026-07-15.1"
_FAMILY_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^claude(?:[-_.:]|$)"), "anthropic"),
    (re.compile(r"^(?:gpt|chatgpt|codex)(?:[-_.:]|$)"), "openai"),
    (re.compile(r"^o(?:1|3|4)(?:[-_.:]|$)"), "openai"),
    (re.compile(r"^deepseek(?:[-_.:]|$)"), "deepseek"),
    (re.compile(r"^(?:glm|chatglm)(?:[-_.:]|$)"), "zhipu"),
    (re.compile(r"^(?:kimi|moonshot)(?:[-_.:]|$)"), "moonshot"),
    (re.compile(r"^minimax(?:[-_.:]|$)"), "minimax"),
    (re.compile(r"^(?:qwen(?:[0-9]|[-_.:]|$)|qwq(?:[-_.:]|$))"), "alibaba-qwen"),
    (re.compile(r"^gemini(?:[-_.:]|$)"), "google-gemini"),
    (re.compile(r"^grok(?:[-_.:]|$)"), "xai-grok"),
    (re.compile(r"^(?:mistral|mixtral|codestral)(?:[-_.:]|$)"), "mistral"),
    (re.compile(r"^hunyuan(?:[-_.:]|$)"), "tencent-hunyuan"),
    (re.compile(r"^ernie(?:[-_.:]|$)"), "baidu-ernie"),
    (re.compile(r"^doubao(?:[-_.:]|$)"), "bytedance-doubao"),
    (re.compile(r"^agnes(?:[-_.:]|$)"), "agnes"),
    (re.compile(r"^sonar(?:[-_.:]|$)"), "perplexity-sonar"),
    (re.compile(r"^llama(?:[-_.:]|$)"), "meta-llama"),
)


def canonical_model_id(value: Any) -> str | None:
    text = str(value or "").strip().casefold()
    if not text or len(text) > _MAX_MODEL_ID_CHARS:
        return None
    if any(ch.isspace() or ord(ch) < 0x20 for ch in text):
        return None
    return text


def model_family_from_identifier(value: Any) -> str | None:
    model = canonical_model_id(value)
    if model is None:
        return None
    # Aggregators commonly return ``vendor/model-id``.  The leaf is still
    # required to match this closed registry; arbitrary labels stay unknown.
    leaf = model.rsplit("/", 1)[-1]
    for pattern, family in _FAMILY_PATTERNS:
        if pattern.match(leaf):
            return family
    return None


def exact_verified_model_identity(
    upstream_model: Any,
    observed_model: Any,
) -> tuple[str, str] | None:
    expected = canonical_model_id(upstream_model)
    observed = canonical_model_id(observed_model)
    if expected is None or observed is None or expected != observed:
        return None
    family = model_family_from_identifier(observed)
    if family is None:
        return None
    return str(observed_model).strip(), family


# This is deliberately a small, versioned allow-list.  A connection's editable
# ``tier`` is not evidence of review capability.  New models stay unqualified
# until their canonical provider-returned id is reviewed and added here.
_STRONG_REVIEW_MODEL_IDS = frozenset(
    {
        "gpt-4o",
        "gpt-4.1",
        "gpt-5.4",
        "gpt-5.5",
        "gpt-5.3-codex",
        "claude-sonnet-4-6",
        "claude-opus-4-6",
        "claude-opus-4-7",
        "claude-opus-4-8",
        "gemini-2.5-pro",
        "deepseek-v3",
    }
)
_STRONG_REVIEW_MODEL_PATTERNS: tuple[re.Pattern[str], ...] = (
    # Claude CLI returns dated ids for aliases.  Only already-reviewed 4.x
    # Sonnet/Opus generations are accepted; Haiku is intentionally excluded.
    re.compile(r"^claude-(?:sonnet|opus)-4-(?:5|6|7|8)(?:-\d{8})?$"),
)
_WEAK_REVIEW_PATTERN = re.compile(
    r"(?:^|[-_.])(?:mini|nano|flash|haiku|turbo)(?:[-_.]|$)"
)


def review_strength_from_identifier(value: Any) -> str | None:
    """Return registry-derived review strength; unknown never means strong."""

    model = canonical_model_id(value)
    if model is None:
        return None
    leaf = model.rsplit("/", 1)[-1]
    if _WEAK_REVIEW_PATTERN.search(leaf):
        return "weak"
    if leaf in _STRONG_REVIEW_MODEL_IDS:
        return "strong"
    if any(pattern.fullmatch(leaf) for pattern in _STRONG_REVIEW_MODEL_PATTERNS):
        return "strong"
    return None
