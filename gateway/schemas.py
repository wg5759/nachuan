"""OpenAI 兼容的请求/响应数据结构（pydantic v2）。

设计原则：对未知字段一律放行（extra="allow"），最大化对 OpenAI 生态客户端
与上游的透传保真度（tools / response_format / seed 等都能原样转发）。
"""

from __future__ import annotations

import json
import re
import time
import uuid
from typing import Annotated, Any, Literal, Optional, Union

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)


# These are hard safety ceilings, not pricing estimates.  They keep one
# authenticated request from multiplying into an unbounded number of paid
# upstream calls or an unbounded in-memory prompt.  Provider-specific limits
# may be lower and remain the provider's responsibility.
MAX_CHAT_MESSAGES = 256
MAX_CHAT_IMAGES = 4
MAX_CHAT_CONTENT_BLOCKS = 64
MAX_CHAT_REQUEST_BYTES = 24 * 1024 * 1024
MAX_MEDIA_REQUEST_BYTES = 24 * 1024 * 1024
MAX_MEDIA_PROMPT_CHARS = 32_768
MAX_IMAGE_COUNT = 4
MAX_VIDEO_KEYFRAMES = 4
MAX_WORKFLOW_PROMPT_CHARS = 65_536
# 8 panel answers + the original prompt remain below failover.py's verified
# 400k-character long-input threshold (8*32768 + 65536 = 327680).
MAX_WORKFLOW_OUTPUT_CHARS = 32_768
MAX_WORKFLOW_CONCURRENCY = 4
MAX_PANELISTS = 8
MAX_DEBATERS = 4
MAX_DEBATE_ROUNDS = 4
MAX_PIPELINE_STEPS = 12
MAX_DECOMPOSE_SUBTASKS = 6

ModelId = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=256)
]
WorkflowPrompt = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True, min_length=1, max_length=MAX_WORKFLOW_PROMPT_CHARS
    ),
]


def _json_size(value: Any) -> int:
    """Return canonical UTF-8 size, rejecting non-JSON/recursive values."""

    try:
        raw = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError("request contains a non-JSON or excessively nested value") from exc
    return len(raw.encode("utf-8"))


def _require_json_size(value: Any, *, maximum: int, label: str) -> None:
    if _json_size(value) > maximum:
        raise ValueError(f"{label} exceeds {maximum} bytes")


def _validate_multipliers(
    value: Any, *, fields: tuple[str, ...], maximum: int
) -> Any:
    """Reject common provider aliases that can multiply paid generations."""

    if not isinstance(value, dict):
        return value
    containers = [value]
    if isinstance(value.get("extra_body"), dict):
        containers.append(value["extra_body"])
    for container in containers:
        for name in fields:
            if name not in container or container[name] is None:
                continue
            raw = container[name]
            if isinstance(raw, bool):
                raise ValueError(f"{name} must be an integer")
            try:
                parsed = int(raw)
            except (TypeError, ValueError, OverflowError) as exc:
                raise ValueError(f"{name} must be an integer") from exc
            if parsed != raw or not 1 <= parsed <= maximum:
                raise ValueError(f"{name} must be between 1 and {maximum}")
    return value


def _gen_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex}"


# ── 请求 ──────────────────────────────────────────────
class ChatMessage(BaseModel):
    model_config = ConfigDict(extra="allow")

    role: Annotated[
        str, StringConstraints(strip_whitespace=True, min_length=1, max_length=32)
    ]
    # content 可为 str，或 OpenAI 多模态的 list[dict]；助手工具调用消息可为 None
    content: Optional[Any] = None
    name: Optional[
        Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=256)]
    ] = None

    @field_validator("content")
    @classmethod
    def _bounded_content(cls, content: Any) -> Any:
        if content is None:
            return None
        if isinstance(content, str):
            if len(content) > 2 * 1024 * 1024:
                raise ValueError("message content exceeds 2 MiB")
            return content
        if isinstance(content, list):
            if len(content) > MAX_CHAT_CONTENT_BLOCKS:
                raise ValueError(
                    f"message has more than {MAX_CHAT_CONTENT_BLOCKS} content blocks"
                )
            if any(not isinstance(block, dict) for block in content):
                raise ValueError("multimodal content blocks must be objects")
            _require_json_size(content, maximum=MAX_CHAT_REQUEST_BYTES, label="message content")
            return content
        # Some OpenAI-compatible clients use an object for tool content. Keep
        # that compatibility, but never accept an unbounded Python object.
        _require_json_size(content, maximum=2 * 1024 * 1024, label="message content")
        return content


class ChatCompletionRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    model: ModelId
    messages: list[ChatMessage] = Field(
        min_length=1, max_length=MAX_CHAT_MESSAGES
    )
    temperature: Optional[float] = Field(default=None, ge=0.0, le=2.0)
    top_p: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    max_tokens: Optional[int] = Field(default=None, ge=1, le=131_072)
    # Common OpenAI-compatible choice multipliers. Their product is capped
    # below so n=4,best_of=4 cannot unexpectedly become sixteen outputs.
    n: Optional[int] = Field(default=None, ge=1, le=4)
    best_of: Optional[int] = Field(default=None, ge=1, le=4)
    stream: bool = False
    stop: Optional[Union[str, list[str]]] = None

    @model_validator(mode="before")
    @classmethod
    def _bounded_choice_aliases(cls, value: Any) -> Any:
        return _validate_multipliers(
            value,
            fields=("n", "best_of", "num_outputs", "num_samples", "batch_size"),
            maximum=4,
        )

    @field_validator("stop")
    @classmethod
    def _bounded_stop(cls, stop: str | list[str] | None) -> str | list[str] | None:
        if stop is None:
            return None
        values = [stop] if isinstance(stop, str) else stop
        if len(values) > 16:
            raise ValueError("stop supports at most 16 strings")
        if any(not isinstance(item, str) or len(item) > 1024 for item in values):
            raise ValueError("each stop string must be at most 1024 characters")
        return stop

    @model_validator(mode="after")
    def _bounded_chat_request(self) -> "ChatCompletionRequest":
        if (self.n or 1) * (self.best_of or 1) > 4:
            raise ValueError("n * best_of must not exceed 4")
        image_count = 0
        for message in self.messages:
            if not isinstance(message.content, list):
                continue
            for block in message.content:
                kind = str(block.get("type") or "").lower()
                if kind in {"image_url", "input_image", "image"}:
                    image_count += 1
        if image_count > MAX_CHAT_IMAGES:
            raise ValueError(f"chat request supports at most {MAX_CHAT_IMAGES} images")
        _require_json_size(
            self.model_dump(exclude_none=True),
            maximum=MAX_CHAT_REQUEST_BYTES,
            label="chat request",
        )
        return self

    def to_upstream_payload(self, upstream_model: str, *, stream: bool) -> dict[str, Any]:
        """生成发往上游的 payload：替换 model 名、设定 stream，并在流式时请求 usage。"""
        data = self.model_dump(exclude_none=True)
        data["model"] = upstream_model
        data["stream"] = stream
        if stream:
            opts = dict(data.get("stream_options") or {})
            opts.setdefault("include_usage", True)
            data["stream_options"] = opts
        else:
            data.pop("stream_options", None)
        return data

    def prompt_text(self) -> str:
        """把 messages 拍平成纯文本（供 echo 及非 OpenAI 适配器使用）。"""
        parts: list[str] = []
        for m in self.messages:
            content = m.content
            if isinstance(content, list):  # 多模态：拼接其中的文本块
                text = "".join(
                    str(blk.get("text", ""))
                    for blk in content
                    if isinstance(blk, dict) and blk.get("type") in (None, "text")
                )
            else:
                text = "" if content is None else str(content)
            parts.append(f"{m.role}: {text}")
        return "\n".join(parts)


# ── 响应 ──────────────────────────────────────────────
class Usage(BaseModel):
    model_config = ConfigDict(extra="allow")

    # Missing provider evidence is unknown, never zero.  Adapters such as echo
    # that can count deterministically populate all three fields explicitly.
    prompt_tokens: Optional[int] = Field(default=None, ge=0)
    completion_tokens: Optional[int] = Field(default=None, ge=0)
    total_tokens: Optional[int] = Field(default=None, ge=0)


class ChatCompletionResponseChoice(BaseModel):
    index: int = 0
    message: ChatMessage
    finish_reason: Optional[str] = "stop"


class ChatCompletionResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str = Field(default_factory=lambda: _gen_id("chatcmpl"))
    object: str = "chat.completion"
    created: int = Field(default_factory=lambda: int(time.time()))
    model: str
    choices: list[ChatCompletionResponseChoice]
    usage: Usage = Field(default_factory=Usage)

    @classmethod
    def from_text(cls, *, model: str, text: str, usage: Optional[Usage] = None) -> "ChatCompletionResponse":
        """便捷构造：把一段文本包成完整的 chat.completion 对象。"""
        return cls(
            model=model,
            choices=[
                ChatCompletionResponseChoice(
                    message=ChatMessage(role="assistant", content=text),
                    finish_reason="stop",
                )
            ],
            usage=usage or Usage(),
        )


# ── 流式 chunk 工具 ───────────────────────────────────
def text_chunk(*, model: str, delta_text: str, chunk_id: str, role: Optional[str] = None) -> dict[str, Any]:
    """构造一个 OpenAI 兼容的 chat.completion.chunk（增量文本）。"""
    delta: dict[str, Any] = {}
    if role is not None:
        delta["role"] = role
    delta["content"] = delta_text
    return {
        "id": chunk_id,
        "object": "chat.completion.chunk",
        "created": int(time.time()),
        "model": model,
        "choices": [{"index": 0, "delta": delta, "finish_reason": None}],
    }


def final_chunk(*, model: str, chunk_id: str, usage: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """构造收尾 chunk（finish_reason=stop，可附带 usage）。"""
    out: dict[str, Any] = {
        "id": chunk_id,
        "object": "chat.completion.chunk",
        "created": int(time.time()),
        "model": model,
        "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
    }
    if usage is not None:
        out["usage"] = usage
    return out


# ── 生图请求（M3 多模态）──
class ImageGenerationRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    model: ModelId
    prompt: Annotated[
        str,
        StringConstraints(
            strip_whitespace=True, min_length=1, max_length=MAX_MEDIA_PROMPT_CHARS
        ),
    ]
    n: Optional[int] = Field(default=None, ge=1, le=MAX_IMAGE_COUNT)
    size: Optional[str] = None
    response_format: Optional[Literal["url", "b64_json"]] = None

    @model_validator(mode="before")
    @classmethod
    def _bounded_generation_aliases(cls, value: Any) -> Any:
        return _validate_multipliers(
            value,
            fields=("n", "num_images", "num_outputs", "num_samples", "batch_size"),
            maximum=MAX_IMAGE_COUNT,
        )

    @field_validator("size")
    @classmethod
    def _bounded_size(cls, size: str | None) -> str | None:
        if size is None:
            return None
        normalized = size.strip().lower()
        if normalized == "auto":
            return normalized
        match = re.fullmatch(r"(\d{2,5})x(\d{2,5})", normalized)
        if match is None:
            raise ValueError("size must be 'auto' or WIDTHxHEIGHT")
        width, height = (int(part) for part in match.groups())
        if not (64 <= width <= 4096 and 64 <= height <= 4096):
            raise ValueError("image dimensions must be between 64 and 4096")
        if width * height > 16_777_216:
            raise ValueError("image dimensions exceed the 16 megapixel limit")
        return normalized

    @model_validator(mode="after")
    def _bounded_image_request(self) -> "ImageGenerationRequest":
        _require_json_size(
            self.model_dump(exclude_none=True),
            maximum=MAX_MEDIA_REQUEST_BYTES,
            label="image request",
        )
        return self

    def to_upstream_payload(self, upstream_model: str) -> dict[str, Any]:
        data = self.model_dump(exclude_none=True)
        data["model"] = upstream_model
        return data


# ── 生视频请求（M3 多模态 · 异步：create→poll）──
class VideoGenerationRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    model: ModelId
    prompt: Annotated[
        str,
        StringConstraints(
            strip_whitespace=True, min_length=1, max_length=MAX_MEDIA_PROMPT_CHARS
        ),
    ]
    image: Optional[Any] = None  # 图生视频：图片 URL 或数组
    mode: Optional[
        Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=64)]
    ] = None  # ti2vid / keyframes 等
    height: Optional[int] = Field(default=None, ge=64, le=4096)
    width: Optional[int] = Field(default=None, ge=64, le=4096)
    # Agnes' verified contract is 8n+1 frames, capped at 441.
    num_frames: Optional[int] = Field(default=None, ge=9, le=441)
    frame_rate: Optional[float] = Field(default=None, ge=1.0, le=60.0)

    @model_validator(mode="before")
    @classmethod
    def _bounded_video_aliases(cls, value: Any) -> Any:
        return _validate_multipliers(
            value,
            fields=("n", "num_videos", "num_outputs", "num_samples", "batch_size"),
            maximum=1,
        )

    @model_validator(mode="after")
    def _bounded_video_request(self) -> "VideoGenerationRequest":
        if (self.width is None) != (self.height is None):
            raise ValueError("video width and height must be supplied together")
        if self.width is not None and self.height is not None:
            if self.width * self.height > 8_294_400:
                raise ValueError("video dimensions exceed the 4K pixel limit")
        if self.num_frames is not None and (self.num_frames - 1) % 8 != 0:
            raise ValueError("num_frames must satisfy 8n+1 and be at most 441")

        image_values: list[Any] = []
        if self.image is not None:
            image_values.extend(self.image if isinstance(self.image, list) else [self.image])
        extra_body = (self.model_extra or {}).get("extra_body")
        if isinstance(extra_body, dict) and extra_body.get("image") is not None:
            raw = extra_body["image"]
            image_values.extend(raw if isinstance(raw, list) else [raw])
        if len(image_values) > MAX_VIDEO_KEYFRAMES:
            raise ValueError(
                f"video request supports at most {MAX_VIDEO_KEYFRAMES} keyframes"
            )
        if any(not isinstance(item, (str, dict)) for item in image_values):
            raise ValueError("video keyframes must be URLs, base64 strings, or objects")
        _require_json_size(
            image_values,
            maximum=20 * 1024 * 1024,
            label="video keyframes",
        )
        _require_json_size(
            self.model_dump(exclude_none=True),
            maximum=MAX_MEDIA_REQUEST_BYTES,
            label="video request",
        )
        return self

    def to_upstream_payload(self, upstream_model: str) -> dict[str, Any]:
        data = self.model_dump(exclude_none=True)
        data["model"] = upstream_model
        return data


# ── Bounded multi-model workflow inputs ────────────────────────────────
class PanelWorkflowRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    prompt: WorkflowPrompt
    panelists: list[ModelId] = Field(min_length=1, max_length=MAX_PANELISTS)
    judge: ModelId

    @model_validator(mode="after")
    def require_requested_route_independence(self) -> "PanelWorkflowRequest":
        if len(set(self.panelists)) != len(self.panelists):
            raise ValueError("panelist model routes must be distinct")
        if self.judge in self.panelists:
            raise ValueError("judge model route must differ from every panelist")
        return self


class DebateWorkflowRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    prompt: WorkflowPrompt
    debaters: list[ModelId] = Field(min_length=2, max_length=MAX_DEBATERS)
    judge: ModelId
    rounds: int = Field(default=2, ge=1, le=MAX_DEBATE_ROUNDS)

    @model_validator(mode="after")
    def require_requested_route_independence(self) -> "DebateWorkflowRequest":
        if len(set(self.debaters)) != len(self.debaters):
            raise ValueError("debater model routes must be distinct")
        if self.judge in self.debaters:
            raise ValueError("judge model route must differ from every debater")
        return self


class DecomposeWorkflowRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task: WorkflowPrompt
    planner: ModelId
    aggregator: ModelId


class PipelineStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    model: ModelId
    instruction: Annotated[
        str, StringConstraints(strip_whitespace=True, max_length=16_384)
    ] = ""


class PipelineWorkflowRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    prompt: WorkflowPrompt
    steps: list[PipelineStep] = Field(min_length=1, max_length=MAX_PIPELINE_STEPS)


class WorkflowOutputLimitError(RuntimeError):
    """An upstream model exceeded the safe intermediate-output contract."""


def require_workflow_output(value: Any, *, label: str) -> str:
    """Validate, never silently truncate, an intermediate model output."""

    if not isinstance(value, str):
        raise WorkflowOutputLimitError(f"{label} output is not text")
    if len(value) > MAX_WORKFLOW_OUTPUT_CHARS:
        raise WorkflowOutputLimitError(
            f"{label} output exceeds {MAX_WORKFLOW_OUTPUT_CHARS} characters"
        )
    return value
