"""生视频：请求校验 + 不支持的 provider + openai_compat 的 create/poll（mock）。"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

import gateway.public_media as public_media
import gateway.providers.openai_compat as oc
from gateway.app import app
from gateway.public_media import (
    PinnedTarget,
    PublicFetchContentTypeError,
    PublicFetchSecurityError,
    PublicFetchTimeout,
    PublicFetchTooLarge,
    PublicFileResult,
    download_public_file,
    fetch_public_bytes,
    fetch_public_text,
    request_public_bytes,
)
from gateway.providers.base import ProviderError
from gateway.providers.openai_compat import OpenAICompatProvider
from gateway.schemas import VideoGenerationRequest

AUTH = {"Authorization": "Bearer test-key"}
UP = "https://up.example/v1"


def test_video_validation(paid_media_auth_headers):
    with TestClient(app) as c:
        r = c.post(
            "/v1/videos/generations",
            headers={
                **paid_media_auth_headers,
                "Idempotency-Key": f"test-video-{uuid4()}",
                "X-Nachuan-Paid-Media-Protocol": "2",
            },
            json={"model": "echo"},
        )
        assert r.status_code == 422  # 缺 prompt


def test_video_unsupported_provider(paid_media_auth_headers):
    # echo 既没有可冻结的视频轮询身份，也没有 video asset-v2 能力；
    # 视频创建先在稳定 route identity 门失败，绝不能触达 provider。
    with TestClient(app) as c:
        r = c.post(
            "/v1/videos/generations",
            headers={
                **paid_media_auth_headers,
                "Idempotency-Key": f"test-video-{uuid4()}",
                "X-Nachuan-Paid-Media-Protocol": "2",
            },
            json={"model": "echo", "prompt": "a cat"},
        )
        assert r.status_code == 503
        assert r.json()["detail"]["code"] == "video_route_identity_unavailable"


@respx.mock
async def test_openai_compat_create_and_poll_video():
    respx.post(f"{UP}/videos").mock(return_value=httpx.Response(200, json={"task_id": "t123"}))
    respx.get(f"{UP}/videos/t123").mock(
        return_value=httpx.Response(200, json={"status": "done", "url": "http://x/v.mp4"})
    )
    p = OpenAICompatProvider(name="t", base_url=UP, api_key="k")
    created = await p.generate_video(VideoGenerationRequest(model="v", prompt="a cat"), "agnes-video-v2.0")
    assert created["task_id"] == "t123"
    polled = await p.get_video("t123")
    assert polled["url"] == "http://x/v.mp4"
    await p.aclose()


@respx.mock
async def test_get_video_retries_transient_then_succeeds(monkeypatch):
    """瞬时错(RemoteProtocolError 连接被掐 + 502)→退避重试→最终成功；一次抖动不该整条报废。"""
    monkeypatch.setattr(oc, "_VIDEO_RETRY_BACKOFFS", (0.0, 0.0, 0.0, 0.0))  # 退避清零，测试不真睡
    route = respx.get(f"{UP}/videos/t9").mock(
        side_effect=[
            httpx.RemoteProtocolError("server disconnected"),  # 新纳入网的瞬时错 → 重试
            httpx.Response(502),  # 上游临时 502 → 重试
            httpx.Response(200, json={"status": "done", "url": "http://x/v.mp4"}),  # 成功
        ]
    )
    p = OpenAICompatProvider(name="t", base_url=UP, api_key="k")
    polled = await p.get_video("t9")
    assert polled["url"] == "http://x/v.mp4"
    assert route.call_count == 3  # 重试 2 次才成
    await p.aclose()


@respx.mock
async def test_agnes_get_video_uses_agnesapi_and_extracts_nested_url():
    """机主实测根因:Agnes 状态在 /agnesapi?video_id=(非 /videos/{id}),成片 URL 藏在嵌套字段。
    get_video 要走对端点 + 从 11 字段挖出 URL 归一化到 st.url,前端才认得出"完成"。"""
    AGNES = "https://apihub.agnes-ai.com/v1"
    route = respx.get(url__regex=r"https://apihub\.agnes-ai\.com/agnesapi.*").mock(
        return_value=httpx.Response(200, json={"status": "Completed", "data": {"video_url": "https://x/v.mp4"}})
    )
    p = OpenAICompatProvider(name="agnes", base_url=AGNES, api_key="k")
    got = await p.get_video("task_abc")
    assert route.called  # 打的是 /agnesapi,不是 /v1/videos/{id}
    assert got["url"] == "https://x/v.mp4"  # 从 data.video_url 挖出、归一到 url
    assert got["status"] == "completed"  # 归一为小写,便于前端匹配
    await p.aclose()


@respx.mock
async def test_agnes_get_video_extracts_current_official_metadata_url():
    """Current Agnes V2.0 docs place the completed asset at metadata.url."""

    agnes = "https://apihub.agnes-ai.com/v1"
    respx.get(url__regex=r"https://apihub\.agnes-ai\.com/agnesapi.*").mock(
        return_value=httpx.Response(
            200,
            json={
                "status": "completed",
                "video_id": "video_poll_official",
                "metadata": {
                    "url": (
                        "https://platform-outputs.agnes-ai.space/videos/"
                        "agnes-video-v2.0/task_official.mp4"
                    )
                },
            },
        )
    )
    provider = OpenAICompatProvider(name="agnes", base_url=agnes, api_key="k")
    got = await provider.get_video("video_poll_official")
    assert got["url"] == (
        "https://platform-outputs.agnes-ai.space/videos/"
        "agnes-video-v2.0/task_official.mp4"
    )
    assert got["status"] == "completed"
    await provider.aclose()


@respx.mock
async def test_agnes_create_returns_pollable_video_id_not_submit_task_id():
    """Agnes create 的 task_id 不能查询；/agnesapi 只认同响应里的 video_id。"""
    agnes = "https://apihub.agnes-ai.com/v1"
    respx.post(f"{agnes}/videos").mock(return_value=httpx.Response(200, json={
        "id": "task_submit_123",
        "task_id": "task_submit_123",
        "video_id": "video_poll_456",
        "status": "queued",
    }))
    poll = respx.get(
        "https://apihub.agnes-ai.com/agnesapi?video_id=video_poll_456"
    ).mock(return_value=httpx.Response(200, json={
        "status": "completed", "url": "https://x/final.mp4",
    }))

    p = OpenAICompatProvider(name="agnes", base_url=agnes, api_key="k")
    created = await p.generate_video(
        VideoGenerationRequest(model="agnes-video", prompt="cat"),
        "agnes-video-v2.0",
    )
    assert created["task_id"] == "video_poll_456"
    assert created["video_id"] == "video_poll_456"
    assert created["upstream_task_id"] == "task_submit_123"
    got = await p.get_video(created["task_id"])
    assert poll.called and got["url"] == "https://x/final.mp4"
    await p.aclose()


@respx.mock
async def test_agnes_create_without_video_id_fails_closed_instead_of_mispolling_task_id():
    """A task_id belongs to the legacy endpoint and must not enter /agnesapi."""

    agnes = "https://apihub.agnes-ai.com/v1"
    respx.post(f"{agnes}/videos").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "task_submit_only",
                "task_id": "task_submit_only",
                "status": "queued",
            },
        )
    )
    provider = OpenAICompatProvider(name="agnes", base_url=agnes, api_key="k")
    try:
        with pytest.raises(ProviderError, match="video_id"):
            await provider.generate_video(
                VideoGenerationRequest(model="agnes-video", prompt="cat"),
                "agnes-video-v2.0",
            )
    finally:
        await provider.aclose()


@respx.mock
async def test_agnes_get_video_still_processing_no_url():
    """仍在生成:agnesapi 回 processing、无 URL → get_video 返 status=processing 且不带 url(前端继续轮)。"""
    AGNES = "https://apihub.agnes-ai.com/v1"
    respx.get(url__regex=r".*/agnesapi.*").mock(
        return_value=httpx.Response(200, json={"status": "processing"})
    )
    p = OpenAICompatProvider(name="agnes", base_url=AGNES, api_key="k")
    got = await p.get_video("task_xyz")
    assert got["status"] == "processing"
    assert not got.get("url")
    await p.aclose()


@respx.mock
async def test_get_video_no_retry_on_4xx(monkeypatch):
    """4xx(401 鉴权错)→白重试，直接抛，只调一次。"""
    monkeypatch.setattr(oc, "_VIDEO_RETRY_BACKOFFS", (0.0, 0.0, 0.0, 0.0))
    route = respx.get(f"{UP}/videos/t4").mock(return_value=httpx.Response(401, text="unauth"))
    p = OpenAICompatProvider(name="t", base_url=UP, api_key="k")
    with pytest.raises(ProviderError):
        await p.get_video("t4")
    assert route.call_count == 1  # 不重试
    await p.aclose()


class _PinnedResponse:
    def __init__(self, body=b"", *, status=200, headers=None):
        self.status = status
        self.reason = "test"
        self._headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
        self._chunks = list(body) if isinstance(body, list) else [body]
        self.closed = False

    def getheader(self, name, default=None):
        return self._headers.get(str(name).lower(), default)

    def getheaders(self):
        return list(self._headers.items())

    def read1(self, _size):
        return self._chunks.pop(0) if self._chunks else b""

    def close(self):
        self.closed = True


class _PinnedConnection:
    sock = None

    def __init__(self, response):
        self.response = response
        self.request_args = None
        self.closed = False

    def request(self, *args, **kwargs):
        self.request_args = (args, kwargs)

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True


def _public_dns(host, port, **_kwargs):
    del host
    return [(2, 1, 6, "", ("93.184.216.34", port))]


def test_public_fetch_pins_socket_to_validated_ip():
    targets: list[PinnedTarget] = []

    def factory(target, timeout):
        targets.append(target)
        assert 0 < timeout <= 5
        return _PinnedConnection(
            _PinnedResponse(
                b"MP4BYTES",
                headers={"content-type": "video/mp4", "content-length": "8"},
            )
        )

    got = fetch_public_bytes(
        "https://media.example/video.mp4",
        max_bytes=32,
        allowed_type_prefixes=("video/",),
        resolver=_public_dns,
        connection_factory=factory,
        idle_timeout=5,
    )
    assert got.data == b"MP4BYTES"
    assert targets == [
        PinnedTarget(
            scheme="https",
            hostname="media.example",
            port=443,
            ip="93.184.216.34",
        )
    ]


@pytest.mark.parametrize(
    "answers",
    [
        [(2, 1, 6, "", ("127.0.0.1", 443))],
        [
            (2, 1, 6, "", ("93.184.216.34", 443)),
            (2, 1, 6, "", ("10.0.0.7", 443)),
        ],
    ],
)
def test_public_fetch_rejects_private_or_mixed_dns(answers):
    connected = False

    def resolver(_host, _port, **_kwargs):
        return answers

    def factory(_target, _timeout):
        nonlocal connected
        connected = True
        raise AssertionError("unsafe DNS answer must not reach connect")

    with pytest.raises(PublicFetchSecurityError):
        fetch_public_bytes(
            "https://media.example/video.mp4",
            max_bytes=32,
            allowed_type_prefixes=("video/",),
            resolver=resolver,
            connection_factory=factory,
        )
    assert connected is False


def test_public_fetch_revalidates_and_pins_redirect_second_hop():
    targets: list[PinnedTarget] = []
    responses = [
        _PinnedResponse(status=302, headers={"location": "https://cdn.example/final.mp4"}),
        _PinnedResponse(b"video", headers={"content-type": "video/mp4"}),
    ]

    def resolver(host, port, **_kwargs):
        ip = "93.184.216.34" if host == "origin.example" else "142.250.72.14"
        return [(2, 1, 6, "", (ip, port))]

    def factory(target, _timeout):
        targets.append(target)
        return _PinnedConnection(responses.pop(0))

    got = fetch_public_bytes(
        "https://origin.example/start",
        max_bytes=32,
        allowed_type_prefixes=("video/",),
        resolver=resolver,
        connection_factory=factory,
    )
    assert got.data == b"video"
    assert [(target.hostname, target.ip) for target in targets] == [
        ("origin.example", "93.184.216.34"),
        ("cdn.example", "142.250.72.14"),
    ]


def test_public_fetch_rejects_private_redirect_second_hop():
    responses = [_PinnedResponse(status=302, headers={"location": "https://private.example/x"})]

    def resolver(host, port, **_kwargs):
        ip = "93.184.216.34" if host == "origin.example" else "127.0.0.1"
        return [(2, 1, 6, "", (ip, port))]

    with pytest.raises(PublicFetchSecurityError):
        fetch_public_bytes(
            "https://origin.example/start",
            max_bytes=32,
            allowed_type_prefixes=("video/",),
            resolver=resolver,
            connection_factory=lambda _target, _timeout: _PinnedConnection(responses.pop(0)),
        )


def test_public_fetch_applies_caller_url_guard_to_every_redirect():
    response = _PinnedResponse(
        status=302,
        headers={"location": "https://other-public.example/final.mp4"},
    )
    connected = 0

    def factory(_target, _timeout):
        nonlocal connected
        connected += 1
        return _PinnedConnection(response)

    with pytest.raises(PublicFetchSecurityError, match="host policy"):
        fetch_public_bytes(
            "https://official.example/start",
            max_bytes=32,
            allowed_type_prefixes=("video/",),
            resolver=_public_dns,
            connection_factory=factory,
            url_guard=lambda candidate: candidate.startswith("https://official.example/"),
        )
    assert connected == 1


def test_public_fetch_rejects_https_downgrade():
    response = _PinnedResponse(status=302, headers={"location": "http://cdn.example/final.mp4"})
    with pytest.raises(PublicFetchSecurityError, match="HTTPS"):
        fetch_public_bytes(
            "https://origin.example/start",
            max_bytes=32,
            allowed_type_prefixes=("video/",),
            resolver=_public_dns,
            connection_factory=lambda _target, _timeout: _PinnedConnection(response),
        )


def test_public_fetch_rejects_credentials_before_cross_origin_redirect():
    connected = False

    def factory(_target, _timeout):
        nonlocal connected
        connected = True
        raise AssertionError("credential-bearing request must not reach the network")

    with pytest.raises(PublicFetchSecurityError, match="credential-free"):
        fetch_public_bytes(
            "https://origin.example/start",
            max_bytes=32,
            allowed_type_prefixes=("video/",),
            headers={"Authorization": "Bearer must-not-leak"},
            resolver=_public_dns,
            connection_factory=factory,
        )
    assert connected is False


def test_public_post_is_pinned_bounded_and_never_redirect_replayed():
    response = _PinnedResponse(
        b"ok",
        headers={
            "content-length": "2",
            "x-encrypted-param": "receipt",
        },
    )
    connection = _PinnedConnection(response)
    got = request_public_bytes(
        "https://upload.example/c2c?signature=opaque",
        method="POST",
        request_body=b"cipher",
        request_content_type="application/octet-stream",
        max_request_bytes=6,
        max_bytes=8,
        require_content_type=False,
        resolver=_public_dns,
        connection_factory=lambda target, _timeout: (
            connection
            if target.ip == "93.184.216.34"
            else pytest.fail("connection was not pinned to the validated IP")
        ),
    )
    assert got.data == b"ok"
    assert got.headers["x-encrypted-param"] == "receipt"
    assert connection.request_args is not None
    args, kwargs = connection.request_args
    assert args[:2] == ("POST", "/c2c?signature=opaque")
    assert kwargs["body"] == b"cipher"
    assert kwargs["headers"]["Content-Type"] == "application/octet-stream"

    redirecting = _PinnedConnection(
        _PinnedResponse(status=307, headers={"location": "https://upload.example/other"})
    )
    with pytest.raises(PublicFetchSecurityError, match="request body"):
        request_public_bytes(
            "https://upload.example/c2c",
            method="POST",
            request_body=b"cipher",
            request_content_type="application/octet-stream",
            max_request_bytes=6,
            max_bytes=8,
            require_content_type=False,
            resolver=_public_dns,
            connection_factory=lambda _target, _timeout: redirecting,
        )


def test_public_fetch_rejects_nonstandard_port_before_dns():
    resolved = False

    def resolver(*_args, **_kwargs):
        nonlocal resolved
        resolved = True
        raise AssertionError("nonstandard port must be rejected before DNS")

    with pytest.raises(PublicFetchSecurityError, match="standard"):
        fetch_public_bytes(
            "https://media.example:8443/video.mp4",
            max_bytes=32,
            allowed_type_prefixes=("video/",),
            resolver=resolver,
        )
    assert resolved is False

    for mismatched in (
        "http://media.example:443/video.mp4",
        "https://media.example:80/video.mp4",
    ):
        with pytest.raises(PublicFetchSecurityError, match="scheme"):
            fetch_public_bytes(
                mismatched,
                max_bytes=32,
                allowed_type_prefixes=("video/",),
                resolver=resolver,
            )
    assert resolved is False


def test_public_fetch_percent_encodes_unicode_request_target():
    connection = _PinnedConnection(
        _PinnedResponse(b"video", headers={"content-type": "video/mp4"})
    )
    got = fetch_public_bytes(
        "https://media.example/成片/你好.mp4?名称=最终版",
        max_bytes=32,
        allowed_type_prefixes=("video/",),
        resolver=_public_dns,
        connection_factory=lambda _target, _timeout: connection,
    )
    assert got.data == b"video"
    assert connection.request_args is not None
    request_target = connection.request_args[0][1]
    request_target.encode("ascii")
    assert "%E6%88%90%E7%89%87" in request_target


def test_public_fetch_text_honors_charset_and_character_cap():
    body = "你好世界".encode("gb18030")
    response = _PinnedResponse(
        body,
        headers={
            "content-type": "text/html; charset=gb18030",
            "content-length": str(len(body)),
        },
    )
    got = fetch_public_text(
        "https://article.example/page",
        max_bytes=32,
        max_chars=2,
        allowed_type_prefixes=("text/",),
        resolver=_public_dns,
        connection_factory=lambda _target, _timeout: _PinnedConnection(response),
    )
    assert got.text == "你好"
    assert got.encoding == "gb18030"
    assert got.size == len(body)


def test_public_fetch_text_rejects_non_text_or_unknown_charset():
    for charset in ("base64_codec", "definitely-not-a-codec"):
        response = _PinnedResponse(
            b"payload",
            headers={
                "content-type": f"text/plain; charset={charset}",
                "content-length": "7",
            },
        )
        with pytest.raises(PublicFetchContentTypeError, match="charset"):
            fetch_public_text(
                "https://article.example/page",
                max_bytes=32,
                max_chars=32,
                allowed_type_prefixes=("text/",),
                resolver=_public_dns,
                connection_factory=lambda _target, _timeout, response=response: _PinnedConnection(response),
            )


def test_public_file_unknown_length_cap_cleans_partial(tmp_path):
    response = _PinnedResponse(
        [b"12345678", b"9"],
        headers={"content-type": "video/mp4"},
    )
    with pytest.raises(PublicFetchTooLarge):
        download_public_file(
            "https://media.example/video.mp4",
            max_bytes=8,
            allowed_type_prefixes=("video/",),
            resolver=_public_dns,
            connection_factory=lambda _target, _timeout: _PinnedConnection(response),
            temp_dir=tmp_path,
        )
    assert list(tmp_path.iterdir()) == []


def test_public_file_declared_length_cap_cleans_partial_without_reading(tmp_path):
    class UnreadableResponse(_PinnedResponse):
        def read1(self, _size):
            raise AssertionError("oversized declared response must not be read")

    response = UnreadableResponse(
        headers={"content-type": "video/mp4", "content-length": "9"}
    )
    with pytest.raises(PublicFetchTooLarge, match="declared"):
        download_public_file(
            "https://media.example/video.mp4",
            max_bytes=8,
            allowed_type_prefixes=("video/",),
            resolver=_public_dns,
            connection_factory=lambda _target, _timeout: _PinnedConnection(response),
            temp_dir=tmp_path,
        )
    assert list(tmp_path.iterdir()) == []


def test_public_file_rejects_utf8_content_encoding_mislabel_by_default(
    tmp_path,
):
    response = _PinnedResponse(
        b"raw-image",
        headers={
            "content-type": "image/png",
            "content-encoding": "utf-8",
            "content-length": "9",
        },
    )
    with pytest.raises(PublicFetchContentTypeError, match="encoded"):
        download_public_file(
            "https://media.example/image.png",
            max_bytes=32,
            allowed_exact_types=("image/png",),
            resolver=_public_dns,
            connection_factory=lambda _target, _timeout: _PinnedConnection(response),
            temp_dir=tmp_path,
        )
    assert list(tmp_path.iterdir()) == []


def test_public_file_explicit_url_guard_can_treat_utf8_mislabel_as_identity(
    tmp_path,
):
    response = _PinnedResponse(
        b"raw-image",
        headers={
            "content-type": "image/png",
            "content-encoding": "utf-8",
            "content-length": "9",
        },
    )
    guarded_urls: list[str] = []

    def utf8_identity_url_guard(candidate: str) -> bool:
        guarded_urls.append(candidate)
        return candidate == "https://media.example/image.png"

    result = download_public_file(
        "https://media.example/image.png",
        max_bytes=32,
        allowed_exact_types=("image/png",),
        utf8_identity_url_guard=utf8_identity_url_guard,
        resolver=_public_dns,
        connection_factory=lambda _target, _timeout: _PinnedConnection(response),
        temp_dir=tmp_path,
    )
    try:
        assert Path(result.path).read_bytes() == b"raw-image"
        assert result.content_type == "image/png"
        assert result.headers["content-encoding"] == "utf-8"
        assert guarded_urls == ["https://media.example/image.png"]
    finally:
        Path(result.path).unlink(missing_ok=True)


def test_public_file_utf8_identity_guard_rejection_stays_fail_closed(tmp_path):
    response = _PinnedResponse(
        b"raw-image",
        headers={
            "content-type": "image/png",
            "content-encoding": "utf-8",
            "content-length": "9",
        },
    )
    with pytest.raises(PublicFetchContentTypeError, match="encoded"):
        download_public_file(
            "https://other.example/image.png",
            max_bytes=32,
            allowed_exact_types=("image/png",),
            utf8_identity_url_guard=lambda _candidate: False,
            resolver=_public_dns,
            connection_factory=lambda _target, _timeout: _PinnedConnection(response),
            temp_dir=tmp_path,
        )
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "content_encoding",
    ("gzip", "br", "utf-8, gzip", "utf-8; charset=utf-8", "utf-8, utf-8"),
)
def test_public_file_utf8_identity_guard_never_accepts_transform_or_composite_encoding(
    tmp_path,
    content_encoding,
):
    response = _PinnedResponse(
        b"raw-image",
        headers={
            "content-type": "image/png",
            "content-encoding": content_encoding,
            "content-length": "9",
        },
    )
    with pytest.raises(PublicFetchContentTypeError, match="encoded"):
        download_public_file(
            "https://media.example/image.png",
            max_bytes=32,
            allowed_exact_types=("image/png",),
            utf8_identity_url_guard=lambda _candidate: True,
            resolver=_public_dns,
            connection_factory=lambda _target, _timeout: _PinnedConnection(response),
            temp_dir=tmp_path,
        )
    assert list(tmp_path.iterdir()) == []


def test_public_file_utf8_identity_guard_evaluates_the_final_redirect_url(
    tmp_path,
):
    responses = [
        _PinnedResponse(
            status=302,
            headers={"location": "https://other.example/image.png"},
        ),
        _PinnedResponse(
            b"raw-image",
            headers={
                "content-type": "image/png",
                "content-encoding": "utf-8",
                "content-length": "9",
            },
        ),
    ]
    with pytest.raises(PublicFetchContentTypeError, match="encoded"):
        download_public_file(
            "https://allowed.example/image.png",
            max_bytes=32,
            allowed_exact_types=("image/png",),
            utf8_identity_url_guard=lambda candidate: (
                candidate == "https://allowed.example/image.png"
            ),
            resolver=_public_dns,
            connection_factory=lambda _target, _timeout: _PinnedConnection(
                responses.pop(0)
            ),
            temp_dir=tmp_path,
        )
    assert list(tmp_path.iterdir()) == []

    responses = [
        _PinnedResponse(
            status=302,
            headers={"location": "https://allowed.example/image.png"},
        ),
        _PinnedResponse(
            b"raw-image",
            headers={
                "content-type": "image/png",
                "content-encoding": "utf-8",
                "content-length": "9",
            },
        ),
    ]
    result = download_public_file(
        "https://other.example/image.png",
        max_bytes=32,
        allowed_exact_types=("image/png",),
        utf8_identity_url_guard=lambda candidate: (
            candidate == "https://allowed.example/image.png"
        ),
        resolver=_public_dns,
        connection_factory=lambda _target, _timeout: _PinnedConnection(
            responses.pop(0)
        ),
        temp_dir=tmp_path,
    )
    try:
        assert Path(result.path).read_bytes() == b"raw-image"
        assert result.final_url == "https://allowed.example/image.png"
    finally:
        Path(result.path).unlink(missing_ok=True)


def test_public_fetch_dns_is_inside_wall_clock_deadline():
    class DeadlineClock:
        """Expire only after the resolver worker has been dispatched."""

        def __init__(self):
            self.calls = 0

        def __call__(self):
            self.calls += 1
            # _fetch_into establishes the deadline on call 1 and
            # _resolve_public acquires its bounded slot on call 2.  Advancing
            # on call 3 makes the post-dispatch deadline check deterministic,
            # without asserting on a scheduler-dependent number of ms.
            return 0.0 if self.calls <= 2 else 2.0

    resolver_started = threading.Event()
    resolver_release = threading.Event()
    resolver_finished = threading.Event()

    def stalled_dns(_host, port, **_kwargs):
        resolver_started.set()
        try:
            if not resolver_release.wait(timeout=10):
                raise AssertionError("test resolver release handshake timed out")
            return [(2, 1, 6, "", ("93.184.216.34", port))]
        finally:
            resolver_finished.set()

    clock = DeadlineClock()
    try:
        with pytest.raises(PublicFetchTimeout, match="DNS"):
            fetch_public_bytes(
                "https://media.example/video.mp4",
                max_bytes=8,
                allowed_type_prefixes=("video/",),
                total_timeout=1.0,
                resolver=stalled_dns,
                connection_factory=lambda *_args: pytest.fail("connect must not run"),
                clock=clock,
            )
        assert resolver_started.wait(timeout=10), "resolver worker was not dispatched"
        assert not resolver_finished.is_set(), (
            "fetch waited for DNS completion instead of enforcing its deadline"
        )
        assert clock.calls >= 3
    finally:
        resolver_release.set()
    assert resolver_finished.wait(timeout=10), "resolver worker did not shut down"


def test_public_fetch_http_operation_threads_are_bounded(monkeypatch):
    class ExhaustedSlots:
        def __init__(self):
            self.acquire_calls = 0

        def acquire(self, *, timeout):
            assert timeout > 0
            self.acquire_calls += 1
            return False

        def release(self):
            raise AssertionError("no HTTP slot was acquired")

    slots = ExhaustedSlots()
    monkeypatch.setattr(public_media, "_HTTP_SLOTS", slots)
    connection = _PinnedConnection(
        _PinnedResponse(b"video", headers={"content-type": "video/mp4"})
    )
    with pytest.raises(PublicFetchTimeout, match="capacity"):
        fetch_public_bytes(
            "https://93.184.216.34/video.mp4",
            max_bytes=32,
            allowed_type_prefixes=("video/",),
            total_timeout=1,
            connection_factory=lambda _target, _timeout: connection,
        )
    assert slots.acquire_calls == 1
    assert connection.request_args is None


def test_public_fetch_redirects_share_the_original_deadline():
    class Clock:
        value = 0.0

        def __call__(self):
            return self.value

    clock = Clock()

    class SlowRedirect(_PinnedResponse):
        def getheader(self, name, default=None):
            value = super().getheader(name, default)
            if str(name).lower() == "location":
                clock.value = 2.0
            return value

    connected = 0

    def factory(_target, _timeout):
        nonlocal connected
        connected += 1
        return _PinnedConnection(
            SlowRedirect(status=302, headers={"location": "https://cdn.example/final.mp4"})
        )

    with pytest.raises(PublicFetchTimeout):
        fetch_public_bytes(
            "https://origin.example/start",
            max_bytes=8,
            allowed_type_prefixes=("video/",),
            total_timeout=1,
            resolver=_public_dns,
            connection_factory=factory,
            clock=clock,
        )
    assert connected == 1


def test_public_fetch_wall_clock_deadline_cleans_partial(tmp_path):
    class Clock:
        value = 0.0

        def __call__(self):
            return self.value

    clock = Clock()

    class SlowResponse(_PinnedResponse):
        def read1(self, size):
            chunk = super().read1(size)
            clock.value += 2.0
            return chunk

    response = SlowResponse([b"x", b"y"], headers={"content-type": "video/mp4"})
    with pytest.raises(PublicFetchTimeout):
        download_public_file(
            "https://media.example/video.mp4",
            max_bytes=8,
            allowed_type_prefixes=("video/",),
            total_timeout=1,
            resolver=_public_dns,
            connection_factory=lambda _target, _timeout: _PinnedConnection(response),
            temp_dir=tmp_path,
            clock=clock,
        )
    assert list(tmp_path.iterdir()) == []


def test_fetch_video_proxies_bytes(monkeypatch, tmp_path):
    """/v1/videos/fetch：引擎代下海外成片字节回给前端（前端做 blob 本地播放）。"""
    fetched = tmp_path / "fetched.video"

    def fake_download(url, **kwargs):
        assert url == "https://agnes-ai.space/v/abc.mp4"
        assert kwargs["max_bytes"] == 512 * 1024 * 1024
        fetched.write_bytes(b"MP4BYTES")
        return PublicFileResult(
            path=str(fetched),
            content_type="video/mp4",
            final_url=url,
            size=8,
            headers={"content-type": "video/mp4"},
        )

    monkeypatch.setattr("gateway.app.download_public_file", fake_download)
    with TestClient(app) as c:
        r = c.get("/v1/videos/fetch?url=https://agnes-ai.space/v/abc.mp4", headers=AUTH)
    assert r.status_code == 200
    assert r.content == b"MP4BYTES"
    assert "video/mp4" in r.headers.get("content-type", "")
    assert not fetched.exists()


def test_fetch_video_rejects_non_http():
    """非 http(s) 的 url（如 file://）直接 400，别让引擎代拉本地文件（基本 SSRF 护栏）。"""
    with TestClient(app) as c:
        r = c.get("/v1/videos/fetch?url=file:///etc/passwd", headers=AUTH)
    assert r.status_code == 400


def test_fetch_video_rejects_localhost_ssrf():
    with TestClient(app) as c:
        r = c.get("/v1/videos/fetch?url=http://localhost:8080/health", headers=AUTH)
    assert r.status_code == 400


def test_studio_job_recovers_from_disk_after_restart(tmp_path, monkeypatch):
    """长视频 job 落盘持久化：内存丢了(热更新/引擎重启)也能从磁盘恢复进度/成片——
    机主实测灾难根修：30秒外星人大战真拼好了(final_*.mp4)、内存索引却蒸发、成片取不回、以为模型敷衍。"""
    import orchestrator.studio as studio

    monkeypatch.setattr(studio, "_out_dir", lambda: str(tmp_path))

    # ① job 文件在 → 从磁盘读回真实进度
    jid = "deadbeef1234"
    studio._persist(jid, {"status": "running", "progress": 3, "total": 9, "video": "", "msg": "第4/9镜"})
    studio._JOBS.clear()  # 模拟引擎重启：内存全丢
    j = studio.get_job(jid)
    assert j["status"] == "running" and j["progress"] == 3 and j["total"] == 9

    # ② job 文件也没了，但成片 final_*.mp4 在盘上 → 认完成，成片不白做
    jid2 = "cafe00009999"
    final = tmp_path / f"final_{jid2}.mp4"
    final.write_bytes(b"\x00\x00fake mp4")
    studio._JOBS.clear()
    j2 = studio.get_job(jid2)
    assert j2["status"] == "done" and j2["video"].endswith(f"final_{jid2}.mp4")

    # ③ 啥都没 → unknown（不误报完成）
    studio._JOBS.clear()
    assert studio.get_job("nothing000000")["status"] == "unknown"


def test_find_media_url_rejects_image_returns_video():
    """长视频 shot1~8 全下成 PNG 的根因回归：_find_media_url 的 dict 分支必须拦图片 URL、
    只认视频——图生视频响应常回显输入图/首帧(png)，旧代码有 http url 就当成片 → 下成图片循环污染。"""
    from orchestrator.media import _find_media_url

    # 图生视频处理中回显输入图 → 绝不当成片
    assert _find_media_url({"url": "https://x/frame.png", "status": "processing"}) == ""
    assert _find_media_url({"preview_url": "https://x/a.jpg"}) == ""
    # 真成片：含 video 字样 / .mp4 扩展名 → 抠到
    assert _find_media_url({"data": {"url": "https://x/videos/task_abc"}}) == "https://x/videos/task_abc"
    assert _find_media_url({"output_url": "https://x/out.mp4"}) == "https://x/out.mp4"
    # 图在前、视频在后 → 跳过图、抠到视频
    assert _find_media_url({"thumb": "https://x/t.jpg", "r": {"video_url": "https://x/f.mp4"}}) == "https://x/f.mp4"


def test_studio_looks_like_image_guards_stitch(tmp_path):
    """第二道防线：下载到 PNG(魔数)识别为图片 → 不塞进拼接（万一 URL 校验漏网也拦住）。"""
    from orchestrator.studio import _looks_like_image

    png = tmp_path / "shot.mp4"
    png.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 50)  # PNG 魔数
    assert _looks_like_image(str(png)) is True
    mp4 = tmp_path / "real.mp4"
    mp4.write_bytes(b"\x00\x00\x00\x20ftypmp42" + b"\x00" * 50)  # mp4 ftyp
    assert _looks_like_image(str(mp4)) is False
