from __future__ import annotations

from gateway.failover import _public_provider_stream_error
from gateway.app import _public_provider_http_error
from gateway.providers.base import (
    ProviderError,
    ProviderSubmissionOutcomeUnknown,
    friendly_error,
    friendly_status,
)


def test_unknown_provider_exception_does_not_echo_raw_detail() -> None:
    secret = "sk-live-secret C:\\Users\\owner\\private.txt"

    message = friendly_error(RuntimeError(secret))

    assert message == "上游请求失败——请稍后重试或到诊断中心查看详情"
    assert "sk-live-secret" not in message
    assert "private.txt" not in message


def test_generic_upstream_4xx_does_not_echo_response_body() -> None:
    raw_body = '<html>invalid api_key="sk-live-secret" at /srv/provider.py</html>'

    message = friendly_status(422, raw_body)

    assert message == "上游拒绝了请求（422）——请检查请求参数或模型配置"
    assert "sk-live-secret" not in message
    assert "/srv/provider.py" not in message


def test_known_network_error_keeps_actionable_sanitized_message() -> None:
    message = friendly_error(ConnectionError("connection refused at 127.0.0.1:9999"))

    assert message == "连不上上游服务——网络不通或需要代理"
    assert "127.0.0.1" not in message


def test_gateway_provider_error_mapper_never_echoes_adapter_detail() -> None:
    exposed = "Bearer sk-live-secret C:\\Users\\owner\\private.txt"

    error = _public_provider_http_error(ProviderError(exposed, status_code=502))

    assert error.status_code == 502
    assert error.detail == friendly_status(502)
    assert error.headers == {"Cache-Control": "no-store"}
    assert "sk-live-secret" not in str(error.detail)
    assert "private.txt" not in str(error.detail)


def test_gateway_provider_error_mapper_clamps_invalid_http_status() -> None:
    error = ProviderError("raw upstream detail", status_code=200)

    mapped = _public_provider_http_error(error)

    assert mapped.status_code == 502
    assert mapped.detail == friendly_status(502)


def test_stream_terminal_never_echoes_provider_owned_error_text() -> None:
    secret = "sk-live-stream-secret https://internal-provider.invalid"

    terminal = _public_provider_stream_error(
        ProviderError(secret, status_code=502)
    )

    assert terminal["error"]["message"] == friendly_status(502)
    assert terminal["error"]["status_code"] == 502
    assert secret not in str(terminal)


def test_unknown_submission_stream_terminal_is_actionable_but_sanitized() -> None:
    terminal = _public_provider_stream_error(
        ProviderSubmissionOutcomeUnknown(
            "Bearer sk-live-unknown secret upstream body",
            status_code=503,
        )
    )

    assert terminal["error"] == {
        "message": "上游可能已接收请求但结果未知，请勿自动重试",
        "type": "provider_error",
        "status_code": 503,
    }
    assert "sk-live-unknown" not in str(terminal)
