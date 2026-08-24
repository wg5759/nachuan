from __future__ import annotations

import httpx
import pytest

import gateway.kimi_release_manifest as release_manifest
from gateway.kimi_release_manifest import (
    KimiManifestFetchError,
    fetch_kimi_official_manifest,
)


VERSION = "0.27.0"
ORIGIN = (
    "https://code.kimi.com/"
    f"kimi-code/binaries/{VERSION}/manifest.json"
)
CDN = (
    "https://cdn.kimi.com/"
    f"kimi-code/binaries/{VERSION}/manifest.json"
)
BODY = b'{"version":"0.27.0","tag":"fixture","platforms":{}}'


def _json_response(request: httpx.Request, body: bytes = BODY) -> httpx.Response:
    return httpx.Response(
        200,
        headers={
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
        },
        stream=httpx.ByteStream(body),
        request=request,
    )


def test_fetcher_exposes_the_one_official_redirect_and_reads_bounded_raw_body(
    monkeypatch,
) -> None:
    requests: list[httpx.Request] = []
    client_options: list[dict[str, object]] = []
    real_client = httpx.Client

    def client_spy(*args, **kwargs):
        client_options.append(dict(kwargs))
        return real_client(*args, **kwargs)

    monkeypatch.setattr(release_manifest.httpx, "Client", client_spy)

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if str(request.url) == ORIGIN:
            return httpx.Response(
                302,
                headers={"Location": CDN, "Content-Length": "0"},
                request=request,
            )
        assert str(request.url) == CDN
        return _json_response(request)

    result = fetch_kimi_official_manifest(
        ORIGIN,
        transport=httpx.MockTransport(handler),
    )

    assert result.body == BODY
    assert result.final_url == CDN
    assert result.redirect_count == 1
    assert [str(request.url) for request in requests] == [ORIGIN, CDN]
    assert client_options == [
        {
            "transport": client_options[0]["transport"],
            "follow_redirects": False,
            "trust_env": False,
            "http2": False,
            "timeout": client_options[0]["timeout"],
            "limits": client_options[0]["limits"],
            "headers": {
                "Accept": "application/json",
                "Accept-Encoding": "identity",
                "User-Agent": "Nachuan-Kimi-Manifest/1",
            },
        }
    ]
    assert all(request.headers["accept-encoding"] == "identity" for request in requests)
    assert all("authorization" not in request.headers for request in requests)
    assert all("cookie" not in request.headers for request in requests)


@pytest.mark.parametrize(
    "location",
    [
        "http://cdn.kimi.com/kimi-code/binaries/0.27.0/manifest.json",
        "https://evil.example/kimi-code/binaries/0.27.0/manifest.json",
        "https://cdn.kimi.com/kimi-code/binaries/0.27.1/manifest.json",
        "https://cdn.kimi.com:443/kimi-code/binaries/0.27.0/manifest.json",
        "https://user@cdn.kimi.com/kimi-code/binaries/0.27.0/manifest.json",
        "https://cdn.kimi.com/kimi-code/binaries/0.27.0/manifest.json?x=1",
        "https://cdn.kimi.com/kimi-code/binaries/0.27.0/manifest.json#x",
    ],
)
def test_fetcher_rejects_any_noncanonical_redirect_without_following(
    location: str,
) -> None:
    requests: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(str(request.url))
        return httpx.Response(
            302,
            headers={"Location": location, "Content-Length": "0"},
            request=request,
        )

    with pytest.raises(KimiManifestFetchError, match="redirect"):
        fetch_kimi_official_manifest(
            ORIGIN,
            transport=httpx.MockTransport(handler),
        )

    assert requests == [ORIGIN]


def test_fetcher_rejects_a_second_redirect() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            302,
            headers={"Location": CDN, "Content-Length": "0"},
            request=request,
        )

    with pytest.raises(KimiManifestFetchError, match="status"):
        fetch_kimi_official_manifest(
            ORIGIN,
            transport=httpx.MockTransport(handler),
        )


@pytest.mark.parametrize(
    "headers,body,message",
    [
        ({"Content-Length": "0"}, b"", "length"),
        ({}, BODY, "length"),
        ({"Content-Length": "999999"}, BODY, "length"),
        ({"Content-Length": str(len(BODY) + 1)}, BODY, "length"),
        (
            {
                "Content-Length": str(len(BODY)),
                "Content-Encoding": "gzip",
            },
            BODY,
            "encoding",
        ),
        (
            {
                "Content-Length": str(len(BODY)),
                "Transfer-Encoding": "chunked",
            },
            BODY,
            "transfer",
        ),
    ],
)
def test_fetcher_rejects_ambiguous_or_unbounded_manifest_responses(
    headers: dict[str, str],
    body: bytes,
    message: str,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers=headers,
            stream=httpx.ByteStream(body),
            request=request,
        )

    with pytest.raises(KimiManifestFetchError, match=message):
        fetch_kimi_official_manifest(
            ORIGIN,
            transport=httpx.MockTransport(handler),
        )


@pytest.mark.parametrize(
    "url",
    [
        "https://code.kimi.com/kimi-code/binaries/latest/manifest.json",
        "http://code.kimi.com/kimi-code/binaries/0.27.0/manifest.json",
        "https://code.kimi.com:443/kimi-code/binaries/0.27.0/manifest.json",
        "https://code.kimi.com/kimi-code/binaries/0.27.0/manifest.json?x=1",
    ],
)
def test_fetcher_rejects_noncanonical_origin_url_before_network(url: str) -> None:
    transport = httpx.MockTransport(
        lambda request: pytest.fail(f"unexpected network request: {request.url}")
    )

    with pytest.raises(KimiManifestFetchError, match="URL"):
        fetch_kimi_official_manifest(url, transport=transport)
