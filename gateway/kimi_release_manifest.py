"""Strict, proxy-independent fetch of the official Kimi Code release manifest."""

from __future__ import annotations

import re

import httpx

from gateway.subscription_cli_config import KimiManifestFetchResult


_ORIGIN = re.compile(
    r"^https://code\.kimi\.com/kimi-code/binaries/"
    r"([0-9]+)\.([0-9]+)\.([0-9]+)/manifest\.json$"
)
_MAX_MANIFEST_BYTES = 64 * 1024
_HEADERS = {
    "Accept": "application/json",
    "Accept-Encoding": "identity",
    "User-Agent": "Nachuan-Kimi-Manifest/1",
}


class KimiManifestFetchError(RuntimeError):
    """The official manifest could not be fetched through the closed HTTPS chain."""


def _read_bounded_manifest(response: httpx.Response) -> bytes:
    if response.status_code != 200:
        raise KimiManifestFetchError(
            f"Kimi official manifest returned unexpected status {response.status_code}"
        )
    content_encoding = response.headers.get("Content-Encoding", "").strip().lower()
    if content_encoding not in {"", "identity"}:
        raise KimiManifestFetchError(
            "Kimi official manifest response has an unsupported encoding"
        )
    if response.headers.get("Transfer-Encoding"):
        raise KimiManifestFetchError(
            "Kimi official manifest response has ambiguous transfer framing"
        )
    raw_length = response.headers.get("Content-Length", "").strip()
    if not re.fullmatch(r"[0-9]+", raw_length):
        raise KimiManifestFetchError(
            "Kimi official manifest response length is missing or invalid"
        )
    content_length = int(raw_length)
    if content_length <= 0 or content_length > _MAX_MANIFEST_BYTES:
        raise KimiManifestFetchError(
            "Kimi official manifest response length is outside the accepted bound"
        )

    body = bytearray()
    try:
        for chunk in response.iter_raw():
            body.extend(chunk)
            if len(body) > content_length or len(body) > _MAX_MANIFEST_BYTES:
                raise KimiManifestFetchError(
                    "Kimi official manifest response exceeded its declared length"
                )
    except KimiManifestFetchError:
        raise
    except (httpx.HTTPError, OSError) as exc:
        raise KimiManifestFetchError(
            "Kimi official manifest response could not be read"
        ) from exc
    if len(body) != content_length:
        raise KimiManifestFetchError(
            "Kimi official manifest response length does not match its body"
        )
    return bytes(body)


def fetch_kimi_official_manifest(
    url: str,
    *,
    transport: httpx.BaseTransport | None = None,
) -> KimiManifestFetchResult:
    """Fetch one exact release manifest without ambient proxy or hidden redirects."""

    match = _ORIGIN.fullmatch(str(url or ""))
    if match is None:
        raise KimiManifestFetchError("Kimi official manifest URL is not canonical")
    version = ".".join(match.groups())
    cdn_url = (
        "https://cdn.kimi.com/"
        f"kimi-code/binaries/{version}/manifest.json"
    )
    timeout = httpx.Timeout(10.0, connect=10.0, read=10.0, write=10.0, pool=5.0)
    limits = httpx.Limits(
        max_connections=1,
        max_keepalive_connections=0,
        keepalive_expiry=0.0,
    )
    try:
        with httpx.Client(
            transport=transport,
            follow_redirects=False,
            trust_env=False,
            http2=False,
            timeout=timeout,
            limits=limits,
            headers=dict(_HEADERS),
        ) as client:
            with client.stream("GET", url) as origin_response:
                if origin_response.status_code == 200:
                    body = _read_bounded_manifest(origin_response)
                    return KimiManifestFetchResult(
                        body=body,
                        final_url=url,
                        redirect_count=0,
                    )
                if origin_response.status_code != 302:
                    raise KimiManifestFetchError(
                        "Kimi official manifest returned unexpected status "
                        f"{origin_response.status_code}"
                    )
                location = origin_response.headers.get("Location", "")
                if location != cdn_url:
                    raise KimiManifestFetchError(
                        "Kimi official manifest redirect is not the canonical CDN URL"
                    )

            with client.stream("GET", cdn_url) as cdn_response:
                body = _read_bounded_manifest(cdn_response)
                return KimiManifestFetchResult(
                    body=body,
                    final_url=cdn_url,
                    redirect_count=1,
                )
    except KimiManifestFetchError:
        raise
    except (httpx.HTTPError, OSError) as exc:
        raise KimiManifestFetchError(
            "Kimi official manifest HTTPS request failed"
        ) from exc


__all__ = [
    "KimiManifestFetchError",
    "fetch_kimi_official_manifest",
]
