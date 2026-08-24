"""Pinned public-HTTP fetches for untrusted media and document URLs.

The security boundary is stronger than a DNS pre-check: every request hop resolves
all addresses, rejects the whole answer set if any address is non-public, and then
connects the socket to one of those exact validated addresses.  HTTPS still uses
the original hostname for SNI and certificate verification.
"""

from __future__ import annotations

import codecs
import http.client
import ipaddress
import os
import queue
import re
import socket
import ssl
import tempfile
import threading
import time
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, Sequence
from urllib.parse import SplitResult, quote, urljoin, urlsplit, urlunsplit


_LOCAL_HOST = re.compile(r"(?:^|\.)(?:localhost|local|internal|home|lan)$", re.I)
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_DNS_SLOTS = threading.BoundedSemaphore(8)
_HTTP_SLOTS = threading.BoundedSemaphore(16)
_READ_CHUNK_BYTES = 64 * 1024
_MAX_URL_LENGTH = 8192
_SAFE_CALLER_HEADERS = frozenset({"accept", "accept-language", "user-agent"})
_CHARSET = re.compile(r"(?:^|;)\s*charset\s*=\s*[\"']?([^;\"'\s]+)", re.I)
_TEXT_ENCODINGS = frozenset(
    {
        "utf-8",
        "utf-16",
        "utf-16-le",
        "utf-16-be",
        "gb18030",
        "gbk",
        "gb2312",
        "big5",
        "latin-1",
        "cp1252",
        "shift_jis",
        "euc_jp",
        "euc_kr",
    }
)


class PublicFetchError(RuntimeError):
    """Base class for controlled public-fetch failures."""


class PublicFetchSecurityError(PublicFetchError):
    """The URL, DNS answer, or redirect violates the public-network policy."""


class PublicFetchTimeout(PublicFetchError):
    """The single wall-clock deadline or per-read idle deadline expired."""


class PublicFetchTooLarge(PublicFetchError):
    """The declared or streamed response exceeded the configured byte cap."""


class PublicFetchContentTypeError(PublicFetchError):
    """The response Content-Type is missing or outside the caller's allowlist."""


class PublicFetchHTTPError(PublicFetchError):
    """The remote server returned an unusable HTTP response."""

    def __init__(self, status: int, reason: str = "") -> None:
        super().__init__(f"remote HTTP status {status}{': ' + reason if reason else ''}")
        self.status = status


class PublicFetchNetworkError(PublicFetchError):
    """Every validated address failed at the network or HTTP protocol layer."""


@dataclass(frozen=True)
class PinnedTarget:
    scheme: str
    hostname: str
    port: int
    ip: str


@dataclass(frozen=True)
class PublicBytesResult:
    data: bytes
    content_type: str
    final_url: str
    size: int
    headers: Mapping[str, str]


@dataclass(frozen=True)
class PublicFileResult:
    path: str
    content_type: str
    final_url: str
    size: int
    headers: Mapping[str, str]


@dataclass(frozen=True)
class PublicTextResult:
    text: str
    encoding: str
    content_type: str
    final_url: str
    size: int
    headers: Mapping[str, str]


class _Connection(Protocol):
    sock: Any

    def request(self, method: str, url: str, **kwargs: Any) -> None: ...

    def getresponse(self) -> Any: ...

    def close(self) -> None: ...


Resolver = Callable[..., Sequence[Any]]
ConnectionFactory = Callable[[PinnedTarget, float], _Connection]
Clock = Callable[[], float]
URLGuard = Callable[[str], bool]


def _is_public_ip(raw: str) -> bool:
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return False
    return bool(ip.is_global) and not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _remaining(deadline: float, clock: Clock) -> float:
    remaining = deadline - clock()
    if remaining <= 0:
        raise PublicFetchTimeout("public fetch exceeded its wall-clock deadline")
    return remaining


def _canonical_url(url: str) -> tuple[str, SplitResult, str, int]:
    if not isinstance(url, str) or not url or len(url) > _MAX_URL_LENGTH:
        raise PublicFetchSecurityError("URL is empty or too long")
    try:
        parsed = urlsplit(url)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise PublicFetchSecurityError("only public http/https URLs are allowed")
        if parsed.username is not None or parsed.password is not None:
            raise PublicFetchSecurityError("URL credentials are not allowed")
        if "\\" in parsed.netloc:
            raise PublicFetchSecurityError("URL authority contains a backslash")
        if parsed.fragment:
            parsed = parsed._replace(fragment="")
        scheme = parsed.scheme.lower()
        raw_host = parsed.hostname.rstrip(".")
        if not raw_host:
            raise PublicFetchSecurityError("URL hostname is empty")
        try:
            literal = ipaddress.ip_address(raw_host.split("%", 1)[0])
        except ValueError:
            # Reject packed/octal numeric spellings.  DNS names must contain a
            # letter after IDNA canonicalisation.
            hostname = raw_host.encode("idna").decode("ascii").lower()
            if not re.search(r"[a-z]", hostname, re.I) or _LOCAL_HOST.search(hostname):
                raise PublicFetchSecurityError("local or numeric hostname is not allowed")
        else:
            if "%" in raw_host or not _is_public_ip(str(literal)):
                raise PublicFetchSecurityError("non-public IP literal is not allowed")
            hostname = str(literal)
        port = parsed.port or (443 if scheme == "https" else 80)
        expected_port = 443 if scheme == "https" else 80
        if port != expected_port:
            raise PublicFetchSecurityError("URL port does not match the standard scheme port")
        path = parsed.path or "/"
        query = parsed.query
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in path + query):
            raise PublicFetchSecurityError("URL path contains control characters")
        # http.client accepts an ASCII request target.  Encode valid Unicode
        # paths deterministically instead of leaking UnicodeEncodeError as a 500.
        path = quote(path, safe="/%:@-._~!$&'()*+,;=")
        query = quote(query, safe="=&%:@/?-._~!$'()*+,;")
        netloc_host = f"[{hostname}]" if ":" in hostname else hostname
        default_port = 443 if scheme == "https" else 80
        netloc = netloc_host if port == default_port else f"{netloc_host}:{port}"
        canonical = urlunsplit((scheme, netloc, path, query, ""))
        return canonical, urlsplit(canonical), hostname, port
    except PublicFetchSecurityError:
        raise
    except (UnicodeError, ValueError) as exc:
        raise PublicFetchSecurityError("malformed URL") from exc


def _resolve_public(
    hostname: str,
    port: int,
    *,
    resolver: Resolver,
    deadline: float,
    clock: Clock,
) -> tuple[str, ...]:
    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        address = str(literal)
        if not _is_public_ip(address):
            raise PublicFetchSecurityError("DNS target is not public")
        return (address,)

    try:
        remaining = _remaining(deadline, clock)
    except PublicFetchTimeout as exc:
        raise PublicFetchTimeout("public DNS lookup exceeded the wall-clock deadline") from exc
    if not _DNS_SLOTS.acquire(timeout=remaining):
        raise PublicFetchTimeout("public DNS resolver capacity timed out")
    result_queue: queue.Queue[tuple[bool, Any]] = queue.Queue(maxsize=1)

    def _resolve() -> None:
        try:
            answers = resolver(
                hostname,
                port,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
                proto=socket.IPPROTO_TCP,
            )
            result_queue.put((True, answers))
        except BaseException as exc:  # noqa: BLE001 - transfer exact resolver failure
            result_queue.put((False, exc))
        finally:
            _DNS_SLOTS.release()

    threading.Thread(
        target=_resolve,
        name="nachuan-public-dns",
        daemon=True,
    ).start()
    try:
        try:
            dns_remaining = _remaining(deadline, clock)
        except PublicFetchTimeout as exc:
            raise PublicFetchTimeout(
                "public DNS lookup exceeded the wall-clock deadline"
            ) from exc
        ok, value = result_queue.get(timeout=dns_remaining)
    except queue.Empty as exc:
        raise PublicFetchTimeout("public DNS lookup exceeded the wall-clock deadline") from exc
    try:
        _remaining(deadline, clock)
    except PublicFetchTimeout as exc:
        raise PublicFetchTimeout("public DNS lookup exceeded the wall-clock deadline") from exc
    if not ok:
        raise PublicFetchNetworkError("public DNS lookup failed") from value

    addresses: list[str] = []
    for answer in value:
        try:
            raw = str(answer[4][0]).split("%", 1)[0]
            address = str(ipaddress.ip_address(raw))
        except (IndexError, TypeError, ValueError) as exc:
            raise PublicFetchSecurityError("DNS returned a malformed address") from exc
        if not _is_public_ip(address):
            # Reject the complete mixed answer set.  Selecting only its public
            # member would leave resolver rebinding and split-horizon ambiguity.
            raise PublicFetchSecurityError("DNS answer contains a non-public address")
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise PublicFetchNetworkError("public DNS lookup returned no addresses")
    return tuple(addresses)


def _open_pinned_socket(connection: http.client.HTTPConnection, target: PinnedTarget) -> None:
    connection.sock = connection._create_connection(  # noqa: SLF001 - stdlib extension seam
        (target.ip, target.port),
        connection.timeout,
        connection.source_address,
    )
    try:
        connection.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, target: PinnedTarget, timeout: float) -> None:
        super().__init__(target.hostname, target.port, timeout=timeout)
        self._pinned_target = target

    def connect(self) -> None:
        _open_pinned_socket(self, self._pinned_target)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, target: PinnedTarget, timeout: float) -> None:
        super().__init__(
            target.hostname,
            target.port,
            timeout=timeout,
            context=ssl.create_default_context(),
        )
        self._pinned_target = target

    def connect(self) -> None:
        # Connect to the validated IP, but deliberately keep the original DNS
        # hostname for both SNI and hostname/certificate verification.
        _open_pinned_socket(self, self._pinned_target)
        self.sock = self._context.wrap_socket(  # noqa: SLF001 - HTTPSConnection contract
            self.sock,
            server_hostname=self._pinned_target.hostname,
        )


def _default_connection_factory(target: PinnedTarget, timeout: float) -> _Connection:
    if target.scheme == "https":
        return _PinnedHTTPSConnection(target, timeout)
    return _PinnedHTTPConnection(target, timeout)


def _deadline_call(
    func: Callable[[], Any],
    *,
    deadline: float,
    clock: Clock,
    on_timeout: Callable[[], None] | None = None,
) -> Any:
    """Bound connect/request/header parsing even if a peer slow-drips lines."""

    try:
        slot_wait = _remaining(deadline, clock)
    except PublicFetchTimeout as exc:
        raise PublicFetchTimeout("public HTTP operation exceeded the wall-clock deadline") from exc
    if not _HTTP_SLOTS.acquire(timeout=slot_wait):
        raise PublicFetchTimeout("public HTTP operation capacity timed out")
    result_queue: queue.Queue[tuple[bool, Any]] = queue.Queue(maxsize=1)

    def _call() -> None:
        try:
            result_queue.put((True, func()))
        except BaseException as exc:  # noqa: BLE001 - transfer exact network failure
            result_queue.put((False, exc))
        finally:
            _HTTP_SLOTS.release()

    try:
        threading.Thread(target=_call, name="nachuan-public-http", daemon=True).start()
    except BaseException:
        _HTTP_SLOTS.release()
        raise
    try:
        try:
            operation_remaining = _remaining(deadline, clock)
        except PublicFetchTimeout as exc:
            if on_timeout is not None:
                try:
                    on_timeout()
                except Exception:  # noqa: BLE001 - timeout remains authoritative
                    pass
            raise PublicFetchTimeout(
                "public HTTP operation exceeded the wall-clock deadline"
            ) from exc
        ok, value = result_queue.get(timeout=operation_remaining)
    except queue.Empty as exc:
        if on_timeout is not None:
            try:
                on_timeout()
            except Exception:  # noqa: BLE001 - timeout remains authoritative
                pass
        raise PublicFetchTimeout("public HTTP operation exceeded the wall-clock deadline") from exc
    _remaining(deadline, clock)
    if not ok:
        raise value
    return value


def _set_socket_timeout(connection: _Connection, response: Any, timeout: float) -> None:
    candidates = [getattr(connection, "sock", None)]
    fp = getattr(response, "fp", None)
    candidates.append(getattr(getattr(fp, "raw", None), "_sock", None))
    for candidate in candidates:
        if candidate is not None:
            candidate.settimeout(timeout)
            return


def _request_target(parsed: SplitResult) -> str:
    return urlunsplit(("", "", parsed.path or "/", parsed.query, ""))


def _host_header(hostname: str, scheme: str, port: int) -> str:
    host = f"[{hostname}]" if ":" in hostname else hostname
    default_port = 443 if scheme == "https" else 80
    return host if port == default_port else f"{host}:{port}"


def _normalise_headers(headers: Mapping[str, str] | None) -> dict[str, str]:
    result = {
        "User-Agent": "Nachuan-PinnedFetcher/1.0",
        "Accept-Encoding": "identity",
        "Connection": "close",
    }
    for name, value in (headers or {}).items():
        key = str(name).strip()
        val = str(value).strip()
        if not key or "\r" in key or "\n" in key or "\r" in val or "\n" in val:
            raise PublicFetchSecurityError("invalid public fetch header")
        # This primitive follows untrusted cross-origin redirects.  A positive
        # allowlist prevents ambient bearer/cookie/proxy credentials (and custom
        # secret headers) from being forwarded to a redirect-selected host.
        if key.lower() not in _SAFE_CALLER_HEADERS:
            raise PublicFetchSecurityError(
                "public fetch header is not in the credential-free allowlist"
            )
        try:
            key.encode("ascii")
            val.encode("latin-1")
        except UnicodeError as exc:
            raise PublicFetchSecurityError("public fetch header is not HTTP encodable") from exc
        result[key] = val
    return result


@dataclass(frozen=True)
class _FetchMetadata:
    content_type: str
    final_url: str
    size: int
    headers: Mapping[str, str]


def _fetch_into(
    url: str,
    write: Callable[[bytes], Any],
    *,
    max_bytes: int,
    allowed_type_prefixes: tuple[str, ...],
    allowed_exact_types: tuple[str, ...],
    total_timeout: float,
    idle_timeout: float,
    max_redirects: int,
    headers: Mapping[str, str] | None,
    method: str,
    request_body: bytes | None,
    request_content_type: str,
    require_content_type: bool,
    url_guard: URLGuard | None,
    resolver: Resolver,
    connection_factory: ConnectionFactory,
    clock: Clock,
    utf8_identity_url_guard: URLGuard | None = None,
) -> _FetchMetadata:
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    if total_timeout <= 0 or idle_timeout <= 0:
        raise ValueError("timeouts must be positive")
    if max_redirects < 0 or max_redirects > 20:
        raise ValueError("max_redirects is outside the safe range")
    if require_content_type and not allowed_type_prefixes and not allowed_exact_types:
        raise ValueError("an explicit Content-Type allowlist is required")
    method = str(method or "").upper()
    if method not in {"GET", "POST"}:
        raise ValueError("public fetch method must be GET or POST")
    if method == "GET" and request_body is not None:
        raise ValueError("GET public fetch cannot carry a request body")
    if request_content_type:
        try:
            request_content_type.encode("ascii")
        except UnicodeError as exc:
            raise PublicFetchSecurityError("request Content-Type is not ASCII") from exc
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in request_content_type):
            raise PublicFetchSecurityError("request Content-Type contains controls")

    deadline = clock() + float(total_timeout)
    current, parsed, hostname, port = _canonical_url(url)

    def _check_url_guard(candidate: str) -> None:
        if url_guard is None:
            return
        try:
            allowed = bool(url_guard(candidate))
        except Exception as exc:  # noqa: BLE001 - guard failure must fail closed
            raise PublicFetchSecurityError("public URL guard failed") from exc
        if not allowed:
            raise PublicFetchSecurityError("public URL is outside the caller's host policy")

    _check_url_guard(current)
    request_headers = _normalise_headers(headers)
    if request_body is not None and request_content_type:
        request_headers["Content-Type"] = request_content_type
    redirects = 0

    while True:
        addresses = _resolve_public(
            hostname,
            port,
            resolver=resolver,
            deadline=deadline,
            clock=clock,
        )
        response = None
        connection: _Connection | None = None
        last_error: BaseException | None = None
        for address in addresses:
            target = PinnedTarget(parsed.scheme, hostname, port, address)
            connection = connection_factory(
                target,
                min(float(idle_timeout), _remaining(deadline, clock)),
            )
            hop_headers = dict(request_headers)
            hop_headers["Host"] = _host_header(hostname, parsed.scheme, port)
            try:
                _deadline_call(
                    lambda: connection.request(
                        method,
                        _request_target(parsed),
                        body=request_body,
                        headers=hop_headers,
                    ),
                    deadline=deadline,
                    clock=clock,
                    on_timeout=connection.close,
                )
                response = _deadline_call(
                    connection.getresponse,
                    deadline=deadline,
                    clock=clock,
                    on_timeout=connection.close,
                )
                break
            except PublicFetchTimeout:
                connection.close()
                raise
            except (UnicodeError, http.client.InvalidURL) as exc:
                connection.close()
                raise PublicFetchSecurityError("URL cannot be encoded as a safe HTTP request") from exc
            except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
                last_error = exc
                connection.close()
                connection = None
        if response is None or connection is None:
            raise PublicFetchNetworkError("all validated addresses failed") from last_error

        try:
            status = int(response.status)
            if status in _REDIRECT_STATUSES:
                if method != "GET":
                    raise PublicFetchSecurityError(
                        "redirecting a public request body is not allowed"
                    )
                location = str(response.getheader("Location") or "").strip()
                if not location:
                    raise PublicFetchHTTPError(status, "redirect is missing Location")
                if redirects >= max_redirects:
                    raise PublicFetchHTTPError(status, "redirect limit exceeded")
                next_url, next_parsed, next_hostname, next_port = _canonical_url(
                    urljoin(current, location)
                )
                if parsed.scheme == "https" and next_parsed.scheme != "https":
                    raise PublicFetchSecurityError("HTTPS redirect downgrade is not allowed")
                _check_url_guard(next_url)
                redirects += 1
                current, parsed, hostname, port = (
                    next_url,
                    next_parsed,
                    next_hostname,
                    next_port,
                )
                continue
            if status < 200 or status >= 300:
                raise PublicFetchHTTPError(status, str(getattr(response, "reason", "")))

            raw_content_type = str(response.getheader("Content-Type") or "").strip()
            content_type = raw_content_type.split(";", 1)[0].strip().lower()
            if require_content_type and not content_type:
                raise PublicFetchContentTypeError("remote Content-Type is not allowed")
            if content_type and (allowed_type_prefixes or allowed_exact_types) and not (
                content_type in allowed_exact_types
                or any(content_type.startswith(prefix) for prefix in allowed_type_prefixes)
            ):
                raise PublicFetchContentTypeError("remote Content-Type is not allowed")
            content_encoding = str(response.getheader("Content-Encoding") or "").strip().lower()
            if content_encoding not in {"", "identity"}:
                utf8_identity_allowed = False
                if content_encoding == "utf-8" and utf8_identity_url_guard is not None:
                    try:
                        utf8_identity_allowed = bool(
                            utf8_identity_url_guard(current)
                        )
                    except Exception as exc:  # noqa: BLE001 - policy must fail closed
                        raise PublicFetchSecurityError(
                            "UTF-8 identity URL guard failed"
                        ) from exc
                if not utf8_identity_allowed:
                    raise PublicFetchContentTypeError(
                        "encoded public responses are not allowed"
                    )

            raw_length = str(response.getheader("Content-Length") or "").strip()
            declared: int | None = None
            if raw_length:
                try:
                    declared = int(raw_length)
                except ValueError as exc:
                    raise PublicFetchHTTPError(status, "invalid Content-Length") from exc
                if declared < 0:
                    raise PublicFetchHTTPError(status, "invalid Content-Length")
                if declared > max_bytes:
                    raise PublicFetchTooLarge("declared response exceeds the byte cap")

            total = 0
            read = getattr(response, "read1", None) or response.read
            while True:
                remaining = _remaining(deadline, clock)
                try:
                    _set_socket_timeout(
                        connection,
                        response,
                        min(float(idle_timeout), remaining),
                    )
                    chunk = read(min(_READ_CHUNK_BYTES, max_bytes - total + 1))
                except (socket.timeout, TimeoutError) as exc:
                    raise PublicFetchTimeout("public response body idle timeout") from exc
                _remaining(deadline, clock)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise PublicFetchTooLarge("streamed response exceeds the byte cap")
                write(chunk)
            if declared is not None and total != declared:
                raise PublicFetchHTTPError(status, "response body length did not match Content-Length")

            response_headers = {
                str(name).lower(): str(value)
                for name, value in response.getheaders()
                if str(name).lower() not in {"set-cookie", "authorization", "proxy-authorization"}
            }
            return _FetchMetadata(
                content_type=content_type,
                final_url=current,
                size=total,
                headers=response_headers,
            )
        finally:
            try:
                response.close()
            finally:
                connection.close()


def fetch_public_bytes(
    url: str,
    *,
    max_bytes: int,
    allowed_type_prefixes: tuple[str, ...] = (),
    allowed_exact_types: tuple[str, ...] = (),
    total_timeout: float = 30.0,
    idle_timeout: float = 15.0,
    max_redirects: int = 5,
    headers: Mapping[str, str] | None = None,
    require_content_type: bool = True,
    url_guard: URLGuard | None = None,
    resolver: Resolver = socket.getaddrinfo,
    connection_factory: ConnectionFactory = _default_connection_factory,
    clock: Clock = time.monotonic,
) -> PublicBytesResult:
    """Fetch bounded bytes while pinning every connection to validated public DNS."""

    buffer = BytesIO()
    metadata = _fetch_into(
        url,
        buffer.write,
        max_bytes=max_bytes,
        allowed_type_prefixes=allowed_type_prefixes,
        allowed_exact_types=allowed_exact_types,
        total_timeout=total_timeout,
        idle_timeout=idle_timeout,
        max_redirects=max_redirects,
        headers=headers,
        method="GET",
        request_body=None,
        request_content_type="",
        require_content_type=require_content_type,
        url_guard=url_guard,
        resolver=resolver,
        connection_factory=connection_factory,
        clock=clock,
    )
    return PublicBytesResult(
        data=buffer.getvalue(),
        content_type=metadata.content_type,
        final_url=metadata.final_url,
        size=metadata.size,
        headers=metadata.headers,
    )


def fetch_public_text(
    url: str,
    *,
    max_bytes: int,
    max_chars: int,
    allowed_type_prefixes: tuple[str, ...] = (),
    allowed_exact_types: tuple[str, ...] = (),
    total_timeout: float = 30.0,
    idle_timeout: float = 15.0,
    max_redirects: int = 5,
    headers: Mapping[str, str] | None = None,
    default_encoding: str = "utf-8",
    url_guard: URLGuard | None = None,
    resolver: Resolver = socket.getaddrinfo,
    connection_factory: ConnectionFactory = _default_connection_factory,
    clock: Clock = time.monotonic,
) -> PublicTextResult:
    """Fetch bounded text, honoring only a valid declared response charset."""

    if max_chars <= 0:
        raise ValueError("max_chars must be positive")
    result = fetch_public_bytes(
        url,
        max_bytes=max_bytes,
        allowed_type_prefixes=allowed_type_prefixes,
        allowed_exact_types=allowed_exact_types,
        total_timeout=total_timeout,
        idle_timeout=idle_timeout,
        max_redirects=max_redirects,
        headers=headers,
        url_guard=url_guard,
        resolver=resolver,
        connection_factory=connection_factory,
        clock=clock,
    )
    raw_content_type = str(result.headers.get("content-type") or "")
    match = _CHARSET.search(raw_content_type)
    encoding = (match.group(1) if match else default_encoding).strip().lower()
    try:
        codec = codecs.lookup(encoding)
    except LookupError as exc:
        raise PublicFetchContentTypeError("remote response declared an invalid charset") from exc
    canonical_encoding = codec.name
    if (
        len(encoding) > 40
        or not getattr(codec, "_is_text_encoding", False)
        or canonical_encoding not in _TEXT_ENCODINGS
    ):
        raise PublicFetchContentTypeError("remote response charset is not allowed")
    try:
        decoded = result.data.decode(canonical_encoding, errors="replace")
    except (LookupError, TypeError, UnicodeError) as exc:
        raise PublicFetchContentTypeError("remote response charset could not decode text") from exc
    text = decoded[:max_chars]
    return PublicTextResult(
        text=text,
        encoding=canonical_encoding,
        content_type=result.content_type,
        final_url=result.final_url,
        size=result.size,
        headers=result.headers,
    )


def request_public_bytes(
    url: str,
    *,
    method: str,
    request_body: bytes,
    request_content_type: str,
    max_request_bytes: int,
    max_bytes: int,
    allowed_type_prefixes: tuple[str, ...] = (),
    allowed_exact_types: tuple[str, ...] = (),
    require_content_type: bool = True,
    total_timeout: float = 30.0,
    idle_timeout: float = 15.0,
    max_redirects: int = 0,
    headers: Mapping[str, str] | None = None,
    url_guard: URLGuard | None = None,
    resolver: Resolver = socket.getaddrinfo,
    connection_factory: ConnectionFactory = _default_connection_factory,
    clock: Clock = time.monotonic,
) -> PublicBytesResult:
    """Send a bounded credential-free request to a pinned public endpoint.

    Request bodies are never replayed across redirects.  This is intended for
    pre-signed public upload URLs, not authenticated APIs.
    """

    body = bytes(request_body)
    if max_request_bytes <= 0 or len(body) > max_request_bytes:
        raise PublicFetchTooLarge("public request body exceeds the byte cap")
    buffer = BytesIO()
    metadata = _fetch_into(
        url,
        buffer.write,
        max_bytes=max_bytes,
        allowed_type_prefixes=allowed_type_prefixes,
        allowed_exact_types=allowed_exact_types,
        total_timeout=total_timeout,
        idle_timeout=idle_timeout,
        max_redirects=max_redirects,
        headers=headers,
        method=method,
        request_body=body,
        request_content_type=request_content_type,
        require_content_type=require_content_type,
        url_guard=url_guard,
        resolver=resolver,
        connection_factory=connection_factory,
        clock=clock,
    )
    return PublicBytesResult(
        data=buffer.getvalue(),
        content_type=metadata.content_type,
        final_url=metadata.final_url,
        size=metadata.size,
        headers=metadata.headers,
    )


def download_public_file(
    url: str,
    *,
    max_bytes: int,
    allowed_type_prefixes: tuple[str, ...] = (),
    allowed_exact_types: tuple[str, ...] = (),
    total_timeout: float = 180.0,
    idle_timeout: float = 20.0,
    max_redirects: int = 5,
    headers: Mapping[str, str] | None = None,
    url_guard: URLGuard | None = None,
    utf8_identity_url_guard: URLGuard | None = None,
    temp_dir: str | os.PathLike[str] | None = None,
    resolver: Resolver = socket.getaddrinfo,
    connection_factory: ConnectionFactory = _default_connection_factory,
    clock: Clock = time.monotonic,
) -> PublicFileResult:
    """Download to a private temporary file and remove every failed partial."""

    directory = None if temp_dir is None else os.fspath(Path(temp_dir))
    fd, path = tempfile.mkstemp(prefix="nachuan-public-", suffix=".media", dir=directory)
    os.close(fd)
    try:
        with open(path, "wb") as output:
            metadata = _fetch_into(
                url,
                output.write,
                max_bytes=max_bytes,
                allowed_type_prefixes=allowed_type_prefixes,
                allowed_exact_types=allowed_exact_types,
                total_timeout=total_timeout,
                idle_timeout=idle_timeout,
                max_redirects=max_redirects,
                headers=headers,
                method="GET",
                request_body=None,
                request_content_type="",
                require_content_type=True,
                url_guard=url_guard,
                resolver=resolver,
                connection_factory=connection_factory,
                clock=clock,
                utf8_identity_url_guard=utf8_identity_url_guard,
            )
        return PublicFileResult(
            path=path,
            content_type=metadata.content_type,
            final_url=metadata.final_url,
            size=metadata.size,
            headers=metadata.headers,
        )
    except BaseException:
        try:
            os.remove(path)
        except OSError:
            pass
        raise
