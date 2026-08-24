"""Test-only launcher for a real local Nachuan Web/Gateway E2E run.

This entry point is deliberately separate from the product CLI.  It disables
the two automatic network/download paths needed by the browser acceptance
harness, then delegates to the real ``nachuan start`` implementation.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
import sys
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import TextIO


_BANNER = (
    "=== TEST-ONLY ZERO-NETWORK: local Web/Gateway E2E; "
    "no web search, no model auto-download ===\n"
)
_DATA_DIR_FLAG = "--data-dir"
_DATA_DIR_MARKER = ".nachuan-zero-network-e2e"
_USAGE_ERROR = 64


class ZeroNetworkViolation(OSError):
    """A non-loopback network operation escaped the test-only boundary."""


class TestDataDirViolation(ValueError):
    """The test launcher was not given a safely isolated data directory."""


def _prepare_test_data_dir(argv: Sequence[str]) -> list[str]:
    """Consume one required test-only data directory and return CLI arguments.

    A non-empty directory is accepted only after this launcher has marked it.
    This prevents a typo or missing environment variable from mutating the
    operator's real Nachuan connections, conversations, or paid-media ledger.
    """

    forwarded: list[str] = []
    configured: str | None = None
    index = 0
    while index < len(argv):
        token = str(argv[index])
        if token == _DATA_DIR_FLAG:
            if configured is not None or index + 1 >= len(argv):
                raise TestDataDirViolation(
                    "测试启动器必须且只能提供一次 --data-dir <独立目录>"
                )
            configured = str(argv[index + 1]).strip()
            index += 2
            continue
        if token.startswith(f"{_DATA_DIR_FLAG}="):
            if configured is not None:
                raise TestDataDirViolation(
                    "测试启动器必须且只能提供一次 --data-dir <独立目录>"
                )
            configured = token.partition("=")[2].strip()
            index += 1
            continue
        forwarded.append(token)
        index += 1

    if not configured:
        raise TestDataDirViolation(
            "测试启动器拒绝使用默认数据目录；请提供 --data-dir <独立目录>"
        )

    data_dir = Path(configured).expanduser().resolve()
    if data_dir.exists() and not data_dir.is_dir():
        raise TestDataDirViolation("--data-dir 必须指向目录")
    data_dir.mkdir(parents=True, exist_ok=True)
    marker = data_dir / _DATA_DIR_MARKER
    existing = [entry for entry in data_dir.iterdir() if entry != marker]
    if existing and not marker.is_file():
        raise TestDataDirViolation(
            "--data-dir 已含文件且不是本启动器创建的测试目录，已拒绝启动"
        )
    if not marker.exists():
        marker.write_text("nachuan.zero-network-e2e-data/v1\n", encoding="utf-8")
    os.environ["DATA_DIR"] = str(data_dir)
    return forwarded


def _loopback_host(host: object) -> bool:
    if isinstance(host, bytes):
        try:
            host = host.decode("ascii", "strict")
        except UnicodeError:
            return False
    if not isinstance(host, str):
        return False
    normalized = host.strip().rstrip(".").casefold()
    if normalized == "localhost":
        return True
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv4Address):
        return address.is_loopback
    return address == ipaddress.IPv6Address("::1")


def _reject_external(host: object) -> None:
    if not _loopback_host(host):
        raise ZeroNetworkViolation(
            f"TEST-ONLY ZERO-NETWORK blocked outbound host: {host!r}"
        )


@contextmanager
def _loopback_only_sockets() -> Iterator[None]:
    """Confine this process to loopback for the lifetime of the real Engine."""

    original_getaddrinfo = socket.getaddrinfo
    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex

    def guarded_getaddrinfo(host, *args, **kwargs):  # noqa: ANN001
        # ``None``/empty host is a local passive-resolution form used by some
        # server libraries. Any later outbound connect is still checked below.
        if host not in (None, "", b""):
            _reject_external(host)
        results = original_getaddrinfo(host, *args, **kwargs)
        if host in (None, "", b""):
            return results
        for family, _socktype, _proto, _canonname, sockaddr in results:
            if family in {socket.AF_INET, socket.AF_INET6}:
                try:
                    resolved_host = sockaddr[0]
                except (IndexError, TypeError) as exc:
                    raise ZeroNetworkViolation(
                        "TEST-ONLY ZERO-NETWORK received an invalid DNS address"
                    ) from exc
                _reject_external(resolved_host)
        return results

    def guarded_connect(client: socket.socket, address) -> object:  # noqa: ANN001
        if client.family in {socket.AF_INET, socket.AF_INET6}:
            try:
                host = address[0]
            except (IndexError, TypeError) as exc:
                raise ZeroNetworkViolation(
                    "TEST-ONLY ZERO-NETWORK received an invalid socket address"
                ) from exc
            _reject_external(host)
        return original_connect(client, address)

    def guarded_connect_ex(client: socket.socket, address) -> int:  # noqa: ANN001
        if client.family in {socket.AF_INET, socket.AF_INET6}:
            try:
                host = address[0]
            except (IndexError, TypeError) as exc:
                raise ZeroNetworkViolation(
                    "TEST-ONLY ZERO-NETWORK received an invalid socket address"
                ) from exc
            _reject_external(host)
        return original_connect_ex(client, address)

    socket.getaddrinfo = guarded_getaddrinfo
    socket.socket.connect = guarded_connect
    socket.socket.connect_ex = guarded_connect_ex
    try:
        yield
    finally:
        socket.getaddrinfo = original_getaddrinfo
        socket.socket.connect = original_connect
        socket.socket.connect_ex = original_connect_ex


async def _disabled_web_search(*_args: object, **_kwargs: object) -> int:
    """Return the public no-results contract without opening a socket."""

    await asyncio.sleep(0)
    return 0


@contextmanager
def _installed_zero_network_guards() -> Iterator[None]:
    """Scope test-only guards to the delegated CLI lifetime.

    The standalone launcher normally exits when ``nachuan run`` returns, but
    unit tests and embedded callers share a process.  Restoring both the module
    function and environment prevents a completed zero-network run from
    disabling later, unrelated requests in that process.
    """

    missing = object()
    previous_autodownload: object = os.environ.get("LOCAL_MODEL_AUTODOWNLOAD", missing)
    previous_embedding: object = os.environ.get("NACHUAN_EMBED_DISABLED", missing)
    from gateway import websearch

    previous_search = websearch.maybe_augment_request
    os.environ["LOCAL_MODEL_AUTODOWNLOAD"] = "0"
    os.environ["NACHUAN_EMBED_DISABLED"] = "1"
    # gateway.app imports this module object (``from gateway import websearch``),
    # so replacing the attribute also covers an app module imported earlier in
    # the same process; there is no copied function alias to patch separately.
    websearch.maybe_augment_request = _disabled_web_search
    try:
        yield
    finally:
        websearch.maybe_augment_request = previous_search
        for name, previous in (
            ("LOCAL_MODEL_AUTODOWNLOAD", previous_autodownload),
            ("NACHUAN_EMBED_DISABLED", previous_embedding),
        ):
            if previous is missing:
                os.environ.pop(name, None)
            else:
                os.environ[name] = str(previous)


def main(
    argv: Sequence[str] | None = None,
    *,
    out: TextIO | None = None,
    err: TextIO | None = None,
) -> int:
    """Install the E2E guards and enter the real ``nachuan start`` command."""

    output = sys.stdout if out is None else out
    error = sys.stderr if err is None else err
    try:
        forwarded = _prepare_test_data_dir(sys.argv[1:] if argv is None else argv)
    except TestDataDirViolation as exc:
        error.write(f"{exc}\n")
        error.flush()
        return _USAGE_ERROR
    with _installed_zero_network_guards(), _loopback_only_sockets():
        from cli import nachuan

        output.write(_BANNER)
        output.flush()
        return nachuan.run(["start", *forwarded], out=output, err=error)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
