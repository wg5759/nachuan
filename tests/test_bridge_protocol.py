from __future__ import annotations

import io
import json
import os
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import gateway.bridge_protocol as bridge_protocol
from gateway.bridge_protocol import (
    BridgePayloadTooLarge,
    BridgeProtocolError,
    BridgeProtocolMiddleware,
    BridgeReplayError,
    BridgeReplayStoreUnavailable,
    HEADER_REQUEST_NONCE,
    NonceReplayGuard,
    PersistentNonceReplayGuard,
    open_request,
    open_response,
    request_bridge_bytes,
    seal_request,
    seal_response,
)


SECRET = "sk-bridge-v2-weixin-" + "7" * 64


def test_request_and_response_round_trip_are_confidential_and_bound() -> None:
    plaintext = "微信用户说：你好，内部报价 12345".encode()
    sealed = seal_request(
        secret=SECRET,
        channel="weixin",
        method="POST",
        url_or_target="http://127.0.0.1:8080/v1/agent/chat?mode=fast",
        body=plaintext,
        timestamp=2_000_000_000,
        request_nonce="1" * 32,
        request_iv=b"\x02" * 12,
    )
    wire = sealed.body + json.dumps(sealed.headers, sort_keys=True).encode()
    assert SECRET.encode() not in wire
    assert plaintext not in wire
    assert b"Authorization" not in wire

    guard = NonceReplayGuard()
    opened = open_request(
        secret=SECRET,
        method="POST",
        target="/v1/agent/chat?mode=fast",
        headers=sealed.headers,
        body=sealed.body,
        replay_guard=guard,
        now=2_000_000_000,
    )
    assert opened.body == plaintext

    response_plaintext = b'{"reply":"authenticated"}'
    response_body, response_headers = seal_response(
        secret=SECRET,
        channel="weixin",
        request_nonce=sealed.request_nonce,
        status=200,
        body=response_plaintext,
        response_iv=b"\x03" * 12,
    )
    assert response_plaintext not in response_body
    assert open_response(
        secret=SECRET,
        channel="weixin",
        request_nonce=sealed.request_nonce,
        status=200,
        headers=response_headers,
        body=response_body,
    ) == response_plaintext
    with pytest.raises(BridgeProtocolError):
        open_response(
            secret=SECRET,
            channel="weixin",
            request_nonce=sealed.request_nonce,
            status=201,
            headers=response_headers,
            body=response_body,
        )


def test_authenticated_request_nonce_is_single_use() -> None:
    sealed = seal_request(
        secret=SECRET,
        channel="weixin",
        method="GET",
        url_or_target="/v1/bridge/health",
        body=b"",
        timestamp=2_000_000_000,
        request_nonce="a" * 32,
        request_iv=b"\x04" * 12,
    )
    guard = NonceReplayGuard()
    kwargs = {
        "secret": SECRET,
        "method": "GET",
        "target": "/v1/bridge/health",
        "headers": sealed.headers,
        "body": sealed.body,
        "replay_guard": guard,
        "now": 2_000_000_000,
    }
    assert open_request(**kwargs).body == b""
    with pytest.raises(BridgeReplayError):
        open_request(**kwargs)


def test_persistent_guard_rejects_replay_after_guard_restart(tmp_path) -> None:
    path = tmp_path / "bridge-replay.db"
    first = PersistentNonceReplayGuard(path)
    first.consume(
        "weixin",
        "c" * 32,
        now=2_000_000_000,
        valid_until=2_000_000_091,
    )
    restarted = PersistentNonceReplayGuard(path)
    with pytest.raises(BridgeReplayError, match="replay rejected"):
        restarted.consume(
            "weixin",
            "c" * 32,
            now=2_000_000_001,
            valid_until=2_000_000_091,
        )


def test_persistent_guard_wraps_post_commit_file_error_without_unconsuming_nonce(
    tmp_path, monkeypatch
) -> None:
    path = tmp_path / "bridge-replay.db"
    guard = PersistentNonceReplayGuard(path)
    original_assert_file_bounds = guard._assert_file_bounds
    checks = 0

    def fail_only_after_commit() -> None:
        nonlocal checks
        checks += 1
        if checks == 1:
            original_assert_file_bounds()
            return
        raise OSError("simulated post-commit filesystem failure")

    monkeypatch.setattr(guard, "_assert_file_bounds", fail_only_after_commit)
    with pytest.raises(BridgeReplayStoreUnavailable) as raised:
        guard.consume(
            "weixin",
            "b" * 32,
            now=2_000_000_000,
            valid_until=2_000_000_091,
        )
    assert isinstance(raised.value.__cause__, OSError)
    guard.close()

    restarted = PersistentNonceReplayGuard(path)
    with pytest.raises(BridgeReplayError, match="replay rejected"):
        restarted.consume(
            "weixin",
            "b" * 32,
            now=2_000_000_001,
            valid_until=2_000_000_091,
        )


def test_persistent_guard_concurrent_nonce_has_exactly_one_winner(tmp_path) -> None:
    path = tmp_path / "bridge-replay.db"
    guards = [PersistentNonceReplayGuard(path), PersistentNonceReplayGuard(path)]
    barrier = threading.Barrier(2)

    def consume(index: int) -> str:
        barrier.wait(timeout=5)
        try:
            guards[index].consume(
                "feishu",
                "d" * 32,
                now=2_000_000_000,
                valid_until=2_000_000_091,
            )
            return "accepted"
        except BridgeReplayError:
            return "rejected"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(consume, (0, 1)))
    assert sorted(results) == ["accepted", "rejected"]


def test_persistent_guard_full_and_unsafe_paths_fail_closed(tmp_path) -> None:
    full_path = tmp_path / "full.db"
    guard = PersistentNonceReplayGuard(full_path, max_entries=1)
    guard.consume(
        "weixin",
        "e" * 32,
        now=2_000_000_000,
        valid_until=2_000_000_091,
    )
    with pytest.raises(BridgeReplayError, match="store is full"):
        guard.consume(
            "weixin",
            "f" * 32,
            now=2_000_000_001,
            valid_until=2_000_000_091,
        )

    directory_path = tmp_path / "directory.db"
    directory_path.mkdir()
    with pytest.raises(BridgeReplayStoreUnavailable):
        PersistentNonceReplayGuard(directory_path)

    missing_parent = tmp_path / "missing" / "replay.db"
    with pytest.raises(BridgeReplayStoreUnavailable):
        PersistentNonceReplayGuard(missing_parent)
    assert not missing_parent.parent.exists()

    oversized_shm_path = tmp_path / "oversized-shm.db"
    Path(f"{oversized_shm_path}-shm").write_bytes(b"x" * (64 * 1024 + 1))
    with pytest.raises(BridgeReplayStoreUnavailable, match="SHM"):
        PersistentNonceReplayGuard(oversized_shm_path, shm_max_bytes=64 * 1024)
    assert not oversized_shm_path.exists()

    target = tmp_path / "target.db"
    target.write_bytes(b"not a database")
    link = tmp_path / "linked.db"
    try:
        os.symlink(target, link)
    except (NotImplementedError, OSError):
        return
    with pytest.raises(BridgeReplayStoreUnavailable):
        PersistentNonceReplayGuard(link)


def test_persistent_guard_hot_path_stays_bounded_with_ten_thousand_rows(tmp_path) -> None:
    path = tmp_path / "bridge-replay.db"
    guard = PersistentNonceReplayGuard(path, max_entries=20_000)
    guard.close()
    rows = [("weixin", f"{index:032x}", 2_000_000_091) for index in range(10_000)]
    with closing(sqlite3.connect(path)) as connection:
        connection.executemany(
            "INSERT INTO bridge_nonce_replay(channel, nonce, valid_until) VALUES (?, ?, ?)",
            rows,
        )
        connection.execute(
            "UPDATE bridge_nonce_replay_meta SET row_count=10000 WHERE singleton=1"
        )
        connection.commit()
    restarted = PersistentNonceReplayGuard(path, max_entries=20_000)
    started = time.perf_counter()
    restarted.consume(
        "feishu",
        "f" * 32,
        now=2_000_000_000,
        valid_until=2_000_000_091,
    )
    assert time.perf_counter() - started < 2.0


def test_fake_loopback_server_sees_neither_capability_nor_prompt_and_is_rejected() -> None:
    captured: dict[str, object] = {}
    prompt = "绝密 prompt：请分析这份合同".encode()

    class FakeEngine(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 - stdlib callback name
            length = int(self.headers.get("Content-Length", "0"))
            captured["headers"] = dict(self.headers.items())
            captured["body"] = self.rfile.read(length)
            forged = b'{"reply":"forged by fake port owner"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(forged)))
            self.end_headers()
            self.wfile.write(forged)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), FakeEngine)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with pytest.raises(BridgeProtocolError):
            request_bridge_bytes(
                opener,
                url=f"http://127.0.0.1:{server.server_port}/v1/agent/chat",
                secret=SECRET,
                channel="weixin",
                method="POST",
                body=prompt,
                headers={"Content-Type": "application/json"},
                timeout=2,
            )
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)

    headers = captured["headers"]
    body = bytes(captured["body"])
    assert isinstance(headers, dict)
    serialized_headers = json.dumps(headers, sort_keys=True).encode()
    assert b"Authorization" not in serialized_headers
    assert SECRET.encode() not in serialized_headers + body
    assert prompt not in body


def test_oversized_media_fails_before_opening_an_unauthenticated_port(monkeypatch) -> None:
    monkeypatch.setitem(bridge_protocol._REQUEST_PATH_LIMITS, "/v1/vision", 4)

    class NeverOpen:
        def open(self, *_args, **_kwargs):
            raise AssertionError("oversized plaintext must fail before network I/O")

    with pytest.raises(BridgePayloadTooLarge, match="sealed limit"):
        request_bridge_bytes(
            NeverOpen(),
            url="http://127.0.0.1:8080/v1/vision",
            secret=SECRET,
            channel="weixin",
            method="POST",
            body=b"12345",
            timeout=1,
        )


def test_authenticated_http_error_is_decrypted_before_being_raised() -> None:
    expected = b'{"detail":"channel mismatch"}'

    class AuthenticatedErrorOpener:
        def open(self, request, **_kwargs):
            request_headers = {
                str(name).lower(): str(value) for name, value in request.header_items()
            }
            request_nonce = request_headers[HEADER_REQUEST_NONCE.lower()]
            body, headers = seal_response(
                secret=SECRET,
                channel="weixin",
                request_nonce=request_nonce,
                status=403,
                body=expected,
            )
            raise urllib.error.HTTPError(
                request.full_url,
                403,
                "Forbidden",
                headers,
                io.BytesIO(body),
            )

    with pytest.raises(urllib.error.HTTPError) as raised:
        request_bridge_bytes(
            AuthenticatedErrorOpener(),
            url="http://127.0.0.1:8080/v1/agent/feedback",
            secret=SECRET,
            channel="weixin",
            method="POST",
            body=b"{}",
            timeout=1,
        )
    assert raised.value.code == 403
    assert raised.value.read() == expected


def test_asgi_middleware_decrypts_once_and_rejects_replay_after_restart(tmp_path) -> None:
    received: dict[str, object] = {}

    async def endpoint(scope, receive, send):
        if scope["type"] == "lifespan":
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif message["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        request = await receive()
        received["body"] = request["body"]
        received["credential"] = scope["state"]["nachuan_bridge_credential"]
        response = b'{"status":"ok"}'
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send({"type": "http.response.body", "body": response})

    replay_path = tmp_path / "middleware-replay.db"
    middleware = BridgeProtocolMiddleware(
        endpoint,
        key_provider=lambda: {"weixin": SECRET},
        replay_guard=PersistentNonceReplayGuard(replay_path),
        wall_clock=lambda: 2_000_000_000,
    )
    sealed = seal_request(
        secret=SECRET,
        channel="weixin",
        method="POST",
        url_or_target="/v1/agent/chat",
        body=b'{"message":"hello"}',
        timestamp=2_000_000_000,
        request_nonce="b" * 32,
        request_iv=b"\x05" * 12,
    )
    with TestClient(middleware) as client:
        response = client.post(
            "/v1/agent/chat",
            content=sealed.body,
            headers=sealed.headers,
        )
        assert response.status_code == 200
        assert open_response(
            secret=SECRET,
            channel="weixin",
            request_nonce=sealed.request_nonce,
            status=response.status_code,
            headers=response.headers,
            body=response.content,
        ) == b'{"status":"ok"}'
        replay = client.post(
            "/v1/agent/chat",
            content=sealed.body,
            headers=sealed.headers,
        )
    assert replay.status_code == 401

    restarted_middleware = BridgeProtocolMiddleware(
        endpoint,
        key_provider=lambda: {"weixin": SECRET},
        replay_guard=PersistentNonceReplayGuard(replay_path),
        wall_clock=lambda: 2_000_000_001,
    )
    with TestClient(restarted_middleware) as restarted_client:
        after_restart = restarted_client.post(
            "/v1/agent/chat",
            content=sealed.body,
            headers=sealed.headers,
        )
    assert after_restart.status_code == 401
    assert received == {
        "body": b'{"message":"hello"}',
        "credential": "bridge:weixin",
    }
