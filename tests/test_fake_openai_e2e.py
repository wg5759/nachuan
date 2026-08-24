from __future__ import annotations

import json
import re
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from gateway.connections import normalize_connection_candidate
from scripts.fake_openai_e2e import MODEL_ID, REPLY


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "fake_openai_e2e.py"


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _request(port: int, path: str) -> tuple[int, bytes, dict[str, str]]:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(f"http://127.0.0.1:{port}{path}", timeout=1) as response:
            return response.status, response.read(), dict(response.headers.items())
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), dict(exc.headers.items())


def _post_json(
    port: int,
    path: str,
    payload: object,
    *,
    headers: dict[str, str] | None = None,
) -> tuple[int, bytes, dict[str, str]]:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=1) as response:
            return response.status, response.read(), dict(response.headers.items())
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), dict(exc.headers.items())


def _start_server(tmp_path: Path) -> tuple[subprocess.Popen[str], int, Path]:
    port = _free_loopback_port()
    log_path = tmp_path / "fake-openai.jsonl"
    process = subprocess.Popen(
        [
            sys.executable,
            "-u",
            str(SCRIPT),
            "--port",
            str(port),
            "--log",
            str(log_path),
        ],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        creationflags=(
            getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            if sys.platform == "win32"
            else 0
        ),
    )
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stdout, stderr = process.communicate(timeout=1)
            raise AssertionError(
                f"fake OpenAI server exited before ready: {stdout=} {stderr=}"
            )
        try:
            status, _, _ = _request(port, "/v1/models")
        except (OSError, TimeoutError):
            time.sleep(0.05)
            continue
        if status == 200:
            return process, port, log_path
        time.sleep(0.05)
    process.terminate()
    process.wait(timeout=2)
    raise AssertionError("fake OpenAI server did not become ready")


def _stop_server(process: subprocess.Popen[str]) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)


def test_e2e_model_id_is_admissible_by_the_real_connection_contract() -> None:
    normalized = normalize_connection_candidate(
        "ollama",
        {
            "type": "openai_compat",
            "api_key": "",
            "base_url": "http://127.0.0.1:18181/v1",
            "enabled_models": [
                {"id": MODEL_ID, "upstream_model": MODEL_ID, "tier": "local"}
            ],
        },
    )

    assert normalized["enabled_models"][0]["id"] == MODEL_ID


def test_models_exposes_only_the_deterministic_e2e_model(tmp_path: Path) -> None:
    process, port, _ = _start_server(tmp_path)
    try:
        status, body, headers = _request(port, "/v1/models")
    finally:
        _stop_server(process)

    assert status == 200
    assert headers["Content-Type"].startswith("application/json")
    payload = json.loads(body)
    assert payload == {
        "object": "list",
        "data": [
            {
                "id": MODEL_ID,
                "object": "model",
                "created": 0,
                "owned_by": "nachuan-e2e",
            }
        ],
    }


def test_non_stream_chat_returns_standard_deterministic_completion(
    tmp_path: Path,
) -> None:
    process, port, _ = _start_server(tmp_path)
    try:
        status, body, headers = _post_json(
            port,
            "/v1/chat/completions",
            {
                "model": MODEL_ID,
                "messages": [{"role": "user", "content": "这段不会被回显"}],
                "stream": False,
            },
        )
    finally:
        _stop_server(process)

    assert status == 200
    assert headers["Content-Type"].startswith("application/json")
    assert json.loads(body) == {
        "id": "chatcmpl-nachuan-e2e",
        "object": "chat.completion",
        "created": 0,
        "model": MODEL_ID,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": REPLY},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }


def test_stream_chat_returns_openai_sse_chunks_and_done(tmp_path: Path) -> None:
    process, port, _ = _start_server(tmp_path)
    try:
        status, body, headers = _post_json(
            port,
            "/v1/chat/completions",
            {
                "model": MODEL_ID,
                "messages": [{"role": "user", "content": "请流式回复"}],
                "stream": True,
            },
        )
    finally:
        _stop_server(process)

    assert status == 200
    assert headers["Content-Type"].startswith("text/event-stream")
    events = [line.removeprefix("data: ") for line in body.decode().splitlines() if line]
    assert events[-1] == "[DONE]"
    chunks = [json.loads(event) for event in events[:-1]]
    assert chunks == [
        {
            "id": "chatcmpl-nachuan-e2e",
            "object": "chat.completion.chunk",
            "created": 0,
            "model": MODEL_ID,
            "choices": [
                {"index": 0, "delta": {"role": "assistant"}, "finish_reason": None}
            ],
        },
        {
            "id": "chatcmpl-nachuan-e2e",
            "object": "chat.completion.chunk",
            "created": 0,
            "model": MODEL_ID,
            "choices": [
                {"index": 0, "delta": {"content": REPLY}, "finish_reason": None}
            ],
        },
        {
            "id": "chatcmpl-nachuan-e2e",
            "object": "chat.completion.chunk",
            "created": 0,
            "model": MODEL_ID,
            "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
        },
    ]


def test_jsonl_audit_log_contains_only_safe_request_metadata(tmp_path: Path) -> None:
    secret = "sk-e2e-secret-must-never-be-logged"
    prompt = "完整提示绝不能写进替身服务日志"
    process, port, log_path = _start_server(tmp_path)
    try:
        status, _, _ = _post_json(
            port,
            "/v1/chat/completions",
            {
                "model": MODEL_ID,
                "messages": [{"role": "user", "content": prompt}],
                "stream": True,
            },
            headers={"Authorization": f"Bearer {secret}"},
        )
        assert status == 200
    finally:
        _stop_server(process)

    raw_log = log_path.read_text(encoding="utf-8")
    assert secret not in raw_log
    assert prompt not in raw_log
    entries = [json.loads(line) for line in raw_log.splitlines()]
    assert entries
    assert all(
        set(entry) == {"method", "path", "model", "stream", "timestamp"}
        for entry in entries
    )
    assert all(
        re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", entry["timestamp"])
        for entry in entries
    )
    chat_entry = next(entry for entry in entries if entry["method"] == "POST")
    assert chat_entry == {
        "method": "POST",
        "path": "/v1/chat/completions",
        "model": MODEL_ID,
        "stream": True,
        "timestamp": chat_entry["timestamp"],
    }


def test_every_unrecognized_path_returns_404_instead_of_exposing_a_handler(
    tmp_path: Path,
) -> None:
    process, port, _ = _start_server(tmp_path)
    try:
        get_status, _, _ = _request(port, "/not-an-openai-route")
        post_status, _, _ = _post_json(port, "/not-an-openai-route", {})
        put_request = urllib.request.Request(
            f"http://127.0.0.1:{port}/not-an-openai-route",
            data=b"{}",
            method="PUT",
        )
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            opener.open(put_request, timeout=1)
        except urllib.error.HTTPError as exc:
            put_status = exc.code
        else:
            raise AssertionError("unrecognized PUT unexpectedly succeeded")
    finally:
        _stop_server(process)

    assert (get_status, post_status, put_status) == (404, 404, 404)


def test_shutdown_signal_exits_zero_and_releases_the_loopback_port(
    tmp_path: Path,
) -> None:
    process, port, _ = _start_server(tmp_path)
    try:
        stop_signal = (
            signal.CTRL_BREAK_EVENT if sys.platform == "win32" else signal.SIGTERM
        )
        process.send_signal(stop_signal)
        returncode = process.wait(timeout=3)
    finally:
        _stop_server(process)

    assert returncode == 0
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", port))
