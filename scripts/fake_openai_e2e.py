"""Deterministic loopback-only OpenAI-compatible server for local E2E tests."""

from __future__ import annotations

import argparse
import json
import signal
import threading
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


MODEL_ID = "loopback-e2e-chat"
REPLY = "纳川零外网测试回复。"


def _json_bytes(payload: object) -> bytes:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )


class _FakeOpenAIServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port: int, log_path: Path) -> None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        self.log_path = log_path
        self._log_lock = threading.Lock()
        super().__init__(("127.0.0.1", port), _Handler)

    def audit(
        self, *, method: str, path: str, model: str | None, stream: bool
    ) -> None:
        entry = {
            "method": method,
            "path": path,
            "model": model,
            "stream": stream,
            "timestamp": datetime.now(UTC)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
        }
        line = json.dumps(entry, ensure_ascii=False, separators=(",", ":")) + "\n"
        with self._log_lock, self.log_path.open("a", encoding="utf-8", newline="") as log:
            log.write(line)


class _Handler(BaseHTTPRequestHandler):
    server_version = "NachuanFakeOpenAI/1"

    def do_GET(self) -> None:  # noqa: N802 - stdlib callback name
        path = urlsplit(self.path).path
        self._audit(path=path, model=None, stream=False)
        if path != "/v1/models":
            self.send_error(404)
            return
        self._send_json(
            200,
            {
                "object": "list",
                "data": [
                    {
                        "id": MODEL_ID,
                        "object": "model",
                        "created": 0,
                        "owned_by": "nachuan-e2e",
                    }
                ],
            },
        )

    def do_POST(self) -> None:  # noqa: N802 - stdlib callback name
        path = urlsplit(self.path).path
        if path != "/v1/chat/completions":
            self._audit(path=path, model=None, stream=False)
            self.send_error(404)
            return
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            request = json.loads(self.rfile.read(content_length))
        except (TypeError, ValueError, json.JSONDecodeError):
            self._audit(path=path, model=None, stream=False)
            self._send_json(400, {"error": {"message": "invalid JSON"}})
            return
        requested_model = request.get("model")
        model = MODEL_ID if requested_model == MODEL_ID else None
        stream = request.get("stream", False) is True
        self._audit(path=path, model=model, stream=stream)
        if requested_model != MODEL_ID:
            self._send_json(400, {"error": {"message": "unsupported request"}})
            return
        if stream:
            self._send_stream()
            return
        self._send_json(
            200,
            {
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
                "usage": {
                    "prompt_tokens": 0,
                    "completion_tokens": 0,
                    "total_tokens": 0,
                },
            },
        )

    def do_PUT(self) -> None:  # noqa: N802 - stdlib callback name
        path = urlsplit(self.path).path
        self._audit(path=path, model=None, stream=False)
        self.send_error(404)

    def _audit(self, *, path: str, model: str | None, stream: bool) -> None:
        server = self.server
        if not isinstance(server, _FakeOpenAIServer):
            raise RuntimeError("unexpected server type")
        server.audit(
            method=self.command,
            path=path,
            model=model,
            stream=stream,
        )

    def _send_stream(self) -> None:
        base = {
            "id": "chatcmpl-nachuan-e2e",
            "object": "chat.completion.chunk",
            "created": 0,
            "model": MODEL_ID,
        }
        chunks = [
            {
                **base,
                "choices": [
                    {
                        "index": 0,
                        "delta": {"role": "assistant"},
                        "finish_reason": None,
                    }
                ],
            },
            {
                **base,
                "choices": [
                    {
                        "index": 0,
                        "delta": {"content": REPLY},
                        "finish_reason": None,
                    }
                ],
            },
            {
                **base,
                "choices": [
                    {"index": 0, "delta": {}, "finish_reason": "stop"}
                ],
            },
        ]
        body = b"".join(b"data: " + _json_bytes(chunk) + b"\n\n" for chunk in chunks)
        body += b"data: [DONE]\n\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, status: int, payload: object) -> None:
        body = _json_bytes(payload)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: Any) -> None:
        return


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--log", type=Path, required=True)
    return parser.parse_args()


def _raise_keyboard_interrupt(_signum: int, _frame: object) -> None:
    raise KeyboardInterrupt


def main() -> int:
    args = _parse_args()
    server = _FakeOpenAIServer(args.port, args.log)
    signal.signal(signal.SIGTERM, _raise_keyboard_interrupt)
    if hasattr(signal, "SIGBREAK"):
        signal.signal(signal.SIGBREAK, _raise_keyboard_interrupt)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
