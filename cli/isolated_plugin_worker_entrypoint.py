"""Single-request framed worker used only behind an OS isolation launcher."""

from __future__ import annotations

import json
import os
import runpy
import struct
import sys
from pathlib import Path
from typing import Any

_REQUEST_SCHEMA = "nachuan.isolated-plugin.request.v1"
_RESULT_SCHEMA = "nachuan.isolated-plugin.result.v1"
_READY_SCHEMA = "nachuan.isolated-plugin.ready.v1"
_MAX_FRAME = 64 * 1024
_MAX_CONTROL_FRAME = 256


def _read_exact(stream: Any, size: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while total < size:
        chunk = stream.read(size - total)
        if not chunk:
            raise ValueError("isolated plugin frame is truncated")
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def _read_frame(stream: Any, maximum: int) -> bytes:
    header = _read_exact(stream, 4)
    size = struct.unpack(">I", header)[0]
    if size < 2 or size > maximum:
        raise ValueError("isolated plugin frame length is invalid")
    body = _read_exact(stream, size)
    if stream.read(1):
        raise ValueError("isolated plugin worker accepts one request")
    return body


def _write_frame(stream: Any, body: bytes, maximum: int) -> None:
    if not 2 <= len(body) <= maximum:
        raise ValueError("isolated plugin response length is invalid")
    stream.write(struct.pack(">I", len(body)))
    stream.write(body)
    stream.flush()


def _closed_request(payload: bytes) -> dict[str, object]:
    def closed_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("isolated plugin request has duplicate fields")
            value[key] = item
        return value

    def reject_constant(_value: str) -> object:
        raise ValueError("isolated plugin request has non-finite numbers")

    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=closed_object,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ValueError("isolated plugin request is invalid") from exc
    canonical = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    if canonical != payload:
        raise ValueError("isolated plugin request is not canonical")
    if not isinstance(value, dict) or set(value) != {"schema", "input"}:
        raise ValueError("isolated plugin request is not closed")
    if value.get("schema") != _REQUEST_SCHEMA or not isinstance(value.get("input"), dict):
        raise ValueError("isolated plugin request is invalid")
    return value["input"]


def _result(ok: bool, output: object, maximum: int) -> bytes:
    try:
        payload = json.dumps(
            {"schema": _RESULT_SCHEMA, "ok": ok, "output": output},
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ValueError("isolated plugin result is invalid") from exc
    if len(payload) > maximum:
        raise ValueError("isolated plugin result exceeds its limit")
    return payload


def run(entrypoint: str | Path, *, max_request: int, max_response: int) -> int:
    if not 2 <= max_request <= _MAX_FRAME or not 2 <= max_response <= _MAX_FRAME:
        return 64
    path = Path(os.path.abspath(os.fspath(entrypoint)))
    if path.name != "plugin.py" or not path.is_file() or path.is_symlink():
        return 65
    try:
        ready = json.dumps(
            {"schema": _READY_SCHEMA},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        _write_frame(sys.stdout.buffer, ready, _MAX_CONTROL_FRAME)
        request = _closed_request(_read_frame(sys.stdin.buffer, max_request))
        namespace = runpy.run_path(str(path), run_name="nachuan_isolated_plugin")
        handler = namespace.get("handle")
        if not callable(handler):
            raise TypeError("isolated plugin handler is missing")
        output = handler(request)
        body = _result(True, output, max_response)
        _write_frame(sys.stdout.buffer, body, max_response)
        return 0
    except BaseException:  # noqa: BLE001 -- never expose plugin-controlled details
        try:
            _write_frame(sys.stdout.buffer, _result(False, None, max_response), max_response)
        except BaseException:  # noqa: BLE001, S110 -- there is no safe secondary channel
            pass
        return 70


def main() -> None:
    # The launcher supplies only the trusted copied entrypoint and two bounded
    # integers.  No shell, token, credential, workspace or network target is
    # representable on argv.
    if len(sys.argv) != 4:
        raise SystemExit(64)
    try:
        request_limit = int(sys.argv[2])
        response_limit = int(sys.argv[3])
    except ValueError:
        raise SystemExit(64) from None
    raise SystemExit(
        run(sys.argv[1], max_request=request_limit, max_response=response_limit)
    )


if __name__ == "__main__":
    main()
