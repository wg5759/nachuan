from __future__ import annotations

import json
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKER = ROOT / "cli" / "isolated_plugin_worker_entrypoint.py"


def _frame(value: object) -> bytes:
    body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return struct.pack(">I", len(body)) + body


def _responses(payload: bytes) -> list[object]:
    values: list[object] = []
    while payload:
        assert len(payload) >= 4
        size = struct.unpack(">I", payload[:4])[0]
        assert len(payload) >= size + 4
        values.append(json.loads(payload[4 : size + 4]))
        payload = payload[size + 4 :]
    return values


def _run(plugin: Path, payload: bytes) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            "-B",
            "-X",
            "utf8",
            str(WORKER),
            str(plugin),
            "4096",
            "4096",
        ],
        input=payload,
        capture_output=True,
        timeout=10,
        check=False,
    )


def test_worker_runs_one_framed_request_without_site_packages(tmp_path) -> None:
    plugin = tmp_path / "plugin.py"
    plugin.write_text(
        "def handle(value):\n    return {'sum': value['a'] + value['b']}\n",
        encoding="utf-8",
    )
    result = _run(
        plugin,
        _frame(
            {
                "schema": "nachuan.isolated-plugin.request.v1",
                "input": {"a": 2, "b": 5},
            }
        ),
    )
    assert result.returncode == 0
    assert result.stderr == b""
    assert _responses(result.stdout) == [
        {"schema": "nachuan.isolated-plugin.ready.v1"},
        {
            "schema": "nachuan.isolated-plugin.result.v1",
            "ok": True,
            "output": {"sum": 7},
        },
    ]


def test_worker_failure_is_generic_and_never_echoes_plugin_exception(tmp_path) -> None:
    plugin = tmp_path / "plugin.py"
    plugin.write_text(
        "def handle(_value):\n    raise RuntimeError('secret-controlled-detail')\n",
        encoding="utf-8",
    )
    result = _run(
        plugin,
        _frame(
            {
                "schema": "nachuan.isolated-plugin.request.v1",
                "input": {},
            }
        ),
    )
    assert result.returncode == 70
    assert result.stderr == b""
    assert b"secret-controlled-detail" not in result.stdout
    assert _responses(result.stdout) == [
        {"schema": "nachuan.isolated-plugin.ready.v1"},
        {
            "schema": "nachuan.isolated-plugin.result.v1",
            "ok": False,
            "output": None,
        },
    ]


def test_worker_rejects_multiple_frames_without_running_plugin(tmp_path) -> None:
    marker = tmp_path / "ran.txt"
    plugin = tmp_path / "plugin.py"
    plugin.write_text(
        f"from pathlib import Path\ndef handle(value):\n    Path({str(marker)!r}).write_text('ran')\n    return value\n",
        encoding="utf-8",
    )
    request = {
        "schema": "nachuan.isolated-plugin.request.v1",
        "input": {},
    }
    result = _run(plugin, _frame(request) + _frame(request))
    assert result.returncode == 70
    assert not marker.exists()
    assert _responses(result.stdout)[-1]["ok"] is False
