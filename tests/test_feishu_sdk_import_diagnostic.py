"""The diagnostic must preserve failure evidence without emitting exception text."""

import importlib.util
from pathlib import Path


SOURCE = Path(__file__).resolve().parents[1] / "scripts/diagnostics/probe_feishu_sdk_import.py"
spec = importlib.util.spec_from_file_location("feishu_sdk_diagnostic", SOURCE)
diagnostic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diagnostic)


def test_embedded_child_compiles_without_importing_sdk():
    compile(diagnostic.CHILD, "<sdk-diagnostic>", "exec")


def test_exception_evidence_does_not_return_message_or_absolute_path():
    secret = "synthetic-sensitive-error-message"
    error = ('Traceback (most recent call last):\n'
             '  File "C:\\private-owner\\runner.py", line 42, in run\n'
             'RuntimeError: ' + secret + '\n').encode()
    result = diagnostic.observation(b"", error)
    assert result["exception_type"] == "RuntimeError"
    assert result["error_frames"] == [{"file": "runner.py", "line": 42, "function": "run"}]
    assert secret not in str(result)
    assert "private-owner" not in str(result)
    assert result["marker"] is None


def test_closed_phases_and_valid_marker_only():
    output = (b'not json\n{"phase":"untrusted","marker":"IMPORT_OK"}\n'
              b'{"phase":"child_started"}\n'
              b'{"phase":"import_finished","marker":"IMPORT_OK","target":"json"}\n')
    result = diagnostic.observation(output, b"")
    assert result["phases"] == ["child_started", "import_finished"]
    assert result["marker"]["target"] == "json"


def test_blocked_event_and_native_crash_remain_distinct():
    blocked = diagnostic.observation(b"", b"RuntimeError: SDK_IMPORT_SIDE_EFFECT_DENIED:socket.connect\n")
    assert blocked["blocked_event"] == "socket.connect"
    assert not blocked["native_access_violation"]
    crashed = diagnostic.observation(b"", b"Windows fatal exception: access violation\n")
    assert crashed["native_access_violation"]
    assert crashed["blocked_event"] is None


def test_import_profile_keeps_only_module_name():
    result = diagnostic.observation(b"", b"import time: 100 | 200 |   lark_oapi.api.corehr\n")
    assert result["completed_import_count"] == 1
    assert result["last_completed_import"] == "lark_oapi.api.corehr"
