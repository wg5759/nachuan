"""本地模型运行时：供应链证明、隔离启动、就绪身份与下载故障关闭。"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from gateway import local_model

_EXE = "llama-server.exe" if sys.platform == "win32" else "llama-server"


def _symlink_or_skip(link, target, *, target_is_directory: bool = False) -> None:
    try:
        link.symlink_to(target, target_is_directory=target_is_directory)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"symlink creation is unavailable on this Windows account: {exc}")


def _configure_attested_runtime(tmp_path, monkeypatch):
    binary = tmp_path / _EXE
    model = tmp_path / "model.gguf"
    binary.write_bytes(b"x")
    model.write_bytes(b"GGUF0000")
    monkeypatch.setenv("LLAMA_SERVER_BIN", str(binary))
    monkeypatch.setenv("LOCAL_MODEL_PATH", str(model))
    monkeypatch.setenv(
        "LLAMA_SERVER_SHA256",
        "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
    )
    monkeypatch.setenv(
        "LOCAL_MODEL_SHA256",
        "f63366e55ab1a16b61419fbc1fe208d61d13d2b8142f9ca5004d222fbc1655b4",
    )
    monkeypatch.delenv("NACHUAN_LOCAL_RUNTIME_MANIFEST", raising=False)
    monkeypatch.setattr(local_model, "_ready_alias", None)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        monkeypatch.setattr(local_model, "LOCAL_PORT", sock.getsockname()[1])
    return binary, model


def test_unavailable_without_binary_or_model(tmp_path, monkeypatch):
    for k in ("LLAMA_SERVER_BIN", "LLAMA_SERVER_DIR", "LOCAL_MODEL_PATH", "LOCAL_MODEL_DIR"):
        monkeypatch.delenv(k, raising=False)
    assert local_model.available() is False
    assert local_model.base_url() == ""


def test_unavailable_when_binary_and_model_have_no_sha256_attestation(tmp_path, monkeypatch):
    binary = tmp_path / _EXE
    model = tmp_path / "model.gguf"
    binary.write_bytes(b"reviewed-binary")
    model.write_bytes(b"GGUFreviewed-model")
    monkeypatch.setenv("LLAMA_SERVER_BIN", str(binary))
    monkeypatch.setenv("LOCAL_MODEL_PATH", str(model))
    for name in (
        "LLAMA_SERVER_SHA256",
        "LOCAL_MODEL_SHA256",
        "NACHUAN_LOCAL_RUNTIME_MANIFEST",
    ):
        monkeypatch.delenv(name, raising=False)

    assert local_model.available() is False


def test_resolves_paths_and_available(tmp_path, monkeypatch):
    models = tmp_path / "models"
    models.mkdir()
    gguf = models / "m.gguf"
    gguf.write_bytes(b"GGUF0000")
    binp = tmp_path / "bin"
    binp.mkdir()
    (binp / _EXE).write_bytes(b"x")
    monkeypatch.setenv("LOCAL_MODEL_DIR", str(models))
    monkeypatch.setenv("LLAMA_SERVER_DIR", str(binp))
    monkeypatch.setenv(
        "LLAMA_SERVER_SHA256",
        "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
    )
    monkeypatch.setenv(
        "LOCAL_MODEL_SHA256",
        "f63366e55ab1a16b61419fbc1fe208d61d13d2b8142f9ca5004d222fbc1655b4",
    )
    monkeypatch.delenv("LOCAL_MODEL_PATH", raising=False)
    monkeypatch.delenv("LLAMA_SERVER_BIN", raising=False)

    assert local_model.gguf_path() == str(gguf)
    assert local_model.available() is True
    assert local_model.base_url().endswith(f":{local_model.LOCAL_PORT}/v1")


def test_audit_manifest_binds_binary_model_and_adjacent_runtime_dll(tmp_path, monkeypatch):
    runtime = tmp_path / "runtime"
    models = tmp_path / "models"
    runtime.mkdir()
    models.mkdir()
    binary = runtime / _EXE
    dependency = runtime / "ggml-base.dll"
    model = models / "model.gguf"
    binary.write_bytes(b"server")
    dependency.write_bytes(b"dependency")
    model.write_bytes(b"GGUFmodel")
    manifest = tmp_path / "local-runtime-manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema": 1,
                "artifacts": [
                    {
                        "role": "llama-server",
                        "path": f"runtime/{_EXE}",
                        "sha256": "b3eacd33433b31b5252351032c9b3e7a2e7aa7738d5decdf0dd6c62680853c06",
                    },
                    {
                        "role": "runtime-dependency",
                        "path": "runtime/ggml-base.dll",
                        "sha256": "f26350dafe3f19aabfd69ac463fb5daf76015c9a2763e76e2ad32fc0fcfedf31",
                    },
                    {
                        "role": "model",
                        "path": "models/model.gguf",
                        "sha256": "590c2659ff773d971c999dee15861927193b9cf45de6f5a2603e4f2760ed56c1",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("LLAMA_SERVER_BIN", str(binary))
    monkeypatch.setenv("LOCAL_MODEL_PATH", str(model))
    monkeypatch.setenv("NACHUAN_LOCAL_RUNTIME_MANIFEST", str(manifest))
    monkeypatch.delenv("LLAMA_SERVER_SHA256", raising=False)
    monkeypatch.delenv("LOCAL_MODEL_SHA256", raising=False)

    assert local_model.available() is True
    dependency.write_bytes(b"tampered")
    assert local_model.available() is False
    dependency.write_bytes(b"dependency")
    unlisted = runtime / "ggml-cpu-unreviewed.dll"
    unlisted.write_bytes(b"unreviewed")
    assert local_model.available() is False
    unlisted.unlink()
    model.write_bytes(b"GGUFtampered-model")
    assert local_model.available() is False


def test_binary_symlink_is_never_an_attested_runtime(tmp_path, monkeypatch):
    real_binary = tmp_path / f"real-{_EXE}"
    binary = tmp_path / _EXE
    model = tmp_path / "model.gguf"
    real_binary.write_bytes(b"server")
    _symlink_or_skip(binary, real_binary)
    model.write_bytes(b"GGUFmodel")
    monkeypatch.setenv("LLAMA_SERVER_BIN", str(binary))
    monkeypatch.setenv("LOCAL_MODEL_PATH", str(model))
    monkeypatch.setenv("LLAMA_SERVER_SHA256", local_model._sha256(str(real_binary)))  # noqa: SLF001
    monkeypatch.setenv("LOCAL_MODEL_SHA256", local_model._sha256(str(model)))  # noqa: SLF001
    monkeypatch.delenv("NACHUAN_LOCAL_RUNTIME_MANIFEST", raising=False)

    assert local_model.available() is False


def test_model_symlink_is_never_an_attested_gguf(tmp_path, monkeypatch):
    binary = tmp_path / _EXE
    real_model = tmp_path / "real-model.gguf"
    model = tmp_path / "model.gguf"
    binary.write_bytes(b"server")
    real_model.write_bytes(b"GGUFmodel")
    _symlink_or_skip(model, real_model)
    monkeypatch.setenv("LLAMA_SERVER_BIN", str(binary))
    monkeypatch.setenv("LOCAL_MODEL_PATH", str(model))
    monkeypatch.setenv("LLAMA_SERVER_SHA256", local_model._sha256(str(binary)))  # noqa: SLF001
    monkeypatch.setenv("LOCAL_MODEL_SHA256", local_model._sha256(str(real_model)))  # noqa: SLF001

    assert local_model.available() is False


def test_runtime_rejects_parent_directory_redirect(tmp_path, monkeypatch):
    real_runtime = tmp_path / "real-runtime"
    linked_runtime = tmp_path / "runtime"
    real_runtime.mkdir()
    _symlink_or_skip(linked_runtime, real_runtime, target_is_directory=True)
    binary = real_runtime / _EXE
    model = tmp_path / "model.gguf"
    binary.write_bytes(b"server")
    model.write_bytes(b"GGUFmodel")
    monkeypatch.setenv("LLAMA_SERVER_BIN", str(linked_runtime / _EXE))
    monkeypatch.setenv("LOCAL_MODEL_PATH", str(model))
    monkeypatch.setenv("LLAMA_SERVER_SHA256", local_model._sha256(str(binary)))  # noqa: SLF001
    monkeypatch.setenv("LOCAL_MODEL_SHA256", local_model._sha256(str(model)))  # noqa: SLF001
    monkeypatch.delenv("NACHUAN_LOCAL_RUNTIME_MANIFEST", raising=False)

    assert local_model.available() is False


def test_runtime_manifest_itself_cannot_be_a_symlink(tmp_path, monkeypatch):
    real_manifest = tmp_path / "real-manifest.json"
    linked_manifest = tmp_path / "local-runtime-manifest.json"
    real_manifest.write_text(json.dumps({"schema": 1, "artifacts": []}), encoding="utf-8")
    _symlink_or_skip(linked_manifest, real_manifest)
    monkeypatch.setenv("NACHUAN_LOCAL_RUNTIME_MANIFEST", str(linked_manifest))

    assert local_model._load_runtime_manifest() is None  # noqa: SLF001


def test_runtime_manifest_env_path_must_be_absolute(tmp_path, monkeypatch):
    manifest = tmp_path / "local-runtime-manifest.json"
    manifest.write_text(json.dumps({"schema": 1, "artifacts": []}), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NACHUAN_LOCAL_RUNTIME_MANIFEST", manifest.name)

    assert local_model._load_runtime_manifest() is None  # noqa: SLF001


def test_active_marker_rejects_traversal_and_nested_model_paths(tmp_path, monkeypatch):
    models = tmp_path / "models"
    models.mkdir()
    (tmp_path / "outside.gguf").write_bytes(b"GGUFoutside")
    nested = models / "nested"
    nested.mkdir()
    (nested / "inside.gguf").write_bytes(b"GGUFinside")
    marker = models / ".active"
    monkeypatch.setenv("LOCAL_MODEL_DIR", str(models))
    monkeypatch.delenv("LOCAL_MODEL_PATH", raising=False)

    for unsafe in ("../outside.gguf", "nested/inside.gguf", "nested\\inside.gguf"):
        marker.write_text(unsafe, encoding="utf-8")
        assert local_model.gguf_path() is None


def test_active_marker_itself_cannot_be_a_symlink(tmp_path, monkeypatch):
    models = tmp_path / "models"
    models.mkdir()
    model = models / "model.gguf"
    model.write_bytes(b"GGUFmodel")
    real_marker = models / "selected.txt"
    real_marker.write_text(model.name, encoding="utf-8")
    _symlink_or_skip(models / ".active", real_marker)
    monkeypatch.setenv("LOCAL_MODEL_DIR", str(models))
    monkeypatch.delenv("LOCAL_MODEL_PATH", raising=False)

    assert local_model.gguf_path() is None


def test_adjacent_library_symlink_fails_closed_even_when_target_is_in_runtime(
    tmp_path, monkeypatch
):
    runtime = tmp_path / "runtime"
    models = tmp_path / "models"
    runtime.mkdir()
    models.mkdir()
    binary = runtime / _EXE
    dependency_target = runtime / "reviewed-library.bin"
    dependency_link = runtime / "ggml-base.dll"
    model = models / "model.gguf"
    binary.write_bytes(b"server")
    dependency_target.write_bytes(b"dependency")
    _symlink_or_skip(dependency_link, dependency_target)
    model.write_bytes(b"GGUFmodel")
    manifest = tmp_path / "local-runtime-manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema": 1,
                "artifacts": [
                    {
                        "role": "llama-server",
                        "path": f"runtime/{_EXE}",
                        "sha256": local_model._sha256(str(binary)),  # noqa: SLF001
                    },
                    {
                        "role": "runtime-dependency",
                        "path": "runtime/ggml-base.dll",
                        "sha256": local_model._sha256(str(dependency_target)),  # noqa: SLF001
                    },
                    {
                        "role": "model",
                        "path": "models/model.gguf",
                        "sha256": local_model._sha256(str(model)),  # noqa: SLF001
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("LLAMA_SERVER_BIN", str(binary))
    monkeypatch.setenv("LOCAL_MODEL_PATH", str(model))
    monkeypatch.setenv("NACHUAN_LOCAL_RUNTIME_MANIFEST", str(manifest))
    monkeypatch.delenv("LLAMA_SERVER_SHA256", raising=False)
    monkeypatch.delenv("LOCAL_MODEL_SHA256", raising=False)

    assert local_model.available() is False


def test_runtime_env_paths_must_be_absolute(tmp_path, monkeypatch):
    binary = tmp_path / _EXE
    model = tmp_path / "model.gguf"
    binary.write_bytes(b"server")
    model.write_bytes(b"GGUFmodel")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LLAMA_SERVER_BIN", _EXE)
    monkeypatch.setenv("LOCAL_MODEL_PATH", model.name)
    monkeypatch.setenv("LLAMA_SERVER_SHA256", local_model._sha256(str(binary)))  # noqa: SLF001
    monkeypatch.setenv("LOCAL_MODEL_SHA256", local_model._sha256(str(model)))  # noqa: SLF001

    assert local_model.available() is False


def test_matching_hash_does_not_make_non_gguf_model_available(tmp_path, monkeypatch):
    binary = tmp_path / _EXE
    model = tmp_path / "model.gguf"
    binary.write_bytes(b"server")
    model.write_bytes(b"NOT-A-GGUF")
    monkeypatch.setenv("LLAMA_SERVER_BIN", str(binary))
    monkeypatch.setenv("LOCAL_MODEL_PATH", str(model))
    monkeypatch.setenv("LLAMA_SERVER_SHA256", local_model._sha256(str(binary)))  # noqa: SLF001
    monkeypatch.setenv("LOCAL_MODEL_SHA256", local_model._sha256(str(model)))  # noqa: SLF001

    assert local_model.available() is False


@pytest.mark.skipif(sys.platform != "win32", reason="Windows executable extension rule")
def test_windows_runtime_binary_must_be_exact_exe(tmp_path, monkeypatch):
    binary = tmp_path / "llama-server.cmd"
    model = tmp_path / "model.gguf"
    binary.write_bytes(b"server")
    model.write_bytes(b"GGUFmodel")
    monkeypatch.setenv("LLAMA_SERVER_BIN", str(binary))
    monkeypatch.setenv("LOCAL_MODEL_PATH", str(model))
    monkeypatch.setenv("LLAMA_SERVER_SHA256", local_model._sha256(str(binary)))  # noqa: SLF001
    monkeypatch.setenv("LOCAL_MODEL_SHA256", local_model._sha256(str(model)))  # noqa: SLF001

    assert local_model.available() is False


def test_hash_attestation_rejects_path_replaced_during_read(tmp_path, monkeypatch):
    candidate = tmp_path / "runtime.dll"
    candidate.write_bytes(b"reviewed-bytes")
    expected = local_model._sha256(str(candidate))  # noqa: SLF001
    real_identity = local_model._safe_file_identity  # noqa: SLF001
    state = {"candidate_checks": 0}

    def replaced_identity(path, **kwargs):
        identity = real_identity(path, **kwargs)
        if str(path) == str(candidate) and identity is not None:
            state["candidate_checks"] += 1
            if state["candidate_checks"] >= 2:
                return local_model._FileIdentity(  # noqa: SLF001
                    device=identity.device,
                    inode=identity.inode + 1,
                    mode=identity.mode,
                    size=identity.size,
                    modified_ns=identity.modified_ns,
                    changed_ns=identity.changed_ns,
                )
        return identity

    monkeypatch.setattr(local_model, "_safe_file_identity", replaced_identity)

    assert local_model._matches_digest(str(candidate), expected) is False  # noqa: SLF001
    assert state["candidate_checks"] >= 2


def test_runtime_manifest_rejects_absolute_traversal_and_uncontrolled_roots(
    tmp_path, monkeypatch
):
    manifest = tmp_path / "local-runtime-manifest.json"
    monkeypatch.setenv("NACHUAN_LOCAL_RUNTIME_MANIFEST", str(manifest))
    digest = "a" * 64
    unsafe_paths = (
        str((tmp_path / "outside.exe").resolve()),
        "../outside.exe",
        "llama\\server.exe",
        "other/server.exe",
    )
    for unsafe in unsafe_paths:
        manifest.write_text(
            json.dumps(
                {
                    "schema": 1,
                    "artifacts": [
                        {"role": "llama-server", "path": unsafe, "sha256": digest}
                    ],
                }
            ),
            encoding="utf-8",
        )
        assert local_model._load_runtime_manifest() is None  # noqa: SLF001


def test_start_uses_minimal_environment_without_gateway_or_provider_secrets(tmp_path, monkeypatch):
    _configure_attested_runtime(tmp_path, monkeypatch)
    captured = {}

    class RunningProcess:
        pid = 7319

        @staticmethod
        def poll():
            return None

        @staticmethod
        def terminate():
            return None

    def fake_popen(command, **kwargs):
        captured["command"] = command
        captured.update(kwargs)
        return RunningProcess()

    class ReadyResponse:
        status = 200

        @staticmethod
        def read(_limit):
            command = captured["command"]
            alias = command[command.index("--alias") + 1] if "--alias" in command else "local"
            return json.dumps({"data": [{"id": alias}]}).encode("utf-8")

    class ReadyConnection:
        def request(self, *args, **kwargs):
            return None

        def getresponse(self):
            return ReadyResponse()

        def close(self):
            return None

    monkeypatch.setattr(local_model.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(local_model, "HTTPConnection", lambda *args, **kwargs: ReadyConnection())
    monkeypatch.setattr(local_model, "_proc", None)
    monkeypatch.setenv("SYSTEMROOT", r"C:\Windows")
    monkeypatch.setenv("TEMP", str(tmp_path / "temp"))
    for name in (
        "NACHUAN_GATEWAY_KEY",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "WEIXIN_BOT_TOKEN",
        "SUPABASE_SERVICE_KEY",
        "HTTPS_PROXY",
    ):
        monkeypatch.setenv(name, "must-not-reach-llama")

    assert local_model.start() is True
    command = captured["command"]
    assert local_model.ready_model_alias() == command[command.index("--alias") + 1]
    child_env = captured["env"]
    assert child_env["SYSTEMROOT"] == r"C:\Windows"
    assert child_env["TEMP"] == str(tmp_path / "temp")
    assert not ({
        "NACHUAN_GATEWAY_KEY",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "WEIXIN_BOT_TOKEN",
        "SUPABASE_SERVICE_KEY",
        "HTTPS_PROXY",
    } & set(child_env))


def test_start_never_launches_unattested_runtime(tmp_path, monkeypatch):
    binary = tmp_path / _EXE
    model = tmp_path / "model.gguf"
    binary.write_bytes(b"unreviewed-binary")
    model.write_bytes(b"GGUFunreviewed-model")
    monkeypatch.setenv("LLAMA_SERVER_BIN", str(binary))
    monkeypatch.setenv("LOCAL_MODEL_PATH", str(model))
    for name in (
        "LLAMA_SERVER_SHA256",
        "LOCAL_MODEL_SHA256",
        "NACHUAN_LOCAL_RUNTIME_MANIFEST",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(local_model, "_proc", None)
    launched = False

    def fail_if_launched(*args, **kwargs):
        nonlocal launched
        launched = True
        raise AssertionError("unattested llama-server must not be launched")

    monkeypatch.setattr(local_model.subprocess, "Popen", fail_if_launched)

    assert local_model.start() is False
    assert launched is False
    monkeypatch.setenv("LLAMA_SERVER_SHA256", "0" * 64)
    monkeypatch.setenv("LOCAL_MODEL_SHA256", "1" * 64)
    assert local_model.start() is False
    assert launched is False


def test_start_repeats_full_attestation_immediately_before_launch(tmp_path, monkeypatch):
    _configure_attested_runtime(tmp_path, monkeypatch)
    real_attest = local_model._local_runtime_attested  # noqa: SLF001
    state = {"attestations": 0, "launched": False}

    def counting_attestation(binary, model):
        state["attestations"] += 1
        return real_attest(binary, model)

    class ExitedProcess:
        pid = 8400

        @staticmethod
        def poll():
            return 1

    def fake_popen(*args, **kwargs):
        state["launched"] = True
        assert state["attestations"] == 2
        return ExitedProcess()

    monkeypatch.setattr(local_model, "_local_runtime_attested", counting_attestation)
    monkeypatch.setattr(local_model.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(local_model, "_proc", None)

    assert local_model.start() is False
    assert state == {"attestations": 2, "launched": True}


def test_start_does_not_report_ready_when_managed_process_exits_immediately(tmp_path, monkeypatch):
    _configure_attested_runtime(tmp_path, monkeypatch)

    class ExitedProcess:
        pid = 8401

        @staticmethod
        def poll():
            return 23

    monkeypatch.setattr(local_model.subprocess, "Popen", lambda *args, **kwargs: ExitedProcess())
    monkeypatch.setattr(local_model, "_proc", None)

    assert local_model.start() is False
    assert local_model._proc is None


def test_start_times_out_and_terminates_process_that_never_becomes_ready(tmp_path, monkeypatch):
    _configure_attested_runtime(tmp_path, monkeypatch)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        unused_port = sock.getsockname()[1]
    monkeypatch.setattr(local_model, "LOCAL_PORT", unused_port)
    monkeypatch.setenv("LOCAL_LLAMA_START_TIMEOUT", "0.05")
    state = {"terminated": False}

    class HungProcess:
        pid = 8402

        @staticmethod
        def poll():
            return 0 if state["terminated"] else None

        @staticmethod
        def terminate():
            state["terminated"] = True

        @staticmethod
        def wait(timeout=None):
            return 0

    monkeypatch.setattr(local_model.subprocess, "Popen", lambda *args, **kwargs: HungProcess())
    monkeypatch.setattr(local_model, "_proc", None)

    assert local_model.start() is False
    assert state["terminated"] is True
    assert local_model._proc is None


def test_start_rejects_models_response_from_preexisting_service(tmp_path, monkeypatch):
    _configure_attested_runtime(tmp_path, monkeypatch)
    monkeypatch.setenv("LOCAL_LLAMA_START_TIMEOUT", "0.05")
    state = {"terminated": False, "command": []}

    class RunningProcess:
        pid = 8403

        @staticmethod
        def poll():
            return 0 if state["terminated"] else None

        @staticmethod
        def terminate():
            state["terminated"] = True

        @staticmethod
        def wait(timeout=None):
            return 0

    class StaleResponse:
        status = 200

        @staticmethod
        def read(_limit):
            return b'{"data":[{"id":"pre-existing-service"}]}'

    class StaleConnection:
        def request(self, *args, **kwargs):
            return None

        def getresponse(self):
            return StaleResponse()

        def close(self):
            return None

    def fake_popen(command, **kwargs):
        state["command"] = command
        return RunningProcess()

    monkeypatch.setattr(local_model.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(local_model, "HTTPConnection", lambda *args, **kwargs: StaleConnection())
    monkeypatch.setattr(local_model, "_proc", None)

    assert local_model.start() is False
    assert "--alias" in state["command"]
    assert state["terminated"] is True
    assert local_model._proc is None


def test_start_does_not_launch_when_loopback_port_is_already_owned(tmp_path, monkeypatch):
    _configure_attested_runtime(tmp_path, monkeypatch)
    launched = False

    def fail_if_launched(*args, **kwargs):
        nonlocal launched
        launched = True
        raise AssertionError("occupied port must fail before Popen")

    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        monkeypatch.setattr(local_model, "LOCAL_PORT", listener.getsockname()[1])
        monkeypatch.setattr(local_model.subprocess, "Popen", fail_if_launched)
        monkeypatch.setattr(local_model, "_proc", None)

        assert local_model.start() is False

    assert launched is False


def test_start_probe_cannot_be_satisfied_by_environment_http_proxy(tmp_path, monkeypatch):
    _configure_attested_runtime(tmp_path, monkeypatch)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        unused_model_port = sock.getsockname()[1]
    monkeypatch.setattr(local_model, "LOCAL_PORT", unused_model_port)
    monkeypatch.setenv("LOCAL_LLAMA_START_TIMEOUT", "0.08")
    state = {"command": [], "terminated": False}

    class ProxyHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            command = state["command"]
            alias = command[command.index("--alias") + 1]
            body = json.dumps({"data": [{"id": alias}]}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            return None

    class RunningProcess:
        pid = 8404

        @staticmethod
        def poll():
            return 0 if state["terminated"] else None

        @staticmethod
        def terminate():
            state["terminated"] = True

        @staticmethod
        def wait(timeout=None):
            return 0

    def fake_popen(command, **kwargs):
        state["command"] = command
        return RunningProcess()

    proxy = ThreadingHTTPServer(("127.0.0.1", 0), ProxyHandler)
    worker = threading.Thread(target=proxy.serve_forever, daemon=True)
    worker.start()
    try:
        proxy_url = f"http://127.0.0.1:{proxy.server_port}"
        monkeypatch.setenv("HTTP_PROXY", proxy_url)
        monkeypatch.setenv("http_proxy", proxy_url)
        for name in ("NO_PROXY", "no_proxy", "REQUEST_METHOD"):
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setattr(local_model.subprocess, "Popen", fake_popen)
        monkeypatch.setattr(local_model, "_proc", None)

        assert local_model.start() is False
    finally:
        proxy.shutdown()
        proxy.server_close()
        worker.join(timeout=2)

    assert state["terminated"] is True


def test_start_kills_process_when_graceful_timeout_cleanup_fails(tmp_path, monkeypatch):
    _configure_attested_runtime(tmp_path, monkeypatch)
    monkeypatch.setenv("LOCAL_LLAMA_START_TIMEOUT", "0.02")
    state = {"killed": False}

    class StubbornProcess:
        pid = 8405

        @staticmethod
        def poll():
            return 0 if state["killed"] else None

        @staticmethod
        def terminate():
            raise OSError("graceful termination failed")

        @staticmethod
        def kill():
            state["killed"] = True

        @staticmethod
        def wait(timeout=None):
            return 0

    class RefusedConnection:
        def request(self, *args, **kwargs):
            raise OSError("not listening")

        def close(self):
            return None

    monkeypatch.setattr(local_model.subprocess, "Popen", lambda *args, **kwargs: StubbornProcess())
    monkeypatch.setattr(local_model, "HTTPConnection", lambda *args, **kwargs: RefusedConnection())
    monkeypatch.setattr(local_model, "_proc", None)

    assert local_model.start() is False
    assert state["killed"] is True
    assert local_model._proc is None


def test_idempotent_start_rechecks_managed_server_readiness(tmp_path, monkeypatch):
    _configure_attested_runtime(tmp_path, monkeypatch)
    monkeypatch.setenv("LOCAL_LLAMA_START_TIMEOUT", "0.02")
    state = {"ready": True, "command": [], "processes": []}

    class ManagedProcess:
        def __init__(self):
            self.pid = 8500 + len(state["processes"])
            self.terminated = False

        def poll(self):
            return 0 if self.terminated else None

        def terminate(self):
            self.terminated = True

        def wait(self, timeout=None):
            return 0

    class DynamicResponse:
        status = 200

        @staticmethod
        def read(_limit):
            command = state["command"]
            alias = command[command.index("--alias") + 1]
            return json.dumps({"data": [{"id": alias}]}).encode("utf-8")

    class DynamicConnection:
        def request(self, *args, **kwargs):
            if not state["ready"]:
                raise OSError("managed endpoint is no longer ready")

        def getresponse(self):
            return DynamicResponse()

        def close(self):
            return None

    def fake_popen(command, **kwargs):
        state["command"] = command
        process = ManagedProcess()
        state["processes"].append(process)
        return process

    monkeypatch.setattr(local_model.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(local_model, "HTTPConnection", lambda *args, **kwargs: DynamicConnection())
    monkeypatch.setattr(local_model, "_proc", None)

    assert local_model.start() is True
    state["ready"] = False
    assert local_model.start() is False
    assert all(process.terminated for process in state["processes"])
    assert local_model._proc is None


def test_should_autodownload(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCAL_MODEL_DIR", str(tmp_path))
    monkeypatch.setenv("LOCAL_MODEL_AUTODOWNLOAD", "1")
    assert local_model.should_autodownload() is False  # 只有旧开关仍必须 fail-closed
    monkeypatch.setenv("NACHUAN_ENABLE_VERIFIED_MODEL_DOWNLOAD", "1")
    monkeypatch.setenv("LOCAL_MODEL_REVISION", "a" * 40)
    monkeypatch.setenv("LOCAL_MODEL_SHA256", "b" * 64)
    assert local_model.should_autodownload() is True
    monkeypatch.delenv("LOCAL_MODEL_AUTODOWNLOAD")
    assert local_model.should_autodownload() is False  # 没开开关就不下


def test_download_skips_when_model_present(tmp_path, monkeypatch):
    # 目录已有 GGUF → 直接返回该文件、绝不联网（幂等、不重复下）
    gguf = tmp_path / "exist.gguf"
    gguf.write_bytes(b"GGUF")
    monkeypatch.setenv("LOCAL_MODEL_DIR", str(tmp_path))
    assert local_model.download_model() == str(gguf)


def test_download_noop_without_dest(monkeypatch):
    monkeypatch.delenv("LOCAL_MODEL_DIR", raising=False)
    assert local_model.download_model() is None  # 无目标目录 → 安全返回 None


def test_remote_download_requires_revision_and_sha(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCAL_MODEL_DIR", str(tmp_path))
    monkeypatch.setenv("NACHUAN_ENABLE_VERIFIED_MODEL_DOWNLOAD", "1")
    monkeypatch.delenv("LOCAL_MODEL_REVISION", raising=False)
    monkeypatch.delenv("LOCAL_MODEL_SHA256", raising=False)
    assert local_model.download_model("qwen2.5-0.5b") is None


def test_existing_pinned_model_must_match_digest(tmp_path, monkeypatch):
    p = tmp_path / "qwen2.5-0.5b-instruct-q4_k_m.gguf"
    p.write_bytes(b"GGUFtampered")
    monkeypatch.setenv("LOCAL_MODEL_DIR", str(tmp_path))
    monkeypatch.setenv("LOCAL_MODEL_REVISION", "a" * 40)
    monkeypatch.setenv("LOCAL_MODEL_SHA256", "0" * 64)
    assert local_model.download_model("qwen2.5-0.5b") is None


def test_download_fsyncs_before_publish_and_removes_failed_published_file(
    tmp_path, monkeypatch
):
    payload = b"GGUF-reviewed-download"
    digest = hashlib.sha256(payload).hexdigest()
    destination = tmp_path / "qwen2.5-0.5b-instruct-q4_k_m.gguf"
    monkeypatch.setenv("LOCAL_MODEL_DIR", str(tmp_path))
    monkeypatch.setenv("NACHUAN_ENABLE_VERIFIED_MODEL_DOWNLOAD", "1")
    monkeypatch.setenv("LOCAL_MODEL_REVISION", "a" * 40)
    monkeypatch.setenv("LOCAL_MODEL_SHA256", digest)

    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def raise_for_status(self):
            return None

        def iter_bytes(self, _size):
            yield payload

    import httpx

    monkeypatch.setattr(httpx, "stream", lambda *_args, **_kwargs: _Response())
    events: list[str] = []
    real_fsync = local_model.os.fsync
    real_replace = local_model.os.replace

    def tracked_fsync(fd):
        events.append("fsync")
        return real_fsync(fd)

    def tracked_replace(source, target):
        events.append("replace")
        return real_replace(source, target)

    monkeypatch.setattr(local_model.os, "fsync", tracked_fsync)
    monkeypatch.setattr(local_model.os, "replace", tracked_replace)
    real_safe_model_file = local_model._safe_model_file

    def fail_only_after_publish(path):
        if os.path.normcase(str(path)) == os.path.normcase(str(destination)):
            return False
        return real_safe_model_file(path)

    monkeypatch.setattr(local_model, "_safe_model_file", fail_only_after_publish)

    assert local_model.download_model("qwen2.5-0.5b") is None
    assert events.index("fsync") < events.index("replace")
    assert not destination.exists()
    assert not (tmp_path / f"{destination.name}.part").exists()


def test_catalog_has_multiple_free_models():
    ids = [e["id"] for e in local_model.CATALOG]
    assert "qwen2.5-1.5b" in ids and len(ids) >= 4  # 多个免费模型可选
    assert local_model._entry("qwen2.5-3b")["size_mb"] > 0  # 条目带体积，前端按机器选


def test_catalog_status_and_active(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCAL_MODEL_DIR", str(tmp_path))
    (tmp_path / "qwen2.5-1.5b-instruct-q4_k_m.gguf").write_bytes(b"GGUF")
    (tmp_path / ".active").write_text("qwen2.5-1.5b-instruct-q4_k_m.gguf", encoding="utf-8")
    assert local_model.active_model_id() == "qwen2.5-1.5b"
    cat = {e["id"]: e for e in local_model.catalog()}
    assert cat["qwen2.5-1.5b"]["downloaded"] and cat["qwen2.5-1.5b"]["active"]
    assert not cat["qwen2.5-7b"]["downloaded"] and not cat["qwen2.5-7b"]["active"]


def test_local_catalog_endpoint():
    from fastapi.testclient import TestClient

    from gateway.app import app

    with TestClient(app) as c:
        r = c.get("/v1/local/catalog", headers={"Authorization": "Bearer test-key"})
        assert r.status_code == 200 and len(r.json()["models"]) >= 4
        bad = c.post(
            "/v1/local/select",
            headers={"Authorization": "Bearer test-key"},
            json={"model_id": "nope"},
        )
        assert bad.status_code == 422  # 未知 id 拒掉


def test_gateway_startup_does_not_wait_for_local_model_cold_start(monkeypatch):
    from fastapi.testclient import TestClient

    from gateway.app import app

    entered = threading.Event()
    release = threading.Event()

    def slow_start(_cancel_event=None) -> bool:
        entered.set()
        release.wait(10)
        return False

    monkeypatch.setattr(local_model, "should_autodownload", lambda: False)
    monkeypatch.setattr(local_model, "start", slow_start)
    started = time.monotonic()
    try:
        with TestClient(app) as client:
            assert time.monotonic() - started < 5
            assert entered.wait(1)
            assert client.get(
                "/health", headers={"Authorization": "Bearer test-key"}
            ).status_code == 200
    finally:
        release.set()
