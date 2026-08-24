from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from gateway.codex_subscription_worker import (
    CodexSubscriptionError,
    CodexSubscriptionWorker,
    CodexWorkerRequest,
    CodexWorkerResult,
    codex_cli_argv,
    codex_worker_environment,
)


def _fake_pe(marker: bytes = b"codex") -> bytes:
    payload = bytearray(128)
    payload[:2] = b"MZ"
    payload[0x3C:0x40] = (64).to_bytes(4, "little")
    payload[64:68] = b"PE\0\0"
    payload[80 : 80 + len(marker)] = marker
    return bytes(payload)


def _environment(tmp_path: Path) -> tuple[dict[str, str], Path]:
    executable = (tmp_path / "codex.exe").resolve()
    executable.write_bytes(_fake_pe())
    return (
        {
            "CODEX_CLI_PATH": str(executable),
            "CODEX_CLI_SHA256": hashlib.sha256(executable.read_bytes()).hexdigest(),
            "USERPROFILE": str(tmp_path / "profile"),
            "APPDATA": str(tmp_path / "profile" / "AppData" / "Roaming"),
            "LOCALAPPDATA": str(tmp_path / "profile" / "AppData" / "Local"),
            "TEMP": str(tmp_path / "temp"),
            "PATH": "ignored-path",
        },
        executable,
    )


class _Runner:
    def __init__(self, *results: CodexWorkerResult) -> None:
        self.results = list(results)
        self.requests: list[CodexWorkerRequest] = []

    def __call__(self, request: CodexWorkerRequest) -> CodexWorkerResult:
        self.requests.append(request)
        return self.results.pop(0)


def _success_jsonl(text: str = "NACHUAN_CODEX_OK") -> str:
    return "\n".join(
        [
            json.dumps({"type": "thread.started", "thread_id": "thread_123"}),
            json.dumps({"type": "turn.started"}),
            json.dumps(
                {
                    "type": "item.completed",
                    "item": {
                        "id": "item_1",
                        "type": "agent_message",
                        "text": text,
                    },
                }
            ),
            json.dumps(
                {
                    "type": "turn.completed",
                    "usage": {
                        "input_tokens": 9,
                        "cached_input_tokens": 2,
                        "output_tokens": 4,
                    },
                }
            ),
        ]
    )


def test_status_probe_uses_exact_official_command_without_public_secrets(
    tmp_path: Path,
) -> None:
    environment, executable = _environment(tmp_path)
    runner = _Runner(
        CodexWorkerResult(
            returncode=0,
            stdout="Logged in using ChatGPT\n",
            stderr="",
            process_tree_exit_verified=True,
        )
    )
    worker = CodexSubscriptionWorker(environment=environment, runner=runner)

    assert worker.probe_status() == "authenticated_unprobed"

    request = runner.requests[0]
    assert request.operation == "status"
    assert codex_cli_argv(request, tmp_path / "blank") == (
        str(executable),
        "login",
        "status",
    )
    serialized = repr(request).lower()
    assert str(executable).lower() not in serialized
    assert environment["CODEX_CLI_SHA256"] not in serialized
    assert "logged in using chatgpt" not in serialized


def test_status_probe_accepts_only_closed_known_login_phrases(tmp_path: Path) -> None:
    environment, _ = _environment(tmp_path)
    logged_out = _Runner(
        CodexWorkerResult(
            returncode=1,
            stdout="",
            stderr="Not logged in\n",
            process_tree_exit_verified=True,
        )
    )
    assert (
        CodexSubscriptionWorker(
            environment=environment,
            runner=logged_out,
        ).probe_status()
        == "logged_out"
    )

    forged = _Runner(
        CodexWorkerResult(
            returncode=0,
            stdout="Logged in using ChatGPT token=must-not-parse",
            stderr="",
            process_tree_exit_verified=True,
        )
    )
    assert (
        CodexSubscriptionWorker(
            environment=environment,
            runner=forged,
        ).probe_status()
        == "unavailable"
    )


def test_status_probe_accepts_current_official_stderr_login_banner(
    tmp_path: Path,
) -> None:
    environment, _ = _environment(tmp_path)
    runner = _Runner(
        CodexWorkerResult(
            returncode=0,
            stdout="",
            stderr="Logged in using ChatGPT\n",
            process_tree_exit_verified=True,
        )
    )

    assert (
        CodexSubscriptionWorker(
            environment=environment,
            runner=runner,
        ).probe_status()
        == "authenticated_unprobed"
    )


def test_invoke_keeps_prompt_out_of_argv_and_requires_read_only_ephemeral_mode(
    tmp_path: Path,
) -> None:
    environment, executable = _environment(tmp_path)
    prompt = "PRIVATE-PROMPT-DO-NOT-PUT-IN-ARGV"
    runner = _Runner(
        CodexWorkerResult(
            returncode=0,
            stdout=_success_jsonl("safe response"),
            stderr="progress is not protocol",
            process_tree_exit_verified=True,
        )
    )
    worker = CodexSubscriptionWorker(environment=environment, runner=runner)

    result = worker.invoke(prompt)

    assert result.text == "safe response"
    assert result.thread_id == "thread_123"
    assert result.prompt_tokens == 9
    assert result.cached_tokens == 2
    assert result.completion_tokens == 4
    request = runner.requests[0]
    argv = codex_cli_argv(request, tmp_path / "blank")
    assert argv == (
        str(executable),
        "exec",
        "--json",
        "--ephemeral",
        "--ignore-user-config",
        "--ignore-rules",
        "--sandbox",
        "read-only",
        "--skip-git-repo-check",
        "-C",
        str(tmp_path / "blank"),
        "-",
    )
    assert prompt not in argv
    assert "--model" not in argv
    assert prompt not in repr(request)
    assert request.prompt_bytes() == prompt.encode("utf-8")


@pytest.mark.parametrize(
    "stdout",
    [
        '{"type":"thread.started","thread_id":"thread_1","thread_id":"thread_2"}',
        '{"type":"unknown.future.event"}',
        "\n".join(
            [
                '{"type":"thread.started","thread_id":"thread_1"}',
                '{"type":"turn.started"}',
                (
                    '{"type":"item.completed","item":'
                    '{"id":"i","type":"agent_message","text":"reply"}}'
                ),
            ]
        ),
    ],
)
def test_invoke_fails_closed_on_ambiguous_or_incomplete_jsonl(
    tmp_path: Path,
    stdout: str,
) -> None:
    environment, _ = _environment(tmp_path)
    worker = CodexSubscriptionWorker(
        environment=environment,
        runner=_Runner(
            CodexWorkerResult(
                returncode=0,
                stdout=stdout,
                stderr="",
                process_tree_exit_verified=True,
            )
        ),
    )

    with pytest.raises(CodexSubscriptionError) as caught:
        worker.invoke("hello")

    assert caught.value.code == "protocol_rejected"
    assert "hello" not in str(caught.value)
    assert stdout not in str(caught.value)


def test_worker_refuses_unverified_process_cleanup_even_after_valid_output(
    tmp_path: Path,
) -> None:
    environment, _ = _environment(tmp_path)
    worker = CodexSubscriptionWorker(
        environment=environment,
        runner=_Runner(
            CodexWorkerResult(
                returncode=0,
                stdout=_success_jsonl(),
                stderr="",
                process_tree_exit_verified=False,
            )
        ),
    )

    with pytest.raises(CodexSubscriptionError) as caught:
        worker.invoke("hello")

    assert caught.value.code == "process_cleanup_unverified"


def test_worker_rechecks_attestation_before_every_operation(tmp_path: Path) -> None:
    environment, executable = _environment(tmp_path)
    runner = _Runner(
        CodexWorkerResult(
            returncode=0,
            stdout="Logged in using ChatGPT\n",
            stderr="",
            process_tree_exit_verified=True,
        )
    )
    worker = CodexSubscriptionWorker(environment=environment, runner=runner)
    executable.write_bytes(_fake_pe(b"replacement"))

    assert worker.probe_status() == "untrusted_binary"
    assert runner.requests == []


def test_worker_environment_is_secret_free_but_keeps_login_store_pointers() -> None:
    child = codex_worker_environment(
        {
            "USERPROFILE": r"C:\Users\owner",
            "APPDATA": r"C:\Users\owner\AppData\Roaming",
            "LOCALAPPDATA": r"C:\Users\owner\AppData\Local",
            "CODEX_HOME": r"C:\Users\owner\.codex",
            "SYSTEMROOT": r"C:\Windows",
            "PATH": r"C:\safe",
            "OPENAI_API_KEY": "sk-secret",
            "NACHUAN_API_KEY": "runtime-secret",
            "VOLCANO_API_KEY": "provider-secret",
            "HTTPS_PROXY": "http://user:password@proxy",
            "BASH_ENV": r"C:\evil.sh",
            "NODE_OPTIONS": "--require C:\\evil.js",
        }
    )

    assert child["CODEX_HOME"] == r"C:\Users\owner\.codex"
    assert child["USERPROFILE"] == r"C:\Users\owner"
    assert child["NO_COLOR"] == "1"
    for forbidden in (
        "OPENAI_API_KEY",
        "NACHUAN_API_KEY",
        "VOLCANO_API_KEY",
        "HTTPS_PROXY",
        "BASH_ENV",
        "NODE_OPTIONS",
    ):
        assert forbidden not in child


def test_prompt_size_is_bounded_before_runner_or_cli_start(tmp_path: Path) -> None:
    environment, _ = _environment(tmp_path)
    runner = _Runner()
    worker = CodexSubscriptionWorker(environment=environment, runner=runner)

    with pytest.raises(CodexSubscriptionError) as caught:
        worker.invoke("x" * (4 * 1024 * 1024 + 1))

    assert caught.value.code == "prompt_size_rejected"
    assert runner.requests == []


def test_default_runner_uses_dedicated_temp_root_and_drops_parent_secrets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment, _ = _environment(tmp_path)
    runtime_root = tmp_path / "subscription-cli-runtime"
    runtime_root.mkdir()
    environment["CODEX_CLI_TEMP_ROOT"] = str(runtime_root)
    environment["OPENAI_API_KEY"] = "must-not-inherit"
    captured: list[dict[str, str]] = []

    def fake_run(request, *, source_environment):
        del request
        captured.append(dict(source_environment))
        return CodexWorkerResult(
            returncode=0,
            stdout="Logged in using ChatGPT\n",
            stderr="",
            process_tree_exit_verified=True,
        )

    monkeypatch.setattr(
        "cli.codex_worker_entrypoint.run_codex_worker_request",
        fake_run,
    )

    worker = CodexSubscriptionWorker(environment=environment)

    assert worker.probe_status() == "authenticated_unprobed"
    assert captured == [
        {
            key: value
            for key, value in codex_worker_environment(
                {
                    **environment,
                    "TEMP": str(runtime_root),
                    "TMP": str(runtime_root),
                }
            ).items()
        }
    ]
    assert "OPENAI_API_KEY" not in captured[0]
    assert captured[0]["TEMP"] == str(runtime_root)
    assert captured[0]["TMP"] == str(runtime_root)
