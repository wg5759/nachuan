from __future__ import annotations

import io
from pathlib import Path

import pytest

import cli.kimi_auth_probe_entrypoint as entrypoint
from cli.kimi_auth_probe_entrypoint import run_kimi_auth_probe_request
from gateway.kimi_acp_auth_probe_protocol import KimiAcpAuthProbeResult
from gateway.kimi_subscription_login import (
    KimiAuthProbeResult,
    KimiLoginRequest,
)
from gateway.kimi_subscription_worker import kimi_worker_environment


def test_probe_auth_is_prompt_free_and_uses_exact_acp_argv(
    tmp_path: Path,
) -> None:
    executable = (tmp_path / "official" / "kimi.exe").resolve()
    executable.parent.mkdir()
    executable.write_bytes(b"MZ")
    kimi_home = (tmp_path / "profile").resolve()
    temp_root = (tmp_path / "runtime").resolve()
    kimi_home.mkdir()
    temp_root.mkdir()
    environment = kimi_worker_environment(
        {
            "KIMI_CLI_PATH": str(executable),
            "KIMI_CLI_SHA256": "a" * 64,
            "KIMI_CLI_VERSION": "0.27.0",
            "KIMI_CODE_HOME": str(kimi_home),
            "KIMI_CLI_TEMP_ROOT": str(temp_root),
        }
    )
    request = KimiLoginRequest(
        executable_path=str(executable),
        executable_sha256="a" * 64,
        executable_version="0.27.0",
        kimi_code_home=str(kimi_home),
        timeout_seconds=10.0,
    )
    observed: list[tuple[tuple[str, ...], Path, dict[str, str], float, str]] = []

    def process_runner(
        argv: tuple[str, ...],
        *,
        cwd: Path,
        environment: dict[str, str],
        timeout_seconds: float,
        bound_version: str,
    ) -> KimiAuthProbeResult:
        observed.append(
            (argv, cwd, dict(environment), timeout_seconds, bound_version)
        )
        assert cwd.is_dir()
        assert list(cwd.iterdir()) == []
        return KimiAuthProbeResult(
            token_present=True,
            returncode=0,
            timed_out=False,
            process_tree_exit_verified=True,
        )

    result = run_kimi_auth_probe_request(
        request,
        environment=environment,
        process_runner=process_runner,
    )

    assert result.token_present is True
    assert observed == [
        (
            (str(executable), "acp"),
            observed[0][1],
            environment,
            10.0,
            "0.27.0",
        )
    ]


def test_default_probe_transport_requires_clean_process_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeProcess:
        def __init__(self) -> None:
            self.stdin = io.BytesIO()
            self.stdout = io.BytesIO()
            self.stderr = io.BytesIO()
            self.pid = 1234
            self.returncode: int | None = 0

        def poll(self) -> int | None:
            return self.returncode

    process = FakeProcess()
    observed: dict[str, object] = {}
    monkeypatch.setattr(
        entrypoint,
        "_spawn_contained_process",
        lambda argv, **kwargs: (
            observed.update(argv=argv, **kwargs) or (process, None, process.pid)
        ),
    )
    monkeypatch.setattr(
        entrypoint,
        "run_kimi_acp_auth_probe_protocol",
        lambda request, channel: (
            observed.update(request=request, channel=channel)
            or KimiAcpAuthProbeResult(token_present=True)
        ),
    )
    monkeypatch.setattr(
        entrypoint,
        "_wait_contained_tree_empty",
        lambda *_args, **_kwargs: True,
    )

    result = entrypoint._run_acp_auth_probe_process(
        (r"C:\fixed\kimi.exe", "acp"),
        cwd=tmp_path,
        environment={},
        timeout_seconds=3.0,
        bound_version="0.27.0",
    )

    assert result == KimiAuthProbeResult(
        token_present=True,
        returncode=0,
        timed_out=False,
        process_tree_exit_verified=True,
    )
    assert observed["argv"] == (r"C:\fixed\kimi.exe", "acp")
    assert not hasattr(result, "stderr")


def test_default_probe_transport_fails_when_tree_does_not_empty(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeProcess:
        def __init__(self) -> None:
            self.stdin = io.BytesIO()
            self.stdout = io.BytesIO()
            self.stderr = io.BytesIO()
            self.pid = 1234
            self.returncode: int | None = 0

        def poll(self) -> int | None:
            return self.returncode

    process = FakeProcess()
    monkeypatch.setattr(
        entrypoint,
        "_spawn_contained_process",
        lambda *_args, **_kwargs: (process, None, process.pid),
    )
    monkeypatch.setattr(
        entrypoint,
        "run_kimi_acp_auth_probe_protocol",
        lambda *_args, **_kwargs: KimiAcpAuthProbeResult(
            token_present=True
        ),
    )
    monkeypatch.setattr(
        entrypoint,
        "_wait_contained_tree_empty",
        lambda *_args, **_kwargs: False,
    )
    monkeypatch.setattr(
        entrypoint,
        "_kill_contained_process_tree",
        lambda *_args, **_kwargs: True,
    )

    with pytest.raises(
        RuntimeError,
        match="auth_probe_process_cleanup_unverified",
    ):
        entrypoint._run_acp_auth_probe_process(
            (r"C:\fixed\kimi.exe", "acp"),
            cwd=tmp_path,
            environment={},
            timeout_seconds=3.0,
            bound_version="0.27.0",
        )
