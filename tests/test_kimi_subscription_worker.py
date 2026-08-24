from __future__ import annotations

import hashlib
import threading
from pathlib import Path

import pytest

import gateway.kimi_subscription_worker as worker_module
from gateway.kimi_subscription_worker import (
    KimiSubscriptionError,
    KimiSubscriptionWorker,
    KimiWorkerRequest,
    KimiWorkerResult,
    kimi_cli_argv,
    kimi_worker_environment,
)


def _write_fake_pe(path: Path) -> None:
    header = bytearray(512)
    header[:2] = b"MZ"
    header[0x3C:0x40] = (128).to_bytes(4, "little")
    header[128:132] = b"PE\0\0"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(bytes(header))


def _environment(tmp_path: Path) -> tuple[dict[str, str], Path]:
    executable = tmp_path / "official" / "kimi.exe"
    _write_fake_pe(executable)
    kimi_home = tmp_path / "data" / "subscription-kimi-code-home"
    temp_root = tmp_path / "data" / "subscription-cli-runtime" / "kimi-code"
    kimi_home.mkdir(parents=True)
    temp_root.mkdir(parents=True)
    system_root = Path("C:/Windows")
    environment = {
        "KIMI_CLI_PATH": str(executable.resolve()),
        "KIMI_CLI_SHA256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        "KIMI_CLI_VERSION": "0.27.0",
        "KIMI_CODE_HOME": str(kimi_home.resolve()),
        "KIMI_CLI_TEMP_ROOT": str(temp_root.resolve()),
        "SYSTEMROOT": str(system_root),
        "WINDIR": str(system_root),
        "SYSTEMDRIVE": "C:",
        "COMSPEC": str(system_root / "System32" / "cmd.exe"),
        "PATH": r"C:\malicious-bin",
        "USERPROFILE": r"C:\Users\real-owner",
        "HOME": r"C:\Users\real-owner",
        "APPDATA": r"C:\Users\real-owner\AppData\Roaming",
        "LOCALAPPDATA": r"C:\Users\real-owner\AppData\Local",
        "HTTPS_PROXY": "http://user:secret@proxy.invalid",
        "KIMI_API_KEY": "must-not-inherit",
        "KIMI_MODEL_API_KEY": "must-not-inherit",
        "KIMI_CODE_OAUTH_HOST": "https://evil.invalid",
        "KIMI_CODE_BASE_URL": "https://evil.invalid",
        "NACHUAN_GATEWAY_KEY": "must-not-inherit",
        "XREVIEW_SECRET": "must-not-inherit",
        "BASH_ENV": r"C:\evil.sh",
        "NODE_OPTIONS": "--require=C:\\evil.js",
        "NODE_EXTRA_CA_CERTS": r"C:\evil-ca.pem",
    }
    return environment, executable


class _Runner:
    def __init__(self, result: KimiWorkerResult) -> None:
        self.result = result
        self.requests: list[KimiWorkerRequest] = []

    def __call__(self, request: KimiWorkerRequest) -> KimiWorkerResult:
        self.requests.append(request)
        return self.result


def _success(text: str = "NACHUAN_KIMI_OK") -> KimiWorkerResult:
    return KimiWorkerResult(
        returncode=0,
        text=text,
        session_id="session-0123456789abcdef",
        stop_reason="end_turn",
        actual_served_model=None,
        tool_activity_observed=False,
        process_tree_exit_verified=True,
    )


def test_invoke_keeps_prompt_out_of_argv_and_exposes_only_generic_model(
    tmp_path: Path,
) -> None:
    environment, executable = _environment(tmp_path)
    runner = _Runner(_success())
    worker = KimiSubscriptionWorker(environment=environment, runner=runner)
    prompt = "PRIVATE_PRODUCT_PROMPT_不进入命令行"

    result = worker.invoke(prompt)

    assert result.text == "NACHUAN_KIMI_OK"
    assert result.session_id == "session-0123456789abcdef"
    assert result.model_id == "kimi-code-subscription"
    assert result.actual_served_model is None
    assert len(runner.requests) == 1
    request = runner.requests[0]
    assert kimi_cli_argv(request) == (str(executable.resolve()), "acp")
    assert prompt not in "\0".join(kimi_cli_argv(request))
    assert prompt not in repr(request)
    assert environment["KIMI_CLI_SHA256"] not in repr(request)
    assert request.bound_version == "0.27.0"


@pytest.mark.parametrize("version", ["", "v0.27.0", "0.27", "0.27.0 extra"])
def test_worker_requires_exact_protected_manifest_version(
    tmp_path: Path,
    version: str,
) -> None:
    environment, _ = _environment(tmp_path)
    environment["KIMI_CLI_VERSION"] = version
    runner = _Runner(_success())
    worker = KimiSubscriptionWorker(environment=environment, runner=runner)

    with pytest.raises(KimiSubscriptionError, match="binding_version_rejected"):
        worker.invoke("hello")

    assert runner.requests == []


def test_worker_environment_rehomes_all_profile_paths_and_drops_ambient_inputs(
    tmp_path: Path,
) -> None:
    source, _ = _environment(tmp_path)

    child = kimi_worker_environment(source)

    private_home = (
        Path(source["KIMI_CLI_TEMP_ROOT"]) / "os-home"
    ).resolve(strict=True)
    assert child == {
        "SYSTEMROOT": r"C:\Windows",
        "WINDIR": r"C:\Windows",
        "SYSTEMDRIVE": "C:",
        "COMSPEC": r"C:\Windows\System32\cmd.exe",
        "PATH": r"C:\Windows\System32",
        "PATHEXT": ".COM;.EXE",
        "HOME": str(private_home),
        "USERPROFILE": str(private_home),
        "APPDATA": str((private_home / "AppData" / "Roaming").resolve(strict=True)),
        "LOCALAPPDATA": str(
            (private_home / "AppData" / "Local").resolve(strict=True)
        ),
        "KIMI_CLI_TEMP_ROOT": str(
            Path(source["KIMI_CLI_TEMP_ROOT"]).resolve(strict=True)
        ),
        "TEMP": str(Path(source["KIMI_CLI_TEMP_ROOT"]).resolve(strict=True)),
        "TMP": str(Path(source["KIMI_CLI_TEMP_ROOT"]).resolve(strict=True)),
        "KIMI_CODE_HOME": str(Path(source["KIMI_CODE_HOME"]).resolve(strict=True)),
        "KIMI_DISABLE_TELEMETRY": "1",
        "KIMI_CODE_NO_AUTO_UPDATE": "1",
        "KIMI_DISABLE_CRON": "1",
        "KIMI_CODE_BACKGROUND_KEEP_ALIVE_ON_EXIT": "0",
        "KIMI_LOG_LEVEL": "off",
        "NO_COLOR": "1",
        "CI": "1",
    }
    serialized = "\0".join(f"{key}={value}" for key, value in child.items())
    for secret in (
        "must-not-inherit",
        "proxy.invalid",
        "real-owner",
        "evil.invalid",
        "evil.sh",
        "evil.js",
        "evil-ca.pem",
        "XREVIEW",
    ):
        assert secret not in serialized
    assert not (private_home / ".agents").exists()


def test_worker_environment_can_be_reapplied_by_the_fixed_child_helper(
    tmp_path: Path,
) -> None:
    source, _ = _environment(tmp_path)

    child = kimi_worker_environment(source)

    assert kimi_worker_environment(child) == child


@pytest.mark.parametrize(
    ("result", "code"),
    [
        (
            KimiWorkerResult(
                0,
                "valid",
                "session-valid",
                "end_turn",
                None,
                False,
                False,
            ),
            "process_cleanup_unverified",
        ),
        (
            KimiWorkerResult(
                0,
                "valid",
                "session-valid",
                "refusal",
                None,
                False,
                True,
            ),
            "stop_reason_rejected",
        ),
        (
            KimiWorkerResult(
                0,
                "valid",
                "session-valid",
                "end_turn",
                "k3",
                False,
                True,
            ),
            "served_model_receipt_unverified",
        ),
        (
            KimiWorkerResult(
                0,
                "valid",
                "session-valid",
                "end_turn",
                None,
                True,
                True,
            ),
            "tool_activity_rejected",
        ),
        (
            KimiWorkerResult(
                70,
                "",
                "",
                "",
                None,
                False,
                True,
            ),
            "cli_failed",
        ),
    ],
)
def test_worker_rejects_unclosed_or_overclaimed_results(
    tmp_path: Path,
    result: KimiWorkerResult,
    code: str,
) -> None:
    environment, _ = _environment(tmp_path)
    worker = KimiSubscriptionWorker(
        environment=environment,
        runner=_Runner(result),
    )

    with pytest.raises(KimiSubscriptionError, match=code):
        worker.invoke("hello")


def test_worker_surfaces_only_stable_inner_failure_code(
    tmp_path: Path,
) -> None:
    environment, _ = _environment(tmp_path)
    prompt = "PRIVATE_PROMPT_MUST_NOT_LEAK"
    remote_detail = "REMOTE_MESSAGE_AND_DATA_MUST_NOT_LEAK"
    result = KimiWorkerResult(
        returncode=70,
        text=remote_detail,
        session_id="",
        stop_reason="",
        actual_served_model=None,
        tool_activity_observed=False,
        process_tree_exit_verified=True,
        failure_code="auth_required",
    )
    worker = KimiSubscriptionWorker(
        environment=environment,
        runner=_Runner(result),
    )

    with pytest.raises(KimiSubscriptionError) as caught:
        worker.invoke(prompt)

    assert caught.value.code == "auth_required"
    assert str(caught.value) == "auth_required"
    assert prompt not in repr(caught.value)
    assert remote_detail not in repr(caught.value)


def test_binary_replacement_is_rejected_before_runner(tmp_path: Path) -> None:
    environment, executable = _environment(tmp_path)
    runner = _Runner(_success())
    executable.write_bytes(executable.read_bytes() + b"changed")
    worker = KimiSubscriptionWorker(environment=environment, runner=runner)

    with pytest.raises(KimiSubscriptionError, match="binary_untrusted"):
        worker.invoke("hello")

    assert runner.requests == []


def test_prompt_is_bounded_before_runner(tmp_path: Path) -> None:
    environment, _ = _environment(tmp_path)
    runner = _Runner(_success())
    worker = KimiSubscriptionWorker(environment=environment, runner=runner)

    with pytest.raises(KimiSubscriptionError, match="prompt_size_rejected"):
        worker.invoke("")
    with pytest.raises(KimiSubscriptionError, match="prompt_size_rejected"):
        worker.invoke("x" * (4 * 1024 * 1024 + 1))

    assert runner.requests == []


def test_default_worker_passes_external_cancellation_event(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment, _ = _environment(tmp_path)
    cancellation_event = threading.Event()
    observed: list[threading.Event | None] = []

    def fake_default_runner(
        request: KimiWorkerRequest,
        source_environment,
        *,
        cancellation_event=None,
    ) -> KimiWorkerResult:
        del request, source_environment
        observed.append(cancellation_event)
        return _success()

    monkeypatch.setattr(worker_module, "_default_runner", fake_default_runner)
    worker = KimiSubscriptionWorker(environment=environment)

    assert worker.invoke(
        "hello",
        cancellation_event=cancellation_event,
    ).text == "NACHUAN_KIMI_OK"
    assert observed == [cancellation_event]


@pytest.mark.parametrize(
    "relative",
    [
        "AGENTS.md",
        "mcp.json",
        "skills",
        "plugins",
    ],
)
def test_active_instruction_surfaces_in_product_home_fail_closed(
    tmp_path: Path,
    relative: str,
) -> None:
    environment, _ = _environment(tmp_path)
    target = Path(environment["KIMI_CODE_HOME"]) / relative
    if "." in target.name:
        target.write_text("untrusted active configuration", encoding="utf-8")
    else:
        target.mkdir()
    runner = _Runner(_success())
    worker = KimiSubscriptionWorker(environment=environment, runner=runner)

    with pytest.raises(
        KimiSubscriptionError,
        match="active_config_surface_rejected",
    ):
        worker.invoke("hello")

    assert runner.requests == []


def test_product_worker_does_not_import_review_or_xreview_modules() -> None:
    source = (
        Path(__file__).parents[1]
        / "gateway"
        / "kimi_subscription_worker.py"
    ).read_text(encoding="utf-8")
    assert "scripts.kimi_acp_private_client" not in source
    assert "xreview" not in source.lower()
