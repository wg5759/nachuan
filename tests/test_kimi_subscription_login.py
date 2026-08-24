from __future__ import annotations

import builtins
import hashlib
import os
from pathlib import Path
from typing import Any

import pytest

from gateway.kimi_subscription_login import (
    KimiAuthProbeResult,
    KimiLoginRequest,
    KimiLoginResult,
    KimiSubscriptionLoginController,
    KimiSubscriptionLoginError,
    kimi_login_argv,
)
from gateway.kimi_subscription_worker import kimi_worker_environment


def _write_fake_pe(path: Path, marker: bytes = b"kimi-login") -> None:
    header = bytearray(512)
    header[:2] = b"MZ"
    header[0x3C:0x40] = (128).to_bytes(4, "little")
    header[128:132] = b"PE\0\0"
    header[160 : 160 + len(marker)] = marker
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(bytes(header))


def _overlay(tmp_path: Path) -> tuple[dict[str, str], Path]:
    executable = tmp_path / "official" / "kimi.exe"
    _write_fake_pe(executable)
    kimi_home = tmp_path / "protected" / "kimi-code-home"
    temp_root = tmp_path / "protected" / "runtime" / "kimi-code"
    kimi_home.mkdir(parents=True)
    temp_root.mkdir(parents=True)
    return (
        {
            "KIMI_CLI_PATH": str(executable.resolve()),
            "KIMI_CLI_SHA256": hashlib.sha256(
                executable.read_bytes()
            ).hexdigest(),
            "KIMI_CLI_VERSION": "0.27.0",
            "KIMI_CODE_HOME": str(kimi_home.resolve()),
            "KIMI_CLI_TEMP_ROOT": str(temp_root.resolve()),
            # These are deliberately hostile ambient values.  None may cross
            # the protected-overlay boundary into the child.
            "PATH": str(tmp_path / "path-trap"),
            "USERPROFILE": r"C:\Users\ambient-owner",
            "HOME": r"C:\Users\ambient-owner",
            "KIMI_API_KEY": "ambient-provider-secret",
            "KIMI_CODE_BASE_URL": "https://evil.invalid",
            "HTTPS_PROXY": "http://user:password@proxy.invalid",
            "BASH_ENV": r"C:\evil.sh",
            "NODE_OPTIONS": "--require=C:\\evil.js",
            "NODE_EXTRA_CA_CERTS": r"C:\evil-ca.pem",
            "NACHUAN_GATEWAY_KEY": "ambient-gateway-secret",
        },
        executable,
    )


def _success() -> KimiLoginResult:
    return KimiLoginResult(
        returncode=0,
        timed_out=False,
        cancelled=False,
        process_tree_exit_verified=True,
    )


class _Runner:
    def __init__(self, result: KimiLoginResult) -> None:
        self.result = result
        self.requests: list[KimiLoginRequest] = []
        self.environments: list[dict[str, str]] = []

    def __call__(
        self,
        request: KimiLoginRequest,
        *,
        environment: dict[str, str],
    ) -> KimiLoginResult:
        self.requests.append(request)
        self.environments.append(dict(environment))
        return self.result


class _AuthProbe:
    def __init__(self, result: KimiAuthProbeResult) -> None:
        self.result = result
        self.requests: list[KimiLoginRequest] = []
        self.environments: list[dict[str, str]] = []

    def __call__(
        self,
        request: KimiLoginRequest,
        *,
        environment: dict[str, str],
    ) -> KimiAuthProbeResult:
        self.requests.append(request)
        self.environments.append(dict(environment))
        return self.result


def _present_auth_probe() -> _AuthProbe:
    return _AuthProbe(
        KimiAuthProbeResult(
            token_present=True,
            returncode=0,
            timed_out=False,
            process_tree_exit_verified=True,
        )
    )


def test_status_uses_independent_prompt_free_auth_probe(
    tmp_path: Path,
) -> None:
    overlay, _ = _overlay(tmp_path)
    runner = _Runner(_success())
    auth_probe = _AuthProbe(
        KimiAuthProbeResult(
            token_present=True,
            returncode=0,
            timed_out=False,
            process_tree_exit_verified=True,
        )
    )
    controller = KimiSubscriptionLoginController(
        protected_overlay=overlay,
        runner=runner,
        auth_probe=auth_probe,
    )

    assert controller.probe_status() == "authenticated_unprobed"
    assert runner.requests == []
    assert len(auth_probe.requests) == 1
    assert auth_probe.environments == [kimi_worker_environment(overlay)]


def test_nonzero_login_preserves_failure_even_when_new_token_appears(
    tmp_path: Path,
) -> None:
    overlay, _ = _overlay(tmp_path)
    login_runner = _Runner(
        KimiLoginResult(
            returncode=1,
            timed_out=False,
            cancelled=False,
            process_tree_exit_verified=True,
        )
    )
    probe_results = iter(
        [
            KimiAuthProbeResult(
                token_present=False,
                returncode=0,
                timed_out=False,
                process_tree_exit_verified=True,
            ),
            KimiAuthProbeResult(
                token_present=True,
                returncode=0,
                timed_out=False,
                process_tree_exit_verified=True,
            ),
        ]
    )
    observed: list[KimiLoginRequest] = []

    def auth_probe(
        request: KimiLoginRequest,
        *,
        environment: dict[str, str],
    ) -> KimiAuthProbeResult:
        assert environment == kimi_worker_environment(overlay)
        observed.append(request)
        return next(probe_results)

    controller = KimiSubscriptionLoginController(
        protected_overlay=overlay,
        runner=login_runner,
        auth_probe=auth_probe,
    )

    with pytest.raises(
        KimiSubscriptionLoginError,
        match="login_process_failed_token_present",
    ):
        controller.login()

    assert len(login_runner.requests) == 1
    assert len(observed) == 2


def test_login_uses_only_bound_executable_and_same_product_home(
    tmp_path: Path,
) -> None:
    overlay, executable = _overlay(tmp_path)
    trap = Path(overlay["PATH"]) / "kimi.exe"
    _write_fake_pe(trap, b"path-trap")
    runner = _Runner(_success())
    controller = KimiSubscriptionLoginController(
        protected_overlay=overlay,
        runner=runner,
        auth_probe=_present_auth_probe(),
    )

    state = controller.login()

    assert state == "authenticated_unprobed"
    assert len(runner.requests) == 1
    request = runner.requests[0]
    assert kimi_login_argv(request) == (str(executable.resolve()), "login")
    assert str(trap.resolve()) not in kimi_login_argv(request)
    assert request.executable_version == "0.27.0"
    assert request.kimi_code_home == str(
        Path(overlay["KIMI_CODE_HOME"]).resolve(strict=True)
    )
    assert str(executable.resolve()) not in repr(request)
    assert overlay["KIMI_CLI_SHA256"] not in repr(request)
    assert overlay["KIMI_CODE_HOME"] not in repr(request)

    child = runner.environments[0]
    assert child == kimi_worker_environment(overlay)
    assert child["KIMI_CODE_HOME"] == request.kimi_code_home
    serialized = "\0".join(f"{key}={value}" for key, value in child.items())
    for forbidden in (
        "ambient-provider-secret",
        "ambient-gateway-secret",
        "ambient-owner",
        "proxy.invalid",
        "evil.invalid",
        "evil.sh",
        "evil.js",
        "evil-ca.pem",
        str(trap.resolve()),
    ):
        assert forbidden not in serialized


def test_default_controller_delegates_to_contained_login_runner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    overlay, _ = _overlay(tmp_path)
    observed: list[tuple[KimiLoginRequest, dict[str, str]]] = []

    def fake_default_runner(
        request: KimiLoginRequest,
        *,
        environment: dict[str, str],
    ) -> KimiLoginResult:
        observed.append((request, dict(environment)))
        return _success()

    monkeypatch.setattr(
        "gateway.kimi_subscription_login._default_login_runner",
        fake_default_runner,
        raising=False,
    )

    controller = KimiSubscriptionLoginController(
        protected_overlay=overlay,
        auth_probe=_present_auth_probe(),
    )

    assert controller.login() == "authenticated_unprobed"
    assert len(observed) == 1
    assert kimi_login_argv(observed[0][0]) == (
        overlay["KIMI_CLI_PATH"],
        "login",
    )
    assert observed[0][1] == kimi_worker_environment(overlay)


def test_executable_is_pinned_for_the_entire_runner_call(tmp_path: Path) -> None:
    overlay, executable = _overlay(tmp_path)

    class PinProbeRunner(_Runner):
        replacement_blocked = False

        def __call__(
            self,
            request: KimiLoginRequest,
            *,
            environment: dict[str, str],
        ) -> KimiLoginResult:
            try:
                executable.write_bytes(b"replacement")
            except OSError:
                self.replacement_blocked = True
            return super().__call__(request, environment=environment)

    runner = PinProbeRunner(_success())
    controller = KimiSubscriptionLoginController(
        protected_overlay=overlay,
        runner=runner,
        auth_probe=_present_auth_probe(),
    )

    assert controller.login() == "authenticated_unprobed"
    assert runner.replacement_blocked is True
    assert hashlib.sha256(executable.read_bytes()).hexdigest() == overlay[
        "KIMI_CLI_SHA256"
    ]


def test_every_login_rechecks_binary_attestation_before_runner(
    tmp_path: Path,
) -> None:
    overlay, executable = _overlay(tmp_path)
    runner = _Runner(_success())
    controller = KimiSubscriptionLoginController(
        protected_overlay=overlay,
        runner=runner,
        auth_probe=_present_auth_probe(),
    )

    assert controller.login() == "authenticated_unprobed"
    executable.write_bytes(executable.read_bytes() + b"changed-after-first-call")

    with pytest.raises(KimiSubscriptionLoginError, match="binary_untrusted"):
        controller.login()

    assert len(runner.requests) == 1


@pytest.mark.parametrize(
    "relative",
    ["AGENTS.md", "mcp.json", "skills", "plugins"],
)
def test_active_product_configuration_is_rejected_before_login(
    tmp_path: Path,
    relative: str,
) -> None:
    overlay, _ = _overlay(tmp_path)
    target = Path(overlay["KIMI_CODE_HOME"]) / relative
    if "." in target.name:
        target.write_text("untrusted active configuration", encoding="utf-8")
    else:
        target.mkdir()
    runner = _Runner(_success())
    controller = KimiSubscriptionLoginController(
        protected_overlay=overlay,
        runner=runner,
    )

    with pytest.raises(
        KimiSubscriptionLoginError,
        match="active_config_surface_rejected",
    ):
        controller.login()

    assert runner.requests == []


@pytest.mark.parametrize(
    ("result", "code"),
    [
        (
            KimiLoginResult(
                returncode=1,
                timed_out=False,
                cancelled=False,
                process_tree_exit_verified=True,
            ),
            "login_failed",
        ),
        (
            KimiLoginResult(
                returncode=124,
                timed_out=True,
                cancelled=False,
                process_tree_exit_verified=True,
            ),
            "login_timeout",
        ),
        (
            KimiLoginResult(
                returncode=0,
                timed_out=False,
                cancelled=True,
                process_tree_exit_verified=True,
            ),
            "login_cancelled",
        ),
        (
            KimiLoginResult(
                returncode=0,
                timed_out=False,
                cancelled=False,
                process_tree_exit_verified=False,
            ),
            "process_cleanup_unverified",
        ),
    ],
)
def test_nonzero_timeout_cancel_and_unverified_cleanup_fail_closed(
    tmp_path: Path,
    result: KimiLoginResult,
    code: str,
) -> None:
    overlay, _ = _overlay(tmp_path)
    controller = KimiSubscriptionLoginController(
        protected_overlay=overlay,
        runner=_Runner(result),
        auth_probe=_present_auth_probe(),
    )

    with pytest.raises(KimiSubscriptionLoginError, match=code):
        controller.login()


def test_login_never_reads_or_parses_vendor_auth_material(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    overlay, _ = _overlay(tmp_path)
    kimi_home = Path(overlay["KIMI_CODE_HOME"])
    protected_files = {
        (kimi_home / name).resolve()
        for name in ("credentials.json", "oauth.json", "token.json")
    }
    for path in protected_files:
        path.write_text("DO_NOT_READ_VENDOR_AUTH_MATERIAL", encoding="utf-8")

    original_path_open = Path.open
    original_builtin_open = builtins.open

    def guarded_path_open(
        self: Path,
        *args: Any,
        **kwargs: Any,
    ):
        if self.resolve() in protected_files:
            raise AssertionError("vendor auth material was opened")
        return original_path_open(self, *args, **kwargs)

    def guarded_builtin_open(
        file: Any,
        *args: Any,
        **kwargs: Any,
    ):
        try:
            candidate = Path(file).resolve()
        except (OSError, TypeError, ValueError):
            candidate = None
        if candidate in protected_files:
            raise AssertionError("vendor auth material was opened")
        return original_builtin_open(file, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded_path_open)
    monkeypatch.setattr(builtins, "open", guarded_builtin_open)
    runner = _Runner(_success())
    controller = KimiSubscriptionLoginController(
        protected_overlay=overlay,
        runner=runner,
        auth_probe=_present_auth_probe(),
    )

    assert controller.login() == "authenticated_unprobed"
    assert len(runner.requests) == 1


def test_login_product_module_has_no_review_adapter_dependency() -> None:
    source = (
        Path(__file__).parents[1]
        / "gateway"
        / "kimi_subscription_login.py"
    ).read_text(encoding="utf-8")
    assert "scripts.kimi_acp_private_client" not in source
    assert "xreview" not in source.lower()
    assert "wire.jsonl" not in source.lower()
