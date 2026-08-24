"""订阅连接 actual-served 身份回执与官方 CLI 退出状态如实上报。

边界（上游线文事实，2026-08-18 复核）：
- Codex CLI 0.144.x `codex exec --json` 的 ThreadEvent 闭集
  （codex-rs/exec/src/exec_events.rs @ rust-v0.144.5）不含任何 model 字段；
- Kimi Code 0.27 ACP initialize/session-new/prompt 响应精确键集同样不含
  实际服役模型字段（gateway/kimi_acp_product_protocol.py 的闭管道校验）。

因此连接验证时持久化的回执只能如实记 `unproven`；配置别名/自报型号永远
不得充当 actual-served 证据。Codex 退出必须经官方 `codex logout` 并以退出后
官方 `login status` 复核为准；Kimi 官方 CLI 无 headless logout，如实拒绝。
"""

from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cli.codex_worker_entrypoint import _decode_request, _encode_request
from cli.nachuan import EXIT_OK, EXIT_REFUSED, EXIT_UNAVAILABLE, run
from gateway import admin, catalog
from gateway.auth import require_api_key, require_approval_admin_key
from gateway.codex_subscription_worker import (
    CodexSubscriptionError,
    CodexSubscriptionWorker,
    CodexWorkerRequest,
    CodexWorkerResult,
    codex_cli_argv,
)
from gateway.connections import ConnectionStore, normalize_connection_candidate
from gateway.providers.codex import CodexProvider
from gateway.providers.kimi_subscription import KimiSubscriptionProvider


def _fake_pe(marker: bytes) -> bytes:
    payload = bytearray(160)
    payload[:2] = b"MZ"
    payload[0x3C:0x40] = (64).to_bytes(4, "little")
    payload[64:68] = b"PE\0\0"
    payload[96 : 96 + len(marker)] = marker
    return bytes(payload)


def _codex_environment(tmp_path: Path) -> dict[str, str]:
    executable = (tmp_path / "codex.exe").resolve()
    executable.write_bytes(_fake_pe(b"codex"))
    return {
        "CODEX_CLI_PATH": str(executable),
        "CODEX_CLI_SHA256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        "USERPROFILE": str(tmp_path / "profile"),
        "APPDATA": str(tmp_path / "profile" / "AppData" / "Roaming"),
        "LOCALAPPDATA": str(tmp_path / "profile" / "AppData" / "Local"),
        "TEMP": str(tmp_path / "temp"),
        "PATH": "ignored-path",
    }


def _kimi_environment(tmp_path: Path) -> dict[str, str]:
    executable = (tmp_path / "kimi.exe").resolve()
    executable.write_bytes(_fake_pe(b"kimi"))
    return {
        "KIMI_CLI_PATH": str(executable),
        "KIMI_CLI_SHA256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        "KIMI_CLI_VERSION": "0.27.0",
    }


def _verified_openai_record(store: ConnectionStore, provider: str) -> dict:
    return store.mark_verified(
        provider,
        {
            "type": "openai_compat",
            "api_key": "secret",
            "base_url": "https://api.openai.com/v1",
            "enabled_models": [{"id": "m1", "upstream_model": "u1"}],
        },
        verified_at_value="2026-08-18T00:00:00Z",
    )


_UNPROVEN_CODEX = {
    "status": "unproven",
    "model": None,
    "evidence": "codex_exec_jsonl_turn_has_no_served_model_field",
}
_UNPROVEN_KIMI = {
    "status": "unproven",
    "model": None,
    "evidence": "kimi_acp_prompt_response_has_no_served_model_field",
}


@pytest.fixture(autouse=True)
def _development_profile(monkeypatch):
    monkeypatch.setenv("NACHUAN_RUNTIME_PROFILE", "development")


class TestActualServedReceiptStore:
    def test_mark_and_read_unproven_roundtrip(self, tmp_path: Path) -> None:
        store = ConnectionStore(tmp_path / "connections.json")
        record = _verified_openai_record(store, "codex")
        marked = store.mark_actual_served(
            "codex",
            record,
            receipt=dict(_UNPROVEN_CODEX),
            checked_at_value="2026-08-18T00:00:01Z",
        )
        view = store.actual_served("codex", marked)
        assert view == {
            "status": "unproven",
            "model": None,
            "evidence": "codex_exec_jsonl_turn_has_no_served_model_field",
            "checked_at": "2026-08-18T00:00:01Z",
        }
        stored = marked["_actual_served"]
        assert set(stored) == {
            "schema",
            "status",
            "model",
            "evidence",
            "checked_at",
            "receipt_hmac_sha256",
        }
        assert stored["schema"] == "nachuan.actual-served-receipt.v1"

    def test_receipt_survives_set_and_store_reopen(self, tmp_path: Path) -> None:
        path = tmp_path / "connections.json"
        store = ConnectionStore(path)
        record = _verified_openai_record(store, "codex")
        marked = store.mark_actual_served(
            "codex",
            record,
            receipt=dict(_UNPROVEN_CODEX),
            checked_at_value="2026-08-18T00:00:01Z",
        )
        store.set("codex", marked)
        reopened = ConnectionStore(path)
        reloaded = reopened.get("codex")
        assert reloaded is not None
        assert reopened.actual_served("codex", reloaded) == {
            "status": "unproven",
            "model": None,
            "evidence": "codex_exec_jsonl_turn_has_no_served_model_field",
            "checked_at": "2026-08-18T00:00:01Z",
        }

    def test_receipt_refuses_unverified_connection(self, tmp_path: Path) -> None:
        store = ConnectionStore(tmp_path / "connections.json")
        candidate = normalize_connection_candidate(
            "codex",
            {
                "type": "openai_compat",
                "api_key": "secret",
                "base_url": "https://api.openai.com/v1",
                "enabled_models": [{"id": "m1", "upstream_model": "u1"}],
            },
        )
        with pytest.raises(ValueError):
            store.mark_actual_served(
                "codex", candidate, receipt=dict(_UNPROVEN_CODEX)
            )

    @pytest.mark.parametrize(
        "receipt",
        [
            {"status": "observed", "model": "gpt-5.4", "evidence": "codex_exec_jsonl_turn_has_no_served_model_field"},
            {"status": "unproven", "model": "codex-subscription-default", "evidence": "codex_exec_jsonl_turn_has_no_served_model_field"},
            {"status": "unproven", "model": None, "evidence": "wire_says_nothing_trust_me"},
            {"status": "verified", "model": None, "evidence": "codex_exec_jsonl_turn_has_no_served_model_field"},
            {"status": "unproven", "evidence": "codex_exec_jsonl_turn_has_no_served_model_field"},
            {"status": "unproven", "model": None},
            {"status": "unproven", "model": None, "evidence": "codex_exec_jsonl_turn_has_no_served_model_field", "extra": 1},
            {"status": "unproven", "model": "gpt-5.4\x00", "evidence": "codex_exec_jsonl_turn_has_no_served_model_field"},
        ],
    )
    def test_receipt_rejects_non_closed_or_inconsistent_shapes(
        self, tmp_path: Path, receipt: dict
    ) -> None:
        store = ConnectionStore(tmp_path / "connections.json")
        record = _verified_openai_record(store, "codex")
        with pytest.raises((TypeError, ValueError)):
            store.mark_actual_served("codex", record, receipt=receipt)

    def test_tampered_receipt_fails_closed(self, tmp_path: Path) -> None:
        store = ConnectionStore(tmp_path / "connections.json")
        record = _verified_openai_record(store, "codex")
        marked = store.mark_actual_served(
            "codex", record, receipt=dict(_UNPROVEN_CODEX)
        )
        tampered = json.loads(json.dumps(marked))
        tampered["_actual_served"]["evidence"] = (
            "kimi_acp_prompt_response_has_no_served_model_field"
        )
        assert store.actual_served("codex", tampered) is None
        tampered_model = json.loads(json.dumps(marked))
        tampered_model["_actual_served"]["model"] = "gpt-5.4"
        assert store.actual_served("codex", tampered_model) is None

    def test_receipt_lapses_when_verification_generation_is_broken(
        self, tmp_path: Path
    ) -> None:
        store = ConnectionStore(tmp_path / "connections.json")
        record = _verified_openai_record(store, "codex")
        marked = store.mark_actual_served(
            "codex", record, receipt=dict(_UNPROVEN_CODEX)
        )
        stale = json.loads(json.dumps(marked))
        stale["_verification"]["state"] = "legacy_unverified"
        assert store.actual_served("codex", stale) is None

    def test_receipt_is_not_portable_across_providers(
        self, tmp_path: Path
    ) -> None:
        store = ConnectionStore(tmp_path / "connections.json")
        record = _verified_openai_record(store, "codex")
        marked = store.mark_actual_served(
            "codex", record, receipt=dict(_UNPROVEN_CODEX)
        )
        other = _verified_openai_record(store, "kimi")
        other["_actual_served"] = marked["_actual_served"]
        assert store.actual_served("kimi", other) is None

    def test_legacy_record_without_receipt_reads_none(self, tmp_path: Path) -> None:
        store = ConnectionStore(tmp_path / "connections.json")
        record = _verified_openai_record(store, "codex")
        assert store.actual_served("codex", record) is None


class _CodexWorker:
    def __init__(self) -> None:
        from gateway.codex_subscription_worker import CodexInvocation

        self._invocation = CodexInvocation(
            text="ok", thread_id="thread_1",
            prompt_tokens=1, cached_tokens=0, completion_tokens=1,
        )

    def invoke(self, prompt: str):
        return self._invocation


class _KimiWorker:
    def invoke(self, prompt: str, *, cancellation_event):
        from gateway.kimi_subscription_worker import KimiInvocation

        return KimiInvocation(
            text="ok",
            session_id="session-0123456789abcdef",
            model_id="kimi-code-subscription",
            actual_served_model=None,
        )


class TestProviderActualServedReceipt:
    def test_codex_receipt_is_unproven_and_never_the_configured_alias(
        self, tmp_path: Path
    ) -> None:
        provider = CodexProvider(
            environment=_codex_environment(tmp_path), worker=_CodexWorker()
        )
        receipt = provider.actual_served_receipt()
        assert receipt == _UNPROVEN_CODEX
        assert receipt["model"] != "codex-subscription-default"
        receipt["status"] = "observed"
        assert provider.actual_served_receipt() == _UNPROVEN_CODEX

    def test_kimi_receipt_is_unproven_and_never_the_internal_alias(
        self, tmp_path: Path
    ) -> None:
        provider = KimiSubscriptionProvider(
            environment=_kimi_environment(tmp_path), worker=_KimiWorker()
        )
        receipt = provider.actual_served_receipt()
        assert receipt == _UNPROVEN_KIMI
        assert receipt["model"] not in {"kimi-code/k3", "kimi-code-subscription"}


class _ProbeOkProvider:
    connection_probe_timeout_s = 180.0

    def __init__(self, receipt: object = ..., *, hook_raises: bool = False) -> None:
        self._receipt = receipt
        self._hook_raises = hook_raises

    async def probe_chat(self, _req, _upstream_model):
        return {
            "id": "probe",
            "model": "codex-subscription",
            "choices": [{"message": {"role": "assistant", "content": "ok"}}],
        }

    async def aclose(self):
        return None


class _ProbeOkProviderWithReceipt(_ProbeOkProvider):
    def __init__(self, receipt: dict, *, hook_raises: bool = False) -> None:
        super().__init__(receipt, hook_raises=hook_raises)

    def actual_served_receipt(self):
        if self._hook_raises:
            raise RuntimeError("PRIVATE_RECEIPT_FAILURE_DETAIL")
        return dict(self._receipt)


class _Route:
    def __init__(self, provider: object, virtual: str, upstream: str) -> None:
        self.provider = provider
        self.virtual_model = virtual
        self.upstream_model = upstream


class _Router:
    def __init__(self, route: _Route) -> None:
        self._route = route

    def assign_available_model_ids(self, _provider, conn):
        return conn

    def build_transient_routes(self, _provider, _conn):
        return [self._route]

    def assert_connection_model_ids_available(self, _provider, _conn):
        return None

    async def reload_connection(self, _provider):
        return None


def _connect_app(store: ConnectionStore, route: _Route) -> FastAPI:
    test_app = FastAPI()
    test_app.include_router(admin.router)
    test_app.dependency_overrides[require_api_key] = lambda: "runtime"
    test_app.dependency_overrides[require_approval_admin_key] = lambda: "approval"
    test_app.state.store = store
    test_app.state.router = _Router(route)
    return test_app


class TestAdminConnectActualServed:
    def test_codex_connect_persists_unproven_receipt(
        self, monkeypatch, tmp_path: Path
    ) -> None:
        async def call_probe(provider, req, upstream_model, **_kwargs):
            return await provider.probe_chat(req, upstream_model)

        monkeypatch.setattr(admin, "chat_once_with_deadline", call_probe)
        store = ConnectionStore(tmp_path / "connections.json")
        route = _Route(
            _ProbeOkProviderWithReceipt(_UNPROVEN_CODEX),
            "codex-subscription",
            "codex-subscription-default",
        )
        with TestClient(_connect_app(store, route)) as client:
            response = client.post(
                "/admin/connections/codex",
                json={
                    "type": "codex",
                    "api_key": "",
                    "base_url": "",
                    "enabled_models": [
                        {
                            "id": "codex-subscription",
                            "upstream_model": "codex-subscription-default",
                        }
                    ],
                },
            )
            assert response.status_code == 200
            body = response.json()
            assert body["ok"] is True
            actual = body["actual_served"]
            assert actual["status"] == "unproven"
            assert actual["model"] is None
            assert (
                actual["evidence"]
                == "codex_exec_jsonl_turn_has_no_served_model_field"
            )
            assert isinstance(actual["checked_at"], str) and actual["checked_at"]

            record = store.get("codex")
            assert record is not None and "_actual_served" in record
            view = store.actual_served("codex", record)
            assert view is not None and view["status"] == "unproven"
            masked = client.get("/admin/connections").json()["codex"]
            assert "_actual_served" not in masked
            assert "receipt_hmac" not in json.dumps(masked)

    def test_kimi_connect_persists_unproven_receipt(
        self, monkeypatch, tmp_path: Path
    ) -> None:
        async def call_probe(provider, req, upstream_model, **_kwargs):
            return await provider.probe_chat(req, upstream_model)

        monkeypatch.setattr(admin, "chat_once_with_deadline", call_probe)
        store = ConnectionStore(tmp_path / "connections.json")
        route = _Route(
            _ProbeOkProviderWithReceipt(_UNPROVEN_KIMI),
            "kimi-code-subscription",
            "kimi-code-subscription",
        )
        with TestClient(_connect_app(store, route)) as client:
            response = client.post(
                "/admin/connections/kimi-code",
                json={
                    "type": "kimi_code",
                    "api_key": "",
                    "base_url": "",
                    "enabled_models": [
                        {
                            "id": "kimi-code-subscription",
                            "upstream_model": "kimi-code-subscription",
                            "tool_capable": False,
                        }
                    ],
                },
            )
            assert response.status_code == 200
            body = response.json()
            assert body["ok"] is True
            assert (
                body["actual_served"]["evidence"]
                == "kimi_acp_prompt_response_has_no_served_model_field"
            )
            record = store.get("kimi-code")
            assert record is not None
            assert store.actual_served("kimi-code", record)["status"] == "unproven"

    def test_connect_without_receipt_hook_records_none(
        self, monkeypatch, tmp_path: Path
    ) -> None:
        async def call_probe(provider, req, upstream_model, **_kwargs):
            return await provider.probe_chat(req, upstream_model)

        monkeypatch.setattr(admin, "chat_once_with_deadline", call_probe)
        store = ConnectionStore(tmp_path / "connections.json")
        route = _Route(_ProbeOkProvider(None), "m1", "u1")
        with TestClient(_connect_app(store, route)) as client:
            response = client.post(
                "/admin/connections/plain",
                json={
                    "type": "openai_compat",
                    "api_key": "secret",
                    "base_url": "https://api.openai.com/v1",
                    "enabled_models": [{"id": "m1", "upstream_model": "u1"}],
                },
            )
            assert response.status_code == 200
            body = response.json()
            assert body["ok"] is True
            assert body["actual_served"] is None
            record = store.get("plain")
            assert record is not None and "_actual_served" not in record

    def test_connect_fails_closed_when_receipt_hook_fails(
        self, monkeypatch, tmp_path: Path
    ) -> None:
        async def call_probe(provider, req, upstream_model, **_kwargs):
            return await provider.probe_chat(req, upstream_model)

        monkeypatch.setattr(admin, "chat_once_with_deadline", call_probe)
        store = ConnectionStore(tmp_path / "connections.json")
        route = _Route(
            _ProbeOkProviderWithReceipt(_UNPROVEN_KIMI, hook_raises=True),
            "kimi-code-subscription",
            "kimi-code-subscription",
        )
        with TestClient(_connect_app(store, route)) as client:
            response = client.post(
                "/admin/connections/kimi-code",
                json={
                    "type": "kimi_code",
                    "api_key": "",
                    "base_url": "",
                    "enabled_models": [
                        {
                            "id": "kimi-code-subscription",
                            "upstream_model": "kimi-code-subscription",
                            "tool_capable": False,
                        }
                    ],
                },
            )
            body = response.json()
            assert body["ok"] is False
            assert body["reason_code"] == "connector_unavailable"
            assert "PRIVATE_RECEIPT_FAILURE_DETAIL" not in json.dumps(body)
            assert store.get("kimi-code") is None


class TestCatalogActualServed:
    @pytest.mark.parametrize(
        ("preset_name", "model_id"),
        [
            ("kimi-code", "kimi-code-subscription"),
            ("codex", "codex-subscription"),
        ],
    )
    def test_subscription_preset_models_display_unproven(
        self, preset_name: str, model_id: str
    ) -> None:
        models = catalog.preset_models(preset_name)
        assert models[0]["id"] == model_id
        assert models[0]["actual_served"] == "unproven"

    def test_api_key_presets_do_not_claim_a_served_identity_field(self) -> None:
        models = catalog.preset_models("deepseek")
        assert all("actual_served" not in model for model in models)

    def test_display_field_rejects_non_closed_values(self) -> None:
        with pytest.raises(ValueError):
            catalog._m("x", "x", actual_served="probably-gpt-5")

    def test_echoed_display_field_never_breaks_connection_intake(self) -> None:
        candidate = normalize_connection_candidate(
            "plain",
            {
                "type": "openai_compat",
                "api_key": "secret",
                "base_url": "https://api.openai.com/v1",
                "enabled_models": [
                    {
                        "id": "m1",
                        "upstream_model": "u1",
                        "actual_served": "unproven",
                    }
                ],
            },
        )
        assert "actual_served" not in candidate["enabled_models"][0]
        with pytest.raises(ValueError):
            normalize_connection_candidate(
                "plain",
                {
                    "type": "openai_compat",
                    "api_key": "secret",
                    "base_url": "https://api.openai.com/v1",
                    "enabled_models": [
                        {
                            "id": "m1",
                            "upstream_model": "u1",
                            "actual_served": "probably-gpt-5",
                        }
                    ],
                },
            )


class _QueueRunner:
    def __init__(self, *results: CodexWorkerResult) -> None:
        self.results = list(results)
        self.requests: list[CodexWorkerRequest] = []

    def __call__(self, request: CodexWorkerRequest) -> CodexWorkerResult:
        self.requests.append(request)
        return self.results.pop(0)


def _worker_result(
    returncode: int, stdout: str = "", stderr: str = ""
) -> CodexWorkerResult:
    return CodexWorkerResult(
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        process_tree_exit_verified=True,
    )


class TestCodexLogoutWorker:
    def test_logout_argv_is_the_exact_official_command(
        self, tmp_path: Path
    ) -> None:
        environment = _codex_environment(tmp_path)
        request = CodexWorkerRequest(
            operation="logout",
            executable_path=environment["CODEX_CLI_PATH"],
            executable_sha256=environment["CODEX_CLI_SHA256"],
        )
        assert codex_cli_argv(request, tmp_path) == (
            environment["CODEX_CLI_PATH"],
            "logout",
        )

    def test_logout_request_rejects_any_prompt_payload(self, tmp_path: Path) -> None:
        environment = _codex_environment(tmp_path)
        request = CodexWorkerRequest(
            operation="logout",
            executable_path=environment["CODEX_CLI_PATH"],
            executable_sha256=environment["CODEX_CLI_SHA256"],
            prompt="x",
        )
        with pytest.raises(CodexSubscriptionError):
            request.prompt_bytes()

    def test_helper_protocol_accepts_the_logout_operation(
        self, tmp_path: Path
    ) -> None:
        environment = _codex_environment(tmp_path)
        request = CodexWorkerRequest(
            operation="logout",
            executable_path=environment["CODEX_CLI_PATH"],
            executable_sha256=environment["CODEX_CLI_SHA256"],
        )
        decoded = _decode_request(_encode_request(request))
        assert decoded.operation == "logout"

    def test_logout_success_requires_official_logged_out_status(
        self, tmp_path: Path
    ) -> None:
        environment = _codex_environment(tmp_path)
        runner = _QueueRunner(
            _worker_result(0),
            _worker_result(1, stderr="Not logged in\n"),
        )
        worker = CodexSubscriptionWorker(environment=environment, runner=runner)
        assert worker.logout() == "logged_out"
        assert [request.operation for request in runner.requests] == [
            "logout",
            "status",
        ]

    def test_zero_exit_without_logged_out_evidence_is_not_success(
        self, tmp_path: Path
    ) -> None:
        environment = _codex_environment(tmp_path)
        runner = _QueueRunner(
            _worker_result(0),
            _worker_result(0, stdout="Logged in using ChatGPT\n"),
        )
        worker = CodexSubscriptionWorker(environment=environment, runner=runner)
        with pytest.raises(CodexSubscriptionError) as excinfo:
            worker.logout()
        assert excinfo.value.code == "logout_unverified"

    def test_failed_logout_process_stays_failed_even_when_state_changed(
        self, tmp_path: Path
    ) -> None:
        environment = _codex_environment(tmp_path)
        runner = _QueueRunner(
            _worker_result(70, stderr="worker_process_error"),
            _worker_result(1, stderr="Not logged in\n"),
        )
        worker = CodexSubscriptionWorker(environment=environment, runner=runner)
        with pytest.raises(CodexSubscriptionError) as excinfo:
            worker.logout()
        assert excinfo.value.code == "logout_process_failed_logged_out"

    def test_failed_logout_process_with_session_intact_is_logout_failed(
        self, tmp_path: Path
    ) -> None:
        environment = _codex_environment(tmp_path)
        runner = _QueueRunner(
            _worker_result(70, stderr="worker_process_error"),
            _worker_result(0, stdout="Logged in using ChatGPT\n"),
        )
        worker = CodexSubscriptionWorker(environment=environment, runner=runner)
        with pytest.raises(CodexSubscriptionError) as excinfo:
            worker.logout()
        assert excinfo.value.code == "logout_failed"


def _invoke_cli(argv: list[str]):
    out, err = io.StringIO(), io.StringIO()

    def handler(request: httpx.Request) -> httpx.Response:
        pytest.fail("subscription CLI commands must not call Gateway")

    code = run(
        argv,
        transport=httpx.MockTransport(handler),
        out=out,
        err=err,
    )
    return code, out.getvalue(), err.getvalue()


class TestCliLogout:
    def test_codex_logout_reports_official_logged_out_state(
        self, monkeypatch, tmp_path: Path
    ) -> None:
        monkeypatch.setenv("DATA_DIR", str(tmp_path))
        monkeypatch.setattr(
            "cli.nachuan.load_subscription_cli_environment",
            lambda _data_dir: {"CODEX_CLI_PATH": r"D:\trusted\codex.exe"},
            raising=False,
        )

        class FakeWorker:
            def __init__(self, *, environment):
                assert environment["CODEX_CLI_PATH"] == r"D:\trusted\codex.exe"

            def logout(self):
                return "logged_out"

        monkeypatch.setattr(
            "cli.nachuan.CodexSubscriptionWorker", FakeWorker, raising=False
        )
        code, out, err = _invoke_cli(["codex", "logout"])
        assert code == EXIT_OK
        assert err == ""
        assert "logged_out" in out

    def test_codex_logout_failure_is_reported_with_the_closed_code(
        self, monkeypatch, tmp_path: Path
    ) -> None:
        monkeypatch.setenv("DATA_DIR", str(tmp_path))
        monkeypatch.setattr(
            "cli.nachuan.load_subscription_cli_environment",
            lambda _data_dir: {"CODEX_CLI_PATH": r"D:\trusted\codex.exe"},
            raising=False,
        )

        class FakeWorker:
            def __init__(self, *, environment):
                pass

            def logout(self):
                raise CodexSubscriptionError("logout_unverified")

        monkeypatch.setattr(
            "cli.nachuan.CodexSubscriptionWorker", FakeWorker, raising=False
        )
        code, out, err = _invoke_cli(["codex", "logout", "--json"])
        assert code == EXIT_UNAVAILABLE
        assert json.loads(out)["state"] == "logout_unverified"

    def test_kimi_logout_is_truthfully_unsupported_and_never_touches_vendor_files(
        self, monkeypatch, tmp_path: Path
    ) -> None:
        monkeypatch.setenv("DATA_DIR", str(tmp_path))
        code, out, err = _invoke_cli(["kimi", "logout", "--json"])
        assert code == EXIT_REFUSED
        assert json.loads(out)["state"] == "logout_unsupported"
