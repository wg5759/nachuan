"""nachuan CLI 合同测试（ADR-0013：分发形态转向 CLI + 本地 Web）。

CLI 是本地引擎的用户入口：status / models / chat / ui。
所有测试用 httpx.MockTransport 替代网络，不依赖真实引擎。
"""

from __future__ import annotations

import io
import json

import httpx
import pytest

from cli.nachuan import (
    EXIT_OK,
    EXIT_REFUSED,
    EXIT_UNAVAILABLE,
    run,
)


def _invoke(argv, *, handler, out=None, err=None):
    transport = httpx.MockTransport(handler)
    out = out if out is not None else io.StringIO()
    err = err if err is not None else io.StringIO()
    code = run(argv, transport=transport, out=out, err=err)
    return code, out.getvalue(), err.getvalue()


def _ok_json(payload, status=200):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json=payload)

    return handler


class TestStatus:
    def test_ok(self):
        code, out, _ = _invoke(["status"], handler=_ok_json({"status": "ok"}))
        assert code == EXIT_OK
        assert "ok" in out

    def test_engine_down(self):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused", request=request)

        code, _, err = _invoke(["status"], handler=handler)
        assert code == EXIT_UNAVAILABLE
        assert "未运行" in err or "不可达" in err

    def test_status_needs_no_key(self, monkeypatch):
        monkeypatch.delenv("NACHUAN_GATEWAY_KEY", raising=False)
        seen = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["authorization"] = request.headers.get("authorization")
            return httpx.Response(200, json={"status": "ok"})

        code, _, _ = _invoke(["status"], handler=handler)
        assert code == EXIT_OK
        assert seen["authorization"] is None


class TestModels:
    def test_ok_sends_bearer(self, monkeypatch):
        monkeypatch.setenv("NACHUAN_GATEWAY_KEY", "test-runtime-key")
        seen = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["authorization"] = request.headers.get("authorization")
            return httpx.Response(200, json={"data": [{"id": "auto"}, {"id": "m1"}]})

        code, out, _ = _invoke(["models"], handler=handler)
        assert code == EXIT_OK
        assert seen["authorization"] == "Bearer test-runtime-key"
        assert "auto" in out and "m1" in out

    def test_unauthorized(self, monkeypatch):
        monkeypatch.setenv("NACHUAN_GATEWAY_KEY", "wrong")
        code, _, err = _invoke(["models"], handler=_ok_json({}, status=401))
        assert code == EXIT_REFUSED
        assert "key" in err.lower() or "鉴权" in err

    def test_no_key_available(self, monkeypatch, tmp_path):
        monkeypatch.delenv("NACHUAN_GATEWAY_KEY", raising=False)
        monkeypatch.setenv("DATA_DIR", str(tmp_path))
        code, _, err = _invoke(["models"], handler=_ok_json({"data": []}))
        assert code == EXIT_REFUSED
        assert "gateway_api_key" in err or "NACHUAN_GATEWAY_KEY" in err

    def test_key_file_fallback(self, monkeypatch, tmp_path):
        monkeypatch.delenv("NACHUAN_GATEWAY_KEY", raising=False)
        monkeypatch.setenv("DATA_DIR", str(tmp_path))
        (tmp_path / "gateway_api_key.txt").write_text("file-key\n", encoding="utf-8")
        seen = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["authorization"] = request.headers.get("authorization")
            return httpx.Response(200, json={"data": []})

        code, _, _ = _invoke(["models"], handler=handler)
        assert code == EXIT_OK
        assert seen["authorization"] == "Bearer file-key"

    def test_protected_local_owner_key_precedes_legacy_plaintext_file(
        self, monkeypatch, tmp_path
    ):
        monkeypatch.delenv("NACHUAN_GATEWAY_KEY", raising=False)
        monkeypatch.setenv("DATA_DIR", str(tmp_path))
        (tmp_path / "gateway_api_key.txt").write_text(
            "legacy-file-key\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(
            "cli.nachuan.load_local_owner_credentials",
            lambda _data_dir: type(
                "Credentials",
                (),
                {"runtime_key": "protected-runtime-key"},
            )(),
        )
        seen = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["authorization"] = request.headers.get("authorization")
            return httpx.Response(200, json={"data": []})

        code, _, _ = _invoke(["models"], handler=handler)

        assert code == EXIT_OK
        assert seen["authorization"] == "Bearer protected-runtime-key"

    def test_corrupt_protected_owner_state_does_not_fall_back_to_plaintext(
        self, monkeypatch, tmp_path
    ):
        from cli.local_web_start import LocalOwnerCredentialError

        monkeypatch.delenv("NACHUAN_GATEWAY_KEY", raising=False)
        monkeypatch.setenv("DATA_DIR", str(tmp_path))
        (tmp_path / "gateway_api_key.txt").write_text(
            "must-not-be-used\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(
            "cli.nachuan.load_local_owner_credentials",
            lambda _data_dir: (_ for _ in ()).throw(
                LocalOwnerCredentialError("corrupt")
            ),
        )

        code, _, err = _invoke(
            ["models"],
            handler=lambda request: pytest.fail(
                "corrupt protected state must fail before any request"
            ),
        )

        assert code == EXIT_REFUSED
        assert "runtime key" in err.lower()


class TestChat:
    def _chat_response(self, request: httpx.Request) -> httpx.Response:
        self.last_request = request
        return httpx.Response(
            200,
            json={
                "choices": [
                    {"message": {"role": "assistant", "content": "你好，纳川"}}
                ]
            },
        )

    def test_ok_prints_content(self, monkeypatch):
        monkeypatch.setenv("NACHUAN_GATEWAY_KEY", "k")
        code, out, _ = _invoke(["chat", "你好"], handler=self._chat_response)
        assert code == EXIT_OK
        assert "你好，纳川" in out
        body = json.loads(self.last_request.content)
        assert body["messages"] == [{"role": "user", "content": "你好"}]
        assert body["stream"] is False
        assert body["model"] == "auto"

    def test_model_flag(self, monkeypatch):
        monkeypatch.setenv("NACHUAN_GATEWAY_KEY", "k")
        code, _, _ = _invoke(
            ["chat", "--model", "nachuan-ultra", "hi"], handler=self._chat_response
        )
        assert code == EXIT_OK
        assert json.loads(self.last_request.content)["model"] == "nachuan-ultra"

    def test_json_flag(self, monkeypatch):
        monkeypatch.setenv("NACHUAN_GATEWAY_KEY", "k")
        code, out, _ = _invoke(["chat", "--json", "hi"], handler=self._chat_response)
        assert code == EXIT_OK
        assert json.loads(out)["choices"][0]["message"]["content"] == "你好，纳川"

    def test_http_error(self, monkeypatch):
        monkeypatch.setenv("NACHUAN_GATEWAY_KEY", "k")
        code, _, err = _invoke(["chat", "hi"], handler=_ok_json({"error": "x"}, status=500))
        assert code == EXIT_UNAVAILABLE

    def test_no_key(self, monkeypatch, tmp_path):
        monkeypatch.delenv("NACHUAN_GATEWAY_KEY", raising=False)
        monkeypatch.setenv("DATA_DIR", str(tmp_path))
        code, _, _ = _invoke(["chat", "hi"], handler=self._chat_response)
        assert code == EXIT_REFUSED


class TestUi:
    def test_prints_url(self):
        code, out, _ = _invoke(["ui"], handler=_ok_json({}))
        assert code == EXIT_OK
        assert "http://127.0.0.1:8080/" in out
        assert "wheel 内置 Web UI" in out
        assert "404" not in out


class TestStart:
    def test_start_is_local_and_dispatches_without_calling_an_existing_engine(
        self, monkeypatch, tmp_path
    ):
        monkeypatch.setenv("DATA_DIR", str(tmp_path))
        observed = {}
        credentials = type(
            "Credentials",
            (),
            {
                "runtime_key": "nc-runtime-v1-" + ("R" * 43),
                "approval_key": "nc-approval-v1-" + ("P" * 43),
                "created": True,
            },
        )()
        paid_capability = type(
            "PaidCapability",
            (),
            {
                "key": "sk-paid-media-" + ("a" * 64),
                "created": True,
            },
        )()

        monkeypatch.setattr(
            "cli.nachuan.load_or_create_local_owner_credentials",
            lambda data_dir: (
                observed.setdefault("data_dir", data_dir),
                credentials,
            )[1],
            raising=False,
        )
        monkeypatch.setattr(
            "cli.nachuan.load_or_create_local_paid_media_capability",
            lambda data_dir: (
                observed.setdefault("paid_data_dir", data_dir),
                paid_capability,
            )[1],
            raising=False,
        )

        def fake_serve(
            selected,
            selected_paid,
            *,
            data_dir,
            port,
            open_browser,
            out,
            environment,
        ):
            observed.update(
                {
                    "credentials": selected,
                    "paid_capability": selected_paid,
                    "serve_data_dir": data_dir,
                    "port": port,
                    "open_browser": open_browser,
                    "environment": environment,
                }
            )
            out.write("started\n")
            return EXIT_OK

        monkeypatch.setattr(
            "cli.nachuan.serve_local_web",
            fake_serve,
            raising=False,
        )

        code, out, err = _invoke(
            ["start", "--no-open", "--port", "18081"],
            handler=lambda request: pytest.fail(
                "nachuan start must not contact a pre-existing Gateway"
            ),
        )

        assert code == EXIT_OK
        assert err == ""
        assert out == "started\n"
        assert observed["data_dir"] == tmp_path
        assert observed["paid_data_dir"] == tmp_path
        assert observed["serve_data_dir"] == tmp_path
        assert observed["credentials"] is credentials
        assert observed["paid_capability"] is paid_capability
        assert observed["port"] == 18081
        assert observed["open_browser"] is False


class TestCodexSubscription:
    def test_bind_is_local_and_does_not_require_engine(
        self, monkeypatch, tmp_path
    ):
        monkeypatch.setenv("DATA_DIR", str(tmp_path))
        seen = {}

        def fake_bind(data_dir, path, *, environment):
            seen["data_dir"] = data_dir
            seen["path"] = path
            seen["environment"] = environment
            return type(
                "Binding",
                (),
                {
                    "path": r"D:\trusted\codex.exe",
                    "sha256": "a" * 64,
                    "publisher": "OpenAI OpCo, LLC",
                },
            )()

        monkeypatch.setattr(
            "cli.nachuan.discover_and_bind_codex_subscription_cli",
            fake_bind,
            raising=False,
        )

        code, out, err = _invoke(
            ["codex", "bind", "--path", r"D:\lead\codex.exe"],
            handler=lambda request: pytest.fail("Codex bind must not call Gateway"),
        )

        assert code == EXIT_OK
        assert err == ""
        assert seen["data_dir"] == tmp_path
        assert seen["path"] == r"D:\lead\codex.exe"
        assert seen["environment"] is not None
        assert "OpenAI OpCo, LLC" in out
        assert "D:\\trusted\\codex.exe" in out

    def test_status_reads_protected_binding_without_engine(
        self, monkeypatch, tmp_path
    ):
        monkeypatch.setenv("DATA_DIR", str(tmp_path))
        monkeypatch.setattr(
            "cli.nachuan.load_subscription_cli_environment",
            lambda _data_dir: {
                "CODEX_CLI_PATH": r"D:\trusted\codex.exe",
                "CODEX_CLI_SHA256": "a" * 64,
            },
            raising=False,
        )

        class FakeWorker:
            def __init__(self, *, environment):
                assert environment["CODEX_CLI_PATH"] == r"D:\trusted\codex.exe"

            def probe_status(self):
                return "authenticated_unprobed"

        monkeypatch.setattr(
            "cli.nachuan.CodexSubscriptionWorker",
            FakeWorker,
            raising=False,
        )

        code, out, err = _invoke(
            ["codex", "status"],
            handler=lambda request: pytest.fail("Codex status must not call Gateway"),
        )

        assert code == EXIT_OK
        assert err == ""
        assert "authenticated_unprobed" in out


class TestKimiSubscription:
    def test_bind_uses_official_manifest_without_contacting_gateway(
        self, monkeypatch, tmp_path
    ):
        monkeypatch.setenv("DATA_DIR", str(tmp_path))
        seen = {}

        def fake_bind(
            data_dir,
            path,
            *,
            version,
            manifest_fetcher,
        ):
            seen["data_dir"] = data_dir
            seen["path"] = path
            seen["version"] = version
            seen["manifest_fetcher"] = manifest_fetcher
            return type(
                "Binding",
                (),
                {
                    "path": r"D:\trusted\kimi.exe",
                    "sha256": "b" * 64,
                    "provenance": "official_https_manifest_v1",
                    "version": "0.27.0",
                    "platform": "win32-x64",
                    "filename": "kimi-code-win32-x64.exe",
                    "manifest_sha256": "c" * 64,
                },
            )()

        monkeypatch.setattr(
            "cli.nachuan.bind_kimi_subscription_cli",
            fake_bind,
            raising=False,
        )

        code, out, err = _invoke(
            [
                "kimi",
                "bind",
                "--path",
                r"D:\lead\kimi.exe",
                "--version",
                "0.27.0",
            ],
            handler=lambda request: pytest.fail("Kimi bind must not call Gateway"),
        )

        assert code == EXIT_OK
        assert err == ""
        assert seen["data_dir"] == tmp_path
        assert seen["path"] == r"D:\lead\kimi.exe"
        assert seen["version"] == "0.27.0"
        assert callable(seen["manifest_fetcher"])
        assert "official_https_manifest_v1" in out
        assert "0.27.0" in out
        assert "D:\\trusted\\kimi.exe" in out

    def test_status_is_local_and_scoped_to_kimi_binding(
        self, monkeypatch, tmp_path
    ):
        monkeypatch.setenv("DATA_DIR", str(tmp_path))
        overlay = {
            "CODEX_CLI_PATH": r"D:\trusted\codex.exe",
            "CODEX_CLI_SHA256": "a" * 64,
            "KIMI_CLI_PATH": r"D:\trusted\kimi.exe",
            "KIMI_CLI_SHA256": "b" * 64,
            "KIMI_CLI_VERSION": "0.27.0",
            "KIMI_CODE_HOME": r"D:\trusted\kimi-home",
            "KIMI_CLI_TEMP_ROOT": r"D:\trusted\kimi-temp",
        }
        monkeypatch.setattr(
            "cli.nachuan.load_subscription_cli_environment",
            lambda _data_dir: dict(overlay),
            raising=False,
        )
        observed = []

        class FakeLoginController:
            def __init__(self, *, protected_overlay):
                observed.append(dict(protected_overlay))

            def probe_status(self):
                return "authenticated_unprobed"

        monkeypatch.setattr(
            "cli.nachuan.KimiSubscriptionLoginController",
            FakeLoginController,
            raising=False,
        )

        code, out, err = _invoke(
            ["kimi", "status", "--json"],
            handler=lambda request: pytest.fail("Kimi status must not call Gateway"),
        )

        assert code == EXIT_OK
        assert err == ""
        assert observed == [overlay]
        assert json.loads(out) == {
            "bound": True,
            "state": "authenticated_unprobed",
        }

    def test_status_does_not_treat_a_codex_only_overlay_as_kimi_bound(
        self, monkeypatch, tmp_path
    ):
        monkeypatch.setenv("DATA_DIR", str(tmp_path))
        monkeypatch.setattr(
            "cli.nachuan.load_subscription_cli_environment",
            lambda _data_dir: {
                "CODEX_CLI_PATH": r"D:\trusted\codex.exe",
                "CODEX_CLI_SHA256": "a" * 64,
            },
            raising=False,
        )

        code, out, err = _invoke(
            ["kimi", "status", "--json"],
            handler=lambda request: pytest.fail("Kimi status must not call Gateway"),
        )

        assert code == EXIT_UNAVAILABLE
        assert err == ""
        assert json.loads(out) == {
            "bound": False,
            "state": "not_installed",
        }

    def test_login_uses_protected_overlay_without_contacting_gateway(
        self, monkeypatch, tmp_path
    ):
        monkeypatch.setenv("DATA_DIR", str(tmp_path))
        overlay = {
            "KIMI_CLI_PATH": r"D:\trusted\kimi.exe",
            "KIMI_CLI_SHA256": "b" * 64,
            "KIMI_CLI_VERSION": "0.27.0",
            "KIMI_CLI_TEMP_ROOT": r"D:\trusted\kimi-temp",
            "KIMI_CODE_HOME": r"D:\trusted\kimi-home",
        }
        monkeypatch.setattr(
            "cli.nachuan.load_subscription_cli_environment",
            lambda _data_dir: dict(overlay),
            raising=False,
        )
        observed = []

        class FakeLoginController:
            def __init__(self, *, protected_overlay):
                observed.append(dict(protected_overlay))

            def login(self):
                return "authenticated_unprobed"

        monkeypatch.setattr(
            "cli.nachuan.KimiSubscriptionLoginController",
            FakeLoginController,
            raising=False,
        )

        code, out, err = _invoke(
            ["kimi", "login", "--json"],
            handler=lambda request: pytest.fail(
                "Kimi login must not call Gateway"
            ),
        )

        assert code == EXIT_OK
        assert err == ""
        assert observed == [overlay]
        assert json.loads(out) == {
            "state": "authenticated_unprobed",
        }

    def test_unbind_is_local_and_scoped(self, monkeypatch, tmp_path):
        monkeypatch.setenv("DATA_DIR", str(tmp_path))
        seen = []

        def fake_unbind(data_dir):
            seen.append(data_dir)
            return True

        monkeypatch.setattr(
            "cli.nachuan.unbind_kimi_subscription_cli",
            fake_unbind,
            raising=False,
        )

        code, out, err = _invoke(
            ["kimi", "unbind", "--json"],
            handler=lambda request: pytest.fail("Kimi unbind must not call Gateway"),
        )

        assert code == EXIT_OK
        assert err == ""
        assert seen == [tmp_path]
        assert json.loads(out) == {"removed": True, "state": "unbound"}
