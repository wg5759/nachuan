from __future__ import annotations

import ast
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import engine_main
from gateway import connections, local_model, mcp_registry, runtime_profile as runtime_profile_module
from gateway.app import app
from gateway.media_binary import MediaBinaryUnavailable, require_media_binary
from gateway.providers.cli_env import sanitized_cli_env
from gateway.runtime_profile import (
    ExternalProgramAuthority,
    RUNTIME_PROFILE_SCHEMA,
    RuntimeCapability,
    resolve_runtime_profile,
)
from gateway.router import Router
from orchestrator.studio import start_execution
from orchestrator.tool_agent import execute_tool, run_tool_agent


PROJECT_ROOT = Path(__file__).resolve().parents[1]
AUTH = {"Authorization": "Bearer test-key"}


def test_store_gateway_import_does_not_load_host_cli_providers() -> None:
    """A frozen store Gateway must not even register host-CLI provider code."""

    probe = "\n".join(
        [
            "import os, sys",
            f"sys.path.insert(0, {str(PROJECT_ROOT)!r})",
            "os.environ['NACHUAN_RUNTIME_PROFILE'] = 'store'",
            "setattr(sys, 'frozen', True)",
            "import gateway.router",
            "forbidden = sorted(name for name in sys.modules if name in {",
            "    'gateway.providers.claude_code',",
            "    'gateway.providers.codex',",
            "})",
            "if forbidden:",
            "    print('STORE_HOST_CLI_PROVIDER_LOADED=' + ','.join(forbidden))",
            "    raise SystemExit(91)",
        ]
    )
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
        "TEMP": os.environ.get("TEMP", ""),
        "TMP": os.environ.get("TMP", ""),
    }
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-X", "utf8", "-c", probe],
        cwd=PROJECT_ROOT,
        env=environment,
        capture_output=True,
        check=False,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0, result.stdout + result.stderr


def test_retired_claude_connection_is_rejected_before_runtime_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NACHUAN_RUNTIME_PROFILE", "store")
    candidate = {
        "type": "claude_code",
        "api_key": "",
        "base_url": "",
        "enabled_models": [
            {
                "id": "claude-opus",
                "upstream_model": "opus",
                "tier": "premium",
                "description": "",
                "modality": "chat",
                "rank": 0,
                "flagship": True,
                "tool_capable": False,
                "skills": [],
            }
        ],
    }

    with pytest.raises(ValueError, match="连接协议尚不可用"):
        connections.normalize_connection_candidate(
            "claude-local",
            candidate,
            verify_public=False,
        )


def test_frozen_engine_pins_store_profile_before_gateway_import(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    observed: list[str | None] = []
    fake_gateway_app = type(
        "FakeGatewayApp",
        (),
        {"main": staticmethod(lambda: observed.append(os.environ.get("NACHUAN_RUNTIME_PROFILE")))},
    )
    monkeypatch.setattr(engine_main.sys, "frozen", True, raising=False)
    monkeypatch.setenv("DATA_DIR", str(tmp_path.resolve()))
    monkeypatch.setenv("NACHUAN_RUNTIME_PROFILE", "development")
    profile_path = tmp_path / "store-runtime-profile.v1.json"
    profile_bytes = (PROJECT_ROOT / "config" / profile_path.name).read_bytes()
    profile_path.write_bytes(profile_bytes)
    monkeypatch.setattr(
        runtime_profile_module,
        "_expected_packaged_profile_path",
        lambda: profile_path.resolve(),
        raising=False,
    )
    monkeypatch.setenv("NACHUAN_STORE_RUNTIME_PROFILE_MANIFEST", str(profile_path.resolve()))
    monkeypatch.setenv(
        "NACHUAN_STORE_RUNTIME_PROFILE_SHA256",
        hashlib.sha256(profile_bytes).hexdigest(),
    )
    monkeypatch.setitem(sys.modules, "gateway.app", fake_gateway_app)

    assert engine_main.run_engine_entrypoint([]) == 0
    assert observed == ["store"]


def test_frozen_store_engine_rejects_missing_asar_profile_binding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(runtime_profile_module.sys, "frozen", True, raising=False)
    monkeypatch.delenv("NACHUAN_STORE_RUNTIME_PROFILE_MANIFEST", raising=False)
    monkeypatch.delenv("NACHUAN_STORE_RUNTIME_PROFILE_SHA256", raising=False)

    with pytest.raises(RuntimeError, match="profile.*binding"):
        runtime_profile_module.enforce_frozen_store_profile()


def test_store_engine_build_consumes_the_versioned_profile_exclusion_closure() -> None:
    spec_path = PROJECT_ROOT / "engine.spec"
    source = spec_path.read_text("utf-8")
    tree = ast.parse(source, filename=str(spec_path))
    imported_profile = any(
        isinstance(node, ast.ImportFrom)
        and node.module == "gateway.runtime_profile"
        and any(alias.name == "STORE_RUNTIME_PROFILE" for alias in node.names)
        for node in ast.walk(tree)
    )
    analysis_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "Analysis"
    ]
    assert imported_profile is True
    assert len(analysis_calls) == 1
    excludes = next(
        keyword.value for keyword in analysis_calls[0].keywords if keyword.arg == "excludes"
    )
    excludes_source = ast.get_source_segment(source, excludes) or ""
    assert "STORE_RUNTIME_PROFILE.frozen_python_excludes" in excludes_source
    collected_packages = {
        value.value
        for node in ast.walk(tree)
        if isinstance(node, ast.For)
        and isinstance(node.iter, ast.Tuple)
        for value in node.iter.elts
        if isinstance(value, ast.Constant) and isinstance(value.value, str)
    }
    assert "yt_dlp" not in collected_packages


def test_store_profile_cannot_enable_unpinned_plugin_capable_downloads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from gateway import app as gateway_app

    monkeypatch.setenv("NACHUAN_RUNTIME_PROFILE", "store")
    monkeypatch.setenv(
        gateway_app._LAPIAN_YTDLP_RISK_ENV,
        gateway_app._LAPIAN_YTDLP_RISK_ACCEPT,
    )

    assert gateway_app._lapian_ytdlp_enabled() is False


def test_frozen_store_profile_is_a_versioned_closed_capability_allowlist() -> None:
    profile = resolve_runtime_profile(
        frozen=True,
        environment={"NACHUAN_RUNTIME_PROFILE": "development"},
    )

    assert profile.schema == RUNTIME_PROFILE_SCHEMA == "nachuan.runtime-profile/v1"
    assert profile.name == "store"
    assert profile.frozen_python_excludes == (
        "gateway.providers.claude_code",
        "gateway.providers.codex",
        "yt_dlp",
    )
    assert profile.allows_connection_type("claude_code") is False
    assert profile.allows_provider_type("codex") is False
    for capability in (
        RuntimeCapability.CONTROLLED_AGENT_EXECUTION,
        RuntimeCapability.STUDIO_EXECUTION,
        RuntimeCapability.HOST_CLI_PROVIDER,
        RuntimeCapability.MCP_PLUGIN_REGISTRY,
        RuntimeCapability.PLUGIN_AUTO_DISCOVERY,
        RuntimeCapability.FORMAL_XREVIEW,
        RuntimeCapability.PAGE_AGENT_READ,
        RuntimeCapability.PAGE_AGENT_WRITE,
        RuntimeCapability.WORKSPACE_FILE_TOOLS,
    ):
        assert profile.allows(capability) is False

    assert profile.allows_external_program(
        authority=ExternalProgramAuthority.ATTESTED_HOST_TOOL,
        role="host-ai-cli",
    ) is False
    assert profile.allows_external_program(
        authority=ExternalProgramAuthority.FINAL_PAYLOAD_MANIFEST,
        role="ffmpeg",
        manifest_roles=frozenset(),
    ) is False
    assert profile.allows_external_program(
        authority=ExternalProgramAuthority.FINAL_PAYLOAD_MANIFEST,
        role="ffmpeg",
        manifest_roles=frozenset({"ffmpeg"}),
    ) is True


def test_frozen_cli_environment_helper_does_not_reopen_host_cli_secrets() -> None:
    sanitized = sanitized_cli_env(
        {
            "SYSTEMROOT": r"C:\Windows",
            "CODEX_HOME": r"C:\Users\owner\.codex",
            "OPENAI_API_KEY": "must-not-survive",
            "NACHUAN_WEIXIN_BRIDGE_API_KEY": "must-not-survive",
            "BOT_TOKEN": "must-not-survive",
            "HTTPS_PROXY": "http://user:password@proxy.invalid",
        }
    )

    assert sanitized == {
        "SYSTEMROOT": r"C:\Windows",
        "CODEX_HOME": r"C:\Users\owner\.codex",
        "NO_COLOR": "1",
    }
    profile = resolve_runtime_profile(frozen=True)
    assert profile.allows(RuntimeCapability.HOST_CLI_PROVIDER) is False
    assert profile.allows_external_program(
        authority=ExternalProgramAuthority.ATTESTED_HOST_TOOL,
        role="host-ai-cli",
    ) is False


def test_store_profile_is_materialized_from_the_versioned_manifest() -> None:
    path = PROJECT_ROOT / "config" / "store-runtime-profile.v1.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    profile = resolve_runtime_profile(frozen=True)

    assert payload["schema"] == profile.schema
    assert payload["name"] == profile.name
    assert payload["capabilities"] == sorted(item.value for item in profile.capabilities)
    assert payload["connectionTypes"] == sorted(profile.connection_types)
    assert payload["providerTypes"] == sorted(profile.provider_types)
    assert payload["externalProgramAuthorities"] == sorted(
        item.value for item in profile.external_program_authorities
    )
    assert payload["externalProgramRoles"] == sorted(profile.external_program_roles)
    assert payload["frozenPythonExcludes"] == list(profile.frozen_python_excludes)


def test_source_development_profile_preserves_existing_operator_capabilities() -> None:
    profile = resolve_runtime_profile(
        frozen=False,
        environment={"NACHUAN_RUNTIME_PROFILE": "development"},
    )

    assert profile.name == "development"
    assert profile.allows_connection_type("claude_code") is False
    assert profile.allows_provider_type("claude_code") is False
    assert profile.allows_provider_type("codex") is True
    assert profile.allows(RuntimeCapability.HOST_CLI_PROVIDER) is True
    assert profile.allows(RuntimeCapability.MCP_PLUGIN_REGISTRY) is True
    assert profile.frozen_python_excludes == ()


@pytest.mark.parametrize("provider_type", ["claude_code", "codex"])
def test_store_router_cannot_instantiate_host_cli_provider_even_after_validation_bypass(
    monkeypatch: pytest.MonkeyPatch,
    provider_type: str,
) -> None:
    monkeypatch.setenv("NACHUAN_RUNTIME_PROFILE", "store")
    router = Router.__new__(Router)

    assert router._make_provider_from_conn(
        "bypassed-record",
        {
            "type": provider_type,
            "api_key": "",
            "base_url": "",
            "enabled_models": [{"id": "demo", "upstream_model": "demo"}],
        },
    ) is None


def test_store_profile_blocks_mcp_registration_even_when_worker_support_is_wired(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(mcp_registry, "_ISOLATED_MCP_WORKER_WIRED", True, raising=False)
    monkeypatch.setenv("NACHUAN_RUNTIME_PROFILE", "store")
    assert mcp_registry.verified_mcp_enabled() is False

    monkeypatch.setenv("NACHUAN_RUNTIME_PROFILE", "development")
    assert mcp_registry.verified_mcp_enabled() is True


def test_store_catalog_does_not_register_host_cli_as_connectable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NACHUAN_RUNTIME_PROFILE", "store")
    catalog = Router.__new__(Router).catalog_view()
    cli = {item["name"]: item for item in catalog if item["name"] in {"claude_code", "codex"}}

    assert set(cli) == {"codex"}
    assert all(item["connectable"] is False for item in cli.values())
    assert all("运行配置" in str(item["unavailable_reason"]) for item in cli.values())


def test_store_agent_mutation_routes_fail_before_request_parsing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NACHUAN_RUNTIME_PROFILE", "store")

    with TestClient(app, raise_server_exceptions=False) as client:
        responses = [
            client.post(
                path,
                headers={**AUTH, "Content-Type": "application/json"},
                content=b"{",
            )
            for path in (
                "/v1/agent/run",
                "/v1/agent/inject",
                "/v1/agent/undo",
                "/v1/studio/execute",
                "/v1/mcp",
                "/v1/mcp/demo/remove",
            )
        ]

    assert [response.status_code for response in responses] == [503, 503, 503, 503, 503, 503]
    assert all("运行配置" in response.json()["detail"] for response in responses)


@pytest.mark.asyncio
async def test_store_tool_executor_denies_workspace_tools_before_path_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NACHUAN_RUNTIME_PROFILE", "store")

    result = await execute_tool("list_dir", {"path": "."}, workdir="")

    assert "运行配置" in result
    assert "独立低权限 worker" in result


@pytest.mark.asyncio
async def test_store_tool_agent_fails_before_tool_schemas_reach_a_model(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NACHUAN_RUNTIME_PROFILE", "store")

    with pytest.raises(PermissionError, match="运行配置.*独立低权限 worker"):
        await run_tool_agent(None, "unreachable-model", "noop", workdir="")


def test_store_mcp_registry_is_empty_and_immutable_even_if_worker_is_wired(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(mcp_registry, "_ISOLATED_MCP_WORKER_WIRED", True, raising=False)
    monkeypatch.setenv("NACHUAN_RUNTIME_PROFILE", "store")

    assert mcp_registry.list_servers() == {}
    with pytest.raises(RuntimeError, match="运行配置"):
        mcp_registry.add_server(
            "demo",
            command=str(Path(sys.executable).resolve()),
            sha256="0" * 64,
        )
    with pytest.raises(RuntimeError, match="运行配置"):
        mcp_registry.remove_server("demo")


def test_store_media_launch_rejects_env_attestation_without_final_manifest(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    ffmpeg = tmp_path / "ffmpeg.exe"
    ffprobe = tmp_path / "ffprobe.exe"
    ffmpeg.write_bytes(b"MZ-store-profile-test")
    ffprobe.write_bytes(b"MZ-store-profile-test-probe")
    monkeypatch.setenv("NACHUAN_RUNTIME_PROFILE", "store")
    monkeypatch.setenv("FFMPEG_BIN", str(ffmpeg.resolve()))
    monkeypatch.setenv("FFMPEG_SHA256", hashlib.sha256(ffmpeg.read_bytes()).hexdigest())
    monkeypatch.delenv("NACHUAN_MEDIA_RUNTIME_MANIFEST", raising=False)

    with pytest.raises(MediaBinaryUnavailable, match="最终载荷清单"):
        require_media_binary("ffmpeg")


def test_store_media_launch_accepts_exact_final_manifest_role(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    media = tmp_path / "media"
    media.mkdir()
    ffmpeg = media / "ffmpeg.exe"
    ffprobe = media / "ffprobe.exe"
    ffmpeg.write_bytes(b"MZ-store-profile-test")
    ffprobe.write_bytes(b"MZ-store-profile-test-probe")
    manifest = tmp_path / "media-runtime-manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema": "nachuan.media-runtime-manifest.v1",
                "artifacts": [
                    {
                        "path": "media/ffmpeg.exe",
                        "role": "ffmpeg",
                        "sha256": hashlib.sha256(ffmpeg.read_bytes()).hexdigest(),
                        "size": ffmpeg.stat().st_size,
                    },
                    {
                        "path": "media/ffprobe.exe",
                        "role": "ffprobe",
                        "sha256": hashlib.sha256(ffprobe.read_bytes()).hexdigest(),
                        "size": ffprobe.stat().st_size,
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("NACHUAN_RUNTIME_PROFILE", "store")
    monkeypatch.setenv("FFMPEG_BIN", str(ffmpeg.resolve()))
    monkeypatch.setenv("FFMPEG_SHA256", hashlib.sha256(ffmpeg.read_bytes()).hexdigest())
    monkeypatch.setenv("NACHUAN_MEDIA_RUNTIME_MANIFEST", str(manifest.resolve()))

    assert require_media_binary("ffmpeg").path == str(ffmpeg.resolve())


def test_store_local_model_launch_requires_llama_role_in_final_manifest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NACHUAN_RUNTIME_PROFILE", "store")

    assert local_model._profile_allows_runtime_manifest(  # noqa: SLF001
        {"model.gguf": ("model", "0" * 64)}
    ) is False
    assert local_model._profile_allows_runtime_manifest(  # noqa: SLF001
        {
            "llama-server.exe": ("llama-server", "1" * 64),
            "model.gguf": ("model", "0" * 64),
        }
    ) is True


def test_store_studio_executor_fails_before_media_or_job_allocation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("NACHUAN_RUNTIME_PROFILE", "store")

    with pytest.raises(PermissionError, match="运行配置.*独立低权限 worker"):
        start_execution(None, {"shots": [{}]}, str(tmp_path))
