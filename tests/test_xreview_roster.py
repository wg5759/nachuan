from __future__ import annotations

import json
import hashlib
import os
import shutil
import signal
import subprocess
import sys
import textwrap
import time
from pathlib import Path


PROJECT_ROOT = Path(__file__).parents[1]
GIT_BASH = Path(r"C:\Program Files\Git\bin\bash.exe")


def _run(
    *args: str,
    cwd: Path,
    env: dict[str, str] | None = None,
    timeout: float = 180.0,
) -> subprocess.CompletedProcess[str]:
    command = list(args)
    popen_kwargs: dict[str, object] = {}
    if os.name == "nt":
        popen_kwargs["creationflags"] = getattr(
            subprocess, "CREATE_NEW_PROCESS_GROUP", 0
        )
    else:
        popen_kwargs["start_new_session"] = True
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        **popen_kwargs,
    )
    try:
        stdout, _stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        if os.name == "nt":
            taskkill = Path(os.environ["WINDIR"]) / "System32" / "taskkill.exe"
            try:
                subprocess.run(
                    [str(taskkill), "/PID", str(process.pid), "/T", "/F"],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=15,
                )
            except (OSError, subprocess.TimeoutExpired):
                process.kill()
        else:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (OSError, ProcessLookupError):
                process.kill()
        try:
            stdout, _stderr = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout = exc.output or ""
        raise subprocess.TimeoutExpired(command, timeout, output=stdout) from None
    return subprocess.CompletedProcess(command, process.returncode, stdout, None)


def _git(repo: Path, *args: str) -> str:
    result = _run("git", *args, cwd=repo)
    assert result.returncode == 0, result.stdout
    return result.stdout.strip()


def _msys(path: Path) -> str:
    resolved = path.resolve()
    drive = resolved.drive.rstrip(":").lower()
    suffix = resolved.as_posix().split(":", 1)[-1]
    return f"/{drive}{suffix}"


def test_run_timeout_terminates_pipe_inheriting_descendants(tmp_path: Path) -> None:
    sentinel = tmp_path / "descendant-survived-timeout"
    script = f'( sleep 2; : > "{_msys(sentinel)}" ) & wait'

    try:
        _run(str(GIT_BASH), "-lc", script, cwd=tmp_path, timeout=0.1)
    except subprocess.TimeoutExpired:
        pass
    else:
        raise AssertionError("the outer watchdog did not expire")

    time.sleep(2.2)
    assert not sentinel.exists()


def _write_executable(path: Path, source: str) -> None:
    path.write_text(textwrap.dedent(source).lstrip(), encoding="utf-8", newline="\n")
    path.chmod(0o755)


def _manifest_path(path: Path) -> str:
    """Return one path spelling accepted by both Git Bash and native Python."""
    return path.resolve().as_posix()


def _write_tool_trust_manifest(
    destination: Path,
    fake_bin: Path,
    *,
    mode: str = "test-only",
    native_overrides: dict[str, Path] | None = None,
    reviewer_overrides: dict[str, Path] | None = None,
) -> tuple[Path, str]:
    native_tools = {
        "bash": GIT_BASH,
        "git": Path(shutil.which("git") or ""),
        "python": Path(sys.executable),
        "taskkill": Path(os.environ["WINDIR"]) / "System32" / "taskkill.exe",
    }
    native_tools.update(native_overrides or {})
    reviewer_tools = {
        "kimi": fake_bin / "kimi",
        "codex": fake_bin / "codex",
        "opencode": fake_bin / "opencode",
    }
    reviewer_tools.update(reviewer_overrides or {})
    lines = ["schema\t1", f"mode\t{mode}"]
    for name in sorted(native_tools | reviewer_tools):
        path = (native_tools | reviewer_tools)[name].resolve()
        launch = (
            "native"
            if name in native_tools or name in (reviewer_overrides or {})
            else "bash-script"
        )
        payload = path.read_bytes()
        lines.append(
            "\t".join(
                (
                    "tool",
                    name,
                    launch,
                    _manifest_path(path),
                    str(len(payload)),
                    hashlib.sha256(payload).hexdigest(),
                )
            )
        )
    destination.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return destination, hashlib.sha256(destination.read_bytes()).hexdigest()


def _make_fake_reviewers(fake_bin: Path) -> None:
    fake_bin.mkdir()
    _write_executable(
        fake_bin / "kimi",
        r'''
        #!/usr/bin/env bash
        model=''
        while [[ "$#" -gt 0 ]]; do
          if [[ "$1" == '-m' ]]; then
            model="$2"
            shift 2
          else
            shift
          fi
        done
        printf '%s\n' "$model" >> "$FAKE_CALLS"
        session_id='session_11111111-2222-4333-8444-555555555555'
        wire="$FAKE_KIMI_CODE_HOME/sessions/workspace/$session_id/agents/main/wire.jsonl"
        mkdir -p "${wire%/*}"
        observed_model="${FAKE_KIMI_WIRE_MODEL:-k3}"
        observed_usage="${FAKE_KIMI_USAGE_MODEL:-kimi-code/k3}"
        observed_alias="${FAKE_KIMI_ALIAS:-kimi-code/k3}"
        request_id="${FAKE_KIMI_REQUEST_ID:-request-11111111}"
        usage_request_id="${FAKE_KIMI_USAGE_REQUEST_ID:-$request_id}"
        printf '{"type":"config.update","modelAlias":"%s"}\n' "$observed_alias" > "$wire"
        if [[ -n "${FAKE_KIMI_DUPLICATE_ALIAS:-}" ]]; then
          printf '{"type":"config.update","modelAlias":"%s"}\n' "$observed_alias" >> "$wire"
        fi
        printf '{"type":"llm.request","model":"%s","modelAlias":"%s","requestId":"%s"}\n' "$observed_model" "$observed_alias" "$request_id" >> "$wire"
        if [[ -n "${FAKE_KIMI_DUPLICATE_REQUEST:-}" ]]; then
          printf '{"type":"llm.request","model":"%s","modelAlias":"%s","requestId":"%s"}\n' "$observed_model" "$observed_alias" "$request_id" >> "$wire"
        fi
        printf '{"type":"usage.record","model":"%s","requestId":"%s"}\n' "$observed_usage" "$usage_request_id" >> "$wire"
        if [[ -n "${FAKE_KIMI_DUPLICATE_USAGE:-}" ]]; then
          printf '{"type":"usage.record","model":"%s","requestId":"%s"}\n' "$observed_usage" "$usage_request_id" >> "$wire"
        fi
        if [[ "${FAKE_NO_VERDICT_MODEL:-}" == "$model" ]]; then
          printf '{"role":"assistant","content":"review completed without a structured marker"}\n'
        else
          printf '{"role":"assistant","content":"XREVIEW_VERDICT_JSON={\\"schema\\":1,\\"reviewed_commit\\":\\"%s\\",\\"reviewed_tree\\":\\"%s\\",\\"verdict\\":\\"pass\\",\\"summary\\":\\"independent review passed\\",\\"findings\\":[]}"}\n' "$FAKE_TARGET" "$FAKE_TREE"
        fi
        if [[ -n "${FAKE_KIMI_DUPLICATE_ASSISTANT:-}" ]]; then
          printf '{"role":"assistant","content":"second report must be rejected"}\n'
        fi
        printf '{"role":"meta","type":"session.resume_hint","session_id":"%s","command":"resume","content":"resume hint"}\n' "$session_id"
        ''',
    )
    _write_executable(
        fake_bin / "codex",
        r'''
        #!/usr/bin/env bash
        : > "$FAKE_CODEX_SENTINEL"
        printf '%s\n' 'gpt-5.6-sol' >> "$FAKE_CALLS"
        printf 'model: gpt-5.6-sol\nsandbox: read-only\n'
        printf 'XREVIEW_VERDICT_JSON={"schema":1,"reviewed_commit":"%s","reviewed_tree":"%s","verdict":"pass","summary":"independent review passed","findings":[]}\n' "$FAKE_TARGET" "$FAKE_TREE"
        ''',
    )
    _write_executable(
        fake_bin / "opencode",
        r'''
        #!/usr/bin/env bash
        model=''
        while [[ "$#" -gt 0 ]]; do
          if [[ "$1" == '-m' ]]; then
            model="$2"
            shift 2
          else
            shift
          fi
        done
        slug="${model#volcengine/}"
        printf '%s\n' "$slug" >> "$FAKE_CALLS"
        if [[ -n "${FAKE_RAW_CANARY:-}" ]]; then
          printf '%s\n' "$FAKE_RAW_CANARY"
        fi
        printf '> plan · %s\n' "$slug"
        if [[ "${FAKE_MUTATE_MODEL:-}" == "$slug" ]]; then
          printf 'tampered\n' > input/app.txt
        fi
        if [[ "${FAKE_HANG_MODEL:-}" == "$slug" ]]; then
          ( sleep 3; : > "$FAKE_ORPHAN_SENTINEL" ) &
          wait
          exit 0
        elif [[ "${FAKE_NO_VERDICT_MODEL:-}" == "$slug" ]]; then
          exit 0
        elif [[ "${FAKE_P1_MODEL:-}" == "$slug" ]]; then
          printf 'XREVIEW_VERDICT_JSON={"schema":1,"reviewed_commit":"%s","reviewed_tree":"%s","verdict":"fail","summary":"reproducible release blocker","findings":[{"severity":"P1","file":"app.txt","line":"1","summary":"blocking defect"}]}\n' "$FAKE_TARGET" "$FAKE_TREE"
        else
          printf 'XREVIEW_VERDICT_JSON={"schema":1,"reviewed_commit":"%s","reviewed_tree":"%s","verdict":"pass","summary":"independent review passed","findings":[]}\n' "$FAKE_TARGET" "$FAKE_TREE"
        fi
        if [[ "${FAKE_REPLACE_RUNNING_MODEL:-}" == "$slug" ]]; then
          if printf '# replaced while reviewer was live\n' > "$FAKE_REVIEWER_SELF_PATH"; then
            : > "$FAKE_REPLACEMENT_SUCCEEDED"
          else
            : > "$FAKE_REPLACEMENT_BLOCKED"
          fi
        fi
        ''',
    )


def _make_path_attackers(fake_bin: Path, sentinel: Path) -> None:
    fake_bin.mkdir()
    for name in ("kimi", "codex", "opencode"):
        _write_executable(
            fake_bin / name,
            f'''\
            #!/usr/bin/env bash
            printf '%s\n' '{name}' >> "{_msys(sentinel)}"
            exit 97
            ''',
        )


def _trust_failure_env(
    tmp_path: Path,
    fake_bin: Path,
    output: Path,
    manifest: Path,
    manifest_sha256: str,
) -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "FAKE_CALLS": _msys(tmp_path / "calls.txt"),
            "XREVIEW_OUTPUT_DIR": _msys(output),
            "XREVIEW_PYTHON": _msys(Path(sys.executable)),
            "XREVIEW_TOOL_TRUST_MANIFEST": _manifest_path(manifest),
            "XREVIEW_TOOL_TRUST_MANIFEST_SHA256": manifest_sha256,
            "XREVIEW_TRUST_MODE": "test-only",
            "FAKE_KIMI_CODE_HOME": _msys(tmp_path / "fake-kimi-home"),
        }
    )
    return env


def _add_test_tool_trust(
    env: dict[str, str],
    tmp_path: Path,
    fake_bin: Path,
    *,
    native_overrides: dict[str, Path] | None = None,
) -> Path:
    manifest, digest = _write_tool_trust_manifest(
        tmp_path / "xreview-tools.tsv",
        fake_bin,
        native_overrides=native_overrides,
    )
    env.update(
        {
            "XREVIEW_TOOL_TRUST_MANIFEST": _manifest_path(manifest),
            "XREVIEW_TOOL_TRUST_MANIFEST_SHA256": digest,
            "XREVIEW_TRUST_MODE": "test-only",
            "FAKE_KIMI_CODE_HOME": _msys(tmp_path / "fake-kimi-home"),
        }
    )
    return manifest


def _make_review_repo(tmp_path: Path) -> tuple[Path, str, str]:
    repo = tmp_path / "repo"
    (repo / "scripts").mkdir(parents=True)
    shutil.copy2(PROJECT_ROOT / "scripts" / "xreview.sh", repo / "scripts" / "xreview.sh")
    (repo / "app.txt").write_text("committed-v1\n", encoding="utf-8")
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "xreview@example.invalid")
    _git(repo, "config", "user.name", "xreview-test")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "base")
    (repo / "app.txt").write_text("committed-v2\n", encoding="utf-8")
    _git(repo, "add", "app.txt")
    _git(repo, "commit", "-qm", "target")
    target = _git(repo, "rev-parse", "HEAD")
    tree = _git(repo, "rev-parse", "HEAD^{tree}")
    (repo / "app.txt").write_text("DIRTY-WORKTREE-MUST-NOT-BE-REVIEWED\n", encoding="utf-8")
    return repo, target, tree


def test_codex_initiator_is_zero_vote_and_four_reviewers_use_frozen_target(
    tmp_path: Path,
) -> None:
    repo, target, tree = _make_review_repo(tmp_path)
    fake_bin = tmp_path / "fake-bin"
    _make_fake_reviewers(fake_bin)
    output = tmp_path / "audit-output"
    calls = tmp_path / "calls.txt"
    codex_sentinel = tmp_path / "codex-was-invoked"
    env = os.environ.copy()
    env.update(
        {
            "PATH": f"{fake_bin}{os.pathsep}{env['PATH']}",
            "FAKE_CALLS": _msys(calls),
            "FAKE_CODEX_SENTINEL": _msys(codex_sentinel),
            "FAKE_TARGET": target,
            "FAKE_TREE": tree,
            "XREVIEW_OUTPUT_DIR": _msys(output),
            "XREVIEW_PYTHON": _msys(Path(sys.executable)),
        }
    )
    _add_test_tool_trust(env, tmp_path, fake_bin)
    index_before = hashlib.sha256((repo / ".git" / "index").read_bytes()).hexdigest()

    result = _run(
        str(GIT_BASH),
        "scripts/xreview.sh",
        target,
        cwd=repo,
        env=env,
    )

    assert result.returncode == 3, result.stdout
    assert "XREVIEW_EXECUTION_RESULT=NON_FORMAL_TEST_COMPLETE" in result.stdout
    assert "XREVIEW_SECURITY_VERDICT=NON_FORMAL_TEST_ONLY" in result.stdout
    assert "PASS" not in result.stdout
    assert not codex_sentinel.exists(), "the initiating Codex family must not review/vote"
    assert sorted(calls.read_text(encoding="utf-8").splitlines()) == [
        "deepseek-v4-pro",
        "glm-5.2",
        "kimi-code/k3",
        "minimax-m3",
    ]
    manifest_text = (output / "audit-manifest.json").read_text(encoding="utf-8")
    assert "PASS" not in manifest_text
    manifest = json.loads(manifest_text)
    assert manifest["initiator"] == {
        "family": "openai",
        "invoked_as_reviewer": False,
        "vote_weight": 0,
    }
    assert manifest["target"]["commit"] == target
    assert manifest["target"]["tree"] == tree
    assert manifest["execution_result"] == "NON_FORMAL_TEST_COMPLETE"
    assert manifest["security_verdict"] == "NON_FORMAL_TEST_ONLY"
    assert manifest["formal_independent_domain_count"] == 2
    assert manifest["formal_four_independent_votes_satisfied"] is False
    assert {reviewer["family"] for reviewer in manifest["reviewers"]} == {
        "deepseek",
        "zhipu",
        "moonshot",
        "minimax",
    }
    for reviewer in manifest["reviewers"]:
        assert reviewer["receipt"]["route_evidence"]
        assert reviewer["receipt"]["completion_evidence"] == "exit=0+structured-verdict-marker"
        assert reviewer["status"]["containment"] == "windows-job-object"
        assert reviewer["status"]["containment_assigned"] is True
        assert reviewer["status"]["startup_gate_released"] is True
    kimi = next(item for item in manifest["reviewers"] if item["family"] == "moonshot")
    assert kimi["kind"] == "kimi"
    assert kimi["receipt"]["requested_model"] == "kimi-code/k3"
    assert kimi["receipt"]["observed_model"] == "k3"
    assert kimi["receipt"]["expected_route"] == {
        "requested_model": "kimi-code/k3",
        "connection_domain": "kimi-code-login",
    }
    assert kimi["receipt"]["observed_route"]["config_model_alias"] == "kimi-code/k3"
    assert kimi["receipt"]["observed_route"]["llm_request_model"] == "k3"
    assert kimi["receipt"]["observed_route"]["usage_model"] == "kimi-code/k3"
    assert kimi["receipt"]["observed_route"]["session_new_after_launch_baseline"] is True
    assert kimi["receipt"]["observed_route"]["event_counts"] == {
        "model_alias": 1,
        "llm_request": 1,
        "usage_record": 1,
    }
    assert kimi["receipt"]["observed_route"]["request_correlation_id"] == "request-11111111"
    assert (
        kimi["receipt"]["observed_route"]["request_correlation_evidence"]
        == "wire.llm.request+usage.record"
    )
    assert len(kimi["receipt"]["observed_route"]["launch_baseline_sha256"]) == 64
    assert kimi["receipt"]["route_evidence"].startswith("kimi.stream-json:")
    expected_formal_provider_env = {
        "deepseek": {
            "ARK_API_KEY",
            "VOLCENGINE_API_KEY",
            "VOLCENGINE_ACCESS_KEY",
            "VOLCENGINE_SECRET_KEY",
            "OPENCODE_CONFIG_DIR",
        },
        "zhipu": {
            "ARK_API_KEY",
            "VOLCENGINE_API_KEY",
            "VOLCENGINE_ACCESS_KEY",
            "VOLCENGINE_SECRET_KEY",
            "OPENCODE_CONFIG_DIR",
        },
        "moonshot": {"KIMI_API_KEY", "KIMI_BASE_URL", "KIMI_CODE_HOME"},
        "minimax": {
            "ARK_API_KEY",
            "VOLCENGINE_API_KEY",
            "VOLCENGINE_ACCESS_KEY",
            "VOLCENGINE_SECRET_KEY",
            "OPENCODE_CONFIG_DIR",
        },
    }
    for reviewer in manifest["reviewers"]:
        status = reviewer["status"]
        assert status["provider_environment_policy_family"] == reviewer["family"]
        assert set(status["formal_provider_environment_allowlist"]) == expected_formal_provider_env[
            reviewer["family"]
        ]
    snapshot = output / "review-root" / "input"
    assert (snapshot / "app.txt").read_text(encoding="utf-8") == "committed-v2\n"
    assert "DIRTY-WORKTREE" not in (snapshot / "app.txt").read_text(encoding="utf-8")
    assert (repo / "app.txt").read_text(encoding="utf-8") == "DIRTY-WORKTREE-MUST-NOT-BE-REVIEWED\n"
    assert hashlib.sha256((repo / ".git" / "index").read_bytes()).hexdigest() == index_before


def test_supervisor_probe_separates_slow_child_startup_from_runtime_timeout(
    tmp_path: Path,
) -> None:
    repo, target, tree = _make_review_repo(tmp_path)
    script = repo / "scripts" / "xreview.sh"
    source = script.read_text(encoding="utf-8")
    original = (
        "import os,time; print(f\"CHILD_WINPID={os.getpid()}\", flush=True); "
        "time.sleep(60)"
    )
    delayed = (
        "import os,time; time.sleep(4); "
        "print(f\"CHILD_WINPID={os.getpid()}\", flush=True); time.sleep(60)"
    )
    assert source.count(original) == 1
    script.write_text(source.replace(original, delayed), encoding="utf-8", newline="\n")

    fake_bin = tmp_path / "fake-bin"
    _make_fake_reviewers(fake_bin)
    output = tmp_path / "audit-output"
    env = os.environ.copy()
    env.update(
        {
            "FAKE_CALLS": _msys(tmp_path / "calls.txt"),
            "FAKE_CODEX_SENTINEL": _msys(tmp_path / "codex-was-invoked"),
            "FAKE_TARGET": target,
            "FAKE_TREE": tree,
            "XREVIEW_OUTPUT_DIR": _msys(output),
            "XREVIEW_PYTHON": _msys(Path(sys.executable)),
        }
    )
    _add_test_tool_trust(env, tmp_path, fake_bin)

    result = _run(
        str(GIT_BASH),
        "scripts/xreview.sh",
        target,
        cwd=repo,
        env=env,
    )

    assert result.returncode == 3, result.stdout
    status = json.loads((output / "supervisor-probe.status.json").read_text(encoding="utf-8"))
    assert status["startup_ready"] is True
    assert status["startup_wait_seconds"] >= 4
    assert status["rc"] == 124
    assert status["reason"] == "timeout"
    assert status["tree_kill_confirmed"] is True


def test_explicit_deepseek_initiator_is_excluded_and_has_zero_vote(
    tmp_path: Path,
) -> None:
    repo, target, tree = _make_review_repo(tmp_path)
    fake_bin = tmp_path / "fake-bin"
    _make_fake_reviewers(fake_bin)
    output = tmp_path / "audit-output"
    calls = tmp_path / "calls.txt"
    codex_sentinel = tmp_path / "codex-was-invoked"
    env = os.environ.copy()
    env.update(
        {
            "PATH": f"{fake_bin}{os.pathsep}{env['PATH']}",
            "FAKE_CALLS": _msys(calls),
            "FAKE_CODEX_SENTINEL": _msys(codex_sentinel),
            "FAKE_TARGET": target,
            "FAKE_TREE": tree,
            "XREVIEW_OUTPUT_DIR": _msys(output),
            "XREVIEW_PYTHON": _msys(Path(sys.executable)),
        }
    )
    _add_test_tool_trust(env, tmp_path, fake_bin)

    result = _run(
        str(GIT_BASH),
        "scripts/xreview.sh",
        target,
        "deepseek",
        cwd=repo,
        env=env,
    )

    assert result.returncode == 3, result.stdout
    assert "XREVIEW_EXECUTION_RESULT=NON_FORMAL_TEST_COMPLETE" in result.stdout
    assert codex_sentinel.exists()
    assert sorted(calls.read_text(encoding="utf-8").splitlines()) == [
        "glm-5.2",
        "gpt-5.6-sol",
        "kimi-code/k3",
        "minimax-m3",
    ]
    manifest = json.loads((output / "audit-manifest.json").read_text(encoding="utf-8"))
    assert manifest["initiator"] == {
        "family": "deepseek",
        "invoked_as_reviewer": False,
        "vote_weight": 0,
    }
    assert manifest["reviewer_count"] == 4
    assert {reviewer["family"] for reviewer in manifest["reviewers"]} == {
        "openai",
        "zhipu",
        "moonshot",
        "minimax",
    }
    openai = next(item for item in manifest["reviewers"] if item["family"] == "openai")
    assert set(openai["status"]["formal_provider_environment_allowlist"]) == {
        "OPENAI_API_KEY",
        "OPENAI_BASE_URL",
        "OPENAI_ORG_ID",
        "OPENAI_PROJECT_ID",
        "CODEX_HOME",
    }


def test_completed_p1_review_fails_security_without_falsifying_execution(
    tmp_path: Path,
) -> None:
    repo, target, tree = _make_review_repo(tmp_path)
    fake_bin = tmp_path / "fake-bin"
    _make_fake_reviewers(fake_bin)
    output = tmp_path / "audit-output"
    env = os.environ.copy()
    env.update(
        {
            "PATH": f"{fake_bin}{os.pathsep}{env['PATH']}",
            "FAKE_CALLS": _msys(tmp_path / "calls.txt"),
            "FAKE_CODEX_SENTINEL": _msys(tmp_path / "codex-was-invoked"),
            "FAKE_TARGET": target,
            "FAKE_TREE": tree,
            "FAKE_P1_MODEL": "glm-5.2",
            "XREVIEW_OUTPUT_DIR": _msys(output),
            "XREVIEW_PYTHON": _msys(Path(sys.executable)),
        }
    )
    _add_test_tool_trust(env, tmp_path, fake_bin)

    result = _run(
        str(GIT_BASH),
        "scripts/xreview.sh",
        target,
        cwd=repo,
        env=env,
    )

    assert result.returncode == 1, result.stdout
    assert "XREVIEW_EXECUTION_RESULT=NON_FORMAL_TEST_COMPLETE" in result.stdout
    assert "XREVIEW_SECURITY_VERDICT=FAIL" in result.stdout
    manifest_path = output / "audit-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["execution_result"] == "NON_FORMAL_TEST_COMPLETE"
    assert manifest["security_verdict"] == "FAIL"
    glm = next(item for item in manifest["reviewers"] if item["family"] == "zhipu")
    assert glm["receipt"]["verdict"] == "fail"
    assert glm["receipt"]["blocker_count"] == 1
    expected_hash = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    assert (output / "audit-manifest.sha256").read_text(encoding="utf-8").split()[0] == expected_hash


def test_exit_zero_without_structured_completion_is_blocked(
    tmp_path: Path,
) -> None:
    repo, target, tree = _make_review_repo(tmp_path)
    fake_bin = tmp_path / "fake-bin"
    _make_fake_reviewers(fake_bin)
    output = tmp_path / "audit-output"
    env = os.environ.copy()
    env.update(
        {
            "PATH": f"{fake_bin}{os.pathsep}{env['PATH']}",
            "FAKE_CALLS": _msys(tmp_path / "calls.txt"),
            "FAKE_CODEX_SENTINEL": _msys(tmp_path / "codex-was-invoked"),
            "FAKE_TARGET": target,
            "FAKE_TREE": tree,
            "FAKE_NO_VERDICT_MODEL": "kimi-code/k3",
            "XREVIEW_OUTPUT_DIR": _msys(output),
            "XREVIEW_PYTHON": _msys(Path(sys.executable)),
        }
    )
    _add_test_tool_trust(env, tmp_path, fake_bin)

    result = _run(
        str(GIT_BASH),
        "scripts/xreview.sh",
        target,
        cwd=repo,
        env=env,
    )

    assert result.returncode == 1, result.stdout
    assert "XREVIEW_EXECUTION_RESULT=FAIL" in result.stdout
    assert "XREVIEW_SECURITY_VERDICT=BLOCKED" in result.stdout
    manifest = json.loads((output / "audit-manifest.json").read_text(encoding="utf-8"))
    assert manifest["execution_result"] == "FAIL"
    assert manifest["security_verdict"] == "BLOCKED"
    kimi = next(item for item in manifest["reviewers"] if item["family"] == "moonshot")
    assert kimi["status"]["rc"] == 0
    assert "receipt" not in kimi


def test_kimi_stdout_claim_cannot_override_conflicting_session_model(
    tmp_path: Path,
) -> None:
    repo, target, tree = _make_review_repo(tmp_path)
    fake_bin = tmp_path / "fake-bin"
    _make_fake_reviewers(fake_bin)
    output = tmp_path / "audit-output"
    env = os.environ.copy()
    env.update(
        {
            "FAKE_CALLS": _msys(tmp_path / "calls.txt"),
            "FAKE_CODEX_SENTINEL": _msys(tmp_path / "codex-was-invoked"),
            "FAKE_TARGET": target,
            "FAKE_TREE": tree,
            "FAKE_KIMI_WIRE_MODEL": "not-k3",
            "XREVIEW_OUTPUT_DIR": _msys(output),
        }
    )
    _add_test_tool_trust(env, tmp_path, fake_bin)

    result = _run(str(GIT_BASH), "scripts/xreview.sh", target, cwd=repo, env=env)

    assert result.returncode == 1, result.stdout
    assert "XREVIEW_EXECUTION_RESULT=FAIL" in result.stdout
    manifest = json.loads((output / "audit-manifest.json").read_text(encoding="utf-8"))
    kimi = next(item for item in manifest["reviewers"] if item["family"] == "moonshot")
    assert kimi["status"]["rc"] == 0
    assert "receipt" not in kimi


def test_kimi_rejects_a_session_that_existed_before_this_reviewer_launch(
    tmp_path: Path,
) -> None:
    repo, target, tree = _make_review_repo(tmp_path)
    fake_bin = tmp_path / "fake-bin"
    _make_fake_reviewers(fake_bin)
    output = tmp_path / "audit-output"
    env = os.environ.copy()
    env.update(
        {
            "FAKE_CALLS": _msys(tmp_path / "calls.txt"),
            "FAKE_CODEX_SENTINEL": _msys(tmp_path / "codex-was-invoked"),
            "FAKE_TARGET": target,
            "FAKE_TREE": tree,
            "XREVIEW_OUTPUT_DIR": _msys(output),
        }
    )
    _add_test_tool_trust(env, tmp_path, fake_bin)
    old_wire = (
        tmp_path
        / "fake-kimi-home"
        / "sessions"
        / "workspace"
        / "session_11111111-2222-4333-8444-555555555555"
        / "agents"
        / "main"
        / "wire.jsonl"
    )
    old_wire.parent.mkdir(parents=True)
    old_wire.write_text(
        '{"type":"config.update","modelAlias":"kimi-code/k3"}\n'
        '{"type":"llm.request","model":"k3","modelAlias":"kimi-code/k3"}\n'
        '{"type":"usage.record","model":"kimi-code/k3"}\n',
        encoding="utf-8",
    )

    result = _run(str(GIT_BASH), "scripts/xreview.sh", target, cwd=repo, env=env)

    assert result.returncode == 1, result.stdout
    manifest = json.loads((output / "audit-manifest.json").read_text(encoding="utf-8"))
    kimi = next(item for item in manifest["reviewers"] if item["family"] == "moonshot")
    assert kimi["status"]["rc"] == 0
    assert "receipt" not in kimi


def test_kimi_requires_exactly_one_llm_request_event(tmp_path: Path) -> None:
    repo, target, tree = _make_review_repo(tmp_path)
    fake_bin = tmp_path / "fake-bin"
    _make_fake_reviewers(fake_bin)
    output = tmp_path / "audit-output"
    env = os.environ.copy()
    env.update(
        {
            "FAKE_CALLS": _msys(tmp_path / "calls.txt"),
            "FAKE_CODEX_SENTINEL": _msys(tmp_path / "codex-was-invoked"),
            "FAKE_TARGET": target,
            "FAKE_TREE": tree,
            "FAKE_KIMI_DUPLICATE_REQUEST": "1",
            "XREVIEW_OUTPUT_DIR": _msys(output),
        }
    )
    _add_test_tool_trust(env, tmp_path, fake_bin)

    result = _run(str(GIT_BASH), "scripts/xreview.sh", target, cwd=repo, env=env)

    assert result.returncode == 1, result.stdout
    manifest = json.loads((output / "audit-manifest.json").read_text(encoding="utf-8"))
    kimi = next(item for item in manifest["reviewers"] if item["family"] == "moonshot")
    assert kimi["status"]["rc"] == 0
    assert "receipt" not in kimi


def test_kimi_requires_exactly_one_model_alias_event(tmp_path: Path) -> None:
    repo, target, tree = _make_review_repo(tmp_path)
    fake_bin = tmp_path / "fake-bin"
    _make_fake_reviewers(fake_bin)
    output = tmp_path / "audit-output"
    env = os.environ.copy()
    env.update(
        {
            "FAKE_CALLS": _msys(tmp_path / "calls.txt"),
            "FAKE_CODEX_SENTINEL": _msys(tmp_path / "codex-was-invoked"),
            "FAKE_TARGET": target,
            "FAKE_TREE": tree,
            "FAKE_KIMI_DUPLICATE_ALIAS": "1",
            "XREVIEW_OUTPUT_DIR": _msys(output),
        }
    )
    _add_test_tool_trust(env, tmp_path, fake_bin)

    result = _run(str(GIT_BASH), "scripts/xreview.sh", target, cwd=repo, env=env)

    assert result.returncode == 1, result.stdout
    manifest = json.loads((output / "audit-manifest.json").read_text(encoding="utf-8"))
    kimi = next(item for item in manifest["reviewers"] if item["family"] == "moonshot")
    assert kimi["status"]["rc"] == 0
    assert "receipt" not in kimi


def test_kimi_requires_exactly_one_usage_record_event(tmp_path: Path) -> None:
    repo, target, tree = _make_review_repo(tmp_path)
    fake_bin = tmp_path / "fake-bin"
    _make_fake_reviewers(fake_bin)
    output = tmp_path / "audit-output"
    env = os.environ.copy()
    env.update(
        {
            "FAKE_CALLS": _msys(tmp_path / "calls.txt"),
            "FAKE_CODEX_SENTINEL": _msys(tmp_path / "codex-was-invoked"),
            "FAKE_TARGET": target,
            "FAKE_TREE": tree,
            "FAKE_KIMI_DUPLICATE_USAGE": "1",
            "XREVIEW_OUTPUT_DIR": _msys(output),
        }
    )
    _add_test_tool_trust(env, tmp_path, fake_bin)

    result = _run(str(GIT_BASH), "scripts/xreview.sh", target, cwd=repo, env=env)

    assert result.returncode == 1, result.stdout
    manifest = json.loads((output / "audit-manifest.json").read_text(encoding="utf-8"))
    kimi = next(item for item in manifest["reviewers"] if item["family"] == "moonshot")
    assert kimi["status"]["rc"] == 0
    assert "receipt" not in kimi


def test_kimi_request_and_usage_identifiers_must_match_when_present(
    tmp_path: Path,
) -> None:
    repo, target, tree = _make_review_repo(tmp_path)
    fake_bin = tmp_path / "fake-bin"
    _make_fake_reviewers(fake_bin)
    output = tmp_path / "audit-output"
    env = os.environ.copy()
    env.update(
        {
            "FAKE_CALLS": _msys(tmp_path / "calls.txt"),
            "FAKE_CODEX_SENTINEL": _msys(tmp_path / "codex-was-invoked"),
            "FAKE_TARGET": target,
            "FAKE_TREE": tree,
            "FAKE_KIMI_REQUEST_ID": "request-one",
            "FAKE_KIMI_USAGE_REQUEST_ID": "request-two",
            "XREVIEW_OUTPUT_DIR": _msys(output),
        }
    )
    _add_test_tool_trust(env, tmp_path, fake_bin)

    result = _run(str(GIT_BASH), "scripts/xreview.sh", target, cwd=repo, env=env)

    assert result.returncode == 1, result.stdout
    manifest = json.loads((output / "audit-manifest.json").read_text(encoding="utf-8"))
    kimi = next(item for item in manifest["reviewers"] if item["family"] == "moonshot")
    assert kimi["status"]["rc"] == 0
    assert "receipt" not in kimi


def test_kimi_requires_one_assistant_report(tmp_path: Path) -> None:
    repo, target, tree = _make_review_repo(tmp_path)
    fake_bin = tmp_path / "fake-bin"
    _make_fake_reviewers(fake_bin)
    output = tmp_path / "audit-output"
    env = os.environ.copy()
    env.update(
        {
            "FAKE_CALLS": _msys(tmp_path / "calls.txt"),
            "FAKE_CODEX_SENTINEL": _msys(tmp_path / "codex-was-invoked"),
            "FAKE_TARGET": target,
            "FAKE_TREE": tree,
            "FAKE_KIMI_DUPLICATE_ASSISTANT": "1",
            "XREVIEW_OUTPUT_DIR": _msys(output),
        }
    )
    _add_test_tool_trust(env, tmp_path, fake_bin)

    result = _run(str(GIT_BASH), "scripts/xreview.sh", target, cwd=repo, env=env)

    assert result.returncode == 1, result.stdout
    assert "XREVIEW_EXECUTION_RESULT=FAIL" in result.stdout
    manifest = json.loads((output / "audit-manifest.json").read_text(encoding="utf-8"))
    kimi = next(item for item in manifest["reviewers"] if item["family"] == "moonshot")
    assert "receipt" not in kimi


def test_raw_reviewer_logs_are_retained_but_not_echoed_to_console(tmp_path: Path) -> None:
    repo, target, tree = _make_review_repo(tmp_path)
    fake_bin = tmp_path / "fake-bin"
    _make_fake_reviewers(fake_bin)
    output = tmp_path / "audit-output"
    canary = "RAW_REVIEWER_LOG_MUST_NOT_REACH_CONSOLE"
    env = os.environ.copy()
    env.update(
        {
            "FAKE_CALLS": _msys(tmp_path / "calls.txt"),
            "FAKE_CODEX_SENTINEL": _msys(tmp_path / "codex-was-invoked"),
            "FAKE_TARGET": target,
            "FAKE_TREE": tree,
            "FAKE_RAW_CANARY": canary,
            "XREVIEW_OUTPUT_DIR": _msys(output),
        }
    )
    _add_test_tool_trust(env, tmp_path, fake_bin)

    result = _run(
        str(GIT_BASH),
        "scripts/xreview.sh",
        target,
        cwd=repo,
        env=env,
    )

    assert result.returncode == 3, result.stdout
    assert canary not in result.stdout
    assert any(
        canary in path.read_text(encoding="utf-8", errors="replace")
        for path in (output / "logs").glob("*.log")
    ), "raw log evidence was discarded instead of quarantined"


def test_snapshot_tampering_is_detected_even_when_reviewer_reports_pass(
    tmp_path: Path,
) -> None:
    repo, target, tree = _make_review_repo(tmp_path)
    fake_bin = tmp_path / "fake-bin"
    _make_fake_reviewers(fake_bin)
    output = tmp_path / "audit-output"
    env = os.environ.copy()
    env.update(
        {
            "PATH": f"{fake_bin}{os.pathsep}{env['PATH']}",
            "FAKE_CALLS": _msys(tmp_path / "calls.txt"),
            "FAKE_CODEX_SENTINEL": _msys(tmp_path / "codex-was-invoked"),
            "FAKE_TARGET": target,
            "FAKE_TREE": tree,
            "FAKE_MUTATE_MODEL": "glm-5.2",
            "XREVIEW_OUTPUT_DIR": _msys(output),
            "XREVIEW_PYTHON": _msys(Path(sys.executable)),
        }
    )
    _add_test_tool_trust(env, tmp_path, fake_bin)

    result = _run(
        str(GIT_BASH),
        "scripts/xreview.sh",
        target,
        cwd=repo,
        env=env,
    )

    assert result.returncode == 1, result.stdout
    assert "frozen review input changed during review" in result.stdout
    assert "XREVIEW_EXECUTION_RESULT=FAIL" in result.stdout
    assert "XREVIEW_SECURITY_VERDICT=BLOCKED" in result.stdout
    manifest = json.loads((output / "audit-manifest.json").read_text(encoding="utf-8"))
    assert manifest["execution_result"] == "FAIL"
    assert manifest["security_verdict"] == "BLOCKED"


def test_route_timeout_kills_descendant_tree_and_blocks_release(
    tmp_path: Path,
) -> None:
    repo, target, tree = _make_review_repo(tmp_path)
    fake_bin = tmp_path / "fake-bin"
    _make_fake_reviewers(fake_bin)
    output = tmp_path / "audit-output"
    orphan_sentinel = tmp_path / "orphan-survived-timeout"
    env = os.environ.copy()
    env.update(
        {
            "PATH": f"{fake_bin}{os.pathsep}{env['PATH']}",
            "FAKE_CALLS": _msys(tmp_path / "calls.txt"),
            "FAKE_CODEX_SENTINEL": _msys(tmp_path / "codex-was-invoked"),
            "FAKE_TARGET": target,
            "FAKE_TREE": tree,
            "FAKE_HANG_MODEL": "minimax-m3",
            "FAKE_ORPHAN_SENTINEL": _msys(orphan_sentinel),
            "XREVIEW_OPENCODE_TIMEOUT_SECONDS": "1",
            "XREVIEW_OUTPUT_DIR": _msys(output),
            "XREVIEW_PYTHON": _msys(Path(sys.executable)),
        }
    )
    _add_test_tool_trust(env, tmp_path, fake_bin)

    result = _run(
        str(GIT_BASH),
        "scripts/xreview.sh",
        target,
        cwd=repo,
        env=env,
    )
    time.sleep(3.25)

    assert result.returncode == 1, result.stdout
    assert not orphan_sentinel.exists(), "timed-out reviewer descendant escaped the supervisor"
    assert "XREVIEW_EXECUTION_RESULT=FAIL" in result.stdout
    assert "XREVIEW_SECURITY_VERDICT=BLOCKED" in result.stdout
    manifest = json.loads((output / "audit-manifest.json").read_text(encoding="utf-8"))
    minimax = next(item for item in manifest["reviewers"] if item["family"] == "minimax")
    assert minimax["status"]["rc"] == 124
    assert minimax["status"]["reason"] == "timeout"
    assert minimax["status"]["tree_kill_confirmed"] is True


def test_zero_timeout_is_rejected_before_any_reviewer_starts(tmp_path: Path) -> None:
    repo, target, _tree = _make_review_repo(tmp_path)
    fake_bin = tmp_path / "fake-bin"
    _make_fake_reviewers(fake_bin)
    output = tmp_path / "audit-output"
    calls = tmp_path / "calls.txt"
    env = os.environ.copy()
    env.update(
        {
            "FAKE_CALLS": _msys(calls),
            "XREVIEW_KIMI_TIMEOUT_SECONDS": "0",
            "XREVIEW_OUTPUT_DIR": _msys(output),
            "XREVIEW_PYTHON": _msys(Path(sys.executable)),
        }
    )
    _add_test_tool_trust(env, tmp_path, fake_bin)

    result = _run(
        str(GIT_BASH),
        "scripts/xreview.sh",
        target,
        cwd=repo,
        env=env,
    )

    assert result.returncode == 64, result.stdout
    assert "must be an integer in 1..7200 seconds" in result.stdout
    assert not calls.exists()


def test_missing_supervisor_fails_closed_before_any_reviewer_starts(
    tmp_path: Path,
) -> None:
    repo, target, _tree = _make_review_repo(tmp_path)
    fake_bin = tmp_path / "fake-bin"
    _make_fake_reviewers(fake_bin)
    missing_python = tmp_path / "missing-python.exe"
    shutil.copy2(Path(sys.executable), missing_python)
    output = tmp_path / "audit-output"
    calls = tmp_path / "calls.txt"
    env = os.environ.copy()
    env.update(
        {
            "FAKE_CALLS": _msys(calls),
            "XREVIEW_OUTPUT_DIR": _msys(output),
        }
    )
    _add_test_tool_trust(
        env,
        tmp_path,
        fake_bin,
        native_overrides={"python": missing_python},
    )
    missing_python.unlink()

    result = _run(
        str(GIT_BASH),
        "scripts/xreview.sh",
        target,
        cwd=repo,
        env=env,
    )

    assert result.returncode == 78, result.stdout
    assert "declared Python bootstrap is unavailable" in result.stdout
    assert not calls.exists()


def test_existing_output_directory_is_rejected_without_reusing_evidence(
    tmp_path: Path,
) -> None:
    repo, target, _tree = _make_review_repo(tmp_path)
    fake_bin = tmp_path / "fake-bin"
    _make_fake_reviewers(fake_bin)
    output = tmp_path / "audit-output"
    output.mkdir()
    marker = output / "old-evidence-must-survive.txt"
    marker.write_text("old\n", encoding="utf-8")
    env = os.environ.copy()
    env["XREVIEW_OUTPUT_DIR"] = _msys(output)
    _add_test_tool_trust(env, tmp_path, fake_bin)

    result = _run(
        str(GIT_BASH),
        "scripts/xreview.sh",
        target,
        cwd=repo,
        env=env,
    )

    assert result.returncode == 73, result.stdout
    assert "must be new and atomically creatable" in result.stdout
    assert marker.read_text(encoding="utf-8") == "old\n"
    assert sorted(path.name for path in output.iterdir()) == [marker.name]


def test_reviewers_are_selected_only_from_the_explicit_trust_manifest_not_path(
    tmp_path: Path,
) -> None:
    repo, target, tree = _make_review_repo(tmp_path)
    trusted_bin = tmp_path / "trusted-reviewers"
    _make_fake_reviewers(trusted_bin)
    path_bin = tmp_path / "path-attackers"
    path_sentinel = tmp_path / "path-attacker-was-executed"
    _make_path_attackers(path_bin, path_sentinel)
    manifest, manifest_sha256 = _write_tool_trust_manifest(
        tmp_path / "xreview-tools.tsv", trusted_bin
    )
    output = tmp_path / "audit-output"
    calls = tmp_path / "calls.txt"
    env = os.environ.copy()
    env.update(
        {
            "PATH": f"{path_bin}{os.pathsep}{env['PATH']}",
            "FAKE_CALLS": _msys(calls),
            "FAKE_CODEX_SENTINEL": _msys(tmp_path / "codex-was-invoked"),
            "FAKE_KIMI_CODE_HOME": _msys(tmp_path / "fake-kimi-home"),
            "FAKE_TARGET": target,
            "FAKE_TREE": tree,
            "XREVIEW_OUTPUT_DIR": _msys(output),
            # Legacy implementation consumes this directly; the attested
            # implementation must ignore it in favor of the manifest binding.
            "XREVIEW_PYTHON": _msys(Path(sys.executable)),
            "XREVIEW_TOOL_TRUST_MANIFEST": _manifest_path(manifest),
            "XREVIEW_TOOL_TRUST_MANIFEST_SHA256": manifest_sha256,
            "XREVIEW_TRUST_MODE": "test-only",
        }
    )

    result = _run(
        str(GIT_BASH),
        "scripts/xreview.sh",
        target,
        cwd=repo,
        env=env,
    )

    assert result.returncode == 3, result.stdout
    assert "XREVIEW_EXECUTION_RESULT=NON_FORMAL_TEST_COMPLETE" in result.stdout
    assert not path_sentinel.exists(), "PATH-shadowed reviewer was executed"
    assert sorted(calls.read_text(encoding="utf-8").splitlines()) == [
        "deepseek-v4-pro",
        "glm-5.2",
        "kimi-code/k3",
        "minimax-m3",
    ]


def test_test_only_rejects_native_reviewer_tools_before_any_reviewer_starts(
    tmp_path: Path,
) -> None:
    repo, target, _tree = _make_review_repo(tmp_path)
    fake_bin = tmp_path / "unused-reviewers"
    _make_fake_reviewers(fake_bin)
    native = Path(sys.executable)
    manifest, digest = _write_tool_trust_manifest(
        tmp_path / "native-test-tools.tsv",
        fake_bin,
        reviewer_overrides={"kimi": native, "codex": native, "opencode": native},
    )
    output = tmp_path / "audit-output"
    calls = tmp_path / "calls.txt"
    env = _trust_failure_env(tmp_path, fake_bin, output, manifest, digest)
    env["FAKE_CALLS"] = _msys(calls)

    result = _run(
        str(GIT_BASH),
        "scripts/xreview.sh",
        target,
        cwd=repo,
        env=env,
    )

    assert result.returncode == 78, result.stdout
    assert "test-only reviewer tools must be bash-script fakes" in result.stdout
    assert "no model was started" in result.stdout
    assert not calls.exists()


def test_supervised_reviewer_shells_do_not_inherit_ambient_bash_env(
    tmp_path: Path,
) -> None:
    repo, target, tree = _make_review_repo(tmp_path)
    fake_bin = tmp_path / "trusted-reviewers"
    _make_fake_reviewers(fake_bin)
    output = tmp_path / "audit-output"
    bash_env_hits = tmp_path / "bash-env-hits.txt"
    bash_env = tmp_path / "ambient-bash-env.sh"
    _write_executable(
        bash_env,
        f'''\
        printf 'ambient-bash-env-executed\\n' >> "{_msys(bash_env_hits)}"
        ''',
    )
    env = os.environ.copy()
    env.update(
        {
            "BASH_ENV": _msys(bash_env),
            "ENV": _msys(bash_env),
            "PYTHONPATH": _msys(tmp_path / "python-injection"),
            "PYTHONHOME": _msys(tmp_path / "python-home-injection"),
            "GIT_DIR": _msys(tmp_path / "git-redirection"),
            "GIT_OBJECT_DIRECTORY": _msys(tmp_path / "git-object-redirection"),
            "NODE_OPTIONS": "--require=ambient-node-injection.js",
            "NODE_EXTRA_CA_CERTS": _msys(tmp_path / "untrusted-ca.pem"),
            "PROMPT_COMMAND": "ambient-prompt-command",
            "PS4": "ambient-xtrace-prefix",
            "KIMI_API_KEY": "test-only-placeholder-not-a-real-secret",
            "KIMI_BASE_URL": "https://example.invalid",
            "OPENAI_API_KEY": "test-only-placeholder-not-a-real-secret",
            "VOLCENGINE_API_KEY": "test-only-placeholder-not-a-real-secret",
            "MINIMAX_API_KEY": "test-only-placeholder-not-a-real-secret",
            "CODEX_HOME": _msys(tmp_path / "real-codex-home-must-not-pass"),
            "KIMI_CODE_HOME": _msys(tmp_path / "real-kimi-home-must-not-pass"),
            "OPENCODE_CONFIG_DIR": _msys(tmp_path / "real-opencode-home-must-not-pass"),
            "XREVIEW_MOONSHOT_KIMI_CODE_HOME": _msys(tmp_path / "scoped-kimi"),
            "XREVIEW_OPENAI_CODEX_HOME": _msys(tmp_path / "scoped-codex"),
            "XREVIEW_ZHIPU_OPENCODE_CONFIG_DIR": _msys(tmp_path / "scoped-zhipu"),
            "XREVIEW_DEEPSEEK_OPENCODE_CONFIG_DIR": _msys(tmp_path / "scoped-deepseek"),
            "XREVIEW_MINIMAX_OPENCODE_CONFIG_DIR": _msys(tmp_path / "scoped-minimax"),
            "FAKE_CALLS": _msys(tmp_path / "calls.txt"),
            "FAKE_CODEX_SENTINEL": _msys(tmp_path / "codex-was-invoked"),
            "FAKE_TARGET": target,
            "FAKE_TREE": tree,
            "XREVIEW_OUTPUT_DIR": _msys(output),
        }
    )
    _add_test_tool_trust(env, tmp_path, fake_bin)

    result = _run(
        str(GIT_BASH),
        "scripts/xreview.sh",
        target,
        cwd=repo,
        env=env,
    )

    assert result.returncode == 3, result.stdout
    assert "XREVIEW_EXECUTION_RESULT=NON_FORMAL_TEST_COMPLETE" in result.stdout
    assert bash_env_hits.read_text(encoding="utf-8").splitlines() == [
        "ambient-bash-env-executed"
    ], "BASH_ENV escaped into a supervised reviewer shell"
    manifest = json.loads((output / "audit-manifest.json").read_text(encoding="utf-8"))
    forbidden = {
        "BASH_ENV",
        "ENV",
        "PYTHONPATH",
        "PYTHONHOME",
        "GIT_DIR",
        "GIT_OBJECT_DIRECTORY",
        "NODE_OPTIONS",
        "NODE_EXTRA_CA_CERTS",
        "PROMPT_COMMAND",
        "PS4",
        "KIMI_API_KEY",
        "KIMI_BASE_URL",
        "OPENAI_API_KEY",
        "VOLCENGINE_API_KEY",
        "MINIMAX_API_KEY",
        "CODEX_HOME",
        "KIMI_CODE_HOME",
        "OPENCODE_CONFIG_DIR",
        "HOME",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "XDG_CONFIG_HOME",
        "XREVIEW_MOONSHOT_KIMI_CODE_HOME",
        "XREVIEW_OPENAI_CODEX_HOME",
        "XREVIEW_ZHIPU_OPENCODE_CONFIG_DIR",
        "XREVIEW_DEEPSEEK_OPENCODE_CONFIG_DIR",
        "XREVIEW_MINIMAX_OPENCODE_CONFIG_DIR",
    }
    for reviewer in manifest["reviewers"]:
        keys = set(reviewer["status"]["child_environment_keys"])
        assert not (keys & forbidden)
        assert not any(name.startswith(("PYTHON", "GIT")) for name in keys)
        assert not any(name.endswith(("API_KEY", "AUTH_TOKEN", "OAUTH_TOKEN")) for name in keys)


def test_git_snapshot_is_fixed_to_repo_and_ignores_ambient_git_redirection(
    tmp_path: Path,
) -> None:
    repo, target, tree = _make_review_repo(tmp_path / "target-root")
    attacker_repo, _attacker_target, _attacker_tree = _make_review_repo(
        tmp_path / "attacker-root"
    )
    fake_bin = tmp_path / "trusted-reviewers"
    _make_fake_reviewers(fake_bin)
    output = tmp_path / "audit-output"
    env = os.environ.copy()
    env.update(
        {
            "GIT_DIR": _msys(attacker_repo / ".git"),
            "GIT_WORK_TREE": _msys(attacker_repo),
            "GIT_OBJECT_DIRECTORY": _msys(attacker_repo / ".git" / "objects"),
            "FAKE_CALLS": _msys(tmp_path / "calls.txt"),
            "FAKE_CODEX_SENTINEL": _msys(tmp_path / "codex-was-invoked"),
            "FAKE_TARGET": target,
            "FAKE_TREE": tree,
            "XREVIEW_OUTPUT_DIR": _msys(output),
        }
    )
    _add_test_tool_trust(env, tmp_path, fake_bin)

    result = _run(
        str(GIT_BASH),
        "scripts/xreview.sh",
        target,
        cwd=repo,
        env=env,
    )

    assert result.returncode == 3, result.stdout
    manifest = json.loads((output / "audit-manifest.json").read_text(encoding="utf-8"))
    assert manifest["target"]["commit"] == target
    assert manifest["target"]["tree"] == tree
    assert (output / "review-root" / "input" / "app.txt").read_text(
        encoding="utf-8"
    ) == "committed-v2\n"


def test_git_snapshot_ignores_same_repository_replace_refs(tmp_path: Path) -> None:
    repo, target, tree = _make_review_repo(tmp_path)
    parent = _git(repo, "rev-parse", f"{target}^")
    (repo / "app.txt").write_text("REPLACE-REF-MUST-NOT-BE-REVIEWED\n", encoding="utf-8")
    _git(repo, "add", "app.txt")
    attacker_tree = _git(repo, "write-tree")
    attacker_commit = _git(
        repo,
        "commit-tree",
        attacker_tree,
        "-p",
        parent,
        "-m",
        "replace-ref attacker",
    )
    _git(repo, "replace", target, attacker_commit)
    fake_bin = tmp_path / "trusted-reviewers"
    _make_fake_reviewers(fake_bin)
    output = tmp_path / "audit-output"
    env = os.environ.copy()
    env.update(
        {
            "FAKE_CALLS": _msys(tmp_path / "calls.txt"),
            "FAKE_CODEX_SENTINEL": _msys(tmp_path / "codex-was-invoked"),
            "FAKE_TARGET": target,
            "FAKE_TREE": tree,
            "XREVIEW_OUTPUT_DIR": _msys(output),
        }
    )
    _add_test_tool_trust(env, tmp_path, fake_bin)

    result = _run(
        str(GIT_BASH),
        "scripts/xreview.sh",
        target,
        cwd=repo,
        env=env,
    )

    assert result.returncode == 3, result.stdout
    manifest = json.loads((output / "audit-manifest.json").read_text(encoding="utf-8"))
    assert manifest["target"]["commit"] == target
    assert manifest["target"]["tree"] == tree
    assert (output / "review-root" / "input" / "app.txt").read_text(
        encoding="utf-8"
    ) == "committed-v2\n"
    assert "REPLACE-REF-MUST-NOT-BE-REVIEWED" not in result.stdout


def test_manifest_field_drift_is_rejected_before_any_reviewer_starts(
    tmp_path: Path,
) -> None:
    repo, target, _tree = _make_review_repo(tmp_path)
    fake_bin = tmp_path / "trusted-reviewers"
    _make_fake_reviewers(fake_bin)
    manifest, _ = _write_tool_trust_manifest(tmp_path / "xreview-tools.tsv", fake_bin)
    rows = manifest.read_text(encoding="utf-8").splitlines()
    rows = [row + "\tunexpected" if row.startswith("tool\tkimi\t") else row for row in rows]
    manifest.write_text("\n".join(rows) + "\n", encoding="utf-8", newline="\n")
    digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
    output = tmp_path / "audit-output"

    result = _run(
        str(GIT_BASH),
        "scripts/xreview.sh",
        target,
        cwd=repo,
        env=_trust_failure_env(tmp_path, fake_bin, output, manifest, digest),
    )

    assert result.returncode == 78, result.stdout
    assert "row has missing/unexpected fields" in result.stdout
    assert "no model was started" in result.stdout
    assert not (tmp_path / "calls.txt").exists()


def test_missing_trust_manifest_fails_before_output_or_reviewer_start(
    tmp_path: Path,
) -> None:
    repo, target, _tree = _make_review_repo(tmp_path)
    path_bin = tmp_path / "path-attackers"
    path_sentinel = tmp_path / "path-attacker-was-executed"
    _make_path_attackers(path_bin, path_sentinel)
    output = tmp_path / "audit-output"
    env = os.environ.copy()
    env["PATH"] = f"{path_bin}{os.pathsep}{env['PATH']}"
    env["XREVIEW_OUTPUT_DIR"] = _msys(output)
    env.pop("XREVIEW_TOOL_TRUST_MANIFEST", None)
    env.pop("XREVIEW_TOOL_TRUST_MANIFEST_SHA256", None)

    result = _run(
        str(GIT_BASH),
        "scripts/xreview.sh",
        target,
        cwd=repo,
        env=env,
    )

    assert result.returncode == 78, result.stdout
    assert "explicit tool trust manifest and digest are required" in result.stdout
    assert "NAKED_BASH_NOT_TRUST_ROOT" in result.stdout
    assert not output.exists()
    assert not path_sentinel.exists()


def test_formal_mode_requires_external_launcher_control_plane_before_creating_output(
    tmp_path: Path,
) -> None:
    repo, target, _tree = _make_review_repo(tmp_path)
    fake_bin = tmp_path / "unused-reviewers"
    _make_fake_reviewers(fake_bin)
    native = Path(sys.executable)
    manifest, digest = _write_tool_trust_manifest(
        tmp_path / "formal-tools.tsv",
        fake_bin,
        mode="formal",
        reviewer_overrides={"kimi": native, "codex": native, "opencode": native},
    )
    output = tmp_path / "must-not-be-created"
    calls = tmp_path / "calls.txt"
    env = os.environ.copy()
    env.update(
        {
            "FAKE_CALLS": _msys(calls),
            "XREVIEW_OUTPUT_DIR": _msys(output),
            "XREVIEW_TOOL_TRUST_MANIFEST": _manifest_path(manifest),
            "XREVIEW_TOOL_TRUST_MANIFEST_SHA256": digest,
            "XREVIEW_TRUST_MODE": "formal",
        }
    )
    env.pop("XREVIEW_EXTERNAL_LAUNCH_RECEIPT", None)
    env.pop("XREVIEW_EXTERNAL_LAUNCH_RECEIPT_SHA256", None)
    env.pop("XREVIEW_EXTERNAL_CONTROL_ROOT", None)

    result = _run(
        str(GIT_BASH),
        "scripts/xreview.sh",
        target,
        cwd=repo,
        env=env,
    )

    assert result.returncode == 78, result.stdout
    assert "external protected launcher receipt/control-plane is required" in result.stdout
    assert "NAKED_BASH_NOT_TRUST_ROOT" in result.stdout
    assert "BASH_ENV can run before script line 1" in result.stdout
    assert "KIMI_PROMPT_ARGV_EXPOSURE" in result.stdout
    assert "same-SID process enumeration" in result.stdout
    assert "no model was started" in result.stdout
    assert not output.exists()
    assert not calls.exists()


def test_formal_mode_refuses_self_declared_receipt_without_external_handle_binding(
    tmp_path: Path,
) -> None:
    repo, target, _tree = _make_review_repo(tmp_path)
    fake_bin = tmp_path / "unused-reviewers"
    _make_fake_reviewers(fake_bin)
    native = Path(sys.executable)
    manifest, digest = _write_tool_trust_manifest(
        tmp_path / "formal-tools.tsv",
        fake_bin,
        mode="formal",
        reviewer_overrides={"kimi": native, "codex": native, "opencode": native},
    )
    receipt = tmp_path / "self-declared-launch-receipt.json"
    receipt.write_text('{"schema":1}\n', encoding="utf-8", newline="\n")
    output = tmp_path / "must-not-be-created"
    calls = tmp_path / "calls.txt"
    env = os.environ.copy()
    env.update(
        {
            "FAKE_CALLS": _msys(calls),
            "XREVIEW_OUTPUT_DIR": _msys(output),
            "XREVIEW_TOOL_TRUST_MANIFEST": _manifest_path(manifest),
            "XREVIEW_TOOL_TRUST_MANIFEST_SHA256": digest,
            "XREVIEW_TRUST_MODE": "formal",
            "XREVIEW_EXTERNAL_LAUNCH_RECEIPT": _manifest_path(receipt),
            "XREVIEW_EXTERNAL_LAUNCH_RECEIPT_SHA256": hashlib.sha256(
                receipt.read_bytes()
            ).hexdigest(),
            "XREVIEW_EXTERNAL_CONTROL_ROOT": _manifest_path(tmp_path),
        }
    )

    result = _run(
        str(GIT_BASH),
        "scripts/xreview.sh",
        target,
        cwd=repo,
        env=env,
    )

    assert result.returncode == 78, result.stdout
    assert "formal evidence is disabled" in result.stdout
    assert "handle-bound external launcher" in result.stdout
    assert "no model was started" in result.stdout
    assert not output.exists()
    assert not calls.exists()


def test_formal_mode_cannot_enable_the_test_only_permission_bypass(
    tmp_path: Path,
) -> None:
    repo, target, _tree = _make_review_repo(tmp_path)
    fake_bin = tmp_path / "unused-reviewers"
    _make_fake_reviewers(fake_bin)
    native = Path(sys.executable)
    manifest, digest = _write_tool_trust_manifest(
        tmp_path / "xreview-tools.tsv",
        fake_bin,
        mode="formal",
        reviewer_overrides={"kimi": native, "codex": native, "opencode": native},
    )
    output = tmp_path / "audit-output"
    env = os.environ.copy()
    env.update(
        {
            "XREVIEW_OUTPUT_DIR": _msys(output),
            "XREVIEW_TOOL_TRUST_MANIFEST": _manifest_path(manifest),
            "XREVIEW_TOOL_TRUST_MANIFEST_SHA256": digest,
            "XREVIEW_TRUST_MODE": "formal",
            "XREVIEW_TEST_ONLY": "1",
        }
    )

    result = _run(
        str(GIT_BASH),
        "scripts/xreview.sh",
        target,
        cwd=repo,
        env=env,
    )

    assert result.returncode == 78, result.stdout
    assert "test-only-bypass" not in result.stdout
    assert "external protected launcher receipt/control-plane is required" in result.stdout
    assert "no model was started" in result.stdout


def test_manifest_byte_tampering_is_rejected_before_any_reviewer_starts(
    tmp_path: Path,
) -> None:
    repo, target, _tree = _make_review_repo(tmp_path)
    fake_bin = tmp_path / "trusted-reviewers"
    _make_fake_reviewers(fake_bin)
    manifest, digest = _write_tool_trust_manifest(tmp_path / "xreview-tools.tsv", fake_bin)
    manifest.write_text(
        manifest.read_text(encoding="utf-8") + "\n",
        encoding="utf-8",
        newline="\n",
    )
    output = tmp_path / "audit-output"

    result = _run(
        str(GIT_BASH),
        "scripts/xreview.sh",
        target,
        cwd=repo,
        env=_trust_failure_env(tmp_path, fake_bin, output, manifest, digest),
    )

    assert result.returncode == 78, result.stdout
    assert "trust manifest SHA-256 mismatch" in result.stdout
    assert "no model was started" in result.stdout
    assert not (tmp_path / "calls.txt").exists()


def test_tool_changed_after_manifest_review_is_rejected_before_any_reviewer_starts(
    tmp_path: Path,
) -> None:
    repo, target, _tree = _make_review_repo(tmp_path)
    fake_bin = tmp_path / "trusted-reviewers"
    _make_fake_reviewers(fake_bin)
    manifest, digest = _write_tool_trust_manifest(tmp_path / "xreview-tools.tsv", fake_bin)
    with (fake_bin / "kimi").open("a", encoding="utf-8", newline="\n") as handle:
        handle.write("# changed after review\n")
    output = tmp_path / "audit-output"

    result = _run(
        str(GIT_BASH),
        "scripts/xreview.sh",
        target,
        cwd=repo,
        env=_trust_failure_env(tmp_path, fake_bin, output, manifest, digest),
    )

    assert result.returncode == 78, result.stdout
    assert "trusted tool size mismatch" in result.stdout
    assert "no model was started" in result.stdout
    assert not (tmp_path / "calls.txt").exists()


def test_running_reviewer_cannot_replace_its_pinned_tool_and_receipt_keeps_both_views(
    tmp_path: Path,
) -> None:
    repo, target, tree = _make_review_repo(tmp_path)
    fake_bin = tmp_path / "trusted-reviewers"
    _make_fake_reviewers(fake_bin)
    manifest, digest = _write_tool_trust_manifest(tmp_path / "xreview-tools.tsv", fake_bin)
    output = tmp_path / "audit-output"
    calls = tmp_path / "calls.txt"
    replacement_succeeded = tmp_path / "replacement-succeeded"
    replacement_blocked = tmp_path / "replacement-blocked"
    opencode_before = (fake_bin / "opencode").read_bytes()
    env = os.environ.copy()
    env.update(
        {
            "FAKE_CALLS": _msys(calls),
            "FAKE_CODEX_SENTINEL": _msys(tmp_path / "codex-was-invoked"),
            "FAKE_KIMI_CODE_HOME": _msys(tmp_path / "fake-kimi-home"),
            "FAKE_TARGET": target,
            "FAKE_TREE": tree,
            "FAKE_REPLACE_RUNNING_MODEL": "glm-5.2",
            "FAKE_REVIEWER_SELF_PATH": _msys(fake_bin / "opencode"),
            "FAKE_REPLACEMENT_SUCCEEDED": _msys(replacement_succeeded),
            "FAKE_REPLACEMENT_BLOCKED": _msys(replacement_blocked),
            "XREVIEW_OUTPUT_DIR": _msys(output),
            "XREVIEW_TOOL_TRUST_MANIFEST": _manifest_path(manifest),
            "XREVIEW_TOOL_TRUST_MANIFEST_SHA256": digest,
            "XREVIEW_TRUST_MODE": "test-only",
        }
    )

    result = _run(
        str(GIT_BASH),
        "scripts/xreview.sh",
        target,
        cwd=repo,
        env=env,
    )

    assert result.returncode == 3, result.stdout
    assert "XREVIEW_EXECUTION_RESULT=NON_FORMAL_TEST_COMPLETE" in result.stdout
    assert replacement_blocked.exists(), "Windows pin did not deny the live replacement"
    assert not replacement_succeeded.exists()
    assert (fake_bin / "opencode").read_bytes() == opencode_before
    audit = json.loads((output / "audit-manifest.json").read_text(encoding="utf-8"))
    glm = next(item for item in audit["reviewers"] if item["family"] == "zhipu")
    tool = glm["receipt"]["tool"]
    assert tool["expected"]["sha256"] == hashlib.sha256(opencode_before).hexdigest()
    assert tool["pre_actual"]["sha256"] == tool["expected"]["sha256"]
    assert tool["post_actual"]["sha256"] == tool["expected"]["sha256"]
    assert tool["receipt_actual"]["sha256"] == tool["expected"]["sha256"]
    assert tool["same_identity_through_receipt"] is True
    assert glm["receipt"]["trust_mode"] == "test-only"
    assert glm["receipt"]["formal_evidence_eligible"] is False
