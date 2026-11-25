from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from gateway import windows_installed_process_manager as process_manager_module
from gateway.installed_channel_supervisor import (
    InstalledChannelSupervisorRuntime,
    InstalledChildLaunch,
)
from gateway.windows_installed_process_manager import (
    WindowsInstalledProcessError,
    WindowsInstalledProcessManager,
    current_windows_process_receipt,
)


def _python_launch(tmp_path: Path, code: str) -> InstalledChildLaunch:
    environment = {
        name: value
        for name in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP", "USERPROFILE")
        if (value := os.environ.get(name))
    }
    environment["PYTHONUTF8"] = "1"
    return InstalledChildLaunch(
        command=str(Path(sys.executable).resolve()),
        args=("-I", "-S", "-B", "-X", "utf8", "-c", code),
        cwd=str(tmp_path.resolve()),
        environment=environment,
    )


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object contract")
def test_child_executes_only_after_job_assignment_and_dies_with_job(tmp_path) -> None:
    marker = tmp_path / "resumed.txt"
    code = (
        "from pathlib import Path;import time;"
        f"Path({str(marker)!r}).write_text('resumed',encoding='utf-8');"
        "time.sleep(60)"
    )
    launch = _python_launch(tmp_path, code)
    manager = WindowsInstalledProcessManager()
    process = manager.spawn_suspended("engine", launch)
    try:
        time.sleep(0.25)
        assert marker.exists() is False
        assert process.poll() is None

        manager.assign_to_job("engine", process)
        manager.resume("engine", process)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and not marker.exists():
            time.sleep(0.05)
        assert marker.read_text("utf-8") == "resumed"
        assert process.poll() is None
    finally:
        manager.terminate_job()

    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and process.poll() is None:
        time.sleep(0.05)
    assert process.poll() is not None


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object contract")
def test_close_kills_an_unassigned_suspended_child_without_executing_it(tmp_path) -> None:
    marker = tmp_path / "must-not-run.txt"
    launch = _python_launch(
        tmp_path,
        "from pathlib import Path;"
        f"Path({str(marker)!r}).write_text('bad',encoding='utf-8')",
    )
    manager = WindowsInstalledProcessManager()
    process = manager.spawn_suspended("engine", launch)

    manager.close()

    assert process.poll() is not None
    assert marker.exists() is False


@pytest.mark.skipif(os.name != "nt", reason="Windows process quiescence contract")
def test_naturally_exited_child_proves_job_quiescence_without_force(tmp_path) -> None:
    launch = _python_launch(tmp_path, "raise SystemExit(0)")
    manager = WindowsInstalledProcessManager()
    process = manager.spawn_suspended("engine", launch)
    manager.assign_to_job("engine", process)
    manager.resume("engine", process)

    assert manager.wait_for_exit("engine", process, timeout_ms=10_000) is True
    assert manager.alive_roles() == ()
    assert manager.wait_for_quiescence(timeout_ms=10_000) is True
    assert manager.is_quiescent() is True
    manager.close_quiescent()
    assert manager.is_quiescent() is True


@pytest.mark.skipif(os.name != "nt", reason="Windows forced quiescence contract")
def test_force_close_proves_job_quiescence_and_is_idempotent(tmp_path) -> None:
    launch = _python_launch(tmp_path, "import time;time.sleep(60)")
    manager = WindowsInstalledProcessManager()
    process = manager.spawn_suspended("engine", launch)
    manager.assign_to_job("engine", process)
    manager.resume("engine", process)

    manager.force_close()
    manager.force_close()

    assert process.poll() is not None
    assert manager.alive_roles() == ()
    assert manager.is_quiescent() is True


@pytest.mark.skipif(os.name != "nt", reason="Windows failed force contract")
def test_failed_job_termination_never_claims_quiescence(
    tmp_path,
    monkeypatch,
) -> None:
    launch = _python_launch(tmp_path, "import time;time.sleep(60)")
    manager = WindowsInstalledProcessManager()
    process = manager.spawn_suspended("engine", launch)
    manager.assign_to_job("engine", process)
    manager.resume("engine", process)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(
                process_manager_module._kernel32,
                "TerminateJobObject",
                lambda _job, _code: False,
            )
            with pytest.raises(
                WindowsInstalledProcessError,
                match="Job termination failed",
            ):
                manager.force_close()
            assert manager.is_quiescent() is False
            assert manager.alive_roles() == ("engine",)
    finally:
        manager.terminate_job()


@pytest.mark.skipif(os.name != "nt", reason="Windows force proof contract")
def test_force_keeps_handles_when_child_terminal_state_is_unproven(
    tmp_path,
    monkeypatch,
) -> None:
    launch = _python_launch(tmp_path, "import time;time.sleep(60)")
    manager = WindowsInstalledProcessManager()
    process = manager.spawn_suspended("engine", launch)
    manager.assign_to_job("engine", process)
    manager.resume("engine", process)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(
                type(process),
                "poll",
                lambda _self: None,
            )
            with pytest.raises(
                WindowsInstalledProcessError,
                match="did not quiesce",
            ):
                manager.force_close()
        manager.force_close()
        assert process.poll() is not None
        assert manager.is_quiescent() is True
    finally:
        manager.terminate_job()


@pytest.mark.skipif(os.name != "nt", reason="Windows concurrent force contract")
def test_concurrent_force_has_one_termination_owner_and_one_cleanup(
    tmp_path,
    monkeypatch,
) -> None:
    launch = _python_launch(tmp_path, "import time;time.sleep(60)")
    manager = WindowsInstalledProcessManager()
    process = manager.spawn_suspended("engine", launch)
    manager.assign_to_job("engine", process)
    manager.resume("engine", process)

    original_terminate = process_manager_module._kernel32.TerminateJobObject
    original_close = process_manager_module._kernel32.CloseHandle
    first_entered = threading.Event()
    release_terminate = threading.Event()
    call_lock = threading.Lock()
    terminate_calls = 0
    close_calls = 0
    errors: list[BaseException] = []

    def controlled_terminate(job, code):
        nonlocal terminate_calls
        with call_lock:
            terminate_calls += 1
            if terminate_calls == 1:
                first_entered.set()
        if not release_terminate.wait(5):
            raise RuntimeError("test termination gate timed out")
        return original_terminate(job, code)

    def controlled_close(handle):
        nonlocal close_calls
        with call_lock:
            close_calls += 1
        return original_close(handle)

    def force() -> None:
        try:
            manager.force_close()
        except BaseException as exc:  # noqa: BLE001 - assert after both owners exit
            errors.append(exc)

    monkeypatch.setattr(
        process_manager_module._kernel32,
        "TerminateJobObject",
        controlled_terminate,
    )
    monkeypatch.setattr(
        process_manager_module._kernel32,
        "CloseHandle",
        controlled_close,
    )
    first = threading.Thread(target=force)
    second = threading.Thread(target=force)
    first.start()
    assert first_entered.wait(5)
    second.start()
    try:
        time.sleep(0.2)
        assert terminate_calls == 1
    finally:
        release_terminate.set()
        first.join(10)
        second.join(10)

    assert not first.is_alive()
    assert not second.is_alive()
    assert errors == []
    assert terminate_calls == 1
    assert close_calls == 2
    assert process.poll() is not None
    assert manager.is_quiescent() is True


@pytest.mark.skipif(os.name != "nt", reason="Windows wait/force concurrency contract")
def test_waiter_keeps_a_valid_proof_handle_while_force_cleans_manager_handles(
    tmp_path,
    monkeypatch,
) -> None:
    launch = _python_launch(tmp_path, "import time;time.sleep(60)")
    manager = WindowsInstalledProcessManager()
    process = manager.spawn_suspended("engine", launch)
    manager.assign_to_job("engine", process)
    manager.resume("engine", process)

    original_wait = process_manager_module._kernel32.WaitForSingleObject
    waiter_entered = threading.Event()
    release_waiter = threading.Event()
    waiter_thread_id: list[int] = []
    results: list[bool] = []
    errors: list[BaseException] = []

    def controlled_wait(handle, timeout):
        if threading.get_ident() == waiter_thread_id[0] and not waiter_entered.is_set():
            waiter_entered.set()
            if not release_waiter.wait(10):
                raise RuntimeError("test waiter gate timed out")
        return original_wait(handle, timeout)

    monkeypatch.setattr(
        process_manager_module._kernel32,
        "WaitForSingleObject",
        controlled_wait,
    )

    def wait_for_child() -> None:
        waiter_thread_id.append(threading.get_ident())
        try:
            results.append(
                manager.wait_for_exit("engine", process, timeout_ms=10_000)
            )
        except BaseException as exc:  # noqa: BLE001 - assert after force cleanup
            errors.append(exc)

    waiter = threading.Thread(target=wait_for_child)
    waiter.start()
    assert waiter_entered.wait(5)
    manager.force_close()
    release_waiter.set()
    waiter.join(10)

    assert not waiter.is_alive()
    assert errors == []
    assert results == [True]
    assert manager.is_quiescent() is True


@pytest.mark.skipif(os.name != "nt", reason="Windows graceful wait/force contract")
def test_graceful_quiescence_wait_releases_state_for_force(tmp_path) -> None:
    launch = _python_launch(tmp_path, "import time;time.sleep(60)")
    manager = WindowsInstalledProcessManager()
    process = manager.spawn_suspended("engine", launch)
    manager.assign_to_job("engine", process)
    manager.resume("engine", process)
    waiter_started = threading.Event()
    waiter_result: list[bool] = []

    def wait_for_tree() -> None:
        waiter_started.set()
        waiter_result.append(manager.wait_for_quiescence(timeout_ms=10_000))

    waiter = threading.Thread(target=wait_for_tree)
    waiter.start()
    assert waiter_started.wait(5)
    time.sleep(0.1)
    started = time.monotonic()
    manager.force_close()
    force_elapsed = time.monotonic() - started
    waiter.join(10)

    assert not waiter.is_alive()
    assert waiter_result == [True]
    assert force_elapsed < 5
    assert manager.is_quiescent() is True


@pytest.mark.skipif(os.name != "nt", reason="Windows spawn/force concurrency contract")
def test_force_waits_for_inflight_suspended_spawn_then_cleans_it_once(
    tmp_path,
    monkeypatch,
) -> None:
    marker = tmp_path / "must-not-run-after-force.txt"
    launch = _python_launch(
        tmp_path,
        "from pathlib import Path;"
        f"Path({str(marker)!r}).write_text('bad',encoding='utf-8')",
    )
    manager = WindowsInstalledProcessManager()
    original_create = process_manager_module._kernel32.CreateProcessW
    create_entered = threading.Event()
    release_create = threading.Event()
    force_done = threading.Event()
    spawned = []
    errors: list[BaseException] = []

    def controlled_create(*args):
        create_entered.set()
        if not release_create.wait(10):
            raise RuntimeError("test create gate timed out")
        return original_create(*args)

    monkeypatch.setattr(
        process_manager_module._kernel32,
        "CreateProcessW",
        controlled_create,
    )

    def spawn() -> None:
        try:
            spawned.append(manager.spawn_suspended("engine", launch))
        except BaseException as exc:  # noqa: BLE001 - assert after both owners exit
            errors.append(exc)

    def force() -> None:
        try:
            manager.force_close()
        except BaseException as exc:  # noqa: BLE001 - assert after both owners exit
            errors.append(exc)
        finally:
            force_done.set()

    spawn_thread = threading.Thread(target=spawn)
    force_thread = threading.Thread(target=force)
    spawn_thread.start()
    assert create_entered.wait(5)
    force_thread.start()
    try:
        assert force_done.wait(0.2) is False
    finally:
        release_create.set()
        spawn_thread.join(10)
        force_thread.join(10)
        for process in spawned:
            if process.poll() is None and process._process_handle:
                process_manager_module._kernel32.TerminateProcess(
                    process._process_handle,
                    125,
                )
            process._close_handles()

    assert not spawn_thread.is_alive()
    assert not force_thread.is_alive()
    assert errors == []
    assert len(spawned) == 1
    assert spawned[0].poll() is not None
    assert marker.exists() is False
    assert manager.is_quiescent() is True


@pytest.mark.skipif(os.name != "nt", reason="Windows resume/force concurrency contract")
def test_force_waits_for_inflight_resume_before_cleaning_handles(
    tmp_path,
    monkeypatch,
) -> None:
    launch = _python_launch(tmp_path, "import time;time.sleep(60)")
    manager = WindowsInstalledProcessManager()
    process = manager.spawn_suspended("engine", launch)
    manager.assign_to_job("engine", process)

    original_resume = process_manager_module._kernel32.ResumeThread
    resume_entered = threading.Event()
    release_resume = threading.Event()
    force_done = threading.Event()
    errors: list[BaseException] = []

    def controlled_resume(handle):
        resume_entered.set()
        if not release_resume.wait(10):
            raise RuntimeError("test resume gate timed out")
        return original_resume(handle)

    monkeypatch.setattr(
        process_manager_module._kernel32,
        "ResumeThread",
        controlled_resume,
    )

    def resume() -> None:
        try:
            manager.resume("engine", process)
        except BaseException as exc:  # noqa: BLE001 - assert after both owners exit
            errors.append(exc)

    def force() -> None:
        try:
            manager.force_close()
        except BaseException as exc:  # noqa: BLE001 - assert after both owners exit
            errors.append(exc)
        finally:
            force_done.set()

    resume_thread = threading.Thread(target=resume)
    force_thread = threading.Thread(target=force)
    resume_thread.start()
    assert resume_entered.wait(5)
    force_thread.start()
    try:
        assert force_done.wait(0.2) is False
    finally:
        release_resume.set()
        resume_thread.join(10)
        force_thread.join(10)

    assert not resume_thread.is_alive()
    assert not force_thread.is_alive()
    assert errors == []
    assert process.poll() is not None
    assert manager.is_quiescent() is True


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object contract")
def test_spawn_rejects_case_insensitive_duplicate_environment_names(tmp_path) -> None:
    launch = _python_launch(tmp_path, "raise SystemExit(0)")
    launch = InstalledChildLaunch(
        command=launch.command,
        args=launch.args,
        cwd=launch.cwd,
        environment={**launch.environment, "NACHUAN_TEST": "a", "nachuan_test": "b"},
    )
    manager = WindowsInstalledProcessManager()
    try:
        with pytest.raises(
            WindowsInstalledProcessError, match="child environment is invalid"
        ):
            manager.spawn_suspended("engine", launch)
    finally:
        manager.close()


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object contract")
def test_real_manager_runs_the_three_role_supervisor_contract(tmp_path) -> None:
    markers = {role: tmp_path / f"{role}.ready" for role in ("engine", "weixin", "feishu")}
    launches = {
        role: _python_launch(
            tmp_path,
            "from pathlib import Path;import time;"
            f"Path({str(marker)!r}).write_text('ready',encoding='utf-8');"
            "time.sleep(60)",
        )
        for role, marker in markers.items()
    }
    manager = WindowsInstalledProcessManager()

    def health(role, process) -> bool:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if markers[role].exists():
                return process.poll() is None
            if process.poll() is not None:
                return False
            time.sleep(0.05)
        return False

    runtime = InstalledChannelSupervisorRuntime(
        launches=launches,
        process_manager=manager,
        health_probe=health,
    )
    state = runtime.start()
    try:
        assert state.ready is True
        assert tuple(state.pids) == ("engine", "weixin", "feishu")
        assert len(set(state.pids.values())) == 3
        assert all(marker.read_text("utf-8") == "ready" for marker in markers.values())
        receipts = runtime.process_receipts()
        assert tuple(receipts) == ("engine", "weixin", "feishu")
        assert {
            role: receipt.pid for role, receipt in receipts.items()
        } == dict(state.pids)
    finally:
        runtime.close()


@pytest.mark.skipif(os.name != "nt", reason="Windows process identity contract")
def test_process_receipts_bind_pid_creation_time_and_command_hash(tmp_path) -> None:
    supervisor = current_windows_process_receipt()
    assert supervisor.pid == os.getpid()
    assert supervisor.started_utc_ticks > 0
    assert len(supervisor.command_line_sha256) == 64

    launch = _python_launch(tmp_path, "import time;time.sleep(60)")
    expected_command = subprocess.list2cmdline([launch.command, *launch.args])
    expected_hash = hashlib.sha256(expected_command.encode("utf-16-le")).hexdigest()
    manager = WindowsInstalledProcessManager()
    process = manager.spawn_suspended("engine", launch)
    try:
        receipt = manager.process_receipt("engine", process)
        assert receipt.pid == process.pid
        assert receipt.started_utc_ticks > 0
        assert receipt.command_line_sha256 == expected_hash
    finally:
        manager.close()
