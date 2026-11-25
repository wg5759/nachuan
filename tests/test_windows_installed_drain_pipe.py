from __future__ import annotations

import os
from pathlib import Path
import json
import subprocess
import sys
import time

import pytest

import gateway.windows_installed_drain_pipe as pipe_transport

from gateway.installed_channel_drain import (
    InstalledChildDrainFence,
    InstalledDrainBinding,
    InstalledDrainCommand,
    InstalledDrainOperation,
    InstalledDrainProtocol,
    InstalledParentDrainCoordinator,
    derive_installed_drain_role_key,
)
from gateway.installed_nachuan_core_identity import nachuan_core_service_sid
from gateway.installed_channel_supervisor_status import InstalledChannelProcessReceipt
from gateway.windows_installed_drain_pipe import (
    WindowsInstalledDrainPipeChildEndpoint,
    WindowsInstalledDrainPipeClient,
    WindowsInstalledDrainPipeError,
    WindowsInstalledDrainPipeParentHub,
    WindowsInstalledDrainPipeParentEndpoint,
    WindowsInstalledDrainPipeServer,
)


pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows named pipe contract")


def _binding() -> InstalledDrainBinding:
    return InstalledDrainBinding(
        installation_id="a" * 64,
        installation_epoch=7,
        config_generation=11,
        service_boot_id="b" * 64,
    )


def _closed_child_environment() -> dict[str, str]:
    allowed = {
        "SYSTEMROOT",
        "WINDIR",
        "SYSTEMDRIVE",
        "COMSPEC",
        "PATHEXT",
        "TEMP",
        "TMP",
    }
    environment = {
        name: value
        for name, value in os.environ.items()
        if name.upper() in allowed
    }
    environment.update(
        {
            "PYTHONIOENCODING": "utf-8",
            "PYTHONUTF8": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )
    return environment


def _child_code() -> str:
    return """
import os
import sys
sys.path.insert(0, sys.argv[2])
from gateway.installed_channel_drain import InstalledDrainBinding
from gateway.windows_installed_drain_pipe import WindowsInstalledDrainPipeClient

binding = InstalledDrainBinding(
    installation_id='a' * 64,
    installation_epoch=7,
    config_generation=11,
    service_boot_id='b' * 64,
)
print(os.getpid(), flush=True)
with WindowsInstalledDrainPipeClient.connect(
    binding=binding,
    role='weixin',
    expected_server_pid=int(sys.argv[1]),
    timeout_ms=5000,
) as connection:
    assert connection.receive(timeout_ms=5000) == b'parent-frame'
    connection.send(b'child-frame', timeout_ms=5000)
"""


def _authenticated_child_code() -> str:
    return """
import json
import os
import sys
sys.path.insert(0, sys.argv[2])
from gateway.installed_channel_drain import (
    InstalledChildDrainFence,
    InstalledDrainBinding,
    InstalledDrainProtocol,
)
from gateway.windows_installed_drain_pipe import (
    WindowsInstalledDrainPipeChildEndpoint,
    WindowsInstalledDrainPipeClient,
)
from gateway.windows_installed_process_manager import current_windows_process_receipt

binding = InstalledDrainBinding(
    installation_id='a' * 64,
    installation_epoch=7,
    config_generation=11,
    service_boot_id='b' * 64,
)
process = current_windows_process_receipt()
print(json.dumps({
    'pid': process.pid,
    'started_utc_ticks': process.started_utc_ticks,
    'command_line_sha256': process.command_line_sha256,
}, separators=(',', ':')), flush=True)
fence = InstalledChildDrainFence(
    binding=binding,
    role='weixin',
    process=process,
)
with WindowsInstalledDrainPipeClient.connect(
    binding=binding,
    role='weixin',
    expected_server_pid=int(sys.argv[1]),
    timeout_ms=5000,
) as connection:
    role_key = connection.bootstrap_child(timeout_ms=5000)
    protocol = InstalledDrainProtocol(
        role_key=role_key,
        binding=binding,
        role='weixin',
        process=process,
    )
    endpoint = WindowsInstalledDrainPipeChildEndpoint(
        connection=connection,
        protocol=protocol,
        timeout_ms=5000,
    )
    command = endpoint.receive_command()
    receipt = fence.apply_command(command)
    endpoint.send_receipt(receipt)
"""


def _coordinated_child_code() -> str:
    return """
import json
import os
import sys
sys.path.insert(0, sys.argv[2])
from gateway.installed_channel_drain import (
    InstalledChildDrainFence,
    InstalledDrainBinding,
    InstalledDrainProtocol,
)
from gateway.windows_installed_drain_pipe import (
    WindowsInstalledDrainPipeChildEndpoint,
    WindowsInstalledDrainPipeClient,
)
from gateway.windows_installed_process_manager import current_windows_process_receipt
from gateway.installed_channel_child_drain_runtime import InstalledChannelChildDrainRuntime

role = sys.argv[3]
endpoint_timeout_ms = int(sys.argv[4]) if len(sys.argv) > 4 else 5000
binding = InstalledDrainBinding(
    installation_id='a' * 64,
    installation_epoch=7,
    config_generation=11,
    service_boot_id='b' * 64,
)
process = current_windows_process_receipt()
print(json.dumps({
    'pid': process.pid,
    'started_utc_ticks': process.started_utc_ticks,
    'command_line_sha256': process.command_line_sha256,
}, separators=(',', ':')), flush=True)
fence = InstalledChildDrainFence(binding=binding, role=role, process=process)
with WindowsInstalledDrainPipeClient.connect(
    binding=binding,
    role=role,
    expected_server_pid=int(sys.argv[1]),
    timeout_ms=5000,
) as connection:
    role_key = connection.bootstrap_child(timeout_ms=5000)
    endpoint = WindowsInstalledDrainPipeChildEndpoint(
        connection=connection,
        protocol=InstalledDrainProtocol(
            role_key=role_key,
            binding=binding,
            role=role,
            process=process,
        ),
        timeout_ms=endpoint_timeout_ms,
    )
    runtime = InstalledChannelChildDrainRuntime(endpoint=endpoint, fence=fence)
    runtime.start()
    assert runtime.wait(timeout=10)
    runtime.raise_if_failed()
"""


def _bad_bootstrap_child_code() -> str:
    return """
import os
import sys
sys.path.insert(0, sys.argv[2])
from gateway.installed_channel_drain import InstalledDrainBinding
from gateway.windows_installed_drain_pipe import WindowsInstalledDrainPipeClient

binding = InstalledDrainBinding(
    installation_id='a' * 64,
    installation_epoch=7,
    config_generation=11,
    service_boot_id='b' * 64,
)
print(os.getpid(), flush=True)
with WindowsInstalledDrainPipeClient.connect(
    binding=binding,
    role='engine',
    expected_server_pid=int(sys.argv[1]),
    timeout_ms=5000,
) as connection:
    connection.receive(timeout_ms=5000)
    connection.send(b'forged-ack', timeout_ms=5000)
"""


def test_real_named_pipe_round_trip_binds_both_process_ids() -> None:
    project_root = Path(__file__).resolve().parents[1]
    server = WindowsInstalledDrainPipeServer(
        binding=_binding(),
        role="weixin",
        allowed_service_sid=nachuan_core_service_sid(),
    )
    environment = _closed_child_environment()
    child = subprocess.Popen(
        [
            sys.executable,
            "-I", "-X", "utf8",
            "-c",
            _child_code(),
            str(os.getpid()),
            str(project_root),
        ],
        cwd=str(project_root),
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True, encoding="utf-8",
    )
    try:
        assert child.stdout is not None
        client_pid = int(child.stdout.readline().strip())
        with server.accept(expected_client_pid=client_pid, timeout_ms=5_000) as connection:
            connection.send(b"parent-frame", timeout_ms=5_000)
            assert connection.receive(timeout_ms=5_000) == b"child-frame"
        stdout, stderr = child.communicate(timeout=10)
        assert child.returncode == 0, (stdout, stderr)
    finally:
        server.close()
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)




def test_receive_preserves_a_frame_completed_during_timeout_cancellation(monkeypatch) -> None:
    """Windows may complete the read before CancelIoEx reaches it (ERROR_NOT_FOUND)."""
    project_root = Path(__file__).resolve().parents[1]
    server = WindowsInstalledDrainPipeServer(
        binding=_binding(), role="weixin", allowed_service_sid=nachuan_core_service_sid()
    )
    code = "import time\n" + _child_code().replace(
        "    connection.send(b'child-frame', timeout_ms=5000)",
        "    time.sleep(0.1)\n    connection.send(b'child-frame', timeout_ms=5000)",
    )
    child = subprocess.Popen(
        [sys.executable, "-I", "-X", "utf8", "-c", code, str(os.getpid()), str(project_root)],
        cwd=str(project_root), env=_closed_child_environment(),
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8",
    )
    real_wait = pipe_transport._kernel32.WaitForSingleObject
    raced = []

    def timeout_after_io_completion(event, timeout):
        result = real_wait(event, timeout)
        assert result == 0, "the real pending read must complete before injecting the race"
        raced.append(True)
        return 258

    try:
        assert child.stdout is not None
        client_pid = int(child.stdout.readline().strip())
        with server.accept(expected_client_pid=client_pid, timeout_ms=5000) as connection:
            connection.send(b"parent-frame", timeout_ms=5000)
            with monkeypatch.context() as fault:
                fault.setattr(pipe_transport._kernel32, "WaitForSingleObject", timeout_after_io_completion)
                assert connection.receive(timeout_ms=5000) == b"child-frame"
            assert raced, "fixture must exercise the overlapped timeout boundary"
        stdout, stderr = child.communicate(timeout=10)
        assert child.returncode == 0, (stdout, stderr)
    finally:
        server.close()
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)




def test_pending_cancellation_is_not_retried_or_waited_without_a_deadline(monkeypatch) -> None:
    project_root = Path(__file__).resolve().parents[1]
    server = WindowsInstalledDrainPipeServer(
        binding=_binding(), role="weixin", allowed_service_sid=nachuan_core_service_sid()
    )
    code = _child_code().replace(
        "    connection.send(b'child-frame', timeout_ms=5000)",
        "    print('ready-to-send', flush=True)\n"
        "    assert sys.stdin.readline().strip() == 'send'\n"
        "    connection.send(b'child-frame', timeout_ms=5000)",
    )
    child = subprocess.Popen(
        [sys.executable, "-I", "-X", "utf8", "-c", code, str(os.getpid()), str(project_root)],
        cwd=str(project_root), env=_closed_child_environment(),
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8",
    )
    try:
        assert child.stdout is not None
        client_pid = int(child.stdout.readline().strip())
        with server.accept(expected_client_pid=client_pid, timeout_ms=5000) as connection:
            connection.send(b"parent-frame", timeout_ms=5000)
            assert child.stdout.readline().strip() == "ready-to-send"
            started = time.monotonic()
            with monkeypatch.context() as fault:
                # Documented OS behavior: cancellation is requested, not completed.
                fault.setattr(pipe_transport._kernel32, "CancelIoEx", lambda *_args: 1)
                with pytest.raises(pipe_transport.WindowsInstalledDrainPipeTimeout) as failure:
                    connection.receive(timeout_ms=20)
                assert failure.value.retry_safe is False
                assert time.monotonic() - started < 0.5
                with pytest.raises(WindowsInstalledDrainPipeError, match="poisoned"):
                    connection.receive(timeout_ms=20)
                stdout, stderr = child.communicate(input="send\n", timeout=10)
                assert child.returncode == 0, (stdout, stderr)
    finally:
        server.close()
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)


def test_server_rejects_a_client_with_the_wrong_expected_pid() -> None:
    project_root = Path(__file__).resolve().parents[1]
    server = WindowsInstalledDrainPipeServer(
        binding=_binding(),
        role="weixin",
        allowed_service_sid=nachuan_core_service_sid(),
    )
    environment = _closed_child_environment()
    child = subprocess.Popen(
        [
            sys.executable,
            "-I", "-X", "utf8",
            "-c",
            _child_code(),
            str(os.getpid()),
            str(project_root),
        ],
        cwd=str(project_root),
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True, encoding="utf-8",
    )
    try:
        assert child.stdout is not None
        client_pid = int(child.stdout.readline().strip())
        with pytest.raises(WindowsInstalledDrainPipeError, match="client process"):
            server.accept(expected_client_pid=client_pid + 1, timeout_ms=5_000)
    finally:
        server.close()
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)


def test_client_rejects_a_server_with_the_wrong_expected_pid() -> None:
    project_root = Path(__file__).resolve().parents[1]
    server = WindowsInstalledDrainPipeServer(
        binding=_binding(),
        role="weixin",
        allowed_service_sid=nachuan_core_service_sid(),
    )
    child = subprocess.Popen(
        [
            sys.executable,
            "-I", "-X", "utf8",
            "-c",
            _child_code(),
            str(os.getpid() + 1),
            str(project_root),
        ],
        cwd=str(project_root),
        env=_closed_child_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True, encoding="utf-8",
    )
    try:
        assert child.stdout is not None
        int(child.stdout.readline().strip())
        stdout, stderr = child.communicate(timeout=10)
        assert child.returncode != 0
        assert "pipe server process mismatch" in stderr
        assert stdout == ""
    finally:
        server.close()
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)


def test_pipe_rejects_an_oversized_frame_before_write() -> None:
    with pytest.raises(WindowsInstalledDrainPipeError, match="frame size"):
        WindowsInstalledDrainPipeClient.validate_frame(b"x" * 16_385)


def test_pipe_is_single_instance_and_connect_timeout_is_bounded() -> None:
    server = WindowsInstalledDrainPipeServer(
        binding=_binding(),
        role="engine",
        allowed_service_sid=nachuan_core_service_sid(),
    )
    try:
        with pytest.raises(WindowsInstalledDrainPipeError, match="server creation"):
            WindowsInstalledDrainPipeServer(
                binding=_binding(),
                role="engine",
                allowed_service_sid=nachuan_core_service_sid(),
            )
        started = time.monotonic()
        with pytest.raises(WindowsInstalledDrainPipeError, match="connect timed out"):
            server.accept(expected_client_pid=os.getpid(), timeout_ms=50)
        assert time.monotonic() - started < 1.0
    finally:
        server.close()


def test_parent_rejects_a_forged_role_key_bootstrap_ack() -> None:
    project_root = Path(__file__).resolve().parents[1]
    server = WindowsInstalledDrainPipeServer(
        binding=_binding(),
        role="engine",
        allowed_service_sid=nachuan_core_service_sid(),
    )
    child = subprocess.Popen(
        [
            sys.executable,
            "-I", "-X", "utf8",
            "-c",
            _bad_bootstrap_child_code(),
            str(os.getpid()),
            str(project_root),
        ],
        cwd=str(project_root),
        env=_closed_child_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True, encoding="utf-8",
    )
    try:
        assert child.stdout is not None
        client_pid = int(child.stdout.readline().strip())
        with server.accept(expected_client_pid=client_pid, timeout_ms=5_000) as connection:
            with pytest.raises(
                WindowsInstalledDrainPipeError,
                match="acknowledgement",
            ):
                connection.bootstrap_parent(b"k" * 32, timeout_ms=5_000)
            with pytest.raises(WindowsInstalledDrainPipeError, match="poisoned"):
                connection.bootstrap_parent(b"k" * 32, timeout_ms=5_000)
        stdout, stderr = child.communicate(timeout=10)
        assert child.returncode == 0, (stdout, stderr)
    finally:
        server.close()
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)


def test_pipe_kernel_dacl_is_protected_and_closed_to_generic_users() -> None:
    service_sid = nachuan_core_service_sid()
    server = WindowsInstalledDrainPipeServer(
        binding=_binding(),
        role="feishu",
        allowed_service_sid=service_sid,
    )
    try:
        sddl = server.security_sddl()
        assert sddl == (
            "D:P(A;;FA;;;SY)(A;;FA;;;BA)"
            f"(A;;0x12019f;;;{service_sid})"
        )
    finally:
        server.close()


def test_real_pipe_carries_authenticated_drain_command_and_role_receipt() -> None:
    project_root = Path(__file__).resolve().parents[1]
    binding = _binding()
    server = WindowsInstalledDrainPipeServer(
        binding=binding,
        role="weixin",
        allowed_service_sid=nachuan_core_service_sid(),
    )
    child = subprocess.Popen(
        [
            sys.executable,
            "-I", "-X", "utf8",
            "-c",
            _authenticated_child_code(),
            str(os.getpid()),
            str(project_root),
        ],
        cwd=str(project_root),
        env=_closed_child_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True, encoding="utf-8",
    )
    try:
        assert child.stdout is not None
        raw_process = json.loads(child.stdout.readline())
        process = InstalledChannelProcessReceipt(**raw_process)
        role_key = derive_installed_drain_role_key(
            control_key=b"k" * 32,
            binding=binding,
            role="weixin",
            process=process,
        )
        operation = InstalledDrainOperation(
            binding=binding,
            stop_id="c" * 64,
            stop_generation=3,
            deadline_utc_ns=1_900_000_000_000_000_000,
        )
        protocol = InstalledDrainProtocol(
            role_key=role_key,
            binding=binding,
            role="weixin",
            process=process,
        )
        with server.accept(expected_client_pid=process.pid, timeout_ms=5_000) as connection:
            connection.bootstrap_parent(role_key, timeout_ms=5_000)
            endpoint = WindowsInstalledDrainPipeParentEndpoint(
                connection=connection,
                protocol=protocol,
                timeout_ms=5_000,
            )
            endpoint.request(
                InstalledDrainCommand(
                    operation=operation,
                    action="close_claims",
                )
            )
            receipt = endpoint.snapshot(operation)
        stdout, stderr = child.communicate(timeout=10)
        assert child.returncode == 0, (stdout, stderr)
        assert receipt.operation == operation
        assert receipt.role == "weixin"
        assert receipt.process == process
        assert receipt.phase == "drained"
        assert receipt.claim_gate_closed is True
    finally:
        server.close()
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)


def test_parent_coordinator_drains_three_real_child_processes_in_order() -> None:
    project_root = Path(__file__).resolve().parents[1]
    binding = _binding()
    roles = ("engine", "weixin", "feishu")
    hub = WindowsInstalledDrainPipeParentHub(
        binding=binding,
        control_key=b"q" * 32,
        allowed_service_sid=nachuan_core_service_sid(),
    )
    children = {}
    try:
        for role in roles:
            children[role] = subprocess.Popen(
                [
                    sys.executable,
                    "-I", "-X", "utf8",
                    "-c",
                    _coordinated_child_code(),
                    str(os.getpid()),
                    str(project_root),
                    role,
                ],
                cwd=str(project_root),
                env=_closed_child_environment(),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True, encoding="utf-8",
            )
        processes = {}
        for role in roles:
            assert children[role].stdout is not None
            processes[role] = InstalledChannelProcessReceipt(
                **json.loads(children[role].stdout.readline())
            )
        endpoints = hub.attach(processes=processes, timeout_ms=5_000)
        operation = InstalledDrainOperation(
            binding=binding,
            stop_id="d" * 64,
            stop_generation=4,
            deadline_utc_ns=1_900_000_000_000_000_000,
        )
        result = InstalledParentDrainCoordinator(
            operation=operation,
            processes=processes,
            endpoints=endpoints,
        ).drain(timeout_ms=5_000)
        assert result.business_drained is True
        assert result.exit_acknowledged is True
        assert result.action_sequence == (
            "weixin:close_claims",
            "feishu:close_claims",
            "engine:close_admission",
            "weixin:exit",
            "feishu:exit",
            "engine:exit",
        )
        for role in roles:
            stdout, stderr = children[role].communicate(timeout=10)
            assert children[role].returncode == 0, (role, stdout, stderr)
    finally:
        hub.close()
        for child in children.values():
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)


def test_parent_hub_attach_uses_one_shared_deadline() -> None:
    hub = WindowsInstalledDrainPipeParentHub(
        binding=_binding(),
        control_key=b"h" * 32,
        allowed_service_sid=nachuan_core_service_sid(),
    )
    processes = {
        role: InstalledChannelProcessReceipt(
            pid=60_000 + index,
            started_utc_ticks=100 + index,
            command_line_sha256=str(index) * 64,
        )
        for index, role in enumerate(("engine", "weixin", "feishu"), start=1)
    }
    started = time.monotonic()
    try:
        with pytest.raises(WindowsInstalledDrainPipeError, match="timed out"):
            hub.attach(processes=processes, timeout_ms=50)
        assert time.monotonic() - started < 1.0
    finally:
        hub.close()


def test_real_child_control_survives_idle_read_timeouts() -> None:
    project_root = Path(__file__).resolve().parents[1]
    binding = _binding()
    role = "engine"
    server = WindowsInstalledDrainPipeServer(
        binding=binding,
        role=role,
        allowed_service_sid=nachuan_core_service_sid(),
    )
    child = subprocess.Popen(
        [
            sys.executable,
            "-I", "-X", "utf8",
            "-c",
            _coordinated_child_code(),
            str(os.getpid()),
            str(project_root),
            role,
            "50",
        ],
        cwd=str(project_root),
        env=_closed_child_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True, encoding="utf-8",
    )
    connection = None
    try:
        assert child.stdout is not None
        process = InstalledChannelProcessReceipt(**json.loads(child.stdout.readline()))
        role_key = derive_installed_drain_role_key(
            control_key=b"i" * 32,
            binding=binding,
            role=role,
            process=process,
        )
        connection = server.accept(
            expected_client_pid=process.pid,
            timeout_ms=5_000,
        )
        connection.bootstrap_parent(role_key, timeout_ms=5_000)
        endpoint = WindowsInstalledDrainPipeParentEndpoint(
            connection=connection,
            protocol=InstalledDrainProtocol(
                role_key=role_key,
                binding=binding,
                role=role,
                process=process,
            ),
            timeout_ms=500,
        )
        time.sleep(0.2)
        assert child.poll() is None
        operation = InstalledDrainOperation(
            binding=binding,
            stop_id="e" * 64,
            stop_generation=5,
            deadline_utc_ns=1_900_000_000_000_000_000,
        )
        endpoint.request(
            InstalledDrainCommand(operation=operation, action="close_admission")
        )
        assert endpoint.snapshot(operation).phase == "drained"
        endpoint.request(InstalledDrainCommand(operation=operation, action="exit"))
        assert endpoint.snapshot(operation).phase == "exit_requested"
        stdout, stderr = child.communicate(timeout=10)
        assert child.returncode == 0, (stdout, stderr)
    finally:
        if connection is not None:
            connection.close()
        server.close()
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)
