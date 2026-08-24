"""Launch one supervisor-owned service with a service-specific environment.

The PowerShell 5.1 ``Start-Process`` cmdlet cannot supply a replacement
environment.  This tiny stdlib-only parent is a defense-in-depth environment
shim: it inherits the supervisor environment, constructs the exact child
environment, starts a fixed command without a shell, and waits for it.  The
supervisor kills the wrapper process tree, so no detached child is created.
It does not isolate malicious code running as the same OS user; production
containment of untrusted components still requires a distinct low-privilege
identity, AppContainer, VM, or equivalent OS-enforced boundary.
"""

from __future__ import annotations

import os
import re
import secrets
import subprocess
import sys
import threading
import time
from collections.abc import Mapping
from pathlib import Path


_SERVICE_COMMANDS: dict[str, tuple[str, ...]] = {
    "engine": ("-u", "-m", "gateway.app"),
    "weixin": ("-u", "scripts/run_weixin_ilink_bridge.py"),
    "feishu": ("-u", "scripts/run_feishu_bridge.py"),
}
_SERVICE_MARKERS = {
    "engine": "gateway.app",
    "weixin": "run_weixin_ilink_bridge.py",
    "feishu": "run_feishu_bridge.py",
}
_CHANNEL_PREFIXES = ("FEISHU_", "WEIXIN_", "TELEGRAM_")
_PAID_MEDIA_KEY_NAME = "NACHUAN_PAID_MEDIA_API_KEY"
_PAID_MEDIA_KEY_PATTERN = re.compile(r"sk-paid-media-[0-9a-f]{64}")
_INJECTION_NAMES = {
    "BASH_ENV",
    "ENV",
    "NODE_OPTIONS",
    "NODE_PATH",
    "PROMPT_COMMAND",
    "PYTHONHOME",
    "PYTHONINSPECT",
    "PYTHONPATH",
    "PYTHONSTARTUP",
}
_BRIDGE_COMMON_NAMES = {
    "APPDATA",
    "BRIDGE_API_KEY",
    "BRIDGE_MODEL",
    "COMPUTERNAME",
    "COMSPEC",
    "HOMEDRIVE",
    "HOMEPATH",
    "LANG",
    "LC_ALL",
    "LOCALAPPDATA",
    "NUMBER_OF_PROCESSORS",
    "PATHEXT",
    "PROCESSOR_ARCHITECTURE",
    "PROCESSOR_IDENTIFIER",
    "PROCESSOR_LEVEL",
    "PROCESSOR_REVISION",
    "PROGRAMDATA",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "TZ",
    "USERDOMAIN",
    "USERNAME",
    "USERPROFILE",
    "WINDIR",
}

# The engine reads ordinary product settings from the project-owned settings
# store/.env.  Only values that are intentionally injected by the supervisor,
# or that select an already-attested local component, may cross this process
# boundary.  In particular PATH, COMSPEC, proxy and custom CA variables are
# rebuilt/dropped below instead of being inherited from an interactive shell.
_ENGINE_ALLOWED_NAMES = _BRIDGE_COMMON_NAMES | {
    "ADMISSION_BACKGROUND_JOB_TTL_SEC",
    "ADMISSION_BACKGROUND_JOBS_GLOBAL",
    "ADMISSION_BACKGROUND_JOBS_PER_KEY",
    "ADMISSION_DAILY_EXPENSIVE_PER_KEY",
    "ADMISSION_MAX_CONCURRENCY_GLOBAL",
    "ADMISSION_MAX_CONCURRENCY_PER_KEY",
    "ADMISSION_ROLLING_MINUTE_PER_KEY",
    "AGENT_ALLOWED_TOOLS",
    "AGENT_DAILY_CALL_CAP",
    "AGENT_EXEC_WORKDIR",
    "AGENT_PERSONA",
    "APPROVAL_ACTION_TTL_SEC",
    "APPROVAL_ADMIN_KEY",
    "BACKUP_DIR",
    "BACKUP_INTERVAL_SEC",
    "CODEX_CLI_PATH",
    "CODEX_CLI_SHA256",
    "CODEX_HOME",
    "COMPRESS_ENABLED",
    "COMPRESS_LONG_CHARS",
    "COMPRESS_MIN_CHARS",
    "CONTENT_DENYLIST",
    "DATA_DIR",
    "FFMPEG_BIN",
    "FFMPEG_SHA256",
    "FFPROBE_BIN",
    "FFPROBE_SHA256",
    "GATEWAY_API_KEYS",
    "GATEWAY_HOST",
    "GATEWAY_PORT",
    "HOME",
    "IMAGEHOST_BUCKET",
    "LLAMA_SERVER_BIN",
    "LLAMA_SERVER_DIR",
    "LLMLINGUA2_DIR",
    "LLMLINGUA2_ONNX",
    "LOCAL_LLAMA_CTX",
    "LOCAL_LLAMA_PORT",
    "LOCAL_LLAMA_START_TIMEOUT",
    "LOCAL_MODEL_DIR",
    "LOCAL_MODEL_ID",
    "LOCAL_MODEL_PATH",
    "LOCAL_MODEL_REVISION",
    "LOCAL_MODEL_SHA256",
    "NACHUAN_AGENT_WALL_MIN",
    "NACHUAN_CHANNEL_ATTEMPT_TIMEOUT",
    "NACHUAN_CHANNEL_TOTAL_TIMEOUT",
    "NACHUAN_CONNECTION_HOST_ALLOWLIST",
    "NACHUAN_COORDINATOR_BACKBONE_DIR",
    "NACHUAN_EMBED_DISABLED",
    "NACHUAN_EMBED_MODEL",
    "NACHUAN_ENABLE_VERIFIED_MODEL_DOWNLOAD",
    "NACHUAN_ENGINE_BOOT_TOKEN",
    "NACHUAN_ENGINE_GENERATION",
    "NACHUAN_ENGINE_PORT",
    "NACHUAN_FAILOVER_ATTEMPT_TIMEOUT",
    "NACHUAN_FAILOVER_FIRST_CHUNK_TIMEOUT",
    "NACHUAN_FAILOVER_IDLE_CHUNK_TIMEOUT",
    "NACHUAN_FAILOVER_STREAM_ATTEMPT_TIMEOUT",
    "NACHUAN_FAILOVER_STREAM_TOTAL_TIMEOUT",
    "NACHUAN_FAILOVER_TOTAL_TIMEOUT",
    "NACHUAN_FEISHU_BRIDGE_API_KEY",
    "NACHUAN_GUARD_HOME",
    "NACHUAN_LOCAL_RUNTIME_MANIFEST",
    "NACHUAN_PAID_MEDIA_API_KEY",
    "NACHUAN_SUPABASE_HOST_ALLOWLIST",
    "NACHUAN_TRINITY",
    "NACHUAN_WARM_AUDIO",
    "NACHUAN_WEIXIN_BRIDGE_API_KEY",
    "NEMOTRON_ASR",
    "NEMOTRON_ASR_DIR",
    "NEMOTRON_ASR_THREADS",
    "SAVERS_WARM",
    "SEMCACHE_DB_DIR",
    "SEMCACHE_EMBED_DIR",
    "SEMCACHE_ENABLED",
    "SEMCACHE_THRESHOLD",
    "SENSEVOICE_ASR",
    "SENSEVOICE_DIR",
    "SENSEVOICE_THREADS",
    "STUDIO_DOWNLOAD_TIMEOUT_SECONDS",
    "STUDIO_FFMPEG_TIMEOUT_SECONDS",
    "STUDIO_FRAME_TIMEOUT_SECONDS",
    "SYNC_INTERVAL_SEC",
    "SYNC_SERVER_URL",
    "USAGE_DB_PATH",
    "VOLCANO_API_KEY",
    "VOLCANO_BASE_URL",
    "WHISPER_MODEL",
    "WHISPER_MODEL_DIR",
}


def _scoped_bridge_key_name(service: str) -> str:
    return f"NACHUAN_{service.upper()}_BRIDGE_API_KEY"


def _casefolded_source(source: Mapping[str, str]) -> dict[str, tuple[str, str]]:
    return {str(name).upper(): (str(name), str(value)) for name, value in source.items()}


def _paid_media_capability(
    folded: Mapping[str, tuple[str, str]],
) -> str:
    """Return one engine-only paid capability without trusting a weak override."""

    runtime_entry = folded.get("GATEWAY_API_KEYS")
    runtime_keys = {
        value.strip()
        for value in (runtime_entry[1].split(",") if runtime_entry else ())
        if value.strip()
    }
    approval_entry = folded.get("APPROVAL_ADMIN_KEY")
    approval_key = approval_entry[1].strip() if approval_entry else ""
    reserved = runtime_keys | ({approval_key} if approval_key else set())

    configured_entry = folded.get(_PAID_MEDIA_KEY_NAME)
    configured = configured_entry[1].strip() if configured_entry else ""
    if configured:
        if not _PAID_MEDIA_KEY_PATTERN.fullmatch(configured) or configured in reserved:
            raise ValueError("invalid or overlapping paid media capability")
        return configured

    while True:
        generated = f"sk-paid-media-{secrets.token_hex(32)}"
        if generated not in reserved:
            return generated


def _trusted_bootstrap_paths() -> tuple[Path, Path]:
    """Return Windows and system directories without trusting process env."""

    if os.name != "nt":
        return Path("/"), Path("/usr/bin")
    import ctypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    def query(name: str) -> Path:
        function = getattr(kernel32, name)
        function.argtypes = [ctypes.c_wchar_p, ctypes.c_uint]
        function.restype = ctypes.c_uint
        buffer = ctypes.create_unicode_buffer(32768)
        length = int(function(buffer, len(buffer)))
        if length <= 0 or length >= len(buffer):
            raise OSError(ctypes.get_last_error(), f"{name} failed")
        return Path(buffer.value).resolve(strict=True)

    return query("GetWindowsDirectoryW"), query("GetSystemDirectoryW")


def build_child_environment(
    service: str,
    source: Mapping[str, str] | None = None,
    *,
    engine_port: int = 8080,
) -> dict[str, str]:
    """Return the environment contract for one fixed managed service."""

    if service not in _SERVICE_COMMANDS:
        raise ValueError("unsupported managed service")
    if not isinstance(engine_port, int) or not (1 <= engine_port <= 65535):
        raise ValueError("invalid managed engine port")
    original = dict(os.environ if source is None else source)
    folded = _casefolded_source(original)

    if service == "engine":
        child = {
            original_name: value
            for upper_name, (original_name, value) in folded.items()
            if upper_name in _ENGINE_ALLOWED_NAMES
            and upper_name not in _INJECTION_NAMES
            and not upper_name.startswith(_CHANNEL_PREFIXES)
        }
        # Canonicalise the name so a case-variant inherited from a shell cannot
        # produce two ambiguous Windows environment entries.  Direct launcher
        # use also gets a fresh capability; the supervisor normally supplies a
        # session-stable value so all engine restarts in that session agree.
        for name in tuple(child):
            if name.upper() == _PAID_MEDIA_KEY_NAME:
                child.pop(name)
        child[_PAID_MEDIA_KEY_NAME] = _paid_media_capability(folded)
    else:
        service_prefix = f"{service.upper()}_"
        denied = {
            f"{service_prefix}ALLOW_ALL",
            f"{service_prefix}ALLOWED",
            f"{service_prefix}OWNER",
            "FEISHU_ALLOWED_USERS",
            "FEISHU_OWNER_OPEN_ID",
        }
        allowed = _BRIDGE_COMMON_NAMES | {
            upper_name
            for upper_name in folded
            if upper_name.startswith(service_prefix) and upper_name not in denied
        }
        child = {
            original_name: value
            for upper_name, (original_name, value) in folded.items()
            if upper_name in allowed and upper_name not in _INJECTION_NAMES
        }
        scoped_key = folded.get(_scoped_bridge_key_name(service))
        child.pop("GATEWAY_API_KEYS", None)
        child.pop("APPROVAL_ADMIN_KEY", None)
        child.pop("NACHUAN_ENGINE_BOOT_TOKEN", None)
        if scoped_key and scoped_key[1].strip():
            child["BRIDGE_API_KEY"] = scoped_key[1].strip()
        else:
            child.pop("BRIDGE_API_KEY", None)

    # These values are invariants, not ambient configuration.
    root = Path(__file__).resolve().parent.parent
    data_dir = root / "data"
    child["NACHUAN_ENV"] = "production"
    child["DATA_DIR"] = str(data_dir)
    child["USAGE_DB_PATH"] = str(data_dir / "usage.db")
    if service == "engine":
        # A managed production engine must never invoke a paid provider
        # without first committing the immutable provider-attempt row.
        child["NACHUAN_PROVIDER_CALL_LEDGER_MODE"] = "required"
        child["NACHUAN_PROVIDER_CALL_LEDGER_PATH"] = str(
            data_dir / "provider-calls.db"
        )
    child["BRIDGE_ENGINE_URL"] = f"http://127.0.0.1:{engine_port}"
    child["GATEWAY_HOST"] = "127.0.0.1"
    child["GATEWAY_PORT"] = str(engine_port)
    child["NO_PROXY"] = "127.0.0.1,localhost,::1"
    child["PYTHONUTF8"] = "1"
    child["PYTHONIOENCODING"] = "utf-8"
    child["PYTHONUNBUFFERED"] = "1"
    windows_dir, system_dir = _trusted_bootstrap_paths()
    path_entries = [Path(sys.executable).resolve(strict=True).parent, system_dir, windows_dir]
    child["PATH"] = os.pathsep.join(dict.fromkeys(str(item) for item in path_entries))
    if os.name == "nt":
        child["SYSTEMROOT"] = str(windows_dir)
        child["WINDIR"] = str(windows_dir)
        child["COMSPEC"] = str((system_dir / "cmd.exe").resolve(strict=True))
        child["PATHEXT"] = ".COM;.EXE;.BAT;.CMD"
    return child


def _watch_parent_exit(
    expected_parent_pid: int,
    expected_parent_creation_filetime: int,
) -> threading.Event:
    """Return an event that is set when the direct supervisor process exits."""

    exited = threading.Event()
    parent_pid = int(expected_parent_pid)
    if parent_pid <= 0 or expected_parent_creation_filetime <= 0:
        exited.set()
        return exited
    if os.name != "nt":
        def wait_posix() -> None:
            while os.getppid() == parent_pid:
                try:
                    os.kill(parent_pid, 0)
                except OSError:
                    break
                time.sleep(0.25)
            exited.set()

        threading.Thread(target=wait_posix, name="supervisor-watch", daemon=True).start()
        return exited

    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.GetProcessTimes.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
    ]
    kernel32.GetProcessTimes.restype = wintypes.BOOL
    parent = kernel32.OpenProcess(0x00100000 | 0x1000, False, parent_pid)
    if not parent:
        exited.set()
        return exited
    created = wintypes.FILETIME()
    exited_at = wintypes.FILETIME()
    kernel_at = wintypes.FILETIME()
    user_at = wintypes.FILETIME()
    if not kernel32.GetProcessTimes(
        parent,
        ctypes.byref(created),
        ctypes.byref(exited_at),
        ctypes.byref(kernel_at),
        ctypes.byref(user_at),
    ):
        kernel32.CloseHandle(parent)
        exited.set()
        return exited
    observed_filetime = (int(created.dwHighDateTime) << 32) | int(created.dwLowDateTime)
    if observed_filetime != int(expected_parent_creation_filetime):
        kernel32.CloseHandle(parent)
        exited.set()
        return exited

    def wait_windows() -> None:
        try:
            kernel32.WaitForSingleObject(parent, 0xFFFFFFFF)
        finally:
            kernel32.CloseHandle(parent)
            exited.set()

    threading.Thread(target=wait_windows, name="supervisor-watch", daemon=True).start()
    return exited


def _create_self_kill_on_close_job() -> object | None:
    """Put this wrapper in a job before it starts any dependency code.

    Windows automatically places descendants in the same job.  Creating and
    joining the job first removes the former Popen-to-Assign race in which a
    hostile startup hook could spawn a detached process before assignment.
    The handle is intentionally kept open for the wrapper lifetime; process
    teardown closes it and KILL_ON_JOB_CLOSE removes every remaining child.
    """

    if os.name != "nt":
        return None
    import ctypes
    from ctypes import wintypes

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoInfo", IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        raise OSError(ctypes.get_last_error(), "CreateJobObjectW failed")
    info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    info.BasicLimitInformation.LimitFlags = 0x00002000  # KILL_ON_JOB_CLOSE
    if not kernel32.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info)):
        kernel32.CloseHandle(job)
        raise OSError(ctypes.get_last_error(), "SetInformationJobObject failed")
    if not kernel32.AssignProcessToJobObject(job, kernel32.GetCurrentProcess()):
        kernel32.CloseHandle(job)
        raise OSError(ctypes.get_last_error(), "AssignProcessToJobObject failed")
    return job


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 5:
        print(
            "managed launcher requires service, identity marker, port and parent identity",
            file=sys.stderr,
        )
        return 64
    service, marker, raw_port, raw_parent_pid, raw_parent_filetime = args
    if service not in _SERVICE_COMMANDS or marker != _SERVICE_MARKERS[service]:
        print("managed launcher contract rejected", file=sys.stderr)
        return 64
    try:
        engine_port = int(raw_port)
        parent_pid = int(raw_parent_pid)
        parent_filetime = int(raw_parent_filetime)
    except ValueError:
        print("managed launcher contract rejected", file=sys.stderr)
        return 64
    if (
        not (1 <= engine_port <= 65535)
        or str(engine_port) != raw_port
        or parent_pid <= 0
        or str(parent_pid) != raw_parent_pid
        or parent_filetime <= 0
        or str(parent_filetime) != raw_parent_filetime
    ):
        print("managed launcher contract rejected", file=sys.stderr)
        return 64

    root = Path(__file__).resolve().parent.parent
    command = [sys.executable, *_SERVICE_COMMANDS[service]]
    logs = root / "data" / "logs"
    logs.mkdir(parents=True, exist_ok=True)

    def record_state(state: str) -> None:
        with (logs / f"{service}.err.log").open("ab", buffering=0) as stream:
            stream.write(f"managed launcher state: {state}\n".encode("ascii", "strict"))

    process: subprocess.Popen[bytes] | None = None
    parent_exited = _watch_parent_exit(parent_pid, parent_filetime)
    if parent_exited.is_set():
        record_state("parent-unavailable")
        print("managed launcher supervisor is unavailable", file=sys.stderr)
        return 75
    # Keep this raw handle alive until process teardown; do not CloseHandle it
    # while the current process is still a member of the KILL_ON_CLOSE job.
    job = _create_self_kill_on_close_job()
    try:
        with (logs / f"{service}.out.log").open("ab", buffering=0) as stdout, (
            logs / f"{service}.err.log"
        ).open("ab", buffering=0) as stderr:
            process = subprocess.Popen(  # noqa: S603 - fixed executable and argv above
                command,
                cwd=root,
                env=build_child_environment(service, engine_port=engine_port),
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                close_fds=True,
            )
            while process.poll() is None:
                if parent_exited.wait(0.25):
                    record_state("parent-exited")
                    print("managed launcher supervisor exited", file=sys.stderr)
                    return 75
            exit_code = int(process.returncode or 0)
            record_state(f"child-exit-{exit_code}")
            return exit_code
    except KeyboardInterrupt:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
        return 130
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        # Referencing the handle here documents and enforces its lifetime.  The
        # OS closes it as this wrapper exits, which activates KILL_ON_JOB_CLOSE.
        _ = job


if __name__ == "__main__":
    try:
        exit_code = main()
    except BaseException as exc:
        # Early parent/job/bootstrap failures happen before the child streams
        # are attached. Persist only the exception class (never message/env)
        # so the supervisor has a bounded diagnostic without leaking secrets.
        args = list(sys.argv[1:])
        service = args[0] if args and args[0] in _SERVICE_COMMANDS else "launcher"
        try:
            logs = Path(__file__).resolve().parent.parent / "data" / "logs"
            logs.mkdir(parents=True, exist_ok=True)
            with (logs / f"{service}.err.log").open("ab", buffering=0) as stream:
                stream.write(
                    f"managed launcher bootstrap failed: {type(exc).__name__}\n".encode(
                        "ascii", "strict"
                    )
                )
        except BaseException:
            pass
        print(
            f"managed launcher bootstrap failed: {type(exc).__name__}",
            file=sys.stderr,
        )
        exit_code = 70
    raise SystemExit(exit_code)
