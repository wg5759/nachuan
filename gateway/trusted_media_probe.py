"""Bounded, attested, full-decode verification for paid media assets.

Container signatures are useful routing hints, not proof that an image or video
can be decoded.  This module forces the expected demuxer, asks the independently
attested ffprobe for one video stream, and then makes the independently attested
ffmpeg decode that stream to completion.  Neither process is resolved through
PATH and their combined stdout/stderr is drained under a hard byte budget.

The HTTP adapter deliberately lives elsewhere.  It must spool a raw request body
to a private, bounded temporary file and must never accept a client-supplied host
filesystem path.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import stat as stat_module
import subprocess
import tempfile
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import BinaryIO, Iterator, Sequence

from gateway.media_binary import (
    MediaBinaryUnavailable,
    minimal_media_env,
    pin_media_binary,
)
from gateway.secure_store import (
    SecureStorageError,
    assert_restricted_windows_acl,
    harden_restricted_windows_acl,
)


_MIB = 1024 * 1024
MAX_IMAGE_INPUT_BYTES = 24 * _MIB
MAX_VIDEO_INPUT_BYTES = 512 * _MIB
MAX_PROCESS_OUTPUT_BYTES = 64 * 1024
MAX_MEDIA_DIMENSION = 16_384
MAX_MEDIA_PIXELS = 64 * 1024 * 1024
MAX_VIDEO_DURATION_SECONDS = 24 * 60 * 60
MAX_DECODED_FRAMES = 10_000_000
MAX_TIMEOUT_SECONDS = 300.0
_READ_CHUNK_BYTES = 64 * 1024
_HASH_CHUNK_BYTES = 1024 * 1024
_MAX_ARGUMENTS = 64
_MAX_ARGUMENT_BYTES = 8192
_PROBE_SLOTS = threading.BoundedSemaphore(2)
_CLOCK = time.monotonic
VALIDATOR_VERSION = "nachuan.trusted-media-probe.v2"
VALIDATION_POLICY = "nachuan.trusted-media-policy.av-closed.v1"
TRUSTED_MEDIA_CACHE_MARKER_NAME = ".nachuan-media-cache-owner.v1.json"
TRUSTED_MEDIA_CACHE_MARKER_SCHEMA = "nachuan.trusted-media-cache-owner.v1"


@dataclass(frozen=True)
class _FormatPolicy:
    media_type: str
    kind: str
    demuxer: str
    required_format_name: str
    video_codecs: frozenset[str]
    audio_codecs: frozenset[str]
    hard_input_limit: int


_FORMATS = {
    "image/png": _FormatPolicy(
        "image/png",
        "image",
        "png_pipe",
        "png_pipe",
        frozenset({"png"}),
        frozenset(),
        MAX_IMAGE_INPUT_BYTES,
    ),
    "image/jpeg": _FormatPolicy(
        "image/jpeg",
        "image",
        "jpeg_pipe",
        "jpeg_pipe",
        frozenset({"mjpeg"}),
        frozenset(),
        MAX_IMAGE_INPUT_BYTES,
    ),
    "image/gif": _FormatPolicy(
        "image/gif",
        "image",
        "gif",
        "gif",
        frozenset({"gif"}),
        frozenset(),
        MAX_IMAGE_INPUT_BYTES,
    ),
    "image/webp": _FormatPolicy(
        "image/webp",
        "image",
        "webp_pipe",
        "webp_pipe",
        frozenset({"webp"}),
        frozenset(),
        MAX_IMAGE_INPUT_BYTES,
    ),
    "video/mp4": _FormatPolicy(
        "video/mp4",
        "video",
        "mp4",
        "mp4",
        frozenset({"h264", "hevc", "av1", "mpeg4"}),
        frozenset({"aac", "mp3", "opus"}),
        MAX_VIDEO_INPUT_BYTES,
    ),
    "video/webm": _FormatPolicy(
        "video/webm",
        "video",
        "matroska",
        "webm",
        frozenset({"vp8", "vp9", "av1"}),
        frozenset({"opus", "vorbis"}),
        MAX_VIDEO_INPUT_BYTES,
    ),
}


class TrustedMediaProbeError(RuntimeError):
    """Base class for controlled, non-diagnostic probe failures."""


class TrustedMediaRejected(TrustedMediaProbeError):
    """The bytes did not satisfy the declared format and full-decode gate."""


class TrustedMediaTooLarge(TrustedMediaProbeError):
    """The staged input exceeded its immutable byte cap."""


class TrustedMediaProbeTimeout(TrustedMediaProbeError):
    """An attested probe process exceeded its hard wall-clock timeout."""


class TrustedMediaProbeBusy(TrustedMediaProbeError):
    """All local decode slots are occupied; no unbounded queue is created."""


class TrustedMediaProbeUnavailable(TrustedMediaProbeError):
    """The attested verifier could not be launched or drained safely."""


@dataclass(frozen=True)
class TrustedMediaProbeReadiness:
    ffmpeg_sha256: str
    ffprobe_sha256: str
    validation_policy: str = VALIDATION_POLICY
    validator_version: str = VALIDATOR_VERSION
    schema: str = "nachuan.trusted-media-probe.readiness.v2"
    ready: bool = True


@dataclass(frozen=True)
class TrustedMediaProbeResult:
    media_type: str
    detected_kind: str
    byte_length: int
    sha256: str
    codec_name: str
    audio_codec_name: str | None
    video_stream_count: int
    audio_stream_count: int
    format_name: str
    width: int
    height: int
    duration_ms: int | None
    decoded_frames: int
    ffmpeg_sha256: str
    ffprobe_sha256: str
    validation_policy: str = VALIDATION_POLICY
    validator_version: str = VALIDATOR_VERSION
    schema: str = "nachuan.trusted-media-probe.result.v2"
    fully_decoded: bool = True


@dataclass(frozen=True, slots=True)
class TrustedMediaScratchOwner:
    """Installation-bound identity written beside FFmpeg's native cache file."""

    installation_id: str
    epoch: int
    database_identity: str
    generation: str

    def __post_init__(self) -> None:
        for field_name in ("installation_id", "database_identity", "generation"):
            if re.fullmatch(r"[0-9a-f]{64}", getattr(self, field_name)) is None:
                raise ValueError(f"trusted media scratch {field_name} is invalid")
        if (
            isinstance(self.epoch, bool)
            or not isinstance(self.epoch, int)
            or self.epoch < 1
        ):
            raise ValueError("trusted media scratch epoch is invalid")


def _scratch_owner_marker_bytes(owner: TrustedMediaScratchOwner) -> bytes:
    if not isinstance(owner, TrustedMediaScratchOwner):
        raise ValueError("trusted media scratch owner is invalid")
    return json.dumps(
        {
            "database_identity": owner.database_identity,
            "epoch": owner.epoch,
            "generation": owner.generation,
            "installation_id": owner.installation_id,
            "schema": TRUSTED_MEDIA_CACHE_MARKER_SCHEMA,
        },
        allow_nan=False,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


@dataclass(frozen=True)
class _BoundedProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    attested_sha256: str = ""


@dataclass(frozen=True)
class _FileIdentity:
    device: int
    inode: int
    mode: int
    links: int
    size: int
    modified_ns: int
    changed_ns: int
    birth_ns: int
    attributes: int


@dataclass(frozen=True)
class _Metadata:
    video_stream_index: int
    audio_stream_index: int | None
    codec_name: str
    audio_codec_name: str | None
    format_name: str
    width: int
    height: int
    duration_ms: int | None


def _policy(expected_media_type: str) -> _FormatPolicy:
    if not isinstance(expected_media_type, str):
        raise ValueError("expected_media_type must be a supported MIME string")
    policy = _FORMATS.get(expected_media_type.strip().lower())
    if policy is None:
        raise ValueError("expected_media_type is not supported by the trusted probe")
    return policy


def _bounded_input_limit(policy: _FormatPolicy, requested: int | None) -> int:
    if requested is None:
        return policy.hard_input_limit
    if isinstance(requested, bool) or not isinstance(requested, int) or requested <= 0:
        raise ValueError("max_input_bytes must be a positive integer")
    return min(requested, policy.hard_input_limit)


def _positive_timeout(timeout_seconds: float) -> float:
    value = float(timeout_seconds)
    if not math.isfinite(value) or value <= 0 or value > MAX_TIMEOUT_SECONDS:
        raise ValueError("probe timeout is outside the safe range")
    return value


def _new_deadline(timeout_seconds: float) -> float:
    return _CLOCK() + _positive_timeout(timeout_seconds)


def _remaining_seconds(deadline: float) -> float:
    remaining = float(deadline) - _CLOCK()
    if not math.isfinite(remaining) or remaining <= 0:
        raise TrustedMediaProbeTimeout(
            "trusted media verification exceeded its total hard timeout"
        )
    return remaining


@contextmanager
def _probe_slot() -> Iterator[None]:
    if not _PROBE_SLOTS.acquire(blocking=False):
        raise TrustedMediaProbeBusy("trusted media decoder capacity is busy")
    try:
        yield
    finally:
        _PROBE_SLOTS.release()


def _bounded_arguments(args: Sequence[str | os.PathLike[str]]) -> list[str]:
    if len(args) > _MAX_ARGUMENTS:
        raise ValueError("trusted media command exceeds its argument-count bound")
    rendered: list[str] = []
    for raw in args:
        value = os.fspath(raw)
        if not isinstance(value, str):
            value = os.fsdecode(value)
        if not value or "\x00" in value or len(value.encode("utf-8")) > _MAX_ARGUMENT_BYTES:
            raise ValueError("trusted media command contains an invalid argument")
        rendered.append(value)
    return rendered


def _kill_process(process: subprocess.Popen[bytes]) -> None:
    try:
        process.kill()
    except (OSError, ProcessLookupError):
        pass


def _drain_bounded_stream(
    stream: BinaryIO,
    target: bytearray,
    *,
    state: dict[str, int],
    lock: threading.Lock,
    overflow: threading.Event,
    process: subprocess.Popen[bytes],
    output_limit_bytes: int,
    failures: list[BaseException],
) -> None:
    try:
        while True:
            chunk = stream.read(_READ_CHUNK_BYTES)
            if not chunk:
                return
            with lock:
                remaining = output_limit_bytes - state["total"]
                if remaining > 0:
                    target.extend(chunk[:remaining])
                state["total"] += len(chunk)
                exceeded = state["total"] > output_limit_bytes
            if exceeded:
                overflow.set()
                _kill_process(process)
                return
    except BaseException as exc:  # noqa: BLE001 - reader failure must close the gate
        failures.append(exc)
        _kill_process(process)


def _pump_pinned_input(
    source: BinaryIO,
    target: BinaryIO,
    *,
    expected_size: int,
    deadline: float,
    process: subprocess.Popen[bytes],
    timed_out: threading.Event,
    failures: list[BaseException],
) -> None:
    total = 0
    try:
        while total < expected_size:
            if _CLOCK() >= deadline:
                timed_out.set()
                _kill_process(process)
                return
            chunk = source.read(min(_READ_CHUNK_BYTES, expected_size - total))
            if not chunk:
                raise OSError("pinned media input ended before its receipt length")
            target.write(chunk)
            total += len(chunk)
        # The staged handle was already sized and hashed, but ensure this
        # particular rewind did not expose an unexpected extra byte.
        if source.read(1):
            raise OSError("pinned media input exceeded its receipt length")
    except (BrokenPipeError, ConnectionResetError):
        # Metadata probes may intentionally stop reading once the selected
        # stream is known.  The immutable handle is rewound for the decoder.
        return
    except OSError as exc:
        if getattr(exc, "winerror", None) in {109, 232}:
            return
        failures.append(exc)
        _kill_process(process)
    except BaseException as exc:  # noqa: BLE001 - input failure closes the gate
        failures.append(exc)
        _kill_process(process)
    finally:
        try:
            target.close()
        except OSError:
            pass


def _run_attested_command(
    tool: str,
    args: Sequence[str | os.PathLike[str]],
    *,
    timeout_seconds: float,
    output_limit_bytes: int = MAX_PROCESS_OUTPUT_BYTES,
    input_handle: BinaryIO | None = None,
    input_size: int | None = None,
    absolute_deadline: float | None = None,
    scratch_parent: Path | None = None,
    scratch_owner: TrustedMediaScratchOwner | None = None,
) -> _BoundedProcessResult:
    # Acquiring the executable pin includes hashing the binary.  It belongs to
    # the caller's one total budget too; never grant a fresh command timeout
    # after that work completes.
    if absolute_deadline is not None:
        _remaining_seconds(float(absolute_deadline))
    with pin_media_binary(tool) as attested:
        effective_timeout = _positive_timeout(timeout_seconds)
        if absolute_deadline is not None:
            effective_timeout = min(
                effective_timeout,
                _remaining_seconds(float(absolute_deadline)),
            )
        pinned_kwargs = {
            "timeout_seconds": effective_timeout,
            "output_limit_bytes": output_limit_bytes,
            "input_handle": input_handle,
            "input_size": input_size,
            "absolute_deadline": absolute_deadline,
        }
        if scratch_parent is None:
            if scratch_owner is not None:
                raise ValueError("trusted media scratch owner requires a scratch parent")
            return _run_pinned_command(
                attested,
                tool,
                args,
                **pinned_kwargs,
            )
        scratch_deadline = (
            float(absolute_deadline)
            if absolute_deadline is not None
            else _CLOCK() + effective_timeout
        )
        with _private_process_scratch_directory(
            Path(scratch_parent),
            deadline=scratch_deadline,
            scratch_owner=scratch_owner,
        ) as scratch_directory:
            return _run_pinned_command(
                attested,
                tool,
                args,
                scratch_directory=scratch_directory,
                **pinned_kwargs,
            )


def _run_pinned_command(
    attested: object,
    tool: str,
    args: Sequence[str | os.PathLike[str]],
    *,
    timeout_seconds: float,
    output_limit_bytes: int = MAX_PROCESS_OUTPUT_BYTES,
    input_handle: BinaryIO | None = None,
    input_size: int | None = None,
    absolute_deadline: float | None = None,
    scratch_directory: Path | None = None,
) -> _BoundedProcessResult:
    """Re-attest and run one fixed media command with bounded pipe draining."""

    timeout = _positive_timeout(timeout_seconds)
    if (
        isinstance(output_limit_bytes, bool)
        or not isinstance(output_limit_bytes, int)
        or output_limit_bytes <= 0
        or output_limit_bytes > _MIB
    ):
        raise ValueError("process output limit is outside the safe range")
    local_deadline = _CLOCK() + timeout
    command_deadline = (
        min(local_deadline, float(absolute_deadline))
        if absolute_deadline is not None
        else local_deadline
    )
    _remaining_seconds(command_deadline)
    path = str(getattr(attested, "path", "") or "")
    digest = str(getattr(attested, "sha256", "") or "")
    if not Path(path).is_absolute() or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise TrustedMediaProbeUnavailable(
            "trusted media verifier pin did not return an attested executable"
        )
    command = [path, *_bounded_arguments(args)]
    if input_handle is None:
        if input_size is not None:
            raise ValueError("input_size requires a pinned input handle")
    elif (
        isinstance(input_size, bool)
        or not isinstance(input_size, int)
        or input_size <= 0
        or input_size > MAX_VIDEO_INPUT_BYTES
    ):
        raise ValueError("pinned input size is outside the safe range")
    if input_handle is not None:
        try:
            input_handle.seek(0)
        except (OSError, ValueError) as exc:
            raise TrustedMediaProbeUnavailable(
                "trusted media pinned input could not be rewound"
            ) from exc
    environment = minimal_media_env()
    process_cwd: str | None = None
    if scratch_directory is not None:
        scratch = _require_private_directory(
            Path(scratch_directory),
            error_message="trusted media verifier scratch directory is not private",
        )
        scratch_text = str(scratch)
        for name in tuple(environment):
            if str(name).upper() in {"TEMP", "TMP", "TMPDIR"}:
                del environment[name]
        # FFmpeg's cache protocol uses a native temporary file.  Keep paid
        # bytes out of the user's/global temp and inside the per-command
        # restricted directory that the caller removes after the child exits.
        environment["TEMP"] = scratch_text
        environment["TMP"] = scratch_text
        environment["TMPDIR"] = scratch_text
        process_cwd = scratch_text
    kwargs: dict[str, object] = {
        "stdin": subprocess.PIPE if input_handle is not None else subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "env": environment,
        "shell": False,
        "close_fds": True,
    }
    if process_cwd is not None:
        kwargs["cwd"] = process_cwd
    if os.name == "nt":
        kwargs["creationflags"] = int(getattr(subprocess, "CREATE_NO_WINDOW", 0))
    try:
        process = subprocess.Popen(command, **kwargs)  # type: ignore[arg-type]
    except OSError as exc:
        raise MediaBinaryUnavailable(
            f"{str(tool).strip().lower()} attested verifier failed to launch"
        ) from exc
    if process.stdout is None or process.stderr is None:
        _kill_process(process)
        raise TrustedMediaProbeUnavailable("trusted media verifier pipes are unavailable")

    stdout = bytearray()
    stderr = bytearray()
    state = {"total": 0}
    lock = threading.Lock()
    overflow = threading.Event()
    failures: list[BaseException] = []
    input_failures: list[BaseException] = []
    input_timed_out = threading.Event()
    readers = [
        threading.Thread(
            target=_drain_bounded_stream,
            args=(process.stdout, stdout),
            kwargs={
                "state": state,
                "lock": lock,
                "overflow": overflow,
                "process": process,
                "output_limit_bytes": output_limit_bytes,
                "failures": failures,
            },
            name=f"nachuan-{tool}-stdout",
            daemon=True,
        ),
        threading.Thread(
            target=_drain_bounded_stream,
            args=(process.stderr, stderr),
            kwargs={
                "state": state,
                "lock": lock,
                "overflow": overflow,
                "process": process,
                "output_limit_bytes": output_limit_bytes,
                "failures": failures,
            },
            name=f"nachuan-{tool}-stderr",
            daemon=True,
        ),
    ]
    for reader in readers:
        reader.start()
    input_thread: threading.Thread | None = None
    if input_handle is not None:
        if process.stdin is None:
            _kill_process(process)
            raise TrustedMediaProbeUnavailable(
                "trusted media verifier input pipe is unavailable"
            )
        input_thread = threading.Thread(
            target=_pump_pinned_input,
            args=(input_handle, process.stdin),
            kwargs={
                "expected_size": int(input_size),
                "deadline": command_deadline,
                "process": process,
                "timed_out": input_timed_out,
                "failures": input_failures,
            },
            name=f"nachuan-{tool}-input",
            daemon=True,
        )
        input_thread.start()
    timed_out = False
    try:
        try:
            try:
                wait_timeout = _remaining_seconds(command_deadline)
            except TrustedMediaProbeTimeout:
                raise subprocess.TimeoutExpired(command, 0.0) from None
            returncode = int(process.wait(timeout=wait_timeout))
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_process(process)
            try:
                returncode = int(process.wait(timeout=5.0))
            except (subprocess.TimeoutExpired, OSError) as exc:
                raise TrustedMediaProbeUnavailable(
                    "timed-out trusted media verifier could not be reaped"
                ) from exc
        for reader in readers:
            reader.join(timeout=2.0)
        if input_thread is not None:
            input_thread.join(timeout=2.0)
        if any(reader.is_alive() for reader in readers):
            _kill_process(process)
            raise TrustedMediaProbeUnavailable(
                "trusted media verifier output could not be drained"
            )
        if input_thread is not None and input_thread.is_alive():
            _kill_process(process)
            raise TrustedMediaProbeUnavailable(
                "trusted media verifier input could not be drained"
            )
    finally:
        for stream in (process.stdout, process.stderr):
            try:
                stream.close()
            except OSError:
                pass
    if timed_out or input_timed_out.is_set():
        raise TrustedMediaProbeTimeout("trusted media verifier exceeded its hard timeout")
    if input_failures:
        raise TrustedMediaProbeUnavailable(
            "trusted media pinned input could not be streamed safely"
        ) from input_failures[0]
    if failures:
        raise TrustedMediaProbeUnavailable(
            "trusted media verifier output could not be read safely"
        ) from failures[0]
    if overflow.is_set():
        raise TrustedMediaRejected("trusted media verifier exceeded its output budget")
    return _BoundedProcessResult(
        returncode,
        bytes(stdout),
        bytes(stderr),
        attested_sha256=digest,
    )


def preflight_trusted_media_probe(
    *, timeout_seconds: float = 3.0
) -> TrustedMediaProbeReadiness:
    """Launch both attested tools without media before any paid outbound call."""

    deadline = _new_deadline(timeout_seconds)
    digests: dict[str, str] = {}
    with _probe_slot():
        for tool in ("ffprobe", "ffmpeg"):
            result = _run_attested_command(
                tool,
                ["-hide_banner", "-version"],
                timeout_seconds=_remaining_seconds(deadline),
                output_limit_bytes=MAX_PROCESS_OUTPUT_BYTES,
                absolute_deadline=deadline,
            )
            _remaining_seconds(deadline)
            expected_prefix = f"{tool} version ".encode("ascii")
            if result.returncode != 0 or not result.stdout.startswith(expected_prefix):
                raise TrustedMediaProbeUnavailable(
                    f"attested {tool} readiness check failed"
                )
            if not re.fullmatch(r"[0-9a-f]{64}", result.attested_sha256):
                raise TrustedMediaProbeUnavailable(
                    f"attested {tool} readiness digest is unavailable"
                )
            digests[tool] = result.attested_sha256
    return TrustedMediaProbeReadiness(
        ffmpeg_sha256=digests["ffmpeg"],
        ffprobe_sha256=digests["ffprobe"],
    )


def _path_has_redirect(path: Path) -> bool:
    try:
        for component in reversed((path, *path.parents)):
            info = os.lstat(component)
            attributes = int(getattr(info, "st_file_attributes", 0))
            if component.is_symlink() or attributes & int(
                getattr(stat_module, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            ):
                return True
        return False
    except OSError:
        return True


def _file_identity(path: Path) -> _FileIdentity:
    if not path.is_absolute() or _path_has_redirect(path):
        raise TrustedMediaRejected("trusted media input path is not a regular local file")
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise TrustedMediaRejected("trusted media input file is unavailable") from exc
    attributes = int(getattr(info, "st_file_attributes", 0))
    if (
        not stat_module.S_ISREG(info.st_mode)
        or attributes
        & int(getattr(stat_module, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
        or int(getattr(info, "st_nlink", 1)) != 1
    ):
        raise TrustedMediaRejected("trusted media input path is not a regular local file")
    return _identity_from_stat(info)


def _identity_from_stat(info: os.stat_result) -> _FileIdentity:
    attributes = int(getattr(info, "st_file_attributes", 0))
    return _FileIdentity(
        device=int(getattr(info, "st_dev", 0)),
        inode=int(getattr(info, "st_ino", 0)),
        mode=int(info.st_mode),
        links=int(getattr(info, "st_nlink", 1)),
        size=int(info.st_size),
        modified_ns=int(getattr(info, "st_mtime_ns", int(info.st_mtime * 1_000_000_000))),
        changed_ns=int(getattr(info, "st_ctime_ns", int(info.st_ctime * 1_000_000_000))),
        birth_ns=int(getattr(info, "st_birthtime_ns", 0)),
        attributes=attributes,
    )


def _require_same_identity(path: Path, expected: _FileIdentity) -> None:
    if not _same_file_identity(_file_identity(path), expected):
        raise TrustedMediaRejected("trusted media input changed during verification")


def _same_file_identity(current: _FileIdentity, expected: _FileIdentity) -> bool:
    # Windows may advance ctime when a protected file is reopened even though
    # its file-id, birth time and content metadata are unchanged.  Do not use
    # that unstable field as the sole identity signal.
    return (
        current.device == expected.device
        and current.inode == expected.inode
        and current.mode == expected.mode
        and current.links == expected.links
        and current.size == expected.size
        and current.modified_ns == expected.modified_ns
        and current.birth_ns == expected.birth_ns
        and current.attributes == expected.attributes
    )


def _hash_pinned_handle(
    handle: BinaryIO,
    *,
    maximum: int,
    expected_size: int,
    deadline: float,
) -> str:
    digest = hashlib.sha256()
    total = 0
    try:
        handle.seek(0)
        while True:
            _remaining_seconds(deadline)
            chunk = handle.read(_HASH_CHUNK_BYTES)
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise TrustedMediaTooLarge("trusted media input exceeds its byte cap")
            digest.update(chunk)
    except TrustedMediaProbeError:
        raise
    except OSError as exc:
        raise TrustedMediaRejected("trusted media input could not be read") from exc
    if total <= 0 or total != expected_size:
        raise TrustedMediaRejected("trusted media input changed while hashing")
    _remaining_seconds(deadline)
    return digest.hexdigest()


def _check_expected_digest(expected_sha256: str | None, actual: str) -> None:
    if expected_sha256 is None:
        return
    candidate = str(expected_sha256).strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", candidate):
        raise ValueError("expected_sha256 must be a 64-character lowercase digest")
    if not hmac.compare_digest(candidate, actual):
        raise TrustedMediaRejected("trusted media input digest does not match its receipt")


def _sniff_declared_format(
    handle: BinaryIO,
    policy: _FormatPolicy,
    size: int,
    *,
    deadline: float,
) -> None:
    _remaining_seconds(deadline)
    try:
        handle.seek(0)
        head = handle.read(min(size, 64 * 1024))
        tail = b""
        if size >= 2:
            handle.seek(size - 2)
            tail = handle.read(2)
    except OSError as exc:
        raise TrustedMediaRejected("trusted media input could not be inspected") from exc
    valid = False
    if policy.media_type == "image/png":
        valid = head.startswith(b"\x89PNG\r\n\x1a\n")
    elif policy.media_type == "image/jpeg":
        valid = head.startswith(b"\xff\xd8\xff") and tail == b"\xff\xd9"
    elif policy.media_type == "image/gif":
        valid = head.startswith((b"GIF87a", b"GIF89a")) and tail.endswith(b";")
    elif policy.media_type == "image/webp":
        valid = (
            len(head) >= 12
            and head[:4] == b"RIFF"
            and head[8:12] == b"WEBP"
            and int.from_bytes(head[4:8], "little") + 8 == size
        )
    elif policy.media_type == "video/mp4":
        valid = len(head) >= 16 and head[4:8] == b"ftyp"
    elif policy.media_type == "video/webm":
        valid = head.startswith(b"\x1a\x45\xdf\xa3") and b"webm" in head
    if not valid:
        raise TrustedMediaRejected("trusted media bytes do not match the declared MIME type")
    _remaining_seconds(deadline)


def _parse_decimal_seconds(raw: object) -> Decimal | None:
    if not isinstance(raw, str) or not raw or len(raw) > 64:
        return None
    try:
        value = Decimal(raw)
    except InvalidOperation:
        return None
    if not value.is_finite():
        return None
    return value


def _parse_probe_metadata(
    raw: bytes,
    *,
    policy: _FormatPolicy,
    byte_length: int,
) -> _Metadata:
    try:
        document = json.loads(raw.decode("utf-8", "strict"))
    except (UnicodeError, ValueError) as exc:
        raise TrustedMediaRejected("trusted media metadata is invalid") from exc
    if not isinstance(document, dict):
        raise TrustedMediaRejected("trusted media metadata is invalid")
    streams = document.get("streams")
    format_info = document.get("format")
    if (
        not isinstance(streams, list)
        or not streams
        or len(streams) > 2
        or not isinstance(format_info, dict)
        or any(not isinstance(stream, dict) for stream in streams)
    ):
        raise TrustedMediaRejected("trusted media stream set is outside the closed policy")
    video_streams: list[dict[str, object]] = []
    audio_streams: list[dict[str, object]] = []
    stream_indexes: set[int] = set()
    for candidate in streams:
        stream_index = candidate.get("index")
        codec_type = candidate.get("codec_type")
        codec = candidate.get("codec_name")
        disposition = candidate.get("disposition")
        attached_pic = disposition.get("attached_pic") if isinstance(disposition, dict) else 0
        if (
            isinstance(stream_index, bool)
            or not isinstance(stream_index, int)
            or stream_index < 0
            or stream_index in stream_indexes
            or codec_type not in {"video", "audio"}
            or not isinstance(codec, str)
            or not re.fullmatch(r"[a-z0-9_.-]{1,64}", codec)
            or attached_pic not in {0, None}
        ):
            raise TrustedMediaRejected("trusted media stream set is outside the closed policy")
        stream_indexes.add(stream_index)
        if codec_type == "video":
            video_streams.append(candidate)
        else:
            audio_streams.append(candidate)
    if len(video_streams) != 1:
        raise TrustedMediaRejected("trusted media must contain exactly one video stream")
    if policy.kind == "image" and (audio_streams or len(streams) != 1):
        raise TrustedMediaRejected("trusted media image contains an unexpected stream")
    if policy.kind == "video" and len(audio_streams) > 1:
        raise TrustedMediaRejected("trusted media video contains too many audio streams")

    stream = video_streams[0]
    stream_index = int(stream["index"])
    codec_name = stream.get("codec_name")
    format_name = format_info.get("format_name")
    width = stream.get("width")
    height = stream.get("height")
    if (
        not isinstance(format_name, str)
        or len(format_name) > 128
        or isinstance(width, bool)
        or isinstance(height, bool)
        or not isinstance(width, int)
        or not isinstance(height, int)
    ):
        raise TrustedMediaRejected("trusted media metadata fields are invalid")
    format_names = frozenset(format_name.split(","))
    if policy.required_format_name not in format_names:
        raise TrustedMediaRejected("trusted media demuxer does not match the declared MIME type")
    if codec_name not in policy.video_codecs:
        raise TrustedMediaRejected("trusted media codec does not match the declared MIME type")
    audio_stream_index: int | None = None
    audio_codec_name: str | None = None
    if audio_streams:
        audio_stream = audio_streams[0]
        audio_stream_index = int(audio_stream["index"])
        audio_codec_name = str(audio_stream["codec_name"])
        if audio_codec_name not in policy.audio_codecs:
            raise TrustedMediaRejected(
                "trusted media audio codec does not match the declared MIME type"
            )
    if (
        width <= 0
        or height <= 0
        or width > MAX_MEDIA_DIMENSION
        or height > MAX_MEDIA_DIMENSION
        or width * height > MAX_MEDIA_PIXELS
    ):
        raise TrustedMediaRejected("trusted media dimensions exceed the decode budget")
    raw_size = format_info.get("size")
    # pipe:0 is intentionally non-seekable and ffprobe may omit format.size.
    # The caller already binds the pinned handle using fstat + SHA-256; if the
    # demuxer does report a size it is additional evidence and must agree.
    if raw_size is not None:
        if (
            not isinstance(raw_size, str)
            or not raw_size.isascii()
            or not raw_size.isdecimal()
            or int(raw_size) != byte_length
        ):
            raise TrustedMediaRejected("trusted media byte length metadata does not match")

    duration_ms: int | None = None
    if policy.kind == "video":
        duration = _parse_decimal_seconds(format_info.get("duration"))
        if duration is None:
            duration = _parse_decimal_seconds(stream.get("duration"))
        if duration is None or duration <= 0 or duration > MAX_VIDEO_DURATION_SECONDS:
            raise TrustedMediaRejected("trusted media video duration is invalid")
        duration_ms = int(duration * 1000)
        if duration_ms <= 0:
            raise TrustedMediaRejected("trusted media video duration is zero")
    return _Metadata(
        stream_index,
        audio_stream_index,
        codec_name,
        audio_codec_name,
        format_name,
        width,
        height,
        duration_ms,
    )


def _parse_decoded_frames(raw: bytes) -> int:
    try:
        text = raw.decode("ascii", "strict")
    except UnicodeError as exc:
        raise TrustedMediaRejected("trusted media decode receipt is invalid") from exc
    final_frame: int | None = None
    saw_end = False
    for line in text.splitlines():
        if not line or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key == "frame":
            if not value.isdecimal():
                raise TrustedMediaRejected("trusted media decode frame receipt is invalid")
            final_frame = int(value)
            if final_frame > MAX_DECODED_FRAMES:
                raise TrustedMediaRejected("trusted media decoded frame count exceeds its budget")
        elif key == "progress" and value == "end":
            saw_end = True
    if not saw_end:
        raise TrustedMediaRejected("trusted media decode did not reach end-of-input")
    if final_frame is None or final_frame <= 0:
        raise TrustedMediaRejected("trusted media decode produced zero decoded frames")
    return final_frame


def _require_private_directory(path: Path, *, error_message: str) -> Path:
    """Return one existing, non-redirected directory owned by this process."""

    candidate = Path(path)
    try:
        if not candidate.is_absolute() or _path_has_redirect(candidate):
            raise OSError("private directory path is redirected")
        resolved = candidate.resolve(strict=True)
        info = os.lstat(resolved)
        if not stat_module.S_ISDIR(info.st_mode):
            raise OSError("private directory path is not a directory")
        if os.name == "nt":
            assert_restricted_windows_acl(resolved)
        else:
            current_uid = int(os.getuid()) if hasattr(os, "getuid") else None
            if current_uid is not None and int(info.st_uid) != current_uid:
                raise OSError("private directory has another owner")
            if stat_module.S_IMODE(info.st_mode) & 0o077:
                raise OSError("private directory permissions are too broad")
        return resolved
    except (OSError, SecureStorageError) as exc:
        raise TrustedMediaProbeUnavailable(error_message) from exc


@contextmanager
def _private_process_scratch_directory(
    parent: Path,
    *,
    deadline: float,
    scratch_owner: TrustedMediaScratchOwner | None = None,
) -> Iterator[Path]:
    """Create and always remove one restricted FFmpeg cache directory."""

    _remaining_seconds(deadline)
    private_parent = _require_private_directory(
        Path(parent),
        error_message="trusted media verifier scratch parent is not private",
    )
    try:
        with tempfile.TemporaryDirectory(
            prefix="nachuan-media-cache-",
            dir=private_parent,
        ) as raw_directory:
            directory = Path(raw_directory).resolve(strict=True)
            if directory.parent != private_parent or _path_has_redirect(directory):
                raise OSError("trusted media verifier scratch path escaped its parent")
            if os.name == "nt":
                harden_restricted_windows_acl(directory, directory=True)
            else:
                os.chmod(directory, 0o700)
            _require_private_directory(
                directory,
                error_message="trusted media verifier scratch directory is not private",
            )
            if scratch_owner is not None:
                marker = directory / TRUSTED_MEDIA_CACHE_MARKER_NAME
                with marker.open("xb") as handle:
                    handle.write(_scratch_owner_marker_bytes(scratch_owner))
                    handle.flush()
                    os.fsync(handle.fileno())
                _harden_staged_file(marker, deadline=deadline)
                _assert_private_staged_path(marker, deadline=deadline)
            _remaining_seconds(deadline)
            yield directory
            _remaining_seconds(deadline)
    except TrustedMediaProbeError:
        raise
    except (OSError, SecureStorageError) as exc:
        raise TrustedMediaProbeUnavailable(
            "trusted media verifier scratch directory could not be secured or removed"
        ) from exc


@contextmanager
def _private_temp_directory(*, deadline: float) -> Iterator[Path]:
    """Create a random staging directory and close inherited write access."""

    _remaining_seconds(deadline)
    with tempfile.TemporaryDirectory(prefix="nachuan-media-probe-") as raw_directory:
        directory = Path(raw_directory).resolve(strict=True)
        try:
            if os.name == "nt":
                harden_restricted_windows_acl(directory, directory=True)
            else:
                os.chmod(directory, 0o700)
                mode = stat_module.S_IMODE(os.lstat(directory).st_mode)
                if mode & 0o077:
                    raise OSError("private staging directory permissions are too broad")
        except (OSError, SecureStorageError) as exc:
            raise TrustedMediaProbeUnavailable(
                "trusted media staging ACL could not be restricted"
            ) from exc
        _remaining_seconds(deadline)
        yield directory


def _harden_staged_file(path: Path, *, deadline: float) -> None:
    try:
        if os.name == "nt":
            harden_restricted_windows_acl(path, directory=False)
        else:
            os.chmod(path, 0o600)
            mode = stat_module.S_IMODE(os.lstat(path).st_mode)
            if mode & 0o077:
                raise OSError("private staging file permissions are too broad")
    except (OSError, SecureStorageError) as exc:
        raise TrustedMediaProbeUnavailable(
            "trusted media staging file ACL could not be restricted"
        ) from exc
    _remaining_seconds(deadline)


def _assert_private_staged_path(path: Path, *, deadline: float) -> None:
    """Verify, without widening it, the caller-owned private spool boundary."""

    _remaining_seconds(deadline)
    try:
        if os.name == "nt":
            # The directory prevents an untrusted principal from swapping the
            # pathname before the deny-delete file handle is acquired; the
            # file ACL independently prevents reads/writes of paid bytes.
            assert_restricted_windows_acl(path.parent)
            _remaining_seconds(deadline)
            assert_restricted_windows_acl(path)
        else:
            current_uid = int(os.getuid()) if hasattr(os, "getuid") else None
            for target, expected_directory in ((path.parent, True), (path, False)):
                info = os.lstat(target)
                if expected_directory != stat_module.S_ISDIR(info.st_mode):
                    raise OSError("private spool path type is invalid")
                if current_uid is not None and int(info.st_uid) != current_uid:
                    raise OSError("private spool path has another owner")
                if stat_module.S_IMODE(info.st_mode) & 0o077:
                    raise OSError("private spool permissions are too broad")
    except (OSError, SecureStorageError) as exc:
        raise TrustedMediaProbeUnavailable(
            "trusted media staged input is not in a private spool"
        ) from exc
    _remaining_seconds(deadline)


@contextmanager
def _pin_staged_file(path: Path, *, expected: _FileIdentity) -> Iterator[BinaryIO]:
    """Deny post-attestation writes/replaces while decoder processes reopen the path.

    Windows sharing rules provide the useful production guarantee: the held
    read handle permits additional readers but denies new write/delete handles.
    POSIX relies on the private 0700 staging directory and the before/after
    inode+digest checks because pathname replacement cannot be denied portably.
    """

    if os.name == "nt":
        import ctypes
        import msvcrt
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateFileW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ]
        kernel32.CreateFileW.restype = wintypes.HANDLE
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        handle = kernel32.CreateFileW(
            str(path),
            0x80000000,  # GENERIC_READ
            0x00000001,  # FILE_SHARE_READ: deny new write/delete handles
            None,
            3,  # OPEN_EXISTING
            0x00200000 | 0x08000000,  # OPEN_REPARSE_POINT | SEQUENTIAL_SCAN
            None,
        )
        invalid_handle = ctypes.c_void_p(-1).value
        if handle in (None, 0, invalid_handle):
            raise TrustedMediaProbeUnavailable(
                "trusted media staging file could not be pinned"
            ) from ctypes.WinError(ctypes.get_last_error())
        descriptor: int | None = None
        pinned: BinaryIO | None = None
        try:
            descriptor = msvcrt.open_osfhandle(
                int(handle), int(os.O_RDONLY | getattr(os, "O_BINARY", 0))
            )
            # open_osfhandle transferred ownership to the descriptor.
            handle = None
            pinned = os.fdopen(descriptor, "rb", buffering=0)
            descriptor = None
            if not _same_file_identity(
                _identity_from_stat(os.fstat(pinned.fileno())), expected
            ):
                raise TrustedMediaRejected(
                    "trusted media staging handle identity does not match"
                )
            _require_same_identity(path, expected)
            yield pinned
            _require_same_identity(path, expected)
        finally:
            if pinned is not None:
                pinned.close()
            elif descriptor is not None:
                os.close(descriptor)
            elif handle not in (None, 0, invalid_handle):
                kernel32.CloseHandle(handle)
        return

    flags = os.O_RDONLY | int(getattr(os, "O_NOFOLLOW", 0))
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise TrustedMediaProbeUnavailable(
            "trusted media staging file could not be pinned"
        ) from exc
    try:
        pinned = os.fdopen(descriptor, "rb", buffering=0)
        descriptor = -1
        if not _same_file_identity(
            _identity_from_stat(os.fstat(pinned.fileno())), expected
        ):
            raise TrustedMediaRejected("trusted media staging handle identity does not match")
        _require_same_identity(path, expected)
        yield pinned
        _require_same_identity(path, expected)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        else:
            pinned.close()


def _copy_source_to_stage(
    source: Path,
    destination: Path,
    *,
    input_limit: int,
    deadline: float,
    expected_byte_length: int | None,
    expected_sha256: str | None,
) -> tuple[int, str]:
    source_identity = _file_identity(source)
    if source_identity.size <= 0:
        raise TrustedMediaRejected("trusted media input is empty")
    if source_identity.size > input_limit:
        raise TrustedMediaTooLarge("trusted media input exceeds its byte cap")
    if expected_byte_length is not None:
        if (
            isinstance(expected_byte_length, bool)
            or not isinstance(expected_byte_length, int)
            or expected_byte_length <= 0
        ):
            raise ValueError("expected_byte_length must be a positive integer")
        if expected_byte_length != source_identity.size:
            raise TrustedMediaRejected("trusted media byte length does not match its receipt")
    digest = hashlib.sha256()
    total = 0
    try:
        with source.open("rb") as input_handle, destination.open("xb") as output_handle:
            while True:
                _remaining_seconds(deadline)
                chunk = input_handle.read(_HASH_CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > input_limit:
                    raise TrustedMediaTooLarge("trusted media input exceeds its byte cap")
                output_handle.write(chunk)
                digest.update(chunk)
            output_handle.flush()
            os.fsync(output_handle.fileno())
    except TrustedMediaProbeError:
        raise
    except OSError as exc:
        raise TrustedMediaProbeUnavailable(
            "trusted media input could not be copied to private staging"
        ) from exc
    _require_same_identity(source, source_identity)
    if total <= 0 or total != source_identity.size:
        raise TrustedMediaRejected("trusted media input changed while staging")
    actual_digest = digest.hexdigest()
    _check_expected_digest(expected_sha256, actual_digest)
    _remaining_seconds(deadline)
    return total, actual_digest


def _probe_file_impl(
    path: Path,
    pinned: BinaryIO,
    *,
    policy: _FormatPolicy,
    input_limit: int,
    deadline: float,
    expected_byte_length: int | None,
    expected_sha256: str | None,
    scratch_owner: TrustedMediaScratchOwner | None = None,
) -> TrustedMediaProbeResult:
    identity = _file_identity(path)
    if identity.size <= 0:
        raise TrustedMediaRejected("trusted media input is empty")
    if identity.size > input_limit:
        raise TrustedMediaTooLarge("trusted media input exceeds its byte cap")
    if expected_byte_length is not None:
        if (
            isinstance(expected_byte_length, bool)
            or not isinstance(expected_byte_length, int)
            or expected_byte_length <= 0
        ):
            raise ValueError("expected_byte_length must be a positive integer")
        if expected_byte_length != identity.size:
            raise TrustedMediaRejected("trusted media byte length does not match its receipt")
    if not _same_file_identity(
        _identity_from_stat(os.fstat(pinned.fileno())), identity
    ):
        raise TrustedMediaRejected("trusted media pinned handle identity does not match")
    digest = _hash_pinned_handle(
        pinned,
        maximum=input_limit,
        expected_size=identity.size,
        deadline=deadline,
    )
    _require_same_identity(path, identity)
    _check_expected_digest(expected_sha256, digest)
    _sniff_declared_format(pinned, policy, identity.size, deadline=deadline)
    _require_same_identity(path, identity)

    seekable_mp4 = policy.media_type == "video/mp4"
    if scratch_owner is not None and not isinstance(
        scratch_owner, TrustedMediaScratchOwner
    ):
        raise ValueError("trusted media scratch owner is invalid")
    protocol_whitelist = "cache,pipe" if seekable_mp4 else "pipe"
    input_url = "cache:pipe:0" if seekable_mp4 else "pipe:0"
    scratch_parent = path.parent if seekable_mp4 else None
    common = [
        "-hide_banner",
        "-v",
        "error",
        "-max_alloc",
        "268435456",
        "-protocol_whitelist",
        protocol_whitelist,
        "-f",
        policy.demuxer,
    ]
    # MOV/MP4 data references can name another file.  Both options default to
    # disabled upstream, but pass the policy explicitly so a future default
    # cannot turn a paid-media probe into a local-file reader.  `cache:` must
    # also be allowed to read forward to an arbitrarily late `moov`; "unlimited"
    # remains bounded by the already-attested input_size and hard media cap.
    input_options = (
        [
            "-read_ahead_limit",
            "-1",
            "-enable_drefs",
            "0",
            "-use_absolute_path",
            "0",
        ]
        if seekable_mp4
        else []
    )
    metadata_result = _run_attested_command(
        "ffprobe",
        [
            *common,
            *input_options,
            "-show_entries",
            (
                "format=format_name,duration,size:"
                "stream=index,codec_type,codec_name,width,height,duration,nb_frames:"
                "stream_disposition=attached_pic"
            ),
            "-of",
            "json=c=1",
            input_url,
        ],
        timeout_seconds=_remaining_seconds(deadline),
        output_limit_bytes=MAX_PROCESS_OUTPUT_BYTES,
        input_handle=pinned,
        input_size=identity.size,
        absolute_deadline=deadline,
        scratch_parent=scratch_parent,
        scratch_owner=scratch_owner if seekable_mp4 else None,
    )
    _remaining_seconds(deadline)
    if metadata_result.returncode != 0:
        raise TrustedMediaRejected("trusted media metadata probe rejected the input")
    _require_same_identity(path, identity)
    metadata = _parse_probe_metadata(
        metadata_result.stdout,
        policy=policy,
        byte_length=identity.size,
    )

    stream_maps = ["-map", f"0:{metadata.video_stream_index}"]
    if metadata.audio_stream_index is not None:
        stream_maps.extend(["-map", f"0:{metadata.audio_stream_index}"])

    decode_result = _run_attested_command(
        "ffmpeg",
        [
            "-hide_banner",
            "-nostdin",
            "-v",
            "error",
            "-xerror",
            "-err_detect",
            "explode",
            "-max_error_rate",
            "0",
            "-max_alloc",
            "268435456",
            "-protocol_whitelist",
            protocol_whitelist,
            "-threads",
            "1",
            "-f",
            policy.demuxer,
            *input_options,
            "-i",
            input_url,
            *stream_maps,
            "-sn",
            "-dn",
            "-stats_period",
            "5",
            "-progress",
            "pipe:1",
            "-f",
            "null",
            "-",
        ],
        timeout_seconds=_remaining_seconds(deadline),
        output_limit_bytes=MAX_PROCESS_OUTPUT_BYTES,
        input_handle=pinned,
        input_size=identity.size,
        absolute_deadline=deadline,
        scratch_parent=scratch_parent,
        scratch_owner=scratch_owner if seekable_mp4 else None,
    )
    _remaining_seconds(deadline)
    if decode_result.returncode != 0:
        raise TrustedMediaRejected("trusted media failed full decode")
    _require_same_identity(path, identity)
    decoded_frames = _parse_decoded_frames(decode_result.stdout)
    final_digest = _hash_pinned_handle(
        pinned,
        maximum=input_limit,
        expected_size=identity.size,
        deadline=deadline,
    )
    _require_same_identity(path, identity)
    if not hmac.compare_digest(final_digest, digest):
        raise TrustedMediaRejected("trusted media input changed during verification")
    _check_expected_digest(expected_sha256, final_digest)
    if not re.fullmatch(r"[0-9a-f]{64}", metadata_result.attested_sha256) or not re.fullmatch(
        r"[0-9a-f]{64}", decode_result.attested_sha256
    ):
        raise TrustedMediaProbeUnavailable(
            "trusted media verifier attestation digest is unavailable"
        )
    return TrustedMediaProbeResult(
        media_type=policy.media_type,
        detected_kind=policy.kind,
        byte_length=identity.size,
        sha256=final_digest,
        codec_name=metadata.codec_name,
        audio_codec_name=metadata.audio_codec_name,
        video_stream_count=1,
        audio_stream_count=1 if metadata.audio_stream_index is not None else 0,
        format_name=metadata.format_name,
        width=metadata.width,
        height=metadata.height,
        duration_ms=metadata.duration_ms,
        decoded_frames=decoded_frames,
        ffmpeg_sha256=decode_result.attested_sha256,
        ffprobe_sha256=metadata_result.attested_sha256,
    )


def probe_trusted_media_file(
    path: str | os.PathLike[str],
    *,
    expected_media_type: str,
    timeout_seconds: float = 60.0,
    max_input_bytes: int | None = None,
    expected_byte_length: int | None = None,
    expected_sha256: str | None = None,
) -> TrustedMediaProbeResult:
    """Copy an external file once, then decode only one pinned private handle."""

    policy = _policy(expected_media_type)
    input_limit = _bounded_input_limit(policy, max_input_bytes)
    deadline = _new_deadline(timeout_seconds)
    candidate = Path(path)
    with _probe_slot():
        with _private_temp_directory(deadline=deadline) as directory:
            staged = directory / "candidate.media"
            staged_size, staged_digest = _copy_source_to_stage(
                candidate,
                staged,
                input_limit=input_limit,
                deadline=deadline,
                expected_byte_length=expected_byte_length,
                expected_sha256=expected_sha256,
            )
            _harden_staged_file(staged, deadline=deadline)
            staged = staged.resolve(strict=True)
            identity = _file_identity(staged)
            if identity.size != staged_size:
                raise TrustedMediaRejected("trusted media staging size changed")
            with _pin_staged_file(staged, expected=identity) as pinned:
                return _probe_file_impl(
                    staged,
                    pinned,
                    policy=policy,
                    input_limit=input_limit,
                    deadline=deadline,
                    expected_byte_length=staged_size,
                    expected_sha256=staged_digest,
                )


def probe_trusted_media_staged_file(
    path: str | os.PathLike[str],
    *,
    expected_media_type: str,
    expected_byte_length: int,
    expected_sha256: str,
    timeout_seconds: float = 60.0,
    max_input_bytes: int | None = None,
    scratch_owner: TrustedMediaScratchOwner | None = None,
) -> TrustedMediaProbeResult:
    """Fully decode one server-owned, private, fsynced spool without copying it.

    This is an internal adapter seam, not a client-path API.  The caller must
    create and close the file under a private directory, fsync it, and provide
    the receipt collected while streaming the raw request body.  This function
    independently enforces the exact receipt and private ACL, then decodes only
    one identity-pinned handle.
    """

    policy = _policy(expected_media_type)
    input_limit = _bounded_input_limit(policy, max_input_bytes)
    deadline = _new_deadline(timeout_seconds)
    if (
        isinstance(expected_byte_length, bool)
        or not isinstance(expected_byte_length, int)
        or expected_byte_length <= 0
    ):
        raise ValueError("expected_byte_length must be a positive integer")
    receipt_digest = str(expected_sha256).strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", receipt_digest):
        raise ValueError("expected_sha256 must be a 64-character lowercase digest")
    candidate = Path(path)
    with _probe_slot():
        identity = _file_identity(candidate)
        if identity.size != expected_byte_length:
            raise TrustedMediaRejected(
                "trusted media byte length does not match its receipt"
            )
        if identity.size > input_limit:
            raise TrustedMediaTooLarge("trusted media input exceeds its byte cap")
        _assert_private_staged_path(candidate, deadline=deadline)
        _require_same_identity(candidate, identity)
        with _pin_staged_file(candidate, expected=identity) as pinned:
            return _probe_file_impl(
                candidate,
                pinned,
                policy=policy,
                input_limit=input_limit,
                deadline=deadline,
                expected_byte_length=expected_byte_length,
                expected_sha256=receipt_digest,
                scratch_owner=scratch_owner,
            )


def probe_trusted_media_bytes(
    data: bytes | bytearray | memoryview,
    *,
    expected_media_type: str,
    timeout_seconds: float = 60.0,
    max_input_bytes: int | None = None,
    expected_sha256: str | None = None,
) -> TrustedMediaProbeResult:
    """Stage bounded bytes with fsync, fully decode them, and always clean up."""

    policy = _policy(expected_media_type)
    input_limit = _bounded_input_limit(policy, max_input_bytes)
    deadline = _new_deadline(timeout_seconds)
    try:
        view = memoryview(data)
    except TypeError as exc:
        raise ValueError("trusted media input must be bytes-like") from exc
    try:
        if view.ndim != 1 or not view.contiguous or view.itemsize != 1:
            raise ValueError("trusted media input must be one contiguous byte buffer")
        byte_length = view.nbytes
        if byte_length <= 0:
            raise TrustedMediaRejected("trusted media input is empty")
        if byte_length > input_limit:
            raise TrustedMediaTooLarge("trusted media input exceeds its byte cap")
        with _probe_slot():
            with _private_temp_directory(deadline=deadline) as directory:
                path = directory / "candidate.media"
                try:
                    digest = hashlib.sha256()
                    with path.open("xb") as handle:
                        offset = 0
                        while offset < byte_length:
                            _remaining_seconds(deadline)
                            end = min(byte_length, offset + _HASH_CHUNK_BYTES)
                            chunk = view[offset:end]
                            handle.write(chunk)
                            digest.update(chunk)
                            offset = end
                        handle.flush()
                        os.fsync(handle.fileno())
                    staged_digest = digest.hexdigest()
                    _check_expected_digest(expected_sha256, staged_digest)
                    _harden_staged_file(path, deadline=deadline)
                    path = path.resolve(strict=True)
                    identity = _file_identity(path)
                    if identity.size != byte_length:
                        raise TrustedMediaRejected("trusted media staging size changed")
                    with _pin_staged_file(path, expected=identity) as pinned:
                        return _probe_file_impl(
                            path,
                            pinned,
                            policy=policy,
                            input_limit=input_limit,
                            deadline=deadline,
                            expected_byte_length=byte_length,
                            expected_sha256=staged_digest,
                        )
                except TrustedMediaProbeError:
                    raise
                except OSError as exc:
                    raise TrustedMediaProbeUnavailable(
                        "trusted media input could not be staged safely"
                    ) from exc
    finally:
        view.release()


__all__ = [
    "MAX_IMAGE_INPUT_BYTES",
    "MAX_PROCESS_OUTPUT_BYTES",
    "MAX_VIDEO_INPUT_BYTES",
    "MediaBinaryUnavailable",
    "TRUSTED_MEDIA_CACHE_MARKER_NAME",
    "TRUSTED_MEDIA_CACHE_MARKER_SCHEMA",
    "VALIDATION_POLICY",
    "VALIDATOR_VERSION",
    "TrustedMediaProbeBusy",
    "TrustedMediaProbeError",
    "TrustedMediaProbeReadiness",
    "TrustedMediaProbeResult",
    "TrustedMediaProbeTimeout",
    "TrustedMediaProbeUnavailable",
    "TrustedMediaRejected",
    "TrustedMediaScratchOwner",
    "TrustedMediaTooLarge",
    "preflight_trusted_media_probe",
    "probe_trusted_media_bytes",
    "probe_trusted_media_file",
    "probe_trusted_media_staged_file",
]
