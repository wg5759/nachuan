"""Private raw-body adapter for the paid-media full-decode gate.

The caller sends bytes, never a host path.  The adapter writes those bytes to
an unguessable, access-restricted spool, binds the transport to an exact length
and SHA-256 receipt, fsyncs it, and only then invokes the attested decoder.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import re
import shutil
import tempfile
import threading
from pathlib import Path
from typing import Any

from fastapi import Request
from starlette.concurrency import run_in_threadpool
from starlette.requests import ClientDisconnect

from gateway.secure_store import (
    SecureStorageError,
    harden_restricted_windows_acl,
)
from gateway.trusted_media_probe import (
    MAX_IMAGE_INPUT_BYTES,
    MAX_VIDEO_INPUT_BYTES,
    TrustedMediaProbeResult,
    VALIDATION_POLICY,
    VALIDATOR_VERSION,
    preflight_trusted_media_probe,
    probe_trusted_media_staged_file,
)


EXPECTED_LENGTH_HEADER = "X-Nachuan-Media-Byte-Length"
EXPECTED_SHA256_HEADER = "X-Nachuan-Media-SHA256"
VALIDATION_SCHEMA = "nachuan.trusted-media-validation.v2"
SUPPORTED_MEDIA_LIMITS = {
    "image/png": MAX_IMAGE_INPUT_BYTES,
    "image/jpeg": MAX_IMAGE_INPUT_BYTES,
    "image/gif": MAX_IMAGE_INPUT_BYTES,
    "image/webp": MAX_IMAGE_INPUT_BYTES,
    "video/mp4": MAX_VIDEO_INPUT_BYTES,
    "video/webm": MAX_VIDEO_INPUT_BYTES,
}
MIN_SPOOL_FREE_FLOOR_BYTES = 256 * 1024 * 1024
_SPOOL_COPY_FACTOR = 1  # The probe decodes this exact private spool in place.
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_LENGTH_RE = re.compile(r"^[1-9][0-9]{0,9}$")
_SPOOL_COMPROMISED = threading.Event()
_SPOOL_UPLOAD_SLOTS = threading.BoundedSemaphore(2)
_SPOOL_CAPACITY_LOCK = threading.Lock()
_ACTIVE_SPOOL_RESERVATION_BYTES = 0


class TrustedMediaRequestError(RuntimeError):
    """Controlled client/transport error with a non-diagnostic public shape."""

    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        *,
        retryable: bool = False,
    ) -> None:
        super().__init__(message)
        self.status_code = int(status_code)
        self.code = str(code)
        self.public_message = str(message)
        self.retryable = bool(retryable)


def _raw_header_values(request: Request, name: str) -> list[str]:
    wanted = name.encode("ascii").lower()
    values: list[str] = []
    for raw_name, raw_value in request.scope.get("headers") or []:
        if bytes(raw_name).lower() == wanted:
            try:
                values.append(bytes(raw_value).decode("latin-1", "strict"))
            except UnicodeError as exc:
                raise TrustedMediaRequestError(
                    400,
                    "invalid_media_probe_headers",
                    "Trusted media probe headers are invalid.",
                ) from exc
    return values


def _exact_single_header(request: Request, name: str) -> str:
    values = _raw_header_values(request, name)
    if len(values) != 1:
        raise TrustedMediaRequestError(
            400,
            "invalid_media_probe_headers",
            "Trusted media probe headers are missing or duplicated.",
        )
    value = values[0].strip()
    if not value:
        raise TrustedMediaRequestError(
            400,
            "invalid_media_probe_headers",
            "Trusted media probe headers are invalid.",
        )
    return value


def _parse_upload_contract(request: Request) -> tuple[str, int, str, int]:
    raw_media_type = _exact_single_header(request, "content-type")
    # Parameters are unnecessary for these binary formats and make receipt
    # canonicalization ambiguous, so the wire contract is an exact MIME token.
    media_type = raw_media_type.casefold()
    limit = SUPPORTED_MEDIA_LIMITS.get(media_type)
    if limit is None or ";" in raw_media_type:
        raise TrustedMediaRequestError(
            415,
            "unsupported_media_probe_type",
            "Trusted media probe type is unsupported.",
        )

    raw_length = _exact_single_header(request, EXPECTED_LENGTH_HEADER)
    if not _LENGTH_RE.fullmatch(raw_length):
        raise TrustedMediaRequestError(
            400,
            "invalid_media_probe_length",
            "Trusted media probe byte length is invalid.",
        )
    expected_length = int(raw_length)
    if expected_length > limit:
        raise TrustedMediaRequestError(
            413,
            "media_probe_payload_too_large",
            "Trusted media probe payload exceeds its type-specific limit.",
        )

    expected_sha256 = _exact_single_header(request, EXPECTED_SHA256_HEADER).lower()
    if not _SHA256_RE.fullmatch(expected_sha256):
        raise TrustedMediaRequestError(
            400,
            "invalid_media_probe_digest",
            "Trusted media probe digest is invalid.",
        )

    content_lengths = _raw_header_values(request, "content-length")
    transfer_encodings = _raw_header_values(request, "transfer-encoding")
    if len(content_lengths) > 1 or len(transfer_encodings) > 1:
        raise TrustedMediaRequestError(
            400,
            "invalid_media_probe_headers",
            "Trusted media probe framing headers are duplicated.",
        )
    if content_lengths and transfer_encodings:
        raise TrustedMediaRequestError(
            400,
            "invalid_media_probe_headers",
            "Trusted media probe framing is ambiguous.",
        )
    if content_lengths:
        raw_transport_length = content_lengths[0].strip()
        if (
            not raw_transport_length.isascii()
            or not raw_transport_length.isdecimal()
            or int(raw_transport_length) != expected_length
        ):
            raise TrustedMediaRequestError(
                400,
                "media_probe_length_mismatch",
                "Trusted media probe transport length does not match its receipt.",
            )
    if transfer_encodings and transfer_encodings[0].strip().casefold() != "chunked":
        raise TrustedMediaRequestError(
            400,
            "invalid_media_probe_headers",
            "Trusted media probe transfer encoding is unsupported.",
        )
    encodings = _raw_header_values(request, "content-encoding")
    if len(encodings) > 1 or (
        encodings and encodings[0].strip().casefold() not in {"", "identity"}
    ):
        raise TrustedMediaRequestError(
            415,
            "unsupported_media_probe_encoding",
            "Trusted media probe content encoding is unsupported.",
        )
    return media_type, expected_length, expected_sha256, limit


def _harden_spool(path: Path, *, directory: bool) -> None:
    if os.name == "nt":
        harden_restricted_windows_acl(path, directory=directory)
    else:
        os.chmod(path, 0o700 if directory else 0o600)


def _acquire_spool_capacity(expected_length: int) -> int:
    """Bound pre-decode uploads and reserve their real same-volume peak."""

    global _ACTIVE_SPOOL_RESERVATION_BYTES
    if not _SPOOL_UPLOAD_SLOTS.acquire(blocking=False):
        raise TrustedMediaRequestError(
            429,
            "media_probe_upload_busy",
            "Trusted media probe upload capacity is busy.",
            retryable=True,
        )
    required = expected_length * _SPOOL_COPY_FACTOR
    try:
        try:
            free = int(shutil.disk_usage(tempfile.gettempdir()).free)
        except OSError as exc:
            raise TrustedMediaRequestError(
                503,
                "media_probe_storage_unavailable",
                "Trusted media probe storage capacity is unavailable.",
                retryable=True,
            ) from exc
        with _SPOOL_CAPACITY_LOCK:
            if (
                free - _ACTIVE_SPOOL_RESERVATION_BYTES
                < required + MIN_SPOOL_FREE_FLOOR_BYTES
            ):
                raise TrustedMediaRequestError(
                    507,
                    "media_probe_storage_insufficient",
                    "Trusted media probe has insufficient private staging capacity.",
                    retryable=True,
                )
            _ACTIVE_SPOOL_RESERVATION_BYTES += required
        return required
    except BaseException:
        _SPOOL_UPLOAD_SLOTS.release()
        raise


def _release_spool_capacity(reserved: int) -> None:
    global _ACTIVE_SPOOL_RESERVATION_BYTES
    with _SPOOL_CAPACITY_LOCK:
        if reserved <= 0 or reserved > _ACTIVE_SPOOL_RESERVATION_BYTES:
            _SPOOL_COMPROMISED.set()
            raise TrustedMediaRequestError(
                503,
                "media_probe_capacity_accounting_failed",
                "Trusted media probe capacity accounting failed.",
                retryable=False,
            )
        _ACTIVE_SPOOL_RESERVATION_BYTES -= reserved
    _SPOOL_UPLOAD_SLOTS.release()


def _make_private_spool() -> tuple[Path, Path, Any]:
    if _SPOOL_COMPROMISED.is_set():
        raise TrustedMediaRequestError(
            503,
            "media_probe_spool_compromised",
            "Trusted media probe staging is disabled until restart.",
            retryable=False,
        )
    try:
        directory = Path(tempfile.mkdtemp(prefix="nachuan-paid-media-probe-")).resolve(
            strict=True
        )
        _harden_spool(directory, directory=True)
        path = directory / "candidate.media"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        fd = os.open(path, flags, 0o600)
        try:
            _harden_spool(path, directory=False)
            handle = os.fdopen(fd, "wb", closefd=True)
        except BaseException:
            os.close(fd)
            raise
        return directory, path, handle
    except (OSError, SecureStorageError) as exc:
        candidate = locals().get("directory")
        if isinstance(candidate, Path):
            try:
                shutil.rmtree(candidate)
            except OSError:
                _SPOOL_COMPROMISED.set()
        raise TrustedMediaRequestError(
            503,
            "media_probe_spool_unavailable",
            "Trusted media probe staging is unavailable.",
            retryable=True,
        ) from exc


def _remove_private_spool(directory: Path) -> None:
    try:
        shutil.rmtree(directory)
    except OSError as exc:
        _SPOOL_COMPROMISED.set()
        raise TrustedMediaRequestError(
            503,
            "media_probe_spool_cleanup_failed",
            "Trusted media probe staging cleanup failed.",
            retryable=True,
        ) from exc


def _write_chunk(handle: Any, chunk: bytes) -> None:
    written = handle.write(chunk)
    if written != len(chunk):
        raise OSError("short trusted-media spool write")


def _flush_spool(handle: Any) -> None:
    handle.flush()
    os.fsync(handle.fileno())


def _required_digest(value: object, field: str) -> str:
    candidate = str(value or "").strip().lower()
    if not _SHA256_RE.fullmatch(candidate):
        raise TrustedMediaRequestError(
            503,
            "media_probe_receipt_unavailable",
            f"Trusted media probe {field} receipt is unavailable.",
            retryable=True,
        )
    return candidate


def _validation_receipt(result: TrustedMediaProbeResult) -> dict[str, Any]:
    if (
        result.schema != "nachuan.trusted-media-probe.result.v2"
        or getattr(result, "validator_version", None) != VALIDATOR_VERSION
        or getattr(result, "validation_policy", None) != VALIDATION_POLICY
        or not result.fully_decoded
    ):
        raise TrustedMediaRequestError(
            503,
            "media_probe_receipt_unavailable",
            "Trusted media probe returned an unsupported receipt.",
            retryable=True,
        )
    ffmpeg_sha256 = _required_digest(
        getattr(result, "ffmpeg_sha256", None), "ffmpeg"
    )
    ffprobe_sha256 = _required_digest(
        getattr(result, "ffprobe_sha256", None), "ffprobe"
    )
    base: dict[str, Any] = {
        "schema": VALIDATION_SCHEMA,
        "validatorVersion": VALIDATOR_VERSION,
        "validationPolicy": VALIDATION_POLICY,
        "fullyDecoded": True,
        "mediaType": result.media_type,
        "byteLength": result.byte_length,
        "sha256": result.sha256,
        "attestedTools": {
            "ffmpegSha256": ffmpeg_sha256,
            "ffprobeSha256": ffprobe_sha256,
        },
        "metadata": {
            "detectedKind": result.detected_kind,
            "codecName": result.codec_name,
            "audioCodecName": result.audio_codec_name,
            "videoStreamCount": result.video_stream_count,
            "audioStreamCount": result.audio_stream_count,
            "formatName": result.format_name,
            "width": result.width,
            "height": result.height,
            "durationMs": result.duration_ms,
            "decodedFrames": result.decoded_frames,
        },
    }
    canonical = json.dumps(
        base, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii")
    base["receiptSha256"] = hashlib.sha256(
        VALIDATION_SCHEMA.encode("ascii") + b"\0" + canonical
    ).hexdigest()
    return base


async def trusted_media_readiness_receipt() -> dict[str, Any]:
    if _SPOOL_COMPROMISED.is_set():
        raise TrustedMediaRequestError(
            503,
            "media_probe_spool_compromised",
            "Trusted media probe staging is disabled until restart.",
            retryable=False,
        )
    readiness = await run_in_threadpool(preflight_trusted_media_probe)
    if (
        readiness.schema != "nachuan.trusted-media-probe.readiness.v2"
        or getattr(readiness, "validator_version", None) != VALIDATOR_VERSION
        or getattr(readiness, "validation_policy", None) != VALIDATION_POLICY
        or not readiness.ready
    ):
        raise TrustedMediaRequestError(
            503,
            "media_probe_unavailable",
            "Trusted media probe is unavailable.",
            retryable=True,
        )
    return {
        "schema": readiness.schema,
        "validatorVersion": VALIDATOR_VERSION,
        "validationPolicy": VALIDATION_POLICY,
        "ready": True,
        "attestedTools": {
            "ffmpegSha256": _required_digest(
                getattr(readiness, "ffmpeg_sha256", None), "ffmpeg"
            ),
            "ffprobeSha256": _required_digest(
                getattr(readiness, "ffprobe_sha256", None), "ffprobe"
            ),
        },
    }


async def validate_trusted_media_request(request: Request) -> dict[str, Any]:
    media_type, expected_length, expected_sha256, limit = _parse_upload_contract(
        request
    )
    reserved = _acquire_spool_capacity(expected_length)
    directory: Path | None = None
    path: Path | None = None
    handle: Any | None = None
    digest = hashlib.sha256()
    total = 0
    try:
        directory, path, handle = _make_private_spool()
        try:
            async for chunk in request.stream():
                if not chunk:
                    continue
                total += len(chunk)
                if total > limit or total > expected_length:
                    raise TrustedMediaRequestError(
                        413,
                        "media_probe_payload_too_large",
                        "Trusted media probe payload exceeds its declared limit.",
                    )
                digest.update(chunk)
                await run_in_threadpool(_write_chunk, handle, bytes(chunk))
            await run_in_threadpool(_flush_spool, handle)
        except ClientDisconnect as exc:
            raise TrustedMediaRequestError(
                400,
                "media_probe_upload_interrupted",
                "Trusted media probe upload was interrupted.",
            ) from exc
        except TrustedMediaRequestError:
            raise
        except OSError as exc:
            raise TrustedMediaRequestError(
                503,
                "media_probe_spool_unavailable",
                "Trusted media probe staging is unavailable.",
                retryable=True,
            ) from exc
        finally:
            handle.close()

        if total != expected_length:
            raise TrustedMediaRequestError(
                400,
                "media_probe_length_mismatch",
                "Trusted media probe byte length does not match its receipt.",
            )
        actual_sha256 = digest.hexdigest()
        if not hmac.compare_digest(actual_sha256, expected_sha256):
            raise TrustedMediaRequestError(
                422,
                "media_probe_digest_mismatch",
                "Trusted media probe bytes do not match their digest receipt.",
            )
        result = await run_in_threadpool(
            probe_trusted_media_staged_file,
            path,
            expected_media_type=media_type,
            max_input_bytes=limit,
            expected_byte_length=expected_length,
            expected_sha256=expected_sha256,
        )
        if (
            result.media_type != media_type
            or result.byte_length != expected_length
            or not hmac.compare_digest(result.sha256, expected_sha256)
        ):
            raise TrustedMediaRequestError(
                503,
                "media_probe_receipt_unavailable",
                "Trusted media probe receipt does not match the uploaded bytes.",
                retryable=True,
            )
        return _validation_receipt(result)
    finally:
        # Do not acknowledge validation while plaintext staging cleanup failed.
        cleanup_error: BaseException | None = None
        if directory is not None:
            try:
                await asyncio.shield(
                    run_in_threadpool(_remove_private_spool, directory)
                )
            except BaseException as exc:  # preserve cleanup failure after release
                cleanup_error = exc
        try:
            _release_spool_capacity(reserved)
        except BaseException as exc:
            if cleanup_error is None:
                cleanup_error = exc
        if cleanup_error is not None:
            raise cleanup_error


__all__ = [
    "EXPECTED_LENGTH_HEADER",
    "EXPECTED_SHA256_HEADER",
    "SUPPORTED_MEDIA_LIMITS",
    "TrustedMediaRequestError",
    "VALIDATION_SCHEMA",
    "VALIDATOR_VERSION",
    "trusted_media_readiness_receipt",
    "validate_trusted_media_request",
]
