"""Strict loopback and health-file attestation for installed channel roles."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import secrets
import stat
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from gateway.installed_channel_supervisor_status import InstalledChannelProcessReceipt


_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_REPARSE_ATTRIBUTE = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


class InstalledChannelHealthError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class InstalledRoleHealthProof:
    role: str
    pid: int
    state: str
    attested: bool
    start_allowed: bool
    ready: bool
    restart_recommended: bool

    def __post_init__(self) -> None:
        if (
            self.role not in {"engine", "weixin", "feishu"}
            or isinstance(self.pid, bool)
            or not isinstance(self.pid, int)
            or self.pid < 0
            or not isinstance(self.state, str)
            or not 1 <= len(self.state) <= 64
            or re.fullmatch(r"[a-z0-9_.-]+", self.state) is None
            or any(
                type(value) is not bool
                for value in (
                    self.attested,
                    self.start_allowed,
                    self.ready,
                    self.restart_recommended,
                )
            )
            or self.ready and not self.start_allowed
            or self.start_allowed and not self.attested
        ):
            raise InstalledChannelHealthError("role health proof is invalid")


def _reject_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def _object_without_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _default_json_fetch(
    url: str, timeout_seconds: float, maximum_bytes: int
) -> object:
    request = urllib.request.Request(
        url,
        method="GET",
        headers={"Accept": "application/json", "User-Agent": "nachuan-supervisor/1"},
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=timeout_seconds) as response:
        if int(getattr(response, "status", 0)) != 200:
            raise InstalledChannelHealthError("health endpoint status is invalid")
        payload = response.read(maximum_bytes + 1)
    if not payload or len(payload) > maximum_bytes:
        raise InstalledChannelHealthError("health endpoint payload is invalid")
    try:
        return json.loads(
            payload.decode("utf-8", errors="strict"),
            parse_constant=_reject_constant,
            object_pairs_hook=_object_without_duplicates,
        )
    except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise InstalledChannelHealthError("health endpoint JSON is invalid") from exc


class InstalledChannelHealthProbe:
    def __init__(
        self,
        *,
        data_directory: str | Path,
        engine_port: int,
        engine_boot_token: str,
        challenge_factory: Callable[[], str] | None = None,
        json_fetch: Callable[[str, float, int], object] | None = None,
        wall_clock: Callable[[], float] | None = None,
    ) -> None:
        data = Path(os.path.abspath(os.fspath(data_directory)))
        try:
            metadata = os.lstat(data)
        except OSError as exc:
            raise InstalledChannelHealthError("data directory is unavailable") from exc
        if (
            not Path(data_directory).is_absolute()
            or not stat.S_ISDIR(metadata.st_mode)
            or data.is_symlink()
            or int(getattr(metadata, "st_file_attributes", 0)) & _REPARSE_ATTRIBUTE
        ):
            raise InstalledChannelHealthError("data directory is invalid")
        if (
            isinstance(engine_port, bool)
            or not isinstance(engine_port, int)
            or not 1024 <= engine_port <= 65535
            or not isinstance(engine_boot_token, str)
            or _HEX64.fullmatch(engine_boot_token) is None
            or not callable(challenge_factory or secrets.token_hex)
            or not callable(json_fetch or _default_json_fetch)
            or not callable(wall_clock or time.time)
        ):
            raise InstalledChannelHealthError("engine health configuration is invalid")
        self._data = data
        self._engine_port = engine_port
        self._engine_boot_token = engine_boot_token
        self._challenge_factory = challenge_factory or (lambda: secrets.token_hex(32))
        self._json_fetch = json_fetch or _default_json_fetch
        self._wall_clock = wall_clock or time.time

    @staticmethod
    def _engine_failure(
        state: str,
        *,
        pid: int = 0,
        attested: bool = False,
        restart_recommended: bool = True,
    ) -> InstalledRoleHealthProof:
        return InstalledRoleHealthProof(
            role="engine",
            pid=pid,
            state=state,
            attested=attested,
            start_allowed=False,
            ready=False,
            restart_recommended=restart_recommended,
        )

    @staticmethod
    def _strict_ready(checks: object, name: str) -> bool:
        if not isinstance(checks, dict) or not isinstance(checks.get(name), dict):
            raise InstalledChannelHealthError("engine health schema is invalid")
        value = checks[name].get("ready")
        if type(value) is not bool:
            raise InstalledChannelHealthError("engine health schema is invalid")
        return value

    def probe_engine(
        self, process: InstalledChannelProcessReceipt
    ) -> InstalledRoleHealthProof:
        if not isinstance(process, InstalledChannelProcessReceipt):
            raise InstalledChannelHealthError("engine process receipt is invalid")
        try:
            challenge = str(self._challenge_factory()).lower()
        except Exception:
            return self._engine_failure("challenge_unavailable")
        if _HEX64.fullmatch(challenge) is None:
            return self._engine_failure("challenge_invalid")
        expected = hmac.new(
            bytes.fromhex(self._engine_boot_token),
            challenge.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        url = (
            f"http://127.0.0.1:{self._engine_port}/health?challenge={challenge}"
        )
        try:
            document = self._json_fetch(url, 2.0, 65536)
        except Exception:
            return self._engine_failure("unreachable", pid=process.pid)
        if not isinstance(document, dict) or document.get("status") != "ok":
            return self._engine_failure("response_not_ok", pid=process.pid)
        proof = document.get("boot_proof")
        if (
            not isinstance(proof, str)
            or _HEX64.fullmatch(proof) is None
            or not hmac.compare_digest(proof, expected)
        ):
            return self._engine_failure("attestation_mismatch", pid=process.pid)
        health_pid = document.get("pid")
        if (
            isinstance(health_pid, bool)
            or not isinstance(health_pid, int)
            or health_pid != process.pid
        ):
            return self._engine_failure(
                "identity_mismatch", pid=process.pid, attested=True
            )
        try:
            readiness = document.get("readiness")
            if readiness not in {"ok", "degraded"}:
                raise InstalledChannelHealthError("engine health schema is invalid")
            checks = document.get("checks")
            database_ready = self._strict_ready(checks, "database")
            connection_ready = self._strict_ready(checks, "connection_store")
            providers_ready = self._strict_ready(checks, "providers")
            if not isinstance(checks, dict) or not isinstance(
                checks.get("financial_ledger"), dict
            ):
                raise InstalledChannelHealthError("engine health schema is invalid")
            financial = checks["financial_ledger"]
            financial_required = financial.get("required")
            financial_ready = financial.get("ready")
            if type(financial_required) is not bool or type(financial_ready) is not bool:
                raise InstalledChannelHealthError("engine health schema is invalid")
        except InstalledChannelHealthError:
            return self._engine_failure(
                "health_schema_invalid", pid=process.pid, attested=True
            )
        if not database_ready:
            return self._engine_failure(
                "database_unready", pid=process.pid, attested=True
            )
        if not financial_required or not financial_ready:
            return self._engine_failure(
                "financial_ledger_unready",
                pid=process.pid,
                attested=True,
                restart_recommended=False,
            )
        if not connection_ready:
            return self._engine_failure(
                "connection_store_unready",
                pid=process.pid,
                attested=True,
                restart_recommended=False,
            )
        if readiness != "ok":
            return self._engine_failure(
                "engine_degraded",
                pid=process.pid,
                attested=True,
                restart_recommended=False,
            )
        if not providers_ready:
            return InstalledRoleHealthProof(
                role="engine",
                pid=process.pid,
                state="provider_unavailable",
                attested=True,
                start_allowed=True,
                ready=False,
                restart_recommended=False,
            )
        return InstalledRoleHealthProof(
            role="engine",
            pid=process.pid,
            state="ready",
            attested=True,
            start_allowed=True,
            ready=True,
            restart_recommended=False,
        )

    @staticmethod
    def _channel_failure(
        role: str,
        state: str,
        *,
        pid: int = 0,
        attested: bool = False,
        start_allowed: bool = False,
        restart_recommended: bool = True,
    ) -> InstalledRoleHealthProof:
        return InstalledRoleHealthProof(
            role=role,
            pid=pid,
            state=state,
            attested=attested,
            start_allowed=start_allowed,
            ready=False,
            restart_recommended=restart_recommended,
        )

    @staticmethod
    def _strict_channel_count(document: dict[str, object], name: str) -> int:
        value = document.get(name)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise InstalledChannelHealthError("channel health count is invalid")
        return value

    @staticmethod
    def _strict_channel_number(document: dict[str, object], name: str) -> float:
        value = document.get(name)
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            or float(value) < 0
        ):
            raise InstalledChannelHealthError("channel health number is invalid")
        return float(value)

    def _read_channel_document(self, role: str) -> dict[str, object]:
        path = self._data / f"{role}_bridge_health.json"
        try:
            metadata = os.lstat(path)
        except OSError as exc:
            raise InstalledChannelHealthError("channel health file is unavailable") from exc
        if (
            not stat.S_ISREG(metadata.st_mode)
            or path.is_symlink()
            or int(getattr(metadata, "st_file_attributes", 0)) & _REPARSE_ATTRIBUTE
            or not 1 <= int(metadata.st_size) <= 65536
        ):
            raise InstalledChannelHealthError("channel health file is invalid")
        try:
            payload = path.read_bytes()
            document = json.loads(
                payload.decode("utf-8", errors="strict"),
                parse_constant=_reject_constant,
                object_pairs_hook=_object_without_duplicates,
            )
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
            raise InstalledChannelHealthError("channel health JSON is invalid") from exc
        if not isinstance(document, dict):
            raise InstalledChannelHealthError("channel health JSON is invalid")
        return document

    def probe_channel(
        self,
        role: str,
        process: InstalledChannelProcessReceipt,
        engine: InstalledRoleHealthProof,
    ) -> InstalledRoleHealthProof:
        if (
            role not in {"weixin", "feishu"}
            or not isinstance(process, InstalledChannelProcessReceipt)
            or not isinstance(engine, InstalledRoleHealthProof)
            or engine.role != "engine"
            or not engine.start_allowed
        ):
            raise InstalledChannelHealthError("channel health binding is invalid")
        try:
            document = self._read_channel_document(role)
            expected_schema = f"nachuan.{role}-bridge-health.v1"
            if document.get("schema") != expected_schema:
                raise InstalledChannelHealthError("channel health schema is invalid")
            health_pid = document.get("pid")
            if (
                isinstance(health_pid, bool)
                or not isinstance(health_pid, int)
                or health_pid != process.pid
            ):
                return self._channel_failure(
                    role, "identity_mismatch", pid=process.pid
                )
            boolean_names = (
                "ready",
                "fresh",
                "connected",
                "access_configured",
                "bridge_key_configured",
                "engine_available",
            )
            booleans: dict[str, bool] = {}
            for name in boolean_names:
                value = document.get(name)
                if type(value) is not bool:
                    raise InstalledChannelHealthError(
                        "channel readiness field is invalid"
                    )
                booleans[name] = value
            updated_at = self._strict_channel_number(document, "updated_at")
            fresh_until = self._strict_channel_number(document, "fresh_until")
            freshness_ttl = self._strict_channel_number(
                document, "freshness_ttl_seconds"
            )
            now = float(self._wall_clock())
            if not math.isfinite(now) or now <= 0:
                raise InstalledChannelHealthError("channel health clock is invalid")
            declared_window = fresh_until - updated_at
            fresh = bool(
                updated_at > 0
                and updated_at <= now + 5.0
                and fresh_until >= now
                and 1.0 <= freshness_ttl <= 60.0
                and 1.0 <= declared_window <= 61.0
                and abs(declared_window - freshness_ttl) <= 1.0
            )
            state = document.get("state")
            if not isinstance(state, str) or state not in {
                "starting",
                "healthy",
                "degraded",
                "stopping",
            }:
                raise InstalledChannelHealthError("channel health state is invalid")
            error_code = document.get("last_error_code")
            if (
                not isinstance(error_code, str)
                or re.fullmatch(r"[A-Za-z0-9_.-]{0,64}", error_code) is None
            ):
                raise InstalledChannelHealthError("channel error code is invalid")
            reasons = document.get("readiness_reasons")
            if not isinstance(reasons, list) or any(
                not isinstance(reason, str)
                or re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", reason) is None
                for reason in reasons
            ) or len(set(reasons)) != len(reasons) or len(reasons) > 32:
                raise InstalledChannelHealthError("channel health reasons are invalid")
            counts = [
                self._strict_channel_count(document, name)
                for name in (
                    "pending_inbound",
                    "pending_outbound",
                    "dead_inbound",
                    "dead_outbound",
                )
            ]
            if role == "weixin":
                counts.append(
                    self._strict_channel_count(
                        document, "consecutive_poll_failures"
                    )
                )
                self._strict_channel_number(
                    document, "oldest_processing_age_seconds"
                )
            else:
                counts.append(
                    self._strict_channel_count(
                        document, "consecutive_reconnect_failures"
                    )
                )
        except InstalledChannelHealthError:
            return self._channel_failure(
                role, "health_invalid", pid=process.pid
            )

        base_healthy = bool(
            fresh
            and booleans["fresh"]
            and booleans["connected"]
            and booleans["access_configured"]
            and booleans["bridge_key_configured"]
            and not any(counts)
        )
        no_model_reasons = {"ready_no_model", "requested_model_unavailable"}
        if (
            base_healthy
            and not engine.ready
            and engine.state == "provider_unavailable"
            and not booleans["engine_available"]
            and state == "degraded"
            and not booleans["ready"]
            and len(reasons) == 1
            and reasons[0] in no_model_reasons
            and document.get("engine_readiness_reason") == reasons[0]
        ):
            return self._channel_failure(
                role,
                "provider_unavailable",
                pid=process.pid,
                attested=True,
                start_allowed=True,
                restart_recommended=False,
            )
        if (
            base_healthy
            and engine.ready
            and booleans["engine_available"]
            and state == "healthy"
            and booleans["ready"]
            and not reasons
        ):
            return InstalledRoleHealthProof(
                role=role,
                pid=process.pid,
                state="ready",
                attested=True,
                start_allowed=True,
                ready=True,
                restart_recommended=False,
            )
        if base_healthy:
            return self._channel_failure(
                role,
                "channel_degraded",
                pid=process.pid,
                attested=True,
                start_allowed=True,
                restart_recommended=False,
            )
        return self._channel_failure(
            role,
            "channel_unhealthy",
            pid=process.pid,
            attested=True,
            restart_recommended=True,
        )


class InstalledChannelRuntimeHealthAdapter:
    """Adapt strict role probes to the Supervisor runtime callback contract."""

    def __init__(
        self,
        *,
        probe: InstalledChannelHealthProbe,
        process_manager,
        monotonic_clock: Callable[[], float] | None = None,
        sleeper: Callable[[float], None] | None = None,
        startup_timeout_seconds: float = 60.0,
        poll_interval_seconds: float = 0.1,
    ) -> None:
        if not isinstance(probe, InstalledChannelHealthProbe) or not callable(
            getattr(process_manager, "process_receipt", None)
        ):
            raise InstalledChannelHealthError("runtime health adapter is invalid")
        timings = (float(startup_timeout_seconds), float(poll_interval_seconds))
        if (
            any(not math.isfinite(value) or value <= 0 for value in timings)
            or timings[1] > timings[0]
            or not callable(monotonic_clock or time.monotonic)
            or not callable(sleeper or time.sleep)
        ):
            raise InstalledChannelHealthError("runtime health timing is invalid")
        self._probe = probe
        self._manager = process_manager
        self._clock = monotonic_clock or time.monotonic
        self._sleep = sleeper or time.sleep
        self._startup_timeout = timings[0]
        self._poll_interval = timings[1]
        self._engine_proof: InstalledRoleHealthProof | None = None

    def __call__(self, role: str, process: object) -> InstalledRoleHealthProof:
        if role not in {"engine", "weixin", "feishu"}:
            raise InstalledChannelHealthError("runtime health role is invalid")
        receipt = self._manager.process_receipt(role, process)
        if not isinstance(receipt, InstalledChannelProcessReceipt):
            raise InstalledChannelHealthError("runtime process receipt is invalid")
        try:
            started = float(self._clock())
        except Exception as exc:
            raise InstalledChannelHealthError("runtime health clock is unavailable") from exc
        if not math.isfinite(started):
            raise InstalledChannelHealthError("runtime health clock is invalid")
        deadline = started + self._startup_timeout
        while True:
            if role == "engine":
                proof = self._probe.probe_engine(receipt)
            else:
                if self._engine_proof is None or not self._engine_proof.start_allowed:
                    raise InstalledChannelHealthError("engine health proof is unavailable")
                proof = self._probe.probe_channel(role, receipt, self._engine_proof)
            if proof.start_allowed or not proof.restart_recommended:
                if role == "engine":
                    self._engine_proof = proof
                return proof
            poll = getattr(process, "poll", None)
            if callable(poll) and poll() is not None:
                return proof
            try:
                now = float(self._clock())
            except Exception as exc:
                raise InstalledChannelHealthError(
                    "runtime health clock is unavailable"
                ) from exc
            if not math.isfinite(now) or now < started:
                raise InstalledChannelHealthError("runtime health clock is invalid")
            if now >= deadline:
                return proof
            self._sleep(min(self._poll_interval, deadline - now))

    def check_runtime(self, runtime: object, previous_state: object):
        from gateway.installed_channel_supervisor import (
            InstalledChannelSupervisorState,
        )

        if not isinstance(previous_state, InstalledChannelSupervisorState) or not callable(
            getattr(runtime, "process_receipts", None)
        ):
            raise InstalledChannelHealthError("runtime health state is invalid")
        receipts = runtime.process_receipts()
        if tuple(receipts) != ("engine", "weixin", "feishu"):
            raise InstalledChannelHealthError("runtime process receipts are invalid")
        for role, receipt in receipts.items():
            if (
                not isinstance(receipt, InstalledChannelProcessReceipt)
                or receipt.pid != previous_state.pids.get(role)
            ):
                raise InstalledChannelHealthError("runtime process identity changed")
        engine = self._probe.probe_engine(receipts["engine"])
        proofs: dict[str, InstalledRoleHealthProof] = {"engine": engine}
        if engine.start_allowed:
            proofs["weixin"] = self._probe.probe_channel(
                "weixin", receipts["weixin"], engine
            )
            proofs["feishu"] = self._probe.probe_channel(
                "feishu", receipts["feishu"], engine
            )
        start_allowed = tuple(proofs) == ("engine", "weixin", "feishu") and all(
            proof.start_allowed for proof in proofs.values()
        )
        ready = start_allowed and all(proof.ready for proof in proofs.values())
        self._engine_proof = engine
        return InstalledChannelSupervisorState(
            pids=previous_state.pids,
            ready=ready,
            start_allowed=start_allowed,
            proofs=proofs,
        )


__all__ = [
    "InstalledChannelHealthError",
    "InstalledChannelHealthProbe",
    "InstalledChannelRuntimeHealthAdapter",
    "InstalledRoleHealthProof",
]
