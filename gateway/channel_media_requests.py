"""Durable, fail-closed request authority for paid channel media inference.

This adapter deliberately owns a separate SQLite database and capacity budget
from image/video creation.  It reuses the hardened durable request state
machine while domain-separating channel, operation, principal and message key.
"""

from __future__ import annotations

import os
import re
from typing import Any, Callable, Literal

from gateway.channel_media_idempotency import (
    derive_channel_media_key,
    validate_channel_media_operation,
    validate_channel_principal_hash,
)
from gateway.durable_media_requests import (
    DurableMediaRequestClaim,
    DurableMediaRequestStore,
    DurableMediaRootState,
    DurableMediaRootTransition,
)


_DIGEST_RE = re.compile(r"[0-9a-f]{64}")
_BACKING_OPERATION = "images.create"
_DEFAULT_RESPONSE_BYTES = 8 * 1024 * 1024
_DEFAULT_TOTAL_RESPONSE_BYTES = 256 * 1024 * 1024
_DEFAULT_DATABASE_BYTES = 512 * 1024 * 1024
_DEFAULT_RETENTION_SECONDS = 7 * 24 * 60 * 60.0


def _validated_request_digest(value: object) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise ValueError("channel media request hash must be a lowercase SHA-256 digest")
    if value == "0" * 64:
        raise ValueError("channel media request hash must be nonzero")
    return value


class DurableChannelMediaRequestStore:
    """Operation-safe facade over one independent durable request store.

    The explicit ``channel_media`` profile has a different application id,
    schema fingerprint and permanent provider-admission registry.  Its core
    request table still has a closed paid-create operation enum, so a channel
    operation is encoded into the already validated internal idempotency key
    and all channel rows use the non-video backing branch.  The facade never
    exposes that implementation alias, and its database must never be shared
    with paid-create routes.
    """

    def __init__(
        self,
        db_path: str | os.PathLike[str],
        *,
        construction_policy: Literal["dev", "create_bound", "open_bound"] = "dev",
        expected_database_identity: str | None = None,
        pre_mutation_hook: Callable[[], None] | None = None,
        root_commit_hook: Callable[[DurableMediaRootTransition], None] | None = None,
        lease_seconds: float = 15 * 60.0,
        retention_seconds: float = _DEFAULT_RETENTION_SECONDS,
        max_response_bytes: int = _DEFAULT_RESPONSE_BYTES,
        max_total_response_bytes: int = _DEFAULT_TOTAL_RESPONSE_BYTES,
        max_records: int = 50_000,
        prune_batch: int = 512,
        max_database_bytes: int = _DEFAULT_DATABASE_BYTES,
    ) -> None:
        self._store = DurableMediaRequestStore(
            db_path,
            schema_profile="channel_media",
            construction_policy=construction_policy,
            expected_database_identity=expected_database_identity,
            pre_mutation_hook=pre_mutation_hook,
            root_commit_hook=root_commit_hook,
            lease_seconds=lease_seconds,
            retention_seconds=retention_seconds,
            max_response_bytes=max_response_bytes,
            max_total_response_bytes=max_total_response_bytes,
            max_records=max_records,
            prune_batch=prune_batch,
            max_database_bytes=max_database_bytes,
        )

    @property
    def path(self):  # noqa: ANN201
        return self._store.path

    @property
    def lease_seconds(self) -> float:
        return self._store.lease_seconds

    def inspect_root_state(self) -> DurableMediaRootState:
        return self._store.inspect_root_state()

    def resume_after_root_reconcile(
        self,
        expected_current_proof: DurableMediaRootState,
    ) -> DurableMediaRootState:
        return self._store.resume_after_root_reconcile(expected_current_proof)

    def enter_authority_manual_only(
        self,
        *,
        installation_id: str,
        epoch: int,
        recovery_floor: int,
        recovery_state_digest: str,
    ) -> DurableMediaRootTransition:
        return self._store.enter_authority_manual_only(
            installation_id=installation_id,
            epoch=epoch,
            recovery_floor=recovery_floor,
            recovery_state_digest=recovery_state_digest,
        )

    def claim(
        self,
        *,
        channel: object,
        operation: object,
        message_key: object,
        principal_hash: object,
        request_sha256: object,
        max_success_bytes: int | None = None,
        now: float | None = None,
    ) -> DurableMediaRequestClaim:
        normalized_operation = validate_channel_media_operation(operation)
        internal_key = derive_channel_media_key(
            channel=channel,
            message_key=message_key,
            operation=normalized_operation,
        )
        return self._store.claim(
            principal_hash=validate_channel_principal_hash(principal_hash),
            operation=_BACKING_OPERATION,
            idempotency_key=internal_key,
            request_sha256=_validated_request_digest(request_sha256),
            max_success_bytes=max_success_bytes,
            now=now,
        )

    def enter_provider_phase(
        self,
        *,
        turn_id: str,
        fencing_token: str,
        max_success_bytes: int | None = None,
        now: float | None = None,
    ) -> bool:
        return self._store.enter_provider_phase(
            turn_id=turn_id,
            fencing_token=fencing_token,
            max_success_bytes=max_success_bytes,
            now=now,
        )

    def heartbeat(
        self,
        *,
        turn_id: str,
        fencing_token: str,
        now: float | None = None,
    ) -> bool:
        return self._store.renew_claim(
            turn_id=turn_id,
            fencing_token=fencing_token,
            now=now,
        )

    def succeed(
        self,
        *,
        turn_id: str,
        fencing_token: str,
        response: dict[str, Any],
        now: float | None = None,
    ) -> bool:
        return self._store.succeed(
            turn_id=turn_id,
            fencing_token=fencing_token,
            response=response,
            now=now,
        )

    def abandon_pre_provider(self, *, turn_id: str, fencing_token: str) -> bool:
        return self._store.abandon_pre_provider(
            turn_id=turn_id,
            fencing_token=fencing_token,
        )

    def close(self) -> None:
        self._store.close()
