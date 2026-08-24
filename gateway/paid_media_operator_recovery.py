"""Local-admin, prepared-only recovery for one existing paid video.

The service accepts no provider, router, credential, create, or poll callback.
Its only remote-byte action is consuming the URL already sealed in the durable
prepared record.  Public documents intentionally omit principals, task aliases,
prepared tokens, provider responses, and upstream URLs.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import re
import time
from types import SimpleNamespace
from typing import Any, Callable

from gateway.durable_media_requests import (
    DurableMediaAssetConflict,
    DurableMediaRequestStore,
    DurableMediaRequestUnavailable,
    hash_media_request,
    prepared_video_operator_recovery_candidate_sha256,
)
from gateway.paid_media_asset_delivery import (
    PaidMediaAssetDeliveryUnavailable,
    archive_paid_media_document_for_web,
)
from gateway.paid_media_asset_protocol import (
    PaidMediaAssetProtocolError,
    parse_asset_result,
)
from gateway.paid_media_asset_store import (
    PaidMediaAssetStore,
    PaidMediaAssetStoreError,
)
from gateway.paid_media_operator_receipts import (
    CompletedPreparedRecoveryReceipt,
    PaidMediaOperatorReceiptError,
    PaidMediaOperatorReceiptStore,
    PreparedRecoveryCandidate,
)
from gateway.paid_media_web import (
    PaidMediaWebConflict,
    PaidMediaWebLedger,
    PaidMediaWebLedgerUnavailable,
)
from gateway.paid_media_web_archive import (
    PaidMediaWebArchiveUnavailable,
    PaidMediaWebAssetArchive,
)


_OPERATION_ID_RE = re.compile(
    r"^desktop-op-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_VIDEO_ALIAS_RE = re.compile(r"^nvt1_[0-9a-f]{64}$")
_CANDIDATE_DOMAIN = b"nachuan-local-operator-prepared-candidate-v1\x00"
_ACK_PROOF_DOMAIN = b"nachuan-local-operator-prepared-ack-proof-v1\x00"
_RESULT_DOMAIN = b"nachuan-paid-media-web-result-v1\x00"
_RECOVERY_DEPENDENCY_ERRORS = (
    DurableMediaAssetConflict,
    DurableMediaRequestUnavailable,
    PaidMediaAssetDeliveryUnavailable,
    PaidMediaAssetStoreError,
    PaidMediaWebArchiveUnavailable,
    PaidMediaWebLedgerUnavailable,
    PaidMediaWebConflict,
    PaidMediaAssetProtocolError,
    PaidMediaOperatorReceiptError,
    ValueError,
    OSError,
)


class PaidMediaOperatorRecoveryError(RuntimeError):
    """Sanitized failure at the explicit local-administrator boundary."""


@dataclass(frozen=True, slots=True)
class PaidMediaOperatorRecoveryInspection:
    operation_id: str
    decision_id: str
    candidate_sha256: str
    challenge: str

    def public_document(self) -> dict[str, object]:
        return {
            "schema": "nachuan.local-paid-media-operator-inspection.v1",
            "operationId": self.operation_id,
            "decisionId": self.decision_id,
            "candidateSha256": self.candidate_sha256,
            "challenge": self.challenge,
            "state": "ready",
            "providerCallsAllowed": False,
        }


@dataclass(frozen=True, slots=True)
class PaidMediaOperatorRecoveryReceipt:
    operation_id: str
    decision_id: str
    candidate_sha256: str
    result_sha256: str
    archive_receipt_sha256: str
    receipt_sha256: str
    asset_sha256: str
    asset_reference: str
    byte_length: int
    media_type: str
    replayed: bool = False

    def public_document(self) -> dict[str, object]:
        return {
            "schema": "nachuan.local-paid-media-operator-recovery-receipt.v1",
            "operationId": self.operation_id,
            "decisionId": self.decision_id,
            "candidateSha256": self.candidate_sha256,
            "state": "completed",
            "providerCreateCalls": 0,
            "providerPollCalls": 0,
            "resultSha256": self.result_sha256,
            "archiveReceiptSha256": self.archive_receipt_sha256,
            "receiptSha256": self.receipt_sha256,
            "assetSha256": self.asset_sha256,
            "assetReference": self.asset_reference,
            "byteLength": self.byte_length,
            "mediaType": self.media_type,
            "replayed": self.replayed,
        }


@dataclass(frozen=True, slots=True)
class _InspectedCandidate:
    receipt_candidate: PreparedRecoveryCandidate
    source_principal_hash: str
    recipient_principal_hash: str
    task_alias: str
    processing_result_sha256: str
    durable_candidate_sha256: str


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise PaidMediaOperatorRecoveryError(
            "operator recovery evidence is invalid"
        ) from exc


def _required_digest(value: object) -> str:
    digest = str(value or "")
    if _DIGEST_RE.fullmatch(digest) is None:
        raise PaidMediaOperatorRecoveryError(
            "operator recovery evidence is invalid"
        )
    return digest


def _operator_candidate_sha256(
    *,
    operation_id: str,
    source_principal_hash: str,
    recipient_principal_hash: str,
    request_sha256: str,
    consent_sha256: str,
    processing_result_sha256: str,
    durable_candidate_sha256: str,
) -> str:
    return hashlib.sha256(
        _CANDIDATE_DOMAIN
        + operation_id.encode("ascii")
        + b"\x00"
        + source_principal_hash.encode("ascii")
        + b"\x00"
        + recipient_principal_hash.encode("ascii")
        + b"\x00"
        + request_sha256.encode("ascii")
        + b"\x00"
        + consent_sha256.encode("ascii")
        + b"\x00"
        + processing_result_sha256.encode("ascii")
        + b"\x00"
        + durable_candidate_sha256.encode("ascii")
    ).hexdigest()


class PaidMediaOperatorRecoveryService:
    """Two-phase, local-owner recovery with no provider-capable dependency."""

    def __init__(
        self,
        *,
        web_ledger: PaidMediaWebLedger,
        media_requests: DurableMediaRequestStore,
        asset_store: PaidMediaAssetStore,
        web_archive: PaidMediaWebAssetArchive,
        receipt_store: PaidMediaOperatorReceiptStore,
        installation_id: str,
        installation_epoch: int,
        assert_local_owner: Callable[[], None],
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        if (
            not isinstance(web_ledger, PaidMediaWebLedger)
            or not isinstance(media_requests, DurableMediaRequestStore)
            or not isinstance(asset_store, PaidMediaAssetStore)
            or not isinstance(web_archive, PaidMediaWebAssetArchive)
            or not isinstance(receipt_store, PaidMediaOperatorReceiptStore)
            or not callable(assert_local_owner)
            or not callable(wall_clock)
        ):
            raise ValueError("operator recovery dependencies are invalid")
        self._web_ledger = web_ledger
        self._media_requests = media_requests
        self._asset_store = asset_store
        self._web_archive = web_archive
        self._receipt_store = receipt_store
        self._installation_id = _required_digest(installation_id)
        if (
            isinstance(installation_epoch, bool)
            or not isinstance(installation_epoch, int)
            or installation_epoch < 1
        ):
            raise ValueError("operator recovery installation epoch is invalid")
        self._installation_epoch = installation_epoch
        self._assert_local_owner_callback = assert_local_owner
        self._wall_clock = wall_clock
        self._state = SimpleNamespace(
            media_requests=media_requests,
            paid_media_assets=asset_store,
            paid_media_web_archive=web_archive,
            paid_media_epoch=installation_epoch,
            paid_media_installation_id=self._installation_id,
        )

    def _assert_local_owner(self) -> None:
        try:
            self._assert_local_owner_callback()
        except Exception as exc:
            raise PaidMediaOperatorRecoveryError(
                "local operator identity is unavailable"
            ) from exc

    def _inspect_candidate(
        self,
        *,
        operation_id: object,
        recipient_principal_hash: object,
    ) -> _InspectedCandidate:
        self._assert_local_owner()
        operation = str(operation_id or "")
        recipient = _required_digest(recipient_principal_hash)
        if _OPERATION_ID_RE.fullmatch(operation) is None:
            raise PaidMediaOperatorRecoveryError(
                "operator recovery operation is invalid"
            )
        row = self._web_ledger.read_operation(operation)
        if row is None:
            raise PaidMediaOperatorRecoveryError(
                "operator recovery operation is unavailable"
            )
        source_principal = _required_digest(row.get("principal_hash"))
        if hmac.compare_digest(source_principal, recipient):
            raise PaidMediaOperatorRecoveryError(
                "operator recovery recipient is unchanged"
            )
        if (
            row.get("path") != "/v1/videos/generations"
            or row.get("operation") != "videos.create"
            or row.get("state") != "delivered"
            or int(row.get("dispatch_count") or 0) != 1
            or int(row.get("last_status") or 0) != 200
            or row.get("asset_document_json") is not None
            or not isinstance(row.get("request_body_json"), str)
            or not isinstance(row.get("consent_json"), str)
            or not isinstance(row.get("result_json"), str)
        ):
            raise PaidMediaOperatorRecoveryError(
                "operator recovery operation is not a prepared video candidate"
            )
        try:
            request_payload = json.loads(str(row["request_body_json"]))
            consent = json.loads(str(row["consent_json"]))
            processing_result = json.loads(str(row["result_json"]))
        except (json.JSONDecodeError, TypeError) as exc:
            raise PaidMediaOperatorRecoveryError(
                "operator recovery evidence is invalid"
            ) from exc
        request_sha256 = _required_digest(row.get("request_sha256"))
        if (
            not isinstance(request_payload, dict)
            or not hmac.compare_digest(
                hash_media_request("videos.create", request_payload),
                request_sha256,
            )
            or not isinstance(consent, dict)
            or set(consent) != {
                "user_confirmed",
                "confirm_summary_sha256",
                "confirmed_at_ms",
                "request_sha256",
            }
            or consent.get("user_confirmed") is not True
            or not hmac.compare_digest(
                str(consent.get("request_sha256") or ""),
                request_sha256,
            )
            or _DIGEST_RE.fullmatch(
                str(consent.get("confirm_summary_sha256") or "")
            )
            is None
            or isinstance(consent.get("confirmed_at_ms"), bool)
            or not isinstance(consent.get("confirmed_at_ms"), int)
            or int(consent["confirmed_at_ms"]) < 0
            or not isinstance(processing_result, dict)
            or set(processing_result) != {"task_id", "status"}
            or processing_result.get("status") != "processing"
        ):
            raise PaidMediaOperatorRecoveryError(
                "operator recovery evidence is invalid"
            )
        task_alias = str(processing_result.get("task_id") or "")
        if _VIDEO_ALIAS_RE.fullmatch(task_alias) is None:
            raise PaidMediaOperatorRecoveryError(
                "operator recovery evidence is invalid"
            )
        processing_result_sha256 = _required_digest(row.get("result_sha256"))
        expected_processing_digest = hashlib.sha256(
            _RESULT_DOMAIN + _canonical_json_bytes(processing_result)
        ).hexdigest()
        if not hmac.compare_digest(
            processing_result_sha256,
            expected_processing_digest,
        ):
            raise PaidMediaOperatorRecoveryError(
                "operator recovery evidence is invalid"
            )
        durable = self._media_requests.inspect_prepared_video_recovery(
            task_alias=task_alias,
            principal_hash=source_principal,
            installation_epoch=self._installation_epoch,
        )
        consent_sha256 = hashlib.sha256(
            str(row["consent_json"]).encode("utf-8")
        ).hexdigest()
        candidate_sha256 = _operator_candidate_sha256(
            operation_id=operation,
            source_principal_hash=source_principal,
            recipient_principal_hash=recipient,
            request_sha256=request_sha256,
            consent_sha256=consent_sha256,
            processing_result_sha256=processing_result_sha256,
            durable_candidate_sha256=durable.candidate_sha256,
        )
        return _InspectedCandidate(
            receipt_candidate=PreparedRecoveryCandidate(
                operation_id=operation,
                candidate_sha256=candidate_sha256,
                consent_sha256=consent_sha256,
                request_sha256=request_sha256,
                prepared_sha256=durable.prepare_sha256,
            ),
            source_principal_hash=source_principal,
            recipient_principal_hash=recipient,
            task_alias=task_alias,
            processing_result_sha256=processing_result_sha256,
            durable_candidate_sha256=durable.candidate_sha256,
        )

    def inspect(
        self,
        *,
        operation_id: object,
        recipient_principal_hash: object,
    ) -> PaidMediaOperatorRecoveryInspection:
        candidate = self._inspect_candidate(
            operation_id=operation_id,
            recipient_principal_hash=recipient_principal_hash,
        )
        try:
            decision = self._receipt_store.inspect(candidate.receipt_candidate)
        except PaidMediaOperatorReceiptError as exc:
            raise PaidMediaOperatorRecoveryError(
                "operator recovery decision is unavailable"
            ) from exc
        return PaidMediaOperatorRecoveryInspection(
            operation_id=candidate.receipt_candidate.operation_id,
            decision_id=decision.decision_id,
            candidate_sha256=candidate.receipt_candidate.candidate_sha256,
            challenge=decision.confirmation_text,
        )

    @staticmethod
    def _public_receipt(
        *,
        candidate: _InspectedCandidate,
        completed: CompletedPreparedRecoveryReceipt,
        asset_document: dict[str, object],
        replayed: bool,
    ) -> PaidMediaOperatorRecoveryReceipt:
        try:
            parsed = parse_asset_result(asset_document)
        except PaidMediaAssetProtocolError as exc:
            raise PaidMediaOperatorRecoveryError(
                "operator recovery result is invalid"
            ) from exc
        if parsed.kind != "video" or len(parsed.assets) != 1:
            raise PaidMediaOperatorRecoveryError(
                "operator recovery result is invalid"
            )
        asset = parsed.assets[0]
        return PaidMediaOperatorRecoveryReceipt(
            operation_id=candidate.receipt_candidate.operation_id,
            decision_id=completed.decision_id,
            candidate_sha256=completed.candidate_sha256,
            result_sha256=completed.result_sha256,
            archive_receipt_sha256=completed.archive_receipt_sha256,
            receipt_sha256=completed.receipt_sha256,
            asset_sha256=asset.sha256,
            asset_reference=f"nachuan-paid-media://sha256/{asset.sha256}",
            byte_length=asset.byte_length,
            media_type=asset.media_type,
            replayed=replayed,
        )

    def _try_completed_replay(
        self,
        *,
        operation_id: object,
        decision_id: str,
        confirmation: str,
        recipient_principal_hash: object,
    ) -> PaidMediaOperatorRecoveryReceipt | None:
        """Return one exact completed transfer without touching live authority."""

        self._assert_local_owner()
        operation = str(operation_id or "")
        recipient = _required_digest(recipient_principal_hash)
        if _OPERATION_ID_RE.fullmatch(operation) is None:
            raise PaidMediaOperatorRecoveryError(
                "operator recovery operation is invalid"
            )
        row = self._web_ledger.read_operation(operation)
        if row is None:
            raise PaidMediaOperatorRecoveryError(
                "operator recovery operation is unavailable"
            )
        row_principal = _required_digest(row.get("principal_hash"))
        if not hmac.compare_digest(row_principal, recipient):
            return None
        try:
            decision = self._receipt_store.read_decision(operation)
            completed = self._receipt_store.read_completed(operation)
        except PaidMediaOperatorReceiptError as exc:
            raise PaidMediaOperatorRecoveryError(
                "operator recovery receipt is unavailable"
            ) from exc
        if (
            decision is None
            or decision.state not in {"executing", "completed"}
            or not hmac.compare_digest(decision.decision_id, str(decision_id))
            or not hmac.compare_digest(decision.confirmation_text, str(confirmation))
            or row.get("path") != "/v1/videos/generations"
            or row.get("operation") != "videos.create"
            or row.get("state") != "delivered"
            or int(row.get("dispatch_count") or 0) != 1
            or int(row.get("last_status") or 0) != 200
            or not isinstance(row.get("asset_document_json"), str)
            or not isinstance(row.get("result_json"), str)
            or not isinstance(row.get("consent_json"), str)
            or not isinstance(row.get("reconcile_json"), str)
            or not hmac.compare_digest(
                _required_digest(row.get("request_sha256")),
                decision.request_sha256,
            )
            or not hmac.compare_digest(
                hashlib.sha256(
                    str(row["consent_json"]).encode("utf-8")
                ).hexdigest(),
                decision.consent_sha256,
            )
        ):
            raise PaidMediaOperatorRecoveryError(
                "operator recovery replay evidence conflicts"
            )
        try:
            asset_document = json.loads(str(row["asset_document_json"]))
            renderer_result = json.loads(str(row["result_json"]))
            audit = json.loads(str(row["reconcile_json"]))
            parsed = parse_asset_result(asset_document)
        except (
            json.JSONDecodeError,
            TypeError,
            PaidMediaAssetProtocolError,
        ) as exc:
            raise PaidMediaOperatorRecoveryError(
                "operator recovery replay evidence conflicts"
            ) from exc
        if parsed.kind != "video" or len(parsed.assets) != 1:
            raise PaidMediaOperatorRecoveryError(
                "operator recovery replay evidence conflicts"
            )
        asset = parsed.assets[0]
        reference = f"nachuan-paid-media://sha256/{asset.sha256}"
        expected_result = {
            "task_id": f"nvt1_{parsed.turn_id}",
            "status": "completed",
            "video_url": reference,
        }
        result_sha256 = hashlib.sha256(
            _RESULT_DOMAIN + _canonical_json_bytes(expected_result)
        ).hexdigest()
        archive_receipt = _required_digest(row.get("archive_receipt_sha256"))
        ack_receipt_sha256 = hashlib.sha256(
            _ACK_PROOF_DOMAIN
            + operation.encode("ascii")
            + b"\x00"
            + result_sha256.encode("ascii")
            + b"\x00"
            + archive_receipt.encode("ascii")
        ).hexdigest()
        expected_audit = {
            "schema": "nachuan.local-paid-media-operator-transfer.v1",
            "decisionId": decision.decision_id,
            "candidateSha256": decision.candidate_sha256,
            "ackReceiptSha256": ack_receipt_sha256,
        }
        if (
            renderer_result != expected_result
            or audit != expected_audit
            or str(row["reconcile_json"])
            != json.dumps(
                expected_audit,
                sort_keys=True,
                separators=(",", ":"),
            )
            or not hmac.compare_digest(
                _required_digest(row.get("result_sha256")),
                result_sha256,
            )
        ):
            raise PaidMediaOperatorRecoveryError(
                "operator recovery replay evidence conflicts"
            )
        indexed = self._web_ledger.find_asset_document(recipient, asset.sha256)
        receipt = self._web_archive.receipt_for_document(
            principal_hash=recipient,
            result=parsed,
            installation_id=self._installation_id,
            installation_epoch=self._installation_epoch,
        )
        archived = self._web_archive.read(
            principal_hash=recipient,
            asset_sha256=asset.sha256,
        )
        if (
            indexed != asset_document
            or receipt is None
            or not hmac.compare_digest(receipt, archive_receipt)
            or archived is None
            or archived.media_type != asset.media_type
            or archived.byte_length != asset.byte_length
            or archived.sha256 != asset.sha256
        ):
            raise PaidMediaOperatorRecoveryError(
                "operator recovery replay evidence conflicts"
            )
        candidate = PreparedRecoveryCandidate(
            operation_id=operation,
            candidate_sha256=decision.candidate_sha256,
            consent_sha256=decision.consent_sha256,
            request_sha256=decision.request_sha256,
            prepared_sha256=decision.prepared_sha256,
        )
        if decision.state == "executing":
            if completed is not None:
                raise PaidMediaOperatorRecoveryError(
                    "operator recovery replay evidence conflicts"
                )
            try:
                completed = self._receipt_store.complete(
                    candidate,
                    decision_id=decision.decision_id,
                    result_sha256=result_sha256,
                    archive_receipt_sha256=archive_receipt,
                    ack_receipt_sha256=ack_receipt_sha256,
                )
            except PaidMediaOperatorReceiptError as exc:
                raise PaidMediaOperatorRecoveryError(
                    "operator recovery receipt is unavailable"
                ) from exc
        elif (
            completed is None
            or not hmac.compare_digest(
                decision.candidate_sha256,
                completed.candidate_sha256,
            )
            or not hmac.compare_digest(
                completed.result_sha256,
                result_sha256,
            )
            or not hmac.compare_digest(
                completed.archive_receipt_sha256,
                archive_receipt,
            )
            or not hmac.compare_digest(
                completed.ack_receipt_sha256,
                ack_receipt_sha256,
            )
        ):
            raise PaidMediaOperatorRecoveryError(
                "operator recovery replay evidence conflicts"
            )
        return PaidMediaOperatorRecoveryReceipt(
            operation_id=operation,
            decision_id=completed.decision_id,
            candidate_sha256=completed.candidate_sha256,
            result_sha256=completed.result_sha256,
            archive_receipt_sha256=completed.archive_receipt_sha256,
            receipt_sha256=completed.receipt_sha256,
            asset_sha256=asset.sha256,
            asset_reference=reference,
            byte_length=asset.byte_length,
            media_type=asset.media_type,
            replayed=True,
        )

    def _reconstruct_executing_candidate(
        self,
        *,
        operation_id: object,
        decision_id: str,
        confirmation: str,
        recipient_principal_hash: object,
    ) -> tuple[_InspectedCandidate, dict[str, object]] | None:
        """Resume after prepared material was already committed locally."""

        self._assert_local_owner()
        operation = str(operation_id or "")
        recipient = _required_digest(recipient_principal_hash)
        if _OPERATION_ID_RE.fullmatch(operation) is None:
            raise PaidMediaOperatorRecoveryError(
                "operator recovery operation is invalid"
            )
        row = self._web_ledger.read_operation(operation)
        if row is None:
            raise PaidMediaOperatorRecoveryError(
                "operator recovery operation is unavailable"
            )
        source = _required_digest(row.get("principal_hash"))
        if hmac.compare_digest(source, recipient):
            return None
        try:
            decision = self._receipt_store.read_decision(operation)
        except PaidMediaOperatorReceiptError as exc:
            raise PaidMediaOperatorRecoveryError(
                "operator recovery receipt is unavailable"
            ) from exc
        if decision is None or decision.state == "pending":
            return None
        if (
            decision.state != "executing"
            or not hmac.compare_digest(decision.decision_id, str(decision_id))
            or not hmac.compare_digest(
                decision.confirmation_text,
                str(confirmation),
            )
            or row.get("path") != "/v1/videos/generations"
            or row.get("operation") != "videos.create"
            or row.get("state") != "delivered"
            or int(row.get("dispatch_count") or 0) != 1
            or int(row.get("last_status") or 0) != 200
            or row.get("asset_document_json") is not None
            or not isinstance(row.get("request_body_json"), str)
            or not isinstance(row.get("consent_json"), str)
            or not isinstance(row.get("result_json"), str)
        ):
            raise PaidMediaOperatorRecoveryError(
                "operator recovery continuation evidence conflicts"
            )
        try:
            request_payload = json.loads(str(row["request_body_json"]))
            consent = json.loads(str(row["consent_json"]))
            processing_result = json.loads(str(row["result_json"]))
        except (json.JSONDecodeError, TypeError) as exc:
            raise PaidMediaOperatorRecoveryError(
                "operator recovery continuation evidence conflicts"
            ) from exc
        request_sha256 = _required_digest(row.get("request_sha256"))
        consent_sha256 = hashlib.sha256(
            str(row["consent_json"]).encode("utf-8")
        ).hexdigest()
        processing_result_sha256 = _required_digest(row.get("result_sha256"))
        task_alias = (
            str(processing_result.get("task_id") or "")
            if isinstance(processing_result, dict)
            else ""
        )
        expected_processing_digest = hashlib.sha256(
            _RESULT_DOMAIN + _canonical_json_bytes(processing_result)
        ).hexdigest()
        if (
            not isinstance(request_payload, dict)
            or not hmac.compare_digest(
                hash_media_request("videos.create", request_payload),
                request_sha256,
            )
            or not hmac.compare_digest(request_sha256, decision.request_sha256)
            or not isinstance(consent, dict)
            or consent.get("user_confirmed") is not True
            or not hmac.compare_digest(
                str(consent.get("request_sha256") or ""),
                request_sha256,
            )
            or not hmac.compare_digest(consent_sha256, decision.consent_sha256)
            or not isinstance(processing_result, dict)
            or set(processing_result) != {"task_id", "status"}
            or processing_result.get("status") != "processing"
            or _VIDEO_ALIAS_RE.fullmatch(task_alias) is None
            or not hmac.compare_digest(
                processing_result_sha256,
                expected_processing_digest,
            )
        ):
            raise PaidMediaOperatorRecoveryError(
                "operator recovery continuation evidence conflicts"
            )
        durable_candidate = (
            prepared_video_operator_recovery_candidate_sha256(
                task_alias=task_alias,
                principal_hash=source,
                installation_epoch=self._installation_epoch,
                prepare_sha256=decision.prepared_sha256,
            )
        )
        candidate_sha256 = _operator_candidate_sha256(
            operation_id=operation,
            source_principal_hash=source,
            recipient_principal_hash=recipient,
            request_sha256=request_sha256,
            consent_sha256=consent_sha256,
            processing_result_sha256=processing_result_sha256,
            durable_candidate_sha256=durable_candidate,
        )
        if not hmac.compare_digest(
            candidate_sha256,
            decision.candidate_sha256,
        ):
            raise PaidMediaOperatorRecoveryError(
                "operator recovery continuation evidence conflicts"
            )
        candidate = _InspectedCandidate(
            receipt_candidate=PreparedRecoveryCandidate(
                operation_id=operation,
                candidate_sha256=candidate_sha256,
                consent_sha256=consent_sha256,
                request_sha256=request_sha256,
                prepared_sha256=decision.prepared_sha256,
            ),
            source_principal_hash=source,
            recipient_principal_hash=recipient,
            task_alias=task_alias,
            processing_result_sha256=processing_result_sha256,
            durable_candidate_sha256=durable_candidate,
        )
        durable_document = self._media_requests.read_asset_success_document(
            turn_id=task_alias.removeprefix("nvt1_"),
            principal_hash=source,
            operation="videos.create",
        )
        if durable_document is None:
            return None
        try:
            parsed = parse_asset_result(durable_document.response)
        except PaidMediaAssetProtocolError as exc:
            raise PaidMediaOperatorRecoveryError(
                "operator recovery continuation evidence conflicts"
            ) from exc
        if (
            parsed.kind != "video"
            or len(parsed.assets) != 1
            or parsed.turn_id != task_alias.removeprefix("nvt1_")
        ):
            raise PaidMediaOperatorRecoveryError(
                "operator recovery continuation evidence conflicts"
            )
        return candidate, durable_document.response

    async def _finish_committed_candidate(
        self,
        *,
        candidate: _InspectedCandidate,
        decision_id: str,
        asset_document: dict[str, object],
        replayed: bool,
    ) -> PaidMediaOperatorRecoveryReceipt:
        archive_receipt = await archive_paid_media_document_for_web(
            self._state,
            principal_hash=candidate.source_principal_hash,
            archive_principal_hash=candidate.recipient_principal_hash,
            asset_document=asset_document,
            now_ms=int(self._wall_clock() * 1000),
        )
        parsed = parse_asset_result(asset_document)
        asset = parsed.assets[0]
        asset_reference = f"nachuan-paid-media://sha256/{asset.sha256}"
        renderer_result = {
            "task_id": candidate.task_alias,
            "status": "completed",
            "video_url": asset_reference,
        }
        result_sha256 = hashlib.sha256(
            _RESULT_DOMAIN + _canonical_json_bytes(renderer_result)
        ).hexdigest()
        ack_receipt_sha256 = hashlib.sha256(
            _ACK_PROOF_DOMAIN
            + candidate.receipt_candidate.operation_id.encode("ascii")
            + b"\x00"
            + result_sha256.encode("ascii")
            + b"\x00"
            + archive_receipt.encode("ascii")
        ).hexdigest()
        row = self._web_ledger.complete_prepared_operator_recovery(
            candidate.receipt_candidate.operation_id,
            source_principal_hash=candidate.source_principal_hash,
            recipient_principal_hash=candidate.recipient_principal_hash,
            expected_request_sha256=candidate.receipt_candidate.request_sha256,
            expected_consent_sha256=candidate.receipt_candidate.consent_sha256,
            expected_processing_result_sha256=(
                candidate.processing_result_sha256
            ),
            renderer_result=renderer_result,
            asset_document=asset_document,
            archive_receipt_sha256=archive_receipt,
            decision_id=decision_id,
            candidate_sha256=candidate.receipt_candidate.candidate_sha256,
            ack_receipt_sha256=ack_receipt_sha256,
            now_ms=int(self._wall_clock() * 1000),
        )
        if not hmac.compare_digest(
            _required_digest(row.get("result_sha256")),
            result_sha256,
        ):
            raise PaidMediaOperatorRecoveryError(
                "operator recovery result proof changed"
            )
        completed = self._receipt_store.complete(
            candidate.receipt_candidate,
            decision_id=decision_id,
            result_sha256=result_sha256,
            archive_receipt_sha256=archive_receipt,
            ack_receipt_sha256=ack_receipt_sha256,
        )
        return self._public_receipt(
            candidate=candidate,
            completed=completed,
            asset_document=asset_document,
            replayed=replayed,
        )

    async def execute(
        self,
        *,
        operation_id: object,
        decision_id: str,
        confirmation: str,
        recipient_principal_hash: object,
    ) -> PaidMediaOperatorRecoveryReceipt:
        try:
            replayed = self._try_completed_replay(
                operation_id=operation_id,
                decision_id=decision_id,
                confirmation=confirmation,
                recipient_principal_hash=recipient_principal_hash,
            )
        except PaidMediaOperatorRecoveryError:
            raise
        except _RECOVERY_DEPENDENCY_ERRORS as exc:
            raise PaidMediaOperatorRecoveryError(
                "operator recovery could not be completed"
            ) from exc
        if replayed is not None:
            return replayed
        try:
            continuation = self._reconstruct_executing_candidate(
                operation_id=operation_id,
                decision_id=decision_id,
                confirmation=confirmation,
                recipient_principal_hash=recipient_principal_hash,
            )
            if continuation is not None:
                candidate, asset_document = continuation
                return await self._finish_committed_candidate(
                    candidate=candidate,
                    decision_id=decision_id,
                    asset_document=asset_document,
                    replayed=True,
                )
        except PaidMediaOperatorRecoveryError:
            raise
        except _RECOVERY_DEPENDENCY_ERRORS as exc:
            raise PaidMediaOperatorRecoveryError(
                "operator recovery could not be completed"
            ) from exc

        try:
            candidate = self._inspect_candidate(
                operation_id=operation_id,
                recipient_principal_hash=recipient_principal_hash,
            )
        except PaidMediaOperatorRecoveryError:
            raise
        except _RECOVERY_DEPENDENCY_ERRORS as exc:
            raise PaidMediaOperatorRecoveryError(
                "operator recovery could not be completed"
            ) from exc
        try:
            self._receipt_store.authorize(
                candidate.receipt_candidate,
                decision_id=decision_id,
                confirmation_text=confirmation,
            )
        except PaidMediaOperatorReceiptError as exc:
            raise PaidMediaOperatorRecoveryError(
                "operator recovery confirmation was rejected"
            ) from exc

        try:
            claim = self._media_requests.claim_prepared_video_recovery(
                task_alias=candidate.task_alias,
                principal_hash=candidate.source_principal_hash,
                installation_epoch=self._installation_epoch,
                expected_candidate_sha256=candidate.durable_candidate_sha256,
            )
        except PaidMediaOperatorRecoveryError:
            raise
        except _RECOVERY_DEPENDENCY_ERRORS as exc:
            raise PaidMediaOperatorRecoveryError(
                "operator recovery could not be completed"
            ) from exc
        committed = False
        try:
            # Deferred import prevents the service module from creating an app
            # dependency and still reuses the one audited local commit path.
            from gateway.app import _commit_prepared_paid_video_asset

            persisted, asset_document = await _commit_prepared_paid_video_asset(
                task_alias=claim.task_alias,
                principal_hash=candidate.source_principal_hash,
                fencing_token=claim.fencing_token,
                provider_result=claim.prepared_provider_response,
                asset_store=self._asset_store,
                prepared_token=claim.prepared_token,
                prepared_asset_response=claim.prepared_asset_response,
                authority_state=self._state,
            )
            if not persisted or not isinstance(asset_document, dict):
                raise PaidMediaOperatorRecoveryError(
                    "operator recovery result could not be committed"
                )
            committed = True
            return await self._finish_committed_candidate(
                candidate=candidate,
                decision_id=decision_id,
                asset_document=asset_document,
                replayed=False,
            )
        except PaidMediaOperatorRecoveryError:
            raise
        except _RECOVERY_DEPENDENCY_ERRORS as exc:
            raise PaidMediaOperatorRecoveryError(
                "operator recovery could not be completed"
            ) from exc
        finally:
            if not committed:
                try:
                    self._media_requests.fail_video_poll(
                        task_alias=claim.task_alias,
                        principal_hash=candidate.source_principal_hash,
                        fencing_token=claim.fencing_token,
                    )
                except Exception:
                    pass
