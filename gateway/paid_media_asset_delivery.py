"""Shared, double-read authority check for paid-media asset delivery."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from fastapi.responses import StreamingResponse
from starlette.concurrency import run_in_threadpool
from starlette.types import Receive, Scope, Send

from gateway.paid_media_asset_protocol import canonical_asset_result
from gateway.paid_media_asset_protocol import parse_asset_ack, parse_asset_result
from gateway.paid_media_asset_store import (
    PaidMediaAssetAuthorizationError,
    PaidMediaAssetStore,
    PaidMediaAssetStoreError,
    PinnedPaidMediaAsset,
)
from gateway.durable_media_requests import DurableMediaRequestUnavailable
from gateway.paid_media_web_archive import (
    PaidMediaWebArchiveUnavailable,
    PaidMediaWebAssetArchive,
)


class PaidMediaAssetDeliveryUnavailable(RuntimeError):
    """The process does not expose the complete paid-media asset authority."""


class _PinnedAssetStreamingResponse(StreamingResponse):
    """Streaming response whose read lease closes on every ASGI exit path."""

    def __init__(
        self,
        pinned: PinnedPaidMediaAsset,
        *,
        headers: Mapping[str, str],
    ) -> None:
        self._pinned = pinned
        super().__init__(
            pinned.iter_chunks(),
            media_type=pinned.media_type,
            headers=dict(headers),
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        try:
            await super().__call__(scope, receive, send)
        finally:
            # Starlette skips BackgroundTask when the client disconnects or
            # the iterator raises.  Keep lease lifetime bound to this response.
            await run_in_threadpool(self._pinned.close)


def pinned_asset_streaming_response(
    pinned: PinnedPaidMediaAsset,
    *,
    headers: Mapping[str, str],
) -> StreamingResponse:
    return _PinnedAssetStreamingResponse(pinned, headers=headers)


async def pin_paid_media_asset_for_principal(
    state: Any,
    *,
    token: str,
    principal_hash: str,
) -> PinnedPaidMediaAsset:
    """Pin one token only while two durable authority reads stay identical.

    Both the privileged engine-session route and the pure-Web materializer use
    this exact check.  Callers map authorization/protocol failures to 404 and
    authority/storage failures to 503 without exposing whether a token exists.
    """

    return await run_in_threadpool(
        _pin_paid_media_asset_for_principal_sync,
        state,
        token=token,
        principal_hash=principal_hash,
    )


def _pin_paid_media_asset_for_principal_sync(
    state: Any,
    *,
    token: str,
    principal_hash: str,
) -> PinnedPaidMediaAsset:
    """Synchronous authority pin used by both streaming and atomic archiving."""

    asset_store = getattr(state, "paid_media_assets", None)
    request_store = getattr(state, "media_requests", None)
    epoch = getattr(state, "paid_media_epoch", None)
    if (
        not isinstance(asset_store, PaidMediaAssetStore)
        or request_store is None
        or isinstance(epoch, bool)
        or not isinstance(epoch, int)
        or epoch < 1
    ):
        raise PaidMediaAssetDeliveryUnavailable(
            "paid-media asset delivery authority is unavailable"
        )

    locator = asset_store.locate_token(token)
    first = request_store.read_unacked_asset_success_document(
        turn_id=locator.turn_id,
        principal_hash=principal_hash,
        operation=locator.operation,
    )
    if first is None:
        raise PaidMediaAssetAuthorizationError("asset authority is unavailable")
    first_canonical = canonical_asset_result(first.response)
    pinned = asset_store.pin_authorized(
        token=token,
        durable_result=first.response,
        principal_hash=principal_hash,
        epoch=epoch,
    )
    try:
        second = request_store.read_unacked_asset_success_document(
            turn_id=locator.turn_id,
            principal_hash=principal_hash,
            operation=locator.operation,
        )
        if second is None or canonical_asset_result(second.response) != first_canonical:
            raise PaidMediaAssetAuthorizationError(
                "asset authority changed while pinning"
        )
    except BaseException:
        pinned.close()
        raise
    return pinned


def _archive_document_incrementally_sync(
    state: Any,
    *,
    archive: PaidMediaWebAssetArchive,
    authority_principal_hash: str,
    archive_principal_hash: str,
    result: Any,
    installation_id: str,
    epoch: int,
    now_ms: int,
) -> str:
    """Store at most one materialized asset at a time under one archive fence."""

    # The durable batch receipt stays dirty across every asset and the final
    # document commit.  A different process therefore recovers a hard-crashed
    # partial instead of mistaking the interval between assets for clean state.
    with archive.document_batch(
        principal_hash=archive_principal_hash,
        result=result,
        installation_id=installation_id,
        installation_epoch=epoch,
        now_ms=now_ms,
    ) as batch:
        for asset in result.assets:
            pinned = _pin_paid_media_asset_for_principal_sync(
                state,
                token=asset.token,
                principal_hash=authority_principal_hash,
            )
            try:
                if (
                    pinned.media_type != asset.media_type
                    or pinned.byte_length != asset.byte_length
                    or pinned.sha256 != asset.sha256
                ):
                    raise PaidMediaAssetAuthorizationError(
                        "paid-media Web archive descriptor differs from authority"
                    )
                payload = b"".join(pinned.iter_chunks())
            finally:
                pinned.close()
            batch.store_asset(asset=asset, payload=payload)
            # Assignment of the next joined payload must not briefly retain
            # this complete object as well.
            del payload
        return batch.commit()


async def archive_paid_media_document_for_web(
    state: Any,
    *,
    principal_hash: str,
    archive_principal_hash: str | None = None,
    asset_document: object,
    now_ms: int,
) -> str:
    """Archive the complete result, then idempotently release its authority.

    The archive receipt is committed only after all closed-set assets have been
    copied and verified.  Durable ACK, object cleanup, and reservation release
    follow in that order; replay resumes safely after a crash at any boundary.
    """

    asset_store = getattr(state, "paid_media_assets", None)
    request_store = getattr(state, "media_requests", None)
    archive = getattr(state, "paid_media_web_archive", None)
    epoch = getattr(state, "paid_media_epoch", None)
    installation_id = getattr(state, "paid_media_installation_id", None)
    if (
        not isinstance(asset_store, PaidMediaAssetStore)
        or request_store is None
        or not isinstance(archive, PaidMediaWebAssetArchive)
        or isinstance(epoch, bool)
        or not isinstance(epoch, int)
        or epoch < 1
        or not isinstance(installation_id, str)
    ):
        raise PaidMediaAssetDeliveryUnavailable(
            "paid-media Web archive authority is unavailable"
        )
    result = parse_asset_result(asset_document)
    operation = "images.create" if result.kind == "image" else "videos.create"
    destination_principal = (
        principal_hash
        if archive_principal_hash is None
        else archive_principal_hash
    )
    receipt = await run_in_threadpool(
        archive.receipt_for_document,
        principal_hash=destination_principal,
        result=result,
        installation_id=installation_id,
        installation_epoch=epoch,
    )
    if receipt is None:
        try:
            receipt = await run_in_threadpool(
                _archive_document_incrementally_sync,
                state,
                archive=archive,
                authority_principal_hash=principal_hash,
                archive_principal_hash=destination_principal,
                result=result,
                installation_id=installation_id,
                epoch=epoch,
                now_ms=now_ms,
            )
        except (
            PaidMediaAssetDeliveryUnavailable,
            PaidMediaAssetAuthorizationError,
            PaidMediaAssetStoreError,
            DurableMediaRequestUnavailable,
            OSError,
        ):
            # A different process may have committed the same deterministic
            # archive receipt and ACKed the live authority after our first
            # lookup.  Accept only a full byte-and-metadata revalidation.
            receipt = await run_in_threadpool(
                archive.receipt_for_document,
                principal_hash=destination_principal,
                result=result,
                installation_id=installation_id,
                installation_epoch=epoch,
            )
            if receipt is None:
                raise

    ack = parse_asset_ack(
        {
            "schema": "nachuan.paid-media-asset-ack.v1",
            "turnId": result.turn_id,
            "tokens": [asset.token for asset in result.assets],
            "archiveReceiptSha256": receipt,
        }
    )
    durable_receipt = await run_in_threadpool(
        request_store.ack_asset_success,
        turn_id=result.turn_id,
        principal_hash=principal_hash,
        operation=operation,
        installation_epoch=epoch,
        tokens=list(ack.tokens),
        archive_receipt_sha256=receipt,
    )
    cleanup = await run_in_threadpool(
        asset_store.ack,
        ack=ack,
        durable_result=asset_document,
        principal_hash=principal_hash,
        epoch=epoch,
        operation=operation,
    )
    if not cleanup.cleanup_complete:
        raise PaidMediaWebArchiveUnavailable(
            "paid-media Web archive cleanup is still pending"
        )
    completed = await run_in_threadpool(
        request_store.complete_asset_ack_cleanup,
        turn_id=result.turn_id,
        principal_hash=principal_hash,
        operation=operation,
        installation_epoch=epoch,
        token_set_digest=durable_receipt.token_set_digest,
        archive_receipt_sha256=receipt,
    )
    if not completed:
        raise DurableMediaRequestUnavailable(
            "paid-media Web archive cleanup completion was not committed"
        )
    return receipt
