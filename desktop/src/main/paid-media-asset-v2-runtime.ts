import {
  buildPaidMediaAssetAck,
  paidMediaAssetResultDigest,
  paidMediaTokenSetDigest,
  parsePaidMediaAssetResult,
  type PaidMediaAssetAck,
  type PaidMediaAssetResult
} from './paid-media-asset-protocol'
import type {
  PaidMediaAssetAckResult,
  PaidMediaImageAssetCreateResult
} from './paid-media-asset-client'
import type { PaidMediaCapacityReservation } from './paid-media-capacity'
import type { PaidMediaPublicOperation } from './paid-media-ledger'
import type {
  PaidMediaAssetV2ExecutionInput,
  PaidMediaAssetV2ExecutionResult
} from './paid-media-service'
import type {
  PaidMediaRecoveryIntentDescriptor,
  PaidMediaRecoveryIntentPayload
} from './paid-media-recovery-intent'
import type {
  PaidMediaAssetAckCompletion,
  PaidMediaAssetAckIntent,
  PaidMediaAssetCapacityReleaseAuthorization,
  PaidMediaArchivedResult,
  PaidMediaSealedStageCapability,
  PaidMediaSealedStageReadSource,
  PaidMediaStageOpenResult,
  PaidMediaStageRecoveryInspection,
  PaidMediaStageWriteCapability,
  PaidMediaV2DispatchMarker,
  PaidMediaValidationReceipt
} from './paid-media-vault'

const OPERATION_ID_PATTERN =
  /^desktop-op-[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
const SHA256_PATTERN = /^[0-9a-f]{64}$/
const ZERO_SHA256 = '0'.repeat(64)

export type PaidMediaRunRecoverableMutation = (
  payload: PaidMediaRecoveryIntentPayload
) => Promise<PaidMediaRecoveryIntentDescriptor>

export interface PaidMediaAssetV2AckConvergenceInput {
  operationId: string
  signal: AbortSignal
  runRecoverableMutation: PaidMediaRunRecoverableMutation
}

interface PaidMediaAssetV2RuntimeVault {
  verifyArchive(operationId: string): Promise<PaidMediaArchivedResult>
  verifyAssetV2DispatchMarker(operationId: string): Promise<PaidMediaV2DispatchMarker>
  verifyAssetAckIntent(operationId: string): Promise<PaidMediaAssetAckIntent>
  hasAssetAckCompletion(operationId: string): boolean
  verifyAssetAckCompletion(operationId: string): Promise<PaidMediaAssetAckCompletion>
  hasAssetCapacityReleaseAuthorization(operationId: string): boolean
  verifyAssetCapacityReleaseAuthorization(
    operationId: string
  ): Promise<PaidMediaAssetCapacityReleaseAuthorization>
  inspectStageRecovery(): Promise<PaidMediaStageRecoveryInspection>
  sealStageWriteCapability(
    stage: PaidMediaStageWriteCapability
  ): Promise<PaidMediaSealedStageCapability>
  createSealedStageReadSource(
    sealed: PaidMediaSealedStageCapability
  ): PaidMediaSealedStageReadSource
}

export interface PaidMediaAssetV2RuntimeDependencies {
  authority: {
    assertOutboundReady(): Promise<unknown>
    localPaidPrincipal(): string
  }
  ledger: { listPublic(): Promise<PaidMediaPublicOperation[]> }
  capacity: { listReservations(): Promise<PaidMediaCapacityReservation[]> }
  vault: PaidMediaAssetV2RuntimeVault
  stageHandoff: { takeStageOpenResult(descriptor: unknown): PaidMediaStageOpenResult | null }
  createImageAssets(input: {
    encodedBody: string
    idempotencyKey: string
    signal: AbortSignal
  }): Promise<PaidMediaImageAssetCreateResult>
  downloadAsset(input: {
    stage: PaidMediaStageWriteCapability
    signal: AbortSignal
  }): Promise<unknown>
  probeAsset(input: {
    descriptor: PaidMediaAssetResult['assets'][number]
    source: PaidMediaSealedStageReadSource
    signal: AbortSignal
  }): Promise<PaidMediaValidationReceipt>
  acknowledgeAssets(input: {
    ack: PaidMediaAssetAck
    signal: AbortSignal
  }): Promise<PaidMediaAssetAckResult>
  audit(event: string, fields: Record<string, unknown>): void
}

export class PaidMediaAssetV2RuntimeError extends Error {
  override readonly name = 'PaidMediaAssetV2RuntimeError'
}

function fail(message: string): PaidMediaAssetV2RuntimeError {
  return new PaidMediaAssetV2RuntimeError(message)
}

function nonzeroDigest(value: unknown): value is string {
  return typeof value === 'string' && SHA256_PATTERN.test(value) && value !== ZERO_SHA256
}

export async function convergePaidMediaAssetV2StartupAcks(input: {
  runtime: Pick<PaidMediaAssetV2Runtime, 'convergeImageAck'>
  operations: readonly PaidMediaPublicOperation[]
  runRecoverableMutation: PaidMediaRunRecoverableMutation
  signal: AbortSignal
  onError(operationId: string, error: unknown): void
}): Promise<void> {
  const candidates = input.operations.filter(
    (operation) =>
      operation.path === '/v1/images/generations' &&
      operation.state === 'result_ready' &&
      nonzeroDigest(operation.v2DispatchReceiptSha256) &&
      nonzeroDigest(operation.v2AckIntentReceiptSha256)
  )
  for (const operation of candidates) {
    try {
      await input.runtime.convergeImageAck({
        operationId: operation.operationId,
        signal: input.signal,
        runRecoverableMutation: input.runRecoverableMutation
      })
    } catch (error) {
      input.onError(operation.operationId, error)
    }
  }
}

export class PaidMediaAssetV2Runtime {
  private readonly ackFlights = new Map<string, Promise<boolean>>()

  constructor(private readonly dependencies: PaidMediaAssetV2RuntimeDependencies) {}

  async executeImage(
    input: PaidMediaAssetV2ExecutionInput
  ): Promise<PaidMediaAssetV2ExecutionResult> {
    await this.dependencies.authority.assertOutboundReady()
    const rootedPrincipal = this.dependencies.authority.localPaidPrincipal()
    if (
      input.path !== '/v1/images/generations' ||
      !nonzeroDigest(rootedPrincipal) ||
      input.recoveryDomainSha256 !== rootedPrincipal
    ) {
      throw fail('Paid media asset-v2 rooted request binding conflicts')
    }

    let operation = await this.operation(input.operationId)
    let dispatch: PaidMediaV2DispatchMarker
    if (
      operation.state === 'dispatching' &&
      operation.dispatchCount === 1 &&
      nonzeroDigest(operation.v2DispatchReceiptSha256)
    ) {
      dispatch = await this.dependencies.vault.verifyAssetV2DispatchMarker(
        input.operationId
      )
    } else {
      await input.runRecoverableMutation({
        kind: 'asset_v2_dispatch',
        operationId: input.operationId,
        claim: {
          path: input.path,
          requestSha256: input.requestSha256,
          recoveryDomainSha256: input.recoveryDomainSha256
        },
        paidPrincipalSha256: rootedPrincipal
      })
      ;[dispatch, operation] = await Promise.all([
        this.dependencies.vault.verifyAssetV2DispatchMarker(input.operationId),
        this.operation(input.operationId)
      ])
    }
    const reservation = (await this.dependencies.capacity.listReservations()).find(
      (candidate) => candidate.operationId === input.operationId
    )
    if (
      dispatch.operationId !== input.operationId ||
      dispatch.path !== input.path ||
      dispatch.requestSha256 !== input.requestSha256 ||
      dispatch.recoveryDomainSha256 !== rootedPrincipal ||
      dispatch.paidPrincipalSha256 !== rootedPrincipal ||
      dispatch.receiptSha256 !== operation.v2DispatchReceiptSha256 ||
      operation.state !== 'dispatching' ||
      operation.dispatchCount !== 1 ||
      !reservation ||
      reservation.path !== input.path ||
      reservation.phase !== 'active'
    ) {
      throw fail('Paid media asset-v2 dispatch evidence conflicts')
    }

    const created = await this.dependencies.createImageAssets({
      encodedBody: input.encodedBody,
      idempotencyKey: input.idempotencyKey,
      signal: input.signal
    })
    if (!created.ok) {
      return {
        ok: false,
        status: created.status,
        detail: `Paid media asset-v2 request failed (${created.code})`,
        ...(created.retryAfterSeconds === undefined
          ? {}
          : { retryAfterSeconds: created.retryAfterSeconds }),
        operation
      }
    }

    const resultSha256 = paidMediaAssetResultDigest(created.result)
    const beforeStage = await this.dependencies.vault.inspectStageRecovery()
    const currentLeases = beforeStage.leases
      .filter((lease) => lease.operationId === input.operationId)
      .sort((left, right) => left.ordinal - right.ordinal)
    const reservePayload: Extract<
      PaidMediaRecoveryIntentPayload,
      { kind: 'asset_v2_stage_reserve' }
    > =
      currentLeases.length === 0
        ? {
            kind: 'asset_v2_stage_reserve',
            operationId: input.operationId,
            mode: 'fresh',
            result: created.result
          }
        : {
            kind: 'asset_v2_stage_reserve',
            operationId: input.operationId,
            mode: 'reclaim',
            result: created.result,
            leases: currentLeases.map((lease, ordinal) => {
              if (
                currentLeases.length !== created.result.assets.length ||
                lease.ordinal !== ordinal ||
                lease.turnId !== created.result.turnId ||
                lease.resultSha256 !== resultSha256 ||
                lease.state !== 'opened' ||
                lease.disposition !== 'reclaim'
              ) {
                throw fail('Paid media asset-v2 stage reclaim evidence conflicts')
              }
              return {
                leaseId: lease.leaseId,
                ordinal,
                generation: lease.generation,
                resultSha256: lease.resultSha256,
                leaseStateDigest: lease.leaseStateDigest
              }
            })
          }
    const reserveDescriptor = await input.runRecoverableMutation(reservePayload)
    const opened = this.dependencies.stageHandoff.takeStageOpenResult(reserveDescriptor)
    if (!opened || !opened.ok) {
      return {
        ok: false,
        status: 0,
        detail:
          opened?.held === true
            ? 'Paid media asset-v2 stage is held for manual recovery'
            : 'Paid media asset-v2 stage capability handoff is unavailable',
        operation
      }
    }

    const validations: PaidMediaValidationReceipt[] = []
    try {
      for (const stage of opened.capabilities) {
        await this.dependencies.downloadAsset({ stage, signal: input.signal })
        const sealed = await this.dependencies.vault.sealStageWriteCapability(stage)
        const validation = await this.dependencies.probeAsset({
          descriptor: sealed.descriptor,
          source: this.dependencies.vault.createSealedStageReadSource(sealed),
          signal: input.signal
        })
        if (sealed.ordinal !== validations.length) {
          throw fail('Paid media asset-v2 sealed stage order conflicts')
        }
        validations.push(validation)
      }
    } catch (error) {
      try {
        const inspection = await this.dependencies.vault.inspectStageRecovery()
        const leases = inspection.leases
          .filter((lease) => lease.operationId === input.operationId)
          .map((lease) => ({
            leaseId: lease.leaseId,
            generation: lease.generation,
            resultSha256: lease.resultSha256,
            leaseStateDigest: lease.leaseStateDigest
          }))
        if (leases.length > 0) {
          await input.runRecoverableMutation({
            kind: 'asset_v2_stage_cleanup',
            operationId: input.operationId,
            leases
          })
        }
      } catch (cleanupError) {
        this.dependencies.audit('paid_media.asset_v2_stage_cleanup_failed', {
          operation_id: input.operationId,
          reason: cleanupError instanceof Error ? cleanupError.name : 'unknown'
        })
      }
      throw error
    }

    const archiveInspection = await this.dependencies.vault.inspectStageRecovery()
    const archiveLeases = archiveInspection.leases
      .filter((lease) => lease.operationId === input.operationId)
      .sort((left, right) => left.ordinal - right.ordinal)
      .map((lease, ordinal) => {
        if (
          lease.ordinal !== ordinal ||
          lease.turnId !== created.result.turnId ||
          lease.resultSha256 !== resultSha256 ||
          lease.state !== 'opened' ||
          lease.disposition !== 'reclaim'
        ) {
          throw fail('Paid media asset-v2 archive lease evidence conflicts')
        }
        return {
          leaseId: lease.leaseId,
          ordinal,
          generation: lease.generation,
          resultSha256: lease.resultSha256,
          leaseStateDigest: lease.leaseStateDigest
        }
      })
    if (
      archiveLeases.length !== created.result.assets.length ||
      validations.length !== created.result.assets.length
    ) {
      throw fail('Paid media asset-v2 archive evidence count conflicts')
    }
    await input.runRecoverableMutation({
      kind: 'asset_v2_stage_archive',
      operationId: input.operationId,
      result: created.result,
      leases: archiveLeases,
      validations
    })
    const archived = await this.dependencies.vault.verifyArchive(input.operationId)
    if (
      archived.receipt.operationId !== input.operationId ||
      archived.receipt.status !== 200 ||
      paidMediaAssetResultDigest(parsePaidMediaAssetResult(archived.result)) !==
        resultSha256
    ) {
      throw fail('Paid media asset-v2 archive postcondition conflicts')
    }
    const ack = buildPaidMediaAssetAck(
      created.result,
      archived.receipt.receiptSha256
    )
    await input.runRecoverableMutation({
      kind: 'asset_v2_result_ready_ack_intent',
      operationId: input.operationId,
      result: created.result,
      archive: {
        receiptSha256: archived.receipt.receiptSha256,
        cleanupComplete: archived.cleanupComplete
      },
      dispatch: { receiptSha256: dispatch.receiptSha256 },
      ack
    })
    const [ackIntent, readyOperation] = await Promise.all([
      this.dependencies.vault.verifyAssetAckIntent(input.operationId),
      this.operation(input.operationId)
    ])
    if (
      readyOperation.state !== 'result_ready' ||
      readyOperation.v2DispatchReceiptSha256 !== dispatch.receiptSha256 ||
      readyOperation.v2AckIntentReceiptSha256 !== ackIntent.receiptSha256 ||
      ackIntent.archiveReceiptSha256 !== archived.receipt.receiptSha256 ||
      ackIntent.assetResultSha256 !== resultSha256
    ) {
      throw fail('Paid media asset-v2 result-ready evidence conflicts')
    }
    await this.convergeImageAck({
      operationId: input.operationId,
      signal: input.signal,
      runRecoverableMutation: input.runRecoverableMutation
    })
    return { ok: true, archived, operation: readyOperation }
  }

  private async operation(operationId: string): Promise<PaidMediaPublicOperation> {
    const operation = (await this.dependencies.ledger.listPublic()).find(
      (candidate) => candidate.operationId === operationId
    )
    if (!operation) throw fail('Paid media asset-v2 ledger operation is unavailable')
    return operation
  }

  convergeImageAck(input: PaidMediaAssetV2AckConvergenceInput): Promise<boolean> {
    if (
      !input ||
      typeof input !== 'object' ||
      typeof input.operationId !== 'string' ||
      !OPERATION_ID_PATTERN.test(input.operationId) ||
      !(input.signal instanceof AbortSignal) ||
      typeof input.runRecoverableMutation !== 'function'
    ) {
      return Promise.reject(fail('Paid media asset-v2 ACK convergence input is invalid'))
    }
    const current = this.ackFlights.get(input.operationId)
    if (current) return current
    const pending = this.convergeImageAckOnce(input)
    this.ackFlights.set(input.operationId, pending)
    return pending.finally(() => {
      if (this.ackFlights.get(input.operationId) === pending) {
        this.ackFlights.delete(input.operationId)
      }
    })
  }

  private async convergeImageAckOnce(
    input: PaidMediaAssetV2AckConvergenceInput
  ): Promise<boolean> {
    await this.dependencies.authority.assertOutboundReady()
    const operation = (await this.dependencies.ledger.listPublic()).find(
      (candidate) => candidate.operationId === input.operationId
    )
    if (
      !operation ||
      operation.path !== '/v1/images/generations' ||
      operation.state !== 'result_ready' ||
      operation.dispatchCount !== 1 ||
      !nonzeroDigest(operation.v2DispatchReceiptSha256) ||
      !nonzeroDigest(operation.v2AckIntentReceiptSha256)
    ) {
      throw fail('Paid media asset-v2 ACK convergence ledger evidence is unavailable')
    }
    const [archive, dispatch, ackIntent] = await Promise.all([
      this.dependencies.vault.verifyArchive(input.operationId),
      this.dependencies.vault.verifyAssetV2DispatchMarker(input.operationId),
      this.dependencies.vault.verifyAssetAckIntent(input.operationId)
    ])
    const rootedPrincipal = this.dependencies.authority.localPaidPrincipal()
    const archiveResult = parsePaidMediaAssetResult(archive.result)
    const tokens = archiveResult.assets.map((asset) => asset.token)
    if (
      !nonzeroDigest(rootedPrincipal) ||
      archive.receipt.operationId !== input.operationId ||
      archive.receipt.status !== 200 ||
      dispatch.operationId !== input.operationId ||
      dispatch.path !== '/v1/images/generations' ||
      dispatch.receiptSha256 !== operation.v2DispatchReceiptSha256 ||
      dispatch.recoveryDomainSha256 !== rootedPrincipal ||
      dispatch.paidPrincipalSha256 !== rootedPrincipal ||
      ackIntent.operationId !== input.operationId ||
      ackIntent.receiptSha256 !== operation.v2AckIntentReceiptSha256 ||
      ackIntent.dispatchReceiptSha256 !== dispatch.receiptSha256 ||
      ackIntent.archiveReceiptSha256 !== archive.receipt.receiptSha256 ||
      ackIntent.turnId !== archiveResult.turnId ||
      ackIntent.assetResultSha256 !== paidMediaAssetResultDigest(archiveResult) ||
      ackIntent.tokenSetDigest !== paidMediaTokenSetDigest(tokens)
    ) {
      throw fail('Paid media asset-v2 ACK convergence evidence conflicts')
    }

    let completion: PaidMediaAssetAckCompletion
    if (this.dependencies.vault.hasAssetAckCompletion(input.operationId)) {
      completion = await this.dependencies.vault.verifyAssetAckCompletion(input.operationId)
    } else {
      const ack = buildPaidMediaAssetAck(
        archiveResult,
        archive.receipt.receiptSha256
      )
      const remote = await this.dependencies.acknowledgeAssets({
        ack,
        signal: input.signal
      })
      if (!remote.ok || !remote.cleanupComplete) {
        this.dependencies.audit('paid_media.asset_v2_ack_pending', {
          operation_id: input.operationId,
          status: remote.ok ? 202 : remote.status
        })
        return false
      }
      await input.runRecoverableMutation({
        kind: 'asset_v2_ack_completion',
        operationId: input.operationId,
        intentReceiptSha256: ackIntent.receiptSha256,
        status: 200,
        response: {
          ok: true,
          turnId: archiveResult.turnId,
          replayed: remote.replayed,
          cleanupComplete: true
        }
      })
      completion = await this.dependencies.vault.verifyAssetAckCompletion(
        input.operationId
      )
    }
    if (
      completion.operationId !== input.operationId ||
      completion.intentReceiptSha256 !== ackIntent.receiptSha256 ||
      completion.status !== 200 ||
      completion.turnId !== archiveResult.turnId ||
      !completion.ok ||
      !completion.cleanupComplete ||
      !nonzeroDigest(completion.receiptSha256)
    ) {
      throw fail('Paid media asset-v2 ACK completion evidence conflicts')
    }

    if (archive.cleanupComplete) {
      let authorization: PaidMediaAssetCapacityReleaseAuthorization
      if (
        this.dependencies.vault.hasAssetCapacityReleaseAuthorization(input.operationId)
      ) {
        authorization =
          await this.dependencies.vault.verifyAssetCapacityReleaseAuthorization(
            input.operationId
          )
      } else {
        await input.runRecoverableMutation({
          kind: 'asset_v2_capacity_release',
          operationId: input.operationId,
          archive: {
            receiptSha256: archive.receipt.receiptSha256,
            cleanupComplete: true
          },
          dispatch: { receiptSha256: dispatch.receiptSha256 },
          ackCompletion: { receiptSha256: completion.receiptSha256 }
        })
        authorization =
          await this.dependencies.vault.verifyAssetCapacityReleaseAuthorization(
            input.operationId
          )
      }
      if (
        authorization.operationId !== input.operationId ||
        authorization.archiveReceiptSha256 !== archive.receipt.receiptSha256 ||
        authorization.dispatchReceiptSha256 !== dispatch.receiptSha256 ||
        authorization.ackCompletionReceiptSha256 !== completion.receiptSha256 ||
        !authorization.cleanupComplete ||
        !nonzeroDigest(authorization.receiptSha256)
      ) {
        throw fail('Paid media asset-v2 capacity release evidence conflicts')
      }
    }
    return true
  }
}
