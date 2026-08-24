import { createHash } from 'node:crypto'

import {
  PAID_MEDIA_CAPACITY_BUDGET_POLICY,
  type PaidMediaCapacityReleaseTombstone,
  type PaidMediaCapacityReservation
} from './paid-media-capacity'
import {
  PAID_MEDIA_RECOVERABLE_HANDLER_VERSION,
  PaidMediaRecoverableMutationConflictError,
  paidMediaCompositeEvidenceDigest,
  type PaidMediaInstallationRootState,
  type PaidMediaRecoverableMutationDescriptor,
  type PaidMediaRecoverableMutationExecutor,
  type PaidMediaRecoverableMutationKind
} from './paid-media-installation-root'
import type {
  PaidMediaPublicOperation,
  PaidMediaV2DispatchInput,
  PaidMediaV2ResultReadyInput
} from './paid-media-ledger'
import {
  canonicalPaidMediaAssetResult,
  paidMediaAssetResultDigest,
  paidMediaTokenSetDigest
} from './paid-media-asset-protocol'
import {
  PaidMediaRecoveryIntentError,
  type PaidMediaRecoveryIntentDescriptor,
  type PaidMediaRecoveryIntentPayload
} from './paid-media-recovery-intent'
import { PaidMediaMutationGate } from './paid-media-mutation-gate'
import type {
  PaidMediaStageOpenResult,
  PaidMediaStageReclaimResult,
  PaidMediaStageRecoveryInspection,
  PaidMediaStageWriteCapability
} from './paid-media-vault'

const RECEIPT_SCHEMA = 'nachuan.paid-media-recovery-executor.receipt.v1'
const RECEIPT_DOMAIN = Buffer.from('nachuan.desktop.paid-media-recovery-executor.v1\0', 'ascii')
const SHA256_PATTERN = /^[0-9a-f]{64}$/
const ZERO_SHA256 = '0'.repeat(64)
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
const OPERATION_ID_PATTERN = /^desktop-op-[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
const MAX_RECEIPT_BYTES = 4096

const RECOVERABLE_KINDS = new Set<PaidMediaRecoverableMutationKind>([
  'asset_v2_dispatch',
  'asset_v2_stage_reserve',
  'asset_v2_stage_archive',
  'asset_v2_stage_cleanup',
  'asset_v2_result_ready_ack_intent',
  'asset_v2_ack_completion',
  'asset_v2_capacity_release'
])

interface PaidMediaRecoveryAuthority {
  readonly state: PaidMediaInstallationRootState
  assertMutationContext(transactionId?: string): void
  localPaidPrincipal(): string
}

interface PaidMediaRecoveryLedger {
  ensureV2DispatchingOnce(input: PaidMediaV2DispatchInput): Promise<
    Pick<
      PaidMediaPublicOperation,
      'operationId' | 'state' | 'dispatchCount' | 'v2DispatchReceiptSha256'
    >
  >
  ensureV2ResultReadyOnce(input: PaidMediaV2ResultReadyInput): Promise<
    Pick<
      PaidMediaPublicOperation,
      | 'operationId'
      | 'state'
      | 'dispatchCount'
      | 'v2DispatchReceiptSha256'
      | 'v2AckIntentReceiptSha256'
    >
  >
}

interface PaidMediaRecoveryLocalReceipt {
  operationId: string
  receiptSha256: string
}

interface PaidMediaRecoveryVault {
  verifyArchive(operationId: string): Promise<{
    receipt: {
      operationId: string
      receiptSha256: string
      responseSha256: string
      responseByteLength: number
    }
    recoveryJson: string
    cleanupComplete: boolean
  }>
  recordAssetV2DispatchMarker(input: {
    operationId: string
    path: '/v1/images/generations' | '/v1/videos/generations'
    requestSha256: string
    recoveryDomainSha256: string
    paidPrincipalSha256: string
    turnId: string | null
    assetResultSha256: string | null
  }): Promise<PaidMediaRecoveryLocalReceipt>
  recordAssetAckIntent(input: {
    operationId: string
    turnId: string
    tokens: readonly string[]
    tokenSetDigest: string
    archiveReceiptSha256: string
    assetResultSha256: string
    dispatchReceiptSha256: string
  }): Promise<PaidMediaRecoveryLocalReceipt>
  recordAssetAckCompletion(input: {
    operationId: string
    intentReceiptSha256: string
    status: 200
    response: {
      ok: true
      turnId: string
      replayed: boolean
      cleanupComplete: true
    }
  }): Promise<PaidMediaRecoveryLocalReceipt>
  recordAssetCapacityReleaseAuthorization(input: {
    operationId: string
    archive: { receiptSha256: string; cleanupComplete: true }
    dispatch: { receiptSha256: string }
    ackCompletion: { receiptSha256: string }
  }): Promise<PaidMediaRecoveryLocalReceipt>
  reserveAndOpenStageLeases(input: {
    operationId: string
    result: Extract<
      PaidMediaRecoveryIntentPayload,
      { kind: 'asset_v2_stage_reserve' }
    >['result']
  }): Promise<PaidMediaStageOpenResult>
  reclaimStageLease(input: {
    operationId: string
    result: Extract<
      PaidMediaRecoveryIntentPayload,
      { kind: 'asset_v2_stage_reserve' }
    >['result']
    leaseId: string
  }): Promise<PaidMediaStageReclaimResult>
  inspectStageRecovery(): Promise<PaidMediaStageRecoveryInspection>
  cleanupStageLease(input: {
    operationId: string
    leaseId: string
    generation: number
    resultSha256: string
  }): Promise<{ status: 'cleaned' | 'pending' | 'held' }>
  archiveRecoveredStageImageResult(input: {
    operationId: string
    status: 200
    result: Extract<
      PaidMediaRecoveryIntentPayload,
      { kind: 'asset_v2_stage_archive' }
    >['result']
    leases: Extract<
      PaidMediaRecoveryIntentPayload,
      { kind: 'asset_v2_stage_archive' }
    >['leases']
    validations: Extract<
      PaidMediaRecoveryIntentPayload,
      { kind: 'asset_v2_stage_archive' }
    >['validations']
  }): Promise<Awaited<ReturnType<PaidMediaRecoveryVault['verifyArchive']>>>
}

interface PaidMediaRecoveryCapacity {
  ensureReservation(input: {
    operationId: string
    path: '/v1/images/generations' | '/v1/videos/generations'
    allowCreate: boolean
  }): Promise<PaidMediaCapacityReservation>
  ensureReleasedWithAuthorization(input: {
    operationId: string
    authorizationReceiptSha256: string
  }): Promise<PaidMediaCapacityReleaseTombstone>
}

export interface PaidMediaRecoveryExecutorDependencies {
  authority: PaidMediaRecoveryAuthority
  gate: PaidMediaMutationGate
  intentStore: {
    read(descriptor: unknown): PaidMediaRecoveryIntentPayload
  }
  ledger: PaidMediaRecoveryLedger
  vault: PaidMediaRecoveryVault
  capacity: PaidMediaRecoveryCapacity
}

export type PaidMediaRecoveryExecutionLocalEvidence =
  | Readonly<{
      state: 'dispatching'
      dispatchCount: 1
      dispatchReceiptSha256: string
    }>
  | Readonly<{
      state: 'result_ready'
      dispatchCount: 1
      dispatchReceiptSha256: string
      ackIntentReceiptSha256: string
    }>
  | Readonly<{
      state: 'ack_completed'
      ackCompletionReceiptSha256: string
    }>
  | Readonly<{
      state: 'capacity_released'
      capacityReleaseReceiptSha256: string
    }>
  | Readonly<{
      state: 'stage_reserved'
      resultSha256: string
      leases: readonly Readonly<{
        leaseId: string
        generation: number
        leaseStateDigest: string
      }>[]
    }>
  | Readonly<{
      state: 'stage_cleaned'
      leases: readonly Readonly<{
        leaseId: string
        generation: number
      }>[]
    }>
  | Readonly<{
      state: 'stage_archived'
      resultSha256: string
      archiveReceiptSha256: string
      cleanupComplete: boolean
    }>

export interface PaidMediaRecoveryExecutionReceipt {
  readonly schema: typeof RECEIPT_SCHEMA
  readonly handlerVersion: typeof PAID_MEDIA_RECOVERABLE_HANDLER_VERSION
  readonly kind: PaidMediaRecoverableMutationKind
  readonly operationId: string
  readonly intentSha256: string
  readonly status: 'verified'
  readonly localEvidence: PaidMediaRecoveryExecutionLocalEvidence
  readonly receiptSha256: string
}

export class PaidMediaRecoveryExecutorError extends Error {
  override readonly name = 'PaidMediaRecoveryExecutorError'
}

export class PaidMediaRecoveryExecutorConflictError extends PaidMediaRecoverableMutationConflictError {
  override readonly name = 'PaidMediaRecoveryExecutorConflictError'
}

function fail(message: string, cause?: unknown): PaidMediaRecoveryExecutorError {
  return new PaidMediaRecoveryExecutorError(
    message,
    cause === undefined ? undefined : { cause }
  )
}

function conflict(message: string, cause?: unknown): PaidMediaRecoveryExecutorConflictError {
  return new PaidMediaRecoveryExecutorConflictError(
    message,
    cause === undefined ? undefined : { cause }
  )
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort()
  const wanted = [...expected].sort()
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index])
}

function nonzeroDigest(value: unknown): value is string {
  return typeof value === 'string' && SHA256_PATTERN.test(value) && value !== ZERO_SHA256
}

function canonicalDescriptor(value: unknown): PaidMediaRecoverableMutationDescriptor {
  if (
    !isRecord(value) ||
    !exactKeys(value, [
      'mode',
      'handlerVersion',
      'kind',
      'operationId',
      'intentSha256',
      'transactionId',
      'preparedAt',
      'beforeCompositeDigest',
      'beforeAuthorityEvidence'
    ]) ||
    value.mode !== 'recoverable' ||
    value.handlerVersion !== PAID_MEDIA_RECOVERABLE_HANDLER_VERSION ||
    typeof value.kind !== 'string' ||
    !RECOVERABLE_KINDS.has(value.kind as PaidMediaRecoverableMutationKind) ||
    typeof value.operationId !== 'string' ||
    !OPERATION_ID_PATTERN.test(value.operationId) ||
    !nonzeroDigest(value.intentSha256) ||
    typeof value.transactionId !== 'string' ||
    !UUID_PATTERN.test(value.transactionId) ||
    !Number.isSafeInteger(value.preparedAt) ||
    Number(value.preparedAt) < 0 ||
    !nonzeroDigest(value.beforeCompositeDigest)
  ) {
    throw conflict('Paid media recovery executor descriptor is invalid')
  }
  let compositeDigest: string
  try {
    compositeDigest = paidMediaCompositeEvidenceDigest(value.beforeAuthorityEvidence)
  } catch (error) {
    throw conflict('Paid media recovery executor before-evidence is invalid', error)
  }
  if (compositeDigest !== value.beforeCompositeDigest) {
    throw conflict('Paid media recovery executor before-evidence does not match')
  }
  return Object.freeze({
    mode: 'recoverable',
    handlerVersion: PAID_MEDIA_RECOVERABLE_HANDLER_VERSION,
    kind: value.kind as PaidMediaRecoverableMutationKind,
    operationId: value.operationId.toLowerCase(),
    intentSha256: value.intentSha256,
    transactionId: value.transactionId.toLowerCase(),
    preparedAt: Number(value.preparedAt),
    beforeCompositeDigest: value.beforeCompositeDigest,
    beforeAuthorityEvidence: Object.freeze({
      ...(value.beforeAuthorityEvidence as PaidMediaRecoverableMutationDescriptor['beforeAuthorityEvidence'])
    })
  })
}

function intentDescriptor(
  descriptor: PaidMediaRecoverableMutationDescriptor
): PaidMediaRecoveryIntentDescriptor {
  return Object.freeze({
    handlerVersion: descriptor.handlerVersion,
    kind: descriptor.kind,
    operationId: descriptor.operationId,
    intentSha256: descriptor.intentSha256
  })
}

function samePendingTicket(
  state: PaidMediaInstallationRootState,
  descriptor: PaidMediaRecoverableMutationDescriptor
): boolean {
  const pending = state.pendingRecovery
  return (
    state.mode === 'recovery_pending' &&
    pending !== undefined &&
    pending.handlerVersion === descriptor.handlerVersion &&
    pending.kind === descriptor.kind &&
    pending.operationId === descriptor.operationId &&
    pending.intentSha256 === descriptor.intentSha256 &&
    pending.preparedAt === descriptor.preparedAt &&
    pending.beforeCompositeDigest === descriptor.beforeCompositeDigest
  )
}

function makeReceipt(
  descriptor: PaidMediaRecoverableMutationDescriptor,
  localEvidence: PaidMediaRecoveryExecutionLocalEvidence
): PaidMediaRecoveryExecutionReceipt {
  const frozenEvidence = Object.freeze({ ...localEvidence })
  const base: Omit<PaidMediaRecoveryExecutionReceipt, 'receiptSha256'> = {
    schema: RECEIPT_SCHEMA,
    handlerVersion: PAID_MEDIA_RECOVERABLE_HANDLER_VERSION,
    kind: descriptor.kind,
    operationId: descriptor.operationId,
    intentSha256: descriptor.intentSha256,
    status: 'verified' as const,
    localEvidence: frozenEvidence
  }
  const receipt = Object.freeze({
    ...base,
    receiptSha256: createHash('sha256')
      .update(RECEIPT_DOMAIN)
      .update(JSON.stringify(base), 'utf8')
      .digest('hex')
  })
  if (Buffer.byteLength(JSON.stringify(receipt), 'utf8') > MAX_RECEIPT_BYTES) {
    throw fail('Paid media recovery executor receipt exceeds its size limit')
  }
  return receipt
}

/**
 * Closed local dispatcher for an already-active Installation Root recovery.
 * It has no transport/provider/session dependency and cannot perform outbound I/O.
 */
export class PaidMediaRecoveryExecutor {
  private readonly flights = new Map<string, Promise<PaidMediaRecoveryExecutionReceipt>>()
  private readonly completedIntentByOperationKind = new Map<string, string>()
  private readonly stageOpenResults = new Map<string, PaidMediaStageOpenResult>()
  private readonly rootAdapter: PaidMediaRecoverableMutationExecutor

  constructor(private readonly dependencies: PaidMediaRecoveryExecutorDependencies) {
    if (
      !dependencies?.authority ||
      typeof dependencies.authority.assertMutationContext !== 'function' ||
      typeof dependencies.authority.localPaidPrincipal !== 'function' ||
      !(dependencies.gate instanceof PaidMediaMutationGate) ||
      !dependencies.gate.isBoundTo(dependencies.authority) ||
      typeof dependencies.intentStore?.read !== 'function' ||
      typeof dependencies.ledger?.ensureV2DispatchingOnce !== 'function' ||
      typeof dependencies.ledger?.ensureV2ResultReadyOnce !== 'function' ||
      typeof dependencies.vault?.verifyArchive !== 'function' ||
      typeof dependencies.vault?.recordAssetV2DispatchMarker !== 'function' ||
      typeof dependencies.vault?.recordAssetAckIntent !== 'function' ||
      typeof dependencies.vault?.recordAssetAckCompletion !== 'function' ||
      typeof dependencies.vault?.recordAssetCapacityReleaseAuthorization !== 'function' ||
      typeof dependencies.vault?.reserveAndOpenStageLeases !== 'function' ||
      typeof dependencies.vault?.reclaimStageLease !== 'function' ||
      typeof dependencies.vault?.inspectStageRecovery !== 'function' ||
      typeof dependencies.vault?.cleanupStageLease !== 'function' ||
      typeof dependencies.vault?.archiveRecoveredStageImageResult !== 'function' ||
      typeof dependencies.capacity?.ensureReservation !== 'function' ||
      typeof dependencies.capacity?.ensureReleasedWithAuthorization !== 'function'
    ) {
      throw fail('Paid media recovery executor dependencies are unavailable')
    }
    this.rootAdapter = Object.freeze({
      execute: async (descriptor: Readonly<PaidMediaRecoverableMutationDescriptor>) => {
        await this.execute(descriptor)
      }
    })
  }

  asRootExecutor(): PaidMediaRecoverableMutationExecutor {
    return this.rootAdapter
  }

  takeStageOpenResult(descriptorValue: unknown): PaidMediaStageOpenResult | null {
    if (
      !isRecord(descriptorValue) ||
      !exactKeys(descriptorValue, [
        'handlerVersion',
        'kind',
        'operationId',
        'intentSha256'
      ]) ||
      descriptorValue.handlerVersion !== PAID_MEDIA_RECOVERABLE_HANDLER_VERSION ||
      descriptorValue.kind !== 'asset_v2_stage_reserve' ||
      typeof descriptorValue.operationId !== 'string' ||
      !OPERATION_ID_PATTERN.test(descriptorValue.operationId) ||
      !nonzeroDigest(descriptorValue.intentSha256)
    ) {
      throw conflict('Paid media stage-result handoff descriptor is invalid')
    }
    const result = this.stageOpenResults.get(descriptorValue.intentSha256)
    if (!result) return null
    this.stageOpenResults.delete(descriptorValue.intentSha256)
    return result
  }

  async execute(descriptorValue: unknown): Promise<PaidMediaRecoveryExecutionReceipt> {
    const descriptor = canonicalDescriptor(descriptorValue)
    const operationKindKey = `${descriptor.kind}\0${descriptor.operationId}`
    const completedIntent = this.completedIntentByOperationKind.get(operationKindKey)
    if (
      descriptor.kind !== 'asset_v2_stage_reserve' &&
      completedIntent !== undefined &&
      completedIntent !== descriptor.intentSha256
    ) {
      throw conflict('Paid media recovery executor intent conflicts with a completed binding')
    }
    const flightKey = `${descriptor.transactionId}\0${descriptor.kind}\0${descriptor.operationId}\0${descriptor.intentSha256}`
    const current = this.flights.get(flightKey)
    if (current) return current
    const pending = this.executeOnce(descriptor).then((receipt) => {
      this.completedIntentByOperationKind.set(operationKindKey, descriptor.intentSha256)
      return receipt
    })
    this.flights.set(flightKey, pending)
    try {
      return await pending
    } finally {
      if (this.flights.get(flightKey) === pending) this.flights.delete(flightKey)
    }
  }

  private assertRootTicket(descriptor: PaidMediaRecoverableMutationDescriptor): void {
    try {
      this.dependencies.authority.assertMutationContext(descriptor.transactionId)
    } catch (error) {
      throw conflict('Paid media recovery executor Root transaction is not active', error)
    }
    if (!samePendingTicket(this.dependencies.authority.state, descriptor)) {
      throw conflict('Paid media recovery executor Root ticket does not match its pending intent')
    }
  }

  private async executeOnce(
    descriptor: PaidMediaRecoverableMutationDescriptor
  ): Promise<PaidMediaRecoveryExecutionReceipt> {
    this.assertRootTicket(descriptor)
    return this.dependencies.gate.runRecoverable(descriptor, async () => {
      this.dependencies.gate.assert({
        transactionId: descriptor.transactionId,
        mode: 'recoverable',
        kind: descriptor.kind,
        operationId: descriptor.operationId,
        intentSha256: descriptor.intentSha256
      })
      this.assertRootTicket(descriptor)
      let payload: PaidMediaRecoveryIntentPayload
      try {
        payload = this.dependencies.intentStore.read(intentDescriptor(descriptor))
      } catch (error) {
        if (error instanceof PaidMediaRecoveryIntentError) {
          throw conflict('Paid media recovery executor intent is unavailable or conflicts', error)
        }
        throw error
      }
      if (payload.kind !== descriptor.kind || payload.operationId !== descriptor.operationId) {
        throw conflict('Paid media recovery executor payload does not match its Root descriptor')
      }
      switch (payload.kind) {
        case 'asset_v2_dispatch':
          return this.executeDispatch(descriptor, payload)
        case 'asset_v2_stage_reserve':
          return this.executeStageReserve(descriptor, payload)
        case 'asset_v2_stage_archive':
          return this.executeStageArchive(descriptor, payload)
        case 'asset_v2_stage_cleanup':
          return this.executeStageCleanup(descriptor, payload)
        case 'asset_v2_result_ready_ack_intent':
          return this.executeResultReadyAckIntent(descriptor, payload)
        case 'asset_v2_ack_completion':
          return this.executeAckCompletion(descriptor, payload)
        case 'asset_v2_capacity_release':
          return this.executeCapacityRelease(descriptor, payload)
      }
    })
  }

  private exactReservedStageEvidence(
    payload: Extract<PaidMediaRecoveryIntentPayload, { kind: 'asset_v2_stage_reserve' }>,
    inspection: PaidMediaStageRecoveryInspection,
    reclaimedFrom?: ReadonlyMap<
      string,
      Readonly<{ generation: number; leaseStateDigest: string }>
    >
  ): Extract<PaidMediaRecoveryExecutionLocalEvidence, { state: 'stage_reserved' }> | null {
    const resultSha256 = paidMediaAssetResultDigest(payload.result)
    const leases = inspection.leases
      .filter((lease) => lease.operationId === payload.operationId)
      .sort((left, right) => left.ordinal - right.ordinal)
    if (leases.length === 0) return null
    if (
      leases.length !== payload.result.assets.length ||
      leases.some(
        (lease, ordinal) =>
          lease.turnId !== payload.result.turnId ||
          lease.ordinal !== ordinal ||
          lease.resultSha256 !== resultSha256 ||
          lease.state !== 'opened' ||
          lease.disposition !== 'reclaim' ||
          !Number.isSafeInteger(lease.generation) ||
          lease.generation < 0 ||
          !nonzeroDigest(lease.leaseId) ||
          !nonzeroDigest(lease.leaseStateDigest)
      )
    ) {
      throw conflict('Paid media stage reservation durable evidence conflicts')
    }
    if (payload.mode === 'reclaim') {
      const bindingsMatch = leases.every((lease, ordinal) => {
        const expected = payload.leases[ordinal]!
        const source = reclaimedFrom?.get(lease.leaseId)
        return (
          expected.leaseId === lease.leaseId &&
          expected.ordinal === ordinal &&
          expected.resultSha256 === lease.resultSha256 &&
          (source
            ? lease.generation === source.generation + 1 &&
              lease.leaseStateDigest !== source.leaseStateDigest
            : lease.generation >= expected.generation &&
              (lease.generation === expected.generation
                ? lease.leaseStateDigest === expected.leaseStateDigest
                : lease.leaseStateDigest !== expected.leaseStateDigest))
        )
      })
      if (!bindingsMatch) {
        throw conflict('Paid media stage reclaim lease binding conflicts')
      }
    }
    return Object.freeze({
      state: 'stage_reserved' as const,
      resultSha256,
      leases: Object.freeze(
        leases.map((lease) =>
          Object.freeze({
            leaseId: lease.leaseId,
            generation: lease.generation,
            leaseStateDigest: lease.leaseStateDigest
          })
        )
      )
    })
  }

  private async executeStageReserve(
    descriptor: PaidMediaRecoverableMutationDescriptor,
    payload: Extract<PaidMediaRecoveryIntentPayload, { kind: 'asset_v2_stage_reserve' }>
  ): Promise<PaidMediaRecoveryExecutionReceipt> {
    let before: PaidMediaStageRecoveryInspection
    try {
      before = await this.dependencies.vault.inspectStageRecovery()
    } catch (error) {
      throw fail('Paid media stage reservation evidence is unavailable', error)
    }
    const existing = this.exactReservedStageEvidence(payload, before)
    if (payload.mode === 'fresh' && existing) return makeReceipt(descriptor, existing)
    if (payload.mode === 'reclaim') {
      if (!existing) {
        throw conflict('Paid media stage reclaim requires exact durable lease evidence')
      }
      const reclaimedFrom = new Map(
        before.leases
          .filter((lease) => lease.operationId === payload.operationId)
          .map((lease) => [
            lease.leaseId,
            Object.freeze({
              generation: lease.generation,
              leaseStateDigest: lease.leaseStateDigest
            })
          ])
      )
      const capabilities: PaidMediaStageWriteCapability[] = []
      for (const lease of payload.leases) {
        let reclaimed: PaidMediaStageReclaimResult
        try {
          reclaimed = await this.dependencies.vault.reclaimStageLease({
            operationId: payload.operationId,
            result: payload.result,
            leaseId: lease.leaseId
          })
        } catch (error) {
          throw fail('Paid media stage reclaim local mutation failed', error)
        }
        if (!reclaimed.ok) {
          if (reclaimed.status === 'held') {
            throw conflict('Paid media stage reclaim is held for manual recovery')
          }
          throw fail('Paid media stage reclaim remains unavailable')
        }
        capabilities.push(reclaimed.capability)
      }
      let after: PaidMediaStageRecoveryInspection
      try {
        after = await this.dependencies.vault.inspectStageRecovery()
      } catch (error) {
        throw fail('Paid media stage reclaim postcondition is unavailable', error)
      }
      const evidence = this.exactReservedStageEvidence(
        payload,
        after,
        reclaimedFrom
      )
      if (!evidence || capabilities.length !== evidence.leases.length) {
        throw conflict('Paid media stage reclaim postcondition is missing')
      }
      if (
        capabilities.some(
          (capability, ordinal) =>
            capability.operationId !== payload.operationId ||
            capability.turnId !== payload.result.turnId ||
            capability.ordinal !== ordinal ||
            capability.leaseId !== evidence.leases[ordinal]!.leaseId ||
            JSON.stringify(capability.descriptor) !==
              JSON.stringify(payload.result.assets[ordinal])
        )
      ) {
        throw conflict('Paid media stage reclaim capability handoff conflicts')
      }
      const opened = Object.freeze({
        ok: true as const,
        capabilities: Object.freeze(capabilities)
      })
      this.stageOpenResults.set(descriptor.intentSha256, opened)
      return makeReceipt(descriptor, evidence)
    }
    let opened: PaidMediaStageOpenResult
    try {
      opened = await this.dependencies.vault.reserveAndOpenStageLeases({
        operationId: payload.operationId,
        result: payload.result
      })
    } catch (error) {
      throw fail('Paid media stage reservation local mutation failed', error)
    }
    if (!opened.ok) {
      throw fail(
        opened.held
          ? 'Paid media stage reservation is held for manual recovery'
          : 'Paid media stage reservation cleanup remains pending'
      )
    }
    let after: PaidMediaStageRecoveryInspection
    try {
      after = await this.dependencies.vault.inspectStageRecovery()
    } catch (error) {
      throw fail('Paid media stage reservation postcondition is unavailable', error)
    }
    const evidence = this.exactReservedStageEvidence(payload, after)
    if (!evidence) {
      throw conflict('Paid media stage reservation postcondition is missing')
    }
    if (
      opened.capabilities.length !== evidence.leases.length ||
      opened.capabilities.some(
        (capability, ordinal) =>
          capability.operationId !== payload.operationId ||
          capability.turnId !== payload.result.turnId ||
          capability.ordinal !== ordinal ||
          capability.leaseId !== evidence.leases[ordinal]!.leaseId ||
          JSON.stringify(capability.descriptor) !==
            JSON.stringify(payload.result.assets[ordinal])
      )
    ) {
      throw conflict('Paid media stage reservation capability handoff conflicts')
    }
    this.stageOpenResults.set(descriptor.intentSha256, opened)
    return makeReceipt(descriptor, evidence)
  }

  private async executeStageCleanup(
    descriptor: PaidMediaRecoverableMutationDescriptor,
    payload: Extract<PaidMediaRecoveryIntentPayload, { kind: 'asset_v2_stage_cleanup' }>
  ): Promise<PaidMediaRecoveryExecutionReceipt> {
    let before: PaidMediaStageRecoveryInspection
    try {
      before = await this.dependencies.vault.inspectStageRecovery()
    } catch (error) {
      throw fail('Paid media stage cleanup evidence is unavailable', error)
    }
    const expectedByLease = new Map(payload.leases.map((lease) => [lease.leaseId, lease]))
    const activeForOperation = before.leases.filter(
      (lease) => lease.operationId === payload.operationId
    )
    if (
      activeForOperation.some((lease) => {
        const expected = expectedByLease.get(lease.leaseId)
        return (
          !expected ||
          lease.generation !== expected.generation ||
          lease.resultSha256 !== expected.resultSha256 ||
          lease.leaseStateDigest !== expected.leaseStateDigest
        )
      })
    ) {
      throw conflict('Paid media stage cleanup durable lease evidence conflicts')
    }
    for (const lease of payload.leases) {
      let result: Awaited<ReturnType<PaidMediaRecoveryVault['cleanupStageLease']>>
      try {
        result = await this.dependencies.vault.cleanupStageLease({
          operationId: payload.operationId,
          leaseId: lease.leaseId,
          generation: lease.generation,
          resultSha256: lease.resultSha256
        })
      } catch (error) {
        throw fail('Paid media stage cleanup local mutation failed', error)
      }
      if (result.status === 'held') {
        throw conflict('Paid media stage cleanup is held for manual recovery')
      }
      if (result.status !== 'cleaned') {
        throw fail('Paid media stage cleanup remains pending')
      }
    }
    let after: PaidMediaStageRecoveryInspection
    try {
      after = await this.dependencies.vault.inspectStageRecovery()
    } catch (error) {
      throw fail('Paid media stage cleanup postcondition is unavailable', error)
    }
    if (
      after.leases.some(
        (lease) =>
          lease.operationId === payload.operationId && expectedByLease.has(lease.leaseId)
      )
    ) {
      throw conflict('Paid media stage cleanup postcondition is incomplete')
    }
    return makeReceipt(
      descriptor,
      Object.freeze({
        state: 'stage_cleaned' as const,
        leases: Object.freeze(
          payload.leases.map((lease) =>
            Object.freeze({ leaseId: lease.leaseId, generation: lease.generation })
          )
        )
      })
    )
  }

  private async executeStageArchive(
    descriptor: PaidMediaRecoverableMutationDescriptor,
    payload: Extract<PaidMediaRecoveryIntentPayload, { kind: 'asset_v2_stage_archive' }>
  ): Promise<PaidMediaRecoveryExecutionReceipt> {
    let archived: Awaited<ReturnType<PaidMediaRecoveryVault['verifyArchive']>>
    try {
      archived = await this.dependencies.vault.archiveRecoveredStageImageResult({
        operationId: payload.operationId,
        status: 200,
        result: payload.result,
        leases: payload.leases,
        validations: payload.validations
      })
    } catch (error) {
      throw fail('Paid media recovered stage archive local mutation failed', error)
    }
    const canonicalResult = canonicalPaidMediaAssetResult(payload.result)
    if (
      archived.receipt.operationId !== payload.operationId ||
      !nonzeroDigest(archived.receipt.receiptSha256) ||
      archived.receipt.responseSha256 !==
        createHash('sha256').update(canonicalResult).digest('hex') ||
      archived.receipt.responseByteLength !== canonicalResult.byteLength ||
      typeof archived.cleanupComplete !== 'boolean'
    ) {
      throw conflict('Paid media recovered stage archive postcondition does not match')
    }
    return makeReceipt(
      descriptor,
      Object.freeze({
        state: 'stage_archived' as const,
        resultSha256: paidMediaAssetResultDigest(payload.result),
        archiveReceiptSha256: archived.receipt.receiptSha256,
        cleanupComplete: archived.cleanupComplete
      })
    )
  }

  private async executeDispatch(
    descriptor: PaidMediaRecoverableMutationDescriptor,
    payload: Extract<PaidMediaRecoveryIntentPayload, { kind: 'asset_v2_dispatch' }>
  ): Promise<PaidMediaRecoveryExecutionReceipt> {
    let rootedPrincipal: string
    try {
      rootedPrincipal = this.dependencies.authority.localPaidPrincipal()
    } catch (error) {
      throw conflict('Paid media recovery rooted principal is unavailable', error)
    }
    if (
      !nonzeroDigest(rootedPrincipal) ||
      payload.claim.recoveryDomainSha256 !== rootedPrincipal ||
      payload.paidPrincipalSha256 !== rootedPrincipal
    ) {
      throw conflict('Paid media recovery dispatch principal binding does not match')
    }
    let reservation: PaidMediaCapacityReservation
    let marker: PaidMediaRecoveryLocalReceipt
    let operation: Awaited<ReturnType<PaidMediaRecoveryLedger['ensureV2DispatchingOnce']>>
    try {
      reservation = await this.dependencies.capacity.ensureReservation({
        operationId: payload.operationId,
        path: payload.claim.path,
        allowCreate: true
      })
      marker = await this.dependencies.vault.recordAssetV2DispatchMarker({
        operationId: payload.operationId,
        path: payload.claim.path,
        requestSha256: payload.claim.requestSha256,
        recoveryDomainSha256: payload.claim.recoveryDomainSha256,
        paidPrincipalSha256: payload.paidPrincipalSha256,
        turnId: null,
        assetResultSha256: null
      })
      operation = await this.dependencies.ledger.ensureV2DispatchingOnce({
        operationId: payload.operationId,
        path: payload.claim.path,
        requestSha256: payload.claim.requestSha256,
        recoveryDomainSha256: payload.claim.recoveryDomainSha256,
        dispatchReceiptSha256: marker.receiptSha256
      })
    } catch (error) {
      throw fail('Paid media recovery dispatch local mutation failed', error)
    }
    if (
      reservation.operationId !== payload.operationId ||
      reservation.path !== payload.claim.path ||
      reservation.phase !== 'active' ||
      reservation.budgetPolicy !== PAID_MEDIA_CAPACITY_BUDGET_POLICY ||
      marker.operationId !== payload.operationId ||
      !nonzeroDigest(marker.receiptSha256) ||
      operation.operationId !== payload.operationId ||
      operation.state !== 'dispatching' ||
      operation.dispatchCount !== 1 ||
      operation.v2DispatchReceiptSha256 !== marker.receiptSha256
    ) {
      throw conflict('Paid media recovery dispatch postcondition does not match')
    }
    return makeReceipt(
      descriptor,
      Object.freeze({
        state: 'dispatching',
        dispatchCount: 1,
        dispatchReceiptSha256: marker.receiptSha256
      })
    )
  }

  private async executeAckCompletion(
    descriptor: PaidMediaRecoverableMutationDescriptor,
    payload: Extract<PaidMediaRecoveryIntentPayload, { kind: 'asset_v2_ack_completion' }>
  ): Promise<PaidMediaRecoveryExecutionReceipt> {
    let completion: PaidMediaRecoveryLocalReceipt
    try {
      completion = await this.dependencies.vault.recordAssetAckCompletion({
        operationId: payload.operationId,
        intentReceiptSha256: payload.intentReceiptSha256,
        status: payload.status,
        response: payload.response
      })
    } catch (error) {
      throw fail('Paid media recovery ACK-completion local mutation failed', error)
    }
    if (
      completion.operationId !== payload.operationId ||
      !nonzeroDigest(completion.receiptSha256)
    ) {
      throw conflict('Paid media recovery ACK-completion postcondition does not match')
    }
    return makeReceipt(
      descriptor,
      Object.freeze({
        state: 'ack_completed',
        ackCompletionReceiptSha256: completion.receiptSha256
      })
    )
  }

  private async executeCapacityRelease(
    descriptor: PaidMediaRecoverableMutationDescriptor,
    payload: Extract<PaidMediaRecoveryIntentPayload, { kind: 'asset_v2_capacity_release' }>
  ): Promise<PaidMediaRecoveryExecutionReceipt> {
    let authorization: PaidMediaRecoveryLocalReceipt
    try {
      authorization =
        await this.dependencies.vault.recordAssetCapacityReleaseAuthorization({
          operationId: payload.operationId,
          archive: payload.archive,
          dispatch: payload.dispatch,
          ackCompletion: payload.ackCompletion
        })
    } catch (error) {
      throw fail('Paid media recovery capacity-release local mutation failed', error)
    }
    if (
      authorization.operationId !== payload.operationId ||
      !nonzeroDigest(authorization.receiptSha256)
    ) {
      throw conflict('Paid media recovery capacity-release postcondition does not match')
    }
    let tombstone: PaidMediaCapacityReleaseTombstone
    try {
      tombstone = await this.dependencies.capacity.ensureReleasedWithAuthorization({
        operationId: payload.operationId,
        authorizationReceiptSha256: authorization.receiptSha256
      })
    } catch (error) {
      throw fail('Paid media recovery capacity-release local mutation failed', error)
    }
    if (
      tombstone.operationId !== payload.operationId ||
      tombstone.authorizationReceiptSha256 !== authorization.receiptSha256 ||
      !Number.isSafeInteger(tombstone.releasedAt) ||
      tombstone.releasedAt < 0 ||
      (tombstone.releasedReservationSha256 !== null &&
        !nonzeroDigest(tombstone.releasedReservationSha256))
    ) {
      throw conflict('Paid media recovery capacity-release postcondition does not match')
    }
    return makeReceipt(
      descriptor,
      Object.freeze({
        state: 'capacity_released',
        capacityReleaseReceiptSha256: authorization.receiptSha256
      })
    )
  }

  private async executeResultReadyAckIntent(
    descriptor: PaidMediaRecoverableMutationDescriptor,
    payload: Extract<
      PaidMediaRecoveryIntentPayload,
      { kind: 'asset_v2_result_ready_ack_intent' }
    >
  ): Promise<PaidMediaRecoveryExecutionReceipt> {
    const tokens = payload.result.assets.map((asset) => asset.token)
    if (
      payload.ack.turnId !== payload.result.turnId ||
      payload.ack.archiveReceiptSha256 !== payload.archive.receiptSha256 ||
      JSON.stringify(payload.ack.tokens) !== JSON.stringify(tokens)
    ) {
      throw conflict('Paid media recovery ACK intent payload bindings do not match')
    }
    const canonicalResult = canonicalPaidMediaAssetResult(payload.result)
    let archive: Awaited<ReturnType<PaidMediaRecoveryVault['verifyArchive']>>
    try {
      archive = await this.dependencies.vault.verifyArchive(payload.operationId)
    } catch (error) {
      throw fail('Paid media recovery archive verification failed', error)
    }
    if (
      archive.receipt.operationId !== payload.operationId ||
      archive.receipt.receiptSha256 !== payload.archive.receiptSha256 ||
      archive.cleanupComplete !== payload.archive.cleanupComplete ||
      archive.receipt.responseSha256 !==
        createHash('sha256').update(canonicalResult).digest('hex') ||
      archive.receipt.responseByteLength !== canonicalResult.byteLength
    ) {
      throw conflict('Paid media recovery archive does not match its ACK intent')
    }
    let ackIntent: PaidMediaRecoveryLocalReceipt
    let operation: Awaited<ReturnType<PaidMediaRecoveryLedger['ensureV2ResultReadyOnce']>>
    try {
      ackIntent = await this.dependencies.vault.recordAssetAckIntent({
        operationId: payload.operationId,
        turnId: payload.result.turnId,
        tokens,
        tokenSetDigest: paidMediaTokenSetDigest(tokens),
        archiveReceiptSha256: payload.archive.receiptSha256,
        assetResultSha256: paidMediaAssetResultDigest(payload.result),
        dispatchReceiptSha256: payload.dispatch.receiptSha256
      })
      operation = await this.dependencies.ledger.ensureV2ResultReadyOnce({
        operationId: payload.operationId,
        dispatchReceiptSha256: payload.dispatch.receiptSha256,
        ackIntentReceiptSha256: ackIntent.receiptSha256,
        status: 200,
        responseJson: archive.recoveryJson
      })
    } catch (error) {
      throw fail('Paid media recovery ACK-intent local mutation failed', error)
    }
    if (
      ackIntent.operationId !== payload.operationId ||
      !nonzeroDigest(ackIntent.receiptSha256) ||
      operation.operationId !== payload.operationId ||
      operation.state !== 'result_ready' ||
      operation.dispatchCount !== 1 ||
      operation.v2DispatchReceiptSha256 !== payload.dispatch.receiptSha256 ||
      operation.v2AckIntentReceiptSha256 !== ackIntent.receiptSha256
    ) {
      throw conflict('Paid media recovery ACK-intent postcondition does not match')
    }
    return makeReceipt(
      descriptor,
      Object.freeze({
        state: 'result_ready',
        dispatchCount: 1,
        dispatchReceiptSha256: payload.dispatch.receiptSha256,
        ackIntentReceiptSha256: ackIntent.receiptSha256
      })
    )
  }
}
