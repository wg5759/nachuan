import { createHash } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, describe, expect, it, vi } from 'vitest'

import {
  PAID_MEDIA_RECOVERABLE_HANDLER_VERSION,
  paidMediaCompositeEvidenceDigest,
  type PaidMediaAuthorityEvidence,
  type PaidMediaRecoverableMutationDescriptor
} from './paid-media-installation-root'
import {
  PaidMediaRecoveryIntentStore
} from './paid-media-recovery-intent'
import {
  canonicalPaidMediaAssetResult,
  paidMediaAssetResultDigest
} from './paid-media-asset-protocol'
import {
  PaidMediaRecoveryExecutor,
  type PaidMediaRecoveryExecutorDependencies
} from './paid-media-recovery-executor'
import { PaidMediaMutationGate } from './paid-media-mutation-gate'

const OPERATION_ID = 'desktop-op-aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
const TRANSACTION_ID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
const REQUEST_SHA256 = '1'.repeat(64)
const RECOVERY_DOMAIN_SHA256 = '2'.repeat(64)
const PAID_PRINCIPAL_SHA256 = RECOVERY_DOMAIN_SHA256
const TURN_ID = 'a'.repeat(64)
const ASSET_SHA256 = 'b'.repeat(64)
const VALIDATION_RECEIPT_SHA256 = 'c'.repeat(64)
const ARCHIVE_RECEIPT_SHA256 = 'd'.repeat(64)
const DISPATCH_RECEIPT_SHA256 = 'e'.repeat(64)
const ACK_INTENT_RECEIPT_SHA256 = 'f'.repeat(64)
const ACK_COMPLETION_RECEIPT_SHA256 = '4'.repeat(64)
const TOKEN = `nma1_${'A'.repeat(43)}`
const RECOVERY_JSON = JSON.stringify({
  data: [{ url: 'nachuan-media://asset/local-image' }],
  created: 1_784_200_000
})

const roots: string[] = []

function digest(value: unknown): string {
  return createHash('sha256').update(JSON.stringify(value), 'utf8').digest('hex')
}

function unexpectedStageVault() {
  return {
    reserveAndOpenStageLeases: vi.fn(async () => {
      throw new Error('unexpected stage reservation mutation')
    }),
    reclaimStageLease: vi.fn(async () => {
      throw new Error('unexpected stage reclaim mutation')
    }),
    inspectStageRecovery: vi.fn(async () => {
      throw new Error('unexpected stage recovery inspection')
    }),
    cleanupStageLease: vi.fn(async () => {
      throw new Error('unexpected stage cleanup mutation')
    }),
    archiveRecoveredStageImageResult: vi.fn(async () => {
      throw new Error('unexpected recovered stage archive mutation')
    })
  }
}

function fakeEncrypt(value: string): Buffer {
  const bytes = Buffer.from(value, 'utf8')
  for (let index = 0; index < bytes.length; index += 1) bytes[index] ^= 0xa5
  return bytes
}

function fakeDecrypt(value: Buffer): string {
  const bytes = Buffer.from(value)
  for (let index = 0; index < bytes.length; index += 1) bytes[index] ^= 0xa5
  return bytes.toString('utf8')
}

function intentStore(): PaidMediaRecoveryIntentStore {
  const root = mkdtempSync(join(tmpdir(), 'nachuan-recovery-executor-'))
  roots.push(root)
  return new PaidMediaRecoveryIntentStore(root, {
    safeStorage: {
      isEncryptionAvailable: () => true,
      encryptString: fakeEncrypt,
      decryptString: fakeDecrypt
    },
    harden: () => undefined
  })
}

const BEFORE_EVIDENCE: PaidMediaAuthorityEvidence = Object.freeze({
  ledgerIdentity: '4'.repeat(64),
  ledgerSequence: 10,
  ledgerStateDigest: '5'.repeat(64),
  vaultStateDigest: '6'.repeat(64),
  capacityIdentity: '7'.repeat(64),
  capacitySequence: 11,
  capacityStateDigest: '8'.repeat(64),
  legacySealDecisionSha256: '9'.repeat(64)
})

function dispatchPayload() {
  return {
    kind: 'asset_v2_dispatch' as const,
    operationId: OPERATION_ID,
    claim: {
      path: '/v1/images/generations' as const,
      requestSha256: REQUEST_SHA256,
      recoveryDomainSha256: RECOVERY_DOMAIN_SHA256
    },
    paidPrincipalSha256: PAID_PRINCIPAL_SHA256
  }
}

function assetResult(validationReceiptSha256 = VALIDATION_RECEIPT_SHA256) {
  return {
    schema: 'nachuan.paid-media-result.v2' as const,
    kind: 'image' as const,
    created: 1_784_200_000,
    turnId: TURN_ID,
    assets: [
      {
        token: TOKEN,
        mediaType: 'image/png',
        byteLength: 68,
        sha256: ASSET_SHA256,
        validationReceiptSha256
      }
    ]
  }
}

function trustedValidation() {
  const base = {
    schema: 'nachuan.trusted-media-validation.v2' as const,
    validatorVersion: 'nachuan.trusted-media-probe.v2' as const,
    validationPolicy: 'nachuan.trusted-media-policy.av-closed.v1' as const,
    fullyDecoded: true as const,
    mediaType: 'image/png' as const,
    byteLength: 68,
    sha256: ASSET_SHA256,
    attestedTools: { ffmpegSha256: '5'.repeat(64), ffprobeSha256: '6'.repeat(64) },
    metadata: {
      detectedKind: 'image' as const,
      codecName: 'png',
      audioCodecName: null,
      videoStreamCount: 1 as const,
      audioStreamCount: 0 as const,
      formatName: 'png_pipe',
      width: 1,
      height: 1,
      durationMs: null,
      decodedFrames: 1
    }
  }
  const canonical = {
    attestedTools: base.attestedTools,
    byteLength: base.byteLength,
    fullyDecoded: base.fullyDecoded,
    mediaType: base.mediaType,
    metadata: {
      audioCodecName: base.metadata.audioCodecName,
      audioStreamCount: base.metadata.audioStreamCount,
      codecName: base.metadata.codecName,
      decodedFrames: base.metadata.decodedFrames,
      detectedKind: base.metadata.detectedKind,
      durationMs: base.metadata.durationMs,
      formatName: base.metadata.formatName,
      height: base.metadata.height,
      videoStreamCount: base.metadata.videoStreamCount,
      width: base.metadata.width
    },
    schema: base.schema,
    sha256: base.sha256,
    validationPolicy: base.validationPolicy,
    validatorVersion: base.validatorVersion
  }
  return {
    ...base,
    receiptSha256: createHash('sha256')
      .update('nachuan.trusted-media-validation.v2\0', 'utf8')
      .update(JSON.stringify(canonical), 'ascii')
      .digest('hex')
  }
}

function resultReadyPayload() {
  return {
    kind: 'asset_v2_result_ready_ack_intent' as const,
    operationId: OPERATION_ID,
    result: assetResult(),
    archive: {
      receiptSha256: ARCHIVE_RECEIPT_SHA256,
      cleanupComplete: true
    },
    dispatch: { receiptSha256: DISPATCH_RECEIPT_SHA256 },
    ack: {
      schema: 'nachuan.paid-media-asset-ack.v1' as const,
      turnId: TURN_ID,
      tokens: [TOKEN],
      archiveReceiptSha256: ARCHIVE_RECEIPT_SHA256
    }
  }
}

function ackCompletionPayload(replayed = false) {
  return {
    kind: 'asset_v2_ack_completion' as const,
    operationId: OPERATION_ID,
    intentReceiptSha256: ACK_INTENT_RECEIPT_SHA256,
    status: 200 as const,
    response: {
      ok: true as const,
      turnId: TURN_ID,
      replayed,
      cleanupComplete: true as const
    }
  }
}

function capacityReleasePayload() {
  return {
    kind: 'asset_v2_capacity_release' as const,
    operationId: OPERATION_ID,
    archive: {
      receiptSha256: ARCHIVE_RECEIPT_SHA256,
      cleanupComplete: true as const
    },
    dispatch: { receiptSha256: DISPATCH_RECEIPT_SHA256 },
    ackCompletion: { receiptSha256: ACK_COMPLETION_RECEIPT_SHA256 }
  }
}

function rootDescriptor(
  prepared: Awaited<ReturnType<PaidMediaRecoveryIntentStore['prepare']>>
): PaidMediaRecoverableMutationDescriptor {
  return Object.freeze({
    mode: 'recoverable',
    handlerVersion: PAID_MEDIA_RECOVERABLE_HANDLER_VERSION,
    kind: prepared.kind,
    operationId: prepared.operationId,
    intentSha256: prepared.intentSha256,
    transactionId: TRANSACTION_ID,
    preparedAt: 1_784_200_000,
    beforeCompositeDigest: paidMediaCompositeEvidenceDigest(BEFORE_EVIDENCE),
    beforeAuthorityEvidence: BEFORE_EVIDENCE
  })
}

interface Fixture {
  executor: PaidMediaRecoveryExecutor
  dependencies: PaidMediaRecoveryExecutorDependencies
  writes: { vault: number; ledger: number }
  calls: string[]
}

function fixture(
  store: PaidMediaRecoveryIntentStore,
  descriptor: PaidMediaRecoverableMutationDescriptor
): Fixture & { capacityReservationWrites: () => number } {
  const calls: string[] = []
  const writes = { vault: 0, ledger: 0 }
  let capacityReservationWrites = 0
  let capacityOperationId: string | null = null
  let dispatchReceiptSha256: string | null = null
  let ledgerReceiptSha256: string | null = null
  const pendingRecovery = Object.freeze({
    handlerVersion: descriptor.handlerVersion,
    kind: descriptor.kind,
    operationId: descriptor.operationId,
    intentSha256: descriptor.intentSha256,
    preparedAt: descriptor.preparedAt,
    beforeCompositeDigest: descriptor.beforeCompositeDigest
  })
  const authority = {
    get state() {
      return {
        mode: 'recovery_pending' as const,
        reasonCode: 'recoverable-local-handler-active',
        pendingRecovery
      }
    },
    assertMutationContext(transactionId?: string) {
      if (transactionId !== TRANSACTION_ID) throw new Error('wrong Root transaction')
    },
    localPaidPrincipal() {
      return PAID_PRINCIPAL_SHA256
    },
  }
  const gate = new PaidMediaMutationGate(authority)
  const dependencies: PaidMediaRecoveryExecutorDependencies = {
    authority,
    gate,
    intentStore: store,
    ledger: {
      ensureV2DispatchingOnce: vi.fn(async (input) => {
        gate.guard()
        calls.push('ledger:dispatch')
        if (ledgerReceiptSha256 === null) {
          ledgerReceiptSha256 = input.dispatchReceiptSha256
          writes.ledger += 1
        } else if (ledgerReceiptSha256 !== input.dispatchReceiptSha256) {
          throw new Error('ledger dispatch conflict')
        }
        return {
          operationId: input.operationId,
          state: 'dispatching' as const,
          dispatchCount: 1,
          v2DispatchReceiptSha256: ledgerReceiptSha256!
        }
      }),
      ensureV2ResultReadyOnce: vi.fn(async () => {
        throw new Error('unexpected result-ready mutation')
      })
    },
    vault: {
      ...unexpectedStageVault(),
      verifyArchive: vi.fn(async () => {
        throw new Error('unexpected archive verification')
      }),
      recordAssetV2DispatchMarker: vi.fn(async (input) => {
        gate.guard()
        calls.push('vault:dispatch')
        const candidate = digest(input)
        if (dispatchReceiptSha256 === null) {
          dispatchReceiptSha256 = candidate
          writes.vault += 1
        } else if (dispatchReceiptSha256 !== candidate) {
          throw new Error('vault dispatch conflict')
        }
        return { operationId: input.operationId, receiptSha256: dispatchReceiptSha256 }
      }),
      recordAssetAckIntent: vi.fn(async () => {
        throw new Error('unexpected ACK intent mutation')
      }),
      recordAssetAckCompletion: vi.fn(async () => {
        throw new Error('unexpected ACK completion mutation')
      }),
      recordAssetCapacityReleaseAuthorization: vi.fn(async () => {
        throw new Error('unexpected capacity authorization mutation')
      })
    },
    capacity: {
      ensureReservation: vi.fn(async (input) => {
        gate.guard()
        calls.push('capacity:reservation')
        if (capacityOperationId === null) {
          capacityOperationId = input.operationId
          capacityReservationWrites += 1
        } else if (capacityOperationId !== input.operationId) {
          throw new Error('capacity reservation conflict')
        }
        return {
          operationId: input.operationId,
          path: input.path,
          phase: 'active' as const,
          budgetPolicy: 'nachuan.paid-media-capacity-budget.v1' as const,
          roleBudgets: [],
          perVolume: [],
          createdAt: 1_784_200_000,
          updatedAt: 1_784_200_000
        }
      }),
      ensureReleasedWithAuthorization: vi.fn(async () => {
        throw new Error('unexpected capacity release')
      })
    }
  }
  return {
    executor: new PaidMediaRecoveryExecutor(dependencies),
    dependencies,
    writes,
    calls,
    capacityReservationWrites: () => capacityReservationWrites
  }
}

function resultFixture(
  store: PaidMediaRecoveryIntentStore,
  descriptor: PaidMediaRecoverableMutationDescriptor,
  options: { archiveResponseSha256?: string } = {}
): Fixture & { responseJson: () => string | null } {
  const calls: string[] = []
  const writes = { vault: 0, ledger: 0 }
  let ackIntentReceiptSha256: string | null = null
  let ledgerIntentReceiptSha256: string | null = null
  let seenResponseJson: string | null = null
  const pendingRecovery = Object.freeze({
    handlerVersion: descriptor.handlerVersion,
    kind: descriptor.kind,
    operationId: descriptor.operationId,
    intentSha256: descriptor.intentSha256,
    preparedAt: descriptor.preparedAt,
    beforeCompositeDigest: descriptor.beforeCompositeDigest
  })
  const authority = {
    get state() {
      return {
        mode: 'recovery_pending' as const,
        reasonCode: 'recoverable-local-handler-active',
        pendingRecovery
      }
    },
    assertMutationContext(transactionId?: string) {
      if (transactionId !== TRANSACTION_ID) throw new Error('wrong Root transaction')
    },
    localPaidPrincipal() {
      return PAID_PRINCIPAL_SHA256
    },
  }
  const gate = new PaidMediaMutationGate(authority)
  const dependencies: PaidMediaRecoveryExecutorDependencies = {
    authority,
    gate,
    intentStore: store,
    ledger: {
      ensureV2DispatchingOnce: vi.fn(async () => {
        throw new Error('unexpected dispatch mutation')
      }),
      ensureV2ResultReadyOnce: vi.fn(async (input) => {
        gate.guard()
        calls.push('ledger:result-ready')
        seenResponseJson = input.responseJson
        if (ledgerIntentReceiptSha256 === null) {
          ledgerIntentReceiptSha256 = input.ackIntentReceiptSha256
          writes.ledger += 1
        } else if (ledgerIntentReceiptSha256 !== input.ackIntentReceiptSha256) {
          throw new Error('ledger result-ready conflict')
        }
        return {
          operationId: input.operationId,
          state: 'result_ready' as const,
          dispatchCount: 1,
          v2DispatchReceiptSha256: input.dispatchReceiptSha256,
          v2AckIntentReceiptSha256: ledgerIntentReceiptSha256!
        }
      })
    },
    vault: {
      ...unexpectedStageVault(),
      verifyArchive: vi.fn(async (operationId) => {
        calls.push('vault:verify-archive')
        const response = canonicalPaidMediaAssetResult(assetResult())
        return {
          receipt: {
            operationId,
            receiptSha256: ARCHIVE_RECEIPT_SHA256,
            responseSha256:
              options.archiveResponseSha256 ??
              createHash('sha256').update(response).digest('hex'),
            responseByteLength: response.byteLength
          },
          recoveryJson: RECOVERY_JSON,
          cleanupComplete: true
        }
      }),
      recordAssetV2DispatchMarker: vi.fn(async () => {
        throw new Error('unexpected dispatch marker mutation')
      }),
      recordAssetAckIntent: vi.fn(async (input) => {
        gate.guard()
        calls.push('vault:ack-intent')
        const candidate = digest(input)
        if (ackIntentReceiptSha256 === null) {
          ackIntentReceiptSha256 = candidate
          writes.vault += 1
        } else if (ackIntentReceiptSha256 !== candidate) {
          throw new Error('vault ACK intent conflict')
        }
        return { operationId: input.operationId, receiptSha256: ackIntentReceiptSha256 }
      }),
      recordAssetAckCompletion: vi.fn(async () => {
        throw new Error('unexpected ACK completion mutation')
      }),
      recordAssetCapacityReleaseAuthorization: vi.fn(async () => {
        throw new Error('unexpected capacity authorization mutation')
      })
    },
    capacity: {
      ensureReservation: vi.fn(async () => {
        throw new Error('unexpected capacity reservation')
      }),
      ensureReleasedWithAuthorization: vi.fn(async () => {
        throw new Error('unexpected capacity release')
      })
    }
  }
  return {
    executor: new PaidMediaRecoveryExecutor(dependencies),
    dependencies,
    writes,
    calls,
    responseJson: () => seenResponseJson
  }
}

function ackCompletionFixture(
  store: PaidMediaRecoveryIntentStore,
  descriptor: PaidMediaRecoverableMutationDescriptor
): Fixture {
  const calls: string[] = []
  const writes = { vault: 0, ledger: 0 }
  let completionReceiptSha256: string | null = null
  const pendingRecovery = Object.freeze({
    handlerVersion: descriptor.handlerVersion,
    kind: descriptor.kind,
    operationId: descriptor.operationId,
    intentSha256: descriptor.intentSha256,
    preparedAt: descriptor.preparedAt,
    beforeCompositeDigest: descriptor.beforeCompositeDigest
  })
  const authority = {
    get state() {
      return {
        mode: 'recovery_pending' as const,
        reasonCode: 'recoverable-local-handler-active',
        pendingRecovery
      }
    },
    assertMutationContext(transactionId?: string) {
      if (transactionId !== TRANSACTION_ID) throw new Error('wrong Root transaction')
    },
    localPaidPrincipal() {
      return PAID_PRINCIPAL_SHA256
    },
  }
  const gate = new PaidMediaMutationGate(authority)
  const dependencies: PaidMediaRecoveryExecutorDependencies = {
    authority,
    gate,
    intentStore: store,
    ledger: {
      ensureV2DispatchingOnce: vi.fn(async () => {
        throw new Error('unexpected dispatch mutation')
      }),
      ensureV2ResultReadyOnce: vi.fn(async () => {
        throw new Error('unexpected result-ready mutation')
      })
    },
    vault: {
      ...unexpectedStageVault(),
      verifyArchive: vi.fn(async () => {
        throw new Error('unexpected archive verification')
      }),
      recordAssetV2DispatchMarker: vi.fn(async () => {
        throw new Error('unexpected dispatch marker mutation')
      }),
      recordAssetAckIntent: vi.fn(async () => {
        throw new Error('unexpected ACK intent mutation')
      }),
      recordAssetAckCompletion: vi.fn(async (input) => {
        gate.guard()
        calls.push('vault:ack-completion')
        const candidate = digest({
          operationId: input.operationId,
          intentReceiptSha256: input.intentReceiptSha256,
          status: input.status,
          ok: input.response.ok,
          turnId: input.response.turnId,
          cleanupComplete: input.response.cleanupComplete
        })
        if (completionReceiptSha256 === null) {
          completionReceiptSha256 = candidate
          writes.vault += 1
        } else if (completionReceiptSha256 !== candidate) {
          throw new Error('vault ACK completion conflict')
        }
        return { operationId: input.operationId, receiptSha256: completionReceiptSha256 }
      }),
      recordAssetCapacityReleaseAuthorization: vi.fn(async () => {
        throw new Error('unexpected capacity authorization mutation')
      })
    },
    capacity: {
      ensureReservation: vi.fn(async () => {
        throw new Error('unexpected capacity reservation')
      }),
      ensureReleasedWithAuthorization: vi.fn(async () => {
        throw new Error('unexpected capacity release')
      })
    }
  }
  return {
    executor: new PaidMediaRecoveryExecutor(dependencies),
    dependencies,
    writes,
    calls
  }
}

function capacityFixture(
  store: PaidMediaRecoveryIntentStore,
  descriptor: PaidMediaRecoverableMutationDescriptor
): Fixture & { capacityWrites: () => number } {
  const calls: string[] = []
  const writes = { vault: 0, ledger: 0 }
  let capacityWrites = 0
  let authorizationReceiptSha256: string | null = null
  let capacityTombstone: {
    operationId: string
    authorizationReceiptSha256: string
    releasedAt: number
    releasedReservationSha256: string | null
  } | null = null
  const pendingRecovery = Object.freeze({
    handlerVersion: descriptor.handlerVersion,
    kind: descriptor.kind,
    operationId: descriptor.operationId,
    intentSha256: descriptor.intentSha256,
    preparedAt: descriptor.preparedAt,
    beforeCompositeDigest: descriptor.beforeCompositeDigest
  })
  const authority = {
    get state() {
      return {
        mode: 'recovery_pending' as const,
        reasonCode: 'recoverable-local-handler-active',
        pendingRecovery
      }
    },
    assertMutationContext(transactionId?: string) {
      if (transactionId !== TRANSACTION_ID) throw new Error('wrong Root transaction')
    },
    localPaidPrincipal() {
      return PAID_PRINCIPAL_SHA256
    },
  }
  const gate = new PaidMediaMutationGate(authority)
  const dependencies: PaidMediaRecoveryExecutorDependencies = {
    authority,
    gate,
    intentStore: store,
    ledger: {
      ensureV2DispatchingOnce: vi.fn(async () => {
        throw new Error('unexpected dispatch mutation')
      }),
      ensureV2ResultReadyOnce: vi.fn(async () => {
        throw new Error('unexpected result-ready mutation')
      })
    },
    vault: {
      ...unexpectedStageVault(),
      verifyArchive: vi.fn(async () => {
        throw new Error('unexpected archive verification')
      }),
      recordAssetV2DispatchMarker: vi.fn(async () => {
        throw new Error('unexpected dispatch marker mutation')
      }),
      recordAssetAckIntent: vi.fn(async () => {
        throw new Error('unexpected ACK intent mutation')
      }),
      recordAssetAckCompletion: vi.fn(async () => {
        throw new Error('unexpected ACK completion mutation')
      }),
      recordAssetCapacityReleaseAuthorization: vi.fn(async (input) => {
        gate.guard()
        calls.push('vault:capacity-authorization')
        const candidate = digest(input)
        if (authorizationReceiptSha256 === null) {
          authorizationReceiptSha256 = candidate
          writes.vault += 1
        } else if (authorizationReceiptSha256 !== candidate) {
          throw new Error('vault capacity authorization conflict')
        }
        return { operationId: input.operationId, receiptSha256: authorizationReceiptSha256 }
      })
    },
    capacity: {
      ensureReservation: vi.fn(async () => {
        throw new Error('unexpected capacity reservation')
      }),
      ensureReleasedWithAuthorization: vi.fn(async (input) => {
        gate.guard()
        calls.push('capacity:ensure-authorized-release')
        if (capacityTombstone === null) {
          capacityTombstone = {
            operationId: input.operationId,
            authorizationReceiptSha256: input.authorizationReceiptSha256,
            releasedAt: 1_784_200_001,
            releasedReservationSha256: 'a'.repeat(64)
          }
          capacityWrites += 1
        } else if (
          capacityTombstone.operationId !== input.operationId ||
          capacityTombstone.authorizationReceiptSha256 !==
            input.authorizationReceiptSha256
        ) {
          throw new Error('capacity release authorization conflict')
        }
        return capacityTombstone
      })
    }
  }
  return {
    executor: new PaidMediaRecoveryExecutor(dependencies),
    dependencies,
    writes,
    calls,
    capacityWrites: () => capacityWrites
  }
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true })
})

describe('PaidMediaRecoveryExecutor', () => {
  it('executes an exact Root-authorized dispatch intent and replays it without another write', async () => {
    const store = intentStore()
    const prepared = await store.prepare(dispatchPayload())
    const descriptor = rootDescriptor(prepared)
    const item = fixture(store, descriptor)

    const first = await item.executor.execute(descriptor)
    const replay = await item.executor.execute(descriptor)

    expect(replay).toEqual(first)
    expect(first).toMatchObject({
      schema: 'nachuan.paid-media-recovery-executor.receipt.v1',
      handlerVersion: 1,
      kind: 'asset_v2_dispatch',
      operationId: OPERATION_ID,
      intentSha256: prepared.intentSha256,
      status: 'verified',
      localEvidence: {
        state: 'dispatching',
        dispatchCount: 1
      }
    })
    expect(item.writes).toEqual({ vault: 1, ledger: 1 })
    expect(item.capacityReservationWrites()).toBe(1)
    expect(item.calls).toEqual([
      'capacity:reservation',
      'vault:dispatch',
      'ledger:dispatch',
      'capacity:reservation',
      'vault:dispatch',
      'ledger:dispatch'
    ])
    expect(Buffer.byteLength(JSON.stringify(first), 'utf8')).toBeLessThanOrEqual(4096)
    expect(JSON.stringify(first)).not.toContain(PAID_PRINCIPAL_SHA256)
  })

  it('enters the unique shared recoverable gate with the full Root descriptor', async () => {
    const store = intentStore()
    const prepared = await store.prepare(dispatchPayload())
    const descriptor = rootDescriptor(prepared)
    const item = fixture(store, descriptor)

    expect(item.dependencies.gate).toBeInstanceOf(PaidMediaMutationGate)
    await expect(item.executor.execute(descriptor)).resolves.toMatchObject({
      kind: 'asset_v2_dispatch',
      status: 'verified'
    })
    expect(item.writes).toEqual({ vault: 1, ledger: 1 })
  })

  it('single-flights concurrent exact replay through one rooted local mutation', async () => {
    const store = intentStore()
    const prepared = await store.prepare(dispatchPayload())
    const descriptor = rootDescriptor(prepared)
    const item = fixture(store, descriptor)

    const [left, right] = await Promise.all([
      item.executor.execute(descriptor),
      item.executor.execute(descriptor)
    ])

    expect(right).toEqual(left)
    expect(item.writes).toEqual({ vault: 1, ledger: 1 })
    expect(item.capacityReservationWrites()).toBe(1)
    expect(item.calls).toEqual([
      'capacity:reservation',
      'vault:dispatch',
      'ledger:dispatch'
    ])
  })

  it('replays the same receipt after recreating the executor over durable local APIs', async () => {
    const store = intentStore()
    const prepared = await store.prepare(dispatchPayload())
    const descriptor = rootDescriptor(prepared)
    const item = fixture(store, descriptor)
    const first = await item.executor.execute(descriptor)

    const restarted = new PaidMediaRecoveryExecutor(item.dependencies)
    const replay = await restarted.execute(descriptor)

    expect(replay).toEqual(first)
    expect(item.writes).toEqual({ vault: 1, ledger: 1 })
  })

  it('has no fallback when the shared mutation context gate is absent', () => {
    expect(() => new PaidMediaRecoveryExecutor({} as never)).toThrow(/dependencies/i)
  })

  it('rejects a dispatch intent whose paid principal is not the rooted recovery principal', async () => {
    const store = intentStore()
    const prepared = await store.prepare({
      ...dispatchPayload(),
      paidPrincipalSha256: '3'.repeat(64)
    })
    const descriptor = rootDescriptor(prepared)
    const item = fixture(store, descriptor)

    await expect(item.executor.execute(descriptor)).rejects.toThrow(/principal|binding/i)
    expect(item.writes).toEqual({ vault: 0, ledger: 0 })
  })

  it('persists an ACK intent before result-ready and returns the same secret-free replay receipt', async () => {
    const store = intentStore()
    const payload = resultReadyPayload()
    const prepared = await store.prepare(payload)
    const descriptor = rootDescriptor(prepared)
    const item = resultFixture(store, descriptor)

    const first = await item.executor.execute(descriptor)
    const replay = await item.executor.execute(descriptor)

    expect(replay).toEqual(first)
    expect(first).toMatchObject({
      kind: 'asset_v2_result_ready_ack_intent',
      status: 'verified',
      localEvidence: {
        state: 'result_ready',
        dispatchCount: 1,
        dispatchReceiptSha256: DISPATCH_RECEIPT_SHA256
      }
    })
    expect(item.writes).toEqual({ vault: 1, ledger: 1 })
    expect(item.calls).toEqual([
      'vault:verify-archive',
      'vault:ack-intent',
      'ledger:result-ready',
      'vault:verify-archive',
      'vault:ack-intent',
      'ledger:result-ready'
    ])
    expect(item.responseJson()).toBe(RECOVERY_JSON)
    expect(JSON.stringify(first)).not.toContain(TOKEN)
  })

  it('rejects an archive/result mismatch before writing an ACK intent or Ledger result', async () => {
    const store = intentStore()
    const prepared = await store.prepare(resultReadyPayload())
    const descriptor = rootDescriptor(prepared)
    const item = resultFixture(store, descriptor, {
      archiveResponseSha256: '1'.repeat(64)
    })

    await expect(item.executor.execute(descriptor)).rejects.toThrow(/archive.*match/i)
    expect(item.writes).toEqual({ vault: 0, ledger: 0 })
    expect(item.calls).toEqual(['vault:verify-archive'])
  })

  it('records a local ACK completion with semantic replay idempotency', async () => {
    const store = intentStore()
    const prepared = await store.prepare(ackCompletionPayload(true))
    const descriptor = rootDescriptor(prepared)
    const item = ackCompletionFixture(store, descriptor)

    const first = await item.executor.execute(descriptor)
    const replay = await item.executor.execute(descriptor)

    expect(replay).toEqual(first)
    expect(first).toMatchObject({
      kind: 'asset_v2_ack_completion',
      localEvidence: {
        state: 'ack_completed'
      }
    })
    expect(item.writes).toEqual({ vault: 1, ledger: 0 })
    expect(item.calls).toEqual([
      'vault:ack-completion',
      'vault:ack-completion'
    ])
  })

  it('persists capacity authorization before an idempotent local reservation release', async () => {
    const store = intentStore()
    const prepared = await store.prepare(capacityReleasePayload())
    const descriptor = rootDescriptor(prepared)
    const item = capacityFixture(store, descriptor)

    const first = await item.executor.execute(descriptor)
    const replay = await item.executor.execute(descriptor)

    expect(replay).toEqual(first)
    expect(first).toMatchObject({
      kind: 'asset_v2_capacity_release',
      localEvidence: {
        state: 'capacity_released'
      }
    })
    expect(item.writes).toEqual({ vault: 1, ledger: 0 })
    expect(item.capacityWrites()).toBe(1)
    expect(item.calls).toEqual([
      'vault:capacity-authorization',
      'capacity:ensure-authorized-release',
      'vault:capacity-authorization',
      'capacity:ensure-authorized-release'
    ])
  })

  it('durably reserves exact stage leases and replays after Main restart without inventing capabilities', async () => {
    const store = intentStore()
    const result = assetResult()
    const prepared = await store.prepare({
      kind: 'asset_v2_stage_reserve',
      operationId: OPERATION_ID,
      mode: 'fresh',
      result
    })
    const descriptor = rootDescriptor(prepared)
    const base = fixture(store, descriptor)
    const leaseId = '7'.repeat(64)
    const resultSha256 = paidMediaAssetResultDigest(result)
    const leaseStateDigest = '8'.repeat(64)
    let reserved = false
    let reserveCalls = 0
    const capability = Object.freeze({
      leaseId,
      operationId: OPERATION_ID,
      turnId: TURN_ID,
      ordinal: 0,
      descriptor: result.assets[0]!,
      write: vi.fn(async (bytes: Uint8Array) => ({ bytesWritten: bytes.byteLength })),
      sync: vi.fn(async () => undefined)
    })
    const dependencies = {
      ...base.dependencies,
      vault: {
        ...base.dependencies.vault,
        reserveAndOpenStageLeases: vi.fn(async () => {
          base.dependencies.gate.guard()
          reserveCalls += 1
          reserved = true
          return Object.freeze({ ok: true as const, capabilities: Object.freeze([capability]) })
        }),
        reclaimStageLease: vi.fn(async () => {
          throw new Error('fresh reservation must not reclaim')
        }),
        inspectStageRecovery: vi.fn(async () => ({
          leases: reserved
            ? [
                {
                  leaseId,
                  operationId: OPERATION_ID,
                  turnId: TURN_ID,
                  ordinal: 0,
                  generation: 0,
                  resultSha256,
                  leaseStateDigest,
                  state: 'opened' as const,
                  disposition: 'reclaim' as const,
                  reasonCode: null
                }
              ]
            : [],
          requiresRootMutation: true as const,
          ageBasedDecision: false as const
        }))
      }
    } as PaidMediaRecoveryExecutorDependencies
    const executor = new PaidMediaRecoveryExecutor(dependencies)

    const first = await executor.execute(descriptor)
    expect(first).toMatchObject({
      kind: 'asset_v2_stage_reserve',
      localEvidence: {
        state: 'stage_reserved',
        resultSha256,
        leases: [
          { leaseId, generation: 0, leaseStateDigest }
        ]
      }
    })
    expect(executor.takeStageOpenResult(prepared)).toEqual({
      ok: true,
      capabilities: [capability]
    })

    const restarted = new PaidMediaRecoveryExecutor(dependencies)
    await expect(restarted.execute(descriptor)).resolves.toEqual(first)
    expect(restarted.takeStageOpenResult(prepared)).toBeNull()
    expect(reserveCalls).toBe(1)
  })

  it('reclaims only an exact durable stage generation and hands off the fenced capability', async () => {
    const store = intentStore()
    const result = assetResult()
    const leaseId = '7'.repeat(64)
    const resultSha256 = paidMediaAssetResultDigest(result)
    const oldLeaseStateDigest = '8'.repeat(64)
    const newLeaseStateDigest = '9'.repeat(64)
    const prepared = await store.prepare({
      kind: 'asset_v2_stage_reserve',
      operationId: OPERATION_ID,
      mode: 'reclaim',
      result,
      leases: [
        {
          leaseId,
          ordinal: 0,
          generation: 3,
          resultSha256,
          leaseStateDigest: oldLeaseStateDigest
        }
      ]
    })
    const descriptor = rootDescriptor(prepared)
    const base = fixture(store, descriptor)
    let generation = 3
    let leaseStateDigest = oldLeaseStateDigest
    let reclaimWrites = 0
    const capability = Object.freeze({
      leaseId,
      operationId: OPERATION_ID,
      turnId: TURN_ID,
      ordinal: 0,
      descriptor: result.assets[0]!,
      write: vi.fn(async (bytes: Uint8Array) => ({ bytesWritten: bytes.byteLength })),
      sync: vi.fn(async () => undefined)
    })
    const dependencies = {
      ...base.dependencies,
      vault: {
        ...base.dependencies.vault,
        reserveAndOpenStageLeases: vi.fn(async () => {
          throw new Error('reclaim must not reserve a fresh lease')
        }),
        reclaimStageLease: vi.fn(async (input) => {
          base.dependencies.gate.guard()
          expect(input).toEqual({ operationId: OPERATION_ID, result, leaseId })
          reclaimWrites += 1
          generation = 4
          leaseStateDigest = newLeaseStateDigest
          return Object.freeze({ ok: true as const, capability })
        }),
        inspectStageRecovery: vi.fn(async () => ({
          leases: [
            {
              leaseId,
              operationId: OPERATION_ID,
              turnId: TURN_ID,
              ordinal: 0,
              generation,
              resultSha256,
              leaseStateDigest,
              state: 'opened' as const,
              disposition: 'reclaim' as const,
              reasonCode: null
            }
          ],
          requiresRootMutation: true as const,
          ageBasedDecision: false as const
        }))
      }
    } as PaidMediaRecoveryExecutorDependencies
    const executor = new PaidMediaRecoveryExecutor(dependencies)

    await expect(executor.execute(descriptor)).resolves.toMatchObject({
      kind: 'asset_v2_stage_reserve',
      localEvidence: {
        state: 'stage_reserved',
        resultSha256,
        leases: [
          { leaseId, generation: 4, leaseStateDigest: newLeaseStateDigest }
        ]
      }
    })
    expect(executor.takeStageOpenResult(prepared)).toEqual({
      ok: true,
      capabilities: [capability]
    })
    expect(reclaimWrites).toBe(1)
  })

  it('resumes a partially reclaimed multi-asset intent without losing its exact baseline', async () => {
    const store = intentStore()
    const first = assetResult()
    const result = {
      ...first,
      assets: [
        first.assets[0]!,
        {
          ...first.assets[0]!,
          token: `nma1_${'B'.repeat(43)}`,
          sha256: '3'.repeat(64),
          validationReceiptSha256: '2'.repeat(64)
        }
      ]
    }
    const resultSha256 = paidMediaAssetResultDigest(result)
    const leaseIds = ['7'.repeat(64), '6'.repeat(64)]
    const baselineDigests = ['8'.repeat(64), '9'.repeat(64)]
    const generations = [3, 3]
    const stateDigests = [...baselineDigests]
    const prepared = await store.prepare({
      kind: 'asset_v2_stage_reserve',
      operationId: OPERATION_ID,
      mode: 'reclaim',
      result,
      leases: leaseIds.map((leaseId, ordinal) => ({
        leaseId,
        ordinal,
        generation: 3,
        resultSha256,
        leaseStateDigest: baselineDigests[ordinal]!
      }))
    })
    const descriptor = rootDescriptor(prepared)
    const base = fixture(store, descriptor)
    let failSecondOnce = true
    let reclaimCalls = 0
    const capability = (ordinal: number) =>
      Object.freeze({
        leaseId: leaseIds[ordinal]!,
        operationId: OPERATION_ID,
        turnId: TURN_ID,
        ordinal,
        descriptor: result.assets[ordinal]!,
        write: vi.fn(async (bytes: Uint8Array) => ({ bytesWritten: bytes.byteLength })),
        sync: vi.fn(async () => undefined)
      })
    const dependencies = {
      ...base.dependencies,
      vault: {
        ...base.dependencies.vault,
        reserveAndOpenStageLeases: vi.fn(async () => {
          throw new Error('partial reclaim must not reserve fresh leases')
        }),
        reclaimStageLease: vi.fn(async (input) => {
          base.dependencies.gate.guard()
          reclaimCalls += 1
          const ordinal = leaseIds.indexOf(input.leaseId)
          if (ordinal === 1 && failSecondOnce) {
            failSecondOnce = false
            throw new Error('injected second reclaim interruption')
          }
          generations[ordinal]! += 1
          stateDigests[ordinal] = createHash('sha256')
            .update(`${ordinal}:${generations[ordinal]}`)
            .digest('hex')
          return Object.freeze({ ok: true as const, capability: capability(ordinal) })
        }),
        inspectStageRecovery: vi.fn(async () => ({
          leases: leaseIds.map((leaseId, ordinal) => ({
            leaseId,
            operationId: OPERATION_ID,
            turnId: TURN_ID,
            ordinal,
            generation: generations[ordinal]!,
            resultSha256,
            leaseStateDigest: stateDigests[ordinal]!,
            state: 'opened' as const,
            disposition: 'reclaim' as const,
            reasonCode: null
          })),
          requiresRootMutation: true as const,
          ageBasedDecision: false as const
        }))
      }
    } as PaidMediaRecoveryExecutorDependencies
    const executor = new PaidMediaRecoveryExecutor(dependencies)

    await expect(executor.execute(descriptor)).rejects.toThrow(/reclaim.*failed/i)
    expect(generations).toEqual([4, 3])
    await expect(executor.execute(descriptor)).resolves.toMatchObject({
      localEvidence: {
        state: 'stage_reserved',
        leases: [
          { leaseId: leaseIds[0], generation: 5 },
          { leaseId: leaseIds[1], generation: 4 }
        ]
      }
    })
    expect(executor.takeStageOpenResult(prepared)).toMatchObject({
      ok: true,
      capabilities: [
        { leaseId: leaseIds[0], ordinal: 0 },
        { leaseId: leaseIds[1], ordinal: 1 }
      ]
    })
    expect(reclaimCalls).toBe(4)
  })

  it('cleans only the exact generation and lease-state intent and replays the terminal state', async () => {
    const store = intentStore()
    const leaseId = '7'.repeat(64)
    const resultSha256 = '8'.repeat(64)
    const leaseStateDigest = '9'.repeat(64)
    const prepared = await store.prepare({
      kind: 'asset_v2_stage_cleanup',
      operationId: OPERATION_ID,
      leases: [{ leaseId, generation: 3, resultSha256, leaseStateDigest }]
    })
    const descriptor = rootDescriptor(prepared)
    const base = fixture(store, descriptor)
    let active = true
    let cleanupWrites = 0
    const dependencies = {
      ...base.dependencies,
      vault: {
        ...base.dependencies.vault,
        inspectStageRecovery: vi.fn(async () => ({
          leases: active
            ? [
                {
                  leaseId,
                  operationId: OPERATION_ID,
                  turnId: TURN_ID,
                  ordinal: 0,
                  generation: 3,
                  resultSha256,
                  leaseStateDigest,
                  state: 'opened' as const,
                  disposition: 'reclaim' as const,
                  reasonCode: null
                }
              ]
            : [],
          requiresRootMutation: true as const,
          ageBasedDecision: false as const
        })),
        cleanupStageLease: vi.fn(async (input) => {
          base.dependencies.gate.guard()
          expect(input).toEqual({
            operationId: OPERATION_ID,
            leaseId,
            generation: 3,
            resultSha256
          })
          if (active) {
            active = false
            cleanupWrites += 1
          }
          return { status: 'cleaned' as const }
        })
      }
    } as PaidMediaRecoveryExecutorDependencies
    const executor = new PaidMediaRecoveryExecutor(dependencies)

    const first = await executor.execute(descriptor)
    const restarted = new PaidMediaRecoveryExecutor(dependencies)
    const replay = await restarted.execute(descriptor)

    expect(replay).toEqual(first)
    expect(first).toMatchObject({
      kind: 'asset_v2_stage_cleanup',
      localEvidence: {
        state: 'stage_cleaned',
        leases: [{ leaseId, generation: 3 }]
      }
    })
    expect(cleanupWrites).toBe(1)
  })

  it('archives restart-pinned stage bytes from exact lease and validation evidence without a sealed capability', async () => {
    const store = intentStore()
    const validation = trustedValidation()
    const result = assetResult(validation.receiptSha256)
    const resultSha256 = paidMediaAssetResultDigest(result)
    const leaseId = '7'.repeat(64)
    const payload = {
      kind: 'asset_v2_stage_archive' as const,
      operationId: OPERATION_ID,
      result,
      leases: [
        {
          leaseId,
          ordinal: 0,
          generation: 2,
          resultSha256,
          leaseStateDigest: '9'.repeat(64)
        }
      ],
      validations: [validation]
    }
    const prepared = await store.prepare(payload)
    const descriptor = rootDescriptor(prepared)
    const base = fixture(store, descriptor)
    let archiveWrites = 0
    const archived = {
      receipt: {
        operationId: OPERATION_ID,
        receiptSha256: ARCHIVE_RECEIPT_SHA256,
        responseSha256: createHash('sha256')
          .update(canonicalPaidMediaAssetResult(result))
          .digest('hex'),
        responseByteLength: canonicalPaidMediaAssetResult(result).byteLength
      },
      recoveryJson: RECOVERY_JSON,
      cleanupComplete: true
    }
    const dependencies = {
      ...base.dependencies,
      vault: {
        ...base.dependencies.vault,
        archiveRecoveredStageImageResult: vi.fn(async (input) => {
          base.dependencies.gate.guard()
          expect(input).toEqual({
            operationId: OPERATION_ID,
            status: 200,
            result,
            leases: payload.leases,
            validations: [validation]
          })
          if (archiveWrites === 0) archiveWrites += 1
          return archived
        })
      }
    } as PaidMediaRecoveryExecutorDependencies
    const executor = new PaidMediaRecoveryExecutor(dependencies)

    const first = await executor.execute(descriptor)
    const restarted = new PaidMediaRecoveryExecutor(dependencies)
    const replay = await restarted.execute(descriptor)

    expect(replay).toEqual(first)
    expect(first).toMatchObject({
      kind: 'asset_v2_stage_archive',
      localEvidence: {
        state: 'stage_archived',
        archiveReceiptSha256: ARCHIVE_RECEIPT_SHA256,
        resultSha256,
        cleanupComplete: true
      }
    })
    expect(archiveWrites).toBe(1)
  })

  it('rejects an ordinary intent descriptor that has no active Root recovery ticket', async () => {
    const store = intentStore()
    const prepared = await store.prepare(dispatchPayload())
    const descriptor = rootDescriptor(prepared)
    const item = fixture(store, descriptor)

    await expect(item.executor.execute(prepared)).rejects.toThrow(/descriptor/i)
    expect(item.calls).toEqual([])
    expect(item.writes).toEqual({ vault: 0, ledger: 0 })
  })

  it('rejects Root transaction, pending summary, and content-address bindings before local writes', async () => {
    const store = intentStore()
    const prepared = await store.prepare(dispatchPayload())
    const descriptor = rootDescriptor(prepared)

    const wrongTransaction = Object.freeze({
      ...descriptor,
      transactionId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc'
    })
    const wrongTransactionItem = fixture(store, wrongTransaction)
    await expect(wrongTransactionItem.executor.execute(wrongTransaction)).rejects.toThrow(
      /Root transaction/i
    )
    expect(wrongTransactionItem.writes).toEqual({ vault: 0, ledger: 0 })

    const extraFieldItem = fixture(store, descriptor)
    await expect(
      extraFieldItem.executor.execute({ ...descriptor, ordinary: true })
    ).rejects.toThrow(/descriptor/i)
    expect(extraFieldItem.calls).toEqual([])

    const wrongContentAddress = Object.freeze({
      ...descriptor,
      intentSha256: 'a'.repeat(64)
    })
    const wrongContentItem = fixture(store, wrongContentAddress)
    await expect(wrongContentItem.executor.execute(wrongContentAddress)).rejects.toThrow()
    expect(wrongContentItem.writes).toEqual({ vault: 0, ledger: 0 })
  })

  it('rejects a mutation gate bound to a different Root authority', async () => {
    const store = intentStore()
    const prepared = await store.prepare(dispatchPayload())
    const descriptor = rootDescriptor(prepared)
    const item = fixture(store, descriptor)
    const foreignAuthority = {
      assertMutationContext: item.dependencies.authority.assertMutationContext,
      localPaidPrincipal: item.dependencies.authority.localPaidPrincipal,
      get state() {
        return item.dependencies.authority.state
      }
    }
    const foreignGate = new PaidMediaMutationGate(foreignAuthority)

    expect(
      () =>
        new PaidMediaRecoveryExecutor({
          ...item.dependencies,
          gate: foreignGate
        })
    ).toThrow(/dependencies/i)
    expect(item.calls).toEqual([])
    expect(item.writes).toEqual({ vault: 0, ledger: 0 })
  })

  it('rejects a different content-addressed intent after completing a one-shot operation kind', async () => {
    const store = intentStore()
    const firstPrepared = await store.prepare(dispatchPayload())
    const firstDescriptor = rootDescriptor(firstPrepared)
    const item = fixture(store, firstDescriptor)
    await item.executor.execute(firstDescriptor)

    const conflictingPrepared = await store.prepare({
      ...dispatchPayload(),
      claim: {
        ...dispatchPayload().claim,
        requestSha256: 'f'.repeat(64)
      }
    })
    const conflictingDescriptor = rootDescriptor(conflictingPrepared)
    await expect(item.executor.execute(conflictingDescriptor)).rejects.toThrow(
      /completed binding/i
    )
    expect(item.writes).toEqual({ vault: 1, ledger: 1 })
  })
})
