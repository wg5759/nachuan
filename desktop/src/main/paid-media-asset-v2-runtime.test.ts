import { createHash } from 'node:crypto'

import { describe, expect, it, vi } from 'vitest'

import {
  PAID_MEDIA_ASSET_RESULT_SCHEMA,
  paidMediaAssetResultDigest,
  paidMediaTokenSetDigest,
  type PaidMediaAssetResult
} from './paid-media-asset-protocol'
import { PAID_MEDIA_RECOVERABLE_HANDLER_VERSION } from './paid-media-installation-root'
import { PAID_MEDIA_CAPACITY_BUDGET_POLICY } from './paid-media-capacity'
import type {
  PaidMediaRecoveryIntentDescriptor,
  PaidMediaRecoveryIntentPayload
} from './paid-media-recovery-intent'
import {
  convergePaidMediaAssetV2StartupAcks,
  PaidMediaAssetV2Runtime
} from './paid-media-asset-v2-runtime'

const OPERATION_ID = 'desktop-op-11111111-1111-4111-8111-111111111111'
const TURN_ID = '1'.repeat(64)
const DISPATCH_RECEIPT = '2'.repeat(64)
const ACK_INTENT_RECEIPT = '3'.repeat(64)
const ARCHIVE_RECEIPT = '4'.repeat(64)
const ACK_COMPLETION_RECEIPT = '5'.repeat(64)
const CAPACITY_RECEIPT = '6'.repeat(64)
const TOKEN = `nma1_${'A'.repeat(43)}`

function result(): PaidMediaAssetResult {
  return Object.freeze({
    schema: PAID_MEDIA_ASSET_RESULT_SCHEMA,
    kind: 'image' as const,
    created: 1_784_200_000,
    turnId: TURN_ID,
    assets: Object.freeze([
      Object.freeze({
        token: TOKEN,
        mediaType: 'image/png' as const,
        byteLength: 68,
        sha256: '7'.repeat(64),
        validationReceiptSha256: '8'.repeat(64)
      })
    ])
  })
}

function descriptor(payload: PaidMediaRecoveryIntentPayload): PaidMediaRecoveryIntentDescriptor {
  return Object.freeze({
    handlerVersion: PAID_MEDIA_RECOVERABLE_HANDLER_VERSION,
    kind: payload.kind,
    operationId: payload.operationId,
    intentSha256: createHash('sha256').update(JSON.stringify(payload)).digest('hex')
  })
}

function archivedResult(assetResult: PaidMediaAssetResult) {
  return {
    receipt: {
      schema: 'nachuan.paid-media-vault.receipt.v1' as const,
      operationId: OPERATION_ID,
      path: '/v1/images/generations' as const,
      requestSha256: '9'.repeat(64),
      responseSha256: 'a'.repeat(64),
      responseByteLength: 128,
      recoverySha256: 'b'.repeat(64),
      receiptSha256: ARCHIVE_RECEIPT,
      status: 200,
      kind: 'image' as const,
      assets: [],
      archivedAt: 3
    },
    result: assetResult,
    recoveryJson: JSON.stringify({ data: [{ url: 'nachuan-paid-media://sha256/asset' }] }),
    cleanupComplete: true
  }
}

describe('PaidMediaAssetV2Runtime', () => {
  it('selects only durable v2 result-ready operations for startup ACK convergence', async () => {
    const convergeImageAck = vi.fn(async () => true)
    const runRecoverableMutation = vi.fn()

    await convergePaidMediaAssetV2StartupAcks({
      runtime: { convergeImageAck },
      operations: [
        {
          operationId: OPERATION_ID,
          path: '/v1/images/generations',
          state: 'result_ready',
          createdAt: 1,
          updatedAt: 2,
          dispatchCount: 1,
          v2DispatchReceiptSha256: DISPATCH_RECEIPT,
          v2AckIntentReceiptSha256: ACK_INTENT_RECEIPT
        },
        {
          operationId: 'desktop-op-22222222-2222-4222-8222-222222222222',
          path: '/v1/images/generations',
          state: 'dispatching',
          createdAt: 1,
          updatedAt: 2,
          dispatchCount: 1,
          v2DispatchReceiptSha256: DISPATCH_RECEIPT
        },
        {
          operationId: 'desktop-op-33333333-3333-4333-8333-333333333333',
          path: '/v1/videos/generations',
          state: 'result_ready',
          createdAt: 1,
          updatedAt: 2,
          dispatchCount: 1
        }
      ],
      runRecoverableMutation,
      signal: new AbortController().signal,
      onError: vi.fn()
    })

    expect(convergeImageAck).toHaveBeenCalledOnce()
    expect(convergeImageAck).toHaveBeenCalledWith({
      operationId: OPERATION_ID,
      signal: expect.any(AbortSignal),
      runRecoverableMutation
    })
  })

  it('retries only a verified archive ACK after failure and never re-enters provider creation', async () => {
    const assetResult = result()
    const dispatch = {
      schema: 'nachuan.paid-media-vault.asset-v2-dispatch.v1' as const,
      operationId: OPERATION_ID,
      path: '/v1/images/generations' as const,
      requestSha256: '9'.repeat(64),
      recoveryDomainSha256: 'a'.repeat(64),
      paidPrincipalSha256: 'a'.repeat(64),
      turnId: null,
      assetResultSha256: null,
      receiptSha256: DISPATCH_RECEIPT
    }
    const ackIntent = {
      schema: 'nachuan.paid-media-vault.asset-ack-intent.v1' as const,
      operationId: OPERATION_ID,
      turnId: TURN_ID,
      tokenSetDigest: paidMediaTokenSetDigest([TOKEN]),
      archiveReceiptSha256: ARCHIVE_RECEIPT,
      assetResultSha256: paidMediaAssetResultDigest(assetResult),
      dispatchReceiptSha256: DISPATCH_RECEIPT,
      receiptSha256: ACK_INTENT_RECEIPT
    }
    const archived = archivedResult(assetResult)
    let completionExists = false
    let releaseExists = false
    const mutationKinds: string[] = []
    const acknowledge = vi
      .fn()
      .mockResolvedValueOnce({
        ok: false,
        status: 503,
        code: 'ack_unavailable',
        retryable: true
      })
      .mockResolvedValueOnce({ ok: true, cleanupComplete: true, replayed: true })
    const createImageAssets = vi.fn(async () => {
      throw new Error('ACK convergence must not create provider assets')
    })
    const downloadAsset = vi.fn(async () => {
      throw new Error('ACK convergence must not download provider assets')
    })
    const probeAsset = vi.fn(async () => {
      throw new Error('ACK convergence must not start a probe')
    })
    const runtime = new PaidMediaAssetV2Runtime({
      authority: {
        assertOutboundReady: vi.fn(async () => undefined),
        localPaidPrincipal: () => 'a'.repeat(64)
      },
      ledger: {
        listPublic: vi.fn(async () => [
          {
            operationId: OPERATION_ID,
            path: '/v1/images/generations' as const,
            state: 'result_ready' as const,
            createdAt: 1,
            updatedAt: 2,
            dispatchCount: 1,
            v2DispatchReceiptSha256: DISPATCH_RECEIPT,
            v2AckIntentReceiptSha256: ACK_INTENT_RECEIPT
          }
        ])
      },
      capacity: { listReservations: vi.fn(async () => []) },
      vault: {
        verifyArchive: vi.fn(async () => archived),
        verifyAssetV2DispatchMarker: vi.fn(async () => dispatch),
        verifyAssetAckIntent: vi.fn(async () => ackIntent),
        hasAssetAckCompletion: vi.fn(() => completionExists),
        verifyAssetAckCompletion: vi.fn(async () => ({
          schema: 'nachuan.paid-media-vault.asset-ack-completion.v1' as const,
          operationId: OPERATION_ID,
          intentReceiptSha256: ACK_INTENT_RECEIPT,
          status: 200 as const,
          turnId: TURN_ID,
          ok: true as const,
          cleanupComplete: true as const,
          semanticResponseSha256: 'b'.repeat(64),
          receiptSha256: ACK_COMPLETION_RECEIPT
        })),
        hasAssetCapacityReleaseAuthorization: vi.fn(() => releaseExists),
        verifyAssetCapacityReleaseAuthorization: vi.fn(async () => ({
          schema: 'nachuan.paid-media-vault.asset-capacity-release.v1' as const,
          operationId: OPERATION_ID,
          archiveReceiptSha256: ARCHIVE_RECEIPT,
          dispatchReceiptSha256: DISPATCH_RECEIPT,
          ackCompletionReceiptSha256: ACK_COMPLETION_RECEIPT,
          cleanupComplete: true as const,
          receiptSha256: CAPACITY_RECEIPT
        })),
        inspectStageRecovery: vi.fn(async () => {
          throw new Error('ACK convergence must not inspect stage recovery')
        }),
        sealStageWriteCapability: vi.fn(async () => {
          throw new Error('ACK convergence must not seal a stage')
        }),
        createSealedStageReadSource: vi.fn(() => {
          throw new Error('ACK convergence must not create a stage source')
        })
      },
      stageHandoff: { takeStageOpenResult: vi.fn(() => null) },
      createImageAssets,
      downloadAsset,
      probeAsset,
      acknowledgeAssets: acknowledge,
      audit: vi.fn()
    })
    const runRecoverableMutation = vi.fn(async (payload: PaidMediaRecoveryIntentPayload) => {
      mutationKinds.push(payload.kind)
      if (payload.kind === 'asset_v2_ack_completion') completionExists = true
      if (payload.kind === 'asset_v2_capacity_release') releaseExists = true
      return descriptor(payload)
    })
    const signal = new AbortController().signal

    await expect(
      runtime.convergeImageAck({ operationId: OPERATION_ID, signal, runRecoverableMutation })
    ).resolves.toBe(false)
    await expect(
      runtime.convergeImageAck({ operationId: OPERATION_ID, signal, runRecoverableMutation })
    ).resolves.toBe(true)

    expect(acknowledge).toHaveBeenCalledTimes(2)
    expect(mutationKinds).toEqual([
      'asset_v2_ack_completion',
      'asset_v2_capacity_release'
    ])
    expect(createImageAssets).not.toHaveBeenCalled()
    expect(downloadAsset).not.toHaveBeenCalled()
    expect(probeAsset).not.toHaveBeenCalled()
  })

  it('routes failure cleanup and the successful lifecycle through all seven recoverable intents', async () => {
    const assetResult = result()
    const requestSha256 = '9'.repeat(64)
    const principal = 'a'.repeat(64)
    const leaseId = 'b'.repeat(64)
    const leaseStateDigest = 'c'.repeat(64)
    const validation = {
      schema: 'nachuan.trusted-media-validation.v2' as const,
      validatorVersion: 'nachuan.trusted-media-probe.v2' as const,
      validationPolicy: 'nachuan.trusted-media-policy.av-closed.v1' as const,
      fullyDecoded: true as const,
      mediaType: 'image/png' as const,
      byteLength: 68,
      sha256: '7'.repeat(64),
      attestedTools: { ffmpegSha256: 'd'.repeat(64), ffprobeSha256: 'e'.repeat(64) },
      metadata: {
        detectedKind: 'image' as const,
        codecName: 'png',
        audioCodecName: null,
        videoStreamCount: 1 as const,
        audioStreamCount: 0 as const,
        formatName: 'png',
        width: 1,
        height: 1,
        durationMs: null,
        decodedFrames: 1
      },
      receiptSha256: '8'.repeat(64)
    }
    let operation = {
      operationId: OPERATION_ID,
      path: '/v1/images/generations' as const,
      state: 'claimed' as const,
      createdAt: 1,
      updatedAt: 1,
      dispatchCount: 0
    } as {
      operationId: string
      path: '/v1/images/generations'
      state: 'claimed' | 'dispatching' | 'result_ready'
      createdAt: number
      updatedAt: number
      dispatchCount: number
      v2DispatchReceiptSha256?: string
      v2AckIntentReceiptSha256?: string
    }
    let reservationActive = false
    let stageActive = false
    let archiveReady = false
    let ackIntentReady = false
    let completionExists = false
    let releaseExists = false
    let stageDescriptor: PaidMediaRecoveryIntentDescriptor | null = null
    const mutationKinds: string[] = []
    const capability = Object.freeze({
      leaseId,
      operationId: OPERATION_ID,
      turnId: TURN_ID,
      ordinal: 0,
      descriptor: assetResult.assets[0]!,
      write: vi.fn(async (bytes: Uint8Array) => ({ bytesWritten: bytes.byteLength })),
      sync: vi.fn(async () => undefined)
    })
    const dispatch = {
      schema: 'nachuan.paid-media-vault.asset-v2-dispatch.v1' as const,
      operationId: OPERATION_ID,
      path: '/v1/images/generations' as const,
      requestSha256,
      recoveryDomainSha256: principal,
      paidPrincipalSha256: principal,
      turnId: null,
      assetResultSha256: null,
      receiptSha256: DISPATCH_RECEIPT
    }
    const archived = archivedResult(assetResult)
    const ackIntent = {
      schema: 'nachuan.paid-media-vault.asset-ack-intent.v1' as const,
      operationId: OPERATION_ID,
      turnId: TURN_ID,
      tokenSetDigest: paidMediaTokenSetDigest([TOKEN]),
      archiveReceiptSha256: ARCHIVE_RECEIPT,
      assetResultSha256: paidMediaAssetResultDigest(assetResult),
      dispatchReceiptSha256: DISPATCH_RECEIPT,
      receiptSha256: ACK_INTENT_RECEIPT
    }
    const probeAsset = vi
      .fn()
      .mockRejectedValueOnce(new Error('injected stage probe failure'))
      .mockResolvedValue(validation)
    const runtime = new PaidMediaAssetV2Runtime({
      authority: {
        assertOutboundReady: vi.fn(async () => undefined),
        localPaidPrincipal: () => principal
      },
      ledger: { listPublic: vi.fn(async () => [operation]) },
      capacity: {
        listReservations: vi.fn(async () =>
          reservationActive
            ? [
                {
                  operationId: OPERATION_ID,
                  path: '/v1/images/generations' as const,
                  phase: 'active' as const,
                  budgetPolicy: PAID_MEDIA_CAPACITY_BUDGET_POLICY as typeof PAID_MEDIA_CAPACITY_BUDGET_POLICY,
                  roleBudgets: [],
                  perVolume: [],
                  createdAt: 1,
                  updatedAt: 1
                }
              ]
            : []
        )
      },
      vault: {
        verifyAssetV2DispatchMarker: vi.fn(async () => dispatch),
        inspectStageRecovery: vi.fn(async () => ({
          leases: stageActive
            ? [
                {
                  leaseId,
                  operationId: OPERATION_ID,
                  turnId: TURN_ID,
                  ordinal: 0,
                  generation: 0,
                  resultSha256: paidMediaAssetResultDigest(assetResult),
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
        sealStageWriteCapability: vi.fn(async () => capability),
        createSealedStageReadSource: vi.fn(() => ({
          byteLength: 68,
          sha256: '7'.repeat(64),
          createReadStream: vi.fn()
        })),
        verifyArchive: vi.fn(async () => {
          if (!archiveReady) throw new Error('archive is not ready')
          return archived
        }),
        verifyAssetAckIntent: vi.fn(async () => {
          if (!ackIntentReady) throw new Error('ACK intent is not ready')
          return ackIntent
        }),
        hasAssetAckCompletion: vi.fn(() => completionExists),
        verifyAssetAckCompletion: vi.fn(async () => ({
          schema: 'nachuan.paid-media-vault.asset-ack-completion.v1' as const,
          operationId: OPERATION_ID,
          intentReceiptSha256: ACK_INTENT_RECEIPT,
          status: 200 as const,
          turnId: TURN_ID,
          ok: true as const,
          cleanupComplete: true as const,
          semanticResponseSha256: 'f'.repeat(64),
          receiptSha256: ACK_COMPLETION_RECEIPT
        })),
        hasAssetCapacityReleaseAuthorization: vi.fn(() => releaseExists),
        verifyAssetCapacityReleaseAuthorization: vi.fn(async () => ({
          schema: 'nachuan.paid-media-vault.asset-capacity-release.v1' as const,
          operationId: OPERATION_ID,
          archiveReceiptSha256: ARCHIVE_RECEIPT,
          dispatchReceiptSha256: DISPATCH_RECEIPT,
          ackCompletionReceiptSha256: ACK_COMPLETION_RECEIPT,
          cleanupComplete: true as const,
          receiptSha256: CAPACITY_RECEIPT
        }))
      },
      stageHandoff: {
        takeStageOpenResult: vi.fn((candidate) =>
          candidate === stageDescriptor
            ? { ok: true as const, capabilities: [capability] }
            : null
        )
      },
      createImageAssets: vi.fn(async () => ({
        ok: true as const,
        status: 200 as const,
        replayed: false,
        result: assetResult
      })),
      downloadAsset: vi.fn(async () => undefined),
      probeAsset,
      acknowledgeAssets: vi.fn(async () => ({
        ok: true as const,
        cleanupComplete: true,
        replayed: false
      })),
      audit: vi.fn()
    })
    const runRecoverableMutation = vi.fn(async (payload: PaidMediaRecoveryIntentPayload) => {
      mutationKinds.push(payload.kind)
      const prepared = descriptor(payload)
      if (payload.kind === 'asset_v2_dispatch') {
        reservationActive = true
        operation = {
          ...operation,
          state: 'dispatching',
          updatedAt: 2,
          dispatchCount: 1,
          v2DispatchReceiptSha256: DISPATCH_RECEIPT
        }
      } else if (payload.kind === 'asset_v2_stage_reserve') {
        stageActive = true
        stageDescriptor = prepared
      } else if (payload.kind === 'asset_v2_stage_archive') {
        stageActive = false
        archiveReady = true
      } else if (payload.kind === 'asset_v2_stage_cleanup') {
        stageActive = false
      } else if (payload.kind === 'asset_v2_result_ready_ack_intent') {
        ackIntentReady = true
        operation = {
          ...operation,
          state: 'result_ready',
          updatedAt: 3,
          v2AckIntentReceiptSha256: ACK_INTENT_RECEIPT
        }
      } else if (payload.kind === 'asset_v2_ack_completion') {
        completionExists = true
      } else if (payload.kind === 'asset_v2_capacity_release') {
        releaseExists = true
      }
      return prepared
    })

    const executionInput = {
      operationId: OPERATION_ID,
      path: '/v1/images/generations' as const,
      encodedBody: JSON.stringify({ model: 'image-model', prompt: 'hello' }),
      requestSha256,
      recoveryDomainSha256: principal,
      idempotencyKey: 'idem_1234567890',
      signal: new AbortController().signal,
      runRecoverableMutation
    }

    await expect(runtime.executeImage(executionInput)).rejects.toThrow(
      'injected stage probe failure'
    )
    await expect(runtime.executeImage(executionInput)).resolves.toMatchObject({
      ok: true,
      archived,
      operation: { state: 'result_ready' }
    })

    expect(mutationKinds).toEqual([
      'asset_v2_dispatch',
      'asset_v2_stage_reserve',
      'asset_v2_stage_cleanup',
      'asset_v2_stage_reserve',
      'asset_v2_stage_archive',
      'asset_v2_result_ready_ack_intent',
      'asset_v2_ack_completion',
      'asset_v2_capacity_release'
    ])
  })
})
