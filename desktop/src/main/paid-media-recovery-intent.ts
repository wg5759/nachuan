import { createHash, randomBytes } from 'node:crypto'
import {
  closeSync,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  linkSync,
  openSync,
  readFileSync,
  realpathSync,
  unlinkSync,
  writeFileSync
} from 'node:fs'
import type { Stats } from 'node:fs'
import { basename, join, resolve } from 'node:path'

import type { PaidMediaAclHardener, PaidMediaPath, PaidMediaSafeStorage } from './paid-media-ledger'
import {
  PAID_MEDIA_RECOVERABLE_HANDLER_VERSION,
  type PaidMediaRecoverableMutationKind
} from './paid-media-installation-root'
import {
  paidMediaAssetResultDigest,
  parsePaidMediaAssetAck,
  parsePaidMediaAssetResult,
  type PaidMediaAssetDescriptor,
  type PaidMediaAssetAck,
  type PaidMediaAssetResult
} from './paid-media-asset-protocol'
import type { PaidMediaValidationReceipt } from './paid-media-vault'

const DOCUMENT_SCHEMA = 'nachuan.paid-media-recovery-intent.v1'
const ENVELOPE_SCHEMA = 'nachuan.paid-media-recovery-intent.envelope.v1'
const PROTECTION = 'electron-safe-storage'
const INTENT_DOMAIN = Buffer.from('nachuan.desktop.paid-media-recovery-intent.v1\0', 'ascii')
const OPERATION_ID_PATTERN = /^desktop-op-[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
const SHA256_PATTERN = /^[0-9a-f]{64}$/
const ZERO_SHA256 = '0'.repeat(64)
const MAX_PLAINTEXT_BYTES = 1024 * 1024
const MAX_FILE_BYTES = 2 * 1024 * 1024
const MAX_MEDIA_DIMENSION = 16_384
const MAX_MEDIA_PIXELS = 64 * 1024 * 1024
const TRUSTED_MEDIA_TYPES = new Set<string>([
  'image/png',
  'image/jpeg',
  'image/gif',
  'image/webp',
  'video/mp4',
  'video/webm'
])

export interface PaidMediaRecoveryDispatchPayload {
  readonly kind: 'asset_v2_dispatch'
  readonly operationId: string
  readonly claim: Readonly<{
    path: PaidMediaPath
    requestSha256: string
    recoveryDomainSha256: string
  }>
  readonly paidPrincipalSha256: string
}

export type PaidMediaRecoveryStageReservePayload =
  | Readonly<{
      kind: 'asset_v2_stage_reserve'
      operationId: string
      mode: 'fresh'
      result: PaidMediaAssetResult
    }>
  | Readonly<{
      kind: 'asset_v2_stage_reserve'
      operationId: string
      mode: 'reclaim'
      result: PaidMediaAssetResult
      leases: readonly Readonly<{
        leaseId: string
        ordinal: number
        generation: number
        resultSha256: string
        leaseStateDigest: string
      }>[]
    }>

export interface PaidMediaRecoveryStageArchivePayload {
  readonly kind: 'asset_v2_stage_archive'
  readonly operationId: string
  readonly result: PaidMediaAssetResult
  readonly leases: readonly Readonly<{
    leaseId: string
    ordinal: number
    generation: number
    resultSha256: string
    leaseStateDigest: string
  }>[]
  readonly validations: readonly PaidMediaValidationReceipt[]
}

export interface PaidMediaRecoveryStageCleanupPayload {
  readonly kind: 'asset_v2_stage_cleanup'
  readonly operationId: string
  readonly leases: readonly Readonly<{
    leaseId: string
    generation: number
    resultSha256: string
    leaseStateDigest: string
  }>[]
}

export interface PaidMediaRecoveryAckIntentPayload {
  readonly kind: 'asset_v2_result_ready_ack_intent'
  readonly operationId: string
  readonly result: PaidMediaAssetResult
  readonly archive: Readonly<{
    receiptSha256: string
    cleanupComplete: boolean
  }>
  readonly dispatch: Readonly<{ receiptSha256: string }>
  readonly ack: PaidMediaAssetAck
}

export interface PaidMediaRecoveryAckCompletionPayload {
  readonly kind: 'asset_v2_ack_completion'
  readonly operationId: string
  readonly intentReceiptSha256: string
  readonly status: 200
  readonly response: Readonly<{
    ok: true
    turnId: string
    replayed: boolean
    cleanupComplete: true
  }>
}

export interface PaidMediaRecoveryCapacityReleasePayload {
  readonly kind: 'asset_v2_capacity_release'
  readonly operationId: string
  readonly archive: Readonly<{
    receiptSha256: string
    cleanupComplete: true
  }>
  readonly dispatch: Readonly<{ receiptSha256: string }>
  readonly ackCompletion: Readonly<{ receiptSha256: string }>
}

export type PaidMediaRecoveryIntentPayload =
  | PaidMediaRecoveryDispatchPayload
  | PaidMediaRecoveryStageReservePayload
  | PaidMediaRecoveryStageArchivePayload
  | PaidMediaRecoveryStageCleanupPayload
  | PaidMediaRecoveryAckIntentPayload
  | PaidMediaRecoveryAckCompletionPayload
  | PaidMediaRecoveryCapacityReleasePayload

export interface PaidMediaRecoveryIntentDescriptor {
  readonly handlerVersion: typeof PAID_MEDIA_RECOVERABLE_HANDLER_VERSION
  readonly kind: PaidMediaRecoverableMutationKind
  readonly operationId: string
  readonly intentSha256: string
}

export type PaidMediaRecoveryIntentPublishPhase =
  | 'after_temp_fsync_before_publish'
  | 'after_publish_before_verify'

export interface PaidMediaRecoveryIntentPublishContext {
  readonly descriptor: PaidMediaRecoveryIntentDescriptor
  readonly temporaryPath: string
  readonly finalPath: string
}

export interface PaidMediaRecoveryIntentStoreDependencies {
  safeStorage: PaidMediaSafeStorage
  harden: PaidMediaAclHardener
  onPublishPhase?: (
    phase: PaidMediaRecoveryIntentPublishPhase,
    context: PaidMediaRecoveryIntentPublishContext
  ) => void | Promise<void>
}

interface RecoveryIntentDocument {
  schema: typeof DOCUMENT_SCHEMA
  handlerVersion: typeof PAID_MEDIA_RECOVERABLE_HANDLER_VERSION
  kind: PaidMediaRecoverableMutationKind
  operationId: string
  intentSha256: string
  payload: PaidMediaRecoveryIntentPayload
}

export class PaidMediaRecoveryIntentError extends Error {
  override readonly name = 'PaidMediaRecoveryIntentError'
}

function fail(message: string, cause?: unknown): PaidMediaRecoveryIntentError {
  return new PaidMediaRecoveryIntentError(
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

function requireOperationId(value: unknown): string {
  if (typeof value !== 'string' || !OPERATION_ID_PATTERN.test(value)) {
    throw fail('Paid media recovery intent operation id is invalid')
  }
  return value.toLowerCase()
}

function requireDigest(value: unknown, label: string): string {
  if (typeof value !== 'string' || !SHA256_PATTERN.test(value) || value === ZERO_SHA256) {
    throw fail(`${label} is invalid`)
  }
  return value
}

function requirePath(value: unknown): PaidMediaPath {
  if (value !== '/v1/images/generations' && value !== '/v1/videos/generations') {
    throw fail('Paid media recovery intent path is invalid')
  }
  return value
}

function canonicalStageCleanupLeases(value: unknown): PaidMediaRecoveryStageCleanupPayload['leases'] {
  if (!Array.isArray(value) || value.length < 1 || value.length > 4) {
    throw fail('Paid media stage cleanup recovery leases are invalid')
  }
  const leases = value.map((candidate) => {
    if (
      !isRecord(candidate) ||
      !exactKeys(candidate, [
        'leaseId',
        'generation',
        'resultSha256',
        'leaseStateDigest'
      ]) ||
      !Number.isSafeInteger(candidate.generation) ||
      Number(candidate.generation) < 0 ||
      Number(candidate.generation) >= 1_000_000
    ) {
      throw fail('Paid media stage cleanup recovery lease binding is invalid')
    }
    return Object.freeze({
      leaseId: requireDigest(candidate.leaseId, 'Paid media stage lease id'),
      generation: Number(candidate.generation),
      resultSha256: requireDigest(
        candidate.resultSha256,
        'Paid media stage cleanup result digest'
      ),
      leaseStateDigest: requireDigest(
        candidate.leaseStateDigest,
        'Paid media stage cleanup lease-state digest'
      )
    })
  })
  if (new Set(leases.map((lease) => lease.leaseId)).size !== leases.length) {
    throw fail('Paid media stage cleanup recovery lease bindings are duplicated')
  }
  leases.sort((left, right) => left.leaseId.localeCompare(right.leaseId, 'en'))
  return Object.freeze(leases)
}

function canonicalStageArchiveLeases(
  value: unknown,
  expectedCount: number,
  expectedResultSha256: string
): PaidMediaRecoveryStageArchivePayload['leases'] {
  if (!Array.isArray(value) || value.length !== expectedCount) {
    throw fail('Paid media stage archive recovery leases are invalid')
  }
  const leases = value.map((candidate, ordinal) => {
    if (
      !isRecord(candidate) ||
      !exactKeys(candidate, [
        'leaseId',
        'ordinal',
        'generation',
        'resultSha256',
        'leaseStateDigest'
      ]) ||
      candidate.ordinal !== ordinal ||
      !Number.isSafeInteger(candidate.generation) ||
      Number(candidate.generation) < 0 ||
      Number(candidate.generation) >= 1_000_000
    ) {
      throw fail('Paid media stage archive recovery lease binding is invalid')
    }
    const resultSha256 = requireDigest(
      candidate.resultSha256,
      'Paid media stage archive result digest'
    )
    if (resultSha256 !== expectedResultSha256) {
      throw fail('Paid media stage archive result digest does not match')
    }
    return Object.freeze({
      leaseId: requireDigest(candidate.leaseId, 'Paid media stage lease id'),
      ordinal,
      generation: Number(candidate.generation),
      resultSha256,
      leaseStateDigest: requireDigest(
        candidate.leaseStateDigest,
        'Paid media stage archive lease-state digest'
      )
    })
  })
  if (new Set(leases.map((lease) => lease.leaseId)).size !== leases.length) {
    throw fail('Paid media stage archive recovery lease bindings are duplicated')
  }
  return Object.freeze(leases)
}

function canonicalValidationReceipt(
  value: unknown,
  expected: PaidMediaAssetDescriptor
): PaidMediaValidationReceipt {
  if (
    !isRecord(value) ||
    !exactKeys(value, [
      'schema',
      'validatorVersion',
      'validationPolicy',
      'fullyDecoded',
      'mediaType',
      'byteLength',
      'sha256',
      'attestedTools',
      'metadata',
      'receiptSha256'
    ]) ||
    value.schema !== 'nachuan.trusted-media-validation.v2' ||
    value.validatorVersion !== 'nachuan.trusted-media-probe.v2' ||
    value.validationPolicy !== 'nachuan.trusted-media-policy.av-closed.v1' ||
    value.fullyDecoded !== true ||
    value.mediaType !== expected.mediaType ||
    value.byteLength !== expected.byteLength ||
    value.sha256 !== expected.sha256 ||
    !isRecord(value.attestedTools) ||
    !exactKeys(value.attestedTools, ['ffmpegSha256', 'ffprobeSha256']) ||
    !isRecord(value.metadata) ||
    !exactKeys(value.metadata, [
      'detectedKind',
      'codecName',
      'audioCodecName',
      'videoStreamCount',
      'audioStreamCount',
      'formatName',
      'width',
      'height',
      'durationMs',
      'decodedFrames'
    ])
  ) {
    throw fail('Paid media trusted validation recovery receipt is invalid')
  }
  const tools = value.attestedTools
  const metadata = value.metadata
  const ffmpegSha256 = requireDigest(
    tools.ffmpegSha256,
    'Paid media validation ffmpeg digest'
  )
  const ffprobeSha256 = requireDigest(
    tools.ffprobeSha256,
    'Paid media validation ffprobe digest'
  )
  const image = expected.mediaType.startsWith('image/')
  if (
    !TRUSTED_MEDIA_TYPES.has(expected.mediaType) ||
    metadata.detectedKind !== (image ? 'image' : 'video') ||
    typeof metadata.codecName !== 'string' ||
    !/^[\x20-\x7e]{1,128}$/.test(metadata.codecName) ||
    typeof metadata.formatName !== 'string' ||
    !/^[\x20-\x7e]{1,128}$/.test(metadata.formatName) ||
    !Number.isSafeInteger(metadata.width) ||
    Number(metadata.width) < 1 ||
    Number(metadata.width) > MAX_MEDIA_DIMENSION ||
    !Number.isSafeInteger(metadata.height) ||
    Number(metadata.height) < 1 ||
    Number(metadata.height) > MAX_MEDIA_DIMENSION ||
    Number(metadata.width) * Number(metadata.height) > MAX_MEDIA_PIXELS ||
    (image
      ? metadata.durationMs !== null
      : !Number.isSafeInteger(metadata.durationMs) ||
        Number(metadata.durationMs) < 1 ||
        Number(metadata.durationMs) > 86_400_000) ||
    !Number.isSafeInteger(metadata.decodedFrames) ||
    Number(metadata.decodedFrames) < 1 ||
    Number(metadata.decodedFrames) > 10_000_000 ||
    metadata.videoStreamCount !== 1 ||
    (metadata.audioStreamCount !== 0 && metadata.audioStreamCount !== 1) ||
    (metadata.audioCodecName !== null &&
      (typeof metadata.audioCodecName !== 'string' ||
        !/^[a-z0-9_.-]{1,64}$/.test(metadata.audioCodecName))) ||
    (metadata.audioStreamCount === 0) !== (metadata.audioCodecName === null) ||
    (image && (metadata.audioStreamCount !== 0 || metadata.audioCodecName !== null))
  ) {
    throw fail('Paid media trusted validation recovery metadata is invalid')
  }
  const mediaType = expected.mediaType as PaidMediaValidationReceipt['mediaType']
  const detectedKind: 'image' | 'video' = image ? 'image' : 'video'
  const base: Omit<PaidMediaValidationReceipt, 'receiptSha256'> = {
    schema: 'nachuan.trusted-media-validation.v2',
    validatorVersion: 'nachuan.trusted-media-probe.v2',
    validationPolicy: 'nachuan.trusted-media-policy.av-closed.v1',
    fullyDecoded: true,
    mediaType,
    byteLength: expected.byteLength,
    sha256: expected.sha256,
    attestedTools: Object.freeze({ ffmpegSha256, ffprobeSha256 }),
    metadata: Object.freeze({
      detectedKind,
      codecName: metadata.codecName,
      audioCodecName: metadata.audioCodecName as string | null,
      videoStreamCount: 1,
      audioStreamCount: metadata.audioStreamCount as 0 | 1,
      formatName: metadata.formatName,
      width: Number(metadata.width),
      height: Number(metadata.height),
      durationMs: metadata.durationMs === null ? null : Number(metadata.durationMs),
      decodedFrames: Number(metadata.decodedFrames)
    })
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
  const receiptSha256 = requireDigest(
    value.receiptSha256,
    'Paid media trusted validation receipt digest'
  )
  const expectedReceipt = createHash('sha256')
    .update('nachuan.trusted-media-validation.v2\0', 'utf8')
    .update(JSON.stringify(canonical), 'ascii')
    .digest('hex')
  if (
    receiptSha256 !== expectedReceipt ||
    receiptSha256 !== expected.validationReceiptSha256
  ) {
    throw fail('Paid media trusted validation recovery receipt does not match')
  }
  return Object.freeze({ ...base, receiptSha256 })
}

function assertPlainData(value: unknown, seen = new Set<object>()): void {
  if (
    value === null ||
    typeof value === 'string' ||
    typeof value === 'boolean'
  ) {
    return
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || Object.is(value, -0)) {
      throw fail('Paid media recovery intent contains an invalid number')
    }
    return
  }
  if (typeof value !== 'object') {
    throw fail('Paid media recovery intent must contain only plain data')
  }
  if (seen.has(value)) throw fail('Paid media recovery intent graph is cyclic or aliased')
  seen.add(value)
  if (Array.isArray(value)) {
    if (Object.getPrototypeOf(value) !== Array.prototype || value.length > 4096) {
      throw fail('Paid media recovery intent array is invalid')
    }
    const keys = Reflect.ownKeys(value)
    const expected = Array.from({ length: value.length }, (_, index) => String(index))
    if (
      keys.some((key) => typeof key === 'symbol') ||
      keys.length !== expected.length + 1 ||
      keys[keys.length - 1] !== 'length' ||
      expected.some((key, index) => keys[index] !== key)
    ) {
      throw fail('Paid media recovery intent array is sparse or extended')
    }
    const descriptors = Object.getOwnPropertyDescriptors(value)
    for (const key of expected) {
      const descriptor = descriptors[key]
      if (!descriptor || 'get' in descriptor || 'set' in descriptor || !descriptor.enumerable) {
        throw fail('Paid media recovery intent array contains accessor fields')
      }
      assertPlainData(descriptor.value, seen)
    }
    seen.delete(value)
    return
  }
  if (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) {
    throw fail('Paid media recovery intent must contain only plain objects')
  }
  const keys = Reflect.ownKeys(value)
  if (keys.some((key) => typeof key === 'symbol')) {
    throw fail('Paid media recovery intent contains symbol fields')
  }
  const descriptors = Object.getOwnPropertyDescriptors(value)
  for (const key of keys as string[]) {
    const descriptor = descriptors[key]
    if (!descriptor || 'get' in descriptor || 'set' in descriptor || !descriptor.enumerable) {
      throw fail('Paid media recovery intent contains accessor or hidden fields')
    }
    assertPlainData(descriptor.value, seen)
  }
  seen.delete(value)
}

function canonicalPayload(value: unknown): PaidMediaRecoveryIntentPayload {
  assertPlainData(value)
  if (!isRecord(value) || typeof value.kind !== 'string') {
    throw fail('Paid media recovery intent payload is invalid')
  }
  if (value.kind === 'asset_v2_dispatch') {
    if (
      !exactKeys(value, ['kind', 'operationId', 'claim', 'paidPrincipalSha256']) ||
      !isRecord(value.claim) ||
      !exactKeys(value.claim, ['path', 'requestSha256', 'recoveryDomainSha256'])
    ) {
      throw fail('Paid media dispatch recovery intent is invalid')
    }
    return Object.freeze({
      kind: 'asset_v2_dispatch',
      operationId: requireOperationId(value.operationId),
      claim: Object.freeze({
        path: requirePath(value.claim.path),
        requestSha256: requireDigest(value.claim.requestSha256, 'Paid media claim request digest'),
        recoveryDomainSha256: requireDigest(
          value.claim.recoveryDomainSha256,
          'Paid media claim recovery domain digest'
        )
      }),
      paidPrincipalSha256: requireDigest(
        value.paidPrincipalSha256,
        'Paid media paid principal digest'
      )
    })
  }
  if (value.kind === 'asset_v2_stage_reserve') {
    if (value.mode === 'fresh') {
      if (!exactKeys(value, ['kind', 'operationId', 'mode', 'result'])) {
        throw fail('Paid media fresh stage reservation recovery intent is invalid')
      }
      return Object.freeze({
        kind: 'asset_v2_stage_reserve',
        operationId: requireOperationId(value.operationId),
        mode: 'fresh',
        result: parsePaidMediaAssetResult(value.result)
      })
    }
    if (value.mode === 'reclaim') {
      if (!exactKeys(value, ['kind', 'operationId', 'mode', 'result', 'leases'])) {
        throw fail('Paid media reclaim stage reservation recovery intent is invalid')
      }
      const result = parsePaidMediaAssetResult(value.result)
      return Object.freeze({
        kind: 'asset_v2_stage_reserve',
        operationId: requireOperationId(value.operationId),
        mode: 'reclaim',
        result,
        leases: canonicalStageArchiveLeases(
          value.leases,
          result.assets.length,
          paidMediaAssetResultDigest(result)
        )
      })
    }
    throw fail('Paid media stage reservation recovery mode is invalid')
  }
  if (value.kind === 'asset_v2_stage_archive') {
    if (
      !exactKeys(value, ['kind', 'operationId', 'result', 'leases', 'validations']) ||
      !Array.isArray(value.validations)
    ) {
      throw fail('Paid media stage archive recovery intent is invalid')
    }
    const result = parsePaidMediaAssetResult(value.result)
    if (value.validations.length !== result.assets.length) {
      throw fail('Paid media stage archive validation count does not match')
    }
    return Object.freeze({
      kind: 'asset_v2_stage_archive',
      operationId: requireOperationId(value.operationId),
      result,
      leases: canonicalStageArchiveLeases(
        value.leases,
        result.assets.length,
        paidMediaAssetResultDigest(result)
      ),
      validations: Object.freeze(
        value.validations.map((validation, ordinal) =>
          canonicalValidationReceipt(validation, result.assets[ordinal]!)
        )
      )
    })
  }
  if (value.kind === 'asset_v2_stage_cleanup') {
    if (!exactKeys(value, ['kind', 'operationId', 'leases'])) {
      throw fail('Paid media stage cleanup recovery intent is invalid')
    }
    return Object.freeze({
      kind: 'asset_v2_stage_cleanup',
      operationId: requireOperationId(value.operationId),
      leases: canonicalStageCleanupLeases(value.leases)
    })
  }
  if (value.kind === 'asset_v2_result_ready_ack_intent') {
    if (
      !exactKeys(value, ['kind', 'operationId', 'result', 'archive', 'dispatch', 'ack']) ||
      !isRecord(value.archive) ||
      !exactKeys(value.archive, ['receiptSha256', 'cleanupComplete']) ||
      typeof value.archive.cleanupComplete !== 'boolean' ||
      !isRecord(value.dispatch) ||
      !exactKeys(value.dispatch, ['receiptSha256'])
    ) {
      throw fail('Paid media result-ready ACK recovery intent is invalid')
    }
    const result = parsePaidMediaAssetResult(value.result)
    const ack = parsePaidMediaAssetAck(value.ack)
    const archiveReceiptSha256 = requireDigest(
      value.archive.receiptSha256,
      'Paid media archive receipt digest'
    )
    if (
      ack.turnId !== result.turnId ||
      ack.archiveReceiptSha256 !== archiveReceiptSha256 ||
      JSON.stringify(ack.tokens) !==
        JSON.stringify(result.assets.map((asset) => asset.token))
    ) {
      throw fail('Paid media result-ready ACK does not match its asset result')
    }
    return Object.freeze({
      kind: 'asset_v2_result_ready_ack_intent',
      operationId: requireOperationId(value.operationId),
      result,
      archive: Object.freeze({
        receiptSha256: archiveReceiptSha256,
        cleanupComplete: value.archive.cleanupComplete
      }),
      dispatch: Object.freeze({
        receiptSha256: requireDigest(
          value.dispatch.receiptSha256,
          'Paid media dispatch receipt digest'
        )
      }),
      ack
    })
  }
  if (value.kind === 'asset_v2_ack_completion') {
    if (
      !exactKeys(value, [
        'kind',
        'operationId',
        'intentReceiptSha256',
        'status',
        'response'
      ]) ||
      value.status !== 200 ||
      !isRecord(value.response) ||
      !exactKeys(value.response, ['ok', 'turnId', 'replayed', 'cleanupComplete']) ||
      value.response.ok !== true ||
      typeof value.response.replayed !== 'boolean' ||
      value.response.cleanupComplete !== true
    ) {
      throw fail('Paid media ACK completion recovery intent is invalid')
    }
    return Object.freeze({
      kind: 'asset_v2_ack_completion',
      operationId: requireOperationId(value.operationId),
      intentReceiptSha256: requireDigest(
        value.intentReceiptSha256,
        'Paid media ACK intent receipt digest'
      ),
      status: 200,
      response: Object.freeze({
        ok: true,
        turnId: requireDigest(value.response.turnId, 'Paid media ACK completion turn id'),
        replayed: value.response.replayed,
        cleanupComplete: true
      })
    })
  }
  if (value.kind === 'asset_v2_capacity_release') {
    if (
      !exactKeys(value, ['kind', 'operationId', 'archive', 'dispatch', 'ackCompletion']) ||
      !isRecord(value.archive) ||
      !exactKeys(value.archive, ['receiptSha256', 'cleanupComplete']) ||
      value.archive.cleanupComplete !== true ||
      !isRecord(value.dispatch) ||
      !exactKeys(value.dispatch, ['receiptSha256']) ||
      !isRecord(value.ackCompletion) ||
      !exactKeys(value.ackCompletion, ['receiptSha256'])
    ) {
      throw fail('Paid media capacity release recovery intent is invalid')
    }
    return Object.freeze({
      kind: 'asset_v2_capacity_release',
      operationId: requireOperationId(value.operationId),
      archive: Object.freeze({
        receiptSha256: requireDigest(
          value.archive.receiptSha256,
          'Paid media archive receipt digest'
        ),
        cleanupComplete: true
      }),
      dispatch: Object.freeze({
        receiptSha256: requireDigest(
          value.dispatch.receiptSha256,
          'Paid media dispatch receipt digest'
        )
      }),
      ackCompletion: Object.freeze({
        receiptSha256: requireDigest(
          value.ackCompletion.receiptSha256,
          'Paid media ACK completion receipt digest'
        )
      })
    })
  }
  throw fail('Paid media recovery intent kind is invalid')
}

function descriptorFor(payload: PaidMediaRecoveryIntentPayload): PaidMediaRecoveryIntentDescriptor {
  const intentSha256 = createHash('sha256')
    .update(INTENT_DOMAIN)
    .update(String(PAID_MEDIA_RECOVERABLE_HANDLER_VERSION), 'ascii')
    .update('\0', 'ascii')
    .update(payload.kind, 'ascii')
    .update('\0', 'ascii')
    .update(payload.operationId, 'ascii')
    .update('\0', 'ascii')
    .update(JSON.stringify(payload), 'utf8')
    .digest('hex')
  if (intentSha256 === ZERO_SHA256) {
    throw fail('Paid media recovery intent digest is invalid')
  }
  return Object.freeze({
    handlerVersion: PAID_MEDIA_RECOVERABLE_HANDLER_VERSION,
    kind: payload.kind,
    operationId: payload.operationId,
    intentSha256
  })
}

function canonicalDescriptor(value: unknown): PaidMediaRecoveryIntentDescriptor {
  assertPlainData(value)
  if (
    !isRecord(value) ||
    !exactKeys(value, ['handlerVersion', 'kind', 'operationId', 'intentSha256']) ||
    value.handlerVersion !== PAID_MEDIA_RECOVERABLE_HANDLER_VERSION ||
    (value.kind !== 'asset_v2_dispatch' &&
      value.kind !== 'asset_v2_stage_reserve' &&
      value.kind !== 'asset_v2_stage_archive' &&
      value.kind !== 'asset_v2_stage_cleanup' &&
      value.kind !== 'asset_v2_result_ready_ack_intent' &&
      value.kind !== 'asset_v2_ack_completion' &&
      value.kind !== 'asset_v2_capacity_release')
  ) {
    throw fail('Paid media recovery intent descriptor is invalid')
  }
  return Object.freeze({
    handlerVersion: PAID_MEDIA_RECOVERABLE_HANDLER_VERSION,
    kind: value.kind,
    operationId: requireOperationId(value.operationId),
    intentSha256: requireDigest(value.intentSha256, 'Paid media recovery intent digest')
  })
}

function parseJsonObject(raw: string, label: string): Record<string, unknown> {
  try {
    const value: unknown = JSON.parse(raw)
    assertPlainData(value)
    if (!isRecord(value)) throw new Error('not an object')
    return value
  } catch (error) {
    if (error instanceof PaidMediaRecoveryIntentError) throw error
    throw fail(`${label} is corrupt`, error)
  }
}

function decodeBase64(value: unknown): Buffer {
  if (
    typeof value !== 'string' ||
    value.length < 4 ||
    value.length > MAX_FILE_BYTES * 2 ||
    value.length % 4 !== 0 ||
    !/^[A-Za-z0-9+/]+={0,2}$/.test(value)
  ) {
    throw fail('Paid media recovery intent envelope is invalid')
  }
  const bytes = Buffer.from(value, 'base64')
  if (bytes.toString('base64') !== value) {
    throw fail('Paid media recovery intent envelope is invalid')
  }
  return bytes
}

function sameIdentity(left: Stats, right: Stats): boolean {
  return (
    left.dev !== undefined &&
    right.dev !== undefined &&
    left.ino !== undefined &&
    right.ino !== undefined &&
    left.dev === right.dev &&
    left.ino === right.ino
  )
}

export class PaidMediaRecoveryIntentStore {
  private readonly root: string

  constructor(
    root: string,
    private readonly dependencies: PaidMediaRecoveryIntentStoreDependencies
  ) {
    this.root = resolve(root)
    if (
      !root ||
      !dependencies?.safeStorage ||
      typeof dependencies.safeStorage.isEncryptionAvailable !== 'function' ||
      typeof dependencies.safeStorage.encryptString !== 'function' ||
      typeof dependencies.safeStorage.decryptString !== 'function' ||
      typeof dependencies.harden !== 'function' ||
      (dependencies.onPublishPhase !== undefined &&
        typeof dependencies.onPublishPhase !== 'function')
    ) {
      throw fail('Paid media recovery intent dependencies are unavailable')
    }
    this.assertRoot()
  }

  private assertRoot(): void {
    const info = lstatSync(this.root)
    if (
      !info.isDirectory() ||
      info.isSymbolicLink() ||
      resolve(realpathSync(this.root)) !== this.root
    ) {
      throw fail('Paid media recovery intent root is redirected')
    }
    this.dependencies.harden(this.root, true)
  }

  private requireEncryption(): void {
    if (!this.dependencies.safeStorage.isEncryptionAvailable()) {
      throw fail('OS-backed paid media recovery intent encryption is unavailable')
    }
  }

  private encode(document: RecoveryIntentDocument): string {
    this.requireEncryption()
    const plaintext = JSON.stringify(document)
    if (Buffer.byteLength(plaintext, 'utf8') > MAX_PLAINTEXT_BYTES) {
      throw fail('Paid media recovery intent exceeds its size limit')
    }
    let encrypted: Buffer
    try {
      encrypted = this.dependencies.safeStorage.encryptString(plaintext)
    } catch (error) {
      throw fail('Paid media recovery intent encryption failed', error)
    }
    if (!Buffer.isBuffer(encrypted) || encrypted.length < 1) {
      throw fail('Paid media recovery intent encryption failed')
    }
    const envelope = JSON.stringify({
      schema: ENVELOPE_SCHEMA,
      protection: PROTECTION,
      ciphertext: encrypted.toString('base64')
    })
    if (Buffer.byteLength(envelope, 'utf8') > MAX_FILE_BYTES) {
      throw fail('Paid media recovery intent envelope exceeds its size limit')
    }
    return envelope
  }

  private decode(raw: string): RecoveryIntentDocument {
    this.requireEncryption()
    if (Buffer.byteLength(raw, 'utf8') > MAX_FILE_BYTES) {
      throw fail('Paid media recovery intent file exceeds its size limit')
    }
    const envelope = parseJsonObject(raw, 'Paid media recovery intent envelope')
    if (
      !exactKeys(envelope, ['schema', 'protection', 'ciphertext']) ||
      envelope.schema !== ENVELOPE_SCHEMA ||
      envelope.protection !== PROTECTION
    ) {
      throw fail('Paid media recovery intent envelope is invalid')
    }
    let plaintext: string
    try {
      plaintext = this.dependencies.safeStorage.decryptString(decodeBase64(envelope.ciphertext))
    } catch (error) {
      if (error instanceof PaidMediaRecoveryIntentError) throw error
      throw fail('Paid media recovery intent decryption failed', error)
    }
    if (Buffer.byteLength(plaintext, 'utf8') > MAX_PLAINTEXT_BYTES) {
      throw fail('Paid media recovery intent plaintext exceeds its size limit')
    }
    const value = parseJsonObject(plaintext, 'Paid media recovery intent')
    if (
      !exactKeys(value, [
        'schema',
        'handlerVersion',
        'kind',
        'operationId',
        'intentSha256',
        'payload'
      ]) ||
      value.schema !== DOCUMENT_SCHEMA ||
      value.handlerVersion !== PAID_MEDIA_RECOVERABLE_HANDLER_VERSION ||
      (value.kind !== 'asset_v2_dispatch' &&
        value.kind !== 'asset_v2_stage_reserve' &&
        value.kind !== 'asset_v2_stage_archive' &&
        value.kind !== 'asset_v2_stage_cleanup' &&
        value.kind !== 'asset_v2_result_ready_ack_intent' &&
        value.kind !== 'asset_v2_ack_completion' &&
        value.kind !== 'asset_v2_capacity_release')
    ) {
      throw fail('Paid media recovery intent document is invalid')
    }
    const payload = canonicalPayload(value.payload)
    const descriptor = descriptorFor(payload)
    if (
      value.kind !== payload.kind ||
      value.operationId !== payload.operationId ||
      value.intentSha256 !== descriptor.intentSha256
    ) {
      throw fail('Paid media recovery intent digest or binding does not match')
    }
    return Object.freeze({
      schema: DOCUMENT_SCHEMA,
      handlerVersion: PAID_MEDIA_RECOVERABLE_HANDLER_VERSION,
      kind: payload.kind,
      operationId: payload.operationId,
      intentSha256: descriptor.intentSha256,
      payload
    })
  }

  private file(descriptor: PaidMediaRecoveryIntentDescriptor): string {
    return join(this.root, `${descriptor.intentSha256}.prepared-intent.json`)
  }

  private readRegular(path: string): string {
    this.assertRoot()
    const before = lstatSync(path)
    if (
      !before.isFile() ||
      before.isSymbolicLink() ||
      before.size < 1 ||
      before.size > MAX_FILE_BYTES ||
      resolve(realpathSync(path)) !== resolve(path)
    ) {
      throw fail('Paid media recovery intent file is redirected or invalid')
    }
    this.dependencies.harden(path, false)
    const handle = openSync(path, 'r')
    try {
      const opened = fstatSync(handle)
      if (!opened.isFile() || !sameIdentity(before, opened) || opened.size !== before.size) {
        throw fail('Paid media recovery intent changed before reading')
      }
      const raw = readFileSync(handle, 'utf8')
      const after = lstatSync(path)
      if (!sameIdentity(opened, after) || after.size !== opened.size) {
        throw fail('Paid media recovery intent changed while reading')
      }
      return raw
    } finally {
      closeSync(handle)
    }
  }

  read(descriptorValue: unknown): PaidMediaRecoveryIntentPayload {
    const descriptor = canonicalDescriptor(descriptorValue)
    const document = this.decode(this.readRegular(this.file(descriptor)))
    if (
      document.kind !== descriptor.kind ||
      document.operationId !== descriptor.operationId ||
      document.intentSha256 !== descriptor.intentSha256
    ) {
      throw fail('Paid media recovery intent does not match its descriptor')
    }
    return document.payload
  }

  async prepare(payloadValue: unknown): Promise<PaidMediaRecoveryIntentDescriptor> {
    const payload = canonicalPayload(payloadValue)
    const descriptor = descriptorFor(payload)
    const document: RecoveryIntentDocument = Object.freeze({
      schema: DOCUMENT_SCHEMA,
      handlerVersion: PAID_MEDIA_RECOVERABLE_HANDLER_VERSION,
      kind: payload.kind,
      operationId: payload.operationId,
      intentSha256: descriptor.intentSha256,
      payload
    })
    const finalPath = this.file(descriptor)
    const temporary = join(
      this.root,
      `.${basename(finalPath)}.${process.pid}.${randomBytes(12).toString('hex')}.tmp`
    )
    const publishContext = Object.freeze({
      descriptor,
      temporaryPath: temporary,
      finalPath
    })
    this.assertRoot()
    const encoded = this.encode(document)
    this.assertRoot()
    let handle: number | null = null
    let published = false
    try {
      handle = openSync(temporary, 'wx', 0o600)
      writeFileSync(handle, encoded, 'utf8')
      fsyncSync(handle)
      closeSync(handle)
      handle = null
      this.dependencies.harden(temporary, false)
      await this.dependencies.onPublishPhase?.(
        'after_temp_fsync_before_publish',
        publishContext
      )
      try {
        linkSync(temporary, finalPath)
        published = true
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error
      }
      if (published) {
        await this.dependencies.onPublishPhase?.('after_publish_before_verify', publishContext)
      }
      const restored = this.read(descriptor)
      if (JSON.stringify(restored) !== JSON.stringify(payload)) {
        throw fail('Paid media recovery intent conflicts with its content address')
      }
      unlinkSync(temporary)
      return descriptor
    } catch (error) {
      if (error instanceof PaidMediaRecoveryIntentError) throw error
      throw fail(
        published
          ? 'Paid media recovery intent publish verification failed'
          : 'Paid media recovery intent atomic publish failed',
        error
      )
    } finally {
      if (handle !== null) closeSync(handle)
      if (existsSync(temporary) && existsSync(finalPath)) {
        try {
          unlinkSync(temporary)
        } catch {
          // A complete orphan temp has no authority; a later bounded
          // maintenance pass may remove it after validating the root.
        }
      }
    }
  }
}
