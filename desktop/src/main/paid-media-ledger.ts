import { createHash, randomBytes } from 'node:crypto'
import {
  closeSync,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync
} from 'node:fs'
import { basename, dirname, join, resolve } from 'node:path'

const ENVELOPE_SCHEMA = 'nachuan.paid-media-main-ledger.envelope.v1'
const DOCUMENT_SCHEMA = 'nachuan.paid-media-main-ledger.v4'
const STREAMING_DOCUMENT_SCHEMA = 'nachuan.paid-media-main-ledger.v3'
const PREVIOUS_DOCUMENT_SCHEMA = 'nachuan.paid-media-main-ledger.v2'
const LEGACY_DOCUMENT_SCHEMA = 'nachuan.paid-media-main-ledger.v1'
const ANCHOR_ENVELOPE_SCHEMA = 'nachuan.paid-media-main-ledger.anchor.envelope.v1'
const ANCHOR_DOCUMENT_SCHEMA = 'nachuan.paid-media-main-ledger.anchor.v1'
const PAIR_INTENT_ENVELOPE_SCHEMA = 'nachuan.paid-media-main-ledger.pair-intent.envelope.v1'
const PAIR_INTENT_DOCUMENT_SCHEMA = 'nachuan.paid-media-main-ledger.pair-intent.v1'
const PROTECTION = 'electron-safe-storage'
const MAX_RESULT_JSON_BYTES = 24 * 1024 * 1024
const MAX_RESULT_BASE64_CHARS = Math.ceil(MAX_RESULT_JSON_BYTES / 3) * 4
const MAX_FILE_BYTES = 66 * 1024 * 1024
const MAX_PLAINTEXT_BYTES = 48 * 1024 * 1024
const MAX_ANCHOR_FILE_BYTES = 64 * 1024
const MAX_ANCHOR_PLAINTEXT_BYTES = 8 * 1024
const MAX_PAIR_INTENT_PLAINTEXT_BYTES = MAX_FILE_BYTES + MAX_ANCHOR_FILE_BYTES + 256 * 1024
const MAX_PAIR_INTENT_FILE_BYTES = Math.ceil((MAX_PAIR_INTENT_PLAINTEXT_BYTES * 4) / 3) + 64 * 1024
const MAX_RECORDS = 2048
const MAX_DISPATCH_COUNT = 100
const MAX_RECONCILIATION_REASON_BYTES = 512
const MAX_RECONCILIATION_EVIDENCE_BYTES = 4096
const FUTURE_SKEW_MS = 5 * 60 * 1000
const TERMINAL_RETENTION_MS = 30 * 24 * 60 * 60 * 1000
const AUTOMATIC_RETRY_MAX_AGE_MS = 27 * 24 * 60 * 60 * 1000
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
const OPERATION_ID_PATTERN = /^desktop-op-([0-9a-f-]{36})$/i
const IDEMPOTENCY_KEY_PATTERN = /^desktop-([0-9a-f-]{36})$/i
const SHA256_PATTERN = /^[0-9a-f]{64}$/
const NONZERO_SHA256_PATTERN = /^(?!0{64}$)[0-9a-f]{64}$/
const AUTHORITY_EVIDENCE_DOMAIN = Buffer.from(
  'nachuan.desktop.paid-media-ledger-evidence.v1\0',
  'ascii'
)
const PAIR_INTENT_RECEIPT_DOMAIN = Buffer.from(
  'nachuan.desktop.paid-media-ledger-pair-intent.v1\0',
  'ascii'
)

export type PaidMediaPath = '/v1/images/generations' | '/v1/videos/generations'
export type PaidMediaLedgerState =
  | 'claimed'
  | 'dispatching'
  | 'recoverable'
  | 'result_ready'
  | 'delivered'
  | 'reconciled'

export interface PaidMediaSafeStorage {
  isEncryptionAvailable(): boolean
  encryptString(value: string): Buffer
  decryptString(value: Buffer): string
}

export type PaidMediaAclHardener = (path: string, directory: boolean) => void

export interface PaidMediaAtomicIO {
  readUtf8(path: string, maxBytes: number, harden: PaidMediaAclHardener): string | null
  writeUtf8Atomic(path: string, value: string, harden: PaidMediaAclHardener): void
}

export interface PaidMediaLedgerDependencies {
  safeStorage: PaidMediaSafeStorage
  harden: PaidMediaAclHardener
  now: () => number
  uuid: () => string
  atomicIO: PaidMediaAtomicIO
}

export interface PaidMediaLedgerAuthorityEvidence {
  ledgerIdentity: string
  ledgerSequence: number
  ledgerStateDigest: string
}

export interface PaidMediaPublicOperation {
  operationId: string
  path: PaidMediaPath
  state: PaidMediaLedgerState
  createdAt: number
  updatedAt: number
  dispatchCount: number
  v2DispatchReceiptSha256?: string
  v2AckIntentReceiptSha256?: string
  lastStatus?: number
  retryAfterSeconds?: number
  deliveredAt?: number
  reconciliation?: {
    at: number
    reason: string
    evidence: string
  }
}

export interface PaidMediaDispatchSecret {
  idempotencyKey: string
  requestSha256: string
}

export interface PaidMediaClaimResult {
  operation: PaidMediaPublicOperation
  dispatch: PaidMediaDispatchSecret
  reused: boolean
  replay?: {
    status: number
    responseJson: string
  }
}

export interface PaidMediaClaimInput {
  path: PaidMediaPath
  requestSha256: string
  recoveryDomainSha256: string
  retryOperationId?: string
}

export interface PaidMediaV2DispatchInput {
  operationId: string
  path: PaidMediaPath
  requestSha256: string
  recoveryDomainSha256: string
  dispatchReceiptSha256: string
}

export interface PaidMediaV2ResultReadyInput {
  operationId: string
  dispatchReceiptSha256: string
  ackIntentReceiptSha256: string
  status: number
  responseJson: string
}

export interface PaidMediaLegacyUnresolvedInput {
  operationId: string
  path: PaidMediaPath
  requestSha256: string
  createdAt: number
  updatedAt: number
  state: 'pending' | 'recoverable'
  lastStatus?: number
  retryAfterSeconds?: number
}

interface ReconciliationRecord {
  at: number
  reason: string
  evidence: string
}

interface PaidMediaOperationRecord {
  operationId: string
  idempotencyKey: string
  path: PaidMediaPath
  requestSha256: string
  recoveryDomainSha256: string | null
  state: PaidMediaLedgerState
  createdAt: number
  updatedAt: number
  dispatchCount: number
  v2DispatchReceiptSha256: string | null
  v2AckIntentReceiptSha256: string | null
  lastStatus: number | null
  retryAfterSeconds: number | null
  resultSha256: string | null
  resultStatus: number | null
  resultJsonBase64: string | null
  deliveredAt: number | null
  reconciliation: ReconciliationRecord | null
}

interface PaidMediaLedgerDocument {
  schema: typeof DOCUMENT_SCHEMA
  ledgerIdentity: string
  sequence: number
  records: PaidMediaOperationRecord[]
}

interface PaidMediaAnchorDocument {
  schema: typeof ANCHOR_DOCUMENT_SCHEMA
  ledgerIdentity: string
  sequenceFloor: number
}

interface PaidMediaPairIntentDocument {
  schema: typeof PAIR_INTENT_DOCUMENT_SCHEMA
  ledgerIdentity: string
  beforeSequence: number
  targetSequence: number
  beforeAnchorSha256: string | null
  beforeLedgerSha256: string | null
  targetAnchorSha256: string
  targetLedgerSha256: string
  targetAnchorEnvelope: string
  targetLedgerEnvelope: string
  receiptSha256: string
}

export class PaidMediaLedgerError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options)
    this.name = 'PaidMediaLedgerError'
  }
}

export class PaidMediaUnresolvedOperationError extends PaidMediaLedgerError {
  constructor() {
    super('A paid media operation is still unresolved')
    this.name = 'PaidMediaUnresolvedOperationError'
  }
}

export class PaidMediaLegacyLedgerMigrationRequiredError extends PaidMediaLedgerError {
  constructor() {
    super('Legacy paid media ledger requires an explicit sealed migration')
    this.name = 'PaidMediaLegacyLedgerMigrationRequiredError'
  }
}

function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort()
  const wanted = [...expected].sort()
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index])
}

function safeInteger(value: unknown, minimum = 0): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= minimum
}

function boundedText(value: unknown, maxBytes: number): value is string {
  return (
    typeof value === 'string' &&
    value.trim().length > 0 &&
    Buffer.byteLength(value, 'utf8') <= maxBytes &&
    !/[\u0000-\u001f\u007f]/.test(value)
  )
}

function validPath(value: unknown): value is PaidMediaPath {
  return value === '/v1/images/generations' || value === '/v1/videos/generations'
}

function validState(value: unknown): value is PaidMediaLedgerState {
  return (
    value === 'claimed' ||
    value === 'dispatching' ||
    value === 'recoverable' ||
    value === 'result_ready' ||
    value === 'delivered' ||
    value === 'reconciled'
  )
}

function isUnresolvedState(state: PaidMediaLedgerState): boolean {
  return (
    state === 'claimed' ||
    state === 'dispatching' ||
    state === 'recoverable' ||
    state === 'result_ready'
  )
}

function terminalAt(record: PaidMediaOperationRecord): number | null {
  if (record.state === 'delivered') return record.deliveredAt
  if (record.state === 'reconciled') return record.reconciliation?.at ?? null
  return null
}

function requireNow(now: () => number): number {
  const value = now()
  if (!safeInteger(value)) throw new PaidMediaLedgerError('Paid media ledger clock is invalid')
  return value
}

function nextSequence(sequence: number): number {
  const next = sequence + 1
  if (!safeInteger(next)) throw new PaidMediaLedgerError('Paid media ledger sequence is exhausted')
  return next
}

function sha256Utf8(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex')
}

function pairIntentReceipt(value: {
  ledgerIdentity: string
  beforeSequence: number
  targetSequence: number
  beforeAnchorSha256: string | null
  beforeLedgerSha256: string | null
  targetAnchorSha256: string
  targetLedgerSha256: string
}): string {
  return createHash('sha256')
    .update(PAIR_INTENT_RECEIPT_DOMAIN)
    .update(JSON.stringify(value), 'utf8')
    .digest('hex')
}

function requireEncryption(storage: PaidMediaSafeStorage): void {
  if (!storage.isEncryptionAvailable()) {
    throw new PaidMediaLedgerError('OS-backed paid media ledger encryption is unavailable')
  }
}

function parseJsonObject(raw: string, message: string): Record<string, unknown> {
  try {
    const value: unknown = JSON.parse(raw)
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('not object')
    return value as Record<string, unknown>
  } catch (error) {
    throw new PaidMediaLedgerError(message, { cause: error })
  }
}

function decodeCiphertext(value: unknown): Buffer {
  if (
    typeof value !== 'string' ||
    !value ||
    value.length > MAX_FILE_BYTES * 2 ||
    value.length % 4 !== 0 ||
    !/^[A-Za-z0-9+/]+={0,2}$/.test(value)
  ) {
    throw new PaidMediaLedgerError('Encrypted paid media ledger envelope is invalid')
  }
  const decoded = Buffer.from(value, 'base64')
  if (decoded.toString('base64') !== value) {
    throw new PaidMediaLedgerError('Encrypted paid media ledger envelope is invalid')
  }
  return decoded
}

function requireStrictJsonResponse(responseJson: unknown): string {
  if (
    typeof responseJson !== 'string' ||
    Buffer.byteLength(responseJson, 'utf8') > MAX_RESULT_JSON_BYTES
  ) {
    throw new PaidMediaLedgerError('Paid media result JSON exceeds the 24 MiB durable limit')
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(responseJson)
  } catch (error) {
    throw new PaidMediaLedgerError('Paid media result JSON is corrupt', { cause: error })
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new PaidMediaLedgerError('Paid media result JSON must be an object')
  }
  return responseJson
}

function resultDigest(responseJson: string): string {
  return createHash('sha256').update(responseJson, 'utf8').digest('hex')
}

function encodeResultJson(responseJson: unknown): {
  resultJsonBase64: string
  resultSha256: string
} {
  const validated = requireStrictJsonResponse(responseJson)
  return {
    resultJsonBase64: Buffer.from(validated, 'utf8').toString('base64'),
    resultSha256: resultDigest(validated)
  }
}

function decodeResultJson(value: unknown, expectedDigest: string): string {
  if (
    typeof value !== 'string' ||
    value.length < 4 ||
    value.length > MAX_RESULT_BASE64_CHARS ||
    value.length % 4 !== 0 ||
    !/^[A-Za-z0-9+/]+={0,2}$/.test(value)
  ) {
    throw new PaidMediaLedgerError('Paid media stored response is corrupt')
  }
  const decoded = Buffer.from(value, 'base64')
  if (
    decoded.byteLength > MAX_RESULT_JSON_BYTES ||
    decoded.toString('base64') !== value
  ) {
    throw new PaidMediaLedgerError('Paid media stored response is corrupt')
  }
  const responseJson = decoded.toString('utf8')
  if (!Buffer.from(responseJson, 'utf8').equals(decoded)) {
    throw new PaidMediaLedgerError('Paid media stored response is not valid UTF-8')
  }
  requireStrictJsonResponse(responseJson)
  if (resultDigest(responseJson) !== expectedDigest) {
    throw new PaidMediaLedgerError('Paid media stored response digest does not match')
  }
  return responseJson
}

type PaidMediaDocumentVersion = 'v1' | 'v2' | 'v3' | 'v4'

function parseRecord(
  value: unknown,
  now: number,
  version: PaidMediaDocumentVersion
): PaidMediaOperationRecord {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new PaidMediaLedgerError('Paid media ledger record is invalid')
  }
  const record = value as Record<string, unknown>
  const hasStreamingResult = version === 'v3' || version === 'v4'
  if (
    !hasExactKeys(record, [
      'operationId',
      'idempotencyKey',
      'path',
      'requestSha256',
      ...(version === 'v1' ? [] : ['recoveryDomainSha256']),
      'state',
      'createdAt',
      'updatedAt',
      'dispatchCount',
      ...(version === 'v4'
        ? ['v2DispatchReceiptSha256', 'v2AckIntentReceiptSha256']
        : []),
      'lastStatus',
      'retryAfterSeconds',
      'resultSha256',
      ...(hasStreamingResult ? ['resultStatus', 'resultJsonBase64'] : []),
      'deliveredAt',
      'reconciliation'
    ])
  ) {
    throw new PaidMediaLedgerError('Paid media ledger record has unknown fields')
  }
  const operationMatch =
    typeof record.operationId === 'string' ? OPERATION_ID_PATTERN.exec(record.operationId) : null
  const keyMatch =
    typeof record.idempotencyKey === 'string'
      ? IDEMPOTENCY_KEY_PATTERN.exec(record.idempotencyKey)
      : null
  if (
    !operationMatch ||
    !keyMatch ||
    !UUID_PATTERN.test(operationMatch[1]) ||
    !UUID_PATTERN.test(keyMatch[1]) ||
    operationMatch[1].toLowerCase() !== keyMatch[1].toLowerCase()
  ) {
    throw new PaidMediaLedgerError('Paid media ledger operation identity is invalid')
  }
  if (!validPath(record.path)) throw new PaidMediaLedgerError('Paid media ledger path is invalid')
  if (typeof record.requestSha256 !== 'string' || !SHA256_PATTERN.test(record.requestSha256)) {
    throw new PaidMediaLedgerError('Paid media ledger request digest is invalid')
  }
  if (
    version !== 'v1' &&
    record.recoveryDomainSha256 !== null &&
    (typeof record.recoveryDomainSha256 !== 'string' ||
      !SHA256_PATTERN.test(record.recoveryDomainSha256))
  ) {
    throw new PaidMediaLedgerError('Paid media ledger recovery domain digest is invalid')
  }
  const recoveryDomainSha256 =
    version === 'v1' ? null : (record.recoveryDomainSha256 as string | null)
  const v2DispatchReceiptSha256 =
    version === 'v4' ? record.v2DispatchReceiptSha256 : null
  const v2AckIntentReceiptSha256 =
    version === 'v4' ? record.v2AckIntentReceiptSha256 : null
  const resultStatus = hasStreamingResult ? record.resultStatus : null
  const resultJsonBase64 = hasStreamingResult ? record.resultJsonBase64 : null
  if (!validState(record.state)) throw new PaidMediaLedgerError('Paid media ledger state is invalid')
  if (
    !safeInteger(record.createdAt) ||
    !safeInteger(record.updatedAt) ||
    record.updatedAt < record.createdAt ||
    record.updatedAt > now + FUTURE_SKEW_MS ||
    !safeInteger(record.dispatchCount) ||
    record.dispatchCount > MAX_DISPATCH_COUNT ||
    (v2DispatchReceiptSha256 !== null &&
      (typeof v2DispatchReceiptSha256 !== 'string' ||
        !NONZERO_SHA256_PATTERN.test(v2DispatchReceiptSha256))) ||
    (v2AckIntentReceiptSha256 !== null &&
      (typeof v2AckIntentReceiptSha256 !== 'string' ||
        !NONZERO_SHA256_PATTERN.test(v2AckIntentReceiptSha256))) ||
    (record.lastStatus !== null &&
      (!safeInteger(record.lastStatus) || record.lastStatus > 599)) ||
    (record.retryAfterSeconds !== null &&
      (!safeInteger(record.retryAfterSeconds, 1) || record.retryAfterSeconds > 900)) ||
    (record.resultSha256 !== null &&
      (typeof record.resultSha256 !== 'string' || !SHA256_PATTERN.test(record.resultSha256))) ||
    (resultStatus !== null &&
      (!safeInteger(resultStatus, 200) || Number(resultStatus) > 299)) ||
    (resultJsonBase64 !== null && typeof resultJsonBase64 !== 'string') ||
    (record.deliveredAt !== null &&
      (!safeInteger(record.deliveredAt) ||
        record.deliveredAt < record.createdAt ||
        record.deliveredAt > record.updatedAt))
  ) {
    throw new PaidMediaLedgerError('Paid media ledger record fields are invalid')
  }
  if (resultJsonBase64 !== null) {
    if (record.resultSha256 === null || resultStatus === null) {
      throw new PaidMediaLedgerError('Paid media stored response fields are incomplete')
    }
    decodeResultJson(resultJsonBase64, record.resultSha256 as string)
  }
  if (record.reconciliation !== null) {
    if (
      !record.reconciliation ||
      typeof record.reconciliation !== 'object' ||
      Array.isArray(record.reconciliation) ||
      !hasExactKeys(record.reconciliation as unknown as Record<string, unknown>, [
        'at',
        'reason',
        'evidence'
      ])
    ) {
      throw new PaidMediaLedgerError('Paid media ledger reconciliation is invalid')
    }
    const reconciliation = record.reconciliation as unknown as Record<string, unknown>
    if (
      !safeInteger(reconciliation.at) ||
      reconciliation.at < Number(record.createdAt) ||
      reconciliation.at > Number(record.updatedAt) ||
      !boundedText(reconciliation.reason, MAX_RECONCILIATION_REASON_BYTES) ||
      !boundedText(reconciliation.evidence, MAX_RECONCILIATION_EVIDENCE_BYTES)
    ) {
      throw new PaidMediaLedgerError('Paid media ledger reconciliation is invalid')
    }
  }
  const noTerminalData = record.deliveredAt === null && record.reconciliation === null
  const hasReplayableResult = resultStatus !== null && resultJsonBase64 !== null
  const hasManualOnlyMigratedResult =
    hasStreamingResult &&
    recoveryDomainSha256 === null &&
    resultStatus === null &&
    resultJsonBase64 === null
  const legacyResultWithoutBody = !hasStreamingResult
  if (
    (v2DispatchReceiptSha256 !== null &&
      (recoveryDomainSha256 === null ||
        record.state === 'claimed' ||
        record.dispatchCount !== 1)) ||
    (v2AckIntentReceiptSha256 !== null &&
      (v2DispatchReceiptSha256 === null ||
        record.dispatchCount !== 1 ||
        (record.state !== 'result_ready' &&
          record.state !== 'delivered' &&
          record.state !== 'reconciled') ||
        record.resultSha256 === null)) ||
    (record.state === 'claimed' &&
      (record.dispatchCount !== 0 ||
        record.lastStatus !== null ||
        record.retryAfterSeconds !== null ||
        record.resultSha256 !== null ||
        resultStatus !== null ||
        resultJsonBase64 !== null ||
        !noTerminalData)) ||
    (record.state === 'dispatching' &&
      (record.dispatchCount < 1 ||
        record.lastStatus !== null ||
        record.retryAfterSeconds !== null ||
        record.resultSha256 !== null ||
        resultStatus !== null ||
        resultJsonBase64 !== null ||
        !noTerminalData)) ||
    (record.state === 'recoverable' &&
      (record.dispatchCount < 1 ||
        record.lastStatus === null ||
        record.resultSha256 !== null ||
        resultStatus !== null ||
        resultJsonBase64 !== null ||
        !noTerminalData)) ||
    (record.state === 'result_ready' &&
      (record.dispatchCount < 1 ||
        record.lastStatus !== null ||
        record.retryAfterSeconds !== null ||
        record.resultSha256 === null ||
        (!hasReplayableResult &&
          !hasManualOnlyMigratedResult &&
          !legacyResultWithoutBody) ||
        !noTerminalData)) ||
    (record.state === 'delivered' &&
      (record.dispatchCount < 1 ||
        record.lastStatus !== null ||
        record.retryAfterSeconds !== null ||
        record.resultSha256 === null ||
        resultJsonBase64 !== null ||
        record.deliveredAt === null ||
        record.reconciliation !== null)) ||
    (record.state === 'reconciled' &&
      (record.deliveredAt !== null ||
        record.reconciliation === null ||
        resultJsonBase64 !== null ||
        (resultStatus !== null && record.resultSha256 === null) ||
        (record.resultSha256 !== null && record.dispatchCount < 1) ||
        (record.lastStatus !== null && record.dispatchCount < 1) ||
        (record.retryAfterSeconds !== null && record.lastStatus === null)))
  ) {
    throw new PaidMediaLedgerError('Paid media ledger state fields are inconsistent')
  }
  return {
    ...(record as unknown as Omit<
      PaidMediaOperationRecord,
      | 'recoveryDomainSha256'
      | 'v2DispatchReceiptSha256'
      | 'v2AckIntentReceiptSha256'
      | 'resultStatus'
      | 'resultJsonBase64'
    >),
    recoveryDomainSha256,
    v2DispatchReceiptSha256: v2DispatchReceiptSha256 as string | null,
    v2AckIntentReceiptSha256: v2AckIntentReceiptSha256 as string | null,
    resultStatus: resultStatus as number | null,
    resultJsonBase64: resultJsonBase64 as string | null
  }
}

function publicOperation(record: PaidMediaOperationRecord): PaidMediaPublicOperation {
  return {
    operationId: record.operationId,
    path: record.path,
    state: record.state,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    dispatchCount: record.dispatchCount,
    ...(record.v2DispatchReceiptSha256 === null
      ? {}
      : { v2DispatchReceiptSha256: record.v2DispatchReceiptSha256 }),
    ...(record.v2AckIntentReceiptSha256 === null
      ? {}
      : { v2AckIntentReceiptSha256: record.v2AckIntentReceiptSha256 }),
    ...(record.lastStatus === null ? {} : { lastStatus: record.lastStatus }),
    ...(record.retryAfterSeconds === null
      ? {}
      : { retryAfterSeconds: record.retryAfterSeconds }),
    ...(record.deliveredAt === null ? {} : { deliveredAt: record.deliveredAt }),
    ...(record.reconciliation === null ? {} : { reconciliation: { ...record.reconciliation } })
  }
}

export const nodePaidMediaAtomicIO: PaidMediaAtomicIO = {
  readUtf8(path, maxBytes, harden) {
    if (!existsSync(path)) return null
    const parent = dirname(path)
    const parentInfo = lstatSync(parent)
    if (!parentInfo.isDirectory() || parentInfo.isSymbolicLink()) {
      throw new PaidMediaLedgerError('Paid media ledger directory is redirected')
    }
    const info = lstatSync(path)
    if (!info.isFile() || info.isSymbolicLink()) {
      throw new PaidMediaLedgerError('Paid media ledger file is redirected')
    }
    if (info.size > maxBytes) throw new PaidMediaLedgerError('Paid media ledger exceeds size limit')
    harden(parent, true)
    harden(path, false)
    return readFileSync(path, 'utf8')
  },
  writeUtf8Atomic(path, value, harden) {
    const parent = dirname(path)
    mkdirSync(parent, { recursive: true })
    const parentInfo = lstatSync(parent)
    if (!parentInfo.isDirectory() || parentInfo.isSymbolicLink()) {
      throw new PaidMediaLedgerError('Paid media ledger directory is redirected')
    }
    if (existsSync(path)) {
      const current = lstatSync(path)
      if (!current.isFile() || current.isSymbolicLink()) {
        throw new PaidMediaLedgerError('Paid media ledger file is redirected')
      }
    }
    harden(parent, true)
    const temp = join(
      parent,
      `.${basename(path)}.${process.pid}.${randomBytes(8).toString('hex')}.tmp`
    )
    let handle: number | null = null
    try {
      handle = openSync(temp, 'wx', 0o600)
      writeFileSync(handle, value, 'utf8')
      fsyncSync(handle)
      closeSync(handle)
      handle = null
      harden(temp, false)
      renameSync(temp, path)
      harden(path, false)
    } catch (error) {
      throw error instanceof PaidMediaLedgerError
        ? error
        : new PaidMediaLedgerError('Atomic paid media ledger write failed', { cause: error })
    } finally {
      if (handle !== null) closeSync(handle)
      if (existsSync(temp)) unlinkSync(temp)
    }
  }
}

class PathMutex {
  private locked = false
  private readonly waiters: Array<() => void> = []

  async run<T>(action: () => T | Promise<T>): Promise<T> {
    if (this.locked) await new Promise<void>((resolveWaiter) => this.waiters.push(resolveWaiter))
    else this.locked = true
    try {
      return await action()
    } finally {
      const next = this.waiters.shift()
      if (next) next()
      else this.locked = false
    }
  }

  get idle(): boolean {
    return !this.locked && this.waiters.length === 0
  }
}

const pathMutexes = new Map<string, PathMutex>()

async function serializedForPath<T>(path: string, action: () => T | Promise<T>): Promise<T> {
  const key = process.platform === 'win32' ? resolve(path).toLowerCase() : resolve(path)
  const mutex = pathMutexes.get(key) ?? new PathMutex()
  pathMutexes.set(key, mutex)
  try {
    return await mutex.run(action)
  } finally {
    if (mutex.idle && pathMutexes.get(key) === mutex) pathMutexes.delete(key)
  }
}

export class PaidMediaLedger {
  private mutationGuard: (() => void) | null = null

  constructor(
    private readonly path: string,
    private readonly dependencies: PaidMediaLedgerDependencies
  ) {
    if (!path || !resolve(path)) throw new PaidMediaLedgerError('Paid media ledger path is invalid')
  }

  private get anchorPath(): string {
    return `${this.path}.anchor`
  }

  private get pairIntentPath(): string {
    return `${this.path}.pair-intent`
  }

  setMutationGuard(guard: () => void): void {
    if (typeof guard !== 'function') {
      throw new PaidMediaLedgerError('Paid media mutation guard is invalid')
    }
    if (this.mutationGuard !== null && this.mutationGuard !== guard) {
      throw new PaidMediaLedgerError('Paid media mutation guard is already attached')
    }
    this.mutationGuard = guard
  }

  private assertMutationAllowed(): void {
    this.mutationGuard?.()
  }

  private decodeEnvelope(
    raw: string,
    envelopeSchema: string,
    maxPlaintextBytes: number,
    label: string
  ): string {
    const envelope = parseJsonObject(raw, `${label} envelope is corrupt`)
    if (
      !hasExactKeys(envelope, ['schema', 'protection', 'ciphertext']) ||
      envelope.schema !== envelopeSchema ||
      envelope.protection !== PROTECTION
    ) {
      throw new PaidMediaLedgerError(`${label} envelope is invalid`)
    }
    let plaintext: string
    try {
      plaintext = this.dependencies.safeStorage.decryptString(decodeCiphertext(envelope.ciphertext))
    } catch (error) {
      if (error instanceof PaidMediaLedgerError) throw error
      throw new PaidMediaLedgerError(`OS-backed ${label.toLowerCase()} decryption failed`, {
        cause: error
      })
    }
    if (Buffer.byteLength(plaintext, 'utf8') > maxPlaintextBytes) {
      throw new PaidMediaLedgerError(`Decrypted ${label.toLowerCase()} exceeds size limit`)
    }
    return plaintext
  }

  private encodeEnvelope(
    value: unknown,
    envelopeSchema: string,
    maxPlaintextBytes: number,
    maxEnvelopeBytes: number,
    label: string
  ): string {
    const plaintext = JSON.stringify(value)
    if (Buffer.byteLength(plaintext, 'utf8') > maxPlaintextBytes) {
      throw new PaidMediaLedgerError(`${label} exceeds size limit`)
    }
    let ciphertext: Buffer
    try {
      ciphertext = this.dependencies.safeStorage.encryptString(plaintext)
    } catch (error) {
      throw new PaidMediaLedgerError(`OS-backed ${label.toLowerCase()} encryption failed`, {
        cause: error
      })
    }
    const envelope = JSON.stringify({
      schema: envelopeSchema,
      protection: PROTECTION,
      ciphertext: ciphertext.toString('base64')
    })
    if (Buffer.byteLength(envelope, 'utf8') > maxEnvelopeBytes) {
      throw new PaidMediaLedgerError(`Encrypted ${label.toLowerCase()} exceeds size limit`)
    }
    return envelope
  }

  private decodeAnchorEnvelope(raw: string): PaidMediaAnchorDocument {
    if (Buffer.byteLength(raw, 'utf8') > MAX_ANCHOR_FILE_BYTES) {
      throw new PaidMediaLedgerError('Paid media ledger anchor exceeds size limit')
    }
    const plaintext = this.decodeEnvelope(
      raw,
      ANCHOR_ENVELOPE_SCHEMA,
      MAX_ANCHOR_PLAINTEXT_BYTES,
      'Paid media ledger anchor'
    )
    const value = parseJsonObject(plaintext, 'Decrypted paid media ledger anchor is corrupt')
    if (
      !hasExactKeys(value, ['schema', 'ledgerIdentity', 'sequenceFloor']) ||
      value.schema !== ANCHOR_DOCUMENT_SCHEMA ||
      typeof value.ledgerIdentity !== 'string' ||
      !SHA256_PATTERN.test(value.ledgerIdentity) ||
      !safeInteger(value.sequenceFloor, 1)
    ) {
      throw new PaidMediaLedgerError('Decrypted paid media ledger anchor schema is invalid')
    }
    return {
      schema: ANCHOR_DOCUMENT_SCHEMA,
      ledgerIdentity: value.ledgerIdentity,
      sequenceFloor: value.sequenceFloor
    }
  }

  private readAnchor(): PaidMediaAnchorDocument | null {
    const raw = this.dependencies.atomicIO.readUtf8(
      this.anchorPath,
      MAX_ANCHOR_FILE_BYTES,
      this.dependencies.harden
    )
    return raw === null ? null : this.decodeAnchorEnvelope(raw)
  }

  private decodeLedgerEnvelope(
    raw: string,
    now: number
  ): {
    version: PaidMediaDocumentVersion
    ledgerIdentity: string | null
    sequence: number
    records: PaidMediaOperationRecord[]
  } {
    if (Buffer.byteLength(raw, 'utf8') > MAX_FILE_BYTES) {
      throw new PaidMediaLedgerError('Paid media ledger exceeds size limit')
    }
    const plaintext = this.decodeEnvelope(
      raw,
      ENVELOPE_SCHEMA,
      MAX_PLAINTEXT_BYTES,
      'Paid media ledger'
    )
    const value = parseJsonObject(plaintext, 'Decrypted paid media ledger is corrupt')
    const version: PaidMediaDocumentVersion | null =
      value.schema === LEGACY_DOCUMENT_SCHEMA
        ? 'v1'
        : value.schema === PREVIOUS_DOCUMENT_SCHEMA
          ? 'v2'
          : value.schema === STREAMING_DOCUMENT_SCHEMA
            ? 'v3'
            : value.schema === DOCUMENT_SCHEMA
              ? 'v4'
              : null
    const hasLedgerIdentity = version !== 'v1' && version !== null
    if (
      version === null ||
      !hasExactKeys(
        value,
        hasLedgerIdentity
          ? ['schema', 'ledgerIdentity', 'sequence', 'records']
          : ['schema', 'sequence', 'records']
      ) ||
      (hasLedgerIdentity &&
        (typeof value.ledgerIdentity !== 'string' || !SHA256_PATTERN.test(value.ledgerIdentity))) ||
      !safeInteger(value.sequence) ||
      !Array.isArray(value.records) ||
      value.records.length > MAX_RECORDS
    ) {
      throw new PaidMediaLedgerError('Decrypted paid media ledger schema is invalid')
    }
    const records = value.records.map((record) =>
      parseRecord(record, now, version as PaidMediaDocumentVersion)
    )
    if (
      new Set(records.map((record) => record.operationId)).size !== records.length ||
      new Set(records.map((record) => record.idempotencyKey)).size !== records.length
    ) {
      throw new PaidMediaLedgerError('Paid media ledger contains duplicate identities')
    }
    if (records.filter((record) => isUnresolvedState(record.state)).length > 1) {
      throw new PaidMediaLedgerError('Paid media ledger contains multiple unresolved operations')
    }
    if (records.filter((record) => record.resultJsonBase64 !== null).length > 1) {
      throw new PaidMediaLedgerError('Paid media ledger contains multiple durable response payloads')
    }
    return {
      version: version as PaidMediaDocumentVersion,
      ledgerIdentity: hasLedgerIdentity ? (value.ledgerIdentity as string) : null,
      sequence: value.sequence as number,
      records
    }
  }

  private readPairIntent(): PaidMediaPairIntentDocument | null {
    const raw = this.dependencies.atomicIO.readUtf8(
      this.pairIntentPath,
      MAX_PAIR_INTENT_FILE_BYTES,
      this.dependencies.harden
    )
    if (raw === null) return null
    if (Buffer.byteLength(raw, 'utf8') > MAX_PAIR_INTENT_FILE_BYTES) {
      throw new PaidMediaLedgerError('Paid media ledger pair intent exceeds size limit')
    }
    const plaintext = this.decodeEnvelope(
      raw,
      PAIR_INTENT_ENVELOPE_SCHEMA,
      MAX_PAIR_INTENT_PLAINTEXT_BYTES,
      'Paid media ledger pair intent'
    )
    const value = parseJsonObject(plaintext, 'Decrypted paid media ledger pair intent is corrupt')
    if (
      !hasExactKeys(value, [
        'schema',
        'ledgerIdentity',
        'beforeSequence',
        'targetSequence',
        'beforeAnchorSha256',
        'beforeLedgerSha256',
        'targetAnchorSha256',
        'targetLedgerSha256',
        'targetAnchorEnvelope',
        'targetLedgerEnvelope',
        'receiptSha256'
      ]) ||
      value.schema !== PAIR_INTENT_DOCUMENT_SCHEMA ||
      typeof value.ledgerIdentity !== 'string' ||
      !SHA256_PATTERN.test(value.ledgerIdentity) ||
      !safeInteger(value.beforeSequence) ||
      !safeInteger(value.targetSequence, 1) ||
      value.targetSequence !== value.beforeSequence + 1 ||
      (value.beforeSequence === 0
        ? value.beforeAnchorSha256 !== null || value.beforeLedgerSha256 !== null
        : typeof value.beforeAnchorSha256 !== 'string' ||
          !SHA256_PATTERN.test(value.beforeAnchorSha256) ||
          typeof value.beforeLedgerSha256 !== 'string' ||
          !SHA256_PATTERN.test(value.beforeLedgerSha256)) ||
      typeof value.targetAnchorSha256 !== 'string' ||
      !SHA256_PATTERN.test(value.targetAnchorSha256) ||
      typeof value.targetLedgerSha256 !== 'string' ||
      !SHA256_PATTERN.test(value.targetLedgerSha256) ||
      typeof value.targetAnchorEnvelope !== 'string' ||
      Buffer.byteLength(value.targetAnchorEnvelope, 'utf8') > MAX_ANCHOR_FILE_BYTES ||
      typeof value.targetLedgerEnvelope !== 'string' ||
      Buffer.byteLength(value.targetLedgerEnvelope, 'utf8') > MAX_FILE_BYTES ||
      typeof value.receiptSha256 !== 'string' ||
      !SHA256_PATTERN.test(value.receiptSha256)
    ) {
      throw new PaidMediaLedgerError('Decrypted paid media ledger pair intent schema is invalid')
    }
    const intent = value as unknown as PaidMediaPairIntentDocument
    if (
      sha256Utf8(intent.targetAnchorEnvelope) !== intent.targetAnchorSha256 ||
      sha256Utf8(intent.targetLedgerEnvelope) !== intent.targetLedgerSha256 ||
      (intent.beforeAnchorSha256 !== null &&
        intent.beforeAnchorSha256 === intent.targetAnchorSha256) ||
      (intent.beforeLedgerSha256 !== null &&
        intent.beforeLedgerSha256 === intent.targetLedgerSha256) ||
      pairIntentReceipt({
        ledgerIdentity: intent.ledgerIdentity,
        beforeSequence: intent.beforeSequence,
        targetSequence: intent.targetSequence,
        beforeAnchorSha256: intent.beforeAnchorSha256,
        beforeLedgerSha256: intent.beforeLedgerSha256,
        targetAnchorSha256: intent.targetAnchorSha256,
        targetLedgerSha256: intent.targetLedgerSha256
      }) !== intent.receiptSha256
    ) {
      throw new PaidMediaLedgerError('Paid media ledger pair intent receipt does not match')
    }
    const targetAnchor = this.decodeAnchorEnvelope(intent.targetAnchorEnvelope)
    const targetLedger = this.decodeLedgerEnvelope(
      intent.targetLedgerEnvelope,
      requireNow(this.dependencies.now)
    )
    if (
      targetLedger.version !== 'v4' ||
      targetLedger.ledgerIdentity !== intent.ledgerIdentity ||
      targetLedger.sequence !== intent.targetSequence ||
      targetAnchor.ledgerIdentity !== intent.ledgerIdentity ||
      targetAnchor.sequenceFloor !== intent.targetSequence
    ) {
      throw new PaidMediaLedgerError('Paid media ledger pair intent target is inconsistent')
    }
    return intent
  }

  private recoverPairPublication(): boolean {
    const intent = this.readPairIntent()
    if (intent === null) return false
    const currentAnchor = this.dependencies.atomicIO.readUtf8(
      this.anchorPath,
      MAX_ANCHOR_FILE_BYTES,
      this.dependencies.harden
    )
    const currentLedger = this.dependencies.atomicIO.readUtf8(
      this.path,
      MAX_FILE_BYTES,
      this.dependencies.harden
    )
    const anchorIsBefore =
      intent.beforeAnchorSha256 === null
        ? currentAnchor === null
        : currentAnchor !== null && sha256Utf8(currentAnchor) === intent.beforeAnchorSha256
    const ledgerIsBefore =
      intent.beforeLedgerSha256 === null
        ? currentLedger === null
        : currentLedger !== null && sha256Utf8(currentLedger) === intent.beforeLedgerSha256
    const anchorIsTarget =
      currentAnchor !== null && sha256Utf8(currentAnchor) === intent.targetAnchorSha256
    const ledgerIsTarget =
      currentLedger !== null && sha256Utf8(currentLedger) === intent.targetLedgerSha256

    if ((!anchorIsBefore && !anchorIsTarget) || (!ledgerIsBefore && !ledgerIsTarget)) {
      throw new PaidMediaLedgerError(
        'Paid media ledger pair differs from both the expected-before and exact target receipts'
      )
    }
    if (anchorIsBefore && ledgerIsTarget) {
      throw new PaidMediaLedgerError('Paid media ledger pair publication crossed its ordered steps')
    }
    if (anchorIsBefore && ledgerIsBefore) {
      this.dependencies.atomicIO.writeUtf8Atomic(
        this.anchorPath,
        intent.targetAnchorEnvelope,
        this.dependencies.harden
      )
    }
    if (ledgerIsBefore) {
      this.dependencies.atomicIO.writeUtf8Atomic(
        this.path,
        intent.targetLedgerEnvelope,
        this.dependencies.harden
      )
    }
    const finalAnchor = this.dependencies.atomicIO.readUtf8(
      this.anchorPath,
      MAX_ANCHOR_FILE_BYTES,
      this.dependencies.harden
    )
    const finalLedger = this.dependencies.atomicIO.readUtf8(
      this.path,
      MAX_FILE_BYTES,
      this.dependencies.harden
    )
    if (
      finalAnchor === null ||
      finalLedger === null ||
      sha256Utf8(finalAnchor) !== intent.targetAnchorSha256 ||
      sha256Utf8(finalLedger) !== intent.targetLedgerSha256
    ) {
      throw new PaidMediaLedgerError('Paid media ledger pair recovery did not reach its exact target')
    }
    return true
  }

  private readDocument(): PaidMediaLedgerDocument {
    requireEncryption(this.dependencies.safeStorage)
    const hasPairIntent = this.recoverPairPublication()
    const now = requireNow(this.dependencies.now)
    const anchor = this.readAnchor()
    const raw = this.dependencies.atomicIO.readUtf8(
      this.path,
      MAX_FILE_BYTES,
      this.dependencies.harden
    )
    if (raw === null) {
      if (anchor !== null) {
        throw new PaidMediaLedgerError(
          'Paid media ledger is missing after initialization; recovery is locked by its anchor'
        )
      }
      return {
        schema: DOCUMENT_SCHEMA,
        ledgerIdentity: randomBytes(32).toString('hex'),
        sequence: 0,
        records: []
      }
    }
    const parsed = this.decodeLedgerEnvelope(raw, now)
    if (parsed.version === 'v1') throw new PaidMediaLegacyLedgerMigrationRequiredError()
    if (anchor === null) {
      throw new PaidMediaLedgerError('Paid media ledger recovery anchor is missing')
    }
    if (anchor.ledgerIdentity !== parsed.ledgerIdentity) {
      throw new PaidMediaLedgerError('Paid media ledger identity does not match its recovery anchor')
    }
    if (parsed.sequence !== anchor.sequenceFloor) {
      throw new PaidMediaLedgerError(
        parsed.sequence < anchor.sequenceFloor
          ? 'Paid media ledger sequence rollback was detected'
          : 'Paid media ledger body advanced ahead of its recovery anchor'
      )
    }
    if (parsed.version === 'v2') throw new PaidMediaLegacyLedgerMigrationRequiredError()
    if (parsed.version === 'v4' && !hasPairIntent) {
      throw new PaidMediaLedgerError('Paid media ledger pair intent is missing')
    }
    return {
      schema: DOCUMENT_SCHEMA,
      ledgerIdentity: parsed.ledgerIdentity as string,
      sequence: parsed.sequence,
      records: parsed.records
    }
  }

  private writeDocument(document: PaidMediaLedgerDocument): void {
    this.assertMutationAllowed()
    requireEncryption(this.dependencies.safeStorage)
    if (
      document.schema !== DOCUMENT_SCHEMA ||
      !SHA256_PATTERN.test(document.ledgerIdentity) ||
      !safeInteger(document.sequence, 1)
    ) {
      throw new PaidMediaLedgerError('Paid media ledger write document is invalid')
    }
    this.recoverPairPublication()
    const beforeAnchorEnvelope = this.dependencies.atomicIO.readUtf8(
      this.anchorPath,
      MAX_ANCHOR_FILE_BYTES,
      this.dependencies.harden
    )
    const beforeLedgerEnvelope = this.dependencies.atomicIO.readUtf8(
      this.path,
      MAX_FILE_BYTES,
      this.dependencies.harden
    )
    if ((beforeAnchorEnvelope === null) !== (beforeLedgerEnvelope === null)) {
      throw new PaidMediaLedgerError('Paid media ledger authority pair is incomplete')
    }
    let beforeSequence = 0
    if (beforeAnchorEnvelope !== null && beforeLedgerEnvelope !== null) {
      const beforeAnchor = this.decodeAnchorEnvelope(beforeAnchorEnvelope)
      const beforeLedger = this.decodeLedgerEnvelope(
        beforeLedgerEnvelope,
        requireNow(this.dependencies.now)
      )
      if (
        beforeLedger.version === 'v1' ||
        beforeLedger.version === 'v2' ||
        beforeLedger.ledgerIdentity !== document.ledgerIdentity ||
        beforeAnchor.ledgerIdentity !== document.ledgerIdentity ||
        beforeLedger.sequence !== beforeAnchor.sequenceFloor
      ) {
        throw new PaidMediaLedgerError('Paid media ledger expected-before pair is inconsistent')
      }
      beforeSequence = beforeLedger.sequence
    }
    if (document.sequence !== beforeSequence + 1) {
      throw new PaidMediaLedgerError('Paid media ledger write is not the next pair sequence')
    }
    const anchorEnvelope = this.encodeEnvelope(
      {
        schema: ANCHOR_DOCUMENT_SCHEMA,
        ledgerIdentity: document.ledgerIdentity,
        sequenceFloor: document.sequence
      } satisfies PaidMediaAnchorDocument,
      ANCHOR_ENVELOPE_SCHEMA,
      MAX_ANCHOR_PLAINTEXT_BYTES,
      MAX_ANCHOR_FILE_BYTES,
      'Paid media ledger anchor'
    )
    const ledgerEnvelope = this.encodeEnvelope(
      document,
      ENVELOPE_SCHEMA,
      MAX_PLAINTEXT_BYTES,
      MAX_FILE_BYTES,
      'Paid media ledger'
    )
    const pairReceiptFields = {
      ledgerIdentity: document.ledgerIdentity,
      beforeSequence,
      targetSequence: document.sequence,
      beforeAnchorSha256:
        beforeAnchorEnvelope === null ? null : sha256Utf8(beforeAnchorEnvelope),
      beforeLedgerSha256:
        beforeLedgerEnvelope === null ? null : sha256Utf8(beforeLedgerEnvelope),
      targetAnchorSha256: sha256Utf8(anchorEnvelope),
      targetLedgerSha256: sha256Utf8(ledgerEnvelope)
    }
    const pairIntentEnvelope = this.encodeEnvelope(
      {
        schema: PAIR_INTENT_DOCUMENT_SCHEMA,
        ...pairReceiptFields,
        targetAnchorEnvelope: anchorEnvelope,
        targetLedgerEnvelope: ledgerEnvelope,
        receiptSha256: pairIntentReceipt(pairReceiptFields)
      } satisfies PaidMediaPairIntentDocument,
      PAIR_INTENT_ENVELOPE_SCHEMA,
      MAX_PAIR_INTENT_PLAINTEXT_BYTES,
      MAX_PAIR_INTENT_FILE_BYTES,
      'Paid media ledger pair intent'
    )
    // The durable intent makes the only valid partial order recoverable:
    // intent -> anchor floor -> ledger body. The intent remains as the latest receipt.
    this.dependencies.atomicIO.writeUtf8Atomic(
      this.pairIntentPath,
      pairIntentEnvelope,
      this.dependencies.harden
    )
    this.dependencies.atomicIO.writeUtf8Atomic(
      this.anchorPath,
      anchorEnvelope,
      this.dependencies.harden
    )
    this.dependencies.atomicIO.writeUtf8Atomic(
      this.path,
      ledgerEnvelope,
      this.dependencies.harden
    )
    const finalAnchor = this.dependencies.atomicIO.readUtf8(
      this.anchorPath,
      MAX_ANCHOR_FILE_BYTES,
      this.dependencies.harden
    )
    const finalLedger = this.dependencies.atomicIO.readUtf8(
      this.path,
      MAX_FILE_BYTES,
      this.dependencies.harden
    )
    if (
      finalAnchor === null ||
      finalLedger === null ||
      sha256Utf8(finalAnchor) !== pairReceiptFields.targetAnchorSha256 ||
      sha256Utf8(finalLedger) !== pairReceiptFields.targetLedgerSha256
    ) {
      throw new PaidMediaLedgerError('Paid media ledger pair publication was not durable')
    }
  }

  /** Explicit first-provisioning initialization; normal startup never creates a ledger. */
  async provisionAuthorityLedger(): Promise<PaidMediaLedgerAuthorityEvidence> {
    return serializedForPath(this.path, () => {
      const ledgerExists =
        this.dependencies.atomicIO.readUtf8(
          this.path,
          MAX_FILE_BYTES,
          this.dependencies.harden
        ) !== null
      const anchorExists =
        this.dependencies.atomicIO.readUtf8(
          this.anchorPath,
          MAX_ANCHOR_FILE_BYTES,
          this.dependencies.harden
        ) !== null
      const pairIntentExists =
        this.dependencies.atomicIO.readUtf8(
          this.pairIntentPath,
          MAX_PAIR_INTENT_FILE_BYTES,
          this.dependencies.harden
        ) !== null
      if (!ledgerExists && !anchorExists && !pairIntentExists) {
        this.writeDocument({
          schema: DOCUMENT_SCHEMA,
          ledgerIdentity: randomBytes(32).toString('hex'),
          sequence: 1,
          records: []
        })
      }
      return this.authorityEvidenceForDocument(this.readDocument())
    })
  }

  private authorityEvidenceForDocument(
    document: PaidMediaLedgerDocument
  ): PaidMediaLedgerAuthorityEvidence {
    const canonical = JSON.stringify({
      schema: document.schema,
      ledgerIdentity: document.ledgerIdentity,
      sequence: document.sequence,
      records: document.records
    })
    return Object.freeze({
      ledgerIdentity: document.ledgerIdentity,
      ledgerSequence: document.sequence,
      ledgerStateDigest: createHash('sha256')
        .update(AUTHORITY_EVIDENCE_DOMAIN)
        .update(canonical, 'utf8')
        .digest('hex')
    })
  }

  async inspectAuthorityEvidence(): Promise<PaidMediaLedgerAuthorityEvidence> {
    return serializedForPath(this.path, () => {
      const document = this.readDocument()
      if (document.sequence === 0) {
        throw new PaidMediaLedgerError('Paid media ledger authority evidence is missing')
      }
      return this.authorityEvidenceForDocument(document)
    })
  }

  private async mutateOperation(
    operationId: string,
    mutate: (record: PaidMediaOperationRecord, now: number) => PaidMediaOperationRecord
  ): Promise<PaidMediaPublicOperation> {
    return serializedForPath(this.path, () => {
      if (typeof operationId !== 'string' || !OPERATION_ID_PATTERN.test(operationId)) {
        throw new PaidMediaLedgerError('Paid media operation id is invalid')
      }
      const document = this.readDocument()
      const index = document.records.findIndex((record) => record.operationId === operationId)
      if (index < 0) throw new PaidMediaLedgerError('Paid media operation is not pending')
      const now = requireNow(this.dependencies.now)
      const previous = document.records[index]
      if (now < previous.updatedAt) {
        throw new PaidMediaLedgerError('Paid media ledger clock moved backwards')
      }
      const next = mutate(previous, now)
      const records = [...document.records]
      records[index] = next
      this.writeDocument({
        schema: DOCUMENT_SCHEMA,
        ledgerIdentity: document.ledgerIdentity,
        sequence: nextSequence(document.sequence),
        records
      })
      return publicOperation(next)
    })
  }

  async importLegacyUnresolved(
    input: PaidMediaLegacyUnresolvedInput
  ): Promise<PaidMediaPublicOperation> {
    return serializedForPath(this.path, () => {
      const raw = input as unknown as Record<string, unknown>
      const recoverable = raw?.state === 'recoverable'
      const hasRetryAfter = Object.prototype.hasOwnProperty.call(raw ?? {}, 'retryAfterSeconds')
      const operationMatch =
        typeof input?.operationId === 'string'
          ? OPERATION_ID_PATTERN.exec(input.operationId)
          : null
      const now = requireNow(this.dependencies.now)
      if (
        !input ||
        typeof input !== 'object' ||
        !hasExactKeys(
          raw,
          recoverable
            ? [
                'operationId',
                'path',
                'requestSha256',
                'createdAt',
                'updatedAt',
                'state',
                'lastStatus',
                ...(hasRetryAfter ? ['retryAfterSeconds'] : [])
              ]
            : [
                'operationId',
                'path',
                'requestSha256',
                'createdAt',
                'updatedAt',
                'state'
              ]
        ) ||
        !operationMatch ||
        !UUID_PATTERN.test(operationMatch[1]) ||
        !validPath(input.path) ||
        typeof input.requestSha256 !== 'string' ||
        !SHA256_PATTERN.test(input.requestSha256) ||
        !safeInteger(input.createdAt) ||
        !safeInteger(input.updatedAt) ||
        input.updatedAt < input.createdAt ||
        input.updatedAt > now + FUTURE_SKEW_MS ||
        (input.state !== 'pending' && input.state !== 'recoverable') ||
        (recoverable && (!safeInteger(input.lastStatus) || Number(input.lastStatus) > 599)) ||
        (hasRetryAfter &&
          (!safeInteger(input.retryAfterSeconds, 1) ||
            Number(input.retryAfterSeconds) > 900))
      ) {
        throw new PaidMediaLedgerError('Legacy paid media operation is invalid')
      }

      const document = this.readDocument()
      const uuid = operationMatch[1].toLowerCase()
      const record: PaidMediaOperationRecord = {
        operationId: `desktop-op-${uuid}`,
        idempotencyKey: `desktop-${uuid}`,
        path: input.path,
        requestSha256: input.requestSha256,
        recoveryDomainSha256: null,
        state: 'recoverable',
        createdAt: input.createdAt,
        updatedAt: input.updatedAt,
        dispatchCount: 1,
        v2DispatchReceiptSha256: null,
        v2AckIntentReceiptSha256: null,
        lastStatus: recoverable ? Number(input.lastStatus) : 0,
        retryAfterSeconds: hasRetryAfter ? Number(input.retryAfterSeconds) : null,
        resultSha256: null,
        resultStatus: null,
        resultJsonBase64: null,
        deliveredAt: null,
        reconciliation: null
      }
      const sameIdentity = document.records.find(
        (candidate) =>
          candidate.operationId.toLowerCase() === record.operationId ||
          candidate.idempotencyKey.toLowerCase() === record.idempotencyKey
      )
      if (sameIdentity) {
        const identical =
          sameIdentity.operationId === record.operationId &&
          sameIdentity.idempotencyKey === record.idempotencyKey &&
          sameIdentity.path === record.path &&
          sameIdentity.requestSha256 === record.requestSha256 &&
          sameIdentity.recoveryDomainSha256 === null &&
          sameIdentity.state === record.state &&
          sameIdentity.createdAt === record.createdAt &&
          sameIdentity.updatedAt === record.updatedAt &&
          sameIdentity.dispatchCount === record.dispatchCount &&
          sameIdentity.lastStatus === record.lastStatus &&
          sameIdentity.retryAfterSeconds === record.retryAfterSeconds &&
          sameIdentity.resultSha256 === null &&
          sameIdentity.resultStatus === null &&
          sameIdentity.resultJsonBase64 === null &&
          sameIdentity.deliveredAt === null &&
          sameIdentity.reconciliation === null
        if (identical) return publicOperation(sameIdentity)
        throw new PaidMediaLedgerError('Legacy paid media operation conflicts with the ledger')
      }
      if (document.records.some((candidate) => isUnresolvedState(candidate.state))) {
        throw new PaidMediaUnresolvedOperationError()
      }
      if (document.records.length >= MAX_RECORDS) {
        throw new PaidMediaLedgerError('Paid media ledger record capacity is full')
      }
      this.writeDocument({
        schema: DOCUMENT_SCHEMA,
        ledgerIdentity: document.ledgerIdentity,
        sequence: nextSequence(document.sequence),
        records: [...document.records, record]
      })
      return publicOperation(record)
    })
  }

  async claim(input: PaidMediaClaimInput): Promise<PaidMediaClaimResult> {
    return serializedForPath(this.path, () => {
      const raw = input as unknown as Record<string, unknown>
      const retryRequested = Object.prototype.hasOwnProperty.call(raw, 'retryOperationId')
      if (
        !input ||
        typeof input !== 'object' ||
        !hasExactKeys(
          raw,
          retryRequested
            ? ['path', 'requestSha256', 'recoveryDomainSha256', 'retryOperationId']
            : ['path', 'requestSha256', 'recoveryDomainSha256']
        ) ||
        !validPath(input.path) ||
        typeof input.requestSha256 !== 'string' ||
        !SHA256_PATTERN.test(input.requestSha256) ||
        typeof input.recoveryDomainSha256 !== 'string' ||
        !SHA256_PATTERN.test(input.recoveryDomainSha256) ||
        (retryRequested &&
          (typeof input.retryOperationId !== 'string' ||
            !OPERATION_ID_PATTERN.test(input.retryOperationId)))
      ) {
        throw new PaidMediaLedgerError('Paid media claim is invalid')
      }
      const document = this.readDocument()
      if (retryRequested) {
        const record = document.records.find(
          (candidate) => candidate.operationId === input.retryOperationId
        )
        if (!record) throw new PaidMediaLedgerError('Paid media retry operation is not pending')
        if (record.recoveryDomainSha256 === null) {
          throw new PaidMediaLedgerError(
            'Paid media retry lacks a trusted recovery domain; reconcile it manually'
          )
        }
        if (
          record.path !== input.path ||
          record.requestSha256 !== input.requestSha256 ||
          record.recoveryDomainSha256 !== input.recoveryDomainSha256
        ) {
          throw new PaidMediaLedgerError('Paid media retry does not match the original operation')
        }
        if (!isUnresolvedState(record.state)) {
          throw new PaidMediaLedgerError('Paid media retry operation is already terminal')
        }
        if (record.state === 'result_ready') {
          if (
            record.resultSha256 === null ||
            record.resultStatus === null ||
            record.resultJsonBase64 === null
          ) {
            throw new PaidMediaLedgerError(
              'Paid media result-ready operation has no durable local response; reconcile it manually'
            )
          }
          return {
            operation: publicOperation(record),
            dispatch: {
              idempotencyKey: record.idempotencyKey,
              requestSha256: record.requestSha256
            },
            reused: true,
            replay: {
              status: record.resultStatus,
              responseJson: decodeResultJson(record.resultJsonBase64, record.resultSha256)
            }
          }
        }
        if (requireNow(this.dependencies.now) - record.createdAt >= AUTOMATIC_RETRY_MAX_AGE_MS) {
          throw new PaidMediaLedgerError(
            'Paid media retry operation is too old for automatic replay; reconcile it manually'
          )
        }
        return {
          operation: publicOperation(record),
          dispatch: {
            idempotencyKey: record.idempotencyKey,
            requestSha256: record.requestSha256
          },
          reused: true
        }
      }
      const now = requireNow(this.dependencies.now)
      const retainedRecords = document.records.filter((record) => {
        const completedAt = terminalAt(record)
        return completedAt === null || now - completedAt < TERMINAL_RETENTION_MS
      })
      if (retainedRecords.some((record) => isUnresolvedState(record.state))) {
        throw new PaidMediaUnresolvedOperationError()
      }
      if (retainedRecords.length >= MAX_RECORDS) {
        throw new PaidMediaLedgerError('Paid media ledger record capacity is full')
      }
      const uuid = this.dependencies.uuid()
      if (typeof uuid !== 'string' || !UUID_PATTERN.test(uuid)) {
        throw new PaidMediaLedgerError('Paid media operation UUID is invalid')
      }
      const record: PaidMediaOperationRecord = {
        operationId: `desktop-op-${uuid}`,
        idempotencyKey: `desktop-${uuid}`,
        path: input.path,
        requestSha256: input.requestSha256,
        recoveryDomainSha256: input.recoveryDomainSha256,
        state: 'claimed',
        createdAt: now,
        updatedAt: now,
        dispatchCount: 0,
        v2DispatchReceiptSha256: null,
        v2AckIntentReceiptSha256: null,
        lastStatus: null,
        retryAfterSeconds: null,
        resultSha256: null,
        resultStatus: null,
        resultJsonBase64: null,
        deliveredAt: null,
        reconciliation: null
      }
      if (
        retainedRecords.some(
          (candidate) =>
            candidate.operationId === record.operationId ||
            candidate.idempotencyKey === record.idempotencyKey
        )
      ) {
        throw new PaidMediaLedgerError('Paid media operation identity collision')
      }
      this.writeDocument({
        schema: DOCUMENT_SCHEMA,
        ledgerIdentity: document.ledgerIdentity,
        sequence: nextSequence(document.sequence),
        records: [...retainedRecords, record]
      })
      return {
        operation: publicOperation(record),
        dispatch: {
          idempotencyKey: record.idempotencyKey,
          requestSha256: record.requestSha256
        },
        reused: false
      }
    })
  }

  async ensureV2DispatchingOnce(
    input: PaidMediaV2DispatchInput
  ): Promise<PaidMediaPublicOperation> {
    const raw = input as unknown as Record<string, unknown>
    if (
      !input ||
      typeof input !== 'object' ||
      !hasExactKeys(raw, [
        'operationId',
        'path',
        'requestSha256',
        'recoveryDomainSha256',
        'dispatchReceiptSha256'
      ]) ||
      typeof input.operationId !== 'string' ||
      !OPERATION_ID_PATTERN.test(input.operationId) ||
      !validPath(input.path) ||
      typeof input.requestSha256 !== 'string' ||
      !SHA256_PATTERN.test(input.requestSha256) ||
      typeof input.recoveryDomainSha256 !== 'string' ||
      !SHA256_PATTERN.test(input.recoveryDomainSha256) ||
      typeof input.dispatchReceiptSha256 !== 'string' ||
      !NONZERO_SHA256_PATTERN.test(input.dispatchReceiptSha256)
    ) {
      throw new PaidMediaLedgerError('Paid media v2 dispatch receipt is invalid')
    }
    return serializedForPath(this.path, () => {
      const document = this.readDocument()
      const index = document.records.findIndex(
        (record) => record.operationId === input.operationId
      )
      if (index < 0) throw new PaidMediaLedgerError('Paid media operation is not pending')
      const previous = document.records[index]
      const semanticsMatch =
        previous.path === input.path &&
        previous.requestSha256 === input.requestSha256 &&
        previous.recoveryDomainSha256 === input.recoveryDomainSha256
      if (previous.v2DispatchReceiptSha256 !== null) {
        if (
          !semanticsMatch ||
          previous.v2DispatchReceiptSha256 !== input.dispatchReceiptSha256 ||
          previous.state !== 'dispatching' ||
          previous.dispatchCount !== 1
        ) {
          throw new PaidMediaLedgerError('Paid media v2 dispatch receipt conflicts with the ledger')
        }
        return publicOperation(previous)
      }
      if (!semanticsMatch || previous.state !== 'claimed' || previous.dispatchCount !== 0) {
        throw new PaidMediaLedgerError(
          'Paid media operation cannot bind a v2 dispatch receipt from its current state'
        )
      }
      const now = requireNow(this.dependencies.now)
      if (now < previous.updatedAt) {
        throw new PaidMediaLedgerError('Paid media ledger clock moved backwards')
      }
      const next: PaidMediaOperationRecord = {
        ...previous,
        state: 'dispatching',
        updatedAt: now,
        dispatchCount: 1,
        v2DispatchReceiptSha256: input.dispatchReceiptSha256,
        lastStatus: null,
        retryAfterSeconds: null,
        resultSha256: null,
        resultStatus: null,
        resultJsonBase64: null,
        deliveredAt: null,
        reconciliation: null
      }
      const records = [...document.records]
      records[index] = next
      this.writeDocument({
        schema: DOCUMENT_SCHEMA,
        ledgerIdentity: document.ledgerIdentity,
        sequence: nextSequence(document.sequence),
        records
      })
      return publicOperation(next)
    })
  }

  async ensureV2ResultReadyOnce(
    input: PaidMediaV2ResultReadyInput
  ): Promise<PaidMediaPublicOperation> {
    const raw = input as unknown as Record<string, unknown>
    if (
      !input ||
      typeof input !== 'object' ||
      !hasExactKeys(raw, [
        'operationId',
        'dispatchReceiptSha256',
        'ackIntentReceiptSha256',
        'status',
        'responseJson'
      ]) ||
      typeof input.operationId !== 'string' ||
      !OPERATION_ID_PATTERN.test(input.operationId) ||
      typeof input.dispatchReceiptSha256 !== 'string' ||
      !NONZERO_SHA256_PATTERN.test(input.dispatchReceiptSha256) ||
      typeof input.ackIntentReceiptSha256 !== 'string' ||
      !NONZERO_SHA256_PATTERN.test(input.ackIntentReceiptSha256) ||
      !safeInteger(input.status, 200) ||
      input.status > 299
    ) {
      throw new PaidMediaLedgerError('Paid media v2 result-ready receipt is invalid')
    }
    const encoded = encodeResultJson(input.responseJson)
    return serializedForPath(this.path, () => {
      const document = this.readDocument()
      const index = document.records.findIndex(
        (record) => record.operationId === input.operationId
      )
      if (index < 0) throw new PaidMediaLedgerError('Paid media operation is not pending')
      const previous = document.records[index]
      if (previous.v2AckIntentReceiptSha256 !== null) {
        if (
          previous.v2DispatchReceiptSha256 !== input.dispatchReceiptSha256 ||
          previous.v2AckIntentReceiptSha256 !== input.ackIntentReceiptSha256 ||
          previous.state !== 'result_ready' ||
          previous.dispatchCount !== 1 ||
          previous.resultStatus !== input.status ||
          previous.resultSha256 !== encoded.resultSha256 ||
          previous.resultJsonBase64 !== encoded.resultJsonBase64
        ) {
          throw new PaidMediaLedgerError(
            'Paid media v2 result-ready receipt conflicts with the ledger'
          )
        }
        return publicOperation(previous)
      }
      if (
        previous.v2DispatchReceiptSha256 !== input.dispatchReceiptSha256 ||
        previous.state !== 'dispatching' ||
        previous.dispatchCount !== 1
      ) {
        throw new PaidMediaLedgerError(
          'Paid media operation cannot bind a v2 result-ready receipt from its current state'
        )
      }
      const now = requireNow(this.dependencies.now)
      if (now < previous.updatedAt) {
        throw new PaidMediaLedgerError('Paid media ledger clock moved backwards')
      }
      const next: PaidMediaOperationRecord = {
        ...previous,
        state: 'result_ready',
        updatedAt: now,
        v2AckIntentReceiptSha256: input.ackIntentReceiptSha256,
        lastStatus: null,
        retryAfterSeconds: null,
        resultSha256: encoded.resultSha256,
        resultStatus: input.status,
        resultJsonBase64: encoded.resultJsonBase64,
        deliveredAt: null,
        reconciliation: null
      }
      const records = [...document.records]
      records[index] = next
      this.writeDocument({
        schema: DOCUMENT_SCHEMA,
        ledgerIdentity: document.ledgerIdentity,
        sequence: nextSequence(document.sequence),
        records
      })
      return publicOperation(next)
    })
  }

  async markDispatching(operationId: string): Promise<PaidMediaPublicOperation> {
    return this.mutateOperation(operationId, (record, now) => {
      if (record.v2DispatchReceiptSha256 !== null) {
        throw new PaidMediaLedgerError(
          'A v2-bound paid media operation cannot use legacy dispatch retry semantics'
        )
      }
      if (
        record.state !== 'claimed' &&
        record.state !== 'dispatching' &&
        record.state !== 'recoverable'
      ) {
        throw new PaidMediaLedgerError('Paid media operation cannot enter dispatching')
      }
      if (record.dispatchCount >= MAX_DISPATCH_COUNT) {
        throw new PaidMediaLedgerError('Paid media dispatch limit is exhausted')
      }
      return {
        ...record,
        state: 'dispatching',
        updatedAt: now,
        dispatchCount: record.dispatchCount + 1,
        lastStatus: null,
        retryAfterSeconds: null,
        resultSha256: null,
        resultStatus: null,
        resultJsonBase64: null,
        deliveredAt: null,
        reconciliation: null
      }
    })
  }

  async markRecoverable(input: {
    operationId: string
    status: number
    retryAfterSeconds?: number
  }): Promise<PaidMediaPublicOperation> {
    const raw = input as unknown as Record<string, unknown>
    const hasRetryAfter = Object.prototype.hasOwnProperty.call(raw, 'retryAfterSeconds')
    if (
      !input ||
      typeof input !== 'object' ||
      !hasExactKeys(
        raw,
        hasRetryAfter
          ? ['operationId', 'status', 'retryAfterSeconds']
          : ['operationId', 'status']
      ) ||
      !safeInteger(input.status) ||
      input.status > 599 ||
      (hasRetryAfter &&
        (!safeInteger(input.retryAfterSeconds, 1) || Number(input.retryAfterSeconds) > 900))
    ) {
      throw new PaidMediaLedgerError('Paid media recovery transition is invalid')
    }
    return this.mutateOperation(input.operationId, (record, now) => {
      if (record.state !== 'dispatching') {
        throw new PaidMediaLedgerError('Paid media operation cannot enter recovery')
      }
      return {
        ...record,
        state: 'recoverable',
        updatedAt: now,
        lastStatus: input.status,
        retryAfterSeconds: input.retryAfterSeconds ?? null
      }
    })
  }

  async markResultReady(input: {
    operationId: string
    status: number
    responseJson: string
  }): Promise<PaidMediaPublicOperation> {
    if (
      !input ||
      typeof input !== 'object' ||
      !hasExactKeys(input as unknown as Record<string, unknown>, [
        'operationId',
        'status',
        'responseJson'
      ]) ||
      typeof input.operationId !== 'string' ||
      !OPERATION_ID_PATTERN.test(input.operationId) ||
      !safeInteger(input.status, 200) ||
      input.status > 299
    ) {
      throw new PaidMediaLedgerError('Paid media result transition is invalid')
    }
    const encoded = encodeResultJson(input.responseJson)
    return this.mutateOperation(input.operationId, (record, now) => {
      if (record.v2DispatchReceiptSha256 !== null) {
        throw new PaidMediaLedgerError(
          'A v2-bound paid media operation cannot use the legacy result-ready transition'
        )
      }
      if (record.state !== 'dispatching') {
        throw new PaidMediaLedgerError('Paid media operation cannot become result ready')
      }
      return {
        ...record,
        state: 'result_ready',
        updatedAt: now,
        lastStatus: null,
        retryAfterSeconds: null,
        resultSha256: encoded.resultSha256,
        resultStatus: input.status,
        resultJsonBase64: encoded.resultJsonBase64
      }
    })
  }

  async markDelivered(input: {
    operationId: string
    resultSha256: string
    archiveReceiptSha256: string
  }): Promise<PaidMediaPublicOperation> {
    if (
      !input ||
      typeof input !== 'object' ||
      !hasExactKeys(input as unknown as Record<string, unknown>, [
        'operationId',
        'resultSha256',
        'archiveReceiptSha256'
      ]) ||
      typeof input.operationId !== 'string' ||
      !OPERATION_ID_PATTERN.test(input.operationId) ||
      typeof input.resultSha256 !== 'string' ||
      !SHA256_PATTERN.test(input.resultSha256) ||
      typeof input.archiveReceiptSha256 !== 'string' ||
      !SHA256_PATTERN.test(input.archiveReceiptSha256)
    ) {
      throw new PaidMediaLedgerError(
        'Paid media delivery requires a verified Main archive receipt'
      )
    }
    return this.mutateOperation(input.operationId, (record, now) => {
      if (record.state !== 'result_ready') {
        throw new PaidMediaLedgerError('Paid media operation cannot become delivered')
      }
      if (record.resultSha256 !== input.resultSha256) {
        throw new PaidMediaLedgerError(
          'Paid media delivery archive does not match the durable result'
        )
      }
      return {
        ...record,
        state: 'delivered',
        updatedAt: now,
        resultJsonBase64: null,
        deliveredAt: now
      }
    })
  }

  async reconcile(input: {
    operationId: string
    reason: string
    evidence: string
  }): Promise<PaidMediaPublicOperation> {
    if (
      !input ||
      typeof input !== 'object' ||
      !hasExactKeys(input as unknown as Record<string, unknown>, [
        'operationId',
        'reason',
        'evidence'
      ]) ||
      typeof input.operationId !== 'string' ||
      !OPERATION_ID_PATTERN.test(input.operationId) ||
      !boundedText(input.reason, MAX_RECONCILIATION_REASON_BYTES) ||
      !boundedText(input.evidence, MAX_RECONCILIATION_EVIDENCE_BYTES)
    ) {
      throw new PaidMediaLedgerError('Paid media reconciliation request is invalid')
    }
    return this.mutateOperation(input.operationId, (record, now) => {
      if (!isUnresolvedState(record.state)) {
        throw new PaidMediaLedgerError('Paid media operation cannot be reconciled')
      }
      return {
        ...record,
        state: 'reconciled',
        updatedAt: now,
        resultJsonBase64: null,
        deliveredAt: null,
        reconciliation: {
          at: now,
          reason: input.reason,
          evidence: input.evidence
        }
      }
    })
  }

  async listPublic(): Promise<PaidMediaPublicOperation[]> {
    return serializedForPath(this.path, () =>
      this.readDocument().records.map((record) => publicOperation(record))
    )
  }
}
