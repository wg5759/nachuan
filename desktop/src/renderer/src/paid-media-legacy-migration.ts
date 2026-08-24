const STORAGE_KEY = 'nachuan.paid-media.pending.v1'
const SENTINEL_SCHEMA = 'nachuan.paid-media.renderer-migrated.v2'
const MAX_LEGACY_BYTES = 128 * 1024
const FUTURE_SKEW_MS = 5 * 60 * 1000
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
const OPERATION_ID_PATTERN = /^desktop-op-([0-9a-f-]{36})$/i
const IDEMPOTENCY_KEY_PATTERN = /^desktop-([0-9a-f-]{36})$/i
const SHA256_PATTERN = /^[0-9a-f]{64}$/

type LegacyPaidMediaPath = '/v1/images/generations' | '/v1/videos/generations'

export interface LegacyPaidMediaImport {
  operationId: string
  path: LegacyPaidMediaPath
  requestSha256: string
  createdAt: number
  updatedAt: number
  state: 'pending' | 'recoverable'
  lastStatus?: number
  retryAfterSeconds?: number
}

interface LegacyImportApi {
  importLegacyPaidMediaJournal: (
    record: LegacyPaidMediaImport | null | { kind: 'migrated' }
  ) => Promise<unknown>
}

export class PaidMediaLegacyMigrationError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options)
    this.name = 'PaidMediaLegacyMigrationError'
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

function parseRecord(value: unknown): LegacyPaidMediaImport {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new PaidMediaLegacyMigrationError('Legacy paid media record is invalid')
  }
  const record = value as Record<string, unknown>
  const expected = [
    'operationId',
    'idempotencyKey',
    'path',
    'requestSha256',
    'createdAt',
    'updatedAt',
    'state',
    ...(record.lastStatus === undefined ? [] : ['lastStatus']),
    ...(record.retryAfterSeconds === undefined ? [] : ['retryAfterSeconds'])
  ]
  if (!hasExactKeys(record, expected)) {
    throw new PaidMediaLegacyMigrationError('Legacy paid media record has unknown fields')
  }
  const operation =
    typeof record.operationId === 'string' ? OPERATION_ID_PATTERN.exec(record.operationId) : null
  const key =
    typeof record.idempotencyKey === 'string'
      ? IDEMPOTENCY_KEY_PATTERN.exec(record.idempotencyKey)
      : null
  if (
    !operation ||
    !key ||
    !UUID_PATTERN.test(operation[1]) ||
    !UUID_PATTERN.test(key[1]) ||
    operation[1].toLowerCase() !== key[1].toLowerCase()
  ) {
    throw new PaidMediaLegacyMigrationError('Legacy paid media identity is invalid')
  }
  if (
    record.path !== '/v1/images/generations' &&
    record.path !== '/v1/videos/generations'
  ) {
    throw new PaidMediaLegacyMigrationError('Legacy paid media path is invalid')
  }
  if (typeof record.requestSha256 !== 'string' || !SHA256_PATTERN.test(record.requestSha256)) {
    throw new PaidMediaLegacyMigrationError('Legacy paid media request digest is invalid')
  }
  if (
    !safeInteger(record.createdAt) ||
    !safeInteger(record.updatedAt) ||
    record.updatedAt < record.createdAt ||
    record.createdAt > Date.now() + FUTURE_SKEW_MS ||
    record.updatedAt > Date.now() + FUTURE_SKEW_MS
  ) {
    throw new PaidMediaLegacyMigrationError('Legacy paid media timestamp is invalid')
  }
  if (record.state !== 'pending' && record.state !== 'recoverable') {
    throw new PaidMediaLegacyMigrationError('Legacy paid media state is invalid')
  }
  if (
    record.lastStatus !== undefined &&
    (!safeInteger(record.lastStatus) || record.lastStatus > 599)
  ) {
    throw new PaidMediaLegacyMigrationError('Legacy paid media status is invalid')
  }
  if (
    record.retryAfterSeconds !== undefined &&
    (!safeInteger(record.retryAfterSeconds, 1) || record.retryAfterSeconds > 900)
  ) {
    throw new PaidMediaLegacyMigrationError('Legacy paid media retry delay is invalid')
  }
  return {
    operationId: record.operationId,
    path: record.path,
    requestSha256: record.requestSha256,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    state: record.state,
    ...(record.lastStatus === undefined ? {} : { lastStatus: record.lastStatus }),
    ...(record.retryAfterSeconds === undefined
      ? {}
      : { retryAfterSeconds: record.retryAfterSeconds })
  } as LegacyPaidMediaImport
}

function parseLegacy(raw: string): LegacyPaidMediaImport | null | 'migrated' {
  if (new TextEncoder().encode(raw).byteLength > MAX_LEGACY_BYTES) {
    throw new PaidMediaLegacyMigrationError('Legacy paid media journal exceeds its size limit')
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch (error) {
    throw new PaidMediaLegacyMigrationError('Legacy paid media journal is corrupt', {
      cause: error
    })
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new PaidMediaLegacyMigrationError('Legacy paid media journal is invalid')
  }
  const document = parsed as Record<string, unknown>
  if (document.schema === SENTINEL_SCHEMA) {
    if (
      !hasExactKeys(document, ['schema', 'migratedAt']) ||
      !safeInteger(document.migratedAt)
    ) {
      throw new PaidMediaLegacyMigrationError('Paid media migration sentinel is invalid')
    }
    return 'migrated'
  }
  if (
    !hasExactKeys(document, ['schema', 'records']) ||
    document.schema !== 1 ||
    !Array.isArray(document.records) ||
    document.records.length > 1
  ) {
    throw new PaidMediaLegacyMigrationError('Legacy paid media journal schema is invalid')
  }
  return document.records.length === 0 ? null : parseRecord(document.records[0])
}

function migrationApi(): LegacyImportApi {
  const candidate = (window as unknown as { api?: Partial<LegacyImportApi> }).api
  if (!candidate || typeof candidate.importLegacyPaidMediaJournal !== 'function') {
    throw new PaidMediaLegacyMigrationError('Main paid media migration API is unavailable')
  }
  return candidate as LegacyImportApi
}

let migration: Promise<void> | null = null

export function ensureLegacyPaidMediaMigrated(): Promise<void> {
  if (migration) return migration
  migration = (async () => {
    let raw: string | null
    try {
      raw = globalThis.localStorage.getItem(STORAGE_KEY)
    } catch (error) {
      throw new PaidMediaLegacyMigrationError('Cannot read the legacy paid media journal', {
        cause: error
      })
    }
    const parsed = raw === null ? null : parseLegacy(raw)
    if (parsed === 'migrated') {
      // Renderer storage is writable and therefore never substitutes for the
      // Main/Installation-Root-bound seal.  A later start must replay a bounded
      // marker so Main can require the already-closed durable decision.
      await migrationApi().importLegacyPaidMediaJournal({ kind: 'migrated' })
      return
    }
    // Main must durably close the one-time seal for both candidate and empty
    // histories before the renderer writes its downgrade-blocking sentinel.
    await migrationApi().importLegacyPaidMediaJournal(parsed)
    const sentinel = JSON.stringify({ schema: SENTINEL_SCHEMA, migratedAt: Date.now() })
    try {
      globalThis.localStorage.setItem(STORAGE_KEY, sentinel)
    } catch (error) {
      throw new PaidMediaLegacyMigrationError(
        'Cannot persist the paid media downgrade-blocking migration sentinel',
        { cause: error }
      )
    }
  })()
  return migration
}
