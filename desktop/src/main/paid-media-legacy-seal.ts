import { createHash, randomBytes } from 'node:crypto'
import {
  closeSync,
  existsSync,
  fsyncSync,
  linkSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync
} from 'node:fs'
import { basename, dirname, join, resolve } from 'node:path'

export interface PaidMediaLegacySealSafeStorage {
  isEncryptionAvailable(): boolean
  encryptString(value: string): Buffer
  decryptString(value: Buffer): string
}

export type PaidMediaLegacySealAclHardener = (path: string, directory: boolean) => void

export interface PaidMediaLegacySealAtomicIO {
  readUtf8(
    path: string,
    maxBytes: number,
    harden: PaidMediaLegacySealAclHardener
  ): string | null
  writeUtf8AtomicNew(
    path: string,
    value: string,
    harden: PaidMediaLegacySealAclHardener
  ): void
  writeUtf8AtomicReplace(
    path: string,
    value: string,
    harden: PaidMediaLegacySealAclHardener
  ): void
}

export interface PaidMediaLegacySealDependencies {
  safeStorage: PaidMediaLegacySealSafeStorage
  harden: PaidMediaLegacySealAclHardener
  now: () => number
  atomicIO: PaidMediaLegacySealAtomicIO
}

export class PaidMediaLegacySealError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options)
    this.name = 'PaidMediaLegacySealError'
  }
}

export class PaidMediaLegacyMigrationUnavailableError extends PaidMediaLegacySealError {
  constructor(message = 'Paid media legacy migration is unavailable', options?: ErrorOptions) {
    super(message, options)
    this.name = 'PaidMediaLegacyMigrationUnavailableError'
  }
}

const MAX_SEAL_BYTES = 64 * 1024
const MAX_PLAINTEXT_BYTES = 16 * 1024
const DOCUMENT_SCHEMA = 'nachuan.paid-media-legacy-seal.v1'
const ENVELOPE_SCHEMA = 'nachuan.paid-media-legacy-seal.envelope.v1'
const CANDIDATE_SCHEMA = 'nachuan.paid-media-legacy-candidate.v1'
const DECISION_SCHEMA = 'nachuan.paid-media-legacy-decision.v1'
const PROTECTION = 'electron-safe-storage'
const FUTURE_SKEW_MS = 5 * 60 * 1000
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
const OPERATION_ID_PATTERN = /^desktop-op-([0-9a-f-]{36})$/i
const SHA256_PATTERN = /^[0-9a-f]{64}$/

export interface PaidMediaLegacySealOpenStatus {
  state: 'open'
}

export type PaidMediaLegacyCandidatePath =
  | '/v1/images/generations'
  | '/v1/videos/generations'

export interface PaidMediaLegacyCandidate {
  operationId: string
  path: PaidMediaLegacyCandidatePath
  requestSha256: string
  createdAt: number
  updatedAt: number
  state: 'pending' | 'recoverable'
  lastStatus?: number
  retryAfterSeconds?: number
}

export interface PaidMediaLegacyCandidateSummary extends PaidMediaLegacyCandidate {
  candidateSha256: string
}

export interface PaidMediaLegacyCandidateDecision {
  kind: 'candidate'
  candidate: PaidMediaLegacyCandidate
}

export type PaidMediaLegacySealDecision = PaidMediaLegacyCandidateDecision | { kind: 'empty' }

export interface PaidMediaLegacyCandidateClosedStatus {
  state: 'closed'
  closedAt: number
  decision: {
    kind: 'candidate'
    decisionSha256: string
    candidate: PaidMediaLegacyCandidateSummary
  }
}

export interface PaidMediaLegacyEmptyClosedStatus {
  state: 'closed'
  closedAt: number
  decision: {
    kind: 'empty'
    decisionSha256: string
  }
}

export type PaidMediaLegacySealClosedStatus =
  | PaidMediaLegacyCandidateClosedStatus
  | PaidMediaLegacyEmptyClosedStatus

export type PaidMediaLegacySealStatus =
  | PaidMediaLegacySealOpenStatus
  | PaidMediaLegacySealClosedStatus

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort()
  const wanted = [...expected].sort()
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index])
}

function safeInteger(value: unknown, minimum = 0): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= minimum
}

function summarizeCandidate(
  input: PaidMediaLegacyCandidate,
  now: number
): PaidMediaLegacyCandidateSummary {
  if (!safeInteger(now)) throw new PaidMediaLegacyMigrationUnavailableError()
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new PaidMediaLegacySealError('Legacy paid media candidate is invalid')
  }
  const raw = input as unknown as Record<string, unknown>
  const recoverable = raw.state === 'recoverable'
  const hasRetryAfter = Object.prototype.hasOwnProperty.call(raw, 'retryAfterSeconds')
  const expected = recoverable
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
    : ['operationId', 'path', 'requestSha256', 'createdAt', 'updatedAt', 'state']
  const operation =
    typeof raw.operationId === 'string' ? OPERATION_ID_PATTERN.exec(raw.operationId) : null
  if (
    !exactKeys(raw, expected) ||
    !operation ||
    !UUID_PATTERN.test(operation[1]) ||
    (raw.path !== '/v1/images/generations' && raw.path !== '/v1/videos/generations') ||
    typeof raw.requestSha256 !== 'string' ||
    !SHA256_PATTERN.test(raw.requestSha256) ||
    !safeInteger(raw.createdAt) ||
    !safeInteger(raw.updatedAt) ||
    raw.updatedAt < raw.createdAt ||
    raw.createdAt > now + FUTURE_SKEW_MS ||
    raw.updatedAt > now + FUTURE_SKEW_MS ||
    (raw.state !== 'pending' && raw.state !== 'recoverable') ||
    (recoverable && (!safeInteger(raw.lastStatus) || raw.lastStatus > 599)) ||
    (hasRetryAfter &&
      (!safeInteger(raw.retryAfterSeconds, 1) || Number(raw.retryAfterSeconds) > 900))
  ) {
    throw new PaidMediaLegacySealError('Legacy paid media candidate is invalid')
  }
  const normalized: PaidMediaLegacyCandidate = {
    operationId: `desktop-op-${operation[1].toLowerCase()}`,
    path: raw.path,
    requestSha256: raw.requestSha256,
    createdAt: raw.createdAt,
    updatedAt: raw.updatedAt,
    state: raw.state,
    ...(recoverable ? { lastStatus: raw.lastStatus as number } : {}),
    ...(hasRetryAfter ? { retryAfterSeconds: raw.retryAfterSeconds as number } : {})
  }
  const canonical = JSON.stringify({ schema: CANDIDATE_SCHEMA, ...normalized })
  if (Buffer.byteLength(canonical, 'utf8') > MAX_PLAINTEXT_BYTES) {
    throw new PaidMediaLegacySealError('Legacy paid media candidate exceeds its size limit')
  }
  return {
    ...normalized,
    candidateSha256: createHash('sha256').update(canonical, 'utf8').digest('hex')
  }
}

function candidateDecisionSha256(candidateSha256: string): string {
  return createHash('sha256')
    .update(
      JSON.stringify({
        schema: DECISION_SCHEMA,
        kind: 'candidate',
        candidateSha256
      }),
      'utf8'
    )
    .digest('hex')
}

function emptyDecisionSha256(): string {
  return createHash('sha256')
    .update(JSON.stringify({ schema: DECISION_SCHEMA, kind: 'empty' }), 'utf8')
    .digest('hex')
}

function writeAtomicReplacement(
  path: string,
  value: string,
  harden: PaidMediaLegacySealAclHardener
): void {
  const parent = dirname(path)
  const parentInfo = lstatSync(parent)
  const current = lstatSync(path)
  if (
    !parentInfo.isDirectory() ||
    parentInfo.isSymbolicLink() ||
    !current.isFile() ||
    current.isSymbolicLink()
  ) {
    throw new PaidMediaLegacyMigrationUnavailableError()
  }
  harden(parent, true)
  harden(path, false)
  const temporary = join(
    parent,
    `.${basename(path)}.${process.pid}.${randomBytes(8).toString('hex')}.tmp`
  )
  let handle: number | null = null
  try {
    handle = openSync(temporary, 'wx', 0o600)
    writeFileSync(handle, value, 'utf8')
    fsyncSync(handle)
    closeSync(handle)
    handle = null
    harden(temporary, false)
    renameSync(temporary, path)
    harden(path, false)
  } catch (error) {
    if (error instanceof PaidMediaLegacyMigrationUnavailableError) throw error
    throw new PaidMediaLegacyMigrationUnavailableError(undefined, { cause: error })
  } finally {
    if (handle !== null) closeSync(handle)
    if (existsSync(temporary)) unlinkSync(temporary)
  }
}

function parseObject(raw: string): Record<string, unknown> {
  try {
    const value: unknown = JSON.parse(raw)
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('not object')
    return value as Record<string, unknown>
  } catch (error) {
    throw new PaidMediaLegacyMigrationUnavailableError(undefined, { cause: error })
  }
}

function decodeCanonicalBase64(value: unknown): Buffer {
  if (
    typeof value !== 'string' ||
    value.length < 4 ||
    value.length > MAX_SEAL_BYTES ||
    value.length % 4 !== 0 ||
    !/^[A-Za-z0-9+/]+={0,2}$/.test(value)
  ) {
    throw new PaidMediaLegacyMigrationUnavailableError()
  }
  const decoded = Buffer.from(value, 'base64')
  if (decoded.toString('base64') !== value) {
    throw new PaidMediaLegacyMigrationUnavailableError()
  }
  return decoded
}

export const nodePaidMediaLegacySealAtomicIO: PaidMediaLegacySealAtomicIO = {
  readUtf8(path, maxBytes, harden) {
    if (!existsSync(path)) return null
    const parent = dirname(path)
    const parentInfo = lstatSync(parent)
    const info = lstatSync(path)
    if (
      !parentInfo.isDirectory() ||
      parentInfo.isSymbolicLink() ||
      !info.isFile() ||
      info.isSymbolicLink()
    ) {
      throw new PaidMediaLegacyMigrationUnavailableError()
    }
    if (info.size < 1 || info.size > maxBytes) {
      throw new PaidMediaLegacyMigrationUnavailableError()
    }
    harden(parent, true)
    harden(path, false)
    return readFileSync(path, 'utf8')
  },
  writeUtf8AtomicNew(path, value, harden) {
    const parent = dirname(path)
    mkdirSync(parent, { recursive: true })
    const parentInfo = lstatSync(parent)
    if (!parentInfo.isDirectory() || parentInfo.isSymbolicLink() || existsSync(path)) {
      throw new PaidMediaLegacyMigrationUnavailableError()
    }
    harden(parent, true)
    const temporary = join(
      parent,
      `.${basename(path)}.${process.pid}.${randomBytes(8).toString('hex')}.tmp`
    )
    let handle: number | null = null
    try {
      handle = openSync(temporary, 'wx', 0o600)
      writeFileSync(handle, value, 'utf8')
      fsyncSync(handle)
      closeSync(handle)
      handle = null
      harden(temporary, false)
      // A hard-link create is atomic and refuses to replace a seal that won a
      // concurrent provisioning race. The temporary inode was already fsynced.
      linkSync(temporary, path)
      harden(path, false)
    } catch (error) {
      if (error instanceof PaidMediaLegacyMigrationUnavailableError) throw error
      throw new PaidMediaLegacyMigrationUnavailableError(undefined, { cause: error })
    } finally {
      if (handle !== null) closeSync(handle)
      if (existsSync(temporary)) unlinkSync(temporary)
    }
  },
  writeUtf8AtomicReplace(path, value, harden) {
    try {
      writeAtomicReplacement(path, value, harden)
    } catch (error) {
      if (error instanceof PaidMediaLegacyMigrationUnavailableError) throw error
      throw new PaidMediaLegacyMigrationUnavailableError(undefined, { cause: error })
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

async function serializedForSealPath<T>(
  path: string,
  action: () => T | Promise<T>
): Promise<T> {
  const key = process.platform === 'win32' ? resolve(path).toLowerCase() : resolve(path)
  const mutex = pathMutexes.get(key) ?? new PathMutex()
  pathMutexes.set(key, mutex)
  try {
    return await mutex.run(action)
  } finally {
    if (mutex.idle && pathMutexes.get(key) === mutex) pathMutexes.delete(key)
  }
}

export class PaidMediaLegacySeal {
  constructor(
    private readonly path: string,
    private readonly dependencies: PaidMediaLegacySealDependencies
  ) {
    if (!path || !resolve(path)) throw new PaidMediaLegacySealError('Legacy seal path is invalid')
  }

  private requireEncryption(): void {
    if (!this.dependencies.safeStorage.isEncryptionAvailable()) {
      throw new PaidMediaLegacyMigrationUnavailableError()
    }
  }

  summarizeCandidate(candidate: PaidMediaLegacyCandidate): PaidMediaLegacyCandidateSummary {
    return summarizeCandidate(candidate, this.dependencies.now())
  }

  private encode(document: unknown): string {
    this.requireEncryption()
    const plaintext = JSON.stringify(document)
    if (Buffer.byteLength(plaintext, 'utf8') > MAX_PLAINTEXT_BYTES) {
      throw new PaidMediaLegacyMigrationUnavailableError()
    }
    let ciphertext: Buffer
    try {
      ciphertext = this.dependencies.safeStorage.encryptString(plaintext)
    } catch (error) {
      throw new PaidMediaLegacyMigrationUnavailableError(undefined, { cause: error })
    }
    if (!Buffer.isBuffer(ciphertext) || ciphertext.length < 1) {
      throw new PaidMediaLegacyMigrationUnavailableError()
    }
    const envelope = JSON.stringify({
      schema: ENVELOPE_SCHEMA,
      protection: PROTECTION,
      ciphertext: ciphertext.toString('base64')
    })
    if (Buffer.byteLength(envelope, 'utf8') > MAX_SEAL_BYTES) {
      throw new PaidMediaLegacyMigrationUnavailableError()
    }
    return envelope
  }

  private decode(raw: string): PaidMediaLegacySealStatus {
    this.requireEncryption()
    if (Buffer.byteLength(raw, 'utf8') > MAX_SEAL_BYTES) {
      throw new PaidMediaLegacyMigrationUnavailableError()
    }
    const envelope = parseObject(raw)
    if (
      !exactKeys(envelope, ['schema', 'protection', 'ciphertext']) ||
      envelope.schema !== ENVELOPE_SCHEMA ||
      envelope.protection !== PROTECTION
    ) {
      throw new PaidMediaLegacyMigrationUnavailableError()
    }
    let plaintext: string
    try {
      plaintext = this.dependencies.safeStorage.decryptString(
        decodeCanonicalBase64(envelope.ciphertext)
      )
    } catch (error) {
      if (error instanceof PaidMediaLegacyMigrationUnavailableError) throw error
      throw new PaidMediaLegacyMigrationUnavailableError(undefined, { cause: error })
    }
    if (Buffer.byteLength(plaintext, 'utf8') > MAX_PLAINTEXT_BYTES) {
      throw new PaidMediaLegacyMigrationUnavailableError()
    }
    const document = parseObject(plaintext)
    if (document.schema !== DOCUMENT_SCHEMA) {
      throw new PaidMediaLegacyMigrationUnavailableError()
    }
    if (document.state === 'open') {
      if (!exactKeys(document, ['schema', 'state'])) {
        throw new PaidMediaLegacyMigrationUnavailableError()
      }
      return { state: 'open' }
    }
    if (
      document.state !== 'closed' ||
      !exactKeys(document, ['schema', 'state', 'closedAt', 'decision']) ||
      !safeInteger(document.closedAt) ||
      document.closedAt > this.dependencies.now() + FUTURE_SKEW_MS ||
      !document.decision ||
      typeof document.decision !== 'object' ||
      Array.isArray(document.decision)
    ) {
      throw new PaidMediaLegacyMigrationUnavailableError()
    }
    const decision = document.decision as Record<string, unknown>
    if (decision.kind === 'empty') {
      if (
        !exactKeys(decision, ['kind', 'decisionSha256']) ||
        decision.decisionSha256 !== emptyDecisionSha256()
      ) {
        throw new PaidMediaLegacyMigrationUnavailableError()
      }
      return {
        state: 'closed',
        closedAt: document.closedAt,
        decision: { kind: 'empty', decisionSha256: decision.decisionSha256 }
      }
    }
    if (
      !exactKeys(decision, ['kind', 'decisionSha256', 'candidate']) ||
      decision.kind !== 'candidate' ||
      typeof decision.decisionSha256 !== 'string' ||
      !SHA256_PATTERN.test(decision.decisionSha256) ||
      !decision.candidate ||
      typeof decision.candidate !== 'object' ||
      Array.isArray(decision.candidate)
    ) {
      throw new PaidMediaLegacyMigrationUnavailableError()
    }
    const storedCandidate = decision.candidate as Record<string, unknown>
    const hasRetryAfter = Object.prototype.hasOwnProperty.call(
      storedCandidate,
      'retryAfterSeconds'
    )
    const candidateKeys = [
      'operationId',
      'path',
      'requestSha256',
      'createdAt',
      'updatedAt',
      'state',
      ...(storedCandidate.state === 'recoverable' ? ['lastStatus'] : []),
      ...(hasRetryAfter ? ['retryAfterSeconds'] : []),
      'candidateSha256'
    ]
    if (
      !exactKeys(storedCandidate, candidateKeys) ||
      typeof storedCandidate.candidateSha256 !== 'string' ||
      !SHA256_PATTERN.test(storedCandidate.candidateSha256)
    ) {
      throw new PaidMediaLegacyMigrationUnavailableError()
    }
    const candidateInput = { ...storedCandidate }
    delete candidateInput.candidateSha256
    let candidate: PaidMediaLegacyCandidateSummary
    try {
      candidate = summarizeCandidate(
        candidateInput as unknown as PaidMediaLegacyCandidate,
        this.dependencies.now()
      )
    } catch (error) {
      throw new PaidMediaLegacyMigrationUnavailableError(undefined, { cause: error })
    }
    if (
      candidate.candidateSha256 !== storedCandidate.candidateSha256 ||
      candidateDecisionSha256(candidate.candidateSha256) !== decision.decisionSha256
    ) {
      throw new PaidMediaLegacyMigrationUnavailableError()
    }
    return {
      state: 'closed',
      closedAt: document.closedAt,
      decision: {
        kind: 'candidate',
        decisionSha256: decision.decisionSha256,
        candidate
      }
    }
  }

  async provisionOpen(): Promise<PaidMediaLegacySealOpenStatus> {
    const document = { schema: DOCUMENT_SCHEMA, state: 'open' }
    this.dependencies.atomicIO.writeUtf8AtomicNew(
      this.path,
      this.encode(document),
      this.dependencies.harden
    )
    return { state: 'open' }
  }

  async close(
    input: PaidMediaLegacySealDecision
  ): Promise<PaidMediaLegacySealClosedStatus> {
    return serializedForSealPath(this.path, () => this.closeSerialized(input))
  }

  private async closeSerialized(
    input: PaidMediaLegacySealDecision
  ): Promise<PaidMediaLegacySealClosedStatus> {
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
      throw new PaidMediaLegacySealError('Legacy paid media seal decision is invalid')
    }
    const rawInput = input as unknown as Record<string, unknown>
    const empty = input.kind === 'empty'
    if (
      (empty && !exactKeys(rawInput, ['kind'])) ||
      (!empty &&
        (!exactKeys(rawInput, ['kind', 'candidate']) || input.kind !== 'candidate'))
    ) {
      throw new PaidMediaLegacySealError('Legacy paid media seal decision is invalid')
    }
    const candidate = input.kind === 'candidate' ? this.summarizeCandidate(input.candidate) : null
    const previous = await this.inspect()
    if (previous.state === 'closed') {
      if (input.kind === 'empty' && previous.decision.kind === 'empty') return previous
      if (
        candidate &&
        previous.decision.kind === 'candidate' &&
        previous.decision.candidate.candidateSha256 === candidate.candidateSha256
      ) {
        return previous
      }
      throw new PaidMediaLegacySealError('Legacy paid media migration is already closed')
    }
    const closedAt = this.dependencies.now()
    if (!safeInteger(closedAt)) throw new PaidMediaLegacyMigrationUnavailableError()
    const status: PaidMediaLegacySealClosedStatus = candidate
      ? {
          state: 'closed',
          closedAt,
          decision: {
            kind: 'candidate',
            decisionSha256: candidateDecisionSha256(candidate.candidateSha256),
            candidate
          }
        }
      : {
          state: 'closed',
          closedAt,
          decision: { kind: 'empty', decisionSha256: emptyDecisionSha256() }
        }
    this.dependencies.atomicIO.writeUtf8AtomicReplace(
      this.path,
      this.encode({ schema: DOCUMENT_SCHEMA, ...status }),
      this.dependencies.harden
    )
    return status
  }

  async inspect(): Promise<PaidMediaLegacySealStatus> {
    this.requireEncryption()
    const raw = this.dependencies.atomicIO.readUtf8(
      this.path,
      MAX_SEAL_BYTES,
      this.dependencies.harden
    )
    if (raw === null) throw new PaidMediaLegacyMigrationUnavailableError()
    return this.decode(raw)
  }
}
