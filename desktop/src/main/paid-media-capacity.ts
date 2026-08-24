import { createHash, randomBytes } from 'node:crypto'
import { resolve } from 'node:path'

import type {
  PaidMediaAclHardener,
  PaidMediaAtomicIO,
  PaidMediaPath,
  PaidMediaSafeStorage
} from './paid-media-ledger'

const OPERATION_ID_PATTERN = /^desktop-op-[0-9a-f-]{36}$/i
const SHA256_PATTERN = /^[0-9a-f]{64}$/
const ENVELOPE_SCHEMA = 'nachuan.paid-media-capacity.slot.envelope.v2'
const ANCHOR_ENVELOPE_SCHEMA = 'nachuan.paid-media-capacity.anchor.envelope.v2'
const DOCUMENT_SCHEMA = 'nachuan.paid-media-capacity.journal.v2'
const ANCHOR_SCHEMA = 'nachuan.paid-media-capacity.anchor.v2'
const RESERVATION_SCHEMA = 'nachuan.paid-media-capacity.reservation.v1'
const RELEASE_TOMBSTONE_SCHEMA = 'nachuan.paid-media-capacity.release-tombstone.v1'
export const PAID_MEDIA_CAPACITY_BUDGET_POLICY = 'nachuan.paid-media-capacity-budget.v1'
const MAX_JOURNAL_BYTES = 4 * 1024 * 1024
const MAX_ANCHOR_BYTES = 64 * 1024
const MAX_RESERVATIONS = 4096
const MAX_JOURNAL_RECORDS = 16_384
const AUTHORITY_EVIDENCE_DOMAIN = 'nachuan.desktop.paid-media-capacity-evidence.v1\0'
const CAPTURE_READ_ONLY_HARDENER: PaidMediaAclHardener = () => undefined

export const PAID_MEDIA_IMAGE_CAPACITY_BYTES = 512n * 1024n * 1024n
export const PAID_MEDIA_VIDEO_CAPACITY_BYTES = 2n * 1024n * 1024n * 1024n
export const PAID_MEDIA_CAPACITY_FREE_FLOOR_BYTES = 512n * 1024n * 1024n

export interface PaidMediaCapacityVolume {
  volumeId: string
  root: string
}

export interface PaidMediaCapacityDependencies {
  safeStorage: PaidMediaSafeStorage
  harden: PaidMediaAclHardener
  now: () => number
  atomicIO: PaidMediaAtomicIO
  tempRoot: () => string
  probeSpoolRoot: () => string
  resolveVolume: (path: string) => PaidMediaCapacityVolume
  freeBytes: (root: string) => bigint
}

export type PaidMediaCapacityRole = 'vault' | 'desktop_staging' | 'probe_spool'

export interface PaidMediaCapacityRoleBudget {
  role: PaidMediaCapacityRole
  volumeId: string
  root: string
  bytes: bigint
}

export interface PaidMediaCapacityReservation {
  operationId: string
  path: PaidMediaPath
  phase: 'active' | 'video_bound' | 'released'
  budgetPolicy: typeof PAID_MEDIA_CAPACITY_BUDGET_POLICY
  roleBudgets: PaidMediaCapacityRoleBudget[]
  perVolume: Array<{
    volumeId: string
    root: string
    bytes: bigint
  }>
  createdAt: number
  updatedAt: number
  taskAliasSha256?: string
}

export interface PaidMediaCapacityAuthorityEvidence {
  capacityIdentity: string
  capacitySequence: number
  capacityStateDigest: string
}

export type PaidMediaCapacityCaptureArtifactRole =
  | 'desktop_capacity_anchor'
  | 'desktop_capacity_active_slot'

export interface PaidMediaCapacityCaptureArtifact {
  role: PaidMediaCapacityCaptureArtifactRole
  path: string
  byteLength: number
  sha256: string
}

export interface PaidMediaCapacityCaptureEvidence extends PaidMediaCapacityAuthorityEvidence {
  activeSlot: CapacityJournalSlot
  documentSha256: string
  artifacts: readonly Readonly<PaidMediaCapacityCaptureArtifact>[]
  externalClosureRequired: Readonly<{
    writerFence: true
    pinnedFileHandles: true
    stagingAclProof: true
  }>
}

export interface PaidMediaCapacityReleaseTombstone {
  operationId: string
  authorizationReceiptSha256: string
  releasedAt: number
  releasedReservationSha256: string | null
}

export class PaidMediaCapacityError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options)
    this.name = 'PaidMediaCapacityError'
  }
}

interface StoredCapacityVolume {
  volumeId: string
  root: string
  bytes: string
}

interface StoredCapacityRoleBudget extends StoredCapacityVolume {
  role: PaidMediaCapacityRole
}

interface StoredCapacityReservationBase {
  schema: typeof RESERVATION_SCHEMA
  operationId: string
  path: PaidMediaPath
  phase: PaidMediaCapacityReservation['phase']
  budgetPolicy: typeof PAID_MEDIA_CAPACITY_BUDGET_POLICY
  roleBudgets: StoredCapacityRoleBudget[]
  perVolume: StoredCapacityVolume[]
  createdAt: number
  updatedAt: number
  taskAliasSha256: string | null
}

interface StoredCapacityReservation extends StoredCapacityReservationBase {
  reservationSha256: string
}

interface StoredCapacityReleaseTombstoneBase {
  schema: typeof RELEASE_TOMBSTONE_SCHEMA
  operationId: string
  authorizationReceiptSha256: string
  releasedAt: number
  releasedReservationSha256: string | null
}

interface StoredCapacityReleaseTombstone extends StoredCapacityReleaseTombstoneBase {
  releaseTombstoneSha256: string
}

type StoredCapacityRecord = StoredCapacityReservation | StoredCapacityReleaseTombstone

interface CapacityJournalDocument {
  schema: typeof DOCUMENT_SCHEMA
  journalIdentity: string
  sequence: number
  records: StoredCapacityRecord[]
}

interface CapacityAnchorDocument {
  schema: typeof ANCHOR_SCHEMA
  journalIdentity: string
  activeSlot: CapacityJournalSlot
  sequence: number
  documentSha256: string
}

export type CapacityJournalSlot = 'a' | 'b'

interface CapacityJournalState {
  activeSlot: CapacityJournalSlot | null
  document: CapacityJournalDocument
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort()
  const wanted = [...expected].sort()
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index])
}

function sha256(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex')
}

function validPath(value: unknown): value is PaidMediaPath {
  return value === '/v1/images/generations' || value === '/v1/videos/generations'
}

function isStoredReservation(value: StoredCapacityRecord): value is StoredCapacityReservation {
  return value.schema === RESERVATION_SCHEMA
}

function isStoredReleaseTombstone(
  value: StoredCapacityRecord
): value is StoredCapacityReleaseTombstone {
  return value.schema === RELEASE_TOMBSTONE_SCHEMA
}

function requireSafeTime(value: number): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new PaidMediaCapacityError('Paid media capacity clock is invalid')
  }
  return value
}

function nextSequence(value: number): number {
  if (!Number.isSafeInteger(value) || value < 0 || value >= Number.MAX_SAFE_INTEGER) {
    throw new PaidMediaCapacityError('Paid media capacity sequence is exhausted')
  }
  return value + 1
}

function roleCapacityBudget(path: PaidMediaPath, role: PaidMediaCapacityRole): bigint {
  if (path === '/v1/videos/generations') {
    return role === 'vault'
      ? PAID_MEDIA_VIDEO_CAPACITY_BYTES / 2n
      : PAID_MEDIA_VIDEO_CAPACITY_BYTES / 4n
  }
  if (role === 'vault') return PAID_MEDIA_IMAGE_CAPACITY_BYTES / 2n
  return role === 'desktop_staging'
    ? (PAID_MEDIA_IMAGE_CAPACITY_BYTES * 3n) / 8n
    : PAID_MEDIA_IMAGE_CAPACITY_BYTES / 8n
}

class CapacityPathMutex {
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

const capacityPathMutexes = new Map<string, CapacityPathMutex>()

async function serializedForCapacityPath<T>(
  path: string,
  action: () => T | Promise<T>
): Promise<T> {
  const key = process.platform === 'win32' ? resolve(path).toLowerCase() : resolve(path)
  const mutex = capacityPathMutexes.get(key) ?? new CapacityPathMutex()
  capacityPathMutexes.set(key, mutex)
  try {
    return await mutex.run(action)
  } finally {
    if (mutex.idle && capacityPathMutexes.get(key) === mutex) capacityPathMutexes.delete(key)
  }
}

export class PaidMediaCapacityManager {
  private mutationGuard: (() => void) | null = null

  constructor(
    private readonly journalPath: string,
    private readonly vaultRoot: string,
    private readonly dependencies: PaidMediaCapacityDependencies
  ) {
    if (!resolve(journalPath) || !resolve(vaultRoot)) {
      throw new PaidMediaCapacityError('Paid media capacity paths are invalid')
    }
  }

  private get anchorPath(): string {
    return `${this.journalPath}.anchor`
  }

  setMutationGuard(guard: () => void): void {
    if (typeof guard !== 'function') {
      throw new PaidMediaCapacityError('Paid media capacity mutation guard is invalid')
    }
    if (this.mutationGuard !== null && this.mutationGuard !== guard) {
      throw new PaidMediaCapacityError('Paid media capacity mutation guard is already attached')
    }
    this.mutationGuard = guard
  }

  private assertMutationAllowed(): void {
    this.mutationGuard?.()
  }

  private slotPath(slot: CapacityJournalSlot): string {
    return `${this.journalPath}.slot-${slot}`
  }

  private encodeEnvelope(
    value: unknown,
    schema: typeof ENVELOPE_SCHEMA | typeof ANCHOR_ENVELOPE_SCHEMA,
    maxBytes: number
  ): string {
    if (!this.dependencies.safeStorage.isEncryptionAvailable()) {
      throw new PaidMediaCapacityError('OS-backed paid media capacity encryption is unavailable')
    }
    const plaintext = JSON.stringify(value)
    if (Buffer.byteLength(plaintext, 'utf8') > maxBytes) {
      throw new PaidMediaCapacityError('Paid media capacity journal exceeds its size limit')
    }
    const ciphertext = this.dependencies.safeStorage.encryptString(plaintext)
    if (!Buffer.isBuffer(ciphertext) || ciphertext.length < 1) {
      throw new PaidMediaCapacityError('Paid media capacity encryption failed')
    }
    return JSON.stringify({
      schema,
      protection: 'electron-safe-storage',
      ciphertext: ciphertext.toString('base64')
    })
  }

  private decodeEnvelope(raw: string, schema: string, maxBytes: number): Record<string, unknown> {
    let envelope: unknown
    try {
      envelope = JSON.parse(raw)
    } catch (error) {
      throw new PaidMediaCapacityError('Paid media capacity envelope is corrupt', { cause: error })
    }
    if (
      !envelope ||
      typeof envelope !== 'object' ||
      Array.isArray(envelope) ||
      !exactKeys(envelope as Record<string, unknown>, ['schema', 'protection', 'ciphertext']) ||
      (envelope as Record<string, unknown>).schema !== schema ||
      (envelope as Record<string, unknown>).protection !== 'electron-safe-storage' ||
      typeof (envelope as Record<string, unknown>).ciphertext !== 'string'
    ) {
      throw new PaidMediaCapacityError('Paid media capacity envelope is invalid')
    }
    let plaintext: string
    try {
      const encoded = (envelope as Record<string, unknown>).ciphertext as string
      const bytes = Buffer.from(encoded, 'base64')
      if (bytes.length < 1 || bytes.toString('base64') !== encoded) throw new Error('invalid base64')
      plaintext = this.dependencies.safeStorage.decryptString(bytes)
    } catch (error) {
      throw new PaidMediaCapacityError('Paid media capacity decryption failed', { cause: error })
    }
    if (Buffer.byteLength(plaintext, 'utf8') > maxBytes) {
      throw new PaidMediaCapacityError('Paid media capacity plaintext exceeds its size limit')
    }
    let value: unknown
    try {
      value = JSON.parse(plaintext)
    } catch (error) {
      throw new PaidMediaCapacityError('Paid media capacity plaintext is corrupt', { cause: error })
    }
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      throw new PaidMediaCapacityError('Paid media capacity plaintext is invalid')
    }
    return value as Record<string, unknown>
  }

  private parseStoredReservation(value: unknown): StoredCapacityReservation {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      throw new PaidMediaCapacityError('Paid media capacity reservation is invalid')
    }
    const raw = value as Record<string, unknown>
    if (
      !exactKeys(raw, [
        'schema',
        'operationId',
        'path',
        'phase',
        'budgetPolicy',
        'roleBudgets',
        'perVolume',
        'createdAt',
        'updatedAt',
        'taskAliasSha256',
        'reservationSha256'
      ]) ||
      raw.schema !== RESERVATION_SCHEMA ||
      typeof raw.operationId !== 'string' ||
      !OPERATION_ID_PATTERN.test(raw.operationId) ||
      !validPath(raw.path) ||
      !['active', 'video_bound', 'released'].includes(String(raw.phase)) ||
      raw.budgetPolicy !== PAID_MEDIA_CAPACITY_BUDGET_POLICY ||
      !Array.isArray(raw.roleBudgets) ||
      raw.roleBudgets.length !== 3 ||
      !Array.isArray(raw.perVolume) ||
      raw.perVolume.length < 1 ||
      raw.perVolume.length > 3 ||
      !Number.isSafeInteger(raw.createdAt) ||
      Number(raw.createdAt) < 0 ||
      !Number.isSafeInteger(raw.updatedAt) ||
      Number(raw.updatedAt) < Number(raw.createdAt) ||
      (raw.taskAliasSha256 !== null &&
        (typeof raw.taskAliasSha256 !== 'string' || !SHA256_PATTERN.test(raw.taskAliasSha256))) ||
      typeof raw.reservationSha256 !== 'string' ||
      !SHA256_PATTERN.test(raw.reservationSha256)
    ) {
      throw new PaidMediaCapacityError('Paid media capacity reservation is invalid')
    }
    const perVolume = raw.perVolume.map((item) => {
      if (!item || typeof item !== 'object' || Array.isArray(item)) {
        throw new PaidMediaCapacityError('Paid media capacity volume is invalid')
      }
      const volume = item as Record<string, unknown>
      if (
        !exactKeys(volume, ['volumeId', 'root', 'bytes']) ||
        typeof volume.volumeId !== 'string' ||
        volume.volumeId.length < 1 ||
        volume.volumeId.length > 256 ||
        typeof volume.root !== 'string' ||
        volume.root.length < 1 ||
        volume.root.length > 4096 ||
        typeof volume.bytes !== 'string' ||
        !/^[1-9][0-9]{0,19}$/.test(volume.bytes)
      ) {
        throw new PaidMediaCapacityError('Paid media capacity volume is invalid')
      }
      return {
        volumeId: volume.volumeId,
        root: volume.root,
        bytes: volume.bytes
      }
    })
    if (new Set(perVolume.map((volume) => volume.volumeId)).size !== perVolume.length) {
      throw new PaidMediaCapacityError('Paid media capacity volumes are duplicated')
    }
    const roleBudgets = raw.roleBudgets.map((item) => {
      if (!item || typeof item !== 'object' || Array.isArray(item)) {
        throw new PaidMediaCapacityError('Paid media capacity role budget is invalid')
      }
      const roleBudget = item as Record<string, unknown>
      if (
        !exactKeys(roleBudget, ['role', 'volumeId', 'root', 'bytes']) ||
        !['vault', 'desktop_staging', 'probe_spool'].includes(String(roleBudget.role)) ||
        typeof roleBudget.volumeId !== 'string' ||
        roleBudget.volumeId.length < 1 ||
        roleBudget.volumeId.length > 256 ||
        typeof roleBudget.root !== 'string' ||
        roleBudget.root.length < 1 ||
        roleBudget.root.length > 4096 ||
        typeof roleBudget.bytes !== 'string' ||
        !/^[1-9][0-9]{0,19}$/.test(roleBudget.bytes)
      ) {
        throw new PaidMediaCapacityError('Paid media capacity role budget is invalid')
      }
      const role = roleBudget.role as PaidMediaCapacityRole
      if (BigInt(roleBudget.bytes) !== roleCapacityBudget(raw.path as PaidMediaPath, role)) {
        throw new PaidMediaCapacityError('Paid media capacity role budget conflicts with policy')
      }
      return {
        role,
        volumeId: roleBudget.volumeId,
        root: roleBudget.root,
        bytes: roleBudget.bytes
      }
    })
    if (
      new Set(roleBudgets.map((roleBudget) => roleBudget.role)).size !== 3 ||
      roleBudgets[0].role !== 'vault' ||
      roleBudgets[1].role !== 'desktop_staging' ||
      roleBudgets[2].role !== 'probe_spool'
    ) {
      throw new PaidMediaCapacityError('Paid media capacity role budgets are invalid')
    }
    const aggregated = new Map<string, StoredCapacityVolume>()
    for (const roleBudget of roleBudgets) {
      const current = aggregated.get(roleBudget.volumeId)
      if (current && current.root !== roleBudget.root) {
        throw new PaidMediaCapacityError('Paid media capacity volume roots conflict')
      }
      aggregated.set(roleBudget.volumeId, {
        volumeId: roleBudget.volumeId,
        root: roleBudget.root,
        bytes: (BigInt(current?.bytes ?? '0') + BigInt(roleBudget.bytes)).toString(10)
      })
    }
    if (JSON.stringify([...aggregated.values()]) !== JSON.stringify(perVolume)) {
      throw new PaidMediaCapacityError('Paid media capacity volume budget does not match roles')
    }
    const base: StoredCapacityReservationBase = {
      schema: RESERVATION_SCHEMA,
      operationId: raw.operationId,
      path: raw.path,
      phase: raw.phase as PaidMediaCapacityReservation['phase'],
      budgetPolicy: PAID_MEDIA_CAPACITY_BUDGET_POLICY,
      roleBudgets,
      perVolume,
      createdAt: raw.createdAt as number,
      updatedAt: raw.updatedAt as number,
      taskAliasSha256: raw.taskAliasSha256 as string | null
    }
    if (sha256(JSON.stringify(base)) !== raw.reservationSha256) {
      throw new PaidMediaCapacityError('Paid media capacity reservation digest does not match')
    }
    return { ...base, reservationSha256: raw.reservationSha256 }
  }

  private parseStoredReleaseTombstone(value: unknown): StoredCapacityReleaseTombstone {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      throw new PaidMediaCapacityError('Paid media capacity release tombstone is invalid')
    }
    const raw = value as Record<string, unknown>
    if (
      !exactKeys(raw, [
        'schema',
        'operationId',
        'authorizationReceiptSha256',
        'releasedAt',
        'releasedReservationSha256',
        'releaseTombstoneSha256'
      ]) ||
      raw.schema !== RELEASE_TOMBSTONE_SCHEMA ||
      typeof raw.operationId !== 'string' ||
      !OPERATION_ID_PATTERN.test(raw.operationId) ||
      typeof raw.authorizationReceiptSha256 !== 'string' ||
      !SHA256_PATTERN.test(raw.authorizationReceiptSha256) ||
      /^0{64}$/.test(raw.authorizationReceiptSha256) ||
      !Number.isSafeInteger(raw.releasedAt) ||
      Number(raw.releasedAt) < 0 ||
      (raw.releasedReservationSha256 !== null &&
        (typeof raw.releasedReservationSha256 !== 'string' ||
          !SHA256_PATTERN.test(raw.releasedReservationSha256))) ||
      typeof raw.releaseTombstoneSha256 !== 'string' ||
      !SHA256_PATTERN.test(raw.releaseTombstoneSha256)
    ) {
      throw new PaidMediaCapacityError('Paid media capacity release tombstone is invalid')
    }
    const base: StoredCapacityReleaseTombstoneBase = {
      schema: RELEASE_TOMBSTONE_SCHEMA,
      operationId: raw.operationId,
      authorizationReceiptSha256: raw.authorizationReceiptSha256,
      releasedAt: raw.releasedAt as number,
      releasedReservationSha256: raw.releasedReservationSha256 as string | null
    }
    if (sha256(JSON.stringify(base)) !== raw.releaseTombstoneSha256) {
      throw new PaidMediaCapacityError('Paid media capacity release tombstone digest does not match')
    }
    return { ...base, releaseTombstoneSha256: raw.releaseTombstoneSha256 }
  }

  private parseStoredRecord(value: unknown): StoredCapacityRecord {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      throw new PaidMediaCapacityError('Paid media capacity record is invalid')
    }
    const schema = (value as Record<string, unknown>).schema
    if (schema === RESERVATION_SCHEMA) return this.parseStoredReservation(value)
    if (schema === RELEASE_TOMBSTONE_SCHEMA) return this.parseStoredReleaseTombstone(value)
    throw new PaidMediaCapacityError('Paid media capacity record schema is invalid')
  }

  private parseAnchor(raw: string): CapacityAnchorDocument {
    const value = this.decodeEnvelope(raw, ANCHOR_ENVELOPE_SCHEMA, MAX_ANCHOR_BYTES)
    if (
      !exactKeys(value, [
        'schema',
        'journalIdentity',
        'activeSlot',
        'sequence',
        'documentSha256'
      ]) ||
      value.schema !== ANCHOR_SCHEMA ||
      typeof value.journalIdentity !== 'string' ||
      !SHA256_PATTERN.test(value.journalIdentity) ||
      !['a', 'b'].includes(String(value.activeSlot)) ||
      !Number.isSafeInteger(value.sequence) ||
      Number(value.sequence) < 1 ||
      typeof value.documentSha256 !== 'string' ||
      !SHA256_PATTERN.test(value.documentSha256)
    ) {
      throw new PaidMediaCapacityError('Paid media capacity anchor is invalid')
    }
    return value as unknown as CapacityAnchorDocument
  }

  private readAnchor(): CapacityAnchorDocument | null {
    const raw = this.dependencies.atomicIO.readUtf8(
      this.anchorPath,
      MAX_ANCHOR_BYTES,
      this.dependencies.harden
    )
    return raw === null ? null : this.parseAnchor(raw)
  }

  private parseDocument(value: Record<string, unknown>): CapacityJournalDocument {
    if (
      !exactKeys(value, ['schema', 'journalIdentity', 'sequence', 'records']) ||
      value.schema !== DOCUMENT_SCHEMA ||
      typeof value.journalIdentity !== 'string' ||
      !SHA256_PATTERN.test(value.journalIdentity) ||
      !Number.isSafeInteger(value.sequence) ||
      Number(value.sequence) < 1 ||
      !Array.isArray(value.records) ||
      value.records.length > MAX_JOURNAL_RECORDS
    ) {
      throw new PaidMediaCapacityError('Paid media capacity journal is invalid')
    }
    const records = value.records.map((record) => this.parseStoredRecord(record))
    if (new Set(records.map((record) => record.operationId)).size !== records.length) {
      throw new PaidMediaCapacityError('Paid media capacity journal has duplicate operations')
    }
    return {
      schema: DOCUMENT_SCHEMA,
      journalIdentity: value.journalIdentity,
      sequence: value.sequence as number,
      records
    }
  }

  private readSlot(slot: CapacityJournalSlot): CapacityJournalDocument {
    const raw = this.dependencies.atomicIO.readUtf8(
      this.slotPath(slot),
      MAX_JOURNAL_BYTES,
      this.dependencies.harden
    )
    if (raw === null) {
      throw new PaidMediaCapacityError('Paid media capacity active journal slot is missing')
    }
    return this.parseSlot(raw)
  }

  private parseSlot(raw: string): CapacityJournalDocument {
    return this.parseDocument(this.decodeEnvelope(raw, ENVELOPE_SCHEMA, MAX_JOURNAL_BYTES))
  }

  private readDocument(): CapacityJournalState {
    const anchor = this.readAnchor()
    if (anchor === null) {
      return {
        activeSlot: null,
        document: {
          schema: DOCUMENT_SCHEMA,
          journalIdentity: randomBytes(32).toString('hex'),
          sequence: 0,
          records: []
        }
      }
    }
    const document = this.readSlot(anchor.activeSlot)
    if (
      document.journalIdentity !== anchor.journalIdentity ||
      document.sequence !== anchor.sequence ||
      sha256(JSON.stringify(document)) !== anchor.documentSha256
    ) {
      throw new PaidMediaCapacityError('Paid media capacity anchor does not match its active slot')
    }
    return { activeSlot: anchor.activeSlot, document }
  }

  private writeDocument(
    previous: CapacityJournalState,
    document: CapacityJournalDocument
  ): void {
    this.assertMutationAllowed()
    if (
      document.journalIdentity !== previous.document.journalIdentity ||
      document.sequence !== nextSequence(previous.document.sequence)
    ) {
      throw new PaidMediaCapacityError('Paid media capacity journal transition is invalid')
    }
    const inactiveSlot: CapacityJournalSlot = previous.activeSlot === 'a' ? 'b' : 'a'
    this.dependencies.atomicIO.writeUtf8Atomic(
      this.slotPath(inactiveSlot),
      this.encodeEnvelope(document, ENVELOPE_SCHEMA, MAX_JOURNAL_BYTES),
      this.dependencies.harden
    )
    const staged = this.readSlot(inactiveSlot)
    const documentSha256 = sha256(JSON.stringify(document))
    if (
      JSON.stringify(staged) !== JSON.stringify(document) ||
      sha256(JSON.stringify(staged)) !== documentSha256
    ) {
      throw new PaidMediaCapacityError('Paid media capacity inactive slot verification failed')
    }
    const anchor: CapacityAnchorDocument = {
      schema: ANCHOR_SCHEMA,
      journalIdentity: document.journalIdentity,
      activeSlot: inactiveSlot,
      sequence: document.sequence,
      documentSha256
    }
    this.dependencies.atomicIO.writeUtf8Atomic(
      this.anchorPath,
      this.encodeEnvelope(anchor, ANCHOR_ENVELOPE_SCHEMA, MAX_ANCHOR_BYTES),
      this.dependencies.harden
    )
  }

  private authorityEvidenceForDocument(
    document: CapacityJournalDocument
  ): PaidMediaCapacityAuthorityEvidence {
    return Object.freeze({
      capacityIdentity: document.journalIdentity,
      capacitySequence: document.sequence,
      capacityStateDigest: createHash('sha256')
        .update(AUTHORITY_EVIDENCE_DOMAIN, 'utf8')
        .update(JSON.stringify(document), 'utf8')
        .digest('hex')
    })
  }

  async provisionAuthorityJournal(): Promise<PaidMediaCapacityAuthorityEvidence> {
    return serializedForCapacityPath(this.journalPath, () => {
      const state = this.readDocument()
      if (state.activeSlot === null) {
        const document: CapacityJournalDocument = {
          schema: DOCUMENT_SCHEMA,
          journalIdentity: state.document.journalIdentity,
          sequence: 1,
          records: []
        }
        this.writeDocument(state, document)
      }
      return this.authorityEvidenceForDocument(this.readDocument().document)
    })
  }

  async inspectAuthorityEvidence(): Promise<PaidMediaCapacityAuthorityEvidence> {
    return serializedForCapacityPath(this.journalPath, () => {
      const state = this.readDocument()
      if (state.activeSlot === null) {
        throw new PaidMediaCapacityError('Paid media capacity authority evidence is missing')
      }
      return this.authorityEvidenceForDocument(state.document)
    })
  }

  async inspectCaptureEvidence(): Promise<PaidMediaCapacityCaptureEvidence> {
    return serializedForCapacityPath(this.journalPath, () => {
      if (!this.dependencies.safeStorage.isEncryptionAvailable()) {
        throw new PaidMediaCapacityError('OS-backed paid media capacity encryption is unavailable')
      }
      const anchorPath = resolve(this.anchorPath)
      const anchorRaw = this.dependencies.atomicIO.readUtf8(
        anchorPath,
        MAX_ANCHOR_BYTES,
        CAPTURE_READ_ONLY_HARDENER
      )
      if (anchorRaw === null) {
        throw new PaidMediaCapacityError('Paid media capacity capture anchor is missing')
      }
      const anchor = this.parseAnchor(anchorRaw)
      const activeSlotPath = resolve(this.slotPath(anchor.activeSlot))
      const activeSlotRaw = this.dependencies.atomicIO.readUtf8(
        activeSlotPath,
        MAX_JOURNAL_BYTES,
        CAPTURE_READ_ONLY_HARDENER
      )
      if (activeSlotRaw === null) {
        throw new PaidMediaCapacityError('Paid media capacity capture active slot is missing')
      }
      const document = this.parseSlot(activeSlotRaw)
      if (
        document.journalIdentity !== anchor.journalIdentity ||
        document.sequence !== anchor.sequence ||
        sha256(JSON.stringify(document)) !== anchor.documentSha256
      ) {
        throw new PaidMediaCapacityError(
          'Paid media capacity capture anchor does not match its active slot'
        )
      }
      const inactiveSlot: CapacityJournalSlot = anchor.activeSlot === 'a' ? 'b' : 'a'
      const inactiveSlotRaw = this.dependencies.atomicIO.readUtf8(
        resolve(this.slotPath(inactiveSlot)),
        MAX_JOURNAL_BYTES,
        CAPTURE_READ_ONLY_HARDENER
      )
      if (inactiveSlotRaw !== null) {
        let inactiveDocument: CapacityJournalDocument
        try {
          inactiveDocument = this.parseSlot(inactiveSlotRaw)
        } catch (error) {
          throw new PaidMediaCapacityError(
            'Paid media capacity capture inactive slot is ambiguous',
            { cause: error }
          )
        }
        if (
          inactiveDocument.journalIdentity !== document.journalIdentity ||
          inactiveDocument.sequence !== document.sequence - 1
        ) {
          throw new PaidMediaCapacityError(
            'Paid media capacity capture inactive slot contains an uncommitted or ambiguous publication'
          )
        }
      }
      const finalAnchorRaw = this.dependencies.atomicIO.readUtf8(
        anchorPath,
        MAX_ANCHOR_BYTES,
        CAPTURE_READ_ONLY_HARDENER
      )
      const finalActiveSlotRaw = this.dependencies.atomicIO.readUtf8(
        activeSlotPath,
        MAX_JOURNAL_BYTES,
        CAPTURE_READ_ONLY_HARDENER
      )
      const finalInactiveSlotRaw = this.dependencies.atomicIO.readUtf8(
        resolve(this.slotPath(inactiveSlot)),
        MAX_JOURNAL_BYTES,
        CAPTURE_READ_ONLY_HARDENER
      )
      if (
        finalAnchorRaw !== anchorRaw ||
        finalActiveSlotRaw !== activeSlotRaw ||
        finalInactiveSlotRaw !== inactiveSlotRaw
      ) {
        throw new PaidMediaCapacityError(
          'Paid media capacity capture bytes changed during inspection'
        )
      }
      const authority = this.authorityEvidenceForDocument(document)
      const artifacts = Object.freeze([
        Object.freeze({
          role: 'desktop_capacity_anchor' as const,
          path: anchorPath,
          byteLength: Buffer.byteLength(anchorRaw, 'utf8'),
          sha256: sha256(anchorRaw)
        }),
        Object.freeze({
          role: 'desktop_capacity_active_slot' as const,
          path: activeSlotPath,
          byteLength: Buffer.byteLength(activeSlotRaw, 'utf8'),
          sha256: sha256(activeSlotRaw)
        })
      ])
      return Object.freeze({
        activeSlot: anchor.activeSlot,
        ...authority,
        documentSha256: anchor.documentSha256,
        artifacts,
        externalClosureRequired: Object.freeze({
          writerFence: true as const,
          pinnedFileHandles: true as const,
          stagingAclProof: true as const
        })
      })
    })
  }

  private publicReservation(value: StoredCapacityReservation): PaidMediaCapacityReservation {
    return {
      operationId: value.operationId,
      path: value.path,
      phase: value.phase,
      budgetPolicy: value.budgetPolicy,
      roleBudgets: value.roleBudgets.map((roleBudget) => ({
        role: roleBudget.role,
        volumeId: roleBudget.volumeId,
        root: roleBudget.root,
        bytes: BigInt(roleBudget.bytes)
      })),
      perVolume: value.perVolume.map((volume) => ({
        volumeId: volume.volumeId,
        root: volume.root,
        bytes: BigInt(volume.bytes)
      })),
      createdAt: value.createdAt,
      updatedAt: value.updatedAt,
      ...(value.taskAliasSha256 === null ? {} : { taskAliasSha256: value.taskAliasSha256 })
    }
  }

  private publicReleaseTombstone(
    value: StoredCapacityReleaseTombstone
  ): PaidMediaCapacityReleaseTombstone {
    return Object.freeze({
      operationId: value.operationId,
      authorizationReceiptSha256: value.authorizationReceiptSha256,
      releasedAt: value.releasedAt,
      releasedReservationSha256: value.releasedReservationSha256
    })
  }

  private plan(path: PaidMediaPath): {
    roleBudgets: PaidMediaCapacityRoleBudget[]
    perVolume: PaidMediaCapacityReservation['perVolume']
  } {
    const roleInputs: Array<{ role: PaidMediaCapacityRole; path: string }> = [
      { role: 'vault', path: this.vaultRoot },
      { role: 'desktop_staging', path: this.dependencies.tempRoot() },
      { role: 'probe_spool', path: this.dependencies.probeSpoolRoot() }
    ]
    const roleBudgets = roleInputs.map(({ role, path: rolePath }) => {
      const volume = this.dependencies.resolveVolume(rolePath)
      if (
        !volume ||
        typeof volume !== 'object' ||
        typeof volume.volumeId !== 'string' ||
        volume.volumeId.length < 1 ||
        volume.volumeId.length > 256 ||
        typeof volume.root !== 'string' ||
        volume.root.length < 1 ||
        volume.root.length > 4096
      ) {
        throw new PaidMediaCapacityError('Paid media capacity volume resolution failed')
      }
      return {
        role,
        volumeId: volume.volumeId,
        root: volume.root,
        bytes: roleCapacityBudget(path, role)
      }
    })
    const aggregated = new Map<string, PaidMediaCapacityReservation['perVolume'][number]>()
    for (const roleBudget of roleBudgets) {
      const current = aggregated.get(roleBudget.volumeId)
      if (current && current.root !== roleBudget.root) {
        throw new PaidMediaCapacityError('Paid media capacity volume roots conflict')
      }
      aggregated.set(roleBudget.volumeId, {
        volumeId: roleBudget.volumeId,
        root: roleBudget.root,
        bytes: (current?.bytes ?? 0n) + roleBudget.bytes
      })
    }
    return { roleBudgets, perVolume: [...aggregated.values()] }
  }

  private activeBytes(document: CapacityJournalDocument, volumeId: string): bigint {
    return document.records
      .filter(isStoredReservation)
      .filter((reservation) => reservation.phase !== 'released')
      .flatMap((reservation) => reservation.perVolume)
      .filter((reserved) => reserved.volumeId === volumeId)
      .reduce((total, reserved) => total + BigInt(reserved.bytes), 0n)
  }

  private freeBytes(root: string): bigint {
    let free: bigint
    try {
      free = this.dependencies.freeBytes(root)
    } catch (error) {
      throw new PaidMediaCapacityError('Paid media capacity free-space probe failed', {
        cause: error
      })
    }
    if (typeof free !== 'bigint' || free < 0n) {
      throw new PaidMediaCapacityError('Paid media capacity free-space probe failed')
    }
    return free
  }

  private assertCurrentReservation(
    document: CapacityJournalDocument,
    existing: StoredCapacityReservation
  ): void {
    const currentPlan = this.plan(existing.path)
    const storedCurrentPlan = {
      budgetPolicy: PAID_MEDIA_CAPACITY_BUDGET_POLICY,
      roleBudgets: currentPlan.roleBudgets.map((roleBudget) => ({
        role: roleBudget.role,
        volumeId: roleBudget.volumeId,
        root: roleBudget.root,
        bytes: roleBudget.bytes.toString(10)
      })),
      perVolume: currentPlan.perVolume.map((volume) => ({
        volumeId: volume.volumeId,
        root: volume.root,
        bytes: volume.bytes.toString(10)
      }))
    }
    if (
      JSON.stringify(storedCurrentPlan) !==
      JSON.stringify({
        budgetPolicy: existing.budgetPolicy,
        roleBudgets: existing.roleBudgets,
        perVolume: existing.perVolume
      })
    ) {
      throw new PaidMediaCapacityError('Paid media capacity reservation plan changed')
    }
    for (const volume of currentPlan.perVolume) {
      if (
        this.freeBytes(volume.root) - this.activeBytes(document, volume.volumeId) <
        PAID_MEDIA_CAPACITY_FREE_FLOOR_BYTES
      ) {
        throw new PaidMediaCapacityError('Paid media capacity is insufficient')
      }
    }
  }

  async ensureReservation(input: {
    operationId: string
    path: PaidMediaPath
    allowCreate: boolean
  }): Promise<PaidMediaCapacityReservation> {
    if (
      !input ||
      typeof input !== 'object' ||
      !OPERATION_ID_PATTERN.test(input.operationId) ||
      !['/v1/images/generations', '/v1/videos/generations'].includes(input.path) ||
      typeof input.allowCreate !== 'boolean'
    ) {
      throw new PaidMediaCapacityError('Paid media capacity reservation request is invalid')
    }
    return serializedForCapacityPath(this.journalPath, () => {
      const state = this.readDocument()
      const document = state.document
      const existing = document.records.find((record) => record.operationId === input.operationId)
      if (existing) {
        if (!isStoredReservation(existing)) {
          throw new PaidMediaCapacityError('Paid media capacity reservation conflicts')
        }
        if (existing.path !== input.path || existing.phase !== 'active') {
          throw new PaidMediaCapacityError('Paid media capacity reservation conflicts')
        }
        this.assertCurrentReservation(document, existing)
        return this.publicReservation(existing)
      }
      if (!input.allowCreate) {
        throw new PaidMediaCapacityError('Paid media capacity reservation is missing')
      }
      if (document.records.filter(isStoredReservation).length >= MAX_RESERVATIONS) {
        throw new PaidMediaCapacityError('Paid media capacity active reservation limit is full')
      }
      if (document.records.length >= MAX_JOURNAL_RECORDS) {
        throw new PaidMediaCapacityError('Paid media capacity journal record limit is full')
      }
      const plan = this.plan(input.path)
      const perVolume = plan.perVolume
      for (const volume of perVolume) {
        const active = this.activeBytes(document, volume.volumeId)
        const free = this.freeBytes(volume.root)
        if (
          free - active < volume.bytes + PAID_MEDIA_CAPACITY_FREE_FLOOR_BYTES
        ) {
          throw new PaidMediaCapacityError('Paid media capacity is insufficient')
        }
      }
      const now = requireSafeTime(this.dependencies.now())
      const base: StoredCapacityReservationBase = {
        schema: RESERVATION_SCHEMA,
        operationId: input.operationId,
        path: input.path,
        phase: 'active',
        budgetPolicy: PAID_MEDIA_CAPACITY_BUDGET_POLICY,
        roleBudgets: plan.roleBudgets.map((roleBudget) => ({
          role: roleBudget.role,
          volumeId: roleBudget.volumeId,
          root: roleBudget.root,
          bytes: roleBudget.bytes.toString(10)
        })),
        perVolume: perVolume.map((volume) => ({
          volumeId: volume.volumeId,
          root: volume.root,
          bytes: volume.bytes.toString(10)
        })),
        createdAt: now,
        updatedAt: now,
        taskAliasSha256: null
      }
      const reservation: StoredCapacityReservation = {
        ...base,
        reservationSha256: sha256(JSON.stringify(base))
      }
      this.writeDocument(state, {
        ...document,
        sequence: nextSequence(document.sequence),
        records: [...document.records, reservation]
      })
      const committed = this.readDocument().document.records.find(
        (record) => record.operationId === input.operationId
      )
      if (
        !committed ||
        !isStoredReservation(committed) ||
        committed.reservationSha256 !== reservation.reservationSha256
      ) {
        throw new PaidMediaCapacityError('Paid media capacity reservation commit is unavailable')
      }
      return this.publicReservation(committed)
    })
  }

  async bindVideoTask(input: {
    operationId: string
    taskAliasSha256: string
  }): Promise<PaidMediaCapacityReservation> {
    if (
      !input ||
      typeof input !== 'object' ||
      !exactKeys(input as unknown as Record<string, unknown>, [
        'operationId',
        'taskAliasSha256'
      ]) ||
      typeof input.operationId !== 'string' ||
      !OPERATION_ID_PATTERN.test(input.operationId) ||
      typeof input.taskAliasSha256 !== 'string' ||
      !SHA256_PATTERN.test(input.taskAliasSha256)
    ) {
      throw new PaidMediaCapacityError('Paid media capacity video binding is invalid')
    }
    return serializedForCapacityPath(this.journalPath, () => {
      const state = this.readDocument()
      const index = state.document.records.findIndex(
        (reservation) => reservation.operationId === input.operationId
      )
      if (index < 0) throw new PaidMediaCapacityError('Paid media capacity reservation is missing')
      const existing = state.document.records[index]
      if (!isStoredReservation(existing)) {
        throw new PaidMediaCapacityError('Paid media capacity video binding conflicts')
      }
      if (existing.path !== '/v1/videos/generations') {
        throw new PaidMediaCapacityError('Paid media capacity video binding conflicts')
      }
      this.assertCurrentReservation(state.document, existing)
      if (existing.phase === 'video_bound') {
        if (existing.taskAliasSha256 !== input.taskAliasSha256) {
          throw new PaidMediaCapacityError('Paid media capacity video binding conflicts')
        }
        return this.publicReservation(existing)
      }
      if (existing.phase !== 'active' || existing.taskAliasSha256 !== null) {
        throw new PaidMediaCapacityError('Paid media capacity video binding conflicts')
      }
      const now = requireSafeTime(this.dependencies.now())
      if (now < existing.updatedAt) {
        throw new PaidMediaCapacityError('Paid media capacity clock moved backwards')
      }
      const { reservationSha256: _previousDigest, ...previousBase } = existing
      const base: StoredCapacityReservationBase = {
        ...previousBase,
        phase: 'video_bound',
        updatedAt: now,
        taskAliasSha256: input.taskAliasSha256
      }
      const bound: StoredCapacityReservation = {
        ...base,
        reservationSha256: sha256(JSON.stringify(base))
      }
      const records = [...state.document.records]
      records[index] = bound
      this.writeDocument(state, {
        ...state.document,
        sequence: nextSequence(state.document.sequence),
        records
      })
      const committed = this.readDocument().document.records.find(
        (reservation) => reservation.operationId === input.operationId
      )
      if (
        !committed ||
        !isStoredReservation(committed) ||
        committed.reservationSha256 !== bound.reservationSha256
      ) {
        throw new PaidMediaCapacityError('Paid media capacity video binding commit is unavailable')
      }
      return this.publicReservation(committed)
    })
  }

  async verifyVideoTaskBinding(input: {
    operationId: string
    taskAliasSha256: string
  }): Promise<PaidMediaCapacityReservation> {
    if (
      !input ||
      typeof input !== 'object' ||
      !exactKeys(input as unknown as Record<string, unknown>, [
        'operationId',
        'taskAliasSha256'
      ]) ||
      typeof input.operationId !== 'string' ||
      !OPERATION_ID_PATTERN.test(input.operationId) ||
      typeof input.taskAliasSha256 !== 'string' ||
      !SHA256_PATTERN.test(input.taskAliasSha256)
    ) {
      throw new PaidMediaCapacityError('Paid media capacity video binding is invalid')
    }
    return serializedForCapacityPath(this.journalPath, () => {
      const state = this.readDocument()
      const existing = state.document.records.find(
        (reservation) => reservation.operationId === input.operationId
      )
      if (
        !existing ||
        !isStoredReservation(existing) ||
        existing.path !== '/v1/videos/generations' ||
        existing.phase !== 'video_bound' ||
        existing.taskAliasSha256 !== input.taskAliasSha256
      ) {
        throw new PaidMediaCapacityError('Paid media capacity video binding conflicts')
      }
      this.assertCurrentReservation(state.document, existing)
      return this.publicReservation(existing)
    })
  }

  async listReservations(): Promise<PaidMediaCapacityReservation[]> {
    return serializedForCapacityPath(this.journalPath, () => {
      if (!this.dependencies.safeStorage.isEncryptionAvailable()) {
        throw new PaidMediaCapacityError('OS-backed paid media capacity encryption is unavailable')
      }
      return this.readDocument().document.records
        .filter(isStoredReservation)
        .map((reservation) => this.publicReservation(reservation))
    })
  }

  async ensureReleasedWithAuthorization(input: {
    operationId: string
    authorizationReceiptSha256: string
  }): Promise<PaidMediaCapacityReleaseTombstone> {
    if (
      !input ||
      typeof input !== 'object' ||
      !exactKeys(input as unknown as Record<string, unknown>, [
        'operationId',
        'authorizationReceiptSha256'
      ]) ||
      typeof input.operationId !== 'string' ||
      !OPERATION_ID_PATTERN.test(input.operationId) ||
      typeof input.authorizationReceiptSha256 !== 'string' ||
      !SHA256_PATTERN.test(input.authorizationReceiptSha256) ||
      /^0{64}$/.test(input.authorizationReceiptSha256)
    ) {
      throw new PaidMediaCapacityError('Paid media capacity release authorization is invalid')
    }
    return serializedForCapacityPath(this.journalPath, () => {
      const state = this.readDocument()
      const index = state.document.records.findIndex(
        (record) => record.operationId === input.operationId
      )
      const existing = index < 0 ? null : state.document.records[index]
      if (existing && isStoredReleaseTombstone(existing)) {
        if (existing.authorizationReceiptSha256 !== input.authorizationReceiptSha256) {
          throw new PaidMediaCapacityError('Paid media capacity release authorization conflicts')
        }
        return this.publicReleaseTombstone(existing)
      }
      if (state.document.records.length >= MAX_JOURNAL_RECORDS && existing === null) {
        throw new PaidMediaCapacityError('Paid media capacity journal record limit is full')
      }
      const releasedAt = requireSafeTime(this.dependencies.now())
      if (existing && releasedAt < existing.updatedAt) {
        throw new PaidMediaCapacityError('Paid media capacity clock moved backwards')
      }
      const base: StoredCapacityReleaseTombstoneBase = {
        schema: RELEASE_TOMBSTONE_SCHEMA,
        operationId: input.operationId,
        authorizationReceiptSha256: input.authorizationReceiptSha256,
        releasedAt,
        releasedReservationSha256: existing?.reservationSha256 ?? null
      }
      const tombstone: StoredCapacityReleaseTombstone = {
        ...base,
        releaseTombstoneSha256: sha256(JSON.stringify(base))
      }
      const records = [...state.document.records]
      if (index < 0) records.push(tombstone)
      else records[index] = tombstone
      this.writeDocument(state, {
        ...state.document,
        sequence: nextSequence(state.document.sequence),
        records
      })
      const committed = this.readDocument().document.records.find(
        (record) => record.operationId === input.operationId
      )
      if (
        !committed ||
        !isStoredReleaseTombstone(committed) ||
        committed.releaseTombstoneSha256 !== tombstone.releaseTombstoneSha256
      ) {
        throw new PaidMediaCapacityError('Paid media capacity release commit is unavailable')
      }
      return this.publicReleaseTombstone(committed)
    })
  }

  async releaseReservation(operationId: string): Promise<boolean> {
    if (typeof operationId !== 'string' || !OPERATION_ID_PATTERN.test(operationId)) {
      throw new PaidMediaCapacityError('Paid media capacity operation id is invalid')
    }
    throw new PaidMediaCapacityError(
      'Paid media capacity release requires a Vault authorization receipt'
    )
  }
}
