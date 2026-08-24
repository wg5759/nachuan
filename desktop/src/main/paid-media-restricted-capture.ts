import { createHash } from 'node:crypto'

import type { PaidMediaCapacityCaptureEvidence, PaidMediaCapacityManager } from './paid-media-capacity'
import type {
  PaidMediaMaintenanceDrainEvidence,
  PaidMediaService
} from './paid-media-service'
import type { PaidMediaVault, PaidMediaVaultCaptureInventory } from './paid-media-vault'

const CAPTURE_SCHEMA = 'nachuan.paid-media-restricted-capture.v1' as const
const CAPTURE_STATUS_SCHEMA = 'nachuan.paid-media-restricted-capture-status.v1' as const
const CAPTURE_SCOPE = 'desktop-main-same-process' as const
const VAULT_INVENTORY_HASH_DOMAIN = 'nachuan:paid-media-restricted-capture:vault:v1\0'
const CAPACITY_EVIDENCE_HASH_DOMAIN = 'nachuan:paid-media-restricted-capture:capacity:v1\0'
const CAPTURE_EVIDENCE_HASH_DOMAIN = 'nachuan:paid-media-restricted-capture:evidence:v1\0'
const SHA256_PATTERN = /^[0-9a-f]{64}$/

export interface PaidMediaRestrictedCaptureDependencies {
  service: Pick<
    PaidMediaService,
    'enterMaintenanceDrain' | 'inspectMaintenanceDrain' | 'releaseMaintenanceDrain'
  >
  vault: Pick<PaidMediaVault, 'inspectCaptureInventory'>
  capacity: Pick<PaidMediaCapacityManager, 'inspectCaptureEvidence'>
}

export interface PaidMediaRestrictedCaptureEvidence {
  readonly schema: typeof CAPTURE_SCHEMA
  readonly scope: typeof CAPTURE_SCOPE
  readonly capability: 'capture_only'
  readonly captureGeneration: number
  readonly captureReady: false
  readonly captureProofStatus: 'partial'
  readonly restoreReady: false
  readonly backupSupported: false
  readonly reanchorSupported: false
  readonly maintenance: Readonly<{
    drainGeneration: number
    acceptedSequence: number
    completedSequence: number
    evidenceSha256: string
  }>
  readonly vault: Readonly<{
    vaultStateDigest: string
    entryCount: number
    inventorySha256: string
  }>
  readonly capacity: Readonly<{
    capacityIdentity: string
    capacitySequence: number
    capacityStateDigest: string
    documentSha256: string
    artifactCount: number
    evidenceSha256: string
  }>
  readonly externalClosureRequired: Readonly<{
    writerFence: true
    pinnedFileHandles: true
    stagingAclProof: true
  }>
  readonly captureEvidenceSha256: string
}

export interface PaidMediaRestrictedCaptureStatus {
  readonly schema: typeof CAPTURE_STATUS_SCHEMA
  readonly scope: typeof CAPTURE_SCOPE
  readonly phase: 'idle' | 'capturing' | 'held' | 'release_failed'
  readonly captureGeneration: number
  readonly captureEvidenceSha256: string | null
}

export interface PaidMediaRestrictedCaptureOptions {
  readonly signal?: AbortSignal
}

type CaptureEvidencePayload = Omit<PaidMediaRestrictedCaptureEvidence, 'captureEvidenceSha256'>

export class PaidMediaRestrictedCaptureError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'PaidMediaRestrictedCaptureError'
  }
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') {
    return JSON.stringify(value)
  }
  if (typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map((entry) => canonicalJson(entry)).join(',')}]`
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>
    return `{${Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
      .join(',')}}`
  }
  throw new PaidMediaRestrictedCaptureError('Restricted capture evidence is invalid')
}

function evidenceSha256(domain: string, value: unknown): string {
  return createHash('sha256').update(domain, 'utf8').update(canonicalJson(value), 'utf8').digest('hex')
}

function isDeepFrozen(value: unknown, seen = new Set<object>()): boolean {
  if (!value || typeof value !== 'object') return true
  if (seen.has(value)) return true
  seen.add(value)
  if (!Object.isFrozen(value)) return false
  return Object.values(value).every((nested) => isDeepFrozen(nested, seen))
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort()
  const wanted = [...expected].sort()
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index])
}

function recordValue(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null
}

function safeCounter(value: unknown, minimum = 0): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= minimum
}

function digest(value: unknown): value is string {
  return typeof value === 'string' && SHA256_PATTERN.test(value)
}

function assertMaintenanceEvidence(value: unknown): asserts value is PaidMediaMaintenanceDrainEvidence {
  const record = recordValue(value)
  if (
    !record ||
    !isDeepFrozen(record) ||
    !exactKeys(record, [
      'schema',
      'scope',
      'drainGeneration',
      'acceptedSequence',
      'completedSequence',
      'activeWorkCount',
      'operationMutexCount',
      'activeRequestCount',
      'executingOperationCount',
      'pendingCancellationCount',
      'legacyBootstrapIdle',
      'evidenceSha256'
    ]) ||
    record.schema !== 'nachuan.paid-media-service-quiescence.v1' ||
    record.scope !== 'desktop-main-paid-media-service' ||
    !safeCounter(record.drainGeneration, 1) ||
    !safeCounter(record.acceptedSequence) ||
    record.completedSequence !== record.acceptedSequence ||
    record.activeWorkCount !== 0 ||
    record.operationMutexCount !== 0 ||
    record.activeRequestCount !== 0 ||
    record.executingOperationCount !== 0 ||
    record.pendingCancellationCount !== 0 ||
    record.legacyBootstrapIdle !== true ||
    !digest(record.evidenceSha256)
  ) {
    throw new PaidMediaRestrictedCaptureError('Restricted capture maintenance evidence is invalid')
  }
}

function assertVaultInventory(value: unknown): asserts value is PaidMediaVaultCaptureInventory {
  const record = recordValue(value)
  const quiescence = recordValue(record?.quiescence)
  if (
    !record ||
    !isDeepFrozen(record) ||
    !exactKeys(record, ['vaultStateDigest', 'entryCount', 'entries', 'quiescence']) ||
    !digest(record.vaultStateDigest) ||
    !safeCounter(record.entryCount) ||
    !Array.isArray(record.entries) ||
    record.entries.length !== record.entryCount ||
    !quiescence ||
    !exactKeys(quiescence, [
      'activeStageLeases',
      'stageOpenHandles',
      'activeStageStream',
      'cleanupRetries',
      'cleanupFlights',
      'terminalArchiveFlights',
      'cleanupPendingEntries',
      'stageRootEntries'
    ]) ||
    quiescence.activeStageLeases !== 0 ||
    quiescence.stageOpenHandles !== 0 ||
    quiescence.activeStageStream !== null ||
    quiescence.cleanupRetries !== 0 ||
    quiescence.cleanupFlights !== 0 ||
    quiescence.terminalArchiveFlights !== 0 ||
    quiescence.cleanupPendingEntries !== 0 ||
    quiescence.stageRootEntries !== 0
  ) {
    throw new PaidMediaRestrictedCaptureError('Restricted capture vault inventory is invalid')
  }
  const paths = new Set<string>()
  for (const entry of record.entries) {
    const item = recordValue(entry)
    if (
      !item ||
      !exactKeys(item, ['path', 'byteLength', 'sha256']) ||
      typeof item.path !== 'string' ||
      item.path.length < 1 ||
      /[\u0000-\u001f\u007f]/.test(item.path) ||
      !safeCounter(item.byteLength) ||
      !digest(item.sha256) ||
      paths.has(item.path)
    ) {
      throw new PaidMediaRestrictedCaptureError('Restricted capture vault inventory is invalid')
    }
    paths.add(item.path)
  }
}

function assertCapacityEvidence(value: unknown): asserts value is PaidMediaCapacityCaptureEvidence {
  const record = recordValue(value)
  const closure = recordValue(record?.externalClosureRequired)
  if (
    !record ||
    !isDeepFrozen(record) ||
    !exactKeys(record, [
      'activeSlot',
      'capacityIdentity',
      'capacitySequence',
      'capacityStateDigest',
      'documentSha256',
      'artifacts',
      'externalClosureRequired'
    ]) ||
    (record.activeSlot !== 'a' && record.activeSlot !== 'b') ||
    !digest(record.capacityIdentity) ||
    !safeCounter(record.capacitySequence, 1) ||
    !digest(record.capacityStateDigest) ||
    !digest(record.documentSha256) ||
    !Array.isArray(record.artifacts) ||
    record.artifacts.length !== 2 ||
    !closure ||
    !exactKeys(closure, ['writerFence', 'pinnedFileHandles', 'stagingAclProof']) ||
    closure.writerFence !== true ||
    closure.pinnedFileHandles !== true ||
    closure.stagingAclProof !== true
  ) {
    throw new PaidMediaRestrictedCaptureError('Restricted capture capacity evidence is invalid')
  }
  const roles = new Set<string>()
  for (const artifact of record.artifacts) {
    const item = recordValue(artifact)
    if (
      !item ||
      !exactKeys(item, ['role', 'path', 'byteLength', 'sha256']) ||
      (item.role !== 'desktop_capacity_anchor' &&
        item.role !== 'desktop_capacity_active_slot') ||
      roles.has(item.role) ||
      typeof item.path !== 'string' ||
      item.path.length < 1 ||
      /[\u0000-\u001f\u007f]/.test(item.path) ||
      !safeCounter(item.byteLength) ||
      !digest(item.sha256)
    ) {
      throw new PaidMediaRestrictedCaptureError('Restricted capture capacity evidence is invalid')
    }
    roles.add(item.role)
  }
}

function sameFrozenEvidence(left: unknown, right: unknown): boolean {
  return isDeepFrozen(left) && isDeepFrozen(right) && canonicalJson(left) === canonicalJson(right)
}

function captureSignal(options: PaidMediaRestrictedCaptureOptions): AbortSignal | undefined {
  if (!options || typeof options !== 'object' || Array.isArray(options)) {
    throw new PaidMediaRestrictedCaptureError('Restricted capture options are invalid')
  }
  const keys = Object.keys(options)
  if (keys.some((key) => key !== 'signal')) {
    throw new PaidMediaRestrictedCaptureError('Restricted capture options are invalid')
  }
  const signal = options.signal
  if (
    signal !== undefined &&
    (!signal ||
      typeof signal !== 'object' ||
      typeof signal.aborted !== 'boolean' ||
      typeof signal.addEventListener !== 'function')
  ) {
    throw new PaidMediaRestrictedCaptureError('Restricted capture options are invalid')
  }
  return signal
}

function throwIfCancelled(signal: AbortSignal | undefined): void {
  if (signal?.aborted) {
    throw new PaidMediaRestrictedCaptureError('Restricted capture was cancelled')
  }
}

/**
 * Coordinates a read-only, same-process inspection while PaidMediaService
 * holds its maintenance drain. The returned self-hash is capture-only error
 * detection: it is not a backup, reanchor, cross-process writer fence, pinned
 * handle proof, ACL proof, trusted attestation, or LocalService receipt.
 */
export class PaidMediaRestrictedCaptureCoordinator {
  private phase: PaidMediaRestrictedCaptureStatus['phase'] = 'idle'
  private captureGeneration = 0
  private capturePromise: Promise<PaidMediaRestrictedCaptureEvidence> | null = null
  private held:
    | {
        publicEvidence: PaidMediaRestrictedCaptureEvidence
        drainEvidence: PaidMediaMaintenanceDrainEvidence
      }
    | null = null
  private lastReleased: PaidMediaRestrictedCaptureEvidence | null = null

  constructor(private readonly dependencies: PaidMediaRestrictedCaptureDependencies) {}

  enterRestrictedCapture(
    options: PaidMediaRestrictedCaptureOptions = {}
  ): Promise<PaidMediaRestrictedCaptureEvidence> {
    if (this.phase === 'held' && this.held) return Promise.resolve(this.held.publicEvidence)
    if (this.phase === 'capturing' && this.capturePromise) return this.capturePromise
    if (this.phase === 'release_failed') {
      return Promise.reject(
        new PaidMediaRestrictedCaptureError(
          'Restricted capture cannot continue because maintenance release failed'
        )
      )
    }
    if (this.captureGeneration >= Number.MAX_SAFE_INTEGER) {
      return Promise.reject(
        new PaidMediaRestrictedCaptureError('Restricted capture generation is exhausted')
      )
    }
    let signal: AbortSignal | undefined
    try {
      signal = captureSignal(options)
      throwIfCancelled(signal)
    } catch (error) {
      return Promise.reject(error)
    }
    this.captureGeneration += 1
    this.phase = 'capturing'
    this.held = null
    const capture = this.captureTwoFrozenPasses(this.captureGeneration, signal)
    this.capturePromise = capture
    return capture
  }

  inspectRestrictedCapture(): PaidMediaRestrictedCaptureStatus {
    return Object.freeze({
      schema: CAPTURE_STATUS_SCHEMA,
      scope: CAPTURE_SCOPE,
      phase: this.phase,
      captureGeneration: this.captureGeneration,
      captureEvidenceSha256: this.held?.publicEvidence.captureEvidenceSha256 ?? null
    })
  }

  releaseRestrictedCapture(evidence: PaidMediaRestrictedCaptureEvidence): boolean {
    if (this.phase === 'idle') return this.lastReleased === evidence
    if (this.phase !== 'held' || !this.held || evidence !== this.held.publicEvidence) return false
    if (!this.dependencies.service.releaseMaintenanceDrain(this.held.drainEvidence)) return false
    this.lastReleased = this.held.publicEvidence
    this.held = null
    this.phase = 'idle'
    return true
  }

  private async captureTwoFrozenPasses(
    generation: number,
    signal: AbortSignal | undefined
  ): Promise<PaidMediaRestrictedCaptureEvidence> {
    let drainEvidence: PaidMediaMaintenanceDrainEvidence | null = null
    try {
      throwIfCancelled(signal)
      const firstDrain = await this.dependencies.service.enterMaintenanceDrain()
      drainEvidence = firstDrain
      assertMaintenanceEvidence(firstDrain)
      // Cancellation is observed only at inspection boundaries. Releasing the
      // drain while an uncancellable read is still executing would reopen a
      // writer race and invalidate the evidence we are trying to protect.
      throwIfCancelled(signal)
      const firstVault = await this.dependencies.vault.inspectCaptureInventory()
      assertVaultInventory(firstVault)
      throwIfCancelled(signal)
      const firstCapacity = await this.dependencies.capacity.inspectCaptureEvidence()
      assertCapacityEvidence(firstCapacity)
      throwIfCancelled(signal)
      const finalDrain = await this.dependencies.service.enterMaintenanceDrain()
      assertMaintenanceEvidence(finalDrain)
      throwIfCancelled(signal)
      const finalVault = await this.dependencies.vault.inspectCaptureInventory()
      assertVaultInventory(finalVault)
      throwIfCancelled(signal)
      const finalCapacity = await this.dependencies.capacity.inspectCaptureEvidence()
      assertCapacityEvidence(finalCapacity)
      throwIfCancelled(signal)
      if (
        !sameFrozenEvidence(firstDrain, finalDrain) ||
        !sameFrozenEvidence(firstVault, finalVault) ||
        !sameFrozenEvidence(firstCapacity, finalCapacity)
      ) {
        throw new PaidMediaRestrictedCaptureError(
          'Restricted capture evidence changed between frozen inspection passes'
        )
      }
      const publicEvidence = this.publicEvidence(
        generation,
        firstDrain,
        firstVault,
        firstCapacity
      )
      this.held = { publicEvidence, drainEvidence: firstDrain }
      this.phase = 'held'
      return publicEvidence
    } catch (error) {
      if (drainEvidence && !this.dependencies.service.releaseMaintenanceDrain(drainEvidence)) {
        this.phase = 'release_failed'
        throw new PaidMediaRestrictedCaptureError(
          'Restricted capture failed and its maintenance drain could not be released'
        )
      }
      this.phase = 'idle'
      if (
        error instanceof PaidMediaRestrictedCaptureError &&
        error.message === 'Restricted capture was cancelled'
      ) {
        throw error
      }
      throw new PaidMediaRestrictedCaptureError('Restricted capture inspection failed safely')
    } finally {
      this.capturePromise = null
    }
  }

  private publicEvidence(
    generation: number,
    maintenance: PaidMediaMaintenanceDrainEvidence,
    vault: PaidMediaVaultCaptureInventory,
    capacity: PaidMediaCapacityCaptureEvidence
  ): PaidMediaRestrictedCaptureEvidence {
    const payload: CaptureEvidencePayload = {
      schema: CAPTURE_SCHEMA,
      scope: CAPTURE_SCOPE,
      capability: 'capture_only',
      captureGeneration: generation,
      captureReady: false,
      captureProofStatus: 'partial',
      restoreReady: false,
      backupSupported: false,
      reanchorSupported: false,
      maintenance: Object.freeze({
        drainGeneration: maintenance.drainGeneration,
        acceptedSequence: maintenance.acceptedSequence,
        completedSequence: maintenance.completedSequence,
        evidenceSha256: maintenance.evidenceSha256
      }),
      vault: Object.freeze({
        vaultStateDigest: vault.vaultStateDigest,
        entryCount: vault.entryCount,
        inventorySha256: evidenceSha256(VAULT_INVENTORY_HASH_DOMAIN, vault)
      }),
      capacity: Object.freeze({
        capacityIdentity: capacity.capacityIdentity,
        capacitySequence: capacity.capacitySequence,
        capacityStateDigest: capacity.capacityStateDigest,
        documentSha256: capacity.documentSha256,
        artifactCount: capacity.artifacts.length,
        evidenceSha256: evidenceSha256(CAPACITY_EVIDENCE_HASH_DOMAIN, capacity)
      }),
      externalClosureRequired: Object.freeze({
        writerFence: capacity.externalClosureRequired.writerFence,
        pinnedFileHandles: capacity.externalClosureRequired.pinnedFileHandles,
        stagingAclProof: capacity.externalClosureRequired.stagingAclProof
      })
    }
    return Object.freeze({
      ...payload,
      captureEvidenceSha256: evidenceSha256(CAPTURE_EVIDENCE_HASH_DOMAIN, payload)
    })
  }
}
