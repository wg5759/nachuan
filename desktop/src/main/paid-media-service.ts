import { createHash } from 'node:crypto'
import http from 'node:http'

import type { PaidMediaCapacityManager } from './paid-media-capacity'
import type {
  PaidMediaAuthorityEvidence,
  PaidMediaAuthorityMutationInput,
  PaidMediaAuthorityMutationContext,
  PaidMediaInstallationRootState,
  PaidMediaRecoverableMutationInput
} from './paid-media-installation-root'
import type {
  PaidMediaLedger,
  PaidMediaLegacyUnresolvedInput,
  PaidMediaPath,
  PaidMediaPublicOperation
} from './paid-media-ledger'
import type { PaidMediaLegacySeal, PaidMediaLegacySealStatus } from './paid-media-legacy-seal'
import { PaidMediaMutationGate } from './paid-media-mutation-gate'
import type {
  PaidMediaRecoveryIntentDescriptor,
  PaidMediaRecoveryIntentPayload,
  PaidMediaRecoveryIntentStore
} from './paid-media-recovery-intent'
import {
  MAX_PAID_MEDIA_ARCHIVE_RESPONSE_BYTES,
  type PaidMediaArchiveDiscoveryPage,
  type PaidMediaArchivedResult,
  type PaidMediaVault
} from './paid-media-vault'

// Gateway schemas and durable response storage both cap the paid-media
// contract at 24 MiB. Sharing this export with IPC prevents an approval dialog
// for a request that Gateway must reject before provider dispatch.
export const MAX_PAID_MEDIA_REQUEST_BYTES = 24 * 1024 * 1024
const MAX_POLL_RESPONSE_BYTES = 24 * 1024 * 1024
const MAX_MODEL_CODE_POINTS = 256
const MAX_PROMPT_CODE_POINTS = 32_768
const MAX_VIDEO_KEYFRAMES = 4
const IMAGE_REQUEST_FIELDS = new Set(['model', 'prompt', 'n', 'size', 'response_format'])
const VIDEO_REQUEST_FIELDS = new Set([
  'model',
  'prompt',
  'image',
  'mode',
  'height',
  'width',
  'num_frames',
  'frame_rate',
  'extra_body'
])
const VIDEO_EXTRA_BODY_FIELDS = new Set(['image', 'mode'])
const RESPONSE_TIMEOUT_MS = 5 * 60 * 1000
const OPERATION_ID_PATTERN = /^desktop-op-[0-9a-f-]{36}$/i
const SHA256_PATTERN = /^[0-9a-f]{64}$/
const VIDEO_TASK_ALIAS_PATTERN = /^nvt1_[0-9a-f]{64}$/
const RECOVERY_DOMAIN_CONTEXT = 'nachuan:paid-media:recovery-domain:v1\0'
const CAPACITY_RELEASE_CONTEXT = 'nachuan:paid-media:capacity-release-authorization:v1\0'
const MAINTENANCE_EVIDENCE_CONTEXT = 'nachuan:paid-media-service:quiescence:v1\0'
const MAINTENANCE_EVIDENCE_SCHEMA = 'nachuan.paid-media-service-quiescence.v1' as const
const MAINTENANCE_STATUS_SCHEMA = 'nachuan.paid-media-service-drain-status.v1' as const
const MAINTENANCE_SCOPE = 'desktop-main-paid-media-service' as const

function capacityReleaseAuthorizationSha256(operationId: string, reason: string): string {
  return createHash('sha256')
    .update(CAPACITY_RELEASE_CONTEXT, 'utf8')
    .update(operationId, 'ascii')
    .update('\0', 'ascii')
    .update(reason, 'ascii')
    .digest('hex')
}

export interface PaidMediaTransportRequest {
  method: 'GET' | 'POST'
  url: string
  path: string
  encodedBody: string
  headers: Record<string, string>
  signal: AbortSignal
  responseByteLimit: number
}

export interface PaidMediaTransportResponse {
  status: number
  headers: Record<string, string | undefined>
  body: string
}

export type PaidMediaTransport = (
  request: PaidMediaTransportRequest
) => Promise<PaidMediaTransportResponse>

export interface PaidMediaInstallationAuthority {
  readonly state: PaidMediaInstallationRootState
  attachEvidenceReader(
    reader: () => PaidMediaAuthorityEvidence | Promise<PaidMediaAuthorityEvidence>
  ): void
  provision(): Promise<PaidMediaInstallationRootState>
  reconcileStartup(): Promise<PaidMediaInstallationRootState>
  localPaidPrincipal(): string
  assertMutationContext(transactionId?: string): void
  assertOutboundReady(): Promise<PaidMediaInstallationRootState>
  runMutation<T>(
    input: PaidMediaAuthorityMutationInput,
    action: (context: PaidMediaAuthorityMutationContext) => Promise<T>
  ): Promise<T>
  runRecoverableMutation?(
    input: PaidMediaRecoverableMutationInput
  ): Promise<PaidMediaInstallationRootState>
  resumeRecoverableMutation?(
    input: PaidMediaRecoverableMutationInput
  ): Promise<PaidMediaInstallationRootState>
}

export interface PaidMediaServiceDependencies {
  ledger: PaidMediaLedger
  vault: PaidMediaVault
  capacity: PaidMediaCapacityManager
  baseUrl: () => string
  runtimeKey: () => string
  approvalKey: () => string
  paidMediaKey: () => string
  transport: PaidMediaTransport
  installationRoot?: PaidMediaInstallationAuthority
  legacySeal?: Pick<PaidMediaLegacySeal, 'inspect' | 'close'>
  mutationGate?: PaidMediaMutationGate
  recoveryIntentStore?: Pick<PaidMediaRecoveryIntentStore, 'prepare'>
  assetV2?: PaidMediaAssetV2Executor
}

export interface PaidMediaAssetV2ExecutionInput {
  operationId: string
  path: '/v1/images/generations'
  encodedBody: string
  requestSha256: string
  recoveryDomainSha256: string
  idempotencyKey: string
  signal: AbortSignal
  runRecoverableMutation(
    payload: PaidMediaRecoveryIntentPayload
  ): Promise<PaidMediaRecoveryIntentDescriptor>
}

export type PaidMediaAssetV2ExecutionResult =
  | {
      ok: true
      archived: PaidMediaArchivedResult
      operation: PaidMediaPublicOperation
    }
  | {
      ok: false
      status: number
      detail: string
      retryAfterSeconds?: number
      operation: PaidMediaPublicOperation
    }

export interface PaidMediaAssetV2Executor {
  isReady(): boolean
  executeImage(input: PaidMediaAssetV2ExecutionInput): Promise<PaidMediaAssetV2ExecutionResult>
  convergeImageAck?(input: {
    operationId: string
    signal: AbortSignal
    runRecoverableMutation(
      payload: PaidMediaRecoveryIntentPayload
    ): Promise<PaidMediaRecoveryIntentDescriptor>
  }): Promise<boolean>
}

export interface PaidMediaInstallationInitializationResult {
  authority: PaidMediaInstallationRootState
  legacyDecisionSha256: string
  legacyImported: boolean
  capacity: {
    inspected: number
    released: number
    bound: number
    held: number
  } | null
}

export type PaidMediaLegacyBootstrapInput =
  | PaidMediaLegacyUnresolvedInput
  | null
  | { kind: 'migrated' }

export interface PaidMediaClaimRequest {
  path: PaidMediaPath
  encodedBody: string
  retryOperationId?: string
}

export interface PaidMediaExecuteRequest {
  operationId: string
  path: PaidMediaPath
  encodedBody: string
}

export interface PaidVideoPollRequest {
  taskAlias: string
  model: string
}

export interface PaidMediaArchiveRecoveryResult {
  operationId: string
  path: PaidMediaPath
  model: string
  status: number
  result: Record<string, unknown>
  deliveryProof: PaidMediaDeliveryProof
  archive: {
    receiptSha256: string
    responseSha256: string
    responseByteLength: number
    assets: PaidMediaArchivedResult['receipt']['assets']
  }
}

export interface PaidMediaDeliveryProof {
  operationId: string
  resultSha256: string
  archiveReceiptSha256: string
}

export type PaidMediaExecutionResult =
  | {
      ok: true
      status: number
      result: unknown
      operation: PaidMediaPublicOperation
      deliveryProof: PaidMediaDeliveryProof
    }

  | {
      ok: false
      status: number
      recoverable: boolean
      detail: string
      retryAfterSeconds?: number
      operation: PaidMediaPublicOperation
    }

export interface PaidMediaMaintenanceDrainEvidence {
  readonly schema: typeof MAINTENANCE_EVIDENCE_SCHEMA
  readonly scope: typeof MAINTENANCE_SCOPE
  readonly drainGeneration: number
  readonly acceptedSequence: number
  readonly completedSequence: number
  readonly activeWorkCount: 0
  readonly operationMutexCount: 0
  readonly activeRequestCount: 0
  readonly executingOperationCount: 0
  readonly pendingCancellationCount: 0
  readonly legacyBootstrapIdle: true
  readonly evidenceSha256: string
}

export interface PaidMediaMaintenanceDrainStatus {
  readonly schema: typeof MAINTENANCE_STATUS_SCHEMA
  readonly scope: typeof MAINTENANCE_SCOPE
  readonly phase: 'accepting' | 'draining' | 'quiescent'
  readonly drainGeneration: number
  readonly acceptedSequence: number
  readonly completedSequence: number
  readonly activeWorkCount: number
}

export class PaidMediaServiceError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options)
    this.name = 'PaidMediaServiceError'
  }
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort()
  const wanted = [...expected].sort()
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index])
}

type PaidMediaMaintenanceEvidencePayload = Omit<
  PaidMediaMaintenanceDrainEvidence,
  'evidenceSha256'
>

function maintenanceEvidenceSha256(value: PaidMediaMaintenanceEvidencePayload): string {
  return createHash('sha256')
    .update(MAINTENANCE_EVIDENCE_CONTEXT, 'utf8')
    .update(JSON.stringify(value), 'ascii')
    .digest('hex')
}

function validMaintenanceEvidence(
  value: unknown
): value is PaidMediaMaintenanceDrainEvidence {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const record = value as unknown as Record<string, unknown>
  if (
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
    record.schema !== MAINTENANCE_EVIDENCE_SCHEMA ||
    record.scope !== MAINTENANCE_SCOPE ||
    !Number.isSafeInteger(record.drainGeneration) ||
    Number(record.drainGeneration) < 1 ||
    !Number.isSafeInteger(record.acceptedSequence) ||
    Number(record.acceptedSequence) < 0 ||
    !Number.isSafeInteger(record.completedSequence) ||
    Number(record.completedSequence) < 0 ||
    record.activeWorkCount !== 0 ||
    record.operationMutexCount !== 0 ||
    record.activeRequestCount !== 0 ||
    record.executingOperationCount !== 0 ||
    record.pendingCancellationCount !== 0 ||
    record.legacyBootstrapIdle !== true ||
    typeof record.evidenceSha256 !== 'string' ||
    !SHA256_PATTERN.test(record.evidenceSha256)
  ) {
    return false
  }
  const evidence = value as PaidMediaMaintenanceDrainEvidence
  const payload: PaidMediaMaintenanceEvidencePayload = {
    schema: evidence.schema,
    scope: evidence.scope,
    drainGeneration: evidence.drainGeneration,
    acceptedSequence: evidence.acceptedSequence,
    completedSequence: evidence.completedSequence,
    activeWorkCount: evidence.activeWorkCount,
    operationMutexCount: evidence.operationMutexCount,
    activeRequestCount: evidence.activeRequestCount,
    executingOperationCount: evidence.executingOperationCount,
    pendingCancellationCount: evidence.pendingCancellationCount,
    legacyBootstrapIdle: evidence.legacyBootstrapIdle
  }
  return evidence.evidenceSha256 === maintenanceEvidenceSha256(payload)
}

function deliveryProof(archived: PaidMediaArchivedResult): PaidMediaDeliveryProof {
  return {
    operationId: archived.receipt.operationId,
    resultSha256: archived.receipt.recoverySha256,
    archiveReceiptSha256: archived.receipt.receiptSha256
  }
}

function validPath(value: unknown): value is PaidMediaPath {
  return value === '/v1/images/generations' || value === '/v1/videos/generations'
}

export interface PaidMediaRequestBodySummary {
  encodedBody: string
  value: Record<string, unknown>
  model: string
  prompt: string
}

function codePointLength(value: string): number {
  return Array.from(value).length
}

/** Keep Desktop admission aligned with Gateway's required media fields. */
export function inspectPaidMediaRequestBody(
  encodedBody: unknown,
  path: PaidMediaPath
): PaidMediaRequestBodySummary {
  if (typeof encodedBody !== 'string' || encodedBody.length < 2) {
    throw new PaidMediaServiceError('Paid media request body is invalid')
  }
  if (Buffer.byteLength(encodedBody, 'utf8') > MAX_PAID_MEDIA_REQUEST_BYTES) {
    throw new PaidMediaServiceError('Paid media request body exceeds its size limit')
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(encodedBody)
  } catch (error) {
    throw new PaidMediaServiceError('Paid media request body is not valid JSON', { cause: error })
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new PaidMediaServiceError('Paid media request body must be a JSON object')
  }
  const value = parsed as Record<string, unknown>
  if (
    typeof value.model !== 'string' ||
    !value.model.trim() ||
    codePointLength(value.model.trim()) > MAX_MODEL_CODE_POINTS ||
    typeof value.prompt !== 'string' ||
    !value.prompt.trim() ||
    codePointLength(value.prompt.trim()) > MAX_PROMPT_CODE_POINTS
  ) {
    throw new PaidMediaServiceError('Paid media request model or prompt is invalid')
  }
  const allowedFields = path === '/v1/images/generations' ? IMAGE_REQUEST_FIELDS : VIDEO_REQUEST_FIELDS
  if (Object.keys(value).some((field) => !allowedFields.has(field))) {
    throw new PaidMediaServiceError('Paid media request contains an unsupported field')
  }
  if (path === '/v1/images/generations') {
    if (
      (value.n !== undefined &&
        (!Number.isInteger(value.n) || Number(value.n) < 1 || Number(value.n) > 4)) ||
      (value.size !== undefined && typeof value.size !== 'string') ||
      (value.response_format !== undefined &&
        value.response_format !== 'url' &&
        value.response_format !== 'b64_json')
    ) {
      throw new PaidMediaServiceError('Paid media image parameters are invalid')
    }
  } else {
    const extraBody = value.extra_body
    if (
      extraBody !== undefined &&
      (!extraBody || typeof extraBody !== 'object' || Array.isArray(extraBody))
    ) {
      throw new PaidMediaServiceError('Paid media video extra_body is invalid')
    }
    const extraRecord = extraBody as Record<string, unknown> | undefined
    if (extraRecord && Object.keys(extraRecord).some((field) => !VIDEO_EXTRA_BODY_FIELDS.has(field))) {
      throw new PaidMediaServiceError('Paid media request contains an unsupported field')
    }
    const mediaInputs: unknown[] = []
    for (const input of [value.image, extraRecord?.image]) {
      if (input === undefined) continue
      mediaInputs.push(...(Array.isArray(input) ? input : [input]))
    }
    if (
      mediaInputs.length > MAX_VIDEO_KEYFRAMES ||
      mediaInputs.some((input) => typeof input !== 'string' || !input.trim()) ||
      (value.mode !== undefined && typeof value.mode !== 'string') ||
      (extraRecord?.mode !== undefined && typeof extraRecord.mode !== 'string') ||
      (value.height !== undefined && !Number.isInteger(value.height)) ||
      (value.width !== undefined && !Number.isInteger(value.width)) ||
      (value.num_frames !== undefined && !Number.isInteger(value.num_frames)) ||
      (value.frame_rate !== undefined &&
        (typeof value.frame_rate !== 'number' || !Number.isFinite(value.frame_rate)))
    ) {
      throw new PaidMediaServiceError('Paid media video parameters are invalid')
    }
  }
  return {
    encodedBody,
    value,
    model: value.model.trim(),
    prompt: value.prompt.trim()
  }
}

function validateBody(encodedBody: unknown, path: PaidMediaPath): string {
  return inspectPaidMediaRequestBody(encodedBody, path).encodedBody
}

function requestDigest(encodedBody: string): string {
  return createHash('sha256').update(encodedBody, 'utf8').digest('hex')
}

function recoveryDomainDigest(paidMediaKey: string): string {
  return createHash('sha256')
    .update(RECOVERY_DOMAIN_CONTEXT, 'utf8')
    .update(paidMediaKey, 'utf8')
    .digest('hex')
}

function validateLoopbackBaseUrl(raw: string): string {
  let url: URL
  try {
    url = new URL(raw)
  } catch (error) {
    throw new PaidMediaServiceError('Paid media engine URL is invalid', { cause: error })
  }
  const loopback =
    url.hostname === '127.0.0.1' || url.hostname === 'localhost' || url.hostname === '[::1]'
  if (
    url.protocol !== 'http:' ||
    !loopback ||
    !url.port ||
    url.username ||
    url.password ||
    (url.pathname !== '/' && url.pathname !== '') ||
    url.search ||
    url.hash
  ) {
    throw new PaidMediaServiceError('Paid media engine must be an explicit loopback HTTP origin')
  }
  return url.origin
}

function validAuthority(value: string): boolean {
  return typeof value === 'string' && value.length >= 16 && value.length <= 256 && !/[\r\n]/.test(value)
}

function boundedRetryAfter(headers: Record<string, string | undefined>): number | undefined {
  const raw = headers['retry-after'] ?? headers['Retry-After']
  if (!raw || !/^\d{1,3}$/.test(raw)) return undefined
  const seconds = Number(raw)
  return Number.isSafeInteger(seconds) && seconds >= 1 && seconds <= 900 ? seconds : undefined
}

function safeDetail(status: number, body: string): string {
  // Upstream error bodies can contain provider details or reflected input.  The
  // renderer only needs a bounded protocol outcome, never raw provider secrets.
  return body.trim() ? `Paid media request failed (${status})` : `Paid media request failed (${status})`
}

function paidVideoPollIsTerminal(result: Record<string, unknown>): boolean {
  const nested =
    result.data && typeof result.data === 'object' && !Array.isArray(result.data)
      ? (result.data as Record<string, unknown>)
      : null
  const rawStatus = result.status || nested?.status
  const status = typeof rawStatus === 'string' ? rawStatus.trim().toLowerCase() : ''
  const terminalStatuses = new Set([
      'complete',
      'completed',
      'done',
      'success',
      'succeeded',
      'failure',
      'failed',
      'error',
      'cancelled',
      'canceled'
    ])
  // A provider may expose preview URLs while still processing. Explicit
  // non-terminal status always wins over URL-shaped fields.
  if (status) return terminalStatuses.has(status)
  return [
    result.url,
    result.video_url,
    result.output_url,
    result.download_url,
    nested?.url,
    nested?.video_url,
    nested?.output_url,
    nested?.download_url
  ].some(
    (value) => typeof value === 'string' && value.trim().length > 0
  )
}

function paidVideoTaskAlias(result: Record<string, unknown>): string | null {
  const aliases = ['task_id', 'video_id', 'id']
    .map((field) => result[field])
    .filter(
      (value): value is string =>
        typeof value === 'string' && VIDEO_TASK_ALIAS_PATTERN.test(value)
    )
  if (aliases.length < 1) return null
  if (new Set(aliases).size !== 1) {
    throw new PaidMediaServiceError('Paid video task aliases are ambiguous')
  }
  return aliases[0]
}

class AsyncMutex {
  private tail: Promise<void> = Promise.resolve()
  private active = 0

  get idle(): boolean {
    return this.active === 0
  }

  async run<T>(action: () => Promise<T>): Promise<T> {
    this.active += 1
    const previous = this.tail
    let release!: () => void
    this.tail = new Promise<void>((resolve) => {
      release = resolve
    })
    await previous
    try {
      return await action()
    } finally {
      this.active -= 1
      release()
    }
  }
}

interface PaidMediaAuthorityWiring {
  readonly ledger: PaidMediaLedger
  readonly vault: PaidMediaVault
  readonly capacity: PaidMediaCapacityManager
  readonly legacySeal: Pick<PaidMediaLegacySeal, 'inspect' | 'close'>
  readonly mutationGate: PaidMediaMutationGate
  readonly evidenceReader: () => Promise<{
    ledgerIdentity: string
    ledgerSequence: number
    ledgerStateDigest: string
    vaultStateDigest: string
    capacityIdentity: string
    capacitySequence: number
    capacityStateDigest: string
    legacySealDecisionSha256: string
  }>
  readonly mutationGuard: () => void
  readonly cleanupMutationRunner: (
    operationId: string,
    action: () => Promise<void>
  ) => Promise<void>
  guardsAttached: boolean
}

const authorityWirings = new WeakMap<PaidMediaInstallationAuthority, PaidMediaAuthorityWiring>()

interface PaidMediaServiceCoordinator {
  readonly operationMutexes: Map<string, AsyncMutex>
  readonly legacyBootstrapMutex: AsyncMutex
  readonly activeRequests: Map<string, AbortController>
  readonly executingOperations: Map<string, number>
  readonly pendingCancellations: Set<string>
  installationRoot: PaidMediaInstallationAuthority | null
  remoteOperationsEnabled: boolean
  remoteOperationsPermanentlyDisabled: boolean
  installationProvisionMode: boolean | null
  localStateProvisionAllowed: boolean | null
  legacyBootstrapAllowed: boolean
  installationInitialized: boolean
  maintenancePhase: 'accepting' | 'draining' | 'quiescent'
  maintenanceGeneration: number
  maintenanceAcceptedSequence: number
  maintenanceCompletedSequence: number
  maintenanceActiveWork: number
  maintenanceEvidence: PaidMediaMaintenanceDrainEvidence | null
  readonly maintenanceWaiters: Set<(evidence: PaidMediaMaintenanceDrainEvidence) => void>
  maintenanceLastReleased: { drainGeneration: number; evidenceSha256: string } | null
  maintenanceCleanupMutationRunner:
    | ((operationId: string, action: () => Promise<void>) => Promise<void>)
    | null
  cleanupMutationExecutor:
    | ((operationId: string, action: () => Promise<void>) => Promise<void>)
    | null
}

const serviceCoordinators = new WeakMap<PaidMediaLedger, PaidMediaServiceCoordinator>()

function coordinatorFor(ledger: PaidMediaLedger): PaidMediaServiceCoordinator {
  const existing = serviceCoordinators.get(ledger)
  if (existing) return existing
  const created: PaidMediaServiceCoordinator = {
    operationMutexes: new Map(),
    legacyBootstrapMutex: new AsyncMutex(),
    activeRequests: new Map(),
    executingOperations: new Map(),
    pendingCancellations: new Set(),
    installationRoot: null,
    remoteOperationsEnabled: true,
    remoteOperationsPermanentlyDisabled: false,
    installationProvisionMode: null,
    localStateProvisionAllowed: null,
    legacyBootstrapAllowed: false,
    installationInitialized: false,
    maintenancePhase: 'accepting',
    maintenanceGeneration: 0,
    maintenanceAcceptedSequence: 0,
    maintenanceCompletedSequence: 0,
    maintenanceActiveWork: 0,
    maintenanceEvidence: null,
    maintenanceWaiters: new Set(),
    maintenanceLastReleased: null,
    maintenanceCleanupMutationRunner: null,
    cleanupMutationExecutor: null
  }
  serviceCoordinators.set(ledger, created)
  return created
}

function requireClosedLegacySeal(status: PaidMediaLegacySealStatus): Extract<
  PaidMediaLegacySealStatus,
  { state: 'closed' }
> {
  if (status.state !== 'closed') {
    throw new PaidMediaServiceError('Paid media legacy migration seal is still open')
  }
  return status
}

export class PaidMediaService {
  private readonly coordinator: PaidMediaServiceCoordinator
  private readonly authorityWiring: PaidMediaAuthorityWiring | null

  constructor(private readonly dependencies: PaidMediaServiceDependencies) {
    this.coordinator = coordinatorFor(dependencies.ledger)
    this.authorityWiring = this.prepareAuthorityWiring()
    if (dependencies.installationRoot) {
      if (
        this.coordinator.installationRoot &&
        this.coordinator.installationRoot !== dependencies.installationRoot
      ) {
        throw new PaidMediaServiceError(
          'Paid media local state is already bound to another Installation Root'
        )
      }
      if (!this.coordinator.installationRoot) {
        this.coordinator.installationRoot = dependencies.installationRoot
        this.remoteOperationsEnabled = false
      }
    }
    if (this.authorityWiring) {
      const existingExecutor = this.coordinator.cleanupMutationExecutor
      if (
        existingExecutor !== null &&
        existingExecutor !== this.authorityWiring.cleanupMutationRunner
      ) {
        throw new PaidMediaServiceError(
          'Paid media cleanup retry is already bound to another Installation Root'
        )
      }
      this.coordinator.cleanupMutationExecutor = this.authorityWiring.cleanupMutationRunner
    }
    if (!this.coordinator.maintenanceCleanupMutationRunner) {
      const coordinator = this.coordinator
      this.coordinator.maintenanceCleanupMutationRunner = async (operationId, action) =>
        this.runMaintenanceTrackedWork(async () => {
          const executor = coordinator.cleanupMutationExecutor
          if (executor) {
            await executor(operationId, action)
            return
          }
          await action()
        })
    }
    if (typeof dependencies.vault.setCleanupMutationRunner === 'function') {
      dependencies.vault.setCleanupMutationRunner(
        this.coordinator.maintenanceCleanupMutationRunner
      )
    }
    this.dependencies.vault.setCleanupRecoveredHandler(() => {
      void this.reconcileCapacityOnStartup().catch(() => undefined)
    })
  }

  private get operationMutexes(): Map<string, AsyncMutex> {
    return this.coordinator.operationMutexes
  }

  private get activeRequests(): Map<string, AbortController> {
    return this.coordinator.activeRequests
  }

  private get executingOperations(): Map<string, number> {
    return this.coordinator.executingOperations
  }

  private get pendingCancellations(): Set<string> {
    return this.coordinator.pendingCancellations
  }

  private maintenanceInternalsIdle(): boolean {
    return (
      this.operationMutexes.size === 0 &&
      this.activeRequests.size === 0 &&
      this.executingOperations.size === 0 &&
      this.pendingCancellations.size === 0 &&
      this.coordinator.legacyBootstrapMutex.idle
    )
  }

  private completeMaintenanceDrainIfReady(): void {
    if (
      this.coordinator.maintenancePhase !== 'draining' ||
      this.coordinator.maintenanceActiveWork !== 0 ||
      this.coordinator.maintenanceAcceptedSequence !==
        this.coordinator.maintenanceCompletedSequence ||
      !this.maintenanceInternalsIdle()
    ) {
      return
    }
    const payload: PaidMediaMaintenanceEvidencePayload = {
      schema: MAINTENANCE_EVIDENCE_SCHEMA,
      scope: MAINTENANCE_SCOPE,
      drainGeneration: this.coordinator.maintenanceGeneration,
      acceptedSequence: this.coordinator.maintenanceAcceptedSequence,
      completedSequence: this.coordinator.maintenanceCompletedSequence,
      activeWorkCount: 0,
      operationMutexCount: 0,
      activeRequestCount: 0,
      executingOperationCount: 0,
      pendingCancellationCount: 0,
      legacyBootstrapIdle: true
    }
    const evidence = Object.freeze({
      ...payload,
      evidenceSha256: maintenanceEvidenceSha256(payload)
    })
    this.coordinator.maintenanceEvidence = evidence
    this.coordinator.maintenancePhase = 'quiescent'
    for (const resolve of this.coordinator.maintenanceWaiters) resolve(evidence)
    this.coordinator.maintenanceWaiters.clear()
  }

  private acceptMaintenanceTrackedWork(): () => void {
    if (this.coordinator.maintenancePhase !== 'accepting') {
      throw new PaidMediaServiceError('Paid media maintenance drain is active')
    }
    if (this.coordinator.maintenanceAcceptedSequence >= Number.MAX_SAFE_INTEGER) {
      throw new PaidMediaServiceError('Paid media maintenance sequence is exhausted')
    }
    this.coordinator.maintenanceAcceptedSequence += 1
    this.coordinator.maintenanceActiveWork += 1
    let completed = false
    return () => {
      if (completed) return
      completed = true
      this.coordinator.maintenanceActiveWork -= 1
      this.coordinator.maintenanceCompletedSequence += 1
      this.completeMaintenanceDrainIfReady()
    }
  }

  private async runMaintenanceTrackedWork<T>(action: () => Promise<T>): Promise<T> {
    const complete = this.acceptMaintenanceTrackedWork()
    try {
      return await action()
    } finally {
      complete()
    }
  }

  /**
   * Fence only work accepted through this shared Desktop Main service coordinator.
   * It is not a cross-process, filesystem-handle, ACL, or LocalService proof.
  */
  enterMaintenanceDrain(): Promise<PaidMediaMaintenanceDrainEvidence> {
    if (
      this.coordinator.maintenancePhase === 'quiescent' &&
      this.coordinator.maintenanceEvidence
    ) {
      return Promise.resolve(this.coordinator.maintenanceEvidence)
    }
    if (this.coordinator.maintenancePhase === 'accepting') {
      if (this.coordinator.maintenanceGeneration >= Number.MAX_SAFE_INTEGER) {
        return Promise.reject(
          new PaidMediaServiceError('Paid media maintenance generation is exhausted')
        )
      }
      this.coordinator.maintenanceGeneration += 1
      this.coordinator.maintenancePhase = 'draining'
      this.coordinator.maintenanceEvidence = null
    }
    const waiting = new Promise<PaidMediaMaintenanceDrainEvidence>((resolve) => {
      this.coordinator.maintenanceWaiters.add(resolve)
    })
    this.completeMaintenanceDrainIfReady()
    return waiting
  }

  inspectMaintenanceDrain(): PaidMediaMaintenanceDrainStatus {
    return Object.freeze({
      schema: MAINTENANCE_STATUS_SCHEMA,
      scope: MAINTENANCE_SCOPE,
      phase: this.coordinator.maintenancePhase,
      drainGeneration: this.coordinator.maintenanceGeneration,
      acceptedSequence: this.coordinator.maintenanceAcceptedSequence,
      completedSequence: this.coordinator.maintenanceCompletedSequence,
      activeWorkCount: this.coordinator.maintenanceActiveWork
    })
  }

  releaseMaintenanceDrain(evidence: PaidMediaMaintenanceDrainEvidence): boolean {
    if (!validMaintenanceEvidence(evidence)) return false
    if (this.coordinator.maintenancePhase === 'accepting') {
      return (
        this.coordinator.maintenanceLastReleased?.drainGeneration ===
          evidence.drainGeneration &&
        this.coordinator.maintenanceLastReleased.evidenceSha256 === evidence.evidenceSha256
      )
    }
    const current = this.coordinator.maintenanceEvidence
    if (
      this.coordinator.maintenancePhase !== 'quiescent' ||
      !current ||
      current.drainGeneration !== evidence.drainGeneration ||
      current.evidenceSha256 !== evidence.evidenceSha256 ||
      !this.maintenanceInternalsIdle() ||
      this.coordinator.maintenanceActiveWork !== 0
    ) {
      return false
    }
    this.coordinator.maintenanceLastReleased = {
      drainGeneration: current.drainGeneration,
      evidenceSha256: current.evidenceSha256
    }
    this.coordinator.maintenanceEvidence = null
    this.coordinator.maintenancePhase = 'accepting'
    return true
  }

  private get remoteOperationsEnabled(): boolean {
    return this.coordinator.remoteOperationsEnabled
  }

  private set remoteOperationsEnabled(value: boolean) {
    this.coordinator.remoteOperationsEnabled = value
  }

  private prepareAuthorityWiring(): PaidMediaAuthorityWiring | null {
    const authority = this.dependencies.installationRoot
    if (!authority) return null
    const legacySeal = this.dependencies.legacySeal
    if (!legacySeal) {
      throw new PaidMediaServiceError(
        'Paid media Installation Root requires a legacy migration seal'
      )
    }
    const existing = authorityWirings.get(authority)
    if (existing) {
      if (
        existing.ledger !== this.dependencies.ledger ||
        existing.vault !== this.dependencies.vault ||
        existing.capacity !== this.dependencies.capacity ||
        existing.legacySeal !== legacySeal ||
        (this.dependencies.mutationGate !== undefined &&
          existing.mutationGate !== this.dependencies.mutationGate)
      ) {
        throw new PaidMediaServiceError(
          'Paid media Installation Root is already bound to another local state set'
        )
      }
      return existing
    }
    const mutationGate = this.dependencies.mutationGate ?? new PaidMediaMutationGate(authority)
    if (!mutationGate.isBoundTo(authority)) {
      throw new PaidMediaServiceError(
        'Paid media mutation gate is bound to another Installation Root'
      )
    }
    let wiring!: PaidMediaAuthorityWiring
    const evidenceReader = async () => {
      const [ledger, vault, capacity, legacy] = await Promise.all([
        this.dependencies.ledger.inspectAuthorityEvidence(),
        this.dependencies.vault.inspectAuthorityEvidence(),
        this.dependencies.capacity.inspectAuthorityEvidence(),
        legacySeal.inspect()
      ])
      const closed = requireClosedLegacySeal(legacy)
      return {
        ledgerIdentity: ledger.ledgerIdentity,
        ledgerSequence: ledger.ledgerSequence,
        ledgerStateDigest: ledger.ledgerStateDigest,
        vaultStateDigest: vault.vaultStateDigest,
        capacityIdentity: capacity.capacityIdentity,
        capacitySequence: capacity.capacitySequence,
        capacityStateDigest: capacity.capacityStateDigest,
        legacySealDecisionSha256: closed.decision.decisionSha256
      }
    }
    const mutationGuard = mutationGate.guard
    const cleanupMutationRunner = async (
      operationId: string,
      action: () => Promise<void>
    ): Promise<void> => {
      await authority.runMutation({ kind: 'cleanup_retry', operationId }, async (context) =>
        mutationGate.runLegacy(
          { transactionId: context.transactionId, kind: 'cleanup_retry', operationId },
          action
        )
      )
    }
    wiring = {
      ledger: this.dependencies.ledger,
      vault: this.dependencies.vault,
      capacity: this.dependencies.capacity,
      legacySeal,
      mutationGate,
      evidenceReader,
      mutationGuard,
      cleanupMutationRunner,
      guardsAttached: false
    }
    authority.attachEvidenceReader(evidenceReader)
    authorityWirings.set(authority, wiring)
    return wiring
  }

  private attachMutationGuards(): void {
    const wiring = this.authorityWiring
    if (!wiring || wiring.guardsAttached) return
    wiring.ledger.setMutationGuard(wiring.mutationGuard)
    wiring.vault.setMutationGuard(wiring.mutationGuard)
    wiring.capacity.setMutationGuard(wiring.mutationGuard)
    const cleanupRunner = this.coordinator.maintenanceCleanupMutationRunner
    if (!cleanupRunner) {
      throw new PaidMediaServiceError('Paid media maintenance cleanup runner is unavailable')
    }
    wiring.vault.setCleanupMutationRunner(cleanupRunner)
    wiring.guardsAttached = true
  }

  private async withOperation<T>(operationId: string, action: () => Promise<T>): Promise<T> {
    const mutex = this.operationMutexes.get(operationId) ?? new AsyncMutex()
    this.operationMutexes.set(operationId, mutex)
    try {
      return await mutex.run(action)
    } finally {
      if (mutex.idle && this.operationMutexes.get(operationId) === mutex) {
        this.operationMutexes.delete(operationId)
      }
    }
  }

  withAuthorities(
    authorities: Pick<
      PaidMediaServiceDependencies,
      'runtimeKey' | 'approvalKey' | 'paidMediaKey'
    >
  ): PaidMediaService {
    const service = new PaidMediaService({ ...this.dependencies, ...authorities })
    service.remoteOperationsEnabled = this.remoteOperationsEnabled
    return service
  }

  private runLocalMutation<T>(
    kind: string,
    operationId: string | undefined,
    action: (context: PaidMediaAuthorityMutationContext) => Promise<T>
  ): Promise<T> {
    const authority = this.dependencies.installationRoot
    if (authority) {
      const wiring = this.authorityWiring
      if (!wiring) {
        throw new PaidMediaServiceError('Paid media Root transaction wiring is unavailable')
      }
      return authority.runMutation(
        { kind, ...(operationId === undefined ? {} : { operationId }) },
        (context) =>
          wiring.mutationGate.runLegacy(
            {
              transactionId: context.transactionId,
              kind,
              operationId: operationId ?? null
            },
            () => action(context)
          )
      )
    }
    return action({
      transactionId: '00000000-0000-4000-8000-000000000000',
      assertOutboundReady: async () => undefined
    })
  }

  private async runRecoverableMutation(
    operationId: string,
    payload: PaidMediaRecoveryIntentPayload
  ): Promise<PaidMediaRecoveryIntentDescriptor> {
    const authority = this.dependencies.installationRoot
    const intentStore = this.dependencies.recoveryIntentStore
    if (
      !authority ||
      typeof authority.runRecoverableMutation !== 'function' ||
      !intentStore ||
      typeof intentStore.prepare !== 'function'
    ) {
      throw new PaidMediaServiceError(
        'Paid media recoverable mutation wiring is unavailable'
      )
    }
    if (payload.operationId !== operationId) {
      throw new PaidMediaServiceError(
        'Paid media recoverable mutation operation binding conflicts'
      )
    }
    const descriptor = await intentStore.prepare(payload)
    if (
      descriptor.kind !== payload.kind ||
      descriptor.operationId !== operationId
    ) {
      throw new PaidMediaServiceError(
        'Paid media recovery intent descriptor binding conflicts'
      )
    }
    const state = await authority.runRecoverableMutation(descriptor)
    if (state.mode !== 'ready') {
      throw new PaidMediaServiceError(
        'Paid media recoverable mutation did not reach an exact Root commit'
      )
    }
    return descriptor
  }

  private recoveryDomainSha256(): string {
    const authority = this.dependencies.installationRoot
    if (authority) return authority.localPaidPrincipal()
    return recoveryDomainDigest(this.validateAuthorities().paidMediaKey)
  }

  private legacyCandidateInput(
    status: Extract<PaidMediaLegacySealStatus, { state: 'closed' }>
  ): PaidMediaLegacyUnresolvedInput | null {
    if (status.decision.kind === 'empty') return null
    const candidate = status.decision.candidate
    return {
      operationId: candidate.operationId,
      path: candidate.path,
      requestSha256: candidate.requestSha256,
      createdAt: candidate.createdAt,
      updatedAt: candidate.updatedAt,
      state: candidate.state,
      ...(candidate.state === 'recoverable'
        ? { lastStatus: Number(candidate.lastStatus) }
        : {}),
      ...(candidate.retryAfterSeconds === undefined
        ? {}
        : { retryAfterSeconds: candidate.retryAfterSeconds })
    }
  }

  private async importClosedLegacyCandidate(
    status: Extract<PaidMediaLegacySealStatus, { state: 'closed' }>
  ): Promise<boolean> {
    const input = this.legacyCandidateInput(status)
    if (!input) return false
    const receiptInput = {
      decisionSha256: status.decision.decisionSha256,
      operationId: input.operationId
    }
    if (await this.dependencies.vault.hasLegacyImportReceipt(receiptInput)) return true
    await this.runLocalMutation('legacy_import', input.operationId, async () => {
      await this.dependencies.ledger.importLegacyUnresolved(input)
      await this.dependencies.vault.recordLegacyImportReceipt(receiptInput)
    })
    return true
  }

  private async migrateTrustedValidationReceipts(preBinding: boolean): Promise<void> {
    let cursor: string | undefined
    do {
      let batch: Awaited<ReturnType<PaidMediaVault['prepareTrustedValidationMigrationBatch']>>
      try {
        batch = await this.dependencies.vault.prepareTrustedValidationMigrationBatch({
          ...(cursor === undefined ? {} : { cursor }),
          limit: 16
        })
      } catch (error) {
        if (!preBinding) {
          // The Root already attested the legacy state. Persist a pending
          // migration intent before surfacing a probe/enumeration failure so a
          // restart cannot mistake the old proof for a fully migrated state.
          try {
            await this.runLocalMutation('validation_migration', undefined, async () => {
              throw error
            })
          } catch (fused) {
            throw new PaidMediaServiceError(
              'Paid media trusted validation migration preparation failed',
              { cause: fused }
            )
          }
        }
        throw new PaidMediaServiceError(
          'Paid media trusted validation migration preparation failed',
          { cause: error }
        )
      }
      if (batch.items.length > 0) {
        if (preBinding) {
          await this.dependencies.vault.commitTrustedValidationMigrations(batch.items)
        } else {
          await this.runLocalMutation('validation_migration', undefined, () =>
            this.dependencies.vault.commitTrustedValidationMigrations(batch.items)
          )
        }
      }
      cursor = batch.nextCursor
    } while (cursor !== undefined)
  }

  async initializeInstallationAuthority(input: {
    provision: boolean
    provisionLocalState: boolean
  }): Promise<PaidMediaInstallationInitializationResult> {
    return this.runMaintenanceTrackedWork(() =>
      this.initializeInstallationAuthorityUnfenced(input)
    )
  }

  private async initializeInstallationAuthorityUnfenced(input: {
    provision: boolean
    provisionLocalState: boolean
  }): Promise<PaidMediaInstallationInitializationResult> {
    if (
      !input ||
      typeof input !== 'object' ||
      !exactKeys(input as unknown as Record<string, unknown>, [
        'provision',
        'provisionLocalState'
      ]) ||
      typeof input.provision !== 'boolean' ||
      typeof input.provisionLocalState !== 'boolean' ||
      (input.provisionLocalState && !input.provision)
    ) {
      throw new PaidMediaServiceError('Paid media Installation Root initialization is invalid')
    }
    const authority = this.dependencies.installationRoot
    const wiring = this.authorityWiring
    if (!authority || !wiring) {
      throw new PaidMediaServiceError('Paid media Installation Root is not configured')
    }
    this.remoteOperationsEnabled = false
    let closed: Extract<PaidMediaLegacySealStatus, { state: 'closed' }> | null = null
    try {
      closed = requireClosedLegacySeal(await wiring.legacySeal.inspect())
      if (input.provisionLocalState) {
        await wiring.ledger.provisionAuthorityLedger()
        await this.migrateTrustedValidationReceipts(true)
        await wiring.vault.provisionAuthorityVault()
        await wiring.capacity.provisionAuthorityJournal()
      }
      if (!input.provisionLocalState) this.attachMutationGuards()
      let state = input.provision
        ? await authority.provision()
        : await authority.reconcileStartup()
      this.attachMutationGuards()
      let recoveredThisBoot = false
      if (state.mode === 'recovery_pending') {
        const pending = state.pendingRecovery
        if (!pending || typeof authority.resumeRecoverableMutation !== 'function') {
          throw new PaidMediaServiceError(
            'Paid media recoverable startup executor is unavailable'
          )
        }
        try {
          state = await authority.resumeRecoverableMutation({
            handlerVersion: pending.handlerVersion,
            kind: pending.kind,
            operationId: pending.operationId,
            intentSha256: pending.intentSha256
          })
          recoveredThisBoot = state.mode === 'ready'
        } catch (error) {
          // A closed-set executor deliberately moves unsupported recovery
          // kinds to manual_only. Keep the local, read-only control plane
          // available in this same boot instead of requiring a second restart.
          const afterRecovery = authority.state
          if (afterRecovery.mode !== 'manual_only') throw error
          state = afterRecovery
        }
      }
      if (state.mode !== 'ready') {
        this.coordinator.installationInitialized = true
        return {
          authority: state,
          legacyDecisionSha256: closed.decision.decisionSha256,
          legacyImported: false,
          capacity: null
        }
      }
      if (recoveredThisBoot) {
        // The exact recovery transaction is the only mutation allowed in this
        // boot. Legacy validation probing/import/capacity reconciliation are
        // deferred to the next clean startup, with remote work still disabled.
        this.coordinator.installationInitialized = true
        return {
          authority: state,
          legacyDecisionSha256: closed.decision.decisionSha256,
          legacyImported: false,
          capacity: null
        }
      }
      if (!input.provisionLocalState) {
        await this.migrateTrustedValidationReceipts(false)
      }
      const legacyImported = await this.importClosedLegacyCandidate(closed)
      const capacity = await this.reconcileCapacityOnStartupUnfenced()
      this.remoteOperationsEnabled = !this.coordinator.remoteOperationsPermanentlyDisabled
      this.coordinator.installationInitialized = true
      return {
        authority: authority.state,
        legacyDecisionSha256: closed.decision.decisionSha256,
        legacyImported,
        capacity
      }
    } catch (error) {
      this.remoteOperationsEnabled = false
      throw new PaidMediaServiceError('Paid media Installation Root initialization failed', {
        cause: error
      })
    } finally {
      // Even a damaged/missing Root must never leave a later manual IPC call
      // with direct write access to the ledger, vault, or capacity journal.
      this.attachMutationGuards()
    }
  }

  async prepareInstallationAuthority(input: {
    provision: boolean
    provisionLocalState: boolean
    allowLegacyBootstrap: boolean
  }): Promise<
    | { state: 'legacy_bootstrap_required' }
    | PaidMediaInstallationInitializationResult
  > {
    return this.runMaintenanceTrackedWork(() =>
      this.prepareInstallationAuthorityUnfenced(input)
    )
  }

  private async prepareInstallationAuthorityUnfenced(input: {
    provision: boolean
    provisionLocalState: boolean
    allowLegacyBootstrap: boolean
  }): Promise<
    | { state: 'legacy_bootstrap_required' }
    | PaidMediaInstallationInitializationResult
  > {
    if (
      !input ||
      typeof input !== 'object' ||
      !exactKeys(input as unknown as Record<string, unknown>, [
        'provision',
        'provisionLocalState',
        'allowLegacyBootstrap'
      ]) ||
      typeof input.provision !== 'boolean' ||
      typeof input.provisionLocalState !== 'boolean' ||
      typeof input.allowLegacyBootstrap !== 'boolean' ||
      (input.provisionLocalState && !input.provision) ||
      (input.allowLegacyBootstrap &&
        (!input.provision || !input.provisionLocalState))
    ) {
      throw new PaidMediaServiceError('Paid media Installation Root preparation is invalid')
    }
    if (!this.authorityWiring) {
      throw new PaidMediaServiceError('Paid media Installation Root is not configured')
    }
    return this.coordinator.legacyBootstrapMutex.run(async () => {
      const configuredMode = this.coordinator.installationProvisionMode
      if (configuredMode !== null && configuredMode !== input.provision) {
        throw new PaidMediaServiceError(
          'Paid media Installation Root preparation mode conflicts with another wrapper'
        )
      }
      const configuredLocalProvision = this.coordinator.localStateProvisionAllowed
      if (
        configuredLocalProvision !== null &&
        configuredLocalProvision !== input.provisionLocalState
      ) {
        throw new PaidMediaServiceError(
          'Paid media local-state provisioning mode conflicts with another wrapper'
        )
      }
      this.coordinator.installationProvisionMode = input.provision
      this.coordinator.localStateProvisionAllowed = input.provisionLocalState
      this.remoteOperationsEnabled = false
      const status = await this.authorityWiring!.legacySeal.inspect()
      if (status.state === 'open') {
        if (!input.allowLegacyBootstrap) {
          this.coordinator.legacyBootstrapAllowed = false
          throw new PaidMediaServiceError(
            'Paid media legacy seal is open outside the first Desktop provisioning window'
          )
        }
        this.coordinator.legacyBootstrapAllowed = true
        return { state: 'legacy_bootstrap_required' }
      }
      // Once a durable decision exists, no wrapper may ever re-enter the
      // one-time close branch. Candidate/null retries are verified read-only.
      this.coordinator.legacyBootstrapAllowed = false
      return this.initializeInstallationAuthorityUnfenced({
        provision: input.provision,
        provisionLocalState: input.provisionLocalState
      })
    })
  }

  async bootstrapLegacyMigration(
    input: PaidMediaLegacyBootstrapInput
  ): Promise<PaidMediaPublicOperation | { state: 'closed'; decisionSha256: string }> {
    return this.runMaintenanceTrackedWork(() => this.bootstrapLegacyMigrationUnfenced(input))
  }

  private async bootstrapLegacyMigrationUnfenced(
    input: PaidMediaLegacyBootstrapInput
  ): Promise<PaidMediaPublicOperation | { state: 'closed'; decisionSha256: string }> {
    return this.coordinator.legacyBootstrapMutex.run(async () => {
      const wiring = this.authorityWiring
      const provisionMode = this.coordinator.installationProvisionMode
      const provisionLocalState = this.coordinator.localStateProvisionAllowed
      if (!wiring || provisionMode === null || provisionLocalState === null) {
        throw new PaidMediaServiceError('Paid media legacy bootstrap is not prepared')
      }
      const migratedReplay =
        input !== null &&
        typeof input === 'object' &&
        !Array.isArray(input) &&
        exactKeys(input as unknown as Record<string, unknown>, ['kind']) &&
        (input as { kind?: unknown }).kind === 'migrated'
      if (
        !migratedReplay &&
        input !== null &&
        typeof input === 'object' &&
        !Array.isArray(input) &&
        Object.prototype.hasOwnProperty.call(input, 'kind')
      ) {
        throw new PaidMediaServiceError('Paid media legacy bootstrap decision is invalid')
      }

      let status = await wiring.legacySeal.inspect()
      if (status.state === 'open') {
        if (migratedReplay) {
          throw new PaidMediaServiceError(
            'Renderer migration sentinel cannot close the durable legacy seal'
          )
        }
        if (!this.coordinator.legacyBootstrapAllowed) {
          throw new PaidMediaServiceError(
            'Paid media legacy bootstrap is not allowed after Desktop binding'
          )
        }
        const decision =
          input === null
            ? ({ kind: 'empty' } as const)
            : ({ kind: 'candidate', candidate: input as PaidMediaLegacyUnresolvedInput } as const)
        status = await wiring.legacySeal.close(decision)
        // Closing the seal consumes the shared capability even when the Root
        // initialization that follows is interrupted. A retry can only verify
        // and replay this exact closed decision.
        this.coordinator.legacyBootstrapAllowed = false
      }

      const closed = requireClosedLegacySeal(status)
      const expected = this.legacyCandidateInput(closed)
      if (
        !migratedReplay &&
        ((input === null) !== (expected === null) ||
          (input !== null && JSON.stringify(input) !== JSON.stringify(expected)))
      ) {
        throw new PaidMediaServiceError(
          'Paid media legacy bootstrap conflicts with the sealed decision'
        )
      }
      if (!this.coordinator.installationInitialized) {
        await this.initializeInstallationAuthorityUnfenced({
          provision: provisionMode,
          provisionLocalState
        })
      }
      if (!expected) {
        return { state: 'closed', decisionSha256: closed.decision.decisionSha256 }
      }
      const imported = (await this.dependencies.ledger.listPublic()).find(
        (operation) => operation.operationId === expected.operationId
      )
      if (!imported) {
        throw new PaidMediaServiceError('Paid media legacy import receipt is incomplete')
      }
      return imported
    })
  }

  disableRemoteOperations(): void {
    this.coordinator.remoteOperationsPermanentlyDisabled = true
    this.remoteOperationsEnabled = false
  }

  private assertRemoteOperationsEnabled(): void {
    if (!this.remoteOperationsEnabled) {
      throw new PaidMediaServiceError(
        'Paid media remote operations are disabled until Installation Root and capacity reconciliation succeed'
      )
    }
  }

  private assetV2ImageReady(path: PaidMediaPath): boolean {
    return path === '/v1/images/generations' && this.dependencies.assetV2?.isReady() === true
  }

  private assertInstallationReadable(): void {
    const authority = this.dependencies.installationRoot
    if (!authority) return
    if (
      !this.coordinator.installationInitialized ||
      (authority.state.mode !== 'ready' && authority.state.mode !== 'manual_only')
    ) {
      throw new PaidMediaServiceError(
        'Paid media local state is unavailable until Installation Root initialization succeeds'
      )
    }
  }

  async ensureMediaProbeReady(): Promise<void> {
    return this.runMaintenanceTrackedWork(() => this.ensureMediaProbeReadyUnfenced())
  }

  private async ensureMediaProbeReadyUnfenced(): Promise<void> {
    this.assertRemoteOperationsEnabled()
    await this.dependencies.installationRoot?.assertOutboundReady()
    await this.dependencies.vault.ensureMediaProbeReady()
  }

  private validateAuthorities(): {
    runtimeKey: string
    paidMediaKey: string
  } {
    const runtimeKey = this.dependencies.runtimeKey()
    const approvalKey = this.dependencies.approvalKey()
    const paidMediaKey = this.dependencies.paidMediaKey()
    if (
      !validAuthority(runtimeKey) ||
      !validAuthority(approvalKey) ||
      !validAuthority(paidMediaKey) ||
      new Set([runtimeKey, approvalKey, paidMediaKey]).size !== 3
    ) {
      throw new PaidMediaServiceError('Paid media authority is unavailable or overlaps another capability')
    }
    return {
      runtimeKey,
      paidMediaKey
    }
  }

  private validateClaim(input: PaidMediaClaimRequest): {
    path: PaidMediaPath
    encodedBody: string
    retryOperationId?: string
  } {
    if (!input || typeof input !== 'object') {
      throw new PaidMediaServiceError('Paid media claim is invalid')
    }
    const raw = input as unknown as Record<string, unknown>
    const retry = Object.prototype.hasOwnProperty.call(raw, 'retryOperationId')
    if (
      !exactKeys(
        raw,
        retry ? ['path', 'encodedBody', 'retryOperationId'] : ['path', 'encodedBody']
      ) ||
      !validPath(input.path) ||
      (retry &&
        (typeof input.retryOperationId !== 'string' ||
          !OPERATION_ID_PATTERN.test(input.retryOperationId)))
    ) {
      throw new PaidMediaServiceError('Paid media claim is invalid')
    }
    return {
      path: input.path,
      encodedBody: validateBody(input.encodedBody, input.path),
      ...(retry ? { retryOperationId: input.retryOperationId } : {})
    }
  }

  async claim(input: PaidMediaClaimRequest): Promise<PaidMediaPublicOperation> {
    return this.runMaintenanceTrackedWork(() => this.claimUnfenced(input))
  }

  private async claimUnfenced(input: PaidMediaClaimRequest): Promise<PaidMediaPublicOperation> {
    const value = this.validateClaim(input)
    this.assertInstallationReadable()
    const recoveryDomainSha256 = this.recoveryDomainSha256()
    if (value.retryOperationId !== undefined) {
      const claimed = await this.dependencies.ledger.claim({
        path: value.path,
        requestSha256: requestDigest(value.encodedBody),
        recoveryDomainSha256,
        retryOperationId: value.retryOperationId
      })
      await this.dependencies.vault.verifyExactRequest({
        operationId: claimed.operation.operationId,
        path: value.path,
        encodedBody: value.encodedBody
      })
      return claimed.operation
    }

    if (this.assetV2ImageReady(value.path)) {
      await this.dependencies.installationRoot?.assertOutboundReady()
    } else {
      this.assertRemoteOperationsEnabled()
      await this.ensureMediaProbeReadyUnfenced()
      this.validateAuthorities()
    }
    return this.runLocalMutation('claim', undefined, async () => {
      const claimed = await this.dependencies.ledger.claim({
        path: value.path,
        requestSha256: requestDigest(value.encodedBody),
        recoveryDomainSha256
      })
      try {
        await this.dependencies.vault.recordClaim({
          operationId: claimed.operation.operationId,
          path: value.path,
          encodedBody: value.encodedBody
        })
      } catch (error) {
        if (claimed.operation.state === 'claimed' && claimed.operation.dispatchCount === 0) {
          try {
            await this.dependencies.ledger.reconcile({
              operationId: claimed.operation.operationId,
              reason: 'main-vault-claim-failed',
              evidence: 'exact request archive could not be committed before dispatch'
            })
          } catch {
            // Keep the unresolved ledger claim when even the zero-dispatch
            // tombstone cannot be committed; never continue to provider.
          }
        }
        throw new PaidMediaServiceError('Paid media exact request archive failed', {
          cause: error
        })
      }
      return claimed.operation
    })
  }

  async pollVideo(input: PaidVideoPollRequest): Promise<Record<string, unknown>> {
    return this.runMaintenanceTrackedWork(() => this.pollVideoUnfenced(input))
  }

  private async pollVideoUnfenced(
    input: PaidVideoPollRequest
  ): Promise<Record<string, unknown>> {
    if (
      !input ||
      typeof input !== 'object' ||
      !exactKeys(input as unknown as Record<string, unknown>, ['taskAlias', 'model']) ||
      typeof input.taskAlias !== 'string' ||
      !VIDEO_TASK_ALIAS_PATTERN.test(input.taskAlias) ||
      typeof input.model !== 'string' ||
      !input.model.trim() ||
      codePointLength(input.model.trim()) > MAX_MODEL_CODE_POINTS ||
      /[\u0000-\u001f\u007f]/.test(input.model)
    ) {
      throw new PaidMediaServiceError('Paid video poll request is invalid')
    }
    this.assertInstallationReadable()
    if (this.dependencies.vault.hasTerminalMediaForTask(input.taskAlias)) {
      const terminal = await this.dependencies.vault.verifyTerminalMediaForTask(input.taskAlias)
      const exactRequest = await this.dependencies.vault.readExactRequest(terminal.operationId)
      if (
        exactRequest.path !== '/v1/videos/generations' ||
        inspectPaidMediaRequestBody(exactRequest.encodedBody, exactRequest.path).model !==
          input.model.trim()
      ) {
        throw new PaidMediaServiceError(
          'Paid video terminal archive does not match the requested creation model'
        )
      }
      if (!this.dependencies.installationRoot && terminal.cleanupComplete) {
        try {
          await this.dependencies.capacity.ensureReleasedWithAuthorization({
            operationId: terminal.operationId,
            authorizationReceiptSha256: terminal.receiptSha256
          })
        } catch {
          // Legacy unrooted callers retain their historical best-effort
          // convergence. Rooted production replay is strictly read-only.
        }
      }
      return terminal.result
    }
    this.assertRemoteOperationsEnabled()
    const binding = await this.dependencies.vault.verifyVideoTaskBinding(input.taskAlias)
    const exactRequest = await this.dependencies.vault.readExactRequest(binding.operationId)
    if (
      exactRequest.path !== '/v1/videos/generations' ||
      inspectPaidMediaRequestBody(exactRequest.encodedBody, exactRequest.path).model !==
        input.model.trim()
    ) {
      throw new PaidMediaServiceError(
        'Paid video task binding does not match the requested creation model'
      )
    }
    try {
      await this.dependencies.capacity.verifyVideoTaskBinding({
        operationId: binding.operationId,
        taskAliasSha256: binding.taskAliasSha256
      })
    } catch (error) {
      throw new PaidMediaServiceError('Paid video capacity binding failed', { cause: error })
    }
    const { runtimeKey, paidMediaKey } = this.validateAuthorities()
    const baseUrl = validateLoopbackBaseUrl(this.dependencies.baseUrl())
    const path = `/v1/videos/${input.taskAlias}`
    const controller = new AbortController()
    await this.dependencies.installationRoot?.assertOutboundReady()
    const response = await this.dependencies.transport({
      method: 'GET',
      url: `${baseUrl}${path}?model=${encodeURIComponent(input.model.trim())}`,
      path,
      encodedBody: '',
      headers: {
        Authorization: `Bearer ${runtimeKey}`,
        'X-Nachuan-Paid-Media-Key': paidMediaKey,
        Accept: 'application/json'
      },
      signal: controller.signal,
      responseByteLimit: MAX_POLL_RESPONSE_BYTES
    })
    if (
      !Number.isInteger(response.status) ||
      response.status < 200 ||
      response.status >= 300 ||
      Buffer.byteLength(response.body, 'utf8') > MAX_POLL_RESPONSE_BYTES
    ) {
      throw new PaidMediaServiceError(`Paid video poll failed (${response.status})`)
    }
    let parsed: unknown
    try {
      parsed = JSON.parse(response.body)
    } catch (error) {
      throw new PaidMediaServiceError('Paid video poll response is invalid', { cause: error })
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new PaidMediaServiceError('Paid video poll response is invalid')
    }
    const result = parsed as Record<string, unknown>
    if (!paidVideoPollIsTerminal(result)) return result
    return this.runLocalMutation('terminal_archive', binding.operationId, async () => {
      try {
        await this.dependencies.capacity.verifyVideoTaskBinding({
          operationId: binding.operationId,
          taskAliasSha256: binding.taskAliasSha256
        })
      } catch (error) {
        throw new PaidMediaServiceError('Paid video terminal capacity recheck failed', {
          cause: error
        })
      }
      const terminal = await this.dependencies.vault.archiveTerminalMediaForTask(
        input.taskAlias,
        result
      )
      if (terminal.cleanupComplete) {
        await this.dependencies.capacity.ensureReleasedWithAuthorization({
          operationId: binding.operationId,
          authorizationReceiptSha256: terminal.receiptSha256
        })
      }
      return terminal.result
    })
  }

  async execute(input: PaidMediaExecuteRequest): Promise<PaidMediaExecutionResult> {
    return this.runMaintenanceTrackedWork(() => this.executeUnfenced(input))
  }

  private async executeUnfenced(
    input: PaidMediaExecuteRequest
  ): Promise<PaidMediaExecutionResult> {
    if (
      !input ||
      typeof input !== 'object' ||
      !exactKeys(input as unknown as Record<string, unknown>, [
        'operationId',
        'path',
        'encodedBody'
      ]) ||
      typeof input.operationId !== 'string' ||
      !OPERATION_ID_PATTERN.test(input.operationId) ||
      !validPath(input.path)
    ) {
      throw new PaidMediaServiceError('Paid media execution request is invalid')
    }
    this.assertInstallationReadable()
    const encodedBody = validateBody(input.encodedBody, input.path)
    const operationId = input.operationId
    this.executingOperations.set(operationId, (this.executingOperations.get(operationId) ?? 0) + 1)
    try {
      return await this.withOperation(operationId, async () => {
        const recoveryDomainSha256 = this.recoveryDomainSha256()
        const claimed = await this.dependencies.ledger.claim({
          path: input.path,
          requestSha256: requestDigest(encodedBody),
          recoveryDomainSha256,
          retryOperationId: operationId
        })
        await this.dependencies.vault.verifyExactRequest({
          operationId,
          path: input.path,
          encodedBody
        })
        if (claimed.replay !== undefined) {
          const archived = await this.dependencies.vault.verifyArchive(operationId)
          if (
            archived.receipt.status !== claimed.replay.status ||
            archived.recoveryJson !== claimed.replay.responseJson ||
            archived.receipt.recoverySha256 !==
              createHash('sha256').update(claimed.replay.responseJson, 'utf8').digest('hex')
          ) {
            throw new PaidMediaServiceError(
              'Durable paid media result does not match its Main archive receipt'
            )
          }
          const ackConvergence = this.dependencies.assetV2?.convergeImageAck
          if (
            claimed.operation.v2AckIntentReceiptSha256 !== undefined &&
            this.dependencies.assetV2?.isReady() === true &&
            typeof ackConvergence === 'function'
          ) {
            const controller = new AbortController()
            try {
              await ackConvergence({
                operationId,
                signal: controller.signal,
                runRecoverableMutation: (payload) =>
                  this.runRecoverableMutation(operationId, payload)
              })
            } catch {
              // The verified archived result remains replayable while the
              // idempotent remote ACK is retried by same-operation/startup convergence.
            }
          }
          if (
            !this.dependencies.installationRoot &&
            archived.receipt.kind === 'image' &&
            archived.cleanupComplete
          ) {
            try {
              await this.dependencies.capacity.ensureReleasedWithAuthorization({
                operationId,
                authorizationReceiptSha256: archived.receipt.receiptSha256
              })
            } catch {
              // Legacy unrooted callers retain their historical best-effort
              // convergence. Rooted production replay is strictly read-only.
            }
          }
          return {
            ok: true,
            status: claimed.replay.status,
            result: archived.result,
            operation: claimed.operation,
            deliveryProof: deliveryProof(archived)
          }
        }
        const assetV2 = this.assetV2ImageReady(input.path)
          ? this.dependencies.assetV2
          : undefined
        if (assetV2) {
          if (
            this.pendingCancellations.has(operationId) &&
            claimed.operation.state === 'claimed' &&
            claimed.operation.dispatchCount === 0
          ) {
            return {
              ok: false,
              status: 0,
              recoverable: true,
              detail: 'Paid media request was cancelled before asset-v2 dispatch',
              operation: claimed.operation
            }
          }
          const controller = new AbortController()
          this.activeRequests.set(operationId, controller)
          if (this.pendingCancellations.has(operationId)) controller.abort()
          try {
            const outcome = await assetV2.executeImage({
              operationId,
              path: '/v1/images/generations',
              encodedBody,
              requestSha256: requestDigest(encodedBody),
              recoveryDomainSha256,
              idempotencyKey: claimed.dispatch.idempotencyKey,
              signal: controller.signal,
              runRecoverableMutation: (payload) =>
                this.runRecoverableMutation(operationId, payload)
            })
            if (!outcome.ok) {
              return {
                ok: false,
                status: outcome.status,
                recoverable: true,
                detail: outcome.detail,
                ...(outcome.retryAfterSeconds === undefined
                  ? {}
                  : { retryAfterSeconds: outcome.retryAfterSeconds }),
                operation: outcome.operation
              }
            }
            return {
              ok: true,
              status: outcome.archived.receipt.status,
              result: outcome.archived.result,
              operation: outcome.operation,
              deliveryProof: deliveryProof(outcome.archived)
            }
          } catch {
            const current = (await this.dependencies.ledger.listPublic()).find(
              (operation) => operation.operationId === operationId
            )
            return {
              ok: false,
              status: 0,
              recoverable: true,
              detail: 'Paid media asset-v2 result is unknown; retry only with the same operation',
              operation: current ?? claimed.operation
            }
          } finally {
            if (this.activeRequests.get(operationId) === controller) {
              this.activeRequests.delete(operationId)
            }
          }
        }
        if (this.dependencies.vault.hasArchive(operationId)) {
          if (claimed.operation.state !== 'dispatching') {
            throw new PaidMediaServiceError(
              'Paid media archive exists outside a recoverable dispatch transition'
            )
          }
          const archived = await this.dependencies.vault.verifyArchive(operationId)
          return this.runLocalMutation('archive_recovery', operationId, async () => {
            if (archived.receipt.kind === 'video_task' && archived.receipt.taskReceiptIdSha256) {
              try {
                await this.dependencies.capacity.bindVideoTask({
                  operationId,
                  taskAliasSha256: archived.receipt.taskReceiptIdSha256
                })
              } catch {
                // Legacy/pre-capacity archives still replay locally. Missing or
                // corrupt bindings will fail closed before any later remote poll.
              }
            }
            const operation = await this.dependencies.ledger.markResultReady({
              operationId,
              status: archived.receipt.status,
              responseJson: archived.recoveryJson
            })
            if (archived.receipt.kind === 'image' && archived.cleanupComplete) {
              try {
                await this.dependencies.capacity.ensureReleasedWithAuthorization({
                  operationId,
                  authorizationReceiptSha256: archived.receipt.receiptSha256
                })
              } catch {
                // The archive and result-ready receipt are already authoritative.
                // Capacity reconciliation is retried separately and must never
                // revoke a local replay or cause another provider call.
              }
            }
            return {
              ok: true as const,
              status: archived.receipt.status,
              result: archived.result,
              operation,
              deliveryProof: deliveryProof(archived)
            }
          })
        }
        if (claimed.operation.state === 'dispatching') {
          throw new PaidMediaServiceError(
            'Paid media dispatch outcome is unknown; manual recovery is required'
          )
        }
        this.assertRemoteOperationsEnabled()
        await this.ensureMediaProbeReadyUnfenced()
        const { runtimeKey, paidMediaKey } = this.validateAuthorities()
        const baseUrl = validateLoopbackBaseUrl(this.dependencies.baseUrl())
        const prepared = await this.runLocalMutation(
          'dispatch_prepare',
          operationId,
          async () => {
            try {
              await this.dependencies.capacity.ensureReservation({
                operationId,
                path: input.path,
                allowCreate:
                  claimed.operation.state === 'claimed' && claimed.operation.dispatchCount === 0
              })
            } catch (error) {
              throw new PaidMediaServiceError('Paid media capacity reservation failed', {
                cause: error
              })
            }
            if (this.pendingCancellations.has(operationId)) {
              await this.dependencies.capacity.ensureReleasedWithAuthorization({
                operationId,
                authorizationReceiptSha256: capacityReleaseAuthorizationSha256(
                  operationId,
                  'cancelled-before-dispatch'
                )
              })
              return { cancelled: true as const, operation: claimed.operation }
            }
            const operation = await this.dependencies.ledger.markDispatching(operationId)
            return { cancelled: false as const, operation }
          }
        )
        if (prepared.cancelled) {
          return {
            ok: false,
            status: 0,
            recoverable: true,
            detail: 'Paid media request was cancelled before dispatch',
            operation: prepared.operation
          }
        }
        if (this.pendingCancellations.has(operationId)) {
          return this.runLocalMutation('execute_result', operationId, async () => {
            const operation = await this.dependencies.ledger.markRecoverable({
              operationId,
              status: 0
            })
            return {
              ok: false as const,
              status: 0,
              recoverable: true as const,
              detail: 'Paid media request was cancelled before transport',
              operation
            }
          })
        }

        // The durable dispatch fence is committed in Root before this fresh
        // proof. Provider latency therefore holds no Root pending receipt or
        // global authority mutex; a crash can only leave an unknown,
        // non-repeatable dispatching operation.
        await this.dependencies.installationRoot?.assertOutboundReady()
        let response: PaidMediaTransportResponse
        const controller = new AbortController()
        this.activeRequests.set(operationId, controller)
        if (this.pendingCancellations.has(operationId)) {
          controller.abort()
          this.activeRequests.delete(operationId)
          return this.runLocalMutation('execute_result', operationId, async () => {
            const operation = await this.dependencies.ledger.markRecoverable({
              operationId,
              status: 0
            })
            return {
              ok: false as const,
              status: 0,
              recoverable: true as const,
              detail: 'Paid media request was cancelled before transport',
              operation
            }
          })
        }
        try {
          response = await this.dependencies.transport({
            method: 'POST',
            url: `${baseUrl}${input.path}`,
            path: input.path,
            encodedBody,
            headers: {
              Authorization: `Bearer ${runtimeKey}`,
              'X-Nachuan-Paid-Media-Key': paidMediaKey,
              'Idempotency-Key': claimed.dispatch.idempotencyKey,
              Accept: 'application/json',
              'Content-Type': 'application/json'
            },
            signal: controller.signal,
            responseByteLimit: MAX_PAID_MEDIA_ARCHIVE_RESPONSE_BYTES
          })
        } catch {
          return this.runLocalMutation('execute_result', operationId, async () => {
            const operation = await this.dependencies.ledger.markRecoverable({
              operationId,
              status: 0
            })
            return {
              ok: false as const,
              status: 0,
              recoverable: true as const,
              detail: 'Paid media transport result is unknown',
              operation
            }
          })
        } finally {
          if (this.activeRequests.get(operationId) === controller) {
            this.activeRequests.delete(operationId)
          }
        }
        return this.runLocalMutation('execute_result', operationId, async () => {
        if (!Number.isInteger(response.status) || response.status < 100 || response.status > 599) {
          const operation = await this.dependencies.ledger.markRecoverable({
            operationId,
            status: 0
          })
          return {
            ok: false,
            status: 0,
            recoverable: true,
            detail: 'Paid media transport returned an invalid status',
            operation
          }
        }
        if (
          Buffer.byteLength(response.body, 'utf8') >
          MAX_PAID_MEDIA_ARCHIVE_RESPONSE_BYTES
        ) {
          const operation = await this.dependencies.ledger.markRecoverable({
            operationId,
            status: response.status
          })
          return {
            ok: false,
            status: response.status,
            recoverable: true,
            detail: 'Paid media response exceeded its size limit',
            operation
          }
        }
        if (response.status < 200 || response.status >= 300) {
          const retryAfterSeconds = boundedRetryAfter(response.headers)
          const operation = await this.dependencies.ledger.markRecoverable({
            operationId,
            status: response.status,
            ...(retryAfterSeconds === undefined ? {} : { retryAfterSeconds })
          })
          return {
            ok: false,
            status: response.status,
            recoverable: true,
            detail: safeDetail(response.status, response.body),
            ...(retryAfterSeconds === undefined ? {} : { retryAfterSeconds }),
            operation
          }
        }
        let result: unknown
        try {
          result = JSON.parse(response.body)
          if (!result || typeof result !== 'object' || Array.isArray(result)) {
            throw new Error('result is not an object')
          }
        } catch {
          const operation = await this.dependencies.ledger.markRecoverable({
            operationId,
            status: response.status
          })
          return {
            ok: false,
            status: response.status,
            recoverable: true,
            detail: 'Paid media success response could not be decoded',
            operation
          }
        }
        let archived: PaidMediaArchivedResult
        try {
          await this.dependencies.capacity.ensureReservation({
            operationId,
            path: input.path,
            allowCreate: false
          })
          archived = await this.dependencies.vault.archiveResult({
            operationId,
            path: input.path,
            status: response.status,
            responseJson: response.body
          })
        } catch {
          const operation = await this.dependencies.ledger.markRecoverable({
            operationId,
            status: response.status
          })
          return {
            ok: false,
            status: response.status,
            recoverable: true,
            detail: 'Paid media success could not be safely archived',
            operation
          }
        }
        if (archived.receipt.kind === 'video_task') {
          if (!archived.receipt.taskReceiptIdSha256) {
            throw new PaidMediaServiceError('Paid video task archive has no binding digest')
          }
          try {
            await this.dependencies.capacity.bindVideoTask({
              operationId,
              taskAliasSha256: archived.receipt.taskReceiptIdSha256
            })
          } catch (error) {
            throw new PaidMediaServiceError('Paid video capacity binding failed', {
              cause: error
            })
          }
        }
        const operation = await this.dependencies.ledger.markResultReady({
          operationId,
          status: response.status,
          responseJson: archived.recoveryJson
        })
        if (archived.receipt.kind === 'image' && archived.cleanupComplete) {
          const verified = await this.dependencies.vault.verifyArchive(operationId)
          if (verified.receipt.receiptSha256 !== archived.receipt.receiptSha256) {
            throw new PaidMediaServiceError('Paid image archive changed before capacity release')
          }
          await this.dependencies.capacity.ensureReleasedWithAuthorization({
            operationId,
            authorizationReceiptSha256: verified.receipt.receiptSha256
          })
        }
        return {
          ok: true,
          status: response.status,
          result: archived.result,
          operation,
          deliveryProof: deliveryProof(archived)
        }
        })
      })
    } finally {
      const remaining = (this.executingOperations.get(operationId) ?? 1) - 1
      if (remaining <= 0) {
        this.executingOperations.delete(operationId)
        this.pendingCancellations.delete(operationId)
      } else {
        this.executingOperations.set(operationId, remaining)
      }
    }
  }

  async acknowledgeDelivered(input: PaidMediaDeliveryProof): Promise<PaidMediaPublicOperation> {
    return this.runMaintenanceTrackedWork(() => this.acknowledgeDeliveredUnfenced(input))
  }

  private async acknowledgeDeliveredUnfenced(
    input: PaidMediaDeliveryProof
  ): Promise<PaidMediaPublicOperation> {
    if (
      !input ||
      typeof input !== 'object' ||
      !exactKeys(input as unknown as Record<string, unknown>, [
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
      throw new PaidMediaServiceError('Paid media delivery proof is invalid')
    }
    const operationId = input.operationId
    this.assertInstallationReadable()
    return this.withOperation(operationId, async () => {
      return this.runLocalMutation('ack_delivery', operationId, async () => {
        const archived = await this.dependencies.vault.verifyArchive(operationId)
        if (
          archived.receipt.recoverySha256 !== input.resultSha256 ||
          archived.receipt.receiptSha256 !== input.archiveReceiptSha256
        ) {
          throw new PaidMediaServiceError(
            'Paid media delivery proof does not match the Main archive receipt'
          )
        }
        return this.dependencies.ledger.markDelivered({
          operationId,
          resultSha256: input.resultSha256,
          archiveReceiptSha256: input.archiveReceiptSha256
        })
      })
    })
  }

  async recoverArchived(operationId: string): Promise<PaidMediaArchiveRecoveryResult> {
    if (typeof operationId !== 'string' || !OPERATION_ID_PATTERN.test(operationId)) {
      throw new PaidMediaServiceError('Paid media operation id is invalid')
    }
    this.assertInstallationReadable()
    const archived = await this.dependencies.vault.recover(operationId)
    const exactRequest = await this.dependencies.vault.readExactRequest(operationId)
    const request = inspectPaidMediaRequestBody(exactRequest.encodedBody, exactRequest.path)
    return {
      operationId: archived.receipt.operationId,
      path: archived.receipt.path,
      model: request.model,
      status: archived.receipt.status,
      result: archived.result,
      deliveryProof: deliveryProof(archived),
      archive: {
        receiptSha256: archived.receipt.receiptSha256,
        responseSha256: archived.receipt.responseSha256,
        responseByteLength: archived.receipt.responseByteLength,
        assets: archived.receipt.assets.map((asset) => ({ ...asset }))
      }
    }
  }

  async listRecoverableArchives(input: {
    cursor?: string
    limit?: number
  } = {}): Promise<PaidMediaArchiveDiscoveryPage> {
    this.assertInstallationReadable()
    return this.dependencies.vault.listRecoverableArchives(input)
  }

  cancel(operationId: string): boolean {
    if (typeof operationId !== 'string' || !OPERATION_ID_PATTERN.test(operationId)) return false
    if (!this.executingOperations.has(operationId)) return false
    this.pendingCancellations.add(operationId)
    const controller = this.activeRequests.get(operationId)
    controller?.abort()
    return true
  }

  async abandonUndispatchedClaim(
    operationId: string,
    evidence: string
  ): Promise<PaidMediaPublicOperation> {
    return this.runMaintenanceTrackedWork(() =>
      this.abandonUndispatchedClaimUnfenced(operationId, evidence)
    )
  }

  private async abandonUndispatchedClaimUnfenced(
    operationId: string,
    evidence: string
  ): Promise<PaidMediaPublicOperation> {
    if (
      typeof operationId !== 'string' ||
      !OPERATION_ID_PATTERN.test(operationId) ||
      typeof evidence !== 'string' ||
      !evidence.trim()
    ) {
      throw new PaidMediaServiceError('Never-dispatched paid media abandonment is invalid')
    }
    this.assertInstallationReadable()
    return this.withOperation(operationId, async () => {
      return this.runLocalMutation('abandon_claim', operationId, async () => {
        const current = (await this.dependencies.ledger.listPublic()).find(
          (record) => record.operationId === operationId
        )
        if (!current || current.state !== 'claimed' || current.dispatchCount !== 0) {
          throw new PaidMediaServiceError(
            'Only a never-dispatched paid media claim can be abandoned automatically'
          )
        }
        const reconciled = await this.dependencies.ledger.reconcile({
          operationId,
          reason: 'pre-dispatch-anchor-failure',
          evidence: evidence.trim()
        })
        await this.dependencies.capacity.ensureReleasedWithAuthorization({
          operationId,
          authorizationReceiptSha256: capacityReleaseAuthorizationSha256(
            operationId,
            'abandon-never-dispatched'
          )
        })
        return reconciled
      })
    })
  }

  async reconcileManually(input: {
    operationId: string
    reason: string
    evidence: string
  }): Promise<PaidMediaPublicOperation> {
    return this.runMaintenanceTrackedWork(() => this.reconcileManuallyUnfenced(input))
  }

  private async reconcileManuallyUnfenced(input: {
    operationId: string
    reason: string
    evidence: string
  }): Promise<PaidMediaPublicOperation> {
    if (!input || typeof input !== 'object') {
      throw new PaidMediaServiceError('Paid media reconciliation request is invalid')
    }
    this.assertInstallationReadable()
    return this.withOperation(input.operationId, async () => {
      return this.runLocalMutation('manual_reconcile', input.operationId, async () => {
        const current = (await this.dependencies.ledger.listPublic()).find(
          (record) => record.operationId === input.operationId
        )
        const reconciled = await this.dependencies.ledger.reconcile(input)
        if (current?.dispatchCount === 0) {
          await this.dependencies.capacity.ensureReleasedWithAuthorization({
            operationId: input.operationId,
            authorizationReceiptSha256: capacityReleaseAuthorizationSha256(
              input.operationId,
              'manual-reconcile-never-dispatched'
            )
          })
        }
        return reconciled
      })
    })
  }

  async listUnresolved(): Promise<PaidMediaPublicOperation[]> {
    this.assertInstallationReadable()
    const records = await this.dependencies.ledger.listPublic()
    return records.filter(
      (record) => record.state !== 'delivered' && record.state !== 'reconciled'
    )
  }

  async reconcileCapacityOnStartup(): Promise<{
    inspected: number
    released: number
    bound: number
    held: number
  }> {
    return this.runMaintenanceTrackedWork(() => this.reconcileCapacityOnStartupUnfenced())
  }

  private async reconcileCapacityOnStartupUnfenced(): Promise<{
    inspected: number
    released: number
    bound: number
    held: number
  }> {
    const reservations = await this.dependencies.capacity.listReservations()
    const cleanupPending = this.dependencies.vault.hasPendingCleanupWork()
    if (!cleanupPending && reservations.length === 0) {
      return { inspected: 0, released: 0, bound: 0, held: 0 }
    }
    return this.runLocalMutation('startup_reconcile', undefined, () =>
      this.reconcileCapacityUnlocked(reservations)
    )
  }

  private async reconcileCapacityUnlocked(
    initialReservations?: Awaited<ReturnType<PaidMediaCapacityManager['listReservations']>>
  ): Promise<{
    inspected: number
    released: number
    bound: number
    held: number
  }> {
    await this.dependencies.vault.recoverPendingCleanup()
    const reservations = initialReservations ?? (await this.dependencies.capacity.listReservations())
    const operations = new Map(
      (await this.dependencies.ledger.listPublic()).map((operation) => [
        operation.operationId,
        operation
      ])
    )
    let released = 0
    let bound = 0
    let held = 0
    for (const reservation of reservations) {
      const operation = operations.get(reservation.operationId)
      if (this.dependencies.vault.hasArchive(reservation.operationId)) {
        const archived = await this.dependencies.vault.verifyArchive(reservation.operationId)
        if (reservation.path === '/v1/images/generations') {
          if (archived.receipt.kind !== 'image') {
            throw new PaidMediaServiceError('Paid image capacity hold conflicts with its archive')
          }
          if (!archived.cleanupComplete) {
            held += 1
            continue
          }
          await this.dependencies.capacity.ensureReleasedWithAuthorization({
            operationId: reservation.operationId,
            authorizationReceiptSha256: archived.receipt.receiptSha256
          })
          released += 1
          continue
        }
        if (
          archived.receipt.kind !== 'video_task' ||
          !archived.receipt.taskReceiptIdSha256
        ) {
          throw new PaidMediaServiceError('Paid video capacity hold conflicts with its archive')
        }
        if (reservation.phase === 'active') {
          await this.dependencies.capacity.bindVideoTask({
            operationId: reservation.operationId,
            taskAliasSha256: archived.receipt.taskReceiptIdSha256
          })
          bound += 1
        } else if (
          reservation.phase !== 'video_bound' ||
          reservation.taskAliasSha256 !== archived.receipt.taskReceiptIdSha256
        ) {
          throw new PaidMediaServiceError('Paid video startup capacity binding conflicts')
        }
        const taskAlias = paidVideoTaskAlias(archived.result)
        if (taskAlias && this.dependencies.vault.hasTerminalMediaForTask(taskAlias)) {
          const terminal = await this.dependencies.vault.verifyTerminalMediaForTask(taskAlias)
          if (terminal.operationId !== reservation.operationId) {
            throw new PaidMediaServiceError('Paid video terminal capacity binding conflicts')
          }
          if (!terminal.cleanupComplete) {
            held += 1
            continue
          }
          await this.dependencies.capacity.ensureReleasedWithAuthorization({
            operationId: reservation.operationId,
            authorizationReceiptSha256: terminal.receiptSha256
          })
          released += 1
          continue
        }
        held += 1
        continue
      }
      if (
        operation &&
        operation.dispatchCount === 0 &&
        (operation.state === 'claimed' || operation.state === 'reconciled')
      ) {
        await this.dependencies.capacity.ensureReleasedWithAuthorization({
          operationId: reservation.operationId,
          authorizationReceiptSha256: capacityReleaseAuthorizationSha256(
            reservation.operationId,
            'startup-never-dispatched'
          )
        })
        released += 1
        continue
      }
      held += 1
    }
    return { inspected: reservations.length, released, bound, held }
  }

  async importLegacyUnresolved(
    input: PaidMediaLegacyUnresolvedInput
  ): Promise<PaidMediaPublicOperation> {
    return this.runMaintenanceTrackedWork(() => this.importLegacyUnresolvedUnfenced(input))
  }

  private async importLegacyUnresolvedUnfenced(
    input: PaidMediaLegacyUnresolvedInput
  ): Promise<PaidMediaPublicOperation> {
    if (!this.dependencies.installationRoot) {
      return this.dependencies.ledger.importLegacyUnresolved(input)
    }
    this.assertInstallationReadable()
    const seal = this.dependencies.legacySeal
    if (!seal) throw new PaidMediaServiceError('Paid media legacy migration seal is unavailable')
    const closed = requireClosedLegacySeal(await seal.inspect())
    const expected = this.legacyCandidateInput(closed)
    if (!expected || JSON.stringify(expected) !== JSON.stringify(input)) {
      throw new PaidMediaServiceError('Paid media legacy import does not match the closed seal')
    }
    await this.importClosedLegacyCandidate(closed)
    const imported = (await this.dependencies.ledger.listPublic()).find(
      (operation) => operation.operationId === input.operationId
    )
    if (!imported) throw new PaidMediaServiceError('Paid media legacy import receipt is incomplete')
    return imported
  }
}

export const nodePaidMediaTransport: PaidMediaTransport = (request) =>
  new Promise((resolve, reject) => {
    if (request.signal.aborted) {
      reject(new PaidMediaServiceError('Paid media request was cancelled before dispatch'))
      return
    }
    const payload = Buffer.from(request.encodedBody, 'utf8')
    if (
      !Number.isSafeInteger(request.responseByteLimit) ||
      request.responseByteLimit < 1 ||
      request.responseByteLimit > MAX_PAID_MEDIA_ARCHIVE_RESPONSE_BYTES
    ) {
      reject(new PaidMediaServiceError('Paid media response byte limit is invalid'))
      return
    }
    let settled = false
    let outgoing: ReturnType<typeof http.request>
    const cleanup = (): void => request.signal.removeEventListener('abort', onAbort)
    const fail = (error: Error): void => {
      if (settled) return
      settled = true
      cleanup()
      reject(error)
    }
    const onAbort = (): void => {
      outgoing.destroy()
      fail(new PaidMediaServiceError('Paid media request was cancelled'))
    }
    outgoing = http.request(
      request.url,
      {
        method: request.method,
        headers:
          request.method === 'POST'
            ? {
                ...request.headers,
                'Content-Length': String(payload.byteLength)
              }
            : request.headers
      },
      (response) => {
        const chunks: Buffer[] = []
        let total = 0
        response.on('data', (chunk: Buffer | string) => {
          const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
          total += bytes.byteLength
          if (total > request.responseByteLimit) {
            response.destroy()
            fail(new PaidMediaServiceError('Paid media response exceeded its size limit'))
            return
          }
          chunks.push(bytes)
        })
        response.on('error', (error) => fail(error))
        response.on('end', () => {
          if (settled) return
          settled = true
          cleanup()
          const headers: Record<string, string | undefined> = {}
          for (const [name, value] of Object.entries(response.headers)) {
            headers[name] = Array.isArray(value) ? value.join(', ') : value
          }
          resolve({
            status: response.statusCode ?? 500,
            headers,
            body: Buffer.concat(chunks).toString('utf8')
          })
        })
      }
    )
    request.signal.addEventListener('abort', onAbort, { once: true })
    outgoing.on('error', (error) => fail(error))
    outgoing.setTimeout(RESPONSE_TIMEOUT_MS, () => {
      outgoing.destroy()
      fail(new PaidMediaServiceError('Paid media request timed out'))
    })
    if (request.method === 'POST') outgoing.write(payload)
    outgoing.end()
  })
