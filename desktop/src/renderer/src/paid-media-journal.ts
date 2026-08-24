import {
  ensureLegacyPaidMediaMigrated,
  type LegacyPaidMediaImport
} from './paid-media-legacy-migration'

export type PaidMediaPath = '/v1/images/generations' | '/v1/videos/generations'

export interface PaidMediaDeliveryProof {
  operationId: string
  resultSha256: string
  archiveReceiptSha256: string
}

export interface PaidMediaRequestOptions<TResult = unknown> {
  operationId?: string
  /** Runs after the main-process ledger commit and before any provider dispatch. */
  onOperationClaimed?: (
    operationId: string
  ) => boolean | void | Promise<boolean | void>
  /** Return true only after the consumer-ready result is durably flushed. */
  onResultDurablyCommitted?: (
    operationId: string,
    result: TResult,
    deliveryProof: PaidMediaDeliveryProof
  ) => boolean | Promise<boolean>
}

export type PaidMediaOperationState =
  | 'claimed'
  | 'dispatching'
  | 'recoverable'
  | 'result_ready'

export interface PendingPaidMediaOperation {
  operationId: string
  path: PaidMediaPath
  createdAt: number
  updatedAt: number
  state: PaidMediaOperationState
  dispatchCount: number
  lastStatus?: number
  retryAfterSeconds?: number
}

export interface PaidMediaArchiveDiscovery {
  operationId: string
  path: PaidMediaPath
  model: string
  status: number
  kind: 'image' | 'video_task'
  archivedAt: number
  receiptSha256: string
  responseByteLength: number
  assets: Array<{
    reference: string
    mediaType: string
    byteLength: number
    sha256: string
  }>
}

export interface PaidMediaArchiveDiscoveryPage {
  items: PaidMediaArchiveDiscovery[]
  nextCursor?: string
}

export interface PaidMediaArchiveRecovery {
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
    assets: PaidMediaArchiveDiscovery['assets']
  }
}

export type PaidMediaExecutionResult =
  | {
      ok: true
      status: number
      result: unknown
      operation: PendingPaidMediaOperation
      deliveryProof: PaidMediaDeliveryProof
    }
  | {
      ok: false
      status: number
      recoverable: boolean
      detail: string
      retryAfterSeconds?: number
      operation: PendingPaidMediaOperation
    }

interface PaidMediaMainApi {
  claimPaidMedia: (input: {
    path: PaidMediaPath
    encodedBody: string
    retryOperationId?: string
  }) => Promise<PendingPaidMediaOperation>
  executePaidMedia: (
    input: { operationId: string; path: PaidMediaPath; encodedBody: string }
  ) => Promise<PaidMediaExecutionResult>
  cancelPaidMedia: (operationId: string) => void
  acknowledgePaidMedia: (deliveryProof: PaidMediaDeliveryProof) => Promise<unknown>
  abandonPaidMediaClaim: (operationId: string, evidence: string) => Promise<unknown>
  listPaidMediaOperations: () => Promise<PendingPaidMediaOperation[]>
  reconcilePaidMedia: (input: {
    operationId: string
    reason: string
    evidence: string
  }) => Promise<unknown>
  importLegacyPaidMediaJournal: (record: LegacyPaidMediaImport) => Promise<unknown>
}

interface PaidMediaArchiveMainApi {
  listPaidMediaArchives: (input?: {
    cursor?: string
    limit?: number
  }) => Promise<PaidMediaArchiveDiscoveryPage>
  recoverPaidMediaArchive: (operationId: string) => Promise<PaidMediaArchiveRecovery>
}

export class PaidMediaJournalError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options)
    this.name = 'PaidMediaJournalError'
  }
}

export class PaidMediaOperationMismatchError extends PaidMediaJournalError {
  constructor(message = 'Paid media retry does not match the original operation') {
    super(message)
    this.name = 'PaidMediaOperationMismatchError'
  }
}

export class PaidMediaOperationExpiredError extends PaidMediaJournalError {
  readonly operationId: string

  constructor(operationId: string) {
    super('Paid media operation is too old for an automatic retry; reconcile it manually')
    this.name = 'PaidMediaOperationExpiredError'
    this.operationId = operationId
  }
}

const SHA256_PATTERN = /^[0-9a-f]{64}$/

export function isPaidMediaDeliveryProof(
  value: unknown,
  operationId?: string
): value is PaidMediaDeliveryProof {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const proof = value as Record<string, unknown>
  return (
    Object.keys(proof).length === 3 &&
    typeof proof.operationId === 'string' &&
    /^desktop-op-[0-9a-f-]{36}$/i.test(proof.operationId) &&
    (operationId === undefined || proof.operationId === operationId) &&
    typeof proof.resultSha256 === 'string' &&
    SHA256_PATTERN.test(proof.resultSha256) &&
    typeof proof.archiveReceiptSha256 === 'string' &&
    SHA256_PATTERN.test(proof.archiveReceiptSha256)
  )
}

function mainApi(): PaidMediaMainApi {
  const candidate = (window as unknown as { api?: Partial<PaidMediaMainApi> }).api
  if (
    !candidate ||
    typeof candidate.claimPaidMedia !== 'function' ||
    typeof candidate.executePaidMedia !== 'function' ||
    typeof candidate.cancelPaidMedia !== 'function' ||
    typeof candidate.acknowledgePaidMedia !== 'function' ||
    typeof candidate.abandonPaidMediaClaim !== 'function' ||
    typeof candidate.listPaidMediaOperations !== 'function' ||
    typeof candidate.reconcilePaidMedia !== 'function'
  ) {
    throw new PaidMediaJournalError('Main-process paid media control plane is unavailable')
  }
  return candidate as PaidMediaMainApi
}

function archiveMainApi(): PaidMediaArchiveMainApi {
  const candidate = (window as unknown as { api?: Partial<PaidMediaArchiveMainApi> }).api
  if (
    !candidate ||
    typeof candidate.listPaidMediaArchives !== 'function' ||
    typeof candidate.recoverPaidMediaArchive !== 'function'
  ) {
    throw new PaidMediaJournalError('Main-process paid media archive is unavailable')
  }
  return candidate as PaidMediaArchiveMainApi
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

function translateMainError(error: unknown, operationId?: string): Error {
  const message = errorMessage(error)
  const name = error instanceof Error ? error.name : ''
  if (name === 'PaidMediaIpc:operation_expired' && operationId) {
    return new PaidMediaOperationExpiredError(operationId)
  }
  if (name === 'PaidMediaIpc:operation_mismatch') {
    return new PaidMediaOperationMismatchError(message)
  }
  if (/too old/i.test(message) && operationId) return new PaidMediaOperationExpiredError(operationId)
  if (/does not match|mismatch/i.test(message)) return new PaidMediaOperationMismatchError(message)
  if (error instanceof PaidMediaJournalError) return error
  return new PaidMediaJournalError(message || 'Main-process paid media journal failed', {
    cause: error
  })
}

export async function claimPaidMediaOperation(
  path: PaidMediaPath,
  encodedBody: string,
  retry?: Pick<PaidMediaRequestOptions, 'operationId'>
): Promise<PendingPaidMediaOperation> {
  await ensureLegacyPaidMediaMigrated()
  try {
    return await mainApi().claimPaidMedia({
      path,
      encodedBody,
      ...(retry?.operationId === undefined
        ? {}
        : { retryOperationId: retry.operationId })
    })
  } catch (error) {
    throw translateMainError(error, retry?.operationId)
  }
}

export async function executePaidMediaOperation(
  operationId: string,
  path: PaidMediaPath,
  encodedBody: string,
  signal?: AbortSignal
): Promise<PaidMediaExecutionResult> {
  await ensureLegacyPaidMediaMigrated()
  const api = mainApi()
  if (signal?.aborted) {
    try {
      // execute IPC has not been invoked, so this can only succeed for a
      // zero-dispatch claim. Main verifies that invariant before tombstoning.
      await api.abandonPaidMediaClaim(
        operationId,
        'renderer cancelled before main dispatch'
      )
    } catch {
      // If main cannot prove zero dispatch, the unresolved gate is retained.
    }
    throw new PaidMediaJournalError('Paid media request was cancelled before dispatch')
  }
  const cancel = (): void => api.cancelPaidMedia(operationId)
  signal?.addEventListener('abort', cancel, { once: true })
  try {
    const result = await api.executePaidMedia({ operationId, path, encodedBody })
    if (result.ok && !isPaidMediaDeliveryProof(result.deliveryProof, operationId)) {
      throw new PaidMediaJournalError('Main returned an invalid paid media delivery proof')
    }
    return result
  } catch (error) {
    throw translateMainError(error, operationId)
  } finally {
    signal?.removeEventListener('abort', cancel)
  }
}

export async function completePaidMediaOperation(
  deliveryProof: PaidMediaDeliveryProof
): Promise<void> {
  await ensureLegacyPaidMediaMigrated()
  if (!isPaidMediaDeliveryProof(deliveryProof)) {
    throw new PaidMediaJournalError('Paid media delivery proof is invalid')
  }
  try {
    await mainApi().acknowledgePaidMedia(deliveryProof)
  } catch (error) {
    throw translateMainError(error, deliveryProof.operationId)
  }
}

export async function abandonUndispatchedPaidMediaOperation(
  operationId: string,
  evidence: string
): Promise<void> {
  await ensureLegacyPaidMediaMigrated()
  try {
    await mainApi().abandonPaidMediaClaim(operationId, evidence)
  } catch (error) {
    throw translateMainError(error, operationId)
  }
}

export async function discardPendingPaidMediaOperation(
  operationId: string,
  evidence: string
): Promise<boolean> {
  await ensureLegacyPaidMediaMigrated()
  try {
    await mainApi().reconcilePaidMedia({
      operationId,
      reason: 'provider-console-checked',
      evidence
    })
    return true
  } catch (error) {
    if (/cancelled/i.test(errorMessage(error))) return false
    throw translateMainError(error, operationId)
  }
}

export async function listPendingPaidMediaOperations(): Promise<PendingPaidMediaOperation[]> {
  await ensureLegacyPaidMediaMigrated()
  try {
    return await mainApi().listPaidMediaOperations()
  } catch (error) {
    throw translateMainError(error)
  }
}

export async function listRecoverablePaidMediaArchives(input: {
  cursor?: string
  limit?: number
} = {}): Promise<PaidMediaArchiveDiscoveryPage> {
  try {
    return await archiveMainApi().listPaidMediaArchives(input)
  } catch (error) {
    throw translateMainError(error)
  }
}

export async function recoverPaidMediaArchive(
  operationId: string
): Promise<PaidMediaArchiveRecovery> {
  if (typeof operationId !== 'string' || !/^desktop-op-[0-9a-f-]{36}$/i.test(operationId)) {
    throw new PaidMediaJournalError('Paid media archive operation id is invalid')
  }
  try {
    const recovered = await archiveMainApi().recoverPaidMediaArchive(operationId)
    if (!isPaidMediaDeliveryProof(recovered.deliveryProof, operationId)) {
      throw new PaidMediaJournalError('Main returned an invalid archive delivery proof')
    }
    return recovered
  } catch (error) {
    throw translateMainError(error, operationId)
  }
}
