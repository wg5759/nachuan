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

import type {
  InstallationRootClient,
  InstallationRootComponentSnapshot,
  InstallationRootMutationEnvelope,
  InstallationRootSnapshot
} from './installation-root-client'

const DOCUMENT_SCHEMA = 'nachuan.paid-media-installation-authority.v4'
const ENVELOPE_SCHEMA = 'nachuan.paid-media-installation-authority.envelope.v1'
const ANCHOR_SCHEMA = 'nachuan.paid-media-installation-authority.anchor.v1'
const ANCHOR_ENVELOPE_SCHEMA = 'nachuan.paid-media-installation-authority.anchor.envelope.v1'
const PAIR_INTENT_SCHEMA = 'nachuan.paid-media-installation-authority.pair-intent.v1'
const PAIR_INTENT_ENVELOPE_SCHEMA =
  'nachuan.paid-media-installation-authority.pair-intent.envelope.v1'
const PROTECTION = 'electron-safe-storage'
const STATE_DOMAIN = Buffer.from('nachuan.desktop.paid-media-authority-state.v4\0', 'ascii')
const EVIDENCE_DOMAIN = Buffer.from('nachuan.desktop.paid-media-composite-evidence.v1\0', 'ascii')
const PAID_PRINCIPAL_DOMAIN = Buffer.from('nachuan.desktop.paid-principal.v1\0', 'ascii')
const PAIR_INTENT_DOMAIN = Buffer.from(
  'nachuan.desktop.paid-media-authority-pair-intent.v1\0',
  'ascii'
)
const SHA256_PATTERN = /^[0-9a-f]{64}$/
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
const OPERATION_ID_PATTERN = /^desktop-op-[0-9a-f-]{36}$/i
const KIND_PATTERN = /^[a-z][a-z0-9_.-]{0,63}$/
const ZERO_DIGEST = '0'.repeat(64)
const MAX_FILE_BYTES = 512 * 1024
const MAX_PLAINTEXT_BYTES = 256 * 1024
const MAX_RECONCILE_INSPECTIONS = 8
const MAX_ROOT_CAS_CALLS = 4

export const PAID_MEDIA_RECOVERABLE_HANDLER_VERSION = 1 as const

const RECOVERABLE_MUTATION_KINDS = [
  'asset_v2_dispatch',
  'asset_v2_stage_reserve',
  'asset_v2_stage_archive',
  'asset_v2_stage_cleanup',
  'asset_v2_result_ready_ack_intent',
  'asset_v2_ack_completion',
  'asset_v2_capacity_release'
] as const

export type PaidMediaRecoverableMutationKind = (typeof RECOVERABLE_MUTATION_KINDS)[number]

const RECOVERABLE_MUTATION_KIND_SET = new Set<string>(RECOVERABLE_MUTATION_KINDS)

type RootClient = Pick<
  InstallationRootClient,
  | 'snapshot'
  | 'bindDesktop'
  | 'verifyDesktop'
  | 'advanceDesktop'
  | 'acknowledgeDesktopRecovery'
>

export interface PaidMediaInstallationRootSafeStorage {
  isEncryptionAvailable(): boolean
  encryptString(value: string): Buffer
  decryptString(value: Buffer): string
}

export type PaidMediaInstallationRootAclHardener = (path: string, directory: boolean) => void

export interface PaidMediaInstallationRootAtomicIO {
  readUtf8(
    path: string,
    maxBytes: number,
    harden: PaidMediaInstallationRootAclHardener
  ): string | null
  writeUtf8Atomic(
    path: string,
    value: string,
    harden: PaidMediaInstallationRootAclHardener
  ): void
}

export interface PaidMediaAuthorityEvidence {
  ledgerIdentity: string
  ledgerSequence: number
  ledgerStateDigest: string
  vaultStateDigest: string
  capacityIdentity: string
  capacitySequence: number
  capacityStateDigest: string
  legacySealDecisionSha256: string
}

export interface PaidMediaInstallationRootAuthorityDependencies {
  client: RootClient
  safeStorage: PaidMediaInstallationRootSafeStorage
  harden: PaidMediaInstallationRootAclHardener
  atomicIO: PaidMediaInstallationRootAtomicIO
  now: () => number
  uuid: () => string
  readEvidence?: () => PaidMediaAuthorityEvidence | Promise<PaidMediaAuthorityEvidence>
  recoverableExecutor?: PaidMediaRecoverableMutationExecutor
}

export type PaidMediaInstallationRootMode =
  | 'detached'
  | 'provisioned_not_active'
  | 'ready'
  | 'recovery_pending'
  | 'manual_only'
  | 'fused'

export interface PaidMediaRecoverablePendingSummary {
  handlerVersion: typeof PAID_MEDIA_RECOVERABLE_HANDLER_VERSION
  kind: PaidMediaRecoverableMutationKind
  operationId: string
  intentSha256: string
  preparedAt: number
  beforeCompositeDigest: string
}

export interface PaidMediaInstallationRootState {
  mode: PaidMediaInstallationRootMode
  reasonCode: string
  installationId?: string
  epoch?: number
  desktopIdentity?: string
  mutationSequence?: number
  stateDigest?: string
  paidPrincipal?: string
  pendingRecovery?: Readonly<PaidMediaRecoverablePendingSummary>
}

export interface PaidMediaAuthorityMutationInput {
  kind: string
  operationId?: string
}

export interface PaidMediaAuthorityMutationContext {
  readonly transactionId: string
  assertOutboundReady(): Promise<void>
}

export interface PaidMediaRecoverableMutationInput {
  handlerVersion: typeof PAID_MEDIA_RECOVERABLE_HANDLER_VERSION
  kind: PaidMediaRecoverableMutationKind
  operationId: string
  intentSha256: string
}

export interface PaidMediaRecoverableMutationDescriptor
  extends PaidMediaRecoverableMutationInput {
  mode: 'recoverable'
  transactionId: string
  preparedAt: number
  beforeCompositeDigest: string
  beforeAuthorityEvidence: Readonly<PaidMediaAuthorityEvidence>
}

export interface PaidMediaRecoverableMutationExecutor {
  /**
   * A closed, local-only dispatcher. Implementations must use kind to select
   * an idempotent create-or-verify handler, return only after its exact local
   * postcondition is durable, and throw PaidMediaRecoverableMutationConflictError
   * for semantic conflicts. The descriptor deliberately carries no Root client
   * and no outbound capability.
   */
  execute(descriptor: Readonly<PaidMediaRecoverableMutationDescriptor>): Promise<void>
}

interface LegacyPendingIntent {
  transactionId: string
  kind: string
  operationId: string | null
  preparedAt: number
  beforeCompositeDigest: string
}

interface RecoverablePendingIntent extends PaidMediaRecoverableMutationDescriptor {}

type PendingIntent = LegacyPendingIntent | RecoverablePendingIntent

interface RecoverableCommitReceipt extends PaidMediaRecoverableMutationInput {
  mode: 'recoverable'
  transactionId: string
  preparedAt: number
  pendingStateDigest: string
  beforeCompositeDigest: string
  afterCompositeDigest: string
  afterAuthorityEvidence: Readonly<PaidMediaAuthorityEvidence>
}

type AuthorityMode = 'normal' | 'manual_only'

interface AuthorityDocumentBase {
  schema: typeof DOCUMENT_SCHEMA
  installationId: string
  epoch: number
  desktopIdentity: string
  rootPrincipalDigest: string
  mutationSequence: number
  stateDigest: string
  previousStateDigest: string | null
  compositeDigest: string
  authorityMode: AuthorityMode
  recoveryFloor: number | null
  recoveryStateDigest: string | null
  pendingIntent: PendingIntent | null
  recoverableCommit?: RecoverableCommitReceipt
}

interface AuthorityDocument extends AuthorityDocumentBase {}

interface AuthorityAnchor {
  schema: typeof ANCHOR_SCHEMA
  installationId: string
  epoch: number
  desktopIdentity: string
  mutationSequence: number
  stateDigest: string
}

interface AuthorityPairIntent {
  schema: typeof PAIR_INTENT_SCHEMA
  installationId: string
  epoch: number
  desktopIdentity: string
  expectedPreviousSequence: number | null
  expectedPreviousStateDigest: string | null
  expectedPreviousDocument: AuthorityDocument | null
  expectedPreviousAnchor: AuthorityAnchor | null
  targetSequence: number
  targetStateDigest: string
  targetDocument: AuthorityDocument
  targetAnchor: AuthorityAnchor
  receiptDigest: string
}

interface LegacyActiveMutation {
  mode: 'legacy'
  transactionId: string
  before: AuthorityDocument
  pending: AuthorityDocument
}

interface RecoverableActiveMutation {
  mode: 'recoverable'
  transactionId: string
  pending: AuthorityDocument & { pendingIntent: RecoverablePendingIntent }
}

type ActiveMutation = LegacyActiveMutation | RecoverableActiveMutation

export class PaidMediaInstallationRootError extends Error {
  override readonly name: string = 'PaidMediaInstallationRootError'
}

export class PaidMediaRecoverableMutationConflictError extends PaidMediaInstallationRootError {
  override readonly name: string = 'PaidMediaRecoverableMutationConflictError'
}

export class PaidMediaInstallationRootUnavailableError extends PaidMediaInstallationRootError {
  override readonly name: string = 'PaidMediaInstallationRootUnavailableError'
}

class PaidMediaInstallationRootReadTransientError extends Error {
  override readonly name: string = 'PaidMediaInstallationRootReadTransientError'
}

function fail(message: string, cause?: unknown): PaidMediaInstallationRootUnavailableError {
  return new PaidMediaInstallationRootUnavailableError(
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

function digest(value: unknown, allowZero = false): value is string {
  return (
    typeof value === 'string' &&
    SHA256_PATTERN.test(value) &&
    (allowZero || value !== ZERO_DIGEST)
  )
}

function counter(value: unknown, minimum = 0): value is number {
  return Number.isSafeInteger(value) && Number(value) >= minimum
}

function nextCounter(value: number): number {
  const next = value + 1
  if (!counter(next, 1)) throw fail('Paid media authority sequence is exhausted')
  return next
}

function parseObject(raw: string, label: string): Record<string, unknown> {
  try {
    const parsed: unknown = JSON.parse(raw)
    if (!isRecord(parsed)) throw new Error('not an object')
    return parsed
  } catch (error) {
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
    throw fail('Paid media authority envelope is invalid')
  }
  const bytes = Buffer.from(value, 'base64')
  if (bytes.toString('base64') !== value) throw fail('Paid media authority envelope is invalid')
  return bytes
}

function canonicalEvidence(value: unknown): PaidMediaAuthorityEvidence {
  if (!isRecord(value)) throw fail('Paid media composite evidence is invalid')
  if (
    !exactKeys(value, [
      'ledgerIdentity',
      'ledgerSequence',
      'ledgerStateDigest',
      'vaultStateDigest',
      'capacityIdentity',
      'capacitySequence',
      'capacityStateDigest',
      'legacySealDecisionSha256'
    ]) ||
    !digest(value.ledgerIdentity) ||
    !counter(value.ledgerSequence) ||
    !digest(value.ledgerStateDigest) ||
    !digest(value.vaultStateDigest) ||
    !digest(value.capacityIdentity) ||
    !counter(value.capacitySequence) ||
    !digest(value.capacityStateDigest) ||
    !digest(value.legacySealDecisionSha256)
  ) {
    throw fail('Paid media composite evidence is invalid')
  }
  return Object.freeze({
    ledgerIdentity: value.ledgerIdentity,
    ledgerSequence: Number(value.ledgerSequence),
    ledgerStateDigest: value.ledgerStateDigest,
    vaultStateDigest: value.vaultStateDigest,
    capacityIdentity: value.capacityIdentity,
    capacitySequence: Number(value.capacitySequence),
    capacityStateDigest: value.capacityStateDigest,
    legacySealDecisionSha256: value.legacySealDecisionSha256
  })
}

function sameAuthorityEvidence(
  left: PaidMediaAuthorityEvidence,
  right: PaidMediaAuthorityEvidence
): boolean {
  return (
    left.ledgerIdentity === right.ledgerIdentity &&
    left.ledgerSequence === right.ledgerSequence &&
    left.ledgerStateDigest === right.ledgerStateDigest &&
    left.vaultStateDigest === right.vaultStateDigest &&
    left.capacityIdentity === right.capacityIdentity &&
    left.capacitySequence === right.capacitySequence &&
    left.capacityStateDigest === right.capacityStateDigest &&
    left.legacySealDecisionSha256 === right.legacySealDecisionSha256
  )
}

function isRecoverableKind(value: unknown): value is PaidMediaRecoverableMutationKind {
  return typeof value === 'string' && RECOVERABLE_MUTATION_KIND_SET.has(value)
}

function isRecoverablePending(value: PendingIntent | null): value is RecoverablePendingIntent {
  return value !== null && 'mode' in value && value.mode === 'recoverable'
}

function frozenEvidence(value: PaidMediaAuthorityEvidence): Readonly<PaidMediaAuthorityEvidence> {
  return Object.freeze({ ...value })
}

function frozenRecoverableDescriptor(
  value: RecoverablePendingIntent
): Readonly<PaidMediaRecoverableMutationDescriptor> {
  return Object.freeze({
    mode: 'recoverable',
    handlerVersion: value.handlerVersion,
    kind: value.kind,
    operationId: value.operationId,
    intentSha256: value.intentSha256,
    transactionId: value.transactionId,
    preparedAt: value.preparedAt,
    beforeCompositeDigest: value.beforeCompositeDigest,
    beforeAuthorityEvidence: frozenEvidence(value.beforeAuthorityEvidence)
  })
}

export function paidMediaCompositeEvidenceDigest(value: unknown): string {
  const evidence = canonicalEvidence(value)
  return createHash('sha256')
    .update(EVIDENCE_DOMAIN)
    .update(
      JSON.stringify({
        ledgerIdentity: evidence.ledgerIdentity,
        ledgerSequence: evidence.ledgerSequence,
        ledgerStateDigest: evidence.ledgerStateDigest,
        vaultStateDigest: evidence.vaultStateDigest,
        capacityIdentity: evidence.capacityIdentity,
        capacitySequence: evidence.capacitySequence,
        capacityStateDigest: evidence.capacityStateDigest,
        legacySealDecisionSha256: evidence.legacySealDecisionSha256
      }),
      'utf8'
    )
    .digest('hex')
}

function pendingCanonical(value: PendingIntent | null): unknown {
  if (value === null) return null
  if (!isRecoverablePending(value)) {
    return {
        transactionId: value.transactionId,
        kind: value.kind,
        operationId: value.operationId,
        preparedAt: value.preparedAt,
        beforeCompositeDigest: value.beforeCompositeDigest
      }
  }
  return {
    mode: 'recoverable',
    handlerVersion: value.handlerVersion,
    kind: value.kind,
    operationId: value.operationId,
    intentSha256: value.intentSha256,
    transactionId: value.transactionId,
    preparedAt: value.preparedAt,
    beforeCompositeDigest: value.beforeCompositeDigest,
    beforeAuthorityEvidence: value.beforeAuthorityEvidence
  }
}

function recoverableCommitCanonical(value: RecoverableCommitReceipt): unknown {
  return {
    mode: 'recoverable',
    handlerVersion: value.handlerVersion,
    kind: value.kind,
    operationId: value.operationId,
    intentSha256: value.intentSha256,
    transactionId: value.transactionId,
    preparedAt: value.preparedAt,
    pendingStateDigest: value.pendingStateDigest,
    beforeCompositeDigest: value.beforeCompositeDigest,
    afterCompositeDigest: value.afterCompositeDigest,
    afterAuthorityEvidence: value.afterAuthorityEvidence
  }
}

function stateDigestFor(
  previousStateDigest: string | null,
  value: Omit<AuthorityDocument, 'stateDigest' | 'schema'>
): string {
  return createHash('sha256')
    .update(STATE_DOMAIN)
    .update(
      JSON.stringify({
        previousStateDigest,
        installationId: value.installationId,
        epoch: value.epoch,
        desktopIdentity: value.desktopIdentity,
        rootPrincipalDigest: value.rootPrincipalDigest,
        mutationSequence: value.mutationSequence,
        compositeDigest: value.compositeDigest,
        authorityMode: value.authorityMode,
        recoveryFloor: value.recoveryFloor,
        recoveryStateDigest: value.recoveryStateDigest,
        pendingIntent: pendingCanonical(value.pendingIntent),
        ...(value.recoverableCommit === undefined
          ? {}
          : { recoverableCommit: recoverableCommitCanonical(value.recoverableCommit) })
      }),
      'utf8'
    )
    .digest('hex')
}

function makeDocument(
  value: Omit<AuthorityDocument, 'schema' | 'stateDigest'>
): AuthorityDocument {
  return {
    schema: DOCUMENT_SCHEMA,
    ...value,
    stateDigest: stateDigestFor(value.previousStateDigest, value)
  }
}

function sameProof(
  component: InstallationRootComponentSnapshot,
  document: Pick<AuthorityDocument, 'mutationSequence' | 'stateDigest'>
): boolean {
  return (
    component.sequenceFloor === document.mutationSequence &&
    component.stateDigest === document.stateDigest
  )
}

function paidPrincipal(rootPrincipalDigest: string): string {
  return createHash('sha256')
    .update(PAID_PRINCIPAL_DOMAIN)
    .update(Buffer.from(rootPrincipalDigest, 'hex'))
    .digest('hex')
}

function cloneDocument(document: AuthorityDocument): AuthorityDocument {
  return {
    ...document,
    pendingIntent:
      document.pendingIntent === null
        ? null
        : isRecoverablePending(document.pendingIntent)
          ? {
              ...document.pendingIntent,
              beforeAuthorityEvidence: { ...document.pendingIntent.beforeAuthorityEvidence }
            }
          : { ...document.pendingIntent },
    ...(document.recoverableCommit === undefined
      ? {}
      : {
          recoverableCommit: {
            ...document.recoverableCommit,
            afterAuthorityEvidence: { ...document.recoverableCommit.afterAuthorityEvidence }
          }
        })
  }
}

function authorityDocumentCanonical(document: AuthorityDocument): Record<string, unknown> {
  return {
    schema: DOCUMENT_SCHEMA,
    installationId: document.installationId,
    epoch: document.epoch,
    desktopIdentity: document.desktopIdentity,
    rootPrincipalDigest: document.rootPrincipalDigest,
    mutationSequence: document.mutationSequence,
    stateDigest: document.stateDigest,
    previousStateDigest: document.previousStateDigest,
    compositeDigest: document.compositeDigest,
    authorityMode: document.authorityMode,
    recoveryFloor: document.recoveryFloor,
    recoveryStateDigest: document.recoveryStateDigest,
    pendingIntent: pendingCanonical(document.pendingIntent),
    ...(document.recoverableCommit === undefined
      ? {}
      : { recoverableCommit: recoverableCommitCanonical(document.recoverableCommit) })
  }
}

function authorityAnchorFor(document: AuthorityDocument): AuthorityAnchor {
  return {
    schema: ANCHOR_SCHEMA,
    installationId: document.installationId,
    epoch: document.epoch,
    desktopIdentity: document.desktopIdentity,
    mutationSequence: document.mutationSequence,
    stateDigest: document.stateDigest
  }
}

function authorityAnchorCanonical(anchor: AuthorityAnchor): Record<string, unknown> {
  return {
    schema: ANCHOR_SCHEMA,
    installationId: anchor.installationId,
    epoch: anchor.epoch,
    desktopIdentity: anchor.desktopIdentity,
    mutationSequence: anchor.mutationSequence,
    stateDigest: anchor.stateDigest
  }
}

function sameAuthorityDocument(left: AuthorityDocument, right: AuthorityDocument): boolean {
  return (
    JSON.stringify(authorityDocumentCanonical(left)) ===
    JSON.stringify(authorityDocumentCanonical(right))
  )
}

function sameAuthorityAnchor(left: AuthorityAnchor, right: AuthorityAnchor): boolean {
  return (
    JSON.stringify(authorityAnchorCanonical(left)) === JSON.stringify(authorityAnchorCanonical(right))
  )
}

function authorityPairIntentReceipt(
  value: Omit<AuthorityPairIntent, 'receiptDigest'>
): string {
  return createHash('sha256')
    .update(PAIR_INTENT_DOMAIN)
    .update(
      JSON.stringify({
        schema: PAIR_INTENT_SCHEMA,
        installationId: value.installationId,
        epoch: value.epoch,
        desktopIdentity: value.desktopIdentity,
        expectedPreviousSequence: value.expectedPreviousSequence,
        expectedPreviousStateDigest: value.expectedPreviousStateDigest,
        expectedPreviousDocument:
          value.expectedPreviousDocument === null
            ? null
            : authorityDocumentCanonical(value.expectedPreviousDocument),
        expectedPreviousAnchor:
          value.expectedPreviousAnchor === null
            ? null
            : authorityAnchorCanonical(value.expectedPreviousAnchor),
        targetSequence: value.targetSequence,
        targetStateDigest: value.targetStateDigest,
        targetDocument: authorityDocumentCanonical(value.targetDocument),
        targetAnchor: authorityAnchorCanonical(value.targetAnchor)
      }),
      'utf8'
    )
    .digest('hex')
}

export const nodePaidMediaInstallationRootAtomicIO: PaidMediaInstallationRootAtomicIO = {
  readUtf8(path, maxBytes, harden) {
    if (!existsSync(path)) return null
    const parent = dirname(path)
    const parentInfo = lstatSync(parent)
    const info = lstatSync(path)
    if (
      !parentInfo.isDirectory() ||
      parentInfo.isSymbolicLink() ||
      !info.isFile() ||
      info.isSymbolicLink() ||
      info.size < 1 ||
      info.size > maxBytes
    ) {
      throw fail('Paid media authority path is invalid')
    }
    harden(parent, true)
    harden(path, false)
    return readFileSync(path, 'utf8')
  },
  writeUtf8Atomic(path, value, harden) {
    const parent = dirname(path)
    mkdirSync(parent, { recursive: true })
    const parentInfo = lstatSync(parent)
    if (!parentInfo.isDirectory() || parentInfo.isSymbolicLink()) {
      throw fail('Paid media authority directory is redirected')
    }
    if (existsSync(path)) {
      const info = lstatSync(path)
      if (!info.isFile() || info.isSymbolicLink()) {
        throw fail('Paid media authority file is redirected')
      }
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
      renameSync(temporary, path)
      harden(path, false)
    } catch (error) {
      if (error instanceof PaidMediaInstallationRootError) throw error
      throw fail('Paid media authority atomic write failed', error)
    } finally {
      if (handle !== null) closeSync(handle)
      if (existsSync(temporary)) unlinkSync(temporary)
    }
  }
}

/**
 * Root-bound transaction authority for all Desktop paid-media local state.
 *
 * Legacy runMutation intentionally keeps its original local-pending, action,
 * Root-pending and Root-final sequence; any interrupted legacy pending still
 * converges only to permanent manual-only mode.
 *
 * Explicit recoverable mutations use the stronger order: persist the closed
 * pending descriptor, prove that exact pending in Installation Root, publish
 * the recovery guard, then invoke the local-only idempotent executor. After a
 * closed evidence transition succeeds, a final document retains recoverable
 * provenance until Root confirms the pending-to-final CAS. This distinction is
 * structural and never inferred from a legacy kind or a generic plus-one gap.
 *
 * Every local authority transition first replaces an encrypted, strict pair
 * intent and then publishes anchor followed by body. The latest committed
 * intent is retained: restart may roll forward only when each current member
 * is the intent's exact predecessor or exact target. No intent, an unknown
 * member, or malformed evidence remains fail-closed.
 */
export class PaidMediaInstallationRootAuthority {
  private tail: Promise<void> = Promise.resolve()
  private activeMutation: ActiveMutation | null = null
  private evidenceReader: (() => PaidMediaAuthorityEvidence | Promise<PaidMediaAuthorityEvidence>) | null
  private stateValue: PaidMediaInstallationRootState = {
    mode: 'detached',
    reasonCode: 'not-initialized'
  }

  constructor(
    private readonly path: string,
    private readonly dependencies: PaidMediaInstallationRootAuthorityDependencies
  ) {
    if (!path || !resolve(path)) throw fail('Paid media authority path is invalid')
    if (
      !dependencies ||
      !dependencies.client ||
      typeof dependencies.client.snapshot !== 'function' ||
      typeof dependencies.client.bindDesktop !== 'function' ||
      typeof dependencies.client.verifyDesktop !== 'function' ||
      typeof dependencies.client.advanceDesktop !== 'function' ||
      typeof dependencies.client.acknowledgeDesktopRecovery !== 'function' ||
      !dependencies.safeStorage ||
      typeof dependencies.atomicIO?.readUtf8 !== 'function' ||
      typeof dependencies.atomicIO?.writeUtf8Atomic !== 'function' ||
      typeof dependencies.now !== 'function' ||
      typeof dependencies.uuid !== 'function' ||
      (dependencies.recoverableExecutor !== undefined &&
        typeof dependencies.recoverableExecutor.execute !== 'function')
    ) {
      throw fail('Paid media authority dependencies are unavailable')
    }
    this.evidenceReader = dependencies.readEvidence ?? null
  }

  get state(): PaidMediaInstallationRootState {
    return Object.freeze({
      ...this.stateValue,
      ...(this.stateValue.pendingRecovery === undefined
        ? {}
        : { pendingRecovery: Object.freeze({ ...this.stateValue.pendingRecovery }) })
    })
  }

  attachEvidenceReader(
    reader: () => PaidMediaAuthorityEvidence | Promise<PaidMediaAuthorityEvidence>
  ): void {
    if (typeof reader !== 'function' || (this.evidenceReader && this.evidenceReader !== reader)) {
      throw fail('Paid media composite evidence reader is already attached')
    }
    this.evidenceReader = reader
  }

  private serialize<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.tail.then(operation, operation)
    this.tail = result.then(
      () => undefined,
      () => undefined
    )
    return result
  }

  private get anchorPath(): string {
    return `${this.path}.anchor`
  }

  private get pairIntentPath(): string {
    return `${this.path}.pair-intent`
  }

  private requireEncryption(): void {
    if (!this.dependencies.safeStorage.isEncryptionAvailable()) {
      throw fail('OS-backed paid media authority encryption is unavailable')
    }
  }

  private encode(value: unknown, schema: string, label: string): string {
    this.requireEncryption()
    const plaintext = JSON.stringify(value)
    if (Buffer.byteLength(plaintext, 'utf8') > MAX_PLAINTEXT_BYTES) {
      throw fail(`${label} exceeds its size limit`)
    }
    let encrypted: Buffer
    try {
      encrypted = this.dependencies.safeStorage.encryptString(plaintext)
    } catch (error) {
      throw fail(`${label} encryption failed`, error)
    }
    if (!Buffer.isBuffer(encrypted) || encrypted.length < 1) {
      throw fail(`${label} encryption failed`)
    }
    const envelope = JSON.stringify({
      schema,
      protection: PROTECTION,
      ciphertext: encrypted.toString('base64')
    })
    if (Buffer.byteLength(envelope, 'utf8') > MAX_FILE_BYTES) {
      throw fail(`${label} envelope exceeds its size limit`)
    }
    return envelope
  }

  private decode(raw: string, schema: string, label: string): Record<string, unknown> {
    this.requireEncryption()
    if (Buffer.byteLength(raw, 'utf8') > MAX_FILE_BYTES) throw fail(`${label} exceeds its size limit`)
    const envelope = parseObject(raw, `${label} envelope`)
    if (
      !exactKeys(envelope, ['schema', 'protection', 'ciphertext']) ||
      envelope.schema !== schema ||
      envelope.protection !== PROTECTION
    ) {
      throw fail(`${label} envelope is invalid`)
    }
    let plaintext: string
    try {
      plaintext = this.dependencies.safeStorage.decryptString(decodeBase64(envelope.ciphertext))
    } catch (error) {
      if (error instanceof PaidMediaInstallationRootError) throw error
      throw fail(`${label} decryption failed`, error)
    }
    if (Buffer.byteLength(plaintext, 'utf8') > MAX_PLAINTEXT_BYTES) {
      throw fail(`${label} plaintext exceeds its size limit`)
    }
    return parseObject(plaintext, label)
  }

  private parsePending(value: unknown): PendingIntent | null {
    if (value === null) return null
    if (isRecord(value) && value.mode === 'recoverable') {
      if (
        !exactKeys(value, [
          'mode',
          'handlerVersion',
          'kind',
          'operationId',
          'intentSha256',
          'transactionId',
          'preparedAt',
          'beforeCompositeDigest',
          'beforeAuthorityEvidence'
        ]) ||
        value.handlerVersion !== PAID_MEDIA_RECOVERABLE_HANDLER_VERSION ||
        !isRecoverableKind(value.kind) ||
        typeof value.operationId !== 'string' ||
        !OPERATION_ID_PATTERN.test(value.operationId) ||
        !digest(value.intentSha256) ||
        typeof value.transactionId !== 'string' ||
        !UUID_PATTERN.test(value.transactionId) ||
        !counter(value.preparedAt) ||
        !digest(value.beforeCompositeDigest)
      ) {
        throw fail('Paid media recoverable pending intent is invalid')
      }
      const beforeAuthorityEvidence = canonicalEvidence(value.beforeAuthorityEvidence)
      if (paidMediaCompositeEvidenceDigest(beforeAuthorityEvidence) !== value.beforeCompositeDigest) {
        throw fail('Paid media recoverable pending evidence does not match')
      }
      return {
        mode: 'recoverable',
        handlerVersion: PAID_MEDIA_RECOVERABLE_HANDLER_VERSION,
        kind: value.kind,
        operationId: value.operationId,
        intentSha256: value.intentSha256,
        transactionId: value.transactionId.toLowerCase(),
        preparedAt: Number(value.preparedAt),
        beforeCompositeDigest: value.beforeCompositeDigest,
        beforeAuthorityEvidence: frozenEvidence(beforeAuthorityEvidence)
      }
    }
    if (
      !isRecord(value) ||
      !exactKeys(value, [
        'transactionId',
        'kind',
        'operationId',
        'preparedAt',
        'beforeCompositeDigest'
      ]) ||
      typeof value.transactionId !== 'string' ||
      !UUID_PATTERN.test(value.transactionId) ||
      typeof value.kind !== 'string' ||
      !KIND_PATTERN.test(value.kind) ||
      (value.operationId !== null &&
        (typeof value.operationId !== 'string' || !OPERATION_ID_PATTERN.test(value.operationId))) ||
      !counter(value.preparedAt) ||
      !digest(value.beforeCompositeDigest)
    ) {
      throw fail('Paid media authority pending intent is invalid')
    }
    return {
      transactionId: value.transactionId.toLowerCase(),
      kind: value.kind,
      operationId: value.operationId as string | null,
      preparedAt: Number(value.preparedAt),
      beforeCompositeDigest: value.beforeCompositeDigest
    }
  }

  private parseRecoverableCommit(value: unknown): RecoverableCommitReceipt {
    if (
      !isRecord(value) ||
      !exactKeys(value, [
        'mode',
        'handlerVersion',
        'kind',
        'operationId',
        'intentSha256',
        'transactionId',
        'preparedAt',
        'pendingStateDigest',
        'beforeCompositeDigest',
        'afterCompositeDigest',
        'afterAuthorityEvidence'
      ]) ||
      value.mode !== 'recoverable' ||
      value.handlerVersion !== PAID_MEDIA_RECOVERABLE_HANDLER_VERSION ||
      !isRecoverableKind(value.kind) ||
      typeof value.operationId !== 'string' ||
      !OPERATION_ID_PATTERN.test(value.operationId) ||
      !digest(value.intentSha256) ||
      typeof value.transactionId !== 'string' ||
      !UUID_PATTERN.test(value.transactionId) ||
      !counter(value.preparedAt) ||
      !digest(value.pendingStateDigest) ||
      !digest(value.beforeCompositeDigest) ||
      !digest(value.afterCompositeDigest)
    ) {
      throw fail('Paid media recoverable commit receipt is invalid')
    }
    const afterAuthorityEvidence = canonicalEvidence(value.afterAuthorityEvidence)
    if (paidMediaCompositeEvidenceDigest(afterAuthorityEvidence) !== value.afterCompositeDigest) {
      throw fail('Paid media recoverable commit evidence does not match')
    }
    return {
      mode: 'recoverable',
      handlerVersion: PAID_MEDIA_RECOVERABLE_HANDLER_VERSION,
      kind: value.kind,
      operationId: value.operationId,
      intentSha256: value.intentSha256,
      transactionId: value.transactionId.toLowerCase(),
      preparedAt: Number(value.preparedAt),
      pendingStateDigest: value.pendingStateDigest,
      beforeCompositeDigest: value.beforeCompositeDigest,
      afterCompositeDigest: value.afterCompositeDigest,
      afterAuthorityEvidence: frozenEvidence(afterAuthorityEvidence)
    }
  }

  private parseDocument(value: Record<string, unknown>): AuthorityDocument {
    const hasRecoverableCommit = Object.prototype.hasOwnProperty.call(value, 'recoverableCommit')
    if (
      !exactKeys(value, [
        'schema',
        'installationId',
        'epoch',
        'desktopIdentity',
        'rootPrincipalDigest',
        'mutationSequence',
        'stateDigest',
        'previousStateDigest',
        'compositeDigest',
        'authorityMode',
        'recoveryFloor',
        'recoveryStateDigest',
        'pendingIntent',
        ...(hasRecoverableCommit ? ['recoverableCommit'] : [])
      ]) ||
      value.schema !== DOCUMENT_SCHEMA ||
      !digest(value.installationId) ||
      !counter(value.epoch, 1) ||
      !digest(value.desktopIdentity) ||
      !digest(value.rootPrincipalDigest) ||
      !counter(value.mutationSequence) ||
      !digest(value.stateDigest) ||
      (value.previousStateDigest !== null && !digest(value.previousStateDigest)) ||
      !digest(value.compositeDigest) ||
      (value.authorityMode !== 'normal' && value.authorityMode !== 'manual_only') ||
      (value.recoveryFloor !== null && !counter(value.recoveryFloor)) ||
      (value.recoveryStateDigest !== null && !digest(value.recoveryStateDigest))
    ) {
      throw fail('Paid media authority document is invalid')
    }
    const pendingIntent = this.parsePending(value.pendingIntent)
    const recoverableCommit = hasRecoverableCommit
      ? this.parseRecoverableCommit(value.recoverableCommit)
      : undefined
    const document: AuthorityDocument = {
      schema: DOCUMENT_SCHEMA,
      installationId: value.installationId,
      epoch: Number(value.epoch),
      desktopIdentity: value.desktopIdentity,
      rootPrincipalDigest: value.rootPrincipalDigest,
      mutationSequence: Number(value.mutationSequence),
      stateDigest: value.stateDigest,
      previousStateDigest: value.previousStateDigest as string | null,
      compositeDigest: value.compositeDigest,
      authorityMode: value.authorityMode,
      recoveryFloor: value.recoveryFloor === null ? null : Number(value.recoveryFloor),
      recoveryStateDigest: value.recoveryStateDigest as string | null,
      pendingIntent,
      ...(recoverableCommit === undefined ? {} : { recoverableCommit })
    }
    if (
      (document.mutationSequence === 0
        ? document.previousStateDigest !== null
        : document.previousStateDigest === null) ||
      (document.recoveryFloor === null) !== (document.recoveryStateDigest === null) ||
      (document.authorityMode === 'normal' &&
        (document.recoveryFloor !== null || document.recoveryStateDigest !== null)) ||
      (document.recoveryFloor !== null &&
        (document.authorityMode !== 'manual_only' ||
          document.mutationSequence !== document.recoveryFloor + 1)) ||
      (document.pendingIntent !== null && document.authorityMode !== 'normal') ||
      (document.pendingIntent !== null && document.recoverableCommit !== undefined) ||
      (document.recoverableCommit !== undefined &&
        (document.authorityMode !== 'normal' ||
          document.pendingIntent !== null ||
          document.mutationSequence < 2 ||
          document.previousStateDigest !== document.recoverableCommit.pendingStateDigest ||
          document.compositeDigest !== document.recoverableCommit.afterCompositeDigest)) ||
      stateDigestFor(document.previousStateDigest, document) !== document.stateDigest
    ) {
      throw fail('Paid media authority document state is inconsistent')
    }
    return document
  }

  private parseAnchor(value: Record<string, unknown>): AuthorityAnchor {
    if (
      !exactKeys(value, [
        'schema',
        'installationId',
        'epoch',
        'desktopIdentity',
        'mutationSequence',
        'stateDigest'
      ]) ||
      value.schema !== ANCHOR_SCHEMA ||
      !digest(value.installationId) ||
      !counter(value.epoch, 1) ||
      !digest(value.desktopIdentity) ||
      !counter(value.mutationSequence) ||
      !digest(value.stateDigest)
    ) {
      throw fail('Paid media authority anchor is invalid')
    }
    return {
      schema: ANCHOR_SCHEMA,
      installationId: value.installationId,
      epoch: Number(value.epoch),
      desktopIdentity: value.desktopIdentity,
      mutationSequence: Number(value.mutationSequence),
      stateDigest: value.stateDigest
    }
  }

  private parsePairIntent(value: Record<string, unknown>): AuthorityPairIntent {
    if (
      !exactKeys(value, [
        'schema',
        'installationId',
        'epoch',
        'desktopIdentity',
        'expectedPreviousSequence',
        'expectedPreviousStateDigest',
        'expectedPreviousDocument',
        'expectedPreviousAnchor',
        'targetSequence',
        'targetStateDigest',
        'targetDocument',
        'targetAnchor',
        'receiptDigest'
      ]) ||
      value.schema !== PAIR_INTENT_SCHEMA ||
      !digest(value.installationId) ||
      !counter(value.epoch, 1) ||
      !digest(value.desktopIdentity) ||
      (value.expectedPreviousSequence !== null && !counter(value.expectedPreviousSequence)) ||
      (value.expectedPreviousStateDigest !== null && !digest(value.expectedPreviousStateDigest)) ||
      !counter(value.targetSequence) ||
      !digest(value.targetStateDigest) ||
      !digest(value.receiptDigest) ||
      !isRecord(value.targetDocument) ||
      !isRecord(value.targetAnchor)
    ) {
      throw fail('Paid media authority pair intent is invalid')
    }
    const targetDocument = this.parseDocument(value.targetDocument)
    const targetAnchor = this.parseAnchor(value.targetAnchor)
    const hasExpected = value.expectedPreviousDocument !== null
    if (
      hasExpected !== (value.expectedPreviousAnchor !== null) ||
      hasExpected !== (value.expectedPreviousSequence !== null) ||
      hasExpected !== (value.expectedPreviousStateDigest !== null) ||
      (hasExpected &&
        (!isRecord(value.expectedPreviousDocument) || !isRecord(value.expectedPreviousAnchor)))
    ) {
      throw fail('Paid media authority pair intent predecessor is invalid')
    }
    const expectedPreviousDocument = hasExpected
      ? this.parseDocument(value.expectedPreviousDocument as Record<string, unknown>)
      : null
    const expectedPreviousAnchor = hasExpected
      ? this.parseAnchor(value.expectedPreviousAnchor as Record<string, unknown>)
      : null
    const intentWithoutReceipt: Omit<AuthorityPairIntent, 'receiptDigest'> = {
      schema: PAIR_INTENT_SCHEMA,
      installationId: value.installationId,
      epoch: Number(value.epoch),
      desktopIdentity: value.desktopIdentity,
      expectedPreviousSequence:
        value.expectedPreviousSequence === null ? null : Number(value.expectedPreviousSequence),
      expectedPreviousStateDigest: value.expectedPreviousStateDigest as string | null,
      expectedPreviousDocument,
      expectedPreviousAnchor,
      targetSequence: Number(value.targetSequence),
      targetStateDigest: value.targetStateDigest,
      targetDocument,
      targetAnchor
    }
    if (
      targetDocument.installationId !== intentWithoutReceipt.installationId ||
      targetDocument.epoch !== intentWithoutReceipt.epoch ||
      targetDocument.desktopIdentity !== intentWithoutReceipt.desktopIdentity ||
      targetDocument.mutationSequence !== intentWithoutReceipt.targetSequence ||
      targetDocument.stateDigest !== intentWithoutReceipt.targetStateDigest ||
      !sameAuthorityAnchor(authorityAnchorFor(targetDocument), targetAnchor) ||
      (expectedPreviousDocument === null
        ? targetDocument.mutationSequence !== 0 || targetDocument.previousStateDigest !== null
        : expectedPreviousAnchor === null ||
          expectedPreviousDocument.installationId !== intentWithoutReceipt.installationId ||
          expectedPreviousDocument.epoch !== intentWithoutReceipt.epoch ||
          expectedPreviousDocument.desktopIdentity !== intentWithoutReceipt.desktopIdentity ||
          expectedPreviousDocument.rootPrincipalDigest !== targetDocument.rootPrincipalDigest ||
          expectedPreviousDocument.mutationSequence !==
            intentWithoutReceipt.expectedPreviousSequence ||
          expectedPreviousDocument.stateDigest !==
            intentWithoutReceipt.expectedPreviousStateDigest ||
          !sameAuthorityAnchor(authorityAnchorFor(expectedPreviousDocument), expectedPreviousAnchor) ||
          targetDocument.mutationSequence !==
            nextCounter(expectedPreviousDocument.mutationSequence) ||
          targetDocument.previousStateDigest !== expectedPreviousDocument.stateDigest) ||
      authorityPairIntentReceipt(intentWithoutReceipt) !== value.receiptDigest
    ) {
      throw fail('Paid media authority pair intent does not match its transaction')
    }
    return {
      ...intentWithoutReceipt,
      receiptDigest: value.receiptDigest
    }
  }

  private readDocument(): AuthorityDocument | null {
    const rawDocument = this.dependencies.atomicIO.readUtf8(
      this.path,
      MAX_FILE_BYTES,
      this.dependencies.harden
    )
    const rawAnchor = this.dependencies.atomicIO.readUtf8(
      this.anchorPath,
      MAX_FILE_BYTES,
      this.dependencies.harden
    )
    const rawPairIntent = this.dependencies.atomicIO.readUtf8(
      this.pairIntentPath,
      MAX_FILE_BYTES,
      this.dependencies.harden
    )
    const document =
      rawDocument === null
        ? null
        : this.parseDocument(this.decode(rawDocument, ENVELOPE_SCHEMA, 'Paid media authority'))
    const anchor =
      rawAnchor === null
        ? null
        : this.parseAnchor(
            this.decode(rawAnchor, ANCHOR_ENVELOPE_SCHEMA, 'Paid media authority anchor')
          )
    if (rawPairIntent === null) {
      if (document === null && anchor === null) return null
      if (document === null || anchor === null) throw fail('Paid media authority pair is incomplete')
      if (!sameAuthorityAnchor(authorityAnchorFor(document), anchor)) {
        throw fail('Paid media authority rollback or replacement was detected')
      }
      return document
    }
    const intent = this.parsePairIntent(
      this.decode(
        rawPairIntent,
        PAIR_INTENT_ENVELOPE_SCHEMA,
        'Paid media authority pair intent'
      )
    )
    const documentIsTarget = document !== null && sameAuthorityDocument(document, intent.targetDocument)
    const documentIsPrevious =
      intent.expectedPreviousDocument === null
        ? document === null
        : document !== null && sameAuthorityDocument(document, intent.expectedPreviousDocument)
    const anchorIsTarget = anchor !== null && sameAuthorityAnchor(anchor, intent.targetAnchor)
    const anchorIsPrevious =
      intent.expectedPreviousAnchor === null
        ? anchor === null
        : anchor !== null && sameAuthorityAnchor(anchor, intent.expectedPreviousAnchor)
    if ((!documentIsTarget && !documentIsPrevious) || (!anchorIsTarget && !anchorIsPrevious)) {
      throw fail('Paid media authority pair does not belong to its transaction')
    }
    if (!anchorIsTarget || !documentIsTarget) {
      this.writePairTarget(intent.targetDocument, intent.targetAnchor)
    }
    return cloneDocument(intent.targetDocument)
  }

  private writePairTarget(document: AuthorityDocument, anchor: AuthorityAnchor): void {
    this.dependencies.atomicIO.writeUtf8Atomic(
      this.anchorPath,
      this.encode(anchor, ANCHOR_ENVELOPE_SCHEMA, 'Paid media authority anchor'),
      this.dependencies.harden
    )
    this.dependencies.atomicIO.writeUtf8Atomic(
      this.path,
      this.encode(document, ENVELOPE_SCHEMA, 'Paid media authority'),
      this.dependencies.harden
    )
  }

  private writeDocument(document: AuthorityDocument): void {
    const parsed = this.parseDocument(document as unknown as Record<string, unknown>)
    const previous = this.readDocument()
    if (previous !== null && sameAuthorityDocument(previous, parsed)) return
    if (
      (previous === null &&
        (parsed.mutationSequence !== 0 || parsed.previousStateDigest !== null)) ||
      (previous !== null &&
        (parsed.installationId !== previous.installationId ||
          parsed.epoch !== previous.epoch ||
          parsed.desktopIdentity !== previous.desktopIdentity ||
          parsed.rootPrincipalDigest !== previous.rootPrincipalDigest ||
          parsed.mutationSequence !== nextCounter(previous.mutationSequence) ||
          parsed.previousStateDigest !== previous.stateDigest))
    ) {
      throw fail('Paid media authority pair transition is invalid')
    }
    const targetAnchor = authorityAnchorFor(parsed)
    const expectedPreviousAnchor = previous === null ? null : authorityAnchorFor(previous)
    const intentWithoutReceipt: Omit<AuthorityPairIntent, 'receiptDigest'> = {
      schema: PAIR_INTENT_SCHEMA,
      installationId: parsed.installationId,
      epoch: parsed.epoch,
      desktopIdentity: parsed.desktopIdentity,
      expectedPreviousSequence: previous?.mutationSequence ?? null,
      expectedPreviousStateDigest: previous?.stateDigest ?? null,
      expectedPreviousDocument: previous === null ? null : cloneDocument(previous),
      expectedPreviousAnchor,
      targetSequence: parsed.mutationSequence,
      targetStateDigest: parsed.stateDigest,
      targetDocument: cloneDocument(parsed),
      targetAnchor
    }
    const intent = this.parsePairIntent({
      ...intentWithoutReceipt,
      receiptDigest: authorityPairIntentReceipt(intentWithoutReceipt)
    } as unknown as Record<string, unknown>)
    this.dependencies.atomicIO.writeUtf8Atomic(
      this.pairIntentPath,
      this.encode(intent, PAIR_INTENT_ENVELOPE_SCHEMA, 'Paid media authority pair intent'),
      this.dependencies.harden
    )
    this.writePairTarget(parsed, targetAnchor)
  }

  private async readEvidence(): Promise<{ value: PaidMediaAuthorityEvidence; digest: string }> {
    if (!this.evidenceReader) throw fail('Paid media composite evidence reader is unavailable')
    const value = canonicalEvidence(await this.evidenceReader())
    return { value, digest: paidMediaCompositeEvidenceDigest(value) }
  }

  private validateSnapshot(
    snapshot: InstallationRootSnapshot,
    document: AuthorityDocument,
    requireActive = true
  ): InstallationRootComponentSnapshot {
    if (
      (requireActive && snapshot.status !== 'active') ||
      (!requireActive && snapshot.status !== 'active' && snapshot.status !== 'provisioning') ||
      snapshot.lockKind !== 'none' ||
      snapshot.reanchorPending ||
      snapshot.installationId !== document.installationId ||
      snapshot.epoch !== document.epoch ||
      snapshot.principalDigest !== document.rootPrincipalDigest
    ) {
      throw fail('Paid media installation identity or epoch drift was detected')
    }
    const component = snapshot.components.desktop
    if (
      !component.bound ||
      component.identity !== document.desktopIdentity ||
      component.epoch !== document.epoch ||
      !digest(component.stateDigest)
    ) {
      throw fail('Paid media Desktop component binding drift was detected')
    }
    return component
  }

  private publish(
    mode: PaidMediaInstallationRootMode,
    reasonCode: string,
    document?: AuthorityDocument
  ): PaidMediaInstallationRootState {
    const recoverable =
      document && isRecoverablePending(document.pendingIntent)
        ? document.pendingIntent
        : document?.recoverableCommit
    this.stateValue = {
      mode,
      reasonCode,
      ...(document
        ? {
            installationId: document.installationId,
            epoch: document.epoch,
            desktopIdentity: document.desktopIdentity,
            mutationSequence: document.mutationSequence,
            stateDigest: document.stateDigest,
            ...(mode === 'ready' || mode === 'manual_only'
              ? { paidPrincipal: paidPrincipal(document.rootPrincipalDigest) }
              : {}),
            ...(recoverable && mode !== 'ready' && mode !== 'manual_only'
              ? {
                  pendingRecovery: {
                    handlerVersion: recoverable.handlerVersion,
                    kind: recoverable.kind,
                    operationId: recoverable.operationId,
                    intentSha256: recoverable.intentSha256,
                    preparedAt: recoverable.preparedAt,
                    beforeCompositeDigest: recoverable.beforeCompositeDigest
                  }
                }
              : {})
          }
        : {})
    }
    return this.state
  }

  private fuse(reasonCode: string, document?: AuthorityDocument): PaidMediaInstallationRootState {
    return this.publish('fused', reasonCode, document)
  }

  provision(): Promise<PaidMediaInstallationRootState> {
    return this.serialize(async () => {
      let document: AuthorityDocument | null = null
      try {
        let envelope: Awaited<ReturnType<RootClient['snapshot']>>
        try {
          envelope = await this.dependencies.client.snapshot()
        } catch (error) {
          throw new PaidMediaInstallationRootReadTransientError(
            'Installation Root snapshot is temporarily unavailable',
            { cause: error }
          )
        }
        const snapshot = envelope.snapshot
        if (
          (snapshot.status !== 'provisioning' && snapshot.status !== 'active') ||
          snapshot.lockKind !== 'none' ||
          snapshot.reanchorPending ||
          !digest(snapshot.installationId) ||
          !counter(snapshot.epoch, 1) ||
          !digest(snapshot.principalDigest)
        ) {
          throw fail('Installation Root is not accepting Desktop provisioning')
        }
        const component = snapshot.components.desktop
        if (
          !digest(component.identity) ||
          component.epoch !== snapshot.epoch ||
          (component.bound && snapshot.status === 'provisioning' && !digest(component.stateDigest))
        ) {
          throw fail('Installer-preallocated Desktop identity is invalid')
        }
        document = this.readDocument()
        if (document === null) {
          if (component.bound || snapshot.status !== 'provisioning') {
            throw fail('Bound Desktop authority is missing and cannot be recreated')
          }
          const composite = await this.readEvidence()
          document = makeDocument({
            installationId: snapshot.installationId,
            epoch: snapshot.epoch,
            desktopIdentity: component.identity,
            rootPrincipalDigest: snapshot.principalDigest,
            mutationSequence: 0,
            previousStateDigest: null,
            compositeDigest: composite.digest,
            authorityMode: 'normal',
            recoveryFloor: null,
            recoveryStateDigest: null,
            pendingIntent: null
          })
          this.writeDocument(document)
        }
        if (
          document.installationId !== snapshot.installationId ||
          document.epoch !== snapshot.epoch ||
          document.desktopIdentity !== component.identity ||
          document.rootPrincipalDigest !== snapshot.principalDigest
        ) {
          throw fail('Local Desktop authority does not match the installer identity')
        }
        const composite = await this.readEvidence()
        if (
          composite.digest !== document.compositeDigest &&
          !(component.bound && isRecoverablePending(document.pendingIntent))
        ) {
          throw fail('Paid media composite evidence changed before Desktop binding')
        }
        if (!component.bound) {
          const result = await this.dependencies.client.bindDesktop({
            installationId: document.installationId,
            epoch: document.epoch,
            identity: document.desktopIdentity,
            stateDigest: document.stateDigest,
            expectedRootRevision: snapshot.rootRevision,
            sequenceFloor: document.mutationSequence
          })
          const bound = this.validateSnapshot(result.snapshot, document, false)
          if (!sameProof(bound, document) || bound.recoveryFloor !== null) {
            throw fail('Installation Root did not confirm the exact Desktop binding')
          }
          if (result.snapshot.status === 'provisioning') {
            return this.publish(
              'provisioned_not_active',
              'awaiting-installation-activation',
              document
            )
          }
        }
        return await this.reconcileUnlocked()
      } catch (error) {
        if (error instanceof PaidMediaInstallationRootReadTransientError && document === null) {
          this.publish('detached', 'installation-root-temporarily-unavailable')
          throw fail('Paid media Installation Root is temporarily unavailable', error)
        }
        this.fuse('provisioning-failed', document ?? undefined)
        if (error instanceof PaidMediaInstallationRootUnavailableError) throw error
        throw fail('Paid media Desktop provisioning failed', error)
      }
    })
  }

  reconcileStartup(): Promise<PaidMediaInstallationRootState> {
    return this.serialize(() => this.reconcileUnlocked())
  }

  private async enterManualRecovery(
    snapshot: InstallationRootSnapshot,
    before: AuthorityDocument
  ): Promise<AuthorityDocument> {
    const composite = await this.readEvidence()
    const after = makeDocument({
      installationId: before.installationId,
      epoch: before.epoch,
      desktopIdentity: before.desktopIdentity,
      rootPrincipalDigest: before.rootPrincipalDigest,
      mutationSequence: nextCounter(before.mutationSequence),
      previousStateDigest: before.stateDigest,
      compositeDigest: composite.digest,
      authorityMode: 'manual_only',
      recoveryFloor: before.mutationSequence,
      recoveryStateDigest: before.stateDigest,
      pendingIntent: null
    })
    this.writeDocument(after)
    await this.acknowledgeRecovery(snapshot, before, after)
    return after
  }

  private async acknowledgeRecovery(
    snapshot: InstallationRootSnapshot,
    before: AuthorityDocument,
    after: AuthorityDocument
  ): Promise<void> {
    const result = await this.dependencies.client.acknowledgeDesktopRecovery({
      installationId: after.installationId,
      epoch: after.epoch,
      identity: after.desktopIdentity,
      recoveryFloor: before.mutationSequence,
      recoveryStateDigest: before.stateDigest,
      nextFloor: after.mutationSequence,
      nextStateDigest: after.stateDigest,
      expectedRootRevision: snapshot.rootRevision
    })
    const component = this.validateSnapshot(result.snapshot, after)
    if (!sameProof(component, after) || component.recoveryFloor !== null) {
      throw fail('Installation Root did not acknowledge Desktop recovery')
    }
  }

  private async enterManualFromPending(
    snapshot: InstallationRootSnapshot,
    before: AuthorityDocument
  ): Promise<AuthorityDocument> {
    const composite = await this.readEvidence()
    const after = makeDocument({
      installationId: before.installationId,
      epoch: before.epoch,
      desktopIdentity: before.desktopIdentity,
      rootPrincipalDigest: before.rootPrincipalDigest,
      mutationSequence: nextCounter(before.mutationSequence),
      previousStateDigest: before.stateDigest,
      compositeDigest: composite.digest,
      authorityMode: 'manual_only',
      recoveryFloor: null,
      recoveryStateDigest: null,
      pendingIntent: null
    })
    this.writeDocument(after)
    await this.confirmTransition(before, after, snapshot)
    return after
  }

  private recoverableBeforeProof(
    document: AuthorityDocument & { pendingIntent: RecoverablePendingIntent }
  ): Pick<AuthorityDocument, 'mutationSequence' | 'stateDigest'> {
    if (document.mutationSequence < 1 || document.previousStateDigest === null) {
      throw fail('Paid media recoverable pending predecessor is invalid')
    }
    return {
      mutationSequence: document.mutationSequence - 1,
      stateDigest: document.previousStateDigest
    }
  }

  private async assertRecoverableBeforeEvidence(
    pending: RecoverablePendingIntent
  ): Promise<void> {
    const current = await this.readEvidence()
    if (
      current.digest !== pending.beforeCompositeDigest ||
      !sameAuthorityEvidence(current.value, pending.beforeAuthorityEvidence)
    ) {
      throw fail('Paid media recoverable before-authority evidence changed')
    }
  }

  private async confirmRecoverableTransition(
    before: Pick<AuthorityDocument, 'mutationSequence' | 'stateDigest'>,
    after: AuthorityDocument,
    initialSnapshot?: InstallationRootSnapshot
  ): Promise<void> {
    try {
      await this.confirmTransition(before, after, initialSnapshot)
      return
    } catch (error) {
      let snapshot: InstallationRootSnapshot
      try {
        snapshot = (await this.dependencies.client.snapshot()).snapshot
      } catch (snapshotError) {
        throw new PaidMediaInstallationRootReadTransientError(
          'Installation Root recoverable transition is temporarily unavailable',
          { cause: snapshotError }
        )
      }
      const component = this.validateSnapshot(snapshot, after)
      if (component.recoveryFloor !== null) {
        throw fail('Paid media recoverable Root gained a recovery fence')
      }
      if (sameProof(component, after)) return
      if (sameProof(component, before)) {
        throw new PaidMediaInstallationRootReadTransientError(
          'Installation Root recoverable transition has not committed',
          { cause: error }
        )
      }
      throw fail('Paid media recoverable Root floor is neither before nor pending', error)
    }
  }

  private async convergeRecoverablePendingRoot(
    document: AuthorityDocument & { pendingIntent: RecoverablePendingIntent },
    initialSnapshot?: InstallationRootSnapshot
  ): Promise<void> {
    let snapshot = initialSnapshot
    if (!snapshot) {
      try {
        snapshot = (await this.dependencies.client.snapshot()).snapshot
      } catch (error) {
        throw new PaidMediaInstallationRootReadTransientError(
          'Installation Root recoverable pending proof is temporarily unavailable',
          { cause: error }
        )
      }
    }
    const component = this.validateSnapshot(snapshot, document)
    if (component.recoveryFloor !== null) {
      throw fail('Paid media recoverable Root has a recovery fence')
    }
    if (sameProof(component, document)) return
    const before = this.recoverableBeforeProof(document)
    if (!sameProof(component, before)) {
      throw fail('Paid media recoverable Root floor is neither before nor pending')
    }
    // With the stronger pending-first protocol, no handler is authorized while
    // Root is still at the predecessor. Any local authority drift here cannot
    // be a legitimate partial handler and must never be blessed.
    await this.assertRecoverableBeforeEvidence(document.pendingIntent)
    await this.confirmRecoverableTransition(before, document, snapshot)
  }

  private activateRecoverablePending(
    document: AuthorityDocument & { pendingIntent: RecoverablePendingIntent },
    reasonCode: string
  ): PaidMediaInstallationRootState {
    this.activeMutation = {
      mode: 'recoverable',
      transactionId: document.pendingIntent.transactionId,
      pending: document
    }
    return this.publish('recovery_pending', reasonCode, document)
  }

  private recoverableCommitPendingProof(
    document: AuthorityDocument & { recoverableCommit: RecoverableCommitReceipt }
  ): Pick<AuthorityDocument, 'mutationSequence' | 'stateDigest'> {
    if (
      document.mutationSequence < 1 ||
      document.previousStateDigest !== document.recoverableCommit.pendingStateDigest
    ) {
      throw fail('Paid media recoverable final predecessor is invalid')
    }
    return {
      mutationSequence: document.mutationSequence - 1,
      stateDigest: document.recoverableCommit.pendingStateDigest
    }
  }

  private async reconcileUnlocked(): Promise<PaidMediaInstallationRootState> {
    let local: AuthorityDocument | null = null
    try {
      for (let inspection = 0; inspection < MAX_RECONCILE_INSPECTIONS; inspection += 1) {
        local = this.readDocument()
        if (local === null) throw fail('Paid media authority is missing')
        let envelope: Awaited<ReturnType<RootClient['snapshot']>>
        try {
          envelope = await this.dependencies.client.snapshot()
        } catch (error) {
          throw new PaidMediaInstallationRootReadTransientError(
            'Installation Root snapshot is temporarily unavailable',
            { cause: error }
          )
        }
        const snapshot = envelope.snapshot
        if (snapshot.status === 'provisioning') {
          const component = this.validateSnapshot(snapshot, local, false)
          if (
            !sameProof(component, local) ||
            component.recoveryFloor !== null ||
            local.authorityMode !== 'normal' ||
            local.pendingIntent !== null ||
            local.recoverableCommit !== undefined
          ) {
            throw fail('Provisioning Desktop authority is not exact and quiescent')
          }
          const evidence = await this.readEvidence()
          if (evidence.digest !== local.compositeDigest) {
            throw fail('Provisioning Desktop composite evidence changed')
          }
          this.activeMutation = null
          return this.publish(
            'provisioned_not_active',
            'awaiting-installation-activation',
            local
          )
        }
        const component = this.validateSnapshot(snapshot, local)

        if (isRecoverablePending(local.pendingIntent)) {
          const recoverableLocal = local as AuthorityDocument & {
            pendingIntent: RecoverablePendingIntent
          }
          await this.convergeRecoverablePendingRoot(recoverableLocal, snapshot)
          return this.activateRecoverablePending(
            recoverableLocal,
            'recoverable-local-handler-pending'
          )
        }

        if (local.recoverableCommit !== undefined && !sameProof(component, local)) {
          const recoverableFinal = local as AuthorityDocument & {
            recoverableCommit: RecoverableCommitReceipt
          }
          const pendingProof = this.recoverableCommitPendingProof(recoverableFinal)
          if (component.recoveryFloor !== null || !sameProof(component, pendingProof)) {
            throw fail('Paid media recoverable final Root floor does not match its receipt')
          }
          const evidence = await this.readEvidence()
          if (
            evidence.digest !== recoverableFinal.recoverableCommit.afterCompositeDigest ||
            !sameAuthorityEvidence(
              evidence.value,
              recoverableFinal.recoverableCommit.afterAuthorityEvidence
            )
          ) {
            throw fail('Paid media recoverable final evidence changed before Root finalize')
          }
          await this.confirmRecoverableTransition(pendingProof, recoverableFinal, snapshot)
          continue
        }

        if (sameProof(component, local)) {
          if (component.recoveryFloor !== null) {
            if (
              component.recoveryFloor !== local.mutationSequence ||
              component.recoveryStateDigest !== local.stateDigest
            ) {
              throw fail('Desktop recovery fence drift was detected')
            }
            local = await this.enterManualRecovery(snapshot, local)
            continue
          }
          if (local.authorityMode === 'manual_only') {
            const evidence = await this.readEvidence()
            if (evidence.digest !== local.compositeDigest || local.pendingIntent !== null) {
              throw fail('Manual-only paid media evidence changed')
            }
            return this.publish('manual_only', 'manual-recovery-required', local)
          }
          if (local.pendingIntent !== null) {
            local = await this.enterManualFromPending(snapshot, local)
            continue
          }
          const evidence = await this.readEvidence()
          if (
            evidence.digest !== local.compositeDigest ||
            (local.recoverableCommit !== undefined &&
              !sameAuthorityEvidence(
                evidence.value,
                local.recoverableCommit.afterAuthorityEvidence
              ))
          ) {
            throw fail('Paid media composite evidence replacement was detected')
          }
          this.activeMutation = null
          return this.publish('ready', 'authority-exact', local)
        }

        if (
          component.recoveryFloor === null &&
          local.mutationSequence === component.sequenceFloor + 1 &&
          local.previousStateDigest === component.stateDigest
        ) {
          try {
            await this.dependencies.client.verifyDesktop({
              installationId: local.installationId,
              epoch: local.epoch,
              identity: local.desktopIdentity,
              sequenceFloor: local.mutationSequence,
              stateDigest: local.stateDigest,
              previousStateDigest: local.previousStateDigest
            })
          } catch {
            // A response can be lost after the Root installs its recovery
            // fence. Only the next fresh snapshot decides the branch.
          }
          continue
        }

        if (
          local.authorityMode === 'manual_only' &&
          local.recoveryFloor !== null &&
          local.recoveryStateDigest !== null &&
          component.sequenceFloor === local.recoveryFloor &&
          component.stateDigest === local.recoveryStateDigest &&
          component.recoveryFloor === local.recoveryFloor &&
          component.recoveryStateDigest === local.recoveryStateDigest
        ) {
          const before: AuthorityDocument = {
            ...local,
            mutationSequence: local.recoveryFloor,
            stateDigest: local.recoveryStateDigest,
            previousStateDigest: null,
            authorityMode: 'normal',
            recoveryFloor: null,
            recoveryStateDigest: null,
            pendingIntent: null
          }
          await this.acknowledgeRecovery(snapshot, before, local)
          continue
        }
        throw fail('Paid media Desktop floor gap is not recoverable')
      }
      throw fail('Paid media startup reconciliation did not converge')
    } catch (error) {
      if (error instanceof PaidMediaInstallationRootReadTransientError) {
        if (this.stateValue.mode !== 'ready') {
          this.publish('detached', 'installation-root-temporarily-unavailable', local ?? undefined)
        }
        throw fail('Paid media Installation Root is temporarily unavailable', error)
      }
      this.fuse('authority-reconciliation-failed', local ?? undefined)
      if (error instanceof PaidMediaInstallationRootUnavailableError) throw error
      throw fail('Paid media startup authority is unavailable', error)
    }
  }

  private validateMutationInput(input: PaidMediaAuthorityMutationInput): PaidMediaAuthorityMutationInput {
    if (!isRecord(input) || typeof input.kind !== 'string' || !KIND_PATTERN.test(input.kind)) {
      throw fail('Paid media authority mutation input is invalid')
    }
    const hasOperationId = Object.prototype.hasOwnProperty.call(input, 'operationId')
    if (
      !exactKeys(input, hasOperationId ? ['kind', 'operationId'] : ['kind']) ||
      (hasOperationId &&
        (typeof input.operationId !== 'string' || !OPERATION_ID_PATTERN.test(input.operationId)))
    ) {
      throw fail('Paid media authority mutation input is invalid')
    }
    return { kind: input.kind, ...(hasOperationId ? { operationId: input.operationId } : {}) }
  }

  private validateRecoverableInput(input: PaidMediaRecoverableMutationInput): PaidMediaRecoverableMutationInput {
    if (
      !isRecord(input) ||
      !exactKeys(input, ['handlerVersion', 'kind', 'operationId', 'intentSha256']) ||
      input.handlerVersion !== PAID_MEDIA_RECOVERABLE_HANDLER_VERSION ||
      !isRecoverableKind(input.kind) ||
      typeof input.operationId !== 'string' ||
      !OPERATION_ID_PATTERN.test(input.operationId) ||
      !digest(input.intentSha256)
    ) {
      throw fail('Paid media recoverable mutation input is invalid')
    }
    return {
      handlerVersion: PAID_MEDIA_RECOVERABLE_HANDLER_VERSION,
      kind: input.kind,
      operationId: input.operationId,
      intentSha256: input.intentSha256
    }
  }

  private recoverableMatchesInput(
    value: PaidMediaRecoverableMutationDescriptor | RecoverableCommitReceipt,
    input: PaidMediaRecoverableMutationInput
  ): boolean {
    return (
      value.handlerVersion === input.handlerVersion &&
      value.kind === input.kind &&
      value.operationId === input.operationId &&
      value.intentSha256 === input.intentSha256
    )
  }

  private requireRecoverableExecutor(): PaidMediaRecoverableMutationExecutor {
    const executor = this.dependencies.recoverableExecutor
    if (!executor || typeof executor.execute !== 'function') {
      throw fail('Paid media recoverable local executor is unavailable')
    }
    return executor
  }

  private assertRecoverableAfterEvidence(
    kind: PaidMediaRecoverableMutationKind,
    before: PaidMediaAuthorityEvidence,
    after: PaidMediaAuthorityEvidence
  ): void {
    const ledgerSame =
      before.ledgerSequence === after.ledgerSequence &&
      before.ledgerStateDigest === after.ledgerStateDigest
    const ledgerChanged =
      after.ledgerSequence > before.ledgerSequence &&
      after.ledgerStateDigest !== before.ledgerStateDigest
    const vaultSame = before.vaultStateDigest === after.vaultStateDigest
    const capacitySame =
      before.capacitySequence === after.capacitySequence &&
      before.capacityStateDigest === after.capacityStateDigest
    const capacityChanged =
      after.capacitySequence > before.capacitySequence &&
      after.capacityStateDigest !== before.capacityStateDigest
    const expected = (() => {
      switch (kind) {
        case 'asset_v2_dispatch':
          return { ledgerChanged: true, vaultChanged: true, capacityChanged: true }
        case 'asset_v2_result_ready_ack_intent':
          return { ledgerChanged: true, vaultChanged: true, capacityChanged: false }
        case 'asset_v2_stage_reserve':
        case 'asset_v2_stage_archive':
        case 'asset_v2_stage_cleanup':
        case 'asset_v2_ack_completion':
          return { ledgerChanged: false, vaultChanged: true, capacityChanged: false }
        case 'asset_v2_capacity_release':
          return { ledgerChanged: false, vaultChanged: true, capacityChanged: true }
      }
    })()
    if (
      before.ledgerIdentity !== after.ledgerIdentity ||
      before.capacityIdentity !== after.capacityIdentity ||
      before.legacySealDecisionSha256 !== after.legacySealDecisionSha256 ||
      (expected.ledgerChanged ? !ledgerChanged : !ledgerSame) ||
      (expected.vaultChanged ? vaultSame : !vaultSame) ||
      (expected.capacityChanged ? !capacityChanged : !capacitySame)
    ) {
      throw new PaidMediaRecoverableMutationConflictError(
        'Paid media recoverable authority transition conflicts with its closed handler policy'
      )
    }
  }

  private async enterManualFromRecoverableConflict(
    pending: AuthorityDocument & { pendingIntent: RecoverablePendingIntent },
    conflict: PaidMediaRecoverableMutationConflictError
  ): Promise<never> {
    this.activeMutation = null
    try {
      const snapshot = (await this.dependencies.client.snapshot()).snapshot
      const component = this.validateSnapshot(snapshot, pending)
      if (component.recoveryFloor !== null || !sameProof(component, pending)) {
        throw fail('Paid media recoverable conflict Root pending is not exact')
      }
      const manual = await this.enterManualFromPending(snapshot, pending)
      this.publish('manual_only', 'recoverable-local-conflict', manual)
    } catch (error) {
      this.fuse('recoverable-conflict-unconfirmed', this.readDocument() ?? pending)
      throw error instanceof PaidMediaInstallationRootUnavailableError
        ? error
        : fail('Paid media recoverable conflict could not enter manual-only mode', error)
    }
    throw conflict
  }

  private async executeRecoverablePending(
    pending: AuthorityDocument & { pendingIntent: RecoverablePendingIntent },
    input: PaidMediaRecoverableMutationInput
  ): Promise<PaidMediaInstallationRootState> {
    if (!this.recoverableMatchesInput(pending.pendingIntent, input)) {
      throw fail('Paid media recoverable resume descriptor does not match the pending intent')
    }
    const executor = this.requireRecoverableExecutor()

    // Every execution attempt obtains a fresh signed Root proof. Merely having
    // sent the pending CAS previously never authorizes a local handler.
    await this.convergeRecoverablePendingRoot(pending)
    this.activateRecoverablePending(pending, 'recoverable-local-handler-active')

    try {
      await executor.execute(frozenRecoverableDescriptor(pending.pendingIntent))
    } catch (error) {
      if (error instanceof PaidMediaRecoverableMutationConflictError) {
        return await this.enterManualFromRecoverableConflict(pending, error)
      }
      this.activeMutation = null
      this.publish('recovery_pending', 'recoverable-local-handler-retry', pending)
      throw error
    }

    let afterEvidence: Awaited<ReturnType<PaidMediaInstallationRootAuthority['readEvidence']>>
    try {
      afterEvidence = await this.readEvidence()
      this.assertRecoverableAfterEvidence(
        pending.pendingIntent.kind,
        pending.pendingIntent.beforeAuthorityEvidence,
        afterEvidence.value
      )
    } catch (error) {
      if (error instanceof PaidMediaRecoverableMutationConflictError) {
        return await this.enterManualFromRecoverableConflict(pending, error)
      }
      this.activeMutation = null
      this.publish('recovery_pending', 'recoverable-postcondition-read-retry', pending)
      throw error
    }

    const commit: RecoverableCommitReceipt = {
      mode: 'recoverable',
      handlerVersion: pending.pendingIntent.handlerVersion,
      kind: pending.pendingIntent.kind,
      operationId: pending.pendingIntent.operationId,
      intentSha256: pending.pendingIntent.intentSha256,
      transactionId: pending.pendingIntent.transactionId,
      preparedAt: pending.pendingIntent.preparedAt,
      pendingStateDigest: pending.stateDigest,
      beforeCompositeDigest: pending.pendingIntent.beforeCompositeDigest,
      afterCompositeDigest: afterEvidence.digest,
      afterAuthorityEvidence: frozenEvidence(afterEvidence.value)
    }
    const finalDocument = makeDocument({
      installationId: pending.installationId,
      epoch: pending.epoch,
      desktopIdentity: pending.desktopIdentity,
      rootPrincipalDigest: pending.rootPrincipalDigest,
      mutationSequence: nextCounter(pending.mutationSequence),
      previousStateDigest: pending.stateDigest,
      compositeDigest: afterEvidence.digest,
      authorityMode: 'normal',
      recoveryFloor: null,
      recoveryStateDigest: null,
      pendingIntent: null,
      recoverableCommit: commit
    })

    try {
      this.writeDocument(finalDocument)
    } catch (error) {
      this.activeMutation = null
      // If the new pair intent did not publish, the exact old pending remains
      // resumable. Once that intent publishes, restart may complete only an
      // anchor/body member that is exactly its predecessor or exact target;
      // corrupt, unknown and cross-transaction members still fail closed.
      this.publish('recovery_pending', 'recoverable-final-write-retry', pending)
      throw error
    }

    try {
      await this.confirmRecoverableTransition(pending, finalDocument)
    } catch (error) {
      this.activeMutation = null
      if (error instanceof PaidMediaInstallationRootReadTransientError) {
        this.publish('recovery_pending', 'recoverable-root-finalize-pending', finalDocument)
        throw fail('Paid media recoverable Root finalization is temporarily unavailable', error)
      }
      this.fuse('recoverable-root-finalize-conflict', finalDocument)
      throw error instanceof PaidMediaInstallationRootUnavailableError
        ? error
        : fail('Paid media recoverable Root finalization conflicted', error)
    }
    this.activeMutation = null
    return this.publish('ready', 'recoverable-authority-exact', finalDocument)
  }

  async runRecoverableMutation(
    input: PaidMediaRecoverableMutationInput
  ): Promise<PaidMediaInstallationRootState> {
    const normalized = this.validateRecoverableInput(input)
    return this.serialize(async () => {
      if (this.stateValue.mode !== 'ready') {
        throw fail('Paid media recoverable mutation authority is unavailable')
      }
      await this.proveExactUnlocked()
      const before = this.readDocument()
      if (
        before === null ||
        before.authorityMode !== 'normal' ||
        before.pendingIntent !== null
      ) {
        throw fail('Paid media recoverable mutation precondition is unavailable')
      }
      if (
        before.recoverableCommit !== undefined &&
        this.recoverableMatchesInput(before.recoverableCommit, normalized)
      ) {
        // A caller may lose the successful response after both local and Root
        // finalization. Replaying the exact descriptor is a read-only success;
        // creating a new pending transaction would turn the handler's exact
        // idempotent no-op into a false conflict/manual-only transition.
        return await this.reconcileUnlocked()
      }
      this.requireRecoverableExecutor()
      const evidenceBefore = await this.readEvidence()
      if (evidenceBefore.digest !== before.compositeDigest) {
        this.fuse('recoverable-composite-evidence-drift', before)
        throw fail('Paid media composite evidence changed before recoverable mutation')
      }
      const transactionId = this.dependencies.uuid()
      const preparedAt = this.dependencies.now()
      if (!UUID_PATTERN.test(transactionId) || !counter(preparedAt)) {
        throw fail('Paid media recoverable mutation identity or clock is invalid')
      }
      const pendingIntent: RecoverablePendingIntent = {
        mode: 'recoverable',
        ...normalized,
        transactionId: transactionId.toLowerCase(),
        preparedAt,
        beforeCompositeDigest: evidenceBefore.digest,
        beforeAuthorityEvidence: frozenEvidence(evidenceBefore.value)
      }
      const pending = makeDocument({
        installationId: before.installationId,
        epoch: before.epoch,
        desktopIdentity: before.desktopIdentity,
        rootPrincipalDigest: before.rootPrincipalDigest,
        mutationSequence: nextCounter(before.mutationSequence),
        previousStateDigest: before.stateDigest,
        compositeDigest: before.compositeDigest,
        authorityMode: 'normal',
        recoveryFloor: null,
        recoveryStateDigest: null,
        pendingIntent
      }) as AuthorityDocument & { pendingIntent: RecoverablePendingIntent }
      this.writeDocument(pending)
      try {
        await this.convergeRecoverablePendingRoot(pending)
      } catch (error) {
        this.activeMutation = null
        if (error instanceof PaidMediaInstallationRootReadTransientError) {
          this.publish('detached', 'recoverable-root-pending-unconfirmed', pending)
          throw fail('Paid media recoverable Root pending is temporarily unavailable', error)
        }
        this.fuse('recoverable-root-pending-conflict', pending)
        throw error instanceof PaidMediaInstallationRootUnavailableError
          ? error
          : fail('Paid media recoverable Root pending conflicted', error)
      }
      return await this.executeRecoverablePending(pending, normalized)
    })
  }

  async resumeRecoverableMutation(
    input: PaidMediaRecoverableMutationInput
  ): Promise<PaidMediaInstallationRootState> {
    const normalized = this.validateRecoverableInput(input)
    return this.serialize(async () => {
      const local = this.readDocument()
      if (local === null || local.authorityMode !== 'normal') {
        throw fail('Paid media recoverable local authority is unavailable')
      }
      if (isRecoverablePending(local.pendingIntent)) {
        if (!this.recoverableMatchesInput(local.pendingIntent, normalized)) {
          throw fail('Paid media recoverable resume descriptor does not match the pending intent')
        }
        this.requireRecoverableExecutor()
        return await this.executeRecoverablePending(
          local as AuthorityDocument & { pendingIntent: RecoverablePendingIntent },
          normalized
        )
      }
      if (
        local.recoverableCommit !== undefined &&
        this.recoverableMatchesInput(local.recoverableCommit, normalized)
      ) {
        return await this.reconcileUnlocked()
      }
      throw fail('Paid media recoverable pending intent is unavailable')
    })
  }

  async runMutation<T>(
    input: PaidMediaAuthorityMutationInput,
    action: (context: PaidMediaAuthorityMutationContext) => Promise<T>
  ): Promise<T> {
    const normalized = this.validateMutationInput(input)
    if (typeof action !== 'function') throw fail('Paid media authority mutation action is invalid')
    return this.serialize(async () => {
      if (this.stateValue.mode !== 'ready') throw fail('Paid media mutation authority is unavailable')
      await this.proveExactUnlocked()
      const before = this.readDocument()
      if (
        before === null ||
        before.authorityMode !== 'normal' ||
        before.pendingIntent !== null
      ) {
        this.fuse('mutation-precondition-failed', before ?? undefined)
        throw fail('Paid media mutation authority is unavailable')
      }
      const evidenceBefore = await this.readEvidence()
      if (evidenceBefore.digest !== before.compositeDigest) {
        this.fuse('composite-evidence-drift', before)
        throw fail('Paid media composite evidence changed before mutation')
      }
      const transactionId = this.dependencies.uuid()
      const now = this.dependencies.now()
      if (!UUID_PATTERN.test(transactionId) || !counter(now)) {
        throw fail('Paid media mutation identity or clock is invalid')
      }
      const pending = makeDocument({
        installationId: before.installationId,
        epoch: before.epoch,
        desktopIdentity: before.desktopIdentity,
        rootPrincipalDigest: before.rootPrincipalDigest,
        mutationSequence: nextCounter(before.mutationSequence),
        previousStateDigest: before.stateDigest,
        compositeDigest: before.compositeDigest,
        authorityMode: 'normal',
        recoveryFloor: null,
        recoveryStateDigest: null,
        pendingIntent: {
          transactionId: transactionId.toLowerCase(),
          kind: normalized.kind,
          operationId: normalized.operationId ?? null,
          preparedAt: now,
          beforeCompositeDigest: before.compositeDigest
        }
      })
      this.writeDocument(pending)
      this.activeMutation = {
        mode: 'legacy',
        transactionId: transactionId.toLowerCase(),
        before,
        pending
      }

      let result!: T
      let actionError: unknown
      try {
        result = await action({
          transactionId: transactionId.toLowerCase(),
          assertOutboundReady: () => this.assertOutboundForActiveMutation(transactionId)
        })
      } catch (error) {
        actionError = error
      }

      if (this.stateValue.mode !== 'ready') {
        // A failed outbound proof is a security event, not an ordinary
        // business error. Keep the local pending receipt untouched so startup
        // can only converge through the one-step manual-recovery fence.
        this.activeMutation = null
        if (actionError instanceof PaidMediaInstallationRootUnavailableError) {
          throw actionError
        }
        throw fail('Paid media mutation authority failed during its active transaction', actionError)
      }
      if (actionError !== undefined) {
        // An exception may follow a create-only file publication but precede
        // its ledger/index receipt. Never bless that ambiguous partial action
        // as a normal idle composite state.
        this.fuse('mutation-action-failed', pending)
        this.activeMutation = null
        throw actionError
      }

      try {
        const afterEvidence = await this.readEvidence()
        await this.confirmTransition(before, pending)
        const finalDocument = makeDocument({
          installationId: pending.installationId,
          epoch: pending.epoch,
          desktopIdentity: pending.desktopIdentity,
          rootPrincipalDigest: pending.rootPrincipalDigest,
          mutationSequence: nextCounter(pending.mutationSequence),
          previousStateDigest: pending.stateDigest,
          compositeDigest: afterEvidence.digest,
          authorityMode: 'normal',
          recoveryFloor: null,
          recoveryStateDigest: null,
          pendingIntent: null
        })
        this.writeDocument(finalDocument)
        await this.confirmTransition(pending, finalDocument)
        this.publish('ready', 'authority-exact', finalDocument)
      } catch (error) {
        this.fuse('root-commit-unconfirmed', this.readDocument() ?? pending)
        throw error instanceof PaidMediaInstallationRootUnavailableError
          ? error
          : fail('Paid media Root commit could not be confirmed', error)
      } finally {
        this.activeMutation = null
      }
      return result
    })
  }

  private async confirmTransition(
    before: Pick<AuthorityDocument, 'mutationSequence' | 'stateDigest'>,
    after: AuthorityDocument,
    initialSnapshot?: InstallationRootSnapshot
  ): Promise<void> {
    let snapshot = initialSnapshot
    let calls = 0
    for (let inspection = 0; inspection <= MAX_ROOT_CAS_CALLS; inspection += 1) {
      if (!snapshot) {
        try {
          snapshot = (await this.dependencies.client.snapshot()).snapshot
        } catch {
          snapshot = undefined
          continue
        }
      }
      const component = this.validateSnapshot(snapshot, after)
      if (component.recoveryFloor !== null) throw fail('Desktop Root has a recovery fence')
      if (sameProof(component, after)) return
      if (!sameProof(component, before)) {
        throw fail('Desktop Root is neither before nor after the local transition')
      }
      if (calls >= MAX_ROOT_CAS_CALLS) break
      calls += 1
      try {
        const result: InstallationRootMutationEnvelope =
          await this.dependencies.client.advanceDesktop({
            installationId: after.installationId,
            epoch: after.epoch,
            identity: after.desktopIdentity,
            expectedFloor: before.mutationSequence,
            expectedStateDigest: before.stateDigest,
            nextFloor: after.mutationSequence,
            nextStateDigest: after.stateDigest,
            expectedRootRevision: snapshot.rootRevision
          })
        const advanced = this.validateSnapshot(result.snapshot, after)
        if (advanced.recoveryFloor === null && sameProof(advanced, after)) return
      } catch {
        // Resolve a pre/post-commit transport ambiguity with a fresh snapshot.
      }
      snapshot = undefined
    }
    throw fail('Desktop Root CAS did not converge')
  }

  assertMutationContext(transactionId?: string): void {
    const active = this.activeMutation
    const stateMatchesActive =
      (active?.mode === 'legacy' && this.stateValue.mode === 'ready') ||
      (active?.mode === 'recoverable' && this.stateValue.mode === 'recovery_pending')
    if (
      !stateMatchesActive ||
      !active ||
      (transactionId !== undefined && active.transactionId !== transactionId.toLowerCase())
    ) {
      throw fail('Paid media local mutation is outside the Root transaction gate')
    }
  }

  private async assertOutboundForActiveMutation(transactionId: string): Promise<void> {
    const active = this.activeMutation
    this.assertMutationContext(transactionId)
    if (!active || active.mode !== 'legacy') {
      throw fail('Paid media outbound mutation context is unavailable')
    }
    try {
      const snapshot = (await this.dependencies.client.snapshot()).snapshot
      const component = this.validateSnapshot(snapshot, active.before)
      if (component.recoveryFloor !== null || !sameProof(component, active.before)) {
        throw fail('Paid media outbound Root proof is not exact')
      }
    } catch (error) {
      this.fuse('outbound-authority-unavailable', active.pending)
      if (error instanceof PaidMediaInstallationRootUnavailableError) throw error
      throw fail('Paid media outbound authority is unavailable', error)
    }
  }

  assertOutboundReady(): Promise<PaidMediaInstallationRootState> {
    if (this.stateValue.mode === 'recovery_pending') {
      return Promise.reject(fail('Paid media outbound is blocked by local recovery'))
    }
    return this.serialize(() => this.proveExactUnlocked())
  }

  /**
   * Stable paid-media recovery principal derived only from the sealed
   * Installation Root principal. This deliberately does not require a live
   * Root read, so an already-verified local replay remains addressable while
   * the loopback Root service is temporarily restarting.
   */
  localPaidPrincipal(): string {
    const document = this.readDocument()
    if (document === null) throw fail('Paid media local authority is unavailable')
    return paidPrincipal(document.rootPrincipalDigest)
  }

  private async proveExactUnlocked(): Promise<PaidMediaInstallationRootState> {
    let local: AuthorityDocument | null = null
    try {
      if (this.stateValue.mode !== 'ready') throw fail('Paid media outbound authority is unavailable')
      local = this.readDocument()
      if (
        local === null ||
        local.authorityMode !== 'normal' ||
        local.pendingIntent !== null
      ) {
        throw fail('Paid media local authority is not ready')
      }
      const evidence = await this.readEvidence()
      if (evidence.digest !== local.compositeDigest) {
        throw fail('Paid media composite evidence replacement was detected')
      }
    } catch (error) {
      this.fuse('outbound-authority-mismatch', local ?? undefined)
      if (error instanceof PaidMediaInstallationRootUnavailableError) throw error
      throw fail('Paid media outbound authority is unavailable', error)
    }

    let snapshot: InstallationRootSnapshot
    try {
      snapshot = (await this.dependencies.client.snapshot()).snapshot
    } catch (error) {
      // No local write has started. A restarting loopback engine or expired
      // session only makes this attempt unavailable; the last exact proof is
      // retained so a later fresh snapshot can re-establish readiness.
      throw fail('Paid media Installation Root is temporarily unavailable', error)
    }
    try {
      const component = this.validateSnapshot(snapshot, local)
      if (component.recoveryFloor !== null || !sameProof(component, local)) {
        throw fail('Paid media outbound Root proof is not exact')
      }
      return this.publish('ready', 'outbound-proof-fresh', local)
    } catch (error) {
      this.fuse('outbound-authority-mismatch', local)
      if (error instanceof PaidMediaInstallationRootUnavailableError) throw error
      throw fail('Paid media outbound authority is unavailable', error)
    }
  }

  inspectLocalDocumentForTests(): Readonly<AuthorityDocument> | null {
    const document = this.readDocument()
    return document === null ? null : Object.freeze(cloneDocument(document))
  }
}
