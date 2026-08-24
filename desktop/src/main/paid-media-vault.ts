import { createHash, randomBytes } from 'node:crypto'
import {
  closeSync,
  constants as fsConstants,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmdirSync,
  rmSync,
  unlinkSync,
  writeFileSync
} from 'node:fs'
import type { BigIntStats, Dirent, Stats } from 'node:fs'
import {
  open as openFile,
  type FileHandle
} from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { basename, dirname, join, relative, resolve } from 'node:path'
import { Readable } from 'node:stream'

import {
  downloadPublicMedia,
  isPublicMediaAddress,
  MAX_REMOTE_MEDIA_BYTES
} from './media-download'
import type {
  PaidMediaAclHardener,
  PaidMediaPath,
  PaidMediaSafeStorage
} from './paid-media-ledger'
import {
  PAID_MEDIA_ASSET_RESULT_SCHEMA,
  canonicalPaidMediaAssetResult,
  paidMediaAssetTokenHash,
  paidMediaAssetResultDigest,
  paidMediaTokenSetDigest,
  parsePaidMediaAssetResult,
  type PaidMediaAssetDescriptor,
  type PaidMediaAssetResult
} from './paid-media-asset-protocol'

const CLAIM_SCHEMA = 'nachuan.paid-media-vault.claim.v1'
const ASSET_V2_DISPATCH_SCHEMA = 'nachuan.paid-media-vault.asset-v2-dispatch.v1'
const ASSET_ACK_INTENT_SCHEMA = 'nachuan.paid-media-vault.asset-ack-intent.v1'
const ASSET_ACK_COMPLETION_SCHEMA = 'nachuan.paid-media-vault.asset-ack-completion.v1'
const ASSET_CAPACITY_RELEASE_SCHEMA =
  'nachuan.paid-media-vault.asset-capacity-release.v1'
const ARCHIVE_SCHEMA = 'nachuan.paid-media-vault.archive.v1'
const DISCOVERY_SCHEMA = 'nachuan.paid-media-vault.discovery.v1'
const PRESENTATION_SCHEMA = 'nachuan.paid-media-vault.presentation.v1'
const VALIDATION_SIDECAR_SCHEMA = 'nachuan.paid-media-vault.asset-validation.v2'
const TRUSTED_VALIDATION_SCHEMA = 'nachuan.trusted-media-validation.v2'
const TRUSTED_VALIDATOR_VERSION = 'nachuan.trusted-media-probe.v2'
const TRUSTED_VALIDATION_POLICY = 'nachuan.trusted-media-policy.av-closed.v1'
const LEGACY_VALIDATION_SCHEMA = 'nachuan.trusted-media-validation.v1'
const LEGACY_VALIDATOR_VERSION = 'nachuan.trusted-media-probe.v1'
const TASK_INDEX_SCHEMA = 'nachuan.paid-media-vault.video-task-index.v1'
const TERMINAL_SCHEMA = 'nachuan.paid-media-vault.video-terminal.v1'
const CLEANUP_MARKER_SCHEMA = 'nachuan.paid-media-vault.cleanup-pending.v1'
const LEGACY_IMPORT_RECEIPT_SCHEMA = 'nachuan.paid-media-vault.legacy-import-receipt.v1'
const FETCH_STAGING_DIRECTORY_PATTERN = /^nachuan-paid-media-fetch-[A-Za-z0-9]{6}$/
const ENVELOPE_SCHEMA = 'nachuan.paid-media-vault.envelope.v1'
const PROTECTION = 'electron-safe-storage'
const OPERATION_ID_PATTERN = /^desktop-op-[0-9a-f-]{36}$/i
const VIDEO_TASK_ALIAS_PATTERN = /^nvt1_[0-9a-f]{64}$/
const SHA256_PATTERN = /^[0-9a-f]{64}$/
const MAX_REQUEST_BYTES = 24 * 1024 * 1024
// Four admitted image outputs can each decode to 24 MiB. Base64 expansion and
// a small JSON envelope require a bounded ceiling above the old 24 MiB ledger
// limit. Raw provider JSON is hashed, then reduced to a tiny recovery manifest;
// it is never nested inside another base64/encryption envelope.
export const MAX_PAID_MEDIA_ARCHIVE_RESPONSE_BYTES = 128 * 1024 * 1024
const MAX_RECOVERY_JSON_BYTES = 1024 * 1024
export const MAX_PAID_MEDIA_ARCHIVE_ASSET_BYTES = 24 * 1024 * 1024
export const PAID_MEDIA_STAGE_STREAM_CHUNK_BYTES = 64 * 1024
export const MAX_PAID_MEDIA_TERMINAL_VIDEO_BYTES = MAX_REMOTE_MEDIA_BYTES
const MAX_POLL_RESPONSE_BYTES_FOR_VAULT = 24 * 1024 * 1024
const MAX_ENCRYPTED_DOCUMENT_BYTES = 72 * 1024 * 1024
const MAX_URL_LENGTH = 4096
const MAX_VIDEO_TASK_ID_BYTES = 512
const MAX_MODEL_ID_BYTES = 512
const MAX_MEDIA_DIMENSION = 16_384
const MAX_MEDIA_PIXELS = 64 * 1024 * 1024
const DEFAULT_ARCHIVE_DISCOVERY_PAGE = 50
const MAX_ARCHIVE_DISCOVERY_PAGE = 100
const DEFAULT_VALIDATION_MIGRATION_PAGE = 16
const MAX_VALIDATION_MIGRATION_PAGE = 32
const MAX_VALIDATION_MIGRATION_PLANS = MAX_VALIDATION_MIGRATION_PAGE * 4
const LOCAL_HOSTNAME = /(?:^|\.)(?:localhost|local|internal|home|lan)$/i
const AUTHORITY_EVIDENCE_DOMAIN = Buffer.from(
  'nachuan.desktop.paid-media-vault-evidence.v1\0',
  'ascii'
)
const AUTHORITY_INDEX_STATE_DOMAIN = Buffer.from(
  'nachuan.desktop.paid-media-vault-index-state.v1\0',
  'ascii'
)
const AUTHORITY_INDEX_SCHEMA = 'nachuan.paid-media-vault-authority-index.v1'
const AUTHORITY_EVENT_SCHEMA = 'nachuan.paid-media-vault-authority-event.v1'
const AUTHORITY_STAGE_EVENT_SCHEMA = 'nachuan.paid-media-vault-authority-event.v2'
const STAGE_LEASE_EVENT_SCHEMA = 'nachuan.paid-media-stage-lease-event.v2'
const STAGE_LEASE_STATE_DOMAIN = Buffer.from(
  'nachuan.desktop.paid-media-stage-lease-state.v2\0',
  'ascii'
)
const STAGE_LEASE_ID_DOMAIN = Buffer.from(
  'nachuan.desktop.paid-media-stage-lease-id.v2\0',
  'ascii'
)
const ZERO_SHA256 = '0'.repeat(64)
const STAGE_DIRECTORY_PREFIX = 'nachuan-paid-media-stage-'
const STAGE_DIRECTORY_PATTERN = /^nachuan-paid-media-stage-([0-9a-f]{64})$/
const STAGE_FILE_NAME = 'asset.bin' as const
const MAX_STAGE_LEASES = 250_000
const MAX_ACTIVE_STAGE_LEASES = 16_384
const LEGACY_IMPORT_RECEIPT_DOMAIN = Buffer.from(
  'nachuan.desktop.paid-media-legacy-import-receipt.v1\0',
  'ascii'
)
const ASSET_V2_DISPATCH_RECEIPT_DOMAIN = Buffer.from(
  'nachuan.desktop.paid-media-asset-v2-dispatch.v1\0',
  'ascii'
)
const ASSET_ACK_INTENT_RECEIPT_DOMAIN = Buffer.from(
  'nachuan.desktop.paid-media-asset-ack-intent.v1\0',
  'ascii'
)
const ASSET_ACK_COMPLETION_SEMANTIC_DOMAIN = Buffer.from(
  'nachuan.desktop.paid-media-asset-ack-completion-semantic.v1\0',
  'ascii'
)
const ASSET_ACK_COMPLETION_RECEIPT_DOMAIN = Buffer.from(
  'nachuan.desktop.paid-media-asset-ack-completion.v1\0',
  'ascii'
)
const ASSET_CAPACITY_RELEASE_RECEIPT_DOMAIN = Buffer.from(
  'nachuan.desktop.paid-media-asset-capacity-release.v1\0',
  'ascii'
)
const MAX_AUTHORITY_EVIDENCE_ENTRIES = 250_000
const MAX_AUTHORITY_HEAD_BYTES = 256 * 1024
const MAX_AUTHORITY_EVENT_BYTES = 256 * 1024
const MAX_AUTHORITY_JOURNAL_BYTES = 512 * 1024 * 1024

export type PaidMediaRemoteFetchResult =
  | {
      bytes: Buffer
      contentType?: string
      finalUrl: string
    }
  | {
      filePath: string
      byteLength: number
      contentType?: string
      finalUrl: string
    }

export type PaidMediaRemoteFetcher = (
  url: string,
  maxBytes: number
) => Promise<PaidMediaRemoteFetchResult>

export interface PaidMediaVaultAuthorityEvidence {
  vaultStateDigest: string
  entryCount: number
}

export interface PaidMediaVaultCaptureInventoryEntry {
  path: string
  byteLength: number
  sha256: string
}

export interface PaidMediaVaultCaptureInventory {
  vaultStateDigest: string
  entryCount: number
  entries: readonly Readonly<PaidMediaVaultCaptureInventoryEntry>[]
  quiescence: Readonly<{
    activeStageLeases: 0
    stageOpenHandles: 0
    activeStageStream: null
    cleanupRetries: 0
    cleanupFlights: 0
    terminalArchiveFlights: 0
    cleanupPendingEntries: 0
    stageRootEntries: 0
  }>
}

export interface PaidMediaVaultCommittedPrefixRecoveryEvidence {
  /** Recovery diagnostics only. This is never outbound/startup readiness proof. */
  recoveryOnly: true
  outboundReady: false
  committedVaultStateDigest: string
  committedSequence: number
  committedJournalByteLength: number
  physicalJournalByteLength: number
  uncommittedTailByteLength: number
  /** `null` means the tail is not exactly one valid, chained, replayable event. */
  uncommittedTailEventCount: 0 | 1 | null
  entryCount: number
  totalBytes: number
}

export type PaidMediaVaultAuthorityTailRecoveryBoundary =
  | {
      kind: 'file_event'
      action: 'create' | 'delete'
      relativePath: string
      byteLength: number
      sha256: string
    }
  | {
      kind: 'stage_transition'
      leaseId: string
      leaseSequence: number
      state: PaidMediaStageLeaseState
      leaseStateDigest: string
    }

export interface PaidMediaVaultAuthorityTailRecoveryInput {
  operationId: string
  committedVaultStateDigest: string
  boundary: PaidMediaVaultAuthorityTailRecoveryBoundary
}

export interface PaidMediaVaultAuthorityTailRecoveryResult {
  operationId: string
  action: 'create' | 'delete' | 'stage_transition'
  recovered: true
  previousVaultStateDigest: string
  vaultStateDigest: string
  sequence: number
  eventStateDigest: string
}

export interface PaidMediaV2DispatchMarker {
  schema: typeof ASSET_V2_DISPATCH_SCHEMA
  operationId: string
  path: PaidMediaPath
  requestSha256: string
  recoveryDomainSha256: string
  paidPrincipalSha256: string
  turnId: string | null
  assetResultSha256: string | null
  receiptSha256: string
}

export interface PaidMediaAssetAckIntent {
  schema: typeof ASSET_ACK_INTENT_SCHEMA
  operationId: string
  turnId: string
  tokenSetDigest: string
  archiveReceiptSha256: string
  assetResultSha256: string
  dispatchReceiptSha256: string
  receiptSha256: string
}

export interface PaidMediaAssetAckCompletion {
  schema: typeof ASSET_ACK_COMPLETION_SCHEMA
  operationId: string
  intentReceiptSha256: string
  status: 200
  turnId: string
  ok: true
  cleanupComplete: true
  semanticResponseSha256: string
  receiptSha256: string
}

export interface PaidMediaAssetCapacityReleaseAuthorization {
  schema: typeof ASSET_CAPACITY_RELEASE_SCHEMA
  operationId: string
  archiveReceiptSha256: string
  dispatchReceiptSha256: string
  ackCompletionReceiptSha256: string
  cleanupComplete: true
  receiptSha256: string
}

export type PaidMediaStageLeaseState =
  | 'reserved'
  | 'opened'
  | 'aborted_cleanup_pending'
  | 'aborted_cleaned'
  | 'archived_cleanup_pending'
  | 'archived_cleaned'
  | 'held'

export interface PaidMediaStageWriteCapability {
  readonly leaseId: string
  readonly operationId: string
  readonly turnId: string
  readonly ordinal: number
  readonly descriptor: PaidMediaAssetDescriptor
  write(bytes: Uint8Array, position: number): Promise<{ bytesWritten: number }>
  sync(): Promise<void>
}

export interface PaidMediaSealedStageCapability {
  readonly leaseId: string
  readonly operationId: string
  readonly turnId: string
  readonly ordinal: number
  readonly descriptor: PaidMediaAssetDescriptor
}

export interface PaidMediaSealedStageReadSource {
  readonly byteLength: number
  readonly sha256: string
  readonly createReadStream: () => Readable
}

export interface PaidMediaSealedStageArchiveAsset {
  readonly ordinal: number
  readonly sealed: PaidMediaSealedStageCapability
  readonly validation: PaidMediaValidationReceipt
}

export type PaidMediaStageOpenResult =
  | Readonly<{
      ok: true
      capabilities: readonly PaidMediaStageWriteCapability[]
    }>
  | Readonly<{
      ok: false
      cleanupPending: boolean
      held: boolean
    }>

export type PaidMediaStageReclaimResult =
  | Readonly<{ ok: true; capability: PaidMediaStageWriteCapability }>
  | Readonly<{ ok: false; status: 'cleaned' | 'pending' | 'held' }>

export interface PaidMediaStageRecoveryLease {
  leaseId: string
  operationId: string
  turnId: string
  ordinal: number
  generation: number
  resultSha256: string
  leaseStateDigest: string
  state: PaidMediaStageLeaseState
  disposition: 'cleanup' | 'reclaim' | 'manual_only'
  reasonCode: string | null
}

export interface PaidMediaStageRecoveryInspection {
  leases: readonly PaidMediaStageRecoveryLease[]
  requiresRootMutation: true
  ageBasedDecision: false
}

export interface PaidMediaValidationReceipt {
  schema: 'nachuan.trusted-media-validation.v2'
  validatorVersion: 'nachuan.trusted-media-probe.v2'
  validationPolicy: 'nachuan.trusted-media-policy.av-closed.v1'
  fullyDecoded: true
  mediaType: PaidMediaArchivedAsset['mediaType']
  byteLength: number
  sha256: string
  attestedTools: {
    ffmpegSha256: string
    ffprobeSha256: string
  }
  metadata: {
    detectedKind: 'image' | 'video'
    codecName: string
    audioCodecName: string | null
    videoStreamCount: 1
    audioStreamCount: 0 | 1
    formatName: string
    width: number
    height: number
    durationMs: number | null
    decodedFrames: number
  }
  receiptSha256: string
}

interface PaidMediaLegacyValidationReceipt {
  schema: 'nachuan.trusted-media-validation.v1'
  validatorVersion: 'nachuan.trusted-media-probe.v1'
  fullyDecoded: true
  mediaType: PaidMediaArchivedAsset['mediaType']
  byteLength: number
  sha256: string
  attestedTools: {
    ffmpegSha256: string
    ffprobeSha256: string
  }
  metadata: {
    detectedKind: 'image' | 'video'
    codecName: string
    formatName: string
    width: number
    height: number
    durationMs: number | null
    decodedFrames: number
  }
  receiptSha256: string
}

type PaidMediaStoredValidationReceipt =
  | PaidMediaValidationReceipt
  | PaidMediaLegacyValidationReceipt

export type PaidMediaTrustedProbeResult = PaidMediaValidationReceipt

export interface PaidMediaVaultDependencies {
  safeStorage: PaidMediaSafeStorage
  harden: PaidMediaAclHardener
  now: () => number
  fetchRemote: PaidMediaRemoteFetcher
  ensureMediaProbeReady: () => Promise<void>
  validateMediaAsset: (input: {
    createReadStream: () => Readable
    mediaType: PaidMediaArchivedAsset['mediaType']
    byteLength: number
    sha256: string
  }) => Promise<PaidMediaTrustedProbeResult>
  onCleanupError?: (error: unknown) => void
  cleanupIO?: {
    unlinkStagedFile: (path: string) => void
    removeEmptyStagingDirectory: (path: string) => void
    unlinkMarker: (path: string) => void
  }
  beforeAssetPin?: (path: string) => void
  beforeAuthorityHeadCommit?: () => void
  onValidationMigrationDirectoryEnumeration?: (path: string) => void
  stageRoot?: () => string
  beforeStageFileCreate?: (input: {
    leaseId: string
    operationId: string
    ordinal: number
  }) => void | Promise<void>
  beforeStageOpenedCommit?: (input: {
    leaseId: string
    operationId: string
    ordinal: number
  }) => void | Promise<void>
  beforeArchivedStageCleanupIntent?: (input: { operationId: string }) => void | Promise<void>
  stageCleanupIO?: {
    unlinkStageFile: (path: string) => void
    removeEmptyStageDirectory: (path: string) => void
  }
  onAuthorityJournalReplay?: () => void
  onStageHandleUse?: (input: {
    phase: 'opened' | 'write' | 'sync' | 'seal' | 'read'
    witness: object
  }) => void
  onStageStreamChunk?: (input: {
    phase: 'probe' | 'archive'
    leaseId: string
    ordinal: number
    byteLength: number
  }) => void
  onStageArchiveAsset?: (input: {
    phase: 'start' | 'finish'
    leaseId: string
    ordinal: number
  }) => void
  afterStageAssetPublished?: (input: {
    leaseId: string
    ordinal: number
    path: string
    newlyPublished: boolean
  }) => void | Promise<void>
  afterStageAssetLinkedBeforeAuthority?: (input: {
    leaseId: string
    ordinal: number
    path: string
  }) => void | Promise<void>
}

export interface PaidMediaExactRequest {
  operationId: string
  path: PaidMediaPath
  requestSha256: string
  encodedBody: string
}

export interface PaidMediaArchivedAsset {
  sha256: string
  byteLength: number
  mediaType:
    | 'image/png'
    | 'image/jpeg'
    | 'image/gif'
    | 'image/webp'
    | 'video/mp4'
    | 'video/webm'
  extension: 'png' | 'jpg' | 'gif' | 'webp' | 'mp4' | 'webm'
  source: 'inline' | 'remote'
  sourceSha256: string
  reference: string
  /** Missing only on a legacy receipt; explicit startup migration writes trusted-v2 evidence. */
  validation?: PaidMediaStoredValidationReceipt
}

export interface PaidMediaVideoTaskBinding {
  operationId: string
  taskAliasSha256: string
  creationReceiptSha256: string
  createdAt: number
}

export interface PaidMediaArchiveReceipt {
  schema: 'nachuan.paid-media-vault.receipt.v1'
  operationId: string
  path: PaidMediaPath
  requestSha256: string
  responseSha256: string
  responseByteLength: number
  recoverySha256: string
  receiptSha256: string
  status: number
  kind: 'image' | 'video_task'
  taskReceiptIdSha256?: string
  assets: PaidMediaArchivedAsset[]
  archivedAt: number
}

export interface PaidMediaArchivedResult {
  receipt: PaidMediaArchiveReceipt
  recoveryJson: string
  result: Record<string, unknown>
  cleanupComplete: boolean
}

export interface PaidMediaValidationMigrationPlan {
  source: {
    kind: 'archive' | 'terminal'
    name: string
    receiptSha256: string
  }
  asset: Pick<PaidMediaArchivedAsset, 'reference' | 'mediaType' | 'byteLength' | 'sha256'>
  validation: PaidMediaValidationReceipt
  planSha256: string
}

export interface PaidMediaValidationMigrationBatch {
  items: PaidMediaValidationMigrationPlan[]
  nextCursor?: string
}

export interface PaidMediaTerminalArchiveResult {
  operationId: string
  receiptSha256: string
  asset?: PaidMediaArchivedAsset
  result: Record<string, unknown>
  cleanupComplete: boolean
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
  assets: Array<
    Pick<PaidMediaArchivedAsset, 'reference' | 'mediaType' | 'byteLength' | 'sha256'>
  >
  presentation?: PaidMediaArchivePresentationState
}

export type PaidMediaArchivePresentationState =
  | 'attention'
  | 'delivered'
  | 'restored'
  | 'hidden'

export interface PaidMediaArchiveDiscoveryPage {
  items: PaidMediaArchiveDiscovery[]
  nextCursor?: string
}

interface ClaimBase {
  schema: typeof CLAIM_SCHEMA
  operationId: string
  path: PaidMediaPath
  requestSha256: string
  requestUtf8Base64: string
  createdAt: number
}

interface AssetV2DispatchBase {
  assetResultSha256: string | null
  operationId: string
  paidPrincipalSha256: string
  path: PaidMediaPath
  recoveryDomainSha256: string
  requestSha256: string
  schema: typeof ASSET_V2_DISPATCH_SCHEMA
  turnId: string | null
}

interface AssetV2DispatchDocument extends AssetV2DispatchBase {
  receiptSha256: string
}

interface AssetAckIntentBase {
  archiveReceiptSha256: string
  assetResultSha256: string
  dispatchReceiptSha256: string
  operationId: string
  schema: typeof ASSET_ACK_INTENT_SCHEMA
  tokens: string[]
  tokenSetDigest: string
  turnId: string
}

interface AssetAckIntentDocument extends AssetAckIntentBase {
  receiptSha256: string
}

interface AssetAckCompletionBase {
  cleanupComplete: true
  intentReceiptSha256: string
  ok: true
  operationId: string
  schema: typeof ASSET_ACK_COMPLETION_SCHEMA
  semanticResponseSha256: string
  status: 200
  turnId: string
}

interface AssetAckCompletionDocument extends AssetAckCompletionBase {
  receiptSha256: string
}

interface AssetCapacityReleaseBase {
  ackCompletionReceiptSha256: string
  archiveReceiptSha256: string
  cleanupComplete: true
  dispatchReceiptSha256: string
  operationId: string
  schema: typeof ASSET_CAPACITY_RELEASE_SCHEMA
}

interface AssetCapacityReleaseDocument extends AssetCapacityReleaseBase {
  receiptSha256: string
}

interface HardenedPathIdentity {
  directory: boolean
  dev: number
  ino: number
  birthtimeMs: number
}

interface VerifiedAssetIdentity extends HardenedPathIdentity {
  size: number
  mtimeMs: number
  ctimeMs: number
}

export interface PaidMediaOpenAsset {
  handle: FileHandle
  byteLength: number
  mediaType: PaidMediaArchivedAsset['mediaType']
  sha256: string
}

interface ClaimDocument extends ClaimBase {
  claimSha256: string
}

interface ArchiveBase {
  schema: typeof ARCHIVE_SCHEMA
  operationId: string
  path: PaidMediaPath
  requestSha256: string
  responseSha256: string
  responseByteLength: number
  recoverySha256: string
  recoveryJsonUtf8Base64: string
  status: number
  kind: 'image' | 'video_task'
  taskReceiptIdSha256: string | null
  assets: PaidMediaArchivedAsset[]
  archivedAt: number
}

interface ArchiveDocument extends ArchiveBase {
  receiptSha256: string
}

interface DiscoveryBase extends PaidMediaArchiveDiscovery {
  schema: typeof DISCOVERY_SCHEMA
}

interface DiscoveryDocument extends DiscoveryBase {
  discoverySha256: string
}

interface PresentationBase {
  schema: typeof PRESENTATION_SCHEMA
  operationId: string
  archiveReceiptSha256: string
  state: PaidMediaArchivePresentationState
  updatedAt: number
}

interface PresentationDocument extends PresentationBase {
  presentationSha256: string
}

interface ValidationSidecarBase {
  schema: typeof VALIDATION_SIDECAR_SCHEMA
  assetSha256: string
  validation: PaidMediaValidationReceipt
}

interface ValidationSidecarDocument extends ValidationSidecarBase {
  sidecarSha256: string
}

interface VideoTaskIndexBase {
  schema: typeof TASK_INDEX_SCHEMA
  taskAliasSha256: string
  operationId: string
  creationReceiptSha256: string
  createdAt: number
}

interface VideoTaskIndexDocument extends VideoTaskIndexBase {
  indexSha256: string
}

interface TerminalBase {
  schema: typeof TERMINAL_SCHEMA
  taskAliasSha256: string
  operationId: string
  creationReceiptSha256: string
  providerResultSha256: string
  providerResultByteLength: number
  recoverySha256: string
  recoveryJsonUtf8Base64: string
  asset: PaidMediaArchivedAsset | null
  archivedAt: number
}

interface TerminalDocument extends TerminalBase {
  receiptSha256: string
}

interface CleanupStableIdentity {
  pathSha256: string
  dev: number
  ino: number
  birthtimeMs: number
}

interface CleanupStagingIdentity extends CleanupStableIdentity {
  mtimeMs: number
  ctimeMs: number
  size: number
}

interface CleanupMarkerBase {
  schema: typeof CLEANUP_MARKER_SCHEMA
  operationId: string
  cleanupId: string
  tempRoot: CleanupStableIdentity
  directoryName: string
  directory: CleanupStagingIdentity
  fileName: 'asset.bin'
  file: CleanupStagingIdentity
  createdAt: number
}

interface CleanupMarkerDocument extends CleanupMarkerBase {
  markerSha256: string
}

interface LegacyImportReceiptBase {
  schema: typeof LEGACY_IMPORT_RECEIPT_SCHEMA
  decisionSha256: string
  operationId: string
}

interface LegacyImportReceipt extends LegacyImportReceiptBase {
  receiptSha256: string
}

interface VaultAuthorityEntry {
  path: string
  byteLength: number
  sha256: string
}

interface StageStableIdentity {
  pathSha256: string
  dev: string
  ino: string
  birthtimeNs: string
}

interface StageFullIdentity extends StageStableIdentity {
  mtimeNs: string
  ctimeNs: string
  size: string
}

interface StageLeaseEventBase {
  schema: typeof STAGE_LEASE_EVENT_SCHEMA
  leaseId: string
  leaseSequence: number
  previousLeaseStateDigest: string
  state: PaidMediaStageLeaseState
  operationId: string
  turnId: string
  resultSha256: string
  ordinal: number
  descriptor: PaidMediaAssetDescriptor
  descriptorSha256: string
  generation: number
  tempRoot: StageStableIdentity
  directoryName: string
  fileName: typeof STAGE_FILE_NAME
  directory: StageFullIdentity | null
  file: StageFullIdentity | null
  reasonCode: string | null
  createdAt: number
  updatedAt: number
}

interface StageLeaseEvent extends StageLeaseEventBase {
  leaseStateDigest: string
}

interface VaultAuthorityFileEventBase {
  schema: typeof AUTHORITY_EVENT_SCHEMA
  vaultIdentity: string
  sequence: number
  previousStateDigest: string
  action: 'create' | 'delete'
  entry: VaultAuthorityEntry
}

interface VaultAuthorityFileEvent extends VaultAuthorityFileEventBase {
  stateDigest: string
}

interface VaultAuthorityStageEventBase {
  schema: typeof AUTHORITY_STAGE_EVENT_SCHEMA
  vaultIdentity: string
  sequence: number
  previousStateDigest: string
  action: 'stage_transition'
  stage: StageLeaseEvent
}

interface VaultAuthorityStageEvent extends VaultAuthorityStageEventBase {
  stateDigest: string
}

type VaultAuthorityEventBase = VaultAuthorityFileEventBase | VaultAuthorityStageEventBase
type VaultAuthorityEvent = VaultAuthorityFileEvent | VaultAuthorityStageEvent

interface VaultAuthorityHead {
  schema: typeof AUTHORITY_INDEX_SCHEMA
  vaultIdentity: string
  sequence: number
  stateDigest: string
  journalByteLength: number
  entryCount: number
  totalBytes: number
}

interface VaultAuthorityIndexCache {
  head: VaultAuthorityHead
  entries: Map<string, VaultAuthorityEntry>
  stageLeases: Map<string, StageLeaseEvent>
  activeStageLeases: Map<string, StageLeaseEvent>
  stageBindingIndex: Map<string, string>
  stageLeafIndex: Map<string, string>
  stageOperationIndex: Map<string, Set<string>>
  journalIdentity: HardenedPathIdentity
  journalMtimeMs: number
  journalCtimeMs: number
  journalSize: number
}

type VaultAuthorityMutableIndexes = Pick<
  VaultAuthorityIndexCache,
  | 'entries'
  | 'stageLeases'
  | 'activeStageLeases'
  | 'stageBindingIndex'
  | 'stageLeafIndex'
  | 'stageOperationIndex'
>

interface StageOpenHandleRecord {
  leaseId: string
  operationId: string
  turnId: string
  ordinal: number
  generation: number
  descriptor: PaidMediaAssetDescriptor
  handle: FileHandle
  filePath: string
  directoryPath: string
  tempRootPath: string
  tempRootIdentity: StageStableIdentity
  directoryIdentity: StageFullIdentity
  fileIdentity: StageFullIdentity
  offset: number
  digest: ReturnType<typeof createHash>
  state: 'open' | 'sealed' | 'revoked'
  witness: object
}

interface StageOpeningContext {
  leaseId: string
  tempRootPath: string
  directoryPath: string
  filePath: string
  handle: FileHandle | null
  directoryIdentity: StageFullIdentity | null
  fileIdentity: StageFullIdentity | null
}

type StageLeafInspection =
  | { kind: 'absent' }
  | {
      kind: 'exact'
      directory: StageFullIdentity
      file: StageFullIdentity | null
    }
  | { kind: 'mismatch'; reasonCode: string }

interface ValidationMigrationSource {
  key: string
  kind: 'archive' | 'terminal'
  name: string
  path: string
  dev: number
  ino: number
  birthtimeMs: number
  mtimeMs: number
  ctimeMs: number
  size: number
}

interface ValidationMigrationSourceSnapshot {
  digest: string
  sources: ValidationMigrationSource[]
}

export class PaidMediaVaultError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options)
    this.name = 'PaidMediaVaultError'
  }
}

class PaidMediaCleanupHoldError extends PaidMediaVaultError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options)
    this.name = 'PaidMediaCleanupHoldError'
  }
}

function sha256(value: string | Buffer): string {
  return createHash('sha256').update(value).digest('hex')
}

function requireNonzeroSha256(value: unknown, label: string): string {
  if (
    typeof value !== 'string' ||
    !SHA256_PATTERN.test(value) ||
    value === ZERO_SHA256
  ) {
    throw new PaidMediaVaultError(`${label} is invalid`)
  }
  return value
}

function recoverySidecarDigest(domain: Buffer, value: unknown): string {
  const digest = createHash('sha256')
    .update(domain)
    .update(JSON.stringify(value), 'ascii')
    .digest('hex')
  if (digest === ZERO_SHA256) {
    throw new PaidMediaVaultError('Paid media recovery sidecar digest is invalid')
  }
  return digest
}

function canonicalAssetAckTokens(value: unknown): {
  tokens: string[]
  tokenSetDigest: string
} {
  if (!Array.isArray(value)) {
    throw new PaidMediaVaultError('Paid media asset ACK token set is invalid')
  }
  try {
    const tokenSetDigest = paidMediaTokenSetDigest(value)
    const tokens = (value as string[]).slice().sort()
    return { tokens, tokenSetDigest }
  } catch (error) {
    throw new PaidMediaVaultError('Paid media asset ACK token set is invalid', {
      cause: error
    })
  }
}

function publicV2DispatchMarker(
  document: AssetV2DispatchDocument
): PaidMediaV2DispatchMarker {
  return Object.freeze({
    schema: ASSET_V2_DISPATCH_SCHEMA,
    operationId: document.operationId,
    path: document.path,
    requestSha256: document.requestSha256,
    recoveryDomainSha256: document.recoveryDomainSha256,
    paidPrincipalSha256: document.paidPrincipalSha256,
    turnId: document.turnId,
    assetResultSha256: document.assetResultSha256,
    receiptSha256: document.receiptSha256
  })
}

function publicAssetAckIntent(document: AssetAckIntentDocument): PaidMediaAssetAckIntent {
  return Object.freeze({
    schema: ASSET_ACK_INTENT_SCHEMA,
    operationId: document.operationId,
    turnId: document.turnId,
    tokenSetDigest: document.tokenSetDigest,
    archiveReceiptSha256: document.archiveReceiptSha256,
    assetResultSha256: document.assetResultSha256,
    dispatchReceiptSha256: document.dispatchReceiptSha256,
    receiptSha256: document.receiptSha256
  })
}

function publicAssetAckCompletion(
  document: AssetAckCompletionDocument
): PaidMediaAssetAckCompletion {
  return Object.freeze({
    schema: ASSET_ACK_COMPLETION_SCHEMA,
    operationId: document.operationId,
    intentReceiptSha256: document.intentReceiptSha256,
    status: 200,
    turnId: document.turnId,
    ok: true,
    cleanupComplete: true,
    semanticResponseSha256: document.semanticResponseSha256,
    receiptSha256: document.receiptSha256
  })
}

function publicAssetCapacityRelease(
  document: AssetCapacityReleaseDocument
): PaidMediaAssetCapacityReleaseAuthorization {
  return Object.freeze({
    schema: ASSET_CAPACITY_RELEASE_SCHEMA,
    operationId: document.operationId,
    archiveReceiptSha256: document.archiveReceiptSha256,
    dispatchReceiptSha256: document.dispatchReceiptSha256,
    ackCompletionReceiptSha256: document.ackCompletionReceiptSha256,
    cleanupComplete: true,
    receiptSha256: document.receiptSha256
  })
}

function normalizedAbsolutePath(path: string): string {
  const absolute = resolve(path)
  return process.platform === 'win32' ? absolute.toLowerCase() : absolute
}

function canonicalPrivateTempRoot(): string {
  const configured = resolve(tmpdir())
  const info = lstatSync(configured)
  if (!info.isDirectory() || info.isSymbolicLink()) {
    throw new PaidMediaVaultError('Paid media private temp root is redirected')
  }
  const canonical = resolve(realpathSync(configured))
  if (normalizedAbsolutePath(canonical) !== normalizedAbsolutePath(configured)) {
    throw new PaidMediaVaultError('Paid media private temp root is not canonical')
  }
  return canonical
}

function validationReceiptDigest(
  value:
    | Omit<PaidMediaValidationReceipt, 'receiptSha256'>
    | Omit<PaidMediaLegacyValidationReceipt, 'receiptSha256'>
): string {
  // Match gateway/trusted_media_http.py json.dumps(sort_keys=True,
  // separators=(",", ":"), ensure_ascii=True). All admitted strings are
  // ASCII, and insertion order below is recursively lexicographic.
  const canonicalMetadata =
    value.schema === TRUSTED_VALIDATION_SCHEMA
      ? {
          audioCodecName: value.metadata.audioCodecName,
          audioStreamCount: value.metadata.audioStreamCount,
          codecName: value.metadata.codecName,
          decodedFrames: value.metadata.decodedFrames,
          detectedKind: value.metadata.detectedKind,
          durationMs: value.metadata.durationMs,
          formatName: value.metadata.formatName,
          height: value.metadata.height,
          videoStreamCount: value.metadata.videoStreamCount,
          width: value.metadata.width
        }
      : {
          codecName: value.metadata.codecName,
          decodedFrames: value.metadata.decodedFrames,
          detectedKind: value.metadata.detectedKind,
          durationMs: value.metadata.durationMs,
          formatName: value.metadata.formatName,
          height: value.metadata.height,
          width: value.metadata.width
        }
  const canonical = {
    attestedTools: {
      ffmpegSha256: value.attestedTools.ffmpegSha256,
      ffprobeSha256: value.attestedTools.ffprobeSha256
    },
    byteLength: value.byteLength,
    fullyDecoded: value.fullyDecoded,
    mediaType: value.mediaType,
    metadata: canonicalMetadata,
    schema: value.schema,
    sha256: value.sha256,
    ...(value.schema === TRUSTED_VALIDATION_SCHEMA
      ? { validationPolicy: value.validationPolicy }
      : {}),
    validatorVersion: value.validatorVersion
  }
  return createHash('sha256')
    .update(`${value.schema}\0`, 'utf8')
    .update(JSON.stringify(canonical), 'ascii')
    .digest('hex')
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort()
  const wanted = [...expected].sort()
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index])
}

interface ArchiveCursor {
  schema: 'nachuan.paid-media-vault.cursor.v1'
  archivedAt: number
  operationId: string
}

function encodeArchiveCursor(value: ArchiveCursor): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url')
}

function decodeArchiveCursor(raw: unknown): ArchiveCursor | null {
  if (raw === undefined) return null
  if (typeof raw !== 'string' || raw.length < 8 || raw.length > 256 || !/^[A-Za-z0-9_-]+$/.test(raw)) {
    throw new PaidMediaVaultError('Paid media archive discovery cursor is invalid')
  }
  let value: Record<string, unknown>
  try {
    const bytes = Buffer.from(raw, 'base64url')
    if (bytes.toString('base64url') !== raw) throw new Error('non-canonical cursor')
    value = parseObject(bytes.toString('utf8'), 'Paid media archive discovery cursor')
  } catch (error) {
    if (error instanceof PaidMediaVaultError) throw error
    throw new PaidMediaVaultError('Paid media archive discovery cursor is invalid', {
      cause: error
    })
  }
  if (
    !exactKeys(value, ['schema', 'archivedAt', 'operationId']) ||
    value.schema !== 'nachuan.paid-media-vault.cursor.v1' ||
    !Number.isSafeInteger(value.archivedAt) ||
    Number(value.archivedAt) < 0 ||
    typeof value.operationId !== 'string' ||
    !OPERATION_ID_PATTERN.test(value.operationId)
  ) {
    throw new PaidMediaVaultError('Paid media archive discovery cursor is invalid')
  }
  return value as unknown as ArchiveCursor
}

function validPath(value: unknown): value is PaidMediaPath {
  return value === '/v1/images/generations' || value === '/v1/videos/generations'
}

function parseStoredValidationReceipt(
  value: unknown,
  expected: Pick<PaidMediaArchivedAsset, 'mediaType' | 'byteLength' | 'sha256'>
): PaidMediaStoredValidationReceipt | undefined {
  if (value === undefined) return undefined
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new PaidMediaVaultError('Paid media trusted validation receipt is invalid')
  }
  const raw = value as Record<string, unknown>
  const tools = raw.attestedTools
  const metadata = raw.metadata
  const trustedV2 =
    raw.schema === TRUSTED_VALIDATION_SCHEMA &&
    raw.validatorVersion === TRUSTED_VALIDATOR_VERSION &&
    raw.validationPolicy === TRUSTED_VALIDATION_POLICY
  const legacyV1 =
    raw.schema === LEGACY_VALIDATION_SCHEMA &&
    raw.validatorVersion === LEGACY_VALIDATOR_VERSION
  if (
    (!trustedV2 && !legacyV1) ||
    !exactKeys(
      raw,
      trustedV2
        ? [
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
          ]
        : [
            'schema',
            'validatorVersion',
            'fullyDecoded',
            'mediaType',
            'byteLength',
            'sha256',
            'attestedTools',
            'metadata',
            'receiptSha256'
          ]
    ) ||
    raw.fullyDecoded !== true ||
    raw.mediaType !== expected.mediaType ||
    raw.byteLength !== expected.byteLength ||
    raw.sha256 !== expected.sha256 ||
    !tools ||
    typeof tools !== 'object' ||
    Array.isArray(tools) ||
    !exactKeys(tools as Record<string, unknown>, ['ffmpegSha256', 'ffprobeSha256']) ||
    typeof (tools as Record<string, unknown>).ffmpegSha256 !== 'string' ||
    !SHA256_PATTERN.test((tools as Record<string, unknown>).ffmpegSha256 as string) ||
    typeof (tools as Record<string, unknown>).ffprobeSha256 !== 'string' ||
    !SHA256_PATTERN.test((tools as Record<string, unknown>).ffprobeSha256 as string) ||
    !metadata ||
    typeof metadata !== 'object' ||
    Array.isArray(metadata) ||
    !exactKeys(
      metadata as Record<string, unknown>,
      trustedV2
        ? [
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
          ]
        : [
            'detectedKind',
            'codecName',
            'formatName',
            'width',
            'height',
            'durationMs',
            'decodedFrames'
          ]
    ) ||
    typeof raw.receiptSha256 !== 'string' ||
    !SHA256_PATTERN.test(raw.receiptSha256)
  ) {
    throw new PaidMediaVaultError('Paid media trusted validation receipt is invalid')
  }
  const detail = metadata as Record<string, unknown>
  if (
    detail.detectedKind !== (expected.mediaType.startsWith('image/') ? 'image' : 'video') ||
    typeof detail.codecName !== 'string' ||
    detail.codecName.length < 1 ||
    detail.codecName.length > 128 ||
    !/^[\x20-\x7e]+$/.test(detail.codecName) ||
    typeof detail.formatName !== 'string' ||
    detail.formatName.length < 1 ||
    detail.formatName.length > 128 ||
    !/^[\x20-\x7e]+$/.test(detail.formatName) ||
    !Number.isSafeInteger(detail.width) ||
    Number(detail.width) < 1 ||
    Number(detail.width) > MAX_MEDIA_DIMENSION ||
    !Number.isSafeInteger(detail.height) ||
    Number(detail.height) < 1 ||
    Number(detail.height) > MAX_MEDIA_DIMENSION ||
    Number(detail.width) * Number(detail.height) > MAX_MEDIA_PIXELS ||
    (expected.mediaType.startsWith('image/')
      ? detail.durationMs !== null
      : !Number.isSafeInteger(detail.durationMs) ||
        Number(detail.durationMs) < 1 ||
        Number(detail.durationMs) > 86_400_000) ||
    !Number.isSafeInteger(detail.decodedFrames) ||
    Number(detail.decodedFrames) < 1 ||
    Number(detail.decodedFrames) > 10_000_000
  ) {
    throw new PaidMediaVaultError('Paid media trusted validation receipt is invalid')
  }
  const common = {
    fullyDecoded: true as const,
    mediaType: raw.mediaType as PaidMediaArchivedAsset['mediaType'],
    byteLength: raw.byteLength as number,
    sha256: raw.sha256 as string,
    attestedTools: {
      ffmpegSha256: (tools as Record<string, unknown>).ffmpegSha256 as string,
      ffprobeSha256: (tools as Record<string, unknown>).ffprobeSha256 as string
    }
  }
  if (trustedV2) {
    if (
      (detail.audioCodecName !== null &&
        (typeof detail.audioCodecName !== 'string' ||
          !/^[a-z0-9_.-]{1,64}$/.test(detail.audioCodecName))) ||
      detail.videoStreamCount !== 1 ||
      (detail.audioStreamCount !== 0 && detail.audioStreamCount !== 1) ||
      (detail.audioStreamCount === 0) !== (detail.audioCodecName === null) ||
      (expected.mediaType.startsWith('image/') &&
        (detail.audioStreamCount !== 0 || detail.audioCodecName !== null))
    ) {
      throw new PaidMediaVaultError('Paid media trusted validation receipt is invalid')
    }
    const base: Omit<PaidMediaValidationReceipt, 'receiptSha256'> = {
      schema: TRUSTED_VALIDATION_SCHEMA,
      validatorVersion: TRUSTED_VALIDATOR_VERSION,
      validationPolicy: TRUSTED_VALIDATION_POLICY,
      ...common,
      metadata: {
        detectedKind: detail.detectedKind as 'image' | 'video',
        codecName: detail.codecName,
        audioCodecName: detail.audioCodecName as string | null,
        videoStreamCount: 1,
        audioStreamCount: detail.audioStreamCount as 0 | 1,
        formatName: detail.formatName,
        width: detail.width as number,
        height: detail.height as number,
        durationMs: detail.durationMs as number | null,
        decodedFrames: detail.decodedFrames as number
      }
    }
    if (validationReceiptDigest(base) !== raw.receiptSha256) {
      throw new PaidMediaVaultError('Paid media trusted validation receipt digest does not match')
    }
    return { ...base, receiptSha256: raw.receiptSha256 as string }
  }
  const base: Omit<PaidMediaLegacyValidationReceipt, 'receiptSha256'> = {
    schema: LEGACY_VALIDATION_SCHEMA,
    validatorVersion: LEGACY_VALIDATOR_VERSION,
    ...common,
    metadata: {
      detectedKind: detail.detectedKind as 'image' | 'video',
      codecName: detail.codecName,
      formatName: detail.formatName,
      width: detail.width as number,
      height: detail.height as number,
      durationMs: detail.durationMs as number | null,
      decodedFrames: detail.decodedFrames as number
    }
  }
  if (validationReceiptDigest(base) !== raw.receiptSha256) {
    throw new PaidMediaVaultError('Paid media legacy validation receipt digest does not match')
  }
  return { ...base, receiptSha256: raw.receiptSha256 as string }
}

function parseTrustedValidationReceipt(
  value: unknown,
  expected: Pick<PaidMediaArchivedAsset, 'mediaType' | 'byteLength' | 'sha256'>
): PaidMediaValidationReceipt {
  const parsed = parseStoredValidationReceipt(value, expected)
  if (!parsed || parsed.schema !== TRUSTED_VALIDATION_SCHEMA) {
    throw new PaidMediaVaultError('Paid media trusted v2 validation receipt is required')
  }
  return parsed
}

function requireOperationId(value: unknown): string {
  if (typeof value !== 'string' || !OPERATION_ID_PATTERN.test(value)) {
    throw new PaidMediaVaultError('Paid media vault operation id is invalid')
  }
  return value
}

function requireNow(now: () => number): number {
  const value = now()
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new PaidMediaVaultError('Paid media vault clock is invalid')
  }
  return value
}

function requireEncryption(storage: PaidMediaSafeStorage): void {
  if (!storage.isEncryptionAvailable()) {
    throw new PaidMediaVaultError('OS-backed paid media vault encryption is unavailable')
  }
}

function decodeCanonicalBase64(value: unknown, maxBytes: number, label: string): Buffer {
  if (
    typeof value !== 'string' ||
    value.length < 4 ||
    value.length > Math.ceil(maxBytes / 3) * 4 + 4 ||
    value.length % 4 !== 0 ||
    !/^[A-Za-z0-9+/]+={0,2}$/.test(value)
  ) {
    throw new PaidMediaVaultError(`${label} is not canonical base64`)
  }
  const decoded = Buffer.from(value, 'base64')
  if (decoded.length > maxBytes || decoded.toString('base64') !== value) {
    throw new PaidMediaVaultError(`${label} is not canonical base64`)
  }
  return decoded
}

function parseObject(raw: string, label: string): Record<string, unknown> {
  try {
    const parsed: unknown = JSON.parse(raw)
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('not object')
    return parsed as Record<string, unknown>
  } catch (error) {
    throw new PaidMediaVaultError(`${label} is corrupt`, { cause: error })
  }
}

function validateHttpsAssetUrl(raw: unknown): string {
  if (typeof raw !== 'string' || raw.length < 1 || raw.length > MAX_URL_LENGTH) {
    throw new PaidMediaVaultError('Paid media archive URL is invalid')
  }
  let url: URL
  try {
    url = new URL(raw)
  } catch (error) {
    throw new PaidMediaVaultError('Paid media archive URL is invalid', { cause: error })
  }
  if (
    url.protocol !== 'https:' ||
    !url.hostname ||
    url.username ||
    url.password ||
    url.port
  ) {
    throw new PaidMediaVaultError('Paid media archive URL must use credential-free HTTPS')
  }
  const hostname = url.hostname.replace(/^\[|\]$/g, '').replace(/\.$/, '').toLowerCase()
  if (!hostname || hostname.length > 253 || LOCAL_HOSTNAME.test(hostname)) {
    throw new PaidMediaVaultError('Paid media archive URL hostname is forbidden')
  }
  const literal = hostname.split('%', 1)[0]
  if (/^[0-9a-f:.]+$/i.test(literal) && !isPublicMediaAddress(literal)) {
    throw new PaidMediaVaultError('Paid media archive URL must resolve to a public address')
  }
  if (!/[a-z]/i.test(hostname) && !isPublicMediaAddress(hostname)) {
    throw new PaidMediaVaultError('Paid media archive numeric hostname is forbidden')
  }
  url.hash = ''
  return url.toString()
}

function validatePixelDimensions(width: number, height: number, label: string): void {
  if (
    !Number.isSafeInteger(width) ||
    !Number.isSafeInteger(height) ||
    width < 1 ||
    height < 1 ||
    width > MAX_MEDIA_DIMENSION ||
    height > MAX_MEDIA_DIMENSION ||
    width * height > MAX_MEDIA_PIXELS
  ) {
    throw new PaidMediaVaultError(`${label} dimensions exceed the decode budget`)
  }
}

const CRC32_TABLE = Array.from({ length: 256 }, (_, value) => {
  let current = value
  for (let bit = 0; bit < 8; bit += 1) {
    current = (current & 1) !== 0 ? 0xedb88320 ^ (current >>> 1) : current >>> 1
  }
  return current >>> 0
})

function crc32(bytes: Buffer, start: number, end: number): number {
  let value = 0xffffffff
  for (let index = start; index < end; index += 1) {
    value = CRC32_TABLE[(value ^ bytes[index]) & 0xff] ^ (value >>> 8)
  }
  return (value ^ 0xffffffff) >>> 0
}

function validatePng(bytes: Buffer): void {
  let offset = 8
  let chunks = 0
  let sawHeader = false
  let sawImageData = false
  let sawEnd = false
  while (offset < bytes.length) {
    if (bytes.length - offset < 12 || chunks >= 100_000) {
      throw new PaidMediaVaultError('Paid media PNG structure is invalid')
    }
    const length = bytes.readUInt32BE(offset)
    const dataStart = offset + 8
    const dataEnd = dataStart + length
    const chunkEnd = dataEnd + 4
    if (dataEnd < dataStart || chunkEnd > bytes.length) {
      throw new PaidMediaVaultError('Paid media PNG chunk exceeds its file')
    }
    const type = bytes.subarray(offset + 4, offset + 8).toString('ascii')
    if (!/^[A-Za-z]{4}$/.test(type)) {
      throw new PaidMediaVaultError('Paid media PNG chunk type is invalid')
    }
    if (bytes.readUInt32BE(dataEnd) !== crc32(bytes, offset + 4, dataEnd)) {
      throw new PaidMediaVaultError('Paid media PNG chunk checksum is invalid')
    }
    if (chunks === 0) {
      if (type !== 'IHDR' || length !== 13) {
        throw new PaidMediaVaultError('Paid media PNG header is invalid')
      }
      validatePixelDimensions(
        bytes.readUInt32BE(dataStart),
        bytes.readUInt32BE(dataStart + 4),
        'Paid media PNG'
      )
      if (
        ![1, 2, 4, 8, 16].includes(bytes[dataStart + 8]) ||
        ![0, 2, 3, 4, 6].includes(bytes[dataStart + 9]) ||
        bytes[dataStart + 10] !== 0 ||
        bytes[dataStart + 11] !== 0 ||
        ![0, 1].includes(bytes[dataStart + 12])
      ) {
        throw new PaidMediaVaultError('Paid media PNG decode parameters are invalid')
      }
      sawHeader = true
    } else if (type === 'IHDR') {
      throw new PaidMediaVaultError('Paid media PNG has duplicate headers')
    }
    if (type === 'IDAT') sawImageData = true
    if (type === 'IEND') {
      if (length !== 0 || chunkEnd !== bytes.length) {
        throw new PaidMediaVaultError('Paid media PNG end marker is invalid')
      }
      sawEnd = true
    }
    offset = chunkEnd
    chunks += 1
  }
  if (!sawHeader || !sawImageData || !sawEnd || offset !== bytes.length) {
    throw new PaidMediaVaultError('Paid media PNG is incomplete')
  }
}

function validateJpegDimensions(bytes: Buffer): void {
  let offset = 2
  while (offset + 4 <= bytes.length - 2) {
    if (bytes[offset] !== 0xff) {
      offset += 1
      continue
    }
    while (bytes[offset] === 0xff) offset += 1
    const marker = bytes[offset++]
    if (marker === 0xd8 || marker === 0xd9 || marker === 0x01) continue
    if (offset + 2 > bytes.length) break
    const length = bytes.readUInt16BE(offset)
    if (length < 2 || offset + length > bytes.length) break
    if (
      (marker >= 0xc0 && marker <= 0xc3) ||
      (marker >= 0xc5 && marker <= 0xc7) ||
      (marker >= 0xc9 && marker <= 0xcb) ||
      (marker >= 0xcd && marker <= 0xcf)
    ) {
      if (length < 7) break
      validatePixelDimensions(
        bytes.readUInt16BE(offset + 5),
        bytes.readUInt16BE(offset + 3),
        'Paid media JPEG'
      )
      return
    }
    offset += length
  }
  throw new PaidMediaVaultError('Paid media JPEG dimensions are missing')
}

function detectImage(bytes: Buffer): Pick<PaidMediaArchivedAsset, 'mediaType' | 'extension'> {
  if (
    bytes.length >= 24 &&
    bytes.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))
  ) {
    validatePng(bytes)
    return { mediaType: 'image/png', extension: 'png' }
  }
  if (
    bytes.length >= 4 &&
    bytes[0] === 0xff &&
    bytes[1] === 0xd8 &&
    bytes[2] === 0xff &&
    bytes[bytes.length - 2] === 0xff &&
    bytes[bytes.length - 1] === 0xd9
  ) {
    validateJpegDimensions(bytes)
    return { mediaType: 'image/jpeg', extension: 'jpg' }
  }
  const header = bytes.subarray(0, 6).toString('ascii')
  if (bytes.length >= 13 && (header === 'GIF87a' || header === 'GIF89a')) {
    validatePixelDimensions(bytes.readUInt16LE(6), bytes.readUInt16LE(8), 'Paid media GIF')
    if (bytes[bytes.length - 1] !== 0x3b) {
      throw new PaidMediaVaultError('Paid media GIF trailer is missing')
    }
    return { mediaType: 'image/gif', extension: 'gif' }
  }
  if (
    bytes.length >= 12 &&
    bytes.subarray(0, 4).toString('ascii') === 'RIFF' &&
    bytes.subarray(8, 12).toString('ascii') === 'WEBP'
  ) {
    if (bytes.readUInt32LE(4) + 8 !== bytes.length) {
      throw new PaidMediaVaultError('Paid media WebP container length is invalid')
    }
    return { mediaType: 'image/webp', extension: 'webp' }
  }
  throw new PaidMediaVaultError('Paid media archive image magic is unsupported')
}

type PaidMediaImageType = Extract<PaidMediaArchivedAsset['mediaType'], `image/${string}`>

function imageExtension(mediaType: PaidMediaImageType): PaidMediaArchivedAsset['extension'] {
  switch (mediaType) {
    case 'image/png':
      return 'png'
    case 'image/jpeg':
      return 'jpg'
    case 'image/gif':
      return 'gif'
    case 'image/webp':
      return 'webp'
  }
}

function requireImageType(value: PaidMediaAssetDescriptor['mediaType']): PaidMediaImageType {
  if (
    value !== 'image/png' &&
    value !== 'image/jpeg' &&
    value !== 'image/gif' &&
    value !== 'image/webp'
  ) {
    throw new PaidMediaVaultError('Paid media sealed stage image type is invalid')
  }
  return value
}

/** Bounded structural evidence used while hashing file-backed image assets. */
class BoundedImageStreamVerifier {
  private readonly prefix = Buffer.alloc(33)
  private prefixLength = 0
  private readonly tail = Buffer.alloc(12)
  private tailLength = 0
  private total = 0

  constructor(
    private readonly mediaType: PaidMediaImageType,
    private readonly expectedLength: number
  ) {}

  update(bytes: Buffer): void {
    if (bytes.length < 1 || this.total + bytes.length > this.expectedLength) {
      throw new PaidMediaVaultError('Paid media archive image length is invalid')
    }
    if (this.prefixLength < this.prefix.length) {
      const count = Math.min(this.prefix.length - this.prefixLength, bytes.length)
      bytes.copy(this.prefix, this.prefixLength, 0, count)
      this.prefixLength += count
    }
    if (bytes.length >= this.tail.length) {
      bytes.copy(this.tail, 0, bytes.length - this.tail.length)
      this.tailLength = this.tail.length
    } else {
      const preserved = Math.min(this.tailLength, this.tail.length - bytes.length)
      if (preserved > 0) {
        this.tail.copyWithin(0, this.tailLength - preserved, this.tailLength)
      }
      bytes.copy(this.tail, preserved)
      this.tailLength = preserved + bytes.length
    }
    this.total += bytes.length
  }

  finish(): void {
    if (this.total !== this.expectedLength) {
      throw new PaidMediaVaultError('Paid media archive image length does not match')
    }
    if (this.mediaType === 'image/png') {
      const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])
      const end = Buffer.from('0000000049454e44ae426082', 'hex')
      if (
        this.prefixLength < 33 ||
        !this.prefix.subarray(0, 8).equals(signature) ||
        this.prefix.readUInt32BE(8) !== 13 ||
        this.prefix.subarray(12, 16).toString('ascii') !== 'IHDR' ||
        this.tailLength !== end.length ||
        !this.tail.equals(end)
      ) {
        throw new PaidMediaVaultError('Paid media archive PNG magic or structure is invalid')
      }
      validatePixelDimensions(
        this.prefix.readUInt32BE(16),
        this.prefix.readUInt32BE(20),
        'Paid media PNG'
      )
      if (
        ![1, 2, 4, 8, 16].includes(this.prefix[24]) ||
        ![0, 2, 3, 4, 6].includes(this.prefix[25]) ||
        this.prefix[26] !== 0 ||
        this.prefix[27] !== 0 ||
        ![0, 1].includes(this.prefix[28])
      ) {
        throw new PaidMediaVaultError('Paid media PNG decode parameters are invalid')
      }
      return
    }
    if (this.mediaType === 'image/jpeg') {
      if (
        this.prefixLength < 4 ||
        this.prefix[0] !== 0xff ||
        this.prefix[1] !== 0xd8 ||
        this.prefix[2] !== 0xff ||
        this.tailLength < 2 ||
        this.tail[this.tailLength - 2] !== 0xff ||
        this.tail[this.tailLength - 1] !== 0xd9
      ) {
        throw new PaidMediaVaultError('Paid media archive JPEG magic or structure is invalid')
      }
      return
    }
    if (this.mediaType === 'image/gif') {
      const header = this.prefix.subarray(0, 6).toString('ascii')
      if (
        this.prefixLength < 13 ||
        (header !== 'GIF87a' && header !== 'GIF89a') ||
        this.tailLength < 1 ||
        this.tail[this.tailLength - 1] !== 0x3b
      ) {
        throw new PaidMediaVaultError('Paid media archive GIF magic or structure is invalid')
      }
      validatePixelDimensions(
        this.prefix.readUInt16LE(6),
        this.prefix.readUInt16LE(8),
        'Paid media GIF'
      )
      return
    }
    if (
      this.prefixLength < 12 ||
      this.prefix.subarray(0, 4).toString('ascii') !== 'RIFF' ||
      this.prefix.subarray(8, 12).toString('ascii') !== 'WEBP' ||
      this.prefix.readUInt32LE(4) + 8 !== this.expectedLength
    ) {
      throw new PaidMediaVaultError('Paid media archive WebP magic or structure is invalid')
    }
  }
}

function detectVideo(bytes: Buffer): Pick<PaidMediaArchivedAsset, 'mediaType' | 'extension'> {
  if (bytes.length >= 16 && bytes.subarray(4, 8).toString('ascii') === 'ftyp') {
    let offset = 0
    let sawFtyp = false
    let sawMoov = false
    let sawMovieHeader = false
    let sawTrack = false
    let sawMediaData = false
    while (offset < bytes.length) {
      if (bytes.length - offset < 8) {
        throw new PaidMediaVaultError('Paid media MP4 box header is truncated')
      }
      let boxLength = bytes.readUInt32BE(offset)
      const type = bytes.subarray(offset + 4, offset + 8).toString('ascii')
      let headerLength = 8
      if (boxLength === 1) {
        if (bytes.length - offset < 16) {
          throw new PaidMediaVaultError('Paid media MP4 extended box is truncated')
        }
        const extended = bytes.readBigUInt64BE(offset + 8)
        if (extended > BigInt(Number.MAX_SAFE_INTEGER)) {
          throw new PaidMediaVaultError('Paid media MP4 box is too large')
        }
        boxLength = Number(extended)
        headerLength = 16
      } else if (boxLength === 0) {
        boxLength = bytes.length - offset
      }
      if (
        boxLength < headerLength ||
        offset + boxLength > bytes.length ||
        !/^[\x20-\x7e]{4}$/.test(type)
      ) {
        throw new PaidMediaVaultError('Paid media MP4 box structure is invalid')
      }
      const payload = bytes.subarray(offset + headerLength, offset + boxLength)
      if (type === 'ftyp') sawFtyp = payload.length >= 8
      if (type === 'moov') {
        sawMoov = payload.length >= 128
        sawMovieHeader = payload.indexOf(Buffer.from('mvhd', 'ascii')) >= 0
        sawTrack = payload.indexOf(Buffer.from('trak', 'ascii')) >= 0
      }
      if (type === 'mdat' && payload.length >= 16) sawMediaData = true
      offset += boxLength
    }
    if (!sawFtyp || !sawMoov || !sawMovieHeader || !sawTrack || !sawMediaData) {
      throw new PaidMediaVaultError('Paid media MP4 is not a complete playable container')
    }
    return { mediaType: 'video/mp4', extension: 'mp4' }
  }
  if (
    bytes.length >= 8 &&
    bytes.subarray(0, 4).equals(Buffer.from([0x1a, 0x45, 0xdf, 0xa3]))
  ) {
    if (
      bytes.indexOf(Buffer.from([0x18, 0x53, 0x80, 0x67])) < 0 ||
      bytes.indexOf(Buffer.from([0x16, 0x54, 0xae, 0x6b])) < 0 ||
      bytes.indexOf(Buffer.from([0x1f, 0x43, 0xb6, 0x75])) < 0
    ) {
      throw new PaidMediaVaultError('Paid media WebM is not a complete playable container')
    }
    return { mediaType: 'video/webm', extension: 'webm' }
  }
  throw new PaidMediaVaultError('Paid media terminal video magic is unsupported')
}

async function readFileRange(
  handle: FileHandle,
  position: number,
  length: number,
  label: string
): Promise<Buffer> {
  const bytes = Buffer.alloc(length)
  const received = await handle.read(bytes, 0, length, position)
  if (received.bytesRead !== length) {
    throw new PaidMediaVaultError(`${label} is truncated`)
  }
  return bytes
}

async function readMp4Box(
  handle: FileHandle,
  offset: number,
  end: number
): Promise<{ type: string; length: number; headerLength: number }> {
  if (end - offset < 8) throw new PaidMediaVaultError('Paid media MP4 box header is truncated')
  const header = await readFileRange(handle, offset, Math.min(16, end - offset), 'Paid media MP4')
  let length = header.readUInt32BE(0)
  const type = header.subarray(4, 8).toString('ascii')
  let headerLength = 8
  if (length === 1) {
    if (header.length < 16) {
      throw new PaidMediaVaultError('Paid media MP4 extended box is truncated')
    }
    const extended = header.readBigUInt64BE(8)
    if (extended > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new PaidMediaVaultError('Paid media MP4 box is too large')
    }
    length = Number(extended)
    headerLength = 16
  } else if (length === 0) {
    length = end - offset
  }
  if (
    length < headerLength ||
    offset + length > end ||
    !/^[\x20-\x7e]{4}$/.test(type)
  ) {
    throw new PaidMediaVaultError('Paid media MP4 box structure is invalid')
  }
  return { type, length, headerLength }
}

async function validateStoredVideoFile(
  handle: FileHandle,
  byteLength: number,
  extension: 'mp4' | 'webm'
): Promise<void> {
  if (extension === 'webm') {
    let first = true
    let tail = Buffer.alloc(0)
    let sawSegment = false
    let sawTracks = false
    let sawCluster = false
    for await (const value of handle.createReadStream({
      start: 0,
      end: byteLength - 1,
      autoClose: false,
      highWaterMark: 256 * 1024
    })) {
      const chunk = Buffer.isBuffer(value) ? value : Buffer.from(value)
      if (first) {
        first = false
        if (
          chunk.length < 4 ||
          !chunk.subarray(0, 4).equals(Buffer.from([0x1a, 0x45, 0xdf, 0xa3]))
        ) {
          throw new PaidMediaVaultError('Paid media WebM header is invalid')
        }
      }
      const searchable = tail.length ? Buffer.concat([tail, chunk]) : chunk
      sawSegment ||= searchable.indexOf(Buffer.from([0x18, 0x53, 0x80, 0x67])) >= 0
      sawTracks ||= searchable.indexOf(Buffer.from([0x16, 0x54, 0xae, 0x6b])) >= 0
      sawCluster ||= searchable.indexOf(Buffer.from([0x1f, 0x43, 0xb6, 0x75])) >= 0
      tail = searchable.subarray(Math.max(0, searchable.length - 3))
    }
    if (!sawSegment || !sawTracks || !sawCluster) {
      throw new PaidMediaVaultError('Paid media WebM is not a complete playable container')
    }
    return
  }

  let offset = 0
  let sawFtyp = false
  let sawMoov = false
  let sawMovieHeader = false
  let sawTrack = false
  let sawMediaData = false
  while (offset < byteLength) {
    const box = await readMp4Box(handle, offset, byteLength)
    const payloadStart = offset + box.headerLength
    const boxEnd = offset + box.length
    if (box.type === 'ftyp') sawFtyp = box.length - box.headerLength >= 8
    if (box.type === 'mdat' && box.length - box.headerLength >= 16) sawMediaData = true
    if (box.type === 'moov') {
      sawMoov = box.length - box.headerLength >= 128
      let childOffset = payloadStart
      while (childOffset < boxEnd) {
        const child = await readMp4Box(handle, childOffset, boxEnd)
        if (child.type === 'mvhd' && child.length - child.headerLength >= 96) {
          sawMovieHeader = true
        }
        if (child.type === 'trak' && child.length - child.headerLength >= 64) {
          sawTrack = true
        }
        childOffset += child.length
      }
    }
    offset = boxEnd
  }
  if (!sawFtyp || !sawMoov || !sawMovieHeader || !sawTrack || !sawMediaData) {
    throw new PaidMediaVaultError('Paid media MP4 is not structurally complete')
  }
}

function validateDeclaredImageType(
  contentType: string | undefined,
  detected: PaidMediaArchivedAsset['mediaType']
): void {
  if (contentType === undefined) return
  const normalized = contentType.split(';', 1)[0].trim().toLowerCase()
  if (!normalized || normalized === 'application/octet-stream' || normalized === 'binary/octet-stream') {
    return
  }
  const canonical = normalized === 'image/jpg' ? 'image/jpeg' : normalized
  if (canonical !== detected) {
    throw new PaidMediaVaultError('Paid media archive declared type does not match image magic')
  }
}

function validateDeclaredVideoType(
  contentType: string | undefined,
  detected: PaidMediaArchivedAsset['mediaType']
): void {
  if (contentType === undefined) return
  const normalized = contentType.split(';', 1)[0].trim().toLowerCase()
  if (!normalized || normalized === 'application/octet-stream' || normalized === 'binary/octet-stream') {
    return
  }
  if (normalized !== detected) {
    throw new PaidMediaVaultError('Paid media archive declared type does not match video magic')
  }
}

function publicReceipt(document: ArchiveDocument): PaidMediaArchiveReceipt {
  return {
    schema: 'nachuan.paid-media-vault.receipt.v1',
    operationId: document.operationId,
    path: document.path,
    requestSha256: document.requestSha256,
    responseSha256: document.responseSha256,
    responseByteLength: document.responseByteLength,
    recoverySha256: document.recoverySha256,
    receiptSha256: document.receiptSha256,
    status: document.status,
    kind: document.kind,
    ...(document.taskReceiptIdSha256 === null
      ? {}
      : { taskReceiptIdSha256: document.taskReceiptIdSha256 }),
    assets: document.assets.map((asset) => ({ ...asset })),
    archivedAt: document.archivedAt
  }
}

export async function nodePaidMediaRemoteFetcher(
  rawUrl: string,
  maxBytes: number
): Promise<PaidMediaRemoteFetchResult> {
  const url = validateHttpsAssetUrl(rawUrl)
  const bounded = Math.max(1, Math.min(Math.floor(maxBytes), MAX_REMOTE_MEDIA_BYTES))
  const tempRoot = canonicalPrivateTempRoot()
  const root = mkdtempSync(join(tempRoot, 'nachuan-paid-media-fetch-'))
  const destination = join(root, 'asset.bin')
  const rootIdentity = lstatSync(root)
  let handedOff = false
  try {
    const received = await downloadPublicMedia(url, destination, bounded)
    const info = lstatSync(destination)
    if (
      !info.isFile() ||
      info.isSymbolicLink() ||
      info.size !== received ||
      info.size < 1 ||
      info.size > bounded
    ) {
      throw new PaidMediaVaultError('Paid media archive download length is invalid')
    }
    handedOff = true
    return {
      filePath: destination,
      byteLength: received,
      contentType: 'application/octet-stream',
      finalUrl: url
    }
  } catch (error) {
    if (error instanceof PaidMediaVaultError) throw error
    throw new PaidMediaVaultError('Paid media archive download failed', { cause: error })
  } finally {
    if (!handedOff) {
      try {
        const currentRoot = lstatSync(root)
        if (
          !currentRoot.isDirectory() ||
          currentRoot.isSymbolicLink() ||
          currentRoot.dev !== rootIdentity.dev ||
          currentRoot.ino !== rootIdentity.ino ||
          currentRoot.birthtimeMs !== rootIdentity.birthtimeMs ||
          normalizedAbsolutePath(realpathSync(root)) !== normalizedAbsolutePath(root) ||
          normalizedAbsolutePath(dirname(root)) !== normalizedAbsolutePath(tempRoot) ||
          !FETCH_STAGING_DIRECTORY_PATTERN.test(basename(root))
        ) {
          throw new PaidMediaVaultError('Paid media failed fetch staging identity changed')
        }
        const entries = readdirSync(root, { withFileTypes: true })
        if (entries.length === 1 && entries[0]?.name === 'asset.bin') {
          const file = lstatSync(destination)
          if (
            !file.isFile() ||
            file.isSymbolicLink() ||
            normalizedAbsolutePath(realpathSync(destination)) !==
              normalizedAbsolutePath(destination)
          ) {
            throw new PaidMediaVaultError('Paid media failed fetch asset is redirected')
          }
          unlinkSync(destination)
        } else if (entries.length !== 0) {
          throw new PaidMediaVaultError('Paid media failed fetch staging contains unknown entries')
        }
        if (readdirSync(root).length !== 0) {
          throw new PaidMediaVaultError('Paid media failed fetch staging is not empty')
        }
        rmdirSync(root)
      } catch {
        // Fail closed: never broaden deletion to an unexpected staging tree.
      }
    }
  }
}

export class PaidMediaVault {
  private readonly root: string
  private readonly claimsPath: string
  private readonly archivesPath: string
  private readonly discoveriesPath: string
  private readonly presentationsPath: string
  private readonly assetValidationsPath: string
  private readonly assetsPath: string
  private readonly videoTasksPath: string
  private readonly videoTerminalsPath: string
  private readonly cleanupPendingPath: string
  private readonly legacyImportsPath: string
  private readonly authorityHeadPath: string
  private readonly authorityJournalPath: string
  private cleanupRecoveredHandler: ((operationId: string) => void | Promise<void>) | null = null
  private mutationGuard: (() => void) | null = null
  private authorityStrict = false
  private authorityIndexCache: VaultAuthorityIndexCache | null = null
  private authorityIndexPoisoned = false
  private validationMigrationSourceCache: ValidationMigrationSourceSnapshot | null = null
  private cleanupMutationRunner:
    | ((operationId: string, action: () => Promise<void>) => Promise<void>)
    | null = null
  private readonly cleanupRetries = new Map<
    string,
    { timer: ReturnType<typeof setTimeout>; attempt: number }
  >()
  private readonly cleanupFlights = new Map<string, Promise<boolean>>()
  private readonly hardenedPaths = new Map<string, HardenedPathIdentity>()
  private readonly verifiedAssets = new Map<
    string,
    VerifiedAssetIdentity & {
      sha256: string
      mediaType: PaidMediaArchivedAsset['mediaType']
    }
  >()
  private readonly terminalArchiveFlights = new Map<
    string,
    { providerResultSha256: string; promise: Promise<PaidMediaTerminalArchiveResult> }
  >()
  private readonly stageWriteCapabilities = new WeakMap<object, StageOpenHandleRecord>()
  private readonly sealedStageCapabilities = new WeakMap<object, StageOpenHandleRecord>()
  private readonly stageOpenHandles = new Map<string, StageOpenHandleRecord>()
  private activeStageStream: StageOpenHandleRecord | null = null
  private captureInspectionReadOnly = false

  constructor(root: string, private readonly dependencies: PaidMediaVaultDependencies) {
    if (!resolve(root)) throw new PaidMediaVaultError('Paid media vault root is invalid')
    this.root = resolve(root)
    this.claimsPath = join(this.root, 'claims')
    this.archivesPath = join(this.root, 'archives')
    this.discoveriesPath = join(this.root, 'discoveries')
    this.presentationsPath = join(this.root, 'presentations')
    this.assetValidationsPath = join(this.root, 'asset-validations')
    this.assetsPath = join(this.root, 'assets')
    this.videoTasksPath = join(this.root, 'video-tasks')
    this.videoTerminalsPath = join(this.root, 'video-terminals')
    this.cleanupPendingPath = join(this.root, 'cleanup-pending')
    this.legacyImportsPath = join(this.root, 'legacy-imports')
    this.authorityHeadPath = `${this.root}.authority.json`
    this.authorityJournalPath = `${this.root}.authority.journal`
  }

  setCleanupRecoveredHandler(
    handler: ((operationId: string) => void | Promise<void>) | null
  ): void {
    if (handler !== null && typeof handler !== 'function') {
      throw new PaidMediaVaultError('Paid media cleanup recovery handler is invalid')
    }
    this.cleanupRecoveredHandler = handler
  }

  setMutationGuard(guard: () => void): void {
    if (typeof guard !== 'function') {
      throw new PaidMediaVaultError('Paid media mutation guard is invalid')
    }
    if (this.mutationGuard !== null && this.mutationGuard !== guard) {
      throw new PaidMediaVaultError('Paid media mutation guard is already attached')
    }
    this.mutationGuard = guard
    this.authorityStrict = true
  }

  setCleanupMutationRunner(
    runner: (operationId: string, action: () => Promise<void>) => Promise<void>
  ): void {
    if (typeof runner !== 'function') {
      throw new PaidMediaVaultError('Paid media cleanup mutation runner is invalid')
    }
    if (this.cleanupMutationRunner !== null && this.cleanupMutationRunner !== runner) {
      throw new PaidMediaVaultError('Paid media cleanup mutation runner is already attached')
    }
    this.cleanupMutationRunner = runner
  }

  private assertMutationAllowed(): void {
    this.mutationGuard?.()
  }

  async ensureMediaProbeReady(): Promise<void> {
    try {
      await this.dependencies.ensureMediaProbeReady()
    } catch (error) {
      throw new PaidMediaVaultError('Trusted paid media probe is unavailable', { cause: error })
    }
  }

  hasTerminalMediaForTask(taskAlias: string): boolean {
    this.prepare()
    return existsSync(this.terminalFile(taskAlias))
  }

  private async validateTrustedMedia(input: {
    createReadStream: () => Readable
    mediaType: PaidMediaArchivedAsset['mediaType']
    byteLength: number
    sha256: string
  }): Promise<PaidMediaValidationReceipt> {
    let receipt: Awaited<ReturnType<PaidMediaVaultDependencies['validateMediaAsset']>>
    try {
      receipt = await this.dependencies.validateMediaAsset(input)
    } catch (error) {
      throw new PaidMediaVaultError('Trusted paid media decode validation failed', {
        cause: error
      })
    }
    return parseTrustedValidationReceipt(receipt, input)
  }

  private pathIdentity(info: Stats, directory: boolean): HardenedPathIdentity {
    return {
      directory,
      dev: info.dev,
      ino: info.ino,
      birthtimeMs: info.birthtimeMs
    }
  }

  private cleanupPathIdentity(path: string, directory: boolean): CleanupStagingIdentity {
    const absolute = resolve(path)
    const info = lstatSync(absolute)
    if (
      info.isSymbolicLink() ||
      (directory ? !info.isDirectory() : !info.isFile()) ||
      normalizedAbsolutePath(realpathSync(absolute)) !== normalizedAbsolutePath(absolute) ||
      !Number.isFinite(info.dev) ||
      info.dev < 0 ||
      !Number.isFinite(info.ino) ||
      info.ino < 0 ||
      !Number.isFinite(info.birthtimeMs) ||
      !Number.isFinite(info.mtimeMs) ||
      !Number.isFinite(info.ctimeMs) ||
      !Number.isSafeInteger(info.size) ||
      info.size < 0
    ) {
      throw new PaidMediaVaultError('Paid media cleanup staging identity is invalid')
    }
    return {
      pathSha256: sha256(normalizedAbsolutePath(absolute)),
      dev: info.dev,
      ino: info.ino,
      birthtimeMs: info.birthtimeMs,
      mtimeMs: info.mtimeMs,
      ctimeMs: info.ctimeMs,
      size: info.size
    }
  }

  private sameStableCleanupIdentity(
    left: CleanupStableIdentity,
    right: CleanupStableIdentity
  ): boolean {
    return (
      left.pathSha256 === right.pathSha256 &&
      left.dev === right.dev &&
      left.ino === right.ino &&
      left.birthtimeMs === right.birthtimeMs
    )
  }

  private cleanupRootIdentity(path: string): CleanupStableIdentity {
    const { pathSha256, dev, ino, birthtimeMs } = this.cleanupPathIdentity(path, true)
    return { pathSha256, dev, ino, birthtimeMs }
  }

  private sameFullCleanupIdentity(
    left: CleanupStagingIdentity,
    right: CleanupStagingIdentity
  ): boolean {
    return (
      this.sameStableCleanupIdentity(left, right) &&
      left.mtimeMs === right.mtimeMs &&
      left.ctimeMs === right.ctimeMs &&
      left.size === right.size
    )
  }

  private cleanupPathExists(path: string): boolean {
    try {
      lstatSync(path)
      return true
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false
      throw error
    }
  }

  private controlledCleanupBase(
    operationId: string,
    result: Extract<PaidMediaRemoteFetchResult, { filePath: string }>,
    cleanupId: string
  ): CleanupMarkerBase {
    if (
      !Number.isSafeInteger(result.byteLength) ||
      result.byteLength < 1 ||
      result.byteLength > MAX_PAID_MEDIA_TERMINAL_VIDEO_BYTES
    ) {
      throw new PaidMediaVaultError('Paid media cleanup staging length is invalid')
    }
    const tempRoot = canonicalPrivateTempRoot()
    const filePath = resolve(result.filePath)
    const directoryPath = dirname(filePath)
    const directoryName = basename(directoryPath)
    if (
      basename(filePath) !== 'asset.bin' ||
      normalizedAbsolutePath(dirname(directoryPath)) !== normalizedAbsolutePath(tempRoot) ||
      !FETCH_STAGING_DIRECTORY_PATTERN.test(directoryName) ||
      resolve(tempRoot, directoryName, 'asset.bin') !== filePath
    ) {
      throw new PaidMediaVaultError('Paid media cleanup staging contract is invalid')
    }
    const entries = readdirSync(directoryPath, { withFileTypes: true })
    if (
      entries.length !== 1 ||
      entries[0]?.name !== 'asset.bin' ||
      !entries[0].isFile() ||
      entries[0].isSymbolicLink()
    ) {
      throw new PaidMediaVaultError('Paid media cleanup staging is not a closed file set')
    }
    const file = this.cleanupPathIdentity(filePath, false)
    if (file.size !== result.byteLength) {
      throw new PaidMediaVaultError('Paid media cleanup staging length changed')
    }
    return {
      schema: CLEANUP_MARKER_SCHEMA,
      operationId: requireOperationId(operationId),
      cleanupId,
      tempRoot: this.cleanupRootIdentity(tempRoot),
      directoryName,
      directory: this.cleanupPathIdentity(directoryPath, true),
      fileName: 'asset.bin',
      file,
      createdAt: requireNow(this.dependencies.now)
    }
  }

  private createCleanupMarker(
    operationId: string,
    result: Extract<PaidMediaRemoteFetchResult, { filePath: string }>
  ): CleanupMarkerDocument & { path: string } {
    this.prepare()
    const cleanupId = randomBytes(16).toString('hex')
    const base = this.controlledCleanupBase(operationId, result, cleanupId)
    const document: CleanupMarkerDocument = {
      ...base,
      markerSha256: sha256(JSON.stringify(base))
    }
    const marker = {
      ...document,
      path: join(this.cleanupPendingPath, `${base.operationId}_${cleanupId}.json`)
    }
    try {
      this.validateControlledCleanupState(marker)
      this.writeAtomicNew(
        marker.path,
        this.encodeEncrypted(document),
        'Paid media cleanup marker',
        64 * 1024
      )
      this.validateControlledCleanupState(marker)
    } catch (error) {
      try {
        this.performControlledCleanup(marker)
      } catch (cleanupError) {
        this.dependencies.onCleanupError?.(cleanupError)
      }
      throw error
    }
    return marker
  }

  private parseCleanupIdentity(value: unknown): CleanupStagingIdentity {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      throw new PaidMediaVaultError('Paid media cleanup marker identity is invalid')
    }
    const identity = value as Record<string, unknown>
    if (
      !exactKeys(identity, [
        'pathSha256',
        'dev',
        'ino',
        'birthtimeMs',
        'mtimeMs',
        'ctimeMs',
        'size'
      ]) ||
      typeof identity.pathSha256 !== 'string' ||
      !SHA256_PATTERN.test(identity.pathSha256) ||
      !Number.isFinite(identity.dev) ||
      Number(identity.dev) < 0 ||
      !Number.isFinite(identity.ino) ||
      Number(identity.ino) < 0 ||
      !Number.isFinite(identity.birthtimeMs) ||
      !Number.isFinite(identity.mtimeMs) ||
      !Number.isFinite(identity.ctimeMs) ||
      !Number.isSafeInteger(identity.size) ||
      Number(identity.size) < 0
    ) {
      throw new PaidMediaVaultError('Paid media cleanup marker identity is invalid')
    }
    return {
      pathSha256: identity.pathSha256,
      dev: Number(identity.dev),
      ino: Number(identity.ino),
      birthtimeMs: Number(identity.birthtimeMs),
      mtimeMs: Number(identity.mtimeMs),
      ctimeMs: Number(identity.ctimeMs),
      size: Number(identity.size)
    }
  }

  private parseCleanupRootIdentity(value: unknown): CleanupStableIdentity {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      throw new PaidMediaVaultError('Paid media cleanup marker temp root identity is invalid')
    }
    const identity = value as Record<string, unknown>
    if (
      !exactKeys(identity, ['pathSha256', 'dev', 'ino', 'birthtimeMs']) ||
      typeof identity.pathSha256 !== 'string' ||
      !SHA256_PATTERN.test(identity.pathSha256) ||
      !Number.isFinite(identity.dev) ||
      Number(identity.dev) < 0 ||
      !Number.isFinite(identity.ino) ||
      Number(identity.ino) < 0 ||
      !Number.isFinite(identity.birthtimeMs)
    ) {
      throw new PaidMediaVaultError('Paid media cleanup marker temp root identity is invalid')
    }
    return {
      pathSha256: identity.pathSha256,
      dev: Number(identity.dev),
      ino: Number(identity.ino),
      birthtimeMs: Number(identity.birthtimeMs)
    }
  }

  private parseCleanupMarker(
    value: Record<string, unknown>,
    path: string
  ): CleanupMarkerDocument & { path: string } {
    if (
      !exactKeys(value, [
        'schema',
        'operationId',
        'cleanupId',
        'tempRoot',
        'directoryName',
        'directory',
        'fileName',
        'file',
        'createdAt',
        'markerSha256'
      ]) ||
      value.schema !== CLEANUP_MARKER_SCHEMA ||
      typeof value.operationId !== 'string' ||
      typeof value.cleanupId !== 'string' ||
      !/^[0-9a-f]{32}$/.test(value.cleanupId) ||
      typeof value.directoryName !== 'string' ||
      !FETCH_STAGING_DIRECTORY_PATTERN.test(value.directoryName) ||
      value.fileName !== 'asset.bin' ||
      !Number.isSafeInteger(value.createdAt) ||
      Number(value.createdAt) < 1 ||
      typeof value.markerSha256 !== 'string' ||
      !SHA256_PATTERN.test(value.markerSha256)
    ) {
      throw new PaidMediaVaultError('Paid media cleanup marker is invalid')
    }
    const operationId = requireOperationId(value.operationId)
    const base: CleanupMarkerBase = {
      schema: CLEANUP_MARKER_SCHEMA,
      operationId,
      cleanupId: value.cleanupId,
      tempRoot: this.parseCleanupRootIdentity(value.tempRoot),
      directoryName: value.directoryName,
      directory: this.parseCleanupIdentity(value.directory),
      fileName: 'asset.bin',
      file: this.parseCleanupIdentity(value.file),
      createdAt: Number(value.createdAt)
    }
    if (
      value.markerSha256 !== sha256(JSON.stringify(base)) ||
      basename(path) !== `${operationId}_${base.cleanupId}.json`
    ) {
      throw new PaidMediaVaultError('Paid media cleanup marker digest or filename is invalid')
    }
    return { ...base, markerSha256: value.markerSha256, path: resolve(path) }
  }

  private readCleanupMarker(path: string): CleanupMarkerDocument & { path: string } {
    return this.parseCleanupMarker(
      this.decodeEncrypted(
        this.readRegular(path, 64 * 1024, 'Paid media cleanup marker'),
        'Paid media cleanup marker'
      ),
      path
    )
  }

  private assertPersistedCleanupMarker(
    marker: CleanupMarkerDocument & { path: string }
  ): void {
    const persisted = this.readCleanupMarker(marker.path)
    if (persisted.markerSha256 !== marker.markerSha256) {
      throw new PaidMediaVaultError('Paid media cleanup marker changed')
    }
  }

  private validateControlledCleanupState(
    marker: CleanupMarkerDocument
  ): { directoryPath: string; filePath: string; directoryPresent: boolean; filePresent: boolean } {
    try {
      const tempRoot = canonicalPrivateTempRoot()
      if (
        !this.sameStableCleanupIdentity(
          this.cleanupRootIdentity(tempRoot),
          marker.tempRoot
        )
      ) {
        throw new PaidMediaVaultError('Paid media cleanup temp root identity changed')
      }
      const directoryPath = resolve(tempRoot, marker.directoryName)
      const filePath = resolve(directoryPath, marker.fileName)
      if (
        normalizedAbsolutePath(dirname(directoryPath)) !== normalizedAbsolutePath(tempRoot) ||
        basename(directoryPath) !== marker.directoryName ||
        basename(filePath) !== 'asset.bin'
      ) {
        throw new PaidMediaVaultError('Paid media cleanup marker path reconstruction failed')
      }
      if (!this.cleanupPathExists(directoryPath)) {
        return { directoryPath, filePath, directoryPresent: false, filePresent: false }
      }
      const directoryIdentity = this.cleanupPathIdentity(directoryPath, true)
      if (!this.sameStableCleanupIdentity(directoryIdentity, marker.directory)) {
        throw new PaidMediaVaultError('Paid media cleanup directory identity changed')
      }
      const entries = readdirSync(directoryPath, { withFileTypes: true })
      if (entries.length === 0) {
        return { directoryPath, filePath, directoryPresent: true, filePresent: false }
      }
      if (
        entries.length !== 1 ||
        entries[0]?.name !== 'asset.bin' ||
        !entries[0].isFile() ||
        entries[0].isSymbolicLink() ||
        !this.sameFullCleanupIdentity(directoryIdentity, marker.directory) ||
        !this.sameFullCleanupIdentity(this.cleanupPathIdentity(filePath, false), marker.file)
      ) {
        throw new PaidMediaVaultError('Paid media cleanup staging identity or closed set changed')
      }
      return { directoryPath, filePath, directoryPresent: true, filePresent: true }
    } catch (error) {
      if (error instanceof PaidMediaCleanupHoldError) throw error
      throw new PaidMediaCleanupHoldError('Paid media cleanup requires permanent review', {
        cause: error
      })
    }
  }

  private performControlledCleanup(marker: CleanupMarkerDocument): void {
    let state = this.validateControlledCleanupState(marker)
    if (state.filePresent) {
      this.assertMutationAllowed()
      ;(this.dependencies.cleanupIO?.unlinkStagedFile ?? unlinkSync)(state.filePath)
      state = this.validateControlledCleanupState(marker)
      if (state.filePresent) {
        throw new PaidMediaVaultError('Paid media cleanup staged file was not removed')
      }
    }
    if (state.directoryPresent) {
      this.assertMutationAllowed()
      ;(this.dependencies.cleanupIO?.removeEmptyStagingDirectory ?? rmdirSync)(
        state.directoryPath
      )
      state = this.validateControlledCleanupState(marker)
    }
    if (state.directoryPresent || state.filePresent) {
      throw new PaidMediaVaultError('Paid media cleanup staging was not removed')
    }
  }

  private removeCleanupMarker(marker: CleanupMarkerDocument & { path: string }): boolean {
    try {
      this.assertPersistedCleanupMarker(marker)
      this.assertMutationAllowed()
      ;(this.dependencies.cleanupIO?.unlinkMarker ?? unlinkSync)(marker.path)
      this.hardenedPaths.delete(resolve(marker.path))
      this.recordAuthorityDelete(marker.path)
      this.cancelCleanupRetry(marker)
      return true
    } catch (error) {
      this.dependencies.onCleanupError?.(error)
      return false
    }
  }

  private notifyCleanupRecovered(operationId: string): void {
    if (!this.cleanupRecoveredHandler) return
    void Promise.resolve(this.cleanupRecoveredHandler(operationId)).catch((error: unknown) => {
      this.dependencies.onCleanupError?.(error)
    })
  }

  private cleanupRetryKey(marker: CleanupMarkerDocument & { path: string }): string {
    return `${resolve(marker.path)}\0${marker.markerSha256}`
  }

  private cancelCleanupRetry(marker: CleanupMarkerDocument & { path: string }): void {
    const key = this.cleanupRetryKey(marker)
    const scheduled = this.cleanupRetries.get(key)
    if (!scheduled) return
    clearTimeout(scheduled.timer)
    this.cleanupRetries.delete(key)
  }

  private runCleanupSingleflight(
    marker: CleanupMarkerDocument & { path: string },
    action: () => Promise<boolean>
  ): Promise<boolean> {
    const key = this.cleanupRetryKey(marker)
    const existing = this.cleanupFlights.get(key)
    if (existing) return existing
    let flight!: Promise<boolean>
    flight = Promise.resolve()
      .then(action)
      .finally(() => {
        if (this.cleanupFlights.get(key) === flight) this.cleanupFlights.delete(key)
      })
    this.cleanupFlights.set(key, flight)
    return flight
  }

  private async convergeCleanupMarker(
    marker: CleanupMarkerDocument & { path: string }
  ): Promise<boolean> {
    if (!existsSync(marker.path)) return true
    const persisted = this.readCleanupMarker(marker.path)
    if (persisted.markerSha256 !== marker.markerSha256) {
      throw new PaidMediaCleanupHoldError('Paid media cleanup marker changed before retry')
    }
    this.performControlledCleanup(persisted)
    if (!existsSync(persisted.path)) return true
    return this.removeCleanupMarker(persisted)
  }

  private scheduleCleanupRetry(
    marker: CleanupMarkerDocument & { path: string },
    attempt = 0
  ): void {
    const key = this.cleanupRetryKey(marker)
    if (
      this.cleanupRetries.has(key) ||
      this.cleanupFlights.has(key) ||
      attempt > 6 ||
      !existsSync(marker.path)
    ) {
      return
    }
    const delay = Math.min(5 * 60_000, 30_000 * 2 ** attempt)
    const retry = setTimeout(() => {
      this.cleanupRetries.delete(key)
      // Another retry/startup reconciliation may already have converged. A
      // missing marker is success, never a reason to create a new Root txn.
      if (!existsSync(marker.path)) return
      const running = (async (): Promise<boolean> => {
        let recovered = false
        const action = async (): Promise<void> => {
          recovered = await this.runCleanupSingleflight(marker, () =>
            this.convergeCleanupMarker(marker)
          )
        }
        if (this.cleanupMutationRunner) {
          await this.cleanupMutationRunner(marker.operationId, action)
        } else {
          await action()
        }
        return recovered
      })()
      void running.then(
        (recovered) => {
          if (recovered) {
            this.notifyCleanupRecovered(marker.operationId)
          } else if (existsSync(marker.path)) {
            this.scheduleCleanupRetry(marker, attempt + 1)
          }
        },
        (error: unknown) => {
          if (!existsSync(marker.path)) return
          this.dependencies.onCleanupError?.(error)
          if (!(error instanceof PaidMediaCleanupHoldError)) {
            this.scheduleCleanupRetry(marker, attempt + 1)
          }
        }
      )
    }, delay)
    retry.unref()
    this.cleanupRetries.set(key, { timer: retry, attempt })
  }

  private async cleanupFetched(
    result: PaidMediaRemoteFetchResult,
    marker: (CleanupMarkerDocument & { path: string }) | null
  ): Promise<boolean> {
    if (!('filePath' in result)) return true
    if (!marker) throw new PaidMediaVaultError('Paid media cleanup marker is missing')
    try {
      const recovered = await this.runCleanupSingleflight(marker, () =>
        this.convergeCleanupMarker(marker)
      )
      if (recovered) return true
    } catch (error) {
      this.dependencies.onCleanupError?.(error)
      if (!(error instanceof PaidMediaCleanupHoldError)) this.scheduleCleanupRetry(marker)
      return false
    }
    this.scheduleCleanupRetry(marker)
    return false
  }

  async recoverPendingCleanup(): Promise<{ inspected: number; recovered: number; held: number }> {
    this.prepare()
    let inspected = 0
    let recovered = 0
    let held = 0
    for (const entry of readdirSync(this.cleanupPendingPath, { withFileTypes: true })) {
      inspected += 1
      if (!entry.isFile() || entry.isSymbolicLink()) {
        held += 1
        this.dependencies.onCleanupError?.(
          new PaidMediaCleanupHoldError('Paid media cleanup marker directory contains an unknown entry')
        )
        continue
      }
      const path = join(this.cleanupPendingPath, entry.name)
      let marker: CleanupMarkerDocument & { path: string }
      try {
        marker = this.readCleanupMarker(path)
      } catch (error) {
        if (!existsSync(path)) {
          recovered += 1
          continue
        }
        held += 1
        this.dependencies.onCleanupError?.(error)
        if (!(error instanceof PaidMediaCleanupHoldError)) {
          try {
            const retryMarker = this.readCleanupMarker(path)
            this.scheduleCleanupRetry(retryMarker)
          } catch {
            // An unreadable marker is a permanent hold, never a deletion candidate.
          }
        }
        continue
      }
      try {
        if (await this.runCleanupSingleflight(marker, () => this.convergeCleanupMarker(marker))) {
          recovered += 1
          continue
        }
      } catch (error) {
        this.dependencies.onCleanupError?.(error)
        if (error instanceof PaidMediaCleanupHoldError) {
          held += 1
          continue
        }
      }
      if (existsSync(marker.path)) {
        held += 1
        this.scheduleCleanupRetry(marker)
      } else {
        recovered += 1
      }
    }
    return { inspected, recovered, held }
  }

  hasPendingCleanupWork(): boolean {
    this.prepare()
    return readdirSync(this.cleanupPendingPath).length > 0
  }

  private hasPendingCleanup(operationId: string): boolean {
    this.prepare()
    const expectedOperationId = requireOperationId(operationId)
    for (const entry of readdirSync(this.cleanupPendingPath, { withFileTypes: true })) {
      if (!entry.isFile() || entry.isSymbolicLink()) return true
      try {
        if (
          this.readCleanupMarker(join(this.cleanupPendingPath, entry.name)).operationId ===
          expectedOperationId
        ) {
          return true
        }
      } catch {
        // An untrusted or corrupted marker is a global fail-closed hold. It must
        // never become an accidental cleanup-complete signal for any operation.
        return true
      }
    }
    return false
  }

  private samePathIdentity(
    left: HardenedPathIdentity | undefined,
    right: HardenedPathIdentity
  ): boolean {
    return (
      left?.directory === right.directory &&
      left.dev === right.dev &&
      left.ino === right.ino &&
      left.birthtimeMs === right.birthtimeMs
    )
  }

  private assertPathKind(info: Stats, directory: boolean, label: string): void {
    if (
      info.isSymbolicLink() ||
      (directory ? !info.isDirectory() : !info.isFile())
    ) {
      throw new PaidMediaVaultError(`${label} is redirected`)
    }
  }

  private hardenIfChanged(
    path: string,
    directory: boolean,
    observed = lstatSync(path)
  ): Stats {
    const key = resolve(path)
    this.assertPathKind(observed, directory, 'Paid media vault path')
    if (this.captureInspectionReadOnly) return observed
    const observedIdentity = this.pathIdentity(observed, directory)
    if (this.samePathIdentity(this.hardenedPaths.get(key), observedIdentity)) {
      return observed
    }

    this.dependencies.harden(path, directory)
    const hardened = lstatSync(path)
    this.assertPathKind(hardened, directory, 'Paid media vault path')
    this.hardenedPaths.set(key, this.pathIdentity(hardened, directory))
    return hardened
  }

  private ensureDirectory(path: string): void {
    if (!existsSync(path)) this.assertMutationAllowed()
    mkdirSync(path, { recursive: true })
    this.hardenIfChanged(path, true)
  }

  private authorityDirectories(): string[] {
    return [
      this.claimsPath,
      this.archivesPath,
      this.discoveriesPath,
      this.presentationsPath,
      this.assetValidationsPath,
      this.assetsPath,
      this.videoTasksPath,
      this.videoTerminalsPath,
      this.cleanupPendingPath,
      this.legacyImportsPath
    ]
  }

  private assertAuthorityDirectories(): void {
    if (!existsSync(this.root)) {
      throw new PaidMediaVaultError('Paid media vault authority root is missing')
    }
    this.hardenIfChanged(this.root, true)
    const expected = new Set(this.authorityDirectories().map((path) => basename(path)))
    const actual = readdirSync(this.root, { withFileTypes: true })
    if (
      actual.length !== expected.size ||
      actual.some(
        (entry) =>
          !expected.has(entry.name) ||
          !entry.isDirectory() ||
          entry.isSymbolicLink()
      )
    ) {
      throw new PaidMediaVaultError('Paid media vault authority directory set changed')
    }
    for (const path of this.authorityDirectories()) this.hardenIfChanged(path, true)
  }

  private prepare(): void {
    if (this.authorityStrict) {
      this.assertAuthorityDirectories()
      return
    }
    this.ensureDirectory(this.root)
    for (const path of this.authorityDirectories()) this.ensureDirectory(path)
  }

  private hashAuthorityFile(path: string): { byteLength: number; sha256: string } {
    const before = this.hardenIfChanged(path, false)
    if (!before.isFile() || before.isSymbolicLink() || before.size < 1) {
      throw new PaidMediaVaultError('Paid media vault authority file is invalid')
    }
    const handle = openSync(path, 'r')
    try {
      const pinned = fstatSync(handle)
      if (
        !pinned.isFile() ||
        pinned.dev !== before.dev ||
        pinned.ino !== before.ino ||
        pinned.birthtimeMs !== before.birthtimeMs ||
        pinned.mtimeMs !== before.mtimeMs ||
        pinned.ctimeMs !== before.ctimeMs ||
        pinned.size !== before.size
      ) {
        throw new PaidMediaVaultError('Paid media vault authority file changed before hashing')
      }
      const hash = createHash('sha256')
      const buffer = Buffer.allocUnsafe(1024 * 1024)
      let offset = 0
      while (offset < pinned.size) {
        const received = readSync(
          handle,
          buffer,
          0,
          Math.min(buffer.length, pinned.size - offset),
          offset
        )
        if (received < 1) {
          throw new PaidMediaVaultError('Paid media vault authority file is truncated')
        }
        hash.update(buffer.subarray(0, received))
        offset += received
      }
      const after = fstatSync(handle)
      if (
        after.dev !== pinned.dev ||
        after.ino !== pinned.ino ||
        after.birthtimeMs !== pinned.birthtimeMs ||
        after.mtimeMs !== pinned.mtimeMs ||
        after.ctimeMs !== pinned.ctimeMs ||
        after.size !== pinned.size
      ) {
        throw new PaidMediaVaultError('Paid media vault authority file changed while hashing')
      }
      return { byteLength: pinned.size, sha256: hash.digest('hex') }
    } finally {
      closeSync(handle)
    }
  }

  private authorityRelativeFile(path: string): string {
    const absolute = resolve(path)
    const relativePath = relative(this.root, absolute).replace(/\\/g, '/')
    if (
      !relativePath ||
      relativePath.startsWith('../') ||
      relativePath === '..' ||
      Buffer.byteLength(relativePath, 'utf8') > 4096
    ) {
      throw new PaidMediaVaultError('Paid media vault authority path is invalid')
    }
    return relativePath
  }

  private initialAuthorityState(vaultIdentity: string): string {
    return createHash('sha256')
      .update(AUTHORITY_INDEX_STATE_DOMAIN)
      .update(Buffer.from(vaultIdentity, 'hex'))
      .digest('hex')
  }

  private authorityEvidenceDigest(head: VaultAuthorityHead): string {
    return createHash('sha256')
      .update(AUTHORITY_EVIDENCE_DOMAIN)
      .update(JSON.stringify(head), 'utf8')
      .digest('hex')
  }

  private authorityEventState(base: VaultAuthorityEventBase): string {
    return createHash('sha256')
      .update(AUTHORITY_INDEX_STATE_DOMAIN)
      .update(JSON.stringify(base), 'utf8')
      .digest('hex')
  }

  private stageDescriptorDigest(descriptor: PaidMediaAssetDescriptor): string {
    return createHash('sha256')
      .update('nachuan.desktop.paid-media-stage-descriptor.v2\0', 'ascii')
      .update(
        JSON.stringify({
          byteLength: descriptor.byteLength,
          mediaType: descriptor.mediaType,
          sha256: descriptor.sha256,
          token: descriptor.token,
          validationReceiptSha256: descriptor.validationReceiptSha256
        }),
        'ascii'
      )
      .digest('hex')
  }

  private stageLeaseStateDigest(base: StageLeaseEventBase): string {
    return createHash('sha256')
      .update(STAGE_LEASE_STATE_DOMAIN)
      .update(JSON.stringify(base), 'utf8')
      .digest('hex')
  }

  private parseStageDecimal(value: unknown, label: string): string {
    if (
      typeof value !== 'string' ||
      !/^(?:0|[1-9][0-9]*)$/.test(value) ||
      value.length > 40
    ) {
      throw new PaidMediaVaultError(`${label} is invalid`)
    }
    return value
  }

  private parseStageIdentity(value: unknown, full: false): StageStableIdentity
  private parseStageIdentity(value: unknown, full: true): StageFullIdentity
  private parseStageIdentity(
    value: unknown,
    full: boolean
  ): StageStableIdentity | StageFullIdentity {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      throw new PaidMediaVaultError('Paid media stage identity is invalid')
    }
    const raw = value as Record<string, unknown>
    const stableKeys = ['pathSha256', 'dev', 'ino', 'birthtimeNs']
    if (
      !exactKeys(raw, full ? [...stableKeys, 'mtimeNs', 'ctimeNs', 'size'] : stableKeys) ||
      typeof raw.pathSha256 !== 'string' ||
      !SHA256_PATTERN.test(raw.pathSha256)
    ) {
      throw new PaidMediaVaultError('Paid media stage identity is invalid')
    }
    const stable: StageStableIdentity = {
      pathSha256: raw.pathSha256,
      dev: this.parseStageDecimal(raw.dev, 'Paid media stage device identity'),
      ino: this.parseStageDecimal(raw.ino, 'Paid media stage inode identity'),
      birthtimeNs: this.parseStageDecimal(
        raw.birthtimeNs,
        'Paid media stage birth identity'
      )
    }
    if (!full) return stable
    return {
      ...stable,
      mtimeNs: this.parseStageDecimal(raw.mtimeNs, 'Paid media stage mtime identity'),
      ctimeNs: this.parseStageDecimal(raw.ctimeNs, 'Paid media stage ctime identity'),
      size: this.parseStageDecimal(raw.size, 'Paid media stage size identity')
    }
  }

  private parseStageDescriptor(value: unknown): PaidMediaAssetDescriptor {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      throw new PaidMediaVaultError('Paid media stage descriptor is invalid')
    }
    const mediaType = (value as Record<string, unknown>).mediaType
    try {
      return parsePaidMediaAssetResult({
        schema: PAID_MEDIA_ASSET_RESULT_SCHEMA,
        kind:
          typeof mediaType === 'string' && mediaType.startsWith('video/')
            ? 'video'
            : 'image',
        created: 1,
        turnId: '1'.repeat(64),
        assets: [value]
      }).assets[0]!
    } catch (error) {
      throw new PaidMediaVaultError('Paid media stage descriptor is invalid', { cause: error })
    }
  }

  private parseStageLeaseEvent(value: unknown): StageLeaseEvent {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      throw new PaidMediaVaultError('Paid media stage lease event is invalid')
    }
    const raw = value as Record<string, unknown>
    if (
      !exactKeys(raw, [
        'schema',
        'leaseId',
        'leaseSequence',
        'previousLeaseStateDigest',
        'state',
        'operationId',
        'turnId',
        'resultSha256',
        'ordinal',
        'descriptor',
        'descriptorSha256',
        'generation',
        'tempRoot',
        'directoryName',
        'fileName',
        'directory',
        'file',
        'reasonCode',
        'createdAt',
        'updatedAt',
        'leaseStateDigest'
      ]) ||
      raw.schema !== STAGE_LEASE_EVENT_SCHEMA ||
      typeof raw.leaseId !== 'string' ||
      !SHA256_PATTERN.test(raw.leaseId) ||
      !Number.isSafeInteger(raw.leaseSequence) ||
      Number(raw.leaseSequence) < 1 ||
      typeof raw.previousLeaseStateDigest !== 'string' ||
      !SHA256_PATTERN.test(raw.previousLeaseStateDigest) ||
      ![
        'reserved',
        'opened',
        'aborted_cleanup_pending',
        'aborted_cleaned',
        'archived_cleanup_pending',
        'archived_cleaned',
        'held'
      ].includes(String(raw.state)) ||
      typeof raw.turnId !== 'string' ||
      !SHA256_PATTERN.test(raw.turnId) ||
      raw.turnId === ZERO_SHA256 ||
      typeof raw.resultSha256 !== 'string' ||
      !SHA256_PATTERN.test(raw.resultSha256) ||
      raw.resultSha256 === ZERO_SHA256 ||
      !Number.isSafeInteger(raw.ordinal) ||
      Number(raw.ordinal) < 0 ||
      Number(raw.ordinal) > 3 ||
      typeof raw.descriptorSha256 !== 'string' ||
      !SHA256_PATTERN.test(raw.descriptorSha256) ||
      !Number.isSafeInteger(raw.generation) ||
      Number(raw.generation) < 0 ||
      Number(raw.generation) > 1_000_000 ||
      raw.directoryName !== `${STAGE_DIRECTORY_PREFIX}${raw.leaseId}` ||
      typeof raw.directoryName !== 'string' ||
      !STAGE_DIRECTORY_PATTERN.test(raw.directoryName) ||
      raw.fileName !== STAGE_FILE_NAME ||
      !Number.isSafeInteger(raw.createdAt) ||
      Number(raw.createdAt) < 0 ||
      !Number.isSafeInteger(raw.updatedAt) ||
      Number(raw.updatedAt) < Number(raw.createdAt) ||
      typeof raw.leaseStateDigest !== 'string' ||
      !SHA256_PATTERN.test(raw.leaseStateDigest)
    ) {
      throw new PaidMediaVaultError('Paid media stage lease event is invalid')
    }
    const state = raw.state as PaidMediaStageLeaseState
    const reasonCode =
      raw.reasonCode === null
        ? null
        : typeof raw.reasonCode === 'string' && /^[a-z][a-z0-9_]{0,63}$/.test(raw.reasonCode)
          ? raw.reasonCode
          : undefined
    if (
      reasonCode === undefined ||
      ((state === 'reserved' || state === 'opened') && reasonCode !== null) ||
      ((state === 'aborted_cleanup_pending' ||
        state === 'aborted_cleaned' ||
        state === 'archived_cleanup_pending' ||
        state === 'archived_cleaned' ||
        state === 'held') &&
        reasonCode === null) ||
      (state === 'reserved' && (raw.directory !== null || raw.file !== null)) ||
      (state === 'opened' && (raw.directory === null || raw.file === null))
    ) {
      throw new PaidMediaVaultError('Paid media stage lease state payload is invalid')
    }
    const descriptor = this.parseStageDescriptor(raw.descriptor)
    if (this.stageDescriptorDigest(descriptor) !== raw.descriptorSha256) {
      throw new PaidMediaVaultError('Paid media stage descriptor digest does not match')
    }
    const base: StageLeaseEventBase = {
      schema: STAGE_LEASE_EVENT_SCHEMA,
      leaseId: raw.leaseId,
      leaseSequence: Number(raw.leaseSequence),
      previousLeaseStateDigest: raw.previousLeaseStateDigest,
      state,
      operationId: requireOperationId(raw.operationId),
      turnId: raw.turnId,
      resultSha256: raw.resultSha256,
      ordinal: Number(raw.ordinal),
      descriptor,
      descriptorSha256: raw.descriptorSha256,
      generation: Number(raw.generation) as StageLeaseEventBase['generation'],
      tempRoot: this.parseStageIdentity(raw.tempRoot, false),
      directoryName: raw.directoryName,
      fileName: STAGE_FILE_NAME,
      directory: raw.directory === null ? null : this.parseStageIdentity(raw.directory, true),
      file: raw.file === null ? null : this.parseStageIdentity(raw.file, true),
      reasonCode,
      createdAt: Number(raw.createdAt),
      updatedAt: Number(raw.updatedAt)
    }
    if (this.stageLeaseStateDigest(base) !== raw.leaseStateDigest) {
      throw new PaidMediaVaultError('Paid media stage lease event digest does not match')
    }
    return { ...base, leaseStateDigest: raw.leaseStateDigest }
  }

  private parseAuthorityHead(value: Record<string, unknown>): VaultAuthorityHead {
    if (
      !exactKeys(value, [
        'schema',
        'vaultIdentity',
        'sequence',
        'stateDigest',
        'journalByteLength',
        'entryCount',
        'totalBytes'
      ]) ||
      value.schema !== AUTHORITY_INDEX_SCHEMA ||
      typeof value.vaultIdentity !== 'string' ||
      !SHA256_PATTERN.test(value.vaultIdentity) ||
      !Number.isSafeInteger(value.sequence) ||
      Number(value.sequence) < 0 ||
      typeof value.stateDigest !== 'string' ||
      !SHA256_PATTERN.test(value.stateDigest) ||
      !Number.isSafeInteger(value.journalByteLength) ||
      Number(value.journalByteLength) < 0 ||
      Number(value.journalByteLength) > MAX_AUTHORITY_JOURNAL_BYTES ||
      !Number.isSafeInteger(value.entryCount) ||
      Number(value.entryCount) < 0 ||
      Number(value.entryCount) > MAX_AUTHORITY_EVIDENCE_ENTRIES ||
      !Number.isSafeInteger(value.totalBytes) ||
      Number(value.totalBytes) < 0
    ) {
      throw new PaidMediaVaultError('Paid media vault authority head is invalid')
    }
    return {
      schema: AUTHORITY_INDEX_SCHEMA,
      vaultIdentity: value.vaultIdentity,
      sequence: Number(value.sequence),
      stateDigest: value.stateDigest,
      journalByteLength: Number(value.journalByteLength),
      entryCount: Number(value.entryCount),
      totalBytes: Number(value.totalBytes)
    }
  }

  private parseAuthorityEvent(value: Record<string, unknown>): VaultAuthorityEvent {
    if (value.schema === AUTHORITY_STAGE_EVENT_SCHEMA) {
      if (
        !exactKeys(value, [
          'schema',
          'vaultIdentity',
          'sequence',
          'previousStateDigest',
          'action',
          'stage',
          'stateDigest'
        ]) ||
        typeof value.vaultIdentity !== 'string' ||
        !SHA256_PATTERN.test(value.vaultIdentity) ||
        !Number.isSafeInteger(value.sequence) ||
        Number(value.sequence) < 1 ||
        typeof value.previousStateDigest !== 'string' ||
        !SHA256_PATTERN.test(value.previousStateDigest) ||
        value.action !== 'stage_transition' ||
        typeof value.stateDigest !== 'string' ||
        !SHA256_PATTERN.test(value.stateDigest)
      ) {
        throw new PaidMediaVaultError('Paid media vault stage authority event is invalid')
      }
      const base: VaultAuthorityStageEventBase = {
        schema: AUTHORITY_STAGE_EVENT_SCHEMA,
        vaultIdentity: value.vaultIdentity,
        sequence: Number(value.sequence),
        previousStateDigest: value.previousStateDigest,
        action: 'stage_transition',
        stage: this.parseStageLeaseEvent(value.stage)
      }
      if (this.authorityEventState(base) !== value.stateDigest) {
        throw new PaidMediaVaultError('Paid media vault authority event digest does not match')
      }
      return { ...base, stateDigest: value.stateDigest }
    }
    if (
      !exactKeys(value, [
        'schema',
        'vaultIdentity',
        'sequence',
        'previousStateDigest',
        'action',
        'entry',
        'stateDigest'
      ]) ||
      value.schema !== AUTHORITY_EVENT_SCHEMA ||
      typeof value.vaultIdentity !== 'string' ||
      !SHA256_PATTERN.test(value.vaultIdentity) ||
      !Number.isSafeInteger(value.sequence) ||
      Number(value.sequence) < 1 ||
      typeof value.previousStateDigest !== 'string' ||
      !SHA256_PATTERN.test(value.previousStateDigest) ||
      (value.action !== 'create' && value.action !== 'delete') ||
      !value.entry ||
      typeof value.entry !== 'object' ||
      Array.isArray(value.entry) ||
      typeof value.stateDigest !== 'string' ||
      !SHA256_PATTERN.test(value.stateDigest)
    ) {
      throw new PaidMediaVaultError('Paid media vault authority event is invalid')
    }
    const rawEntry = value.entry as Record<string, unknown>
    if (
      !exactKeys(rawEntry, ['path', 'byteLength', 'sha256']) ||
      typeof rawEntry.path !== 'string' ||
      !rawEntry.path ||
      rawEntry.path.startsWith('../') ||
      Buffer.byteLength(rawEntry.path, 'utf8') > 4096 ||
      !Number.isSafeInteger(rawEntry.byteLength) ||
      Number(rawEntry.byteLength) < 1 ||
      typeof rawEntry.sha256 !== 'string' ||
      !SHA256_PATTERN.test(rawEntry.sha256)
    ) {
      throw new PaidMediaVaultError('Paid media vault authority event entry is invalid')
    }
    const base: VaultAuthorityFileEventBase = {
      schema: AUTHORITY_EVENT_SCHEMA,
      vaultIdentity: value.vaultIdentity,
      sequence: Number(value.sequence),
      previousStateDigest: value.previousStateDigest,
      action: value.action,
      entry: {
        path: rawEntry.path,
        byteLength: Number(rawEntry.byteLength),
        sha256: rawEntry.sha256
      }
    }
    if (this.authorityEventState(base) !== value.stateDigest) {
      throw new PaidMediaVaultError('Paid media vault authority event digest does not match')
    }
    return { ...base, stateDigest: value.stateDigest }
  }

  private encodeAuthorityEvent(event: VaultAuthorityEvent): Buffer {
    const payload = this.encodeEncrypted(event)
    if (payload.length < 1 || payload.length > MAX_AUTHORITY_EVENT_BYTES) {
      throw new PaidMediaVaultError('Paid media vault authority event exceeds its size limit')
    }
    const record = Buffer.allocUnsafe(4 + payload.length)
    record.writeUInt32BE(payload.length, 0)
    payload.copy(record, 4)
    return record
  }

  private writeAuthorityHead(head: VaultAuthorityHead): void {
    const bytes = this.encodeEncrypted(head)
    if (bytes.length < 1 || bytes.length > MAX_AUTHORITY_HEAD_BYTES) {
      throw new PaidMediaVaultError('Paid media vault authority head exceeds its size limit')
    }
    const parent = dirname(this.authorityHeadPath)
    this.hardenIfChanged(parent, true)
    const temporary = join(
      parent,
      `.${basename(this.authorityHeadPath)}.${process.pid}.${randomBytes(8).toString('hex')}.tmp`
    )
    let handle: number | null = null
    try {
      handle = openSync(temporary, 'wx', 0o600)
      writeFileSync(handle, bytes)
      fsyncSync(handle)
      closeSync(handle)
      handle = null
      this.hardenIfChanged(temporary, false)
      renameSync(temporary, this.authorityHeadPath)
      this.hardenedPaths.delete(resolve(temporary))
      this.hardenIfChanged(this.authorityHeadPath, false)
    } catch (error) {
      if (handle !== null) closeSync(handle)
      try {
        unlinkSync(temporary)
      } catch {
        // The temporary head may already have been atomically published.
      }
      this.hardenedPaths.delete(resolve(temporary))
      throw new PaidMediaVaultError('Paid media vault authority head could not be committed', {
        cause: error
      })
    }
  }

  private writeAuthorityJournalNew(bytes: Buffer): void {
    if (bytes.length > MAX_AUTHORITY_JOURNAL_BYTES) {
      throw new PaidMediaVaultError('Paid media vault authority journal is full')
    }
    const handle = openSync(this.authorityJournalPath, 'wx', 0o600)
    try {
      if (bytes.length > 0) writeFileSync(handle, bytes)
      fsyncSync(handle)
    } finally {
      closeSync(handle)
    }
    this.hardenIfChanged(this.authorityJournalPath, false)
  }

  private readAuthorityJournalPrefix(byteLength: number): {
    bytes: Buffer
    info: Stats
  } {
    const before = this.hardenIfChanged(this.authorityJournalPath, false)
    if (
      !before.isFile() ||
      before.isSymbolicLink() ||
      byteLength < 0 ||
      byteLength > before.size ||
      before.size > MAX_AUTHORITY_JOURNAL_BYTES
    ) {
      throw new PaidMediaVaultError('Paid media vault authority journal is invalid')
    }
    const handle = openSync(this.authorityJournalPath, 'r')
    try {
      const pinned = fstatSync(handle)
      if (
        pinned.dev !== before.dev ||
        pinned.ino !== before.ino ||
        pinned.birthtimeMs !== before.birthtimeMs ||
        pinned.mtimeMs !== before.mtimeMs ||
        pinned.ctimeMs !== before.ctimeMs ||
        pinned.size !== before.size
      ) {
        throw new PaidMediaVaultError('Paid media vault authority journal changed before reading')
      }
      const bytes = Buffer.allocUnsafe(byteLength)
      let offset = 0
      while (offset < byteLength) {
        const received = readSync(handle, bytes, offset, byteLength - offset, offset)
        if (received < 1) {
          throw new PaidMediaVaultError('Paid media vault authority journal is truncated')
        }
        offset += received
      }
      const after = fstatSync(handle)
      if (
        after.dev !== pinned.dev ||
        after.ino !== pinned.ino ||
        after.birthtimeMs !== pinned.birthtimeMs ||
        after.mtimeMs !== pinned.mtimeMs ||
        after.ctimeMs !== pinned.ctimeMs ||
        after.size !== pinned.size
      ) {
        throw new PaidMediaVaultError('Paid media vault authority journal changed while reading')
      }
      return { bytes, info: after }
    } finally {
      closeSync(handle)
    }
  }

  private stageBindingKey(stage: Pick<StageLeaseEvent, 'operationId' | 'turnId' | 'ordinal'>): string {
    return `${stage.operationId}\0${stage.turnId}\0${String(stage.ordinal)}`
  }

  private stageLeafKey(
    stage: Pick<StageLeaseEvent, 'tempRoot' | 'directoryName' | 'fileName'>
  ): string {
    return `${stage.tempRoot.pathSha256}\0${stage.directoryName}\0${stage.fileName}`
  }

  private computeStageLeaseId(input: {
    vaultIdentity: string
    operationId: string
    turnId: string
    resultSha256: string
    ordinal: number
    descriptorSha256: string
  }): string {
    return createHash('sha256')
      .update(STAGE_LEASE_ID_DOMAIN)
      .update(Buffer.from(input.vaultIdentity, 'hex'))
      .update(input.operationId, 'ascii')
      .update('\0', 'ascii')
      .update(input.turnId, 'ascii')
      .update(Buffer.from(input.resultSha256, 'hex'))
      .update(String(input.ordinal), 'ascii')
      .update(Buffer.from(input.descriptorSha256, 'hex'))
      .update('0', 'ascii')
      .digest('hex')
  }

  private sameStageStableIdentity(
    left: StageStableIdentity,
    right: StageStableIdentity
  ): boolean {
    return (
      left.pathSha256 === right.pathSha256 &&
      left.dev === right.dev &&
      left.ino === right.ino &&
      left.birthtimeNs === right.birthtimeNs
    )
  }

  private assertStageTransitionIdentityContinuity(
    previous: StageLeaseEvent,
    next: StageLeaseEvent
  ): void {
    if (
      (previous.directory !== null &&
        next.directory !== null &&
        !this.sameStageStableIdentity(previous.directory, next.directory)) ||
      (previous.file !== null &&
        next.file !== null &&
        !this.sameStageStableIdentity(previous.file, next.file))
    ) {
      throw new PaidMediaVaultError('Paid media stage lease identity changed across transition')
    }
  }

  private applyStageTransition(
    vaultIdentity: string,
    stage: StageLeaseEvent,
    indexes: {
      entries: Map<string, VaultAuthorityEntry>
      stageLeases: Map<string, StageLeaseEvent>
      activeStageLeases: Map<string, StageLeaseEvent>
      stageBindingIndex: Map<string, string>
      stageLeafIndex: Map<string, string>
      stageOperationIndex: Map<string, Set<string>>
    }
  ): void {
    const expectedLeaseId = this.computeStageLeaseId({
      vaultIdentity,
      operationId: stage.operationId,
      turnId: stage.turnId,
      resultSha256: stage.resultSha256,
      ordinal: stage.ordinal,
      descriptorSha256: stage.descriptorSha256
    })
    if (stage.leaseId !== expectedLeaseId) {
      throw new PaidMediaVaultError('Paid media stage lease id does not match its binding')
    }
    const bindingKey = this.stageBindingKey(stage)
    const leafKey = this.stageLeafKey(stage)
    const previous = indexes.stageLeases.get(stage.leaseId)
    if (!previous) {
      if (
        stage.state !== 'reserved' ||
        stage.generation !== 0 ||
        stage.leaseSequence !== 1 ||
        stage.previousLeaseStateDigest !== ZERO_SHA256 ||
        indexes.stageLeases.size >= MAX_STAGE_LEASES ||
        indexes.activeStageLeases.size >= MAX_ACTIVE_STAGE_LEASES ||
        indexes.stageBindingIndex.has(bindingKey) ||
        indexes.stageLeafIndex.has(leafKey)
      ) {
        throw new PaidMediaVaultError('Paid media stage lease reservation conflicts')
      }
      indexes.stageLeases.set(stage.leaseId, stage)
      indexes.activeStageLeases.set(stage.leaseId, stage)
      indexes.stageBindingIndex.set(bindingKey, stage.leaseId)
      indexes.stageLeafIndex.set(leafKey, stage.leaseId)
      const operationLeases = new Set(indexes.stageOperationIndex.get(stage.operationId) ?? [])
      operationLeases.add(stage.leaseId)
      indexes.stageOperationIndex.set(stage.operationId, operationLeases)
      return
    }
    const immutablePrevious = {
      leaseId: previous.leaseId,
      operationId: previous.operationId,
      turnId: previous.turnId,
      resultSha256: previous.resultSha256,
      ordinal: previous.ordinal,
      descriptor: previous.descriptor,
      descriptorSha256: previous.descriptorSha256,
      tempRoot: previous.tempRoot,
      directoryName: previous.directoryName,
      fileName: previous.fileName,
      createdAt: previous.createdAt
    }
    const immutableNext = {
      leaseId: stage.leaseId,
      operationId: stage.operationId,
      turnId: stage.turnId,
      resultSha256: stage.resultSha256,
      ordinal: stage.ordinal,
      descriptor: stage.descriptor,
      descriptorSha256: stage.descriptorSha256,
      tempRoot: stage.tempRoot,
      directoryName: stage.directoryName,
      fileName: stage.fileName,
      createdAt: stage.createdAt
    }
    const allowed =
      (previous.state === 'reserved' &&
        ['opened', 'aborted_cleanup_pending', 'held'].includes(stage.state)) ||
      (previous.state === 'opened' &&
        ['opened', 'aborted_cleanup_pending', 'archived_cleanup_pending', 'held'].includes(
          stage.state
        )) ||
      (previous.state === 'aborted_cleanup_pending' &&
        ['aborted_cleaned', 'held'].includes(stage.state)) ||
      (previous.state === 'aborted_cleaned' && stage.state === 'reserved') ||
      (previous.state === 'archived_cleanup_pending' &&
        ['archived_cleaned', 'held'].includes(stage.state))
    const generationIsValid =
      (previous.state === 'opened' && stage.state === 'opened') ||
      (previous.state === 'aborted_cleaned' && stage.state === 'reserved')
        ? stage.generation === previous.generation + 1
        : stage.generation === previous.generation
    if (
      !allowed ||
      !generationIsValid ||
      (previous.state === 'aborted_cleaned' &&
        stage.state === 'reserved' &&
        indexes.activeStageLeases.size >= MAX_ACTIVE_STAGE_LEASES) ||
      stage.leaseSequence !== previous.leaseSequence + 1 ||
      stage.previousLeaseStateDigest !== previous.leaseStateDigest ||
      stage.updatedAt < previous.updatedAt ||
      JSON.stringify(immutableNext) !== JSON.stringify(immutablePrevious) ||
      indexes.stageBindingIndex.get(bindingKey) !== stage.leaseId ||
      indexes.stageLeafIndex.get(leafKey) !== stage.leaseId ||
      !indexes.stageOperationIndex.get(stage.operationId)?.has(stage.leaseId) ||
      (['archived_cleanup_pending', 'archived_cleaned'].includes(stage.state) &&
        !indexes.entries.has(`archives/${stage.operationId}.json`))
    ) {
      throw new PaidMediaVaultError('Paid media stage lease transition is illegal')
    }
    this.assertStageTransitionIdentityContinuity(previous, stage)
    indexes.stageLeases.set(stage.leaseId, stage)
    if (stage.state === 'aborted_cleaned' || stage.state === 'archived_cleaned') {
      indexes.activeStageLeases.delete(stage.leaseId)
    }
    else indexes.activeStageLeases.set(stage.leaseId, stage)
  }

  private cloneAuthorityIndexes(
    source: VaultAuthorityMutableIndexes
  ): VaultAuthorityMutableIndexes {
    return {
      entries: new Map(source.entries),
      stageLeases: new Map(source.stageLeases),
      activeStageLeases: new Map(source.activeStageLeases),
      stageBindingIndex: new Map(source.stageBindingIndex),
      stageLeafIndex: new Map(source.stageLeafIndex),
      stageOperationIndex: new Map(
        [...source.stageOperationIndex].map(([operationId, leaseIds]) => [
          operationId,
          new Set(leaseIds)
        ])
      )
    }
  }

  private applyAuthorityEvent(
    vaultIdentity: string,
    event: VaultAuthorityEvent,
    indexes: VaultAuthorityMutableIndexes,
    totalBytes: number
  ): number {
    if (event.action === 'stage_transition') {
      this.applyStageTransition(vaultIdentity, event.stage, indexes)
      return totalBytes
    }
    const previous = indexes.entries.get(event.entry.path)
    if (event.action === 'create') {
      if (
        previous ||
        indexes.entries.size >= MAX_AUTHORITY_EVIDENCE_ENTRIES ||
        !Number.isSafeInteger(totalBytes + event.entry.byteLength)
      ) {
        throw new PaidMediaVaultError('Paid media vault authority create conflicts')
      }
      indexes.entries.set(event.entry.path, event.entry)
      return totalBytes + event.entry.byteLength
    }
    if (!previous || JSON.stringify(previous) !== JSON.stringify(event.entry)) {
      throw new PaidMediaVaultError('Paid media vault authority delete conflicts')
    }
    indexes.entries.delete(event.entry.path)
    const nextTotalBytes = totalBytes - event.entry.byteLength
    if (!Number.isSafeInteger(nextTotalBytes) || nextTotalBytes < 0) {
      throw new PaidMediaVaultError('Paid media vault authority byte total is invalid')
    }
    return nextTotalBytes
  }

  private replayAuthorityPrefix(
    head: VaultAuthorityHead,
    journal: { bytes: Buffer; info: Stats }
  ): VaultAuthorityIndexCache {
    if (journal.bytes.length !== head.journalByteLength) {
      throw new PaidMediaVaultError('Paid media vault authority prefix length is invalid')
    }
    const indexes: VaultAuthorityMutableIndexes = {
      entries: new Map<string, VaultAuthorityEntry>(),
      stageLeases: new Map<string, StageLeaseEvent>(),
      activeStageLeases: new Map<string, StageLeaseEvent>(),
      stageBindingIndex: new Map<string, string>(),
      stageLeafIndex: new Map<string, string>(),
      stageOperationIndex: new Map<string, Set<string>>()
    }
    this.dependencies.onAuthorityJournalReplay?.()
    let sequence = 0
    let stateDigest = this.initialAuthorityState(head.vaultIdentity)
    let offset = 0
    let totalBytes = 0
    while (offset < journal.bytes.length) {
      if (offset + 4 > journal.bytes.length) {
        throw new PaidMediaVaultError('Paid media vault authority journal record is truncated')
      }
      const length = journal.bytes.readUInt32BE(offset)
      offset += 4
      if (
        length < 1 ||
        length > MAX_AUTHORITY_EVENT_BYTES ||
        offset + length > journal.bytes.length
      ) {
        throw new PaidMediaVaultError('Paid media vault authority journal record is invalid')
      }
      const event = this.parseAuthorityEvent(
        this.decodeEncrypted(
          journal.bytes.subarray(offset, offset + length),
          'Paid media vault authority event'
        )
      )
      offset += length
      if (
        event.vaultIdentity !== head.vaultIdentity ||
        event.sequence !== sequence + 1 ||
        event.previousStateDigest !== stateDigest
      ) {
        throw new PaidMediaVaultError('Paid media vault authority event chain is invalid')
      }
      totalBytes = this.applyAuthorityEvent(
        head.vaultIdentity,
        event,
        indexes,
        totalBytes
      )
      sequence = event.sequence
      stateDigest = event.stateDigest
    }
    if (
      offset !== head.journalByteLength ||
      sequence !== head.sequence ||
      stateDigest !== head.stateDigest ||
      indexes.entries.size !== head.entryCount ||
      totalBytes !== head.totalBytes
    ) {
      throw new PaidMediaVaultError('Paid media vault authority head does not match its journal')
    }
    return {
      head,
      ...indexes,
      journalIdentity: this.pathIdentity(journal.info, false),
      journalMtimeMs: journal.info.mtimeMs,
      journalCtimeMs: journal.info.ctimeMs,
      journalSize: journal.info.size
    }
  }

  private loadAuthorityIndex(): VaultAuthorityIndexCache {
    if (this.authorityIndexPoisoned) {
      throw new PaidMediaVaultError('Paid media vault authority index is poisoned')
    }
    if (!existsSync(this.authorityHeadPath) || !existsSync(this.authorityJournalPath)) {
      throw new PaidMediaVaultError('Paid media vault authority index is missing')
    }
    const head = this.parseAuthorityHead(
      this.decodeEncrypted(
        this.readRegular(
          this.authorityHeadPath,
          MAX_AUTHORITY_HEAD_BYTES,
          'Paid media vault authority head'
        ),
        'Paid media vault authority head'
      )
    )
    const journalInfo = lstatSync(this.authorityJournalPath)
    if (journalInfo.size !== head.journalByteLength) {
      throw new PaidMediaVaultError('Paid media vault authority journal has an uncommitted tail')
    }
    const cached = this.authorityIndexCache
    if (
      cached &&
      JSON.stringify(cached.head) === JSON.stringify(head) &&
      cached.journalIdentity.dev === journalInfo.dev &&
      cached.journalIdentity.ino === journalInfo.ino &&
      cached.journalIdentity.birthtimeMs === journalInfo.birthtimeMs &&
      cached.journalMtimeMs === journalInfo.mtimeMs &&
      cached.journalCtimeMs === journalInfo.ctimeMs &&
      cached.journalSize === journalInfo.size
    ) {
      return cached
    }
    const journal = this.readAuthorityJournalPrefix(head.journalByteLength)
    const cache = this.replayAuthorityPrefix(head, journal)
    this.authorityIndexCache = cache
    return cache
  }

  private readAuthorityHeadForRecovery(): VaultAuthorityHead {
    if (!existsSync(this.authorityHeadPath) || !existsSync(this.authorityJournalPath)) {
      throw new PaidMediaVaultError('Paid media vault authority index is missing')
    }
    return this.parseAuthorityHead(
      this.decodeEncrypted(
        this.readRegular(
          this.authorityHeadPath,
          MAX_AUTHORITY_HEAD_BYTES,
          'Paid media vault authority head'
        ),
        'Paid media vault authority head'
      )
    )
  }

  private readCommittedAuthorityPrefixForRecovery(): {
    head: VaultAuthorityHead
    index: VaultAuthorityIndexCache
    journalBytes: Buffer
    tailBytes: Buffer
  } {
    const head = this.readAuthorityHeadForRecovery()
    const journalInfo = lstatSync(this.authorityJournalPath)
    if (
      !journalInfo.isFile() ||
      journalInfo.isSymbolicLink() ||
      journalInfo.size < head.journalByteLength ||
      journalInfo.size > MAX_AUTHORITY_JOURNAL_BYTES
    ) {
      throw new PaidMediaVaultError('Paid media vault committed authority prefix is unavailable')
    }
    const journal = this.readAuthorityJournalPrefix(journalInfo.size)
    const confirmedHead = this.readAuthorityHeadForRecovery()
    if (JSON.stringify(confirmedHead) !== JSON.stringify(head)) {
      throw new PaidMediaVaultError(
        'Paid media vault authority head changed while proving its committed prefix'
      )
    }
    const index = this.replayAuthorityPrefix(head, {
      bytes: journal.bytes.subarray(0, head.journalByteLength),
      info: journal.info
    })
    return {
      head,
      index,
      journalBytes: journal.bytes,
      tailBytes: journal.bytes.subarray(head.journalByteLength)
    }
  }

  private analyzeSingleAuthorityTail(
    committed: ReturnType<PaidMediaVault['readCommittedAuthorityPrefixForRecovery']>
  ): {
    event: VaultAuthorityEvent
    indexes: VaultAuthorityMutableIndexes
    nextHead: VaultAuthorityHead
  } {
    const tail = committed.tailBytes
    if (tail.length === 0) {
      throw new PaidMediaVaultError('Paid media vault authority tail is already committed')
    }
    if (tail.length < 4) {
      throw new PaidMediaVaultError('Paid media vault authority tail record is partial')
    }
    const length = tail.readUInt32BE(0)
    if (
      length < 1 ||
      length > MAX_AUTHORITY_EVENT_BYTES ||
      length + 4 !== tail.length
    ) {
      throw new PaidMediaVaultError(
        'Paid media vault authority recovery requires exactly one complete tail event'
      )
    }
    const event = this.parseAuthorityEvent(
      this.decodeEncrypted(
        tail.subarray(4),
        'Paid media vault authority recovery event'
      )
    )
    if (
      event.vaultIdentity !== committed.head.vaultIdentity ||
      event.sequence !== committed.head.sequence + 1 ||
      event.previousStateDigest !== committed.head.stateDigest
    ) {
      throw new PaidMediaVaultError('Paid media vault authority recovery chain is invalid')
    }
    const indexes = this.cloneAuthorityIndexes(committed.index)
    const totalBytes = this.applyAuthorityEvent(
      committed.head.vaultIdentity,
      event,
      indexes,
      committed.head.totalBytes
    )
    const nextHead: VaultAuthorityHead = {
      schema: AUTHORITY_INDEX_SCHEMA,
      vaultIdentity: committed.head.vaultIdentity,
      sequence: event.sequence,
      stateDigest: event.stateDigest,
      journalByteLength: committed.journalBytes.length,
      entryCount: indexes.entries.size,
      totalBytes
    }
    return { event, indexes, nextHead }
  }

  private normalizeAuthorityTailRecoveryInput(
    input: PaidMediaVaultAuthorityTailRecoveryInput
  ): PaidMediaVaultAuthorityTailRecoveryInput {
    if (
      !input ||
      typeof input !== 'object' ||
      Array.isArray(input) ||
      !exactKeys(input as unknown as Record<string, unknown>, [
        'operationId',
        'committedVaultStateDigest',
        'boundary'
      ]) ||
      typeof input.committedVaultStateDigest !== 'string' ||
      !SHA256_PATTERN.test(input.committedVaultStateDigest) ||
      !input.boundary ||
      typeof input.boundary !== 'object' ||
      Array.isArray(input.boundary)
    ) {
      throw new PaidMediaVaultError('Paid media vault authority tail recovery input is invalid')
    }
    const operationId = requireOperationId(input.operationId)
    const boundary = input.boundary
    if (boundary.kind === 'file_event') {
      if (
        !exactKeys(boundary as unknown as Record<string, unknown>, [
          'kind',
          'action',
          'relativePath',
          'byteLength',
          'sha256'
        ]) ||
        (boundary.action !== 'create' && boundary.action !== 'delete') ||
        typeof boundary.relativePath !== 'string' ||
        !boundary.relativePath ||
        !Number.isSafeInteger(boundary.byteLength) ||
        boundary.byteLength < 1 ||
        typeof boundary.sha256 !== 'string' ||
        !SHA256_PATTERN.test(boundary.sha256)
      ) {
        throw new PaidMediaVaultError(
          'Paid media vault authority file recovery boundary is invalid'
        )
      }
      return {
        operationId,
        committedVaultStateDigest: input.committedVaultStateDigest,
        boundary: {
          kind: 'file_event',
          action: boundary.action,
          relativePath: boundary.relativePath,
          byteLength: boundary.byteLength,
          sha256: boundary.sha256
        }
      }
    }
    if (boundary.kind === 'stage_transition') {
      if (
        !exactKeys(boundary as unknown as Record<string, unknown>, [
          'kind',
          'leaseId',
          'leaseSequence',
          'state',
          'leaseStateDigest'
        ]) ||
        typeof boundary.leaseId !== 'string' ||
        !SHA256_PATTERN.test(boundary.leaseId) ||
        !Number.isSafeInteger(boundary.leaseSequence) ||
        boundary.leaseSequence < 1 ||
        ![
          'reserved',
          'opened',
          'aborted_cleanup_pending',
          'aborted_cleaned',
          'archived_cleanup_pending',
          'archived_cleaned',
          'held'
        ].includes(boundary.state) ||
        typeof boundary.leaseStateDigest !== 'string' ||
        !SHA256_PATTERN.test(boundary.leaseStateDigest)
      ) {
        throw new PaidMediaVaultError(
          'Paid media vault authority stage recovery boundary is invalid'
        )
      }
      return {
        operationId,
        committedVaultStateDigest: input.committedVaultStateDigest,
        boundary: {
          kind: 'stage_transition',
          leaseId: boundary.leaseId,
          leaseSequence: boundary.leaseSequence,
          state: boundary.state,
          leaseStateDigest: boundary.leaseStateDigest
        }
      }
    }
    throw new PaidMediaVaultError('Paid media vault authority recovery boundary is closed')
  }

  private authorityRecoveryFilePath(
    relativePath: string,
    operationId: string,
    action: 'create' | 'delete'
  ): string {
    const segments = relativePath.split('/')
    if (
      segments.some((segment) => !segment || segment === '.' || segment === '..') ||
      relativePath.includes('\\')
    ) {
      throw new PaidMediaVaultError('Paid media vault authority recovery path is invalid')
    }
    const absolute = resolve(this.root, ...segments)
    const allowedParent = this.authorityDirectories().some(
      (directory) =>
        normalizedAbsolutePath(directory) === normalizedAbsolutePath(dirname(absolute))
    )
    const exactCreatePaths = new Set([
      `claims/${operationId}.json`,
      `claims/${operationId}.asset-v2-dispatch.json`,
      `claims/${operationId}.asset-ack-intent.json`,
      `claims/${operationId}.asset-ack-completion.json`,
      `claims/${operationId}.asset-capacity-release.json`,
      `archives/${operationId}.json`
    ])
    const fileName = basename(absolute)
    const discoveryBound =
      dirname(relativePath).replace(/\\/g, '/') === 'discoveries' &&
      fileName.endsWith(`_${operationId}.json`) &&
      /^\d{16}_/.test(fileName)
    const cleanupBound =
      dirname(relativePath).replace(/\\/g, '/') === 'cleanup-pending' &&
      fileName.startsWith(`${operationId}_`) &&
      /^[0-9a-f]{32}\.json$/.test(fileName.slice(operationId.length + 1))
    const operationBound =
      (action === 'create' &&
        (exactCreatePaths.has(relativePath) || discoveryBound || cleanupBound)) ||
      (action === 'delete' && cleanupBound)
    if (
      !allowedParent ||
      this.authorityRelativeFile(absolute) !== relativePath ||
      !operationBound
    ) {
      throw new PaidMediaVaultError(
        'Paid media vault authority recovery event is not bound to its operation'
      )
    }
    return absolute
  }

  private assertAuthorityRecoveryBoundary(
    input: PaidMediaVaultAuthorityTailRecoveryInput,
    event: VaultAuthorityEvent
  ): void {
    if (event.action === 'stage_transition') {
      const expected = {
        kind: 'stage_transition' as const,
        leaseId: event.stage.leaseId,
        leaseSequence: event.stage.leaseSequence,
        state: event.stage.state,
        leaseStateDigest: event.stage.leaseStateDigest
      }
      if (
        input.operationId !== event.stage.operationId ||
        JSON.stringify(input.boundary) !== JSON.stringify(expected)
      ) {
        throw new PaidMediaVaultError(
          'Paid media vault authority stage recovery boundary does not match'
        )
      }
      return
    }
    const expected = {
      kind: 'file_event' as const,
      action: event.action,
      relativePath: event.entry.path,
      byteLength: event.entry.byteLength,
      sha256: event.entry.sha256
    }
    if (JSON.stringify(input.boundary) !== JSON.stringify(expected)) {
      throw new PaidMediaVaultError(
        'Paid media vault authority file recovery boundary does not match'
      )
    }
    this.authorityRecoveryFilePath(event.entry.path, input.operationId, event.action)
  }

  private assertAuthorityRecoveryPostcondition(
    input: PaidMediaVaultAuthorityTailRecoveryInput,
    event: VaultAuthorityEvent
  ): void {
    if (event.action !== 'stage_transition') {
      const path = this.authorityRecoveryFilePath(
        event.entry.path,
        input.operationId,
        event.action
      )
      if (event.action === 'delete') {
        if (existsSync(path)) {
          throw new PaidMediaVaultError(
            'Paid media vault authority delete recovery postcondition does not match'
          )
        }
        return
      }
      const actual = this.hashAuthorityFile(path)
      if (JSON.stringify(actual) !== JSON.stringify({
        byteLength: event.entry.byteLength,
        sha256: event.entry.sha256
      })) {
        throw new PaidMediaVaultError(
          'Paid media vault authority create recovery postcondition does not match'
        )
      }
      return
    }
    const inspection = this.inspectStageLeaf(event.stage)
    const requiresAbsent = [
      'reserved',
      'aborted_cleaned',
      'archived_cleaned'
    ].includes(event.stage.state)
    const requiresExact = [
      'opened',
      'aborted_cleanup_pending',
      'archived_cleanup_pending'
    ].includes(event.stage.state)
    // `held` is itself the conservative/manual-only postcondition; accepting it
    // cannot authorize cleanup, reopening, outbound use, or capacity release.
    if (
      (requiresAbsent && inspection.kind !== 'absent') ||
      (requiresExact && inspection.kind !== 'exact')
    ) {
      throw new PaidMediaVaultError(
        'Paid media vault authority stage recovery postcondition does not match'
      )
    }
  }

  private appendAuthorityEvent(
    action: 'create' | 'delete',
    entry: VaultAuthorityEntry
  ): void {
    const current = this.loadAuthorityIndex()
    const previous = current.entries.get(entry.path)
    if (action === 'create' ? previous !== undefined : JSON.stringify(previous) !== JSON.stringify(entry)) {
      throw new PaidMediaVaultError(`Paid media vault authority ${action} conflicts`)
    }
    if (action === 'create' && current.entries.size >= MAX_AUTHORITY_EVIDENCE_ENTRIES) {
      throw new PaidMediaVaultError('Paid media vault authority index is full')
    }
    const base: VaultAuthorityFileEventBase = {
      schema: AUTHORITY_EVENT_SCHEMA,
      vaultIdentity: current.head.vaultIdentity,
      sequence: current.head.sequence + 1,
      previousStateDigest: current.head.stateDigest,
      action,
      entry
    }
    const event: VaultAuthorityFileEvent = {
      ...base,
      stateDigest: this.authorityEventState(base)
    }
    const record = this.encodeAuthorityEvent(event)
    if (current.head.journalByteLength + record.length > MAX_AUTHORITY_JOURNAL_BYTES) {
      throw new PaidMediaVaultError('Paid media vault authority journal is full')
    }
    try {
      const handle = openSync(this.authorityJournalPath, 'a', 0o600)
      try {
        writeFileSync(handle, record)
        fsyncSync(handle)
      } finally {
        closeSync(handle)
      }
      this.hardenIfChanged(this.authorityJournalPath, false)
      const nextHead: VaultAuthorityHead = {
        schema: AUTHORITY_INDEX_SCHEMA,
        vaultIdentity: current.head.vaultIdentity,
        sequence: event.sequence,
        stateDigest: event.stateDigest,
        journalByteLength: current.head.journalByteLength + record.length,
        entryCount: current.head.entryCount + (action === 'create' ? 1 : -1),
        totalBytes:
          current.head.totalBytes +
          (action === 'create' ? entry.byteLength : -entry.byteLength)
      }
      this.dependencies.beforeAuthorityHeadCommit?.()
      this.writeAuthorityHead(nextHead)
      const nextEntries = new Map(current.entries)
      if (action === 'create') nextEntries.set(entry.path, entry)
      else nextEntries.delete(entry.path)
      const journalInfo = lstatSync(this.authorityJournalPath)
      if (journalInfo.size !== nextHead.journalByteLength) {
        throw new PaidMediaVaultError('Paid media vault authority journal commit is incomplete')
      }
      this.authorityIndexCache = {
        head: nextHead,
        entries: nextEntries,
        stageLeases: current.stageLeases,
        activeStageLeases: current.activeStageLeases,
        stageBindingIndex: current.stageBindingIndex,
        stageLeafIndex: current.stageLeafIndex,
        stageOperationIndex: current.stageOperationIndex,
        journalIdentity: this.pathIdentity(journalInfo, false),
        journalMtimeMs: journalInfo.mtimeMs,
        journalCtimeMs: journalInfo.ctimeMs,
        journalSize: journalInfo.size
      }
    } catch (error) {
      this.authorityIndexPoisoned = true
      throw error
    }
  }

  private appendStageAuthorityEvent(stage: StageLeaseEvent): void {
    const current = this.loadAuthorityIndex()
    const { leaseStateDigest, ...stageBase } = stage
    if (this.stageLeaseStateDigest(stageBase) !== leaseStateDigest) {
      throw new PaidMediaVaultError('Paid media stage lease event digest does not match')
    }
    const stageLeases = new Map(current.stageLeases)
    const activeStageLeases = new Map(current.activeStageLeases)
    const stageBindingIndex = new Map(current.stageBindingIndex)
    const stageLeafIndex = new Map(current.stageLeafIndex)
    const stageOperationIndex = new Map(current.stageOperationIndex)
    this.applyStageTransition(current.head.vaultIdentity, stage, {
      entries: current.entries,
      stageLeases,
      activeStageLeases,
      stageBindingIndex,
      stageLeafIndex,
      stageOperationIndex
    })
    const base: VaultAuthorityStageEventBase = {
      schema: AUTHORITY_STAGE_EVENT_SCHEMA,
      vaultIdentity: current.head.vaultIdentity,
      sequence: current.head.sequence + 1,
      previousStateDigest: current.head.stateDigest,
      action: 'stage_transition',
      stage
    }
    const event: VaultAuthorityStageEvent = {
      ...base,
      stateDigest: this.authorityEventState(base)
    }
    const record = this.encodeAuthorityEvent(event)
    if (current.head.journalByteLength + record.length > MAX_AUTHORITY_JOURNAL_BYTES) {
      throw new PaidMediaVaultError('Paid media vault authority journal is full')
    }
    try {
      const handle = openSync(this.authorityJournalPath, 'a', 0o600)
      try {
        writeFileSync(handle, record)
        fsyncSync(handle)
      } finally {
        closeSync(handle)
      }
      this.hardenIfChanged(this.authorityJournalPath, false)
      const nextHead: VaultAuthorityHead = {
        schema: AUTHORITY_INDEX_SCHEMA,
        vaultIdentity: current.head.vaultIdentity,
        sequence: event.sequence,
        stateDigest: event.stateDigest,
        journalByteLength: current.head.journalByteLength + record.length,
        // v1 physical authority statistics deliberately exclude v2 stage leases.
        entryCount: current.head.entryCount,
        totalBytes: current.head.totalBytes
      }
      this.dependencies.beforeAuthorityHeadCommit?.()
      this.writeAuthorityHead(nextHead)
      const journalInfo = lstatSync(this.authorityJournalPath)
      if (journalInfo.size !== nextHead.journalByteLength) {
        throw new PaidMediaVaultError('Paid media vault authority journal commit is incomplete')
      }
      this.authorityIndexCache = {
        head: nextHead,
        entries: current.entries,
        stageLeases,
        activeStageLeases,
        stageBindingIndex,
        stageLeafIndex,
        stageOperationIndex,
        journalIdentity: this.pathIdentity(journalInfo, false),
        journalMtimeMs: journalInfo.mtimeMs,
        journalCtimeMs: journalInfo.ctimeMs,
        journalSize: journalInfo.size
      }
    } catch (error) {
      this.authorityIndexPoisoned = true
      throw error
    }
  }

  private recordAuthorityCreate(path: string, bytes: Buffer): void {
    if (!this.authorityStrict) return
    try {
      this.appendAuthorityEvent('create', {
        path: this.authorityRelativeFile(path),
        byteLength: bytes.length,
        sha256: sha256(bytes)
      })
    } catch (error) {
      this.authorityIndexPoisoned = true
      throw error
    }
  }

  private recordAuthorityCreateDigest(path: string, byteLength: number, digestValue: string): void {
    if (!this.authorityStrict) return
    try {
      this.appendAuthorityEvent('create', {
        path: this.authorityRelativeFile(path),
        byteLength,
        sha256: digestValue
      })
    } catch (error) {
      this.authorityIndexPoisoned = true
      throw error
    }
  }

  private recordAuthorityDelete(path: string): void {
    if (!this.authorityStrict) return
    try {
      const index = this.loadAuthorityIndex()
      const relativePath = this.authorityRelativeFile(path)
      const entry = index.entries.get(relativePath)
      if (!entry) throw new PaidMediaVaultError('Paid media vault authority delete is not registered')
      this.appendAuthorityEvent('delete', entry)
    } catch (error) {
      this.authorityIndexPoisoned = true
      throw error
    }
  }

  private scanAuthorityFiles(): VaultAuthorityEntry[] {
    const entries: VaultAuthorityEntry[] = []
    const visit = (path: string): void => {
      const children = readdirSync(path, { withFileTypes: true }).sort((left, right) =>
        left.name.localeCompare(right.name, 'en')
      )
      for (const child of children) {
        if (entries.length >= MAX_AUTHORITY_EVIDENCE_ENTRIES) {
          throw new PaidMediaVaultError('Paid media vault authority evidence is full')
        }
        const childPath = join(path, child.name)
        const relativePath = relative(this.root, childPath).replace(/\\/g, '/')
        if (
          !relativePath ||
          relativePath.startsWith('../') ||
          Buffer.byteLength(relativePath, 'utf8') > 4096 ||
          child.isSymbolicLink()
        ) {
          throw new PaidMediaVaultError('Paid media vault authority path is invalid')
        }
        if (child.isDirectory()) {
          this.hardenIfChanged(childPath, true)
          visit(childPath)
          continue
        }
        if (!child.isFile()) {
          throw new PaidMediaVaultError('Paid media vault authority entry is invalid')
        }
        const hashed = this.hashAuthorityFile(childPath)
        entries.push({ path: relativePath, ...hashed })
      }
    }
    visit(this.root)
    return entries
  }

  async provisionAuthorityVault(): Promise<PaidMediaVaultAuthorityEvidence> {
    if (this.authorityStrict) {
      throw new PaidMediaVaultError('Bound paid media vault cannot be reprovisioned')
    }
    this.prepare()
    const headExists = existsSync(this.authorityHeadPath)
    const journalExists = existsSync(this.authorityJournalPath)
    if (headExists !== journalExists) {
      throw new PaidMediaVaultError('Paid media vault authority index pair is incomplete')
    }
    const scanned = this.scanAuthorityFiles()
    if (!headExists) {
      const vaultIdentity = randomBytes(32).toString('hex')
      let sequence = 0
      let stateDigest = this.initialAuthorityState(vaultIdentity)
      const records: Buffer[] = []
      let journalByteLength = 0
      let totalBytes = 0
      for (const entry of scanned) {
        const base: VaultAuthorityFileEventBase = {
          schema: AUTHORITY_EVENT_SCHEMA,
          vaultIdentity,
          sequence: ++sequence,
          previousStateDigest: stateDigest,
          action: 'create',
          entry
        }
        const event: VaultAuthorityFileEvent = {
          ...base,
          stateDigest: this.authorityEventState(base)
        }
        const record = this.encodeAuthorityEvent(event)
        records.push(record)
        journalByteLength += record.length
        totalBytes += entry.byteLength
        stateDigest = event.stateDigest
      }
      this.writeAuthorityJournalNew(Buffer.concat(records, journalByteLength))
      this.writeAuthorityHead({
        schema: AUTHORITY_INDEX_SCHEMA,
        vaultIdentity,
        sequence,
        stateDigest,
        journalByteLength,
        entryCount: scanned.length,
        totalBytes
      })
    } else {
      const current = this.loadAuthorityIndex()
      const actual = new Map(scanned.map((entry) => [entry.path, entry]))
      if (
        actual.size !== current.entries.size ||
        [...actual].some(
          ([path, entry]) => JSON.stringify(current.entries.get(path)) !== JSON.stringify(entry)
        )
      ) {
        throw new PaidMediaVaultError('Paid media vault changed after authority provisioning')
      }
    }
    this.authorityIndexCache = null
    return this.inspectAuthorityEvidence()
  }

  async inspectAuthorityEvidence(): Promise<PaidMediaVaultAuthorityEvidence> {
    this.assertAuthorityDirectories()
    const index = this.loadAuthorityIndex()
    return Object.freeze({
      vaultStateDigest: this.authorityEvidenceDigest(index.head),
      entryCount: index.head.entryCount
    })
  }

  async inspectCaptureInventory(): Promise<PaidMediaVaultCaptureInventory> {
    if (this.captureInspectionReadOnly) {
      throw new PaidMediaVaultError('Paid media vault capture inspection is already active')
    }
    this.captureInspectionReadOnly = true
    try {
      return this.inspectCaptureInventoryReadOnly()
    } finally {
      this.captureInspectionReadOnly = false
    }
  }

  private inspectCaptureInventoryReadOnly(): PaidMediaVaultCaptureInventory {
    this.assertAuthorityDirectories()
    const index = this.loadAuthorityIndex()
    const quiescence = {
      activeStageLeases: index.activeStageLeases.size,
      stageOpenHandles: this.stageOpenHandles.size,
      activeStageStream: this.activeStageStream === null ? 0 : 1,
      cleanupRetries: this.cleanupRetries.size,
      cleanupFlights: this.cleanupFlights.size,
      terminalArchiveFlights: this.terminalArchiveFlights.size
    }
    if (Object.values(quiescence).some((count) => count !== 0)) {
      throw new PaidMediaVaultError(
        `Paid media vault capture is not quiescent: ${Object.entries(quiescence)
          .map(([name, count]) => `${name}=${String(count)}`)
          .join(', ')}`
      )
    }
    const cleanupPendingEntries = readdirSync(this.cleanupPendingPath, {
      withFileTypes: true
    }).length
    if (cleanupPendingEntries !== 0) {
      throw new PaidMediaVaultError(
        'Paid media vault capture cleanup-pending directory is not empty'
      )
    }
    const stageRoot = this.configuredStageRoot()
    const stageRootEntries = readdirSync(stageRoot.path, { withFileTypes: true }).length
    this.assertStageRootStable(stageRoot.path, stageRoot.identity)
    if (stageRootEntries !== 0) {
      throw new PaidMediaVaultError('Paid media vault capture stage root is not empty')
    }
    const indexedEntries = [...index.entries.values()].sort((left, right) =>
      left.path.localeCompare(right.path, 'en')
    )
    const physicalEntries = this.scanAuthorityFiles().sort((left, right) =>
      left.path.localeCompare(right.path, 'en')
    )
    if (
      indexedEntries.length !== physicalEntries.length ||
      indexedEntries.some((entry, index) => {
        const physical = physicalEntries[index]
        return (
          !physical ||
          physical.path !== entry.path ||
          physical.byteLength !== entry.byteLength ||
          physical.sha256 !== entry.sha256
        )
      })
    ) {
      throw new PaidMediaVaultError(
        'Paid media vault capture inventory does not match its authority index'
      )
    }
    const entries = physicalEntries.map((entry) => Object.freeze({ ...entry }))
    return Object.freeze({
      vaultStateDigest: this.authorityEvidenceDigest(index.head),
      entryCount: index.head.entryCount,
      entries: Object.freeze(entries),
      quiescence: Object.freeze({
        activeStageLeases: 0 as const,
        stageOpenHandles: 0 as const,
        activeStageStream: null,
        cleanupRetries: 0 as const,
        cleanupFlights: 0 as const,
        terminalArchiveFlights: 0 as const,
        cleanupPendingEntries: 0 as const,
        stageRootEntries: 0 as const
      })
    })
  }

  async inspectCommittedAuthorityPrefixForRecovery(): Promise<PaidMediaVaultCommittedPrefixRecoveryEvidence> {
    this.assertAuthorityDirectories()
    const committed = this.readCommittedAuthorityPrefixForRecovery()
    let uncommittedTailEventCount: 0 | 1 | null = 0
    if (committed.tailBytes.length > 0) {
      try {
        this.analyzeSingleAuthorityTail(committed)
        uncommittedTailEventCount = 1
      } catch {
        uncommittedTailEventCount = null
      }
    }
    return Object.freeze({
      recoveryOnly: true,
      outboundReady: false,
      committedVaultStateDigest: this.authorityEvidenceDigest(committed.head),
      committedSequence: committed.head.sequence,
      committedJournalByteLength: committed.head.journalByteLength,
      physicalJournalByteLength: committed.journalBytes.length,
      uncommittedTailByteLength: committed.tailBytes.length,
      uncommittedTailEventCount,
      entryCount: committed.head.entryCount,
      totalBytes: committed.head.totalBytes
    })
  }

  async recoverSingleAuthorityJournalTail(
    rawInput: PaidMediaVaultAuthorityTailRecoveryInput
  ): Promise<PaidMediaVaultAuthorityTailRecoveryResult> {
    this.assertAuthorityTailRecoveryMutationAuthority()
    const input = this.normalizeAuthorityTailRecoveryInput(rawInput)
    const committed = this.readCommittedAuthorityPrefixForRecovery()
    if (committed.tailBytes.length === 0) {
      throw new PaidMediaVaultError('Paid media vault authority tail is already committed')
    }
    const previousVaultStateDigest = this.authorityEvidenceDigest(committed.head)
    if (input.committedVaultStateDigest !== previousVaultStateDigest) {
      throw new PaidMediaVaultError(
        'Paid media vault committed prefix does not match the recovery transaction'
      )
    }
    const analyzed = this.analyzeSingleAuthorityTail(committed)
    this.assertAuthorityRecoveryBoundary(input, analyzed.event)
    this.assertAuthorityRecoveryPostcondition(input, analyzed.event)
    try {
      this.dependencies.beforeAuthorityHeadCommit?.()
      this.assertAuthorityRecoveryPostcondition(input, analyzed.event)
      this.writeAuthorityHead(analyzed.nextHead)
    } catch (error) {
      this.authorityIndexPoisoned = true
      throw error
    }

    this.authorityIndexCache = null
    this.authorityIndexPoisoned = false
    let verified: VaultAuthorityIndexCache
    try {
      verified = this.loadAuthorityIndex()
      if (JSON.stringify(verified.head) !== JSON.stringify(analyzed.nextHead)) {
        throw new PaidMediaVaultError(
          'Paid media vault recovered authority head did not verify'
        )
      }
      this.assertAuthorityRecoveryPostcondition(input, analyzed.event)
    } catch (error) {
      this.authorityIndexPoisoned = true
      throw error
    }
    return Object.freeze({
      operationId: input.operationId,
      action: analyzed.event.action,
      recovered: true,
      previousVaultStateDigest,
      vaultStateDigest: this.authorityEvidenceDigest(verified.head),
      sequence: analyzed.event.sequence,
      eventStateDigest: analyzed.event.stateDigest
    })
  }

  private stageIdentityFromStats(
    path: string,
    info: BigIntStats,
    directory: boolean
  ): StageFullIdentity {
    if (
      info.isSymbolicLink() ||
      (directory ? !info.isDirectory() : !info.isFile()) ||
      info.dev < 0n ||
      info.ino < 0n ||
      info.birthtimeNs < 0n ||
      info.mtimeNs < 0n ||
      info.ctimeNs < 0n ||
      info.size < 0n
    ) {
      throw new PaidMediaVaultError('Paid media stage object identity is invalid')
    }
    return {
      pathSha256: sha256(normalizedAbsolutePath(path)),
      dev: info.dev.toString(10),
      ino: info.ino.toString(10),
      birthtimeNs: info.birthtimeNs.toString(10),
      mtimeNs: info.mtimeNs.toString(10),
      ctimeNs: info.ctimeNs.toString(10),
      size: info.size.toString(10)
    }
  }

  private stagePathIdentity(path: string, directory: boolean): StageFullIdentity {
    const absolute = resolve(path)
    const info = lstatSync(absolute, { bigint: true })
    if (
      normalizedAbsolutePath(realpathSync(absolute)) !== normalizedAbsolutePath(absolute)
    ) {
      throw new PaidMediaVaultError('Paid media stage object is redirected')
    }
    return this.stageIdentityFromStats(absolute, info, directory)
  }

  private async stageHandleIdentity(
    handle: FileHandle,
    path: string
  ): Promise<StageFullIdentity> {
    const info = await handle.stat({ bigint: true })
    return this.stageIdentityFromStats(resolve(path), info, false)
  }

  private stageStableIdentity(identity: StageFullIdentity): StageStableIdentity {
    return {
      pathSha256: identity.pathSha256,
      dev: identity.dev,
      ino: identity.ino,
      birthtimeNs: identity.birthtimeNs
    }
  }

  private configuredStageRoot(): { path: string; identity: StageStableIdentity } {
    if (!this.dependencies.stageRoot) {
      throw new PaidMediaVaultError('Paid media dedicated stage root is required')
    }
    const raw = this.dependencies.stageRoot()
    if (typeof raw !== 'string' || raw.length < 1) {
      throw new PaidMediaVaultError('Paid media dedicated stage root is required')
    }
    const configured = resolve(raw)
    if (normalizedAbsolutePath(configured) === normalizedAbsolutePath(tmpdir())) {
      throw new PaidMediaVaultError('Paid media dedicated stage root cannot be the shared temp root')
    }
    const relativeToVault = relative(this.root, configured).replace(/\\/g, '/')
    const vaultRelativeToStage = relative(configured, this.root).replace(/\\/g, '/')
    const isInside = (candidate: string): boolean =>
      candidate === '' ||
      (!candidate.startsWith('../') &&
        candidate !== '..' &&
        !/^[A-Za-z]:[\\/]/.test(candidate))
    if (
      isInside(relativeToVault) ||
      isInside(vaultRelativeToStage)
    ) {
      throw new PaidMediaVaultError('Paid media stage root overlaps the authority vault')
    }
    const identity = this.stagePathIdentity(configured, true)
    return { path: configured, identity: this.stageStableIdentity(identity) }
  }

  private assertStageRootStable(path: string, expected: StageStableIdentity): void {
    const actual = this.stageStableIdentity(this.stagePathIdentity(path, true))
    if (!this.sameStageStableIdentity(expected, actual)) {
      throw new PaidMediaVaultError('Paid media stage root identity changed')
    }
  }

  private assertStageMutationAuthority(): void {
    this.assertMutationAllowed()
    if (!this.authorityStrict || this.mutationGuard === null) {
      throw new PaidMediaVaultError('Paid media stage mutation requires Installation Root')
    }
    this.assertAuthorityDirectories()
  }

  private assertAssetRecoveryMutationAuthority(): void {
    this.assertMutationAllowed()
    if (!this.authorityStrict || this.mutationGuard === null) {
      throw new PaidMediaVaultError(
        'Paid media asset recovery mutation requires Installation Root'
      )
    }
    this.assertAuthorityDirectories()
  }

  private assertAuthorityTailRecoveryMutationAuthority(): void {
    this.assertMutationAllowed()
    if (!this.authorityStrict || this.mutationGuard === null) {
      throw new PaidMediaVaultError(
        'Paid media authority tail recovery mutation requires Installation Root'
      )
    }
    this.assertAuthorityDirectories()
  }

  private makeReservedStageEvent(input: {
    vaultIdentity: string
    operationId: string
    resultSha256: string
    result: PaidMediaAssetResult
    ordinal: number
    tempRoot: StageStableIdentity
  }): StageLeaseEvent {
    const descriptor = Object.freeze({ ...input.result.assets[input.ordinal]! })
    const descriptorSha256 = this.stageDescriptorDigest(descriptor)
    const leaseId = this.computeStageLeaseId({
      vaultIdentity: input.vaultIdentity,
      operationId: input.operationId,
      turnId: input.result.turnId,
      resultSha256: input.resultSha256,
      ordinal: input.ordinal,
      descriptorSha256
    })
    const createdAt = this.dependencies.now()
    if (!Number.isSafeInteger(createdAt) || createdAt < 0) {
      throw new PaidMediaVaultError('Paid media stage clock is invalid')
    }
    const base: StageLeaseEventBase = {
      schema: STAGE_LEASE_EVENT_SCHEMA,
      leaseId,
      leaseSequence: 1,
      previousLeaseStateDigest: ZERO_SHA256,
      state: 'reserved',
      operationId: input.operationId,
      turnId: input.result.turnId,
      resultSha256: input.resultSha256,
      ordinal: input.ordinal,
      descriptor,
      descriptorSha256,
      generation: 0,
      tempRoot: input.tempRoot,
      directoryName: `${STAGE_DIRECTORY_PREFIX}${leaseId}`,
      fileName: STAGE_FILE_NAME,
      directory: null,
      file: null,
      reasonCode: null,
      createdAt,
      updatedAt: createdAt
    }
    return { ...base, leaseStateDigest: this.stageLeaseStateDigest(base) }
  }

  private makeStageTransition(
    previous: StageLeaseEvent,
    state: PaidMediaStageLeaseState,
    directory: StageFullIdentity | null,
    file: StageFullIdentity | null,
    reasonCode: string | null,
    generation = previous.generation
  ): StageLeaseEvent {
    const updatedAt = this.dependencies.now()
    if (!Number.isSafeInteger(updatedAt) || updatedAt < previous.updatedAt) {
      throw new PaidMediaVaultError('Paid media stage clock moved backwards')
    }
    const base: StageLeaseEventBase = {
      schema: STAGE_LEASE_EVENT_SCHEMA,
      leaseId: previous.leaseId,
      leaseSequence: previous.leaseSequence + 1,
      previousLeaseStateDigest: previous.leaseStateDigest,
      state,
      operationId: previous.operationId,
      turnId: previous.turnId,
      resultSha256: previous.resultSha256,
      ordinal: previous.ordinal,
      descriptor: previous.descriptor,
      descriptorSha256: previous.descriptorSha256,
      generation,
      tempRoot: previous.tempRoot,
      directoryName: previous.directoryName,
      fileName: STAGE_FILE_NAME,
      directory,
      file,
      reasonCode,
      createdAt: previous.createdAt,
      updatedAt
    }
    return { ...base, leaseStateDigest: this.stageLeaseStateDigest(base) }
  }

  private stagePaths(stage: StageLeaseEvent): {
    tempRootPath: string
    directoryPath: string
    filePath: string
  } {
    const configured = this.configuredStageRoot()
    if (!this.sameStageStableIdentity(configured.identity, stage.tempRoot)) {
      throw new PaidMediaVaultError('Paid media stage root no longer matches its lease')
    }
    const directoryPath = join(configured.path, stage.directoryName)
    const filePath = join(directoryPath, STAGE_FILE_NAME)
    if (
      normalizedAbsolutePath(dirname(directoryPath)) !==
        normalizedAbsolutePath(configured.path) ||
      normalizedAbsolutePath(dirname(filePath)) !== normalizedAbsolutePath(directoryPath)
    ) {
      throw new PaidMediaVaultError('Paid media stage lease path escaped its root')
    }
    return { tempRootPath: configured.path, directoryPath, filePath }
  }

  private assertStageOpenRecordIdentity(record: StageOpenHandleRecord): Promise<void> {
    return (async () => {
      this.assertStageRootStable(record.tempRootPath, record.tempRootIdentity)
      const directory = this.stagePathIdentity(record.directoryPath, true)
      const pathFile = this.stagePathIdentity(record.filePath, false)
      const handleFile = await this.stageHandleIdentity(record.handle, record.filePath)
      if (
        !this.sameStageStableIdentity(record.directoryIdentity, directory) ||
        !this.sameStageStableIdentity(record.fileIdentity, pathFile) ||
        !this.sameStageStableIdentity(record.fileIdentity, handleFile)
      ) {
        throw new PaidMediaVaultError('Paid media stage handle identity changed')
      }
    })()
  }

  private stageHandleHook(
    phase: 'opened' | 'write' | 'sync' | 'seal' | 'read',
    record: StageOpenHandleRecord
  ): void {
    this.dependencies.onStageHandleUse?.({ phase, witness: record.witness })
  }

  private assertStageRecordAuthority(record: StageOpenHandleRecord): void {
    const current = this.loadAuthorityIndex().stageLeases.get(record.leaseId)
    if (
      !current ||
      current.state !== 'opened' ||
      current.generation !== record.generation ||
      current.operationId !== record.operationId ||
      current.turnId !== record.turnId ||
      current.ordinal !== record.ordinal ||
      JSON.stringify(current.descriptor) !== JSON.stringify(record.descriptor)
    ) {
      record.state = 'revoked'
      throw new PaidMediaVaultError('Paid media stage capability authority is revoked')
    }
  }

  private requireStageWriteCapability(value: unknown): StageOpenHandleRecord {
    if (!value || typeof value !== 'object') {
      throw new PaidMediaVaultError('Paid media stage capability is forged')
    }
    const record = this.stageWriteCapabilities.get(value as object)
    if (!record || record.state !== 'open') {
      throw new PaidMediaVaultError('Paid media stage capability is forged or revoked')
    }
    this.assertStageRecordAuthority(record)
    return record
  }

  private async writeStageCapability(
    value: object,
    bytes: Uint8Array,
    position: number
  ): Promise<{ bytesWritten: number }> {
    const record = this.requireStageWriteCapability(value)
    if (
      !(bytes instanceof Uint8Array) ||
      !Number.isSafeInteger(position) ||
      position < 0 ||
      position !== record.offset
    ) {
      throw new PaidMediaVaultError('Paid media stage write bytes are invalid')
    }
    const copy = Buffer.from(bytes)
    if (record.offset + copy.length > record.descriptor.byteLength) {
      throw new PaidMediaVaultError('Paid media stage write exceeds the declared length')
    }
    await this.assertStageOpenRecordIdentity(record)
    this.stageHandleHook('write', record)
    let offset = 0
    while (offset < copy.length) {
      const written = await record.handle.write(
        copy,
        offset,
        copy.length - offset,
        record.offset + offset
      )
      if (written.bytesWritten < 1) {
        throw new PaidMediaVaultError('Paid media stage write made no progress')
      }
      offset += written.bytesWritten
    }
    record.offset += copy.length
    record.digest.update(copy)
    return { bytesWritten: copy.length }
  }

  private async syncStageCapability(value: object): Promise<void> {
    const record = this.requireStageWriteCapability(value)
    await this.assertStageOpenRecordIdentity(record)
    this.stageHandleHook('sync', record)
    await record.handle.sync()
  }

  private mintStageWriteCapability(record: StageOpenHandleRecord): PaidMediaStageWriteCapability {
    const owner = this
    const capability: PaidMediaStageWriteCapability = Object.freeze({
      leaseId: record.leaseId,
      operationId: record.operationId,
      turnId: record.turnId,
      ordinal: record.ordinal,
      descriptor: record.descriptor,
      async write(
        this: PaidMediaStageWriteCapability,
        bytes: Uint8Array,
        position: number
      ): Promise<{ bytesWritten: number }> {
        return owner.writeStageCapability(this, bytes, position)
      },
      async sync(this: PaidMediaStageWriteCapability): Promise<void> {
        await owner.syncStageCapability(this)
      }
    })
    this.stageWriteCapabilities.set(capability, record)
    return capability
  }

  async sealStageWriteCapability(
    capability: PaidMediaStageWriteCapability
  ): Promise<PaidMediaSealedStageCapability> {
    const record = this.requireStageWriteCapability(capability)
    await this.assertStageOpenRecordIdentity(record)
    this.stageHandleHook('seal', record)
    await record.handle.sync()
    const handleIdentity = await this.stageHandleIdentity(record.handle, record.filePath)
    if (
      record.offset !== record.descriptor.byteLength ||
      BigInt(handleIdentity.size) !== BigInt(record.descriptor.byteLength)
    ) {
      throw new PaidMediaVaultError('Paid media stage asset length is incomplete')
    }
    const digest = record.digest.copy().digest('hex')
    if (digest !== record.descriptor.sha256) {
      record.state = 'revoked'
      this.stageWriteCapabilities.delete(capability)
      throw new PaidMediaVaultError('Paid media stage asset digest does not match')
    }
    record.state = 'sealed'
    this.stageWriteCapabilities.delete(capability)
    const sealed: PaidMediaSealedStageCapability = Object.freeze({
      leaseId: record.leaseId,
      operationId: record.operationId,
      turnId: record.turnId,
      ordinal: record.ordinal,
      descriptor: record.descriptor
    })
    this.sealedStageCapabilities.set(sealed, record)
    return sealed
  }

  createSealedStageReadSource(
    capability: PaidMediaSealedStageCapability
  ): PaidMediaSealedStageReadSource {
    const record = this.requireSealedStageCapability(capability)
    let consumed = false
    return Object.freeze({
      byteLength: record.descriptor.byteLength,
      sha256: record.descriptor.sha256,
      createReadStream: (): Readable => {
        if (consumed) {
          throw new PaidMediaVaultError('Paid media sealed stage source was already consumed')
        }
        consumed = true
        this.acquireStageStream(record)
        try {
          return this.createSealedStageRecordReadStream(record)
        } catch (error) {
          this.releaseStageStream(record)
          throw error
        }
      }
    })
  }

  private acquireStageStream(record: StageOpenHandleRecord): void {
    this.assertStageRecordAuthority(record)
    if (this.activeStageStream !== null) {
      throw new PaidMediaVaultError('Paid media stage stream is already active')
    }
    this.activeStageStream = record
  }

  private releaseStageStream(record: StageOpenHandleRecord): void {
    if (this.activeStageStream === record) this.activeStageStream = null
  }

  private requireSealedStageCapability(
    capability: PaidMediaSealedStageCapability
  ): StageOpenHandleRecord {
    const record = this.lookupSealedStageCapability(capability)
    if (record.state !== 'sealed') {
      throw new PaidMediaVaultError('Paid media sealed stage capability is forged or revoked')
    }
    this.assertStageRecordAuthority(record)
    return record
  }

  private lookupSealedStageCapability(
    capability: PaidMediaSealedStageCapability
  ): StageOpenHandleRecord {
    if (!capability || typeof capability !== 'object') {
      throw new PaidMediaVaultError('Paid media sealed stage capability is forged')
    }
    const record = this.sealedStageCapabilities.get(capability as object)
    if (!record) {
      throw new PaidMediaVaultError('Paid media sealed stage capability is forged')
    }
    return record
  }

  private createSealedStageRecordReadStream(record: StageOpenHandleRecord): Readable {
    const owner = this
    async function* chunks(): AsyncGenerator<Buffer> {
      try {
        owner.assertStageRecordAuthority(record)
        await owner.assertStageOpenRecordIdentity(record)
        owner.stageHandleHook('read', record)
        const before = await record.handle.stat()
        if (!before.isFile() || before.size !== record.descriptor.byteLength) {
          throw new PaidMediaVaultError('Paid media sealed stage asset length is invalid')
        }
        let offset = 0
        while (offset < before.size) {
          owner.assertStageRecordAuthority(record)
          const wanted = Math.min(PAID_MEDIA_STAGE_STREAM_CHUNK_BYTES, before.size - offset)
          const buffer = Buffer.allocUnsafe(wanted)
          const { bytesRead } = await record.handle.read(buffer, 0, wanted, offset)
          if (bytesRead < 1) {
            throw new PaidMediaVaultError('Paid media sealed stage asset is truncated')
          }
          const chunk = bytesRead === buffer.length ? buffer : buffer.subarray(0, bytesRead)
          offset += bytesRead
          owner.dependencies.onStageStreamChunk?.({
            phase: 'probe',
            leaseId: record.leaseId,
            ordinal: record.ordinal,
            byteLength: chunk.length
          })
          yield chunk
        }
        owner.assertStageRecordAuthority(record)
        await owner.assertStageOpenRecordIdentity(record)
        const after = await record.handle.stat()
        if (
          offset !== record.descriptor.byteLength ||
          after.dev !== before.dev ||
          after.ino !== before.ino ||
          after.birthtimeMs !== before.birthtimeMs ||
          after.mtimeMs !== before.mtimeMs ||
          after.ctimeMs !== before.ctimeMs ||
          after.size !== before.size
        ) {
          throw new PaidMediaVaultError('Paid media sealed stage asset changed while streaming')
        }
      } finally {
        owner.releaseStageStream(record)
      }
    }
    const stream = Readable.from(chunks(), { objectMode: false, highWaterMark: 1 })
    stream.once('close', () => owner.releaseStageStream(record))
    return stream
  }

  private inspectStageLeaf(stage: StageLeaseEvent): StageLeafInspection {
    let paths: ReturnType<PaidMediaVault['stagePaths']>
    try {
      paths = this.stagePaths(stage)
      this.assertStageRootStable(paths.tempRootPath, stage.tempRoot)
    } catch {
      return { kind: 'mismatch', reasonCode: 'stage_root_identity_changed' }
    }
    if (!existsSync(paths.directoryPath)) return { kind: 'absent' }
    let directory: StageFullIdentity
    try {
      directory = this.stagePathIdentity(paths.directoryPath, true)
    } catch {
      return { kind: 'mismatch', reasonCode: 'stage_directory_invalid' }
    }
    if (
      stage.directory === null ||
      !this.sameStageStableIdentity(stage.directory, directory)
    ) {
      return { kind: 'mismatch', reasonCode: 'stage_directory_identity_changed' }
    }
    let entries: Dirent[]
    try {
      entries = readdirSync(paths.directoryPath, { withFileTypes: true })
    } catch {
      return { kind: 'mismatch', reasonCode: 'stage_directory_unreadable' }
    }
    if (
      entries.length > 1 ||
      (entries.length === 1 &&
        (entries[0]!.name !== STAGE_FILE_NAME ||
          !entries[0]!.isFile() ||
          entries[0]!.isSymbolicLink()))
    ) {
      return { kind: 'mismatch', reasonCode: 'stage_tree_outside_closed_set' }
    }
    if (entries.length === 0) {
      return { kind: 'exact', directory, file: null }
    }
    if (stage.file === null) {
      return { kind: 'mismatch', reasonCode: 'stage_file_was_not_authorized' }
    }
    let file: StageFullIdentity
    try {
      file = this.stagePathIdentity(paths.filePath, false)
    } catch {
      return { kind: 'mismatch', reasonCode: 'stage_file_invalid' }
    }
    if (!this.sameStageStableIdentity(stage.file, file)) {
      return { kind: 'mismatch', reasonCode: 'stage_file_identity_changed' }
    }
    return { kind: 'exact', directory, file }
  }

  private async revokeStageHandle(leaseId: string): Promise<boolean> {
    const record = this.stageOpenHandles.get(leaseId)
    if (!record) return true
    record.state = 'revoked'
    try {
      await record.handle.close()
      this.stageOpenHandles.delete(leaseId)
      return true
    } catch (error) {
      this.dependencies.onCleanupError?.(error)
      return false
    }
  }

  private appendStageHeld(
    stage: StageLeaseEvent,
    reasonCode: string,
    directory = stage.directory,
    file = stage.file
  ): StageLeaseEvent {
    if (stage.state === 'held') return stage
    const held = this.makeStageTransition(stage, 'held', directory, file, reasonCode)
    this.appendStageAuthorityEvent(held)
    return held
  }

  private appendStageCleaned(stage: StageLeaseEvent): StageLeaseEvent {
    if (
      stage.state !== 'aborted_cleanup_pending' &&
      stage.state !== 'archived_cleanup_pending'
    ) {
      throw new PaidMediaVaultError('Paid media stage cleanup completion has no durable intent')
    }
    const cleaned = this.makeStageTransition(
      stage,
      stage.state === 'archived_cleanup_pending' ? 'archived_cleaned' : 'aborted_cleaned',
      stage.directory,
      stage.file,
      stage.reasonCode
    )
    this.appendStageAuthorityEvent(cleaned)
    return cleaned
  }

  private archivedStageReceiptMatches(
    stage: StageLeaseEvent,
    archived: PaidMediaArchivedResult
  ): boolean {
    const authority = this.loadAuthorityIndex()
    const operationLeases = authority.stageOperationIndex.get(stage.operationId)
    if (
      !operationLeases ||
      !operationLeases.has(stage.leaseId) ||
      archived.receipt.operationId !== stage.operationId ||
      archived.receipt.path !== '/v1/images/generations' ||
      archived.receipt.status !== 200 ||
      archived.receipt.kind !== 'image' ||
      archived.receipt.assets.length !== operationLeases.size
    ) {
      return false
    }
    return [...operationLeases].every((leaseId) => {
      const related = authority.stageLeases.get(leaseId)
      const asset = related ? archived.receipt.assets[related.ordinal] : undefined
      return Boolean(
        related &&
          asset &&
          related.operationId === stage.operationId &&
          asset.sha256 === related.descriptor.sha256 &&
          asset.byteLength === related.descriptor.byteLength &&
          asset.mediaType === related.descriptor.mediaType &&
          asset.sourceSha256 === paidMediaAssetTokenHash(related.descriptor.token) &&
          asset.validation?.schema === TRUSTED_VALIDATION_SCHEMA &&
          asset.validation.receiptSha256 === related.descriptor.validationReceiptSha256
      )
    })
  }

  private async performPendingStageCleanup(
    stage: StageLeaseEvent
  ): Promise<'cleaned' | 'pending' | 'held'> {
    if (
      stage.state !== 'aborted_cleanup_pending' &&
      stage.state !== 'archived_cleanup_pending'
    ) {
      throw new PaidMediaVaultError('Paid media stage cleanup requires a pending lease')
    }
    if (stage.state === 'archived_cleanup_pending') {
      try {
        const archived = await this.verifyArchive(stage.operationId)
        if (!this.archivedStageReceiptMatches(stage, archived)) {
          throw new PaidMediaVaultError('Paid media archived stage cleanup binding conflicts')
        }
      } catch (error) {
        this.dependencies.onCleanupError?.(error)
        await this.revokeStageHandle(stage.leaseId)
        this.appendStageHeld(stage, 'archive_cleanup_evidence_invalid')
        return 'held'
      }
    }
    if (!(await this.revokeStageHandle(stage.leaseId))) return 'pending'
    let inspection = this.inspectStageLeaf(stage)
    if (inspection.kind === 'mismatch') {
      this.appendStageHeld(stage, inspection.reasonCode)
      return 'held'
    }
    if (inspection.kind === 'absent') {
      this.appendStageCleaned(stage)
      return 'cleaned'
    }
    const paths = this.stagePaths(stage)
    try {
      if (inspection.file !== null) {
        ;(this.dependencies.stageCleanupIO?.unlinkStageFile ?? unlinkSync)(paths.filePath)
      }
      inspection = this.inspectStageLeaf(stage)
      if (inspection.kind === 'mismatch') {
        this.appendStageHeld(stage, inspection.reasonCode)
        return 'held'
      }
      if (inspection.kind === 'exact') {
        if (inspection.file !== null || readdirSync(paths.directoryPath).length !== 0) {
          this.appendStageHeld(stage, 'stage_tree_outside_closed_set')
          return 'held'
        }
        ;(this.dependencies.stageCleanupIO?.removeEmptyStageDirectory ?? rmdirSync)(
          paths.directoryPath
        )
      }
      if (existsSync(paths.directoryPath)) return 'pending'
      this.appendStageCleaned(stage)
      return 'cleaned'
    } catch (error) {
      this.dependencies.onCleanupError?.(error)
      const afterFailure = this.inspectStageLeaf(stage)
      if (afterFailure.kind === 'mismatch') {
        this.appendStageHeld(stage, afterFailure.reasonCode)
        return 'held'
      }
      return 'pending'
    }
  }

  private async openReservedStageLease(
    stage: StageLeaseEvent,
    context: StageOpeningContext
  ): Promise<{ event: StageLeaseEvent; capability: PaidMediaStageWriteCapability }> {
    await this.dependencies.beforeStageFileCreate?.({
      leaseId: stage.leaseId,
      operationId: stage.operationId,
      ordinal: stage.ordinal
    })
    this.assertStageRootStable(context.tempRootPath, stage.tempRoot)
    mkdirSync(context.directoryPath, { mode: 0o700 })
    context.directoryIdentity = this.stagePathIdentity(context.directoryPath, true)
    this.hardenIfChanged(context.directoryPath, true)
    const hardenedDirectory = this.stagePathIdentity(context.directoryPath, true)
    if (!this.sameStageStableIdentity(context.directoryIdentity, hardenedDirectory)) {
      throw new PaidMediaVaultError('Paid media stage directory changed while hardening')
    }
    context.directoryIdentity = hardenedDirectory
    this.assertStageRootStable(context.tempRootPath, stage.tempRoot)
    context.handle = await openFile(context.filePath, 'wx+', 0o600)
    const beforePath = this.stagePathIdentity(context.filePath, false)
    const beforeHandle = await this.stageHandleIdentity(context.handle, context.filePath)
    if (!this.sameStageStableIdentity(beforePath, beforeHandle)) {
      throw new PaidMediaVaultError('Paid media stage file path does not match its handle')
    }
    context.fileIdentity = beforeHandle
    this.hardenIfChanged(context.filePath, false)
    const afterPath = this.stagePathIdentity(context.filePath, false)
    const afterHandle = await this.stageHandleIdentity(context.handle, context.filePath)
    if (
      !this.sameStageStableIdentity(context.fileIdentity, afterPath) ||
      !this.sameStageStableIdentity(context.fileIdentity, afterHandle)
    ) {
      throw new PaidMediaVaultError('Paid media stage file changed while hardening')
    }
    context.fileIdentity = afterHandle
    await this.dependencies.beforeStageOpenedCommit?.({
      leaseId: stage.leaseId,
      operationId: stage.operationId,
      ordinal: stage.ordinal
    })
    this.assertStageRootStable(context.tempRootPath, stage.tempRoot)
    const finalDirectory = this.stagePathIdentity(context.directoryPath, true)
    const finalPath = this.stagePathIdentity(context.filePath, false)
    const finalHandle = await this.stageHandleIdentity(context.handle, context.filePath)
    if (
      !this.sameStageStableIdentity(context.directoryIdentity, finalDirectory) ||
      !this.sameStageStableIdentity(context.fileIdentity, finalPath) ||
      !this.sameStageStableIdentity(context.fileIdentity, finalHandle) ||
      readdirSync(context.directoryPath).length !== 1 ||
      readdirSync(context.directoryPath)[0] !== STAGE_FILE_NAME
    ) {
      throw new PaidMediaVaultError('Paid media stage leaf changed before opening commit')
    }
    context.directoryIdentity = finalDirectory
    context.fileIdentity = finalHandle
    const opened = this.makeStageTransition(
      stage,
      'opened',
      finalDirectory,
      finalHandle,
      null
    )
    this.appendStageAuthorityEvent(opened)
    const witness = Object.freeze({})
    const record: StageOpenHandleRecord = {
      leaseId: opened.leaseId,
      operationId: opened.operationId,
      turnId: opened.turnId,
      ordinal: opened.ordinal,
      generation: opened.generation,
      descriptor: opened.descriptor,
      handle: context.handle,
      filePath: context.filePath,
      directoryPath: context.directoryPath,
      tempRootPath: context.tempRootPath,
      tempRootIdentity: opened.tempRoot,
      directoryIdentity: finalDirectory,
      fileIdentity: finalHandle,
      offset: 0,
      digest: createHash('sha256'),
      state: 'open',
      witness
    }
    this.stageOpenHandles.set(opened.leaseId, record)
    this.stageHandleHook('opened', record)
    return { event: opened, capability: this.mintStageWriteCapability(record) }
  }

  private async abortStageBatch(
    reservations: readonly StageLeaseEvent[],
    contexts: ReadonlyMap<string, StageOpeningContext>
  ): Promise<{ cleanupPending: boolean; held: boolean }> {
    let cleanupPending = false
    let held = false
    for (const reservation of reservations) {
      const context = contexts.get(reservation.leaseId)
      const registered = this.stageOpenHandles.get(reservation.leaseId)
      if (registered) {
        if (!(await this.revokeStageHandle(reservation.leaseId))) cleanupPending = true
      } else if (context?.handle) {
        try {
          await context.handle.close()
          context.handle = null
        } catch (error) {
          this.dependencies.onCleanupError?.(error)
          cleanupPending = true
        }
      }
      const current = this.loadAuthorityIndex().stageLeases.get(reservation.leaseId)
      if (!current || current.state === 'aborted_cleaned') continue
      if (current.state === 'held') {
        held = true
        continue
      }
      const directory = current.directory ?? context?.directoryIdentity ?? null
      const file = current.file ?? context?.fileIdentity ?? null
      if (directory === null) {
        let directoryExists = true
        try {
          directoryExists = existsSync(this.stagePaths(current).directoryPath)
        } catch {
          // A changed root is a hold, never a deletion hint.
        }
        if (directoryExists) {
          this.appendStageHeld(current, 'unproven_stage_leaf', directory, file)
          held = true
          continue
        }
      }
      const pending = this.makeStageTransition(
        current,
        'aborted_cleanup_pending',
        directory,
        file,
        'stage_open_failed'
      )
      this.appendStageAuthorityEvent(pending)
      const status = await this.performPendingStageCleanup(pending)
      cleanupPending ||= status === 'pending'
      held ||= status === 'held'
    }
    return { cleanupPending, held }
  }

  async reserveAndOpenStageLeases(input: {
    operationId: string
    result: PaidMediaAssetResult
  }): Promise<PaidMediaStageOpenResult> {
    this.assertStageMutationAuthority()
    if (
      !input ||
      typeof input !== 'object' ||
      !exactKeys(input as unknown as Record<string, unknown>, ['operationId', 'result'])
    ) {
      throw new PaidMediaVaultError('Paid media stage reservation input is invalid')
    }
    const operationId = requireOperationId(input.operationId)
    const result = parsePaidMediaAssetResult(input.result)
    const resultSha256 = paidMediaAssetResultDigest(result)
    const stageRoot = this.configuredStageRoot()
    const current = this.loadAuthorityIndex()
    const priorOperationLeases = current.stageOperationIndex.get(operationId)
    if (
      priorOperationLeases &&
      [...priorOperationLeases].some((leaseId) => {
        const prior = current.stageLeases.get(leaseId)
        const expected = prior ? result.assets[prior.ordinal] : undefined
        return (
          !prior ||
          !expected ||
          prior.turnId !== result.turnId ||
          prior.resultSha256 !== resultSha256 ||
          JSON.stringify(prior.descriptor) !== JSON.stringify(expected)
        )
      })
    ) {
      throw new PaidMediaVaultError('Paid media stage reservation conflicts')
    }
    const desiredReservations = result.assets.map((_, ordinal) =>
      this.makeReservedStageEvent({
        vaultIdentity: current.head.vaultIdentity,
        operationId,
        resultSha256,
        result,
        ordinal,
        tempRoot: stageRoot.identity
      })
    )
    let newLeaseCount = 0
    const reservations = desiredReservations.map((desired) => {
      const existing = current.stageLeases.get(desired.leaseId)
      if (!existing) {
        newLeaseCount += 1
        if (
          current.stageBindingIndex.has(this.stageBindingKey(desired)) ||
          current.stageLeafIndex.has(this.stageLeafKey(desired))
        ) {
          throw new PaidMediaVaultError('Paid media stage reservation conflicts')
        }
        return desired
      }
      if (
        existing.state !== 'aborted_cleaned' ||
        existing.generation >= 1_000_000 ||
        existing.operationId !== operationId ||
        existing.turnId !== result.turnId ||
        existing.resultSha256 !== resultSha256 ||
        existing.ordinal !== desired.ordinal ||
        JSON.stringify(existing.descriptor) !== JSON.stringify(desired.descriptor) ||
        !this.sameStageStableIdentity(existing.tempRoot, stageRoot.identity) ||
        current.stageBindingIndex.get(this.stageBindingKey(existing)) !== existing.leaseId ||
        current.stageLeafIndex.get(this.stageLeafKey(existing)) !== existing.leaseId
      ) {
        throw new PaidMediaVaultError('Paid media stage reservation conflicts')
      }
      return this.makeStageTransition(
        existing,
        'reserved',
        null,
        null,
        null,
        existing.generation + 1
      )
    })
    if (
      current.stageLeases.size + newLeaseCount > MAX_STAGE_LEASES ||
      current.activeStageLeases.size + reservations.length > MAX_ACTIVE_STAGE_LEASES
    ) {
      throw new PaidMediaVaultError('Paid media stage lease capacity is exhausted')
    }
    for (const reservation of reservations) {
      if (existsSync(join(stageRoot.path, reservation.directoryName))) {
        throw new PaidMediaVaultError('Paid media stage reservation conflicts')
      }
    }
    // Every lease is durably reserved before the first directory or file is created.
    for (const reservation of reservations) this.appendStageAuthorityEvent(reservation)
    this.hardenIfChanged(stageRoot.path, true)
    this.assertStageRootStable(stageRoot.path, stageRoot.identity)
    const contexts = new Map<string, StageOpeningContext>()
    for (const reservation of reservations) {
      const directoryPath = join(stageRoot.path, reservation.directoryName)
      contexts.set(reservation.leaseId, {
        leaseId: reservation.leaseId,
        tempRootPath: stageRoot.path,
        directoryPath,
        filePath: join(directoryPath, STAGE_FILE_NAME),
        handle: null,
        directoryIdentity: null,
        fileIdentity: null
      })
    }
    const capabilities: PaidMediaStageWriteCapability[] = []
    try {
      for (const reservation of reservations) {
        const opened = await this.openReservedStageLease(
          reservation,
          contexts.get(reservation.leaseId)!
        )
        capabilities.push(opened.capability)
      }
      return Object.freeze({ ok: true, capabilities: Object.freeze(capabilities) })
    } catch (error) {
      if (this.authorityIndexPoisoned) {
        for (const context of contexts.values()) {
          try {
            await context.handle?.close()
          } catch {
            // Authority poison takes precedence; startup recovery must inspect the tail.
          }
        }
        throw error
      }
      this.dependencies.onCleanupError?.(error)
      const aborted = await this.abortStageBatch(reservations, contexts)
      return Object.freeze({ ok: false, ...aborted })
    }
  }

  async resumeArchivedStageCleanup(operationId: string): Promise<PaidMediaArchivedResult> {
    this.assertStageMutationAuthority()
    const normalizedOperationId = requireOperationId(operationId)
    const authority = this.loadAuthorityIndex()
    const leaseIds = [...(authority.stageOperationIndex.get(normalizedOperationId) ?? [])]
    const stages = leaseIds.map((leaseId) => authority.stageLeases.get(leaseId)!)
    let archived: PaidMediaArchivedResult
    try {
      archived = await this.verifyArchive(normalizedOperationId)
      if (stages.some((stage) => !stage || !this.archivedStageReceiptMatches(stage, archived))) {
        throw new PaidMediaVaultError('Paid media archived stage cleanup binding conflicts')
      }
    } catch (error) {
      this.dependencies.onCleanupError?.(error)
      for (const stage of stages) {
        if (
          stage &&
          (stage.state === 'opened' || stage.state === 'archived_cleanup_pending')
        ) {
          await this.revokeStageHandle(stage.leaseId)
          this.appendStageHeld(stage, 'archive_cleanup_evidence_invalid')
        }
      }
      throw error
    }
    return this.finishArchivedStageCleanup(normalizedOperationId, stages)
  }

  async reclaimStageLease(input: {
    operationId: string
    result: PaidMediaAssetResult
    leaseId: string
  }): Promise<PaidMediaStageReclaimResult> {
    this.assertStageMutationAuthority()
    if (
      !input ||
      typeof input !== 'object' ||
      !exactKeys(input as unknown as Record<string, unknown>, [
        'operationId',
        'result',
        'leaseId'
      ]) ||
      typeof input.leaseId !== 'string' ||
      !SHA256_PATTERN.test(input.leaseId)
    ) {
      throw new PaidMediaVaultError('Paid media stage reclaim input is invalid')
    }
    const operationId = requireOperationId(input.operationId)
    const result = parsePaidMediaAssetResult(input.result)
    const resultSha256 = paidMediaAssetResultDigest(result)
    let stage = this.loadAuthorityIndex().stageLeases.get(input.leaseId)
    const descriptor = stage ? result.assets[stage.ordinal] : undefined
    if (
      !stage ||
      !descriptor ||
      stage.operationId !== operationId ||
      stage.turnId !== result.turnId ||
      stage.resultSha256 !== resultSha256 ||
      JSON.stringify(stage.descriptor) !== JSON.stringify(descriptor)
    ) {
      throw new PaidMediaVaultError('Paid media stage reclaim binding conflicts')
    }
    if (existsSync(this.archiveFile(operationId))) {
      if (stage.state === 'held') {
        return Object.freeze({ ok: false, status: 'held' })
      }
      if (
        !['opened', 'archived_cleanup_pending', 'archived_cleaned'].includes(stage.state)
      ) {
        throw new PaidMediaVaultError('Paid media stage reclaim state conflicts')
      }
      const responseBytes = canonicalPaidMediaAssetResult(result)
      try {
        const archived = await this.verifyArchive(operationId)
        if (
          archived.receipt.responseSha256 !== sha256(responseBytes) ||
          archived.receipt.responseByteLength !== responseBytes.length ||
          !this.archivedStageReceiptMatches(stage, archived)
        ) {
          throw new PaidMediaVaultError('Paid media archived stage cleanup binding conflicts')
        }
      } catch (error) {
        this.dependencies.onCleanupError?.(error)
        if (stage.state !== 'archived_cleaned') {
          await this.revokeStageHandle(stage.leaseId)
          this.appendStageHeld(stage, 'archive_cleanup_evidence_invalid')
          return Object.freeze({ ok: false, status: 'held' })
        }
        throw error
      }
      await this.finishArchivedStageCleanup(operationId, [stage])
      stage = this.loadAuthorityIndex().stageLeases.get(input.leaseId)!
      return Object.freeze({
        ok: false,
        status:
          stage.state === 'archived_cleaned'
            ? 'cleaned'
            : stage.state === 'held'
              ? 'held'
              : 'pending'
      })
    }
    if (stage.state !== 'opened' || stage.generation >= 1_000_000) {
      throw new PaidMediaVaultError('Paid media stage reclaim state conflicts')
    }
    let inspection = this.inspectStageLeaf(stage)
    if (inspection.kind !== 'exact' || inspection.file === null) {
      await this.revokeStageHandle(stage.leaseId)
      this.appendStageHeld(
        stage,
        inspection.kind === 'mismatch' ? inspection.reasonCode : 'stage_leaf_absent'
      )
      return Object.freeze({ ok: false, status: 'held' })
    }
    if (!(await this.revokeStageHandle(stage.leaseId))) {
      return Object.freeze({ ok: false, status: 'pending' })
    }
    inspection = this.inspectStageLeaf(stage)
    if (inspection.kind !== 'exact' || inspection.file === null) {
      this.appendStageHeld(
        stage,
        inspection.kind === 'mismatch' ? inspection.reasonCode : 'stage_leaf_absent'
      )
      return Object.freeze({ ok: false, status: 'held' })
    }
    const paths = this.stagePaths(stage)
    let handle: FileHandle | null = null
    let registeredRecord: StageOpenHandleRecord | null = null
    try {
      handle = await openFile(paths.filePath, 'r+')
      const openedDirectory = this.stagePathIdentity(paths.directoryPath, true)
      const openedPath = this.stagePathIdentity(paths.filePath, false)
      const openedHandle = await this.stageHandleIdentity(handle, paths.filePath)
      if (
        !this.sameStageStableIdentity(inspection.directory, openedDirectory) ||
        !this.sameStageStableIdentity(inspection.file, openedPath) ||
        !this.sameStageStableIdentity(inspection.file, openedHandle) ||
        readdirSync(paths.directoryPath).length !== 1 ||
        readdirSync(paths.directoryPath)[0] !== STAGE_FILE_NAME
      ) {
        throw new PaidMediaVaultError('Paid media stage reclaim leaf changed while opening')
      }
      await handle.truncate(0)
      await handle.sync()
      this.assertStageRootStable(paths.tempRootPath, stage.tempRoot)
      const finalDirectory = this.stagePathIdentity(paths.directoryPath, true)
      const finalPath = this.stagePathIdentity(paths.filePath, false)
      const finalHandle = await this.stageHandleIdentity(handle, paths.filePath)
      if (
        !this.sameStageStableIdentity(openedDirectory, finalDirectory) ||
        !this.sameStageStableIdentity(openedHandle, finalPath) ||
        !this.sameStageStableIdentity(openedHandle, finalHandle) ||
        finalHandle.size !== '0' ||
        readdirSync(paths.directoryPath).length !== 1 ||
        readdirSync(paths.directoryPath)[0] !== STAGE_FILE_NAME
      ) {
        throw new PaidMediaVaultError('Paid media stage reclaim leaf changed before commit')
      }
      const reclaimed = this.makeStageTransition(
        stage,
        'opened',
        finalDirectory,
        finalHandle,
        null,
        stage.generation + 1
      )
      this.appendStageAuthorityEvent(reclaimed)
      const record: StageOpenHandleRecord = {
        leaseId: reclaimed.leaseId,
        operationId: reclaimed.operationId,
        turnId: reclaimed.turnId,
        ordinal: reclaimed.ordinal,
        generation: reclaimed.generation,
        descriptor: reclaimed.descriptor,
        handle,
        filePath: paths.filePath,
        directoryPath: paths.directoryPath,
        tempRootPath: paths.tempRootPath,
        tempRootIdentity: reclaimed.tempRoot,
        directoryIdentity: finalDirectory,
        fileIdentity: finalHandle,
        offset: 0,
        digest: createHash('sha256'),
        state: 'open',
        witness: Object.freeze({})
      }
      registeredRecord = record
      this.stageOpenHandles.set(reclaimed.leaseId, record)
      this.stageHandleHook('opened', record)
      handle = null
      return Object.freeze({ ok: true, capability: this.mintStageWriteCapability(record) })
    } catch (error) {
      this.dependencies.onCleanupError?.(error)
      if (registeredRecord) {
        registeredRecord.state = 'revoked'
        if (this.stageOpenHandles.get(registeredRecord.leaseId) === registeredRecord) {
          this.stageOpenHandles.delete(registeredRecord.leaseId)
        }
      }
      await handle?.close().catch(() => undefined)
      if (!this.authorityIndexPoisoned) {
        const current = this.loadAuthorityIndex().stageLeases.get(stage.leaseId)
        if (current?.state === 'opened') {
          const after = this.inspectStageLeaf(current)
          this.appendStageHeld(
            current,
            after.kind === 'mismatch' ? after.reasonCode : 'stage_reclaim_failed'
          )
          return Object.freeze({ ok: false, status: 'held' })
        }
      }
      throw error
    }
  }

  async cleanupStageLease(input: {
    operationId: string
    leaseId: string
    generation: number
    resultSha256: string
  }): Promise<{ status: 'cleaned' | 'pending' | 'held' }> {
    this.assertStageMutationAuthority()
    if (
      !input ||
      typeof input !== 'object' ||
      !exactKeys(input as unknown as Record<string, unknown>, [
        'operationId',
        'leaseId',
        'generation',
        'resultSha256'
      ])
    ) {
      throw new PaidMediaVaultError('Paid media stage cleanup input is invalid')
    }
    const operationId = requireOperationId(input.operationId)
    const leaseId = input.leaseId
    if (
      typeof leaseId !== 'string' ||
      !SHA256_PATTERN.test(leaseId) ||
      !Number.isSafeInteger(input.generation) ||
      input.generation < 0 ||
      typeof input.resultSha256 !== 'string' ||
      !SHA256_PATTERN.test(input.resultSha256) ||
      input.resultSha256 === ZERO_SHA256
    ) {
      throw new PaidMediaVaultError('Paid media stage cleanup binding is invalid')
    }
    let stage = this.loadAuthorityIndex().stageLeases.get(leaseId)
    if (!stage) throw new PaidMediaVaultError('Paid media stage lease is unknown')
    if (
      stage.operationId !== operationId ||
      stage.generation !== input.generation ||
      stage.resultSha256 !== input.resultSha256
    ) {
      throw new PaidMediaVaultError('Paid media stage cleanup operation binding conflicts')
    }
    if (stage.state === 'aborted_cleaned' || stage.state === 'archived_cleaned') {
      return { status: 'cleaned' }
    }
    if (stage.state === 'held') return { status: 'held' }
    if (stage.state === 'opened' && existsSync(this.archiveFile(stage.operationId))) {
      try {
        const archived = await this.verifyArchive(stage.operationId)
        if (!this.archivedStageReceiptMatches(stage, archived)) {
          throw new PaidMediaVaultError('Paid media archived stage cleanup binding conflicts')
        }
      } catch (error) {
        this.dependencies.onCleanupError?.(error)
        await this.revokeStageHandle(stage.leaseId)
        this.appendStageHeld(stage, 'archive_cleanup_evidence_invalid')
        return { status: 'held' }
      }
      stage = this.makeStageTransition(
        stage,
        'archived_cleanup_pending',
        stage.directory,
        stage.file,
        'archive_committed'
      )
      this.appendStageAuthorityEvent(stage)
    }
    if (
      stage.state !== 'aborted_cleanup_pending' &&
      stage.state !== 'archived_cleanup_pending'
    ) {
      let directory = stage.directory
      let file = stage.file
      if (stage.state === 'reserved') {
        const inspection = this.inspectStageLeaf(stage)
        if (inspection.kind === 'mismatch') {
          this.appendStageHeld(stage, inspection.reasonCode)
          return { status: 'held' }
        }
        if (inspection.kind === 'exact') {
          this.appendStageHeld(stage, 'unproven_stage_leaf')
          return { status: 'held' }
        }
        directory = null
        file = null
      }
      stage = this.makeStageTransition(
        stage,
        'aborted_cleanup_pending',
        directory,
        file,
        'cleanup_requested'
      )
      this.appendStageAuthorityEvent(stage)
    }
    return { status: await this.performPendingStageCleanup(stage) }
  }

  async inspectStageRecovery(): Promise<PaidMediaStageRecoveryInspection> {
    const index = this.loadAuthorityIndex()
    const leases = [...index.activeStageLeases.values()]
      .sort(
        (left, right) =>
          left.operationId.localeCompare(right.operationId, 'en') || left.ordinal - right.ordinal
      )
      .map((stage): PaidMediaStageRecoveryLease => {
        if (stage.state === 'held') {
          return {
            leaseId: stage.leaseId,
            operationId: stage.operationId,
            turnId: stage.turnId,
            ordinal: stage.ordinal,
            generation: stage.generation,
            resultSha256: stage.resultSha256,
            leaseStateDigest: stage.leaseStateDigest,
            state: stage.state,
            disposition: 'manual_only',
            reasonCode: stage.reasonCode
          }
        }
        const inspection = this.inspectStageLeaf(stage)
        const usable = inspection.kind === 'exact'
        const absent = inspection.kind === 'absent'
        const disposition =
          stage.state === 'reserved'
            ? absent
              ? 'cleanup'
              : 'manual_only'
            : stage.state === 'opened'
              ? usable && inspection.file !== null
                ? 'reclaim'
                : 'manual_only'
              : usable || absent
                ? 'cleanup'
                : 'manual_only'
        return {
          leaseId: stage.leaseId,
          operationId: stage.operationId,
          turnId: stage.turnId,
          ordinal: stage.ordinal,
          generation: stage.generation,
          resultSha256: stage.resultSha256,
          leaseStateDigest: stage.leaseStateDigest,
          state: stage.state,
          disposition,
          reasonCode:
            disposition === 'manual_only' && inspection.kind === 'mismatch'
              ? inspection.reasonCode
              : stage.reasonCode
        }
      })
    return Object.freeze({
      leases: Object.freeze(leases),
      requiresRootMutation: true,
      ageBasedDecision: false
    })
  }

  private normalizeLegacyImportReceiptInput(input: {
    decisionSha256: string
    operationId: string
  }): LegacyImportReceiptBase {
    if (
      !input ||
      typeof input !== 'object' ||
      !exactKeys(input as unknown as Record<string, unknown>, [
        'decisionSha256',
        'operationId'
      ]) ||
      typeof input.decisionSha256 !== 'string' ||
      !SHA256_PATTERN.test(input.decisionSha256)
    ) {
      throw new PaidMediaVaultError('Paid media legacy import receipt input is invalid')
    }
    return {
      schema: LEGACY_IMPORT_RECEIPT_SCHEMA,
      decisionSha256: input.decisionSha256,
      operationId: requireOperationId(input.operationId)
    }
  }

  private legacyImportReceiptDigest(base: LegacyImportReceiptBase): string {
    return createHash('sha256')
      .update(LEGACY_IMPORT_RECEIPT_DOMAIN)
      .update(JSON.stringify(base), 'utf8')
      .digest('hex')
  }

  private legacyImportReceiptFile(decisionSha256: string): string {
    if (!SHA256_PATTERN.test(decisionSha256)) {
      throw new PaidMediaVaultError('Paid media legacy import decision digest is invalid')
    }
    return join(this.legacyImportsPath, `${decisionSha256}.json`)
  }

  private readLegacyImportReceipt(path: string): LegacyImportReceipt {
    const value = this.decodeEncrypted(
      this.readRegular(path, MAX_ENCRYPTED_DOCUMENT_BYTES, 'Paid media legacy import receipt'),
      'Paid media legacy import receipt'
    )
    if (
      !exactKeys(value, ['schema', 'decisionSha256', 'operationId', 'receiptSha256']) ||
      value.schema !== LEGACY_IMPORT_RECEIPT_SCHEMA ||
      typeof value.decisionSha256 !== 'string' ||
      !SHA256_PATTERN.test(value.decisionSha256) ||
      typeof value.operationId !== 'string' ||
      !OPERATION_ID_PATTERN.test(value.operationId) ||
      typeof value.receiptSha256 !== 'string' ||
      !SHA256_PATTERN.test(value.receiptSha256)
    ) {
      throw new PaidMediaVaultError('Paid media legacy import receipt is invalid')
    }
    const base: LegacyImportReceiptBase = {
      schema: LEGACY_IMPORT_RECEIPT_SCHEMA,
      decisionSha256: value.decisionSha256,
      operationId: value.operationId.toLowerCase()
    }
    if (value.receiptSha256 !== this.legacyImportReceiptDigest(base)) {
      throw new PaidMediaVaultError('Paid media legacy import receipt digest does not match')
    }
    return { ...base, receiptSha256: value.receiptSha256 }
  }

  async hasLegacyImportReceipt(input: {
    decisionSha256: string
    operationId: string
  }): Promise<boolean> {
    this.prepare()
    const expected = this.normalizeLegacyImportReceiptInput(input)
    const path = this.legacyImportReceiptFile(expected.decisionSha256)
    if (!existsSync(path)) return false
    const receipt = this.readLegacyImportReceipt(path)
    if (
      receipt.decisionSha256 !== expected.decisionSha256 ||
      receipt.operationId !== expected.operationId
    ) {
      throw new PaidMediaVaultError('Paid media legacy import receipt conflicts with the seal')
    }
    return true
  }

  async recordLegacyImportReceipt(input: {
    decisionSha256: string
    operationId: string
  }): Promise<void> {
    this.prepare()
    const base = this.normalizeLegacyImportReceiptInput(input)
    const path = this.legacyImportReceiptFile(base.decisionSha256)
    if (existsSync(path)) {
      await this.hasLegacyImportReceipt(input)
      return
    }
    const receipt: LegacyImportReceipt = {
      ...base,
      receiptSha256: this.legacyImportReceiptDigest(base)
    }
    this.writeAtomicNew(
      path,
      this.encodeEncrypted(receipt),
      'Paid media legacy import receipt'
    )
  }

  private registeredAuthorityEntry(path: string): VaultAuthorityEntry | null {
    if (!this.authorityStrict) return null
    const absolute = resolve(path)
    const relativePath = relative(this.root, absolute).replace(/\\/g, '/')
    if (!relativePath || relativePath === '..' || relativePath.startsWith('../')) return null
    const entry = this.loadAuthorityIndex().entries.get(relativePath)
    if (!entry) {
      throw new PaidMediaVaultError('Paid media vault file is not registered by authority')
    }
    return entry
  }

  private hasRegisteredAuthorityEntry(path: string): boolean {
    if (!this.authorityStrict) return false
    const absolute = resolve(path)
    const relativePath = relative(this.root, absolute).replace(/\\/g, '/')
    if (!relativePath || relativePath === '..' || relativePath.startsWith('../')) {
      return false
    }
    return this.loadAuthorityIndex().entries.has(relativePath)
  }

  private async verifyUnregisteredStageAssetForAdoption(input: {
    path: string
    mediaType: PaidMediaImageType
    byteLength: number
    sha256: string
  }): Promise<void> {
    const before = this.hardenIfChanged(input.path, false)
    if (before.size !== input.byteLength) {
      throw new PaidMediaVaultError('Paid media uncommitted stage asset length conflicts')
    }
    const identity = this.verifiedAssetIdentity(before)
    const handle = await openFile(input.path, 'r')
    try {
      const pinned = await handle.stat()
      if (
        !pinned.isFile() ||
        !this.sameVerifiedAssetIdentity(identity, this.verifiedAssetIdentity(pinned))
      ) {
        throw new PaidMediaVaultError('Paid media uncommitted stage asset changed before pin')
      }
      const hash = createHash('sha256')
      const image = new BoundedImageStreamVerifier(input.mediaType, input.byteLength)
      let byteLength = 0
      for await (const value of handle.createReadStream({
        start: 0,
        end: pinned.size - 1,
        autoClose: false,
        highWaterMark: PAID_MEDIA_STAGE_STREAM_CHUNK_BYTES
      })) {
        const chunk = Buffer.isBuffer(value) ? value : Buffer.from(value)
        byteLength += chunk.length
        if (byteLength > input.byteLength) {
          throw new PaidMediaVaultError('Paid media uncommitted stage asset exceeded its length')
        }
        hash.update(chunk)
        image.update(chunk)
      }
      image.finish()
      const after = await handle.stat()
      if (
        byteLength !== input.byteLength ||
        hash.digest('hex') !== input.sha256 ||
        !this.sameVerifiedAssetIdentity(
          this.verifiedAssetIdentity(pinned),
          this.verifiedAssetIdentity(after)
        )
      ) {
        throw new PaidMediaVaultError('Paid media uncommitted stage asset evidence conflicts')
      }
    } finally {
      await handle.close().catch(() => undefined)
    }
  }

  private readRegular(path: string, maxBytes: number, label: string): Buffer {
    const registered = this.registeredAuthorityEntry(path)
    const parentInfo = this.hardenIfChanged(dirname(path), true)
    this.assertPathKind(parentInfo, true, 'Paid media vault directory')
    if (!existsSync(path)) throw new PaidMediaVaultError(`${label} is missing`)
    const before = this.hardenIfChanged(path, false)
    if (!before.isFile() || before.isSymbolicLink() || before.size < 1 || before.size > maxBytes) {
      throw new PaidMediaVaultError(`${label} is redirected or exceeds its size limit`)
    }
    const handle = openSync(path, 'r')
    try {
      const pinned = fstatSync(handle)
      if (
        !pinned.isFile() ||
        pinned.dev !== before.dev ||
        pinned.ino !== before.ino ||
        pinned.birthtimeMs !== before.birthtimeMs ||
        pinned.mtimeMs !== before.mtimeMs ||
        pinned.ctimeMs !== before.ctimeMs ||
        pinned.size !== before.size ||
        pinned.size < 1 ||
        pinned.size > maxBytes
      ) {
        throw new PaidMediaVaultError(`${label} changed before it was pinned`)
      }
      const bytes = Buffer.allocUnsafe(pinned.size)
      let offset = 0
      while (offset < bytes.length) {
        const received = readSync(handle, bytes, offset, bytes.length - offset, offset)
        if (received < 1) throw new PaidMediaVaultError(`${label} is truncated`)
        offset += received
      }
      const after = fstatSync(handle)
      if (
        after.dev !== pinned.dev ||
        after.ino !== pinned.ino ||
        after.birthtimeMs !== pinned.birthtimeMs ||
        after.mtimeMs !== pinned.mtimeMs ||
        after.ctimeMs !== pinned.ctimeMs ||
        after.size !== pinned.size
      ) {
        throw new PaidMediaVaultError(`${label} changed while reading`)
      }
      if (
        registered &&
        (registered.byteLength !== bytes.length || registered.sha256 !== sha256(bytes))
      ) {
        throw new PaidMediaVaultError(`${label} does not match its authority entry`)
      }
      return bytes
    } finally {
      closeSync(handle)
    }
  }

  private writeAtomicNew(
    path: string,
    bytes: Buffer,
    label: string,
    maxBytes = MAX_ENCRYPTED_DOCUMENT_BYTES
  ): void {
    this.assertMutationAllowed()
    // Refuse ordinary mutations before touching the filesystem whenever an
    // unresolved authority tail (or same-instance poison) exists. Only the
    // explicit tail recovery API may cross that boundary.
    if (this.authorityStrict) this.loadAuthorityIndex()
    if (bytes.length < 1 || bytes.length > maxBytes) {
      throw new PaidMediaVaultError(`${label} exceeds its size limit`)
    }
    this.ensureDirectory(dirname(path))
    if (existsSync(path)) throw new PaidMediaVaultError(`${label} already exists`)
    const temporary = join(
      dirname(path),
      `.${basename(path)}.${process.pid}.${randomBytes(8).toString('hex')}.tmp`
    )
    let handle: number | null = null
    try {
      handle = openSync(temporary, 'wx', 0o600)
      writeFileSync(handle, bytes)
      fsyncSync(handle)
      closeSync(handle)
      handle = null
      this.hardenIfChanged(temporary, false)
      const temporaryIdentity = this.hardenedPaths.get(resolve(temporary))
      try {
        // link(2) is an atomic create-only publication: unlike rename on
        // Windows it never replaces a destination created by a racing writer.
        linkSync(temporary, path)
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'EEXIST') {
          throw new PaidMediaVaultError(`${label} already exists`, { cause: error })
        }
        throw error
      }
      unlinkSync(temporary)
      const committedInfo = lstatSync(path)
      this.assertPathKind(committedInfo, false, label)
      const committedIdentity = this.pathIdentity(committedInfo, false)
      if (!this.samePathIdentity(temporaryIdentity, committedIdentity)) {
        this.hardenIfChanged(path, false, committedInfo)
      } else {
        // ACLs belong to the file object, so publishing the same inode through
        // a hard link preserves hardening. Transfer the cache key instead of
        // spawning a second synchronous ACL process.
        this.hardenedPaths.set(resolve(path), committedIdentity)
      }
      this.hardenedPaths.delete(resolve(temporary))
      // The temporary file descriptor was fsynced before create-only publish.
      // Reopening a file read-only and fsyncing it fails with EPERM on
      // Windows, while adding no byte durability beyond the flushed inode.
      this.recordAuthorityCreate(path, bytes)
    } catch (error) {
      if (handle !== null) closeSync(handle)
      try {
        unlinkSync(temporary)
      } catch {
        // The temporary file may already have been atomically renamed.
      }
      this.hardenedPaths.delete(resolve(temporary))
      if (error instanceof PaidMediaVaultError) throw error
      throw new PaidMediaVaultError(`${label} could not be committed`, { cause: error })
    }
  }

  private encodeEncrypted(document: unknown): Buffer {
    requireEncryption(this.dependencies.safeStorage)
    const plaintext = JSON.stringify(document)
    const encrypted = this.dependencies.safeStorage.encryptString(plaintext)
    if (!Buffer.isBuffer(encrypted) || encrypted.length < 1) {
      throw new PaidMediaVaultError('Paid media vault encryption failed')
    }
    return Buffer.from(
      JSON.stringify({
        schema: ENVELOPE_SCHEMA,
        protection: PROTECTION,
        ciphertext: encrypted.toString('base64')
      }),
      'utf8'
    )
  }

  private decodeEncrypted(bytes: Buffer, label: string): Record<string, unknown> {
    requireEncryption(this.dependencies.safeStorage)
    const envelope = parseObject(bytes.toString('utf8'), `${label} envelope`)
    if (
      !exactKeys(envelope, ['schema', 'protection', 'ciphertext']) ||
      envelope.schema !== ENVELOPE_SCHEMA ||
      envelope.protection !== PROTECTION
    ) {
      throw new PaidMediaVaultError(`${label} envelope is invalid`)
    }
    const ciphertext = decodeCanonicalBase64(
      envelope.ciphertext,
      MAX_ENCRYPTED_DOCUMENT_BYTES,
      `${label} ciphertext`
    )
    let plaintext: string
    try {
      plaintext = this.dependencies.safeStorage.decryptString(ciphertext)
    } catch (error) {
      throw new PaidMediaVaultError(`${label} decryption failed`, { cause: error })
    }
    return parseObject(plaintext, label)
  }

  private readValidationSidecar(asset: Pick<PaidMediaArchivedAsset, 'sha256' | 'mediaType' | 'byteLength'>): PaidMediaValidationReceipt | null {
    const path = this.assetValidationFile(asset.sha256)
    if (!existsSync(path)) return null
    const value = this.decodeEncrypted(
      this.readRegular(path, MAX_ENCRYPTED_DOCUMENT_BYTES, 'Paid media asset validation sidecar'),
      'Paid media asset validation sidecar'
    )
    if (
      !exactKeys(value, ['schema', 'assetSha256', 'validation', 'sidecarSha256']) ||
      value.schema !== VALIDATION_SIDECAR_SCHEMA ||
      value.assetSha256 !== asset.sha256 ||
      typeof value.sidecarSha256 !== 'string' ||
      !SHA256_PATTERN.test(value.sidecarSha256)
    ) {
      throw new PaidMediaVaultError('Paid media asset validation sidecar is invalid')
    }
    const validation = parseTrustedValidationReceipt(value.validation, asset)
    const base: ValidationSidecarBase = {
      schema: VALIDATION_SIDECAR_SCHEMA,
      assetSha256: asset.sha256,
      validation
    }
    if (sha256(JSON.stringify(base)) !== value.sidecarSha256) {
      throw new PaidMediaVaultError('Paid media asset validation sidecar digest does not match')
    }
    return validation
  }

  private writeValidationSidecar(
    asset: Pick<PaidMediaArchivedAsset, 'sha256' | 'mediaType' | 'byteLength'>,
    validation: PaidMediaValidationReceipt
  ): void {
    const existing = this.readValidationSidecar(asset)
    if (existing) {
      if (JSON.stringify(existing) !== JSON.stringify(validation)) {
        throw new PaidMediaVaultError('Paid media asset validation sidecar conflicts')
      }
      return
    }
    const base: ValidationSidecarBase = {
      schema: VALIDATION_SIDECAR_SCHEMA,
      assetSha256: asset.sha256,
      validation
    }
    const document: ValidationSidecarDocument = {
      ...base,
      sidecarSha256: sha256(JSON.stringify(base))
    }
    try {
      this.writeAtomicNew(
        this.assetValidationFile(asset.sha256),
        this.encodeEncrypted(document),
        'Paid media asset validation sidecar'
      )
    } catch (error) {
      const raced = this.readValidationSidecar(asset)
      if (!raced || JSON.stringify(raced) !== JSON.stringify(validation)) throw error
    }
  }

  private requireTrustedAssetValidation(
    asset: PaidMediaArchivedAsset
  ): PaidMediaValidationReceipt {
    if (asset.validation?.schema === TRUSTED_VALIDATION_SCHEMA) return asset.validation
    const migrated = this.readValidationSidecar(asset)
    if (migrated) return migrated
    throw new PaidMediaVaultError(
      'Paid media trusted v2 validation receipt is missing; explicit startup migration is required'
    )
  }

  private collectValidationMigrationSources(): ValidationMigrationSourceSnapshot {
    this.prepare()
    const sources: ValidationMigrationSource[] = []
    const append = (
      directory: string,
      kind: 'archive' | 'terminal',
      validName: (name: string) => boolean
    ): void => {
      this.dependencies.onValidationMigrationDirectoryEnumeration?.(directory)
      for (const entry of readdirSync(directory, { withFileTypes: true })) {
        if (!entry.isFile() || entry.isSymbolicLink() || !validName(entry.name)) {
          throw new PaidMediaVaultError(
            'Paid media validation migration source set is invalid'
          )
        }
        if (sources.length >= MAX_AUTHORITY_EVIDENCE_ENTRIES) {
          throw new PaidMediaVaultError(
            'Paid media validation migration source set is too large'
          )
        }
        const path = join(directory, entry.name)
        const info = this.hardenIfChanged(path, false)
        if (
          !Number.isFinite(info.dev) ||
          info.dev < 0 ||
          !Number.isFinite(info.ino) ||
          info.ino < 0 ||
          !Number.isFinite(info.birthtimeMs) ||
          !Number.isFinite(info.mtimeMs) ||
          !Number.isFinite(info.ctimeMs) ||
          !Number.isSafeInteger(info.size) ||
          info.size < 0
        ) {
          throw new PaidMediaVaultError(
            'Paid media validation migration source identity is invalid'
          )
        }
        sources.push({
          key: `${kind}/${entry.name}`,
          kind,
          name: entry.name,
          path,
          dev: info.dev,
          ino: info.ino,
          birthtimeMs: info.birthtimeMs,
          mtimeMs: info.mtimeMs,
          ctimeMs: info.ctimeMs,
          size: info.size
        })
      }
    }
    append(
      this.archivesPath,
      'archive',
      (name) => name.endsWith('.json') && OPERATION_ID_PATTERN.test(name.slice(0, -5))
    )
    append(
      this.videoTerminalsPath,
      'terminal',
      (name) => name.endsWith('.json') && SHA256_PATTERN.test(name.slice(0, -5))
    )
    sources.sort((left, right) => left.key.localeCompare(right.key, 'en'))
    const digest = sha256(
      JSON.stringify(
        sources.map(({ key, dev, ino, birthtimeMs, mtimeMs, ctimeMs, size }) => ({
          key,
          dev,
          ino,
          birthtimeMs,
          mtimeMs,
          ctimeMs,
          size
        }))
      )
    )
    return { digest, sources }
  }

  private readValidationMigrationSource(source: {
    kind: 'archive' | 'terminal'
    name: string
    path: string
  }): { receiptSha256: string; assets: PaidMediaArchivedAsset[] } {
    if (source.kind === 'archive') {
      const document = this.parseArchive(
        this.decodeEncrypted(
          this.readRegular(
            source.path,
            MAX_ENCRYPTED_DOCUMENT_BYTES,
            'Paid media validation migration archive'
          ),
          'Paid media validation migration archive'
        )
      )
      if (`${document.operationId}.json` !== source.name) {
        throw new PaidMediaVaultError('Paid media validation migration archive name conflicts')
      }
      return { receiptSha256: document.receiptSha256, assets: document.assets }
    }
    const document = this.parseTerminal(
      this.decodeEncrypted(
        this.readRegular(
          source.path,
          MAX_ENCRYPTED_DOCUMENT_BYTES,
          'Paid media validation migration terminal'
        ),
        'Paid media validation migration terminal'
      )
    )
    if (`${document.taskAliasSha256}.json` !== source.name) {
      throw new PaidMediaVaultError('Paid media validation migration terminal name conflicts')
    }
    return {
      receiptSha256: document.receiptSha256,
      assets: document.asset === null ? [] : [document.asset]
    }
  }

  private validationMigrationPlanSha256(
    source: PaidMediaValidationMigrationPlan['source'],
    asset: PaidMediaValidationMigrationPlan['asset'],
    validation: PaidMediaValidationReceipt
  ): string {
    return sha256(JSON.stringify({ source, asset, validation }))
  }

  async prepareTrustedValidationMigrationBatch(
    input: { cursor?: string; limit?: number } = {}
  ): Promise<PaidMediaValidationMigrationBatch> {
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
      throw new PaidMediaVaultError('Paid media validation migration request is invalid')
    }
    const raw = input as Record<string, unknown>
    if (
      Object.keys(raw).some((key) => key !== 'cursor' && key !== 'limit') ||
      (raw.cursor !== undefined &&
        (typeof raw.cursor !== 'string' ||
          !/^[0-9a-f]{64}:[1-9][0-9]{0,6}$/.test(raw.cursor))) ||
      (raw.limit !== undefined &&
        (!Number.isSafeInteger(raw.limit) ||
          Number(raw.limit) < 1 ||
          Number(raw.limit) > MAX_VALIDATION_MIGRATION_PAGE))
    ) {
      throw new PaidMediaVaultError('Paid media validation migration request is invalid')
    }
    let start = 0
    let snapshot: ValidationMigrationSourceSnapshot
    if (raw.cursor === undefined) {
      this.validationMigrationSourceCache = null
      snapshot = this.collectValidationMigrationSources()
      this.validationMigrationSourceCache = snapshot
    } else {
      const [digest, rawIndex] = (raw.cursor as string).split(':')
      const index = Number(rawIndex)
      snapshot = this.validationMigrationSourceCache as ValidationMigrationSourceSnapshot
      if (
        !snapshot ||
        snapshot.digest !== digest ||
        !Number.isSafeInteger(index) ||
        index < 1 ||
        index >= snapshot.sources.length
      ) {
        throw new PaidMediaVaultError('Paid media validation migration cursor is stale')
      }
      start = index
    }
    const sources = snapshot.sources
    const limit = (raw.limit as number | undefined) ?? DEFAULT_VALIDATION_MIGRATION_PAGE
    const selected = sources.slice(start, start + limit)
    const plans = new Map<string, PaidMediaValidationMigrationPlan>()
    let probeReady = false
    for (const source of selected) {
      const receipt = this.readValidationMigrationSource(source)
      for (const asset of receipt.assets) {
        if (
          asset.validation?.schema === TRUSTED_VALIDATION_SCHEMA ||
          this.readValidationSidecar(asset) !== null
        ) {
          continue
        }
        const duplicate = plans.get(asset.sha256)
        if (duplicate) {
          if (
            duplicate.asset.reference !== asset.reference ||
            duplicate.asset.mediaType !== asset.mediaType ||
            duplicate.asset.byteLength !== asset.byteLength
          ) {
            throw new PaidMediaVaultError(
              'Paid media validation migration duplicate asset conflicts'
            )
          }
          continue
        }
        if (!probeReady) {
          await this.ensureMediaProbeReady()
          probeReady = true
        }
        const opened = await this.openAsset(asset.reference)
        let validation: PaidMediaValidationReceipt
        try {
          if (
            opened.byteLength !== asset.byteLength ||
            opened.sha256 !== asset.sha256 ||
            opened.mediaType !== asset.mediaType
          ) {
            throw new PaidMediaVaultError(
              'Paid media validation migration asset does not match its receipt'
            )
          }
          validation = await this.validateTrustedMedia({
            createReadStream: () =>
              opened.handle.createReadStream({
                start: 0,
                end: asset.byteLength - 1,
                autoClose: false,
                highWaterMark: 1024 * 1024
              }),
            mediaType: asset.mediaType,
            byteLength: asset.byteLength,
            sha256: asset.sha256
          })
        } finally {
          await opened.handle.close().catch(() => undefined)
        }
        const sourceProof = {
          kind: source.kind,
          name: source.name,
          receiptSha256: receipt.receiptSha256
        } as const
        const assetProof = {
          reference: asset.reference,
          mediaType: asset.mediaType,
          byteLength: asset.byteLength,
          sha256: asset.sha256
        }
        plans.set(asset.sha256, {
          source: sourceProof,
          asset: assetProof,
          validation,
          planSha256: this.validationMigrationPlanSha256(
            sourceProof,
            assetProof,
            validation
          )
        })
      }
    }
    const items = [...plans.values()]
    if (items.length > MAX_VALIDATION_MIGRATION_PLANS) {
      throw new PaidMediaVaultError('Paid media validation migration batch is too large')
    }
    const hasMore = start + selected.length < sources.length
    if (!hasMore) {
      try {
        const finalSnapshot = this.collectValidationMigrationSources()
        if (finalSnapshot.digest !== snapshot.digest) {
          throw new PaidMediaVaultError(
            'Paid media validation migration source snapshot changed'
          )
        }
      } finally {
        this.validationMigrationSourceCache = null
      }
    }
    return {
      items,
      ...(hasMore && selected.length > 0
        ? { nextCursor: `${snapshot.digest}:${start + selected.length}` }
        : {})
    }
  }

  async commitTrustedValidationMigrations(
    plans: readonly PaidMediaValidationMigrationPlan[]
  ): Promise<{ committed: number; alreadyPresent: number }> {
    if (!Array.isArray(plans) || plans.length < 1 || plans.length > MAX_VALIDATION_MIGRATION_PLANS) {
      throw new PaidMediaVaultError('Paid media validation migration plan set is invalid')
    }
    this.prepare()
    let committed = 0
    let alreadyPresent = 0
    for (const rawPlan of plans) {
      if (!rawPlan || typeof rawPlan !== 'object' || Array.isArray(rawPlan)) {
        throw new PaidMediaVaultError('Paid media validation migration plan is invalid')
      }
      const plan = rawPlan as PaidMediaValidationMigrationPlan
      if (
        !exactKeys(plan as unknown as Record<string, unknown>, [
          'source',
          'asset',
          'validation',
          'planSha256'
        ]) ||
        !plan.source ||
        !exactKeys(plan.source as unknown as Record<string, unknown>, [
          'kind',
          'name',
          'receiptSha256'
        ]) ||
        (plan.source.kind !== 'archive' && plan.source.kind !== 'terminal') ||
        typeof plan.source.name !== 'string' ||
        !SHA256_PATTERN.test(plan.source.receiptSha256) ||
        !plan.asset ||
        !exactKeys(plan.asset as unknown as Record<string, unknown>, [
          'reference',
          'mediaType',
          'byteLength',
          'sha256'
        ]) ||
        typeof plan.planSha256 !== 'string' ||
        !SHA256_PATTERN.test(plan.planSha256)
      ) {
        throw new PaidMediaVaultError('Paid media validation migration plan is invalid')
      }
      const validation = parseTrustedValidationReceipt(plan.validation, plan.asset)
      if (
        this.validationMigrationPlanSha256(plan.source, plan.asset, validation) !==
        plan.planSha256
      ) {
        throw new PaidMediaVaultError('Paid media validation migration plan digest conflicts')
      }
      const directory =
        plan.source.kind === 'archive' ? this.archivesPath : this.videoTerminalsPath
      const sourcePath = join(directory, plan.source.name)
      if (basename(sourcePath) !== plan.source.name || !existsSync(sourcePath)) {
        throw new PaidMediaVaultError('Paid media validation migration source is missing')
      }
      const source = this.readValidationMigrationSource({
        kind: plan.source.kind,
        name: plan.source.name,
        path: sourcePath
      })
      if (
        source.receiptSha256 !== plan.source.receiptSha256 ||
        !source.assets.some(
          (asset) =>
            asset.reference === plan.asset.reference &&
            asset.mediaType === plan.asset.mediaType &&
            asset.byteLength === plan.asset.byteLength &&
            asset.sha256 === plan.asset.sha256
        )
      ) {
        throw new PaidMediaVaultError('Paid media validation migration source changed')
      }
      const opened = await this.openAsset(plan.asset.reference)
      try {
        if (
          opened.byteLength !== plan.asset.byteLength ||
          opened.sha256 !== plan.asset.sha256 ||
          opened.mediaType !== plan.asset.mediaType
        ) {
          throw new PaidMediaVaultError('Paid media validation migration pinned asset changed')
        }
        const existing = this.readValidationSidecar(plan.asset)
        if (existing) {
          if (JSON.stringify(existing) !== JSON.stringify(validation)) {
            throw new PaidMediaVaultError('Paid media validation migration sidecar conflicts')
          }
          alreadyPresent += 1
          continue
        }
        this.writeValidationSidecar(plan.asset, validation)
        committed += 1
      } finally {
        await opened.handle.close().catch(() => undefined)
      }
    }
    return { committed, alreadyPresent }
  }

  private claimFile(operationId: string): string {
    return join(this.claimsPath, `${requireOperationId(operationId)}.json`)
  }

  private assetV2DispatchFile(operationId: string): string {
    return join(
      this.claimsPath,
      `${requireOperationId(operationId)}.asset-v2-dispatch.json`
    )
  }

  private assetAckIntentFile(operationId: string): string {
    return join(
      this.claimsPath,
      `${requireOperationId(operationId)}.asset-ack-intent.json`
    )
  }

  private assetAckCompletionFile(operationId: string): string {
    return join(
      this.claimsPath,
      `${requireOperationId(operationId)}.asset-ack-completion.json`
    )
  }

  private assetCapacityReleaseFile(operationId: string): string {
    return join(
      this.claimsPath,
      `${requireOperationId(operationId)}.asset-capacity-release.json`
    )
  }

  private archiveFile(operationId: string): string {
    return join(this.archivesPath, `${requireOperationId(operationId)}.json`)
  }

  private assetValidationFile(assetSha256: string): string {
    if (!SHA256_PATTERN.test(assetSha256)) {
      throw new PaidMediaVaultError('Paid media asset validation digest is invalid')
    }
    return join(this.assetValidationsPath, `${assetSha256}.trusted-v2.json`)
  }

  private discoveryFile(archivedAt: number, operationId: string): string {
    if (!Number.isSafeInteger(archivedAt) || archivedAt < 0) {
      throw new PaidMediaVaultError('Paid media archive discovery time is invalid')
    }
    return join(
      this.discoveriesPath,
      `${String(archivedAt).padStart(16, '0')}_${requireOperationId(operationId)}.json`
    )
  }

  private requestModel(encodedBody: string): string {
    const request = parseObject(encodedBody, 'Paid media vault request model')
    if (
      typeof request.model !== 'string' ||
      request.model.length < 1 ||
      Buffer.byteLength(request.model, 'utf8') > MAX_MODEL_ID_BYTES
    ) {
      throw new PaidMediaVaultError('Paid media vault request model is invalid')
    }
    return request.model
  }

  private parseDiscovery(value: Record<string, unknown>): DiscoveryDocument {
    if (
      !exactKeys(value, [
        'schema',
        'operationId',
        'path',
        'model',
        'status',
        'kind',
        'archivedAt',
        'receiptSha256',
        'responseByteLength',
        'assets',
        'discoverySha256'
      ]) ||
      value.schema !== DISCOVERY_SCHEMA ||
      typeof value.operationId !== 'string' ||
      !OPERATION_ID_PATTERN.test(value.operationId) ||
      !validPath(value.path) ||
      typeof value.model !== 'string' ||
      value.model.length < 1 ||
      Buffer.byteLength(value.model, 'utf8') > MAX_MODEL_ID_BYTES ||
      !Number.isSafeInteger(value.status) ||
      Number(value.status) < 200 ||
      Number(value.status) > 299 ||
      (value.kind !== 'image' && value.kind !== 'video_task') ||
      !Number.isSafeInteger(value.archivedAt) ||
      Number(value.archivedAt) < 0 ||
      typeof value.receiptSha256 !== 'string' ||
      !SHA256_PATTERN.test(value.receiptSha256) ||
      !Number.isSafeInteger(value.responseByteLength) ||
      Number(value.responseByteLength) < 2 ||
      Number(value.responseByteLength) > MAX_PAID_MEDIA_ARCHIVE_RESPONSE_BYTES ||
      !Array.isArray(value.assets) ||
      typeof value.discoverySha256 !== 'string' ||
      !SHA256_PATTERN.test(value.discoverySha256)
    ) {
      throw new PaidMediaVaultError('Paid media archive discovery index is invalid')
    }
    const assets = value.assets.map((candidate) => {
      if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) {
        throw new PaidMediaVaultError('Paid media archive discovery asset is invalid')
      }
      const asset = candidate as Record<string, unknown>
      if (
        !exactKeys(asset, ['reference', 'mediaType', 'byteLength', 'sha256']) ||
        typeof asset.sha256 !== 'string' ||
        !SHA256_PATTERN.test(asset.sha256) ||
        typeof asset.reference !== 'string' ||
        asset.reference !== `nachuan-paid-media://sha256/${asset.sha256}` ||
        !['image/png', 'image/jpeg', 'image/gif', 'image/webp'].includes(
          String(asset.mediaType)
        ) ||
        !Number.isSafeInteger(asset.byteLength) ||
        Number(asset.byteLength) < 1 ||
        Number(asset.byteLength) > MAX_PAID_MEDIA_ARCHIVE_ASSET_BYTES
      ) {
        throw new PaidMediaVaultError('Paid media archive discovery asset is invalid')
      }
      return {
        reference: asset.reference,
        mediaType: asset.mediaType as PaidMediaArchivedAsset['mediaType'],
        byteLength: asset.byteLength as number,
        sha256: asset.sha256
      }
    })
    if (
      (value.path === '/v1/images/generations') !== (value.kind === 'image') ||
      (value.kind === 'image' ? assets.length < 1 || assets.length > 4 : assets.length !== 0)
    ) {
      throw new PaidMediaVaultError('Paid media archive discovery kind is inconsistent')
    }
    const base: DiscoveryBase = {
      schema: DISCOVERY_SCHEMA,
      operationId: value.operationId,
      path: value.path,
      model: value.model,
      status: value.status as number,
      kind: value.kind,
      archivedAt: value.archivedAt as number,
      receiptSha256: value.receiptSha256,
      responseByteLength: value.responseByteLength as number,
      assets
    }
    if (sha256(JSON.stringify(base)) !== value.discoverySha256) {
      throw new PaidMediaVaultError('Paid media archive discovery digest does not match')
    }
    return { ...base, discoverySha256: value.discoverySha256 }
  }

  private ensureDiscoveryIndex(
    archive: Pick<
      PaidMediaArchiveReceipt,
      | 'operationId'
      | 'path'
      | 'status'
      | 'kind'
      | 'archivedAt'
      | 'receiptSha256'
      | 'responseByteLength'
      | 'assets'
    >,
    model: string
  ): DiscoveryDocument {
    const base: DiscoveryBase = {
      schema: DISCOVERY_SCHEMA,
      operationId: archive.operationId,
      path: archive.path,
      model,
      status: archive.status,
      kind: archive.kind,
      archivedAt: archive.archivedAt,
      receiptSha256: archive.receiptSha256,
      responseByteLength: archive.responseByteLength,
      assets: archive.assets.map((asset) => ({
        reference: asset.reference,
        mediaType: asset.mediaType,
        byteLength: asset.byteLength,
        sha256: asset.sha256
      }))
    }
    const document: DiscoveryDocument = {
      ...base,
      discoverySha256: sha256(JSON.stringify(base))
    }
    const path = this.discoveryFile(archive.archivedAt, archive.operationId)
    if (existsSync(path)) {
      const existing = this.parseDiscovery(
        this.decodeEncrypted(
          this.readRegular(path, MAX_ENCRYPTED_DOCUMENT_BYTES, 'Paid media discovery index'),
          'Paid media discovery index'
        )
      )
      if (JSON.stringify(existing) !== JSON.stringify(document)) {
        throw new PaidMediaVaultError('Paid media archive discovery conflicts with its receipt')
      }
      return existing
    }
    this.writeAtomicNew(
      path,
      this.encodeEncrypted(document),
      'Paid media discovery index'
    )
    return document
  }

  private taskAliasDigest(taskAlias: string): string {
    if (typeof taskAlias !== 'string' || !VIDEO_TASK_ALIAS_PATTERN.test(taskAlias)) {
      throw new PaidMediaVaultError('Paid media video task alias is invalid')
    }
    return sha256(taskAlias)
  }

  private taskIndexFile(taskAlias: string): string {
    return join(this.videoTasksPath, `${this.taskAliasDigest(taskAlias)}.json`)
  }

  private terminalFile(taskAlias: string): string {
    return join(this.videoTerminalsPath, `${this.taskAliasDigest(taskAlias)}.json`)
  }

  private parseAssetV2DispatchMarker(
    value: Record<string, unknown>
  ): AssetV2DispatchDocument {
    if (
      !exactKeys(value, [
        'assetResultSha256',
        'operationId',
        'paidPrincipalSha256',
        'path',
        'recoveryDomainSha256',
        'requestSha256',
        'schema',
        'turnId',
        'receiptSha256'
      ]) ||
      value.schema !== ASSET_V2_DISPATCH_SCHEMA ||
      !validPath(value.path)
    ) {
      throw new PaidMediaVaultError('Paid media asset v2 dispatch marker is invalid')
    }
    const turnId =
      value.turnId === null
        ? null
        : requireNonzeroSha256(value.turnId, 'Paid media asset v2 dispatch turn id')
    const assetResultSha256 =
      value.assetResultSha256 === null
        ? null
        : requireNonzeroSha256(
            value.assetResultSha256,
            'Paid media asset v2 dispatch result digest'
          )
    if ((turnId === null) !== (assetResultSha256 === null)) {
      throw new PaidMediaVaultError(
        'Paid media asset v2 dispatch result identity is incomplete'
      )
    }
    const base: AssetV2DispatchBase = {
      assetResultSha256,
      operationId: requireOperationId(value.operationId),
      paidPrincipalSha256: requireNonzeroSha256(
        value.paidPrincipalSha256,
        'Paid media asset v2 dispatch principal digest'
      ),
      path: value.path,
      recoveryDomainSha256: requireNonzeroSha256(
        value.recoveryDomainSha256,
        'Paid media asset v2 dispatch recovery domain digest'
      ),
      requestSha256: requireNonzeroSha256(
        value.requestSha256,
        'Paid media asset v2 dispatch request digest'
      ),
      schema: ASSET_V2_DISPATCH_SCHEMA,
      turnId
    }
    const receiptSha256 = requireNonzeroSha256(
      value.receiptSha256,
      'Paid media asset v2 dispatch receipt digest'
    )
    if (
      receiptSha256 !==
      recoverySidecarDigest(ASSET_V2_DISPATCH_RECEIPT_DOMAIN, base)
    ) {
      throw new PaidMediaVaultError(
        'Paid media asset v2 dispatch receipt digest does not match'
      )
    }
    return { ...base, receiptSha256 }
  }

  private readAssetV2DispatchMarkerDocument(
    operationId: string
  ): AssetV2DispatchDocument {
    const normalizedOperationId = requireOperationId(operationId)
    this.prepare()
    const document = this.parseAssetV2DispatchMarker(
      this.decodeEncrypted(
        this.readRegular(
          this.assetV2DispatchFile(normalizedOperationId),
          MAX_ENCRYPTED_DOCUMENT_BYTES,
          'Paid media asset v2 dispatch marker'
        ),
        'Paid media asset v2 dispatch marker'
      )
    )
    if (document.operationId !== normalizedOperationId) {
      throw new PaidMediaVaultError(
        'Paid media asset v2 dispatch operation does not match'
      )
    }
    return document
  }

  async recordAssetV2DispatchMarker(input: {
    operationId: string
    path: PaidMediaPath
    requestSha256: string
    recoveryDomainSha256: string
    paidPrincipalSha256: string
    turnId: string | null
    assetResultSha256: string | null
  }): Promise<PaidMediaV2DispatchMarker> {
    this.assertAssetRecoveryMutationAuthority()
    if (
      !input ||
      typeof input !== 'object' ||
      !exactKeys(input as unknown as Record<string, unknown>, [
        'operationId',
        'path',
        'requestSha256',
        'recoveryDomainSha256',
        'paidPrincipalSha256',
        'turnId',
        'assetResultSha256'
      ]) ||
      !validPath(input.path)
    ) {
      throw new PaidMediaVaultError('Paid media asset v2 dispatch input is invalid')
    }
    const operationId = requireOperationId(input.operationId)
    const claim = await this.readExactRequest(operationId)
    const turnId =
      input.turnId === null
        ? null
        : requireNonzeroSha256(input.turnId, 'Paid media asset v2 dispatch turn id')
    const assetResultSha256 =
      input.assetResultSha256 === null
        ? null
        : requireNonzeroSha256(
            input.assetResultSha256,
            'Paid media asset v2 dispatch result digest'
          )
    if (
      claim.path !== input.path ||
      claim.requestSha256 !== input.requestSha256 ||
      (turnId === null) !== (assetResultSha256 === null)
    ) {
      throw new PaidMediaVaultError('Paid media asset v2 dispatch claim binding conflicts')
    }
    const base: AssetV2DispatchBase = {
      assetResultSha256,
      operationId,
      paidPrincipalSha256: requireNonzeroSha256(
        input.paidPrincipalSha256,
        'Paid media asset v2 dispatch principal digest'
      ),
      path: input.path,
      recoveryDomainSha256: requireNonzeroSha256(
        input.recoveryDomainSha256,
        'Paid media asset v2 dispatch recovery domain digest'
      ),
      requestSha256: requireNonzeroSha256(
        input.requestSha256,
        'Paid media asset v2 dispatch request digest'
      ),
      schema: ASSET_V2_DISPATCH_SCHEMA,
      turnId
    }
    const document: AssetV2DispatchDocument = {
      ...base,
      receiptSha256: recoverySidecarDigest(
        ASSET_V2_DISPATCH_RECEIPT_DOMAIN,
        base
      )
    }
    const path = this.assetV2DispatchFile(operationId)
    if (existsSync(path)) {
      const existing = this.readAssetV2DispatchMarkerDocument(operationId)
      if (JSON.stringify(existing) !== JSON.stringify(document)) {
        throw new PaidMediaVaultError(
          'Paid media asset v2 dispatch marker conflicts'
        )
      }
      return this.verifyAssetV2DispatchMarker(operationId)
    }
    this.writeAtomicNew(
      path,
      this.encodeEncrypted(document),
      'Paid media asset v2 dispatch marker'
    )
    return this.verifyAssetV2DispatchMarker(operationId)
  }

  async verifyAssetV2DispatchMarker(
    operationId: string
  ): Promise<PaidMediaV2DispatchMarker> {
    const document = this.readAssetV2DispatchMarkerDocument(operationId)
    const claim = await this.readExactRequest(document.operationId)
    if (
      claim.path !== document.path ||
      claim.requestSha256 !== document.requestSha256
    ) {
      throw new PaidMediaVaultError(
        'Paid media asset v2 dispatch claim binding does not match'
      )
    }
    return publicV2DispatchMarker(document)
  }

  private parseAssetAckIntent(value: Record<string, unknown>): AssetAckIntentDocument {
    if (
      !exactKeys(value, [
        'archiveReceiptSha256',
        'assetResultSha256',
        'dispatchReceiptSha256',
        'operationId',
        'schema',
        'tokens',
        'tokenSetDigest',
        'turnId',
        'receiptSha256'
      ]) ||
      value.schema !== ASSET_ACK_INTENT_SCHEMA
    ) {
      throw new PaidMediaVaultError('Paid media asset ACK intent is invalid')
    }
    const normalizedTokens = canonicalAssetAckTokens(value.tokens)
    if (
      JSON.stringify(value.tokens) !== JSON.stringify(normalizedTokens.tokens) ||
      value.tokenSetDigest !== normalizedTokens.tokenSetDigest
    ) {
      throw new PaidMediaVaultError(
        'Paid media asset ACK intent token set is not canonical'
      )
    }
    const base: AssetAckIntentBase = {
      archiveReceiptSha256: requireNonzeroSha256(
        value.archiveReceiptSha256,
        'Paid media asset ACK archive receipt digest'
      ),
      assetResultSha256: requireNonzeroSha256(
        value.assetResultSha256,
        'Paid media asset ACK result digest'
      ),
      dispatchReceiptSha256: requireNonzeroSha256(
        value.dispatchReceiptSha256,
        'Paid media asset ACK dispatch receipt digest'
      ),
      operationId: requireOperationId(value.operationId),
      schema: ASSET_ACK_INTENT_SCHEMA,
      tokens: normalizedTokens.tokens,
      tokenSetDigest: normalizedTokens.tokenSetDigest,
      turnId: requireNonzeroSha256(value.turnId, 'Paid media asset ACK turn id')
    }
    const receiptSha256 = requireNonzeroSha256(
      value.receiptSha256,
      'Paid media asset ACK intent receipt digest'
    )
    if (
      receiptSha256 !== recoverySidecarDigest(ASSET_ACK_INTENT_RECEIPT_DOMAIN, base)
    ) {
      throw new PaidMediaVaultError(
        'Paid media asset ACK intent receipt digest does not match'
      )
    }
    return { ...base, receiptSha256 }
  }

  private readAssetAckIntentDocument(operationId: string): AssetAckIntentDocument {
    const normalizedOperationId = requireOperationId(operationId)
    this.prepare()
    const document = this.parseAssetAckIntent(
      this.decodeEncrypted(
        this.readRegular(
          this.assetAckIntentFile(normalizedOperationId),
          MAX_ENCRYPTED_DOCUMENT_BYTES,
          'Paid media asset ACK intent'
        ),
        'Paid media asset ACK intent'
      )
    )
    if (document.operationId !== normalizedOperationId) {
      throw new PaidMediaVaultError('Paid media asset ACK intent operation does not match')
    }
    return document
  }

  private assertAssetAckIntentResultEvidence(
    document: AssetAckIntentDocument,
    archive: PaidMediaArchivedResult
  ): void {
    const authority = this.loadAuthorityIndex()
    const leaseIds = authority.stageOperationIndex.get(document.operationId)
    if (!leaseIds || leaseIds.size < 1) {
      throw new PaidMediaVaultError(
        'Paid media asset ACK intent lacks v2 stage evidence'
      )
    }
    const stages = [...leaseIds]
      .map((leaseId) => authority.stageLeases.get(leaseId))
      .sort((left, right) => (left?.ordinal ?? -1) - (right?.ordinal ?? -1))
    const stageTokens = stages.map((stage) => stage?.descriptor.token)
    const normalizedStageTokens = canonicalAssetAckTokens(stageTokens)
    if (
      stages.length !== document.tokens.length ||
      archive.receipt.assets.length !== stages.length ||
      normalizedStageTokens.tokenSetDigest !== document.tokenSetDigest ||
      stages.some((stage, ordinal) => {
        const asset = archive.receipt.assets[ordinal]
        return (
          !stage ||
          !asset ||
          stage.ordinal !== ordinal ||
          stage.operationId !== document.operationId ||
          stage.turnId !== document.turnId ||
          stage.resultSha256 !== document.assetResultSha256 ||
          // `opened`/`held` may still authorize deleting the Gateway's remote
          // copy when the immutable local archive itself verifies. They never
          // authorize local capacity release: that later gate independently
          // requires verifyArchive().cleanupComplete === true, which only an
          // exact archived_cleaned stage set can satisfy.
          ![
            'opened',
            'archived_cleanup_pending',
            'archived_cleaned',
            'held'
          ].includes(stage.state) ||
          asset.sha256 !== stage.descriptor.sha256 ||
          asset.byteLength !== stage.descriptor.byteLength ||
          asset.mediaType !== stage.descriptor.mediaType ||
          asset.sourceSha256 !== paidMediaAssetTokenHash(stage.descriptor.token)
        )
      })
    ) {
      throw new PaidMediaVaultError(
        'Paid media asset ACK intent result evidence conflicts'
      )
    }
  }

  async recordAssetAckIntent(input: {
    operationId: string
    turnId: string
    tokens: readonly string[]
    tokenSetDigest: string
    archiveReceiptSha256: string
    assetResultSha256: string
    dispatchReceiptSha256: string
  }): Promise<PaidMediaAssetAckIntent> {
    this.assertAssetRecoveryMutationAuthority()
    if (
      !input ||
      typeof input !== 'object' ||
      !exactKeys(input as unknown as Record<string, unknown>, [
        'operationId',
        'turnId',
        'tokens',
        'tokenSetDigest',
        'archiveReceiptSha256',
        'assetResultSha256',
        'dispatchReceiptSha256'
      ])
    ) {
      throw new PaidMediaVaultError('Paid media asset ACK intent input is invalid')
    }
    const operationId = requireOperationId(input.operationId)
    const normalizedTokens = canonicalAssetAckTokens(input.tokens)
    if (input.tokenSetDigest !== normalizedTokens.tokenSetDigest) {
      throw new PaidMediaVaultError('Paid media asset ACK token set digest conflicts')
    }
    const base: AssetAckIntentBase = {
      archiveReceiptSha256: requireNonzeroSha256(
        input.archiveReceiptSha256,
        'Paid media asset ACK archive receipt digest'
      ),
      assetResultSha256: requireNonzeroSha256(
        input.assetResultSha256,
        'Paid media asset ACK result digest'
      ),
      dispatchReceiptSha256: requireNonzeroSha256(
        input.dispatchReceiptSha256,
        'Paid media asset ACK dispatch receipt digest'
      ),
      operationId,
      schema: ASSET_ACK_INTENT_SCHEMA,
      tokens: normalizedTokens.tokens,
      tokenSetDigest: normalizedTokens.tokenSetDigest,
      turnId: requireNonzeroSha256(input.turnId, 'Paid media asset ACK turn id')
    }
    const document: AssetAckIntentDocument = {
      ...base,
      receiptSha256: recoverySidecarDigest(ASSET_ACK_INTENT_RECEIPT_DOMAIN, base)
    }
    const path = this.assetAckIntentFile(operationId)
    if (existsSync(path)) {
      const existing = this.readAssetAckIntentDocument(operationId)
      if (JSON.stringify(existing) !== JSON.stringify(document)) {
        throw new PaidMediaVaultError('Paid media asset ACK intent conflicts')
      }
      await this.verifyAssetAckIntent(operationId)
      return publicAssetAckIntent(existing)
    }
    const dispatch = await this.verifyAssetV2DispatchMarker(operationId)
    const archive = await this.verifyArchive(operationId)
    if (
      dispatch.receiptSha256 !== document.dispatchReceiptSha256 ||
      archive.receipt.receiptSha256 !== document.archiveReceiptSha256 ||
      (dispatch.turnId !== null && dispatch.turnId !== document.turnId) ||
      (dispatch.assetResultSha256 !== null &&
        dispatch.assetResultSha256 !== document.assetResultSha256)
    ) {
      throw new PaidMediaVaultError('Paid media asset ACK intent evidence conflicts')
    }
    this.assertAssetAckIntentResultEvidence(document, archive)
    this.writeAtomicNew(
      path,
      this.encodeEncrypted(document),
      'Paid media asset ACK intent'
    )
    return this.verifyAssetAckIntent(operationId)
  }

  async verifyAssetAckIntent(operationId: string): Promise<PaidMediaAssetAckIntent> {
    const document = this.readAssetAckIntentDocument(operationId)
    const dispatch = await this.verifyAssetV2DispatchMarker(document.operationId)
    const archive = await this.verifyArchive(document.operationId)
    if (
      dispatch.receiptSha256 !== document.dispatchReceiptSha256 ||
      archive.receipt.receiptSha256 !== document.archiveReceiptSha256 ||
      (dispatch.turnId !== null && dispatch.turnId !== document.turnId) ||
      (dispatch.assetResultSha256 !== null &&
        dispatch.assetResultSha256 !== document.assetResultSha256)
    ) {
      throw new PaidMediaVaultError(
        'Paid media asset ACK intent evidence does not match'
      )
    }
    this.assertAssetAckIntentResultEvidence(document, archive)
    return publicAssetAckIntent(document)
  }

  private assetAckSemanticResponseSha256(input: {
    status: 200
    turnId: string
    ok: true
    cleanupComplete: true
  }): string {
    const canonical = {
      cleanupComplete: input.cleanupComplete,
      ok: input.ok,
      status: input.status,
      turnId: input.turnId
    }
    return recoverySidecarDigest(
      ASSET_ACK_COMPLETION_SEMANTIC_DOMAIN,
      canonical
    )
  }

  private parseAssetAckCompletion(
    value: Record<string, unknown>
  ): AssetAckCompletionDocument {
    if (
      !exactKeys(value, [
        'cleanupComplete',
        'intentReceiptSha256',
        'ok',
        'operationId',
        'schema',
        'semanticResponseSha256',
        'status',
        'turnId',
        'receiptSha256'
      ]) ||
      value.schema !== ASSET_ACK_COMPLETION_SCHEMA ||
      value.status !== 200 ||
      value.ok !== true ||
      value.cleanupComplete !== true
    ) {
      throw new PaidMediaVaultError('Paid media asset ACK completion is invalid')
    }
    const turnId = requireNonzeroSha256(
      value.turnId,
      'Paid media asset ACK completion turn id'
    )
    const semanticResponseSha256 = requireNonzeroSha256(
      value.semanticResponseSha256,
      'Paid media asset ACK semantic response digest'
    )
    if (
      semanticResponseSha256 !==
      this.assetAckSemanticResponseSha256({
        status: 200,
        turnId,
        ok: true,
        cleanupComplete: true
      })
    ) {
      throw new PaidMediaVaultError(
        'Paid media asset ACK semantic response digest does not match'
      )
    }
    const base: AssetAckCompletionBase = {
      cleanupComplete: true,
      intentReceiptSha256: requireNonzeroSha256(
        value.intentReceiptSha256,
        'Paid media asset ACK intent receipt digest'
      ),
      ok: true,
      operationId: requireOperationId(value.operationId),
      schema: ASSET_ACK_COMPLETION_SCHEMA,
      semanticResponseSha256,
      status: 200,
      turnId
    }
    const receiptSha256 = requireNonzeroSha256(
      value.receiptSha256,
      'Paid media asset ACK completion receipt digest'
    )
    if (
      receiptSha256 !==
      recoverySidecarDigest(ASSET_ACK_COMPLETION_RECEIPT_DOMAIN, base)
    ) {
      throw new PaidMediaVaultError(
        'Paid media asset ACK completion receipt digest does not match'
      )
    }
    return { ...base, receiptSha256 }
  }

  private readAssetAckCompletionDocument(
    operationId: string
  ): AssetAckCompletionDocument {
    const normalizedOperationId = requireOperationId(operationId)
    this.prepare()
    const document = this.parseAssetAckCompletion(
      this.decodeEncrypted(
        this.readRegular(
          this.assetAckCompletionFile(normalizedOperationId),
          MAX_ENCRYPTED_DOCUMENT_BYTES,
          'Paid media asset ACK completion'
        ),
        'Paid media asset ACK completion'
      )
    )
    if (document.operationId !== normalizedOperationId) {
      throw new PaidMediaVaultError(
        'Paid media asset ACK completion operation does not match'
      )
    }
    return document
  }

  async recordAssetAckCompletion(input: {
    operationId: string
    intentReceiptSha256: string
    status: 200
    response: {
      ok: true
      turnId: string
      replayed: boolean
      cleanupComplete: true
    }
  }): Promise<PaidMediaAssetAckCompletion> {
    this.assertAssetRecoveryMutationAuthority()
    if (
      !input ||
      typeof input !== 'object' ||
      !exactKeys(input as unknown as Record<string, unknown>, [
        'operationId',
        'intentReceiptSha256',
        'status',
        'response'
      ]) ||
      input.status !== 200 ||
      !input.response ||
      typeof input.response !== 'object' ||
      !exactKeys(input.response as unknown as Record<string, unknown>, [
        'ok',
        'turnId',
        'replayed',
        'cleanupComplete'
      ]) ||
      input.response.ok !== true ||
      typeof input.response.replayed !== 'boolean' ||
      input.response.cleanupComplete !== true
    ) {
      throw new PaidMediaVaultError('Paid media asset ACK completion input is invalid')
    }
    const operationId = requireOperationId(input.operationId)
    const turnId = requireNonzeroSha256(
      input.response.turnId,
      'Paid media asset ACK completion turn id'
    )
    const intentReceiptSha256 = requireNonzeroSha256(
      input.intentReceiptSha256,
      'Paid media asset ACK intent receipt digest'
    )
    const base: AssetAckCompletionBase = {
      cleanupComplete: true,
      intentReceiptSha256,
      ok: true,
      operationId,
      schema: ASSET_ACK_COMPLETION_SCHEMA,
      semanticResponseSha256: this.assetAckSemanticResponseSha256({
        status: 200,
        turnId,
        ok: true,
        cleanupComplete: true
      }),
      status: 200,
      turnId
    }
    const document: AssetAckCompletionDocument = {
      ...base,
      receiptSha256: recoverySidecarDigest(
        ASSET_ACK_COMPLETION_RECEIPT_DOMAIN,
        base
      )
    }
    const path = this.assetAckCompletionFile(operationId)
    if (existsSync(path)) {
      const existing = this.readAssetAckCompletionDocument(operationId)
      if (JSON.stringify(existing) !== JSON.stringify(document)) {
        throw new PaidMediaVaultError('Paid media asset ACK completion conflicts')
      }
      await this.verifyAssetAckCompletion(operationId)
      return publicAssetAckCompletion(existing)
    }
    const intent = await this.verifyAssetAckIntent(operationId)
    if (
      intent.receiptSha256 !== intentReceiptSha256 ||
      intent.turnId !== turnId
    ) {
      throw new PaidMediaVaultError(
        'Paid media asset ACK completion intent binding conflicts'
      )
    }
    this.writeAtomicNew(
      path,
      this.encodeEncrypted(document),
      'Paid media asset ACK completion'
    )
    return this.verifyAssetAckCompletion(operationId)
  }

  async verifyAssetAckCompletion(
    operationId: string
  ): Promise<PaidMediaAssetAckCompletion> {
    const document = this.readAssetAckCompletionDocument(operationId)
    const intent = await this.verifyAssetAckIntent(document.operationId)
    if (
      intent.receiptSha256 !== document.intentReceiptSha256 ||
      intent.turnId !== document.turnId
    ) {
      throw new PaidMediaVaultError(
        'Paid media asset ACK completion intent binding does not match'
      )
    }
    return publicAssetAckCompletion(document)
  }

  private parseAssetCapacityRelease(
    value: Record<string, unknown>
  ): AssetCapacityReleaseDocument {
    if (
      !exactKeys(value, [
        'ackCompletionReceiptSha256',
        'archiveReceiptSha256',
        'cleanupComplete',
        'dispatchReceiptSha256',
        'operationId',
        'schema',
        'receiptSha256'
      ]) ||
      value.schema !== ASSET_CAPACITY_RELEASE_SCHEMA ||
      value.cleanupComplete !== true
    ) {
      throw new PaidMediaVaultError(
        'Paid media asset capacity release authorization is invalid'
      )
    }
    const base: AssetCapacityReleaseBase = {
      ackCompletionReceiptSha256: requireNonzeroSha256(
        value.ackCompletionReceiptSha256,
        'Paid media asset ACK completion receipt digest'
      ),
      archiveReceiptSha256: requireNonzeroSha256(
        value.archiveReceiptSha256,
        'Paid media asset archive receipt digest'
      ),
      cleanupComplete: true,
      dispatchReceiptSha256: requireNonzeroSha256(
        value.dispatchReceiptSha256,
        'Paid media asset dispatch receipt digest'
      ),
      operationId: requireOperationId(value.operationId),
      schema: ASSET_CAPACITY_RELEASE_SCHEMA
    }
    const receiptSha256 = requireNonzeroSha256(
      value.receiptSha256,
      'Paid media asset capacity release receipt digest'
    )
    if (
      receiptSha256 !==
      recoverySidecarDigest(ASSET_CAPACITY_RELEASE_RECEIPT_DOMAIN, base)
    ) {
      throw new PaidMediaVaultError(
        'Paid media asset capacity release receipt digest does not match'
      )
    }
    return { ...base, receiptSha256 }
  }

  private readAssetCapacityReleaseDocument(
    operationId: string
  ): AssetCapacityReleaseDocument {
    const normalizedOperationId = requireOperationId(operationId)
    this.prepare()
    const document = this.parseAssetCapacityRelease(
      this.decodeEncrypted(
        this.readRegular(
          this.assetCapacityReleaseFile(normalizedOperationId),
          MAX_ENCRYPTED_DOCUMENT_BYTES,
          'Paid media asset capacity release authorization'
        ),
        'Paid media asset capacity release authorization'
      )
    )
    if (document.operationId !== normalizedOperationId) {
      throw new PaidMediaVaultError(
        'Paid media asset capacity release operation does not match'
      )
    }
    return document
  }

  private async resolveAssetCapacityReleaseBase(input: {
    operationId: string
    archiveReceiptSha256: string
    dispatchReceiptSha256: string
    ackCompletionReceiptSha256: string
  }): Promise<AssetCapacityReleaseBase> {
    const operationId = requireOperationId(input.operationId)
    const archive = await this.verifyArchive(operationId)
    const dispatch = await this.verifyAssetV2DispatchMarker(operationId)
    const completion = await this.verifyAssetAckCompletion(operationId)
    const intent = await this.verifyAssetAckIntent(operationId)
    if (
      archive.cleanupComplete !== true ||
      archive.receipt.receiptSha256 !== input.archiveReceiptSha256 ||
      dispatch.receiptSha256 !== input.dispatchReceiptSha256 ||
      completion.receiptSha256 !== input.ackCompletionReceiptSha256 ||
      completion.intentReceiptSha256 !== intent.receiptSha256 ||
      intent.archiveReceiptSha256 !== archive.receipt.receiptSha256 ||
      intent.dispatchReceiptSha256 !== dispatch.receiptSha256 ||
      intent.turnId !== completion.turnId ||
      (dispatch.turnId !== null && dispatch.turnId !== intent.turnId) ||
      (dispatch.assetResultSha256 !== null &&
        dispatch.assetResultSha256 !== intent.assetResultSha256)
    ) {
      throw new PaidMediaVaultError(
        'Paid media asset capacity release evidence is incomplete or conflicts'
      )
    }
    return {
      ackCompletionReceiptSha256: completion.receiptSha256,
      archiveReceiptSha256: archive.receipt.receiptSha256,
      cleanupComplete: true,
      dispatchReceiptSha256: dispatch.receiptSha256,
      operationId,
      schema: ASSET_CAPACITY_RELEASE_SCHEMA
    }
  }

  async recordAssetCapacityReleaseAuthorization(input: {
    operationId: string
    archive: { receiptSha256: string; cleanupComplete: true }
    dispatch: { receiptSha256: string }
    ackCompletion: { receiptSha256: string }
  }): Promise<PaidMediaAssetCapacityReleaseAuthorization> {
    this.assertAssetRecoveryMutationAuthority()
    if (
      !input ||
      typeof input !== 'object' ||
      !exactKeys(input as unknown as Record<string, unknown>, [
        'operationId',
        'archive',
        'dispatch',
        'ackCompletion'
      ]) ||
      !input.archive ||
      typeof input.archive !== 'object' ||
      !exactKeys(input.archive as unknown as Record<string, unknown>, [
        'receiptSha256',
        'cleanupComplete'
      ]) ||
      input.archive.cleanupComplete !== true ||
      !input.dispatch ||
      typeof input.dispatch !== 'object' ||
      !exactKeys(input.dispatch as unknown as Record<string, unknown>, [
        'receiptSha256'
      ]) ||
      !input.ackCompletion ||
      typeof input.ackCompletion !== 'object' ||
      !exactKeys(input.ackCompletion as unknown as Record<string, unknown>, [
        'receiptSha256'
      ])
    ) {
      throw new PaidMediaVaultError(
        'Paid media asset capacity release authorization input is invalid'
      )
    }
    const base = await this.resolveAssetCapacityReleaseBase({
      operationId: input.operationId,
      archiveReceiptSha256: requireNonzeroSha256(
        input.archive.receiptSha256,
        'Paid media asset archive receipt digest'
      ),
      dispatchReceiptSha256: requireNonzeroSha256(
        input.dispatch.receiptSha256,
        'Paid media asset dispatch receipt digest'
      ),
      ackCompletionReceiptSha256: requireNonzeroSha256(
        input.ackCompletion.receiptSha256,
        'Paid media asset ACK completion receipt digest'
      )
    })
    const document: AssetCapacityReleaseDocument = {
      ...base,
      receiptSha256: recoverySidecarDigest(
        ASSET_CAPACITY_RELEASE_RECEIPT_DOMAIN,
        base
      )
    }
    const path = this.assetCapacityReleaseFile(base.operationId)
    if (existsSync(path)) {
      const existing = this.readAssetCapacityReleaseDocument(base.operationId)
      if (JSON.stringify(existing) !== JSON.stringify(document)) {
        throw new PaidMediaVaultError(
          'Paid media asset capacity release authorization conflicts'
        )
      }
      return this.verifyAssetCapacityReleaseAuthorization(base.operationId)
    }
    this.writeAtomicNew(
      path,
      this.encodeEncrypted(document),
      'Paid media asset capacity release authorization'
    )
    return this.verifyAssetCapacityReleaseAuthorization(base.operationId)
  }

  async verifyAssetCapacityReleaseAuthorization(
    operationId: string
  ): Promise<PaidMediaAssetCapacityReleaseAuthorization> {
    const document = this.readAssetCapacityReleaseDocument(operationId)
    const expected = await this.resolveAssetCapacityReleaseBase({
      operationId: document.operationId,
      archiveReceiptSha256: document.archiveReceiptSha256,
      dispatchReceiptSha256: document.dispatchReceiptSha256,
      ackCompletionReceiptSha256: document.ackCompletionReceiptSha256
    })
    if (
      JSON.stringify(expected) !==
      JSON.stringify({
        ackCompletionReceiptSha256: document.ackCompletionReceiptSha256,
        archiveReceiptSha256: document.archiveReceiptSha256,
        cleanupComplete: document.cleanupComplete,
        dispatchReceiptSha256: document.dispatchReceiptSha256,
        operationId: document.operationId,
        schema: document.schema
      })
    ) {
      throw new PaidMediaVaultError(
        'Paid media asset capacity release authorization evidence does not match'
      )
    }
    return publicAssetCapacityRelease(document)
  }

  private parseClaim(value: Record<string, unknown>): ClaimDocument {
    if (
      !exactKeys(value, [
        'schema',
        'operationId',
        'path',
        'requestSha256',
        'requestUtf8Base64',
        'createdAt',
        'claimSha256'
      ]) ||
      value.schema !== CLAIM_SCHEMA ||
      typeof value.operationId !== 'string' ||
      !OPERATION_ID_PATTERN.test(value.operationId) ||
      !validPath(value.path) ||
      typeof value.requestSha256 !== 'string' ||
      !SHA256_PATTERN.test(value.requestSha256) ||
      !Number.isSafeInteger(value.createdAt) ||
      Number(value.createdAt) < 0 ||
      typeof value.claimSha256 !== 'string' ||
      !SHA256_PATTERN.test(value.claimSha256)
    ) {
      throw new PaidMediaVaultError('Paid media vault claim is invalid')
    }
    const requestBytes = decodeCanonicalBase64(
      value.requestUtf8Base64,
      MAX_REQUEST_BYTES,
      'Paid media vault request'
    )
    const encodedBody = requestBytes.toString('utf8')
    if (!Buffer.from(encodedBody, 'utf8').equals(requestBytes)) {
      throw new PaidMediaVaultError('Paid media vault request is not valid UTF-8')
    }
    if (sha256(requestBytes) !== value.requestSha256) {
      throw new PaidMediaVaultError('Paid media vault request digest does not match')
    }
    const base: ClaimBase = {
      schema: CLAIM_SCHEMA,
      operationId: value.operationId,
      path: value.path,
      requestSha256: value.requestSha256,
      requestUtf8Base64: value.requestUtf8Base64 as string,
      createdAt: value.createdAt as number
    }
    if (sha256(JSON.stringify(base)) !== value.claimSha256) {
      throw new PaidMediaVaultError('Paid media vault claim receipt does not match')
    }
    return { ...base, claimSha256: value.claimSha256 }
  }

  async recordClaim(input: {
    operationId: string
    path: PaidMediaPath
    encodedBody: string
  }): Promise<PaidMediaExactRequest> {
    if (
      !input ||
      typeof input !== 'object' ||
      !exactKeys(input as unknown as Record<string, unknown>, [
        'operationId',
        'path',
        'encodedBody'
      ]) ||
      !validPath(input.path) ||
      typeof input.encodedBody !== 'string'
    ) {
      throw new PaidMediaVaultError('Paid media vault claim input is invalid')
    }
    const operationId = requireOperationId(input.operationId)
    const requestBytes = Buffer.from(input.encodedBody, 'utf8')
    if (
      requestBytes.length < 2 ||
      requestBytes.length > MAX_REQUEST_BYTES ||
      requestBytes.toString('utf8') !== input.encodedBody
    ) {
      throw new PaidMediaVaultError('Paid media vault request bytes are invalid')
    }
    this.prepare()
    const base: ClaimBase = {
      schema: CLAIM_SCHEMA,
      operationId,
      path: input.path,
      requestSha256: sha256(requestBytes),
      requestUtf8Base64: requestBytes.toString('base64'),
      createdAt: requireNow(this.dependencies.now)
    }
    const document: ClaimDocument = { ...base, claimSha256: sha256(JSON.stringify(base)) }
    const path = this.claimFile(operationId)
    if (existsSync(path)) {
      const existing = await this.readExactRequest(operationId)
      if (
        existing.path !== input.path ||
        existing.requestSha256 !== document.requestSha256 ||
        existing.encodedBody !== input.encodedBody
      ) {
        throw new PaidMediaVaultError('Paid media vault request conflicts with the existing claim')
      }
      return existing
    }
    this.writeAtomicNew(path, this.encodeEncrypted(document), 'Paid media vault claim')
    return this.readExactRequest(operationId)
  }

  async readExactRequest(operationId: string): Promise<PaidMediaExactRequest> {
    this.prepare()
    const value = this.decodeEncrypted(
      this.readRegular(
        this.claimFile(operationId),
        MAX_ENCRYPTED_DOCUMENT_BYTES,
        'Paid media vault claim'
      ),
      'Paid media vault claim'
    )
    const claim = this.parseClaim(value)
    if (claim.operationId !== operationId) {
      throw new PaidMediaVaultError('Paid media vault claim operation does not match')
    }
    return {
      operationId: claim.operationId,
      path: claim.path,
      requestSha256: claim.requestSha256,
      encodedBody: decodeCanonicalBase64(
        claim.requestUtf8Base64,
        MAX_REQUEST_BYTES,
        'Paid media vault request'
      ).toString('utf8')
    }
  }

  async verifyExactRequest(input: {
    operationId: string
    path: PaidMediaPath
    encodedBody: string
  }): Promise<PaidMediaExactRequest> {
    const stored = await this.readExactRequest(input.operationId)
    if (
      stored.path !== input.path ||
      stored.requestSha256 !== sha256(Buffer.from(input.encodedBody, 'utf8')) ||
      stored.encodedBody !== input.encodedBody
    ) {
      throw new PaidMediaVaultError('Paid media execution does not match the exact archived request')
    }
    return stored
  }

  private async writeAsset(bytes: Buffer, input: {
    source: 'inline' | 'remote'
    sourceSha256: string
    contentType?: string
  }): Promise<PaidMediaArchivedAsset> {
    if (bytes.length < 1 || bytes.length > MAX_PAID_MEDIA_ARCHIVE_ASSET_BYTES) {
      throw new PaidMediaVaultError('Paid media archive asset exceeds its size limit')
    }
    const detected = detectImage(bytes)
    validateDeclaredImageType(input.contentType, detected.mediaType)
    const digest = sha256(bytes)
    const validation = await this.validateTrustedMedia({
      createReadStream: () => Readable.from([bytes]),
      mediaType: detected.mediaType,
      byteLength: bytes.length,
      sha256: digest
    })
    const path = join(this.assetsPath, `${digest}.${detected.extension}`)
    if (existsSync(path)) {
      const existing = this.readRegular(
        path,
        MAX_PAID_MEDIA_ARCHIVE_ASSET_BYTES,
        'Paid media archive asset'
      )
      if (!existing.equals(bytes) || sha256(existing) !== digest) {
        throw new PaidMediaVaultError('Paid media archive asset digest conflict')
      }
    } else {
      this.writeAtomicNew(
        path,
        bytes,
        'Paid media archive asset',
        MAX_PAID_MEDIA_ARCHIVE_ASSET_BYTES
      )
    }
    return {
      sha256: digest,
      byteLength: bytes.length,
      ...detected,
      source: input.source,
      sourceSha256: input.sourceSha256,
      reference: `nachuan-paid-media://sha256/${digest}`,
      validation
    }
  }

  private async writeValidatedStageImageAssetFromHandle(
    record: StageOpenHandleRecord,
    descriptor: PaidMediaAssetDescriptor,
    validation: PaidMediaValidationReceipt
  ): Promise<PaidMediaArchivedAsset> {
    this.assertMutationAllowed()
    if (
      descriptor.byteLength < 1 ||
      descriptor.byteLength > MAX_PAID_MEDIA_ARCHIVE_ASSET_BYTES
    ) {
      throw new PaidMediaVaultError('Paid media sealed stage asset exceeds its size limit')
    }
    const mediaType = requireImageType(descriptor.mediaType)
    const extension = imageExtension(mediaType)
    if (
      validation.mediaType !== mediaType ||
      validation.byteLength !== descriptor.byteLength ||
      validation.sha256 !== descriptor.sha256 ||
      validation.receiptSha256 !== descriptor.validationReceiptSha256
    ) {
      throw new PaidMediaVaultError('Paid media sealed stage asset evidence does not match')
    }
    this.acquireStageStream(record)
    let archiveHookStarted = false
    let temporary = ''
    let destinationHandle: FileHandle | null = null
    try {
      this.dependencies.onStageArchiveAsset?.({
        phase: 'start',
        leaseId: record.leaseId,
        ordinal: record.ordinal
      })
      archiveHookStarted = true
      this.assertStageRecordAuthority(record)
      await this.assertStageOpenRecordIdentity(record)
      this.stageHandleHook('read', record)
      const sourceBefore = await record.handle.stat()
      if (!sourceBefore.isFile() || sourceBefore.size !== descriptor.byteLength) {
        throw new PaidMediaVaultError('Paid media sealed stage asset length is invalid')
      }

      this.prepare()
      temporary = join(this.assetsPath, `.stage-${record.leaseId}.tmp`)
      if (existsSync(temporary)) {
        const residual = lstatSync(temporary)
        if (
          !residual.isFile() ||
          residual.isSymbolicLink() ||
          residual.size < 0 ||
          residual.size > descriptor.byteLength ||
          normalizedAbsolutePath(realpathSync(temporary)) !== normalizedAbsolutePath(temporary)
        ) {
          throw new PaidMediaVaultError('Paid media stage archive residual conflicts')
        }
        this.hardenIfChanged(temporary, false, residual)
        unlinkSync(temporary)
        this.hardenedPaths.delete(resolve(temporary))
      }
      destinationHandle = await openFile(temporary, 'wx+', 0o600)
      const hash = createHash('sha256')
      const image = new BoundedImageStreamVerifier(mediaType, descriptor.byteLength)
      const buffer = Buffer.allocUnsafe(PAID_MEDIA_STAGE_STREAM_CHUNK_BYTES)
      let byteLength = 0
      while (byteLength < descriptor.byteLength) {
        this.assertStageRecordAuthority(record)
        const wanted = Math.min(buffer.length, descriptor.byteLength - byteLength)
        const { bytesRead } = await record.handle.read(buffer, 0, wanted, byteLength)
        if (bytesRead < 1) {
          throw new PaidMediaVaultError('Paid media sealed stage asset is truncated')
        }
        const chunk = buffer.subarray(0, bytesRead)
        hash.update(chunk)
        image.update(chunk)
        let written = 0
        while (written < bytesRead) {
          const result = await destinationHandle.write(
            chunk,
            written,
            bytesRead - written,
            byteLength + written
          )
          if (result.bytesWritten < 1) {
            throw new PaidMediaVaultError('Paid media sealed stage archive copy stalled')
          }
          written += result.bytesWritten
        }
        byteLength += bytesRead
        this.dependencies.onStageStreamChunk?.({
          phase: 'archive',
          leaseId: record.leaseId,
          ordinal: record.ordinal,
          byteLength: bytesRead
        })
      }
      await destinationHandle.sync()
      await destinationHandle.close()
      destinationHandle = null

      this.assertStageRecordAuthority(record)
      await this.assertStageOpenRecordIdentity(record)
      const sourceAfter = await record.handle.stat()
      if (
        byteLength !== descriptor.byteLength ||
        sourceAfter.dev !== sourceBefore.dev ||
        sourceAfter.ino !== sourceBefore.ino ||
        sourceAfter.birthtimeMs !== sourceBefore.birthtimeMs ||
        sourceAfter.mtimeMs !== sourceBefore.mtimeMs ||
        sourceAfter.ctimeMs !== sourceBefore.ctimeMs ||
        sourceAfter.size !== sourceBefore.size
      ) {
        throw new PaidMediaVaultError('Paid media sealed stage asset changed while archiving')
      }
      image.finish()
      const digest = hash.digest('hex')
      if (digest !== descriptor.sha256) {
        throw new PaidMediaVaultError('Paid media sealed stage asset digest does not match')
      }

      const reference = `nachuan-paid-media://sha256/${digest}`
      const destination = join(this.assetsPath, `${digest}.${extension}`)
      this.hardenIfChanged(temporary, false)
      const temporaryIdentity = this.hardenedPaths.get(resolve(temporary))
      let newlyPublished = false
      try {
        // Atomic create-only publication; a racing or pre-existing destination
        // is verified through openAsset and is never replaced.
        linkSync(temporary, destination)
        newlyPublished = true
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error
      }
      if (newlyPublished) {
        const publishedTemporary = temporary
        unlinkSync(temporary)
        temporary = ''
        const destinationInfo = lstatSync(destination)
        const destinationIdentity = this.pathIdentity(destinationInfo, false)
        if (this.samePathIdentity(temporaryIdentity, destinationIdentity)) {
          this.hardenedPaths.set(resolve(destination), destinationIdentity)
        } else {
          this.hardenIfChanged(destination, false, destinationInfo)
        }
        this.hardenedPaths.delete(resolve(publishedTemporary))
        await this.dependencies.afterStageAssetLinkedBeforeAuthority?.({
          leaseId: record.leaseId,
          ordinal: record.ordinal,
          path: destination
        })
        this.recordAuthorityCreateDigest(destination, byteLength, digest)
      } else if (!this.hasRegisteredAuthorityEntry(destination)) {
        // A power loss may occur after create-only publication but before the
        // authority journal append. The active stage lease is the durable
        // intent; adopt only an exact pinned regular file.
        await this.verifyUnregisteredStageAssetForAdoption({
          path: destination,
          mediaType,
          byteLength,
          sha256: digest
        })
        this.recordAuthorityCreateDigest(destination, byteLength, digest)
      }

      const verified = await this.openAsset(reference)
      try {
        if (
          verified.byteLength !== byteLength ||
          verified.mediaType !== mediaType ||
          verified.sha256 !== digest
        ) {
          throw new PaidMediaVaultError('Paid media archive asset digest conflict')
        }
      } finally {
        await verified.handle.close().catch(() => undefined)
      }
      await this.dependencies.afterStageAssetPublished?.({
        leaseId: record.leaseId,
        ordinal: record.ordinal,
        path: destination,
        newlyPublished
      })
      return {
        sha256: digest,
        byteLength,
        mediaType,
        extension,
        source: 'remote',
        sourceSha256: paidMediaAssetTokenHash(descriptor.token),
        reference,
        validation
      }
    } finally {
      if (destinationHandle) await destinationHandle.close().catch(() => undefined)
      if (temporary) {
        this.hardenedPaths.delete(resolve(temporary))
        try {
          unlinkSync(temporary)
        } catch {
          // The temporary file was published or never created.
        }
      }
      this.releaseStageStream(record)
      if (archiveHookStarted) {
        this.dependencies.onStageArchiveAsset?.({
          phase: 'finish',
          leaseId: record.leaseId,
          ordinal: record.ordinal
        })
      }
    }
  }

  private async writeTerminalVideoAssetFile(filePath: string, input: {
    byteLength: number
    sourceSha256: string
    contentType?: string
  }): Promise<PaidMediaArchivedAsset> {
    this.assertMutationAllowed()
    const pathBefore = lstatSync(filePath)
    if (
      !pathBefore.isFile() ||
      pathBefore.isSymbolicLink() ||
      pathBefore.size !== input.byteLength ||
      pathBefore.size < 1 ||
      pathBefore.size > MAX_PAID_MEDIA_TERMINAL_VIDEO_BYTES
    ) {
      throw new PaidMediaVaultError('Paid media terminal video fetch file is invalid')
    }
    const source = await openFile(filePath, 'r')
    let temporary = ''
    try {
      const sourceBefore = await source.stat()
      if (
        !sourceBefore.isFile() ||
        sourceBefore.dev !== pathBefore.dev ||
        sourceBefore.ino !== pathBefore.ino ||
        sourceBefore.birthtimeMs !== pathBefore.birthtimeMs ||
        sourceBefore.mtimeMs !== pathBefore.mtimeMs ||
        sourceBefore.ctimeMs !== pathBefore.ctimeMs ||
        sourceBefore.size !== pathBefore.size
      ) {
        throw new PaidMediaVaultError('Paid media terminal video changed before it was pinned')
      }
      const header = await readFileRange(
        source,
        0,
        Math.min(16, sourceBefore.size),
        'Paid media terminal video'
      )
      const extension =
        header.length >= 8 && header.subarray(4, 8).toString('ascii') === 'ftyp'
          ? 'mp4'
          : header.length >= 4 &&
              header.subarray(0, 4).equals(Buffer.from([0x1a, 0x45, 0xdf, 0xa3]))
            ? 'webm'
            : null
      if (extension === null) {
        throw new PaidMediaVaultError('Paid media terminal video magic is unsupported')
      }
      const mediaType = extension === 'mp4' ? 'video/mp4' : 'video/webm'
      validateDeclaredVideoType(input.contentType, mediaType)
      await validateStoredVideoFile(source, sourceBefore.size, extension)

      this.prepare()
      temporary = join(
        this.assetsPath,
        `.terminal.${process.pid}.${randomBytes(16).toString('hex')}.tmp`
      )
      const destinationHandle = await openFile(temporary, 'wx+', 0o600)
      const hash = createHash('sha256')
      let byteLength = 0
      const buffer = Buffer.allocUnsafe(1024 * 1024)
      try {
        while (byteLength < sourceBefore.size) {
          const wanted = Math.min(buffer.length, sourceBefore.size - byteLength)
          const { bytesRead } = await source.read(buffer, 0, wanted, byteLength)
          if (bytesRead < 1) {
            throw new PaidMediaVaultError('Paid media terminal video is truncated')
          }
          const chunk = buffer.subarray(0, bytesRead)
          hash.update(chunk)
          let written = 0
          while (written < bytesRead) {
            const result = await destinationHandle.write(
              chunk,
              written,
              bytesRead - written,
              byteLength + written
            )
            if (result.bytesWritten < 1) {
              throw new PaidMediaVaultError('Paid media terminal video copy stalled')
            }
            written += result.bytesWritten
          }
          byteLength += bytesRead
          if (byteLength > MAX_PAID_MEDIA_TERMINAL_VIDEO_BYTES) {
            throw new PaidMediaVaultError('Paid media terminal video exceeds its size limit')
          }
        }
        await destinationHandle.sync()
      } finally {
        await destinationHandle.close()
      }
      const digest = hash.digest('hex')
      const sourceAfterCopy = await source.stat()
      if (
        byteLength !== input.byteLength ||
        sourceAfterCopy.dev !== sourceBefore.dev ||
        sourceAfterCopy.ino !== sourceBefore.ino ||
        sourceAfterCopy.birthtimeMs !== sourceBefore.birthtimeMs ||
        sourceAfterCopy.mtimeMs !== sourceBefore.mtimeMs ||
        sourceAfterCopy.ctimeMs !== sourceBefore.ctimeMs ||
        sourceAfterCopy.size !== sourceBefore.size
      ) {
        throw new PaidMediaVaultError('Paid media terminal video changed while copying')
      }
      const validation = await this.validateTrustedMedia({
        createReadStream: () =>
          source.createReadStream({
            start: 0,
            end: byteLength - 1,
            autoClose: false,
            highWaterMark: 1024 * 1024
          }),
        mediaType,
        byteLength,
        sha256: digest
      })
      const sourceAfterValidation = await source.stat()
      if (
        sourceAfterValidation.dev !== sourceBefore.dev ||
        sourceAfterValidation.ino !== sourceBefore.ino ||
        sourceAfterValidation.birthtimeMs !== sourceBefore.birthtimeMs ||
        sourceAfterValidation.mtimeMs !== sourceBefore.mtimeMs ||
        sourceAfterValidation.ctimeMs !== sourceBefore.ctimeMs ||
        sourceAfterValidation.size !== sourceBefore.size
      ) {
        throw new PaidMediaVaultError('Paid media terminal video changed during validation')
      }

      const reference = `nachuan-paid-media://sha256/${digest}`
      const destination = join(this.assetsPath, `${digest}.${extension}`)
      let published = false
      if (!existsSync(destination)) {
        this.hardenIfChanged(temporary, false)
        const temporaryIdentity = this.hardenedPaths.get(resolve(temporary))
        try {
          linkSync(temporary, destination)
          unlinkSync(temporary)
          const destinationInfo = lstatSync(destination)
          const destinationIdentity = this.pathIdentity(destinationInfo, false)
          if (this.samePathIdentity(temporaryIdentity, destinationIdentity)) {
            this.hardenedPaths.set(resolve(destination), destinationIdentity)
          } else {
            this.hardenIfChanged(destination, false, destinationInfo)
          }
          published = true
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error
        }
      }
      if (published) this.recordAuthorityCreateDigest(destination, byteLength, digest)
      const verified = await this.openAsset(reference)
      try {
        if (
          verified.byteLength !== byteLength ||
          verified.mediaType !== mediaType ||
          verified.sha256 !== digest
        ) {
          throw new PaidMediaVaultError('Paid media terminal video asset digest conflict')
        }
      } finally {
        await verified.handle.close().catch(() => undefined)
      }
      return {
        sha256: digest,
        byteLength,
        mediaType,
        extension,
        source: 'remote',
        sourceSha256: input.sourceSha256,
        reference,
        validation
      }
    } finally {
      await source.close().catch(() => undefined)
      if (temporary) {
        this.hardenedPaths.delete(resolve(temporary))
        try {
          unlinkSync(temporary)
        } catch {
          // The temporary file was renamed or never created.
        }
      }
    }
  }

  private async writeTerminalVideoAssetBuffer(bytes: Buffer, input: {
    sourceSha256: string
    contentType?: string
  }): Promise<PaidMediaArchivedAsset> {
    if (!Buffer.isBuffer(bytes) || bytes.length < 1 || bytes.length > MAX_PAID_MEDIA_TERMINAL_VIDEO_BYTES) {
      throw new PaidMediaVaultError('Paid media terminal video exceeds its size limit')
    }
    const root = mkdtempSync(join(tmpdir(), 'nachuan-paid-media-buffer-'))
    const path = join(root, 'terminal-video.bin')
    try {
      writeFileSync(path, bytes, { flag: 'wx', mode: 0o600 })
      return await this.writeTerminalVideoAssetFile(path, {
        byteLength: bytes.length,
        ...input
      })
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  }

  private imageItems(result: Record<string, unknown>): Record<string, unknown>[] {
    if (!Array.isArray(result.data) || result.data.length < 1 || result.data.length > 4) {
      throw new PaidMediaVaultError('Paid media image response data is invalid')
    }
    return result.data.map((item) => {
      if (!item || typeof item !== 'object' || Array.isArray(item)) {
        throw new PaidMediaVaultError('Paid media image response item is invalid')
      }
      return item as Record<string, unknown>
    })
  }

  private async archiveImageAssets(
    result: Record<string, unknown>,
    operationId: string
  ): Promise<{
    assets: PaidMediaArchivedAsset[]
    recoveryResult: Record<string, unknown>
  }> {
    const assets: PaidMediaArchivedAsset[] = []
    for (const item of this.imageItems(result)) {
      const hasInline = typeof item.b64_json === 'string' && item.b64_json.length > 0
      const hasRemote = typeof item.url === 'string' && item.url.length > 0
      if (hasInline === hasRemote) {
        throw new PaidMediaVaultError('Paid media image response must contain one asset source')
      }
      if (hasInline) {
        const bytes = decodeCanonicalBase64(
          item.b64_json,
          MAX_PAID_MEDIA_ARCHIVE_ASSET_BYTES,
          'Paid media inline image'
        )
        assets.push(
          await this.writeAsset(bytes, {
            source: 'inline',
            sourceSha256: sha256(bytes)
          })
        )
        continue
      }
      const sourceUrl = validateHttpsAssetUrl(item.url)
      let fetched: PaidMediaRemoteFetchResult
      try {
        fetched = await this.dependencies.fetchRemote(
          sourceUrl,
          MAX_PAID_MEDIA_ARCHIVE_ASSET_BYTES
        )
      } catch (error) {
        throw new PaidMediaVaultError('Paid media archive remote image could not be fetched', {
          cause: error
        })
      }
      if (!fetched || typeof fetched !== 'object') {
        throw new PaidMediaVaultError('Paid media archive fetcher returned invalid bytes')
      }
      const cleanupMarker =
        'filePath' in fetched ? this.createCleanupMarker(operationId, fetched) : null
      try {
        validateHttpsAssetUrl(fetched.finalUrl)
        let bytes: Buffer
        if ('bytes' in fetched) {
          if (!Buffer.isBuffer(fetched.bytes)) {
            throw new PaidMediaVaultError('Paid media archive fetcher returned invalid bytes')
          }
          bytes = fetched.bytes
        } else {
          const info = lstatSync(fetched.filePath)
          if (
            !info.isFile() ||
            info.isSymbolicLink() ||
            info.size !== fetched.byteLength ||
            info.size < 1 ||
            info.size > MAX_PAID_MEDIA_ARCHIVE_ASSET_BYTES
          ) {
            throw new PaidMediaVaultError('Paid media archive fetch file is invalid')
          }
          const pinned = await openFile(fetched.filePath, 'r')
          try {
            const before = await pinned.stat()
            if (
              !before.isFile() ||
              before.dev !== info.dev ||
              before.ino !== info.ino ||
              before.birthtimeMs !== info.birthtimeMs ||
              before.mtimeMs !== info.mtimeMs ||
              before.ctimeMs !== info.ctimeMs ||
              before.size !== info.size
            ) {
              throw new PaidMediaVaultError('Paid media archive fetch file changed before it was pinned')
            }
            bytes = await pinned.readFile()
            const after = await pinned.stat()
            if (
              bytes.length !== fetched.byteLength ||
              after.dev !== before.dev ||
              after.ino !== before.ino ||
              after.birthtimeMs !== before.birthtimeMs ||
              after.mtimeMs !== before.mtimeMs ||
              after.ctimeMs !== before.ctimeMs ||
              after.size !== before.size
            ) {
              throw new PaidMediaVaultError('Paid media archive fetch file changed while reading')
            }
          } finally {
            await pinned.close().catch(() => undefined)
          }
        }
        assets.push(
          await this.writeAsset(bytes, {
            source: 'remote',
            sourceSha256: sha256(sourceUrl),
            contentType: fetched.contentType
          })
        )
      } finally {
        await this.cleanupFetched(fetched, cleanupMarker)
      }
    }
    const recoveryResult: Record<string, unknown> = {
      data: assets.map((asset) => ({ url: asset.reference }))
    }
    // Legacy provider metadata is pass-through only; `created` is never an asset count.
    if (
      (typeof result.created === 'number' && Number.isSafeInteger(result.created)) ||
      (typeof result.created === 'string' && result.created.length <= 128)
    ) {
      recoveryResult.created = result.created
    }
    return { assets, recoveryResult }
  }

  private videoTaskDigest(result: Record<string, unknown>): string {
    const ids = ['task_id', 'video_id', 'id']
      .map((field) => result[field])
      .filter((value): value is string => typeof value === 'string' && value.trim().length > 0)
      .map((value) => value.trim())
    if (
      ids.length < 1 ||
      ids.some(
        (value) =>
          Buffer.byteLength(value, 'utf8') > MAX_VIDEO_TASK_ID_BYTES ||
          /[\u0000-\u001f\u007f]/.test(value)
      ) ||
      new Set(ids).size !== 1
    ) {
      throw new PaidMediaVaultError('Paid media video task receipt is invalid or ambiguous')
    }
    return sha256(ids[0])
  }

  private videoRecoveryResult(result: Record<string, unknown>): Record<string, unknown> {
    const recovery: Record<string, unknown> = {}
    for (const field of ['task_id', 'video_id', 'id'] as const) {
      const value = result[field]
      if (typeof value === 'string' && value.trim().length > 0) recovery[field] = value.trim()
    }
    if (typeof result.status === 'string' && result.status.length <= 128) {
      recovery.status = result.status
    }
    return recovery
  }

  private videoTaskAlias(result: Record<string, unknown>): string | null {
    const aliases = ['task_id', 'video_id', 'id']
      .map((field) => result[field])
      .filter(
        (value): value is string =>
          typeof value === 'string' && VIDEO_TASK_ALIAS_PATTERN.test(value)
      )
    if (aliases.length === 0) return null
    if (new Set(aliases).size !== 1) {
      throw new PaidMediaVaultError('Paid media video task aliases are ambiguous')
    }
    return aliases[0]
  }

  private parseVideoTaskIndex(value: Record<string, unknown>): VideoTaskIndexDocument {
    if (
      !exactKeys(value, [
        'schema',
        'taskAliasSha256',
        'operationId',
        'creationReceiptSha256',
        'createdAt',
        'indexSha256'
      ]) ||
      value.schema !== TASK_INDEX_SCHEMA ||
      typeof value.taskAliasSha256 !== 'string' ||
      !SHA256_PATTERN.test(value.taskAliasSha256) ||
      typeof value.operationId !== 'string' ||
      !OPERATION_ID_PATTERN.test(value.operationId) ||
      typeof value.creationReceiptSha256 !== 'string' ||
      !SHA256_PATTERN.test(value.creationReceiptSha256) ||
      !Number.isSafeInteger(value.createdAt) ||
      Number(value.createdAt) < 0 ||
      typeof value.indexSha256 !== 'string' ||
      !SHA256_PATTERN.test(value.indexSha256)
    ) {
      throw new PaidMediaVaultError('Paid media video task index is invalid')
    }
    const base: VideoTaskIndexBase = {
      schema: TASK_INDEX_SCHEMA,
      taskAliasSha256: value.taskAliasSha256,
      operationId: value.operationId,
      creationReceiptSha256: value.creationReceiptSha256,
      createdAt: value.createdAt as number
    }
    if (sha256(JSON.stringify(base)) !== value.indexSha256) {
      throw new PaidMediaVaultError('Paid media video task index digest does not match')
    }
    return { ...base, indexSha256: value.indexSha256 }
  }

  private ensureVideoTaskIndex(archived: PaidMediaArchivedResult): void {
    if (archived.receipt.kind !== 'video_task') return
    const taskAlias = this.videoTaskAlias(archived.result)
    if (taskAlias === null) return
    const base: VideoTaskIndexBase = {
      schema: TASK_INDEX_SCHEMA,
      taskAliasSha256: this.taskAliasDigest(taskAlias),
      operationId: archived.receipt.operationId,
      creationReceiptSha256: archived.receipt.receiptSha256,
      createdAt: archived.receipt.archivedAt
    }
    const document: VideoTaskIndexDocument = {
      ...base,
      indexSha256: sha256(JSON.stringify(base))
    }
    const path = this.taskIndexFile(taskAlias)
    if (existsSync(path)) {
      const existing = this.parseVideoTaskIndex(
        this.decodeEncrypted(
          this.readRegular(path, MAX_ENCRYPTED_DOCUMENT_BYTES, 'Paid media video task index'),
          'Paid media video task index'
        )
      )
      if (JSON.stringify(existing) !== JSON.stringify(document)) {
        throw new PaidMediaVaultError('Paid media video task index conflicts with its receipt')
      }
      return
    }
    this.writeAtomicNew(
      path,
      this.encodeEncrypted(document),
      'Paid media video task index'
    )
  }

  private readVideoTaskIndex(taskAlias: string): VideoTaskIndexDocument {
    this.prepare()
    const path = this.taskIndexFile(taskAlias)
    if (!existsSync(path)) {
      throw new PaidMediaVaultError('Paid media video task index is missing')
    }
    const index = this.parseVideoTaskIndex(
      this.decodeEncrypted(
        this.readRegular(path, MAX_ENCRYPTED_DOCUMENT_BYTES, 'Paid media video task index'),
        'Paid media video task index'
      )
    )
    if (index.taskAliasSha256 !== this.taskAliasDigest(taskAlias)) {
      throw new PaidMediaVaultError('Paid media video task index alias does not match')
    }
    return index
  }

  async verifyVideoTaskBinding(taskAlias: string): Promise<PaidMediaVideoTaskBinding> {
    const index = this.readVideoTaskIndex(taskAlias)
    const creation = await this.verifyArchive(index.operationId)
    if (
      creation.receipt.kind !== 'video_task' ||
      creation.receipt.receiptSha256 !== index.creationReceiptSha256 ||
      creation.receipt.taskReceiptIdSha256 !== index.taskAliasSha256 ||
      this.videoTaskAlias(creation.result) !== taskAlias
    ) {
      throw new PaidMediaVaultError('Paid media video task binding does not match its archive')
    }
    return {
      operationId: index.operationId,
      taskAliasSha256: index.taskAliasSha256,
      creationReceiptSha256: index.creationReceiptSha256,
      createdAt: index.createdAt
    }
  }

  private async finishArchivedStageCleanup(
    operationId: string,
    leases: readonly Pick<StageLeaseEvent, 'leaseId'>[]
  ): Promise<PaidMediaArchivedResult> {
    for (const lease of leases) {
      let current = this.loadAuthorityIndex().stageLeases.get(lease.leaseId)
      if (!current || current.operationId !== operationId) {
        throw new PaidMediaVaultError('Paid media archived stage lease is missing')
      }
      if (current.state === 'archived_cleaned' || current.state === 'held') continue
      if (current.state === 'opened') {
        current = this.makeStageTransition(
          current,
          'archived_cleanup_pending',
          current.directory,
          current.file,
          'archive_committed'
        )
        this.appendStageAuthorityEvent(current)
      }
      if (current.state !== 'archived_cleanup_pending') {
        throw new PaidMediaVaultError('Paid media archived stage lease state conflicts')
      }
      await this.performPendingStageCleanup(current)
    }
    return this.verifyArchive(operationId)
  }

  async archiveRecoveredStageImageResult(input: {
    operationId: string
    status: 200
    result: PaidMediaAssetResult
    leases: readonly Readonly<{
      leaseId: string
      ordinal: number
      generation: number
      resultSha256: string
      leaseStateDigest: string
    }>[]
    validations: readonly PaidMediaValidationReceipt[]
  }): Promise<PaidMediaArchivedResult> {
    this.assertStageMutationAuthority()
    if (
      !input ||
      typeof input !== 'object' ||
      !exactKeys(input as unknown as Record<string, unknown>, [
        'operationId',
        'status',
        'result',
        'leases',
        'validations'
      ]) ||
      input.status !== 200 ||
      !Array.isArray(input.leases) ||
      !Array.isArray(input.validations)
    ) {
      throw new PaidMediaVaultError('Paid media recovered stage archive input is invalid')
    }
    const operationId = requireOperationId(input.operationId)
    const result = parsePaidMediaAssetResult(input.result)
    if (
      result.kind !== 'image' ||
      input.leases.length !== result.assets.length ||
      input.validations.length !== result.assets.length
    ) {
      throw new PaidMediaVaultError('Paid media recovered stage image result is inconsistent')
    }
    const request = await this.readExactRequest(operationId)
    if (request.path !== '/v1/images/generations') {
      throw new PaidMediaVaultError('Paid media recovered stage archive request kind conflicts')
    }
    const resultSha256 = paidMediaAssetResultDigest(result)
    const responseBytes = canonicalPaidMediaAssetResult(result)
    const responseSha256 = sha256(responseBytes)
    const archivePath = this.archiveFile(operationId)
    const archiveExists = existsSync(archivePath)
    const authority = this.loadAuthorityIndex()
    const bindings = input.leases.map((candidate, ordinal) => {
      if (
        !candidate ||
        typeof candidate !== 'object' ||
        !exactKeys(candidate as unknown as Record<string, unknown>, [
          'leaseId',
          'ordinal',
          'generation',
          'resultSha256',
          'leaseStateDigest'
        ]) ||
        candidate.ordinal !== ordinal ||
        !Number.isSafeInteger(candidate.generation) ||
        candidate.generation < 0
      ) {
        throw new PaidMediaVaultError('Paid media recovered stage lease binding is invalid')
      }
      const leaseId = requireNonzeroSha256(
        candidate.leaseId,
        'Paid media recovered stage lease id'
      )
      const boundResultSha256 = requireNonzeroSha256(
        candidate.resultSha256,
        'Paid media recovered stage result digest'
      )
      const leaseStateDigest = requireNonzeroSha256(
        candidate.leaseStateDigest,
        'Paid media recovered stage lease-state digest'
      )
      const descriptor = result.assets[ordinal]!
      const stage = authority.stageLeases.get(leaseId)
      const validation = parseTrustedValidationReceipt(input.validations[ordinal], {
        mediaType: descriptor.mediaType as PaidMediaArchivedAsset['mediaType'],
        byteLength: descriptor.byteLength,
        sha256: descriptor.sha256
      })
      if (
        validation.receiptSha256 !== descriptor.validationReceiptSha256 ||
        boundResultSha256 !== resultSha256 ||
        !stage ||
        (archiveExists
          ? !['opened', 'archived_cleanup_pending', 'archived_cleaned', 'held'].includes(
              stage.state
            )
          : stage.state !== 'opened') ||
        stage.operationId !== operationId ||
        stage.turnId !== result.turnId ||
        stage.resultSha256 !== resultSha256 ||
        stage.ordinal !== ordinal ||
        stage.generation !== candidate.generation ||
        ((archiveExists === false || stage.state === 'opened') &&
          stage.leaseStateDigest !== leaseStateDigest) ||
        JSON.stringify(stage.descriptor) !== JSON.stringify(descriptor)
      ) {
        throw new PaidMediaVaultError('Paid media recovered stage archive binding conflicts')
      }
      return { stage, descriptor, validation }
    })
    if (new Set(bindings.map(({ stage }) => stage.leaseId)).size !== bindings.length) {
      throw new PaidMediaVaultError('Paid media recovered stage lease bindings are duplicated')
    }
    if (archiveExists) {
      const existing = await this.verifyArchive(operationId)
      if (
        existing.receipt.path !== '/v1/images/generations' ||
        existing.receipt.status !== 200 ||
        existing.receipt.responseSha256 !== responseSha256 ||
        existing.receipt.responseByteLength !== responseBytes.length ||
        existing.receipt.assets.length !== bindings.length ||
        existing.receipt.assets.some((asset, ordinal) => {
          const expected = bindings[ordinal]!
          return (
            asset.sha256 !== expected.descriptor.sha256 ||
            asset.byteLength !== expected.descriptor.byteLength ||
            asset.mediaType !== expected.descriptor.mediaType ||
            asset.sourceSha256 !== paidMediaAssetTokenHash(expected.descriptor.token) ||
            asset.validation?.schema !== TRUSTED_VALIDATION_SCHEMA ||
            asset.validation.receiptSha256 !== expected.validation.receiptSha256
          )
        })
      ) {
        throw new PaidMediaVaultError('Paid media archive conflicts with the existing result')
      }
      return this.finishArchivedStageCleanup(operationId, bindings.map(({ stage }) => stage))
    }

    const records: StageOpenHandleRecord[] = []
    try {
      for (const { stage, descriptor } of bindings) {
        const inspection = this.inspectStageLeaf(stage)
        if (inspection.kind !== 'exact' || inspection.file === null) {
          throw new PaidMediaVaultError('Paid media recovered stage object is not exact')
        }
        const paths = this.stagePaths(stage)
        const handle = await openFile(paths.filePath, 'r')
        try {
          const handleIdentity = await this.stageHandleIdentity(handle, paths.filePath)
          if (!this.sameStageStableIdentity(inspection.file, handleIdentity)) {
            throw new PaidMediaVaultError('Paid media recovered stage handle identity changed')
          }
          records.push({
            leaseId: stage.leaseId,
            operationId,
            turnId: result.turnId,
            ordinal: stage.ordinal,
            generation: stage.generation,
            descriptor,
            handle,
            filePath: paths.filePath,
            directoryPath: paths.directoryPath,
            tempRootPath: paths.tempRootPath,
            tempRootIdentity: stage.tempRoot,
            directoryIdentity: inspection.directory,
            fileIdentity: inspection.file,
            offset: descriptor.byteLength,
            digest: createHash('sha256'),
            state: 'sealed',
            witness: Object.freeze({})
          })
        } catch (error) {
          await handle.close().catch(() => undefined)
          throw error
        }
      }

      const assets: PaidMediaArchivedAsset[] = []
      for (const [ordinal, record] of records.entries()) {
        const binding = bindings[ordinal]!
        assets.push(
          await this.writeValidatedStageImageAssetFromHandle(
            record,
            binding.descriptor,
            binding.validation
          )
        )
      }
      const recoveryResult: Record<string, unknown> = {
        data: assets.map((asset) => ({ url: asset.reference })),
        created: result.created
      }
      const recoveryBytes = Buffer.from(JSON.stringify(recoveryResult), 'utf8')
      if (recoveryBytes.length < 2 || recoveryBytes.length > MAX_RECOVERY_JSON_BYTES) {
        throw new PaidMediaVaultError(
          'Paid media archive recovery manifest exceeds its size limit'
        )
      }
      const base: ArchiveBase = {
        schema: ARCHIVE_SCHEMA,
        operationId,
        path: '/v1/images/generations',
        requestSha256: request.requestSha256,
        responseSha256,
        responseByteLength: responseBytes.length,
        recoverySha256: sha256(recoveryBytes),
        recoveryJsonUtf8Base64: recoveryBytes.toString('base64'),
        status: 200,
        kind: 'image',
        taskReceiptIdSha256: null,
        assets,
        archivedAt: requireNow(this.dependencies.now)
      }
      const document: ArchiveDocument = {
        ...base,
        receiptSha256: sha256(JSON.stringify(base))
      }
      this.ensureDiscoveryIndex(document, this.requestModel(request.encodedBody))
      this.writeAtomicNew(
        archivePath,
        this.encodeEncrypted(document),
        'Paid media archive receipt'
      )
      await this.verifyArchive(operationId)
      await this.dependencies.beforeArchivedStageCleanupIntent?.({ operationId })
    } finally {
      for (const record of records) {
        record.state = 'revoked'
        await record.handle.close().catch((error) => this.dependencies.onCleanupError?.(error))
      }
    }
    return this.finishArchivedStageCleanup(operationId, bindings.map(({ stage }) => stage))
  }

  async archiveSealedStageImageResult(input: {
    operationId: string
    status: 200
    result: PaidMediaAssetResult
    assets: readonly PaidMediaSealedStageArchiveAsset[]
  }): Promise<PaidMediaArchivedResult> {
    this.assertStageMutationAuthority()
    if (
      !input ||
      typeof input !== 'object' ||
      !exactKeys(input as unknown as Record<string, unknown>, [
        'operationId',
        'status',
        'result',
        'assets'
      ]) ||
      input.status !== 200 ||
      !Array.isArray(input.assets)
    ) {
      throw new PaidMediaVaultError('Paid media sealed stage archive input is invalid')
    }
    const operationId = requireOperationId(input.operationId)
    const result = parsePaidMediaAssetResult(input.result)
    if (
      result.kind !== 'image' ||
      input.assets.length !== result.assets.length
    ) {
      throw new PaidMediaVaultError('Paid media sealed stage image result is inconsistent')
    }
    const request = await this.readExactRequest(operationId)
    if (request.path !== '/v1/images/generations') {
      throw new PaidMediaVaultError('Paid media sealed stage archive request kind conflicts')
    }
    const resultSha256 = paidMediaAssetResultDigest(result)
    const responseBytes = canonicalPaidMediaAssetResult(result)
    const responseSha256 = sha256(responseBytes)
    const archivePath = this.archiveFile(operationId)
    const archiveExists = existsSync(archivePath)
    const authority = this.loadAuthorityIndex()
    const prepared = input.assets.map((candidate, ordinal) => {
      if (
        !candidate ||
        typeof candidate !== 'object' ||
        !exactKeys(candidate as unknown as Record<string, unknown>, [
          'ordinal',
          'sealed',
          'validation'
        ]) ||
        candidate.ordinal !== ordinal
      ) {
        throw new PaidMediaVaultError('Paid media sealed stage archive asset is invalid')
      }
      const record = this.lookupSealedStageCapability(candidate.sealed)
      const descriptor = result.assets[ordinal]!
      const stage = authority.stageLeases.get(record.leaseId)
      const validation = parseTrustedValidationReceipt(candidate.validation, {
        mediaType: descriptor.mediaType as PaidMediaArchivedAsset['mediaType'],
        byteLength: descriptor.byteLength,
        sha256: descriptor.sha256
      })
      if (
        validation.receiptSha256 !== descriptor.validationReceiptSha256 ||
        !stage ||
        (archiveExists
          ? !['opened', 'archived_cleanup_pending', 'archived_cleaned', 'held'].includes(
              stage.state
            )
          : stage.state !== 'opened' || record.state !== 'sealed') ||
        stage.operationId !== operationId ||
        stage.turnId !== result.turnId ||
        stage.resultSha256 !== resultSha256 ||
        stage.ordinal !== ordinal ||
        stage.generation !== record.generation ||
        record.operationId !== operationId ||
        record.turnId !== result.turnId ||
        record.ordinal !== ordinal ||
        JSON.stringify(stage.descriptor) !== JSON.stringify(descriptor) ||
        JSON.stringify(record.descriptor) !== JSON.stringify(descriptor)
      ) {
        throw new PaidMediaVaultError('Paid media sealed stage archive binding conflicts')
      }
      return { record, stage, descriptor, validation }
    })
    if (archiveExists) {
      const existing = await this.verifyArchive(operationId)
      if (
        existing.receipt.path !== '/v1/images/generations' ||
        existing.receipt.status !== 200 ||
        existing.receipt.responseSha256 !== responseSha256 ||
        existing.receipt.responseByteLength !== responseBytes.length ||
        existing.receipt.assets.length !== prepared.length ||
        existing.receipt.assets.some((asset, ordinal) => {
          const expected = prepared[ordinal]!
          return (
            asset.sha256 !== expected.descriptor.sha256 ||
            asset.byteLength !== expected.descriptor.byteLength ||
            asset.mediaType !== expected.descriptor.mediaType ||
            asset.sourceSha256 !== paidMediaAssetTokenHash(expected.descriptor.token) ||
            asset.validation?.schema !== TRUSTED_VALIDATION_SCHEMA ||
            asset.validation.receiptSha256 !== expected.validation.receiptSha256
          )
        })
      ) {
        throw new PaidMediaVaultError('Paid media archive conflicts with the existing result')
      }
      return this.finishArchivedStageCleanup(operationId, prepared.map(({ stage }) => stage))
    }

    const assets: PaidMediaArchivedAsset[] = []
    for (const { record, descriptor, validation } of prepared) {
      assets.push(
        await this.writeValidatedStageImageAssetFromHandle(record, descriptor, validation)
      )
    }
    const recoveryResult: Record<string, unknown> = {
      data: assets.map((asset) => ({ url: asset.reference })),
      // Provider Unix timestamp carried across Python/JSON/TypeScript; never an asset count.
      created: result.created
    }
    const recoveryBytes = Buffer.from(JSON.stringify(recoveryResult), 'utf8')
    if (recoveryBytes.length < 2 || recoveryBytes.length > MAX_RECOVERY_JSON_BYTES) {
      throw new PaidMediaVaultError('Paid media archive recovery manifest exceeds its size limit')
    }
    const base: ArchiveBase = {
      schema: ARCHIVE_SCHEMA,
      operationId,
      path: '/v1/images/generations',
      requestSha256: request.requestSha256,
      responseSha256,
      responseByteLength: responseBytes.length,
      recoverySha256: sha256(recoveryBytes),
      recoveryJsonUtf8Base64: recoveryBytes.toString('base64'),
      status: 200,
      kind: 'image',
      taskReceiptIdSha256: null,
      assets,
      archivedAt: requireNow(this.dependencies.now)
    }
    const document: ArchiveDocument = {
      ...base,
      receiptSha256: sha256(JSON.stringify(base))
    }
    this.ensureDiscoveryIndex(document, this.requestModel(request.encodedBody))
    this.writeAtomicNew(
      archivePath,
      this.encodeEncrypted(document),
      'Paid media archive receipt'
    )
    // The durable archive and every content-addressed asset are verified before
    // any stage cleanup intent is allowed into the authority journal.
    await this.verifyArchive(operationId)
    await this.dependencies.beforeArchivedStageCleanupIntent?.({ operationId })
    return this.finishArchivedStageCleanup(operationId, prepared.map(({ stage }) => stage))
  }

  async archiveResult(input: {
    operationId: string
    path: PaidMediaPath
    status: number
    responseJson: string
  }): Promise<PaidMediaArchivedResult> {
    if (
      !input ||
      typeof input !== 'object' ||
      !exactKeys(input as unknown as Record<string, unknown>, [
        'operationId',
        'path',
        'status',
        'responseJson'
      ]) ||
      !validPath(input.path) ||
      !Number.isSafeInteger(input.status) ||
      input.status < 200 ||
      input.status > 299 ||
      typeof input.responseJson !== 'string'
    ) {
      throw new PaidMediaVaultError('Paid media archive result input is invalid')
    }
    const operationId = requireOperationId(input.operationId)
    const responseBytes = Buffer.from(input.responseJson, 'utf8')
    if (
      responseBytes.length < 2 ||
      responseBytes.length > MAX_PAID_MEDIA_ARCHIVE_RESPONSE_BYTES ||
      responseBytes.toString('utf8') !== input.responseJson
    ) {
      throw new PaidMediaVaultError('Paid media archive response bytes are invalid')
    }
    const result = parseObject(input.responseJson, 'Paid media archive response')
    const request = await this.verifyExactRequest({
      operationId,
      path: input.path,
      encodedBody: (await this.readExactRequest(operationId)).encodedBody
    })
    this.prepare()
    const archivePath = this.archiveFile(operationId)
    if (existsSync(archivePath)) {
      const existing = await this.verifyArchive(operationId)
      if (
        existing.receipt.path !== input.path ||
        existing.receipt.status !== input.status ||
        existing.receipt.responseSha256 !== sha256(responseBytes) ||
        existing.receipt.responseByteLength !== responseBytes.length
      ) {
        throw new PaidMediaVaultError('Paid media archive conflicts with the existing result')
      }
      this.ensureDiscoveryIndex(existing.receipt, this.requestModel(request.encodedBody))
      this.ensureVideoTaskIndex(existing)
      return existing
    }

    const kind = input.path === '/v1/images/generations' ? 'image' : 'video_task'
    const imageArchive =
      kind === 'image' ? await this.archiveImageAssets(result, operationId) : null
    const assets = imageArchive?.assets ?? []
    const taskReceiptIdSha256 = kind === 'video_task' ? this.videoTaskDigest(result) : null
    const recoveryResult =
      imageArchive?.recoveryResult ?? this.videoRecoveryResult(result)
    const recoveryJson = JSON.stringify(recoveryResult)
    const recoveryBytes = Buffer.from(recoveryJson, 'utf8')
    if (recoveryBytes.length < 2 || recoveryBytes.length > MAX_RECOVERY_JSON_BYTES) {
      throw new PaidMediaVaultError('Paid media archive recovery manifest exceeds its size limit')
    }
    const base: ArchiveBase = {
      schema: ARCHIVE_SCHEMA,
      operationId,
      path: input.path,
      requestSha256: request.requestSha256,
      responseSha256: sha256(responseBytes),
      responseByteLength: responseBytes.length,
      recoverySha256: sha256(recoveryBytes),
      recoveryJsonUtf8Base64: recoveryBytes.toString('base64'),
      status: input.status,
      kind,
      taskReceiptIdSha256,
      assets,
      archivedAt: requireNow(this.dependencies.now)
    }
    const document: ArchiveDocument = {
      ...base,
      receiptSha256: sha256(JSON.stringify(base))
    }
    // Write the compact index first. A crash can therefore leave, at worst, a
    // stale index entry that discovery filters by archive existence; it cannot
    // leave a committed archive permanently undiscoverable.
    this.ensureDiscoveryIndex(document, this.requestModel(request.encodedBody))
    this.writeAtomicNew(
      archivePath,
      this.encodeEncrypted(document),
      'Paid media archive receipt'
    )
    const archived = await this.verifyArchive(operationId)
    this.ensureVideoTaskIndex(archived)
    return archived
  }

  private parseArchive(value: Record<string, unknown>): ArchiveDocument {
    if (
      !exactKeys(value, [
        'schema',
        'operationId',
        'path',
        'requestSha256',
        'responseSha256',
        'responseByteLength',
        'recoverySha256',
        'recoveryJsonUtf8Base64',
        'status',
        'kind',
        'taskReceiptIdSha256',
        'assets',
        'archivedAt',
        'receiptSha256'
      ]) ||
      value.schema !== ARCHIVE_SCHEMA ||
      typeof value.operationId !== 'string' ||
      !OPERATION_ID_PATTERN.test(value.operationId) ||
      !validPath(value.path) ||
      typeof value.requestSha256 !== 'string' ||
      !SHA256_PATTERN.test(value.requestSha256) ||
      typeof value.responseSha256 !== 'string' ||
      !SHA256_PATTERN.test(value.responseSha256) ||
      !Number.isSafeInteger(value.responseByteLength) ||
      Number(value.responseByteLength) < 2 ||
      Number(value.responseByteLength) > MAX_PAID_MEDIA_ARCHIVE_RESPONSE_BYTES ||
      typeof value.recoverySha256 !== 'string' ||
      !SHA256_PATTERN.test(value.recoverySha256) ||
      !Number.isSafeInteger(value.status) ||
      Number(value.status) < 200 ||
      Number(value.status) > 299 ||
      (value.kind !== 'image' && value.kind !== 'video_task') ||
      (value.taskReceiptIdSha256 !== null &&
        (typeof value.taskReceiptIdSha256 !== 'string' ||
          !SHA256_PATTERN.test(value.taskReceiptIdSha256))) ||
      !Array.isArray(value.assets) ||
      !Number.isSafeInteger(value.archivedAt) ||
      Number(value.archivedAt) < 0 ||
      typeof value.receiptSha256 !== 'string' ||
      !SHA256_PATTERN.test(value.receiptSha256)
    ) {
      throw new PaidMediaVaultError('Paid media archive receipt is invalid')
    }
    const recoveryBytes = decodeCanonicalBase64(
      value.recoveryJsonUtf8Base64,
      MAX_RECOVERY_JSON_BYTES,
      'Paid media archive recovery manifest'
    )
    const recoveryJson = recoveryBytes.toString('utf8')
    if (!Buffer.from(recoveryJson, 'utf8').equals(recoveryBytes)) {
      throw new PaidMediaVaultError('Paid media archive recovery manifest is not valid UTF-8')
    }
    parseObject(recoveryJson, 'Paid media archive recovery manifest')
    if (sha256(recoveryBytes) !== value.recoverySha256) {
      throw new PaidMediaVaultError('Paid media archive recovery manifest digest does not match')
    }
    const assets: PaidMediaArchivedAsset[] = value.assets.map((candidate) => {
      if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) {
        throw new PaidMediaVaultError('Paid media archive asset receipt is invalid')
      }
      const asset = candidate as Record<string, unknown>
      const hasValidation = Object.prototype.hasOwnProperty.call(asset, 'validation')
      if (
        !exactKeys(
          asset,
          [
            'sha256',
            'byteLength',
            'mediaType',
            'extension',
            'source',
            'sourceSha256',
            'reference',
            ...(hasValidation ? ['validation'] : [])
          ]
        ) ||
        typeof asset.sha256 !== 'string' ||
        !SHA256_PATTERN.test(asset.sha256) ||
        !Number.isSafeInteger(asset.byteLength) ||
        Number(asset.byteLength) < 1 ||
        Number(asset.byteLength) > MAX_PAID_MEDIA_ARCHIVE_ASSET_BYTES ||
        !['image/png', 'image/jpeg', 'image/gif', 'image/webp'].includes(
          String(asset.mediaType)
        ) ||
        !['png', 'jpg', 'gif', 'webp'].includes(String(asset.extension)) ||
        (asset.source !== 'inline' && asset.source !== 'remote') ||
        typeof asset.sourceSha256 !== 'string' ||
        !SHA256_PATTERN.test(asset.sourceSha256) ||
        asset.reference !== `nachuan-paid-media://sha256/${asset.sha256}`
      ) {
        throw new PaidMediaVaultError('Paid media archive asset receipt is invalid')
      }
      const normalized = asset as unknown as PaidMediaArchivedAsset
      const validation = parseStoredValidationReceipt(asset.validation, normalized)
      return { ...normalized, ...(validation ? { validation } : {}) }
    })
    if (
      (value.kind === 'image' &&
        (assets.length < 1 || value.taskReceiptIdSha256 !== null)) ||
      (value.kind === 'video_task' &&
        (assets.length !== 0 || value.taskReceiptIdSha256 === null))
    ) {
      throw new PaidMediaVaultError('Paid media archive kind fields are inconsistent')
    }
    const base: ArchiveBase = {
      schema: ARCHIVE_SCHEMA,
      operationId: value.operationId,
      path: value.path,
      requestSha256: value.requestSha256,
      responseSha256: value.responseSha256,
      responseByteLength: value.responseByteLength as number,
      recoverySha256: value.recoverySha256,
      recoveryJsonUtf8Base64: value.recoveryJsonUtf8Base64 as string,
      status: value.status as number,
      kind: value.kind,
      taskReceiptIdSha256: value.taskReceiptIdSha256 as string | null,
      assets,
      archivedAt: value.archivedAt as number
    }
    if (sha256(JSON.stringify(base)) !== value.receiptSha256) {
      throw new PaidMediaVaultError('Paid media archive receipt digest does not match')
    }
    return { ...base, receiptSha256: value.receiptSha256 }
  }

  private archiveStageCleanupComplete(document: ArchiveDocument): boolean {
    if (!this.authorityStrict) return true
    const authority = this.loadAuthorityIndex()
    const operationLeases = authority.stageOperationIndex.get(document.operationId)
    if (!operationLeases || operationLeases.size === 0) return true
    const stages = [...operationLeases]
      .map((leaseId) => authority.stageLeases.get(leaseId))
      .sort((left, right) => (left?.ordinal ?? -1) - (right?.ordinal ?? -1))
    if (
      document.kind !== 'image' ||
      stages.length !== document.assets.length ||
      stages.some((stage, ordinal) => {
        const asset = document.assets[ordinal]
        return (
          !stage ||
          stage.ordinal !== ordinal ||
          stage.state !== 'archived_cleaned' ||
          !asset ||
          asset.sha256 !== stage.descriptor.sha256 ||
          asset.byteLength !== stage.descriptor.byteLength ||
          asset.mediaType !== stage.descriptor.mediaType ||
          asset.sourceSha256 !== paidMediaAssetTokenHash(stage.descriptor.token) ||
          asset.validation?.schema !== TRUSTED_VALIDATION_SCHEMA ||
          asset.validation.receiptSha256 !== stage.descriptor.validationReceiptSha256
        )
      })
    ) {
      return false
    }
    return true
  }

  async verifyArchive(operationId: string): Promise<PaidMediaArchivedResult> {
    this.prepare()
    const archivePath = this.archiveFile(operationId)
    if (!existsSync(archivePath)) {
      throw new PaidMediaVaultError('Paid media archive receipt is missing')
    }
    const document = this.parseArchive(
      this.decodeEncrypted(
        this.readRegular(
          archivePath,
          MAX_ENCRYPTED_DOCUMENT_BYTES,
          'Paid media archive receipt'
        ),
        'Paid media archive receipt'
      )
    )
    if (document.operationId !== operationId) {
      throw new PaidMediaVaultError('Paid media archive operation does not match')
    }
    const request = await this.readExactRequest(operationId)
    if (
      request.path !== document.path ||
      request.requestSha256 !== document.requestSha256
    ) {
      throw new PaidMediaVaultError('Paid media archive request binding does not match')
    }
    for (const asset of document.assets) {
      const opened = await this.openAsset(asset.reference)
      try {
        if (
          opened.byteLength !== asset.byteLength ||
          opened.sha256 !== asset.sha256 ||
          opened.mediaType !== asset.mediaType
        ) {
          throw new PaidMediaVaultError('Paid media archive asset does not match its receipt')
        }
        this.requireTrustedAssetValidation(asset)
      } finally {
        await opened.handle.close().catch(() => undefined)
      }
    }
    const recoveryJson = decodeCanonicalBase64(
      document.recoveryJsonUtf8Base64,
      MAX_RECOVERY_JSON_BYTES,
      'Paid media archive recovery manifest'
    ).toString('utf8')
    return {
      receipt: publicReceipt(document),
      recoveryJson,
      result: parseObject(recoveryJson, 'Paid media archive recovery manifest'),
      cleanupComplete:
        !this.hasPendingCleanup(document.operationId) &&
        this.archiveStageCleanupComplete(document)
    }
  }

  private terminalUrl(result: Record<string, unknown>): string | null {
    const nested =
      result.data && typeof result.data === 'object' && !Array.isArray(result.data)
        ? (result.data as Record<string, unknown>)
        : null
    const urls = [
      result.url,
      result.video_url,
      result.output_url,
      result.download_url,
      nested?.url,
      nested?.video_url,
      nested?.output_url,
      nested?.download_url
    ]
      .filter((value): value is string => typeof value === 'string' && value.trim().length > 0)
      .map((value) => validateHttpsAssetUrl(value.trim()))
    if (urls.length === 0) return null
    if (new Set(urls).size !== 1) {
      throw new PaidMediaVaultError('Paid media terminal video URLs are ambiguous')
    }
    return urls[0]
  }

  private terminalRecoveryResult(
    providerResult: Record<string, unknown>,
    asset: PaidMediaArchivedAsset | null
  ): Record<string, unknown> {
    const recovery: Record<string, unknown> = {}
    const nested =
      providerResult.data &&
      typeof providerResult.data === 'object' &&
      !Array.isArray(providerResult.data)
        ? (providerResult.data as Record<string, unknown>)
        : null
    for (const field of ['task_id', 'video_id', 'id'] as const) {
      const value = providerResult[field]
      if (typeof value === 'string' && value.length <= MAX_VIDEO_TASK_ID_BYTES) {
        recovery[field] = value
      }
    }
    if (typeof providerResult.status === 'string' && providerResult.status.length <= 128) {
      recovery.status = providerResult.status
    }
    if (typeof providerResult.progress === 'number' && Number.isFinite(providerResult.progress)) {
      recovery.progress = providerResult.progress
    }
    const stableNested: Record<string, unknown> = {}
    if (nested) {
      if (typeof nested.status === 'string' && nested.status.length <= 128) {
        stableNested.status = nested.status
      }
      if (typeof nested.progress === 'number' && Number.isFinite(nested.progress)) {
        stableNested.progress = nested.progress
      }
      if (typeof nested.error === 'string' && nested.error.length <= 2048) {
        stableNested.error = nested.error
      }
    }
    if (asset !== null) {
      const reference = asset.reference
      for (const field of ['url', 'video_url', 'output_url', 'download_url'] as const) {
        if (Object.prototype.hasOwnProperty.call(providerResult, field)) {
          recovery[field] = reference
        }
      }
      if (nested) {
        for (const field of ['url', 'video_url', 'output_url', 'download_url'] as const) {
          if (Object.prototype.hasOwnProperty.call(nested, field)) {
            stableNested[field] = reference
          }
        }
      }
      if (Object.keys(stableNested).length > 0) recovery.data = stableNested
      if (
        !Object.prototype.hasOwnProperty.call(recovery, 'url') &&
        !Object.prototype.hasOwnProperty.call(recovery, 'video_url') &&
        !Object.prototype.hasOwnProperty.call(recovery, 'output_url') &&
        !Object.prototype.hasOwnProperty.call(recovery, 'download_url') &&
        !Object.prototype.hasOwnProperty.call(recovery, 'data')
      ) {
        recovery.video_url = reference
      }
    } else {
      if (typeof providerResult.error === 'string' && providerResult.error.length <= 2048) {
        recovery.error = providerResult.error
      }
      if (Object.keys(stableNested).length > 0) recovery.data = stableNested
    }
    return recovery
  }

  private parseTerminalAsset(value: unknown): PaidMediaArchivedAsset | null {
    if (value === null) return null
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      throw new PaidMediaVaultError('Paid media terminal video asset receipt is invalid')
    }
    const asset = value as Record<string, unknown>
    const hasValidation = Object.prototype.hasOwnProperty.call(asset, 'validation')
    if (
      !exactKeys(
        asset,
        [
          'sha256',
          'byteLength',
          'mediaType',
          'extension',
          'source',
          'sourceSha256',
          'reference',
          ...(hasValidation ? ['validation'] : [])
        ]
      ) ||
      typeof asset.sha256 !== 'string' ||
      !SHA256_PATTERN.test(asset.sha256) ||
      !Number.isSafeInteger(asset.byteLength) ||
      Number(asset.byteLength) < 1 ||
      Number(asset.byteLength) > MAX_PAID_MEDIA_TERMINAL_VIDEO_BYTES ||
      (asset.mediaType !== 'video/mp4' && asset.mediaType !== 'video/webm') ||
      (asset.extension !== 'mp4' && asset.extension !== 'webm') ||
      asset.source !== 'remote' ||
      typeof asset.sourceSha256 !== 'string' ||
      !SHA256_PATTERN.test(asset.sourceSha256) ||
      asset.reference !== `nachuan-paid-media://sha256/${asset.sha256}`
    ) {
      throw new PaidMediaVaultError('Paid media terminal video asset receipt is invalid')
    }
    const normalized = asset as unknown as PaidMediaArchivedAsset
    const validation = parseStoredValidationReceipt(asset.validation, normalized)
    return { ...normalized, ...(validation ? { validation } : {}) }
  }

  private parseTerminal(value: Record<string, unknown>): TerminalDocument {
    if (
      !exactKeys(value, [
        'schema',
        'taskAliasSha256',
        'operationId',
        'creationReceiptSha256',
        'providerResultSha256',
        'providerResultByteLength',
        'recoverySha256',
        'recoveryJsonUtf8Base64',
        'asset',
        'archivedAt',
        'receiptSha256'
      ]) ||
      value.schema !== TERMINAL_SCHEMA ||
      typeof value.taskAliasSha256 !== 'string' ||
      !SHA256_PATTERN.test(value.taskAliasSha256) ||
      typeof value.operationId !== 'string' ||
      !OPERATION_ID_PATTERN.test(value.operationId) ||
      typeof value.creationReceiptSha256 !== 'string' ||
      !SHA256_PATTERN.test(value.creationReceiptSha256) ||
      typeof value.providerResultSha256 !== 'string' ||
      !SHA256_PATTERN.test(value.providerResultSha256) ||
      !Number.isSafeInteger(value.providerResultByteLength) ||
      Number(value.providerResultByteLength) < 2 ||
      Number(value.providerResultByteLength) > MAX_POLL_RESPONSE_BYTES_FOR_VAULT ||
      typeof value.recoverySha256 !== 'string' ||
      !SHA256_PATTERN.test(value.recoverySha256) ||
      !Number.isSafeInteger(value.archivedAt) ||
      Number(value.archivedAt) < 0 ||
      typeof value.receiptSha256 !== 'string' ||
      !SHA256_PATTERN.test(value.receiptSha256)
    ) {
      throw new PaidMediaVaultError('Paid media terminal video receipt is invalid')
    }
    const recoveryBytes = decodeCanonicalBase64(
      value.recoveryJsonUtf8Base64,
      MAX_RECOVERY_JSON_BYTES,
      'Paid media terminal recovery manifest'
    )
    const recoveryJson = recoveryBytes.toString('utf8')
    if (!Buffer.from(recoveryJson, 'utf8').equals(recoveryBytes)) {
      throw new PaidMediaVaultError('Paid media terminal recovery manifest is not valid UTF-8')
    }
    parseObject(recoveryJson, 'Paid media terminal recovery manifest')
    if (sha256(recoveryBytes) !== value.recoverySha256) {
      throw new PaidMediaVaultError('Paid media terminal recovery manifest digest does not match')
    }
    const asset = this.parseTerminalAsset(value.asset)
    const base: TerminalBase = {
      schema: TERMINAL_SCHEMA,
      taskAliasSha256: value.taskAliasSha256,
      operationId: value.operationId,
      creationReceiptSha256: value.creationReceiptSha256,
      providerResultSha256: value.providerResultSha256,
      providerResultByteLength: value.providerResultByteLength as number,
      recoverySha256: value.recoverySha256,
      recoveryJsonUtf8Base64: value.recoveryJsonUtf8Base64 as string,
      asset,
      archivedAt: value.archivedAt as number
    }
    if (sha256(JSON.stringify(base)) !== value.receiptSha256) {
      throw new PaidMediaVaultError('Paid media terminal video receipt digest does not match')
    }
    return { ...base, receiptSha256: value.receiptSha256 }
  }

  async archiveTerminalMediaForTask(
    taskAlias: string,
    providerResult: Record<string, unknown>
  ): Promise<PaidMediaTerminalArchiveResult> {
    if (!providerResult || typeof providerResult !== 'object' || Array.isArray(providerResult)) {
      throw new PaidMediaVaultError('Paid media terminal video result is invalid')
    }
    const providerJson = JSON.stringify(providerResult)
    const providerBytes = Buffer.from(providerJson, 'utf8')
    if (
      providerBytes.length < 2 ||
      providerBytes.length > MAX_POLL_RESPONSE_BYTES_FOR_VAULT ||
      providerBytes.toString('utf8') !== providerJson
    ) {
      throw new PaidMediaVaultError('Paid media terminal video result exceeds its size limit')
    }
    const flightKey = this.taskAliasDigest(taskAlias)
    const providerResultSha256 = sha256(providerBytes)
    const running = this.terminalArchiveFlights.get(flightKey)
    if (running) {
      if (running.providerResultSha256 !== providerResultSha256) {
        throw new PaidMediaVaultError('Paid media terminal video conflicts with its receipt')
      }
      return running.promise
    }
    const promise = this.archiveTerminalMediaForTaskOnce(
      taskAlias,
      providerResult,
      providerBytes
    )
    this.terminalArchiveFlights.set(flightKey, { providerResultSha256, promise })
    try {
      return await promise
    } finally {
      if (this.terminalArchiveFlights.get(flightKey)?.promise === promise) {
        this.terminalArchiveFlights.delete(flightKey)
      }
    }
  }

  private async archiveTerminalMediaForTaskOnce(
    taskAlias: string,
    providerResult: Record<string, unknown>,
    providerBytes: Buffer
  ): Promise<PaidMediaTerminalArchiveResult> {
    const index = this.readVideoTaskIndex(taskAlias)
    const creation = await this.verifyArchive(index.operationId)
    if (
      creation.receipt.kind !== 'video_task' ||
      creation.receipt.receiptSha256 !== index.creationReceiptSha256 ||
      creation.receipt.taskReceiptIdSha256 !== this.taskAliasDigest(taskAlias)
    ) {
      throw new PaidMediaVaultError('Paid media terminal video is not bound to its creation receipt')
    }
    const terminalPath = this.terminalFile(taskAlias)
    if (existsSync(terminalPath)) {
      const existing = await this.verifyTerminalMediaForTask(taskAlias)
      const document = this.parseTerminal(
        this.decodeEncrypted(
          this.readRegular(
            terminalPath,
            MAX_ENCRYPTED_DOCUMENT_BYTES,
            'Paid media terminal video receipt'
          ),
          'Paid media terminal video receipt'
        )
      )
      if (
        document.providerResultSha256 !== sha256(providerBytes) ||
        document.providerResultByteLength !== providerBytes.length
      ) {
        throw new PaidMediaVaultError('Paid media terminal video conflicts with its receipt')
      }
      return existing
    }
    const nested =
      providerResult.data &&
      typeof providerResult.data === 'object' &&
      !Array.isArray(providerResult.data)
        ? (providerResult.data as Record<string, unknown>)
        : null
    const rawStatus = providerResult.status || nested?.status
    const status = typeof rawStatus === 'string' ? rawStatus.trim().toLowerCase() : ''
    const failureTerminal = new Set([
      'failure',
      'failed',
      'error',
      'cancelled',
      'canceled'
    ]).has(status)
    const successTerminal = new Set([
      'complete',
      'completed',
      'done',
      'success',
      'succeeded'
    ]).has(status)
    // Explicit failure wins over any stale/preview URL in the provider body.
    // Store a no-asset terminal receipt so polling converges exactly once.
    const sourceUrl = failureTerminal ? null : this.terminalUrl(providerResult)
    if (sourceUrl === null && !failureTerminal) {
      throw new PaidMediaVaultError('Paid media video result is not a proven terminal receipt')
    }
    if (sourceUrl !== null && status && !successTerminal) {
      throw new PaidMediaVaultError('Paid media terminal video status conflicts with its URL')
    }
    let asset: PaidMediaArchivedAsset | null = null
    if (sourceUrl !== null) {
      let fetched: PaidMediaRemoteFetchResult
      try {
        fetched = await this.dependencies.fetchRemote(
          sourceUrl,
          MAX_PAID_MEDIA_TERMINAL_VIDEO_BYTES
        )
      } catch (error) {
        throw new PaidMediaVaultError('Paid media terminal video could not be fetched', {
          cause: error
        })
      }
      if (!fetched || typeof fetched !== 'object') {
        throw new PaidMediaVaultError('Paid media terminal video fetcher returned invalid bytes')
      }
      const cleanupMarker =
        'filePath' in fetched ? this.createCleanupMarker(index.operationId, fetched) : null
      try {
        validateHttpsAssetUrl(fetched.finalUrl)
        if ('bytes' in fetched && !Buffer.isBuffer(fetched.bytes)) {
          throw new PaidMediaVaultError('Paid media terminal video fetcher returned invalid bytes')
        }
        asset = 'bytes' in fetched
          ? await this.writeTerminalVideoAssetBuffer(fetched.bytes, {
              sourceSha256: sha256(sourceUrl),
              contentType: fetched.contentType
            })
          : await this.writeTerminalVideoAssetFile(fetched.filePath, {
              byteLength: fetched.byteLength,
              sourceSha256: sha256(sourceUrl),
              contentType: fetched.contentType
            })
      } finally {
        await this.cleanupFetched(fetched, cleanupMarker)
      }
    }
    const recoveryResult = this.terminalRecoveryResult(providerResult, asset)
    const recoveryJson = JSON.stringify(recoveryResult)
    const recoveryBytes = Buffer.from(recoveryJson, 'utf8')
    if (recoveryBytes.length < 2 || recoveryBytes.length > MAX_RECOVERY_JSON_BYTES) {
      throw new PaidMediaVaultError('Paid media terminal recovery manifest exceeds its size limit')
    }
    const base: TerminalBase = {
      schema: TERMINAL_SCHEMA,
      taskAliasSha256: this.taskAliasDigest(taskAlias),
      operationId: index.operationId,
      creationReceiptSha256: index.creationReceiptSha256,
      providerResultSha256: sha256(providerBytes),
      providerResultByteLength: providerBytes.length,
      recoverySha256: sha256(recoveryBytes),
      recoveryJsonUtf8Base64: recoveryBytes.toString('base64'),
      asset,
      archivedAt: requireNow(this.dependencies.now)
    }
    const document: TerminalDocument = {
      ...base,
      receiptSha256: sha256(JSON.stringify(base))
    }
    this.writeAtomicNew(
      terminalPath,
      this.encodeEncrypted(document),
      'Paid media terminal video receipt'
    )
    return this.verifyTerminalMediaForTask(taskAlias)
  }

  async verifyTerminalMediaForTask(taskAlias: string): Promise<PaidMediaTerminalArchiveResult> {
    const index = this.readVideoTaskIndex(taskAlias)
    const creation = await this.verifyArchive(index.operationId)
    if (creation.receipt.receiptSha256 !== index.creationReceiptSha256) {
      throw new PaidMediaVaultError('Paid media terminal video creation receipt does not match')
    }
    const path = this.terminalFile(taskAlias)
    if (!existsSync(path)) {
      throw new PaidMediaVaultError('Paid media terminal video receipt is missing')
    }
    const terminal = this.parseTerminal(
      this.decodeEncrypted(
        this.readRegular(
          path,
          MAX_ENCRYPTED_DOCUMENT_BYTES,
          'Paid media terminal video receipt'
        ),
        'Paid media terminal video receipt'
      )
    )
    if (
      terminal.taskAliasSha256 !== this.taskAliasDigest(taskAlias) ||
      terminal.operationId !== index.operationId ||
      terminal.creationReceiptSha256 !== index.creationReceiptSha256
    ) {
      throw new PaidMediaVaultError('Paid media terminal video binding does not match')
    }
    if (terminal.asset !== null) {
      const stored = await this.openAsset(terminal.asset.reference)
      try {
        if (
          stored.byteLength !== terminal.asset.byteLength ||
          stored.sha256 !== terminal.asset.sha256 ||
          stored.mediaType !== terminal.asset.mediaType
        ) {
          throw new PaidMediaVaultError('Paid media terminal video asset does not match its receipt')
        }
        this.requireTrustedAssetValidation(terminal.asset)
      } finally {
        await stored.handle.close().catch(() => undefined)
      }
    }
    const recoveryJson = decodeCanonicalBase64(
      terminal.recoveryJsonUtf8Base64,
      MAX_RECOVERY_JSON_BYTES,
      'Paid media terminal recovery manifest'
    ).toString('utf8')
    return {
      operationId: terminal.operationId,
      receiptSha256: terminal.receiptSha256,
      ...(terminal.asset === null ? {} : { asset: { ...terminal.asset } }),
      result: parseObject(recoveryJson, 'Paid media terminal recovery manifest'),
      cleanupComplete: !this.hasPendingCleanup(terminal.operationId)
    }
  }

  async recover(operationId: string): Promise<PaidMediaArchivedResult> {
    return this.verifyArchive(operationId)
  }

  async listRecoverableArchives(input: {
    cursor?: string
    limit?: number
  } = {}): Promise<PaidMediaArchiveDiscoveryPage> {
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
      throw new PaidMediaVaultError('Paid media archive discovery request is invalid')
    }
    const raw = input as Record<string, unknown>
    if (
      Object.keys(raw).some((key) => key !== 'cursor' && key !== 'limit') ||
      (raw.limit !== undefined &&
        (!Number.isSafeInteger(raw.limit) ||
          Number(raw.limit) < 1 ||
          Number(raw.limit) > MAX_ARCHIVE_DISCOVERY_PAGE))
    ) {
      throw new PaidMediaVaultError('Paid media archive discovery request is invalid')
    }
    const cursor = decodeArchiveCursor(raw.cursor)
    const limit = (raw.limit as number | undefined) ?? DEFAULT_ARCHIVE_DISCOVERY_PAGE
    this.prepare()
    const candidates = readdirSync(this.discoveriesPath, { withFileTypes: true })
      .flatMap((entry) => {
        if (!entry.isFile() || entry.isSymbolicLink()) return []
        const matched = /^(\d{16})_(desktop-op-[0-9a-f-]{36})\.json$/i.exec(entry.name)
        if (!matched) return []
        const archivedAt = Number(matched[1])
        const operationId = matched[2]
        if (
          !Number.isSafeInteger(archivedAt) ||
          archivedAt < 0 ||
          !existsSync(this.archiveFile(operationId))
        ) {
          return []
        }
        return [{ filename: entry.name, archivedAt, operationId }]
      })
    candidates.sort(
      (left, right) =>
        right.archivedAt - left.archivedAt ||
        left.operationId.localeCompare(right.operationId)
    )
    const afterCursor =
      cursor === null
        ? candidates
        : candidates.filter(
            (document) =>
              document.archivedAt < cursor.archivedAt ||
              (document.archivedAt === cursor.archivedAt &&
                document.operationId.localeCompare(cursor.operationId) > 0)
          )
    const selected = afterCursor.slice(0, limit)
    const documents = selected.map((candidate) => {
      const document = this.parseDiscovery(
        this.decodeEncrypted(
          this.readRegular(
            join(this.discoveriesPath, candidate.filename),
            MAX_ENCRYPTED_DOCUMENT_BYTES,
            'Paid media discovery index'
          ),
          'Paid media discovery index'
        )
      )
      if (
        document.operationId.toLowerCase() !== candidate.operationId.toLowerCase() ||
        document.archivedAt !== candidate.archivedAt
      ) {
        throw new PaidMediaVaultError('Paid media archive discovery filename does not match')
      }
      return document
    })
    const items = documents.map((document) => ({
      operationId: document.operationId,
      path: document.path,
      model: document.model,
      status: document.status,
      kind: document.kind,
      archivedAt: document.archivedAt,
      receiptSha256: document.receiptSha256,
      responseByteLength: document.responseByteLength,
      assets: document.assets.map((asset) => ({
        reference: asset.reference,
        mediaType: asset.mediaType,
        byteLength: asset.byteLength,
        sha256: asset.sha256
      }))
    }))
    const more = afterCursor.length > selected.length
    const last = selected[selected.length - 1]
    return {
      items,
      ...(more && last
        ? {
            nextCursor: encodeArchiveCursor({
              schema: 'nachuan.paid-media-vault.cursor.v1',
              archivedAt: last.archivedAt,
              operationId: last.operationId
            })
          }
        : {})
    }
  }

  hasArchive(operationId: string): boolean {
    this.prepare()
    return existsSync(this.archiveFile(operationId))
  }

  hasAssetAckCompletion(operationId: string): boolean {
    this.prepare()
    return existsSync(this.assetAckCompletionFile(operationId))
  }

  hasAssetCapacityReleaseAuthorization(operationId: string): boolean {
    this.prepare()
    return existsSync(this.assetCapacityReleaseFile(operationId))
  }

  private locateAsset(reference: string): {
    path: string
    digest: string
    extension: PaidMediaArchivedAsset['extension']
    mediaType: PaidMediaArchivedAsset['mediaType']
    maxBytes: number
  } {
    if (typeof reference !== 'string' || reference.length > 256) {
      throw new PaidMediaVaultError('Paid media archive asset reference is invalid')
    }
    let parsed: URL
    try {
      parsed = new URL(reference)
    } catch (error) {
      throw new PaidMediaVaultError('Paid media archive asset reference is invalid', {
        cause: error
      })
    }
    const digest = parsed.pathname.replace(/^\//, '')
    if (
      parsed.protocol !== 'nachuan-paid-media:' ||
      parsed.hostname !== 'sha256' ||
      !SHA256_PATTERN.test(digest) ||
      parsed.search ||
      parsed.hash ||
      parsed.username ||
      parsed.password ||
      parsed.port
    ) {
      throw new PaidMediaVaultError('Paid media archive asset reference is invalid')
    }
    this.prepare()
    const candidates = [
      ['png', 'image/png'],
      ['jpg', 'image/jpeg'],
      ['gif', 'image/gif'],
      ['webp', 'image/webp'],
      ['mp4', 'video/mp4'],
      ['webm', 'video/webm']
    ] as const
    const matches = candidates.filter(([extension]) =>
      existsSync(join(this.assetsPath, `${digest}.${extension}`))
    )
    if (matches.length !== 1) {
      throw new PaidMediaVaultError('Paid media archive asset is missing or ambiguous')
    }
    const [extension, mediaType] = matches[0]
    const video = mediaType === 'video/mp4' || mediaType === 'video/webm'
    return {
      path: join(this.assetsPath, `${digest}.${extension}`),
      digest,
      extension,
      mediaType,
      maxBytes: video
        ? MAX_PAID_MEDIA_TERMINAL_VIDEO_BYTES
        : MAX_PAID_MEDIA_ARCHIVE_ASSET_BYTES
    }
  }

  private verifiedAssetIdentity(info: Stats): VerifiedAssetIdentity {
    return {
      ...this.pathIdentity(info, false),
      size: info.size,
      mtimeMs: info.mtimeMs,
      ctimeMs: info.ctimeMs
    }
  }

  private sameVerifiedAssetIdentity(
    left: VerifiedAssetIdentity | undefined,
    right: VerifiedAssetIdentity
  ): boolean {
    return (
      this.samePathIdentity(left, right) &&
      left?.size === right.size &&
      left.mtimeMs === right.mtimeMs &&
      left.ctimeMs === right.ctimeMs
    )
  }

  async openAsset(reference: string): Promise<PaidMediaOpenAsset> {
    const located = this.locateAsset(reference)
    const registered = this.registeredAuthorityEntry(located.path)
    const before = this.hardenIfChanged(located.path, false)
    if (before.size < 1 || before.size > located.maxBytes) {
      throw new PaidMediaVaultError('Paid media archive asset exceeds its size limit')
    }
    const identity = this.verifiedAssetIdentity(before)
    if (
      registered &&
      (registered.byteLength !== before.size || registered.sha256 !== located.digest)
    ) {
      throw new PaidMediaVaultError('Paid media archive asset does not match its authority entry')
    }
    const cached = this.verifiedAssets.get(resolve(located.path))
    this.dependencies.beforeAssetPin?.(located.path)
    const handle = await openFile(located.path, 'r')
    try {
      const pinned = await handle.stat()
      const pinnedIdentity = this.verifiedAssetIdentity(pinned)
      if (!pinned.isFile() || !this.sameVerifiedAssetIdentity(identity, pinnedIdentity)) {
        throw new PaidMediaVaultError('Paid media archive asset changed before it was pinned')
      }
      if (
        cached?.sha256 === located.digest &&
        cached.mediaType === located.mediaType &&
        this.sameVerifiedAssetIdentity(cached, pinnedIdentity)
      ) {
        return {
          handle,
          byteLength: pinned.size,
          mediaType: located.mediaType,
          sha256: located.digest
        }
      }
      if (cached) this.verifiedAssets.delete(resolve(located.path))

      let digest: string
      if (located.extension === 'mp4' || located.extension === 'webm') {
        await validateStoredVideoFile(handle, pinned.size, located.extension)
        const hash = createHash('sha256')
        let bytesRead = 0
        for await (const value of handle.createReadStream({
          start: 0,
          end: pinned.size - 1,
          autoClose: false,
          highWaterMark: 1024 * 1024
        })) {
          const chunk = Buffer.isBuffer(value) ? value : Buffer.from(value)
          bytesRead += chunk.length
          if (bytesRead > located.maxBytes) {
            throw new PaidMediaVaultError('Paid media archive asset exceeds its size limit')
          }
          hash.update(chunk)
        }
        if (bytesRead !== pinned.size) {
          throw new PaidMediaVaultError('Paid media archive asset changed while hashing')
        }
        digest = hash.digest('hex')
      } else {
        const mediaType = requireImageType(located.mediaType)
        const image = new BoundedImageStreamVerifier(mediaType, pinned.size)
        const hash = createHash('sha256')
        let byteLength = 0
        for await (const value of handle.createReadStream({
          start: 0,
          end: pinned.size - 1,
          autoClose: false,
          highWaterMark: PAID_MEDIA_STAGE_STREAM_CHUNK_BYTES
        })) {
          const chunk = Buffer.isBuffer(value) ? value : Buffer.from(value)
          byteLength += chunk.length
          if (byteLength > located.maxBytes) {
            throw new PaidMediaVaultError('Paid media archive asset exceeds its size limit')
          }
          hash.update(chunk)
          image.update(chunk)
        }
        if (byteLength !== pinned.size) {
          throw new PaidMediaVaultError('Paid media archive asset changed while reading')
        }
        image.finish()
        if (imageExtension(mediaType) !== located.extension) {
          throw new PaidMediaVaultError('Paid media archive asset magic does not match')
        }
        digest = hash.digest('hex')
      }
      const after = await handle.stat()
      const afterIdentity = this.verifiedAssetIdentity(after)
      if (!this.sameVerifiedAssetIdentity(pinnedIdentity, afterIdentity)) {
        throw new PaidMediaVaultError('Paid media archive asset changed during verification')
      }
      if (digest !== located.digest) {
        throw new PaidMediaVaultError('Paid media archive asset digest does not match')
      }
      this.verifiedAssets.set(resolve(located.path), {
        ...afterIdentity,
        sha256: located.digest,
        mediaType: located.mediaType
      })
      return {
        handle,
        byteLength: after.size,
        mediaType: located.mediaType,
        sha256: located.digest
      }
    } catch (error) {
      this.verifiedAssets.delete(resolve(located.path))
      await handle.close().catch(() => undefined)
      throw error
    }
  }

  async readAsset(reference: string): Promise<{
    bytes: Buffer
    mediaType: PaidMediaArchivedAsset['mediaType']
  }> {
    const located = this.locateAsset(reference)
    const video = located.mediaType === 'video/mp4' || located.mediaType === 'video/webm'
    const bytes = this.readRegular(
      located.path,
      located.maxBytes,
      'Paid media archive asset'
    )
    if (sha256(bytes) !== located.digest) {
      throw new PaidMediaVaultError('Paid media archive asset digest does not match')
    }
    const detected = video ? detectVideo(bytes) : detectImage(bytes)
    if (
      detected.extension !== located.extension ||
      detected.mediaType !== located.mediaType
    ) {
      throw new PaidMediaVaultError('Paid media archive asset magic does not match')
    }
    return { bytes, mediaType: located.mediaType }
  }
}
