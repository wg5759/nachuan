/// <reference types="vite/client" />

import type { RuntimeCapabilityManifest } from '../../runtime-capabilities'

export interface RendererEngineRequest {
  requestId: string
  method: 'GET' | 'POST'
  target: string
  bodyKind: 'none' | 'json'
  body?: string
  responseKind: 'json' | 'binary' | 'stream'
}

export interface RendererEngineResponse {
  status: number
  contentType: string
  body: Uint8Array
}

export interface RendererEngineUploadRequest {
  requestId: string
  method: 'POST'
  target: string
  bodyKind: 'binary'
  bodyLength: number
  responseKind: 'json'
}

export type RendererEngineStreamEvent =
  | { kind: 'start'; status: number; contentType: string }
  | { kind: 'chunk'; chunk: Uint8Array }

export interface RendererEngineStreamResult {
  status: number
  contentType: string
  bytes: number
}

export type PaidMediaPath = '/v1/images/generations' | '/v1/videos/generations'
export type PaidMediaOperationState =
  | 'claimed'
  | 'dispatching'
  | 'recoverable'
  | 'result_ready'

export interface PaidMediaPublicOperation {
  operationId: string
  path: PaidMediaPath
  state: PaidMediaOperationState
  createdAt: number
  updatedAt: number
  dispatchCount: number
  lastStatus?: number
  retryAfterSeconds?: number
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

export interface LegacyPaidMediaImport {
  operationId: string
  path: PaidMediaPath
  requestSha256: string
  createdAt: number
  updatedAt: number
  state: 'pending' | 'recoverable'
  lastStatus?: number
  retryAfterSeconds?: number
}

export interface ApprovalIpcRecord {
  id: number
  kind: 'action' | 'skill_card'
  summary: string
  payload: Record<string, unknown>
  status: string
  created_at?: number
}

export interface DesktopUpdateState {
  phase: 'disabled' | 'idle' | 'checking' | 'downloading' | 'ready' | 'installing' | 'blocked'
  version?: string
  reason?: 'not-configured' | 'up-to-date' | 'network' | 'security' | 'failed'
}

export type ChannelRecoveryChannel = 'weixin' | 'feishu'

export interface ChannelRecoveryTarget {
  channel: ChannelRecoveryChannel
  targetKind: 'inbound' | 'delivery' | 'video' | 'inbox' | 'outbox'
  targetKey: string
}

export interface ChannelRecoverySnapshot {
  schema: 'nachuan.weixin-recovery-snapshot.v1' | 'nachuan.feishu-recovery-inspect.v1'
  targetKind: ChannelRecoveryTarget['targetKind']
  targetKeySha256: string
  expectedBeforeDigest: string
  affectedCounts: Record<string, number>
  decisionId: string
  decidedAtMs: number
}

export interface ChannelRecoveryCloseInput extends ChannelRecoveryTarget {
  targetKeySha256: string
  expectedBeforeDigest: string
  decisionId: string
  decidedAtMs: number
  reason: string
  userConfirmed: true
  confirmFinal: true
}

export interface ChannelRecoveryResult {
  schema: 'nachuan.channel-recovery-result.v1'
  operationDigest: string
  receiptSha256: string
  affectedCounts: Record<string, number>
  applied: boolean
}

/** Minimal connection-model wire payload accepted by the gateway. */
export interface ConnectionModelPayload {
  id: string
  upstream_model?: string
  tier?: string
  description?: string
  modality?: string
  rank?: number
  flagship?: boolean
  tool_capable?: boolean
  skills?: string[]
}

/** Fully projected catalog model used by the graphical Connection Center. */
export interface CatalogModel extends ConnectionModelPayload {
  upstream_model: string
  tier: string
  description: string
}

export interface DesktopAPI {
  /** Renderer target identity. UI capability decisions must not guess from User-Agent. */
  runtimeKind: 'electron' | 'web'
  /** Static surface declaration only; callers must still perform runtime health checks. */
  runtimeCapabilities: RuntimeCapabilityManifest
  engineRequest: (input: RendererEngineRequest) => Promise<RendererEngineResponse>
  engineStream: (
    input: RendererEngineRequest,
    onEvent: (event: RendererEngineStreamEvent) => void | Promise<void>
  ) => Promise<RendererEngineStreamResult>
  engineUpload: (
    input: RendererEngineUploadRequest,
    readChunk: (offset: number, maximumBytes: number) => Uint8Array | Promise<Uint8Array>
  ) => Promise<RendererEngineResponse>
  cancelEngineRequest: (requestId: string) => void
  claimPaidMedia: (input: {
    path: PaidMediaPath
    encodedBody: string
    retryOperationId?: string
  }) => Promise<PaidMediaPublicOperation>
  executePaidMedia: (input: {
    operationId: string
    path: PaidMediaPath
    encodedBody: string
  }) => Promise<PaidMediaExecutionResult>
  pollPaidVideo: (input: { taskAlias: string; model: string }) => Promise<Record<string, unknown>>
  recoverPaidMediaArchive: (operationId: string) => Promise<
    Record<string, unknown> & { deliveryProof: PaidMediaDeliveryProof }
  >
  listPaidMediaArchives: (input?: { cursor?: string; limit?: number }) => Promise<{
    items: Record<string, unknown>[]
    nextCursor?: string
  }>
  cancelPaidMedia: (operationId: string) => void
  listPaidMediaOperations: () => Promise<PaidMediaPublicOperation[]>
  acknowledgePaidMedia: (deliveryProof: PaidMediaDeliveryProof) => Promise<unknown>
  abandonPaidMediaClaim: (operationId: string, evidence: string) => Promise<unknown>
  reconcilePaidMedia: (input: {
    operationId: string
    reason: string
    evidence: string
  }) => Promise<unknown>
  importLegacyPaidMediaJournal: (
    input: LegacyPaidMediaImport | null | { kind: 'migrated' }
  ) => Promise<unknown>
  /** Web-only transient materializer; Electron resolves the durable scheme natively. */
  resolvePaidMediaAsset?: (reference: string) => Promise<string>
  /** Release one renderer ownership of a Web-only object URL. */
  releasePaidMediaAsset?: (reference: string) => void
  listApprovals: (userId: string) => Promise<{ pending: ApprovalIpcRecord[] }>
  resolveApproval: (payload: {
    id: number
    decision: 'approve' | 'reject' | 'revise'
    note?: string
  }) => Promise<{ status: string; case_id?: number }>
  saveConnection: (payload: {
    provider: string
    type: string
    api_key: string
    base_url: string
    enabled_models: ConnectionModelPayload[]
    preserve_existing_credential: boolean
  }) => Promise<{
    ok: boolean
    models: string[]
    rejected_models?: string[]
    state?: string
    error?: string
    reason_code?: 'reauth_required' | 'text_contract_rejected' | 'connector_unavailable'
  }>
  deleteConnection: (provider: string) => Promise<{ ok: boolean }>
  configureSync: (url: string, anonKey: string) => Promise<unknown>
  authenticateSync: (
    kind: 'login' | 'signup',
    email: string,
    password: string
  ) => Promise<unknown>
  toggleSync: (enabled: boolean) => Promise<unknown>
  runSync: () => Promise<unknown>
  inspectChannelRecovery: (input: ChannelRecoveryTarget) => Promise<ChannelRecoverySnapshot>
  closeChannelRecovery: (input: ChannelRecoveryCloseInput) => Promise<ChannelRecoveryResult>
  getUpdateState: () => Promise<DesktopUpdateState>
  checkForUpdates: () => Promise<DesktopUpdateState>
  installVerifiedUpdate: () => Promise<{ ok: boolean }>
  onUpdateState: (cb: (state: DesktopUpdateState) => void) => () => void
  onSetView: (cb: (key: string) => void) => () => void
  onAppCommand: (cb: (command: string) => void) => () => void
  setLang: (lang: string) => void
  snipBg: () => Promise<{ dataUrl: string; width: number; height: number } | null>
  startSnip: () => Promise<{ ok: boolean }>
  pickDirectory: () => Promise<string>
  saveMedia: (p: {
    filename: string
    bytes?: ArrayBuffer
    url?: string
  }) => Promise<{ ok: boolean; path?: string; error?: string }>
  snipReady: () => void
  snipDone: (payload: { dataUrl: string; action: string }) => void
  snipCancel: () => void
  onSnipResult: (cb: (dataUrl: string, action: string) => void) => () => void
}

declare global {
  interface Window {
    api: DesktopAPI
  }
}
