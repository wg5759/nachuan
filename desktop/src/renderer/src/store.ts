import { create } from 'zustand'
import { persist } from 'zustand/middleware'

import {
  createConversation as apiCreateConversation,
  deleteConversation as apiDeleteConversation,
  getOfflineMode as apiGetOfflineMode,
  importConversations as apiImportConversations,
  listConversationsResult as apiListConversationsResult,
  patchConversation as apiPatchConversation,
  saveConversationMessages as apiSaveConversationMessages,
  setOfflineMode as apiSetOfflineMode,
  type EngineFeatures,
  type PatchConversationPayload
} from './api'
import type { PaidMediaDeliveryProof } from './paid-media-journal'

export type EngineStatus = 'starting' | 'online' | 'degraded' | 'offline'

export interface ModelInfo {
  id: string
  owned_by?: string
  /** 服务端 Router 声明的原生执行后端；未声明时走 function-calling agent。 */
  exec_backend?: 'codex' | 'claude'
  tier?: string
  modality?: string
  description?: string
  chat_usable?: boolean
  review_vote_candidate?: boolean
  review_strength?: 'strong' | 'weak' | null
  tool_capable?: boolean
  skills?: string[]
}

/** 原生 CLI 执行路由只信服务端元数据，禁止从模型 ID/厂商显示名猜测。 */
export const nativeExecBackendForModel = (
  models: ModelInfo[],
  modelId: string | null
): 'codex' | undefined => {
  const backend = models.find((model) => model.id === modelId)?.exec_backend
  return backend === 'codex' ? backend : undefined
}

export interface TokenUsage {
  prompt_tokens?: number
  completion_tokens?: number
  total_tokens?: number
  cached_tokens?: number
  cost_usd?: number
}

export type ViewKey =
  | 'chat'
  | 'coding'
  | 'coding-studio'
  | 'connections'
  | 'orchestrate'
  | 'usage'
  | 'brain'
  | 'media'
  | 'mcp'
  | 'kb'
  | 'studio'
  | 'sync'
  | 'settings'
  | 'about'

// 右栏浏览器缩放档：normal=三栏 / wide=收起左栏给浏览器腾地 / max=收左+中栏，浏览器铺满
export type BrowserZoom = 'normal' | 'wide' | 'max'

// 一条聊天显示消息。全文消息现统一落盘至服务端 SQLite（/v1/conversations），
// 不再写入 localStorage；blob: 为会话级临时 URL，视频仍保留原始源 videoSrc 供重启后恢复。
export interface ChatDisplayMsg {
  role: 'user' | 'assistant'
  content: string
  ts?: number // 发送时间戳（悬停操作栏里显示）
  startedAt?: number
  completedAt?: number
  workLog?: string[]
  reasoning?: string
  images?: string[]
  video?: string
  videoSrc?: string // 视频原始 http 源（可持久化）；重启后据此再代下成 blob 播放
  videoTask?: { task_id: string; model: string; prompt?: string } // 进行中的生视频任务：重启自动续传；prompt 供"插队补充"时注入上下文
  meta?: string
  model?: string
  usage?: TokenUsage
  translated?: string
  // 文档附件：超长文/文本文件转成的「文档卡」（不在气泡里铺一墙字，喂模型时再展开为上下文）
  docs?: { name: string; chars: number; content: string }[]
  // 内联动作卡：只有服务端签发一次性 receipt 的改动才可撤销。
  actions?: { path: string; before: string; after: string; undo_receipt?: string }[]
  // 付费媒体恢复只保留随机操作身份和重建请求所需的小字段。图片正文/密钥不复制到这里；
  // 视频引用沿用紧邻用户消息的 images，重试时还要过 journal 的请求摘要校验。
  paidMediaOperation?: {
    operationId: string
    kind: 'image' | 'video'
    model: string
    blocked?: boolean
    phase?: 'awaiting_result' | 'awaiting_ack'
    deliveryProof?: PaidMediaDeliveryProof
  }
}

export type ConversationKind = 'chat' | 'code' | 'browser'

export interface Conversation {
  id: string
  title: string
  kind: ConversationKind
  messages: ChatDisplayMsg[]
  createdAt: number
  updatedAt: number
  /** 目标工作目录：**每个对话独立**（机主实测：以前全局残留到新对话）。 */
  workdir?: string
  /** 归档：从主列表隐藏，不删数据。 */
  archived?: boolean
  /** 无痕会话标记：为 true 时绝不落盘到服务端 `/v1/conversations`。 */
  incognito?: boolean
  /** 输入框草稿（未发送的文字/文档/图片）——仅保留在内存会话中，不进 localStorage。 */
  draft?: {
    text?: string
    docs?: { name: string; content: string }[]
    images?: { name: string; dataUrl: string }[]
  }
}

/**
 * 极轻量付费媒体恢复锚点（仅保存操作身份、vault 内容寻址 URI 与任务 ID，
 * 绝不含聊天正文、用户提示词或 base64 图片；无待核销付费媒体时为空数组）。
 */
export interface PaidMediaAnchorRecord {
  conversationId: string
  messageTs: number
  operationId: string
  kind: 'image' | 'video'
  model: string
  blocked?: boolean
  phase?: 'awaiting_result' | 'awaiting_ack'
  deliveryProof?: PaidMediaDeliveryProof
  images?: string[]
  videoTask?: { task_id: string; model: string; prompt?: string }
}

const STORAGE_KEY = 'agg-conversations'
const DURABLE_MEDIA_PATTERN = /^(https?:|file:|sandbox:|studio:|nachuan-paid-media:)/
const VAULT_IMAGE_PATTERN = /^nachuan-paid-media:\/\/sha256\/[0-9a-f]{64}$/

const newId = (): string => Date.now().toString(36) + Math.random().toString(36).slice(2, 6)
const blankConv = (kind: ConversationKind = 'chat', incognito = false): Conversation => ({
  id: newId(),
  title: '新对话',
  kind,
  messages: [],
  createdAt: Date.now(),
  updatedAt: Date.now(),
  ...(incognito ? { incognito: true } : {})
})
const deriveTitle = (msgs: ChatDisplayMsg[]): string => {
  const first = msgs.find((m) => m.role === 'user' && m.content.trim())
  return first ? first.content.trim().slice(0, 18) : '新对话'
}

/** A renderer preference is active only after it matches the live model list exactly. */
export const validatedModelSelection = (
  models: ModelInfo[],
  candidate: string | null
): string | null =>
  candidate !== null && models.some((model) => model.id === candidate) ? candidate : null

export const preferredChatModel = (models: ModelInfo[], current: string | null): string | null => {
  const exists = (id: string | null): boolean => validatedModelSelection(models, id) !== null
  // #12：把舰队号「纳川·智脑」(nachuan) 扶正为默认大脑——它内部「先快后升」（简单问题便宜模型秒答、
  // 复杂才升编排），当默认不再等于每句话都烧配额，于是可以推翻批5「舰队只当招牌、不做自动默认」的旧约束
  //（那条约束定于先快后升之前）。已有主动选择优先保留；无舰队（空版）再退回强模型逻辑。
  const fleet = models.find((m) => m.id === 'nachuan')?.id
  const pickable = models.filter((m) => m.owned_by !== 'fleet')
  const premium = pickable.find((m) => m.modality !== 'image' && m.modality !== 'video' && m.tier === 'premium')?.id
  // 保留用户主动选择；但弱模型 agnes-flash 只是老的兜底默认 → 有更好大脑（舰队/强模型）时升上去。
  if (exists(current) && !(current === 'agnes-flash' && (fleet || premium))) return current
  return (
    fleet ??
    premium ??
    pickable.find((m) => m.id !== 'echo' && m.modality !== 'image' && m.modality !== 'video')?.id ??
    pickable.find((m) => m.id !== 'echo')?.id ??
    pickable[0]?.id ??
    models[0]?.id ??
    null
  )
}

function sanitizeMessageForServer(m: ChatDisplayMsg): ChatDisplayMsg {
  const keptImages = m.images?.filter(
    (u) => DURABLE_MEDIA_PATTERN.test(u) || u.startsWith('data:image/')
  )
  return {
    role: m.role,
    content: m.content,
    ...(m.ts !== undefined ? { ts: m.ts } : {}),
    ...(m.startedAt !== undefined ? { startedAt: m.startedAt } : {}),
    ...(m.completedAt !== undefined ? { completedAt: m.completedAt } : {}),
    ...(m.workLog?.length ? { workLog: m.workLog } : {}),
    ...(m.meta !== undefined ? { meta: m.meta } : {}),
    ...(m.model !== undefined ? { model: m.model } : {}),
    ...(m.usage !== undefined ? { usage: m.usage } : {}),
    ...(m.reasoning !== undefined ? { reasoning: m.reasoning } : {}),
    ...(m.translated !== undefined ? { translated: m.translated } : {}),
    ...(m.docs?.length ? { docs: m.docs } : {}),
    ...(keptImages?.length ? { images: keptImages } : {}),
    ...(m.video && DURABLE_MEDIA_PATTERN.test(m.video) ? { video: m.video } : {}),
    ...(m.videoSrc !== undefined ? { videoSrc: m.videoSrc } : {}),
    ...(m.videoTask !== undefined ? { videoTask: m.videoTask } : {}),
    ...(m.paidMediaOperation !== undefined ? { paidMediaOperation: m.paidMediaOperation } : {})
  }
}

function extractPaidMediaAnchors(conversations: Conversation[]): PaidMediaAnchorRecord[] {
  const anchors: PaidMediaAnchorRecord[] = []
  for (const conv of conversations) {
    for (const msg of conv.messages) {
      if (msg.role !== 'assistant' || !msg.paidMediaOperation || typeof msg.ts !== 'number') {
        continue
      }
      const vaultImages = (msg.images ?? []).filter((url) => VAULT_IMAGE_PATTERN.test(url))
      anchors.push({
        conversationId: conv.id,
        messageTs: msg.ts,
        operationId: msg.paidMediaOperation.operationId,
        kind: msg.paidMediaOperation.kind,
        model: msg.paidMediaOperation.model,
        ...(msg.paidMediaOperation.blocked !== undefined
          ? { blocked: msg.paidMediaOperation.blocked }
          : {}),
        ...(msg.paidMediaOperation.phase !== undefined
          ? { phase: msg.paidMediaOperation.phase }
          : {}),
        ...(msg.paidMediaOperation.deliveryProof !== undefined
          ? { deliveryProof: msg.paidMediaOperation.deliveryProof }
          : {}),
        ...(vaultImages.length ? { images: vaultImages } : {}),
        ...(msg.videoTask ? { videoTask: msg.videoTask } : {})
      })
    }
  }
  return anchors
}

// ── 服务端会话异步防抖同步器（无痕会话绝不落盘）──────────────────────────────
const _createdOnServer = new Set<string>()
const _msgSyncTimers = new Map<string, ReturnType<typeof setTimeout>>()
const _patchSyncTimers = new Map<string, ReturnType<typeof setTimeout>>()
const _pendingPatchByConv = new Map<string, PatchConversationPayload>()
let _pendingLegacyConversations: Conversation[] | null = null

function cancelServerSyncFor(convId: string): void {
  const mt = _msgSyncTimers.get(convId)
  if (mt) {
    clearTimeout(mt)
    _msgSyncTimers.delete(convId)
  }
  const pt = _patchSyncTimers.get(convId)
  if (pt) {
    clearTimeout(pt)
    _patchSyncTimers.delete(convId)
  }
  _pendingPatchByConv.delete(convId)
}

async function pushConversationMessagesNow(convId: string): Promise<void> {
  const conv = useAppStore.getState().conversations.find((c) => c.id === convId)
  if (!conv || conv.incognito) return
  const messages = conv.messages.map(sanitizeMessageForServer)
  if (!_createdOnServer.has(convId)) {
    const created = await apiCreateConversation({
      id: conv.id,
      title: conv.title,
      kind: conv.kind,
      workdir: conv.workdir ?? '',
      archived: Boolean(conv.archived),
      messages
    })
    if (created) {
      _createdOnServer.add(convId)
      return
    }
  }
  const saved = await apiSaveConversationMessages(convId, messages)
  if (!saved.ok) {
    const recreated = await apiCreateConversation({
      id: conv.id,
      title: conv.title,
      kind: conv.kind,
      workdir: conv.workdir ?? '',
      archived: Boolean(conv.archived),
      messages
    })
    if (recreated) _createdOnServer.add(convId)
  }
}

function scheduleServerMessagesSync(convId: string, delayMs = 600): void {
  const conv = useAppStore.getState().conversations.find((c) => c.id === convId)
  if (!conv || conv.incognito) return
  const existing = _msgSyncTimers.get(convId)
  if (existing) clearTimeout(existing)
  if (delayMs <= 0) {
    _msgSyncTimers.delete(convId)
    void pushConversationMessagesNow(convId)
    return
  }
  const timer = setTimeout(() => {
    _msgSyncTimers.delete(convId)
    void pushConversationMessagesNow(convId)
  }, delayMs)
  _msgSyncTimers.set(convId, timer)
}

function scheduleServerPatchSync(
  convId: string,
  patch: PatchConversationPayload,
  delayMs = 400
): void {
  const conv = useAppStore.getState().conversations.find((c) => c.id === convId)
  if (!conv || conv.incognito) return
  const merged = { ...(_pendingPatchByConv.get(convId) ?? {}), ...patch }
  _pendingPatchByConv.set(convId, merged)
  const existing = _patchSyncTimers.get(convId)
  if (existing) clearTimeout(existing)
  const run = (): void => {
    _patchSyncTimers.delete(convId)
    const nextPatch = _pendingPatchByConv.get(convId)
    _pendingPatchByConv.delete(convId)
    if (!nextPatch) return
    const latest = useAppStore.getState().conversations.find((c) => c.id === convId)
    if (!latest || latest.incognito) return
    void apiPatchConversation(convId, nextPatch)
  }
  if (delayMs <= 0) {
    run()
    return
  }
  _patchSyncTimers.set(convId, setTimeout(run, delayMs))
}

function flushServerSyncQueues(): void {
  for (const [convId, timer] of [..._msgSyncTimers.entries()]) {
    clearTimeout(timer)
    _msgSyncTimers.delete(convId)
    void pushConversationMessagesNow(convId)
  }
  for (const [convId, timer] of [..._patchSyncTimers.entries()]) {
    clearTimeout(timer)
    _patchSyncTimers.delete(convId)
    const patch = _pendingPatchByConv.get(convId)
    _pendingPatchByConv.delete(convId)
    const latest = useAppStore.getState().conversations.find((c) => c.id === convId)
    if (patch && latest && !latest.incognito) {
      void apiPatchConversation(convId, patch)
    }
  }
}

type MsgUpdater = ChatDisplayMsg[] | ((prev: ChatDisplayMsg[]) => ChatDisplayMsg[])

interface AppState {
  status: EngineStatus
  engineFeatures: EngineFeatures
  models: ModelInfo[]
  currentModel: string | null
  /** Persisted preference held inert until a fresh `/v1/models` allowlist arrives. */
  restoredModelPreference: string | null
  /** 重启后恢复的轻量付费媒体操作锚点（绝不含聊天正文）。 */
  restoredPaidMediaAnchors: PaidMediaAnchorRecord[]
  conversationsHydrated: boolean
  view: ViewKey
  setStatus: (s: EngineStatus) => void
  setEngineFeatures: (features: EngineFeatures) => void
  setModels: (m: ModelInfo[]) => void
  setCurrentModel: (id: string | null) => void
  setView: (v: ViewKey) => void
  // 浏览器↔聊天桥接：右栏浏览器底部输入框驱动同一个执行 agent；并把状态/回复回传给浏览器栏显示
  browserInput: { text: string; ts: number } | null
  agentBusy: boolean
  lastAgentReply: string
  browserZoom: BrowserZoom
  submitBrowserInput: (text: string) => void
  clearBrowserInput: () => void
  setAgentBusy: (b: boolean) => void
  setLastAgentReply: (s: string) => void
  setBrowserZoom: (z: BrowserZoom) => void
  cycleBrowserZoom: () => void
  /** 任务/对话生成完成时的提示音开关（默认开，可在设置菜单关）。 */
  soundEnabled: boolean
  setSoundEnabled: (v: boolean) => void
  /** P2 纯离线（空气间隙）模式运行态，以服务端 /v1/privacy/offline-mode 为单一真相源（不落盘 localStorage）。 */
  offlineMode: boolean
  setOfflineModeState: (enabled: boolean) => void
  refreshOfflineMode: () => Promise<boolean>
  toggleOfflineMode: (enabled: boolean) => Promise<{ ok: boolean; enabled: boolean }>
  // 右栏浏览器默认关闭；可手动开/关，agent 用到浏览器工具时自动开
  browserOpen: boolean
  openBrowser: () => void
  closeBrowser: () => void
  toggleBrowser: () => void
  // 浏览器里干完的活，给中间当前对话留一条摘要（中间 agent 据此"知道"发生了什么）
  appendBrowserNote: (text: string) => void
  // 多对话（会话列表——服务端 /v1/conversations 单一真相源 + 内存响应式副本）
  conversations: Conversation[]
  currentConvId: string | null
  hydrateConversationsFromServer: () => Promise<void>
  ensureConversation: () => void
  newConversation: (kind?: ConversationKind, opts?: { incognito?: boolean }) => string
  switchConversation: (id: string) => void
  renameConversation: (id: string, title: string) => void
  deleteConversation: (id: string) => void
  archiveConversation: (id: string, archived?: boolean) => void
  setConvWorkdir: (id: string, workdir: string) => void
  setConvIncognito: (id: string, incognito: boolean) => void
  setConvDraft: (id: string, draft: Conversation['draft']) => void
  setCurrentMessages: (updater: MsgUpdater) => void
  /** 往**指定对话**写消息（异步回写用：任务跑着时用户切了对话，结果必须写回发起时的对话，
   *  绝不能跟着 currentConvId 走串——codex 审出的跨对话写串洞）。 */
  setConvMessages: (convId: string, updater: MsgUpdater) => void
}

function readLegacyConversationsFromStorage(): Conversation[] {
  if (typeof localStorage === 'undefined') return []
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return []
    const parsed = JSON.parse(raw) as { state?: { conversations?: unknown } }
    const list = parsed?.state?.conversations
    if (!Array.isArray(list) || list.length === 0) return []
    return list.filter(
      (item): item is Conversation =>
        Boolean(item) &&
        typeof item === 'object' &&
        !Array.isArray(item) &&
        typeof (item as Conversation).id === 'string' &&
        Array.isArray((item as Conversation).messages)
    )
  } catch {
    return []
  }
}

function writeSlimLocalPreferences(state: AppState): boolean {
  if (typeof localStorage === 'undefined') return true
  const paidMediaAnchors = extractPaidMediaAnchors(state.conversations)
  const payload = {
    state: {
      currentModel: state.currentModel ?? state.restoredModelPreference,
      currentConvId: state.currentConvId,
      soundEnabled: state.soundEnabled,
      ...(paidMediaAnchors.length ? { paidMediaAnchors } : {})
    },
    version: 0
  }
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(payload))
    return true
  } catch (e) {
    console.warn('[persist] 轻量偏好写入失败', e)
    return false
  }
}

function mergePersistedAppState(persisted: unknown, current: AppState): AppState {
  if (!persisted || typeof persisted !== 'object' || Array.isArray(persisted)) return current
  const record = persisted as Record<string, unknown>
  const candidate =
    typeof record.currentModel === 'string' &&
    record.currentModel.length > 0 &&
    record.currentModel.length <= 256
      ? record.currentModel
      : null

  // 兼容旧版本 localStorage 中残存的历史 conversations：先暂存进内存待迁移至服务端，
  // 绝不再写回 localStorage。
  const legacyConversations = Array.isArray(record.conversations)
    ? (record.conversations as Conversation[]).filter(
        (c) => Boolean(c) && typeof c.id === 'string' && Array.isArray(c.messages)
      )
    : []
  if (legacyConversations.length > 0) {
    _pendingLegacyConversations = legacyConversations
  }

  const restoredPaidMediaAnchors = Array.isArray(record.paidMediaAnchors)
    ? (record.paidMediaAnchors as PaidMediaAnchorRecord[]).filter(
        (a) =>
          Boolean(a) &&
          typeof a.conversationId === 'string' &&
          typeof a.operationId === 'string' &&
          typeof a.messageTs === 'number'
      )
    : []

  return {
    ...current,
    currentConvId:
      typeof record.currentConvId === 'string' || record.currentConvId === null
        ? record.currentConvId
        : current.currentConvId,
    soundEnabled:
      typeof record.soundEnabled === 'boolean' ? record.soundEnabled : current.soundEnabled,
    conversations:
      legacyConversations.length > 0 ? legacyConversations : current.conversations,
    restoredPaidMediaAnchors,
    models: [],
    currentModel: null,
    restoredModelPreference: candidate
  }
}

// 轻量 UI 偏好防抖持久化：不再包含任何 conversations 聊天全文，单次写入 < 2KB。
type _SV = { state: unknown; version?: number }
let _flushPersistStorage = (): boolean => true
const _persistStorage = ((): {
  getItem: (n: string) => _SV | null
  setItem: (n: string, v: _SV) => void
  removeItem: (n: string) => void
} => {
  let timer: ReturnType<typeof setTimeout> | null = null
  let pending: [string, _SV] | null = null
  const flush = (): boolean => {
    if (timer) {
      clearTimeout(timer)
      timer = null
    }
    if (!pending) return true
    const current = pending
    const [n, v] = current
    try {
      localStorage.setItem(n, JSON.stringify(v))
      if (pending === current) pending = null
      return true
    } catch (e) {
      console.warn('[persist] 写入失败(多半超 localStorage 配额)，本次不持久化', e)
      return false
    }
  }
  _flushPersistStorage = flush
  if (typeof window !== 'undefined') {
    const onUnload = (): void => {
      flush()
      flushServerSyncQueues()
    }
    window.addEventListener('beforeunload', onUnload)
    window.addEventListener('pagehide', onUnload)
  }
  return {
    getItem: (n) => {
      const s = localStorage.getItem(n)
      try {
        return s ? (JSON.parse(s) as _SV) : null
      } catch {
        try {
          if (s) localStorage.setItem(n + '.bak', s)
        } catch {
          /* ignore */
        }
        return null
      }
    },
    setItem: (n, v) => {
      pending = [n, v]
      if (!timer) timer = setTimeout(flush, 700)
    },
    removeItem: (n) => {
      pending = null
      localStorage.removeItem(n)
    }
  }
})()

/** 付费操作进入可恢复终态后立即固化轻量锚点并推送服务端同步，不等普通防抖。 */
export function flushAppStorePersistence(): boolean {
  flushServerSyncQueues()
  return _flushPersistStorage()
}

type PaidMediaPersistedResultExpectation = {
  conversationId: string
  messageTs: number
  operationId: string
  deliveryProof: PaidMediaDeliveryProof
} & (
  | { images: string[]; videoTask?: never }
  | {
      images?: never
      videoTask: { task_id: string; model: string; prompt?: string }
    }
)

function samePaidMediaDeliveryProof(
  value: unknown,
  expected: PaidMediaDeliveryProof
): boolean {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const proof = value as Record<string, unknown>
  return (
    Object.keys(proof).length === 3 &&
    expected.operationId === proof.operationId &&
    /^[0-9a-f]{64}$/.test(expected.resultSha256) &&
    expected.resultSha256 === proof.resultSha256 &&
    /^[0-9a-f]{64}$/.test(expected.archiveReceiptSha256) &&
    expected.archiveReceiptSha256 === proof.archiveReceiptSha256
  )
}

function matchesPaidMediaExpectation(
  candidate: {
    images?: unknown
    videoTask?: unknown
  },
  expected: PaidMediaPersistedResultExpectation
): boolean {
  if (expected.images !== undefined) {
    return (
      expected.images.length >= 1 &&
      expected.images.length <= 4 &&
      expected.images.every((item) => VAULT_IMAGE_PATTERN.test(item)) &&
      Array.isArray(candidate.images) &&
      candidate.images.length === expected.images.length &&
      candidate.images.every(
        (item, index) =>
          typeof item === 'string' &&
          VAULT_IMAGE_PATTERN.test(item) &&
          item === expected.images[index]
      )
    )
  }
  const task = candidate.videoTask
  if (!task || typeof task !== 'object' || Array.isArray(task)) return false
  const persisted = task as Record<string, unknown>
  return (
    persisted.task_id === expected.videoTask.task_id &&
    persisted.model === expected.videoTask.model &&
    persisted.prompt === expected.videoTask.prompt
  )
}

/**
 * 校验付费媒体交付结果是否已在内存真相源与轻量本地锚点中精确固化，并立刻派发服务端落盘。
 * 非 vault 引用（例如 oversized data URL / 普通外链）会被强制拒绝，绝不误签 ACK。
 */
export function flushAndVerifyPaidMediaResult(
  expected: PaidMediaPersistedResultExpectation
): boolean {
  if (expected.deliveryProof.operationId !== expected.operationId) return false
  const state = useAppStore.getState()
  const conversation = state.conversations.find(
    (candidate) => candidate.id === expected.conversationId
  )
  if (!conversation || !Array.isArray(conversation.messages)) return false

  const memMatches = conversation.messages.filter((message) => {
    const operation = message.paidMediaOperation
    return (
      message.role === 'assistant' &&
      message.ts === expected.messageTs &&
      operation !== undefined &&
      operation.operationId === expected.operationId &&
      operation.phase === 'awaiting_ack' &&
      samePaidMediaDeliveryProof(operation.deliveryProof, expected.deliveryProof)
    )
  })
  if (memMatches.length !== 1) return false
  if (!matchesPaidMediaExpectation(memMatches[0], expected)) return false

  // 立即推送该会话消息到服务端 SQLite，并强制刷新轻量本地恢复锚点
  scheduleServerMessagesSync(expected.conversationId, 0)
  if (!_flushPersistStorage()) return false

  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw || raw.length > 64 * 1024 * 1024) return false
    const envelope = JSON.parse(raw) as {
      state?: { paidMediaAnchors?: unknown }
    }
    if (!Array.isArray(envelope.state?.paidMediaAnchors)) return false
    const anchors = envelope.state.paidMediaAnchors as Array<Record<string, unknown>>
    const persistedMatches = anchors.filter(
      (anchor) =>
        anchor.conversationId === expected.conversationId &&
        anchor.messageTs === expected.messageTs &&
        anchor.operationId === expected.operationId &&
        anchor.phase === 'awaiting_ack' &&
        samePaidMediaDeliveryProof(anchor.deliveryProof, expected.deliveryProof)
    )
    if (persistedMatches.length !== 1) return false
    return matchesPaidMediaExpectation(persistedMatches[0], expected)
  } catch {
    return false
  }
}

export const useAppStore = create<AppState>()(
  persist(
    (set, get) => ({
      status: 'starting',
      engineFeatures: {},
      models: [],
      currentModel: null,
      restoredModelPreference: null,
      restoredPaidMediaAnchors: [],
      conversationsHydrated: false,
      view: 'chat',
      setStatus: (s) => set({ status: s }),
      setEngineFeatures: (features) => set({ engineFeatures: features }),
      setModels: (m) =>
        set((st) => ({
          models: m,
          // 默认主模型优先 premium；Agnes 只作为免费/便宜备选，不再冒充主脑。
          currentModel: preferredChatModel(m, st.currentModel ?? st.restoredModelPreference),
          restoredModelPreference: null
        })),
      setCurrentModel: (id) =>
        set((state) => ({
          currentModel: validatedModelSelection(state.models, id),
          restoredModelPreference: null
        })),
      setView: (v) => set({ view: v }),
      browserInput: null,
      agentBusy: false,
      lastAgentReply: '',
      browserZoom: 'normal',
      submitBrowserInput: (text) => set({ browserInput: { text, ts: Date.now() } }),
      clearBrowserInput: () => set({ browserInput: null }),
      setAgentBusy: (b) => set({ agentBusy: b }),
      setLastAgentReply: (s) => set({ lastAgentReply: s }),
      soundEnabled: true,
      setSoundEnabled: (v) => set({ soundEnabled: v }),
      offlineMode: false,
      setOfflineModeState: (enabled) => set({ offlineMode: Boolean(enabled) }),
      refreshOfflineMode: async () => {
        const res = await apiGetOfflineMode()
        if (res.ok !== false) {
          set({ offlineMode: res.enabled })
          return res.enabled
        }
        return get().offlineMode
      },
      toggleOfflineMode: async (enabled) => {
        const res = await apiSetOfflineMode(enabled)
        if (res.ok !== false) {
          set({ offlineMode: res.enabled })
          return { ok: true, enabled: res.enabled }
        }
        return { ok: false, enabled: get().offlineMode }
      },
      setBrowserZoom: (z) => set({ browserZoom: z }),
      cycleBrowserZoom: () =>
        set((st) => ({
          browserZoom:
            st.browserZoom === 'normal' ? 'wide' : st.browserZoom === 'wide' ? 'max' : 'normal'
        })),
      browserOpen: false,
      openBrowser: () => set({ browserOpen: true }),
      closeBrowser: () => set({ browserOpen: false }),
      toggleBrowser: () => set((s) => ({ browserOpen: !s.browserOpen })),
      appendBrowserNote: (text) => {
        const targetConvId = get().currentConvId
        set((s) => ({
          conversations: s.conversations.map((c) =>
            c.id === s.currentConvId
              ? {
                  ...c,
                  messages: [
                    ...c.messages,
                    { role: 'assistant' as const, content: text, meta: '来自浏览器' }
                  ],
                  updatedAt: Date.now()
                }
              : c
          )
        }))
        if (targetConvId) scheduleServerMessagesSync(targetConvId)
      },
      conversations: [],
      currentConvId: null,
      hydrateConversationsFromServer: async () => {
        // 1. 检测旧 localStorage['agg-conversations'] 或启动时捕获的待迁移会话全文
        const storageLegacy = readLegacyConversationsFromStorage()
        const legacy = storageLegacy.length > 0 ? storageLegacy : (_pendingLegacyConversations ?? [])
        const migrateable = legacy.filter((conv) => !conv.incognito)
        if (migrateable.length > 0) {
          const imported = await apiImportConversations(
            migrateable.map((conv) => ({
              ...conv,
              messages: conv.messages.map(sanitizeMessageForServer)
            }))
          )
          if (imported.ok) {
            _pendingLegacyConversations = null
            // 迁移成功后立即重写 localStorage 剔除旧全文
            writeSlimLocalPreferences(get())
          }
        } else if (storageLegacy.length > 0) {
          // 即使全部为无痕会话也立即剔除旧 localStorage 全文
          _pendingLegacyConversations = null
          writeSlimLocalPreferences(get())
        }

        // 2. 拉取服务端权威会话列表并同步进内存 store
        const remote = await apiListConversationsResult()
        if (!remote.ok) return

        for (const conv of remote.conversations) _createdOnServer.add(conv.id)
        set((s) => {
          const incognitoConvs = s.conversations.filter((c) => c.incognito)
          const merged = [...incognitoConvs, ...remote.conversations]
          const hasCurrent =
            Boolean(s.currentConvId) && merged.some((c) => c.id === s.currentConvId)
          const nextCurrentId = hasCurrent
            ? s.currentConvId
            : (merged.find((c) => !c.archived)?.id ?? merged[0]?.id ?? null)
          return {
            conversations: merged,
            currentConvId: nextCurrentId,
            conversationsHydrated: true
          }
        })
        writeSlimLocalPreferences(get())
      },
      ensureConversation: () => {
        let created: Conversation | null = null
        set((s) => {
          if (s.currentConvId && s.conversations.some((c) => c.id === s.currentConvId)) return {}
          if (s.conversations.length) return { currentConvId: s.conversations[0].id }
          const c = blankConv()
          created = c
          return { conversations: [c], currentConvId: c.id }
        })
        if (created && !(created as Conversation).incognito) {
          const conv = created as Conversation
          void apiCreateConversation({
            id: conv.id,
            title: conv.title,
            kind: conv.kind,
            workdir: conv.workdir ?? '',
            archived: Boolean(conv.archived),
            messages: []
          }).then((res) => {
            if (res) _createdOnServer.add(conv.id)
          })
        }
      },
      newConversation: (kind, opts) => {
        const incognito = opts?.incognito === true
        const c = blankConv(kind, incognito)
        set((s) => ({
          conversations: [c, ...s.conversations],
          currentConvId: c.id
        }))
        if (!incognito) {
          void apiCreateConversation({
            id: c.id,
            title: c.title,
            kind: c.kind,
            workdir: c.workdir ?? '',
            archived: Boolean(c.archived),
            messages: []
          }).then((res) => {
            if (res) _createdOnServer.add(c.id)
          })
        }
        return c.id
      },
      switchConversation: (id) => set({ currentConvId: id }),
      renameConversation: (id, title) => {
        set((s) => ({
          conversations: s.conversations.map((c) => (c.id === id ? { ...c, title } : c))
        }))
        scheduleServerPatchSync(id, { title })
      },
      deleteConversation: (id) => {
        const existing = get().conversations.find((c) => c.id === id)
        cancelServerSyncFor(id)
        _createdOnServer.delete(id)
        set((s) => {
          const rest = s.conversations.filter((c) => c.id !== id)
          const cur = s.currentConvId === id ? (rest[0]?.id ?? null) : s.currentConvId
          return { conversations: rest, currentConvId: cur }
        })
        if (existing && !existing.incognito) {
          void apiDeleteConversation(id)
        }
      },
      archiveConversation: (id, archived = true) => {
        set((s) => {
          const convs = s.conversations.map((c) => (c.id === id ? { ...c, archived } : c))
          // 归档当前对话 → 切到下一个未归档的（没有则清空，聊天区显欢迎屏）
          let cur = s.currentConvId
          if (archived && s.currentConvId === id) {
            cur = convs.find((c) => !c.archived)?.id ?? null
          }
          return { conversations: convs, currentConvId: cur }
        })
        scheduleServerPatchSync(id, { archived }, 0)
      },
      setConvWorkdir: (id, workdir) => {
        const prev = get().conversations.find((c) => c.id === id)
        if (prev?.workdir === workdir) return
        set((s) => ({
          conversations: s.conversations.map((c) => (c.id === id ? { ...c, workdir } : c))
        }))
        scheduleServerPatchSync(id, { workdir })
      },
      setConvIncognito: (id, incognito) => {
        if (incognito) cancelServerSyncFor(id)
        set((s) => ({
          conversations: s.conversations.map((c) => (c.id === id ? { ...c, incognito } : c))
        }))
      },
      setConvDraft: (id, draft) =>
        set((s) => ({
          conversations: s.conversations.map((c) => (c.id === id ? { ...c, draft } : c))
        })),
      setCurrentMessages: (updater) => {
        const convId = get().currentConvId
        if (!convId) return
        let derivedNewTitle: string | null = null
        set((s) => ({
          conversations: s.conversations.map((c) => {
            if (c.id !== convId) return c
            const next = typeof updater === 'function' ? updater(c.messages) : updater
            const title = c.title === '新对话' ? deriveTitle(next) : c.title
            if (title !== c.title) derivedNewTitle = title
            return { ...c, messages: next, title, updatedAt: Date.now() }
          })
        }))
        if (derivedNewTitle) scheduleServerPatchSync(convId, { title: derivedNewTitle })
        scheduleServerMessagesSync(convId)
      },
      setConvMessages: (convId, updater) => {
        let derivedNewTitle: string | null = null
        set((s) => ({
          conversations: s.conversations.map((c) => {
            if (c.id !== convId) return c
            const next = typeof updater === 'function' ? updater(c.messages) : updater
            const title = c.title === '新对话' ? deriveTitle(next) : c.title
            if (title !== c.title) derivedNewTitle = title
            return { ...c, messages: next, title, updatedAt: Date.now() }
          })
        }))
        if (derivedNewTitle) scheduleServerPatchSync(convId, { title: derivedNewTitle })
        scheduleServerMessagesSync(convId)
      }
    }),
    {
      name: STORAGE_KEY,
      storage: _persistStorage as never,
      // P1-3A：彻底淘汰 localStorage 存 conversations 会话全文！
      // 仅保留极轻量 UI 偏好（总大小 < 2KB）与待核销付费媒体操作锚点（无聊天正文/无 base64 图）。
      partialize: (s) => {
        const paidMediaAnchors = extractPaidMediaAnchors(s.conversations)
        return {
          currentModel: s.currentModel ?? s.restoredModelPreference,
          currentConvId: s.currentConvId,
          soundEnabled: s.soundEnabled,
          ...(paidMediaAnchors.length ? { paidMediaAnchors } : {})
        }
      },
      merge: mergePersistedAppState
    }
  )
)
