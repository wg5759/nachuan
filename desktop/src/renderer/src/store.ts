import { create } from 'zustand'
import { persist } from 'zustand/middleware'

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

// 一条聊天显示消息。媒体尽量持久化（见下方 partialize）：图片存可持久 URL；
// 视频 blob 是会话级临时 URL、重启即失效 → 另存原始源 videoSrc，重启后再代下播放。
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

// 一个对话（会话）：各自一套消息与记忆，可新建/切换/删除/重命名，持久化到 localStorage
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
  /** 输入框草稿（未发送的文字/文档/图片）——随对话持久化，重启回来还在原处（机主要求）。
   *  图片存 dataUrl（受总量上限，超出的仅会话内保留）；恢复时据此重建 File。 */
  draft?: {
    text?: string
    docs?: { name: string; content: string }[]
    images?: { name: string; dataUrl: string }[]
  }
}

const newId = (): string => Date.now().toString(36) + Math.random().toString(36).slice(2, 6)
const blankConv = (kind: ConversationKind = 'chat'): Conversation => ({
  id: newId(),
  title: '新对话',
  kind,
  messages: [],
  createdAt: Date.now(),
  updatedAt: Date.now()
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

type MsgUpdater = ChatDisplayMsg[] | ((prev: ChatDisplayMsg[]) => ChatDisplayMsg[])

interface AppState {
  status: EngineStatus
  models: ModelInfo[]
  currentModel: string | null
  /** Persisted preference held inert until a fresh `/v1/models` allowlist arrives. */
  restoredModelPreference: string | null
  view: ViewKey
  setStatus: (s: EngineStatus) => void
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
  // 右栏浏览器默认关闭；可手动开/关，agent 用到浏览器工具时自动开
  browserOpen: boolean
  openBrowser: () => void
  closeBrowser: () => void
  toggleBrowser: () => void
  // 浏览器里干完的活，给中间当前对话留一条摘要（中间 agent 据此"知道"发生了什么）
  appendBrowserNote: (text: string) => void
  // 多对话（会话列表）
  conversations: Conversation[]
  currentConvId: string | null
  ensureConversation: () => void
  newConversation: (kind?: ConversationKind) => string
  switchConversation: (id: string) => void
  renameConversation: (id: string, title: string) => void
  deleteConversation: (id: string) => void
  archiveConversation: (id: string, archived?: boolean) => void
  setConvWorkdir: (id: string, workdir: string) => void
  setConvDraft: (id: string, draft: Conversation['draft']) => void
  setCurrentMessages: (updater: MsgUpdater) => void
  /** 往**指定对话**写消息（异步回写用：任务跑着时用户切了对话，结果必须写回发起时的对话，
   *  绝不能跟着 currentConvId 走串——codex 审出的跨对话写串洞）。 */
  setConvMessages: (convId: string, updater: MsgUpdater) => void
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
  return {
    ...current,
    currentConvId:
      typeof record.currentConvId === 'string' || record.currentConvId === null
        ? record.currentConvId
        : current.currentConvId,
    soundEnabled:
      typeof record.soundEnabled === 'boolean' ? record.soundEnabled : current.soundEnabled,
    conversations: Array.isArray(record.conversations)
      ? (record.conversations as Conversation[])
      : current.conversations,
    models: [],
    currentModel: null,
    restoredModelPreference: candidate
  }
}

// 防抖持久化（真·热路径零重活版）：流式每个 token 都 setMessages → zustand persist 每次 set 都会
// partialize + **JSON.stringify(含几MB base64 媒体)** + 写盘。之前只把「写盘」防抖了，stringify 仍每
// delta 全量跑 → 回车/流式照卡(机主实测:修几次还卡的真凶)。改用自定义 PersistStorage：
// setItem 只存**对象引用**(O(1))，~700ms 后 flush 才 stringify+写盘；退出前 beforeunload 兜底 flush。
// 顺带吞 QuotaExceededError（配额满别静默炸掉整个持久化——复审 Fable/Kimi 提）。
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
    timer = null
    if (!pending) return true
    const current = pending
    const [n, v] = current
    try {
      // 防误清历史（机主实测：热更新灌入中间态代码 → 空 state 覆盖真数据 → 聊天记录全没）：
      // 要写入的对话数比现存少一半以上时，先把现存整份备份到 .bak（保留最近一次"缩水前"档，可手工找回）。
      try {
        const nextConvs = (v?.state as { conversations?: unknown[] } | undefined)?.conversations?.length ?? 0
        const cur = localStorage.getItem(n)
        if (cur) {
          const curConvs = (JSON.parse(cur)?.state?.conversations?.length as number) ?? 0
          if (curConvs > 0 && nextConvs < curConvs / 2) localStorage.setItem(n + '.bak', cur)
        }
      } catch {
        /* 备份失败不阻塞正常落盘 */
      }
      localStorage.setItem(n, JSON.stringify(v)) // stringify 挪到这：700ms 最多一次，不再每 delta 卡主线程
      if (pending === current) pending = null
      return true
    } catch (e) {
      console.warn('[persist] 写入失败(多半超 localStorage 配额)，本次不持久化', e)
      return false
    }
  }
  _flushPersistStorage = flush
  if (typeof window !== 'undefined') {
    // 退出双兜底：beforeunload 落一次；pagehide(更晚) 再落一次——保证组件在 beforeunload 里
    // 最后写入的草稿（ChatPane 未发送输入）也能赶上落盘。flush 幂等，跑两次无害。
    window.addEventListener('beforeunload', flush)
    window.addEventListener('pagehide', flush)
  }
  return {
    getItem: (n) => {
      const s = localStorage.getItem(n)
      try {
        return s ? (JSON.parse(s) as _SV) : null // 旧数据就是 createJSONStorage 的 {state,version}，原样兼容
      } catch {
        // 读坏（半截写入等）：把坏档留到 .bak 再放弃——否则接下来空态落盘，坏档也被埋（想救都没底稿）
        try {
          if (s) localStorage.setItem(n + '.bak', s)
        } catch {
          /* ignore */
        }
        return null
      }
    },
    setItem: (n, v) => {
      pending = [n, v] // 只挂引用，零序列化
      if (!timer) timer = setTimeout(flush, 700)
    },
    removeItem: (n) => {
      pending = null
      localStorage.removeItem(n)
    }
  }
})()

/** 付费操作进入可恢复终态后立即固化消息里的 operationId，不等普通 700ms 防抖。 */
export function flushAppStorePersistence(): boolean {
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

/**
 * A successful localStorage write is not proof that partialize retained a paid
 * result. Read the exact serialized snapshot back before main may mark the
 * operation delivered; oversized data URLs are intentionally rejected here.
 */
export function flushAndVerifyPaidMediaResult(
  expected: PaidMediaPersistedResultExpectation
): boolean {
  if (!_flushPersistStorage()) return false
  let raw: string | null = null
  try {
    raw = localStorage.getItem('agg-conversations')
    if (!raw || raw.length > 64 * 1024 * 1024) return false
    const envelope = JSON.parse(raw) as {
      state?: { conversations?: unknown }
    }
    if (!Array.isArray(envelope.state?.conversations)) return false
    const conversations = envelope.state.conversations as Array<Record<string, unknown>>
    const conversation = conversations.find(
      (candidate) => candidate.id === expected.conversationId
    )
    if (!conversation || !Array.isArray(conversation.messages)) return false
    const matches = (conversation.messages as unknown[]).filter((value) => {
      if (!value || typeof value !== 'object' || Array.isArray(value)) return false
      const message = value as Record<string, unknown>
      const operation = message.paidMediaOperation
      return (
        message.role === 'assistant' &&
        message.ts === expected.messageTs &&
        operation !== null &&
        typeof operation === 'object' &&
        !Array.isArray(operation) &&
        (operation as Record<string, unknown>).operationId === expected.operationId &&
        expected.deliveryProof.operationId === expected.operationId &&
        (operation as Record<string, unknown>).phase === 'awaiting_ack' &&
        samePaidMediaDeliveryProof(
          (operation as Record<string, unknown>).deliveryProof,
          expected.deliveryProof
        )
      )
    })
    if (matches.length !== 1) return false
    const message = matches[0] as Record<string, unknown>
    if (expected.images !== undefined) {
      return (
        expected.images.length >= 1 &&
        expected.images.length <= 4 &&
        expected.images.every((item) =>
          /^nachuan-paid-media:\/\/sha256\/[0-9a-f]{64}$/.test(item)
        ) &&
        Array.isArray(message.images) &&
        message.images.length === expected.images.length &&
        message.images.every(
          (item, index) =>
            typeof item === 'string' &&
            /^nachuan-paid-media:\/\/sha256\/[0-9a-f]{64}$/.test(item) &&
            item === expected.images[index]
        )
      )
    }
    const task = message.videoTask
    if (!task || typeof task !== 'object' || Array.isArray(task)) return false
    const persisted = task as Record<string, unknown>
    return (
      persisted.task_id === expected.videoTask.task_id &&
      persisted.model === expected.videoTask.model &&
      persisted.prompt === expected.videoTask.prompt
    )
  } catch {
    return false
  }
}

export const useAppStore = create<AppState>()(
  persist(
    (set) => ({
      status: 'starting',
      models: [],
      currentModel: null,
      restoredModelPreference: null,
      view: 'chat',
      setStatus: (s) => set({ status: s }),
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
      appendBrowserNote: (text) =>
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
        })),
      conversations: [],
      currentConvId: null,
      ensureConversation: () =>
        set((s) => {
          if (s.currentConvId && s.conversations.some((c) => c.id === s.currentConvId)) return {}
          if (s.conversations.length) return { currentConvId: s.conversations[0].id }
          const c = blankConv()
          return { conversations: [c], currentConvId: c.id }
        }),
      newConversation: (kind) => {
        const c = blankConv(kind)
        set((s) => {
          return { conversations: [c, ...s.conversations], currentConvId: c.id }
        })
        return c.id
      },
      switchConversation: (id) => set({ currentConvId: id }),
      renameConversation: (id, title) =>
        set((s) => ({
          conversations: s.conversations.map((c) => (c.id === id ? { ...c, title } : c))
        })),
      deleteConversation: (id) =>
        set((s) => {
          const rest = s.conversations.filter((c) => c.id !== id)
          const cur = s.currentConvId === id ? (rest[0]?.id ?? null) : s.currentConvId
          return { conversations: rest, currentConvId: cur }
        }),
      archiveConversation: (id, archived = true) =>
        set((s) => {
          const convs = s.conversations.map((c) => (c.id === id ? { ...c, archived } : c))
          // 归档当前对话 → 切到下一个未归档的（没有则清空，聊天区显欢迎屏）
          let cur = s.currentConvId
          if (archived && s.currentConvId === id) {
            cur = convs.find((c) => !c.archived)?.id ?? null
          }
          return { conversations: convs, currentConvId: cur }
        }),
      setConvWorkdir: (id, workdir) =>
        set((s) => ({
          conversations: s.conversations.map((c) => (c.id === id ? { ...c, workdir } : c))
        })),
      setConvDraft: (id, draft) =>
        set((s) => ({
          conversations: s.conversations.map((c) => (c.id === id ? { ...c, draft } : c))
        })),
      setCurrentMessages: (updater) =>
        set((s) => ({
          conversations: s.conversations.map((c) => {
            if (c.id !== s.currentConvId) return c
            const next = typeof updater === 'function' ? updater(c.messages) : updater
            const title = c.title === '新对话' ? deriveTitle(next) : c.title
            return { ...c, messages: next, title, updatedAt: Date.now() }
          })
        })),
      setConvMessages: (convId, updater) =>
        set((s) => ({
          conversations: s.conversations.map((c) => {
            if (c.id !== convId) return c
            const next = typeof updater === 'function' ? updater(c.messages) : updater
            const title = c.title === '新对话' ? deriveTitle(next) : c.title
            return { ...c, messages: next, title, updatedAt: Date.now() }
          })
        }))
    }),
    {
      name: 'agg-conversations',
      // 自定义 PersistStorage(非 createJSONStorage)：setItem 只挂对象引用、stringify 延到 flush——
      // 否则每个流式 delta 都全量 stringify 几 MB base64 → 回车/流式卡（机主实测）。见上方 _persistStorage。
      storage: _persistStorage as never,
      // 持久化对话 + 尽量固定住媒体（机主实测：重启后图/视频消失、空消息还在转圈）。
      // http/file/sandbox/studio 引用小而持久 → 直接留；data:base64 图大 → 反向累计设预算，
      // 优先保最近对话、超预算不再持久化，防 localStorage 配额炸掉；blob: 会话级临时 URL 不留
      // （视频改存原始源 videoSrc，重启后再代下播放）。
      partialize: (s) => {
        const DURABLE = /^(https?:|file:|sandbox:|studio:|nachuan-paid-media:)/
        // data:base64 图大 → 按「实际存储字节」逐次占用预算(不去重：JSON 逐条各存一份，同图 N 条=N 份)，
        // 优先保最近对话(数组头=最新)+最近消息(数组尾=最新)，超预算丢弃 → 防 localStorage 配额被击穿后
        // zustand persist 静默失败、此后全不持久化。去留按「第几对话:第几条:URL」逐次记，与真实存储一致。
        let dataBudget = 2_500_000
        const keep = new Set<string>()
        for (let ci = 0; ci < s.conversations.length; ci++) {
          const msgs = s.conversations[ci].messages
          for (let mi = msgs.length - 1; mi >= 0; mi--) {
            for (const u of msgs[mi].images ?? []) {
              if (u.startsWith('data:') && dataBudget - u.length > 0) {
                dataBudget -= u.length
                keep.add(`${ci}:${mi}:${u}`)
              }
            }
          }
        }
        const keepImages = (imgs: string[] | undefined, ci: number, mi: number): string[] | undefined => {
          if (!imgs?.length) return undefined
          const kept = imgs.filter((u) => DURABLE.test(u) || keep.has(`${ci}:${mi}:${u}`))
          return kept.length ? kept : undefined
        }
        return {
          currentModel: s.currentModel ?? s.restoredModelPreference,
          currentConvId: s.currentConvId,
          soundEnabled: s.soundEnabled,
          conversations: s.conversations.map((c, ci) => ({
            ...c,
            messages: c.messages.map((m, mi) => ({
              role: m.role,
              content: m.content,
              ts: m.ts,
              startedAt: m.startedAt,
              completedAt: m.completedAt,
              workLog: m.workLog,
              meta: m.meta,
              model: m.model,
              usage: m.usage,
              reasoning: m.reasoning,
              translated: m.translated,
              docs: m.docs,
              images: keepImages(m.images, ci, mi),
              video: m.video && DURABLE.test(m.video) ? m.video : undefined,
              videoSrc: m.videoSrc,
              videoTask: m.videoTask, // 进行中任务号也落盘 → 重启自动续传
              paidMediaOperation: m.paidMediaOperation
            }))
          }))
        }
      },
      merge: mergePersistedAppState
    }
  )
)
