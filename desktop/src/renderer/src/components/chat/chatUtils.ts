import {
  isDurablePaidMediaAssetRef,
  type AgentEvent,
  type ChatContentPart,
  type ChatMsg
} from '../../api'
import type { ChatDisplayMsg as DisplayMsg, TokenUsage } from '../../store'

// 显示消息稳定空数组常量，避免无谓重渲染
export const EMPTY_MSGS: DisplayMsg[] = []

// 粘贴/输入超过这么多字符，就当成「一份文档」而不是一句话：转成文档附件，不在输入框/气泡里铺一墙字。
export const DOC_THRESHOLD = 2000
export const DAILY_VIDEO_ROOT = 'D:\\AI视频制作'

export type PendingDoc = { name: string; content: string }
// dataUrl：添加时后台算好（≤2MB 的图才算），草稿恢复用
export type PendingImage = { name: string; url: string; file: File; dataUrl?: string }
// convId：排队消息属于入队时的对话——完成后只发回那个对话，绝不窜进新开的窗口
export type QueuedMessage = {
  text: string
  docs?: PendingDoc[]
  images?: PendingImage[]
  convId?: string
}

export type ExecPermissionMode = 'plan' | 'auto' | 'full' | 'custom'
export type ReasoningLevel = 'low' | 'medium' | 'high'
export type TFn = (key: string, opts?: Record<string, unknown>) => string

export const EXEC_PERMISSION_OPTIONS: {
  value: ExecPermissionMode
  label: string
  desc: string
}[] = [
  { value: 'plan', label: 'chat.perm_request', desc: 'chat.permdesc_request' },
  { value: 'auto', label: 'chat.perm_auto', desc: 'chat.permdesc_auto' },
  { value: 'full', label: 'chat.perm_full', desc: 'chat.permdesc_full' },
  { value: 'custom', label: 'chat.perm_custom', desc: 'chat.permdesc_custom' }
]

export const APP_CAPABILITY_SYSTEM: ChatMsg = {
  role: 'system',
  content: [
    '你运行在“纳川”桌面应用中，不是孤立网页模型。',
    '普通聊天只负责回答；需要读写本地文件、运行命令、调用其它模型时，应使用“动手执行/执行代理”路线。',
    '执行代理提供受工作区约束的 list_dir/read_file/write_file 与 list_models/ask_model 等工具；宿主命令在独立低权限执行器接入前保持关闭。',
    '纳川有长期记忆、知识库检索和上下文压缩；压缩只处理旧工具输出/冗余上下文，不改变用户当前指令。',
    '不要直接声称“无法访问本地文件/无法调用其它模型”；应说明当前路线能否通过纳川工具完成。'
  ].join('\n')
}

// 简易行级 diff 统计（多重集交集）：给内联动作卡显示 +增/-删
export function diffStat(before: string, after: string): { add: number; del: number } {
  const b = before ? before.split('\n') : []
  const a = after ? after.split('\n') : []
  const bag = new Map<string, number>()
  for (const l of b) bag.set(l, (bag.get(l) || 0) + 1)
  let same = 0
  for (const l of a) {
    const c = bag.get(l) || 0
    if (c > 0) {
      bag.set(l, c - 1)
      same++
    }
  }
  return { add: a.length - same, del: b.length - same }
}

// 超级体路由标签 → 中文（case_reuse=复用强模型解法、teacher=强模型解、cheap=免费模型）
export const routeLabelZh = (label: string): string =>
  ({ case_reuse: '复用案例', teacher: '强模型解', cheap: '免费模型' })[label] ?? label

// 给粘贴的长文起个名字：取首行前 16 字做标题，没有就叫「长文」
export const pastedDocName = (text: string): string => {
  const head = text.trim().split('\n')[0]?.slice(0, 16).trim()
  return `${head || '长文'}.md`
}

// 文档附件 → 喂给模型的上下文块（带文件名与分隔，模型能据实引用）
export function docsToContext(docs: { name: string; content: string }[]): string {
  return docs.map((d) => `【附件文档：${d.name}】\n${d.content}`).join('\n\n')
}

// 一条消息真正喂给模型的文字 = 文档附件展开 + 正文（历史轮次也据此重新带上文档，问下一句不丢上下文）
export function msgToModelText(m: DisplayMsg): string {
  if (m.docs?.length) {
    const ctx = docsToContext(m.docs)
    return m.content ? `${ctx}\n\n${m.content}` : ctx
  }
  return m.content
}

// 在当前会话内保留结构化 image_url：同轮上传图、上一轮 AI 生图才能被 agent 的 staged_images 找到。
export function displayImageUrls(m: DisplayMsg): string[] {
  const urls = (m.images ?? []).filter(
    (url) => url.startsWith('data:image/') || url.startsWith('http://') || url.startsWith('https://')
  )
  const markdown = [...m.content.matchAll(/!\[[^\]]*\]\((https?:\/\/[^)\s]+)\)/g)].map((x) => x[1])
  return [...new Set([...urls, ...markdown].filter((url): url is string => Boolean(url)))]
}

export function messagesToAgentHistory(messages: DisplayMsg[]): ChatMsg[] {
  let latestImageIndex = -1
  for (let i = messages.length - 1; i >= 0; i--) {
    if (displayImageUrls(messages[i]).length) {
      latestImageIndex = i
      break
    }
  }
  const hist = messages.map((m, i) => {
    const text = msgToModelText(m)
    const urls = i === latestImageIndex ? displayImageUrls(m) : []
    const content: string | ChatContentPart[] = urls.length
      ? [
          ...(text ? [{ type: 'text' as const, text }] : []),
          ...urls.map((url) => ({ type: 'image_url' as const, image_url: { url } }))
        ]
      : text
    return { role: m.role, content } as ChatMsg
  })
  // 后台任务上下文衔接：插队/继续聊时，正在跑的生视频任务必须"在场"
  const running = messages.filter((m) => m.videoTask && !m.video)
  if (running.length) {
    const lines = running.map(
      (m, j) =>
        `${j + 1}. ${m.videoTask!.task_id.startsWith('studio:') ? '长视频(分镜逐镜生成)' : '短视频'}：` +
        `${m.videoTask!.prompt || '(内容见上文对话)'}`
    )
    hist.push({
      role: 'assistant',
      content:
        `〔系统提示·后台任务进行中〕当前有 ${running.length} 个生视频任务正在引擎后台运行，成片会自动贴回对话：\n` +
        lines.join('\n') +
        '\n用户接下来的话可能是对这些任务的补充/修改/询问——请结合任务内容理解，别当成无关新话题。' +
        '注意：已派发任务的画面参数中途改不了；用户若要改内容，如实说明并给两个选择：重新派一个新任务（含新要求），或等成片出来再调整。用户问进度就答"还在后台生成中，做好自动贴回"，绝不要重新调用生成工具。'
    } as ChatMsg)
  }
  return hist
}

export function latestDisplayImages(messages: DisplayMsg[]): string[] {
  for (let i = messages.length - 1; i >= 0; i--) {
    const urls = displayImageUrls(messages[i])
    if (urls.length) return urls
  }
  return []
}

// 进度行判定：以 ⚙/💭/🔍/⬆ 开头，或以空白+「·」开头的缩进子项。
export function isFleetProgressLine(line: string): boolean {
  return /^(⚙|💭|🔍|⬆)/.test(line) || /^\s+·/.test(line)
}

// 从舰队消息里分离「开头连续进度行」与正文。
export function splitFleetProgress(content: string): { steps: string[]; body: string } {
  const lines = content.split('\n')
  const steps: string[] = []
  let i = 0
  while (i < lines.length) {
    const line = lines[i]
    if (isFleetProgressLine(line)) {
      steps.push(line)
      i += 1
    } else if (line.trim() === '' && steps.length > 0) {
      i += 1
    } else {
      break
    }
  }
  if (steps.length === 0) return { steps: [], body: content }
  return { steps, body: lines.slice(i).join('\n') }
}

export function readFileAsDataUrl(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onerror = () => reject(reader.error ?? new Error('read image failed'))
    reader.onload = () => resolve(String(reader.result || ''))
    reader.readAsDataURL(file)
  })
}

// 大图压缩后再发：≤300KB 原样；更大则等比缩到最长边 1600px、JPEG 0.85（透明填白底）。
export async function imageFileToDataUrl(file: File): Promise<string> {
  const raw = await readFileAsDataUrl(file)
  if (raw.length < 300_000) return raw
  try {
    const img = await new Promise<HTMLImageElement>((resolve, reject) => {
      const el = new Image()
      el.onload = () => resolve(el)
      el.onerror = () => reject(new Error('decode image failed'))
      el.src = raw
    })
    const scale = Math.min(1, 1600 / Math.max(img.width, img.height, 1))
    const w = Math.max(1, Math.round(img.width * scale))
    const h = Math.max(1, Math.round(img.height * scale))
    const canvas = document.createElement('canvas')
    canvas.width = w
    canvas.height = h
    const ctx = canvas.getContext('2d')
    if (!ctx) return raw
    ctx.fillStyle = '#fff'
    ctx.fillRect(0, 0, w, h)
    ctx.drawImage(img, 0, 0, w, h)
    const out = canvas.toDataURL('image/jpeg', 0.85)
    return out.length < raw.length ? out : raw
  } catch {
    return raw
  }
}

export const usageValue = (
  usage: TokenUsage | undefined,
  key: keyof TokenUsage
): number | undefined => {
  const n = Number(usage?.[key])
  return Number.isFinite(n) ? n : undefined
}

export function hasTokenUsage(usage?: TokenUsage): boolean {
  return ['prompt_tokens', 'completion_tokens', 'total_tokens', 'cached_tokens'].some(
    (k) => usageValue(usage, k as keyof TokenUsage) !== undefined
  )
}

export function formatTokenUsage(usage: TokenUsage | undefined, t: TFn): string {
  if (!hasTokenUsage(usage)) return ''
  const total = usageValue(usage, 'total_tokens')
  const prompt = usageValue(usage, 'prompt_tokens')
  const completion = usageValue(usage, 'completion_tokens')
  const cached = usageValue(usage, 'cached_tokens')
  const parts: string[] = []
  if (total !== undefined) parts.push(t('chat.tokenTotal', { n: total }))
  const io: string[] = []
  if (prompt !== undefined) io.push(t('chat.tokenIn', { n: prompt }))
  if (completion !== undefined) io.push(t('chat.tokenOut', { n: completion }))
  if (io.length) parts.push(io.join(' / '))
  if (cached) parts.push(t('chat.tokenCached', { n: cached }))
  return parts.join(' · ')
}

// 把图片/视频存到本地。走主进程保存（原生「另存为」对话框）。
export async function downloadMedia(originalSrc: string, filename: string): Promise<void> {
  let src = originalSrc
  let releaseReference: string | null = null
  try {
    if (isDurablePaidMediaAssetRef(src) && window.api?.resolvePaidMediaAsset) {
      src = await window.api.resolvePaidMediaAsset(src)
      releaseReference = originalSrc
    }
    try {
      if (window.api?.saveMedia) {
        let r: { ok: boolean; path?: string; error?: string }
        if (/^https?:/i.test(src)) {
          r = await window.api.saveMedia({ filename, url: src })
        } else {
          const bytes = await (await fetch(src)).arrayBuffer()
          r = await window.api.saveMedia({ filename, bytes })
        }
        if (!r.ok && r.error !== 'canceled') window.alert(`保存失败：${r.error || '未知错误'}`)
        return
      }
    } catch {
      window.alert('保存失败：媒体读取或安全校验未通过')
      return
    }
    if (/^https?:/i.test(src)) {
      window.alert('保存失败：安全下载服务不可用')
      return
    }
    try {
      const blob = await (await fetch(src)).blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = filename
      document.body.appendChild(a)
      a.click()
      a.remove()
      setTimeout(() => URL.revokeObjectURL(url), 2000)
    } catch {
      // 全失败也不打断对话
    }
  } finally {
    if (releaseReference) window.api?.releasePaidMediaAsset?.(releaseReference)
  }
}

export function formatElapsed(start?: number, end?: number): string {
  if (!start) return ''
  const ms = Math.max(0, (end ?? Date.now()) - start)
  const sec = Math.round(ms / 1000)
  if (sec < 60) return `${sec}s`
  const min = Math.floor(sec / 60)
  const rest = sec % 60
  return `${min}m ${rest}s`
}

// 单行截断（时间线里 verdict/plan 可能很长，别撑爆 UI；整行 title 保留全文可悬停看）。
export const clip = (s: unknown, n = 160): string =>
  String(s ?? '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, n)

// 把编排器的一个进度事件渲染成时间线里的一行（i18n）。返回 null 表示这类事件不单独成行。
export function agentEventLine(ev: AgentEvent, t: TFn): string | null {
  switch (ev.type) {
    case 'route': {
      const diff = String((ev.difficulty as string) ?? '')
      const model = String((ev.model as string) ?? '?')
      return ev.complex
        ? t('chat.agRouteComplex', { model, difficulty: diff })
        : t('chat.agRouteSimple', { model })
    }
    case 'plan':
      return t('chat.agPlan', { plan: clip(ev.plan, 200) })
    case 'step':
      return t('chat.agStep', { log: clip(ev.log, 180) })
    case 'verify':
      return (
        (ev.verified ? t('chat.agVerifyPass') : t('chat.agVerifyFail')) +
        (ev.verdict ? ` — ${clip(ev.verdict, 160)}` : '')
      )
    case 'escalate':
      return t('chat.agEscalate', { from: String(ev.from ?? '?'), to: String(ev.to ?? '?') })
    case 'replan':
      return t('chat.agReplan', { model: String(ev.model ?? '?'), plan: clip(ev.plan, 200) })
    case 'done':
      return t(ev.verified === false ? 'chat.agDoneBest' : 'chat.agDone')
    default:
      return null
  }
}

export const maxStepsForReasoning = (level: ReasoningLevel): number =>
  level === 'high' ? 80 : level === 'medium' ? 50 : 30

// 完成提示音：Web Audio 现合成一段柔和「叮—咚」（两声下行三度），零文件零依赖。
export function playCompletionChime(): void {
  try {
    const Ctx =
      window.AudioContext ||
      (window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext
    if (!Ctx) return
    const ctx = new Ctx()
    const now = ctx.currentTime
    ;[
      { f: 784, t: 0 },
      { f: 659, t: 0.16 }
    ].forEach(({ f, t }) => {
      const osc = ctx.createOscillator()
      const gain = ctx.createGain()
      osc.type = 'sine'
      osc.frequency.value = f
      gain.gain.setValueAtTime(0.0001, now + t)
      gain.gain.exponentialRampToValueAtTime(0.16, now + t + 0.02)
      gain.gain.exponentialRampToValueAtTime(0.0001, now + t + 0.32)
      osc.connect(gain).connect(ctx.destination)
      osc.start(now + t)
      osc.stop(now + t + 0.34)
    })
    setTimeout(() => void ctx.close().catch(() => {}), 800)
  } catch {
    /* 音频不可用就静默，绝不影响功能 */
  }
}

export async function copyTextToClipboard(text: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text)
  } catch {
    const ta = document.createElement('textarea')
    ta.value = text
    ta.style.position = 'fixed'
    ta.style.opacity = '0'
    document.body.appendChild(ta)
    ta.select()
    try {
      document.execCommand('copy')
    } catch {
      /* 失败不打断 */
    }
    ta.remove()
  }
}

const LOCAL_UI_MODEL_PROVIDERS = new Set([
  'local',
  'ollama',
  'lmstudio',
  'llamacpp',
  'llama.cpp',
  'llama',
  'jan',
  'vllm',
  'echo'
])

export function isLocalModelInfo(
  model: { id?: string; owned_by?: string } | undefined,
  modelId?: string | null
): boolean {
  const owned = (model?.owned_by ?? '').trim().toLowerCase()
  if (owned && LOCAL_UI_MODEL_PROVIDERS.has(owned)) return true
  const id = (model?.id ?? modelId ?? '').trim().toLowerCase()
  if (!id) return false
  if (LOCAL_UI_MODEL_PROVIDERS.has(id)) return true
  return /^(local|ollama|llama\d*|llamacpp|lmstudio|jan|vllm)([:/-]|$)/.test(id)
}

export interface ResolvedChatPrivacyFlags {
  webSearch: boolean
  incognito: boolean
  injectMemory: boolean | undefined
  conversationId: string | undefined
  webSearchBlockedBy: 'offline' | 'incognito' | 'local' | 'feature' | null
}

export function resolveChatPrivacyFlags(opts: {
  webSearchEnabled: boolean
  incognito: boolean
  model?: { id?: string; owned_by?: string }
  modelId?: string | null
  conversationId?: string | null
  webSearchFeatureEnabled?: boolean
  offlineMode?: boolean
}): ResolvedChatPrivacyFlags {
  const incognito = opts.incognito === true
  const offline = opts.offlineMode === true
  const local = isLocalModelInfo(opts.model, opts.modelId)
  const featureDisabled = opts.webSearchFeatureEnabled === false
  const webSearchBlockedBy: 'offline' | 'incognito' | 'local' | 'feature' | null = offline
    ? 'offline'
    : incognito
      ? 'incognito'
      : local
        ? 'local'
        : featureDisabled
          ? 'feature'
          : null
  const webSearch = webSearchBlockedBy === null && opts.webSearchEnabled === true
  return {
    webSearch,
    incognito,
    injectMemory: incognito ? false : undefined,
    conversationId: incognito ? undefined : opts.conversationId || undefined,
    webSearchBlockedBy
  }
}
