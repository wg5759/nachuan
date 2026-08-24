import React, { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  agentChat,
  agentExec,
  agentInject,
  agentRunStream,
  undoFile,
  chatStream,
  createVideo,
  generateImage,
  isDurablePaidMediaAssetRef,
  paidVideoTerminalAssetUrl,
  paidVideoStatusValue,
  PAID_VIDEO_FAILURE_STATUSES,
  PAID_VIDEO_SUCCESS_STATUSES,
  pollVideo,
  transcribeAudio,
  translateText,
  lapianVideo,
  lapianUrl,
  studioPlan,
  studioExecute,
  studioJob,
  studioVideoBlobUrl,
  videoBlobUrl,
  startDailyVideo,
  queryKb,
  classifyIntent,
  webRead,
  awaitVideo,
  discardPendingPaidMediaOperation,
  PaidMediaRequestError,
  type ChatContentPart,
  type ChatMsg,
  type AgentEvent,
  type PaidMediaDeliveryProof,
  type PendingVideo,
  type StudioPlan
} from '../api'
import {
  nativeExecBackendForModel,
  flushAndVerifyPaidMediaResult,
  flushAppStorePersistence,
  useAppStore,
  type ChatDisplayMsg as DisplayMsg,
  type TokenUsage
} from '../store'
import { isFleetModelId } from './ModelSelector'
import {
  agentOutcomeLabelZh,
  concreteAgentModel,
  initialChatTurnMode
} from './chat-turn-routing'
import {
  createPaidVideoSubmissionGate,
  patchPaidMediaMessage,
  patchPaidMediaMessageAndFlush,
  type PaidMediaMessageTarget
} from './chat-pane-paid-media-routing'
import {
  prepareCreativeComposerSubmission,
  type CreativeComposerRequest
} from '../creative-composer-bridge'
import { PaidMediaRecoveryCard } from './PaidMediaRecoveryCard'
import { MAX_PENDING_IMAGES, isTextAttachmentFile, planPickedFiles } from '../utils/attachments'
import type { RuntimeCapabilityManifest, RuntimeKind } from '../../../runtime-capabilities'
import {
  isActionTask,
  isDailyVideoWorkflow,
  isImageRequest,
  isVideoRequest,
  VIDEO_URL,
  isLapianRequest,
  isStudioRequest,
  isStudioConfirm,
  isTranslateRequest,
  parseTranslate,
  isKbRequest,
  isWebReadRequest,
  extractUrl,
  ANY_URL
} from '../utils/intent'

// 显示消息类型现来自 store（按对话持久化）；这里给一个稳定的空数组常量，避免无谓重渲染
const EMPTY_MSGS: DisplayMsg[] = []

// 简易行级 diff 统计（多重集交集）：给内联动作卡显示 +增/-删
function diffStat(before: string, after: string): { add: number; del: number } {
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

// 「大脑说了算」：主栏只有一个「大脑」选择，就两种用法——
//   ① 选「纳川·智脑/Ultra」= 让所有模型智能路由、配合干活（编排：分诊/点将/动手/验证）；
//   ② 选某个具体模型 = 单独用它。没有别的模式/选项，力求最简。
// 「超级助手」(记忆/案例/反思) 已做成底层通用——任何对话默认带记忆，不再作为可选模式。
// 意图识别正则全部抽到 ../utils/intent（可单测，见 utils/intent.test.ts，#22）；
// 舰队路径彻底不用正则——该不该动手/生图/生视频/拉片全由舰队用工具自决，正则仅留给"单独用某个模型"的默认路径。

// 超级体路由标签 → 中文（case_reuse=复用强模型解法、teacher=强模型解、cheap=免费模型）
const routeLabelZh = (label: string): string =>
  ({ case_reuse: '复用案例', teacher: '强模型解', cheap: '免费模型' })[label] ?? label

// ── 文档附件（超长文 → 文档卡）──────────────────────────────────────────────
// 粘贴/输入超过这么多字符，就当成「一份文档」而不是一句话：转成文档附件，不在输入框/气泡里铺一墙字。
const DOC_THRESHOLD = 2000
type PendingDoc = { name: string; content: string }
// dataUrl：添加时后台算好（≤2MB 的图才算），草稿持久化用——重启后据此重建 File（机主要求：未发送的不丢）
type PendingImage = { name: string; url: string; file: File; dataUrl?: string }
// convId：排队消息属于入队时的对话——完成后只发回那个对话，绝不窜进新开的窗口
type QueuedMessage = { text: string; docs?: PendingDoc[]; images?: PendingImage[]; convId?: string }
const DAILY_VIDEO_ROOT = 'D:\\AI视频制作'
// 目标工作目录已改为「每对话独立」存在 conversation.workdir 里（不再用全局 localStorage）。
const APP_CAPABILITY_SYSTEM: ChatMsg = {
  role: 'system',
  content: [
    '你运行在“纳川”桌面应用中，不是孤立网页模型。',
    '普通聊天只负责回答；需要读写本地文件、运行命令、调用其它模型时，应使用“动手执行/执行代理”路线。',
    '执行代理提供受工作区约束的 list_dir/read_file/write_file 与 list_models/ask_model 等工具；宿主命令在独立低权限执行器接入前保持关闭。',
    '纳川有长期记忆、知识库检索和上下文压缩；压缩只处理旧工具输出/冗余上下文，不改变用户当前指令。',
    '不要直接声称“无法访问本地文件/无法调用其它模型”；应说明当前路线能否通过纳川工具完成。'
  ].join('\n')
}
// 文本类文件（点 ＋ 选文件时，这些后缀/类型按文档处理；图片/视频仍走看图/拉片）
const isTextFile = isTextAttachmentFile
// 给粘贴的长文起个名字：取首行前 16 字做标题，没有就叫「长文」
const pastedDocName = (text: string): string => {
  const head = text.trim().split('\n')[0]?.slice(0, 16).trim()
  return `${head || '长文'}.md`
}
// 文档附件 → 喂给模型的上下文块（带文件名与分隔，模型能据实引用）
function docsToContext(docs: { name: string; content: string }[]): string {
  return docs.map((d) => `【附件文档：${d.name}】\n${d.content}`).join('\n\n')
}
// 一条消息真正喂给模型的文字 = 文档附件展开 + 正文（历史轮次也据此重新带上文档，问下一句不丢上下文）
function msgToModelText(m: DisplayMsg): string {
  if (m.docs?.length) {
    const ctx = docsToContext(m.docs)
    return m.content ? `${ctx}\n\n${m.content}` : ctx
  }
  return m.content
}

// 图片不持久化，但在当前桌面会话内要保留结构化 image_url：同轮上传图、上一轮 AI 生图
// 才能被纳川 agent 的 staged_images 找到。只给“最近一组图”，避免旧图混进本轮 keyframes。
function displayImageUrls(m: DisplayMsg): string[] {
  const urls = (m.images ?? []).filter(
    (url) => url.startsWith('data:image/') || url.startsWith('http://') || url.startsWith('https://')
  )
  const markdown = [...m.content.matchAll(/!\[[^\]]*\]\((https?:\/\/[^)\s]+)\)/g)].map((x) => x[1])
  return [...new Set([...urls, ...markdown].filter((url): url is string => Boolean(url)))]
}

function messagesToAgentHistory(messages: DisplayMsg[]): ChatMsg[] {
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
  // 后台任务上下文衔接（机主定案）：插队/继续聊时，正在跑的生视频任务必须"在场"——
  // 用户此刻发消息多半是对它的补充/修改/询问，模型不知道任务存在就会无头接话。
  // 注入一条说明（含任务内容+进行中状态+能改什么不能改什么），让模型接得上。
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

function latestDisplayImages(messages: DisplayMsg[]): string[] {
  for (let i = messages.length - 1; i >= 0; i--) {
    const urls = displayImageUrls(messages[i])
    if (urls.length) return urls
  }
  return []
}

// 舰队号判定 isFleetModelId + 选单显示名 modelLabel 已抽到 ./ModelSelector（选择器移进顶栏后两处共用）。

// 舰队流式正文形如：开头若干「进度行」（⚙ 路由 / ⚙ 点将#1 / 💭 … / 　· … / 🔍 审核 / ⬆ 升级），
// 空行后接正文。把开头连续的进度行剥出来渲染成可折叠时间线，正文照常。
// 进度行判定：以 ⚙/💭/🔍/⬆ 开头，或以空白+「·」开头的缩进子项。
function isFleetProgressLine(line: string): boolean {
  return /^(⚙|💭|🔍|⬆)/.test(line) || /^\s+·/.test(line)
}

// 从舰队消息里分离「开头连续进度行」与正文。碰到第一条非进度、非空的行即为正文起点；
// 进度块与正文之间的空行吞掉。若一行进度都没有 → steps 为空、正文即原文（普通消息不受影响）。
function splitFleetProgress(content: string): { steps: string[]; body: string } {
  const lines = content.split('\n')
  const steps: string[] = []
  let i = 0
  while (i < lines.length) {
    const line = lines[i]
    if (isFleetProgressLine(line)) {
      steps.push(line)
      i += 1
    } else if (line.trim() === '' && steps.length > 0) {
      // 进度块内部/收尾的空行：跳过，不计入正文也不计入步骤
      i += 1
    } else {
      break
    }
  }
  if (steps.length === 0) return { steps: [], body: content }
  return { steps, body: lines.slice(i).join('\n') }
}

function readFileAsDataUrl(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onerror = () => reject(reader.error ?? new Error('read image failed'))
    reader.onload = () => resolve(String(reader.result || ''))
    reader.readAsDataURL(file)
  })
}

// 大图压缩后再发：原图 base64 直发（16宫格图动辄数MB）是三重毒——payload 过代理易触发
// TLS 记录损坏(DECRYPTION_FAILED_OR_BAD_RECORD_MAC，机主实测舰队直接炸)、视觉 token 爆炸、
// localStorage 配额吃紧。≤300KB 原样；更大则等比缩到最长边 1600px、JPEG 0.85（透明填白底）。
async function imageFileToDataUrl(file: File): Promise<string> {
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
    ctx.fillStyle = '#fff' // JPEG 无透明通道：白底
    ctx.fillRect(0, 0, w, h)
    ctx.drawImage(img, 0, 0, w, h)
    const out = canvas.toDataURL('image/jpeg', 0.85)
    return out.length < raw.length ? out : raw // 压完反而更大(罕见)就用原图
  } catch {
    return raw // 解码/画布失败 → 原图兜底，绝不因压缩丢图
  }
}

const usageValue = (usage: TokenUsage | undefined, key: keyof TokenUsage): number | undefined => {
  const n = Number(usage?.[key])
  return Number.isFinite(n) ? n : undefined
}

function hasTokenUsage(usage?: TokenUsage): boolean {
  return ['prompt_tokens', 'completion_tokens', 'total_tokens', 'cached_tokens'].some(
    (k) => usageValue(usage, k as keyof TokenUsage) !== undefined
  )
}

function formatTokenUsage(
  usage: TokenUsage | undefined,
  t: (key: string, opts?: Record<string, unknown>) => string
): string {
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

// 把图片/视频存到本地。走主进程保存（原生「另存为」对话框）：渲染层 fetch(https/blob)
// 会被 CSP connect-src 拦死→旧实现静默吞掉、点了毫无反应（机主实测「保存根本无效」的根因）。
// data:/blob: 在渲染层取字节传 bytes；https 传 url 让主进程 net.fetch 代下（无 CORS/CSP）。
async function downloadMedia(originalSrc: string, filename: string): Promise<void> {
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
          const bytes = await (await fetch(src)).arrayBuffer() // data:/blob: 本地取字节，CSP 已放行
          r = await window.api.saveMedia({ filename, bytes })
        }
        if (!r.ok && r.error !== 'canceled') window.alert(`保存失败：${r.error || '未知错误'}`)
        // A privileged main-process rejection is final.  Falling through to a
        // renderer fetch would bypass its SSRF/redirect/size policy if CSP is
        // relaxed in a future release.
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
      // 仅旧 preload 缺失时为本地 data/blob 保留锚点兜底；远程 URL 永不走此路径。
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

export function observePaidMediaNearViewport(
  target: Element,
  onVisibilityChange: (nearViewport: boolean) => void,
  Observer: typeof IntersectionObserver | undefined =
    typeof globalThis.IntersectionObserver === 'function'
      ? globalThis.IntersectionObserver
      : undefined
): () => void {
  if (!Observer) return () => {}
  const observer = new Observer(
    (entries) => {
      const entry = entries.find((candidate) => candidate.target === target)
      if (entry) onVisibilityChange(entry.isIntersecting)
    },
    { rootMargin: '512px 0px' }
  )
  observer.observe(target)
  return () => observer.disconnect()
}

function useResolvedMediaSource<T extends Element>(
  src: string | undefined
): [string | undefined, React.RefCallback<T>] {
  const durable = Boolean(src && isDurablePaidMediaAssetRef(src))
  const [resolved, setResolved] = useState<string | undefined>(durable ? undefined : src)
  const [target, setTargetElement] = useState<T | null>(null)
  const setTarget = useCallback((node: T | null) => setTargetElement(node), [])
  useEffect(() => {
    setResolved(durable ? undefined : src)
    if (
      !src ||
      !durable ||
      !target ||
      !window.api?.resolvePaidMediaAsset
    ) {
      return
    }
    let disposed = false
    let nearViewport = false
    let owned = false
    let requestGeneration = 0
    const release = (): void => {
      if (owned) {
        window.api?.releasePaidMediaAsset?.(src)
        owned = false
      }
    }
    const stopObserving = observePaidMediaNearViewport(
      target,
      (isNearViewport) => {
        if (isNearViewport === nearViewport) return
        nearViewport = isNearViewport
        requestGeneration += 1
        const generation = requestGeneration
        if (!nearViewport) {
          setResolved(undefined)
          release()
          return
        }
        void window.api
          ?.resolvePaidMediaAsset?.(src)
          .then((url) => {
            owned = true
            if (disposed || !nearViewport || generation !== requestGeneration) {
              release()
              return
            }
            setResolved(url)
          })
          .catch(() => {
            // Keep the durable reference in state for later retry/reload; never expose it as src.
          })
      }
    )
    return () => {
      disposed = true
      requestGeneration += 1
      stopObserving()
      release()
    }
  }, [durable, src, target])
  return [resolved, setTarget]
}

function ResolvedPaidMediaImage(props: React.ImgHTMLAttributes<HTMLImageElement>): React.JSX.Element {
  const [resolved, setTarget] = useResolvedMediaSource<HTMLImageElement>(
    typeof props.src === 'string' ? props.src : undefined
  )
  return <img {...props} ref={setTarget} src={resolved} loading={props.loading ?? 'lazy'} />
}

function ResolvedPaidMediaVideo(props: React.VideoHTMLAttributes<HTMLVideoElement>): React.JSX.Element {
  const [resolved, setTarget] = useResolvedMediaSource<HTMLVideoElement>(
    typeof props.src === 'string' ? props.src : undefined
  )
  return <video {...props} ref={setTarget} src={resolved} preload={props.preload ?? 'metadata'} />
}

function formatElapsed(start?: number, end?: number): string {
  if (!start) return ''
  const ms = Math.max(0, (end ?? Date.now()) - start)
  const sec = Math.round(ms / 1000)
  if (sec < 60) return `${sec}s`
  const min = Math.floor(sec / 60)
  const rest = sec % 60
  return `${min}m ${rest}s`
}

// 单行截断（时间线里 verdict/plan 可能很长，别撑爆 UI；整行 title 保留全文可悬停看）。
const clip = (s: unknown, n = 160): string =>
  String(s ?? '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, n)

// 把编排器的一个进度事件渲染成时间线里的一行（i18n）。返回 null 表示这类事件不单独成行。
type TFn = (key: string, opts?: Record<string, unknown>) => string
function agentEventLine(ev: AgentEvent, t: TFn): string | null {
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
      return (ev.verified ? t('chat.agVerifyPass') : t('chat.agVerifyFail')) +
        (ev.verdict ? ` — ${clip(ev.verdict, 160)}` : '')
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

// 消息里的「文档卡」：紧凑显示文件名+字数，可展开预览全文、下载成 .md
function DocCard({ doc }: { doc: { name: string; chars: number; content: string } }): React.ReactNode {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const download = (): void => {
    const blob = new Blob([doc.content], { type: 'text/markdown;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = /\.(md|markdown|txt)$/i.test(doc.name) ? doc.name : `${doc.name}.md`
    a.click()
    setTimeout(() => URL.revokeObjectURL(url), 1000)
  }
  return (
    <div className="inline-block text-left border border-neutral-700 rounded-md bg-neutral-900 max-w-[85%] overflow-hidden align-top">
      <div className="flex items-center gap-2 px-2 py-1 text-xs">
        <span className="text-base leading-none">📄</span>
        <span className="text-neutral-200 truncate max-w-[160px]">{doc.name}</span>
        <span className="text-neutral-500 shrink-0">{t('chat.docChars', { n: doc.chars })}</span>
        <button
          onClick={() => setOpen((v) => !v)}
          className="ml-1 text-neutral-400 hover:text-neutral-100 shrink-0"
        >
          {open ? t('chat.docCollapse') : t('chat.docPreview')}
        </button>
        <button onClick={download} className="text-neutral-400 hover:text-neutral-100 shrink-0">
          {t('chat.docDownload')}
        </button>
      </div>
      {open && (
        <div className="max-h-60 overflow-auto px-2 py-1 border-t border-neutral-800 text-xs text-neutral-300 whitespace-pre-wrap select-text">
          {doc.content}
        </div>
      )}
    </div>
  )
}

type ExecPermissionMode = 'plan' | 'auto' | 'full' | 'custom'
type ReasoningLevel = 'low' | 'medium' | 'high'

// 步数=安全天花板，不是"到点就收尾"。纳川的 agent 本来就会在"模型给出最终答案"时自然停，
// 加上循环/停滞检测挡打转——所以这里放宽，让复杂长任务能真正干到完成(像 Claude/Codex 那样)，
// 而不是到 24 就被砍断。真跑飞了有停滞检测兜底。
const maxStepsForReasoning = (level: ReasoningLevel): number =>
  level === 'high' ? 80 : level === 'medium' ? 50 : 30

const EXEC_PERMISSION_OPTIONS: {
  value: ExecPermissionMode
  label: string
  desc: string
}[] = [
  { value: 'plan', label: 'chat.perm_request', desc: 'chat.permdesc_request' },
  { value: 'auto', label: 'chat.perm_auto', desc: 'chat.permdesc_auto' },
  { value: 'full', label: 'chat.perm_full', desc: 'chat.permdesc_full' },
  { value: 'custom', label: 'chat.perm_custom', desc: 'chat.permdesc_custom' }
]

function PermissionIcon({ mode, className = '' }: { mode: ExecPermissionMode; className?: string }): React.ReactNode {
  const common = {
    width: 22,
    height: 22,
    viewBox: '0 0 24 24',
    fill: 'none',
    stroke: 'currentColor',
    strokeWidth: 1.8,
    strokeLinecap: 'round' as const,
    strokeLinejoin: 'round' as const,
    className
  }
  if (mode === 'plan') {
    return (
      <svg {...common}>
        <path d="M7 11.5V6.8a1.4 1.4 0 0 1 2.8 0v4.1" />
        <path d="M9.8 10.7V5.4a1.4 1.4 0 0 1 2.8 0v5.3" />
        <path d="M12.6 10.5V6.7a1.4 1.4 0 0 1 2.8 0v4.6" />
        <path d="M15.4 11.7V8.8a1.4 1.4 0 0 1 2.8 0v5.6c0 4.1-2.5 6.6-6.2 6.6h-.7c-2.2 0-3.7-.9-4.8-2.5L4.2 15a1.5 1.5 0 0 1 2.5-1.6L8 15.1" />
      </svg>
    )
  }
  if (mode === 'auto') {
    return (
      <svg {...common}>
        <path d="M12 3.2 19 6v5.3c0 4.3-2.7 7.7-7 9.5-4.3-1.8-7-5.2-7-9.5V6l7-2.8Z" />
        <path d="m8.8 12.1 2.1 2.1 4.4-4.6" />
      </svg>
    )
  }
  if (mode === 'full') {
    return (
      <svg {...common}>
        <path d="M12 3.2 19 6v5.3c0 4.3-2.7 7.7-7 9.5-4.3-1.8-7-5.2-7-9.5V6l7-2.8Z" />
        <path d="M12 7.8v5.1" />
        <path d="M12 16.3h.01" />
      </svg>
    )
  }
  return (
    <svg {...common}>
      <path d="M12 15.2a3.2 3.2 0 1 0 0-6.4 3.2 3.2 0 0 0 0 6.4Z" />
      <path d="M19.4 15a1.8 1.8 0 0 0 .4 2l.1.1a2.1 2.1 0 0 1-3 3l-.1-.1a1.8 1.8 0 0 0-2-.4 1.8 1.8 0 0 0-1.1 1.6v.2a2.1 2.1 0 0 1-4.2 0v-.2a1.8 1.8 0 0 0-1.1-1.6 1.8 1.8 0 0 0-2 .4l-.1.1a2.1 2.1 0 0 1-3-3l.1-.1a1.8 1.8 0 0 0 .4-2 1.8 1.8 0 0 0-1.6-1.1H2a2.1 2.1 0 0 1 0-4.2h.2a1.8 1.8 0 0 0 1.6-1.1 1.8 1.8 0 0 0-.4-2l-.1-.1a2.1 2.1 0 0 1 3-3l.1.1a1.8 1.8 0 0 0 2 .4h.1a1.8 1.8 0 0 0 1-1.6V2a2.1 2.1 0 0 1 4.2 0v.2a1.8 1.8 0 0 0 1.1 1.6 1.8 1.8 0 0 0 2-.4l.1-.1a2.1 2.1 0 0 1 3 3l-.1.1a1.8 1.8 0 0 0-.4 2v.1a1.8 1.8 0 0 0 1.6 1H22a2.1 2.1 0 0 1 0 4.2h-.2a1.8 1.8 0 0 0-1.6 1.1l-.8.2Z" />
    </svg>
  )
}

function ExecPermissionMenu({
  value,
  onChange
}: {
  value: ExecPermissionMode
  onChange: (v: ExecPermissionMode) => void
}): React.ReactNode {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    const onDown = (e: MouseEvent): void => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', onDown)
    return () => document.removeEventListener('mousedown', onDown)
  }, [open])

  const cur = EXEC_PERMISSION_OPTIONS.find((o) => o.value === value) ?? EXEC_PERMISSION_OPTIONS[1]
  const hot = value === 'full'

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        title={t('chat.execPerm')}
        onClick={() => setOpen((v) => !v)}
        className={`h-8 inline-flex items-center gap-1.5 rounded-md px-2 text-sm hover:bg-neutral-800 ${
          hot ? 'text-orange-400' : 'text-neutral-300'
        }`}
      >
        <PermissionIcon mode={value} className="shrink-0" />
        <span className="max-w-[9rem] truncate">{t(cur.label)}</span>
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="shrink-0 opacity-70">
          <path d="m6 9 6 6 6-6" />
        </svg>
      </button>

      {open && (
        <div className="absolute left-0 bottom-full z-50 mb-2 w-[min(430px,calc(100vw-40px))] rounded-2xl border border-neutral-700 bg-neutral-950/95 py-2 shadow-2xl backdrop-blur">
          {EXEC_PERMISSION_OPTIONS.map((o) => {
            const selected = o.value === value
            return (
              <button
                key={o.value}
                type="button"
                onClick={() => {
                  onChange(o.value)
                  setOpen(false)
                }}
                className={`flex w-full items-center gap-4 px-5 py-3 text-left transition-colors ${
                  selected ? 'bg-neutral-800/80' : 'hover:bg-neutral-900'
                }`}
              >
                <PermissionIcon mode={o.value} className="shrink-0 text-neutral-400" />
                <span className="min-w-0 flex-1">
                  <span className="block text-base leading-6 text-neutral-100">{t(o.label)}</span>
                  <span className="block text-sm leading-5 text-neutral-500">{t(o.desc)}</span>
                </span>
                {selected && (
                  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" className="shrink-0 text-neutral-200">
                    <path d="m20 6-11 11-5-5" />
                  </svg>
                )}
              </button>
            )
          })}
        </div>
      )}
    </div>
  )
}

function ComposerIcon({
  type,
  className = ''
}: {
  type: 'plus' | 'file' | 'target' | 'plan' | 'x'
  className?: string
}): React.ReactNode {
  const common = {
    width: 20,
    height: 20,
    viewBox: '0 0 24 24',
    fill: 'none',
    stroke: 'currentColor',
    strokeWidth: 1.8,
    strokeLinecap: 'round' as const,
    strokeLinejoin: 'round' as const,
    className
  }
  if (type === 'file') {
    return (
      <svg {...common}>
        <path d="M14 2H7a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V7Z" />
        <path d="M14 2v5h5" />
        <path d="M9 13h6" />
        <path d="M9 17h4" />
      </svg>
    )
  }
  if (type === 'target') {
    return (
      <svg {...common}>
        <circle cx="12" cy="12" r="8" />
        <circle cx="12" cy="12" r="3" />
        <path d="M12 2v3" />
        <path d="M12 19v3" />
        <path d="M2 12h3" />
        <path d="M19 12h3" />
      </svg>
    )
  }
  if (type === 'plan') {
    return (
      <svg {...common}>
        <path d="M8 6h13" />
        <path d="M8 12h13" />
        <path d="M8 18h13" />
        <path d="m3 6 .6.6L5 5.2" />
        <path d="m3 12 .6.6L5 11.2" />
        <path d="m3 18 .6.6L5 17.2" />
      </svg>
    )
  }
  if (type === 'x') {
    return (
      <svg {...common}>
        <path d="M18 6 6 18" />
        <path d="m6 6 12 12" />
      </svg>
    )
  }
  return (
    <svg {...common}>
      <path d="M12 5v14" />
      <path d="M5 12h14" />
    </svg>
  )
}

export function ComposerAttachmentRow({
  runtimeKind,
  runtimeCapabilities,
  onPickFile,
  onPickFolder
}: {
  runtimeKind: RuntimeKind
  runtimeCapabilities: RuntimeCapabilityManifest
  onPickFile: () => void
  onPickFolder: () => void
}): React.JSX.Element {
  const { t } = useTranslation()
  const surface = runtimeKind === 'electron' ? 'electron' : 'localWeb'
  const directorySupport =
    runtimeCapabilities.capabilities.directoryPicker.surfaces[surface].declaredSupport
  const canPickDirectory =
    directorySupport === 'implemented' || directorySupport === 'implemented-with-preconditions'

  return (
    <div className="flex px-1.5">
      <button
        type="button"
        onClick={onPickFile}
        className="flex min-w-0 flex-1 items-center gap-3 rounded-lg px-3 py-2.5 text-left hover:bg-neutral-900"
      >
        <ComposerIcon type="file" className="shrink-0 text-neutral-400" />
        <span className="min-w-0 flex-1 truncate text-sm text-neutral-100">{t('chat.addFile')}</span>
      </button>
      {canPickDirectory && (
        <button
          type="button"
          onClick={onPickFolder}
          className="ml-1 rounded-lg border border-neutral-800 px-2 text-xs text-neutral-300 hover:bg-neutral-900"
        >
          {t('chat.addFolder')}
        </button>
      )}
    </div>
  )
}

function ComposerMenu({
  runtimeKind,
  runtimeCapabilities,
  target,
  onPickFile,
  onPickFolder,
  onTargetChange,
  onPlanMode
}: {
  runtimeKind: RuntimeKind
  runtimeCapabilities: RuntimeCapabilityManifest
  target: string
  onPickFile: () => void
  onPickFolder: () => void
  onTargetChange: (target: string) => void
  onPlanMode: () => void
}): React.ReactNode {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const [targetOpen, setTargetOpen] = useState(false)
  const [draft, setDraft] = useState(target)
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => setDraft(target), [target])
  useEffect(() => {
    if (!open) return
    const onDown = (e: MouseEvent): void => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', onDown)
    return () => document.removeEventListener('mousedown', onDown)
  }, [open])

  const applyTarget = (): void => {
    onTargetChange(draft.trim())
    setTargetOpen(false)
  }

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        title={t('chat.addMenu')}
        className="h-8 w-8 shrink-0 flex items-center justify-center rounded-md text-neutral-400 hover:bg-neutral-800 disabled:opacity-40"
      >
        <ComposerIcon type="plus" />
      </button>
      {open && (
        <div className="absolute left-0 bottom-full z-50 mb-2 w-[min(360px,calc(100vw-40px))] rounded-xl border border-neutral-700 bg-neutral-950/95 py-1.5 shadow-2xl backdrop-blur">
          <ComposerAttachmentRow
            runtimeKind={runtimeKind}
            runtimeCapabilities={runtimeCapabilities}
            onPickFile={() => {
              onPickFile()
              setOpen(false)
            }}
            onPickFolder={() => {
              onPickFolder()
              setOpen(false)
            }}
          />
          <button
            type="button"
            onClick={() => setTargetOpen((v) => !v)}
            className="flex w-full items-center gap-3 px-4 py-2.5 text-left hover:bg-neutral-900"
          >
            <ComposerIcon type="target" className="shrink-0 text-neutral-400" />
            <span className="min-w-0 flex-1">
              <span className="block truncate text-sm text-neutral-100">{t('chat.target')}</span>
              {target && <span className="block truncate text-xs text-neutral-500">{target}</span>}
            </span>
          </button>
          {targetOpen && (
            <div className="px-4 pb-2">
              <div className="flex gap-1">
                <input
                  value={draft}
                  onChange={(e) => setDraft(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') applyTarget()
                    if (e.key === 'Escape') setTargetOpen(false)
                  }}
                  placeholder={t('chat.targetPlaceholder')}
                  className="min-w-0 flex-1 rounded-md border border-neutral-700 bg-neutral-900 px-2 py-1 text-xs text-neutral-100 outline-none"
                />
                <button
                  type="button"
                  onClick={applyTarget}
                  className="rounded-md bg-blue-600 px-2 text-xs text-white hover:bg-blue-500"
                >
                  {t('chat.apply')}
                </button>
              </div>
            </div>
          )}
          <button
            type="button"
            onClick={() => {
              onPlanMode()
              setOpen(false)
            }}
            className="flex w-full items-center gap-3 px-4 py-2.5 text-left hover:bg-neutral-900"
          >
            <ComposerIcon type="plan" className="shrink-0 text-neutral-400" />
            <span className="min-w-0 flex-1 truncate text-sm text-neutral-100">{t('chat.planMode')}</span>
          </button>
        </div>
      )}
    </div>
  )
}

export interface ChatPaneProps {
  creativeRequest?: CreativeComposerRequest | null
  onCreativeRequestHandled?: (requestId: number, error?: string) => void
}

export default function ChatPane({
  creativeRequest = null,
  onCreativeRequestHandled
}: ChatPaneProps = {}): React.ReactNode {
  const { t } = useTranslation()
  const models = useAppStore((s) => s.models)
  const currentModel = useAppStore((s) => s.currentModel)
  const engineStatus = useAppStore((s) => s.status) // 视频重启恢复：等引擎在线再代下
  const setAgentBusy = useAppStore((s) => s.setAgentBusy)
  const setLastAgentReply = useAppStore((s) => s.setLastAgentReply)
  const openBrowser = useAppStore((s) => s.openBrowser)
  // 消息按「当前对话」存在 store 里（多对话 + 持久化）。setMessages 保持同样的签名（数组或更新函数），
  // 所以下面所有 setMessages(...) 调用都无需改动。
  const messages = useAppStore((s) => {
    const c = s.conversations.find((x) => x.id === s.currentConvId)
    return c?.messages ?? EMPTY_MSGS
  })
  const setMessages = useAppStore((s) => s.setCurrentMessages)
  // 异步回写专用：写回**发起时的对话**——任务跑着时切对话，结果绝不能跟着 currentConvId 串台（codex 审）
  const setConvMessages = useAppStore((s) => s.setConvMessages)
  const ensureConversation = useAppStore((s) => s.ensureConversation)
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const [paidVideoSubmissionInFlight, setPaidVideoSubmissionInFlight] = useState(false)
  const paidVideoSubmissionGateRef = useRef<ReturnType<typeof createPaidVideoSubmissionGate> | null>(
    null
  )
  const paidVideoSubmissionGate =
    paidVideoSubmissionGateRef.current ??
    createPaidVideoSubmissionGate(setPaidVideoSubmissionInFlight)
  paidVideoSubmissionGateRef.current = paidVideoSubmissionGate
  const [recording, setRecording] = useState(false)
  const [transcribing, setTranscribing] = useState(false)
  const [micLevel, setMicLevel] = useState(0)
  const [reasoningLevel, setReasoningLevel] = useState<ReasoningLevel>('medium')
  const [execMode, setExecMode] = useState<ExecPermissionMode>('auto')
  const [pendingEdits, setPendingEdits] = useState<{ text: string; removed: DisplayMsg[] }[]>([])
  const [stackExpanded, setStackExpanded] = useState(false)
  const [queued, setQueued] = useState<QueuedMessage[]>([]) // 生成时排队的消息，完成后自动发
  const [pendingImages, setPendingImages] = useState<PendingImage[]>([]) // 待发图片（截图/多图选择），发送时一次性喂给视觉模型
  const [pendingDocs, setPendingDocs] = useState<PendingDoc[]>([]) // 待发的文档附件（超长文/文本文件）
  const [pendingStudioPlan, setPendingStudioPlan] = useState<StudioPlan | null>(null) // 视频工作室：等用户确认的分镜方案
  const [recoveringPaidMedia, setRecoveringPaidMedia] = useState<string | null>(null)
  const handledCreativeRequestRef = useRef<number | null>(null)
  // 目标工作目录：**每个对话独立**（机主实测根因#1：以前存全局 localStorage → 新对话残留上个的）。
  // 从当前对话的 workdir 读；切换/新建对话时自动跟随（下方 effect）。
  const convWorkdir = useAppStore((s) => {
    const c = s.conversations.find((x) => x.id === s.currentConvId)
    return c?.workdir ?? ''
  })
  const setConvWorkdir = useAppStore((s) => s.setConvWorkdir)
  const currentConvId = useAppStore((s) => s.currentConvId)
  const [workTarget, setWorkTarget] = useState(convWorkdir)
  // 切换对话 → 目标路径跟着切到那个对话自己的（新对话=空，不再带上一个）
  useEffect(() => {
    setWorkTarget(convWorkdir)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [currentConvId])

  // ── 输入框草稿随对话持久化（机主要求：没发送的文字/文档/图片，重启/切换回来还在原处）──
  const setConvDraft = useAppStore((s) => s.setConvDraft)
  const draftValsRef = useRef({ input: '', docs: [] as PendingDoc[], images: [] as PendingImage[] })
  draftValsRef.current = { input, docs: pendingDocs, images: pendingImages }
  // 组草稿（带预算：图片 dataUrl 总量 ≤2.5MB、文档 ≤500KB，超出仅会话内保留不进草稿）；全空 → undefined 清掉
  const buildDraft = (): NonNullable<Parameters<typeof setConvDraft>[1]> | undefined => {
    const { input: text, docs, images } = draftValsRef.current
    let imgBudget = 2_500_000
    const imgs: { name: string; dataUrl: string }[] = []
    for (const im of images) {
      if (im.dataUrl && imgBudget - im.dataUrl.length > 0) {
        imgBudget -= im.dataUrl.length
        imgs.push({ name: im.name, dataUrl: im.dataUrl })
      }
    }
    let docBudget = 500_000
    const ds: PendingDoc[] = []
    for (const d of docs) {
      if (docBudget - d.content.length > 0) {
        docBudget -= d.content.length
        ds.push(d)
      }
    }
    if (!text.trim() && !imgs.length && !ds.length) return undefined
    return { text: text || undefined, docs: ds.length ? ds : undefined, images: imgs.length ? imgs : undefined }
  }
  // 切换对话：先把上一个对话的草稿**立即**落库（不等防抖），再恢复新对话的草稿
  const prevConvRef = useRef<string | null>(null)
  useEffect(() => {
    const prev = prevConvRef.current
    if (prev && prev !== currentConvId) setConvDraft(prev, buildDraft())
    prevConvRef.current = currentConvId
    // 旧待发图的 blob 预览地址不再用了（恢复走 dataUrl），释放防泄漏；flush 只用 dataUrl，不受影响
    for (const p of draftValsRef.current.images) if (p.url.startsWith('blob:') && p.dataUrl) URL.revokeObjectURL(p.url)
    const d = useAppStore.getState().conversations.find((c) => c.id === currentConvId)?.draft
    setInput(d?.text ?? '')
    setPendingDocs(d?.docs ?? [])
    setPendingImages([])
    // 撤回编辑栏是"当下"操作，跨对话残留会带 autoFocus 抢焦点/让新对话看着像卡住 → 切对话即清
    setPendingEdits([])
    setStackExpanded(false)
    const cid = currentConvId
    if (d?.images?.length) {
      // 图片草稿：dataUrl → 重建 File（发送路径要 File）；预览直接用 dataUrl。异步完成时校验没切走。
      void Promise.all(
        d.images.map(async (im) => {
          const blob = await (await fetch(im.dataUrl)).blob()
          return { name: im.name, file: new File([blob], im.name, { type: blob.type }), url: im.dataUrl, dataUrl: im.dataUrl }
        })
      )
        .then((items) => {
          if (useAppStore.getState().currentConvId === cid) setPendingImages(items)
        })
        .catch(() => {})
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [currentConvId])
  // 输入/附件变化 → 600ms 防抖写草稿（发送后清空也随之写空，重启不会又冒出来）
  useEffect(() => {
    if (!currentConvId) return
    const id = window.setTimeout(() => setConvDraft(currentConvId, buildDraft()), 600)
    return () => window.clearTimeout(id)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [input, pendingDocs, pendingImages, currentConvId])
  // 直接关 app（没切对话、防抖没到）：退出瞬间立即落草稿；store 落盘兜在 pagehide（更晚），顺序有保证
  useEffect(() => {
    const onUnload = (): void => {
      if (currentConvId) setConvDraft(currentConvId, buildDraft())
    }
    window.addEventListener('beforeunload', onUnload)
    return () => window.removeEventListener('beforeunload', onUnload)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [currentConvId])
  // 计时器每秒 tick（机主实测根因#4：formatElapsed 只在重渲染时算，没事件进来就冻住）。
  // busy 期间每秒 forceTick → "已运行 Xs" 真正走起来；完成后停。
  const [, forceTick] = useState(0)
  const inputRef = useRef<HTMLTextAreaElement>(null)
  // 输入框随文字自动增高（min ~2 行，max ~240px，超了内部滚动）
  useEffect(() => {
    const ta = inputRef.current
    if (!ta) return
    ta.style.height = 'auto'
    // 机主实测：输入区太高挤占聊天窗——min 收到 36、max 收到 160（超出内部滚动）
    ta.style.height = `${Math.min(Math.max(ta.scrollHeight, 36), 160)}px`
  }, [input])
  // 目标路径写回**当前对话**（每对话独立记忆，随对话持久化）。
  useEffect(() => {
    if (currentConvId) setConvWorkdir(currentConvId, workTarget.trim())
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [workTarget])
  // busy 期间每秒 tick，驱动"已运行"计时器真正走秒。
  useEffect(() => {
    if (!busy) return
    const id = window.setInterval(() => forceTick((n) => n + 1), 1000)
    return () => window.clearInterval(id)
  }, [busy])
  const scrollRef = useRef<HTMLDivElement>(null)
  const drainingRef = useRef(false)
  const lastInjectRef = useRef<{ text: string; at: number } | null>(null) // 插话去重（10s 内同文只注入一次）
  const abortRef = useRef<AbortController | null>(null) // 当前生成的中止器（撤回时打断模型）
  const recRef = useRef<MediaRecorder | null>(null)
  const chunksRef = useRef<Blob[]>([])
  const audioCtxRef = useRef<AudioContext | null>(null)
  const micRafRef = useRef<number | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)

  // 每次消息变化都滚到底——你发的最后一条始终在最底部
  useEffect(() => {
    const el = scrollRef.current
    if (el) el.scrollTo({ top: el.scrollHeight })
  }, [messages])

  // 完成提示音：Web Audio 现合成一段柔和「叮—咚」（两声下行三度），零文件零依赖。
  const soundEnabled = useAppStore((s) => s.soundEnabled)
  const playDone = (): void => {
    try {
      const Ctx = window.AudioContext || (window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext
      if (!Ctx) return
      const ctx = new Ctx()
      const now = ctx.currentTime
      // 两个音符：G5(784) → E5(659)，正弦波 + 渐弱包络，温和不刺耳
      ;[
        { f: 784, t: 0 },
        { f: 659, t: 0.16 }
      ].forEach(({ f, t }) => {
        const osc = ctx.createOscillator()
        const gain = ctx.createGain()
        osc.type = 'sine'
        osc.frequency.value = f
        gain.gain.setValueAtTime(0.0001, now + t)
        gain.gain.exponentialRampToValueAtTime(0.16, now + t + 0.02) // 快起
        gain.gain.exponentialRampToValueAtTime(0.0001, now + t + 0.32) // 慢落
        osc.connect(gain).connect(ctx.destination)
        osc.start(now + t)
        osc.stop(now + t + 0.34)
      })
      setTimeout(() => void ctx.close().catch(() => {}), 800)
    } catch {
      /* 音频不可用就静默，绝不影响功能 */
    }
  }
  // busy true→false 跃迁 = 一轮生成/任务真正结束 → 响一声（一处统一，覆盖聊天/agent/图/短视频所有路径）
  const prevBusyRef = useRef(false)
  useEffect(() => {
    if (prevBusyRef.current && !busy && soundEnabled) playDone()
    prevBusyRef.current = busy
  }, [busy, soundEnabled])

  // 重启后恢复视频：持久化只留了 videoSrc(原始源)、blob 已失效 → 据源经引擎再代下成可播放 blob。
  // 要引擎在线才代下；用 Map 记每个源的状态(-1=进行中 / 99=成功 / 0..2=失败次数)避免无限重试；
  // resolve 时校验仍在同一对话——否则撤销未挂上的 blob 防泄漏、并重置以便切回再试；连败 3 次写一句提示。
  const [hydrateTick, setHydrateTick] = useState(0) // 失败后主动排重试用(codex 审：否则依赖不变 effect 不再跑)
  const videoHydrateRef = useRef<Map<string, number>>(new Map())
  useEffect(() => {
    const convId = currentConvId
    messages.forEach((m) => {
      if (!m.videoSrc || m.video) return
      const src = m.videoSrc
      if (isDurablePaidMediaAssetRef(src)) {
        videoHydrateRef.current.set(src, 99)
        setMessages((prev) =>
          prev.map((x) => (x.videoSrc === src && !x.video ? { ...x, video: src } : x))
        )
        return
      }
      if (engineStatus !== 'online') return
      const tries = videoHydrateRef.current.get(src) ?? 0
      if (tries < 0 || tries >= 3 || tries === 99) return // 进行中 / 放弃 / 已成功
      videoHydrateRef.current.set(src, -1)
      const p = src.startsWith('studio:')
        ? studioVideoBlobUrl(src.slice('studio:'.length))
        : videoBlobUrl(src)
      void p
        .then((blob) => {
          if (useAppStore.getState().currentConvId !== convId) {
            URL.revokeObjectURL(blob) // 已切走：撤销未挂上的 blob 防泄漏，重置以便切回重试
            videoHydrateRef.current.set(src, tries)
            return
          }
          videoHydrateRef.current.set(src, 99)
          setMessages((prev) => prev.map((x) => (x.videoSrc === src && !x.video ? { ...x, video: blob } : x)))
        })
        .catch(() => {
          const n = tries + 1
          videoHydrateRef.current.set(src, n)
          if (n >= 3) {
            if (useAppStore.getState().currentConvId === convId) {
              setMessages((prev) =>
                prev.map((x) => (x.videoSrc === src && !x.video && !x.content ? { ...x, content: t('chat.videoTimeout') } : x))
              )
            }
          } else {
            setTimeout(() => setHydrateTick((x) => x + 1), 4000) // 主动排下一次重试
          }
        })
    })
  }, [messages, engineStatus, currentConvId, hydrateTick]) // eslint-disable-line react-hooks/exhaustive-deps

  // 断点续传 + 幽灵计时定格（机主实测：重启后秒数还在走、分不清真假）：
  // ① 有 videoTask 没成片的消息 = 重启前进行中的云端生视频 → 引擎在线后**自动**接上轮询（不用说"继续"），
  //    成片照常自动贴回；② 其它「有 startedAt 没 completedAt」的遗留消息 = 被重启打断的生成 → 定格计时，
  //    别再显示"还在跑"（正在流式的最后一条除外）。
  const resumedTasksRef = useRef<Set<string>>(new Set())
  useEffect(() => {
    // ① 断点续传：有 videoTask 没成片的 → 引擎在线后自动接上轮询（去重防重复起）
    for (const m of messages) {
      if (m.videoTask && !m.video && engineStatus === 'online' && !resumedTasksRef.current.has(m.videoTask.task_id)) {
        resumedTasksRef.current.add(m.videoTask.task_id)
        void awaitAndAttachVideo(
          { task_id: m.videoTask.task_id, model: m.videoTask.model },
          m.ts,
          currentConvId ?? undefined // 锚点在当前对话的 messages 里，成片写回它
        )
      }
    }
    // ② 幽灵计时定格：**一次批量 patch + 无变化返回原引用**。绝不能逐条 map——引用失配时
    //   .map() 空转也会造新数组 → messages 变 → effect 重跑 → 死循环打满主线程（输入框都打不进字）。
    if (!busy && messages.some((m) => !m.videoTask && m.startedAt && !m.completedAt)) {
      const now = Date.now()
      setMessages((prev) => {
        let changed = false
        const next = prev.map((x) => {
          if (!x.videoTask && x.startedAt && !x.completedAt) {
            changed = true
            return { ...x, completedAt: now }
          }
          return x
        })
        return changed ? next : prev // 无变化返回原引用 → 不触发 effect 重跑，物理断循环
      })
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [messages, engineStatus, busy])

  useEffect(() => () => stopMicMeter(), []) // eslint-disable-line react-hooks/exhaustive-deps

  // 排队：当前生成完(空闲)后，把暂存的消息按顺序自动发出去。
  // 只发**属于当前对话**的排队消息——否则删除/打断后 busy 一解除，旧排队消息会窜进新开的对话
  //（机主实测：开新窗口就"忙起来/输入没反应"的元凶之一）；别的对话的留在队里，切回去再发。
  useEffect(() => {
    if (busy || drainingRef.current) return
    const idx = queued.findIndex((q) => !q.convId || q.convId === currentConvId)
    if (idx < 0) return
    drainingRef.current = true
    const next = queued[idx]
    setQueued((q) => q.filter((_, j) => j !== idx))
    void send(next.text, false, next.docs ?? [], next.images ?? []).finally(() => {
      drainingRef.current = false
    })
  }, [busy, queued, currentConvId]) // eslint-disable-line react-hooks/exhaustive-deps


  // 语音输入：点一下开录、再点停；停止时把整段录音（完整 webm）一次性转写。
  // 关键：不用 timeslice 分片——MediaRecorder 分片拼出来的 webm，ffmpeg 常无法解码
  // （正是之前 500「Invalid data」的根因）。不分片时 stop 会一次给出完整可解码的 webm。
  const stopMicMeter = (): void => {
    if (micRafRef.current !== null) {
      cancelAnimationFrame(micRafRef.current)
      micRafRef.current = null
    }
    void audioCtxRef.current?.close().catch(() => {})
    audioCtxRef.current = null
    setMicLevel(0)
  }

  const startMicMeter = (stream: MediaStream): void => {
    stopMicMeter()
    const Ctx = window.AudioContext || (window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext
    if (!Ctx) return
    const ctx = new Ctx()
    const analyser = ctx.createAnalyser()
    analyser.fftSize = 256
    ctx.createMediaStreamSource(stream).connect(analyser)
    const data = new Uint8Array(analyser.frequencyBinCount)
    const tick = (): void => {
      analyser.getByteTimeDomainData(data)
      let sum = 0
      for (const v of data) {
        const d = v - 128
        sum += d * d
      }
      setMicLevel(Math.min(1, Math.sqrt(sum / data.length) / 42))
      micRafRef.current = requestAnimationFrame(tick)
    }
    audioCtxRef.current = ctx
    tick()
  }

  const toggleRecord = async (): Promise<void> => {
    if (recording) {
      recRef.current?.stop()
      return
    }
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true })
      const rec = new MediaRecorder(stream)
      chunksRef.current = []
      startMicMeter(stream)
      const baseText = input.trim() // 录音前已有的文字，转写结果追加在它后面
      rec.ondataavailable = (ev): void => {
        if (ev.data.size) chunksRef.current.push(ev.data)
      }
      rec.onstop = async (): Promise<void> => {
        stream.getTracks().forEach((tk) => tk.stop())
        stopMicMeter()
        setRecording(false)
        if (!chunksRef.current.length) return
        const blob = new Blob(chunksRef.current, { type: rec.mimeType || 'audio/webm' })
        setTranscribing(true)
        try {
          const text = await transcribeAudio(blob)
          if (text) setInput(baseText ? `${baseText} ${text}` : text)
        } catch (e) {
          setInput((prev) => `${prev}${t('chat.sttFail', { e: String(e) })}`)
        } finally {
          setTranscribing(false)
        }
      }
      recRef.current = rec
      rec.start() // 不分片：stop 时一次拿到完整录音再转写
      setRecording(true)
    } catch (e) {
      setInput((prev) => `${prev}${t('chat.micFail', { e: String(e) })}`)
    }
  }


  // F4 行内消息译：点某条消息的「译」→ 中⇄英互译，结果显示在该条下方（微信式）
  // 回退编辑：把这条「你发的」消息取回输入框，并移除它及其之后的内容，改完重发即可（撤回+修改一步到位）
  // 只有动到「正在生成的那一轮」（最后一组 user+assistant）才打断模型；
  // 删/撤历史消息不动当前任务（机主实测：删了条重复消息，正在跑的时间线被无辜杀掉）。
  const isActiveTurn = (i: number): boolean => busy && i >= messages.length - 2

  const retractMsg = (i: number): void => {
    const m = messages[i]
    if (!m || m.role !== 'user') return
    if (isActiveTurn(i)) {
      abortRef.current?.abort()
      setBusy(false)
      setAgentBusy(false)
    }
    // 入"回退栈"（多条堆叠、不互相淹没）；记下被移除内容，✕ 可还原全部
    setPendingEdits((prev) => [...prev, { text: m.content, removed: messages.slice(i) }])
    setMessages(messages.slice(0, i))
  }

  // 删除：直接移除这条用户消息及其回复（不进编辑栏，区别于"撤回"）；只打断自己那轮
  const deleteMsg = (i: number): void => {
    const m = messages[i]
    if (!m || m.role !== 'user') return
    if (isActiveTurn(i)) {
      abortRef.current?.abort()
      setBusy(false)
      setAgentBusy(false)
    }
    const next = messages[i + 1]?.role === 'assistant' ? i + 2 : i + 1
    setMessages([...messages.slice(0, i), ...messages.slice(next)])
  }

  // 📷 截图结果：右键菜单/快捷键 → 主进程浮层框选 → 推回 {dataUrl, action}
  //   paste=贴进输入备发 / ocr=提取文字 / translate=翻译；后两者走看图模型，结果作为消息回到对话
  const runSnipAction = async (dataUrl: string, action: string): Promise<void> => {
    // 现在只剩「嵌入对话」会回传到这里（提取文字/翻译已在浮层就地完成并可复制）
    if (action !== 'paste') return
    const blob = await (await fetch(dataUrl)).blob()
    const file = new File([blob], 'screenshot.png', { type: 'image/png' })
    addPendingImages([file])
  }
  // 订阅一次，用 ref 始终指向最新闭包（避免 busy/messages 过期）
  const snipRef = useRef(runSnipAction)
  snipRef.current = runSnipAction
  useEffect(() => window.api?.onSnipResult?.((d, a) => void snipRef.current(d, a)), [])

  // 复制整段消息文字到剪贴板 → 按钮短暂变「已复制✓」给反馈（机主实测：点了没动静）
  const [copiedIdx, setCopiedIdx] = useState<number | null>(null)
  const copiedTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const copyMsg = async (i: number): Promise<void> => {
    const c = messages[i]?.content
    if (!c) return
    try {
      await navigator.clipboard.writeText(c)
    } catch {
      // 极少数环境 clipboard API 不可用 → 兜底 execCommand
      const ta = document.createElement('textarea')
      ta.value = c
      ta.style.position = 'fixed'
      ta.style.opacity = '0'
      document.body.appendChild(ta)
      ta.select()
      try {
        document.execCommand('copy')
      } catch {
        /* 都失败就算了，不打断 */
      }
      ta.remove()
    }
    setCopiedIdx(i)
    if (copiedTimerRef.current) clearTimeout(copiedTimerRef.current)
    copiedTimerRef.current = setTimeout(() => setCopiedIdx(null), 1600)
  }

  // 内联动作卡：restore=true 撤销（把改前内容写回文件）；之后把卡片从该消息移除（审核=不撤销仅移除）
  const resolveAction = async (mi: number, ai: number, restore: boolean): Promise<void> => {
    const act = messages[mi]?.actions?.[ai]
    if (!act) return
    if (restore && act.undo_receipt) {
      try {
        await undoFile(act.undo_receipt, act.before)
      } catch {
        /* ignore */
      }
    }
    setMessages((prev) => {
      const copy = prev.slice()
      const m = copy[mi]
      if (m?.actions) copy[mi] = { ...m, actions: m.actions.filter((_, i) => i !== ai) }
      return copy
    })
  }

  const translateMsg = async (i: number): Promise<void> => {
    const m = messages[i]
    if (!m?.content) return
    const target = /[一-鿿]/.test(m.content) ? 'en' : 'zh'
    try {
      const out = await translateText(m.content, target)
      setMessages((prev) => {
        const c = prev.slice()
        c[i] = { ...c[i], translated: out }
        return c
      })
    } catch {
      /* 忽略 */
    }
  }

  // 加一份文档附件（超长文/文本文件）：进 pendingDocs，发送时再展开喂给模型
  const addPendingDoc = (name: string, content: string): void => {
    const c = content.replace(/\r\n/g, '\n').trim()
    if (!c) return
    setPendingDocs((prev) => [...prev, { name, content: c }])
  }

  const addPendingImages = (files: File[]): void => {
    const plan = planPickedFiles(files, pendingImages.length)
    if (plan.images.length) {
      const items = plan.images.map((file) => ({ name: file.name, file, url: URL.createObjectURL(file) }))
      setPendingImages((prev) => [...prev, ...items])
      // 后台补 dataUrl（草稿持久化用）：≤2MB 的图才算，太大的仅会话内保留（不进草稿）
      for (const it of items) {
        if (it.file.size > 2_000_000) continue
        void imageFileToDataUrl(it.file).then((dataUrl) =>
          setPendingImages((prev) => prev.map((p) => (p.url === it.url ? { ...p, dataUrl } : p)))
        )
      }
    }
    if (plan.overflowImages > 0) {
      setMessages((p) => [
        ...p,
        {
          role: 'assistant',
          content: t('chat.imageLimit', { n: MAX_PENDING_IMAGES, dropped: plan.overflowImages })
        }
      ])
    }
  }

  // ＋号附件：图片→待发多图；文本文档→转文档附件；视频→拉片报告（视频仍是立即处理）
  const onPickFiles = async (files: File[]): Promise<void> => {
    // 图片/文档只是暂存(发送时才用)，生成中/别的对话也该能加——不再被 busy 锁(机主实测:+号灰掉传不了)
    const plan = planPickedFiles(files, pendingImages.length)
    if (plan.images.length) addPendingImages(plan.images as File[])
    if (plan.overflowImages > 0) {
      setMessages((p) => [
        ...p,
        {
          role: 'assistant',
          content: t('chat.imageLimit', { n: MAX_PENDING_IMAGES, dropped: plan.overflowImages })
        }
      ])
    }

    for (const f of plan.texts as File[]) {
      try {
        addPendingDoc(f.name, await f.text())
      } catch (e) {
        setMessages((p) => [...p, { role: 'assistant', content: `⚠️ ${String(e)}` }])
      }
    }

    if (plan.unsupported.length) {
      setMessages((p) => [...p, { role: 'assistant', content: t('chat.attachHint') }])
    }

    if (plan.videos.length === 0 || busy) return // 拉片会占用生成，busy 时先不处理视频(图片/文档已暂存)
    const f = plan.videos[0] as File
    setMessages((p) => [
      ...p,
      { role: 'user', content: `🎬 ${f.name}`, ts: Date.now() },
      { role: 'assistant', content: t('chat.lapianRunning') }
    ])
    setBusy(true)
    const setLast = (patch: Partial<DisplayMsg>): void =>
      setMessages((prev) => {
        const c = prev.slice()
        c[c.length - 1] = { role: 'assistant', content: '', ...patch }
        return c
      })
    try {
      const r = await lapianVideo(f, { withAudio: true })
      setLast({
        content: r.report || t('chat.emptyReport'),
        meta: `〔${t('chat.lapianMeta', { frames: r.frames ?? '?', synth: r.synth_model ?? '?' })}〕`,
        model: r.synth_model
      })
    } catch (e) {
      setLast({ content: `⚠️ ${String(e)}` })
    } finally {
      setBusy(false)
    }
  }

  const onPickFolder = async (): Promise<void> => {
    try {
      const dir = await window.api.pickDirectory()
      if (dir) setWorkTarget(dir)
    } catch (e) {
      setMessages((p) => [...p, { role: 'assistant', content: `⚠️ ${String(e)}` }])
    }
  }

  // 视频工作室：分镜方案转可读文字（给用户确认用）
  const studioPlanText = (p: StudioPlan): string =>
    t('chat.studioPlanCard', {
      title: p.title,
      style: p.style,
      shots: p.shots.map((s) => `${s.n}. ${s.desc}（${s.seconds}s · ${s.motion}）`).join('\n')
    })

  // 视频工作室：确认后才成片——execute → 轮询进度 → 展示成片（慢，几分钟）
  const runStudioExecute = async (plan: StudioPlan): Promise<void> => {
    setMessages((p) => [...p, { role: 'assistant', content: t('chat.studioRunning'), ts: Date.now() }])
    setBusy(true)
    const setLastStudio = (patch: Partial<DisplayMsg>): void =>
      setMessages((prev) => {
        const copy = prev.slice()
        copy[copy.length - 1] = { role: 'assistant', content: '', ...patch }
        return copy
      })
    try {
      const launch = await studioExecute(plan)
      if (launch.needs_approval) {
        setLastStudio({ content: `方案已冻结并送审（审批号 ${launch.approval_id ?? '-'}），批准后启动。` })
        return
      }
      const job_id = launch.job_id
      if (!job_id) throw new Error('视频任务未返回 job_id')
      let done = false
      // 长片逐镜生成以小时计（每镜 1-3 分钟）——上限 4h，别 20 分钟就放弃（长视频工作流）
      for (let i = 0; i < 2880 && !done; i++) {
        await new Promise((r) => setTimeout(r, 5000))
        const st = await studioJob(job_id)
        if (st.video) {
          const url = await studioVideoBlobUrl(job_id)
          setLastStudio({ video: url, videoSrc: `studio:${job_id}`, content: '' })
          done = true
        } else if (st.error) {
          setLastStudio({ content: t('chat.videoFail', { e: String(st.error) }) })
          done = true
        } else {
          setLastStudio({
            content: t('chat.studioProgress', { progress: st.progress ?? 0, total: st.total ?? 0, msg: st.msg || '' })
          })
        }
      }
      if (!done) setLastStudio({ content: t('chat.videoTimeout') })
    } catch (e) {
      setLastStudio({ content: `⚠️ ${String(e)}` })
    } finally {
      setBusy(false)
    }
  }

  // #6：舰队把生视频派成异步任务（task_id 藏在返回里）→ 前台后台轮询，成片自动贴回对话。
  // 独立成一条 assistant 消息（用唯一 ts 锚定），轮询期间显示进度，不阻塞用户继续聊天。
  // anchorTs 传入 = 断点续传：复用重启前那条消息接着轮（videoTask 已持久化，云端任务没白做）。
  const awaitAndAttachVideo = async (pv: PendingVideo, anchorTs?: number, homeConvId?: string): Promise<void> => {
    resumedTasksRef.current.add(pv.task_id) // 登记：正在轮询——续传 effect 别对同一任务再起一份
    // 锚点/进度/成片都写回**发起时的对话**——轮询几分钟期间用户切对话，绝不能写串（codex 审）
    const home = homeConvId ?? useAppStore.getState().currentConvId ?? ''
    const vts = anchorTs ?? Date.now() + Math.random() // 唯一锚点，避免和别的消息 ts 撞车
    if (anchorTs == null) {
      setConvMessages(home, (p) => [
        ...p,
        {
          role: 'assistant',
          content: t('chat.videoProgress', { status: '', progress: 0 }),
          ts: vts,
          startedAt: Date.now(),
          // 持久化任务号+内容 → 重启自动续传；prompt 供后续消息注入"后台任务进行中"上下文（插队补充能接上）
          videoTask: { task_id: pv.task_id, model: pv.model, prompt: pv.prompt }
        }
      ])
    }
    const patch = (patchObj: Partial<DisplayMsg>): void =>
      setConvMessages(home, (prev) => prev.map((m) => (m.ts === vts ? { ...m, ...patchObj } : m)))
    // 长视频（视频工作室后台 job，task_id=studio:{job_id}）：轮询节奏慢(15s)、上限长(6h)，
    // 分镜逐镜生成耗时以小时计；进度显示"第 X/N 镜"。成片经引擎文件端点代下贴回。
    if (pv.task_id.startsWith('studio:')) {
      const jid = pv.task_id.slice('studio:'.length)
      const t0 = Date.now()
      try {
        while (Date.now() - t0 < 6 * 3600_000) {
          await new Promise((r) => setTimeout(r, 15000))
          const st = await studioJob(jid).catch(() => null)
          if (!st) continue // 单次轮询失败（引擎重启中等）→ 继续等
          if (st.error) {
            patch({ content: t('chat.videoFail', { e: String(st.error) }), videoTask: undefined, completedAt: Date.now() })
            return
          }
          if (st.video) {
            const url = await studioVideoBlobUrl(jid).catch(() => '')
            // 部分镜失败 → 如实标注成片不完整/偏短，别让你以为是完整时长（机主实测:3秒残片当30秒完成）
            const note = st.partial ? (st.msg || t('chat.videoPartial')) : ''
            if (url) patch({ video: url, videoSrc: `studio:${jid}`, content: note, videoTask: undefined, completedAt: Date.now() })
            else patch({ content: t('chat.videoTimeout'), videoTask: undefined, completedAt: Date.now() })
            if (useAppStore.getState().soundEnabled) playDone() // 长视频成片贴回（不走 busy）→ 单独提示
            return
          }
          if (st.status === 'unknown') {
            patch({ content: t('chat.videoFail', { e: '任务已丢失（引擎重启过，长视频任务不跨引擎重启）' }), videoTask: undefined, completedAt: Date.now() })
            return
          }
          const total = Number(st.total) || 0
          const prog = Number(st.progress) || 0
          patch({
            content: t('chat.videoProgress', {
              status: String(st.msg || ''),
              progress: total ? Math.round((prog / total) * 100) : 0
            })
          })
        }
        patch({ content: t('chat.videoTimeout'), videoTask: undefined, completedAt: Date.now() })
      } catch (e) {
        patch({ content: t('chat.videoFail', { e: String(e) }), videoTask: undefined, completedAt: Date.now() })
      }
      return
    }
    try {
      const src = await awaitVideo(pv.model, pv.task_id, {
        // provider 有的返 0–1、有的返 0–100 → 归一化成百分比再显示
        onProgress: (p) =>
          patch({
            content: t('chat.videoProgress', { status: '', progress: p <= 1 ? Math.round(p * 100) : Math.round(p) })
          })
      })
      if (src) {
        const hasDurableVideoAsset = isDurablePaidMediaAssetRef(src)
        const play = hasDurableVideoAsset
          ? src
          : await videoBlobUrl(src).catch(() => src)
        patch({
          video: play,
          videoSrc: src,
          content: '',
          ...(hasDurableVideoAsset
            ? { videoTask: undefined, completedAt: Date.now() }
            : { completedAt: undefined })
        })
        if (useAppStore.getState().soundEnabled) playDone() // 短视频异步成片贴回（不走 busy）→ 提示
      } else {
        patch({
          content: `${t('chat.videoTimeout')}（任务编号已保留，可稍后继续）`,
          completedAt: undefined
        })
      }
    } catch (e) {
      patch({
        content: t('chat.videoProgress', {
          status: `轮询暂停，任务已保留：${String(e)}`,
          progress: 0
        }),
        completedAt: undefined
      })
    }
  }

  const retryPaidMedia = async (messageIndex: number): Promise<void> => {
    const message = messages[messageIndex]
    const recovery = message?.paidMediaOperation
    if (!message || !recovery || recovery.blocked || recoveringPaidMedia || !currentConvId) return
    const target: PaidMediaMessageTarget = {
      conversationId: currentConvId,
      messageTs: message.ts,
      operationId: recovery.operationId
    }
    const messageTarget: PaidMediaMessageTarget = {
      conversationId: currentConvId,
      messageTs: message.ts
    }
    const sourceMessage = messages[messageIndex - 1]
    const prompt = sourceMessage?.role === 'user' ? sourceMessage.content : ''
    const sourceImages = sourceMessage?.role === 'user' ? (sourceMessage.images ?? []) : []
    const patch = (value: Partial<DisplayMsg>): boolean =>
      patchPaidMediaMessage(setConvMessages, target, value)
    const patchAfterTerminal = (value: Partial<DisplayMsg>): boolean =>
      patch(value) || patchPaidMediaMessage(setConvMessages, messageTarget, value)
    let resultAwaitingAck = false
    let deliveryProof: PaidMediaDeliveryProof | undefined
    setRecoveringPaidMedia(recovery.operationId)
    patch({ content: '正在用原操作编号安全恢复，不会创建新的付费请求…' })
    try {
      if (recovery.kind === 'image') {
        await generateImage(recovery.model, prompt, undefined, {
          operationId: recovery.operationId,
          onResultDurablyCommitted: (operationId, images, proof) => {
            if (operationId !== recovery.operationId) return false
            deliveryProof = proof
            const applied = patch({
              content: images.length ? '' : t('chat.noImage'),
              images,
              paidMediaOperation: {
                ...recovery,
                phase: 'awaiting_ack',
                deliveryProof: proof
              },
              completedAt: Date.now()
            })
            resultAwaitingAck =
              applied &&
              flushAndVerifyPaidMediaResult({
                conversationId: target.conversationId,
                messageTs: target.messageTs!,
                operationId,
                deliveryProof: proof,
                images
              })
            return resultAwaitingAck
          }
        })
        if (
          patch({ paidMediaOperation: undefined })
        ) {
          flushAppStorePersistence()
        }
      } else {
        const created = await createVideo(
          recovery.model,
          prompt,
          undefined,
          sourceImages,
          {
            operationId: recovery.operationId,
            onResultDurablyCommitted: (operationId, result, proof) => {
              if (operationId !== recovery.operationId) return false
              deliveryProof = proof
              const taskId = result.video_id || result.task_id || result.id || ''
              if (!taskId) return false
              const applied = patch({
                content: t('chat.videoProgress', { status: '', progress: 0 }),
                paidMediaOperation: {
                  ...recovery,
                  phase: 'awaiting_ack',
                  deliveryProof: proof
                },
                videoTask: { task_id: taskId, model: recovery.model, prompt }
              })
              resultAwaitingAck =
                applied &&
                flushAndVerifyPaidMediaResult({
                  conversationId: target.conversationId,
                  messageTs: target.messageTs!,
                  operationId,
                  deliveryProof: proof,
                  videoTask: { task_id: taskId, model: recovery.model, prompt }
                })
              return resultAwaitingAck
            }
          }
        )
        if (patch({ paidMediaOperation: undefined })) flushAppStorePersistence()
        const taskId = created.video_id || created.task_id || created.id || ''
        if (!taskId) throw new Error('供应商返回成功，但没有可轮询的视频任务号')
        void awaitAndAttachVideo(
          { task_id: taskId, model: recovery.model, prompt },
          message.ts,
          target.conversationId
        )
      }
    } catch (error) {
      const retryable = error instanceof PaidMediaRequestError && error.recoverable
      if (
        patchAfterTerminal({
          content: `⚠️ ${String(error)}${retryable ? '；仍可继续使用同一操作编号恢复。' : '；已停止自动恢复，请先人工核对。'}`,
          paidMediaOperation: {
            ...recovery,
            phase: resultAwaitingAck ? 'awaiting_ack' : recovery.phase,
            ...(resultAwaitingAck && deliveryProof ? { deliveryProof } : {}),
            blocked: !retryable
          },
          completedAt: Date.now()
        })
      ) {
        flushAppStorePersistence()
      }
    } finally {
      setRecoveringPaidMedia(null)
    }
  }

  const discardPaidMediaRecovery = async (messageIndex: number): Promise<void> => {
    const message = messages[messageIndex]
    const recovery = message?.paidMediaOperation
    if (!message || !recovery || !currentConvId) return
    const target: PaidMediaMessageTarget = {
      conversationId: currentConvId,
      messageTs: message.ts,
      operationId: recovery.operationId
    }
    const evidence = window.prompt(
      '只有核对供应商账单/任务后才能结案。请填写供应商任务号、账单号或明确的未扣费查询凭据；主进程随后还会连续两次确认。',
      ''
    )
    if (!evidence?.trim()) return
    try {
      const reconciled = await discardPendingPaidMediaOperation(
        recovery.operationId,
        evidence.trim()
      )
      if (!reconciled) return
      const applied = patchPaidMediaMessage(setConvMessages, target, (candidate) => ({
        ...candidate,
        content: `${candidate.content}\n已按你的选择移除本机恢复记录。`,
        paidMediaOperation: undefined
      }))
      if (applied) flushAppStorePersistence()
    } catch (error) {
      patchPaidMediaMessage(setConvMessages, target, {
        content: `⚠️ 无法移除恢复记录：${String(error)}`
      })
    }
  }

  const send = async (
    textArg?: string,
    forceExec = false,
    docsArg?: PendingDoc[],
    imagesArg?: PendingImage[],
    interrupt = false,
    modelOverride?: string
  ): Promise<void> => {
    const text = (typeof textArg === 'string' ? textArg : input).trim()
    // 文档附件：排队/程序化重发用透传来的 docsArg；从输入框直接发则取 pendingDocs
    const docs = docsArg ?? (typeof textArg === 'string' ? [] : pendingDocs)
    const images = imagesArg ?? (typeof textArg === 'string' ? [] : pendingImages)
    const turnModelId = modelOverride ?? currentModel
    if ((!text && docs.length === 0 && images.length === 0) || !turnModelId) return
    if (paidVideoSubmissionGate.isActive() && !interrupt) return
    // 兜底建对话：全新进入/对话被删光/currentConvId 指向已不存在的对话（脏状态）时，
    // 打字发消息也**必须**能发——自动建一个，绝不拦着说"没有对话"（机主实测 bug）。
    if (!currentConvId || !useAppStore.getState().conversations.some((c) => c.id === currentConvId)) {
      ensureConversation()
    }
    const convId = useAppStore.getState().currentConvId ?? '' // 本轮确定的对话 id（ensureConversation 已保证有效）
    if (busy && !interrupt) {
      // 运行中插话（Claude Code 式）：agent 长任务跑着时发纯文本 → 注入运行中循环——
      // 任务不打断、下一步就吸收你的补充（机主定案：插话=补充信息，不是砍任务、也不该干等排队）。
      // 带图/文档或没有活跃 agent 任务时，走下方排队（完成后自动发）。
      if (text && docs.length === 0 && images.length === 0 && useAppStore.getState().agentBusy && convId) {
        // 插话去重：10 秒内同文重复（回车狂敲/以为没反应再点）→ 只注入一次，别给 agent 塞两遍
        //（机主实测：出现两条一模一样的"补充"）。
        const dup = lastInjectRef.current
        if (dup && dup.text === text && Date.now() - dup.at < 10_000) {
          setInput('')
          return
        }
        const injected = await agentInject(convId, text)
        if (injected) {
          lastInjectRef.current = { text, at: Date.now() }
          setMessages((p) => [...p, { role: 'user', content: text, ts: Date.now() }])
          setInput('')
          return // 时间线会出现「💬 用户插话已并入」（引擎推的 step 事件）
        }
      }
      // 正在生成 → 连同文档/图片进暂存栏排队（完成后自动发），而不是卡住发不出去/丢附件。
      // 同文重复不再入队（机主实测：狂敲回车发出两段一样的）；记 convId 只发回本对话。
      setQueued((q) =>
        !docs.length && !images.length && q.some((x) => x.text === text && !x.docs?.length && !x.images?.length)
          ? q
          : [
              ...q,
              {
                text,
                docs: docs.length ? docs : undefined,
                images: images.length ? images : undefined,
                convId: convId || undefined
              }
            ]
      )
      setInput('')
      if (docs.length) setPendingDocs([])
      if (images.length && typeof textArg !== 'string') setPendingImages([])
      return
    }
    if (busy && interrupt) {
      abortRef.current?.abort()
      setBusy(false)
      setAgentBusy(false)
    }
    const ac = new AbortController() // 本轮生成的中止器：撤回时用它打断模型
    abortRef.current = ac

    // #12 纳川当默认大脑：选中舰队号（纳川/纳川·Ultra）时，不再用正则猜意图——
    // 一律交给舰队自己编排（内部先快后升：简单问题便宜模型秒答、复杂才升；该动手/生图/生视频/拉片
    // 都由舰队用工具自决）。带图输入除外（走视觉直连）。旧的正则意图识别仅保留给「手动点具体模型」的高级路径。
    const useFleet = isFleetModelId(turnModelId) && images.length === 0

    // 自动智能：贴视频链接 +「拉片/拆解」→ 自动下视频逐帧拆成拉片报告（不走模型路由）
    if (!useFleet && images.length === 0 && !forceExec && docs.length === 0 && isLapianRequest(text)) {
      const um = text.match(VIDEO_URL)
      setMessages([
        ...messages,
        { role: 'user', content: text, ts: Date.now() },
        { role: 'assistant', content: t('chat.lapianRunning'), ts: Date.now() }
      ])
      setInput('')
      setBusy(true)
      try {
        const res = await lapianUrl(um ? um[0] : text)
        setMessages((prev) => {
          const c = prev.slice()
          c[c.length - 1] = {
            role: 'assistant',
            content: res.report || t('chat.emptyReport'),
            ts: c[c.length - 1]?.ts,
            model: res.synth_model
          }
          return c
        })
      } catch (e) {
        setMessages((prev) => {
          const c = prev.slice()
          c[c.length - 1] = { role: 'assistant', content: `⚠️ ${String(e)}`, ts: c[c.length - 1]?.ts }
          return c
        })
      } finally {
        setBusy(false)
      }
      return
    }

    // 自动智能：贴网页链接 +「读/总结」→ 抓正文 + 模型总结（视频链接走拉片，不到这）
    if (!useFleet && images.length === 0 && !forceExec && docs.length === 0 && isWebReadRequest(text)) {
      const url = extractUrl(text)
      const q = text.replace(ANY_URL, '').trim()
      setMessages([
        ...messages,
        { role: 'user', content: text, ts: Date.now() },
        { role: 'assistant', content: t('chat.webReading'), ts: Date.now() }
      ])
      setInput('')
      setBusy(true)
      try {
        const res = await webRead(url, q)
        const reply = `**${res.title}**\n\n${res.summary}\n\n🔗 ${res.url}`
        setMessages((p) => {
          const c = p.slice()
          c[c.length - 1] = {
            role: 'assistant',
            content: reply,
            ts: c[c.length - 1]?.ts,
            model: res.model,
            usage: res.usage
          }
          return c
        })
      } catch (e) {
        setMessages((p) => {
          const c = p.slice()
          c[c.length - 1] = { role: 'assistant', content: `⚠️ ${String(e)}`, ts: c[c.length - 1]?.ts }
          return c
        })
      } finally {
        setBusy(false)
      }
      return
    }

    // 视频工作室：上一步出了分镜方案在等确认 → 确认就成片，否则当"改方案"反馈带原方案重新规划（#18）
    if (pendingStudioPlan && !forceExec && docs.length === 0) {
      const plan = pendingStudioPlan
      setPendingStudioPlan(null)
      if (isStudioConfirm(text)) {
        setMessages((p) => [...p, { role: 'user', content: text, ts: Date.now() }])
        setInput('')
        await runStudioExecute(plan)
        return
      }
      setMessages([
        ...messages,
        { role: 'user', content: text, ts: Date.now() },
        { role: 'assistant', content: t('chat.studioPlanning'), ts: Date.now() }
      ])
      setInput('')
      setBusy(true)
      try {
        const np = await studioPlan('', text, plan)
        setPendingStudioPlan(np)
        setMessages((prev) => {
          const c = prev.slice()
          c[c.length - 1] = { role: 'assistant', content: studioPlanText(np), ts: c[c.length - 1]?.ts }
          return c
        })
      } catch (e) {
        setMessages((prev) => {
          const c = prev.slice()
          c[c.length - 1] = { role: 'assistant', content: `⚠️ ${String(e)}`, ts: c[c.length - 1]?.ts }
          return c
        })
      } finally {
        setBusy(false)
      }
      return
    }

    // 自动智能：「多镜头/分镜/视频工作室」→ 先出分镜方案给你看，确认了再成片（#18，防白烧几分钟）
    if (!useFleet && images.length === 0 && !forceExec && docs.length === 0 && isStudioRequest(text)) {
      setMessages([
        ...messages,
        { role: 'user', content: text, ts: Date.now() },
        { role: 'assistant', content: t('chat.studioPlanning'), ts: Date.now() }
      ])
      setInput('')
      setBusy(true)
      try {
        const plan = await studioPlan(text)
        setPendingStudioPlan(plan)
        setMessages((prev) => {
          const c = prev.slice()
          c[c.length - 1] = { role: 'assistant', content: studioPlanText(plan), ts: c[c.length - 1]?.ts }
          return c
        })
      } catch (e) {
        setMessages((prev) => {
          const c = prev.slice()
          c[c.length - 1] = { role: 'assistant', content: `⚠️ ${String(e)}`, ts: c[c.length - 1]?.ts }
          return c
        })
      } finally {
        setBusy(false)
      }
      return
    }

    // 自动智能：「翻译成X」→ 调翻译接口把译文贴回（待译为空则译上一条回复）
    if (!useFleet && images.length === 0 && !forceExec && docs.length === 0 && isTranslateRequest(text)) {
      const { target, text: toTr } = parseTranslate(text)
      const prevMsg = messages[messages.length - 1]
      const source = toTr || (prevMsg ? msgToModelText(prevMsg) : '')
      setMessages([
        ...messages,
        { role: 'user', content: text, ts: Date.now() },
        { role: 'assistant', content: t('chat.translating'), ts: Date.now() }
      ])
      setInput('')
      setBusy(true)
      try {
        const out = await translateText(source, target)
        setMessages((p) => {
          const c = p.slice()
          c[c.length - 1] = { role: 'assistant', content: out || t('chat.emptyReport'), ts: c[c.length - 1]?.ts }
          return c
        })
      } catch (e) {
        setMessages((p) => {
          const c = p.slice()
          c[c.length - 1] = { role: 'assistant', content: `⚠️ ${String(e)}`, ts: c[c.length - 1]?.ts }
          return c
        })
      } finally {
        setBusy(false)
      }
      return
    }

    // 自动智能：「据我文档/知识库」→ 走本地知识库检索，回答 + 附来源
    if (!useFleet && images.length === 0 && !forceExec && docs.length === 0 && isKbRequest(text)) {
      setMessages([
        ...messages,
        { role: 'user', content: text, ts: Date.now() },
        { role: 'assistant', content: t('chat.kbQuerying'), ts: Date.now() }
      ])
      setInput('')
      setBusy(true)
      try {
        const res = await queryKb(text)
        const src = res.sources?.length
          ? `\n\n${t('chat.kbSources')}${res.sources.map((s) => s.title).filter(Boolean).join('、')}`
          : ''
        setMessages((p) => {
          const c = p.slice()
          c[c.length - 1] = {
            role: 'assistant',
            content: (res.answer || t('chat.emptyReport')) + src,
            ts: c[c.length - 1]?.ts,
            model: res.model,
            usage: res.usage
          }
          return c
        })
      } catch (e) {
        setMessages((p) => {
          const c = p.slice()
          c[c.length - 1] = { role: 'assistant', content: `⚠️ ${String(e)}`, ts: c[c.length - 1]?.ts }
          return c
        })
      } finally {
        setBusy(false)
      }
      return
    }

    const rawTargetWorkdir = workTarget.trim() || undefined
    const dailyVideoWorkflow =
      !useFleet && images.length === 0 && docs.length === 0 && !forceExec && isDailyVideoWorkflow(text)
    const targetWorkdir = dailyVideoWorkflow ? rawTargetWorkdir || DAILY_VIDEO_ROOT : rawTargetWorkdir
    // 聊天/执行硬分界：选中舰队号只决定“谁来思考”，绝不自动升级成执行权限。
    // 普通文字（包括“你好”“分析方案”）走零工具 advisory；只有明确动作意图、用户点执行，
    // 或显式目标工作目录才进入受 capability 约束的 exec。
    // 例外（机主实测修）：画图/生视频这类**媒体生成**即便舰队当家也不走 exec——弱模型常摆烂说
    // "我无法生成视频"而不去调工具，必须直连图/视频模型才可靠（见下方媒体块，命中会把 effMode 改回 direct）。
    let effMode = initialChatTurnMode({
      hasImages: images.length > 0,
      forceExec,
      actionTask: isActionTask(text),
      hasTargetWorkdir: Boolean(targetWorkdir)
    })
    // 文档附件：这一条真正喂给模型的文字 = 文档展开成上下文 + 正文（气泡里只显紧凑文档卡）
    const targetNote = targetWorkdir ? `【本次目标路径】\n${targetWorkdir}\n\n` : ''
    const contentText = docs.length ? `${docsToContext(docs)}\n\n${text}`.trim() : text
    const modelText = `${targetNote}${contentText}`.trim()
    const startedAt = Date.now()
    // 发起时的对话 id：本轮所有异步回写（流式/结果/错误/视频锚点）都写回它——
    // 任务跑着时用户切对话，结果绝不能跟着 currentConvId 写串（codex 审出的跨对话洞）。
    const runConvId = convId
    const patchRun = (patch: Partial<DisplayMsg>): void =>
      setConvMessages(runConvId, (prev) =>
        prev.map((mm) => (mm.ts === startedAt && mm.role === 'assistant' ? { ...mm, ...patch } : mm))
      )
    const agentMaxSteps = maxStepsForReasoning(reasoningLevel)
    // 机主反馈：工作状态别堆内部设置噪音（知识库预读/执行上限/推理级别/执行路线这些是后台机制，不用给用户看）。
    // 只在**真设了目标工作目录**时留一行提示，其余留白——真正的进展交给下面的实时步骤事件。
    const baseWorkLog = targetWorkdir ? [t('chat.workTargetPath', { path: targetWorkdir })] : []

    // 每日 AI 资讯视频：固定走 RUNBOOK 点火脚本，不能交给通用 agent 循环猜流程。
    if (dailyVideoWorkflow) {
      if (!rawTargetWorkdir) setWorkTarget(DAILY_VIDEO_ROOT)
      setMessages([
        ...messages,
        { role: 'user', content: text, ts: startedAt },
        {
          role: 'assistant',
          content: t('chat.dailyVideoStarting'),
          ts: startedAt,
          startedAt,
          workLog: [...baseWorkLog, t('chat.workDailyVideoRunbook')]
        }
      ])
      setInput('')
      setBusy(true)
      try {
        const res = await startDailyVideo(targetWorkdir, undefined, ac.signal)
        if (res.needs_approval) {
          setMessages((prev) => {
            const copy = prev.slice()
            copy[copy.length - 1] = {
              ...(copy[copy.length - 1] ?? { role: 'assistant', content: '' }),
              role: 'assistant',
              content: `工作流参数已冻结并送审（审批号 ${res.approval_id ?? '-'}），批准后自动点火。`,
              completedAt: Date.now()
            }
            return copy
          })
          return
        }
        setMessages((prev) => {
          const copy = prev.slice()
          copy[copy.length - 1] = {
            ...(copy[copy.length - 1] ?? { role: 'assistant', content: '' }),
            role: 'assistant',
            content: t('chat.dailyVideoStarted', {
              task: res.task || '-',
              dir: res.episode_dir,
              log: res.duo_log
            }),
            meta: `〔${t('chat.execTag')} → daily-video〕`,
            model: 'workflow:daily-video',
            completedAt: Date.now(),
            workLog: [
              ...((copy[copy.length - 1] as DisplayMsg | undefined)?.workLog ?? []),
              t('chat.workDailyVideoTask', { task: res.task || '-' }),
              t('chat.workDailyVideoDir', { dir: res.episode_dir }),
              t('chat.workDailyVideoLog', { log: res.duo_log })
            ]
          }
          return copy
        })
      } catch (e) {
        if (ac.signal.aborted) return
        setMessages((prev) => {
          const copy = prev.slice()
          copy[copy.length - 1] = {
            ...(copy[copy.length - 1] ?? { role: 'assistant', content: '' }),
            role: 'assistant',
            content: t('chat.dailyVideoFailed', { e: String(e) }),
            meta: `〔${t('chat.execTag')} → daily-video〕`,
            model: 'workflow:daily-video',
            completedAt: Date.now()
          }
          return copy
        })
      } finally {
        setBusy(false)
      }
      return
    }

    // 自动智能：识别画图/生视频意图 → 改用对应的图/视频模型（成品直接贴进聊天，像飞书）；否则用当前模型
    // 注意：带了文档附件就别去图/视频生成（那是给文本对话/总结用的）
    let effModelId = turnModelId
    // 媒体生成意图识别：非舰队走老条件（auto 且非 exec）；舰队当家也要识别（机主实测：舰队被 fast-first
    // 甩给弱模型，弱模型摆烂不调生视频工具 → 必须在这里直连图/视频模型，别进 exec）。
    if (
      !modelOverride &&
      images.length === 0 &&
      !forceExec &&
      docs.length === 0 &&
      (useFleet || (effMode !== 'exec'))
    ) {
      const wantImage = isImageRequest(text)
      const wantVideo = isVideoRequest(text)
      if (wantImage || wantVideo) {
        // 正则命中图/视频意图 → 用免费模型确认一次，挡掉"画饼充饥/视频怎么剪"这类误触发（#17）；
        // 分类失败就回退正则结果（绝不因分类器挂了而让明确的"画一只猫"失灵）。
        const intent = await classifyIntent(text).catch(() => (wantImage ? 'image' : 'video'))
        if (intent === 'image') effModelId = models.find((m) => m.modality === 'image')?.id || turnModelId
        else if (intent === 'video')
          effModelId = models.find((m) => m.modality === 'video')?.id || turnModelId
        // 命中媒体（effModelId 换成了图/视频模型）→ 强制直连该模型出片，别再进舰队 exec（弱模型会摆烂）
        if (effModelId !== turnModelId) effMode = 'direct'
        // 分类器说不是图/视频（如成语/提问）→ 保持当前模型，走普通对话
      }
    }
    const model = models.find((m) => m.id === effModelId)

    // 生视频模型：创建任务 → 轮询进度 → 展示
    if (model?.modality === 'video') {
      const sourceImages = images.length
        ? await Promise.all(images.map((img) => imageFileToDataUrl(img.file)))
        : latestDisplayImages(messages)
      if (!paidVideoSubmissionGate.tryBegin()) return
      setConvMessages(runConvId, (previous) => [
        ...previous,
        { role: 'user', content: text, images: sourceImages.length ? sourceImages : undefined, ts: startedAt },
        {
          role: 'assistant',
          content: t('chat.videoGen'),
          ts: startedAt,
          startedAt,
          workLog: [...baseWorkLog, t('chat.workVideoModel', { model: effModelId })]
        }
      ])
      setInput('')
      setBusy(true)
      const paidMediaTarget: PaidMediaMessageTarget = {
        conversationId: runConvId,
        messageTs: startedAt
      }
      let paidOperationId: string | undefined
      let resultAwaitingAck = false
      let deliveryProof: PaidMediaDeliveryProof | undefined
      const setLast = (
        patch: Partial<DisplayMsg>,
        target: PaidMediaMessageTarget = paidMediaTarget
      ): boolean =>
        patchPaidMediaMessage(setConvMessages, target, (message) => ({
          ...message,
          role: 'assistant',
          content: '',
          completedAt: Date.now(),
          ...patch
        }))
      try {
        const created = await createVideo(effModelId, text, ac.signal, sourceImages, {
          onOperationClaimed: (operationId) => {
            paidOperationId = operationId
            if (
              !patchPaidMediaMessageAndFlush(
                setConvMessages,
                paidMediaTarget,
                {
                  paidMediaOperation: {
                    operationId,
                    kind: 'video',
                    model: effModelId,
                    phase: 'awaiting_result'
                  },
                  completedAt: undefined
                },
                flushAppStorePersistence
              )
            ) {
              throw new Error('无法在发送前持久化付费视频恢复编号')
            }
          },
          onResultDurablyCommitted: (operationId, result, proof) => {
            const taskId = result.video_id || result.task_id || result.id || ''
            if (!taskId) return false
            resumedTasksRef.current.add(taskId)
            paidOperationId = operationId
            deliveryProof = proof
            const applied = patchPaidMediaMessage(
              setConvMessages,
              { ...paidMediaTarget, operationId },
              {
                paidMediaOperation: {
                  operationId,
                  kind: 'video',
                  model: effModelId,
                  phase: 'awaiting_ack',
                  deliveryProof: proof
                },
                videoTask: { task_id: taskId, model: effModelId, prompt: text },
                completedAt: undefined
              }
            )
            resultAwaitingAck =
              applied &&
              flushAndVerifyPaidMediaResult({
                conversationId: paidMediaTarget.conversationId,
                messageTs: paidMediaTarget.messageTs!,
                operationId,
                deliveryProof: proof,
                videoTask: { task_id: taskId, model: effModelId, prompt: text }
              })
            return resultAwaitingAck
          }
        })
        if (paidOperationId) {
          patchPaidMediaMessageAndFlush(
            setConvMessages,
            { ...paidMediaTarget, operationId: paidOperationId },
            { paidMediaOperation: undefined },
            flushAppStorePersistence
          )
        }
        const taskId = created.video_id || created.task_id || created.id || ''
        let done = false
        // 轮询容错：视频要几分钟，Agnes 海外偶发抖一下(502/网络)——单次失败绝不整条报废，接住继续轮；
        // 连续多次才判死。**但整体按墙钟总时长封顶**(不按次数)——否则每次轮询慢(后端重试)会 grind 到几十分钟。
        let pollFails = 0
        const startPoll = Date.now()
        const MAX_POLL_MS = 12 * 60_000 // 12 分钟硬上限：到点必收手（修：以前按 150 次算，慢轮询能拖到 50 分钟）
        while (!done && !ac.signal.aborted && Date.now() - startPoll < MAX_POLL_MS) {
          await new Promise((r) => setTimeout(r, 5000))
          if (ac.signal.aborted) break // 撤回 → 停止轮询视频
          const mins = Math.floor((Date.now() - startPoll) / 60000)
          let st: Awaited<ReturnType<typeof pollVideo>>
          try {
            st = await pollVideo(effModelId, taskId)
            if (!st.error) pollFails = 0 // 非终态 error 不是成功响应，也不能清任务锚
          } catch (e) {
            if (ac.signal.aborted) break
            pollFails += 1
            if (pollFails >= 5) {
              // 轮询读失败不等于 provider 任务失败。进入有界指数退避并保留 alias；
              // Gateway 还有 durable backoff，这一层只防本地网络故障时 UI 空转。
              const pollErrorBackoffMs = Math.min(
                60_000,
                5000 * 2 ** Math.min(4, pollFails - 5)
              )
              setLast({
                content: t('chat.videoProgress', {
                  status: `轮询暂停 ${Math.ceil(pollErrorBackoffMs / 1000)} 秒，任务已保留：${String(e)}`,
                  progress: 0
                }),
                completedAt: undefined
              })
              await new Promise((resolve) => setTimeout(resolve, pollErrorBackoffMs))
              continue
            }
            setLast({ content: t('chat.videoProgress', { status: `网络抖动重试中 ${mins}分`, progress: 0 }) })
            continue // 接住这次失败，下一轮接着问
          }
          const url = paidVideoTerminalAssetUrl(st) || ''
          const status = paidVideoStatusValue(st)
          if (url && isDurablePaidMediaAssetRef(url)) {
            setLast({
              video: url,
              videoSrc: url,
              content: '',
              videoTask: undefined,
              completedAt: Date.now()
            })
            done = true
          } else if (PAID_VIDEO_FAILURE_STATUSES.has(status)) {
            setLast({
              content: t('chat.videoFail', { e: String(st.error || status) }),
              videoTask: undefined
            })
            done = true
          } else if (st.error) {
            pollFails += 1
            const pollErrorBackoffMs = Math.min(
              60_000,
              5000 * 2 ** Math.min(4, Math.max(0, pollFails - 1))
            )
            setLast({
              content: t('chat.videoProgress', {
                status: `供应商暂态错误，${Math.ceil(pollErrorBackoffMs / 1000)} 秒后继续：${String(st.error)}`,
                progress: st.progress ?? 0
              }),
              completedAt: undefined
            })
            await new Promise((resolve) => setTimeout(resolve, pollErrorBackoffMs))
          } else {
            // 仍在生成：把已等分钟数显出来，用户看得见在动、也知道离 12 分钟上限还有多久
            const waitingStatus = PAID_VIDEO_SUCCESS_STATUSES.has(status)
              ? `${status}（等待 Main 归档成片）`
              : status || 'queued'
            setLast({ content: t('chat.videoProgress', { status: `${waitingStatus} 已等${mins}分`, progress: st.progress ?? 0 }) })
          }
        }
        if (!done) {
          setLast({
            content: `${t('chat.videoTimeout')}（任务编号已保留，可稍后继续）`,
            completedAt: undefined
          })
        }
      } catch (e) {
        if (e instanceof PaidMediaRequestError && e.recoverable) {
          if (
            setLast(
              {
                content: `⚠️ ${String(e)}；操作处于待核对状态，请使用下方“查询/恢复原操作”，不要重新发送。`,
                paidMediaOperation: {
                  operationId: e.operationId,
                  kind: 'video',
                  model: effModelId,
                  phase: resultAwaitingAck ? 'awaiting_ack' : 'awaiting_result',
                  ...(resultAwaitingAck && deliveryProof ? { deliveryProof } : {})
                }
              },
              { ...paidMediaTarget, operationId: e.operationId }
            ) ||
            setLast({
              content: `⚠️ ${String(e)}；操作处于待核对状态，请使用下方“查询/恢复原操作”，不要重新发送。`,
              paidMediaOperation: {
                operationId: e.operationId,
                kind: 'video',
                model: effModelId,
                phase: resultAwaitingAck ? 'awaiting_ack' : 'awaiting_result',
                ...(resultAwaitingAck && deliveryProof ? { deliveryProof } : {})
              }
            })
          ) {
            flushAppStorePersistence()
          }
        } else {
          setLast({ content: `⚠️ ${String(e)}`, paidMediaOperation: undefined })
        }
      } finally {
        paidVideoSubmissionGate.finish()
        setBusy(false)
      }
      return
    }

    if (model?.modality === 'image') {
      setConvMessages(runConvId, (previous) => [
        ...previous,
        { role: 'user', content: text, ts: startedAt },
        {
          role: 'assistant',
          content: '',
          ts: startedAt,
          startedAt,
          workLog: [...baseWorkLog, t('chat.workImageModel', { model: effModelId })]
        }
      ])
      setInput('')
      setBusy(true)
      const paidMediaTarget: PaidMediaMessageTarget = {
        conversationId: runConvId,
        messageTs: startedAt
      }
      let paidOperationId: string | undefined
      let resultAwaitingAck = false
      let deliveryProof: PaidMediaDeliveryProof | undefined
      try {
        await generateImage(effModelId, text, ac.signal, {
          onOperationClaimed: (operationId) => {
            paidOperationId = operationId
            if (
              !patchPaidMediaMessageAndFlush(
                setConvMessages,
                paidMediaTarget,
                {
                  paidMediaOperation: {
                    operationId,
                    kind: 'image',
                    model: effModelId,
                    phase: 'awaiting_result'
                  }
                },
                flushAppStorePersistence
              )
            ) {
              throw new Error('无法在发送前持久化付费图片恢复编号')
            }
          },
          onResultDurablyCommitted: (operationId, images, proof) => {
            paidOperationId = operationId
            deliveryProof = proof
            const applied = patchPaidMediaMessage(
              setConvMessages,
              { ...paidMediaTarget, operationId },
              {
                role: 'assistant',
                content: images.length ? '' : t('chat.noImage'),
                images,
                paidMediaOperation: {
                  operationId,
                  kind: 'image',
                  model: effModelId,
                  phase: 'awaiting_ack',
                  deliveryProof: proof
                },
                completedAt: Date.now()
              }
            )
            resultAwaitingAck =
              applied &&
              flushAndVerifyPaidMediaResult({
                conversationId: paidMediaTarget.conversationId,
                messageTs: paidMediaTarget.messageTs!,
                operationId,
                deliveryProof: proof,
                images
              })
            return resultAwaitingAck
          }
        })
        if (paidOperationId) {
          patchPaidMediaMessageAndFlush(
            setConvMessages,
            { ...paidMediaTarget, operationId: paidOperationId },
            { paidMediaOperation: undefined },
            flushAppStorePersistence
          )
        }
      } catch (e) {
        if (ac.signal.aborted) return // 撤回打断的，不显示错误、不污染气泡
        const errorPatch: Partial<DisplayMsg> = {
          role: 'assistant',
          content:
            e instanceof PaidMediaRequestError && e.recoverable
              ? `⚠️ ${String(e)}；操作处于待核对状态，请使用下方“查询/恢复原操作”，不要重新发送。`
              : `⚠️ ${String(e)}`,
          paidMediaOperation:
            e instanceof PaidMediaRequestError && e.recoverable
              ? {
                  operationId: e.operationId,
                  kind: 'image' as const,
                  model: effModelId,
                  phase: resultAwaitingAck ? 'awaiting_ack' : 'awaiting_result',
                  ...(resultAwaitingAck && deliveryProof ? { deliveryProof } : {})
                }
              : undefined,
          completedAt: Date.now()
        }
        if (e instanceof PaidMediaRequestError && e.recoverable) {
          const applied =
            patchPaidMediaMessage(setConvMessages, { ...paidMediaTarget, operationId: e.operationId }, errorPatch) ||
            patchPaidMediaMessage(setConvMessages, paidMediaTarget, errorPatch)
          if (applied) flushAppStorePersistence()
        } else {
          patchPaidMediaMessage(setConvMessages, paidMediaTarget, errorPatch)
        }
      } finally {
        setBusy(false)
      }
      return
    }

    let imageDataUrls: string[] = []
    try {
      imageDataUrls = images.length ? await Promise.all(images.map((img) => imageFileToDataUrl(img.file))) : []
    } catch (e) {
      setMessages((p) => [...p, { role: 'assistant', content: `⚠️ ${String(e)}` }])
      return
    }
    const userContent: string | ChatContentPart[] = imageDataUrls.length
      ? [
          { type: 'text', text: modelText || t('chat.imageDefaultQuestion') },
          ...imageDataUrls.map((url) => ({ type: 'image_url' as const, image_url: { url } }))
        ]
      : modelText
    const history: ChatMsg[] = [
      APP_CAPABILITY_SYSTEM,
      ...messagesToAgentHistory(messages),
      { role: 'user', content: userContent }
    ]
    setMessages([
      ...messages,
      {
        role: 'user',
        content: text,
        images: imageDataUrls.length ? imageDataUrls : undefined,
        docs: docs.length ? docs.map((d) => ({ name: d.name, chars: d.content.length, content: d.content })) : undefined,
        ts: startedAt
      },
      {
        role: 'assistant',
        content: '',
        ts: startedAt,
        startedAt,
        workLog: [
          ...baseWorkLog,
          ...(docs.length ? [t('chat.workDocs', { n: docs.length })] : []),
          ...(images.length ? [t('chat.workImages', { n: images.length })] : [])
        ]
      }
    ])
    setInput('')
    setPendingDocs([]) // 文档附件已随这条发出，清空待发区
    if (images.length && typeof textArg !== 'string') setPendingImages([])
    setBusy(true)

    // 超级体模式：走 /v1/agent/chat（带长记忆/案例库/反思；服务端按会话记上下文）
    if (effMode === 'agent') {
      try {
        const res = await agentChat(modelText, {
          chatId: runConvId,
          model: concreteAgentModel(turnModelId),
          signal: ac.signal
        })
        const r = res.agent_route
        const bits = [res.model]
        if (r?.label) bits.push(routeLabelZh(r.label))
        if (res.memories_used?.length) bits.push(`记忆×${res.memories_used.length}`)
        bits.push(agentOutcomeLabelZh(res.outcome, res.blocked))
        const meta = `〔${t('chat.agentTag')} → ${bits.join(' · ')}〕`
        patchRun({
          content: res.reply,
          meta,
          model: res.model,
          usage: res.usage,
          completedAt: Date.now()
        })
      } catch (e) {
        if (ac.signal.aborted) return // 撤回打断的，不显示错误、不污染气泡
        patchRun({ content: `⚠️ ${String(e)}`, completedAt: Date.now() })
      } finally {
        setBusy(false)
      }
      return
    }

    // 执行模式：选中的模型自己动手（浏览器/文件/命令）。
    // 当前启用的原生 CLI 借其自带 agent 循环（/v1/agent/exec）；其它任何会 function-calling 的
    // 模型（agnes/glm/kimi/gpt…）走我们自写的通用循环（/v1/agent/run），右栏浏览器看着它操作。
    if (effMode === 'exec') {
      const m = turnModelId ?? ''
      // #12「大脑说了算」：exec 一律用**所选的大脑**——舰队号(nachuan/-ultra)后端据此选 trinity/conductor；
      // 具体模型就用它自己动手（不再有"auto 忽略你选的模型、后端另挑"这种迷惑行为）。
      const explicitModel = turnModelId || undefined
      // 原生 CLI 路由只信 /v1/models 的 Router 元数据，禁止从模型名字猜。
      // 例如 codex-spark/gpt-5.x 不含 "-codex"，所以不能靠名字判断。
      const cliBackend = nativeExecBackendForModel(models, turnModelId)
      const isCli = Boolean(cliBackend)
      // config.toml 选项先作为 UI 占位；后端尚未解析本地 config.toml，执行时按自动审批语义处理。
      const runExecMode = execMode === 'custom' ? 'auto' : execMode
      // 对话记忆：把之前的轮次作为 history 传给执行 agent（长任务/长对话也不丢）。
      // 机主实测根因#5：以前带全部历史→话题串；我曾错误地砍成"最近8条"（长任务会死）。
      // 正解：前端带足量历史（上限仅防payload爆），**引擎侧做语义摘要压缩**——老对话摘成
      // "主线要点(做过什么/产出在哪/任务到哪)"，近的原样保留（见 gateway compress_history）。
      const HIST_MAX = 120 // 仅 payload 安全上限；真正的"满了就压缩"在引擎侧
      const histForAgent: ChatMsg[] = messagesToAgentHistory(
        messages
          .filter((mm) => (mm.content && mm.content.trim()) || mm.docs?.length || mm.images?.length)
          .slice(-HIST_MAX)
      )
      setAgentBusy(true)
      try {
        if (isCli) {
          // 原生 CLI 是一次性调用：把对话历史拼进任务里，让它也带记忆
          const histText = histForAgent
            .map((h) => {
              const content =
                typeof h.content === 'string'
                  ? h.content
                  : h.content.map((part) => (part.type === 'text' ? part.text : '[图片]')).join('\n')
              return `${h.role === 'user' ? '我' : '助手'}：${content}`
            })
            .join('\n')
          const taskWithHist = histText
            ? `【之前的对话】\n${histText}\n\n【现在的指令】\n${modelText}`
            : modelText
          const res = await agentExec(taskWithHist, {
            backend: cliBackend,
            mode: runExecMode,
            model: explicitModel,
            workdir: targetWorkdir,
            instruction: modelText, // 审批 summary 用当前指令原句，不显示拼接历史的大字报
            signal: ac.signal
          })
          if (res.needs_approval) {
            // P5：高风险动作被前置闸挡下 → 提示去审核弹窗确认（同意后才真正执行）
            patchRun({ content: t('chat.execHeld', { summary: res.summary || '' }), completedAt: Date.now() })
            return
          }
          const meta = `〔${t('chat.execTag')} → ${res.backend ?? m}${res.cost_usd ? ` ·$${res.cost_usd.toFixed(3)}` : ''}〕`
          setLastAgentReply(res.result || '')
          patchRun({
            content: res.result || t('chat.noOutput'),
            meta,
            model: res.backend ?? m,
            completedAt: Date.now()
          })
        } else {
          // 规划档=只读工具；自动/全开=放开文件与命令
          const allow =
            runExecMode === 'plan'
              ? [
                  'list_dir',
                  'read_file',
                  'list_models',
                  'ask_model',
                  'list_skills',
                  'load_skill',
                  'web_read',
                  'kb_query',
                  'translate'
                ]
              : undefined
          // 把编排器一条实时事件渲染成时间线：追加到当前助手气泡的 workLog（活的工作状态卡）。
          let browserOpened = false
          // 按 ts 锚定占位气泡（不能用"最后一条"：运行中插话会 append 新 user 消息，
          // length-1 定位会把进度写进用户的插话气泡/写丢——机主实测"就停在这里了"的根因）。
          const pushTimeline = (line: string, browserish = false): void => {
            if (browserish && !browserOpened) {
              browserOpened = true
              openBrowser() // 一有浏览器动作立刻开右栏，让你看着它操作
            }
            setConvMessages(runConvId, (prev) =>
              prev.map((mm) =>
                mm.ts === startedAt && mm.role === 'assistant'
                  ? { ...mm, workLog: [...(mm.workLog ?? []), line] }
                  : mm
              )
            )
          }
          const res = await agentRunStream(modelText, explicitModel, {
            history: histForAgent,
            workdir: targetWorkdir,
            mode: runExecMode,
            max_steps: agentMaxSteps,
            signal: ac.signal,
            ...(convId ? { conversation_id: convId } : {}),
            ...(allow ? { allow } : {}),
            onEvent: (ev: AgentEvent) => {
              // 视频任务派发即登记（不等最终结果）：点「插队」中止流也不丢——job 在引擎后台照跑，
              // 锚点已建、轮询已起、videoTask 已持久化（断点续传同款机制）。
              if (ev.type === 'pending_video' && typeof ev.task_id === 'string' && ev.task_id) {
                if (!resumedTasksRef.current.has(ev.task_id)) {
                  void awaitAndAttachVideo(
                    {
                      task_id: ev.task_id,
                      model: String(ev.model || ''),
                      prompt: typeof ev.prompt === 'string' ? ev.prompt : undefined
                    },
                    undefined,
                    runConvId // 锚点写回发起对话，中途切对话不串
                  )
                }
                return
              }
              const line = agentEventLine(ev, t)
              if (line) pushTimeline(line, ev.type === 'step' && String(ev.log ?? '').startsWith('browser_'))
            }
          })
          if (res.needs_approval) {
            patchRun({
              content: t('chat.execHeld', { summary: res.summary || '' }),
              completedAt: Date.now()
            })
            return
          }
          const meta = `〔${t('chat.execTag')} → ${res.model ?? explicitModel ?? m} ·${t('chat.steps', { n: res.steps })}${res.tool_log?.length ? ` ·${t('chat.tools', { n: res.tool_log.length })}` : ''}〕`
          setLastAgentReply(res.reply || '')
          // 兜底：若流里没显式浏览器事件、但最终 tool_log 里有，仍自动打开右栏
          if (!browserOpened && res.tool_log?.some((x) => x.startsWith('browser_'))) openBrowser()
          // ts 锚定 + 写回发起对话（插话 append/切对话都不串）；时间线已实时铺好，不重铺 tool_log
          patchRun({
            content: res.reply || t('chat.noOutput'),
            meta,
            model: res.model ?? explicitModel ?? m,
            usage: res.usage,
            completedAt: Date.now(),
            actions: res.file_changes?.length ? res.file_changes : undefined,
            images: res.media?.length ? res.media : undefined
          })
          // #6：exec 路若派了异步生视频任务，后台轮询到成片自动贴回对话。
          // 用 resumedTasksRef 全局去重：流式 pending_video 事件多半已建过锚点，这里只兜漏网的。
          if (res.pending_videos?.length) {
            for (const pv of res.pending_videos) {
              if (pv.task_id && !resumedTasksRef.current.has(pv.task_id)) {
                void awaitAndAttachVideo(pv, undefined, runConvId)
              }
            }
          }
        }
      } catch (e) {
        if (ac.signal.aborted) return // 撤回打断的，不显示错误、不污染气泡
        patchRun({ content: `⚠️ ${String(e)}`, completedAt: Date.now() })
      } finally {
        setBusy(false)
        setAgentBusy(false)
      }
      return
    }

    try {
      let acc = ''
      let reason = ''
      let servedModel = turnModelId
      let usage: TokenUsage | undefined
      const seenVideoTasks = new Set<string>()
      for await (const delta of chatStream(turnModelId, history, ac.signal, true, reasoningLevel, convId || undefined)) {
        if (ac.signal.aborted) break
        if (delta.model) servedModel = delta.model
        if (delta.usage) usage = delta.usage
        acc += delta.content ?? ''
        reason += delta.reasoning ?? ''
        // #6：舰队生视频异步任务 → 后台轮询到成片，自动贴回对话（不阻塞聊天）
        if (delta.pendingVideos?.length) {
          for (const pv of delta.pendingVideos) {
            if (pv.task_id && !seenVideoTasks.has(pv.task_id)) {
              seenVideoTasks.add(pv.task_id)
              void awaitAndAttachVideo(pv, undefined, runConvId)
            }
          }
        }
        // ts 锚定 + 写回发起对话：流式期间插话/切对话都不会把正文写进别的气泡/别的对话（codex 审）
        patchRun({
          content: acc,
          reasoning: reason || undefined,
          model: servedModel ?? undefined,
          usage,
          ...(usage ? { completedAt: Date.now() } : {})
        })
        const el = scrollRef.current
        if (el) el.scrollTo({ top: el.scrollHeight })
      }
    } catch (e) {
      patchRun({ content: `⚠️ ${String(e)}`, completedAt: Date.now() })
    } finally {
      setConvMessages(runConvId, (prev) =>
        prev.map((mm) =>
          mm.ts === startedAt && mm.role === 'assistant' && mm.startedAt && !mm.completedAt
            ? { ...mm, completedAt: Date.now() }
            : mm
        )
      )
      setBusy(false)
    }
  }

  // 统一创作抽屉只负责收集参数；真正的图片/视频请求仍从这里进入同一个 send 路径，
  // 因而继续复用 consent、幂等、账本、ACK、恢复和对话锚点，绝不另起一条直连 API。
  useEffect(() => {
    if (
      !creativeRequest ||
      busy ||
      handledCreativeRequestRef.current === creativeRequest.id
    ) {
      return
    }
    handledCreativeRequestRef.current = creativeRequest.id
    let failure: string | undefined
    void prepareCreativeComposerSubmission(creativeRequest)
      .then((prepared) => send(prepared.prompt, false, [], prepared.images, false, prepared.model))
      .catch((error: unknown) => {
        failure = error instanceof Error ? error.message : String(error)
        setMessages((previous) => [
          ...previous,
          { role: 'assistant', content: `⚠️ 创作请求未提交：${failure}`, ts: Date.now() }
        ])
      })
      .finally(() => onCreativeRequestHandled?.(creativeRequest.id, failure))
    // send is deliberately the existing render-scoped composer path. The request id is the replay fence.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [busy, creativeRequest, onCreativeRequestHandled])

  // 首次进入确保有一个当前对话
  useEffect(() => {
    ensureConversation()
  }, [ensureConversation])

  return (
    <div className="nachuan-chat-pane flex flex-col h-full">
      {/* 「大脑」选择器已移进顶栏（App.tsx Header 的 ModelSelector）；聊天区顶部不再占一行。 */}
      <div ref={scrollRef} className="nachuan-message-canvas flex-1 overflow-auto p-4 space-y-3">
        {messages.length === 0 && (
          <div className="h-full flex flex-col items-center justify-center text-center gap-3 select-none">
            <svg viewBox="0 0 80 80" className="w-20 h-20" xmlns="http://www.w3.org/2000/svg">
              <defs>
                <linearGradient id="ncLogo" x1="0" y1="0" x2="1" y2="1">
                  <stop offset="0" stopColor="#60a5fa" />
                  <stop offset="1" stopColor="#2563eb" />
                </linearGradient>
              </defs>
              <path d="M8 20 C 30 22, 34 38, 52 40" stroke="url(#ncLogo)" strokeWidth="4" strokeLinecap="round" fill="none" opacity="0.9" />
              <path d="M8 40 C 28 40, 34 40, 52 40" stroke="url(#ncLogo)" strokeWidth="4" strokeLinecap="round" fill="none" opacity="0.7" />
              <path d="M8 60 C 30 58, 34 42, 52 40" stroke="url(#ncLogo)" strokeWidth="4" strokeLinecap="round" fill="none" opacity="0.5" />
              <circle cx="56" cy="40" r="11" fill="url(#ncLogo)" />
              <circle cx="56" cy="40" r="11" fill="none" stroke="#93c5fd" strokeWidth="1.5" opacity="0.5" />
            </svg>
            <div className="text-lg font-semibold text-neutral-300">纳川 · Nexus</div>
            <div className="text-sm text-neutral-600">{t('chat.empty')}</div>
          </div>
        )}
        {messages.map((m, i) => (
          <div key={i} className={`group ${m.role === 'user' ? 'text-right' : 'text-left'}`}>
            {m.role === 'assistant' && m.meta && (
              <div className="text-xs text-neutral-600 mb-0.5">{m.meta}</div>
            )}
            {m.role === 'assistant' && m.reasoning && (
              <details
                open={busy && i === messages.length - 1}
                className="mb-1 inline-block max-w-[85%] text-left text-xs text-neutral-500"
              >
                <summary className="cursor-pointer select-none">💭 {t(busy && i === messages.length - 1 ? 'chat.thinking' : 'chat.thinkingDone')}</summary>
                <div className="mt-1 pl-2 border-l-2 border-neutral-700 whitespace-pre-wrap italic">
                  {m.reasoning}
                </div>
              </details>
            )}
            {m.role === 'assistant' && (m.workLog?.length || m.startedAt) && (
              <details
                open={busy && i === messages.length - 1}
                className="mb-1 block max-w-[85%] text-left text-xs text-neutral-500"
              >
                <summary className="inline-flex cursor-pointer select-none items-center gap-2">
                  <span>{t('chat.workStatus')}</span>
                  {m.startedAt && (
                    <span className="text-neutral-600">
                      {t(m.completedAt ? 'chat.elapsedDone' : 'chat.elapsedRunning', {
                        time: formatElapsed(m.startedAt, m.completedAt)
                      })}
                    </span>
                  )}
                </summary>
                {m.workLog?.length ? (
                  <div className="mt-1 space-y-0.5 border-l-2 border-neutral-800 pl-2">
                    {m.workLog.map((line, j) => (
                      <div key={j} className="truncate" title={line}>
                        {line}
                      </div>
                    ))}
                  </div>
                ) : null}
              </details>
            )}
            <div>
              {(() => {
                // 舰队消息：把开头的编排进度行剥成可折叠时间线，正文照常。普通消息 steps 恒空、走原逻辑。
                const isFleetMsg =
                  m.role === 'assistant' &&
                  (isFleetModelId(m.model) || /^⚙/.test(m.content ?? ''))
                const { steps, body } = isFleetMsg
                  ? splitFleetProgress(m.content ?? '')
                  : { steps: [] as string[], body: m.content ?? '' }
                const live = busy && i === messages.length - 1
                return (
                  <>
                    {steps.length > 0 && (
                      <details
                        open={live}
                        className="mb-1 block max-w-[85%] text-left text-xs text-neutral-500"
                      >
                        <summary className="cursor-pointer select-none">
                          {t('chat.fleetTimeline', { n: steps.length })}
                        </summary>
                        <div className="mt-1 space-y-0.5 border-l-2 border-neutral-800 pl-2">
                          {steps.map((line, j) => (
                            <div key={j} className="whitespace-pre-wrap break-words" title={line}>
                              {line}
                            </div>
                          ))}
                        </div>
                      </details>
                    )}
                    {body && (
                      <div
                        className={`inline-block px-3 py-2 rounded-lg max-w-[85%] whitespace-pre-wrap break-words text-sm select-text ${
                          m.role === 'user' ? 'bg-blue-600 text-white' : 'bg-neutral-800 text-neutral-100'
                        }`}
                      >
                        {body}
                      </div>
                    )}
                    {m.paidMediaOperation && (
                      <PaidMediaRecoveryCard
                        operationId={m.paidMediaOperation.operationId}
                        blocked={Boolean(m.paidMediaOperation.blocked)}
                        recovering={recoveringPaidMedia === m.paidMediaOperation.operationId}
                        onRetry={() => void retryPaidMedia(i)}
                        onDiscard={() => void discardPaidMediaRecovery(i)}
                      />
                    )}
                  </>
                )
              })()}
              {m.content && (
                <div
                  className={`mt-0.5 flex items-center gap-2 text-[10px] text-neutral-500 transition-opacity ${
                    m.role === 'assistant' ? 'opacity-100' : 'opacity-0 group-hover:opacity-100'
                  } ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}
                >
                  {(() => {
                    // 助手气泡在流式替换时丢了 ts → 回退用紧邻的用户消息时间（同一时刻，足够准）
                    const ts = m.ts ?? (m.role === 'assistant' ? messages[i - 1]?.ts : undefined)
                    if (!ts) return null
                    const dt = new Date(ts)
                    const ymd = `${String(dt.getFullYear()).slice(2)}.${dt.getMonth() + 1}.${dt.getDate()}`
                    const hm = dt.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' })
                    return <span className="text-neutral-500">{`${ymd} ${hm}`}</span>
                  })()}
                  {m.role === 'assistant' && (m.model || hasTokenUsage(m.usage)) && (
                    <span
                      className="max-w-[22rem] truncate text-neutral-500"
                      title={[m.model ? t('chat.modelUsed', { model: m.model }) : '', formatTokenUsage(m.usage, t)]
                        .filter(Boolean)
                        .join(' · ')}
                    >
                      {[
                        m.model ? t('chat.modelUsed', { model: m.model }) : '',
                        formatTokenUsage(m.usage, t)
                      ]
                        .filter(Boolean)
                        .join(' · ')}
                    </span>
                  )}
                  {m.role === 'assistant' && m.startedAt && m.completedAt && (
                    <span className="text-neutral-500">
                      {t('chat.elapsedDone', { time: formatElapsed(m.startedAt, m.completedAt) })}
                    </span>
                  )}
                  <button
                    onClick={() => void translateMsg(i)}
                    title={t('chat.translateThis')}
                    className="hover:text-neutral-200"
                  >
                    {t('chat.translateAct')}
                  </button>
                  <button
                    onClick={() => void copyMsg(i)}
                    title={t('chat.copyMsg')}
                    className={copiedIdx === i ? 'text-green-500' : 'hover:text-neutral-200'}
                  >
                    {copiedIdx === i ? t('chat.copied') : t('chat.copyAct')}
                  </button>
                  {m.role === 'user' && (
                    <button
                      onClick={() => retractMsg(i)}
                      title={t('chat.retract')}
                      className="inline-flex hover:text-neutral-200"
                    >
                      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M9 14 4 9l5-5" />
                        <path d="M4 9h11a5 5 0 0 1 0 10h-1" />
                      </svg>
                    </button>
                  )}
                  {m.role === 'user' && (
                    <button
                      onClick={() => deleteMsg(i)}
                      title={t('chat.deleteMsg')}
                      className="inline-flex hover:text-red-400"
                    >
                      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M3 6h18M8 6V4a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v2m1 0v14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2V6" />
                      </svg>
                    </button>
                  )}
                </div>
              )}
              {m.translated && (
                <div
                  className={`mt-1 text-xs italic ${m.role === 'user' ? 'text-blue-300' : 'text-neutral-400'}`}
                >
                  {m.translated}
                </div>
              )}
              {!m.content && !m.images?.length && !m.docs?.length && busy && i === messages.length - 1 && (
                <div className="inline-flex items-center gap-1 px-3 py-2.5 rounded-lg bg-neutral-800">
                  <span className="w-1.5 h-1.5 rounded-full bg-neutral-400 animate-bounce [animation-delay:-0.3s]" />
                  <span className="w-1.5 h-1.5 rounded-full bg-neutral-400 animate-bounce [animation-delay:-0.15s]" />
                  <span className="w-1.5 h-1.5 rounded-full bg-neutral-400 animate-bounce" />
                </div>
              )}
              {m.docs && m.docs.length > 0 && (
                <div className="mt-1 flex flex-col items-start gap-1">
                  {m.docs.map((d, j) => (
                    <DocCard key={j} doc={d} />
                  ))}
                </div>
              )}
              {m.images && m.images.length > 0 && (
                <div className="mt-1 flex flex-wrap gap-2">
                  {m.images.map((src, j) => (
                    <div key={j} className="group/img relative">
                      <ResolvedPaidMediaImage
                        src={src}
                        alt=""
                        className="max-w-[280px] rounded-lg border border-neutral-700"
                      />
                      <button
                        onClick={() =>
                          void downloadMedia(src, `纳川-图片-${m.ts ?? Date.now()}-${j + 1}.png`)
                        }
                        title={t('chat.saveImage')}
                        className="absolute right-1.5 top-1.5 rounded bg-black/60 p-1 text-white opacity-0 transition group-hover/img:opacity-100 hover:bg-black/80"
                      >
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                          <path d="m7 10 5 5 5-5" />
                          <path d="M12 15V3" />
                        </svg>
                      </button>
                    </div>
                  ))}
                </div>
              )}
              {m.video && (
                <div className="group/vid relative mt-1 inline-block">
                  <ResolvedPaidMediaVideo
                    src={m.video}
                    controls
                    className="max-w-[360px] rounded-lg border border-neutral-700"
                  />
                  <button
                    onClick={() => void downloadMedia(m.videoSrc && /^https?:/i.test(m.videoSrc) ? m.videoSrc : m.video!, `纳川-视频-${m.ts ?? Date.now()}.mp4`)}
                    title={t('chat.saveVideo')}
                    className="absolute right-1.5 top-1.5 rounded bg-black/60 p-1 text-white opacity-0 transition group-hover/vid:opacity-100 hover:bg-black/80"
                  >
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                      <path d="m7 10 5 5 5-5" />
                      <path d="M12 15V3" />
                    </svg>
                  </button>
                </div>
              )}
              {m.actions && m.actions.length > 0 && (
                <div className="mt-1 space-y-1">
                  {m.actions.map((act, ai) => {
                    const { add, del } = diffStat(act.before, act.after)
                    return (
                      <div
                        key={ai}
                        className="inline-block text-left border border-neutral-700 rounded-md px-2 py-1 bg-neutral-900 max-w-[85%]"
                      >
                        <div className="flex items-center gap-2 text-xs">
                          <span className="text-neutral-300 truncate max-w-[150px]">📝 {act.path}</span>
                          <span className="text-green-500">+{add}</span>
                          <span className="text-red-400">-{del}</span>
                          {act.undo_receipt && (
                            <button
                              onClick={() => void resolveAction(i, ai, true)}
                              className="ml-2 text-neutral-400 hover:text-neutral-100"
                            >
                              {t('chat.undoEdit')}
                            </button>
                          )}
                          <button
                            onClick={() => void resolveAction(i, ai, false)}
                            className="text-neutral-400 hover:text-neutral-100"
                          >
                            {t('chat.reviewed')}
                          </button>
                        </div>
                      </div>
                    )
                  })}
                </div>
              )}
            </div>
          </div>
        ))}
      </div>

      {pendingEdits.length > 0 && (
        <div className="px-3 pt-2 border-t border-neutral-800">
          <div className="rounded border border-blue-700 bg-neutral-900 p-2">
            <div className="flex items-center justify-between mb-1">
              <span className="text-[10px] text-neutral-500">
                {pendingEdits.length > 1
                  ? t('chat.stackCount', { n: pendingEdits.length })
                  : t('chat.editPending')}
              </span>
              {pendingEdits.length > 1 && (
                <button
                  onClick={() => setStackExpanded((e) => !e)}
                  className="text-[10px] text-neutral-400 hover:text-neutral-200"
                >
                  {stackExpanded ? t('chat.collapse') : t('chat.expand')}
                </button>
              )}
            </div>
            {stackExpanded &&
              pendingEdits.slice(0, -1).map((e, k) => (
                <div
                  key={k}
                  onClick={() =>
                    setPendingEdits((prev) =>
                      prev.map((x, j) => (j === prev.length - 1 ? { ...x, text: e.text } : x))
                    )
                  }
                  title={t('chat.putToEdit')}
                  className="text-xs text-neutral-500 truncate px-1 py-0.5 mb-0.5 bg-neutral-950 rounded cursor-pointer hover:text-neutral-300"
                >
                  ↩ {e.text}
                </div>
              ))}
            <textarea
              value={pendingEdits[pendingEdits.length - 1].text}
              autoFocus
              onChange={(e) =>
                setPendingEdits((prev) =>
                  prev.map((x, j) => (j === prev.length - 1 ? { ...x, text: e.target.value } : x))
                )
              }
              onKeyDown={(e) => {
                if (e.nativeEvent.isComposing || e.keyCode === 229) return
                if (e.key === 'Enter' && !e.shiftKey) {
                  e.preventDefault()
                  const txt = pendingEdits[pendingEdits.length - 1].text
                  setPendingEdits([])
                  setStackExpanded(false)
                  void send(txt)
                }
              }}
              rows={2}
              className="w-full resize-none bg-neutral-950 border border-neutral-700 rounded px-2 py-1 text-sm text-neutral-100"
            />
            <div className="flex gap-2 mt-1 justify-end">
              <button
                onClick={() => {
                  setMessages([
                    ...messages,
                    ...pendingEdits
                      .slice()
                      .reverse()
                      .flatMap((e) => e.removed)
                  ])
                  setPendingEdits([])
                  setStackExpanded(false)
                }}
                className="px-2 py-0.5 text-xs rounded border border-neutral-700 text-neutral-400 hover:bg-neutral-800"
              >
                {t('chat.discard')}
              </button>
              <button
                onClick={() => {
                  const txt = pendingEdits[pendingEdits.length - 1].text
                  setPendingEdits([])
                  setStackExpanded(false)
                  void send(txt)
                }}
                disabled={!pendingEdits[pendingEdits.length - 1].text.trim()}
                className="px-3 py-0.5 text-xs rounded bg-blue-600 text-white disabled:opacity-40"
              >
                {t('chat.send')}
              </button>
            </div>
          </div>
        </div>
      )}
      {queued.some((q) => !q.convId || q.convId === currentConvId) && (
        <div className="px-3 pt-2 flex flex-col gap-1">
          {/* 只显示属于当前对话的排队消息（别的对话的留在队里、切回去再显示/发送） */}
          {queued.map((q, i) => ({ q, i })).filter(({ q }) => !q.convId || q.convId === currentConvId).map(({ q, i }) => (
            <div
              key={i}
              className="flex items-center gap-2 text-xs bg-neutral-900 border border-blue-800 rounded px-2 py-1"
            >
              <span className="text-blue-400 shrink-0">{t('chat.queued')}</span>
              {q.docs?.length ? <span className="shrink-0" title={t('chat.docPending')}>📄</span> : null}
              <span className="flex-1 truncate text-neutral-300">{q.text || (q.docs?.length ? q.docs[0].name : '')}</span>
              <button
                onClick={() => {
                  const item = q
                  setQueued((qs) => qs.filter((_, j) => j !== i))
                  void send(item.text, false, item.docs ?? [], item.images ?? [], true)
                }}
                className="shrink-0 rounded border border-blue-800 px-2 py-0.5 text-blue-300 hover:bg-blue-500/10"
                title={t('chat.queueNow')}
              >
                {t('chat.queueNow')}
              </button>
              <button
                onClick={() => setQueued((qs) => qs.filter((_, j) => j !== i))}
                className="text-neutral-500 hover:text-red-400"
                title={t('chat.queuedRemove')}
              >
                ✕
              </button>
            </div>
          ))}
        </div>
      )}
      {pendingImages.length > 0 && (
        <div className="px-3 pt-2">
          <div className="flex flex-wrap gap-2">
            {pendingImages.map((img, i) => (
              <div
                key={`${img.name}-${i}`}
                className="relative h-14 w-14 overflow-hidden rounded-md border border-neutral-700 bg-neutral-900"
                title={img.name}
              >
                <img src={img.url} alt="" className="h-full w-full object-cover" />
                <button
                  onClick={() => {
                    URL.revokeObjectURL(img.url)
                    setPendingImages((p) => p.filter((_, j) => j !== i))
                  }}
                  className="absolute right-0.5 top-0.5 h-5 w-5 rounded bg-neutral-950/80 text-xs text-neutral-300 hover:text-red-300"
                  title={t('chat.queuedRemove')}
                >
                  ✕
                </button>
              </div>
            ))}
            <div className="flex h-14 min-w-28 items-center rounded-md border border-neutral-800 bg-neutral-900/70 px-2 text-xs text-neutral-400">
              {t('chat.pendingImages', { n: pendingImages.length, max: MAX_PENDING_IMAGES })}
            </div>
          </div>
        </div>
      )}
      {pendingDocs.length > 0 && (
        <div className="px-3 pt-2 flex flex-wrap gap-2">
          {pendingDocs.map((d, i) => (
            <div
              key={i}
              className="inline-flex items-center gap-2 bg-neutral-900 border border-neutral-700 rounded px-2 py-1 max-w-[260px]"
              title={d.name}
            >
              <span className="text-base leading-none">📄</span>
              <span className="text-xs text-neutral-300 truncate">{d.name}</span>
              <span className="text-[10px] text-neutral-500 shrink-0">
                {t('chat.docChars', { n: d.content.length })}
              </span>
              <button
                onClick={() => setPendingDocs((p) => p.filter((_, j) => j !== i))}
                className="text-neutral-500 hover:text-red-400 shrink-0"
                title={t('chat.queuedRemove')}
              >
                ✕
              </button>
            </div>
          ))}
        </div>
      )}
      <div className="nachuan-composer-region p-2 border-t border-neutral-800">
        <div className="nachuan-composer-card rounded-2xl border border-neutral-700 bg-neutral-950 px-3 pt-1.5 pb-1.5 shadow-lg">
          {workTarget && (
            <div className="mb-1 flex items-center gap-1 rounded-md border border-neutral-800 bg-neutral-900/70 px-2 py-1 text-xs text-neutral-400">
              <ComposerIcon type="target" className="h-4 w-4 shrink-0" />
              <span className="shrink-0 text-neutral-500">{t('chat.target')}</span>
              <span className="min-w-0 flex-1 truncate text-neutral-300" title={workTarget}>
                {workTarget}
              </span>
              <button
                type="button"
                onClick={() => setWorkTarget('')}
                className="h-5 w-5 shrink-0 rounded text-neutral-500 hover:bg-neutral-800 hover:text-neutral-100"
                title={t('chat.clearTarget')}
              >
                <ComposerIcon type="x" className="m-auto h-4 w-4" />
              </button>
            </div>
          )}
          <textarea
            ref={inputRef}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              // 中文输入法合成期(选字/上屏)的 Enter 不当发送——否则空/半成品文本触发 send 早退，
              // 表现为「按了没反应」(机主实测：发送键有时没反应的真凶)。
              if (e.nativeEvent.isComposing || e.keyCode === 229) return
              if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault()
                void send()
              }
            }}
            onPaste={(e) => {
              // 粘贴图片（含截图）：贴进输入框暂存，补文字后再发（不自动发）
              const img = Array.from(e.clipboardData.items).find((it) => it.type.startsWith('image/'))
              const f = img?.getAsFile()
              if (f) {
                e.preventDefault()
                addPendingImages([f])
                return
              }
              // 粘贴超长文 → 转「文档附件」，不撑爆输入框（短指令仍可单独打字一起发）
              const pasted = e.clipboardData.getData('text')
              if (pasted && pasted.length > DOC_THRESHOLD) {
                e.preventDefault()
                addPendingDoc(pastedDocName(pasted), pasted)
              }
            }}
            rows={1}
            placeholder={t('chat.placeholder')}
            className="w-full resize-none bg-transparent px-1 py-1 text-sm text-neutral-100 placeholder:text-neutral-600 outline-none max-h-60 overflow-y-auto"
          />
          <input
            ref={fileRef}
            type="file"
            multiple
            accept="image/*,video/*,text/*,.md,.markdown,.txt,.csv,.tsv,.json,.log,.yml,.yaml,.toml,.ini,.xml,.html,.htm,.tex,.srt,.vtt"
            className="hidden"
            onChange={(e) => {
              const files = Array.from(e.target.files ?? [])
              if (files.length) void onPickFiles(files)
              e.target.value = ''
            }}
          />
          <div className="mt-1 flex items-center justify-between gap-2">
            <div className="min-w-0 flex items-center gap-1">
              <ComposerMenu
                runtimeKind={window.api.runtimeKind}
                runtimeCapabilities={window.api.runtimeCapabilities}
                target={workTarget}
                onPickFile={() => fileRef.current?.click()}
                onPickFolder={() => void onPickFolder()}
                onTargetChange={setWorkTarget}
                onPlanMode={() => setExecMode('plan')}
              />
              {input.length > DOC_THRESHOLD && (
                <button
                  onClick={() => {
                    addPendingDoc(pastedDocName(input), input)
                    setInput('')
                  }}
                  disabled={busy}
                  title={t('chat.toDoc')}
                  className="h-8 w-8 shrink-0 flex items-center justify-center rounded-md border border-blue-700 text-blue-400 hover:bg-blue-500/10 disabled:opacity-40"
                >
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M14 2H7a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V7Z" />
                    <path d="M14 2v5h5" />
                    <path d="M8 13h8" />
                    <path d="M8 17h5" />
                  </svg>
                </button>
              )}
              <ExecPermissionMenu value={execMode} onChange={setExecMode} />
            </div>

            <div className="shrink-0 flex items-center gap-1">
              {transcribing && (
                <span className="text-xs text-blue-400 animate-pulse px-1 whitespace-nowrap">
                  {t('chat.transcribing')}
                </span>
              )}
              <select
                value={reasoningLevel}
                onChange={(e) => setReasoningLevel(e.target.value as ReasoningLevel)}
                disabled={busy}
                title={t('chat.reasoningLevel')}
                className="h-8 rounded-md border border-neutral-800 bg-neutral-950 px-2 text-xs text-neutral-300 outline-none hover:bg-neutral-900 disabled:opacity-40"
              >
                <option value="low">{t('chat.reason_low')}</option>
                <option value="medium">{t('chat.reason_medium')}</option>
                <option value="high">{t('chat.reason_high')}</option>
              </select>
              <button
                onClick={() => void toggleRecord()}
                disabled={transcribing}
                title={
                  transcribing ? t('chat.transcribing') : recording ? t('chat.micStop') : t('chat.micTitle')
                }
                className={`relative h-8 w-8 flex items-center justify-center overflow-hidden rounded-md ${
                  recording
                    ? 'text-red-400 bg-red-500/10'
                    : 'text-neutral-400 hover:bg-neutral-800'
                }`}
              >
                {recording && (
                  <span className="absolute inset-x-1 bottom-1 flex h-4 items-end justify-center gap-0.5">
                    {[0.45, 0.75, 1, 0.65, 0.5].map((scale, idx) => (
                      <span
                        key={idx}
                        className="w-0.5 rounded-full bg-red-300 transition-[height] duration-75"
                        style={{ height: `${4 + micLevel * 18 * scale}px` }}
                      />
                    ))}
                  </span>
                )}
                <svg
                  width="18"
                  height="18"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1.6"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  className={recording ? 'opacity-35' : undefined}
                >
                  <rect x="9" y="2" width="6" height="11" rx="3" />
                  <path d="M5 10a7 7 0 0 0 14 0" />
                  <line x1="12" y1="17" x2="12" y2="21" />
                  <line x1="8" y1="21" x2="16" y2="21" />
                </svg>
              </button>
              <button
                onClick={() => void send()}
                disabled={
                  paidVideoSubmissionInFlight ||
                  !currentModel ||
                  (!input.trim() && pendingImages.length === 0 && pendingDocs.length === 0)
                }
                title={busy && input.trim() ? t('chat.queue') : t('chat.send')}
                className="h-9 w-9 flex items-center justify-center rounded-full bg-neutral-100 text-neutral-950 hover:opacity-90 disabled:opacity-40"
              >
                <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M12 19V5" />
                  <path d="m5 12 7-7 7 7" />
                </svg>
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
