import type { ModelInfo, TokenUsage } from './store'
import type { CatalogModel } from './env'
export type { CatalogModel } from './env'
import {
  abandonUndispatchedPaidMediaOperation,
  claimPaidMediaOperation,
  completePaidMediaOperation,
  discardPendingPaidMediaOperation,
  executePaidMediaOperation,
  listRecoverablePaidMediaArchives,
  listPendingPaidMediaOperations,
  PaidMediaJournalError,
  PaidMediaOperationExpiredError,
  PaidMediaOperationMismatchError,
  recoverPaidMediaArchive,
  type PaidMediaArchiveDiscovery,
  type PaidMediaArchiveDiscoveryPage,
  type PaidMediaArchiveRecovery,
  type PaidMediaDeliveryProof,
  type PaidMediaPath,
  type PaidMediaRequestOptions,
  type PendingPaidMediaOperation
} from './paid-media-journal'

type RendererEngineRequest = Parameters<typeof window.api.engineRequest>[0]
type RendererEngineResponse = Awaited<ReturnType<typeof window.api.engineRequest>>
type RendererEngineUploadRequest = Parameters<typeof window.api.engineUpload>[0]
type RendererEngineStreamEvent = Parameters<
  Parameters<typeof window.api.engineStream>[1]
>[0]

export {
  completePaidMediaOperation,
  discardPendingPaidMediaOperation,
  listRecoverablePaidMediaArchives,
  listPendingPaidMediaOperations,
  PaidMediaJournalError,
  PaidMediaOperationExpiredError,
  PaidMediaOperationMismatchError,
  recoverPaidMediaArchive
}
export type {
  PaidMediaArchiveDiscovery,
  PaidMediaArchiveDiscoveryPage,
  PaidMediaArchiveRecovery,
  PaidMediaDeliveryProof,
  PaidMediaRequestOptions,
  PendingPaidMediaOperation
}

function nextEngineRequestId(): string {
  return globalThis.crypto.randomUUID()
}

function abortError(): DOMException {
  return new DOMException('The operation was aborted', 'AbortError')
}

async function invokeEngineRequest(
  input: Omit<RendererEngineRequest, 'requestId'>,
  signal?: AbortSignal
): Promise<RendererEngineResponse> {
  if (signal?.aborted) throw abortError()
  const requestId = nextEngineRequestId()
  const abort = (): void => window.api.cancelEngineRequest(requestId)
  signal?.addEventListener('abort', abort, { once: true })
  try {
    const response = await window.api.engineRequest({ requestId, ...input })
    // Main may race and complete just after cancellation.  A late success must
    // never be committed into UI/history after the user withdrew the Turn.
    if (signal?.aborted) throw abortError()
    return response
  } catch (error) {
    if (signal?.aborted) throw abortError()
    throw error
  } finally {
    signal?.removeEventListener('abort', abort)
  }
}

function decodeEngineBody(body: Uint8Array): string {
  return new TextDecoder('utf-8', { fatal: true }).decode(body)
}

function mimeEssence(contentType: string): string {
  return contentType.split(';', 1)[0].trim().toLowerCase()
}

function isJsonContentType(contentType: string): boolean {
  return mimeEssence(contentType) === 'application/json'
}

function checkedJsonResponse<T>(response: RendererEngineResponse): T {
  const text = decodeEngineBody(response.body)
  if (response.status < 200 || response.status >= 300) {
    throw new Error(`${response.status} ${text}`)
  }
  return JSON.parse(text) as T
}

export async function apiGet<T = unknown>(path: string): Promise<T> {
  return checkedJsonResponse<T>(
    await invokeEngineRequest({
      method: 'GET',
      target: path,
      bodyKind: 'none',
      responseKind: 'json'
    })
  )
}

type EngineHealthDocument = {
  status?: unknown
  readiness?: unknown
  checks?: { financial_ledger?: { required?: unknown; ready?: unknown } }
}

export type EngineProbeStatus = 'online' | 'degraded' | 'offline'

export async function probeEngineStatus(): Promise<EngineProbeStatus> {
  try {
    const health = await apiGet<EngineHealthDocument>('/health')
    if (health.status !== 'ok') return 'offline'
    return health.readiness === 'ok' &&
      health.checks?.financial_ledger?.required === true &&
      health.checks.financial_ledger.ready === true
      ? 'online'
      : 'degraded'
  } catch {
    return 'offline'
  }
}

export async function probeEngine(): Promise<boolean> {
  return (await probeEngineStatus()) === 'online'
}

export async function apiPost<T = unknown>(
  path: string,
  body: unknown,
  signal?: AbortSignal
): Promise<T> {
  const encoded = JSON.stringify(body)
  if (typeof encoded !== 'string') throw new Error('Engine request body is not serializable')
  return checkedJsonResponse<T>(
    await invokeEngineRequest(
      {
        method: 'POST',
        target: path,
        bodyKind: 'json',
        body: encoded,
        responseKind: 'json'
      },
      signal
    )
  )
}

async function apiPostBinary<T>(
  target: string,
  blob: Blob,
  signal?: AbortSignal
): Promise<T> {
  if (signal?.aborted) throw abortError()
  if (!blob || !Number.isSafeInteger(blob.size) || blob.size < 0) {
    throw new Error('Engine upload body is invalid')
  }
  const requestId = nextEngineRequestId()
  const abort = (): void => window.api.cancelEngineRequest(requestId)
  signal?.addEventListener('abort', abort, { once: true })
  try {
    const response = await window.api.engineUpload(
      {
        requestId,
        method: 'POST',
        target,
        bodyKind: 'binary',
        bodyLength: blob.size,
        responseKind: 'json'
      } satisfies RendererEngineUploadRequest,
      async (offset, maximumBytes) => {
        if (signal?.aborted) throw abortError()
        if (
          !Number.isSafeInteger(offset) ||
          offset < 0 ||
          !Number.isSafeInteger(maximumBytes) ||
          maximumBytes < 1 ||
          offset >= blob.size
        ) {
          throw new Error('Engine upload credit is invalid')
        }
        const end = Math.min(blob.size, offset + maximumBytes)
        const chunk = new Uint8Array(await blob.slice(offset, end).arrayBuffer())
        if (signal?.aborted) throw abortError()
        if (chunk.byteLength < 1 || chunk.byteLength > maximumBytes) {
          throw new Error('Engine upload chunk is invalid')
        }
        return chunk
      }
    )
    return checkedJsonResponse<T>(response)
  } catch (error) {
    if (signal?.aborted) throw abortError()
    throw error
  } finally {
    signal?.removeEventListener('abort', abort)
  }
}

async function* engineStreamEvents(
  input: Omit<RendererEngineRequest, 'requestId'>,
  signal?: AbortSignal
): AsyncGenerator<RendererEngineStreamEvent> {
  if (signal?.aborted) throw abortError()
  const requestId = nextEngineRequestId()
  let pending: { event: RendererEngineStreamEvent; release: () => void } | null = null
  let settled = false
  let failure: unknown
  let wake: (() => void) | null = null
  const notify = (): void => {
    const current = wake
    wake = null
    current?.()
  }
  const abort = (): void => window.api.cancelEngineRequest(requestId)
  signal?.addEventListener('abort', abort, { once: true })
  const done = window.api
    .engineStream(
      { requestId, ...input },
      (event) =>
        new Promise<void>((resolve, reject) => {
          if (pending) {
            reject(new Error('Engine stream exceeded its in-flight credit'))
            return
          }
          pending = { event, release: resolve }
          notify()
        })
    )
    .then(
      () => {
        settled = true
        notify()
      },
      (error) => {
        failure = error
        settled = true
        notify()
      }
    )
  try {
    while (!settled || pending) {
      const current = pending as {
        event: RendererEngineStreamEvent
        release: () => void
      } | null
      if (current) {
        pending = null
        try {
          yield current.event
        } finally {
          current.release()
        }
        continue
      }
      await new Promise<void>((resolve) => {
        wake = resolve
      })
    }
    if (failure !== undefined) {
      if (signal?.aborted) throw abortError()
      throw failure
    }
  } finally {
    const current = pending as {
      event: RendererEngineStreamEvent
      release: () => void
    } | null
    pending = null
    current?.release()
    signal?.removeEventListener('abort', abort)
    if (!settled) window.api.cancelEngineRequest(requestId)
    void done
  }
}

async function engineBinaryBlob(
  target: string,
  signal?: AbortSignal
): Promise<Blob> {
  let status = 0
  let contentType = ''
  const events = engineStreamEvents(
    {
      method: 'GET',
      target,
      bodyKind: 'none',
      responseKind: 'binary'
    },
    signal
  )
  const stream = new ReadableStream<Uint8Array>({
    async pull(controller) {
      while (true) {
        const next = await events.next()
        if (next.done) {
          controller.close()
          return
        }
        if (next.value.kind === 'start') {
          status = next.value.status
          contentType = next.value.contentType
          continue
        }
        controller.enqueue(next.value.chunk)
        return
      }
    },
    async cancel() {
      await events.return(undefined)
    }
  })
  const body = await new Response(stream).blob()
  if (status < 200 || status >= 300) {
    const detail = await body.text()
    throw new Error(`${status} ${detail}`)
  }
  return new Blob([body], { type: contentType })
}

export class PaidMediaRequestError extends Error {
  readonly operationId: string
  readonly status: number
  readonly recoverable: boolean
  readonly retryAfterSeconds?: number

  constructor(
    message: string,
    options: {
      operationId: string
      status: number
      recoverable: boolean
      retryAfterSeconds?: number
      cause?: unknown
    }
  ) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause })
    this.name = 'PaidMediaRequestError'
    this.operationId = options.operationId
    this.status = options.status
    this.recoverable = options.recoverable
    this.retryAfterSeconds = options.retryAfterSeconds
  }
}

async function paidMediaPost<T>(
  path: PaidMediaPath,
  body: unknown,
  isSemanticSuccess: (value: unknown) => value is T,
  signal?: AbortSignal,
  options?: Pick<PaidMediaRequestOptions, 'operationId' | 'onOperationClaimed'>
): Promise<{
  operationId: string
  result: T
  deliveryProof: PaidMediaDeliveryProof
}> {
  const encodedBody = JSON.stringify(body)
  const operation = await claimPaidMediaOperation(
    path,
    encodedBody,
    options?.operationId === undefined ? undefined : { operationId: options.operationId }
  )
  if (options?.operationId === undefined && options?.onOperationClaimed) {
    try {
      await options.onOperationClaimed(operation.operationId)
    } catch (error) {
      // Main has not dispatched yet.  It may terminalize only a zero-dispatch
      // claim and retains a tombstone instead of deleting financial history.
      try {
        await abandonUndispatchedPaidMediaOperation(
          operation.operationId,
          'renderer recovery anchor failed before dispatch'
        )
      } catch {
        // If the main process cannot prove it remained undispatched, the record
        // stays unresolved and therefore blocks a fresh paid operation.
      }
      throw new PaidMediaJournalError(
        'Cannot persist the paid media recovery reference before sending',
        { cause: error }
      )
    }
  }
  let response
  try {
    response = await executePaidMediaOperation(
      operation.operationId,
      path,
      encodedBody,
      signal
    )
  } catch (error) {
    throw new PaidMediaRequestError('Paid media main-process dispatch failed safely', {
      operationId: operation.operationId,
      status: 0,
      recoverable: true,
      cause: error
    })
  }
  if (!response.ok) {
    throw new PaidMediaRequestError(response.detail, {
      operationId: operation.operationId,
      status: response.status,
      recoverable: response.recoverable,
      ...(response.retryAfterSeconds === undefined
        ? {}
        : { retryAfterSeconds: response.retryAfterSeconds })
    })
  }
  if (!isSemanticSuccess(response.result)) {
    // Main already retained this exact operation as result_ready.  Leaving it
    // unresolved is the safe state: an explicit retry reuses the same key.
    throw new PaidMediaRequestError(
      'Paid media success response is missing a usable result receipt',
      {
        operationId: operation.operationId,
        status: response.status,
        recoverable: true
      }
    )
  }
  return {
    operationId: operation.operationId,
    result: response.result,
    deliveryProof: response.deliveryProof
  }
}

async function acknowledgeDurablePaidMediaResult<TResult>(
  deliveryProof: PaidMediaDeliveryProof,
  result: TResult,
  callback: PaidMediaRequestOptions<TResult>['onResultDurablyCommitted']
): Promise<void> {
  const operationId = deliveryProof.operationId
  // Safe default: an API caller that forgets the durable-result callback leaks
  // one pending record instead of opening a duplicate-charge window.
  if (!callback) return
  let committed = false
  try {
    committed = (await callback(operationId, result, deliveryProof)) === true
  } catch (error) {
    throw new PaidMediaRequestError('Paid media result could not be durably committed', {
      operationId,
      status: 200,
      recoverable: true,
      cause: error
    })
  }
  if (!committed) {
    throw new PaidMediaRequestError('Paid media result could not be durably committed', {
      operationId,
      status: 200,
      recoverable: true
    })
  }
  try {
    await completePaidMediaOperation(deliveryProof)
  } catch (error) {
    // The result is durable, but retaining the same operation is safer than
    // allowing a new key while journal cleanup is uncertain.
    throw new PaidMediaRequestError('Paid media result is durable but journal cleanup failed', {
      operationId,
      status: 200,
      recoverable: true,
      cause: error
    })
  }
}

// ── 经发布清单验证的本地模型（可选/可切换）──
export interface LocalModelInfo {
  id: string
  name: string
  size_mb: number
  desc: string
  downloaded: boolean
  active: boolean
}
export interface LocalCatalog {
  enabled: boolean
  ready?: boolean
  attested?: boolean
  active: string
  models: LocalModelInfo[]
}
/** 内置本地模型目录 + 当前激活/下载状态。 */
export async function fetchLocalCatalog(): Promise<LocalCatalog> {
  return apiGet<LocalCatalog>('/v1/local/catalog')
}
/** 选/切换本地模型：仅验证过的固定版本可启动或下载。 */
export async function selectLocalModel(
  modelId: string,
  opts?: { task?: string; approval_id?: number; user_id?: string }
): Promise<Record<string, unknown>> {
  return apiPost('/v1/local/select', { model_id: modelId, ...opts })
}

// ── 知识库（IMA）：导入文档 / 列表 / 删除 / 据实带引用问答 ──
export interface KbDoc {
  id: number
  title: string
  source: string
  chunks: number
  created_at: number
}
export interface KbSource {
  doc_id: number
  title: string
  score: number
}
export async function fetchKbDocs(userId = 'owner'): Promise<KbDoc[]> {
  return (await apiGet<{ docs: KbDoc[] }>(`/v1/kb/docs?user_id=${encodeURIComponent(userId)}`)).docs
}
export async function importKbDoc(
  title: string,
  text: string,
  userId = 'owner'
): Promise<{ doc_id: number; chunks: number }> {
  return apiPost('/v1/kb/docs', { user_id: userId, title, text })
}
export interface DestructiveResult {
  ok?: boolean
  needs_approval?: boolean
  approval_id?: number
  summary?: string
}
export function deleteKbDoc(
  docId: number,
  userId = 'owner',
  approvalId?: number
): Promise<DestructiveResult> {
  return apiPost(`/v1/kb/docs/${docId}/delete`, {
    user_id: userId,
    ...(approvalId ? { approval_id: approvalId } : {})
  })
}
export async function queryKb(
  query: string,
  userId = 'owner'
): Promise<{ answer: string; sources: KbSource[]; model?: string; usage?: TokenUsage }> {
  return apiPost('/v1/kb/query', { user_id: userId, query })
}
// 模型判意图（#17）：比关键词正则准。失败由调用方 .catch 回退正则结果。
export async function classifyIntent(message: string): Promise<string> {
  return (await apiPost<{ intent: string }>('/v1/intent', { message })).intent || 'chat'
}
// 网页抓正文 + 总结（贴链接→AI 读内容）。视频链接请走拉片。
export interface WebReadResult {
  title: string
  url: string
  summary: string
  chars: number
  model?: string
  usage?: TokenUsage
}
export function webRead(url: string, question = ''): Promise<WebReadResult> {
  return apiPost('/v1/web/read', { url, question })
}

// ── 视频工作室（创作线·①②出方案+调教）──
export interface StudioShot {
  n: number
  desc: string
  seconds: number
  motion: string
}
export interface StudioPlan {
  title: string
  style: string
  subject?: string
  shots: StudioShot[]
  raw?: string
}
/** 出/改分镜方案：首次给 goal；调教时给 feedback + 现有 plan。 */
export async function studioPlan(
  goal: string,
  feedback = '',
  plan?: StudioPlan
): Promise<StudioPlan> {
  return (await apiPost<{ plan: StudioPlan }>('/v1/studio/plan', { goal, feedback, plan })).plan
}
export interface StudioJob {
  status: string
  progress: number
  total: number
  msg: string
  video: string
  error: string
  partial?: boolean // true=部分镜失败，成片偏短、不足目标时长（如实告知，别当完整片）
}
export async function studioExecute(
  plan: StudioPlan,
  opts?: { task?: string; approval_id?: number; user_id?: string }
): Promise<{ job_id?: string; needs_approval?: boolean; approval_id?: number; summary?: string }> {
  return apiPost('/v1/studio/execute', { plan, ...opts })
}
export async function studioJob(jobId: string): Promise<StudioJob> {
  return apiGet(`/v1/studio/execute/${encodeURIComponent(jobId)}`)
}
/** 取成片视频（带鉴权）→ 本地 object URL，喂给 <video src>。 */
export async function studioVideoBlobUrl(jobId: string): Promise<string> {
  return URL.createObjectURL(
    await engineBinaryBlob(`/v1/studio/video/${encodeURIComponent(jobId)}`)
  )
}

/** 引擎代下海外成片（agnes-ai.space 等）→ 本地 blob URL，喂给 <video src>。
 *  前端直连海外域名常拉不动（灰播放键）；引擎能连上游，让它代下最稳。失败时上层回退用原 URL。 */
export async function videoBlobUrl(url: string): Promise<string> {
  if (isDurablePaidMediaAssetRef(url)) return url
  return URL.createObjectURL(
    await engineBinaryBlob(`/v1/videos/fetch?url=${encodeURIComponent(url)}`)
  )
}

// ── 每日 AI 资讯视频：按 D:\AI视频制作 RUNBOOK 点火，不走通用 agent 循环 ──
export interface DailyVideoStartResult {
  ok?: boolean
  date?: string
  root?: string
  episode_dir?: string
  task?: string
  runner_log?: string
  duo_log?: string
  stdout?: string
  message?: string
  needs_approval?: boolean
  approval_id?: number
  summary?: string
}
export function startDailyVideo(
  root?: string,
  date?: string,
  signal?: AbortSignal,
  opts?: { task?: string; approval_id?: number; user_id?: string }
): Promise<DailyVideoStartResult> {
  return apiPost('/v1/workflows/daily-video/start', { root, date, ...opts }, signal)
}

/** 可选本地语音实验接口；text-first 发行版未携带运行库时会明确返回 503。 */
export async function transcribeAudio(blob: Blob, language?: string): Promise<string> {
  const q = language ? `?language=${encodeURIComponent(language)}` : ''
  return (
    await apiPostBinary<{ text?: string }>(`/v1/audio/transcriptions${q}`, blob)
  ).text ?? ''
}

/** 语音转写模型档：tiny 最快 / base 均衡 / small 最准。界面可直接切换。 */
export async function getAudioModel(): Promise<{ model: string; options: string[] }> {
  return apiGet<{ model: string; options: string[] }>('/v1/audio/model')
}
export async function setAudioModel(model: string): Promise<{ model: string }> {
  return apiPost<{ model: string }>('/v1/audio/model', { model })
}

/** 实时翻译（D2）：把文本译成 target（默认 en），走自家免费模型。 */
export async function translateText(text: string, target = 'en'): Promise<string> {
  const r = await apiPost<{ translated?: string }>('/v1/translate', { text, target })
  return r.translated ?? ''
}

export interface ExecResult {
  result: string
  backend?: string
  cost_usd?: number
  workdir?: string
  // P5 重大事项前置闸：高风险动作返回 needs_approval=true；审批后用一次性 approval_id 重发。
  needs_approval?: boolean
  approval_id?: number
  summary?: string
  risk?: string
}
/** 执行 Agent（F1）：让当前启用的原生执行器处理文件/命令。mode: plan/auto/full。 */
export function agentExec(
  task: string,
  opts?: {
    backend?: string
    mode?: string
    model?: string
    workdir?: string
    approval_id?: number
    user_id?: string
    /** 当前指令原句（task 可能拼了历史大字报；审批 summary 用它，别吓人） */
    instruction?: string
    signal?: AbortSignal
  }
): Promise<ExecResult> {
  const { signal, ...rest } = opts ?? {}
  return apiPost<ExecResult>('/v1/agent/exec', { task, ...rest }, signal)
}

// ── P5/P6 人工审核分级：待审清单 + 裁决（同意/换方案/取消） ──
export interface Approval {
  id: number
  kind: 'action' | 'skill_card'
  summary: string
  payload: Record<string, unknown>
  status: string
  created_at?: number
}
export function listApprovals(userId = 'owner'): Promise<Approval[]> {
  return window.api.listApprovals(userId).then((r) => r.pending || [])
}
export function resolveApproval(
  id: number,
  decision: 'approve' | 'reject' | 'revise',
  note = ''
): Promise<{ status: string; case_id?: number }> {
  return window.api.resolveApproval({ id, decision, note })
}

// 通用 Agent 循环：任何会 function-calling 的模型（agnes/glm/kimi/gpt…）用工具（浏览器/文件/命令）
export interface FileChange {
  path: string
  before: string
  after: string
  undo_receipt?: string
}
export interface AgentRunResult {
  reply: string
  steps: number
  model?: string
  usage?: TokenUsage
  tool_log?: string[]
  file_changes?: FileChange[]
  media?: string[]
  pending_videos?: PendingVideo[] // #6：异步生视频任务，前端轮询到成片自动贴回
  needs_approval?: boolean
  approval_id?: number
  summary?: string
  risk?: string
  scope?: string
}
export function agentRun(
  task: string,
  model: string | undefined,
  opts?: {
    workdir?: string
    allow?: string[]
    max_steps?: number
    history?: ChatMsg[]
    mode?: string
    approval_id?: number
    orchestrate?: boolean
    user_id?: string
    signal?: AbortSignal
  }
): Promise<AgentRunResult> {
  const { signal, ...rest } = opts ?? {}
  // model 为空 → 不传，让后端按任务复杂度自动路由（不再默认便宜模型）。
  return apiPost<AgentRunResult>('/v1/agent/run', { task, ...(model ? { model } : {}), ...rest }, signal)
}

export interface AgentJobResult {
  job_id?: string
  id?: string
  status?: string
  needs_approval?: boolean
  approval_id?: number
  summary?: string
}

export function createAgentJob(
  goal: string,
  opts?: {
    steps?: Record<string, unknown>[]
    workdir?: string
    backend?: string
    mode?: string
    approval_id?: number
    user_id?: string
  }
): Promise<AgentJobResult> {
  return apiPost<AgentJobResult>('/v1/agent/job', { goal, ...(opts ?? {}) })
}

export function resumeAgentJob(
  jobId: string,
  opts?: {
    workdir?: string
    backend?: string
    mode?: string
    approval_id?: number
    user_id?: string
  }
): Promise<AgentJobResult> {
  return apiPost<AgentJobResult>(`/v1/agent/job/${encodeURIComponent(jobId)}/resume`, opts ?? {})
}

// 编排型 super-agent 的实时进度事件（后端 run_orchestrated_agent 的 on_event → SSE）。
// type ∈ route/plan/step/verify/replan/escalate/done + 末尾 result（带完整结果 dict）/ error。
export interface AgentEvent {
  type:
    | 'route'
    | 'plan'
    | 'step'
    | 'verify'
    | 'replan'
    | 'escalate'
    | 'done'
    | 'result'
    | 'error'
    | 'pending_video' // 视频任务派发即推（插队/中断也不丢任务，前端立即建锚点轮询）
  [k: string]: unknown
}

/** 运行中插话（steering）：agent 任务跑着时把话注入循环——任务不打断、下一步吸收。
 *  返回 false = 该对话没有运行中任务（前端应走普通发送/排队）。 */
export async function agentInject(conversationId: string, message: string): Promise<boolean> {
  try {
    const r = await apiPost<{ injected?: boolean }>('/v1/agent/inject', {
      conversation_id: conversationId,
      message
    })
    return Boolean(r?.injected)
  } catch {
    return false // 引擎旧版没这端点/网络抖动 → 走普通发送，别拦着用户说话
  }
}

/**
 * 流式跑编排型 agent：POST /v1/agent/run (stream:true)，边执行边回 SSE 事件。
 * 每收到一个事件调 onEvent(ev)；收到 type:'result' 用其 result 作为最终结果 resolve；
 * 遇 type:'error' 抛错。仿照本文件 chatStream 的读取（getReader + TextDecoder + 按 data: 切行）。
 * model 为 undefined 时不传（让后端按复杂度自动路由到够强的模型）；显式传才尊重。
 */
export async function agentRunStream(
  task: string,
  model: string | undefined,
  opts: {
    workdir?: string
    allow?: string[]
    max_steps?: number
    history?: ChatMsg[]
    conversation_id?: string
    mode?: string
    approval_id?: number
    user_id?: string
    onEvent?: (ev: AgentEvent) => void
    signal?: AbortSignal
  }
): Promise<AgentRunResult> {
  const { onEvent, signal, ...rest } = opts
  // 空转保险丝（机主实测 139 分钟转圈）：流上超过这么久没有任何新事件 → 判定上游挂死，
  // 主动断流报人话错误，绝不让"已运行 xx 分钟"永远转下去。每来一个事件就续命。
  const IDLE_MS = 300_000
  const idleCtl = new AbortController()
  const forwardAbort = (): void => idleCtl.abort()
  if (signal) signal.addEventListener('abort', forwardAbort, { once: true })
  let idleTimer = setTimeout(() => idleCtl.abort(), IDLE_MS)
  const feed = (): void => {
    clearTimeout(idleTimer)
    idleTimer = setTimeout(() => idleCtl.abort(), IDLE_MS)
  }
  try {
    const decoder = new TextDecoder()
    let buf = ''
    let result: AgentRunResult | null = null
    let status = 0
    let contentType = ''
    const jsonChunks: Uint8Array[] = []
    const encoded = JSON.stringify({
      task,
      stream: true,
      ...(model ? { model } : {}),
      ...rest
    })
    try {
      for await (const transportEvent of engineStreamEvents(
        {
          method: 'POST',
          target: '/v1/agent/run',
          bodyKind: 'json',
          body: encoded,
          responseKind: 'stream'
        },
        idleCtl.signal
      )) {
        feed()
        if (transportEvent.kind === 'start') {
          status = transportEvent.status
          contentType = transportEvent.contentType
          continue
        }
        if (isJsonContentType(contentType)) {
          jsonChunks.push(transportEvent.chunk)
          continue
        }
        buf += decoder.decode(transportEvent.chunk, { stream: true })
        const lines = buf.split('\n')
        buf = lines.pop() ?? ''
        for (const line of lines) {
          const s = line.trim()
          if (!s.startsWith('data:')) continue
          const payload = s.slice(5).trim()
          if (payload === '[DONE]') {
            if (result) return result
            throw new Error('agent stream ended without result')
          }
          let ev: AgentEvent
          try {
            ev = JSON.parse(payload) as AgentEvent
          } catch {
            continue // 忽略心跳/不完整片段
          }
          if (ev.type === 'error') throw new Error(String(ev.message ?? 'agent error'))
          if (ev.type === 'result') {
            result = (ev.result ?? {}) as AgentRunResult
            continue // 最终回复在 result 里，别当普通事件推给 UI
          }
          onEvent?.(ev)
        }
      }
    } catch (error) {
      if (idleCtl.signal.aborted && !signal?.aborted) {
        throw new Error(t_idleAgentStream())
      }
      throw error
    }
    if (isJsonContentType(contentType)) {
      const payloadText = new TextDecoder().decode(
        await new Blob(jsonChunks.map((chunk) => Uint8Array.from(chunk).buffer)).arrayBuffer()
      )
      const payload = JSON.parse(payloadText) as AgentRunResult
      if (status < 200 || status >= 300) throw new Error(`${status} ${payloadText}`)
      return payload
    }
    if (status < 200 || status >= 300) throw new Error(`${status}`)
    if (buf.trim()) {
      const lines = buf.split('\n')
      for (const line of lines) {
        const s = line.trim()
        if (!s.startsWith('data:')) continue
        const payload = s.slice(5).trim()
        if (payload === '[DONE]') {
          if (result) return result
          throw new Error('agent stream ended without result')
        }
        let ev: AgentEvent
        try {
          ev = JSON.parse(payload) as AgentEvent
        } catch {
          continue // 忽略心跳/不完整片段
        }
        if (ev.type === 'error') throw new Error(String(ev.message ?? 'agent error'))
        if (ev.type === 'result') {
          result = (ev.result ?? {}) as AgentRunResult
          continue // 最终回复在 result 里，别当普通事件推给 UI
        }
        onEvent?.(ev)
      }
    }
    if (result) return result
    throw new Error('agent stream closed without result')
  } finally {
    clearTimeout(idleTimer)
    signal?.removeEventListener('abort', forwardAbort)
  }
}

function t_idleAgentStream(): string {
  return '执行流超过 5 分钟没有任何进展，已自动中断（上游模型可能挂死或撞限额）。可重试或换个模型。'
}
/** 撤销内联动作卡：把文件还原成改前内容。 */
export function undoFile(receipt: string, content: string): Promise<{ ok: boolean }> {
  return apiPost<{ ok: boolean }>('/v1/agent/undo', { receipt, content })
}
/** 清一个对话的引擎侧累积摘要；非空摘要必须走一次性审批。 */
export function clearConvSummary(
  convId: string,
  userId = 'owner',
  approvalId?: number
): Promise<DestructiveResult> {
  return apiPost<DestructiveResult>(`/v1/conv/${encodeURIComponent(convId)}/clear-summary`, {
    user_id: userId,
    ...(approvalId ? { approval_id: approvalId } : {})
  })
}

export async function fetchModels(): Promise<ModelInfo[]> {
  const data = await apiGet<{ data: ModelInfo[] }>('/v1/models')
  return data.data
}

export interface OrchestrationCapabilities {
  chat_model_count: number
  review_candidate_count: number
  independent_identity_count: number
  single_review_ready: boolean
  post_summary_final_review_ready: boolean
  four_vendor_review_ready: boolean
  reason: string | null
}

const MAX_ORCHESTRATION_CAPABILITY_COUNT = 256

function isCapabilityCount(value: unknown): value is number {
  return (
    typeof value === 'number' &&
    Number.isSafeInteger(value) &&
    value >= 0 &&
    value <= MAX_ORCHESTRATION_CAPABILITY_COUNT
  )
}

function isCapabilityReason(value: unknown): value is string | null {
  return (
    value === null ||
    (typeof value === 'string' &&
      value.length > 0 &&
      value.length <= 256 &&
      ![...value].some((char) => char.charCodeAt(0) < 0x20))
  )
}

/**
 * Read the prospective orchestration schedule from the engine.
 *
 * The monotonic checks deliberately fail closed: a later review tier cannot be
 * advertised unless every prerequisite tier and its minimum route counts are
 * also present.  This snapshot still is not proof that any review call ran.
 */
export async function fetchOrchestrationCapabilities(): Promise<OrchestrationCapabilities> {
  const value = await apiGet<unknown>('/v1/orchestration/capabilities')
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Invalid orchestration capability response')
  }
  const row = value as Record<string, unknown>
  const chatModelCount = row.chat_model_count
  const reviewCandidateCount = row.review_candidate_count
  const independentIdentityCount = row.independent_identity_count
  const singleReviewReady = row.single_review_ready
  const postSummaryFinalReviewReady = row.post_summary_final_review_ready
  const fourVendorReviewReady = row.four_vendor_review_ready
  const reason = row.reason

  if (
    !isCapabilityCount(chatModelCount) ||
    !isCapabilityCount(reviewCandidateCount) ||
    !isCapabilityCount(independentIdentityCount) ||
    reviewCandidateCount > chatModelCount ||
    independentIdentityCount > chatModelCount ||
    typeof singleReviewReady !== 'boolean' ||
    typeof postSummaryFinalReviewReady !== 'boolean' ||
    typeof fourVendorReviewReady !== 'boolean' ||
    !isCapabilityReason(reason) ||
    (singleReviewReady &&
      (chatModelCount < 2 || reviewCandidateCount < 1 || independentIdentityCount < 2)) ||
    (postSummaryFinalReviewReady &&
      (!singleReviewReady ||
        chatModelCount < 3 ||
        reviewCandidateCount < 2 ||
        independentIdentityCount < 3)) ||
    (fourVendorReviewReady &&
      (!postSummaryFinalReviewReady ||
        chatModelCount < 5 ||
        reviewCandidateCount < 4 ||
        independentIdentityCount < 5)) ||
    (reason === null) !== fourVendorReviewReady
  ) {
    throw new Error('Invalid orchestration capability response')
  }

  return {
    chat_model_count: chatModelCount,
    review_candidate_count: reviewCandidateCount,
    independent_identity_count: independentIdentityCount,
    single_review_ready: singleReviewReady,
    post_summary_final_review_ready: postSummaryFinalReviewReady,
    four_vendor_review_ready: fourVendorReviewReady,
    reason
  }
}

export type ChatContentPart =
  | { type: 'text'; text: string }
  | { type: 'image_url'; image_url: { url: string } }

export interface ChatMsg {
  role: 'system' | 'user' | 'assistant'
  content: string | ChatContentPart[]
}

// ── 单答模式（智能/级联/经济/最强）走 /v1/route ──
export interface RouteResult {
  choices: { message: { content: string } }[]
  _route?: { mode: string; model?: string; escalated?: boolean }
  usage?: TokenUsage
}
export function routeChat(
  mode: string,
  messages: ChatMsg[],
  signal?: AbortSignal,
  reasoningEffort?: string,
  conversationId?: string
): Promise<RouteResult> {
  return apiPost<RouteResult>(
    '/v1/route',
    {
      mode,
      messages,
      web_search: true,
      ...(reasoningEffort ? { reasoning_effort: reasoningEffort } : {}),
      ...(conversationId ? { conversation_id: conversationId } : {})
    },
    signal
  )
}

// ── 超级智能体：带长期记忆 / 案例库 / 反思（飞书与桌面共用同一引擎端点）──
export interface AgentRoute {
  label?: string
  model?: string
  reused_case_id?: number
  stored_case_id?: number
}
export type AgentOutcome =
  | 'completed'
  | 'completed_unverified'
  | 'accepted_async'
  | 'rejected_capacity'
  | 'partial'
  | 'failed'
  | 'blocked'
export interface AgentReply {
  reply: string
  model: string
  usage?: TokenUsage
  turns?: number
  memories_used?: string[]
  agent_route?: AgentRoute | null
  outcome: AgentOutcome
  blocked: boolean
  reviewed?: boolean | null
  verified?: boolean | null
  machine_verified?: boolean | null
  images?: string[]
  video?: string
  video_task?: string
}
export interface AgentChatOptions {
  userId?: string
  chatId?: string
  channel?: string
  model?: string
  signal?: AbortSignal
}

const AGENT_OUTCOMES = new Set<AgentOutcome>([
  'completed',
  'completed_unverified',
  'accepted_async',
  'rejected_capacity',
  'partial',
  'failed',
  'blocked'
])

function invalidAgentResponse(): never {
  throw new Error('Invalid Agent response')
}

function validateAgentReply(value: unknown): AgentReply {
  if (!value || typeof value !== 'object' || Array.isArray(value)) invalidAgentResponse()
  const reply = value as Record<string, unknown>
  if (
    typeof reply.reply !== 'string' ||
    typeof reply.model !== 'string' ||
    !reply.model.trim() ||
    typeof reply.outcome !== 'string' ||
    !AGENT_OUTCOMES.has(reply.outcome as AgentOutcome) ||
    typeof reply.blocked !== 'boolean'
  ) {
    invalidAgentResponse()
  }

  for (const field of ['reviewed', 'verified', 'machine_verified'] as const) {
    const item = reply[field]
    if (item !== undefined && item !== null && typeof item !== 'boolean') invalidAgentResponse()
  }
  if (
    reply.memories_used !== undefined &&
    (!Array.isArray(reply.memories_used) ||
      reply.memories_used.some((item) => typeof item !== 'string'))
  ) {
    invalidAgentResponse()
  }
  if (
    reply.images !== undefined &&
    (!Array.isArray(reply.images) || reply.images.some((item) => typeof item !== 'string'))
  ) {
    invalidAgentResponse()
  }
  if (reply.video !== undefined && typeof reply.video !== 'string') invalidAgentResponse()
  if (reply.video_task !== undefined && typeof reply.video_task !== 'string') invalidAgentResponse()
  if (
    reply.agent_route !== undefined &&
    reply.agent_route !== null &&
    (typeof reply.agent_route !== 'object' || Array.isArray(reply.agent_route))
  ) {
    invalidAgentResponse()
  }

  const outcome = reply.outcome as AgentOutcome
  const mustBeBlocked = outcome === 'blocked' || outcome === 'rejected_capacity'
  if (reply.blocked !== mustBeBlocked) invalidAgentResponse()
  if (outcome === 'completed' && (reply.verified !== true || reply.machine_verified !== true)) {
    invalidAgentResponse()
  }
  if (outcome !== 'completed' && (reply.verified === true || reply.machine_verified === true)) {
    invalidAgentResponse()
  }
  if (outcome === 'accepted_async' && !String(reply.video_task || '').trim()) {
    invalidAgentResponse()
  }
  return reply as unknown as AgentReply
}

/** 桌面端统一用 user_id='owner'（与机主飞书共享记忆），channel='desktop'。 */
export function agentChat(
  message: string,
  opts?: AgentChatOptions
): Promise<AgentReply> {
  return apiPost<unknown>(
    '/v1/agent/chat',
    {
      message,
      user_id: opts?.userId ?? 'owner',
      chat_id: opts?.chatId ?? 'desktop-main',
      channel: opts?.channel ?? 'desktop',
      ...(opts?.model ? { model: opts.model } : {})
    },
    opts?.signal
  ).then(validateAgentReply)
}

// 进化看板（M6）：查看机器人为某用户学到的记忆与案例
export interface AgentMemory {
  id: number
  text: string
  kind: string
  created_at?: number
  updated_at?: number
}
export interface AgentCase {
  id: number
  problem: string
  solution: string
  model?: string
  created_at?: number
}
export function fetchAgentMemory(userId = 'owner'): Promise<AgentMemory[]> {
  return apiGet<{ memories: AgentMemory[] }>(
    `/v1/agent/memory?user_id=${encodeURIComponent(userId)}`
  ).then((d) => d.memories)
}
export function fetchAgentCases(userId = 'owner'): Promise<AgentCase[]> {
  return apiGet<{ cases: AgentCase[] }>(`/v1/agent/cases?user_id=${encodeURIComponent(userId)}`).then(
    (d) => d.cases
  )
}
export function clearAgentMemory(
  userId = 'owner',
  approvalId?: number
): Promise<DestructiveResult> {
  return apiPost<DestructiveResult>('/v1/agent/memory/clear', {
    user_id: userId,
    ...(approvalId ? { approval_id: approvalId } : {})
  })
}

// ── 战绩看板（F6）：只读全表，每行=某模型在某任务类的胜负 + 胜率 + 最近时间 ──
export interface ScoreboardRow {
  model: string
  task_kind: string
  wins: number
  losses: number
  win_rate: number | null
  last_at: string | null
}
export function fetchScoreboard(): Promise<ScoreboardRow[]> {
  return apiGet<{ rows: ScoreboardRow[] }>('/v1/scoreboard').then((d) => d.rows ?? [])
}

export interface PendingVideo {
  task_id: string
  model: string
  prompt?: string
}
export interface ChatDelta {
  content?: string
  reasoning?: string
  model?: string
  usage?: TokenUsage
  pendingVideos?: PendingVideo[]
}

export function parseChatStreamPayload(payload: string): ChatDelta | null {
  let chunk: any
  try {
    chunk = JSON.parse(payload)
  } catch {
    return null
  }
  if (chunk?.error && typeof chunk.error === 'object') {
    const message =
      typeof chunk.error.message === 'string' && chunk.error.message.trim()
        ? chunk.error.message.trim()
        : '流式响应失败'
    const trace =
      typeof chunk.error.trace_id === 'string' && chunk.error.trace_id.trim()
        ? ` (trace_id: ${chunk.error.trace_id.trim()})`
        : ''
    throw new Error(`${message}${trace}`)
  }
  const d = chunk?.choices?.[0]?.delta
  const content: string | undefined = d?.content
  const reasoning: string | undefined = d?.reasoning_content ?? d?.reasoning
  const chunkModel: string | undefined =
    typeof chunk?.model === 'string' ? chunk.model : undefined
  const usage: TokenUsage | undefined =
    chunk?.usage && typeof chunk.usage === 'object' ? chunk.usage : undefined
  const finished = Boolean(chunk?.choices?.[0]?.finish_reason)
  const pendingVideos: PendingVideo[] | undefined = Array.isArray(chunk?._pending_videos)
    ? chunk._pending_videos
    : undefined
  return content || reasoning || chunkModel || usage || finished || pendingVideos
    ? { content, reasoning, model: chunkModel, usage, pendingVideos }
    : null
}

/** 轮询一个异步视频任务直到成片（或超时/失败）→ 返回**原始源 URL**（可持久化）。
 *  调用方负责代下成 blob 播放（videoBlobUrl）并把源存进 videoSrc，重启后可据此再代下。 */
export async function awaitVideo(
  model: string,
  taskId: string,
  opts?: { maxMs?: number; intervalMs?: number; onProgress?: (p: number) => void }
): Promise<string | null> {
  const maxMs = opts?.maxMs ?? 600_000 // 视频最多等 10 分钟
  const intervalMs = opts?.intervalMs ?? 8000
  const t0 = Date.now()
  let consecutivePollErrors = 0
  while (Date.now() - t0 < maxMs) {
    let delayMs = intervalMs
    try {
      const st = await pollVideo(model, taskId)
      const url = paidVideoTerminalAssetUrl(st)
      if (url) return url // 返回原始源；代下 blob 交给调用方（便于持久化 videoSrc、重启可再代下）
      const status = paidVideoStatusValue(st)
      if (PAID_VIDEO_FAILURE_STATUSES.has(status)) return null
      if (st.error) {
        consecutivePollErrors += 1
        delayMs = Math.min(60_000, intervalMs * 2 ** Math.min(4, consecutivePollErrors - 1))
      } else {
        consecutivePollErrors = 0
        if (typeof st.progress === 'number') opts?.onProgress?.(st.progress)
      }
    } catch {
      consecutivePollErrors += 1
      delayMs = Math.min(60_000, intervalMs * 2 ** Math.min(4, consecutivePollErrors - 1))
    }
    await new Promise((r) => setTimeout(r, delayMs))
  }
  return null
}

/** 调网关流式接口，逐段产出内容/思考增量。 */
export async function* chatStream(
  model: string,
  messages: ChatMsg[],
  signal?: AbortSignal,
  webSearch = true,
  reasoningEffort?: string,
  conversationId?: string
): AsyncGenerator<ChatDelta> {
  const encoded = JSON.stringify({
      model,
      messages,
      stream: true,
      web_search: webSearch,
      ...(reasoningEffort ? { reasoning_effort: reasoningEffort } : {}),
      ...(conversationId ? { conversation_id: conversationId } : {})
  })
  const decoder = new TextDecoder()
  let buf = ''
  let status = 0
  let contentType = ''
  const jsonChunks: Uint8Array[] = []
  for await (const event of engineStreamEvents(
    {
      method: 'POST',
      target: '/v1/chat/completions',
      bodyKind: 'json',
      body: encoded,
      responseKind: 'stream'
    },
    signal
  )) {
    if (event.kind === 'start') {
      status = event.status
      contentType = event.contentType
      continue
    }
    if (isJsonContentType(contentType)) {
      jsonChunks.push(event.chunk)
      continue
    }
    buf += decoder.decode(event.chunk, { stream: true })
    const lines = buf.split('\n')
    buf = lines.pop() ?? ''
    for (const line of lines) {
      const s = line.trim()
      if (!s.startsWith('data:')) continue
      const payload = s.slice(5).trim()
      if (payload === '[DONE]') return
      const delta = parseChatStreamPayload(payload)
      if (delta) yield delta
    }
  }
  if (isJsonContentType(contentType)) {
    const detail = new TextDecoder().decode(
      await new Blob(jsonChunks.map((chunk) => Uint8Array.from(chunk).buffer)).arrayBuffer()
    )
    throw new Error(`${status} ${detail}`)
  }
  if (status < 200 || status >= 300) throw new Error(`${status}`)
  if (buf.trim()) {
    const s = buf.trim()
    if (s.startsWith('data:')) {
      const payload = s.slice(5).trim()
      if (payload === '[DONE]') return
      const delta = parseChatStreamPayload(payload)
      if (delta) yield delta
    }
  }
  throw new Error('流式连接在 [DONE] 前意外结束')
}

// ── 连接中心 ──
export type SubscriptionConnectorState =
  | 'not_installed'
  | 'untrusted_binary'
  | 'version_unsupported'
  | 'installed_unprobed'
  | 'logged_out'
  | 'login_pending'
  | 'authenticated_unprobed'
  | 'ready'
  | 'reauth_required'
  | 'entitlement_denied'
  | 'degraded'
  | 'unavailable'

export interface SubscriptionConnector {
  id: 'codex' | 'kimi-code'
  label: string
  state: SubscriptionConnectorState
  auth: 'device_code'
  transport: 'stdio_jsonl' | 'acp_stdio'
  version: string | null
  capabilities: Array<'chat' | 'code'>
  login_supported: boolean
  logout_supported: boolean
}

const SUBSCRIPTION_CONNECTOR_STATES: ReadonlySet<string> = new Set([
  'not_installed',
  'untrusted_binary',
  'version_unsupported',
  'installed_unprobed',
  'logged_out',
  'login_pending',
  'authenticated_unprobed',
  'ready',
  'reauth_required',
  'entitlement_denied',
  'degraded',
  'unavailable'
])

function publicSubscriptionConnector(value: unknown): SubscriptionConnector | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Invalid subscription connector response')
  }
  const raw = value as Record<string, unknown>
  if (raw.id !== 'codex' && raw.id !== 'kimi-code') return null
  const id = raw.id
  const expectedTransport = id === 'codex' ? 'stdio_jsonl' : 'acp_stdio'
  if (
    typeof raw.state !== 'string' ||
    !SUBSCRIPTION_CONNECTOR_STATES.has(raw.state) ||
    raw.auth !== 'device_code' ||
    raw.transport !== expectedTransport ||
    (raw.version !== null &&
      (typeof raw.version !== 'string' ||
        raw.version.trim().length === 0 ||
        raw.version.length > 64)) ||
    typeof raw.login_supported !== 'boolean' ||
    typeof raw.logout_supported !== 'boolean' ||
    !Array.isArray(raw.capabilities) ||
    raw.capabilities.length < 1 ||
    raw.capabilities.length > 2 ||
    new Set(raw.capabilities).size !== raw.capabilities.length ||
    raw.capabilities.some((capability) => capability !== 'chat' && capability !== 'code')
  ) {
    throw new Error('Invalid subscription connector response')
  }
  return {
    id,
    label: id === 'codex' ? 'Codex' : 'Kimi Code',
    state: raw.state as SubscriptionConnectorState,
    auth: 'device_code',
    transport: expectedTransport,
    version: raw.version,
    capabilities: raw.capabilities as Array<'chat' | 'code'>,
    login_supported: raw.login_supported,
    logout_supported: raw.logout_supported
  }
}

export function fetchSubscriptionConnectors(): Promise<SubscriptionConnector[]> {
  return apiGet<unknown>('/v1/subscription-connectors').then((document) => {
    if (!document || typeof document !== 'object' || Array.isArray(document)) {
      throw new Error('Invalid subscription connector response')
    }
    const connectors = (document as Record<string, unknown>).connectors
    if (!Array.isArray(connectors)) throw new Error('Invalid subscription connector response')
    return connectors.flatMap((connector) => {
      const projected = publicSubscriptionConnector(connector)
      return projected ? [projected] : []
    })
  })
}

export interface CatalogProvider {
  name: string
  label: string
  region: string
  auth: 'api_key' | 'login' | 'none'
  type: string
  default_base_url: string
  auto_discover_models?: boolean
  note?: string
  connectable?: boolean
  unavailable_reason?: string
  models: CatalogModel[]
}

export interface ConnectionSummary {
  credential_present?: boolean
  credential_reverification_available?: boolean
  type?: string
  base_url?: string
  enabled_models?: CatalogModel[]
  state?: 'verified' | 'legacy_unverified' | 'disabled'
  verified_at?: string
}

export type ConnectionFailureReasonCode =
  | 'invalid_credentials'
  | 'quota_or_rate_limited'
  | 'model_or_endpoint_not_found'
  | 'network_or_timeout'
  | 'upstream_unavailable'
  | 'invalid_request'
  | 'reauth_required'
  | 'text_contract_rejected'
  | 'connector_unavailable'

export interface LocalServer {
  name: string
  label: string
  base_url: string
  alive: boolean
  models: string[]
}

export function fetchCatalog(): Promise<CatalogProvider[]> {
  return apiGet<{ providers: CatalogProvider[] }>('/admin/catalog').then((d) => d.providers)
}

export function fetchConnections(): Promise<Record<string, ConnectionSummary>> {
  return apiGet<Record<string, ConnectionSummary>>('/admin/connections')
}

export function saveConnection(
  provider: string,
  payload: {
    type: string
    api_key: string
    base_url: string
    enabled_models: CatalogModel[]
    preserve_existing_credential: boolean
  }
): Promise<{
  ok: boolean
  models: string[]
  rejected_models?: string[]
  state?: string
  error?: string
  reason_code?: ConnectionFailureReasonCode
}> {
  return window.api.saveConnection({ provider, ...payload })
}

export function testConnection(
  provider: string
): Promise<{ ok: boolean; error?: string; model?: string }> {
  return apiPost<{ ok: boolean; error?: string; model?: string }>(
    `/admin/connections/${provider}/test`,
    {}
  )
}

export function deleteConnection(provider: string): Promise<{ ok: boolean }> {
  return window.api.deleteConnection(provider)
}

export function detectLocal(): Promise<LocalServer[]> {
  return apiGet<{ local: LocalServer[] }>('/admin/local/detect').then((d) => d.local)
}

export function fetchUpstreamModels(
  baseUrl: string
): Promise<{ ok: boolean; models?: string[]; error?: string }> {
  return apiGet(`/admin/local/models?base_url=${encodeURIComponent(baseUrl)}`)
}

interface ImageResult {
  data: { url: string }[]
}

function isImageResult(value: unknown): value is ImageResult {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const result = value as Record<string, unknown>
  if (Object.keys(result).sort().join('\0') !== 'data') return false
  const data = result.data
  if (!Array.isArray(data) || data.length < 1 || data.length > 4) return false
  return data.every((item) => {
    if (!item || typeof item !== 'object' || Array.isArray(item)) return false
    const image = item as Record<string, unknown>
    return (
      Object.keys(image).sort().join('\0') === 'url' &&
      isDurablePaidMediaAssetRef(image.url)
    )
  })
}

/** 生图（M3）：仅返回 Main Vault 的内容寻址引用。 */
export async function generateImage(
  model: string,
  prompt: string,
  signal?: AbortSignal,
  options?: PaidMediaRequestOptions<string[]>
): Promise<string[]> {
  const response = await paidMediaPost<ImageResult>(
    '/v1/images/generations',
    { model, prompt },
    isImageResult,
    signal,
    options
  )
  const images = response.result.data.map((image) => image.url)
  await acknowledgeDurablePaidMediaResult(
    response.deliveryProof,
    images,
    options?.onResultDurablyCommitted
  )
  return images
}

// ── 生视频（异步：create→poll）──
export interface VideoCreated {
  task_id?: string
  id?: string
  video_id?: string
}
export interface VideoStatus {
  status?: string
  progress?: number
  url?: string
  video_url?: string
  output_url?: string
  download_url?: string
  error?: unknown
  data?: {
    status?: string
    progress?: number
    error?: unknown
    url?: string
    video_url?: string
    output_url?: string
    download_url?: string
  }
}
export const PAID_VIDEO_SUCCESS_STATUSES = new Set([
  'complete',
  'completed',
  'done',
  'success',
  'succeeded'
])
export const PAID_VIDEO_FAILURE_STATUSES = new Set([
  'failure',
  'failed',
  'error',
  'cancelled',
  'canceled'
])
export function paidVideoStatusValue(status: VideoStatus): string {
  const raw = status.status || status.data?.status
  return typeof raw === 'string' ? raw.trim().toLowerCase() : ''
}
export function paidVideoTerminalAssetUrl(status: VideoStatus): string | undefined {
  const state = paidVideoStatusValue(status)
  if (state && !PAID_VIDEO_SUCCESS_STATUSES.has(state)) return undefined
  const candidates = [
    status.url,
    status.video_url,
    status.output_url,
    status.download_url,
    status.data?.url,
    status.data?.video_url,
    status.data?.output_url,
    status.data?.download_url
  ]
    .filter(isDurablePaidMediaAssetRef)
    .map((value) => value.trim())
  const unique = [...new Set(candidates)]
  return unique.length === 1 ? unique[0] : undefined
}
export type DurablePaidMediaAssetRef = `nachuan-paid-media://sha256/${string}`
export function isDurablePaidMediaAssetRef(
  value: unknown
): value is DurablePaidMediaAssetRef {
  return (
    typeof value === 'string' &&
    /^nachuan-paid-media:\/\/sha256\/[0-9a-f]{64}$/.test(value)
  )
}
const MAX_VIDEO_RECEIPT_ID_LENGTH = 512
function isVideoCreated(value: unknown): value is VideoCreated {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const record = value as Record<string, unknown>
  return ['task_id', 'video_id', 'id'].some((field) => {
    const candidate = record[field]
    return (
      typeof candidate === 'string' &&
      candidate.trim().length > 0 &&
      candidate.length <= MAX_VIDEO_RECEIPT_ID_LENGTH
    )
  })
}
export async function createVideo(
  model: string,
  prompt: string,
  signal?: AbortSignal,
  images?: string[],
  options?: PaidMediaRequestOptions<VideoCreated>
): Promise<VideoCreated> {
  const normalized = (images ?? [])
    .map((url) => (url.startsWith('data:image/') ? (url.split(',', 2)[1] ?? '') : url))
    // 前端图片只会是 http URL 或(上面已剥前缀的)纯 base64 → 只去掉空串；上游 _video_image_arg 再做魔数校验
    .filter(Boolean)
  const body: Record<string, unknown> = { model, prompt }
  if (normalized.length === 1) body.image = normalized[0]
  else if (normalized.length > 1) body.extra_body = { image: normalized.slice(-4), mode: 'keyframes' }
  const response = await paidMediaPost<VideoCreated>(
    '/v1/videos/generations',
    body,
    isVideoCreated,
    signal,
    options
  )
  await acknowledgeDurablePaidMediaResult(
    response.deliveryProof,
    response.result,
    options?.onResultDurablyCommitted
  )
  return response.result
}
export function pollVideo(model: string, taskId: string): Promise<VideoStatus> {
  return window.api.pollPaidVideo({ taskAlias: taskId, model }) as Promise<VideoStatus>
}

// ── 协作编排（M4）──
export type WorkflowOutcome = 'completed' | 'completed_unverified' | 'partial' | 'failed'
export interface WorkflowRoute {
  /** Legacy requested-model alias retained for response-v1 clients. */
  model?: string | null
  requested_model?: string | null
  actual_model?: string | null
  provider?: string | null
  upstream_model?: string | null
  observed_model?: string | null
  independence_domain?: string | null
  tier?: string | null
}
export interface WorkflowTruth {
  response_version: number
  outcome: WorkflowOutcome
  stopped_reason?: string | null
  machine_verified: boolean
}
export interface WorkflowCall extends WorkflowRoute {
  answer?: string | null
  status: 'ok' | 'failed' | 'duplicate' | 'identity_unknown' | 'skipped'
  error?: string | null
  error_type?: string | null
  duplicate_of?: string | null
}
export interface PanelResult {
  response_version: number
  panelists: WorkflowCall[]
  judge?: string
  summary?: string | null
  review_verdict?: string | null
  verdict?: string | null
  judge_error?: string | null
  error?: string
  effective_panelists: number
  judge_route?: WorkflowRoute | null
  judge_independent: boolean
  judge_vote_weight: number
  degraded_reasons?: string[]
  collaboration_type: 'multi_source_synthesis'
  outcome: WorkflowOutcome
  stopped_reason?: string | null
  machine_verified: boolean
}

/** 议会汇总：多个 panelists 作答 → judge 综合。 */
export function runPanel(
  prompt: string,
  panelists: string[],
  judge: string,
  signal?: AbortSignal
): Promise<PanelResult> {
  return apiPost<PanelResult>('/v1/orchestrate/panel', { prompt, panelists, judge }, signal)
}

export interface CodingImpl {
  name: string
  agent: string
  result?: { ok?: boolean; output?: string; error?: string }
  diff?: string
  error?: string
}
export interface CodingResult {
  plan?: string
  implementations?: CodingImpl[]
  review?: string
  needs_approval?: boolean
  approval_id?: number
  summary?: string
  scope?: string
}

/** 编程团队：规划 → 并行实现(各 worktree) → 评审。 */
export function runCodingTeam(
  repo: string,
  task: string,
  planner: string,
  implementers: { name: string; agent: string; model?: string }[],
  reviewer: string,
  opts?: { approval_id?: number; user_id?: string }
): Promise<CodingResult> {
  return apiPost<CodingResult>('/v1/orchestrate/coding', {
    repo,
    task,
    planner,
    implementers,
    reviewer,
    ...opts
  })
}

export function runArchEditor(
  repo: string,
  task: string,
  architect: string,
  editor: string,
  opts?: { approval_id?: number; user_id?: string }
): Promise<Record<string, unknown>> {
  return apiPost('/v1/orchestrate/arch-editor', { repo, task, architect, editor, ...opts })
}

export interface DebateResult extends WorkflowTruth {
  rounds: number
  rounds_attempted: number
  rounds_with_quorum: number
  rounds_completed: number
  transcript: Record<string, string>[]
  round_details: WorkflowCall[][]
  effective_debaters: number
  judge?: string
  summary?: string | null
  review_verdict?: string | null
  verdict?: string | null
  judge_error?: string | null
  judge_route?: WorkflowRoute | null
  judge_independent: boolean
  judge_vote_weight: number
  degraded_reasons?: string[]
  collaboration_type: 'multi_source_synthesis'
}
export function runDebate(
  prompt: string,
  debaters: string[],
  judge: string,
  rounds: number,
  signal?: AbortSignal
): Promise<DebateResult> {
  return apiPost<DebateResult>(
    '/v1/orchestrate/debate',
    { prompt, debaters, judge, rounds },
    signal
  )
}

export interface DecomposeSubtask extends WorkflowCall {
  subtask: string
  requested_tier?: string
}
export interface DecomposeResult extends WorkflowTruth {
  plan?: string
  planner?: string
  planner_route?: WorkflowRoute | null
  subtasks: DecomposeSubtask[]
  aggregator?: string
  aggregator_route?: WorkflowRoute | null
  final?: string | null
  error?: string | null
  error_type?: string | null
  workflow_kind: 'pipeline_collaboration'
  aggregation_is_review: false
}
export function runDecompose(
  task: string,
  planner: string,
  aggregator: string,
  signal?: AbortSignal
): Promise<DecomposeResult> {
  return apiPost<DecomposeResult>(
    '/v1/orchestrate/decompose',
    { task, planner, aggregator },
    signal
  )
}

export interface PipelineStep {
  model: string
  instruction: string
}
export interface PipelineTrace extends WorkflowRoute {
  step: number
  instruction: string
  output?: string | null
  status: 'ok' | 'failed' | 'skipped'
  error?: string | null
  error_type?: string | null
}
export interface PipelineResult extends WorkflowTruth {
  final?: string | null
  partial_output?: string | null
  trace: PipelineTrace[]
  workflow_kind: 'pipeline_collaboration'
}
export function runPipeline(
  prompt: string,
  steps: PipelineStep[],
  signal?: AbortSignal
): Promise<PipelineResult> {
  return apiPost<PipelineResult>('/v1/orchestrate/pipeline', { prompt, steps }, signal)
}

// ── 用量 / 成本（M6）──
export interface UsageRow {
  model: string
  resolved_model: string
  provider: string
  calls: number
  success_calls: number
  failed_calls: number
  in_flight_calls: number
  outcome_unknown_calls: number
  prompt_tokens: number | null
  known_prompt_tokens: number
  completion_tokens: number | null
  known_completion_tokens: number
  total_tokens: number | null
  known_total_tokens: number
  cached_tokens: number | null
  known_cached_tokens: number
  unknown_token_calls: number
  unknown_cost_calls: number
  provider_reported_cost_calls: number
  invoice_reconciled_cost_calls: number
  estimated_cost_calls: number
  unverified_cost_calls: number
  provider_internal_breakdown_calls: number
  cost_usd: number | null
  known_cost_usd: number
  known_cost_microusd: string
  provider_reported_cost_usd: number
  invoice_reconciled_cost_usd: number
  billed_cost_usd: number
  estimated_cost_usd: number
  unclassified_cost_usd: number
  billed_cost_complete: boolean
  cost_basis: string
  identity_basis: string
}
export interface UsageSummary {
  financial_source: boolean
  reason: string | null
  ledger_table: 'provider_calls'
  currency: 'USD'
  period: 'day' | 'month' | 'all'
  period_start_utc: string | null
  period_end_utc: string | null
  models: UsageRow[]
  total_calls: number
  terminal_calls: number
  success_calls: number
  failed_calls: number
  in_flight_calls: number
  outcome_unknown_calls: number
  unknown_token_calls: number
  unknown_cost_calls: number
  known_cost_usd: number
  known_cost_microusd: string
  provider_reported_cost_usd: number
  invoice_reconciled_cost_usd: number
  billed_cost_usd: number
  estimated_cost_usd: number
  unclassified_cost_usd: number
  billed_cost_complete: boolean
  provider_reported_cost_calls: number
  invoice_reconciled_cost_calls: number
  estimated_cost_calls: number
  unverified_cost_calls: number
  provider_internal_breakdown_calls: number
  total_cost_usd: number | null
  database_bytes: number
  wal_bytes: number
  storage_bytes: number
  disk_free_bytes: number
  max_database_bytes: number
  capacity_ratio: number
  capacity_status: 'ok' | 'warning' | 'critical'
}
export function fetchUsage(): Promise<UsageSummary> {
  return apiGet<UsageSummary>('/admin/financial-usage?period=month')
}

// ── 拉片（#29）：上传视频 → 逐帧分析 → 报告/SOP ──
export interface LapianResult {
  duration?: number
  frames?: number
  vision_model?: string
  synth_model?: string
  has_transcript?: boolean
  report?: string
  analyses?: { ts: number; desc: string }[]
}
export async function lapianVideo(
  file: Blob,
  opts?: { maxFrames?: number; withAudio?: boolean; visionModel?: string }
): Promise<LapianResult> {
  const q = new URLSearchParams()
  if (opts?.maxFrames) q.set('max_frames', String(opts.maxFrames))
  if (opts?.withAudio !== undefined) q.set('with_audio', String(opts.withAudio))
  if (opts?.visionModel) q.set('vision_model', opts.visionModel)
  const query = q.toString()
  return apiPostBinary<LapianResult>(`/v1/lapian${query ? `?${query}` : ''}`, file)
}
/** 拉片·网址版：粘贴任意视频网址 → 后端 yt-dlp 下载 → 逐帧分析 → 报告（生成可能要等下载+分析）。 */
export async function lapianUrl(url: string): Promise<LapianResult> {
  return apiPost<LapianResult>('/v1/lapian/url', { url, with_audio: true })
}

// ── 看图理解 / OCR（#28）：上传图片 → 文字 ──
export async function visionImage(file: Blob, question?: string): Promise<string> {
  const q = question ? `?question=${encodeURIComponent(question)}` : ''
  return (await apiPostBinary<{ text?: string }>(`/v1/vision${q}`, file)).text ?? ''
}

// ── MCP 工具：仅登记经过 SHA-256 证明的本地可执行文件 ──
export interface McpServer {
  command?: string
  args?: string[]
  url?: string
  sha256?: string
  env?: Record<string, string>
}
export interface McpProbe {
  ok: boolean
  detail: string
}
export function fetchMcp(): Promise<{
  enabled: boolean
  mcpServers: Record<string, McpServer>
  status: Record<string, McpProbe>
}> {
  return apiGet('/v1/mcp')
}
export interface McpPreset {
  name: string
  desc: string
  runtime: string
  command: string
  args: string[]
  note?: string
  available: boolean
  audited?: boolean
}
export function fetchMcpPresets(): Promise<McpPreset[]> {
  return apiGet<{ presets: McpPreset[] }>('/v1/mcp/presets').then((d) => d.presets)
}
export function addMcp(body: {
  name: string
  command?: string
  args?: string[]
  sha256?: string
  task?: string
  approval_id?: number
  user_id?: string
}): Promise<{
  ok?: boolean
  mcpServers?: Record<string, McpServer>
  probe?: McpProbe
  needs_approval?: boolean
  approval_id?: number
  summary?: string
}> {
  return apiPost('/v1/mcp', body)
}
export function removeMcp(
  name: string,
  opts?: { task?: string; approval_id?: number; user_id?: string }
): Promise<{ ok?: boolean; needs_approval?: boolean; approval_id?: number; summary?: string }> {
  return apiPost(`/v1/mcp/${encodeURIComponent(name)}/remove`, opts ?? {})
}

// ── 跨设备云同步（Supabase）：记忆/案例/知识库，按账户隔离 ──
export interface SyncStatus {
  configured: boolean
  logged_in: boolean
  enabled: boolean
  email: string
  url: string
  device_id: string
  scope?: 'personal_account' | string
  cloud_user_id?: string
  local_user?: string
  sync_tables?: string[]
  last_sync: Record<string, number>
}
export interface SyncRunResult {
  ok: boolean
  skipped?: boolean
  reason?: string
  pushed?: Record<string, number>
  pulled?: Record<string, number>
  error?: string
}
export interface SyncAuthResult {
  ok: boolean
  logged_in?: boolean
  need_confirm?: boolean
  user_id?: string
  email?: string
  error?: string
}
export function fetchSyncStatus(): Promise<SyncStatus> {
  return apiGet<SyncStatus>('/v1/sync/status')
}
export function syncConfig(url: string, anonKey: string): Promise<SyncStatus> {
  return window.api.configureSync(url, anonKey) as Promise<SyncStatus>
}
export function syncSignup(email: string, password: string): Promise<SyncAuthResult> {
  return window.api.authenticateSync('signup', email, password) as Promise<SyncAuthResult>
}
export function syncLogin(email: string, password: string): Promise<SyncAuthResult> {
  return window.api.authenticateSync('login', email, password) as Promise<SyncAuthResult>
}
export function syncToggle(enabled: boolean): Promise<SyncStatus> {
  return window.api.toggleSync(enabled) as Promise<SyncStatus>
}
export function syncRun(): Promise<SyncRunResult> {
  return window.api.runSync() as Promise<SyncRunResult>
}
