// ADR-0013 Web 形态：同源网关 HTTP 客户端。
//
// 所有 window.api 的出站请求都经此单点：
// - 自动附带 Authorization: Bearer <runtime key>（从标签页 sessionStorage 读，见 credentials.ts）；
// - includeApprovalKey 时附带 X-Nachuan-Approval-Key（审批/连接/同步等双头路由）；
// - 只接受同源相对路径（"/" 开头且非 "//"），从类型上排除跨域与 key 泄漏面；
// - `/v1/models` 首次 401 或其他请求连续 401 达到阈值时回调
//   onConsecutiveUnauthorized（登录闸重提示），
//   runtime / approval 两个凭据域独立计数，同域非 401 才重置；trackUnauthorized=false
//   的调用（付费媒体）不参与计数——
//   金融能力是独立信任域，永不为它重提示运行时 Key。

import type { CredentialStore } from './credentials'

export interface WebHttpRequest {
  readonly method: 'GET' | 'POST' | 'DELETE'
  readonly target: string
  readonly body?: string | ArrayBuffer
  readonly contentType?: string
  readonly includeApprovalKey?: boolean
  readonly trackUnauthorized?: boolean
  readonly signal?: AbortSignal
}

export interface WebHttpJsonRequest {
  readonly method: 'GET' | 'POST' | 'DELETE'
  readonly target: string
  readonly json?: unknown
  readonly includeApprovalKey?: boolean
  readonly trackUnauthorized?: boolean
  readonly signal?: AbortSignal
}

export interface WebHttpResponse {
  readonly status: number
  readonly contentType: string
  readonly body: Uint8Array
}

export interface WebHttpClient {
  /** 打开响应（不做实体读取），供流式消费；401 计数在响应头到达时进行。 */
  open(input: WebHttpRequest): Promise<Response>
  /** 读取完整响应实体；与 preload 语义一致：任何 HTTP 状态都正常返回，由调用方判定。 */
  request(input: WebHttpRequest): Promise<WebHttpResponse>
  /** JSON 交换：非 2xx 抛 WebHttpError（状态码 + 引擎原文如实上抛）。 */
  requestJson<T = unknown>(input: WebHttpJsonRequest): Promise<T>
}

export class WebHttpError extends Error {
  override readonly name = 'WebHttpError'
  readonly status: number

  constructor(status: number, text: string) {
    super(`${status} ${text.slice(0, 2000)}`)
    this.status = status
  }
}

export interface WebHttpClientDeps {
  readonly credentials: CredentialStore
  readonly onConsecutiveUnauthorized?: () => void
  readonly fetchImpl?: typeof fetch
  /** 连续 401 触发登录闸的阈值，默认 2。 */
  readonly unauthorizedThreshold?: number
}

function checkedTarget(target: unknown): string {
  if (
    typeof target !== 'string' ||
    !target.startsWith('/') ||
    target.startsWith('//') ||
    /[\u0000-\u001f]/.test(target)
  ) {
    throw new Error('Web gateway request target is invalid')
  }
  return target
}

export function createWebHttpClient(deps: WebHttpClientDeps): WebHttpClient {
  if (!deps || typeof deps.credentials !== 'object') {
    throw new Error('Web HTTP client credentials are unavailable')
  }
  const doFetch: typeof fetch =
    deps.fetchImpl ?? ((input, init) => globalThis.fetch(input, init))
  const threshold =
    Number.isSafeInteger(deps.unauthorizedThreshold) && (deps.unauthorizedThreshold as number) > 0
      ? (deps.unauthorizedThreshold as number)
      : 2
  let consecutiveRuntimeUnauthorized = 0
  let consecutiveApprovalUnauthorized = 0

  function noteStatus(
    status: number,
    track: boolean,
    target: string,
    includeApprovalKey: boolean
  ): void {
    if (!track) return
    const unauthorizedCount = includeApprovalKey
      ? consecutiveApprovalUnauthorized
      : consecutiveRuntimeUnauthorized
    if (status === 401) {
      const nextUnauthorizedCount = unauthorizedCount + 1
      if (includeApprovalKey) {
        consecutiveApprovalUnauthorized = nextUnauthorizedCount
      } else {
        consecutiveRuntimeUnauthorized = nextUnauthorizedCount
      }
      // `/v1/models` is the renderer's authoritative first refresh after a page
      // reload.  Waiting for a second unrelated request leaves the app looking
      // online while it can only display an empty model picker.
      if (target === '/v1/models' || nextUnauthorizedCount >= threshold) {
        deps.onConsecutiveUnauthorized?.()
      }
    } else if (includeApprovalKey) {
      consecutiveApprovalUnauthorized = 0
    } else {
      consecutiveRuntimeUnauthorized = 0
    }
  }

  function buildHeaders(input: WebHttpRequest): Record<string, string> {
    const headers: Record<string, string> = {}
    const runtimeKey = deps.credentials.getRuntimeKey()
    if (runtimeKey) headers['Authorization'] = `Bearer ${runtimeKey}`
    if (input.includeApprovalKey) {
      const approvalKey = deps.credentials.getApprovalKey()
      if (approvalKey) headers['X-Nachuan-Approval-Key'] = approvalKey
    }
    if (input.contentType) headers['Content-Type'] = input.contentType
    return headers
  }

  async function open(input: WebHttpRequest): Promise<Response> {
    const target = checkedTarget(input?.target)
    const response = await doFetch(target, {
      method: input.method,
      headers: buildHeaders(input),
      body: input.body ?? null,
      signal: input.signal ?? null
    })
    noteStatus(
      response.status,
      input.trackUnauthorized !== false,
      target,
      input.includeApprovalKey === true
    )
    return response
  }

  async function request(input: WebHttpRequest): Promise<WebHttpResponse> {
    const response = await open(input)
    const buffer = await response.arrayBuffer()
    return Object.freeze({
      status: response.status,
      contentType: response.headers.get('content-type') ?? '',
      body: new Uint8Array(buffer)
    })
  }

  async function requestJson<T = unknown>(input: WebHttpJsonRequest): Promise<T> {
    const response = await request({
      method: input.method,
      target: input.target,
      ...(input.json !== undefined
        ? { body: JSON.stringify(input.json), contentType: 'application/json' }
        : {}),
      ...(input.includeApprovalKey !== undefined
        ? { includeApprovalKey: input.includeApprovalKey }
        : {}),
      ...(input.trackUnauthorized !== undefined
        ? { trackUnauthorized: input.trackUnauthorized }
        : {}),
      ...(input.signal !== undefined ? { signal: input.signal } : {})
    })
    const text = new TextDecoder('utf-8', { fatal: false }).decode(response.body)
    if (response.status < 200 || response.status >= 300) {
      throw new WebHttpError(response.status, text)
    }
    return JSON.parse(text) as T
  }

  return Object.freeze({ open, request, requestJson })
}
