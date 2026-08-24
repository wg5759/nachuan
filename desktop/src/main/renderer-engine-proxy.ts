import { createHash, randomBytes } from 'node:crypto'
import http, { Agent, type ClientRequest, type IncomingMessage } from 'node:http'
import type { Socket } from 'node:net'

import {
  DESKTOP_ENGINE_SESSION_CHALLENGE_JSON,
  DESKTOP_ENGINE_SESSION_CHALLENGE_PATH,
  type DesktopEngineSessionIdentity,
  signDesktopEngineSessionRequest,
  verifyDesktopEngineSessionResponse
} from './desktop-engine-session-protocol'

const REQUEST_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const LOWER_HEX_64 = /^[0-9a-f]{64}$/
const ZERO_DIGEST = '0'.repeat(64)
const CHALLENGE_TIMEOUT_MS = 5_000
const MAX_TARGET_BYTES = 8 * 1024
const MAX_JSON_DEPTH = 32
const MAX_JSON_NODES = 100_000
export const RENDERER_ENGINE_FLOW_CHUNK_BYTES = 64 * 1024
const MAX_ACTIVE_RENDERER_ENGINE_REQUESTS = 8
const MAX_ACTIVE_RENDERER_ENGINE_STREAMS = 2
const MAX_ACTIVE_RENDERER_ENGINE_BINARY_STREAMS = 1
const MAX_ACTIVE_RENDERER_ENGINE_UPLOADS = 1
const MAX_RENDERER_ENGINE_STREAM_FRAMES = 8_192
const MAX_SSE_RESPONSE_BYTES = 8 * 1024 * 1024
const MAX_LEGACY_MEDIA_RESPONSE_BYTES = 16 * 1024 * 1024
const MAX_BINARY_ERROR_RESPONSE_BYTES = 1024 * 1024

export type RendererEngineBodyKind = 'none' | 'json' | 'binary'
export type RendererEngineResponseKind = 'json' | 'binary' | 'stream'

export interface RendererEngineRequest {
  readonly requestId: string
  readonly method: 'GET' | 'POST'
  readonly target: string
  readonly bodyKind: 'none' | 'json'
  readonly body?: string
  readonly responseKind: RendererEngineResponseKind
}

export interface RendererEngineUploadRequest {
  readonly requestId: string
  readonly method: 'POST'
  readonly target: string
  readonly bodyKind: 'binary'
  readonly bodyLength: number
  readonly responseKind: 'json'
}

export interface RendererEngineResponse {
  readonly status: number
  readonly contentType: string
  readonly body: Uint8Array
}

export type RendererEngineStreamEvent =
  | Readonly<{ kind: 'start'; status: number; contentType: string }>
  | Readonly<{ kind: 'chunk'; chunk: Uint8Array }>

export interface RendererEngineStreamResult {
  readonly status: number
  readonly contentType: string
  readonly bytes: number
}

type ValidatedRequest = Readonly<{
  requestId: string
  method: 'GET' | 'POST'
  target: string
  body: Buffer
  bodyKind: RendererEngineBodyKind
  responseKind: RendererEngineResponseKind
  policy: RoutePolicy
}>

type ValidatedUploadRequest = Readonly<{
  requestId: string
  method: 'POST'
  target: string
  bodyKind: 'binary'
  bodyLength: number
  responseKind: 'json'
  policy: RoutePolicy
}>

export type RendererEngineUploadReader = (
  offset: number,
  maximumBytes: number,
  signal: AbortSignal
) => Promise<Uint8Array>

type RoutePolicy = Readonly<{
  bodyKind: RendererEngineBodyKind
  responseKinds: readonly RendererEngineResponseKind[]
  requestBytes: number
  responseBytes: number
  totalTimeoutMs: number
  firstByteTimeoutMs: number
  bodyIdleTimeoutMs: number
  allowedKeys?: readonly string[]
  requiredKeys?: readonly string[]
}>

type RendererEngineTransport = (input: ValidatedRequest) => Promise<RendererEngineResponse>

export interface RendererEngineProxyDependencies {
  readonly session: () => DesktopEngineSessionIdentity | null
  readonly runtimeKey: () => string
  readonly now?: () => number
  readonly transport?: RendererEngineTransport
}

type RendererEngineAdmissionKind = 'request' | 'stream' | 'binary' | 'upload'

type ActiveRendererEngineRequest = Readonly<{
  controller: AbortController
  kind: RendererEngineAdmissionKind
}>

export class RendererEngineProxyError extends Error {
  override readonly name = 'RendererEngineProxyError'

  constructor(
    message: string,
    readonly code: 'ENGINE_FORBIDDEN' | 'ENGINE_BUSY' | 'ENGINE_STREAM_FAILED'
  ) {
    super(message)
  }
}

function forbidden(): RendererEngineProxyError {
  return new RendererEngineProxyError('Renderer Engine request is not permitted', 'ENGINE_FORBIDDEN')
}

function busy(): RendererEngineProxyError {
  return new RendererEngineProxyError('Renderer Engine is busy', 'ENGINE_BUSY')
}

function failed(message = 'Renderer Engine request failed'): RendererEngineProxyError {
  return new RendererEngineProxyError(message, 'ENGINE_STREAM_FAILED')
}

export function advanceRendererEngineStreamFrameBudget(current: number): number {
  if (
    !Number.isSafeInteger(current) ||
    current < 0 ||
    current >= MAX_RENDERER_ENGINE_STREAM_FRAMES
  ) {
    throw failed()
  }
  return current + 1
}

function sha256(value: Uint8Array): string {
  return createHash('sha256').update(value).digest('hex')
}

function exactSession(value: unknown): DesktopEngineSessionIdentity {
  if (
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    typeof (value as DesktopEngineSessionIdentity).bootToken !== 'string' ||
    !LOWER_HEX_64.test((value as DesktopEngineSessionIdentity).bootToken) ||
    (value as DesktopEngineSessionIdentity).bootToken === ZERO_DIGEST ||
    !Number.isSafeInteger((value as DesktopEngineSessionIdentity).generation) ||
    (value as DesktopEngineSessionIdentity).generation < 1 ||
    !Number.isSafeInteger((value as DesktopEngineSessionIdentity).pid) ||
    (value as DesktopEngineSessionIdentity).pid < 1 ||
    !Number.isSafeInteger((value as DesktopEngineSessionIdentity).port) ||
    (value as DesktopEngineSessionIdentity).port < 1024 ||
    (value as DesktopEngineSessionIdentity).port > 65_535
  ) {
    throw failed('Renderer Engine session is unavailable')
  }
  const session = value as DesktopEngineSessionIdentity
  return Object.freeze({
    bootToken: session.bootToken,
    generation: session.generation,
    pid: session.pid,
    port: session.port
  })
}

function sameSession(
  left: DesktopEngineSessionIdentity,
  right: DesktopEngineSessionIdentity
): boolean {
  return (
    left.bootToken === right.bootToken &&
    left.generation === right.generation &&
    left.pid === right.pid &&
    left.port === right.port
  )
}

function assertLoopback(socket: Socket, session: DesktopEngineSessionIdentity): void {
  if (
    socket.destroyed ||
    socket.remoteAddress !== '127.0.0.1' ||
    socket.localAddress !== '127.0.0.1' ||
    socket.remotePort !== session.port
  ) {
    throw failed('Renderer Engine connection failed authentication')
  }
}

function rawHeaders(headers: Readonly<Record<string, string>>): string[] {
  return Object.entries(headers).flatMap(([name, value]) => [name, value])
}

async function readBounded(response: IncomingMessage, maximum: number): Promise<Buffer> {
  const chunks: Buffer[] = []
  let total = 0
  for await (const raw of response) {
    const chunk = Buffer.isBuffer(raw) ? raw : Buffer.from(raw)
    total += chunk.byteLength
    if (total > maximum) throw failed('Renderer Engine response exceeded its limit')
    chunks.push(chunk)
  }
  return Buffer.concat(chunks, total)
}

function responseHeaderValues(response: IncomingMessage, name: string): string[] {
  const raw = response.rawHeaders
  const values: string[] = []
  for (let index = 0; index < raw.length; index += 2) {
    if (raw[index].toLowerCase() === name) values.push(raw[index + 1])
  }
  return values
}

function responseContentType(
  response: IncomingMessage,
  kind: RendererEngineResponseKind,
  status: number
): string {
  const values = responseHeaderValues(response, 'content-type')
  if (values.length !== 1) {
    throw failed('Renderer Engine response type is invalid')
  }
  const value = values[0]
  const json = /^application\/json(?:;\s*charset=utf-8)?$/i.test(value)
  const eventStream = /^text\/event-stream(?:;\s*charset=utf-8)?$/i.test(value)
  const binary =
    /^(?:video|audio|image)\/[A-Za-z0-9!#$&^_.+-]+(?:;[\x20-\x7e]*)?$/i.test(value) ||
    /^application\/octet-stream(?:;[\x20-\x7e]*)?$/i.test(value)
  if (
    (kind === 'json' && !json) ||
    (kind === 'stream' && !json && !eventStream) ||
    (kind === 'binary' && !json && !binary) ||
    (kind === 'binary' && status >= 200 && status < 300 && json)
  ) {
    throw failed('Renderer Engine response type is invalid')
  }
  return value
}

function declaredResponseLength(response: IncomingMessage, maximum: number): number | null {
  const values = responseHeaderValues(response, 'content-length')
  if (values.length > 1) throw failed('Renderer Engine response length is ambiguous')
  if (values.length === 0) return null
  if (!/^(0|[1-9][0-9]*)$/.test(values[0])) {
    throw failed('Renderer Engine response length is invalid')
  }
  const length = Number(values[0])
  if (!Number.isSafeInteger(length) || length > maximum) {
    throw failed('Renderer Engine response exceeded its limit')
  }
  return length
}

function validateResponseEnvelope(
  response: IncomingMessage,
  kind: RendererEngineResponseKind,
  maximum: number
): {
  status: number
  contentType: string
  declaredLength: number | null
  bodyLimit: number
} {
  const status = response.statusCode
  if (
    status === undefined ||
    status < 200 ||
    status > 599 ||
    (status >= 300 && status <= 399) ||
    responseHeaderValues(response, 'content-encoding').some((value) => value !== 'identity') ||
    responseHeaderValues(response, 'content-range').length > 0 ||
    responseHeaderValues(response, 'location').length > 0 ||
    responseHeaderValues(response, 'trailer').length > 0 ||
    responseHeaderValues(response, 'upgrade').length > 0
  ) {
    throw failed('Renderer Engine response envelope is invalid')
  }
  const bodyLimit =
    kind === 'binary' && (status < 200 || status >= 300)
      ? Math.min(maximum, MAX_BINARY_ERROR_RESPONSE_BYTES)
      : maximum
  return {
    status,
    contentType: responseContentType(response, kind, status),
    declaredLength: declaredResponseLength(response, bodyLimit),
    bodyLimit
  }
}

const JSON_SIMPLE = Object.freeze({
  bodyKind: 'json' as const,
  responseKinds: Object.freeze(['json'] as const),
  requestBytes: 4 * 1024 * 1024,
  responseBytes: 16 * 1024 * 1024,
  totalTimeoutMs: 5 * 60 * 1000,
  firstByteTimeoutMs: 60_000,
  bodyIdleTimeoutMs: 30_000
})

const GET_SIMPLE = Object.freeze({
  bodyKind: 'none' as const,
  responseKinds: Object.freeze(['json'] as const),
  requestBytes: 0,
  responseBytes: 16 * 1024 * 1024,
  totalTimeoutMs: 60_000,
  firstByteTimeoutMs: 15_000,
  bodyIdleTimeoutMs: 30_000
})

function jsonPolicy(
  allowedKeys: readonly string[],
  requiredKeys: readonly string[] = [],
  overrides: Partial<RoutePolicy> = {}
): RoutePolicy {
  return Object.freeze({
    ...JSON_SIMPLE,
    allowedKeys: Object.freeze([...allowedKeys]),
    requiredKeys: Object.freeze([...requiredKeys]),
    ...overrides
  })
}

function decodedExact(raw: string, minimum: number, maximum: number): string | null {
  let decoded: string
  try {
    decoded = decodeURIComponent(raw)
  } catch {
    return null
  }
  if (
    decoded.length < minimum ||
    decoded.length > maximum ||
    /[\u0000-\u001f\u007f]/.test(decoded) ||
    encodeURIComponent(decoded) !== raw
  ) {
    return null
  }
  return decoded
}

function exactOneQuery(
  target: string,
  path: string,
  name: string,
  minimum: number,
  maximum: number
): boolean {
  const prefix = `${path}?${name}=`
  return target.startsWith(prefix) && decodedExact(target.slice(prefix.length), minimum, maximum) !== null
}

function exactEncodedTail(target: string, prefix: string, suffix = ''): string | null {
  if (!target.startsWith(prefix) || (suffix && !target.endsWith(suffix))) return null
  const end = suffix ? target.length - suffix.length : target.length
  return decodedExact(target.slice(prefix.length, end), 1, 256)
}

function exactLapianQuery(target: string): boolean {
  if (target === '/v1/lapian') return true
  if (!target.startsWith('/v1/lapian?')) return false
  const raw = target.slice('/v1/lapian?'.length)
  const params = new URLSearchParams(raw)
  if (params.toString() !== raw) return false
  const observed = [...params.keys()]
  if (new Set(observed).size !== observed.length) return false
  if (observed.some((key) => !['max_frames', 'with_audio', 'vision_model'].includes(key))) return false
  const expectedOrder = ['max_frames', 'with_audio', 'vision_model'].filter((key) => params.has(key))
  if (observed.some((key, index) => key !== expectedOrder[index])) return false
  const maxFrames = params.get('max_frames')
  if (maxFrames !== null && (!/^[1-9][0-9]{0,3}$/.test(maxFrames) || Number(maxFrames) > 1000)) {
    return false
  }
  const withAudio = params.get('with_audio')
  if (withAudio !== null && withAudio !== 'true' && withAudio !== 'false') return false
  const visionModel = params.get('vision_model')
  return visionModel === null || (visionModel.length >= 1 && visionModel.length <= 256)
}

function routePolicy(
  method: unknown,
  target: unknown
): RoutePolicy | null {
  if (
    (method !== 'GET' && method !== 'POST') ||
    typeof target !== 'string' ||
    Buffer.byteLength(target, 'utf8') > MAX_TARGET_BYTES ||
    !/^\/[\x21-\x7e]*$/.test(target) ||
    target.includes('#') ||
    target.includes('\\') ||
    target.includes('//')
  ) {
    return null
  }

  if (method === 'GET') {
    if (
      ['/health', '/v1/local/catalog', '/v1/audio/model', '/v1/models', '/v1/scoreboard',
        '/admin/catalog', '/admin/connections', '/admin/local/detect', '/v1/mcp',
        '/v1/mcp/presets', '/v1/sync/status'].includes(target)
    ) {
      return GET_SIMPLE
    }
    if (target === '/admin/financial-usage?period=month') return GET_SIMPLE
    if (
      exactOneQuery(target, '/v1/kb/docs', 'user_id', 1, 128) ||
      exactOneQuery(target, '/v1/agent/memory', 'user_id', 1, 128) ||
      exactOneQuery(target, '/v1/agent/cases', 'user_id', 1, 128) ||
      exactOneQuery(target, '/admin/local/models', 'base_url', 1, 2_048)
    ) {
      return GET_SIMPLE
    }
    if (exactEncodedTail(target, '/v1/studio/execute/') !== null) return GET_SIMPLE
    if (exactEncodedTail(target, '/v1/studio/video/') !== null) {
      return Object.freeze({
        ...GET_SIMPLE,
        responseKinds: Object.freeze(['binary'] as const),
        responseBytes: MAX_LEGACY_MEDIA_RESPONSE_BYTES,
        totalTimeoutMs: 15 * 60 * 1000,
        firstByteTimeoutMs: 60_000,
        bodyIdleTimeoutMs: 60_000
      })
    }
    if (exactOneQuery(target, '/v1/videos/fetch', 'url', 1, 8_192)) {
      return Object.freeze({
        ...GET_SIMPLE,
        responseKinds: Object.freeze(['binary'] as const),
        responseBytes: MAX_LEGACY_MEDIA_RESPONSE_BYTES,
        totalTimeoutMs: 30 * 60 * 1000,
        firstByteTimeoutMs: 60_000,
        bodyIdleTimeoutMs: 60_000
      })
    }
    return null
  }

  const exactJson = (path: string, allowed: readonly string[], required: readonly string[] = []): RoutePolicy | null =>
    target === path ? jsonPolicy(allowed, required) : null
  let policy: RoutePolicy | null
  policy = exactJson('/v1/local/select', ['model_id', 'task', 'approval_id', 'user_id'], ['model_id'])
  if (policy) return policy
  policy = exactJson('/v1/kb/docs', ['user_id', 'title', 'text'], ['user_id', 'title', 'text'])
  if (policy) return policy
  if (/^\/v1\/kb\/docs\/[1-9][0-9]*\/delete$/.test(target)) {
    return jsonPolicy(['user_id', 'approval_id'], ['user_id'])
  }
  policy = exactJson('/v1/kb/query', ['user_id', 'query'], ['user_id', 'query'])
  if (policy) return policy
  policy = exactJson('/v1/intent', ['message'], ['message'])
  if (policy) return policy
  policy = exactJson('/v1/web/read', ['url', 'question'], ['url', 'question'])
  if (policy) return policy
  policy = exactJson('/v1/studio/plan', ['goal', 'feedback', 'plan'], ['goal', 'feedback'])
  if (policy) return policy
  policy = exactJson('/v1/studio/execute', ['plan', 'task', 'approval_id', 'user_id'], ['plan'])
  if (policy) return policy
  policy = exactJson('/v1/workflows/daily-video/start', ['root', 'date', 'task', 'approval_id', 'user_id'])
  if (policy) return policy
  policy = exactJson('/v1/audio/model', ['model'], ['model'])
  if (policy) return policy
  policy = exactJson('/v1/translate', ['text', 'target'], ['text', 'target'])
  if (policy) return policy
  policy = exactJson(
    '/v1/agent/exec',
    ['task', 'backend', 'mode', 'model', 'workdir', 'approval_id', 'user_id', 'instruction'],
    ['task']
  )
  if (policy) return policy
  policy = exactJson(
    '/v1/agent/run',
    ['task', 'model', 'workdir', 'allow', 'max_steps', 'history', 'mode', 'approval_id',
      'orchestrate', 'user_id', 'stream', 'conversation_id'],
    ['task']
  )
  if (policy) {
    return Object.freeze({
      ...policy,
      responseKinds: Object.freeze(['json', 'stream'] as const),
      requestBytes: 16 * 1024 * 1024,
      responseBytes: 64 * 1024 * 1024,
      totalTimeoutMs: 24 * 60 * 60 * 1000,
      firstByteTimeoutMs: 5 * 60 * 1000,
      bodyIdleTimeoutMs: 5 * 60 * 1000
    })
  }
  policy = exactJson(
    '/v1/agent/job',
    ['goal', 'steps', 'workdir', 'backend', 'mode', 'approval_id', 'user_id'],
    ['goal']
  )
  if (policy) return policy
  if (exactEncodedTail(target, '/v1/agent/job/', '/resume') !== null) {
    return jsonPolicy(['workdir', 'backend', 'mode', 'approval_id', 'user_id'])
  }
  policy = exactJson('/v1/agent/inject', ['conversation_id', 'message'], ['conversation_id', 'message'])
  if (policy) return policy
  policy = exactJson('/v1/agent/undo', ['receipt', 'content'], ['receipt', 'content'])
  if (policy) return Object.freeze({ ...policy, requestBytes: 32 * 1024 * 1024 })
  if (exactEncodedTail(target, '/v1/conv/', '/clear-summary') !== null) {
    return jsonPolicy(['user_id', 'approval_id'], ['user_id'])
  }
  policy = exactJson(
    '/v1/route',
    ['mode', 'messages', 'web_search', 'reasoning_effort', 'conversation_id'],
    ['mode', 'messages', 'web_search']
  )
  if (policy) return Object.freeze({ ...policy, requestBytes: 16 * 1024 * 1024 })
  policy = exactJson('/v1/agent/chat', ['message', 'user_id', 'chat_id', 'channel', 'model'], ['message', 'user_id', 'chat_id', 'channel'])
  if (policy) return policy
  policy = exactJson('/v1/agent/memory/clear', ['user_id', 'approval_id'], ['user_id'])
  if (policy) return policy
  policy = exactJson(
    '/v1/chat/completions',
    ['model', 'messages', 'stream', 'web_search', 'reasoning_effort', 'conversation_id'],
    ['model', 'messages', 'stream', 'web_search']
  )
  if (policy) {
    return Object.freeze({
      ...policy,
      responseKinds: Object.freeze(['stream'] as const),
      requestBytes: 16 * 1024 * 1024,
      responseBytes: 8 * 1024 * 1024,
      totalTimeoutMs: 2 * 60 * 60 * 1000,
      firstByteTimeoutMs: 2 * 60 * 1000,
      bodyIdleTimeoutMs: 5 * 60 * 1000
    })
  }
  if (/^\/admin\/connections\/[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\/test$/.test(target)) {
    return jsonPolicy([])
  }
  policy = exactJson('/v1/orchestrate/panel', ['prompt', 'panelists', 'judge'], ['prompt', 'panelists', 'judge'])
  if (policy) return Object.freeze({ ...policy, totalTimeoutMs: 4 * 60 * 60 * 1000 })
  policy = exactJson(
    '/v1/orchestrate/coding',
    ['repo', 'task', 'planner', 'implementers', 'reviewer', 'approval_id', 'user_id'],
    ['repo', 'task', 'planner', 'implementers', 'reviewer']
  )
  if (policy) return Object.freeze({ ...policy, totalTimeoutMs: 8 * 60 * 60 * 1000 })
  policy = exactJson(
    '/v1/orchestrate/arch-editor',
    ['repo', 'task', 'architect', 'editor', 'approval_id', 'user_id'],
    ['repo', 'task', 'architect', 'editor']
  )
  if (policy) return Object.freeze({ ...policy, totalTimeoutMs: 8 * 60 * 60 * 1000 })
  policy = exactJson('/v1/orchestrate/debate', ['prompt', 'debaters', 'judge', 'rounds'], ['prompt', 'debaters', 'judge', 'rounds'])
  if (policy) return Object.freeze({ ...policy, totalTimeoutMs: 4 * 60 * 60 * 1000 })
  policy = exactJson('/v1/orchestrate/decompose', ['task', 'planner', 'aggregator'], ['task', 'planner', 'aggregator'])
  if (policy) return Object.freeze({ ...policy, totalTimeoutMs: 4 * 60 * 60 * 1000 })
  policy = exactJson('/v1/orchestrate/pipeline', ['prompt', 'steps'], ['prompt', 'steps'])
  if (policy) return Object.freeze({ ...policy, totalTimeoutMs: 4 * 60 * 60 * 1000 })
  policy = exactJson('/v1/lapian/url', ['url', 'with_audio'], ['url', 'with_audio'])
  if (policy) return Object.freeze({ ...policy, totalTimeoutMs: 2 * 60 * 60 * 1000 })
  policy = exactJson('/v1/mcp', ['name', 'command', 'args', 'sha256', 'task', 'approval_id', 'user_id'], ['name'])
  if (policy) return policy
  if (exactEncodedTail(target, '/v1/mcp/', '/remove') !== null) {
    return jsonPolicy(['task', 'approval_id', 'user_id'])
  }
  if (target.startsWith('/v1/audio/transcriptions')) {
    if (
      target !== '/v1/audio/transcriptions' &&
      !exactOneQuery(target, '/v1/audio/transcriptions', 'language', 1, 64)
    ) return null
    return Object.freeze({
      ...JSON_SIMPLE,
      bodyKind: 'binary' as const,
      requestBytes: 64 * 1024 * 1024,
      totalTimeoutMs: 30 * 60 * 1000
    })
  }
  if (exactLapianQuery(target)) {
    return Object.freeze({
      ...JSON_SIMPLE,
      bodyKind: 'binary' as const,
      requestBytes: 512 * 1024 * 1024,
      responseBytes: 64 * 1024 * 1024,
      totalTimeoutMs: 4 * 60 * 60 * 1000,
      firstByteTimeoutMs: 5 * 60 * 1000,
      bodyIdleTimeoutMs: 5 * 60 * 1000
    })
  }
  if (target === '/v1/vision' || exactOneQuery(target, '/v1/vision', 'question', 1, 8_192)) {
    return Object.freeze({
      ...JSON_SIMPLE,
      bodyKind: 'binary' as const,
      requestBytes: 64 * 1024 * 1024,
      totalTimeoutMs: 30 * 60 * 1000
    })
  }
  return null
}

function strictJsonBody(text: string, policy: RoutePolicy): Buffer {
  const bytes = Buffer.from(text, 'utf8')
  if (bytes.byteLength > policy.requestBytes) throw forbidden()
  let value: unknown
  try {
    value = JSON.parse(text)
  } catch {
    throw forbidden()
  }
  if (!value || typeof value !== 'object' || Array.isArray(value) || JSON.stringify(value) !== text) {
    throw forbidden()
  }
  const pending: Array<{ value: unknown; depth: number }> = [{ value, depth: 1 }]
  let nodes = 0
  while (pending.length > 0) {
    const current = pending.pop()
    if (!current || current.depth > MAX_JSON_DEPTH || ++nodes > MAX_JSON_NODES) throw forbidden()
    const item = current.value
    if (item === null || typeof item === 'string' || typeof item === 'boolean') continue
    if (typeof item === 'number') {
      if (!Number.isFinite(item)) throw forbidden()
      continue
    }
    if (!item || typeof item !== 'object') throw forbidden()
    if (Array.isArray(item)) {
      if (item.length > MAX_JSON_NODES) throw forbidden()
      for (const child of item) pending.push({ value: child, depth: current.depth + 1 })
      continue
    }
    const keys = Object.keys(item)
    if (
      keys.length > 256 ||
      keys.some((key) => key === '__proto__' || key === 'prototype' || key === 'constructor')
    ) {
      throw forbidden()
    }
    for (const key of keys) {
      pending.push({ value: (item as Record<string, unknown>)[key], depth: current.depth + 1 })
    }
  }
  const topKeys = Object.keys(value as Record<string, unknown>)
  const allowed = new Set(policy.allowedKeys ?? [])
  if (topKeys.some((key) => !allowed.has(key))) throw forbidden()
  if ((policy.requiredKeys ?? []).some((key) => !topKeys.includes(key))) throw forbidden()
  return bytes
}

function captureRequest(input: unknown): ValidatedRequest {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw forbidden()
  const value = input as Record<string, unknown>
  const keys = Object.keys(value).sort()
  const hasBody = Object.prototype.hasOwnProperty.call(value, 'body')
  const expected = (hasBody
    ? ['body', 'bodyKind', 'method', 'requestId', 'responseKind', 'target']
    : ['bodyKind', 'method', 'requestId', 'responseKind', 'target']
  ).sort()
  const policy = routePolicy(value.method, value.target)
  if (
    keys.length !== expected.length ||
    keys.some((key, index) => key !== expected[index]) ||
    typeof value.requestId !== 'string' ||
    !REQUEST_ID.test(value.requestId) ||
    (value.method !== 'GET' && value.method !== 'POST') ||
    typeof value.target !== 'string' ||
    !policy ||
    (value.bodyKind !== 'none' && value.bodyKind !== 'json') ||
    value.bodyKind !== policy.bodyKind ||
    (value.responseKind !== 'json' &&
      value.responseKind !== 'binary' &&
      value.responseKind !== 'stream') ||
    !policy.responseKinds.includes(value.responseKind)
  ) {
    throw forbidden()
  }
  let body: Buffer
  if (value.bodyKind === 'none') {
    if (hasBody) throw forbidden()
    body = Buffer.alloc(0)
  } else {
    if (typeof value.body !== 'string') throw forbidden()
    body = strictJsonBody(value.body, policy)
    const parsed = JSON.parse(value.body) as Record<string, unknown>
    if (
      (value.responseKind === 'stream' && parsed.stream !== true) ||
      (value.target === '/v1/chat/completions' && parsed.stream !== true) ||
      (value.target === '/v1/agent/run' && value.responseKind === 'json' && parsed.stream === true)
    ) {
      throw forbidden()
    }
  }
  const effectivePolicy =
    value.responseKind === 'stream' && policy.responseBytes > MAX_SSE_RESPONSE_BYTES
      ? Object.freeze({ ...policy, responseBytes: MAX_SSE_RESPONSE_BYTES })
      : policy
  return Object.freeze({
    requestId: value.requestId,
    method: value.method,
    target: value.target,
    bodyKind: value.bodyKind,
    body,
    responseKind: value.responseKind,
    policy: effectivePolicy
  })
}

function captureUploadRequest(input: unknown): ValidatedUploadRequest {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw forbidden()
  const value = input as RendererEngineUploadRequest
  const keys = Object.keys(value).sort()
  const expected = [
    'bodyKind',
    'bodyLength',
    'method',
    'requestId',
    'responseKind',
    'target'
  ].sort()
  const policy = routePolicy(value.method, value.target)
  if (
    keys.length !== expected.length ||
    keys.some((key, index) => key !== expected[index]) ||
    !REQUEST_ID.test(value.requestId) ||
    !policy ||
    value.method !== 'POST' ||
    value.bodyKind !== 'binary' ||
    policy.bodyKind !== 'binary' ||
    value.responseKind !== 'json' ||
    !policy.responseKinds.includes('json') ||
    !Number.isSafeInteger(value.bodyLength) ||
    value.bodyLength < 0 ||
    value.bodyLength > policy.requestBytes
  ) {
    throw forbidden()
  }
  return Object.freeze({
    requestId: value.requestId,
    method: value.method,
    target: value.target,
    bodyKind: value.bodyKind,
    bodyLength: value.bodyLength,
    responseKind: value.responseKind,
    policy
  })
}

/**
 * Main-owned, closed renderer-to-Engine boundary.
 *
 * The per-boot HMAC challenge is completed on a pinned IPv4 loopback socket
 * before the ordinary runtime key is placed on that same connection.  No
 * endpoint, credential, header or timeout is supplied by renderer code.
 */
export class RendererEngineProxy {
  private readonly now: () => number
  private readonly active = new Map<string, ActiveRendererEngineRequest>()

  constructor(private readonly dependencies: RendererEngineProxyDependencies) {
    if (
      !dependencies ||
      typeof dependencies.session !== 'function' ||
      typeof dependencies.runtimeKey !== 'function' ||
      (dependencies.transport !== undefined && typeof dependencies.transport !== 'function')
    ) {
      throw failed('Renderer Engine proxy dependencies are unavailable')
    }
    this.now = dependencies.now ?? Date.now
  }

  async request(input: RendererEngineRequest): Promise<RendererEngineResponse> {
    const capturedInput = captureRequest(input)
    if (capturedInput.responseKind !== 'json') throw forbidden()
    const controller = this.begin(capturedInput.requestId, 'request')
    try {
      if (this.dependencies.transport) return await this.dependencies.transport(capturedInput)
      const captured = exactSession(this.dependencies.session())
      const agent = new Agent({ keepAlive: true, maxSockets: 1, maxFreeSockets: 1 })
      try {
        const socket = await this.challenge(captured, agent, controller.signal)
        const key = this.runtimeKey()
        return await this.exchange(
          captured,
          socket,
          agent,
          key,
          capturedInput,
          controller.signal
        )
      } finally {
        agent.destroy()
      }
    } finally {
      this.finish(capturedInput.requestId, controller)
    }
  }

  async stream(
    input: RendererEngineRequest,
    onEvent: (event: RendererEngineStreamEvent) => void | Promise<void>
  ): Promise<RendererEngineStreamResult> {
    const capturedInput = captureRequest(input)
    if (
      capturedInput.responseKind === 'json' ||
      typeof onEvent !== 'function' ||
      this.dependencies.transport
    ) {
      throw forbidden()
    }
    const controller = this.begin(
      capturedInput.requestId,
      capturedInput.responseKind === 'binary' ? 'binary' : 'stream'
    )
    try {
      const captured = exactSession(this.dependencies.session())
      const agent = new Agent({ keepAlive: true, maxSockets: 1, maxFreeSockets: 1 })
      try {
        const socket = await this.challenge(captured, agent, controller.signal)
        const key = this.runtimeKey()
        return await this.exchangeStream(
          captured,
          socket,
          agent,
          key,
          capturedInput,
          onEvent,
          controller.signal
        )
      } finally {
        agent.destroy()
      }
    } finally {
      this.finish(capturedInput.requestId, controller)
    }
  }

  async upload(
    input: RendererEngineUploadRequest,
    readChunk: RendererEngineUploadReader
  ): Promise<RendererEngineResponse> {
    const capturedInput = captureUploadRequest(input)
    if (typeof readChunk !== 'function' || this.dependencies.transport) throw forbidden()
    const controller = this.begin(capturedInput.requestId, 'upload')
    try {
      const captured = exactSession(this.dependencies.session())
      const agent = new Agent({ keepAlive: true, maxSockets: 1, maxFreeSockets: 1 })
      try {
        const socket = await this.challenge(captured, agent, controller.signal)
        const key = this.runtimeKey()
        return await this.exchangeUpload(
          captured,
          socket,
          agent,
          key,
          capturedInput,
          readChunk,
          controller.signal
        )
      } finally {
        agent.destroy()
      }
    } finally {
      this.finish(capturedInput.requestId, controller)
    }
  }

  cancel(requestId: unknown): boolean {
    if (typeof requestId !== 'string' || !REQUEST_ID.test(requestId)) return false
    const active = this.active.get(requestId)
    if (!active) return false
    active.controller.abort()
    return true
  }

  private begin(requestId: string, kind: RendererEngineAdmissionKind): AbortController {
    if (this.active.has(requestId)) throw forbidden()
    if (this.active.size >= MAX_ACTIVE_RENDERER_ENGINE_REQUESTS) throw busy()
    let sameKind = 0
    for (const active of this.active.values()) {
      if (active.kind === kind) sameKind += 1
    }
    if (
      (kind === 'stream' && sameKind >= MAX_ACTIVE_RENDERER_ENGINE_STREAMS) ||
      (kind === 'binary' && sameKind >= MAX_ACTIVE_RENDERER_ENGINE_BINARY_STREAMS) ||
      (kind === 'upload' && sameKind >= MAX_ACTIVE_RENDERER_ENGINE_UPLOADS)
    ) {
      throw busy()
    }
    const controller = new AbortController()
    this.active.set(requestId, Object.freeze({ controller, kind }))
    return controller
  }

  private finish(requestId: string, controller: AbortController): void {
    if (this.active.get(requestId)?.controller === controller) this.active.delete(requestId)
  }

  private runtimeKey(): string {
    const key = this.dependencies.runtimeKey()
    if (
      typeof key !== 'string' ||
      key.length < 16 ||
      key.length > 256 ||
      /[^\x21-\x7e]/.test(key)
    ) {
      throw failed('Renderer Engine authority is unavailable')
    }
    return key
  }

  private assertCurrent(captured: DesktopEngineSessionIdentity): void {
    let current: DesktopEngineSessionIdentity
    try {
      current = exactSession(this.dependencies.session())
    } catch {
      throw failed('Renderer Engine session changed during the request')
    }
    if (!sameSession(captured, current)) {
      throw failed('Renderer Engine session changed during the request')
    }
  }

  private challenge(
    captured: DesktopEngineSessionIdentity,
    agent: Agent,
    signal: AbortSignal
  ): Promise<Socket> {
    const baseHeaders = {
      Host: `127.0.0.1:${captured.port}`,
      Connection: 'keep-alive',
      'Content-Length': '0',
      Accept: 'application/json',
      'Accept-Encoding': 'identity',
      'Cache-Control': 'no-store'
    }
    const timestampMs = this.now()
    if (!Number.isSafeInteger(timestampMs) || timestampMs < 1) {
      return Promise.reject(failed('Renderer Engine clock is invalid'))
    }
    const signed = signDesktopEngineSessionRequest({
      session: captured,
      timestampMs,
      nonce: randomBytes(32).toString('hex'),
      channelNonce: ZERO_DIGEST,
      capability: 'session.challenge',
      method: 'GET',
      target: DESKTOP_ENGINE_SESSION_CHALLENGE_PATH,
      bodySha256: sha256(Buffer.alloc(0)),
      rawHeaders: rawHeaders(baseHeaders)
    })
    return new Promise<Socket>((resolve, reject) => {
      let request: ClientRequest | null = null
      let pinned: Socket | null = null
      let settled = false
      const timer = setTimeout(() => rejectFixed(), CHALLENGE_TIMEOUT_MS)
      timer.unref()
      const cleanup = (): void => {
        clearTimeout(timer)
        request?.setTimeout(0)
        signal.removeEventListener('abort', abort)
      }
      const rejectFixed = (message = 'Renderer Engine connection failed authentication'): void => {
        if (settled) return
        settled = true
        cleanup()
        request?.destroy()
        reject(failed(message))
      }
      const abort = (): void => rejectFixed('Renderer Engine request failed')
      if (signal.aborted) {
        abort()
        return
      }
      signal.addEventListener('abort', abort, { once: true })
      try {
        request = http.request(
          {
            protocol: 'http:',
            hostname: '127.0.0.1',
            family: 4,
            localAddress: '127.0.0.1',
            port: captured.port,
            method: 'GET',
            path: DESKTOP_ENGINE_SESSION_CHALLENGE_PATH,
            headers: { ...baseHeaders, ...signed.headers },
            agent
          },
          (response) => {
            void (async (): Promise<void> => {
              try {
                if (!pinned || response.socket !== pinned || response.statusCode !== 200) {
                  throw failed()
                }
                assertLoopback(pinned, captured)
                this.assertCurrent(captured)
                const body = await readBounded(response, 256)
                if (
                  !response.complete ||
                  response.rawTrailers.length !== 0 ||
                  body.toString('utf8') !== DESKTOP_ENGINE_SESSION_CHALLENGE_JSON
                ) {
                  throw failed()
                }
                verifyDesktopEngineSessionResponse({
                  session: captured,
                  requestNonce: signed.nonce,
                  capability: 'session.challenge',
                  status: 200,
                  bodySha256: sha256(body),
                  rawHeaders: response.rawHeaders
                })
                this.assertCurrent(captured)
                await new Promise<void>((next) => setImmediate(next))
                assertLoopback(pinned, captured)
                if (settled) return
                settled = true
                cleanup()
                resolve(pinned)
              } catch {
                rejectFixed()
              }
            })()
          }
        )
      } catch {
        rejectFixed()
        return
      }
      request.once('socket', (socket) => {
        pinned = socket
      })
      request.once('upgrade', (response) => {
        response.destroy()
        rejectFixed()
      })
      request.once('error', () => rejectFixed())
      request.setTimeout(CHALLENGE_TIMEOUT_MS, rejectFixed)
      request.end()
    })
  }

  private exchange(
    captured: DesktopEngineSessionIdentity,
    pinned: Socket,
    agent: Agent,
    key: string,
    input: ValidatedRequest,
    signal: AbortSignal
  ): Promise<RendererEngineResponse> {
    return new Promise<RendererEngineResponse>((resolve, reject) => {
      let request: ClientRequest | null = null
      let settled = false
      const timer = setTimeout(() => rejectFixed(), input.policy.totalTimeoutMs)
      timer.unref()
      const cleanup = (): void => {
        clearTimeout(timer)
        request?.setTimeout(0)
        signal.removeEventListener('abort', abort)
      }
      const rejectFixed = (): void => {
        if (settled) return
        settled = true
        cleanup()
        request?.destroy()
        reject(failed())
      }
      const abort = (): void => rejectFixed()
      if (signal.aborted) {
        abort()
        return
      }
      signal.addEventListener('abort', abort, { once: true })
      try {
        request = http.request(
          {
            protocol: 'http:',
            hostname: '127.0.0.1',
            family: 4,
            localAddress: '127.0.0.1',
            port: captured.port,
            method: input.method,
            path: input.target,
            headers: {
              Host: `127.0.0.1:${captured.port}`,
              Connection: 'close',
              'Content-Length': String(input.body.byteLength),
              Accept: 'application/json',
              'Accept-Encoding': 'identity',
              'Cache-Control': 'no-store',
              ...(input.bodyKind === 'json'
                ? { 'Content-Type': 'application/json' }
                : input.bodyKind === 'binary'
                  ? { 'Content-Type': 'application/octet-stream' }
                  : {}),
              Authorization: `Bearer ${key}`
            },
            agent
          },
          (response) => {
            void (async (): Promise<void> => {
              try {
                if (response.socket !== pinned) throw failed()
                assertLoopback(pinned, captured)
                this.assertCurrent(captured)
                const envelope = validateResponseEnvelope(
                  response,
                  'json',
                  input.policy.responseBytes
                )
                response.setTimeout(input.policy.bodyIdleTimeoutMs, rejectFixed)
                const body = await readBounded(response, input.policy.responseBytes)
                if (!response.complete || response.rawTrailers.length !== 0) throw failed()
                if (
                  envelope.declaredLength === null ||
                  envelope.declaredLength !== body.byteLength
                ) {
                  throw failed()
                }
                this.assertCurrent(captured)
                JSON.parse(body.toString('utf8'))
                if (settled) return
                settled = true
                cleanup()
                resolve(
                  Object.freeze({
                    status: envelope.status,
                    contentType: envelope.contentType,
                    body: Uint8Array.from(body)
                  })
                )
              } catch {
                rejectFixed()
              }
            })()
          }
        )
      } catch {
        rejectFixed()
        return
      }
      request.once('socket', (socket) => {
        try {
          if (socket !== pinned) throw failed()
          assertLoopback(socket, captured)
          this.assertCurrent(captured)
          request?.end(input.body)
        } catch {
          rejectFixed()
        }
      })
      request.once('upgrade', (response) => {
        response.destroy()
        rejectFixed()
      })
      request.once('error', rejectFixed)
      request.setTimeout(input.policy.firstByteTimeoutMs, rejectFixed)
    })
  }

  private exchangeStream(
    captured: DesktopEngineSessionIdentity,
    pinned: Socket,
    agent: Agent,
    key: string,
    input: ValidatedRequest,
    onEvent: (event: RendererEngineStreamEvent) => void | Promise<void>,
    signal: AbortSignal
  ): Promise<RendererEngineStreamResult> {
    return new Promise<RendererEngineStreamResult>((resolve, reject) => {
      let request: ClientRequest | null = null
      let response: IncomingMessage | null = null
      let settled = false
      const timer = setTimeout(() => rejectFixed(), input.policy.totalTimeoutMs)
      timer.unref()
      const cleanup = (): void => {
        clearTimeout(timer)
        request?.setTimeout(0)
        response?.setTimeout(0)
        signal.removeEventListener('abort', abort)
      }
      const rejectFixed = (): void => {
        if (settled) return
        settled = true
        cleanup()
        response?.destroy()
        request?.destroy()
        reject(failed())
      }
      const abort = (): void => rejectFixed()
      if (signal.aborted) {
        abort()
        return
      }
      signal.addEventListener('abort', abort, { once: true })
      try {
        request = http.request(
          {
            protocol: 'http:',
            hostname: '127.0.0.1',
            family: 4,
            localAddress: '127.0.0.1',
            port: captured.port,
            method: input.method,
            path: input.target,
            headers: {
              Host: `127.0.0.1:${captured.port}`,
              Connection: 'close',
              'Content-Length': String(input.body.byteLength),
              Accept:
                input.responseKind === 'stream'
                  ? 'text/event-stream, application/json'
                  : 'application/octet-stream, video/*, audio/*, image/*, application/json',
              'Accept-Encoding': 'identity',
              'Cache-Control': 'no-store',
              ...(input.bodyKind === 'json'
                ? { 'Content-Type': 'application/json' }
                : input.bodyKind === 'binary'
                  ? { 'Content-Type': 'application/octet-stream' }
                  : {}),
              Authorization: `Bearer ${key}`
            },
            agent
          },
          (incoming) => {
            response = incoming
            request?.setTimeout(0)
            void (async (): Promise<void> => {
              try {
                if (incoming.socket !== pinned) throw failed()
                assertLoopback(pinned, captured)
                this.assertCurrent(captured)
                const envelope = validateResponseEnvelope(
                  incoming,
                  input.responseKind,
                  input.policy.responseBytes
                )
                await onEvent(
                  Object.freeze({
                    kind: 'start',
                    status: envelope.status,
                    contentType: envelope.contentType
                  })
                )
                incoming.setTimeout(input.policy.bodyIdleTimeoutMs, rejectFixed)
                let bytes = 0
                let frames = 0
                let binaryPending = Buffer.alloc(0)
                const emitChunk = async (part: Buffer): Promise<void> => {
                  if (part.byteLength < 1 || part.byteLength > RENDERER_ENGINE_FLOW_CHUNK_BYTES) {
                    throw failed()
                  }
                  frames = advanceRendererEngineStreamFrameBudget(frames)
                  await onEvent(
                    Object.freeze({ kind: 'chunk', chunk: Uint8Array.from(part) })
                  )
                }
                for await (const raw of incoming) {
                  const chunk = Buffer.isBuffer(raw) ? raw : Buffer.from(raw)
                  bytes += chunk.byteLength
                  if (bytes > envelope.bodyLimit) throw failed()
                  if (input.responseKind === 'binary') {
                    let offset = 0
                    if (binaryPending.byteLength > 0) {
                      const needed = RENDERER_ENGINE_FLOW_CHUNK_BYTES - binaryPending.byteLength
                      const take = Math.min(needed, chunk.byteLength)
                      binaryPending = Buffer.concat(
                        [binaryPending, chunk.subarray(0, take)],
                        binaryPending.byteLength + take
                      )
                      offset = take
                      if (binaryPending.byteLength === RENDERER_ENGINE_FLOW_CHUNK_BYTES) {
                        await emitChunk(binaryPending)
                        binaryPending = Buffer.alloc(0)
                      }
                    }
                    while (chunk.byteLength - offset >= RENDERER_ENGINE_FLOW_CHUNK_BYTES) {
                      await emitChunk(
                        chunk.subarray(offset, offset + RENDERER_ENGINE_FLOW_CHUNK_BYTES)
                      )
                      offset += RENDERER_ENGINE_FLOW_CHUNK_BYTES
                    }
                    if (offset < chunk.byteLength) {
                      binaryPending = Buffer.from(chunk.subarray(offset))
                    }
                    continue
                  }
                  for (
                    let offset = 0;
                    offset < chunk.byteLength;
                    offset += RENDERER_ENGINE_FLOW_CHUNK_BYTES
                  ) {
                    const part = chunk.subarray(
                      offset,
                      Math.min(chunk.byteLength, offset + RENDERER_ENGINE_FLOW_CHUNK_BYTES)
                    )
                    await emitChunk(part)
                  }
                }
                if (binaryPending.byteLength > 0) await emitChunk(binaryPending)
                if (!incoming.complete || incoming.rawTrailers.length !== 0) throw failed()
                if (envelope.declaredLength !== null && envelope.declaredLength !== bytes) {
                  throw failed()
                }
                this.assertCurrent(captured)
                if (settled) return
                settled = true
                cleanup()
                resolve(
                  Object.freeze({
                    status: envelope.status,
                    contentType: envelope.contentType,
                    bytes
                  })
                )
              } catch {
                rejectFixed()
              }
            })()
          }
        )
      } catch {
        rejectFixed()
        return
      }
      request.once('socket', (socket) => {
        try {
          if (socket !== pinned) throw failed()
          assertLoopback(socket, captured)
          this.assertCurrent(captured)
          request?.end(input.body)
        } catch {
          rejectFixed()
        }
      })
      request.once('upgrade', (incoming) => {
        incoming.destroy()
        rejectFixed()
      })
      request.once('error', rejectFixed)
      request.setTimeout(input.policy.firstByteTimeoutMs, rejectFixed)
    })
  }

  private exchangeUpload(
    captured: DesktopEngineSessionIdentity,
    pinned: Socket,
    agent: Agent,
    key: string,
    input: ValidatedUploadRequest,
    readChunk: RendererEngineUploadReader,
    signal: AbortSignal
  ): Promise<RendererEngineResponse> {
    return new Promise<RendererEngineResponse>((resolve, reject) => {
      let request: ClientRequest | null = null
      let uploadComplete = false
      let settled = false
      const timer = setTimeout(() => rejectFixed(), input.policy.totalTimeoutMs)
      timer.unref()
      const cleanup = (): void => {
        clearTimeout(timer)
        request?.setTimeout(0)
        signal.removeEventListener('abort', abort)
      }
      const rejectFixed = (): void => {
        if (settled) return
        settled = true
        cleanup()
        request?.destroy()
        reject(failed())
      }
      const abort = (): void => rejectFixed()
      if (signal.aborted) {
        abort()
        return
      }
      signal.addEventListener('abort', abort, { once: true })
      try {
        request = http.request(
          {
            protocol: 'http:',
            hostname: '127.0.0.1',
            family: 4,
            localAddress: '127.0.0.1',
            port: captured.port,
            method: input.method,
            path: input.target,
            headers: {
              Host: `127.0.0.1:${captured.port}`,
              Connection: 'close',
              'Content-Length': String(input.bodyLength),
              Accept: 'application/json',
              'Accept-Encoding': 'identity',
              'Cache-Control': 'no-store',
              'Content-Type': 'application/octet-stream',
              Authorization: `Bearer ${key}`
            },
            agent
          },
          (response) => {
            void (async (): Promise<void> => {
              try {
                if (!uploadComplete || response.socket !== pinned) throw failed()
                assertLoopback(pinned, captured)
                this.assertCurrent(captured)
                const envelope = validateResponseEnvelope(
                  response,
                  'json',
                  input.policy.responseBytes
                )
                response.setTimeout(input.policy.bodyIdleTimeoutMs, rejectFixed)
                const body = await readBounded(response, input.policy.responseBytes)
                if (!response.complete || response.rawTrailers.length !== 0) throw failed()
                if (
                  envelope.declaredLength === null ||
                  envelope.declaredLength !== body.byteLength
                ) {
                  throw failed()
                }
                this.assertCurrent(captured)
                JSON.parse(body.toString('utf8'))
                if (settled) return
                settled = true
                cleanup()
                resolve(
                  Object.freeze({
                    status: envelope.status,
                    contentType: envelope.contentType,
                    body: Uint8Array.from(body)
                  })
                )
              } catch {
                rejectFixed()
              }
            })()
          }
        )
      } catch {
        rejectFixed()
        return
      }
      request.once('socket', (socket) => {
        void (async (): Promise<void> => {
          try {
            if (socket !== pinned) throw failed()
            assertLoopback(socket, captured)
            this.assertCurrent(captured)
            let offset = 0
            while (offset < input.bodyLength) {
              if (signal.aborted) throw failed()
              const maximumBytes = Math.min(
                RENDERER_ENGINE_FLOW_CHUNK_BYTES,
                input.bodyLength - offset
              )
              const supplied = await readChunk(offset, maximumBytes, signal)
              if (
                !(supplied instanceof Uint8Array) ||
                supplied.byteLength !== maximumBytes ||
                offset + supplied.byteLength > input.bodyLength
              ) {
                throw failed()
              }
              const chunk = Buffer.from(supplied)
              await writeWithBackpressure(request as ClientRequest, chunk, signal)
              offset += chunk.byteLength
              this.assertCurrent(captured)
            }
            uploadComplete = true
            request?.end()
          } catch {
            rejectFixed()
          }
        })()
      })
      request.once('upgrade', (response) => {
        response.destroy()
        rejectFixed()
      })
      request.once('error', rejectFixed)
      request.setTimeout(input.policy.firstByteTimeoutMs, rejectFixed)
    })
  }
}

function writeWithBackpressure(
  request: ClientRequest,
  chunk: Buffer,
  signal: AbortSignal
): Promise<void> {
  if (signal.aborted || request.destroyed) return Promise.reject(failed())
  return new Promise<void>((resolve, reject) => {
    let settled = false
    const cleanup = (): void => {
      request.removeListener('drain', drained)
      request.removeListener('error', rejected)
      request.removeListener('close', rejected)
      signal.removeEventListener('abort', rejected)
    }
    const resolved = (): void => {
      if (settled) return
      settled = true
      cleanup()
      resolve()
    }
    const rejected = (): void => {
      if (settled) return
      settled = true
      cleanup()
      reject(failed())
    }
    const drained = (): void => resolved()
    request.once('error', rejected)
    request.once('close', rejected)
    signal.addEventListener('abort', rejected, { once: true })
    try {
      if (request.write(chunk)) resolved()
      else request.once('drain', drained)
    } catch {
      rejected()
    }
  })
}
