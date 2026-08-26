import { createHash, randomBytes } from 'node:crypto'
import http, { Agent, type ClientRequest, type IncomingMessage } from 'node:http'
import type { Socket } from 'node:net'
import { TextDecoder } from 'node:util'

import {
  DESKTOP_ENGINE_SESSION_CHALLENGE_JSON,
  DESKTOP_ENGINE_SESSION_CHALLENGE_PATH,
  type DesktopEngineSessionIdentity,
  signDesktopEngineSessionRequest,
  verifyDesktopEngineSessionResponse
} from './desktop-engine-session-protocol'

const LOWER_HEX_64 = /^[0-9a-f]{64}$/
const ZERO_DIGEST = '0'.repeat(64)
const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/
const CANONICAL_LENGTH = /^(0|[1-9][0-9]*)$/
const POSITIVE_DECIMAL = /^[1-9][0-9]*$/
const PROVIDER_NAME = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/
const SESSION_HEADER_PREFIX = 'x-nachuan-engine-session-'
const MAX_REQUEST_BYTES = 768 * 1024
const MAX_RESPONSE_BYTES = 1024 * 1024
const MAX_JSON_DEPTH = 32
const APPROVAL_RESOLVE_BODY_LIMIT = 16 * 1024
const CONNECTION_SAVE_BODY_LIMIT = 512 * 1024
const SYNC_CONFIG_BODY_LIMIT = 24 * 1024
const SYNC_AUTH_BODY_LIMIT = 4 * 1024
const SYNC_TOGGLE_BODY_LIMIT = 1024
const SYNC_RUN_BODY_LIMIT = 16
const CHANNEL_RECOVERY_BODY_LIMIT = 32 * 1024
const MAX_TOTAL_TIMEOUT_MS = 5 * 60 * 1000
const DEFAULT_CHALLENGE_TIMEOUT_MS = 2_000
const DEFAULT_BODY_IDLE_TIMEOUT_MS = 20_000
const MAX_CHALLENGE_BYTES = 256

const ALLOWED_RESPONSE_HEADERS = new Set([
  'content-type',
  'content-length',
  'cache-control',
  'connection',
  'date',
  'server',
  'keep-alive'
])

export type DesktopEngineSessionCapability =
  | 'plugin.ui.snapshot'
  | 'approval.list'
  | 'approval.resolve'
  | 'connection.save'
  | 'connection.delete'
  | 'sync.config'
  | 'sync.auth'
  | 'sync.toggle'
  | 'sync.run'
  | 'channel-recovery.inspect'
  | 'channel-recovery.close'

export type DesktopEngineSessionSupplier = () => DesktopEngineSessionIdentity | null

export interface DesktopEngineSessionClientDependencies {
  readonly session: DesktopEngineSessionSupplier
  readonly now?: () => number
  readonly challengeTimeoutMs?: number
  readonly bodyIdleTimeoutMs?: number
}

export interface DesktopEngineSessionJsonExchangeInput {
  readonly capability: DesktopEngineSessionCapability
  readonly method: 'GET' | 'POST' | 'DELETE'
  readonly target: string
  readonly body: Buffer
  readonly signal: AbortSignal
  readonly totalTimeoutMs: number
  readonly firstByteTimeoutMs: number
  readonly bodyIdleTimeoutMs?: number
}

export interface DesktopEngineSessionJsonResponse {
  readonly status: number
  readonly body: unknown
}

export class DesktopEngineSessionClientError extends Error {
  override readonly name = 'DesktopEngineSessionClientError'
}

type RawHeaderMap = ReadonlyMap<string, readonly string[]>
type AuthenticatedConnection = Readonly<{ socket: Socket; challengeNonce: string }>

function fail(message: string): DesktopEngineSessionClientError {
  return new DesktopEngineSessionClientError(message)
}

function sha256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex')
}

function validSession(value: unknown): DesktopEngineSessionIdentity {
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
    throw fail('Desktop engine session is unavailable')
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

function validTimeout(value: unknown, label: string, maximum: number): number {
  if (!Number.isSafeInteger(value) || Number(value) < 1 || Number(value) > maximum) {
    throw fail(`${label} is invalid`)
  }
  return Number(value)
}

function validNow(value: unknown): number {
  if (!Number.isSafeInteger(value) || Number(value) < 1) {
    throw fail('Desktop engine-session clock is invalid')
  }
  return Number(value)
}

function rawHeaders(headers: Readonly<Record<string, string>>): string[] {
  return Object.entries(headers).flatMap(([name, value]) => [name, value])
}

function applicationHeaders(
  session: DesktopEngineSessionIdentity,
  bodyLength: number,
  connection: 'keep-alive' | 'close',
  jsonBody: boolean
): Record<string, string> {
  if (!Number.isSafeInteger(bodyLength) || bodyLength < 0 || bodyLength > MAX_REQUEST_BYTES) {
    throw fail('Desktop engine-session request body exceeds its limit')
  }
  return {
    Host: `127.0.0.1:${session.port}`,
    Connection: connection,
    'Content-Length': String(bodyLength),
    Accept: 'application/json',
    'Accept-Encoding': 'identity',
    'Cache-Control': 'no-store',
    ...(jsonBody ? { 'Content-Type': 'application/json' } : {})
  }
}

function parseRawHeaders(raw: readonly string[]): RawHeaderMap {
  if (!Array.isArray(raw) || raw.length % 2 !== 0) {
    throw fail('Desktop engine-session response headers are malformed')
  }
  const result = new Map<string, string[]>()
  for (let index = 0; index < raw.length; index += 2) {
    const name = raw[index]
    const value = raw[index + 1]
    if (
      typeof name !== 'string' ||
      !HEADER_NAME.test(name) ||
      typeof value !== 'string' ||
      value.length < 1 ||
      value !== value.trim() ||
      /[^\x20-\x7e]/.test(value)
    ) {
      throw fail('Desktop engine-session response headers are malformed')
    }
    const lowerName = name.toLowerCase()
    if (!lowerName.startsWith(SESSION_HEADER_PREFIX) && !ALLOWED_RESPONSE_HEADERS.has(lowerName)) {
      throw fail(`Desktop engine-session response contains unbound ${lowerName}`)
    }
    const values = result.get(lowerName) ?? []
    values.push(value)
    result.set(lowerName, values)
  }
  return result
}

function singleton(headers: RawHeaderMap, name: string, required = true): string | null {
  const values = headers.get(name.toLowerCase()) ?? []
  if (values.length === 0) {
    if (required) throw fail(`Desktop engine-session response is missing ${name}`)
    return null
  }
  if (values.length !== 1 || values[0].length < 1 || values[0] !== values[0].trim()) {
    throw fail(`Desktop engine-session response has ambiguous ${name}`)
  }
  return values[0]
}

function validatedResponseLength(headers: RawHeaderMap, maximum: number): number {
  const value = singleton(headers, 'content-length')
  if (!value || !CANONICAL_LENGTH.test(value)) {
    throw fail('Desktop engine-session response Content-Length is invalid')
  }
  const length = Number(value)
  if (!Number.isSafeInteger(length) || length > maximum) {
    throw fail('Desktop engine-session response exceeds its limit')
  }
  return length
}

function validateJsonResponseHeaders(
  raw: readonly string[],
  expectedConnection: 'keep-alive' | 'close',
  maximum: number
): number {
  const headers = parseRawHeaders(raw)
  if (
    singleton(headers, 'content-type') !== 'application/json' ||
    singleton(headers, 'cache-control') !== 'no-store' ||
    singleton(headers, 'connection') !== expectedConnection
  ) {
    throw fail('Desktop engine-session JSON response contract is invalid')
  }
  for (const optional of ['date', 'server', 'keep-alive']) singleton(headers, optional, false)
  return validatedResponseLength(headers, maximum)
}

function requireNoTrailers(response: IncomingMessage): void {
  if (response.rawTrailers.length !== 0) {
    throw fail('Desktop engine-session response trailers are forbidden')
  }
}

function assertPeer(socket: Socket, session: DesktopEngineSessionIdentity): void {
  if (
    socket.destroyed ||
    socket.connecting ||
    socket.localAddress !== '127.0.0.1' ||
    socket.remoteAddress !== '127.0.0.1' ||
    socket.remotePort !== session.port
  ) {
    throw fail('Desktop engine-session peer is invalid')
  }
}

async function readExactBody(response: IncomingMessage, expected: number): Promise<Buffer> {
  const storage = Buffer.allocUnsafe(expected)
  let total = 0
  for await (const raw of response) {
    const bytes = Buffer.isBuffer(raw) ? raw : Buffer.from(raw)
    if (total + bytes.length > expected) {
      response.destroy()
      throw fail('Desktop engine-session response exceeded its declared length')
    }
    bytes.copy(storage, total)
    total += bytes.length
  }
  if (total !== expected) throw fail('Desktop engine-session response length does not match')
  return storage
}

function parseJson(body: Buffer): unknown {
  let text: string
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(body)
  } catch {
    throw fail('Desktop engine-session response is not valid UTF-8')
  }
  try {
    return JSON.parse(text) as unknown
  } catch {
    throw fail('Desktop engine-session response is not valid JSON')
  }
}

function closedManifestFailure(): never {
  throw fail('Desktop engine-session request violates the closed manifest')
}

function strictRequestJson(body: Buffer): Record<string, unknown> {
  let text: string
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(body)
  } catch {
    return closedManifestFailure()
  }
  let value: unknown
  try {
    value = JSON.parse(text) as unknown
  } catch {
    return closedManifestFailure()
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return closedManifestFailure()
  }
  if (JSON.stringify(value) !== text) return closedManifestFailure()
  const pending: Array<{ value: unknown; depth: number }> = [{ value, depth: 1 }]
  while (pending.length > 0) {
    const current = pending.pop()
    if (!current) break
    if (current.depth > MAX_JSON_DEPTH) closedManifestFailure()
    if (Array.isArray(current.value)) {
      for (const child of current.value) {
        pending.push({ value: child, depth: current.depth + 1 })
      }
    } else if (current.value && typeof current.value === 'object') {
      for (const child of Object.values(current.value as Record<string, unknown>)) {
        pending.push({ value: child, depth: current.depth + 1 })
      }
    }
  }
  return value as Record<string, unknown>
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): void {
  const observed = Object.keys(value).sort()
  const wanted = [...expected].sort()
  if (observed.length !== wanted.length || observed.some((key, index) => key !== wanted[index])) {
    closedManifestFailure()
  }
}

function hasControl(value: string, nulOnly = false): boolean {
  return nulOnly ? value.includes('\0') : /[\u0000-\u001f\u007f]/.test(value)
}

function validateClosedExchange(input: DesktopEngineSessionJsonExchangeInput): void {
  if (
    !['GET', 'POST', 'DELETE'].includes(input.method) ||
    typeof input.target !== 'string' ||
    !(input.signal instanceof AbortSignal) ||
    !Number.isSafeInteger(input.totalTimeoutMs) ||
    input.totalTimeoutMs < 1 ||
    input.totalTimeoutMs > MAX_TOTAL_TIMEOUT_MS ||
    !Number.isSafeInteger(input.firstByteTimeoutMs) ||
    input.firstByteTimeoutMs < 1 ||
    input.firstByteTimeoutMs > input.totalTimeoutMs ||
    (input.bodyIdleTimeoutMs !== undefined &&
      (!Number.isSafeInteger(input.bodyIdleTimeoutMs) ||
        input.bodyIdleTimeoutMs < 1 ||
        input.bodyIdleTimeoutMs > 60_000)) ||
    !Buffer.isBuffer(input.body) ||
    input.body.byteLength > MAX_REQUEST_BYTES
  ) {
    closedManifestFailure()
  }
  const emptyBody = (): void => {
    if (input.body.byteLength !== 0) closedManifestFailure()
  }
  const postJson = (): Record<string, unknown> => {
    if (input.method !== 'POST') closedManifestFailure()
    return strictRequestJson(input.body)
  }

  if (input.capability === 'plugin.ui.snapshot') {
    if (
      input.method !== 'GET' ||
      input.target !== '/internal/v1/desktop/session/plugin-ui-snapshot'
    ) {
      closedManifestFailure()
    }
    emptyBody()
    return
  }

  if (input.capability === 'approval.list') {
    if (input.method !== 'GET') closedManifestFailure()
    emptyBody()
    const prefix = '/v1/approvals?user_id='
    if (!input.target.startsWith(prefix)) closedManifestFailure()
    const encoded = input.target.slice(prefix.length)
    let decoded: string
    try {
      decoded = decodeURIComponent(encoded)
    } catch {
      return closedManifestFailure()
    }
    if (
      decoded.length < 1 ||
      decoded.length > 128 ||
      hasControl(decoded) ||
      encodeURIComponent(decoded) !== encoded
    ) {
      closedManifestFailure()
    }
    return
  }

  if (input.capability === 'approval.resolve') {
    if (input.body.byteLength > APPROVAL_RESOLVE_BODY_LIMIT) closedManifestFailure()
    const match = /^\/v1\/approvals\/([1-9][0-9]*)\/resolve$/.exec(input.target)
    if (!match || !POSITIVE_DECIMAL.test(match[1])) closedManifestFailure()
    const id = Number(match[1])
    if (!Number.isSafeInteger(id) || id < 1) closedManifestFailure()
    const value = postJson()
    exactKeys(value, ['decision', 'note'])
    if (
      !['approve', 'reject', 'revise'].includes(String(value.decision)) ||
      typeof value.note !== 'string' ||
      value.note.length > 2_000 ||
      hasControl(value.note, true)
    ) {
      closedManifestFailure()
    }
    return
  }

  if (input.capability === 'connection.save' || input.capability === 'connection.delete') {
    const prefix = '/admin/connections/'
    const provider = input.target.startsWith(prefix) ? input.target.slice(prefix.length) : ''
    if (!PROVIDER_NAME.test(provider)) closedManifestFailure()
    if (input.capability === 'connection.delete') {
      if (input.method !== 'DELETE') closedManifestFailure()
      emptyBody()
      return
    }
    if (input.body.byteLength > CONNECTION_SAVE_BODY_LIMIT) closedManifestFailure()
    const value = postJson()
    exactKeys(value, [
      'type',
      'api_key',
      'base_url',
      'enabled_models',
      'preserve_existing_credential'
    ])
    if (
      typeof value.type !== 'string' ||
      value.type.length < 1 ||
      value.type.length > 128 ||
      hasControl(value.type) ||
      typeof value.api_key !== 'string' ||
      value.api_key.length > 32_768 ||
      hasControl(value.api_key, true) ||
      typeof value.base_url !== 'string' ||
      value.base_url.length > 2_048 ||
      hasControl(value.base_url) ||
      !Array.isArray(value.enabled_models) ||
      value.enabled_models.length > 200 ||
      typeof value.preserve_existing_credential !== 'boolean' ||
      value.enabled_models.some(
        (model) => !model || typeof model !== 'object' || Array.isArray(model)
      )
    ) {
      closedManifestFailure()
    }
    return
  }

  if (input.capability === 'sync.config') {
    if (input.body.byteLength > SYNC_CONFIG_BODY_LIMIT) closedManifestFailure()
    if (input.target !== '/v1/sync/config') closedManifestFailure()
    const value = postJson()
    exactKeys(value, ['url', 'anon_key'])
    if (
      typeof value.url !== 'string' ||
      value.url.length < 1 ||
      value.url.length > 2_048 ||
      hasControl(value.url) ||
      typeof value.anon_key !== 'string' ||
      value.anon_key.length < 1 ||
      value.anon_key.length > 16_384 ||
      hasControl(value.anon_key, true)
    ) {
      closedManifestFailure()
    }
    return
  }

  if (input.capability === 'sync.auth') {
    if (input.body.byteLength > SYNC_AUTH_BODY_LIMIT) closedManifestFailure()
    if (!['/v1/sync/login', '/v1/sync/signup'].includes(input.target)) {
      closedManifestFailure()
    }
    const value = postJson()
    exactKeys(value, ['email', 'password'])
    if (
      typeof value.email !== 'string' ||
      value.email.length < 1 ||
      value.email.length > 320 ||
      hasControl(value.email) ||
      typeof value.password !== 'string' ||
      value.password.length < 1 ||
      value.password.length > 1_024 ||
      hasControl(value.password, true)
    ) {
      closedManifestFailure()
    }
    return
  }

  if (input.capability === 'sync.toggle') {
    if (input.body.byteLength > SYNC_TOGGLE_BODY_LIMIT) closedManifestFailure()
    if (input.target !== '/v1/sync/toggle') closedManifestFailure()
    const value = postJson()
    exactKeys(value, ['enabled'])
    if (typeof value.enabled !== 'boolean') closedManifestFailure()
    return
  }

  if (input.capability === 'sync.run') {
    if (input.body.byteLength > SYNC_RUN_BODY_LIMIT) closedManifestFailure()
    if (input.target !== '/v1/sync/run') closedManifestFailure()
    const value = postJson()
    exactKeys(value, [])
    return
  }

  if (
    input.capability === 'channel-recovery.inspect' ||
    input.capability === 'channel-recovery.close'
  ) {
    if (input.body.byteLength > CHANNEL_RECOVERY_BODY_LIMIT) closedManifestFailure()
    const match = /^\/admin\/channel-recovery\/(weixin|feishu)\/(inspect|close-without-replay)$/.exec(
      input.target
    )
    if (!match) closedManifestFailure()
    const expectedAction =
      input.capability === 'channel-recovery.inspect' ? 'inspect' : 'close-without-replay'
    if (match[2] !== expectedAction) closedManifestFailure()
    const value = postJson()
    const targetKinds =
      match[1] === 'weixin'
        ? new Set(['inbound', 'delivery', 'video'])
        : new Set(['inbox', 'outbox', 'video'])
    if (input.capability === 'channel-recovery.inspect') {
      exactKeys(value, ['target_kind', 'target_key'])
      if (
        !targetKinds.has(String(value.target_kind)) ||
        typeof value.target_key !== 'string' ||
        value.target_key.length < 1 ||
        value.target_key.length > 512 ||
        hasControl(value.target_key)
      ) {
        closedManifestFailure()
      }
      return
    }
    exactKeys(value, [
      'target_kind',
      'target_key',
      'expected_before_digest',
      'decision_id',
      'decided_at_ms',
      'reason',
      'user_confirmed',
      'confirm_final'
    ])
    if (
      !targetKinds.has(String(value.target_kind)) ||
      typeof value.target_key !== 'string' ||
      value.target_key.length < 1 ||
      value.target_key.length > 512 ||
      hasControl(value.target_key) ||
      typeof value.expected_before_digest !== 'string' ||
      !LOWER_HEX_64.test(value.expected_before_digest) ||
      value.expected_before_digest === ZERO_DIGEST ||
      typeof value.decision_id !== 'string' ||
      !LOWER_HEX_64.test(value.decision_id) ||
      value.decision_id === ZERO_DIGEST ||
      !Number.isSafeInteger(value.decided_at_ms) ||
      Number(value.decided_at_ms) < 0 ||
      typeof value.reason !== 'string' ||
      value.reason.length < 1 ||
      value.reason.length > 2_048 ||
      hasControl(value.reason) ||
      value.user_confirmed !== true ||
      value.confirm_final !== true
    ) {
      closedManifestFailure()
    }
    return
  }

  closedManifestFailure()
}

function captureClosedExchange(input: unknown): DesktopEngineSessionJsonExchangeInput {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    closedManifestFailure()
  }
  const source = input as DesktopEngineSessionJsonExchangeInput
  if (!Buffer.isBuffer(source.body)) closedManifestFailure()
  const captured: DesktopEngineSessionJsonExchangeInput = {
    capability: source.capability,
    method: source.method,
    target: source.target,
    body: Buffer.from(source.body),
    signal: source.signal,
    totalTimeoutMs: source.totalTimeoutMs,
    firstByteTimeoutMs: source.firstByteTimeoutMs,
    ...(source.bodyIdleTimeoutMs === undefined
      ? {}
      : { bodyIdleTimeoutMs: source.bodyIdleTimeoutMs })
  }
  validateClosedExchange(captured)
  return Object.freeze(captured)
}

export class DesktopEngineSessionClient {
  private readonly now: () => number
  private readonly challengeTimeoutMs: number
  private readonly defaultBodyIdleTimeoutMs: number

  constructor(private readonly dependencies: DesktopEngineSessionClientDependencies) {
    if (!dependencies || typeof dependencies.session !== 'function') {
      throw fail('Desktop engine-session supplier is unavailable')
    }
    this.now = dependencies.now ?? Date.now
    this.challengeTimeoutMs = validTimeout(
      dependencies.challengeTimeoutMs ?? DEFAULT_CHALLENGE_TIMEOUT_MS,
      'Desktop engine-session challenge timeout',
      10_000
    )
    this.defaultBodyIdleTimeoutMs = validTimeout(
      dependencies.bodyIdleTimeoutMs ?? DEFAULT_BODY_IDLE_TIMEOUT_MS,
      'Desktop engine-session body idle timeout',
      60_000
    )
  }

  private captureSession(): DesktopEngineSessionIdentity {
    try {
      return validSession(this.dependencies.session())
    } catch {
      throw fail('Desktop engine session is unavailable')
    }
  }

  private sessionIsCurrent(captured: DesktopEngineSessionIdentity): boolean {
    try {
      return sameSession(captured, validSession(this.dependencies.session()))
    } catch {
      return false
    }
  }

  private assertSessionCurrent(captured: DesktopEngineSessionIdentity): void {
    if (!this.sessionIsCurrent(captured)) {
      throw fail('Desktop engine session changed during the request')
    }
  }

  private authenticateConnection(
    captured: DesktopEngineSessionIdentity,
    agent: Agent,
    signal: AbortSignal
  ): Promise<AuthenticatedConnection> {
    const baseHeaders = applicationHeaders(captured, 0, 'keep-alive', false)
    const signed = signDesktopEngineSessionRequest({
      session: captured,
      timestampMs: validNow(this.now()),
      nonce: randomBytes(32).toString('hex'),
      channelNonce: ZERO_DIGEST,
      capability: 'session.challenge',
      method: 'GET',
      target: DESKTOP_ENGINE_SESSION_CHALLENGE_PATH,
      bodySha256: sha256(Buffer.alloc(0)),
      rawHeaders: rawHeaders(baseHeaders)
    })

    return new Promise<AuthenticatedConnection>((resolve, reject) => {
      let settled = false
      let request: ClientRequest | null = null
      let response: IncomingMessage | null = null
      let pinned: Socket | null = null
      let totalTimer: NodeJS.Timeout | null = null

      const cleanup = (): void => {
        if (totalTimer) clearTimeout(totalTimer)
        totalTimer = null
        request?.setTimeout(0)
        signal.removeEventListener('abort', abort)
      }
      const rejectFixed = (message: string): void => {
        if (settled) return
        settled = true
        cleanup()
        response?.destroy()
        request?.destroy()
        reject(fail(message))
      }
      const abort = (): void => rejectFixed('Desktop engine-session challenge was cancelled')

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
          (incoming) => {
            response = incoming
            request?.setTimeout(0)
            void (async (): Promise<void> => {
              try {
                if (settled || !pinned || incoming.socket !== pinned) {
                  throw fail('Desktop engine-session challenge socket changed')
                }
                assertPeer(pinned, captured)
                this.assertSessionCurrent(captured)
                if (incoming.statusCode !== 200) {
                  throw fail('Desktop engine-session challenge status is invalid')
                }
                const expectedLength = validateJsonResponseHeaders(
                  incoming.rawHeaders,
                  'keep-alive',
                  MAX_CHALLENGE_BYTES
                )
                incoming.setTimeout(this.challengeTimeoutMs, () => {
                  rejectFixed('Desktop engine-session challenge body timed out')
                })
                const body = await readExactBody(incoming, expectedLength)
                requireNoTrailers(incoming)
                if (
                  !incoming.complete ||
                  body.toString('utf8') !== DESKTOP_ENGINE_SESSION_CHALLENGE_JSON
                ) {
                  throw fail('Desktop engine-session challenge body is invalid')
                }
                verifyDesktopEngineSessionResponse({
                  session: captured,
                  requestNonce: signed.nonce,
                  capability: 'session.challenge',
                  status: incoming.statusCode,
                  bodySha256: sha256(body),
                  rawHeaders: incoming.rawHeaders
                })
                this.assertSessionCurrent(captured)
                await new Promise<void>((next) => setImmediate(next))
                assertPeer(pinned, captured)
                this.assertSessionCurrent(captured)
                if (settled) return
                settled = true
                cleanup()
                resolve(Object.freeze({ socket: pinned, challengeNonce: signed.nonce }))
              } catch {
                rejectFixed('Desktop engine-session challenge failed authentication')
              }
            })()
          }
        )
      } catch {
        rejectFixed('Desktop engine-session challenge transport failed')
        return
      }
      request.once('socket', (socket) => {
        pinned = socket
      })
      request.once('upgrade', (incoming) => {
        incoming.destroy()
        rejectFixed('Desktop engine-session challenge upgrade is forbidden')
      })
      request.once('error', () => rejectFixed('Desktop engine-session challenge transport failed'))
      request.setTimeout(this.challengeTimeoutMs, () => {
        rejectFixed('Desktop engine-session challenge timed out')
      })
      totalTimer = setTimeout(() => {
        rejectFixed('Desktop engine-session challenge timed out')
      }, this.challengeTimeoutMs)
      totalTimer.unref()
      request.end()
    })
  }

  private performExchange(
    captured: DesktopEngineSessionIdentity,
    authenticated: AuthenticatedConnection,
    agent: Agent,
    input: DesktopEngineSessionJsonExchangeInput
  ): Promise<DesktopEngineSessionJsonResponse> {
    const totalTimeoutMs = validTimeout(
      input.totalTimeoutMs,
      'Desktop engine-session total timeout',
      MAX_TOTAL_TIMEOUT_MS
    )
    const firstByteTimeoutMs = validTimeout(
      input.firstByteTimeoutMs,
      'Desktop engine-session first-byte timeout',
      totalTimeoutMs
    )
    const bodyIdleTimeoutMs = validTimeout(
      input.bodyIdleTimeoutMs ?? this.defaultBodyIdleTimeoutMs,
      'Desktop engine-session body idle timeout',
      60_000
    )
    if (!Buffer.isBuffer(input.body) || input.body.byteLength > MAX_REQUEST_BYTES) {
      throw fail('Desktop engine-session request body is invalid')
    }
    const baseHeaders = applicationHeaders(
      captured,
      input.body.byteLength,
      'close',
      input.method === 'POST'
    )
    const signed = signDesktopEngineSessionRequest({
      session: captured,
      timestampMs: validNow(this.now()),
      nonce: randomBytes(32).toString('hex'),
      channelNonce: authenticated.challengeNonce,
      capability: input.capability,
      method: input.method,
      target: input.target,
      bodySha256: sha256(input.body),
      rawHeaders: rawHeaders(baseHeaders)
    })

    return new Promise<DesktopEngineSessionJsonResponse>((resolve, reject) => {
      let settled = false
      let sent = false
      let request: ClientRequest | null = null
      let response: IncomingMessage | null = null
      let totalTimer: NodeJS.Timeout | null = null
      const cleanup = (): void => {
        if (totalTimer) clearTimeout(totalTimer)
        totalTimer = null
        request?.setTimeout(0)
        input.signal.removeEventListener('abort', abort)
      }
      const rejectFixed = (message: string): void => {
        if (settled) return
        settled = true
        cleanup()
        response?.destroy()
        request?.destroy()
        reject(fail(message))
      }
      const abort = (): void => rejectFixed('Desktop engine-session request was cancelled')
      if (input.signal.aborted) {
        abort()
        return
      }
      input.signal.addEventListener('abort', abort, { once: true })
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
            headers: { ...baseHeaders, ...signed.headers },
            agent
          },
          (incoming) => {
            response = incoming
            request?.setTimeout(0)
            void (async (): Promise<void> => {
              try {
                if (
                  settled ||
                  !sent ||
                  incoming.socket !== authenticated.socket ||
                  incoming.statusCode === undefined ||
                  incoming.statusCode < 200 ||
                  incoming.statusCode > 599 ||
                  (incoming.statusCode >= 300 && incoming.statusCode <= 399)
                ) {
                  throw fail('Desktop engine-session response is invalid')
                }
                assertPeer(authenticated.socket, captured)
                this.assertSessionCurrent(captured)
                const expectedLength = validateJsonResponseHeaders(
                  incoming.rawHeaders,
                  'close',
                  MAX_RESPONSE_BYTES
                )
                incoming.setTimeout(bodyIdleTimeoutMs, () => {
                  rejectFixed('Desktop engine-session response body timed out')
                })
                const body = await readExactBody(incoming, expectedLength)
                requireNoTrailers(incoming)
                if (!incoming.complete) throw fail('Desktop engine-session response is incomplete')
                verifyDesktopEngineSessionResponse({
                  session: captured,
                  requestNonce: signed.nonce,
                  capability: input.capability,
                  status: incoming.statusCode,
                  bodySha256: sha256(body),
                  rawHeaders: incoming.rawHeaders
                })
                this.assertSessionCurrent(captured)
                const parsed = parseJson(body)
                if (settled) return
                settled = true
                cleanup()
                resolve(Object.freeze({ status: incoming.statusCode, body: parsed }))
              } catch {
                rejectFixed('Desktop engine-session response failed authentication')
              }
            })()
          }
        )
      } catch {
        rejectFixed('Desktop engine-session request transport failed')
        return
      }
      request.once('socket', (socket) => {
        try {
          if (socket !== authenticated.socket) {
            socket.destroy()
            throw fail('Desktop engine-session socket changed before dispatch')
          }
          assertPeer(socket, captured)
          this.assertSessionCurrent(captured)
          request?.setTimeout(firstByteTimeoutMs, () => {
            rejectFixed('Desktop engine-session response headers timed out')
          })
          sent = true
          request?.end(input.body)
        } catch {
          rejectFixed('Desktop engine-session request was not dispatched')
        }
      })
      request.once('upgrade', (incoming) => {
        incoming.destroy()
        rejectFixed('Desktop engine-session upgrade is forbidden')
      })
      request.once('error', () => rejectFixed('Desktop engine-session request transport failed'))
      totalTimer = setTimeout(() => {
        rejectFixed('Desktop engine-session request exceeded its total timeout')
      }, totalTimeoutMs)
      totalTimer.unref()
    })
  }

  async exchangeJson(
    input: DesktopEngineSessionJsonExchangeInput
  ): Promise<DesktopEngineSessionJsonResponse> {
    const capturedInput = captureClosedExchange(input)
    const captured = this.captureSession()
    this.assertSessionCurrent(captured)
    const agent = new Agent({ keepAlive: true, maxSockets: 1, maxFreeSockets: 1 })
    try {
      const authenticated = await this.authenticateConnection(
        captured,
        agent,
        capturedInput.signal
      )
      this.assertSessionCurrent(captured)
      return await this.performExchange(captured, authenticated, agent, capturedInput)
    } finally {
      agent.destroy()
    }
  }
}
