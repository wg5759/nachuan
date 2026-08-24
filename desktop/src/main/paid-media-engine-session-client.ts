import { createHash, randomBytes } from 'node:crypto'
import http, { Agent, type ClientRequest, type IncomingMessage } from 'node:http'
import type { Socket } from 'node:net'
import { Readable, Transform, pipeline } from 'node:stream'

import type {
  InstallationRootEngineSession,
  InstallationRootSessionSupplier
} from './installation-root-client'
import {
  PAID_MEDIA_ENGINE_SESSION_CHALLENGE_JSON,
  PAID_MEDIA_ENGINE_SESSION_CHALLENGE_PATH,
  type PaidMediaEngineSessionIdentity,
  signPaidMediaEngineSessionRequest,
  verifyPaidMediaEngineSessionResponse,
  verifyPaidMediaEngineSessionResponseEnvelope
} from './paid-media-engine-session-protocol'

const LOWER_HEX_64 = /^[0-9a-f]{64}$/
const ZERO_DIGEST = '0'.repeat(64)
const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/
const CANONICAL_LENGTH = /^(0|[1-9][0-9]*)$/
const SESSION_HEADER_PREFIX = 'x-nachuan-paid-session-'
const MAX_TOTAL_TIMEOUT_MS = 5 * 60 * 1000
// Matches paid-media-asset-protocol MAX_PAID_MEDIA_ASSET_RESULT_BYTES without
// importing the higher-level protocol into this transport module.
const MAX_BUFFER_REQUEST_BODY_BYTES = 1024 * 1024
const MAX_STREAM_REQUEST_BODY_BYTES = 24 * 1024 * 1024
export const PAID_MEDIA_ENGINE_SESSION_MAX_BODY_CHUNK_BYTES = 64 * 1024
export const PAID_MEDIA_ENGINE_SESSION_MAX_BODY_CHUNKS = 4_096
const DEFAULT_CHALLENGE_TIMEOUT_MS = 2_000
const DEFAULT_BODY_IDLE_TIMEOUT_MS = 20_000
const MAX_CHALLENGE_BYTES = 256

const RESERVED_APPLICATION_HEADERS = new Set([
  'host',
  'connection',
  'content-length',
  'authorization',
  'proxy-authorization',
  'x-nachuan-paid-media-key',
  'transfer-encoding',
  'expect',
  'trailer',
  'upgrade'
])

const FORBIDDEN_RESPONSE_HEADERS = [
  'content-encoding',
  'transfer-encoding',
  'content-range',
  'location',
  'trailer',
  'upgrade'
] as const

type RawHeaderMap = ReadonlyMap<string, readonly string[]>

export class PaidMediaEngineSessionClientError extends Error {
  override readonly name = 'PaidMediaEngineSessionClientError'
}

export interface PaidMediaEngineSessionClientDependencies {
  readonly session: InstallationRootSessionSupplier
  readonly now?: () => number
  readonly challengeTimeoutMs?: number
  readonly bodyIdleTimeoutMs?: number
  /**
   * Schedules the end-to-end policy deadline. Tests inject a deterministic
   * event source here; production keeps the real unref'd wall-clock timer.
   */
  readonly scheduleTotalTimeout?: (callback: () => void, delayMs: number) => () => void
  readonly onRequestBodyChunk?: (input: { byteLength: number }) => void
}

/**
 * A replay-free, file-backed request body.  The descriptor is authenticated
 * before the factory is invoked; the transport independently re-counts and
 * re-hashes every byte before it accepts a response.
 */
export interface PaidMediaEngineSessionBodySource {
  readonly byteLength: number
  readonly sha256: string
  readonly createReadStream: () => Readable | Promise<Readable>
}

export interface PaidMediaEngineSessionExchangeInput {
  readonly method: 'GET' | 'POST'
  readonly target: string
  readonly headers: Readonly<Record<string, string>>
  readonly body: Buffer | PaidMediaEngineSessionBodySource
  readonly signal: AbortSignal
  readonly totalTimeoutMs: number
  /** Time from sending the authenticated request to receiving response headers. */
  readonly firstByteTimeoutMs: number
  readonly bodyIdleTimeoutMs?: number
}

export interface PaidMediaEngineSessionResponse {
  readonly status: number
  readonly rawHeaders: readonly string[]
  readonly response: IncomingMessage
  readonly declaredBodySha256: string
}

export interface PaidMediaEngineSessionConsumed<T> {
  readonly value: T
  /** SHA-256 of the exact response bytes consumed from the pinned stream. */
  readonly bodySha256: string
}

function fail(message: string): PaidMediaEngineSessionClientError {
  return new PaidMediaEngineSessionClientError(message)
}

function sha256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex')
}

function prepareBody(
  value: unknown
): Readonly<{
  byteLength: number
  sha256: string
  buffer: Buffer | null
  source: PaidMediaEngineSessionBodySource | null
}> {
  if (Buffer.isBuffer(value)) {
    if (value.byteLength > MAX_BUFFER_REQUEST_BODY_BYTES) {
      throw fail('Paid media request body is invalid')
    }
    const snapshot = Buffer.from(value)
    return Object.freeze({
      byteLength: snapshot.byteLength,
      sha256: sha256(snapshot),
      buffer: snapshot,
      source: null
    })
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw fail('Paid media request body is invalid')
  }
  const source = value as PaidMediaEngineSessionBodySource
  const byteLength = source.byteLength
  const bodySha256 = source.sha256
  const createReadStream = source.createReadStream
  if (
    !Number.isSafeInteger(byteLength) ||
    byteLength < 0 ||
    byteLength > MAX_STREAM_REQUEST_BODY_BYTES ||
    typeof bodySha256 !== 'string' ||
    !LOWER_HEX_64.test(bodySha256) ||
    typeof createReadStream !== 'function'
  ) {
    throw fail('Paid media request body is invalid')
  }
  const snapshot = Object.freeze({
    byteLength,
    sha256: bodySha256,
    createReadStream: createReadStream.bind(source)
  })
  return Object.freeze({
    byteLength: snapshot.byteLength,
    sha256: snapshot.sha256,
    buffer: null,
    source: snapshot
  })
}

function validSession(value: unknown): PaidMediaEngineSessionIdentity {
  if (
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    !Number.isSafeInteger((value as InstallationRootEngineSession).generation) ||
    (value as InstallationRootEngineSession).generation < 1 ||
    !Number.isSafeInteger((value as InstallationRootEngineSession).pid) ||
    (value as InstallationRootEngineSession).pid < 1 ||
    !Number.isSafeInteger((value as InstallationRootEngineSession).port) ||
    (value as InstallationRootEngineSession).port < 1_024 ||
    (value as InstallationRootEngineSession).port > 65_535 ||
    typeof (value as InstallationRootEngineSession).bootToken !== 'string' ||
    !LOWER_HEX_64.test((value as InstallationRootEngineSession).bootToken) ||
    (value as InstallationRootEngineSession).bootToken === ZERO_DIGEST
  ) {
    throw fail('Paid media engine session is unavailable')
  }
  const session = value as InstallationRootEngineSession
  return Object.freeze({
    generation: session.generation,
    pid: session.pid,
    port: session.port,
    bootToken: session.bootToken
  })
}

function sameSession(
  left: PaidMediaEngineSessionIdentity,
  right: PaidMediaEngineSessionIdentity
): boolean {
  return (
    left.generation === right.generation &&
    left.pid === right.pid &&
    left.port === right.port &&
    left.bootToken === right.bootToken
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
    throw fail('Paid media engine-session clock is invalid')
  }
  return Number(value)
}

function scheduleSystemTimeout(callback: () => void, delayMs: number): () => void {
  let active = true
  const timer = setTimeout(() => {
    active = false
    callback()
  }, delayMs)
  timer.unref()
  return () => {
    if (!active) return
    active = false
    clearTimeout(timer)
  }
}

function rawHeaders(headers: Readonly<Record<string, string>>): string[] {
  return Object.entries(headers).flatMap(([name, value]) => [name, value])
}

function applicationHeaders(
  input: Readonly<Record<string, string>>,
  session: PaidMediaEngineSessionIdentity,
  bodyLength: number,
  connection: 'keep-alive' | 'close'
): Record<string, string> {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw fail('Paid media request headers are invalid')
  }
  const output: Record<string, string> = {
    Host: `127.0.0.1:${session.port}`,
    Connection: connection,
    'Content-Length': String(bodyLength)
  }
  const names = new Set<string>(['host', 'connection', 'content-length'])
  for (const [name, value] of Object.entries(input)) {
    const lowerName = name.toLowerCase()
    if (
      !HEADER_NAME.test(name) ||
      names.has(lowerName) ||
      RESERVED_APPLICATION_HEADERS.has(lowerName) ||
      lowerName.startsWith(SESSION_HEADER_PREFIX) ||
      typeof value !== 'string' ||
      value.length < 1 ||
      value !== value.trim() ||
      /[^\x20-\x7e]/.test(value) ||
      value.includes(',')
    ) {
      throw fail('Paid media request headers are invalid')
    }
    names.add(lowerName)
    output[name] = value
  }
  return output
}

function parseRawHeaders(raw: readonly string[]): RawHeaderMap {
  if (!Array.isArray(raw) || raw.length % 2 !== 0) {
    throw fail('Paid media response headers are malformed')
  }
  const result = new Map<string, string[]>()
  for (let index = 0; index < raw.length; index += 2) {
    const name = raw[index]
    const value = raw[index + 1]
    if (
      typeof name !== 'string' ||
      !HEADER_NAME.test(name) ||
      typeof value !== 'string' ||
      /[^\x20-\x7e]/.test(value)
    ) {
      throw fail('Paid media response headers are malformed')
    }
    const lowerName = name.toLowerCase()
    const values = result.get(lowerName) ?? []
    values.push(value)
    result.set(lowerName, values)
  }
  return result
}

function singleton(headers: RawHeaderMap, name: string, required = true): string | null {
  const values = headers.get(name.toLowerCase()) ?? []
  if (values.length === 0) {
    if (required) throw fail(`Paid media response is missing ${name}`)
    return null
  }
  if (
    values.length !== 1 ||
    values[0].length < 1 ||
    values[0] !== values[0].trim() ||
    values[0].includes(',')
  ) {
    throw fail(`Paid media response has ambiguous ${name}`)
  }
  return values[0]
}

function contentLength(headers: RawHeaderMap, maximum: number): number {
  const value = singleton(headers, 'content-length')
  if (!value || !CANONICAL_LENGTH.test(value)) {
    throw fail('Paid media response Content-Length is invalid')
  }
  const length = Number(value)
  if (!Number.isSafeInteger(length) || length > maximum) {
    throw fail('Paid media response Content-Length exceeds its limit')
  }
  return length
}

function requireNoTransforms(headers: RawHeaderMap): void {
  for (const name of FORBIDDEN_RESPONSE_HEADERS) {
    if ((headers.get(name) ?? []).length !== 0) {
      throw fail(`Paid media response contains forbidden ${name}`)
    }
  }
}

function requireNoTrailers(response: IncomingMessage): void {
  if (response.rawTrailers.length !== 0) {
    throw fail('Paid media response trailers are forbidden')
  }
}

function assertPeer(socket: Socket, session: PaidMediaEngineSessionIdentity): void {
  if (
    socket.destroyed ||
    socket.connecting ||
    socket.localAddress !== '127.0.0.1' ||
    socket.remoteAddress !== '127.0.0.1' ||
    socket.remotePort !== session.port
  ) {
    throw fail('Paid media engine-session peer is invalid')
  }
}

async function readExactBody(response: IncomingMessage, expected: number): Promise<Buffer> {
  const storage = Buffer.allocUnsafe(expected)
  let total = 0
  for await (const raw of response) {
    const bytes = Buffer.isBuffer(raw) ? raw : Buffer.from(raw)
    if (total + bytes.length > expected) {
      response.destroy()
      throw fail('Paid media response exceeded its declared length')
    }
    bytes.copy(storage, total)
    total += bytes.length
  }
  if (total !== expected) {
    throw fail('Paid media response length does not match')
  }
  return storage
}

/**
 * Authenticates the freshly published engine before releasing any sensitive
 * paid-media target, token or body.  The actual request is ended only after
 * Node assigns the exact TCP socket that carried the signed challenge.
 */
export class PaidMediaEngineSessionClient {
  private readonly now: () => number
  private readonly challengeTimeoutMs: number
  private readonly defaultBodyIdleTimeoutMs: number
  private readonly scheduleTotalTimeout: (callback: () => void, delayMs: number) => () => void

  constructor(private readonly dependencies: PaidMediaEngineSessionClientDependencies) {
    if (!dependencies || typeof dependencies.session !== 'function') {
      throw fail('Paid media engine-session supplier is unavailable')
    }
    if (
      dependencies.scheduleTotalTimeout !== undefined &&
      typeof dependencies.scheduleTotalTimeout !== 'function'
    ) {
      throw fail('Paid media engine-session total-timeout policy is unavailable')
    }
    this.now = dependencies.now ?? Date.now
    this.scheduleTotalTimeout = dependencies.scheduleTotalTimeout ?? scheduleSystemTimeout
    this.challengeTimeoutMs = validTimeout(
      dependencies.challengeTimeoutMs ?? DEFAULT_CHALLENGE_TIMEOUT_MS,
      'Paid media engine-session challenge timeout',
      10_000
    )
    this.defaultBodyIdleTimeoutMs = validTimeout(
      dependencies.bodyIdleTimeoutMs ?? DEFAULT_BODY_IDLE_TIMEOUT_MS,
      'Paid media engine-session body idle timeout',
      60_000
    )
  }

  private captureSession(): PaidMediaEngineSessionIdentity {
    try {
      return validSession(this.dependencies.session())
    } catch {
      throw fail('Paid media engine session is unavailable')
    }
  }

  private sessionIsCurrent(captured: PaidMediaEngineSessionIdentity): boolean {
    try {
      return sameSession(captured, validSession(this.dependencies.session()))
    } catch {
      return false
    }
  }

  private assertSessionCurrent(captured: PaidMediaEngineSessionIdentity): void {
    if (!this.sessionIsCurrent(captured)) {
      throw fail('Paid media engine session changed during the request')
    }
  }

  private authenticateConnection(
    captured: PaidMediaEngineSessionIdentity,
    agent: Agent,
    signal: AbortSignal
  ): Promise<Socket> {
    const baseHeaders = applicationHeaders(
      { Accept: 'application/json', 'Cache-Control': 'no-store' },
      captured,
      0,
      'keep-alive'
    )
    const signed = signPaidMediaEngineSessionRequest({
      session: captured,
      timestampMs: validNow(this.now()),
      nonce: randomBytes(32).toString('hex'),
      method: 'GET',
      target: PAID_MEDIA_ENGINE_SESSION_CHALLENGE_PATH,
      bodySha256: sha256(Buffer.alloc(0)),
      rawHeaders: rawHeaders(baseHeaders)
    })

    return new Promise<Socket>((resolve, reject) => {
      let settled = false
      let request: ClientRequest | null = null
      let response: IncomingMessage | null = null
      let pinned: Socket | null = null
      let totalTimer: NodeJS.Timeout | null = null

      const cleanup = (): void => {
        if (totalTimer) clearTimeout(totalTimer)
        totalTimer = null
        request?.setTimeout(0)
        request?.removeListener('timeout', onChallengeHeaderTimeout)
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
      const abort = (): void => rejectFixed('Paid media engine-session challenge was cancelled')
      const onChallengeHeaderTimeout = (): void => {
        rejectFixed('Paid media engine-session challenge timed out')
      }

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
            path: PAID_MEDIA_ENGINE_SESSION_CHALLENGE_PATH,
            headers: { ...baseHeaders, ...signed.headers },
            agent
          },
          (incoming) => {
            response = incoming
            request?.setTimeout(0)
            request?.removeListener('timeout', onChallengeHeaderTimeout)
            void (async (): Promise<void> => {
              try {
                if (settled || !pinned || incoming.socket !== pinned) {
                  throw fail('Paid media engine-session challenge socket changed')
                }
                assertPeer(pinned, captured)
                this.assertSessionCurrent(captured)
                if (incoming.statusCode !== 200) {
                  throw fail('Paid media engine-session challenge status is invalid')
                }
                const verified = verifyPaidMediaEngineSessionResponseEnvelope({
                  session: captured,
                  requestNonce: signed.nonce,
                  status: incoming.statusCode,
                  rawHeaders: incoming.rawHeaders
                })
                const headers = parseRawHeaders(incoming.rawHeaders)
                requireNoTransforms(headers)
                if (
                  singleton(headers, 'content-type') !== 'application/json' ||
                  singleton(headers, 'cache-control') !== 'no-store' ||
                  singleton(headers, 'connection') !== 'keep-alive'
                ) {
                  throw fail('Paid media engine-session challenge metadata is invalid')
                }
                const expectedLength = Buffer.byteLength(
                  PAID_MEDIA_ENGINE_SESSION_CHALLENGE_JSON,
                  'utf8'
                )
                if (contentLength(headers, MAX_CHALLENGE_BYTES) !== expectedLength) {
                  throw fail('Paid media engine-session challenge length is invalid')
                }
                incoming.setTimeout(this.challengeTimeoutMs, () => {
                  rejectFixed('Paid media engine-session challenge body timed out')
                })
                const body = await readExactBody(incoming, expectedLength)
                requireNoTrailers(incoming)
                if (
                  !incoming.complete ||
                  body.toString('utf8') !== PAID_MEDIA_ENGINE_SESSION_CHALLENGE_JSON
                ) {
                  throw fail('Paid media engine-session challenge body is invalid')
                }
                verifyPaidMediaEngineSessionResponse({
                  session: captured,
                  requestNonce: signed.nonce,
                  status: incoming.statusCode,
                  bodySha256: sha256(body),
                  rawHeaders: incoming.rawHeaders
                })
                if (verified.declaredBodySha256 !== sha256(body)) {
                  throw fail('Paid media engine-session challenge digest is invalid')
                }
                this.assertSessionCurrent(captured)
                await new Promise<void>((next) => setImmediate(next))
                assertPeer(pinned, captured)
                this.assertSessionCurrent(captured)
                if (settled) return
                settled = true
                cleanup()
                resolve(pinned)
              } catch {
                rejectFixed('Paid media engine-session challenge failed')
              }
            })()
          }
        )
      } catch {
        rejectFixed('Paid media engine-session challenge failed')
        return
      }

      request.once('socket', (socket) => {
        pinned = socket
      })
      request.once('upgrade', (incoming) => {
        incoming.destroy()
        rejectFixed('Paid media engine-session challenge upgrade is forbidden')
      })
      request.once('error', () => {
        rejectFixed('Paid media engine-session challenge transport failed')
      })
      request.setTimeout(this.challengeTimeoutMs)
      request.once('timeout', onChallengeHeaderTimeout)
      totalTimer = setTimeout(() => {
        rejectFixed('Paid media engine-session challenge timed out')
      }, this.challengeTimeoutMs)
      totalTimer.unref()
      request.end()
    })
  }

  private performExchange<T>(
    captured: PaidMediaEngineSessionIdentity,
    pinned: Socket,
    agent: Agent,
    input: PaidMediaEngineSessionExchangeInput,
    body: ReturnType<typeof prepareBody>,
    consume: (
      response: PaidMediaEngineSessionResponse
    ) => Promise<PaidMediaEngineSessionConsumed<T>>
  ): Promise<T> {
    const totalTimeoutMs = validTimeout(
      input.totalTimeoutMs,
      'Paid media request total timeout',
      MAX_TOTAL_TIMEOUT_MS
    )
    const firstByteTimeoutMs = validTimeout(
      input.firstByteTimeoutMs,
      'Paid media request first-byte timeout',
      totalTimeoutMs
    )
    const bodyIdleTimeoutMs = validTimeout(
      input.bodyIdleTimeoutMs ?? this.defaultBodyIdleTimeoutMs,
      'Paid media response body idle timeout',
      60_000
    )
    const baseHeaders = applicationHeaders(
      input.headers,
      captured,
      body.byteLength,
      'close'
    )
    const signed = signPaidMediaEngineSessionRequest({
      session: captured,
      timestampMs: validNow(this.now()),
      nonce: randomBytes(32).toString('hex'),
      method: input.method,
      target: input.target,
      bodySha256: body.sha256,
      rawHeaders: rawHeaders(baseHeaders)
    })

    return new Promise<T>((resolve, reject) => {
      let settled = false
      let uploadStarted = false
      let uploadComplete = false
      let request: ClientRequest | null = null
      let response: IncomingMessage | null = null
      let source: Readable | null = null
      let meter: Transform | null = null
      let cancelTotalTimeout: (() => void) | null = null

      const cleanup = (): void => {
        cancelTotalTimeout?.()
        cancelTotalTimeout = null
        request?.setTimeout(0)
        request?.removeListener('timeout', onFirstByteTimeout)
        input.signal.removeEventListener('abort', abort)
      }
      const rejectFixed = (message: string): void => {
        if (settled) return
        settled = true
        cleanup()
        response?.destroy()
        source?.destroy()
        meter?.destroy()
        request?.destroy()
        reject(fail(message))
      }
      const abort = (): void => rejectFixed('Paid media engine-session request was cancelled')
      const onFirstByteTimeout = (): void => {
        rejectFixed('Paid media engine-session response headers timed out')
      }

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
            request?.removeListener('timeout', onFirstByteTimeout)
            void (async (): Promise<void> => {
              try {
                if (
                  settled ||
                  !uploadStarted ||
                  !uploadComplete ||
                  incoming.socket !== pinned ||
                  incoming.statusCode === undefined ||
                  incoming.statusCode < 200 ||
                  incoming.statusCode > 599 ||
                  (incoming.statusCode >= 300 && incoming.statusCode <= 399)
                ) {
                  throw fail('Paid media engine-session response is invalid')
                }
                assertPeer(pinned, captured)
                this.assertSessionCurrent(captured)
                const verified = verifyPaidMediaEngineSessionResponseEnvelope({
                  session: captured,
                  requestNonce: signed.nonce,
                  status: incoming.statusCode,
                  rawHeaders: incoming.rawHeaders
                })
                requireNoTransforms(parseRawHeaders(incoming.rawHeaders))
                incoming.setTimeout(bodyIdleTimeoutMs, () => {
                  rejectFixed('Paid media engine-session response body timed out')
                })
                const consumed = await consume(
                  Object.freeze({
                    status: incoming.statusCode,
                    rawHeaders: incoming.rawHeaders,
                    response: incoming,
                    declaredBodySha256: verified.declaredBodySha256
                  })
                )
                if (
                  !consumed ||
                  typeof consumed !== 'object' ||
                  typeof consumed.bodySha256 !== 'string' ||
                  !LOWER_HEX_64.test(consumed.bodySha256) ||
                  !incoming.complete
                ) {
                  throw fail('Paid media engine-session response consumption is invalid')
                }
                requireNoTrailers(incoming)
                verifyPaidMediaEngineSessionResponse({
                  session: captured,
                  requestNonce: signed.nonce,
                  status: incoming.statusCode,
                  bodySha256: consumed.bodySha256,
                  rawHeaders: incoming.rawHeaders
                })
                this.assertSessionCurrent(captured)
                if (settled) return
                settled = true
                cleanup()
                resolve(consumed.value)
              } catch {
                rejectFixed('Paid media engine-session response failed authentication')
              }
            })()
          }
        )
      } catch {
        rejectFixed('Paid media engine-session request transport failed')
        return
      }

      request.once('socket', (socket) => {
        void (async (): Promise<void> => {
          try {
            if (socket !== pinned) {
              socket.destroy()
              throw fail('Paid media engine-session socket changed before dispatch')
            }
            assertPeer(socket, captured)
            this.assertSessionCurrent(captured)
            request?.setTimeout(firstByteTimeoutMs)
            request?.once('timeout', onFirstByteTimeout)
            request?.once('finish', () => {
              uploadComplete = true
            })
            uploadStarted = true
            const candidate = body.buffer
              ? Readable.from(
                  (function* boundedBufferChunks(): Generator<Buffer> {
                    for (
                      let offset = 0;
                      offset < body.buffer!.length;
                      offset += PAID_MEDIA_ENGINE_SESSION_MAX_BODY_CHUNK_BYTES
                    ) {
                      yield body.buffer!.subarray(
                        offset,
                        offset + PAID_MEDIA_ENGINE_SESSION_MAX_BODY_CHUNK_BYTES
                      )
                    }
                  })(),
                  { objectMode: false, highWaterMark: 1 }
                )
              : await body.source!.createReadStream()
            if (!(candidate instanceof Readable)) {
              throw fail('Paid media request body source is invalid')
            }
            if (settled) {
              candidate.destroy()
              return
            }
            source = candidate
            const digest = createHash('sha256')
            const observeBodyChunk = this.dependencies.onRequestBodyChunk
            let byteLength = 0
            let chunkCount = 0
            meter = new Transform({
              transform(chunk: unknown, _encoding, callback): void {
                try {
                  const rawLength =
                    Buffer.isBuffer(chunk) || chunk instanceof Uint8Array
                      ? chunk.byteLength
                      : -1
                  if (
                    rawLength < 1 ||
                    rawLength > PAID_MEDIA_ENGINE_SESSION_MAX_BODY_CHUNK_BYTES ||
                    chunkCount >= PAID_MEDIA_ENGINE_SESSION_MAX_BODY_CHUNKS ||
                    byteLength + rawLength > body.byteLength
                  ) {
                    callback(fail('Paid media request body exceeded its declared length'))
                    return
                  }
                  const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array)
                  chunkCount += 1
                  byteLength += bytes.length
                  digest.update(bytes)
                  // Observability contains only bounded byte counts, never body data.
                  observeBodyChunk?.({ byteLength: bytes.length })
                  callback(null, bytes)
                } catch (error) {
                  callback(error as Error)
                }
              },
              flush(callback): void {
                try {
                  if (byteLength !== body.byteLength) {
                    callback(fail('Paid media request body length does not match'))
                    return
                  }
                  if (digest.digest('hex') !== body.sha256) {
                    callback(fail('Paid media request body digest does not match'))
                    return
                  }
                  callback()
                } catch (error) {
                  callback(error as Error)
                }
              }
            })
            pipeline(source, meter, request!, (error) => {
              if (error) {
                rejectFixed('Paid media engine-session request body failed verification')
              }
            })
          } catch {
            rejectFixed('Paid media engine-session request was not dispatched')
          }
        })()
      })
      request.once('upgrade', (incoming) => {
        incoming.destroy()
        rejectFixed('Paid media engine-session upgrade is forbidden')
      })
      request.once('error', () => {
        rejectFixed('Paid media engine-session request transport failed')
      })
      try {
        cancelTotalTimeout = this.scheduleTotalTimeout(() => {
          rejectFixed('Paid media engine-session request exceeded its total timeout')
        }, totalTimeoutMs)
        if (typeof cancelTotalTimeout !== 'function') {
          throw fail('Paid media engine-session total-timeout policy is unavailable')
        }
      } catch {
        rejectFixed('Paid media engine-session total-timeout policy failed')
      }
    })
  }

  async exchange<T>(
    input: PaidMediaEngineSessionExchangeInput,
    consume: (
      response: PaidMediaEngineSessionResponse
    ) => Promise<PaidMediaEngineSessionConsumed<T>>
  ): Promise<T> {
    if (!input || typeof input !== 'object' || typeof consume !== 'function') {
      throw fail('Paid media engine-session request is invalid')
    }
    const body = prepareBody(input.body)
    const captured = this.captureSession()
    this.assertSessionCurrent(captured)
    const agent = new Agent({ keepAlive: true, maxSockets: 1, maxFreeSockets: 1 })
    try {
      const pinned = await this.authenticateConnection(captured, agent, input.signal)
      this.assertSessionCurrent(captured)
      try {
        return await this.performExchange(captured, pinned, agent, input, body, consume)
      } finally {
        this.assertSessionCurrent(captured)
      }
    } finally {
      agent.destroy()
    }
  }
}
