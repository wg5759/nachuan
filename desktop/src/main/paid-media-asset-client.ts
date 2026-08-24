import { createHash } from 'node:crypto'
import type { IncomingMessage } from 'node:http'
import { TextDecoder } from 'node:util'

import {
  MAX_PAID_MEDIA_ASSET_BYTES,
  MAX_PAID_MEDIA_ASSET_RESULT_BYTES,
  PAID_MEDIA_ASSET_PROTOCOL_HEADER,
  PAID_MEDIA_ASSET_PROTOCOL_VERSION,
  type PaidMediaAssetAck,
  type PaidMediaAssetDescriptor,
  type PaidMediaAssetResult,
  parsePaidMediaAssetAck,
  parsePaidMediaAssetResult
} from './paid-media-asset-protocol'
import type {
  PaidMediaEngineSessionClient,
  PaidMediaEngineSessionConsumed,
  PaidMediaEngineSessionResponse
} from './paid-media-engine-session-client'

const RESPONSE_TIMEOUT_MS = 5 * 60 * 1000
const RESPONSE_IDLE_TIMEOUT_MS = 20 * 1000
const MAX_ACK_RESPONSE_BYTES = 64 * 1024
const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/
const CANONICAL_LENGTH = /^(0|[1-9][0-9]*)$/
const IDEMPOTENCY_KEY = /^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$/
const ERROR_CODE = /^[a-z][a-z0-9_]{0,127}$/
const STAGE_LEASE_ID = /^[0-9a-f]{64}$/
const STAGE_OPERATION_ID = /^desktop-op-[0-9a-f-]{36}$/i
const UTF8_FATAL = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })

export class PaidMediaAssetClientError extends Error {
  override readonly name: string = 'PaidMediaAssetClientError'

  constructor(message: string, options?: ErrorOptions) {
    super(message, options)
  }
}

export class PaidMediaAssetRemoteError extends PaidMediaAssetClientError {
  override readonly name: string = 'PaidMediaAssetRemoteError'

  constructor(
    readonly status: number,
    readonly code: string,
    readonly retryable: boolean,
    readonly retryAfterSeconds?: number
  ) {
    super('Paid media Gateway rejected the authenticated asset request')
  }
}

export interface PaidMediaRawResponse {
  status: number
  rawHeaders: readonly string[]
  rawTrailers?: readonly string[]
  body: Buffer
}

export interface PaidMediaAssetStageWriteCapability {
  readonly leaseId: string
  readonly operationId: string
  readonly turnId: string
  readonly ordinal: number
  readonly descriptor: PaidMediaAssetDescriptor
  write(bytes: Uint8Array, position: number): Promise<{ bytesWritten: number }>
  sync(): Promise<void>
}

export interface PaidMediaDownloadedAsset {
  readonly descriptor: PaidMediaAssetDescriptor
  readonly byteLength: number
  readonly sha256: string
}

export interface PaidMediaAssetDownloadInput {
  sessionClient: Pick<PaidMediaEngineSessionClient, 'exchange'>
  stage: PaidMediaAssetStageWriteCapability
  signal: AbortSignal
  timeoutMs?: number
}

export type PaidMediaAssetAckResult =
  | { ok: true; cleanupComplete: boolean; replayed: boolean }
  | Extract<PaidMediaImageAssetCreateResult, { ok: false }>

export type PaidMediaImageAssetCreateResult =
  | {
      ok: true
      status: 200
      replayed: boolean
      result: PaidMediaAssetResult
    }
  | {
      ok: false
      status: number
      code: string
      retryable: boolean
      retryAfterSeconds?: number
    }

type HeaderMap = ReadonlyMap<string, readonly string[]>

function fail(message: string, cause?: unknown): PaidMediaAssetClientError {
  return new PaidMediaAssetClientError(
    message,
    cause === undefined ? undefined : { cause }
  )
}


function parseRawHeaders(rawHeaders: readonly string[]): HeaderMap {
  if (!Array.isArray(rawHeaders) || rawHeaders.length % 2 !== 0) {
    throw fail('Paid media response headers are malformed')
  }
  const values = new Map<string, string[]>()
  for (let index = 0; index < rawHeaders.length; index += 2) {
    const rawName = rawHeaders[index]
    const rawValue = rawHeaders[index + 1]
    if (
      typeof rawName !== 'string' ||
      !HEADER_NAME.test(rawName) ||
      typeof rawValue !== 'string' ||
      /[\r\n\0]/.test(rawValue)
    ) {
      throw fail('Paid media response headers are malformed')
    }
    const name = rawName.toLowerCase()
    const current = values.get(name) ?? []
    current.push(rawValue.trim())
    values.set(name, current)
  }
  return values
}

function singleton(headers: HeaderMap, name: string, required = true): string | null {
  const values = headers.get(name.toLowerCase()) ?? []
  if (values.length === 0) {
    if (required) throw fail(`Paid media response is missing ${name}`)
    return null
  }
  if (values.length !== 1 || values[0].includes(',')) {
    throw fail(`Paid media response has ambiguous ${name}`)
  }
  return values[0]
}

function requireNoTransportTransform(headers: HeaderMap): void {
  for (const name of [
    'content-encoding',
    'transfer-encoding',
    'content-range',
    'location',
    'trailer',
    'upgrade'
  ]) {
    if ((headers.get(name) ?? []).length !== 0) {
      throw fail(`Paid media response contains forbidden ${name}`)
    }
  }
}

function canonicalContentLength(headers: HeaderMap): number {
  const value = singleton(headers, 'content-length')
  if (!value || !CANONICAL_LENGTH.test(value)) {
    throw fail('Paid media response Content-Length is invalid')
  }
  const length = Number(value)
  if (!Number.isSafeInteger(length)) {
    throw fail('Paid media response Content-Length is invalid')
  }
  return length
}

function requireProtocolV2(headers: HeaderMap): void {
  if (
    singleton(headers, PAID_MEDIA_ASSET_PROTOCOL_HEADER) !==
    PAID_MEDIA_ASSET_PROTOCOL_VERSION
  ) {
    throw fail('Paid media response protocol version is invalid')
  }
}

function decodeStrictUtf8(bytes: Buffer, label: string): string {
  try {
    return UTF8_FATAL.decode(bytes)
  } catch (error) {
    throw fail(`${label} is not valid UTF-8`, error)
  }
}

function requireNoTrailers(rawTrailers: readonly string[] | undefined): void {
  if (rawTrailers && rawTrailers.length !== 0) {
    throw fail('Paid media response trailers are forbidden')
  }
}

export function parsePaidMediaAssetResultResponse(
  response: PaidMediaRawResponse,
  expectedKind: 'image' | 'video'
): PaidMediaAssetResult {
  if (
    !response ||
    typeof response !== 'object' ||
    !Number.isInteger(response.status) ||
    response.status !== 200 ||
    !Buffer.isBuffer(response.body) ||
    response.body.length < 2 ||
    response.body.length > MAX_PAID_MEDIA_ASSET_RESULT_BYTES
  ) {
    throw fail('Paid media asset metadata response is invalid')
  }
  const headers = parseRawHeaders(response.rawHeaders)
  requireProtocolV2(headers)
  requireNoTransportTransform(headers)
  requireNoTrailers(response.rawTrailers)
  if (singleton(headers, 'content-type') !== 'application/json') {
    throw fail('Paid media asset metadata Content-Type is invalid')
  }
  if (singleton(headers, 'cache-control') !== 'no-store') {
    throw fail('Paid media asset metadata cache policy is invalid')
  }
  if (canonicalContentLength(headers) !== response.body.length) {
    throw fail('Paid media asset metadata length does not match')
  }
  let value: unknown
  try {
    value = JSON.parse(decodeStrictUtf8(response.body, 'Paid media asset metadata'))
  } catch (error) {
    if (error instanceof PaidMediaAssetClientError) throw error
    throw fail('Paid media asset metadata JSON is invalid', error)
  }
  const result = parsePaidMediaAssetResult(value)
  if (result.kind !== expectedKind) {
    throw fail('Paid media asset metadata kind does not match the operation')
  }
  return result
}

function parsePaidMediaErrorResponse(response: PaidMediaRawResponse): Extract<
  PaidMediaImageAssetCreateResult,
  { ok: false }
> {
  if (
    !Number.isInteger(response.status) ||
    response.status < 400 ||
    response.status > 599 ||
    !Buffer.isBuffer(response.body) ||
    response.body.length < 2 ||
    response.body.length > MAX_ACK_RESPONSE_BYTES
  ) {
    throw fail('Paid media error response is invalid')
  }
  const headers = parseRawHeaders(response.rawHeaders)
  requireProtocolV2(headers)
  requireNoTransportTransform(headers)
  requireNoTrailers(response.rawTrailers)
  if (singleton(headers, 'content-type') !== 'application/json') {
    throw fail('Paid media error Content-Type is invalid')
  }
  if (singleton(headers, 'cache-control') !== 'no-store') {
    throw fail('Paid media error cache policy is invalid')
  }
  if (canonicalContentLength(headers) !== response.body.length) {
    throw fail('Paid media error response length does not match')
  }
  let value: unknown
  try {
    value = JSON.parse(decodeStrictUtf8(response.body, 'Paid media error response'))
  } catch (error) {
    if (error instanceof PaidMediaAssetClientError) throw error
    throw fail('Paid media error response JSON is invalid')
  }
  if (
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    Object.keys(value as Record<string, unknown>).join('\0') !== 'detail'
  ) {
    throw fail('Paid media error response schema is invalid')
  }
  const detail = (value as Record<string, unknown>).detail
  if (
    !detail ||
    typeof detail !== 'object' ||
    Array.isArray(detail) ||
    Object.keys(detail as Record<string, unknown>).sort().join('\0') !==
      ['code', 'message', 'retryable'].sort().join('\0')
  ) {
    throw fail('Paid media error detail schema is invalid')
  }
  const document = detail as Record<string, unknown>
  if (
    typeof document.code !== 'string' ||
    !ERROR_CODE.test(document.code) ||
    typeof document.message !== 'string' ||
    Buffer.byteLength(document.message, 'utf8') > 1024 ||
    /[\r\n\0]/.test(document.message) ||
    typeof document.retryable !== 'boolean'
  ) {
    throw fail('Paid media error detail is invalid')
  }
  const retryAfter = singleton(headers, 'retry-after', false)
  let retryAfterSeconds: number | undefined
  if (retryAfter !== null) {
    if (!CANONICAL_LENGTH.test(retryAfter)) {
      throw fail('Paid media error Retry-After is invalid')
    }
    retryAfterSeconds = Number(retryAfter)
    if (
      !Number.isSafeInteger(retryAfterSeconds) ||
      retryAfterSeconds < 1 ||
      retryAfterSeconds > 900
    ) {
      throw fail('Paid media error Retry-After is invalid')
    }
    if (document.retryable !== true) {
      throw fail('Paid media error retry policy is inconsistent')
    }
  }
  return {
    ok: false,
    status: response.status,
    code: document.code,
    retryable: document.retryable,
    ...(retryAfterSeconds === undefined ? {} : { retryAfterSeconds })
  }
}

function validatedTimeout(value: number | undefined): number {
  const timeout = value ?? RESPONSE_TIMEOUT_MS
  if (!Number.isSafeInteger(timeout) || timeout < 1_000 || timeout > RESPONSE_TIMEOUT_MS) {
    throw fail('Paid media asset timeout is invalid')
  }
  return timeout
}

function requestHeaders(accept: string): Record<string, string> {
  return {
    [PAID_MEDIA_ASSET_PROTOCOL_HEADER]: PAID_MEDIA_ASSET_PROTOCOL_VERSION,
    Accept: accept,
    'Accept-Encoding': 'identity',
    'Cache-Control': 'no-store'
  }
}

function requireSessionClient(
  value: Pick<PaidMediaEngineSessionClient, 'exchange'>
): Pick<PaidMediaEngineSessionClient, 'exchange'> {
  if (!value || typeof value.exchange !== 'function') {
    throw fail('Paid media engine-session client is unavailable')
  }
  return value
}

function validatedDownloadHeaders(
  response: IncomingMessage,
  descriptor: PaidMediaAssetDescriptor
): void {
  if (response.statusCode !== 200) {
    throw fail('Paid media asset download was not successful')
  }
  const headers = parseRawHeaders(response.rawHeaders)
  requireProtocolV2(headers)
  requireNoTransportTransform(headers)
  if (singleton(headers, 'content-type') !== descriptor.mediaType) {
    throw fail('Paid media asset Content-Type does not match its receipt')
  }
  if (canonicalContentLength(headers) !== descriptor.byteLength) {
    throw fail('Paid media asset Content-Length does not match its receipt')
  }
  if (singleton(headers, 'x-content-sha256') !== descriptor.sha256) {
    throw fail('Paid media asset digest header does not match its receipt')
  }
  if (singleton(headers, 'cache-control') !== 'no-store') {
    throw fail('Paid media asset cache policy is invalid')
  }
  if (singleton(headers, 'x-content-type-options') !== 'nosniff') {
    throw fail('Paid media asset sniffing policy is invalid')
  }
}

async function writeAll(
  stage: PaidMediaAssetStageWriteCapability,
  bytes: Buffer,
  position: number
): Promise<void> {
  let offset = 0
  while (offset < bytes.length) {
    const written = await stage.write(bytes.subarray(offset), position + offset)
    if (
      !written ||
      typeof written !== 'object' ||
      !Number.isSafeInteger(written.bytesWritten) ||
      written.bytesWritten < 1 ||
      written.bytesWritten > bytes.length - offset
    ) {
      throw fail('Paid media staging write stalled')
    }
    offset += written.bytesWritten
  }
}

export async function downloadPaidMediaAsset(
  input: PaidMediaAssetDownloadInput
): Promise<PaidMediaDownloadedAsset> {
  if (
    !input ||
    typeof input !== 'object' ||
    !input.stage ||
    typeof input.stage !== 'object' ||
    !STAGE_LEASE_ID.test(input.stage.leaseId) ||
    !STAGE_OPERATION_ID.test(input.stage.operationId) ||
    !Number.isSafeInteger(input.stage.ordinal) ||
    input.stage.ordinal < 0 ||
    input.stage.ordinal >= 4 ||
    typeof input.stage.write !== 'function' ||
    typeof input.stage.sync !== 'function'
  ) {
    throw fail('Paid media stage capability is invalid')
  }
  const descriptor = parsePaidMediaAssetResult({
    schema: 'nachuan.paid-media-result.v2',
    kind: input.stage.descriptor.mediaType.startsWith('image/') ? 'image' : 'video',
    created: 0,
    turnId: input.stage.turnId,
    assets: [input.stage.descriptor]
  }).assets[0]
  if (descriptor.byteLength > MAX_PAID_MEDIA_ASSET_BYTES) {
    throw fail('Paid media asset exceeds its staging limit')
  }
  const sessionClient = requireSessionClient(input.sessionClient)
  const timeoutMs = validatedTimeout(input.timeoutMs)
  try {
    const outcome = await sessionClient.exchange<
      | { ok: true; downloaded: PaidMediaDownloadedAsset }
      | { ok: false; response: PaidMediaRawResponse }
    >(
      {
        method: 'GET',
        target: `/v1/paid-media/assets/${encodeURIComponent(descriptor.token)}`,
        headers: requestHeaders(descriptor.mediaType),
        body: Buffer.alloc(0),
        signal: input.signal,
        totalTimeoutMs: timeoutMs,
        firstByteTimeoutMs: Math.min(timeoutMs, RESPONSE_IDLE_TIMEOUT_MS)
      },
      async (authenticated): Promise<
        PaidMediaEngineSessionConsumed<
          | { ok: true; downloaded: PaidMediaDownloadedAsset }
          | { ok: false; response: PaidMediaRawResponse }
        >
      > => {
        if (authenticated.status !== 200) {
          const consumed = await readBoundedResponse(authenticated, MAX_ACK_RESPONSE_BYTES)
          return {
            value: { ok: false, response: consumed.value },
            bodySha256: consumed.bodySha256
          }
        }
        validatedDownloadHeaders(authenticated.response, descriptor)
        const digest = createHash('sha256')
        let byteLength = 0
        for await (const raw of authenticated.response) {
          if (input.signal.aborted) {
            throw fail('Paid media asset request was cancelled')
          }
          const bytes = Buffer.isBuffer(raw) ? raw : Buffer.from(raw)
          if (byteLength + bytes.length > descriptor.byteLength) {
            authenticated.response.destroy()
            throw fail('Paid media asset exceeded its declared length')
          }
          await writeAll(input.stage, bytes, byteLength)
          digest.update(bytes)
          byteLength += bytes.length
        }
        const bodySha256 = digest.digest('hex')
        if (byteLength !== descriptor.byteLength || bodySha256 !== descriptor.sha256) {
          throw fail('Paid media asset bytes do not match their receipt')
        }
        await input.stage.sync()
        return {
          value: {
            ok: true,
            downloaded: Object.freeze({ descriptor, byteLength, sha256: bodySha256 })
          },
          bodySha256
        }
      }
    )
    if (outcome.ok) return outcome.downloaded
    const remote = parsePaidMediaErrorResponse(outcome.response)
    throw new PaidMediaAssetRemoteError(
      remote.status,
      remote.code,
      remote.retryable,
      remote.retryAfterSeconds
    )
  } catch (error) {
    if (error instanceof PaidMediaAssetRemoteError) throw error
    if (error instanceof PaidMediaAssetClientError) throw error
    // Session transport and stage capabilities intentionally expose neither
    // the opaque token nor a filesystem path through their error chains.
    void error
    throw fail('Paid media asset could not be staged safely')
  }
}

function parseAckResponse(response: PaidMediaRawResponse, ack: PaidMediaAssetAck): PaidMediaAssetAckResult {
  if (
    !Number.isInteger(response.status) ||
    (response.status !== 200 && response.status !== 202) ||
    !Buffer.isBuffer(response.body) ||
    response.body.length < 2 ||
    response.body.length > MAX_ACK_RESPONSE_BYTES
  ) {
    throw fail('Paid media ACK response is invalid')
  }
  const headers = parseRawHeaders(response.rawHeaders)
  requireProtocolV2(headers)
  requireNoTransportTransform(headers)
  requireNoTrailers(response.rawTrailers)
  if (singleton(headers, 'content-type') !== 'application/json') {
    throw fail('Paid media ACK Content-Type is invalid')
  }
  if (singleton(headers, 'cache-control') !== 'no-store') {
    throw fail('Paid media ACK cache policy is invalid')
  }
  const retryAfter = singleton(headers, 'retry-after', false)
  if (
    (response.status === 200 && retryAfter !== null) ||
    (response.status === 202 && retryAfter !== '1')
  ) {
    throw fail('Paid media ACK retry policy is invalid')
  }
  if (canonicalContentLength(headers) !== response.body.length) {
    throw fail('Paid media ACK response length does not match')
  }
  let value: unknown
  try {
    value = JSON.parse(decodeStrictUtf8(response.body, 'Paid media ACK response'))
  } catch (error) {
    if (error instanceof PaidMediaAssetClientError) throw error
    throw fail('Paid media ACK response JSON is invalid', error)
  }
  if (
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    Object.keys(value as Record<string, unknown>).sort().join('\0') !==
      ['cleanupComplete', 'ok', 'replayed', 'turnId'].sort().join('\0')
  ) {
    throw fail('Paid media ACK response schema is invalid')
  }
  const document = value as Record<string, unknown>
  if (
    document.turnId !== ack.turnId ||
    typeof document.ok !== 'boolean' ||
    typeof document.replayed !== 'boolean' ||
    typeof document.cleanupComplete !== 'boolean' ||
    document.ok !== document.cleanupComplete ||
    (response.status === 200) !== document.cleanupComplete
  ) {
    throw fail('Paid media ACK response authority does not match')
  }
  return {
    ok: true,
    cleanupComplete: document.cleanupComplete,
    replayed: document.replayed
  }
}

async function readBoundedResponse(
  authenticated: PaidMediaEngineSessionResponse,
  maximum: number
): Promise<PaidMediaEngineSessionConsumed<PaidMediaRawResponse>> {
  const headers = parseRawHeaders(authenticated.rawHeaders)
  requireNoTransportTransform(headers)
  const declaredLength = canonicalContentLength(headers)
  if (declaredLength > maximum) {
    authenticated.response.destroy()
    throw fail('Paid media response exceeded its size limit')
  }
  const storage = Buffer.allocUnsafe(declaredLength)
  const digest = createHash('sha256')
  let total = 0
  for await (const raw of authenticated.response) {
    const bytes = Buffer.isBuffer(raw) ? raw : Buffer.from(raw)
    if (total + bytes.length > declaredLength) {
      authenticated.response.destroy()
      throw fail('Paid media response exceeded its declared length')
    }
    bytes.copy(storage, total)
    digest.update(bytes)
    total += bytes.length
  }
  if (total !== declaredLength) {
    throw fail('Paid media response length does not match')
  }
  return {
    value: {
      status: authenticated.status,
      rawHeaders: authenticated.rawHeaders,
      rawTrailers: authenticated.response.rawTrailers,
      body: storage.subarray(0, total)
    },
    bodySha256: digest.digest('hex')
  }
}

export async function createPaidMediaImageAssets(input: {
  sessionClient: Pick<PaidMediaEngineSessionClient, 'exchange'>
  encodedBody: string
  idempotencyKey: string
  signal: AbortSignal
  timeoutMs?: number
}): Promise<PaidMediaImageAssetCreateResult> {
  const sessionClient = requireSessionClient(input.sessionClient)
  const timeoutMs = validatedTimeout(input.timeoutMs)
  if (
    typeof input.encodedBody !== 'string' ||
    typeof input.idempotencyKey !== 'string' ||
    !IDEMPOTENCY_KEY.test(input.idempotencyKey)
  ) {
    throw fail('Paid media image request is invalid')
  }
  const body = Buffer.from(input.encodedBody, 'utf8')
  if (
    body.length < 2 ||
    body.length > MAX_PAID_MEDIA_ASSET_RESULT_BYTES ||
    body.toString('utf8') !== input.encodedBody
  ) {
    throw fail('Paid media image request bytes are invalid')
  }
  try {
    const raw = await sessionClient.exchange(
      {
        method: 'POST',
        target: '/v1/images/generations',
        headers: {
          ...requestHeaders('application/json'),
          'Content-Type': 'application/json',
          'Idempotency-Key': input.idempotencyKey
        },
        body,
        signal: input.signal,
        totalTimeoutMs: timeoutMs,
        // Provider execution may legitimately take minutes before the first
        // byte. The absolute total deadline remains authoritative; body-idle
        // starts only after authenticated response headers arrive.
        firstByteTimeoutMs: timeoutMs
      },
      (authenticated) =>
        readBoundedResponse(
          authenticated,
          authenticated.status === 200
            ? MAX_PAID_MEDIA_ASSET_RESULT_BYTES
            : MAX_ACK_RESPONSE_BYTES
        )
    )
    if (raw.status !== 200) return parsePaidMediaErrorResponse(raw)
    const headers = parseRawHeaders(raw.rawHeaders)
    const replay = singleton(headers, 'idempotency-replayed')
    if (replay !== 'true' && replay !== 'false') {
      throw fail('Paid media idempotency replay header is invalid')
    }
    return {
      ok: true,
      status: 200,
      replayed: replay === 'true',
      result: parsePaidMediaAssetResultResponse(raw, 'image')
    }
  } catch (error) {
    if (error instanceof PaidMediaAssetClientError) throw error
    void error
    throw fail('Paid media image request did not complete safely')
  }
}

export async function acknowledgePaidMediaAssets(input: {
  sessionClient: Pick<PaidMediaEngineSessionClient, 'exchange'>
  ack: PaidMediaAssetAck
  signal: AbortSignal
  timeoutMs?: number
}): Promise<PaidMediaAssetAckResult> {
  const sessionClient = requireSessionClient(input.sessionClient)
  const ack = parsePaidMediaAssetAck(input.ack)
  const timeoutMs = validatedTimeout(input.timeoutMs)
  const body = Buffer.from(JSON.stringify(ack), 'utf8')
  try {
    const raw = await sessionClient.exchange(
      {
        method: 'POST',
        target: '/v1/paid-media/assets/ack',
        headers: {
          ...requestHeaders('application/json'),
          'Content-Type': 'application/json'
        },
        body,
        signal: input.signal,
        totalTimeoutMs: timeoutMs,
        firstByteTimeoutMs: Math.min(timeoutMs, RESPONSE_IDLE_TIMEOUT_MS)
      },
      (authenticated) => readBoundedResponse(authenticated, MAX_ACK_RESPONSE_BYTES)
    )
    if (raw.status !== 200 && raw.status !== 202) {
      return parsePaidMediaErrorResponse(raw)
    }
    return parseAckResponse(raw, ack)
  } catch (error) {
    if (error instanceof PaidMediaAssetClientError) throw error
    void error
    throw fail('Paid media ACK did not complete safely')
  }
}

export const _paidMediaAssetClientTest = Object.freeze({
  parseAckResponse,
  parseRawHeaders,
  validatedDownloadHeaders
})
