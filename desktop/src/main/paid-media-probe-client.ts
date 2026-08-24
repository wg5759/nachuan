import { createHash, timingSafeEqual } from 'node:crypto'
import * as http from 'node:http'
import { pipeline, Readable, Transform } from 'node:stream'

import type {
  PaidMediaArchivedAsset,
  PaidMediaTrustedProbeResult
} from './paid-media-vault'

const VALIDATION_SCHEMA = 'nachuan.trusted-media-validation.v2'
const READINESS_SCHEMA = 'nachuan.trusted-media-probe.readiness.v2'
const VALIDATOR_VERSION = 'nachuan.trusted-media-probe.v2'
const VALIDATION_POLICY = 'nachuan.trusted-media-policy.av-closed.v1'
const PAID_KEY_PATTERN = /^sk-paid-media-[0-9a-f]{64}$/
const SHA256_PATTERN = /^[0-9a-f]{64}$/
const TOKEN_PATTERN = /^[a-z0-9_.-]{1,64}$/
const RESPONSE_LIMIT = 64 * 1024
const READINESS_TIMEOUT_MS = 10_000
const VALIDATION_TIMEOUT_MS = 310_000

export class PaidMediaProbeClientError extends Error {}

export interface PaidMediaProbeTransportResponse {
  status: number
  contentType?: string
  body: Buffer
}

export interface PaidMediaProbeTransportRequest {
  url: string
  method: 'GET' | 'POST'
  headers: Record<string, string>
  timeoutMs: number
  responseByteLimit: number
  body?: {
    stream: Readable
    byteLength: number
    sha256: string
  }
}

export type PaidMediaProbeTransport = (
  request: PaidMediaProbeTransportRequest
) => Promise<PaidMediaProbeTransportResponse>

export interface PaidMediaProbeClientDependencies {
  baseUrl: () => string
  runtimeKey: () => string
  paidMediaKey: () => string
  transport?: PaidMediaProbeTransport
}

export interface PaidMediaProbeValidationInput {
  createReadStream: () => Readable
  mediaType: PaidMediaArchivedAsset['mediaType']
  byteLength: number
  sha256: string
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value)
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort()
  const wanted = [...expected].sort()
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index])
}

function digestEquals(left: string, right: string): boolean {
  if (!SHA256_PATTERN.test(left) || !SHA256_PATTERN.test(right)) return false
  return timingSafeEqual(Buffer.from(left, 'ascii'), Buffer.from(right, 'ascii'))
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(',')}]`
  if (isRecord(value)) {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(',')}}`
  }
  return JSON.stringify(value)
}

function parseStrictJson(raw: Buffer): unknown {
  if (raw.byteLength < 2 || raw.byteLength > RESPONSE_LIMIT) {
    throw new PaidMediaProbeClientError('Trusted media probe response size is invalid')
  }
  let text: string
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(raw)
  } catch (error) {
    throw new PaidMediaProbeClientError('Trusted media probe response encoding is invalid', {
      cause: error
    })
  }
  try {
    return JSON.parse(text) as unknown
  } catch (error) {
    throw new PaidMediaProbeClientError('Trusted media probe response JSON is invalid', {
      cause: error
    })
  }
}

function parseAttestedTools(value: unknown): {
  ffmpegSha256: string
  ffprobeSha256: string
} {
  if (
    !isRecord(value) ||
    !exactKeys(value, ['ffmpegSha256', 'ffprobeSha256']) ||
    typeof value.ffmpegSha256 !== 'string' ||
    typeof value.ffprobeSha256 !== 'string' ||
    !SHA256_PATTERN.test(value.ffmpegSha256) ||
    !SHA256_PATTERN.test(value.ffprobeSha256)
  ) {
    throw new PaidMediaProbeClientError('Trusted media probe tool attestation is invalid')
  }
  return {
    ffmpegSha256: value.ffmpegSha256,
    ffprobeSha256: value.ffprobeSha256
  }
}

export function parsePaidMediaProbeReadiness(raw: Buffer): void {
  const value = parseStrictJson(raw)
  if (
    !isRecord(value) ||
    !exactKeys(value, [
      'schema',
      'validatorVersion',
      'validationPolicy',
      'ready',
      'attestedTools'
    ]) ||
    value.schema !== READINESS_SCHEMA ||
    value.validatorVersion !== VALIDATOR_VERSION ||
    value.validationPolicy !== VALIDATION_POLICY ||
    value.ready !== true
  ) {
    throw new PaidMediaProbeClientError('Trusted media probe readiness receipt is invalid')
  }
  parseAttestedTools(value.attestedTools)
}

function parseMetadata(
  value: unknown,
  mediaType: PaidMediaArchivedAsset['mediaType']
): PaidMediaTrustedProbeResult['metadata'] {
  if (
    !isRecord(value) ||
    !exactKeys(value, [
      'detectedKind',
      'codecName',
      'audioCodecName',
      'videoStreamCount',
      'audioStreamCount',
      'formatName',
      'width',
      'height',
      'durationMs',
      'decodedFrames'
    ]) ||
    !['image', 'video'].includes(String(value.detectedKind)) ||
    typeof value.codecName !== 'string' ||
    !TOKEN_PATTERN.test(value.codecName) ||
    (value.audioCodecName !== null &&
      (typeof value.audioCodecName !== 'string' || !TOKEN_PATTERN.test(value.audioCodecName))) ||
    value.videoStreamCount !== 1 ||
    (value.audioStreamCount !== 0 && value.audioStreamCount !== 1) ||
    (value.audioStreamCount === 0) !== (value.audioCodecName === null) ||
    typeof value.formatName !== 'string' ||
    value.formatName.length < 1 ||
    value.formatName.length > 128 ||
    !Number.isSafeInteger(value.width) ||
    !Number.isSafeInteger(value.height) ||
    Number(value.width) < 1 ||
    Number(value.height) < 1 ||
    Number(value.width) > 16_384 ||
    Number(value.height) > 16_384 ||
    Number(value.width) * Number(value.height) > 64 * 1024 * 1024 ||
    !Number.isSafeInteger(value.decodedFrames) ||
    Number(value.decodedFrames) < 1 ||
    Number(value.decodedFrames) > 10_000_000
  ) {
    throw new PaidMediaProbeClientError('Trusted media probe metadata is invalid')
  }
  const expectedKind = mediaType.startsWith('image/') ? 'image' : 'video'
  if (value.detectedKind !== expectedKind) {
    throw new PaidMediaProbeClientError('Trusted media probe kind does not match')
  }
  if (expectedKind === 'image' && (value.audioStreamCount !== 0 || value.audioCodecName !== null)) {
    throw new PaidMediaProbeClientError('Trusted media probe image audio metadata is invalid')
  }
  if (
    (expectedKind === 'image' && value.durationMs !== null) ||
    (expectedKind === 'video' &&
      (!Number.isSafeInteger(value.durationMs) ||
        Number(value.durationMs) < 1 ||
        Number(value.durationMs) > 86_400_000))
  ) {
    throw new PaidMediaProbeClientError('Trusted media probe duration is invalid')
  }
  return {
    detectedKind: expectedKind,
    codecName: value.codecName,
    audioCodecName: value.audioCodecName,
    videoStreamCount: 1,
    audioStreamCount: value.audioStreamCount,
    formatName: value.formatName,
    width: Number(value.width),
    height: Number(value.height),
    durationMs: value.durationMs === null ? null : Number(value.durationMs),
    decodedFrames: Number(value.decodedFrames)
  }
}

export function parsePaidMediaValidationReceipt(
  raw: Buffer,
  expected: Pick<PaidMediaProbeValidationInput, 'mediaType' | 'byteLength' | 'sha256'>
): PaidMediaTrustedProbeResult {
  const value = parseStrictJson(raw)
  if (
    !isRecord(value) ||
    !exactKeys(value, [
      'schema',
      'validatorVersion',
      'validationPolicy',
      'fullyDecoded',
      'mediaType',
      'byteLength',
      'sha256',
      'attestedTools',
      'metadata',
      'receiptSha256'
    ]) ||
    value.schema !== VALIDATION_SCHEMA ||
    value.validatorVersion !== VALIDATOR_VERSION ||
    value.validationPolicy !== VALIDATION_POLICY ||
    value.fullyDecoded !== true ||
    value.mediaType !== expected.mediaType ||
    value.byteLength !== expected.byteLength ||
    typeof value.sha256 !== 'string' ||
    !digestEquals(value.sha256, expected.sha256) ||
    typeof value.receiptSha256 !== 'string' ||
    !SHA256_PATTERN.test(value.receiptSha256)
  ) {
    throw new PaidMediaProbeClientError('Trusted media validation receipt is invalid')
  }
  const attestedTools = parseAttestedTools(value.attestedTools)
  const metadata = parseMetadata(value.metadata, expected.mediaType)
  const base: Omit<PaidMediaTrustedProbeResult, 'receiptSha256'> = {
    schema: VALIDATION_SCHEMA,
    validatorVersion: VALIDATOR_VERSION,
    validationPolicy: VALIDATION_POLICY,
    fullyDecoded: true as const,
    mediaType: expected.mediaType,
    byteLength: expected.byteLength,
    sha256: expected.sha256,
    attestedTools,
    metadata
  }
  const receiptSha256 = createHash('sha256')
    .update(Buffer.from('nachuan.trusted-media-validation.v2\0', 'utf8'))
    .update(Buffer.from(canonicalJson(base), 'ascii'))
    .digest('hex')
  if (!digestEquals(value.receiptSha256, receiptSha256)) {
    throw new PaidMediaProbeClientError('Trusted media validation receipt digest is invalid')
  }
  return { ...base, receiptSha256 }
}

function exactLoopbackBaseUrl(raw: string): string {
  let parsed: URL
  try {
    parsed = new URL(raw)
  } catch (error) {
    throw new PaidMediaProbeClientError('Trusted media probe gateway URL is invalid', {
      cause: error
    })
  }
  if (
    parsed.protocol !== 'http:' ||
    parsed.hostname !== '127.0.0.1' ||
    !parsed.port ||
    parsed.username ||
    parsed.password ||
    (parsed.pathname !== '' && parsed.pathname !== '/') ||
    parsed.search ||
    parsed.hash
  ) {
    throw new PaidMediaProbeClientError('Trusted media probe gateway must be exact loopback HTTP')
  }
  return `http://127.0.0.1:${parsed.port}`
}

function boundedSecret(value: string, label: string): string {
  const candidate = String(value || '').trim()
  if (!candidate || candidate.length > 4096 || /[\u0000-\u001f\u007f]/.test(candidate)) {
    throw new PaidMediaProbeClientError(`Trusted media probe ${label} is unavailable`)
  }
  return candidate
}

function requireJsonResponse(response: PaidMediaProbeTransportResponse): Buffer {
  if (response.status !== 200) {
    throw new PaidMediaProbeClientError(
      `Trusted media probe request failed with status ${response.status}`
    )
  }
  if ((response.contentType || '').trim().toLowerCase() !== 'application/json') {
    throw new PaidMediaProbeClientError('Trusted media probe response type is invalid')
  }
  return response.body
}

export class PaidMediaProbeClient {
  private readonly transport: PaidMediaProbeTransport

  constructor(private readonly dependencies: PaidMediaProbeClientDependencies) {
    this.transport = dependencies.transport ?? nodePaidMediaProbeTransport
  }

  private authority(): { baseUrl: string; runtimeKey: string; paidMediaKey: string } {
    const baseUrl = exactLoopbackBaseUrl(this.dependencies.baseUrl())
    const runtimeKey = boundedSecret(this.dependencies.runtimeKey(), 'runtime authority')
    const paidMediaKey = boundedSecret(this.dependencies.paidMediaKey(), 'paid authority')
    if (!PAID_KEY_PATTERN.test(paidMediaKey) || paidMediaKey === runtimeKey) {
      throw new PaidMediaProbeClientError('Trusted media probe paid authority is invalid')
    }
    return { baseUrl, runtimeKey, paidMediaKey }
  }

  async ensureReady(): Promise<void> {
    const authority = this.authority()
    const response = await this.transport({
      url: `${authority.baseUrl}/v1/paid-media/probe/readiness`,
      method: 'GET',
      headers: {
        Authorization: `Bearer ${authority.runtimeKey}`,
        'X-Nachuan-Paid-Media-Key': authority.paidMediaKey,
        Accept: 'application/json'
      },
      timeoutMs: READINESS_TIMEOUT_MS,
      responseByteLimit: RESPONSE_LIMIT
    })
    parsePaidMediaProbeReadiness(requireJsonResponse(response))
  }

  async validate(input: PaidMediaProbeValidationInput): Promise<PaidMediaTrustedProbeResult> {
    if (
      !input ||
      typeof input !== 'object' ||
      typeof input.createReadStream !== 'function' ||
      ![
        'image/png',
        'image/jpeg',
        'image/gif',
        'image/webp',
        'video/mp4',
        'video/webm'
      ].includes(input.mediaType) ||
      !Number.isSafeInteger(input.byteLength) ||
      input.byteLength < 1 ||
      !SHA256_PATTERN.test(input.sha256)
    ) {
      throw new PaidMediaProbeClientError('Trusted media probe validation input is invalid')
    }
    const maximum = input.mediaType.startsWith('image/') ? 24 * 1024 * 1024 : 512 * 1024 * 1024
    if (input.byteLength > maximum) {
      throw new PaidMediaProbeClientError('Trusted media probe validation input exceeds its limit')
    }
    const authority = this.authority()
    const stream = input.createReadStream()
    if (!(stream instanceof Readable)) {
      throw new PaidMediaProbeClientError('Trusted media probe input stream is invalid')
    }
    const response = await this.transport({
      url: `${authority.baseUrl}/v1/paid-media/probe`,
      method: 'POST',
      headers: {
        Authorization: `Bearer ${authority.runtimeKey}`,
        'X-Nachuan-Paid-Media-Key': authority.paidMediaKey,
        Accept: 'application/json',
        'Content-Type': input.mediaType,
        'Content-Length': String(input.byteLength),
        'X-Nachuan-Media-Byte-Length': String(input.byteLength),
        'X-Nachuan-Media-SHA256': input.sha256
      },
      timeoutMs: VALIDATION_TIMEOUT_MS,
      responseByteLimit: RESPONSE_LIMIT,
      body: { stream, byteLength: input.byteLength, sha256: input.sha256 }
    })
    return parsePaidMediaValidationReceipt(requireJsonResponse(response), input)
  }
}

class ExactBodyTransform extends Transform {
  private readonly digest = createHash('sha256')
  private total = 0

  constructor(
    private readonly expectedLength: number,
    private readonly expectedSha256: string
  ) {
    super()
  }

  override _transform(
    chunk: Buffer | string,
    encoding: BufferEncoding,
    callback: (error?: Error | null, data?: Buffer) => void
  ): void {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding)
    this.total += bytes.byteLength
    if (this.total > this.expectedLength) {
      callback(new PaidMediaProbeClientError('Trusted media probe stream exceeds its receipt'))
      return
    }
    this.digest.update(bytes)
    callback(null, bytes)
  }

  override _flush(callback: (error?: Error | null) => void): void {
    if (
      this.total !== this.expectedLength ||
      !digestEquals(this.digest.digest('hex'), this.expectedSha256)
    ) {
      callback(new PaidMediaProbeClientError('Trusted media probe stream does not match its receipt'))
      return
    }
    callback()
  }
}

type HttpRequestFactory = (
  url: string,
  options: http.RequestOptions,
  callback: (response: http.IncomingMessage) => void
) => http.ClientRequest

export function createNodePaidMediaProbeTransport(
  requestFactory: HttpRequestFactory = http.request
): PaidMediaProbeTransport {
  return (request) => new Promise((resolve, reject) => {
    if (
      !Number.isSafeInteger(request.responseByteLimit) ||
      request.responseByteLimit < 1 ||
      request.responseByteLimit > RESPONSE_LIMIT ||
      !Number.isSafeInteger(request.timeoutMs) ||
      request.timeoutMs < 1 ||
      request.timeoutMs > VALIDATION_TIMEOUT_MS
    ) {
      reject(new PaidMediaProbeClientError('Trusted media probe transport bounds are invalid'))
      return
    }
    let settled = false
    let responseStarted = false
    let responseStream: http.IncomingMessage | undefined
    const source = request.body?.stream
    const fail = (error: unknown): void => {
      if (settled) return
      settled = true
      source?.destroy()
      responseStream?.destroy()
      outgoing.destroy()
      reject(
        error instanceof PaidMediaProbeClientError
          ? error
          : new PaidMediaProbeClientError('Trusted media probe transport failed', { cause: error })
      )
    }
    const outgoing = requestFactory(
      request.url,
      { method: request.method, headers: request.headers },
      (response) => {
        responseStarted = true
        responseStream = response
        if ((response.statusCode ?? 500) !== 200) {
          // Authentication/header limits can reject before the server asks for
          // a 512 MiB body. Stop the pinned source immediately; never keep
          // uploading plaintext after a terminal response already exists.
          settled = true
          source?.destroy()
          response.resume()
          resolve({
            status: response.statusCode ?? 500,
            contentType: Array.isArray(response.headers['content-type'])
              ? undefined
              : response.headers['content-type'],
            body: Buffer.alloc(0)
          })
          return
        }
        const chunks: Buffer[] = []
        let total = 0
        response.on('data', (chunk: Buffer | string) => {
          const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
          total += bytes.byteLength
          if (total > request.responseByteLimit) {
            fail(new PaidMediaProbeClientError('Trusted media probe response exceeds its limit'))
            return
          }
          chunks.push(bytes)
        })
        response.on('error', fail)
        response.on('end', () => {
          if (settled) return
          const rawContentType = response.headers['content-type']
          if (Array.isArray(rawContentType)) {
            fail(new PaidMediaProbeClientError('Trusted media probe response headers are invalid'))
            return
          }
          settled = true
          resolve({
            status: response.statusCode ?? 500,
            contentType: rawContentType,
            body: Buffer.concat(chunks, total)
          })
        })
      }
    )
    outgoing.on('error', (error) => {
      if (!responseStarted) fail(error)
    })
    outgoing.setTimeout(request.timeoutMs, () => {
      fail(new PaidMediaProbeClientError('Trusted media probe transport timed out'))
    })
    if (!request.body) {
      outgoing.end()
      return
    }
    const meter = new ExactBodyTransform(request.body.byteLength, request.body.sha256)
    pipeline(request.body.stream, meter, outgoing, (error) => {
      if (error && !responseStarted) fail(error)
    })
  })
}

export const nodePaidMediaProbeTransport = createNodePaidMediaProbeTransport()
