import { createHash, timingSafeEqual } from 'node:crypto'

import {
  MAX_PAID_MEDIA_ASSET_BYTES,
  PAID_MEDIA_ASSET_PROTOCOL_HEADER,
  PAID_MEDIA_ASSET_PROTOCOL_VERSION,
  type PaidMediaAssetDescriptor
} from './paid-media-asset-protocol'
import type {
  PaidMediaEngineSessionClient,
  PaidMediaEngineSessionBodySource,
  PaidMediaEngineSessionConsumed,
  PaidMediaEngineSessionResponse
} from './paid-media-engine-session-client'
import {
  parsePaidMediaValidationReceipt,
  type PaidMediaProbeValidationInput
} from './paid-media-probe-client'
import type { PaidMediaTrustedProbeResult } from './paid-media-vault'

const RESPONSE_LIMIT = 64 * 1024
const VALIDATION_TIMEOUT_MS = 5 * 60 * 1000
const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/
const CANONICAL_LENGTH = /^(0|[1-9][0-9]*)$/
const SHA256 = /^[0-9a-f]{64}$/
const SUPPORTED_MEDIA_TYPES = [
  'image/png',
  'image/jpeg',
  'image/gif',
  'image/webp',
  'video/mp4',
  'video/webm'
] as const
type SupportedMediaType = (typeof SUPPORTED_MEDIA_TYPES)[number]
const FORBIDDEN_RESPONSE_HEADERS = [
  'content-encoding',
  'transfer-encoding',
  'content-range',
  'location',
  'trailer',
  'upgrade'
] as const

type HeaderMap = ReadonlyMap<string, readonly string[]>

export class PaidMediaEngineSessionProbeClientError extends Error {
  override readonly name = 'PaidMediaEngineSessionProbeClientError'
}

function fail(message: string): PaidMediaEngineSessionProbeClientError {
  return new PaidMediaEngineSessionProbeClientError(message)
}

function digestEquals(left: string, right: string): boolean {
  if (!SHA256.test(left) || !SHA256.test(right)) return false
  return timingSafeEqual(Buffer.from(left, 'ascii'), Buffer.from(right, 'ascii'))
}

function isSupportedMediaType(value: unknown): value is SupportedMediaType {
  return (
    typeof value === 'string' &&
    (SUPPORTED_MEDIA_TYPES as readonly string[]).includes(value)
  )
}

function parseRawHeaders(rawHeaders: readonly string[]): HeaderMap {
  if (!Array.isArray(rawHeaders) || rawHeaders.length % 2 !== 0) {
    throw fail('Paid media probe response headers are malformed')
  }
  const headers = new Map<string, string[]>()
  for (let index = 0; index < rawHeaders.length; index += 2) {
    const name = rawHeaders[index]
    const value = rawHeaders[index + 1]
    if (
      typeof name !== 'string' ||
      !HEADER_NAME.test(name) ||
      typeof value !== 'string' ||
      value.length < 1 ||
      value !== value.trim() ||
      /[^\x20-\x7e]/.test(value)
    ) {
      throw fail('Paid media probe response headers are malformed')
    }
    const normalized = name.toLowerCase()
    const values = headers.get(normalized) ?? []
    values.push(value)
    headers.set(normalized, values)
  }
  return headers
}

function singleton(headers: HeaderMap, name: string): string {
  const values = headers.get(name.toLowerCase()) ?? []
  if (values.length !== 1 || values[0]!.includes(',')) {
    throw fail(`Paid media probe response has ambiguous ${name}`)
  }
  return values[0]!
}

function validateResponseHeaders(response: PaidMediaEngineSessionResponse): number {
  const headers = parseRawHeaders(response.rawHeaders)
  for (const name of FORBIDDEN_RESPONSE_HEADERS) {
    if ((headers.get(name) ?? []).length !== 0) {
      throw fail(`Paid media probe response contains forbidden ${name}`)
    }
  }
  if (
    singleton(headers, 'content-type') !== 'application/json' ||
    singleton(headers, 'cache-control') !== 'no-store' ||
    singleton(headers, PAID_MEDIA_ASSET_PROTOCOL_HEADER) !==
      PAID_MEDIA_ASSET_PROTOCOL_VERSION
  ) {
    throw fail('Paid media probe response metadata is invalid')
  }
  const rawLength = singleton(headers, 'content-length')
  if (!CANONICAL_LENGTH.test(rawLength)) {
    throw fail('Paid media probe response Content-Length is invalid')
  }
  const length = Number(rawLength)
  if (!Number.isSafeInteger(length) || length < 2 || length > RESPONSE_LIMIT) {
    response.response.destroy()
    throw fail('Paid media probe response exceeds its size limit')
  }
  return length
}

async function consumeResponse(
  response: PaidMediaEngineSessionResponse
): Promise<
  PaidMediaEngineSessionConsumed<{ status: number; body: Buffer }>
> {
  const expectedLength = validateResponseHeaders(response)
  const body = Buffer.allocUnsafe(expectedLength)
  const digest = createHash('sha256')
  let offset = 0
  for await (const raw of response.response) {
    const bytes = Buffer.isBuffer(raw) ? raw : Buffer.from(raw)
    if (offset + bytes.length > expectedLength) {
      response.response.destroy()
      throw fail('Paid media probe response exceeded its declared length')
    }
    bytes.copy(body, offset)
    digest.update(bytes)
    offset += bytes.length
  }
  if (offset !== expectedLength || response.response.rawTrailers.length !== 0) {
    throw fail('Paid media probe response framing is invalid')
  }
  return {
    value: { status: response.status, body },
    bodySha256: digest.digest('hex')
  }
}

function validTimeout(value: number | undefined): number {
  const timeout = value ?? VALIDATION_TIMEOUT_MS
  if (!Number.isSafeInteger(timeout) || timeout < 1_000 || timeout > VALIDATION_TIMEOUT_MS) {
    throw fail('Paid media probe timeout is invalid')
  }
  return timeout
}

export async function probePaidMediaStagedAsset(input: {
  sessionClient: Pick<PaidMediaEngineSessionClient, 'exchange'>
  descriptor: PaidMediaAssetDescriptor
  source: Pick<PaidMediaEngineSessionBodySource, 'createReadStream'>
  signal: AbortSignal
  timeoutMs?: number
}): Promise<PaidMediaTrustedProbeResult> {
  if (
    !input ||
    typeof input !== 'object' ||
    !input.sessionClient ||
    typeof input.sessionClient.exchange !== 'function' ||
    !input.descriptor ||
    typeof input.descriptor !== 'object' ||
    !isSupportedMediaType(input.descriptor.mediaType) ||
    !Number.isSafeInteger(input.descriptor.byteLength) ||
    input.descriptor.byteLength < 1 ||
    input.descriptor.byteLength > MAX_PAID_MEDIA_ASSET_BYTES ||
    !SHA256.test(input.descriptor.sha256) ||
    input.descriptor.sha256 === '0'.repeat(64) ||
    !input.source ||
    typeof input.source !== 'object' ||
    typeof input.source.createReadStream !== 'function' ||
    !SHA256.test(input.descriptor.validationReceiptSha256) ||
    input.descriptor.validationReceiptSha256 === '0'.repeat(64)
  ) {
    throw fail('Paid media staged probe input is invalid')
  }
  const mediaType = input.descriptor.mediaType
  const timeoutMs = validTimeout(input.timeoutMs)
  let raw: { status: number; body: Buffer }
  try {
    raw = await input.sessionClient.exchange(
      {
        method: 'POST',
        target: '/v1/paid-media/probe',
        headers: {
          Accept: 'application/json',
          'Accept-Encoding': 'identity',
          'Cache-Control': 'no-store',
          'Content-Type': mediaType,
          [PAID_MEDIA_ASSET_PROTOCOL_HEADER]: PAID_MEDIA_ASSET_PROTOCOL_VERSION,
          'X-Nachuan-Media-Byte-Length': String(input.descriptor.byteLength),
          'X-Nachuan-Media-SHA256': input.descriptor.sha256
        },
        body: Object.freeze({
          byteLength: input.descriptor.byteLength,
          sha256: input.descriptor.sha256,
          createReadStream: input.source.createReadStream.bind(input.source)
        }),
        signal: input.signal,
        totalTimeoutMs: timeoutMs,
        firstByteTimeoutMs: timeoutMs
      },
      consumeResponse
    )
  } catch (error) {
    if (error instanceof PaidMediaEngineSessionProbeClientError) throw error
    void error
    throw fail('Paid media staged probe did not complete safely')
  }
  if (raw.status !== 200) {
    throw fail('Paid media staged probe was rejected')
  }
  let receipt: PaidMediaTrustedProbeResult
  try {
    const expected: Pick<
      PaidMediaProbeValidationInput,
      'mediaType' | 'byteLength' | 'sha256'
    > = {
      mediaType,
      byteLength: input.descriptor.byteLength,
      sha256: input.descriptor.sha256
    }
    receipt = parsePaidMediaValidationReceipt(raw.body, expected)
  } catch {
    throw fail('Paid media staged probe receipt is invalid')
  }
  if (!digestEquals(receipt.receiptSha256, input.descriptor.validationReceiptSha256)) {
    throw fail('Paid media staged probe receipt does not match the Gateway asset authority')
  }
  return receipt
}
