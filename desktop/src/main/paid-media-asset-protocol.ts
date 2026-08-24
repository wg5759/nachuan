import { createHash } from 'node:crypto'

export const PAID_MEDIA_ASSET_PROTOCOL_HEADER = 'X-Nachuan-Paid-Media-Protocol'
export const PAID_MEDIA_ASSET_PROTOCOL_VERSION = '2'
export const PAID_MEDIA_ASSET_RESULT_SCHEMA = 'nachuan.paid-media-result.v2'
export const PAID_MEDIA_ASSET_ACK_SCHEMA = 'nachuan.paid-media-asset-ack.v1'
export const MAX_PAID_MEDIA_ASSET_RESULT_BYTES = 1024 * 1024
export const MAX_PAID_MEDIA_ASSETS = 4
export const MAX_PAID_MEDIA_ASSET_BYTES = 24 * 1024 * 1024

const SHA256 = /^[0-9a-f]{64}$/
const TOKEN = /^nma1_[A-Za-z0-9_-]{43}$/
const ZERO_DIGEST = '0'.repeat(64)
const SUPPORTED_MEDIA_TYPES = new Set([
  'image/png',
  'image/jpeg',
  'image/gif',
  'image/webp',
  'video/mp4',
  'video/webm'
])
const TOKEN_SET_DOMAIN = Buffer.from('nachuan-paid-media-token-set-v1\0', 'ascii')
const RESULT_DOMAIN = Buffer.from('nachuan-paid-media-result-document-v2\0', 'ascii')
const TOKEN_HASH_DOMAIN = Buffer.from('nachuan-paid-media-asset-token-v1\0', 'ascii')

export class PaidMediaAssetProtocolError extends Error {
  override readonly name = 'PaidMediaAssetProtocolError'

  constructor(
    readonly code: string,
    message: string,
    options?: ErrorOptions
  ) {
    super(message, options)
  }
}

export type PaidMediaAssetDescriptor = Readonly<{
  token: string
  mediaType: string
  byteLength: number
  sha256: string
  validationReceiptSha256: string
}>

export type PaidMediaAssetResult = Readonly<{
  schema: typeof PAID_MEDIA_ASSET_RESULT_SCHEMA
  kind: 'image' | 'video'
  created: number
  turnId: string
  assets: readonly PaidMediaAssetDescriptor[]
}>

export type PaidMediaAssetAck = Readonly<{
  schema: typeof PAID_MEDIA_ASSET_ACK_SCHEMA
  turnId: string
  tokens: readonly string[]
  archiveReceiptSha256: string
}>

function fail(code: string, message: string): PaidMediaAssetProtocolError {
  return new PaidMediaAssetProtocolError(code, message)
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort()
  const wanted = [...expected].sort()
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index])
}

function digest(value: unknown, label: string): string {
  if (typeof value !== 'string' || !SHA256.test(value) || value === ZERO_DIGEST) {
    throw fail('invalid_paid_media_asset_document', `${label} is invalid`)
  }
  return value
}

function token(value: unknown): string {
  if (typeof value !== 'string' || !TOKEN.test(value)) {
    throw fail('invalid_paid_media_asset_token', 'Paid media asset token is invalid')
  }
  return value
}

function canonicalDocument(result: PaidMediaAssetResult): Record<string, unknown> {
  // Insertion order is intentionally ASCII-key-sorted to match the Gateway's
  // canonical JSON encoder byte-for-byte.
  return {
    assets: result.assets.map((asset) => ({
      byteLength: asset.byteLength,
      mediaType: asset.mediaType,
      sha256: asset.sha256,
      token: asset.token,
      validationReceiptSha256: asset.validationReceiptSha256
    })),
    created: result.created,
    kind: result.kind,
    schema: result.schema,
    turnId: result.turnId
  }
}

function canonicalBytes(result: PaidMediaAssetResult): Buffer {
  const bytes = Buffer.from(JSON.stringify(canonicalDocument(result)), 'ascii')
  if (bytes.byteLength > MAX_PAID_MEDIA_ASSET_RESULT_BYTES) {
    throw fail(
      'paid_media_asset_document_too_large',
      'Paid media asset metadata exceeds its size limit'
    )
  }
  return bytes
}

export function parsePaidMediaAssetResult(value: unknown): PaidMediaAssetResult {
  if (
    !isRecord(value) ||
    !exactKeys(value, ['schema', 'kind', 'created', 'turnId', 'assets']) ||
    value.schema !== PAID_MEDIA_ASSET_RESULT_SCHEMA ||
    (value.kind !== 'image' && value.kind !== 'video') ||
    !Number.isSafeInteger(value.created) ||
    Number(value.created) < 0 ||
    !Array.isArray(value.assets) ||
    value.assets.length < 1 ||
    value.assets.length > MAX_PAID_MEDIA_ASSETS
  ) {
    throw fail('invalid_paid_media_asset_document', 'Paid media result schema is invalid')
  }
  const turnId = digest(value.turnId, 'Paid media turn id')
  const tokens = new Set<string>()
  const assets = value.assets.map((raw): PaidMediaAssetDescriptor => {
    if (
      !isRecord(raw) ||
      !exactKeys(raw, ['token', 'mediaType', 'byteLength', 'sha256', 'validationReceiptSha256'])
    ) {
      throw fail(
        'invalid_paid_media_asset_document',
        'Paid media asset fields are outside the closed protocol'
      )
    }
    const normalizedToken = token(raw.token)
    if (tokens.has(normalizedToken)) {
      throw fail('invalid_paid_media_asset_document', 'Paid media asset tokens are duplicated')
    }
    tokens.add(normalizedToken)
    if (
      typeof raw.mediaType !== 'string' ||
      !SUPPORTED_MEDIA_TYPES.has(raw.mediaType) ||
      (value.kind === 'image' && !raw.mediaType.startsWith('image/')) ||
      (value.kind === 'video' && !raw.mediaType.startsWith('video/')) ||
      !Number.isSafeInteger(raw.byteLength) ||
      Number(raw.byteLength) < 1 ||
      Number(raw.byteLength) > MAX_PAID_MEDIA_ASSET_BYTES
    ) {
      throw fail('invalid_paid_media_asset_document', 'Paid media asset metadata is invalid')
    }
    return Object.freeze({
      token: normalizedToken,
      mediaType: raw.mediaType,
      byteLength: Number(raw.byteLength),
      sha256: digest(raw.sha256, 'Paid media asset digest'),
      validationReceiptSha256: digest(
        raw.validationReceiptSha256,
        'Paid media validation receipt digest'
      )
    })
  })
  const result: PaidMediaAssetResult = Object.freeze({
    schema: PAID_MEDIA_ASSET_RESULT_SCHEMA,
    kind: value.kind,
    created: Number(value.created),
    turnId,
    assets: Object.freeze(assets)
  })
  canonicalBytes(result)
  return result
}

export function canonicalPaidMediaAssetResult(value: unknown): Buffer {
  // Object.freeze is not an integrity brand. Always parse again so a frozen
  // object with extra/provider fields cannot bypass the wire schema.
  return canonicalBytes(parsePaidMediaAssetResult(value))
}

export function paidMediaAssetResultDigest(value: unknown): string {
  return createHash('sha256')
    .update(RESULT_DOMAIN)
    .update(canonicalPaidMediaAssetResult(value))
    .digest('hex')
}

export function paidMediaAssetTokenHash(value: unknown): string {
  return createHash('sha256')
    .update(TOKEN_HASH_DOMAIN)
    .update(token(value), 'ascii')
    .digest('hex')
}

export function paidMediaTokenSetDigest(values: readonly unknown[]): string {
  if (!Array.isArray(values)) {
    throw fail('invalid_paid_media_asset_ack', 'Paid media ACK tokens must be an array')
  }
  const normalized = values.map(token)
  if (
    normalized.length < 1 ||
    normalized.length > MAX_PAID_MEDIA_ASSETS ||
    new Set(normalized).size !== normalized.length
  ) {
    throw fail('invalid_paid_media_asset_ack', 'Paid media ACK token set is invalid')
  }
  return createHash('sha256')
    .update(TOKEN_SET_DOMAIN)
    .update(normalized.sort().join('\0'), 'ascii')
    .digest('hex')
}

export function buildPaidMediaAssetAck(
  resultValue: unknown,
  archiveReceiptSha256: unknown
): PaidMediaAssetAck {
  const result = parsePaidMediaAssetResult(resultValue)
  const receipt = digest(archiveReceiptSha256, 'Paid media archive receipt digest')
  const tokens = Object.freeze(result.assets.map((asset) => asset.token))
  paidMediaTokenSetDigest(tokens)
  return Object.freeze({
    schema: PAID_MEDIA_ASSET_ACK_SCHEMA,
    turnId: result.turnId,
    tokens,
    archiveReceiptSha256: receipt
  })
}

export function parsePaidMediaAssetAck(value: unknown): PaidMediaAssetAck {
  if (
    !isRecord(value) ||
    !exactKeys(value, ['schema', 'turnId', 'tokens', 'archiveReceiptSha256']) ||
    value.schema !== PAID_MEDIA_ASSET_ACK_SCHEMA ||
    !Array.isArray(value.tokens)
  ) {
    throw fail('invalid_paid_media_asset_ack', 'Paid media asset ACK schema is invalid')
  }
  const tokens = Object.freeze(value.tokens.map(token))
  paidMediaTokenSetDigest(tokens)
  return Object.freeze({
    schema: PAID_MEDIA_ASSET_ACK_SCHEMA,
    turnId: digest(value.turnId, 'Paid media ACK turn id'),
    tokens,
    archiveReceiptSha256: digest(
      value.archiveReceiptSha256,
      'Paid media archive receipt digest'
    )
  })
}
