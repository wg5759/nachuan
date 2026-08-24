import { createHash, createHmac, timingSafeEqual } from 'node:crypto'

export const PAID_MEDIA_ENGINE_SESSION_VERSION = '1'
export const PAID_MEDIA_ENGINE_SESSION_CHALLENGE_PATH =
  '/internal/v1/paid-media/session/challenge'
export const PAID_MEDIA_ENGINE_SESSION_CHALLENGE_SCHEMA =
  'nachuan.paid-media.engine-session.challenge.v1'
export const PAID_MEDIA_ENGINE_SESSION_CHALLENGE_JSON =
  '{"schema":"nachuan.paid-media.engine-session.challenge.v1","ok":true}'
export const PAID_MEDIA_ENGINE_SESSION_MAX_PAST_MS = 30_000
export const PAID_MEDIA_ENGINE_SESSION_MAX_FUTURE_MS = 5_000
export const PAID_MEDIA_ENGINE_SESSION_DOMAINS = Object.freeze({
  key: 'nachuan.paid-media.engine-session.key.v1',
  request: 'nachuan.paid-media.engine-session.request.v1',
  requestContract: 'nachuan.paid-media.engine-session.request-contract.v1',
  response: 'nachuan.paid-media.engine-session.response.v1',
  responseContract: 'nachuan.paid-media.engine-session.response-contract.v1'
})

export const PAID_MEDIA_ENGINE_SESSION_HEADERS = Object.freeze({
  protocol: 'X-Nachuan-Paid-Session-Protocol',
  timestampMs: 'X-Nachuan-Paid-Session-Timestamp-Ms',
  nonce: 'X-Nachuan-Paid-Session-Nonce',
  generation: 'X-Nachuan-Paid-Session-Generation',
  pid: 'X-Nachuan-Paid-Session-Pid',
  port: 'X-Nachuan-Paid-Session-Port',
  bodySha256: 'X-Nachuan-Paid-Session-Body-SHA256',
  requestContractSha256: 'X-Nachuan-Paid-Session-Request-Contract-SHA256',
  signature: 'X-Nachuan-Paid-Session-Signature',
  requestNonce: 'X-Nachuan-Paid-Session-Request-Nonce',
  responseBodySha256: 'X-Nachuan-Paid-Session-Response-Body-SHA256',
  responseContractSha256: 'X-Nachuan-Paid-Session-Response-Contract-SHA256',
  responseSignature: 'X-Nachuan-Paid-Session-Response-Signature'
})
export const PAID_MEDIA_ENGINE_SESSION_RESPONSE_CONTRACT_HEADERS = Object.freeze([
  'content-type',
  'content-length',
  'cache-control',
  'x-nachuan-paid-media-protocol',
  'idempotency-replayed',
  'retry-after',
  'x-content-sha256',
  'x-content-type-options',
  'content-encoding',
  'transfer-encoding',
  'content-range',
  'location',
  'trailer',
  'upgrade'
] as const)

const REQUEST_DOMAIN = Buffer.from(
  PAID_MEDIA_ENGINE_SESSION_DOMAINS.request,
  'ascii'
)
const REQUEST_CONTRACT_DOMAIN = Buffer.from(
  PAID_MEDIA_ENGINE_SESSION_DOMAINS.requestContract,
  'ascii'
)
const RESPONSE_DOMAIN = Buffer.from(
  PAID_MEDIA_ENGINE_SESSION_DOMAINS.response,
  'ascii'
)
const RESPONSE_CONTRACT_DOMAIN = Buffer.from(
  PAID_MEDIA_ENGINE_SESSION_DOMAINS.responseContract,
  'ascii'
)
const LOWER_HEX_32 = /^[0-9a-f]{64}$/
const METHOD = /^[A-Z]{1,16}$/
const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/
const CANONICAL_DECIMAL = /^(?:0|[1-9][0-9]*)$/
const ZERO_HEX_32 = '0'.repeat(64)
const MAX_TARGET_BYTES = 8 * 1024
const MAX_CLOCK_WINDOW_MS = 5 * 60 * 1000
const SESSION_HEADER_PREFIX = 'x-nachuan-paid-session-'
const REQUEST_SESSION_HEADERS = Object.freeze([
  PAID_MEDIA_ENGINE_SESSION_HEADERS.protocol,
  PAID_MEDIA_ENGINE_SESSION_HEADERS.timestampMs,
  PAID_MEDIA_ENGINE_SESSION_HEADERS.nonce,
  PAID_MEDIA_ENGINE_SESSION_HEADERS.generation,
  PAID_MEDIA_ENGINE_SESSION_HEADERS.pid,
  PAID_MEDIA_ENGINE_SESSION_HEADERS.port,
  PAID_MEDIA_ENGINE_SESSION_HEADERS.bodySha256,
  PAID_MEDIA_ENGINE_SESSION_HEADERS.requestContractSha256,
  PAID_MEDIA_ENGINE_SESSION_HEADERS.signature
])
const RESPONSE_SESSION_HEADERS = Object.freeze([
  PAID_MEDIA_ENGINE_SESSION_HEADERS.protocol,
  PAID_MEDIA_ENGINE_SESSION_HEADERS.requestNonce,
  PAID_MEDIA_ENGINE_SESSION_HEADERS.generation,
  PAID_MEDIA_ENGINE_SESSION_HEADERS.pid,
  PAID_MEDIA_ENGINE_SESSION_HEADERS.port,
  PAID_MEDIA_ENGINE_SESSION_HEADERS.responseBodySha256,
  PAID_MEDIA_ENGINE_SESSION_HEADERS.responseContractSha256,
  PAID_MEDIA_ENGINE_SESSION_HEADERS.responseSignature
])
const ALL_SESSION_HEADER_NAMES = new Set(
  [...REQUEST_SESSION_HEADERS, ...RESPONSE_SESSION_HEADERS].map((name) =>
    name.toLowerCase()
  )
)

export class PaidMediaEngineSessionProtocolError extends Error {
  override readonly name = 'PaidMediaEngineSessionProtocolError'

  constructor(
    readonly code: string,
    message: string,
    options?: ErrorOptions
  ) {
    super(message, options)
  }
}

export type PaidMediaEngineSessionIdentity = Readonly<{
  bootToken: string
  generation: number
  pid: number
  port: number
}>

export type PaidMediaEngineSessionSignedRequest = Readonly<{
  headers: Readonly<Record<string, string>>
  timestampMs: number
  nonce: string
  bodySha256: string
  contractSha256: string
  signature: string
}>

export type PaidMediaEngineSessionVerifiedRequest = Readonly<{
  timestampMs: number
  nonce: string
  generation: number
  pid: number
  port: number
  bodySha256: string
  contractSha256: string
}>

export type PaidMediaEngineSessionSignedResponse = Readonly<{
  headers: Readonly<Record<string, string>>
  requestNonce: string
  bodySha256: string
  contractSha256: string
  signature: string
}>

export type PaidMediaEngineSessionVerifiedResponse = Readonly<{
  requestNonce: string
  generation: number
  pid: number
  port: number
  status: number
  declaredBodySha256: string
  contractSha256: string
}>

type ParsedRawHeader = Readonly<{ lowerName: string; value: string }>

function fail(code: string, message: string): PaidMediaEngineSessionProtocolError {
  return new PaidMediaEngineSessionProtocolError(code, message)
}

function lowerHex32(value: unknown, label: string, allowZero = true): Buffer {
  if (
    typeof value !== 'string' ||
    !LOWER_HEX_32.test(value) ||
    (!allowZero && value === ZERO_HEX_32)
  ) {
    throw fail('invalid_engine_session_input', `${label} is invalid`)
  }
  return Buffer.from(value, 'hex')
}

function uint64(value: unknown, label: string, minimum = 0): Buffer {
  if (!Number.isSafeInteger(value) || Number(value) < minimum) {
    throw fail('invalid_engine_session_input', `${label} is outside its range`)
  }
  const output = Buffer.allocUnsafe(8)
  output.writeBigUInt64BE(BigInt(Number(value)))
  return output
}

function uint32(value: unknown, label: string, minimum = 0, maximum = 0xffff_ffff): Buffer {
  if (
    !Number.isSafeInteger(value) ||
    Number(value) < minimum ||
    Number(value) > maximum
  ) {
    throw fail('invalid_engine_session_input', `${label} is outside its range`)
  }
  const output = Buffer.allocUnsafe(4)
  output.writeUInt32BE(Number(value))
  return output
}

function canonicalDecimal(value: unknown, label: string, minimum: number): string {
  uint64(value, label, minimum)
  return String(value)
}

function validatedSession(value: unknown): PaidMediaEngineSessionIdentity {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw fail('invalid_engine_session_input', 'Paid media engine session is invalid')
  }
  const session = value as Record<string, unknown>
  if (
    Object.keys(session).sort().join('\0') !==
    ['bootToken', 'generation', 'pid', 'port'].sort().join('\0')
  ) {
    throw fail('invalid_engine_session_input', 'Paid media engine session is invalid')
  }
  lowerHex32(session.bootToken, 'Paid media engine boot token', false)
  uint64(session.generation, 'Paid media engine generation', 1)
  uint64(session.pid, 'Paid media engine pid', 1)
  uint32(session.port, 'Paid media engine port', 1024, 65_535)
  return Object.freeze({
    bootToken: session.bootToken as string,
    generation: Number(session.generation),
    pid: Number(session.pid),
    port: Number(session.port)
  })
}

function validatedTimestamp(value: unknown): number {
  uint64(value, 'Paid media engine-session timestamp')
  return Number(value)
}

function parsedCanonicalDecimal(
  value: unknown,
  label: string,
  minimum: number,
  maximum = Number.MAX_SAFE_INTEGER
): number {
  if (
    typeof value !== 'string' ||
    !CANONICAL_DECIMAL.test(value) ||
    value.length > 16
  ) {
    throw fail('invalid_engine_session_headers', `${label} is invalid`)
  }
  const parsed = Number(value)
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw fail('invalid_engine_session_headers', `${label} is outside its range`)
  }
  return parsed
}

function validatedMethod(value: unknown): string {
  if (typeof value !== 'string' || !METHOD.test(value)) {
    throw fail('invalid_engine_session_input', 'Paid media engine-session method is invalid')
  }
  return value
}

function validatedTarget(value: unknown): string {
  if (
    typeof value !== 'string' ||
    !value.startsWith('/') ||
    value.includes('?') ||
    value.includes('#') ||
    value.includes('\\') ||
    Buffer.byteLength(value, 'ascii') > MAX_TARGET_BYTES ||
    /[^\x21-\x7e]/.test(value)
  ) {
    throw fail(
      'invalid_engine_session_input',
      'Paid media engine-session target is not query-free ASCII origin-form'
    )
  }
  return value
}

function frame(domain: Buffer, fields: readonly Buffer[]): Buffer {
  const parts: Buffer[] = [uint32(domain.byteLength, 'Frame domain length'), domain]
  parts.push(uint32(fields.length, 'Frame field count'))
  for (const field of fields) {
    parts.push(uint64(field.byteLength, 'Frame field length'), field)
  }
  return Buffer.concat(parts)
}

function requestMacInput(input: {
  timestampMs: number
  nonce: string
  session: PaidMediaEngineSessionIdentity
  method: string
  target: string
  bodySha256: string
  contractSha256: string
}): Buffer {
  return frame(REQUEST_DOMAIN, [
    Buffer.from(PAID_MEDIA_ENGINE_SESSION_VERSION, 'ascii'),
    uint64(input.timestampMs, 'Paid media engine-session timestamp'),
    lowerHex32(input.nonce, 'Paid media engine-session nonce', false),
    uint64(input.session.generation, 'Paid media engine generation', 1),
    uint64(input.session.pid, 'Paid media engine pid', 1),
    uint32(input.session.port, 'Paid media engine port', 1024, 65_535),
    Buffer.from(input.method, 'ascii'),
    Buffer.from(input.target, 'ascii'),
    lowerHex32(input.bodySha256, 'Paid media engine-session body digest'),
    lowerHex32(input.contractSha256, 'Paid media engine-session request contract digest')
  ])
}

function responseMacInput(input: {
  requestNonce: string
  session: PaidMediaEngineSessionIdentity
  status: number
  bodySha256: string
  contractSha256: string
}): Buffer {
  return frame(RESPONSE_DOMAIN, [
    Buffer.from(PAID_MEDIA_ENGINE_SESSION_VERSION, 'ascii'),
    lowerHex32(input.requestNonce, 'Paid media engine-session request nonce', false),
    uint64(input.session.generation, 'Paid media engine generation', 1),
    uint64(input.session.pid, 'Paid media engine pid', 1),
    uint32(input.session.port, 'Paid media engine port', 1024, 65_535),
    uint32(input.status, 'Paid media engine-session response status', 100, 599),
    lowerHex32(input.bodySha256, 'Paid media engine-session response body digest'),
    lowerHex32(input.contractSha256, 'Paid media engine-session response contract digest')
  ])
}

function exactHexEqual(left: unknown, right: unknown): boolean {
  if (
    typeof left !== 'string' ||
    typeof right !== 'string' ||
    !LOWER_HEX_32.test(left) ||
    !LOWER_HEX_32.test(right)
  ) {
    return false
  }
  return timingSafeEqual(Buffer.from(left, 'hex'), Buffer.from(right, 'hex'))
}

function parseRawHeaders(rawHeaders: readonly string[]): readonly ParsedRawHeader[] {
  if (!Array.isArray(rawHeaders) || rawHeaders.length % 2 !== 0) {
    throw fail('invalid_engine_session_headers', 'Paid media engine-session headers are malformed')
  }
  const parsed: ParsedRawHeader[] = []
  for (let index = 0; index < rawHeaders.length; index += 2) {
    const name = rawHeaders[index]
    const value = rawHeaders[index + 1]
    if (
      typeof name !== 'string' ||
      !HEADER_NAME.test(name) ||
      typeof value !== 'string' ||
      /[^\x20-\x7e]/.test(value)
    ) {
      throw fail(
        'invalid_engine_session_headers',
        'Paid media engine-session headers are malformed'
      )
    }
    parsed.push(Object.freeze({ lowerName: name.toLowerCase(), value }))
  }
  return Object.freeze(parsed)
}

function extractSessionHeaders(
  rawHeaders: readonly string[],
  direction: 'request' | 'response'
): Readonly<Record<string, string>> {
  const required = direction === 'request' ? REQUEST_SESSION_HEADERS : RESPONSE_SESSION_HEADERS
  const requiredNames = new Map(required.map((name) => [name.toLowerCase(), name]))
  const observed = new Map(required.map((name) => [name.toLowerCase(), [] as string[]]))
  for (const { lowerName, value } of parseRawHeaders(rawHeaders)) {
    if (!lowerName.startsWith(SESSION_HEADER_PREFIX)) continue
    if (!ALL_SESSION_HEADER_NAMES.has(lowerName)) {
      throw fail(
        'unknown_engine_session_header',
        'Unknown paid media engine-session header'
      )
    }
    if (!requiredNames.has(lowerName)) {
      throw fail(
        'wrong_engine_session_header_direction',
        'Paid media engine-session header is used in the wrong direction'
      )
    }
    observed.get(lowerName)?.push(value)
  }
  const result: Record<string, string> = {}
  for (const [lowerName, canonicalName] of requiredNames) {
    const values = observed.get(lowerName)
    if (
      !values ||
      values.length !== 1 ||
      values[0].length === 0 ||
      values[0] !== values[0].trim() ||
      values[0].includes(',')
    ) {
      throw fail(
        'ambiguous_engine_session_header',
        'Paid media engine-session header is missing, duplicate, or merged'
      )
    }
    result[canonicalName] = values[0]
  }
  return Object.freeze(result)
}

function responseContractFrame(rawHeaders: readonly string[]): Buffer {
  const parsed = parseRawHeaders(rawHeaders)
  const contractNames = new Set<string>(PAID_MEDIA_ENGINE_SESSION_RESPONSE_CONTRACT_HEADERS)
  const observed = new Map<string, string[]>(
    PAID_MEDIA_ENGINE_SESSION_RESPONSE_CONTRACT_HEADERS.map((name) => [name, [] as string[]])
  )
  let responseSessionHeaderCount = 0
  for (const { lowerName, value } of parsed) {
    if (lowerName.startsWith(SESSION_HEADER_PREFIX)) {
      if (!ALL_SESSION_HEADER_NAMES.has(lowerName)) {
        throw fail(
          'unknown_engine_session_header',
          'Unknown paid media engine-session header'
        )
      }
      if (!RESPONSE_SESSION_HEADERS.some((name) => name.toLowerCase() === lowerName)) {
        throw fail(
          'wrong_engine_session_header_direction',
          'Paid media engine-session header is used in the wrong direction'
        )
      }
      responseSessionHeaderCount += 1
      continue
    }
    if (contractNames.has(lowerName)) observed.get(lowerName)?.push(value)
  }
  if (responseSessionHeaderCount > 0) extractSessionHeaders(rawHeaders, 'response')
  const fields = PAID_MEDIA_ENGINE_SESSION_RESPONSE_CONTRACT_HEADERS.map((name) => {
    const values = observed.get(name) ?? []
    if (values.length === 0) return Buffer.from([0])
    if (
      values.length !== 1 ||
      values[0].length === 0 ||
      values[0] !== values[0].trim() ||
      values[0].includes(',')
    ) {
      throw fail(
        'ambiguous_engine_session_contract_header',
        'Paid media response contract header is duplicate, merged, or non-canonical'
      )
    }
    return Buffer.concat([Buffer.from([1]), Buffer.from(values[0], 'ascii')])
  })
  return frame(RESPONSE_CONTRACT_DOMAIN, fields)
}

function requestContractFrame(rawHeaders: readonly string[]): Buffer {
  const parsed = parseRawHeaders(rawHeaders)
  const observed = new Map<string, string[]>()
  let requestSessionHeaderCount = 0
  for (const { lowerName, value } of parsed) {
    if (lowerName.startsWith(SESSION_HEADER_PREFIX)) {
      if (!ALL_SESSION_HEADER_NAMES.has(lowerName)) {
        throw fail(
          'unknown_engine_session_header',
          'Unknown paid media engine-session header'
        )
      }
      if (!REQUEST_SESSION_HEADERS.some((name) => name.toLowerCase() === lowerName)) {
        throw fail(
          'wrong_engine_session_header_direction',
          'Paid media engine-session header is used in the wrong direction'
        )
      }
      requestSessionHeaderCount += 1
      continue
    }
    const values = observed.get(lowerName) ?? []
    values.push(value)
    observed.set(lowerName, values)
  }
  if (requestSessionHeaderCount > 0) extractSessionHeaders(rawHeaders, 'request')
  const names = [...observed.keys()].sort((left, right) =>
    Buffer.compare(Buffer.from(left, 'ascii'), Buffer.from(right, 'ascii'))
  )
  const fields: Buffer[] = []
  for (const name of names) {
    const values = observed.get(name) ?? []
    if (
      values.length !== 1 ||
      values[0].length === 0 ||
      values[0] !== values[0].trim() ||
      values[0].includes(',')
    ) {
      throw fail(
        'ambiguous_engine_session_request_contract_header',
        'Paid media request contract header is duplicate, merged, or non-canonical'
      )
    }
    fields.push(Buffer.from(name, 'ascii'), Buffer.from(values[0], 'ascii'))
  }
  return frame(REQUEST_CONTRACT_DOMAIN, fields)
}

export function paidMediaEngineSessionRequestContractSha256(
  rawHeaders: readonly string[]
): string {
  return createHash('sha256').update(requestContractFrame(rawHeaders)).digest('hex')
}

export function paidMediaEngineSessionResponseContractSha256(
  rawHeaders: readonly string[]
): string {
  return createHash('sha256').update(responseContractFrame(rawHeaders)).digest('hex')
}

export function derivePaidMediaEngineSessionKey(bootToken: unknown): Buffer {
  const key = lowerHex32(bootToken, 'Paid media engine boot token', false)
  return createHmac('sha256', key)
    .update(PAID_MEDIA_ENGINE_SESSION_DOMAINS.key, 'ascii')
    .digest()
}

export function signPaidMediaEngineSessionRequest(input: {
  session: PaidMediaEngineSessionIdentity
  timestampMs: number
  nonce: string
  method: string
  target: string
  bodySha256: string
  rawHeaders: readonly string[]
}): PaidMediaEngineSessionSignedRequest {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw fail('invalid_engine_session_input', 'Paid media engine-session request is invalid')
  }
  const session = validatedSession(input.session)
  const timestampMs = validatedTimestamp(input.timestampMs)
  const nonce = lowerHex32(input.nonce, 'Paid media engine-session nonce', false)
  const method = validatedMethod(input.method)
  const target = validatedTarget(input.target)
  const bodySha256 = lowerHex32(
    input.bodySha256,
    'Paid media engine-session body digest'
  )
  const contractSha256 = paidMediaEngineSessionRequestContractSha256(input.rawHeaders)
  const signature = createHmac(
    'sha256',
    derivePaidMediaEngineSessionKey(session.bootToken)
  )
    .update(
      requestMacInput({
        timestampMs,
        nonce: nonce.toString('hex'),
        session,
        method,
        target,
        bodySha256: bodySha256.toString('hex'),
        contractSha256
      })
    )
    .digest('hex')
  const bodySha256Hex = bodySha256.toString('hex')
  const nonceHex = nonce.toString('hex')
  return Object.freeze({
    headers: Object.freeze({
      [PAID_MEDIA_ENGINE_SESSION_HEADERS.protocol]: PAID_MEDIA_ENGINE_SESSION_VERSION,
      [PAID_MEDIA_ENGINE_SESSION_HEADERS.timestampMs]: String(timestampMs),
      [PAID_MEDIA_ENGINE_SESSION_HEADERS.nonce]: nonceHex,
      [PAID_MEDIA_ENGINE_SESSION_HEADERS.generation]: canonicalDecimal(
        session.generation,
        'Paid media engine generation',
        1
      ),
      [PAID_MEDIA_ENGINE_SESSION_HEADERS.pid]: canonicalDecimal(
        session.pid,
        'Paid media engine pid',
        1
      ),
      [PAID_MEDIA_ENGINE_SESSION_HEADERS.port]: String(session.port),
      [PAID_MEDIA_ENGINE_SESSION_HEADERS.bodySha256]: bodySha256Hex,
      [PAID_MEDIA_ENGINE_SESSION_HEADERS.requestContractSha256]: contractSha256,
      [PAID_MEDIA_ENGINE_SESSION_HEADERS.signature]: signature
    }),
    timestampMs,
    nonce: nonceHex,
    bodySha256: bodySha256Hex,
    contractSha256,
    signature
  })
}

export function verifyPaidMediaEngineSessionRequest(input: {
  session: PaidMediaEngineSessionIdentity
  rawHeaders: readonly string[]
  nowMs: number
  maxPastMs?: number
  maxFutureMs?: number
  method: string
  target: string
  bodySha256: string
}): PaidMediaEngineSessionVerifiedRequest {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw fail('invalid_engine_session_input', 'Paid media engine-session request is invalid')
  }
  const session = validatedSession(input.session)
  const headers = extractSessionHeaders(input.rawHeaders, 'request')
  if (headers[PAID_MEDIA_ENGINE_SESSION_HEADERS.protocol] !== PAID_MEDIA_ENGINE_SESSION_VERSION) {
    throw fail('unsupported_engine_session_protocol', 'Paid media engine-session version is invalid')
  }
  const timestampMs = parsedCanonicalDecimal(
    headers[PAID_MEDIA_ENGINE_SESSION_HEADERS.timestampMs],
    'Paid media engine-session timestamp',
    0
  )
  const nowMs = validatedTimestamp(input.nowMs)
  const maxPastMs =
    input.maxPastMs === undefined
      ? PAID_MEDIA_ENGINE_SESSION_MAX_PAST_MS
      : parsedCanonicalDecimal(
          String(input.maxPastMs),
          'Paid media engine-session past window',
          0,
          MAX_CLOCK_WINDOW_MS
        )
  const maxFutureMs =
    input.maxFutureMs === undefined
      ? PAID_MEDIA_ENGINE_SESSION_MAX_FUTURE_MS
      : parsedCanonicalDecimal(
          String(input.maxFutureMs),
          'Paid media engine-session future window',
          0,
          MAX_CLOCK_WINDOW_MS
        )
  if (
    (timestampMs <= nowMs && nowMs - timestampMs > maxPastMs) ||
    (timestampMs > nowMs && timestampMs - nowMs > maxFutureMs)
  ) {
    throw fail('expired_engine_session_request', 'Paid media engine-session request is expired')
  }
  const nonce = headers[PAID_MEDIA_ENGINE_SESSION_HEADERS.nonce]
  lowerHex32(nonce, 'Paid media engine-session nonce', false)
  const generation = parsedCanonicalDecimal(
    headers[PAID_MEDIA_ENGINE_SESSION_HEADERS.generation],
    'Paid media engine generation',
    1
  )
  const pid = parsedCanonicalDecimal(
    headers[PAID_MEDIA_ENGINE_SESSION_HEADERS.pid],
    'Paid media engine pid',
    1
  )
  const port = parsedCanonicalDecimal(
    headers[PAID_MEDIA_ENGINE_SESSION_HEADERS.port],
    'Paid media engine port',
    1024,
    65_535
  )
  if (generation !== session.generation || pid !== session.pid || port !== session.port) {
    throw fail('engine_session_mismatch', 'Paid media engine-session identity does not match')
  }
  const method = validatedMethod(input.method)
  const target = validatedTarget(input.target)
  const bodySha256 = lowerHex32(
    input.bodySha256,
    'Paid media engine-session body digest'
  ).toString('hex')
  const claimedBodySha256 = headers[PAID_MEDIA_ENGINE_SESSION_HEADERS.bodySha256]
  const claimedContractSha256 =
    headers[PAID_MEDIA_ENGINE_SESSION_HEADERS.requestContractSha256]
  const claimedSignature = headers[PAID_MEDIA_ENGINE_SESSION_HEADERS.signature]
  lowerHex32(claimedContractSha256, 'Paid media engine-session request contract digest')
  const contractSha256 = paidMediaEngineSessionRequestContractSha256(input.rawHeaders)
  if (
    !exactHexEqual(claimedBodySha256, bodySha256) ||
    !exactHexEqual(claimedContractSha256, contractSha256)
  ) {
    throw fail('engine_session_authentication_failed', 'Paid media engine-session authentication failed')
  }
  const expectedSignature = createHmac(
    'sha256',
    derivePaidMediaEngineSessionKey(session.bootToken)
  )
    .update(
      requestMacInput({
        timestampMs,
        nonce,
        session: { ...session, generation, pid, port },
        method,
        target,
        bodySha256,
        contractSha256
      })
    )
    .digest('hex')
  if (!exactHexEqual(claimedSignature, expectedSignature)) {
    throw fail('engine_session_authentication_failed', 'Paid media engine-session authentication failed')
  }
  return Object.freeze({
    timestampMs,
    nonce,
    generation,
    pid,
    port,
    bodySha256,
    contractSha256
  })
}

export function signPaidMediaEngineSessionResponse(input: {
  session: PaidMediaEngineSessionIdentity
  requestNonce: string
  status: number
  bodySha256: string
  rawHeaders: readonly string[]
}): PaidMediaEngineSessionSignedResponse {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw fail('invalid_engine_session_input', 'Paid media engine-session response is invalid')
  }
  const session = validatedSession(input.session)
  const requestNonce = lowerHex32(
    input.requestNonce,
    'Paid media engine-session request nonce',
    false
  ).toString('hex')
  uint32(input.status, 'Paid media engine-session response status', 100, 599)
  const bodySha256 = lowerHex32(
    input.bodySha256,
    'Paid media engine-session response body digest'
  ).toString('hex')
  const contractSha256 = paidMediaEngineSessionResponseContractSha256(input.rawHeaders)
  const signature = createHmac(
    'sha256',
    derivePaidMediaEngineSessionKey(session.bootToken)
  )
    .update(
      responseMacInput({
        requestNonce,
        session,
        status: input.status,
        bodySha256,
        contractSha256
      })
    )
    .digest('hex')
  return Object.freeze({
    headers: Object.freeze({
      [PAID_MEDIA_ENGINE_SESSION_HEADERS.protocol]: PAID_MEDIA_ENGINE_SESSION_VERSION,
      [PAID_MEDIA_ENGINE_SESSION_HEADERS.requestNonce]: requestNonce,
      [PAID_MEDIA_ENGINE_SESSION_HEADERS.generation]: String(session.generation),
      [PAID_MEDIA_ENGINE_SESSION_HEADERS.pid]: String(session.pid),
      [PAID_MEDIA_ENGINE_SESSION_HEADERS.port]: String(session.port),
      [PAID_MEDIA_ENGINE_SESSION_HEADERS.responseBodySha256]: bodySha256,
      [PAID_MEDIA_ENGINE_SESSION_HEADERS.responseContractSha256]: contractSha256,
      [PAID_MEDIA_ENGINE_SESSION_HEADERS.responseSignature]: signature
    }),
    requestNonce,
    bodySha256,
    contractSha256,
    signature
  })
}

export function verifyPaidMediaEngineSessionResponseEnvelope(input: {
  session: PaidMediaEngineSessionIdentity
  requestNonce: string
  status: number
  rawHeaders: readonly string[]
}): PaidMediaEngineSessionVerifiedResponse {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw fail('invalid_engine_session_input', 'Paid media engine-session response is invalid')
  }
  const session = validatedSession(input.session)
  const expectedRequestNonce = lowerHex32(
    input.requestNonce,
    'Paid media engine-session request nonce',
    false
  ).toString('hex')
  uint32(input.status, 'Paid media engine-session response status', 100, 599)
  const headers = extractSessionHeaders(input.rawHeaders, 'response')
  if (headers[PAID_MEDIA_ENGINE_SESSION_HEADERS.protocol] !== PAID_MEDIA_ENGINE_SESSION_VERSION) {
    throw fail('unsupported_engine_session_protocol', 'Paid media engine-session version is invalid')
  }
  const requestNonce = headers[PAID_MEDIA_ENGINE_SESSION_HEADERS.requestNonce]
  const generation = parsedCanonicalDecimal(
    headers[PAID_MEDIA_ENGINE_SESSION_HEADERS.generation],
    'Paid media engine generation',
    1
  )
  const pid = parsedCanonicalDecimal(
    headers[PAID_MEDIA_ENGINE_SESSION_HEADERS.pid],
    'Paid media engine pid',
    1
  )
  const port = parsedCanonicalDecimal(
    headers[PAID_MEDIA_ENGINE_SESSION_HEADERS.port],
    'Paid media engine port',
    1024,
    65_535
  )
  if (
    !exactHexEqual(requestNonce, expectedRequestNonce) ||
    generation !== session.generation ||
    pid !== session.pid ||
    port !== session.port
  ) {
    throw fail('engine_session_mismatch', 'Paid media engine-session identity does not match')
  }
  const declaredBodySha256 = headers[PAID_MEDIA_ENGINE_SESSION_HEADERS.responseBodySha256]
  const claimedContractSha256 =
    headers[PAID_MEDIA_ENGINE_SESSION_HEADERS.responseContractSha256]
  const claimedSignature = headers[PAID_MEDIA_ENGINE_SESSION_HEADERS.responseSignature]
  lowerHex32(declaredBodySha256, 'Paid media engine-session response body digest')
  lowerHex32(claimedContractSha256, 'Paid media engine-session response contract digest')
  const contractSha256 = paidMediaEngineSessionResponseContractSha256(input.rawHeaders)
  if (!exactHexEqual(claimedContractSha256, contractSha256)) {
    throw fail('engine_session_authentication_failed', 'Paid media engine-session authentication failed')
  }
  const expectedSignature = createHmac(
    'sha256',
    derivePaidMediaEngineSessionKey(session.bootToken)
  )
    .update(
      responseMacInput({
        requestNonce,
        session: { ...session, generation, pid, port },
        status: input.status,
        bodySha256: declaredBodySha256,
        contractSha256
      })
    )
    .digest('hex')
  if (!exactHexEqual(claimedSignature, expectedSignature)) {
    throw fail('engine_session_authentication_failed', 'Paid media engine-session authentication failed')
  }
  return Object.freeze({
    requestNonce,
    generation,
    pid,
    port,
    status: input.status,
    declaredBodySha256,
    contractSha256
  })
}

export function verifyPaidMediaEngineSessionResponse(input: {
  session: PaidMediaEngineSessionIdentity
  requestNonce: string
  status: number
  bodySha256: string
  rawHeaders: readonly string[]
}): PaidMediaEngineSessionVerifiedResponse {
  const verified = verifyPaidMediaEngineSessionResponseEnvelope(input)
  const bodySha256 = lowerHex32(
    input.bodySha256,
    'Paid media engine-session response body digest'
  ).toString('hex')
  if (!exactHexEqual(verified.declaredBodySha256, bodySha256)) {
    throw fail('engine_session_body_mismatch', 'Paid media engine-session response body changed')
  }
  return verified
}
