import { createHash, createHmac, timingSafeEqual } from 'node:crypto'

export const DESKTOP_ENGINE_SESSION_VERSION = '1'
export const DESKTOP_ENGINE_SESSION_CHALLENGE_PATH =
  '/internal/v1/desktop/session/challenge'
export const DESKTOP_ENGINE_SESSION_CHALLENGE_SCHEMA =
  'nachuan.desktop.engine-session.challenge.v1'
export const DESKTOP_ENGINE_SESSION_CHALLENGE_JSON =
  '{"schema":"nachuan.desktop.engine-session.challenge.v1","ok":true}'
export const DESKTOP_ENGINE_SESSION_MAX_PAST_MS = 30_000
export const DESKTOP_ENGINE_SESSION_MAX_FUTURE_MS = 5_000

export const DESKTOP_ENGINE_SESSION_DOMAINS = Object.freeze({
  key: 'nachuan.desktop.engine-session.key.v1',
  request: 'nachuan.desktop.engine-session.request.v1',
  requestContract: 'nachuan.desktop.engine-session.request-contract.v1',
  response: 'nachuan.desktop.engine-session.response.v1',
  responseContract: 'nachuan.desktop.engine-session.response-contract.v1'
})

const LOWER_HEX_32 = /^[0-9a-f]{64}$/
const ZERO_HEX_32 = '0'.repeat(64)
const METHOD = /^[A-Z]{1,16}$/
const CAPABILITY = /^[a-z][a-z0-9.-]{0,63}$/
const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/
const CANONICAL_DECIMAL = /^(?:0|[1-9][0-9]*)$/
const MAX_TARGET_BYTES = 8 * 1024
const MAX_CLOCK_WINDOW_MS = 5 * 60 * 1000
const SESSION_HEADER_PREFIX = 'x-nachuan-engine-session-'
const REQUEST_DOMAIN = Buffer.from(DESKTOP_ENGINE_SESSION_DOMAINS.request, 'ascii')
const REQUEST_CONTRACT_DOMAIN = Buffer.from(
  DESKTOP_ENGINE_SESSION_DOMAINS.requestContract,
  'ascii'
)
const RESPONSE_DOMAIN = Buffer.from(DESKTOP_ENGINE_SESSION_DOMAINS.response, 'ascii')
const RESPONSE_CONTRACT_DOMAIN = Buffer.from(
  DESKTOP_ENGINE_SESSION_DOMAINS.responseContract,
  'ascii'
)

export const DESKTOP_ENGINE_SESSION_HEADERS = Object.freeze({
  protocol: 'X-Nachuan-Engine-Session-Protocol',
  timestampMs: 'X-Nachuan-Engine-Session-Timestamp-Ms',
  nonce: 'X-Nachuan-Engine-Session-Nonce',
  channelNonce: 'X-Nachuan-Engine-Session-Channel-Nonce',
  generation: 'X-Nachuan-Engine-Session-Generation',
  pid: 'X-Nachuan-Engine-Session-Pid',
  port: 'X-Nachuan-Engine-Session-Port',
  capability: 'X-Nachuan-Engine-Session-Capability',
  bodySha256: 'X-Nachuan-Engine-Session-Body-SHA256',
  requestContractSha256: 'X-Nachuan-Engine-Session-Request-Contract-SHA256',
  signature: 'X-Nachuan-Engine-Session-Signature',
  requestNonce: 'X-Nachuan-Engine-Session-Request-Nonce',
  responseBodySha256: 'X-Nachuan-Engine-Session-Response-Body-SHA256',
  responseContractSha256: 'X-Nachuan-Engine-Session-Response-Contract-SHA256',
  responseSignature: 'X-Nachuan-Engine-Session-Response-Signature'
})

const REQUEST_SESSION_HEADERS = Object.freeze([
  DESKTOP_ENGINE_SESSION_HEADERS.protocol,
  DESKTOP_ENGINE_SESSION_HEADERS.timestampMs,
  DESKTOP_ENGINE_SESSION_HEADERS.nonce,
  DESKTOP_ENGINE_SESSION_HEADERS.channelNonce,
  DESKTOP_ENGINE_SESSION_HEADERS.generation,
  DESKTOP_ENGINE_SESSION_HEADERS.pid,
  DESKTOP_ENGINE_SESSION_HEADERS.port,
  DESKTOP_ENGINE_SESSION_HEADERS.capability,
  DESKTOP_ENGINE_SESSION_HEADERS.bodySha256,
  DESKTOP_ENGINE_SESSION_HEADERS.requestContractSha256,
  DESKTOP_ENGINE_SESSION_HEADERS.signature
])
const RESPONSE_SESSION_HEADERS = Object.freeze([
  DESKTOP_ENGINE_SESSION_HEADERS.protocol,
  DESKTOP_ENGINE_SESSION_HEADERS.requestNonce,
  DESKTOP_ENGINE_SESSION_HEADERS.generation,
  DESKTOP_ENGINE_SESSION_HEADERS.pid,
  DESKTOP_ENGINE_SESSION_HEADERS.port,
  DESKTOP_ENGINE_SESSION_HEADERS.capability,
  DESKTOP_ENGINE_SESSION_HEADERS.responseBodySha256,
  DESKTOP_ENGINE_SESSION_HEADERS.responseContractSha256,
  DESKTOP_ENGINE_SESSION_HEADERS.responseSignature
])
const ALL_SESSION_HEADER_NAMES = new Set(
  [...REQUEST_SESSION_HEADERS, ...RESPONSE_SESSION_HEADERS].map((name) =>
    name.toLowerCase()
  )
)
// HTTP servers may append these transport diagnostics after the ASGI app has
// signed its response. They never affect representation semantics or authority.
const UNSIGNED_TRANSPORT_RESPONSE_HEADERS = new Set(['date', 'server', 'keep-alive'])

export type DesktopEngineSessionIdentity = Readonly<{
  bootToken: string
  generation: number
  pid: number
  port: number
}>

export type DesktopEngineSessionSignedRequest = Readonly<{
  headers: Readonly<Record<string, string>>
  timestampMs: number
  nonce: string
  channelNonce: string
  capability: string
  bodySha256: string
  contractSha256: string
  signature: string
}>

export type DesktopEngineSessionVerifiedRequest = Readonly<{
  timestampMs: number
  nonce: string
  channelNonce: string
  generation: number
  pid: number
  port: number
  capability: string
  bodySha256: string
  contractSha256: string
}>

export type DesktopEngineSessionSignedResponse = Readonly<{
  headers: Readonly<Record<string, string>>
  requestNonce: string
  capability: string
  bodySha256: string
  contractSha256: string
  signature: string
}>

export type DesktopEngineSessionVerifiedResponse = Readonly<{
  requestNonce: string
  generation: number
  pid: number
  port: number
  capability: string
  status: number
  declaredBodySha256: string
  contractSha256: string
}>

type ParsedRawHeader = Readonly<{ lowerName: string; value: string }>

export class DesktopEngineSessionProtocolError extends Error {
  override readonly name = 'DesktopEngineSessionProtocolError'

  constructor(
    readonly code: string,
    message: string,
    options?: ErrorOptions
  ) {
    super(message, options)
  }
}

function fail(code: string, message: string): DesktopEngineSessionProtocolError {
  return new DesktopEngineSessionProtocolError(code, message)
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

function validatedSession(value: unknown): DesktopEngineSessionIdentity {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw fail('invalid_engine_session_input', 'Desktop engine session is invalid')
  }
  const session = value as Record<string, unknown>
  if (
    Object.keys(session).sort().join('\0') !==
    ['bootToken', 'generation', 'pid', 'port'].sort().join('\0')
  ) {
    throw fail('invalid_engine_session_input', 'Desktop engine session is invalid')
  }
  lowerHex32(session.bootToken, 'Desktop engine boot token', false)
  uint64(session.generation, 'Desktop engine generation', 1)
  uint64(session.pid, 'Desktop engine pid', 1)
  uint32(session.port, 'Desktop engine port', 1024, 65_535)
  return Object.freeze({
    bootToken: session.bootToken as string,
    generation: Number(session.generation),
    pid: Number(session.pid),
    port: Number(session.port)
  })
}

function validatedMethod(value: unknown): string {
  if (typeof value !== 'string' || !METHOD.test(value)) {
    throw fail('invalid_engine_session_input', 'Desktop engine-session method is invalid')
  }
  return value
}

function validatedCapability(value: unknown): string {
  if (typeof value !== 'string' || !CAPABILITY.test(value)) {
    throw fail('invalid_engine_session_input', 'Desktop engine-session capability is invalid')
  }
  return value
}

function validatedTarget(value: unknown): string {
  if (
    typeof value !== 'string' ||
    !value.startsWith('/') ||
    value.includes('#') ||
    value.includes('\\') ||
    value.indexOf('?') !== value.lastIndexOf('?') ||
    Buffer.byteLength(value, 'ascii') > MAX_TARGET_BYTES ||
    /[^\x21-\x7e]/.test(value)
  ) {
    throw fail(
      'invalid_engine_session_input',
      'Desktop engine-session target is not exact ASCII origin-form'
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
  channelNonce: string
  session: DesktopEngineSessionIdentity
  capability: string
  method: string
  target: string
  bodySha256: string
  contractSha256: string
}): Buffer {
  return frame(REQUEST_DOMAIN, [
    Buffer.from(DESKTOP_ENGINE_SESSION_VERSION, 'ascii'),
    uint64(input.timestampMs, 'Desktop engine-session timestamp'),
    lowerHex32(input.nonce, 'Desktop engine-session nonce', false),
    lowerHex32(input.channelNonce, 'Desktop engine-session channel nonce'),
    uint64(input.session.generation, 'Desktop engine generation', 1),
    uint64(input.session.pid, 'Desktop engine pid', 1),
    uint32(input.session.port, 'Desktop engine port', 1024, 65_535),
    Buffer.from(input.capability, 'ascii'),
    Buffer.from(input.method, 'ascii'),
    Buffer.from(input.target, 'ascii'),
    lowerHex32(input.bodySha256, 'Desktop engine-session body digest'),
    lowerHex32(input.contractSha256, 'Desktop engine-session request contract digest')
  ])
}

function responseMacInput(input: {
  requestNonce: string
  session: DesktopEngineSessionIdentity
  capability: string
  status: number
  bodySha256: string
  contractSha256: string
}): Buffer {
  return frame(RESPONSE_DOMAIN, [
    Buffer.from(DESKTOP_ENGINE_SESSION_VERSION, 'ascii'),
    lowerHex32(input.requestNonce, 'Desktop engine-session request nonce', false),
    uint64(input.session.generation, 'Desktop engine generation', 1),
    uint64(input.session.pid, 'Desktop engine pid', 1),
    uint32(input.session.port, 'Desktop engine port', 1024, 65_535),
    Buffer.from(input.capability, 'ascii'),
    uint32(input.status, 'Desktop engine-session response status', 100, 599),
    lowerHex32(input.bodySha256, 'Desktop engine-session response body digest'),
    lowerHex32(input.contractSha256, 'Desktop engine-session response contract digest')
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
    throw fail('invalid_engine_session_headers', 'Desktop engine-session headers are malformed')
  }
  const parsed: ParsedRawHeader[] = []
  for (let index = 0; index < rawHeaders.length; index += 2) {
    const name = rawHeaders[index]
    const value = rawHeaders[index + 1]
    if (
      typeof name !== 'string' ||
      !HEADER_NAME.test(name) ||
      typeof value !== 'string' ||
      value.length === 0 ||
      value !== value.trim() ||
      /[^\x20-\x7e]/.test(value)
    ) {
      throw fail('invalid_engine_session_headers', 'Desktop engine-session headers are malformed')
    }
    parsed.push(Object.freeze({ lowerName: name.toLowerCase(), value }))
  }
  return Object.freeze(parsed)
}

function extractRequestSessionHeaders(
  rawHeaders: readonly string[]
): Readonly<Record<string, string>> {
  const requiredNames = new Map(
    REQUEST_SESSION_HEADERS.map((name) => [name.toLowerCase(), name])
  )
  const observed = new Map(
    REQUEST_SESSION_HEADERS.map((name) => [name.toLowerCase(), [] as string[]])
  )
  for (const { lowerName, value } of parseRawHeaders(rawHeaders)) {
    if (!lowerName.startsWith(SESSION_HEADER_PREFIX)) continue
    if (value.includes(',')) {
      throw fail(
        'ambiguous_engine_session_header',
        'Desktop engine-session header is comma-combined'
      )
    }
    if (!ALL_SESSION_HEADER_NAMES.has(lowerName)) {
      throw fail('unknown_engine_session_header', 'Unknown Desktop engine-session header')
    }
    if (!requiredNames.has(lowerName)) {
      throw fail(
        'wrong_engine_session_header_direction',
        'Desktop engine-session header is used in the wrong direction'
      )
    }
    observed.get(lowerName)?.push(value)
  }
  const result: Record<string, string> = {}
  for (const [lowerName, canonicalName] of requiredNames) {
    const values = observed.get(lowerName)
    if (!values || values.length !== 1) {
      throw fail(
        'ambiguous_engine_session_header',
        'Desktop engine-session header is missing or duplicate'
      )
    }
    result[canonicalName] = values[0]
  }
  return Object.freeze(result)
}

function extractResponseSessionHeaders(
  rawHeaders: readonly string[]
): Readonly<Record<string, string>> {
  const requiredNames = new Map(
    RESPONSE_SESSION_HEADERS.map((name) => [name.toLowerCase(), name])
  )
  const observed = new Map(
    RESPONSE_SESSION_HEADERS.map((name) => [name.toLowerCase(), [] as string[]])
  )
  for (const { lowerName, value } of parseRawHeaders(rawHeaders)) {
    if (!lowerName.startsWith(SESSION_HEADER_PREFIX)) continue
    if (value.includes(',')) {
      throw fail(
        'ambiguous_engine_session_header',
        'Desktop engine-session header is comma-combined'
      )
    }
    if (!ALL_SESSION_HEADER_NAMES.has(lowerName)) {
      throw fail('unknown_engine_session_header', 'Unknown Desktop engine-session header')
    }
    if (!requiredNames.has(lowerName)) {
      throw fail(
        'wrong_engine_session_header_direction',
        'Desktop engine-session header is used in the wrong direction'
      )
    }
    observed.get(lowerName)?.push(value)
  }
  const result: Record<string, string> = {}
  for (const [lowerName, canonicalName] of requiredNames) {
    const values = observed.get(lowerName)
    if (!values || values.length !== 1) {
      throw fail(
        'ambiguous_engine_session_header',
        'Desktop engine-session header is missing or duplicate'
      )
    }
    result[canonicalName] = values[0]
  }
  return Object.freeze(result)
}

function requestContractFrame(rawHeaders: readonly string[]): Buffer {
  const observed = new Map<string, string[]>()
  for (const { lowerName, value } of parseRawHeaders(rawHeaders)) {
    if (lowerName.startsWith(SESSION_HEADER_PREFIX)) continue
    const values = observed.get(lowerName) ?? []
    values.push(value)
    observed.set(lowerName, values)
  }
  const names = [...observed.keys()].sort((left, right) =>
    Buffer.compare(Buffer.from(left, 'ascii'), Buffer.from(right, 'ascii'))
  )
  const fields: Buffer[] = []
  for (const name of names) {
    const values = observed.get(name) ?? []
    if (values.length !== 1) {
      throw fail(
        'ambiguous_engine_session_request_contract_header',
        'Desktop request contract header is duplicate'
      )
    }
    fields.push(Buffer.from(name, 'ascii'), Buffer.from(values[0], 'ascii'))
  }
  return frame(REQUEST_CONTRACT_DOMAIN, fields)
}

export function desktopEngineSessionRequestContractSha256(
  rawHeaders: readonly string[]
): string {
  return createHash('sha256').update(requestContractFrame(rawHeaders)).digest('hex')
}

function responseContractFrame(rawHeaders: readonly string[]): Buffer {
  const observed = new Map<string, string[]>()
  for (const { lowerName, value } of parseRawHeaders(rawHeaders)) {
    if (lowerName.startsWith(SESSION_HEADER_PREFIX)) continue
    const values = observed.get(lowerName) ?? []
    values.push(value)
    observed.set(lowerName, values)
  }
  const names = [...observed.keys()].sort((left, right) =>
    Buffer.compare(Buffer.from(left, 'ascii'), Buffer.from(right, 'ascii'))
  )
  const fields: Buffer[] = []
  for (const name of names) {
    const values = observed.get(name) ?? []
    if (values.length !== 1) {
      throw fail(
        'ambiguous_engine_session_response_contract_header',
        'Desktop response contract header is duplicate'
      )
    }
    if (UNSIGNED_TRANSPORT_RESPONSE_HEADERS.has(name)) continue
    fields.push(Buffer.from(name, 'ascii'), Buffer.from(values[0], 'ascii'))
  }
  return frame(RESPONSE_CONTRACT_DOMAIN, fields)
}

export function desktopEngineSessionResponseContractSha256(
  rawHeaders: readonly string[]
): string {
  return createHash('sha256').update(responseContractFrame(rawHeaders)).digest('hex')
}

export function deriveDesktopEngineSessionKey(bootToken: unknown): Buffer {
  const key = lowerHex32(bootToken, 'Desktop engine boot token', false)
  return createHmac('sha256', key)
    .update(DESKTOP_ENGINE_SESSION_DOMAINS.key, 'ascii')
    .digest()
}

export function signDesktopEngineSessionRequest(input: {
  session: DesktopEngineSessionIdentity
  timestampMs: number
  nonce: string
  channelNonce: string
  capability: string
  method: string
  target: string
  bodySha256: string
  rawHeaders: readonly string[]
}): DesktopEngineSessionSignedRequest {
  const session = validatedSession(input.session)
  uint64(input.timestampMs, 'Desktop engine-session timestamp', 1)
  const nonce = lowerHex32(input.nonce, 'Desktop engine-session nonce', false).toString('hex')
  const channelNonce = lowerHex32(
    input.channelNonce,
    'Desktop engine-session channel nonce'
  ).toString('hex')
  const capability = validatedCapability(input.capability)
  const method = validatedMethod(input.method)
  const target = validatedTarget(input.target)
  const bodySha256 = lowerHex32(
    input.bodySha256,
    'Desktop engine-session body digest'
  ).toString('hex')
  const contractSha256 = desktopEngineSessionRequestContractSha256(input.rawHeaders)
  const signature = createHmac('sha256', deriveDesktopEngineSessionKey(session.bootToken))
    .update(
      requestMacInput({
        timestampMs: input.timestampMs,
        nonce,
        channelNonce,
        session,
        capability,
        method,
        target,
        bodySha256,
        contractSha256
      })
    )
    .digest('hex')
  return Object.freeze({
    headers: Object.freeze({
      [DESKTOP_ENGINE_SESSION_HEADERS.protocol]: DESKTOP_ENGINE_SESSION_VERSION,
      [DESKTOP_ENGINE_SESSION_HEADERS.timestampMs]: String(input.timestampMs),
      [DESKTOP_ENGINE_SESSION_HEADERS.nonce]: nonce,
      [DESKTOP_ENGINE_SESSION_HEADERS.channelNonce]: channelNonce,
      [DESKTOP_ENGINE_SESSION_HEADERS.generation]: canonicalDecimal(
        session.generation,
        'Desktop engine generation',
        1
      ),
      [DESKTOP_ENGINE_SESSION_HEADERS.pid]: canonicalDecimal(
        session.pid,
        'Desktop engine pid',
        1
      ),
      [DESKTOP_ENGINE_SESSION_HEADERS.port]: String(session.port),
      [DESKTOP_ENGINE_SESSION_HEADERS.capability]: capability,
      [DESKTOP_ENGINE_SESSION_HEADERS.bodySha256]: bodySha256,
      [DESKTOP_ENGINE_SESSION_HEADERS.requestContractSha256]: contractSha256,
      [DESKTOP_ENGINE_SESSION_HEADERS.signature]: signature
    }),
    timestampMs: input.timestampMs,
    nonce,
    channelNonce,
    capability,
    bodySha256,
    contractSha256,
    signature
  })
}

export function verifyDesktopEngineSessionRequest(input: {
  session: DesktopEngineSessionIdentity
  rawHeaders: readonly string[]
  nowMs: number
  maxPastMs?: number
  maxFutureMs?: number
  capability: string
  method: string
  target: string
  bodySha256: string
}): DesktopEngineSessionVerifiedRequest {
  const session = validatedSession(input.session)
  const headers = extractRequestSessionHeaders(input.rawHeaders)
  if (headers[DESKTOP_ENGINE_SESSION_HEADERS.protocol] !== DESKTOP_ENGINE_SESSION_VERSION) {
    throw fail('unsupported_engine_session_protocol', 'Desktop engine-session version is invalid')
  }
  const timestampMs = parsedCanonicalDecimal(
    headers[DESKTOP_ENGINE_SESSION_HEADERS.timestampMs],
    'Desktop engine-session timestamp',
    1
  )
  uint64(input.nowMs, 'Desktop engine-session clock', 1)
  const maxPastMs = input.maxPastMs ?? DESKTOP_ENGINE_SESSION_MAX_PAST_MS
  const maxFutureMs = input.maxFutureMs ?? DESKTOP_ENGINE_SESSION_MAX_FUTURE_MS
  if (
    !Number.isSafeInteger(maxPastMs) ||
    !Number.isSafeInteger(maxFutureMs) ||
    maxPastMs < 0 ||
    maxFutureMs < 0 ||
    maxPastMs + maxFutureMs > MAX_CLOCK_WINDOW_MS
  ) {
    throw fail('invalid_engine_session_input', 'Desktop engine-session time window is invalid')
  }
  if (
    (timestampMs <= input.nowMs && input.nowMs - timestampMs > maxPastMs) ||
    (timestampMs > input.nowMs && timestampMs - input.nowMs > maxFutureMs)
  ) {
    throw fail('expired_engine_session_request', 'Desktop engine-session request is expired')
  }
  const nonce = lowerHex32(
    headers[DESKTOP_ENGINE_SESSION_HEADERS.nonce],
    'Desktop engine-session nonce',
    false
  ).toString('hex')
  const channelNonce = lowerHex32(
    headers[DESKTOP_ENGINE_SESSION_HEADERS.channelNonce],
    'Desktop engine-session channel nonce'
  ).toString('hex')
  const generation = parsedCanonicalDecimal(
    headers[DESKTOP_ENGINE_SESSION_HEADERS.generation],
    'Desktop engine generation',
    1
  )
  const pid = parsedCanonicalDecimal(
    headers[DESKTOP_ENGINE_SESSION_HEADERS.pid],
    'Desktop engine pid',
    1
  )
  const port = parsedCanonicalDecimal(
    headers[DESKTOP_ENGINE_SESSION_HEADERS.port],
    'Desktop engine port',
    1024,
    65_535
  )
  if (generation !== session.generation || pid !== session.pid || port !== session.port) {
    throw fail('engine_session_mismatch', 'Desktop engine-session identity does not match')
  }
  const capability = validatedCapability(input.capability)
  const method = validatedMethod(input.method)
  const target = validatedTarget(input.target)
  const bodySha256 = lowerHex32(
    input.bodySha256,
    'Desktop engine-session body digest'
  ).toString('hex')
  const claimedCapability = headers[DESKTOP_ENGINE_SESSION_HEADERS.capability]
  const claimedBodySha256 = headers[DESKTOP_ENGINE_SESSION_HEADERS.bodySha256]
  const claimedContractSha256 =
    headers[DESKTOP_ENGINE_SESSION_HEADERS.requestContractSha256]
  const claimedSignature = headers[DESKTOP_ENGINE_SESSION_HEADERS.signature]
  const contractSha256 = desktopEngineSessionRequestContractSha256(input.rawHeaders)
  const expectedSignature = createHmac(
    'sha256',
    deriveDesktopEngineSessionKey(session.bootToken)
  )
    .update(
      requestMacInput({
        timestampMs,
        nonce,
        channelNonce,
        session: { ...session, generation, pid, port },
        capability: claimedCapability,
        method,
        target,
        bodySha256,
        contractSha256
      })
    )
    .digest('hex')
  if (
    claimedCapability !== capability ||
    !exactHexEqual(claimedBodySha256, bodySha256) ||
    !exactHexEqual(claimedContractSha256, contractSha256) ||
    !exactHexEqual(claimedSignature, expectedSignature)
  ) {
    throw fail('engine_session_authentication_failed', 'Desktop engine-session authentication failed')
  }
  return Object.freeze({
    timestampMs,
    nonce,
    channelNonce,
    generation,
    pid,
    port,
    capability,
    bodySha256,
    contractSha256
  })
}

export function signDesktopEngineSessionResponse(input: {
  session: DesktopEngineSessionIdentity
  requestNonce: string
  capability: string
  status: number
  bodySha256: string
  rawHeaders: readonly string[]
}): DesktopEngineSessionSignedResponse {
  const session = validatedSession(input.session)
  const requestNonce = lowerHex32(
    input.requestNonce,
    'Desktop engine-session request nonce',
    false
  ).toString('hex')
  const capability = validatedCapability(input.capability)
  uint32(input.status, 'Desktop engine-session response status', 100, 599)
  const bodySha256 = lowerHex32(
    input.bodySha256,
    'Desktop engine-session response body digest'
  ).toString('hex')
  const contractSha256 = desktopEngineSessionResponseContractSha256(input.rawHeaders)
  const signature = createHmac('sha256', deriveDesktopEngineSessionKey(session.bootToken))
    .update(
      responseMacInput({
        requestNonce,
        session,
        capability,
        status: input.status,
        bodySha256,
        contractSha256
      })
    )
    .digest('hex')
  return Object.freeze({
    headers: Object.freeze({
      [DESKTOP_ENGINE_SESSION_HEADERS.protocol]: DESKTOP_ENGINE_SESSION_VERSION,
      [DESKTOP_ENGINE_SESSION_HEADERS.requestNonce]: requestNonce,
      [DESKTOP_ENGINE_SESSION_HEADERS.generation]: String(session.generation),
      [DESKTOP_ENGINE_SESSION_HEADERS.pid]: String(session.pid),
      [DESKTOP_ENGINE_SESSION_HEADERS.port]: String(session.port),
      [DESKTOP_ENGINE_SESSION_HEADERS.capability]: capability,
      [DESKTOP_ENGINE_SESSION_HEADERS.responseBodySha256]: bodySha256,
      [DESKTOP_ENGINE_SESSION_HEADERS.responseContractSha256]: contractSha256,
      [DESKTOP_ENGINE_SESSION_HEADERS.responseSignature]: signature
    }),
    requestNonce,
    capability,
    bodySha256,
    contractSha256,
    signature
  })
}

export function verifyDesktopEngineSessionResponse(input: {
  session: DesktopEngineSessionIdentity
  requestNonce: string
  capability: string
  status: number
  bodySha256: string
  rawHeaders: readonly string[]
}): DesktopEngineSessionVerifiedResponse {
  const session = validatedSession(input.session)
  const expectedRequestNonce = lowerHex32(
    input.requestNonce,
    'Desktop engine-session request nonce',
    false
  ).toString('hex')
  const expectedCapability = validatedCapability(input.capability)
  uint32(input.status, 'Desktop engine-session response status', 100, 599)
  const bodySha256 = lowerHex32(
    input.bodySha256,
    'Desktop engine-session response body digest'
  ).toString('hex')
  const headers = extractResponseSessionHeaders(input.rawHeaders)
  if (headers[DESKTOP_ENGINE_SESSION_HEADERS.protocol] !== DESKTOP_ENGINE_SESSION_VERSION) {
    throw fail('unsupported_engine_session_protocol', 'Desktop engine-session version is invalid')
  }
  const requestNonce = headers[DESKTOP_ENGINE_SESSION_HEADERS.requestNonce]
  const generation = parsedCanonicalDecimal(
    headers[DESKTOP_ENGINE_SESSION_HEADERS.generation],
    'Desktop engine generation',
    1
  )
  const pid = parsedCanonicalDecimal(
    headers[DESKTOP_ENGINE_SESSION_HEADERS.pid],
    'Desktop engine pid',
    1
  )
  const port = parsedCanonicalDecimal(
    headers[DESKTOP_ENGINE_SESSION_HEADERS.port],
    'Desktop engine port',
    1024,
    65_535
  )
  const capability = headers[DESKTOP_ENGINE_SESSION_HEADERS.capability]
  const declaredBodySha256 = headers[DESKTOP_ENGINE_SESSION_HEADERS.responseBodySha256]
  const claimedContractSha256 =
    headers[DESKTOP_ENGINE_SESSION_HEADERS.responseContractSha256]
  const claimedSignature = headers[DESKTOP_ENGINE_SESSION_HEADERS.responseSignature]
  const contractSha256 = desktopEngineSessionResponseContractSha256(input.rawHeaders)
  const expectedSignature = createHmac(
    'sha256',
    deriveDesktopEngineSessionKey(session.bootToken)
  )
    .update(
      responseMacInput({
        requestNonce,
        session: { ...session, generation, pid, port },
        capability,
        status: input.status,
        bodySha256: declaredBodySha256,
        contractSha256
      })
    )
    .digest('hex')
  if (
    !exactHexEqual(requestNonce, expectedRequestNonce) ||
    generation !== session.generation ||
    pid !== session.pid ||
    port !== session.port ||
    capability !== expectedCapability ||
    !exactHexEqual(declaredBodySha256, bodySha256) ||
    !exactHexEqual(claimedContractSha256, contractSha256) ||
    !exactHexEqual(claimedSignature, expectedSignature)
  ) {
    throw fail('engine_session_authentication_failed', 'Desktop engine-session response failed authentication')
  }
  return Object.freeze({
    requestNonce,
    generation,
    pid,
    port,
    capability,
    status: input.status,
    declaredBodySha256,
    contractSha256
  })
}
