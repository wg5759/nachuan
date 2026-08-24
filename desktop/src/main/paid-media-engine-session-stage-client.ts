import { createHash, timingSafeEqual } from 'node:crypto'

import type {
  InstallationRootEngineSession,
  InstallationRootSessionSupplier
} from './installation-root-client'
import type {
  PaidMediaEngineSessionClient,
  PaidMediaEngineSessionConsumed,
  PaidMediaEngineSessionResponse
} from './paid-media-engine-session-client'

export const PAID_MEDIA_ENGINE_SESSION_STAGE_READY_PATH =
  '/internal/v1/paid-media/session/stage-ready'

const REQUEST_SCHEMA = 'nachuan.paid-media.engine-session.stage-ready.v1'
const RECEIPT_SCHEMA = 'nachuan.paid-media.engine-session.stage-ready.receipt.v1'
const SHA256 = /^[0-9a-f]{64}$/
const ZERO_DIGEST = '0'.repeat(64)
const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/
const CANONICAL_LENGTH = /^(0|[1-9][0-9]*)$/
const RESPONSE_LIMIT = 512
const DEFAULT_TIMEOUT_MS = 5_000
const MAX_TIMEOUT_MS = 10_000
const FORBIDDEN_RESPONSE_HEADERS = [
  'content-encoding',
  'transfer-encoding',
  'content-range',
  'location',
  'trailer',
  'upgrade'
] as const

type HeaderMap = ReadonlyMap<string, readonly string[]>

export class PaidMediaEngineSessionStageClientError extends Error {
  override readonly name = 'PaidMediaEngineSessionStageClientError'
}

export interface PaidMediaEngineSessionStageBinding {
  readonly installationPrincipal: string
  readonly vaultEvidenceSha256: string
}

function fail(message: string): PaidMediaEngineSessionStageClientError {
  return new PaidMediaEngineSessionStageClientError(message)
}

function digest(value: unknown): value is string {
  return typeof value === 'string' && SHA256.test(value) && value !== ZERO_DIGEST
}

function validSession(value: unknown): InstallationRootEngineSession {
  const candidate = value as InstallationRootEngineSession
  if (
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    !Number.isSafeInteger(candidate.generation) ||
    candidate.generation < 1 ||
    !Number.isSafeInteger(candidate.pid) ||
    candidate.pid < 1 ||
    !Number.isSafeInteger(candidate.port) ||
    candidate.port < 1_024 ||
    candidate.port > 65_535 ||
    !digest(candidate.bootToken)
  ) {
    throw fail('Paid media engine session is unavailable')
  }
  return Object.freeze({
    generation: candidate.generation,
    pid: candidate.pid,
    port: candidate.port,
    bootToken: candidate.bootToken
  })
}

function sameSession(
  left: InstallationRootEngineSession,
  right: InstallationRootEngineSession
): boolean {
  return (
    left.generation === right.generation &&
    left.pid === right.pid &&
    left.port === right.port &&
    left.bootToken === right.bootToken
  )
}

function readSession(supplier: InstallationRootSessionSupplier): InstallationRootEngineSession {
  try {
    return validSession(supplier())
  } catch {
    throw fail('Paid media engine session is unavailable')
  }
}

function timeout(value: unknown): number {
  const normalized = value === undefined ? DEFAULT_TIMEOUT_MS : value
  if (
    !Number.isSafeInteger(normalized) ||
    Number(normalized) < 1_000 ||
    Number(normalized) > MAX_TIMEOUT_MS
  ) {
    throw fail('Paid media stage-ready timeout is invalid')
  }
  return Number(normalized)
}

function parseRawHeaders(rawHeaders: readonly string[]): HeaderMap {
  if (!Array.isArray(rawHeaders) || rawHeaders.length % 2 !== 0) {
    throw fail('Paid media stage-ready response headers are malformed')
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
      throw fail('Paid media stage-ready response headers are malformed')
    }
    const normalized = name.toLowerCase()
    const observed = headers.get(normalized) ?? []
    observed.push(value)
    headers.set(normalized, observed)
  }
  return headers
}

function singleton(headers: HeaderMap, name: string): string {
  const values = headers.get(name.toLowerCase()) ?? []
  if (values.length !== 1 || values[0]!.includes(',')) {
    throw fail(`Paid media stage-ready response has ambiguous ${name}`)
  }
  return values[0]!
}

function responseLength(response: PaidMediaEngineSessionResponse): number {
  const headers = parseRawHeaders(response.rawHeaders)
  for (const name of FORBIDDEN_RESPONSE_HEADERS) {
    if ((headers.get(name) ?? []).length !== 0) {
      throw fail(`Paid media stage-ready response contains forbidden ${name}`)
    }
  }
  if (
    singleton(headers, 'content-type') !== 'application/json' ||
    singleton(headers, 'cache-control') !== 'no-store' ||
    singleton(headers, 'connection') !== 'close'
  ) {
    throw fail('Paid media stage-ready response metadata is invalid')
  }
  const rawLength = singleton(headers, 'content-length')
  if (!CANONICAL_LENGTH.test(rawLength)) {
    throw fail('Paid media stage-ready response Content-Length is invalid')
  }
  const length = Number(rawLength)
  if (!Number.isSafeInteger(length) || length < 2 || length > RESPONSE_LIMIT) {
    response.response.destroy()
    throw fail('Paid media stage-ready response exceeds its size limit')
  }
  return length
}

async function consumeResponse(
  response: PaidMediaEngineSessionResponse
): Promise<PaidMediaEngineSessionConsumed<{ status: number; body: Buffer }>> {
  const expectedLength = responseLength(response)
  const body = Buffer.allocUnsafe(expectedLength)
  const bodyDigest = createHash('sha256')
  let offset = 0
  for await (const raw of response.response) {
    const bytes = Buffer.isBuffer(raw) ? raw : Buffer.from(raw)
    if (offset + bytes.length > expectedLength) {
      response.response.destroy()
      throw fail('Paid media stage-ready response exceeded its declared length')
    }
    bytes.copy(body, offset)
    bodyDigest.update(bytes)
    offset += bytes.length
  }
  if (offset !== expectedLength || response.response.rawTrailers.length !== 0) {
    throw fail('Paid media stage-ready response framing is invalid')
  }
  return {
    value: { status: response.status, body },
    bodySha256: bodyDigest.digest('hex')
  }
}

function canonicalRequest(
  session: InstallationRootEngineSession,
  binding: PaidMediaEngineSessionStageBinding
): Buffer {
  return Buffer.from(
    JSON.stringify({
      schema: REQUEST_SCHEMA,
      generation: session.generation,
      pid: session.pid,
      port: session.port,
      installationPrincipal: binding.installationPrincipal,
      vaultEvidenceSha256: binding.vaultEvidenceSha256
    }),
    'ascii'
  )
}

function canonicalReceipt(binding: PaidMediaEngineSessionStageBinding): Buffer {
  return Buffer.from(
    JSON.stringify({
      schema: RECEIPT_SCHEMA,
      ok: true,
      vaultEvidenceSha256: binding.vaultEvidenceSha256
    }),
    'ascii'
  )
}

/**
 * Publish one boot-local Desktop Main attestation after local Root/evidence and
 * stage-recovery checks have completed. Gateway cannot independently read the
 * Desktop Vault; the HMAC-authenticated boot session is the attester, while
 * Gateway independently checks the Installation Root principal.
 *
 * This helper intentionally has no startup side effect. Main must not call it
 * until its Root mutation runner has resolved every stage recovery disposition.
 */
export async function activatePaidMediaEngineSessionStage(input: {
  readonly session: InstallationRootSessionSupplier
  readonly sessionClient: Pick<PaidMediaEngineSessionClient, 'exchange'>
  readonly installationPrincipal: string
  readonly vaultEvidenceSha256: string
  readonly signal: AbortSignal
  readonly timeoutMs?: number
}): Promise<PaidMediaEngineSessionStageBinding> {
  if (
    !input ||
    typeof input !== 'object' ||
    typeof input.session !== 'function' ||
    !input.sessionClient ||
    typeof input.sessionClient.exchange !== 'function' ||
    !digest(input.installationPrincipal) ||
    !digest(input.vaultEvidenceSha256) ||
    !input.signal ||
    typeof input.signal.aborted !== 'boolean'
  ) {
    throw fail('Paid media stage-ready input is invalid')
  }
  const captured = readSession(input.session)
  const binding = Object.freeze({
    installationPrincipal: input.installationPrincipal,
    vaultEvidenceSha256: input.vaultEvidenceSha256
  })
  const requestBody = canonicalRequest(captured, binding)
  const totalTimeoutMs = timeout(input.timeoutMs)
  let result: { status: number; body: Buffer }
  try {
    result = await input.sessionClient.exchange(
      {
        method: 'POST',
        target: PAID_MEDIA_ENGINE_SESSION_STAGE_READY_PATH,
        headers: {
          Accept: 'application/json',
          'Accept-Encoding': 'identity',
          'Cache-Control': 'no-store',
          'Content-Type': 'application/json',
          'X-Nachuan-Paid-Media-Protocol': '2'
        },
        body: requestBody,
        signal: input.signal,
        totalTimeoutMs,
        firstByteTimeoutMs: totalTimeoutMs
      },
      consumeResponse
    )
  } catch (error) {
    if (error instanceof PaidMediaEngineSessionStageClientError) {
      throw fail('Paid media stage-ready exchange did not complete safely')
    }
    void error
    throw fail('Paid media stage-ready exchange did not complete safely')
  }
  const current = readSession(input.session)
  if (!sameSession(captured, current)) {
    throw fail('Paid media engine session changed across stage-ready exchange')
  }
  const expected = canonicalReceipt(binding)
  if (
    result.status !== 200 ||
    result.body.length !== expected.length ||
    !timingSafeEqual(result.body, expected)
  ) {
    throw fail('Paid media stage-ready receipt is invalid')
  }
  return binding
}
