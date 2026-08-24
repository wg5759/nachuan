import { lookup as dnsLookup } from 'node:dns/promises'
import { randomBytes } from 'node:crypto'
import { createWriteStream } from 'node:fs'
import { rename, rm, writeFile } from 'node:fs/promises'
import { request as httpRequest } from 'node:http'
import { request as httpsRequest } from 'node:https'
import { isIP, type LookupFunction } from 'node:net'
import { basename, dirname, join } from 'node:path'
import { Transform, type TransformCallback } from 'node:stream'
import { pipeline } from 'node:stream/promises'

export const MAX_INLINE_MEDIA_BYTES = 32 * 1024 * 1024
export const MAX_REMOTE_MEDIA_BYTES = 512 * 1024 * 1024
const MAX_URL_LENGTH = 4096
const MAX_REDIRECTS = 4
const IDLE_TIMEOUT_MS = 30_000
const TOTAL_TIMEOUT_MS = 10 * 60_000

type AddressAnswer = { address: string; family: number }
type AddressResolver = (
  hostname: string,
  options: { all: true; verbatim: true }
) => Promise<AddressAnswer[]>

export type PublicMediaTarget = {
  url: URL
  address: string
  family: 4 | 6
}

const LOCAL_NAME = /(?:^|\.)(?:localhost|local|internal|home|lan)$/i

function publicIpv4(address: string): boolean {
  const parts = address.split('.').map(Number)
  if (
    parts.length !== 4 ||
    parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)
  ) {
    return false
  }
  const [a, b, c] = parts
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false
  if (a === 100 && b >= 64 && b <= 127) return false
  if (a === 169 && b === 254) return false
  if (a === 172 && b >= 16 && b <= 31) return false
  if (a === 192 && b === 168) return false
  if (a === 192 && b === 0 && c === 0) return false
  if (a === 192 && b === 0 && c === 2) return false
  if (a === 192 && b === 88 && c === 99) return false
  if (a === 198 && (b === 18 || b === 19)) return false
  if (a === 198 && b === 51 && c === 100) return false
  if (a === 203 && b === 0 && c === 113) return false
  return true
}

function publicIpv6(address: string): boolean {
  const normalized = address.toLowerCase().split('%', 1)[0]
  if (!normalized || normalized.startsWith('::') || normalized.includes('.')) return false
  const first = Number.parseInt(normalized.split(':', 1)[0], 16)
  // Routable unicast assigned by IANA is currently within 2000::/3.  Keeping
  // this narrow also rejects ULA, link-local, multicast, documentation, NAT64,
  // IPv4-mapped and other special-use forms without an incomplete deny-list.
  if (!Number.isInteger(first) || first < 0x2000 || first > 0x3fff) return false
  return !normalized.startsWith('2001:db8:')
}

export function isPublicMediaAddress(address: string): boolean {
  const family = isIP(address.split('%', 1)[0])
  if (family === 4) return publicIpv4(address)
  if (family === 6) return publicIpv6(address)
  return false
}

function parseMediaUrl(raw: string): URL {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > MAX_URL_LENGTH) {
    throw new Error('media URL is missing or too long')
  }
  let url: URL
  try {
    url = new URL(raw)
  } catch {
    throw new Error('media URL is invalid')
  }
  if ((url.protocol !== 'https:' && url.protocol !== 'http:') || !url.hostname) {
    throw new Error('media URL must use HTTP or HTTPS')
  }
  if (url.username || url.password) throw new Error('media URL credentials are forbidden')
  // Non-default ports add a public port-scanning primitive and are not needed
  // by any supported media provider.
  if (url.port) throw new Error('media URL must use the default port')
  const hostname = url.hostname.replace(/^\[|\]$/g, '').replace(/\.$/, '').toLowerCase()
  if (!hostname || hostname.length > 253 || LOCAL_NAME.test(hostname)) {
    throw new Error('media URL hostname is forbidden')
  }
  url.hash = ''
  return url
}

function remainingBudget(deadline: number): number {
  const remaining = Math.floor(deadline - Date.now())
  if (remaining <= 0) throw new Error('media download total timeout')
  return remaining
}

async function withinDeadline<T>(promise: Promise<T>, deadline: number, label: string): Promise<T> {
  const timeout = remainingBudget(deadline)
  let timer: NodeJS.Timeout | undefined
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error(label)), timeout)
      })
    ])
  } finally {
    if (timer) clearTimeout(timer)
  }
}

export async function resolvePublicMediaTarget(
  raw: string,
  resolver: AddressResolver = dnsLookup as AddressResolver,
  deadline = Date.now() + IDLE_TIMEOUT_MS
): Promise<PublicMediaTarget> {
  const url = parseMediaUrl(raw)
  const hostname = url.hostname.replace(/^\[|\]$/g, '').replace(/\.$/, '').toLowerCase()
  const literalFamily = isIP(hostname)
  let answers: AddressAnswer[]
  if (literalFamily) {
    answers = [{ address: hostname, family: literalFamily }]
  } else {
    // Packed/octal/numeric-only hostnames are intentionally rejected rather
    // than relying on platform-specific legacy parsing.
    if (!/[a-z]/i.test(hostname)) throw new Error('numeric media hostname is forbidden')
    answers = await withinDeadline(
      resolver(hostname, { all: true, verbatim: true }),
      deadline,
      'media DNS resolution timeout'
    )
  }
  if (!answers.length || answers.some((answer) => !isPublicMediaAddress(answer.address))) {
    throw new Error('media URL did not resolve exclusively to public addresses')
  }
  const selected = answers.find((answer) => answer.family === 4 || answer.family === 6)
  if (!selected || (selected.family !== 4 && selected.family !== 6)) {
    throw new Error('media URL has no supported public address')
  }
  return { url, address: selected.address, family: selected.family }
}

function allowedMediaContentType(raw: string | string[] | undefined): boolean {
  if (raw === undefined) return true
  const value = (Array.isArray(raw) ? raw[0] || '' : raw).split(';', 1)[0].trim().toLowerCase()
  return (
    value.startsWith('image/') ||
    value.startsWith('video/') ||
    value.startsWith('audio/') ||
    value === 'application/octet-stream' ||
    value === 'application/mp4' ||
    value === 'binary/octet-stream'
  )
}

function parseContentLength(raw: string | string[] | undefined): number | null {
  if (typeof raw !== 'string' || !/^\d+$/.test(raw)) return null
  const value = Number(raw)
  return Number.isSafeInteger(value) && value >= 0 ? value : null
}

type DownloadAttempt = { redirect: string } | { bytes: number }

export class MediaByteLimitTransform extends Transform {
  bytes = 0

  constructor(private readonly maxBytes: number) {
    super()
  }

  override _transform(chunk: Buffer, _encoding: BufferEncoding, callback: TransformCallback): void {
    this.bytes += chunk.length
    if (this.bytes > this.maxBytes) callback(new Error('remote media exceeds the size limit'))
    else callback(null, chunk)
  }
}

async function downloadAttempt(
  target: PublicMediaTarget,
  temporaryPath: string,
  maxBytes: number,
  deadline: number
): Promise<DownloadAttempt> {
  const totalBudget = remainingBudget(deadline)
  const lookup: LookupFunction = ((
    _hostname: string,
    _options: unknown,
    callback: (error: Error | null, address: string, family: number) => void
  ) => {
    callback(null, target.address, target.family)
  }) as LookupFunction
  const request = target.url.protocol === 'https:' ? httpsRequest : httpRequest

  return await new Promise<DownloadAttempt>((resolve, reject) => {
    let settled = false
    let totalTimer: NodeJS.Timeout | undefined
    const finish = (error: Error | null, result?: DownloadAttempt): void => {
      if (settled) return
      settled = true
      if (totalTimer) clearTimeout(totalTimer)
      if (error) reject(error)
      else resolve(result as DownloadAttempt)
    }
    const req = request(
      target.url,
      {
        method: 'GET',
        agent: false,
        lookup,
        headers: {
          Accept: 'image/*, video/*, audio/*, application/octet-stream;q=0.8',
          'User-Agent': 'Nachuan-Desktop/0.1 media-save'
        }
      },
      (response) => {
        const status = response.statusCode || 0
        if ([301, 302, 303, 307, 308].includes(status)) {
          const location = response.headers.location
          response.destroy()
          if (!location) {
            finish(new Error('media redirect is missing Location'))
            return
          }
          let redirect: URL
          try {
            redirect = new URL(location, target.url)
          } catch {
            finish(new Error('media redirect URL is invalid'))
            return
          }
          if (target.url.protocol === 'https:' && redirect.protocol !== 'https:') {
            finish(new Error('media redirect may not downgrade HTTPS'))
            return
          }
          finish(null, { redirect: redirect.toString() })
          return
        }
        if (status !== 200) {
          response.destroy()
          finish(new Error(`media server returned HTTP ${status}`))
          return
        }
        if (!allowedMediaContentType(response.headers['content-type'])) {
          response.destroy()
          finish(new Error('remote response is not a supported media type'))
          return
        }
        const contentLength = parseContentLength(response.headers['content-length'])
        if (contentLength !== null && contentLength > maxBytes) {
          response.destroy()
          finish(new Error('remote media exceeds the size limit'))
          return
        }
        const limiter = new MediaByteLimitTransform(maxBytes)
        const output = createWriteStream(temporaryPath, { flags: 'wx', mode: 0o600 })
        void pipeline(response, limiter, output).then(
          () => finish(null, { bytes: limiter.bytes }),
          (error: unknown) =>
            finish(error instanceof Error ? error : new Error('media download failed'))
        )
      }
    )
    req.setTimeout(IDLE_TIMEOUT_MS, () => req.destroy(new Error('media download idle timeout')))
    req.once('error', (error) => finish(error))
    totalTimer = setTimeout(
      () => req.destroy(new Error('media download total timeout')),
      totalBudget
    )
    totalTimer.unref()
    req.end()
  })
}

function temporarySibling(destination: string): string {
  const suffix = `${process.pid}-${Date.now()}-${randomBytes(8).toString('hex')}`
  return join(dirname(destination), `.${basename(destination)}.nachuan-${suffix}.tmp`)
}

export async function writeBoundedMediaBytes(
  destination: string,
  bytes: ArrayBuffer,
  maxBytes = MAX_INLINE_MEDIA_BYTES
): Promise<number> {
  if (!(bytes instanceof ArrayBuffer) || bytes.byteLength <= 0 || bytes.byteLength > maxBytes) {
    throw new Error('inline media is empty or exceeds the size limit')
  }
  const temporaryPath = temporarySibling(destination)
  try {
    await writeFile(temporaryPath, Buffer.from(bytes), { flag: 'wx', mode: 0o600 })
    await rename(temporaryPath, destination)
    return bytes.byteLength
  } finally {
    await rm(temporaryPath, { force: true }).catch(() => undefined)
  }
}

export async function downloadPublicMedia(
  rawUrl: string,
  destination: string,
  maxBytes = MAX_REMOTE_MEDIA_BYTES,
  dependencies: {
    resolver?: AddressResolver
    attempt?: (
      target: PublicMediaTarget,
      temporaryPath: string,
      maxBytes: number,
      deadline: number
    ) => Promise<DownloadAttempt>
    totalTimeoutMs?: number
  } = {}
): Promise<number> {
  const boundedMax = Math.max(1, Math.min(Math.floor(maxBytes), MAX_REMOTE_MEDIA_BYTES))
  const totalTimeout = Math.max(
    1,
    Math.min(Math.floor(dependencies.totalTimeoutMs ?? TOTAL_TIMEOUT_MS), TOTAL_TIMEOUT_MS)
  )
  const deadline = Date.now() + totalTimeout
  const resolver = dependencies.resolver ?? (dnsLookup as AddressResolver)
  const attemptDownload = dependencies.attempt ?? downloadAttempt
  const temporaryPath = temporarySibling(destination)
  let current = rawUrl
  const visited = new Set<string>()
  try {
    for (let redirects = 0; redirects <= MAX_REDIRECTS; redirects += 1) {
      const target = await resolvePublicMediaTarget(current, resolver, deadline)
      const canonical = target.url.toString()
      if (visited.has(canonical)) throw new Error('media redirect loop detected')
      visited.add(canonical)
      const attempt = await attemptDownload(target, temporaryPath, boundedMax, deadline)
      if ('redirect' in attempt) {
        current = attempt.redirect
        continue
      }
      await rename(temporaryPath, destination)
      return attempt.bytes
    }
    throw new Error('media redirect limit exceeded')
  } finally {
    await rm(temporaryPath, { force: true }).catch(() => undefined)
  }
}
