import { isIP } from 'node:net'

export interface OfflineBlockedEvent {
  readonly url: string
  readonly sessionName: string
  readonly tsMs: number
  readonly reason: string
}

export interface WebRequestBeforeRequestDetails {
  readonly url: string
}

export interface WebRequestBeforeRequestResponse {
  cancel?: boolean
}

export type WebRequestBeforeRequestListener = (
  details: WebRequestBeforeRequestDetails,
  callback: (response: WebRequestBeforeRequestResponse) => void
) => void

export interface WebRequestLikeSession {
  readonly webRequest: {
    onBeforeRequest(listener: WebRequestBeforeRequestListener | null): void
  }
}

export class OfflineModeError extends Error {
  override readonly name = 'OfflineModeError'
  readonly code = 'OFFLINE_MODE_BLOCKED'

  constructor(message = 'Offline air-gap mode is enabled; external network access is blocked') {
    super(message)
  }
}

const MAX_RECENT_BLOCKED = 200
const LOCAL_ONLY_SCHEMES = new Set([
  'file:',
  'data:',
  'blob:',
  'devtools:',
  'nachuan-paid-media:'
])
const NETWORK_SCHEMES = new Set(['http:', 'https:', 'ws:', 'wss:'])
const CANONICAL_IPV4_LOOPBACK =
  /^127\.(?:0|[1-9]\d{0,2})\.(?:0|[1-9]\d{0,2})\.(?:0|[1-9]\d{0,2})$/

function isCanonicalLoopbackIpv4(hostname: string): boolean {
  if (!CANONICAL_IPV4_LOOPBACK.test(hostname)) return false
  const octets = hostname.split('.').map(Number)
  return octets.length === 4 && octets.every((octet) => Number.isInteger(octet) && octet >= 0 && octet <= 255)
}

function isLoopbackHostname(rawHostname: string): boolean {
  const normalized = rawHostname.trim().replace(/^\[|\]$/g, '').replace(/\.$/, '').toLowerCase()
  if (!normalized) return false
  if (normalized === 'localhost') return true
  if (normalized === '::1' || normalized === '0:0:0:0:0:0:0:1') return true
  if (normalized === '127.0.0.1' || normalized === '127.77.77.77') return true
  if (isIP(normalized) === 4 && isCanonicalLoopbackIpv4(normalized)) return true
  return false
}

/**
 * 判断 URL 是否为本地或回环地址（纯离线空气间隙模式下唯一允许放行的目标）。
 * 明确放行：127.0.0.1、localhost、[::1]、127.77.77.77（及规范 127.x.x.x 回环段）、
 * file:、data:、blob:、about:blank、devtools:、nachuan-paid-media:。
 */
export function isLoopbackOrLocalUrl(rawUrl: string): boolean {
  if (typeof rawUrl !== 'string') return false
  const trimmed = rawUrl.trim()
  if (!trimmed) return false
  if (trimmed === 'about:blank') return true

  let parsed: URL
  try {
    parsed = new URL(trimmed)
  } catch {
    return false
  }

  const protocol = parsed.protocol.toLowerCase()
  if (protocol === 'about:') {
    return parsed.pathname.toLowerCase() === 'blank' && !parsed.hostname
  }
  if (LOCAL_ONLY_SCHEMES.has(protocol)) {
    return true
  }
  if (!NETWORK_SCHEMES.has(protocol)) {
    return false
  }
  if (!parsed.hostname) return false
  return isLoopbackHostname(parsed.hostname)
}

export class OfflineGuard {
  private enabled = false
  private blockedCount = 0
  private readonly recentBlocked: OfflineBlockedEvent[] = []
  private readonly listeners = new Set<(enabled: boolean) => void>()

  constructor(initialEnabled = false) {
    this.enabled = Boolean(initialEnabled)
  }

  isEnabled(): boolean {
    return this.enabled
  }

  setEnabled(enabled: boolean): boolean {
    const next = Boolean(enabled)
    if (this.enabled === next) return this.enabled
    this.enabled = next
    for (const listener of this.listeners) {
      try {
        listener(next)
      } catch {
        // 订阅者异常不应影响离线态切换生效
      }
    }
    return this.enabled
  }

  subscribe(listener: (enabled: boolean) => void): () => void {
    this.listeners.add(listener)
    return () => {
      this.listeners.delete(listener)
    }
  }

  shouldBlockUrl(url: string): boolean {
    return this.enabled && !isLoopbackOrLocalUrl(url)
  }

  assertOutboundAllowed(url: string, caller = 'main'): void {
    if (!this.shouldBlockUrl(url)) return
    this.recordBlocked(url, caller, 'air_gap_offline_mode')
    throw new OfflineModeError(
      `Offline air-gap mode is enabled; blocked external request from ${caller}`
    )
  }

  attachToSession(
    targetSession: WebRequestLikeSession,
    sessionName: string,
    onBlocked?: (event: OfflineBlockedEvent) => void
  ): () => void {
    const listener: WebRequestBeforeRequestListener = (details, callback) => {
      if (!this.shouldBlockUrl(details.url)) {
        callback({ cancel: false })
        return
      }
      const event = this.recordBlocked(details.url, sessionName, 'air_gap_offline_mode')
      onBlocked?.(event)
      callback({ cancel: true })
    }
    targetSession.webRequest.onBeforeRequest(listener)
    return () => {
      targetSession.webRequest.onBeforeRequest(null)
    }
  }

  getBlockedCount(): number {
    return this.blockedCount
  }

  getRecentBlocked(): readonly OfflineBlockedEvent[] {
    return this.recentBlocked.slice()
  }

  resetMetrics(): void {
    this.blockedCount = 0
    this.recentBlocked.length = 0
  }

  private recordBlocked(url: string, sessionName: string, reason: string): OfflineBlockedEvent {
    this.blockedCount += 1
    const event: OfflineBlockedEvent = Object.freeze({
      url,
      sessionName,
      tsMs: Date.now(),
      reason
    })
    this.recentBlocked.push(event)
    if (this.recentBlocked.length > MAX_RECENT_BLOCKED) {
      this.recentBlocked.splice(0, this.recentBlocked.length - MAX_RECENT_BLOCKED)
    }
    return event
  }
}

export const desktopOfflineGuard = new OfflineGuard(
  process.env['NACHUAN_OFFLINE_MODE'] === '1' ||
    process.env['NACHUAN_OFFLINE_MODE']?.toLowerCase() === 'true'
)

export function isDesktopOfflineModeEnabled(): boolean {
  return desktopOfflineGuard.isEnabled()
}

export function setDesktopOfflineModeEnabled(enabled: boolean): boolean {
  return desktopOfflineGuard.setEnabled(enabled)
}

export function assertDesktopOutboundAllowed(url: string, caller = 'main'): void {
  desktopOfflineGuard.assertOutboundAllowed(url, caller)
}

export function attachOfflineGuardToSession(
  targetSession: WebRequestLikeSession,
  sessionName: string,
  onBlocked?: (event: OfflineBlockedEvent) => void
): () => void {
  return desktopOfflineGuard.attachToSession(targetSession, sessionName, onBlocked)
}
