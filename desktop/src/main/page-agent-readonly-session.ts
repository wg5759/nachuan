import { randomBytes as systemRandomBytes, randomUUID as systemRandomUUID } from 'node:crypto'
import { performance } from 'node:perf_hooks'
import { types as utilTypes } from 'node:util'

// Pure Main-process policy only: this module does not create Electron sessions,
// inspect a DOM, load Page Agent, navigate, or execute any browser action.

export interface PageAgentReadonlyWebPreferences {
  readonly sandbox: true
  readonly contextIsolation: true
  readonly webSecurity: true
  readonly allowRunningInsecureContent: false
  readonly disableDialogs: true
  readonly navigateOnDragDrop: false
  readonly spellcheck: false
  readonly nodeIntegration: false
  readonly webviewTag: false
  readonly devTools: false
}

export interface PageAgentReadonlySessionSpec {
  readonly sessionId: string
  readonly partition: string
  readonly webPreferences: PageAgentReadonlyWebPreferences
}

export interface PageAgentReadonlySessionPolicyOptions {
  readonly now?: () => number
  readonly randomBytes?: (size: number) => Uint8Array
  readonly randomUUID?: () => string
  readonly maxCapabilities?: number
  readonly maxExecutionLeases?: number
  readonly maxElementHandles?: number
  readonly maxElementHandlesPerSession?: number
  readonly maxLiveSessions?: number
  readonly maxSessionCreations?: number
}

export type PageAgentReadonlyAction = 'inspect' | 'scroll'

export interface PageAgentReadonlyDomSnapshotBinding {
  readonly sessionId: string
  readonly webContentsId: number
  readonly origin: string
  readonly navigationEpoch: number
  readonly domSha256: string
}

export interface PageAgentReadonlyElementHandleMintRequest
  extends PageAgentReadonlyDomSnapshotBinding {
  readonly elementIdentitySha256: string
}

export interface PageAgentReadonlyCapabilityScope extends PageAgentReadonlyDomSnapshotBinding {
  readonly elementHandle: string
  readonly action: PageAgentReadonlyAction
  readonly valueSha256: string
}

export interface PageAgentReadonlyCapabilityBinding extends PageAgentReadonlyCapabilityScope {
  readonly expiresAtMs: number
}

export interface PageAgentReadonlyIssuedCapability {
  readonly token: string
  readonly expiresAtMs: number
}

export interface PageAgentReadonlyExecutionLease {
  readonly signal: AbortSignal
  assertCurrent(): boolean
  close(): boolean
}

interface PageAgentReadonlyActiveExecution {
  readonly binding: PageAgentReadonlyCapabilityBinding
  readonly controller: AbortController
}

const WEB_PREFERENCES: PageAgentReadonlyWebPreferences = Object.freeze({
  sandbox: true,
  contextIsolation: true,
  webSecurity: true,
  allowRunningInsecureContent: false,
  disableDialogs: true,
  navigateOnDragDrop: false,
  spellcheck: false,
  nodeIntegration: false,
  webviewTag: false,
  devTools: false
})

const SESSION_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const SHA256_PATTERN = /^[0-9a-f]{64}$/
export const PAGE_AGENT_EMPTY_PAYLOAD_SHA256 =
  'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
const MAX_CAPABILITIES_HARD = 4_096
const MAX_EXECUTION_LEASES_HARD = 4_096
const MAX_CAPABILITY_TTL_MS = 30_000
const MAX_ELEMENT_HANDLES_HARD = 4_096
const MAX_ELEMENT_HANDLES_PER_SESSION_HARD = 512
const MAX_LIVE_SESSIONS_HARD = 64
const MAX_SESSION_CREATIONS_HARD = 4_096
const CAPABILITY_SCOPE_KEYS = [
  'sessionId',
  'webContentsId',
  'origin',
  'navigationEpoch',
  'domSha256',
  'elementHandle',
  'action',
  'valueSha256'
] as const
const DOM_SNAPSHOT_KEYS = [
  'sessionId',
  'webContentsId',
  'origin',
  'navigationEpoch',
  'domSha256'
] as const
const ELEMENT_HANDLE_MINT_KEYS = [...DOM_SNAPSHOT_KEYS, 'elementIdentitySha256'] as const
const OPAQUE_ELEMENT_HANDLE_PATTERN = /^el_[A-Za-z0-9_-]{43}$/
const CAPABILITY_TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/
const TYPED_ARRAY_PROTOTYPE = Object.getPrototypeOf(Uint8Array.prototype) as object
const TYPED_ARRAY_BUFFER_GETTER = Object.getOwnPropertyDescriptor(
  TYPED_ARRAY_PROTOTYPE,
  'buffer'
)?.get
const TYPED_ARRAY_BYTE_OFFSET_GETTER = Object.getOwnPropertyDescriptor(
  TYPED_ARRAY_PROTOTYPE,
  'byteOffset'
)?.get
const TYPED_ARRAY_BYTE_LENGTH_GETTER = Object.getOwnPropertyDescriptor(
  TYPED_ARRAY_PROTOTYPE,
  'byteLength'
)?.get

function monotonicNowMs(): number {
  return Math.floor(performance.now())
}

function assertPositiveSafeInteger(value: unknown, name: string): number {
  if (!Number.isSafeInteger(value) || Number(value) <= 0) {
    throw new Error(`${name} must be a positive safe integer`)
  }
  return Number(value)
}

function assertExactRecord(value: unknown, expectedKeys: readonly string[], name: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`${name} must be an exact object`)
  }
  if (utilTypes.isProxy(value)) {
    throw new Error(`${name} must not be a Proxy`)
  }
  const prototype = Object.getPrototypeOf(value)
  if (prototype !== Object.prototype && prototype !== null) {
    throw new Error(`${name} must be a plain object`)
  }
  const keys = Reflect.ownKeys(value)
  if (
    keys.length !== expectedKeys.length ||
    keys.some((key) => typeof key !== 'string' || !expectedKeys.includes(key))
  ) {
    throw new Error(`${name} has unexpected fields`)
  }
  const normalized = Object.create(null) as Record<string, unknown>
  for (const key of expectedKeys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key)
    if (!descriptor || !descriptor.enumerable || !('value' in descriptor)) {
      throw new Error(`${name} fields must be enumerable data properties`)
    }
    normalized[key] = descriptor.value
  }
  return Object.freeze(normalized)
}

function assertExactHttpsOrigin(value: unknown): string {
  if (typeof value !== 'string') throw new Error('origin must be an exact HTTPS origin')
  let parsed: URL
  try {
    parsed = new URL(value)
  } catch {
    throw new Error('origin must be an exact HTTPS origin')
  }
  if (parsed.protocol !== 'https:' || parsed.origin !== value || parsed.username || parsed.password) {
    throw new Error('origin must be an exact HTTPS origin')
  }
  return value
}

function assertElementHandle(value: unknown): string {
  if (typeof value !== 'string' || !OPAQUE_ELEMENT_HANDLE_PATTERN.test(value)) {
    throw new Error('elementHandle must be a fixed opaque element handle')
  }
  return value
}

function copyTrustedRandomBytes(value: unknown, errorMessage: string): Buffer {
  if (
    utilTypes.isProxy(value) ||
    !utilTypes.isUint8Array(value) ||
    !TYPED_ARRAY_BUFFER_GETTER ||
    !TYPED_ARRAY_BYTE_OFFSET_GETTER ||
    !TYPED_ARRAY_BYTE_LENGTH_GETTER
  ) {
    throw new Error(errorMessage)
  }
  try {
    const backingBuffer: unknown = TYPED_ARRAY_BUFFER_GETTER.call(value)
    const byteOffset: unknown = TYPED_ARRAY_BYTE_OFFSET_GETTER.call(value)
    const byteLength: unknown = TYPED_ARRAY_BYTE_LENGTH_GETTER.call(value)
    if (
      utilTypes.isSharedArrayBuffer(backingBuffer) ||
      !utilTypes.isArrayBuffer(backingBuffer) ||
      !Number.isSafeInteger(byteOffset) ||
      Number(byteOffset) < 0 ||
      byteLength !== 32
    ) {
      throw new Error(errorMessage)
    }
    const trustedView = Buffer.from(backingBuffer, Number(byteOffset), 32)
    const copiedBytes = Buffer.from(trustedView)
    if (copiedBytes.byteLength !== 32) throw new Error(errorMessage)
    return copiedBytes
  } catch {
    throw new Error(errorMessage)
  }
}

export class PageAgentReadonlySessionPolicy {
  private readonly now: () => number
  private readonly randomBytes: (size: number) => Uint8Array
  private readonly randomUUID: () => string
  private readonly maxCapabilities: number
  private readonly maxExecutionLeases: number
  private readonly maxElementHandles: number
  private readonly maxElementHandlesPerSession: number
  private readonly maxLiveSessions: number
  private readonly maxSessionCreations: number
  private readonly sessions = new Set<string>()
  private readonly usedSessionIds = new Set<string>()
  private readonly usedWebContentsIds = new Set<number>()
  private readonly webContentsBindings = new Map<string, number>()
  private readonly navigationEpochs = new Map<string, number>()
  private readonly capabilities = new Map<string, PageAgentReadonlyCapabilityBinding>()
  private readonly activeExecutions = new Map<object, PageAgentReadonlyActiveExecution>()
  private readonly elementHandles = new Map<string, PageAgentReadonlyElementHandleMintRequest>()
  private readonly currentSnapshots = new Map<string, PageAgentReadonlyDomSnapshotBinding>()
  private lastClockMs: number | null = null
  private mutationInProgress = false

  constructor(options: PageAgentReadonlySessionPolicyOptions = {}) {
    this.now = options.now ?? monotonicNowMs
    this.randomBytes = options.randomBytes ?? systemRandomBytes
    this.randomUUID = options.randomUUID ?? systemRandomUUID
    this.maxCapabilities = options.maxCapabilities ?? 128
    this.maxExecutionLeases = options.maxExecutionLeases ?? 64
    this.maxElementHandles = options.maxElementHandles ?? 512
    this.maxElementHandlesPerSession =
      options.maxElementHandlesPerSession ?? Math.min(128, this.maxElementHandles)
    this.maxLiveSessions = options.maxLiveSessions ?? 16
    this.maxSessionCreations = options.maxSessionCreations ?? 1_024
    assertPositiveSafeInteger(this.maxCapabilities, 'maxCapabilities')
    assertPositiveSafeInteger(this.maxExecutionLeases, 'maxExecutionLeases')
    assertPositiveSafeInteger(this.maxElementHandles, 'maxElementHandles')
    assertPositiveSafeInteger(this.maxElementHandlesPerSession, 'maxElementHandlesPerSession')
    assertPositiveSafeInteger(this.maxLiveSessions, 'maxLiveSessions')
    assertPositiveSafeInteger(this.maxSessionCreations, 'maxSessionCreations')
    if (this.maxCapabilities > MAX_CAPABILITIES_HARD) {
      throw new Error('maxCapabilities exceeds the hard maximum')
    }
    if (this.maxExecutionLeases > MAX_EXECUTION_LEASES_HARD) {
      throw new Error('maxExecutionLeases exceeds the hard maximum')
    }
    if (this.maxElementHandles > MAX_ELEMENT_HANDLES_HARD) {
      throw new Error('maxElementHandles exceeds the hard maximum')
    }
    if (this.maxElementHandlesPerSession > MAX_ELEMENT_HANDLES_PER_SESSION_HARD) {
      throw new Error('maxElementHandlesPerSession exceeds the hard maximum')
    }
    if (this.maxElementHandlesPerSession > this.maxElementHandles) {
      throw new Error('maxElementHandlesPerSession cannot exceed maxElementHandles')
    }
    if (this.maxLiveSessions > MAX_LIVE_SESSIONS_HARD) {
      throw new Error('maxLiveSessions exceeds the hard maximum')
    }
    if (this.maxSessionCreations > MAX_SESSION_CREATIONS_HARD) {
      throw new Error('maxSessionCreations exceeds the hard maximum')
    }
    if (this.maxLiveSessions > this.maxSessionCreations) {
      throw new Error('maxLiveSessions cannot exceed maxSessionCreations')
    }
  }

  createSession(): PageAgentReadonlySessionSpec {
    this.enterMutation()
    try {
      if (this.sessions.size >= this.maxLiveSessions) {
        throw new Error('Page Agent live session capacity is exhausted')
      }
      if (this.usedSessionIds.size >= this.maxSessionCreations) {
        throw new Error('Page Agent lifetime session capacity is exhausted')
      }
      const sessionId: unknown = this.randomUUID()
      if (
        typeof sessionId !== 'string' ||
        !SESSION_ID_PATTERN.test(sessionId) ||
        this.usedSessionIds.has(sessionId)
      ) {
        throw new Error('Page Agent session identity is invalid or not unique')
      }
      this.usedSessionIds.add(sessionId)
      this.sessions.add(sessionId)
      return Object.freeze({
        sessionId,
        partition: `nachuan-page-agent-readonly-${sessionId}`,
        webPreferences: WEB_PREFERENCES
      })
    } finally {
      this.leaveMutation()
    }
  }

  assertAction(action: unknown): PageAgentReadonlyAction {
    if (action !== 'inspect' && action !== 'scroll') {
      throw new Error('Page Agent read-only action is not allowed')
    }
    return action
  }

  bindWebContents(sessionIdValue: unknown, webContentsIdValue: unknown): void {
    this.enterMutation()
    try {
      if (typeof sessionIdValue !== 'string' || !this.sessions.has(sessionIdValue)) {
        throw new Error('Page Agent session is not open')
      }
      const webContentsId = assertPositiveSafeInteger(webContentsIdValue, 'webContentsId')
      if (this.webContentsBindings.has(sessionIdValue)) {
        throw new Error('Page Agent session is already bound to a WebContents identity')
      }
      if (this.usedWebContentsIds.has(webContentsId)) {
        throw new Error('Page Agent WebContents identity was already used by another session')
      }
      this.usedWebContentsIds.add(webContentsId)
      this.webContentsBindings.set(sessionIdValue, webContentsId)
      this.navigationEpochs.set(sessionIdValue, 0)
    } finally {
      this.leaveMutation()
    }
  }

  beginNavigation(sessionIdValue: unknown, webContentsIdValue: unknown): number {
    this.enterMutation()
    try {
      if (typeof sessionIdValue !== 'string' || !this.sessions.has(sessionIdValue)) {
        throw new Error('Page Agent session is not open')
      }
      const webContentsId = assertPositiveSafeInteger(webContentsIdValue, 'webContentsId')
      if (this.webContentsBindings.get(sessionIdValue) !== webContentsId) {
        throw new Error('Page Agent bound WebContents identity does not match')
      }
      const currentEpoch = this.navigationEpochs.get(sessionIdValue)
      if (currentEpoch === undefined || currentEpoch >= Number.MAX_SAFE_INTEGER) {
        throw new Error('Page Agent navigation epoch is unavailable or exhausted')
      }
      const nextEpoch = currentEpoch + 1
      this.navigationEpochs.set(sessionIdValue, nextEpoch)
      this.revokeWebContentsAuthority(sessionIdValue, webContentsId)
      this.abortActiveExecutions(sessionIdValue, webContentsId)
      return nextEpoch
    } finally {
      this.leaveMutation()
    }
  }

  mintElementHandle(snapshotValue: unknown): string {
    this.enterMutation()
    try {
      const request = this.parseElementHandleMintRequest(snapshotValue)
      if (!this.sessions.has(request.sessionId)) {
        throw new Error('Page Agent session is not open')
      }
      if (this.webContentsBindings.get(request.sessionId) !== request.webContentsId) {
        throw new Error('Page Agent bound WebContents identity does not match')
      }
      if (this.navigationEpochs.get(request.sessionId) !== request.navigationEpoch) {
        throw new Error('Page Agent current navigation epoch does not match')
      }
      const snapshotKey = this.domSnapshotKey(request)
      const currentSnapshot = this.currentSnapshots.get(snapshotKey)
      const advancesSnapshot = currentSnapshot
        ? this.assertSnapshotTransition(currentSnapshot, request)
        : true
      const obsoleteHandles = advancesSnapshot
        ? [...this.elementHandles.entries()]
            .filter(([, handle]) => this.domSnapshotKey(handle) === snapshotKey)
            .map(([elementHandle]) => elementHandle)
        : []
      const obsoleteHandleSet = new Set(obsoleteHandles)
      const projectedGlobalCount = this.elementHandles.size - obsoleteHandles.length
      const projectedSessionCount = [...this.elementHandles.entries()].filter(
        ([elementHandle, handle]) =>
          handle.sessionId === request.sessionId && !obsoleteHandleSet.has(elementHandle)
      ).length
      if (projectedGlobalCount >= this.maxElementHandles) {
        throw new Error('Page Agent element handle capacity is exhausted')
      }
      if (projectedSessionCount >= this.maxElementHandlesPerSession) {
        throw new Error('Page Agent per-session element handle capacity is exhausted')
      }
      const copiedHandleBytes = copyTrustedRandomBytes(
        this.randomBytes(32),
        'Page Agent element handle randomness is invalid'
      )
      const elementHandle = `el_${copiedHandleBytes.toString('base64url')}`
      if (!OPAQUE_ELEMENT_HANDLE_PATTERN.test(elementHandle) || this.elementHandles.has(elementHandle)) {
        throw new Error('Page Agent opaque element handle is not unique')
      }
      if (!this.sessions.has(request.sessionId)) {
        throw new Error('Page Agent session closed while minting an element handle')
      }
      if (this.elementHandles.size - obsoleteHandles.length >= this.maxElementHandles) {
        throw new Error('Page Agent element handle capacity changed while minting')
      }
      const finalSessionCount = [...this.elementHandles.entries()].filter(
        ([registeredHandle, handle]) =>
          handle.sessionId === request.sessionId && !obsoleteHandleSet.has(registeredHandle)
      ).length
      if (finalSessionCount >= this.maxElementHandlesPerSession) {
        throw new Error('Page Agent per-session element handle capacity changed while minting')
      }
      if (advancesSnapshot) {
        for (const obsoleteHandle of obsoleteHandles) this.elementHandles.delete(obsoleteHandle)
        for (const [token, capability] of this.capabilities) {
          if (
            capability.sessionId === request.sessionId &&
            capability.webContentsId === request.webContentsId
          ) {
            this.capabilities.delete(token)
          }
        }
        this.currentSnapshots.set(snapshotKey, this.snapshotFrom(request))
      }
      this.elementHandles.set(elementHandle, request)
      return elementHandle
    } finally {
      this.leaveMutation()
    }
  }

  issueCapability(scopeValue: unknown, ttlMsValue: unknown): PageAgentReadonlyIssuedCapability {
    this.enterMutation()
    try {
      const scope = this.parseScope(scopeValue)
      const ttlMs = assertPositiveSafeInteger(ttlMsValue, 'capability TTL')
      if (ttlMs > MAX_CAPABILITY_TTL_MS) {
        throw new Error('Page Agent capability TTL exceeds its bound')
      }
      if (!this.sessions.has(scope.sessionId)) {
        throw new Error('Page Agent session is not open')
      }
      this.assertElementHandleAuthority(scope)

      const now = this.readClock()
      this.pruneExpiredCapabilities(now)
      if (this.capabilities.size >= this.maxCapabilities) {
        throw new Error('Page Agent capability capacity is exhausted')
      }
      const expiresAtMs = now + ttlMs
      if (!Number.isSafeInteger(expiresAtMs)) {
        throw new Error('Page Agent capability expiry is invalid')
      }
      const copiedTokenBytes = copyTrustedRandomBytes(
        this.randomBytes(32),
        'Page Agent capability randomness is invalid'
      )
      const token = copiedTokenBytes.toString('base64url')
      if (!CAPABILITY_TOKEN_PATTERN.test(token)) {
        throw new Error('Page Agent capability randomness is invalid')
      }
      if (!this.sessions.has(scope.sessionId)) {
        throw new Error('Page Agent session closed while issuing a capability')
      }
      if (this.capabilities.size >= this.maxCapabilities) {
        throw new Error('Page Agent capability capacity changed while issuing')
      }
      if (this.capabilities.has(token)) {
        throw new Error('Page Agent capability token is not unique')
      }
      this.capabilities.set(token, Object.freeze({ ...scope, expiresAtMs }))
      return Object.freeze({ token, expiresAtMs })
    } finally {
      this.leaveMutation()
    }
  }

  consumeCapability(tokenValue: unknown, bindingValue: unknown): boolean {
    if (!this.tryEnterMutation()) return false
    try {
      if (typeof tokenValue !== 'string') return false
      const record = this.capabilities.get(tokenValue)
      if (!record) return false

      // Once admitted by the non-reentrant guard, destruction deliberately
      // precedes parsing, clock access, and every binding check.
      this.capabilities.delete(tokenValue)
      const binding = this.parseBinding(bindingValue)
      this.assertElementHandleAuthority(binding)
      if (this.readClock() >= record.expiresAtMs || !this.sessions.has(record.sessionId)) return false
      return CAPABILITY_SCOPE_KEYS.every((key) => binding[key] === record[key]) &&
        binding.expiresAtMs === record.expiresAtMs
    } catch {
      return false
    } finally {
      this.leaveMutation()
    }
  }

  beginExecution(
    tokenValue: unknown,
    bindingValue: unknown
  ): PageAgentReadonlyExecutionLease | null {
    if (!this.tryEnterMutation()) return null
    try {
      if (typeof tokenValue !== 'string') return null
      const record = this.capabilities.get(tokenValue)
      if (!record) return null

      // The token is one-shot even when the supplied binding is malformed,
      // expired, stale, or otherwise rejected.
      this.capabilities.delete(tokenValue)
      const binding = this.parseBinding(bindingValue)
      this.assertElementHandleAuthority(binding)
      const now = this.readClock()
      if (now >= record.expiresAtMs || !this.sessions.has(record.sessionId)) return null
      if (
        !CAPABILITY_SCOPE_KEYS.every((key) => binding[key] === record[key]) ||
        binding.expiresAtMs !== record.expiresAtMs
      ) {
        return null
      }
      this.pruneExpiredExecutions(now)
      if (this.activeExecutions.size >= this.maxExecutionLeases) return null

      const leaseKey = Object.freeze({})
      const controller = new AbortController()
      this.activeExecutions.set(leaseKey, Object.freeze({ binding, controller }))
      return Object.freeze({
        signal: controller.signal,
        assertCurrent: (): boolean => this.isExecutionCurrent(leaseKey),
        close: (): boolean => this.closeExecution(leaseKey)
      })
    } catch {
      return null
    } finally {
      this.leaveMutation()
    }
  }

  closeSession(sessionIdValue: unknown): boolean {
    if (!this.tryEnterMutation()) return false
    try {
      if (typeof sessionIdValue !== 'string' || !this.sessions.delete(sessionIdValue)) return false
      const webContentsId = this.webContentsBindings.get(sessionIdValue)
      for (const [token, capability] of this.capabilities) {
        if (capability.sessionId === sessionIdValue) this.capabilities.delete(token)
      }
      for (const [elementHandle, snapshot] of this.elementHandles) {
        if (snapshot.sessionId === sessionIdValue) this.elementHandles.delete(elementHandle)
      }
      for (const [snapshotKey, snapshot] of this.currentSnapshots) {
        if (snapshot.sessionId === sessionIdValue) this.currentSnapshots.delete(snapshotKey)
      }
      this.webContentsBindings.delete(sessionIdValue)
      this.navigationEpochs.delete(sessionIdValue)
      if (webContentsId !== undefined) {
        this.abortActiveExecutions(sessionIdValue, webContentsId)
      }
      return true
    } finally {
      this.leaveMutation()
    }
  }

  /** Read-only view of the authoritative navigation epoch for an open session. */
  currentNavigationEpoch(sessionIdValue: unknown): number | null {
    if (typeof sessionIdValue !== 'string' || !this.sessions.has(sessionIdValue)) {
      return null
    }
    return this.navigationEpochs.get(sessionIdValue) ?? null
  }

  private parseScope(value: unknown): PageAgentReadonlyCapabilityScope {
    const record = assertExactRecord(value, CAPABILITY_SCOPE_KEYS, 'capability scope')
    if (typeof record.sessionId !== 'string' || !SESSION_ID_PATTERN.test(record.sessionId)) {
      throw new Error('sessionId is invalid')
    }
    if (typeof record.domSha256 !== 'string' || !SHA256_PATTERN.test(record.domSha256)) {
      throw new Error('domSha256 is invalid')
    }
    if (typeof record.valueSha256 !== 'string' || !SHA256_PATTERN.test(record.valueSha256)) {
      throw new Error('valueSha256 is invalid')
    }
    const action = this.assertAction(record.action)
    if (action === 'inspect' && record.valueSha256 !== PAGE_AGENT_EMPTY_PAYLOAD_SHA256) {
      throw new Error('inspect must bind the canonical empty payload digest')
    }
    if (action === 'scroll' && record.valueSha256 === PAGE_AGENT_EMPTY_PAYLOAD_SHA256) {
      throw new Error('scroll must bind a non-empty canonical payload digest')
    }
    return Object.freeze({
      sessionId: record.sessionId,
      webContentsId: assertPositiveSafeInteger(record.webContentsId, 'webContentsId'),
      origin: assertExactHttpsOrigin(record.origin),
      navigationEpoch: assertPositiveSafeInteger(record.navigationEpoch, 'navigationEpoch'),
      domSha256: record.domSha256,
      elementHandle: assertElementHandle(record.elementHandle),
      action,
      valueSha256: record.valueSha256
    })
  }

  private parseDomSnapshot(value: unknown): PageAgentReadonlyDomSnapshotBinding {
    const record = assertExactRecord(value, DOM_SNAPSHOT_KEYS, 'DOM snapshot binding')
    if (typeof record.sessionId !== 'string' || !SESSION_ID_PATTERN.test(record.sessionId)) {
      throw new Error('sessionId is invalid')
    }
    if (typeof record.domSha256 !== 'string' || !SHA256_PATTERN.test(record.domSha256)) {
      throw new Error('domSha256 is invalid')
    }
    return Object.freeze({
      sessionId: record.sessionId,
      webContentsId: assertPositiveSafeInteger(record.webContentsId, 'webContentsId'),
      origin: assertExactHttpsOrigin(record.origin),
      navigationEpoch: assertPositiveSafeInteger(record.navigationEpoch, 'navigationEpoch'),
      domSha256: record.domSha256
    })
  }

  private parseElementHandleMintRequest(value: unknown): PageAgentReadonlyElementHandleMintRequest {
    const record = assertExactRecord(value, ELEMENT_HANDLE_MINT_KEYS, 'element handle mint request')
    const snapshot = this.parseDomSnapshot(
      Object.fromEntries(DOM_SNAPSHOT_KEYS.map((key) => [key, record[key]]))
    )
    if (
      typeof record.elementIdentitySha256 !== 'string' ||
      !SHA256_PATTERN.test(record.elementIdentitySha256)
    ) {
      throw new Error('elementIdentitySha256 is invalid')
    }
    return Object.freeze({
      ...snapshot,
      elementIdentitySha256: record.elementIdentitySha256
    })
  }

  private parseBinding(value: unknown): PageAgentReadonlyCapabilityBinding {
    const record = assertExactRecord(
      value,
      [...CAPABILITY_SCOPE_KEYS, 'expiresAtMs'],
      'capability binding'
    )
    const scope = this.parseScope(
      Object.fromEntries(CAPABILITY_SCOPE_KEYS.map((key) => [key, record[key]]))
    )
    return Object.freeze({
      ...scope,
      expiresAtMs: assertPositiveSafeInteger(record.expiresAtMs, 'expiresAtMs')
    })
  }

  private readClock(): number {
    const value = this.now()
    if (!Number.isSafeInteger(value) || value < 0) {
      this.abortAllActiveExecutions()
      throw new Error('Page Agent capability clock is invalid')
    }
    if (this.lastClockMs !== null && value < this.lastClockMs) {
      this.abortAllActiveExecutions()
      throw new Error('Page Agent capability clock moved backwards')
    }
    this.lastClockMs = value
    return value
  }

  private pruneExpiredCapabilities(now: number): void {
    for (const [token, capability] of this.capabilities) {
      if (capability.expiresAtMs <= now || !this.sessions.has(capability.sessionId)) {
        this.capabilities.delete(token)
      }
    }
  }

  private assertElementHandleAuthority(scope: PageAgentReadonlyCapabilityScope): void {
    const currentSnapshot = this.currentSnapshots.get(this.domSnapshotKey(scope))
    if (
      !currentSnapshot ||
      DOM_SNAPSHOT_KEYS.some((key) => currentSnapshot[key] !== scope[key])
    ) {
      throw new Error('Page Agent current snapshot authority does not match')
    }
    const snapshot = this.elementHandles.get(scope.elementHandle)
    if (!snapshot) throw new Error('Page Agent opaque element handle is not registered')
    if (DOM_SNAPSHOT_KEYS.some((key) => snapshot[key] !== scope[key])) {
      throw new Error('Page Agent element handle snapshot binding does not match')
    }
  }

  private isExecutionCurrent(leaseKey: object): boolean {
    if (!this.tryEnterMutation()) return false
    try {
      const execution = this.activeExecutions.get(leaseKey)
      if (!execution) return false
      const { binding } = execution
      if (
        this.readClock() >= binding.expiresAtMs ||
        !this.sessions.has(binding.sessionId) ||
        this.webContentsBindings.get(binding.sessionId) !== binding.webContentsId ||
        this.navigationEpochs.get(binding.sessionId) !== binding.navigationEpoch
      ) {
        this.abortExecutionEntries([[leaseKey, execution]])
        return false
      }
      this.assertElementHandleAuthority(binding)
      return true
    } catch {
      const execution = this.activeExecutions.get(leaseKey)
      if (execution) this.abortExecutionEntries([[leaseKey, execution]])
      return false
    } finally {
      this.leaveMutation()
    }
  }

  private closeExecution(leaseKey: object): boolean {
    if (!this.tryEnterMutation()) return false
    try {
      const execution = this.activeExecutions.get(leaseKey)
      if (!execution) return false
      this.abortExecutionEntries([[leaseKey, execution]])
      return true
    } finally {
      this.leaveMutation()
    }
  }

  private assertSnapshotTransition(
    current: PageAgentReadonlyDomSnapshotBinding,
    next: PageAgentReadonlyDomSnapshotBinding
  ): boolean {
    if (next.navigationEpoch < current.navigationEpoch) {
      throw new Error('Page Agent DOM snapshot rollback is not allowed')
    }
    if (next.navigationEpoch === current.navigationEpoch) {
      if (next.origin !== current.origin || next.domSha256 !== current.domSha256) {
        throw new Error('Page Agent DOM snapshot fork is not allowed')
      }
      return false
    }
    return true
  }

  private domSnapshotKey(snapshot: PageAgentReadonlyDomSnapshotBinding): string {
    return `${snapshot.sessionId}:${snapshot.webContentsId}`
  }

  private snapshotFrom(
    snapshot: PageAgentReadonlyDomSnapshotBinding
  ): PageAgentReadonlyDomSnapshotBinding {
    return Object.freeze(
      Object.fromEntries(DOM_SNAPSHOT_KEYS.map((key) => [key, snapshot[key]]))
    ) as unknown as PageAgentReadonlyDomSnapshotBinding
  }

  private revokeWebContentsAuthority(sessionId: string, webContentsId: number): void {
    for (const [token, capability] of this.capabilities) {
      if (capability.sessionId === sessionId && capability.webContentsId === webContentsId) {
        this.capabilities.delete(token)
      }
    }
    for (const [elementHandle, snapshot] of this.elementHandles) {
      if (snapshot.sessionId === sessionId && snapshot.webContentsId === webContentsId) {
        this.elementHandles.delete(elementHandle)
      }
    }
    for (const [snapshotKey, snapshot] of this.currentSnapshots) {
      if (snapshot.sessionId === sessionId && snapshot.webContentsId === webContentsId) {
        this.currentSnapshots.delete(snapshotKey)
      }
    }
  }

  private abortActiveExecutions(sessionId: string, webContentsId: number): void {
    const executions = [...this.activeExecutions.entries()].filter(
      ([, execution]) =>
        execution.binding.sessionId === sessionId &&
        execution.binding.webContentsId === webContentsId
    )
    this.abortExecutionEntries(executions)
  }

  private pruneExpiredExecutions(now: number): void {
    this.abortExecutionEntries(
      [...this.activeExecutions.entries()].filter(
        ([, execution]) => execution.binding.expiresAtMs <= now
      )
    )
  }

  private abortAllActiveExecutions(): void {
    this.abortExecutionEntries([...this.activeExecutions.entries()])
  }

  private abortExecutionEntries(
    executions: ReadonlyArray<readonly [object, PageAgentReadonlyActiveExecution]>
  ): void {
    const removed: PageAgentReadonlyActiveExecution[] = []
    // Remove the complete matching set first so every synchronous abort
    // listener observes all retired executions as non-current.
    for (const [leaseKey, execution] of executions) {
      if (this.activeExecutions.get(leaseKey) !== execution) continue
      this.activeExecutions.delete(leaseKey)
      removed.push(execution)
    }
    for (const execution of removed) {
      try {
        execution.controller.abort()
      } catch {
        // The internal authority is already retired; listener failures cannot
        // resurrect it or prevent the remaining executions from being aborted.
      }
    }
  }

  private enterMutation(): void {
    if (!this.tryEnterMutation()) {
      throw new Error('Page Agent re-entrant mutation is not allowed')
    }
  }

  private tryEnterMutation(): boolean {
    if (this.mutationInProgress) return false
    this.mutationInProgress = true
    return true
  }

  private leaveMutation(): void {
    this.mutationInProgress = false
  }
}
