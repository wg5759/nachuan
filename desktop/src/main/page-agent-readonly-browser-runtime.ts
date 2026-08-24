import type {
  PageAgentReadonlySessionSpec,
  PageAgentReadonlyWebPreferences
} from './page-agent-readonly-session'
import { types as utilTypes } from 'node:util'

// Main-process lifecycle contract only.  The production Electron adapter and
// Page Agent itself are deliberately not wired here.

export interface PageAgentReadonlyBrowserPolicy {
  createSession(): PageAgentReadonlySessionSpec
  bindWebContents(sessionId: unknown, webContentsId: unknown): void
  beginNavigation(sessionId: unknown, webContentsId: unknown): number
  closeSession(sessionId: unknown): boolean
}

export interface PageAgentReadonlyNavigationEvent {
  preventDefault(): void
  readonly url?: string
  readonly isMainFrame?: boolean
}

export interface PageAgentReadonlyDownloadEvent {
  preventDefault(): void
}

export interface PageAgentReadonlyRequestDetails {
  readonly url: string
  readonly webContentsId?: number
}

type UnknownListener = (...args: unknown[]) => void

export interface PageAgentReadonlyBrowserWebContents {
  readonly id: number
  readonly session: PageAgentReadonlyBrowserSession
  on(event: string, listener: UnknownListener): void
  removeListener(event: string, listener: UnknownListener): void
  setWindowOpenHandler(
    handler: (details: Readonly<{ url: string }>) => Readonly<{ action: 'deny' }>
  ): void
  loadURL(url: string): Promise<void>
  stop(): void
  close(): void
}

export interface PageAgentReadonlyBrowserView {
  readonly webContents: PageAgentReadonlyBrowserWebContents
}

type PermissionRequestHandler = (...args: unknown[]) => void
type PermissionCheckHandler = (...args: unknown[]) => boolean
type BeforeRequestHandler = (
  details: PageAgentReadonlyRequestDetails,
  callback: (result: Readonly<{ cancel: boolean }>) => void
) => void

export interface PageAgentReadonlyBrowserSession {
  readonly storagePath: string | null
  readonly webRequest: {
    onBeforeRequest(
      filter: Readonly<{ urls: readonly string[] }>,
      listener: BeforeRequestHandler
    ): void
  }
  setPermissionRequestHandler(handler: PermissionRequestHandler): void
  setPermissionCheckHandler(handler: PermissionCheckHandler): void
  on(event: 'will-download', listener: (event: PageAgentReadonlyDownloadEvent) => void): void
  closeAllConnections(): Promise<void>
  clearData(): Promise<void>
  clearStorageData(): Promise<void>
  clearCache(): Promise<void>
  clearAuthCache(): Promise<void>
  clearHostResolverCache(): Promise<void>
}

export interface PageAgentReadonlyBrowserRuntimeOptions {
  readonly controlledOrigin: string
  readonly cleanupTimeoutMs?: number
  readonly loadTimeoutMs?: number
  readonly policy: PageAgentReadonlyBrowserPolicy
  readonly fromPartition: (
    partition: string,
    options: Readonly<{ cache: false }>
  ) => PageAgentReadonlyBrowserSession
  readonly createView: (options: Readonly<{
    session: PageAgentReadonlyBrowserSession
    webPreferences: PageAgentReadonlyWebPreferences
  }>) => PageAgentReadonlyBrowserView
  readonly attachView: (view: PageAgentReadonlyBrowserView) => void
  readonly detachView: (view: PageAgentReadonlyBrowserView) => void
}

type Lifecycle = 'new' | 'opening' | 'open' | 'closing' | 'closed'
type CleanupStageResult = Readonly<{ ok: boolean }>

const DEFAULT_CLEANUP_TIMEOUT_MS = 5_000
const MIN_CLEANUP_TIMEOUT_MS = 3
const MAX_CLEANUP_TIMEOUT_MS = 30_000
const DEFAULT_LOAD_TIMEOUT_MS = 30_000
const MIN_LOAD_TIMEOUT_MS = 3
const MAX_LOAD_TIMEOUT_MS = 120_000
const SESSION_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const LOCKED_WEB_PREFERENCES = Object.freeze({
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
}) satisfies PageAgentReadonlyWebPreferences

function validLockedWebPreferences(value: unknown): value is PageAgentReadonlyWebPreferences {
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    utilTypes.isProxy(value)
  ) {
    return false
  }
  const prototype = Object.getPrototypeOf(value)
  if (prototype !== Object.prototype && prototype !== null) return false
  const expectedKeys = Object.keys(LOCKED_WEB_PREFERENCES)
  const keys = Reflect.ownKeys(value)
  if (
    keys.length !== expectedKeys.length ||
    keys.some((key) => typeof key !== 'string' || !expectedKeys.includes(key))
  ) {
    return false
  }
  for (const key of expectedKeys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key)
    if (
      !descriptor ||
      !descriptor.enumerable ||
      !('value' in descriptor) ||
      descriptor.value !== LOCKED_WEB_PREFERENCES[key as keyof PageAgentReadonlyWebPreferences]
    ) {
      return false
    }
  }
  return true
}

function exactHttpsOrigin(value: unknown): string {
  if (typeof value !== 'string') {
    throw new Error('controlledOrigin must be an exact controlled HTTPS origin')
  }
  try {
    const parsed = new URL(value)
    if (
      parsed.protocol !== 'https:' ||
      parsed.origin !== value ||
      parsed.username ||
      parsed.password
    ) {
      throw new Error('invalid')
    }
    return value
  } catch {
    throw new Error('controlledOrigin must be an exact controlled HTTPS origin')
  }
}

function targetWithinOrigin(value: unknown, controlledOrigin: string): string {
  if (typeof value !== 'string') {
    throw new Error('target must stay within the exact controlled HTTPS origin')
  }
  try {
    const parsed = new URL(value)
    if (
      parsed.protocol !== 'https:' ||
      parsed.origin !== controlledOrigin ||
      parsed.username ||
      parsed.password
    ) {
      throw new Error('invalid')
    }
    return parsed.href
  } catch {
    throw new Error('target must stay within the exact controlled HTTPS origin')
  }
}

function validWebContentsId(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) > 0
}

function validEphemeralPartition(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= 256 &&
    !value.toLowerCase().startsWith('persist:') &&
    !value.includes('\0')
  )
}

export class PageAgentReadonlyBrowserRuntime {
  private readonly controlledOrigin: string
  private readonly policy: PageAgentReadonlyBrowserPolicy
  private readonly fromPartition: PageAgentReadonlyBrowserRuntimeOptions['fromPartition']
  private readonly createView: PageAgentReadonlyBrowserRuntimeOptions['createView']
  private readonly attachView: PageAgentReadonlyBrowserRuntimeOptions['attachView']
  private readonly detachView: PageAgentReadonlyBrowserRuntimeOptions['detachView']
  private readonly cleanupTimeoutMs: number
  private readonly loadTimeoutMs: number
  private lifecycle: Lifecycle = 'new'
  private spec: PageAgentReadonlySessionSpec | null = null
  private browserSession: PageAgentReadonlyBrowserSession | null = null
  private view: PageAgentReadonlyBrowserView | null = null
  private attachAttempted = false
  private policyBound = false
  private policyCloseAttempted = false
  private cleanupOk = true
  private closePromise: Promise<boolean> | null = null
  private navigationListeners: ReadonlyArray<readonly [string, UnknownListener]> = []

  constructor(options: PageAgentReadonlyBrowserRuntimeOptions) {
    this.controlledOrigin = exactHttpsOrigin(options.controlledOrigin)
    this.policy = options.policy
    this.fromPartition = options.fromPartition
    this.createView = options.createView
    this.attachView = options.attachView
    this.detachView = options.detachView
    this.cleanupTimeoutMs = options.cleanupTimeoutMs ?? DEFAULT_CLEANUP_TIMEOUT_MS
    if (
      !Number.isSafeInteger(this.cleanupTimeoutMs) ||
      this.cleanupTimeoutMs < MIN_CLEANUP_TIMEOUT_MS ||
      this.cleanupTimeoutMs > MAX_CLEANUP_TIMEOUT_MS
    ) {
      throw new Error('Page Agent browser cleanup timeout is invalid')
    }
    this.loadTimeoutMs = options.loadTimeoutMs ?? DEFAULT_LOAD_TIMEOUT_MS
    if (
      !Number.isSafeInteger(this.loadTimeoutMs) ||
      this.loadTimeoutMs < MIN_LOAD_TIMEOUT_MS ||
      this.loadTimeoutMs > MAX_LOAD_TIMEOUT_MS
    ) {
      throw new Error('Page Agent browser load timeout is invalid')
    }
  }

  async open(initialUrlValue: unknown): Promise<void> {
    const initialUrl = targetWithinOrigin(initialUrlValue, this.controlledOrigin)
    if (this.lifecycle !== 'new') throw new Error('Page Agent browser runtime is single-use')
    this.lifecycle = 'opening'
    try {
      const spec = this.policy.createSession()
      if (
        typeof spec?.sessionId !== 'string' ||
        !SESSION_ID_PATTERN.test(spec.sessionId) ||
        !validEphemeralPartition(spec?.partition) ||
        spec.partition !== `nachuan-page-agent-readonly-${spec.sessionId}`
      ) {
        throw new Error('Page Agent policy returned an invalid ephemeral session')
      }
      this.spec = spec
      if (!validLockedWebPreferences(spec.webPreferences)) {
        throw new Error('Page Agent policy returned invalid locked-down WebPreferences')
      }
      this.assertOpening()
      const browserSession = this.fromPartition(spec.partition, Object.freeze({ cache: false }))
      this.browserSession = browserSession
      this.assertOpening()
      if (browserSession?.storagePath !== null) {
        throw new Error('Page Agent browser requires a non-persistent in-memory session')
      }
      this.configureSession(browserSession)

      const view = this.createView({
        session: browserSession,
        webPreferences: spec.webPreferences
      })
      this.view = view
      this.assertOpening()
      if (!view?.webContents || !validWebContentsId(view.webContents.id)) {
        throw new Error('Page Agent browser view has an invalid WebContents identity')
      }
      if (view.webContents.session !== browserSession) {
        throw new Error('Page Agent browser view is not bound to the exact isolated session')
      }
      this.policy.bindWebContents(spec.sessionId, view.webContents.id)
      this.policyBound = true
      this.assertOpening()
      this.configureWebContents(view.webContents)
      this.assertOpening()
      this.attachAttempted = true
      this.attachView(view)
      this.assertOpening()
      await this.loadWithDeadline(view.webContents, initialUrl)
      this.assertOpening()
      this.lifecycle = 'open'
    } catch (error) {
      await this.close()
      throw error
    }
  }

  async navigate(targetValue: unknown): Promise<void> {
    const target = targetWithinOrigin(targetValue, this.controlledOrigin)
    if (this.lifecycle !== 'open' || !this.view) {
      throw new Error('Page Agent browser runtime is not open')
    }
    const view = this.view
    try {
      await this.loadWithDeadline(view.webContents, target)
    } catch (error) {
      void this.close()
      throw error
    }
    if (this.lifecycle !== 'open' || this.view !== view) {
      void this.close()
      throw new Error('Page Agent browser navigation was cancelled by close')
    }
  }

  close(): Promise<boolean> {
    if (this.closePromise) return this.closePromise
    let resolveClose!: (result: boolean) => void
    const closePromise = new Promise<boolean>((resolve) => {
      resolveClose = resolve
    })
    this.closePromise = closePromise
    this.lifecycle = 'closing'

    // Revoke all policy authority before any asynchronous cleanup can yield.
    this.revokePolicyAuthority()
    void Promise.resolve()
      .then(() => this.finishClose())
      .then(resolveClose, () => {
        this.cleanupOk = false
        this.finalizeClosedState()
        resolveClose(false)
      })
    return closePromise
  }

  whenClosed(): Promise<boolean> {
    if (this.closePromise) return this.closePromise
    return Promise.resolve(this.lifecycle === 'closed')
  }

  /** Authoritative identity of the open session for Main-owned page readers. */
  currentSessionBinding(): Readonly<{ sessionId: string; webContentsId: number }> | null {
    if (this.lifecycle !== 'open' || !this.spec || !this.view || !this.policyBound) {
      return null
    }
    return Object.freeze({
      sessionId: this.spec.sessionId,
      webContentsId: this.view.webContents.id
    })
  }

  private configureSession(browserSession: PageAgentReadonlyBrowserSession): void {
    browserSession.setPermissionRequestHandler((...args: unknown[]) => {
      const callback = args[2]
      if (typeof callback === 'function') callback(false)
      else void this.close()
    })
    this.assertOpening()
    browserSession.setPermissionCheckHandler(() => false)
    this.assertOpening()
    browserSession.on('will-download', (event) => event.preventDefault())
    this.assertOpening()
    browserSession.webRequest.onBeforeRequest(
      { urls: ['<all_urls>'] },
      (details, callback) => {
        let allowed = false
        try {
          const view = this.view
          if (
            (this.lifecycle !== 'opening' && this.lifecycle !== 'open') ||
            !this.policyBound ||
            !view ||
            !validWebContentsId(details.webContentsId) ||
            details.webContentsId !== view.webContents.id
          ) {
            throw new Error('request is not bound to the active Page Agent WebContents')
          }
          targetWithinOrigin(details.url, this.controlledOrigin)
          allowed = true
        } catch {
          allowed = false
        }
        callback(Object.freeze({ cancel: !allowed }))
      }
    )
    this.assertOpening()
  }

  private configureWebContents(webContents: PageAgentReadonlyBrowserWebContents): void {
    const failClosedNavigation = (eventValue: unknown): void => {
      const event = eventValue as Partial<PageAgentReadonlyNavigationEvent> | null
      if (event && typeof event.preventDefault === 'function') event.preventDefault()
      try {
        webContents.stop()
      } catch {
        // Continue into synchronous authority revocation.
      }
      void this.close()
    }
    const blockUnexpectedNavigation: UnknownListener = (eventValue) => {
      const details = eventValue as Partial<PageAgentReadonlyNavigationEvent> | null
      try {
        targetWithinOrigin(details?.url, this.controlledOrigin)
      } catch {
        failClosedNavigation(eventValue)
      }
    }
    const navigationStarted: UnknownListener = (eventValue) => {
      const details = eventValue as Partial<PageAgentReadonlyNavigationEvent> | null
      try {
        targetWithinOrigin(details?.url, this.controlledOrigin)
        if (!this.spec || !this.policyBound) throw new Error('policy binding unavailable')
        this.policy.beginNavigation(this.spec.sessionId, webContents.id)
      } catch {
        failClosedNavigation(eventValue)
      }
    }
    const denyLogin: UnknownListener = (eventValue, _detailsValue, _authInfoValue, callbackValue) => {
      const event = eventValue as Partial<PageAgentReadonlyNavigationEvent> | null
      if (event && typeof event.preventDefault === 'function') event.preventDefault()
      if (typeof callbackValue === 'function') callbackValue()
      else void this.close()
    }
    const terminalFailure: UnknownListener = () => {
      void this.close()
    }
    this.navigationListeners = Object.freeze([
      Object.freeze(['will-frame-navigate', blockUnexpectedNavigation] as const),
      Object.freeze(['will-redirect', blockUnexpectedNavigation] as const),
      Object.freeze(['did-start-navigation', navigationStarted] as const),
      Object.freeze(['login', denyLogin] as const),
      Object.freeze(['render-process-gone', terminalFailure] as const),
      Object.freeze(['destroyed', terminalFailure] as const)
    ])
    for (const [event, listener] of this.navigationListeners) {
      webContents.on(event, listener)
      this.assertOpening()
    }
    webContents.setWindowOpenHandler(() => Object.freeze({ action: 'deny' as const }))
    this.assertOpening()
  }

  private async finishClose(): Promise<boolean> {
    let cleanupOk = this.cleanupOk
    const browserSession = this.browserSession
    const view = this.view
    try {
      if (view) {
        for (const [event, listener] of this.navigationListeners) {
          try {
            view.webContents.removeListener(event, listener)
          } catch {
            cleanupOk = false
          }
        }
        try {
          view.webContents.stop()
        } catch {
          cleanupOk = false
        }
        if (this.attachAttempted) {
          this.attachAttempted = false
          try {
            this.detachView(view)
          } catch {
            cleanupOk = false
          }
        }
        try {
          view.webContents.close()
        } catch {
          cleanupOk = false
        }
      }

      if (browserSession) {
        const stageTimeoutMs = Math.max(1, Math.floor(this.cleanupTimeoutMs / 3))
        const firstConnections = await this.settleCleanupStage(
          [() => browserSession.closeAllConnections()],
          stageTimeoutMs
        )
        const dataCleanup = await this.settleCleanupStage(
          [
            () => browserSession.clearData(),
            () => browserSession.clearStorageData(),
            () => browserSession.clearCache(),
            () => browserSession.clearAuthCache(),
            () => browserSession.clearHostResolverCache()
          ],
          stageTimeoutMs
        )
        const finalConnections = await this.settleCleanupStage(
          [() => browserSession.closeAllConnections()],
          stageTimeoutMs
        )
        cleanupOk =
          cleanupOk && firstConnections.ok && dataCleanup.ok && finalConnections.ok

        // The partition is lifetime-unique and can never be reopened by this
        // policy. Keep all deny gates installed even after successful cleanup:
        // removing them sequentially would create a partially reopened Session
        // if any later removal failed.
      }
      return cleanupOk
    } catch {
      cleanupOk = false
      return false
    } finally {
      this.cleanupOk = cleanupOk
      this.finalizeClosedState()
    }
  }

  private async settleCleanupStage(
    tasks: ReadonlyArray<() => Promise<void> | void>,
    timeoutMs: number
  ): Promise<CleanupStageResult> {
    const settled = Promise.allSettled(
      tasks.map((task) => Promise.resolve().then(task))
    ).then((results) =>
      Object.freeze({
        ok: results.every((result) => result.status === 'fulfilled')
      })
    )
    let timer: ReturnType<typeof setTimeout> | undefined
    const timedOut = new Promise<CleanupStageResult>((resolve) => {
      timer = setTimeout(
        () => resolve(Object.freeze({ ok: false })),
        timeoutMs
      )
    })
    const result = await Promise.race([settled, timedOut])
    if (timer !== undefined) clearTimeout(timer)
    return result
  }

  private async loadWithDeadline(
    webContents: PageAgentReadonlyBrowserWebContents,
    url: string
  ): Promise<void> {
    let timer: ReturnType<typeof setTimeout> | undefined
    const timedOut = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(
        () => reject(new Error('Page Agent browser load timed out')),
        this.loadTimeoutMs
      )
    })
    try {
      const loading = webContents.loadURL(url)
      await Promise.race([loading, timedOut])
    } finally {
      if (timer !== undefined) clearTimeout(timer)
    }
  }

  private finalizeClosedState(): void {
    this.navigationListeners = []
    this.policyBound = false
    this.view = null
    this.browserSession = null
    this.lifecycle = 'closed'
  }

  private assertOpening(): void {
    if (this.lifecycle === 'opening') return
    this.revokePolicyAuthority()
    throw new Error('Page Agent browser opening was cancelled by close')
  }

  private revokePolicyAuthority(): void {
    if (!this.spec || this.policyCloseAttempted) return
    this.policyCloseAttempted = true
    this.policyBound = false
    try {
      if (!this.policy.closeSession(this.spec.sessionId)) this.cleanupOk = false
    } catch {
      this.cleanupOk = false
    }
  }
}
