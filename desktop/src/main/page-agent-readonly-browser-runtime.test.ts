import { describe, expect, it, vi } from 'vitest'

import {
  PageAgentReadonlyBrowserRuntime,
  type PageAgentReadonlyBrowserPolicy,
  type PageAgentReadonlyBrowserSession,
  type PageAgentReadonlyBrowserView,
  type PageAgentReadonlyBrowserWebContents,
  type PageAgentReadonlyDownloadEvent,
  type PageAgentReadonlyNavigationEvent,
  type PageAgentReadonlyRequestDetails
} from './page-agent-readonly-browser-runtime'
import {
  PAGE_AGENT_EMPTY_PAYLOAD_SHA256,
  PageAgentReadonlySessionPolicy
} from './page-agent-readonly-session'

const SESSION_SPEC = Object.freeze({
  sessionId: '11111111-1111-4111-8111-111111111111',
  partition: 'nachuan-page-agent-readonly-11111111-1111-4111-8111-111111111111',
  webPreferences: Object.freeze({
    sandbox: true as const,
    contextIsolation: true as const,
    webSecurity: true as const,
    allowRunningInsecureContent: false as const,
    disableDialogs: true as const,
    navigateOnDragDrop: false as const,
    spellcheck: false as const,
    nodeIntegration: false as const,
    webviewTag: false as const,
    devTools: false as const
  })
})

class FakePolicy implements PageAgentReadonlyBrowserPolicy {
  readonly calls: string[] = []
  sessionSpec = SESSION_SPEC
  onCreate: (() => void) | null = null
  onClose: (() => void) | null = null

  createSession() {
    this.calls.push('create-session')
    this.onCreate?.()
    return this.sessionSpec
  }

  bindWebContents(sessionId: unknown, webContentsId: unknown): void {
    this.calls.push(`bind:${String(sessionId)}:${String(webContentsId)}`)
  }

  beginNavigation(sessionId: unknown, webContentsId: unknown): number {
    this.calls.push(`navigate:${String(sessionId)}:${String(webContentsId)}`)
    return this.calls.filter((value) => value.startsWith('navigate:')).length
  }

  closeSession(sessionId: unknown): boolean {
    this.calls.push(`close:${String(sessionId)}`)
    this.onClose?.()
    return true
  }
}

type Listener = (...args: unknown[]) => void

class FakeWebContents implements PageAgentReadonlyBrowserWebContents {
  id = 71
  readonly calls: string[]
  session: FakeSession
  readonly listeners = new Map<string, Set<Listener>>()
  loaded: string[] = []
  loadFailure: Error | null = null
  loadGate: Promise<void> | null = null
  windowOpenHandler: ((details: Readonly<{ url: string }>) => Readonly<{ action: 'deny' }>) | null = null

  constructor(calls: string[], session: FakeSession) {
    this.calls = calls
    this.session = session
  }

  on(event: string, listener: Listener): void {
    const bucket = this.listeners.get(event) ?? new Set<Listener>()
    bucket.add(listener)
    this.listeners.set(event, bucket)
  }

  removeListener(event: string, listener: Listener): void {
    this.listeners.get(event)?.delete(listener)
  }

  emit(event: string, ...args: unknown[]): void {
    for (const listener of [...(this.listeners.get(event) ?? [])]) listener(...args)
  }

  setWindowOpenHandler(
    handler: (details: Readonly<{ url: string }>) => Readonly<{ action: 'deny' }>
  ): void {
    this.windowOpenHandler = handler
  }

  async loadURL(url: string): Promise<void> {
    this.calls.push(`load:${url}`)
    this.loaded.push(url)
    if (this.loadFailure) throw this.loadFailure
    if (this.loadGate) await this.loadGate
  }

  stop(): void {
    this.calls.push('stop')
  }

  close(): void {
    this.calls.push('webcontents-close')
  }
}

class FakeView implements PageAgentReadonlyBrowserView {
  readonly webContents: FakeWebContents
  readonly calls: string[]
  onAttach: (() => void) | null = null

  constructor(calls: string[], session: FakeSession) {
    this.calls = calls
    this.webContents = new FakeWebContents(calls, session)
  }
}

class FakeSession implements PageAgentReadonlyBrowserSession {
  readonly calls: string[]
  storagePath: string | null = null
  permissionRequestHandler: ((...args: unknown[]) => void) | null = null
  permissionCheckHandler: ((...args: unknown[]) => boolean) | null = null
  downloadListener: ((event: PageAgentReadonlyDownloadEvent) => void) | null = null
  requestListener:
    | ((details: PageAgentReadonlyRequestDetails, callback: (result: Readonly<{ cancel: boolean }>) => void) => void)
    | null = null
  requestFilter: Readonly<{ urls: readonly string[] }> | null = null
  clearFailures = new Set<string>()
  syncFailures = new Set<string>()
  neverSettles = new Set<string>()
  cleanupGateSnapshots: Array<Readonly<{
    operation: string
    networkDenied: boolean
    permissionsDenied: boolean
  }>> = []
  private closeConnectionsCount = 0
  onPermissionRequestSet: (() => void) | null = null
  onCleanupOperation: ((operation: string) => void) | null = null

  readonly webRequest = {
    onBeforeRequest: (
      filterOrListener:
        | Readonly<{ urls: readonly string[] }>
        | ((
            details: PageAgentReadonlyRequestDetails,
            callback: (result: Readonly<{ cancel: boolean }>) => void
          ) => void)
        | null,
      listener?:
        | ((
            details: PageAgentReadonlyRequestDetails,
            callback: (result: Readonly<{ cancel: boolean }>) => void
          ) => void)
        | null
    ): void => {
      const effectiveListener =
        typeof filterOrListener === 'function' ? filterOrListener : (listener ?? null)
      this.calls.push(effectiveListener ? 'network-gate' : 'network-gate-clear')
      this.requestFilter =
        typeof filterOrListener === 'object' && filterOrListener !== null
          ? filterOrListener
          : null
      this.requestListener = effectiveListener
    }
  }

  constructor(calls: string[]) {
    this.calls = calls
  }

  setPermissionRequestHandler(handler: ((...args: unknown[]) => void) | null): void {
    this.calls.push(handler ? 'permission-request-deny' : 'permission-request-clear')
    this.permissionRequestHandler = handler
    if (handler) this.onPermissionRequestSet?.()
  }

  setPermissionCheckHandler(handler: ((...args: unknown[]) => boolean) | null): void {
    this.calls.push(handler ? 'permission-check-deny' : 'permission-check-clear')
    this.permissionCheckHandler = handler
  }

  on(event: 'will-download', listener: (event: PageAgentReadonlyDownloadEvent) => void): void {
    expect(event).toBe('will-download')
    this.calls.push('download-deny')
    this.downloadListener = listener
  }

  removeListener(event: 'will-download', listener: (event: PageAgentReadonlyDownloadEvent) => void): void {
    expect(event).toBe('will-download')
    if (this.downloadListener === listener) this.downloadListener = null
    this.calls.push('download-deny-clear')
  }

  closeAllConnections(): Promise<void> {
    this.closeConnectionsCount += 1
    return this.cleanupOperation(`close-connections-${this.closeConnectionsCount}`, 'connections')
  }

  clearData(): Promise<void> {
    return this.cleanupOperation('clear-data', 'data')
  }

  clearStorageData(): Promise<void> {
    return this.cleanupOperation('clear-storage', 'storage')
  }

  clearCache(): Promise<void> {
    return this.cleanupOperation('clear-cache', 'cache')
  }

  clearAuthCache(): Promise<void> {
    return this.cleanupOperation('clear-auth', 'auth')
  }

  clearHostResolverCache(): Promise<void> {
    return this.cleanupOperation('clear-host-resolver', 'host-resolver')
  }

  private cleanupOperation(call: string, behavior: string): Promise<void> {
    this.calls.push(call)
    this.cleanupGateSnapshots.push(
      Object.freeze({
        operation: call,
        networkDenied: this.requestListener !== null,
        permissionsDenied:
          this.permissionRequestHandler !== null && this.permissionCheckHandler !== null
      })
    )
    this.onCleanupOperation?.(call)
    if (this.syncFailures.has(behavior)) throw new Error(`${behavior} sync failed`)
    if (this.neverSettles.has(behavior)) return new Promise<void>(() => undefined)
    if (this.clearFailures.has(behavior)) return Promise.reject(new Error(`${behavior} failed`))
    return Promise.resolve()
  }
}

function setup(
  options: Readonly<{ cleanupTimeoutMs?: number; loadTimeoutMs?: number }> = {}
) {
  const calls: string[] = []
  const policy = new FakePolicy()
  const browserSession = new FakeSession(calls)
  const view = new FakeView(calls, browserSession)
  const createView = vi.fn(() => {
    calls.push('create-view')
    return view
  })
  const runtime = new PageAgentReadonlyBrowserRuntime({
    controlledOrigin: 'https://portal.example',
    cleanupTimeoutMs: options.cleanupTimeoutMs,
    loadTimeoutMs: options.loadTimeoutMs,
    policy,
    fromPartition: (partition, options?: Readonly<{ cache: false }>) => {
      calls.push(`from-partition:${partition}:cache=${String(options?.cache)}`)
      return browserSession
    },
    createView,
    attachView: () => {
      calls.push('attach')
      view.onAttach?.()
    },
    detachView: () => calls.push('detach')
  })
  return { browserSession, calls, createView, policy, runtime, view }
}

describe('PageAgentReadonlyBrowserRuntime', () => {
  it('rejects load timeout configuration outside the finite hard bound', () => {
    for (const loadTimeoutMs of [0, 2, 120_001, 1.5, Number.NaN]) {
      expect(() => setup({ loadTimeoutMs })).toThrow(/load timeout is invalid/i)
    }
  })

  it('configures the unique ephemeral session before creating or loading the Main-owned view', async () => {
    const { browserSession, calls, createView, policy, runtime, view } = setup()

    await runtime.open('https://portal.example/start?tab=1')

    expect(policy.calls).toEqual([
      'create-session',
      `bind:${SESSION_SPEC.sessionId}:${view.webContents.id}`
    ])
    expect(createView).toHaveBeenCalledWith({
      session: browserSession,
      webPreferences: SESSION_SPEC.webPreferences
    })
    expect(calls).toEqual([
      `from-partition:${SESSION_SPEC.partition}:cache=false`,
      'permission-request-deny',
      'permission-check-deny',
      'download-deny',
      'network-gate',
      'create-view',
      'attach',
      'load:https://portal.example/start?tab=1'
    ])
    expect(view.webContents.windowOpenHandler?.({ url: 'https://portal.example/popup' })).toEqual({
      action: 'deny'
    })

    let permission = true
    browserSession.permissionRequestHandler?.(
      {},
      'notifications',
      (allowed: boolean) => {
        permission = allowed
      },
      { requestingUrl: 'https://portal.example/' }
    )
    expect(permission).toBe(false)
    expect(browserSession.permissionCheckHandler?.({}, 'clipboard-read')).toBe(false)

    const download = { preventDefault: vi.fn() }
    browserSession.downloadListener?.(download)
    expect(download.preventDefault).toHaveBeenCalledOnce()
  })

  it('rejects a persistent session and a view that is not bound to the exact isolated session', async () => {
    const persistent = setup()
    persistent.browserSession.storagePath = 'C:\\persisted-agent-profile'
    await expect(persistent.runtime.open('https://portal.example/')).rejects.toThrow(
      /in-memory session/i
    )

    const mismatched = setup()
    mismatched.view.webContents.session = new FakeSession(mismatched.calls)
    await expect(mismatched.runtime.open('https://portal.example/')).rejects.toThrow(
      /exact isolated session/i
    )
  })

  it('closes partial ownership when the created view has an invalid WebContents identity', async () => {
    const { calls, policy, runtime, view } = setup()
    view.webContents.id = 0

    await expect(runtime.open('https://portal.example/')).rejects.toThrow(
      /invalid WebContents identity/i
    )
    expect(await runtime.whenClosed()).toBe(true)
    expect(calls.filter((call) => call === 'webcontents-close')).toHaveLength(1)
    expect(calls.filter((call) => call === 'detach')).toHaveLength(0)
    expect(policy.calls.some((call) => call.startsWith('bind:'))).toBe(false)
  })

  it('rejects a policy spec that weakens or extends the exact locked WebPreferences', async () => {
    const weakened = setup()
    weakened.policy.sessionSpec = Object.freeze({
      ...SESSION_SPEC,
      webPreferences: Object.freeze({
        ...SESSION_SPEC.webPreferences,
        disableDialogs: false
      })
    }) as unknown as typeof SESSION_SPEC
    await expect(weakened.runtime.open('https://portal.example/')).rejects.toThrow(
      /locked-down|invalid ephemeral session/i
    )

    const extended = setup()
    extended.policy.sessionSpec = Object.freeze({
      ...SESSION_SPEC,
      webPreferences: Object.freeze({
        ...SESSION_SPEC.webPreferences,
        preload: 'must-not-load.js'
      })
    }) as unknown as typeof SESSION_SPEC
    await expect(extended.runtime.open('https://portal.example/')).rejects.toThrow(
      /locked-down|invalid ephemeral session/i
    )
  })

  it('does not create resources after close re-enters from session creation', async () => {
    const { calls, policy, runtime } = setup()
    policy.onCreate = () => {
      void runtime.close()
    }

    await expect(runtime.open('https://portal.example/')).rejects.toThrow(/cancelled|closing|closed/i)
    expect(calls.some((call) => call.startsWith('from-partition:'))).toBe(false)
    expect(policy.calls.filter((call) => call.startsWith('close:'))).toHaveLength(1)
    expect(await runtime.close()).toBe(true)
  })

  it('compensates an attach that closes or throws after taking ownership', async () => {
    const closing = setup()
    closing.view.onAttach = () => {
      void closing.runtime.close()
    }
    await expect(closing.runtime.open('https://portal.example/')).rejects.toThrow(
      /cancelled|closing|closed/i
    )
    expect(await closing.runtime.whenClosed()).toBe(true)
    expect(closing.calls.filter((call) => call === 'detach')).toHaveLength(1)
    expect(closing.calls.filter((call) => call === 'webcontents-close')).toHaveLength(1)
    expect(closing.calls.some((call) => call.startsWith('load:'))).toBe(false)

    const throwing = setup()
    throwing.view.onAttach = () => {
      throw new Error('attach failed after ownership')
    }
    await expect(throwing.runtime.open('https://portal.example/')).rejects.toThrow(
      'attach failed after ownership'
    )
    expect(await throwing.runtime.whenClosed()).toBe(true)
    expect(throwing.calls.filter((call) => call === 'detach')).toHaveLength(1)
    expect(throwing.calls.filter((call) => call === 'webcontents-close')).toHaveLength(1)
  })

  it('stops opening immediately when a session configuration boundary closes it', async () => {
    const { browserSession, calls, runtime } = setup()
    browserSession.onPermissionRequestSet = () => {
      void runtime.close()
    }

    await expect(runtime.open('https://portal.example/')).rejects.toThrow(
      /cancelled|closing|closed/i
    )
    expect(calls).toContain('permission-request-deny')
    expect(calls).not.toContain('permission-check-deny')
    expect(calls).not.toContain('download-deny')
    expect(calls).not.toContain('network-gate')
    expect(calls).not.toContain('create-view')
    expect(await runtime.whenClosed()).toBe(true)
  })

  it('rejects an initial load whose promise returns after the runtime has begun closing', async () => {
    const { calls, runtime, view } = setup()
    let releaseLoad!: () => void
    view.webContents.loadGate = new Promise<void>((resolve) => {
      releaseLoad = resolve
    })

    const opening = runtime.open('https://portal.example/slow-start')
    expect(calls).toContain('load:https://portal.example/slow-start')
    const closing = runtime.close()
    releaseLoad()

    await expect(opening).rejects.toThrow(/cancelled|closing|closed/i)
    expect(await closing).toBe(true)
    expect(calls.filter((call) => call === 'webcontents-close')).toHaveLength(1)
  })

  it('hard-bounds a never-settling initial load and completes bounded close cleanup', async () => {
    vi.useFakeTimers()
    try {
      const { calls, runtime, view } = setup({ cleanupTimeoutMs: 30, loadTimeoutMs: 30 })
      view.webContents.loadGate = new Promise<void>(() => undefined)
      let outcome = 'pending'
      void runtime.open('https://portal.example/never-loads').then(
        () => {
          outcome = 'resolved'
        },
        (error: unknown) => {
          outcome = String(error)
        }
      )

      await vi.advanceTimersByTimeAsync(100)

      expect(outcome).toMatch(/load timed out/i)
      expect(await runtime.whenClosed()).toBe(true)
      expect(calls.filter((call) => call === 'webcontents-close')).toHaveLength(1)
      expect(calls.filter((call) => call.startsWith('close-connections-'))).toHaveLength(2)
    } finally {
      vi.useRealTimers()
    }
  })

  it('keeps close bounded when both initial load and cleanup operations never settle', async () => {
    vi.useFakeTimers()
    try {
      const { browserSession, runtime, view } = setup({
        cleanupTimeoutMs: 30,
        loadTimeoutMs: 30
      })
      view.webContents.loadGate = new Promise<void>(() => undefined)
      browserSession.neverSettles.add('connections')
      browserSession.neverSettles.add('storage')
      let outcome = 'pending'
      void runtime.open('https://portal.example/never-loads-or-cleans').then(
        () => {
          outcome = 'resolved'
        },
        (error: unknown) => {
          outcome = String(error)
        }
      )

      await vi.advanceTimersByTimeAsync(200)

      expect(outcome).toMatch(/load timed out/i)
      expect(await runtime.whenClosed()).toBe(false)
      await expect(runtime.navigate('https://portal.example/after-timeouts')).rejects.toThrow(
        /not open/i
      )
      expect(browserSession.requestListener).not.toBeNull()
      expect(browserSession.permissionRequestHandler).not.toBeNull()
      expect(browserSession.permissionCheckHandler).not.toBeNull()
    } finally {
      vi.useRealTimers()
    }
  })

  it('allows network only within the exact controlled HTTPS origin', async () => {
    const { browserSession, runtime, view } = setup()
    await runtime.open('https://portal.example/')
    expect(browserSession.requestFilter).toEqual({ urls: ['<all_urls>'] })
    const decision = (url: string, webContentsId: number | null = view.webContents.id): boolean => {
      let cancel = false
      browserSession.requestListener?.(
        webContentsId === null ? { url } : { url, webContentsId },
        (result) => {
        cancel = result.cancel
        }
      )
      return cancel
    }

    expect(decision('https://portal.example/app.js')).toBe(false)
    expect(decision('https://portal.example/app.js', null)).toBe(true)
    expect(decision('https://portal.example/app.js', view.webContents.id + 1)).toBe(true)
    expect(decision('https://portal.example.evil.test/app.js')).toBe(true)
    expect(decision('http://portal.example/app.js')).toBe(true)
    expect(decision('data:text/javascript,alert(1)')).toBe(true)
    expect(decision('https://user:pass@portal.example/app.js')).toBe(true)
  })

  it('revokes policy authority at every allowed frame navigation start', async () => {
    const { policy, runtime, view } = setup()
    await runtime.open('https://portal.example/')
    const event: PageAgentReadonlyNavigationEvent = { preventDefault: vi.fn() }

    view.webContents.emit('did-start-navigation', {
      ...event,
      url: 'https://portal.example/next',
      isMainFrame: true
    })
    view.webContents.emit('did-start-navigation', {
      ...event,
      url: 'https://portal.example/frame',
      isMainFrame: false
    })

    expect(policy.calls.filter((call) => call.startsWith('navigate:'))).toEqual([
      `navigate:${SESSION_SPEC.sessionId}:${view.webContents.id}`,
      `navigate:${SESSION_SPEC.sessionId}:${view.webContents.id}`
    ])
  })

  it('revokes snapshots, queued capabilities and active execution on same-origin subframe navigation', async () => {
    const calls: string[] = []
    const browserSession = new FakeSession(calls)
    const view = new FakeView(calls, browserSession)
    let randomByte = 1
    const policy = new PageAgentReadonlySessionPolicy({
      now: () => 1_000,
      randomBytes: (size) => Buffer.alloc(size, randomByte++),
      randomUUID: () => SESSION_SPEC.sessionId
    })
    const runtime = new PageAgentReadonlyBrowserRuntime({
      controlledOrigin: 'https://portal.example',
      policy,
      fromPartition: () => browserSession,
      createView: () => view,
      attachView: () => undefined,
      detachView: () => undefined
    })
    await runtime.open('https://portal.example/')
    view.webContents.emit('did-start-navigation', {
      preventDefault: vi.fn(),
      url: 'https://portal.example/',
      isMainFrame: true
    })

    const snapshot = Object.freeze({
      sessionId: SESSION_SPEC.sessionId,
      webContentsId: view.webContents.id,
      origin: 'https://portal.example',
      navigationEpoch: 1,
      domSha256: 'a'.repeat(64),
      elementIdentitySha256: 'b'.repeat(64)
    })
    const elementHandle = policy.mintElementHandle(snapshot)
    const scope = Object.freeze({
      sessionId: SESSION_SPEC.sessionId,
      webContentsId: view.webContents.id,
      origin: 'https://portal.example',
      navigationEpoch: 1,
      domSha256: 'a'.repeat(64),
      elementHandle,
      action: 'inspect' as const,
      valueSha256: PAGE_AGENT_EMPTY_PAYLOAD_SHA256
    })
    const queued = policy.issueCapability(scope, 500)
    const active = policy.issueCapability(scope, 500)
    const activeLease = policy.beginExecution(active.token, {
      ...scope,
      expiresAtMs: active.expiresAtMs
    })
    expect(activeLease).not.toBeNull()

    view.webContents.emit('did-start-navigation', {
      preventDefault: vi.fn(),
      url: 'https://portal.example/embedded',
      isMainFrame: false
    })

    expect(activeLease?.signal.aborted).toBe(true)
    expect(activeLease?.assertCurrent()).toBe(false)
    expect(
      policy.consumeCapability(queued.token, {
        ...scope,
        expiresAtMs: queued.expiresAtMs
      })
    ).toBe(false)
    expect(() => policy.mintElementHandle(snapshot)).toThrow(/navigation epoch/i)
    expect(await runtime.close()).toBe(true)
  })

  it('blocks a cross-origin navigation before commit and fails closed if it starts anyway', async () => {
    const { calls, policy, runtime, view } = setup()
    await runtime.open('https://portal.example/')
    const willEvent: PageAgentReadonlyNavigationEvent = { preventDefault: vi.fn() }
    view.webContents.emit('will-frame-navigate', {
      ...willEvent,
      url: 'https://evil.example/',
      isMainFrame: false
    })
    expect(willEvent.preventDefault).toHaveBeenCalledOnce()

    const startedEvent: PageAgentReadonlyNavigationEvent = { preventDefault: vi.fn() }
    view.webContents.emit('did-start-navigation', {
      ...startedEvent,
      url: 'https://evil.example/',
      isMainFrame: true
    })
    await runtime.whenClosed()

    expect(calls).toContain('stop')
    expect(policy.calls).toContain(`close:${SESSION_SPEC.sessionId}`)
    expect(policy.calls.some((call) => call.startsWith('navigate:'))).toBe(false)
  })

  it('fails closed when a cross-origin subframe starts without a preceding will-frame event', async () => {
    const { calls, policy, runtime, view } = setup()
    await runtime.open('https://portal.example/')
    const startedEvent: PageAgentReadonlyNavigationEvent = { preventDefault: vi.fn() }

    view.webContents.emit('did-start-navigation', {
      ...startedEvent,
      url: 'data:text/html,unexpected-frame',
      isMainFrame: false
    })

    expect(startedEvent.preventDefault).toHaveBeenCalledOnce()
    expect(await runtime.whenClosed()).toBe(true)
    expect(calls).toContain('stop')
    expect(policy.calls.some((call) => call.startsWith('navigate:'))).toBe(false)
  })

  it('explicitly cancels WebContents HTTP and proxy authentication', async () => {
    const { runtime, view } = setup()
    await runtime.open('https://portal.example/')
    const event = { preventDefault: vi.fn() }
    const callback = vi.fn()

    view.webContents.emit('login', event, {}, { isProxy: true }, callback)

    expect(event.preventDefault).toHaveBeenCalledOnce()
    expect(callback).toHaveBeenCalledOnce()
    expect(callback).toHaveBeenCalledWith()
  })

  it('rejects a navigation whose load returns after the runtime has begun closing', async () => {
    const { calls, runtime, view } = setup()
    await runtime.open('https://portal.example/')
    let releaseLoad!: () => void
    view.webContents.loadGate = new Promise<void>((resolve) => {
      releaseLoad = resolve
    })

    const navigation = runtime.navigate('https://portal.example/slow')
    expect(calls).toContain('load:https://portal.example/slow')
    const closing = runtime.close()
    releaseLoad()

    await expect(navigation).rejects.toThrow(/cancelled|closing|closed/i)
    expect(await closing).toBe(true)
    expect(calls.filter((call) => call === 'webcontents-close')).toHaveLength(1)
  })

  it('hard-bounds a never-settling navigation and starts bounded fail-closed cleanup', async () => {
    vi.useFakeTimers()
    const state = setup({ cleanupTimeoutMs: 30, loadTimeoutMs: 30 })
    try {
      await state.runtime.open('https://portal.example/')
      state.view.webContents.loadGate = new Promise<void>(() => undefined)
      let outcome = 'pending'
      void state.runtime.navigate('https://portal.example/never-navigates').then(
        () => {
          outcome = 'resolved'
        },
        (error: unknown) => {
          outcome = String(error)
        }
      )

      await vi.advanceTimersByTimeAsync(100)

      expect(outcome).toMatch(/load timed out/i)
      expect(await state.runtime.whenClosed()).toBe(true)
      expect(state.calls.filter((call) => call === 'webcontents-close')).toHaveLength(1)
      expect(
        state.calls.filter((call) => call.startsWith('close-connections-'))
      ).toHaveLength(2)
    } finally {
      await state.runtime.close()
      vi.useRealTimers()
    }
  })

  it('revokes, cleans once and permanently retains every deny gate for the unique partition', async () => {
    const { browserSession, calls, policy, runtime, view } = setup()
    await runtime.open('https://portal.example/')

    const closing = runtime.close()
    let sameOriginAfterCloseCancelled = false
    browserSession.requestListener?.(
      { url: 'https://portal.example/late-worker.js', webContentsId: view.webContents.id },
      (result) => {
        sameOriginAfterCloseCancelled = result.cancel
      }
    )
    expect(sameOriginAfterCloseCancelled).toBe(true)

    expect(await closing).toBe(true)
    expect(await runtime.close()).toBe(true)

    const closeAt = policy.calls.indexOf(`close:${SESSION_SPEC.sessionId}`)
    expect(closeAt).toBeGreaterThan(-1)
    expect(calls.filter((call) => call === 'detach')).toHaveLength(1)
    expect(calls.filter((call) => call === 'webcontents-close')).toHaveLength(1)
    expect(calls.filter((call) => call === 'clear-storage')).toHaveLength(1)
    expect(calls.filter((call) => call === 'clear-data')).toHaveLength(1)
    expect(calls.filter((call) => call === 'clear-cache')).toHaveLength(1)
    expect(calls.filter((call) => call === 'clear-auth')).toHaveLength(1)
    expect(calls.filter((call) => call === 'clear-host-resolver')).toHaveLength(1)
    expect(calls.filter((call) => call.startsWith('close-connections-'))).toHaveLength(2)
    expect(browserSession.cleanupGateSnapshots.every((snapshot) => snapshot.networkDenied)).toBe(true)
    expect(browserSession.cleanupGateSnapshots.every((snapshot) => snapshot.permissionsDenied)).toBe(
      true
    )
    expect(browserSession.requestListener).not.toBeNull()
    expect(browserSession.permissionRequestHandler).not.toBeNull()
    expect(browserSession.permissionCheckHandler).not.toBeNull()
    expect(browserSession.downloadListener).not.toBeNull()
    expect(calls).not.toContain('permission-request-clear')
    expect(calls).not.toContain('permission-check-clear')
    expect(calls).not.toContain('download-deny-clear')
    expect(calls).not.toContain('network-gate-clear')

    const firstConnectionsAt = calls.indexOf('close-connections-1')
    const secondConnectionsAt = calls.indexOf('close-connections-2')
    for (const operation of [
      'clear-data',
      'clear-storage',
      'clear-cache',
      'clear-auth',
      'clear-host-resolver'
    ]) {
      expect(calls.indexOf(operation)).toBeGreaterThan(firstConnectionsAt)
      expect(calls.indexOf(operation)).toBeLessThan(secondConnectionsAt)
    }
  })

  it('coalesces close re-entry from authority revocation and asynchronous cleanup', async () => {
    const { browserSession, calls, policy, runtime } = setup()
    await runtime.open('https://portal.example/')
    policy.onClose = () => {
      void runtime.close()
    }
    browserSession.onCleanupOperation = () => {
      void runtime.close()
    }

    expect(await runtime.close()).toBe(true)
    expect(await runtime.close()).toBe(true)
    expect(policy.calls.filter((call) => call.startsWith('close:'))).toHaveLength(1)
    expect(calls.filter((call) => call === 'detach')).toHaveLength(1)
    expect(calls.filter((call) => call === 'webcontents-close')).toHaveLength(1)
    expect(calls.filter((call) => call.startsWith('close-connections-'))).toHaveLength(2)
    expect(calls.filter((call) => call.startsWith('clear-'))).toHaveLength(5)
  })

  it('cleans partial state on load failure and reports cleanup failure without skipping later cleanup', async () => {
    const { browserSession, calls, policy, runtime, view } = setup()
    view.webContents.loadFailure = new Error('load failed')
    browserSession.clearFailures.add('storage')

    await expect(runtime.open('https://portal.example/')).rejects.toThrow('load failed')
    expect(await runtime.whenClosed()).toBe(false)
    expect(policy.calls).toContain(`close:${SESSION_SPEC.sessionId}`)
    expect(calls).toContain('clear-storage')
    expect(calls).toContain('clear-cache')
    expect(calls).toContain('clear-auth')
    expect(calls).toContain('clear-data')
    expect(calls).toContain('clear-host-resolver')
    expect(calls.filter((call) => call.startsWith('close-connections-'))).toHaveLength(2)
  })

  it('contains synchronous cleanup throws, attempts every cleanup, and always closes', async () => {
    const { browserSession, calls, runtime } = setup()
    await runtime.open('https://portal.example/')
    browserSession.syncFailures.add('storage')

    expect(await runtime.close()).toBe(false)
    expect(await runtime.whenClosed()).toBe(false)
    expect(calls).toContain('clear-storage')
    expect(calls).toContain('clear-data')
    expect(calls).toContain('clear-cache')
    expect(calls).toContain('clear-auth')
    expect(calls).toContain('clear-host-resolver')
    expect(calls.filter((call) => call.startsWith('close-connections-'))).toHaveLength(2)
    await expect(runtime.navigate('https://portal.example/after-close')).rejects.toThrow(/not open/i)
  })

  it('hard-bounds never-settling cleanup and leaves deny handlers installed', async () => {
    vi.useFakeTimers()
    try {
      const { browserSession, calls, runtime } = setup({ cleanupTimeoutMs: 30 })
      await runtime.open('https://portal.example/')
      browserSession.neverSettles.add('connections')
      browserSession.neverSettles.add('storage')
      let result: boolean | undefined
      void runtime.close().then((value) => {
        result = value
      })

      await vi.advanceTimersByTimeAsync(100)

      expect(result).toBe(false)
      expect(calls).toContain('clear-storage')
      expect(calls).toContain('clear-data')
      expect(calls).toContain('clear-cache')
      expect(calls).toContain('clear-auth')
      expect(calls).toContain('clear-host-resolver')
      expect(calls.filter((call) => call.startsWith('close-connections-'))).toHaveLength(2)
      expect(browserSession.requestListener).not.toBeNull()
      expect(browserSession.permissionRequestHandler).not.toBeNull()
      expect(browserSession.permissionCheckHandler).not.toBeNull()
      await expect(runtime.navigate('https://portal.example/after-timeout')).rejects.toThrow(/not open/i)
    } finally {
      vi.useRealTimers()
    }
  })

  it.each([
    'http://portal.example/',
    'https://other.example/',
    'https://user:pass@portal.example/',
    'not a url'
  ])('rejects an initial target outside the exact origin before session creation: %s', async (url) => {
    const { policy, runtime } = setup()
    await expect(runtime.open(url)).rejects.toThrow('exact controlled HTTPS origin')
    expect(policy.calls).toEqual([])
  })
})
