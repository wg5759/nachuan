import { describe, expect, it, vi } from 'vitest'

import { createProductionPageAgentElectronRuntime } from './page-agent-electron-adapter'
import type {
  PageAgentReadonlyBrowserPolicy,
  PageAgentReadonlyDownloadEvent,
  PageAgentReadonlyNavigationEvent
} from './page-agent-readonly-browser-runtime'

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

type Listener = (...args: unknown[]) => void

class FakePolicy implements PageAgentReadonlyBrowserPolicy {
  readonly calls: string[] = []

  createSession() {
    this.calls.push('create-session')
    return SESSION_SPEC
  }

  bindWebContents(sessionId: unknown, webContentsId: unknown): void {
    this.calls.push(`bind:${String(sessionId)}:${String(webContentsId)}`)
  }

  beginNavigation(sessionId: unknown, webContentsId: unknown): number {
    this.calls.push(`navigate:${String(sessionId)}:${String(webContentsId)}`)
    return 1
  }

  closeSession(sessionId: unknown): boolean {
    this.calls.push(`close:${String(sessionId)}`)
    return true
  }
}

class FakeRawSession {
  readonly storagePath: string | null = null
  permissionRequestHandler: Listener | null = null
  permissionCheckHandler: Listener | null = null
  readonly sessionListeners = new Map<string, Listener[]>()
  beforeRequestListener: ((details: Record<string, unknown>, callback: (result: { cancel: boolean }) => void) => void) | null = null
  beforeRequestRegistrations = 0
  readonly webRequest = {
    onBeforeRequest: (
      _filter: { urls: string[] },
      listener: (details: Record<string, unknown>, callback: (result: { cancel: boolean }) => void) => void
    ): void => {
      this.beforeRequestRegistrations += 1
      this.beforeRequestListener = listener
    }
  }
  readonly serviceWorkers = {
    on: (event: string, listener: Listener): void => {
      this.addSessionListener(`service-workers:${event}`, listener)
    }
  }

  setPermissionRequestHandler(handler: Listener): void {
    this.permissionRequestHandler = handler
  }

  setPermissionCheckHandler(handler: Listener): void {
    this.permissionCheckHandler = handler
  }

  on(event: string, listener: Listener): void {
    this.addSessionListener(event, listener)
  }

  closeAllConnections(): Promise<void> {
    return Promise.resolve()
  }

  clearData(): Promise<void> {
    return Promise.resolve()
  }

  clearStorageData(): Promise<void> {
    return Promise.resolve()
  }

  clearCache(): Promise<void> {
    return Promise.resolve()
  }

  clearAuthCache(): Promise<void> {
    return Promise.resolve()
  }

  clearHostResolverCache(): Promise<void> {
    return Promise.resolve()
  }

  private addSessionListener(event: string, listener: Listener): void {
    this.sessionListeners.set(event, [...(this.sessionListeners.get(event) ?? []), listener])
  }
}

class FakeRawWebContents {
  readonly id = 71
  readonly listeners = new Map<string, Listener[]>()
  readonly loaded: string[] = []
  readonly session: FakeRawSession
  windowOpenHandler: ((details: { url: string }) => { action: 'deny' }) | null = null
  stopCalls = 0
  closeCalls = 0

  constructor(session: FakeRawSession) {
    this.session = session
  }

  on(event: string, listener: Listener): void {
    this.listeners.set(event, [...(this.listeners.get(event) ?? []), listener])
  }

  removeListener(event: string, listener: Listener): void {
    this.listeners.set(
      event,
      (this.listeners.get(event) ?? []).filter((candidate) => candidate !== listener)
    )
  }

  setWindowOpenHandler(handler: (details: { url: string }) => { action: 'deny' }): void {
    this.windowOpenHandler = handler
  }

  loadURL(url: string): Promise<void> {
    this.loaded.push(url)
    return Promise.resolve()
  }

  stop(): void {
    this.stopCalls += 1
  }

  close(): void {
    this.closeCalls += 1
  }

  emitNavigation(event: string, details: PageAgentReadonlyNavigationEvent): void {
    for (const listener of this.listeners.get(event) ?? []) listener(details)
  }
}

describe('Page Agent Electron 39 adapter', () => {
  it('creates the production view with the exact in-memory Session and locked WebPreferences', async () => {
    const policy = new FakePolicy()
    const rawSession = new FakeRawSession()
    const rawWebContents = new FakeRawWebContents(rawSession)
    let constructorOptions: Record<string, unknown> | undefined
    const attach = vi.fn()
    const detach = vi.fn()
    class FakeWebContentsView {
      readonly webContents = rawWebContents

      constructor(options?: Record<string, unknown>) {
        constructorOptions = options
      }
    }
    const electron = {
      session: {
        fromPartition: vi.fn(() => rawSession)
      },
      WebContentsView: FakeWebContentsView
    } as unknown as Pick<typeof import('electron'), 'session' | 'WebContentsView'>

    const runtime = createProductionPageAgentElectronRuntime(electron, {
      controlledOrigin: 'https://portal.example',
      policy,
      attachView: attach,
      detachView: detach
    })
    await runtime.open('https://portal.example/start')

    expect(electron.session.fromPartition).toHaveBeenCalledWith(SESSION_SPEC.partition, {
      cache: false
    })
    expect(constructorOptions).toEqual({
      webPreferences: { ...SESSION_SPEC.webPreferences, session: rawSession }
    })
    expect(attach).toHaveBeenCalledOnce()
    expect(attach).toHaveBeenCalledWith(expect.objectContaining({ webContents: rawWebContents }))
    expect(rawWebContents.loaded).toEqual(['https://portal.example/start'])

    const downloadEvent: PageAgentReadonlyDownloadEvent = { preventDefault: vi.fn() }
    for (const listener of rawSession.sessionListeners.get('will-download') ?? []) {
      listener(downloadEvent)
    }
    expect(downloadEvent.preventDefault).toHaveBeenCalledOnce()

    await runtime.close()
    expect(detach).toHaveBeenCalledOnce()
  })

  it('allows a request identity only for the exact raw WebContents and a live frame', async () => {
    const policy = new FakePolicy()
    const rawSession = new FakeRawSession()
    const rawWebContents = new FakeRawWebContents(rawSession)
    class FakeWebContentsView {
      readonly webContents = rawWebContents
    }
    const electron = {
      session: { fromPartition: () => rawSession },
      WebContentsView: FakeWebContentsView
    } as unknown as Pick<typeof import('electron'), 'session' | 'WebContentsView'>
    const runtime = createProductionPageAgentElectronRuntime(electron, {
      controlledOrigin: 'https://portal.example',
      policy,
      attachView: () => undefined,
      detachView: () => undefined
    })
    await runtime.open('https://portal.example/start')

    const decide = (overrides: Record<string, unknown> = {}): boolean => {
      let cancelled = false
      rawSession.beforeRequestListener?.(
        {
          url: 'https://portal.example/data',
          method: 'GET',
          resourceType: 'xhr',
          uploadData: [],
          webContentsId: rawWebContents.id,
          webContents: rawWebContents,
          frame: Object.freeze({ routingId: 9 }),
          ...overrides
        },
        (result) => {
          cancelled = result.cancel
        }
      )
      return cancelled
    }

    expect(decide()).toBe(false)
    expect(decide({ webContents: {} })).toBe(true)
    expect(decide({ frame: null })).toBe(true)
    expect(decide({ webContentsId: rawWebContents.id + 1 })).toBe(true)
    expect(decide({ webContentsId: undefined })).toBe(true)
  })

  it('permits only bodyless reads for the explicit Electron 39 resource-type policy', async () => {
    const policy = new FakePolicy()
    const rawSession = new FakeRawSession()
    const rawWebContents = new FakeRawWebContents(rawSession)
    class FakeWebContentsView {
      readonly webContents = rawWebContents
    }
    const electron = {
      session: { fromPartition: () => rawSession },
      WebContentsView: FakeWebContentsView
    } as unknown as Pick<typeof import('electron'), 'session' | 'WebContentsView'>
    const runtime = createProductionPageAgentElectronRuntime(electron, {
      controlledOrigin: 'https://portal.example',
      policy,
      attachView: () => undefined,
      detachView: () => undefined
    })
    await runtime.open('https://portal.example/start')

    const decide = (overrides: Record<string, unknown>): boolean => {
      let cancelled = false
      rawSession.beforeRequestListener?.(
        {
          url: 'https://portal.example/data',
          method: 'GET',
          resourceType: 'xhr',
          uploadData: [],
          webContentsId: rawWebContents.id,
          webContents: rawWebContents,
          frame: Object.freeze({ routingId: 9 }),
          ...overrides
        },
        (result) => {
          cancelled = result.cancel
        }
      )
      return cancelled
    }

    expect(decide({ method: 'GET' })).toBe(false)
    expect(decide({ method: 'HEAD' })).toBe(false)
    expect(decide({ method: 'POST' })).toBe(true)
    expect(decide({ method: 'get' })).toBe(true)
    expect(decide({ uploadData: [{ bytes: Buffer.from('write') }] })).toBe(true)
    // Real Electron 39 omits uploadData on bodyless GET/HEAD: undefined is a
    // bodyless read, not a smuggled body; present non-empty/lying/Proxy
    // shapes stay cancelled.
    expect(decide({ uploadData: undefined })).toBe(false)
    let cancelledWhenAbsent = true
    rawSession.beforeRequestListener?.(
      Object.freeze({
        url: 'https://portal.example/data',
        method: 'GET',
        resourceType: 'mainFrame',
        webContentsId: rawWebContents.id,
        webContents: rawWebContents,
        frame: Object.freeze({ routingId: 9 })
      }),
      (result) => {
        cancelledWhenAbsent = result.cancel
      }
    )
    expect(cancelledWhenAbsent).toBe(false)
    expect(decide({ uploadData: { length: 0 } })).toBe(true)
    const uploadBytesRead = vi.fn(() => {
      throw new Error('upload item must stay opaque')
    })
    const disguisedUploadData = new Proxy(
      [Object.defineProperty({}, 'bytes', { get: uploadBytesRead })],
      {
        get(target, property, receiver) {
          if (property === 'length') return 0
          return Reflect.get(target, property, receiver)
        }
      }
    )
    expect(Array.isArray(disguisedUploadData)).toBe(true)
    expect(decide({ uploadData: disguisedUploadData })).toBe(true)
    expect(uploadBytesRead).not.toHaveBeenCalled()
    expect(decide({ resourceType: undefined })).toBe(true)
    expect(decide({ resourceType: 'futureExperimental' })).toBe(true)
    for (const resourceType of [
      'mainFrame',
      'subFrame',
      'stylesheet',
      'script',
      'image',
      'font',
      'object',
      'xhr',
      'media',
      'other'
    ]) {
      expect(decide({ resourceType })).toBe(false)
    }
    for (const resourceType of ['ping', 'cspReport', 'webSocket']) {
      expect(decide({ resourceType })).toBe(true)
    }
    expect(decide({ resourceType: 'beacon' })).toBe(true)
  })

  it('cancels malformed request details instead of leaving Chromium waiting', async () => {
    const policy = new FakePolicy()
    const rawSession = new FakeRawSession()
    const rawWebContents = new FakeRawWebContents(rawSession)
    class FakeWebContentsView {
      readonly webContents = rawWebContents
    }
    const electron = {
      session: { fromPartition: () => rawSession },
      WebContentsView: FakeWebContentsView
    } as unknown as Pick<typeof import('electron'), 'session' | 'WebContentsView'>
    const runtime = createProductionPageAgentElectronRuntime(electron, {
      controlledOrigin: 'https://portal.example',
      policy,
      attachView: () => undefined,
      detachView: () => undefined
    })
    await runtime.open('https://portal.example/start')
    const callback = vi.fn()

    expect(() => {
      rawSession.beforeRequestListener?.(
        null as unknown as Record<string, unknown>,
        callback
      )
    }).not.toThrow()
    expect(callback).toHaveBeenCalledOnce()
    expect(callback).toHaveBeenCalledWith({ cancel: true })
  })

  it('closes a foreign-session WebContents before it can attach or load', async () => {
    const policy = new FakePolicy()
    const expectedSession = new FakeRawSession()
    const foreignSession = new FakeRawSession()
    const rawWebContents = new FakeRawWebContents(foreignSession)
    const attach = vi.fn()
    class FakeWebContentsView {
      readonly webContents = rawWebContents
    }
    const electron = {
      session: { fromPartition: () => expectedSession },
      WebContentsView: FakeWebContentsView
    } as unknown as Pick<typeof import('electron'), 'session' | 'WebContentsView'>
    const runtime = createProductionPageAgentElectronRuntime(electron, {
      controlledOrigin: 'https://portal.example',
      policy,
      attachView: attach,
      detachView: () => undefined
    })

    await expect(runtime.open('https://portal.example/start')).rejects.toThrow(/exact.*Session/i)
    expect(attach).not.toHaveBeenCalled()
    expect(rawWebContents.loaded).toEqual([])
    expect(rawWebContents.stopCalls).toBe(1)
    expect(rawWebContents.closeCalls).toBe(1)
  })

  it('denies Electron permission requests and checks with the Electron 39 callback order', async () => {
    const policy = new FakePolicy()
    const rawSession = new FakeRawSession()
    const rawWebContents = new FakeRawWebContents(rawSession)
    class FakeWebContentsView {
      readonly webContents = rawWebContents
    }
    const electron = {
      session: { fromPartition: () => rawSession },
      WebContentsView: FakeWebContentsView
    } as unknown as Pick<typeof import('electron'), 'session' | 'WebContentsView'>
    const runtime = createProductionPageAgentElectronRuntime(electron, {
      controlledOrigin: 'https://portal.example',
      policy,
      attachView: () => undefined,
      detachView: () => undefined
    })
    await runtime.open('https://portal.example/start')
    const permissionCallback = vi.fn()

    rawSession.permissionRequestHandler?.(
      rawWebContents,
      'geolocation',
      permissionCallback,
      Object.freeze({ requestingUrl: 'https://portal.example/start' })
    )

    expect(permissionCallback).toHaveBeenCalledOnce()
    expect(permissionCallback).toHaveBeenCalledWith(false)
    expect(
      (rawSession.permissionCheckHandler as ((...args: unknown[]) => boolean) | null)?.(
        rawWebContents,
        'geolocation',
        'https://portal.example',
        Object.freeze({ isMainFrame: true })
      )
    ).toBe(false)
  })

  it('answers HTTP authentication and client-certificate challenges without credentials', async () => {
    const policy = new FakePolicy()
    const rawSession = new FakeRawSession()
    const rawWebContents = new FakeRawWebContents(rawSession)
    class FakeWebContentsView {
      readonly webContents = rawWebContents
    }
    const electron = {
      session: { fromPartition: () => rawSession },
      WebContentsView: FakeWebContentsView
    } as unknown as Pick<typeof import('electron'), 'session' | 'WebContentsView'>
    const runtime = createProductionPageAgentElectronRuntime(electron, {
      controlledOrigin: 'https://portal.example',
      policy,
      attachView: () => undefined,
      detachView: () => undefined
    })
    await runtime.open('https://portal.example/start')

    const loginEvent = { preventDefault: vi.fn() }
    const loginCallback = vi.fn()
    for (const listener of rawWebContents.listeners.get('login') ?? []) {
      listener(loginEvent, {}, { isProxy: false }, loginCallback)
    }
    expect(loginEvent.preventDefault).toHaveBeenCalledOnce()
    expect(loginCallback).toHaveBeenCalledWith()

    const certificateEvent = { preventDefault: vi.fn() }
    const certificateCallback = vi.fn()
    for (const listener of rawWebContents.listeners.get('select-client-certificate') ?? []) {
      listener(certificateEvent, 'https://portal.example', [{ subjectName: 'unexpected' }], certificateCallback)
    }
    expect(certificateEvent.preventDefault).toHaveBeenCalledOnce()
    expect(certificateCallback).toHaveBeenCalledWith()
  })

  it('closes when a client-certificate challenge cannot be denied', async () => {
    const policy = new FakePolicy()
    const rawSession = new FakeRawSession()
    const rawWebContents = new FakeRawWebContents(rawSession)
    class FakeWebContentsView {
      readonly webContents = rawWebContents
    }
    const electron = {
      session: { fromPartition: () => rawSession },
      WebContentsView: FakeWebContentsView
    } as unknown as Pick<typeof import('electron'), 'session' | 'WebContentsView'>
    const runtime = createProductionPageAgentElectronRuntime(electron, {
      controlledOrigin: 'https://portal.example',
      policy,
      attachView: () => undefined,
      detachView: () => undefined
    })
    await runtime.open('https://portal.example/start')
    const certificateEvent = {
      preventDefault: vi.fn(() => {
        throw new Error('client-certificate cancellation failed')
      })
    }

    expect(() => {
      for (const listener of rawWebContents.listeners.get('select-client-certificate') ?? []) {
        listener(certificateEvent, 'https://portal.example', [], vi.fn())
      }
    }).not.toThrow()
    expect(await runtime.whenClosed()).toBe(true)
    expect(policy.calls.filter((call) => call.startsWith('close:'))).toHaveLength(1)
  })

  it('cancels Chromium preconnect before it can create an untracked connection', async () => {
    const policy = new FakePolicy()
    const rawSession = new FakeRawSession()
    const rawWebContents = new FakeRawWebContents(rawSession)
    class FakeWebContentsView {
      readonly webContents = rawWebContents
    }
    const electron = {
      session: { fromPartition: () => rawSession },
      WebContentsView: FakeWebContentsView
    } as unknown as Pick<typeof import('electron'), 'session' | 'WebContentsView'>
    const runtime = createProductionPageAgentElectronRuntime(electron, {
      controlledOrigin: 'https://portal.example',
      policy,
      attachView: () => undefined,
      detachView: () => undefined
    })
    await runtime.open('https://portal.example/start')
    const event = { preventDefault: vi.fn() }

    for (const listener of rawSession.sessionListeners.get('preconnect') ?? []) {
      listener(event, 'https://portal.example', true)
    }

    expect(rawSession.sessionListeners.get('preconnect')).toHaveLength(1)
    expect(event.preventDefault).toHaveBeenCalledOnce()
  })

  it('closes when Chromium preconnect cannot be cancelled', async () => {
    const policy = new FakePolicy()
    const rawSession = new FakeRawSession()
    const rawWebContents = new FakeRawWebContents(rawSession)
    class FakeWebContentsView {
      readonly webContents = rawWebContents
    }
    const electron = {
      session: { fromPartition: () => rawSession },
      WebContentsView: FakeWebContentsView
    } as unknown as Pick<typeof import('electron'), 'session' | 'WebContentsView'>
    const runtime = createProductionPageAgentElectronRuntime(electron, {
      controlledOrigin: 'https://portal.example',
      policy,
      attachView: () => undefined,
      detachView: () => undefined
    })
    await runtime.open('https://portal.example/start')
    const event = {
      preventDefault: vi.fn(() => {
        throw new Error('preconnect cancellation failed')
      })
    }

    expect(() => {
      for (const listener of rawSession.sessionListeners.get('preconnect') ?? []) {
        listener(event, 'https://portal.example', true)
      }
    }).not.toThrow()
    expect(await runtime.whenClosed()).toBe(true)
    expect(rawWebContents.closeCalls).toBe(1)
  })

  it('fails closed when the isolated Session registers a Service Worker', async () => {
    const policy = new FakePolicy()
    const rawSession = new FakeRawSession()
    const rawWebContents = new FakeRawWebContents(rawSession)
    class FakeWebContentsView {
      readonly webContents = rawWebContents
    }
    const electron = {
      session: { fromPartition: () => rawSession },
      WebContentsView: FakeWebContentsView
    } as unknown as Pick<typeof import('electron'), 'session' | 'WebContentsView'>
    const runtime = createProductionPageAgentElectronRuntime(electron, {
      controlledOrigin: 'https://portal.example',
      policy,
      attachView: () => undefined,
      detachView: () => undefined
    })
    await runtime.open('https://portal.example/start')

    for (const listener of
      rawSession.sessionListeners.get('service-workers:registration-completed') ?? []) {
      listener({}, Object.freeze({ scope: 'https://portal.example/' }))
    }

    expect(await runtime.whenClosed()).toBe(true)
    expect(policy.calls.filter((call) => call.startsWith('close:'))).toHaveLength(1)
    expect(rawWebContents.closeCalls).toBe(1)
  })

  it('refuses to let a second adapter replace the WebRequest owner of a raw Session', async () => {
    const rawSession = new FakeRawSession()
    class FakeWebContentsView {
      readonly webContents = new FakeRawWebContents(rawSession)
    }
    const electron = {
      session: { fromPartition: () => rawSession },
      WebContentsView: FakeWebContentsView
    } as unknown as Pick<typeof import('electron'), 'session' | 'WebContentsView'>
    const makeRuntime = (): ReturnType<typeof createProductionPageAgentElectronRuntime> =>
      createProductionPageAgentElectronRuntime(electron, {
        controlledOrigin: 'https://portal.example',
        policy: new FakePolicy(),
        attachView: () => undefined,
        detachView: () => undefined
      })
    const first = makeRuntime()
    await first.open('https://portal.example/start')
    const second = makeRuntime()

    await expect(second.open('https://portal.example/start')).rejects.toThrow(/WebRequest.*owned/i)
    expect(rawSession.beforeRequestRegistrations).toBe(1)
    await first.close()
  })
})
