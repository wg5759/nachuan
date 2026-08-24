import { types as nodeTypes } from 'node:util'
import type { OnBeforeRequestListenerDetails, Session, WebContentsView } from 'electron'

import {
  PageAgentReadonlyBrowserRuntime,
  type PageAgentReadonlyBrowserPolicy,
  type PageAgentReadonlyBrowserRuntimeOptions,
  type PageAgentReadonlyBrowserSession,
  type PageAgentReadonlyBrowserView,
  type PageAgentReadonlyBrowserWebContents,
  type PageAgentReadonlyDownloadEvent,
  type PageAgentReadonlyRequestDetails
} from './page-agent-readonly-browser-runtime'
import type { PageAgentReadonlyWebPreferences } from './page-agent-readonly-session'

type UnknownListener = (...args: unknown[]) => void
type BeforeRequestCallback = (result: Readonly<{ cancel: boolean }>) => void

interface RawRequestDetails {
  readonly url: string
  readonly method?: string
  readonly resourceType?: string
  readonly uploadData?: readonly unknown[]
  readonly webContentsId?: number
  readonly webContents?: unknown
  readonly frame?: unknown | null
}

interface RawSessionPort {
  readonly storagePath: string | null
  readonly serviceWorkers: {
    on(event: 'registration-completed', listener: UnknownListener): void
  }
  readonly webRequest: {
    onBeforeRequest(
      filter: Readonly<{ urls: readonly string[] }>,
      listener: (details: RawRequestDetails, callback: BeforeRequestCallback) => void
    ): void
  }
  setPermissionRequestHandler(handler: UnknownListener): void
  setPermissionCheckHandler(handler: UnknownListener): void
  on(event: string, listener: UnknownListener): void
  closeAllConnections(): Promise<void>
  clearData(): Promise<void>
  clearStorageData(): Promise<void>
  clearCache(): Promise<void>
  clearAuthCache(): Promise<void>
  clearHostResolverCache(): Promise<void>
}

interface RawWebContentsPort {
  readonly id: number
  readonly session: RawSessionPort
  on(event: string, listener: UnknownListener): void
  removeListener(event: string, listener: UnknownListener): void
  setWindowOpenHandler(
    handler: (details: Readonly<{ url: string }>) => Readonly<{ action: 'deny' }>
  ): void
  loadURL(url: string): Promise<void>
  stop(): void
  close(): void
}

interface RawViewPort {
  readonly webContents: RawWebContentsPort
}

interface PageAgentElectronRuntimePortOptions {
  readonly controlledOrigin: string
  readonly cleanupTimeoutMs?: number
  readonly loadTimeoutMs?: number
  readonly policy: PageAgentReadonlyBrowserPolicy
  readonly fromPartition: (
    partition: string,
    options: Readonly<{ cache: false }>
  ) => RawSessionPort
  readonly createView: (options: Readonly<{
    session: RawSessionPort
    webPreferences: PageAgentReadonlyWebPreferences
  }>) => RawViewPort
  readonly attachView: (view: RawViewPort) => void
  readonly detachView: (view: RawViewPort) => void
}

export interface ProductionPageAgentElectronRuntimeOptions {
  readonly controlledOrigin: string
  readonly cleanupTimeoutMs?: number
  readonly loadTimeoutMs?: number
  readonly policy: PageAgentReadonlyBrowserPolicy
  readonly attachView: (view: WebContentsView) => void
  readonly detachView: (view: WebContentsView) => void
}

const ownedRawWebRequestSessions = new WeakSet<RawSessionPort>()
const CANCEL_RAW_REQUEST = Object.freeze({ cancel: true })
type Electron39ResourceType = OnBeforeRequestListenerDetails['resourceType']
const ELECTRON_39_RESOURCE_TYPE_POLICY = Object.freeze({
  mainFrame: 'allow',
  subFrame: 'allow',
  stylesheet: 'allow',
  script: 'allow',
  image: 'allow',
  font: 'allow',
  object: 'allow',
  xhr: 'allow',
  ping: 'deny',
  cspReport: 'deny',
  media: 'allow',
  webSocket: 'deny',
  other: 'allow'
} satisfies Record<Electron39ResourceType, 'allow' | 'deny'>)

function isAllowedElectron39ReadResourceType(value: unknown): boolean {
  return (
    typeof value === 'string' &&
    Object.prototype.hasOwnProperty.call(ELECTRON_39_RESOURCE_TYPE_POLICY, value) &&
    ELECTRON_39_RESOURCE_TYPE_POLICY[value as Electron39ResourceType] === 'allow'
  )
}

function createPageAgentElectronRuntime(
  options: PageAgentElectronRuntimePortOptions
): PageAgentReadonlyBrowserRuntime {
  const rawSessions = new WeakMap<PageAgentReadonlyBrowserSession, RawSessionPort>()
  const rawViews = new WeakMap<PageAgentReadonlyBrowserView, RawViewPort>()
  const rawWebContentsBySession = new WeakMap<RawSessionPort, RawWebContentsPort>()
  let runtimeRef: PageAgentReadonlyBrowserRuntime | null = null
  let terminalSignalPending = false
  const closeForTerminalSignal = (): void => {
    if (runtimeRef) void runtimeRef.close()
    else terminalSignalPending = true
  }

  const runtimeOptions: PageAgentReadonlyBrowserRuntimeOptions = {
    controlledOrigin: options.controlledOrigin,
    cleanupTimeoutMs: options.cleanupTimeoutMs,
    loadTimeoutMs: options.loadTimeoutMs,
    policy: options.policy,
    fromPartition: (partition, partitionOptions) => {
      const rawSession = options.fromPartition(partition, partitionOptions)
      if (ownedRawWebRequestSessions.has(rawSession)) {
        throw new Error('Page Agent Electron WebRequest Session is already owned')
      }
      ownedRawWebRequestSessions.add(rawSession)
      rawSession.on('preconnect', (eventValue) => {
        const event = eventValue as { preventDefault?: unknown } | null
        try {
          if (!event || typeof event.preventDefault !== 'function') throw new Error('uncancellable')
          event.preventDefault()
        } catch {
          closeForTerminalSignal()
        }
      })
      rawSession.serviceWorkers.on('registration-completed', closeForTerminalSignal)
      const browserSession: PageAgentReadonlyBrowserSession = {
        storagePath: rawSession.storagePath,
        webRequest: {
          onBeforeRequest: (filter, listener) => {
            rawSession.webRequest.onBeforeRequest(
              Object.freeze({ urls: Object.freeze([...filter.urls]) }),
              (details, callback) => {
                let completed = false
                const complete: BeforeRequestCallback = (result) => {
                  if (completed) return
                  completed = true
                  callback(result)
                }
                try {
                  const expectedWebContents = rawWebContentsBySession.get(rawSession)
                  const uploadData = details.uploadData
                  // Real Electron 39 omits uploadData entirely on a bodyless
                  // GET/HEAD; a present value must still be a genuine,
                  // non-Proxy, zero-length array.  Anything else cancels.
                  const bodylessRead =
                    (details.method === 'GET' || details.method === 'HEAD') &&
                    !nodeTypes.isProxy(uploadData) &&
                    (uploadData === undefined ||
                      (Array.isArray(uploadData) && uploadData.length === 0))
                  const readResourceType = isAllowedElectron39ReadResourceType(
                    details.resourceType
                  )
                  const exactLiveFrame =
                    bodylessRead &&
                    readResourceType &&
                    expectedWebContents !== undefined &&
                    details.webContents === expectedWebContents &&
                    details.frame !== undefined &&
                    details.frame !== null &&
                    details.webContentsId === expectedWebContents.id
                  const normalized: PageAgentReadonlyRequestDetails = Object.freeze({
                    url: details.url,
                    webContentsId: exactLiveFrame ? details.webContentsId : undefined
                  })
                  listener(normalized, complete)
                } catch {
                  if (!completed) {
                    try {
                      complete(CANCEL_RAW_REQUEST)
                    } catch {
                      closeForTerminalSignal()
                    }
                  } else {
                    closeForTerminalSignal()
                  }
                }
              }
            )
          }
        },
        setPermissionRequestHandler: (handler) => rawSession.setPermissionRequestHandler(handler),
        setPermissionCheckHandler: (handler) => rawSession.setPermissionCheckHandler(handler),
        on: (_event, listener: (event: PageAgentReadonlyDownloadEvent) => void) =>
          rawSession.on('will-download', listener as UnknownListener),
        closeAllConnections: () => rawSession.closeAllConnections(),
        clearData: () => rawSession.clearData(),
        clearStorageData: () => rawSession.clearStorageData(),
        clearCache: () => rawSession.clearCache(),
        clearAuthCache: () => rawSession.clearAuthCache(),
        clearHostResolverCache: () => rawSession.clearHostResolverCache()
      }
      rawSessions.set(browserSession, rawSession)
      return browserSession
    },
    createView: ({ session: browserSession, webPreferences }) => {
      const rawSession = rawSessions.get(browserSession)
      if (!rawSession) throw new Error('Page Agent Electron Session wrapper is not owned by this adapter')
      const rawView = options.createView({ session: rawSession, webPreferences })
      const rawWebContents = rawView.webContents
      if (rawWebContents.session !== rawSession) {
        try {
          rawWebContents.stop()
        } catch {
          // Continue to the terminal close attempt.
        }
        try {
          rawWebContents.close()
        } catch {
          // The adapter still rejects the foreign ownership below.
        }
        throw new Error('Page Agent Electron view is not bound to the exact raw Session')
      }
      rawWebContents.on(
        'select-client-certificate',
        (eventValue, _urlValue, _certificateListValue, callbackValue) => {
          const event = eventValue as { preventDefault?: unknown } | null
          try {
            if (!event || typeof event.preventDefault !== 'function') {
              throw new Error('uncancellable')
            }
            if (typeof callbackValue !== 'function') throw new Error('missing callback')
            event.preventDefault()
            callbackValue()
          } catch {
            closeForTerminalSignal()
          }
        }
      )
      rawWebContentsBySession.set(rawSession, rawWebContents)
      const webContents: PageAgentReadonlyBrowserWebContents = {
        id: rawWebContents.id,
        session: browserSession,
        on: (event, listener) => rawWebContents.on(event, listener),
        removeListener: (event, listener) => rawWebContents.removeListener(event, listener),
        setWindowOpenHandler: (handler) => rawWebContents.setWindowOpenHandler(handler),
        loadURL: (url) => rawWebContents.loadURL(url),
        stop: () => rawWebContents.stop(),
        close: () => rawWebContents.close()
      }
      const view: PageAgentReadonlyBrowserView = Object.freeze({ webContents })
      rawViews.set(view, rawView)
      return view
    },
    attachView: (view) => {
      const rawView = rawViews.get(view)
      if (!rawView) throw new Error('Page Agent Electron view wrapper is not owned by this adapter')
      options.attachView(rawView)
    },
    detachView: (view) => {
      const rawView = rawViews.get(view)
      if (!rawView) throw new Error('Page Agent Electron view wrapper is not owned by this adapter')
      options.detachView(rawView)
    }
  }
  const runtime = new PageAgentReadonlyBrowserRuntime(runtimeOptions)
  runtimeRef = runtime
  if (terminalSignalPending) void runtime.close()
  return runtime
}

export function createProductionPageAgentElectronRuntime(
  electron: Pick<typeof import('electron'), 'session' | 'WebContentsView'>,
  options: ProductionPageAgentElectronRuntimeOptions
): PageAgentReadonlyBrowserRuntime {
  return createPageAgentElectronRuntime({
    ...options,
    fromPartition: (partition, partitionOptions) =>
      electron.session.fromPartition(partition, { cache: partitionOptions.cache }) as unknown as RawSessionPort,
    createView: ({ session, webPreferences }) =>
      new electron.WebContentsView({
        webPreferences: {
          ...webPreferences,
          session: session as unknown as Session
        }
      }) as unknown as RawViewPort,
    attachView: (view) => options.attachView(view as unknown as WebContentsView),
    detachView: (view) => options.detachView(view as unknown as WebContentsView)
  })
}
