// Real Electron 39 PoC harness for the read-only Page Agent (ADR-0011).
// Bundled at test time by esbuild and spawned as the main process of the
// pinned Electron runtime by page-agent-real-electron-poc.test.ts.
// It never exposes a model/renderer path: all page scripts are compile-time
// constants owned by Main (the reader's fixed scripts plus the labeled
// harness evidence probes below).

import { appendFileSync, readFileSync, writeFileSync } from 'node:fs'

import {
  app,
  session as electronSession,
  WebContentsView,
  BaseWindow,
  type Session,
  type WebPreferences
} from 'electron'

import { createProductionPageAgentElectronRuntime } from './page-agent-electron-adapter'
import { PageAgentReadonlySessionPolicy } from './page-agent-readonly-session'
import { PageAgentReadonlyPageReader } from './page-agent-readonly-page-reader'
import type { PageAgentReadonlyBrowserRuntime } from './page-agent-readonly-browser-runtime'

interface HarnessConfig {
  readonly originMain: string
  readonly originPreconnect: string
  readonly originClientCert: string
  readonly fixtureFingerprint: string
  readonly reportPath: string
  readonly marksPath: string
  readonly userDataDir: string
}

const argv = process.argv.filter((arg) => arg !== '--')
const config: HarnessConfig = JSON.parse(readFileSync(argv[2], 'utf8'))

const marks = (step: string, extra?: unknown): void => {
  appendFileSync(config.marksPath, JSON.stringify({ step, extra }) + '\n')
}

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms))

async function main(): Promise<number> {
  app.commandLine.appendSwitch('disable-gpu')
  app.setPath('userData', config.userDataDir)
  await app.whenReady()
  marks('ready')

  const policy = new PageAgentReadonlySessionPolicy()
  const counters: Record<string, number> = {
    preconnectEvent: 0,
    willDownload: 0,
    loginEvent: 0,
    selectClientCertificate: 0,
    closeAllConnections: 0,
    clearData: 0,
    clearStorageData: 0,
    clearCache: 0,
    clearAuthCache: 0,
    clearHostResolverCache: 0
  }
  const rawSessions: Session[] = []
  const hidden = new BaseWindow({ show: false, width: 1280, height: 900 })
  let attachedView: WebContentsView | null = null

  const attachView = (view: WebContentsView): void => {
    attachedView = view
    hidden.contentView.addChildView(view)
    view.setBounds({ x: 0, y: 0, width: 1280, height: 900 })
  }
  const detachView = (view: WebContentsView): void => {
    try {
      hidden.contentView.removeChildView(view)
    } finally {
      if (attachedView === view) attachedView = null
    }
  }
  // attachedView 的写入发生在回调里，TS 的控制流分析会把它窄化成 null/never；
  // 通过函数体读取可拿到真实声明类型。
  const currentView = (): WebContentsView | null => attachedView

  // Test-only instrumentation of the harness-owned raw Session/View ports:
  // loopback fixture certificate pinning plus deny-gate event counters.  The
  // adapter contract under test is unchanged; instrumentation only counts or
  // pins and never weakens a deny gate.
  const instrumentedElectron = {
    session: {
      fromPartition: (partition: string, options: { cache: false }) => {
        const raw = electronSession.fromPartition(partition, options)
        raw.setCertificateVerifyProc((request, callback) => {
          const pinned =
            request.hostname === '127.0.0.1' &&
            request.certificate?.fingerprint === config.fixtureFingerprint
          callback(pinned ? 0 : -2)
        })
        for (const name of [
          'closeAllConnections',
          'clearData',
          'clearStorageData',
          'clearCache',
          'clearAuthCache',
          'clearHostResolverCache'
        ] as const) {
          const original = raw[name].bind(raw) as () => Promise<void>
          raw[name] = (): Promise<void> => {
            counters[name] += 1
            return original()
          }
        }
        raw.on('preconnect', () => {
          counters.preconnectEvent += 1
        })
        raw.on('will-download', () => {
          counters.willDownload += 1
        })
        rawSessions.push(raw)
        return raw
      }
    },
    WebContentsView: class extends WebContentsView {
      constructor(options: { webPreferences?: WebPreferences }) {
        super(options)
        this.webContents.on('select-client-certificate', () => {
          counters.selectClientCertificate += 1
        })
        this.webContents.on('login', () => {
          counters.loginEvent += 1
        })
      }
    }
  }

  const newInstrumentedRuntime = (controlledOrigin: string): PageAgentReadonlyBrowserRuntime =>
    createProductionPageAgentElectronRuntime(
      instrumentedElectron as unknown as Pick<typeof import('electron'), 'session' | 'WebContentsView'>,
      { controlledOrigin, policy, attachView, detachView }
    )

  const report: Record<string, unknown> = {
    electronVersion: process.versions.electron,
    chromeVersion: process.versions.chrome,
    scenarios: {}
  }
  const scenarios = report.scenarios as Record<string, unknown>

  // ---- S1: open → probe poll → inspect → scroll → navigation revocation → close
  try {
    const runtime = newInstrumentedRuntime(config.originMain)
    await runtime.open(`${config.originMain}/`)
    const binding = runtime.currentSessionBinding()
    const view = currentView()
    if (!binding || !view) throw new Error('PoC S1 binding is unavailable')
    marks('s1-opened', { webContentsId: view.webContents?.id })
    const reader = new PageAgentReadonlyPageReader({
      policy,
      sessionId: binding.sessionId,
      webContentsId: binding.webContentsId,
      controlledOrigin: config.originMain,
      executeJavaScript: (script) => view.webContents.executeJavaScript(script)
    })
    let probed = ''
    for (let attempt = 0; attempt < 60; attempt += 1) {
      const capture = await reader.captureDom()
      probed = JSON.stringify(capture.nodes)
      if (probed.includes('ws-error') || probed.includes('ws-open') || probed.includes('ws-closed')) break
      await sleep(250)
    }
    const inspect = await reader.inspect()
    const omegaHandle = inspect.handles['omega']
    if (typeof omegaHandle !== 'string') throw new Error('PoC fixture node #omega is missing')
    const scroll = await reader.scrollToHandle(omegaHandle)
    // Harness evidence probe (fixed Main-owned script, never model-supplied):
    // the locked-down session must deny the geolocation permission check.
    const geoState = String(
      await view.webContents.executeJavaScript(
        `navigator.permissions ? navigator.permissions.query({ name: 'geolocation' }).then((r) => String(r.state)).catch((error) => 'probe-error:' + String(error)) : 'no-permissions-api'`,
        true
      )
    )
    const agentCookies = await rawSessions[0]!.cookies.get({})
    const defaultCookies = await electronSession.defaultSession.cookies.get({})
    const epochBefore = inspect.navigationEpoch
    await runtime.navigate(`${config.originMain}/page2`)
    const epochAfter = policy.currentNavigationEpoch(binding.sessionId)
    let revokedError = ''
    try {
      await reader.scrollToHandle(omegaHandle)
      revokedError = 'NO-ERROR'
    } catch (error) {
      revokedError = String(error)
    }
    // Capture the landed URL before close(): webContents is destroyed by close.
    const finalUrl = view.webContents.getURL()
    reader.close()
    const closedOk = await runtime.close()
    const cookiesAfterClose = await rawSessions[0]!.cookies.get({})
    scenarios.s1 = {
      storagePathIsNull: rawSessions[0]?.storagePath === null,
      webContentsId: binding.webContentsId,
      sessionId: binding.sessionId,
      openedUrl: finalUrl,
      inspect: {
        nodeCount: inspect.nodes.length,
        domSha256: inspect.domSha256,
        origin: inspect.origin,
        navigationEpoch: inspect.navigationEpoch,
        scrollY: inspect.scrollY,
        capabilityEvidence: inspect.capabilityEvidence,
        nodeIds: inspect.nodes.filter((node) => node.id).map((node) => node.id)
      },
      scroll,
      wsProbeText: probed.includes('ws-error') ? 'ws-error' : 'other',
      geoState,
      cookiesDuring: agentCookies.map((cookie) => cookie.name),
      defaultSessionCookiesDuring: defaultCookies.length,
      navigation: { epochBefore, epochAfter, revokedError },
      closedOk,
      cookiesAfterClose: cookiesAfterClose.length
    }
    marks('s1-done')
  } catch (error) {
    scenarios.s1 = { fatal: String(error), stack: error instanceof Error ? error.stack : undefined }
    marks('s1-fatal', String(error))
  }

  // ---- S2: a download attempt must be prevented and never touch disk
  try {
    const runtime = newInstrumentedRuntime(config.originMain)
    await runtime.open(`${config.originMain}/`)
    let navigateError = ''
    try {
      await runtime.navigate(`${config.originMain}/download`)
    } catch (error) {
      navigateError = String(error)
    }
    const closedOk = await runtime.close()
    scenarios.s2Download = {
      willDownloadEvents: counters.willDownload,
      navigateError,
      closedOk
    }
    marks('s2-done')
  } catch (error) {
    scenarios.s2Download = { fatal: String(error), willDownloadEvents: counters.willDownload }
    marks('s2-fatal', String(error))
  }

  // ---- S3: HTTP login must be denied without prompting for credentials
  try {
    const runtime = newInstrumentedRuntime(config.originMain)
    let openError = ''
    try {
      await runtime.open(`${config.originMain}/auth`)
    } catch (error) {
      openError = String(error)
    }
    let landedUrl = ''
    let landedPage = ''
    try {
      const liveView = currentView()
      if (liveView) {
        landedUrl = liveView.webContents.getURL()
        landedPage = String(
          await liveView.webContents.executeJavaScript(
            `document.title + '|' + (document.body ? document.body.textContent.slice(0, 200) : '')`,
            true
          )
        )
      }
    } catch {
      landedPage = '(destroyed)'
    }
    const closedOk = await runtime.close()
    scenarios.s3Login = {
      loginEvents: counters.loginEvent,
      openError,
      landedUrl,
      landedPage,
      closedOk
    }
    marks('s3-done')
  } catch (error) {
    scenarios.s3Login = { fatal: String(error), loginEvents: counters.loginEvent }
    marks('s3-fatal', String(error))
  }

  // ---- S4: a client-certificate request must be cancelled
  try {
    const runtime = newInstrumentedRuntime(config.originClientCert)
    let openError = ''
    try {
      await runtime.open(`${config.originClientCert}/`)
    } catch (error) {
      openError = String(error)
    }
    const closedOk = await runtime.close()
    scenarios.s4ClientCert = {
      selectClientCertificateEvents: counters.selectClientCertificate,
      openError,
      closedOk
    }
    marks('s4-done')
  } catch (error) {
    scenarios.s4ClientCert = {
      fatal: String(error),
      selectClientCertificateEvents: counters.selectClientCertificate
    }
    marks('s4-fatal', String(error))
  }

  // ---- Policy-level write-action rejection inside the same real process
  const writeRejections: Record<string, string> = {}
  for (const action of ['click', 'input', 'submit', 'download', 'eval']) {
    try {
      policy.assertAction(action)
      writeRejections[action] = 'NOT-REJECTED'
    } catch (error) {
      writeRejections[action] = String(error)
    }
  }

  report.counters = counters
  report.writeRejections = writeRejections
  report.preconnect = { eventCount: counters.preconnectEvent }
  writeFileSync(config.reportPath, JSON.stringify(report, null, 2))
  marks('report-written')
  return 0
}

main()
  .then((code) => app.exit(code))
  .catch((error: unknown) => {
    marks('harness-fatal', String(error))
    try {
      writeFileSync(config.reportPath, JSON.stringify({ fatal: String(error) }))
    } catch {
      // The marks channel already carries the failure.
    }
    app.exit(1)
  })
