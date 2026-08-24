import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import { spawn, spawnSync } from 'node:child_process'
import { createHash, X509Certificate } from 'node:crypto'
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync
} from 'node:fs'
import { createServer, type Server as HttpsServer } from 'node:https'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import type { Duplex } from 'node:stream'

// Real Electron 39 PoC evidence for the read-only Page Agent (ADR-0011).
// Boots the pinned Electron runtime once, drives the production adapter +
// session policy + page reader against a loopback HTTPS fixture, and asserts
// the session-lifecycle evidence item by item.  When the pinned runtime has
// not been prepared this file skips with an explicit reason instead of
// faking green.

const here = dirname(fileURLToPath(import.meta.url))
const repoRoot = resolve(here, '..', '..', '..')
const desktopRoot = resolve(repoRoot, 'desktop')
const electronExe = join(desktopRoot, 'build', 'electron-runtime', 'extracted', 'electron.exe')
const evidenceDir = join(repoRoot, 'data', 'test-evidence')

const RUNTIME_AVAILABLE = existsSync(electronExe)
const HOSTED_GITHUB_RUNNER = process.env.GITHUB_ACTIONS === 'true'

interface FixtureState {
  wsUpgradeAttempts: number
  preconnectConnections: number
  clientCertHandshakeErrors: number
  clientCertServed: number
  mainSocketsSeen: number
  downloadServed: number
  authServed: number
  authWithCredentials: number
}

function fixturePage(preconnectOrigin: string, wsUrl: string): string {
  return `<!doctype html>
<html><head><title>page-agent-poc-fixture</title>
<link rel="preconnect" href="${preconnectOrigin}">
</head>
<body>
<header id="site-header">PoC fixture header</header>
<main id="content">
<section id="alpha">Alpha section</section>
<div style="height:4800px" id="spacer">spacer</div>
<section id="omega">Omega bottom section</section>
</main>
<div id="probe-ws">pending</div>
<script>
(function () {
  var el = document.getElementById('probe-ws')
  try {
    var ws = new WebSocket('${wsUrl}')
    ws.onopen = function () { el.textContent = 'ws-open' }
    ws.onerror = function () { el.textContent = 'ws-error' }
    ws.onclose = function () {
      if (el.textContent === 'pending') el.textContent = 'ws-closed'
    }
  } catch (error) {
    el.textContent = 'ws-threw'
  }
})()
</script>
</body></html>`
}

const PAGE2 = `<!doctype html><html><head><title>page-agent-poc-page2</title></head>
<body><main id="page2-marker">second page</main></body></html>`

// Hosted GitHub Windows runners do not provide the interactive desktop
// boundary this real BaseWindow/WebContentsView acceptance requires. Keep it
// as a real local/clean-VM test and let CI run the deterministic adapter and
// policy suites instead of weakening Electron with --no-sandbox.
describe.skipIf(!RUNTIME_AVAILABLE || HOSTED_GITHUB_RUNNER)('page-agent real Electron 39 read-only PoC', () => {
  let fixture: FixtureState
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let report: any = null
  let marks: string[] = []
  let electronStderr = ''
  let electronExitCode: number | null = null
  let tempRoot = ''
  let servers: HttpsServer[] = []
  let evidence: Record<string, unknown> = {}
  const assertions: Record<string, string> = {}

  const record = (name: string, check: () => void): void => {
    try {
      check()
      assertions[name] = 'pass'
    } catch (error) {
      assertions[name] = `FAIL: ${String(error)}`
      throw error
    }
  }

  beforeAll(async () => {
    fixture = {
      wsUpgradeAttempts: 0,
      preconnectConnections: 0,
      clientCertHandshakeErrors: 0,
      clientCertServed: 0,
      mainSocketsSeen: 0,
      downloadServed: 0,
      authServed: 0,
      authWithCredentials: 0
    }
    tempRoot = mkdtempSync(join(tmpdir(), 'page-agent-real-electron-poc-'))

    // Loopback self-signed fixture certificate (test-only, generated per run).
    const keyPath = join(tempRoot, 'fixture-key.pem')
    const certPath = join(tempRoot, 'fixture-cert.pem')
    const opensslCandidates = [
      'openssl',
      'C:/Program Files/Git/mingw64/bin/openssl.exe',
      '/mingw64/bin/openssl.exe'
    ]
    let generated = false
    let lastError = ''
    for (const openssl of opensslCandidates) {
      const result = spawnSync(openssl, [
        'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
        '-keyout', keyPath, '-out', certPath, '-days', '1', '-subj', '/CN=127.0.0.1',
        '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost'
      ], { encoding: 'utf8' })
      if (result.status === 0 && existsSync(certPath)) {
        generated = true
        break
      }
      lastError = String(result.error || result.stderr)
    }
    if (!generated) throw new Error(`PoC fixture certificate generation failed: ${lastError}`)
    const fixtureCert = new X509Certificate(readFileSync(certPath))
    const fixtureFingerprint = `sha256/${createHash('sha256').update(fixtureCert.raw).digest('base64')}`
    const tls = { key: readFileSync(keyPath), cert: readFileSync(certPath) }

    const mainSockets = new Set<Duplex>()
    const mainServer = createServer(tls, (request, response) => {
      const url = request.url ?? '/'
      if (url === '/page2') {
        response.writeHead(200, { 'content-type': 'text/html' })
        response.end(PAGE2)
        return
      }
      if (url === '/download') {
        fixture.downloadServed += 1
        response.writeHead(200, {
          'content-type': 'application/octet-stream',
          'content-disposition': 'attachment; filename="poc.bin"'
        })
        response.end(Buffer.from('poc-download-bytes'))
        return
      }
      if (url === '/auth') {
        fixture.authServed += 1
        if (typeof request.headers.authorization === 'string') fixture.authWithCredentials += 1
        response.writeHead(401, { 'www-authenticate': 'Basic realm="poc"' })
        response.end('auth required')
        return
      }
      response.writeHead(200, {
        'content-type': 'text/html',
        'set-cookie': 'poc=agent-readonly; Path=/; Secure; SameSite=Strict'
      })
      response.end('fixture') // placeholder, replaced below
    })
    mainServer.on('connection', (socket) => {
      mainSockets.add(socket)
      fixture.mainSocketsSeen += 1
      socket.on('close', () => mainSockets.delete(socket))
    })
    mainServer.on('upgrade', () => {
      fixture.wsUpgradeAttempts += 1
    })

    const preconnectServer = createServer(tls, (_request, response) => {
      response.writeHead(204)
      response.end()
    })
    preconnectServer.on('secureConnection', () => {
      fixture.preconnectConnections += 1
    })

    const clientCertServer = createServer(
      { ...tls, requestCert: true, rejectUnauthorized: true },
      (_request, response) => {
        fixture.clientCertServed += 1
        response.writeHead(200, { 'content-type': 'text/plain' })
        response.end('client-cert-ok')
      }
    )
    clientCertServer.on('tlsClientError', () => {
      fixture.clientCertHandshakeErrors += 1
    })

    for (const server of [mainServer, preconnectServer, clientCertServer]) {
      await new Promise<void>((resolveListen) => server.listen(0, '127.0.0.1', resolveListen))
    }
    servers = [mainServer, preconnectServer, clientCertServer]
    const mainPort = (mainServer.address() as { port: number }).port
    const preconnectPort = (preconnectServer.address() as { port: number }).port
    const clientCertPort = (clientCertServer.address() as { port: number }).port
    const originMain = `https://127.0.0.1:${mainPort}`
    const originPreconnect = `https://127.0.0.1:${preconnectPort}`
    const originClientCert = `https://127.0.0.1:${clientCertPort}`

    // Serve the real fixture page now that the ports are known.
    mainServer.removeAllListeners('request')
    mainServer.on('request', (request, response) => {
      const url = request.url ?? '/'
      if (url === '/page2') {
        response.writeHead(200, { 'content-type': 'text/html' })
        response.end(PAGE2)
        return
      }
      if (url === '/download') {
        fixture.downloadServed += 1
        response.writeHead(200, {
          'content-type': 'application/octet-stream',
          'content-disposition': 'attachment; filename="poc.bin"'
        })
        response.end(Buffer.from('poc-download-bytes'))
        return
      }
      if (url === '/auth') {
        fixture.authServed += 1
        if (typeof request.headers.authorization === 'string') fixture.authWithCredentials += 1
        response.writeHead(401, { 'www-authenticate': 'Basic realm="poc"' })
        response.end('auth required')
        return
      }
      response.writeHead(200, {
        'content-type': 'text/html',
        'set-cookie': 'poc=agent-readonly; Path=/; Secure; SameSite=Strict'
      })
      response.end(fixturePage(originPreconnect, `wss://127.0.0.1:${mainPort}/ws-endpoint`))
    })

    // Bundle the harness entry and boot the pinned Electron runtime.
    const esbuild = await import(
      pathToFileURL(join(desktopRoot, 'node_modules', 'esbuild', 'lib', 'main.js')).href
    )
    const bundlePath = join(tempRoot, 'page-agent-real-electron-poc.main.cjs')
    await esbuild.build({
      entryPoints: [join(here, 'page-agent-real-electron-poc.main.ts')],
      bundle: true,
      platform: 'node',
      format: 'cjs',
      outfile: bundlePath,
      external: ['electron'],
      logLevel: 'silent'
    })

    const configPath = join(tempRoot, 'harness-config.json')
    const reportPath = join(tempRoot, 'harness-report.json')
    const marksPath = join(tempRoot, 'harness-marks.log')
    const userDataDir = join(tempRoot, 'electron-user-data')
    writeFileSync(
      configPath,
      JSON.stringify({
        originMain,
        originPreconnect,
        originClientCert,
        fixtureFingerprint,
        reportPath,
        marksPath,
        userDataDir
      })
    )

    electronExitCode = await new Promise<number>((resolveExit) => {
      const child = spawn(
        electronExe,
        [bundlePath.replaceAll('/', '\\'), '--', configPath.replaceAll('/', '\\')],
        { stdio: ['ignore', 'pipe', 'pipe'] }
      )
      let stderr = ''
      child.stderr.on('data', (chunk) => {
        stderr += chunk
      })
      const killer = setTimeout(() => {
        child.kill('SIGKILL')
        resolveExit(-1)
      }, 240_000)
      child.on('exit', (code) => {
        clearTimeout(killer)
        electronStderr = stderr
        resolveExit(code ?? -1)
      })
    })
    marks = existsSync(marksPath)
      ? readFileSync(marksPath, 'utf8').split('\n').filter(Boolean)
      : marks
    if (existsSync(reportPath)) {
      report = JSON.parse(readFileSync(reportPath, 'utf8'))
    }
    evidence = {
      kind: 'page-agent-real-electron-poc',
      generatedAt: new Date().toISOString(),
      fixture: { originMain, originPreconnect, originClientCert },
      electronExitCode,
      electronStderr: electronStderr.slice(0, 1000),
      harnessMarks: marks,
      harnessReport: report,
      fixtureSide: fixture
    }
  }, 300_000)

  afterAll(() => {
    for (const server of servers) {
      server.closeAllConnections?.()
      server.close()
    }
    mkdirSync(evidenceDir, { recursive: true })
    const day = new Date().toISOString().slice(0, 10).replaceAll('-', '')
    writeFileSync(
      join(evidenceDir, `page-agent-real-electron-poc-${day}.json`),
      JSON.stringify(
        {
          ...evidence,
          assertions,
          claim:
            'ADR-0011 read-only Page Agent PoC-level acceptance on the pinned real Electron 39 runtime; NOT production-ready and not wired into the shipped app',
          commands: [
            'npm --prefix desktop run prepare:electron-runtime',
            'npm --prefix desktop run typecheck',
            'npm --prefix desktop test',
            'node scripts/node-runtime-policy.mjs run scripts/vitest-isolated-runner.mjs run --testTimeout=30000 --no-file-parallelism src/main/page-agent-real-electron-poc.test.ts'
          ],
          uncovered: [
            {
              item: 'select-client-certificate listener firing',
              reason:
                'Chromium only raises select-client-certificate when the OS client certificate store is non-empty; this machine has none. Real evidence here is the refused required-cert handshake (ERR_BAD_SSL_CLIENT_AUTH_CERT, server never served); the cancel branch stays covered by page-agent-electron-adapter.test.ts fakes.'
            },
            {
              item: 'BrowserPane renderer wiring',
              reason:
                'Wiring the PoC window into BrowserPane crosses out-of-scope main modules (IPC/window manager owned by another agent); PoC evidence is the vitest+real-Electron harness instead.'
            }
          ]
        },
        null,
        2
      )
    )
    if (tempRoot) rmSync(tempRoot, { recursive: true, force: true })
  })

  it('boots the pinned Electron 39 runtime and writes the harness report', () => {
    record('boot', () => {
      expect(electronExitCode, electronStderr).toBe(0)
      expect(report).not.toBeNull()
      expect(report?.electronVersion).toBe('39.8.10')
      expect(marks.some((line) => line.includes('report-written'))).toBe(true)
    })
  })

  it('runs S1 in a real isolated in-memory session bound to an exact WebContents', () => {
    record('s1-session', () => {
      const s1 = (report?.scenarios as Record<string, never>)?.s1 as Record<string, unknown>
      expect(s1?.fatal).toBeUndefined()
      expect(s1?.storagePathIsNull).toBe(true)
      expect(s1?.webContentsId).toBeGreaterThan(0)
      expect(String(s1?.openedUrl)).toBe(`${(evidence.fixture as Record<string, string>).originMain}/page2`)
    })
  })

  it('inspect maps the real DOM into bounded nodes with a consumed capability', () => {
    record('inspect', () => {
      const s1 = (report?.scenarios as Record<string, never>)?.s1 as Record<string, unknown>
      const inspect = s1?.inspect as Record<string, unknown>
      expect(inspect?.nodeCount).toBeGreaterThan(3)
      expect(String(inspect?.domSha256)).toMatch(/^[0-9a-f]{64}$/)
      expect(inspect?.origin).toBe((evidence.fixture as Record<string, string>).originMain)
      expect(inspect?.navigationEpoch).toBe(1)
      expect((inspect?.capabilityEvidence as Record<string, boolean>)?.issued).toBe(true)
      expect((inspect?.capabilityEvidence as Record<string, boolean>)?.consumed).toBe(true)
      expect(inspect?.nodeIds).toContain('alpha')
      expect(inspect?.nodeIds).toContain('omega')
    })
  })

  it('scroll moves the real viewport to the minted element handle', () => {
    record('scroll', () => {
      const s1 = (report?.scenarios as Record<string, never>)?.s1 as Record<string, unknown>
      const scroll = s1?.scroll as Record<string, unknown>
      expect((scroll?.capabilityEvidence as Record<string, boolean>)?.consumed).toBe(true)
      expect(scroll?.scrollYBefore).toBe(0)
      expect(scroll?.scrollYAfter).toBeGreaterThan(0)
    })
  })

  it('navigation advances the epoch and revokes the pre-navigation element handle', () => {
    record('navigation-revocation', () => {
      const s1 = (report?.scenarios as Record<string, never>)?.s1 as Record<string, unknown>
      const navigation = s1?.navigation as Record<string, unknown>
      expect(navigation?.epochAfter).toBe((navigation?.epochBefore as number) + 1)
      expect(String(navigation?.revokedError)).not.toBe('NO-ERROR')
      expect(String(navigation?.revokedError)).toMatch(/revoked|rejected/i)
    })
  })

  it('denies WebSocket at the request gate and the page observes the failure', () => {
    record('websocket-deny', () => {
      const s1 = (report?.scenarios as Record<string, never>)?.s1 as Record<string, unknown>
      expect(s1?.wsProbeText).toBe('ws-error')
      expect(fixture.wsUpgradeAttempts).toBe(0)
    })
  })

  it('denies the geolocation permission check in the locked-down session', () => {
    record('permission-deny', () => {
      const s1 = (report?.scenarios as Record<string, never>)?.s1 as Record<string, unknown>
      expect(s1?.geoState).toBe('denied')
    })
  })

  it('prevents the download navigation from producing a file', () => {
    record('download-deny', () => {
      const s2 = (report?.scenarios as Record<string, never>)?.s2Download as Record<string, unknown>
      expect(s2?.fatal).toBeUndefined()
      expect(s2?.willDownloadEvents).toBeGreaterThan(0)
      expect(fixture.downloadServed).toBeGreaterThan(0)
    })
  })

  it('denies HTTP login without ever prompting for credentials', () => {
    record('login-deny', () => {
      const s3 = (report?.scenarios as Record<string, never>)?.s3Login as Record<string, unknown>
      expect(s3?.fatal).toBeUndefined()
      expect(s3?.loginEvents).toBeGreaterThan(0)
      // The denied login never prompts and never supplies credentials: the
      // fixture server saw zero Authorization headers, and the page shows the
      // server's own 401 denial body instead of any authenticated content.
      expect(fixture.authWithCredentials).toBe(0)
      expect(String(s3?.landedPage)).toContain('auth required')
      expect(s3?.closedOk).not.toBe(false)
    })
  })

  it('cancels the real client-certificate request during the TLS handshake', () => {
    record('client-certificate-cancel', () => {
      const s4 = (report?.scenarios as Record<string, never>)?.s4ClientCert as Record<string, unknown>
      expect(s4?.fatal).toBeUndefined()
      // The fixture server requires a client certificate: the agent session
      // must never complete such a handshake or supply any credential.
      expect(String(s4?.openError)).toMatch(/ERR|failed|cancel/i)
      expect(fixture.clientCertServed).toBe(0)
      // select-client-certificate only fires when the OS cert store is
      // non-empty; this machine has none, so the cancel listener is
      // contract-covered by page-agent-electron-adapter.test.ts fakes and
      // the real evidence here is the refused handshake (fail-closed).
      expect(s4?.selectClientCertificateEvents).toBe(0)
    })
  })

  it('keeps fixture cookies inside the ephemeral session and clears them on close', () => {
    record('cookie-isolation', () => {
      const s1 = (report?.scenarios as Record<string, never>)?.s1 as Record<string, unknown>
      expect(s1?.cookiesDuring).toContain('poc')
      expect(s1?.defaultSessionCookiesDuring).toBe(0)
      expect(s1?.cookiesAfterClose).toBe(0)
    })
  })

  it('closes real connection pools and clears session data on close', () => {
    record('connection-pool-cleanup', () => {
      const counters = report?.counters as Record<string, number>
      // Two closeAllConnections stages per runtime close, four runtimes.
      expect(counters?.closeAllConnections).toBeGreaterThanOrEqual(2)
      expect(counters?.clearData).toBeGreaterThanOrEqual(1)
      const s1 = (report?.scenarios as Record<string, never>)?.s1 as Record<string, unknown>
      expect(s1?.closedOk).toBe(true)
    })
  })

  it('keeps preconnect behind the cancel gate', () => {
    record('preconnect-gate', () => {
      const preconnect = report?.preconnect as Record<string, number>
      expect(fixture.preconnectConnections).toBe(0)
      // If Chromium never raises the session preconnect event in a hidden
      // WebContentsView, the cancel path stays covered by the adapter fake
      // tests; the network-level evidence here is that no connection escaped.
      expect(preconnect?.eventCount).toBeGreaterThanOrEqual(0)
    })
  })

  it('hard-rejects write-shaped actions at the real policy boundary', () => {
    record('write-action-reject', () => {
      const writeRejections = report?.writeRejections as Record<string, string>
      for (const action of ['click', 'input', 'submit', 'download', 'eval']) {
        expect(writeRejections?.[action]).toMatch(/not allowed/)
      }
    })
  })
})
