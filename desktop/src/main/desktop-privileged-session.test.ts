import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import type { Socket } from 'node:net'

import { afterEach, describe, expect, it, vi } from 'vitest'

import { DesktopEngineSessionClient } from './desktop-engine-session-client'
import {
  DESKTOP_ENGINE_SESSION_CHALLENGE_JSON,
  DESKTOP_ENGINE_SESSION_CHALLENGE_PATH,
  type DesktopEngineSessionIdentity,
  signDesktopEngineSessionResponse,
  verifyDesktopEngineSessionRequest
} from './desktop-engine-session-protocol'
import { DesktopPrivilegedSession } from './desktop-privileged-session'

const BOOT_TOKEN = '7a'.repeat(32)
const NOW = 1_800_000_000_000

type ExpectedExchange = Readonly<{
  capability:
    | 'approval.list'
    | 'approval.resolve'
    | 'connection.save'
    | 'connection.delete'
    | 'sync.config'
    | 'sync.auth'
    | 'sync.toggle'
    | 'sync.run'
    | 'channel-recovery.inspect'
    | 'channel-recovery.close'
  method: 'GET' | 'POST' | 'DELETE'
  target: string
  body: string
}>

function digest(body: Uint8Array): string {
  return createHash('sha256').update(body).digest('hex')
}

async function readBody(request: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = []
  for await (const raw of request) chunks.push(Buffer.isBuffer(raw) ? raw : Buffer.from(raw))
  return Buffer.concat(chunks)
}

function raw(headers: Readonly<Record<string, string>>): string[] {
  return Object.entries(headers).flatMap(([name, value]) => [name, value])
}

function sendSignedJson(
  response: ServerResponse,
  session: DesktopEngineSessionIdentity,
  requestNonce: string,
  capability: string,
  status: number,
  body: Buffer,
  connection: 'keep-alive' | 'close'
): void {
  const base = {
    'Content-Type': 'application/json',
    'Content-Length': String(body.byteLength),
    'Cache-Control': 'no-store',
    Connection: connection
  }
  const signed = signDesktopEngineSessionResponse({
    session,
    requestNonce,
    capability,
    status,
    bodySha256: digest(body),
    rawHeaders: raw(base)
  })
  response.writeHead(status, { ...base, ...signed.headers })
  response.end(body)
}

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  const address = server.address()
  if (!address || typeof address === 'string') throw new Error('test listener unavailable')
  return address.port
}

describe('DesktopPrivilegedSession', () => {
  const servers: Server[] = []

  afterEach(async () => {
    vi.restoreAllMocks()
    await Promise.all(
      servers.splice(0).map(
        (server) =>
          new Promise<void>((resolve) => {
            server.closeAllConnections()
            server.close(() => resolve())
          })
      )
    )
  })

  it('sends all ten capabilities and eleven exact routes without any long-lived key header', async () => {
    const expected: ExpectedExchange[] = [
      {
        capability: 'approval.list',
        method: 'GET',
        target: '/v1/approvals?user_id=owner%20%2F%20cn',
        body: ''
      },
      {
        capability: 'approval.resolve',
        method: 'POST',
        target: '/v1/approvals/7/resolve',
        body: '{"decision":"revise","note":"add evidence"}'
      },
      {
        capability: 'connection.save',
        method: 'POST',
        target: '/admin/connections/openai',
        body:
          '{"type":"openai","api_key":"provider-secret","base_url":"https://api.example","enabled_models":[{"id":"m1"}],"preserve_existing_credential":false}'
      },
      {
        capability: 'connection.delete',
        method: 'DELETE',
        target: '/admin/connections/openai',
        body: ''
      },
      {
        capability: 'sync.config',
        method: 'POST',
        target: '/v1/sync/config',
        body: '{"url":"https://sync.example","anon_key":"anon-secret"}'
      },
      {
        capability: 'sync.auth',
        method: 'POST',
        target: '/v1/sync/login',
        body: '{"email":"owner@example.com","password":"login-secret"}'
      },
      {
        capability: 'sync.auth',
        method: 'POST',
        target: '/v1/sync/signup',
        body: '{"email":"new@example.com","password":"signup-secret"}'
      },
      {
        capability: 'sync.toggle',
        method: 'POST',
        target: '/v1/sync/toggle',
        body: '{"enabled":false}'
      },
      {
        capability: 'sync.run',
        method: 'POST',
        target: '/v1/sync/run',
        body: '{}'
      },
      {
        capability: 'channel-recovery.inspect',
        method: 'POST',
        target: '/admin/channel-recovery/feishu/inspect',
        body: '{"target_kind":"video","target_key":"video-task-1"}'
      },
      {
        capability: 'channel-recovery.close',
        method: 'POST',
        target: '/admin/channel-recovery/feishu/close-without-replay',
        body:
          '{"target_kind":"video","target_key":"video-task-1","expected_before_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","decision_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","decided_at_ms":1000,"reason":"operator confirmed no replay","user_confirmed":true,"confirm_final":true}'
      }
    ]
    const challenged = new WeakMap<Socket, string>()
    const observedSockets = new Set<Socket>()
    let next = 0
    let session!: DesktopEngineSessionIdentity
    const server = createServer(async (request, response) => {
      observedSockets.add(request.socket)
      const body = await readBody(request)
      const isChallenge = request.url === DESKTOP_ENGINE_SESSION_CHALLENGE_PATH
      const item = isChallenge ? null : expected[next]
      if (!isChallenge && !item) {
        response.destroy()
        return
      }
      const capability = isChallenge ? 'session.challenge' : item!.capability
      const verified = verifyDesktopEngineSessionRequest({
        session,
        rawHeaders: request.rawHeaders,
        nowMs: NOW,
        capability,
        method: request.method ?? '',
        target: request.url ?? '',
        bodySha256: digest(body)
      })
      expect(request.headers.authorization).toBeUndefined()
      expect(request.headers['x-nachuan-approval-key']).toBeUndefined()
      expect(request.headers['x-nachuan-paid-media-key']).toBeUndefined()
      if (isChallenge) {
        expect(body).toEqual(Buffer.alloc(0))
        expect(verified.channelNonce).toBe('0'.repeat(64))
        challenged.set(request.socket, verified.nonce)
        sendSignedJson(
          response,
          session,
          verified.nonce,
          capability,
          200,
          Buffer.from(DESKTOP_ENGINE_SESSION_CHALLENGE_JSON, 'utf8'),
          'keep-alive'
        )
        return
      }
      expect(request.method).toBe(item!.method)
      expect(request.url).toBe(item!.target)
      expect(body.toString('utf8')).toBe(item!.body)
      expect(verified.channelNonce).toBe(challenged.get(request.socket))
      next += 1
      sendSignedJson(
        response,
        session,
        verified.nonce,
        capability,
        200,
        Buffer.from(`{"route":${next}}`, 'utf8'),
        'close'
      )
    })
    servers.push(server)
    const port = await listen(server)
    session = Object.freeze({ bootToken: BOOT_TOKEN, generation: 11, pid: 42_424, port })
    const api = new DesktopPrivilegedSession(
      new DesktopEngineSessionClient({ session: () => session, now: () => NOW })
    )

    await api.listApprovals('owner / cn')
    await api.resolveApproval(7, 'revise', 'add evidence')
    await api.saveConnection('openai', {
      type: 'openai',
      apiKey: 'provider-secret',
      baseUrl: 'https://api.example',
      enabledModels: [{ id: 'm1' }],
      preserveExistingCredential: false
    })
    await api.deleteConnection('openai')
    await api.configureSync('https://sync.example', 'anon-secret')
    await api.authenticateSync('login', 'owner@example.com', 'login-secret')
    await api.authenticateSync('signup', 'new@example.com', 'signup-secret')
    await api.setSyncEnabled(false)
    await api.runSync()
    await api.inspectChannelRecovery({
      channel: 'feishu',
      targetKind: 'video',
      targetKey: 'video-task-1'
    })
    await api.closeChannelRecovery({
      channel: 'feishu',
      targetKind: 'video',
      targetKey: 'video-task-1',
      expectedBeforeDigest: 'a'.repeat(64),
      decisionId: 'b'.repeat(64),
      decidedAtMs: 1000,
      reason: 'operator confirmed no replay',
      userConfirmed: true,
      confirmFinal: true
    })

    expect(next).toBe(expected.length)
    expect(observedSockets.size).toBe(expected.length)
  })

  it('uses one immutable timeout policy and maps non-2xx and internal details to fixed errors', async () => {
    const captured: unknown[] = []
    const exchangeJson = vi.fn(async (input: unknown) => {
      captured.push(input)
      return { status: 503, body: { detail: 'do-not-reflect-this-detail' } }
    })
    const api = new DesktopPrivilegedSession({ exchangeJson })

    await expect(api.runSync()).rejects.toThrow('Desktop privileged request was rejected')
    expect(captured).toHaveLength(1)
    expect(captured[0]).toMatchObject({
      capability: 'sync.run',
      method: 'POST',
      target: '/v1/sync/run',
      totalTimeoutMs: 5_000,
      firstByteTimeoutMs: 5_000,
      bodyIdleTimeoutMs: 5_000
    })
    expect((captured[0] as { body: Buffer }).body.toString('utf8')).toBe('{}')

    exchangeJson.mockRejectedValueOnce(new Error('socket included sensitive implementation detail'))
    await expect(api.runSync()).rejects.toThrow('Desktop privileged request failed')
  })

  it('gives the bounded Connect transaction enough time to finish before the client aborts', async () => {
    const exchangeJson = vi.fn(async (_input: unknown) => ({
      status: 200,
      body: { ok: true, models: ['m1'] }
    }))
    const api = new DesktopPrivilegedSession({ exchangeJson })

    await api.saveConnection('openai', {
      type: 'openai',
      apiKey: '',
      baseUrl: 'https://api.example',
      enabledModels: [{ id: 'm1' }],
      preserveExistingCredential: true
    })

    expect(exchangeJson).toHaveBeenCalledWith(
      expect.objectContaining({
        totalTimeoutMs: 30_000,
        firstByteTimeoutMs: 30_000,
        bodyIdleTimeoutMs: 5_000
      })
    )
    expect((exchangeJson.mock.calls[0][0] as { body: Buffer }).body.toString('utf8')).toContain(
      '"preserve_existing_credential":true'
    )
  })

  it('rejects runtime-untyped and lossy JSON values before the session client can open a socket', async () => {
    const exchangeJson = vi.fn(async () => ({ status: 200, body: { ok: true } }))
    const api = new DesktopPrivilegedSession({ exchangeJson })
    const cyclic: Record<string, unknown> = {}
    cyclic.self = cyclic

    await expect(
      api.resolveApproval(7, 'later' as 'approve', 'note')
    ).rejects.toThrow('Desktop privileged request is invalid')
    await expect(
      api.saveConnection('openai', {
        type: 'openai',
        apiKey: 'secret',
        baseUrl: 'https://api.example',
        enabledModels: [{ score: Number.NaN }],
        preserveExistingCredential: false
      })
    ).rejects.toThrow('Desktop privileged request is invalid')
    await expect(
      api.saveConnection('openai', {
        type: 'openai',
        apiKey: 'secret',
        baseUrl: 'https://api.example',
        enabledModels: [cyclic],
        preserveExistingCredential: false
      })
    ).rejects.toThrow('Desktop privileged request is invalid')
    await expect(
      api.configureSync('https://sync.example', 'bad\0key')
    ).rejects.toThrow('Desktop privileged request is invalid')
    await expect(
      api.authenticateSync('login', 'owner@example.com', 'bad\0password')
    ).rejects.toThrow('Desktop privileged request is invalid')
    await expect(
      api.setSyncEnabled('true' as unknown as boolean)
    ).rejects.toThrow('Desktop privileged request is invalid')

    expect(exchangeJson).not.toHaveBeenCalled()
  })

  it('fails before the network when the atomic engine session is not published', async () => {
    const api = new DesktopPrivilegedSession(
      new DesktopEngineSessionClient({ session: () => null, now: () => NOW })
    )
    await expect(api.runSync()).rejects.toThrow('Desktop privileged request failed')
  })

  it('rejects a stale challenged socket when the engine session rotates', async () => {
    let session!: DesktopEngineSessionIdentity
    let operations = 0
    const server = createServer(async (request, response) => {
      const body = await readBody(request)
      if (request.url !== DESKTOP_ENGINE_SESSION_CHALLENGE_PATH) {
        operations += 1
        response.destroy()
        return
      }
      const captured = session
      const verified = verifyDesktopEngineSessionRequest({
        session: captured,
        rawHeaders: request.rawHeaders,
        nowMs: NOW,
        capability: 'session.challenge',
        method: request.method ?? '',
        target: request.url ?? '',
        bodySha256: digest(body)
      })
      session = Object.freeze({ ...captured, bootToken: '8b'.repeat(32), generation: 12 })
      sendSignedJson(
        response,
        captured,
        verified.nonce,
        'session.challenge',
        200,
        Buffer.from(DESKTOP_ENGINE_SESSION_CHALLENGE_JSON, 'utf8'),
        'keep-alive'
      )
    })
    servers.push(server)
    const port = await listen(server)
    session = Object.freeze({ bootToken: BOOT_TOKEN, generation: 11, pid: 42_424, port })
    const api = new DesktopPrivilegedSession(
      new DesktopEngineSessionClient({ session: () => session, now: () => NOW })
    )

    await expect(api.runSync()).rejects.toThrow('Desktop privileged request failed')
    expect(operations).toBe(0)
  })

  it('turns a challenge timeout into a fixed failure without dispatching the body', async () => {
    let requests = 0
    const server = createServer((request) => {
      requests += 1
      request.resume()
    })
    servers.push(server)
    const port = await listen(server)
    const session = Object.freeze({ bootToken: BOOT_TOKEN, generation: 11, pid: 42_424, port })
    const api = new DesktopPrivilegedSession(
      new DesktopEngineSessionClient({
        session: () => session,
        now: () => NOW,
        challengeTimeoutMs: 50
      })
    )

    await expect(api.runSync()).rejects.toThrow('Desktop privileged request failed')
    expect(requests).toBe(1)
  })

  it('wires Main handlers only through the session adapter', () => {
    const source = readFileSync(new URL('./index.ts', import.meta.url), 'utf8')
    expect(source).toContain('const desktopEngineSessionClient = new DesktopEngineSessionClient({')
    expect(source).toContain('session: () => engineRootSessions.session()')
    expect(source).toContain('const desktopPrivilegedSession = new DesktopPrivilegedSession(')

    const start = source.indexOf("ipcMain.handle('approval:list'")
    const end = source.indexOf('let snipWin:', start)
    expect(start).toBeGreaterThan(-1)
    expect(end).toBeGreaterThan(start)
    const handlers = source.slice(start, end)
    for (const method of [
      'listApprovals',
      'resolveApproval',
      'saveConnection',
      'deleteConnection',
      'configureSync',
      'authenticateSync',
      'setSyncEnabled',
      'runSync',
      'inspectChannelRecovery',
      'closeChannelRecovery'
    ]) {
      expect(handlers).toContain(`desktopPrivilegedSession.${method}`)
    }
    expect(handlers).not.toContain('privilegedRequest(')
    expect(handlers).not.toContain('engineKey')
    expect(handlers).not.toContain('approvalKey')
    expect(handlers).not.toContain('Authorization')
    expect(handlers).not.toContain('X-Nachuan-Approval-Key')
  })
})
