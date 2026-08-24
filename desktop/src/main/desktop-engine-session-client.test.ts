import { createHash } from 'node:crypto'
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import type { Socket } from 'node:net'

import { afterEach, describe, expect, it } from 'vitest'

import { DesktopEngineSessionClient } from './desktop-engine-session-client'
import {
  DESKTOP_ENGINE_SESSION_CHALLENGE_JSON,
  DESKTOP_ENGINE_SESSION_CHALLENGE_PATH,
  type DesktopEngineSessionIdentity,
  signDesktopEngineSessionResponse,
  verifyDesktopEngineSessionRequest
} from './desktop-engine-session-protocol'

const BOOT_TOKEN = 'ab'.repeat(32)
const NOW = 1_800_000_000_000

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

describe('DesktopEngineSessionClient', () => {
  const servers: Server[] = []

  afterEach(async () => {
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

  it('authenticates then releases the secret body on exactly the challenged TCP socket', async () => {
    const sockets = new Set<Socket>()
    const observed: Array<{ url: string; body: Buffer; headers: IncomingMessage['headers'] }> = []
    let session!: DesktopEngineSessionIdentity
    let challengeNonce = ''
    const server = createServer(async (request, response) => {
      sockets.add(request.socket)
      const body = await readBody(request)
      const capability =
        request.url === DESKTOP_ENGINE_SESSION_CHALLENGE_PATH
          ? 'session.challenge'
          : 'sync.run'
      const verified = verifyDesktopEngineSessionRequest({
        session,
        rawHeaders: request.rawHeaders,
        nowMs: NOW,
        capability,
        method: request.method ?? '',
        target: request.url ?? '',
        bodySha256: digest(body)
      })
      observed.push({ url: request.url ?? '', body, headers: request.headers })
      if (capability === 'session.challenge') {
        challengeNonce = verified.nonce
        expect(verified.channelNonce).toBe('0'.repeat(64))
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
      expect(verified.channelNonce).toBe(challengeNonce)
      sendSignedJson(
        response,
        session,
        verified.nonce,
        capability,
        200,
        Buffer.from('{"ok":true}', 'utf8'),
        'close'
      )
    })
    servers.push(server)
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
    const address = server.address()
    if (!address || typeof address === 'string') throw new Error('test listener unavailable')
    session = Object.freeze({ bootToken: BOOT_TOKEN, generation: 9, pid: 4242, port: address.port })

    const client = new DesktopEngineSessionClient({ session: () => session, now: () => NOW })
    const result = await client.exchangeJson({
      capability: 'sync.run',
      method: 'POST',
      target: '/v1/sync/run',
      body: Buffer.from('{}', 'utf8'),
      signal: new AbortController().signal,
      totalTimeoutMs: 5_000,
      firstByteTimeoutMs: 2_000
    })

    expect(result).toEqual({ status: 200, body: { ok: true } })
    expect(observed.map((item) => item.url)).toEqual([
      DESKTOP_ENGINE_SESSION_CHALLENGE_PATH,
      '/v1/sync/run'
    ])
    expect(observed[0].body).toEqual(Buffer.alloc(0))
    expect(observed[1].body.toString('utf8')).toBe('{}')
    expect(sockets.size).toBe(1)
    for (const item of observed) {
      expect(item.headers.authorization).toBeUndefined()
      expect(item.headers['x-nachuan-approval-key']).toBeUndefined()
      expect(item.headers['x-nachuan-paid-media-key']).toBeUndefined()
    }
  })

  it('rejects the complete runtime manifest before dispatch and admits an exact byte boundary', async () => {
    let requests = 0
    const server = createServer((request, response) => {
      requests += 1
      request.resume()
      response.destroy()
    })
    servers.push(server)
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
    const address = server.address()
    if (!address || typeof address === 'string') throw new Error('test listener unavailable')
    const session = Object.freeze({
      bootToken: BOOT_TOKEN,
      generation: 9,
      pid: 4242,
      port: address.port
    })
    const client = new DesktopEngineSessionClient({ session: () => session, now: () => NOW })
    const signal = new AbortController().signal

    await expect(
      client.exchangeJson({
        capability: 'approval.resolve',
        method: 'POST',
        target: '/v1/sync/run',
        body: Buffer.from('{}'),
        signal,
        totalTimeoutMs: 5_000,
        firstByteTimeoutMs: 2_000
      })
    ).rejects.toThrow('closed manifest')
    await expect(
      client.exchangeJson({
        capability: 'sync.run',
        method: 'POST',
        target: '/v1/sync/%72un',
        body: Buffer.from('{}'),
        signal,
        totalTimeoutMs: 5_000,
        firstByteTimeoutMs: 2_000
      })
    ).rejects.toThrow('closed manifest')
    await expect(
      client.exchangeJson({
        capability: 'approval.list',
        method: 'GET',
        target: '/v1/approvals?user_id=a%62',
        body: Buffer.alloc(0),
        signal,
        totalTimeoutMs: 5_000,
        firstByteTimeoutMs: 2_000
      })
    ).rejects.toThrow('closed manifest')
    await expect(
      client.exchangeJson({
        capability: 'sync.toggle',
        method: 'POST',
        target: '/v1/sync/toggle',
        body: Buffer.from('{"enabled":true,"extra":true}'),
        signal,
        totalTimeoutMs: 5_000,
        firstByteTimeoutMs: 2_000
      })
    ).rejects.toThrow('closed manifest')
    await expect(
      client.exchangeJson({
        capability: 'sync.toggle',
        method: 'POST',
        target: '/v1/sync/toggle',
        body: Buffer.from('{"enabled":true,"enabled":false}'),
        signal,
        totalTimeoutMs: 5_000,
        firstByteTimeoutMs: 2_000
      })
    ).rejects.toThrow('closed manifest')

    let nestedModel: unknown = { id: 'm' }
    for (let depth = 0; depth < 40; depth += 1) nestedModel = { child: nestedModel }
    await expect(
      client.exchangeJson({
        capability: 'connection.save',
        method: 'POST',
        target: '/admin/connections/openai',
        body: Buffer.from(
          JSON.stringify({
            type: 'openai',
            api_key: '',
            base_url: '',
            enabled_models: [nestedModel],
            preserve_existing_credential: false
          })
        ),
        signal,
        totalTimeoutMs: 5_000,
        firstByteTimeoutMs: 2_000
      })
    ).rejects.toThrow('closed manifest')

    const configBodyAt = (size: number): Buffer => {
      const fixed = Buffer.from(JSON.stringify({ url: 'https://x', anon_key: '' }))
      const remaining = size - fixed.byteLength
      const threeByteCharacters = Math.floor(remaining / 3)
      const oneByteCharacters = remaining % 3
      const body = Buffer.from(
        JSON.stringify({
          url: 'https://x',
          anon_key: `${'密'.repeat(threeByteCharacters)}${'a'.repeat(oneByteCharacters)}`
        })
      )
      if (body.byteLength !== size) throw new Error('test config body size mismatch')
      return body
    }
    await expect(
      client.exchangeJson({
        capability: 'sync.config',
        method: 'POST',
        target: '/v1/sync/config',
        body: configBodyAt(24 * 1024 + 1),
        signal,
        totalTimeoutMs: 5_000,
        firstByteTimeoutMs: 2_000
      })
    ).rejects.toThrow('closed manifest')
    await expect(
      client.exchangeJson({
        capability: 'sync.auth',
        method: 'POST',
        target: '/v1/sync/login',
        body: Buffer.from(
          JSON.stringify({ email: 'owner@example.com', password: '\u0001'.repeat(700) })
        ),
        signal,
        totalTimeoutMs: 5_000,
        firstByteTimeoutMs: 2_000
      })
    ).rejects.toThrow('closed manifest')

    for (const overrides of [
      { totalTimeoutMs: 0 },
      { firstByteTimeoutMs: 5_001 },
      { bodyIdleTimeoutMs: 60_001 },
      { signal: {} as AbortSignal }
    ]) {
      await expect(
        client.exchangeJson({
          capability: 'sync.run',
          method: 'POST',
          target: '/v1/sync/run',
          body: Buffer.from('{}'),
          signal,
          totalTimeoutMs: 5_000,
          firstByteTimeoutMs: 2_000,
          ...overrides
        })
      ).rejects.toThrow('closed manifest')
    }

    await new Promise<void>((resolve) => setImmediate(resolve))
    expect(requests).toBe(0)

    await expect(
      client.exchangeJson({
        capability: 'sync.config',
        method: 'POST',
        target: '/v1/sync/config',
        body: configBodyAt(24 * 1024),
        signal,
        totalTimeoutMs: 5_000,
        firstByteTimeoutMs: 2_000
      })
    ).rejects.toThrow('challenge transport failed')
    expect(requests).toBe(1)
  })
})
