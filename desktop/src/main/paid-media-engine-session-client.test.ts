import { createHash } from 'node:crypto'
import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse
} from 'node:http'
import { Readable } from 'node:stream'

import { afterEach, describe, expect, it } from 'vitest'

import {
  PAID_MEDIA_ENGINE_SESSION_CHALLENGE_JSON,
  PAID_MEDIA_ENGINE_SESSION_CHALLENGE_PATH,
  type PaidMediaEngineSessionIdentity,
  signPaidMediaEngineSessionResponse,
  verifyPaidMediaEngineSessionRequest
} from './paid-media-engine-session-protocol'
import {
  PaidMediaEngineSessionClient,
  PaidMediaEngineSessionClientError,
  type PaidMediaEngineSessionConsumed,
  type PaidMediaEngineSessionResponse
} from './paid-media-engine-session-client'

const NOW = 1_784_200_123_456
const servers: Server[] = []

function digest(value: Buffer | string): string {
  return createHash('sha256').update(value).digest('hex')
}

function controlledTimeoutPolicy() {
  let sequence = 0
  const pending = new Map<number, { callback: () => void; delayMs: number }>()

  return Object.freeze({
    schedule(callback: () => void, delayMs: number): () => void {
      const id = ++sequence
      pending.set(id, { callback, delayMs })
      return () => pending.delete(id)
    },
    activeDelays(): number[] {
      return [...pending.values()].map(({ delayMs }) => delayMs)
    },
    fire(delayMs: number): void {
      const match = [...pending.entries()].find(([, entry]) => entry.delayMs === delayMs)
      if (!match) throw new Error(`test timeout policy has no active ${delayMs}ms deadline`)
      const [id, entry] = match
      pending.delete(id)
      entry.callback()
    }
  })
}

function responseRawHeaders(headers: Readonly<Record<string, string>>): string[] {
  return Object.entries(headers).flatMap(([name, value]) => [name, value])
}

async function readRequest(request: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = []
  let total = 0
  for await (const raw of request) {
    const bytes = Buffer.isBuffer(raw) ? raw : Buffer.from(raw)
    total += bytes.length
    if (total > 1024 * 1024) throw new Error('test request exceeded its bound')
    chunks.push(bytes)
  }
  return Buffer.concat(chunks, total)
}

async function consumeBuffer(
  input: PaidMediaEngineSessionResponse,
  maximum = 1024 * 1024
): Promise<PaidMediaEngineSessionConsumed<Buffer>> {
  const chunks: Buffer[] = []
  let total = 0
  for await (const raw of input.response) {
    const bytes = Buffer.isBuffer(raw) ? raw : Buffer.from(raw)
    total += bytes.length
    if (total > maximum) throw new Error('test response exceeded its bound')
    chunks.push(bytes)
  }
  const body = Buffer.concat(chunks, total)
  return { value: body, bodySha256: digest(body) }
}

function sendSigned(
  response: ServerResponse,
  session: PaidMediaEngineSessionIdentity,
  requestNonce: string,
  status: number,
  body: Buffer,
  headers: Readonly<Record<string, string>>,
  mutateAfterSigning?: (headers: Record<string, string>) => void
): void {
  const signed = signPaidMediaEngineSessionResponse({
    session,
    requestNonce,
    status,
    bodySha256: digest(body),
    rawHeaders: responseRawHeaders(headers)
  })
  const finalHeaders = { ...headers, ...signed.headers }
  mutateAfterSigning?.(finalHeaders)
  response.writeHead(status, finalHeaders)
  response.end(body)
}

function verifyRequest(
  request: IncomingMessage,
  session: PaidMediaEngineSessionIdentity,
  body: Buffer
) {
  return verifyPaidMediaEngineSessionRequest({
    session,
    rawHeaders: request.rawHeaders,
    nowMs: NOW,
    method: request.method ?? '',
    target: request.url ?? '',
    bodySha256: digest(body)
  })
}

function sendChallenge(
  request: IncomingMessage,
  response: ServerResponse,
  session: PaidMediaEngineSessionIdentity,
  body: Buffer
): string {
  expect(request.url).toBe(PAID_MEDIA_ENGINE_SESSION_CHALLENGE_PATH)
  expect(body).toHaveLength(0)
  const verified = verifyRequest(request, session, body)
  const challenge = Buffer.from(PAID_MEDIA_ENGINE_SESSION_CHALLENGE_JSON, 'utf8')
  sendSigned(response, session, verified.nonce, 200, challenge, {
    'Content-Type': 'application/json',
    'Content-Length': String(challenge.length),
    'Cache-Control': 'no-store',
    Connection: 'keep-alive'
  })
  return verified.nonce
}

async function listen(
  handler: (request: IncomingMessage, response: ServerResponse) => void | Promise<void>
): Promise<{ server: Server; port: number }> {
  const server = createServer((request, response) => {
    void Promise.resolve(handler(request, response)).catch(() => {
      if (!response.headersSent) response.writeHead(500, { 'Content-Length': '0' })
      response.end()
    })
  })
  servers.push(server)
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => resolve())
  })
  const address = server.address()
  if (!address || typeof address === 'string') throw new Error('test server address missing')
  return { server, port: address.port }
}

afterEach(async () => {
  await Promise.all(
    servers.splice(0).map(
      (server) => new Promise<void>((resolve) => server.close(() => resolve()))
    )
  )
})

describe('PaidMediaEngineSessionClient', () => {
  it('authenticates before lazily streaming an exactly signed request body', async () => {
    let session!: PaidMediaEngineSessionIdentity
    let sourceCreated = 0
    const paths: string[] = []
    const payload = Buffer.from('streamed-stage-asset')
    const source = {
      byteLength: payload.length,
      sha256: digest(payload),
      createReadStream: () => {
        sourceCreated += 1
        return Readable.from([
          payload.subarray(0, 5),
          payload.subarray(5, 11),
          payload.subarray(11)
        ])
      }
    }
    const { port } = await listen(async (request, response) => {
      paths.push(request.url ?? '')
      const body = await readRequest(request)
      if (request.url === PAID_MEDIA_ENGINE_SESSION_CHALLENGE_PATH) {
        expect(sourceCreated).toBe(0)
        source.byteLength = 1
        source.sha256 = 'f'.repeat(64)
        source.createReadStream = () => Readable.from([Buffer.from('mutated')])
        sendChallenge(request, response, session, body)
        return
      }
      expect(body).toEqual(payload)
      const verified = verifyRequest(request, session, body)
      const result = Buffer.from('{"ok":true}', 'utf8')
      sendSigned(response, session, verified.nonce, 200, result, {
        'Content-Type': 'application/json',
        'Content-Length': String(result.length),
        'Cache-Control': 'no-store',
        Connection: 'close'
      })
    })
    session = Object.freeze({
      bootToken: '10'.repeat(32),
      generation: 7,
      pid: 43_210,
      port
    })
    const client = new PaidMediaEngineSessionClient({ session: () => session, now: () => NOW })
    const result = await client.exchange(
      {
        method: 'POST',
        target: '/v1/paid-media/probe',
        headers: { Accept: 'application/json', 'Content-Type': 'image/png' },
        body: source,
        signal: new AbortController().signal,
        totalTimeoutMs: 2_000,
        firstByteTimeoutMs: 2_000
      },
      consumeBuffer
    )

    expect(result.toString('utf8')).toBe('{"ok":true}')
    expect(sourceCreated).toBe(1)
    expect(paths).toEqual([
      PAID_MEDIA_ENGINE_SESSION_CHALLENGE_PATH,
      '/v1/paid-media/probe'
    ])
  })

  it('authenticates one socket before sending a secret body and sends no long-term keys', async () => {
    let session!: PaidMediaEngineSessionIdentity
    const sockets = new Set<unknown>()
    const paths: string[] = []
    const prompt = JSON.stringify({ model: 'image-model', prompt: 'commercial-secret' })
    const { port } = await listen(async (request, response) => {
      paths.push(request.url ?? '')
      sockets.add(request.socket)
      const body = await readRequest(request)
      expect(request.headers.authorization).toBeUndefined()
      expect(request.headers['x-nachuan-paid-media-key']).toBeUndefined()
      if (request.url === PAID_MEDIA_ENGINE_SESSION_CHALLENGE_PATH) {
        sendChallenge(request, response, session, body)
        return
      }
      expect(body.toString('utf8')).toBe(prompt)
      const verified = verifyRequest(request, session, body)
      expect(request.headers['idempotency-key']).toBe('desktop-op-1234567890')
      const result = Buffer.from('{"ok":true}', 'utf8')
      sendSigned(response, session, verified.nonce, 200, result, {
        'Content-Type': 'application/json',
        'Content-Length': String(result.length),
        'Cache-Control': 'no-store',
        'X-Nachuan-Paid-Media-Protocol': '2',
        'Idempotency-Replayed': 'false',
        Connection: 'close'
      })
    })
    session = Object.freeze({
      bootToken: '11'.repeat(32),
      generation: 7,
      pid: 43_210,
      port
    })
    const client = new PaidMediaEngineSessionClient({ session: () => session, now: () => NOW })
    const result = await client.exchange(
      {
        method: 'POST',
        target: '/v1/images/generations',
        headers: {
          Accept: 'application/json',
          'Cache-Control': 'no-store',
          'Content-Type': 'application/json',
          'X-Nachuan-Paid-Media-Protocol': '2',
          'Idempotency-Key': 'desktop-op-1234567890'
        },
        body: Buffer.from(prompt, 'utf8'),
        signal: new AbortController().signal,
        totalTimeoutMs: 2_000,
        firstByteTimeoutMs: 2_000
      },
      consumeBuffer
    )
    expect(result.toString('utf8')).toBe('{"ok":true}')
    expect(paths).toEqual([
      PAID_MEDIA_ENGINE_SESSION_CHALLENGE_PATH,
      '/v1/images/generations'
    ])
    expect(sockets.size).toBe(1)
  })

  it('rejects short, long, digest-drifted, and oversized source chunks during transport metering', async () => {
    let session!: PaidMediaEngineSessionIdentity
    const { port } = await listen(async (request, response) => {
      if (request.url === PAID_MEDIA_ENGINE_SESSION_CHALLENGE_PATH) {
        sendChallenge(request, response, session, await readRequest(request))
        return
      }
      request.resume()
    })
    session = Object.freeze({
      bootToken: '12'.repeat(32),
      generation: 1,
      pid: 1,
      port
    })
    const client = new PaidMediaEngineSessionClient({ session: () => session, now: () => NOW })
    const cases = [
      {
        name: 'short',
        declared: Buffer.from('abcd'),
        delivered: Buffer.from('abc')
      },
      {
        name: 'long',
        declared: Buffer.from('abc'),
        delivered: Buffer.from('abcd')
      },
      {
        name: 'digest drift',
        declared: Buffer.from('abd'),
        delivered: Buffer.from('abc')
      },
      {
        name: 'oversized chunk',
        declared: Buffer.alloc(64 * 1024 + 1, 0x41),
        delivered: Buffer.alloc(64 * 1024 + 1, 0x41)
      }
    ]
    for (const item of cases) {
      let source: Readable | null = null
      await expect(
        client.exchange(
          {
            method: 'POST',
            target: '/v1/paid-media/probe',
            headers: { Accept: 'application/json', 'Content-Type': 'image/png' },
            body: {
              byteLength: item.declared.length,
              sha256: digest(item.declared),
              createReadStream: () => {
                source = Readable.from([item.delivered])
                return source
              }
            },
            signal: new AbortController().signal,
            totalTimeoutMs: 1_000,
            firstByteTimeoutMs: 1_000
          },
          consumeBuffer
        ),
        item.name
      ).rejects.toThrow(/body failed verification|not dispatched|transport/i)
      expect((source as Readable | null)?.destroyed).toBe(true)
    }
  })

  it('closes zero-chunk and excessive tiny-chunk floods with bounded transport work', async () => {
    let session!: PaidMediaEngineSessionIdentity
    let providerBytes = 0
    const observedChunks: number[] = []
    const { port } = await listen(async (request, response) => {
      if (request.url === PAID_MEDIA_ENGINE_SESSION_CHALLENGE_PATH) {
        sendChallenge(request, response, session, await readRequest(request))
        return
      }
      for await (const raw of request) {
        providerBytes += Buffer.isBuffer(raw) ? raw.length : Buffer.byteLength(raw)
      }
    })
    session = Object.freeze({
      bootToken: '14'.repeat(32),
      generation: 1,
      pid: 1,
      port
    })
    const client = new PaidMediaEngineSessionClient({
      session: () => session,
      now: () => NOW,
      onRequestBodyChunk: ({ byteLength }) => observedChunks.push(byteLength)
    })

    const zeroSource = Readable.from(
      Array.from({ length: 4_096 }, () => Buffer.alloc(0)),
      { objectMode: false }
    )
    await expect(
      client.exchange(
        {
          method: 'POST',
          target: '/v1/paid-media/probe',
          headers: { Accept: 'application/json', 'Content-Type': 'image/png' },
          body: {
            byteLength: 1,
            sha256: digest('x'),
            createReadStream: () => zeroSource
          },
          signal: new AbortController().signal,
          totalTimeoutMs: 5_000,
          firstByteTimeoutMs: 5_000
        },
        consumeBuffer
      )
    ).rejects.toThrow(/body failed verification|not dispatched|transport/i)
    expect(zeroSource.destroyed).toBe(true)
    expect(providerBytes).toBe(0)
    expect(observedChunks).toEqual([])

    const floodBytes = Buffer.alloc(4_097, 0x78)
    const floodSource = Readable.from(
      (function* tinyChunks(): Generator<Buffer> {
        for (let index = 0; index < floodBytes.length; index += 1) {
          yield floodBytes.subarray(index, index + 1)
        }
      })(),
      { objectMode: false, highWaterMark: 1 }
    )
    await expect(
      client.exchange(
        {
          method: 'POST',
          target: '/v1/paid-media/probe',
          headers: { Accept: 'application/json', 'Content-Type': 'image/png' },
          body: {
            byteLength: floodBytes.length,
            sha256: digest(floodBytes),
            createReadStream: () => floodSource
          },
          signal: new AbortController().signal,
          totalTimeoutMs: 10_000,
          firstByteTimeoutMs: 10_000
        },
        consumeBuffer
      )
    ).rejects.toThrow(/body failed verification|transport/i)
    expect(floodSource.destroyed).toBe(true)
    expect(observedChunks).toHaveLength(4_096)
    expect(Math.max(...observedChunks)).toBe(1)
    expect(providerBytes).toBeLessThanOrEqual(4_096)
  }, 15_000)

  it('snapshots and transports a legacy sub-1 MiB Buffer only as 64 KiB chunks', async () => {
    let session!: PaidMediaEngineSessionIdentity
    const payload = Buffer.alloc(512 * 1024 + 17, 0x61)
    const observedChunks: number[] = []
    const { port } = await listen(async (request, response) => {
      const body = await readRequest(request)
      if (request.url === PAID_MEDIA_ENGINE_SESSION_CHALLENGE_PATH) {
        payload.fill(0x62)
        sendChallenge(request, response, session, body)
        return
      }
      expect(body).toEqual(Buffer.alloc(512 * 1024 + 17, 0x61))
      const verified = verifyRequest(request, session, body)
      const result = Buffer.from('{"ok":true}')
      sendSigned(response, session, verified.nonce, 200, result, {
        'Content-Type': 'application/json',
        'Content-Length': String(result.length),
        'Cache-Control': 'no-store',
        Connection: 'close'
      })
    })
    session = Object.freeze({
      bootToken: '13'.repeat(32),
      generation: 1,
      pid: 1,
      port
    })
    const timeouts = controlledTimeoutPolicy()
    const client = new PaidMediaEngineSessionClient({
      session: () => session,
      now: () => NOW,
      scheduleTotalTimeout: timeouts.schedule,
      onRequestBodyChunk: ({ byteLength }) => observedChunks.push(byteLength)
    })
    await expect(
      client.exchange(
        {
          method: 'POST',
          target: '/v1/images/generations',
          headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
          body: payload,
          signal: new AbortController().signal,
          totalTimeoutMs: 10_000,
          firstByteTimeoutMs: 10_000
        },
        consumeBuffer
      )
    ).resolves.toEqual(Buffer.from('{"ok":true}'))
    expect(observedChunks.length).toBeGreaterThan(1)
    expect(Math.max(...observedChunks)).toBeLessThanOrEqual(64 * 1024)
    expect(timeouts.activeDelays()).toEqual([])
  }, 15_000)

  it('rejects a Buffer above the 1 MiB caller contract before session lookup or socket use', async () => {
    let sessionLookups = 0
    const client = new PaidMediaEngineSessionClient({
      session: () => {
        sessionLookups += 1
        throw new Error('must not look up a session')
      },
      now: () => NOW
    })
    await expect(
      client.exchange(
        {
          method: 'POST',
          target: '/v1/images/generations',
          headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
          body: Buffer.alloc(1024 * 1024 + 1),
          signal: new AbortController().signal,
          totalTimeoutMs: 1_000,
          firstByteTimeoutMs: 1_000
        },
        consumeBuffer
      )
    ).rejects.toThrow(/body is invalid/i)
    expect(sessionLookups).toBe(0)
  })

  it('never releases the secret target or body after an unsigned challenge', async () => {
    const paths: string[] = []
    let sourceCreated = 0
    const secret = Buffer.from('{"prompt":"must-not-leak"}', 'utf8')
    const { port } = await listen(async (request, response) => {
      paths.push(request.url ?? '')
      await readRequest(request)
      const body = Buffer.from(PAID_MEDIA_ENGINE_SESSION_CHALLENGE_JSON, 'utf8')
      response.writeHead(200, {
        'Content-Type': 'application/json',
        'Content-Length': String(body.length),
        'Cache-Control': 'no-store',
        Connection: 'keep-alive'
      })
      response.end(body)
    })
    const session = Object.freeze({
      bootToken: '22'.repeat(32),
      generation: 1,
      pid: 1,
      port
    })
    const client = new PaidMediaEngineSessionClient({ session: () => session, now: () => NOW })
    await expect(
      client.exchange(
        {
          method: 'POST',
          target: '/v1/images/generations',
          headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
          body: {
            byteLength: secret.length,
            sha256: digest(secret),
            createReadStream: () => {
              sourceCreated += 1
              return Readable.from([secret])
            }
          },
          signal: new AbortController().signal,
          totalTimeoutMs: 1_000,
          firstByteTimeoutMs: 1_000
        },
        consumeBuffer
      )
    ).rejects.toBeInstanceOf(PaidMediaEngineSessionClientError)
    expect(paths).toEqual([PAID_MEDIA_ENGINE_SESSION_CHALLENGE_PATH])
    expect(sourceCreated).toBe(0)
  })

  it('rejects a generation change after challenge without dispatching the actual request', async () => {
    let current!: PaidMediaEngineSessionIdentity
    const paths: string[] = []
    const { port } = await listen(async (request, response) => {
      paths.push(request.url ?? '')
      const body = await readRequest(request)
      const captured = current
      const verified = verifyRequest(request, captured, body)
      const challenge = Buffer.from(PAID_MEDIA_ENGINE_SESSION_CHALLENGE_JSON, 'utf8')
      const headers = {
        'Content-Type': 'application/json',
        'Content-Length': String(challenge.length),
        'Cache-Control': 'no-store',
        Connection: 'keep-alive'
      }
      const signed = signPaidMediaEngineSessionResponse({
        session: captured,
        requestNonce: verified.nonce,
        status: 200,
        bodySha256: digest(challenge),
        rawHeaders: responseRawHeaders(headers)
      })
      current = Object.freeze({ ...captured, generation: captured.generation + 1 })
      response.writeHead(200, { ...headers, ...signed.headers })
      response.end(challenge)
    })
    current = Object.freeze({
      bootToken: '33'.repeat(32),
      generation: 9,
      pid: 99,
      port
    })
    const client = new PaidMediaEngineSessionClient({ session: () => current, now: () => NOW })
    await expect(
      client.exchange(
        {
          method: 'POST',
          target: '/v1/images/generations',
          headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
          body: Buffer.from('{"prompt":"must-not-leak"}', 'utf8'),
          signal: new AbortController().signal,
          totalTimeoutMs: 1_000,
          firstByteTimeoutMs: 1_000
        },
        consumeBuffer
      )
    ).rejects.toThrow(/changed|challenge/i)
    expect(paths).toEqual([PAID_MEDIA_ENGINE_SESSION_CHALLENGE_PATH])
  })

  it('rejects an authenticated response that arrives before the streamed upload finishes', async () => {
    let session!: PaidMediaEngineSessionIdentity
    const payload = Buffer.alloc(128 * 1024, 0x51)
    let source!: Readable
    const { port } = await listen(async (request, response) => {
      if (request.url === PAID_MEDIA_ENGINE_SESSION_CHALLENGE_PATH) {
        sendChallenge(request, response, session, await readRequest(request))
        return
      }
      const verified = verifyPaidMediaEngineSessionRequest({
        session,
        rawHeaders: request.rawHeaders,
        nowMs: NOW,
        method: request.method ?? '',
        target: request.url ?? '',
        bodySha256: digest(payload)
      })
      const result = Buffer.from('{"tooEarly":true}', 'utf8')
      sendSigned(response, session, verified.nonce, 200, result, {
        'Content-Type': 'application/json',
        'Content-Length': String(result.length),
        'Cache-Control': 'no-store',
        Connection: 'close'
      })
    })
    session = Object.freeze({
      bootToken: '34'.repeat(32),
      generation: 1,
      pid: 1,
      port
    })
    const client = new PaidMediaEngineSessionClient({ session: () => session, now: () => NOW })
    let emitted = false
    source = new Readable({
      read() {
        if (emitted) return
        emitted = true
        this.push(payload.subarray(0, 1))
      }
    })
    await expect(
      client.exchange(
        {
          method: 'POST',
          target: '/v1/paid-media/probe',
          headers: { Accept: 'application/json', 'Content-Type': 'image/png' },
          body: {
            byteLength: payload.length,
            sha256: digest(payload),
            createReadStream: () => source
          },
          signal: new AbortController().signal,
          totalTimeoutMs: 1_000,
          firstByteTimeoutMs: 1_000
        },
        consumeBuffer
      )
    ).rejects.toThrow(/authentication|transport/i)
    expect(source.destroyed).toBe(true)
  })

  it('destroys a hanging streamed source on cancellation', async () => {
    let session!: PaidMediaEngineSessionIdentity
    const { port } = await listen(async (request, response) => {
      if (request.url === PAID_MEDIA_ENGINE_SESSION_CHALLENGE_PATH) {
        sendChallenge(request, response, session, await readRequest(request))
        return
      }
      request.resume()
    })
    session = Object.freeze({
      bootToken: '35'.repeat(32),
      generation: 1,
      pid: 1,
      port
    })
    const client = new PaidMediaEngineSessionClient({ session: () => session, now: () => NOW })
    const controller = new AbortController()
    let markStarted!: () => void
    const started = new Promise<void>((resolve) => {
      markStarted = resolve
    })
    let emitted = false
    const source = new Readable({
      read() {
        if (emitted) return
        emitted = true
        this.push(Buffer.from('x'))
        markStarted()
      }
    })
    const pending = client.exchange(
      {
        method: 'POST',
        target: '/v1/paid-media/probe',
        headers: { Accept: 'application/json', 'Content-Type': 'image/png' },
        body: {
          byteLength: 2,
          sha256: digest('xy'),
          createReadStream: () => source
        },
        signal: controller.signal,
        totalTimeoutMs: 1_000,
        firstByteTimeoutMs: 1_000
      },
      consumeBuffer
    )
    await started
    controller.abort()
    await expect(pending).rejects.toBeInstanceOf(PaidMediaEngineSessionClientError)
    expect(source.destroyed).toBe(true)
  })

  it('expires a hanging request only when the injected total-timeout policy fires', async () => {
    let session!: PaidMediaEngineSessionIdentity
    const { port } = await listen(async (request, response) => {
      if (request.url === PAID_MEDIA_ENGINE_SESSION_CHALLENGE_PATH) {
        sendChallenge(request, response, session, await readRequest(request))
        return
      }
      request.resume()
    })
    session = Object.freeze({
      bootToken: '36'.repeat(32),
      generation: 1,
      pid: 1,
      port
    })
    const timeouts = controlledTimeoutPolicy()
    const client = new PaidMediaEngineSessionClient({
      session: () => session,
      now: () => NOW,
      scheduleTotalTimeout: timeouts.schedule
    })
    const controller = new AbortController()
    let markStarted!: () => void
    const started = new Promise<void>((resolve) => {
      markStarted = resolve
    })
    let emitted = false
    const source = new Readable({
      read() {
        if (emitted) return
        emitted = true
        this.push(Buffer.from('x'))
        markStarted()
      }
    })
    const pending = client.exchange(
      {
        method: 'POST',
        target: '/v1/paid-media/probe',
        headers: { Accept: 'application/json', 'Content-Type': 'image/png' },
        body: {
          byteLength: 2,
          sha256: digest('xy'),
          createReadStream: () => source
        },
        signal: controller.signal,
        totalTimeoutMs: 60_000,
        firstByteTimeoutMs: 60_000
      },
      consumeBuffer
    )

    try {
      await started
      expect(timeouts.activeDelays()).toEqual([60_000])
      timeouts.fire(60_000)
      await expect(pending).rejects.toThrow(/total timeout/i)
      expect(source.destroyed).toBe(true)
    } finally {
      controller.abort()
      await pending.catch(() => undefined)
    }
  })

  it('rejects response-contract injection after a valid signed request', async () => {
    let session!: PaidMediaEngineSessionIdentity
    const { port } = await listen(async (request, response) => {
      const body = await readRequest(request)
      if (request.url === PAID_MEDIA_ENGINE_SESSION_CHALLENGE_PATH) {
        sendChallenge(request, response, session, body)
        return
      }
      const verified = verifyRequest(request, session, body)
      const result = Buffer.from('{"ok":true}', 'utf8')
      sendSigned(
        response,
        session,
        verified.nonce,
        200,
        result,
        {
          'Content-Type': 'application/json',
          'Content-Length': String(result.length),
          'Cache-Control': 'no-store',
          Connection: 'close'
        },
        (headers) => {
          headers['Retry-After'] = '1'
        }
      )
    })
    session = Object.freeze({
      bootToken: '44'.repeat(32),
      generation: 1,
      pid: 1,
      port
    })
    const client = new PaidMediaEngineSessionClient({ session: () => session, now: () => NOW })
    await expect(
      client.exchange(
        {
          method: 'POST',
          target: '/v1/images/generations',
          headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
          body: Buffer.from('{}'),
          signal: new AbortController().signal,
          totalTimeoutMs: 1_000,
          firstByteTimeoutMs: 1_000
        },
        consumeBuffer
      )
    ).rejects.toThrow(/authentication/i)
  })

  it('rejects a body that differs from the digest signed in the response envelope', async () => {
    let session!: PaidMediaEngineSessionIdentity
    const { port } = await listen(async (request, response) => {
      const body = await readRequest(request)
      if (request.url === PAID_MEDIA_ENGINE_SESSION_CHALLENGE_PATH) {
        sendChallenge(request, response, session, body)
        return
      }
      const verified = verifyRequest(request, session, body)
      const declared = Buffer.from('trusted-body', 'utf8')
      const delivered = Buffer.from('changed-body', 'utf8')
      const headers = {
        'Content-Type': 'application/octet-stream',
        'Content-Length': String(delivered.length),
        'Cache-Control': 'no-store',
        Connection: 'close'
      }
      const signed = signPaidMediaEngineSessionResponse({
        session,
        requestNonce: verified.nonce,
        status: 200,
        bodySha256: digest(declared),
        rawHeaders: responseRawHeaders(headers)
      })
      response.writeHead(200, { ...headers, ...signed.headers })
      response.end(delivered)
    })
    session = Object.freeze({
      bootToken: '55'.repeat(32),
      generation: 1,
      pid: 1,
      port
    })
    const client = new PaidMediaEngineSessionClient({ session: () => session, now: () => NOW })
    await expect(
      client.exchange(
        {
          method: 'GET',
          target: '/v1/paid-media/assets/nma1_' + 'A'.repeat(43),
          headers: { Accept: 'application/octet-stream', 'Accept-Encoding': 'identity' },
          body: Buffer.alloc(0),
          signal: new AbortController().signal,
          totalTimeoutMs: 1_000,
          firstByteTimeoutMs: 1_000
        },
        consumeBuffer
      )
    ).rejects.toThrow(/authentication/i)
  })

  it('keeps total and body-idle timeouts independent', async () => {
    let session!: PaidMediaEngineSessionIdentity
    let mode: 'drip' | 'idle' = 'drip'
    let markResponseStarted!: () => void
    const responseStarted = new Promise<void>((resolve) => {
      markResponseStarted = resolve
    })
    const payload = Buffer.alloc(16, 0x31)
    const { port } = await listen(async (request, response) => {
      const body = await readRequest(request)
      if (request.url === PAID_MEDIA_ENGINE_SESSION_CHALLENGE_PATH) {
        sendChallenge(request, response, session, body)
        return
      }
      const verified = verifyRequest(request, session, body)
      const headers = {
        'Content-Type': 'application/octet-stream',
        'Content-Length': String(payload.length),
        'Cache-Control': 'no-store',
        Connection: 'close'
      }
      const signed = signPaidMediaEngineSessionResponse({
        session,
        requestNonce: verified.nonce,
        status: 200,
        bodySha256: digest(payload),
        rawHeaders: responseRawHeaders(headers)
      })
      response.writeHead(200, { ...headers, ...signed.headers })
      response.write(payload.subarray(0, 1))
      markResponseStarted()
      if (mode === 'idle') return
      let offset = 1
      const timer = setInterval(() => {
        if (response.destroyed || offset >= payload.length) {
          clearInterval(timer)
          if (!response.destroyed) response.end()
          return
        }
        response.write(payload.subarray(offset, offset + 1))
        offset += 1
      }, 20)
      timer.unref()
      response.once('close', () => clearInterval(timer))
    })
    session = Object.freeze({
      bootToken: '66'.repeat(32),
      generation: 1,
      pid: 1,
      port
    })
    const timeouts = controlledTimeoutPolicy()
    const client = new PaidMediaEngineSessionClient({
      session: () => session,
      now: () => NOW,
      bodyIdleTimeoutMs: 50,
      scheduleTotalTimeout: timeouts.schedule
    })
    const totalPending = client.exchange(
      {
        method: 'GET',
        target: '/v1/paid-media/assets/nma1_' + 'A'.repeat(43),
        headers: { Accept: 'application/octet-stream', 'Accept-Encoding': 'identity' },
        body: Buffer.alloc(0),
        signal: new AbortController().signal,
        totalTimeoutMs: 60_000,
        firstByteTimeoutMs: 60_000,
        bodyIdleTimeoutMs: 60
      },
      consumeBuffer
    )
    await responseStarted
    expect(timeouts.activeDelays()).toEqual([60_000])
    timeouts.fire(60_000)
    await expect(totalPending).rejects.toThrow(/total timeout/i)

    mode = 'idle'
    await expect(
      client.exchange(
        {
          method: 'GET',
          target: '/v1/paid-media/assets/nma1_' + 'B'.repeat(43),
          headers: { Accept: 'application/octet-stream', 'Accept-Encoding': 'identity' },
          body: Buffer.alloc(0),
          signal: new AbortController().signal,
          totalTimeoutMs: 2_000,
          // Keep the header budget comfortably above loaded-CI scheduling;
          // this branch is specifically proving post-header body-idle.
          firstByteTimeoutMs: 1_000,
          bodyIdleTimeoutMs: 50
        },
        consumeBuffer
      )
    ).rejects.toThrow(/body timed out|authentication/i)
    expect(timeouts.activeDelays()).toEqual([])
  })
})
