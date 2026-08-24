import { createHash } from 'node:crypto'
import { Readable, Writable } from 'node:stream'
import type { ClientRequest, IncomingMessage, RequestOptions } from 'node:http'
import { describe, expect, it, vi } from 'vitest'

import {
  PaidMediaProbeClient,
  createNodePaidMediaProbeTransport,
  parsePaidMediaValidationReceipt,
  type PaidMediaProbeTransportRequest
} from './paid-media-probe-client'

const RUNTIME_KEY = 'runtime-secret'
const PAID_KEY = `sk-paid-media-${'c'.repeat(64)}`

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>
    return `{${Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
      .join(',')}}`
  }
  return JSON.stringify(value)
}

function validation(raw: Buffer) {
  const base = {
    schema: 'nachuan.trusted-media-validation.v2',
    validatorVersion: 'nachuan.trusted-media-probe.v2',
    validationPolicy: 'nachuan.trusted-media-policy.av-closed.v1',
    fullyDecoded: true,
    mediaType: 'image/png',
    byteLength: raw.byteLength,
    sha256: createHash('sha256').update(raw).digest('hex'),
    attestedTools: {
      ffmpegSha256: '1'.repeat(64),
      ffprobeSha256: '2'.repeat(64)
    },
    metadata: {
      detectedKind: 'image',
      codecName: 'png',
      audioCodecName: null,
      videoStreamCount: 1,
      audioStreamCount: 0,
      formatName: 'png_pipe',
      width: 16,
      height: 16,
      durationMs: null,
      decodedFrames: 1
    }
  }
  return {
    ...base,
    receiptSha256: createHash('sha256')
      .update(Buffer.from('nachuan.trusted-media-validation.v2\0'))
      .update(Buffer.from(canonicalJson(base), 'ascii'))
      .digest('hex')
  }
}

describe('PaidMediaProbeClient', () => {
  it('requires exact dual authority and checks the attested readiness schema', async () => {
    const transport = vi.fn(async (request: PaidMediaProbeTransportRequest) => {
      expect(request.url).toBe('http://127.0.0.1:8080/v1/paid-media/probe/readiness')
      expect(request.method).toBe('GET')
      expect(request.headers.Authorization).toBe(`Bearer ${RUNTIME_KEY}`)
      expect(request.headers['X-Nachuan-Paid-Media-Key']).toBe(PAID_KEY)
      return {
        status: 200,
        contentType: 'application/json',
        body: Buffer.from(
          JSON.stringify({
            schema: 'nachuan.trusted-media-probe.readiness.v2',
            validatorVersion: 'nachuan.trusted-media-probe.v2',
            validationPolicy: 'nachuan.trusted-media-policy.av-closed.v1',
            ready: true,
            attestedTools: {
              ffmpegSha256: '1'.repeat(64),
              ffprobeSha256: '2'.repeat(64)
            }
          })
        )
      }
    })
    const client = new PaidMediaProbeClient({
      baseUrl: () => 'http://127.0.0.1:8080',
      runtimeKey: () => RUNTIME_KEY,
      paidMediaKey: () => PAID_KEY,
      transport
    })
    await expect(client.ensureReady()).resolves.toBeUndefined()
    expect(transport).toHaveBeenCalledOnce()

    const bad = new PaidMediaProbeClient({
      baseUrl: () => 'http://localhost:8080',
      runtimeKey: () => RUNTIME_KEY,
      paidMediaKey: () => PAID_KEY,
      transport
    })
    await expect(bad.ensureReady()).rejects.toThrow('exact loopback')
  })

  it('streams bytes with exact length/digest headers and verifies the full receipt', async () => {
    const raw = Buffer.from('\x89PNG\r\n\x1a\ntrusted')
    const digest = createHash('sha256').update(raw).digest('hex')
    let streamed = Buffer.alloc(0)
    const transport = vi.fn(async (request: PaidMediaProbeTransportRequest) => {
      expect(request.method).toBe('POST')
      expect(request.headers['Content-Type']).toBe('image/png')
      expect(request.headers['Content-Length']).toBe(String(raw.byteLength))
      expect(request.headers['X-Nachuan-Media-Byte-Length']).toBe(String(raw.byteLength))
      expect(request.headers['X-Nachuan-Media-SHA256']).toBe(digest)
      expect(request.body).toBeDefined()
      const chunks: Buffer[] = []
      for await (const chunk of request.body!.stream) chunks.push(Buffer.from(chunk))
      streamed = Buffer.concat(chunks)
      return {
        status: 200,
        contentType: 'application/json',
        body: Buffer.from(JSON.stringify(validation(raw)))
      }
    })
    const client = new PaidMediaProbeClient({
      baseUrl: () => 'http://127.0.0.1:8080/',
      runtimeKey: () => RUNTIME_KEY,
      paidMediaKey: () => PAID_KEY,
      transport
    })
    const receipt = await client.validate({
      createReadStream: () => Readable.from([raw]),
      mediaType: 'image/png',
      byteLength: raw.byteLength,
      sha256: digest
    })
    expect(streamed).toEqual(raw)
    expect(receipt.sha256).toBe(digest)
    expect(receipt.fullyDecoded).toBe(true)
    expect(receipt.receiptSha256).toMatch(/^[0-9a-f]{64}$/)
  })

  it('rejects extra fields, altered tool evidence, and a forged receipt digest', () => {
    const raw = Buffer.from('asset')
    const expected = {
      mediaType: 'image/png' as const,
      byteLength: raw.byteLength,
      sha256: createHash('sha256').update(raw).digest('hex')
    }
    const extra = { ...validation(raw), path: 'C:\\private\\asset.png' }
    expect(() =>
      parsePaidMediaValidationReceipt(Buffer.from(JSON.stringify(extra)), expected)
    ).toThrow('receipt is invalid')

    const forged = validation(raw)
    forged.attestedTools.ffmpegSha256 = '3'.repeat(64)
    expect(() =>
      parsePaidMediaValidationReceipt(Buffer.from(JSON.stringify(forged)), expected)
    ).toThrow('receipt digest is invalid')

    for (const mixed of [
      { ...validation(raw), schema: 'nachuan.trusted-media-validation.v1' },
      { ...validation(raw), validatorVersion: 'nachuan.trusted-media-probe.v1' },
      {
        ...validation(raw),
        validationPolicy: 'nachuan.trusted-media-policy.video-only.v1'
      }
    ]) {
      expect(() =>
        parsePaidMediaValidationReceipt(Buffer.from(JSON.stringify(mixed)), expected)
      ).toThrow('receipt is invalid')
    }
  })

  it('uses fatal UTF-8 and never exposes authority in transport errors', async () => {
    const transport = vi.fn(async () => ({
      status: 200,
      contentType: 'application/json',
      body: Buffer.from([0xff, 0xfe])
    }))
    const client = new PaidMediaProbeClient({
      baseUrl: () => 'http://127.0.0.1:8080',
      runtimeKey: () => RUNTIME_KEY,
      paidMediaKey: () => PAID_KEY,
      transport
    })
    let message = ''
    try {
      await client.ensureReady()
    } catch (error) {
      message = String(error)
    }
    expect(message).toContain('encoding is invalid')
    expect(message).not.toContain(RUNTIME_KEY)
    expect(message).not.toContain(PAID_KEY)
  })

  it('destroys a large pinned upload as soon as the server returns a terminal status', async () => {
    let destroyed = false
    class EndlessSource extends Readable {
      override _read(): void {
        this.push(Buffer.alloc(1024, 7))
      }

      override _destroy(error: Error | null, callback: (error?: Error | null) => void): void {
        destroyed = true
        callback(error)
      }
    }
    class FakeRequest extends Writable {
      setTimeout(): this {
        return this
      }

      override _write(
        _chunk: Buffer,
        _encoding: BufferEncoding,
        callback: (...args: any[]) => void
      ): void {
        callback()
      }
    }
    const source = new EndlessSource()
    const fakeFactory = (
      _url: string,
      _options: RequestOptions,
      callback: (response: IncomingMessage) => void
    ): ClientRequest => {
      const request = new FakeRequest()
      queueMicrotask(() => {
        const response = Readable.from([]) as IncomingMessage
        response.statusCode = 401
        response.headers = { 'content-type': 'application/json' }
        callback(response)
      })
      return request as unknown as ClientRequest
    }
    const transport = createNodePaidMediaProbeTransport(fakeFactory)
    const response = await transport({
      url: 'http://127.0.0.1:8080/v1/paid-media/probe',
      method: 'POST',
      headers: {},
      timeoutMs: 1000,
      responseByteLimit: 1024,
      body: { stream: source, byteLength: 1024 * 1024, sha256: '0'.repeat(64) }
    })
    expect(response.status).toBe(401)
    expect(destroyed).toBe(true)
  })
})
