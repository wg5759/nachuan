import { createHash } from 'node:crypto'
import type { IncomingMessage } from 'node:http'
import { Readable } from 'node:stream'

import { describe, expect, it, vi } from 'vitest'

import {
  PAID_MEDIA_ASSET_ACK_SCHEMA,
  PAID_MEDIA_ASSET_PROTOCOL_HEADER,
  PAID_MEDIA_ASSET_RESULT_SCHEMA,
  type PaidMediaAssetAck,
  type PaidMediaAssetDescriptor
} from './paid-media-asset-protocol'
import {
  type PaidMediaEngineSessionClient,
  type PaidMediaEngineSessionConsumed,
  type PaidMediaEngineSessionExchangeInput,
  type PaidMediaEngineSessionResponse
} from './paid-media-engine-session-client'
import {
  PaidMediaAssetClientError,
  PaidMediaAssetRemoteError,
  _paidMediaAssetClientTest,
  acknowledgePaidMediaAssets,
  createPaidMediaImageAssets,
  downloadPaidMediaAsset,
  parsePaidMediaAssetResultResponse,
  type PaidMediaAssetStageWriteCapability
} from './paid-media-asset-client'

function sha256(value: Buffer | string): string {
  return createHash('sha256').update(value).digest('hex')
}

function token(character = 'A'): string {
  return `nma1_${character.repeat(43)}`
}

function descriptor(bytes: Buffer): PaidMediaAssetDescriptor {
  return {
    token: token(),
    mediaType: 'image/png',
    byteLength: bytes.length,
    sha256: sha256(bytes),
    validationReceiptSha256: sha256('validation')
  }
}

function result(bytes: Buffer) {
  return {
    schema: PAID_MEDIA_ASSET_RESULT_SCHEMA,
    kind: 'image' as const,
    created: 1,
    turnId: sha256('turn'),
    assets: [descriptor(bytes)]
  }
}

function jsonRawResponse(value: unknown, options: {
  status?: number
  extra?: string[]
  includeProtocol?: boolean
  rawTrailers?: string[]
} = {}) {
  const body = Buffer.from(JSON.stringify(value), 'utf8')
  return {
    status: options.status ?? 200,
    rawHeaders: [
      'Content-Type',
      'application/json',
      'Content-Length',
      String(body.length),
      'Cache-Control',
      'no-store',
      ...(options.includeProtocol === false
        ? []
        : [PAID_MEDIA_ASSET_PROTOCOL_HEADER, '2']),
      ...(options.extra ?? [])
    ],
    rawTrailers: options.rawTrailers ?? [],
    body
  }
}

interface FakeResponse {
  status: number
  rawHeaders: string[]
  body: Buffer
  chunks?: Buffer[]
  rawTrailers?: string[]
}

class FakeSessionClient implements Pick<PaidMediaEngineSessionClient, 'exchange'> {
  readonly calls: PaidMediaEngineSessionExchangeInput[] = []

  constructor(private readonly queued: FakeResponse[]) {}

  async exchange<T>(
    input: PaidMediaEngineSessionExchangeInput,
    consume: (
      response: PaidMediaEngineSessionResponse
    ) => Promise<PaidMediaEngineSessionConsumed<T>>
  ): Promise<T> {
    this.calls.push(input)
    const next = this.queued.shift()
    if (!next) throw new Error('fake session response is missing')
    const stream = Readable.from(next.chunks ?? [next.body]) as unknown as IncomingMessage
    Object.assign(stream, {
      statusCode: next.status,
      rawHeaders: next.rawHeaders,
      rawTrailers: next.rawTrailers ?? [],
      complete: true
    })
    const consumed = await consume({
      status: next.status,
      rawHeaders: next.rawHeaders,
      response: stream,
      declaredBodySha256: sha256(next.body)
    })
    if (consumed.bodySha256 !== sha256(next.body)) {
      throw new Error('fake response digest mismatch')
    }
    return consumed.value
  }
}

function fakeStage(
  expected: PaidMediaAssetDescriptor,
  options: { maximumWrite?: number; stall?: boolean } = {}
): PaidMediaAssetStageWriteCapability & { bytes: Buffer; sync: ReturnType<typeof vi.fn> } {
  const bytes = Buffer.alloc(expected.byteLength)
  const sync = vi.fn(async () => undefined)
  return {
    leaseId: 'a'.repeat(64),
    operationId: 'desktop-op-12345678-1234-1234-1234-123456789abc',
    turnId: sha256('turn'),
    ordinal: 0,
    descriptor: expected,
    bytes,
    async write(raw, position) {
      if (options.stall) return { bytesWritten: 0 }
      const source = Buffer.from(raw)
      const count = Math.min(source.length, options.maximumWrite ?? source.length)
      source.copy(bytes, position, 0, count)
      return { bytesWritten: count }
    },
    sync
  }
}

function assetResponse(bytes: Buffer, expected = descriptor(bytes), extra: string[] = []): FakeResponse {
  return {
    status: 200,
    rawHeaders: [
      'Content-Type',
      expected.mediaType,
      'Content-Length',
      String(bytes.length),
      'X-Content-SHA256',
      expected.sha256,
      'Cache-Control',
      'no-store',
      'X-Content-Type-Options',
      'nosniff',
      PAID_MEDIA_ASSET_PROTOCOL_HEADER,
      '2',
      ...extra
    ],
    body: bytes,
    chunks: [bytes.subarray(0, 3), bytes.subarray(3)]
  }
}

describe('paid media asset client v2', () => {
  it('strictly decodes bounded UTF-8 metadata with one protocol header', () => {
    const bytes = Buffer.from('image-bytes')
    expect(parsePaidMediaAssetResultResponse(jsonRawResponse(result(bytes)), 'image')).toEqual(
      result(bytes)
    )

    const duplicated = jsonRawResponse(result(bytes), {
      extra: [PAID_MEDIA_ASSET_PROTOCOL_HEADER, '2']
    })
    expect(() => parsePaidMediaAssetResultResponse(duplicated, 'image')).toThrow(/ambiguous/i)

    const invalidUtf8 = jsonRawResponse(result(bytes))
    invalidUtf8.body = Buffer.from([0xc3, 0x28])
    invalidUtf8.rawHeaders[3] = '2'
    expect(() => parsePaidMediaAssetResultResponse(invalidUtf8, 'image')).toThrow(/UTF-8/i)

    expect(() =>
      parsePaidMediaAssetResultResponse(
        jsonRawResponse(result(bytes), { rawTrailers: ['X-Late', 'value'] }),
        'image'
      )
    ).toThrow(/trailers/i)
  })

  it('streams into only the Vault write capability and never sends long-term keys', async () => {
    const bytes = Buffer.concat([
      Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
      Buffer.alloc(64 * 1024, 0x5a)
    ])
    const expected = descriptor(bytes)
    const stage = fakeStage(expected, { maximumWrite: 4093 })
    const sessionClient = new FakeSessionClient([assetResponse(bytes, expected)])
    await expect(
      downloadPaidMediaAsset({
        sessionClient,
        stage,
        signal: new AbortController().signal
      })
    ).resolves.toEqual({ descriptor: expected, byteLength: bytes.length, sha256: expected.sha256 })
    expect(stage.bytes).toEqual(bytes)
    expect(stage.sync).toHaveBeenCalledTimes(1)
    expect(sessionClient.calls).toHaveLength(1)
    expect(sessionClient.calls[0].target).toBe(`/v1/paid-media/assets/${expected.token}`)
    expect(sessionClient.calls[0].headers).not.toHaveProperty('Authorization')
    expect(sessionClient.calls[0].headers).not.toHaveProperty('X-Nachuan-Paid-Media-Key')
    expect(sessionClient.calls[0].firstByteTimeoutMs).toBe(20_000)
  })

  it('creates image assets with provider TTFB governed by the total deadline', async () => {
    const bytes = Buffer.from('asset')
    const assetResult = result(bytes)
    const success = jsonRawResponse(assetResult, {
      extra: ['Idempotency-Replayed', 'false']
    })
    const client = new FakeSessionClient([success])
    await expect(
      createPaidMediaImageAssets({
        sessionClient: client,
        encodedBody: JSON.stringify({ model: 'image-model', prompt: 'hello' }),
        idempotencyKey: 'desktop-op-1234567890',
        signal: new AbortController().signal,
        timeoutMs: 90_000
      })
    ).resolves.toEqual({ ok: true, status: 200, replayed: false, result: assetResult })
    expect(client.calls[0].firstByteTimeoutMs).toBe(90_000)
    expect(client.calls[0].totalTimeoutMs).toBe(90_000)
    expect(client.calls[0].headers).not.toHaveProperty('Authorization')
    expect(client.calls[0].headers['Idempotency-Key']).toBe('desktop-op-1234567890')
  })

  it('requires the v2 contract even on closed Gateway errors', async () => {
    const error = {
      detail: {
        code: 'media_capacity_exhausted',
        message: 'Paid media capacity is unavailable.',
        retryable: true
      }
    }
    const valid = jsonRawResponse(error, {
      status: 429,
      extra: ['Retry-After', '3']
    })
    await expect(
      createPaidMediaImageAssets({
        sessionClient: new FakeSessionClient([valid]),
        encodedBody: '{"model":"image-model","prompt":"hello"}',
        idempotencyKey: 'desktop-op-1234567890',
        signal: new AbortController().signal
      })
    ).resolves.toEqual({
      ok: false,
      status: 429,
      code: 'media_capacity_exhausted',
      retryable: true,
      retryAfterSeconds: 3
    })

    const downgraded = jsonRawResponse(error, { status: 429, includeProtocol: false })
    await expect(
      createPaidMediaImageAssets({
        sessionClient: new FakeSessionClient([downgraded]),
        encodedBody: '{"model":"image-model","prompt":"hello"}',
        idempotencyKey: 'desktop-op-1234567890',
        signal: new AbortController().signal
      })
    ).rejects.toThrow(/protocol/i)
  })

  it('rejects ambiguous or transformed assets before writing stage bytes', async () => {
    const bytes = Buffer.from('asset')
    const expected = descriptor(bytes)
    for (const extra of [
      ['X-Content-SHA256', expected.sha256],
      ['Content-Encoding', 'gzip'],
      ['Transfer-Encoding', 'chunked'],
      ['Trailer', 'X-Late'],
      ['Upgrade', 'websocket']
    ]) {
      const stage = fakeStage(expected)
      await expect(
        downloadPaidMediaAsset({
          sessionClient: new FakeSessionClient([assetResponse(bytes, expected, extra)]),
          stage,
          signal: new AbortController().signal
        })
      ).rejects.toBeInstanceOf(PaidMediaAssetClientError)
      expect(stage.bytes).toEqual(Buffer.alloc(bytes.length))
      expect(stage.sync).not.toHaveBeenCalled()
    }
  })

  it('does not expose an opaque token from a failed session transport', async () => {
    const bytes = Buffer.from('asset')
    const expected = descriptor(bytes)
    const sessionClient = {
      async exchange(): Promise<never> {
        throw new Error(`transport failed at /assets/${expected.token}`)
      }
    } as Pick<PaidMediaEngineSessionClient, 'exchange'>
    let failure: unknown
    try {
      await downloadPaidMediaAsset({
        sessionClient,
        stage: fakeStage(expected),
        signal: new AbortController().signal
      })
    } catch (error) {
      failure = error
    }
    expect(failure).toBeInstanceOf(PaidMediaAssetClientError)
    const exposed = failure as Error & { cause?: unknown }
    expect(`${exposed.message}\n${exposed.stack ?? ''}\n${String(exposed.cause ?? '')}`).not.toContain(
      expected.token
    )
  })

  it('treats a stalled stage writer as a durable-lease failure without path cleanup', async () => {
    const bytes = Buffer.from('asset')
    const expected = descriptor(bytes)
    const stage = fakeStage(expected, { stall: true })
    await expect(
      downloadPaidMediaAsset({
        sessionClient: new FakeSessionClient([assetResponse(bytes, expected)]),
        stage,
        signal: new AbortController().signal
      })
    ).rejects.toThrow(/authentication|staging/i)
    expect(stage.sync).not.toHaveBeenCalled()
    expect(stage).not.toHaveProperty('path')
    expect(stage).not.toHaveProperty('dispose')
  })

  it('returns closed ACK success and typed non-2xx outcomes without clearing local state', async () => {
    const ack: PaidMediaAssetAck = {
      schema: PAID_MEDIA_ASSET_ACK_SCHEMA,
      turnId: sha256('turn'),
      tokens: [token()],
      archiveReceiptSha256: sha256('archive')
    }
    const pending = jsonRawResponse(
      { ok: false, turnId: ack.turnId, replayed: true, cleanupComplete: false },
      { status: 202, extra: ['Retry-After', '1'] }
    )
    await expect(
      acknowledgePaidMediaAssets({
        sessionClient: new FakeSessionClient([pending]),
        ack,
        signal: new AbortController().signal
      })
    ).resolves.toEqual({ ok: true, cleanupComplete: false, replayed: true })

    const unavailable = jsonRawResponse(
      {
        detail: {
          code: 'asset_cleanup_unavailable',
          message: 'Cleanup is temporarily unavailable.',
          retryable: true
        }
      },
      { status: 503, extra: ['Retry-After', '2'] }
    )
    await expect(
      acknowledgePaidMediaAssets({
        sessionClient: new FakeSessionClient([unavailable]),
        ack,
        signal: new AbortController().signal
      })
    ).resolves.toEqual({
      ok: false,
      status: 503,
      code: 'asset_cleanup_unavailable',
      retryable: true,
      retryAfterSeconds: 2
    })

    const mismatched = jsonRawResponse({
      ok: true,
      turnId: sha256('other-turn'),
      replayed: false,
      cleanupComplete: true
    })
    expect(() => _paidMediaAssetClientTest.parseAckResponse(mismatched, ack)).toThrow(
      /authority/i
    )
  })

  it('surfaces a typed authenticated download rejection without leaking its token', async () => {
    const bytes = Buffer.from('asset')
    const expected = descriptor(bytes)
    const error = jsonRawResponse(
      {
        detail: {
          code: 'asset_not_available',
          message: 'Asset is not available.',
          retryable: false
        }
      },
      { status: 410 }
    )
    await expect(
      downloadPaidMediaAsset({
        sessionClient: new FakeSessionClient([error]),
        stage: fakeStage(expected),
        signal: new AbortController().signal
      })
    ).rejects.toMatchObject({
      name: 'PaidMediaAssetRemoteError',
      status: 410,
      code: 'asset_not_available',
      retryable: false
    } satisfies Partial<PaidMediaAssetRemoteError>)
  })
})
