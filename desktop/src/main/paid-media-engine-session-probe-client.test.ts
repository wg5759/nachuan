import { createHash } from 'node:crypto'
import type { IncomingMessage } from 'node:http'
import { Readable } from 'node:stream'

import { describe, expect, it } from 'vitest'

import {
  PAID_MEDIA_ASSET_PROTOCOL_HEADER,
  type PaidMediaAssetDescriptor
} from './paid-media-asset-protocol'
import type {
  PaidMediaEngineSessionClient,
  PaidMediaEngineSessionConsumed,
  PaidMediaEngineSessionExchangeInput,
  PaidMediaEngineSessionResponse
} from './paid-media-engine-session-client'
import {
  PaidMediaEngineSessionProbeClientError,
  probePaidMediaStagedAsset
} from './paid-media-engine-session-probe-client'

function sha256(value: Buffer | string): string {
  return createHash('sha256').update(value).digest('hex')
}

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

function validation(bytes: Buffer) {
  const base = {
    schema: 'nachuan.trusted-media-validation.v2',
    validatorVersion: 'nachuan.trusted-media-probe.v2',
    validationPolicy: 'nachuan.trusted-media-policy.av-closed.v1',
    fullyDecoded: true,
    mediaType: 'image/png',
    byteLength: bytes.length,
    sha256: sha256(bytes),
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

function responseHeaders(body: Buffer, extra: string[] = []): string[] {
  return [
    'Content-Type',
    'application/json',
    'Content-Length',
    String(body.length),
    'Cache-Control',
    'no-store',
    PAID_MEDIA_ASSET_PROTOCOL_HEADER,
    '2',
    ...extra
  ]
}

class FakeSessionClient implements Pick<PaidMediaEngineSessionClient, 'exchange'> {
  readonly calls: PaidMediaEngineSessionExchangeInput[] = []

  constructor(
    private readonly status: number,
    private readonly body: Buffer,
    private readonly headers = responseHeaders(body)
  ) {}

  async exchange<T>(
    input: PaidMediaEngineSessionExchangeInput,
    consume: (
      response: PaidMediaEngineSessionResponse
    ) => Promise<PaidMediaEngineSessionConsumed<T>>
  ): Promise<T> {
    this.calls.push(input)
    const stream = Readable.from([this.body]) as unknown as IncomingMessage
    Object.assign(stream, {
      statusCode: this.status,
      rawHeaders: this.headers,
      rawTrailers: [],
      complete: true
    })
    const result = await consume({
      status: this.status,
      rawHeaders: this.headers,
      response: stream,
      declaredBodySha256: sha256(this.body)
    })
    expect(result.bodySha256).toBe(sha256(this.body))
    return result.value
  }
}

function fixture() {
  const bytes = Buffer.from('validated-image-bytes')
  const receipt = validation(bytes)
  const descriptor: PaidMediaAssetDescriptor = {
    token: `nma1_${'A'.repeat(43)}`,
    mediaType: 'image/png',
    byteLength: bytes.length,
    sha256: sha256(bytes),
    validationReceiptSha256: receipt.receiptSha256
  }
  return { bytes, receipt, descriptor }
}

describe('paid media engine-session probe client', () => {
  it('passes a lazy file-backed source without releasing any long-term key', async () => {
    const { bytes, receipt, descriptor } = fixture()
    const client = new FakeSessionClient(200, Buffer.from(JSON.stringify(receipt)))
    let sourceCreated = 0
    const result = await probePaidMediaStagedAsset({
      sessionClient: client,
      descriptor,
      source: {
        createReadStream: () => {
          sourceCreated += 1
          return Readable.from([bytes])
        }
      },
      signal: new AbortController().signal
    })

    expect(result.receiptSha256).toBe(descriptor.validationReceiptSha256)
    expect(client.calls).toHaveLength(1)
    expect(client.calls[0]).toMatchObject({
      method: 'POST',
      target: '/v1/paid-media/probe',
      body: {
        byteLength: descriptor.byteLength,
        sha256: descriptor.sha256
      },
      totalTimeoutMs: 300_000,
      firstByteTimeoutMs: 300_000
    })
    expect(sourceCreated).toBe(0)
    expect(client.calls[0]!.headers).toMatchObject({
      'Content-Type': descriptor.mediaType,
      'X-Nachuan-Media-Byte-Length': String(descriptor.byteLength),
      'X-Nachuan-Media-SHA256': descriptor.sha256,
      [PAID_MEDIA_ASSET_PROTOCOL_HEADER]: '2'
    })
    expect(Object.keys(client.calls[0]!.headers).join(' ')).not.toMatch(
      /authorization|paid-media-key/i
    )
  })

  it('rejects a validation receipt that is not the one bound to the asset descriptor', async () => {
    const { bytes, receipt, descriptor } = fixture()
    const client = new FakeSessionClient(200, Buffer.from(JSON.stringify(receipt)))
    await expect(
      probePaidMediaStagedAsset({
        sessionClient: client,
        descriptor: { ...descriptor, validationReceiptSha256: 'f'.repeat(64) },
        source: { createReadStream: () => Readable.from([bytes]) },
        signal: new AbortController().signal
      })
    ).rejects.toThrow('does not match the Gateway asset authority')
  })

  it('rejects non-v2 or transformed responses before accepting probe evidence', async () => {
    const { bytes, receipt, descriptor } = fixture()
    const body = Buffer.from(JSON.stringify(receipt))
    const headers = responseHeaders(body, ['Content-Encoding', 'gzip'])
    const client = new FakeSessionClient(200, body, headers)
    await expect(
      probePaidMediaStagedAsset({
        sessionClient: client,
        descriptor,
        source: { createReadStream: () => Readable.from([bytes]) },
        signal: new AbortController().signal
      })
    ).rejects.toThrow(PaidMediaEngineSessionProbeClientError)
  })

  it('returns a fixed rejection for a signed non-success response', async () => {
    const { bytes, descriptor } = fixture()
    const body = Buffer.from('{"detail":"closed"}')
    const client = new FakeSessionClient(503, body)
    await expect(
      probePaidMediaStagedAsset({
        sessionClient: client,
        descriptor,
        source: { createReadStream: () => Readable.from([bytes]) },
        signal: new AbortController().signal
      })
    ).rejects.toThrow('Paid media staged probe was rejected')
  })
})
