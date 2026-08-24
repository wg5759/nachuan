import { describe, expect, it } from 'vitest'

import {
  DESKTOP_ENGINE_SESSION_HEADERS,
  deriveDesktopEngineSessionKey,
  signDesktopEngineSessionRequest,
  signDesktopEngineSessionResponse,
  verifyDesktopEngineSessionRequest,
  verifyDesktopEngineSessionResponse
} from './desktop-engine-session-protocol'

const session = Object.freeze({
  bootToken: '11'.repeat(32),
  generation: 7,
  pid: 4242,
  port: 43111
})

const requestHeaders = [
  'Host',
  '127.0.0.1:43111',
  'Connection',
  'close',
  'Content-Length',
  '2',
  'Accept',
  'application/json',
  'Accept-Encoding',
  'identity',
  'Cache-Control',
  'no-store',
  'Content-Type',
  'application/json'
]

describe('desktop engine-session protocol', () => {
  it('derives a domain-separated key that cannot overlap the paid-media session domain', () => {
    expect(deriveDesktopEngineSessionKey('11'.repeat(32)).toString('hex')).toBe(
      '44455a72ce95d106649f0e305f5c1e123996a7be51587dc9fd4a334a92abfec6'
    )
  })

  it('signs and verifies a capability-bound request using the cross-language frame', () => {
    const signed = signDesktopEngineSessionRequest({
      session,
      timestampMs: 1_800_000_000_000,
      nonce: '22'.repeat(32),
      channelNonce: '33'.repeat(32),
      capability: 'sync.run',
      method: 'POST',
      target: '/v1/sync/run',
      bodySha256: '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a',
      rawHeaders: requestHeaders
    })

    expect(signed.contractSha256).toBe(
      '48df1e1f6691e8f9647a7bc1be24457a98e0b11d3fc4341c26c36c8b14e78926'
    )
    expect(signed.signature).toBe(
      '708a022463984085bd1adcaee63bbe771913847587ec4202ff7ffe59fca9ac30'
    )
    expect(Object.keys(signed.headers).every((name) => name.startsWith('X-Nachuan-Engine-Session-'))).toBe(true)
    expect(signed.headers[DESKTOP_ENGINE_SESSION_HEADERS.capability]).toBe('sync.run')
    expect(
      verifyDesktopEngineSessionRequest({
        session,
        rawHeaders: [
          ...requestHeaders,
          ...Object.entries(signed.headers).flatMap(([name, value]) => [name, value])
        ],
        nowMs: 1_800_000_000_100,
        capability: 'sync.run',
        method: 'POST',
        target: '/v1/sync/run',
        bodySha256: signed.bodySha256
      })
    ).toMatchObject({
      nonce: '22'.repeat(32),
      channelNonce: '33'.repeat(32),
      capability: 'sync.run',
      generation: 7,
      pid: 4242,
      port: 43111
    })
  })

  it('authenticates the exact JSON response body, capability, status and controllable headers', () => {
    const responseHeaders = [
      'Content-Type',
      'application/json',
      'Content-Length',
      '11',
      'Cache-Control',
      'no-store',
      'Connection',
      'close'
    ]
    const signed = signDesktopEngineSessionResponse({
      session,
      requestNonce: '22'.repeat(32),
      capability: 'sync.run',
      status: 200,
      bodySha256: '4062edaf750fb8074e7e83e0c9028c94e32468a8b6f1614774328ef045150f93',
      rawHeaders: responseHeaders
    })

    expect(signed.contractSha256).toBe(
      'b292f18cd442dfeff7333ff5d30aaf56fde3cfbef81b6f84e54d59e0006e30a3'
    )
    expect(signed.signature).toBe(
      '1de2ac7f407d6747997d76fb2f77575e428c5f2f9fcbc2e77bbbdc1730847655'
    )
    expect(
      verifyDesktopEngineSessionResponse({
        session,
        requestNonce: '22'.repeat(32),
        capability: 'sync.run',
        status: 200,
        bodySha256: signed.bodySha256,
        rawHeaders: [
          ...responseHeaders,
          ...Object.entries(signed.headers).flatMap(([name, value]) => [name, value]),
          'Date',
          'Fri, 17 Jul 2026 00:00:00 GMT',
          'Server',
          'uvicorn'
        ]
      })
    ).toMatchObject({
      requestNonce: '22'.repeat(32),
      capability: 'sync.run',
      status: 200,
      declaredBodySha256: signed.bodySha256
    })
  })
})
