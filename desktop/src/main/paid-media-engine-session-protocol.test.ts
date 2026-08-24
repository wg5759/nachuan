import { describe, expect, it } from 'vitest'

import {
  PAID_MEDIA_ENGINE_SESSION_CHALLENGE_JSON,
  PAID_MEDIA_ENGINE_SESSION_CHALLENGE_PATH,
  PAID_MEDIA_ENGINE_SESSION_CHALLENGE_SCHEMA,
  PAID_MEDIA_ENGINE_SESSION_DOMAINS,
  PAID_MEDIA_ENGINE_SESSION_HEADERS,
  PAID_MEDIA_ENGINE_SESSION_RESPONSE_CONTRACT_HEADERS,
  derivePaidMediaEngineSessionKey,
  paidMediaEngineSessionResponseContractSha256,
  signPaidMediaEngineSessionRequest,
  signPaidMediaEngineSessionResponse,
  verifyPaidMediaEngineSessionRequest,
  verifyPaidMediaEngineSessionResponse,
  verifyPaidMediaEngineSessionResponseEnvelope
} from './paid-media-engine-session-protocol'

const FIXTURE = Object.freeze({
  bootToken: '0123456789abcdef'.repeat(4),
  keyHex: '2ab8e2271856f482a50273325c27d147e2c42b555e76cc353ebd754796738abd',
  timestampMs: 1_784_200_123_456,
  nonce: '00112233445566778899aabbccddeeff'.repeat(2),
  generation: 7,
  pid: 43_210,
  port: 43_111,
  method: 'POST',
  target: '/v1/images/generations',
  requestBodySha256: 'd098eae8b6eed31982568318847fd7ca08be4394156a602fd806bc8e6af55ed2',
  requestContractSha256:
    'f88ab2d8b299797c298fb4d226ad7ff388f5d10c7221a224ca23bd90f6de6a63',
  requestSignature: '9bbf32b0bd7c65d3c5bae7fa75322b67257b78f36c0141d70e05e15e6807a852',
  responseStatus: 200,
  responseBodySha256: 'e2e9bbab138d978ba7ecf5ebb734fb873e7416b7187dd35c039876a54046db26',
  responseContractSha256:
    '2c1fc00755136e3b0a28400930edd033d6bc7f3018164d1132817af64fe60aa3',
  responseSignature: '127c1f5f15125c7eae3a665c519ed15010dade3990310ee2fa403c62c9991260'
})

const SESSION = Object.freeze({
  bootToken: FIXTURE.bootToken,
  generation: FIXTURE.generation,
  pid: FIXTURE.pid,
  port: FIXTURE.port
})

const REQUEST_CONTRACT_HEADERS = Object.freeze([
  'Content-Type',
  'application/json',
  'Content-Length',
  '40',
  'Accept',
  'application/json',
  'Accept-Encoding',
  'identity',
  'Cache-Control',
  'no-store',
  'Connection',
  'keep-alive',
  'Host',
  '127.0.0.1:43111',
  'X-Nachuan-Paid-Media-Protocol',
  '2',
  'Idempotency-Key',
  'desktop-op-1234567890'
])

function rawHeaders(headers: Readonly<Record<string, string>>): string[] {
  return Object.entries(headers).flatMap(([name, value]) => [name, value])
}

describe('paid media engine-session protocol v1', () => {
  it('derives an independent session key and signs the Python fixture request', () => {
    expect(PAID_MEDIA_ENGINE_SESSION_DOMAINS).toEqual({
      key: 'nachuan.paid-media.engine-session.key.v1',
      request: 'nachuan.paid-media.engine-session.request.v1',
      requestContract: 'nachuan.paid-media.engine-session.request-contract.v1',
      response: 'nachuan.paid-media.engine-session.response.v1',
      responseContract: 'nachuan.paid-media.engine-session.response-contract.v1'
    })
    expect(PAID_MEDIA_ENGINE_SESSION_CHALLENGE_PATH).toBe(
      '/internal/v1/paid-media/session/challenge'
    )
    expect(PAID_MEDIA_ENGINE_SESSION_CHALLENGE_SCHEMA).toBe(
      'nachuan.paid-media.engine-session.challenge.v1'
    )
    expect(PAID_MEDIA_ENGINE_SESSION_CHALLENGE_JSON).toBe(
      '{"schema":"nachuan.paid-media.engine-session.challenge.v1","ok":true}'
    )
    expect(derivePaidMediaEngineSessionKey(FIXTURE.bootToken).toString('hex')).toBe(
      FIXTURE.keyHex
    )

    const signed = signPaidMediaEngineSessionRequest({
      session: SESSION,
      timestampMs: FIXTURE.timestampMs,
      nonce: FIXTURE.nonce,
      method: FIXTURE.method,
      target: FIXTURE.target,
      bodySha256: FIXTURE.requestBodySha256,
      rawHeaders: REQUEST_CONTRACT_HEADERS
    })
    expect(signed.contractSha256).toBe(FIXTURE.requestContractSha256)
    expect(signed.signature).toBe(FIXTURE.requestSignature)
    expect(signed.headers).toEqual({
      [PAID_MEDIA_ENGINE_SESSION_HEADERS.protocol]: '1',
      [PAID_MEDIA_ENGINE_SESSION_HEADERS.timestampMs]: String(FIXTURE.timestampMs),
      [PAID_MEDIA_ENGINE_SESSION_HEADERS.nonce]: FIXTURE.nonce,
      [PAID_MEDIA_ENGINE_SESSION_HEADERS.generation]: String(FIXTURE.generation),
      [PAID_MEDIA_ENGINE_SESSION_HEADERS.pid]: String(FIXTURE.pid),
      [PAID_MEDIA_ENGINE_SESSION_HEADERS.port]: String(FIXTURE.port),
      [PAID_MEDIA_ENGINE_SESSION_HEADERS.bodySha256]: FIXTURE.requestBodySha256,
      [PAID_MEDIA_ENGINE_SESSION_HEADERS.requestContractSha256]:
        FIXTURE.requestContractSha256,
      [PAID_MEDIA_ENGINE_SESSION_HEADERS.signature]: FIXTURE.requestSignature
    })
  })

  it('verifies the exact request session and enforces the bounded timestamp window', () => {
    const signed = signPaidMediaEngineSessionRequest({
      session: SESSION,
      timestampMs: FIXTURE.timestampMs,
      nonce: FIXTURE.nonce,
      method: FIXTURE.method,
      target: FIXTURE.target,
      bodySha256: FIXTURE.requestBodySha256,
      rawHeaders: REQUEST_CONTRACT_HEADERS
    })
    const headers = [...REQUEST_CONTRACT_HEADERS, ...rawHeaders(signed.headers)]
    expect(
      verifyPaidMediaEngineSessionRequest({
        session: SESSION,
        rawHeaders: headers,
        nowMs: FIXTURE.timestampMs + 30_000,
        maxPastMs: 30_000,
        maxFutureMs: 5_000,
        method: FIXTURE.method,
        target: FIXTURE.target,
        bodySha256: FIXTURE.requestBodySha256
      })
    ).toEqual({
      timestampMs: FIXTURE.timestampMs,
      nonce: FIXTURE.nonce,
      generation: FIXTURE.generation,
      pid: FIXTURE.pid,
      port: FIXTURE.port,
      bodySha256: FIXTURE.requestBodySha256,
      contractSha256: FIXTURE.requestContractSha256
    })

    expect(() =>
      verifyPaidMediaEngineSessionRequest({
        session: SESSION,
        rawHeaders: headers,
        nowMs: FIXTURE.timestampMs + 30_001,
        method: FIXTURE.method,
        target: FIXTURE.target,
        bodySha256: FIXTURE.requestBodySha256
      })
    ).toThrow(/expired/i)
  })

  it('signs and verifies the streaming response fixture with its 14-header contract', () => {
    expect(PAID_MEDIA_ENGINE_SESSION_RESPONSE_CONTRACT_HEADERS).toEqual([
      'content-type',
      'content-length',
      'cache-control',
      'x-nachuan-paid-media-protocol',
      'idempotency-replayed',
      'retry-after',
      'x-content-sha256',
      'x-content-type-options',
      'content-encoding',
      'transfer-encoding',
      'content-range',
      'location',
      'trailer',
      'upgrade'
    ])
    const contractHeaders = [
      'Content-Type',
      'application/json',
      'Content-Length',
      '69',
      'Cache-Control',
      'no-store',
      'Connection',
      'keep-alive'
    ]
    expect(paidMediaEngineSessionResponseContractSha256(contractHeaders)).toBe(
      FIXTURE.responseContractSha256
    )
    const signed = signPaidMediaEngineSessionResponse({
      session: SESSION,
      requestNonce: FIXTURE.nonce,
      status: FIXTURE.responseStatus,
      bodySha256: FIXTURE.responseBodySha256,
      rawHeaders: contractHeaders
    })
    expect(signed.signature).toBe(FIXTURE.responseSignature)
    expect(signed.contractSha256).toBe(FIXTURE.responseContractSha256)
    const fullRawHeaders = [...contractHeaders, ...rawHeaders(signed.headers)]
    expect(
      verifyPaidMediaEngineSessionResponse({
        session: SESSION,
        requestNonce: FIXTURE.nonce,
        status: FIXTURE.responseStatus,
        bodySha256: FIXTURE.responseBodySha256,
        rawHeaders: fullRawHeaders
      })
    ).toEqual({
      requestNonce: FIXTURE.nonce,
      generation: FIXTURE.generation,
      pid: FIXTURE.pid,
      port: FIXTURE.port,
      status: FIXTURE.responseStatus,
      declaredBodySha256: FIXTURE.responseBodySha256,
      contractSha256: FIXTURE.responseContractSha256
    })
  })

  it('keeps the session raw-header namespace closed and unambiguous', () => {
    const signed = signPaidMediaEngineSessionRequest({
      session: SESSION,
      timestampMs: FIXTURE.timestampMs,
      nonce: FIXTURE.nonce,
      method: FIXTURE.method,
      target: FIXTURE.target,
      bodySha256: FIXTURE.requestBodySha256,
      rawHeaders: REQUEST_CONTRACT_HEADERS
    })
    const base = [...REQUEST_CONTRACT_HEADERS, ...rawHeaders(signed.headers)]
    const verify = (headers: string[]): unknown =>
      verifyPaidMediaEngineSessionRequest({
        session: SESSION,
        rawHeaders: headers,
        nowMs: FIXTURE.timestampMs,
        method: FIXTURE.method,
        target: FIXTURE.target,
        bodySha256: FIXTURE.requestBodySha256
      })

    expect(() =>
      verify([...base, 'X-Nachuan-Paid-Session-Unknown', 'value'])
    ).toThrow(/Unknown paid media engine-session header/i)
    expect(() =>
      verify([...base, PAID_MEDIA_ENGINE_SESSION_HEADERS.protocol, '1'])
    ).toThrow(/duplicate|merged/i)
    expect(() =>
      verify(
        base.map((value, index) =>
          index === base.indexOf(PAID_MEDIA_ENGINE_SESSION_HEADERS.protocol) + 1
            ? '1, 1'
            : value
        )
      )
    ).toThrow(/duplicate|merged/i)
    expect(() =>
      verify([...base, PAID_MEDIA_ENGINE_SESSION_HEADERS.requestNonce, FIXTURE.nonce])
    ).toThrow(/wrong direction/i)
  })

  it('binds the request HMAC to the exact session, method, target, and body digest', () => {
    const signed = signPaidMediaEngineSessionRequest({
      session: SESSION,
      timestampMs: FIXTURE.timestampMs,
      nonce: FIXTURE.nonce,
      method: FIXTURE.method,
      target: FIXTURE.target,
      bodySha256: FIXTURE.requestBodySha256,
      rawHeaders: REQUEST_CONTRACT_HEADERS
    })
    const verify = (
      overrides: Partial<Parameters<typeof verifyPaidMediaEngineSessionRequest>[0]> = {}
    ): unknown =>
      verifyPaidMediaEngineSessionRequest({
        session: SESSION,
        rawHeaders: [...REQUEST_CONTRACT_HEADERS, ...rawHeaders(signed.headers)],
        nowMs: FIXTURE.timestampMs,
        method: FIXTURE.method,
        target: FIXTURE.target,
        bodySha256: FIXTURE.requestBodySha256,
        ...overrides
      })

    expect(() => verify({ session: { ...SESSION, generation: 8 } })).toThrow(
      /identity does not match/i
    )
    expect(() => verify({ method: 'GET' })).toThrow(/authentication failed/i)
    expect(() => verify({ target: '/v1/videos/generations' })).toThrow(
      /authentication failed/i
    )
    expect(() => verify({ bodySha256: 'a'.repeat(64) })).toThrow(
      /authentication failed/i
    )
  })

  it('binds every non-session request header and rejects ambiguous header contracts', () => {
    const signed = signPaidMediaEngineSessionRequest({
      session: SESSION,
      timestampMs: FIXTURE.timestampMs,
      nonce: FIXTURE.nonce,
      method: FIXTURE.method,
      target: FIXTURE.target,
      bodySha256: FIXTURE.requestBodySha256,
      rawHeaders: REQUEST_CONTRACT_HEADERS
    })
    const sessionHeaders = rawHeaders(signed.headers)
    const verify = (ordinaryHeaders: readonly string[]): unknown =>
      verifyPaidMediaEngineSessionRequest({
        session: SESSION,
        rawHeaders: [...ordinaryHeaders, ...sessionHeaders],
        nowMs: FIXTURE.timestampMs,
        method: FIXTURE.method,
        target: FIXTURE.target,
        bodySha256: FIXTURE.requestBodySha256
      })

    const changed = [...REQUEST_CONTRACT_HEADERS]
    changed[changed.indexOf('Idempotency-Key') + 1] = 'desktop-op-0987654321'
    expect(() => verify(changed)).toThrow(/authentication failed/i)

    const removed = [...REQUEST_CONTRACT_HEADERS]
    removed.splice(removed.indexOf('Accept'), 2)
    expect(() => verify(removed)).toThrow(/authentication failed/i)
    expect(() => verify([...REQUEST_CONTRACT_HEADERS, 'X-New-Header', 'value'])).toThrow(
      /authentication failed/i
    )
    expect(() =>
      verify([...REQUEST_CONTRACT_HEADERS, 'content-type', 'application/json'])
    ).toThrow(/request contract header is duplicate/i)

    const merged = [...REQUEST_CONTRACT_HEADERS]
    merged[merged.indexOf('Accept') + 1] = 'application/json, text/plain'
    expect(() => verify(merged)).toThrow(/request contract header is duplicate|merged/i)

    const reordered: string[] = []
    for (let index = REQUEST_CONTRACT_HEADERS.length - 2; index >= 0; index -= 2) {
      reordered.push(
        REQUEST_CONTRACT_HEADERS[index].toLowerCase(),
        REQUEST_CONTRACT_HEADERS[index + 1]
      )
    }
    expect(verify(reordered)).toMatchObject({
      contractSha256: FIXTURE.requestContractSha256
    })
  })

  it('verifies the response envelope before streaming and rejects every bound-field change', () => {
    const contractHeaders = [
      'Content-Type',
      'application/json',
      'Content-Length',
      '69',
      'Cache-Control',
      'no-store',
      'Connection',
      'keep-alive'
    ]
    const signed = signPaidMediaEngineSessionResponse({
      session: SESSION,
      requestNonce: FIXTURE.nonce,
      status: FIXTURE.responseStatus,
      bodySha256: FIXTURE.responseBodySha256,
      rawHeaders: contractHeaders
    })
    const fullRawHeaders = [...contractHeaders, ...rawHeaders(signed.headers)]
    expect(
      verifyPaidMediaEngineSessionResponseEnvelope({
        session: SESSION,
        requestNonce: FIXTURE.nonce,
        status: FIXTURE.responseStatus,
        rawHeaders: fullRawHeaders
      }).declaredBodySha256
    ).toBe(FIXTURE.responseBodySha256)

    expect(() =>
      verifyPaidMediaEngineSessionResponse({
        session: SESSION,
        requestNonce: FIXTURE.nonce,
        status: FIXTURE.responseStatus,
        bodySha256: 'b'.repeat(64),
        rawHeaders: fullRawHeaders
      })
    ).toThrow(/body changed/i)
    expect(() =>
      verifyPaidMediaEngineSessionResponseEnvelope({
        session: { ...SESSION, pid: SESSION.pid + 1 },
        requestNonce: FIXTURE.nonce,
        status: FIXTURE.responseStatus,
        rawHeaders: fullRawHeaders
      })
    ).toThrow(/identity does not match/i)
    expect(() =>
      verifyPaidMediaEngineSessionResponseEnvelope({
        session: SESSION,
        requestNonce: 'f'.repeat(64),
        status: FIXTURE.responseStatus,
        rawHeaders: fullRawHeaders
      })
    ).toThrow(/identity does not match/i)
    expect(() =>
      verifyPaidMediaEngineSessionResponseEnvelope({
        session: SESSION,
        requestNonce: FIXTURE.nonce,
        status: 201,
        rawHeaders: fullRawHeaders
      })
    ).toThrow(/authentication failed/i)
    const changedContract = [...fullRawHeaders]
    changedContract[1] = 'application/octet-stream'
    expect(() =>
      verifyPaidMediaEngineSessionResponseEnvelope({
        session: SESSION,
        requestNonce: FIXTURE.nonce,
        status: FIXTURE.responseStatus,
        rawHeaders: changedContract
      })
    ).toThrow(/authentication failed/i)

    const changedDeclaredBody = [...fullRawHeaders]
    changedDeclaredBody[
      changedDeclaredBody.indexOf(
        PAID_MEDIA_ENGINE_SESSION_HEADERS.responseBodySha256
      ) + 1
    ] = 'c'.repeat(64)
    expect(() =>
      verifyPaidMediaEngineSessionResponseEnvelope({
        session: SESSION,
        requestNonce: FIXTURE.nonce,
        status: FIXTURE.responseStatus,
        rawHeaders: changedDeclaredBody
      })
    ).toThrow(/authentication failed/i)

    const changedSignature = [...fullRawHeaders]
    changedSignature[
      changedSignature.indexOf(PAID_MEDIA_ENGINE_SESSION_HEADERS.responseSignature) + 1
    ] = 'd'.repeat(64)
    expect(() =>
      verifyPaidMediaEngineSessionResponseEnvelope({
        session: SESSION,
        requestNonce: FIXTURE.nonce,
        status: FIXTURE.responseStatus,
        rawHeaders: changedSignature
      })
    ).toThrow(/authentication failed/i)
  })

  it('binds response contract presence and ignores only the specified transport metadata', () => {
    const contractHeaders = [
      'Content-Type',
      'application/json',
      'Content-Length',
      '69',
      'Cache-Control',
      'no-store',
      'Connection',
      'keep-alive'
    ]
    const signed = signPaidMediaEngineSessionResponse({
      session: SESSION,
      requestNonce: FIXTURE.nonce,
      status: FIXTURE.responseStatus,
      bodySha256: FIXTURE.responseBodySha256,
      rawHeaders: contractHeaders
    })
    const sessionHeaders = rawHeaders(signed.headers)
    const verify = (ordinaryHeaders: readonly string[]): unknown =>
      verifyPaidMediaEngineSessionResponseEnvelope({
        session: SESSION,
        requestNonce: FIXTURE.nonce,
        status: FIXTURE.responseStatus,
        rawHeaders: [...ordinaryHeaders, ...sessionHeaders]
      })

    const removed = [...contractHeaders]
    removed.splice(removed.indexOf('Cache-Control'), 2)
    expect(() => verify(removed)).toThrow(/authentication failed/i)
    expect(() => verify([...contractHeaders, 'Transfer-Encoding', 'chunked'])).toThrow(
      /authentication failed/i
    )

    const changed = [...contractHeaders]
    changed[changed.indexOf('Content-Length') + 1] = '70'
    expect(() => verify(changed)).toThrow(/authentication failed/i)

    const excluded = [...contractHeaders]
    excluded[excluded.indexOf('Connection') + 1] = 'close'
    excluded.push(
      'Date',
      'Fri, 17 Jul 2026 12:00:00 GMT',
      'Server',
      'nachuan-test'
    )
    expect(verify(excluded)).toMatchObject({
      contractSha256: FIXTURE.responseContractSha256
    })
  })

  it('rejects unknown, wrong-direction, duplicate, and merged response security headers', () => {
    const contractHeaders = [
      'Content-Type',
      'application/json',
      'Content-Length',
      '69',
      'Cache-Control',
      'no-store'
    ]
    const signed = signPaidMediaEngineSessionResponse({
      session: SESSION,
      requestNonce: FIXTURE.nonce,
      status: FIXTURE.responseStatus,
      bodySha256: FIXTURE.responseBodySha256,
      rawHeaders: contractHeaders
    })
    const base = [...contractHeaders, ...rawHeaders(signed.headers)]
    const verify = (headers: string[]): unknown =>
      verifyPaidMediaEngineSessionResponseEnvelope({
        session: SESSION,
        requestNonce: FIXTURE.nonce,
        status: FIXTURE.responseStatus,
        rawHeaders: headers
      })

    expect(() =>
      verify([...base, 'X-Nachuan-Paid-Session-Future', '1'])
    ).toThrow(/Unknown paid media engine-session header/i)
    expect(() =>
      verify([...base, PAID_MEDIA_ENGINE_SESSION_HEADERS.timestampMs, '1'])
    ).toThrow(/wrong direction/i)
    expect(() =>
      verify([
        ...base,
        PAID_MEDIA_ENGINE_SESSION_HEADERS.responseSignature,
        signed.signature
      ])
    ).toThrow(/duplicate|merged/i)
    const mergedSignature = [...base]
    const signatureIndex = mergedSignature.indexOf(
      PAID_MEDIA_ENGINE_SESSION_HEADERS.responseSignature
    )
    mergedSignature[signatureIndex + 1] = `${signed.signature}, ${signed.signature}`
    expect(() => verify(mergedSignature)).toThrow(/duplicate|merged/i)
    expect(() => verify([...base, 'Content-Type', 'application/json'])).toThrow(
      /contract header is duplicate/i
    )
    const mergedContract = [...base]
    mergedContract[mergedContract.indexOf('Cache-Control') + 1] = 'no-store, private'
    expect(() => verify(mergedContract)).toThrow(/contract header is duplicate|merged/i)
  })

  it('rejects future timestamps, non-canonical ranges, and bad origin-form targets', () => {
    const signRequest = (
      overrides: Partial<Parameters<typeof signPaidMediaEngineSessionRequest>[0]> = {}
    ): unknown =>
      signPaidMediaEngineSessionRequest({
        session: SESSION,
        timestampMs: FIXTURE.timestampMs,
        nonce: FIXTURE.nonce,
        method: FIXTURE.method,
        target: FIXTURE.target,
        bodySha256: FIXTURE.requestBodySha256,
        rawHeaders: REQUEST_CONTRACT_HEADERS,
        ...overrides
      })
    for (const target of [
      'v1/images/generations',
      'https://127.0.0.1/v1/images/generations',
      '/v1/images/generations?x=1',
      '/v1/images/generations#x',
      '/v1\\images',
      '/v1/images\n'
    ]) {
      expect(() => signRequest({ target })).toThrow(/origin-form/i)
    }
    expect(() => signRequest({ session: { ...SESSION, port: 1023 } })).toThrow(/port/i)
    expect(() => signRequest({ session: { ...SESSION, generation: 0 } })).toThrow(
      /generation/i
    )
    expect(() => signRequest({ session: { ...SESSION, bootToken: '0'.repeat(64) } })).toThrow(
      /boot token/i
    )

    const future = signPaidMediaEngineSessionRequest({
      session: SESSION,
      timestampMs: FIXTURE.timestampMs + 5_001,
      nonce: FIXTURE.nonce,
      method: FIXTURE.method,
      target: FIXTURE.target,
      bodySha256: FIXTURE.requestBodySha256,
      rawHeaders: REQUEST_CONTRACT_HEADERS
    })
    expect(() =>
      verifyPaidMediaEngineSessionRequest({
        session: SESSION,
        rawHeaders: [...REQUEST_CONTRACT_HEADERS, ...rawHeaders(future.headers)],
        nowMs: FIXTURE.timestampMs,
        method: FIXTURE.method,
        target: FIXTURE.target,
        bodySha256: FIXTURE.requestBodySha256
      })
    ).toThrow(/expired/i)
    const nonCanonical = [...REQUEST_CONTRACT_HEADERS, ...rawHeaders(future.headers)]
    nonCanonical[nonCanonical.indexOf(PAID_MEDIA_ENGINE_SESSION_HEADERS.generation) + 1] =
      '07'
    expect(() =>
      verifyPaidMediaEngineSessionRequest({
        session: SESSION,
        rawHeaders: nonCanonical,
        nowMs: FIXTURE.timestampMs + 5_001,
        method: FIXTURE.method,
        target: FIXTURE.target,
        bodySha256: FIXTURE.requestBodySha256
      })
    ).toThrow(/generation is invalid/i)
  })
})
