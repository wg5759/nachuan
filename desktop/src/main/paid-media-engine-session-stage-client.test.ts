import { createHash } from 'node:crypto'
import { Readable } from 'node:stream'

import { describe, expect, it, vi } from 'vitest'

import type { InstallationRootEngineSession } from './installation-root-client'
import type {
  PaidMediaEngineSessionClient,
  PaidMediaEngineSessionExchangeInput,
  PaidMediaEngineSessionResponse
} from './paid-media-engine-session-client'
import {
  activatePaidMediaEngineSessionStage,
  PAID_MEDIA_ENGINE_SESSION_STAGE_READY_PATH
} from './paid-media-engine-session-stage-client'

const SESSION: InstallationRootEngineSession = Object.freeze({
  generation: 7,
  pid: 43_210,
  port: 43_111,
  bootToken: '01'.repeat(32)
})
const PRINCIPAL = 'a'.repeat(64)
const VAULT_EVIDENCE = 'b'.repeat(64)

function sha256(value: Uint8Array): string {
  return createHash('sha256').update(value).digest('hex')
}

function responseFor(body: Buffer): PaidMediaEngineSessionResponse {
  const stream = Readable.from([body]) as unknown as PaidMediaEngineSessionResponse['response']
  Object.defineProperty(stream, 'rawTrailers', { value: [], configurable: true })
  return {
    status: 200,
    rawHeaders: [
      'Content-Type',
      'application/json',
      'Content-Length',
      String(body.byteLength),
      'Cache-Control',
      'no-store',
      'Connection',
      'close'
    ],
    response: stream,
    declaredBodySha256: sha256(body)
  }
}

function fakeClient(receipt: Buffer): {
  client: Pick<PaidMediaEngineSessionClient, 'exchange'>
  exchange: ReturnType<typeof vi.fn>
} {
  const exchange = vi.fn(
    async (
      request: PaidMediaEngineSessionExchangeInput,
      consume: (response: PaidMediaEngineSessionResponse) => Promise<{
        value: unknown
        bodySha256: string
      }>
    ) => {
      void request
      return (await consume(responseFor(receipt))).value
    }
  )
  return {
    client: { exchange } as unknown as Pick<PaidMediaEngineSessionClient, 'exchange'>,
    exchange
  }
}

function receipt(vaultEvidenceSha256 = VAULT_EVIDENCE): Buffer {
  return Buffer.from(
    `{"schema":"nachuan.paid-media.engine-session.stage-ready.receipt.v1","ok":true,"vaultEvidenceSha256":"${vaultEvidenceSha256}"}`,
    'ascii'
  )
}

describe('paid-media boot-local stage-ready client', () => {
  it('sends one exact canonical identity/evidence binding through the pinned session exchange', async () => {
    const item = fakeClient(receipt())
    const signal = new AbortController().signal

    await expect(
      activatePaidMediaEngineSessionStage({
        session: () => SESSION,
        sessionClient: item.client,
        installationPrincipal: PRINCIPAL,
        vaultEvidenceSha256: VAULT_EVIDENCE,
        signal
      })
    ).resolves.toEqual({
      installationPrincipal: PRINCIPAL,
      vaultEvidenceSha256: VAULT_EVIDENCE
    })

    expect(item.exchange).toHaveBeenCalledTimes(1)
    const request = item.exchange.mock.calls[0]![0] as PaidMediaEngineSessionExchangeInput
    expect(request.method).toBe('POST')
    expect(request.target).toBe(PAID_MEDIA_ENGINE_SESSION_STAGE_READY_PATH)
    expect(request.signal).toBe(signal)
    expect(request.headers).toEqual({
      Accept: 'application/json',
      'Accept-Encoding': 'identity',
      'Cache-Control': 'no-store',
      'Content-Type': 'application/json',
      'X-Nachuan-Paid-Media-Protocol': '2'
    })
    expect(request.body.toString('ascii')).toBe(
      `{"schema":"nachuan.paid-media.engine-session.stage-ready.v1","generation":7,"pid":43210,"port":43111,"installationPrincipal":"${PRINCIPAL}","vaultEvidenceSha256":"${VAULT_EVIDENCE}"}`
    )
  })

  it('rejects zero evidence and a noncanonical or mismatched signed receipt', async () => {
    const invalid = fakeClient(receipt())
    await expect(
      activatePaidMediaEngineSessionStage({
        session: () => SESSION,
        sessionClient: invalid.client,
        installationPrincipal: PRINCIPAL,
        vaultEvidenceSha256: '0'.repeat(64),
        signal: new AbortController().signal
      })
    ).rejects.toThrow(/stage-ready input is invalid/i)
    expect(invalid.exchange).not.toHaveBeenCalled()

    const noncanonical = fakeClient(
      Buffer.from(`{ "schema":"nachuan.paid-media.engine-session.stage-ready.receipt.v1","ok":true,"vaultEvidenceSha256":"${VAULT_EVIDENCE}"}`, 'ascii')
    )
    await expect(
      activatePaidMediaEngineSessionStage({
        session: () => SESSION,
        sessionClient: noncanonical.client,
        installationPrincipal: PRINCIPAL,
        vaultEvidenceSha256: VAULT_EVIDENCE,
        signal: new AbortController().signal
      })
    ).rejects.toThrow(/receipt is invalid/i)

    const mismatched = fakeClient(receipt('c'.repeat(64)))
    await expect(
      activatePaidMediaEngineSessionStage({
        session: () => SESSION,
        sessionClient: mismatched.client,
        installationPrincipal: PRINCIPAL,
        vaultEvidenceSha256: VAULT_EVIDENCE,
        signal: new AbortController().signal
      })
    ).rejects.toThrow(/receipt is invalid/i)
  })

  it('rejects when the published engine session changes across the exchange', async () => {
    let current = SESSION
    const item = fakeClient(receipt())
    item.exchange.mockImplementationOnce(async (_request, consume) => {
      const consumed = await consume(responseFor(receipt()))
      current = Object.freeze({ ...SESSION, generation: SESSION.generation + 1 })
      return consumed.value
    })

    await expect(
      activatePaidMediaEngineSessionStage({
        session: () => current,
        sessionClient: item.client,
        installationPrincipal: PRINCIPAL,
        vaultEvidenceSha256: VAULT_EVIDENCE,
        signal: new AbortController().signal
      })
    ).rejects.toThrow(/engine session changed/i)
  })
})
