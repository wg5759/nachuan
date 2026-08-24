import { beforeEach, describe, expect, it, vi } from 'vitest'

describe('renderer Engine health contract', () => {
  const engineRequest = vi.fn()

  beforeEach(() => {
    vi.resetModules()
    engineRequest.mockReset()
    vi.stubGlobal('window', {
      api: {
        engineRequest,
        engineStream: vi.fn(),
        engineUpload: vi.fn(),
        cancelEngineRequest: vi.fn()
      }
    })
  })

  function healthResponse(document: unknown): {
    status: number
    contentType: string
    body: Uint8Array
  } {
    return {
      status: 200,
      contentType: 'application/json',
      body: Uint8Array.from(Buffer.from(JSON.stringify(document), 'utf8'))
    }
  }

  it('reports offline when health is HTTP 200 but degraded', async () => {
    engineRequest.mockResolvedValue(
      healthResponse({
        status: 'ok',
        readiness: 'degraded',
        checks: { financial_ledger: { required: true, ready: false } }
      })
    )
    const { probeEngine } = await import('./api')

    await expect(probeEngine()).resolves.toBe(false)
    expect(engineRequest.mock.calls[0][0]).toMatchObject({
      method: 'GET',
      target: '/health',
      bodyKind: 'none',
      responseKind: 'json'
    })
  })

  it('reports offline for an off or Noop provider-call ledger', async () => {
    engineRequest.mockResolvedValue(
      healthResponse({
        status: 'ok',
        readiness: 'ok',
        checks: {
          financial_ledger: { required: false, ready: true, status: 'disabled' }
        }
      })
    )
    const { probeEngine } = await import('./api')

    await expect(probeEngine()).resolves.toBe(false)
  })

  it('distinguishes a reachable degraded Engine from an offline Engine', async () => {
    engineRequest.mockResolvedValue(
      healthResponse({
        status: 'ok',
        readiness: 'degraded',
        checks: {
          financial_ledger: { required: false, ready: false, status: 'disabled' },
          providers: { ready: true, model_count: 1 }
        }
      })
    )
    const { probeEngineStatus } = await import('./api')

    await expect(probeEngineStatus()).resolves.toBe('degraded')
  })

  it('reports offline when a required provider-call ledger is not ready', async () => {
    engineRequest.mockResolvedValue(
      healthResponse({
        status: 'ok',
        readiness: 'ok',
        checks: {
          financial_ledger: { required: true, ready: false, status: 'unavailable' }
        }
      })
    )
    const { probeEngine } = await import('./api')

    await expect(probeEngine()).resolves.toBe(false)
  })

  it('reports offline when the health document status is not ok', async () => {
    engineRequest.mockResolvedValue(
      healthResponse({
        status: 'error',
        readiness: 'ok',
        checks: { financial_ledger: { required: true, ready: true } }
      })
    )
    const { probeEngine } = await import('./api')

    await expect(probeEngine()).resolves.toBe(false)
  })

  it('reports offline when the health body is malformed JSON', async () => {
    engineRequest.mockResolvedValue({
      status: 200,
      contentType: 'application/json',
      body: Uint8Array.from(Buffer.from('{"status":"ok"', 'utf8'))
    })
    const { probeEngine } = await import('./api')

    await expect(probeEngine()).resolves.toBe(false)
  })

  it('reports online for an ok, ready, required ledger health document', async () => {
    engineRequest.mockResolvedValue(
      healthResponse({
        status: 'ok',
        readiness: 'ok',
        checks: {
          financial_ledger: { required: true, ready: true, status: 'ok' }
        }
      })
    )
    const { probeEngine } = await import('./api')

    await expect(probeEngine()).resolves.toBe(true)
  })
})
