import { beforeEach, describe, expect, it, vi } from 'vitest'

describe('subscription connector discovery boundary', () => {
  const engineRequest = vi.fn()

  beforeEach(() => {
    vi.resetModules()
    engineRequest.mockReset()
    vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new Error('renderer fetch is forbidden'))))
    vi.stubGlobal('window', {
      api: {
        engineRequest,
        engineStream: vi.fn(),
        engineUpload: vi.fn(),
        cancelEngineRequest: vi.fn()
      }
    })
  })

  it('loads the public Codex and Kimi status through the fixed Engine proxy', async () => {
    const connectors = [
      {
        id: 'codex',
        label: 'Codex',
        state: 'installed_unprobed',
        auth: 'device_code',
        transport: 'stdio_jsonl',
        version: '0.144.5',
        capabilities: ['chat', 'code'],
        login_supported: true,
        logout_supported: true
      },
      {
        id: 'kimi-code',
        label: 'Kimi Code',
        state: 'not_installed',
        auth: 'device_code',
        transport: 'acp_stdio',
        version: null,
        capabilities: ['chat', 'code'],
        login_supported: true,
        logout_supported: false
      }
    ]
    engineRequest.mockResolvedValue({
      status: 200,
      contentType: 'application/json',
      body: Uint8Array.from(Buffer.from(JSON.stringify({ connectors }), 'utf8'))
    })
    const { fetchSubscriptionConnectors } = await import('./api')

    await expect(fetchSubscriptionConnectors()).resolves.toEqual(connectors)
    expect(engineRequest).toHaveBeenCalledOnce()
    expect(engineRequest.mock.calls[0][0]).toMatchObject({
      method: 'GET',
      target: '/v1/subscription-connectors',
      bodyKind: 'none',
      responseKind: 'json'
    })
    expect(JSON.stringify(engineRequest.mock.calls)).not.toMatch(
      /authorization|bearer|api.?key|token|cookie/i
    )
    expect(globalThis.fetch).not.toHaveBeenCalled()
  })

  it('projects only public fields and drops unknown connector ids', async () => {
    engineRequest.mockResolvedValue({
      status: 200,
      contentType: 'application/json',
      body: Uint8Array.from(
        Buffer.from(
          JSON.stringify({
            connectors: [
              {
                id: 'codex',
                label: 'Codex',
                state: 'ready',
                auth: 'device_code',
                transport: 'stdio_jsonl',
                version: '0.144.5',
                capabilities: ['chat', 'code'],
                login_supported: true,
                logout_supported: true,
                token: 'must-not-escape',
                credential_path: 'must-not-escape'
              },
              {
                id: 'unexpected',
                label: 'Unexpected',
                state: 'ready',
                auth: 'device_code',
                transport: 'stdio_jsonl',
                version: null,
                capabilities: ['chat'],
                login_supported: true,
                logout_supported: true
              }
            ]
          }),
          'utf8'
        )
      )
    })
    const { fetchSubscriptionConnectors } = await import('./api')

    const result = await fetchSubscriptionConnectors()

    expect(result).toEqual([
      {
        id: 'codex',
        label: 'Codex',
        state: 'ready',
        auth: 'device_code',
        transport: 'stdio_jsonl',
        version: '0.144.5',
        capabilities: ['chat', 'code'],
        login_supported: true,
        logout_supported: true
      }
    ])
    expect(JSON.stringify(result)).not.toMatch(/must-not-escape|token|credential_path/i)
  })
})
