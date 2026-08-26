import { beforeEach, describe, expect, it, vi } from 'vitest'

const invoke = vi.fn()

vi.mock('electron', () => ({
  contextBridge: { exposeInMainWorld: vi.fn() },
  ipcRenderer: {
    invoke,
    send: vi.fn(),
    on: vi.fn(),
    removeListener: vi.fn()
  }
}))

describe('paid media preload delivery proof', () => {
  beforeEach(() => {
    vi.resetModules()
    invoke.mockReset().mockResolvedValue({ ok: true, value: null })
    vi.stubGlobal('window', { addEventListener: vi.fn() })
  })

  it('forwards the exact delivery proof object without reducing it to operationId', async () => {
    const deliveryProof = {
      operationId: 'desktop-op-11111111-1111-4111-8111-111111111111',
      resultSha256: 'a'.repeat(64),
      archiveReceiptSha256: 'b'.repeat(64)
    }
    await import('./index')

    await (window as unknown as {
      api: { acknowledgePaidMedia: (proof: typeof deliveryProof) => Promise<unknown> }
    }).api.acknowledgePaidMedia(deliveryProof)

    expect(invoke).toHaveBeenCalledWith('paid-media:acknowledge', deliveryProof)
  })

  it('reports the Electron runtime through the public renderer API', async () => {
    await import('./index')

    const api = (window as unknown as {
      api: { runtimeKind?: unknown; runtimeCapabilities?: unknown }
    }).api
    expect(api.runtimeKind).toBe('electron')
    expect(api.runtimeCapabilities).toMatchObject({
      schema: 'nachuan.client-port-capabilities.v1',
      authoritative: false,
      runtimeReadinessIncluded: false,
      capabilities: {
        engineProxy: {
          surfaces: {
            electron: { declaredSupport: 'implemented', adapter: 'electron-ipc' }
          }
        },
        screenSnip: {
          surfaces: {
            electron: { declaredSupport: 'implemented', adapter: 'electron-ipc' }
          }
        }
      }
    })
  })

  it('exposes plugin UI only through the fixed no-input Main IPC', async () => {
    invoke.mockResolvedValueOnce({
      schema: 'nachuan.plugin-ui.snapshot.v1',
      slots: []
    })
    await import('./index')

    await (window as unknown as {
      api: { getPluginUiSnapshot: () => Promise<unknown> }
    }).api.getPluginUiSnapshot()

    expect(invoke).toHaveBeenCalledWith('plugin-ui:snapshot')
  })
})
