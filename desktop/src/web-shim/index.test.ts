import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { KeyValueStorage } from './credentials'

function memoryStorage(initial: Record<string, string> = {}): KeyValueStorage {
  const data = { ...initial }
  return {
    getItem: (key: string) => data[key] ?? null,
    setItem: (key: string, value: string) => {
      data[key] = value
    },
    removeItem: (key: string) => {
      delete data[key]
    }
  }
}

describe('Web renderer API installation', () => {
  beforeEach(() => {
    vi.resetModules()
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('reports the Web runtime through the public renderer API', async () => {
    const browserWindow: {
      api?: { runtimeKind?: unknown; runtimeCapabilities?: unknown }
      location: { reload(): void }
    } = {
      location: { reload: vi.fn() }
    }
    vi.stubGlobal('window', browserWindow)
    vi.stubGlobal(
      'sessionStorage',
      memoryStorage({ 'nachuan.web.runtimeKey': 'test-runtime-key' })
    )
    vi.stubGlobal('localStorage', memoryStorage())

    await import('./index')

    expect(browserWindow.api?.runtimeKind).toBe('web')
    expect(browserWindow.api?.runtimeCapabilities).toMatchObject({
      schema: 'nachuan.client-port-capabilities.v1',
      authoritative: false,
      runtimeReadinessIncluded: false,
      capabilities: {
        engineProxy: {
          surfaces: {
            localWeb: { declaredSupport: 'implemented', adapter: 'same-origin-http' }
          }
        },
        screenSnip: {
          surfaces: {
            localWeb: { declaredSupport: 'unsupported', adapter: 'fail-closed' }
          }
        }
      }
    })
  })

  it('fails closed instead of reusing a stale or foreign preinstalled API', async () => {
    const fetchImpl = vi.fn()
    const staleApi = { runtimeKind: 'electron' }
    const browserWindow = {
      api: staleApi,
      location: { reload: vi.fn() }
    }
    vi.stubGlobal('window', browserWindow)
    vi.stubGlobal('fetch', fetchImpl)
    vi.stubGlobal(
      'sessionStorage',
      memoryStorage({ 'nachuan.web.runtimeKey': 'test-runtime-key' })
    )
    vi.stubGlobal('localStorage', memoryStorage())

    await expect(import('./index')).rejects.toThrow(/capability|Runtime API/i)
    expect(browserWindow.api).toBe(staleApi)
    expect(fetchImpl).not.toHaveBeenCalled()
  })
})
