import { beforeEach, describe, expect, it, vi } from 'vitest'

function fakeLocalStorage(initial: Record<string, string> = {}): Storage {
  const values = new Map(Object.entries(initial))
  return {
    get length() {
      return values.size
    },
    clear: vi.fn(() => values.clear()),
    getItem: vi.fn((key: string) => values.get(key) ?? null),
    key: vi.fn((index: number) => [...values.keys()][index] ?? null),
    removeItem: vi.fn((key: string) => values.delete(key)),
    setItem: vi.fn((key: string, value: string) => values.set(key, value))
  }
}

function persistedStore(currentModel: string): string {
  return JSON.stringify({
    state: {
      currentModel,
      currentConvId: null,
      soundEnabled: true,
      conversations: []
    },
    version: 0
  })
}

describe('persisted model selection validation', () => {
  beforeEach(() => {
    vi.resetModules()
    vi.unstubAllGlobals()
    vi.stubGlobal(
      'localStorage',
      fakeLocalStorage({ 'agg-conversations': persistedStore('glm') })
    )
    vi.stubGlobal('window', {
      addEventListener: vi.fn(),
      removeEventListener: vi.fn()
    })
  })

  it('keeps a persisted preference inactive until the live model allowlist validates it', async () => {
    const { useAppStore } = await import('./store')

    expect(useAppStore.getState().currentModel).toBeNull()
    useAppStore.getState().setModels([
      { id: 'nachuan', owned_by: 'fleet', tier: 'premium', modality: 'chat' },
      { id: 'glm', owned_by: 'volcano', tier: 'premium', modality: 'chat' }
    ])
    expect(useAppStore.getState().currentModel).toBe('glm')
  })

  it('rejects a stale or forged persisted id and falls back to the live recommendation', async () => {
    localStorage.setItem('agg-conversations', persistedStore('forged-model'))
    const { useAppStore } = await import('./store')

    expect(useAppStore.getState().currentModel).toBeNull()
    useAppStore.getState().setModels([
      { id: 'nachuan', owned_by: 'fleet', tier: 'premium', modality: 'chat' },
      { id: 'glm', owned_by: 'volcano', tier: 'premium', modality: 'chat' }
    ])
    expect(useAppStore.getState().currentModel).toBe('nachuan')

    useAppStore.getState().setCurrentModel('forged-model')
    expect(useAppStore.getState().currentModel).toBeNull()
  })

  it('persists the validated current model preference for the next launch', async () => {
    const { flushAppStorePersistence, useAppStore } = await import('./store')
    useAppStore.getState().setModels([
      { id: 'nachuan', owned_by: 'fleet', tier: 'premium', modality: 'chat' },
      { id: 'glm', owned_by: 'volcano', tier: 'premium', modality: 'chat' }
    ])
    expect(flushAppStorePersistence()).toBe(true)

    const persisted = JSON.parse(localStorage.getItem('agg-conversations') ?? '{}') as {
      state?: { currentModel?: string }
    }
    expect(persisted.state?.currentModel).toBe('glm')
  })
})
