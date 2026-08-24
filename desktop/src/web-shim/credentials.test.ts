import { afterEach, describe, expect, it, vi } from 'vitest'

import { createCredentialStore, type KeyValueStorage } from './credentials'

function memoryStorage(initial: Record<string, string> = {}): KeyValueStorage & {
  data: Record<string, string>
} {
  const data: Record<string, string> = { ...initial }
  return {
    data,
    getItem: (key: string) => (key in data ? data[key] : null),
    setItem: (key: string, value: string) => {
      data[key] = value
    },
    removeItem: (key: string) => {
      delete data[key]
    }
  }
}

describe('web-shim credentials', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('keeps keys across a reload without writing them to durable localStorage', () => {
    const durableStorage = memoryStorage()
    const tabSessionStorage = memoryStorage()
    vi.stubGlobal('localStorage', durableStorage)
    vi.stubGlobal('sessionStorage', tabSessionStorage)

    createCredentialStore().save('runtime-key', 'approval-key')
    const afterReload = createCredentialStore()

    expect(afterReload.getRuntimeKey()).toBe('runtime-key')
    expect(afterReload.getApprovalKey()).toBe('approval-key')
    expect(durableStorage.data).toEqual({})
    expect(tabSessionStorage.data).toEqual({
      'nachuan.web.runtimeKey': 'runtime-key',
      'nachuan.web.approvalKey': 'approval-key'
    })
  })

  it('removes legacy durable key items without touching unrelated localStorage data', () => {
    const durableStorage = memoryStorage({
      'nachuan.web.runtimeKey': 'legacy-runtime',
      'nachuan.web.approvalKey': 'legacy-approval',
      'business.unrelated': 'keep-me'
    })
    vi.stubGlobal('localStorage', durableStorage)
    vi.stubGlobal('sessionStorage', memoryStorage())

    createCredentialStore()

    expect(durableStorage.data).toEqual({ 'business.unrelated': 'keep-me' })
  })

  it('roundtrips runtime and approval keys through the injected storage', () => {
    const storage = memoryStorage()
    const store = createCredentialStore(() => storage)

    expect(store.getRuntimeKey()).toBeNull()
    expect(store.getApprovalKey()).toBeNull()

    store.save(' runtime-key ', ' approval-key ')
    expect(store.getRuntimeKey()).toBe('runtime-key')
    expect(store.getApprovalKey()).toBe('approval-key')
    expect(storage.data['nachuan.web.runtimeKey']).toBe('runtime-key')
    expect(storage.data['nachuan.web.approvalKey']).toBe('approval-key')
  })

  it('removes only the approval item when approval key is empty', () => {
    const storage = memoryStorage({
      'nachuan.web.runtimeKey': 'old-runtime',
      'nachuan.web.approvalKey': 'old-approval',
      'business.unrelated': 'keep-me'
    })
    const store = createCredentialStore(() => storage)

    store.save('new-runtime', '')
    expect(store.getRuntimeKey()).toBe('new-runtime')
    expect(store.getApprovalKey()).toBeNull()
    expect(storage.data['business.unrelated']).toBe('keep-me')
    expect('nachuan.web.approvalKey' in storage.data).toBe(false)
  })

  it('never clears unrelated business data in the injected storage', () => {
    const storage = memoryStorage({ 'chat.history': 'x', 'ui.prefs': 'y' })
    const store = createCredentialStore(() => storage)
    store.save('rk', 'ak')
    expect(storage.data['chat.history']).toBe('x')
    expect(storage.data['ui.prefs']).toBe('y')
  })

  it('returns null when storage is unavailable and never throws on read', () => {
    const store = createCredentialStore(() => null)
    expect(store.getRuntimeKey()).toBeNull()
    expect(store.getApprovalKey()).toBeNull()
  })

  it('throws a clear error when saving without storage or with an empty runtime key', () => {
    expect(() => createCredentialStore(() => null).save('rk', null)).toThrow(/会话存储不可用/)
    const store = createCredentialStore(() => memoryStorage())
    expect(() => store.save('   ', null)).toThrow(/运行时 Key/)
  })

  it('swallows storage read failures (privacy mode) and reports null', () => {
    const broken: KeyValueStorage = {
      getItem: () => {
        throw new Error('denied')
      },
      setItem: () => {},
      removeItem: () => {}
    }
    const store = createCredentialStore(() => broken)
    expect(store.getRuntimeKey()).toBeNull()
    expect(store.getApprovalKey()).toBeNull()
  })
})
