import { describe, expect, it, vi } from 'vitest'

import {
  createWebElectronOnlyApi,
  type SaveMediaDom,
  type SaveMediaUrlApi
} from './electron-only'

function fakeDom() {
  const anchor = {
    href: '',
    download: '',
    rel: '',
    click: vi.fn(),
    remove: vi.fn()
  }
  const doc: SaveMediaDom = {
    createElement: vi.fn(() => anchor),
    body: { appendChild: vi.fn() }
  }
  const urlApi: SaveMediaUrlApi = {
    createObjectURL: vi.fn(() => 'blob:fake-object-url'),
    revokeObjectURL: vi.fn()
  }
  return { anchor, doc, urlApi }
}

function fetchMockArgs(fetchImpl: ReturnType<typeof vi.fn>): unknown[] {
  return fetchImpl.mock.calls[0] as unknown[]
}

describe('web-shim electron-only fail-closed surface', () => {
  it('reports updates as disabled (pip owns updates) and never starts flows', async () => {
    const api = createWebElectronOnlyApi()

    await expect(api.getUpdateState()).resolves.toEqual({
      phase: 'disabled',
      reason: 'not-configured'
    })
    await expect(api.checkForUpdates()).resolves.toEqual({
      phase: 'disabled',
      reason: 'not-configured'
    })
    await expect(api.installVerifiedUpdate()).resolves.toEqual({ ok: false })
  })

  it('returns no-op unsubscribe functions for every event subscription', () => {
    const api = createWebElectronOnlyApi()
    const cb = vi.fn()

    for (const subscribe of [
      api.onUpdateState,
      api.onSetView,
      api.onAppCommand,
      api.onSnipResult
    ]) {
      const unsubscribe = subscribe(cb as never)
      expect(typeof unsubscribe).toBe('function')
      expect(() => unsubscribe()).not.toThrow()
    }
    expect(cb).not.toHaveBeenCalled()
  })

  it('fails snip capture closed with truthful shapes', async () => {
    const api = createWebElectronOnlyApi()

    await expect(api.snipBg()).resolves.toBeNull()
    await expect(api.startSnip()).resolves.toEqual({ ok: false })
    expect(() => api.snipReady()).not.toThrow()
    expect(() => api.snipDone({ dataUrl: 'data:', action: 'copy' })).not.toThrow()
    expect(() => api.snipCancel()).not.toThrow()
  })

  it('setLang is a no-op (no native menu to rebuild)', () => {
    const api = createWebElectronOnlyApi()
    expect(() => api.setLang('zh')).not.toThrow()
  })

  it('pickDirectory rejects with an explicit unavailable error', async () => {
    const api = createWebElectronOnlyApi()
    await expect(api.pickDirectory()).rejects.toThrow(/Web 形态不可用：选择目录/)
  })

  it('saveMedia downloads local bytes through an anchor', async () => {
    const { anchor, doc, urlApi } = fakeDom()
    const api = createWebElectronOnlyApi({ document: doc, urlApi })

    const result = await api.saveMedia({ filename: 'shot.png', bytes: new ArrayBuffer(4) })

    expect(result).toEqual({ ok: true, path: 'shot.png' })
    expect(urlApi.createObjectURL).toHaveBeenCalledTimes(1)
    expect(anchor.download).toBe('shot.png')
    expect(anchor.href).toBe('blob:fake-object-url')
    expect(anchor.click).toHaveBeenCalledTimes(1)
    expect(anchor.remove).toHaveBeenCalledTimes(1)
    await new Promise((resolve) => setTimeout(resolve, 0))
    expect(urlApi.revokeObjectURL).toHaveBeenCalledWith('blob:fake-object-url')
  })

  it('saveMedia fetches data:/blob: sources locally before downloading', async () => {
    const { anchor, doc, urlApi } = fakeDom()
    const fetchImpl = vi.fn(async () => new Response(new Blob(['pixels'])))
    const api = createWebElectronOnlyApi({
      document: doc,
      urlApi,
      fetchImpl: fetchImpl as unknown as typeof fetch
    })

    const result = await api.saveMedia({ filename: 'img.png', url: 'data:image/png;base64,AA==' })

    expect(result.ok).toBe(true)
    expect(fetchMockArgs(fetchImpl)).toEqual(['data:image/png;base64,AA=='])
    expect(anchor.click).toHaveBeenCalledTimes(1)
  })

  it('saveMedia refuses remote https downloads instead of faking success', async () => {
    const { doc, urlApi } = fakeDom()
    const fetchImpl = vi.fn()
    const api = createWebElectronOnlyApi({
      document: doc,
      urlApi,
      fetchImpl: fetchImpl as unknown as typeof fetch
    })

    const result = await api.saveMedia({ filename: 'img.png', url: 'https://cdn.example.com/x.png' })

    expect(result.ok).toBe(false)
    expect(result.error).toMatch(/同源策略/)
    expect(fetchImpl).not.toHaveBeenCalled()
    expect(urlApi.createObjectURL).not.toHaveBeenCalled()
  })

  it('saveMedia reports invalid input and missing download capability truthfully', async () => {
    const { doc, urlApi } = fakeDom()
    const api = createWebElectronOnlyApi({ document: doc, urlApi })

    await expect(api.saveMedia({ filename: '' })).resolves.toMatchObject({ ok: false })
    await expect(api.saveMedia({ filename: 'x.png' })).resolves.toMatchObject({
      ok: false,
      error: '缺少可保存的媒体内容'
    })

    const noDom = createWebElectronOnlyApi({ document: undefined, urlApi: undefined })
    const failure = await noDom.saveMedia({ filename: 'x.png', bytes: new ArrayBuffer(1) })
    expect(failure.ok).toBe(false)
  })
})
