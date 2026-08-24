import { readFileSync } from 'node:fs'

import { describe, expect, it } from 'vitest'

function source(relative: string): string {
  return readFileSync(new URL(relative, import.meta.url), 'utf8')
}

describe('renderer Engine authority boundary', () => {
  it('makes the runtime key and direct loopback Engine transport unrepresentable in renderer/preload', () => {
    const main = source('./index.ts')
    const preload = source('../preload/index.ts')
    const api = source('../renderer/src/api.ts')
    const app = source('../renderer/src/App.tsx')
    const store = source('../renderer/src/store.ts')
    const types = source('../renderer/src/env.d.ts')
    const html = source('../renderer/index.html')

    expect(main).toContain('const rendererEngineProxy = new RendererEngineProxy({')
    expect(main).toContain('registerRendererEngineProxyIpc(ipcMain, rendererEngineProxy')
    expect(main).not.toContain("ipcMain.handle('engine:info'")
    expect(preload).not.toContain("ipcRenderer.invoke('engine:info'")
    expect(preload).not.toContain('getEngineInfo')

    for (const rendererSource of [api, app, store, types]) {
      expect(rendererSource).not.toMatch(/\bengineInfo\b|\bEngineInfo\b|getEngineInfo/)
      expect(rendererSource).not.toMatch(/engine\.baseUrl|e\.baseUrl|e\.key/)
    }
    expect(api).not.toContain('Authorization')
    expect(api).not.toMatch(/\bfetch\s*\(/)
    expect(types.slice(0, types.indexOf('export type PaidMediaPath'))).not.toMatch(
      /\bkey\b|header|baseUrl|authorization/i
    )
    expect(html).not.toMatch(/(?:https?|wss?):\/\/(?:127\.0\.0\.1|localhost):\*/)
  })
})
