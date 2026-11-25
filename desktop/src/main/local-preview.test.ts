import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { localPreviewEngineEnvironment, localPreviewPaths } from './local-preview'

describe('explicit local desktop preview', () => {
  it('does not alter ordinary source or packaged startup', () => {
    expect(localPreviewPaths(false, undefined, resolve('.'))).toBeNull()
    expect(localPreviewPaths(true, undefined, resolve('.'))).toBeNull()
  })
  it('never uses the preview to relax a packaged runtime', () => {
    expect(() => localPreviewPaths(true, 'LOCAL_ONLY', resolve('.'))).toThrow()
    expect(() => localPreviewPaths(false, 'typo', resolve('.'))).toThrow()
  })
  it('anchors every runtime data location to the isolated preview', () => {
    const paths = localPreviewPaths(false, 'LOCAL_ONLY', resolve('.'))!
    const env = localPreviewEngineEnvironment(paths)
    expect(paths.userData).toContain('本机桌面体验版')
    expect(env.USAGE_DB_PATH.startsWith(paths.userData)).toBe(true)
    expect(env.NACHUAN_CONNECTIONS_PATH.startsWith(paths.userData)).toBe(true)
    expect(env.NACHUAN_CONFIG_ENV_ONLY).toBe('1')
  })
  it('binds the profile before ownership and skips channel autostart', () => {
    const source = readFileSync(new URL('./index.ts', import.meta.url), 'utf8')
    expect(source.indexOf("app.setPath('userData', localPreview.userData)")).toBeLessThan(source.indexOf('app.requestSingleInstanceLock()'))
    expect(source).toContain('!localPreview && weixinBridgeSupervisor.start(')
    expect(source).toContain('Object.assign(env, localPreviewEngineEnvironment(localPreview))')
  })
})
