import { describe, expect, it, vi } from 'vitest'
import { commitSuccessfulModelRefresh } from './model-refresh'

describe('successful model refresh', () => {
  it('commits an authoritative empty model list so stale routes are cleared', () => {
    const setModels = vi.fn()

    const refreshed = commitSuccessfulModelRefresh([], setModels)

    expect(refreshed).toBe(true)
    expect(setModels).toHaveBeenCalledOnce()
    expect(setModels).toHaveBeenCalledWith([])
  })
})
