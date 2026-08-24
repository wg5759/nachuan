import { describe, expect, it } from 'vitest'

import { canUseEngineRuntime } from './engine-status'

describe('Engine runtime availability', () => {
  it('keeps non-financial runtime APIs available while the Engine is degraded', () => {
    expect(canUseEngineRuntime('online')).toBe(true)
    expect(canUseEngineRuntime('degraded')).toBe(true)
    expect(canUseEngineRuntime('starting')).toBe(false)
    expect(canUseEngineRuntime('offline')).toBe(false)
  })
})
