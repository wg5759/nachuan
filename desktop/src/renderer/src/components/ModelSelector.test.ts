import { describe, expect, it } from 'vitest'

import type { ModelInfo } from '../store'
import {
  canSelectModels,
  isSpecificModelSelection,
  specificModelDisplayName,
  visibleModelChoices
} from './ModelSelector'

const model = (id: string, owned_by: string): ModelInfo => ({ id, owned_by, modality: 'chat' })

describe('visibleModelChoices', () => {
  const automatic = model('nachuan', 'fleet')
  const strongest = model('nachuan-ultra', 'fleet')
  const concrete = model('provider-model', 'provider')

  it('shows only customer-facing automatic choices by default', () => {
    expect(visibleModelChoices([concrete, automatic, strongest], 'nachuan', false)).toEqual([
      automatic,
      strongest
    ])
  })

  it('keeps an explicitly selected concrete model visible without exposing every model', () => {
    expect(visibleModelChoices([automatic, concrete], concrete.id, false)).toEqual([
      automatic,
      concrete
    ])
  })

  it('shows concrete models only after the customer opens advanced choices', () => {
    expect(visibleModelChoices([automatic, concrete], 'nachuan', true)).toEqual([
      automatic,
      concrete
    ])
  })

  it('falls back to concrete choices when no automatic fleet is available', () => {
    expect(visibleModelChoices([concrete], null, false)).toEqual([concrete])
  })

  it('never treats a known fleet id as a concrete model when provider metadata drifts', () => {
    expect(isSpecificModelSelection([model('nachuan', 'legacy-provider')], 'nachuan')).toBe(false)
    expect(isSpecificModelSelection([concrete], concrete.id)).toBe(true)
  })

  it('keeps models usable when the Engine is reachable but degraded', () => {
    expect(canSelectModels('offline', [automatic])).toBe(false)
    expect(canSelectModels('starting', [automatic])).toBe(false)
    expect(canSelectModels('online', [])).toBe(false)
    expect(canSelectModels('online', [automatic])).toBe(true)
    expect(canSelectModels('degraded', [automatic])).toBe(true)
  })

  it('hides internal collision aliases behind a provider-aware friendly name', () => {
    expect(specificModelDisplayName(model('openrouter::gpt-4o', 'openrouter'))).toBe(
      'openrouter · gpt-4o'
    )
    expect(specificModelDisplayName(concrete)).toBe('provider-model')
  })
})
