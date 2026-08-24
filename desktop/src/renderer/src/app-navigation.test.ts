import { describe, expect, it } from 'vitest'

import {
  primaryDestinationForState,
  resolvePrimaryDestination
} from './app-navigation'

describe('unified app navigation', () => {
  it('maps every customer-facing destination without inventing a second chat surface', () => {
    expect(resolvePrimaryDestination('chat')).toEqual({ view: 'chat', creativeOpen: false })
    expect(resolvePrimaryDestination('create')).toEqual({ view: 'chat', creativeOpen: true })
    expect(resolvePrimaryDestination('connections')).toEqual({
      view: 'connections',
      creativeOpen: false
    })
    expect(resolvePrimaryDestination('files')).toEqual({ view: 'media', creativeOpen: false })
    expect(resolvePrimaryDestination('settings')).toEqual({ view: 'settings', creativeOpen: false })
  })

  it('keeps creation highlighted only while the chat canvas and drawer are both active', () => {
    expect(primaryDestinationForState('chat', true)).toBe('create')
    expect(primaryDestinationForState('chat', false)).toBe('chat')
    expect(primaryDestinationForState('media', true)).toBe('files')
    expect(primaryDestinationForState('connections', false)).toBe('connections')
    expect(primaryDestinationForState('settings', false)).toBe('settings')
    expect(primaryDestinationForState('kb', false)).toBe('chat')
  })
})
