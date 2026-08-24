import type { PrimaryDestination } from './components/UnifiedAppShell'
import type { ViewKey } from './store'

export interface PrimaryNavigationState {
  view: ViewKey
  creativeOpen: boolean
}

export function resolvePrimaryDestination(
  destination: PrimaryDestination
): PrimaryNavigationState {
  if (destination === 'create') return { view: 'chat', creativeOpen: true }
  if (destination === 'connections') return { view: 'connections', creativeOpen: false }
  if (destination === 'files') return { view: 'media', creativeOpen: false }
  if (destination === 'settings') return { view: 'settings', creativeOpen: false }
  return { view: 'chat', creativeOpen: false }
}

export function primaryDestinationForState(
  view: ViewKey,
  creativeOpen: boolean
): PrimaryDestination {
  if (view === 'chat') return creativeOpen ? 'create' : 'chat'
  if (view === 'connections') return 'connections'
  if (view === 'media') return 'files'
  if (view === 'settings') return 'settings'
  return 'chat'
}
