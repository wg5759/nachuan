import React from 'react'

export type PrimaryDestination = 'chat' | 'create' | 'connections' | 'files' | 'settings'

export type PrimaryNavigationLabels = Record<PrimaryDestination, string>

const destinations: PrimaryDestination[] = [
  'chat',
  'create',
  'connections',
  'files',
  'settings'
]

function DestinationIcon({ destination }: { destination: PrimaryDestination }): React.ReactNode {
  if (destination === 'chat') {
    return <path d="M5 6.5A2.5 2.5 0 0 1 7.5 4h9A2.5 2.5 0 0 1 19 6.5v6a2.5 2.5 0 0 1-2.5 2.5H11l-4.5 3v-3A2.5 2.5 0 0 1 4 12.5v-6Z" />
  }
  if (destination === 'create') {
    return <><path d="m12 3 1.2 3.8L17 8l-3.8 1.2L12 13l-1.2-3.8L7 8l3.8-1.2L12 3Z" /><path d="m18 14 .7 2.3L21 17l-2.3.7L18 20l-.7-2.3L15 17l2.3-.7L18 14Z" /></>
  }
  if (destination === 'connections') {
    return <><circle cx="8" cy="12" r="3" /><circle cx="17" cy="7" r="2" /><circle cx="17" cy="17" r="2" /><path d="m10.7 10.7 4.5-2.6m-4.5 5.2 4.5 2.6" /></>
  }
  if (destination === 'files') {
    return <path d="M3.5 7.5A2.5 2.5 0 0 1 6 5h4l2 2h6A2.5 2.5 0 0 1 20.5 9.5v7A2.5 2.5 0 0 1 18 19H6a2.5 2.5 0 0 1-2.5-2.5v-9Z" />
  }
  return <><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1-2.8 2.8-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.6v.2h-4V21a1.7 1.7 0 0 0-1-1.6 1.7 1.7 0 0 0-1.9.3l-.1.1L4.2 17l.1-.1a1.7 1.7 0 0 0 .3-1.9A1.7 1.7 0 0 0 3 14H2.8v-4H3a1.7 1.7 0 0 0 1.6-1 1.7 1.7 0 0 0-.3-1.9L4.2 7 7 4.2l.1.1A1.7 1.7 0 0 0 9 4.6 1.7 1.7 0 0 0 10 3v-.2h4V3a1.7 1.7 0 0 0 1 1.6 1.7 1.7 0 0 0 1.9-.3l.1-.1L19.8 7l-.1.1a1.7 1.7 0 0 0-.3 1.9 1.7 1.7 0 0 0 1.6 1h.2v4H21a1.7 1.7 0 0 0-1.6 1Z" /></>
}

export function PrimaryNavigation({
  active,
  labels,
  onSelect
}: {
  active: PrimaryDestination
  labels: PrimaryNavigationLabels
  onSelect: (destination: PrimaryDestination) => void
}): React.ReactNode {
  return (
    <nav className="nachuan-primary-nav" aria-label="Primary">
      {destinations.map((destination) => (
        <button
          key={destination}
          type="button"
          data-primary-destination={destination}
          aria-label={labels[destination]}
          aria-current={active === destination ? 'page' : undefined}
          onClick={() => onSelect(destination)}
          className="nachuan-primary-nav-item"
        >
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <DestinationIcon destination={destination} />
          </svg>
          <span>{labels[destination]}</span>
        </button>
      ))}
    </nav>
  )
}

export interface AppShellFrameProps {
  creative: boolean
  navigation: React.ReactNode
  conversation: React.ReactNode
  creativeDrawer: React.ReactNode
}

/**
 * Shared presentational frame for both renderer builds. Surface-specific API
 * adapters stay outside this component so Web and Electron render the same
 * navigation, conversation canvas, and contextual creative drawer.
 */
export function AppShellFrame({
  creative,
  navigation,
  conversation,
  creativeDrawer
}: AppShellFrameProps): React.ReactNode {
  return (
    <div className="nachuan-app-shell" data-nachuan-shell="unified">
      <aside className="nachuan-app-shell-navigation" aria-label="主导航">
        {navigation}
      </aside>
      <section className="nachuan-app-shell-conversation">{conversation}</section>
      {creative ? (
        <aside className="nachuan-app-shell-creative" aria-label="创作面板">
          {creativeDrawer}
        </aside>
      ) : null}
    </div>
  )
}
