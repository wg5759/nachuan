import React from 'react'
import { useTranslation } from 'react-i18next'

import { useAppStore, type EngineStatus } from '../store'
import ModelSelector from './ModelSelector'

export type RuntimeKind = 'electron' | 'web'
export type EngineTone = 'online' | 'degraded' | 'starting' | 'offline'

function HeaderIcon({ name }: { name: 'menu' | 'sparkles' | 'settings' | 'browser' }): React.ReactNode {
  const common = {
    viewBox: '0 0 24 24',
    fill: 'none',
    stroke: 'currentColor',
    strokeWidth: 1.8,
    strokeLinecap: 'round' as const,
    strokeLinejoin: 'round' as const,
    'aria-hidden': true
  }
  if (name === 'menu') {
    return <svg {...common}><path d="M5 7h14M5 12h14M5 17h14" /></svg>
  }
  if (name === 'sparkles') {
    return <svg {...common}><path d="m12 3 1.1 3.9L17 8l-3.9 1.1L12 13l-1.1-3.9L7 8l3.9-1.1L12 3Z" /><path d="m18 14 .7 2.3L21 17l-2.3.7L18 20l-.7-2.3L15 17l2.3-.7L18 14Z" /></svg>
  }
  if (name === 'browser') {
    return <svg {...common}><rect x="3" y="4" width="18" height="16" rx="3" /><path d="M3 9h18M7 6.5h.01M10 6.5h.01" /></svg>
  }
  return <svg {...common}><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1-2.8 2.8-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.6v.2h-4V21a1.7 1.7 0 0 0-1-1.6 1.7 1.7 0 0 0-1.9.3l-.1.1L4.2 17l.1-.1a1.7 1.7 0 0 0 .3-1.9A1.7 1.7 0 0 0 3 14H2.8v-4H3a1.7 1.7 0 0 0 1.6-1 1.7 1.7 0 0 0-.3-1.9L4.2 7 7 4.2l.1.1A1.7 1.7 0 0 0 9 4.6 1.7 1.7 0 0 0 10 3v-.2h4V3a1.7 1.7 0 0 0 1 1.6 1.7 1.7 0 0 0 1.9-.3l.1-.1L19.8 7l-.1.1a1.7 1.7 0 0 0-.3 1.9 1.7 1.7 0 0 0 1.6 1h.2v4H21a1.7 1.7 0 0 0-1.6 1Z" /></svg>
}

export function AppHeaderView({
  runtimeKind,
  engineTone,
  engineLabel,
  modelControl,
  creativeOpen,
  onToggleNavigation,
  onToggleCreative,
  onOpenSettings,
  onToggleBrowser,
  language = 'zh'
}: {
  runtimeKind: RuntimeKind
  engineTone: EngineTone
  engineLabel: string
  modelControl: React.ReactNode
  creativeOpen: boolean
  onToggleNavigation: () => void
  onToggleCreative: () => void
  onOpenSettings: () => void
  onToggleBrowser: () => void
  language?: 'zh' | 'en'
}): React.ReactNode {
  const zh = language === 'zh'
  const noDrag = { WebkitAppRegion: 'no-drag' } as React.CSSProperties
  const drag = { WebkitAppRegion: runtimeKind === 'electron' ? 'drag' : 'no-drag' } as React.CSSProperties
  return (
    <header
      className={`nachuan-header nachuan-header--${runtimeKind}`}
      style={drag}
      data-runtime-kind={runtimeKind}
    >
      <div className="nachuan-header-brand">
        <button
          type="button"
          className="nachuan-icon-button nachuan-navigation-toggle"
          style={noDrag}
          onClick={onToggleNavigation}
          aria-label={zh ? '展开或收起导航' : 'Toggle navigation'}
        >
          <HeaderIcon name="menu" />
        </button>
        <span className="nachuan-logo" aria-hidden="true">川</span>
        <span className="nachuan-brand-copy">
          <strong>纳川</strong>
          <small>{zh ? '一处连接，协同所有模型' : 'One place for every model'}</small>
        </span>
      </div>

      <div className="nachuan-header-actions" style={noDrag}>
        <div className="nachuan-model-control">{modelControl}</div>
        <span className={`nachuan-engine-status nachuan-engine-status--${engineTone}`} title={engineLabel}>
          <span aria-hidden="true" />
          {engineLabel}
        </span>
        <button
          type="button"
          className={`nachuan-creative-trigger${creativeOpen ? ' is-active' : ''}`}
          onClick={onToggleCreative}
          aria-pressed={creativeOpen}
          aria-label={creativeOpen ? (zh ? '关闭创作面板' : 'Close creation panel') : (zh ? '打开创作面板' : 'Open creation panel')}
        >
          <HeaderIcon name="sparkles" />
          <span>{zh ? '创作' : 'Create'}</span>
        </button>
        {runtimeKind === 'electron' && (
          <button
            type="button"
            className="nachuan-icon-button nachuan-browser-trigger"
            onClick={onToggleBrowser}
            aria-label={zh ? '内置浏览器' : 'Built-in browser'}
          >
            <HeaderIcon name="browser" />
          </button>
        )}
        <button
          type="button"
          className="nachuan-icon-button"
          onClick={onOpenSettings}
          aria-label={zh ? '打开设置' : 'Open settings'}
        >
          <HeaderIcon name="settings" />
        </button>
      </div>
    </header>
  )
}

function statusLabel(status: EngineStatus, t: (key: string) => string): string {
  if (status === 'online') return t('engine.online')
  if (status === 'degraded') return t('engine.degraded')
  if (status === 'starting') return t('engine.starting')
  return t('engine.offline')
}

export default function AppHeader({
  creativeOpen,
  onToggleNavigation,
  onToggleCreative,
  onOpenSettings,
  onToggleBrowser
}: {
  creativeOpen: boolean
  onToggleNavigation: () => void
  onToggleCreative: () => void
  onOpenSettings: () => void
  onToggleBrowser: () => void
}): React.ReactNode {
  const { t, i18n } = useTranslation()
  const status = useAppStore((state) => state.status)
  const api = window.api as typeof window.api & { runtimeKind?: RuntimeKind }
  return (
    <AppHeaderView
      runtimeKind={api.runtimeKind ?? 'electron'}
      engineTone={status}
      engineLabel={statusLabel(status, t)}
      modelControl={<ModelSelector />}
      creativeOpen={creativeOpen}
      onToggleNavigation={onToggleNavigation}
      onToggleCreative={onToggleCreative}
      onOpenSettings={onOpenSettings}
      onToggleBrowser={onToggleBrowser}
      language={i18n.language.toLowerCase().startsWith('zh') ? 'zh' : 'en'}
    />
  )
}
