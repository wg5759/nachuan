import React from 'react'
import { useTranslation } from 'react-i18next'

import { useAppStore, type EngineStatus } from '../store'
import ModelSelector from './ModelSelector'

export type RuntimeKind = 'electron' | 'web'
export type EngineTone = 'online' | 'degraded' | 'starting' | 'offline'

function HeaderIcon({ name }: { name: 'menu' | 'browser' }): React.ReactNode {
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
  return <svg {...common}><rect x="3" y="4" width="18" height="16" rx="3" /><path d="M3 9h18M7 6.5h.01M10 6.5h.01" /></svg>
}

export function AppHeaderView({
  runtimeKind,
  engineTone,
  engineLabel,
  modelControl,
  onToggleNavigation,
  onToggleBrowser,
  language = 'zh'
}: {
  runtimeKind: RuntimeKind
  engineTone: EngineTone
  engineLabel: string
  modelControl: React.ReactNode
  onToggleNavigation: () => void
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
  onToggleNavigation,
  onToggleBrowser
}: {
  onToggleNavigation: () => void
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
      onToggleNavigation={onToggleNavigation}
      onToggleBrowser={onToggleBrowser}
      language={i18n.language.toLowerCase().startsWith('zh') ? 'zh' : 'en'}
    />
  )
}
