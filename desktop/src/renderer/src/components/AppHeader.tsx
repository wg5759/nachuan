import React from 'react'
import { useTranslation } from '../i18n'

import { useAppStore, type EngineStatus } from '../store'
import ModelSelector from './ModelSelector'

export type RuntimeKind = 'electron' | 'web'
export type EngineTone = 'online' | 'degraded' | 'starting' | 'offline'

function HeaderIcon({
  name
}: {
  name: 'menu' | 'sparkles' | 'settings' | 'browser' | 'shield' | 'shieldCheck' | 'code' | 'terminal'
}): React.ReactNode {
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
  if (name === 'code') {
    return <svg {...common}><path d="m8 9-4 3 4 3M16 9l4 3-4 3M13.5 6l-3 12" /></svg>
  }
  if (name === 'terminal') {
    return <svg {...common}><rect x="3" y="4" width="18" height="16" rx="3" /><path d="m8 10 3 2.5L8 15M13 15h4" /></svg>
  }
  if (name === 'sparkles') {
    return <svg {...common}><path d="m12 3 1.1 3.9L17 8l-3.9 1.1L12 13l-1.1-3.9L7 8l3.9-1.1L12 3Z" /><path d="m18 14 .7 2.3L21 17l-2.3.7L18 20l-.7-2.3L15 17l2.3-.7L18 14Z" /></svg>
  }
  if (name === 'browser') {
    return <svg {...common}><rect x="3" y="4" width="18" height="16" rx="3" /><path d="M3 9h18M7 6.5h.01M10 6.5h.01" /></svg>
  }
  if (name === 'shield') {
    return <svg {...common}><path d="M12 3 19 6v5.4c0 4.3-2.8 7.8-7 9.6-4.2-1.8-7-5.3-7-9.6V6l7-3Z" /></svg>
  }
  if (name === 'shieldCheck') {
    return (
      <svg {...common}>
        <path d="M12 3 19 6v5.4c0 4.3-2.8 7.8-7 9.6-4.2-1.8-7-5.3-7-9.6V6l7-3Z" />
        <path d="m9 12.2 2.1 2.1 4.2-4.4" />
      </svg>
    )
  }
  return <svg {...common}><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1-2.8 2.8-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.6v.2h-4V21a1.7 1.7 0 0 0-1-1.6 1.7 1.7 0 0 0-1.9.3l-.1.1L4.2 17l.1-.1a1.7 1.7 0 0 0 .3-1.9A1.7 1.7 0 0 0 3 14H2.8v-4H3a1.7 1.7 0 0 0 1.6-1 1.7 1.7 0 0 0-.3-1.9L4.2 7 7 4.2l.1.1A1.7 1.7 0 0 0 9 4.6 1.7 1.7 0 0 0 10 3v-.2h4V3a1.7 1.7 0 0 0 1 1.6 1.7 1.7 0 0 0 1.9-.3l.1-.1L19.8 7l-.1.1a1.7 1.7 0 0 0-.3 1.9 1.7 1.7 0 0 0 1.6 1h.2v4H21a1.7 1.7 0 0 0-1.6 1Z" /></svg>
}

export function AppHeaderView({
  runtimeKind,
  engineTone,
  engineLabel,
  modelControl,
  creativeOpen,
  codingOpen = false,
  codingStudioOpen = false,
  offlineMode = false,
  onToggleNavigation,
  onOpenCoding,
  onOpenCodingStudio,
  onToggleCreative,
  onOpenSettings,
  onOpenPrivacyAudit,
  onToggleBrowser,
  language = 'zh'
}: {
  runtimeKind: RuntimeKind
  engineTone: EngineTone
  engineLabel: string
  modelControl: React.ReactNode
  creativeOpen: boolean
  codingOpen?: boolean
  codingStudioOpen?: boolean
  offlineMode?: boolean
  onToggleNavigation: () => void
  onOpenCoding?: () => void
  onOpenCodingStudio?: () => void
  onToggleCreative: () => void
  onOpenSettings: () => void
  onOpenPrivacyAudit?: () => void
  onToggleBrowser: () => void
  language?: 'zh' | 'en'
}): React.ReactNode {
  const zh = language === 'zh'
  const noDrag = { WebkitAppRegion: 'no-drag' } as React.CSSProperties
  const drag = { WebkitAppRegion: runtimeKind === 'electron' ? 'drag' : 'no-drag' } as React.CSSProperties
  const privacyChipLabel = offlineMode
    ? zh
      ? '纯离线 · 0 外联'
      : 'Air-Gapped · 0 External'
    : zh
      ? '零遥测审计'
      : 'Zero-Telemetry'
  const privacyChipTitle = zh
    ? '查看实时网络出站审计与纯离线模式设置'
    : 'Open real-time outbound network audit and air-gap offline mode settings'
  const handleOpenPrivacyAudit = onOpenPrivacyAudit ?? onOpenSettings
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
          <strong>{zh ? '纳川' : 'Nachuan'}</strong>
          <small>{zh ? '一处连接，协同所有模型' : 'One place for every model'}</small>
        </span>
      </div>

      <div className="nachuan-header-actions" style={noDrag}>
        <div className="nachuan-model-control">{modelControl}</div>
        <button
          type="button"
          data-testid="privacy-status-chip"
          data-offline-mode={offlineMode ? 'true' : 'false'}
          className={`nachuan-privacy-chip ${
            offlineMode ? 'nachuan-privacy-chip--offline' : 'nachuan-privacy-chip--audit'
          }`}
          onClick={handleOpenPrivacyAudit}
          title={privacyChipTitle}
          aria-label={privacyChipTitle}
        >
          <HeaderIcon name={offlineMode ? 'shieldCheck' : 'shield'} />
          <span>{privacyChipLabel}</span>
        </button>
        <span className={`nachuan-engine-status nachuan-engine-status--${engineTone}`} title={engineLabel}>
          <span aria-hidden="true" />
          {engineLabel}
        </span>
        {onOpenCoding && (
          <button
            type="button"
            data-testid="coding-control-trigger"
            className={`nachuan-creative-trigger nachuan-coding-trigger${codingOpen ? ' is-active' : ''}`}
            onClick={onOpenCoding}
            aria-pressed={codingOpen}
            aria-label={
              codingOpen
                ? zh
                  ? '返回对话视图'
                  : 'Back to conversation'
                : zh
                  ? '打开编码控制面'
                  : 'Open coding control plane'
            }
          >
            <HeaderIcon name="code" />
            <span>{zh ? '编码' : 'Code'}</span>
          </button>
        )}
        {onOpenCodingStudio && (
          <button
            type="button"
            data-testid="header-coding-studio-btn"
            className={`nachuan-creative-trigger nachuan-coding-trigger${codingStudioOpen ? ' is-active' : ''}`}
            onClick={onOpenCodingStudio}
            aria-pressed={codingStudioOpen}
            aria-label={zh ? '打开编码工作台' : 'Open Coding Studio'}
            title={zh ? '多 Worktree 编码工作台与跨端审批队列' : 'Multi-worktree Coding Studio and cross-device approval queue'}
          >
            <HeaderIcon name="terminal" />
            <span>{zh ? '编码工作台' : 'Coding Studio'}</span>
          </button>
        )}
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
  codingOpen = false,
  codingStudioOpen = false,
  onToggleNavigation,
  onOpenCoding,
  onOpenCodingStudio,
  onToggleCreative,
  onOpenSettings,
  onOpenPrivacyAudit,
  onToggleBrowser
}: {
  creativeOpen: boolean
  codingOpen?: boolean
  codingStudioOpen?: boolean
  onToggleNavigation: () => void
  onOpenCoding?: () => void
  onOpenCodingStudio?: () => void
  onToggleCreative: () => void
  onOpenSettings: () => void
  onOpenPrivacyAudit?: () => void
  onToggleBrowser: () => void
}): React.ReactNode {
  const { t, i18n } = useTranslation()
  const status = useAppStore((state) => state.status)
  const offlineMode = useAppStore((state) => state.offlineMode)
  const api = window.api as typeof window.api & { runtimeKind?: RuntimeKind }
  return (
    <AppHeaderView
      runtimeKind={api.runtimeKind ?? 'electron'}
      engineTone={status}
      engineLabel={statusLabel(status, t)}
      modelControl={<ModelSelector />}
      creativeOpen={creativeOpen}
      codingOpen={codingOpen}
      codingStudioOpen={codingStudioOpen}
      offlineMode={offlineMode}
      onToggleNavigation={onToggleNavigation}
      onOpenCoding={onOpenCoding}
      onOpenCodingStudio={onOpenCodingStudio}
      onToggleCreative={onToggleCreative}
      onOpenSettings={onOpenSettings}
      onOpenPrivacyAudit={onOpenPrivacyAudit}
      onToggleBrowser={onToggleBrowser}
      language={i18n.language.toLowerCase().startsWith('zh') ? 'zh' : 'en'}
    />
  )
}
