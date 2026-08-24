import React, { useState } from 'react'
import { useTranslation } from 'react-i18next'

import { clearConvSummary } from '../api'
import { useAppStore, type ConversationKind, type ViewKey } from '../store'
import {
  PrimaryNavigation,
  type PrimaryDestination,
  type PrimaryNavigationLabels
} from './UnifiedAppShell'

export interface LeftPaneProps {
  activePrimary?: PrimaryDestination
  onPrimaryChange?: (destination: PrimaryDestination) => void
  onNavigate?: () => void
}

type GlyphName = ConversationKind | 'archive' | 'restore' | 'trash' | 'plus' | 'search' | 'grid'

function Glyph({ name }: { name: GlyphName }): React.ReactNode {
  const common = {
    viewBox: '0 0 24 24',
    fill: 'none',
    stroke: 'currentColor',
    strokeWidth: 1.8,
    strokeLinecap: 'round' as const,
    strokeLinejoin: 'round' as const,
    'aria-hidden': true
  }
  if (name === 'plus') return <svg {...common}><path d="M12 5v14M5 12h14" /></svg>
  if (name === 'search') return <svg {...common}><circle cx="11" cy="11" r="6.5" /><path d="m16 16 4 4" /></svg>
  if (name === 'code') return <svg {...common}><path d="m9 8-4 4 4 4M15 8l4 4-4 4M13 5l-2 14" /></svg>
  if (name === 'browser') return <svg {...common}><circle cx="12" cy="12" r="9" /><path d="M3 12h18M12 3c2.4 2.5 3.5 5.5 3.5 9S14.4 18.5 12 21M12 3C9.6 5.5 8.5 8.5 8.5 12S9.6 18.5 12 21" /></svg>
  if (name === 'archive') return <svg {...common}><path d="M4 7h16v13H4zM3 4h18v3H3zM9 11h6" /></svg>
  if (name === 'restore') return <svg {...common}><path d="M4 12a8 8 0 1 0 2.3-5.7L4 8.5M4 4v4.5h4.5" /></svg>
  if (name === 'trash') return <svg {...common}><path d="M4 7h16M9 7V4h6v3M7 7l1 13h8l1-13M10 11v5M14 11v5" /></svg>
  if (name === 'grid') return <svg {...common}><rect x="4" y="4" width="6" height="6" rx="1" /><rect x="14" y="4" width="6" height="6" rx="1" /><rect x="4" y="14" width="6" height="6" rx="1" /><rect x="14" y="14" width="6" height="6" rx="1" /></svg>
  return <svg {...common}><path d="M5 6.5A2.5 2.5 0 0 1 7.5 4h9A2.5 2.5 0 0 1 19 6.5v6a2.5 2.5 0 0 1-2.5 2.5H11l-4.5 3v-3A2.5 2.5 0 0 1 4 12.5v-6Z" /></svg>
}

const workspaceViews: ViewKey[] = [
  'brain',
  'kb',
  'studio',
  'sync',
  'mcp',
  'orchestrate',
  'usage',
  'about'
]

export default function LeftPane({
  activePrimary,
  onPrimaryChange,
  onNavigate
}: LeftPaneProps = {}): React.ReactNode {
  const { t } = useTranslation()
  const view = useAppStore((state) => state.view)
  const setView = useAppStore((state) => state.setView)
  const conversations = useAppStore((state) => state.conversations)
  const currentConvId = useAppStore((state) => state.currentConvId)
  const newConversation = useAppStore((state) => state.newConversation)
  const switchConversation = useAppStore((state) => state.switchConversation)
  const deleteConversation = useAppStore((state) => state.deleteConversation)
  const renameConversation = useAppStore((state) => state.renameConversation)
  const archiveConversation = useAppStore((state) => state.archiveConversation)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [editText, setEditText] = useState('')
  const [query, setQuery] = useState('')
  const [showArchived, setShowArchived] = useState(false)

  const resolvedPrimary =
    activePrimary ??
    (view === 'connections'
      ? 'connections'
      : view === 'media'
        ? 'files'
        : view === 'settings'
          ? 'settings'
          : 'chat')
  const primaryLabels: PrimaryNavigationLabels = {
    chat: t('left.primaryChat'),
    create: t('left.primaryCreate'),
    connections: t('left.primaryConnections'),
    files: t('left.primaryFiles'),
    settings: t('left.primarySettings')
  }
  const selectPrimary = (destination: PrimaryDestination): void => {
    if (onPrimaryChange) {
      onPrimaryChange(destination)
      onNavigate?.()
      return
    }
    if (destination === 'connections') setView('connections')
    else if (destination === 'files') setView('media')
    else if (destination === 'settings') setView('settings')
    else setView('chat')
    onNavigate?.()
  }
  const createConversation = (kind: ConversationKind): void => {
    newConversation(kind)
    setView('chat')
    onNavigate?.()
  }
  const openConversation = (id: string): void => {
    switchConversation(id)
    setView('chat')
    onNavigate?.()
  }
  const commitRename = (id: string): void => {
    if (editText.trim()) renameConversation(id, editText.trim())
    setEditingId(null)
  }
  const normalizedQuery = query.trim().toLowerCase()
  const archivedCount = conversations.filter((conversation) => conversation.archived).length
  const filtered = conversations
    .filter((conversation) => (showArchived ? conversation.archived : !conversation.archived))
    .filter((conversation) =>
      normalizedQuery ? conversation.title.toLowerCase().includes(normalizedQuery) : true
    )

  return (
    <div className="nachuan-left-pane">
      <PrimaryNavigation active={resolvedPrimary} labels={primaryLabels} onSelect={selectPrimary} />

      <div className="nachuan-new-conversation">
        <button type="button" className="nachuan-new-chat" onClick={() => createConversation('chat')}>
          <Glyph name="plus" />
          <span>{t('left.newChat')}</span>
        </button>
        <button type="button" onClick={() => createConversation('code')} aria-label={t('left.newCode')} title={t('left.newCode')}>
          <Glyph name="code" />
        </button>
        <button type="button" onClick={() => createConversation('browser')} aria-label={t('left.newBrowser')} title={t('left.newBrowser')}>
          <Glyph name="browser" />
        </button>
      </div>

      <label className="nachuan-conversation-search">
        <Glyph name="search" />
        <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder={t('left.search')} />
      </label>

      <div className="nachuan-conversation-section-heading">
        <span>{showArchived ? t('left.archivedTitle') : t('left.recentTitle')}</span>
        <small>{filtered.length}</small>
      </div>
      <div className="nachuan-conversation-list">
        {filtered.length === 0 && (
          <div className="nachuan-conversation-empty">
            {query ? t('left.noMatch') : t('left.empty')}
          </div>
        )}
        {filtered.map((conversation) => {
          const active = conversation.id === currentConvId && view === 'chat'
          const title = conversation.title === '新对话' ? t('left.untitled') : conversation.title
          return (
            <div
              key={conversation.id}
              role="button"
              tabIndex={0}
              data-conversation-kind={conversation.kind}
              className={`nachuan-conversation-row${active ? ' is-active' : ''}`}
              onClick={() => openConversation(conversation.id)}
              onKeyDown={(event) => {
                if (event.key === 'Enter' || event.key === ' ') openConversation(conversation.id)
              }}
            >
              <span className="nachuan-conversation-kind"><Glyph name={conversation.kind} /></span>
              {editingId === conversation.id ? (
                <input
                  autoFocus
                  value={editText}
                  onChange={(event) => setEditText(event.target.value)}
                  onClick={(event) => event.stopPropagation()}
                  onBlur={() => commitRename(conversation.id)}
                  onKeyDown={(event) => {
                    event.stopPropagation()
                    if (event.key === 'Enter') commitRename(conversation.id)
                    else if (event.key === 'Escape') setEditingId(null)
                  }}
                  className="nachuan-conversation-rename"
                />
              ) : (
                <span
                  className="nachuan-conversation-title"
                  title={t('left.dblRename')}
                  onDoubleClick={(event) => {
                    event.stopPropagation()
                    setEditingId(conversation.id)
                    setEditText(conversation.title)
                  }}
                >
                  {title}
                </span>
              )}
              <span className="nachuan-conversation-actions">
                <button
                  type="button"
                  onClick={(event) => {
                    event.stopPropagation()
                    archiveConversation(conversation.id, !conversation.archived)
                  }}
                  aria-label={conversation.archived ? t('left.unarchiveTitle') : t('left.archiveTitle')}
                  title={conversation.archived ? t('left.unarchiveTitle') : t('left.archiveTitle')}
                >
                  <Glyph name={conversation.archived ? 'restore' : 'archive'} />
                </button>
                <button
                  type="button"
                  onClick={(event) => {
                    event.stopPropagation()
                    if (window.confirm(t('left.delConfirm', { t: title }))) {
                      void clearConvSummary(conversation.id)
                      deleteConversation(conversation.id)
                    }
                  }}
                  aria-label={t('left.delTitle')}
                  title={t('left.delTitle')}
                >
                  <Glyph name="trash" />
                </button>
              </span>
            </div>
          )
        })}
      </div>

      {(archivedCount > 0 || showArchived) && (
        <button type="button" className="nachuan-archive-toggle" onClick={() => setShowArchived((value) => !value)}>
          {showArchived ? t('left.backToActive') : t('left.showArchived', { n: archivedCount })}
        </button>
      )}

      <details className="nachuan-workspace-menu">
        <summary>
          <span><Glyph name="grid" />{t('left.workspaceTitle')}</span>
          <span aria-hidden="true">⌄</span>
        </summary>
        <div>
          {workspaceViews.map((destination) => (
            <button
              key={destination}
              type="button"
              data-workspace-destination={destination}
              aria-current={view === destination ? 'page' : undefined}
              onClick={() => {
                setView(destination)
                onNavigate?.()
              }}
            >
              <span>{t(`left.workspace.${destination}`)}</span>
            </button>
          ))}
        </div>
      </details>
    </div>
  )
}
