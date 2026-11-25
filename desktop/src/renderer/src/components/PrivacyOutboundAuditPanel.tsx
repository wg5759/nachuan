import React, { useCallback, useEffect, useRef, useState } from 'react'

import {
  clearOutboundAudit,
  getOutboundAudit,
  type OutboundAuditItem,
  type OutboundAuditSnapshot
} from '../api'
import { useTranslation } from '../i18n'
import { useAppStore } from '../store'

export type OutboundAuditFilter = 'all' | 'external' | 'blocked'

export const OUTBOUND_AUDIT_POLL_INTERVAL_MS = 3000

const EMPTY_SNAPSHOT: OutboundAuditSnapshot = {
  offline_mode: false,
  total_allowed: 0,
  total_blocked: 0,
  non_loopback_count: 0,
  items: []
}

export function filterOutboundAuditItems(
  items: readonly OutboundAuditItem[],
  filter: OutboundAuditFilter
): OutboundAuditItem[] {
  if (filter === 'external') return items.filter((item) => !item.is_loopback)
  if (filter === 'blocked') return items.filter((item) => item.blocked)
  return [...items]
}

export function computeOutboundAuditCounts(snapshot: OutboundAuditSnapshot): {
  externalCount: number
  blockedCount: number
  loopbackCount: number
} {
  const externalCount = Math.max(0, snapshot.non_loopback_count)
  const blockedCount = Math.max(0, snapshot.total_blocked)
  const itemsLoopbackCount = snapshot.items.filter((item) => item.is_loopback).length
  const totalRecorded = Math.max(0, snapshot.total_allowed) + blockedCount
  let loopbackCount: number
  if (snapshot.items.length > 0 && totalRecorded === snapshot.items.length) {
    loopbackCount = itemsLoopbackCount
  } else if (snapshot.total_allowed >= externalCount) {
    loopbackCount = snapshot.total_allowed - externalCount
  } else {
    loopbackCount = Math.max(itemsLoopbackCount, snapshot.total_allowed)
  }
  return { externalCount, blockedCount, loopbackCount }
}

export function formatAuditTimestamp(tsMs: number): string {
  if (!Number.isFinite(tsMs) || tsMs <= 0) return '--:--:--'
  const date = new Date(tsMs)
  const pad = (n: number): string => String(n).padStart(2, '0')
  return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`
}

export function formatAuditHost(item: OutboundAuditItem): string {
  if (!item.host) return '-'
  return item.port !== null ? `${item.host}:${item.port}` : item.host
}

export interface PrivacyOutboundAuditPanelViewProps {
  snapshot: OutboundAuditSnapshot
  offlineMode: boolean
  filter: OutboundAuditFilter
  paused: boolean
  loading: boolean
  togglingOffline: boolean
  clearing: boolean
  notice?: string
  error?: string
  onToggleOfflineMode: () => void
  onFilterChange: (next: OutboundAuditFilter) => void
  onTogglePolling: () => void
  onRefresh: () => void
  onClear: () => void
}

export type PrivacyAuditTranslate = (key: string, opts?: Record<string, unknown>) => string

export async function performOfflineModeToggle(
  currentOfflineMode: boolean,
  toggleFn: (enabled: boolean) => Promise<{ ok: boolean; enabled: boolean }>
): Promise<{ ok: boolean; enabled: boolean }> {
  return toggleFn(!currentOfflineMode)
}

export async function performClearOutboundAudit(): Promise<{ ok: boolean; cleared: number }> {
  return clearOutboundAudit()
}

export function buildPrivacyOutboundAuditPanelTree(
  {
    snapshot,
    offlineMode,
    filter,
    paused,
    loading,
    togglingOffline,
    clearing,
    notice = '',
    error = '',
    onToggleOfflineMode,
    onFilterChange,
    onTogglePolling,
    onRefresh,
    onClear
  }: PrivacyOutboundAuditPanelViewProps,
  t: PrivacyAuditTranslate
): React.ReactNode {
  const counts = computeOutboundAuditCounts(snapshot)
  const filteredItems = filterOutboundAuditItems(snapshot.items, filter)

  return (
    <section
      id="privacy-outbound-audit"
      data-testid="privacy-outbound-audit-panel"
      className="nachuan-settings-card nachuan-audit"
      aria-label={t('privacyAudit.sectionAria')}
    >
      <div className="nachuan-audit-hero">
        <div className="nachuan-audit-hero-copy">
          <div className="nachuan-audit-heading-line">
            <span className="nachuan-audit-eyebrow">{t('privacyAudit.eyebrow')}</span>
            <span
              data-testid="offline-mode-status-badge"
              className={`nachuan-audit-mode-badge${offlineMode ? ' is-offline' : ''}`}
            >
              {offlineMode ? t('privacyAudit.statusActive') : t('privacyAudit.statusStandard')}
            </span>
          </div>
          <h2>{t('privacyAudit.title')}</h2>
          <p>{t('privacyAudit.desc')}</p>
        </div>

        <button
          type="button"
          role="switch"
          data-testid="toggle-offline-mode"
          aria-checked={offlineMode}
          aria-label={t('privacyAudit.toggleAria')}
          disabled={togglingOffline}
          className={`nachuan-switch nachuan-audit-switch${offlineMode ? ' is-offline' : ''}`}
          onClick={onToggleOfflineMode}
        >
          <span />
        </button>
      </div>

      <div className="nachuan-audit-stats" role="group" aria-label={t('privacyAudit.sectionAria')}>
        <div
          data-testid="audit-stat-external"
          className={`nachuan-audit-stat${counts.externalCount > 0 ? ' is-warn' : ' is-clean'}`}
        >
          <span>{t('privacyAudit.statExternal')}</span>
          <strong>{counts.externalCount}</strong>
        </div>
        <div
          data-testid="audit-stat-blocked"
          className={`nachuan-audit-stat${counts.blockedCount > 0 ? ' is-blocked' : ''}`}
        >
          <span>{t('privacyAudit.statBlocked')}</span>
          <strong>{counts.blockedCount}</strong>
        </div>
        <div data-testid="audit-stat-loopback" className="nachuan-audit-stat is-loopback">
          <span>{t('privacyAudit.statLoopback')}</span>
          <strong>{counts.loopbackCount}</strong>
        </div>
      </div>

      <div className="nachuan-audit-toolbar">
        <div
          className="nachuan-segmented"
          role="group"
          aria-label={t('privacyAudit.filterAria')}
        >
          <button
            type="button"
            data-testid="filter-all"
            aria-pressed={filter === 'all'}
            onClick={() => onFilterChange('all')}
          >
            {t('privacyAudit.filterAll')}
          </button>
          <button
            type="button"
            data-testid="filter-external"
            aria-pressed={filter === 'external'}
            onClick={() => onFilterChange('external')}
          >
            {t('privacyAudit.filterExternal')}
          </button>
          <button
            type="button"
            data-testid="filter-blocked"
            aria-pressed={filter === 'blocked'}
            onClick={() => onFilterChange('blocked')}
          >
            {t('privacyAudit.filterBlocked')}
          </button>
        </div>

        <div className="nachuan-audit-actions">
          <span className={`nachuan-audit-poll-indicator${paused ? ' is-paused' : ''}`}>
            {paused ? t('privacyAudit.pausedBadge') : t('privacyAudit.pollingBadge')}
          </span>
          <button
            type="button"
            data-testid="toggle-audit-polling"
            className="nachuan-audit-btn"
            onClick={onTogglePolling}
          >
            {paused ? t('privacyAudit.resumePolling') : t('privacyAudit.pausePolling')}
          </button>
          <button
            type="button"
            data-testid="refresh-outbound-audit"
            className="nachuan-audit-btn"
            disabled={loading}
            onClick={onRefresh}
          >
            {loading ? t('privacyAudit.refreshing') : t('privacyAudit.refresh')}
          </button>
          <button
            type="button"
            data-testid="clear-outbound-audit"
            className="nachuan-audit-btn nachuan-audit-btn--danger"
            disabled={clearing}
            onClick={onClear}
          >
            {clearing ? t('privacyAudit.clearing') : t('privacyAudit.clear')}
          </button>
        </div>
      </div>

      {snapshot.unavailable && (
        <p className="nachuan-audit-banner is-muted" role="status">
          {t('privacyAudit.unavailable')}
        </p>
      )}
      {notice && (
        <p className="nachuan-audit-banner is-ok" role="status">
          {notice}
        </p>
      )}
      {error && (
        <p className="nachuan-audit-banner is-error" role="alert">
          {error}
        </p>
      )}

      <div className="nachuan-audit-table-wrap">
        <table className="nachuan-audit-table" data-testid="outbound-audit-table">
          <thead>
            <tr>
              <th>{t('privacyAudit.colTime')}</th>
              <th>{t('privacyAudit.colMethod')}</th>
              <th>{t('privacyAudit.colTarget')}</th>
              <th>{t('privacyAudit.colCaller')}</th>
              <th>{t('privacyAudit.colStatus')}</th>
              <th>{t('privacyAudit.colVerdict')}</th>
            </tr>
          </thead>
          <tbody>
            {filteredItems.length === 0 ? (
              <tr>
                <td colSpan={6} className="nachuan-audit-empty">
                  {t('privacyAudit.empty')}
                </td>
              </tr>
            ) : (
              filteredItems.map((item) => {
                const hostText = formatAuditHost(item)
                const statusText =
                  item.status_code !== null
                    ? `${item.status_code}${item.latency_ms !== null ? ` · ${item.latency_ms}ms` : ''}`
                    : item.latency_ms !== null
                      ? `${item.latency_ms}ms`
                      : item.error || '-'
                return (
                  <tr
                    key={item.id}
                    data-audit-id={item.id}
                    data-loopback={item.is_loopback ? 'true' : 'false'}
                    data-blocked={item.blocked ? 'true' : 'false'}
                    className={
                      item.blocked
                        ? 'is-row-blocked'
                        : !item.is_loopback
                          ? 'is-row-external'
                          : 'is-row-loopback'
                    }
                  >
                    <td className="nachuan-audit-mono">{formatAuditTimestamp(item.ts_ms)}</td>
                    <td>
                      <span className="nachuan-audit-method">{item.method}</span>
                    </td>
                    <td>
                      <div className="nachuan-audit-target">
                        <span
                          className={`nachuan-audit-host-badge${
                            item.is_loopback ? ' is-loopback' : ' is-external'
                          }`}
                        >
                          {item.is_loopback
                            ? t('privacyAudit.tagLoopback')
                            : t('privacyAudit.tagExternal')}
                        </span>
                        <span
                          className={`nachuan-audit-host${
                            item.is_loopback ? ' is-loopback' : ' is-external'
                          }`}
                          title={`${item.scheme ? `${item.scheme}://` : ''}${hostText}${item.path}`}
                        >
                          {hostText}
                        </span>
                      </div>
                      {item.path && (
                        <div className="nachuan-audit-path" title={item.path}>
                          {item.path}
                        </div>
                      )}
                    </td>
                    <td className="nachuan-audit-mono">{item.caller || '-'}</td>
                    <td className="nachuan-audit-mono">{statusText}</td>
                    <td>
                      <span
                        className={`nachuan-audit-verdict${
                          item.blocked ? ' is-blocked' : ' is-allowed'
                        }`}
                      >
                        {item.blocked
                          ? t('privacyAudit.verdictBlocked')
                          : t('privacyAudit.verdictAllowed')}
                      </span>
                      {(item.block_reason || item.error) && (
                        <div className="nachuan-audit-reason">
                          {item.block_reason || item.error}
                        </div>
                      )}
                    </td>
                  </tr>
                )
              })
            )}
          </tbody>
        </table>
      </div>
    </section>
  )
}

export function PrivacyOutboundAuditPanelView(
  props: PrivacyOutboundAuditPanelViewProps
): React.ReactNode {
  const { t } = useTranslation()
  return buildPrivacyOutboundAuditPanelTree(props, t)
}

export interface PrivacyOutboundAuditPanelProps {
  pollIntervalMs?: number
  initialSnapshot?: OutboundAuditSnapshot
  initialFilter?: OutboundAuditFilter
}

export default function PrivacyOutboundAuditPanel({
  pollIntervalMs = OUTBOUND_AUDIT_POLL_INTERVAL_MS,
  initialSnapshot = EMPTY_SNAPSHOT,
  initialFilter = 'all'
}: PrivacyOutboundAuditPanelProps = {}): React.ReactNode {
  const { t } = useTranslation()
  const offlineMode = useAppStore((state) => state.offlineMode)
  const setOfflineModeState = useAppStore((state) => state.setOfflineModeState)
  const toggleOfflineMode = useAppStore((state) => state.toggleOfflineMode)

  const [snapshot, setSnapshot] = useState<OutboundAuditSnapshot>(initialSnapshot)
  const [filter, setFilter] = useState<OutboundAuditFilter>(initialFilter)
  const [paused, setPaused] = useState(false)
  const [loading, setLoading] = useState(false)
  const [togglingOffline, setTogglingOffline] = useState(false)
  const [clearing, setClearing] = useState(false)
  const [notice, setNotice] = useState('')
  const [error, setError] = useState('')
  const mountedRef = useRef(true)

  const refresh = useCallback(async () => {
    setLoading(true)
    try {
      const next = await getOutboundAudit({ limit: 200 })
      if (!mountedRef.current) return
      setSnapshot(next)
      if (!next.unavailable) {
        setOfflineModeState(next.offline_mode)
      }
    } finally {
      if (mountedRef.current) setLoading(false)
    }
  }, [setOfflineModeState])

  useEffect(() => {
    mountedRef.current = true
    void refresh()
    return () => {
      mountedRef.current = false
    }
  }, [refresh])

  useEffect(() => {
    if (paused || pollIntervalMs <= 0) return
    const timer = window.setInterval(() => {
      void refresh()
    }, pollIntervalMs)
    return () => window.clearInterval(timer)
  }, [paused, pollIntervalMs, refresh])

  const handleToggleOfflineMode = useCallback(async () => {
    setTogglingOffline(true)
    setError('')
    setNotice('')
    try {
      const result = await performOfflineModeToggle(offlineMode, toggleOfflineMode)
      if (!mountedRef.current) return
      if (!result.ok) {
        setError(t('privacyAudit.toggleFailed'))
        return
      }
      setSnapshot((current) => ({ ...current, offline_mode: result.enabled }))
      await refresh()
    } finally {
      if (mountedRef.current) setTogglingOffline(false)
    }
  }, [offlineMode, refresh, t, toggleOfflineMode])

  const handleClear = useCallback(async () => {
    setClearing(true)
    setError('')
    setNotice('')
    try {
      const result = await performClearOutboundAudit()
      if (!mountedRef.current) return
      if (!result.ok) {
        setError(t('privacyAudit.clearFailed'))
        return
      }
      setNotice(t('privacyAudit.clearedNotice', { n: result.cleared }))
      setSnapshot((current) => ({
        ...current,
        total_allowed: 0,
        total_blocked: 0,
        non_loopback_count: 0,
        items: []
      }))
      await refresh()
    } finally {
      if (mountedRef.current) setClearing(false)
    }
  }, [refresh, t])

  return (
    <PrivacyOutboundAuditPanelView
      snapshot={snapshot}
      offlineMode={offlineMode}
      filter={filter}
      paused={paused}
      loading={loading}
      togglingOffline={togglingOffline}
      clearing={clearing}
      notice={notice}
      error={error}
      onToggleOfflineMode={() => void handleToggleOfflineMode()}
      onFilterChange={setFilter}
      onTogglePolling={() => setPaused((prev) => !prev)}
      onRefresh={() => void refresh()}
      onClear={() => void handleClear()}
    />
  )
}
