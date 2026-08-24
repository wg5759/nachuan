import React, { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { fetchUsage, type UsageRow, type UsageSummary } from '../api'

const BAR_COLORS = [
  '#22c55e',
  '#3b82f6',
  '#a855f7',
  '#f59e0b',
  '#ef4444',
  '#14b8a6',
  '#ec4899',
  '#84cc16',
  '#f97316',
  '#6366f1'
]

// Financial aggregation may scan a large append-only ledger.  Keep live mode
// useful without turning an open dashboard into a write-path contention loop.
const USAGE_POLL_INTERVAL_MS = 60_000

const isFleetUsageRow = (row: UsageRow): boolean =>
  row.provider === 'fleet' || row.resolved_model.startsWith('nachuan')

export default function UsagePane(): React.ReactNode {
  const { t } = useTranslation()
  const [data, setData] = useState<UsageSummary | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [live, setLive] = useState(true)
  const [budget, setBudget] = useState<number>(
    () => Number(localStorage.getItem('usage.budget')) || 5
  )
  const refreshInFlight = useRef(false)

  const saveBudget = (value: number): void => {
    setBudget(value)
    localStorage.setItem('usage.budget', String(value))
  }
  const refresh = useCallback(async (): Promise<void> => {
    // The financial ledger is append-only and may be large.  Never overlap
    // summary reads when a previous poll is still running.
    if (refreshInFlight.current) return
    refreshInFlight.current = true
    try {
      setData(await fetchUsage())
      setError(null)
    } catch (reason) {
      setError(String(reason))
    } finally {
      refreshInFlight.current = false
    }
  }, [])

  useEffect(() => {
    let cancelled = false
    let timer: ReturnType<typeof setTimeout> | undefined
    const poll = async (): Promise<void> => {
      if (document.visibilityState === 'visible') await refresh()
      if (!cancelled && live) timer = setTimeout(() => void poll(), USAGE_POLL_INTERVAL_MS)
    }
    void poll()
    return () => {
      cancelled = true
      if (timer !== undefined) clearTimeout(timer)
    }
  }, [live, refresh])

  const fmt = (value: number): string => value.toLocaleString()
  const models = data?.models ?? []
  const maxTok = Math.max(1, ...models.map((model) => model.known_total_tokens))
  const authoritative = data?.financial_source === true
  const completeCost =
    authoritative && data.billed_cost_complete && data.total_cost_usd !== null

  const tokenText = (row: UsageRow): string =>
    row.total_tokens === null
      ? `${fmt(row.known_total_tokens)} + ?`
      : fmt(row.total_tokens)
  const costText = (row: UsageRow): string => {
    if (row.billed_cost_complete && row.cost_usd !== null) return `$${row.cost_usd}`
    const parts: string[] = []
    if (row.invoice_reconciled_cost_usd > 0) {
      parts.push(t('usage.reconciledCost', { cost: row.invoice_reconciled_cost_usd }))
    }
    if (row.provider_reported_cost_usd > 0) {
      parts.push(t('usage.reportedCost', { cost: row.provider_reported_cost_usd }))
    }
    if (row.estimated_cost_usd > 0) {
      parts.push(t('usage.estimatedCost', { cost: row.estimated_cost_usd }))
    }
    if (row.unclassified_cost_usd > 0) {
      parts.push(t('usage.unverifiedCost', { cost: row.unclassified_cost_usd }))
    }
    if (row.unknown_cost_calls > 0) {
      parts.push(t('usage.unknownCost', { count: row.unknown_cost_calls }))
    }
    return parts.length > 0 ? parts.join(' + ') : t('usage.noCostEvidence')
  }

  const summaryCostText = (): string => {
    if (!data) return ''
    if (completeCost) return `$${data.total_cost_usd}`
    const parts: string[] = []
    if (data.invoice_reconciled_cost_usd > 0) {
      parts.push(t('usage.reconciledCost', { cost: data.invoice_reconciled_cost_usd }))
    }
    if (data.provider_reported_cost_usd > 0) {
      parts.push(t('usage.reportedCost', { cost: data.provider_reported_cost_usd }))
    }
    if (data.estimated_cost_usd > 0) {
      parts.push(t('usage.estimatedCost', { cost: data.estimated_cost_usd }))
    }
    if (data.unclassified_cost_usd > 0) {
      parts.push(t('usage.unverifiedCost', { cost: data.unclassified_cost_usd }))
    }
    if (data.unknown_cost_calls > 0) {
      parts.push(t('usage.unknownCost', { count: data.unknown_cost_calls }))
    }
    return parts.length > 0 ? parts.join(' + ') : '$0'
  }

  return (
    <div className="p-4 space-y-3 overflow-auto h-full">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">{t('usage.title')}</h2>
        <div className="flex items-center gap-3">
          <label className="text-xs flex items-center gap-1 cursor-pointer select-none">
            <input type="checkbox" checked={live} onChange={(event) => setLive(event.target.checked)} />
            {t('usage.live')}
          </label>
          <button
            onClick={() => void refresh()}
            className="px-3 py-1 text-sm rounded border border-neutral-700 hover:bg-neutral-800"
          >
            {t('usage.refresh')}
          </button>
        </div>
      </div>

      {error && <div className="text-red-400 text-sm">{error}</div>}
      {data && !authoritative && (
        <div className="rounded border border-red-900 bg-red-950/30 p-3 text-sm text-red-300">
          {t('usage.financialUnavailable')}
        </div>
      )}

      {data && authoritative && (
        <>
          <div className="text-sm text-neutral-400 flex flex-wrap items-center gap-2">
            <span>
              {t('usage.total')}：
              <span className={completeCost ? 'text-green-400 font-mono' : 'text-amber-400 font-mono'}>
                {summaryCostText()}
              </span>
            </span>
            {data.outcome_unknown_calls > 0 && (
              <span className="text-amber-400">
                {t('usage.unknownOutcomes', { count: data.outcome_unknown_calls })}
              </span>
            )}
            {live && (
              <span className="text-xs text-green-500 flex items-center gap-1">
                <span className="inline-block w-2 h-2 rounded-full bg-green-500 animate-pulse" />
                {t('usage.liveOn')}
              </span>
            )}
          </div>

          {data.capacity_status !== 'ok' && (
            <div className="rounded border border-amber-900 bg-amber-950/20 p-2 text-xs text-amber-300">
              {t('usage.capacityWarning', { percent: Math.round(data.capacity_ratio * 100) })}
            </div>
          )}

          {completeCost ? (
            <div>
              <div className="flex justify-between items-center text-xs mb-0.5">
                <span className="text-neutral-400">{t('usage.budget')}</span>
                <span className="font-mono">
                  ${data.total_cost_usd} / $
                  <input
                    type="number"
                    value={budget}
                    onChange={(event) => saveBudget(Number(event.target.value) || 0)}
                    className="w-14 bg-neutral-800 rounded px-1 text-right ml-0.5"
                  />
                </span>
              </div>
              <div className="h-2 rounded bg-neutral-800 overflow-hidden">
                <div
                  className="h-full rounded transition-all"
                  style={{
                    width: `${Math.min(100, budget > 0 ? ((data.total_cost_usd ?? 0) / budget) * 100 : 0)}%`,
                    background:
                      (data.total_cost_usd ?? 0) >= budget
                        ? '#ef4444'
                        : (data.total_cost_usd ?? 0) >= budget * 0.8
                          ? '#f59e0b'
                          : '#22c55e'
                  }}
                />
              </div>
              {(data.total_cost_usd ?? 0) >= budget && (
                <div className="text-red-400 text-xs mt-0.5">⚠️ {t('usage.over')}</div>
              )}
            </div>
          ) : (
            <div className="rounded border border-amber-900 bg-amber-950/20 p-2 text-xs text-amber-300">
              {t('usage.budgetDisabled', {
                count: data.unknown_cost_calls,
                reported: data.provider_reported_cost_calls,
                estimated: data.estimated_cost_calls,
                unverified: data.unverified_cost_calls
              })}
            </div>
          )}

          <div className="space-y-1.5">
            {models.map((model, index) => {
              const pct = Math.round((model.known_total_tokens / maxTok) * 100)
              const color = BAR_COLORS[index % BAR_COLORS.length]
              return (
                <div
                  key={`${model.provider}:${model.model}:${model.resolved_model}`}
                  className="text-xs"
                >
                  <div className="flex justify-between mb-0.5">
                    <span className="font-mono">
                      {model.model}
                      <span className="ml-1 text-neutral-500">({model.provider})</span>
                      {isFleetUsageRow(model) && (
                        <span className="ml-1 cursor-default text-amber-400" title={t('usage.fleetBadge')}>
                          ⚡
                        </span>
                      )}
                    </span>
                    <span className="text-neutral-400 font-mono">
                      {tokenText(model)} tok · {costText(model)} · {model.calls}×
                    </span>
                  </div>
                  <div className="h-3 rounded bg-neutral-800 overflow-hidden">
                    <div
                      className="h-full rounded transition-all duration-500"
                      style={{ width: `${pct}%`, background: color }}
                    />
                  </div>
                </div>
              )
            })}
            {models.length === 0 && (
              <div className="text-neutral-600 text-sm py-2">{t('usage.empty')}</div>
            )}
          </div>

          <table className="w-full text-xs mt-2">
            <thead className="text-neutral-500 border-b border-neutral-800">
              <tr>
                <th className="text-left py-1">{t('usage.model')}</th>
                <th className="text-right">{t('usage.calls')}</th>
                <th className="text-right">{t('usage.in')}</th>
                <th className="text-right">{t('usage.cached')}</th>
                <th className="text-right">{t('usage.out')}</th>
                <th className="text-right">{t('usage.cost')}</th>
                <th className="text-left pl-2">{t('usage.basis')}</th>
              </tr>
            </thead>
            <tbody>
              {models.map((model) => (
                <tr
                  key={`${model.provider}:${model.model}:${model.resolved_model}`}
                  className="border-b border-neutral-900"
                >
                  <td className="py-1 font-mono">{model.model}</td>
                  <td className="text-right">{model.calls}</td>
                  <td className="text-right font-mono">
                    {fmt(model.known_prompt_tokens)}{model.prompt_tokens === null ? ' + ?' : ''}
                  </td>
                  <td className="text-right font-mono text-green-500">
                    {fmt(model.known_cached_tokens)}{model.cached_tokens === null ? ' + ?' : ''}
                  </td>
                  <td className="text-right font-mono">
                    {fmt(model.known_completion_tokens)}{model.completion_tokens === null ? ' + ?' : ''}
                  </td>
                  <td className="text-right font-mono">{costText(model)}</td>
                  <td className="pl-2 text-neutral-500">{model.cost_basis}</td>
                </tr>
              ))}
              {models.length === 0 && (
                <tr>
                  <td colSpan={7} className="text-neutral-600 py-2">
                    {t('usage.empty')}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </>
      )}
    </div>
  )
}
