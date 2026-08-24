import React, { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  clearAgentMemory,
  fetchAgentCases,
  fetchAgentMemory,
  fetchScoreboard,
  type AgentCase,
  type AgentMemory,
  type ScoreboardRow
} from '../api'

const kindZh: Record<string, string> = { fact: '事实', lesson: '教训', insight: '洞察' }

type BrainTab = 'learn' | 'scoreboard'

// 战绩「最近时间」：ISO 串 → 本地「M.D HH:mm」，坏值原样返回（不炸表）。
function fmtLastAt(iso: string | null): string {
  if (!iso) return '—'
  const dt = new Date(iso)
  if (Number.isNaN(dt.getTime())) return iso
  const md = `${dt.getMonth() + 1}.${dt.getDate()}`
  const hm = dt.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' })
  return `${md} ${hm}`
}

// 进化看板：展示超级体为机主(owner)学到的长期记忆与技能/案例库，让“进化”看得见；
// 「战绩」tab 露出舰队按任务类累计的模型胜负（F6 记分牌），让“路由越用越准”也看得见。
export default function AgentBrainPane(): React.ReactNode {
  const { t } = useTranslation()
  const [tab, setTab] = useState<BrainTab>('learn')
  const [mems, setMems] = useState<AgentMemory[]>([])
  const [cases, setCases] = useState<AgentCase[]>([])
  const [board, setBoard] = useState<ScoreboardRow[]>([])
  const [busy, setBusy] = useState(false)

  const load = async (): Promise<void> => {
    setBusy(true)
    try {
      const [m, c, s] = await Promise.all([
        fetchAgentMemory('owner'),
        fetchAgentCases('owner'),
        fetchScoreboard().catch(() => [] as ScoreboardRow[]) // 记分牌离线/空 → 空表，不牵连记忆/案例
      ])
      setMems(m)
      setCases(c)
      setBoard(s)
    } catch {
      /* 引擎离线时忽略 */
    } finally {
      setBusy(false)
    }
  }

  useEffect(() => {
    void load()
  }, [])

  const onClear = async (): Promise<void> => {
    await clearAgentMemory('owner').catch(() => {})
    void load()
  }

  const tabBtn = (key: BrainTab, label: string): React.ReactNode => (
    <button
      onClick={() => setTab(key)}
      className={`px-2 py-1 text-xs rounded border ${
        tab === key
          ? 'border-blue-500 bg-blue-500/10 text-blue-300'
          : 'border-neutral-700 text-neutral-400 hover:bg-neutral-800'
      }`}
    >
      {label}
    </button>
  )

  return (
    <div className="flex flex-col h-full">
      <div className="px-3 py-2 border-b border-neutral-800 flex items-center gap-2">
        <span className="text-sm font-medium">{t('brain.title')}</span>
        <div className="flex items-center gap-1 ml-2">
          {tabBtn('learn', t('brain.tabLearn'))}
          {tabBtn('scoreboard', t('brain.tabScoreboard'))}
        </div>
        <button
          onClick={() => void load()}
          disabled={busy}
          className="ml-auto px-2 py-1 text-xs rounded border border-neutral-700 hover:bg-neutral-800 disabled:opacity-40"
        >
          {busy ? t('brain.loading') : t('brain.refresh')}
        </button>
        {tab === 'learn' && (
          <button
            onClick={() => void onClear()}
            className="px-2 py-1 text-xs rounded border border-neutral-700 hover:bg-neutral-800"
          >
            {t('brain.clear')}
          </button>
        )}
      </div>

      {tab === 'learn' ? (
        <div className="flex-1 overflow-auto p-3 space-y-4 text-sm">
          <section>
            <div className="text-xs uppercase tracking-wide text-neutral-500 mb-1">
              {t('brain.memories')}（{mems.length}）
            </div>
            {mems.length === 0 && (
              <div className="text-neutral-600 text-xs">{t('brain.empty')}</div>
            )}
            <ul className="space-y-1">
              {mems.map((m) => (
                <li key={m.id} className="flex gap-2 items-start">
                  <span className="text-[10px] px-1 rounded bg-neutral-800 text-neutral-400 shrink-0 mt-0.5">
                    {kindZh[m.kind] ?? m.kind}
                  </span>
                  <span className="text-neutral-200">{m.text}</span>
                </li>
              ))}
            </ul>
          </section>
          <section>
            <div className="text-xs uppercase tracking-wide text-neutral-500 mb-1">
              {t('brain.cases')}（{cases.length}）
            </div>
            {cases.length === 0 && (
              <div className="text-neutral-600 text-xs">{t('brain.emptyCases')}</div>
            )}
            <ul className="space-y-2">
              {cases.map((c) => (
                <li key={c.id} className="border border-neutral-800 rounded p-2">
                  <div className="text-neutral-300">{c.problem}</div>
                  <div className="text-xs text-neutral-500 mt-1">
                    {t('brain.byModel')}：{c.model || '?'}
                  </div>
                </li>
              ))}
            </ul>
          </section>
        </div>
      ) : (
        <div className="flex-1 overflow-auto p-3 text-sm">
          <div className="text-xs text-neutral-500 mb-2">{t('brain.scoreboardHint')}</div>
          {board.length === 0 ? (
            <div className="text-neutral-600 text-xs py-2">{t('brain.emptyScoreboard')}</div>
          ) : (
            <table className="w-full text-xs">
              <thead className="text-neutral-500 border-b border-neutral-800">
                <tr>
                  <th className="text-left py-1">{t('brain.sbModel')}</th>
                  <th className="text-left">{t('brain.sbKind')}</th>
                  <th className="text-right">{t('brain.sbWins')}</th>
                  <th className="text-right">{t('brain.sbLosses')}</th>
                  <th className="text-right">{t('brain.sbRate')}</th>
                  <th className="text-right pr-1">{t('brain.sbLast')}</th>
                </tr>
              </thead>
              <tbody>
                {board.map((r) => (
                  <tr key={`${r.model}\u0000${r.task_kind}`} className="border-b border-neutral-900">
                    <td className="py-1 font-mono text-neutral-200">{r.model}</td>
                    <td className="text-neutral-400">{r.task_kind}</td>
                    <td className="text-right font-mono text-green-500">{r.wins}</td>
                    <td className="text-right font-mono text-neutral-400">{r.losses}</td>
                    <td className="text-right font-mono">
                      {r.win_rate == null ? '—' : `${Math.round(r.win_rate * 100)}%`}
                    </td>
                    <td className="text-right pr-1 text-neutral-500">{fmtLastAt(r.last_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  )
}
