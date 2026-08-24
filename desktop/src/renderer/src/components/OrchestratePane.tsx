import React, { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  fetchOrchestrationCapabilities,
  runDebate,
  runDecompose,
  runPanel,
  runPipeline,
  type DebateResult,
  type DecomposeResult,
  type OrchestrationCapabilities,
  type PanelResult,
  type PipelineResult,
  type PipelineStep,
  type WorkflowOutcome,
  type WorkflowRoute
} from '../api'
import { useAppStore } from '../store'
import {
  manualCollaborationModels,
  orchestrationCapabilityReasonKey,
  orchestrationCapabilityRows,
  synthesisSummaryKey
} from './orchestrate-contract'

type Mode = 'panel' | 'debate' | 'decompose' | 'pipeline'

function routeLabel(route: WorkflowRoute): string {
  const requested = route.requested_model || '?'
  const actual = route.actual_model || '?'
  const model = requested === actual ? actual : `${requested} → ${actual}`
  return route.provider ? `${model} / ${route.provider}` : model
}

function OutcomeNotice({ outcome }: { outcome: WorkflowOutcome }): React.ReactNode {
  const { t } = useTranslation()
  const tone =
    outcome === 'failed'
      ? 'border-red-900 bg-red-950/30 text-red-300'
      : outcome === 'partial'
        ? 'border-amber-900 bg-amber-950/30 text-amber-300'
        : outcome === 'completed'
          ? 'border-green-900 bg-green-950/30 text-green-300'
          : 'border-blue-900 bg-blue-950/30 text-blue-300'
  return <div className={`border rounded-lg px-3 py-2 text-sm ${tone}`}>{t(`orch.outcome.${outcome}`)}</div>
}

function WorkflowDiagnostics({
  degradedReasons,
  error,
  stoppedReason
}: {
  degradedReasons?: string[]
  error?: string | null
  stoppedReason?: string | null
}): React.ReactNode {
  const { t } = useTranslation()
  if (!error && !stoppedReason && !degradedReasons?.length) return null
  return (
    <div className="border border-amber-900 rounded-lg px-3 py-2 bg-amber-950/30 text-amber-300 text-sm space-y-1">
      {error && <div>{error}</div>}
      {stoppedReason && <div>{t('orch.stoppedReason')}: {stoppedReason}</div>}
      {!!degradedReasons?.length && (
        <div>{t('orch.degradedReasons')}: {degradedReasons.join(', ')}</div>
      )}
    </div>
  )
}

function isAbortError(error: unknown): boolean {
  return error instanceof DOMException && error.name === 'AbortError'
}

function StopWaitingControl({ onStop }: { onStop: () => void }): React.ReactNode {
  const { t } = useTranslation()
  return (
    <div className="flex items-center gap-2">
      <button
        type="button"
        onClick={onStop}
        className="px-4 py-1.5 rounded border border-amber-800 text-amber-300 hover:bg-amber-950/40"
      >
        {t('orch.cancel')}
      </button>
      <span className="text-xs text-amber-400">{t('orch.stopWaitingHint')}</span>
    </div>
  )
}

type CapabilityLoadState = 'loading' | 'ready' | 'error'

const UNVERIFIED_CAPABILITIES: OrchestrationCapabilities = {
  chat_model_count: 0,
  review_candidate_count: 0,
  independent_identity_count: 0,
  single_review_ready: false,
  post_summary_final_review_ready: false,
  four_vendor_review_ready: false,
  reason: 'routes_snapshot_unavailable'
}

export function OrchestrationCapabilityStatus({
  capabilities,
  state
}: {
  capabilities: OrchestrationCapabilities | null
  state: CapabilityLoadState
}): React.ReactNode {
  const { t } = useTranslation()

  if (state === 'loading') {
    return (
      <section
        aria-label={t('orch.capabilities.title')}
        aria-live="polite"
        className="border-b border-neutral-800 bg-neutral-950/70 px-3 py-2 text-xs"
      >
        <span className="font-medium text-neutral-300">{t('orch.capabilities.title')}</span>
        <span className="ml-2 text-neutral-500">{t('orch.capabilities.loading')}</span>
      </section>
    )
  }

  const hasVerifiedSnapshot = state === 'ready' && capabilities !== null
  const visibleCapabilities = hasVerifiedSnapshot ? capabilities : UNVERIFIED_CAPABILITIES
  const rows = orchestrationCapabilityRows(visibleCapabilities)
  return (
    <section
      aria-label={t('orch.capabilities.title')}
      aria-live="polite"
      className="border-b border-neutral-800 bg-neutral-950/70 px-3 py-2 text-xs space-y-1.5"
    >
      <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1">
        <span className="font-medium text-neutral-300">{t('orch.capabilities.title')}</span>
        {hasVerifiedSnapshot ? (
          <span className="text-neutral-500">
            {t('orch.capabilities.counts', {
              chat: visibleCapabilities.chat_model_count,
              candidates: visibleCapabilities.review_candidate_count,
              identities: visibleCapabilities.independent_identity_count
            })}
          </span>
        ) : (
          <span className="text-amber-400">{t('orch.capabilities.unverifiable')}</span>
        )}
      </div>
      <div className="grid grid-cols-1 gap-1 sm:grid-cols-2 xl:grid-cols-4">
        {rows.map((row) => (
          <div
            key={row.id}
            data-capability={row.id}
            data-capability-ready={String(row.ready)}
            className={`flex items-center justify-between gap-2 rounded border px-2 py-1 ${
              row.ready
                ? 'border-green-900/80 bg-green-950/20 text-green-300'
                : 'border-neutral-800 bg-neutral-900/40 text-neutral-400'
            }`}
          >
            <span>{t(row.labelKey)}</span>
            <span className="shrink-0">
              {t(
                row.ready
                  ? row.availableWhenReady
                    ? 'orch.capabilities.available'
                    : 'orch.capabilities.ready'
                  : 'orch.capabilities.notReady'
              )}
            </span>
          </div>
        ))}
      </div>
      {hasVerifiedSnapshot && visibleCapabilities.reason && (
        <div className="text-amber-400">
          {t('orch.capabilities.reasonPrefix')}:{' '}
          {t(orchestrationCapabilityReasonKey(visibleCapabilities.reason), {
            reason: visibleCapabilities.reason
          })}
        </div>
      )}
      {hasVerifiedSnapshot && (
        <div className="text-neutral-600">{t('orch.capabilities.prospectiveOnly')}</div>
      )}
    </section>
  )
}

export default function OrchestratePane(): React.ReactNode {
  const { t } = useTranslation()
  const [mode, setMode] = useState<Mode>('panel')
  const [capabilityState, setCapabilityState] = useState<CapabilityLoadState>('loading')
  const [capabilities, setCapabilities] = useState<OrchestrationCapabilities | null>(null)

  useEffect(() => {
    let mounted = true
    void fetchOrchestrationCapabilities().then(
      (value) => {
        if (!mounted) return
        setCapabilities(value)
        setCapabilityState('ready')
      },
      () => {
        if (!mounted) return
        setCapabilities(null)
        setCapabilityState('error')
      }
    )
    return () => {
      mounted = false
    }
  }, [])

  const Tab = ({ k, label }: { k: Mode; label: string }): React.ReactNode => (
    <button
      onClick={() => setMode(k)}
      className={`px-3 py-1 rounded text-sm ${
        mode === k ? 'bg-neutral-800 text-neutral-100' : 'text-neutral-400 hover:bg-neutral-900'
      }`}
    >
      {label}
    </button>
  )

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <div className="flex gap-1 p-2 border-b border-neutral-800">
        <Tab k="panel" label={t('orch.tabPanel')} />
        <Tab k="debate" label={t('orch.tabDebate')} />
        <Tab k="decompose" label={t('orch.tabDecompose')} />
        <Tab k="pipeline" label={t('orch.tabPipeline')} />
      </div>
      <OrchestrationCapabilityStatus capabilities={capabilities} state={capabilityState} />
      <div className="flex-1 overflow-auto">
        {mode === 'panel' ? (
          <PanelMode />
        ) : mode === 'debate' ? (
          <DebateMode />
        ) : mode === 'decompose' ? (
          <DecomposeMode />
        ) : (
          <PipelineMode />
        )}
      </div>
    </div>
  )
}

function PanelMode(): React.ReactNode {
  const { t } = useTranslation()
  const models = manualCollaborationModels(useAppStore((s) => s.models))
  const [prompt, setPrompt] = useState('')
  const [panelists, setPanelists] = useState<Set<string>>(new Set())
  const [judge, setJudge] = useState('')
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<PanelResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const abortRef = useRef<AbortController | null>(null)

  const toggle = (id: string): void => {
    if (!panelists.has(id) && judge === id) setJudge('')
    setPanelists((prev) => {
      const n = new Set(prev)
      if (n.has(id)) n.delete(id)
      else n.add(id)
      return n
    })
  }

  const run = async (): Promise<void> => {
    if (!prompt.trim() || panelists.size === 0 || !judge || busy) return
    setBusy(true)
    setError(null)
    setResult(null)
    const controller = new AbortController()
    abortRef.current = controller
    try {
      setResult(await runPanel(prompt.trim(), [...panelists], judge, controller.signal))
    } catch (e) {
      setError(isAbortError(e) ? t('orch.cancelled') : String(e))
    } finally {
      if (abortRef.current === controller) abortRef.current = null
      setBusy(false)
    }
  }

  return (
    <div className="p-4 space-y-4">
      <p className="text-xs text-neutral-500">{t('orch.hint')}</p>
      <div>
        <div className="text-sm text-neutral-400 mb-1">{t('orch.panelists')}</div>
        <div className="grid grid-cols-2 gap-1">
          {models.map((m) => (
            <label key={m.id} className="flex items-center gap-2 text-sm">
              <input type="checkbox" checked={panelists.has(m.id)} onChange={() => toggle(m.id)} />
              <span className="font-mono text-xs">{m.id}</span>
            </label>
          ))}
        </div>
      </div>
      <div>
        <div className="text-sm text-neutral-400 mb-1">{t('orch.judge')}</div>
        <select
          value={judge}
          onChange={(e) => setJudge(e.target.value)}
          className="bg-neutral-900 border border-neutral-700 rounded px-2 py-1 text-sm"
        >
          <option value="">{t('orch.pickJudge')}</option>
          {models.map((m) => (
            <option key={m.id} value={m.id} disabled={panelists.has(m.id)}>
              {m.id}
            </option>
          ))}
        </select>
      </div>
      <textarea
        value={prompt}
        onChange={(e) => setPrompt(e.target.value)}
        rows={3}
        placeholder={t('orch.promptPh')}
        className="w-full resize-none bg-neutral-900 border border-neutral-700 rounded px-2 py-1 text-sm text-neutral-100"
      />
      <div className="flex gap-2">
        <button
          onClick={() => void run()}
          disabled={busy || !prompt.trim() || panelists.size === 0 || !judge}
          className="px-4 py-1.5 rounded bg-blue-600 hover:bg-blue-500 disabled:opacity-40"
        >
          {busy ? t('orch.running') : t('orch.run')}
        </button>
        {busy && <StopWaitingControl onStop={() => abortRef.current?.abort()} />}
      </div>
      {error && <div className="text-red-400 text-sm">{error}</div>}
      {result && (
        <div className="space-y-3">
          <OutcomeNotice outcome={result.outcome} />
          <WorkflowDiagnostics
            degradedReasons={result.degraded_reasons}
            error={result.error || result.judge_error}
            stoppedReason={result.stopped_reason}
          />
          {result.panelists.map((p, i) => (
            <div key={i} className="border border-neutral-800 rounded-lg p-3 bg-neutral-900/40">
              <div className="text-xs font-mono text-neutral-400 mb-1">
                {routeLabel(p)} · {p.status}
              </div>
              {p.answer ? (
                <div className="text-sm whitespace-pre-wrap">{p.answer}</div>
              ) : (
                <div className="text-sm text-red-400">{p.error}</div>
              )}
            </div>
          ))}
          {result.summary && (
            <div
              className={`border rounded-lg p-3 ${
                result.judge_vote_weight > 0
                  ? 'border-blue-900 bg-blue-950/30'
                  : 'border-amber-900 bg-amber-950/30'
              }`}
            >
              <div
                className={`text-xs font-mono mb-1 ${
                  result.judge_vote_weight > 0 ? 'text-blue-300' : 'text-amber-300'
                }`}
              >
                Σ {t(synthesisSummaryKey(result))}（
                {result.judge_route ? routeLabel(result.judge_route) : result.judge}）
              </div>
              <div className="text-sm whitespace-pre-wrap">{result.summary}</div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function ModelSelect({
  value,
  onChange,
  models
}: {
  value: string
  onChange: (v: string) => void
  models: { id: string }[]
}): React.ReactNode {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="mt-1 w-full bg-neutral-900 border border-neutral-700 rounded px-2 py-1 text-sm"
    >
      <option value="">…</option>
      {models.map((m) => (
        <option key={m.id} value={m.id}>
          {m.id}
        </option>
      ))}
    </select>
  )
}

function DebateMode(): React.ReactNode {
  const { t } = useTranslation()
  const models = manualCollaborationModels(useAppStore((s) => s.models))
  const [prompt, setPrompt] = useState('')
  const [debaters, setDebaters] = useState<Set<string>>(new Set())
  const [judge, setJudge] = useState('')
  const [rounds, setRounds] = useState(2)
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<DebateResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const abortRef = useRef<AbortController | null>(null)
  const toggle = (id: string): void => {
    if (!debaters.has(id) && judge === id) setJudge('')
    setDebaters((p) => {
      const n = new Set(p)
      if (n.has(id)) n.delete(id)
      else n.add(id)
      return n
    })
  }
  const run = async (): Promise<void> => {
    if (!prompt.trim() || debaters.size < 2 || !judge || busy) return
    setBusy(true)
    setError(null)
    setResult(null)
    const controller = new AbortController()
    abortRef.current = controller
    try {
      setResult(await runDebate(prompt.trim(), [...debaters], judge, rounds, controller.signal))
    } catch (e) {
      setError(isAbortError(e) ? t('orch.cancelled') : String(e))
    } finally {
      if (abortRef.current === controller) abortRef.current = null
      setBusy(false)
    }
  }
  return (
    <div className="p-4 space-y-3">
      <p className="text-xs text-neutral-500">{t('orch.debateHint')}</p>
      <div>
        <div className="text-sm text-neutral-400 mb-1">{t('orch.debaters')}</div>
        <div className="grid grid-cols-2 gap-1">
          {models.map((m) => (
            <label key={m.id} className="flex items-center gap-2 text-sm">
              <input type="checkbox" checked={debaters.has(m.id)} onChange={() => toggle(m.id)} />
              <span className="font-mono text-xs">{m.id}</span>
            </label>
          ))}
        </div>
      </div>
      <div className="flex gap-3">
        <label className="text-sm flex-1">
          <span className="text-neutral-400">{t('orch.judge')}</span>
          <ModelSelect value={judge} onChange={setJudge} models={models.filter((m) => !debaters.has(m.id))} />
        </label>
        <label className="text-sm w-24">
          <span className="text-neutral-400">{t('orch.rounds')}</span>
          <input
            type="number"
            min={1}
            max={4}
            value={rounds}
            onChange={(e) => setRounds(Number(e.target.value))}
            className="mt-1 w-full bg-neutral-900 border border-neutral-700 rounded px-2 py-1 text-sm"
          />
        </label>
      </div>
      <textarea
        value={prompt}
        onChange={(e) => setPrompt(e.target.value)}
        rows={3}
        placeholder={t('orch.promptPh')}
        className="w-full resize-none bg-neutral-900 border border-neutral-700 rounded px-2 py-1 text-sm"
      />
      <div className="flex gap-2">
        <button
          onClick={() => void run()}
          disabled={busy || !prompt.trim() || debaters.size < 2 || !judge}
          className="px-4 py-1.5 rounded bg-blue-600 hover:bg-blue-500 disabled:opacity-40"
        >
          {busy ? t('orch.running') : t('orch.run')}
        </button>
        {busy && <StopWaitingControl onStop={() => abortRef.current?.abort()} />}
      </div>
      {error && <div className="text-red-400 text-sm">{error}</div>}
      {result && (
        <div className="space-y-3">
          <OutcomeNotice outcome={result.outcome} />
          <WorkflowDiagnostics
            degradedReasons={result.degraded_reasons}
            error={result.judge_error}
            stoppedReason={result.stopped_reason}
          />
          <div className="text-xs text-neutral-500">
            {t('orch.roundsAttempted')}: {result.rounds_attempted} · {t('orch.roundsWithQuorum')}:{' '}
            {result.rounds_with_quorum}
          </div>
          {result.round_details.map((round, ri) => (
            <div key={ri} className="border border-neutral-800 rounded-lg p-3 bg-neutral-900/40">
              <div className="text-xs text-neutral-500 mb-1">第 {ri + 1} 轮</div>
              {round.map((call, ci) => (
                <div key={`${call.requested_model}-${ci}`} className="mb-2">
                  <div className="text-xs font-mono text-neutral-400">
                    {routeLabel(call)} · {call.status}
                  </div>
                  <div className={`text-sm whitespace-pre-wrap ${call.error ? 'text-red-400' : ''}`}>
                    {call.answer || call.error}
                  </div>
                </div>
              ))}
            </div>
          ))}
          {result.summary && (
            <div
              className={`border rounded-lg p-3 ${
                result.judge_vote_weight > 0
                  ? 'border-blue-900 bg-blue-950/30'
                  : 'border-amber-900 bg-amber-950/30'
              }`}
            >
              <div
                className={`text-xs font-mono mb-1 ${
                  result.judge_vote_weight > 0 ? 'text-blue-300' : 'text-amber-300'
                }`}
              >
                Σ {t(synthesisSummaryKey(result))}（
                {result.judge_route ? routeLabel(result.judge_route) : result.judge}）
              </div>
              <div className="text-sm whitespace-pre-wrap">{result.summary}</div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function DecomposeMode(): React.ReactNode {
  const { t } = useTranslation()
  const models = manualCollaborationModels(useAppStore((s) => s.models))
  const [task, setTask] = useState('')
  const [planner, setPlanner] = useState('')
  const [aggregator, setAggregator] = useState('')
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<DecomposeResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const abortRef = useRef<AbortController | null>(null)
  const run = async (): Promise<void> => {
    if (!task.trim() || !planner || !aggregator || busy) return
    setBusy(true)
    setError(null)
    setResult(null)
    const controller = new AbortController()
    abortRef.current = controller
    try {
      setResult(await runDecompose(task.trim(), planner, aggregator, controller.signal))
    } catch (e) {
      setError(isAbortError(e) ? t('orch.cancelled') : String(e))
    } finally {
      if (abortRef.current === controller) abortRef.current = null
      setBusy(false)
    }
  }
  return (
    <div className="p-4 space-y-3">
      <p className="text-xs text-neutral-500">{t('orch.decomposeHint')}</p>
      <textarea
        value={task}
        onChange={(e) => setTask(e.target.value)}
        rows={3}
        placeholder={t('orch.taskPh')}
        className="w-full resize-none bg-neutral-900 border border-neutral-700 rounded px-2 py-1 text-sm"
      />
      <div className="flex gap-3">
        <label className="text-sm flex-1">
          <span className="text-neutral-400">{t('orch.planner')}</span>
          <ModelSelect value={planner} onChange={setPlanner} models={models} />
        </label>
        <label className="text-sm flex-1">
          <span className="text-neutral-400">{t('orch.aggregator')}</span>
          <ModelSelect value={aggregator} onChange={setAggregator} models={models} />
        </label>
      </div>
      <div className="flex gap-2">
        <button
          onClick={() => void run()}
          disabled={busy || !task.trim() || !planner || !aggregator}
          className="px-4 py-1.5 rounded bg-blue-600 hover:bg-blue-500 disabled:opacity-40"
        >
          {busy ? t('orch.running') : t('orch.run')}
        </button>
        {busy && <StopWaitingControl onStop={() => abortRef.current?.abort()} />}
      </div>
      {error && <div className="text-red-400 text-sm">{error}</div>}
      {result && (
        <div className="space-y-3">
          <OutcomeNotice outcome={result.outcome} />
          <WorkflowDiagnostics error={result.error} stoppedReason={result.stopped_reason} />
          {result.plan && (
            <div className="border border-neutral-800 rounded-lg p-3 bg-neutral-900/40">
              <div className="text-xs text-neutral-400 mb-1">📋 {t('orch.plan')}</div>
              <div className="text-sm whitespace-pre-wrap">{result.plan}</div>
            </div>
          )}
          {result.subtasks.map((s, i) => (
            <div key={i} className="border border-neutral-800 rounded-lg p-3 bg-neutral-900/40">
              <div className="text-xs font-mono text-neutral-400 mb-1">
                {s.subtask} <span className="text-neutral-600">→ {routeLabel(s)} · {s.status}</span>
              </div>
              <div className={`text-sm whitespace-pre-wrap ${s.error ? 'text-red-400' : ''}`}>
                {s.answer || s.error}
              </div>
            </div>
          ))}
          {result.final && (
            <div className="border border-blue-900 rounded-lg p-3 bg-blue-950/30">
              <div className="text-xs font-mono text-blue-300 mb-1">
                {result.outcome === 'partial' ? '△' : 'Σ'} {t('orch.final')}
              </div>
              <div className="text-sm whitespace-pre-wrap">{result.final}</div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function PipelineMode(): React.ReactNode {
  const { t } = useTranslation()
  const models = manualCollaborationModels(useAppStore((s) => s.models))
  const [prompt, setPrompt] = useState('')
  const [steps, setSteps] = useState<PipelineStep[]>([{ model: '', instruction: '' }])
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<PipelineResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const abortRef = useRef<AbortController | null>(null)
  const setStep = (i: number, patch: Partial<PipelineStep>): void =>
    setSteps((p) => p.map((s, j) => (j === i ? { ...s, ...patch } : s)))
  const run = async (): Promise<void> => {
    const valid = steps.filter((s) => s.model)
    if (!prompt.trim() || valid.length === 0 || busy) return
    setBusy(true)
    setError(null)
    setResult(null)
    const controller = new AbortController()
    abortRef.current = controller
    try {
      setResult(await runPipeline(prompt.trim(), valid, controller.signal))
    } catch (e) {
      setError(isAbortError(e) ? t('orch.cancelled') : String(e))
    } finally {
      if (abortRef.current === controller) abortRef.current = null
      setBusy(false)
    }
  }
  return (
    <div className="p-4 space-y-3">
      <p className="text-xs text-neutral-500">{t('orch.pipelineHint')}</p>
      <textarea
        value={prompt}
        onChange={(e) => setPrompt(e.target.value)}
        rows={2}
        placeholder={t('orch.promptPh')}
        className="w-full resize-none bg-neutral-900 border border-neutral-700 rounded px-2 py-1 text-sm"
      />
      <div className="space-y-2">
        {steps.map((s, i) => (
          <div key={i} className="flex gap-2 items-center">
            <span className="text-xs text-neutral-500 w-5">{i + 1}.</span>
            <select
              value={s.model}
              onChange={(e) => setStep(i, { model: e.target.value })}
              className="bg-neutral-900 border border-neutral-700 rounded px-2 py-1 text-sm"
            >
              <option value="">{t('orch.step')}</option>
              {models.map((m) => (
                <option key={m.id} value={m.id}>
                  {m.id}
                </option>
              ))}
            </select>
            <input
              value={s.instruction}
              onChange={(e) => setStep(i, { instruction: e.target.value })}
              placeholder={t('orch.instruction')}
              className="flex-1 bg-neutral-900 border border-neutral-700 rounded px-2 py-1 text-sm"
            />
            {steps.length > 1 && (
              <button onClick={() => setSteps((p) => p.filter((_, j) => j !== i))} className="text-red-400 text-xs px-1">
                ✕
              </button>
            )}
          </div>
        ))}
        <button onClick={() => setSteps((p) => [...p, { model: '', instruction: '' }])} className="text-xs text-blue-400">
          + {t('orch.addStep')}
        </button>
      </div>
      <div className="flex gap-2">
        <button
          onClick={() => void run()}
          disabled={busy || !prompt.trim() || !steps.some((s) => s.model)}
          className="px-4 py-1.5 rounded bg-blue-600 hover:bg-blue-500 disabled:opacity-40"
        >
          {busy ? t('orch.running') : t('orch.run')}
        </button>
        {busy && <StopWaitingControl onStop={() => abortRef.current?.abort()} />}
      </div>
      {error && <div className="text-red-400 text-sm">{error}</div>}
      {result && (
        <div className="space-y-3">
          <OutcomeNotice outcome={result.outcome} />
          <WorkflowDiagnostics stoppedReason={result.stopped_reason} />
          {result.trace.map((tr, i) => (
            <div key={i} className="border border-neutral-800 rounded-lg p-3 bg-neutral-900/40">
              <div className="text-xs font-mono text-neutral-400 mb-1">
                {tr.step}. {routeLabel(tr)} · {tr.status}
                {tr.instruction && <span className="text-neutral-600"> · {tr.instruction}</span>}
              </div>
              <div className={`text-sm whitespace-pre-wrap ${tr.error ? 'text-red-400' : ''}`}>
                {tr.output || tr.error}
              </div>
            </div>
          ))}
          {result.final && (
            <div className="border border-blue-900 rounded-lg p-3 bg-blue-950/30">
              <div className="text-xs font-mono text-blue-300 mb-1">Σ {t('orch.final')}</div>
              <div className="text-sm whitespace-pre-wrap">{result.final}</div>
            </div>
          )}
          {!result.final && result.partial_output && (
            <div className="border border-amber-900 rounded-lg p-3 bg-amber-950/30">
              <div className="text-xs font-mono text-amber-300 mb-1">△ {t('orch.partialOutput')}</div>
              <div className="text-sm whitespace-pre-wrap">{result.partial_output}</div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
