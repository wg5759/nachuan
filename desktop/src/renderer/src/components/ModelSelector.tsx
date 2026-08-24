import React, { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import Dropdown from './Dropdown'
import { useAppStore, type EngineStatus, type ModelInfo } from '../store'
import { canUseEngineRuntime } from '../engine-status'

// 舰队虚拟号（Fugu「一个模型号背后的模型舰队」）：引擎 /v1/models 里 owned_by==='fleet'。
const FLEET_IDS = new Set(['nachuan', 'nachuan-ultra'])
export function isFleetModelId(id?: string | null): boolean {
  return Boolean(id && FLEET_IDS.has(id))
}

// 选单显示名：舰队号挂招牌（纳川·智脑 ⚡ / …Ultra 🧠），其它模型沿用「id (tier)」原样。
export function specificModelDisplayName(m: ModelInfo): string {
  const separator = m.id.indexOf('::')
  if (separator < 1) return m.id
  const leaf = m.id.slice(separator + 2)
  return `${m.owned_by || m.id.slice(0, separator)} · ${leaf}`
}

function modelLabel(
  m: ModelInfo,
  t: (key: string, opts?: Record<string, unknown>) => string
): string {
  if (m.owned_by === 'fleet' || isFleetModelId(m.id)) {
    return t(m.id === 'nachuan-ultra' ? 'chat.fleetUltra' : 'chat.fleet')
  }
  const review = m.review_vote_candidate
    ? ` · ${t('chat.reviewVoteCandidate')}`
    : ` · ${t('chat.noReviewVote')}`
  return `${t('chat.advancedModel')} · ${specificModelDisplayName(m)}${m.tier ? ` (${m.tier})` : ''}${review}`
}

export function visibleModelChoices(
  models: ModelInfo[],
  currentModel: string | null,
  showAdvanced: boolean
): ModelInfo[] {
  const automatic = models.filter((model) => model.owned_by === 'fleet' || isFleetModelId(model.id))
  const specific = models.filter(
    (model) => model.owned_by !== 'fleet' && !isFleetModelId(model.id)
  )
  if (automatic.length === 0) return specific
  if (showAdvanced) return [...automatic, ...specific]
  const currentSpecific = specific.find((model) => model.id === currentModel)
  return currentSpecific ? [...automatic, currentSpecific] : automatic
}

export function isSpecificModelSelection(
  models: ModelInfo[],
  currentModel: string | null
): boolean {
  return Boolean(
    currentModel &&
      models.some(
        (model) =>
          model.id === currentModel && model.owned_by !== 'fleet' && !isFleetModelId(model.id)
      )
  )
}

export function canSelectModels(status: EngineStatus, models: ModelInfo[]): boolean {
  return canUseEngineRuntime(status) && models.length > 0
}

// 顶栏「大脑」选择器（原在聊天区左上，按机主布局移进顶栏 ③）。就这一个选择，力求最简：
//   选「纳川·智脑/Ultra」= 所有模型智能路由配合干活；选某个具体模型 = 单独用它。
export default function ModelSelector({ className }: { className?: string }): React.ReactNode {
  const { t } = useTranslation()
  const models = useAppStore((s) => s.models)
  const status = useAppStore((s) => s.status)
  const currentModel = useAppStore((s) => s.currentModel)
  const setCurrentModel = useAppStore((s) => s.setCurrentModel)
  const hasAutomatic = models.some((model) => model.owned_by === 'fleet' || isFleetModelId(model.id))
  const hasSpecific = models.some(
    (model) => model.owned_by !== 'fleet' && !isFleetModelId(model.id)
  )
  const currentIsSpecific = isSpecificModelSelection(models, currentModel)
  const selectionEnabled = canSelectModels(status, models)
  const [showAdvanced, setShowAdvanced] = useState(currentIsSpecific)
  useEffect(() => {
    if (currentIsSpecific) setShowAdvanced(true)
  }, [currentIsSpecific])
  // 舰队号（纳川·智脑/Ultra）是默认大脑 → 置顶；复制再排(不改 store 原数组)、稳定排序。
  // useMemo：仅 models/语言变化时重排，避免每次渲染都跑 sort（MiniMax 审）。
  const options = useMemo(
    () =>
      models.length === 0
        ? [{ value: '', label: t('chat.noModel') }]
        : visibleModelChoices(models, currentModel, showAdvanced)
            .sort((a, b) => Number(isFleetModelId(b.id)) - Number(isFleetModelId(a.id)))
            .map((m) => ({ value: m.id, label: modelLabel(m, t) })),
    [currentModel, models, showAdvanced, t]
  )
  return (
    <div className={`flex items-center gap-1 ${className ?? ''}`}>
      <Dropdown
        value={currentModel ?? ''}
        onChange={(v) => setCurrentModel(v || null)}
        disabled={!selectionEnabled}
        title={t('chat.brain')}
        options={options}
      />
      {hasAutomatic && hasSpecific && (
        <button
          type="button"
          disabled={!selectionEnabled}
          onClick={() => setShowAdvanced((value) => !value)}
          className="px-2 py-1 text-xs rounded border border-neutral-700 text-neutral-400 hover:bg-neutral-800 disabled:cursor-not-allowed disabled:opacity-50"
          title={t('chat.advancedModelHint')}
        >
          {showAdvanced ? t('chat.hideAdvanced') : t('chat.chooseSpecificModel')}
        </button>
      )}
    </div>
  )
}
