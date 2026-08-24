import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  type Approval,
  addMcp,
  agentExec,
  agentRun,
  clearAgentMemory,
  clearConvSummary,
  createAgentJob,
  deleteKbDoc,
  listApprovals,
  removeMcp,
  resolveApproval,
  resumeAgentJob,
  runArchEditor,
  runCodingTeam,
  selectLocalModel,
  startDailyVideo,
  studioExecute
} from '../api'
import { useAppStore } from '../store'
import { canUseEngineRuntime } from '../engine-status'
import { approvalExecutionTask, routeApprovalExecutionResult } from '../approval-result-routing'
import { publishKnowledgeDocumentsChanged } from '../knowledge-refresh'

// P5/P6 审核分级：
//   · 重大动作(action) → 全屏阻断弹窗，必须当场「同意/换方案/取消」（真·重大事项才拦）。
//   · 技能卡(skill_card) → 右下角非阻断小卡，攒着慢慢审，绝不打断你干活（呼应"别屁大点事都问我"）。
// 轮询 /v1/approvals；无待审则完全隐身。
export default function ApprovalCenter(): JSX.Element | null {
  const { t } = useTranslation()
  const status = useAppStore((s) => s.status)
  const setConvMessages = useAppStore((s) => s.setConvMessages)
  const [items, setItems] = useState<Approval[]>([])
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)
  const [toast, setToast] = useState('')

  // toast 8 秒自动消失（机主实测：右下浮层常驻不走，挤占视野）
  useEffect(() => {
    if (!toast) return
    const id = window.setTimeout(() => setToast(''), 8000)
    return () => window.clearTimeout(id)
  }, [toast])

  useEffect(() => {
    if (!canUseEngineRuntime(status)) return
    let stop = false
    let timer = 0
    const poll = async (): Promise<void> => {
      try {
        const p = await listApprovals('owner')
        if (!stop) setItems(p)
      } catch {
        /* 引擎短暂不可用，下次再轮询 */
      }
      if (!stop) timer = window.setTimeout(poll, 6000)
    }
    void poll()
    return () => {
      stop = true
      window.clearTimeout(timer)
    }
  }, [status])

  // decision: approve(同意/入库) / revise(换方案，仅动作) / reject(取消/驳回)
  const decide = async (target: Approval, decision: 'approve' | 'reject' | 'revise'): Promise<void> => {
    if (busy) return
    setBusy(true)
    const n = note
    try {
      await resolveApproval(target.id, decision, n)
      if (target.kind === 'action' && decision === 'approve') {
        // 高风险动作获批 → 带服务端一次性 approval_id 重发；布尔 approved 不能作为能力凭证。
        const task = approvalExecutionTask(target)
        const workdir = String((target.payload?.workdir as string) || '')
        const mode = String(target.payload?.mode || 'plan')
        const scope = String(target.payload?.scope || 'agent_exec')
        let resultText = ''
        if (scope === 'agent_run') {
          const rawAllow = target.payload?.allow
          const allow = Array.isArray(rawAllow) ? rawAllow.map(String) : undefined
          const rawMaxSteps = Number(target.payload?.max_steps)
          const res = await agentRun(task, String(target.payload?.model || '') || undefined, {
            approval_id: target.id,
            workdir: workdir || undefined,
            mode,
            allow,
            max_steps: Number.isFinite(rawMaxSteps) && rawMaxSteps > 0 ? rawMaxSteps : undefined,
            orchestrate: target.payload?.orchestrate !== false
          })
          resultText = res.reply || ''
        } else if (scope === 'agent_job') {
          const rawSteps = target.payload?.steps
          const res = await createAgentJob(task, {
            approval_id: target.id,
            workdir: workdir || undefined,
            mode,
            backend: String(target.payload?.backend || '') || undefined,
            steps: Array.isArray(rawSteps) ? (rawSteps as Record<string, unknown>[]) : undefined
          })
          resultText = res.job_id ? `任务已启动：${res.job_id}` : t('appr.done')
        } else if (scope === 'agent_job_resume') {
          const jobId = String(target.payload?.job_id || '')
          if (!jobId) throw new Error('审批记录缺少 job_id')
          const res = await resumeAgentJob(jobId, {
            approval_id: target.id,
            workdir: workdir || undefined,
            mode,
            backend: String(target.payload?.backend || '') || undefined
          })
          resultText = `任务已恢复：${res.job_id || res.id || jobId}`
        } else if (scope === 'orchestrate_coding') {
          const rawImpl = target.payload?.implementers
          if (!Array.isArray(rawImpl)) throw new Error('审批记录缺少 implementers')
          const res = await runCodingTeam(
            workdir,
            task,
            String(target.payload?.planner || ''),
            rawImpl as { name: string; agent: string; model?: string }[],
            String(target.payload?.reviewer || ''),
            { approval_id: target.id }
          )
          resultText = res.review || `编程团队已完成，共 ${res.implementations?.length ?? 0} 个实现。`
        } else if (scope === 'orchestrate_arch_editor') {
          const res = await runArchEditor(
            workdir,
            task,
            String(target.payload?.architect || ''),
            String(target.payload?.editor || ''),
            { approval_id: target.id }
          )
          resultText = String(res.diff || res.error || '架构编辑任务已完成')
        } else if (scope === 'mcp_add') {
          const res = await addMcp({
            name: String(target.payload?.name || ''),
            command: String(target.payload?.command || '') || undefined,
            args: Array.isArray(target.payload?.args) ? target.payload.args.map(String) : undefined,
            sha256: String(target.payload?.sha256 || '') || undefined,
            task,
            approval_id: target.id
          })
          resultText = res.ok ? 'MCP 已登记并启用' : 'MCP 操作完成'
        } else if (scope === 'mcp_remove') {
          const name = String(target.payload?.name || '')
          if (!name) throw new Error('审批记录缺少 MCP 名称')
          const res = await removeMcp(name, { task, approval_id: target.id })
          resultText = res.ok ? `MCP ${name} 已移除` : 'MCP 移除完成'
        } else if (scope === 'local_model_select') {
          const modelId = String(target.payload?.model_id || '')
          if (!modelId) throw new Error('审批记录缺少 model_id')
          const res = await selectLocalModel(modelId, { task, approval_id: target.id })
          resultText = `本地模型已切换：${String(res.model_id || modelId)}`
        } else if (scope === 'daily_video_start') {
          const res = await startDailyVideo(
            String(target.payload?.root || workdir),
            String(target.payload?.date || '') || undefined,
            undefined,
            { task, approval_id: target.id }
          )
          resultText = res.task
            ? `每日视频任务已启动：${res.task}\n日志：${res.duo_log || ''}`
            : String(res.message || '每日视频工作流已启动')
        } else if (scope === 'studio_execute') {
          const rawPlan = target.payload?.plan
          if (!rawPlan || typeof rawPlan !== 'object') throw new Error('审批记录缺少视频方案')
          const res = await studioExecute(rawPlan as Parameters<typeof studioExecute>[0], {
            task,
            approval_id: target.id
          })
          resultText = res.job_id ? `视频任务已启动：${res.job_id}` : '视频任务已启动'
        } else if (scope === 'memory_clear') {
          const rawTarget = target.payload?.target
          const targetSpec = rawTarget && typeof rawTarget === 'object' ? rawTarget as Record<string, unknown> : {}
          const targetUser = String(targetSpec.user_id || target.payload?.user_id || 'owner')
          const res = await clearAgentMemory(targetUser, target.id)
          resultText = res.ok ? `已清空 ${targetUser} 的长期记忆` : '记忆清理未完成'
        } else if (scope === 'knowledge_document_delete') {
          const rawTarget = target.payload?.target
          const targetSpec = rawTarget && typeof rawTarget === 'object' ? rawTarget as Record<string, unknown> : {}
          const docId = Number(targetSpec.doc_id)
          const targetUser = String(targetSpec.user_id || 'owner')
          if (!Number.isSafeInteger(docId) || docId <= 0) throw new Error('审批记录缺少 doc_id')
          const res = await deleteKbDoc(docId, targetUser, target.id)
          if (res.ok) publishKnowledgeDocumentsChanged()
          resultText = res.ok ? `知识库文档 #${docId} 已删除` : '知识库文档删除未完成'
        } else if (scope === 'conversation_summary_clear') {
          const rawTarget = target.payload?.target
          const targetSpec = rawTarget && typeof rawTarget === 'object' ? rawTarget as Record<string, unknown> : {}
          const conversationId = String(targetSpec.conversation_id || '')
          if (!conversationId) throw new Error('审批记录缺少 conversation_id')
          const res = await clearConvSummary(conversationId, 'owner', target.id)
          resultText = res.ok ? '对话摘要已清空' : '对话摘要清理未完成'
        } else {
          const res = await agentExec(task, {
            approval_id: target.id,
            workdir: workdir || undefined,
            mode,
            backend: String(target.payload?.backend || '') || undefined,
            model: String(target.payload?.model || '') || undefined
          })
          resultText = res.result || ''
        }
        setToast('✅ ' + (resultText || t('appr.done')).slice(0, 160))
        // 完整结果只回流到服务端冻结的发起会话。用户等待审批时即使切换会话，
        // 也不能把 A 的执行结果写进当前的 B；没有会话锚点的后台审批只显示 toast。
        if (resultText) {
          routeApprovalExecutionResult({
            approval: target,
            text: resultText,
            meta: `〔${t('chat.execTag')} · ${t('appr.approvedTag')}〕`,
            setConversationMessages: setConvMessages
          })
        }
      } else if (target.kind === 'action' && decision === 'revise') {
        setToast('↩ 已退回修改；修改后的方案需要重新发起审批。')
      } else if (target.kind === 'skill_card' && decision === 'approve') {
        setToast('✅ ' + t('appr.intoCases'))
      }
    } catch (e) {
      setToast('⚠️ ' + String(e))
    } finally {
      setNote('')
      setItems((xs) => xs.filter((x) => x.id !== target.id))
      setBusy(false)
    }
  }

  const action = items.find((x) => x.kind === 'action')
  const card = items.find((x) => x.kind === 'skill_card')

  const toastEl = toast ? (
    <div className="fixed bottom-4 right-4 z-[70] max-w-sm rounded-md border border-neutral-600 bg-neutral-800 px-3 py-2 text-sm text-neutral-100 shadow-xl">
      {toast}
      <button onClick={() => setToast('')} className="ml-2 text-neutral-500 hover:text-neutral-200">
        ✕
      </button>
    </div>
  ) : null

  // 1) 重大动作：全屏阻断弹窗
  if (action) {
    const detail = String((action.payload?.task as string) || action.summary)
    return (
      <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/50">
        <div className="w-[480px] max-w-[92vw] rounded-lg border border-blue-700 bg-neutral-900 p-4 shadow-2xl">
          <div className="mb-2 text-sm font-semibold text-blue-300">🔴 {t('appr.actionTitle')}</div>
          <div className="mb-2 max-h-52 overflow-auto whitespace-pre-wrap rounded bg-neutral-800 p-2 text-sm text-neutral-100">
            {detail}
          </div>
          <textarea
            value={note}
            onChange={(e) => setNote(e.target.value)}
            rows={2}
            placeholder={t('appr.notePh')}
            className="mb-2 w-full resize-none rounded border border-neutral-700 bg-neutral-900 px-2 py-1 text-sm text-neutral-100"
          />
          <div className="flex justify-end gap-2">
            <button onClick={() => void decide(action, 'reject')} disabled={busy} className="rounded border border-neutral-700 px-3 py-1 text-sm text-neutral-300 hover:bg-neutral-800 disabled:opacity-40">
              {t('appr.cancel')}
            </button>
            <button onClick={() => void decide(action, 'revise')} disabled={busy} className="rounded border border-amber-700 px-3 py-1 text-sm text-amber-300 hover:bg-amber-900/30 disabled:opacity-40">
              {t('appr.revise')}
            </button>
            <button onClick={() => void decide(action, 'approve')} disabled={busy} className="rounded bg-blue-600 px-3 py-1 text-sm text-white hover:bg-blue-500 disabled:opacity-40">
              {t('appr.approve')}
            </button>
          </div>
        </div>
        {toastEl}
      </div>
    )
  }

  // 2) 技能卡：右下角非阻断小卡（慢慢审，不打断）
  if (card) {
    return (
      <>
        <div className="fixed bottom-4 right-4 z-[60] w-[360px] max-w-[88vw] rounded-lg border border-neutral-700 bg-neutral-900 p-3 shadow-2xl">
          <div className="mb-1 flex items-center justify-between">
            <span className="text-xs font-semibold text-emerald-300">🔖 {t('appr.cardTitle')}</span>
            {items.filter((x) => x.kind === 'skill_card').length > 1 && (
              <span className="text-[11px] text-neutral-500">
                {t('appr.count', { n: items.filter((x) => x.kind === 'skill_card').length })}
              </span>
            )}
          </div>
          <div className="mb-2 max-h-32 overflow-auto whitespace-pre-wrap rounded bg-neutral-800 p-2 text-xs text-neutral-200">
            {t('appr.problem')}：{String(card.payload?.problem || card.summary)}
            {'\n'}
            {t('appr.solution')}：{String(card.payload?.solution || '')}
          </div>
          <input
            value={note}
            onChange={(e) => setNote(e.target.value)}
            placeholder={t('appr.notePhCard')}
            className="mb-2 w-full rounded border border-neutral-700 bg-neutral-900 px-2 py-1 text-xs text-neutral-100"
          />
          <div className="flex justify-end gap-2">
            <button onClick={() => void decide(card, 'reject')} disabled={busy} className="rounded border border-neutral-700 px-2.5 py-1 text-xs text-neutral-300 hover:bg-neutral-800 disabled:opacity-40">
              {t('appr.reject')}
            </button>
            <button onClick={() => void decide(card, 'approve')} disabled={busy} className="rounded bg-emerald-600 px-2.5 py-1 text-xs text-white hover:bg-emerald-500 disabled:opacity-40">
              {t('appr.intoCasesBtn')}
            </button>
          </div>
        </div>
        {toastEl}
      </>
    )
  }

  return toastEl
}
