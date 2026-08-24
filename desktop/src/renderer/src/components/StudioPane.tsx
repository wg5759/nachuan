import React, { useState } from 'react'
import {
  type StudioJob,
  type StudioPlan,
  studioExecute,
  studioJob,
  studioPlan,
  studioVideoBlobUrl
} from '../api'

// 视频工作室（创作线）：① 出分镜方案 → ② 调教 → ③ 执行成片（③ 随后上线）。中文优先。
export default function StudioPane(): React.ReactNode {
  const [goal, setGoal] = useState('')
  const [plan, setPlan] = useState<StudioPlan | null>(null)
  const [feedback, setFeedback] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [job, setJob] = useState<StudioJob | null>(null)
  const [videoUrl, setVideoUrl] = useState('')

  const run = async (fb = ''): Promise<void> => {
    if (!goal.trim()) return
    setBusy(true)
    setErr('')
    try {
      setPlan(await studioPlan(goal, fb, fb ? (plan ?? undefined) : undefined))
      if (fb) setFeedback('')
    } catch (e) {
      setErr(String(e))
    } finally {
      setBusy(false)
    }
  }

  const execute = async (): Promise<void> => {
    if (!plan?.shots?.length) return
    setJob({ status: 'running', progress: 0, total: plan.shots.length, msg: '开始…', video: '', error: '' })
    setVideoUrl('')
    try {
      const launch = await studioExecute(plan)
      if (launch.needs_approval) {
        setJob((j) => ({
          ...(j as StudioJob),
          status: 'approval',
          msg: `方案已送审（${launch.approval_id ?? '-'}），批准后启动。`
        }))
        return
      }
      const job_id = launch.job_id
      if (!job_id) throw new Error('视频任务未返回 job_id')
      for (;;) {
        await new Promise((r) => setTimeout(r, 4000))
        const j = await studioJob(job_id)
        setJob(j)
        if (j.status === 'done') {
          setVideoUrl(await studioVideoBlobUrl(job_id))
          break
        }
        if (j.status === 'error' || j.status === 'unknown') break
      }
    } catch (e) {
      setJob((j) => ({ ...(j as StudioJob), status: 'error', error: String(e) }))
    }
  }

  const totalSec = plan?.shots?.reduce((a, s) => a + (s.seconds || 0), 0) ?? 0

  return (
    <div className="flex flex-col h-full overflow-auto">
      <div className="px-3 py-2 border-b border-neutral-800 text-sm font-medium">
        🎬 视频工作室（先出分镜方案 → 调教 → 执行）
      </div>
      <div className="p-3 space-y-4">
        <section className="space-y-2">
          <div className="text-sm text-neutral-400">① 你的目标</div>
          <div className="flex gap-2">
            <input
              value={goal}
              onChange={(e) => setGoal(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !plan) void run()
              }}
              placeholder="如：做个10秒产品宣传片，介绍一款智能保温水杯，科技感"
              className="flex-1 px-2 py-1.5 rounded bg-neutral-950 border border-neutral-700 text-sm"
            />
            <button
              onClick={() => void run()}
              disabled={busy || !goal.trim()}
              className="px-3 rounded bg-blue-600 hover:bg-blue-500 disabled:opacity-40 text-sm whitespace-nowrap"
            >
              {busy && !plan ? '出方案中…' : '出方案'}
            </button>
          </div>
          {err && <div className="text-xs text-red-400">{err}</div>}
        </section>

        {plan && (
          <>
            <section className="space-y-2 border border-neutral-800 rounded-lg p-3 bg-neutral-900/40">
              <div className="flex items-center justify-between">
                <div className="font-medium">{plan.title || '分镜方案'}</div>
                <div className="text-xs text-neutral-500">
                  {plan.shots.length} 镜 · 约 {totalSec}s
                </div>
              </div>
              {plan.style && <div className="text-xs text-neutral-400">风格：{plan.style}</div>}
              {plan.subject && (
                <div className="text-xs text-neutral-400">主体（每镜锁定一致）：{plan.subject}</div>
              )}
              <div className="space-y-2">
                {plan.shots.map((s) => (
                  <div key={s.n} className="text-sm border-l-2 border-blue-700/50 pl-2">
                    <div className="text-neutral-300">
                      <span className="text-blue-400">#{s.n}</span>
                      <span className="text-neutral-500 text-xs ml-2">
                        {s.seconds}s · {s.motion}
                      </span>
                    </div>
                    <div className="text-neutral-400 text-xs mt-0.5">{s.desc}</div>
                  </div>
                ))}
                {plan.shots.length === 0 && plan.raw && (
                  <div className="text-xs text-neutral-500 whitespace-pre-wrap">{plan.raw}</div>
                )}
              </div>
            </section>

            <section className="space-y-2">
              <div className="text-sm text-neutral-400">② 调教（不满意就提，反复改到满意）</div>
              <div className="flex gap-2">
                <input
                  value={feedback}
                  onChange={(e) => setFeedback(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') void run(feedback)
                  }}
                  placeholder="如：第3镜换夜景 / 整体再暗黑科技感 / 加一镜展示保温效果"
                  className="flex-1 px-2 py-1.5 rounded bg-neutral-950 border border-neutral-700 text-sm"
                />
                <button
                  onClick={() => void run(feedback)}
                  disabled={busy || !feedback.trim()}
                  className="px-3 rounded border border-neutral-700 hover:bg-neutral-800 disabled:opacity-40 text-sm whitespace-nowrap"
                >
                  {busy ? '改方案中…' : '改方案'}
                </button>
              </div>
            </section>

            <div className="space-y-2">
              <div className="text-sm text-neutral-400">③ 执行成片（逐镜生成，约每镜几分钟，请耐心）</div>
              <button
                onClick={() => void execute()}
                disabled={job?.status === 'running'}
                className="w-full py-2 rounded bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-sm"
              >
                {job?.status === 'running'
                  ? `成片中… ${job.progress}/${job.total} · ${job.msg}`
                  : '③ 按方案执行成片（逐镜生成 + 拼接）'}
              </button>
              {job?.status === 'error' && (
                <div className="text-xs text-red-400">成片失败：{job.error}</div>
              )}
              {videoUrl && (
                <video
                  src={videoUrl}
                  controls
                  className="w-full rounded border border-neutral-800"
                />
              )}
            </div>
          </>
        )}
      </div>
    </div>
  )
}
