import React from 'react'

import i18n from '../i18n'
import { useAppStore } from '../store'
import type {
  ChannelRecoveryChannel,
  ChannelRecoveryResult,
  ChannelRecoverySnapshot,
  ChannelRecoveryTarget
} from '../env'

type SettingsLanguage = 'zh' | 'en'

const RECOVERY_KINDS: Record<ChannelRecoveryChannel, ChannelRecoveryTarget['targetKind'][]> = {
  weixin: ['inbound', 'delivery', 'video'],
  feishu: ['inbox', 'outbox', 'video']
}

function ChannelRecoveryPanel({ language }: { language: SettingsLanguage }): React.ReactNode {
  const zh = language === 'zh'
  const [channel, setChannel] = React.useState<ChannelRecoveryChannel>('weixin')
  const [targetKind, setTargetKind] = React.useState<ChannelRecoveryTarget['targetKind']>('inbound')
  const [targetKey, setTargetKey] = React.useState('')
  const [reason, setReason] = React.useState('')
  const [firstConfirmed, setFirstConfirmed] = React.useState(false)
  const [finalConfirmed, setFinalConfirmed] = React.useState(false)
  const [snapshot, setSnapshot] = React.useState<ChannelRecoverySnapshot | null>(null)
  const [result, setResult] = React.useState<ChannelRecoveryResult | null>(null)
  const [busy, setBusy] = React.useState<'inspect' | 'close' | null>(null)
  const [error, setError] = React.useState('')

  const clearDecision = React.useCallback(() => {
    setSnapshot(null)
    setResult(null)
    setFirstConfirmed(false)
    setFinalConfirmed(false)
    setError('')
  }, [])

  const inspect = async (): Promise<void> => {
    setBusy('inspect')
    setError('')
    setResult(null)
    try {
      setSnapshot(await window.api.inspectChannelRecovery({ channel, targetKind, targetKey }))
    } catch (caught) {
      setSnapshot(null)
      setError(caught instanceof Error ? caught.message : String(caught))
    } finally {
      setBusy(null)
    }
  }

  const close = async (): Promise<void> => {
    if (!snapshot || !firstConfirmed || !finalConfirmed || !reason.trim()) return
    const approved =
      window.api.runtimeKind === 'electron' ||
      window.confirm(
        zh
          ? '这是永久结案：不会恢复、不会重发、不会再次调用平台。确定继续吗？'
          : 'This permanently closes the records without restore, replay, or another platform call. Continue?'
      )
    if (!approved) return
    setBusy('close')
    setError('')
    try {
      setResult(await window.api.closeChannelRecovery({
        channel,
        targetKind,
        targetKey,
        targetKeySha256: snapshot.targetKeySha256,
        expectedBeforeDigest: snapshot.expectedBeforeDigest,
        decisionId: snapshot.decisionId,
        decidedAtMs: snapshot.decidedAtMs,
        reason: reason.trim(),
        userConfirmed: true,
        confirmFinal: true
      }))
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught))
    } finally {
      setBusy(null)
    }
  }

  return (
    <section className="nachuan-settings-card nachuan-recovery" aria-label={zh ? '消息恢复结案' : 'Message recovery closure'}>
      <div className="nachuan-recovery-heading">
        <div>
          <h2>{zh ? '平台结果未知：人工结案' : 'Unknown platform result: manual closure'}</h2>
          <p>{zh ? '仅处理已进入 recovery_required 的微信/飞书记录；先检查，再双重确认。不会恢复原件，也不会自动重发。' : 'Only handles Weixin or Feishu records already in recovery_required. Inspect first, then confirm twice. No restore or replay.'}</p>
        </div>
        <span className="nachuan-recovery-badge">NO REPLAY</span>
      </div>

      <div className="nachuan-recovery-grid">
        <label>
          <span>{zh ? '渠道' : 'Channel'}</span>
          <select value={channel} onChange={(event) => {
            const next = event.target.value as ChannelRecoveryChannel
            setChannel(next)
            setTargetKind(RECOVERY_KINDS[next][0])
            clearDecision()
          }}>
            <option value="weixin">{zh ? '微信' : 'Weixin'}</option>
            <option value="feishu">{zh ? '飞书' : 'Feishu'}</option>
          </select>
        </label>
        <label>
          <span>{zh ? '记录类型' : 'Record type'}</span>
          <select value={targetKind} onChange={(event) => {
            setTargetKind(event.target.value as ChannelRecoveryTarget['targetKind'])
            clearDecision()
          }}>
            {RECOVERY_KINDS[channel].map((kind) => <option key={kind} value={kind}>{kind}</option>)}
          </select>
        </label>
        <label className="nachuan-recovery-target">
          <span>{zh ? '目标键（消息/投递/任务标识）' : 'Target key (message, delivery, or task id)'}</span>
          <input value={targetKey} maxLength={512} autoComplete="off" spellCheck={false} onChange={(event) => {
            setTargetKey(event.target.value)
            clearDecision()
          }} />
        </label>
      </div>

      <button type="button" className="nachuan-recovery-action" disabled={busy !== null || targetKey.length < 1} onClick={() => void inspect()}>
        {busy === 'inspect' ? (zh ? '检查中…' : 'Inspecting…') : (zh ? '只读检查' : 'Read-only inspect')}
      </button>

      {snapshot && <div className="nachuan-recovery-proof" aria-live="polite">
        <strong>{zh ? '检查结果（不显示原始目标）' : 'Inspection result (raw target hidden)'}</strong>
        <dl>
          <div><dt>{zh ? '目标摘要' : 'Target digest'}</dt><dd>{snapshot.targetKeySha256}</dd></div>
          <div><dt>{zh ? '状态摘要' : 'State digest'}</dt><dd>{snapshot.expectedBeforeDigest}</dd></div>
          <div><dt>{zh ? '受影响记录' : 'Affected rows'}</dt><dd>{JSON.stringify(snapshot.affectedCounts)}</dd></div>
          <div><dt>{zh ? '决策时间' : 'Decision time'}</dt><dd>{new Date(snapshot.decidedAtMs).toLocaleString()}</dd></div>
        </dl>
        <label className="nachuan-recovery-reason">
          <span>{zh ? '结案依据' : 'Closure rationale'}</span>
          <textarea value={reason} maxLength={2048} onChange={(event) => {
            setReason(event.target.value)
            setResult(null)
          }} placeholder={zh ? '写明已核实的平台结果和不重发依据' : 'Document the verified platform outcome and no-replay basis'} />
        </label>
        <label className="nachuan-recovery-check">
          <input type="checkbox" checked={firstConfirmed} onChange={(event) => setFirstConfirmed(event.target.checked)} />
          <span>{zh ? '我确认平台结果未知，禁止自动重放' : 'I confirm the platform result is unknown and automatic replay is forbidden'}</span>
        </label>
        <label className="nachuan-recovery-check">
          <input type="checkbox" checked={finalConfirmed} onChange={(event) => setFinalConfirmed(event.target.checked)} />
          <span>{zh ? '我确认只做结案，不恢复、不重发' : 'I confirm closure only: no restore and no replay'}</span>
        </label>
        <button type="button" className="nachuan-recovery-action nachuan-recovery-danger" disabled={busy !== null || !reason.trim() || !firstConfirmed || !finalConfirmed} onClick={() => void close()}>
          {busy === 'close' ? (zh ? '写入回执中…' : 'Writing receipt…') : (zh ? '永久结案并写入回执' : 'Permanently close and write receipt')}
        </button>
      </div>}

      {result && <div className="nachuan-recovery-result" aria-live="polite">
        <strong>{result.applied ? (zh ? '结案已应用' : 'Closure applied') : (zh ? '已找到同一操作的既有回执' : 'Existing receipt returned for the same operation')}</strong>
        <span>{zh ? '回执摘要' : 'Receipt digest'}: {result.receiptSha256}</span>
        <span>{zh ? '操作摘要' : 'Operation digest'}: {result.operationDigest}</span>
      </div>}
      {error && <p className="nachuan-recovery-error" role="alert">{error}</p>}
    </section>
  )
}

export function SettingsPaneView({
  language,
  soundEnabled,
  onLanguageChange,
  onSoundChange,
  onOpenConnections,
  onOpenAbout
}: {
  language: SettingsLanguage
  soundEnabled: boolean
  onLanguageChange: (language: SettingsLanguage) => void
  onSoundChange: (enabled: boolean) => void
  onOpenConnections: () => void
  onOpenAbout: () => void
}): React.ReactNode {
  const zh = language === 'zh'
  return (
    <main className="nachuan-page nachuan-settings" aria-labelledby="settings-title">
      <div className="nachuan-page-heading">
        <span className="nachuan-eyebrow">NACHUAN</span>
        <h1 id="settings-title">{zh ? '常规设置' : 'General settings'}</h1>
        <p>{zh ? '只呈现当前真正生效的偏好；模型与账号统一在连接中心管理。' : 'Only working preferences live here. Models and accounts stay in Connections.'}</p>
      </div>

      <section className="nachuan-settings-card" aria-label={zh ? '界面与提醒' : 'Interface and alerts'}>
        <div className="nachuan-setting-row">
          <div>
            <h2>{zh ? '界面语言' : 'Language'}</h2>
            <p>{zh ? '切换纳川界面的显示语言。' : 'Change the display language.'}</p>
          </div>
          <div className="nachuan-segmented" role="group" aria-label={zh ? '界面语言' : 'Language'}>
            <button
              type="button"
              aria-pressed={language === 'zh'}
              onClick={() => onLanguageChange('zh')}
            >
              简体中文
            </button>
            <button
              type="button"
              aria-pressed={language === 'en'}
              onClick={() => onLanguageChange('en')}
            >
              English
            </button>
          </div>
        </div>
        <div className="nachuan-setting-row">
          <div>
            <h2>{zh ? '完成提示音' : 'Completion sound'}</h2>
            <p>{zh ? '任务和媒体生成完成后播放提示音。' : 'Play a sound when a task or media job finishes.'}</p>
          </div>
          <button
            type="button"
            role="switch"
            aria-checked={soundEnabled}
            className="nachuan-switch"
            onClick={() => onSoundChange(!soundEnabled)}
          >
            <span />
          </button>
        </div>
      </section>

      <section className="nachuan-settings-card" aria-label={zh ? '管理' : 'Manage'}>
        <button type="button" className="nachuan-settings-link" onClick={onOpenConnections}>
          <span>
            <strong>{zh ? '连接中心' : 'Connections'}</strong>
            <small>{zh ? '管理 API Key、订阅登录与本地模型' : 'Manage API keys, subscriptions and local models'}</small>
          </span>
          <span aria-hidden="true">→</span>
        </button>
        <button type="button" className="nachuan-settings-link" onClick={onOpenAbout}>
          <span>
            <strong>{zh ? '关于纳川' : 'About Nachuan'}</strong>
            <small>{zh ? '版本、更新与产品信息' : 'Version, updates and product information'}</small>
          </span>
          <span aria-hidden="true">→</span>
        </button>
      </section>
      <ChannelRecoveryPanel language={language} />
    </main>
  )
}

export default function SettingsPane(): React.ReactNode {
  const soundEnabled = useAppStore((state) => state.soundEnabled)
  const setSoundEnabled = useAppStore((state) => state.setSoundEnabled)
  const setView = useAppStore((state) => state.setView)
  const language: SettingsLanguage = i18n.language.toLowerCase().startsWith('zh') ? 'zh' : 'en'
  return (
    <SettingsPaneView
      language={language}
      soundEnabled={soundEnabled}
      onLanguageChange={(next) => {
        void i18n.changeLanguage(next)
        window.api.setLang(next)
      }}
      onSoundChange={setSoundEnabled}
      onOpenConnections={() => setView('connections')}
      onOpenAbout={() => setView('about')}
    />
  )
}
