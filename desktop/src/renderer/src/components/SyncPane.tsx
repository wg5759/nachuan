import React, { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  fetchSyncStatus,
  syncConfig,
  syncSignup,
  syncLogin,
  syncToggle,
  syncRun,
  type SyncStatus,
  type SyncRunResult
} from '../api'

// 跨设备云同步（Supabase）：填项目 URL/anon key → 注册或登录账户 → 开同步/手动同步。
// 只有登录同一账户的设备之间，记忆/案例/知识库才互相同步（RLS 行级隔离）。
export default function SyncPane(): React.ReactNode {
  const { t } = useTranslation()
  const [st, setSt] = useState<SyncStatus | null>(null)
  const [url, setUrl] = useState('')
  const [anonKey, setAnonKey] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState('')
  const [last, setLast] = useState<SyncRunResult | null>(null)

  const load = (): void => {
    fetchSyncStatus()
      .then((s) => {
        setSt(s)
        setUrl((u) => u || s.url)
        setEmail((e) => e || s.email)
      })
      .catch(() => {})
  }
  useEffect(() => load(), [])

  const onConfig = async (): Promise<void> => {
    setBusy(true)
    setMsg('')
    try {
      const s = await syncConfig(url.trim(), anonKey.trim())
      setSt(s)
      setAnonKey('')
      setMsg(t('sync.savedConfig'))
    } catch (e) {
      setMsg(String(e))
    } finally {
      setBusy(false)
    }
  }

  const onAuth = async (kind: 'signup' | 'login'): Promise<void> => {
    setBusy(true)
    setMsg('')
    try {
      const r =
        kind === 'signup'
          ? await syncSignup(email.trim(), password)
          : await syncLogin(email.trim(), password)
      if (!r.ok) setMsg(r.error || t('sync.authFail'))
      else if (r.need_confirm) setMsg(t('sync.needConfirm'))
      else {
        setMsg(t('sync.loggedIn'))
        setPassword('')
      }
      load()
    } catch (e) {
      setMsg(String(e))
    } finally {
      setBusy(false)
    }
  }

  const onToggle = async (): Promise<void> => {
    if (!st) return
    const s = await syncToggle(!st.enabled).catch(() => null)
    if (s) setSt(s)
  }

  const onRun = async (): Promise<void> => {
    setBusy(true)
    setMsg('')
    try {
      const r = await syncRun()
      setLast(r)
      if (r.skipped) setMsg(t('sync.skipped'))
      else if (!r.ok) setMsg(r.error || t('sync.authFail'))
      else setMsg(t('sync.done'))
      load()
    } catch (e) {
      setMsg(String(e))
    } finally {
      setBusy(false)
    }
  }

  const inp = 'w-full bg-neutral-900 border border-neutral-700 rounded px-2 py-1 text-sm'
  const sumRun = (m?: Record<string, number>): string =>
    m
      ? Object.entries(m)
          .filter(([, n]) => n > 0)
          .map(([k, n]) => `${k}:${n}`)
          .join(' ') || '0'
      : '0'

  return (
    <div className="flex flex-col h-full">
      <div className="px-3 py-2 border-b border-neutral-800 text-sm font-medium">{t('sync.title')}</div>
      <div className="flex-1 overflow-auto p-3 space-y-4 text-sm">
        <div className="text-xs text-neutral-500">{t('sync.hint')}</div>

        {/* ① Supabase 配置 */}
        <section className="space-y-2">
          <div className="text-xs uppercase tracking-wide text-neutral-500">① {t('sync.secConfig')}</div>
          <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder={t('sync.phUrl')} className={inp} />
          <input
            value={anonKey}
            onChange={(e) => setAnonKey(e.target.value)}
            placeholder={st?.configured ? t('sync.keySaved') : t('sync.phKey')}
            className={inp}
          />
          <button
            onClick={() => void onConfig()}
            disabled={busy}
            className="px-3 py-1 text-xs rounded bg-blue-700 hover:bg-blue-600 disabled:opacity-40"
          >
            {t('sync.save')}
          </button>
        </section>

        {/* ② 账户（注册 / 登录） */}
        <section className="space-y-2">
          <div className="text-xs uppercase tracking-wide text-neutral-500">② {t('sync.secAccount')}</div>
          <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder={t('sync.phEmail')} className={inp} />
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder={t('sync.phPwd')}
            className={inp}
          />
          <div className="flex gap-2">
            <button
              onClick={() => void onAuth('login')}
              disabled={busy || !st?.configured}
              className="px-3 py-1 text-xs rounded bg-blue-700 hover:bg-blue-600 disabled:opacity-40"
            >
              {t('sync.login')}
            </button>
            <button
              onClick={() => void onAuth('signup')}
              disabled={busy || !st?.configured}
              className="px-3 py-1 text-xs rounded border border-neutral-700 hover:bg-neutral-800 disabled:opacity-40"
            >
              {t('sync.signup')}
            </button>
          </div>
        </section>

        {/* ③ 同步 */}
        <section className="space-y-2">
          <div className="text-xs uppercase tracking-wide text-neutral-500">③ {t('sync.secSync')}</div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => void onToggle()}
              className={`px-2 py-0.5 text-xs rounded border ${
                st?.enabled ? 'border-green-600 text-green-400' : 'border-neutral-700 text-neutral-400'
              }`}
            >
              {st?.enabled ? t('sync.on') : t('sync.off')}
            </button>
            <button
              onClick={() => void onRun()}
              disabled={busy || !st?.logged_in}
              className="px-3 py-1 text-xs rounded bg-blue-700 hover:bg-blue-600 disabled:opacity-40"
            >
              {busy ? t('sync.running') : t('sync.runNow')}
            </button>
          </div>
          {last && (last.pushed || last.pulled) && (
            <div className="text-xs text-neutral-400">
              ⬆ {sumRun(last.pushed)} · ⬇ {sumRun(last.pulled)}
            </div>
          )}
        </section>

        {/* 状态 */}
        <div className="text-xs text-neutral-500 border-t border-neutral-800 pt-2 space-y-0.5">
          <div>
            {t('sync.stConfigured')}: {st?.configured ? '✓' : '—'} · {t('sync.stLoggedIn')}:{' '}
            {st?.logged_in ? st.email || '✓' : '—'}
          </div>
          <div>
            {t('sync.stScope')}: {t('sync.scopePersonal')} · {t('sync.stLocalUser')}:{' '}
            {st?.local_user || 'owner'}
          </div>
          <div>
            {t('sync.stTables')}: {(st?.sync_tables ?? ['memory', 'cases', 'kb_docs', 'kb_chunks']).join(' / ')}
          </div>
          <div>
            {t('sync.stDevice')}: {st?.device_id || '—'}
          </div>
        </div>
        {msg && <div className="text-xs text-amber-400">{msg}</div>}
      </div>
    </div>
  )
}
