import React, { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  addMcp,
  fetchMcp,
  fetchMcpPresets,
  removeMcp,
  type McpPreset,
  type McpProbe,
  type McpServer
} from '../api'

// MCP 工具中心：远程包预设只作迁移说明；仅本地哈希证明后的 MCP 可由后端启用。
export default function McpPane(): React.ReactNode {
  const { t } = useTranslation()
  const [servers, setServers] = useState<Record<string, McpServer>>({})
  const [enabled, setEnabled] = useState(false)
  const [status, setStatus] = useState<Record<string, McpProbe>>({})
  const [presets, setPresets] = useState<McpPreset[]>([])
  const [name, setName] = useState('')
  const [cmd, setCmd] = useState('')
  const [args, setArgs] = useState('')
  const [sha256, setSha256] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')

  const load = (): void => {
    fetchMcp()
      .then((d) => {
        setEnabled(Boolean(d.enabled))
        setServers(d.mcpServers || {})
        setStatus(d.status || {})
      })
      .catch(() => {})
  }
  useEffect(() => {
    load()
    fetchMcpPresets()
      .then(setPresets)
      .catch(() => {})
  }, [])

  const doAdd = async (body: {
    name: string
    command?: string
    args?: string[]
    sha256?: string
  }): Promise<void> => {
    setBusy(true)
    setErr('')
    try {
      const r = await addMcp(body)
      if (r.needs_approval) {
        setErr(`已送一次性审批（${r.approval_id ?? '-'}）；批准后才会启用。`)
        return
      }
      if (r.probe && !r.probe.ok) setErr(t('mcp.unavailable', { detail: r.probe.detail }))
      load()
    } catch (e) {
      setErr(String(e))
    } finally {
      setBusy(false)
    }
  }

  const onAdd = async (): Promise<void> => {
    if (!name.trim() || !cmd.trim() || !/^[0-9a-fA-F]{64}$/.test(sha256.trim())) {
      setErr(t('mcp.needFields'))
      return
    }
    await doAdd({
      name: name.trim(),
      command: cmd.trim(),
      args: args.trim() ? args.trim().split(/\s+/) : undefined,
      sha256: sha256.trim().toLowerCase()
    })
    setName('')
    setCmd('')
    setArgs('')
    setSha256('')
  }

  const onPreset = async (p: McpPreset): Promise<void> => {
    if (!p.available) {
      setErr(t('mcp.runtimeMissing', { runtime: p.runtime }))
      return
    }
    setErr(t('mcp.runtimeMissing', { runtime: p.runtime }))
  }

  const onRemove = async (n: string): Promise<void> => {
    try {
      const r = await removeMcp(n)
      if (r.needs_approval) {
        setErr(`移除请求已送审（${r.approval_id ?? '-'}）。`)
      } else {
        load()
      }
    } catch (e) {
      setErr(String(e))
    }
  }

  const inp = 'w-full bg-neutral-900 border border-neutral-700 rounded px-2 py-1 text-sm'

  return (
    <div className="flex flex-col h-full">
      <div className="px-3 py-2 border-b border-neutral-800 text-sm font-medium">{t('mcp.title')}</div>
      <div className="p-3 space-y-2 overflow-auto">
        <div className="text-xs text-neutral-500">{t('mcp.hint')}</div>
        {!enabled && (
          <div className="rounded border border-amber-800 bg-amber-950/30 p-2 text-xs text-amber-300">
            正式版已隔离未审计 MCP。只有固定版本、哈希与签名验证完成的插件才允许启用。
          </div>
        )}

        {/* 历史预设默认禁用，避免远程 registry 下载后即刻执行。 */}
        {presets.length > 0 && (
          <div>
            <div className="text-xs uppercase tracking-wide text-neutral-500 mb-1">{t('mcp.presets')}</div>
            <div className="flex flex-wrap gap-1.5">
              {presets.map((p) => (
                <button
                  key={p.name}
                  onClick={() => void onPreset(p)}
                  disabled={busy || !enabled}
                  title={`${p.desc}${p.note ? ' · ' + p.note : ''}\n${p.command} ${p.args.join(' ')}`}
                  className={`px-2 py-1 text-xs rounded border disabled:opacity-40 ${
                    p.available
                      ? 'border-neutral-700 hover:bg-neutral-800'
                      : 'border-neutral-800 text-neutral-600'
                  }`}
                >
                  {p.available ? '＋ ' : '⚠ '}
                  {p.name}
                  <span className="text-neutral-500"> · {p.desc}</span>
                </button>
              ))}
            </div>
          </div>
        )}

        {/* 手动挂载 */}
        <div className="text-xs uppercase tracking-wide text-neutral-500 pt-1">{t('mcp.manual')}</div>
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder={t('mcp.phName')} className={inp} />
        <input value={cmd} onChange={(e) => setCmd(e.target.value)} placeholder={t('mcp.phCmd')} className={inp} />
        <input value={args} onChange={(e) => setArgs(e.target.value)} placeholder={t('mcp.phArgs')} className={inp} />
        <input value={sha256} onChange={(e) => setSha256(e.target.value)} placeholder={t('mcp.phSha256')} className={inp} />
        <button
          onClick={() => void onAdd()}
          disabled={busy || !enabled}
          className="px-3 py-1 text-sm rounded bg-blue-700 hover:bg-blue-600 disabled:opacity-40"
        >
          {busy ? t('mcp.mounting') : t('mcp.mount')}
        </button>
        {err && <div className="text-xs text-red-400">{err}</div>}
      </div>
      <div className="flex-1 overflow-auto px-3 pb-3">
        <div className="text-xs uppercase tracking-wide text-neutral-500 mb-1">
          {t('mcp.mountedCount', { n: Object.keys(servers).length })}
        </div>
        <ul className="space-y-1 text-sm">
          {Object.entries(servers).map(([n, s]) => {
            const ok = status[n]?.ok
            return (
              <li key={n} className="flex items-center gap-2 border border-neutral-800 rounded p-2">
                <span
                  title={status[n]?.detail || ''}
                  className={`shrink-0 text-xs ${ok ? 'text-green-500' : 'text-amber-500'}`}
                >
                  {ok ? '●' : '○'}
                </span>
                <span className="text-neutral-200 shrink-0">{n}</span>
                <span className="text-xs text-neutral-500 truncate">
                  {s.url || `${s.command ?? ''} ${(s.args || []).join(' ')}`}
                </span>
                <button
                  onClick={() => void onRemove(n)}
                  className="ml-auto text-xs text-neutral-500 hover:text-red-400 shrink-0"
                >
                  {t('mcp.remove')}
                </button>
              </li>
            )
          })}
        </ul>
      </div>
    </div>
  )
}
