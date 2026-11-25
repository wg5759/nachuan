import React, { useEffect, useRef, useState } from 'react'
import { useTranslation } from '../../i18n'
import type { RuntimeCapabilityManifest, RuntimeKind } from '../../../../runtime-capabilities'
import { EXEC_PERMISSION_OPTIONS, type ExecPermissionMode } from './chatUtils'

export function PermissionIcon({
  mode,
  className = ''
}: {
  mode: ExecPermissionMode
  className?: string
}): React.ReactNode {
  const common = {
    width: 22,
    height: 22,
    viewBox: '0 0 24 24',
    fill: 'none',
    stroke: 'currentColor',
    strokeWidth: 1.8,
    strokeLinecap: 'round' as const,
    strokeLinejoin: 'round' as const,
    className
  }
  if (mode === 'plan') {
    return (
      <svg {...common}>
        <path d="M7 11.5V6.8a1.4 1.4 0 0 1 2.8 0v4.1" />
        <path d="M9.8 10.7V5.4a1.4 1.4 0 0 1 2.8 0v5.3" />
        <path d="M12.6 10.5V6.7a1.4 1.4 0 0 1 2.8 0v4.6" />
        <path d="M15.4 11.7V8.8a1.4 1.4 0 0 1 2.8 0v5.6c0 4.1-2.5 6.6-6.2 6.6h-.7c-2.2 0-3.7-.9-4.8-2.5L4.2 15a1.5 1.5 0 0 1 2.5-1.6L8 15.1" />
      </svg>
    )
  }
  if (mode === 'auto') {
    return (
      <svg {...common}>
        <path d="M12 3.2 19 6v5.3c0 4.3-2.7 7.7-7 9.5-4.3-1.8-7-5.2-7-9.5V6l7-2.8Z" />
        <path d="m8.8 12.1 2.1 2.1 4.4-4.6" />
      </svg>
    )
  }
  if (mode === 'full') {
    return (
      <svg {...common}>
        <path d="M12 3.2 19 6v5.3c0 4.3-2.7 7.7-7 9.5-4.3-1.8-7-5.2-7-9.5V6l7-2.8Z" />
        <path d="M12 7.8v5.1" />
        <path d="M12 16.3h.01" />
      </svg>
    )
  }
  return (
    <svg {...common}>
      <path d="M12 15.2a3.2 3.2 0 1 0 0-6.4 3.2 3.2 0 0 0 0 6.4Z" />
      <path d="M19.4 15a1.8 1.8 0 0 0 .4 2l.1.1a2.1 2.1 0 0 1-3 3l-.1-.1a1.8 1.8 0 0 0-2-.4 1.8 1.8 0 0 0-1.1 1.6v.2a2.1 2.1 0 0 1-4.2 0v-.2a1.8 1.8 0 0 0-1.1-1.6 1.8 1.8 0 0 0-2 .4l-.1.1a2.1 2.1 0 0 1-3-3l.1-.1a1.8 1.8 0 0 0 .4-2 1.8 1.8 0 0 0-1.6-1.1H2a2.1 2.1 0 0 1 0-4.2h.2a1.8 1.8 0 0 0 1.6-1.1 1.8 1.8 0 0 0-.4-2l-.1-.1a2.1 2.1 0 0 1 3-3l.1.1a1.8 1.8 0 0 0 2 .4h.1a1.8 1.8 0 0 0 1-1.6V2a2.1 2.1 0 0 1 4.2 0v.2a1.8 1.8 0 0 0 1.1 1.6 1.8 1.8 0 0 0 2-.4l.1-.1a2.1 2.1 0 0 1 3 3l-.1.1a1.8 1.8 0 0 0-.4 2v.1a1.8 1.8 0 0 0 1.6 1H22a2.1 2.1 0 0 1 0 4.2h-.2a1.8 1.8 0 0 0-1.6 1.1l-.8.2Z" />
    </svg>
  )
}

export function ExecPermissionMenu({
  value,
  onChange
}: {
  value: ExecPermissionMode
  onChange: (v: ExecPermissionMode) => void
}): React.ReactNode {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    const onDown = (e: MouseEvent): void => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', onDown)
    return () => document.removeEventListener('mousedown', onDown)
  }, [open])

  const cur = EXEC_PERMISSION_OPTIONS.find((o) => o.value === value) ?? EXEC_PERMISSION_OPTIONS[1]
  const hot = value === 'full'

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        title={t('chat.execPerm')}
        onClick={() => setOpen((v) => !v)}
        className={`h-8 inline-flex items-center gap-1.5 rounded-md px-2 text-sm hover:bg-neutral-800 ${
          hot ? 'text-orange-400' : 'text-neutral-300'
        }`}
      >
        <PermissionIcon mode={value} className="shrink-0" />
        <span className="max-w-[9rem] truncate">{t(cur.label)}</span>
        <svg
          width="14"
          height="14"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
          className="shrink-0 opacity-70"
        >
          <path d="m6 9 6 6 6-6" />
        </svg>
      </button>

      {open && (
        <div className="absolute left-0 bottom-full z-50 mb-2 w-[min(430px,calc(100vw-40px))] rounded-2xl border border-neutral-700 bg-neutral-950/95 py-2 shadow-2xl backdrop-blur">
          {EXEC_PERMISSION_OPTIONS.map((o) => {
            const selected = o.value === value
            return (
              <button
                key={o.value}
                type="button"
                onClick={() => {
                  onChange(o.value)
                  setOpen(false)
                }}
                className={`flex w-full items-center gap-4 px-5 py-3 text-left transition-colors ${
                  selected ? 'bg-neutral-800/80' : 'hover:bg-neutral-900'
                }`}
              >
                <PermissionIcon mode={o.value} className="shrink-0 text-neutral-400" />
                <span className="min-w-0 flex-1">
                  <span className="block text-base leading-6 text-neutral-100">{t(o.label)}</span>
                  <span className="block text-sm leading-5 text-neutral-500">{t(o.desc)}</span>
                </span>
                {selected && (
                  <svg
                    width="22"
                    height="22"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2.2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    className="shrink-0 text-neutral-200"
                  >
                    <path d="m20 6-11 11-5-5" />
                  </svg>
                )}
              </button>
            )
          })}
        </div>
      )}
    </div>
  )
}

export function ComposerIcon({
  type,
  className = ''
}: {
  type: 'plus' | 'file' | 'target' | 'plan' | 'x'
  className?: string
}): React.ReactNode {
  const common = {
    width: 20,
    height: 20,
    viewBox: '0 0 24 24',
    fill: 'none',
    stroke: 'currentColor',
    strokeWidth: 1.8,
    strokeLinecap: 'round' as const,
    strokeLinejoin: 'round' as const,
    className
  }
  if (type === 'file') {
    return (
      <svg {...common}>
        <path d="M14 2H7a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V7Z" />
        <path d="M14 2v5h5" />
        <path d="M9 13h6" />
        <path d="M9 17h4" />
      </svg>
    )
  }
  if (type === 'target') {
    return (
      <svg {...common}>
        <circle cx="12" cy="12" r="8" />
        <circle cx="12" cy="12" r="3" />
        <path d="M12 2v3" />
        <path d="M12 19v3" />
        <path d="M2 12h3" />
        <path d="M19 12h3" />
      </svg>
    )
  }
  if (type === 'plan') {
    return (
      <svg {...common}>
        <path d="M8 6h13" />
        <path d="M8 12h13" />
        <path d="M8 18h13" />
        <path d="m3 6 .6.6L5 5.2" />
        <path d="m3 12 .6.6L5 11.2" />
        <path d="m3 18 .6.6L5 17.2" />
      </svg>
    )
  }
  if (type === 'x') {
    return (
      <svg {...common}>
        <path d="M18 6 6 18" />
        <path d="m6 6 12 12" />
      </svg>
    )
  }
  return (
    <svg {...common}>
      <path d="M12 5v14" />
      <path d="M5 12h14" />
    </svg>
  )
}

export function ComposerAttachmentRow({
  runtimeKind,
  runtimeCapabilities,
  onPickFile,
  onPickFolder
}: {
  runtimeKind: RuntimeKind
  runtimeCapabilities: RuntimeCapabilityManifest
  onPickFile: () => void
  onPickFolder: () => void
}): React.JSX.Element {
  const { t } = useTranslation()
  const surface = runtimeKind === 'electron' ? 'electron' : 'localWeb'
  const directorySupport =
    runtimeCapabilities.capabilities.directoryPicker.surfaces[surface].declaredSupport
  const canPickDirectory =
    directorySupport === 'implemented' || directorySupport === 'implemented-with-preconditions'

  return (
    <div className="flex px-1.5">
      <button
        type="button"
        onClick={onPickFile}
        className="flex min-w-0 flex-1 items-center gap-3 rounded-lg px-3 py-2.5 text-left hover:bg-neutral-900"
      >
        <ComposerIcon type="file" className="shrink-0 text-neutral-400" />
        <span className="min-w-0 flex-1 truncate text-sm text-neutral-100">{t('chat.addFile')}</span>
      </button>
      {canPickDirectory && (
        <button
          type="button"
          onClick={onPickFolder}
          className="ml-1 rounded-lg border border-neutral-800 px-2 text-xs text-neutral-300 hover:bg-neutral-900"
        >
          {t('chat.addFolder')}
        </button>
      )}
    </div>
  )
}

export function ComposerMenu({
  runtimeKind,
  runtimeCapabilities,
  target,
  onPickFile,
  onPickFolder,
  onTargetChange,
  onPlanMode
}: {
  runtimeKind: RuntimeKind
  runtimeCapabilities: RuntimeCapabilityManifest
  target: string
  onPickFile: () => void
  onPickFolder: () => void
  onTargetChange: (target: string) => void
  onPlanMode: () => void
}): React.ReactNode {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const [targetOpen, setTargetOpen] = useState(false)
  const [draft, setDraft] = useState(target)
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => setDraft(target), [target])
  useEffect(() => {
    if (!open) return
    const onDown = (e: MouseEvent): void => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', onDown)
    return () => document.removeEventListener('mousedown', onDown)
  }, [open])

  const applyTarget = (): void => {
    onTargetChange(draft.trim())
    setTargetOpen(false)
  }

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        title={t('chat.addMenu')}
        className="h-8 w-8 shrink-0 flex items-center justify-center rounded-md text-neutral-400 hover:bg-neutral-800 disabled:opacity-40"
      >
        <ComposerIcon type="plus" />
      </button>
      {open && (
        <div className="absolute left-0 bottom-full z-50 mb-2 w-[min(360px,calc(100vw-40px))] rounded-xl border border-neutral-700 bg-neutral-950/95 py-1.5 shadow-2xl backdrop-blur">
          <ComposerAttachmentRow
            runtimeKind={runtimeKind}
            runtimeCapabilities={runtimeCapabilities}
            onPickFile={() => {
              onPickFile()
              setOpen(false)
            }}
            onPickFolder={() => {
              onPickFolder()
              setOpen(false)
            }}
          />
          <button
            type="button"
            onClick={() => setTargetOpen((v) => !v)}
            className="flex w-full items-center gap-3 px-4 py-2.5 text-left hover:bg-neutral-900"
          >
            <ComposerIcon type="target" className="shrink-0 text-neutral-400" />
            <span className="min-w-0 flex-1">
              <span className="block truncate text-sm text-neutral-100">{t('chat.target')}</span>
              {target && <span className="block truncate text-xs text-neutral-500">{target}</span>}
            </span>
          </button>
          {targetOpen && (
            <div className="px-4 pb-2">
              <div className="flex gap-1">
                <input
                  value={draft}
                  onChange={(e) => setDraft(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') applyTarget()
                    if (e.key === 'Escape') setTargetOpen(false)
                  }}
                  placeholder={t('chat.targetPlaceholder')}
                  className="min-w-0 flex-1 rounded-md border border-neutral-700 bg-neutral-900 px-2 py-1 text-xs text-neutral-100 outline-none"
                />
                <button
                  type="button"
                  onClick={applyTarget}
                  className="rounded-md bg-blue-600 px-2 text-xs text-white hover:bg-blue-500"
                >
                  {t('chat.apply')}
                </button>
              </div>
            </div>
          )}
          <button
            type="button"
            onClick={() => {
              onPlanMode()
              setOpen(false)
            }}
            className="flex w-full items-center gap-3 px-4 py-2.5 text-left hover:bg-neutral-900"
          >
            <ComposerIcon type="plan" className="shrink-0 text-neutral-400" />
            <span className="min-w-0 flex-1 truncate text-sm text-neutral-100">
              {t('chat.planMode')}
            </span>
          </button>
        </div>
      )}
    </div>
  )
}

export function ComposerPrivacyControls({
  webSearchEnabled,
  onToggleWebSearch,
  incognito,
  onToggleIncognito,
  webSearchBlockedBy,
  disabled = false
}: {
  webSearchEnabled: boolean
  onToggleWebSearch: () => void
  incognito: boolean
  onToggleIncognito: () => void
  webSearchBlockedBy: 'offline' | 'incognito' | 'local' | 'feature' | null
  disabled?: boolean
}): React.ReactNode {
  const { t } = useTranslation()
  const webSearchActive = webSearchBlockedBy === null && webSearchEnabled
  const webSearchTitle =
    webSearchBlockedBy === 'offline'
      ? t('chat.webSearchDisabledOffline', { defaultValue: '纯离线模式已开启' })
      : webSearchBlockedBy === 'incognito'
        ? t('chat.webSearchDisabledIncognito', { defaultValue: '无痕模式下已强制禁用联网搜索' })
        : webSearchBlockedBy === 'local'
          ? t('chat.webSearchDisabledLocal', { defaultValue: '本地离线模型已强制禁用联网搜索' })
          : webSearchBlockedBy === 'feature'
            ? t('chat.webSearchDisabledFeature', { defaultValue: '当前引擎未启用联网搜索能力' })
            : t('chat.webSearchTitle', {
                defaultValue: '联网搜索（默认关闭；开启后将把问题发往外部搜索引擎）'
              })

  return (
    <div className="flex items-center gap-1">
      <button
        type="button"
        data-testid="toggle-web-search"
        data-blocked-by={webSearchBlockedBy ?? ''}
        aria-pressed={webSearchActive}
        disabled={disabled || webSearchBlockedBy !== null}
        onClick={onToggleWebSearch}
        title={webSearchTitle}
        className={`h-8 shrink-0 flex items-center gap-1 rounded-md border px-2 text-xs transition-colors disabled:opacity-40 ${
          webSearchActive
            ? 'border-blue-500/70 bg-blue-500/15 text-blue-300'
            : 'border-neutral-800 bg-neutral-950 text-neutral-400 hover:bg-neutral-900 hover:text-neutral-200'
        }`}
      >
        <span aria-hidden="true">🌐</span>
        <span>{t('chat.webSearch', { defaultValue: '联网搜索' })}</span>
      </button>
      <button
        type="button"
        data-testid="toggle-incognito"
        aria-pressed={incognito}
        disabled={disabled}
        onClick={onToggleIncognito}
        title={t('chat.incognitoTitle', {
          defaultValue: '无痕隐私模式（关闭记忆注入、记忆抽取、联网搜索与服务端摘要）'
        })}
        className={`h-8 shrink-0 flex items-center gap-1 rounded-md border px-2 text-xs transition-colors disabled:opacity-40 ${
          incognito
            ? 'border-amber-500/70 bg-amber-500/15 text-amber-300'
            : 'border-neutral-800 bg-neutral-950 text-neutral-400 hover:bg-neutral-900 hover:text-neutral-200'
        }`}
      >
        <span aria-hidden="true">🕶</span>
        <span>{t('chat.incognito', { defaultValue: '无痕' })}</span>
      </button>
    </div>
  )
}
