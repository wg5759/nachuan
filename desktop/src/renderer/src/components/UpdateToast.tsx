import React, { useEffect, useState } from 'react'
import i18n from '../i18n'
import type { DesktopUpdateState } from '../env'

const disabled: DesktopUpdateState = { phase: 'disabled', reason: 'not-configured' }

export default function UpdateToast(): React.ReactNode {
  const [state, setState] = useState<DesktopUpdateState>(disabled)
  const [dismissedVersion, setDismissedVersion] = useState('')
  const zh = i18n.language.toLowerCase().startsWith('zh')

  useEffect(() => {
    let active = true
    void window.api.getUpdateState().then((next) => {
      if (active) setState(next)
    })
    const unsubscribe = window.api.onUpdateState((next) => {
      setState(next)
      if (next.phase !== 'ready') setDismissedVersion('')
    })
    return () => {
      active = false
      unsubscribe()
    }
  }, [])

  if (state.phase === 'disabled') return null
  if (state.phase === 'ready' && state.version === dismissedVersion) return null

  const check = (): void => {
    void window.api.checkForUpdates().then(setState)
  }
  const install = (): void => {
    void window.api.installVerifiedUpdate().then((result) => {
      if (!result.ok) setState({ phase: 'blocked', reason: 'security' })
    })
  }

  if (state.phase === 'idle') {
    return (
      <button
        type="button"
        onClick={check}
        className="fixed right-3 bottom-3 z-[80] rounded-md border border-neutral-700 bg-neutral-900/90 px-3 py-1.5 text-xs text-neutral-300 shadow-lg hover:bg-neutral-800"
      >
        {zh ? '检查更新' : 'Check for updates'}
      </button>
    )
  }

  const securityBlocked = state.phase === 'blocked' && state.reason === 'security'
  const title =
    state.phase === 'ready'
      ? zh
        ? `纳川 ${state.version || ''} 已安全下载`
        : `Nachuan ${state.version || ''} is verified`
      : state.phase === 'downloading'
        ? zh
          ? '正在下载更新…'
          : 'Downloading update…'
        : state.phase === 'checking'
          ? zh
            ? '正在检查更新…'
            : 'Checking for updates…'
          : state.phase === 'installing'
            ? zh
              ? '正在重启并安装…'
              : 'Restarting to install…'
            : securityBlocked
              ? zh
                ? '更新安全校验失败，已阻止安装'
                : 'Update security verification failed; install blocked'
              : zh
                ? '暂时无法检查更新'
                : 'Unable to check for updates right now'

  return (
    <div className="fixed right-4 top-14 z-[80] w-[340px] rounded-lg border border-neutral-700 bg-neutral-900 p-4 text-sm text-neutral-100 shadow-2xl">
      <div className="font-medium">{title}</div>
      {state.phase === 'ready' && (
        <div className="mt-3 flex justify-end gap-2">
          <button
            type="button"
            onClick={() => setDismissedVersion(state.version || 'unknown')}
            className="rounded border border-neutral-600 px-3 py-1.5 text-neutral-300 hover:bg-neutral-800"
          >
            {zh ? '稍后' : 'Later'}
          </button>
          <button
            type="button"
            onClick={install}
            className="rounded bg-blue-600 px-3 py-1.5 text-white hover:bg-blue-500"
          >
            {zh ? '立即重启安装' : 'Restart and install'}
          </button>
        </div>
      )}
      {state.phase === 'blocked' && (
        <div className="mt-3 flex justify-end">
          <button
            type="button"
            onClick={check}
            className="rounded border border-neutral-600 px-3 py-1.5 text-neutral-200 hover:bg-neutral-800"
          >
            {zh ? '重新检查' : 'Try again'}
          </button>
        </div>
      )}
    </div>
  )
}
