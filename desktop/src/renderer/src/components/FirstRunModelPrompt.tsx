import React from 'react'
import { useTranslation } from 'react-i18next'

export function FirstRunModelPrompt({
  onConnect
}: {
  onConnect: () => void
}): React.ReactNode {
  const { t } = useTranslation()
  return (
    <div className="max-w-md rounded-2xl border border-blue-900/70 bg-blue-950/25 p-5 text-left shadow-lg">
      <div className="text-xs font-medium uppercase tracking-wider text-blue-300">
        {t('firstRun.eyebrow')}
      </div>
      <div className="mt-2 text-lg font-semibold text-neutral-100">
        {t('firstRun.title')}
      </div>
      <div className="mt-2 text-sm leading-6 text-neutral-400">{t('firstRun.hint')}</div>
      <ol className="mt-4 grid gap-2 text-sm text-neutral-300">
        <li>1. {t('firstRun.stepEngine')}</li>
        <li className="text-blue-200">2. {t('firstRun.stepModel')}</li>
        <li className="text-neutral-500">3. {t('firstRun.stepChat')}</li>
      </ol>
      <button
        type="button"
        onClick={onConnect}
        className="mt-5 w-full rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500"
      >
        {t('firstRun.connectModel')}
      </button>
    </div>
  )
}
