import React from 'react'
import { useTranslation } from 'react-i18next'

// 关于页：产品/公司/版权 + 中国商用合规展示（ICP 备案号 / 公安联网备案号）。
// 备案号必须在 app 内可见可查；这里集中展示，号可被选中复制。
export default function AboutPane(): React.ReactNode {
  const { t } = useTranslation()
  const rows: [string, string][] = [
    [t('about.company'), '杭州灵界科技有限公司'],
    [t('about.version'), '0.2.0 early-access'],
    [t('about.copyright'), '© 2026 杭州灵界科技有限公司'],
    [t('about.site'), '02602.com'],
    [t('about.icp'), '浙ICP备2022027681号-3'],
    [t('about.psb'), '浙公网安备33010402000555号']
  ]
  return (
    <div className="flex flex-col h-full">
      <div className="px-3 py-2 border-b border-neutral-800 text-sm font-medium">{t('about.title')}</div>
      <div className="flex-1 overflow-auto p-4">
        <div className="max-w-md mx-auto mt-6 mb-5 text-center">
          <div className="text-2xl font-semibold text-neutral-100">纳川 · Nexus</div>
          <div className="text-xs text-neutral-500 mt-1">{t('about.tagline')}</div>
        </div>
        <table className="max-w-md mx-auto">
          <tbody>
            {rows.map(([k, v]) => (
              <tr key={k}>
                <td className="text-xs text-neutral-500 pr-4 py-1.5 whitespace-nowrap align-top">{k}</td>
                <td className="text-sm text-neutral-200 py-1.5 select-text">{v}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <div className="max-w-md mx-auto mt-6 text-[11px] text-neutral-600 text-center">
          {t('about.beianNote')}
        </div>
      </div>
    </div>
  )
}
