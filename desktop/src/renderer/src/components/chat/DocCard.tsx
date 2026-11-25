import React, { useState } from 'react'
import { useTranslation } from '../../i18n'

// 消息里的「文档卡」：紧凑显示文件名+字数，可展开预览全文、下载成 .md
export function DocCard({
  doc
}: {
  doc: { name: string; chars: number; content: string }
}): React.ReactNode {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const download = (): void => {
    const blob = new Blob([doc.content], { type: 'text/markdown;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = /\.(md|markdown|txt)$/i.test(doc.name) ? doc.name : `${doc.name}.md`
    a.click()
    setTimeout(() => URL.revokeObjectURL(url), 1000)
  }
  return (
    <div className="inline-block text-left border border-neutral-700 rounded-md bg-neutral-900 max-w-[85%] overflow-hidden align-top">
      <div className="flex items-center gap-2 px-2 py-1 text-xs">
        <span className="text-base leading-none">📄</span>
        <span className="text-neutral-200 truncate max-w-[160px]">{doc.name}</span>
        <span className="text-neutral-500 shrink-0">{t('chat.docChars', { n: doc.chars })}</span>
        <button
          onClick={() => setOpen((v) => !v)}
          className="ml-1 text-neutral-400 hover:text-neutral-100 shrink-0"
        >
          {open ? t('chat.docCollapse') : t('chat.docPreview')}
        </button>
        <button onClick={download} className="text-neutral-400 hover:text-neutral-100 shrink-0">
          {t('chat.docDownload')}
        </button>
      </div>
      {open && (
        <div className="max-h-60 overflow-auto px-2 py-1 border-t border-neutral-800 text-xs text-neutral-300 whitespace-pre-wrap select-text">
          {doc.content}
        </div>
      )}
    </div>
  )
}
