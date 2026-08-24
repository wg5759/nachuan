import React, { useEffect, useRef, useState } from 'react'
import i18n from '../i18n'
import { useAppStore } from '../store'

// 顶栏自定义菜单栏（文件/编辑/功能/设置/帮助）：把原本藏在 Alt 原生菜单里的功能露到顶栏，
// 语言切换收进「设置」（不再单独占一个显眼按钮）。视图/新对话等动作渲染层直接调 store；
// 原生菜单(Alt)仍在，作为缩放/重载/开发者工具等的完整兜底。
type Item = { label: string; onClick: () => void } | 'sep'

export default function MenuBar({
  onToggleLeft,
  onToggleRight
}: {
  onToggleLeft: () => void
  onToggleRight: () => void
}): React.ReactNode {
  const setView = useAppStore((s) => s.setView)
  const newConversation = useAppStore((s) => s.newConversation)
  const openBrowser = useAppStore((s) => s.openBrowser)
  const soundEnabled = useAppStore((s) => s.soundEnabled)
  const setSoundEnabled = useAppStore((s) => s.setSoundEnabled)
  const [open, setOpen] = useState<number | null>(null)
  const ref = useRef<HTMLDivElement>(null)
  const zh = i18n.language === 'zh'

  // 打开状态时点菜单外任意处收起（截图切外部程序不误收：只监听本程序 mousedown）
  useEffect(() => {
    if (open === null) return
    const onDown = (e: MouseEvent): void => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(null)
    }
    document.addEventListener('mousedown', onDown)
    return () => document.removeEventListener('mousedown', onDown)
  }, [open])

  const newChat = (kind: 'chat' | 'code' | 'browser'): void => {
    newConversation(kind)
    setView('chat')
    if (kind === 'browser') openBrowser()
  }
  const toggleLang = (): void => {
    const next = i18n.language === 'zh' ? 'en' : 'zh'
    void i18n.changeLanguage(next)
    window.api.setLang(next)
  }

  const menus: { title: string; items: Item[] }[] = [
    {
      title: zh ? '文件' : 'File',
      items: [
        { label: zh ? '新对话' : 'New Chat', onClick: () => newChat('chat') },
        { label: zh ? '新代码对话' : 'New Code Chat', onClick: () => newChat('code') },
        { label: zh ? '新浏览器对话' : 'New Browser Chat', onClick: () => newChat('browser') },
        'sep',
        { label: zh ? '连接中心' : 'Connections', onClick: () => setView('connections') },
        { label: zh ? '同步' : 'Sync', onClick: () => setView('sync') }
      ]
    },
    {
      title: zh ? '编辑' : 'Edit',
      items: [
        { label: zh ? '复制' : 'Copy', onClick: () => document.execCommand('copy') },
        { label: zh ? '粘贴' : 'Paste', onClick: () => document.execCommand('paste') },
        { label: zh ? '全选' : 'Select All', onClick: () => document.execCommand('selectAll') }
      ]
    },
    {
      title: zh ? '功能' : 'Features',
      items: [
        { label: zh ? '🔌 模型接入（连接中心）' : '🔌 Connect Models', onClick: () => setView('connections') },
        'sep',
        { label: zh ? '对话' : 'Chat', onClick: () => setView('chat') },
        { label: zh ? '知识库' : 'Knowledge', onClick: () => setView('kb') },
        { label: zh ? '视频工作室' : 'Studio', onClick: () => setView('studio') },
        { label: zh ? '媒体库' : 'Media', onClick: () => setView('media') },
        { label: zh ? '工具 (MCP)' : 'Tools (MCP)', onClick: () => setView('mcp') },
        { label: zh ? '编排' : 'Orchestrate', onClick: () => setView('orchestrate') },
        { label: zh ? '用量' : 'Usage', onClick: () => setView('usage') },
        { label: zh ? '智能大脑' : 'Agent Brain', onClick: () => setView('brain') }
      ]
    },
    {
      title: zh ? '设置' : 'Settings',
      items: [
        { label: zh ? '语言：中文 → English' : 'Language: English → 中文', onClick: toggleLang },
        {
          label:
            (soundEnabled ? '✓ ' : '　') +
            (zh ? '完成提示音' : 'Completion sound'),
          onClick: () => setSoundEnabled(!soundEnabled)
        },
        'sep',
        { label: zh ? '切换左栏' : 'Toggle Sidebar', onClick: onToggleLeft },
        { label: zh ? '切换浏览器栏' : 'Toggle Browser', onClick: onToggleRight }
      ]
    },
    {
      title: zh ? '帮助' : 'Help',
      items: [{ label: zh ? '关于' : 'About', onClick: () => setView('about') }]
    }
  ]

  return (
    <div ref={ref} className="flex items-center">
      {menus.map((m, i) => (
        <div key={i} className="relative">
          <button
            type="button"
            onClick={() => setOpen(open === i ? null : i)}
            // 按住不夺输入框焦点 → 「编辑」的复制/粘贴/全选 execCommand 才能作用到 textarea 选区
            onMouseDown={(e) => e.preventDefault()}
            onMouseEnter={() => open !== null && setOpen(i)}
            className={`rounded px-2 py-1 text-sm text-neutral-300 ${
              open === i ? 'bg-neutral-800 text-neutral-100' : 'hover:bg-neutral-800'
            }`}
          >
            {m.title}
          </button>
          {open === i && (
            <div className="absolute left-0 top-full z-50 mt-1 min-w-[190px] rounded-md border border-neutral-700 bg-neutral-950 py-1 shadow-xl">
              {m.items.map((it, j) =>
                it === 'sep' ? (
                  <div key={j} className="my-1 border-t border-neutral-800" />
                ) : (
                  <button
                    key={j}
                    type="button"
                    onClick={() => {
                      it.onClick()
                      setOpen(null)
                    }}
                    onMouseDown={(e) => e.preventDefault()} // 保住输入框焦点，编辑项 execCommand 才生效
                    className="block w-full text-left px-3 py-1.5 text-sm text-neutral-200 hover:bg-neutral-800"
                  >
                    {it.label}
                  </button>
                )
              )}
            </div>
          )}
        </div>
      ))}
    </div>
  )
}
