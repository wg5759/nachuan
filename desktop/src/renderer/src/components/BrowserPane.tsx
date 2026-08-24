import React, { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useAppStore, type ChatDisplayMsg } from '../store'
import { agentRun, visionImage, lapianVideo } from '../api'

const HOME = 'https://www.bing.com'

/** 右栏内嵌手动浏览器 + 独立 Agent 对话。
 *  网页控制在隔离会话、动作能力和审批闭环完成前保持故障关闭；输入框仍可聊天和发图/视频。 */
export default function BrowserPane(): React.ReactNode {
  const { t } = useTranslation()
  const containerRef = useRef<HTMLDivElement>(null)
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const wvRef = useRef<any>(null)
  const fileRef = useRef<HTMLInputElement>(null)
  const msgsRef = useRef<HTMLDivElement>(null)
  const [addr, setAddr] = useState(HOME)
  const [chat, setChat] = useState('')
  const [msgs, setMsgs] = useState<ChatDisplayMsg[]>([])
  const [busy, setBusy] = useState(false)
  const [tabs, setTabs] = useState<{ id: string; url: string }[]>([{ id: 't0', url: HOME }])
  const [activeTabId, setActiveTabId] = useState('t0')
  const activeRef = useRef(activeTabId)
  activeRef.current = activeTabId

  const cycleBrowserZoom = useAppStore((s) => s.cycleBrowserZoom)
  const browserZoom = useAppStore((s) => s.browserZoom)
  const currentModel = useAppStore((s) => s.currentModel)
  const appendBrowserNote = useAppStore((s) => s.appendBrowserNote)

  useEffect(() => {
    const container = containerRef.current
    if (!container) return
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const wv: any = document.createElement('webview')
    wv.setAttribute('src', HOME)
    wv.style.width = '100%'
    wv.style.height = '100%'
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const onNav = (e: any): void => {
      if (e?.url) {
        setAddr(e.url)
        setTabs((ts) => ts.map((tb) => (tb.id === activeRef.current ? { ...tb, url: e.url } : tb)))
      }
    }
    wv.addEventListener('did-navigate', onNav)
    wv.addEventListener('did-navigate-in-page', onNav)
    container.appendChild(wv)
    wvRef.current = wv
    return () => {
      wv.removeEventListener('did-navigate', onNav)
      wv.removeEventListener('did-navigate-in-page', onNav)
      wv.remove()
    }
  }, [])

  useEffect(() => {
    const el = msgsRef.current
    if (el) el.scrollTo({ top: el.scrollHeight })
  }, [msgs])

  const navigate = (raw: string): void => {
    let target = raw.trim()
    if (!target) return
    if (!/^https?:\/\//.test(target)) target = 'https://' + target
    setAddr(target)
    setTabs((ts) => ts.map((tb) => (tb.id === activeTabId ? { ...tb, url: target } : tb)))
    wvRef.current?.loadURL?.(target)
  }

  // 轻量标签（B 方案）：共用一个 webview，切标签即换网址；仅供机主手动浏览。
  const tabTitle = (url: string): string => {
    try {
      return new URL(url).hostname.replace(/^www\./, '')
    } catch {
      return url.slice(0, 18) || 'New'
    }
  }
  const switchTab = (id: string): void => {
    const tb = tabs.find((x) => x.id === id)
    if (!tb) return
    setActiveTabId(id)
    setAddr(tb.url)
    wvRef.current?.loadURL?.(tb.url)
  }
  const newTab = (): void => {
    const id = 't' + Date.now().toString(36)
    setTabs((ts) => [...ts, { id, url: HOME }])
    setActiveTabId(id)
    setAddr(HOME)
    wvRef.current?.loadURL?.(HOME)
  }
  const closeTab = (id: string): void => {
    if (tabs.length <= 1) return
    const rest = tabs.filter((x) => x.id !== id)
    setTabs(rest)
    if (id === activeTabId) {
      const nt = rest[0]
      setActiveTabId(nt.id)
      setAddr(nt.url)
      wvRef.current?.loadURL?.(nt.url)
    }
  }

  const setLast = (patch: Partial<ChatDisplayMsg>): void =>
    setMsgs((p) => {
      const c = p.slice()
      c[c.length - 1] = { role: 'assistant', content: '', ...patch }
      return c
    })

  const sendChat = async (): Promise<void> => {
    const text = chat.trim() // 注意：用 text 而非 t，避免与 useTranslation 的 t 撞名
    if (!text || busy) return
    const history = msgs
      .filter((m) => m.content && m.content.trim())
      .map((m) => ({ role: m.role, content: m.content }))
    setChat('')
    setMsgs((p) => [...p, { role: 'user', content: text }, { role: 'assistant', content: '' }])
    setBusy(true)
    try {
      // 显式选了模型才传；否则不指定，让后端按复杂度自动路由（不再无脑用弱模型 agnes-flash）。
      const res = await agentRun(text, currentModel || undefined, { history })
      const reply = res.reply || t('browser.noOutput')
      const meta =
        t('browser.steps', { n: res.steps }) +
        (res.tool_log?.length ? t('browser.tools', { n: res.tool_log.length }) : '')
      setLast({ content: reply, meta })
      // 浏览器里干完的活，给中间当前对话留一条摘要，让中间 agent 知道发生了什么
      appendBrowserNote(t('browser.note', { task: text, result: reply.slice(0, 120) }))
    } catch (e) {
      setLast({ content: `⚠️ ${String(e)}` })
    } finally {
      setBusy(false)
    }
  }

  const onPickFile = async (f: File): Promise<void> => {
    if (busy) return
    const isImg = f.type.startsWith('image/')
    const isVid = f.type.startsWith('video/')
    if (!isImg && !isVid) {
      setMsgs((p) => [...p, { role: 'assistant', content: t('browser.pickHint') }])
      return
    }
    const preview = isImg ? URL.createObjectURL(f) : ''
    setMsgs((p) => [
      ...p,
      { role: 'user', content: isVid ? `🎬 ${f.name}` : '', images: isImg ? [preview] : undefined },
      { role: 'assistant', content: '' }
    ])
    setBusy(true)
    try {
      if (isImg) {
        setLast({ content: (await visionImage(f)) || t('browser.noVision') })
      } else {
        const r = await lapianVideo(f, { withAudio: true })
        setLast({
          content: r.report || t('browser.emptyReport'),
          meta: t('browser.lapianMeta', { n: r.frames ?? '?' })
        })
      }
    } catch (e) {
      setLast({ content: `⚠️ ${String(e)}` })
    } finally {
      setBusy(false)
    }
  }

  const zoomTitle =
    browserZoom === 'normal'
      ? t('browser.zoomWide')
      : browserZoom === 'wide'
        ? t('browser.zoomMax')
        : t('browser.zoomNormal')

  return (
    <div className="flex flex-col h-full">
      {/* 标签条（轻量标签：共用一个 webview，切换即换网址；agent 仍操作当前页） */}
      <div className="flex items-center gap-0.5 px-1 pt-1 overflow-x-auto border-b border-neutral-900">
        {tabs.map((tb) => (
          <div
            key={tb.id}
            onClick={() => switchTab(tb.id)}
            className={`group flex items-center gap-1 px-2 py-0.5 rounded-t text-xs cursor-pointer shrink-0 max-w-[130px] ${
              tb.id === activeTabId
                ? 'bg-neutral-800 text-neutral-100'
                : 'text-neutral-400 hover:bg-neutral-900'
            }`}
          >
            <span className="truncate">{tabTitle(tb.url)}</span>
            {tabs.length > 1 && (
              <button
                onClick={(e) => {
                  e.stopPropagation()
                  closeTab(tb.id)
                }}
                className="opacity-0 group-hover:opacity-100 text-neutral-500 hover:text-red-400"
              >
                ✕
              </button>
            )}
          </div>
        ))}
        <button
          onClick={newTab}
          title={t('browser.newTab')}
          className="shrink-0 px-1.5 text-neutral-400 hover:text-neutral-200"
        >
          ＋
        </button>
      </div>
      {/* 顶栏：导航 + 缩放（地址框可收缩，⛶ 固定不被长网址挤掉） */}
      <div className="p-2 flex gap-1 border-b border-neutral-800 items-center">
        <button
          onClick={() => wvRef.current?.goBack?.()}
          className="shrink-0 px-2 rounded hover:bg-neutral-800 text-neutral-300"
        >
          ←
        </button>
        <button
          onClick={() => wvRef.current?.goForward?.()}
          className="shrink-0 px-2 rounded hover:bg-neutral-800 text-neutral-300"
        >
          →
        </button>
        <button
          onClick={() => wvRef.current?.reload?.()}
          className="shrink-0 px-2 rounded hover:bg-neutral-800 text-neutral-300"
        >
          ⟳
        </button>
        <input
          value={addr}
          onChange={(e) => setAddr(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') navigate(addr)
          }}
          className="flex-1 min-w-0 bg-neutral-900 border border-neutral-700 rounded px-2 py-1 text-xs text-neutral-100"
        />
        <button
          onClick={cycleBrowserZoom}
          title={zoomTitle}
          className={`shrink-0 px-2 rounded border hover:bg-neutral-800 ${
            browserZoom !== 'normal'
              ? 'text-blue-400 border-blue-500'
              : 'text-neutral-300 border-neutral-600'
          }`}
        >
          ⛶
        </button>
      </div>

      {/* 网页 */}
      <div ref={containerRef} className="flex-1 min-h-0" />

      {/* 浏览器自带的对话记录（留在这边，不跳中间） */}
      {msgs.length > 0 && (
        <div ref={msgsRef} className="border-t border-neutral-800 max-h-52 overflow-auto p-2 space-y-2">
          {msgs.map((m, i) => (
            <div key={i} className={m.role === 'user' ? 'text-right' : 'text-left'}>
              {m.role === 'assistant' && m.meta && (
                <div className="text-[10px] text-neutral-600 mb-0.5">{m.meta}</div>
              )}
              {m.images?.map((src, j) => (
                <img key={j} src={src} alt="" className="inline-block max-w-[140px] rounded mb-1" />
              ))}
              {m.content ? (
                <div
                  className={`inline-block px-2 py-1 rounded text-sm whitespace-pre-wrap max-w-[92%] select-text ${
                    m.role === 'user' ? 'bg-blue-600 text-white' : 'bg-neutral-800 text-neutral-100'
                  }`}
                >
                  {m.content}
                </div>
              ) : (
                <span className="text-neutral-500 text-sm">…</span>
              )}
            </div>
          ))}
        </div>
      )}

      {/* 输入行：文字 + ＋发图/视频 + 发送 */}
      <div className="border-t border-amber-950 bg-amber-950/20 px-2 pt-1.5 text-[11px] text-amber-300">
        {t('browser.controlUnavailable')}
      </div>
      <div className="border-t border-neutral-800 p-2 flex gap-2 items-end">
        <textarea
          value={chat}
          onChange={(e) => setChat(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
              e.preventDefault()
              void sendChat()
            }
          }}
          rows={2}
          placeholder={t('browser.placeholder', { m: currentModel ?? t('browser.model') })}
          className="flex-1 min-w-0 resize-none bg-neutral-900 border border-neutral-700 rounded px-2 py-1 text-sm text-neutral-100"
        />
        <input
          ref={fileRef}
          type="file"
          accept="image/*,video/*"
          className="hidden"
          onChange={(e) => {
            const f = e.target.files?.[0]
            if (f) void onPickFile(f)
            e.target.value = ''
          }}
        />
        <button
          onClick={() => fileRef.current?.click()}
          disabled={busy}
          title={t('browser.fileTitle')}
          className="shrink-0 px-2 py-2 rounded border border-neutral-700 text-neutral-400 hover:bg-neutral-800 disabled:opacity-40 text-lg leading-none"
        >
          ＋
        </button>
        <button
          onClick={sendChat}
          disabled={busy || !chat.trim()}
          className="shrink-0 px-3 py-2 rounded bg-blue-600 text-white text-sm disabled:opacity-40"
        >
          {busy ? '…' : t('chat.send')}
        </button>
      </div>
    </div>
  )
}
