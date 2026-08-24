import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { visionImage } from '../api'

// 自制「微信式」截图浮层：冻结当前屏 → 拖拽框选 → 选区下方弹出工具条
//   提取文字 / 翻译：就地在浮层调看图模型，结果显示在「衍生结果框」里（可选中、可复制），浮层不关闭
//   嵌入对话：把选区图贴进主窗口输入框（暂存，补文字再发）；取消/Esc 关闭
interface Bg {
  dataUrl: string
  width: number
  height: number
}
interface Rect {
  x: number
  y: number
  w: number
  h: number
}
interface Panel {
  kind: 'ocr' | 'translate'
  loading: boolean
  text: string
  error: string
}

export default function SnipOverlay(): JSX.Element {
  const { t } = useTranslation()
  const [bg, setBg] = useState<Bg | null>(null)
  const [rect, setRect] = useState<Rect | null>(null)
  const [done, setDone] = useState(false) // 选区已确定 → 显示工具条
  const [panel, setPanel] = useState<Panel | null>(null) // 提取文字/翻译的衍生结果框
  const startRef = useRef<{ x: number; y: number } | null>(null)
  const imgRef = useRef<HTMLImageElement | null>(null)

  useEffect(() => {
    // 让浮层窗口真正透明（盖掉 index.css 的深色底）
    document.documentElement.style.background = 'transparent'
    document.body.style.background = 'transparent'
    document.body.style.margin = '0'
    void window.api.snipBg().then((b) => b && setBg(b))
    const onKey = (e: KeyboardEvent): void => {
      if (e.key === 'Escape') void window.api.snipCancel()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  const onDown = (e: React.MouseEvent): void => {
    startRef.current = { x: e.clientX, y: e.clientY }
    setDone(false)
    setPanel(null)
    setRect({ x: e.clientX, y: e.clientY, w: 0, h: 0 })
  }
  const onMove = (e: React.MouseEvent): void => {
    const s = startRef.current
    if (!s) return
    setRect({
      x: Math.min(s.x, e.clientX),
      y: Math.min(s.y, e.clientY),
      w: Math.abs(e.clientX - s.x),
      h: Math.abs(e.clientY - s.y)
    })
  }
  const onUp = (): void => {
    if (!startRef.current) return
    startRef.current = null
    setRect((r) => {
      if (r && r.w > 4 && r.h > 4) {
        setDone(true)
        return r
      }
      return null
    })
  }

  // 把 CSS 选区映射回原始截图像素裁切（保证清晰，含高 DPI 缩放）
  const cropDataUrl = (): string => {
    const img = imgRef.current
    if (!img || !bg || !rect) return ''
    const rx = bg.width / window.innerWidth
    const ry = bg.height / window.innerHeight
    const cv = document.createElement('canvas')
    cv.width = Math.max(1, Math.round(rect.w * rx))
    cv.height = Math.max(1, Math.round(rect.h * ry))
    const ctx = cv.getContext('2d')
    if (!ctx) return ''
    ctx.drawImage(img, rect.x * rx, rect.y * ry, rect.w * rx, rect.h * ry, 0, 0, cv.width, cv.height)
    return cv.toDataURL('image/png')
  }

  // 嵌入对话：把选区图回传主窗口（暂存进输入框），关闭浮层
  const embed = (): void => {
    const dataUrl = cropDataUrl()
    if (!dataUrl) return void window.api.snipCancel()
    void window.api.snipDone({ dataUrl, action: 'paste' })
  }
  // 复制图到剪贴板 / 存成 PNG —— 拿去发给别的程序
  const copyImg = (): void => {
    const dataUrl = cropDataUrl()
    if (!dataUrl) return void window.api.snipCancel()
    void window.api.snipDone({ dataUrl, action: 'copy' })
  }
  const saveImg = (): void => {
    const dataUrl = cropDataUrl()
    if (!dataUrl) return void window.api.snipCancel()
    void window.api.snipDone({ dataUrl, action: 'save' })
  }

  // 提取文字 / 翻译：就地调看图模型，结果进衍生框
  const runVision = async (kind: 'ocr' | 'translate'): Promise<void> => {
    const dataUrl = cropDataUrl()
    if (!dataUrl) return
    setPanel({ kind, loading: true, text: '', error: '' })
    try {
      const blob = await (await fetch(dataUrl)).blob()
      const q =
        kind === 'translate'
          ? '识别图片中的文字并翻译：中文→英文，其它语言→中文，只输出译文，不要解释'
          : '提取图片中的所有文字，原样输出、保留换行，不要翻译、不要解释'
      const text = (await visionImage(blob, q)).trim()
      setPanel({ kind, loading: false, text, error: '' })
    } catch (e) {
      setPanel({ kind, loading: false, text: '', error: String(e) })
    }
  }

  const copyText = async (): Promise<void> => {
    const txt = panel?.text
    if (!txt) return
    try {
      await navigator.clipboard.writeText(txt)
    } catch {
      // 退化路径：execCommand
      const ta = document.createElement('textarea')
      ta.value = txt
      document.body.appendChild(ta)
      ta.select()
      document.execCommand('copy')
      ta.remove()
    }
  }

  // bg 未就绪：渲染极简占位（此时窗口仍隐藏，用户看不到）
  if (!bg) return <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.2)' }} />

  // 工具条位置：默认选区正下方，贴底则翻到上方；水平方向避免越界
  const barTop = rect
    ? rect.y + rect.h + 8 + 44 < window.innerHeight
      ? rect.y + rect.h + 8
      : Math.max(8, rect.y - 44)
    : 0
  const barLeft = rect ? Math.min(Math.max(8, rect.x), window.innerWidth - 520) : 0
  // 结果框：工具条下方，整体夹在屏内
  const panelTop = Math.min(Math.max(8, barTop + 44), window.innerHeight - 250)
  const panelLeft = rect ? Math.min(Math.max(8, rect.x), window.innerWidth - 440) : 0
  const panelWidth = rect ? Math.min(Math.max(rect.w, 300), 460) : 360

  const btn: React.CSSProperties = {
    padding: '6px 10px',
    fontSize: 13,
    color: '#e5e5e5',
    background: 'transparent',
    border: 'none',
    borderRadius: 6,
    cursor: 'pointer',
    whiteSpace: 'nowrap'
  }

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        cursor: 'crosshair',
        userSelect: 'none',
        overflow: 'hidden'
      }}
      onMouseDown={onDown}
      onMouseMove={onMove}
      onMouseUp={onUp}
    >
      <img
        ref={imgRef}
        src={bg.dataUrl}
        draggable={false}
        style={{ position: 'absolute', inset: 0, width: '100vw', height: '100vh', display: 'block' }}
        onLoad={() => void window.api.snipReady()}
      />
      {/* 选区高亮：用超大 box-shadow 把选区以外压暗，选区内保持清晰 */}
      {rect && (
        <div
          style={{
            position: 'absolute',
            left: rect.x,
            top: rect.y,
            width: rect.w,
            height: rect.h,
            boxShadow: '0 0 0 9999px rgba(0,0,0,0.45)',
            border: '1.5px solid #3b82f6',
            pointerEvents: 'none'
          }}
        />
      )}
      {/* 未开始框选：整屏轻压暗 + 顶部提示 */}
      {!rect && (
        <>
          <div
            style={{
              position: 'absolute',
              inset: 0,
              background: 'rgba(0,0,0,0.3)',
              pointerEvents: 'none'
            }}
          />
          <div
            style={{
              position: 'absolute',
              top: 18,
              left: 0,
              right: 0,
              textAlign: 'center',
              color: '#fff',
              fontSize: 13,
              textShadow: '0 1px 3px #000',
              pointerEvents: 'none'
            }}
          >
            {t('chat.snipHint')}
          </div>
        </>
      )}
      {/* 选区尺寸标签 */}
      {rect && rect.w > 0 && (
        <div
          style={{
            position: 'absolute',
            left: rect.x,
            top: Math.max(2, rect.y - 20),
            color: '#fff',
            fontSize: 11,
            background: 'rgba(0,0,0,0.6)',
            padding: '1px 6px',
            borderRadius: 4,
            pointerEvents: 'none'
          }}
        >
          {Math.round(rect.w)} × {Math.round(rect.h)}
        </div>
      )}
      {/* 选区工具条 */}
      {done && rect && (
        <div
          style={{
            position: 'absolute',
            top: barTop,
            left: barLeft,
            display: 'flex',
            gap: 2,
            padding: 4,
            background: 'rgba(23,23,23,0.96)',
            border: '1px solid #333',
            borderRadius: 8,
            boxShadow: '0 6px 24px rgba(0,0,0,0.5)'
          }}
          onMouseDown={(e) => e.stopPropagation()}
        >
          <button style={{ ...btn, color: '#60a5fa' }} onClick={() => void runVision('ocr')}>
            📝 {t('chat.snipOcr')}
          </button>
          <button style={{ ...btn, color: '#60a5fa' }} onClick={() => void runVision('translate')}>
            🌐 {t('chat.snipTranslate')}
          </button>
          <span style={{ width: 1, background: '#3a3a3a', margin: '4px 2px' }} />
          <button style={btn} onClick={embed}>
            💬 {t('chat.snipPaste')}
          </button>
          <button style={btn} onClick={copyImg}>
            📋 {t('chat.snipCopy')}
          </button>
          <button style={{ ...btn, display: 'inline-flex', alignItems: 'center', gap: 4 }} onClick={saveImg}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
              <path d="m7 10 5 5 5-5" />
              <path d="M12 15V3" />
            </svg>
            {t('chat.snipSave')}
          </button>
          <button style={{ ...btn, color: '#a3a3a3' }} onClick={() => void window.api.snipCancel()}>
            ✕ {t('chat.snipCancel')}
          </button>
        </div>
      )}
      {/* 衍生结果框：提取文字 / 翻译 的文本，可选中、可复制 */}
      {panel && (
        <div
          style={{
            position: 'absolute',
            top: panelTop,
            left: panelLeft,
            width: panelWidth,
            maxHeight: 240,
            display: 'flex',
            flexDirection: 'column',
            background: 'rgba(23,23,23,0.98)',
            border: '1px solid #3b82f6',
            borderRadius: 8,
            boxShadow: '0 8px 30px rgba(0,0,0,0.6)'
          }}
          onMouseDown={(e) => e.stopPropagation()}
        >
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '6px 8px',
              borderBottom: '1px solid #333'
            }}
          >
            <span style={{ fontSize: 12, color: '#60a5fa' }}>
              {panel.kind === 'translate' ? `🌐 ${t('chat.snipTranslate')}` : `📝 ${t('chat.snipOcr')}`}
            </span>
            <div style={{ display: 'flex', gap: 4 }}>
              <button
                style={{ ...btn, padding: '2px 8px', fontSize: 12, color: '#e5e5e5', opacity: panel.text ? 1 : 0.4 }}
                disabled={!panel.text}
                onClick={() => void copyText()}
              >
                {t('chat.snipCopy')}
              </button>
              <button
                style={{ ...btn, padding: '2px 8px', fontSize: 12, color: '#a3a3a3' }}
                onClick={() => setPanel(null)}
              >
                ✕
              </button>
            </div>
          </div>
          <div
            style={{
              overflow: 'auto',
              padding: '8px 10px',
              fontSize: 13,
              lineHeight: 1.5,
              color: panel.error ? '#f87171' : '#e5e5e5',
              whiteSpace: 'pre-wrap',
              userSelect: 'text',
              cursor: 'text'
            }}
          >
            {panel.loading
              ? panel.kind === 'translate'
                ? t('chat.snipTranslating')
                : t('chat.snipOcring')
              : panel.error
                ? panel.error
                : panel.text || t('chat.noVision')}
          </div>
        </div>
      )}
    </div>
  )
}
