import React, { useEffect, useRef, useState } from 'react'

export interface DropdownOption {
  value: string
  label: string
  desc?: string
  group?: string
}

/** 自定义下拉框：只在「点本程序内部的别处」时收起；切到微信等外部程序截图不会收（不监听 window blur）。
 *  这是原生 <select> 做不到的——原生下拉失焦必关。 */
export default function Dropdown({
  value,
  options,
  onChange,
  disabled,
  title,
  className
}: {
  value: string
  options: DropdownOption[]
  onChange: (v: string) => void
  disabled?: boolean
  title?: string
  className?: string
}): React.ReactNode {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    // 只监听本程序内部的 mousedown：点应用内别处才收；切到外部程序（无 mousedown）保持打开
    const onDown = (e: MouseEvent): void => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', onDown)
    return () => document.removeEventListener('mousedown', onDown)
  }, [open])

  const cur = options.find((o) => o.value === value)
  const groups: Record<string, DropdownOption[]> = {}
  for (const o of options) {
    const g = o.group || ''
    ;(groups[g] ||= []).push(o)
  }

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        disabled={disabled}
        title={title}
        onClick={() => setOpen((o) => !o)}
        className={`bg-neutral-900 border border-neutral-700 rounded px-2 py-1 text-sm flex items-center gap-1 disabled:opacity-40 ${className ?? ''}`}
      >
        <span className="truncate max-w-[180px]">{cur?.label || value || '—'}</span>
        <span className="text-neutral-500 text-[10px]">▾</span>
      </button>
      {open && !disabled && (
        <div className="absolute left-0 top-full z-50 mt-1 min-w-[230px] max-h-80 overflow-auto bg-neutral-900 border border-neutral-700 rounded shadow-xl py-1">
          {Object.entries(groups).map(([g, opts]) => (
            <div key={g}>
              {g && <div className="px-2 pt-1.5 pb-0.5 text-[10px] text-neutral-500">{g}</div>}
              {opts.map((o) => (
                <button
                  key={o.value}
                  type="button"
                  onClick={() => {
                    onChange(o.value)
                    setOpen(false)
                  }}
                  className="block w-full text-left px-3 py-1 hover:bg-neutral-800"
                >
                  <div className={`text-sm ${o.value === value ? 'text-blue-400' : 'text-neutral-100'}`}>
                    {o.label}
                  </div>
                  {o.desc && (
                    <div className="text-[10px] text-neutral-500 leading-tight">{o.desc}</div>
                  )}
                </button>
              ))}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
