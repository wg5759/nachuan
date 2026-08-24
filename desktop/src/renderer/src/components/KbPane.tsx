import React, { useEffect, useState } from 'react'
import { type KbDoc, type KbSource, deleteKbDoc, fetchKbDocs, importKbDoc, queryKb } from '../api'
import { subscribeKnowledgeDocumentsChanged } from '../knowledge-refresh'
import { isTextAttachmentFile } from '../utils/attachments'

const KB_TEXT_FILE_ACCEPT =
  'text/*,.md,.markdown,.txt,.csv,.tsv,.json,.log,.yml,.yaml,.ini,.toml,.xml,.html,.htm,.tex,.rtf,.srt,.vtt'
const MAX_KB_TEXT_FILE_BYTES = 4 * 1024 * 1024

interface KbTextFileInput {
  name: string
  type: string
  size: number
  text: () => Promise<string>
}

export async function prepareKbTextFile(
  file: KbTextFileInput
): Promise<{ title: string; text: string }> {
  if (!isTextAttachmentFile(file)) throw new Error('只支持文本、Markdown、CSV 和字幕文件')
  if (
    !Number.isSafeInteger(file.size) ||
    file.size < 0 ||
    file.size > MAX_KB_TEXT_FILE_BYTES
  ) {
    throw new Error('本地文本文件不能超过 4MB')
  }
  return { title: file.name, text: await file.text() }
}

// 知识库（IMA）：导入文档 → 据实带引用问答 → 文档列表（中文优先；i18n 归英文第2批）
export default function KbPane(): React.ReactNode {
  const [docs, setDocs] = useState<KbDoc[]>([])
  const [title, setTitle] = useState('')
  const [text, setText] = useState('')
  const [query, setQuery] = useState('')
  const [answer, setAnswer] = useState('')
  const [sources, setSources] = useState<KbSource[]>([])
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState('')

  const load = async (): Promise<void> => {
    try {
      setDocs(await fetchKbDocs())
    } catch {
      /* 引擎离线时忽略 */
    }
  }
  useEffect(() => {
    void load()
    return subscribeKnowledgeDocumentsChanged(() => {
      void load()
    })
  }, [])

  const onPickLocalFile = async (file: File | undefined): Promise<void> => {
    if (!file) return
    setBusy(true)
    setMsg('')
    try {
      const prepared = await prepareKbTextFile(file)
      setTitle(prepared.title)
      setText(prepared.text)
      setMsg(`已读取「${prepared.title}」，请确认内容后点击导入。`)
    } catch (error) {
      setMsg(`读取失败：${String(error)}`)
    } finally {
      setBusy(false)
    }
  }

  const onImport = async (): Promise<void> => {
    if (!text.trim()) return
    setBusy(true)
    setMsg('')
    try {
      const r = await importKbDoc(title || '未命名', text)
      setMsg(`已导入「${title || '未命名'}」，切了 ${r.chunks} 块`)
      setTitle('')
      setText('')
      await load()
    } catch (e) {
      setMsg('导入失败：' + String(e))
    } finally {
      setBusy(false)
    }
  }

  const onDelete = async (id: number): Promise<void> => {
    try {
      const result = await deleteKbDoc(id)
      if (result.needs_approval) {
        setMsg(`删除请求已送审（${String(result.approval_id ?? '-')}），批准后才会删除。`)
        return
      }
      await load()
    } catch (error) {
      setMsg(`删除失败：${String(error)}`)
    }
  }

  const onQuery = async (): Promise<void> => {
    if (!query.trim()) return
    setBusy(true)
    setAnswer('')
    setSources([])
    try {
      const r = await queryKb(query)
      setAnswer(r.answer)
      setSources(r.sources)
    } catch (e) {
      setAnswer('查询失败：' + String(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex flex-col h-full overflow-auto">
      <div className="px-3 py-2 border-b border-neutral-800 text-sm font-medium">
        📚 知识库（导入文档，据实带引用回答）
      </div>
      <div className="p-3 space-y-4">
        <section className="space-y-2">
          <div className="flex gap-2">
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') void onQuery()
              }}
              placeholder="问知识库里的内容…"
              className="flex-1 px-2 py-1.5 rounded bg-neutral-950 border border-neutral-700 text-sm"
            />
            <button
              onClick={() => void onQuery()}
              disabled={busy || !query.trim()}
              className="px-3 rounded bg-blue-600 hover:bg-blue-500 disabled:opacity-40 text-sm"
            >
              问
            </button>
          </div>
          {answer && (
            <div className="rounded border border-neutral-800 bg-neutral-900/50 p-3 text-sm whitespace-pre-wrap">
              {answer}
              {sources.length > 0 && (
                <div className="mt-2 pt-2 border-t border-neutral-800 text-xs text-neutral-500">
                  来源：{sources.map((s, i) => `[${i + 1}] ${s.title}`).join('  ')}
                </div>
              )}
            </div>
          )}
        </section>

        <section className="space-y-2 border border-neutral-800 rounded-lg p-3 bg-neutral-900/30">
          <div className="text-sm font-medium">导入文档</div>
          <input
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="标题（如：公司报销规定）"
            className="w-full px-2 py-1 rounded bg-neutral-950 border border-neutral-700 text-sm"
          />
          <div className="flex flex-wrap items-center gap-2">
            <label className="cursor-pointer rounded border border-neutral-700 px-3 py-1 text-sm text-neutral-200 hover:bg-neutral-800">
              选择本地文本文件
              <input
                type="file"
                accept={KB_TEXT_FILE_ACCEPT}
                className="hidden"
                disabled={busy}
                onChange={(event) => {
                  const file = event.target.files?.[0]
                  void onPickLocalFile(file)
                  event.target.value = ''
                }}
              />
            </label>
            <span className="text-xs text-neutral-500">选择后只预填，确认内容后才会导入。</span>
          </div>
          <textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder="粘贴文档内容…"
            rows={6}
            className="w-full px-2 py-1 rounded bg-neutral-950 border border-neutral-700 text-sm resize-y"
          />
          <div className="flex items-center gap-2">
            <button
              onClick={() => void onImport()}
              disabled={busy || !text.trim()}
              className="px-3 py-1 rounded bg-blue-600 hover:bg-blue-500 disabled:opacity-40 text-sm"
            >
              导入
            </button>
            {msg && <span className="text-xs text-neutral-400">{msg}</span>}
          </div>
        </section>

        <section className="space-y-1">
          <div className="text-xs uppercase tracking-wide text-neutral-500">已收录 · {docs.length}</div>
          {docs.map((d) => (
            <div
              key={d.id}
              className="flex items-center justify-between text-sm py-1 border-b border-neutral-800/50"
            >
              <span className="truncate">
                {d.title}
                <span className="text-neutral-600 text-xs ml-2">{d.chunks} 块</span>
              </span>
              <button
                onClick={() => void onDelete(d.id)}
                className="px-2 text-xs text-red-400 hover:text-red-300"
              >
                删除
              </button>
            </div>
          ))}
          {docs.length === 0 && (
            <div className="text-xs text-neutral-600">还没有文档，导入一篇试试。</div>
          )}
        </section>
      </div>
    </div>
  )
}
