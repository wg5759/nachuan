import React, { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { lapianVideo, lapianUrl, visionImage, type LapianResult } from '../api'
import StudioPane from './StudioPane'

// 媒体工坊（无缝一处）：拉片（视频/网址→报告）+ 看图/OCR + 视频工作室（生成）。
export default function MediaPane(): React.ReactNode {
  const { t } = useTranslation()
  const [tab, setTab] = useState<'lapian' | 'vision' | 'studio'>('lapian')
  const [url, setUrl] = useState('')
  const [busy, setBusy] = useState(false)
  const [report, setReport] = useState('')
  const [meta, setMeta] = useState('')

  const onVideo = async (f: File): Promise<void> => {
    setBusy(true)
    setReport('')
    setMeta(t('media.lapianRunning'))
    try {
      const r: LapianResult = await lapianVideo(f, { withAudio: true })
      setMeta(
        t('media.meta', {
          frames: r.frames ?? '?',
          vision: r.vision_model ?? '?',
          synth: r.synth_model ?? '?'
        }) + (r.has_transcript ? t('media.withTranscript') : '')
      )
      setReport(r.report || t('media.emptyReport'))
    } catch (e) {
      setMeta(t('media.failed', { e: String(e) }))
    } finally {
      setBusy(false)
    }
  }

  const onImage = async (f: File): Promise<void> => {
    setBusy(true)
    setReport('')
    setMeta(t('media.visionRunning'))
    try {
      setReport((await visionImage(f)) || t('media.noVision'))
      setMeta('')
    } catch (e) {
      setMeta(t('media.failed', { e: String(e) }))
    } finally {
      setBusy(false)
    }
  }

  const onUrl = async (): Promise<void> => {
    if (!url.trim()) return
    setBusy(true)
    setReport('')
    setMeta(t('media.lapianRunning'))
    try {
      const r: LapianResult = await lapianUrl(url.trim())
      setMeta(
        t('media.meta', {
          frames: r.frames ?? '?',
          vision: r.vision_model ?? '?',
          synth: r.synth_model ?? '?'
        }) + (r.has_transcript ? t('media.withTranscript') : '')
      )
      setReport(r.report || t('media.emptyReport'))
    } catch (e) {
      setMeta(t('media.failed', { e: String(e) }))
    } finally {
      setBusy(false)
    }
  }

  const Tab = ({
    k,
    label
  }: {
    k: 'lapian' | 'vision' | 'studio'
    label: string
  }): React.ReactNode => (
    <button
      onClick={() => setTab(k)}
      className={`px-2 py-1 rounded ${tab === k ? 'bg-neutral-800 text-neutral-100' : 'text-neutral-500 hover:bg-neutral-900'}`}
    >
      {label}
    </button>
  )

  return (
    <div className="flex flex-col h-full">
      <div className="px-3 py-2 border-b border-neutral-800 flex items-center gap-2 text-sm">
        <Tab k="lapian" label={t('media.tabLapian')} />
        <Tab k="vision" label={t('media.tabVision')} />
        <Tab k="studio" label="🎬 视频工作室" />
      </div>
      {tab === 'studio' ? (
        <div className="flex-1 overflow-hidden">
          <StudioPane />
        </div>
      ) : (
        <>
          <div className="p-3 space-y-2">
            {tab === 'lapian' && (
              <div className="flex gap-2">
                <input
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') void onUrl()
                  }}
                  placeholder="粘贴视频网址（YouTube/抖音/B站…全球任意）→ 拉解析报告"
                  className="flex-1 px-2 py-1.5 rounded bg-neutral-950 border border-neutral-700 text-sm"
                />
                <button
                  onClick={() => void onUrl()}
                  disabled={busy || !url.trim()}
                  className="px-3 rounded bg-blue-600 hover:bg-blue-500 disabled:opacity-40 text-sm whitespace-nowrap"
                >
                  拉片
                </button>
              </div>
            )}
            <label className="block border border-dashed border-neutral-700 rounded p-5 text-center text-sm text-neutral-400 cursor-pointer hover:bg-neutral-900">
              {tab === 'lapian' ? t('media.pickVideo') + '（或上面贴网址）' : t('media.pickImage')}
              <input
                type="file"
                accept={tab === 'lapian' ? 'video/*' : 'image/*'}
                className="hidden"
                disabled={busy}
                onChange={(ev) => {
                  const f = ev.target.files?.[0]
                  if (f) void (tab === 'lapian' ? onVideo(f) : onImage(f))
                  ev.target.value = ''
                }}
              />
            </label>
            {meta && <div className="text-xs text-neutral-500">{meta}</div>}
          </div>
          <div className="flex-1 overflow-auto px-3 pb-3">
            {report && (
              <pre className="whitespace-pre-wrap break-words text-sm text-neutral-200 font-sans leading-relaxed">
                {report}
              </pre>
            )}
          </div>
        </>
      )}
    </div>
  )
}
