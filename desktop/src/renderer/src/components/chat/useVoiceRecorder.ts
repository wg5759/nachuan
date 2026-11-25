import { useCallback, useEffect, useRef, useState } from 'react'
import { transcribeAudio } from '../../api'
import type { TFn } from './chatUtils'

export interface UseVoiceRecorderOptions {
  input: string
  setInput: React.Dispatch<React.SetStateAction<string>>
  t: TFn
}

export interface UseVoiceRecorderResult {
  recording: boolean
  transcribing: boolean
  micLevel: number
  toggleRecord: () => Promise<void>
}

// 语音输入：点一下开录、再点停；停止时把整段录音（完整 webm）一次性转写。
// 关键：不用 timeslice 分片——MediaRecorder 分片拼出来的 webm，ffmpeg 常无法解码。
export function useVoiceRecorder({
  input,
  setInput,
  t
}: UseVoiceRecorderOptions): UseVoiceRecorderResult {
  const [recording, setRecording] = useState(false)
  const [transcribing, setTranscribing] = useState(false)
  const [micLevel, setMicLevel] = useState(0)

  const recRef = useRef<MediaRecorder | null>(null)
  const chunksRef = useRef<Blob[]>([])
  const audioCtxRef = useRef<AudioContext | null>(null)
  const micRafRef = useRef<number | null>(null)
  const inputRef = useRef(input)
  inputRef.current = input

  const stopMicMeter = useCallback((): void => {
    if (micRafRef.current !== null) {
      cancelAnimationFrame(micRafRef.current)
      micRafRef.current = null
    }
    void audioCtxRef.current?.close().catch(() => {})
    audioCtxRef.current = null
    setMicLevel(0)
  }, [])

  const startMicMeter = useCallback(
    (stream: MediaStream): void => {
      stopMicMeter()
      const Ctx =
        window.AudioContext ||
        (window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext
      if (!Ctx) return
      const ctx = new Ctx()
      const analyser = ctx.createAnalyser()
      analyser.fftSize = 256
      ctx.createMediaStreamSource(stream).connect(analyser)
      const data = new Uint8Array(analyser.frequencyBinCount)
      const tick = (): void => {
        analyser.getByteTimeDomainData(data)
        let sum = 0
        for (const v of data) {
          const d = v - 128
          sum += d * d
        }
        setMicLevel(Math.min(1, Math.sqrt(sum / data.length) / 42))
        micRafRef.current = requestAnimationFrame(tick)
      }
      audioCtxRef.current = ctx
      tick()
    },
    [stopMicMeter]
  )

  useEffect(() => () => stopMicMeter(), [stopMicMeter])

  const toggleRecord = useCallback(async (): Promise<void> => {
    if (recording) {
      recRef.current?.stop()
      return
    }
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true })
      const rec = new MediaRecorder(stream)
      chunksRef.current = []
      startMicMeter(stream)
      const baseText = inputRef.current.trim()
      rec.ondataavailable = (ev): void => {
        if (ev.data.size) chunksRef.current.push(ev.data)
      }
      rec.onstop = async (): Promise<void> => {
        stream.getTracks().forEach((tk) => tk.stop())
        stopMicMeter()
        setRecording(false)
        if (!chunksRef.current.length) return
        const blob = new Blob(chunksRef.current, { type: rec.mimeType || 'audio/webm' })
        setTranscribing(true)
        try {
          const text = await transcribeAudio(blob)
          if (text) setInput(baseText ? `${baseText} ${text}` : text)
        } catch (e) {
          setInput((prev) => `${prev}${t('chat.sttFail', { e: String(e) })}`)
        } finally {
          setTranscribing(false)
        }
      }
      recRef.current = rec
      rec.start()
      setRecording(true)
    } catch (e) {
      setInput((prev) => `${prev}${t('chat.micFail', { e: String(e) })}`)
    }
  }, [recording, setInput, startMicMeter, stopMicMeter, t])

  return {
    recording,
    transcribing,
    micLevel,
    toggleRecord
  }
}
