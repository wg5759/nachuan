import { readFileSync } from 'node:fs'

import { describe, expect, it, vi } from 'vitest'

import type { ChatDisplayMsg } from '../store'
import {
  createPaidVideoSubmissionGate,
  patchPaidMediaMessage,
  patchPaidMediaMessageAndFlush,
  type SetConversationMessages
} from './chat-pane-paid-media-routing'
import { observePaidMediaNearViewport } from './ChatPane'

const source = readFileSync(new URL('./ChatPane.tsx', import.meta.url), 'utf8')

function between(start: string, end: string): string {
  const from = source.indexOf(start)
  const to = source.indexOf(end, from + start.length)
  expect(from, `missing start marker: ${start}`).toBeGreaterThanOrEqual(0)
  expect(to, `missing end marker: ${end}`).toBeGreaterThan(from)
  return source.slice(from, to)
}

describe('ChatPane paid-media conversation routing', () => {
  it('admits only one paid-video submission until the active request finishes', () => {
    const transitions: boolean[] = []
    const gate = createPaidVideoSubmissionGate((active) => transitions.push(active))

    expect(gate.tryBegin()).toBe(true)
    expect(gate.tryBegin()).toBe(false)
    expect(gate.isActive()).toBe(true)
    expect(transitions).toEqual([true])

    gate.finish()
    expect(gate.isActive()).toBe(false)
    expect(transitions).toEqual([true, false])
    expect(gate.tryBegin()).toBe(true)
  })

  it('closes the paid-video gate before confirmation and disables both click and Enter resubmission', () => {
    const sendEntry = between(
      'const send = async',
      '// #12 纳川当默认大脑'
    )
    const paidGeneration = between(
      '// 生视频模型：创建任务 → 轮询进度 → 展示',
      'let imageDataUrls: string[] = []'
    )
    const composerSend = between(
      '<button\n                onClick={() => void send()}',
      '</button>',
    )

    expect(sendEntry).toContain('paidVideoSubmissionGate.isActive()')
    expect(paidGeneration).toContain('paidVideoSubmissionGate.tryBegin()')
    expect(paidGeneration.indexOf('paidVideoSubmissionGate.tryBegin()')).toBeLessThan(
      paidGeneration.indexOf('createVideo(')
    )
    expect(paidGeneration).toContain('paidVideoSubmissionGate.finish()')
    expect(composerSend).toContain('paidVideoSubmissionInFlight')
  })

  it('materializes durable media only while its element is near the viewport', () => {
    const resolver = between(
      'function useResolvedMediaSource',
      'function formatElapsed'
    )

    expect(source).toContain("rootMargin: '512px 0px'")
    expect(resolver).toContain('observePaidMediaNearViewport')
    expect(resolver).toContain('setResolved(undefined)')
    expect(resolver).toContain('releasePaidMediaAsset')
    expect(resolver).toContain('stopObserving()')
    expect(resolver).toMatch(/<img[^>]+ref=\{setTarget\}/)
    expect(resolver).toMatch(/<video[^>]+ref=\{setTarget\}/)
  })

  it('observes the exact media element with a near-viewport margin and disconnects cleanly', () => {
    const target = {} as Element
    const visibility: boolean[] = []
    const observe = vi.fn()
    const disconnect = vi.fn()
    let callback: IntersectionObserverCallback | undefined
    let options: IntersectionObserverInit | undefined
    const Observer = class {
      constructor(next: IntersectionObserverCallback, nextOptions?: IntersectionObserverInit) {
        callback = next
        options = nextOptions
      }
      observe = observe
      disconnect = disconnect
    } as unknown as typeof IntersectionObserver

    const stop = observePaidMediaNearViewport(
      target,
      (nearViewport) => visibility.push(nearViewport),
      Observer
    )
    expect(observe).toHaveBeenCalledWith(target)
    expect(options).toEqual({ rootMargin: '512px 0px' })
    callback?.(
      [{ target, isIntersecting: true } as IntersectionObserverEntry],
      {} as IntersectionObserver
    )
    callback?.(
      [{ target, isIntersecting: false } as IntersectionObserverEntry],
      {} as IntersectionObserver
    )
    expect(visibility).toEqual([true, false])
    stop()
    expect(disconnect).toHaveBeenCalledTimes(1)
  })

  it('never routes asynchronous paid image/video writes through the current conversation setter', () => {
    const paidGeneration = between(
      '// 生视频模型：创建任务 → 轮询进度 → 展示',
      'let imageDataUrls: string[] = []'
    )

    expect(paidGeneration).toContain('setConvMessages(runConvId')
    expect(paidGeneration).not.toMatch(/\bsetMessages\s*\(/)
  })

  it('keeps an awaiting-ack anchor until the exact serialized result has been read back', () => {
    const paidGeneration = between(
      '// 生视频模型：创建任务 → 轮询进度 → 展示',
      'let imageDataUrls: string[] = []'
    )

    expect(paidGeneration).toContain("phase: 'awaiting_ack'")
    expect(paidGeneration).toContain('flushAndVerifyPaidMediaResult({')
    expect(paidGeneration).toContain('{ paidMediaOperation: undefined }')
    expect(paidGeneration.indexOf("phase: 'awaiting_ack'")).toBeLessThan(
      paidGeneration.indexOf('{ paidMediaOperation: undefined }')
    )
  })

  it('registers a freshly created paid-video alias before publishing its resumable anchor', () => {
    const paidGeneration = between(
      "if (model?.modality === 'video') {",
      'let imageDataUrls: string[] = []'
    )
    const committedResult = paidGeneration.slice(
      paidGeneration.indexOf('onResultDurablyCommitted:'),
      paidGeneration.indexOf('return resultAwaitingAck')
    )

    expect(committedResult).toContain('resumedTasksRef.current.add(taskId)')
    expect(committedResult.indexOf('resumedTasksRef.current.add(taskId)')).toBeLessThan(
      committedResult.indexOf('patchPaidMediaMessage(')
    )
  })

  it('never deletes the video task anchor on poll errors, wall timeout, or remote-only success', () => {
    const paidGeneration = between(
      '// 生视频模型：创建任务 → 轮询进度 → 展示',
      'let imageDataUrls: string[] = []'
    )
    const repeatedErrors = paidGeneration.slice(
      paidGeneration.indexOf('if (pollFails >= 5)'),
      paidGeneration.indexOf('const url = paidVideoTerminalAssetUrl(st)')
    )
    const remoteOnlySuccess = paidGeneration.slice(
      paidGeneration.indexOf('const url = paidVideoTerminalAssetUrl(st)'),
      paidGeneration.indexOf('} else if (PAID_VIDEO_FAILURE_STATUSES.has(status))')
    )
    const wallTimeout = paidGeneration.slice(
      paidGeneration.indexOf('if (!done)'),
      paidGeneration.indexOf('} catch (e)', paidGeneration.indexOf('if (!done)'))
    )

    expect(repeatedErrors).not.toContain('videoTask: undefined')
    expect(repeatedErrors).toContain('Math.min(4, pollFails - 5)')
    expect(repeatedErrors).toContain('60_000')
    expect(wallTimeout).not.toContain('videoTask: undefined')
    expect(remoteOnlySuccess).toContain('paidVideoTerminalAssetUrl(st)')
    expect(remoteOnlySuccess).toContain('isDurablePaidMediaAssetRef(url)')
    expect(remoteOnlySuccess).toContain('videoTask: undefined')
    expect(paidGeneration).toContain("t('chat.videoTimeout')")
  })

  it('keeps the resumed cloud task after the 10-minute await window or poll exception', () => {
    const resumedCloudPoll = between(
      'const src = await awaitVideo(pv.model, pv.task_id',
      'const retryPaidMedia = async'
    )

    expect(resumedCloudPoll).toContain('任务编号已保留')
    expect(resumedCloudPoll).toContain('轮询暂停，任务已保留')
    expect(resumedCloudPoll).toContain('isDurablePaidMediaAssetRef(src)')
    expect(resumedCloudPoll).toContain('? { videoTask: undefined, completedAt: Date.now() }')
  })

  it('reconciles the captured conversation/message identity instead of a drifting index', () => {
    const reconcile = between(
      'const discardPaidMediaRecovery = async',
      'const send = async'
    )

    expect(reconcile).toContain('conversationId: currentConvId')
    expect(reconcile).toContain('operationId: recovery.operationId')
    expect(reconcile).toContain('messageTs: message.ts')
    expect(reconcile).not.toMatch(/\bsetMessages\s*\(/)
    expect(reconcile).not.toMatch(/next\s*\[\s*messageIndex\s*\]/)
  })

  it('keeps claim/result persistence in conversation A after the user switches to B', () => {
    const state: Record<string, ChatDisplayMsg[]> = {
      A: [
        { role: 'user', content: 'draw cat', ts: 10 },
        { role: 'assistant', content: '', ts: 10, startedAt: 10 }
      ],
      B: [
        { role: 'user', content: 'unrelated', ts: 10 },
        { role: 'assistant', content: 'B must stay unchanged', ts: 10, startedAt: 10 }
      ]
    }
    const originalB = structuredClone(state.B)
    const setConversationMessages: SetConversationMessages = (conversationId, updater) => {
      state[conversationId] =
        typeof updater === 'function' ? updater(state[conversationId]) : updater
    }
    const flush = vi.fn(() => true)
    const ack = vi.fn()
    const target = { conversationId: 'A', messageTs: 10 }

    expect(
      patchPaidMediaMessageAndFlush(
        setConversationMessages,
        target,
        {
          paidMediaOperation: {
            operationId: 'desktop-op-a',
            kind: 'image',
            model: 'image-model'
          }
        },
        flush
      )
    ).toBe(true)
    expect(state.B).toEqual(originalB)
    expect(state.A[1].paidMediaOperation?.operationId).toBe('desktop-op-a')

    const durable = patchPaidMediaMessageAndFlush(
      setConversationMessages,
      { ...target, operationId: 'desktop-op-a' },
      {
        images: ['https://media.invalid/cat.png'],
        paidMediaOperation: undefined
      },
      flush
    )
    if (durable) ack()

    expect(state.B).toEqual(originalB)
    expect(state.A[1]).toMatchObject({ images: ['https://media.invalid/cat.png'] })
    expect(flush).toHaveBeenCalledTimes(2)
    expect(flush.mock.invocationCallOrder[1]).toBeLessThan(ack.mock.invocationCallOrder[0])
  })

  it('uses ts plus operation identity when reconciliation waits and the index drifts', () => {
    const state: Record<string, ChatDisplayMsg[]> = {
      A: [
        { role: 'user', content: 'newer insertion', ts: 30 },
        { role: 'user', content: 'draw cat', ts: 20 },
        {
          role: 'assistant',
          content: 'recover A',
          ts: 20,
          paidMediaOperation: {
            operationId: 'desktop-op-a',
            kind: 'image',
            model: 'image-model'
          }
        }
      ],
      B: [
        { role: 'user', content: 'B', ts: 20 },
        {
          role: 'assistant',
          content: 'recover B',
          ts: 20,
          paidMediaOperation: {
            operationId: 'desktop-op-b',
            kind: 'image',
            model: 'image-model'
          }
        }
      ]
    }
    const originalB = structuredClone(state.B)
    const setConversationMessages: SetConversationMessages = (conversationId, updater) => {
      state[conversationId] =
        typeof updater === 'function' ? updater(state[conversationId]) : updater
    }

    expect(
      patchPaidMediaMessage(
        setConversationMessages,
        { conversationId: 'A', messageTs: 20, operationId: 'desktop-op-a' },
        (message) => ({
          ...message,
          content: `${message.content}\nreconciled`,
          paidMediaOperation: undefined
        })
      )
    ).toBe(true)
    expect(state.A[2]).toMatchObject({ content: 'recover A\nreconciled' })
    expect(state.A[2].paidMediaOperation).toBeUndefined()
    expect(state.B).toEqual(originalB)
  })

  it('does not flush or acknowledge if the captured message identity disappeared', () => {
    const messages: ChatDisplayMsg[] = [
      { role: 'assistant', content: 'replacement', ts: 20 }
    ]
    const setConversationMessages: SetConversationMessages = (_conversationId, updater) => {
      if (typeof updater === 'function') updater(messages)
    }
    const flush = vi.fn(() => true)
    const ack = vi.fn()

    const durable = patchPaidMediaMessageAndFlush(
      setConversationMessages,
      { conversationId: 'A', messageTs: 20, operationId: 'desktop-op-gone' },
      { images: ['https://media.invalid/should-not-ack.png'] },
      flush
    )
    if (durable) ack()

    expect(durable).toBe(false)
    expect(flush).not.toHaveBeenCalled()
    expect(ack).not.toHaveBeenCalled()
  })
})
