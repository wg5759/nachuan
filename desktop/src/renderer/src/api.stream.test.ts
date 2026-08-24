import { describe, expect, it } from 'vitest'

import { parseChatStreamPayload } from './api'

describe('desktop chat stream error contract', () => {
  it('turns a terminal backend error into a visible exception with trace id', () => {
    expect(() =>
      parseChatStreamPayload(
        JSON.stringify({
          error: {
            message: '上游首包超时',
            type: 'stream_first_byte_timeout',
            trace_id: 'trace-123'
          }
        })
      )
    ).toThrow('上游首包超时 (trace_id: trace-123)')
  })

  it('ignores malformed heartbeats but preserves valid deltas', () => {
    expect(parseChatStreamPayload('{')).toBeNull()
    expect(
      parseChatStreamPayload(
        JSON.stringify({ choices: [{ delta: { content: '你好' }, finish_reason: null }] })
      )
    ).toMatchObject({ content: '你好' })
  })
})
