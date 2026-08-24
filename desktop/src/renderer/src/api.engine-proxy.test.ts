import { beforeEach, describe, expect, it, vi } from 'vitest'

describe('renderer Engine API boundary', () => {
  const engineRequest = vi.fn()
  const engineStream = vi.fn()
  const engineUpload = vi.fn()
  const cancelEngineRequest = vi.fn()

  beforeEach(() => {
    vi.resetModules()
    vi.restoreAllMocks()
    engineRequest.mockReset()
    engineStream.mockReset()
    engineUpload.mockReset()
    cancelEngineRequest.mockReset()
    vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new Error('renderer fetch is forbidden'))))
    vi.stubGlobal('window', {
      api: { engineRequest, engineStream, engineUpload, cancelEngineRequest }
    })
  })

  it('loads models through fixed IPC without a URL, header or runtime key', async () => {
    engineRequest.mockResolvedValue({
      status: 200,
      contentType: 'application/json',
      body: Uint8Array.from(Buffer.from('{"data":[{"id":"nachuan"}]}', 'utf8'))
    })
    const { fetchModels } = await import('./api')

    await expect(fetchModels()).resolves.toEqual([{ id: 'nachuan' }])
    expect(engineRequest).toHaveBeenCalledTimes(1)
    expect(engineRequest.mock.calls[0][0]).toMatchObject({
      method: 'GET',
      target: '/v1/models',
      bodyKind: 'none',
      responseKind: 'json'
    })
    expect(JSON.stringify(engineRequest.mock.calls)).not.toMatch(
      /authorization|bearer|api.?key|baseUrl/i
    )
    expect(globalThis.fetch).not.toHaveBeenCalled()
  })

  it('loads a truthful orchestration capability snapshot through fixed IPC', async () => {
    const snapshot = {
      chat_model_count: 3,
      review_candidate_count: 2,
      independent_identity_count: 3,
      single_review_ready: true,
      post_summary_final_review_ready: true,
      four_vendor_review_ready: false,
      reason: 'four_vendor_review_requires_four_independent_reviewers'
    }
    engineRequest.mockResolvedValue({
      status: 200,
      contentType: 'application/json',
      body: Uint8Array.from(Buffer.from(JSON.stringify(snapshot), 'utf8'))
    })
    const { fetchOrchestrationCapabilities } = await import('./api')

    await expect(fetchOrchestrationCapabilities()).resolves.toEqual(snapshot)
    expect(engineRequest).toHaveBeenCalledOnce()
    expect(engineRequest.mock.calls[0][0]).toMatchObject({
      method: 'GET',
      target: '/v1/orchestration/capabilities',
      bodyKind: 'none',
      responseKind: 'json'
    })
    expect(JSON.stringify(engineRequest.mock.calls)).not.toMatch(
      /authorization|bearer|api.?key|baseUrl/i
    )
    expect(globalThis.fetch).not.toHaveBeenCalled()
  })

  it('rejects a capability snapshot that promotes a later review tier', async () => {
    engineRequest.mockResolvedValue({
      status: 200,
      contentType: 'application/json',
      body: Uint8Array.from(
        Buffer.from(
          JSON.stringify({
            chat_model_count: 5,
            review_candidate_count: 4,
            independent_identity_count: 5,
            single_review_ready: true,
            post_summary_final_review_ready: false,
            four_vendor_review_ready: true,
            reason: null
          }),
          'utf8'
        )
      )
    })
    const { fetchOrchestrationCapabilities } = await import('./api')

    await expect(fetchOrchestrationCapabilities()).rejects.toThrow(
      'Invalid orchestration capability response'
    )
  })

  it('parses chat SSE delivered by the fixed stream IPC', async () => {
    engineStream.mockImplementation(async (_input, emit) => {
      await emit({ kind: 'start', status: 200, contentType: 'text/event-stream' })
      await emit({
        kind: 'chunk',
        chunk: Uint8Array.from(
          Buffer.from('data: {"choices":[{"delta":{"content":"你好"}}]}\n\n', 'utf8')
        )
      })
      await emit({ kind: 'chunk', chunk: Uint8Array.from(Buffer.from('data: [DONE]\n\n')) })
      return { status: 200, contentType: 'text/event-stream', bytes: 64 }
    })
    const { chatStream } = await import('./api')
    const chunks: unknown[] = []

    for await (const chunk of chatStream('nachuan', [{ role: 'user', content: '你好' }])) {
      chunks.push(chunk)
    }

    expect(chunks).toEqual([{ content: '你好' }])
    expect(engineStream.mock.calls[0][0]).toMatchObject({
      method: 'POST',
      target: '/v1/chat/completions',
      bodyKind: 'json',
      responseKind: 'stream'
    })
    expect(globalThis.fetch).not.toHaveBeenCalled()
  })

  it('holds the renderer stream credit until the consumer advances past the yielded delta', async () => {
    let contentCreditReleased = false
    engineStream.mockImplementation(async (_input, emit) => {
      await emit({ kind: 'start', status: 200, contentType: 'text/event-stream' })
      await emit({
        kind: 'chunk',
        chunk: Uint8Array.from(
          Buffer.from('data: {"choices":[{"delta":{"content":"你"}}]}\n\n', 'utf8')
        )
      })
      contentCreditReleased = true
      await emit({ kind: 'chunk', chunk: Uint8Array.from(Buffer.from('data: [DONE]\n\n')) })
      return { status: 200, contentType: 'text/event-stream', bytes: 62 }
    })
    const { chatStream } = await import('./api')
    const stream = chatStream('nachuan', [{ role: 'user', content: '你好' }])

    await expect(stream.next()).resolves.toEqual({ done: false, value: { content: '你' } })
    expect(contentCreditReleased).toBe(false)
    await expect(stream.next()).resolves.toEqual({ done: true, value: undefined })
    expect(contentCreditReleased).toBe(true)
  })

  it('binds Agent Turn identity/model to the conversation and rejects a late result after abort', async () => {
    let release: ((value: unknown) => void) | undefined
    engineRequest.mockImplementation(
      () =>
        new Promise((resolve) => {
          release = resolve
        })
    )
    const { agentChat } = await import('./api')
    const controller = new AbortController()
    const pending = agentChat('你好', {
      chatId: 'conversation-a',
      model: 'glm-5.1',
      signal: controller.signal
    })

    await vi.waitFor(() => expect(engineRequest).toHaveBeenCalledOnce())
    const request = engineRequest.mock.calls[0][0]
    expect(request.target).toBe('/v1/agent/chat')
    expect(JSON.parse(request.body)).toMatchObject({
      message: '你好',
      user_id: 'owner',
      chat_id: 'conversation-a',
      channel: 'desktop',
      model: 'glm-5.1'
    })

    controller.abort()
    expect(cancelEngineRequest).toHaveBeenCalledWith(request.requestId)
    release?.({
      status: 200,
      contentType: 'application/json',
      body: Uint8Array.from(
        Buffer.from('{"reply":"late","model":"glm-5.1"}', 'utf8')
      )
    })
    await expect(pending).rejects.toMatchObject({ name: 'AbortError' })
  })

  it.each([
    ['missing outcome', { reply: 'answer', model: 'glm-5.1', blocked: false }],
    [
      'unknown outcome',
      { reply: 'answer', model: 'glm-5.1', outcome: 'looks_good', blocked: false }
    ],
    [
      'unverified completed result',
      {
        reply: 'answer',
        model: 'glm-5.1',
        outcome: 'completed',
        blocked: false,
        verified: false,
        machine_verified: false
      }
    ],
    [
      'blocked result marked unblocked',
      { reply: 'denied', model: '(blocked)', outcome: 'blocked', blocked: false }
    ],
    [
      'async acceptance without a durable task id',
      { reply: 'queued', model: 'agnes-video', outcome: 'accepted_async', blocked: false }
    ]
  ])('rejects an Agent response with %s', async (_label, payload) => {
    engineRequest.mockResolvedValue({
      status: 200,
      contentType: 'application/json',
      body: Uint8Array.from(Buffer.from(JSON.stringify(payload), 'utf8'))
    })
    const { agentChat } = await import('./api')

    await expect(agentChat('你好')).rejects.toThrow('Invalid Agent response')
  })

  it('accepts only a coherent unverified Agent terminal result', async () => {
    const payload = {
      reply: 'answer',
      model: 'glm-5.1',
      outcome: 'completed_unverified',
      blocked: false,
      reviewed: false,
      verified: false,
      machine_verified: false
    }
    engineRequest.mockResolvedValue({
      status: 200,
      contentType: 'application/json',
      body: Uint8Array.from(Buffer.from(JSON.stringify(payload), 'utf8'))
    })
    const { agentChat } = await import('./api')

    await expect(agentChat('你好')).resolves.toEqual(payload)
  })

  it('uploads a Blob through bounded pull credits without reading the whole file', async () => {
    const payload = Uint8Array.from([1, 2, 3, 4, 5, 6, 7])
    const wholeFileRead = vi.fn(() => Promise.reject(new Error('whole-file read is forbidden')))
    const file = {
      size: payload.byteLength,
      arrayBuffer: wholeFileRead,
      slice: vi.fn((start: number, end: number) => new Blob([payload.slice(start, end)]))
    } as unknown as Blob
    let maximumConcurrentReads = 0
    let activeReads = 0
    const requestedMaximums: number[] = []
    engineUpload.mockImplementation(async (input, readChunk) => {
      expect(input).toMatchObject({
        method: 'POST',
        target: '/v1/vision',
        bodyKind: 'binary',
        bodyLength: payload.byteLength,
        responseKind: 'json'
      })
      const chunks: Uint8Array[] = []
      let offset = 0
      while (offset < payload.byteLength) {
        activeReads += 1
        maximumConcurrentReads = Math.max(maximumConcurrentReads, activeReads)
        const maximumBytes = Math.min(3, payload.byteLength - offset)
        requestedMaximums.push(maximumBytes)
        const chunk = await readChunk(offset, maximumBytes)
        activeReads -= 1
        chunks.push(chunk)
        offset += chunk.byteLength
      }
      expect(Buffer.concat(chunks.map((chunk) => Buffer.from(chunk)))).toEqual(Buffer.from(payload))
      return {
        status: 200,
        contentType: 'Application/JSON; Charset=UTF-8',
        body: Uint8Array.from(Buffer.from('{"text":"ok"}', 'utf8'))
      }
    })
    const { visionImage } = await import('./api')

    await expect(visionImage(file)).resolves.toBe('ok')
    expect(wholeFileRead).not.toHaveBeenCalled()
    expect(maximumConcurrentReads).toBe(1)
    expect(requestedMaximums.every((maximum) => maximum <= 64 * 1024)).toBe(true)
    expect(engineRequest).not.toHaveBeenCalled()
  })

  it('treats JSON MIME essences case-insensitively on a streaming endpoint', async () => {
    engineStream.mockImplementation(async (_input, emit) => {
      await emit({ kind: 'start', status: 503, contentType: 'Application/JSON; Charset=UTF-8' })
      await emit({
        kind: 'chunk',
        chunk: Uint8Array.from(Buffer.from('{"detail":"temporarily unavailable"}', 'utf8'))
      })
      return { status: 503, contentType: 'Application/JSON; Charset=UTF-8', bytes: 36 }
    })
    const { chatStream } = await import('./api')

    await expect(async () => {
      for await (const _chunk of chatStream('nachuan', [{ role: 'user', content: '你好' }])) {
        // consume
      }
    }).rejects.toThrow('503 {"detail":"temporarily unavailable"}')
  })
})
