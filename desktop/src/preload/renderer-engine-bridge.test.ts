import { describe, expect, it, vi } from 'vitest'

import { createRendererEngineBridge } from './renderer-engine-bridge'

describe('renderer Engine preload bridge', () => {
  it('rejects legacy buffered binary requests before invoking Main', async () => {
    const ipc = {
      invoke: vi.fn(),
      send: vi.fn(),
      on: vi.fn(),
      removeListener: vi.fn()
    }
    const bridge = createRendererEngineBridge(ipc)

    await expect(
      bridge.request({
        requestId: '00000000-0000-4000-8000-000000000001',
        method: 'POST',
        target: '/v1/vision',
        bodyKind: 'binary',
        body: Uint8Array.from([1]),
        responseKind: 'json'
      } as never)
    ).rejects.toThrow('Invalid Renderer Engine request')
    expect(ipc.invoke).not.toHaveBeenCalled()
  })

  it('uses only fixed channels and routes stream chunks by a non-secret request id', async () => {
    const listeners = new Map<string, (...args: unknown[]) => void>()
    let finishStream!: (value: unknown) => void
    const invoke = vi.fn((channel: string) => {
      if (channel === 'engine:stream') {
        return new Promise((resolve) => {
          finishStream = resolve
        })
      }
      return Promise.resolve({
        status: 200,
        contentType: 'application/json',
        body: Uint8Array.from([123, 125])
      })
    })
    const send = vi.fn()
    const ipc = {
      invoke,
      send,
      on: vi.fn((channel: string, listener: (...args: unknown[]) => void) => {
        listeners.set(channel, listener)
      }),
      removeListener: vi.fn()
    }
    const bridge = createRendererEngineBridge(ipc)
    const requestId = '11111111-1111-4111-8111-111111111111'
    const request = {
      requestId,
      method: 'GET' as const,
      target: '/v1/models',
      bodyKind: 'none' as const,
      responseKind: 'json' as const
    }

    await expect(bridge.request(request)).resolves.toMatchObject({ status: 200 })
    const events: unknown[] = []
    let releaseStart!: () => void
    const startReleased = new Promise<void>((resolve) => {
      releaseStart = resolve
    })
    const pending = bridge.stream({ ...request, responseKind: 'stream' }, async (event) => {
      events.push(event)
      if (event.kind === 'start') await startReleased
    })
    listeners.get('engine:stream-event')?.({}, {
      requestId,
      sequence: 0,
      kind: 'start',
      status: 200,
      contentType: 'text/event-stream'
    })
    await Promise.resolve()
    expect(send).not.toHaveBeenCalledWith('engine:stream-ack', expect.anything())
    releaseStart()
    await vi.waitFor(() =>
      expect(send).toHaveBeenCalledWith('engine:stream-ack', { requestId, sequence: 0 })
    )
    listeners.get('engine:stream-event')?.({}, {
      requestId,
      sequence: 1,
      kind: 'chunk',
      chunk: Uint8Array.from([1, 2, 3])
    })
    await vi.waitFor(() =>
      expect(send).toHaveBeenCalledWith('engine:stream-ack', { requestId, sequence: 1 })
    )
    finishStream({ status: 200, contentType: 'text/event-stream', bytes: 3 })
    await expect(pending).resolves.toMatchObject({ bytes: 3 })
    bridge.cancel(requestId)

    expect(invoke.mock.calls.map((call) => call[0])).toEqual([
      'engine:request',
      'engine:stream'
    ])
    expect(send).toHaveBeenCalledWith('engine:cancel', requestId)
    expect(listeners.size).toBe(2)
    expect([...listeners.keys()].sort()).toEqual(['engine:stream-event', 'engine:upload-credit'])
    expect(events).toHaveLength(2)
    expect(JSON.stringify(invoke.mock.calls)).not.toMatch(/authorization|bearer|api.?key|baseUrl/i)
  })

  it('serves one bounded upload credit at a time over fixed channels', async () => {
    const listeners = new Map<string, (...args: unknown[]) => void>()
    const requestId = '22222222-2222-4222-8222-222222222222'
    let finishUpload!: (value: unknown) => void
    const ipc = {
      invoke: vi.fn((channel: string) => {
        if (channel === 'engine:upload') {
          return new Promise((resolve) => {
            finishUpload = resolve
          })
        }
        return Promise.reject(new Error('unexpected channel'))
      }),
      send: vi.fn(),
      on: vi.fn((channel: string, listener: (...args: unknown[]) => void) => {
        listeners.set(channel, listener)
      }),
      removeListener: vi.fn()
    }
    const bridge = createRendererEngineBridge(ipc)
    const reads: Array<{ offset: number; maximumBytes: number }> = []
    const pending = bridge.upload(
      {
        requestId,
        method: 'POST',
        target: '/v1/vision',
        bodyKind: 'binary',
        bodyLength: 3,
        responseKind: 'json'
      },
      async (offset, maximumBytes) => {
        reads.push({ offset, maximumBytes })
        return Uint8Array.from([1, 2, 3]).slice(offset, offset + maximumBytes)
      }
    )

    listeners.get('engine:upload-credit')?.({}, {
      requestId,
      sequence: 0,
      offset: 0,
      maximumBytes: 3
    })
    await vi.waitFor(() =>
      expect(ipc.send).toHaveBeenCalledWith('engine:upload-chunk', {
        requestId,
        sequence: 0,
        chunk: Uint8Array.from([1, 2, 3])
      })
    )
    finishUpload({
      status: 200,
      contentType: 'Application/JSON; Charset=UTF-8',
      body: Uint8Array.from(Buffer.from('{"text":"ok"}', 'utf8'))
    })
    await expect(pending).resolves.toMatchObject({ status: 200 })
    expect(reads).toEqual([{ offset: 0, maximumBytes: 3 }])
    expect(JSON.stringify(ipc.invoke.mock.calls)).not.toMatch(/authorization|bearer|api.?key|baseUrl/i)
  })
})
