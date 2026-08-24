import { EventEmitter } from 'node:events'

import { describe, expect, it, vi } from 'vitest'

import { registerRendererEngineProxyIpc } from './renderer-engine-ipc'

describe('renderer Engine IPC registration', () => {
  it('rejects a legacy buffered binary request before invoking the proxy', async () => {
    const handlers = new Map<string, (...args: any[]) => any>()
    const ipc = {
      handle: (channel: string, handler: (...args: any[]) => any) => handlers.set(channel, handler),
      on: vi.fn(),
      removeHandler: vi.fn(),
      removeListener: vi.fn()
    }
    const proxy = {
      request: vi.fn(),
      stream: vi.fn(),
      upload: vi.fn(),
      cancel: vi.fn()
    }
    registerRendererEngineProxyIpc(ipc, proxy, vi.fn())

    await expect(
      handlers.get('engine:request')?.(
        { sender: { send: vi.fn() }, senderFrame: {} },
        {
          requestId: '00000000-0000-4000-8000-000000000002',
          method: 'POST',
          target: '/v1/vision',
          bodyKind: 'binary',
          body: Uint8Array.from([1]),
          responseKind: 'json'
        }
      )
    ).rejects.toThrow('invalid Renderer Engine IPC request')
    expect(proxy.request).not.toHaveBeenCalled()
  })

  it('re-authorizes the expected frame and emits stream data only on one fixed channel', async () => {
    const handlers = new Map<string, (...args: any[]) => any>()
    const listeners = new Map<string, (...args: any[]) => any>()
    const ipc = {
      handle: vi.fn((channel: string, handler: (...args: any[]) => any) => {
        handlers.set(channel, handler)
      }),
      on: vi.fn((channel: string, handler: (...args: any[]) => any) => {
        listeners.set(channel, handler)
      }),
      removeHandler: vi.fn(),
      removeListener: vi.fn()
    }
    const proxy = {
      request: vi.fn(async () => ({
        status: 200,
        contentType: 'application/json',
        body: Uint8Array.from([123, 125])
      })),
      stream: vi.fn(async (_input: unknown, emit: (event: unknown) => Promise<void>) => {
        await emit({ kind: 'start', status: 200, contentType: 'text/event-stream' })
        await emit({ kind: 'chunk', chunk: Uint8Array.from([1, 2, 3]) })
        return { status: 200, contentType: 'text/event-stream', bytes: 3 }
      }),
      upload: vi.fn(),
      cancel: vi.fn(() => true)
    }
    const authorize = vi.fn()
    registerRendererEngineProxyIpc(ipc, proxy, authorize)
    const send = vi.fn()
    const sender = Object.assign(new EventEmitter(), { send })
    const frame = {}
    const event = { sender, senderFrame: frame }
    const input = {
      requestId: '11111111-1111-4111-8111-111111111111',
      method: 'GET',
      target: '/v1/models',
      bodyKind: 'none',
      responseKind: 'json'
    }

    await expect(handlers.get('engine:request')?.(event, input)).resolves.toMatchObject({
      status: 200
    })
    const pendingStream = handlers.get('engine:stream')?.(event, {
      ...input,
      responseKind: 'stream'
    })
    await vi.waitFor(() => expect(send).toHaveBeenCalledTimes(1))
    expect(send.mock.calls[0][1]).toMatchObject({ sequence: 0 })
    listeners.get('engine:stream-ack')?.(event, { requestId: input.requestId, sequence: 0 })
    await vi.waitFor(() => expect(send).toHaveBeenCalledTimes(2))
    expect(send.mock.calls[1][1]).toMatchObject({ sequence: 1 })
    listeners.get('engine:stream-ack')?.(event, { requestId: input.requestId, sequence: 1 })
    await expect(pendingStream).resolves.toMatchObject({ bytes: 3 })
    listeners.get('engine:cancel')?.(event, input.requestId)

    expect(authorize.mock.calls.length).toBeGreaterThanOrEqual(9)
    expect(send).toHaveBeenCalledTimes(2)
    expect(send.mock.calls.map((call) => call[0])).toEqual([
      'engine:stream-event',
      'engine:stream-event'
    ])
    expect(send.mock.calls[0][1]).toMatchObject({
      requestId: input.requestId,
      kind: 'start',
      status: 200
    })
    expect(send.mock.calls[1][1]).toMatchObject({
      requestId: input.requestId,
      kind: 'chunk'
    })
    expect(proxy.cancel).toHaveBeenCalledWith(input.requestId)
  })

  it('cancels a bound request immediately when its initiating sender is destroyed', async () => {
    const handlers = new Map<string, (...args: any[]) => any>()
    const listeners = new Map<string, (...args: any[]) => any>()
    const ipc = {
      handle: (_channel: string, handler: (...args: any[]) => any) => handlers.set(_channel, handler),
      on: (_channel: string, handler: (...args: any[]) => any) => listeners.set(_channel, handler),
      removeHandler: vi.fn(),
      removeListener: vi.fn()
    }
    let finish!: () => void
    const proxy = {
      request: vi.fn(
        () =>
          new Promise<{ status: number; contentType: string; body: Uint8Array }>((resolve) => {
            finish = () => resolve({
              status: 200,
              contentType: 'application/json',
              body: Uint8Array.from([123, 125])
            })
          })
      ),
      stream: vi.fn(),
      upload: vi.fn(),
      cancel: vi.fn(() => true)
    }
    registerRendererEngineProxyIpc(ipc, proxy, vi.fn())
    const sender = Object.assign(new EventEmitter(), { send: vi.fn() })
    const event = { sender, senderFrame: {} }
    const requestId = '22222222-2222-4222-8222-222222222222'
    const pending = handlers.get('engine:request')?.(event, {
      requestId,
      method: 'GET',
      target: '/v1/models',
      bodyKind: 'none',
      responseKind: 'json'
    })
    await vi.waitFor(() => expect(proxy.request).toHaveBeenCalledTimes(1))

    sender.emit('destroyed')
    expect(proxy.cancel).toHaveBeenCalledWith(requestId)
    finish()
    await pending
  })

  it('pulls exactly one bounded upload chunk per Main-issued credit', async () => {
    const handlers = new Map<string, (...args: any[]) => any>()
    const listeners = new Map<string, (...args: any[]) => any>()
    const ipc = {
      handle: (_channel: string, handler: (...args: any[]) => any) => handlers.set(_channel, handler),
      on: (_channel: string, handler: (...args: any[]) => any) => listeners.set(_channel, handler),
      removeHandler: vi.fn(),
      removeListener: vi.fn()
    }
    const proxy = {
      request: vi.fn(),
      stream: vi.fn(),
      upload: vi.fn(async (_input: unknown, readChunk: (...args: any[]) => Promise<Uint8Array>) => {
        const controller = new AbortController()
        const chunk = await readChunk(0, 3, controller.signal)
        expect(chunk).toEqual(Uint8Array.from([1, 2, 3]))
        return {
          status: 200,
          contentType: 'application/json',
          body: Uint8Array.from([123, 125])
        }
      }),
      cancel: vi.fn(() => true)
    }
    registerRendererEngineProxyIpc(ipc, proxy, vi.fn())
    const send = vi.fn()
    const event = {
      sender: Object.assign(new EventEmitter(), { send }),
      senderFrame: {}
    }
    const requestId = '33333333-3333-4333-8333-333333333333'
    const pending = handlers.get('engine:upload')?.(event, {
      requestId,
      method: 'POST',
      target: '/v1/vision',
      bodyKind: 'binary',
      bodyLength: 3,
      responseKind: 'json'
    })

    await vi.waitFor(() => expect(send).toHaveBeenCalledTimes(1))
    expect(send).toHaveBeenCalledWith('engine:upload-credit', {
      requestId,
      sequence: 0,
      offset: 0,
      maximumBytes: 3
    })
    listeners.get('engine:upload-chunk')?.(event, {
      requestId,
      sequence: 0,
      chunk: Uint8Array.from([1, 2, 3])
    })
    await expect(pending).resolves.toMatchObject({ status: 200 })
    expect(send).toHaveBeenCalledTimes(1)
  })

  it('does not invoke the proxy when sender authorization fails', async () => {
    const handlers = new Map<string, (...args: any[]) => any>()
    const ipc = {
      handle: (_channel: string, handler: (...args: any[]) => any) => {
        handlers.set(_channel, handler)
      },
      on: vi.fn(),
      removeHandler: vi.fn(),
      removeListener: vi.fn()
    }
    const proxy = {
      request: vi.fn(),
      stream: vi.fn(),
      upload: vi.fn(),
      cancel: vi.fn()
    }
    registerRendererEngineProxyIpc(ipc, proxy, () => {
      throw new Error('unauthorized IPC sender')
    })

    await expect(
      handlers.get('engine:request')?.(
        { sender: { send: vi.fn() } },
        {
          requestId: '11111111-1111-4111-8111-111111111111',
          method: 'GET',
          target: '/v1/models',
          bodyKind: 'none',
          responseKind: 'json'
        }
      )
    ).rejects.toThrow('unauthorized IPC sender')
    expect(proxy.request).not.toHaveBeenCalled()
  })
})
