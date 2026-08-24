import { describe, expect, it, vi } from 'vitest'

import type {
  RendererEngineRequest,
  RendererEngineStreamEvent,
  RendererEngineUploadRequest
} from '../renderer/src/env'
import { createCredentialStore, type KeyValueStorage } from './credentials'
import { createWebHttpClient } from './http'
import { createWebEngineBridge } from './engine'

function runtimeStorage(): KeyValueStorage {
  const data: Record<string, string> = { 'nachuan.web.runtimeKey': 'runtime-key' }
  return {
    getItem: (key: string) => (key in data ? data[key] : null),
    setItem: (key: string, value: string) => {
      data[key] = value
    },
    removeItem: (key: string) => {
      delete data[key]
    }
  }
}

function bridgeWith(fetchImpl: ReturnType<typeof vi.fn>) {
  const http = createWebHttpClient({
    credentials: createCredentialStore(() => runtimeStorage()),
    fetchImpl: fetchImpl as unknown as typeof fetch
  })
  return createWebEngineBridge(http)
}

const REQUEST_ID = '123e4567-e89b-42d3-a456-426614174000'

function requestInput(patch: Partial<RendererEngineRequest> = {}): RendererEngineRequest {
  return {
    requestId: REQUEST_ID,
    method: 'GET',
    target: '/v1/models',
    bodyKind: 'none',
    responseKind: 'json',
    ...patch
  }
}

function uploadInput(bodyLength: number): RendererEngineUploadRequest {
  return {
    requestId: REQUEST_ID,
    method: 'POST',
    target: '/v1/audio/transcriptions',
    bodyKind: 'binary',
    bodyLength,
    responseKind: 'json'
  }
}

function streamOf(chunks: Uint8Array[]): ReadableStream<Uint8Array> {
  return new ReadableStream<Uint8Array>({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(chunk)
      controller.close()
    }
  })
}

describe('web-shim engine bridge', () => {
  it('rejects non-UUID-v4 request ids before every transport operation', async () => {
    const fetchMock = vi.fn(async () => new Response('{}', { status: 200 }))
    const bridge = bridgeWith(fetchMock)
    const invalidRequestId = 'not-a-renderer-request-id'

    await expect(
      bridge.engineRequest(requestInput({ requestId: invalidRequestId }))
    ).rejects.toThrow(/Invalid Renderer Engine request/)
    await expect(
      bridge.engineStream(
        requestInput({ requestId: invalidRequestId, responseKind: 'stream' }),
        () => undefined
      )
    ).rejects.toThrow(/Invalid Renderer Engine request/)
    await expect(
      bridge.engineUpload(
        { ...uploadInput(1), requestId: invalidRequestId },
        () => new Uint8Array(1)
      )
    ).rejects.toThrow(/Invalid Renderer Engine upload request/)
    expect(() => bridge.cancelEngineRequest(invalidRequestId)).not.toThrow()
    expect(fetchMock).not.toHaveBeenCalled()
  })

  describe('engineRequest', () => {
    it('issues an authorized same-origin GET and returns raw bytes for any status', async () => {
      const fetchMock = vi.fn(
        async () =>
          new Response('{"data":[]}', { status: 200, headers: { 'content-type': 'application/json' } })
      )
      const bridge = bridgeWith(fetchMock)

      const response = await bridge.engineRequest(requestInput())

      expect(response.status).toBe(200)
      expect(response.contentType).toContain('application/json')
      expect(response.body).toBeInstanceOf(Uint8Array)
      expect(new TextDecoder().decode(response.body)).toBe('{"data":[]}')
      const [target, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit]
      expect(target).toBe('/v1/models')
      expect(init.method).toBe('GET')
      expect((init.headers as Record<string, string>)['Authorization']).toBe('Bearer runtime-key')
      expect(init.body).toBeNull()
      expect(init.signal).toBeInstanceOf(AbortSignal)
    })

    it('sends JSON bodies with content type for POST', async () => {
      const fetchMock = vi.fn(async () => new Response('{}', { status: 200 }))
      const bridge = bridgeWith(fetchMock)

      await bridge.engineRequest(
        requestInput({ method: 'POST', bodyKind: 'json', body: '{"a":1}', target: '/v1/chat/completions' })
      )

      const [, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit]
      expect(init.body).toBe('{"a":1}')
      expect((init.headers as Record<string, string>)['Content-Type']).toBe('application/json')
    })

    it('resolves (not rejects) on HTTP error status, matching preload semantics', async () => {
      const fetchMock = vi.fn(async () => new Response('boom', { status: 500 }))
      const bridge = bridgeWith(fetchMock)

      const response = await bridge.engineRequest(requestInput())
      expect(response.status).toBe(500)
      expect(new TextDecoder().decode(response.body)).toBe('boom')
    })

    it('rejects invalid request shapes before touching fetch', async () => {
      const fetchMock = vi.fn(async () => new Response('{}', { status: 200 }))
      const bridge = bridgeWith(fetchMock)

      await expect(
        bridge.engineRequest(requestInput({ bodyKind: 'none', body: '{}' }))
      ).rejects.toThrow(/Invalid Renderer Engine request/)
      await expect(
        bridge.engineRequest(requestInput({ requestId: '' }))
      ).rejects.toThrow(/Invalid Renderer Engine request/)
      expect(fetchMock).not.toHaveBeenCalled()
    })

    it('aborting via cancelEngineRequest rejects the in-flight request', async () => {
      const fetchMock = vi.fn(
        (_input: RequestInfo | URL, init?: RequestInit) =>
          new Promise<Response>((_resolve, reject) => {
            init?.signal?.addEventListener('abort', () =>
              reject(new DOMException('The operation was aborted', 'AbortError'))
            )
          })
      )
      const bridge = bridgeWith(fetchMock)

      const pending = bridge.engineRequest(requestInput())
      const assertion = expect(pending).rejects.toMatchObject({ name: 'AbortError' })
      bridge.cancelEngineRequest(REQUEST_ID)
      await assertion
    })

    it('cancel with an unknown request id is a no-op', () => {
      const bridge = bridgeWith(vi.fn())
      expect(() => bridge.cancelEngineRequest('does-not-exist')).not.toThrow()
    })
  })

  describe('engineStream', () => {
    it('emits start then chunks in order and resolves truthful byte counts', async () => {
      const fetchMock = vi.fn(
        async () =>
          new Response(streamOf([new Uint8Array([1, 2, 3]), new Uint8Array([4, 5])]), {
            status: 200,
            headers: { 'content-type': 'text/event-stream' }
          })
      )
      const bridge = bridgeWith(fetchMock)
      const events: RendererEngineStreamEvent[] = []

      const result = await bridge.engineStream(
        requestInput({ responseKind: 'stream', target: '/v1/chat/completions' }),
        (event) => {
          events.push(event)
        }
      )

      expect(events.map((event) => event.kind)).toEqual(['start', 'chunk', 'chunk'])
      expect(events[0]).toMatchObject({ kind: 'start', status: 200 })
      expect((events[0] as { contentType: string }).contentType).toContain('text/event-stream')
      expect(Array.from((events[1] as { chunk: Uint8Array }).chunk)).toEqual([1, 2, 3])
      expect(Array.from((events[2] as { chunk: Uint8Array }).chunk)).toEqual([4, 5])
      expect(result).toEqual({ status: 200, contentType: 'text/event-stream', bytes: 5 })
    })

    it('honors the one-in-flight credit: the next chunk waits for onEvent to resolve', async () => {
      const fetchMock = vi.fn(
        async () =>
          new Response(streamOf([new Uint8Array([1]), new Uint8Array([2])]), { status: 200 })
      )
      const bridge = bridgeWith(fetchMock)
      const delivered: string[] = []
      let releaseFirstChunk: (() => void) | null = null

      const done = bridge.engineStream(requestInput({ responseKind: 'stream' }), async (event) => {
        if (event.kind === 'start') {
          delivered.push('start')
          return
        }
        delivered.push(`chunk:${Array.from(event.chunk).join(',')}:begin`)
        if (delivered.length === 2) {
          await new Promise<void>((resolve) => {
            releaseFirstChunk = resolve
          })
        }
        delivered.push(`chunk:${Array.from(event.chunk).join(',')}:end`)
      })

      await vi.waitFor(() => {
        expect(delivered).toEqual(['start', 'chunk:1:begin'])
      })
      expect(releaseFirstChunk).not.toBeNull()
      ;(releaseFirstChunk as unknown as () => void)()
      await done
      expect(delivered).toEqual(['start', 'chunk:1:begin', 'chunk:1:end', 'chunk:2:begin', 'chunk:2:end'])
    })

    it('rejects json responseKind streams and duplicate callbacks misconfigurations', async () => {
      const fetchMock = vi.fn(async () => new Response('{}', { status: 200 }))
      const bridge = bridgeWith(fetchMock)

      await expect(
        bridge.engineStream(requestInput({ responseKind: 'json' }), () => {})
      ).rejects.toThrow(/Invalid Renderer Engine stream request/)
      expect(fetchMock).not.toHaveBeenCalled()
    })

    it('cancelEngineRequest aborts an in-flight stream with AbortError', async () => {
      const fetchMock = vi.fn(
        async (_input: RequestInfo | URL, init?: RequestInit) =>
          new Response(
            new ReadableStream<Uint8Array>({
              start(controller) {
                init?.signal?.addEventListener('abort', () => {
                  controller.error(new DOMException('The operation was aborted', 'AbortError'))
                })
              }
            }),
            { status: 200 }
          )
      )
      const bridge = bridgeWith(fetchMock)
      const started: string[] = []

      const pending = bridge.engineStream(requestInput({ responseKind: 'stream' }), (event) => {
        started.push(event.kind)
      })
      const assertion = expect(pending).rejects.toMatchObject({ name: 'AbortError' })
      await vi.waitFor(() => expect(started).toEqual(['start']))
      bridge.cancelEngineRequest(REQUEST_ID)
      await assertion
    })
  })

  describe('engineUpload', () => {
    it('reads 64KiB credits and posts the assembled binary body', async () => {
      const fetchMock = vi.fn(
        async () => new Response('{"ok":true}', { status: 200, headers: { 'content-type': 'application/json' } })
      )
      const bridge = bridgeWith(fetchMock)
      const credits: Array<[number, number]> = []
      const total = 150_000

      const response = await bridge.engineUpload(uploadInput(total), (offset, maximumBytes) => {
        credits.push([offset, maximumBytes])
        return new Uint8Array(maximumBytes).fill(7)
      })

      expect(credits).toEqual([
        [0, 65_536],
        [65_536, 65_536],
        [131_072, 18_928]
      ])
      const [, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit]
      expect(init.method).toBe('POST')
      expect((init.headers as Record<string, string>)['Content-Type']).toBe('application/octet-stream')
      expect((init.headers as Record<string, string>)['Authorization']).toBe('Bearer runtime-key')
      expect(init.body).toBeInstanceOf(ArrayBuffer)
      expect((init.body as ArrayBuffer).byteLength).toBe(total)
      expect(new Uint8Array(init.body as ArrayBuffer)[0]).toBe(7)
      expect(response.status).toBe(200)
    })

    it('supports zero-length uploads without invoking the reader', async () => {
      const fetchMock = vi.fn(async () => new Response('{}', { status: 200 }))
      const bridge = bridgeWith(fetchMock)
      const readChunk = vi.fn()

      await bridge.engineUpload(uploadInput(0), readChunk)

      expect(readChunk).not.toHaveBeenCalled()
      const [, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit]
      expect((init.body as ArrayBuffer).byteLength).toBe(0)
    })

    it('rejects chunks that violate the granted credit', async () => {
      const fetchMock = vi.fn(async () => new Response('{}', { status: 200 }))
      const bridge = bridgeWith(fetchMock)

      await expect(
        bridge.engineUpload(uploadInput(10), () => new Uint8Array(3))
      ).rejects.toThrow(/Invalid Renderer Engine upload chunk/)
      expect(fetchMock).not.toHaveBeenCalled()
    })

    it('validates the upload request shape', async () => {
      const bridge = bridgeWith(vi.fn())
      await expect(
        bridge.engineUpload({ ...uploadInput(1), bodyLength: -1 }, () => new Uint8Array(1))
      ).rejects.toThrow(/Invalid Renderer Engine upload request/)
    })
  })
})
