import { isRendererEngineRequestId } from '../renderer-engine-contract'

const FLOW_CHUNK_BYTES = 64 * 1024

export interface PreloadRendererEngineRequest {
  readonly requestId: string
  readonly method: 'GET' | 'POST'
  readonly target: string
  readonly bodyKind: 'none' | 'json'
  readonly body?: string
  readonly responseKind: 'json' | 'binary' | 'stream'
}

export interface PreloadRendererEngineUploadRequest {
  readonly requestId: string
  readonly method: 'POST'
  readonly target: string
  readonly bodyKind: 'binary'
  readonly bodyLength: number
  readonly responseKind: 'json'
}

export interface PreloadRendererEngineResponse {
  readonly status: number
  readonly contentType: string
  readonly body: Uint8Array
}

export type PreloadRendererEngineStreamEvent =
  | Readonly<{ kind: 'start'; status: number; contentType: string }>
  | Readonly<{ kind: 'chunk'; chunk: Uint8Array }>

export interface PreloadRendererEngineStreamResult {
  readonly status: number
  readonly contentType: string
  readonly bytes: number
}

export type PreloadRendererEngineUploadReader = (
  offset: number,
  maximumBytes: number
) => Uint8Array | Promise<Uint8Array>

type IpcListener = (event: unknown, payload: unknown) => void

export interface RendererEnginePreloadIpc {
  invoke(channel: string, input: unknown): Promise<unknown>
  send(channel: string, input: unknown): void
  on(channel: string, listener: IpcListener): void
  removeListener(channel: string, listener: IpcListener): void
}

export interface RendererEnginePreloadBridge {
  request(input: PreloadRendererEngineRequest): Promise<PreloadRendererEngineResponse>
  stream(
    input: PreloadRendererEngineRequest,
    onEvent: (event: PreloadRendererEngineStreamEvent) => void | Promise<void>
  ): Promise<PreloadRendererEngineStreamResult>
  upload(
    input: PreloadRendererEngineUploadRequest,
    readChunk: PreloadRendererEngineUploadReader
  ): Promise<PreloadRendererEngineResponse>
  cancel(requestId: string): void
  dispose(): void
}

type StreamState = {
  readonly callback: (event: PreloadRendererEngineStreamEvent) => void | Promise<void>
  nextSequence: number
  processing: boolean
}

type UploadState = {
  readonly bodyLength: number
  readonly readChunk: PreloadRendererEngineUploadReader
  nextSequence: number
  nextOffset: number
  processing: boolean
}

function captureInput(input: PreloadRendererEngineRequest): PreloadRendererEngineRequest {
  if (!input || typeof input !== 'object') {
    throw new Error('Invalid Renderer Engine request')
  }
  const value = input as unknown as Record<string, unknown>
  const hasBody = Object.prototype.hasOwnProperty.call(value, 'body')
  if (
    !isRendererEngineRequestId(value.requestId) ||
    (value.bodyKind !== 'none' && value.bodyKind !== 'json') ||
    (value.bodyKind === 'none' && hasBody) ||
    (value.bodyKind === 'json' && typeof value.body !== 'string')
  ) {
    throw new Error('Invalid Renderer Engine request')
  }
  return Object.freeze({
    requestId: value.requestId,
    method: value.method as 'GET' | 'POST',
    target: value.target as string,
    bodyKind: value.bodyKind,
    ...(hasBody ? { body: value.body as string } : {}),
    responseKind: value.responseKind as 'json' | 'binary' | 'stream'
  })
}

function captureUploadInput(
  input: PreloadRendererEngineUploadRequest
): PreloadRendererEngineUploadRequest {
  if (
    !input ||
    typeof input !== 'object' ||
    !isRendererEngineRequestId(input.requestId) ||
    input.method !== 'POST' ||
    input.bodyKind !== 'binary' ||
    input.responseKind !== 'json' ||
    !Number.isSafeInteger(input.bodyLength) ||
    input.bodyLength < 0
  ) {
    throw new Error('Invalid Renderer Engine upload request')
  }
  return Object.freeze({
    requestId: input.requestId,
    method: input.method,
    target: input.target,
    bodyKind: input.bodyKind,
    bodyLength: input.bodyLength,
    responseKind: input.responseKind
  })
}

function validStatus(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) >= 200 && Number(value) <= 599
}

function validContentType(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length >= 1 &&
    value.length <= 256 &&
    !/[^\x20-\x7e]/.test(value)
  )
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort()
  const sorted = [...expected].sort()
  return actual.length === sorted.length && actual.every((key, index) => key === sorted[index])
}

function checkedResponse(value: unknown): PreloadRendererEngineResponse {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Invalid Renderer Engine response')
  }
  const response = value as PreloadRendererEngineResponse
  if (
    !validStatus(response.status) ||
    !validContentType(response.contentType) ||
    !(response.body instanceof Uint8Array)
  ) {
    throw new Error('Invalid Renderer Engine response')
  }
  return Object.freeze({
    status: response.status,
    contentType: response.contentType,
    body: Uint8Array.from(response.body)
  })
}

function checkedStreamResult(value: unknown): PreloadRendererEngineStreamResult {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Invalid Renderer Engine stream result')
  }
  const result = value as PreloadRendererEngineStreamResult
  if (
    !validStatus(result.status) ||
    !validContentType(result.contentType) ||
    !Number.isSafeInteger(result.bytes) ||
    result.bytes < 0
  ) {
    throw new Error('Invalid Renderer Engine stream result')
  }
  return Object.freeze({
    status: result.status,
    contentType: result.contentType,
    bytes: result.bytes
  })
}

export function createRendererEngineBridge(
  ipc: RendererEnginePreloadIpc
): RendererEnginePreloadBridge {
  if (
    !ipc ||
    typeof ipc.invoke !== 'function' ||
    typeof ipc.send !== 'function' ||
    typeof ipc.on !== 'function' ||
    typeof ipc.removeListener !== 'function'
  ) {
    throw new Error('Renderer Engine preload IPC is unavailable')
  }
  const streams = new Map<string, StreamState>()
  const uploads = new Map<string, UploadState>()

  const cancelStream = (requestId: string, state: StreamState): void => {
    if (streams.get(requestId) === state) streams.delete(requestId)
    ipc.send('engine:cancel', requestId)
  }

  const cancelUpload = (requestId: string, state: UploadState): void => {
    if (uploads.get(requestId) === state) uploads.delete(requestId)
    ipc.send('engine:cancel', requestId)
  }

  const streamListener: IpcListener = (_event, payload) => {
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return
    const value = payload as Record<string, unknown>
    if (!isRendererEngineRequestId(value.requestId)) return
    const state = streams.get(value.requestId)
    if (!state) return
    const start =
      value.kind === 'start' &&
      exactKeys(value, ['contentType', 'kind', 'requestId', 'sequence', 'status']) &&
      validStatus(value.status) &&
      validContentType(value.contentType)
    const chunk =
      value.kind === 'chunk' &&
      exactKeys(value, ['chunk', 'kind', 'requestId', 'sequence']) &&
      value.chunk instanceof Uint8Array &&
      value.chunk.byteLength <= FLOW_CHUNK_BYTES
    if (
      (!start && !chunk) ||
      !Number.isSafeInteger(value.sequence) ||
      value.sequence !== state.nextSequence ||
      state.processing
    ) {
      cancelStream(value.requestId, state)
      return
    }
    state.processing = true
    const sequence = value.sequence as number
    const event: PreloadRendererEngineStreamEvent = start
      ? Object.freeze({
          kind: 'start',
          status: value.status as number,
          contentType: value.contentType as string
        })
      : Object.freeze({ kind: 'chunk', chunk: Uint8Array.from(value.chunk as Uint8Array) })
    void Promise.resolve()
      .then(() => state.callback(event))
      .then(
        () => {
          if (streams.get(value.requestId as string) !== state) return
          state.processing = false
          state.nextSequence += 1
          ipc.send('engine:stream-ack', { requestId: value.requestId, sequence })
        },
        () => cancelStream(value.requestId as string, state)
      )
  }

  const uploadListener: IpcListener = (_event, payload) => {
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return
    const value = payload as Record<string, unknown>
    if (!isRendererEngineRequestId(value.requestId)) return
    const state = uploads.get(value.requestId)
    if (!state) return
    if (
      !exactKeys(value, ['maximumBytes', 'offset', 'requestId', 'sequence']) ||
      !Number.isSafeInteger(value.sequence) ||
      value.sequence !== state.nextSequence ||
      !Number.isSafeInteger(value.offset) ||
      value.offset !== state.nextOffset ||
      !Number.isSafeInteger(value.maximumBytes) ||
      Number(value.maximumBytes) < 1 ||
      Number(value.maximumBytes) > FLOW_CHUNK_BYTES ||
      Number(value.maximumBytes) > state.bodyLength - state.nextOffset ||
      state.processing
    ) {
      cancelUpload(value.requestId, state)
      return
    }
    state.processing = true
    const sequence = value.sequence as number
    const maximumBytes = value.maximumBytes as number
    const offset = value.offset as number
    void Promise.resolve()
      .then(() => state.readChunk(offset, maximumBytes))
      .then(
        (raw) => {
          if (uploads.get(value.requestId as string) !== state) return
          if (
            !(raw instanceof Uint8Array) ||
            raw.byteLength !== maximumBytes ||
            offset + raw.byteLength > state.bodyLength
          ) {
            cancelUpload(value.requestId as string, state)
            return
          }
          const chunk = Uint8Array.from(raw)
          state.processing = false
          state.nextSequence += 1
          state.nextOffset += chunk.byteLength
          ipc.send('engine:upload-chunk', { requestId: value.requestId, sequence, chunk })
        },
        () => cancelUpload(value.requestId as string, state)
      )
  }

  ipc.on('engine:stream-event', streamListener)
  ipc.on('engine:upload-credit', uploadListener)

  const bridge: RendererEnginePreloadBridge = {
    request: async (input: PreloadRendererEngineRequest) =>
      checkedResponse(await ipc.invoke('engine:request', captureInput(input))),
    stream: async (
      input: PreloadRendererEngineRequest,
      onEvent: (event: PreloadRendererEngineStreamEvent) => void | Promise<void>
    ) => {
      const captured = captureInput(input)
      if (
        captured.responseKind === 'json' ||
        typeof onEvent !== 'function' ||
        streams.has(captured.requestId) ||
        uploads.has(captured.requestId)
      ) {
        throw new Error('Invalid Renderer Engine stream request')
      }
      const state: StreamState = { callback: onEvent, nextSequence: 0, processing: false }
      streams.set(captured.requestId, state)
      try {
        return checkedStreamResult(await ipc.invoke('engine:stream', captured))
      } finally {
        if (streams.get(captured.requestId) === state) streams.delete(captured.requestId)
      }
    },
    upload: async (
      input: PreloadRendererEngineUploadRequest,
      readChunk: PreloadRendererEngineUploadReader
    ) => {
      const captured = captureUploadInput(input)
      if (
        typeof readChunk !== 'function' ||
        streams.has(captured.requestId) ||
        uploads.has(captured.requestId)
      ) {
        throw new Error('Invalid Renderer Engine upload request')
      }
      const state: UploadState = {
        bodyLength: captured.bodyLength,
        readChunk,
        nextSequence: 0,
        nextOffset: 0,
        processing: false
      }
      uploads.set(captured.requestId, state)
      try {
        return checkedResponse(await ipc.invoke('engine:upload', captured))
      } finally {
        if (uploads.get(captured.requestId) === state) uploads.delete(captured.requestId)
      }
    },
    cancel: (requestId: string) => {
      if (!isRendererEngineRequestId(requestId)) return
      streams.delete(requestId)
      uploads.delete(requestId)
      ipc.send('engine:cancel', requestId)
    },
    dispose: () => {
      const requestIds = new Set([...streams.keys(), ...uploads.keys()])
      streams.clear()
      uploads.clear()
      for (const requestId of requestIds) ipc.send('engine:cancel', requestId)
      ipc.removeListener('engine:stream-event', streamListener)
      ipc.removeListener('engine:upload-credit', uploadListener)
    }
  }
  return Object.freeze(bridge)
}
