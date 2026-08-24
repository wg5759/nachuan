import type {
  RendererEngineProxy,
  RendererEngineRequest,
  RendererEngineResponse,
  RendererEngineStreamEvent,
  RendererEngineStreamResult,
  RendererEngineUploadRequest
} from './renderer-engine-proxy'

const REQUEST_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const FLOW_ACK_TIMEOUT_MS = 30_000
const FLOW_CHUNK_BYTES = 64 * 1024

type IpcSender = {
  send: (channel: string, payload: unknown) => void
}

type LifecycleEmitter = {
  on?: (event: string, listener: (...args: unknown[]) => void) => unknown
  removeListener?: (event: string, listener: (...args: unknown[]) => void) => unknown
}

type IpcEvent = Readonly<{
  sender: IpcSender
  senderFrame?: unknown
}>

type IpcHandler = (event: IpcEvent, input?: unknown) => unknown
type IpcListener = (event: IpcEvent, input?: unknown) => void

export interface RendererEngineIpcRegistrar {
  handle(channel: string, handler: IpcHandler): void
  on(channel: string, listener: IpcListener): void
  removeHandler(channel: string): void
  removeListener(channel: string, listener: IpcListener): void
}

type RendererEngineProxySurface = Pick<
  RendererEngineProxy,
  'request' | 'stream' | 'upload' | 'cancel'
>
type AuthorizeIpcSender = (event: IpcEvent) => void

type Owner = Readonly<{ sender: IpcSender; senderFrame: unknown }>
type StreamPending = {
  readonly sequence: number
  readonly resolve: () => void
  readonly reject: (error: Error) => void
  readonly timer: ReturnType<typeof setTimeout>
}
type StreamFlow = {
  readonly owner: Owner
  nextSequence: number
  pending: StreamPending | null
  closed: boolean
}
type UploadPending = {
  readonly sequence: number
  readonly maximumBytes: number
  readonly signal: AbortSignal
  readonly abort: () => void
  readonly resolve: (chunk: Uint8Array) => void
  readonly reject: (error: Error) => void
  readonly timer: ReturnType<typeof setTimeout>
}
type UploadFlow = {
  readonly owner: Owner
  nextSequence: number
  pending: UploadPending | null
  closed: boolean
}
type SenderLifecycle = {
  readonly requestIds: Set<string>
  readonly destroyed: (...args: unknown[]) => void
  readonly gone: (...args: unknown[]) => void
  readonly navigation: (...args: unknown[]) => void
}

function invalidIpc(): Error {
  return new Error('invalid Renderer Engine IPC request')
}

function requestIdOf(input: unknown): string {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw invalidIpc()
  const requestId = (input as { requestId?: unknown }).requestId
  if (typeof requestId !== 'string' || !REQUEST_ID.test(requestId)) throw invalidIpc()
  return requestId
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort()
  const sorted = [...expected].sort()
  return actual.length === sorted.length && actual.every((key, index) => key === sorted[index])
}

function sameOwner(event: IpcEvent, owner: Owner): boolean {
  return event.sender === owner.sender && event.senderFrame === owner.senderFrame
}

/** Register the only renderer-facing Engine transport channels. */
export function registerRendererEngineProxyIpc(
  ipc: RendererEngineIpcRegistrar,
  proxy: RendererEngineProxySurface,
  authorize: AuthorizeIpcSender
): () => void {
  if (
    !ipc ||
    typeof ipc.handle !== 'function' ||
    typeof ipc.on !== 'function' ||
    !proxy ||
    typeof proxy.request !== 'function' ||
    typeof proxy.stream !== 'function' ||
    typeof proxy.upload !== 'function' ||
    typeof proxy.cancel !== 'function' ||
    typeof authorize !== 'function'
  ) {
    throw new Error('Renderer Engine IPC dependencies are unavailable')
  }

  const owners = new Map<string, Owner>()
  const lifecycles = new Map<IpcSender, SenderLifecycle>()
  const streams = new Map<string, StreamFlow>()
  const uploads = new Map<string, UploadFlow>()

  const rejectStreamPending = (flow: StreamFlow, error = invalidIpc()): void => {
    const pending = flow.pending as StreamPending
    if (!pending) return
    flow.pending = null
    clearTimeout(pending.timer)
    pending.reject(error)
  }

  const rejectUploadPending = (flow: UploadFlow, error = invalidIpc()): void => {
    const pending = flow.pending
    if (!pending) return
    flow.pending = null
    clearTimeout(pending.timer)
    pending.signal.removeEventListener('abort', pending.abort)
    pending.reject(error)
  }

  const cancelBound = (requestId: string): void => {
    const stream = streams.get(requestId)
    if (stream) {
      stream.closed = true
      rejectStreamPending(stream)
    }
    const upload = uploads.get(requestId)
    if (upload) {
      upload.closed = true
      rejectUploadPending(upload)
    }
    proxy.cancel(requestId)
  }

  const cancelSender = (sender: IpcSender): void => {
    const lifecycle = lifecycles.get(sender)
    if (!lifecycle) return
    for (const requestId of [...lifecycle.requestIds]) cancelBound(requestId)
  }

  const bindOwner = (event: IpcEvent, requestId: string): (() => void) => {
    if (owners.has(requestId)) throw invalidIpc()
    const owner = Object.freeze({ sender: event.sender, senderFrame: event.senderFrame })
    owners.set(requestId, owner)
    let lifecycle = lifecycles.get(event.sender)
    if (!lifecycle) {
      const emitter = event.sender as IpcSender & LifecycleEmitter
      const destroyed = (): void => cancelSender(event.sender)
      const gone = (): void => cancelSender(event.sender)
      const navigation = (...args: unknown[]): void => {
        // Electron: event, url, isInPlace, isMainFrame.  Unknown shapes fail closed.
        if (args[3] !== false) cancelSender(event.sender)
      }
      lifecycle = { requestIds: new Set(), destroyed, gone, navigation }
      lifecycles.set(event.sender, lifecycle)
      emitter.on?.('destroyed', destroyed)
      emitter.on?.('render-process-gone', gone)
      emitter.on?.('did-start-navigation', navigation)
    }
    lifecycle.requestIds.add(requestId)
    return () => {
      if (owners.get(requestId) === owner) owners.delete(requestId)
      const current = lifecycles.get(event.sender)
      if (!current) return
      current.requestIds.delete(requestId)
      if (current.requestIds.size !== 0) return
      const emitter = event.sender as IpcSender & LifecycleEmitter
      emitter.removeListener?.('destroyed', current.destroyed)
      emitter.removeListener?.('render-process-gone', current.gone)
      emitter.removeListener?.('did-start-navigation', current.navigation)
      lifecycles.delete(event.sender)
    }
  }

  const requestHandler = async (
    event: IpcEvent,
    input?: unknown
  ): Promise<RendererEngineResponse> => {
    authorize(event)
    const requestId = requestIdOf(input)
    const value = input as Record<string, unknown>
    if (value.bodyKind === 'binary' || value.body instanceof Uint8Array) throw invalidIpc()
    const unbind = bindOwner(event, requestId)
    try {
      const result = await proxy.request(input as RendererEngineRequest)
      authorize(event)
      if (!sameOwner(event, owners.get(requestId) ?? Object.freeze({ sender: event.sender, senderFrame: null }))) {
        throw invalidIpc()
      }
      return result
    } finally {
      unbind()
    }
  }

  const sendStreamEvent = async (
    requestId: string,
    flow: StreamFlow,
    streamEvent: RendererEngineStreamEvent
  ): Promise<void> => {
    if (flow.closed || flow.pending) throw invalidIpc()
    const ownerEvent = { sender: flow.owner.sender, senderFrame: flow.owner.senderFrame }
    authorize(ownerEvent)
    const sequence = flow.nextSequence
    flow.nextSequence += 1
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        if (flow.pending?.sequence !== sequence) return
        flow.pending = null
        proxy.cancel(requestId)
        reject(invalidIpc())
      }, FLOW_ACK_TIMEOUT_MS)
      timer.unref()
      flow.pending = { sequence, resolve, reject, timer }
      try {
        flow.owner.sender.send(
          'engine:stream-event',
          streamEvent.kind === 'start'
            ? Object.freeze({ requestId, sequence, ...streamEvent })
            : Object.freeze({
                requestId,
                sequence,
                kind: 'chunk',
                chunk: Uint8Array.from(streamEvent.chunk)
              })
        )
      } catch {
        rejectStreamPending(flow)
      }
    })
    authorize(ownerEvent)
  }

  const streamHandler = async (
    event: IpcEvent,
    input?: unknown
  ): Promise<RendererEngineStreamResult> => {
    authorize(event)
    const requestId = requestIdOf(input)
    const unbind = bindOwner(event, requestId)
    const owner = owners.get(requestId) as Owner
    const flow: StreamFlow = { owner, nextSequence: 0, pending: null, closed: false }
    streams.set(requestId, flow)
    try {
      const result = await proxy.stream(
        input as RendererEngineRequest,
        (streamEvent: RendererEngineStreamEvent) => sendStreamEvent(requestId, flow, streamEvent)
      )
      authorize(event)
      if (!sameOwner(event, owner)) throw invalidIpc()
      return result
    } finally {
      flow.closed = true
      rejectStreamPending(flow)
      if (streams.get(requestId) === flow) streams.delete(requestId)
      unbind()
    }
  }

  const pullUploadChunk = (
    requestId: string,
    flow: UploadFlow,
    offset: number,
    maximumBytes: number,
    signal: AbortSignal
  ): Promise<Uint8Array> => {
    if (
      flow.closed ||
      flow.pending ||
      signal.aborted ||
      !Number.isSafeInteger(offset) ||
      offset < 0 ||
      !Number.isSafeInteger(maximumBytes) ||
      maximumBytes < 1 ||
      maximumBytes > FLOW_CHUNK_BYTES
    ) {
      return Promise.reject(invalidIpc())
    }
    const ownerEvent = { sender: flow.owner.sender, senderFrame: flow.owner.senderFrame }
    authorize(ownerEvent)
    const sequence = flow.nextSequence
    flow.nextSequence += 1
    return new Promise<Uint8Array>((resolve, reject) => {
      const abort = (): void => rejectUploadPending(flow)
      const timer = setTimeout(() => {
        if (flow.pending?.sequence !== sequence) return
        flow.pending = null
        signal.removeEventListener('abort', abort)
        proxy.cancel(requestId)
        reject(invalidIpc())
      }, FLOW_ACK_TIMEOUT_MS)
      timer.unref()
      flow.pending = {
        sequence,
        maximumBytes,
        signal,
        abort,
        resolve,
        reject,
        timer
      }
      signal.addEventListener('abort', abort, { once: true })
      try {
        flow.owner.sender.send(
          'engine:upload-credit',
          Object.freeze({ requestId, sequence, offset, maximumBytes })
        )
      } catch {
        rejectUploadPending(flow)
      }
    })
  }

  const uploadHandler = async (
    event: IpcEvent,
    input?: unknown
  ): Promise<RendererEngineResponse> => {
    authorize(event)
    const requestId = requestIdOf(input)
    const unbind = bindOwner(event, requestId)
    const owner = owners.get(requestId) as Owner
    const flow: UploadFlow = { owner, nextSequence: 0, pending: null, closed: false }
    uploads.set(requestId, flow)
    try {
      const result = await proxy.upload(
        input as RendererEngineUploadRequest,
        (offset, maximumBytes, signal) =>
          pullUploadChunk(requestId, flow, offset, maximumBytes, signal)
      )
      authorize(event)
      if (!sameOwner(event, owner)) throw invalidIpc()
      return result
    } finally {
      flow.closed = true
      rejectUploadPending(flow)
      if (uploads.get(requestId) === flow) uploads.delete(requestId)
      unbind()
    }
  }

  const streamAckListener = (event: IpcEvent, input?: unknown): void => {
    authorize(event)
    if (!input || typeof input !== 'object' || Array.isArray(input)) throw invalidIpc()
    const value = input as Record<string, unknown>
    if (
      !exactKeys(value, ['requestId', 'sequence']) ||
      typeof value.requestId !== 'string' ||
      !REQUEST_ID.test(value.requestId) ||
      !Number.isSafeInteger(value.sequence) ||
      Number(value.sequence) < 0
    ) {
      throw invalidIpc()
    }
    const flow = streams.get(value.requestId)
    if (!flow || !sameOwner(event, flow.owner) || flow.pending?.sequence !== value.sequence) {
      if (flow) cancelBound(value.requestId)
      throw invalidIpc()
    }
    const pending = flow.pending as StreamPending
    flow.pending = null
    clearTimeout(pending.timer)
    pending.resolve()
  }

  const uploadChunkListener = (event: IpcEvent, input?: unknown): void => {
    authorize(event)
    if (!input || typeof input !== 'object' || Array.isArray(input)) throw invalidIpc()
    const value = input as Record<string, unknown>
    if (
      !exactKeys(value, ['chunk', 'requestId', 'sequence']) ||
      typeof value.requestId !== 'string' ||
      !REQUEST_ID.test(value.requestId) ||
      !Number.isSafeInteger(value.sequence) ||
      Number(value.sequence) < 0 ||
      !(value.chunk instanceof Uint8Array)
    ) {
      throw invalidIpc()
    }
    const flow = uploads.get(value.requestId)
    const pending = flow?.pending
    if (
      !flow ||
      !pending ||
      !sameOwner(event, flow.owner) ||
      pending.sequence !== value.sequence ||
      value.chunk.byteLength !== pending.maximumBytes ||
      value.chunk.byteLength > FLOW_CHUNK_BYTES
    ) {
      if (flow) cancelBound(value.requestId)
      throw invalidIpc()
    }
    const accepted = pending as UploadPending
    flow.pending = null
    clearTimeout(accepted.timer)
    accepted.signal.removeEventListener('abort', accepted.abort)
    accepted.resolve(Uint8Array.from(value.chunk))
  }

  const cancelListener = (event: IpcEvent, input?: unknown): void => {
    authorize(event)
    if (typeof input !== 'string' || !REQUEST_ID.test(input)) throw invalidIpc()
    const owner = owners.get(input)
    if (owner && !sameOwner(event, owner)) throw invalidIpc()
    cancelBound(input)
  }

  ipc.handle('engine:request', requestHandler)
  ipc.handle('engine:stream', streamHandler)
  ipc.handle('engine:upload', uploadHandler)
  ipc.on('engine:stream-ack', streamAckListener)
  ipc.on('engine:upload-chunk', uploadChunkListener)
  ipc.on('engine:cancel', cancelListener)

  return () => {
    for (const requestId of owners.keys()) cancelBound(requestId)
    ipc.removeHandler('engine:request')
    ipc.removeHandler('engine:stream')
    ipc.removeHandler('engine:upload')
    ipc.removeListener('engine:stream-ack', streamAckListener)
    ipc.removeListener('engine:upload-chunk', uploadChunkListener)
    ipc.removeListener('engine:cancel', cancelListener)
  }
}
