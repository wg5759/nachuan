// ADR-0013 Web 形态：window.api 引擎代理四件套的 fetch 实现。
// 与 preload（desktop/src/preload/renderer-engine-bridge.ts）同名同形同语义：
// - request/upload：任何 HTTP 状态都照常返回 {status, contentType, body}，由渲染层判定；
// - stream：先 start 事件再逐 chunk 事件，逐条 await onEvent（信用纪律与 IPC 序列/ack 对齐），
//   完成时 resolve {status, contentType, bytes}；
// - cancel(requestId)：AbortController 按 requestId 注册表中止在途请求/流/上传。

import type {
  DesktopAPI,
  RendererEngineRequest,
  RendererEngineResponse,
  RendererEngineStreamEvent,
  RendererEngineStreamResult,
  RendererEngineUploadRequest
} from '../renderer/src/env'
import { isRendererEngineRequestId } from '../renderer-engine-contract'
import type { WebHttpClient } from './http'

const UPLOAD_CREDIT_BYTES = 64 * 1024

type EngineBridge = Pick<
  DesktopAPI,
  'engineRequest' | 'engineStream' | 'engineUpload' | 'cancelEngineRequest'
>

function checkRequest(input: RendererEngineRequest): void {
  if (
    !input ||
    typeof input !== 'object' ||
    !isRendererEngineRequestId(input.requestId) ||
    (input.method !== 'GET' && input.method !== 'POST') ||
    (input.bodyKind !== 'none' && input.bodyKind !== 'json') ||
    (input.bodyKind === 'none' && input.body !== undefined) ||
    (input.bodyKind === 'json' && typeof input.body !== 'string')
  ) {
    throw new Error('Invalid Renderer Engine request')
  }
}

function checkUploadInput(input: RendererEngineUploadRequest): void {
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
}

function abortError(): DOMException {
  return new DOMException('The operation was aborted', 'AbortError')
}

export function createWebEngineBridge(http: WebHttpClient): EngineBridge {
  const inflight = new Map<string, AbortController>()

  function register(requestId: string): AbortController {
    cancel(requestId)
    const controller = new AbortController()
    inflight.set(requestId, controller)
    return controller
  }

  function release(requestId: string, controller: AbortController): void {
    if (inflight.get(requestId) === controller) inflight.delete(requestId)
  }

  function cancel(requestId: string): void {
    if (!isRendererEngineRequestId(requestId)) return
    inflight.get(requestId)?.abort()
    inflight.delete(requestId)
  }

  async function engineRequest(input: RendererEngineRequest): Promise<RendererEngineResponse> {
    checkRequest(input)
    const controller = register(input.requestId)
    try {
      return await http.request({
        method: input.method,
        target: input.target,
        ...(input.bodyKind === 'json'
          ? { body: input.body, contentType: 'application/json' }
          : {}),
        signal: controller.signal
      })
    } finally {
      release(input.requestId, controller)
    }
  }

  async function engineStream(
    input: RendererEngineRequest,
    onEvent: (event: RendererEngineStreamEvent) => void | Promise<void>
  ): Promise<RendererEngineStreamResult> {
    checkRequest(input)
    if (input.responseKind === 'json' || typeof onEvent !== 'function') {
      throw new Error('Invalid Renderer Engine stream request')
    }
    const controller = register(input.requestId)
    try {
      const response = await http.open({
        method: input.method,
        target: input.target,
        ...(input.bodyKind === 'json'
          ? { body: input.body, contentType: 'application/json' }
          : {}),
        signal: controller.signal
      })
      const contentType = response.headers.get('content-type') ?? ''
      await onEvent(
        Object.freeze({ kind: 'start' as const, status: response.status, contentType })
      )
      let bytes = 0
      const reader = response.body?.getReader()
      if (reader) {
        for (;;) {
          if (controller.signal.aborted) throw abortError()
          const { done, value } = await reader.read()
          if (done) break
          if (!value || value.byteLength === 0) continue
          bytes += value.byteLength
          await onEvent(Object.freeze({ kind: 'chunk' as const, chunk: Uint8Array.from(value) }))
        }
      }
      return Object.freeze({ status: response.status, contentType, bytes })
    } finally {
      release(input.requestId, controller)
    }
  }

  async function engineUpload(
    input: RendererEngineUploadRequest,
    readChunk: (offset: number, maximumBytes: number) => Uint8Array | Promise<Uint8Array>
  ): Promise<RendererEngineResponse> {
    checkUploadInput(input)
    if (typeof readChunk !== 'function') {
      throw new Error('Invalid Renderer Engine upload request')
    }
    const controller = register(input.requestId)
    try {
      const body = new Uint8Array(input.bodyLength)
      let offset = 0
      while (offset < input.bodyLength) {
        if (controller.signal.aborted) throw abortError()
        const maximumBytes = Math.min(UPLOAD_CREDIT_BYTES, input.bodyLength - offset)
        const chunk = await readChunk(offset, maximumBytes)
        if (!(chunk instanceof Uint8Array) || chunk.byteLength !== maximumBytes) {
          throw new Error('Invalid Renderer Engine upload chunk')
        }
        body.set(chunk, offset)
        offset += chunk.byteLength
      }
      return await http.request({
        method: 'POST',
        target: input.target,
        body: body.buffer,
        contentType: 'application/octet-stream',
        signal: controller.signal
      })
    } finally {
      release(input.requestId, controller)
    }
  }

  return Object.freeze({
    engineRequest,
    engineStream,
    engineUpload,
    cancelEngineRequest: cancel
  })
}
