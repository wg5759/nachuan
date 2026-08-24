import { beforeEach, describe, expect, it, vi } from 'vitest'

import { createCredentialStore, type KeyValueStorage } from '../../web-shim/credentials'
import { createWebHttpClient } from '../../web-shim/http'
import { createWebPaidMediaApi } from '../../web-shim/paid-media'

const OPERATION_ID = 'desktop-op-11111111-1111-4111-8111-111111111111'
const ASSET_BYTES = new TextEncoder().encode('private-image-bytes')
const ASSET_SHA256 = 'b86a89c0eda0e9381e785564df9dc33f88d96e04aae6fa6185c9c94de2652520'
const DURABLE_IMAGE_REF = `nachuan-paid-media://sha256/${ASSET_SHA256}`
const DELIVERY_PROOF = {
  operationId: OPERATION_ID,
  resultSha256: 'a'.repeat(64),
  archiveReceiptSha256: 'b'.repeat(64)
}

function fakeStorage(): Storage {
  const values = new Map<string, string>()
  return {
    get length() {
      return values.size
    },
    clear: vi.fn(() => values.clear()),
    getItem: vi.fn((key: string) => values.get(key) ?? null),
    key: vi.fn((index: number) => [...values.keys()][index] ?? null),
    removeItem: vi.fn((key: string) => values.delete(key)),
    setItem: vi.fn((key: string, value: string) => values.set(key, value))
  }
}

function jsonResponse(value: unknown): Response {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: { 'content-type': 'application/json' }
  })
}

describe('Web paid-media consent chain', () => {
  beforeEach(() => {
    vi.resetModules()
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  it('confirms the exact image request before claim and keeps execute consent-free', async () => {
    const events: string[] = []
    const requests: Array<{ target: string; body: unknown }> = []
    const storage = fakeStorage()
    storage.setItem('nachuan.web.runtimeKey', 'runtime-key')
    storage.setItem('nachuan.web.approvalKey', 'approval-key')

    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const target = String(input)
      const verb = target.split('/').at(-1) ?? ''
      const body = init?.body === undefined ? undefined : JSON.parse(String(init.body))
      events.push(verb)
      requests.push({ target, body })
      if (verb === 'claim') {
        return jsonResponse({
          operationId: OPERATION_ID,
          path: '/v1/images/generations',
          state: 'claimed',
          createdAt: 1_750_000_000_000,
          updatedAt: 1_750_000_000_001,
          dispatchCount: 0
        })
      }
      if (verb === 'execute') {
        return jsonResponse({
          ok: true,
          status: 200,
          result: { data: [{ url: DURABLE_IMAGE_REF }] },
          operation: {
            operationId: OPERATION_ID,
            path: '/v1/images/generations',
            state: 'result_ready',
            createdAt: 1_750_000_000_000,
            updatedAt: 1_750_000_000_002,
            dispatchCount: 1
          },
          deliveryProof: DELIVERY_PROOF
        })
      }
      if (verb === 'read-asset') {
        return new Response(ASSET_BYTES, {
          status: 200,
          headers: {
            'content-type': 'image/png',
            'content-length': String(ASSET_BYTES.byteLength),
            'x-content-sha256': ASSET_SHA256
          }
        })
      }
      return jsonResponse({ ok: true })
    })
    const confirm = vi.fn(() => {
      events.push('confirm')
      return true
    })
    const credentials = createCredentialStore(() => storage as KeyValueStorage)
    const http = createWebHttpClient({
      credentials,
      fetchImpl: fetchMock as unknown as typeof fetch,
      onConsecutiveUnauthorized: vi.fn()
    })
    vi.stubGlobal('localStorage', storage)
    vi.stubGlobal('confirm', confirm)
    vi.stubGlobal('window', { api: createWebPaidMediaApi(http) })

    const { generateImage } = await import('./api')
    await expect(
      generateImage('image-model', 'river', undefined, {
        onResultDurablyCommitted: () => {
          events.push('durable-callback')
          return true
        }
      })
    ).resolves.toEqual([DURABLE_IMAGE_REF])

    const claim = requests.find((request) => request.target.endsWith('/claim'))
    const execute = requests.find((request) => request.target.endsWith('/execute'))
    expect(confirm).toHaveBeenCalledTimes(1)
    expect(events.indexOf('confirm')).toBeLessThan(events.indexOf('claim'))
    expect(events.indexOf('execute')).toBeLessThan(events.indexOf('read-asset'))
    expect(events.indexOf('read-asset')).toBeLessThan(events.indexOf('durable-callback'))
    expect(events.indexOf('durable-callback')).toBeLessThan(events.indexOf('acknowledge'))
    expect(claim?.body).toEqual({
      path: '/v1/images/generations',
      encodedBody: '{"model":"image-model","prompt":"river"}',
      user_confirmed: true,
      confirm_summary_sha256: 'b2f4c533ccb517b7889ed4880feec904709e5d1fcd25418c6a3253ca33b90a14'
    })
    expect(execute?.body).toEqual({
      operationId: OPERATION_ID,
      path: '/v1/images/generations',
      encodedBody: '{"model":"image-model","prompt":"river"}'
    })
    expect(requests.find((request) => request.target.endsWith('/read-asset'))?.body).toEqual({
      reference: DURABLE_IMAGE_REF
    })
  })

  it('confirms one fresh agnes-video request exactly once before one claim and execute', async () => {
    const events: string[] = []
    const requests: Array<{ verb: string; body: unknown }> = []
    const storage = fakeStorage()
    storage.setItem('nachuan.web.runtimeKey', 'runtime-key')
    storage.setItem('nachuan.web.approvalKey', 'approval-key')
    const taskAlias = `nvt1_${'c'.repeat(64)}`
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const verb = String(input).split('/').at(-1) ?? ''
      const body = init?.body === undefined ? undefined : JSON.parse(String(init.body))
      events.push(verb)
      requests.push({ verb, body })
      if (verb === 'claim') {
        return jsonResponse({
          operationId: OPERATION_ID,
          path: '/v1/videos/generations',
          state: 'claimed',
          createdAt: 1,
          updatedAt: 1,
          dispatchCount: 0
        })
      }
      if (verb === 'execute') {
        return jsonResponse({
          ok: true,
          status: 200,
          result: { task_id: taskAlias },
          operation: {
            operationId: OPERATION_ID,
            path: '/v1/videos/generations',
            state: 'result_ready',
            createdAt: 1,
            updatedAt: 2,
            dispatchCount: 1
          },
          deliveryProof: DELIVERY_PROOF
        })
      }
      return jsonResponse({ ok: true })
    })
    const confirm = vi.fn(() => {
      events.push('confirm')
      return true
    })
    const committed = vi.fn(() => {
      events.push('durable-callback')
      return true
    })
    const http = createWebHttpClient({
      credentials: createCredentialStore(() => storage as KeyValueStorage),
      fetchImpl: fetchMock as unknown as typeof fetch,
      onConsecutiveUnauthorized: vi.fn()
    })
    vi.stubGlobal('localStorage', storage)
    vi.stubGlobal('confirm', confirm)
    vi.stubGlobal('window', { api: createWebPaidMediaApi(http) })

    const { createVideo } = await import('./api')
    await expect(
      createVideo('agnes-video', '一只橘猫在窗边眨眼，镜头固定。', undefined, undefined, {
        onResultDurablyCommitted: committed
      })
    ).resolves.toEqual({ task_id: taskAlias })

    expect(confirm).toHaveBeenCalledTimes(1)
    expect(requests.filter(({ verb }) => verb === 'claim')).toHaveLength(1)
    expect(requests.filter(({ verb }) => verb === 'execute')).toHaveLength(1)
    expect(requests.filter(({ verb }) => verb === 'acknowledge')).toHaveLength(1)
    expect(
      events.filter((event) =>
        ['confirm', 'claim', 'execute', 'durable-callback', 'acknowledge'].includes(event)
      )
    ).toEqual(['confirm', 'claim', 'execute', 'durable-callback', 'acknowledge'])
    expect(requests.find(({ verb }) => verb === 'claim')?.body).toEqual({
      path: '/v1/videos/generations',
      encodedBody:
        '{"model":"agnes-video","prompt":"一只橘猫在窗边眨眼，镜头固定。"}',
      user_confirmed: true,
      confirm_summary_sha256: 'cb2698aa7cf3d14b35c6dcda6d88576c6fadcc0cd98ad4806a0de187194c1c68'
    })
    expect(requests.find(({ verb }) => verb === 'execute')?.body).toEqual({
      operationId: OPERATION_ID,
      path: '/v1/videos/generations',
      encodedBody:
        '{"model":"agnes-video","prompt":"一只橘猫在窗边眨眼，镜头固定。"}'
    })
  })

  it('creates no paid-video operation when the native confirmation is declined', async () => {
    const verbs: string[] = []
    const storage = fakeStorage()
    storage.setItem('nachuan.web.runtimeKey', 'runtime-key')
    storage.setItem('nachuan.web.approvalKey', 'approval-key')
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      verbs.push(String(input).split('/').at(-1) ?? '')
      return jsonResponse({ ok: true })
    })
    const confirm = vi.fn(() => false)
    const http = createWebHttpClient({
      credentials: createCredentialStore(() => storage as KeyValueStorage),
      fetchImpl: fetchMock as unknown as typeof fetch,
      onConsecutiveUnauthorized: vi.fn()
    })
    vi.stubGlobal('localStorage', storage)
    vi.stubGlobal('confirm', confirm)
    vi.stubGlobal('window', { api: createWebPaidMediaApi(http) })

    const { createVideo } = await import('./api')
    await expect(
      createVideo('agnes-video', '一只橘猫在窗边眨眼，镜头固定。')
    ).rejects.toThrow(/not confirmed/i)

    expect(confirm).toHaveBeenCalledTimes(1)
    expect(verbs).not.toContain('claim')
    expect(verbs).not.toContain('execute')
    expect(verbs).not.toContain('acknowledge')
  })

  it('does not durably commit or acknowledge when Web asset materialization fails', async () => {
    const storage = fakeStorage()
    storage.setItem('nachuan.web.runtimeKey', 'runtime-key')
    storage.setItem('nachuan.web.approvalKey', 'approval-key')
    const targets: string[] = []
    const badReference = `nachuan-paid-media://sha256/${'a'.repeat(64)}`
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const target = String(input)
      const verb = target.split('/').at(-1) ?? ''
      targets.push(verb)
      if (verb === 'claim') {
        return jsonResponse({
          operationId: OPERATION_ID,
          path: '/v1/images/generations',
          state: 'claimed',
          createdAt: 1,
          updatedAt: 1,
          dispatchCount: 0
        })
      }
      if (verb === 'execute') {
        return jsonResponse({
          ok: true,
          status: 200,
          result: { data: [{ url: badReference }] },
          operation: {},
          deliveryProof: DELIVERY_PROOF
        })
      }
      if (verb === 'read-asset') {
        const wrong = new TextEncoder().encode('wrong materialized bytes')
        return new Response(wrong, {
          status: 200,
          headers: {
            'content-type': 'image/png',
            'content-length': String(wrong.byteLength),
            'x-content-sha256': 'a'.repeat(64)
          }
        })
      }
      return jsonResponse({ ok: true })
    })
    const http = createWebHttpClient({
      credentials: createCredentialStore(() => storage as KeyValueStorage),
      fetchImpl: fetchMock as unknown as typeof fetch,
      onConsecutiveUnauthorized: vi.fn()
    })
    const committed = vi.fn(() => true)
    vi.stubGlobal('localStorage', storage)
    vi.stubGlobal('confirm', vi.fn(() => true))
    vi.stubGlobal('window', { api: createWebPaidMediaApi(http) })

    const { generateImage } = await import('./api')
    await expect(
      generateImage('image-model', 'river', undefined, {
        onResultDurablyCommitted: committed
      })
    ).rejects.toThrow(/dispatch failed safely/i)

    expect(targets).toContain('read-asset')
    expect(targets).not.toContain('acknowledge')
    expect(committed).not.toHaveBeenCalled()
  })

  it.each([
    ['the first confirmation', [false]],
    ['the final confirmation', [true, false]]
  ])('treats cancelling %s as a normal journal cancellation', async (_label, answers) => {
    const storage = fakeStorage()
    storage.setItem('nachuan.web.runtimeKey', 'runtime-key')
    storage.setItem('nachuan.web.approvalKey', 'approval-key')
    const targets: string[] = []
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      targets.push(String(input))
      return jsonResponse({ ok: true })
    })
    const confirm = vi.fn(() => answers.shift() ?? false)
    const credentials = createCredentialStore(() => storage as KeyValueStorage)
    const http = createWebHttpClient({
      credentials,
      fetchImpl: fetchMock as unknown as typeof fetch,
      onConsecutiveUnauthorized: vi.fn()
    })
    vi.stubGlobal('localStorage', storage)
    vi.stubGlobal('confirm', confirm)
    vi.stubGlobal('window', { api: createWebPaidMediaApi(http) })

    const { discardPendingPaidMediaOperation } = await import('./paid-media-journal')
    await expect(
      discardPendingPaidMediaOperation(OPERATION_ID, 'provider receipt checked')
    ).resolves.toBe(false)

    expect(targets.some((target) => target.endsWith('/reconcile'))).toBe(false)
  })
})
