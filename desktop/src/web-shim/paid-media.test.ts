import { beforeEach, describe, expect, it, vi, type Mock } from 'vitest'

import { createCredentialStore, type KeyValueStorage } from './credentials'
import { createWebHttpClient, WebHttpError } from './http'
import { createWebPaidMediaApi, WebPaidMediaConsentError } from './paid-media'

const data: Record<string, string> = {}
const storage: KeyValueStorage = {
  getItem: (key: string) => (key in data ? data[key] : null),
  setItem: (key: string, value: string) => {
    data[key] = value
  },
  removeItem: (key: string) => {
    delete data[key]
  }
}

let fetchMock: ReturnType<typeof vi.fn>
let onUnauthorized: Mock<() => void>

function api() {
  const http = createWebHttpClient({
    credentials: createCredentialStore(() => storage),
    fetchImpl: fetchMock as unknown as typeof fetch,
    onConsecutiveUnauthorized: () => onUnauthorized()
  })
  return createWebPaidMediaApi(http)
}

function lastCall(): [string, RequestInit] {
  return fetchMock.mock.calls[fetchMock.mock.calls.length - 1] as unknown as [string, RequestInit]
}

async function digestHex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', bytes.buffer as ArrayBuffer)
  return [...new Uint8Array(digest)].map((value) => value.toString(16).padStart(2, '0')).join('')
}

beforeEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
  for (const key of Object.keys(data)) delete data[key]
  data['nachuan.web.runtimeKey'] = 'runtime-key'
  onUnauthorized = vi.fn()
  vi.stubGlobal('confirm', vi.fn(() => true))
  fetchMock = vi.fn(
    async () => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } })
  )
})

describe('web-shim paid media verbs', () => {
  it('verifies durable references before returning success but materializes blobs only on demand', async () => {
    const bytes = new TextEncoder().encode('private-asset-bytes')
    const sha256 = await digestHex(bytes)
    const reference = `nachuan-paid-media://sha256/${sha256}`
    const createObjectURL = vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:paid-media-test')
    const revokeObjectURL = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {})
    fetchMock.mockImplementation(async (target: string, init?: RequestInit) => {
      if (target === '/v1/paid-media/web/read-asset') {
        expect(JSON.parse(String(init?.body))).toEqual({ reference })
        expect((init?.headers as Record<string, string>)['Authorization']).toBe(
          'Bearer runtime-key'
        )
        expect((init?.headers as Record<string, string>)['X-Nachuan-Approval-Key']).toBeUndefined()
        return new Response(bytes, {
          status: 200,
          headers: {
            'content-type': 'image/png',
            'content-length': String(bytes.byteLength),
            'x-content-sha256': sha256
          }
        })
      }
      return new Response(
        JSON.stringify({
          ok: true,
          status: 200,
          result: { data: [{ url: reference }] },
          operation: {},
          deliveryProof: {}
        }),
        { status: 200, headers: { 'content-type': 'application/json' } }
      )
    })
    const subject = api()

    const result = await subject.executePaidMedia({
      operationId: 'op-1',
      path: '/v1/images/generations',
      encodedBody: '{}'
    })

    expect(fetchMock.mock.calls.map((call) => call[0])).toEqual([
      '/v1/paid-media/web/execute',
      '/v1/paid-media/web/read-asset'
    ])
    expect(result).toMatchObject({ result: { data: [{ url: reference }] } })
    expect(JSON.stringify(fetchMock.mock.calls)).not.toContain('nma1_')
    expect(createObjectURL).not.toHaveBeenCalled()
    expect(await subject.resolvePaidMediaAsset?.(reference)).toBe('blob:paid-media-test')
    expect(await subject.resolvePaidMediaAsset?.(reference)).toBe('blob:paid-media-test')
    expect(fetchMock).toHaveBeenCalledTimes(3)
    expect(createObjectURL).toHaveBeenCalledTimes(1)

    subject.releasePaidMediaAsset?.(reference)
    await Promise.resolve()
    expect(revokeObjectURL).not.toHaveBeenCalled()
    subject.releasePaidMediaAsset?.(reference)
    await Promise.resolve()
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:paid-media-test')
  })

  it('verifies multiple result assets sequentially instead of competing for the byte budget', async () => {
    const bodies = [new Uint8Array([71]), new Uint8Array([72])]
    const references = await Promise.all(
      bodies.map(async (bytes) => `nachuan-paid-media://sha256/${await digestHex(bytes)}`)
    )
    const readResolvers: Array<(response: Response) => void> = []
    fetchMock.mockImplementation(async (target: string) => {
      if (target.endsWith('/execute')) {
        return new Response(
          JSON.stringify({
            ok: true,
            status: 200,
            result: { data: references.map((url) => ({ url })) },
            operation: {},
            deliveryProof: {}
          }),
          { status: 200, headers: { 'content-type': 'application/json' } }
        )
      }
      return await new Promise<Response>((resolve) => readResolvers.push(resolve))
    })
    const verified = api().executePaidMedia({
      operationId: 'op-multi-2',
      path: '/v1/images/generations',
      encodedBody: '{}'
    })
    await vi.waitFor(() => expect(readResolvers).toHaveLength(1))
    readResolvers.shift()?.(
      new Response(bodies[0], {
        status: 200,
        headers: {
          'content-type': 'image/png',
          'content-length': '1',
          'x-content-sha256': references[0].slice(-64)
        }
      })
    )
    await vi.waitFor(() => expect(readResolvers).toHaveLength(1))
    readResolvers.shift()?.(
      new Response(bodies[1], {
        status: 200,
        headers: {
          'content-type': 'image/png',
          'content-length': '1',
          'x-content-sha256': references[1].slice(-64)
        }
      })
    )
    await expect(verified).resolves.toMatchObject({ ok: true })
  })

  it('limits paid-media blob materialization to two concurrent asset reads', async () => {
    const bodies = [1, 2, 3].map((value) => new Uint8Array([value]))
    const references = await Promise.all(
      bodies.map(async (bytes) => `nachuan-paid-media://sha256/${await digestHex(bytes)}`)
    )
    const pending = new Map<string, (response: Response) => void>()
    fetchMock.mockImplementation(
      async (_target: string, init?: RequestInit) =>
        await new Promise<Response>((resolve) => {
          pending.set(JSON.parse(String(init?.body)).reference, resolve)
        })
    )
    vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:concurrent-paid-media')
    vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {})
    const subject = api()

    const resolutions = references.map((reference) => subject.resolvePaidMediaAsset(reference))
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2))
    expect(pending.has(references[2])).toBe(false)

    for (let index = 0; index < references.length; index += 1) {
      const bytes = bodies[index]
      const reference = references[index]
      await vi.waitFor(() => expect(pending.has(reference)).toBe(true))
      pending.get(reference)?.(
        new Response(bytes, {
          status: 200,
          headers: {
            'content-type': 'image/png',
            'content-length': String(bytes.byteLength),
            'x-content-sha256': reference.slice(-64)
          }
        })
      )
      await resolutions[index]
    }
    expect(fetchMock).toHaveBeenCalledTimes(3)
    for (const reference of references) subject.releasePaidMediaAsset(reference)
  })

  it('keeps a ninth owned blob waiting until an existing cache slot is released', async () => {
    const bodies = Array.from({ length: 9 }, (_, index) => new Uint8Array([index + 1]))
    const references = await Promise.all(
      bodies.map(async (bytes) => `nachuan-paid-media://sha256/${await digestHex(bytes)}`)
    )
    const responseByReference = new Map(
      references.map((reference, index) => [reference, bodies[index]] as const)
    )
    fetchMock.mockImplementation(async (_target: string, init?: RequestInit) => {
      const reference = JSON.parse(String(init?.body)).reference as string
      const bytes = responseByReference.get(reference)!
      return new Response(bytes, {
        status: 200,
        headers: {
          'content-type': 'image/png',
          'content-length': String(bytes.byteLength),
          'x-content-sha256': reference.slice(-64)
        }
      })
    })
    vi.spyOn(URL, 'createObjectURL').mockImplementation((_blob) => `blob:${Math.random()}`)
    vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {})
    const subject = api()

    for (const reference of references.slice(0, 8)) {
      await subject.resolvePaidMediaAsset(reference)
    }
    const ninth = subject.resolvePaidMediaAsset(references[8])
    const sameNinth = subject.resolvePaidMediaAsset(references[8])
    await new Promise((resolve) => setTimeout(resolve, 0))
    expect(fetchMock).toHaveBeenCalledTimes(8)
    subject.releasePaidMediaAsset(references[0])
    await expect(ninth).resolves.toMatch(/^blob:/)
    await expect(sameNinth).resolves.toMatch(/^blob:/)
    expect(fetchMock).toHaveBeenCalledTimes(9)

    for (const reference of references.slice(1)) subject.releasePaidMediaAsset(reference)
    subject.releasePaidMediaAsset(references[8])
  })

  it('resumes a byte-budget-blocked materialization after an owned blob is released', async () => {
    const firstBytes = new Uint8Array(17 * 1024 * 1024)
    firstBytes[firstBytes.length - 1] = 1
    const firstReference = `nachuan-paid-media://sha256/${await digestHex(firstBytes)}`
    const secondBytes = new Uint8Array(16 * 1024 * 1024)
    secondBytes[secondBytes.length - 1] = 2
    const secondReference = `nachuan-paid-media://sha256/${await digestHex(secondBytes)}`
    fetchMock.mockImplementation(async (_target: string, init?: RequestInit) => {
      const reference = JSON.parse(String(init?.body)).reference as string
      const isFirst = reference === firstReference
      const bytes = isFirst ? firstBytes : secondBytes
      return new Response(bytes, {
        status: 200,
        headers: {
          'content-type': 'image/png',
          'content-length': String(bytes.byteLength),
          'x-content-sha256': isFirst ? firstReference.slice(-64) : secondReference.slice(-64)
        }
      })
    })
    vi.spyOn(URL, 'createObjectURL')
      .mockReturnValueOnce('blob:large-first')
      .mockReturnValueOnce('blob:large-second')
    vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {})
    const subject = api()

    await expect(subject.resolvePaidMediaAsset(firstReference)).resolves.toBe('blob:large-first')
    let secondSettled = false
    const second = subject.resolvePaidMediaAsset(secondReference).finally(() => {
      secondSettled = true
    })
    await new Promise((resolve) => setTimeout(resolve, 0))
    expect(secondSettled).toBe(false)
    subject.releasePaidMediaAsset(firstReference)
    await expect(second).resolves.toBe('blob:large-second')
    subject.releasePaidMediaAsset(secondReference)
  })

  it('does not hand out a revoked blob when release is immediately followed by reacquire', async () => {
    const bytes = new Uint8Array([42])
    const reference = `nachuan-paid-media://sha256/${await digestHex(bytes)}`
    fetchMock.mockImplementation(
      async () => new Response(bytes, {
        status: 200,
        headers: {
          'content-type': 'image/png',
          'content-length': '1',
          'x-content-sha256': reference.slice(-64)
        }
      })
    )
    const createObjectURL = vi
      .spyOn(URL, 'createObjectURL')
      .mockReturnValueOnce('blob:first')
      .mockReturnValueOnce('blob:second')
    const revokeObjectURL = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {})
    const subject = api()

    await expect(subject.resolvePaidMediaAsset(reference)).resolves.toBe('blob:first')
    subject.releasePaidMediaAsset(reference)
    await expect(subject.resolvePaidMediaAsset(reference)).resolves.toBe('blob:second')

    expect(revokeObjectURL).toHaveBeenCalledWith('blob:first')
    expect(createObjectURL).toHaveBeenCalledTimes(2)
    subject.releasePaidMediaAsset(reference)
  })

  it('preserves owned blobs across BFCache pagehide and disposes them on final pagehide', async () => {
    let pagehide: ((event: Event) => void) | undefined
    vi.stubGlobal(
      'addEventListener',
      vi.fn((type: string, listener: EventListener) => {
        if (type === 'pagehide') pagehide = listener
      })
    )
    const bytes = new Uint8Array([91])
    const reference = `nachuan-paid-media://sha256/${await digestHex(bytes)}`
    fetchMock.mockImplementation(
      async () => new Response(bytes, {
        status: 200,
        headers: {
          'content-type': 'image/png',
          'content-length': '1',
          'x-content-sha256': reference.slice(-64)
        }
      })
    )
    vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:bfcache')
    const revokeObjectURL = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {})
    const subject = api()
    await subject.resolvePaidMediaAsset(reference)

    pagehide?.({ persisted: true } as unknown as Event)
    await Promise.resolve()
    expect(revokeObjectURL).not.toHaveBeenCalled()
    pagehide?.({ persisted: false } as unknown as Event)
    await Promise.resolve()
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:bfcache')
  })

  it('rejects a materialized asset whose bytes do not match the durable reference', async () => {
    const reference = `nachuan-paid-media://sha256/${'a'.repeat(64)}`
    const bytes = new TextEncoder().encode('wrong bytes')
    fetchMock.mockImplementation(async (target: string) => {
      if (target === '/v1/paid-media/web/read-asset') {
        return new Response(bytes, {
          status: 200,
          headers: {
            'content-type': 'image/png',
            'content-length': String(bytes.byteLength),
            'x-content-sha256': 'a'.repeat(64)
          }
        })
      }
      return new Response(
        JSON.stringify({
          ok: true,
          status: 200,
          result: { data: [{ url: reference }] },
          operation: {},
          deliveryProof: {}
        }),
        { status: 200, headers: { 'content-type': 'application/json' } }
      )
    })

    await expect(
      api().executePaidMedia({
        operationId: 'op-1',
        path: '/v1/images/generations',
        encodedBody: '{}'
      })
    ).rejects.toThrow(/digest/i)
  })

  it('requires two user confirmations before posting a reconciliation', async () => {
    data['nachuan.web.approvalKey'] = 'approval-key'
    const confirm = globalThis.confirm as unknown as Mock<(message?: string) => boolean>

    await api().reconcilePaidMedia({ operationId: 'op-4', reason: 'manual', evidence: 'receipt' })

    expect(confirm).toHaveBeenCalledTimes(2)
    expect(JSON.parse(String(lastCall()[1].body))).toEqual({
      operationId: 'op-4',
      reason: 'manual',
      evidence: 'receipt',
      user_confirmed: true,
      confirm_final: true
    })
  })

  it('claims a paid media operation via POST /v1/paid-media/web/claim', async () => {
    await api().claimPaidMedia({ path: '/v1/images/generations', encodedBody: '{"prompt":"x"}' })
    const [target, init] = lastCall()
    expect(target).toBe('/v1/paid-media/web/claim')
    expect(init.method).toBe('POST')
    expect(JSON.parse(String(init.body))).toEqual({
      path: '/v1/images/generations',
      encodedBody: '{"prompt":"x"}',
      user_confirmed: true,
      confirm_summary_sha256: 'f7d68f03847607a63b85450562063da6c9c9c05f8a5dafeed51d3850eb8d12ae'
    })
    // 运行时 Bearer 仍随附；付费 Key 永不经过本层。
    expect((init.headers as Record<string, string>)['Authorization']).toBe('Bearer runtime-key')
  })

  it('summarizes nested paid-video billing inputs without echoing image payloads', async () => {
    const encodedBody =
      '{"model":"video-model","prompt":"animate","extra_body":{"image":["SENSITIVE-IMAGE-PAYLOAD-A","SENSITIVE-IMAGE-PAYLOAD-B"],"mode":"keyframes","duration":8,"resolution":"1080p","frame_rate":24}}'
    const confirm = globalThis.confirm as unknown as Mock<(message?: string) => boolean>

    await api().claimPaidMedia({ path: '/v1/videos/generations', encodedBody })

    const message = String(confirm.mock.calls[0]?.[0])
    expect(message).toContain('extra_body.image count: 2')
    expect(message).toContain('extra_body.mode: keyframes')
    expect(message).toContain('extra_body.duration: 8')
    expect(message).toContain('extra_body.resolution: 1080p')
    expect(message).toContain('extra_body.frame_rate: 24')
    expect(message).not.toContain('SENSITIVE-IMAGE-PAYLOAD-A')
    expect(message).not.toContain('SENSITIVE-IMAGE-PAYLOAD-B')
    expect(JSON.parse(String(lastCall()[1].body))).toMatchObject({ encodedBody })
  })

  it('does not create a paid operation when the user declines', async () => {
    const confirm = vi.fn(() => false)
    vi.stubGlobal('confirm', confirm)

    await expect(
      api().claimPaidMedia({ path: '/v1/images/generations', encodedBody: '{}' })
    ).rejects.toBeInstanceOf(WebPaidMediaConsentError)

    expect(confirm).toHaveBeenCalledTimes(1)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('reuses a retry operation without asking for new consent', async () => {
    const confirm = vi.fn(() => false)
    vi.stubGlobal('confirm', confirm)

    await api().claimPaidMedia({
      path: '/v1/images/generations',
      encodedBody: '{}',
      retryOperationId: 'desktop-op-123e4567-e89b-42d3-a456-426614174000'
    })

    expect(confirm).not.toHaveBeenCalled()
    expect(JSON.parse(String(lastCall()[1].body))).toEqual({
      path: '/v1/images/generations',
      encodedBody: '{}',
      retryOperationId: 'desktop-op-123e4567-e89b-42d3-a456-426614174000'
    })
  })

  it.each([
    ['the first confirmation', [false]],
    ['the final confirmation', [true, false]]
  ])('does not reconcile when the user rejects %s', async (_label, answers) => {
    const confirm = vi.fn(() => answers.shift() ?? false)
    vi.stubGlobal('confirm', confirm)

    await expect(
      api().reconcilePaidMedia({ operationId: 'op-4', reason: 'manual', evidence: 'receipt' })
    ).rejects.toBeInstanceOf(WebPaidMediaConsentError)

    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('maps every verb to its route with the expected payload shape', async () => {
    const subject = api()
    const proof = {
      operationId: 'desktop-op-123e4567-e89b-42d3-a456-426614174000',
      resultSha256: 'a'.repeat(64),
      archiveReceiptSha256: 'b'.repeat(64)
    }

    await subject.executePaidMedia({
      operationId: 'op-1',
      path: '/v1/videos/generations',
      encodedBody: '{}'
    })
    expect(lastCall()[0]).toBe('/v1/paid-media/web/execute')
    expect(JSON.parse(String(lastCall()[1].body))).toEqual({
      operationId: 'op-1',
      path: '/v1/videos/generations',
      encodedBody: '{}'
    })

    await subject.pollPaidVideo({ taskAlias: 'task-1', model: 'm' })
    expect(lastCall()[0]).toBe('/v1/paid-media/web/poll-video')

    await subject.recoverPaidMediaArchive('op-2')
    expect(lastCall()[0]).toBe('/v1/paid-media/web/recover-archive')
    expect(JSON.parse(String(lastCall()[1].body))).toEqual({ operationId: 'op-2' })

    await subject.listPaidMediaArchives({ cursor: 'c', limit: 10 })
    expect(lastCall()[0]).toBe('/v1/paid-media/web/list-archives')
    expect(JSON.parse(String(lastCall()[1].body))).toEqual({ cursor: 'c', limit: 10 })

    await subject.listPaidMediaArchives()
    expect(JSON.parse(String(lastCall()[1].body))).toEqual({})

    await subject.listPaidMediaOperations()
    expect(lastCall()[0]).toBe('/v1/paid-media/web/list')
    expect(JSON.parse(String(lastCall()[1].body))).toEqual({})

    await subject.acknowledgePaidMedia(proof)
    expect(lastCall()[0]).toBe('/v1/paid-media/web/acknowledge')
    expect(JSON.parse(String(lastCall()[1].body))).toEqual(proof)

    await subject.abandonPaidMediaClaim('op-3', 'evidence-text')
    expect(lastCall()[0]).toBe('/v1/paid-media/web/abandon')
    expect(JSON.parse(String(lastCall()[1].body))).toEqual({
      operationId: 'op-3',
      evidence: 'evidence-text'
    })

    await subject.reconcilePaidMedia({ operationId: 'op-4', reason: 'r', evidence: 'e' })
    expect(lastCall()[0]).toBe('/v1/paid-media/web/reconcile')

    await subject.importLegacyPaidMediaJournal(null)
    expect(lastCall()[0]).toBe('/v1/paid-media/web/import-legacy')
    expect(JSON.parse(String(lastCall()[1].body))).toBeNull()
  })

  it('cancelPaidMedia is fire-and-forget but still posts the cancel verb', async () => {
    api().cancelPaidMedia('op-9')

    expect(lastCall()[0]).toBe('/v1/paid-media/web/cancel')
    expect(lastCall()[1].method).toBe('POST')
    expect(JSON.parse(String(lastCall()[1].body))).toEqual({ operationId: 'op-9' })
  })

  it('truthfully rethrows an engine 404', async () => {
    fetchMock.mockResolvedValue(new Response('{"detail":"Not Found"}', { status: 404 }))

    const failure = await api()
      .claimPaidMedia({ path: '/v1/images/generations', encodedBody: '{}' })
      .catch((error: unknown) => error)

    expect(failure).toBeInstanceOf(WebHttpError)
    expect((failure as WebHttpError).status).toBe(404)
    expect((failure as WebHttpError).message).toContain('404')
    expect((failure as WebHttpError).message).toContain('Not Found')
  })

  it('truthfully rethrows engine 503 (capability unavailable)', async () => {
    fetchMock.mockResolvedValue(
      new Response('{"detail":"付费媒体 Key 未配置或格式无效；拒绝创建操作"}', { status: 503 })
    )

    const failure = await api()
      .executePaidMedia({ operationId: 'op-1', path: '/v1/images/generations', encodedBody: '{}' })
      .catch((error: unknown) => error)

    expect(failure).toBeInstanceOf(WebHttpError)
    expect((failure as WebHttpError).status).toBe(503)
    expect((failure as WebHttpError).message).toContain('付费媒体 Key 未配置')
  })

  it('attaches the approval key only to approval-domain write verbs', async () => {
    data['nachuan.web.approvalKey'] = 'approval-key'
    const subject = api()

    await subject.claimPaidMedia({ path: '/v1/images/generations', encodedBody: '{}' })
    expect((lastCall()[1].headers as Record<string, string>)['X-Nachuan-Approval-Key']).toBe(
      'approval-key'
    )

    await subject.executePaidMedia({
      operationId: 'op-1',
      path: '/v1/images/generations',
      encodedBody: '{}'
    })
    expect((lastCall()[1].headers as Record<string, string>)['X-Nachuan-Approval-Key']).toBe(
      'approval-key'
    )

    await subject.abandonPaidMediaClaim('op-3', 'evidence')
    expect((lastCall()[1].headers as Record<string, string>)['X-Nachuan-Approval-Key']).toBe(
      'approval-key'
    )

    await subject.reconcilePaidMedia({ operationId: 'op-4', reason: 'r', evidence: 'e' })
    expect((lastCall()[1].headers as Record<string, string>)['X-Nachuan-Approval-Key']).toBe(
      'approval-key'
    )

    await subject.importLegacyPaidMediaJournal(null)
    expect((lastCall()[1].headers as Record<string, string>)['X-Nachuan-Approval-Key']).toBe(
      'approval-key'
    )

    // 读路径与轮询不在审批信任域：永不携带审批头。
    await subject.listPaidMediaOperations()
    expect(
      (lastCall()[1].headers as Record<string, string>)['X-Nachuan-Approval-Key']
    ).toBeUndefined()
    await subject.pollPaidVideo({ taskAlias: 'task-1', model: 'm' })
    expect(
      (lastCall()[1].headers as Record<string, string>)['X-Nachuan-Approval-Key']
    ).toBeUndefined()
  })

  it('never feeds paid-media 401s into the runtime-key login gate counter', async () => {
    fetchMock.mockResolvedValue(new Response('{"detail":"unauthorized"}', { status: 401 }))

    const subject = api()
    await subject.listPaidMediaOperations().catch(() => {})
    await subject.listPaidMediaOperations().catch(() => {})
    await subject.listPaidMediaOperations().catch(() => {})

    expect(onUnauthorized).not.toHaveBeenCalled()
  })
})
