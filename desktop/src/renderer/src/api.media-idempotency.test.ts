import { beforeEach, describe, expect, it, vi } from 'vitest'

const UUID_ONE = '11111111-1111-4111-8111-111111111111'
const UUID_TWO = '22222222-2222-4222-8222-222222222222'
const DELIVERY_PROOF = {
  operationId: `desktop-op-${UUID_ONE}`,
  resultSha256: 'a'.repeat(64),
  archiveReceiptSha256: 'b'.repeat(64)
}
const DURABLE_IMAGE_REF = `nachuan-paid-media://sha256/${'d'.repeat(64)}`

function fakeLocalStorage(): Storage {
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

function operation(uuid = UUID_ONE, state = 'claimed') {
  return {
    operationId: `desktop-op-${uuid}`,
    path: '/v1/images/generations' as const,
    state,
    createdAt: 1_750_000_000_000,
    updatedAt: 1_750_000_000_001,
    dispatchCount: state === 'claimed' ? 0 : 1
  }
}

function deferred<T = void>(): {
  promise: Promise<T>
  resolve: (value: T | PromiseLike<T>) => void
} {
  let resolve!: (value: T | PromiseLike<T>) => void
  const promise = new Promise<T>((done) => {
    resolve = done
  })
  return { promise, resolve }
}

type DesktopApiMock = ReturnType<typeof desktopApiMock>

function desktopApiMock() {
  const claimed = operation()
  return {
    getEngineInfo: vi.fn().mockResolvedValue({
      baseUrl: 'http://127.0.0.1:18000',
      key: 'ordinary-renderer-runtime-key'
    }),
    importLegacyPaidMediaJournal: vi.fn().mockResolvedValue(undefined),
    claimPaidMedia: vi.fn().mockResolvedValue(claimed),
    executePaidMedia: vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      result: { data: [{ url: DURABLE_IMAGE_REF }] },
      operation: { ...claimed, state: 'result_ready', dispatchCount: 1 },
      deliveryProof: DELIVERY_PROOF
    }),
    pollPaidVideo: vi.fn().mockResolvedValue({ status: 'processing', progress: 25 }),
    cancelPaidMedia: vi.fn(),
    acknowledgePaidMedia: vi.fn().mockResolvedValue(undefined),
    abandonPaidMediaClaim: vi.fn().mockResolvedValue(undefined),
    listPaidMediaOperations: vi.fn().mockResolvedValue([]),
    reconcilePaidMedia: vi.fn().mockResolvedValue(undefined)
  }
}

let desktopApi: DesktopApiMock

describe('paid media renderer/main-process seam', () => {
  beforeEach(() => {
    vi.useRealTimers()
    vi.resetModules()
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
    desktopApi = desktopApiMock()
    vi.stubGlobal('localStorage', fakeLocalStorage())
    vi.stubGlobal('window', { api: desktopApi })
    vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new Error('renderer fetch must not run'))))
  })

  it('polls a paid video alias only through the narrow preload seam', async () => {
    const fetchMock = globalThis.fetch as ReturnType<typeof vi.fn>
    const { pollVideo } = await import('./api')
    const taskAlias = `nvt1_${'a'.repeat(64)}`

    await expect(pollVideo('video-model', taskAlias)).resolves.toEqual({
      status: 'processing',
      progress: 25
    })
    expect(desktopApi.pollPaidVideo).toHaveBeenCalledWith({
      taskAlias,
      model: 'video-model'
    })
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('recognizes only a content-addressed main-vault media reference as durable', async () => {
    const { isDurablePaidMediaAssetRef } = await import('./api')

    expect(
      isDurablePaidMediaAssetRef(`nachuan-paid-media://sha256/${'a'.repeat(64)}`)
    ).toBe(true)
    expect(isDurablePaidMediaAssetRef('https://provider.invalid/final.mp4')).toBe(false)
    expect(isDurablePaidMediaAssetRef(`nachuan-paid-media://sha256/${'A'.repeat(64)}`)).toBe(
      false
    )
    expect(isDurablePaidMediaAssetRef('nachuan-paid-media://sha256/../escape')).toBe(false)
  })

  it('uses a durable main-vault video reference directly without a blob fetch', async () => {
    const fetchMock = globalThis.fetch as ReturnType<typeof vi.fn>
    const { videoBlobUrl } = await import('./api')
    const reference = `nachuan-paid-media://sha256/${'a'.repeat(64)}`

    await expect(videoBlobUrl(reference)).resolves.toBe(reference)
    expect(desktopApi.getEngineInfo).not.toHaveBeenCalled()
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('sends only path/body/operation to main and never performs a renderer fetch', async () => {
    const fetchMock = globalThis.fetch as ReturnType<typeof vi.fn>
    const { generateImage } = await import('./api')

    await expect(
      generateImage('image-model', 'river', undefined, {
        onResultDurablyCommitted: () => true
      })
    ).resolves.toEqual([DURABLE_IMAGE_REF])

    expect(desktopApi.claimPaidMedia).toHaveBeenCalledWith({
      path: '/v1/images/generations',
      encodedBody: JSON.stringify({ model: 'image-model', prompt: 'river' })
    })
    expect(desktopApi.executePaidMedia).toHaveBeenCalledWith({
      operationId: `desktop-op-${UUID_ONE}`,
      path: '/v1/images/generations',
      encodedBody: JSON.stringify({ model: 'image-model', prompt: 'river' })
    })
    expect(JSON.stringify(desktopApi.executePaidMedia.mock.calls)).not.toMatch(
      /Idempotency-Key|sk-paid-media|requestSha256/i
    )
    expect(fetchMock).not.toHaveBeenCalled()
    expect(desktopApi.acknowledgePaidMedia).toHaveBeenCalledWith(DELIVERY_PROOF)
  })

  it.each([
    ['an HTTPS provider URL', { data: [{ url: 'https://media.invalid/not-durable.png' }] }],
    ['a small inline payload', { data: [{ b64_json: 'aW5saW5lLW5vdC1kdXJhYmxl' }] }]
  ])(
    'rejects %s before the durable callback and main acknowledgement',
    async (_label, result) => {
      desktopApi.executePaidMedia.mockResolvedValueOnce({
        ok: true,
        status: 200,
        result,
        operation: { ...operation(), state: 'result_ready', dispatchCount: 1 },
        deliveryProof: DELIVERY_PROOF
      })
      const durable = vi.fn(() => true)
      const { generateImage, PaidMediaRequestError } = await import('./api')

      await expect(
        generateImage('image-model', 'must stay private', undefined, {
          onResultDurablyCommitted: durable
        })
      ).rejects.toBeInstanceOf(PaidMediaRequestError)

      expect(durable).not.toHaveBeenCalled()
      expect(desktopApi.acknowledgePaidMedia).not.toHaveBeenCalled()
    }
  )

  it('waits for an async recovery anchor before asking main to dispatch', async () => {
    const anchor = deferred<void>()
    const entered = deferred<void>()
    const { generateImage } = await import('./api')
    const request = generateImage('image-model', 'cat', undefined, {
      onOperationClaimed: async () => {
        entered.resolve()
        await anchor.promise
      }
    })

    await entered.promise
    await new Promise<void>((resolve) => setTimeout(resolve, 0))
    expect(desktopApi.executePaidMedia).not.toHaveBeenCalled()

    anchor.resolve()
    await expect(request).resolves.toEqual([DURABLE_IMAGE_REF])
    expect(desktopApi.executePaidMedia).toHaveBeenCalledTimes(1)
  })

  it('terminalizes only the undispatched claim when the recovery anchor fails', async () => {
    const { generateImage, PaidMediaJournalError } = await import('./api')

    await expect(
      generateImage('image-model', 'cat', undefined, {
        onOperationClaimed: async () => {
          throw new Error('conversation flush failed')
        }
      })
    ).rejects.toBeInstanceOf(PaidMediaJournalError)

    expect(desktopApi.abandonPaidMediaClaim).toHaveBeenCalledWith(
      `desktop-op-${UUID_ONE}`,
      'renderer recovery anchor failed before dispatch'
    )
    expect(desktopApi.executePaidMedia).not.toHaveBeenCalled()
  })

  it('maps a recoverable main outcome without inventing a second attempt', async () => {
    desktopApi.executePaidMedia.mockResolvedValueOnce({
      ok: false,
      status: 425,
      recoverable: true,
      detail: 'Paid media request failed (425)',
      retryAfterSeconds: 3,
      operation: { ...operation(), state: 'recoverable', dispatchCount: 1 }
    } as never)
    const { generateImage, PaidMediaRequestError } = await import('./api')

    const error = await generateImage('image-model', 'cat').catch((value: unknown) => value)
    expect(error).toBeInstanceOf(PaidMediaRequestError)
    expect(error).toMatchObject({
      operationId: `desktop-op-${UUID_ONE}`,
      status: 425,
      recoverable: true,
      retryAfterSeconds: 3
    })
    expect(desktopApi.executePaidMedia).toHaveBeenCalledTimes(1)
  })

  it('passes an explicit recovery operation to main for exact binding', async () => {
    const { generateImage } = await import('./api')

    await generateImage('image-model', 'cat', undefined, {
      operationId: `desktop-op-${UUID_ONE}`
    })

    expect(desktopApi.claimPaidMedia).toHaveBeenCalledWith({
      path: '/v1/images/generations',
      encodedBody: JSON.stringify({ model: 'image-model', prompt: 'cat' }),
      retryOperationId: `desktop-op-${UUID_ONE}`
    })
  })

  it.each([
    ['does not match the original operation', 'PaidMediaOperationMismatchError'],
    ['operation is too old for automatic retry', 'PaidMediaOperationExpiredError']
  ])('preserves the main fail-closed retry class for %s', async (message, name) => {
    desktopApi.claimPaidMedia.mockRejectedValueOnce(new Error(message))
    const api = await import('./api')

    const error = await api
      .generateImage('image-model', 'cat', undefined, {
        operationId: `desktop-op-${UUID_ONE}`
      })
      .catch((value: unknown) => value)
    expect(error).toBeInstanceOf(
      name === 'PaidMediaOperationMismatchError'
        ? api.PaidMediaOperationMismatchError
        : api.PaidMediaOperationExpiredError
    )
    expect(desktopApi.executePaidMedia).not.toHaveBeenCalled()
  })

  it('maps the real preload operation_expired tag even when its sanitized message omits "too old"', async () => {
    const tagged = new Error('Paid media retry is outside the automatic recovery window')
    tagged.name = 'PaidMediaIpc:operation_expired'
    desktopApi.claimPaidMedia.mockRejectedValueOnce(tagged)
    const api = await import('./api')

    const error = await api
      .generateImage('image-model', 'cat', undefined, {
        operationId: `desktop-op-${UUID_ONE}`
      })
      .catch((value: unknown) => value)

    expect(error).toBeInstanceOf(api.PaidMediaOperationExpiredError)
    expect(error).toMatchObject({ operationId: `desktop-op-${UUID_ONE}` })
    expect(desktopApi.executePaidMedia).not.toHaveBeenCalled()
  })

  it('keeps a semantic-invalid success unresolved and unacknowledged', async () => {
    desktopApi.executePaidMedia.mockResolvedValueOnce({
      ok: true,
      status: 200,
      result: { data: [{ url: '   ', b64_json: '' }] },
      operation: { ...operation(), state: 'result_ready', dispatchCount: 1 },
      deliveryProof: DELIVERY_PROOF
    } as never)
    const { generateImage, PaidMediaRequestError } = await import('./api')

    await expect(generateImage('image-model', 'cat')).rejects.toBeInstanceOf(
      PaidMediaRequestError
    )
    expect(desktopApi.acknowledgePaidMedia).not.toHaveBeenCalled()
  })

  it('normalizes a video receipt and acknowledges only after its durable callback', async () => {
    desktopApi.claimPaidMedia.mockResolvedValueOnce({
      ...operation(),
      path: '/v1/videos/generations'
    })
    desktopApi.executePaidMedia.mockResolvedValueOnce({
      ok: true,
      status: 200,
      result: { task_id: 'video-task-1' },
      operation: {
        ...operation(),
        path: '/v1/videos/generations',
        state: 'result_ready',
        dispatchCount: 1
      },
      deliveryProof: DELIVERY_PROOF
    } as never)
    const durable = vi.fn().mockResolvedValue(true)
    const { createVideo } = await import('./api')

    await expect(
      createVideo('video-model', 'movie', undefined, undefined, {
        onResultDurablyCommitted: durable
      })
    ).resolves.toEqual({ task_id: 'video-task-1' })
    expect(durable).toHaveBeenCalledWith(
      `desktop-op-${UUID_ONE}`,
      { task_id: 'video-task-1' },
      DELIVERY_PROOF
    )
    expect(desktopApi.acknowledgePaidMedia).toHaveBeenCalledTimes(1)
  })

  it.each(['false', 'throw'])('does not acknowledge when durable result callback returns %s', async (mode) => {
    const { generateImage, PaidMediaRequestError } = await import('./api')

    const error = await generateImage('image-model', 'cat', undefined, {
      onResultDurablyCommitted: () => {
        if (mode === 'throw') throw new Error('flush failed')
        return false
      }
    }).catch((value: unknown) => value)

    expect(error).toBeInstanceOf(PaidMediaRequestError)
    expect(error).toMatchObject({ status: 200, recoverable: true })
    expect(desktopApi.acknowledgePaidMedia).not.toHaveBeenCalled()
  })

  it('waits for an async durable commit before acknowledging main', async () => {
    const durable = deferred<boolean>()
    const { generateImage } = await import('./api')
    const request = generateImage('image-model', 'cat', undefined, {
      onResultDurablyCommitted: () => durable.promise
    })

    await vi.waitFor(() => expect(desktopApi.executePaidMedia).toHaveBeenCalledTimes(1))
    expect(desktopApi.acknowledgePaidMedia).not.toHaveBeenCalled()
    durable.resolve(true)

    await expect(request).resolves.toEqual([DURABLE_IMAGE_REF])
    expect(desktopApi.acknowledgePaidMedia).toHaveBeenCalledTimes(1)
  })

  it('leaves result_ready unresolved when main acknowledgement fails', async () => {
    desktopApi.acknowledgePaidMedia.mockRejectedValueOnce(new Error('ledger write failed'))
    const { generateImage, PaidMediaRequestError } = await import('./api')

    await expect(
      generateImage('image-model', 'cat', undefined, {
        onResultDurablyCommitted: () => true
      })
    ).rejects.toBeInstanceOf(PaidMediaRequestError)
  })

  it('routes AbortSignal cancellation to main without cloning the signal over IPC', async () => {
    const controller = new AbortController()
    const pending = deferred<unknown>()
    desktopApi.executePaidMedia.mockReturnValueOnce(pending.promise as never)
    const { generateImage } = await import('./api')
    const request = generateImage('image-model', 'cat', controller.signal)
    await vi.waitFor(() => expect(desktopApi.executePaidMedia).toHaveBeenCalledTimes(1))
    controller.abort()

    expect(desktopApi.cancelPaidMedia).toHaveBeenCalledWith(`desktop-op-${UUID_ONE}`)
    pending.resolve({
      ok: false,
      status: 0,
      recoverable: true,
      detail: 'Paid media transport result is unknown',
      operation: { ...operation(), state: 'recoverable', dispatchCount: 1 }
    })
    await expect(request).rejects.toMatchObject({ status: 0, recoverable: true })
  })

  it('terminalizes a newly claimed zero-dispatch operation when already aborted before main execute', async () => {
    const controller = new AbortController()
    controller.abort()
    const { generateImage } = await import('./api')

    const error = await generateImage('image-model', 'cat', controller.signal, {
      onOperationClaimed: () => undefined
    }).catch((value: unknown) => value)

    expect(error).toMatchObject({
      operationId: `desktop-op-${UUID_ONE}`,
      status: 0,
      recoverable: true
    })
    expect(desktopApi.executePaidMedia).not.toHaveBeenCalled()
    expect(desktopApi.cancelPaidMedia).not.toHaveBeenCalled()
    expect(desktopApi.abandonPaidMediaClaim).toHaveBeenCalledWith(
      `desktop-op-${UUID_ONE}`,
      'renderer cancelled before main dispatch'
    )
  })

  it('lists and manually reconciles through async main APIs', async () => {
    desktopApi.listPaidMediaOperations.mockResolvedValueOnce([
      { ...operation(UUID_TWO), state: 'recoverable', dispatchCount: 1 }
    ] as never)
    const { discardPendingPaidMediaOperation, listPendingPaidMediaOperations } = await import(
      './api'
    )

    await expect(listPendingPaidMediaOperations()).resolves.toEqual([
      expect.objectContaining({ operationId: `desktop-op-${UUID_TWO}` })
    ])
    await discardPendingPaidMediaOperation(
      `desktop-op-${UUID_TWO}`,
      'invoice-42 checked; no duplicate charge'
    )
    expect(desktopApi.reconcilePaidMedia).toHaveBeenCalledWith({
      operationId: `desktop-op-${UUID_TWO}`,
      reason: 'provider-console-checked',
      evidence: 'invoice-42 checked; no duplicate charge'
    })
  })
})
