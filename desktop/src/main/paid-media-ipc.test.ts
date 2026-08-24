import { describe, expect, it, vi } from 'vitest'

import type { PaidMediaPublicOperation } from './paid-media-ledger'
import type { PaidMediaService } from './paid-media-service'
import { PAID_MEDIA_IPC_CHANNELS, registerPaidMediaIpc } from './paid-media-ipc'

type InvokeHandler = (event: object, ...args: unknown[]) => unknown
type SendHandler = (event: object, ...args: unknown[]) => unknown

class FakeIpcMain {
  readonly handlers = new Map<string, InvokeHandler>()
  readonly listeners = new Map<string, SendHandler[]>()

  handle(channel: string, handler: InvokeHandler): void {
    if (this.handlers.has(channel)) throw new Error(`duplicate handler: ${channel}`)
    this.handlers.set(channel, handler)
  }

  removeHandler(channel: string): void {
    this.handlers.delete(channel)
  }

  on(channel: string, listener: SendHandler): this {
    const current = this.listeners.get(channel) ?? []
    current.push(listener)
    this.listeners.set(channel, current)
    return this
  }

  removeListener(channel: string, listener: SendHandler): this {
    const current = this.listeners.get(channel) ?? []
    this.listeners.set(
      channel,
      current.filter((item) => item !== listener)
    )
    return this
  }

  async invoke(channel: string, event: object, ...args: unknown[]): Promise<unknown> {
    const handler = this.handlers.get(channel)
    if (!handler) throw new Error(`missing handler: ${channel}`)
    return handler(event, ...args)
  }

  async emit(channel: string, event: object, ...args: unknown[]): Promise<void> {
    const listeners = this.listeners.get(channel) ?? []
    if (listeners.length === 0) throw new Error(`missing listener: ${channel}`)
    await Promise.all(listeners.map((listener) => listener(event, ...args)))
  }
}

const operation: PaidMediaPublicOperation = {
  operationId: 'desktop-op-11111111-1111-4111-8111-111111111111',
  path: '/v1/images/generations',
  state: 'claimed',
  createdAt: 1_700_000_000_000,
  updatedAt: 1_700_000_000_000,
  dispatchCount: 0
}
const validImageBody = JSON.stringify({ model: 'image', prompt: 'draw a river' })

function serviceStub(overrides: Partial<PaidMediaService> = {}): PaidMediaService {
  return {
    ensureMediaProbeReady: vi.fn(async () => undefined),
    claim: vi.fn(async () => operation),
    execute: vi.fn(),
    pollVideo: vi.fn(),
    recoverArchived: vi.fn(),
    listRecoverableArchives: vi.fn(async () => ({ items: [] })),
    listUnresolved: vi.fn(async () => []),
    acknowledgeDelivered: vi.fn(),
    abandonUndispatchedClaim: vi.fn(),
    reconcileManually: vi.fn(),
    importLegacyUnresolved: vi.fn(),
    bootstrapLegacyMigration: vi.fn(),
    cancel: vi.fn(() => false),
    ...overrides
  } as unknown as PaidMediaService
}

function reconciliationServiceStub(
  overrides: Partial<PaidMediaService> = {}
): PaidMediaService {
  return serviceStub({
    listUnresolved: vi.fn(async () => [operation]),
    ...overrides
  })
}

describe('paid media IPC boundary', () => {
  it('authorizes a bounded paid-video poll alias before delegating to main service', async () => {
    const ipcMain = new FakeIpcMain()
    const pollVideo = vi.fn(async () => ({ status: 'processing', progress: 20 }))
    registerPaidMediaIpc({
      ipcMain,
      service: serviceStub({ pollVideo }),
      authorize: vi.fn(),
      ownerWindow: () => ({}),
      dialog: { showMessageBox: vi.fn() }
    })
    const taskAlias = `nvt1_${'a'.repeat(64)}`

    const response = await ipcMain.invoke(PAID_MEDIA_IPC_CHANNELS.pollVideo, {}, {
      taskAlias,
      model: 'video-model'
    })

    expect(response).toEqual({ ok: true, value: { status: 'processing', progress: 20 } })
    expect(pollVideo).toHaveBeenCalledWith({ taskAlias, model: 'video-model' })
  })

  it('recovers a Main-owned paid-media archive by exact operation id', async () => {
    const ipcMain = new FakeIpcMain()
    const recovered = {
      operationId: operation.operationId,
      path: operation.path,
      model: 'image-model',
      status: 200,
      result: { data: [{ url: `nachuan-paid-media://sha256/${'a'.repeat(64)}` }] },
      deliveryProof: {
        operationId: operation.operationId,
        resultSha256: 'd'.repeat(64),
        archiveReceiptSha256: 'b'.repeat(64)
      },
      archive: {
        receiptSha256: 'b'.repeat(64),
        responseSha256: 'c'.repeat(64),
        responseByteLength: 128,
        assets: []
      }
    }
    const recoverArchived = vi.fn(async () => recovered)
    registerPaidMediaIpc({
      ipcMain,
      service: serviceStub({ recoverArchived }),
      authorize: vi.fn(),
      ownerWindow: () => ({}),
      dialog: { showMessageBox: vi.fn() }
    })

    await expect(
      ipcMain.invoke(PAID_MEDIA_IPC_CHANNELS.recoverArchive, {}, {
        operationId: operation.operationId
      })
    ).resolves.toEqual({ ok: true, value: recovered })
    expect(recoverArchived).toHaveBeenCalledWith(operation.operationId)
  })

  it('discovers bounded Main-owned orphan archives without renderer-held operation ids', async () => {
    const ipcMain = new FakeIpcMain()
    const archives = [
      {
        operationId: operation.operationId,
        path: operation.path,
        model: 'image-model',
        status: 200,
        kind: 'image' as const,
        archivedAt: 1_700_000_000_001,
        receiptSha256: 'd'.repeat(64),
        responseByteLength: 128,
        assets: []
      }
    ]
    const page = { items: archives, nextCursor: 'cursor-next' }
    const listRecoverableArchives = vi.fn(async () => page)
    registerPaidMediaIpc({
      ipcMain,
      service: serviceStub({ listRecoverableArchives }),
      authorize: vi.fn(),
      ownerWindow: () => ({}),
      dialog: { showMessageBox: vi.fn() }
    })

    await expect(
      ipcMain.invoke(PAID_MEDIA_IPC_CHANNELS.listArchives, {})
    ).resolves.toEqual({ ok: true, value: page })
    expect(listRecoverableArchives).toHaveBeenCalledTimes(1)
  })

  it('authorizes and obtains native approval before accepting a new paid-media claim', async () => {
    const order: string[] = []
    const ipcMain = new FakeIpcMain()
    const service = serviceStub({
      ensureMediaProbeReady: vi.fn(async () => {
        order.push('readiness')
      }),
      claim: vi.fn(async () => {
        order.push('claim')
        return operation
      })
    })
    registerPaidMediaIpc({
      ipcMain,
      service,
      authorize: () => {
        order.push('authorize')
      },
      ownerWindow: () => ({}),
      dialog: {
        showMessageBox: vi.fn(async () => {
          order.push('approve')
          return { response: 1 }
        })
      }
    })

    const response = await ipcMain.invoke(PAID_MEDIA_IPC_CHANNELS.claim, {}, {
      path: '/v1/images/generations',
      encodedBody: validImageBody
    })

    expect(order).toEqual(['authorize', 'readiness', 'approve', 'claim'])
    expect(response).toEqual({ ok: true, value: operation })
  })

  it('fails before opening native approval when the trusted probe is unavailable', async () => {
    const ipcMain = new FakeIpcMain()
    const service = serviceStub({
      ensureMediaProbeReady: vi.fn(async () => {
        throw new Error('probe offline')
      })
    })
    const dialog = { showMessageBox: vi.fn(async () => ({ response: 1 })) }
    registerPaidMediaIpc({
      ipcMain,
      service,
      authorize: vi.fn(),
      ownerWindow: () => ({}),
      dialog
    })

    await expect(
      ipcMain.invoke(PAID_MEDIA_IPC_CHANNELS.claim, {}, {
        path: '/v1/images/generations',
        encodedBody: validImageBody
      })
    ).resolves.toEqual({
      ok: false,
      error: { code: 'operation_failed', message: 'Paid media safety probe is unavailable' }
    })
    expect(dialog.showMessageBox).not.toHaveBeenCalled()
    expect(service.claim).not.toHaveBeenCalled()
  })

  it('shows the model, prompt preview, cost parameters, and digest in native approval', async () => {
    const ipcMain = new FakeIpcMain()
    const service = serviceStub()
    let approvalDetail = ''
    const encodedBody = JSON.stringify({
      model: 'video-model',
      prompt: '让湖面上的小船缓慢驶向远山',
      image: 'A'.repeat(4096),
      num_frames: 49
    })
    registerPaidMediaIpc({
      ipcMain,
      service,
      authorize: vi.fn(),
      ownerWindow: () => ({}),
      dialog: {
        showMessageBox: vi.fn(async (_owner, options) => {
          approvalDetail = String(options.detail ?? '')
          return { response: 0 }
        })
      }
    })

    await ipcMain.invoke(PAID_MEDIA_IPC_CHANNELS.claim, {}, {
      path: '/v1/videos/generations',
      encodedBody
    })

    expect(approvalDetail).toContain('/v1/videos/generations')
    expect(approvalDetail).toContain('video-model')
    expect(approvalDetail).toContain('让湖面上的小船缓慢驶向远山')
    expect(approvalDetail).toContain('num_frames=49')
    expect(approvalDetail).toMatch(/SHA-256: [0-9a-f]{64}/)
    expect(approvalDetail).not.toContain('A'.repeat(256))
    expect(service.claim).not.toHaveBeenCalled()
  })

  it.each(['not-json', '[]', '{"model":"image"}', '{"model":"image","prompt":" "}'])(
    'rejects a semantically invalid paid body before native approval: %s',
    async (encodedBody) => {
      const ipcMain = new FakeIpcMain()
      const service = serviceStub()
      const dialog = { showMessageBox: vi.fn(async () => ({ response: 1 })) }
      registerPaidMediaIpc({
        ipcMain,
        service,
        authorize: vi.fn(),
        ownerWindow: () => ({}),
        dialog
      })

      const response = await ipcMain.invoke(PAID_MEDIA_IPC_CHANNELS.claim, {}, {
        path: '/v1/images/generations',
        encodedBody
      })

      expect(response).toEqual({
        ok: false,
        error: { code: 'invalid_request', message: 'Paid media IPC request is invalid' }
      })
      expect(dialog.showMessageBox).not.toHaveBeenCalled()
      expect(service.claim).not.toHaveBeenCalled()
    }
  )

  it('rejects unknown or complex provider parameters before native approval', async () => {
    const ipcMain = new FakeIpcMain()
    const service = serviceStub()
    const dialog = { showMessageBox: vi.fn(async () => ({ response: 1 })) }
    registerPaidMediaIpc({
      ipcMain,
      service,
      authorize: vi.fn(),
      ownerWindow: () => ({}),
      dialog
    })

    const response = await ipcMain.invoke(PAID_MEDIA_IPC_CHANNELS.claim, {}, {
      path: '/v1/videos/generations',
      encodedBody: JSON.stringify({
        model: 'video-model',
        prompt: 'film',
        extra_body: { image: ['aGVsbG8='], hidden_provider_option: { credits: 99 } }
      })
    })

    expect(response).toEqual({
      ok: false,
      error: { code: 'invalid_request', message: 'Paid media IPC request is invalid' }
    })
    expect(dialog.showMessageBox).not.toHaveBeenCalled()
    expect(service.claim).not.toHaveBeenCalled()
  })

  it('does not create a ledger claim when native approval for a new paid request is cancelled', async () => {
    const ipcMain = new FakeIpcMain()
    const service = serviceStub()
    const dialog = { showMessageBox: vi.fn(async () => ({ response: 0 })) }
    registerPaidMediaIpc({
      ipcMain,
      service,
      authorize: vi.fn(),
      ownerWindow: () => ({}),
      dialog
    })

    const response = await ipcMain.invoke(PAID_MEDIA_IPC_CHANNELS.claim, {}, {
      path: '/v1/images/generations',
      encodedBody: validImageBody
    })

    expect(dialog.showMessageBox).toHaveBeenCalledTimes(1)
    expect(service.claim).not.toHaveBeenCalled()
    expect(response).toEqual({
      ok: false,
      error: {
        code: 'cancelled',
        message: 'Paid media request was cancelled'
      }
    })
  })

  it('fails closed without a native owner window before creating a new paid claim', async () => {
    const ipcMain = new FakeIpcMain()
    const service = serviceStub()
    const dialog = { showMessageBox: vi.fn(async () => ({ response: 1 })) }
    registerPaidMediaIpc({
      ipcMain,
      service,
      authorize: vi.fn(),
      ownerWindow: () => null,
      dialog
    })

    const response = await ipcMain.invoke(PAID_MEDIA_IPC_CHANNELS.claim, {}, {
      path: '/v1/images/generations',
      encodedBody: validImageBody
    })

    expect(dialog.showMessageBox).not.toHaveBeenCalled()
    expect(service.claim).not.toHaveBeenCalled()
    expect(response).toEqual({
      ok: false,
      error: {
        code: 'operation_failed',
        message: 'Paid media approval is unavailable'
      }
    })
  })

  it('retries an existing durable operation without opening a second native approval dialog', async () => {
    const ipcMain = new FakeIpcMain()
    const service = serviceStub()
    const dialog = { showMessageBox: vi.fn(async () => ({ response: 1 })) }
    registerPaidMediaIpc({
      ipcMain,
      service,
      authorize: vi.fn(),
      ownerWindow: () => ({}),
      dialog
    })
    const request = {
      path: '/v1/images/generations',
      encodedBody: validImageBody,
      retryOperationId: operation.operationId
    }

    const response = await ipcMain.invoke(PAID_MEDIA_IPC_CHANNELS.claim, {}, request)

    expect(dialog.showMessageBox).not.toHaveBeenCalled()
    expect(service.claim).toHaveBeenCalledWith(request)
    expect(response).toEqual({ ok: true, value: operation })
  })

  it('rejects a new paid request before native approval when a trusted operation is unresolved', async () => {
    const ipcMain = new FakeIpcMain()
    const service = serviceStub({
      listUnresolved: vi.fn(async () => [operation])
    })
    const dialog = {
      showMessageBox: vi.fn(async (_owner: unknown, _options: Record<string, unknown>) => ({
        response: 1
      }))
    }
    registerPaidMediaIpc({
      ipcMain,
      service,
      authorize: vi.fn(),
      ownerWindow: () => ({}),
      dialog
    })

    const response = await ipcMain.invoke(PAID_MEDIA_IPC_CHANNELS.claim, {}, {
      path: '/v1/images/generations',
      encodedBody: validImageBody
    })

    expect(dialog.showMessageBox).not.toHaveBeenCalled()
    expect(service.claim).not.toHaveBeenCalled()
    expect(response).toEqual({
      ok: false,
      error: {
        code: 'unresolved',
        message: 'Another paid media operation is unresolved'
      }
    })
  })

  it('allows only one concurrent native approval prompt for new paid requests', async () => {
    const ipcMain = new FakeIpcMain()
    const service = serviceStub()
    let approve!: (value: { response: number }) => void
    const dialog = {
      showMessageBox: vi
        .fn()
        .mockImplementationOnce(
          () =>
          new Promise<{ response: number }>((resolve) => {
            approve = resolve
          })
        )
        .mockResolvedValue({ response: 0 })
    }
    registerPaidMediaIpc({
      ipcMain,
      service,
      authorize: vi.fn(),
      ownerWindow: () => ({}),
      dialog
    })
    const request = {
      path: '/v1/images/generations',
      encodedBody: validImageBody
    }

    const first = ipcMain.invoke(PAID_MEDIA_IPC_CHANNELS.claim, {}, request)
    await vi.waitFor(() => expect(dialog.showMessageBox).toHaveBeenCalledTimes(1))
    const second = await ipcMain.invoke(PAID_MEDIA_IPC_CHANNELS.claim, {}, request)
    approve({ response: 1 })

    await expect(first).resolves.toEqual({ ok: true, value: operation })
    expect(second).toEqual({
      ok: false,
      error: {
        code: 'unresolved',
        message: 'Another paid media operation is unresolved'
      }
    })
    expect(dialog.showMessageBox).toHaveBeenCalledTimes(1)
    expect(service.claim).toHaveBeenCalledTimes(1)
  })

  it('fails closed without leaking authorization errors to the renderer', async () => {
    const ipcMain = new FakeIpcMain()
    const service = serviceStub()
    registerPaidMediaIpc({
      ipcMain,
      service,
      authorize: () => {
        throw new Error('Bearer runtime-secret X-Nachuan-Paid-Media-Key=paid-secret')
      },
      ownerWindow: () => ({}),
      dialog: { showMessageBox: vi.fn() }
    })

    const response = await ipcMain.invoke(PAID_MEDIA_IPC_CHANNELS.claim, {}, {
      path: '/v1/images/generations',
      encodedBody: validImageBody
    })

    expect(service.claim).not.toHaveBeenCalled()
    expect(response).toEqual({
      ok: false,
      error: {
        code: 'unauthorized',
        message: 'Paid media IPC authorization failed'
      }
    })
    expect(JSON.stringify(response)).not.toContain('secret')
  })

  it('rejects a non-exact execute payload only after sender authorization', async () => {
    const order: string[] = []
    const ipcMain = new FakeIpcMain()
    const service = serviceStub({
      execute: vi.fn(async () => {
        order.push('execute')
        throw new Error('must not execute')
      })
    })
    registerPaidMediaIpc({
      ipcMain,
      service,
      authorize: () => {
        order.push('authorize')
      },
      ownerWindow: () => ({}),
      dialog: { showMessageBox: vi.fn() }
    })

    const response = await ipcMain.invoke(PAID_MEDIA_IPC_CHANNELS.execute, {}, {
      operationId: operation.operationId,
      path: '/v1/images/generations',
      encodedBody: validImageBody,
      runtimeKey: 'must-not-cross-ipc'
    })

    expect(order).toEqual(['authorize'])
    expect(service.execute).not.toHaveBeenCalled()
    expect(response).toEqual({
      ok: false,
      error: {
        code: 'invalid_request',
        message: 'Paid media IPC request is invalid'
      }
    })
  })

  it('exposes only the unresolved public operation list after authorization', async () => {
    const order: string[] = []
    const ipcMain = new FakeIpcMain()
    const service = serviceStub({
      listUnresolved: vi.fn(async () => {
        order.push('list')
        return [operation]
      })
    })
    registerPaidMediaIpc({
      ipcMain,
      service,
      authorize: () => {
        order.push('authorize')
      },
      ownerWindow: () => ({}),
      dialog: { showMessageBox: vi.fn() }
    })

    const response = await ipcMain.invoke(PAID_MEDIA_IPC_CHANNELS.list, {})

    expect(order).toEqual(['authorize', 'list'])
    expect(response).toEqual({ ok: true, value: [operation] })
  })

  it('acknowledges durable renderer delivery through an exact Main archive proof', async () => {
    const ipcMain = new FakeIpcMain()
    const delivered = { ...operation, state: 'delivered' as const, deliveredAt: 1_700_000_001_000 }
    const deliveryProof = {
      operationId: operation.operationId,
      resultSha256: 'a'.repeat(64),
      archiveReceiptSha256: 'b'.repeat(64)
    }
    const service = serviceStub({
      acknowledgeDelivered: vi.fn(async () => delivered)
    })
    registerPaidMediaIpc({
      ipcMain,
      service,
      authorize: vi.fn(),
      ownerWindow: () => ({}),
      dialog: { showMessageBox: vi.fn() }
    })

    const response = await ipcMain.invoke(
      PAID_MEDIA_IPC_CHANNELS.acknowledge,
      {},
      deliveryProof
    )

    expect(service.acknowledgeDelivered).toHaveBeenCalledWith(deliveryProof)
    expect(response).toEqual({ ok: true, value: delivered })
  })

  it('rejects a bare operation-id acknowledgement before Main can clear a result', async () => {
    const ipcMain = new FakeIpcMain()
    const service = serviceStub()
    registerPaidMediaIpc({
      ipcMain,
      service,
      authorize: vi.fn(),
      ownerWindow: () => ({}),
      dialog: { showMessageBox: vi.fn() }
    })

    const response = await ipcMain.invoke(PAID_MEDIA_IPC_CHANNELS.acknowledge, {}, {
      operationId: operation.operationId
    })

    expect(service.acknowledgeDelivered).not.toHaveBeenCalled()
    expect(response).toEqual({
      ok: false,
      error: {
        code: 'invalid_request',
        message: 'Paid media IPC request is invalid'
      }
    })
  })

  it('abandons only through the bounded service command without widening its payload', async () => {
    const ipcMain = new FakeIpcMain()
    const reconciled = {
      ...operation,
      state: 'reconciled' as const,
      reconciliation: {
        at: 1_700_000_001_000,
        reason: 'pre-dispatch-anchor-failure',
        evidence: 'renderer durable anchor failed'
      }
    }
    const service = serviceStub({
      abandonUndispatchedClaim: vi.fn(async () => reconciled)
    })
    registerPaidMediaIpc({
      ipcMain,
      service,
      authorize: vi.fn(),
      ownerWindow: () => ({}),
      dialog: { showMessageBox: vi.fn() }
    })

    const response = await ipcMain.invoke(PAID_MEDIA_IPC_CHANNELS.abandon, {}, {
      operationId: operation.operationId,
      evidence: 'renderer durable anchor failed'
    })

    expect(service.abandonUndispatchedClaim).toHaveBeenCalledWith(
      operation.operationId,
      'renderer durable anchor failed'
    )
    expect(response).toEqual({ ok: true, value: reconciled })
  })

  it('leaves the ledger unchanged when the first native reconciliation warning is cancelled', async () => {
    const ipcMain = new FakeIpcMain()
    const service = reconciliationServiceStub()
    const dialog = {
      showMessageBox: vi.fn(async () => ({ response: 0 }))
    }
    registerPaidMediaIpc({
      ipcMain,
      service,
      authorize: vi.fn(),
      ownerWindow: () => ({}),
      dialog
    })

    const response = await ipcMain.invoke(PAID_MEDIA_IPC_CHANNELS.reconcile, {}, {
      operationId: operation.operationId,
      reason: 'provider-bill-reviewed',
      evidence: 'invoice 2026-07-16 confirms no duplicate charge'
    })

    expect(dialog.showMessageBox).toHaveBeenCalledTimes(1)
    expect(service.reconcileManually).not.toHaveBeenCalled()
    expect(response).toEqual({
      ok: false,
      error: {
        code: 'cancelled',
        message: 'Paid media reconciliation was cancelled'
      }
    })
  })

  it('still leaves the ledger unchanged when the second native confirmation is cancelled', async () => {
    const ipcMain = new FakeIpcMain()
    const service = reconciliationServiceStub()
    const dialog = {
      showMessageBox: vi
        .fn()
        .mockResolvedValueOnce({ response: 1 })
        .mockResolvedValueOnce({ response: 0 })
    }
    registerPaidMediaIpc({
      ipcMain,
      service,
      authorize: vi.fn(),
      ownerWindow: () => ({}),
      dialog
    })

    const response = await ipcMain.invoke(PAID_MEDIA_IPC_CHANNELS.reconcile, {}, {
      operationId: operation.operationId,
      reason: 'provider-bill-reviewed',
      evidence: 'invoice 2026-07-16 confirms no duplicate charge'
    })

    expect(dialog.showMessageBox).toHaveBeenCalledTimes(2)
    expect(service.reconcileManually).not.toHaveBeenCalled()
    expect(response).toEqual({
      ok: false,
      error: {
        code: 'cancelled',
        message: 'Paid media reconciliation was cancelled'
      }
    })
  })

  it('delegates exact reconciliation evidence only after both confirmations and sanitizes rejection', async () => {
    const ipcMain = new FakeIpcMain()
    const input = {
      operationId: operation.operationId,
      reason: 'provider-bill-reviewed',
      evidence: 'invoice 2026-07-16 confirms no duplicate charge'
    }
    const service = reconciliationServiceStub({
      reconcileManually: vi.fn(async () => {
        throw new Error('invalid evidence near paid-secret and request digest deadbeef')
      })
    })
    const dialog = {
      showMessageBox: vi.fn(async (_owner: unknown, _options: Record<string, unknown>) => ({ response: 1 }))
    }
    registerPaidMediaIpc({
      ipcMain,
      service,
      authorize: vi.fn(),
      ownerWindow: () => ({}),
      dialog
    })

    const response = await ipcMain.invoke(PAID_MEDIA_IPC_CHANNELS.reconcile, {}, input)

    expect(dialog.showMessageBox).toHaveBeenCalledTimes(2)
    expect(dialog.showMessageBox.mock.calls[0][1]).toMatchObject({
      detail: expect.stringContaining(input.evidence)
    })
    expect(dialog.showMessageBox.mock.calls[0][1]).toMatchObject({
      detail: expect.stringContaining(operation.path)
    })
    expect(dialog.showMessageBox.mock.calls[0][1]).toMatchObject({
      detail: expect.stringContaining(`已派发次数：${operation.dispatchCount}`)
    })
    expect(dialog.showMessageBox.mock.calls[0][1]).toMatchObject({
      detail: expect.stringContaining('用户提供的核对说明（未验证）')
    })
    expect(JSON.stringify(dialog.showMessageBox.mock.calls[1][1])).not.toContain(
      '不可删除'
    )
    expect(service.reconcileManually).toHaveBeenCalledWith(input)
    expect(response).toEqual({
      ok: false,
      error: {
        code: 'operation_failed',
        message: 'Paid media operation failed'
      }
    })
    expect(JSON.stringify(response)).not.toMatch(/paid-secret|deadbeef/)
  })

  it('rejects oversized reconciliation evidence before opening a native dialog', async () => {
    const ipcMain = new FakeIpcMain()
    const service = serviceStub()
    const dialog = { showMessageBox: vi.fn(async () => ({ response: 1 })) }
    registerPaidMediaIpc({
      ipcMain,
      service,
      authorize: vi.fn(),
      ownerWindow: () => ({}),
      dialog
    })

    const response = await ipcMain.invoke(PAID_MEDIA_IPC_CHANNELS.reconcile, {}, {
      operationId: operation.operationId,
      reason: 'provider-bill-reviewed',
      evidence: 'x'.repeat(4097)
    })

    expect(response).toEqual({
      ok: false,
      error: {
        code: 'invalid_request',
        message: 'Paid media IPC request is invalid'
      }
    })
    expect(dialog.showMessageBox).not.toHaveBeenCalled()
    expect(service.reconcileManually).not.toHaveBeenCalled()
  })

  it('fails closed before native reconciliation when the trusted main ledger has no matching operation', async () => {
    const ipcMain = new FakeIpcMain()
    const service = serviceStub({ listUnresolved: vi.fn(async () => []) })
    const dialog = {
      showMessageBox: vi.fn(async (_owner: unknown, _options: Record<string, unknown>) => ({
        response: 1
      }))
    }
    registerPaidMediaIpc({
      ipcMain,
      service,
      authorize: vi.fn(),
      ownerWindow: () => ({}),
      dialog
    })

    const response = await ipcMain.invoke(PAID_MEDIA_IPC_CHANNELS.reconcile, {}, {
      operationId: operation.operationId,
      reason: 'provider-bill-reviewed',
      evidence: 'invoice checked'
    })

    expect(dialog.showMessageBox).not.toHaveBeenCalled()
    expect(service.reconcileManually).not.toHaveBeenCalled()
    expect(response).toEqual({
      ok: false,
      error: {
        code: 'operation_failed',
        message: 'Paid media reconciliation is unavailable'
      }
    })
  })

  it('does not cancel an active transport when the send event is unauthorized', async () => {
    const ipcMain = new FakeIpcMain()
    const service = serviceStub({ cancel: vi.fn(() => true) })
    registerPaidMediaIpc({
      ipcMain,
      service,
      authorize: () => {
        throw new Error('untrusted frame')
      },
      ownerWindow: () => ({}),
      dialog: { showMessageBox: vi.fn() }
    })

    await ipcMain.emit(PAID_MEDIA_IPC_CHANNELS.cancel, {}, {
      operationId: operation.operationId
    })

    expect(service.cancel).not.toHaveBeenCalled()
  })

  it('cancels an active transport only after asynchronous sender authorization succeeds', async () => {
    const order: string[] = []
    const ipcMain = new FakeIpcMain()
    const service = serviceStub({
      cancel: vi.fn(() => {
        order.push('cancel')
        return true
      })
    })
    registerPaidMediaIpc({
      ipcMain,
      service,
      authorize: async () => {
        await Promise.resolve()
        order.push('authorize')
      },
      ownerWindow: () => ({}),
      dialog: { showMessageBox: vi.fn() }
    })

    await ipcMain.emit(PAID_MEDIA_IPC_CHANNELS.cancel, {}, {
      operationId: operation.operationId
    })

    expect(order).toEqual(['authorize', 'cancel'])
    expect(service.cancel).toHaveBeenCalledWith(operation.operationId)
  })

  it('replaces a prior registration without letting its stale disposer remove the new handlers', async () => {
    const ipcMain = new FakeIpcMain()
    const first = registerPaidMediaIpc({
      ipcMain,
      service: serviceStub(),
      authorize: vi.fn(),
      ownerWindow: () => ({}),
      dialog: { showMessageBox: vi.fn() }
    })
    const replacementService = serviceStub({
      listUnresolved: vi.fn(async () => [operation])
    })

    const second = registerPaidMediaIpc({
      ipcMain,
      service: replacementService,
      authorize: vi.fn(),
      ownerWindow: () => ({}),
      dialog: { showMessageBox: vi.fn() }
    })
    first.dispose()

    expect(await ipcMain.invoke(PAID_MEDIA_IPC_CHANNELS.list, {})).toEqual({
      ok: true,
      value: [operation]
    })
    expect(ipcMain.listeners.get(PAID_MEDIA_IPC_CHANNELS.cancel)).toHaveLength(1)

    second.dispose()
    expect(ipcMain.handlers.size).toBe(0)
    expect(ipcMain.listeners.get(PAID_MEDIA_IPC_CHANNELS.cancel)).toHaveLength(0)
  })

  it('does not import a legacy unresolved operation from an unauthorized frame', async () => {
    const ipcMain = new FakeIpcMain()
    const service = serviceStub()
    registerPaidMediaIpc({
      ipcMain,
      service,
      authorize: () => {
        throw new Error('untrusted frame')
      },
      ownerWindow: () => ({}),
      dialog: { showMessageBox: vi.fn() }
    })

    const response = await ipcMain.invoke(PAID_MEDIA_IPC_CHANNELS.importLegacy, {}, {
      operationId: operation.operationId,
      path: operation.path,
      requestSha256: 'a'.repeat(64),
      createdAt: operation.createdAt,
      updatedAt: operation.updatedAt,
      state: 'pending'
    })

    expect(service.bootstrapLegacyMigration).not.toHaveBeenCalled()
    expect(response).toEqual({
      ok: false,
      error: {
        code: 'unauthorized',
        message: 'Paid media IPC authorization failed'
      }
    })
  })

  it('imports the exact legacy DTO without returning idempotency or authority secrets', async () => {
    const ipcMain = new FakeIpcMain()
    const input = {
      operationId: operation.operationId,
      path: operation.path,
      requestSha256: 'a'.repeat(64),
      createdAt: operation.createdAt,
      updatedAt: operation.updatedAt,
      state: 'pending' as const
    }
    const service = serviceStub({
      bootstrapLegacyMigration: vi.fn(async () => operation)
    })
    registerPaidMediaIpc({
      ipcMain,
      service,
      authorize: vi.fn(),
      ownerWindow: () => ({}),
      dialog: { showMessageBox: vi.fn() }
    })

    const response = await ipcMain.invoke(PAID_MEDIA_IPC_CHANNELS.importLegacy, {}, input)

    expect(service.bootstrapLegacyMigration).toHaveBeenCalledWith(input)
    expect(response).toEqual({ ok: true, value: operation })
    expect(JSON.stringify(response)).not.toMatch(
      /idempotency|runtimeKey|paidMediaKey|requestSha256|Bearer/i
    )
  })

  it('forwards only the bounded migrated marker for closed-seal replay', async () => {
    const ipcMain = new FakeIpcMain()
    const closed = { state: 'closed' as const, decisionSha256: 'b'.repeat(64) }
    const service = serviceStub({
      bootstrapLegacyMigration: vi.fn(async () => closed)
    })
    registerPaidMediaIpc({
      ipcMain,
      service,
      authorize: vi.fn(),
      ownerWindow: () => ({}),
      dialog: { showMessageBox: vi.fn() }
    })

    const response = await ipcMain.invoke(PAID_MEDIA_IPC_CHANNELS.importLegacy, {}, {
      kind: 'migrated'
    })

    expect(service.bootstrapLegacyMigration).toHaveBeenCalledWith({ kind: 'migrated' })
    expect(response).toEqual({ ok: true, value: closed })
  })

  it('rejects expanded renderer migration markers before they reach Main state', async () => {
    const ipcMain = new FakeIpcMain()
    const service = serviceStub()
    registerPaidMediaIpc({
      ipcMain,
      service,
      authorize: vi.fn(),
      ownerWindow: () => ({}),
      dialog: { showMessageBox: vi.fn() }
    })

    const response = await ipcMain.invoke(PAID_MEDIA_IPC_CHANNELS.importLegacy, {}, {
      kind: 'migrated',
      decisionSha256: 'b'.repeat(64)
    })

    expect(service.bootstrapLegacyMigration).not.toHaveBeenCalled()
    expect(response).toEqual({
      ok: false,
      error: {
        code: 'invalid_request',
        message: 'Paid media IPC request is invalid'
      }
    })
  })

  it('maps stable retry failures to tagged codes without relying on Error prototypes', async () => {
    const ipcMain = new FakeIpcMain()
    const failures = [
      Object.assign(new Error('Paid media retry does not match the original operation'), {
        name: 'PaidMediaLedgerError'
      }),
      Object.assign(
        new Error('Paid media retry operation is too old for automatic replay; reconcile it manually'),
        { name: 'PaidMediaLedgerError' }
      ),
      Object.assign(new Error('A paid media operation is still unresolved'), {
        name: 'PaidMediaUnresolvedOperationError'
      })
    ]
    const service = serviceStub({
      claim: vi.fn(async () => {
        throw failures.shift()
      })
    })
    registerPaidMediaIpc({
      ipcMain,
      service,
      authorize: vi.fn(),
      ownerWindow: () => ({}),
      dialog: { showMessageBox: vi.fn() }
    })
    const request = {
      path: '/v1/images/generations',
      encodedBody: validImageBody,
      retryOperationId: operation.operationId
    }

    const mismatch = await ipcMain.invoke(PAID_MEDIA_IPC_CHANNELS.claim, {}, request)
    const expired = await ipcMain.invoke(PAID_MEDIA_IPC_CHANNELS.claim, {}, request)
    const unresolved = await ipcMain.invoke(PAID_MEDIA_IPC_CHANNELS.claim, {}, request)

    expect(mismatch).toEqual({
      ok: false,
      error: {
        code: 'operation_mismatch',
        message: 'Paid media retry does not match its original operation'
      }
    })
    expect(expired).toEqual({
      ok: false,
      error: {
        code: 'operation_expired',
        message: 'Paid media retry is outside the automatic recovery window'
      }
    })
    expect(unresolved).toEqual({
      ok: false,
      error: {
        code: 'unresolved',
        message: 'Another paid media operation is unresolved'
      }
    })
  })

  it('sanitizes service failures on execute, list, acknowledge, and abandon', async () => {
    const ipcMain = new FakeIpcMain()
    const fail = async (): Promise<never> => {
      throw new Error('Bearer runtime-secret; paid-secret; idempotency=desktop-secret')
    }
    const service = serviceStub({
      execute: vi.fn(fail),
      listUnresolved: vi.fn(fail),
      acknowledgeDelivered: vi.fn(fail),
      abandonUndispatchedClaim: vi.fn(fail)
    })
    registerPaidMediaIpc({
      ipcMain,
      service,
      authorize: vi.fn(),
      ownerWindow: () => ({}),
      dialog: { showMessageBox: vi.fn() }
    })

    const responses = [
      await ipcMain.invoke(PAID_MEDIA_IPC_CHANNELS.execute, {}, {
        operationId: operation.operationId,
        path: operation.path,
        encodedBody: validImageBody
      }),
      await ipcMain.invoke(PAID_MEDIA_IPC_CHANNELS.list, {}),
      await ipcMain.invoke(PAID_MEDIA_IPC_CHANNELS.acknowledge, {}, {
        operationId: operation.operationId,
        resultSha256: 'a'.repeat(64),
        archiveReceiptSha256: 'b'.repeat(64)
      }),
      await ipcMain.invoke(PAID_MEDIA_IPC_CHANNELS.abandon, {}, {
        operationId: operation.operationId,
        evidence: 'anchor failed before dispatch'
      })
    ]

    for (const response of responses) {
      expect(response).toEqual({
        ok: false,
        error: {
          code: 'operation_failed',
          message: 'Paid media operation failed'
        }
      })
      expect(JSON.stringify(response)).not.toMatch(/runtime-secret|paid-secret|desktop-secret/)
    }
  })

  it('rejects claim fields or extra IPC arguments that could widen the paid boundary', async () => {
    const ipcMain = new FakeIpcMain()
    const service = serviceStub()
    registerPaidMediaIpc({
      ipcMain,
      service,
      authorize: vi.fn(),
      ownerWindow: () => ({}),
      dialog: { showMessageBox: vi.fn() }
    })

    const response = await ipcMain.invoke(
      PAID_MEDIA_IPC_CHANNELS.claim,
      {},
      {
        path: operation.path,
        encodedBody: validImageBody,
        paidMediaKey: 'must-not-cross-ipc'
      },
      { runtimeKey: 'also-forbidden' }
    )

    expect(service.claim).not.toHaveBeenCalled()
    expect(response).toEqual({
      ok: false,
      error: {
        code: 'invalid_request',
        message: 'Paid media IPC request is invalid'
      }
    })
  })

  it('sanitizes native-dialog failures before they cross the reconciliation IPC boundary', async () => {
    const ipcMain = new FakeIpcMain()
    const service = reconciliationServiceStub()
    registerPaidMediaIpc({
      ipcMain,
      service,
      authorize: vi.fn(),
      ownerWindow: () => ({}),
      dialog: {
        showMessageBox: vi.fn(async () => {
          throw new Error('native dialog failed near paid-secret')
        })
      }
    })

    const response = await ipcMain.invoke(PAID_MEDIA_IPC_CHANNELS.reconcile, {}, {
      operationId: operation.operationId,
      reason: 'provider-bill-reviewed',
      evidence: 'invoice checked'
    })

    expect(service.reconcileManually).not.toHaveBeenCalled()
    expect(response).toEqual({
      ok: false,
      error: {
        code: 'operation_failed',
        message: 'Paid media operation failed'
      }
    })
    expect(JSON.stringify(response)).not.toContain('paid-secret')
  })
})
