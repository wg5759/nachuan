import { beforeEach, describe, expect, it, vi } from 'vitest'

function fakeLocalStorage(): Storage {
  const values = new Map<string, string>()
  return {
    get length() {
      return values.size
    },
    clear: vi.fn(() => values.clear()),
    getItem: vi.fn((key: string) => values.get(key) ?? null),
    key: vi.fn((index: number) => [...values.keys()][index] ?? null),
    removeItem: vi.fn((key: string) => {
      values.delete(key)
    }),
    setItem: vi.fn((key: string, value: string) => {
      values.set(key, value)
    })
  }
}

describe('paid media recovery message persistence', () => {
  beforeEach(() => {
    vi.resetModules()
    vi.unstubAllGlobals()
    vi.stubGlobal('localStorage', fakeLocalStorage())
    vi.stubGlobal('window', {
      addEventListener: vi.fn(),
      removeEventListener: vi.fn()
    })
  })

  it('flushes the operation reference immediately and rehydrates it after renderer restart', async () => {
    const first = await import('./store')
    first.useAppStore.getState().ensureConversation()
    const conversationId = first.useAppStore.getState().currentConvId
    expect(conversationId).toBeTruthy()
    first.useAppStore.getState().setConvMessages(conversationId!, [
      { role: 'user', content: 'private cat prompt', ts: 1 },
      {
        role: 'assistant',
        content: 'request result unknown',
        ts: 1,
        paidMediaOperation: {
          operationId: 'desktop-op-11111111-1111-4111-8111-111111111111',
          kind: 'image',
          model: 'image-model'
        }
      }
    ])
    first.flushAppStorePersistence()

    const raw = localStorage.getItem('agg-conversations')
    expect(raw).toBeTruthy()
    const persisted = JSON.parse(raw!) as {
      state: { conversations: { messages: Record<string, unknown>[] }[] }
    }
    const reference = persisted.state.conversations[0].messages[1].paidMediaOperation
    expect(reference).toEqual({
      operationId: 'desktop-op-11111111-1111-4111-8111-111111111111',
      kind: 'image',
      model: 'image-model'
    })
    expect(JSON.stringify(reference)).not.toContain('private cat prompt')

    vi.resetModules()
    const restarted = await import('./store')
    expect(
      restarted.useAppStore.getState().conversations[0].messages[1].paidMediaOperation
    ).toEqual(reference)
  })

  it('keeps a failed persistence snapshot pending so the same durable result can be flushed again', async () => {
    const store = await import('./store')
    store.useAppStore.getState().ensureConversation()
    const conversationId = store.useAppStore.getState().currentConvId
    expect(conversationId).toBeTruthy()
    store.useAppStore.getState().setConvMessages(conversationId!, [
      { role: 'user', content: 'cat', ts: 2 },
      {
        role: 'assistant',
        content: '',
        images: ['https://media.invalid/durable.png'],
        ts: 2,
        completedAt: 3
      }
    ])

    const storage = localStorage
    const originalSetItem = storage.setItem.bind(storage)
    let rejectOnce = true
    storage.setItem = vi.fn((key: string, value: string) => {
      if (key === 'agg-conversations' && rejectOnce) {
        rejectOnce = false
        throw new DOMException('quota exceeded', 'QuotaExceededError')
      }
      originalSetItem(key, value)
    })

    expect(store.flushAppStorePersistence()).toBe(false)
    expect(localStorage.getItem('agg-conversations')).toBeNull()
    expect(store.flushAppStorePersistence()).toBe(true)
    expect(localStorage.getItem('agg-conversations')).toContain(
      'https://media.invalid/durable.png'
    )
  })

  it('does not certify a paid image result that partialize silently omitted from storage', async () => {
    const store = await import('./store')
    store.useAppStore.getState().ensureConversation()
    const conversationId = store.useAppStore.getState().currentConvId
    expect(conversationId).toBeTruthy()
    const operationId = 'desktop-op-22222222-2222-4222-8222-222222222222'
    const deliveryProof = {
      operationId,
      resultSha256: 'c'.repeat(64),
      archiveReceiptSha256: 'd'.repeat(64)
    }
    const oversizedDataUrl = `data:image/png;base64,${'A'.repeat(2_500_001)}`
    store.useAppStore.getState().setConvMessages(conversationId!, [
      { role: 'user', content: 'cat', ts: 2 },
      {
        role: 'assistant',
        content: '',
        images: [oversizedDataUrl],
        ts: 2,
        startedAt: 2,
        paidMediaOperation: {
          operationId,
          kind: 'image',
          model: 'image-model',
          phase: 'awaiting_ack',
          deliveryProof
        }
      }
    ])

    expect(
      store.flushAndVerifyPaidMediaResult({
        conversationId: conversationId!,
        messageTs: 2,
        operationId,
        deliveryProof,
        images: [oversizedDataUrl]
      })
    ).toBe(false)

    const raw = localStorage.getItem('agg-conversations')
    expect(raw).toContain(operationId)
    expect(raw).not.toContain(oversizedDataUrl)
  })

  it('certifies only the exact persisted conversation, operation, and small result receipt', async () => {
    const store = await import('./store')
    store.useAppStore.getState().ensureConversation()
    const conversationId = store.useAppStore.getState().currentConvId
    expect(conversationId).toBeTruthy()
    const operationId = 'desktop-op-33333333-3333-4333-8333-333333333333'
    const deliveryProof = {
      operationId,
      resultSha256: 'a'.repeat(64),
      archiveReceiptSha256: 'b'.repeat(64)
    }
    const image = `nachuan-paid-media://sha256/${'9'.repeat(64)}`
    store.useAppStore.getState().setConvMessages(conversationId!, [
      { role: 'user', content: 'cat', ts: 3 },
      {
        role: 'assistant',
        content: '',
        images: [image],
        ts: 3,
        startedAt: 3,
        paidMediaOperation: {
          operationId,
          kind: 'image',
          model: 'image-model',
          phase: 'awaiting_ack',
          deliveryProof
        }
      }
    ])

    expect(
      store.flushAndVerifyPaidMediaResult({
        conversationId: conversationId!,
        messageTs: 3,
        operationId,
        deliveryProof,
        images: [image]
      })
    ).toBe(true)
    expect(
      store.flushAndVerifyPaidMediaResult({
        conversationId: conversationId!,
        messageTs: 3,
        operationId,
        deliveryProof,
        images: ['https://media.invalid/wrong.png']
      })
    ).toBe(false)
    expect(
      store.flushAndVerifyPaidMediaResult({
        conversationId: conversationId!,
        messageTs: 3,
        operationId,
        deliveryProof: { ...deliveryProof, archiveReceiptSha256: 'c'.repeat(64) },
        images: [image]
      })
    ).toBe(false)
  })

  it.each([
    'https://media.invalid/not-durable.png',
    'data:image/png;base64,aW5saW5lLW5vdC1kdXJhYmxl'
  ])('never certifies a non-vault paid image reference: %s', async (image) => {
    const store = await import('./store')
    store.useAppStore.getState().ensureConversation()
    const conversationId = store.useAppStore.getState().currentConvId
    expect(conversationId).toBeTruthy()
    const operationId = 'desktop-op-44444444-4444-4444-8444-444444444444'
    const deliveryProof = {
      operationId,
      resultSha256: 'e'.repeat(64),
      archiveReceiptSha256: 'f'.repeat(64)
    }
    store.useAppStore.getState().setConvMessages(conversationId!, [
      { role: 'user', content: 'cat', ts: 4 },
      {
        role: 'assistant',
        content: '',
        images: [image],
        ts: 4,
        startedAt: 4,
        paidMediaOperation: {
          operationId,
          kind: 'image',
          model: 'image-model',
          phase: 'awaiting_ack',
          deliveryProof
        }
      }
    ])

    expect(
      store.flushAndVerifyPaidMediaResult({
        conversationId: conversationId!,
        messageTs: 4,
        operationId,
        deliveryProof,
        images: [image]
      })
    ).toBe(false)
  })
})
