import { describe, expect, it, vi } from 'vitest'

import { convergePaidMediaAcknowledgements } from './paid-media-ack-convergence'

const operationId = 'desktop-op-11111111-1111-4111-8111-111111111111'
const deliveryProof = {
  operationId,
  resultSha256: 'a'.repeat(64),
  archiveReceiptSha256: 'b'.repeat(64)
}

function conversations() {
  return [
    {
      id: 'conversation-a',
      messages: [
        {
          role: 'assistant',
          content: '',
          ts: 10,
          images: ['https://media.invalid/cat.png'],
          paidMediaOperation: {
            operationId,
            kind: 'image' as const,
            model: 'image-model',
            phase: 'awaiting_ack' as const,
            deliveryProof
          }
        }
      ]
    }
  ]
}

describe('paid media awaiting-ack convergence', () => {
  it('re-verifies persisted result, acknowledges result_ready, then clears its anchor', async () => {
    const order: string[] = []
    const verify = vi.fn(() => {
      order.push('verify')
      return true
    })
    const acknowledge = vi.fn(async () => {
      order.push('ack')
    })
    const clear = vi.fn(() => {
      order.push('clear')
      return true
    })

    const result = await convergePaidMediaAcknowledgements({
      conversations: conversations(),
      unresolved: [{ operationId, state: 'result_ready' }],
      verify,
      acknowledge,
      clear
    })

    expect(order).toEqual(['verify', 'ack', 'clear'])
    expect(result.acknowledged).toEqual([operationId])
    expect(acknowledge).toHaveBeenCalledWith(deliveryProof)
  })

  it('clears a terminal/pruned stale anchor without issuing another acknowledgement', async () => {
    const acknowledge = vi.fn()
    const clear = vi.fn(() => true)

    await convergePaidMediaAcknowledgements({
      conversations: conversations(),
      unresolved: [],
      verify: vi.fn(() => true),
      acknowledge,
      clear
    })

    expect(acknowledge).not.toHaveBeenCalled()
    expect(clear).toHaveBeenCalledTimes(1)
  })

  it.each([
    ['result is not in the serialized snapshot', 'result_ready', false],
    ['operation has not reached result_ready', 'recoverable', true]
  ])('leaves the anchor when %s', async (_label, state, verified) => {
    const acknowledge = vi.fn()
    const clear = vi.fn()

    await convergePaidMediaAcknowledgements({
      conversations: conversations(),
      unresolved: [{ operationId, state }],
      verify: vi.fn(() => verified),
      acknowledge,
      clear
    })

    expect(acknowledge).not.toHaveBeenCalled()
    expect(clear).not.toHaveBeenCalled()
  })
})
