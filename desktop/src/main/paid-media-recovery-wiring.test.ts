import { describe, expect, it, vi } from 'vitest'

import { PaidMediaRecoveryExecutorSlot } from './paid-media-recovery-wiring'
import {
  PAID_MEDIA_RECOVERABLE_HANDLER_VERSION,
  type PaidMediaRecoverableMutationDescriptor,
  type PaidMediaRecoverableMutationExecutor
} from './paid-media-installation-root'

const DESCRIPTOR: PaidMediaRecoverableMutationDescriptor = Object.freeze({
  mode: 'recoverable',
  handlerVersion: PAID_MEDIA_RECOVERABLE_HANDLER_VERSION,
  kind: 'asset_v2_dispatch',
  operationId: 'desktop-op-bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
  intentSha256: '1'.repeat(64),
  transactionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  preparedAt: 1_784_200_000,
  beforeCompositeDigest: '2'.repeat(64),
  beforeAuthorityEvidence: Object.freeze({
    ledgerIdentity: '3'.repeat(64),
    ledgerSequence: 10,
    ledgerStateDigest: '4'.repeat(64),
    vaultStateDigest: '5'.repeat(64),
    capacityIdentity: '6'.repeat(64),
    capacitySequence: 11,
    capacityStateDigest: '7'.repeat(64),
    legacySealDecisionSha256: '8'.repeat(64)
  })
})

function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolve!: () => void
  const promise = new Promise<void>((done) => {
    resolve = done
  })
  return { promise, resolve }
}

describe('PaidMediaRecoveryExecutorSlot', () => {
  it('rejects execution before bind without queueing it for a later delegate', async () => {
    const execute = vi.fn(async () => {})
    const delegate: PaidMediaRecoverableMutationExecutor = { execute }
    const slot = new PaidMediaRecoveryExecutorSlot()

    const rejected = slot.execute(DESCRIPTOR)
    await expect(rejected).rejects.toThrow(/not bound/i)

    slot.bind(delegate)
    await Promise.resolve()
    expect(execute).not.toHaveBeenCalled()
  })

  it('locks the first delegate and rejects every later bind without replacement', async () => {
    const firstExecute = vi.fn(async () => {})
    const first: PaidMediaRecoverableMutationExecutor = { execute: firstExecute }
    const secondExecute = vi.fn(async () => {})
    const second: PaidMediaRecoverableMutationExecutor = { execute: secondExecute }
    const slot = new PaidMediaRecoveryExecutorSlot()

    slot.bind(first)
    expect(() => slot.bind(first)).toThrow(/already bound/i)
    expect(() => slot.bind(second)).toThrow(/already bound/i)

    await slot.execute(DESCRIPTOR)
    expect(firstExecute).toHaveBeenCalledTimes(1)
    expect(secondExecute).not.toHaveBeenCalled()
  })

  it('rejects missing, malformed, and self delegates without consuming the slot', async () => {
    const slot = new PaidMediaRecoveryExecutorSlot()
    const invalidDelegates: unknown[] = [
      undefined,
      null,
      {},
      { execute: null },
      slot
    ]

    for (const invalid of invalidDelegates) {
      expect(() =>
        slot.bind(invalid as PaidMediaRecoverableMutationExecutor)
      ).toThrow('Paid media recovery executor slot delegate is invalid')
    }

    const execute = vi.fn(async () => {})
    slot.bind({ execute })
    await slot.execute(DESCRIPTOR)
    expect(execute).toHaveBeenCalledWith(DESCRIPTOR)
  })

  it('normalizes a hostile execute getter to the stable invalid-delegate error', async () => {
    const slot = new PaidMediaRecoveryExecutorSlot()
    const hostile = Object.create(null) as Record<string, unknown>
    Object.defineProperty(hostile, 'execute', {
      get() {
        throw new Error('hostile getter escaped')
      }
    })

    expect(() =>
      slot.bind(hostile as unknown as PaidMediaRecoverableMutationExecutor)
    ).toThrow('Paid media recovery executor slot delegate is invalid')

    const execute = vi.fn(async () => {})
    slot.bind({ execute })
    await slot.execute(DESCRIPTOR)
    expect(execute).toHaveBeenCalledTimes(1)
  })

  it('pins the first execute method so property mutation cannot bypass one-time bind', async () => {
    const originalExecute = vi.fn(async () => {})
    const replacementExecute = vi.fn(async () => {})
    const delegate = { execute: originalExecute }
    const slot = new PaidMediaRecoveryExecutorSlot()

    slot.bind(delegate)
    delegate.execute = replacementExecute
    await slot.execute(DESCRIPTOR)

    expect(originalExecute).toHaveBeenCalledWith(DESCRIPTOR)
    expect(replacementExecute).not.toHaveBeenCalled()
  })

  it('rejects reentrant bind from an execute getter without consuming the slot', async () => {
    const slot = new PaidMediaRecoveryExecutorSlot()
    const nestedExecute = vi.fn(async () => {})
    const reentrant = Object.create(null) as Record<string, unknown>
    Object.defineProperty(reentrant, 'execute', {
      get() {
        slot.bind({ execute: nestedExecute })
        return async () => {}
      }
    })

    expect(() =>
      slot.bind(reentrant as unknown as PaidMediaRecoverableMutationExecutor)
    ).toThrow('Paid media recovery executor slot delegate is invalid')

    const finalExecute = vi.fn(async () => {})
    slot.bind({ execute: finalExecute })
    await slot.execute(DESCRIPTOR)
    expect(nestedExecute).not.toHaveBeenCalled()
    expect(finalExecute).toHaveBeenCalledWith(DESCRIPTOR)
  })

  it('surfaces a synchronous delegate failure as the execute Promise rejection', async () => {
    const failure = new Error('delegate failed synchronously')
    const slot = new PaidMediaRecoveryExecutorSlot()
    slot.bind({
      execute() {
        throw failure
      }
    })

    let execution!: Promise<void>
    expect(() => {
      execution = slot.execute(DESCRIPTOR)
    }).not.toThrow()
    await expect(execution).rejects.toBe(failure)
  })

  it('forwards complete descriptors by identity and does not serialize concurrent calls', async () => {
    const secondDescriptor: PaidMediaRecoverableMutationDescriptor = Object.freeze({
      ...DESCRIPTOR,
      transactionId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
      operationId: 'desktop-op-dddddddd-dddd-4ddd-8ddd-dddddddddddd',
      intentSha256: '9'.repeat(64)
    })
    const firstFlight = deferred()
    const secondFlight = deferred()
    const observed: Readonly<PaidMediaRecoverableMutationDescriptor>[] = []
    const delegate: PaidMediaRecoverableMutationExecutor = {
      execute(descriptor) {
        observed.push(descriptor)
        return descriptor === DESCRIPTOR ? firstFlight.promise : secondFlight.promise
      }
    }
    const slot = new PaidMediaRecoveryExecutorSlot()
    slot.bind(delegate)

    let firstSettled = false
    const first = slot.execute(DESCRIPTOR).then(() => {
      firstSettled = true
    })
    const second = slot.execute(secondDescriptor)

    expect(observed).toEqual([DESCRIPTOR, secondDescriptor])
    expect(observed[0]).toBe(DESCRIPTOR)
    expect(observed[1]).toBe(secondDescriptor)

    secondFlight.resolve()
    await second
    expect(firstSettled).toBe(false)

    firstFlight.resolve()
    await first
    expect(firstSettled).toBe(true)
  })
})
