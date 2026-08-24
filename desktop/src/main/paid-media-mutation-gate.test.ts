import { describe, expect, it } from 'vitest'

import { PaidMediaMutationGate } from './paid-media-mutation-gate'
import {
  PAID_MEDIA_RECOVERABLE_HANDLER_VERSION,
  paidMediaCompositeEvidenceDigest,
  type PaidMediaAuthorityEvidence,
  type PaidMediaRecoverableMutationDescriptor
} from './paid-media-installation-root'

const TRANSACTION_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
const OPERATION_ID = 'desktop-op-bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'

const BEFORE_EVIDENCE: PaidMediaAuthorityEvidence = Object.freeze({
  ledgerIdentity: '1'.repeat(64),
  ledgerSequence: 10,
  ledgerStateDigest: '2'.repeat(64),
  vaultStateDigest: '3'.repeat(64),
  capacityIdentity: '4'.repeat(64),
  capacitySequence: 11,
  capacityStateDigest: '5'.repeat(64),
  legacySealDecisionSha256: '6'.repeat(64)
})

function recoveryDescriptor(): PaidMediaRecoverableMutationDescriptor {
  return Object.freeze({
    mode: 'recoverable',
    handlerVersion: PAID_MEDIA_RECOVERABLE_HANDLER_VERSION,
    kind: 'asset_v2_dispatch',
    operationId: OPERATION_ID,
    intentSha256: '7'.repeat(64),
    transactionId: TRANSACTION_ID,
    preparedAt: 1_784_200_000,
    beforeCompositeDigest: paidMediaCompositeEvidenceDigest(BEFORE_EVIDENCE),
    beforeAuthorityEvidence: BEFORE_EVIDENCE
  })
}

function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolve!: () => void
  const promise = new Promise<void>((done) => {
    resolve = done
  })
  return { promise, resolve }
}

describe('PaidMediaMutationGate', () => {
  it('revokes a legacy token inherited by a detached Promise after the action returns', async () => {
    const rootCalls: Array<string | undefined> = []
    const root = {
      assertMutationContext(transactionId?: string) {
        rootCalls.push(transactionId)
        if (transactionId !== TRANSACTION_ID) throw new Error('wrong Root transaction')
      }
    }
    const gate = new PaidMediaMutationGate(root)
    const release = deferred()
    let detached!: Promise<void>
    let detachedWrites = 0

    await gate.runLegacy(
      {
        transactionId: TRANSACTION_ID,
        kind: 'claim',
        operationId: null
      },
      async () => {
        expect(
          gate.assert({
            transactionId: TRANSACTION_ID,
            mode: 'legacy',
            kind: 'claim',
            operationId: null,
            intentSha256: null
          })
        ).toEqual({
          transactionId: TRANSACTION_ID,
          mode: 'legacy',
          kind: 'claim',
          operationId: null,
          intentSha256: null,
          open: true
        })
        gate.guard()
        detached = release.promise.then(() => {
          gate.guard()
          detachedWrites += 1
        })
      }
    )

    release.resolve()
    await expect(detached).rejects.toThrow(/closed|revoked/i)
    expect(detachedWrites).toBe(0)
    expect(() => gate.guard()).toThrow(/context/i)
    expect(rootCalls).toEqual([TRANSACTION_ID, TRANSACTION_ID, TRANSACTION_ID])
  })

  it('binds a recoverable context to the full Root descriptor', async () => {
    const rootCalls: Array<string | undefined> = []
    const root = {
      assertMutationContext(transactionId?: string) {
        rootCalls.push(transactionId)
        if (transactionId !== TRANSACTION_ID) throw new Error('wrong Root transaction')
      }
    }
    const gate = new PaidMediaMutationGate(root)
    const descriptor = recoveryDescriptor()

    const result = await gate.runRecoverable(descriptor, async () =>
      gate.assert({
        transactionId: descriptor.transactionId,
        mode: 'recoverable',
        kind: descriptor.kind,
        operationId: descriptor.operationId,
        intentSha256: descriptor.intentSha256
      })
    )

    expect(result).toEqual({
      transactionId: TRANSACTION_ID,
      mode: 'recoverable',
      kind: 'asset_v2_dispatch',
      operationId: OPERATION_ID,
      intentSha256: '7'.repeat(64),
      open: true
    })
    expect(rootCalls).toEqual([TRANSACTION_ID, TRANSACTION_ID])
    expect(() => gate.guard()).toThrow(/context/i)
  })

  it('rejects nested legacy or recoverable actions before the nested action runs', async () => {
    const root = {
      assertMutationContext(transactionId?: string) {
        if (transactionId !== TRANSACTION_ID) throw new Error('wrong Root transaction')
      }
    }
    const gate = new PaidMediaMutationGate(root)
    let nestedWrites = 0

    await gate.runLegacy(
      { transactionId: TRANSACTION_ID, kind: 'claim', operationId: null },
      async () => {
        await expect(
          gate.runRecoverable(recoveryDescriptor(), async () => {
            nestedWrites += 1
          })
        ).rejects.toThrow(/nested/i)
        await expect(
          gate.runLegacy(
            { transactionId: TRANSACTION_ID, kind: 'archive', operationId: null },
            async () => {
              nestedWrites += 1
            }
          )
        ).rejects.toThrow(/nested/i)
      }
    )

    expect(nestedWrites).toBe(0)
  })

  it('rejects a second gate for the same Root authority and a gate without Root assertion', () => {
    const root = { assertMutationContext: () => undefined }
    new PaidMediaMutationGate(root)

    expect(() => new PaidMediaMutationGate(root)).toThrow(/already exists/i)
    expect(() => new PaidMediaMutationGate({} as never)).toThrow(/Root assertion/i)
  })

  it('rejects a wrong Root transaction and closes its token before any action', async () => {
    const root = {
      assertMutationContext(transactionId?: string) {
        if (transactionId !== TRANSACTION_ID) throw new Error('wrong Root transaction')
      }
    }
    const gate = new PaidMediaMutationGate(root)
    let writes = 0

    await expect(
      gate.runLegacy(
        {
          transactionId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
          kind: 'claim',
          operationId: null
        },
        async () => {
          writes += 1
        }
      )
    ).rejects.toThrow(/Root transaction/i)
    expect(writes).toBe(0)
    expect(() => gate.guard()).toThrow(/context/i)
  })

  it.each([
    ['extra field', { ...recoveryDescriptor(), extra: true }],
    ['wrong handler', { ...recoveryDescriptor(), handlerVersion: 2 }],
    ['zero intent', { ...recoveryDescriptor(), intentSha256: '0'.repeat(64) }],
    [
      'before-evidence drift',
      {
        ...recoveryDescriptor(),
        beforeAuthorityEvidence: {
          ...BEFORE_EVIDENCE,
          vaultStateDigest: '8'.repeat(64)
        }
      }
    ]
  ])('rejects a recoverable descriptor with %s before its action', async (_label, value) => {
    const root = { assertMutationContext: () => undefined }
    const gate = new PaidMediaMutationGate(root)
    let writes = 0

    await expect(
      gate.runRecoverable(value, async () => {
        writes += 1
      })
    ).rejects.toThrow(/descriptor|evidence/i)
    expect(writes).toBe(0)
  })

  it('rejects an expected transaction or descriptor binding that differs from the open token', async () => {
    const root = {
      assertMutationContext(transactionId?: string) {
        if (transactionId !== TRANSACTION_ID) throw new Error('wrong Root transaction')
      }
    }
    const gate = new PaidMediaMutationGate(root)

    await gate.runRecoverable(recoveryDescriptor(), async () => {
      expect(() =>
        gate.assert({
          transactionId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
          mode: 'recoverable',
          kind: 'asset_v2_dispatch',
          operationId: OPERATION_ID,
          intentSha256: '7'.repeat(64)
        })
      ).toThrow(/does not match/i)
      expect(() =>
        gate.assert({
          transactionId: TRANSACTION_ID,
          mode: 'recoverable',
          kind: 'asset_v2_ack_completion',
          operationId: OPERATION_ID,
          intentSha256: '7'.repeat(64)
        })
      ).toThrow(/does not match/i)
    })
  })
})
