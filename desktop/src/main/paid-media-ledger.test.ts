import { createHash } from 'node:crypto'
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, describe, expect, it } from 'vitest'

import {
  nodePaidMediaAtomicIO,
  PaidMediaLedger,
  type PaidMediaLedgerDependencies
} from './paid-media-ledger'

const roots: string[] = []
const noAcl = (): void => undefined
const RECOVERY_DOMAIN_SHA256 = 'f'.repeat(64)
const PAIR_INTENT_RECEIPT_DOMAIN = Buffer.from(
  'nachuan.desktop.paid-media-ledger-pair-intent.v1\0',
  'ascii'
)
const deliveryProof = (operationId: string, responseJson: string) => ({
  operationId,
  resultSha256: createHash('sha256').update(responseJson, 'utf8').digest('hex'),
  archiveReceiptSha256: 'e'.repeat(64)
})
const fakeStorage = {
  isEncryptionAvailable: () => true,
  encryptString: (value: string) =>
    Buffer.from(Buffer.from(value, 'utf8').map((byte) => byte ^ 0xa5)),
  decryptString: (value: Buffer) =>
    Buffer.from(Buffer.from(value).map((byte) => byte ^ 0xa5)).toString('utf8')
}

function readSealedDocument(path: string): {
  envelope: Record<string, unknown>
  document: Record<string, unknown>
} {
  const envelope = JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>
  const document = JSON.parse(
    fakeStorage.decryptString(Buffer.from(String(envelope.ciphertext), 'base64'))
  ) as Record<string, unknown>
  return { envelope, document }
}

function writeSealedDocument(
  path: string,
  envelope: Record<string, unknown>,
  document: Record<string, unknown>
): void {
  writeFileSync(
    path,
    JSON.stringify({
      ...envelope,
      ciphertext: fakeStorage.encryptString(JSON.stringify(document)).toString('base64')
    }),
    'utf8'
  )
}

function pairIntentReceiptForTest(document: Record<string, unknown>): string {
  return createHash('sha256')
    .update(PAIR_INTENT_RECEIPT_DOMAIN)
    .update(
      JSON.stringify({
        ledgerIdentity: document.ledgerIdentity,
        beforeSequence: document.beforeSequence,
        targetSequence: document.targetSequence,
        beforeAnchorSha256: document.beforeAnchorSha256,
        beforeLedgerSha256: document.beforeLedgerSha256,
        targetAnchorSha256: document.targetAnchorSha256,
        targetLedgerSha256: document.targetLedgerSha256
      }),
      'utf8'
    )
    .digest('hex')
}

function testLedger(
  now = 1_750_000_000_000,
  uuid = '11111111-1111-4111-8111-111111111111'
): { path: string; deps: PaidMediaLedgerDependencies } {
  const root = mkdtempSync(join(tmpdir(), 'nachuan-paid-main-ledger-'))
  roots.push(root)
  return {
    path: join(root, 'paid-media-ledger.json'),
    deps: {
      safeStorage: fakeStorage,
      harden: noAcl,
      now: () => now,
      uuid: () => uuid,
      atomicIO: nodePaidMediaAtomicIO
    }
  }
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true })
}, 60_000)

// Every case in this suite exercises the real atomic file/anchor/pair-intent path.
// Keep the wider Windows durability budget local to this suite so ordinary tests
// still fail at the repository-wide 30 second boundary.
describe('main-process paid media ledger', { timeout: 90_000 }, () => {
  it('exposes a strict composite commitment and gates every logical write but not reads', async () => {
    const item = testLedger()
    const ledger = new PaidMediaLedger(item.path, item.deps)
    const initial = await ledger.provisionAuthorityLedger()
    let mutationContext = false
    ledger.setMutationGuard(() => {
      if (!mutationContext) throw new Error('outside authority transaction')
    })

    await expect(ledger.listPublic()).resolves.toEqual([])
    await expect(ledger.inspectAuthorityEvidence()).resolves.toEqual(initial)
    await expect(
      ledger.claim({
        path: '/v1/images/generations',
        requestSha256: '1'.repeat(64),
        recoveryDomainSha256: RECOVERY_DOMAIN_SHA256
      })
    ).rejects.toThrow(/outside authority transaction/i)

    mutationContext = true
    await ledger.claim({
      path: '/v1/images/generations',
      requestSha256: '1'.repeat(64),
      recoveryDomainSha256: RECOVERY_DOMAIN_SHA256
    })
    mutationContext = false
    const changed = await ledger.inspectAuthorityEvidence()
    expect(changed.ledgerIdentity).toBe(initial.ledgerIdentity)
    expect(changed.ledgerSequence).toBe(initial.ledgerSequence + 1)
    expect(changed.ledgerStateDigest).not.toBe(initial.ledgerStateDigest)
  })

  it('imports a legacy pending operation as possibly dispatched but blocks untrusted replay', async () => {
    const now = 1_750_000_000_000
    const item = testLedger(now)
    const ledger = new PaidMediaLedger(item.path, item.deps)
    const uuid = '12121212-1212-4121-8121-121212121212'
    const requestSha256 = '0'.repeat(64)

    const imported = await ledger.importLegacyUnresolved({
      operationId: `desktop-op-${uuid}`,
      path: '/v1/images/generations',
      requestSha256,
      createdAt: now - 2_000,
      updatedAt: now - 1_000,
      state: 'pending'
    })

    expect(imported).toEqual({
      operationId: `desktop-op-${uuid}`,
      path: '/v1/images/generations',
      state: 'recoverable',
      createdAt: now - 2_000,
      updatedAt: now - 1_000,
      dispatchCount: 1,
      lastStatus: 0
    })
    await expect(
      ledger.claim({
        path: '/v1/images/generations',
        requestSha256,
        recoveryDomainSha256: RECOVERY_DOMAIN_SHA256,
        retryOperationId: `desktop-op-${uuid}`
      })
    ).rejects.toThrow(/trusted recovery domain|reconcile.*manually/i)
    expect(readFileSync(item.path, 'utf8')).not.toContain(`desktop-${uuid}`)
  })

  it('preserves legacy recovery status and retry evidence during import', async () => {
    const now = 1_750_000_000_000
    const item = testLedger(now)
    const ledger = new PaidMediaLedger(item.path, item.deps)
    const operationId = 'desktop-op-13131313-1313-4131-8131-131313131313'

    await expect(
      ledger.importLegacyUnresolved({
        operationId,
        path: '/v1/videos/generations',
        requestSha256: '1'.repeat(64),
        createdAt: now - 5_000,
        updatedAt: now - 1_000,
        state: 'recoverable',
        lastStatus: 429,
        retryAfterSeconds: 45
      })
    ).resolves.toEqual({
      operationId,
      path: '/v1/videos/generations',
      state: 'recoverable',
      createdAt: now - 5_000,
      updatedAt: now - 1_000,
      dispatchCount: 1,
      lastStatus: 429,
      retryAfterSeconds: 45
    })
  })

  it('treats an identical legacy import as idempotent without rewriting the ledger', async () => {
    const now = 1_750_000_000_000
    const item = testLedger(now)
    const ledger = new PaidMediaLedger(item.path, item.deps)
    const legacy = {
      operationId: 'desktop-op-14141414-1414-4141-8141-141414141414',
      path: '/v1/images/generations' as const,
      requestSha256: '2'.repeat(64),
      createdAt: now - 10_000,
      updatedAt: now - 9_000,
      state: 'recoverable' as const,
      lastStatus: 503,
      retryAfterSeconds: 30
    }

    const first = await ledger.importLegacyUnresolved(legacy)
    const before = readFileSync(item.path, 'utf8')
    const second = await new PaidMediaLedger(item.path, item.deps).importLegacyUnresolved(legacy)

    expect(second).toEqual(first)
    expect(readFileSync(item.path, 'utf8')).toBe(before)
    expect(await ledger.listPublic()).toEqual([first])
  })

  it('rejects rather than trusts a plaintext legacy idempotency key', async () => {
    const now = 1_750_000_000_000
    const item = testLedger(now)
    const ledger = new PaidMediaLedger(item.path, item.deps)

    await expect(
      ledger.importLegacyUnresolved({
        operationId: 'desktop-op-15151515-1515-4151-8151-151515151515',
        idempotencyKey: 'desktop-aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
        path: '/v1/images/generations',
        requestSha256: '3'.repeat(64),
        createdAt: now - 2_000,
        updatedAt: now - 1_000,
        state: 'pending'
      } as never)
    ).rejects.toThrow('invalid')
    expect(await ledger.listPublic()).toEqual([])
  })

  it('validates every legacy identity, request, timestamp, state, status, and retry field strictly', async () => {
    const now = 1_750_000_000_000
    const base = {
      operationId: 'desktop-op-16161616-1616-4161-8161-161616161616',
      path: '/v1/images/generations',
      requestSha256: '4'.repeat(64),
      createdAt: now - 2_000,
      updatedAt: now - 1_000,
      state: 'pending'
    }
    const invalidInputs: unknown[] = [
      { ...base, operationId: 'desktop-op-not-a-uuid' },
      { ...base, path: '/v1/chat/completions' },
      { ...base, requestSha256: 'ABC'.repeat(21) },
      { ...base, createdAt: now, updatedAt: now - 1 },
      { ...base, createdAt: now + 300_001, updatedAt: now + 300_001 },
      { ...base, state: 'delivered' },
      { ...base, lastStatus: 0 },
      { ...base, state: 'recoverable' },
      { ...base, state: 'recoverable', lastStatus: 600 },
      { ...base, state: 'recoverable', lastStatus: 429, retryAfterSeconds: 0 },
      { ...base, state: 'recoverable', lastStatus: 429, retryAfterSeconds: 901 },
      [base, { ...base, operationId: 'desktop-op-17171717-1717-4171-8171-171717171717' }]
    ]

    for (const invalid of invalidInputs) {
      const item = testLedger(now)
      const ledger = new PaidMediaLedger(item.path, item.deps)
      await expect(ledger.importLegacyUnresolved(invalid as never)).rejects.toThrow('invalid')
      expect(await ledger.listPublic()).toEqual([])
    }
  })

  it('fails closed without rewriting when a repeated legacy identity conflicts', async () => {
    const now = 1_750_000_000_000
    const item = testLedger(now)
    const ledger = new PaidMediaLedger(item.path, item.deps)
    const legacy = {
      operationId: 'desktop-op-18181818-1818-4181-8181-181818181818',
      path: '/v1/images/generations' as const,
      requestSha256: '5'.repeat(64),
      createdAt: now - 2_000,
      updatedAt: now - 1_000,
      state: 'pending' as const
    }
    await ledger.importLegacyUnresolved(legacy)
    const before = readFileSync(item.path, 'utf8')

    await expect(
      ledger.importLegacyUnresolved({ ...legacy, requestSha256: '6'.repeat(64) })
    ).rejects.toThrow('conflicts')
    expect(readFileSync(item.path, 'utf8')).toBe(before)
  })

  it('refuses a legacy import while a different operation is unresolved', async () => {
    const now = 1_750_000_000_000
    const item = testLedger(now)
    const ledger = new PaidMediaLedger(item.path, item.deps)
    await ledger.claim({
      path: '/v1/images/generations',
      requestSha256: '7'.repeat(64),
      recoveryDomainSha256: RECOVERY_DOMAIN_SHA256
    })
    const before = readFileSync(item.path, 'utf8')

    await expect(
      ledger.importLegacyUnresolved({
        operationId: 'desktop-op-19191919-1919-4191-8191-191919191919',
        path: '/v1/videos/generations',
        requestSha256: '8'.repeat(64),
        createdAt: now - 2_000,
        updatedAt: now - 1_000,
        state: 'pending'
      })
    ).rejects.toThrow('still unresolved')
    expect(readFileSync(item.path, 'utf8')).toBe(before)
  })

  it('imports beside an existing terminal tombstone without deleting it', async () => {
    let now = 1_750_000_000_000
    const item = testLedger(now)
    item.deps.now = () => now
    const ledger = new PaidMediaLedger(item.path, item.deps)
    const current = await ledger.claim({
      path: '/v1/images/generations',
      requestSha256: '9'.repeat(64),
      recoveryDomainSha256: RECOVERY_DOMAIN_SHA256
    })
    now += 1
    await ledger.markDispatching(current.operation.operationId)
    now += 1
    const terminalResponse = JSON.stringify({ id: 'terminal-result' })
    await ledger.markResultReady({
      operationId: current.operation.operationId,
      status: 200,
      responseJson: terminalResponse
    } as never)
    now += 1
    const delivered = await ledger.markDelivered(
      deliveryProof(current.operation.operationId, terminalResponse)
    )
    now += 1

    const imported = await ledger.importLegacyUnresolved({
      operationId: 'desktop-op-20202020-2020-4202-8202-202020202020',
      path: '/v1/videos/generations',
      requestSha256: 'b'.repeat(64),
      createdAt: now - 2,
      updatedAt: now - 1,
      state: 'pending'
    })

    expect(await ledger.listPublic()).toEqual([delivered, imported])
  })

  it('imports old legacy evidence but blocks replay because its recovery domain is untrusted', async () => {
    const retryWindowMs = 27 * 24 * 60 * 60 * 1000
    const now = 1_750_000_000_000
    const item = testLedger(now)
    const ledger = new PaidMediaLedger(item.path, item.deps)
    const operationId = 'desktop-op-21212121-2121-4212-8212-212121212121'
    const requestSha256 = 'c'.repeat(64)

    const imported = await ledger.importLegacyUnresolved({
      operationId,
      path: '/v1/images/generations',
      requestSha256,
      createdAt: now - retryWindowMs - 1,
      updatedAt: now - retryWindowMs,
      state: 'pending'
    })

    expect(imported.state).toBe('recoverable')
    await expect(
      ledger.claim({
        path: '/v1/images/generations',
        requestSha256,
        recoveryDomainSha256: RECOVERY_DOMAIN_SHA256,
        retryOperationId: operationId
      })
    ).rejects.toThrow(/trusted recovery domain|reconcile.*manually/i)
    expect(await ledger.listPublic()).toEqual([imported])
  })

  it('serializes concurrent legacy imports so at most one unresolved record is committed', async () => {
    const now = 1_750_000_000_000
    const item = testLedger(now)
    const left = new PaidMediaLedger(item.path, item.deps)
    const right = new PaidMediaLedger(item.path, item.deps)
    const legacy = (uuid: string, requestSha256: string) => ({
      operationId: `desktop-op-${uuid}`,
      path: '/v1/images/generations' as const,
      requestSha256,
      createdAt: now - 2_000,
      updatedAt: now - 1_000,
      state: 'pending' as const
    })

    const settled = await Promise.allSettled([
      left.importLegacyUnresolved(
        legacy('22222222-2222-4222-8222-222222222222', 'd'.repeat(64))
      ),
      right.importLegacyUnresolved(
        legacy('23232323-2323-4232-8232-232323232323', 'e'.repeat(64))
      )
    ])

    expect(settled.filter((result) => result.status === 'fulfilled')).toHaveLength(1)
    expect(settled.filter((result) => result.status === 'rejected')).toHaveLength(1)
    expect(await left.listPublic()).toHaveLength(1)
  })

  it('persists an encrypted claim before returning and exposes no key or digest in its public DTO', async () => {
    const item = testLedger()
    const requestSha256 = 'a'.repeat(64)
    const ledger = new PaidMediaLedger(item.path, item.deps)

    const claimed = await ledger.claim({
      path: '/v1/images/generations',
      requestSha256,
      recoveryDomainSha256: RECOVERY_DOMAIN_SHA256
    })

    expect(claimed.operation).toEqual({
      operationId: 'desktop-op-11111111-1111-4111-8111-111111111111',
      path: '/v1/images/generations',
      state: 'claimed',
      createdAt: 1_750_000_000_000,
      updatedAt: 1_750_000_000_000,
      dispatchCount: 0
    })
    expect(claimed.dispatch).toEqual({
      idempotencyKey: 'desktop-11111111-1111-4111-8111-111111111111',
      requestSha256
    })
    expect(claimed.reused).toBe(false)
    expect(claimed.operation).not.toHaveProperty('idempotencyKey')
    expect(claimed.operation).not.toHaveProperty('requestSha256')

    const raw = readFileSync(item.path, 'utf8')
    expect(raw).toContain('nachuan.paid-media-main-ledger.envelope.v1')
    expect(raw).not.toContain(claimed.dispatch.idempotencyKey)
    expect(raw).not.toContain(requestSha256)

    const reopened = new PaidMediaLedger(item.path, item.deps)
    expect(await reopened.listPublic()).toEqual([claimed.operation])
  })

  it('reuses the original key only for an exact retry identity', async () => {
    const item = testLedger()
    const ledger = new PaidMediaLedger(item.path, item.deps)
    const requestSha256 = 'b'.repeat(64)
    const first = await ledger.claim({
      path: '/v1/videos/generations',
      requestSha256,
      recoveryDomainSha256: RECOVERY_DOMAIN_SHA256
    })

    const retry = await ledger.claim({
      path: '/v1/videos/generations',
      requestSha256,
      recoveryDomainSha256: RECOVERY_DOMAIN_SHA256,
      retryOperationId: first.operation.operationId
    })

    expect(retry).toEqual({ ...first, reused: true })
    expect(await ledger.listPublic()).toEqual([first.operation])
    await expect(
      ledger.claim({
        path: '/v1/images/generations',
        requestSha256,
        recoveryDomainSha256: RECOVERY_DOMAIN_SHA256,
        retryOperationId: first.operation.operationId
      })
    ).rejects.toThrow('does not match')
    await expect(
      ledger.claim({
        path: '/v1/videos/generations',
        requestSha256: 'c'.repeat(64),
        recoveryDomainSha256: RECOVERY_DOMAIN_SHA256,
        retryOperationId: first.operation.operationId
      })
    ).rejects.toThrow('does not match')
    expect(await ledger.listPublic()).toEqual([first.operation])
  })

  it('binds an exact retry to the original paid capability recovery domain', async () => {
    const item = testLedger()
    const ledger = new PaidMediaLedger(item.path, item.deps)
    const requestSha256 = '1'.repeat(64)
    const originalDomain = '2'.repeat(64)
    const first = await ledger.claim({
      path: '/v1/images/generations',
      requestSha256,
      recoveryDomainSha256: originalDomain
    } as never)

    await expect(
      ledger.claim({
        path: '/v1/images/generations',
        requestSha256,
        recoveryDomainSha256: '3'.repeat(64),
        retryOperationId: first.operation.operationId
      } as never)
    ).rejects.toThrow(/recovery domain|match/i)
    await expect(
      ledger.claim({
        path: '/v1/images/generations',
        requestSha256,
        recoveryDomainSha256: originalDomain,
        retryOperationId: first.operation.operationId
      } as never)
    ).resolves.toMatchObject({ reused: true, dispatch: first.dispatch })
  })

  it('binds v2 dispatch exactly once and makes an exact restart replay byte-for-byte read-only', async () => {
    let now = 1_750_000_000_000
    const item = testLedger()
    item.deps.now = () => now
    const ledger = new PaidMediaLedger(item.path, item.deps)
    const claimed = await ledger.claim({
      path: '/v1/images/generations',
      requestSha256: '3'.repeat(64),
      recoveryDomainSha256: RECOVERY_DOMAIN_SHA256
    })
    const dispatchInput = {
      operationId: claimed.operation.operationId,
      path: '/v1/images/generations' as const,
      requestSha256: claimed.dispatch.requestSha256,
      recoveryDomainSha256: RECOVERY_DOMAIN_SHA256,
      dispatchReceiptSha256: '4'.repeat(64)
    }
    let mutationAllowed = false
    ledger.setMutationGuard(() => {
      if (!mutationAllowed) throw new Error('outside root mutation')
    })
    await expect(ledger.ensureV2DispatchingOnce(dispatchInput)).rejects.toThrow(
      'outside root mutation'
    )

    mutationAllowed = true
    now += 1
    const first = await ledger.ensureV2DispatchingOnce(dispatchInput)
    mutationAllowed = false
    expect(first).toEqual({
      ...claimed.operation,
      state: 'dispatching',
      updatedAt: now,
      dispatchCount: 1,
      v2DispatchReceiptSha256: dispatchInput.dispatchReceiptSha256
    })
    expect(first).not.toHaveProperty('idempotencyKey')
    expect(first).not.toHaveProperty('requestSha256')
    const exactBytes = {
      ledger: readFileSync(item.path, 'utf8'),
      anchor: readFileSync(`${item.path}.anchor`, 'utf8'),
      intent: readFileSync(`${item.path}.pair-intent`, 'utf8')
    }
    const exactEvidence = await ledger.inspectAuthorityEvidence()

    now += 10_000
    await expect(ledger.ensureV2DispatchingOnce(dispatchInput)).resolves.toEqual(first)
    await expect(
      new PaidMediaLedger(item.path, item.deps).ensureV2DispatchingOnce(dispatchInput)
    ).resolves.toEqual(first)
    expect(readFileSync(item.path, 'utf8')).toBe(exactBytes.ledger)
    expect(readFileSync(`${item.path}.anchor`, 'utf8')).toBe(exactBytes.anchor)
    expect(readFileSync(`${item.path}.pair-intent`, 'utf8')).toBe(exactBytes.intent)
    expect(await new PaidMediaLedger(item.path, item.deps).inspectAuthorityEvidence()).toEqual(
      exactEvidence
    )

    for (const conflicting of [
      { ...dispatchInput, dispatchReceiptSha256: '5'.repeat(64) },
      { ...dispatchInput, requestSha256: '6'.repeat(64) },
      { ...dispatchInput, recoveryDomainSha256: '7'.repeat(64) },
      { ...dispatchInput, path: '/v1/videos/generations' as const }
    ]) {
      await expect(
        new PaidMediaLedger(item.path, item.deps).ensureV2DispatchingOnce(conflicting)
      ).rejects.toThrow(/conflict/i)
    }
    await expect(ledger.markDispatching(claimed.operation.operationId)).rejects.toThrow(
      /v2-bound|legacy dispatch/i
    )
    expect(readFileSync(item.path, 'utf8')).toBe(exactBytes.ledger)
  })

  it('binds a v2 result-ready ACK intent once and replays the exact result without a write', async () => {
    let now = 1_750_000_000_000
    const item = testLedger()
    item.deps.now = () => now
    const ledger = new PaidMediaLedger(item.path, item.deps)
    const claimed = await ledger.claim({
      path: '/v1/images/generations',
      requestSha256: '6'.repeat(64),
      recoveryDomainSha256: RECOVERY_DOMAIN_SHA256
    })
    let mutationAllowed = true
    ledger.setMutationGuard(() => {
      if (!mutationAllowed) throw new Error('outside root mutation')
    })
    const dispatchReceiptSha256 = '7'.repeat(64)
    const ackIntentReceiptSha256 = '8'.repeat(64)
    await ledger.ensureV2DispatchingOnce({
      operationId: claimed.operation.operationId,
      path: '/v1/images/generations',
      requestSha256: claimed.dispatch.requestSha256,
      recoveryDomainSha256: RECOVERY_DOMAIN_SHA256,
      dispatchReceiptSha256
    })
    const responseJson = JSON.stringify({ schema: 'nachuan.paid-media-result.v2', assets: [] })
    const resultInput = {
      operationId: claimed.operation.operationId,
      dispatchReceiptSha256,
      ackIntentReceiptSha256,
      status: 200,
      responseJson
    }

    mutationAllowed = false
    await expect(ledger.ensureV2ResultReadyOnce(resultInput)).rejects.toThrow(
      'outside root mutation'
    )
    mutationAllowed = true
    now += 1
    const first = await ledger.ensureV2ResultReadyOnce(resultInput)
    mutationAllowed = false
    expect(first).toEqual({
      ...claimed.operation,
      state: 'result_ready',
      updatedAt: now,
      dispatchCount: 1,
      v2DispatchReceiptSha256: dispatchReceiptSha256,
      v2AckIntentReceiptSha256: ackIntentReceiptSha256
    })
    const exactBytes = {
      ledger: readFileSync(item.path, 'utf8'),
      anchor: readFileSync(`${item.path}.anchor`, 'utf8'),
      intent: readFileSync(`${item.path}.pair-intent`, 'utf8')
    }
    const exactEvidence = await ledger.inspectAuthorityEvidence()

    now += 10_000
    await expect(ledger.ensureV2ResultReadyOnce(resultInput)).resolves.toEqual(first)
    await expect(
      new PaidMediaLedger(item.path, item.deps).ensureV2ResultReadyOnce(resultInput)
    ).resolves.toEqual(first)
    expect(readFileSync(item.path, 'utf8')).toBe(exactBytes.ledger)
    expect(readFileSync(`${item.path}.anchor`, 'utf8')).toBe(exactBytes.anchor)
    expect(readFileSync(`${item.path}.pair-intent`, 'utf8')).toBe(exactBytes.intent)
    expect(await new PaidMediaLedger(item.path, item.deps).inspectAuthorityEvidence()).toEqual(
      exactEvidence
    )

    for (const conflicting of [
      { ...resultInput, dispatchReceiptSha256: '9'.repeat(64) },
      { ...resultInput, ackIntentReceiptSha256: 'a'.repeat(64) },
      { ...resultInput, status: 201 },
      { ...resultInput, responseJson: JSON.stringify({ different: true }) }
    ]) {
      await expect(
        new PaidMediaLedger(item.path, item.deps).ensureV2ResultReadyOnce(conflicting)
      ).rejects.toThrow(/conflict/i)
    }
    expect(readFileSync(item.path, 'utf8')).toBe(exactBytes.ledger)

    mutationAllowed = true
    await ledger.markDelivered(deliveryProof(claimed.operation.operationId, responseJson))
    mutationAllowed = false
    await expect(ledger.ensureV2ResultReadyOnce(resultInput)).rejects.toThrow(/conflict/i)
  })

  it('keeps both legacy result writes and legacy result states outside v2 ACK-intent recovery', async () => {
    const bound = testLedger()
    const boundLedger = new PaidMediaLedger(bound.path, bound.deps)
    const boundClaim = await boundLedger.claim({
      path: '/v1/videos/generations',
      requestSha256: 'b'.repeat(64),
      recoveryDomainSha256: RECOVERY_DOMAIN_SHA256
    })
    await boundLedger.ensureV2DispatchingOnce({
      operationId: boundClaim.operation.operationId,
      path: '/v1/videos/generations',
      requestSha256: boundClaim.dispatch.requestSha256,
      recoveryDomainSha256: RECOVERY_DOMAIN_SHA256,
      dispatchReceiptSha256: 'c'.repeat(64)
    })
    const boundBytes = readFileSync(bound.path, 'utf8')
    await expect(
      boundLedger.markResultReady({
        operationId: boundClaim.operation.operationId,
        status: 202,
        responseJson: JSON.stringify({ id: 'must-not-write' })
      })
    ).rejects.toThrow(/v2-bound|legacy result/i)
    expect(readFileSync(bound.path, 'utf8')).toBe(boundBytes)

    const legacy = testLedger()
    const legacyLedger = new PaidMediaLedger(legacy.path, legacy.deps)
    const legacyClaim = await legacyLedger.claim({
      path: '/v1/videos/generations',
      requestSha256: 'd'.repeat(64),
      recoveryDomainSha256: RECOVERY_DOMAIN_SHA256
    })
    await legacyLedger.markDispatching(legacyClaim.operation.operationId)
    await legacyLedger.markResultReady({
      operationId: legacyClaim.operation.operationId,
      status: 202,
      responseJson: JSON.stringify({ id: 'legacy-result' })
    })
    const legacyBytes = readFileSync(legacy.path, 'utf8')
    await expect(
      legacyLedger.ensureV2ResultReadyOnce({
        operationId: legacyClaim.operation.operationId,
        dispatchReceiptSha256: 'e'.repeat(64),
        ackIntentReceiptSha256: 'f'.repeat(64),
        status: 202,
        responseJson: JSON.stringify({ id: 'legacy-result' })
      })
    ).rejects.toThrow(/cannot bind|conflict|current state/i)
    expect(readFileSync(legacy.path, 'utf8')).toBe(legacyBytes)
  })

  it('refuses to retrofit a v2 receipt onto every legacy dispatched/result state', async () => {
    for (const state of ['dispatching', 'recoverable', 'result_ready'] as const) {
      const item = testLedger()
      const ledger = new PaidMediaLedger(item.path, item.deps)
      const claimed = await ledger.claim({
        path: '/v1/videos/generations',
        requestSha256: '8'.repeat(64),
        recoveryDomainSha256: RECOVERY_DOMAIN_SHA256
      })
      await ledger.markDispatching(claimed.operation.operationId)
      if (state === 'recoverable') {
        await ledger.markRecoverable({ operationId: claimed.operation.operationId, status: 503 })
      } else if (state === 'result_ready') {
        await ledger.markResultReady({
          operationId: claimed.operation.operationId,
          status: 202,
          responseJson: JSON.stringify({ id: 'legacy-result' })
        })
      }
      const before = readFileSync(item.path, 'utf8')
      await expect(
        ledger.ensureV2DispatchingOnce({
          operationId: claimed.operation.operationId,
          path: '/v1/videos/generations',
          requestSha256: claimed.dispatch.requestSha256,
          recoveryDomainSha256: RECOVERY_DOMAIN_SHA256,
          dispatchReceiptSha256: '9'.repeat(64)
        })
      ).rejects.toThrow(/cannot bind|current state/i)
      expect(readFileSync(item.path, 'utf8')).toBe(before)
    }
  })

  it('validates the v2 dispatch input as a strict closed receipt schema', async () => {
    const item = testLedger()
    const ledger = new PaidMediaLedger(item.path, item.deps)
    const claimed = await ledger.claim({
      path: '/v1/images/generations',
      requestSha256: 'a'.repeat(64),
      recoveryDomainSha256: RECOVERY_DOMAIN_SHA256
    })
    const before = readFileSync(item.path, 'utf8')
    await expect(
      ledger.ensureV2DispatchingOnce({
        operationId: claimed.operation.operationId,
        path: '/v1/images/generations',
        requestSha256: claimed.dispatch.requestSha256,
        recoveryDomainSha256: RECOVERY_DOMAIN_SHA256,
        dispatchReceiptSha256: 'b'.repeat(64),
        extra: true
      } as never)
    ).rejects.toThrow(/receipt.*invalid/i)
    await expect(
      ledger.ensureV2DispatchingOnce({
        operationId: claimed.operation.operationId,
        path: '/v1/images/generations',
        requestSha256: claimed.dispatch.requestSha256,
        recoveryDomainSha256: RECOVERY_DOMAIN_SHA256,
        dispatchReceiptSha256: '0'.repeat(64)
      })
    ).rejects.toThrow(/receipt.*invalid/i)
    expect(readFileSync(item.path, 'utf8')).toBe(before)

    await ledger.ensureV2DispatchingOnce({
      operationId: claimed.operation.operationId,
      path: '/v1/images/generations',
      requestSha256: claimed.dispatch.requestSha256,
      recoveryDomainSha256: RECOVERY_DOMAIN_SHA256,
      dispatchReceiptSha256: 'c'.repeat(64)
    })
    const beforeResult = readFileSync(item.path, 'utf8')
    for (const invalid of [
      {
        operationId: claimed.operation.operationId,
        dispatchReceiptSha256: '0'.repeat(64),
        ackIntentReceiptSha256: 'd'.repeat(64),
        status: 200,
        responseJson: '{}'
      },
      {
        operationId: claimed.operation.operationId,
        dispatchReceiptSha256: 'c'.repeat(64),
        ackIntentReceiptSha256: '0'.repeat(64),
        status: 200,
        responseJson: '{}'
      },
      {
        operationId: claimed.operation.operationId,
        dispatchReceiptSha256: 'c'.repeat(64),
        ackIntentReceiptSha256: 'd'.repeat(64),
        status: 200,
        responseJson: '{}',
        extra: true
      }
    ]) {
      await expect(ledger.ensureV2ResultReadyOnce(invalid as never)).rejects.toThrow(
        /receipt.*invalid|result.*invalid/i
      )
    }
    expect(readFileSync(item.path, 'utf8')).toBe(beforeResult)
  })

  it('rejects a zero v2 dispatch marker from an otherwise exact persisted pair receipt', async () => {
    const item = testLedger()
    const ledger = new PaidMediaLedger(item.path, item.deps)
    const claimed = await ledger.claim({
      path: '/v1/images/generations',
      requestSha256: 'c'.repeat(64),
      recoveryDomainSha256: RECOVERY_DOMAIN_SHA256
    })
    await ledger.ensureV2DispatchingOnce({
      operationId: claimed.operation.operationId,
      path: '/v1/images/generations',
      requestSha256: claimed.dispatch.requestSha256,
      recoveryDomainSha256: RECOVERY_DOMAIN_SHA256,
      dispatchReceiptSha256: 'd'.repeat(64)
    })

    const sealedLedger = readSealedDocument(item.path)
    const records = sealedLedger.document.records as Array<Record<string, unknown>>
    records[0].v2DispatchReceiptSha256 = '0'.repeat(64)
    const tamperedLedgerEnvelope = JSON.stringify({
      ...sealedLedger.envelope,
      ciphertext: fakeStorage
        .encryptString(JSON.stringify(sealedLedger.document))
        .toString('base64')
    })
    writeFileSync(item.path, tamperedLedgerEnvelope, 'utf8')

    const sealedIntent = readSealedDocument(`${item.path}.pair-intent`)
    sealedIntent.document.targetLedgerEnvelope = tamperedLedgerEnvelope
    sealedIntent.document.targetLedgerSha256 = createHash('sha256')
      .update(tamperedLedgerEnvelope, 'utf8')
      .digest('hex')
    sealedIntent.document.receiptSha256 = pairIntentReceiptForTest(sealedIntent.document)
    writeSealedDocument(`${item.path}.pair-intent`, sealedIntent.envelope, sealedIntent.document)

    await expect(new PaidMediaLedger(item.path, item.deps).listPublic()).rejects.toThrow(
      /dispatch.*digest|record fields/i
    )
  })

  it('rejects a zero v2 ACK-intent marker from an otherwise exact persisted pair receipt', async () => {
    const item = testLedger()
    const ledger = new PaidMediaLedger(item.path, item.deps)
    const claimed = await ledger.claim({
      path: '/v1/images/generations',
      requestSha256: 'e'.repeat(64),
      recoveryDomainSha256: RECOVERY_DOMAIN_SHA256
    })
    await ledger.ensureV2DispatchingOnce({
      operationId: claimed.operation.operationId,
      path: '/v1/images/generations',
      requestSha256: claimed.dispatch.requestSha256,
      recoveryDomainSha256: RECOVERY_DOMAIN_SHA256,
      dispatchReceiptSha256: 'a'.repeat(64)
    })
    await ledger.ensureV2ResultReadyOnce({
      operationId: claimed.operation.operationId,
      dispatchReceiptSha256: 'a'.repeat(64),
      ackIntentReceiptSha256: 'b'.repeat(64),
      status: 200,
      responseJson: JSON.stringify({ result: 'ready' })
    })

    const sealedLedger = readSealedDocument(item.path)
    const records = sealedLedger.document.records as Array<Record<string, unknown>>
    records[0].v2AckIntentReceiptSha256 = '0'.repeat(64)
    const tamperedLedgerEnvelope = JSON.stringify({
      ...sealedLedger.envelope,
      ciphertext: fakeStorage
        .encryptString(JSON.stringify(sealedLedger.document))
        .toString('base64')
    })
    writeFileSync(item.path, tamperedLedgerEnvelope, 'utf8')

    const sealedIntent = readSealedDocument(`${item.path}.pair-intent`)
    sealedIntent.document.targetLedgerEnvelope = tamperedLedgerEnvelope
    sealedIntent.document.targetLedgerSha256 = createHash('sha256')
      .update(tamperedLedgerEnvelope, 'utf8')
      .digest('hex')
    sealedIntent.document.receiptSha256 = pairIntentReceiptForTest(sealedIntent.document)
    writeSealedDocument(`${item.path}.pair-intent`, sealedIntent.envelope, sealedIntent.document)

    await expect(new PaidMediaLedger(item.path, item.deps).listPublic()).rejects.toThrow(
      /ack.*digest|record fields/i
    )
  })

  it('persists the paid operation lifecycle and retains delivered tombstones without blocking a new claim', async () => {
    let now = 1_750_000_000_000
    const uuids = [
      '22222222-2222-4222-8222-222222222222',
      '33333333-3333-4333-8333-333333333333'
    ]
    const item = testLedger()
    item.deps.now = () => now
    item.deps.uuid = () => uuids.shift() ?? '44444444-4444-4444-8444-444444444444'
    const ledger = new PaidMediaLedger(item.path, item.deps)
    const requestSha256 = 'd'.repeat(64)
    const first = await ledger.claim({
      path: '/v1/images/generations',
      requestSha256,
      recoveryDomainSha256: RECOVERY_DOMAIN_SHA256
    })

    now += 1
    expect(await ledger.markDispatching(first.operation.operationId)).toMatchObject({
      state: 'dispatching',
      dispatchCount: 1,
      updatedAt: now
    })
    now += 1
    expect(
      await ledger.markRecoverable({
        operationId: first.operation.operationId,
        status: 425,
        retryAfterSeconds: 12
      })
    ).toMatchObject({
      state: 'recoverable',
      dispatchCount: 1,
      lastStatus: 425,
      retryAfterSeconds: 12,
      updatedAt: now
    })
    expect(
      await ledger.claim({
        path: '/v1/images/generations',
        requestSha256,
        recoveryDomainSha256: RECOVERY_DOMAIN_SHA256,
        retryOperationId: first.operation.operationId
      })
    ).toMatchObject({ reused: true, dispatch: first.dispatch })

    now += 1
    expect(await ledger.markDispatching(first.operation.operationId)).toMatchObject({
      state: 'dispatching',
      dispatchCount: 2,
      updatedAt: now
    })
    now += 1
    const lifecycleResponse = JSON.stringify({ id: 'lifecycle-result' })
    expect(
      await ledger.markResultReady({
        operationId: first.operation.operationId,
        status: 201,
        responseJson: lifecycleResponse
      } as never)
    ).not.toHaveProperty('resultSha256')
    now += 1
    const delivered = await ledger.markDelivered(
      deliveryProof(first.operation.operationId, lifecycleResponse)
    )
    expect(delivered).toMatchObject({
      state: 'delivered',
      deliveredAt: now,
      updatedAt: now
    })

    now += 1
    const second = await ledger.claim({
      path: '/v1/videos/generations',
      requestSha256: 'f'.repeat(64),
      recoveryDomainSha256: RECOVERY_DOMAIN_SHA256
    })
    expect(second.operation.state).toBe('claimed')
    expect(await ledger.listPublic()).toEqual([delivered, second.operation])
  })

  it('requires bounded native reconciliation evidence and persists a non-destructive tombstone', async () => {
    let now = 1_750_000_000_000
    const item = testLedger()
    item.deps.now = () => now
    const ledger = new PaidMediaLedger(item.path, item.deps)
    const first = await ledger.claim({
      path: '/v1/videos/generations',
      requestSha256: '1'.repeat(64),
      recoveryDomainSha256: RECOVERY_DOMAIN_SHA256
    })
    const before = await ledger.listPublic()

    await expect(
      ledger.reconcile({
        operationId: first.operation.operationId,
        reason: '供应商账单已人工核对'
      } as never)
    ).rejects.toThrow('reconciliation')
    await expect(
      ledger.reconcile({
        operationId: first.operation.operationId,
        reason: '供应商账单已人工核对',
        evidence: 'provider-task=synthetic-42; invoice=synthetic-99',
        state: 'delivered'
      } as never)
    ).rejects.toThrow('reconciliation')
    expect(await ledger.listPublic()).toEqual(before)

    now += 1
    const reconciled = await ledger.reconcile({
      operationId: first.operation.operationId,
      reason: '供应商账单已人工核对',
      evidence: 'provider-task=synthetic-42; invoice=synthetic-99'
    })
    expect(reconciled).toMatchObject({
      state: 'reconciled',
      updatedAt: now,
      reconciliation: {
        at: now,
        reason: '供应商账单已人工核对',
        evidence: 'provider-task=synthetic-42; invoice=synthetic-99'
      }
    })
    expect(await new PaidMediaLedger(item.path, item.deps).listPublic()).toEqual([reconciled])
  })

  it('retains terminal keys for 30 days and prunes only expired tombstones during a later main mutation', async () => {
    const thirtyDaysMs = 30 * 24 * 60 * 60 * 1000
    let now = 1_750_000_000_000
    const uuids = [
      '55555555-5555-4555-8555-555555555555',
      '66666666-6666-4666-8666-666666666666',
      '77777777-7777-4777-8777-777777777777'
    ]
    const item = testLedger()
    item.deps.now = () => now
    item.deps.uuid = () => uuids.shift() ?? '88888888-8888-4888-8888-888888888888'
    const ledger = new PaidMediaLedger(item.path, item.deps)

    const first = await ledger.claim({
      path: '/v1/images/generations',
      requestSha256: '2'.repeat(64),
      recoveryDomainSha256: RECOVERY_DOMAIN_SHA256
    })
    now += 1
    await ledger.markDispatching(first.operation.operationId)
    now += 1
    const retainedResponse = JSON.stringify({ id: 'retained-result' })
    await ledger.markResultReady({
      operationId: first.operation.operationId,
      status: 200,
      responseJson: retainedResponse
    } as never)
    now += 1
    const delivered = await ledger.markDelivered(
      deliveryProof(first.operation.operationId, retainedResponse)
    )

    now = Number(delivered.deliveredAt) + thirtyDaysMs - 1
    const second = await ledger.claim({
      path: '/v1/videos/generations',
      requestSha256: '4'.repeat(64),
      recoveryDomainSha256: RECOVERY_DOMAIN_SHA256
    })
    expect(await ledger.listPublic()).toEqual([delivered, second.operation])
    now += 1
    const reconciled = await ledger.reconcile({
      operationId: second.operation.operationId,
      reason: '人工确认未产生供应商任务',
      evidence: 'provider-query=synthetic-none; invoice=synthetic-none'
    })

    now = Number(delivered.deliveredAt) + thirtyDaysMs
    const third = await ledger.claim({
      path: '/v1/images/generations',
      requestSha256: '5'.repeat(64),
      recoveryDomainSha256: RECOVERY_DOMAIN_SHA256
    })
    expect(await ledger.listPublic()).toEqual([reconciled, third.operation])
  })

  it('serializes concurrent claims across ledger instances so exactly one succeeds', async () => {
    const item = testLedger()
    const uuids = [
      '99999999-9999-4999-8999-999999999999',
      'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
    ]
    item.deps.uuid = () => uuids.shift() ?? 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
    const left = new PaidMediaLedger(item.path, item.deps)
    const right = new PaidMediaLedger(item.path, item.deps)

    const settled = await Promise.allSettled([
      left.claim({
        path: '/v1/images/generations',
        requestSha256: '6'.repeat(64),
        recoveryDomainSha256: RECOVERY_DOMAIN_SHA256
      }),
      right.claim({
        path: '/v1/videos/generations',
        requestSha256: '7'.repeat(64),
        recoveryDomainSha256: RECOVERY_DOMAIN_SHA256
      })
    ])

    expect(settled.filter((result) => result.status === 'fulfilled')).toHaveLength(1)
    expect(settled.filter((result) => result.status === 'rejected')).toHaveLength(1)
    const rejected = settled.find((result) => result.status === 'rejected')
    expect(rejected).toMatchObject({
      reason: { name: 'PaidMediaUnresolvedOperationError' }
    })
    expect(await left.listPublic()).toHaveLength(1)
  })

  it('fails closed when an initialized ledger file is deleted instead of treating it as first use', async () => {
    const item = testLedger()
    const ledger = new PaidMediaLedger(item.path, item.deps)
    await ledger.claim({
      path: '/v1/images/generations',
      requestSha256: '4'.repeat(64),
      recoveryDomainSha256: RECOVERY_DOMAIN_SHA256
    })
    expect(existsSync(`${item.path}.anchor`)).toBe(true)

    rmSync(item.path)
    rmSync(`${item.path}.pair-intent`)
    await expect(new PaidMediaLedger(item.path, item.deps).listPublic()).rejects.toThrow(
      /missing|rollback|anchor/i
    )
    expect(existsSync(item.path)).toBe(false)
  })

  it('fails closed when the ledger sequence is rolled back below its encrypted anchor floor', async () => {
    const item = testLedger()
    const ledger = new PaidMediaLedger(item.path, item.deps)
    const first = await ledger.claim({
      path: '/v1/videos/generations',
      requestSha256: '5'.repeat(64),
      recoveryDomainSha256: RECOVERY_DOMAIN_SHA256
    })
    const rolledBackLedger = readFileSync(item.path, 'utf8')
    await ledger.markDispatching(first.operation.operationId)
    const anchoredBytes = readFileSync(`${item.path}.anchor`, 'utf8')

    rmSync(`${item.path}.pair-intent`)
    writeFileSync(item.path, rolledBackLedger, 'utf8')
    await expect(new PaidMediaLedger(item.path, item.deps).listPublic()).rejects.toThrow(
      /sequence|rollback/i
    )
    expect(readFileSync(`${item.path}.anchor`, 'utf8')).toBe(anchoredBytes)
    expect(readFileSync(item.path, 'utf8')).toBe(rolledBackLedger)
  })

  it('recovers an interrupted anchor/body publication only from its exact durable pair intent', async () => {
    const item = testLedger()
    const writes: string[] = []
    let failLedgerWrite = false
    item.deps.atomicIO = {
      readUtf8: nodePaidMediaAtomicIO.readUtf8,
      writeUtf8Atomic: (path, value, harden) => {
        writes.push(path)
        if (failLedgerWrite && path === item.path) throw new Error('simulated ledger write loss')
        nodePaidMediaAtomicIO.writeUtf8Atomic(path, value, harden)
      }
    }
    const ledger = new PaidMediaLedger(item.path, item.deps)
    const claimed = await ledger.claim({
      path: '/v1/images/generations',
      requestSha256: '6'.repeat(64),
      recoveryDomainSha256: RECOVERY_DOMAIN_SHA256
    })

    failLedgerWrite = true
    await expect(ledger.markDispatching(claimed.operation.operationId)).rejects.toThrow(
      'simulated ledger write loss'
    )
    expect(writes.slice(-3)).toEqual([
      `${item.path}.pair-intent`,
      `${item.path}.anchor`,
      item.path
    ])

    failLedgerWrite = false
    await expect(new PaidMediaLedger(item.path, item.deps).listPublic()).resolves.toEqual([
      expect.objectContaining({
        operationId: claimed.operation.operationId,
        state: 'dispatching',
        dispatchCount: 1
      })
    ])
  })

  it('recovers first provisioning when only the durable pair intent was published', async () => {
    const item = testLedger()
    let failAnchorWrite = true
    item.deps.atomicIO = {
      readUtf8: nodePaidMediaAtomicIO.readUtf8,
      writeUtf8Atomic: (path, value, harden) => {
        if (failAnchorWrite && path === `${item.path}.anchor`) {
          throw new Error('simulated initial anchor loss')
        }
        nodePaidMediaAtomicIO.writeUtf8Atomic(path, value, harden)
      }
    }

    await expect(new PaidMediaLedger(item.path, item.deps).provisionAuthorityLedger()).rejects.toThrow(
      'simulated initial anchor loss'
    )
    expect(existsSync(`${item.path}.pair-intent`)).toBe(true)
    expect(existsSync(`${item.path}.anchor`)).toBe(false)
    expect(existsSync(item.path)).toBe(false)

    failAnchorWrite = false
    const recovered = await new PaidMediaLedger(item.path, item.deps).provisionAuthorityLedger()
    expect(recovered.ledgerSequence).toBe(1)
    await expect(new PaidMediaLedger(item.path, item.deps).listPublic()).resolves.toEqual([])
  })

  it('accepts an exact target pair when publication completed before the caller observed failure', async () => {
    const item = testLedger()
    let throwAfterLedgerPublish = true
    item.deps.atomicIO = {
      readUtf8: nodePaidMediaAtomicIO.readUtf8,
      writeUtf8Atomic: (path, value, harden) => {
        nodePaidMediaAtomicIO.writeUtf8Atomic(path, value, harden)
        if (throwAfterLedgerPublish && path === item.path) {
          throw new Error('simulated loss after body publication')
        }
      }
    }

    await expect(
      new PaidMediaLedger(item.path, item.deps).claim({
        path: '/v1/images/generations',
        requestSha256: '6'.repeat(64),
        recoveryDomainSha256: RECOVERY_DOMAIN_SHA256
      })
    ).rejects.toThrow('simulated loss after body publication')
    throwAfterLedgerPublish = false
    await expect(new PaidMediaLedger(item.path, item.deps).listPublic()).resolves.toEqual([
      expect.objectContaining({ state: 'claimed', dispatchCount: 0 })
    ])
  })

  it('keeps and atomically replaces the latest pair receipt after every logical mutation', async () => {
    const item = testLedger()
    const ledger = new PaidMediaLedger(item.path, item.deps)
    const claimed = await ledger.claim({
      path: '/v1/images/generations',
      requestSha256: '6'.repeat(64),
      recoveryDomainSha256: RECOVERY_DOMAIN_SHA256
    })
    const firstIntent = readFileSync(`${item.path}.pair-intent`, 'utf8')

    await ledger.markDispatching(claimed.operation.operationId)
    const secondIntent = readFileSync(`${item.path}.pair-intent`, 'utf8')
    expect(secondIntent).not.toBe(firstIntent)
    expect(existsSync(`${item.path}.pair-intent`)).toBe(true)
    await expect(new PaidMediaLedger(item.path, item.deps).listPublic()).resolves.toEqual([
      expect.objectContaining({ state: 'dispatching', dispatchCount: 1 })
    ])
  })

  it('rejects crossed publication order and unknown bytes even when a valid intent exists', async () => {
    const crossed = testLedger()
    const crossedLedger = new PaidMediaLedger(crossed.path, crossed.deps)
    const claimed = await crossedLedger.claim({
      path: '/v1/videos/generations',
      requestSha256: '6'.repeat(64),
      recoveryDomainSha256: RECOVERY_DOMAIN_SHA256
    })
    const beforeAnchor = readFileSync(`${crossed.path}.anchor`, 'utf8')
    await crossedLedger.markDispatching(claimed.operation.operationId)
    const targetBody = readFileSync(crossed.path, 'utf8')
    writeFileSync(`${crossed.path}.anchor`, beforeAnchor, 'utf8')
    await expect(new PaidMediaLedger(crossed.path, crossed.deps).listPublic()).rejects.toThrow(
      /crossed|ordered steps/i
    )
    expect(readFileSync(crossed.path, 'utf8')).toBe(targetBody)
    expect(readFileSync(`${crossed.path}.anchor`, 'utf8')).toBe(beforeAnchor)

    const unknown = testLedger()
    const unknownLedger = new PaidMediaLedger(unknown.path, unknown.deps)
    await unknownLedger.claim({
      path: '/v1/images/generations',
      requestSha256: '7'.repeat(64),
      recoveryDomainSha256: RECOVERY_DOMAIN_SHA256
    })
    const unknownAnchor = readFileSync(`${unknown.path}.anchor`, 'utf8')
    writeFileSync(unknown.path, '{"unknown":true}', 'utf8')
    await expect(new PaidMediaLedger(unknown.path, unknown.deps).listPublic()).rejects.toThrow(
      /expected-before|exact target/i
    )
    expect(readFileSync(`${unknown.path}.anchor`, 'utf8')).toBe(unknownAnchor)
    expect(readFileSync(unknown.path, 'utf8')).toBe('{"unknown":true}')
  })

  it('rejects corrupt, extra-field, wrong-previous, and identity-drift pair intent evidence', async () => {
    const corrupt = testLedger()
    await new PaidMediaLedger(corrupt.path, corrupt.deps).claim({
      path: '/v1/images/generations',
      requestSha256: '8'.repeat(64),
      recoveryDomainSha256: RECOVERY_DOMAIN_SHA256
    })
    const corruptLedger = readFileSync(corrupt.path, 'utf8')
    const corruptAnchor = readFileSync(`${corrupt.path}.anchor`, 'utf8')
    writeFileSync(`${corrupt.path}.pair-intent`, '{not-json', 'utf8')
    await expect(new PaidMediaLedger(corrupt.path, corrupt.deps).listPublic()).rejects.toThrow(
      /pair intent.*corrupt/i
    )
    expect(readFileSync(corrupt.path, 'utf8')).toBe(corruptLedger)
    expect(readFileSync(`${corrupt.path}.anchor`, 'utf8')).toBe(corruptAnchor)

    const extra = testLedger()
    await new PaidMediaLedger(extra.path, extra.deps).claim({
      path: '/v1/images/generations',
      requestSha256: '9'.repeat(64),
      recoveryDomainSha256: RECOVERY_DOMAIN_SHA256
    })
    const extraIntent = readSealedDocument(`${extra.path}.pair-intent`)
    extraIntent.document.untrusted = true
    writeSealedDocument(`${extra.path}.pair-intent`, extraIntent.envelope, extraIntent.document)
    await expect(new PaidMediaLedger(extra.path, extra.deps).listPublic()).rejects.toThrow(
      /pair intent schema/i
    )

    const wrongPrevious = testLedger()
    const wrongPreviousLedger = new PaidMediaLedger(wrongPrevious.path, wrongPrevious.deps)
    const wrongPreviousClaim = await wrongPreviousLedger.claim({
      path: '/v1/images/generations',
      requestSha256: 'a'.repeat(64),
      recoveryDomainSha256: RECOVERY_DOMAIN_SHA256
    })
    await wrongPreviousLedger.markDispatching(wrongPreviousClaim.operation.operationId)
    const wrongIntent = readSealedDocument(`${wrongPrevious.path}.pair-intent`)
    wrongIntent.document.beforeLedgerSha256 = 'b'.repeat(64)
    writeSealedDocument(
      `${wrongPrevious.path}.pair-intent`,
      wrongIntent.envelope,
      wrongIntent.document
    )
    await expect(
      new PaidMediaLedger(wrongPrevious.path, wrongPrevious.deps).listPublic()
    ).rejects.toThrow(/pair intent receipt/i)

    const left = testLedger()
    const right = testLedger()
    await new PaidMediaLedger(left.path, left.deps).claim({
      path: '/v1/images/generations',
      requestSha256: 'c'.repeat(64),
      recoveryDomainSha256: RECOVERY_DOMAIN_SHA256
    })
    await new PaidMediaLedger(right.path, right.deps).claim({
      path: '/v1/images/generations',
      requestSha256: 'd'.repeat(64),
      recoveryDomainSha256: RECOVERY_DOMAIN_SHA256
    })
    writeFileSync(`${left.path}.anchor`, readFileSync(`${right.path}.anchor`, 'utf8'), 'utf8')
    await expect(new PaidMediaLedger(left.path, left.deps).listPublic()).rejects.toThrow(
      /expected-before|exact target/i
    )
  })

  it('reads an exact legacy v3 anchor/body pair without inventing a pair intent', async () => {
    const item = testLedger()
    const ledger = new PaidMediaLedger(item.path, item.deps)
    const claimed = await ledger.claim({
      path: '/v1/images/generations',
      requestSha256: 'e'.repeat(64),
      recoveryDomainSha256: RECOVERY_DOMAIN_SHA256
    })
    const sealed = readSealedDocument(item.path)
    sealed.document.schema = 'nachuan.paid-media-main-ledger.v3'
    const records = sealed.document.records as Array<Record<string, unknown>>
    for (const record of records) {
      delete record.v2DispatchReceiptSha256
      delete record.v2AckIntentReceiptSha256
    }
    writeSealedDocument(item.path, sealed.envelope, sealed.document)
    rmSync(`${item.path}.pair-intent`)

    await expect(new PaidMediaLedger(item.path, item.deps).listPublic()).resolves.toEqual([
      claimed.operation
    ])
    expect(existsSync(`${item.path}.pair-intent`)).toBe(false)
  })

  it('never silently migrates a v1 ledger before an explicit sealed recovery', async () => {
    const item = testLedger()
    const uuid = '24242424-2424-4242-8242-242424242424'
    const document = JSON.stringify({
      schema: 'nachuan.paid-media-main-ledger.v1',
      sequence: 7,
      records: [
        {
          operationId: `desktop-op-${uuid}`,
          idempotencyKey: `desktop-${uuid}`,
          path: '/v1/images/generations',
          requestSha256: '7'.repeat(64),
          state: 'recoverable',
          createdAt: item.deps.now() - 2,
          updatedAt: item.deps.now() - 1,
          dispatchCount: 1,
          lastStatus: 503,
          retryAfterSeconds: null,
          resultSha256: null,
          deliveredAt: null,
          reconciliation: null
        }
      ]
    })
    writeFileSync(
      item.path,
      JSON.stringify({
        schema: 'nachuan.paid-media-main-ledger.envelope.v1',
        protection: 'electron-safe-storage',
        ciphertext: fakeStorage.encryptString(document).toString('base64')
      }),
      'utf8'
    )

    const ledger = new PaidMediaLedger(item.path, item.deps)
    const original = readFileSync(item.path, 'utf8')
    await expect(ledger.listPublic()).rejects.toThrow(/explicit sealed migration/i)
    expect(readFileSync(item.path, 'utf8')).toBe(original)
    expect(existsSync(`${item.path}.anchor`)).toBe(false)
  })

  it('never silently migrates a v2 digest-only result', async () => {
    const item = testLedger()
    const ledgerIdentity = '8'.repeat(64)
    const uuid = '25252525-2525-4252-8252-252525252525'
    const document = JSON.stringify({
      schema: 'nachuan.paid-media-main-ledger.v2',
      ledgerIdentity,
      sequence: 9,
      records: [
        {
          operationId: `desktop-op-${uuid}`,
          idempotencyKey: `desktop-${uuid}`,
          path: '/v1/videos/generations',
          requestSha256: '9'.repeat(64),
          recoveryDomainSha256: RECOVERY_DOMAIN_SHA256,
          state: 'result_ready',
          createdAt: item.deps.now() - 2,
          updatedAt: item.deps.now() - 1,
          dispatchCount: 1,
          lastStatus: null,
          retryAfterSeconds: null,
          resultSha256: 'a'.repeat(64),
          deliveredAt: null,
          reconciliation: null
        }
      ]
    })
    writeFileSync(
      item.path,
      JSON.stringify({
        schema: 'nachuan.paid-media-main-ledger.envelope.v1',
        protection: 'electron-safe-storage',
        ciphertext: fakeStorage.encryptString(document).toString('base64')
      }),
      'utf8'
    )
    writeFileSync(
      `${item.path}.anchor`,
      JSON.stringify({
        schema: 'nachuan.paid-media-main-ledger.anchor.envelope.v1',
        protection: 'electron-safe-storage',
        ciphertext: fakeStorage
          .encryptString(
            JSON.stringify({
              schema: 'nachuan.paid-media-main-ledger.anchor.v1',
              ledgerIdentity,
              sequenceFloor: 9
            })
          )
          .toString('base64')
      }),
      'utf8'
    )

    const ledger = new PaidMediaLedger(item.path, item.deps)
    const originalLedger = readFileSync(item.path, 'utf8')
    const originalAnchor = readFileSync(`${item.path}.anchor`, 'utf8')
    await expect(ledger.listPublic()).rejects.toThrow(/explicit sealed migration/i)
    expect(readFileSync(item.path, 'utf8')).toBe(originalLedger)
    expect(readFileSync(`${item.path}.anchor`, 'utf8')).toBe(originalAnchor)
  })

  it('stops automatic exact retry before the 30-day server receipt boundary', async () => {
    const retryWindowMs = 27 * 24 * 60 * 60 * 1000
    let now = 1_750_000_000_000
    const item = testLedger()
    item.deps.now = () => now
    const ledger = new PaidMediaLedger(item.path, item.deps)
    const first = await ledger.claim({
      path: '/v1/images/generations',
      requestSha256: '8'.repeat(64),
      recoveryDomainSha256: RECOVERY_DOMAIN_SHA256
    })

    now += retryWindowMs
    await expect(
      ledger.claim({
        path: '/v1/images/generations',
        requestSha256: '8'.repeat(64),
        recoveryDomainSha256: RECOVERY_DOMAIN_SHA256,
        retryOperationId: first.operation.operationId
      })
    ).rejects.toThrow('too old')
    expect(await ledger.listPublic()).toEqual([first.operation])
  })

  it('re-enters dispatching after a dispatch crash but replays a result-ready body locally', async () => {
    let now = 1_750_000_000_000
    const item = testLedger()
    item.deps.now = () => now
    const original = new PaidMediaLedger(item.path, item.deps)
    const requestSha256 = '9'.repeat(64)
    const first = await original.claim({
      path: '/v1/videos/generations',
      requestSha256,
      recoveryDomainSha256: RECOVERY_DOMAIN_SHA256
    })
    now += 1
    await original.markDispatching(first.operation.operationId)

    const afterDispatchCrash = new PaidMediaLedger(item.path, item.deps)
    const dispatchRetry = await afterDispatchCrash.claim({
      path: '/v1/videos/generations',
      requestSha256,
      recoveryDomainSha256: RECOVERY_DOMAIN_SHA256,
      retryOperationId: first.operation.operationId
    })
    expect(dispatchRetry.dispatch).toEqual(first.dispatch)
    now += 1
    expect(await afterDispatchCrash.markDispatching(first.operation.operationId)).toMatchObject({
      state: 'dispatching',
      dispatchCount: 2
    })
    now += 1
    const responseJson = JSON.stringify({ id: 'video-task-durable', status: 'queued' })
    await afterDispatchCrash.markResultReady({
      operationId: first.operation.operationId,
      status: 202,
      responseJson
    } as never)

    const afterResultCrash = new PaidMediaLedger(item.path, item.deps)
    const resultRetry = await afterResultCrash.claim({
      path: '/v1/videos/generations',
      requestSha256,
      recoveryDomainSha256: RECOVERY_DOMAIN_SHA256,
      retryOperationId: first.operation.operationId
    })
    expect(resultRetry.dispatch).toEqual(first.dispatch)
    expect(resultRetry).toMatchObject({
      replay: { status: 202, responseJson },
      operation: { state: 'result_ready', dispatchCount: 2 }
    })
    expect(JSON.stringify(resultRetry.operation)).not.toMatch(
      /resultSha256|resultJsonBase64|responseJson|video-task-durable/i
    )
    await expect(
      afterResultCrash.markDispatching(first.operation.operationId)
    ).rejects.toThrow(/result.ready|cannot enter dispatching/i)
    expect(await new PaidMediaLedger(item.path, item.deps).listPublic()).toEqual([
      resultRetry.operation
    ])
  })

  it('clears the large response body after delivery while retaining its encrypted digest tombstone', async () => {
    const item = testLedger()
    const ledger = new PaidMediaLedger(item.path, item.deps)
    const claimed = await ledger.claim({
      path: '/v1/images/generations',
      requestSha256: 'a'.repeat(64),
      recoveryDomainSha256: RECOVERY_DOMAIN_SHA256
    })
    await ledger.markDispatching(claimed.operation.operationId)
    const responseJson = JSON.stringify({ created: 1, data: [{ url: 'https://invalid/result.png' }] })
    await ledger.markResultReady({
      operationId: claimed.operation.operationId,
      status: 200,
      responseJson
    } as never)
    const readyEnvelope = JSON.parse(readFileSync(item.path, 'utf8')) as { ciphertext: string }
    const readyDocument = JSON.parse(
      fakeStorage.decryptString(Buffer.from(readyEnvelope.ciphertext, 'base64'))
    ) as { records: Array<Record<string, unknown>> }
    expect(readyDocument.records[0]).toMatchObject({
      resultSha256: expect.stringMatching(/^[0-9a-f]{64}$/),
      resultStatus: 200,
      resultJsonBase64: Buffer.from(responseJson, 'utf8').toString('base64')
    })

    const delivered = await ledger.markDelivered(
      deliveryProof(claimed.operation.operationId, responseJson)
    )
    expect(delivered).not.toHaveProperty('resultSha256')
    expect(delivered).not.toHaveProperty('resultJsonBase64')
    const deliveredEnvelope = JSON.parse(readFileSync(item.path, 'utf8')) as { ciphertext: string }
    const deliveredDocument = JSON.parse(
      fakeStorage.decryptString(Buffer.from(deliveredEnvelope.ciphertext, 'base64'))
    ) as { records: Array<Record<string, unknown>> }
    expect(deliveredDocument.records[0]).toMatchObject({
      resultSha256: readyDocument.records[0].resultSha256,
      resultStatus: 200,
      resultJsonBase64: null
    })
  })

  it('clears the large response body on manual reconciliation while retaining its digest evidence', async () => {
    const item = testLedger()
    const ledger = new PaidMediaLedger(item.path, item.deps)
    const claimed = await ledger.claim({
      path: '/v1/videos/generations',
      requestSha256: 'c'.repeat(64),
      recoveryDomainSha256: RECOVERY_DOMAIN_SHA256
    })
    await ledger.markDispatching(claimed.operation.operationId)
    await ledger.markResultReady({
      operationId: claimed.operation.operationId,
      status: 202,
      responseJson: JSON.stringify({ id: 'manual-result', status: 'queued' })
    })

    const reconciled = await ledger.reconcile({
      operationId: claimed.operation.operationId,
      reason: 'provider-console-checked',
      evidence: 'provider-task=manual-result; invoice=checked'
    })
    expect(reconciled).not.toHaveProperty('resultSha256')
    expect(reconciled).not.toHaveProperty('resultJsonBase64')
    const envelope = JSON.parse(readFileSync(item.path, 'utf8')) as { ciphertext: string }
    const document = JSON.parse(
      fakeStorage.decryptString(Buffer.from(envelope.ciphertext, 'base64'))
    ) as { records: Array<Record<string, unknown>> }
    expect(document.records[0]).toMatchObject({
      state: 'reconciled',
      resultSha256: expect.stringMatching(/^[0-9a-f]{64}$/),
      resultStatus: 202,
      resultJsonBase64: null
    })
  })

  it('fails closed without rewriting when a stored response is corrupt or exceeds 24 MiB', async () => {
    const item = testLedger()
    const ledger = new PaidMediaLedger(item.path, item.deps)
    const claimed = await ledger.claim({
      path: '/v1/videos/generations',
      requestSha256: 'b'.repeat(64),
      recoveryDomainSha256: RECOVERY_DOMAIN_SHA256
    })
    await ledger.markDispatching(claimed.operation.operationId)
    const beforeOversize = readFileSync(item.path, 'utf8')
    await expect(
      ledger.markResultReady({
        operationId: claimed.operation.operationId,
        status: 200,
        responseJson: JSON.stringify({ data: 'x'.repeat(24 * 1024 * 1024) })
      } as never)
    ).rejects.toThrow(/24 MiB|size limit|too large/i)
    expect(readFileSync(item.path, 'utf8')).toBe(beforeOversize)

    const responseJson = JSON.stringify({ id: 'uncorrupted-result' })
    await ledger.markResultReady({
      operationId: claimed.operation.operationId,
      status: 200,
      responseJson
    } as never)
    const envelope = JSON.parse(readFileSync(item.path, 'utf8')) as Record<string, unknown>
    const document = JSON.parse(
      fakeStorage.decryptString(Buffer.from(String(envelope.ciphertext), 'base64'))
    ) as { records: Array<Record<string, unknown>> }
    document.records[0].resultJsonBase64 = Buffer.from(
      JSON.stringify({ id: 'tampered-result' }),
      'utf8'
    ).toString('base64')
    envelope.ciphertext = fakeStorage.encryptString(JSON.stringify(document)).toString('base64')
    const corrupt = JSON.stringify(envelope)
    rmSync(`${item.path}.pair-intent`)
    writeFileSync(item.path, corrupt, 'utf8')

    await expect(new PaidMediaLedger(item.path, item.deps).listPublic()).rejects.toThrow(
      /stored response digest|result.*digest|response.*corrupt/i
    )
    expect(readFileSync(item.path, 'utf8')).toBe(corrupt)
  })

  it('fails closed without rewriting corrupt, plaintext, or extra-field ledger documents', async () => {
    const item = testLedger()
    const ledger = new PaidMediaLedger(item.path, item.deps)
    await ledger.claim({
      path: '/v1/images/generations',
      requestSha256: 'b'.repeat(64),
      recoveryDomainSha256: RECOVERY_DOMAIN_SHA256
    })
    const validEnvelope = JSON.parse(readFileSync(item.path, 'utf8')) as Record<string, unknown>
    const plaintext = fakeStorage.decryptString(
      Buffer.from(String(validEnvelope.ciphertext), 'base64')
    )
    const document = JSON.parse(plaintext) as { records: Record<string, unknown>[] }
    document.records[0].attackerClear = true
    validEnvelope.ciphertext = fakeStorage
      .encryptString(JSON.stringify(document))
      .toString('base64')
    const withExtraField = JSON.stringify(validEnvelope)
    rmSync(`${item.path}.pair-intent`)
    writeFileSync(item.path, withExtraField, 'utf8')

    await expect(new PaidMediaLedger(item.path, item.deps).listPublic()).rejects.toThrow(
      'unknown fields'
    )
    expect(readFileSync(item.path, 'utf8')).toBe(withExtraField)

    const plaintextLegacy = JSON.stringify({ schema: 1, records: [] })
    writeFileSync(item.path, plaintextLegacy, 'utf8')
    await expect(new PaidMediaLedger(item.path, item.deps).listPublic()).rejects.toThrow(
      'envelope'
    )
    expect(readFileSync(item.path, 'utf8')).toBe(plaintextLegacy)

    writeFileSync(item.path, '{not-json', 'utf8')
    await expect(new PaidMediaLedger(item.path, item.deps).listPublic()).rejects.toThrow('corrupt')
    expect(readFileSync(item.path, 'utf8')).toBe('{not-json')
  })

  it('refuses an exhausted mutation sequence without changing the ledger bytes', async () => {
    const item = testLedger()
    const document = JSON.stringify({
      schema: 'nachuan.paid-media-main-ledger.v1',
      sequence: Number.MAX_SAFE_INTEGER,
      records: []
    })
    const envelope = JSON.stringify({
      schema: 'nachuan.paid-media-main-ledger.envelope.v1',
      protection: 'electron-safe-storage',
      ciphertext: fakeStorage.encryptString(document).toString('base64')
    })
    writeFileSync(item.path, envelope, 'utf8')

    await expect(
      new PaidMediaLedger(item.path, item.deps).claim({
        path: '/v1/images/generations',
        requestSha256: 'c'.repeat(64),
        recoveryDomainSha256: RECOVERY_DOMAIN_SHA256
      })
    ).rejects.toThrow(/explicit sealed migration/i)
    expect(readFileSync(item.path, 'utf8')).toBe(envelope)
  })

  it('fails closed at the bounded recent-tombstone capacity without rewriting the ledger', async () => {
    const item = testLedger()
    const now = item.deps.now()
    const records = Array.from({ length: 2048 }, (_, index) => {
      const uuid = `00000000-0000-4000-8000-${index.toString(16).padStart(12, '0')}`
      return {
        operationId: `desktop-op-${uuid}`,
        idempotencyKey: `desktop-${uuid}`,
        path: '/v1/images/generations',
        requestSha256: 'd'.repeat(64),
        recoveryDomainSha256: RECOVERY_DOMAIN_SHA256,
        state: 'delivered',
        createdAt: now - 1,
        updatedAt: now,
        dispatchCount: 1,
        lastStatus: null,
        retryAfterSeconds: null,
        resultSha256: 'e'.repeat(64),
        resultStatus: null,
        resultJsonBase64: null,
        deliveredAt: now,
        reconciliation: null
      }
    })
    const ledgerIdentity = 'a'.repeat(64)
    const document = JSON.stringify({
      schema: 'nachuan.paid-media-main-ledger.v3',
      ledgerIdentity,
      sequence: 2048,
      records
    })
    const envelope = JSON.stringify({
      schema: 'nachuan.paid-media-main-ledger.envelope.v1',
      protection: 'electron-safe-storage',
      ciphertext: fakeStorage.encryptString(document).toString('base64')
    })
    writeFileSync(item.path, envelope, 'utf8')
    writeFileSync(
      `${item.path}.anchor`,
      JSON.stringify({
        schema: 'nachuan.paid-media-main-ledger.anchor.envelope.v1',
        protection: 'electron-safe-storage',
        ciphertext: fakeStorage
          .encryptString(
            JSON.stringify({
              schema: 'nachuan.paid-media-main-ledger.anchor.v1',
              ledgerIdentity,
              sequenceFloor: 2048
            })
          )
          .toString('base64')
      }),
      'utf8'
    )
    const ledger = new PaidMediaLedger(item.path, item.deps)
    await ledger.listPublic()
    const migratedLedger = readFileSync(item.path, 'utf8')
    const migratedAnchor = readFileSync(`${item.path}.anchor`, 'utf8')

    await expect(
      ledger.claim({
        path: '/v1/videos/generations',
        requestSha256: 'f'.repeat(64),
        recoveryDomainSha256: RECOVERY_DOMAIN_SHA256
      })
    ).rejects.toThrow('capacity')
    expect(readFileSync(item.path, 'utf8')).toBe(migratedLedger)
    expect(readFileSync(`${item.path}.anchor`, 'utf8')).toBe(migratedAnchor)
  })

  it('rejects an oversized atomic input before decrypting it', async () => {
    const item = testLedger()
    let decryptCalls = 0
    item.deps.safeStorage = {
      ...fakeStorage,
      decryptString: (value) => {
        decryptCalls += 1
        return fakeStorage.decryptString(value)
      }
    }
    item.deps.atomicIO = {
      readUtf8: (_path, maxBytes) => 'x'.repeat(maxBytes + 1),
      writeUtf8Atomic: () => {
        throw new Error('must not write')
      }
    }

    await expect(new PaidMediaLedger(item.path, item.deps).listPublic()).rejects.toThrow(
      'size limit'
    )
    expect(decryptCalls).toBe(0)
  })
})
