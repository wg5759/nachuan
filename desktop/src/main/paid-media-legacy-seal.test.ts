import {
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, describe, expect, it, vi } from 'vitest'

import {
  nodePaidMediaLegacySealAtomicIO,
  PaidMediaLegacyMigrationUnavailableError,
  PaidMediaLegacySeal
} from './paid-media-legacy-seal'

const roots: string[] = []
const fakeStorage = {
  isEncryptionAvailable: () => true,
  encryptString: (value: string) => Buffer.from(`protected:${value}`, 'utf8'),
  decryptString: (value: Buffer) => {
    const text = value.toString('utf8')
    if (!text.startsWith('protected:')) throw new Error('invalid ciphertext')
    return text.slice('protected:'.length)
  }
}
const CANDIDATE = {
  operationId: 'desktop-op-11111111-1111-4111-8111-111111111111',
  path: '/v1/images/generations' as const,
  requestSha256: 'a'.repeat(64),
  createdAt: 1_799_999_998_000,
  updatedAt: 1_799_999_999_000,
  state: 'pending' as const
}
const CANDIDATE_SHA256 = 'c0a79408b04eb5053ccc1126ed16e63487a9cb81a72def1c591cd594ac66135a'
const CANDIDATE_DECISION_SHA256 =
  '9c84027005dfda78dd4f42975d36149df2dd44736004244e243b523b5d020811'

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true })
})

function fixture(): {
  path: string
  harden: ReturnType<typeof vi.fn>
  seal: PaidMediaLegacySeal
} {
  const root = mkdtempSync(join(tmpdir(), 'nachuan-paid-legacy-seal-'))
  roots.push(root)
  const path = join(root, 'legacy-migration.seal')
  const harden = vi.fn()
  return {
    path,
    harden,
    seal: new PaidMediaLegacySeal(path, {
    safeStorage: fakeStorage,
    harden,
    now: () => 1_800_000_000_000,
    atomicIO: nodePaidMediaLegacySealAtomicIO
    })
  }
}

describe('main-process paid media legacy migration seal', () => {
  it('treats a missing seal as migration unavailable instead of completed or open', async () => {
    const { seal } = fixture()

    await expect(seal.inspect()).rejects.toBeInstanceOf(
      PaidMediaLegacyMigrationUnavailableError
    )
  })

  it('explicitly provisions an encrypted open seal for a trusted first install', async () => {
    const { path, harden, seal } = fixture()

    await expect(seal.provisionOpen()).resolves.toEqual({ state: 'open' })
    await expect(seal.inspect()).resolves.toEqual({ state: 'open' })

    const onDisk = readFileSync(path, 'utf8')
    expect(onDisk).not.toContain('"state":"open"')
    expect(onDisk).not.toContain('nachuan.paid-media-legacy-seal.v1')
    expect(harden).toHaveBeenCalled()
  })

  it('returns a version-bound digest for the exact legacy candidate summary', () => {
    const { seal } = fixture()

    expect(
      seal.summarizeCandidate(CANDIDATE)
    ).toEqual({
      ...CANDIDATE,
      candidateSha256: CANDIDATE_SHA256
    })
  })

  it('durably closes an open seal with the exact candidate digest binding', async () => {
    const { seal } = fixture()
    await seal.provisionOpen()

    const expected = {
      state: 'closed' as const,
      closedAt: 1_800_000_000_000,
      decision: {
        kind: 'candidate' as const,
        decisionSha256: CANDIDATE_DECISION_SHA256,
        candidate: { ...CANDIDATE, candidateSha256: CANDIDATE_SHA256 }
      }
    }

    await expect(seal.close({ kind: 'candidate', candidate: CANDIDATE })).resolves.toEqual(
      expected
    )
    await expect(seal.inspect()).resolves.toEqual(expected)
  })

  it('idempotently returns the original seal when the same candidate is retried', async () => {
    const { seal } = fixture()
    await seal.provisionOpen()
    const first = await seal.close({ kind: 'candidate', candidate: CANDIDATE })

    await expect(
      seal.close({ kind: 'candidate', candidate: { ...CANDIDATE } })
    ).resolves.toEqual(first)
  })

  it('closes with an explicit digest-bound empty decision when no candidate exists', async () => {
    const { seal } = fixture()
    await seal.provisionOpen()

    const expected = {
      state: 'closed' as const,
      closedAt: 1_800_000_000_000,
      decision: {
        kind: 'empty' as const,
        decisionSha256: '518bbd2dd8638424d717b041c68d2fa02d078ff3ee9e22bb3c75c16461ec4ba0'
      }
    }
    await expect(seal.close({ kind: 'empty' })).resolves.toEqual(expected)
    await expect(seal.inspect()).resolves.toEqual(expected)
  })

  it('rejects a different candidate after the one-shot seal is closed', async () => {
    const { seal } = fixture()
    await seal.provisionOpen()
    await seal.close({ kind: 'candidate', candidate: CANDIDATE })

    await expect(
      seal.close({
        kind: 'candidate',
        candidate: { ...CANDIDATE, requestSha256: 'b'.repeat(64) }
      })
    ).rejects.toThrow(/already closed/i)
  })

  it('keeps the one-shot decision closed across a Main-process restart', async () => {
    const { path, seal } = fixture()
    await seal.provisionOpen()
    const closed = await seal.close({ kind: 'candidate', candidate: CANDIDATE })
    const restarted = new PaidMediaLegacySeal(path, {
      safeStorage: fakeStorage,
      harden: vi.fn(),
      now: () => 1_900_000_000_000,
      atomicIO: nodePaidMediaLegacySealAtomicIO
    })

    await expect(restarted.inspect()).resolves.toEqual(closed)
    await expect(
      restarted.close({
        kind: 'candidate',
        candidate: { ...CANDIDATE, requestSha256: 'b'.repeat(64) }
      })
    ).rejects.toThrow(/already closed/i)
    await expect(restarted.inspect()).resolves.toEqual(closed)
  })

  it('allows only one of two concurrent different candidates to close the seal', async () => {
    const { seal } = fixture()
    await seal.provisionOpen()

    const outcomes = await Promise.allSettled([
      seal.close({ kind: 'candidate', candidate: CANDIDATE }),
      seal.close({
        kind: 'candidate',
        candidate: { ...CANDIDATE, requestSha256: 'b'.repeat(64) }
      })
    ])

    expect(outcomes.filter((outcome) => outcome.status === 'fulfilled')).toHaveLength(1)
    expect(outcomes.filter((outcome) => outcome.status === 'rejected')).toHaveLength(1)
  })

  it.each(['deleted', 'corrupt', 'reparse'] as const)(
    'fails closed as migration unavailable when the seal is %s',
    async (damage) => {
      const { path, seal } = fixture()
      await seal.provisionOpen()
      if (damage === 'deleted') unlinkSync(path)
      if (damage === 'corrupt') writeFileSync(path, '{not-json', 'utf8')
      if (damage === 'reparse') {
        const outside = `${path}.outside`
        writeFileSync(outside, 'redirected', 'utf8')
        unlinkSync(path)
        symlinkSync(outside, path, 'file')
      }

      await expect(seal.inspect()).rejects.toBeInstanceOf(
        PaidMediaLegacyMigrationUnavailableError
      )
    }
  )

  it('rejects unknown candidate fields and oversized seal files', async () => {
    const { path, seal } = fixture()
    expect(() =>
      seal.summarizeCandidate({ ...CANDIDATE, hidden: true } as typeof CANDIDATE)
    ).toThrow(/candidate is invalid/i)

    await seal.provisionOpen()
    writeFileSync(path, 'x'.repeat(64 * 1024 + 1), 'utf8')
    await expect(seal.inspect()).rejects.toBeInstanceOf(
      PaidMediaLegacyMigrationUnavailableError
    )
  })
})
