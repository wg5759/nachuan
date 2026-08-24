import { createHash } from 'node:crypto'
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'

import {
  nodePaidMediaAtomicIO,
  type PaidMediaAtomicIO,
  type PaidMediaSafeStorage
} from './paid-media-ledger'
import {
  PAID_MEDIA_CAPACITY_FREE_FLOOR_BYTES,
  PAID_MEDIA_IMAGE_CAPACITY_BYTES,
  PAID_MEDIA_VIDEO_CAPACITY_BYTES,
  PaidMediaCapacityManager
} from './paid-media-capacity'

const OPERATION_ID = 'desktop-op-11111111-1111-4111-8111-111111111111'
const SECOND_OPERATION_ID = 'desktop-op-22222222-2222-4222-8222-222222222222'
const TASK_ALIAS_SHA256 = 'c'.repeat(64)
const CAPACITY_RELEASE_AUTHORIZATION_SHA256 = 'e'.repeat(64)

function sha256Utf8(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex')
}

const fakeStorage: PaidMediaSafeStorage = {
  isEncryptionAvailable: () => true,
  encryptString: (value) => Buffer.from(`protected:${value}`, 'utf8'),
  decryptString: (value) => {
    const text = value.toString('utf8')
    if (!text.startsWith('protected:')) throw new Error('invalid ciphertext')
    return text.slice('protected:'.length)
  }
}

const roots: string[] = []

afterEach(() => {
  while (roots.length > 0) rmSync(roots.pop()!, { recursive: true, force: true })
})

describe('PaidMediaCapacityManager', () => {
  it('commits capacity identity/sequence evidence and rejects writes outside the Root gate', async () => {
    const root = mkdtempSync(join(tmpdir(), 'nachuan-paid-capacity-authority-'))
    roots.push(root)
    const manager = new PaidMediaCapacityManager(join(root, 'capacity.json'), root, {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_000,
      atomicIO: nodePaidMediaAtomicIO,
      tempRoot: () => root,
      probeSpoolRoot: () => root,
      resolveVolume: () => ({ volumeId: 'volume-one', root }),
      freeBytes: () =>
        PAID_MEDIA_VIDEO_CAPACITY_BYTES + PAID_MEDIA_CAPACITY_FREE_FLOOR_BYTES
    })
    const initial = await manager.provisionAuthorityJournal()
    let mutationContext = false
    manager.setMutationGuard(() => {
      if (!mutationContext) throw new Error('outside Root transaction')
    })

    await expect(manager.inspectAuthorityEvidence()).resolves.toEqual(initial)
    await expect(
      manager.ensureReservation({
        operationId: OPERATION_ID,
        path: '/v1/videos/generations',
        allowCreate: true
      })
    ).rejects.toThrow(/outside Root transaction/i)

    mutationContext = true
    await manager.ensureReservation({
      operationId: OPERATION_ID,
      path: '/v1/videos/generations',
      allowCreate: true
    })
    mutationContext = false
    const changed = await manager.inspectAuthorityEvidence()
    expect(changed.capacityIdentity).toBe(initial.capacityIdentity)
    expect(changed.capacitySequence).toBe(initial.capacitySequence + 1)
    expect(changed.capacityStateDigest).not.toBe(initial.capacityStateDigest)
  })

  it('returns the exact anchor-bound active-slot evidence without hardening or writing', async () => {
    const root = mkdtempSync(join(tmpdir(), 'nachuan-paid-capacity-capture-'))
    roots.push(root)
    const path = join(root, 'capacity.json')
    const harden = vi.fn()
    const writeUtf8Atomic = vi.fn(nodePaidMediaAtomicIO.writeUtf8Atomic)
    const manager = new PaidMediaCapacityManager(path, root, {
      safeStorage: fakeStorage,
      harden,
      now: () => 1_800_000_000_000,
      atomicIO: {
        readUtf8: nodePaidMediaAtomicIO.readUtf8,
        writeUtf8Atomic
      },
      tempRoot: () => root,
      probeSpoolRoot: () => root,
      resolveVolume: () => ({ volumeId: 'volume-one', root }),
      freeBytes: () =>
        PAID_MEDIA_VIDEO_CAPACITY_BYTES + PAID_MEDIA_CAPACITY_FREE_FLOOR_BYTES
    })
    const authority = await manager.provisionAuthorityJournal()
    harden.mockClear()
    writeUtf8Atomic.mockClear()
    const anchorPath = `${path}.anchor`
    const activeSlotPath = `${path}.slot-a`
    const anchorRaw = readFileSync(anchorPath, 'utf8')
    const activeSlotRaw = readFileSync(activeSlotPath, 'utf8')
    const documentSha256 = sha256Utf8(
      JSON.stringify({
        schema: 'nachuan.paid-media-capacity.journal.v2',
        journalIdentity: authority.capacityIdentity,
        sequence: 1,
        records: []
      })
    )

    const evidence = await manager.inspectCaptureEvidence()

    expect(evidence).toEqual({
      activeSlot: 'a',
      capacityIdentity: authority.capacityIdentity,
      capacitySequence: 1,
      capacityStateDigest: authority.capacityStateDigest,
      documentSha256,
      artifacts: [
        {
          role: 'desktop_capacity_anchor',
          path: anchorPath,
          byteLength: Buffer.byteLength(anchorRaw, 'utf8'),
          sha256: sha256Utf8(anchorRaw)
        },
        {
          role: 'desktop_capacity_active_slot',
          path: activeSlotPath,
          byteLength: Buffer.byteLength(activeSlotRaw, 'utf8'),
          sha256: sha256Utf8(activeSlotRaw)
        }
      ],
      externalClosureRequired: {
        writerFence: true,
        pinnedFileHandles: true,
        stagingAclProof: true
      }
    })
    expect(Object.isFrozen(evidence)).toBe(true)
    expect(Object.isFrozen(evidence.artifacts)).toBe(true)
    expect(evidence.artifacts.every(Object.isFrozen)).toBe(true)
    expect(Object.isFrozen(evidence.externalClosureRequired)).toBe(true)
    expect(harden).not.toHaveBeenCalled()
    expect(writeUtf8Atomic).not.toHaveBeenCalled()
  })

  it('rejects an uncommitted newer inactive slot instead of hiding a torn publication', async () => {
    const root = mkdtempSync(join(tmpdir(), 'nachuan-paid-capacity-capture-torn-'))
    roots.push(root)
    const path = join(root, 'capacity.json')
    const dependencyBase = {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_000,
      tempRoot: () => root,
      probeSpoolRoot: () => root,
      resolveVolume: () => ({ volumeId: 'volume-one', root }),
      freeBytes: () =>
        PAID_MEDIA_VIDEO_CAPACITY_BYTES + PAID_MEDIA_CAPACITY_FREE_FLOOR_BYTES
    }
    await new PaidMediaCapacityManager(path, root, {
      ...dependencyBase,
      atomicIO: nodePaidMediaAtomicIO
    }).provisionAuthorityJournal()
    const interrupted = new PaidMediaCapacityManager(path, root, {
      ...dependencyBase,
      atomicIO: {
        readUtf8: nodePaidMediaAtomicIO.readUtf8,
        writeUtf8Atomic: (target, value, harden) => {
          if (target === `${path}.anchor`) throw new Error('synthetic torn capture anchor')
          nodePaidMediaAtomicIO.writeUtf8Atomic(target, value, harden)
        }
      }
    })
    await expect(
      interrupted.ensureReservation({
        operationId: OPERATION_ID,
        path: '/v1/videos/generations',
        allowCreate: true
      })
    ).rejects.toThrow(/synthetic torn capture anchor/i)
    const inactiveSlotPath = `${path}.slot-b`
    const tornBytes = readFileSync(inactiveSlotPath)

    const restarted = new PaidMediaCapacityManager(path, root, {
      ...dependencyBase,
      atomicIO: nodePaidMediaAtomicIO
    })
    await expect(restarted.inspectCaptureEvidence()).rejects.toThrow(
      /capture.*inactive slot.*uncommitted|torn|ambiguous/i
    )
    expect(readFileSync(inactiveSlotPath)).toEqual(tornBytes)
  })

  it('rejects when the anchor bytes change before capture inspection closes', async () => {
    const root = mkdtempSync(join(tmpdir(), 'nachuan-paid-capacity-capture-race-'))
    roots.push(root)
    const path = join(root, 'capacity.json')
    const dependencyBase = {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_000,
      tempRoot: () => root,
      probeSpoolRoot: () => root,
      resolveVolume: () => ({ volumeId: 'volume-one', root }),
      freeBytes: () =>
        PAID_MEDIA_VIDEO_CAPACITY_BYTES + PAID_MEDIA_CAPACITY_FREE_FLOOR_BYTES
    }
    await new PaidMediaCapacityManager(path, root, {
      ...dependencyBase,
      atomicIO: nodePaidMediaAtomicIO
    }).provisionAuthorityJournal()
    const anchorPath = `${path}.anchor`
    let changed = false
    const racingIO: PaidMediaAtomicIO = {
      readUtf8: (target, maxBytes, harden) => {
        const value = nodePaidMediaAtomicIO.readUtf8(target, maxBytes, harden)
        if (!changed && target === `${path}.slot-b`) {
          changed = true
          writeFileSync(anchorPath, `${readFileSync(anchorPath, 'utf8')} `, 'utf8')
        }
        return value
      },
      writeUtf8Atomic: nodePaidMediaAtomicIO.writeUtf8Atomic
    }
    const manager = new PaidMediaCapacityManager(path, root, {
      ...dependencyBase,
      atomicIO: racingIO
    })

    await expect(manager.inspectCaptureEvidence()).rejects.toThrow(
      /capture.*changed during inspection|mutable/i
    )
    expect(changed).toBe(true)
    expect(readFileSync(anchorPath, 'utf8')).toMatch(/\s$/)
  })

  it('rejects an inactive slot that is not the exact previous sequence', async () => {
    const root = mkdtempSync(join(tmpdir(), 'nachuan-paid-capacity-capture-ambiguous-'))
    roots.push(root)
    const path = join(root, 'capacity.json')
    const manager = new PaidMediaCapacityManager(path, root, {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_000,
      atomicIO: nodePaidMediaAtomicIO,
      tempRoot: () => root,
      probeSpoolRoot: () => root,
      resolveVolume: () => ({ volumeId: 'volume-one', root }),
      freeBytes: () =>
        PAID_MEDIA_VIDEO_CAPACITY_BYTES * 2n + PAID_MEDIA_CAPACITY_FREE_FLOOR_BYTES
    })
    await manager.provisionAuthorityJournal()
    const firstSequenceBytes = readFileSync(`${path}.slot-a`)
    await manager.ensureReservation({
      operationId: OPERATION_ID,
      path: '/v1/videos/generations',
      allowCreate: true
    })
    await manager.ensureReservation({
      operationId: SECOND_OPERATION_ID,
      path: '/v1/videos/generations',
      allowCreate: true
    })
    writeFileSync(`${path}.slot-b`, firstSequenceBytes)

    await expect(manager.inspectCaptureEvidence()).rejects.toThrow(
      /capture inactive slot.*ambiguous|previous sequence/i
    )
    expect(readFileSync(`${path}.slot-b`)).toEqual(firstSequenceBytes)
  })

  it('fails capture when the anchor is missing without initializing a replacement', async () => {
    const root = mkdtempSync(join(tmpdir(), 'nachuan-paid-capacity-capture-anchor-missing-'))
    roots.push(root)
    const path = join(root, 'capacity.json')
    const manager = new PaidMediaCapacityManager(path, root, {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_000,
      atomicIO: nodePaidMediaAtomicIO,
      tempRoot: () => root,
      probeSpoolRoot: () => root,
      resolveVolume: () => ({ volumeId: 'volume-one', root }),
      freeBytes: () =>
        PAID_MEDIA_VIDEO_CAPACITY_BYTES + PAID_MEDIA_CAPACITY_FREE_FLOOR_BYTES
    })
    await manager.provisionAuthorityJournal()
    const slotBytes = readFileSync(`${path}.slot-a`)
    rmSync(`${path}.anchor`)

    await expect(manager.inspectCaptureEvidence()).rejects.toThrow(/capture anchor is missing/i)
    expect(existsSync(`${path}.anchor`)).toBe(false)
    expect(readFileSync(`${path}.slot-a`)).toEqual(slotBytes)
  })

  it('fails capture when the anchor-selected active slot is missing', async () => {
    const root = mkdtempSync(join(tmpdir(), 'nachuan-paid-capacity-capture-slot-missing-'))
    roots.push(root)
    const path = join(root, 'capacity.json')
    const manager = new PaidMediaCapacityManager(path, root, {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_000,
      atomicIO: nodePaidMediaAtomicIO,
      tempRoot: () => root,
      probeSpoolRoot: () => root,
      resolveVolume: () => ({ volumeId: 'volume-one', root }),
      freeBytes: () =>
        PAID_MEDIA_VIDEO_CAPACITY_BYTES + PAID_MEDIA_CAPACITY_FREE_FLOOR_BYTES
    })
    await manager.provisionAuthorityJournal()
    const anchorBytes = readFileSync(`${path}.anchor`)
    rmSync(`${path}.slot-a`)

    await expect(manager.inspectCaptureEvidence()).rejects.toThrow(
      /capture active slot is missing/i
    )
    expect(readFileSync(`${path}.anchor`)).toEqual(anchorBytes)
    expect(existsSync(`${path}.slot-a`)).toBe(false)
  })

  it('fails capture when the active slot no longer matches its anchor', async () => {
    const root = mkdtempSync(join(tmpdir(), 'nachuan-paid-capacity-capture-mismatch-'))
    roots.push(root)
    const path = join(root, 'capacity.json')
    const manager = new PaidMediaCapacityManager(path, root, {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_000,
      atomicIO: nodePaidMediaAtomicIO,
      tempRoot: () => root,
      probeSpoolRoot: () => root,
      resolveVolume: () => ({ volumeId: 'volume-one', root }),
      freeBytes: () =>
        PAID_MEDIA_VIDEO_CAPACITY_BYTES + PAID_MEDIA_CAPACITY_FREE_FLOOR_BYTES
    })
    await manager.provisionAuthorityJournal()
    const activeSlotPath = `${path}.slot-a`
    const envelope = JSON.parse(readFileSync(activeSlotPath, 'utf8')) as {
      ciphertext: string
    }
    const document = JSON.parse(
      fakeStorage.decryptString(Buffer.from(envelope.ciphertext, 'base64'))
    ) as { sequence: number }
    document.sequence += 1
    envelope.ciphertext = fakeStorage.encryptString(JSON.stringify(document)).toString('base64')
    writeFileSync(activeSlotPath, JSON.stringify(envelope), 'utf8')
    const mismatchedBytes = readFileSync(activeSlotPath)

    await expect(manager.inspectCaptureEvidence()).rejects.toThrow(
      /capture anchor does not match its active slot/i
    )
    expect(readFileSync(activeSlotPath)).toEqual(mismatchedBytes)
  })

  it('selects slot b only after the anchor commits slot b as active', async () => {
    const root = mkdtempSync(join(tmpdir(), 'nachuan-paid-capacity-capture-slot-b-'))
    roots.push(root)
    const path = join(root, 'capacity.json')
    const manager = new PaidMediaCapacityManager(path, root, {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_000,
      atomicIO: nodePaidMediaAtomicIO,
      tempRoot: () => root,
      probeSpoolRoot: () => root,
      resolveVolume: () => ({ volumeId: 'volume-one', root }),
      freeBytes: () =>
        PAID_MEDIA_VIDEO_CAPACITY_BYTES + PAID_MEDIA_CAPACITY_FREE_FLOOR_BYTES
    })
    await manager.provisionAuthorityJournal()
    await manager.ensureReservation({
      operationId: OPERATION_ID,
      path: '/v1/videos/generations',
      allowCreate: true
    })
    const authority = await manager.inspectAuthorityEvidence()

    await expect(manager.inspectCaptureEvidence()).resolves.toMatchObject({
      activeSlot: 'b',
      capacityIdentity: authority.capacityIdentity,
      capacitySequence: 2,
      capacityStateDigest: authority.capacityStateDigest,
      artifacts: [
        { role: 'desktop_capacity_anchor', path: `${path}.anchor` },
        { role: 'desktop_capacity_active_slot', path: `${path}.slot-b` }
      ]
    })
  })

  it('persists one authorization-bound release tombstone and replays it without another commit', async () => {
    const root = mkdtempSync(join(tmpdir(), 'nachuan-paid-capacity-release-'))
    roots.push(root)
    const path = join(root, 'capacity.json')
    const dependencies = {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_000,
      atomicIO: nodePaidMediaAtomicIO,
      tempRoot: () => root,
      probeSpoolRoot: () => root,
      resolveVolume: () => ({ volumeId: 'volume-one', root }),
      freeBytes: () =>
        PAID_MEDIA_VIDEO_CAPACITY_BYTES + PAID_MEDIA_CAPACITY_FREE_FLOOR_BYTES
    }
    const manager = new PaidMediaCapacityManager(path, root, dependencies)
    await manager.ensureReservation({
      operationId: OPERATION_ID,
      path: '/v1/videos/generations',
      allowCreate: true
    })
    const beforeRelease = await manager.inspectAuthorityEvidence()

    const released = await manager.ensureReleasedWithAuthorization({
      operationId: OPERATION_ID,
      authorizationReceiptSha256: CAPACITY_RELEASE_AUTHORIZATION_SHA256
    })
    expect(released).toEqual({
      operationId: OPERATION_ID,
      authorizationReceiptSha256: CAPACITY_RELEASE_AUTHORIZATION_SHA256,
      releasedAt: 1_800_000_000_000,
      releasedReservationSha256: expect.stringMatching(/^[0-9a-f]{64}$/)
    })
    await expect(manager.listReservations()).resolves.toEqual([])
    const committed = await manager.inspectAuthorityEvidence()
    expect(committed.capacityIdentity).toBe(beforeRelease.capacityIdentity)
    expect(committed.capacitySequence).toBe(beforeRelease.capacitySequence + 1)
    expect(committed.capacityStateDigest).not.toBe(beforeRelease.capacityStateDigest)

    await expect(
      manager.ensureReleasedWithAuthorization({
        operationId: OPERATION_ID,
        authorizationReceiptSha256: CAPACITY_RELEASE_AUTHORIZATION_SHA256
      })
    ).resolves.toEqual(released)
    await expect(manager.inspectAuthorityEvidence()).resolves.toEqual(committed)
  })

  it('requires a nonzero receipt and the Root mutation gate before tombstoning a missing reservation', async () => {
    const root = mkdtempSync(join(tmpdir(), 'nachuan-paid-capacity-release-gate-'))
    roots.push(root)
    const manager = new PaidMediaCapacityManager(join(root, 'capacity.json'), root, {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_000,
      atomicIO: nodePaidMediaAtomicIO,
      tempRoot: () => root,
      probeSpoolRoot: () => root,
      resolveVolume: () => ({ volumeId: 'volume-one', root }),
      freeBytes: () =>
        PAID_MEDIA_VIDEO_CAPACITY_BYTES + PAID_MEDIA_CAPACITY_FREE_FLOOR_BYTES
    })
    const initial = await manager.provisionAuthorityJournal()
    let mutationContext = false
    manager.setMutationGuard(() => {
      if (!mutationContext) throw new Error('outside Root transaction')
    })

    await expect(
      manager.ensureReleasedWithAuthorization({
        operationId: OPERATION_ID,
        authorizationReceiptSha256: '0'.repeat(64)
      })
    ).rejects.toThrow(/authorization.*invalid/i)
    await expect(
      manager.ensureReleasedWithAuthorization({
        operationId: OPERATION_ID,
        authorizationReceiptSha256: CAPACITY_RELEASE_AUTHORIZATION_SHA256
      })
    ).rejects.toThrow(/outside Root transaction/i)
    await expect(manager.inspectAuthorityEvidence()).resolves.toEqual(initial)

    mutationContext = true
    await expect(
      manager.ensureReleasedWithAuthorization({
        operationId: OPERATION_ID,
        authorizationReceiptSha256: CAPACITY_RELEASE_AUTHORIZATION_SHA256
      })
    ).resolves.toEqual({
      operationId: OPERATION_ID,
      authorizationReceiptSha256: CAPACITY_RELEASE_AUTHORIZATION_SHA256,
      releasedAt: 1_800_000_000_000,
      releasedReservationSha256: null
    })
    mutationContext = false
    const committed = await manager.inspectAuthorityEvidence()
    expect(committed.capacitySequence).toBe(initial.capacitySequence + 1)
    expect(committed.capacityStateDigest).not.toBe(initial.capacityStateDigest)
  })

  it('keeps the authorization binding immutable across restart', async () => {
    const root = mkdtempSync(join(tmpdir(), 'nachuan-paid-capacity-release-restart-'))
    roots.push(root)
    const path = join(root, 'capacity.json')
    const dependencies = {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_000,
      atomicIO: nodePaidMediaAtomicIO,
      tempRoot: () => root,
      probeSpoolRoot: () => root,
      resolveVolume: () => ({ volumeId: 'volume-one', root }),
      freeBytes: () =>
        PAID_MEDIA_VIDEO_CAPACITY_BYTES + PAID_MEDIA_CAPACITY_FREE_FLOOR_BYTES
    }
    const first = new PaidMediaCapacityManager(path, root, dependencies)
    const tombstone = await first.ensureReleasedWithAuthorization({
      operationId: OPERATION_ID,
      authorizationReceiptSha256: CAPACITY_RELEASE_AUTHORIZATION_SHA256
    })
    const committed = await first.inspectAuthorityEvidence()

    const restarted = new PaidMediaCapacityManager(path, root, dependencies)
    await expect(
      restarted.ensureReleasedWithAuthorization({
        operationId: OPERATION_ID,
        authorizationReceiptSha256: CAPACITY_RELEASE_AUTHORIZATION_SHA256
      })
    ).resolves.toEqual(tombstone)
    await expect(
      restarted.ensureReleasedWithAuthorization({
        operationId: OPERATION_ID,
        authorizationReceiptSha256: 'f'.repeat(64)
      })
    ).rejects.toThrow(/authorization conflicts/i)
    await expect(
      restarted.ensureReservation({
        operationId: OPERATION_ID,
        path: '/v1/videos/generations',
        allowCreate: true
      })
    ).rejects.toThrow(/reservation conflicts/i)
    await expect(restarted.inspectAuthorityEvidence()).resolves.toEqual(committed)
  })

  it('keeps the reservation authoritative when the release slot lands but its anchor does not', async () => {
    const root = mkdtempSync(join(tmpdir(), 'nachuan-paid-capacity-release-anchor-crash-'))
    roots.push(root)
    const path = join(root, 'capacity.json')
    const dependencyBase = {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_000,
      tempRoot: () => root,
      probeSpoolRoot: () => root,
      resolveVolume: () => ({ volumeId: 'volume-one', root }),
      freeBytes: () =>
        PAID_MEDIA_VIDEO_CAPACITY_BYTES + PAID_MEDIA_CAPACITY_FREE_FLOOR_BYTES
    }
    const first = new PaidMediaCapacityManager(path, root, {
      ...dependencyBase,
      atomicIO: nodePaidMediaAtomicIO
    })
    await first.ensureReservation({
      operationId: OPERATION_ID,
      path: '/v1/videos/generations',
      allowCreate: true
    })
    const reservedEvidence = await first.inspectAuthorityEvidence()
    const interruptedIO: PaidMediaAtomicIO = {
      readUtf8: nodePaidMediaAtomicIO.readUtf8,
      writeUtf8Atomic: (target, value, harden) => {
        if (target === `${path}.anchor`) throw new Error('synthetic release anchor crash')
        nodePaidMediaAtomicIO.writeUtf8Atomic(target, value, harden)
      }
    }
    const interrupted = new PaidMediaCapacityManager(path, root, {
      ...dependencyBase,
      atomicIO: interruptedIO
    })
    await expect(
      interrupted.ensureReleasedWithAuthorization({
        operationId: OPERATION_ID,
        authorizationReceiptSha256: CAPACITY_RELEASE_AUTHORIZATION_SHA256
      })
    ).rejects.toThrow(/synthetic release anchor crash/i)

    const restarted = new PaidMediaCapacityManager(path, root, {
      ...dependencyBase,
      atomicIO: nodePaidMediaAtomicIO
    })
    await expect(restarted.inspectAuthorityEvidence()).resolves.toEqual(reservedEvidence)
    await expect(restarted.listReservations()).resolves.toEqual([
      expect.objectContaining({ operationId: OPERATION_ID, phase: 'active' })
    ])
    await expect(
      restarted.ensureReleasedWithAuthorization({
        operationId: OPERATION_ID,
        authorizationReceiptSha256: CAPACITY_RELEASE_AUTHORIZATION_SHA256
      })
    ).resolves.toMatchObject({
      operationId: OPERATION_ID,
      authorizationReceiptSha256: CAPACITY_RELEASE_AUTHORIZATION_SHA256
    })
    await expect(restarted.listReservations()).resolves.toEqual([])
  })

  it('recovers an exact replay when the release commits but its success response is lost', async () => {
    const root = mkdtempSync(join(tmpdir(), 'nachuan-paid-capacity-release-response-crash-'))
    roots.push(root)
    const path = join(root, 'capacity.json')
    const dependencyBase = {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_000,
      tempRoot: () => root,
      probeSpoolRoot: () => root,
      resolveVolume: () => ({ volumeId: 'volume-one', root }),
      freeBytes: () =>
        PAID_MEDIA_VIDEO_CAPACITY_BYTES + PAID_MEDIA_CAPACITY_FREE_FLOOR_BYTES
    }
    const first = new PaidMediaCapacityManager(path, root, {
      ...dependencyBase,
      atomicIO: nodePaidMediaAtomicIO
    })
    await first.ensureReservation({
      operationId: OPERATION_ID,
      path: '/v1/videos/generations',
      allowCreate: true
    })
    let failCommittedSlotRead = false
    const interruptedIO: PaidMediaAtomicIO = {
      readUtf8: (target, maxBytes, harden) => {
        if (failCommittedSlotRead && /\.slot-[ab]$/.test(target)) {
          failCommittedSlotRead = false
          throw new Error('synthetic lost release response')
        }
        return nodePaidMediaAtomicIO.readUtf8(target, maxBytes, harden)
      },
      writeUtf8Atomic: (target, value, harden) => {
        nodePaidMediaAtomicIO.writeUtf8Atomic(target, value, harden)
        if (target === `${path}.anchor`) failCommittedSlotRead = true
      }
    }
    const interrupted = new PaidMediaCapacityManager(path, root, {
      ...dependencyBase,
      atomicIO: interruptedIO
    })
    await expect(
      interrupted.ensureReleasedWithAuthorization({
        operationId: OPERATION_ID,
        authorizationReceiptSha256: CAPACITY_RELEASE_AUTHORIZATION_SHA256
      })
    ).rejects.toThrow(/synthetic lost release response/i)

    const restarted = new PaidMediaCapacityManager(path, root, {
      ...dependencyBase,
      atomicIO: nodePaidMediaAtomicIO
    })
    const committed = await restarted.inspectAuthorityEvidence()
    await expect(restarted.listReservations()).resolves.toEqual([])
    await expect(
      restarted.ensureReleasedWithAuthorization({
        operationId: OPERATION_ID,
        authorizationReceiptSha256: CAPACITY_RELEASE_AUTHORIZATION_SHA256
      })
    ).resolves.toMatchObject({
      operationId: OPERATION_ID,
      authorizationReceiptSha256: CAPACITY_RELEASE_AUTHORIZATION_SHA256
    })
    await expect(restarted.inspectAuthorityEvidence()).resolves.toEqual(committed)
  })

  it('fails closed on the legacy receiptless release API without changing authority evidence', async () => {
    const root = mkdtempSync(join(tmpdir(), 'nachuan-paid-capacity-release-legacy-'))
    roots.push(root)
    const manager = new PaidMediaCapacityManager(join(root, 'capacity.json'), root, {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_000,
      atomicIO: nodePaidMediaAtomicIO,
      tempRoot: () => root,
      probeSpoolRoot: () => root,
      resolveVolume: () => ({ volumeId: 'volume-one', root }),
      freeBytes: () =>
        PAID_MEDIA_VIDEO_CAPACITY_BYTES + PAID_MEDIA_CAPACITY_FREE_FLOOR_BYTES
    })
    await manager.ensureReservation({
      operationId: OPERATION_ID,
      path: '/v1/videos/generations',
      allowCreate: true
    })
    const before = await manager.inspectAuthorityEvidence()

    await expect(manager.releaseReservation(OPERATION_ID)).rejects.toThrow(
      /requires a Vault authorization receipt/i
    )
    await expect(manager.listReservations()).resolves.toEqual([
      expect.objectContaining({ operationId: OPERATION_ID, phase: 'active' })
    ])
    await expect(manager.inspectAuthorityEvidence()).resolves.toEqual(before)
  })

  it('admits the exact video budget plus free floor and aggregates one shared volume', async () => {
    const root = mkdtempSync(join(tmpdir(), 'nachuan-paid-capacity-'))
    roots.push(root)
    const manager = new PaidMediaCapacityManager(join(root, 'capacity.json'), root, {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_000,
      atomicIO: nodePaidMediaAtomicIO,
      tempRoot: () => root,
      probeSpoolRoot: () => root,
      resolveVolume: () => ({ volumeId: 'volume-one', root }),
      freeBytes: () =>
        PAID_MEDIA_VIDEO_CAPACITY_BYTES + PAID_MEDIA_CAPACITY_FREE_FLOOR_BYTES
    })

    await expect(
      manager.ensureReservation({
        operationId: OPERATION_ID,
        path: '/v1/videos/generations',
        allowCreate: true
      })
    ).resolves.toMatchObject({
      operationId: OPERATION_ID,
      path: '/v1/videos/generations',
      phase: 'active',
      perVolume: [{ volumeId: 'volume-one', root, bytes: 2_147_483_648n }]
    })
  })

  it('keeps an exact active reservation across restart without recreating it', async () => {
    const root = mkdtempSync(join(tmpdir(), 'nachuan-paid-capacity-restart-'))
    roots.push(root)
    const dependencies = {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_000,
      atomicIO: nodePaidMediaAtomicIO,
      tempRoot: () => root,
      probeSpoolRoot: () => root,
      resolveVolume: () => ({ volumeId: 'volume-one', root }),
      freeBytes: () =>
        PAID_MEDIA_VIDEO_CAPACITY_BYTES + PAID_MEDIA_CAPACITY_FREE_FLOOR_BYTES
    }
    const path = join(root, 'capacity.json')
    const first = new PaidMediaCapacityManager(path, root, dependencies)
    await first.ensureReservation({
      operationId: OPERATION_ID,
      path: '/v1/videos/generations',
      allowCreate: true
    })

    const restarted = new PaidMediaCapacityManager(path, root, dependencies)
    await expect(
      restarted.ensureReservation({
        operationId: OPERATION_ID,
        path: '/v1/videos/generations',
        allowCreate: false
      })
    ).resolves.toMatchObject({
      operationId: OPERATION_ID,
      path: '/v1/videos/generations',
      phase: 'active',
      perVolume: [{ bytes: 2_147_483_648n }]
    })
  })

  it('keeps initialization uncommitted when the first inactive slot write crashes', async () => {
    const root = mkdtempSync(join(tmpdir(), 'nachuan-paid-capacity-crash-'))
    roots.push(root)
    const path = join(root, 'capacity.json')
    const interruptedIO: PaidMediaAtomicIO = {
      readUtf8: nodePaidMediaAtomicIO.readUtf8,
      writeUtf8Atomic: (target, value, harden) => {
        if (target === `${path}.slot-a`) throw new Error('synthetic crash before slot commit')
        nodePaidMediaAtomicIO.writeUtf8Atomic(target, value, harden)
      }
    }
    const dependencyBase = {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_000,
      tempRoot: () => root,
      probeSpoolRoot: () => root,
      resolveVolume: () => ({ volumeId: 'volume-one', root }),
      freeBytes: () =>
        PAID_MEDIA_VIDEO_CAPACITY_BYTES + PAID_MEDIA_CAPACITY_FREE_FLOOR_BYTES
    }
    const interrupted = new PaidMediaCapacityManager(path, root, {
      ...dependencyBase,
      atomicIO: interruptedIO
    })
    await expect(
      interrupted.ensureReservation({
        operationId: OPERATION_ID,
        path: '/v1/videos/generations',
        allowCreate: true
      })
    ).rejects.toThrow(/synthetic crash/i)

    expect(existsSync(`${path}.anchor`)).toBe(false)
    const restarted = new PaidMediaCapacityManager(path, root, {
      ...dependencyBase,
      atomicIO: nodePaidMediaAtomicIO
    })
    await expect(
      restarted.ensureReservation({
        operationId: OPERATION_ID,
        path: '/v1/videos/generations',
        allowCreate: true
      })
    ).resolves.toMatchObject({ operationId: OPERATION_ID, phase: 'active' })
  })

  it('preserves the previous committed journal if the next sequence anchor does not commit', async () => {
    const root = mkdtempSync(join(tmpdir(), 'nachuan-paid-capacity-anchor-crash-'))
    roots.push(root)
    const path = join(root, 'capacity.json')
    const dependencyBase = {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_000,
      tempRoot: () => root,
      probeSpoolRoot: () => root,
      resolveVolume: () => ({ volumeId: 'volume-one', root }),
      freeBytes: () =>
        PAID_MEDIA_VIDEO_CAPACITY_BYTES * 2n + PAID_MEDIA_CAPACITY_FREE_FLOOR_BYTES
    }
    const initial = new PaidMediaCapacityManager(path, root, {
      ...dependencyBase,
      atomicIO: nodePaidMediaAtomicIO
    })
    await initial.ensureReservation({
      operationId: OPERATION_ID,
      path: '/v1/videos/generations',
      allowCreate: true
    })

    const interruptedIO: PaidMediaAtomicIO = {
      readUtf8: nodePaidMediaAtomicIO.readUtf8,
      writeUtf8Atomic: (target, value, harden) => {
        if (target === `${path}.anchor`) throw new Error('synthetic crash before anchor commit')
        nodePaidMediaAtomicIO.writeUtf8Atomic(target, value, harden)
      }
    }
    const interrupted = new PaidMediaCapacityManager(path, root, {
      ...dependencyBase,
      atomicIO: interruptedIO
    })
    await expect(
      interrupted.ensureReservation({
        operationId: SECOND_OPERATION_ID,
        path: '/v1/videos/generations',
        allowCreate: true
      })
    ).rejects.toThrow(/synthetic crash/i)
    expect(existsSync(`${path}.slot-b`)).toBe(true)

    const restarted = new PaidMediaCapacityManager(path, root, {
      ...dependencyBase,
      atomicIO: nodePaidMediaAtomicIO
    })
    await expect(
      restarted.ensureReservation({
        operationId: OPERATION_ID,
        path: '/v1/videos/generations',
        allowCreate: false
      })
    ).resolves.toMatchObject({ operationId: OPERATION_ID, phase: 'active' })
    await expect(
      restarted.ensureReservation({
        operationId: SECOND_OPERATION_ID,
        path: '/v1/videos/generations',
        allowCreate: false
      })
    ).rejects.toThrow(/missing/i)
    await expect(
      restarted.ensureReservation({
        operationId: SECOND_OPERATION_ID,
        path: '/v1/videos/generations',
        allowCreate: true
      })
    ).resolves.toMatchObject({ operationId: SECOND_OPERATION_ID, phase: 'active' })
  })

  it('serializes two managers for one journal so a reentrant writer cannot oversell capacity', async () => {
    const root = mkdtempSync(join(tmpdir(), 'nachuan-paid-capacity-concurrent-'))
    roots.push(root)
    const path = join(root, 'capacity.json')
    let second!: PaidMediaCapacityManager
    let secondAttempt: Promise<unknown> | undefined
    let injectReentrantWriter = true
    const reentrantIO: PaidMediaAtomicIO = {
      readUtf8: nodePaidMediaAtomicIO.readUtf8,
      writeUtf8Atomic: (target, value, harden) => {
        if (target === `${path}.anchor` && injectReentrantWriter) {
          injectReentrantWriter = false
          secondAttempt = second.ensureReservation({
            operationId: SECOND_OPERATION_ID,
            path: '/v1/videos/generations',
            allowCreate: true
          })
        }
        nodePaidMediaAtomicIO.writeUtf8Atomic(target, value, harden)
      }
    }
    const dependencies = {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_000,
      atomicIO: reentrantIO,
      tempRoot: () => root,
      probeSpoolRoot: () => root,
      resolveVolume: () => ({ volumeId: 'volume-one', root }),
      freeBytes: () =>
        PAID_MEDIA_VIDEO_CAPACITY_BYTES + PAID_MEDIA_CAPACITY_FREE_FLOOR_BYTES
    }
    const first = new PaidMediaCapacityManager(path, root, dependencies)
    second = new PaidMediaCapacityManager(path, root, dependencies)

    await expect(
      first.ensureReservation({
        operationId: OPERATION_ID,
        path: '/v1/videos/generations',
        allowCreate: true
      })
    ).resolves.toMatchObject({ operationId: OPERATION_ID })
    expect(secondAttempt).toBeDefined()
    await expect(secondAttempt!).rejects.toThrow(/insufficient/i)

    const restarted = new PaidMediaCapacityManager(path, root, {
      ...dependencies,
      atomicIO: nodePaidMediaAtomicIO
    })
    await expect(
      restarted.ensureReservation({
        operationId: SECOND_OPERATION_ID,
        path: '/v1/videos/generations',
        allowCreate: false
      })
    ).rejects.toThrow(/missing/i)
  })

  it('reserves explicit vault, Desktop staging, and Gateway probe-spool volumes', async () => {
    const root = mkdtempSync(join(tmpdir(), 'nachuan-paid-capacity-three-volumes-'))
    roots.push(root)
    const vaultRoot = join(root, 'vault')
    const desktopTempRoot = join(root, 'desktop-temp')
    const probeSpoolRoot = join(root, 'probe-spool')
    const manager = new PaidMediaCapacityManager(join(root, 'capacity.json'), vaultRoot, {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_000,
      atomicIO: nodePaidMediaAtomicIO,
      tempRoot: () => desktopTempRoot,
      probeSpoolRoot: () => probeSpoolRoot,
      resolveVolume: (path) =>
        path === vaultRoot
          ? { volumeId: 'vault-volume', root: vaultRoot }
          : path === desktopTempRoot
            ? { volumeId: 'desktop-volume', root: desktopTempRoot }
            : { volumeId: 'probe-volume', root: probeSpoolRoot },
      freeBytes: () => 4n * PAID_MEDIA_VIDEO_CAPACITY_BYTES
    })

    await expect(
      manager.ensureReservation({
        operationId: OPERATION_ID,
        path: '/v1/videos/generations',
        allowCreate: true
      })
    ).resolves.toMatchObject({
      perVolume: [
        { volumeId: 'vault-volume', root: vaultRoot, bytes: 1_073_741_824n },
        { volumeId: 'desktop-volume', root: desktopTempRoot, bytes: 536_870_912n },
        { volumeId: 'probe-volume', root: probeSpoolRoot, bytes: 536_870_912n }
      ],
      budgetPolicy: 'nachuan.paid-media-capacity-budget.v1',
      roleBudgets: [
        { role: 'vault', volumeId: 'vault-volume', bytes: 1_073_741_824n },
        { role: 'desktop_staging', volumeId: 'desktop-volume', bytes: 536_870_912n },
        { role: 'probe_spool', volumeId: 'probe-volume', bytes: 536_870_912n }
      ]
    })
  })

  it('fails closed when a persisted reservation no longer matches the current volume plan', async () => {
    const root = mkdtempSync(join(tmpdir(), 'nachuan-paid-capacity-plan-change-'))
    roots.push(root)
    const path = join(root, 'capacity.json')
    let probeSpoolRoot = root
    const dependencies = {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_000,
      atomicIO: nodePaidMediaAtomicIO,
      tempRoot: () => root,
      probeSpoolRoot: () => probeSpoolRoot,
      resolveVolume: (candidate: string) =>
        candidate === root
          ? { volumeId: 'volume-one', root }
          : { volumeId: 'volume-two', root: candidate },
      freeBytes: () => 4n * PAID_MEDIA_VIDEO_CAPACITY_BYTES
    }
    await new PaidMediaCapacityManager(path, root, dependencies).ensureReservation({
      operationId: OPERATION_ID,
      path: '/v1/videos/generations',
      allowCreate: true
    })
    probeSpoolRoot = join(root, 'moved-probe-spool')

    await expect(
      new PaidMediaCapacityManager(path, root, dependencies).ensureReservation({
        operationId: OPERATION_ID,
        path: '/v1/videos/generations',
        allowCreate: false
      })
    ).rejects.toThrow(/plan changed/i)
  })

  it('rejects a reservation when the exact per-volume boundary is short by one byte', async () => {
    const root = mkdtempSync(join(tmpdir(), 'nachuan-paid-capacity-one-byte-'))
    roots.push(root)
    const required =
      PAID_MEDIA_VIDEO_CAPACITY_BYTES + PAID_MEDIA_CAPACITY_FREE_FLOOR_BYTES
    const manager = new PaidMediaCapacityManager(join(root, 'capacity.json'), root, {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_000,
      atomicIO: nodePaidMediaAtomicIO,
      tempRoot: () => root,
      probeSpoolRoot: () => root,
      resolveVolume: () => ({ volumeId: 'volume-one', root }),
      freeBytes: () => required - 1n
    })

    await expect(
      manager.ensureReservation({
        operationId: OPERATION_ID,
        path: '/v1/videos/generations',
        allowCreate: true
      })
    ).rejects.toThrow(/insufficient/i)
  })

  it('rechecks current free space and all active holds before reusing a reservation', async () => {
    const root = mkdtempSync(join(tmpdir(), 'nachuan-paid-capacity-recheck-'))
    roots.push(root)
    const path = join(root, 'capacity.json')
    let free = PAID_MEDIA_VIDEO_CAPACITY_BYTES + PAID_MEDIA_CAPACITY_FREE_FLOOR_BYTES
    const dependencies = {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_000,
      atomicIO: nodePaidMediaAtomicIO,
      tempRoot: () => root,
      probeSpoolRoot: () => root,
      resolveVolume: () => ({ volumeId: 'volume-one', root }),
      freeBytes: () => free
    }
    await new PaidMediaCapacityManager(path, root, dependencies).ensureReservation({
      operationId: OPERATION_ID,
      path: '/v1/videos/generations',
      allowCreate: true
    })
    free -= 1n

    await expect(
      new PaidMediaCapacityManager(path, root, dependencies).ensureReservation({
        operationId: OPERATION_ID,
        path: '/v1/videos/generations',
        allowCreate: false
      })
    ).rejects.toThrow(/insufficient/i)
  })

  it('never falls back to an older slot when the anchor-bound active slot is corrupt', async () => {
    const root = mkdtempSync(join(tmpdir(), 'nachuan-paid-capacity-no-fallback-'))
    roots.push(root)
    const path = join(root, 'capacity.json')
    const dependencies = {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_000,
      atomicIO: nodePaidMediaAtomicIO,
      tempRoot: () => root,
      probeSpoolRoot: () => root,
      resolveVolume: () => ({ volumeId: 'volume-one', root }),
      freeBytes: () =>
        PAID_MEDIA_VIDEO_CAPACITY_BYTES * 2n + PAID_MEDIA_CAPACITY_FREE_FLOOR_BYTES
    }
    const manager = new PaidMediaCapacityManager(path, root, dependencies)
    await manager.ensureReservation({
      operationId: OPERATION_ID,
      path: '/v1/videos/generations',
      allowCreate: true
    })
    await manager.ensureReservation({
      operationId: SECOND_OPERATION_ID,
      path: '/v1/videos/generations',
      allowCreate: true
    })
    expect(existsSync(`${path}.slot-a`)).toBe(true)
    expect(existsSync(`${path}.slot-b`)).toBe(true)
    const envelope = JSON.parse(readFileSync(`${path}.slot-b`, 'utf8')) as {
      ciphertext: string
    }
    const plaintext = fakeStorage.decryptString(Buffer.from(envelope.ciphertext, 'base64'))
    const document = JSON.parse(plaintext) as { sequence: number }
    document.sequence -= 1
    envelope.ciphertext = fakeStorage.encryptString(JSON.stringify(document)).toString('base64')
    writeFileSync(`${path}.slot-b`, JSON.stringify(envelope), 'utf8')

    await expect(
      new PaidMediaCapacityManager(path, root, dependencies).ensureReservation({
        operationId: OPERATION_ID,
        path: '/v1/videos/generations',
        allowCreate: false
      })
    ).rejects.toThrow(/anchor|active slot/i)
  })

  it('keeps release tombstones without treating them as active capacity holds', async () => {
    const root = mkdtempSync(join(tmpdir(), 'nachuan-paid-capacity-compaction-'))
    roots.push(root)
    const memory = new Map<string, string>()
    const memoryIO: PaidMediaAtomicIO = {
      readUtf8: (target) => memory.get(target) ?? null,
      writeUtf8Atomic: (target, value) => {
        memory.set(target, value)
      }
    }
    const manager = new PaidMediaCapacityManager(join(root, 'capacity.json'), root, {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_000,
      atomicIO: memoryIO,
      tempRoot: () => root,
      probeSpoolRoot: () => root,
      resolveVolume: () => ({ volumeId: 'volume-one', root }),
      freeBytes: () =>
        PAID_MEDIA_IMAGE_CAPACITY_BYTES + PAID_MEDIA_CAPACITY_FREE_FLOOR_BYTES
    })

    for (let index = 0; index < 32; index += 1) {
      const operationId = `desktop-op-${index.toString(16).padStart(36, '0')}`
      await manager.ensureReservation({
        operationId,
        path: '/v1/images/generations',
        allowCreate: true
      })
      await manager.ensureReleasedWithAuthorization({
        operationId,
        authorizationReceiptSha256: (index + 1).toString(16).padStart(64, '0')
      })
    }
    await expect(manager.listReservations()).resolves.toEqual([])
  }, 30_000)

  it('durably binds one video task digest and reuses only that exact binding', async () => {
    const root = mkdtempSync(join(tmpdir(), 'nachuan-paid-capacity-video-bind-'))
    roots.push(root)
    const path = join(root, 'capacity.json')
    const dependencies = {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_000,
      atomicIO: nodePaidMediaAtomicIO,
      tempRoot: () => root,
      probeSpoolRoot: () => root,
      resolveVolume: () => ({ volumeId: 'volume-one', root }),
      freeBytes: () =>
        PAID_MEDIA_VIDEO_CAPACITY_BYTES + PAID_MEDIA_CAPACITY_FREE_FLOOR_BYTES
    }
    const manager = new PaidMediaCapacityManager(path, root, dependencies)
    await manager.ensureReservation({
      operationId: OPERATION_ID,
      path: '/v1/videos/generations',
      allowCreate: true
    })

    await expect(
      manager.bindVideoTask({ operationId: OPERATION_ID, taskAliasSha256: TASK_ALIAS_SHA256 })
    ).resolves.toMatchObject({
      operationId: OPERATION_ID,
      phase: 'video_bound',
      taskAliasSha256: TASK_ALIAS_SHA256
    })
    const restarted = new PaidMediaCapacityManager(path, root, dependencies)
    await expect(
      restarted.bindVideoTask({
        operationId: OPERATION_ID,
        taskAliasSha256: TASK_ALIAS_SHA256
      })
    ).resolves.toMatchObject({ phase: 'video_bound', taskAliasSha256: TASK_ALIAS_SHA256 })
    await expect(
      restarted.verifyVideoTaskBinding({
        operationId: OPERATION_ID,
        taskAliasSha256: TASK_ALIAS_SHA256
      })
    ).resolves.toMatchObject({ phase: 'video_bound', taskAliasSha256: TASK_ALIAS_SHA256 })
    await expect(restarted.listReservations()).resolves.toEqual([
      expect.objectContaining({
        operationId: OPERATION_ID,
        phase: 'video_bound',
        taskAliasSha256: TASK_ALIAS_SHA256
      })
    ])
    await expect(
      restarted.bindVideoTask({ operationId: OPERATION_ID, taskAliasSha256: 'd'.repeat(64) })
    ).rejects.toThrow(/conflict/i)
  })
})
