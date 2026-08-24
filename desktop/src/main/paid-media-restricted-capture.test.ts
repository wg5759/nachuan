import { describe, expect, it, vi } from 'vitest'

import {
  PaidMediaRestrictedCaptureCoordinator,
  type PaidMediaRestrictedCaptureEvidence
} from './paid-media-restricted-capture'

const DRAIN_EVIDENCE = Object.freeze({
  schema: 'nachuan.paid-media-service-quiescence.v1' as const,
  scope: 'desktop-main-paid-media-service' as const,
  drainGeneration: 7,
  acceptedSequence: 11,
  completedSequence: 11,
  activeWorkCount: 0 as const,
  operationMutexCount: 0 as const,
  activeRequestCount: 0 as const,
  executingOperationCount: 0 as const,
  pendingCancellationCount: 0 as const,
  legacyBootstrapIdle: true as const,
  evidenceSha256: 'a'.repeat(64)
})

const VAULT_INVENTORY = Object.freeze({
  vaultStateDigest: 'b'.repeat(64),
  entryCount: 1,
  entries: Object.freeze([
    Object.freeze({
      path: 'claims/private-operation-name.json',
      byteLength: 321,
      sha256: 'c'.repeat(64)
    })
  ]),
  quiescence: Object.freeze({
    activeStageLeases: 0 as const,
    stageOpenHandles: 0 as const,
    activeStageStream: null,
    cleanupRetries: 0 as const,
    cleanupFlights: 0 as const,
    terminalArchiveFlights: 0 as const,
    cleanupPendingEntries: 0 as const,
    stageRootEntries: 0 as const
  })
})

const CAPACITY_EVIDENCE = Object.freeze({
  activeSlot: 'a' as const,
  capacityIdentity: 'd'.repeat(64),
  capacitySequence: 5,
  capacityStateDigest: 'e'.repeat(64),
  documentSha256: 'f'.repeat(64),
  artifacts: Object.freeze([
    Object.freeze({
      role: 'desktop_capacity_anchor' as const,
      path: 'C:\\private\\capacity.anchor',
      byteLength: 123,
      sha256: '1'.repeat(64)
    }),
    Object.freeze({
      role: 'desktop_capacity_active_slot' as const,
      path: 'C:\\private\\capacity.slot-a',
      byteLength: 456,
      sha256: '2'.repeat(64)
    })
  ]),
  externalClosureRequired: Object.freeze({
    writerFence: true as const,
    pinnedFileHandles: true as const,
    stagingAclProof: true as const
  })
})

function expectDeepFrozen(value: unknown): void {
  if (!value || typeof value !== 'object') return
  expect(Object.isFrozen(value)).toBe(true)
  for (const nested of Object.values(value)) expectDeepFrozen(nested)
}

describe('PaidMediaRestrictedCaptureCoordinator', () => {
  it('captures two identical frozen passes in order and holds the drain until exact release', async () => {
    const callOrder: string[] = []
    const enterMaintenanceDrain = vi.fn(async () => {
      callOrder.push('service')
      return DRAIN_EVIDENCE
    })
    const inspectCaptureInventory = vi.fn(async () => {
      callOrder.push('vault')
      return VAULT_INVENTORY
    })
    const inspectCaptureEvidence = vi.fn(async () => {
      callOrder.push('capacity')
      return CAPACITY_EVIDENCE
    })
    const releaseMaintenanceDrain = vi.fn(() => true)
    const coordinator = new PaidMediaRestrictedCaptureCoordinator({
      service: {
        enterMaintenanceDrain,
        inspectMaintenanceDrain: vi.fn(),
        releaseMaintenanceDrain
      },
      vault: { inspectCaptureInventory },
      capacity: { inspectCaptureEvidence }
    })

    const evidence = await coordinator.enterRestrictedCapture()

    expect(callOrder).toEqual(['service', 'vault', 'capacity', 'service', 'vault', 'capacity'])
    expect(evidence).toMatchObject({
      schema: 'nachuan.paid-media-restricted-capture.v1',
      scope: 'desktop-main-same-process',
      capability: 'capture_only',
      captureGeneration: 1,
      captureReady: false,
      captureProofStatus: 'partial',
      restoreReady: false,
      backupSupported: false,
      reanchorSupported: false,
      maintenance: {
        drainGeneration: 7,
        acceptedSequence: 11,
        completedSequence: 11,
        evidenceSha256: 'a'.repeat(64)
      },
      vault: {
        vaultStateDigest: 'b'.repeat(64),
        entryCount: 1,
        inventorySha256: expect.stringMatching(/^[0-9a-f]{64}$/)
      },
      capacity: {
        capacityIdentity: 'd'.repeat(64),
        capacitySequence: 5,
        capacityStateDigest: 'e'.repeat(64),
        documentSha256: 'f'.repeat(64),
        artifactCount: 2,
        evidenceSha256: expect.stringMatching(/^[0-9a-f]{64}$/)
      },
      externalClosureRequired: {
        writerFence: true,
        pinnedFileHandles: true,
        stagingAclProof: true
      },
      captureEvidenceSha256: expect.stringMatching(/^[0-9a-f]{64}$/)
    } satisfies Partial<PaidMediaRestrictedCaptureEvidence>)
    expectDeepFrozen(evidence)
    const serializedEvidence = JSON.stringify(evidence)
    for (const sensitive of [
      'private-operation-name',
      'C:\\private',
      'capacity.anchor',
      'capacity.slot-a'
    ]) {
      expect(serializedEvidence).not.toContain(sensitive)
    }
    expect(coordinator.inspectRestrictedCapture()).toMatchObject({
      phase: 'held',
      captureGeneration: 1,
      captureEvidenceSha256: evidence.captureEvidenceSha256
    })
    expect(releaseMaintenanceDrain).not.toHaveBeenCalled()

    expect(coordinator.releaseRestrictedCapture(evidence)).toBe(true)
    expect(releaseMaintenanceDrain).toHaveBeenCalledOnce()
    expect(releaseMaintenanceDrain).toHaveBeenCalledWith(DRAIN_EVIDENCE)
    expect(coordinator.inspectRestrictedCapture()).toMatchObject({
      phase: 'idle',
      captureGeneration: 1,
      captureEvidenceSha256: null
    })
  })

  it('singleflights concurrent enter calls into one capture generation', async () => {
    let announceInventory!: () => void
    const inventoryStarted = new Promise<void>((resolve) => {
      announceInventory = resolve
    })
    let releaseInventory!: () => void
    const inventoryReleased = new Promise<void>((resolve) => {
      releaseInventory = resolve
    })
    let inventoryCalls = 0
    const enterMaintenanceDrain = vi.fn(async () => DRAIN_EVIDENCE)
    const inspectCaptureInventory = vi.fn(async () => {
      inventoryCalls += 1
      if (inventoryCalls === 1) {
        announceInventory()
        await inventoryReleased
      }
      return VAULT_INVENTORY
    })
    const releaseMaintenanceDrain = vi.fn(() => true)
    const coordinator = new PaidMediaRestrictedCaptureCoordinator({
      service: {
        enterMaintenanceDrain,
        inspectMaintenanceDrain: vi.fn(),
        releaseMaintenanceDrain
      },
      vault: { inspectCaptureInventory },
      capacity: { inspectCaptureEvidence: vi.fn(async () => CAPACITY_EVIDENCE) }
    })

    const first = coordinator.enterRestrictedCapture()
    const duplicate = coordinator.enterRestrictedCapture()

    expect(duplicate).toBe(first)
    await inventoryStarted
    expect(coordinator.inspectRestrictedCapture()).toMatchObject({
      phase: 'capturing',
      captureGeneration: 1,
      captureEvidenceSha256: null
    })
    expect(enterMaintenanceDrain).toHaveBeenCalledOnce()
    releaseInventory()
    const [firstEvidence, duplicateEvidence] = await Promise.all([first, duplicate])

    expect(duplicateEvidence).toBe(firstEvidence)
    expect(enterMaintenanceDrain).toHaveBeenCalledTimes(2)
    expect(inspectCaptureInventory).toHaveBeenCalledTimes(2)
    expect(coordinator.releaseRestrictedCapture(firstEvidence)).toBe(true)
  })

  it('releases the drain when cancellation arrives during an inspection', async () => {
    let announceCapacity!: () => void
    const capacityStarted = new Promise<void>((resolve) => {
      announceCapacity = resolve
    })
    let releaseCapacity!: () => void
    const capacityReleased = new Promise<void>((resolve) => {
      releaseCapacity = resolve
    })
    const inspectCaptureEvidence = vi.fn(async () => {
      announceCapacity()
      await capacityReleased
      return CAPACITY_EVIDENCE
    })
    const releaseMaintenanceDrain = vi.fn(() => true)
    const coordinator = new PaidMediaRestrictedCaptureCoordinator({
      service: {
        enterMaintenanceDrain: vi.fn(async () => DRAIN_EVIDENCE),
        inspectMaintenanceDrain: vi.fn(),
        releaseMaintenanceDrain
      },
      vault: { inspectCaptureInventory: vi.fn(async () => VAULT_INVENTORY) },
      capacity: { inspectCaptureEvidence }
    })
    const controller = new AbortController()

    const capturing = coordinator.enterRestrictedCapture({ signal: controller.signal })
    await capacityStarted
    controller.abort()
    releaseCapacity()

    await expect(capturing).rejects.toThrow(/restricted capture.*cancelled/i)
    expect(inspectCaptureEvidence).toHaveBeenCalledOnce()
    expect(releaseMaintenanceDrain).toHaveBeenCalledOnce()
    expect(releaseMaintenanceDrain).toHaveBeenCalledWith(DRAIN_EVIDENCE)
    expect(coordinator.inspectRestrictedCapture()).toMatchObject({
      phase: 'idle',
      captureGeneration: 1,
      captureEvidenceSha256: null
    })
  })

  it('rejects evidence drift between passes and releases the drain', async () => {
    const changedInventory = Object.freeze({
      ...VAULT_INVENTORY,
      vaultStateDigest: '9'.repeat(64)
    })
    const inspectCaptureInventory = vi
      .fn()
      .mockResolvedValueOnce(VAULT_INVENTORY)
      .mockResolvedValueOnce(changedInventory)
    const releaseMaintenanceDrain = vi.fn(() => true)
    const coordinator = new PaidMediaRestrictedCaptureCoordinator({
      service: {
        enterMaintenanceDrain: vi.fn(async () => DRAIN_EVIDENCE),
        inspectMaintenanceDrain: vi.fn(),
        releaseMaintenanceDrain
      },
      vault: { inspectCaptureInventory },
      capacity: { inspectCaptureEvidence: vi.fn(async () => CAPACITY_EVIDENCE) }
    })

    await expect(coordinator.enterRestrictedCapture()).rejects.toThrow(
      'Restricted capture inspection failed safely'
    )

    expect(inspectCaptureInventory).toHaveBeenCalledTimes(2)
    expect(releaseMaintenanceDrain).toHaveBeenCalledOnce()
    expect(releaseMaintenanceDrain).toHaveBeenCalledWith(DRAIN_EVIDENCE)
    expect(coordinator.inspectRestrictedCapture()).toMatchObject({
      phase: 'idle',
      captureGeneration: 1,
      captureEvidenceSha256: null
    })
  })

  it('redacts inspection failures and releases the drain', async () => {
    const secret = 'sk-private-capacity-inspection-detail'
    const releaseMaintenanceDrain = vi.fn(() => true)
    const coordinator = new PaidMediaRestrictedCaptureCoordinator({
      service: {
        enterMaintenanceDrain: vi.fn(async () => DRAIN_EVIDENCE),
        inspectMaintenanceDrain: vi.fn(),
        releaseMaintenanceDrain
      },
      vault: { inspectCaptureInventory: vi.fn(async () => VAULT_INVENTORY) },
      capacity: {
        inspectCaptureEvidence: vi.fn(async () => {
          throw new Error(secret)
        })
      }
    })

    let captured: unknown
    try {
      await coordinator.enterRestrictedCapture()
    } catch (error) {
      captured = error
    }

    expect(captured).toBeInstanceOf(Error)
    expect((captured as Error).message).toBe('Restricted capture inspection failed safely')
    expect((captured as Error).message).not.toContain(secret)
    expect((captured as Error & { cause?: unknown }).cause).toBeUndefined()
    expect(releaseMaintenanceDrain).toHaveBeenCalledOnce()
    expect(coordinator.inspectRestrictedCapture()).toMatchObject({ phase: 'idle' })
  })

  it('rejects stale and forged release evidence across capture generations', async () => {
    const releaseMaintenanceDrain = vi.fn(() => true)
    const coordinator = new PaidMediaRestrictedCaptureCoordinator({
      service: {
        enterMaintenanceDrain: vi.fn(async () => DRAIN_EVIDENCE),
        inspectMaintenanceDrain: vi.fn(),
        releaseMaintenanceDrain
      },
      vault: { inspectCaptureInventory: vi.fn(async () => VAULT_INVENTORY) },
      capacity: { inspectCaptureEvidence: vi.fn(async () => CAPACITY_EVIDENCE) }
    })
    const first = await coordinator.enterRestrictedCapture()
    expect(coordinator.releaseRestrictedCapture(first)).toBe(true)
    expect(coordinator.releaseRestrictedCapture(first)).toBe(true)
    const second = await coordinator.enterRestrictedCapture()

    expect(second.captureGeneration).toBe(2)
    expect(coordinator.releaseRestrictedCapture(first)).toBe(false)
    expect(
      coordinator.releaseRestrictedCapture({
        ...second,
        captureEvidenceSha256: '0'.repeat(64)
      })
    ).toBe(false)
    expect(coordinator.inspectRestrictedCapture()).toMatchObject({
      phase: 'held',
      captureGeneration: 2,
      captureEvidenceSha256: second.captureEvidenceSha256
    })
    expect(releaseMaintenanceDrain).toHaveBeenCalledOnce()

    expect(coordinator.releaseRestrictedCapture(second)).toBe(true)
    expect(releaseMaintenanceDrain).toHaveBeenCalledTimes(2)
  })

  it('keeps service reads available while writes stay fenced until release', async () => {
    let drained = false
    const service = {
      enterMaintenanceDrain: vi.fn(async () => {
        drained = true
        return DRAIN_EVIDENCE
      }),
      inspectMaintenanceDrain: vi.fn(),
      releaseMaintenanceDrain: vi.fn(() => {
        drained = false
        return true
      }),
      listUnresolved: vi.fn(async () => []),
      claim: vi.fn(async () => {
        if (drained) throw new Error('Paid media maintenance drain is active')
        return { state: 'claimed' }
      })
    }
    const coordinator = new PaidMediaRestrictedCaptureCoordinator({
      service,
      vault: { inspectCaptureInventory: vi.fn(async () => VAULT_INVENTORY) },
      capacity: { inspectCaptureEvidence: vi.fn(async () => CAPACITY_EVIDENCE) }
    })
    const evidence = await coordinator.enterRestrictedCapture()

    await expect(service.listUnresolved()).resolves.toEqual([])
    await expect(service.claim()).rejects.toThrow('Paid media maintenance drain is active')
    expect(coordinator.releaseRestrictedCapture(evidence)).toBe(true)
    await expect(service.claim()).resolves.toEqual({ state: 'claimed' })
  })

  it('rejects matching evidence that was not deeply frozen', async () => {
    const mutableInventory = {
      ...VAULT_INVENTORY,
      entries: [...VAULT_INVENTORY.entries]
    }
    const releaseMaintenanceDrain = vi.fn(() => true)
    const coordinator = new PaidMediaRestrictedCaptureCoordinator({
      service: {
        enterMaintenanceDrain: vi.fn(async () => DRAIN_EVIDENCE),
        inspectMaintenanceDrain: vi.fn(),
        releaseMaintenanceDrain
      },
      vault: { inspectCaptureInventory: vi.fn(async () => mutableInventory) },
      capacity: { inspectCaptureEvidence: vi.fn(async () => CAPACITY_EVIDENCE) }
    })

    await expect(coordinator.enterRestrictedCapture()).rejects.toThrow(
      'Restricted capture inspection failed safely'
    )
    expect(releaseMaintenanceDrain).toHaveBeenCalledOnce()
    expect(coordinator.inspectRestrictedCapture()).toMatchObject({ phase: 'idle' })
  })

  it('rejects unknown inventory fields instead of hashing private data into public evidence', async () => {
    const secret = 'private-prompt-must-not-enter-capture-evidence'
    const taintedInventory = Object.freeze({ ...VAULT_INVENTORY, privatePrompt: secret })
    const releaseMaintenanceDrain = vi.fn(() => true)
    const coordinator = new PaidMediaRestrictedCaptureCoordinator({
      service: {
        enterMaintenanceDrain: vi.fn(async () => DRAIN_EVIDENCE),
        inspectMaintenanceDrain: vi.fn(),
        releaseMaintenanceDrain
      },
      vault: {
        inspectCaptureInventory: vi.fn(async () => taintedInventory)
      },
      capacity: { inspectCaptureEvidence: vi.fn(async () => CAPACITY_EVIDENCE) }
    })

    let captured: unknown
    try {
      await coordinator.enterRestrictedCapture()
    } catch (error) {
      captured = error
    }

    expect(captured).toBeInstanceOf(Error)
    expect((captured as Error).message).toBe('Restricted capture inspection failed safely')
    expect((captured as Error).message).not.toContain(secret)
    expect(releaseMaintenanceDrain).toHaveBeenCalledOnce()
  })

  it('refuses to erase any required external closure gap', async () => {
    const weakenedCapacity = Object.freeze({
      ...CAPACITY_EVIDENCE,
      externalClosureRequired: Object.freeze({
        writerFence: false,
        pinnedFileHandles: true,
        stagingAclProof: true
      })
    })
    const releaseMaintenanceDrain = vi.fn(() => true)
    const coordinator = new PaidMediaRestrictedCaptureCoordinator({
      service: {
        enterMaintenanceDrain: vi.fn(async () => DRAIN_EVIDENCE),
        inspectMaintenanceDrain: vi.fn(),
        releaseMaintenanceDrain
      },
      vault: { inspectCaptureInventory: vi.fn(async () => VAULT_INVENTORY) },
      capacity: {
        inspectCaptureEvidence: vi.fn(async () => weakenedCapacity as never)
      }
    })

    await expect(coordinator.enterRestrictedCapture()).rejects.toThrow(
      'Restricted capture inspection failed safely'
    )
    expect(releaseMaintenanceDrain).toHaveBeenCalledOnce()
    expect(coordinator.inspectRestrictedCapture()).toMatchObject({ phase: 'idle' })
  })
})
