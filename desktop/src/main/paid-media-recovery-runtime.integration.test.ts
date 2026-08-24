import { createHash } from 'node:crypto'
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, describe, expect, it, vi } from 'vitest'

import type {
  InstallationRootDesktopAdvanceRequest,
  InstallationRootDesktopBindRequest,
  InstallationRootDesktopRecoveryAckRequest,
  InstallationRootDesktopVerifyRequest,
  InstallationRootMutationEnvelope,
  InstallationRootSnapshot,
  InstallationRootSnapshotEnvelope
} from './installation-root-client'
import {
  PAID_MEDIA_RECOVERABLE_HANDLER_VERSION,
  PaidMediaInstallationRootAuthority,
  nodePaidMediaInstallationRootAtomicIO,
  type PaidMediaAuthorityEvidence
} from './paid-media-installation-root'
import {
  PaidMediaLedger,
  nodePaidMediaAtomicIO,
  type PaidMediaSafeStorage
} from './paid-media-ledger'
import { PaidMediaVault, type PaidMediaVaultDependencies } from './paid-media-vault'
import {
  PAID_MEDIA_CAPACITY_BUDGET_POLICY,
  PaidMediaCapacityManager
} from './paid-media-capacity'
import { PaidMediaRecoveryIntentStore } from './paid-media-recovery-intent'
import { PaidMediaRecoveryExecutor } from './paid-media-recovery-executor'
import { PaidMediaRecoveryExecutorSlot } from './paid-media-recovery-wiring'
import { PaidMediaMutationGate } from './paid-media-mutation-gate'

const INSTALLATION_ID = '1'.repeat(64)
const DESKTOP_IDENTITY = '2'.repeat(64)
const GATEWAY_IDENTITY = '3'.repeat(64)
const PRINCIPAL_DIGEST = '4'.repeat(64)
const OWNER_DIGEST = '5'.repeat(64)
const ZERO_DIGEST = '0'.repeat(64)
const LEGACY_SEAL_DECISION_SHA256 = '6'.repeat(64)
const OPERATION_UUID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
const OPERATION_ID = `desktop-op-${OPERATION_UUID}`
const NOW = 1_784_200_000
const PATH = '/v1/images/generations' as const
const ENCODED_BODY = '{"model":"offline-test","prompt":"resume exact local dispatch"}'
const REQUEST_SHA256 = createHash('sha256').update(ENCODED_BODY, 'utf8').digest('hex')

const roots: string[] = []

const safeStorage: PaidMediaSafeStorage = {
  isEncryptionAvailable: () => true,
  encryptString: (value) => Buffer.from(value, 'utf8'),
  decryptString: (value) => value.toString('utf8')
}

class FakeInstallationRootClient {
  readonly calls: string[] = []
  private rootRevision = 10
  private snapshotValue: InstallationRootSnapshot

  constructor() {
    this.snapshotValue = this.makeSnapshot({
      status: 'provisioning',
      bound: false,
      sequenceFloor: 0,
      stateDigest: null
    })
  }

  private makeSnapshot(input: {
    status: InstallationRootSnapshot['status']
    bound: boolean
    sequenceFloor: number
    stateDigest: string | null
    recoveryFloor?: number | null
    recoveryStateDigest?: string | null
  }): InstallationRootSnapshot {
    this.rootRevision += 1
    return {
      installationId: INSTALLATION_ID,
      ownerSidDigest: OWNER_DIGEST,
      epoch: 9,
      rootRevision: this.rootRevision,
      status: input.status,
      lockKind: 'none',
      lockReasonDigest: null,
      reanchorPending: false,
      reanchorOperationDigest: null,
      reanchorSnapshotDigest: null,
      reanchorSourceEpoch: null,
      principalDigest: PRINCIPAL_DIGEST,
      components: {
        desktop: {
          identity: DESKTOP_IDENTITY,
          epoch: 9,
          bound: input.bound,
          sequenceFloor: input.sequenceFloor,
          stateDigest: input.stateDigest,
          recoveryFloor: input.recoveryFloor ?? null,
          recoveryStateDigest: input.recoveryStateDigest ?? null
        },
        gateway: {
          identity: GATEWAY_IDENTITY,
          epoch: 9,
          bound: true,
          sequenceFloor: 0,
          stateDigest: '7'.repeat(64),
          recoveryFloor: null,
          recoveryStateDigest: null
        }
      },
      updater: {
        releaseSequence: 0,
        keyringSequence: 0,
        artifactDigest: ZERO_DIGEST,
        stateDigest: ZERO_DIGEST
      }
    }
  }

  snapshot(): Promise<InstallationRootSnapshotEnvelope> {
    this.calls.push('snapshot')
    return Promise.resolve({
      schema: 'nachuan.installation-root.snapshot.v1',
      snapshot: this.snapshotValue
    })
  }

  bindDesktop(input: InstallationRootDesktopBindRequest): Promise<InstallationRootMutationEnvelope> {
    this.calls.push('bind')
    this.snapshotValue = this.makeSnapshot({
      status: 'active',
      bound: true,
      sequenceFloor: input.sequenceFloor,
      stateDigest: input.stateDigest
    })
    return Promise.resolve(this.mutation())
  }

  verifyDesktop(
    input: InstallationRootDesktopVerifyRequest
  ): Promise<InstallationRootMutationEnvelope> {
    this.calls.push('verify')
    const current = this.snapshotValue.components.desktop
    if (
      input.sequenceFloor !== current.sequenceFloor + 1 ||
      input.previousStateDigest !== current.stateDigest
    ) {
      return Promise.reject(new Error('verify conflict'))
    }
    this.snapshotValue = this.makeSnapshot({
      status: 'active',
      bound: true,
      sequenceFloor: input.sequenceFloor,
      stateDigest: input.stateDigest,
      recoveryFloor: input.sequenceFloor,
      recoveryStateDigest: input.stateDigest
    })
    return Promise.resolve(this.mutation(true))
  }

  advanceDesktop(
    input: InstallationRootDesktopAdvanceRequest
  ): Promise<InstallationRootMutationEnvelope> {
    this.calls.push('advance')
    const current = this.snapshotValue.components.desktop
    if (
      current.sequenceFloor !== input.expectedFloor ||
      current.stateDigest !== input.expectedStateDigest
    ) {
      return Promise.reject(new Error('advance conflict'))
    }
    this.snapshotValue = this.makeSnapshot({
      status: 'active',
      bound: true,
      sequenceFloor: input.nextFloor,
      stateDigest: input.nextStateDigest
    })
    return Promise.resolve(this.mutation())
  }

  acknowledgeDesktopRecovery(
    input: InstallationRootDesktopRecoveryAckRequest
  ): Promise<InstallationRootMutationEnvelope> {
    this.calls.push('ack')
    const current = this.snapshotValue.components.desktop
    if (
      current.recoveryFloor !== input.recoveryFloor ||
      current.recoveryStateDigest !== input.recoveryStateDigest
    ) {
      return Promise.reject(new Error('ack conflict'))
    }
    this.snapshotValue = this.makeSnapshot({
      status: 'active',
      bound: true,
      sequenceFloor: input.nextFloor,
      stateDigest: input.nextStateDigest
    })
    return Promise.resolve(this.mutation())
  }

  private mutation(recovered = false): InstallationRootMutationEnvelope {
    return {
      schema: 'nachuan.installation-root.mutation.v1',
      snapshot: this.snapshotValue,
      applied: true,
      recovered
    }
  }
}

interface ExternalFakes {
  transport: (...args: unknown[]) => void
  provider: (...args: unknown[]) => Promise<never>
  probe: (...args: unknown[]) => Promise<never>
}

interface LocalComponents {
  ledger: PaidMediaLedger
  vault: PaidMediaVault
  capacity: PaidMediaCapacityManager
}

function createExternalFakes(): ExternalFakes {
  return {
    transport: vi.fn(),
    provider: vi.fn(async () => {
      throw new Error('provider must stay unreachable during local recovery')
    }),
    probe: vi.fn(async () => {
      throw new Error('probe must stay unreachable during local recovery')
    })
  }
}

function createLocalComponents(root: string, external: ExternalFakes): LocalComponents {
  const vaultRoot = join(root, 'vault')
  const stageRoot = join(root, 'stage')
  const tempRoot = join(root, 'temp')
  const probeSpoolRoot = join(root, 'probe-spool')
  mkdirSync(stageRoot, { recursive: true })
  mkdirSync(tempRoot, { recursive: true })
  mkdirSync(probeSpoolRoot, { recursive: true })
  const harden = (): void => undefined
  const vaultDependencies: PaidMediaVaultDependencies = {
    safeStorage,
    harden,
    now: () => NOW,
    fetchRemote: ((...args: unknown[]) => {
      external.transport(...args)
      return external.provider(...args)
    }) as PaidMediaVaultDependencies['fetchRemote'],
    ensureMediaProbeReady: external.probe as PaidMediaVaultDependencies['ensureMediaProbeReady'],
    validateMediaAsset: external.probe as PaidMediaVaultDependencies['validateMediaAsset'],
    stageRoot: () => stageRoot
  }
  return {
    ledger: new PaidMediaLedger(join(root, 'ledger.json'), {
      safeStorage,
      harden,
      now: () => NOW,
      uuid: () => OPERATION_UUID,
      atomicIO: nodePaidMediaAtomicIO
    }),
    vault: new PaidMediaVault(vaultRoot, vaultDependencies),
    capacity: new PaidMediaCapacityManager(join(root, 'capacity.json'), vaultRoot, {
      safeStorage,
      harden,
      now: () => NOW,
      atomicIO: nodePaidMediaAtomicIO,
      tempRoot: () => tempRoot,
      probeSpoolRoot: () => probeSpoolRoot,
      resolveVolume: () => ({ volumeId: 'test-volume', root }),
      freeBytes: () => 16n * 1024n * 1024n * 1024n
    })
  }
}

async function provisionLocalComponents(components: LocalComponents): Promise<void> {
  await components.ledger.provisionAuthorityLedger()
  await components.vault.provisionAuthorityVault()
  await components.capacity.provisionAuthorityJournal()
}

async function readEvidence(components: LocalComponents): Promise<PaidMediaAuthorityEvidence> {
  const [ledger, vault, capacity] = await Promise.all([
    components.ledger.inspectAuthorityEvidence(),
    components.vault.inspectAuthorityEvidence(),
    components.capacity.inspectAuthorityEvidence()
  ])
  return {
    ledgerIdentity: ledger.ledgerIdentity,
    ledgerSequence: ledger.ledgerSequence,
    ledgerStateDigest: ledger.ledgerStateDigest,
    vaultStateDigest: vault.vaultStateDigest,
    capacityIdentity: capacity.capacityIdentity,
    capacitySequence: capacity.capacitySequence,
    capacityStateDigest: capacity.capacityStateDigest,
    legacySealDecisionSha256: LEGACY_SEAL_DECISION_SHA256
  }
}

function attachGuards(components: LocalComponents, gate: PaidMediaMutationGate): void {
  components.ledger.setMutationGuard(gate.guard)
  components.vault.setMutationGuard(gate.guard)
  components.capacity.setMutationGuard(gate.guard)
}

function createAuthority(input: {
  root: string
  client: FakeInstallationRootClient
  components: LocalComponents
  slot: PaidMediaRecoveryExecutorSlot
  uuids: string[]
}): PaidMediaInstallationRootAuthority {
  let uuidIndex = 0
  return new PaidMediaInstallationRootAuthority(join(input.root, 'installation-authority.json'), {
    client: input.client,
    safeStorage,
    harden: () => undefined,
    atomicIO: nodePaidMediaInstallationRootAtomicIO,
    now: () => NOW,
    uuid: () => input.uuids[uuidIndex++] ?? 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
    readEvidence: () => readEvidence(input.components),
    recoverableExecutor: input.slot
  })
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true })
}, 60_000)

describe('paid media recovery runtime integration', () => {
  it('fails closed before bind, then resumes the exact durable ticket after restart without external I/O', async () => {
    const root = mkdtempSync(join(tmpdir(), 'nachuan-paid-recovery-runtime-'))
    roots.push(root)
    const intentRoot = join(root, 'recovery-intents')
    mkdirSync(intentRoot)
    const external = createExternalFakes()
    const client = new FakeInstallationRootClient()
    const firstComponents = createLocalComponents(root, external)
    await provisionLocalComponents(firstComponents)

    const firstSlot = new PaidMediaRecoveryExecutorSlot()
    const firstAuthority = createAuthority({
      root,
      client,
      components: firstComponents,
      slot: firstSlot,
      uuids: [
        'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
        'cccccccc-cccc-4ccc-8ccc-cccccccccccc'
      ]
    })
    await expect(firstAuthority.provision()).resolves.toMatchObject({ mode: 'ready' })
    const firstGate = new PaidMediaMutationGate(firstAuthority)
    attachGuards(firstComponents, firstGate)

    const paidPrincipalSha256 = firstAuthority.localPaidPrincipal()
    await firstAuthority.runMutation({ kind: 'claim' }, (context) =>
      firstGate.runLegacy(
        { transactionId: context.transactionId, kind: 'claim', operationId: null },
        async () => {
          const claimed = await firstComponents.ledger.claim({
            path: PATH,
            requestSha256: REQUEST_SHA256,
            recoveryDomainSha256: paidPrincipalSha256
          })
          expect(claimed.operation.operationId).toBe(OPERATION_ID)
          await firstComponents.vault.recordClaim({
            operationId: claimed.operation.operationId,
            path: PATH,
            encodedBody: ENCODED_BODY
          })
        }
      )
    )

    const intentStore = new PaidMediaRecoveryIntentStore(intentRoot, {
      safeStorage,
      harden: () => undefined
    })
    const payload = {
      kind: 'asset_v2_dispatch' as const,
      operationId: OPERATION_ID,
      claim: {
        path: PATH,
        requestSha256: REQUEST_SHA256,
        recoveryDomainSha256: paidPrincipalSha256
      },
      paidPrincipalSha256
    }
    const prepared = await intentStore.prepare(payload)
    const evidenceBeforeUnboundAttempt = await readEvidence(firstComponents)

    await expect(
      firstAuthority.runRecoverableMutation({
        handlerVersion: PAID_MEDIA_RECOVERABLE_HANDLER_VERSION,
        kind: prepared.kind,
        operationId: prepared.operationId,
        intentSha256: prepared.intentSha256
      })
    ).rejects.toThrow(/executor slot is not bound/i)
    expect(firstAuthority.state).toMatchObject({
      mode: 'recovery_pending',
      pendingRecovery: prepared
    })
    expect(await readEvidence(firstComponents)).toEqual(evidenceBeforeUnboundAttempt)

    const restartedComponents = createLocalComponents(root, external)
    const restartedSlot = new PaidMediaRecoveryExecutorSlot()
    const restartedAuthority = createAuthority({
      root,
      client,
      components: restartedComponents,
      slot: restartedSlot,
      uuids: ['eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee']
    })
    await expect(restartedAuthority.reconcileStartup()).resolves.toMatchObject({
      mode: 'recovery_pending',
      pendingRecovery: prepared
    })
    const restartedGate = new PaidMediaMutationGate(restartedAuthority)
    attachGuards(restartedComponents, restartedGate)
    const restartedStore = new PaidMediaRecoveryIntentStore(intentRoot, {
      safeStorage,
      harden: () => undefined
    })
    expect(restartedStore.read(prepared)).toEqual(payload)
    const capacityBeforeRecovery =
      await restartedComponents.capacity.inspectAuthorityEvidence()
    const executor = new PaidMediaRecoveryExecutor({
      authority: restartedAuthority,
      gate: restartedGate,
      intentStore: restartedStore,
      ledger: restartedComponents.ledger,
      vault: restartedComponents.vault,
      capacity: restartedComponents.capacity
    })
    restartedSlot.bind(executor.asRootExecutor())

    await expect(
      restartedAuthority.resumeRecoverableMutation({
        handlerVersion: PAID_MEDIA_RECOVERABLE_HANDLER_VERSION,
        kind: prepared.kind,
        operationId: prepared.operationId,
        intentSha256: prepared.intentSha256
      })
    ).resolves.toMatchObject({ mode: 'ready' })

    const [operation] = await restartedComponents.ledger.listPublic()
    expect(operation).toMatchObject({
      operationId: OPERATION_ID,
      state: 'dispatching',
      dispatchCount: 1
    })
    const marker = await restartedComponents.vault.verifyAssetV2DispatchMarker(OPERATION_ID)
    expect(marker).toMatchObject({
      operationId: OPERATION_ID,
      path: PATH,
      requestSha256: REQUEST_SHA256,
      recoveryDomainSha256: paidPrincipalSha256,
      paidPrincipalSha256
    })
    const capacityAfterRecovery =
      await restartedComponents.capacity.inspectAuthorityEvidence()
    expect(capacityAfterRecovery).toMatchObject({
      capacityIdentity: capacityBeforeRecovery.capacityIdentity,
      capacitySequence: capacityBeforeRecovery.capacitySequence + 1
    })
    expect(capacityAfterRecovery.capacityStateDigest).not.toBe(
      capacityBeforeRecovery.capacityStateDigest
    )
    await expect(
      restartedComponents.capacity.ensureReservation({
        operationId: OPERATION_ID,
        path: PATH,
        allowCreate: false
      })
    ).resolves.toMatchObject({
      operationId: OPERATION_ID,
      path: PATH,
      phase: 'active',
      budgetPolicy: PAID_MEDIA_CAPACITY_BUDGET_POLICY
    })
    expect(await restartedComponents.capacity.inspectAuthorityEvidence()).toEqual(
      capacityAfterRecovery
    )
    expect(executor).toBeInstanceOf(PaidMediaRecoveryExecutor)
    expect(external.transport).not.toHaveBeenCalled()
    expect(external.provider).not.toHaveBeenCalled()
    expect(external.probe).not.toHaveBeenCalled()
  }, 120_000)
})
