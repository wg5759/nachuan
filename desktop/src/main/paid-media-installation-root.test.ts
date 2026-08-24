import { createHash } from 'node:crypto'

import { describe, expect, it } from 'vitest'

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
  PaidMediaRecoverableMutationConflictError,
  PaidMediaInstallationRootUnavailableError,
  type PaidMediaAuthorityEvidence,
  type PaidMediaInstallationRootAtomicIO,
  type PaidMediaRecoverableMutationDescriptor,
  type PaidMediaRecoverableMutationExecutor,
  type PaidMediaRecoverableMutationKind
} from './paid-media-installation-root'

const INSTALLATION_ID = '1'.repeat(64)
const DESKTOP_IDENTITY = '2'.repeat(64)
const GATEWAY_IDENTITY = '3'.repeat(64)
const PRINCIPAL_DIGEST = '4'.repeat(64)
const OWNER_DIGEST = '5'.repeat(64)
const ZERO = '0'.repeat(64)
const AUTHORITY_PATH = 'C:\\state\\paid-root.json'
const ANCHOR_PATH = `${AUTHORITY_PATH}.anchor`
const PAIR_INTENT_PATH = `${AUTHORITY_PATH}.pair-intent`
const PAIR_INTENT_DOMAIN = Buffer.from(
  'nachuan.desktop.paid-media-authority-pair-intent.v1\0',
  'ascii'
)

function decodeProtected(io: MemoryAtomicIO, path: string): Record<string, unknown> {
  const raw = io.files.get(path)
  if (raw === undefined) throw new Error(`missing protected test file: ${path}`)
  const envelope = JSON.parse(raw) as { ciphertext: string }
  return JSON.parse(Buffer.from(envelope.ciphertext, 'base64').toString('utf8')) as Record<
    string,
    unknown
  >
}

function encodeProtected(
  io: MemoryAtomicIO,
  path: string,
  envelopeSchema: string,
  value: Record<string, unknown>
): void {
  io.files.set(
    path,
    JSON.stringify({
      schema: envelopeSchema,
      protection: 'electron-safe-storage',
      ciphertext: Buffer.from(JSON.stringify(value), 'utf8').toString('base64')
    })
  )
}

function pairIntentReceipt(value: Record<string, unknown>): string {
  return createHash('sha256')
    .update(PAIR_INTENT_DOMAIN)
    .update(
      JSON.stringify({
        schema: value.schema,
        installationId: value.installationId,
        epoch: value.epoch,
        desktopIdentity: value.desktopIdentity,
        expectedPreviousSequence: value.expectedPreviousSequence,
        expectedPreviousStateDigest: value.expectedPreviousStateDigest,
        expectedPreviousDocument: value.expectedPreviousDocument,
        expectedPreviousAnchor: value.expectedPreviousAnchor,
        targetSequence: value.targetSequence,
        targetStateDigest: value.targetStateDigest,
        targetDocument: value.targetDocument,
        targetAnchor: value.targetAnchor
      }),
      'utf8'
    )
    .digest('hex')
}

function rewritePairIntent(
  io: MemoryAtomicIO,
  mutate: (value: Record<string, unknown>) => void,
  refreshReceipt = true
): void {
  const value = decodeProtected(io, PAIR_INTENT_PATH)
  mutate(value)
  if (refreshReceipt) value.receiptDigest = pairIntentReceipt(value)
  encodeProtected(
    io,
    PAIR_INTENT_PATH,
    'nachuan.paid-media-installation-authority.pair-intent.envelope.v1',
    value
  )
}

function evidence(sequence = 1): PaidMediaAuthorityEvidence {
  return {
    ledgerIdentity: '6'.repeat(64),
    ledgerSequence: sequence,
    ledgerStateDigest: createHash('sha256').update(`ledger:${sequence}`).digest('hex'),
    vaultStateDigest: createHash('sha256').update(`vault:${sequence}`).digest('hex'),
    capacityIdentity: '7'.repeat(64),
    capacitySequence: sequence,
    capacityStateDigest: createHash('sha256').update(`capacity:${sequence}`).digest('hex'),
    legacySealDecisionSha256: '8'.repeat(64)
  }
}

function dispatchEvidence(): PaidMediaAuthorityEvidence {
  return evidence(2)
}

function resultReadyEvidence(): PaidMediaAuthorityEvidence {
  const before = evidence(1)
  const changed = evidence(2)
  return {
    ...changed,
    capacitySequence: before.capacitySequence,
    capacityStateDigest: before.capacityStateDigest
  }
}

function vaultEvidence(): PaidMediaAuthorityEvidence {
  const before = evidence(1)
  return {
    ...before,
    vaultStateDigest: evidence(2).vaultStateDigest
  }
}

function capacityReleaseEvidence(): PaidMediaAuthorityEvidence {
  const before = evidence(1)
  const changed = evidence(2)
  return {
    ...before,
    vaultStateDigest: changed.vaultStateDigest,
    capacitySequence: changed.capacitySequence,
    capacityStateDigest: changed.capacityStateDigest
  }
}

class MemoryAtomicIO implements PaidMediaInstallationRootAtomicIO {
  readonly files = new Map<string, string>()
  readonly writes: string[] = []
  failWrite: { call: number; phase: 'before' | 'after' } | null = null

  readUtf8(path: string): string | null {
    return this.files.get(path) ?? null
  }

  writeUtf8Atomic(path: string, value: string): void {
    const call = this.writes.length + 1
    this.writes.push(path)
    if (this.failWrite?.call === call && this.failWrite.phase === 'before') {
      throw new Error(`simulated atomic write ${call} failure before publish`)
    }
    this.files.set(path, value)
    if (this.failWrite?.call === call && this.failWrite.phase === 'after') {
      throw new Error(`simulated atomic write ${call} failure after publish`)
    }
  }
}

class FakeRootClient {
  readonly calls: string[] = []
  activateOnBind = true
  failAdvanceBeforeCommit = false
  failAdvanceAfterCommit = false
  failAdvanceBeforeCommitFromCall: number | null = null
  failSnapshotTransient = false
  failSnapshotCount = 0
  advanceAttempts = 0
  private snapshotValue: InstallationRootSnapshot

  constructor(bound = false) {
    this.snapshotValue = this.makeSnapshot({
      status: 'provisioning',
      bound,
      sequenceFloor: bound ? 0 : 0,
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
    epoch?: number
    identity?: string
  }): InstallationRootSnapshot {
    const epoch = input.epoch ?? 9
    return {
      installationId: INSTALLATION_ID,
      ownerSidDigest: OWNER_DIGEST,
      epoch,
      rootRevision: (this.snapshotValue?.rootRevision ?? 10) + 1,
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
          identity: input.identity ?? DESKTOP_IDENTITY,
          epoch,
          bound: input.bound,
          sequenceFloor: input.sequenceFloor,
          stateDigest: input.stateDigest,
          recoveryFloor: input.recoveryFloor ?? null,
          recoveryStateDigest: input.recoveryStateDigest ?? null
        },
        gateway: {
          identity: GATEWAY_IDENTITY,
          epoch,
          bound: true,
          sequenceFloor: 0,
          stateDigest: '9'.repeat(64),
          recoveryFloor: null,
          recoveryStateDigest: null
        }
      },
      updater: {
        releaseSequence: 0,
        keyringSequence: 0,
        artifactDigest: ZERO,
        stateDigest: ZERO
      }
    }
  }

  activate(): void {
    const desktop = this.snapshotValue.components.desktop
    this.snapshotValue = this.makeSnapshot({
      status: 'active',
      bound: desktop.bound,
      sequenceFloor: desktop.sequenceFloor,
      stateDigest: desktop.stateDigest,
      recoveryFloor: desktop.recoveryFloor,
      recoveryStateDigest: desktop.recoveryStateDigest
    })
  }

  driftEpoch(): void {
    const desktop = this.snapshotValue.components.desktop
    this.snapshotValue = this.makeSnapshot({
      status: 'active',
      bound: desktop.bound,
      sequenceFloor: desktop.sequenceFloor,
      stateDigest: desktop.stateDigest,
      epoch: 10
    })
  }

  snapshot(): Promise<InstallationRootSnapshotEnvelope> {
    this.calls.push('snapshot')
    if (this.failSnapshotCount > 0) {
      this.failSnapshotCount -= 1
      return Promise.reject(new Error('loopback restarting once'))
    }
    if (this.failSnapshotTransient) return Promise.reject(new Error('loopback restarting'))
    return Promise.resolve({
      schema: 'nachuan.installation-root.snapshot.v1',
      snapshot: this.snapshotValue
    })
  }

  bindDesktop(input: InstallationRootDesktopBindRequest): Promise<InstallationRootMutationEnvelope> {
    this.calls.push('bind')
    this.snapshotValue = this.makeSnapshot({
      status: this.activateOnBind ? 'active' : 'provisioning',
      bound: true,
      sequenceFloor: input.sequenceFloor,
      stateDigest: input.stateDigest
    })
    return Promise.resolve(this.mutation())
  }

  verifyDesktop(input: InstallationRootDesktopVerifyRequest): Promise<InstallationRootMutationEnvelope> {
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

  advanceDesktop(input: InstallationRootDesktopAdvanceRequest): Promise<InstallationRootMutationEnvelope> {
    this.calls.push('advance')
    this.advanceAttempts += 1
    if (
      this.failAdvanceBeforeCommit ||
      (this.failAdvanceBeforeCommitFromCall !== null &&
        this.advanceAttempts >= this.failAdvanceBeforeCommitFromCall)
    ) {
      return Promise.reject(new Error('root unavailable'))
    }
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
    if (this.failAdvanceAfterCommit) return Promise.reject(new Error('response lost'))
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

function fixture(
  root = new FakeRootClient(),
  recoverableExecutor?: PaidMediaRecoverableMutationExecutor
): {
  authority: PaidMediaInstallationRootAuthority
  root: FakeRootClient
  setEvidence(next: PaidMediaAuthorityEvidence): void
  getEvidence(): PaidMediaAuthorityEvidence
  atomicIO: MemoryAtomicIO
} {
  const atomicIO = new MemoryAtomicIO()
  let currentEvidence = evidence()
  const authority = new PaidMediaInstallationRootAuthority('C:\\state\\paid-root.json', {
    client: root,
    safeStorage: {
      isEncryptionAvailable: () => true,
      encryptString: (value) => Buffer.from(value, 'utf8'),
      decryptString: (value) => value.toString('utf8')
    },
    harden: () => undefined,
    atomicIO,
    now: () => 1_700_000_000_000,
    uuid: () => 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    readEvidence: () => Promise.resolve(currentEvidence),
    ...(recoverableExecutor ? { recoverableExecutor } : {})
  })
  return {
    authority,
    root,
    setEvidence(next) {
      currentEvidence = next
    },
    getEvidence() {
      return currentEvidence
    },
    atomicIO
  }
}

const RECOVERABLE_INPUT = Object.freeze({
  handlerVersion: PAID_MEDIA_RECOVERABLE_HANDLER_VERSION,
  kind: 'asset_v2_dispatch' as const,
  operationId: 'desktop-op-aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  intentSha256: 'a'.repeat(64)
})

async function completedRecoverableFixture(): Promise<ReturnType<typeof fixture>> {
  let item!: ReturnType<typeof fixture>
  item = fixture(new FakeRootClient(), {
    async execute() {
      item.setEvidence(dispatchEvidence())
    }
  })
  await item.authority.provision()
  await item.authority.runRecoverableMutation(RECOVERABLE_INPUT)
  return item
}

describe('PaidMediaInstallationRootAuthority', () => {
  it('binds only the installer-preallocated Desktop identity and exact initial composite evidence', async () => {
    const item = fixture()

    const state = await item.authority.provision()

    expect(state).toMatchObject({
      mode: 'ready',
      installationId: INSTALLATION_ID,
      epoch: 9,
      desktopIdentity: DESKTOP_IDENTITY,
      mutationSequence: 0
    })
    expect(item.authority.localPaidPrincipal()).toBe(state.paidPrincipal)
    expect(item.root.calls).toContain('bind')
    expect(item.atomicIO.files.size).toBe(3)
    expect(item.atomicIO.writes).toEqual([PAIR_INTENT_PATH, ANCHOR_PATH, AUTHORITY_PATH])
  })

  it('waits for installation activation after a provisioning bind response', async () => {
    const item = fixture()
    item.root.activateOnBind = false

    await expect(item.authority.provision()).resolves.toMatchObject({
      mode: 'provisioned_not_active',
      reasonCode: 'awaiting-installation-activation'
    })

    await expect(item.authority.reconcileStartup()).resolves.toMatchObject({
      mode: 'provisioned_not_active',
      reasonCode: 'awaiting-installation-activation'
    })

    item.root.activate()
    await expect(item.authority.reconcileStartup()).resolves.toMatchObject({
      mode: 'ready',
      reasonCode: 'authority-exact'
    })
  })

  it.each([
    ['before pair intent publication', 1, 'before', 3],
    ['after pair intent publication and before anchor', 1, 'after', 2],
    ['after anchor publication and before body', 2, 'after', 2],
    ['after body publication and before return', 3, 'after', 0]
  ] as const)(
    'recovers first provision %s',
    async (_label, call, phase, expectedRecoveryWrites) => {
      const item = fixture()
      item.atomicIO.failWrite = { call, phase }

      await expect(item.authority.provision()).rejects.toThrow(/provisioning failed/i)

      const restarted = fixture(item.root)
      for (const [path, value] of item.atomicIO.files) restarted.atomicIO.files.set(path, value)
      await expect(restarted.authority.provision()).resolves.toMatchObject({ mode: 'ready' })
      expect(restarted.atomicIO.writes).toHaveLength(expectedRecoveryWrites)
      expect(restarted.atomicIO.files.has(ANCHOR_PATH)).toBe(true)
      expect(restarted.atomicIO.files.has(AUTHORITY_PATH)).toBe(true)
      expect(restarted.atomicIO.files.has(PAIR_INTENT_PATH)).toBe(true)
    }
  )

  it('keeps the legacy v4 idle document shape byte-compatible and readable after restart', async () => {
    const item = fixture()
    await item.authority.provision()
    const raw = item.atomicIO.files.get('C:\\state\\paid-root.json')
    expect(raw).toBeTypeOf('string')
    const envelope = JSON.parse(raw as string) as { ciphertext: string }
    const document = JSON.parse(Buffer.from(envelope.ciphertext, 'base64').toString('utf8')) as Record<
      string,
      unknown
    >

    expect(document.schema).toBe('nachuan.paid-media-installation-authority.v4')
    expect(Object.keys(document).sort()).toEqual(
      [
        'schema',
        'installationId',
        'epoch',
        'desktopIdentity',
        'rootPrincipalDigest',
        'mutationSequence',
        'stateDigest',
        'previousStateDigest',
        'compositeDigest',
        'authorityMode',
        'recoveryFloor',
        'recoveryStateDigest',
        'pendingIntent'
      ].sort()
    )
    expect(document).not.toHaveProperty('recoverableCommit')

    item.atomicIO.files.delete(PAIR_INTENT_PATH)
    const restarted = fixture(item.root)
    for (const [path, value] of item.atomicIO.files) restarted.atomicIO.files.set(path, value)
    await expect(restarted.authority.reconcileStartup()).resolves.toMatchObject({ mode: 'ready' })
  })

  it('rejects a mismatched legacy pair when no pair intent exists', async () => {
    const item = fixture()
    await item.authority.provision()
    item.atomicIO.files.delete(PAIR_INTENT_PATH)
    const anchor = decodeProtected(item.atomicIO, ANCHOR_PATH)
    anchor.stateDigest = 'a'.repeat(64)
    encodeProtected(
      item.atomicIO,
      ANCHOR_PATH,
      'nachuan.paid-media-installation-authority.anchor.envelope.v1',
      anchor
    )

    const restarted = fixture(item.root)
    for (const [path, value] of item.atomicIO.files) restarted.atomicIO.files.set(path, value)
    await expect(restarted.authority.reconcileStartup()).rejects.toBeInstanceOf(
      PaidMediaInstallationRootUnavailableError
    )
  })

  it.each([
    [
      'corrupt envelope',
      (item: ReturnType<typeof fixture>) => item.atomicIO.files.set(PAIR_INTENT_PATH, '{')
    ],
    [
      'extra top-level field',
      (item: ReturnType<typeof fixture>) =>
        rewritePairIntent(
          item.atomicIO,
          (value) => {
            value.unexpected = true
          },
          false
        )
    ],
    [
      'wrong previous digest with a refreshed receipt',
      (item: ReturnType<typeof fixture>) =>
        rewritePairIntent(item.atomicIO, (value) => {
          value.expectedPreviousStateDigest = 'b'.repeat(64)
        })
    ],
    [
      'cross-step target sequence with a refreshed receipt',
      (item: ReturnType<typeof fixture>) =>
        rewritePairIntent(item.atomicIO, (value) => {
          value.targetSequence = Number(value.targetSequence) + 2
        })
    ],
    [
      'installation identity drift with a refreshed receipt',
      (item: ReturnType<typeof fixture>) =>
        rewritePairIntent(item.atomicIO, (value) => {
          value.installationId = 'f'.repeat(64)
        })
    ],
    [
      'target document extra field with a refreshed receipt',
      (item: ReturnType<typeof fixture>) =>
        rewritePairIntent(item.atomicIO, (value) => {
          const targetDocument = value.targetDocument as Record<string, unknown>
          targetDocument.unexpected = true
        })
    ]
  ] as const)('rejects pair-intent %s', async (_label, corrupt) => {
    const item = await completedRecoverableFixture()
    corrupt(item)

    const restarted = fixture(item.root)
    for (const [path, value] of item.atomicIO.files) restarted.atomicIO.files.set(path, value)
    restarted.setEvidence(item.getEvidence())
    await expect(restarted.authority.reconcileStartup()).rejects.toBeInstanceOf(
      PaidMediaInstallationRootUnavailableError
    )
  })

  it('rejects replacement by a different valid pair intent', async () => {
    const item = await completedRecoverableFixture()
    const other = fixture()
    await other.authority.provision()
    item.atomicIO.files.set(
      PAIR_INTENT_PATH,
      other.atomicIO.files.get(PAIR_INTENT_PATH) as string
    )

    const restarted = fixture(item.root)
    for (const [path, value] of item.atomicIO.files) restarted.atomicIO.files.set(path, value)
    restarted.setEvidence(item.getEvidence())
    await expect(restarted.authority.reconcileStartup()).rejects.toBeInstanceOf(
      PaidMediaInstallationRootUnavailableError
    )
  })

  it('confirms the recoverable Root pending before exposing the guard or executing the closed handler', async () => {
    const events: string[] = []
    let item!: ReturnType<typeof fixture>
    let observed!: PaidMediaRecoverableMutationDescriptor
    const executor: PaidMediaRecoverableMutationExecutor = {
      async execute(descriptor) {
        events.push('handler')
        observed = descriptor
        expect(item.root.calls.filter((call) => call === 'advance')).toHaveLength(1)
        expect(item.authority.state).toMatchObject({
          mode: 'recovery_pending',
          pendingRecovery: RECOVERABLE_INPUT
        })
        expect(item.authority.state.pendingRecovery).not.toHaveProperty('transactionId')
        expect(() => item.authority.assertMutationContext(descriptor.transactionId)).not.toThrow()
        item.setEvidence(dispatchEvidence())
      }
    }
    item = fixture(new FakeRootClient(), executor)
    await item.authority.provision()

    const state = await item.authority.runRecoverableMutation(RECOVERABLE_INPUT)

    expect(events).toEqual(['handler'])
    expect(state).toMatchObject({ mode: 'ready', mutationSequence: 2 })
    expect(item.root.calls.filter((call) => call === 'advance')).toHaveLength(2)
    expect(Object.isFrozen(observed)).toBe(true)
    expect(Object.isFrozen(observed.beforeAuthorityEvidence)).toBe(true)
    expect(Object.keys(observed).sort()).toEqual(
      [
        'beforeAuthorityEvidence',
        'beforeCompositeDigest',
        'handlerVersion',
        'intentSha256',
        'kind',
        'mode',
        'operationId',
        'preparedAt',
        'transactionId'
      ].sort()
    )
    expect(observed).not.toHaveProperty('client')
    expect(observed).not.toHaveProperty('assertOutboundReady')
  })

  it('treats an exact recently committed descriptor as read-only success', async () => {
    let handlerCalls = 0
    let item!: ReturnType<typeof fixture>
    item = fixture(new FakeRootClient(), {
      async execute() {
        handlerCalls += 1
        item.setEvidence(dispatchEvidence())
      }
    })
    await item.authority.provision()
    await expect(item.authority.runRecoverableMutation(RECOVERABLE_INPUT)).resolves.toMatchObject({
      mode: 'ready',
      mutationSequence: 2
    })
    const advancesAfterCommit = item.root.calls.filter((call) => call === 'advance').length

    await expect(item.authority.runRecoverableMutation(RECOVERABLE_INPUT)).resolves.toMatchObject({
      mode: 'ready',
      mutationSequence: 2
    })
    expect(handlerCalls).toBe(1)
    expect(item.root.calls.filter((call) => call === 'advance')).toHaveLength(advancesAfterCommit)
  })

  it('replays an exact committed descriptor after restart without requiring an executor', async () => {
    const completed = await completedRecoverableFixture()
    const restarted = fixture(completed.root)
    for (const [path, value] of completed.atomicIO.files) {
      restarted.atomicIO.files.set(path, value)
    }
    restarted.setEvidence(completed.getEvidence())
    await expect(restarted.authority.reconcileStartup()).resolves.toMatchObject({ mode: 'ready' })
    const advancesBeforeReplay = restarted.root.calls.filter((call) => call === 'advance').length

    await expect(restarted.authority.runRecoverableMutation(RECOVERABLE_INPUT)).resolves.toMatchObject({
      mode: 'ready',
      mutationSequence: 2
    })
    expect(restarted.root.calls.filter((call) => call === 'advance')).toHaveLength(
      advancesBeforeReplay
    )
  })

  it.each([
    ['before pending pair intent publication', 4, 'before', false],
    ['after pending pair intent publication and before anchor', 4, 'after', true],
    ['after pending anchor publication and before body', 5, 'after', true],
    ['after pending body publication and before return', 6, 'after', true]
  ] as const)(
    'recovers a recoverable pending write %s',
    async (_label, call, phase, targetWasDurablyIntended) => {
      let executorCalls = 0
      let active!: ReturnType<typeof fixture>
      const executor: PaidMediaRecoverableMutationExecutor = {
        async execute() {
          executorCalls += 1
          active.setEvidence(dispatchEvidence())
        }
      }
      active = fixture(new FakeRootClient(), executor)
      await active.authority.provision()
      active.atomicIO.failWrite = { call, phase }

      await expect(active.authority.runRecoverableMutation(RECOVERABLE_INPUT)).rejects.toThrow(
        /atomic write/i
      )
      expect(executorCalls).toBe(0)

      const restarted = fixture(active.root, executor)
      for (const [path, value] of active.atomicIO.files) restarted.atomicIO.files.set(path, value)
      restarted.setEvidence(active.getEvidence())
      active = restarted
      if (!targetWasDurablyIntended) {
        await expect(restarted.authority.reconcileStartup()).resolves.toMatchObject({ mode: 'ready' })
        expect(executorCalls).toBe(0)
        return
      }
      await expect(restarted.authority.reconcileStartup()).resolves.toMatchObject({
        mode: 'recovery_pending',
        pendingRecovery: RECOVERABLE_INPUT
      })
      await expect(
        restarted.authority.resumeRecoverableMutation(RECOVERABLE_INPUT)
      ).resolves.toMatchObject({ mode: 'ready', mutationSequence: 2 })
      expect(executorCalls).toBe(1)
    }
  )

  it.each([
    ['before final pair intent publication', 7, 'before', true],
    ['after final pair intent publication and before anchor', 7, 'after', false],
    ['after final anchor publication and before body', 8, 'after', false],
    ['after final body publication and before return', 9, 'after', false]
  ] as const)(
    'recovers a recoverable final write %s',
    async (_label, call, phase, needsIdempotentLocalResume) => {
      let executorCalls = 0
      let active!: ReturnType<typeof fixture>
      const executor: PaidMediaRecoverableMutationExecutor = {
        async execute(descriptor) {
          executorCalls += 1
          expect(descriptor).not.toHaveProperty('provider')
          expect(descriptor).not.toHaveProperty('session')
          expect(descriptor).not.toHaveProperty('transport')
          active.setEvidence(dispatchEvidence())
        }
      }
      active = fixture(new FakeRootClient(), executor)
      await active.authority.provision()
      active.atomicIO.failWrite = { call, phase }

      await expect(active.authority.runRecoverableMutation(RECOVERABLE_INPUT)).rejects.toThrow(
        /atomic write/i
      )
      expect(executorCalls).toBe(1)

      const restarted = fixture(active.root, executor)
      for (const [path, value] of active.atomicIO.files) restarted.atomicIO.files.set(path, value)
      restarted.setEvidence(active.getEvidence())
      active = restarted
      const reconciled = await restarted.authority.reconcileStartup()
      if (needsIdempotentLocalResume) {
        expect(reconciled).toMatchObject({ mode: 'recovery_pending' })
        await expect(
          restarted.authority.resumeRecoverableMutation(RECOVERABLE_INPUT)
        ).resolves.toMatchObject({ mode: 'ready', mutationSequence: 2 })
        expect(executorCalls).toBe(2)
      } else {
        expect(reconciled).toMatchObject({ mode: 'ready', mutationSequence: 2 })
        // A durable final pair intent is sufficient to repair the local pair;
        // startup only finalizes the already-pending Root CAS.
        expect(executorCalls).toBe(1)
      }
    }
  )

  it('never executes before a local pending has converged to the exact Root pending', async () => {
    let handlerCalls = 0
    const executor: PaidMediaRecoverableMutationExecutor = {
      async execute() {
        handlerCalls += 1
      }
    }
    const root = new FakeRootClient()
    root.failAdvanceBeforeCommit = true
    const item = fixture(root, executor)
    await item.authority.provision()

    await expect(item.authority.runRecoverableMutation(RECOVERABLE_INPUT)).rejects.toBeInstanceOf(
      PaidMediaInstallationRootUnavailableError
    )
    expect(handlerCalls).toBe(0)

    root.failAdvanceBeforeCommit = false
    const restarted = fixture(root, executor)
    for (const [path, value] of item.atomicIO.files) restarted.atomicIO.files.set(path, value)
    await expect(restarted.authority.reconcileStartup()).resolves.toMatchObject({
      mode: 'recovery_pending',
      pendingRecovery: RECOVERABLE_INPUT
    })
    expect(handlerCalls).toBe(0)

    restarted.setEvidence(dispatchEvidence())
    await expect(restarted.authority.resumeRecoverableMutation(RECOVERABLE_INPUT)).resolves.toMatchObject({
      mode: 'ready'
    })
    expect(handlerCalls).toBe(1)
  })

  it('retains a recoverable pending without fusing when startup Root proof is transient', async () => {
    let handlerCalls = 0
    const executor: PaidMediaRecoverableMutationExecutor = {
      async execute() {
        handlerCalls += 1
      }
    }
    const root = new FakeRootClient()
    root.failAdvanceBeforeCommit = true
    const item = fixture(root, executor)
    await item.authority.provision()
    await expect(item.authority.runRecoverableMutation(RECOVERABLE_INPUT)).rejects.toBeInstanceOf(
      PaidMediaInstallationRootUnavailableError
    )

    root.failAdvanceBeforeCommit = false
    root.failSnapshotTransient = true
    const restarted = fixture(root, executor)
    for (const [path, value] of item.atomicIO.files) restarted.atomicIO.files.set(path, value)
    const bytesBefore = new Map(restarted.atomicIO.files)
    await expect(restarted.authority.reconcileStartup()).rejects.toBeInstanceOf(
      PaidMediaInstallationRootUnavailableError
    )
    expect(restarted.authority.state.mode).toBe('detached')
    expect(restarted.authority.state.pendingRecovery).toMatchObject(RECOVERABLE_INPUT)
    expect(restarted.atomicIO.files).toEqual(bytesBefore)
    expect(handlerCalls).toBe(0)

    root.failSnapshotTransient = false
    await expect(restarted.authority.reconcileStartup()).resolves.toMatchObject({
      mode: 'recovery_pending'
    })
    expect(handlerCalls).toBe(0)
  })

  it('keeps one recoverable pending across repeated local failures and resumes the same descriptor', async () => {
    let calls = 0
    let providerCalls = 0
    let item!: ReturnType<typeof fixture>
    const descriptors: PaidMediaRecoverableMutationDescriptor[] = []
    const executor: PaidMediaRecoverableMutationExecutor = {
      async execute(descriptor) {
        calls += 1
        descriptors.push(descriptor)
        if ('client' in descriptor || 'assertOutboundReady' in descriptor || 'provider' in descriptor) {
          providerCalls += 1
        }
        expect(item.authority.state.mode).toBe('recovery_pending')
        await expect(item.authority.assertOutboundReady()).rejects.toBeInstanceOf(
          PaidMediaInstallationRootUnavailableError
        )
        if (calls === 1) item.setEvidence(dispatchEvidence())
        if (calls < 3) throw new Error('local disk temporarily unavailable')
      }
    }
    item = fixture(new FakeRootClient(), executor)
    await item.authority.provision()

    await expect(item.authority.runRecoverableMutation(RECOVERABLE_INPUT)).rejects.toThrow(
      'local disk temporarily unavailable'
    )
    expect(item.authority.state.mode).toBe('recovery_pending')

    const secondBoot = fixture(item.root, executor)
    for (const [path, value] of item.atomicIO.files) secondBoot.atomicIO.files.set(path, value)
    secondBoot.setEvidence(dispatchEvidence())
    item = secondBoot
    await expect(item.authority.reconcileStartup()).resolves.toMatchObject({
      mode: 'recovery_pending'
    })
    await expect(item.authority.resumeRecoverableMutation(RECOVERABLE_INPUT)).rejects.toThrow(
      'local disk temporarily unavailable'
    )

    const thirdBoot = fixture(item.root, executor)
    for (const [path, value] of item.atomicIO.files) thirdBoot.atomicIO.files.set(path, value)
    thirdBoot.setEvidence(dispatchEvidence())
    item = thirdBoot
    await expect(item.authority.reconcileStartup()).resolves.toMatchObject({
      mode: 'recovery_pending'
    })
    await expect(item.authority.resumeRecoverableMutation(RECOVERABLE_INPUT)).resolves.toMatchObject({
      mode: 'ready'
    })

    expect(calls).toBe(3)
    expect(providerCalls).toBe(0)
    expect(descriptors.map((descriptor) => JSON.stringify(descriptor))).toEqual([
      JSON.stringify(descriptors[0]),
      JSON.stringify(descriptors[0]),
      JSON.stringify(descriptors[0])
    ])
  })

  it('automatically finishes a recoverable local-final plus Root-pending gap without rerunning the handler', async () => {
    let handlerCalls = 0
    let item!: ReturnType<typeof fixture>
    const executor: PaidMediaRecoverableMutationExecutor = {
      async execute() {
        handlerCalls += 1
        item.setEvidence(dispatchEvidence())
      }
    }
    const root = new FakeRootClient()
    root.failAdvanceBeforeCommitFromCall = 2
    item = fixture(root, executor)
    await item.authority.provision()

    await expect(item.authority.runRecoverableMutation(RECOVERABLE_INPUT)).rejects.toBeInstanceOf(
      PaidMediaInstallationRootUnavailableError
    )
    expect(handlerCalls).toBe(1)
    expect(item.authority.state.mode).toBe('recovery_pending')

    root.failAdvanceBeforeCommitFromCall = null
    const restarted = fixture(root, executor)
    for (const [path, value] of item.atomicIO.files) restarted.atomicIO.files.set(path, value)
    restarted.setEvidence(dispatchEvidence())

    await expect(restarted.authority.reconcileStartup()).resolves.toMatchObject({ mode: 'ready' })
    expect(handlerCalls).toBe(1)
  })

  it('resolves Root CAS response loss at both recoverable transitions without duplicate execution', async () => {
    let handlerCalls = 0
    const root = new FakeRootClient()
    root.failAdvanceAfterCommit = true
    let item!: ReturnType<typeof fixture>
    item = fixture(root, {
      async execute() {
        handlerCalls += 1
        item.setEvidence(dispatchEvidence())
      }
    })
    await item.authority.provision()

    await expect(item.authority.runRecoverableMutation(RECOVERABLE_INPUT)).resolves.toMatchObject({
      mode: 'ready'
    })
    expect(handlerCalls).toBe(1)
    expect(root.advanceAttempts).toBe(2)
  })

  it('rejects a no-op handler and any authority component outside the closed kind policy', async () => {
    const noOp = fixture(new FakeRootClient(), {
      async execute() {
        // A trusted handler returning success without its required durable
        // Vault+ledger transition must not be enough to bless a final.
      }
    })
    await noOp.authority.provision()
    await expect(noOp.authority.runRecoverableMutation(RECOVERABLE_INPUT)).rejects.toBeInstanceOf(
      PaidMediaRecoverableMutationConflictError
    )
    expect(noOp.authority.state.mode).toBe('manual_only')

    let extra!: ReturnType<typeof fixture>
    extra = fixture(new FakeRootClient(), {
      async execute() {
        extra.setEvidence({
          ...dispatchEvidence(),
          legacySealDecisionSha256: 'f'.repeat(64)
        })
      }
    })
    await extra.authority.provision()
    await expect(extra.authority.runRecoverableMutation(RECOVERABLE_INPUT)).rejects.toBeInstanceOf(
      PaidMediaRecoverableMutationConflictError
    )
    expect(extra.authority.state.mode).toBe('manual_only')
  })

  it('enforces the closed authority transition policy for every recoverable handler kind', async () => {
    const cases: Array<[
      PaidMediaRecoverableMutationKind,
      () => PaidMediaAuthorityEvidence
    ]> = [
      ['asset_v2_dispatch', dispatchEvidence],
      ['asset_v2_stage_reserve', vaultEvidence],
      ['asset_v2_stage_archive', vaultEvidence],
      ['asset_v2_stage_cleanup', vaultEvidence],
      ['asset_v2_result_ready_ack_intent', resultReadyEvidence],
      ['asset_v2_ack_completion', vaultEvidence],
      ['asset_v2_capacity_release', capacityReleaseEvidence]
    ]

    for (const [kind, nextEvidence] of cases) {
      let item!: ReturnType<typeof fixture>
      item = fixture(new FakeRootClient(), {
        async execute() {
          item.setEvidence(nextEvidence())
        }
      })
      await item.authority.provision()
      await expect(
        item.authority.runRecoverableMutation({ ...RECOVERABLE_INPUT, kind })
      ).resolves.toMatchObject({ mode: 'ready' })
    }
  })

  it('moves only an explicit recoverable conflict to manual-only and rejects descriptor mismatch or a missing executor', async () => {
    let conflictCalls = 0
    const conflictItem = fixture(new FakeRootClient(), {
      async execute() {
        conflictCalls += 1
        throw new PaidMediaRecoverableMutationConflictError('exact local postcondition conflicts')
      }
    })
    await conflictItem.authority.provision()

    await expect(conflictItem.authority.runRecoverableMutation(RECOVERABLE_INPUT)).rejects.toBeInstanceOf(
      PaidMediaRecoverableMutationConflictError
    )
    expect(conflictCalls).toBe(1)
    expect(conflictItem.authority.state.mode).toBe('manual_only')

    let retryCalls = 0
    const retryItem = fixture(new FakeRootClient(), {
      async execute() {
        retryCalls += 1
        throw new Error('retry me')
      }
    })
    await retryItem.authority.provision()
    await expect(retryItem.authority.runRecoverableMutation(RECOVERABLE_INPUT)).rejects.toThrow('retry me')
    await expect(
      retryItem.authority.resumeRecoverableMutation({
        ...RECOVERABLE_INPUT,
        intentSha256: 'b'.repeat(64)
      })
    ).rejects.toBeInstanceOf(PaidMediaInstallationRootUnavailableError)
    expect(retryCalls).toBe(1)
    expect(retryItem.authority.state.mode).toBe('recovery_pending')

    const missing = fixture()
    await missing.authority.provision()
    await expect(missing.authority.runRecoverableMutation(RECOVERABLE_INPUT)).rejects.toBeInstanceOf(
      PaidMediaInstallationRootUnavailableError
    )
    expect(missing.authority.state.mode).toBe('ready')

    let pendingHandlerCalls = 0
    const pendingRoot = new FakeRootClient()
    const pendingItem = fixture(pendingRoot, {
      async execute() {
        pendingHandlerCalls += 1
        throw new Error('leave pending')
      }
    })
    await pendingItem.authority.provision()
    await expect(pendingItem.authority.runRecoverableMutation(RECOVERABLE_INPUT)).rejects.toThrow(
      'leave pending'
    )
    const missingAfterRestart = fixture(pendingRoot)
    for (const [path, value] of pendingItem.atomicIO.files) {
      missingAfterRestart.atomicIO.files.set(path, value)
    }
    await expect(missingAfterRestart.authority.reconcileStartup()).resolves.toMatchObject({
      mode: 'recovery_pending'
    })
    await expect(
      missingAfterRestart.authority.resumeRecoverableMutation(RECOVERABLE_INPUT)
    ).rejects.toBeInstanceOf(PaidMediaInstallationRootUnavailableError)
    expect(pendingHandlerCalls).toBe(1)
  })

  it('rejects a closed-kind/version mismatch and never blesses evidence drift while Root is still before pending', async () => {
    let handlerCalls = 0
    const root = new FakeRootClient()
    const item = fixture(root, {
      async execute() {
        handlerCalls += 1
      }
    })
    await item.authority.provision()

    await expect(
      item.authority.runRecoverableMutation({
        ...RECOVERABLE_INPUT,
        kind: 'not_allowlisted'
      } as unknown as typeof RECOVERABLE_INPUT)
    ).rejects.toBeInstanceOf(PaidMediaInstallationRootUnavailableError)
    await expect(
      item.authority.runRecoverableMutation({
        ...RECOVERABLE_INPUT,
        handlerVersion: 2
      } as unknown as typeof RECOVERABLE_INPUT)
    ).rejects.toBeInstanceOf(PaidMediaInstallationRootUnavailableError)
    expect(item.authority.state.mode).toBe('ready')

    root.failAdvanceBeforeCommit = true
    await expect(item.authority.runRecoverableMutation(RECOVERABLE_INPUT)).rejects.toBeInstanceOf(
      PaidMediaInstallationRootUnavailableError
    )
    expect(handlerCalls).toBe(0)

    root.failAdvanceBeforeCommit = false
    const restarted = fixture(root, {
      async execute() {
        handlerCalls += 1
      }
    })
    for (const [path, value] of item.atomicIO.files) restarted.atomicIO.files.set(path, value)
    restarted.setEvidence(evidence(99))
    await expect(restarted.authority.reconcileStartup()).rejects.toBeInstanceOf(
      PaidMediaInstallationRootUnavailableError
    )
    expect(handlerCalls).toBe(0)
    expect(restarted.authority.state.mode).toBe('fused')
  })

  it('keeps a legacy pending/final manual-only even when its kind equals the recoverable allowlist', async () => {
    const root = new FakeRootClient()
    root.failAdvanceBeforeCommitFromCall = 2
    const item = fixture(root)
    await item.authority.provision()

    await expect(
      item.authority.runMutation(
        { kind: 'asset_v2_dispatch', operationId: RECOVERABLE_INPUT.operationId },
        async () => {
          item.setEvidence(evidence(2))
        }
      )
    ).rejects.toBeInstanceOf(PaidMediaInstallationRootUnavailableError)

    root.failAdvanceBeforeCommitFromCall = null
    const restarted = fixture(root)
    for (const [path, value] of item.atomicIO.files) restarted.atomicIO.files.set(path, value)
    restarted.setEvidence(evidence(2))
    await expect(restarted.authority.reconcileStartup()).resolves.toMatchObject({
      mode: 'manual_only'
    })
  })

  it('orders local pending, business commit, pending Root CAS, local final, final Root CAS', async () => {
    const item = fixture()
    await item.authority.provision()
    const events: string[] = []
    item.setEvidence(evidence(1))

    const value = await item.authority.runMutation(
      { kind: 'claim', operationId: 'desktop-op-aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' },
      async (context) => {
        events.push('business')
        item.setEvidence(evidence(2))
        await context.assertOutboundReady()
        return 42
      }
    )

    expect(value).toBe(42)
    expect(item.authority.state).toMatchObject({ mode: 'ready', mutationSequence: 2 })
    expect(item.root.calls.filter((call) => call === 'advance')).toHaveLength(2)
    expect(events).toEqual(['business'])
  })

  it('turns an exact local plus-one gap into a permanent manual-only receipt and ACKs recovery', async () => {
    const item = fixture()
    await item.authority.provision()
    item.root.failAdvanceBeforeCommit = true

    await expect(
      item.authority.runMutation({ kind: 'claim' }, async () => {
        item.setEvidence(evidence(2))
      })
    ).rejects.toBeInstanceOf(PaidMediaInstallationRootUnavailableError)

    item.root.failAdvanceBeforeCommit = false
    const restarted = fixture(item.root)
    for (const [path, value] of item.atomicIO.files) restarted.atomicIO.files.set(path, value)
    restarted.setEvidence(evidence(2))
    const state = await restarted.authority.reconcileStartup()

    expect(state.mode).toBe('manual_only')
    expect(item.root.calls).toContain('verify')
    expect(item.root.calls).toContain('ack')
    await expect(
      restarted.authority.runMutation({ kind: 'claim' }, async () => undefined)
    ).rejects.toBeInstanceOf(PaidMediaInstallationRootUnavailableError)
  })

  it('fails closed on installation epoch drift and on idle composite evidence replacement', async () => {
    const epochItem = fixture()
    await epochItem.authority.provision()
    epochItem.root.driftEpoch()
    await expect(epochItem.authority.assertOutboundReady()).rejects.toBeInstanceOf(
      PaidMediaInstallationRootUnavailableError
    )
    expect(epochItem.authority.state.mode).toBe('fused')

    const evidenceItem = fixture()
    await evidenceItem.authority.provision()
    evidenceItem.setEvidence(evidence(99))
    await expect(evidenceItem.authority.assertOutboundReady()).rejects.toBeInstanceOf(
      PaidMediaInstallationRootUnavailableError
    )
    expect(evidenceItem.authority.state.mode).toBe('fused')
  })

  it('keeps the last exact ready proof across a transient Root read failure', async () => {
    const item = fixture()
    await item.authority.provision()
    const bytesBefore = new Map(item.atomicIO.files)
    item.root.failSnapshotTransient = true

    await expect(item.authority.assertOutboundReady()).rejects.toBeInstanceOf(
      PaidMediaInstallationRootUnavailableError
    )
    expect(item.authority.state.mode).toBe('ready')
    expect(item.atomicIO.files).toEqual(bytesBefore)

    item.root.failSnapshotTransient = false
    await expect(item.authority.assertOutboundReady()).resolves.toMatchObject({ mode: 'ready' })
  })

  it('never clears a fused pending receipt after the outbound proof fails once', async () => {
    const item = fixture()
    await item.authority.provision()

    await expect(
      item.authority.runMutation({ kind: 'dispatch_prepare' }, async (context) => {
        item.root.failSnapshotCount = 1
        await context.assertOutboundReady()
      })
    ).rejects.toBeInstanceOf(PaidMediaInstallationRootUnavailableError)

    expect(item.authority.state.mode).toBe('fused')
    expect(item.authority.inspectLocalDocumentForTests()?.pendingIntent).not.toBeNull()
  })

  it('does not rewrite or fuse an exact local document when startup Root read is transient', async () => {
    const item = fixture()
    await item.authority.provision()
    const restarted = fixture(item.root)
    for (const [path, value] of item.atomicIO.files) restarted.atomicIO.files.set(path, value)
    const bytesBefore = new Map(restarted.atomicIO.files)
    item.root.failSnapshotTransient = true

    await expect(restarted.authority.reconcileStartup()).rejects.toBeInstanceOf(
      PaidMediaInstallationRootUnavailableError
    )
    expect(restarted.authority.state.mode).toBe('detached')
    expect(restarted.atomicIO.files).toEqual(bytesBefore)

    item.root.failSnapshotTransient = false
    await expect(restarted.authority.reconcileStartup()).resolves.toMatchObject({ mode: 'ready' })
  })
})
