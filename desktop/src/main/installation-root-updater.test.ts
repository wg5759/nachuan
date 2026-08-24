import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it, vi } from 'vitest'

import {
  INSTALLATION_ROOT_SCHEMAS,
  InstallationRootBusinessError,
  InstallationRootClientError,
  type InstallationRootClient,
  type InstallationRootMutationEnvelope,
  type InstallationRootSnapshot,
  type InstallationRootSnapshotEnvelope,
  type InstallationRootUpdaterProof
} from './installation-root-client'
import {
  InstallationRootUpdaterAuthority,
  InstallationRootUpdaterError,
  installationRootUpdaterProofForState,
  parseInstallationRootUpdateState
} from './installation-root-updater'
import type { UpdateSecurityState } from './update-security'

const digest = (label: string): string => createHash('sha256').update(label).digest('hex')

const zero = '0'.repeat(64)
const installationId = digest('installation')
const componentIdentity = digest('component')

const stateOne: UpdateSecurityState = Object.freeze({
  schema: 2,
  sequence: 12,
  version: '1.2.0',
  artifactSha256: digest('artifact-12'),
  keyringSequence: 4,
  keyringSha256: digest('keyring-4')
})

const stateTwo: UpdateSecurityState = Object.freeze({
  schema: 2,
  sequence: 13,
  version: '1.3.0',
  artifactSha256: digest('artifact-13'),
  keyringSequence: 5,
  keyringSha256: digest('keyring-5')
})

const emptyProof: InstallationRootUpdaterProof = Object.freeze({
  releaseSequence: 0,
  keyringSequence: 0,
  artifactDigest: zero,
  stateDigest: zero
})

function snapshot(
  updater: InstallationRootUpdaterProof,
  overrides: Partial<InstallationRootSnapshot> = {}
): InstallationRootSnapshot {
  return Object.freeze({
    installationId,
    ownerSidDigest: digest('owner'),
    epoch: 3,
    rootRevision: 9,
    status: 'active',
    lockKind: 'none',
    lockReasonDigest: null,
    reanchorPending: false,
    reanchorOperationDigest: null,
    reanchorSnapshotDigest: null,
    reanchorSourceEpoch: null,
    principalDigest: digest('principal'),
    components: Object.freeze({
      desktop: Object.freeze({
        identity: componentIdentity,
        epoch: 3,
        bound: true,
        sequenceFloor: 0,
        stateDigest: digest('desktop-state'),
        recoveryFloor: null,
        recoveryStateDigest: null
      }),
      gateway: Object.freeze({
        identity: digest('gateway'),
        epoch: 3,
        bound: true,
        sequenceFloor: 0,
        stateDigest: digest('gateway-state'),
        recoveryFloor: null,
        recoveryStateDigest: null
      })
    }),
    updater,
    ...overrides
  })
}

function mutation(
  updater: InstallationRootUpdaterProof,
  overrides: Partial<InstallationRootSnapshot> = {},
  recovered = false
): InstallationRootMutationEnvelope {
  return Object.freeze({
    schema: INSTALLATION_ROOT_SCHEMAS.mutation,
    snapshot: snapshot(updater, overrides),
    applied: true,
    recovered
  })
}

function harness(initialState: UpdateSecurityState | null, initialRoot: InstallationRootUpdaterProof) {
  let local: UpdateSecurityState | null = initialState
  let root = initialRoot
  let revision = 9
  const order: string[] = []
  const snapshotCall = vi.fn(async (): Promise<InstallationRootSnapshotEnvelope> => ({
    schema: INSTALLATION_ROOT_SCHEMAS.snapshot,
    snapshot: snapshot(root, { rootRevision: revision })
  }))
  const verifyUpdater = vi.fn(async (request): Promise<InstallationRootMutationEnvelope> => {
    order.push('verify')
    root = Object.freeze({
      releaseSequence: request.releaseSequence,
      keyringSequence: request.keyringSequence,
      artifactDigest: request.artifactDigest,
      stateDigest: request.stateDigest
    })
    revision += 1
    return mutation(root, { rootRevision: revision }, true)
  })
  const advanceUpdater = vi.fn(async (request): Promise<InstallationRootMutationEnvelope> => {
    order.push('advance')
    root = Object.freeze({
      releaseSequence: request.nextReleaseSequence,
      keyringSequence: request.nextKeyringSequence,
      artifactDigest: request.nextArtifactDigest,
      stateDigest: request.nextStateDigest
    })
    revision += 1
    return mutation(root, { rootRevision: revision })
  })
  const writeState = vi.fn((state: UpdateSecurityState) => {
    order.push('write')
    local = state
  })
  const client = {
    snapshot: snapshotCall,
    verifyUpdater,
    advanceUpdater
  } as unknown as Pick<InstallationRootClient, 'snapshot' | 'verifyUpdater' | 'advanceUpdater'>
  const authority = new InstallationRootUpdaterAuthority({
    client,
    readState: () => local,
    writeState
  })
  return {
    authority,
    snapshotCall,
    verifyUpdater,
    advanceUpdater,
    writeState,
    order,
    root: () => root,
    local: () => local
  }
}

describe('installation-root updater state proof', () => {
  it('uses a deterministic domain-separated digest and binds keyring hash through stateDigest', () => {
    const proof = installationRootUpdaterProofForState(stateOne)
    expect(proof).toMatchObject({
      releaseSequence: 12,
      keyringSequence: 4,
      artifactDigest: stateOne.artifactSha256
    })
    expect(proof.stateDigest).toMatch(/^[0-9a-f]{64}$/)
    expect(
      installationRootUpdaterProofForState({ ...stateOne, keyringSha256: digest('different') })
        .stateDigest
    ).not.toBe(proof.stateDigest)
    expect(installationRootUpdaterProofForState(stateOne)).toEqual(proof)
  })

  it('accepts only exact canonical local updater states and reserves sequence zero', () => {
    expect(parseInstallationRootUpdateState(stateOne)).toEqual(stateOne)
    expect(parseInstallationRootUpdateState(null)).toBeNull()
    expect(() => parseInstallationRootUpdateState({ ...stateOne, extra: true })).toThrow(
      InstallationRootUpdaterError
    )
    expect(() =>
      installationRootUpdaterProofForState({
        schema: 1,
        sequence: 0,
        version: '1.0.0',
        artifactSha256: digest('sequence-zero')
      })
    ).toThrow(/sequence/i)
  })
})

describe('InstallationRootUpdaterAuthority', () => {
  it('is wired into packaged update check, commit, and install boundaries', () => {
    const source = readFileSync(join(__dirname, 'index.ts'), 'utf8')
    expect(source).toContain('const rootUpdater = new InstallationRootUpdaterAuthority({')
    expect(source).toContain('beforeCheck: () => rootUpdater.reconcile()')
    expect(source).toContain('commitState: (state) => rootUpdater.commit(state)')
    expect(source).toContain('beforeInstall: (state) => rootUpdater.assertReady(state)')
  })

  it('accepts the exact empty proof without mutating either authority', async () => {
    const value = harness(null, emptyProof)
    await value.authority.reconcile()
    expect(value.snapshotCall).toHaveBeenCalledTimes(1)
    expect(value.verifyUpdater).not.toHaveBeenCalled()
    expect(value.advanceUpdater).not.toHaveBeenCalled()
    expect(value.writeState).not.toHaveBeenCalled()
  })

  it('recovers exactly one local-first crash gap through verifyUpdater(previous)', async () => {
    const candidate = installationRootUpdaterProofForState(stateOne)
    const value = harness(stateOne, emptyProof)
    await value.authority.reconcile()
    expect(value.verifyUpdater).toHaveBeenCalledWith({
      installationId,
      epoch: 3,
      releaseSequence: candidate.releaseSequence,
      keyringSequence: candidate.keyringSequence,
      artifactDigest: candidate.artifactDigest,
      stateDigest: candidate.stateDigest,
      previous: emptyProof
    })
    expect(value.root()).toEqual(candidate)
  })

  it('fails closed without calling recovery when the root is ahead of local state', async () => {
    const root = installationRootUpdaterProofForState(stateTwo)
    const value = harness(stateOne, root)
    await expect(value.authority.reconcile()).rejects.toThrow(/conflicts/i)
    expect(value.verifyUpdater).not.toHaveBeenCalled()
    expect(value.advanceUpdater).not.toHaveBeenCalled()
  })

  it('writes the encrypted local floor before CAS and confirms the exact root response', async () => {
    const value = harness(null, emptyProof)
    await value.authority.commit(stateOne)
    const candidate = installationRootUpdaterProofForState(stateOne)
    expect(value.order).toEqual(['write', 'advance'])
    expect(value.advanceUpdater).toHaveBeenCalledWith({
      installationId,
      epoch: 3,
      expectedReleaseSequence: 0,
      expectedKeyringSequence: 0,
      expectedArtifactDigest: zero,
      expectedStateDigest: zero,
      nextReleaseSequence: candidate.releaseSequence,
      nextKeyringSequence: candidate.keyringSequence,
      nextArtifactDigest: candidate.artifactDigest,
      nextStateDigest: candidate.stateDigest,
      expectedRootRevision: 9
    })
    expect(value.local()).toEqual(stateOne)
    expect(value.root()).toEqual(candidate)
  })

  it('uses exact recovery only after an ambiguous transport failure', async () => {
    const value = harness(null, emptyProof)
    value.advanceUpdater.mockRejectedValueOnce(new InstallationRootClientError('lost response'))
    await value.authority.commit(stateOne)
    expect(value.order).toEqual(['write', 'verify'])
    expect(value.verifyUpdater).toHaveBeenCalledTimes(1)
  })

  it('does not reinterpret a signed business rejection as response loss', async () => {
    const value = harness(null, emptyProof)
    value.advanceUpdater.mockRejectedValueOnce(new InstallationRootBusinessError(409, 'conflict'))
    await expect(value.authority.commit(stateOne)).rejects.toBeInstanceOf(
      InstallationRootBusinessError
    )
    expect(value.verifyUpdater).not.toHaveBeenCalled()
  })

  it('rejects an advance response for another epoch or proof', async () => {
    const value = harness(null, emptyProof)
    value.advanceUpdater.mockResolvedValueOnce(
      mutation(installationRootUpdaterProofForState(stateTwo), { epoch: 4 })
    )
    await expect(value.authority.commit(stateOne)).rejects.toThrow(/does not confirm/i)
  })

  it('rechecks the root immediately before installation and detects drift', async () => {
    const proof = installationRootUpdaterProofForState(stateOne)
    const value = harness(stateOne, proof)
    await value.authority.assertReady(stateOne)
    expect(value.verifyUpdater).not.toHaveBeenCalled()

    const drifted = installationRootUpdaterProofForState(stateTwo)
    value.snapshotCall.mockResolvedValueOnce({
      schema: INSTALLATION_ROOT_SCHEMAS.snapshot,
      snapshot: snapshot(drifted, { rootRevision: 10 })
    })
    await expect(value.authority.assertReady(stateOne)).rejects.toThrow(/conflicts|changed/i)
  })

  it('never recovers an unexpected local floor under an older installation consent', async () => {
    const proof = installationRootUpdaterProofForState(stateOne)
    const value = harness(stateOne, proof)
    value.writeState(stateTwo)
    value.verifyUpdater.mockClear()

    await expect(value.authority.assertReady(stateOne)).rejects.toThrow(/changed/i)
    expect(value.verifyUpdater).not.toHaveBeenCalled()
    expect(value.root()).toEqual(proof)
  })

  it('rejects local proof drift while an installation recovery CAS is in flight', async () => {
    const candidate = installationRootUpdaterProofForState(stateOne)
    const value = harness(stateOne, emptyProof)
    value.verifyUpdater.mockImplementationOnce(async () => {
      value.writeState(stateTwo)
      return mutation(candidate, { rootRevision: 10 }, true)
    })

    await expect(value.authority.assertReady(stateOne)).rejects.toThrow(/local updater proof changed/i)
  })

  it('does not publish a committed updater floor after local state drifts during root CAS', async () => {
    const candidate = installationRootUpdaterProofForState(stateOne)
    const value = harness(null, emptyProof)
    value.advanceUpdater.mockImplementationOnce(async () => {
      value.writeState(stateTwo)
      return mutation(candidate, { rootRevision: 10 })
    })

    await expect(value.authority.commit(stateOne)).rejects.toThrow(/local updater proof changed/i)
    expect(value.local()).toEqual(stateTwo)
  })

  it('serializes concurrent commits so the second transition samples the first root CAS', async () => {
    const value = harness(null, emptyProof)
    await Promise.all([value.authority.commit(stateOne), value.authority.commit(stateTwo)])
    expect(value.order).toEqual(['write', 'advance', 'write', 'advance'])
    expect(value.root()).toEqual(installationRootUpdaterProofForState(stateTwo))
    expect(value.advanceUpdater).toHaveBeenCalledTimes(2)
  })
})
