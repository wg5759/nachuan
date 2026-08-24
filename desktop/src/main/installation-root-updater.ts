import { createHash } from 'node:crypto'

import {
  InstallationRootBusinessError,
  InstallationRootClientError,
  type InstallationRootClient,
  type InstallationRootMutationEnvelope,
  type InstallationRootSnapshot,
  type InstallationRootUpdaterProof
} from './installation-root-client'
import type { UpdateSecurityState } from './update-security'

const SHA256 = /^[0-9a-f]{64}$/
const STABLE_SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/
const ZERO_DIGEST = '0'.repeat(64)
const STATE_DIGEST_DOMAIN = Buffer.from(
  'nachuan.desktop.update-security-state.v1\0',
  'ascii'
)

type UpdaterRootClient = Pick<
  InstallationRootClient,
  'snapshot' | 'verifyUpdater' | 'advanceUpdater'
>

export interface InstallationRootUpdaterAuthorityDependencies {
  readonly client: UpdaterRootClient
  readonly readState: () => unknown
  readonly writeState: (state: UpdateSecurityState) => void
}

export class InstallationRootUpdaterError extends Error {
  override readonly name = 'InstallationRootUpdaterError'
}

interface ReconciledUpdaterState {
  readonly snapshot: InstallationRootSnapshot
  readonly state: UpdateSecurityState | null
  readonly proof: InstallationRootUpdaterProof
}

const INITIAL_PROOF: InstallationRootUpdaterProof = Object.freeze({
  releaseSequence: 0,
  keyringSequence: 0,
  artifactDigest: ZERO_DIGEST,
  stateDigest: ZERO_DIGEST
})

function fail(message: string, cause?: unknown): InstallationRootUpdaterError {
  return new InstallationRootUpdaterError(message, cause === undefined ? undefined : { cause })
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort()
  const wanted = [...expected].sort()
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index])
}

function counter(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) >= 0
}

function digest(value: unknown): value is string {
  return typeof value === 'string' && SHA256.test(value)
}

export function parseInstallationRootUpdateState(value: unknown): UpdateSecurityState | null {
  if (value === undefined || value === null) return null
  if (!isRecord(value) || (value.schema !== 1 && value.schema !== 2)) {
    throw fail('Local updater state is invalid')
  }
  const base = ['artifactSha256', 'schema', 'sequence', 'version'] as const
  const expected = value.schema === 1 ? base : [...base, 'keyringSequence', 'keyringSha256']
  if (
    !exactKeys(value, expected) ||
    !counter(value.sequence) ||
    typeof value.version !== 'string' ||
    !STABLE_SEMVER.test(value.version) ||
    !digest(value.artifactSha256) ||
    value.artifactSha256 === ZERO_DIGEST
  ) {
    throw fail('Local updater state is invalid')
  }
  if (value.schema === 1) {
    return Object.freeze({
      schema: 1,
      sequence: Number(value.sequence),
      version: value.version,
      artifactSha256: value.artifactSha256
    })
  }
  if (!counter(value.keyringSequence) || !digest(value.keyringSha256)) {
    throw fail('Local updater state is invalid')
  }
  return Object.freeze({
    schema: 2,
    sequence: Number(value.sequence),
    version: value.version,
    artifactSha256: value.artifactSha256,
    keyringSequence: Number(value.keyringSequence),
    keyringSha256: value.keyringSha256
  })
}

function canonicalState(state: UpdateSecurityState): string {
  if (state.schema === 1) {
    return JSON.stringify({
      schema: 1,
      sequence: state.sequence,
      version: state.version,
      artifactSha256: state.artifactSha256
    })
  }
  return JSON.stringify({
    schema: 2,
    sequence: state.sequence,
    version: state.version,
    artifactSha256: state.artifactSha256,
    keyringSequence: state.keyringSequence,
    keyringSha256: state.keyringSha256
  })
}

export function installationRootUpdaterProofForState(
  value: unknown
): InstallationRootUpdaterProof {
  const state = parseInstallationRootUpdateState(value)
  if (state === null) return INITIAL_PROOF
  // Installation Root deliberately reserves release sequence zero for its
  // empty proof. A real accepted artifact must therefore start at sequence 1.
  if (state.sequence < 1) throw fail('Local updater sequence cannot bind the empty root proof')
  return Object.freeze({
    releaseSequence: state.sequence,
    keyringSequence: state.schema === 2 ? state.keyringSequence : 0,
    artifactDigest: state.artifactSha256,
    stateDigest: createHash('sha256')
      .update(STATE_DIGEST_DOMAIN)
      .update(canonicalState(state), 'utf8')
      .digest('hex')
  })
}

function sameProof(a: InstallationRootUpdaterProof, b: InstallationRootUpdaterProof): boolean {
  return (
    a.releaseSequence === b.releaseSequence &&
    a.keyringSequence === b.keyringSequence &&
    a.artifactDigest === b.artifactDigest &&
    a.stateDigest === b.stateDigest
  )
}

function monotonicTransition(
  current: InstallationRootUpdaterProof,
  next: InstallationRootUpdaterProof
): boolean {
  if (
    next.releaseSequence < current.releaseSequence ||
    next.keyringSequence < current.keyringSequence ||
    (next.releaseSequence === current.releaseSequence &&
      next.keyringSequence === current.keyringSequence) ||
    next.stateDigest === ZERO_DIGEST ||
    next.stateDigest === current.stateDigest
  ) {
    return false
  }
  if (next.releaseSequence === current.releaseSequence) {
    return next.artifactDigest === current.artifactDigest
  }
  return next.artifactDigest !== ZERO_DIGEST && next.artifactDigest !== current.artifactDigest
}

function requireActiveSnapshot(snapshot: InstallationRootSnapshot): void {
  if (
    snapshot.status !== 'active' ||
    snapshot.lockKind !== 'none' ||
    snapshot.reanchorPending ||
    !digest(snapshot.installationId) ||
    snapshot.installationId === ZERO_DIGEST ||
    !Number.isSafeInteger(snapshot.epoch) ||
    snapshot.epoch < 1 ||
    !Number.isSafeInteger(snapshot.rootRevision) ||
    snapshot.rootRevision < 1
  ) {
    throw fail('Installation root is not active for updater authority')
  }
}

function requireMutationResult(
  result: InstallationRootMutationEnvelope,
  installationId: string,
  epoch: number,
  expected: InstallationRootUpdaterProof
): InstallationRootSnapshot {
  const snapshot = result.snapshot
  requireActiveSnapshot(snapshot)
  if (
    snapshot.installationId !== installationId ||
    snapshot.epoch !== epoch ||
    !sameProof(snapshot.updater, expected)
  ) {
    throw fail('Installation root updater response does not confirm the requested proof')
  }
  return snapshot
}

/**
 * Serializes the encrypted Desktop update floor with the Installation Root.
 *
 * The local state is committed first. If the process dies before the root CAS,
 * the next reconciliation can close exactly that one locally proven gap via
 * ``verifyUpdater(previous=...)``. No installer becomes ready until the root
 * confirms the same proof, and installation performs another fresh reconcile.
 */
export class InstallationRootUpdaterAuthority {
  private tail: Promise<void> = Promise.resolve()

  constructor(private readonly dependencies: InstallationRootUpdaterAuthorityDependencies) {
    if (
      !dependencies ||
      !dependencies.client ||
      typeof dependencies.client.snapshot !== 'function' ||
      typeof dependencies.client.verifyUpdater !== 'function' ||
      typeof dependencies.client.advanceUpdater !== 'function' ||
      typeof dependencies.readState !== 'function' ||
      typeof dependencies.writeState !== 'function'
    ) {
      throw fail('Installation root updater dependencies are unavailable')
    }
  }

  private serialize<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.tail.then(operation, operation)
    this.tail = result.then(
      () => undefined,
      () => undefined
    )
    return result
  }

  reconcile(): Promise<void> {
    return this.serialize(async () => {
      await this.reconcileUnlocked()
    })
  }

  commit(value: UpdateSecurityState): Promise<void> {
    return this.serialize(async () => {
      const state = parseInstallationRootUpdateState(value)
      if (state === null) throw fail('A verified updater state is required')
      const candidate = installationRootUpdaterProofForState(state)
      const current = await this.reconcileUnlocked()
      if (sameProof(current.proof, candidate)) return
      if (!monotonicTransition(current.proof, candidate)) {
        throw fail('Verified updater state is not monotonic with the Installation Root')
      }

      // One encrypted atomic config write is the local commit. Root recovery is
      // allowed only from the exact proof sampled immediately before this write.
      this.dependencies.writeState(state)
      let result: InstallationRootMutationEnvelope
      try {
        result = await this.dependencies.client.advanceUpdater({
          installationId: current.snapshot.installationId,
          epoch: current.snapshot.epoch,
          expectedReleaseSequence: current.proof.releaseSequence,
          expectedKeyringSequence: current.proof.keyringSequence,
          expectedArtifactDigest: current.proof.artifactDigest,
          expectedStateDigest: current.proof.stateDigest,
          nextReleaseSequence: candidate.releaseSequence,
          nextKeyringSequence: candidate.keyringSequence,
          nextArtifactDigest: candidate.artifactDigest,
          nextStateDigest: candidate.stateDigest,
          expectedRootRevision: current.snapshot.rootRevision
        })
      } catch (error) {
        if (error instanceof InstallationRootBusinessError) throw error
        if (!(error instanceof InstallationRootClientError)) throw error
        // Transport/session failure is ambiguous: the root CAS may have
        // committed. The recovery endpoint accepts only exact previous->next.
        result = await this.dependencies.client.verifyUpdater({
          installationId: current.snapshot.installationId,
          epoch: current.snapshot.epoch,
          releaseSequence: candidate.releaseSequence,
          keyringSequence: candidate.keyringSequence,
          artifactDigest: candidate.artifactDigest,
          stateDigest: candidate.stateDigest,
          previous: current.proof
        })
      }
      requireMutationResult(
        result,
        current.snapshot.installationId,
        current.snapshot.epoch,
        candidate
      )
      this.requireLocalProof(candidate)
    })
  }

  assertReady(value?: UpdateSecurityState): Promise<void> {
    return this.serialize(async () => {
      const expected =
        value === undefined ? undefined : installationRootUpdaterProofForState(value)
      const current = await this.reconcileUnlocked(expected)
      if (expected !== undefined && !sameProof(current.proof, expected)) {
        throw fail('Installation root updater proof changed before installation')
      }
    })
  }

  private async reconcileUnlocked(
    requiredLocalProof?: InstallationRootUpdaterProof
  ): Promise<ReconciledUpdaterState> {
    const envelope = await this.dependencies.client.snapshot()
    const snapshot = envelope.snapshot
    requireActiveSnapshot(snapshot)
    const state = parseInstallationRootUpdateState(this.dependencies.readState())
    const local = installationRootUpdaterProofForState(state)
    if (requiredLocalProof !== undefined && !sameProof(local, requiredLocalProof)) {
      // Installation consent is bound to the state that was downloaded and
      // attested. Never recover a different local floor merely because it is
      // monotonic: that would advance Root before rejecting the pending item.
      throw fail('Local updater proof changed before installation')
    }
    const root = snapshot.updater
    if (sameProof(local, root)) {
      return Object.freeze({ snapshot, state, proof: local })
    }
    if (state === null || !monotonicTransition(root, local)) {
      throw fail('Local updater state conflicts with the Installation Root')
    }
    const recovered = await this.dependencies.client.verifyUpdater({
      installationId: snapshot.installationId,
      epoch: snapshot.epoch,
      releaseSequence: local.releaseSequence,
      keyringSequence: local.keyringSequence,
      artifactDigest: local.artifactDigest,
      stateDigest: local.stateDigest,
      previous: root
    })
    const recoveredSnapshot = requireMutationResult(
      recovered,
      snapshot.installationId,
      snapshot.epoch,
      local
    )
    const confirmedState = this.requireLocalProof(local)
    return Object.freeze({ snapshot: recoveredSnapshot, state: confirmedState, proof: local })
  }

  private requireLocalProof(expected: InstallationRootUpdaterProof): UpdateSecurityState | null {
    const state = parseInstallationRootUpdateState(this.dependencies.readState())
    const proof = installationRootUpdaterProofForState(state)
    if (!sameProof(proof, expected)) {
      // Root mutation is already durable and must never be rolled back here.
      // Leave the mismatch visible so a later reconciliation can either prove
      // an exact monotonic recovery or reject the conflicting local state.
      throw fail('Local updater proof changed during Installation Root confirmation')
    }
    return state
  }
}
