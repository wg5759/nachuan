import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import * as http from 'node:http'

const PROTOCOL_VERSION = '1'
const REQUEST_DOMAIN = Buffer.from('nachuan.installation-root.internal.request.v1', 'ascii')
const RESPONSE_DOMAIN = Buffer.from('nachuan.installation-root.internal.response.v1', 'ascii')
const ROOT_HEADER_PREFIX = 'x-nachuan-root-'
const HEX_32_PATTERN = /^[0-9a-f]{64}$/
const METHOD_PATTERN = /^[A-Z]+$/
const TIMESTAMP_PATTERN = /^[1-9][0-9]{12,15}$/
const JSON_BYTE_LIMIT = 64 * 1024
const DEFAULT_TIMEOUT_MS = 2_000

const HEADER_VERSION = 'X-Nachuan-Root-Protocol'
const HEADER_TIMESTAMP_MS = 'X-Nachuan-Root-Timestamp-Ms'
const HEADER_NONCE = 'X-Nachuan-Root-Nonce'
const HEADER_BODY_SHA256 = 'X-Nachuan-Root-Body-SHA256'
const HEADER_SIGNATURE = 'X-Nachuan-Root-Signature'
const HEADER_RESPONSE_REQUEST_NONCE = 'X-Nachuan-Root-Request-Nonce'
const HEADER_RESPONSE_BODY_SHA256 = 'X-Nachuan-Root-Response-Body-SHA256'
const HEADER_RESPONSE_SIGNATURE = 'X-Nachuan-Root-Response-Signature'

const RESPONSE_SECURITY_HEADERS = [
  HEADER_VERSION,
  HEADER_RESPONSE_REQUEST_NONCE,
  HEADER_RESPONSE_BODY_SHA256,
  HEADER_RESPONSE_SIGNATURE
] as const

export const INSTALLATION_ROOT_PATHS = Object.freeze({
  snapshot: '/internal/v1/installation-root/snapshot',
  desktopBind: '/internal/v1/installation-root/components/desktop/bind',
  desktopVerify: '/internal/v1/installation-root/components/desktop/verify',
  desktopAdvance: '/internal/v1/installation-root/components/desktop/advance',
  desktopRecoveryAck: '/internal/v1/installation-root/components/desktop/recovery/ack',
  updaterVerify: '/internal/v1/installation-root/updater/verify',
  updaterAdvance: '/internal/v1/installation-root/updater/advance'
} as const)

export type InstallationRootPath =
  (typeof INSTALLATION_ROOT_PATHS)[keyof typeof INSTALLATION_ROOT_PATHS]
export type InstallationRootMethod = 'GET' | 'POST'

const ALLOWED_ROUTES = new Map<InstallationRootPath, InstallationRootMethod>([
  [INSTALLATION_ROOT_PATHS.snapshot, 'GET'],
  [INSTALLATION_ROOT_PATHS.desktopBind, 'POST'],
  [INSTALLATION_ROOT_PATHS.desktopVerify, 'POST'],
  [INSTALLATION_ROOT_PATHS.desktopAdvance, 'POST'],
  [INSTALLATION_ROOT_PATHS.desktopRecoveryAck, 'POST'],
  [INSTALLATION_ROOT_PATHS.updaterVerify, 'POST'],
  [INSTALLATION_ROOT_PATHS.updaterAdvance, 'POST']
])

export class InstallationRootClientError extends Error {
  override readonly name: string = 'InstallationRootClientError'
}

export interface InstallationRootSignedRequest {
  readonly headers: Readonly<Record<string, string>>
  readonly timestampMs: number
  readonly nonce: string
  readonly bodySha256: string
}

export interface InstallationRootRequestSigningInput {
  readonly bootToken: string
  readonly method: string
  readonly path: string
  readonly body?: Uint8Array
  readonly timestampMs?: number
  readonly nonce?: string
}

export interface InstallationRootResponseVerificationInput {
  readonly bootToken: string
  readonly requestNonce: string
  readonly status: number
  readonly rawHeaders: readonly string[]
  readonly body: Uint8Array
}

export interface InstallationRootVerifiedResponse {
  readonly requestNonce: string
  readonly bodySha256: string
}

export interface InstallationRootEngineSession {
  readonly generation: number
  readonly pid: number
  readonly port: number
  readonly bootToken: string
}

export type InstallationRootSessionSupplier = () => InstallationRootEngineSession | null

export interface InstallationRootClientDependencies {
  readonly session: InstallationRootSessionSupplier
  readonly timeoutMs?: number
}

export interface InstallationRootCallOptions {
  readonly signal?: AbortSignal
}

export interface InstallationRootSignedJsonCall extends InstallationRootCallOptions {
  readonly method: InstallationRootMethod
  readonly path: InstallationRootPath
  readonly body?: Readonly<Record<string, unknown>>
}

export interface InstallationRootJsonResponse {
  readonly status: number
  readonly body: Readonly<Record<string, unknown>>
}

export const INSTALLATION_ROOT_SCHEMAS = Object.freeze({
  snapshot: 'nachuan.installation-root.snapshot.v1',
  mutation: 'nachuan.installation-root.mutation.v1',
  error: 'nachuan.installation-root.error.v1'
} as const)

export const INSTALLATION_ROOT_ERROR_CODES = Object.freeze([
  'invalid_request',
  'authentication_failed',
  'replay_rejected',
  'root_unavailable',
  'root_locked',
  'conflict',
  'internal_error'
] as const)

export type InstallationRootErrorCode = (typeof INSTALLATION_ROOT_ERROR_CODES)[number]
export type InstallationRootStatus =
  | 'provisioning'
  | 'active'
  | 'maintenance_locked'
  | 'retired'
export type InstallationRootLockKind =
  | 'none'
  | 'operator'
  | 'integrity'
  | 'reanchor'
  | 'retired'

export type InstallationRootDesktopBindRequest = Readonly<{
  installationId: string
  epoch: number
  identity: string
  stateDigest: string
  expectedRootRevision: number
  sequenceFloor: number
}>

export type InstallationRootDesktopVerifyRequest = Readonly<{
  installationId: string
  epoch: number
  identity: string
  sequenceFloor: number
  stateDigest: string
  previousStateDigest: string | null
}>

export type InstallationRootDesktopAdvanceRequest = Readonly<{
  installationId: string
  epoch: number
  identity: string
  expectedFloor: number
  expectedStateDigest: string
  nextFloor: number
  nextStateDigest: string
  expectedRootRevision: number
}>

export type InstallationRootDesktopRecoveryAckRequest = Readonly<{
  installationId: string
  epoch: number
  identity: string
  recoveryFloor: number
  recoveryStateDigest: string
  nextFloor: number
  nextStateDigest: string
  expectedRootRevision: number
}>

export type InstallationRootUpdaterProof = Readonly<{
  releaseSequence: number
  keyringSequence: number
  artifactDigest: string
  stateDigest: string
}>

export type InstallationRootUpdaterVerifyRequest = Readonly<{
  installationId: string
  epoch: number
  releaseSequence: number
  keyringSequence: number
  artifactDigest: string
  stateDigest: string
  previous: InstallationRootUpdaterProof | null
}>

export type InstallationRootUpdaterAdvanceRequest = Readonly<{
  installationId: string
  epoch: number
  expectedReleaseSequence: number
  expectedKeyringSequence: number
  expectedArtifactDigest: string
  expectedStateDigest: string
  nextReleaseSequence: number
  nextKeyringSequence: number
  nextArtifactDigest: string
  nextStateDigest: string
  expectedRootRevision: number
}>

export type InstallationRootMutationRequest =
  | InstallationRootDesktopBindRequest
  | InstallationRootDesktopVerifyRequest
  | InstallationRootDesktopAdvanceRequest
  | InstallationRootDesktopRecoveryAckRequest
  | InstallationRootUpdaterVerifyRequest
  | InstallationRootUpdaterAdvanceRequest

export type InstallationRootComponentSnapshot = Readonly<{
  identity: string
  epoch: number
  bound: boolean
  sequenceFloor: number
  stateDigest: string | null
  recoveryFloor: number | null
  recoveryStateDigest: string | null
}>

export type InstallationRootUpdaterSnapshot = InstallationRootUpdaterProof

export type InstallationRootSnapshot = Readonly<{
  installationId: string
  ownerSidDigest: string
  epoch: number
  rootRevision: number
  status: InstallationRootStatus
  lockKind: InstallationRootLockKind
  lockReasonDigest: string | null
  reanchorPending: boolean
  reanchorOperationDigest: string | null
  reanchorSnapshotDigest: string | null
  reanchorSourceEpoch: number | null
  principalDigest: string
  components: Readonly<{
    desktop: InstallationRootComponentSnapshot
    gateway: InstallationRootComponentSnapshot
  }>
  updater: InstallationRootUpdaterSnapshot
}>

export type InstallationRootSnapshotEnvelope = Readonly<{
  schema: typeof INSTALLATION_ROOT_SCHEMAS.snapshot
  snapshot: InstallationRootSnapshot
}>

export type InstallationRootMutationEnvelope = Readonly<{
  schema: typeof INSTALLATION_ROOT_SCHEMAS.mutation
  snapshot: InstallationRootSnapshot
  applied: boolean
  recovered: boolean
}>

export class InstallationRootBusinessError extends InstallationRootClientError {
  override readonly name = 'InstallationRootBusinessError'

  constructor(
    readonly status: number,
    readonly code: InstallationRootErrorCode
  ) {
    super(`Installation root business request failed (${code}, HTTP ${status})`)
  }
}

function protocolError(message: string): InstallationRootClientError {
  return new InstallationRootClientError(message)
}

function hex32(value: unknown, label: string): Buffer {
  if (typeof value !== 'string' || !HEX_32_PATTERN.test(value)) {
    throw protocolError(`Invalid installation root ${label}`)
  }
  return Buffer.from(value, 'hex')
}

function bootKey(bootToken: unknown): Buffer {
  return hex32(bootToken, 'boot authority')
}

function validatedMethod(method: unknown): string {
  if (typeof method !== 'string' || !METHOD_PATTERN.test(method)) {
    throw protocolError('Invalid installation root method')
  }
  return method
}

function validatedPath(path: unknown): string {
  if (
    typeof path !== 'string' ||
    !path.startsWith('/') ||
    path.includes('?') ||
    path.includes('#') ||
    path.includes('\\') ||
    /[^\x20-\x7e]/.test(path)
  ) {
    throw protocolError('Invalid installation root path')
  }
  return path
}

function validatedTimestamp(timestampMs: unknown): number {
  if (
    typeof timestampMs !== 'number' ||
    !Number.isSafeInteger(timestampMs) ||
    timestampMs < 0 ||
    !TIMESTAMP_PATTERN.test(String(timestampMs))
  ) {
    throw protocolError('Invalid installation root timestamp')
  }
  return timestampMs
}

function unsigned32(value: number): Buffer {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw protocolError('Invalid installation root unsigned integer')
  }
  const output = Buffer.allocUnsafe(4)
  output.writeUInt32BE(value)
  return output
}

function unsigned64(value: number): Buffer {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw protocolError('Invalid installation root unsigned integer')
  }
  const output = Buffer.allocUnsafe(8)
  output.writeBigUInt64BE(BigInt(value))
  return output
}

function frame(domain: Buffer, fields: readonly Buffer[]): Buffer {
  const parts: Buffer[] = [unsigned32(domain.byteLength), domain, unsigned32(fields.length)]
  for (const field of fields) {
    parts.push(unsigned64(field.byteLength), field)
  }
  return Buffer.concat(parts)
}

function requestMacInput(input: {
  timestampMs: number
  nonce: string
  method: string
  path: string
  bodySha256: string
}): Buffer {
  return frame(REQUEST_DOMAIN, [
    unsigned64(validatedTimestamp(input.timestampMs)),
    hex32(input.nonce, 'nonce'),
    Buffer.from(validatedMethod(input.method), 'ascii'),
    Buffer.from(validatedPath(input.path), 'ascii'),
    hex32(input.bodySha256, 'request body digest')
  ])
}

function responseMacInput(input: {
  requestNonce: string
  status: number
  bodySha256: string
}): Buffer {
  if (!Number.isSafeInteger(input.status) || input.status < 100 || input.status > 599) {
    throw protocolError('Invalid installation root response status')
  }
  return frame(RESPONSE_DOMAIN, [
    hex32(input.requestNonce, 'request nonce'),
    unsigned32(input.status),
    hex32(input.bodySha256, 'response body digest')
  ])
}

function exactHexEqual(left: string, right: string): boolean {
  if (!HEX_32_PATTERN.test(left) || !HEX_32_PATTERN.test(right)) return false
  return timingSafeEqual(Buffer.from(left, 'hex'), Buffer.from(right, 'hex'))
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value)
}

type SchemaKind = 'request' | 'response'

function schemaFailure(kind: SchemaKind): InstallationRootClientError {
  return protocolError(`Installation root ${kind} schema is invalid`)
}

function exactRecord(
  value: unknown,
  keys: readonly string[],
  kind: SchemaKind
): Record<string, unknown> {
  if (!isRecord(value)) throw schemaFailure(kind)
  const actual = Object.keys(value).sort()
  const expected = [...keys].sort()
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  ) {
    throw schemaFailure(kind)
  }
  return value
}

function schemaCounter(value: unknown, minimum: number, kind: SchemaKind): number {
  if (!Number.isSafeInteger(value) || Number(value) < minimum) throw schemaFailure(kind)
  return Number(value)
}

function schemaDigest(
  value: unknown,
  kind: SchemaKind,
  allowZero = true
): string {
  if (typeof value !== 'string' || !HEX_32_PATTERN.test(value)) throw schemaFailure(kind)
  if (!allowZero && value === '0'.repeat(64)) throw schemaFailure(kind)
  return value
}

function nullableDigest(value: unknown, kind: SchemaKind): string | null {
  return value === null ? null : schemaDigest(value, kind)
}

function nullableCounter(value: unknown, minimum: number, kind: SchemaKind): number | null {
  return value === null ? null : schemaCounter(value, minimum, kind)
}

function schemaBoolean(value: unknown, kind: SchemaKind): boolean {
  if (typeof value !== 'boolean') throw schemaFailure(kind)
  return value
}

function schemaEnum<const T extends readonly string[]>(
  value: unknown,
  allowed: T,
  kind: SchemaKind
): T[number] {
  if (typeof value !== 'string' || !allowed.includes(value)) throw schemaFailure(kind)
  return value as T[number]
}

const UPDATER_PROOF_KEYS = [
  'releaseSequence',
  'keyringSequence',
  'artifactDigest',
  'stateDigest'
] as const

function parseUpdaterProof(value: unknown, kind: SchemaKind): InstallationRootUpdaterProof {
  const record = exactRecord(value, UPDATER_PROOF_KEYS, kind)
  return Object.freeze({
    releaseSequence: schemaCounter(record.releaseSequence, 0, kind),
    keyringSequence: schemaCounter(record.keyringSequence, 0, kind),
    artifactDigest: schemaDigest(record.artifactDigest, kind),
    stateDigest: schemaDigest(record.stateDigest, kind)
  })
}

function updaterTransitionIsMonotonic(
  expected: InstallationRootUpdaterProof,
  next: InstallationRootUpdaterProof
): boolean {
  if (
    next.releaseSequence < expected.releaseSequence ||
    next.keyringSequence < expected.keyringSequence ||
    (next.releaseSequence === expected.releaseSequence &&
      next.keyringSequence === expected.keyringSequence) ||
    next.stateDigest === '0'.repeat(64) ||
    next.stateDigest === expected.stateDigest
  ) {
    return false
  }
  if (next.releaseSequence === expected.releaseSequence) {
    return next.artifactDigest === expected.artifactDigest
  }
  return (
    next.artifactDigest !== '0'.repeat(64) &&
    next.artifactDigest !== expected.artifactDigest
  )
}

function updaterProofIsStructurallyConsistent(value: InstallationRootUpdaterProof): boolean {
  const zero = '0'.repeat(64)
  return (
    (value.releaseSequence === 0) === (value.artifactDigest === zero) &&
    (value.stateDigest === zero) ===
      (value.releaseSequence === 0 && value.keyringSequence === 0)
  )
}

export function validateInstallationRootRequest(
  path: InstallationRootPath,
  value: unknown
): InstallationRootMutationRequest {
  const kind: SchemaKind = 'request'
  if (path === INSTALLATION_ROOT_PATHS.desktopBind) {
    const record = exactRecord(
      value,
      [
        'installationId',
        'epoch',
        'identity',
        'stateDigest',
        'expectedRootRevision',
        'sequenceFloor'
      ],
      kind
    )
    return Object.freeze({
      installationId: schemaDigest(record.installationId, kind, false),
      epoch: schemaCounter(record.epoch, 1, kind),
      identity: schemaDigest(record.identity, kind, false),
      stateDigest: schemaDigest(record.stateDigest, kind, false),
      expectedRootRevision: schemaCounter(record.expectedRootRevision, 1, kind),
      sequenceFloor: schemaCounter(record.sequenceFloor, 0, kind)
    })
  }
  if (path === INSTALLATION_ROOT_PATHS.desktopVerify) {
    const record = exactRecord(
      value,
      [
        'installationId',
        'epoch',
        'identity',
        'sequenceFloor',
        'stateDigest',
        'previousStateDigest'
      ],
      kind
    )
    return Object.freeze({
      installationId: schemaDigest(record.installationId, kind, false),
      epoch: schemaCounter(record.epoch, 1, kind),
      identity: schemaDigest(record.identity, kind, false),
      sequenceFloor: schemaCounter(record.sequenceFloor, 0, kind),
      stateDigest: schemaDigest(record.stateDigest, kind, false),
      previousStateDigest:
        record.previousStateDigest === null
          ? null
          : schemaDigest(record.previousStateDigest, kind, false)
    })
  }
  if (path === INSTALLATION_ROOT_PATHS.desktopAdvance) {
    const record = exactRecord(
      value,
      [
        'installationId',
        'epoch',
        'identity',
        'expectedFloor',
        'expectedStateDigest',
        'nextFloor',
        'nextStateDigest',
        'expectedRootRevision'
      ],
      kind
    )
    const expectedFloor = schemaCounter(record.expectedFloor, 0, kind)
    const nextFloor = schemaCounter(record.nextFloor, 0, kind)
    const expectedStateDigest = schemaDigest(record.expectedStateDigest, kind, false)
    const nextStateDigest = schemaDigest(record.nextStateDigest, kind, false)
    if (nextFloor !== expectedFloor + 1 || nextStateDigest === expectedStateDigest) {
      throw schemaFailure(kind)
    }
    return Object.freeze({
      installationId: schemaDigest(record.installationId, kind, false),
      epoch: schemaCounter(record.epoch, 1, kind),
      identity: schemaDigest(record.identity, kind, false),
      expectedFloor,
      expectedStateDigest,
      nextFloor,
      nextStateDigest,
      expectedRootRevision: schemaCounter(record.expectedRootRevision, 1, kind)
    })
  }
  if (path === INSTALLATION_ROOT_PATHS.desktopRecoveryAck) {
    const record = exactRecord(
      value,
      [
        'installationId',
        'epoch',
        'identity',
        'recoveryFloor',
        'recoveryStateDigest',
        'nextFloor',
        'nextStateDigest',
        'expectedRootRevision'
      ],
      kind
    )
    const recoveryFloor = schemaCounter(record.recoveryFloor, 0, kind)
    const nextFloor = schemaCounter(record.nextFloor, 0, kind)
    const recoveryStateDigest = schemaDigest(record.recoveryStateDigest, kind, false)
    const nextStateDigest = schemaDigest(record.nextStateDigest, kind, false)
    if (nextFloor !== recoveryFloor + 1 || nextStateDigest === recoveryStateDigest) {
      throw schemaFailure(kind)
    }
    return Object.freeze({
      installationId: schemaDigest(record.installationId, kind, false),
      epoch: schemaCounter(record.epoch, 1, kind),
      identity: schemaDigest(record.identity, kind, false),
      recoveryFloor,
      recoveryStateDigest,
      nextFloor,
      nextStateDigest,
      expectedRootRevision: schemaCounter(record.expectedRootRevision, 1, kind)
    })
  }
  if (path === INSTALLATION_ROOT_PATHS.updaterVerify) {
    const record = exactRecord(
      value,
      [
        'installationId',
        'epoch',
        'releaseSequence',
        'keyringSequence',
        'artifactDigest',
        'stateDigest',
        'previous'
      ],
      kind
    )
    const candidate = Object.freeze({
      installationId: schemaDigest(record.installationId, kind, false),
      epoch: schemaCounter(record.epoch, 1, kind),
      releaseSequence: schemaCounter(record.releaseSequence, 0, kind),
      keyringSequence: schemaCounter(record.keyringSequence, 0, kind),
      artifactDigest: schemaDigest(record.artifactDigest, kind),
      stateDigest: schemaDigest(record.stateDigest, kind),
      previous: record.previous === null ? null : parseUpdaterProof(record.previous, kind)
    })
    if (
      !updaterProofIsStructurallyConsistent(candidate) ||
      (candidate.previous !== null &&
        !updaterProofIsStructurallyConsistent(candidate.previous))
    ) {
      throw schemaFailure(kind)
    }
    return candidate
  }
  if (path === INSTALLATION_ROOT_PATHS.updaterAdvance) {
    const record = exactRecord(
      value,
      [
        'installationId',
        'epoch',
        'expectedReleaseSequence',
        'expectedKeyringSequence',
        'expectedArtifactDigest',
        'expectedStateDigest',
        'nextReleaseSequence',
        'nextKeyringSequence',
        'nextArtifactDigest',
        'nextStateDigest',
        'expectedRootRevision'
      ],
      kind
    )
    const expected = parseUpdaterProof(
      {
        releaseSequence: record.expectedReleaseSequence,
        keyringSequence: record.expectedKeyringSequence,
        artifactDigest: record.expectedArtifactDigest,
        stateDigest: record.expectedStateDigest
      },
      kind
    )
    const next = parseUpdaterProof(
      {
        releaseSequence: record.nextReleaseSequence,
        keyringSequence: record.nextKeyringSequence,
        artifactDigest: record.nextArtifactDigest,
        stateDigest: record.nextStateDigest
      },
      kind
    )
    if (
      !updaterProofIsStructurallyConsistent(expected) ||
      !updaterProofIsStructurallyConsistent(next) ||
      !updaterTransitionIsMonotonic(expected, next)
    ) {
      throw schemaFailure(kind)
    }
    return Object.freeze({
      installationId: schemaDigest(record.installationId, kind, false),
      epoch: schemaCounter(record.epoch, 1, kind),
      expectedReleaseSequence: expected.releaseSequence,
      expectedKeyringSequence: expected.keyringSequence,
      expectedArtifactDigest: expected.artifactDigest,
      expectedStateDigest: expected.stateDigest,
      nextReleaseSequence: next.releaseSequence,
      nextKeyringSequence: next.keyringSequence,
      nextArtifactDigest: next.artifactDigest,
      nextStateDigest: next.stateDigest,
      expectedRootRevision: schemaCounter(record.expectedRootRevision, 1, kind)
    })
  }
  throw schemaFailure(kind)
}

const COMPONENT_SNAPSHOT_KEYS = [
  'identity',
  'epoch',
  'bound',
  'sequenceFloor',
  'stateDigest',
  'recoveryFloor',
  'recoveryStateDigest'
] as const

function parseComponentSnapshot(
  value: unknown,
  rootEpoch: number
): InstallationRootComponentSnapshot {
  const kind: SchemaKind = 'response'
  const record = exactRecord(value, COMPONENT_SNAPSHOT_KEYS, kind)
  const component = Object.freeze({
    identity: schemaDigest(record.identity, kind, false),
    epoch: schemaCounter(record.epoch, 1, kind),
    bound: schemaBoolean(record.bound, kind),
    sequenceFloor: schemaCounter(record.sequenceFloor, 0, kind),
    stateDigest: nullableDigest(record.stateDigest, kind),
    recoveryFloor: nullableCounter(record.recoveryFloor, 0, kind),
    recoveryStateDigest: nullableDigest(record.recoveryStateDigest, kind)
  })
  if (component.epoch !== rootEpoch) throw schemaFailure(kind)
  if (!component.bound) {
    if (
      component.sequenceFloor !== 0 ||
      component.stateDigest !== null ||
      component.recoveryFloor !== null ||
      component.recoveryStateDigest !== null
    ) {
      throw schemaFailure(kind)
    }
  } else if (
    component.stateDigest === null ||
    component.stateDigest === '0'.repeat(64) ||
    (component.recoveryFloor === null) !== (component.recoveryStateDigest === null) ||
    (component.recoveryFloor !== null &&
      (component.recoveryFloor !== component.sequenceFloor ||
        component.recoveryStateDigest !== component.stateDigest))
  ) {
    throw schemaFailure(kind)
  }
  return component
}

const SNAPSHOT_KEYS = [
  'installationId',
  'ownerSidDigest',
  'epoch',
  'rootRevision',
  'status',
  'lockKind',
  'lockReasonDigest',
  'reanchorPending',
  'reanchorOperationDigest',
  'reanchorSnapshotDigest',
  'reanchorSourceEpoch',
  'principalDigest',
  'components',
  'updater'
] as const

function parseInstallationRootSnapshot(value: unknown): InstallationRootSnapshot {
  const kind: SchemaKind = 'response'
  const record = exactRecord(value, SNAPSHOT_KEYS, kind)
  const epoch = schemaCounter(record.epoch, 1, kind)
  const componentsRecord = exactRecord(record.components, ['desktop', 'gateway'], kind)
  const components = Object.freeze({
    desktop: parseComponentSnapshot(componentsRecord.desktop, epoch),
    gateway: parseComponentSnapshot(componentsRecord.gateway, epoch)
  })
  const updater = parseUpdaterProof(record.updater, kind)
  if (!updaterProofIsStructurallyConsistent(updater)) {
    throw schemaFailure(kind)
  }
  const status = schemaEnum(
    record.status,
    ['provisioning', 'active', 'maintenance_locked', 'retired'] as const,
    kind
  )
  const lockKind = schemaEnum(
    record.lockKind,
    ['none', 'operator', 'integrity', 'reanchor', 'retired'] as const,
    kind
  )
  const lockReasonDigest = nullableDigest(record.lockReasonDigest, kind)
  const reanchorPending = schemaBoolean(record.reanchorPending, kind)
  const reanchorOperationDigest = nullableDigest(record.reanchorOperationDigest, kind)
  const reanchorSnapshotDigest = nullableDigest(record.reanchorSnapshotDigest, kind)
  const reanchorSourceEpoch = nullableCounter(record.reanchorSourceEpoch, 1, kind)
  const reanchorTriplePresent =
    reanchorOperationDigest !== null &&
    reanchorSnapshotDigest !== null &&
    reanchorSourceEpoch !== null
  const reanchorTripleAbsent =
    reanchorOperationDigest === null &&
    reanchorSnapshotDigest === null &&
    reanchorSourceEpoch === null
  if (
    (status === 'provisioning' &&
      (lockKind !== 'none' ||
        lockReasonDigest !== null ||
        reanchorPending ||
        !reanchorTripleAbsent)) ||
    (status === 'active' &&
      (lockKind !== 'none' ||
        lockReasonDigest !== null ||
        reanchorPending ||
        (!reanchorTripleAbsent &&
          (!reanchorTriplePresent || epoch !== Number(reanchorSourceEpoch) + 1)))) ||
    (status === 'maintenance_locked' &&
      !(
        ((lockKind === 'operator' || lockKind === 'integrity') &&
          !reanchorPending &&
          reanchorTripleAbsent) ||
        (lockKind === 'reanchor' &&
          lockReasonDigest !== null &&
          reanchorPending &&
          reanchorTriplePresent &&
          epoch === Number(reanchorSourceEpoch) + 1)
      )) ||
    (status === 'retired' &&
      (lockKind !== 'retired' ||
        lockReasonDigest === null ||
        reanchorPending ||
        !reanchorTripleAbsent)) ||
    (status === 'active' && (!components.desktop.bound || !components.gateway.bound)) ||
    (status === 'provisioning' && components.desktop.bound && components.gateway.bound)
  ) {
    throw schemaFailure(kind)
  }
  return Object.freeze({
    installationId: schemaDigest(record.installationId, kind, false),
    ownerSidDigest: schemaDigest(record.ownerSidDigest, kind),
    epoch,
    rootRevision: schemaCounter(record.rootRevision, 1, kind),
    status,
    lockKind,
    lockReasonDigest,
    reanchorPending,
    reanchorOperationDigest,
    reanchorSnapshotDigest,
    reanchorSourceEpoch,
    principalDigest: schemaDigest(record.principalDigest, kind),
    components,
    updater
  })
}

function throwInstallationRootBusinessError(response: InstallationRootJsonResponse): never {
  if (!Number.isSafeInteger(response.status) || response.status < 100 || response.status > 599) {
    throw schemaFailure('response')
  }
  const record = exactRecord(response.body, ['schema', 'code'], 'response')
  if (record.schema !== INSTALLATION_ROOT_SCHEMAS.error) throw schemaFailure('response')
  const code = schemaEnum(record.code, INSTALLATION_ROOT_ERROR_CODES, 'response')
  throw new InstallationRootBusinessError(response.status, code)
}

export function parseInstallationRootSnapshotResponse(
  response: InstallationRootJsonResponse
): InstallationRootSnapshotEnvelope {
  if (!Number.isSafeInteger(response.status)) throw schemaFailure('response')
  if (response.status < 200 || response.status > 299) {
    return throwInstallationRootBusinessError(response)
  }
  const record = exactRecord(response.body, ['schema', 'snapshot'], 'response')
  if (record.schema !== INSTALLATION_ROOT_SCHEMAS.snapshot) throw schemaFailure('response')
  return Object.freeze({
    schema: INSTALLATION_ROOT_SCHEMAS.snapshot,
    snapshot: parseInstallationRootSnapshot(record.snapshot)
  })
}

export function parseInstallationRootMutationResponse(
  response: InstallationRootJsonResponse
): InstallationRootMutationEnvelope {
  if (!Number.isSafeInteger(response.status)) throw schemaFailure('response')
  if (response.status < 200 || response.status > 299) {
    return throwInstallationRootBusinessError(response)
  }
  const record = exactRecord(
    response.body,
    ['schema', 'snapshot', 'applied', 'recovered'],
    'response'
  )
  if (record.schema !== INSTALLATION_ROOT_SCHEMAS.mutation) throw schemaFailure('response')
  return Object.freeze({
    schema: INSTALLATION_ROOT_SCHEMAS.mutation,
    snapshot: parseInstallationRootSnapshot(record.snapshot),
    applied: schemaBoolean(record.applied, 'response'),
    recovered: schemaBoolean(record.recovered, 'response')
  })
}

function validatedSession(value: unknown): InstallationRootEngineSession {
  if (
    !isRecord(value) ||
    !Number.isSafeInteger(value.generation) ||
    Number(value.generation) < 1 ||
    !Number.isSafeInteger(value.pid) ||
    Number(value.pid) < 1 ||
    !Number.isSafeInteger(value.port) ||
    Number(value.port) < 1_024 ||
    Number(value.port) > 65_535 ||
    typeof value.bootToken !== 'string' ||
    !HEX_32_PATTERN.test(value.bootToken)
  ) {
    throw protocolError('Installation root engine session is unavailable')
  }
  return Object.freeze({
    generation: Number(value.generation),
    pid: Number(value.pid),
    port: Number(value.port),
    bootToken: value.bootToken
  })
}

function encodeJsonObject(
  value: Readonly<Record<string, unknown>>,
  bootToken: string
): Buffer {
  if (!isRecord(value)) {
    throw protocolError('Installation root request must be a JSON object')
  }
  let serialized: string | undefined
  try {
    serialized = JSON.stringify(value)
  } catch {
    throw protocolError('Installation root request JSON is invalid')
  }
  if (typeof serialized !== 'string') {
    throw protocolError('Installation root request JSON is invalid')
  }
  try {
    if (!isRecord(JSON.parse(serialized) as unknown)) {
      throw protocolError('Installation root request must encode a JSON object')
    }
  } catch (error) {
    if (error instanceof InstallationRootClientError) throw error
    throw protocolError('Installation root request JSON is invalid')
  }
  if (serialized.includes(bootToken)) {
    throw protocolError('Installation root request contains forbidden authority material')
  }
  const body = Buffer.from(serialized, 'utf8')
  if (body.byteLength > JSON_BYTE_LIMIT) {
    throw protocolError('Installation root request exceeds its byte limit')
  }
  return body
}

function parseJsonObject(body: Buffer, bootToken: string): Readonly<Record<string, unknown>> {
  let text: string
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(body)
  } catch {
    throw protocolError('Installation root response encoding is invalid')
  }
  if (text.includes(bootToken)) {
    throw protocolError('Installation root response contains forbidden authority material')
  }
  let value: unknown
  try {
    value = JSON.parse(text) as unknown
  } catch {
    throw protocolError('Installation root response JSON is invalid')
  }
  if (!isRecord(value)) {
    throw protocolError('Installation root response must be a JSON object')
  }
  // JSON escapes can hide an ASCII token from a raw-text search. Re-encoding
  // the parsed object normalises those escapes before the object leaves Main.
  if (JSON.stringify(value).includes(bootToken)) {
    throw protocolError('Installation root response contains forbidden authority material')
  }
  return value
}

function rawHeaderValues(rawHeaders: readonly string[], wantedName: string): string[] {
  const values: string[] = []
  const wanted = wantedName.toLowerCase()
  for (let index = 0; index < rawHeaders.length; index += 2) {
    if (rawHeaders[index].toLowerCase() === wanted) values.push(rawHeaders[index + 1])
  }
  return values
}

function responseContentLength(rawHeaders: readonly string[]): number | undefined {
  // This also validates all root fields and rejects unknown root extensions
  // before any response bytes are accepted into memory.
  extractSingleRootHeaders(rawHeaders, RESPONSE_SECURITY_HEADERS)
  const contentTypes = rawHeaderValues(rawHeaders, 'Content-Type')
  const cacheControls = rawHeaderValues(rawHeaders, 'Cache-Control')
  const lengths = rawHeaderValues(rawHeaders, 'Content-Length')
  if (
    contentTypes.length !== 1 ||
    contentTypes[0].toLowerCase() !== 'application/json' ||
    cacheControls.length !== 1 ||
    cacheControls[0].toLowerCase() !== 'no-store' ||
    lengths.length > 1
  ) {
    throw protocolError('Installation root response metadata is invalid')
  }
  if (lengths.length === 0) return undefined
  if (!/^(?:0|[1-9][0-9]*)$/.test(lengths[0])) {
    throw protocolError('Installation root response length is invalid')
  }
  const length = Number(lengths[0])
  if (!Number.isSafeInteger(length) || length > JSON_BYTE_LIMIT) {
    throw protocolError('Installation root response exceeds its byte limit')
  }
  return length
}

function extractSingleRootHeaders(
  rawHeaders: readonly string[],
  required: readonly string[]
): Readonly<Record<string, string>> {
  if (!Array.isArray(rawHeaders) || rawHeaders.length % 2 !== 0) {
    throw protocolError('Invalid installation root response headers')
  }
  const expected = new Map(required.map((name) => [name.toLowerCase(), name]))
  const observed = new Map(required.map((name) => [name.toLowerCase(), [] as string[]]))
  for (let index = 0; index < rawHeaders.length; index += 2) {
    const name = rawHeaders[index]
    const value = rawHeaders[index + 1]
    if (
      typeof name !== 'string' ||
      typeof value !== 'string' ||
      !name ||
      /[^\x21-\x7e]/.test(name) ||
      /[^\x00-\x7f]/.test(value)
    ) {
      throw protocolError('Invalid installation root response headers')
    }
    const lowerName = name.toLowerCase()
    if (lowerName.startsWith(ROOT_HEADER_PREFIX) && !expected.has(lowerName)) {
      throw protocolError('Unknown installation root response security header')
    }
    observed.get(lowerName)?.push(value)
  }
  const result: Record<string, string> = {}
  for (const [lowerName, canonicalName] of expected) {
    const values = observed.get(lowerName)
    if (!values || values.length !== 1) {
      throw protocolError('Missing or duplicate installation root response security header')
    }
    result[canonicalName] = values[0]
  }
  return Object.freeze(result)
}

export function signInstallationRootRequest(
  input: InstallationRootRequestSigningInput
): InstallationRootSignedRequest {
  const key = bootKey(input.bootToken)
  const body = Buffer.from(input.body ?? Buffer.alloc(0))
  const timestampMs = validatedTimestamp(input.timestampMs ?? Date.now())
  const nonce = input.nonce ?? randomBytes(32).toString('hex')
  hex32(nonce, 'nonce')
  const bodySha256 = createHash('sha256').update(body).digest('hex')
  const signature = createHmac('sha256', key)
    .update(
      requestMacInput({
        timestampMs,
        nonce,
        method: input.method,
        path: input.path,
        bodySha256
      })
    )
    .digest('hex')
  return Object.freeze({
    headers: Object.freeze({
      [HEADER_VERSION]: PROTOCOL_VERSION,
      [HEADER_TIMESTAMP_MS]: String(timestampMs),
      [HEADER_NONCE]: nonce,
      [HEADER_BODY_SHA256]: bodySha256,
      [HEADER_SIGNATURE]: signature
    }),
    timestampMs,
    nonce,
    bodySha256
  })
}

export function verifyInstallationRootResponse(
  input: InstallationRootResponseVerificationInput
): InstallationRootVerifiedResponse {
  const key = bootKey(input.bootToken)
  const requestNonce = input.requestNonce
  hex32(requestNonce, 'request nonce')
  const body = Buffer.from(input.body)
  const headers = extractSingleRootHeaders(input.rawHeaders, RESPONSE_SECURITY_HEADERS)
  if (headers[HEADER_VERSION] !== PROTOCOL_VERSION) {
    throw protocolError('Unsupported installation root response protocol')
  }
  const responseNonce = headers[HEADER_RESPONSE_REQUEST_NONCE]
  const claimedDigest = headers[HEADER_RESPONSE_BODY_SHA256]
  const claimedSignature = headers[HEADER_RESPONSE_SIGNATURE]
  if (!exactHexEqual(responseNonce, requestNonce)) {
    throw protocolError('Installation root response authentication failed')
  }
  const bodySha256 = createHash('sha256').update(body).digest('hex')
  if (!exactHexEqual(claimedDigest, bodySha256)) {
    throw protocolError('Installation root response authentication failed')
  }
  const expectedSignature = createHmac('sha256', key)
    .update(responseMacInput({ requestNonce, status: input.status, bodySha256 }))
    .digest('hex')
  if (!exactHexEqual(claimedSignature, expectedSignature)) {
    throw protocolError('Installation root response authentication failed')
  }
  return Object.freeze({ requestNonce, bodySha256 })
}

export class InstallationRootClient {
  private readonly timeoutMs: number

  constructor(private readonly dependencies: InstallationRootClientDependencies) {
    if (!dependencies || typeof dependencies.session !== 'function') {
      throw protocolError('Installation root session supplier is unavailable')
    }
    const timeoutMs = dependencies.timeoutMs ?? DEFAULT_TIMEOUT_MS
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > DEFAULT_TIMEOUT_MS) {
      throw protocolError('Installation root timeout is outside its bound')
    }
    this.timeoutMs = timeoutMs
  }

  private captureSession(): InstallationRootEngineSession {
    try {
      return validatedSession(this.dependencies.session())
    } catch {
      throw protocolError('Installation root engine session is unavailable')
    }
  }

  private sessionIsCurrent(captured: InstallationRootEngineSession): boolean {
    try {
      const current = validatedSession(this.dependencies.session())
      return (
        current.generation === captured.generation &&
        current.pid === captured.pid &&
        current.port === captured.port &&
        exactHexEqual(current.bootToken, captured.bootToken)
      )
    } catch {
      return false
    }
  }

  private assertSessionCurrent(captured: InstallationRootEngineSession): void {
    if (!this.sessionIsCurrent(captured)) {
      throw protocolError('Installation root engine session changed during the request')
    }
  }

  private request(
    captured: InstallationRootEngineSession,
    method: InstallationRootMethod,
    path: InstallationRootPath,
    body: Buffer,
    signal?: AbortSignal
  ): Promise<InstallationRootJsonResponse> {
    return new Promise((resolve, reject) => {
      let settled = false
      let outgoing: http.ClientRequest | undefined
      let incoming: http.IncomingMessage | undefined
      let timer: ReturnType<typeof setTimeout> | undefined

      const cleanup = (): void => {
        if (timer) clearTimeout(timer)
        signal?.removeEventListener('abort', abort)
      }
      const fail = (error: InstallationRootClientError): void => {
        if (settled) return
        settled = true
        cleanup()
        incoming?.destroy()
        outgoing?.destroy()
        reject(error)
      }
      const succeed = (response: InstallationRootJsonResponse): void => {
        if (settled) return
        settled = true
        cleanup()
        resolve(response)
      }
      const abort = (): void => {
        fail(protocolError('Installation root request was aborted'))
      }

      if (signal?.aborted) {
        abort()
        return
      }
      signal?.addEventListener('abort', abort, { once: true })

      const signed = signInstallationRootRequest({
        bootToken: captured.bootToken,
        method,
        path,
        body
      })
      const headers: Record<string, string> = {
        Accept: 'application/json',
        'Cache-Control': 'no-store',
        'Content-Length': String(body.byteLength),
        ...signed.headers
      }
      if (method === 'POST') headers['Content-Type'] = 'application/json'

      try {
        outgoing = http.request(
          {
            protocol: 'http:',
            hostname: '127.0.0.1',
            family: 4,
            localAddress: '127.0.0.1',
            port: captured.port,
            method,
            path,
            headers,
            agent: false
          },
          (response) => {
            incoming = response
            try {
              this.assertSessionCurrent(captured)
              const status = response.statusCode
              if (!status || status < 100 || status > 599) {
                throw protocolError('Installation root response status is invalid')
              }
              if (status >= 300 && status <= 399) {
                throw protocolError('Installation root redirects are forbidden')
              }
              if (
                response.socket.remoteAddress !== '127.0.0.1' ||
                response.socket.remotePort !== captured.port
              ) {
                throw protocolError('Installation root response peer is invalid')
              }
              const claimedLength = responseContentLength(response.rawHeaders)
              const chunks: Buffer[] = []
              let total = 0
              response.on('data', (chunk: Buffer | string) => {
                const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
                total += bytes.byteLength
                if (total > JSON_BYTE_LIMIT) {
                  fail(protocolError('Installation root response exceeds its byte limit'))
                  return
                }
                chunks.push(bytes)
              })
              response.on('aborted', () => {
                fail(protocolError('Installation root response ended unexpectedly'))
              })
              response.on('error', () => {
                fail(protocolError('Installation root response transport failed'))
              })
              response.on('end', () => {
                if (settled) return
                try {
                  this.assertSessionCurrent(captured)
                  if (claimedLength !== undefined && claimedLength !== total) {
                    throw protocolError('Installation root response length does not match')
                  }
                  const responseBody = Buffer.concat(chunks, total)
                  verifyInstallationRootResponse({
                    bootToken: captured.bootToken,
                    requestNonce: signed.nonce,
                    status,
                    rawHeaders: response.rawHeaders,
                    body: responseBody
                  })
                  const parsed = parseJsonObject(responseBody, captured.bootToken)
                  this.assertSessionCurrent(captured)
                  succeed(Object.freeze({ status, body: parsed }))
                } catch (error) {
                  fail(
                    error instanceof InstallationRootClientError
                      ? error
                      : protocolError('Installation root response is invalid')
                  )
                }
              })
            } catch (error) {
              fail(
                error instanceof InstallationRootClientError
                  ? error
                  : protocolError('Installation root response is invalid')
              )
            }
          }
        )
      } catch {
        fail(protocolError('Installation root request transport failed'))
        return
      }

      outgoing.on('error', () => {
        fail(protocolError('Installation root request transport failed'))
      })
      outgoing.setTimeout(this.timeoutMs, () => {
        fail(protocolError('Installation root request timed out'))
      })
      timer = setTimeout(() => {
        fail(protocolError('Installation root request timed out'))
      }, this.timeoutMs)
      timer.unref?.()
      outgoing.end(body)
    })
  }

  async signedJsonCall(call: InstallationRootSignedJsonCall): Promise<InstallationRootJsonResponse> {
    if (!call || ALLOWED_ROUTES.get(call.path) !== call.method) {
      throw protocolError('Installation root method and path are not allowed')
    }
    const captured = this.captureSession()
    let body: Buffer
    if (call.method === 'GET') {
      if (call.body !== undefined) {
        throw protocolError('Installation root GET body is forbidden')
      }
      body = Buffer.alloc(0)
    } else {
      body = encodeJsonObject(call.body ?? {}, captured.bootToken)
    }
    this.assertSessionCurrent(captured)
    try {
      return await this.request(captured, call.method, call.path, body, call.signal)
    } finally {
      // Revalidate after the await on both fulfillment and rejection. A late
      // result or error from an earlier engine generation never wins a race.
      this.assertSessionCurrent(captured)
    }
  }

  snapshot(options: InstallationRootCallOptions = {}): Promise<InstallationRootSnapshotEnvelope> {
    return this.signedJsonCall({
      method: 'GET',
      path: INSTALLATION_ROOT_PATHS.snapshot,
      ...options
    }).then(parseInstallationRootSnapshotResponse)
  }

  bindDesktop(
    body: InstallationRootDesktopBindRequest,
    options: InstallationRootCallOptions = {}
  ): Promise<InstallationRootMutationEnvelope> {
    const request = validateInstallationRootRequest(INSTALLATION_ROOT_PATHS.desktopBind, body)
    return this.signedJsonCall({
      method: 'POST',
      path: INSTALLATION_ROOT_PATHS.desktopBind,
      body: request,
      ...options
    }).then(parseInstallationRootMutationResponse)
  }

  verifyDesktop(
    body: InstallationRootDesktopVerifyRequest,
    options: InstallationRootCallOptions = {}
  ): Promise<InstallationRootMutationEnvelope> {
    const request = validateInstallationRootRequest(INSTALLATION_ROOT_PATHS.desktopVerify, body)
    return this.signedJsonCall({
      method: 'POST',
      path: INSTALLATION_ROOT_PATHS.desktopVerify,
      body: request,
      ...options
    }).then(parseInstallationRootMutationResponse)
  }

  advanceDesktop(
    body: InstallationRootDesktopAdvanceRequest,
    options: InstallationRootCallOptions = {}
  ): Promise<InstallationRootMutationEnvelope> {
    const request = validateInstallationRootRequest(INSTALLATION_ROOT_PATHS.desktopAdvance, body)
    return this.signedJsonCall({
      method: 'POST',
      path: INSTALLATION_ROOT_PATHS.desktopAdvance,
      body: request,
      ...options
    }).then(parseInstallationRootMutationResponse)
  }

  acknowledgeDesktopRecovery(
    body: InstallationRootDesktopRecoveryAckRequest,
    options: InstallationRootCallOptions = {}
  ): Promise<InstallationRootMutationEnvelope> {
    const request = validateInstallationRootRequest(
      INSTALLATION_ROOT_PATHS.desktopRecoveryAck,
      body
    )
    return this.signedJsonCall({
      method: 'POST',
      path: INSTALLATION_ROOT_PATHS.desktopRecoveryAck,
      body: request,
      ...options
    }).then(parseInstallationRootMutationResponse)
  }

  verifyUpdater(
    body: InstallationRootUpdaterVerifyRequest,
    options: InstallationRootCallOptions = {}
  ): Promise<InstallationRootMutationEnvelope> {
    const request = validateInstallationRootRequest(INSTALLATION_ROOT_PATHS.updaterVerify, body)
    return this.signedJsonCall({
      method: 'POST',
      path: INSTALLATION_ROOT_PATHS.updaterVerify,
      body: request,
      ...options
    }).then(parseInstallationRootMutationResponse)
  }

  advanceUpdater(
    body: InstallationRootUpdaterAdvanceRequest,
    options: InstallationRootCallOptions = {}
  ): Promise<InstallationRootMutationEnvelope> {
    const request = validateInstallationRootRequest(INSTALLATION_ROOT_PATHS.updaterAdvance, body)
    return this.signedJsonCall({
      method: 'POST',
      path: INSTALLATION_ROOT_PATHS.updaterAdvance,
      body: request,
      ...options
    }).then(parseInstallationRootMutationResponse)
  }
}
