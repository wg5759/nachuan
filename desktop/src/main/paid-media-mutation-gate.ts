import { AsyncLocalStorage } from 'node:async_hooks'

import {
  PAID_MEDIA_RECOVERABLE_HANDLER_VERSION,
  paidMediaCompositeEvidenceDigest,
  type PaidMediaRecoverableMutationDescriptor,
  type PaidMediaRecoverableMutationKind
} from './paid-media-installation-root'

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
const OPERATION_ID_PATTERN = /^desktop-op-[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
const KIND_PATTERN = /^[a-z][a-z0-9_.-]{0,63}$/
const SHA256_PATTERN = /^[0-9a-f]{64}$/
const ZERO_SHA256 = '0'.repeat(64)
const RECOVERABLE_KINDS = new Set<PaidMediaRecoverableMutationKind>([
  'asset_v2_dispatch',
  'asset_v2_stage_reserve',
  'asset_v2_stage_archive',
  'asset_v2_stage_cleanup',
  'asset_v2_result_ready_ack_intent',
  'asset_v2_ack_completion',
  'asset_v2_capacity_release'
])

export interface PaidMediaMutationRootAuthority {
  assertMutationContext(transactionId?: string): void
}

export interface PaidMediaLegacyMutationGateContext {
  readonly transactionId: string
  readonly kind: string
  readonly operationId: string | null
}

export interface PaidMediaMutationGateExpectation {
  readonly transactionId: string
  readonly mode: 'legacy' | 'recoverable'
  readonly kind: string
  readonly operationId: string | null
  readonly intentSha256: string | null
}

export interface PaidMediaMutationGateState extends PaidMediaMutationGateExpectation {
  readonly open: boolean
}

interface MutablePaidMediaMutationGateState {
  transactionId: string
  mode: 'legacy' | 'recoverable'
  kind: string
  operationId: string | null
  intentSha256: string | null
  open: boolean
}

export class PaidMediaMutationGateError extends Error {
  override readonly name = 'PaidMediaMutationGateError'
}

function fail(message: string, cause?: unknown): PaidMediaMutationGateError {
  return new PaidMediaMutationGateError(
    message,
    cause === undefined ? undefined : { cause }
  )
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort()
  const wanted = [...expected].sort()
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index])
}

function operationId(value: unknown): string | null {
  if (value === null) return null
  if (typeof value !== 'string' || !OPERATION_ID_PATTERN.test(value)) {
    throw fail('Paid media mutation gate operation id is invalid')
  }
  return value.toLowerCase()
}

function canonicalLegacyContext(value: unknown): PaidMediaLegacyMutationGateContext {
  if (
    !isRecord(value) ||
    !exactKeys(value, ['transactionId', 'kind', 'operationId']) ||
    typeof value.transactionId !== 'string' ||
    !UUID_PATTERN.test(value.transactionId) ||
    typeof value.kind !== 'string' ||
    !KIND_PATTERN.test(value.kind)
  ) {
    throw fail('Paid media legacy mutation gate context is invalid')
  }
  return Object.freeze({
    transactionId: value.transactionId.toLowerCase(),
    kind: value.kind,
    operationId: operationId(value.operationId)
  })
}

function canonicalExpectation(value: unknown): PaidMediaMutationGateExpectation {
  if (
    !isRecord(value) ||
    !exactKeys(value, [
      'transactionId',
      'mode',
      'kind',
      'operationId',
      'intentSha256'
    ]) ||
    typeof value.transactionId !== 'string' ||
    !UUID_PATTERN.test(value.transactionId) ||
    (value.mode !== 'legacy' && value.mode !== 'recoverable') ||
    typeof value.kind !== 'string' ||
    !KIND_PATTERN.test(value.kind) ||
    (value.intentSha256 !== null &&
      (typeof value.intentSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(value.intentSha256)))
  ) {
    throw fail('Paid media mutation gate expectation is invalid')
  }
  return Object.freeze({
    transactionId: value.transactionId.toLowerCase(),
    mode: value.mode,
    kind: value.kind,
    operationId: operationId(value.operationId),
    intentSha256: value.intentSha256
  })
}

function canonicalRecoverableDescriptor(
  value: unknown
): PaidMediaRecoverableMutationDescriptor {
  if (
    !isRecord(value) ||
    !exactKeys(value, [
      'mode',
      'handlerVersion',
      'kind',
      'operationId',
      'intentSha256',
      'transactionId',
      'preparedAt',
      'beforeCompositeDigest',
      'beforeAuthorityEvidence'
    ]) ||
    value.mode !== 'recoverable' ||
    value.handlerVersion !== PAID_MEDIA_RECOVERABLE_HANDLER_VERSION ||
    typeof value.kind !== 'string' ||
    !RECOVERABLE_KINDS.has(value.kind as PaidMediaRecoverableMutationKind) ||
    typeof value.operationId !== 'string' ||
    !OPERATION_ID_PATTERN.test(value.operationId) ||
    typeof value.intentSha256 !== 'string' ||
    !SHA256_PATTERN.test(value.intentSha256) ||
    value.intentSha256 === ZERO_SHA256 ||
    typeof value.transactionId !== 'string' ||
    !UUID_PATTERN.test(value.transactionId) ||
    !Number.isSafeInteger(value.preparedAt) ||
    Number(value.preparedAt) < 0 ||
    typeof value.beforeCompositeDigest !== 'string' ||
    !SHA256_PATTERN.test(value.beforeCompositeDigest) ||
    value.beforeCompositeDigest === ZERO_SHA256
  ) {
    throw fail('Paid media recoverable mutation gate descriptor is invalid')
  }
  let compositeDigest: string
  try {
    compositeDigest = paidMediaCompositeEvidenceDigest(value.beforeAuthorityEvidence)
  } catch (error) {
    throw fail('Paid media recoverable mutation gate before-evidence is invalid', error)
  }
  if (compositeDigest !== value.beforeCompositeDigest) {
    throw fail('Paid media recoverable mutation gate before-evidence does not match')
  }
  return Object.freeze({
    mode: 'recoverable',
    handlerVersion: PAID_MEDIA_RECOVERABLE_HANDLER_VERSION,
    kind: value.kind as PaidMediaRecoverableMutationKind,
    operationId: value.operationId.toLowerCase(),
    intentSha256: value.intentSha256,
    transactionId: value.transactionId.toLowerCase(),
    preparedAt: Number(value.preparedAt),
    beforeCompositeDigest: value.beforeCompositeDigest,
    beforeAuthorityEvidence: Object.freeze({
      ...(value.beforeAuthorityEvidence as PaidMediaRecoverableMutationDescriptor['beforeAuthorityEvidence'])
    })
  })
}

const gateByAuthority = new WeakMap<object, PaidMediaMutationGate>()

export class PaidMediaMutationGate {
  private readonly storage = new AsyncLocalStorage<MutablePaidMediaMutationGateState>()

  constructor(private readonly authority: PaidMediaMutationRootAuthority) {
    if (
      !authority ||
      (typeof authority !== 'object' && typeof authority !== 'function') ||
      typeof authority.assertMutationContext !== 'function'
    ) {
      throw fail('Paid media mutation gate Root assertion is unavailable')
    }
    if (gateByAuthority.has(authority as object)) {
      throw fail('Paid media mutation gate already exists for this Root authority')
    }
    gateByAuthority.set(authority as object, this)
  }

  isBoundTo(authority: PaidMediaMutationRootAuthority): boolean {
    return authority === this.authority
  }

  readonly guard = (): void => {
    const current = this.requireOpenContext()
    try {
      this.authority.assertMutationContext(current.transactionId)
    } catch (error) {
      throw fail('Paid media mutation gate Root transaction is not active', error)
    }
  }

  assert(expectationValue: unknown): Readonly<PaidMediaMutationGateState> {
    const expectation = canonicalExpectation(expectationValue)
    const current = this.requireOpenContext()
    if (
      current.transactionId !== expectation.transactionId ||
      current.mode !== expectation.mode ||
      current.kind !== expectation.kind ||
      current.operationId !== expectation.operationId ||
      current.intentSha256 !== expectation.intentSha256
    ) {
      throw fail('Paid media mutation gate context does not match')
    }
    this.guard()
    return Object.freeze({ ...current })
  }

  async runLegacy<T>(
    contextValue: unknown,
    action: () => Promise<T>
  ): Promise<T> {
    const context = canonicalLegacyContext(contextValue)
    if (typeof action !== 'function') {
      throw fail('Paid media legacy mutation gate action is invalid')
    }
    this.assertNoInheritedContext()
    const token: MutablePaidMediaMutationGateState = {
      transactionId: context.transactionId,
      mode: 'legacy',
      kind: context.kind,
      operationId: context.operationId,
      intentSha256: null,
      open: true
    }
    return this.storage.run(token, async () => {
      try {
        this.guard()
        return await action()
      } finally {
        token.open = false
      }
    })
  }

  async runRecoverable<T>(
    descriptorValue: unknown,
    action: () => Promise<T>
  ): Promise<T> {
    const descriptor = canonicalRecoverableDescriptor(descriptorValue)
    if (typeof action !== 'function') {
      throw fail('Paid media recoverable mutation gate action is invalid')
    }
    this.assertNoInheritedContext()
    const token: MutablePaidMediaMutationGateState = {
      transactionId: descriptor.transactionId,
      mode: 'recoverable',
      kind: descriptor.kind,
      operationId: descriptor.operationId,
      intentSha256: descriptor.intentSha256,
      open: true
    }
    return this.storage.run(token, async () => {
      try {
        this.guard()
        return await action()
      } finally {
        token.open = false
      }
    })
  }

  private assertNoInheritedContext(): void {
    const inherited = this.storage.getStore()
    if (!inherited) return
    throw fail(
      inherited.open
        ? 'Nested paid media mutation gate context is forbidden'
        : 'Inherited paid media mutation gate context is closed'
    )
  }

  private requireOpenContext(): MutablePaidMediaMutationGateState {
    const current = this.storage.getStore()
    if (!current) throw fail('Paid media mutation gate has no active context')
    if (!current.open) throw fail('Paid media mutation gate context is closed')
    return current
  }
}
