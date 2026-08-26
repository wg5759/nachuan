import type {
  DesktopEngineSessionClient,
  DesktopEngineSessionJsonExchangeInput,
  DesktopEngineSessionJsonResponse
} from './desktop-engine-session-client'

const REQUEST_TOTAL_TIMEOUT_MS = 5_000
const REQUEST_FIRST_BYTE_TIMEOUT_MS = 5_000
const REQUEST_BODY_IDLE_TIMEOUT_MS = 5_000
const PROVIDER_NAME = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/
const MAX_JSON_DEPTH = 32
const APPROVAL_RESOLVE_BODY_LIMIT = 16 * 1024
const CONNECTION_SAVE_BODY_LIMIT = 512 * 1024
const SYNC_CONFIG_BODY_LIMIT = 24 * 1024
const SYNC_AUTH_BODY_LIMIT = 4 * 1024
const SYNC_TOGGLE_BODY_LIMIT = 1024
const SYNC_RUN_BODY_LIMIT = 16
const CHANNEL_RECOVERY_BODY_LIMIT = 32 * 1024
const LOWER_HEX_64 = /^[0-9a-f]{64}$/
const ZERO_DIGEST = '0'.repeat(64)

type ExchangeClient = Pick<DesktopEngineSessionClient, 'exchangeJson'>
type ApprovalDecision = 'approve' | 'reject' | 'revise'
type SyncAuthKind = 'login' | 'signup'
type ChannelRecoveryChannel = 'weixin' | 'feishu'

export interface DesktopChannelRecoveryInspectInput {
  readonly channel: ChannelRecoveryChannel
  readonly targetKind: string
  readonly targetKey: string
}

export interface DesktopChannelRecoveryCloseInput
  extends DesktopChannelRecoveryInspectInput {
  readonly expectedBeforeDigest: string
  readonly decisionId: string
  readonly decidedAtMs: number
  readonly reason: string
  readonly userConfirmed: true
  readonly confirmFinal: true
}

export interface DesktopConnectionInput {
  readonly type: string
  readonly apiKey: string
  readonly baseUrl: string
  readonly enabledModels: readonly Readonly<Record<string, unknown>>[]
  readonly preserveExistingCredential: boolean
}

export class DesktopPrivilegedSessionError extends Error {
  override readonly name = 'DesktopPrivilegedSessionError'
}

function failure(message: string): DesktopPrivilegedSessionError {
  return new DesktopPrivilegedSessionError(message)
}

function invalid(): DesktopPrivilegedSessionError {
  return failure('Desktop privileged request is invalid')
}

function exactObjectKeys(value: unknown, expected: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw invalid()
  const prototype = Object.getPrototypeOf(value)
  if (prototype !== Object.prototype && prototype !== null) throw invalid()
  const observed = Object.keys(value).sort()
  const wanted = [...expected].sort()
  if (observed.length !== wanted.length || observed.some((key, index) => key !== wanted[index])) {
    throw invalid()
  }
  return value as Record<string, unknown>
}

function assertClosedJson(value: unknown): void {
  const pending: Array<{ value: unknown; depth: number }> = [{ value, depth: 1 }]
  const observed = new WeakSet<object>()
  while (pending.length > 0) {
    const current = pending.pop()
    if (!current || current.depth > MAX_JSON_DEPTH) throw invalid()
    const item = current.value
    if (item === null || typeof item === 'string' || typeof item === 'boolean') continue
    if (typeof item === 'number') {
      if (!Number.isFinite(item)) throw invalid()
      continue
    }
    if (!item || typeof item !== 'object') throw invalid()
    if (observed.has(item)) throw invalid()
    observed.add(item)
    const prototype = Object.getPrototypeOf(item)
    if (Array.isArray(item)) {
      if (prototype !== Array.prototype) throw invalid()
      const keys = Object.keys(item)
      if (keys.length !== item.length || keys.some((key, index) => key !== String(index))) {
        throw invalid()
      }
      for (const child of item) pending.push({ value: child, depth: current.depth + 1 })
      continue
    }
    if (prototype !== Object.prototype && prototype !== null) throw invalid()
    const descriptors = Object.getOwnPropertyDescriptors(item)
    const stringKeys = Object.keys(descriptors)
    if (Reflect.ownKeys(item).length !== stringKeys.length) throw invalid()
    for (const key of stringKeys) {
      const descriptor = descriptors[key]
      if (!descriptor || !descriptor.enumerable || !('value' in descriptor)) throw invalid()
      pending.push({ value: descriptor.value, depth: current.depth + 1 })
    }
  }
}

function canonicalJson(value: Readonly<Record<string, unknown>>, byteLimit: number): Buffer {
  try {
    assertClosedJson(value)
    const serialized = JSON.stringify(value)
    if (typeof serialized !== 'string') throw new Error('not serializable')
    const body = Buffer.from(serialized, 'utf8')
    if (body.byteLength > byteLimit) throw new Error('too large')
    return body
  } catch {
    throw invalid()
  }
}

function validString(
  value: unknown,
  minimum: number,
  maximum: number,
  control: RegExp
): value is string {
  return (
    typeof value === 'string' &&
    value.length >= minimum &&
    value.length <= maximum &&
    !control.test(value)
  )
}

function exactProvider(provider: string): string {
  if (typeof provider !== 'string' || !PROVIDER_NAME.test(provider)) {
    throw invalid()
  }
  return provider
}

function exactApprovalId(approvalId: number): number {
  if (!Number.isSafeInteger(approvalId) || approvalId < 1) {
    throw invalid()
  }
  return approvalId
}

function exactChannelRecoveryTarget(
  channel: unknown,
  targetKind: unknown,
  targetKey: unknown
): { channel: ChannelRecoveryChannel; targetKind: string; targetKey: string } {
  if (channel !== 'weixin' && channel !== 'feishu') throw invalid()
  const allowed =
    channel === 'weixin'
      ? new Set(['inbound', 'delivery', 'video'])
      : new Set(['inbox', 'outbox', 'video'])
  if (
    typeof targetKind !== 'string' ||
    !allowed.has(targetKind) ||
    !validString(targetKey, 1, 512, /[\u0000-\u001f\u007f]/)
  ) {
    throw invalid()
  }
  return { channel, targetKind, targetKey }
}

/**
 * Closed Main→Gateway surface for ordinary privileged JSON operations.
 *
 * Callers cannot supply a method, target, capability, timeout or header. That
 * keeps the Desktop engine-session client as the only HTTP transport and makes
 * long-lived runtime/approval credentials unrepresentable on this wire.
 */
export class DesktopPrivilegedSession {
  constructor(private readonly client: ExchangeClient) {
    if (!client || typeof client.exchangeJson !== 'function') {
      throw failure('Desktop privileged session client is unavailable')
    }
  }

  private async exchange(
    input: Pick<
      DesktopEngineSessionJsonExchangeInput,
      'capability' | 'method' | 'target' | 'body'
    >
  ): Promise<unknown> {
    const controller = new AbortController()
    const connectionTransaction = input.capability === 'connection.save'
    let response: DesktopEngineSessionJsonResponse
    try {
      response = await this.client.exchangeJson(
        Object.freeze({
          ...input,
          body: Buffer.from(input.body),
          signal: controller.signal,
          totalTimeoutMs: connectionTransaction ? 30_000 : REQUEST_TOTAL_TIMEOUT_MS,
          firstByteTimeoutMs: connectionTransaction ? 30_000 : REQUEST_FIRST_BYTE_TIMEOUT_MS,
          bodyIdleTimeoutMs: REQUEST_BODY_IDLE_TIMEOUT_MS
        })
      )
    } catch {
      throw failure('Desktop privileged request failed')
    }
    if (!Number.isSafeInteger(response.status) || response.status < 200 || response.status >= 300) {
      throw failure('Desktop privileged request was rejected')
    }
    return response.body
  }

  async pluginUiSnapshot(): Promise<unknown> {
    return this.exchange({
      capability: 'plugin.ui.snapshot',
      method: 'GET',
      target: '/internal/v1/desktop/session/plugin-ui-snapshot',
      body: Buffer.alloc(0)
    })
  }

  async listApprovals(userId: string): Promise<unknown> {
    if (
      typeof userId !== 'string' ||
      userId.length < 1 ||
      userId.length > 128 ||
      /[\u0000-\u001f\u007f]/.test(userId)
    ) {
      return Promise.reject(failure('Desktop privileged request is invalid'))
    }
    return this.exchange({
      capability: 'approval.list',
      method: 'GET',
      target: `/v1/approvals?user_id=${encodeURIComponent(userId)}`,
      body: Buffer.alloc(0)
    })
  }

  async resolveApproval(
    approvalId: number,
    decision: ApprovalDecision,
    note: string
  ): Promise<unknown> {
    if (
      (decision !== 'approve' && decision !== 'reject' && decision !== 'revise') ||
      !validString(note, 0, 2_000, /\u0000/)
    ) {
      return Promise.reject(invalid())
    }
    return this.exchange({
      capability: 'approval.resolve',
      method: 'POST',
      target: `/v1/approvals/${exactApprovalId(approvalId)}/resolve`,
      body: canonicalJson({ decision, note }, APPROVAL_RESOLVE_BODY_LIMIT)
    })
  }

  async saveConnection(provider: string, input: DesktopConnectionInput): Promise<unknown> {
    let value: Record<string, unknown>
    try {
      value = exactObjectKeys(input, [
        'type',
        'apiKey',
        'baseUrl',
        'enabledModels',
        'preserveExistingCredential'
      ])
    } catch {
      return Promise.reject(invalid())
    }
    if (
      !validString(value.type, 1, 128, /[\u0000-\u001f\u007f]/) ||
      !validString(value.apiKey, 0, 32_768, /\u0000/) ||
      !validString(value.baseUrl, 0, 2_048, /[\u0000-\u001f\u007f]/) ||
      !Array.isArray(value.enabledModels) ||
      value.enabledModels.length > 200 ||
      typeof value.preserveExistingCredential !== 'boolean' ||
      value.enabledModels.some(
        (model) =>
          !model ||
          typeof model !== 'object' ||
          Array.isArray(model) ||
          (Object.getPrototypeOf(model) !== Object.prototype &&
            Object.getPrototypeOf(model) !== null)
      )
    ) {
      return Promise.reject(invalid())
    }
    return this.exchange({
      capability: 'connection.save',
      method: 'POST',
      target: `/admin/connections/${exactProvider(provider)}`,
      body: canonicalJson({
        type: value.type,
        api_key: value.apiKey,
        base_url: value.baseUrl,
        enabled_models: value.enabledModels,
        preserve_existing_credential: value.preserveExistingCredential
      }, CONNECTION_SAVE_BODY_LIMIT)
    })
  }

  async deleteConnection(provider: string): Promise<unknown> {
    return this.exchange({
      capability: 'connection.delete',
      method: 'DELETE',
      target: `/admin/connections/${exactProvider(provider)}`,
      body: Buffer.alloc(0)
    })
  }

  async configureSync(url: string, anonKey: string): Promise<unknown> {
    if (
      !validString(url, 1, 2_048, /[\u0000-\u001f\u007f]/) ||
      !validString(anonKey, 1, 16_384, /\u0000/)
    ) {
      return Promise.reject(invalid())
    }
    return this.exchange({
      capability: 'sync.config',
      method: 'POST',
      target: '/v1/sync/config',
      body: canonicalJson({ url, anon_key: anonKey }, SYNC_CONFIG_BODY_LIMIT)
    })
  }

  async authenticateSync(kind: SyncAuthKind, email: string, password: string): Promise<unknown> {
    if (
      (kind !== 'login' && kind !== 'signup') ||
      !validString(email, 1, 320, /[\u0000-\u001f\u007f]/) ||
      !validString(password, 1, 1_024, /\u0000/)
    ) {
      return Promise.reject(invalid())
    }
    return this.exchange({
      capability: 'sync.auth',
      method: 'POST',
      target: `/v1/sync/${kind}`,
      body: canonicalJson({ email, password }, SYNC_AUTH_BODY_LIMIT)
    })
  }

  async setSyncEnabled(enabled: boolean): Promise<unknown> {
    if (typeof enabled !== 'boolean') return Promise.reject(invalid())
    return this.exchange({
      capability: 'sync.toggle',
      method: 'POST',
      target: '/v1/sync/toggle',
      body: canonicalJson({ enabled }, SYNC_TOGGLE_BODY_LIMIT)
    })
  }

  async runSync(): Promise<unknown> {
    return this.exchange({
      capability: 'sync.run',
      method: 'POST',
      target: '/v1/sync/run',
      body: canonicalJson({}, SYNC_RUN_BODY_LIMIT)
    })
  }

  async inspectChannelRecovery(input: DesktopChannelRecoveryInspectInput): Promise<unknown> {
    let value: Record<string, unknown>
    try {
      value = exactObjectKeys(input, ['channel', 'targetKind', 'targetKey'])
    } catch {
      return Promise.reject(invalid())
    }
    let target: ReturnType<typeof exactChannelRecoveryTarget>
    try {
      target = exactChannelRecoveryTarget(value.channel, value.targetKind, value.targetKey)
    } catch {
      return Promise.reject(invalid())
    }
    return this.exchange({
      capability: 'channel-recovery.inspect',
      method: 'POST',
      target: `/admin/channel-recovery/${target.channel}/inspect`,
      body: canonicalJson(
        { target_kind: target.targetKind, target_key: target.targetKey },
        CHANNEL_RECOVERY_BODY_LIMIT
      )
    })
  }

  async closeChannelRecovery(input: DesktopChannelRecoveryCloseInput): Promise<unknown> {
    let value: Record<string, unknown>
    try {
      value = exactObjectKeys(input, [
        'channel',
        'targetKind',
        'targetKey',
        'expectedBeforeDigest',
        'decisionId',
        'decidedAtMs',
        'reason',
        'userConfirmed',
        'confirmFinal'
      ])
    } catch {
      return Promise.reject(invalid())
    }
    let target: ReturnType<typeof exactChannelRecoveryTarget>
    try {
      target = exactChannelRecoveryTarget(value.channel, value.targetKind, value.targetKey)
    } catch {
      return Promise.reject(invalid())
    }
    if (
      typeof value.expectedBeforeDigest !== 'string' ||
      !LOWER_HEX_64.test(value.expectedBeforeDigest) ||
      value.expectedBeforeDigest === ZERO_DIGEST ||
      typeof value.decisionId !== 'string' ||
      !LOWER_HEX_64.test(value.decisionId) ||
      value.decisionId === ZERO_DIGEST ||
      !Number.isSafeInteger(value.decidedAtMs) ||
      Number(value.decidedAtMs) < 0 ||
      !validString(value.reason, 1, 2_048, /[\u0000-\u001f\u007f]/) ||
      value.userConfirmed !== true ||
      value.confirmFinal !== true
    ) {
      return Promise.reject(invalid())
    }
    return this.exchange({
      capability: 'channel-recovery.close',
      method: 'POST',
      target: `/admin/channel-recovery/${target.channel}/close-without-replay`,
      body: canonicalJson(
        {
          target_kind: target.targetKind,
          target_key: target.targetKey,
          expected_before_digest: value.expectedBeforeDigest,
          decision_id: value.decisionId,
          decided_at_ms: value.decidedAtMs,
          reason: value.reason,
          user_confirmed: true,
          confirm_final: true
        },
        CHANNEL_RECOVERY_BODY_LIMIT
      )
    })
  }
}
