// ADR-0013 Web 形态：审批 / 连接 / 云同步的网关直连。
// 这些路由在网关侧全部要求双头（gateway/app.py、gateway/admin.py 的 Depends）：
// Authorization: Bearer <runtime key> + X-Nachuan-Approval-Key: <approval key>。
// 审批 Key 未录入时头缺省，网关自行 401/503，错误经 WebHttpError 如实上抛（fail-closed）。

import type { DesktopAPI } from '../renderer/src/env'
import type { WebHttpClient } from './http'

type PrivilegedApi = Pick<
  DesktopAPI,
  | 'listApprovals'
  | 'resolveApproval'
  | 'saveConnection'
  | 'deleteConnection'
  | 'configureSync'
  | 'authenticateSync'
  | 'toggleSync'
  | 'runSync'
  | 'inspectChannelRecovery'
  | 'closeChannelRecovery'
>

type ListApprovalsResult = Awaited<ReturnType<DesktopAPI['listApprovals']>>
type ResolveApprovalResult = Awaited<ReturnType<DesktopAPI['resolveApproval']>>
type SaveConnectionResult = Awaited<ReturnType<DesktopAPI['saveConnection']>>
type DeleteConnectionResult = Awaited<ReturnType<DesktopAPI['deleteConnection']>>

const PROVIDER_NAME = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/
const LOWER_HEX_64 = /^[0-9a-f]{64}$/
const ZERO_DIGEST = '0'.repeat(64)
const APPROVAL_DECISIONS = new Set(['approve', 'reject', 'revise'])

function exactKeys(value: unknown, expected: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('invalid channel recovery request')
  }
  const record = value as Record<string, unknown>
  const observed = Object.keys(record).sort()
  const wanted = [...expected].sort()
  if (observed.length !== wanted.length || observed.some((key, index) => key !== wanted[index])) {
    throw new Error('invalid channel recovery request')
  }
  return record
}

function checkedRecoveryTarget(value: unknown): {
  channel: 'weixin' | 'feishu'
  targetKind: 'inbound' | 'delivery' | 'video' | 'inbox' | 'outbox'
  targetKey: string
} {
  const record = exactKeys(value, ['channel', 'targetKind', 'targetKey'])
  const channel = record.channel
  const targetKind = record.targetKind
  const targetKey = record.targetKey
  const allowed =
    channel === 'weixin'
      ? new Set(['inbound', 'delivery', 'video'])
      : channel === 'feishu'
        ? new Set(['inbox', 'outbox', 'video'])
        : null
  if (
    !allowed ||
    typeof targetKind !== 'string' ||
    !allowed.has(targetKind) ||
    typeof targetKey !== 'string' ||
    targetKey.length < 1 ||
    targetKey.length > 512 ||
    /[\u0000-\u001f\u007f]/.test(targetKey)
  ) {
    throw new Error('invalid channel recovery request')
  }
  return {
    channel: channel as 'weixin' | 'feishu',
    targetKind: targetKind as 'inbound' | 'delivery' | 'video' | 'inbox' | 'outbox',
    targetKey
  }
}

function checkedDigest(value: unknown): string {
  if (typeof value !== 'string' || !LOWER_HEX_64.test(value) || value === ZERO_DIGEST) {
    throw new Error('invalid channel recovery response')
  }
  return value
}

function checkedCounts(value: unknown, channel: 'weixin' | 'feishu'): Record<string, number> {
  const fields = channel === 'weixin' ? ['inbound', 'delivery', 'video'] : ['inbox', 'outbox', 'video']
  const record = exactKeys(value, fields)
  for (const field of fields) {
    if (!Number.isSafeInteger(record[field]) || Number(record[field]) < 0) {
      throw new Error('invalid channel recovery response')
    }
  }
  return Object.fromEntries(fields.map((field) => [field, Number(record[field])]))
}

function checkedRecoverySnapshot(
  value: unknown,
  target: ReturnType<typeof checkedRecoveryTarget>
): Awaited<ReturnType<DesktopAPI['inspectChannelRecovery']>> {
  const expectedKeys = [
    'affected_counts',
    'decided_at_ms',
    'decision_id',
    'expected_before_digest',
    ...(target.channel === 'weixin' ? ['principal_sha256'] : []),
    'schema',
    'target_key_sha256',
    'target_kind'
  ]
  const record = exactKeys(value, expectedKeys)
  const expectedSchema =
    target.channel === 'weixin'
      ? 'nachuan.weixin-recovery-snapshot.v1'
      : 'nachuan.feishu-recovery-inspect.v1'
  if (
    record.schema !== expectedSchema ||
    record.target_kind !== target.targetKind ||
    !Number.isSafeInteger(record.decided_at_ms) ||
    Number(record.decided_at_ms) < 0
  ) {
    throw new Error('invalid channel recovery response')
  }
  if (target.channel === 'weixin') checkedDigest(record.principal_sha256)
  return {
    schema: expectedSchema,
    targetKind: target.targetKind,
    targetKeySha256: checkedDigest(record.target_key_sha256),
    expectedBeforeDigest: checkedDigest(record.expected_before_digest),
    affectedCounts: checkedCounts(record.affected_counts, target.channel),
    decisionId: checkedDigest(record.decision_id),
    decidedAtMs: Number(record.decided_at_ms)
  }
}

function checkedRecoveryResult(
  value: unknown,
  channel: 'weixin' | 'feishu'
): Awaited<ReturnType<DesktopAPI['closeChannelRecovery']>> {
  const record = exactKeys(value, [
    'affected_counts',
    'applied',
    'operation_digest',
    'receipt_sha256',
    'schema'
  ])
  if (record.schema !== 'nachuan.channel-recovery-result.v1' || typeof record.applied !== 'boolean') {
    throw new Error('invalid channel recovery response')
  }
  return {
    schema: 'nachuan.channel-recovery-result.v1',
    operationDigest: checkedDigest(record.operation_digest),
    receiptSha256: checkedDigest(record.receipt_sha256),
    affectedCounts: checkedCounts(record.affected_counts, channel),
    applied: record.applied
  }
}

function checkedUserId(userId: unknown): string {
  if (typeof userId !== 'string' || userId.length < 1 || userId.length > 128) {
    throw new Error('invalid approval user id')
  }
  return userId
}

function checkedProvider(provider: unknown): string {
  if (typeof provider !== 'string' || !PROVIDER_NAME.test(provider)) {
    throw new Error('invalid provider name')
  }
  return provider
}

export function createWebPrivilegedApi(http: WebHttpClient): PrivilegedApi {
  // 双头路由统一开关：includeApprovalKey 使 http 客户端附带审批头。
  const admin = { includeApprovalKey: true } as const
  const recoveryAttempts = new Map<string, number>()
  const recoveryAttemptTtlMs = 15 * 60 * 1000

  const inspectRecovery = async (
    target: ReturnType<typeof checkedRecoveryTarget>
  ): ReturnType<DesktopAPI['inspectChannelRecovery']> => {
    const result = await http.requestJson<unknown>({
      method: 'POST',
      target: `/admin/channel-recovery/${target.channel}/inspect`,
      json: { target_kind: target.targetKind, target_key: target.targetKey },
      ...admin
    })
    return checkedRecoverySnapshot(result, target)
  }

  const api: PrivilegedApi = {
    listApprovals: async (userId: string) =>
      http.requestJson<ListApprovalsResult>({
        method: 'GET',
        target: `/v1/approvals?user_id=${encodeURIComponent(checkedUserId(userId))}`,
        ...admin
      }),

    resolveApproval: async (payload: { id: number; decision: 'approve' | 'reject' | 'revise'; note?: string }) => {
      if (
        !payload ||
        !Number.isSafeInteger(payload.id) ||
        payload.id < 1 ||
        !APPROVAL_DECISIONS.has(String(payload.decision))
      ) {
        throw new Error('invalid approval decision')
      }
      return http.requestJson<ResolveApprovalResult>({
        method: 'POST',
        target: `/v1/approvals/${payload.id}/resolve`,
        json: { decision: payload.decision, note: payload.note ?? '' },
        ...admin
      })
    },

    saveConnection: async (payload: Parameters<DesktopAPI['saveConnection']>[0]) => {
      if (!payload || typeof payload !== 'object') {
        throw new Error('invalid connection configuration')
      }
      const provider = checkedProvider(payload.provider)
      return http.requestJson<SaveConnectionResult>({
        method: 'POST',
        target: `/admin/connections/${encodeURIComponent(provider)}`,
        json: {
          type: payload.type,
          api_key: payload.api_key,
          base_url: payload.base_url,
          enabled_models: payload.enabled_models,
          preserve_existing_credential: payload.preserve_existing_credential
        },
        ...admin
      })
    },

    deleteConnection: async (provider: string) =>
      http.requestJson<DeleteConnectionResult>({
        method: 'DELETE',
        target: `/admin/connections/${encodeURIComponent(checkedProvider(provider))}`,
        ...admin
      }),

    configureSync: (url: string, anonKey: string) =>
      http.requestJson({
        method: 'POST',
        target: '/v1/sync/config',
        json: { url, anon_key: anonKey },
        ...admin
      }),

    authenticateSync: async (kind: 'login' | 'signup', email: string, password: string) => {
      if (kind !== 'login' && kind !== 'signup') throw new Error('invalid sync credentials')
      return http.requestJson({
        method: 'POST',
        target: `/v1/sync/${kind}`,
        json: { email, password },
        ...admin
      })
    },

    toggleSync: (enabled: boolean) =>
      http.requestJson({
        method: 'POST',
        target: '/v1/sync/toggle',
        json: { enabled },
        ...admin
      }),

    runSync: () =>
      http.requestJson({
        method: 'POST',
        target: '/v1/sync/run',
        json: {},
        ...admin
      }),

    inspectChannelRecovery: async (input: Parameters<DesktopAPI['inspectChannelRecovery']>[0]) => {
      const target = checkedRecoveryTarget(input)
      return inspectRecovery(target)
    },

    closeChannelRecovery: async (input: Parameters<DesktopAPI['closeChannelRecovery']>[0]) => {
      const record = exactKeys(input, [
        'channel',
        'confirmFinal',
        'decidedAtMs',
        'decisionId',
        'expectedBeforeDigest',
        'reason',
        'targetKey',
        'targetKeySha256',
        'targetKind',
        'userConfirmed'
      ])
      const target = checkedRecoveryTarget({
        channel: record.channel,
        targetKind: record.targetKind,
        targetKey: record.targetKey
      })
      const reason = record.reason
      if (
        typeof reason !== 'string' ||
        reason.length < 1 ||
        reason.length > 2_048 ||
        /[\u0000-\u001f\u007f]/.test(reason) ||
        record.userConfirmed !== true ||
        record.confirmFinal !== true ||
        !Number.isSafeInteger(record.decidedAtMs) ||
        Number(record.decidedAtMs) < 0
      ) {
        throw new Error('invalid channel recovery request')
      }
      checkedDigest(record.targetKeySha256)
      const expectedBeforeDigest = checkedDigest(record.expectedBeforeDigest)
      const decisionId = checkedDigest(record.decisionId)
      const attemptKey = JSON.stringify({
        channel: target.channel,
        targetKind: target.targetKind,
        targetKey: target.targetKey,
        targetKeySha256: record.targetKeySha256,
        expectedBeforeDigest,
        decisionId,
        decidedAtMs: Number(record.decidedAtMs),
        reason
      })
      const now = Date.now()
      for (const [key, createdAt] of recoveryAttempts) {
        if (now - createdAt > recoveryAttemptTtlMs) recoveryAttempts.delete(key)
      }
      while (recoveryAttempts.size >= 64) {
        const oldest = recoveryAttempts.keys().next().value as string | undefined
        if (!oldest) break
        recoveryAttempts.delete(oldest)
      }
      if (!recoveryAttempts.has(attemptKey)) {
        const fresh = await inspectRecovery(target)
        if (
          fresh.targetKeySha256 !== record.targetKeySha256 ||
          fresh.expectedBeforeDigest !== expectedBeforeDigest
        ) {
          throw new Error('channel recovery target changed; inspect again')
        }
      }
      recoveryAttempts.set(attemptKey, now)
      const result = await http.requestJson<unknown>({
        method: 'POST',
        target: `/admin/channel-recovery/${target.channel}/close-without-replay`,
        json: {
          target_kind: target.targetKind,
          target_key: target.targetKey,
          expected_before_digest: expectedBeforeDigest,
          decision_id: decisionId,
          decided_at_ms: Number(record.decidedAtMs),
          reason,
          user_confirmed: true,
          confirm_final: true
        },
        ...admin
      })
      return checkedRecoveryResult(result, target.channel)
    }
  }
  return Object.freeze(api)
}
