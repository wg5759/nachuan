import { beforeEach, describe, expect, it, vi } from 'vitest'

import { createCredentialStore, type KeyValueStorage } from './credentials'
import { createWebHttpClient, WebHttpError } from './http'
import { createWebPrivilegedApi } from './privileged'

const data: Record<string, string> = {}
const storage: KeyValueStorage = {
  getItem: (key: string) => (key in data ? data[key] : null),
  setItem: (key: string, value: string) => {
    data[key] = value
  },
  removeItem: (key: string) => {
    delete data[key]
  }
}

let fetchMock: ReturnType<typeof vi.fn>

function api() {
  const http = createWebHttpClient({
    credentials: createCredentialStore(() => storage),
    fetchImpl: fetchMock as unknown as typeof fetch
  })
  return createWebPrivilegedApi(http)
}

function lastCall(): [string, RequestInit] {
  return fetchMock.mock.calls[fetchMock.mock.calls.length - 1] as unknown as [string, RequestInit]
}

beforeEach(() => {
  for (const key of Object.keys(data)) delete data[key]
  data['nachuan.web.runtimeKey'] = 'runtime-key'
  data['nachuan.web.approvalKey'] = 'approval-key'
  fetchMock = vi.fn(
    async () => new Response('{"ok":true}', { status: 200, headers: { 'content-type': 'application/json' } })
  )
})

describe('web-shim privileged api (double-header routes)', () => {
  it('listApprovals hits GET /v1/approvals with both credentials and encoded user id', async () => {
    fetchMock.mockResolvedValue(
      new Response('{"user_id":"u 1","pending":[]}', { status: 200 })
    )

    await expect(api().listApprovals('u 1')).resolves.toEqual({ user_id: 'u 1', pending: [] })

    const [target, init] = lastCall()
    expect(target).toBe('/v1/approvals?user_id=u%201')
    expect(init.method).toBe('GET')
    const headers = init.headers as Record<string, string>
    expect(headers['Authorization']).toBe('Bearer runtime-key')
    expect(headers['X-Nachuan-Approval-Key']).toBe('approval-key')
  })

  it('resolveApproval posts the decision contract to /v1/approvals/{id}/resolve', async () => {
    fetchMock.mockResolvedValue(new Response('{"ok":true,"status":"approved"}', { status: 200 }))

    await expect(
      api().resolveApproval({ id: 7, decision: 'approve', note: '放行' })
    ).resolves.toMatchObject({ status: 'approved' })

    const [target, init] = lastCall()
    expect(target).toBe('/v1/approvals/7/resolve')
    expect(init.method).toBe('POST')
    expect(init.body).toBe('{"decision":"approve","note":"放行"}')
    const headers = init.headers as Record<string, string>
    expect(headers['X-Nachuan-Approval-Key']).toBe('approval-key')
  })

  it('resolveApproval defaults a missing note to the empty string and validates input', async () => {
    await api().resolveApproval({ id: 3, decision: 'reject' })
    expect(lastCall()[1].body).toBe('{"decision":"reject","note":""}')

    await expect(api().resolveApproval({ id: 0, decision: 'approve' })).rejects.toThrow(
      /invalid approval/
    )
    await expect(
      api().resolveApproval({ id: 1, decision: 'maybe' as 'approve' })
    ).rejects.toThrow(/invalid approval/)
  })

  it('saveConnection posts to /admin/connections/{provider} without provider in the body', async () => {
    await api().saveConnection({
      provider: 'openai-main',
      type: 'openai_compat',
      api_key: 'sk-test',
      base_url: 'https://api.example.com/v1',
      enabled_models: [{ id: 'm1' }],
      preserve_existing_credential: false
    })

    const [target, init] = lastCall()
    expect(target).toBe('/admin/connections/openai-main')
    expect(init.method).toBe('POST')
    expect(JSON.parse(String(init.body))).toEqual({
      type: 'openai_compat',
      api_key: 'sk-test',
      base_url: 'https://api.example.com/v1',
      enabled_models: [{ id: 'm1' }],
      preserve_existing_credential: false
    })
    const headers = init.headers as Record<string, string>
    expect(headers['Authorization']).toBe('Bearer runtime-key')
    expect(headers['X-Nachuan-Approval-Key']).toBe('approval-key')
  })

  it('deleteConnection issues DELETE /admin/connections/{provider} and rejects bad providers', async () => {
    await api().deleteConnection('openai.main-2')
    const [target, init] = lastCall()
    expect(target).toBe('/admin/connections/openai.main-2')
    expect(init.method).toBe('DELETE')

    await expect(api().deleteConnection('../escape')).rejects.toThrow(/invalid provider/)
  })

  it('configureSync posts {url, anon_key} to /v1/sync/config', async () => {
    await api().configureSync('https://supabase.example.com', 'anon-key')
    const [target, init] = lastCall()
    expect(target).toBe('/v1/sync/config')
    expect(init.body).toBe('{"url":"https://supabase.example.com","anon_key":"anon-key"}')
    expect((init.headers as Record<string, string>)['X-Nachuan-Approval-Key']).toBe('approval-key')
  })

  it('authenticateSync posts credentials to /v1/sync/login and /v1/sync/signup', async () => {
    await api().authenticateSync('login', 'u@example.com', 'pw')
    expect(lastCall()[0]).toBe('/v1/sync/login')
    expect(lastCall()[1].body).toBe('{"email":"u@example.com","password":"pw"}')

    await api().authenticateSync('signup', 'u@example.com', 'pw')
    expect(lastCall()[0]).toBe('/v1/sync/signup')

    await expect(
      api().authenticateSync('reset' as 'login', 'u@example.com', 'pw')
    ).rejects.toThrow(/invalid sync credentials/)
  })

  it('toggleSync and runSync hit their routes with approval headers', async () => {
    await api().toggleSync(true)
    expect(lastCall()[0]).toBe('/v1/sync/toggle')
    expect(lastCall()[1].body).toBe('{"enabled":true}')
    expect((lastCall()[1].headers as Record<string, string>)['X-Nachuan-Approval-Key']).toBe(
      'approval-key'
    )

    await api().runSync()
    expect(lastCall()[0]).toBe('/v1/sync/run')
    expect(lastCall()[1].body).toBe('{}')
  })

  it('inspects channel recovery through the exact double-header route and hides principal data', async () => {
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify({
          schema: 'nachuan.weixin-recovery-snapshot.v1',
          target_kind: 'inbound',
          target_key_sha256: 'a'.repeat(64),
          principal_sha256: 'b'.repeat(64),
          expected_before_digest: 'c'.repeat(64),
          affected_counts: { inbound: 1, delivery: 0, video: 0 },
          decision_id: 'd'.repeat(64),
          decided_at_ms: 1_800_000_000_000
        }),
        { status: 200, headers: { 'content-type': 'application/json' } }
      )
    )

    await expect(
      api().inspectChannelRecovery({ channel: 'weixin', targetKind: 'inbound', targetKey: 'msg-1' })
    ).resolves.toEqual({
      schema: 'nachuan.weixin-recovery-snapshot.v1',
      targetKind: 'inbound',
      targetKeySha256: 'a'.repeat(64),
      expectedBeforeDigest: 'c'.repeat(64),
      affectedCounts: { inbound: 1, delivery: 0, video: 0 },
      decisionId: 'd'.repeat(64),
      decidedAtMs: 1_800_000_000_000
    })
    const [target, init] = lastCall()
    expect(target).toBe('/admin/channel-recovery/weixin/inspect')
    expect(init.body).toBe('{"target_kind":"inbound","target_key":"msg-1"}')
    expect((init.headers as Record<string, string>)['X-Nachuan-Approval-Key']).toBe('approval-key')
  })

  it('closes only with the exact stable decision and omits renderer-only target digest', async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          schema: 'nachuan.feishu-recovery-inspect.v1',
          target_kind: 'video',
          target_key_sha256: 'a'.repeat(64),
          expected_before_digest: 'b'.repeat(64),
          affected_counts: { inbox: 0, outbox: 0, video: 1 },
          decision_id: '9'.repeat(64),
          decided_at_ms: 1_800_000_000_001
        }),
        { status: 200, headers: { 'content-type': 'application/json' } }
      )
    ).mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          schema: 'nachuan.channel-recovery-result.v1',
          operation_digest: 'e'.repeat(64),
          receipt_sha256: 'f'.repeat(64),
          affected_counts: { inbox: 0, outbox: 0, video: 1 },
          applied: true
        }),
        { status: 200, headers: { 'content-type': 'application/json' } }
      )
    )

    await expect(
      api().closeChannelRecovery({
        channel: 'feishu',
        targetKind: 'video',
        targetKey: 'task-1',
        targetKeySha256: 'a'.repeat(64),
        expectedBeforeDigest: 'b'.repeat(64),
        decisionId: 'c'.repeat(64),
        decidedAtMs: 1_800_000_000_000,
        reason: 'operator verified no replay',
        userConfirmed: true,
        confirmFinal: true
      })
    ).resolves.toMatchObject({ applied: true, receiptSha256: 'f'.repeat(64) })
    const [target, init] = lastCall()
    expect(target).toBe('/admin/channel-recovery/feishu/close-without-replay')
    const body = JSON.parse(String(init.body))
    expect(body).toEqual({
      target_kind: 'video',
      target_key: 'task-1',
      expected_before_digest: 'b'.repeat(64),
      decision_id: 'c'.repeat(64),
      decided_at_ms: 1_800_000_000_000,
      reason: 'operator verified no replay',
      user_confirmed: true,
      confirm_final: true
    })
    expect(body).not.toHaveProperty('target_key_sha256')
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it('rejects close when the fresh target digest drifted before mutation', async () => {
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify({
          schema: 'nachuan.feishu-recovery-inspect.v1',
          target_kind: 'video',
          target_key_sha256: 'a'.repeat(64),
          expected_before_digest: '8'.repeat(64),
          affected_counts: { inbox: 0, outbox: 0, video: 1 },
          decision_id: '9'.repeat(64),
          decided_at_ms: 1_800_000_000_001
        }),
        { status: 200, headers: { 'content-type': 'application/json' } }
      )
    )
    await expect(
      api().closeChannelRecovery({
        channel: 'feishu',
        targetKind: 'video',
        targetKey: 'task-drift',
        targetKeySha256: 'a'.repeat(64),
        expectedBeforeDigest: 'b'.repeat(64),
        decisionId: 'c'.repeat(64),
        decidedAtMs: 1_800_000_000_000,
        reason: 'operator verified no replay',
        userConfirmed: true,
        confirmFinal: true
      })
    ).rejects.toThrow(/target changed/)
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(lastCall()[0]).toBe('/admin/channel-recovery/feishu/inspect')
  })

  it('uses the same attempted operation for response-loss retry without another target read', async () => {
    const inspectBody = {
      schema: 'nachuan.feishu-recovery-inspect.v1',
      target_kind: 'video',
      target_key_sha256: 'a'.repeat(64),
      expected_before_digest: 'b'.repeat(64),
      affected_counts: { inbox: 0, outbox: 0, video: 1 },
      decision_id: '9'.repeat(64),
      decided_at_ms: 1_800_000_000_001
    }
    const resultBody = {
      schema: 'nachuan.channel-recovery-result.v1',
      operation_digest: 'e'.repeat(64),
      receipt_sha256: 'f'.repeat(64),
      affected_counts: { inbox: 0, outbox: 0, video: 1 },
      applied: false
    }
    fetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify(inspectBody), { status: 200 }))
      .mockRejectedValueOnce(new TypeError('response lost'))
      .mockResolvedValueOnce(new Response(JSON.stringify(resultBody), { status: 200 }))
    const client = api()
    const decision = {
      channel: 'feishu' as const,
      targetKind: 'video' as const,
      targetKey: 'task-response-loss',
      targetKeySha256: 'a'.repeat(64),
      expectedBeforeDigest: 'b'.repeat(64),
      decisionId: 'c'.repeat(64),
      decidedAtMs: 1_800_000_000_000,
      reason: 'operator verified no replay',
      userConfirmed: true as const,
      confirmFinal: true as const
    }
    await expect(client.closeChannelRecovery(decision)).rejects.toThrow(/response lost/)
    await expect(client.closeChannelRecovery(decision)).resolves.toMatchObject({ applied: false })
    expect(fetchMock).toHaveBeenCalledTimes(3)
    expect(fetchMock.mock.calls.filter(([target]) => String(target).endsWith('/inspect'))).toHaveLength(1)
  })

  it('rejects malformed recovery responses and cross-channel target kinds', async () => {
    await expect(
      api().inspectChannelRecovery({ channel: 'weixin', targetKind: 'inbox', targetKey: 'x' })
    ).rejects.toThrow(/invalid channel recovery/)

    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify({
          schema: 'nachuan.feishu-recovery-inspect.v1',
          target_kind: 'video',
          target_key_sha256: '0'.repeat(64),
          expected_before_digest: 'c'.repeat(64),
          affected_counts: { inbox: 0, outbox: 0, video: 1 },
          decision_id: 'd'.repeat(64),
          decided_at_ms: 1
        }),
        { status: 200, headers: { 'content-type': 'application/json' } }
      )
    )
    await expect(
      api().inspectChannelRecovery({ channel: 'feishu', targetKind: 'video', targetKey: 'x' })
    ).rejects.toThrow(/invalid channel recovery/)
  })

  it('omits the approval header when no approval key is stored', async () => {
    delete data['nachuan.web.approvalKey']

    await api().listApprovals('u')
    const headers = lastCall()[1].headers as Record<string, string>
    expect(headers['Authorization']).toBe('Bearer runtime-key')
    expect('X-Nachuan-Approval-Key' in headers).toBe(false)
  })

  it('truthfully rethrows gateway rejections (status + engine detail)', async () => {
    fetchMock.mockResolvedValue(
      new Response('{"detail":"审批管理员 Key 尚未配置；拒绝审批操作"}', { status: 503 })
    )

    const failure = await api().listApprovals('u').catch((error: unknown) => error)
    expect(failure).toBeInstanceOf(WebHttpError)
    expect((failure as WebHttpError).status).toBe(503)
    expect((failure as WebHttpError).message).toContain('审批管理员 Key 尚未配置')
  })
})
