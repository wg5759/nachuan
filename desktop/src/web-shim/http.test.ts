import { describe, expect, it, vi } from 'vitest'

import { createCredentialStore, type KeyValueStorage } from './credentials'
import { createWebHttpClient, WebHttpError } from './http'

function storageWith(entries: Record<string, string>): KeyValueStorage {
  const data: Record<string, string> = { ...entries }
  return {
    getItem: (key: string) => (key in data ? data[key] : null),
    setItem: (key: string, value: string) => {
      data[key] = value
    },
    removeItem: (key: string) => {
      delete data[key]
    }
  }
}

function clientWith(
  fetchImpl: ReturnType<typeof vi.fn>,
  entries: Record<string, string> = { 'nachuan.web.runtimeKey': 'runtime-key' },
  onConsecutiveUnauthorized?: () => void
) {
  return createWebHttpClient({
    credentials: createCredentialStore(() => storageWith(entries)),
    fetchImpl: fetchImpl as unknown as typeof fetch,
    ...(onConsecutiveUnauthorized ? { onConsecutiveUnauthorized } : {})
  })
}

function jsonResponse(status: number, payload: unknown): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'content-type': 'application/json' }
  })
}

describe('web-shim http client', () => {
  it('attaches the runtime Bearer header and reads full responses for any status', async () => {
    const fetchMock = vi.fn(async () => jsonResponse(200, { ok: true }))
    const client = clientWith(fetchMock)

    const response = await client.request({ method: 'GET', target: '/v1/models' })

    expect(response.status).toBe(200)
    expect(response.contentType).toContain('application/json')
    expect(new TextDecoder().decode(response.body)).toBe('{"ok":true}')
    const [target, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit]
    expect(target).toBe('/v1/models')
    expect((init.headers as Record<string, string>)['Authorization']).toBe('Bearer runtime-key')
    expect((init.headers as Record<string, string>)['X-Nachuan-Web-Session']).toBe('1')
    expect(init.credentials).toBe('same-origin')
    expect((init.headers as Record<string, string>)['X-Nachuan-Approval-Key']).toBeUndefined()
  })

  it('omits Authorization when no runtime key is stored (gateway fails closed)', async () => {
    const fetchMock = vi.fn(async () => jsonResponse(401, { detail: '缺少 Bearer Token' }))
    const client = clientWith(fetchMock, {})

    const response = await client.request({ method: 'GET', target: '/v1/models' })

    expect(response.status).toBe(401)
    const [, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit]
    expect((init.headers as Record<string, string>)['Authorization']).toBeUndefined()
  })

  it('sends the approval header only for double-header routes and only when stored', async () => {
    const fetchMock = vi.fn(async () => jsonResponse(200, { pending: [] }))
    const client = clientWith(fetchMock, {
      'nachuan.web.runtimeKey': 'runtime-key',
      'nachuan.web.approvalKey': 'approval-key'
    })

    await client.request({ method: 'GET', target: '/v1/approvals?user_id=u', includeApprovalKey: true })
    await client.request({ method: 'GET', target: '/v1/models', includeApprovalKey: true })

    const first = fetchMock.mock.calls[0] as unknown as [string, RequestInit]
    expect((first[1].headers as Record<string, string>)['X-Nachuan-Approval-Key']).toBe(
      'approval-key'
    )

    const withoutApproval = clientWith(fetchMock, { 'nachuan.web.runtimeKey': 'runtime-key' })
    await withoutApproval.request({
      method: 'GET',
      target: '/v1/approvals?user_id=u',
      includeApprovalKey: true
    })
    const second = fetchMock.mock.calls[2] as unknown as [string, RequestInit]
    expect((second[1].headers as Record<string, string>)['X-Nachuan-Approval-Key']).toBeUndefined()
  })

  it('rejects non same-origin or malformed targets before any fetch', async () => {
    const fetchMock = vi.fn(async () => jsonResponse(200, {}))
    const client = clientWith(fetchMock)

    await expect(client.request({ method: 'GET', target: '//evil.example/x' })).rejects.toThrow(
      /target is invalid/
    )
    await expect(client.request({ method: 'GET', target: 'https://evil.example/x' })).rejects.toThrow(
      /target is invalid/
    )
    await expect(
      client.request({ method: 'GET', target: '/bad\u0000target' })
    ).rejects.toThrow(/target is invalid/)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('requestJson parses 2xx and throws WebHttpError with truthful status and engine text', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse(200, { pending: [1] }))
      .mockResolvedValueOnce(new Response('{"detail":"审批管理员 Key 尚未配置；拒绝审批操作"}', { status: 503 }))
    const client = clientWith(fetchMock)

    await expect(client.requestJson({ method: 'GET', target: '/v1/approvals?user_id=u' })).resolves.toEqual({
      pending: [1]
    })

    const failure = await client
      .requestJson({ method: 'GET', target: '/v1/approvals?user_id=u' })
      .catch((error: unknown) => error)
    expect(failure).toBeInstanceOf(WebHttpError)
    expect((failure as WebHttpError).status).toBe(503)
    expect((failure as WebHttpError).message).toContain('503')
    expect((failure as WebHttpError).message).toContain('审批管理员 Key 尚未配置')
  })

  it('serializes JSON bodies with an application/json content type', async () => {
    const fetchMock = vi.fn(async () => jsonResponse(200, { ok: true }))
    const client = clientWith(fetchMock)

    await client.requestJson({ method: 'POST', target: '/v1/sync/run', json: {} })

    const [, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit]
    expect(init.body).toBe('{}')
    expect((init.headers as Record<string, string>)['Content-Type']).toBe('application/json')
  })

  it('fires onConsecutiveUnauthorized at the threshold and resets on any non-401', async () => {
    const onUnauthorized = vi.fn()
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const target = String(input)
      if (target === '/ok') return jsonResponse(200, {})
      return jsonResponse(401, { detail: '无效的 API Key' })
    })
    const client = clientWith(fetchMock, { 'nachuan.web.runtimeKey': 'stale-key' }, onUnauthorized)

    await client.request({ method: 'GET', target: '/a' })
    expect(onUnauthorized).not.toHaveBeenCalled()
    await client.request({ method: 'GET', target: '/b' })
    expect(onUnauthorized).toHaveBeenCalledTimes(1)

    await client.request({ method: 'GET', target: '/ok' })
    await client.request({ method: 'GET', target: '/c' })
    expect(onUnauthorized).toHaveBeenCalledTimes(1)
    await client.request({ method: 'GET', target: '/d' })
    expect(onUnauthorized).toHaveBeenCalledTimes(2)
  })

  it('opens the login gate when health polling interleaves every rejected model refresh', async () => {
    const onUnauthorized = vi.fn()
    const fetchMock = vi.fn(async (input: RequestInfo | URL) =>
      String(input) === '/health'
        ? jsonResponse(200, { status: 'ok', readiness: 'ok' })
        : jsonResponse(401, { detail: '无效的 API Key' })
    )
    const client = clientWith(
      fetchMock,
      { 'nachuan.web.runtimeKey': 'stale-key' },
      onUnauthorized
    )

    await client.request({ method: 'GET', target: '/health' })
    await client.request({ method: 'GET', target: '/v1/models' })
    expect(onUnauthorized).toHaveBeenCalledTimes(1)

    await client.request({ method: 'GET', target: '/health' })
    await client.request({ method: 'GET', target: '/v1/models' })
    expect(onUnauthorized).toHaveBeenCalledTimes(2)
  })

  it('reopens credential entry after approval 401s separated by successful health polls', async () => {
    const onUnauthorized = vi.fn()
    const fetchMock = vi.fn(async (input: RequestInfo | URL) =>
      String(input) === '/health'
        ? jsonResponse(200, { status: 'ok', readiness: 'ok' })
        : jsonResponse(401, { detail: 'invalid approval key' })
    )
    const client = clientWith(
      fetchMock,
      {
        'nachuan.web.runtimeKey': 'runtime-key',
        'nachuan.web.approvalKey': 'stale-approval-key'
      },
      onUnauthorized
    )

    await client.request({
      method: 'GET',
      target: '/v1/approvals?user_id=owner',
      includeApprovalKey: true
    })
    await client.request({ method: 'GET', target: '/health' })
    await client.request({
      method: 'GET',
      target: '/v1/approvals?user_id=owner',
      includeApprovalKey: true
    })

    expect(onUnauthorized).toHaveBeenCalledTimes(1)
  })

  it('ignores untracked 401s (paid-media trust domain) in the unauthorized counter', async () => {
    const onUnauthorized = vi.fn()
    const fetchMock = vi.fn(async () => jsonResponse(401, { detail: 'unauthorized' }))
    const client = clientWith(fetchMock, { 'nachuan.web.runtimeKey': 'runtime-key' }, onUnauthorized)

    await client.request({ method: 'POST', target: '/v1/paid-media/web/claim', trackUnauthorized: false })
    await client.request({ method: 'POST', target: '/v1/paid-media/web/list', trackUnauthorized: false })
    await client.request({ method: 'POST', target: '/v1/paid-media/web/list', trackUnauthorized: false })
    expect(onUnauthorized).not.toHaveBeenCalled()
  })
})
