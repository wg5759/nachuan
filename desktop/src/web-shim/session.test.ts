import { describe, expect, it, vi } from 'vitest'

import { establishLocalWebSession, persistLocalWebSession } from './session'

function jsonResponse(status: number, payload: unknown): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'content-type': 'application/json' }
  })
}

describe('local Web persistent session', () => {
  it('exchanges a one-time fragment, scrubs it, and never puts it in the request URL', async () => {
    const token = `nc-web-bootstrap-v1-${'B'.repeat(43)}`
    const replaceState = vi.fn()
    const fetchImpl = vi.fn(async () =>
      jsonResponse(200, { authenticated: true, approval: true })
    )

    await expect(
      establishLocalWebSession({
        fetchImpl: fetchImpl as unknown as typeof fetch,
        location: { hash: `#nachuan-bootstrap=${token}`, pathname: '/', search: '' },
        history: { replaceState }
      })
    ).resolves.toBe(true)

    expect(replaceState).toHaveBeenCalledWith(null, '', '/')
    const [target, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit]
    expect(target).toBe('/v1/local-web/session/bootstrap')
    expect(target).not.toContain(token)
    expect(init.body).toBe(JSON.stringify({ token }))
    expect(init.credentials).toBe('same-origin')
    expect((init.headers as Record<string, string>)['X-Nachuan-Web-Session']).toBe('1')
  })

  it('lets a fresh tab reuse an existing HttpOnly session without JavaScript keys', async () => {
    const fetchImpl = vi.fn(async () =>
      jsonResponse(200, { authenticated: true, approval: true })
    )

    await expect(
      establishLocalWebSession({
        fetchImpl: fetchImpl as unknown as typeof fetch,
        location: { hash: '', pathname: '/', search: '' },
        history: { replaceState: vi.fn() }
      })
    ).resolves.toBe(true)

    const [target, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit]
    expect(target).toBe('/v1/local-web/session')
    expect(init.credentials).toBe('same-origin')
  })

  it('adopts manually verified keys into cookies using headers, not URL or body', async () => {
    const fetchImpl = vi.fn(async () =>
      jsonResponse(200, { authenticated: true, approval: true })
    )

    await expect(
      persistLocalWebSession(
        'runtime-key',
        'approval-key',
        fetchImpl as unknown as typeof fetch
      )
    ).resolves.toBe(true)

    const [target, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit]
    expect(target).toBe('/v1/local-web/session/adopt')
    expect(init.body).toBeUndefined()
    expect(target).not.toContain('runtime-key')
    expect((init.headers as Record<string, string>)['Authorization']).toBe(
      'Bearer runtime-key'
    )
    expect((init.headers as Record<string, string>)['X-Nachuan-Approval-Key']).toBe(
      'approval-key'
    )
  })
})
