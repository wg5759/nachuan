import { createHash } from 'node:crypto'
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import type { Socket } from 'node:net'

import { afterEach, describe, expect, it, vi } from 'vitest'

import {
  DESKTOP_ENGINE_SESSION_CHALLENGE_JSON,
  DESKTOP_ENGINE_SESSION_CHALLENGE_PATH,
  type DesktopEngineSessionIdentity,
  signDesktopEngineSessionResponse,
  verifyDesktopEngineSessionRequest
} from './desktop-engine-session-protocol'
import {
  advanceRendererEngineStreamFrameBudget,
  RendererEngineProxy
} from './renderer-engine-proxy'

const SESSION = Object.freeze({
  bootToken: '7a'.repeat(32),
  generation: 3,
  pid: 42_424,
  port: 41_111
})

describe('RendererEngineProxy', () => {
  const servers: Server[] = []

  afterEach(async () => {
    await Promise.all(
      servers.splice(0).map(
        (server) =>
          new Promise<void>((resolve) => {
            server.closeAllConnections()
            server.close(() => resolve())
          })
      )
    )
  })

  it('accepts exactly 8192 stream data frames and rejects the 8193rd', () => {
    let frames = 0
    for (let index = 0; index < 8_192; index += 1) {
      frames = advanceRendererEngineStreamFrameBudget(frames)
    }
    expect(frames).toBe(8_192)
    expect(() => advanceRendererEngineStreamFrameBudget(frames)).toThrow(
      'Renderer Engine request failed'
    )
  })

  it('rejects a renderer-selected path before reading authority or opening transport', async () => {
    const session = vi.fn(() => SESSION)
    const runtimeKey = vi.fn(() => 'sk-local-' + 'a'.repeat(64))
    const transport = vi.fn()
    const proxy = new RendererEngineProxy({ session, runtimeKey, transport })

    await expect(
      proxy.request({
        requestId: '11111111-1111-4111-8111-111111111111',
        method: 'POST',
        target: '/admin/export-secrets',
        bodyKind: 'json',
        body: '{}',
        responseKind: 'json'
      })
    ).rejects.toThrow('Renderer Engine request is not permitted')

    await expect(
      proxy.request({
        requestId: '11111111-1111-4111-8111-111111111112',
        method: 'GET',
        target: '/v1/plugin-ui/snapshot',
        bodyKind: 'none',
        responseKind: 'json'
      })
    ).rejects.toThrow('Renderer Engine request is not permitted')

    expect(session).not.toHaveBeenCalled()
    expect(runtimeKey).not.toHaveBeenCalled()
    expect(transport).not.toHaveBeenCalled()
  })

  it('pins one loopback socket before disclosing the Main-owned runtime key', async () => {
    const runtimeKey = 'sk-local-' + 'b'.repeat(64)
    const sockets = new Set<Socket>()
    let session!: DesktopEngineSessionIdentity
    const server = createServer(async (request, response) => {
      sockets.add(request.socket)
      const body = await readBody(request)
      if (request.url === DESKTOP_ENGINE_SESSION_CHALLENGE_PATH) {
        const verified = verifyDesktopEngineSessionRequest({
          session,
          rawHeaders: request.rawHeaders,
          nowMs: 1_800_000_000_000,
          capability: 'session.challenge',
          method: request.method ?? '',
          target: request.url,
          bodySha256: sha256(body)
        })
        expect(request.headers.authorization).toBeUndefined()
        sendSignedJson(response, session, verified.nonce)
        return
      }
      expect(request.url).toBe('/v1/models')
      expect(request.method).toBe('GET')
      expect(request.headers.authorization).toBe(`Bearer ${runtimeKey}`)
      expect(
        Object.keys(request.headers).filter((name) =>
          name.startsWith('x-nachuan-engine-session-')
        )
      ).toEqual([])
      const payload = Buffer.from('{"data":[{"id":"nachuan"}]}', 'utf8')
      response.writeHead(200, {
        'Content-Type': 'application/json',
        'Content-Length': String(payload.byteLength),
        'Cache-Control': 'no-store',
        Connection: 'close'
      })
      response.end(payload)
    })
    servers.push(server)
    const port = await listen(server)
    session = Object.freeze({ ...SESSION, port })
    const proxy = new RendererEngineProxy({
      session: () => session,
      runtimeKey: () => runtimeKey,
      now: () => 1_800_000_000_000
    })

    const result = await proxy.request({
      requestId: '22222222-2222-4222-8222-222222222222',
      method: 'GET',
      target: '/v1/models',
      bodyKind: 'none',
      responseKind: 'json'
    })

    expect(result.status).toBe(200)
    expect(Buffer.from(result.body).toString('utf8')).toBe('{"data":[{"id":"nachuan"}]}')
    expect(sockets.size).toBe(1)
    expect(JSON.stringify(result)).not.toContain(runtimeKey)
  })

  it('enforces canonical route-specific JSON and binary contracts before transport', async () => {
    const transport = vi.fn(async () => ({
      status: 200,
      contentType: 'application/json',
      body: Uint8Array.from(Buffer.from('{"ok":true}', 'utf8'))
    }))
    const proxy = new RendererEngineProxy({
      session: () => SESSION,
      runtimeKey: () => 'sk-local-' + 'c'.repeat(64),
      transport
    })

    await expect(
      proxy.request({
        requestId: '33333333-3333-4333-8333-333333333333',
        method: 'POST',
        target: '/v1/route',
        bodyKind: 'json',
        body: '{"mode":"smart","messages":[],"web_search":false,"incognito":true,"inject_memory":false}',
        responseKind: 'json'
      })
    ).resolves.toMatchObject({ status: 200 })
    expect(transport).toHaveBeenCalledTimes(1)

    await expect(
      proxy.request({
        requestId: '33333333-3333-4333-8333-333333333334',
        method: 'POST',
        target: '/v1/agent/run',
        bodyKind: 'json',
        body: '{"task":"inspect","stream":false}',
        responseKind: 'json'
      })
    ).resolves.toMatchObject({ status: 200 })
    const transportCalls = transport.mock.calls as unknown as Array<
      [{ policy: { responseBytes: number } }]
    >
    expect(transportCalls[1][0].policy.responseBytes).toBe(64 * 1024 * 1024)

    await expect(
      proxy.request({
        requestId: '44444444-4444-4444-8444-444444444444',
        method: 'POST',
        target: '/v1/route',
        bodyKind: 'json',
        body: '{"mode":"smart","messages":[],"web_search":true,"headers":{}}',
        responseKind: 'json'
      })
    ).rejects.toThrow('Renderer Engine request is not permitted')
    await expect(
      proxy.request({
        requestId: '55555555-5555-4555-8555-555555555555',
        method: 'GET',
        target: '/v1/kb/docs?user_id=%6fwner',
        bodyKind: 'none',
        responseKind: 'json'
      })
    ).rejects.toThrow('Renderer Engine request is not permitted')
    await expect(
      proxy.request({
        requestId: '66666666-6666-4666-8666-666666666666',
        method: 'POST',
        target: '/v1/vision?question=what',
        bodyKind: 'binary',
        body: Uint8Array.from([1, 2, 3]),
        responseKind: 'binary'
      } as never)
    ).rejects.toThrow('Renderer Engine request is not permitted')
    await expect(
      proxy.request({
        requestId: '66666666-6666-4666-8666-666666666667',
        method: 'POST',
        target: '/v1/vision',
        bodyKind: 'binary',
        body: Uint8Array.from([1, 2, 3]),
        responseKind: 'json'
      } as never)
    ).rejects.toThrow('Renderer Engine request is not permitted')

    expect(transport).toHaveBeenCalledTimes(2)
  })

  it('permits /v1/conversations CRUD and import routes while rejecting unknown fields or malformed ids', async () => {
    const transport = vi.fn(async () => ({
      status: 200,
      contentType: 'application/json',
      body: Uint8Array.from(Buffer.from('{"ok":true}', 'utf8'))
    }))
    const proxy = new RendererEngineProxy({
      session: () => SESSION,
      runtimeKey: () => 'sk-local-' + 'a'.repeat(64),
      transport
    })

    const validRequests = [
      {
        requestId: '12121212-1212-4121-8121-121212121201',
        method: 'GET' as const,
        target: '/v1/conversations',
        bodyKind: 'none' as const,
        responseKind: 'json' as const
      },
      {
        requestId: '12121212-1212-4121-8121-121212121202',
        method: 'POST' as const,
        target: '/v1/conversations',
        bodyKind: 'json' as const,
        body: '{"id":"c1","title":"测试","kind":"chat","messages":[]}',
        responseKind: 'json' as const
      },
      {
        requestId: '12121212-1212-4121-8121-121212121203',
        method: 'GET' as const,
        target: '/v1/conversations/c1',
        bodyKind: 'none' as const,
        responseKind: 'json' as const
      },
      {
        requestId: '12121212-1212-4121-8121-121212121204',
        method: 'PATCH' as const,
        target: '/v1/conversations/c1',
        bodyKind: 'json' as const,
        body: '{"title":"改名","archived":true}',
        responseKind: 'json' as const
      },
      {
        requestId: '12121212-1212-4121-8121-121212121205',
        method: 'PUT' as const,
        target: '/v1/conversations/c1/messages',
        bodyKind: 'json' as const,
        body: '{"messages":[{"role":"user","content":"hi"}]}',
        responseKind: 'json' as const
      },
      {
        requestId: '12121212-1212-4121-8121-121212121206',
        method: 'DELETE' as const,
        target: '/v1/conversations/c1',
        bodyKind: 'none' as const,
        responseKind: 'json' as const
      },
      {
        requestId: '12121212-1212-4121-8121-121212121207',
        method: 'POST' as const,
        target: '/v1/conversations/import',
        bodyKind: 'json' as const,
        body: '{"conversations":[]}',
        responseKind: 'json' as const
      }
    ]

    for (const req of validRequests) {
      await expect(proxy.request(req)).resolves.toMatchObject({ status: 200 })
    }
    expect(transport).toHaveBeenCalledTimes(validRequests.length)

    // 拒绝非白名单字段和越权子路径
    await expect(
      proxy.request({
        requestId: '12121212-1212-4121-8121-121212121208',
        method: 'PATCH',
        target: '/v1/conversations/c1',
        bodyKind: 'json',
        body: '{"messages":[]}',
        responseKind: 'json'
      })
    ).rejects.toThrow('Renderer Engine request is not permitted')

    await expect(
      proxy.request({
        requestId: '12121212-1212-4121-8121-121212121209',
        method: 'DELETE',
        target: '/v1/conversations/import',
        bodyKind: 'none',
        responseKind: 'json'
      })
    ).rejects.toThrow('Renderer Engine request is not permitted')

    await expect(
      proxy.request({
        requestId: '12121212-1212-4121-8121-121212121210',
        method: 'PUT',
        target: '/v1/conversations/c1/other',
        bodyKind: 'json',
        body: '{"messages":[]}',
        responseKind: 'json'
      })
    ).rejects.toThrow('Renderer Engine request is not permitted')

    expect(transport).toHaveBeenCalledTimes(validRequests.length)
  })

  it('permits the 7 /v1/workspace/* routes and rejects unknown fields or invalid payloads', async () => {
    const transport = vi.fn(async () => ({
      status: 200,
      contentType: 'application/json',
      body: Uint8Array.from(Buffer.from('{"ok":true}', 'utf8'))
    }))
    const proxy = new RendererEngineProxy({
      session: () => SESSION,
      runtimeKey: () => 'sk-local-' + 'w'.repeat(64),
      transport
    })

    const validRequests = [
      {
        requestId: '34343434-3434-4343-8343-343434343401',
        method: 'GET' as const,
        target: `/v1/workspace/worktrees?repo_path=${encodeURIComponent('D:\\repo\\demo')}`,
        bodyKind: 'none' as const,
        responseKind: 'json' as const
      },
      {
        requestId: '34343434-3434-4343-8343-343434343402',
        method: 'POST' as const,
        target: '/v1/workspace/worktrees',
        bodyKind: 'json' as const,
        body: JSON.stringify({
          repo_path: 'D:\\repo\\demo',
          task_name: 'feat-diff-ui',
          base_ref: 'main'
        }),
        responseKind: 'json' as const
      },
      {
        requestId: '34343434-3434-4343-8343-343434343403',
        method: 'POST' as const,
        target: '/v1/workspace/worktrees/remove',
        bodyKind: 'json' as const,
        body: JSON.stringify({
          repo_path: 'D:\\repo\\demo',
          worktree_path: 'D:\\repo\\.worktrees\\feat-diff-ui',
          force: false,
          delete_branch: true
        }),
        responseKind: 'json' as const
      },
      {
        requestId: '34343434-3434-4343-8343-343434343404',
        method: 'GET' as const,
        target: `/v1/workspace/diff?worktree_path=${encodeURIComponent('D:\\repo\\.worktrees\\feat-diff-ui')}&staged=false`,
        bodyKind: 'none' as const,
        responseKind: 'json' as const
      },
      {
        requestId: '34343434-3434-4343-8343-343434343405',
        method: 'POST' as const,
        target: '/v1/workspace/revert-file',
        bodyKind: 'json' as const,
        body: JSON.stringify({
          worktree_path: 'D:\\repo\\.worktrees\\feat-diff-ui',
          file_path: 'src/app.ts'
        }),
        responseKind: 'json' as const
      },
      {
        requestId: '34343434-3434-4343-8343-343434343406',
        method: 'POST' as const,
        target: '/v1/workspace/commit',
        bodyKind: 'json' as const,
        body: JSON.stringify({
          worktree_path: 'D:\\repo\\.worktrees\\feat-diff-ui',
          message: 'feat: add diff panel',
          files: ['src/app.ts']
        }),
        responseKind: 'json' as const
      },
      {
        requestId: '34343434-3434-4343-8343-343434343407',
        method: 'POST' as const,
        target: '/v1/workspace/exec-plan',
        bodyKind: 'json' as const,
        body: JSON.stringify({
          worktree_path: 'D:\\repo\\.worktrees\\feat-diff-ui',
          mode: 'build',
          command: 'npm test',
          approval_id: 'appr-42'
        }),
        responseKind: 'json' as const
      }
    ]

    for (const req of validRequests) {
      await expect(proxy.request(req)).resolves.toMatchObject({ status: 200 })
    }
    expect(transport).toHaveBeenCalledTimes(validRequests.length)

    // 拒绝非白名单字段、非法枚举与未放行子路径
    const rejectedRequests = [
      {
        requestId: '34343434-3434-4343-8343-343434343408',
        method: 'POST' as const,
        target: '/v1/workspace/worktrees',
        bodyKind: 'json' as const,
        body: JSON.stringify({ repo_path: 'D:\\repo', task_name: 'x', shell: true }),
        responseKind: 'json' as const
      },
      {
        requestId: '34343434-3434-4343-8343-343434343409',
        method: 'POST' as const,
        target: '/v1/workspace/exec-plan',
        bodyKind: 'json' as const,
        body: JSON.stringify({ worktree_path: 'D:\\repo', mode: 'full', command: 'rm -rf .' }),
        responseKind: 'json' as const
      },
      {
        requestId: '34343434-3434-4343-8343-343434343410',
        method: 'GET' as const,
        target: '/v1/workspace/diff?staged=false',
        bodyKind: 'none' as const,
        responseKind: 'json' as const
      },
      {
        requestId: '34343434-3434-4343-8343-343434343411',
        method: 'POST' as const,
        target: '/v1/workspace/arbitrary-exec',
        bodyKind: 'json' as const,
        body: JSON.stringify({ command: 'whoami' }),
        responseKind: 'json' as const
      }
    ]

    for (const req of rejectedRequests) {
      await expect(proxy.request(req)).rejects.toThrow('Renderer Engine request is not permitted')
    }
    expect(transport).toHaveBeenCalledTimes(validRequests.length)
  })

  it('permits all 10 /v1/coding/* routes while rejecting invalid ids, query params, and malformed/extra fields', async () => {
    const transport = vi.fn(async () => ({
      status: 200,
      contentType: 'application/json',
      body: Uint8Array.from(Buffer.from('{"ok":true}', 'utf8'))
    }))
    const proxy = new RendererEngineProxy({
      session: () => SESSION,
      runtimeKey: () => 'sk-local-' + 'a'.repeat(64),
      transport
    })

    const validRequests = [
      {
        requestId: '13131313-1313-4131-8131-131313131301',
        method: 'GET' as const,
        target: '/v1/coding/sessions',
        bodyKind: 'none' as const,
        responseKind: 'json' as const
      },
      {
        requestId: '13131313-1313-4131-8131-131313131302',
        method: 'POST' as const,
        target: '/v1/coding/sessions',
        bodyKind: 'json' as const,
        body: '{"repo_path":"D:\\\\repo","title":"Refactor auth","base_ref":"HEAD","mode":"plan","agent_engine":"codex"}',
        responseKind: 'json' as const
      },
      {
        requestId: '13131313-1313-4131-8131-131313131303',
        method: 'GET' as const,
        target: '/v1/coding/sessions/wt-a1b2c3d4/diff',
        bodyKind: 'none' as const,
        responseKind: 'json' as const
      },
      {
        requestId: '13131313-1313-4131-8131-131313131304',
        method: 'POST' as const,
        target: '/v1/coding/sessions/wt-a1b2c3d4/mode',
        bodyKind: 'json' as const,
        body: '{"mode":"build"}',
        responseKind: 'json' as const
      },
      {
        requestId: '13131313-1313-4131-8131-131313131305',
        method: 'POST' as const,
        target: '/v1/coding/sessions/wt-a1b2c3d4/revert',
        bodyKind: 'json' as const,
        body: '{"path":"src/index.ts"}',
        responseKind: 'json' as const
      },
      {
        requestId: '13131313-1313-4131-8131-131313131306',
        method: 'POST' as const,
        target: '/v1/coding/sessions/wt-a1b2c3d4/commit',
        bodyKind: 'json' as const,
        body: '{"message":"feat: add coding studio","files":["src/index.ts"]}',
        responseKind: 'json' as const
      },
      {
        requestId: '13131313-1313-4131-8131-131313131307',
        method: 'DELETE' as const,
        target: '/v1/coding/sessions/wt-a1b2c3d4?delete_branch=true',
        bodyKind: 'none' as const,
        responseKind: 'json' as const
      },
      {
        requestId: '13131313-1313-4131-8131-131313131308',
        method: 'DELETE' as const,
        target: '/v1/coding/sessions/wt-a1b2c3d4',
        bodyKind: 'none' as const,
        responseKind: 'json' as const
      },
      {
        requestId: '13131313-1313-4131-8131-131313131309',
        method: 'POST' as const,
        target: '/v1/coding/sessions/wt-a1b2c3d4/exec',
        bodyKind: 'json' as const,
        body: '{"command":"git status","timeout":30}',
        responseKind: 'json' as const
      },
      {
        requestId: '13131313-1313-4131-8131-131313131310',
        method: 'GET' as const,
        target: '/v1/coding/approvals?status=pending',
        bodyKind: 'none' as const,
        responseKind: 'json' as const
      },
      {
        requestId: '13131313-1313-4131-8131-131313131311',
        method: 'GET' as const,
        target: '/v1/coding/approvals',
        bodyKind: 'none' as const,
        responseKind: 'json' as const
      },
      {
        requestId: '13131313-1313-4131-8131-131313131312',
        method: 'POST' as const,
        target: '/v1/coding/approvals/cap-12345abcde/resolve',
        bodyKind: 'json' as const,
        body: '{"decision":"approve","note":"lgtm"}',
        responseKind: 'json' as const
      }
    ]

    for (const req of validRequests) {
      await expect(proxy.request(req)).resolves.toMatchObject({ status: 200 })
    }
    expect(transport).toHaveBeenCalledTimes(validRequests.length)

    const forbiddenRequests = [
      // 非法 session_id（路径穿越 / 含斜杠 / 超长）
      {
        requestId: '13131313-1313-4131-8131-131313131320',
        method: 'GET' as const,
        target: '/v1/coding/sessions/../diff',
        bodyKind: 'none' as const,
        responseKind: 'json' as const
      },
      {
        requestId: '13131313-1313-4131-8131-131313131321',
        method: 'GET' as const,
        target: `/v1/coding/sessions/${'a'.repeat(65)}/diff`,
        bodyKind: 'none' as const,
        responseKind: 'json' as const
      },
      {
        requestId: '13131313-1313-4131-8131-131313131322',
        method: 'POST' as const,
        target: '/v1/coding/sessions/wt-1/shell',
        bodyKind: 'json' as const,
        body: '{"command":"ls"}',
        responseKind: 'json' as const
      },
      // 非法 query 参数
      {
        requestId: '13131313-1313-4131-8131-131313131323',
        method: 'DELETE' as const,
        target: '/v1/coding/sessions/wt-1?delete_branch=yes',
        bodyKind: 'none' as const,
        responseKind: 'json' as const
      },
      {
        requestId: '13131313-1313-4131-8131-131313131324',
        method: 'DELETE' as const,
        target: '/v1/coding/sessions/wt-1?delete_branch=true&extra=1',
        bodyKind: 'none' as const,
        responseKind: 'json' as const
      },
      {
        requestId: '13131313-1313-4131-8131-131313131325',
        method: 'GET' as const,
        target: '/v1/coding/approvals?status=unknown',
        bodyKind: 'none' as const,
        responseKind: 'json' as const
      },
      {
        requestId: '13131313-1313-4131-8131-131313131326',
        method: 'GET' as const,
        target: '/v1/coding/approvals?status=pending&limit=10',
        bodyKind: 'none' as const,
        responseKind: 'json' as const
      },
      // 越权字段或非法字段类型
      {
        requestId: '13131313-1313-4131-8131-131313131327',
        method: 'POST' as const,
        target: '/v1/coding/sessions',
        bodyKind: 'json' as const,
        body: '{"repo_path":"D:\\\\repo","title":"t","admin":true}',
        responseKind: 'json' as const
      },
      {
        requestId: '13131313-1313-4131-8131-131313131328',
        method: 'POST' as const,
        target: '/v1/coding/sessions',
        bodyKind: 'json' as const,
        body: '{"repo_path":"D:\\\\repo","title":"t","agent_engine":"evil-shell"}',
        responseKind: 'json' as const
      },
      {
        requestId: '13131313-1313-4131-8131-131313131329',
        method: 'POST' as const,
        target: '/v1/coding/sessions/wt-1/mode',
        bodyKind: 'json' as const,
        body: '{"mode":"root"}',
        responseKind: 'json' as const
      },
      {
        requestId: '13131313-1313-4131-8131-131313131330',
        method: 'POST' as const,
        target: '/v1/coding/sessions/wt-1/commit',
        bodyKind: 'json' as const,
        body: '{"message":"ok","files":[123]}',
        responseKind: 'json' as const
      },
      {
        requestId: '13131313-1313-4131-8131-131313131331',
        method: 'POST' as const,
        target: '/v1/coding/sessions/wt-1/exec',
        bodyKind: 'json' as const,
        body: '{"command":"pytest","timeout":"60"}',
        responseKind: 'json' as const
      },
      {
        requestId: '13131313-1313-4131-8131-131313131332',
        method: 'POST' as const,
        target: '/v1/coding/approvals/cap-1/resolve',
        bodyKind: 'json' as const,
        body: '{"decision":"force"}',
        responseKind: 'json' as const
      },
      {
        requestId: '13131313-1313-4131-8131-131313131333',
        method: 'POST' as const,
        target: '/v1/coding/approvals/../resolve',
        bodyKind: 'json' as const,
        body: '{"decision":"approve"}',
        responseKind: 'json' as const
      }
    ]

    for (const req of forbiddenRequests) {
      await expect(proxy.request(req)).rejects.toThrow('Renderer Engine request is not permitted')
    }
    expect(transport).toHaveBeenCalledTimes(validRequests.length)
  })

  it('rejects the ninth concurrent renderer request before transport admission', async () => {
    const releases: Array<(value: {
      status: number
      contentType: string
      body: Uint8Array
    }) => void> = []
    const transport = vi.fn(
      () =>
        new Promise<{
          status: number
          contentType: string
          body: Uint8Array
        }>((resolve) => releases.push(resolve))
    )
    const session = vi.fn(() => SESSION)
    const runtimeKey = vi.fn(() => 'sk-local-' + '3'.repeat(64))
    const proxy = new RendererEngineProxy({ session, runtimeKey, transport })
    const ids = Array.from(
      { length: 9 },
      (_, index) => `10000000-0000-4000-8000-${String(index + 1).padStart(12, '0')}`
    )
    const request = (requestId: string) =>
      proxy.request({
        requestId,
        method: 'GET',
        target: '/v1/models',
        bodyKind: 'none',
        responseKind: 'json'
      })
    const pending = ids.slice(0, 8).map(request)
    await vi.waitFor(() => expect(transport).toHaveBeenCalledTimes(8))

    const ninth = request(ids[8])
    void ninth.catch(() => undefined)
    await new Promise<void>((resolve) => setImmediate(resolve))
    const admittedBeforeRelease = transport.mock.calls.length
    expect(session).not.toHaveBeenCalled()
    expect(runtimeKey).not.toHaveBeenCalled()

    const response = {
      status: 200,
      contentType: 'application/json',
      body: Uint8Array.from([123, 125])
    }
    releases.forEach((release) => release(response))
    const outcomes = await Promise.allSettled([...pending, ninth])
    expect(admittedBeforeRelease).toBe(8)
    expect(outcomes[8]).toMatchObject({ status: 'rejected' })
    expect((outcomes[8] as PromiseRejectedResult).reason).toMatchObject({
      code: 'ENGINE_BUSY',
      message: 'Renderer Engine is busy'
    })
  })

  it('streams authenticated SSE chunks without returning the runtime key', async () => {
    const runtimeKey = 'sk-local-' + 'd'.repeat(64)
    let session!: DesktopEngineSessionIdentity
    const server = createServer(async (request, response) => {
      const body = await readBody(request)
      if (request.url === DESKTOP_ENGINE_SESSION_CHALLENGE_PATH) {
        const verified = verifyDesktopEngineSessionRequest({
          session,
          rawHeaders: request.rawHeaders,
          nowMs: 1_800_000_000_000,
          capability: 'session.challenge',
          method: request.method ?? '',
          target: request.url,
          bodySha256: sha256(body)
        })
        sendSignedJson(response, session, verified.nonce)
        return
      }
      expect(request.url).toBe('/v1/chat/completions')
      expect(request.headers.authorization).toBe(`Bearer ${runtimeKey}`)
      expect(body.toString('utf8')).toBe(
        '{"model":"nachuan","messages":[],"stream":true,"web_search":true}'
      )
      response.writeHead(200, {
        'Content-Type': 'text/event-stream; charset=utf-8',
        'Cache-Control': 'no-cache',
        Connection: 'close'
      })
      response.write('data: {"choices":[{"delta":{"content":"你"}}]}\n\n')
      response.end('data: [DONE]\n\n')
    })
    servers.push(server)
    const port = await listen(server)
    session = Object.freeze({ ...SESSION, port })
    const proxy = new RendererEngineProxy({
      session: () => session,
      runtimeKey: () => runtimeKey,
      now: () => 1_800_000_000_000
    })
    const events: Array<Record<string, unknown>> = []

    const result = await proxy.stream(
      {
        requestId: '77777777-7777-4777-8777-777777777777',
        method: 'POST',
        target: '/v1/chat/completions',
        bodyKind: 'json',
        body: '{"model":"nachuan","messages":[],"stream":true,"web_search":true}',
        responseKind: 'stream'
      },
      (event) => {
        events.push(event as unknown as Record<string, unknown>)
      }
    )

    expect(result).toMatchObject({ status: 200, contentType: 'text/event-stream; charset=utf-8' })
    expect(events[0]).toMatchObject({ kind: 'start', status: 200 })
    expect(
      Buffer.concat(
        events
          .filter((event) => event.kind === 'chunk')
          .map((event) => Buffer.from(event.chunk as Uint8Array))
      ).toString('utf8')
    ).toContain('data: [DONE]')
    expect(JSON.stringify({ result, events })).not.toContain(runtimeKey)
  })

  it('does not read the next download chunk until the consumer releases its one credit', async () => {
    let sendSecondChunk!: () => void
    const secondChunkAllowed = new Promise<void>((resolve) => {
      sendSecondChunk = resolve
    })
    let session!: DesktopEngineSessionIdentity
    const server = createServer(async (request, response) => {
      const body = await readBody(request)
      if (request.url === DESKTOP_ENGINE_SESSION_CHALLENGE_PATH) {
        const verified = verifyDesktopEngineSessionRequest({
          session,
          rawHeaders: request.rawHeaders,
          nowMs: 1_800_000_000_000,
          capability: 'session.challenge',
          method: request.method ?? '',
          target: request.url,
          bodySha256: sha256(body)
        })
        sendSignedJson(response, session, verified.nonce)
        return
      }
      const first = Buffer.alloc(64 * 1024, 1)
      const second = Buffer.alloc(64 * 1024, 2)
      response.writeHead(200, {
        'Content-Type': 'Video/MP4',
        'Content-Length': String(first.byteLength + second.byteLength),
        Connection: 'close'
      })
      response.write(first)
      await secondChunkAllowed
      response.end(second)
    })
    servers.push(server)
    const port = await listen(server)
    session = Object.freeze({ ...SESSION, port })
    const sessionProvider = vi.fn(() => session)
    const runtimeKey = vi.fn(() => 'sk-local-' + '1'.repeat(64))
    const proxy = new RendererEngineProxy({
      session: sessionProvider,
      runtimeKey,
      now: () => 1_800_000_000_000
    })
    let release!: () => void
    const firstChunkReleased = new Promise<void>((resolve) => {
      release = resolve
    })
    let firstChunkSeen!: () => void
    const sawFirstChunk = new Promise<void>((resolve) => {
      firstChunkSeen = resolve
    })
    const chunks: Uint8Array[] = []

    const pending = proxy.stream(
      {
        requestId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
        method: 'GET',
        target: '/v1/studio/video/job-1',
        bodyKind: 'none',
        responseKind: 'binary'
      },
      async (event) => {
        if (event.kind !== 'chunk') return
        chunks.push(event.chunk)
        if (chunks.length === 1) {
          firstChunkSeen()
          await firstChunkReleased
        }
      }
    )

    await sawFirstChunk
    const sessionCalls = sessionProvider.mock.calls.length
    const keyCalls = runtimeKey.mock.calls.length
    const competing = proxy.stream(
      {
        requestId: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
        method: 'GET',
        target: '/v1/studio/video/job-2',
        bodyKind: 'none',
        responseKind: 'binary'
      },
      vi.fn()
    )
    await expect(competing).rejects.toMatchObject({ code: 'ENGINE_BUSY' })
    expect(sessionProvider).toHaveBeenCalledTimes(sessionCalls)
    expect(runtimeKey).toHaveBeenCalledTimes(keyCalls)
    sendSecondChunk()
    await new Promise<void>((resolve) => setImmediate(resolve))
    expect(chunks).toHaveLength(1)
    release()
    await expect(pending).resolves.toMatchObject({ bytes: 128 * 1024 })
    expect(Buffer.concat(chunks.map((chunk) => Buffer.from(chunk)))).toEqual(
      Buffer.concat([Buffer.alloc(64 * 1024, 1), Buffer.alloc(64 * 1024, 2)])
    )
  })

  it('rejects a declared legacy media response above 16 MiB before emitting stream data', async () => {
    let session!: DesktopEngineSessionIdentity
    const server = createServer(async (request, response) => {
      const body = await readBody(request)
      if (request.url === DESKTOP_ENGINE_SESSION_CHALLENGE_PATH) {
        const verified = verifyDesktopEngineSessionRequest({
          session,
          rawHeaders: request.rawHeaders,
          nowMs: 1_800_000_000_000,
          capability: 'session.challenge',
          method: request.method ?? '',
          target: request.url,
          bodySha256: sha256(body)
        })
        sendSignedJson(response, session, verified.nonce)
        return
      }
      response.writeHead(200, {
        'Content-Type': 'video/mp4',
        'Content-Length': String(16 * 1024 * 1024 + 1),
        Connection: 'close'
      })
      response.end()
    })
    servers.push(server)
    const port = await listen(server)
    session = Object.freeze({ ...SESSION, port })
    const proxy = new RendererEngineProxy({
      session: () => session,
      runtimeKey: () => 'sk-local-' + '4'.repeat(64),
      now: () => 1_800_000_000_000
    })
    const onEvent = vi.fn()

    await expect(
      proxy.stream(
        {
          requestId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
          method: 'GET',
          target: '/v1/studio/video/job-too-large',
          bodyKind: 'none',
          responseKind: 'binary'
        },
        onEvent
      )
    ).rejects.toThrow('Renderer Engine request failed')
    expect(onEvent).not.toHaveBeenCalled()
  })

  it('pulls a binary upload one bounded chunk at a time instead of accepting a full body buffer', async () => {
    const payload = Uint8Array.from([1, 2, 3, 4, 5, 6, 7])
    let uploaded = new Uint8Array()
    let session!: DesktopEngineSessionIdentity
    const server = createServer(async (request, response) => {
      const body = await readBody(request)
      if (request.url === DESKTOP_ENGINE_SESSION_CHALLENGE_PATH) {
        const verified = verifyDesktopEngineSessionRequest({
          session,
          rawHeaders: request.rawHeaders,
          nowMs: 1_800_000_000_000,
          capability: 'session.challenge',
          method: request.method ?? '',
          target: request.url,
          bodySha256: sha256(body)
        })
        sendSignedJson(response, session, verified.nonce)
        return
      }
      uploaded = Uint8Array.from(body)
      const responseBody = Buffer.from('{"text":"ok"}', 'utf8')
      response.writeHead(200, {
        'Content-Type': 'Application/JSON; Charset=UTF-8',
        'Content-Length': String(responseBody.byteLength),
        Connection: 'close'
      })
      response.end(responseBody)
    })
    servers.push(server)
    const port = await listen(server)
    session = Object.freeze({ ...SESSION, port })
    const proxy = new RendererEngineProxy({
      session: () => session,
      runtimeKey: () => 'sk-local-' + '2'.repeat(64),
      now: () => 1_800_000_000_000
    })
    let activeReads = 0
    let maximumActiveReads = 0
    const requestedMaximums: number[] = []

    const result = await proxy.upload(
      {
        requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
        method: 'POST',
        target: '/v1/vision',
        bodyKind: 'binary',
        bodyLength: payload.byteLength,
        responseKind: 'json'
      },
      async (offset, maximumBytes) => {
        activeReads += 1
        maximumActiveReads = Math.max(maximumActiveReads, activeReads)
        requestedMaximums.push(maximumBytes)
        try {
          await Promise.resolve()
          return payload.slice(offset, Math.min(payload.byteLength, offset + maximumBytes))
        } finally {
          activeReads -= 1
        }
      }
    )

    expect(result.status).toBe(200)
    expect(uploaded).toEqual(payload)
    expect(maximumActiveReads).toBe(1)
    expect(requestedMaximums.every((maximum) => maximum > 0 && maximum <= 64 * 1024)).toBe(true)
    expect(JSON.stringify(result)).not.toMatch(/authorization|bearer|api.?key|baseUrl/i)

    await expect(
      proxy.upload(
        {
          requestId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
          method: 'POST',
          target: '/v1/vision',
          bodyKind: 'binary',
          bodyLength: payload.byteLength,
          responseKind: 'json'
        },
        async (offset, maximumBytes) =>
          payload.slice(offset, Math.min(payload.byteLength, offset + Math.max(1, maximumBytes - 1)))
      )
    ).rejects.toThrow('Renderer Engine request failed')
  })

  it('cancels an in-flight challenge before the runtime key can be read', async () => {
    let challengeSeen!: () => void
    const seen = new Promise<void>((resolve) => {
      challengeSeen = resolve
    })
    const server = createServer((request) => {
      request.resume()
      challengeSeen()
    })
    servers.push(server)
    const port = await listen(server)
    const runtimeKey = vi.fn(() => 'sk-local-' + 'e'.repeat(64))
    const proxy = new RendererEngineProxy({
      session: () => Object.freeze({ ...SESSION, port }),
      runtimeKey,
      now: () => 1_800_000_000_000
    })
    const requestId = '88888888-8888-4888-8888-888888888888'
    const pending = proxy.request({
      requestId,
      method: 'GET',
      target: '/v1/models',
      bodyKind: 'none',
      responseKind: 'json'
    })
    await seen

    expect(proxy.cancel(requestId)).toBe(true)
    await expect(pending).rejects.toThrow('Renderer Engine request failed')
    expect(proxy.cancel(requestId)).toBe(false)
    expect(runtimeKey).not.toHaveBeenCalled()
  })

  it('does not return the loopback endpoint in a challenge connection error', async () => {
    const unavailable = createServer()
    const port = await listen(unavailable)
    await new Promise<void>((resolve, reject) => {
      unavailable.close((error) => (error ? reject(error) : resolve()))
    })
    const runtimeKey = vi.fn(() => 'sk-local-' + 'f'.repeat(64))
    const proxy = new RendererEngineProxy({
      session: () => Object.freeze({ ...SESSION, port }),
      runtimeKey,
      now: () => 1_800_000_000_000
    })

    const pending = proxy.request({
      requestId: '99999999-9999-4999-8999-999999999999',
      method: 'GET',
      target: '/v1/models',
      bodyKind: 'none',
      responseKind: 'json'
    })

    await expect(pending).rejects.toMatchObject({
      message: 'Renderer Engine connection failed authentication'
    })
    await expect(pending).rejects.not.toThrow(`127.0.0.1:${port}`)
    expect(runtimeKey).not.toHaveBeenCalled()
  })
})

function sha256(value: Uint8Array): string {
  return createHash('sha256').update(value).digest('hex')
}

async function readBody(request: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = []
  for await (const raw of request) chunks.push(Buffer.isBuffer(raw) ? raw : Buffer.from(raw))
  return Buffer.concat(chunks)
}

function raw(headers: Readonly<Record<string, string>>): string[] {
  return Object.entries(headers).flatMap(([name, value]) => [name, value])
}

function sendSignedJson(
  response: ServerResponse,
  session: DesktopEngineSessionIdentity,
  requestNonce: string
): void {
  const body = Buffer.from(DESKTOP_ENGINE_SESSION_CHALLENGE_JSON, 'utf8')
  const headers = {
    'Content-Type': 'application/json',
    'Content-Length': String(body.byteLength),
    'Cache-Control': 'no-store',
    Connection: 'keep-alive'
  }
  const signed = signDesktopEngineSessionResponse({
    session,
    requestNonce,
    capability: 'session.challenge',
    status: 200,
    bodySha256: sha256(body),
    rawHeaders: raw(headers)
  })
  response.writeHead(200, { ...headers, ...signed.headers })
  response.end(body)
}

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  const address = server.address()
  if (!address || typeof address === 'string') throw new Error('test listener unavailable')
  return address.port
}
