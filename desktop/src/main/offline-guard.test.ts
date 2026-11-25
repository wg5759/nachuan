import { mkdtemp, rm, stat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, describe, expect, it, vi } from 'vitest'

import { downloadPublicMedia } from './media-download'
import {
  isLoopbackOrLocalUrl,
  OfflineGuard,
  OfflineModeError,
  setDesktopOfflineModeEnabled,
  type WebRequestBeforeRequestListener,
  type WebRequestLikeSession
} from './offline-guard'
import { RendererEngineProxy } from './renderer-engine-proxy'
import {
  describeUnavailableEncryptionGuidance,
  SecureConfigError,
  writeSecureConfig,
  type SafeStringStorage
} from './secure-config'

const SESSION = Object.freeze({
  bootToken: '9b'.repeat(32),
  generation: 1,
  pid: 22_222,
  port: 41_222
})

function createMockSession(): {
  session: WebRequestLikeSession
  dispatch: (url: string) => { cancel?: boolean }
} {
  let activeListener: WebRequestBeforeRequestListener | null = null
  const session: WebRequestLikeSession = {
    webRequest: {
      onBeforeRequest(listener) {
        activeListener = listener
      }
    }
  }
  const dispatch = (url: string): { cancel?: boolean } => {
    if (!activeListener) return { cancel: false }
    let verdict: { cancel?: boolean } = {}
    activeListener({ url }, (response) => {
      verdict = response
    })
    return verdict
  }
  return { session, dispatch }
}

const tempRoots: string[] = []

afterEach(async () => {
  setDesktopOfflineModeEnabled(false)
  await Promise.all(
    tempRoots.splice(0).map((root) => rm(root, { recursive: true, force: true }))
  )
})

describe('P2 desktop offline air-gap guard and proxy whitelist', () => {
  it('allows loopback hosts and local schemes while blocking external hosts and deceptive domains', () => {
    const allowedUrls = [
      'http://127.0.0.1:8080/v1/models',
      'https://127.0.0.1/health',
      'http://localhost:5173/',
      'ws://localhost:8080/ws',
      'http://[::1]:8080/v1/privacy/outbound-audit',
      'http://127.77.77.77:9000/local-rpc',
      'file:///D:/app/out/renderer/index.html',
      'data:image/png;base64,iVBORw0KGgo=',
      'blob:http://127.0.0.1:5173/12345678-1234-4123-8123-1234567890ab',
      'about:blank',
      'devtools://devtools/bundled/inspector.html',
      'nachuan-paid-media://sha256/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
    ]
    for (const url of allowedUrls) {
      expect(isLoopbackOrLocalUrl(url), `should allow ${url}`).toBe(true)
    }

    const blockedUrls = [
      '',
      '   ',
      'not-a-valid-url',
      'https://api.openai.com/v1/chat/completions',
      'https://www.bing.com/search?q=test',
      'http://example.com/',
      'wss://remote.example.org/stream',
      'https://127.0.0.1.attacker.com/exfil',
      'http://localhost.evil.test/steal',
      'http://0.0.0.0:8080/',
      'http://10.0.0.8/internal',
      'http://192.168.1.2/router',
      'http://93.184.216.34/',
      'ftp://127.0.0.1/file',
      'javascript:alert(1)'
    ]
    for (const url of blockedUrls) {
      expect(isLoopbackOrLocalUrl(url), `should block ${url}`).toBe(false)
    }
  })

  it('hard-blocks external webRequest traffic on defaultSession and nachuan-preview-ephemeral when offline', () => {
    const guard = new OfflineGuard(false)
    const defaultMock = createMockSession()
    const previewMock = createMockSession()
    const blockedEvents: string[] = []

    guard.attachToSession(defaultMock.session, 'defaultSession', (ev) =>
      blockedEvents.push(`${ev.sessionName}:${ev.url}`)
    )
    guard.attachToSession(previewMock.session, 'nachuan-preview-ephemeral', (ev) =>
      blockedEvents.push(`${ev.sessionName}:${ev.url}`)
    )

    // 常规模式下公网请求放行
    expect(defaultMock.dispatch('https://api.openai.com/v1/models')).toEqual({ cancel: false })
    expect(previewMock.dispatch('https://example.com/page')).toEqual({ cancel: false })
    expect(guard.getBlockedCount()).toBe(0)

    // 开启纯离线空气间隙模式：公网请求被全部拦截，回环与本地协议继续放行
    guard.setEnabled(true)
    expect(defaultMock.dispatch('https://api.openai.com/v1/models')).toEqual({ cancel: true })
    expect(previewMock.dispatch('https://www.bing.com/')).toEqual({ cancel: true })
    expect(defaultMock.dispatch('http://127.0.0.1:41111/v1/privacy/outbound-audit')).toEqual({
      cancel: false
    })
    expect(defaultMock.dispatch('http://127.77.77.77:9090/ping')).toEqual({ cancel: false })
    expect(defaultMock.dispatch('nachuan-paid-media://sha256/abcdef')).toEqual({ cancel: false })
    expect(previewMock.dispatch('about:blank')).toEqual({ cancel: false })
    expect(guard.getBlockedCount()).toBe(2)
    expect(blockedEvents).toEqual([
      'defaultSession:https://api.openai.com/v1/models',
      'nachuan-preview-ephemeral:https://www.bing.com/'
    ])

    // 关闭离线模式后恢复放行
    guard.setEnabled(false)
    expect(previewMock.dispatch('https://example.com/page')).toEqual({ cancel: false })
  })

  it('blocks downloadPublicMedia before DNS lookup or disk write when desktop offline mode is enabled', async () => {
    const root = await mkdtemp(join(tmpdir(), 'nachuan-offline-media-'))
    tempRoots.push(root)
    const destination = join(root, 'blocked.png')
    const resolver = vi.fn(async () => [{ address: '93.184.216.34', family: 4 }])

    setDesktopOfflineModeEnabled(true)
    await expect(
      downloadPublicMedia('https://cdn.example/image.png', destination, 1024, { resolver })
    ).rejects.toThrow(OfflineModeError)
    expect(resolver).not.toHaveBeenCalled()
    await expect(stat(destination)).rejects.toMatchObject({ code: 'ENOENT' })
  })

  it('whitelists privacy audit/offline routes in RendererEngineProxy, rejects invalid payloads, and syncs OfflineGuard', async () => {
    const guard = new OfflineGuard(false)
    const transport = vi.fn(async (input: { method: string; target: string; body: Buffer }) => {
      if (input.method === 'POST' && input.target === '/v1/privacy/offline-mode') {
        const parsed = JSON.parse(input.body.toString('utf8')) as { enabled: boolean }
        return {
          status: 200,
          contentType: 'application/json',
          body: Uint8Array.from(Buffer.from(JSON.stringify({ enabled: parsed.enabled }), 'utf8'))
        }
      }
      if (input.method === 'GET' && input.target === '/v1/privacy/offline-mode') {
        return {
          status: 200,
          contentType: 'application/json',
          body: Uint8Array.from(Buffer.from('{"enabled":true,"source":"runtime"}', 'utf8'))
        }
      }
      if (input.method === 'DELETE' && input.target === '/v1/privacy/outbound-audit') {
        return {
          status: 200,
          contentType: 'application/json',
          body: Uint8Array.from(Buffer.from('{"ok":true,"cleared":4}', 'utf8'))
        }
      }
      return {
        status: 200,
        contentType: 'application/json',
        body: Uint8Array.from(
          Buffer.from(
            JSON.stringify({
              offline_mode: true,
              total_allowed: 1,
              total_blocked: 0,
              non_loopback_count: 0,
              items: []
            }),
            'utf8'
          )
        )
      }
    })

    const proxy = new RendererEngineProxy({
      session: () => SESSION,
      runtimeKey: () => 'sk-local-' + 'd'.repeat(64),
      transport,
      onOfflineModeChanged: (enabled) => {
        guard.setEnabled(enabled)
      }
    })

    // 合法请求全部放行
    await expect(
      proxy.request({
        requestId: 'a1111111-1111-4111-8111-111111111101',
        method: 'GET',
        target: '/v1/privacy/outbound-audit',
        bodyKind: 'none',
        responseKind: 'json'
      })
    ).resolves.toMatchObject({ status: 200 })

    await expect(
      proxy.request({
        requestId: 'a1111111-1111-4111-8111-111111111102',
        method: 'GET',
        target: '/v1/privacy/outbound-audit?limit=100&since_id=5&blocked_only=true',
        bodyKind: 'none',
        responseKind: 'json'
      })
    ).resolves.toMatchObject({ status: 200 })

    await expect(
      proxy.request({
        requestId: 'a1111111-1111-4111-8111-111111111103',
        method: 'DELETE',
        target: '/v1/privacy/outbound-audit',
        bodyKind: 'none',
        responseKind: 'json'
      })
    ).resolves.toMatchObject({ status: 200 })

    await expect(
      proxy.request({
        requestId: 'a1111111-1111-4111-8111-111111111104',
        method: 'GET',
        target: '/v1/privacy/offline-mode',
        bodyKind: 'none',
        responseKind: 'json'
      })
    ).resolves.toMatchObject({ status: 200 })
    expect(guard.isEnabled()).toBe(true)

    await expect(
      proxy.request({
        requestId: 'a1111111-1111-4111-8111-111111111105',
        method: 'POST',
        target: '/v1/privacy/offline-mode',
        bodyKind: 'json',
        body: '{"enabled":false}',
        responseKind: 'json'
      })
    ).resolves.toMatchObject({ status: 200 })
    expect(guard.isEnabled()).toBe(false)

    await expect(
      proxy.request({
        requestId: 'a1111111-1111-4111-8111-111111111106',
        method: 'POST',
        target: '/v1/privacy/offline-mode',
        bodyKind: 'json',
        body: '{"enabled":true}',
        responseKind: 'json'
      })
    ).resolves.toMatchObject({ status: 200 })
    expect(guard.isEnabled()).toBe(true)

    const allowedCount = transport.mock.calls.length
    expect(allowedCount).toBe(6)

    // 非法 body 与非法 query 全部在进入 transport 前拒绝
    const invalidRequests = [
      {
        requestId: 'b1111111-1111-4111-8111-111111111101',
        method: 'POST' as const,
        target: '/v1/privacy/offline-mode',
        bodyKind: 'json' as const,
        body: '{}',
        responseKind: 'json' as const
      },
      {
        requestId: 'b1111111-1111-4111-8111-111111111102',
        method: 'POST' as const,
        target: '/v1/privacy/offline-mode',
        bodyKind: 'json' as const,
        body: '{"enabled":"true"}',
        responseKind: 'json' as const
      },
      {
        requestId: 'b1111111-1111-4111-8111-111111111103',
        method: 'POST' as const,
        target: '/v1/privacy/offline-mode',
        bodyKind: 'json' as const,
        body: '{"enabled":true,"extra":1}',
        responseKind: 'json' as const
      },
      {
        requestId: 'b1111111-1111-4111-8111-111111111104',
        method: 'GET' as const,
        target: '/v1/privacy/outbound-audit?unknown=1',
        bodyKind: 'none' as const,
        responseKind: 'json' as const
      },
      {
        requestId: 'b1111111-1111-4111-8111-111111111105',
        method: 'GET' as const,
        target: '/v1/privacy/outbound-audit?limit=99999',
        bodyKind: 'none' as const,
        responseKind: 'json' as const
      },
      {
        requestId: 'b1111111-1111-4111-8111-111111111106',
        method: 'GET' as const,
        target: '/v1/privacy/outbound-audit?blocked_only=yes',
        bodyKind: 'none' as const,
        responseKind: 'json' as const
      },
      {
        requestId: 'b1111111-1111-4111-8111-111111111107',
        method: 'DELETE' as const,
        target: '/v1/privacy/offline-mode',
        bodyKind: 'none' as const,
        responseKind: 'json' as const
      }
    ]
    for (const req of invalidRequests) {
      await expect(proxy.request(req)).rejects.toThrow('Renderer Engine request is not permitted')
    }
    expect(transport).toHaveBeenCalledTimes(allowedCount)
  })

  it('provides actionable Linux keyring fail-closed guidance without plaintext fallback', async () => {
    const linuxHint = describeUnavailableEncryptionGuidance('linux')
    expect(linuxHint).toContain('gnome-keyring')
    expect(linuxHint).toContain('Secret Service')
    expect(linuxHint).toContain('fail-closed')

    const root = await mkdtemp(join(tmpdir(), 'nachuan-secure-cfg-'))
    tempRoots.push(root)
    const unavailableStorage: SafeStringStorage = {
      isEncryptionAvailable: () => false,
      encryptString: () => Buffer.alloc(0),
      decryptString: () => ''
    }
    expect(() =>
      writeSecureConfig(join(root, 'config.json'), { engineKey: 'secret' }, unavailableStorage, () => undefined)
    ).toThrow(SecureConfigError)
  })
})
