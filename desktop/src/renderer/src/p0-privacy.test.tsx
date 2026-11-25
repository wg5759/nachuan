import React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import i18n from './i18n'
import {
  BROWSER_DEFAULT_HOME,
  BROWSER_PREVIEW_PARTITION,
  configurePreviewWebview
} from './components/BrowserPane'
import {
  ComposerPrivacyControls,
  isLocalModelInfo,
  resolveChatPrivacyFlags
} from './components/ChatPane'

describe('P0 privacy defaults, toggles and webview isolation', () => {
  const engineRequest = vi.fn()
  const engineStream = vi.fn()
  const engineUpload = vi.fn()
  const cancelEngineRequest = vi.fn()

  beforeEach(() => {
    vi.restoreAllMocks()
    engineRequest.mockReset()
    engineStream.mockReset()
    engineUpload.mockReset()
    cancelEngineRequest.mockReset()
    vi.stubGlobal('window', {
      api: { engineRequest, engineStream, engineUpload, cancelEngineRequest }
    })
  })

  it('defaults web_search to false in chatStream and routeChat, and honors incognito override', async () => {
    engineStream.mockImplementation(async (_input, emit) => {
      await emit({ kind: 'start', status: 200, contentType: 'text/event-stream' })
      await emit({ kind: 'chunk', chunk: Uint8Array.from(Buffer.from('data: [DONE]\n\n')) })
      return { status: 200, contentType: 'text/event-stream', bytes: 14 }
    })
    engineRequest.mockResolvedValue({
      status: 200,
      contentType: 'application/json',
      body: Uint8Array.from(Buffer.from('{"choices":[{"message":{"content":"ok"}}]}', 'utf8'))
    })

    const { chatStream, routeChat } = await import('./api')

    // 1) chatStream 默认 web_search 为 false
    for await (const _delta of chatStream('gpt-5.4', [{ role: 'user', content: '你好' }])) {
      // consume
    }
    const defaultBody = JSON.parse(engineStream.mock.calls[0][0].body)
    expect(defaultBody.web_search).toBe(false)
    expect(defaultBody.incognito).toBeUndefined()

    // 2) chatStream 显式开启 webSearch=true 时透传 true
    for await (const _delta of chatStream('gpt-5.4', [{ role: 'user', content: '查天气' }], undefined, true)) {
      // consume
    }
    expect(JSON.parse(engineStream.mock.calls[1][0].body).web_search).toBe(true)

    // 3) chatStream 无痕模式即使传入 webSearch=true 也强制 web_search=false、禁用记忆注入且剥离 conversation_id
    for await (const _delta of chatStream(
      'gpt-5.4',
      [{ role: 'user', content: '私密对话' }],
      undefined,
      true,
      'medium',
      'conv-123',
      { incognito: true }
    )) {
      // consume
    }
    const incBody = JSON.parse(engineStream.mock.calls[2][0].body)
    expect(incBody.web_search).toBe(false)
    expect(incBody.incognito).toBe(true)
    expect(incBody.inject_memory).toBe(false)
    expect(incBody.conversation_id).toBeUndefined()

    // 4) routeChat 默认 web_search 为 false
    await routeChat('smart', [{ role: 'user', content: '你好' }])
    expect(JSON.parse(engineRequest.mock.calls[0][0].body).web_search).toBe(false)

    // 5) routeChat 显式开启 webSearch=true 且非无痕才传 true
    await routeChat('smart', [{ role: 'user', content: '查新闻' }], undefined, undefined, 'c1', {
      webSearch: true
    })
    expect(JSON.parse(engineRequest.mock.calls[1][0].body)).toMatchObject({
      web_search: true,
      conversation_id: 'c1'
    })

    // 6) routeChat 无痕模式强制关闭联网和记忆
    await routeChat('smart', [{ role: 'user', content: '私密' }], undefined, undefined, 'c1', {
      webSearch: true,
      incognito: true
    })
    const routeInc = JSON.parse(engineRequest.mock.calls[2][0].body)
    expect(routeInc.web_search).toBe(false)
    expect(routeInc.incognito).toBe(true)
    expect(routeInc.inject_memory).toBe(false)
    expect(routeInc.conversation_id).toBeUndefined()
  })

  it('resolves chat privacy flags and renders explicit web-search and incognito toggles', async () => {
    await i18n.changeLanguage('zh')

    expect(isLocalModelInfo({ id: 'qwen-local', owned_by: 'ollama' })).toBe(true)
    expect(isLocalModelInfo(undefined, 'local')).toBe(true)
    expect(isLocalModelInfo(undefined, 'llama3:8b')).toBe(true)
    expect(isLocalModelInfo({ id: 'gpt-5.4', owned_by: 'openai' })).toBe(false)

    // 默认关闭联网搜索
    expect(
      resolveChatPrivacyFlags({
        webSearchEnabled: false,
        incognito: false,
        model: { id: 'gpt-5.4', owned_by: 'openai' },
        conversationId: 'c1'
      })
    ).toEqual({
      webSearch: false,
      incognito: false,
      injectMemory: undefined,
      conversationId: 'c1',
      webSearchBlockedBy: null
    })

    // 本地离线模型强制禁搜
    expect(
      resolveChatPrivacyFlags({
        webSearchEnabled: true,
        incognito: false,
        model: { id: 'qwen-local', owned_by: 'ollama' },
        conversationId: 'c1'
      })
    ).toEqual({
      webSearch: false,
      incognito: false,
      injectMemory: undefined,
      conversationId: 'c1',
      webSearchBlockedBy: 'local'
    })

    // 无痕模式强制禁搜、禁用记忆注入、剥离 conversationId
    expect(
      resolveChatPrivacyFlags({
        webSearchEnabled: true,
        incognito: true,
        model: { id: 'gpt-5.4', owned_by: 'openai' },
        conversationId: 'c1'
      })
    ).toEqual({
      webSearch: false,
      incognito: true,
      injectMemory: false,
      conversationId: undefined,
      webSearchBlockedBy: 'incognito'
    })

    const defaultHtml = renderToStaticMarkup(
      <ComposerPrivacyControls
        webSearchEnabled={false}
        onToggleWebSearch={() => undefined}
        incognito={false}
        onToggleIncognito={() => undefined}
        webSearchBlockedBy={null}
      />
    )
    expect(defaultHtml).toContain('data-testid="toggle-web-search"')
    expect(defaultHtml).toContain('aria-pressed="false"')
    expect(defaultHtml).toContain('data-testid="toggle-incognito"')
    expect(defaultHtml).toContain('联网搜索')
    expect(defaultHtml).toContain('无痕')

    const localBlockedHtml = renderToStaticMarkup(
      <ComposerPrivacyControls
        webSearchEnabled={true}
        onToggleWebSearch={() => undefined}
        incognito={false}
        onToggleIncognito={() => undefined}
        webSearchBlockedBy="local"
      />
    )
    expect(localBlockedHtml).toContain('disabled=""')
    expect(localBlockedHtml).toContain('本地离线模型已强制禁用联网搜索')
  })

  it('configures right-pane BrowserPane webview with ephemeral partition and about:blank home', () => {
    expect(BROWSER_DEFAULT_HOME).toBe('about:blank')
    expect(BROWSER_DEFAULT_HOME).not.toContain('bing.com')
    expect(BROWSER_PREVIEW_PARTITION).toBe('nachuan-preview-ephemeral')
    expect(BROWSER_PREVIEW_PARTITION.startsWith('persist:')).toBe(false)

    const attrs: Record<string, string> = {}
    const fakeWebview = {
      setAttribute: (name: string, value: string) => {
        attrs[name] = value
      },
      style: { width: '', height: '' }
    }
    configurePreviewWebview(fakeWebview)
    expect(attrs.partition).toBe('nachuan-preview-ephemeral')
    expect(attrs.src).toBe('about:blank')
    expect(fakeWebview.style).toEqual({ width: '100%', height: '100%' })
  })
})
