import React from 'react'
import { createInstance } from 'i18next'
import { renderToStaticMarkup } from 'react-dom/server'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { CLIENT_PORT_CAPABILITIES } from '../../runtime-capabilities'
import i18n, { I18nextProvider, initReactI18next, useTranslation } from './i18n'
import en from './locales/en.json'
import zh from './locales/zh.json'
import { DocCard } from './components/chat/DocCard'

function fakeLocalStorage(initial: Record<string, string> = {}): Storage {
  const values = new Map(Object.entries(initial))
  return {
    get length() {
      return values.size
    },
    clear: vi.fn(() => values.clear()),
    getItem: vi.fn((key: string) => values.get(key) ?? null),
    key: vi.fn((index: number) => [...values.keys()][index] ?? null),
    removeItem: vi.fn((key: string) => {
      values.delete(key)
    }),
    setItem: vi.fn((key: string, value: string) => {
      values.set(key, value)
    })
  }
}

describe('P1 slim store, zero-license-blocker i18n, and modular ChatPane', () => {
  beforeEach(async () => {
    vi.resetModules()
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
    await i18n.changeLanguage('zh')
  })

  it('provides reactive useTranslation without react-i18next and updates on changeLanguage', async () => {
    const notifications: string[] = []
    const onLang = (lng: string): void => {
      notifications.push(lng)
    }
    i18n.on('languageChanged', onLang)

    function Probe(): React.ReactElement {
      const { t, i18n: activeI18n } = useTranslation()
      return (
        <div>
          <span data-lang={activeI18n.language}>{t('chat.send')}</span>
          <span>{t('chat.docChars', { n: 42 })}</span>
        </div>
      )
    }

    try {
      const zhHtml = renderToStaticMarkup(<Probe />)
      expect(zhHtml).toContain('data-lang="zh"')
      expect(zhHtml).toContain(i18n.t('chat.send'))
      expect(zhHtml).toContain('42')

      await i18n.changeLanguage('en')
      const enHtml = renderToStaticMarkup(<Probe />)
      expect(enHtml).toContain('data-lang="en"')
      expect(enHtml).toContain(en.chat.send)
      expect(notifications).toContain('en')

      // 独立实例经 I18nextProvider 隔离注入
      const custom = createInstance()
      await custom.use(initReactI18next).init({
        resources: { zh: { translation: zh }, en: { translation: en } },
        lng: 'zh',
        fallbackLng: 'en',
        interpolation: { escapeValue: false }
      })
      const scopedHtml = renderToStaticMarkup(
        <I18nextProvider i18n={custom}>
          <Probe />
        </I18nextProvider>
      )
      expect(scopedHtml).toContain('data-lang="zh"')
      expect(scopedHtml).toContain(zh.chat.send)
    } finally {
      i18n.off('languageChanged', onLang)
      await i18n.changeLanguage('zh')
    }
  })

  it('never writes conversations transcripts to localStorage and keeps persisted prefs under 2KB', async () => {
    const engineRequest = vi.fn().mockResolvedValue({
      status: 200,
      contentType: 'application/json',
      body: Uint8Array.from(Buffer.from('{"id":"c-test"}', 'utf8'))
    })
    vi.stubGlobal('localStorage', fakeLocalStorage())
    vi.stubGlobal('window', {
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      api: {
        engineRequest,
        engineStream: vi.fn(),
        engineUpload: vi.fn(),
        cancelEngineRequest: vi.fn()
      }
    })

    const { flushAppStorePersistence, useAppStore } = await import('./store')
    const convId = useAppStore.getState().newConversation('chat')
    const hugeTranscript = '这是一段很长的敏感聊天记录正文'.repeat(400)
    useAppStore.getState().setConvMessages(convId, [
      {
        role: 'user',
        content: hugeTranscript,
        ts: 1001,
        docs: [{ name: 'secret.md', chars: 5000, content: '机密附件内容'.repeat(200) }]
      },
      {
        role: 'assistant',
        content: '助手详细回复全文'.repeat(300),
        ts: 1002
      }
    ])
    expect(flushAppStorePersistence()).toBe(true)

    const raw = localStorage.getItem('agg-conversations')
    expect(raw).toBeTruthy()
    expect(Buffer.byteLength(raw!, 'utf8')).toBeLessThan(2048)
    const parsed = JSON.parse(raw!) as { state: Record<string, unknown> }
    expect(parsed.state.conversations).toBeUndefined()
    expect(raw).not.toContain('这是一段很长的敏感聊天记录正文')
    expect(raw).not.toContain('机密附件内容')
    expect(raw).not.toContain('助手详细回复全文')

    // 无痕会话绝不落盘到服务端
    engineRequest.mockClear()
    const incognitoId = useAppStore.getState().newConversation('chat', { incognito: true })
    useAppStore.getState().setConvMessages(incognitoId, [
      { role: 'user', content: '无痕机密', ts: 2001 }
    ])
    useAppStore.getState().renameConversation(incognitoId, '无痕改名')
    useAppStore.getState().archiveConversation(incognitoId, true)
    flushAppStorePersistence()
    await Promise.resolve()
    const convApiCalls = engineRequest.mock.calls.filter((call) =>
      String(call[0]?.target ?? '').startsWith('/v1/conversations')
    )
    expect(convApiCalls).toHaveLength(0)
  })

  it('migrates legacy localStorage conversations via POST /v1/conversations/import and strips local transcripts', async () => {
    const legacyConversation = {
      id: 'legacy-conv-1',
      title: '旧历史会话',
      kind: 'chat',
      createdAt: 1700000000000,
      updatedAt: 1700000001000,
      messages: [
        { role: 'user', content: '老版本 localStorage 聊天记录全文', ts: 1700000000000 },
        { role: 'assistant', content: '服务端迁移应完整接管这段回复', ts: 1700000000500 }
      ]
    }
    const serverAuthoritative = {
      ...legacyConversation,
      title: '旧历史会话（服务端权威）'
    }

    const storage = fakeLocalStorage({
      'agg-conversations': JSON.stringify({
        state: {
          currentModel: 'nachuan',
          currentConvId: 'legacy-conv-1',
          soundEnabled: true,
          conversations: [legacyConversation]
        },
        version: 0
      })
    })
    const engineRequest = vi.fn(async (req: { method: string; target: string; body?: string }) => {
      if (req.method === 'POST' && req.target === '/v1/conversations/import') {
        return {
          status: 200,
          contentType: 'application/json',
          body: Uint8Array.from(Buffer.from('{"imported":1,"skipped":0}', 'utf8'))
        }
      }
      if (req.method === 'GET' && req.target === '/v1/conversations') {
        return {
          status: 200,
          contentType: 'application/json',
          body: Uint8Array.from(
            Buffer.from(JSON.stringify({ conversations: [serverAuthoritative] }), 'utf8')
          )
        }
      }
      return {
        status: 404,
        contentType: 'application/json',
        body: Uint8Array.from(Buffer.from('{"detail":"not found"}', 'utf8'))
      }
    })

    vi.stubGlobal('localStorage', storage)
    vi.stubGlobal('window', {
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      api: {
        engineRequest,
        engineStream: vi.fn(),
        engineUpload: vi.fn(),
        cancelEngineRequest: vi.fn()
      }
    })

    const { useAppStore } = await import('./store')
    await useAppStore.getState().hydrateConversationsFromServer()

    const importCall = engineRequest.mock.calls.find(
      ([req]) => req.method === 'POST' && req.target === '/v1/conversations/import'
    )
    expect(importCall).toBeDefined()
    const importedBody = JSON.parse(importCall![0].body!) as {
      conversations: Array<{ id: string; messages: unknown[] }>
    }
    expect(importedBody.conversations).toHaveLength(1)
    expect(importedBody.conversations[0].id).toBe('legacy-conv-1')

    const listCall = engineRequest.mock.calls.find(
      ([req]) => req.method === 'GET' && req.target === '/v1/conversations'
    )
    expect(listCall).toBeDefined()

    // 迁移成功后 localStorage 已清除旧全文
    const rewrittenRaw = localStorage.getItem('agg-conversations')
    expect(rewrittenRaw).toBeTruthy()
    const rewritten = JSON.parse(rewrittenRaw!) as { state: Record<string, unknown> }
    expect(rewritten.state.conversations).toBeUndefined()
    expect(rewrittenRaw).not.toContain('老版本 localStorage 聊天记录全文')

    // 内存 store 已同步为服务端权威版本
    expect(useAppStore.getState().conversationsHydrated).toBe(true)
    expect(useAppStore.getState().conversations[0].title).toBe('旧历史会话（服务端权威）')
  })

  it('renders modularized ChatPane with privacy toggles, /health.features gates, and extracted subcomponents', async () => {
    const engineRequest = vi.fn().mockResolvedValue({
      status: 200,
      contentType: 'application/json',
      body: Uint8Array.from(
        Buffer.from(
          JSON.stringify({
            status: 'ok',
            readiness: 'ok',
            checks: { financial_ledger: { required: true, ready: true } },
            features: { voice: false, stt: false, web_search: false, conversations: true }
          }),
          'utf8'
        )
      )
    })
    vi.stubGlobal('localStorage', fakeLocalStorage())
    vi.stubGlobal('window', {
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      api: {
        runtimeKind: 'web',
        runtimeCapabilities: CLIENT_PORT_CAPABILITIES,
        engineRequest,
        engineStream: vi.fn(),
        engineUpload: vi.fn(),
        cancelEngineRequest: vi.fn()
      }
    })

    const { default: freshI18n } = await import('./i18n')
    await freshI18n.changeLanguage('zh')
    const { probeEngineHealth } = await import('./api')
    const { useAppStore } = await import('./store')
    const {
      default: ChatPane,
      ComposerAttachmentRow,
      ComposerPrivacyControls,
      observePaidMediaNearViewport,
      resolveChatPrivacyFlags
    } = await import('./components/ChatPane')

    // 1) /health.features 探测并写入 store
    const health = await probeEngineHealth()
    expect(health.status).toBe('online')
    expect(health.features).toEqual({
      voice: false,
      stt: false,
      web_search: false,
      conversations: true
    })
    useAppStore.getState().setEngineFeatures(health.features)
    expect(useAppStore.getState().engineFeatures.voice).toBe(false)
    expect(useAppStore.getState().engineFeatures.web_search).toBe(false)

    // 2) 拆解后的 ChatPane 完整渲染（默认关闭联网搜索，提供无痕切换与语音入口）
    const chatHtml = renderToStaticMarkup(<ChatPane />)
    expect(chatHtml).toContain('data-testid="toggle-web-search"')
    expect(chatHtml).toContain('aria-pressed="false"')
    expect(chatHtml).toContain('data-testid="toggle-incognito"')

    // 3) /health.features 关闭联网搜索时强拦截并渲染禁用态
    const featureBlocked = resolveChatPrivacyFlags({
      webSearchEnabled: true,
      incognito: false,
      model: { id: 'gpt-5.4', owned_by: 'openai' },
      conversationId: 'c1',
      webSearchFeatureEnabled: health.features.web_search !== false
    })
    expect(featureBlocked).toEqual({
      webSearch: false,
      incognito: false,
      injectMemory: undefined,
      conversationId: 'c1',
      webSearchBlockedBy: 'feature'
    })
    const featureBlockedHtml = renderToStaticMarkup(
      <ComposerPrivacyControls
        webSearchEnabled={true}
        onToggleWebSearch={() => undefined}
        incognito={false}
        onToggleIncognito={() => undefined}
        webSearchBlockedBy={featureBlocked.webSearchBlockedBy}
      />
    )
    expect(featureBlockedHtml).toContain('disabled=""')
    expect(featureBlockedHtml).toContain('当前引擎未启用联网搜索能力')

    const docHtml = renderToStaticMarkup(
      <DocCard doc={{ name: 'spec.md', chars: 128, content: 'hello spec' }} />
    )
    expect(docHtml).toContain('spec.md')
    expect(docHtml).toContain('128')

    const attachHtml = renderToStaticMarkup(
      <ComposerAttachmentRow
        runtimeKind="electron"
        runtimeCapabilities={CLIENT_PORT_CAPABILITIES}
        onPickFile={() => undefined}
        onPickFolder={() => undefined}
      />
    )
    expect(attachHtml).toContain(zh.chat.addFile)
    expect(attachHtml).toContain(zh.chat.addFolder)

    const privacyHtml = renderToStaticMarkup(
      <ComposerPrivacyControls
        webSearchEnabled={false}
        onToggleWebSearch={() => undefined}
        incognito={true}
        onToggleIncognito={() => undefined}
        webSearchBlockedBy="incognito"
      />
    )
    expect(privacyHtml).toContain('aria-pressed="true"')
    expect(typeof observePaidMediaNearViewport).toBe('function')
  })
})
