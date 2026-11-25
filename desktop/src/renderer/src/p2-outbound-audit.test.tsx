import React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import {
  clearOutboundAudit,
  getOfflineMode,
  getOutboundAudit,
  setOfflineMode,
  type OutboundAuditItem,
  type OutboundAuditSnapshot
} from './api'
import { AppHeaderView } from './components/AppHeader'
import { ComposerPrivacyControls, resolveChatPrivacyFlags } from './components/ChatPane'
import PrivacyOutboundAuditPanel, {
  buildPrivacyOutboundAuditPanelTree,
  computeOutboundAuditCounts,
  filterOutboundAuditItems,
  performClearOutboundAudit,
  performOfflineModeToggle,
  PrivacyOutboundAuditPanelView,
  type OutboundAuditFilter
} from './components/PrivacyOutboundAuditPanel'
import i18n from './i18n'
import { useAppStore } from './store'

const SAMPLE_ITEMS: OutboundAuditItem[] = [
  {
    id: 1,
    ts_ms: 1_764_050_001_000,
    method: 'GET',
    scheme: 'http',
    host: '127.0.0.1',
    port: 11434,
    path: '/api/tags',
    caller: 'local_models',
    is_loopback: true,
    blocked: false,
    block_reason: '',
    status_code: 200,
    latency_ms: 12,
    error: ''
  },
  {
    id: 2,
    ts_ms: 1_764_050_002_000,
    method: 'POST',
    scheme: 'https',
    host: 'api.openai.com',
    port: 443,
    path: '/v1/chat/completions',
    caller: 'upstream_openai',
    is_loopback: false,
    blocked: false,
    block_reason: '',
    status_code: 200,
    latency_ms: 340,
    error: ''
  },
  {
    id: 3,
    ts_ms: 1_764_050_003_000,
    method: 'GET',
    scheme: 'https',
    host: 'www.bing.com',
    port: 443,
    path: '/search?q=privacy',
    caller: 'web_search',
    is_loopback: false,
    blocked: true,
    block_reason: 'air_gap_offline_mode',
    status_code: null,
    latency_ms: null,
    error: 'blocked by air-gap policy'
  }
]

const SAMPLE_SNAPSHOT: OutboundAuditSnapshot = {
  offline_mode: false,
  total_allowed: 2,
  total_blocked: 1,
  non_loopback_count: 2,
  items: SAMPLE_ITEMS
}

function findElementByTestId(
  node: React.ReactNode,
  testId: string
): React.ReactElement<Record<string, unknown>> | null {
  if (!node || typeof node !== 'object') return null
  if (Array.isArray(node)) {
    for (const child of node) {
      const hit = findElementByTestId(child, testId)
      if (hit) return hit
    }
    return null
  }
  if (!React.isValidElement(node)) return null
  const props = node.props as Record<string, unknown>
  if (props['data-testid'] === testId) {
    return node as React.ReactElement<Record<string, unknown>>
  }
  return findElementByTestId(props.children as React.ReactNode, testId)
}

function jsonResponse(payload: unknown, status = 200): {
  status: number
  contentType: string
  body: Uint8Array
} {
  return {
    status,
    contentType: 'application/json',
    body: Uint8Array.from(Buffer.from(JSON.stringify(payload), 'utf8'))
  }
}

describe('P2 outbound network audit panel, air-gap offline mode, header chip and chat guard', () => {
  const engineRequest = vi.fn()
  const cancelEngineRequest = vi.fn()

  beforeEach(async () => {
    vi.restoreAllMocks()
    engineRequest.mockReset()
    cancelEngineRequest.mockReset()
    useAppStore.getState().setOfflineModeState(false)
    await i18n.changeLanguage('zh')
    vi.stubGlobal('window', {
      api: {
        runtimeKind: 'electron',
        engineRequest,
        engineStream: vi.fn(),
        engineUpload: vi.fn(),
        cancelEngineRequest
      }
    })
  })

  afterEach(async () => {
    await i18n.changeLanguage('zh')
    vi.unstubAllGlobals()
  })

  it('calls privacy audit & offline-mode endpoints cleanly and degrades gracefully when engine is unavailable', async () => {
    engineRequest.mockImplementation(async (req: { method: string; target: string; body?: string }) => {
      if (req.method === 'GET' && req.target.startsWith('/v1/privacy/outbound-audit')) {
        return jsonResponse(SAMPLE_SNAPSHOT)
      }
      if (req.method === 'DELETE' && req.target === '/v1/privacy/outbound-audit') {
        return jsonResponse({ ok: true, cleared: 3 })
      }
      if (req.method === 'GET' && req.target === '/v1/privacy/offline-mode') {
        return jsonResponse({ enabled: true, source: 'env' })
      }
      if (req.method === 'POST' && req.target === '/v1/privacy/offline-mode') {
        const parsed = JSON.parse(req.body ?? '{}') as { enabled: boolean }
        return jsonResponse({ enabled: parsed.enabled })
      }
      return jsonResponse({ detail: 'not found' }, 404)
    })

    const snap = await getOutboundAudit({ limit: 50, since_id: 2, blocked_only: true })
    expect(snap.total_blocked).toBe(1)
    expect(snap.items).toHaveLength(3)
    expect(engineRequest).toHaveBeenCalledWith(
      expect.objectContaining({
        method: 'GET',
        target: '/v1/privacy/outbound-audit?limit=50&since_id=2&blocked_only=true'
      })
    )

    const mode = await getOfflineMode()
    expect(mode).toMatchObject({ enabled: true, source: 'env', ok: true })

    const updated = await setOfflineMode(true)
    expect(updated).toMatchObject({ enabled: true, ok: true })
    expect(engineRequest).toHaveBeenCalledWith(
      expect.objectContaining({
        method: 'POST',
        target: '/v1/privacy/offline-mode',
        body: '{"enabled":true}'
      })
    )

    const cleared = await clearOutboundAudit()
    expect(cleared).toEqual({ ok: true, cleared: 3 })
    expect(engineRequest).toHaveBeenCalledWith(
      expect.objectContaining({
        method: 'DELETE',
        target: '/v1/privacy/outbound-audit'
      })
    )

    // 引擎异常/未就绪时优雅降级不抛未捕获异常
    engineRequest.mockRejectedValue(new Error('engine offline'))
    const degradedSnap = await getOutboundAudit()
    expect(degradedSnap.unavailable).toBe(true)
    expect(degradedSnap.items).toEqual([])
    expect(await clearOutboundAudit()).toEqual({ ok: false, cleared: 0 })
    expect(await getOfflineMode()).toMatchObject({ enabled: false, ok: false })
    expect(await setOfflineMode(true)).toMatchObject({ enabled: false, ok: false })
  })

  it('renders PrivacyOutboundAuditPanel, filters external/blocked rows, and dispatches offline toggle & clear API calls', async () => {
    expect(computeOutboundAuditCounts(SAMPLE_SNAPSHOT)).toEqual({
      externalCount: 2,
      blockedCount: 1,
      loopbackCount: 1
    })
    expect(filterOutboundAuditItems(SAMPLE_ITEMS, 'all')).toHaveLength(3)
    expect(filterOutboundAuditItems(SAMPLE_ITEMS, 'external').map((i) => i.host)).toEqual([
      'api.openai.com',
      'www.bing.com'
    ])
    expect(filterOutboundAuditItems(SAMPLE_ITEMS, 'blocked').map((i) => i.host)).toEqual([
      'www.bing.com'
    ])

    // 全部视图渲染验证（中文）
    const allHtml = renderToStaticMarkup(
      <PrivacyOutboundAuditPanelView
        snapshot={SAMPLE_SNAPSHOT}
        offlineMode={false}
        filter="all"
        paused={false}
        loading={false}
        togglingOffline={false}
        clearing={false}
        onToggleOfflineMode={() => undefined}
        onFilterChange={() => undefined}
        onTogglePolling={() => undefined}
        onRefresh={() => undefined}
        onClear={() => undefined}
      />
    )
    expect(allHtml).toContain('纯离线模式（空气间隙 Air-Gap）')
    expect(allHtml).toContain('127.0.0.1:11434')
    expect(allHtml).toContain('api.openai.com:443')
    expect(allHtml).toContain('www.bing.com:443')
    expect(allHtml).toContain('air_gap_offline_mode')
    expect(allHtml).not.toContain('主题')

    // 仅外网筛选：排除本地回环 127.0.0.1
    const externalHtml = renderToStaticMarkup(
      <PrivacyOutboundAuditPanelView
        snapshot={SAMPLE_SNAPSHOT}
        offlineMode={false}
        filter="external"
        paused={false}
        loading={false}
        togglingOffline={false}
        clearing={false}
        onToggleOfflineMode={() => undefined}
        onFilterChange={() => undefined}
        onTogglePolling={() => undefined}
        onRefresh={() => undefined}
        onClear={() => undefined}
      />
    )
    expect(externalHtml).not.toContain('127.0.0.1:11434')
    expect(externalHtml).toContain('api.openai.com:443')
    expect(externalHtml).toContain('www.bing.com:443')

    // 仅已拦截筛选：只保留被拦的 bing 请求
    const blockedHtml = renderToStaticMarkup(
      <PrivacyOutboundAuditPanelView
        snapshot={SAMPLE_SNAPSHOT}
        offlineMode={true}
        filter="blocked"
        paused={true}
        loading={false}
        togglingOffline={false}
        clearing={false}
        onToggleOfflineMode={() => undefined}
        onFilterChange={() => undefined}
        onTogglePolling={() => undefined}
        onRefresh={() => undefined}
        onClear={() => undefined}
      />
    )
    expect(blockedHtml).not.toContain('api.openai.com:443')
    expect(blockedHtml).toContain('www.bing.com:443')
    expect(blockedHtml).toContain('已开启 · 0 外联')

    // 英文双语切换渲染
    await i18n.changeLanguage('en')
    const enHtml = renderToStaticMarkup(
      <PrivacyOutboundAuditPanelView
        snapshot={SAMPLE_SNAPSHOT}
        offlineMode={true}
        filter="all"
        paused={false}
        loading={false}
        togglingOffline={false}
        clearing={false}
        onToggleOfflineMode={() => undefined}
        onFilterChange={() => undefined}
        onTogglePolling={() => undefined}
        onRefresh={() => undefined}
        onClear={() => undefined}
      />
    )
    expect(enHtml).toContain('Air-Gap Offline Mode')
    expect(enHtml).toContain('Enabled · 0 External')
    expect(enHtml).toContain('Clear log')
    await i18n.changeLanguage('zh')

    // 一键切换纯离线模式 -> POST /v1/privacy/offline-mode；一键清空日志 -> DELETE /v1/privacy/outbound-audit
    engineRequest.mockImplementation(async (req: { method: string; target: string; body?: string }) => {
      if (req.method === 'POST' && req.target === '/v1/privacy/offline-mode') {
        const parsed = JSON.parse(req.body ?? '{}') as { enabled: boolean }
        return jsonResponse({ enabled: parsed.enabled })
      }
      if (req.method === 'DELETE' && req.target === '/v1/privacy/outbound-audit') {
        return jsonResponse({ ok: true, cleared: 3 })
      }
      return jsonResponse({ ...SAMPLE_SNAPSHOT, offline_mode: true })
    })

    let selectedFilter: OutboundAuditFilter = 'all'
    const onToggleOfflineMode = vi.fn(async () => {
      await performOfflineModeToggle(false, useAppStore.getState().toggleOfflineMode)
    })
    const onClear = vi.fn(async () => {
      await performClearOutboundAudit()
    })
    const tree = buildPrivacyOutboundAuditPanelTree(
      {
        snapshot: SAMPLE_SNAPSHOT,
        offlineMode: false,
        filter: selectedFilter,
        paused: false,
        loading: false,
        togglingOffline: false,
        clearing: false,
        onToggleOfflineMode,
        onFilterChange: (next) => {
          selectedFilter = next
        },
        onTogglePolling: () => undefined,
        onRefresh: () => undefined,
        onClear
      },
      (key, opts) => String(i18n.t(key, opts))
    )

    const toggleSwitch = findElementByTestId(tree, 'toggle-offline-mode')
    const clearBtn = findElementByTestId(tree, 'clear-outbound-audit')
    const externalFilterBtn = findElementByTestId(tree, 'filter-external')
    const blockedFilterBtn = findElementByTestId(tree, 'filter-blocked')
    expect(toggleSwitch).not.toBeNull()
    expect(clearBtn).not.toBeNull()
    expect(externalFilterBtn).not.toBeNull()
    expect(blockedFilterBtn).not.toBeNull()

    ;(externalFilterBtn!.props.onClick as () => void)()
    expect(selectedFilter).toBe('external')
    ;(blockedFilterBtn!.props.onClick as () => void)()
    expect(selectedFilter).toBe('blocked')

    await (toggleSwitch!.props.onClick as () => Promise<void>)()
    await (clearBtn!.props.onClick as () => Promise<void>)()

    expect(useAppStore.getState().offlineMode).toBe(true)
    expect(engineRequest).toHaveBeenCalledWith(
      expect.objectContaining({
        method: 'POST',
        target: '/v1/privacy/offline-mode',
        body: '{"enabled":true}'
      })
    )
    expect(engineRequest).toHaveBeenCalledWith(
      expect.objectContaining({
        method: 'DELETE',
        target: '/v1/privacy/outbound-audit'
      })
    )

    // 默认导出组件可安全 SSR 渲染
    const connectedHtml = renderToStaticMarkup(
      <PrivacyOutboundAuditPanel initialSnapshot={SAMPLE_SNAPSHOT} />
    )
    expect(connectedHtml).toContain('data-testid="privacy-outbound-audit-panel"')
  })

  it('renders AppHeader privacy status chip for both modes/languages and navigates to audit settings on click', () => {
    const onOpenSettings = vi.fn()
    const onOpenPrivacyAudit = vi.fn()

    const standardZh = renderToStaticMarkup(
      <AppHeaderView
        runtimeKind="electron"
        engineTone="online"
        engineLabel="引擎在线"
        modelControl={null}
        creativeOpen={false}
        offlineMode={false}
        onToggleNavigation={() => undefined}
        onToggleCreative={() => undefined}
        onOpenSettings={onOpenSettings}
        onOpenPrivacyAudit={onOpenPrivacyAudit}
        onToggleBrowser={() => undefined}
        language="zh"
      />
    )
    expect(standardZh).toContain('data-testid="privacy-status-chip"')
    expect(standardZh).toContain('零遥测审计')
    expect(standardZh).toContain('nachuan-privacy-chip--audit')

    const offlineZh = renderToStaticMarkup(
      <AppHeaderView
        runtimeKind="electron"
        engineTone="online"
        engineLabel="引擎在线"
        modelControl={null}
        creativeOpen={false}
        offlineMode={true}
        onToggleNavigation={() => undefined}
        onToggleCreative={() => undefined}
        onOpenSettings={onOpenSettings}
        onOpenPrivacyAudit={onOpenPrivacyAudit}
        onToggleBrowser={() => undefined}
        language="zh"
      />
    )
    expect(offlineZh).toContain('纯离线 · 0 外联')
    expect(offlineZh).toContain('nachuan-privacy-chip--offline')

    const offlineEn = renderToStaticMarkup(
      <AppHeaderView
        runtimeKind="web"
        engineTone="online"
        engineLabel="Engine online"
        modelControl={null}
        creativeOpen={false}
        offlineMode={true}
        onToggleNavigation={() => undefined}
        onToggleCreative={() => undefined}
        onOpenSettings={onOpenSettings}
        onToggleBrowser={() => undefined}
        language="en"
      />
    )
    expect(offlineEn).toContain('Air-Gapped · 0 External')

    const standardEn = renderToStaticMarkup(
      <AppHeaderView
        runtimeKind="web"
        engineTone="online"
        engineLabel="Engine online"
        modelControl={null}
        creativeOpen={false}
        offlineMode={false}
        onToggleNavigation={() => undefined}
        onToggleCreative={() => undefined}
        onOpenSettings={onOpenSettings}
        onToggleBrowser={() => undefined}
        language="en"
      />
    )
    expect(standardEn).toContain('Zero-Telemetry')

    // 点击隐私芯片直达设置页出站审计面板
    const headerElement = AppHeaderView({
      runtimeKind: 'electron',
      engineTone: 'online',
      engineLabel: '引擎在线',
      modelControl: null,
      creativeOpen: false,
      offlineMode: true,
      onToggleNavigation: () => undefined,
      onToggleCreative: () => undefined,
      onOpenSettings,
      onOpenPrivacyAudit,
      onToggleBrowser: () => undefined,
      language: 'zh'
    })
    const chip = findElementByTestId(headerElement, 'privacy-status-chip')
    expect(chip).not.toBeNull()
    ;(chip!.props.onClick as () => void)()
    expect(onOpenPrivacyAudit).toHaveBeenCalledTimes(1)
  })

  it('disables ChatPane web search button with air-gap tooltip when offlineMode is enabled', async () => {
    const flags = resolveChatPrivacyFlags({
      webSearchEnabled: true,
      incognito: false,
      model: { id: 'gpt-5.4', owned_by: 'openai' },
      conversationId: 'conv-1',
      offlineMode: true
    })
    expect(flags).toEqual({
      webSearch: false,
      incognito: false,
      injectMemory: undefined,
      conversationId: 'conv-1',
      webSearchBlockedBy: 'offline'
    })

    await i18n.changeLanguage('zh')
    const zhHtml = renderToStaticMarkup(
      <ComposerPrivacyControls
        webSearchEnabled={true}
        onToggleWebSearch={() => undefined}
        incognito={false}
        onToggleIncognito={() => undefined}
        webSearchBlockedBy={flags.webSearchBlockedBy}
      />
    )
    expect(zhHtml).toContain('disabled=""')
    expect(zhHtml).toContain('纯离线模式已开启')

    await i18n.changeLanguage('en')
    const enHtml = renderToStaticMarkup(
      <ComposerPrivacyControls
        webSearchEnabled={true}
        onToggleWebSearch={() => undefined}
        incognito={false}
        onToggleIncognito={() => undefined}
        webSearchBlockedBy={flags.webSearchBlockedBy}
      />
    )
    expect(enHtml).toContain('disabled=""')
    expect(enHtml).toContain('Air-gapped offline mode is enabled')
  })
})
