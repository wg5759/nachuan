import React, { useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  type CatalogModel,
  type CatalogProvider,
  type ConnectionFailureReasonCode,
  type ConnectionSummary,
  type LocalCatalog,
  type LocalServer,
  type SubscriptionConnector,
  type SubscriptionConnectorState,
  deleteConnection,
  detectLocal,
  fetchCatalog,
  fetchConnections,
  fetchLocalCatalog,
  fetchModels,
  fetchSubscriptionConnectors,
  fetchUpstreamModels,
  saveConnection,
  selectLocalModel,
} from '../api'
import { useAppStore } from '../store'
import {
  canPreserveExistingCredential,
  connectDetectedLocalServer,
  connectionModelChoices,
  disconnectStoredConnection,
  formatVerifiedAt,
  hasCustomizedModelSelection,
  initialEnabledModelIds,
  loginModelForVerification,
  orphanConnectionEntries,
  recommendedCatalogChatModel,
  recommendedLocalChatModel,
  refreshVerifiedConnectionModels,
  selectedCatalogModelsForSave,
  shouldAutoDiscoverCatalogModels,
  shouldOfferDisconnect,
  shouldPreserveExistingCredential,
  shouldShowConnectionProvider
} from './connection-center-state'

const REGION_ORDER = ['subscription', 'cn', 'intl', 'local'] as const
const REGION_KEY: Record<string, string> = {
  subscription: 'conn.regionSubscription',
  cn: 'conn.regionCn',
  intl: 'conn.regionIntl',
  local: 'conn.regionLocal'
}

export type QuickConnectionTarget =
  | 'deepseek'
  | 'kimi-api'
  | 'subscription'
  | 'local'
  | 'all'

export function ConnectionQuickStart({
  verifiedConnections,
  onTarget,
  onStartChat
}: {
  verifiedConnections: number
  onTarget: (target: QuickConnectionTarget) => void
  onStartChat?: () => void
}): React.ReactNode {
  const { t } = useTranslation()
  const ready = verifiedConnections > 0
  return (
    <section className="rounded-xl border border-blue-900/70 bg-blue-950/25 p-4">
      <div className="text-xs font-medium uppercase tracking-wider text-blue-300">
        {t('conn.quick.eyebrow')}
      </div>
      <div className="mt-1 font-medium text-blue-100">
        {ready ? t('conn.quick.readyTitle') : t('conn.quick.title')}
      </div>
      <div className="mt-1 text-xs leading-5 text-neutral-400">
        {ready
          ? t('conn.quick.readyHint', { n: verifiedConnections })
          : t('conn.quick.hint')}
      </div>
      {ready ? (
        <button
          type="button"
          onClick={onStartChat}
          disabled={!onStartChat}
          className="mt-3 rounded-lg bg-blue-600 px-4 py-2 text-sm text-white hover:bg-blue-500 disabled:opacity-40"
        >
          {t('conn.quick.startChat')}
        </button>
      ) : (
        <div className="mt-3 flex flex-wrap gap-2">
          {(
            [
              ['deepseek', 'conn.quick.deepseek'],
              ['kimi-api', 'conn.quick.kimiApi'],
              ['subscription', 'conn.quick.subscription'],
              ['local', 'conn.quick.local'],
              ['all', 'conn.quick.all']
            ] as const
          ).map(([target, key]) => (
            <button
              key={target}
              type="button"
              data-quick-target={target}
              onClick={() => onTarget(target)}
              className="rounded-lg border border-neutral-700 bg-neutral-950/50 px-3 py-2 text-sm text-neutral-200 hover:border-blue-700 hover:bg-blue-950/40"
            >
              {t(key)}
            </button>
          ))}
        </div>
      )}
    </section>
  )
}

export default function ConnectionCenter({
  onStartChat
}: {
  onStartChat?: () => void
} = {}): React.ReactNode {
  const { t } = useTranslation()
  const [catalog, setCatalog] = useState<CatalogProvider[]>([])
  const [connections, setConnections] = useState<Record<string, ConnectionSummary>>({})
  const [query, setQuery] = useState('')
  const [showUnavailable, setShowUnavailable] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const refreshEpoch = useRef(0)
  const changedEpoch = useRef(0)
  const setModels = useAppStore((s) => s.setModels)
  const models = useAppStore((s) => s.models)

  // 只把完成候选验证并持久化回执的来源显示为“已连接”。
  // EXE 存在、配置已保存或临时出现在模型列表中，都不能冒充已验证连接。
  const connectedProviders = useMemo(
    () =>
      new Set(
        Object.entries(connections)
          .filter(([, connection]) => connection.state === 'verified')
          .map(([provider]) => provider)
      ),
    [connections]
  )

  const jumpToQuickTarget = (target: QuickConnectionTarget): void => {
    const selection: Record<QuickConnectionTarget, { query: string; selector?: string }> = {
      deepseek: { query: 'DeepSeek', selector: '[data-connection-provider="deepseek"]' },
      'kimi-api': { query: '月之暗面', selector: '[data-connection-provider="moonshot"]' },
      subscription: { query: '', selector: '[data-connection-section="subscription"]' },
      local: { query: '', selector: '[data-connection-section="local"]' },
      all: { query: '' }
    }
    const next = selection[target]
    const selector = next.selector
    setQuery(next.query)
    if (selector) {
      window.setTimeout(() => {
        document
          .querySelector(selector)
          ?.scrollIntoView({ behavior: 'smooth', block: 'start' })
      }, 0)
    }
  }

  const refresh = async (): Promise<boolean> => {
    const epoch = ++refreshEpoch.current
    try {
      const [cat, conns] = await Promise.all([fetchCatalog(), fetchConnections()])
      if (epoch !== refreshEpoch.current) return true
      setCatalog(cat)
      setConnections(conns)
      setError(null)
      return true
    } catch (e) {
      if (epoch !== refreshEpoch.current) return true
      setError(String(e))
      return false
    }
  }

  useEffect(() => {
    void refresh()
  }, [])

  const afterChange = async (): Promise<void> => {
    const epoch = ++changedEpoch.current
    if (!(await refresh())) throw new Error('connection state refresh failed')
    try {
      const nextModels = await fetchModels()
      if (epoch === changedEpoch.current) setModels(nextModels)
    } catch {
      /* ignore */
    }
  }

  const confirmConnectionActivation = async (
    expectedModelIds: readonly string[]
  ): Promise<boolean> => {
    const epoch = ++changedEpoch.current
    if (!(await refresh())) throw new Error('connection state refresh failed')
    let committed = false
    const confirmed = await refreshVerifiedConnectionModels(
      expectedModelIds,
      fetchModels,
      (nextModels) => {
        if (epoch !== changedEpoch.current) return
        committed = true
        setModels(nextModels)
      }
    )
    return committed && confirmed
  }

  const groups = useMemo(() => {
    const q = query.trim().toLowerCase()
    const g: Record<string, CatalogProvider[]> = {}
    for (const p of catalog) {
      if (q && !`${p.label} ${p.name}`.toLowerCase().includes(q)) continue
      if (!shouldShowConnectionProvider(p.connectable, showUnavailable, connections[p.name])) continue
      const key = p.auth === 'login' ? 'subscription' : p.region || 'intl'
      ;(g[key] ||= []).push(p)
    }
    return g
  }, [catalog, connections, query, showUnavailable])
  const orphanConnections = useMemo(() => {
    const q = query.trim().toLowerCase()
    return orphanConnectionEntries(catalog, connections).filter(
      ({ provider }) => !q || provider.toLowerCase().includes(q)
    )
  }, [catalog, connections, query])

  return (
    <div className="p-4 space-y-5 overflow-auto h-full">
      <div className="flex items-center justify-between gap-3">
        <h2 className="text-lg font-semibold">{t('conn.title')}</h2>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setShowUnavailable((value) => !value)}
            className="px-2 py-1 rounded border border-neutral-700 text-xs text-neutral-400 hover:bg-neutral-800"
          >
            {showUnavailable ? t('conn.hideUnavailable') : t('conn.showUnavailable')}
          </button>
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={t('conn.search')}
            className="px-2 py-1 rounded bg-neutral-950 border border-neutral-700 text-sm w-48"
          />
        </div>
      </div>
      {error && <div className="text-red-400 text-sm">{error}</div>}

      <ConnectionQuickStart
        verifiedConnections={connectedProviders.size}
        onTarget={jumpToQuickTarget}
        onStartChat={onStartChat}
      />

      <SubscriptionConnectorPanel />
      <LocalModelPicker />
      <LocalDetect
        connectedProviders={connectedProviders}
        onVerified={confirmConnectionActivation}
      />

      {orphanConnections.length > 0 && (
        <section className="space-y-3">
          <div className="text-xs uppercase tracking-wide text-amber-400">
            {t('conn.orphanTitle')} · {orphanConnections.length}
          </div>
          {orphanConnections.map(({ provider, connection }) => (
            <OrphanConnectionCard
              key={provider}
              provider={provider}
              connection={connection}
              onChanged={afterChange}
            />
          ))}
        </section>
      )}

      {REGION_ORDER.map((region) => {
        const items = groups[region]
        if (!items || items.length === 0) return null
        return (
          <section key={region} className="space-y-3">
            <div className="text-xs uppercase tracking-wide text-neutral-500">
              {t(REGION_KEY[region])} · {items.length}
            </div>
            {items.map((p) => (
              <ProviderCard
                key={p.name}
                provider={p}
                connected={connectedProviders.has(p.name)}
                connection={connections[p.name]}
                onChanged={afterChange}
                onVerified={confirmConnectionActivation}
              />
            ))}
          </section>
        )
      })}
    </div>
  )
}

type SubscriptionConnectorLoadState = 'loading' | 'ready' | 'error'

const SUBSCRIPTION_CONNECTOR_ORDER = ['codex', 'kimi-code'] as const
const SUBSCRIPTION_CONNECTOR_LABEL: Record<(typeof SUBSCRIPTION_CONNECTOR_ORDER)[number], string> = {
  codex: 'Codex',
  'kimi-code': 'Kimi Code'
}
const SUBSCRIPTION_CONNECTOR_LOGIN_COMMAND: Record<
  (typeof SUBSCRIPTION_CONNECTOR_ORDER)[number],
  string
> = {
  codex: 'codex login --device-auth',
  'kimi-code': 'nachuan kimi login'
}
const CATALOG_LOGIN_INSTRUCTION = {
  codex: {
    provider: 'Codex',
    command: 'codex login --device-auth'
  },
  kimi_code: {
    provider: 'Kimi Code',
    command: 'nachuan kimi login'
  }
} as const
type CatalogLoginType = keyof typeof CATALOG_LOGIN_INSTRUCTION

function catalogLoginInstruction(
  providerType: string
): (typeof CATALOG_LOGIN_INSTRUCTION)[CatalogLoginType] | null {
  if (providerType !== 'codex' && providerType !== 'kimi_code') return null
  return CATALOG_LOGIN_INSTRUCTION[providerType]
}

const KIMI_CONNECTION_FAILURE_KEYS: Partial<Record<ConnectionFailureReasonCode, string>> = {
  reauth_required: 'conn.kimiFailureReauth',
  text_contract_rejected: 'conn.kimiFailureTextContract',
  connector_unavailable: 'conn.kimiFailureUnavailable'
}

const CONNECTION_FAILURE_KEYS: Partial<Record<ConnectionFailureReasonCode, string>> = {
  invalid_credentials: 'conn.failure.invalidCredentials',
  quota_or_rate_limited: 'conn.failure.quotaOrRateLimited',
  model_or_endpoint_not_found: 'conn.failure.modelOrEndpointNotFound',
  network_or_timeout: 'conn.failure.networkOrTimeout',
  upstream_unavailable: 'conn.failure.upstreamUnavailable',
  invalid_request: 'conn.failure.invalidRequest',
  connector_unavailable: 'conn.failure.connectorUnavailable'
}

export function connectionFailureMessage(
  reasonCode: unknown,
  t: (key: string, options?: Record<string, unknown>) => string
): string {
  const key =
    typeof reasonCode === 'string'
      ? CONNECTION_FAILURE_KEYS[reasonCode as ConnectionFailureReasonCode]
      : undefined
  return key ? t(key) : t('conn.connectFail')
}

export function loginConnectionFailureMessage(
  reasonCode: unknown,
  loginCommand: string,
  t: (key: string, options?: Record<string, unknown>) => string
): string {
  if (
    typeof reasonCode === 'string' &&
    Object.prototype.hasOwnProperty.call(KIMI_CONNECTION_FAILURE_KEYS, reasonCode)
  ) {
    return t(KIMI_CONNECTION_FAILURE_KEYS[reasonCode as ConnectionFailureReasonCode]!, {
      cmd: loginCommand
    })
  }
  return t('conn.loginNeed', { cmd: loginCommand })
}

const SUBSCRIPTION_STATE_KEY: Record<SubscriptionConnectorState, string> = {
  not_installed: 'conn.subscription.states.notInstalled',
  untrusted_binary: 'conn.subscription.states.untrustedBinary',
  version_unsupported: 'conn.subscription.states.versionUnsupported',
  installed_unprobed: 'conn.subscription.states.installedUnprobed',
  logged_out: 'conn.subscription.states.loggedOut',
  login_pending: 'conn.subscription.states.loginPending',
  authenticated_unprobed: 'conn.subscription.states.authenticatedUnprobed',
  ready: 'conn.subscription.states.ready',
  reauth_required: 'conn.subscription.states.reauthRequired',
  entitlement_denied: 'conn.subscription.states.entitlementDenied',
  degraded: 'conn.subscription.states.degraded',
  unavailable: 'conn.subscription.states.unavailable'
}

function subscriptionNextStep(
  connector: SubscriptionConnector,
  t: (key: string, options?: Record<string, unknown>) => string
): string {
  const provider = SUBSCRIPTION_CONNECTOR_LABEL[connector.id]
  const command = SUBSCRIPTION_CONNECTOR_LOGIN_COMMAND[connector.id]
  if (connector.state === 'not_installed') {
    return t('conn.subscription.next.install', { provider })
  }
  if (connector.state === 'installed_unprobed') {
    return t('conn.subscription.next.probeInstallation', { provider })
  }
  if (connector.state === 'logged_out' || connector.state === 'reauth_required') {
    return t('conn.subscription.next.login', { command })
  }
  if (connector.state === 'login_pending') return t('conn.subscription.next.finishLogin')
  if (connector.state === 'authenticated_unprobed') {
    return t('conn.subscription.next.verify')
  }
  if (connector.state === 'ready') return t('conn.subscription.next.ready')
  if (connector.state === 'untrusted_binary') {
    return t('conn.subscription.next.installOfficial', { provider })
  }
  if (connector.state === 'version_unsupported') {
    return t('conn.subscription.next.update', { provider })
  }
  if (connector.state === 'entitlement_denied') {
    return t('conn.subscription.next.entitlement', { provider })
  }
  return t('conn.subscription.next.retry', { provider })
}

export function SubscriptionConnectorSection({
  connectors,
  state,
  onRefresh
}: {
  connectors: SubscriptionConnector[]
  state: SubscriptionConnectorLoadState
  onRefresh: () => void | Promise<void>
}): React.ReactNode {
  const { t } = useTranslation()
  const supported = SUBSCRIPTION_CONNECTOR_ORDER.flatMap((id) => {
    const connector = connectors.find((candidate) => candidate?.id === id)
    return connector ? [connector] : []
  })

  return (
    <section
      data-connection-section="subscription"
      className="space-y-3 rounded-lg border border-neutral-800 bg-neutral-900/30 p-3"
    >
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="text-sm font-medium">{t('conn.subscription.title')}</div>
          <div className="mt-1 text-xs text-neutral-500">{t('conn.subscription.hint')}</div>
        </div>
        <button
          type="button"
          onClick={() => void onRefresh()}
          disabled={state === 'loading'}
          className="shrink-0 rounded border border-neutral-700 px-2 py-1 text-xs hover:bg-neutral-800 disabled:opacity-40"
        >
          {t('conn.subscription.refresh')}
        </button>
      </div>

      {state === 'loading' && (
        <div className="text-xs text-neutral-400">{t('conn.subscription.loading')}</div>
      )}
      {state === 'error' && (
        <div className="text-xs text-amber-300">{t('conn.subscription.error')}</div>
      )}
      {state === 'ready' && supported.length === 0 && (
        <div className="text-xs text-neutral-400">{t('conn.subscription.empty')}</div>
      )}
      {state === 'ready' &&
        supported.map((connector) => (
          <article
            key={connector.id}
            data-subscription-connector={connector.id}
            className="rounded border border-neutral-800 bg-neutral-950/40 p-3"
          >
            <div className="flex items-center justify-between gap-3">
              <div className="font-medium">{SUBSCRIPTION_CONNECTOR_LABEL[connector.id]}</div>
              <span className="rounded bg-neutral-800 px-2 py-0.5 text-xs text-neutral-300">
                {t(SUBSCRIPTION_STATE_KEY[connector.state])}
              </span>
            </div>
            <dl className="mt-2 grid gap-1 text-xs text-neutral-400 sm:grid-cols-2">
              <div>
                <dt className="inline">{t('conn.subscription.authLabel')}：</dt>
                <dd className="inline text-neutral-300">
                  {t('conn.subscription.auth.deviceCode')}
                </dd>
              </div>
              <div>
                <dt className="inline">{t('conn.subscription.capabilitiesLabel')}：</dt>
                <dd className="inline text-neutral-300">
                  {connector.capabilities
                    .filter((capability) => capability === 'chat' || capability === 'code')
                    .map((capability) => t(`conn.subscription.capabilities.${capability}`))
                    .join('、')}
                </dd>
              </div>
            </dl>
            <div className="mt-2 text-xs text-blue-200">
              {subscriptionNextStep(connector, t)}
            </div>
          </article>
        ))}
    </section>
  )
}

function SubscriptionConnectorPanel(): React.ReactNode {
  const [connectors, setConnectors] = useState<SubscriptionConnector[]>([])
  const [state, setState] = useState<SubscriptionConnectorLoadState>('loading')
  const refreshEpoch = useRef(0)

  const refresh = async (): Promise<void> => {
    const epoch = ++refreshEpoch.current
    setState('loading')
    try {
      const next = await fetchSubscriptionConnectors()
      if (epoch !== refreshEpoch.current) return
      setConnectors(next)
      setState('ready')
    } catch {
      if (epoch !== refreshEpoch.current) return
      setConnectors([])
      setState('error')
    }
  }

  useEffect(() => {
    void refresh()
  }, [])

  return (
    <SubscriptionConnectorSection
      connectors={connectors}
      state={state}
      onRefresh={refresh}
    />
  )
}

function OrphanConnectionCard({
  provider,
  connection,
  onChanged
}: {
  provider: string
  connection: ConnectionSummary
  onChanged: () => Promise<void>
}): React.ReactNode {
  const { t } = useTranslation()
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState<string | null>(null)
  const removeInFlight = useRef(false)

  const remove = async (): Promise<void> => {
    if (busy || removeInFlight.current) return
    removeInFlight.current = true
    setBusy(true)
    setMsg(null)
    try {
      const result = await disconnectStoredConnection(provider, deleteConnection, onChanged)
      setMsg(
        result.ok
          ? t('conn.disconnectOk')
          : result.reason === 'rejected'
            ? t('conn.disconnectRejected')
            : t('conn.disconnectFail')
      )
    } finally {
      removeInFlight.current = false
      setBusy(false)
    }
  }

  return (
    <div className="rounded-lg border border-amber-900/70 bg-amber-950/20 p-4">
      <div className="flex items-center justify-between gap-3">
        <div className="min-w-0">
          <div className="text-xs text-neutral-500">{t('conn.orphanProvider')}</div>
          <code className="block truncate text-sm text-amber-200">{provider}</code>
        </div>
        <span className="rounded bg-neutral-800 px-2 py-0.5 text-xs text-neutral-400">
          {t('conn.orphanUnavailable')}
        </span>
      </div>
      <div className="mt-2 text-xs text-neutral-400">{t('conn.orphanHint')}</div>
      {connection.credential_present === true && (
        <div className="mt-1 text-xs text-amber-300">{t('conn.orphanCredential')}</div>
      )}
      <button
        type="button"
        onClick={() => void remove()}
        disabled={busy}
        className="mt-3 rounded border border-red-900 px-3 py-1 text-red-400 hover:bg-red-950 disabled:opacity-40"
      >
        {t('conn.delete')}
      </button>
      {msg && <div className="mt-2 text-xs text-neutral-300">{msg}</div>}
    </div>
  )
}

// 本地模型选择器：只启动经发布清单或固定哈希证明的运行态。
function LocalModelPicker(): React.ReactNode {
  const [cat, setCat] = useState<LocalCatalog | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const [msg, setMsg] = useState<string | null>(null)

  const load = async (): Promise<void> => {
    try {
      setCat(await fetchLocalCatalog())
    } catch {
      setCat(null) // 引擎无本地模型能力 → 不显示本节
    }
  }
  useEffect(() => {
    void load()
  }, [])

  const select = async (id: string): Promise<void> => {
    setBusy(id)
    setMsg('正在校验运行包与模型指纹…')
    try {
      const response = await selectLocalModel(id)
      if (response.needs_approval) {
        setMsg(`切换请求已送审（${String(response.approval_id ?? '-')}），批准后执行。`)
        return
      }
      for (let i = 0; i < 300; i++) {
        await new Promise((r) => setTimeout(r, 3000))
        const c = await fetchLocalCatalog()
        setCat(c)
        const m = c.models.find((x) => x.id === id)
        if (m?.active) {
          setMsg(c.enabled ? '已切换并启用 ✓' : '已下载，正在启动…')
          if (c.enabled) break
        }
      }
    } catch (e) {
      setMsg('失败：' + String(e))
    } finally {
      setBusy(null)
    }
  }

  if (!cat) return null
  const gb = (mb: number): string => (mb >= 1024 ? (mb / 1024).toFixed(1) + 'GB' : mb + 'MB')

  return (
    <section
      data-connection-section="local"
      className="space-y-2 border border-neutral-800 rounded-lg p-3 bg-neutral-900/30"
    >
      <div className="flex items-center justify-between">
        <div className="text-sm font-medium">
          本地模型（验证后离线可用）
          <span className="ml-2 text-xs text-neutral-500">{cat.enabled ? '运行中' : '未启用'}</span>
        </div>
        <button
          onClick={() => void load()}
          className="px-2 py-0.5 text-xs rounded border border-neutral-700 hover:bg-neutral-800"
        >
          刷新
        </button>
      </div>
      <div className="space-y-1">
        {cat.models.map((m) => {
          const active = m.active && cat.enabled
          return (
            <div key={m.id} className="flex items-center justify-between gap-2 text-sm py-0.5">
              <span className="flex items-center gap-2 min-w-0">
                <span
                  className={`inline-block w-2 h-2 rounded-full shrink-0 ${
                    active ? 'bg-green-500' : m.downloaded ? 'bg-neutral-500' : 'bg-neutral-700'
                  }`}
                />
                <span className="truncate">
                  {m.name}
                  <span className="text-neutral-500 text-xs ml-1">{gb(m.size_mb)}</span>
                </span>
                <span className="text-neutral-600 text-xs truncate">· {m.desc}</span>
              </span>
              <button
                onClick={() => void select(m.id)}
                disabled={!!busy || active}
                className={`px-2 py-0.5 text-xs rounded whitespace-nowrap shrink-0 disabled:opacity-40 ${
                  active ? 'bg-green-900 text-green-300' : 'bg-blue-600 hover:bg-blue-500'
                }`}
              >
                {active ? '使用中' : busy === m.id ? '处理中…' : m.downloaded ? '切换' : '下载并用'}
              </button>
            </div>
          )
        })}
      </div>
      {msg && <div className="text-xs text-neutral-300">{msg}</div>}
    </section>
  )
}

function LocalDetect({
  connectedProviders,
  onVerified
}: {
  connectedProviders: Set<string>
  onVerified: (expectedModelIds: readonly string[]) => Promise<boolean>
}): React.ReactNode {
  const { t } = useTranslation()
  const [servers, setServers] = useState<LocalServer[] | null>(null)
  const [busy, setBusy] = useState(false)
  const [connecting, setConnecting] = useState<string | null>(null)
  const [msg, setMsg] = useState<string | null>(null)
  const connectInFlight = useRef(false)

  useEffect(() => {
    let active = true
    setBusy(true)
    void detectLocal()
      .then((result) => {
        if (active) setServers(result)
      })
      .catch(() => {
        if (active) setServers([])
      })
      .finally(() => {
        if (active) setBusy(false)
      })
    return () => {
      active = false
    }
  }, [])

  const detect = async (): Promise<void> => {
    if (busy || connectInFlight.current) return
    setBusy(true)
    setMsg(null)
    try {
      setServers(await detectLocal())
    } catch {
      setServers([])
      setMsg(t('conn.localDetectFail'))
    } finally {
      setBusy(false)
    }
  }

  const connect = async (s: LocalServer): Promise<void> => {
    if (connectInFlight.current || busy) return
    connectInFlight.current = true
    setConnecting(s.name)
    setMsg(null)
    try {
      const result = await connectDetectedLocalServer(
        s,
        saveConnection,
        onVerified
      )
      setMsg(
        result.ok
          ? result.activation === 'pending'
            ? t('conn.connectRefreshUnknown')
            : result.rejected > 0
              ? t('conn.connectPartial', {
                  n: result.connected,
                  m: result.rejected
                })
              : t('conn.localConnectOk', { n: result.connected })
          : result.reason === 'rejected'
            ? t('conn.localConnectRejected')
            : t('conn.localConnectFail')
      )
    } finally {
      connectInFlight.current = false
      setConnecting(null)
    }
  }

  return (
    <section className="space-y-2 border border-neutral-800 rounded-lg p-3 bg-neutral-900/30">
      <div className="flex items-center justify-between">
        <div className="text-sm font-medium">{t('conn.localTitle')}</div>
        <button
          onClick={() => void detect()}
          disabled={busy || connecting !== null}
          className="px-3 py-1 text-sm rounded border border-neutral-700 hover:bg-neutral-800 disabled:opacity-40"
        >
          {busy ? t('conn.detecting') : t('conn.detect')}
        </button>
      </div>
      {servers && servers.filter((s) => s.alive).length === 0 && (
        <div className="text-xs text-neutral-500">{t('conn.noLocal')}</div>
      )}
      {servers
        ?.filter((s) => s.alive)
        .map((s) => (
          <div key={s.name} className="flex items-center justify-between text-sm">
            <span className="flex items-center gap-2">
              <span className="inline-block w-2 h-2 rounded-full bg-green-500" />
              {s.label}
              <span className="text-neutral-500 text-xs">({s.models.length})</span>
            </span>
            {recommendedLocalChatModel(s.models) ? (
              <button
                onClick={() => void connect(s)}
                disabled={busy || connecting !== null}
                className="px-2 py-0.5 text-xs rounded bg-blue-600 hover:bg-blue-500 disabled:opacity-40"
              >
                {connecting === s.name
                  ? t('conn.connecting')
                  : connectedProviders.has(s.name)
                    ? t('conn.reconnect')
                    : t('conn.connect')}
              </button>
            ) : (
              <span className="text-xs text-amber-300">{t('conn.localNoChatCandidate')}</span>
            )}
          </div>
        ))}
      {msg && <div className="text-xs text-neutral-300">{msg}</div>}
    </section>
  )
}

export function ProviderCard({
  provider,
  connected,
  connection,
  onChanged,
  onVerified
}: {
  provider: CatalogProvider
  connected: boolean
  connection?: ConnectionSummary
  onChanged: () => Promise<void>
  onVerified: (expectedModelIds: readonly string[]) => Promise<boolean>
}): React.ReactNode {
  const { t } = useTranslation()
  const initialModels = connectionModelChoices(provider.models, connection)
  const initialChecked = initialEnabledModelIds(provider.models, connection)
  const credentialPresent = connection?.credential_present === true
  const connectionState = connection?.state
  const [apiKey, setApiKey] = useState('')
  const [baseUrl, setBaseUrl] = useState(connection?.base_url || provider.default_base_url)
  const [models, setModels] = useState<CatalogModel[]>(initialModels)
  const [checked, setChecked] = useState<Set<string>>(
    () => new Set(initialChecked)
  )
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState<string | null>(null)
  const [customModel, setCustomModel] = useState('')
  const [showAdvanced, setShowAdvanced] = useState(false)
  const removeInFlight = useRef(false)

  useEffect(() => {
    setModels(connectionModelChoices(provider.models, connection))
    setChecked(new Set(initialEnabledModelIds(provider.models, connection)))
    setBaseUrl(connection?.base_url || provider.default_base_url)
  }, [connection, provider.default_base_url, provider.models])

  const noKeyNeeded = provider.auth === 'none'
  const canReuseCredential = canPreserveExistingCredential(connection, provider.type, baseUrl)
  const disconnectAvailable = shouldOfferDisconnect(connection)
  const verifiedAt = formatVerifiedAt(connection?.verified_at)
  const selectedModels = models.filter((model) => checked.has(model.id))
  const manualModelSelection = hasCustomizedModelSelection(
    initialModels,
    new Set(initialChecked),
    models,
    checked,
    customModel
  )
  const canAutoDiscoverModels = shouldAutoDiscoverCatalogModels(
    provider,
    connection,
    manualModelSelection
  )

  const remove = async (): Promise<void> => {
    if (removeInFlight.current || busy || !disconnectAvailable) return
    removeInFlight.current = true
    setBusy(true)
    setMsg(null)
    try {
      const result = await disconnectStoredConnection(provider.name, deleteConnection, onChanged)
      setMsg(
        result.ok
          ? t('conn.disconnectOk')
          : result.reason === 'rejected'
            ? t('conn.disconnectRejected')
            : t('conn.disconnectFail')
      )
    } finally {
      removeInFlight.current = false
      setBusy(false)
    }
  }

  const disconnectButton = disconnectAvailable ? (
    <button
      onClick={() => void remove()}
      disabled={busy}
      className="px-3 py-1 rounded border border-red-900 text-red-400 hover:bg-red-950 disabled:opacity-40"
    >
      {t('conn.delete')}
    </button>
  ) : null

  const verificationReceipt = connected ? (
    <div className="mt-1 text-xs text-neutral-500">
      {verifiedAt && <span>{t('conn.verifiedAt', { time: verifiedAt })} · </span>}
      <span>{t('conn.verificationNotLive')}</span>
    </div>
  ) : null

  // 加一个自定义模型：填「id」→ 上游同名调用；填「显示名=上游名」→ 起别名。已存在的忽略。
  const addCustomModel = (): void => {
    const raw = customModel.trim()
    if (!raw) return
    const [idPart, upPart] = raw.split('=').map((x) => x.trim())
    const id = idPart
    const upstream = upPart || idPart
    if (!id || models.some((m) => m.id === id)) {
      setCustomModel('')
      return
    }
    const m: CatalogModel = { id, upstream_model: upstream, tier: 'default', description: '自定义' }
    setModels((prev) => [...prev, m])
    setChecked((prev) => new Set(prev).add(id))
    setCustomModel('')
  }

  const statusBadge = (
    <span
      className={`text-xs px-2 py-0.5 rounded ${
        connected
          ? 'bg-green-900 text-green-300'
          : connectionState === 'legacy_unverified'
            ? 'bg-amber-950 text-amber-300'
            : 'bg-neutral-800 text-neutral-400'
      }`}
    >
      {connected
        ? t('conn.configurationVerified')
        : connectionState === 'legacy_unverified'
          ? t('conn.needsVerification')
          : t('conn.notConnected')}
    </span>
  )

  if (provider.connectable === false) {
    return (
      <div
        data-connection-provider={provider.name}
        className="border border-neutral-800 rounded-lg p-4 bg-neutral-900/30 opacity-80"
      >
        <div className="flex items-center justify-between">
          <div className="font-medium">{provider.label}</div>
          <span className="text-xs px-2 py-0.5 rounded bg-neutral-800 text-neutral-400">
            {t('conn.unavailable')}
          </span>
        </div>
        <div className="mt-2 text-xs text-neutral-500">
          {provider.unavailable_reason || provider.note || t('conn.unavailableHint')}
        </div>
        {credentialPresent && (
          <div className="mt-2 text-xs text-amber-300">{t('conn.credentialUnavailableStored')}</div>
        )}
        {disconnectButton && <div className="mt-3">{disconnectButton}</div>}
        {msg && <div className="mt-2 text-xs text-neutral-300">{msg}</div>}
      </div>
    )
  }

  // 订阅/登录类：Connect 事务只有在 CLI 登录状态真实验证后才会持久化。
  // 当前版本尚未安全实现 GUI 授权启动器，因此如实提示一次官方终端命令。
  if (provider.auth === 'login') {
    const loginInstruction = catalogLoginInstruction(provider.type)
    if (loginInstruction === null) {
      return (
        <div
          data-connection-provider={provider.name}
          className="border border-neutral-800 rounded-lg p-4 bg-neutral-900/50"
        >
          <div className="flex items-center justify-between">
            <div className="font-medium">{provider.label}</div>
            {statusBadge}
          </div>
          {verificationReceipt}
          <div className="mt-2 text-xs text-amber-300">{t('conn.loginUnsupported')}</div>
          {provider.note && <div className="mt-1 text-xs text-neutral-600">· {provider.note}</div>}
          {disconnectButton && <div className="mt-3">{disconnectButton}</div>}
        </div>
      )
    }
    const loginCmd = loginInstruction.command
    const connectLogin = async (): Promise<void> => {
      let verified = false
      let failureReason: ConnectionFailureReasonCode | undefined
      setBusy(true)
      setMsg(null)
      try {
        const enabledModels = loginModelForVerification(provider.models, connection)
        const result = await saveConnection(provider.name, {
          type: provider.type,
          api_key: '',
          base_url: provider.default_base_url || '',
          enabled_models: enabledModels,
          preserve_existing_credential: false
        })
        if (!result.ok) {
          failureReason = result.reason_code
          throw new Error('connection verification failed')
        }
        verified = true
        const activationConfirmed = await onVerified(result.models)
        setMsg(
          !activationConfirmed
            ? t('conn.connectRefreshUnknown')
            : result.rejected_models?.length
              ? t('conn.connectPartial', {
                  n: result.models.length,
                  m: result.rejected_models.length
                })
              : t('conn.loginOk')
        )
      } catch (e) {
        setMsg(
          verified
            ? t('conn.connectRefreshUnknown')
            : loginConnectionFailureMessage(failureReason, loginCmd, t)
        )
      } finally {
        setBusy(false)
      }
    }
    return (
      <div
        data-connection-provider={provider.name}
        className="border border-neutral-800 rounded-lg p-4 bg-neutral-900/50"
      >
        <div className="flex items-center justify-between">
          <div className="font-medium">{provider.label}</div>
          {statusBadge}
        </div>
        {verificationReceipt}
        <div className="mt-2 text-xs text-neutral-400">
          {t('conn.loginManaged', {
            provider: loginInstruction.provider,
            command: loginInstruction.command
          })}
        </div>
        {provider.note && <div className="mt-1 text-xs text-neutral-600">· {provider.note}</div>}
        <div className="mt-3 flex items-center gap-2">
          <button
            onClick={() => void connectLogin()}
            disabled={busy}
            className="px-3 py-1 rounded bg-blue-600 hover:bg-blue-500 disabled:opacity-40"
          >
            {connected ? t('conn.recheck') : t('conn.connect')}
          </button>
          <code className="text-xs text-neutral-500">{loginCmd}</code>
          {disconnectButton}
        </div>
        {msg && <div className="mt-2 text-xs text-neutral-300">{msg}</div>}
      </div>
    )
  }

  const toggle = (id: string): void => {
    setChecked((prev) => {
      const n = new Set(prev)
      if (n.has(id)) n.delete(id)
      else n.add(id)
      return n
    })
  }

  const pull = async (): Promise<void> => {
    setBusy(true)
    setMsg(null)
    try {
      const res = await fetchUpstreamModels(baseUrl)
      if (res.ok && res.models) {
        const fetched: CatalogModel[] = res.models.map((id) => ({
          id,
          upstream_model: id,
          tier: provider.region === 'local' ? 'local' : 'default',
          description: ''
        }))
        setModels(fetched)
        const recommended = recommendedCatalogChatModel(fetched)
        setChecked(new Set(recommended ? [recommended.id] : []))
        setMsg(t('conn.pulled', { n: fetched.length }))
      } else {
        setMsg(res.error || 'failed')
      }
    } catch (e) {
      setMsg(String(e))
    } finally {
      setBusy(false)
    }
  }

  const connect = async (): Promise<void> => {
    let verified = false
    let failureReason: ConnectionFailureReasonCode | undefined
    setBusy(true)
    setMsg(null)
    try {
      let enabled = selectedCatalogModelsForSave(models, checked, canAutoDiscoverModels)
      if (enabled.length === 0 && customModel.trim()) {
        const [idPart, upstreamPart] = customModel
          .trim()
          .split('=')
          .map((value) => value.trim())
        if (idPart) {
          enabled = [
            {
              id: idPart,
              upstream_model: upstreamPart || idPart,
              tier: 'default',
              description: t('conn.customModel')
            }
          ]
        }
      }
      const res = await saveConnection(provider.name, {
        type: provider.type, // 关键：用引擎 provider 类型，而非展示名
        api_key: apiKey,
        base_url: baseUrl,
        enabled_models: enabled,
        preserve_existing_credential: shouldPreserveExistingCredential(
          connection,
          apiKey,
          provider.type,
          baseUrl
        )
      })
      if (!res.ok) {
        failureReason = res.reason_code
        throw new Error('connection verification failed')
      }
      verified = true
      setApiKey('')
      const successMessage =
        res.rejected_models?.length
          ? t('conn.connectPartial', {
              n: res.models.length,
              m: res.rejected_models.length
            })
          : t('conn.connectOk', { n: res.models.length })
      const activationConfirmed = await onVerified(res.models)
      setMsg(activationConfirmed ? successMessage : t('conn.connectRefreshUnknown'))
    } catch (e) {
      setMsg(
        verified
          ? t('conn.connectRefreshUnknown')
          : connectionFailureMessage(failureReason, t)
      )
    } finally {
      setBusy(false)
    }
  }

  return (
    <div
      data-connection-provider={provider.name}
      className="border border-neutral-800 rounded-lg p-4 bg-neutral-900/50"
    >
      <div className="flex items-center justify-between">
        <div className="font-medium">
          {provider.label}
          {canReuseCredential && (
            <span className="ml-2 text-xs text-neutral-600">{t('conn.credentialStored')}</span>
          )}
        </div>
        {statusBadge}
      </div>
      {verificationReceipt}
      {provider.note && <div className="mt-1 text-xs text-neutral-600">· {provider.note}</div>}

      <div className="mt-3 space-y-3">
        {!noKeyNeeded && (
          <label className="block text-sm">
            <span className="text-neutral-400">API Key</span>
            <input
              type="password"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder={canReuseCredential ? t('conn.keyPhSaved') : t('conn.keyPhNew')}
              className="mt-1 w-full px-2 py-1 rounded bg-neutral-950 border border-neutral-700 text-neutral-100"
            />
          </label>
        )}
        {!noKeyNeeded && credentialPresent && !canReuseCredential && (
          <div className="text-xs text-amber-300">{t('conn.credentialRequiresReentry')}</div>
        )}
        {noKeyNeeded && <div className="text-xs text-neutral-500">{t('conn.noKey')}</div>}

        {canAutoDiscoverModels && !showAdvanced && (
          <div className="rounded border border-neutral-800 bg-neutral-950/40 px-3 py-2 text-xs text-neutral-500">
            {t('conn.autoDiscoverModels')}
          </div>
        )}

        {!noKeyNeeded && (
          <div className="text-xs text-neutral-600">{t('conn.validationProbeNotice')}</div>
        )}

        {!canAutoDiscoverModels && models.length === 0 && !showAdvanced && (
          <div className="rounded border border-neutral-800 bg-neutral-950/40 px-3 py-2 text-xs text-neutral-500">
            {t('conn.modelIdHint')}
          </div>
        )}

        {!canAutoDiscoverModels && models.length > 0 && !showAdvanced && (
          <div className="text-xs text-neutral-500">
            {selectedModels.length === 1
              ? t('conn.recommendedModel', { model: selectedModels[0].id })
              : t('conn.savedModelCount', { n: selectedModels.length })}
          </div>
        )}

        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => void connect()}
            disabled={
              busy ||
              (!apiKey.trim() && !noKeyNeeded && !canReuseCredential) ||
              (checked.size === 0 && !customModel.trim() && !canAutoDiscoverModels)
            }
            className="px-3 py-1 rounded bg-blue-600 hover:bg-blue-500 disabled:opacity-40"
          >
            {busy ? t('conn.connecting') : connected ? t('conn.reconnect') : t('conn.connect')}
          </button>
          {disconnectButton}
          <button
            type="button"
            onClick={() => setShowAdvanced((value) => !value)}
            className="px-2 py-1 text-xs rounded border border-neutral-700 text-neutral-400 hover:bg-neutral-800"
          >
            {showAdvanced ? t('conn.hideAdvanced') : t('conn.advanced')}
          </button>
        </div>
        {msg && <div className="text-xs text-neutral-300">{msg}</div>}

        {showAdvanced && (
          <div className="space-y-3 rounded border border-neutral-800 bg-neutral-950/40 p-3">
            <div className="text-xs text-neutral-500">{t('conn.advancedHint')}</div>
            <label className="block text-sm">
              <span className="text-neutral-400">Base URL</span>
              <div className="flex gap-2">
                <input
                  value={baseUrl}
                  onChange={(e) => setBaseUrl(e.target.value)}
                  className="mt-1 flex-1 px-2 py-1 rounded bg-neutral-950 border border-neutral-700 text-neutral-100 font-mono text-xs"
                />
                {provider.auth === 'none' && (
                  <button
                    onClick={() => void pull()}
                    disabled={busy || !baseUrl}
                    className="mt-1 px-2 py-1 text-xs rounded border border-neutral-700 hover:bg-neutral-800 disabled:opacity-40 whitespace-nowrap"
                  >
                    {t('conn.pull')}
                  </button>
                )}
              </div>
            </label>

            <div className="text-sm">
              <div className="text-neutral-400 mb-1">{t('conn.models')}</div>
              <div className="space-y-1 max-h-48 overflow-auto">
                {models.map((m) => (
                  <label key={m.id} className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      checked={checked.has(m.id)}
                      onChange={() => toggle(m.id)}
                    />
                    <span className="font-mono text-xs">{m.id}</span>
                    {m.upstream_model && m.upstream_model !== m.id && (
                      <span className="text-neutral-500 text-xs">→ {m.upstream_model}</span>
                    )}
                    {m.description && (
                      <span className="text-neutral-600 text-xs">· {m.description}</span>
                    )}
                  </label>
                ))}
                {models.length === 0 && (
                  <div className="text-neutral-600 text-xs">{t('conn.noCandidates')}</div>
                )}
              </div>
              <div className="mt-2 flex gap-2">
                <input
                  value={customModel}
                  onChange={(e) => setCustomModel(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') {
                      e.preventDefault()
                      addCustomModel()
                    }
                  }}
                  placeholder={t('conn.customModelPh')}
                  className="flex-1 px-2 py-1 rounded bg-neutral-950 border border-neutral-700 text-neutral-100 font-mono text-xs"
                />
                <button
                  onClick={addCustomModel}
                  disabled={!customModel.trim()}
                  className="px-2 py-1 text-xs rounded border border-neutral-700 hover:bg-neutral-800 disabled:opacity-40 whitespace-nowrap"
                >
                  {t('conn.addModel')}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
