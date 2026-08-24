import React, { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  Panel,
  PanelGroup,
  PanelResizeHandle,
  type ImperativePanelHandle
} from 'react-resizable-panels'
import {
  completePaidMediaOperation,
  discardPendingPaidMediaOperation,
  fetchModels,
  listRecoverablePaidMediaArchives,
  listPendingPaidMediaOperations,
  probeEngineStatus,
  recoverPaidMediaArchive,
  type PaidMediaArchiveDiscovery,
  type PendingPaidMediaOperation
} from './api'
import {
  flushAndVerifyPaidMediaResult,
  flushAppStorePersistence,
  useAppStore,
  type ViewKey
} from './store'
import LeftPane from './components/LeftPane'
import ChatPane from './components/ChatPane'
import ConnectionCenter from './components/ConnectionCenter'
import OrchestratePane from './components/OrchestratePane'
import UsagePane from './components/UsagePane'
import BrowserPane from './components/BrowserPane'
import AgentBrainPane from './components/AgentBrainPane'
import KbPane from './components/KbPane'
import FilesPane from './components/FilesPane'
import StudioPane from './components/StudioPane'
import SyncPane from './components/SyncPane'
import AboutPane from './components/AboutPane'
import McpPane from './components/McpPane'
import ApprovalCenter from './components/ApprovalCenter'
import UpdateToast from './components/UpdateToast'
import AppHeader from './components/AppHeader'
import ModelSelector from './components/ModelSelector'
import SettingsPane from './components/SettingsPane'
import {
  CreativeDrawer,
  type CreativeMode,
  type CreativeSubmission
} from './components/CreativeDrawer'
import type { CreativeComposerRequest } from './creative-composer-bridge'
import {
  primaryDestinationForState,
  resolvePrimaryDestination
} from './app-navigation'
import type { PrimaryDestination } from './components/UnifiedAppShell'
import { LatestOnlyRefresh } from './paid-media-recovery-refresh'
import { convergePaidMediaAcknowledgements } from './paid-media-ack-convergence'
import { patchPaidMediaMessageAndFlush } from './components/chat-pane-paid-media-routing'
import { commitSuccessfulModelRefresh } from './model-refresh'
import { canUseEngineRuntime } from './engine-status'

function PaidMediaRecoveryNotice(): React.ReactNode {
  const [pending, setPending] = useState<PendingPaidMediaOperation[]>([])
  const [archives, setArchives] = useState<PaidMediaArchiveDiscovery[]>([])
  const [archiveCursor, setArchiveCursor] = useState<string | undefined>()
  const [hiddenArchives, setHiddenArchives] = useState<Set<string>>(() => new Set())
  const [restoringArchives, setRestoringArchives] = useState<Set<string>>(() => new Set())
  const [restoreErrors, setRestoreErrors] = useState<Set<string>>(() => new Set())
  const restoringArchivesRef = useRef(new Set<string>())
  const [ledgerUnavailable, setLedgerUnavailable] = useState(false)
  const [archiveUnavailable, setArchiveUnavailable] = useState(false)
  const [refreshFence] = useState(
    () => new LatestOnlyRefresh<PendingPaidMediaOperation[]>()
  )
  useEffect(() => {
    const loadAndConverge = async (): Promise<PendingPaidMediaOperation[]> => {
      let next = await listPendingPaidMediaOperations()
      const state = useAppStore.getState()
      const convergence = await convergePaidMediaAcknowledgements({
        conversations: state.conversations,
        unresolved: next,
        verify: (anchor) => flushAndVerifyPaidMediaResult(anchor),
        acknowledge: completePaidMediaOperation,
        clear: (anchor) =>
          patchPaidMediaMessageAndFlush(
            state.setConvMessages,
            anchor,
            { paidMediaOperation: undefined },
            flushAppStorePersistence
          )
      })
      if (convergence.acknowledged.length > 0) {
        next = await listPendingPaidMediaOperations()
      }
      return next
    }
    const refresh = (): void => {
      void refreshFence.run(
        loadAndConverge,
        (next) => {
          setPending(next)
          setLedgerUnavailable(false)
        },
        () => {
          // A corrupt/unavailable main ledger is fail-closed in api.ts.
          setLedgerUnavailable(true)
        }
      )
    }
    refresh()
    const timer = window.setInterval(refresh, 2000)
    window.addEventListener('storage', refresh)
    return () => {
      refreshFence.invalidate()
      window.clearInterval(timer)
      window.removeEventListener('storage', refresh)
    }
  }, [refreshFence])
  useEffect(() => {
    let cancelled = false
    const refreshArchives = async (): Promise<void> => {
      try {
        const page = await listRecoverablePaidMediaArchives({ limit: 50 })
        if (!cancelled) {
          setArchives(page.items)
          setArchiveCursor(page.nextCursor)
          setArchiveUnavailable(false)
        }
      } catch {
        if (!cancelled) setArchiveUnavailable(true)
      }
    }
    void refreshArchives()
    const onFocus = (): void => void refreshArchives()
    window.addEventListener('focus', onFocus)
    const timer = window.setInterval(() => void refreshArchives(), 5 * 60_000)
    return () => {
      cancelled = true
      window.clearInterval(timer)
      window.removeEventListener('focus', onFocus)
    }
  }, [])
  const manuallyReconcile = async (operation: PendingPaidMediaOperation): Promise<void> => {
    const evidence = window.prompt(
      `请先查询供应商任务和账单，再填写可追溯凭据（供应商任务号、账单号或“确认未扣费”的查询记录）。\n\n操作：${operation.operationId}\n接口：${operation.path}\n创建：${new Date(operation.createdAt).toLocaleString('zh-CN')}`,
      ''
    )
    if (!evidence?.trim()) return
    try {
      const reconciled = await discardPendingPaidMediaOperation(
        operation.operationId,
        evidence.trim()
      )
      if (!reconciled) return
      refreshFence.invalidate()
      setPending((current) =>
        current.filter((candidate) => candidate.operationId !== operation.operationId)
      )
    } catch {
      setLedgerUnavailable(true)
    }
  }
  const restoreArchive = async (archive: PaidMediaArchiveDiscovery): Promise<void> => {
    if (restoringArchivesRef.current.has(archive.operationId)) return
    restoringArchivesRef.current.add(archive.operationId)
    setRestoringArchives(new Set(restoringArchivesRef.current))
    setRestoreErrors((current) => {
      const next = new Set(current)
      next.delete(archive.operationId)
      return next
    })
    try {
      const recovered = await recoverPaidMediaArchive(archive.operationId)
      const result = recovered.result
      const data = Array.isArray(result.data) ? result.data : []
      const images = data
        .map((item) =>
          item && typeof item === 'object' && !Array.isArray(item)
            ? (item as Record<string, unknown>).url
            : undefined
        )
        .filter((value): value is string => typeof value === 'string')
      const taskId = [result.task_id, result.video_id, result.id].find(
        (value): value is string => typeof value === 'string' && value.length > 0
      )
      const video = [result.video_url, result.url].find(
        (value): value is string => typeof value === 'string' && value.length > 0
      )
      const state = useAppStore.getState()
      const conversationId = state.newConversation('chat')
      const messageTs = Date.now()
      const videoTask = taskId ? { task_id: taskId, model: recovered.model } : undefined
      useAppStore.getState().setConvMessages(conversationId, (messages) => [
        ...messages,
        {
          role: 'assistant',
          content: `已从 Main 保险库恢复付费媒体归档：${archive.operationId}${taskId ? `\n视频任务号：${taskId}` : ''}`,
          ts: messageTs,
          model: recovered.model,
          ...(images.length ? { images } : {}),
          ...(video ? { video } : {}),
          ...(videoTask ? { videoTask } : {}),
          paidMediaOperation: {
            operationId: archive.operationId,
            kind: archive.kind === 'image' ? 'image' : 'video',
            model: recovered.model,
            phase: 'awaiting_ack',
            deliveryProof: recovered.deliveryProof
          }
        }
      ])
      const anchor = images.length
        ? {
            conversationId,
            messageTs,
            operationId: archive.operationId,
            deliveryProof: recovered.deliveryProof,
            images
          }
        : videoTask
          ? {
              conversationId,
              messageTs,
              operationId: archive.operationId,
              deliveryProof: recovered.deliveryProof,
              videoTask
            }
          : null
      if (!anchor || !flushAndVerifyPaidMediaResult(anchor)) {
        throw new Error('archive recovery conversation did not persist')
      }
      setHiddenArchives((current) => new Set(current).add(archive.operationId))
      if (
        pending.some(
          (operation) =>
            operation.operationId === archive.operationId && operation.state === 'result_ready'
        )
      ) {
        try {
          await completePaidMediaOperation(recovered.deliveryProof)
          setPending((current) =>
            current.filter((operation) => operation.operationId !== archive.operationId)
          )
          patchPaidMediaMessageAndFlush(
            useAppStore.getState().setConvMessages,
            anchor,
            { paidMediaOperation: undefined },
            flushAppStorePersistence
          )
        } catch {
          // Keep the verified awaiting_ack anchor. The normal convergence loop
          // retries Main ACK without creating a duplicate recovered message.
        }
      }
    } catch {
      setRestoreErrors((current) => new Set(current).add(archive.operationId))
    } finally {
      restoringArchivesRef.current.delete(archive.operationId)
      setRestoringArchives(new Set(restoringArchivesRef.current))
    }
  }
  const loadMoreArchives = async (): Promise<void> => {
    if (!archiveCursor) return
    try {
      const page = await listRecoverablePaidMediaArchives({
        cursor: archiveCursor,
        limit: 50
      })
      setArchives((current) => {
        const merged = new Map(current.map((item) => [item.operationId, item]))
        for (const item of page.items) merged.set(item.operationId, item)
        return [...merged.values()]
      })
      setArchiveCursor(page.nextCursor)
    } catch {
      setArchiveUnavailable(true)
    }
  }
  const visibleArchives = archives.filter(
    (archive) => !hiddenArchives.has(archive.operationId)
  )
  if (ledgerUnavailable || archiveUnavailable) {
    return (
      <div className="fixed bottom-3 left-1/2 z-[70] -translate-x-1/2 rounded-lg border border-red-700 bg-neutral-950/95 px-3 py-2 text-xs text-red-200 shadow-xl">
        {ledgerUnavailable
          ? '本机付费媒体账本不可用，新的图片/视频付费请求已安全停用。'
          : ''}
        {archiveUnavailable
          ? ' Main 保险库发现/恢复不可用；归档仍保留在 Main，请勿重复生成。'
          : ''}
      </div>
    )
  }
  if (!pending.length && !visibleArchives.length) return null
  return (
    <div className="fixed bottom-3 left-1/2 z-[70] max-h-[45vh] w-[min(46rem,calc(100vw-2rem))] -translate-x-1/2 overflow-auto rounded-lg border border-amber-700 bg-neutral-950/95 px-3 py-2 text-xs text-amber-100 shadow-xl">
      <div className="mb-2">
        {pending.length > 0 ? (
          <>
            有 {pending.length} 个付费媒体操作尚未结案。优先回到原消息点击“安全恢复原操作”；原消息丢失时，
            必须先查询供应商任务/账单，再人工核销，不能直接重新生成。
          </>
        ) : null}
        {visibleArchives.length > 0 ? (
          <div className={pending.length ? 'mt-2 border-t border-amber-800 pt-2' : ''}>
            Main 保险库还保留 {visibleArchives.length} 份可验证付费媒体归档。即使界面记录被清空，
            也可按操作号恢复；恢复不会删除 Main 副本。
          </div>
        ) : null}
      </div>
      <div className="space-y-2">
        {pending.map((operation) => (
          <div
            key={operation.operationId}
            className="rounded border border-amber-800/70 bg-black/20 p-2"
          >
            <div className="break-all font-mono text-amber-300">{operation.operationId}</div>
            <div className="mt-1 text-amber-100/80">
              {operation.path} · {new Date(operation.createdAt).toLocaleString('zh-CN')} ·{' '}
              {operation.state}
            </div>
            <button
              onClick={() => void manuallyReconcile(operation)}
              className="mt-1 rounded border border-amber-700 px-2 py-1 text-amber-200 hover:bg-amber-900/50"
            >
              已核对供应商，移除本机记录
            </button>
          </div>
        ))}
        {visibleArchives.map((archive) => (
          <div
            key={`archive:${archive.operationId}`}
            className="rounded border border-sky-800/70 bg-sky-950/20 p-2"
          >
            <div className="break-all font-mono text-sky-300">{archive.operationId}</div>
            <div className="mt-1 text-sky-100/80">
              Main 归档 · {archive.kind === 'image' ? '图片' : '视频任务'} ·{' '}
              {new Date(archive.archivedAt).toLocaleString('zh-CN')} ·{' '}
              {archive.responseByteLength} bytes
            </div>
            <div className="mt-1 flex gap-2">
              <button
                onClick={() => void restoreArchive(archive)}
                disabled={restoringArchives.has(archive.operationId)}
                className="rounded border border-sky-700 px-2 py-1 text-sky-200 hover:bg-sky-900/50"
              >
                {restoringArchives.has(archive.operationId) ? '恢复中…' : '恢复到新对话'}
              </button>
              <button
                onClick={() =>
                  setHiddenArchives((current) => new Set(current).add(archive.operationId))
                }
                className="rounded border border-neutral-700 px-2 py-1 text-neutral-300 hover:bg-neutral-800"
              >
                本次隐藏
              </button>
            </div>
            {restoreErrors.has(archive.operationId) ? (
              <div className="mt-1 text-red-300">
                此归档深度验证或恢复失败；其他健康归档仍可继续操作，请勿重新付费生成。
              </div>
            ) : null}
          </div>
        ))}
        {archiveCursor ? (
          <button
            onClick={() => void loadMoreArchives()}
            className="w-full rounded border border-sky-800 px-2 py-1 text-sky-200 hover:bg-sky-900/40"
          >
            加载更早的 Main 归档
          </button>
        ) : null}
      </div>
    </div>
  )
}

function useEngine(): void {
  const setStatus = useAppStore((s) => s.setStatus)
  const setModels = useAppStore((s) => s.setModels)
  const status = useAppStore((s) => s.status)

  useEffect(() => {
    let timer: number
    const ping = async (): Promise<void> => {
      setStatus(await probeEngineStatus())
      timer = window.setTimeout(ping, 2000)
    }
    void ping()
    return () => window.clearTimeout(timer)
  }, [setStatus])

  // 引擎在线就拉模型；没拉到（引擎刚重启等场景）每 3 秒快重试。
  // 关键修（机主实测：引擎跑着重启一次→app 一直"无可用模型"要手动刷）：成功后**不永久停**，
  // 而是每 20 秒后台慢复检——引擎悄悄重启/模型变动都能自愈，无需 Ctrl+R。
  useEffect(() => {
    if (!canUseEngineRuntime(status)) return
    let cancelled = false
    let timer: number
    const tryFetch = async (): Promise<void> => {
      let ok = false
      try {
        const m = await fetchModels()
        if (!cancelled) ok = commitSuccessfulModelRefresh(m, setModels)
      } catch {
        /* 引擎短暂不可用，下面按未拿到处理、快重试 */
      }
      // 拿到 → 20s 后慢复检（自愈）；没拿到 → 3s 快重试，直到拿到
      if (!cancelled) timer = window.setTimeout(tryFetch, ok ? 20000 : 3000)
    }
    void tryFetch()
    return () => {
      cancelled = true
      window.clearTimeout(timer)
    }
  }, [status, setModels])
}

export default function App(): React.ReactNode {
  useEngine()
  const { t } = useTranslation()
  const view = useAppStore((s) => s.view)
  const setView = useAppStore((s) => s.setView)
  const status = useAppStore((s) => s.status)
  const models = useAppStore((s) => s.models)
  const browserZoom = useAppStore((s) => s.browserZoom)
  const setBrowserZoom = useAppStore((s) => s.setBrowserZoom)
  const browserOpen = useAppStore((s) => s.browserOpen)
  const toggleBrowser = useAppStore((s) => s.toggleBrowser)
  const openBrowser = useAppStore((s) => s.openBrowser)
  const closeBrowser = useAppStore((s) => s.closeBrowser)
  const newConversation = useAppStore((s) => s.newConversation)
  const [creativeOpen, setCreativeOpen] = useState(false)
  const [creativeMode, setCreativeMode] = useState<CreativeMode>('image')
  const [creativeModel, setCreativeModel] = useState('')
  const [creativePrompt, setCreativePrompt] = useState('')
  const [creativeReference, setCreativeReference] = useState<string | null>(null)
  const [creativeRequest, setCreativeRequest] = useState<CreativeComposerRequest | null>(null)
  const [mobileNavigationOpen, setMobileNavigationOpen] = useState(false)
  const creativeRequestId = useRef(0)
  const creativeRequestPendingRef = useRef(false)
  const leftRef = useRef<ImperativePanelHandle>(null)
  const middleRef = useRef<ImperativePanelHandle>(null)
  const rightRef = useRef<ImperativePanelHandle>(null)
  const toggle = (p: ImperativePanelHandle | null): void => {
    if (!p) return
    if (p.isCollapsed()) p.expand()
    else p.collapse()
  }
  const activePrimary = primaryDestinationForState(view, creativeOpen)
  const selectPrimary = (destination: PrimaryDestination): void => {
    setMobileNavigationOpen(false)
    const next = resolvePrimaryDestination(destination)
    setCreativeOpen(next.creativeOpen)
    setView(next.view)
    if (next.creativeOpen) closeBrowser()
  }
  const handleCreativeModeChange = (mode: CreativeMode): void => {
    setCreativeMode(mode)
    if (mode === 'image') setCreativeReference(null)
    setCreativeModel(models.find((model) => model.modality === mode)?.id ?? '')
  }
  const handleCreativeSubmit = (submission: CreativeSubmission): void => {
    if (creativeRequestPendingRef.current) return
    creativeRequestPendingRef.current = true
    setView('chat')
    closeBrowser()
    setCreativeOpen(false)
    creativeRequestId.current += 1
    setCreativeRequest({ ...submission, id: creativeRequestId.current })
  }
  useEffect(() => {
    const available = models.filter((model) => model.modality === creativeMode)
    setCreativeModel((selected) =>
      available.some((model) => model.id === selected) ? selected : (available[0]?.id ?? '')
    )
  }, [creativeMode, models])
  useEffect(() => {
    if (view !== 'chat' || browserOpen) setCreativeOpen(false)
  }, [browserOpen, view])
  // 浏览器缩放：normal=三栏 / wide=收起左栏给浏览器腾地 / max=收起左+中栏（浏览器铺满，靠其底部输入框沟通）
  useEffect(() => {
    const l = leftRef.current
    const mid = middleRef.current
    if (!l || !mid) return
    if (browserZoom === 'max') {
      l.collapse()
      mid.collapse()
    } else if (browserZoom === 'wide') {
      l.collapse()
      mid.expand()
    } else {
      l.expand()
      mid.expand()
    }
  }, [browserZoom])
  // 右栏浏览器开/关：默认关；手动点或 agent 用到浏览器工具时打开。关时顺便还原左+中栏
  useEffect(() => {
    const r = rightRef.current
    if (!r) return
    if (browserOpen) {
      r.expand()
    } else {
      r.collapse()
      setBrowserZoom('normal')
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [browserOpen])
  // 顶部原生菜单点选 → 切换中间视图
  useEffect(() => {
    return window.api.onSetView((key) => setView(key as ViewKey))
  }, [setView])
  // 顶部原生菜单命令 → 执行 UI 动作（新对话、浏览器栏布局等）
  useEffect(() => {
    return window.api.onAppCommand((command) => {
      if (command === 'new-chat') {
        newConversation('chat')
        setView('chat')
      } else if (command === 'new-code-chat') {
        newConversation('code')
        setView('chat')
      } else if (command === 'new-browser-chat') {
        newConversation('browser')
        setView('chat')
        openBrowser()
      } else if (command === 'toggle-left') {
        toggle(leftRef.current)
      } else if (command === 'toggle-browser') {
        toggleBrowser()
      } else if (command === 'browser-normal' || command === 'browser-wide' || command === 'browser-max') {
        openBrowser()
        setBrowserZoom(command === 'browser-normal' ? 'normal' : command === 'browser-wide' ? 'wide' : 'max')
      }
    })
  }, [newConversation, openBrowser, setBrowserZoom, setView, toggleBrowser])
  return (
    <div className="nachuan-root h-full flex flex-col">
      <AppHeader
        creativeOpen={creativeOpen}
        onToggleNavigation={() => {
          if (window.matchMedia('(max-width: 760px)').matches) {
            setMobileNavigationOpen((open) => !open)
          } else {
            toggle(leftRef.current)
          }
        }}
        onToggleCreative={() => {
          if (creativeOpen) {
            setCreativeOpen(false)
          } else {
            setView('chat')
            closeBrowser()
            setCreativeOpen(true)
          }
        }}
        onOpenSettings={() => selectPrimary('settings')}
        onToggleBrowser={toggleBrowser}
      />
      <div
        className={`nachuan-mobile-navigation${mobileNavigationOpen ? ' is-open' : ''}`}
        aria-hidden={!mobileNavigationOpen}
      >
        <button
          type="button"
          className="nachuan-mobile-navigation-backdrop"
          aria-label={t('left.closeNavigation')}
          onClick={() => setMobileNavigationOpen(false)}
        />
        <aside className="nachuan-mobile-navigation-drawer" aria-label={t('pane.left')}>
          <div className="nachuan-mobile-model-control">
            <span>{t('chat.brain')}</span>
            <ModelSelector />
          </div>
          <LeftPane
            activePrimary={activePrimary}
            onPrimaryChange={selectPrimary}
            onNavigate={() => setMobileNavigationOpen(false)}
          />
        </aside>
      </div>
      <PanelGroup direction="horizontal" className="nachuan-workspace flex-1">
        <Panel
          ref={leftRef}
          defaultSize={19}
          minSize={14}
          maxSize={28}
          collapsible
          collapsedSize={0}
          className="nachuan-navigation-panel flex flex-col"
        >
          <LeftPane activePrimary={activePrimary} onPrimaryChange={selectPrimary} />
        </Panel>
        <PanelResizeHandle className="nachuan-resize-handle" />
        <Panel
          ref={middleRef}
          defaultSize={57}
          minSize={32}
          collapsible
          collapsedSize={0}
          className="nachuan-main-panel flex flex-col"
        >
          <div className="nachuan-center-layout">
            <section className="nachuan-view-surface" aria-label={t('pane.center')}>
              {view === 'chat' ? (
                <ChatPane
                  creativeRequest={creativeRequest}
                  onCreativeRequestHandled={(requestId, error) => {
                    creativeRequestPendingRef.current = false
                    setCreativeRequest((current) =>
                      current?.id === requestId ? null : current
                    )
                    if (!error) {
                      setCreativePrompt('')
                      setCreativeReference(null)
                    }
                  }}
                />
              ) : view === 'brain' ? (
                <AgentBrainPane />
              ) : view === 'kb' ? (
                <KbPane />
              ) : view === 'studio' ? (
                <StudioPane />
              ) : view === 'sync' ? (
                <SyncPane />
              ) : view === 'about' ? (
                <AboutPane />
              ) : view === 'media' ? (
                <FilesPane />
              ) : view === 'mcp' ? (
                <McpPane />
              ) : view === 'orchestrate' ? (
                <OrchestratePane />
              ) : view === 'usage' ? (
                <UsagePane />
              ) : view === 'settings' ? (
                <SettingsPane />
              ) : (
                <ConnectionCenter />
              )}
            </section>
            {creativeOpen && view === 'chat' && (
              <aside className="nachuan-creative-panel" aria-label="创作面板">
                <CreativeDrawer
                  mode={creativeMode}
                  onModeChange={handleCreativeModeChange}
                  models={models}
                  currentModel={creativeModel}
                  onCurrentModelChange={setCreativeModel}
                  prompt={creativePrompt}
                  onPromptChange={setCreativePrompt}
                  referenceImage={creativeReference}
                  onReferenceImageChange={setCreativeReference}
                  onSubmit={handleCreativeSubmit}
                  disabled={creativeRequest !== null || status === 'offline' || status === 'starting'}
                />
              </aside>
            )}
          </div>
        </Panel>
        <PanelResizeHandle className="nachuan-resize-handle" />
        <Panel
          ref={rightRef}
          defaultSize={34}
          minSize={15}
          collapsible
          collapsedSize={0}
          className="nachuan-browser-panel flex flex-col"
        >
          <BrowserPane />
        </Panel>
      </PanelGroup>
      {creativeRequest ? (
        <div className="nachuan-creative-pending" aria-live="polite">
          {t('creative.pending')}
        </div>
      ) : null}
      {/* 浏览器收栏/最大化后，左上悬浮一个还原按钮（哪怕浏览器铺满也能一键找回左侧栏与对话） */}
      {browserZoom !== 'normal' && (
        <button
          onClick={() => setBrowserZoom('normal')}
          title={t('ui.restoreTitle')}
          className="nachuan-restore-layout"
        >
          {t('ui.restore')}
        </button>
      )}
      <ApprovalCenter />
      <UpdateToast />
      <PaidMediaRecoveryNotice />
    </div>
  )
}
