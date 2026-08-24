import { contextBridge, ipcRenderer } from 'electron'

import type { DesktopAPI } from '../renderer/src/env'
import {
  assertRuntimeApiMatchesDeclaration,
  ELECTRON_RUNTIME_CAPABILITIES
} from '../runtime-capabilities'
import { createRendererEngineBridge } from './renderer-engine-bridge'

interface SnipPayload {
  dataUrl: string
  action: string
}

interface UpdateState {
  phase: 'disabled' | 'idle' | 'checking' | 'downloading' | 'ready' | 'installing' | 'blocked'
  version?: string
  reason?: 'not-configured' | 'up-to-date' | 'network' | 'security' | 'failed'
}

interface PaidMediaDeliveryProof {
  operationId: string
  resultSha256: string
  archiveReceiptSha256: string
}

type PaidMediaIpcReply<T> =
  | { ok: true; value: T }
  | { ok: false; error: { code: string; message: string } }

async function invokePaidMedia<T>(channel: string, ...args: unknown[]): Promise<T> {
  const reply = (await ipcRenderer.invoke(channel, ...args)) as PaidMediaIpcReply<T>
  if (!reply || typeof reply !== 'object' || typeof reply.ok !== 'boolean') {
    throw new Error('Invalid paid media IPC reply')
  }
  if (reply.ok) {
    if (!Object.prototype.hasOwnProperty.call(reply, 'value')) {
      throw new Error('Invalid paid media IPC success reply')
    }
    return reply.value
  }
  if (
    !reply.error ||
    typeof reply.error !== 'object' ||
    typeof reply.error.code !== 'string' ||
    typeof reply.error.message !== 'string'
  ) {
    throw new Error('Invalid paid media IPC failure reply')
  }
  const message =
    reply.error && typeof reply.error.message === 'string'
      ? reply.error.message
      : 'Paid media IPC operation failed'
  const error = new Error(message)
  error.name =
    reply.error && typeof reply.error.code === 'string'
      ? `PaidMediaIpc:${reply.error.code}`
      : 'PaidMediaIpc:operation_failed'
  throw error
}

const rendererEngineBridge = createRendererEngineBridge(ipcRenderer)

const api: DesktopAPI = {
  runtimeKind: 'electron' as const,
  runtimeCapabilities: ELECTRON_RUNTIME_CAPABILITIES,
  engineRequest: rendererEngineBridge.request,
  engineStream: rendererEngineBridge.stream,
  engineUpload: rendererEngineBridge.upload,
  cancelEngineRequest: rendererEngineBridge.cancel,
  claimPaidMedia: (input: unknown) => invokePaidMedia('paid-media:claim', input),
  executePaidMedia: (input: unknown) => invokePaidMedia('paid-media:execute', input),
  pollPaidVideo: (input: unknown) => invokePaidMedia('paid-media:poll-video', input),
  recoverPaidMediaArchive: (operationId: string) =>
    invokePaidMedia('paid-media:recover-archive', { operationId }),
  listPaidMediaArchives: (input: { cursor?: string; limit?: number } = {}) =>
    invokePaidMedia('paid-media:list-archives', input),
  cancelPaidMedia: (operationId: string): void =>
    ipcRenderer.send('paid-media:cancel', { operationId }),
  listPaidMediaOperations: () => invokePaidMedia('paid-media:list'),
  acknowledgePaidMedia: (deliveryProof: PaidMediaDeliveryProof) =>
    invokePaidMedia('paid-media:acknowledge', deliveryProof),
  abandonPaidMediaClaim: (operationId: string, evidence: string) =>
    invokePaidMedia('paid-media:abandon', { operationId, evidence }),
  reconcilePaidMedia: (input: unknown) => invokePaidMedia('paid-media:reconcile', input),
  importLegacyPaidMediaJournal: (input: unknown) =>
    invokePaidMedia('paid-media:import-legacy', input),
  listApprovals: (userId: string) => ipcRenderer.invoke('approval:list', userId),
  resolveApproval: (payload: {
    id: number
    decision: 'approve' | 'reject' | 'revise'
    note?: string
  }) => ipcRenderer.invoke('approval:resolve', payload),
  saveConnection: (payload: Parameters<DesktopAPI['saveConnection']>[0]) =>
    ipcRenderer.invoke('connection:save', payload),
  deleteConnection: (provider: string) => ipcRenderer.invoke('connection:delete', provider),
  configureSync: (url: string, anonKey: string) =>
    ipcRenderer.invoke('sync:config', { url, anonKey }),
  authenticateSync: (kind: 'login' | 'signup', email: string, password: string) =>
    ipcRenderer.invoke('sync:auth', { kind, email, password }),
  toggleSync: (enabled: boolean) => ipcRenderer.invoke('sync:toggle', enabled),
  runSync: () => ipcRenderer.invoke('sync:run'),
  inspectChannelRecovery: (input: Parameters<DesktopAPI['inspectChannelRecovery']>[0]) =>
    ipcRenderer.invoke('channel-recovery:inspect', input),
  closeChannelRecovery: (input: Parameters<DesktopAPI['closeChannelRecovery']>[0]) =>
    ipcRenderer.invoke('channel-recovery:close', input),
  getUpdateState: (): Promise<UpdateState> => ipcRenderer.invoke('update:state'),
  checkForUpdates: (): Promise<UpdateState> => ipcRenderer.invoke('update:check'),
  installVerifiedUpdate: (): Promise<{ ok: boolean }> => ipcRenderer.invoke('update:install'),
  onUpdateState: (cb: (state: UpdateState) => void): (() => void) => {
    const h = (_e: unknown, state: UpdateState): void => cb(state)
    ipcRenderer.on('update:state', h)
    return () => ipcRenderer.removeListener('update:state', h)
  },
  // 顶部菜单点选 → 主进程发来视图 key / 命令 → 渲染端切换视图或执行 UI 动作
  onSetView: (cb: (key: string) => void): (() => void) => {
    const h = (_e: unknown, key: string): void => cb(key)
    ipcRenderer.on('set-view', h)
    return () => ipcRenderer.removeListener('set-view', h)
  },
  onAppCommand: (cb: (command: string) => void): (() => void) => {
    const h = (_e: unknown, command: string): void => cb(command)
    ipcRenderer.on('app-command', h)
    return () => ipcRenderer.removeListener('app-command', h)
  },
  // 通知主进程按新语言重建原生菜单
  setLang: (lang: string) => ipcRenderer.send('set-lang', lang),
  // ── 自制截图浮层 ──
  // 浮层窗口：取冻结屏 / 通知已就绪可显示 / 提交选区(裁切图+动作) / 取消
  snipBg: (): Promise<{ dataUrl: string; width: number; height: number } | null> =>
    ipcRenderer.invoke('snip:bg'),
  startSnip: (): Promise<{ ok: boolean }> => ipcRenderer.invoke('snip:start'),
  pickDirectory: (): Promise<string> => ipcRenderer.invoke('dialog:pick-directory'),
  // 保存媒体：bytes(data:/blob: 渲染层已取好字节) 或 url(https 让主进程代下，无 CORS/CSP 限制)
  saveMedia: (p: {
    filename: string
    bytes?: ArrayBuffer
    url?: string
  }): Promise<{ ok: boolean; path?: string; error?: string }> => ipcRenderer.invoke('media:save', p),
  snipReady: (): void => ipcRenderer.send('snip:ready'),
  snipDone: (payload: SnipPayload): void => ipcRenderer.send('snip:done', payload),
  snipCancel: (): void => ipcRenderer.send('snip:cancel'),
  // 主窗口：订阅截图结果（右键菜单/快捷键触发后，主进程把裁切图+动作推回来）
  onSnipResult: (cb: (dataUrl: string, action: string) => void): (() => void) => {
    const h = (_e: unknown, p: SnipPayload): void => cb(p.dataUrl, p.action)
    ipcRenderer.on('snip:result', h)
    return () => ipcRenderer.removeListener('snip:result', h)
  }
}

assertRuntimeApiMatchesDeclaration(api, ELECTRON_RUNTIME_CAPABILITIES)

window.addEventListener('online', () => ipcRenderer.send('update:network-online'))

if (process.contextIsolated) {
  try {
    contextBridge.exposeInMainWorld('api', api)
  } catch (error) {
    console.error(error)
  }
} else {
  // @ts-ignore 退化路径（未启用上下文隔离时）
  window.api = api
}
