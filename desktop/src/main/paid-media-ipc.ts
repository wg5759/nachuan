import { createHash } from 'node:crypto'

import {
  inspectPaidMediaRequestBody,
  MAX_PAID_MEDIA_REQUEST_BYTES,
  type PaidMediaClaimRequest,
  type PaidMediaExecuteRequest,
  type PaidMediaLegacyBootstrapInput,
  type PaidVideoPollRequest,
  type PaidMediaService
} from './paid-media-service'

const OPERATION_ID_PATTERN = /^desktop-op-[0-9a-f-]{36}$/i
const SHA256_PATTERN = /^[0-9a-f]{64}$/
const VIDEO_TASK_ALIAS_PATTERN = /^nvt1_[0-9a-f]{64}$/
const MAX_RECONCILIATION_REASON_BYTES = 512
const MAX_RECONCILIATION_EVIDENCE_BYTES = 4096
const PAID_MEDIA_PATHS = new Set(['/v1/images/generations', '/v1/videos/generations'])
const MAX_APPROVAL_PREVIEW_CODE_POINTS = 180
const APPROVAL_PARAMETER_KEYS = [
  'n',
  'num_images',
  'num_videos',
  'num_outputs',
  'num_samples',
  'batch_size',
  'size',
  'response_format',
  'quality',
  'mode',
  'height',
  'width',
  'num_frames',
  'frame_rate',
  'duration',
  'seconds'
] as const
import type { PaidMediaLegacyUnresolvedInput } from './paid-media-ledger'

export const PAID_MEDIA_IPC_CHANNELS = {
  claim: 'paid-media:claim',
  execute: 'paid-media:execute',
  pollVideo: 'paid-media:poll-video',
  recoverArchive: 'paid-media:recover-archive',
  listArchives: 'paid-media:list-archives',
  list: 'paid-media:list',
  acknowledge: 'paid-media:acknowledge',
  abandon: 'paid-media:abandon',
  reconcile: 'paid-media:reconcile',
  importLegacy: 'paid-media:import-legacy',
  cancel: 'paid-media:cancel'
} as const

type IpcHandler = (event: any, ...args: any[]) => unknown

export interface PaidMediaIpcMainPort {
  handle(channel: string, handler: IpcHandler): void
  removeHandler(channel: string): void
  on(channel: string, listener: IpcHandler): unknown
  removeListener(channel: string, listener: IpcHandler): unknown
}

export interface PaidMediaNativeDialogPort {
  showMessageBox(owner: any, options: Record<string, unknown>): Promise<{ response: number }>
}

export interface RegisterPaidMediaIpcDependencies {
  ipcMain: PaidMediaIpcMainPort
  service: PaidMediaService
  authorize(event: any): void | Promise<void>
  ownerWindow(): any
  dialog: PaidMediaNativeDialogPort
}

export interface PaidMediaIpcRegistration {
  dispose(): void
}

const activeRegistrations = new WeakMap<PaidMediaIpcMainPort, PaidMediaIpcRegistration>()

export type PaidMediaIpcReply<T> =
  | { ok: true; value: T }
  | {
      ok: false
      error: {
        code:
          | 'unauthorized'
          | 'invalid_request'
          | 'operation_failed'
          | 'operation_mismatch'
          | 'operation_expired'
          | 'unresolved'
          | 'cancelled'
        message: string
      }
    }

async function authorize(
  dependencies: RegisterPaidMediaIpcDependencies,
  event: any
): Promise<PaidMediaIpcReply<never> | null> {
  try {
    await dependencies.authorize(event)
    return null
  } catch {
    return {
      ok: false,
      error: {
        code: 'unauthorized',
        message: 'Paid media IPC authorization failed'
      }
    }
  }
}

function hasExactKeys(value: unknown, expected: readonly string[]): value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const actual = Object.keys(value).sort()
  const wanted = [...expected].sort()
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index])
}

function boundedText(value: unknown, maxBytes: number): value is string {
  return (
    typeof value === 'string' &&
    value.trim().length > 0 &&
    Buffer.byteLength(value, 'utf8') <= maxBytes &&
    !/[\u0000-\u001f\u007f]/.test(value)
  )
}

function approvalVisibleText(value: string, maxCodePoints: number): string {
  const normalized = value
    .normalize('NFC')
    .replace(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
  const codePoints = Array.from(normalized)
  return codePoints.length <= maxCodePoints
    ? normalized
    : `${codePoints.slice(0, maxCodePoints).join('')}…`
}

function approvalParameterValue(value: unknown): string {
  if (typeof value === 'string') return approvalVisibleText(value, 64)
  if (typeof value === 'number' && Number.isFinite(value)) return String(value)
  if (typeof value === 'boolean') return String(value)
  if (value === null) return 'null'
  return '[complex]'
}

function paidMediaApprovalDetail(
  path: string,
  inspected: ReturnType<typeof inspectPaidMediaRequestBody>
): string {
  const extraBody =
    inspected.value.extra_body &&
    typeof inspected.value.extra_body === 'object' &&
    !Array.isArray(inspected.value.extra_body)
      ? (inspected.value.extra_body as Record<string, unknown>)
      : null
  const parameters: string[] = []
  for (const key of APPROVAL_PARAMETER_KEYS) {
    const owner = Object.prototype.hasOwnProperty.call(inspected.value, key)
      ? inspected.value
      : extraBody && Object.prototype.hasOwnProperty.call(extraBody, key)
        ? extraBody
        : null
    if (owner) parameters.push(`${key}=${approvalParameterValue(owner[key])}`)
  }
  const mediaInputCount = [inspected.value.image, extraBody?.image].reduce(
    (total: number, value: unknown) =>
      total + (Array.isArray(value) ? value.length : value === undefined || value === null ? 0 : 1),
    0
  )
  const knownKeys = new Set<string>([
    'model',
    'prompt',
    'image',
    'extra_body',
    ...APPROVAL_PARAMETER_KEYS
  ])
  const otherKeys = Object.keys(inspected.value)
    .filter((key) => !knownKeys.has(key))
    .slice(0, 12)
    .map((key) => approvalVisibleText(key, 48))
  const digest = createHash('sha256').update(inspected.encodedBody, 'utf8').digest('hex')
  return [
    '请核对以下由界面提交的付费请求（仅显示在本机系统对话框）：',
    `接口：${path}`,
    `模型：${approvalVisibleText(inspected.model, 128)}`,
    `提示词预览：${approvalVisibleText(inspected.prompt, MAX_APPROVAL_PREVIEW_CODE_POINTS)}`,
    `计费相关参数：${parameters.length ? parameters.join(', ') : '默认/未提供'}`,
    `输入图/关键帧：${mediaInputCount}`,
    `其它顶层字段：${otherKeys.length ? otherKeys.join(', ') : '无'}`,
    `正文大小：${Buffer.byteLength(inspected.encodedBody, 'utf8')} bytes`,
    `请求 SHA-256: ${digest}`,
    '确认后可能产生供应商费用；价格尚未由本机可靠估算。'
  ].join('\n')
}

function isLegacyImport(value: unknown): value is PaidMediaLegacyUnresolvedInput {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const record = value as Record<string, unknown>
  const required = [
    'operationId',
    'path',
    'requestSha256',
    'createdAt',
    'updatedAt',
    'state'
  ]
  const allowed = new Set([...required, 'lastStatus', 'retryAfterSeconds'])
  return (
    required.every((key) => Object.prototype.hasOwnProperty.call(record, key)) &&
    Object.keys(record).every((key) => allowed.has(key))
  )
}

function isLegacyBootstrapInput(value: unknown): value is PaidMediaLegacyBootstrapInput {
  return (
    value === null ||
    isLegacyImport(value) ||
    (hasExactKeys(value, ['kind']) && value.kind === 'migrated')
  )
}

function invalidRequest(): PaidMediaIpcReply<never> {
  return {
    ok: false,
    error: {
      code: 'invalid_request',
      message: 'Paid media IPC request is invalid'
    }
  }
}

function cancelledReconciliation(): PaidMediaIpcReply<never> {
  return {
    ok: false,
    error: {
      code: 'cancelled',
      message: 'Paid media reconciliation was cancelled'
    }
  }
}

function cancelledPaidMediaRequest(): PaidMediaIpcReply<never> {
  return {
    ok: false,
    error: {
      code: 'cancelled',
      message: 'Paid media request was cancelled'
    }
  }
}

function operationFailed(message = 'Paid media operation failed'): PaidMediaIpcReply<never> {
  return {
    ok: false,
    error: {
      code: 'operation_failed',
      message
    }
  }
}

function taggedFailure(
  code: 'operation_mismatch' | 'operation_expired' | 'unresolved',
  message: string
): PaidMediaIpcReply<never> {
  return { ok: false, error: { code, message } }
}

function mapOperationFailure(error: unknown): PaidMediaIpcReply<never> {
  if (!error || typeof error !== 'object') return operationFailed()
  const value = error as { name?: unknown; message?: unknown }
  const name = typeof value.name === 'string' ? value.name : ''
  const message = typeof value.message === 'string' ? value.message : ''
  if (message === 'Paid media retry does not match the original operation') {
    return taggedFailure(
      'operation_mismatch',
      'Paid media retry does not match its original operation'
    )
  }
  if (
    message ===
    'Paid media retry operation is too old for automatic replay; reconcile it manually'
  ) {
    return taggedFailure(
      'operation_expired',
      'Paid media retry is outside the automatic recovery window'
    )
  }
  if (
    name === 'PaidMediaUnresolvedOperationError' ||
    message === 'A paid media operation is still unresolved'
  ) {
    return taggedFailure('unresolved', 'Another paid media operation is unresolved')
  }
  return operationFailed()
}

async function runOperation<T>(action: () => Promise<T>): Promise<PaidMediaIpcReply<T>> {
  try {
    return { ok: true, value: await action() }
  } catch (error) {
    return mapOperationFailure(error)
  }
}

export function registerPaidMediaIpc(
  dependencies: RegisterPaidMediaIpcDependencies
): PaidMediaIpcRegistration {
  activeRegistrations.get(dependencies.ipcMain)?.dispose()
  let claimApprovalActive = false

  const cancelListener: IpcHandler = async (event, ...args) => {
    const denied = await authorize(dependencies, event)
    if (denied) return
    if (
      args.length !== 1 ||
      !hasExactKeys(args[0], ['operationId']) ||
      typeof args[0].operationId !== 'string' ||
      !OPERATION_ID_PATTERN.test(args[0].operationId)
    ) {
      return
    }
    try {
      dependencies.service.cancel(args[0].operationId)
    } catch {
      // A one-way cancellation command has no renderer-facing error channel.
    }
  }

  dependencies.ipcMain.handle(PAID_MEDIA_IPC_CHANNELS.claim, async (event, ...args) => {
    const denied = await authorize(dependencies, event)
    if (denied) return denied
    if (args.length !== 1 || !args[0] || typeof args[0] !== 'object') {
      return invalidRequest()
    }
    const retry = Object.prototype.hasOwnProperty.call(args[0], 'retryOperationId')
    if (
      !hasExactKeys(
        args[0],
        retry ? ['path', 'encodedBody', 'retryOperationId'] : ['path', 'encodedBody']
      ) ||
      typeof args[0].path !== 'string' ||
      !PAID_MEDIA_PATHS.has(args[0].path) ||
      typeof args[0].encodedBody !== 'string' ||
      args[0].encodedBody.length === 0 ||
      Buffer.byteLength(args[0].encodedBody, 'utf8') > MAX_PAID_MEDIA_REQUEST_BYTES ||
      (retry &&
        (typeof args[0].retryOperationId !== 'string' ||
          !OPERATION_ID_PATTERN.test(args[0].retryOperationId)))
    ) {
      return invalidRequest()
    }
    let inspectedBody: ReturnType<typeof inspectPaidMediaRequestBody>
    try {
      inspectedBody = inspectPaidMediaRequestBody(
        args[0].encodedBody,
        args[0].path as '/v1/images/generations' | '/v1/videos/generations'
      )
    } catch {
      return invalidRequest()
    }
    if (!retry) {
      try {
        await dependencies.service.ensureMediaProbeReady()
      } catch {
        return operationFailed('Paid media safety probe is unavailable')
      }
      if (claimApprovalActive) {
        return taggedFailure('unresolved', 'Another paid media operation is unresolved')
      }
      claimApprovalActive = true
      try {
        const unresolvedOperations = await dependencies.service.listUnresolved()
        if (unresolvedOperations.length > 0) {
          return taggedFailure('unresolved', 'Another paid media operation is unresolved')
        }
        const owner = dependencies.ownerWindow()
        if (!owner) return operationFailed('Paid media approval is unavailable')
        const kind = args[0].path === '/v1/videos/generations' ? '视频' : '图片'
        const approval = await dependencies.dialog.showMessageBox(owner, {
          type: 'warning',
          title: '纳川付费媒体授权',
          message: `确认发起新的付费${kind}任务？`,
          detail: paidMediaApprovalDetail(args[0].path, inspectedBody),
          buttons: ['取消', '确认发起'],
          defaultId: 0,
          cancelId: 0,
          noLink: true
        })
        if (approval.response !== 1) return cancelledPaidMediaRequest()
        return await runOperation(() =>
          dependencies.service.claim(args[0] as unknown as PaidMediaClaimRequest)
        )
      } catch {
        return operationFailed()
      } finally {
        claimApprovalActive = false
      }
    }
    return runOperation(() =>
      dependencies.service.claim(args[0] as unknown as PaidMediaClaimRequest)
    )
  })
  dependencies.ipcMain.handle(PAID_MEDIA_IPC_CHANNELS.execute, async (event, ...args) => {
    const denied = await authorize(dependencies, event)
    if (denied) return denied
    if (
      args.length !== 1 ||
      !hasExactKeys(args[0], ['operationId', 'path', 'encodedBody'])
    ) {
      return invalidRequest()
    }
    return runOperation(() =>
      dependencies.service.execute(args[0] as unknown as PaidMediaExecuteRequest)
    )
  })
  dependencies.ipcMain.handle(PAID_MEDIA_IPC_CHANNELS.pollVideo, async (event, ...args) => {
    const denied = await authorize(dependencies, event)
    if (denied) return denied
    if (
      args.length !== 1 ||
      !hasExactKeys(args[0], ['taskAlias', 'model']) ||
      typeof args[0].taskAlias !== 'string' ||
      !VIDEO_TASK_ALIAS_PATTERN.test(args[0].taskAlias) ||
      typeof args[0].model !== 'string' ||
      !args[0].model.trim() ||
      Buffer.byteLength(args[0].model, 'utf8') > 1024 ||
      /[\u0000-\u001f\u007f]/.test(args[0].model)
    ) {
      return invalidRequest()
    }
    return runOperation(() =>
      dependencies.service.pollVideo(args[0] as unknown as PaidVideoPollRequest)
    )
  })
  dependencies.ipcMain.handle(PAID_MEDIA_IPC_CHANNELS.list, async (event, ...args) => {
    const denied = await authorize(dependencies, event)
    if (denied) return denied
    if (args.length !== 0) return invalidRequest()
    return runOperation(() => dependencies.service.listUnresolved())
  })
  dependencies.ipcMain.handle(PAID_MEDIA_IPC_CHANNELS.recoverArchive, async (event, ...args) => {
    const denied = await authorize(dependencies, event)
    if (denied) return denied
    if (
      args.length !== 1 ||
      !hasExactKeys(args[0], ['operationId']) ||
      typeof args[0].operationId !== 'string' ||
      !OPERATION_ID_PATTERN.test(args[0].operationId)
    ) {
      return invalidRequest()
    }
    return runOperation(() => dependencies.service.recoverArchived(args[0].operationId))
  })
  dependencies.ipcMain.handle(PAID_MEDIA_IPC_CHANNELS.listArchives, async (event, ...args) => {
    const denied = await authorize(dependencies, event)
    if (denied) return denied
    if (args.length > 1) return invalidRequest()
    const input = args.length === 0 ? {} : args[0]
    if (!input || typeof input !== 'object' || Array.isArray(input)) return invalidRequest()
    const value = input as Record<string, unknown>
    if (
      Object.keys(value).some((key) => key !== 'cursor' && key !== 'limit') ||
      (value.cursor !== undefined &&
        (typeof value.cursor !== 'string' || value.cursor.length > 256)) ||
      (value.limit !== undefined &&
        (!Number.isSafeInteger(value.limit) || Number(value.limit) < 1 || Number(value.limit) > 100))
    ) {
      return invalidRequest()
    }
    return runOperation(() =>
      dependencies.service.listRecoverableArchives(value as {
        cursor?: string
        limit?: number
      })
    )
  })
  dependencies.ipcMain.handle(PAID_MEDIA_IPC_CHANNELS.acknowledge, async (event, ...args) => {
    const denied = await authorize(dependencies, event)
    if (denied) return denied
    if (
      args.length !== 1 ||
      !hasExactKeys(args[0], [
        'operationId',
        'resultSha256',
        'archiveReceiptSha256'
      ]) ||
      typeof args[0].operationId !== 'string' ||
      !OPERATION_ID_PATTERN.test(args[0].operationId) ||
      typeof args[0].resultSha256 !== 'string' ||
      !SHA256_PATTERN.test(args[0].resultSha256) ||
      typeof args[0].archiveReceiptSha256 !== 'string' ||
      !SHA256_PATTERN.test(args[0].archiveReceiptSha256)
    ) {
      return invalidRequest()
    }
    return runOperation(() =>
      dependencies.service.acknowledgeDelivered({
        operationId: args[0].operationId as string,
        resultSha256: args[0].resultSha256 as string,
        archiveReceiptSha256: args[0].archiveReceiptSha256 as string
      })
    )
  })
  dependencies.ipcMain.handle(PAID_MEDIA_IPC_CHANNELS.abandon, async (event, ...args) => {
    const denied = await authorize(dependencies, event)
    if (denied) return denied
    if (
      args.length !== 1 ||
      !hasExactKeys(args[0], ['operationId', 'evidence']) ||
      typeof args[0].operationId !== 'string' ||
      !OPERATION_ID_PATTERN.test(args[0].operationId) ||
      !boundedText(args[0].evidence, MAX_RECONCILIATION_EVIDENCE_BYTES)
    ) {
      return invalidRequest()
    }
    return runOperation(() =>
      dependencies.service.abandonUndispatchedClaim(
        args[0].operationId,
        args[0].evidence
      )
    )
  })
  dependencies.ipcMain.handle(PAID_MEDIA_IPC_CHANNELS.reconcile, async (event, ...args) => {
    const denied = await authorize(dependencies, event)
    if (denied) return denied
    if (
      args.length !== 1 ||
      !hasExactKeys(args[0], ['operationId', 'reason', 'evidence']) ||
      typeof args[0].operationId !== 'string' ||
      !OPERATION_ID_PATTERN.test(args[0].operationId) ||
      !boundedText(args[0].reason, MAX_RECONCILIATION_REASON_BYTES) ||
      !boundedText(args[0].evidence, MAX_RECONCILIATION_EVIDENCE_BYTES)
    ) {
      return invalidRequest()
    }
    try {
      const owner = dependencies.ownerWindow()
      if (!owner) {
        return {
          ok: false,
          error: {
            code: 'operation_failed',
            message: 'Paid media reconciliation is unavailable'
          }
        }
      }
      const trustedOperation = (await dependencies.service.listUnresolved()).find(
        (candidate) => candidate.operationId === args[0].operationId
      )
      if (!trustedOperation) {
        return operationFailed('Paid media reconciliation is unavailable')
      }
      const warning = await dependencies.dialog.showMessageBox(owner, {
        type: 'warning',
        title: '纳川付费媒体恢复',
        message: '已核查供应商任务和账单？',
        detail: [
          `操作：${trustedOperation.operationId}`,
          `接口：${trustedOperation.path}`,
          `主账本状态：${trustedOperation.state}`,
          `已派发次数：${trustedOperation.dispatchCount}`,
          `创建时间：${new Date(trustedOperation.createdAt).toISOString()}`,
          '',
          `用户提供的核对说明（未验证）：${args[0].evidence}`,
          '',
          '核销后将不再阻止新的付费请求。'
        ].join('\n'),
        buttons: ['取消', '已核查，继续'],
        defaultId: 0,
        cancelId: 0,
        noLink: true
      })
      if (warning.response !== 1) return cancelledReconciliation()
      const finalConfirmation = await dependencies.dialog.showMessageBox(owner, {
        type: 'warning',
        title: '纳川付费媒体最终确认',
        message: '确认人工核销这个付费操作？',
        detail: '该动作会按本机账本保留策略写入核销记录，并解除新付费请求的门禁。',
        buttons: ['取消', '最终确认核销'],
        defaultId: 0,
        cancelId: 0,
        noLink: true
      })
      if (finalConfirmation.response !== 1) return cancelledReconciliation()
      return runOperation(() =>
        dependencies.service.reconcileManually(args[0] as {
          operationId: string
          reason: string
          evidence: string
        })
      )
    } catch {
      return operationFailed()
    }
  })
  dependencies.ipcMain.handle(PAID_MEDIA_IPC_CHANNELS.importLegacy, async (event, ...args) => {
    const denied = await authorize(dependencies, event)
    if (denied) return denied
    if (args.length !== 1 || !isLegacyBootstrapInput(args[0])) {
      return invalidRequest()
    }
    return runOperation(() => dependencies.service.bootstrapLegacyMigration(args[0]))
  })
  dependencies.ipcMain.on(PAID_MEDIA_IPC_CHANNELS.cancel, cancelListener)

  const registration: PaidMediaIpcRegistration = {
    dispose: () => {
      if (activeRegistrations.get(dependencies.ipcMain) !== registration) return
      dependencies.ipcMain.removeHandler(PAID_MEDIA_IPC_CHANNELS.claim)
      dependencies.ipcMain.removeHandler(PAID_MEDIA_IPC_CHANNELS.execute)
      dependencies.ipcMain.removeHandler(PAID_MEDIA_IPC_CHANNELS.pollVideo)
      dependencies.ipcMain.removeHandler(PAID_MEDIA_IPC_CHANNELS.recoverArchive)
      dependencies.ipcMain.removeHandler(PAID_MEDIA_IPC_CHANNELS.listArchives)
      dependencies.ipcMain.removeHandler(PAID_MEDIA_IPC_CHANNELS.list)
      dependencies.ipcMain.removeHandler(PAID_MEDIA_IPC_CHANNELS.acknowledge)
      dependencies.ipcMain.removeHandler(PAID_MEDIA_IPC_CHANNELS.abandon)
      dependencies.ipcMain.removeHandler(PAID_MEDIA_IPC_CHANNELS.reconcile)
      dependencies.ipcMain.removeHandler(PAID_MEDIA_IPC_CHANNELS.importLegacy)
      dependencies.ipcMain.removeListener(PAID_MEDIA_IPC_CHANNELS.cancel, cancelListener)
      activeRegistrations.delete(dependencies.ipcMain)
    }
  }
  activeRegistrations.set(dependencies.ipcMain, registration)
  return registration
}
