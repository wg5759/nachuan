// ADR-0013 Web 形态：付费媒体 13 个方法映射到网关路由；fresh claim 在本层
// 显示冻结请求摘要并绑定 consent digest，人工 reconcile 在本层做双确认。
// 引擎的 4xx/5xx 经 WebHttpError 如实上抛，绝不伪造成功。
// trackUnauthorized=false：付费媒体是独立金融信任域，其 401 不触发运行时 Key 登录闸。

import type { DesktopAPI } from '../renderer/src/env'
import { WebHttpError, type WebHttpClient } from './http'

type PaidMediaApi = Pick<
  DesktopAPI,
  | 'claimPaidMedia'
  | 'executePaidMedia'
  | 'pollPaidVideo'
  | 'recoverPaidMediaArchive'
  | 'listPaidMediaArchives'
  | 'cancelPaidMedia'
  | 'listPaidMediaOperations'
  | 'acknowledgePaidMedia'
  | 'abandonPaidMediaClaim'
  | 'reconcilePaidMedia'
  | 'importLegacyPaidMediaJournal'
> &
  Required<Pick<DesktopAPI, 'resolvePaidMediaAsset' | 'releasePaidMediaAsset'>>

const CONFIRM_DIGEST_DOMAIN = 'nachuan-paid-media-web-confirm-v1'
const ASSET_REFERENCE_RE = /^nachuan-paid-media:\/\/sha256\/([0-9a-f]{64})$/
const MAX_ASSET_BYTES = 24 * 1024 * 1024
const MAX_CACHED_ASSETS = 8
const MAX_CACHED_ASSET_BYTES = 32 * 1024 * 1024
const MAX_CONCURRENT_ASSET_READS = 2
const MAX_QUEUED_ASSET_READS = 8
const ALLOWED_ASSET_MEDIA_TYPES = new Set([
  'image/png',
  'image/jpeg',
  'image/gif',
  'image/webp',
  'video/mp4',
  'video/webm'
])

export class WebPaidMediaConsentError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'WebPaidMediaConsentError'
  }
}

function toHex(bytes: ArrayBuffer): string {
  return [...new Uint8Array(bytes)].map((value) => value.toString(16).padStart(2, '0')).join('')
}

async function sha256Hex(subtle: SubtleCrypto, value: string): Promise<string> {
  return toHex(await subtle.digest('SHA-256', new TextEncoder().encode(value)))
}

async function sha256Bytes(subtle: SubtleCrypto, value: ArrayBuffer): Promise<string> {
  return toHex(await subtle.digest('SHA-256', value))
}

function collectAssetReferences(value: unknown): string[] {
  const references = new Set<string>()
  const visit = (candidate: unknown, depth: number): void => {
    if (depth > 8 || references.size >= 8) return
    if (typeof candidate === 'string') {
      if (ASSET_REFERENCE_RE.test(candidate)) references.add(candidate)
      return
    }
    if (Array.isArray(candidate)) {
      for (const item of candidate.slice(0, 128)) visit(item, depth + 1)
      return
    }
    if (candidate && typeof candidate === 'object') {
      for (const item of Object.values(candidate as Record<string, unknown>).slice(0, 128)) {
        visit(item, depth + 1)
      }
    }
  }
  visit(value, 0)
  return [...references]
}

function oneLine(value: unknown, maximum = 240): string {
  if (typeof value !== 'string') return '(not provided)'
  const normalized = value.replace(/\s+/g, ' ').trim()
  return normalized.length <= maximum ? normalized : `${normalized.slice(0, maximum)}…`
}

const SECRET_FIELD_PATTERN = /(?:^|[_-])(api[_-]?key|authorization|password|secret|token)(?:$|[_-])/i
const LARGE_PAYLOAD_FIELD_PATTERN = /image|audio|video|mask|file|data|url|reference|input/i

function safeExtraBodyValue(field: string, value: unknown): string {
  if (SECRET_FIELD_PATTERN.test(field)) return '[redacted]'
  if (Array.isArray(value)) return `[${value.length} items]`
  if (value && typeof value === 'object') {
    const keys = Object.keys(value as Record<string, unknown>).sort()
    const visible = keys.slice(0, 12).join(', ')
    return `{keys: ${visible}${keys.length > 12 ? ', …' : ''}}`
  }
  if (typeof value === 'string') {
    if (LARGE_PAYLOAD_FIELD_PATTERN.test(field) || value.length > 120) {
      return `[string length: ${value.length}]`
    }
    return oneLine(value, 120)
  }
  if (value === null) return 'null'
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  return `(${typeof value})`
}

function appendExtraBodyDetails(
  details: string[],
  extraBody: unknown
): void {
  if (!extraBody || typeof extraBody !== 'object' || Array.isArray(extraBody)) return
  const fields = extraBody as Record<string, unknown>
  if (fields.image !== undefined) {
    const imageCount = Array.isArray(fields.image) ? fields.image.length : 1
    details.push(`extra_body.image count: ${imageCount}`)
  }
  if (fields.mode !== undefined) {
    details.push(`extra_body.mode: ${safeExtraBodyValue('mode', fields.mode)}`)
  }
  const additional = Object.entries(fields)
    .filter(([field]) => field !== 'image' && field !== 'mode')
    .sort(([left], [right]) => left.localeCompare(right))
  for (const [field, value] of additional.slice(0, 16)) {
    details.push(`extra_body.${field}: ${safeExtraBodyValue(field, value)}`)
  }
  if (additional.length > 16) {
    details.push(`extra_body additional fields: ${additional.length - 16} more`)
  }
}

function confirmationMessage(
  path: string,
  encodedBody: string,
  bodySha256: string
): string {
  let request: Record<string, unknown> = {}
  try {
    const parsed: unknown = JSON.parse(encodedBody)
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      request = parsed as Record<string, unknown>
    }
  } catch {
    // 网关会独立拒绝非法正文；确认层仍展示冻结字节的大小与摘要。
  }
  const details = [
    '纳川付费媒体授权 / Paid media confirmation',
    '',
    '此操作可能产生供应商费用。确认后将创建可恢复、可对账的付费操作。',
    'This operation may incur provider charges.',
    '',
    `接口 / Endpoint: ${path}`,
    `模型 / Model: ${oneLine(request.model, 120)}`,
    `提示词 / Prompt: ${oneLine(request.prompt)}`,
    `正文大小 / Body bytes: ${new TextEncoder().encode(encodedBody).byteLength}`,
    `正文 SHA-256 / Body SHA-256: ${bodySha256}`
  ]
  for (const field of ['n', 'size', 'mode', 'height', 'width', 'num_frames', 'frame_rate']) {
    if (request[field] !== undefined) details.push(`${field}: ${String(request[field])}`)
  }
  appendExtraBodyDetails(details, request.extra_body)
  details.push('', '确认继续？ / Continue?')
  return details.join('\n')
}

function reconciliationMessage(
  input: { operationId: string; reason: string; evidence: string },
  final: boolean
): string {
  return [
    final
      ? '最终确认：关闭付费媒体操作 / Final reconciliation confirmation'
      : '人工核销付费媒体操作 / Reconcile paid media operation',
    '',
    `Operation: ${oneLine(input.operationId, 120)}`,
    `Reason: ${oneLine(input.reason)}`,
    `Evidence: ${oneLine(input.evidence)}`,
    '',
    final
      ? '这是第二次且最终确认。核销后该操作不能自动执行或重试。\nContinue with final reconciliation?'
      : '请先核对外部供应商账单与结果证据。\nHave you verified the external billing and result evidence?'
  ].join('\n')
}

export function createWebPaidMediaApi(http: WebHttpClient): PaidMediaApi {
  // shim 先于 renderer bundle 执行；在这里捕获原生能力，避免应用脚本随后替换。
  const confirmUser =
    typeof globalThis.confirm === 'function' ? globalThis.confirm.bind(globalThis) : null
  const subtle = globalThis.crypto?.subtle ?? null
  const createObjectURL = globalThis.URL?.createObjectURL?.bind(globalThis.URL) ?? null
  const revokeObjectURL = globalThis.URL?.revokeObjectURL?.bind(globalThis.URL) ?? null
  type MaterializedAsset = { readonly url: string; readonly bytes: number; owners: number }
  type AssetRecord = { promise: Promise<MaterializedAsset>; entry?: MaterializedAsset }
  const assetCache = new Map<string, AssetRecord>()
  const assetReadQueue: Array<() => void> = []
  const assetCacheWaiters: Array<() => void> = []
  const assetByteWaiters: Array<{ bytes: number; resume: () => void }> = []
  let activeAssetReads = 0
  let reservedAssetBytes = 0
  let cachedAssetBytes = 0
  const post = <T = unknown>(verb: string, payload: unknown, approval = false): Promise<T> =>
    http.requestJson<T>({
      method: 'POST',
      target: `/v1/paid-media/web/${verb}`,
      json: payload,
      trackUnauthorized: false,
      // claim/execute/abandon/reconcile/import-legacy 属审批信任域：
      // 网关在 Bearer 之外另要求 X-Nachuan-Approval-Key（ADR-0013 §4 独立授权）。
      ...(approval ? { includeApprovalKey: true } : {})
    })

  const runAssetRead = <T>(task: () => Promise<T>): Promise<T> =>
    new Promise<T>((resolve, reject) => {
      const start = (): void => {
        activeAssetReads += 1
        void task()
          .then(resolve, reject)
          .finally(() => {
            activeAssetReads -= 1
            assetReadQueue.shift()?.()
          })
      }
      if (activeAssetReads < MAX_CONCURRENT_ASSET_READS) {
        start()
      } else if (assetReadQueue.length >= MAX_QUEUED_ASSET_READS) {
        reject(new Error('Paid media Web asset read capacity is exhausted'))
      } else {
        assetReadQueue.push(start)
      }
    })

  const drainAssetByteWaiters = (): void => {
    while (assetByteWaiters.length > 0) {
      const next = assetByteWaiters[0]
      if (cachedAssetBytes + reservedAssetBytes + next.bytes > MAX_CACHED_ASSET_BYTES) return
      assetByteWaiters.shift()
      reservedAssetBytes += next.bytes
      next.resume()
    }
  }

  const reserveMaterializedBytes = async (bytes: number): Promise<void> => {
    if (cachedAssetBytes + reservedAssetBytes + bytes <= MAX_CACHED_ASSET_BYTES) {
      reservedAssetBytes += bytes
      return
    }
    if (assetByteWaiters.length >= MAX_QUEUED_ASSET_READS) {
      throw new Error('Paid media Web asset byte-budget queue capacity is exhausted')
    }
    await new Promise<void>((resume) => assetByteWaiters.push({ bytes, resume }))
  }

  const wakeAssetCacheWaiters = (): void => {
    for (const resume of assetCacheWaiters.splice(0)) resume()
  }

  const waitForAssetCacheSlot = async (reference: string): Promise<void> => {
    while (!assetCache.has(reference) && assetCache.size >= MAX_CACHED_ASSETS) {
      if (assetCacheWaiters.length >= MAX_QUEUED_ASSET_READS) {
        throw new Error('Paid media Web asset cache queue capacity is exhausted')
      }
      await new Promise<void>((resume) => assetCacheWaiters.push(resume))
    }
  }

  const fetchAsset = async (
    reference: string,
    createBlob: boolean
  ): Promise<MaterializedAsset | null> => runAssetRead(async () => {
    const matched = ASSET_REFERENCE_RE.exec(reference)
    if (
      !matched ||
      !subtle ||
      (createBlob && (!createObjectURL || typeof Blob !== 'function'))
    ) {
      throw new Error('Paid media Web asset materialization is unavailable')
    }
    const expectedSha256 = matched[1]
    const response = await http.open({
      method: 'POST',
      target: '/v1/paid-media/web/read-asset',
      body: JSON.stringify({ reference }),
      contentType: 'application/json',
      trackUnauthorized: false
    })
    if (!response.ok) {
      throw new WebHttpError(response.status, await response.text())
    }
    const mediaType = (response.headers.get('content-type') ?? '')
      .split(';', 1)[0]
      .trim()
      .toLowerCase()
    const declaredLength = Number(response.headers.get('content-length'))
    const declaredSha256 = response.headers.get('x-content-sha256') ?? ''
    if (
      !ALLOWED_ASSET_MEDIA_TYPES.has(mediaType) ||
      !Number.isSafeInteger(declaredLength) ||
      declaredLength < 1 ||
      declaredLength > MAX_ASSET_BYTES ||
      declaredSha256 !== expectedSha256
    ) {
      throw new Error('Paid media Web asset receipt is invalid')
    }
    if (createBlob) await reserveMaterializedBytes(declaredLength)
    let reservationHeld = createBlob
    try {
      const bytes = await response.arrayBuffer()
      if (bytes.byteLength !== declaredLength) {
        throw new Error('Paid media Web asset length does not match its receipt')
      }
      if ((await sha256Bytes(subtle, bytes)) !== expectedSha256) {
        throw new Error('Paid media Web asset digest does not match its durable reference')
      }
      if (!createBlob) return null
      const entry = {
        url: createObjectURL!(new Blob([bytes], { type: mediaType })),
        bytes: declaredLength,
        owners: 0
      }
      reservedAssetBytes -= declaredLength
      reservationHeld = false
      cachedAssetBytes += declaredLength
      return entry
    } finally {
      if (reservationHeld) reservedAssetBytes -= declaredLength
      if (reservationHeld) drainAssetByteWaiters()
    }
  })

  const dropAsset = (reference: string, record: AssetRecord, entry: MaterializedAsset): void => {
    if (assetCache.get(reference) !== record) return
    assetCache.delete(reference)
    cachedAssetBytes = Math.max(0, cachedAssetBytes - entry.bytes)
    revokeObjectURL?.(entry.url)
    wakeAssetCacheWaiters()
    drainAssetByteWaiters()
  }

  const materialize = async (reference: string): Promise<string> => {
    if (!ASSET_REFERENCE_RE.test(reference)) return reference
    let record = assetCache.get(reference)
    if (!record) {
      await waitForAssetCacheSlot(reference)
      // Another caller for the same reference may have populated the slot while this call waited.
      record = assetCache.get(reference)
    }
    if (!record) {
      record = {} as AssetRecord
      record.promise = fetchAsset(reference, true).then((entry) => {
        if (!entry) throw new Error('Paid media Web asset materialization is unavailable')
        record!.entry = entry
        return entry
      })
      assetCache.set(reference, record)
      // Let same-reference waiters join this singleflight even if the cache is full again.
      wakeAssetCacheWaiters()
      void record.promise.catch(() => {
        if (assetCache.get(reference) === record) {
          assetCache.delete(reference)
          wakeAssetCacheWaiters()
        }
      })
    }
    const entry = await record.promise
    entry.owners += 1
    return entry.url
  }

  const prefetchAssets = async (value: unknown): Promise<void> => {
    // Delivery verification remains before the renderer's durable callback/ACK, but it does not
    // create or retain blob URLs. Historical media obtains an owned blob only when near-visible.
    for (const reference of collectAssetReferences(value)) {
      await fetchAsset(reference, false)
    }
  }

  const disposeAssets = (): void => {
    for (const [reference, record] of assetCache) {
      assetCache.delete(reference)
      void record.promise
        .then((entry) => {
          cachedAssetBytes = Math.max(0, cachedAssetBytes - entry.bytes)
          revokeObjectURL?.(entry.url)
        })
        .catch(() => {})
    }
  }
  if (typeof globalThis.addEventListener === 'function') {
    globalThis.addEventListener('pagehide', (event) => {
      if ('persisted' in event && event.persisted === true) return
      disposeAssets()
    })
  }

  const api: PaidMediaApi = {
    claimPaidMedia: async (input) => {
      if (input.retryOperationId !== undefined) {
        return post<Awaited<ReturnType<DesktopAPI['claimPaidMedia']>>>('claim', input, true)
      }
      if (!confirmUser || !subtle) {
        throw new WebPaidMediaConsentError(
          'Paid media confirmation is unavailable; no paid operation was created'
        )
      }
      // Bind the readable summary, digest and eventual request to the same immutable strings.
      const path = input.path
      const encodedBody = input.encodedBody
      const bodySha256 = await sha256Hex(subtle, encodedBody)
      if (!confirmUser(confirmationMessage(path, encodedBody, bodySha256))) {
        throw new WebPaidMediaConsentError(
          'Paid media request was not confirmed; no paid operation was created'
        )
      }
      const confirmSummarySha256 = await sha256Hex(
        subtle,
        `${CONFIRM_DIGEST_DOMAIN}\0${path}\0${bodySha256}`
      )
      return post<Awaited<ReturnType<DesktopAPI['claimPaidMedia']>>>(
        'claim',
        {
          path,
          encodedBody,
          user_confirmed: true,
          confirm_summary_sha256: confirmSummarySha256
        },
        true
      )
    },
    executePaidMedia: async (input) => {
      const result = await post<Awaited<ReturnType<DesktopAPI['executePaidMedia']>>>(
        'execute',
        input,
        true
      )
      if (result.ok) await prefetchAssets(result.result)
      return result
    },
    pollPaidVideo: async (input) => {
      const result = await post<Awaited<ReturnType<DesktopAPI['pollPaidVideo']>>>(
        'poll-video',
        input
      )
      await prefetchAssets(result)
      return result
    },
    recoverPaidMediaArchive: async (operationId: string) => {
      const result = await post<Awaited<ReturnType<DesktopAPI['recoverPaidMediaArchive']>>>(
        'recover-archive',
        { operationId }
      )
      await prefetchAssets(result)
      return result
    },
    listPaidMediaArchives: (input: { cursor?: string; limit?: number } = {}) =>
      post<Awaited<ReturnType<DesktopAPI['listPaidMediaArchives']>>>('list-archives', input),
    // 与 preload 的 ipcRenderer.send 语义一致：fire-and-forget，无回执。
    cancelPaidMedia: (operationId: string): void => {
      void post('cancel', { operationId }).catch(() => {})
    },
    listPaidMediaOperations: () =>
      post<Awaited<ReturnType<DesktopAPI['listPaidMediaOperations']>>>('list', {}),
    acknowledgePaidMedia: (deliveryProof) => post('acknowledge', deliveryProof),
    abandonPaidMediaClaim: (operationId: string, evidence: string) =>
      post('abandon', { operationId, evidence }, true),
    reconcilePaidMedia: async (input) => {
      if (!confirmUser) {
        throw new WebPaidMediaConsentError(
          'Paid media reconciliation confirmation is unavailable; no operation was changed'
        )
      }
      if (!confirmUser(reconciliationMessage(input, false))) {
        throw new WebPaidMediaConsentError(
          'Paid media reconciliation was cancelled; no operation was changed'
        )
      }
      if (!confirmUser(reconciliationMessage(input, true))) {
        throw new WebPaidMediaConsentError(
          'Final paid media reconciliation was cancelled; no operation was changed'
        )
      }
      return post(
        'reconcile',
        { ...input, user_confirmed: true, confirm_final: true },
        true
      )
    },
    importLegacyPaidMediaJournal: (input) => post('import-legacy', input, true),
    resolvePaidMediaAsset: (reference: string) => materialize(reference),
    releasePaidMediaAsset: (reference: string): void => {
      const record = assetCache.get(reference)
      if (!record) return
      if (record.entry) {
        if (record.entry.owners > 0) record.entry.owners -= 1
        if (record.entry.owners === 0) dropAsset(reference, record, record.entry)
        return
      }
      void record.promise.then((entry) => {
        if (entry.owners > 0) entry.owners -= 1
        if (entry.owners === 0) dropAsset(reference, record, entry)
      })
    }
  }
  return Object.freeze(api)
}
