import type { CatalogModel, CatalogProvider, ConnectionSummary, LocalServer } from '../api'
import type { ModelInfo } from '../store'

type SaveDetectedLocalConnection = (
  provider: string,
  payload: {
    type: string
    api_key: string
    base_url: string
    enabled_models: CatalogModel[]
    preserve_existing_credential: boolean
  }
) => Promise<{ ok: boolean; models: string[]; rejected_models?: string[]; error?: string }>

export type DetectedLocalConnectionResult =
  | { ok: true; connected: number; rejected: number; activation: 'confirmed' | 'pending' }
  | { ok: false; reason: 'rejected' | 'exception' }

export type StoredConnectionRemovalResult =
  | { ok: true }
  | { ok: false; reason: 'rejected' | 'exception' }

const OBVIOUS_NON_CHAT_MODEL = /embed|rerank/i
const EXPLICIT_CHAT_MODEL = /(?:^|[-_.:/])(?:chat|instruct|assistant)(?:$|[-_.:/])/i

/**
 * A successful save is not yet a renderer-ready connection. Confirm that the
 * authoritative model roster contains every model the Gateway just promoted
 * before the UI tells the customer the connection is ready to use.
 */
export async function refreshVerifiedConnectionModels(
  expectedModelIds: readonly string[],
  fetchModels: () => Promise<ModelInfo[]>,
  commitModels: (models: ModelInfo[]) => void
): Promise<boolean> {
  let models: ModelInfo[]
  try {
    models = await fetchModels()
  } catch {
    return false
  }
  commitModels(models)
  const available = new Set(models.map((model) => model.id))
  return expectedModelIds.length > 0 && expectedModelIds.every((id) => available.has(id))
}

/**
 * Local `/models` responses rarely include modality metadata. Fail closed for
 * obvious vector/reranker IDs, then prefer an ID that explicitly says it is a
 * chat/instruction model. The original server order is the final fallback.
 */
export function recommendedLocalChatModel(modelIds: string[]): string | null {
  const seen = new Set<string>()
  const candidates = modelIds
    .map((id) => id.trim())
    .filter((id) => id.length > 0 && !OBVIOUS_NON_CHAT_MODEL.test(id))
    .filter((id) => {
      if (seen.has(id)) return false
      seen.add(id)
      return true
    })
  return candidates.find((id) => EXPLICIT_CHAT_MODEL.test(id)) ?? candidates[0] ?? null
}

function explicitPositiveRank(value: number | undefined): number | null {
  return Number.isInteger(value) && Number(value) > 0 ? Number(value) : null
}

/** Pick exactly one catalog-declared chat model for a new connection. */
export function recommendedCatalogChatModel(models: CatalogModel[]): CatalogModel | null {
  const candidates = models
    .map((model, index) => ({ model, index, rank: explicitPositiveRank(model.rank) }))
    .filter(({ model }) => {
      const modality = model.modality?.trim().toLowerCase()
      if (modality && modality !== 'chat') return false
      return !OBVIOUS_NON_CHAT_MODEL.test(`${model.id} ${model.upstream_model}`)
    })
    .sort((left, right) => {
      if (left.rank !== null && right.rank !== null) return left.rank - right.rank || left.index - right.index
      if (left.rank !== null) return -1
      if (right.rank !== null) return 1
      return left.index - right.index
    })
  return candidates[0]?.model ?? null
}

export function initialEnabledModelIds(
  catalogModels: CatalogModel[],
  connection?: ConnectionSummary
): string[] {
  if (connection) {
    return [
      ...new Set(
        (connection.enabled_models ?? []).map((model) => model.id.trim()).filter(Boolean)
      )
    ]
  }
  const recommended = recommendedCatalogChatModel(catalogModels)
  if (!recommended) return []
  const mediaSiblings = catalogModels
    .filter((model) => {
      const modality = model.modality?.trim().toLowerCase()
      return modality === 'image' || modality === 'video'
    })
    .map((model) => model.id.trim())
    .filter(Boolean)
  return [...new Set([recommended.id, ...mediaSiblings])]
}

export function connectionModelChoices(
  catalogModels: CatalogModel[],
  connection?: ConnectionSummary
): CatalogModel[] {
  if (!connection) return [...catalogModels]
  const stored = connection.enabled_models ?? []
  const storedById = new Map(stored.map((model) => [model.id, model]))
  const catalogIds = new Set(catalogModels.map((model) => model.id))
  return [
    ...catalogModels.map((model) => storedById.get(model.id) ?? model),
    ...stored.filter((model) => !catalogIds.has(model.id))
  ]
}

/**
 * A first-time simple connection may ask the backend to discover and verify
 * models. Existing receipts and any explicit advanced choice always win.
 */
export function shouldAutoDiscoverCatalogModels(
  provider: CatalogProvider,
  connection: ConnectionSummary | undefined,
  manualModelSelection: boolean
): boolean {
  if (connection?.state === 'verified' || manualModelSelection) return false
  if (provider.auto_discover_models === true) return true
  return (
    provider.models.length === 0 &&
    (provider.type === 'openai_compat' || provider.type === 'perplexity')
  )
}

/** Build the exact model manifest sent to the closed backend transaction. */
export function selectedCatalogModelsForSave(
  models: CatalogModel[],
  selectedIds: ReadonlySet<string>,
  autoDiscover: boolean
): CatalogModel[] {
  if (autoDiscover) return []
  return models.filter((model) => selectedIds.has(model.id))
}

function modelSelectionSignature(
  models: CatalogModel[],
  selectedIds: ReadonlySet<string>
): string {
  const roster = models
    .map((model) => [model.id, model.upstream_model])
    .sort(([leftId, leftUpstream], [rightId, rightUpstream]) =>
      leftId.localeCompare(rightId) || leftUpstream.localeCompare(rightUpstream)
    )
  return JSON.stringify({ roster, selected: [...selectedIds].sort() })
}

/** Advanced input is manual only while it differs from the card's current baseline. */
export function hasCustomizedModelSelection(
  initialModels: CatalogModel[],
  initialSelectedIds: ReadonlySet<string>,
  currentModels: CatalogModel[],
  currentSelectedIds: ReadonlySet<string>,
  pendingCustomModel: string
): boolean {
  return (
    pendingCustomModel.trim().length > 0 ||
    modelSelectionSignature(initialModels, initialSelectedIds) !==
      modelSelectionSignature(currentModels, currentSelectedIds)
  )
}

/** Login re-verification always submits exactly one chat model, even for malformed legacy records. */
export function loginModelForVerification(
  catalogModels: CatalogModel[],
  connection?: ConnectionSummary
): CatalogModel[] {
  const choices = connectionModelChoices(catalogModels, connection)
  const selectedIds = new Set(initialEnabledModelIds(catalogModels, connection))
  const selected = choices.filter((model) => selectedIds.has(model.id))
  if (selected.length === 1) return selected
  const recommended = recommendedCatalogChatModel(catalogModels)
  return recommended ? [recommended] : []
}

/** A saved record must remain removable even when it is no longer verified or connectable. */
export function shouldOfferDisconnect(connection?: ConnectionSummary): boolean {
  return connection !== undefined
}

function canonicalConnectionTarget(type: string | undefined, baseUrl: string | undefined): string | null {
  const normalizedType = type?.trim().toLocaleLowerCase('en-US')
  const rawUrl = baseUrl?.trim()
  if (!normalizedType || !rawUrl) return null
  try {
    const parsed = new URL(rawUrl)
    if (
      !['http:', 'https:'].includes(parsed.protocol) ||
      parsed.username ||
      parsed.password ||
      parsed.search ||
      parsed.hash
    ) {
      return null
    }
    const normalizedPath = parsed.pathname.replace(/\/+$/, '')
    return `${normalizedType}\0${parsed.protocol}//${parsed.host}${normalizedPath}`
  } catch {
    return null
  }
}

/**
 * A generic legacy or disabled record may be deleted, but its secret is never
 * reusable. A DPAPI-imported Desktop credential may be used for one explicit
 * re-verification. Both paths remain bound to the exact protocol and API root.
 */
export function canPreserveExistingCredential(
  connection: ConnectionSummary | undefined,
  candidateType: string,
  candidateBaseUrl: string
): boolean {
  const reusableState =
    connection?.state === 'verified' ||
    (connection?.state === 'legacy_unverified' &&
      connection.credential_reverification_available === true)
  if (!reusableState || connection?.credential_present !== true) return false
  const verifiedTarget = canonicalConnectionTarget(connection.type, connection.base_url)
  const candidateTarget = canonicalConnectionTarget(candidateType, candidateBaseUrl)
  return verifiedTarget !== null && verifiedTarget === candidateTarget
}

export function shouldPreserveExistingCredential(
  connection: ConnectionSummary | undefined,
  suppliedKey: string,
  candidateType: string,
  candidateBaseUrl: string
): boolean {
  return (
    suppliedKey.trim().length === 0 &&
    canPreserveExistingCredential(connection, candidateType, candidateBaseUrl)
  )
}

export function shouldShowConnectionProvider(
  connectable: boolean | undefined,
  showUnavailable: boolean,
  connection?: ConnectionSummary
): boolean {
  return connectable !== false || showUnavailable || shouldOfferDisconnect(connection)
}

export function orphanConnectionEntries(
  catalog: CatalogProvider[],
  connections: Record<string, ConnectionSummary>
): Array<{ provider: string; connection: ConnectionSummary }> {
  const knownProviders = new Set(catalog.map((provider) => provider.name))
  return Object.entries(connections)
    .filter(([provider]) => !knownProviders.has(provider))
    .map(([provider, connection]) => ({ provider, connection }))
    .sort((left, right) => left.provider.localeCompare(right.provider))
}

/** Format only a valid verification receipt time; absence never becomes a live-health claim. */
export function formatVerifiedAt(value?: string, timeZone?: string): string | null {
  if (!value?.trim()) return null
  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime())) return null
  const formatter = new Intl.DateTimeFormat('en-US-u-nu-latn', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h23',
    ...(timeZone ? { timeZone } : {})
  })
  const parts = new Map(formatter.formatToParts(parsed).map((part) => [part.type, part.value]))
  const year = parts.get('year')
  const month = parts.get('month')
  const day = parts.get('day')
  const hour = parts.get('hour')
  const minute = parts.get('minute')
  if (!year || !month || !day || !hour || !minute) return null
  return `${year}-${month}-${day} ${hour}:${minute}`
}

export async function disconnectStoredConnection(
  provider: string,
  remove: (provider: string) => Promise<{ ok: boolean }>,
  refresh: () => Promise<void>
): Promise<StoredConnectionRemovalResult> {
  try {
    const response = await remove(provider)
    if (!response.ok) return { ok: false, reason: 'rejected' }
    await refresh()
    return { ok: true }
  } catch {
    return { ok: false, reason: 'exception' }
  }
}

export async function connectDetectedLocalServer(
  server: LocalServer,
  save: SaveDetectedLocalConnection,
  refresh: (expectedModelIds: readonly string[]) => Promise<boolean>
): Promise<DetectedLocalConnectionResult> {
  let response: Awaited<ReturnType<SaveDetectedLocalConnection>>
  try {
    const recommended = recommendedLocalChatModel(server.models)
    if (!recommended) return { ok: false, reason: 'rejected' }
    const enabledModels: CatalogModel[] = [
      {
        id: recommended,
        upstream_model: recommended,
        tier: 'local',
        description: server.label
      }
    ]
    response = await save(server.name, {
      type: 'openai_compat',
      api_key: '',
      base_url: server.base_url,
      enabled_models: enabledModels,
      preserve_existing_credential: false
    })
    if (!response.ok) return { ok: false, reason: 'rejected' }
  } catch {
    return { ok: false, reason: 'exception' }
  }
  let activation: 'confirmed' | 'pending' = 'pending'
  try {
    if (await refresh(response.models)) activation = 'confirmed'
  } catch {
    // The Gateway already committed a verified connection. Keep that fact
    // distinct from a renderer model-roster refresh that can be retried.
  }
  return {
    ok: true,
    connected: response.models.length,
    rejected: response.rejected_models?.length ?? 0,
    activation
  }
}
