import { createHash, randomBytes } from 'node:crypto'
import {
  link,
  lstat,
  mkdir,
  open,
  readFile,
  realpath,
  rm,
  stat,
  unlink
} from 'node:fs/promises'
import { basename, dirname, isAbsolute, join, parse, relative, resolve, sep } from 'node:path'

const VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/
const PROFILE = /^(development|enterprise|service|store)$/
const SAFE_TOKEN = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,95}$/
const EVENT = /^[a-z0-9][a-z0-9_.-]{0,63}$/
const NONCE = /^[0-9a-f]{16}$/
const MAX_ARTIFACTS = 16
const MAX_ARTIFACT_BYTES = 4 * 1024 * 1024 * 1024
const MAX_AUDIT_BYTES = 5 * 1024 * 1024
const MAX_AUDIT_LINES = 20_000
const MAX_AUDIT_EVENTS = 128
const AUDIT_EVENTS = new Set([
  'desktop.before_quit',
  'desktop.ready',
  'desktop.update_current_signature_blocked',
  'desktop.update_state',
  'engine.exit',
  'engine.fatal',
  'engine.ready',
  'engine.restart_scheduled',
  'engine.spawn',
  'paid_media.asset_v2_ack_pending',
  'paid_media.asset_v2_stage_cleanup_failed',
  'paid_media.asset_v2_stage_recovery_required',
  'paid_media.control_plane_degraded',
  'paid_media.control_plane_rooted_v1_disabled',
  'paid_media.fetch_cleanup_failed',
  'support_bundle.created',
  'support_bundle.failed'
])
const WINDOWS_RESERVED_NAMES = new Set([
  'AUX',
  'CON',
  'NUL',
  'PRN',
  ...Array.from({ length: 9 }, (_value, index) => `COM${index + 1}`),
  ...Array.from({ length: 9 }, (_value, index) => `LPT${index + 1}`)
])

const ARTIFACT_KINDS = new Set([
  'app-asar',
  'desktop-executable',
  'engine-executable',
  'engine-runtime-manifest',
  'media-runtime-manifest',
  'update-trust'
])

type JsonRecord = Record<string, unknown>

export interface SupportArtifactInput {
  kind:
    | 'app-asar'
    | 'desktop-executable'
    | 'engine-executable'
    | 'engine-runtime-manifest'
    | 'media-runtime-manifest'
    | 'update-trust'
  relativePath: string
}

export interface CreateSupportBundleOptions {
  installRoot: string
  outputRoot: string
  version: string
  runtimeProfile: string
  artifacts: SupportArtifactInput[]
  health?: unknown
  auditLogPath?: string
  now?: () => Date
  nonce?: () => string
}

export interface SupportBundleResult {
  path: string
  payloadSha256: string
  size: number
}

export interface CreateInstalledSupportBundleOptions {
  isPackaged: boolean
  executablePath: string
  resourcesPath: string
  userDataPath: string
  version: string
  runtimeProfile: string
  loadHealth: () => Promise<unknown>
  now?: () => Date
  nonce?: () => string
}

export class SupportBundleError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'SupportBundleError'
  }
}

function asRecord(value: unknown): JsonRecord {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as JsonRecord)
    : {}
}

function safeToken(value: unknown, fallback = 'unknown'): string {
  const candidate = typeof value === 'string' ? value : ''
  return SAFE_TOKEN.test(candidate) ? candidate : fallback
}

function safeErrorType(value: unknown): string | null {
  const candidate = typeof value === 'string' ? value : ''
  return /^[A-Za-z][A-Za-z0-9_.]{0,127}$/.test(candidate) ? candidate : null
}

function safeTimestamp(value: unknown): string | null {
  if (typeof value !== 'string' || value.length > 40) return null
  const parsed = Date.parse(value)
  if (!Number.isFinite(parsed)) return null
  const canonical = new Date(parsed).toISOString()
  return canonical === value ? canonical : null
}

function nonNegativeInteger(value: unknown, maximum = Number.MAX_SAFE_INTEGER): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) return 0
  return Math.min(value, maximum)
}

function projectHealth(value: unknown): JsonRecord {
  const root = asRecord(value)
  if (!Object.keys(root).length) {
    return { available: false, reasonCode: 'health-unavailable', checks: {} }
  }
  const checks = asRecord(root.checks)
  const database = asRecord(checks.database)
  const financial = asRecord(checks.financial_ledger)
  const backup = asRecord(checks.sqlite_backup)
  const connectionStore = asRecord(checks.connection_store)
  const paidMedia = asRecord(checks.paid_media_authority)
  const providers = asRecord(checks.providers)
  const weixin = asRecord(checks.weixin)

  return {
    available: true,
    status: safeToken(root.status),
    readiness: safeToken(root.readiness),
    codeVersion: nonNegativeInteger(root.code_version),
    checks: {
      database: {
        ready: database.ready === true,
        checked: nonNegativeInteger(database.checked, 10_000),
        failedCount: Array.isArray(database.failed)
          ? Math.min(database.failed.length, 10_000)
          : 0
      },
      financialLedger: {
        required: financial.required === true,
        ready: financial.ready === true,
        status: safeToken(financial.status),
        capacityStatus: safeToken(financial.capacity_status),
        databaseBytes: nonNegativeInteger(financial.database_bytes),
        walBytes: nonNegativeInteger(financial.wal_bytes),
        maxDatabaseBytes: nonNegativeInteger(financial.max_database_bytes),
        diskFreeBytes: nonNegativeInteger(financial.disk_free_bytes),
        lastWriteErrorType: safeErrorType(financial.last_write_error_type),
        lastWriteErrorAt: safeTimestamp(financial.last_write_error_at)
      },
      sqliteBackup: {
        ready: backup.ready === true,
        status: safeToken(backup.status),
        lastAttemptAt: safeTimestamp(backup.last_attempt_at),
        lastSuccessAt: safeTimestamp(backup.last_success_at),
        lastErrorType: safeErrorType(backup.last_error),
        databaseCount: nonNegativeInteger(backup.database_count, 10_000)
      },
      connectionStore: {
        ready: connectionStore.ready === true,
        quarantinedCount: Array.isArray(connectionStore.quarantined)
          ? Math.min(connectionStore.quarantined.length, 10_000)
          : 0
      },
      paidMediaAuthority: {
        mode: safeToken(paidMedia.mode),
        reasonCode: safeToken(paidMedia.reason_code),
        newOperationsReady: paidMedia.new_operations_ready === true,
        replayAvailable: paidMedia.replay_available === true,
        packaged: paidMedia.packaged === true,
        engineSessionVerifierReady: paidMedia.engine_session_verifier_ready === true,
        desktopV2StageAuthorityReady: paidMedia.desktop_v2_stage_authority_ready === true,
        backupSupported: paidMedia.backup_supported === true,
        backupReasonCode: safeToken(paidMedia.backup_reason_code),
        reanchorSupported: paidMedia.reanchor_supported === true
      },
      providers: {
        ready: providers.ready === true,
        count: nonNegativeInteger(providers.count, 10_000),
        externalCount: nonNegativeInteger(providers.external_count, 10_000),
        modelCount: nonNegativeInteger(providers.model_count, 100_000)
      },
      weixin: {
        configured: weixin.configured === true,
        state: safeToken(weixin.state),
        fresh: weixin.fresh === true,
        ready: weixin.ready === true,
        ageSec: nonNegativeInteger(weixin.age_sec),
        pendingInbound: nonNegativeInteger(weixin.pending_inbound, 1_000_000),
        pendingOutbound: nonNegativeInteger(weixin.pending_outbound, 1_000_000),
        deadInbound: nonNegativeInteger(weixin.dead_inbound, 1_000_000),
        deadOutbound: nonNegativeInteger(weixin.dead_outbound, 1_000_000)
      }
    }
  }
}

function checkedRelativePath(value: string): string {
  const parts = value.split('/')
  if (
    !value ||
    value.includes('\\') ||
    value.includes('\0') ||
    isAbsolute(value) ||
    parts.some(
      (part) =>
        !part ||
        part === '.' ||
        part === '..' ||
        part !== part.normalize('NFC') ||
        /[:\u0000-\u001f\u007f]/.test(part) ||
        /[ .]$/.test(part) ||
        WINDOWS_RESERVED_NAMES.has(part.split('.', 1)[0].toUpperCase())
    )
  ) {
    throw new SupportBundleError('support artifact path is not canonical')
  }
  return value
}

async function assertRealDirectory(path: string, label: string): Promise<string> {
  const absolute = resolve(path)
  const root = parse(absolute).root
  let cursor = root
  for (const part of absolute.slice(root.length).split(sep).filter(Boolean)) {
    cursor = join(cursor, part)
    let component
    try {
      component = await lstat(cursor)
    } catch {
      throw new SupportBundleError(`${label} does not exist`)
    }
    if (component.isSymbolicLink()) {
      throw new SupportBundleError(`${label} path contains a filesystem redirect`)
    }
  }
  let info
  try {
    info = await lstat(absolute)
  } catch {
    throw new SupportBundleError(`${label} does not exist`)
  }
  if (!info.isDirectory() || info.isSymbolicLink()) {
    throw new SupportBundleError(`${label} must be a real directory`)
  }
  return await realpath(absolute)
}

function isContained(root: string, candidate: string): boolean {
  const fromRoot = relative(root, candidate)
  return Boolean(fromRoot) && !fromRoot.startsWith(`..${sep}`) && fromRoot !== '..' && !isAbsolute(fromRoot)
}

async function assertArtifactPath(
  installRoot: string,
  installRootReal: string,
  relativePath: string
): Promise<string> {
  const parts = checkedRelativePath(relativePath).split('/')
  let current = installRoot
  for (const part of parts) {
    current = join(current, part)
    let info
    try {
      info = await lstat(current)
    } catch {
      throw new SupportBundleError('support artifact is missing')
    }
    if (info.isSymbolicLink()) {
      throw new SupportBundleError('support artifact path contains a filesystem redirect')
    }
  }
  const target = resolve(installRoot, ...parts)
  if (!isContained(installRoot, target)) {
    throw new SupportBundleError('support artifact escapes the installation root')
  }
  const targetReal = await realpath(target)
  if (!isContained(installRootReal, targetReal)) {
    throw new SupportBundleError('support artifact resolves outside the installation root')
  }
  return target
}

function sameFileIdentity(
  before: Awaited<ReturnType<typeof stat>>,
  after: Awaited<ReturnType<typeof stat>>
): boolean {
  return (
    before.isFile() &&
    after.isFile() &&
    before.dev === after.dev &&
    before.ino === after.ino &&
    before.size === after.size &&
    before.mtimeMs === after.mtimeMs &&
    before.ctimeMs === after.ctimeMs &&
    before.birthtimeMs === after.birthtimeMs
  )
}

async function hashArtifact(
  installRoot: string,
  installRootReal: string,
  artifact: SupportArtifactInput
): Promise<JsonRecord> {
  if (!ARTIFACT_KINDS.has(artifact.kind)) {
    throw new SupportBundleError('support artifact kind is not allowlisted')
  }
  const relativePath = checkedRelativePath(artifact.relativePath)
  const target = await assertArtifactPath(installRoot, installRootReal, relativePath)
  const handle = await open(target, 'r')
  try {
    const before = await handle.stat()
    if (!before.isFile() || before.size < 0 || before.size > MAX_ARTIFACT_BYTES) {
      throw new SupportBundleError('support artifact is not a bounded regular file')
    }
    const digest = createHash('sha256')
    const buffer = Buffer.allocUnsafe(1024 * 1024)
    let position = 0
    for (;;) {
      const read = await handle.read(buffer, 0, buffer.length, position)
      if (read.bytesRead === 0) break
      digest.update(buffer.subarray(0, read.bytesRead))
      position += read.bytesRead
      if (position > MAX_ARTIFACT_BYTES) {
        throw new SupportBundleError('support artifact changed beyond its size bound')
      }
    }
    const after = await handle.stat()
    if (!sameFileIdentity(before, after) || position !== before.size) {
      throw new SupportBundleError('support artifact changed while hashing')
    }
    const pathInfo = await lstat(target)
    if (pathInfo.isSymbolicLink() || !sameFileIdentity(before, pathInfo)) {
      throw new SupportBundleError('support artifact path changed while hashing')
    }
    const targetReal = await realpath(target)
    if (!isContained(installRootReal, targetReal)) {
      throw new SupportBundleError('support artifact path escaped while hashing')
    }
    return {
      kind: artifact.kind,
      path: relativePath,
      sha256: digest.digest('hex'),
      size: before.size
    }
  } finally {
    await handle.close()
  }
}

async function projectAudit(path: string | undefined): Promise<JsonRecord> {
  if (!path) return { available: false, invalidLineCount: 0, lineCount: 0, events: [] }
  try {
    const info = await lstat(path)
    if (!info.isFile() || info.isSymbolicLink() || info.size > MAX_AUDIT_BYTES) {
      return { available: false, invalidLineCount: 0, lineCount: 0, events: [] }
    }
    const text = await readFile(path, 'utf8')
    const lines = text.split(/\r?\n/).filter((line) => line.length > 0)
    if (lines.length > MAX_AUDIT_LINES) {
      return { available: false, invalidLineCount: 0, lineCount: 0, events: [] }
    }
    const aggregates = new Map<string, { count: number; event: string; lastAt: string }>()
    let invalidLineCount = 0
    for (const line of lines) {
      let item: JsonRecord
      try {
        item = asRecord(JSON.parse(line))
      } catch {
        invalidLineCount += 1
        continue
      }
      const event =
        typeof item.event === 'string' &&
        EVENT.test(item.event) &&
        AUDIT_EVENTS.has(item.event)
          ? item.event
          : ''
      const timestamp = safeTimestamp(item.ts)
      if (!event || !timestamp) {
        invalidLineCount += 1
        continue
      }
      const current = aggregates.get(event)
      if (!current && aggregates.size >= MAX_AUDIT_EVENTS) {
        invalidLineCount += 1
        continue
      }
      aggregates.set(event, {
        count: Math.min((current?.count || 0) + 1, MAX_AUDIT_LINES),
        event,
        lastAt: current && current.lastAt > timestamp ? current.lastAt : timestamp
      })
    }
    return {
      available: true,
      invalidLineCount,
      lineCount: lines.length,
      events: [...aggregates.values()].sort((left, right) =>
        left.event < right.event ? -1 : left.event > right.event ? 1 : 0
      )
    }
  } catch {
    return { available: false, invalidLineCount: 0, lineCount: 0, events: [] }
  }
}

async function createOnlyAtomicFile(path: string, bytes: Buffer): Promise<void> {
  const temporary = `${path}.${process.pid}.${randomBytes(8).toString('hex')}.tmp`
  let linked = false
  try {
    const handle = await open(temporary, 'wx', 0o600)
    try {
      await handle.writeFile(bytes)
      await handle.sync()
    } finally {
      await handle.close()
    }
    await link(temporary, path)
    linked = true
    await unlink(temporary)
  } catch (error) {
    await rm(temporary, { force: true })
    if (linked) await rm(path, { force: true })
    throw new SupportBundleError(
      `support bundle could not be committed: ${error instanceof Error ? error.name : 'Error'}`
    )
  }
}

export async function createSupportBundle(
  options: CreateSupportBundleOptions
): Promise<SupportBundleResult> {
  if (!VERSION.test(options.version)) {
    throw new SupportBundleError('support bundle version must be stable SemVer')
  }
  if (!PROFILE.test(options.runtimeProfile)) {
    throw new SupportBundleError('support bundle runtime profile is unsupported')
  }
  if (
    !Array.isArray(options.artifacts) ||
    options.artifacts.length === 0 ||
    options.artifacts.length > MAX_ARTIFACTS
  ) {
    throw new SupportBundleError('support bundle artifacts must be a bounded non-empty list')
  }
  const seenKinds = new Set<string>()
  for (const artifact of options.artifacts) {
    if (seenKinds.has(artifact.kind)) {
      throw new SupportBundleError('support bundle contains a duplicate artifact kind')
    }
    seenKinds.add(artifact.kind)
  }

  const installRoot = resolve(options.installRoot)
  const installRootReal = await assertRealDirectory(installRoot, 'installation root')
  const outputRoot = resolve(options.outputRoot)
  const outputParent = dirname(outputRoot)
  await assertRealDirectory(outputParent, 'support bundle output parent')
  try {
    await mkdir(outputRoot, { recursive: false, mode: 0o700 })
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error
  }
  await assertRealDirectory(outputRoot, 'support bundle output root')
  const createdAt = (options.now || (() => new Date()))().toISOString()
  const nonce = (options.nonce || (() => randomBytes(8).toString('hex')))()
  if (!NONCE.test(nonce)) throw new SupportBundleError('support bundle nonce is invalid')
  const filenameTimestamp = createdAt.replace(/[-:.]/g, '')
  if (!/^\d{8}T\d{9}Z$/.test(filenameTimestamp)) {
    throw new SupportBundleError('support bundle clock returned a non-canonical timestamp')
  }

  const artifacts: JsonRecord[] = []
  for (const artifact of options.artifacts) {
    artifacts.push(await hashArtifact(installRoot, installRootReal, artifact))
  }
  artifacts.sort((left, right) => String(left.kind).localeCompare(String(right.kind), 'en'))

  const payload = {
    schema: 'nachuan.support-bundle.v1',
    createdAt,
    product: {
      name: 'Nachuan',
      version: options.version,
      platform: process.platform,
      arch: process.arch,
      runtimeProfile: options.runtimeProfile
    },
    health: projectHealth(options.health),
    artifacts,
    audit: await projectAudit(options.auditLogPath),
    privacy: {
      auditFieldsIncluded: false,
      businessDataIncluded: false,
      databasesIncluded: false,
      localPathsIncluded: false,
      rawLogsIncluded: false,
      secretsIncluded: false
    }
  }
  const payloadSha256 = createHash('sha256').update(`${JSON.stringify(payload)}\n`).digest('hex')
  const document = {
    ...payload,
    integrity: { algorithm: 'sha256', payloadSha256 }
  }
  const bytes = Buffer.from(`${JSON.stringify(document, null, 2)}\n`, 'utf8')
  const path = join(outputRoot, `nachuan-support-${filenameTimestamp}-${nonce}.json`)
  await createOnlyAtomicFile(path, bytes)
  const committed = await lstat(path)
  if (!committed.isFile() || committed.isSymbolicLink() || committed.size !== bytes.length) {
    throw new SupportBundleError('committed support bundle identity is invalid')
  }
  return { path, payloadSha256, size: bytes.length }
}

export async function createInstalledSupportBundle(
  options: CreateInstalledSupportBundleOptions
): Promise<SupportBundleResult> {
  if (!options.isPackaged) {
    throw new SupportBundleError('installed support bundles require a packaged application')
  }
  const installRoot = dirname(resolve(options.executablePath))
  const resourcesRelative = relative(installRoot, resolve(options.resourcesPath)).split(sep).join('/')
  checkedRelativePath(resourcesRelative)
  const executableRelative = relative(installRoot, resolve(options.executablePath))
    .split(sep)
    .join('/')
  if (executableRelative !== basename(options.executablePath)) {
    throw new SupportBundleError('desktop executable is not directly inside the installation root')
  }
  let health: unknown
  try {
    health = await options.loadHealth()
  } catch {
    health = undefined
  }
  const engineName = process.platform === 'win32' ? 'engine.exe' : 'engine'
  return await createSupportBundle({
    installRoot,
    outputRoot: join(options.userDataPath, 'support-bundles'),
    version: options.version,
    runtimeProfile: options.runtimeProfile,
    health,
    auditLogPath: join(options.userDataPath, 'logs', 'desktop-main.jsonl'),
    now: options.now,
    nonce: options.nonce,
    artifacts: [
      { kind: 'desktop-executable', relativePath: executableRelative },
      { kind: 'app-asar', relativePath: `${resourcesRelative}/app.asar` },
      {
        kind: 'engine-executable',
        relativePath: `${resourcesRelative}/engine/${engineName}`
      },
      {
        kind: 'engine-runtime-manifest',
        relativePath: `${resourcesRelative}/local-runtime-manifest.json`
      },
      {
        kind: 'media-runtime-manifest',
        relativePath: `${resourcesRelative}/media-runtime-manifest.json`
      }
    ]
  })
}
