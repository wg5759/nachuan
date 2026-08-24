import type { AuthenticodeExpectation } from './authenticode'
import { requireStrictAuthenticode } from './authenticode'
import {
  assertUpdateMetadataMatchesManifest,
  assertUpdaterDownloadedPathAgreement,
  attestDownloadedUpdateArtifact,
  updateSecurityStateFor,
  verifySignedUpdateEnvelope,
  type EmbeddedUpdateTrust,
  type UpdateMetadataLike,
  type UpdateSecurityState,
  type VerifiedUpdateManifest
} from './update-security'

const MAX_SIGNED_ENVELOPE_BYTES = 128 * 1024

export type UpdateCheckReason = 'startup' | 'periodic' | 'network-online' | 'resume' | 'manual'
export type UpdateInstallConsent = 'install-now' | 'install-on-exit'
export type UpdateUiPhase =
  | 'disabled'
  | 'idle'
  | 'checking'
  | 'downloading'
  | 'ready'
  | 'installing'
  | 'blocked'

export interface UpdateUiState {
  phase: UpdateUiPhase
  version?: string
  reason?: 'not-configured' | 'up-to-date' | 'network' | 'security' | 'failed'
}

export interface UpdateCheckResultLike {
  isUpdateAvailable: boolean
  updateInfo: UpdateMetadataLike
}

export interface SecureGenericUpdateFeed {
  provider: 'generic'
  url: string
  channel: string
}

export interface SecureUpdaterAdapter {
  autoDownload: boolean
  autoInstallOnAppQuit: boolean
  allowDowngrade: boolean
  allowPrerelease: boolean
  verifyUpdateCodeSignature?: (
    publisherNames: string[],
    path: string
  ) => Promise<string | null>
  setFeedURL(options: SecureGenericUpdateFeed): void
  checkForUpdates(): Promise<UpdateCheckResultLike | null>
  downloadUpdate(): Promise<string[]>
  quitAndInstall(isSilent?: boolean, isForceRunAfter?: boolean): void
  on(event: 'update-downloaded', listener: (event: UpdateMetadataLike & { downloadedFile: string }) => void): this
  on(event: 'error', listener: (error: Error) => void): this
}

export interface SecureAutoUpdaterOptions {
  trust: EmbeddedUpdateTrust
  currentVersion: string
  updater: SecureUpdaterAdapter
  fetchEnvelope: () => Promise<Buffer>
  readState: () => unknown
  writeState: (state: UpdateSecurityState) => void
  beforeCheck?: () => Promise<void>
  commitState?: (
    state: UpdateSecurityState,
    manifest: VerifiedUpdateManifest
  ) => Promise<void>
  beforeInstall?: (
    state: UpdateSecurityState,
    manifest: VerifiedUpdateManifest
  ) => Promise<void>
  notify: (state: UpdateUiState) => void
  verifyAuthenticode?: (path: string, expectation: AuthenticodeExpectation) => Promise<void>
  beforeQuitAndInstall?: () => void
  log?: (message: string) => void
}

interface PendingVerifiedUpdate {
  readonly manifest: VerifiedUpdateManifest
  readonly path: string
  readonly state: UpdateSecurityState
}

export async function fetchBoundedSignedUpdateEnvelope(
  manifestUrl: string,
  fetchImpl: typeof fetch = globalThis.fetch
): Promise<Buffer> {
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), 20_000)
  try {
    const response = await fetchImpl(manifestUrl, {
      method: 'GET',
      redirect: 'error',
      cache: 'no-store',
      credentials: 'omit',
      headers: { Accept: 'application/json' },
      signal: controller.signal
    })
    if (!response.ok || response.status !== 200 || !response.body) {
      throw new Error(`signed update manifest request failed with status ${response.status}`)
    }
    const contentLength = response.headers.get('content-length')
    if (contentLength !== null) {
      const length = Number(contentLength)
      if (!Number.isSafeInteger(length) || length <= 0 || length > MAX_SIGNED_ENVELOPE_BYTES) {
        throw new Error('signed update manifest content length is outside the bound')
      }
    }
    const reader = response.body.getReader()
    const chunks: Buffer[] = []
    let total = 0
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      total += value.byteLength
      if (total > MAX_SIGNED_ENVELOPE_BYTES) {
        await reader.cancel()
        throw new Error('signed update manifest body exceeds the size bound')
      }
      chunks.push(Buffer.from(value))
    }
    if (!total) throw new Error('signed update manifest body is empty')
    return Buffer.concat(chunks, total)
  } finally {
    clearTimeout(timeout)
  }
}

function authenticodeExpectation(trust: EmbeddedUpdateTrust): AuthenticodeExpectation {
  return {
    publisherName: trust.publisherName,
    signerThumbprint: trust.signerThumbprint,
    requireTimestamp: true
  }
}

function isPrivateIpv4(host: string): boolean {
  if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) return false
  const parts = host.split('.').map(Number)
  if (parts.some((part) => part > 255)) return true
  const [first, second] = parts
  return (
    first === 0 ||
    first === 10 ||
    first === 127 ||
    first >= 224 ||
    (first === 100 && second >= 64 && second <= 127) ||
    (first === 169 && second === 254) ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && second === 168) ||
    (first === 198 && (second === 18 || second === 19))
  )
}

function checkedPublicUpdateManifestPointer(trust: EmbeddedUpdateTrust): URL {
  if (trust.releaseTier !== 'early-access' && trust.releaseTier !== 'production') {
    throw new Error('enabled update trust has no controlled release tier')
  }
  if (trust.variant !== 'lean' && trust.variant !== 'full') {
    throw new Error('enabled update trust has no controlled variant')
  }
  const expectedChannel = `${trust.releaseTier}-${trust.variant}-win-x64`
  if (trust.channel !== expectedChannel) {
    throw new Error('embedded update channel drifted from its controlled feed')
  }
  let url: URL
  try {
    url = new URL(trust.manifestUrl)
  } catch (error) {
    throw new Error('embedded signed update manifest URL is invalid', { cause: error })
  }
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, '')
  if (
    url.protocol !== 'https:' ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    !host ||
    host === 'localhost' ||
    host.endsWith('.localhost') ||
    host.endsWith('.local') ||
    host.endsWith('.internal') ||
    host.endsWith('.corp') ||
    host.endsWith('.lan') ||
    host.endsWith('.home') ||
    host.endsWith('.home.arpa') ||
    host.endsWith('.test') ||
    host.endsWith('.invalid') ||
    host === 'example.com' ||
    host.endsWith('.example.com') ||
    host.includes(':') ||
    isPrivateIpv4(host) ||
    (!host.includes('.') && !/^\d/.test(host)) ||
    !url.pathname.endsWith(`/${expectedChannel}.json`)
  ) {
    throw new Error('embedded signed update manifest must use its credential-free public HTTPS pointer')
  }
  return url
}

export function deriveVerifiedGenericUpdateFeed(
  trust: EmbeddedUpdateTrust,
  manifest: VerifiedUpdateManifest
): SecureGenericUpdateFeed {
  const pointer = checkedPublicUpdateManifestPointer(trust)
  if (
    manifest.channel !== trust.channel ||
    manifest.variant !== trust.variant ||
    manifest.platform !== 'win32' ||
    manifest.arch !== 'x64'
  ) {
    throw new Error('verified update manifest drifted from embedded feed authority')
  }
  const base = new URL('.', pointer)
  return {
    provider: 'generic',
    url: new URL(
      `channels/${manifest.channel}/variants/${manifest.variant}/versions/${manifest.version}/sequence-${manifest.sequence}/`,
      base
    ).toString(),
    channel: `${trust.releaseTier}-${manifest.variant}`
  }
}

export class SecureAutoUpdater {
  private readonly options: SecureAutoUpdaterOptions
  private inFlight: Promise<void> | null = null
  private installInFlight: Promise<void> | null = null
  private approvedManifest: VerifiedUpdateManifest | null = null
  private downloadedEventPath = ''
  private pending: PendingVerifiedUpdate | null = null

  constructor(options: SecureAutoUpdaterOptions) {
    this.options = options
    const updater = options.updater
    // These must be false before the first check. electron-updater 6.8.9 adds
    // its quit handler when download completes, so changing the flag later is
    // not a reliable security boundary.
    updater.autoDownload = false
    updater.autoInstallOnAppQuit = false
    updater.allowDowngrade = false
    updater.allowPrerelease = false
    updater.verifyUpdateCodeSignature = async (_publisherNames, path) => {
      const manifest = this.approvedManifest
      if (!manifest) return 'Nachuan independent update manifest was not approved'
      try {
        await attestDownloadedUpdateArtifact(path, manifest, { requireSignedName: false })
        await this.requireProductionAuthenticode(path)
        return null
      } catch {
        return 'Nachuan independent update artifact verification failed'
      }
    }
    updater.on('update-downloaded', (event) => {
      if (this.approvedManifest && event.version === this.approvedManifest.version) {
        this.downloadedEventPath = String(event.downloadedFile || '')
      } else {
        this.downloadedEventPath = ''
      }
    })
    updater.on('error', () => options.log?.('[auto-update] electron-updater reported an error'))
  }

  get hasPendingUpdate(): boolean {
    return this.pending !== null
  }

  get pendingVersion(): string | undefined {
    return this.pending?.manifest.version
  }

  check(reason: UpdateCheckReason): Promise<void> {
    // Checking and installing share one state machine. A periodic revalidation
    // must not race the final Root/file proof or overwrite `installing` with a
    // later `ready` notification.
    if (this.installInFlight) return this.installInFlight
    if (this.pending) {
      if (this.inFlight) return this.inFlight
      const pending = this.pending
      this.inFlight = (async () => {
        try {
          // A cached installer is not proof that the independent authority is
          // still current.  Periodic/manual checks must not keep advertising
          // a stale ready state after an epoch, floor, or local proof change.
          await this.options.beforeInstall?.(pending.state, pending.manifest)
          // Root proof deliberately precedes the cached-file attestation so
          // the final hash is not made stale by an asynchronous authority
          // round-trip. A bad cached artifact is discarded, while a Root
          // failure above retains it for a later exact authority retry.
          await this.attestPendingArtifact(pending)
          this.options.notify({ phase: 'ready', version: pending.manifest.version })
        } catch (error) {
          this.options.notify({ phase: 'blocked', reason: 'security' })
          throw error
        }
      })().finally(() => {
        this.inFlight = null
      })
      return this.inFlight
    }
    if (this.inFlight) return this.inFlight
    this.inFlight = this.runCheck(reason).finally(() => {
      this.inFlight = null
    })
    return this.inFlight
  }

  private async runCheck(_reason: UpdateCheckReason): Promise<void> {
    if (!this.options.trust.enabled) {
      this.options.notify({ phase: 'disabled', reason: 'not-configured' })
      return
    }
    this.options.notify({ phase: 'checking' })
    this.approvedManifest = null
    this.downloadedEventPath = ''
    try {
      if (this.options.beforeCheck) await this.options.beforeCheck()
      checkedPublicUpdateManifestPointer(this.options.trust)
      const envelope = await this.options.fetchEnvelope()
      let manifest: VerifiedUpdateManifest
      try {
        manifest = verifySignedUpdateEnvelope(
          envelope,
          this.options.trust,
          this.options.currentVersion,
          this.options.readState()
        )
      } catch (error) {
        if (error instanceof Error && error.message === 'signed update is not newer than the installed version') {
          this.options.notify({ phase: 'idle', reason: 'up-to-date' })
          return
        }
        throw error
      }
      const feed = deriveVerifiedGenericUpdateFeed(this.options.trust, manifest)
      this.options.updater.setFeedURL(feed)
      this.approvedManifest = manifest
      const result = await this.options.updater.checkForUpdates()
      if (!result || !result.isUpdateAvailable) {
        throw new Error('electron update metadata omitted the independently signed newer release')
      }
      assertUpdateMetadataMatchesManifest(result.updateInfo, manifest)
      this.options.notify({ phase: 'downloading', version: manifest.version })
      const paths = await this.options.updater.downloadUpdate()
      const path = assertUpdaterDownloadedPathAgreement(paths, this.downloadedEventPath, manifest)
      await attestDownloadedUpdateArtifact(path, manifest)
      await this.requireProductionAuthenticode(path)
      const state = updateSecurityStateFor(manifest)
      if (this.options.commitState) {
        await this.options.commitState(state, manifest)
      } else {
        this.options.writeState(state)
      }
      this.pending = { manifest, path, state }
      this.options.notify({ phase: 'ready', version: manifest.version })
    } catch (error) {
      this.pending = null
      this.approvedManifest = null
      const security =
        error instanceof Error &&
        /signature|signed|rollback|sequence|manifest|metadata|SHA-256|Authenticode|installer|artifact|installation root|authority/i.test(
          error.message
        )
      this.options.notify({ phase: 'blocked', reason: security ? 'security' : 'network' })
      throw error
    }
  }

  installVerifiedUpdate(consent?: UpdateInstallConsent): Promise<void> {
    if (consent !== 'install-now' && consent !== 'install-on-exit') {
      return Promise.reject(new Error('installing an update requires explicit user consent'))
    }
    if (this.installInFlight) return this.installInFlight
    const pendingAtConsent = this.pending
    if (!pendingAtConsent) {
      return Promise.reject(new Error('no independently verified update is ready to install'))
    }
    const activeCheck = this.inFlight
    this.installInFlight = (async () => {
      if (activeCheck) await activeCheck
      await this.runInstall(pendingAtConsent)
    })().finally(() => {
      this.installInFlight = null
    })
    return this.installInFlight
  }

  private async runInstall(expected: PendingVerifiedUpdate): Promise<void> {
    const pending = this.pending
    if (!pending || pending !== expected) {
      throw new Error('the independently verified update changed before installation')
    }
    // Prove the monotonic Installation Root first.  The installer file is
    // deliberately reopened and rehashed *after* this asynchronous boundary
    // so no root round-trip widens the final file-verification TOCTOU window.
    await this.options.beforeInstall?.(pending.state, pending.manifest)
    // Re-open, re-identify and rehash immediately before the synchronous
    // quitAndInstall call. This narrows but cannot eliminate a hostile same-SID
    // replacement window for an unsigned app; production adds Authenticode.
    await this.attestPendingArtifact(pending)
    this.options.notify({ phase: 'installing', version: pending.manifest.version })
    this.options.beforeQuitAndInstall?.()
    this.options.updater.quitAndInstall(true, true)
  }

  private async requireProductionAuthenticode(path: string): Promise<void> {
    if (this.options.trust.releaseTier !== 'production') return
    const verify = this.options.verifyAuthenticode || requireStrictAuthenticode
    await verify(path, authenticodeExpectation(this.options.trust))
  }

  private async attestPendingArtifact(pending: PendingVerifiedUpdate): Promise<void> {
    try {
      await attestDownloadedUpdateArtifact(pending.path, pending.manifest)
      await this.requireProductionAuthenticode(pending.path)
    } catch (error) {
      if (this.pending === pending) {
        this.pending = null
        this.approvedManifest = null
      }
      throw error
    }
  }
}
