import { createHash, generateKeyPairSync, sign } from 'node:crypto'
import { EventEmitter } from 'node:events'
import { mkdtempSync, readFileSync, rmSync, truncateSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'

import {
  SecureAutoUpdater,
  type SecureGenericUpdateFeed,
  type SecureUpdaterAdapter,
  type UpdateUiState
} from './secure-auto-updater'
import {
  canonicalUpdateManifest,
  type EmbeddedUpdateTrust,
  type UpdateMetadataLike,
  type VerifiedUpdateManifest
} from './update-security'

const roots: string[] = []
const ARTIFACT_SIZE = 25 * 1024 * 1024

class FakeUpdater extends EventEmitter implements SecureUpdaterAdapter {
  autoDownload = true
  autoInstallOnAppQuit = true
  allowDowngrade = true
  allowPrerelease = true
  verifyUpdateCodeSignature?: (publisherNames: string[], path: string) => Promise<string | null>
  checks = 0
  downloads = 0
  installs = 0
  feeds: SecureGenericUpdateFeed[] = []
  calls: string[] = []
  readonly info: UpdateMetadataLike
  readonly path: string
  tamperBeforeReturn = false

  constructor(info: UpdateMetadataLike, path: string) {
    super()
    this.info = info
    this.path = path
  }

  setFeedURL(options: SecureGenericUpdateFeed): void {
    this.feeds.push(options)
    this.calls.push('set-feed')
  }

  async checkForUpdates() {
    this.checks += 1
    this.calls.push('check')
    expect(this.autoDownload).toBe(false)
    expect(this.autoInstallOnAppQuit).toBe(false)
    expect(this.allowDowngrade).toBe(false)
    return { isUpdateAvailable: true, updateInfo: this.info }
  }

  async downloadUpdate(): Promise<string[]> {
    this.downloads += 1
    const verification = await this.verifyUpdateCodeSignature?.([], this.path)
    if (verification) throw new Error(verification)
    this.emit('update-downloaded', { ...this.info, downloadedFile: this.path })
    if (this.tamperBeforeReturn) writeFileSync(this.path, Buffer.alloc(ARTIFACT_SIZE, 0x41))
    return [this.path]
  }

  quitAndInstall(): void {
    this.installs += 1
  }
}

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'nachuan-secure-updater-'))
  roots.push(root)
  const pair = generateKeyPairSync('ed25519')
  const name = 'nachuan-1.1.0-lean-early-access-unsigned-win.exe'
  const path = join(root, name)
  writeFileSync(path, '')
  truncateSync(path, ARTIFACT_SIZE)
  const sha256 = createHash('sha256').update(Buffer.alloc(ARTIFACT_SIZE)).digest('hex')
  const manifest: VerifiedUpdateManifest = {
    schema: 1,
    channel: 'early-access-lean-win-x64',
    platform: 'win32',
    arch: 'x64',
    variant: 'lean',
    version: '1.1.0',
    sequence: 2,
    keyId: 'early-2026-01',
    artifact: { name, size: ARTIFACT_SIZE, sha256 }
  }
  const signature = sign(null, Buffer.from(canonicalUpdateManifest(manifest), 'utf8'), pair.privateKey)
  const envelope = Buffer.from(
    JSON.stringify({
      schema: 1,
      manifest,
      signature: { algorithm: 'Ed25519', keyId: manifest.keyId, value: signature.toString('base64') }
    })
  )
  const trust: EmbeddedUpdateTrust = {
    schema: 1,
    enabled: true,
    releaseTier: 'early-access',
    channel: manifest.channel,
    variant: 'lean',
    keyId: manifest.keyId,
    publicKeySpkiBase64: pair.publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
    manifestUrl: `https://updates.nachuan.ai/${manifest.channel}.json`,
    currentSequence: 1,
    publisherName: '',
    signerThumbprint: ''
  }
  const info: UpdateMetadataLike = {
    version: manifest.version,
    path: manifest.artifact.name,
    files: [{ url: manifest.artifact.name, size: manifest.artifact.size }]
  }
  return { path, manifest, envelope, trust, info }
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true })
})

describe('secure automatic update controller', () => {
  it('sets the exact immutable generic feed only after the signed envelope verifies', async () => {
    const item = fixture()
    const decoded = JSON.parse(item.envelope.toString('utf8'))
    decoded.signature.value = `${decoded.signature.value[0] === 'A' ? 'B' : 'A'}${decoded.signature.value.slice(1)}`
    const rejectedUpdater = new FakeUpdater(item.info, item.path)
    const rejected = new SecureAutoUpdater({
      trust: item.trust,
      currentVersion: '1.0.0',
      updater: rejectedUpdater,
      fetchEnvelope: async () => Buffer.from(JSON.stringify(decoded)),
      readState: () => undefined,
      writeState: vi.fn(),
      notify: vi.fn()
    })

    await expect(rejected.check('manual')).rejects.toThrow(/signature/i)
    expect(rejectedUpdater.feeds).toEqual([])
    expect(rejectedUpdater.checks).toBe(0)

    const updater = new FakeUpdater(item.info, item.path)
    const controller = new SecureAutoUpdater({
      trust: item.trust,
      currentVersion: '1.0.0',
      updater,
      fetchEnvelope: async () => item.envelope,
      readState: () => undefined,
      writeState: vi.fn(),
      notify: vi.fn()
    })
    await controller.check('manual')

    expect(updater.feeds).toEqual([
      {
        provider: 'generic',
        url: 'https://updates.nachuan.ai/channels/early-access-lean-win-x64/variants/lean/versions/1.1.0/sequence-2/',
        channel: 'early-access-lean'
      }
    ])
    expect(updater.calls.slice(0, 2)).toEqual(['set-feed', 'check'])
  })

  it('rejects private or drifted manifest pointers before fetch, feed setup, or update check', async () => {
    const item = fixture()
    const invalidManifestUrls = [
      `https://updates.corp/${item.manifest.channel}.json`,
      'https://updates.nachuan.ai/not-the-controlled-channel.json'
    ]

    for (const manifestUrl of invalidManifestUrls) {
      const updater = new FakeUpdater(item.info, item.path)
      const fetchEnvelope = vi.fn(async () => item.envelope)
      const controller = new SecureAutoUpdater({
        trust: { ...item.trust, manifestUrl },
        currentVersion: '1.0.0',
        updater,
        fetchEnvelope,
        readState: () => undefined,
        writeState: vi.fn(),
        notify: vi.fn()
      })

      await expect(controller.check('manual')).rejects.toThrow(/manifest|pointer|public/i)
      expect(fetchEnvelope).not.toHaveBeenCalled()
      expect(updater.feeds).toEqual([])
      expect(updater.checks).toBe(0)
    }
  })

  it('keeps both updater automations off, single-flights checks, and installs only after two hashes', async () => {
    const item = fixture()
    const updater = new FakeUpdater(item.info, item.path)
    const states: UpdateUiState[] = []
    const writeState = vi.fn()
    let releaseFetch!: () => void
    const fetchEnvelope = vi.fn(
      () =>
        new Promise<Buffer>((resolve) => {
          releaseFetch = () => resolve(item.envelope)
        })
    )
    const controller = new SecureAutoUpdater({
      trust: item.trust,
      currentVersion: '1.0.0',
      updater,
      fetchEnvelope,
      readState: () => undefined,
      writeState,
      notify: (state) => states.push(state)
    })

    const first = controller.check('startup')
    const second = controller.check('manual')
    expect(first).toBe(second)
    releaseFetch()
    await first

    expect(fetchEnvelope).toHaveBeenCalledTimes(1)
    expect(updater.checks).toBe(1)
    expect(updater.downloads).toBe(1)
    expect(writeState).toHaveBeenCalledWith({
      schema: 1,
      sequence: item.manifest.sequence,
      version: item.manifest.version,
      artifactSha256: item.manifest.artifact.sha256
    })
    expect(controller.hasPendingUpdate).toBe(true)
    expect(states.at(-1)).toEqual({ phase: 'ready', version: item.manifest.version })

    await expect(controller.installVerifiedUpdate()).rejects.toThrow(/explicit user consent/i)
    expect(updater.installs).toBe(0)

    await controller.installVerifiedUpdate('install-now')
    expect(updater.installs).toBe(1)
    expect(updater.autoInstallOnAppQuit).toBe(false)
  })

  it('catches a cache/file replacement after electron-updater reports download complete', async () => {
    const item = fixture()
    const updater = new FakeUpdater(item.info, item.path)
    updater.tamperBeforeReturn = true
    const states: UpdateUiState[] = []
    const controller = new SecureAutoUpdater({
      trust: item.trust,
      currentVersion: '1.0.0',
      updater,
      fetchEnvelope: async () => item.envelope,
      readState: () => undefined,
      writeState: vi.fn(),
      notify: (state) => states.push(state)
    })

    await expect(controller.check('periodic')).rejects.toThrow(/SHA-256/)
    expect(controller.hasPendingUpdate).toBe(false)
    expect(states.at(-1)).toEqual({ phase: 'blocked', reason: 'security' })
    expect(updater.installs).toBe(0)
  })

  it('rehashes immediately before quitAndInstall and blocks a later same-path swap', async () => {
    const item = fixture()
    const updater = new FakeUpdater(item.info, item.path)
    const controller = new SecureAutoUpdater({
      trust: item.trust,
      currentVersion: '1.0.0',
      updater,
      fetchEnvelope: async () => item.envelope,
      readState: () => undefined,
      writeState: vi.fn(),
      notify: vi.fn()
    })
    await controller.check('startup')
    writeFileSync(item.path, Buffer.alloc(ARTIFACT_SIZE, 0x42))

    await expect(controller.installVerifiedUpdate('install-now')).rejects.toThrow(/SHA-256/)
    expect(updater.installs).toBe(0)
    expect(controller.hasPendingUpdate).toBe(false)
  })

  it('gates check, durable state commit, and install through the external root authority', async () => {
    const item = fixture()
    const updater = new FakeUpdater(item.info, item.path)
    const calls: string[] = []
    const writeState = vi.fn()
    const commitState = vi.fn(async (state, manifest) => {
      calls.push('commit')
      expect(state).toEqual({
        schema: 1,
        sequence: item.manifest.sequence,
        version: item.manifest.version,
        artifactSha256: item.manifest.artifact.sha256
      })
      expect(manifest).toEqual(item.manifest)
    })
    const beforeInstall = vi.fn(async (state, manifest) => {
      calls.push('install-proof')
      expect(state.sequence).toBe(item.manifest.sequence)
      expect(manifest).toEqual(item.manifest)
    })
    const controller = new SecureAutoUpdater({
      trust: item.trust,
      currentVersion: '1.0.0',
      updater,
      fetchEnvelope: async () => item.envelope,
      readState: () => undefined,
      writeState,
      beforeCheck: async () => {
        calls.push('check-proof')
      },
      commitState,
      beforeInstall,
      notify: vi.fn()
    })

    await controller.check('startup')
    expect(calls).toEqual(['check-proof', 'commit'])
    expect(commitState).toHaveBeenCalledTimes(1)
    expect(writeState).not.toHaveBeenCalled()

    await controller.installVerifiedUpdate('install-now')
    expect(calls).toEqual(['check-proof', 'commit', 'install-proof'])
    expect(beforeInstall).toHaveBeenCalledTimes(1)
    expect(updater.installs).toBe(1)
  })

  it('revalidates a cached ready item instead of advertising stale authority', async () => {
    const item = fixture()
    const updater = new FakeUpdater(item.info, item.path)
    const states: UpdateUiState[] = []
    let ready = true
    const beforeInstall = vi.fn(async () => {
      if (!ready) throw new Error('Installation Root proof changed')
    })
    const controller = new SecureAutoUpdater({
      trust: item.trust,
      currentVersion: '1.0.0',
      updater,
      fetchEnvelope: async () => item.envelope,
      readState: () => undefined,
      writeState: vi.fn(),
      beforeInstall,
      notify: (state) => states.push(state)
    })

    await controller.check('startup')
    expect(controller.hasPendingUpdate).toBe(true)
    ready = false

    await expect(controller.check('periodic')).rejects.toThrow(/root proof/i)
    expect(beforeInstall).toHaveBeenCalledTimes(1)
    expect(controller.hasPendingUpdate).toBe(true)
    expect(states.at(-1)).toEqual({ phase: 'blocked', reason: 'security' })
    expect(updater.checks).toBe(1)
    expect(updater.downloads).toBe(1)

    ready = true
    await controller.check('manual')
    expect(controller.hasPendingUpdate).toBe(true)
    expect(updater.downloads).toBe(1)
  })

  it('serializes an explicit install behind an in-flight cached revalidation', async () => {
    const item = fixture()
    const updater = new FakeUpdater(item.info, item.path)
    let releaseProof!: () => void
    let enteredProof!: () => void
    const proofEntered = new Promise<void>((resolve) => {
      enteredProof = resolve
    })
    const beforeInstall = vi
      .fn()
      .mockImplementationOnce(
        () =>
          new Promise<void>((resolve) => {
            releaseProof = resolve
            enteredProof()
          })
      )
      .mockResolvedValue(undefined)
    const controller = new SecureAutoUpdater({
      trust: item.trust,
      currentVersion: '1.0.0',
      updater,
      fetchEnvelope: async () => item.envelope,
      readState: () => undefined,
      writeState: vi.fn(),
      beforeInstall,
      notify: vi.fn()
    })

    await controller.check('startup')
    const revalidation = controller.check('periodic')
    await proofEntered
    const installation = controller.installVerifiedUpdate('install-now')
    const callsBeforeRelease = beforeInstall.mock.calls.length
    releaseProof()
    await Promise.all([revalidation, installation])

    expect(callsBeforeRelease).toBe(1)
    expect(beforeInstall).toHaveBeenCalledTimes(2)
    expect(updater.installs).toBe(1)
  })

  it('coalesces a cached check into an in-flight explicit installation', async () => {
    const item = fixture()
    const updater = new FakeUpdater(item.info, item.path)
    let releaseProof!: () => void
    let enteredProof!: () => void
    const proofEntered = new Promise<void>((resolve) => {
      enteredProof = resolve
    })
    const beforeInstall = vi
      .fn()
      .mockImplementationOnce(
        () =>
          new Promise<void>((resolve) => {
            releaseProof = resolve
            enteredProof()
          })
      )
      .mockResolvedValue(undefined)
    const controller = new SecureAutoUpdater({
      trust: item.trust,
      currentVersion: '1.0.0',
      updater,
      fetchEnvelope: async () => item.envelope,
      readState: () => undefined,
      writeState: vi.fn(),
      beforeInstall,
      notify: vi.fn()
    })

    await controller.check('startup')
    const installation = controller.installVerifiedUpdate('install-now')
    await proofEntered
    const revalidation = controller.check('periodic')
    const coalesced = revalidation === installation
    releaseProof()
    await Promise.all([installation, revalidation])

    expect(coalesced).toBe(true)
    expect(beforeInstall).toHaveBeenCalledTimes(1)
    expect(updater.installs).toBe(1)
  })

  it('rehashes cached pending after root proof and clears invalid bytes for exact redownload', async () => {
    const item = fixture()
    const updater = new FakeUpdater(item.info, item.path)
    const order: string[] = []
    let state: unknown
    let tamperOnProof = true
    const controller = new SecureAutoUpdater({
      trust: item.trust,
      currentVersion: '1.0.0',
      updater,
      fetchEnvelope: async () => item.envelope,
      readState: () => state,
      writeState: (next) => {
        state = next
      },
      beforeInstall: async () => {
        order.push('root-proof')
        if (tamperOnProof) {
          tamperOnProof = false
          writeFileSync(item.path, Buffer.alloc(ARTIFACT_SIZE, 0x44))
        }
      },
      notify: vi.fn()
    })

    await controller.check('startup')
    expect(controller.hasPendingUpdate).toBe(true)

    await expect(controller.check('periodic')).rejects.toThrow(/SHA-256/)
    expect(order).toEqual(['root-proof'])
    expect(controller.hasPendingUpdate).toBe(false)
    expect(updater.downloads).toBe(1)

    writeFileSync(item.path, '')
    truncateSync(item.path, ARTIFACT_SIZE)
    await controller.check('manual')
    expect(updater.downloads).toBe(2)
    expect(controller.hasPendingUpdate).toBe(true)
  })

  it('performs the asynchronous root proof before the final installer attestation', async () => {
    const item = fixture()
    const updater = new FakeUpdater(item.info, item.path)
    const controller = new SecureAutoUpdater({
      trust: item.trust,
      currentVersion: '1.0.0',
      updater,
      fetchEnvelope: async () => item.envelope,
      readState: () => undefined,
      writeState: vi.fn(),
      beforeInstall: async () => {
        // Model a same-SID replacement while the root round-trip is in flight.
        // The post-authority hash must see it and block quitAndInstall.
        writeFileSync(item.path, Buffer.alloc(ARTIFACT_SIZE, 0x43))
      },
      notify: vi.fn()
    })

    await controller.check('startup')
    await expect(controller.installVerifiedUpdate('install-now')).rejects.toThrow(/SHA-256/)
    expect(updater.installs).toBe(0)
  })

  it('does not fetch or install when the Installation Root proof fails', async () => {
    const item = fixture()
    const updater = new FakeUpdater(item.info, item.path)
    const fetchEnvelope = vi.fn(async () => item.envelope)
    const states: UpdateUiState[] = []
    const blockedCheck = new SecureAutoUpdater({
      trust: item.trust,
      currentVersion: '1.0.0',
      updater,
      fetchEnvelope,
      readState: () => undefined,
      writeState: vi.fn(),
      beforeCheck: async () => {
        throw new Error('Installation Root authority unavailable')
      },
      notify: (state) => states.push(state)
    })
    await expect(blockedCheck.check('manual')).rejects.toThrow(/root authority/i)
    expect(fetchEnvelope).not.toHaveBeenCalled()
    expect(updater.checks).toBe(0)
    expect(states.at(-1)).toEqual({ phase: 'blocked', reason: 'security' })

    const installUpdater = new FakeUpdater(item.info, item.path)
    const installController = new SecureAutoUpdater({
      trust: item.trust,
      currentVersion: '1.0.0',
      updater: installUpdater,
      fetchEnvelope: async () => item.envelope,
      readState: () => undefined,
      writeState: vi.fn(),
      beforeInstall: async () => {
        throw new Error('Installation Root proof changed')
      },
      notify: vi.fn()
    })
    await installController.check('startup')
    await expect(installController.installVerifiedUpdate('install-now')).rejects.toThrow(
      /root proof/i
    )
    expect(installUpdater.installs).toBe(0)
  })

  it('wires ordinary app quit to cleanup only and reserves install for explicit renderer consent', () => {
    const main = readFileSync(join(__dirname, 'index.ts'), 'utf8')
    const beforeQuit = main.match(/app\.on\('before-quit',[\s\S]*?\n\}\)/)?.[0] || ''
    const toast = readFileSync(
      join(__dirname, '..', 'renderer', 'src', 'components', 'UpdateToast.tsx'),
      'utf8'
    )

    expect(beforeQuit).not.toContain('installVerifiedUpdate')
    expect(main).toContain("secureAutoUpdater.installVerifiedUpdate('install-now')")
    expect(toast).not.toMatch(/install on quit|退出时安装/i)
  })
})
