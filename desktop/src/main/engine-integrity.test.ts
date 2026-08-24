import { createHash } from 'node:crypto'
import { mkdirSync, renameSync, symlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'

import {
  attestPackagedEngine,
  attestPackagedMediaRuntime,
  attestPackagedRuntimeManifest,
  attestPackagedStoreRuntimeProfile,
  bindAttestedStoreRuntimeProfileEnvironment,
  bindAttestedMediaRuntimeEnvironment,
  EngineIntegrityError,
  hashStableBoundedPeFile,
  minimalDevelopmentEngineEnvironment,
  minimalPackagedEngineEnvironment,
  readStableBoundedFile
} from './engine-integrity'

const roots: string[] = []

afterEach(async () => {
  const { rm } = await import('node:fs/promises')
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })))
})

async function fixture(): Promise<{ root: string; engine: string; digest: string }> {
  const { mkdtemp } = await import('node:fs/promises')
  const { tmpdir } = await import('node:os')
  const root = await mkdtemp(join(tmpdir(), 'nachuan-engine-integrity-'))
  roots.push(root)
  const engine = join(root, process.platform === 'win32' ? 'engine.exe' : 'engine')
  const bytes = Buffer.from('synthetic-packaged-engine')
  writeFileSync(engine, bytes)
  return { root, engine, digest: createHash('sha256').update(bytes).digest('hex') }
}

function peX64(marker: string): Buffer {
  const bytes = Buffer.alloc(512)
  bytes.write('MZ')
  bytes.writeUInt32LE(128, 0x3c)
  bytes.write('PE\0\0', 128, 'ascii')
  bytes.writeUInt16LE(0x8664, 132)
  bytes.write(marker, 160)
  return bytes
}

describe('packaged engine integrity', () => {
  it('accepts only the exact digest-bound executable', async () => {
    const item = await fixture()
    await expect(attestPackagedEngine(item.root, item.engine.split(/[\\/]/).pop()!, item.digest)).resolves.toBe(
      item.engine
    )
    writeFileSync(item.engine, 'replaced')
    await expect(
      attestPackagedEngine(item.root, item.engine.split(/[\\/]/).pop()!, item.digest)
    ).rejects.toThrow(/SHA-256/)
  })

  it('rejects an unbound build and adjacent sidecar files', async () => {
    const item = await fixture()
    await expect(
      attestPackagedEngine(item.root, item.engine.split(/[\\/]/).pop()!, '')
    ).rejects.toBeInstanceOf(EngineIntegrityError)
    writeFileSync(join(item.root, 'version.dll'), 'unreviewed')
    await expect(
      attestPackagedEngine(item.root, item.engine.split(/[\\/]/).pop()!, item.digest)
    ).rejects.toThrow(/sidecar/)
  })

  it('rejects a redirected engine directory', async () => {
    const item = await fixture()
    const parent = join(item.root, '..', `nachuan-engine-link-${process.pid}-${Date.now()}`)
    roots.push(parent)
    mkdirSync(parent)
    const link = join(parent, 'engine')
    symlinkSync(item.root, link, process.platform === 'win32' ? 'junction' : 'dir')
    await expect(
      attestPackagedEngine(link, item.engine.split(/[\\/]/).pop()!, item.digest)
    ).rejects.toThrow(/redirect/)
  })

  it('binds the local runtime manifest to the signed main bundle digest', async () => {
    const item = await fixture()
    const manifest = join(item.root, 'local-runtime-manifest.json')
    const bytes = Buffer.from('{"schema":1,"artifacts":[]}\n')
    writeFileSync(manifest, bytes)
    const digest = createHash('sha256').update(bytes).digest('hex')

    await expect(attestPackagedRuntimeManifest(item.root, digest)).resolves.toBe(manifest)
    writeFileSync(manifest, '{"schema":1,"artifacts":[{"path":"changed"}]}')
    await expect(attestPackagedRuntimeManifest(item.root, digest)).rejects.toThrow(
      /signed release binding/
    )
  })

  it('rejects an oversized runtime manifest before parsing it', async () => {
    const item = await fixture()
    const manifest = join(item.root, 'local-runtime-manifest.json')
    const bytes = Buffer.alloc(256 * 1024 + 1, 0x20)
    writeFileSync(manifest, bytes)
    const digest = createHash('sha256').update(bytes).digest('hex')

    await expect(attestPackagedRuntimeManifest(item.root, digest)).rejects.toThrow(
      /acceptable regular file/
    )
  })

  it('detects pathname replacement after opening the manifest handle', async () => {
    const item = await fixture()
    const manifest = join(item.root, 'local-runtime-manifest.json')
    const moved = join(item.root, 'local-runtime-manifest.opened.json')
    writeFileSync(manifest, '{"schema":1,"artifacts":[]}\n')

    expect(() =>
      readStableBoundedFile(
        manifest,
        item.root,
        256 * 1024,
        'local runtime manifest',
        () => {
          renameSync(manifest, moved)
          writeFileSync(manifest, '{"schema":1,"artifacts":[{"path":"replacement"}]}\n')
        }
      )
    ).toThrow(/changed while being read|pathname was replaced/)
  })

  it('does not inherit PATH, proxy variables, or credentials', () => {
    const env = minimalPackagedEngineEnvironment({
      SystemRoot: 'C:\\Windows',
      TEMP: 'C:\\Temp',
      PATH: 'C:\\attacker',
      HTTPS_PROXY: 'http://attacker',
      OPENAI_API_KEY: 'secret'
    })
    expect(env.SystemRoot).toBe('C:\\Windows')
    expect(env.TEMP).toBe('C:\\Temp')
    expect(env.PATH).toBeUndefined()
    expect(env.HTTPS_PROXY).toBeUndefined()
    expect(env.OPENAI_API_KEY).toBeUndefined()
  })

  it('uses an explicit development allowlist without inheriting arbitrary tokens or keys', () => {
    const env = minimalDevelopmentEngineEnvironment({
      SystemRoot: 'C:\\Windows',
      PATH: 'C:\\trusted-dev-tools',
      USERPROFILE: 'C:\\Users\\developer',
      CODEX_CLI_PATH: 'C:\\tools\\codex.exe',
      CODEX_CLI_SHA256: 'a'.repeat(64),
      CLAUDE_CLI_PATH: 'C:\\tools\\claude.exe',
      CLAUDE_CLI_SHA256: 'c'.repeat(64),
      CLAUDE_CONFIG_DIR: 'C:\\Users\\developer\\.claude',
      GH_TOKEN: 'github-secret',
      GITHUB_PAT: 'github-pat',
      OPENAI_API_KEY: 'provider-secret',
      RANDOM_SERVICE_TOKEN: 'random-secret',
      RANDOM_SIGNING_KEY: 'signing-secret',
      HTTPS_PROXY: 'http://user:password@proxy.invalid'
    })
    expect(env.SystemRoot).toBe('C:\\Windows')
    expect(env.PATH).toBe('C:\\trusted-dev-tools')
    expect(env.USERPROFILE).toBe('C:\\Users\\developer')
    expect(env.CODEX_CLI_PATH).toBe('C:\\tools\\codex.exe')
    expect(env.CODEX_CLI_SHA256).toBe('a'.repeat(64))
    expect(env.CLAUDE_CLI_PATH).toBeUndefined()
    expect(env.CLAUDE_CLI_SHA256).toBeUndefined()
    expect(env.CLAUDE_CONFIG_DIR).toBeUndefined()
    expect(env.GH_TOKEN).toBeUndefined()
    expect(env.GITHUB_PAT).toBeUndefined()
    expect(env.OPENAI_API_KEY).toBeUndefined()
    expect(env.RANDOM_SERVICE_TOKEN).toBeUndefined()
    expect(env.RANDOM_SIGNING_KEY).toBeUndefined()
    expect(env.HTTPS_PROXY).toBeUndefined()
  })

  it('attests the exact unsigned fixed-hash media closure and overwrites inherited FF vars', async () => {
    const item = await fixture()
    const media = join(item.root, 'media')
    mkdirSync(media)
    const ffmpeg = peX64('ffmpeg')
    const ffprobe = peX64('ffprobe')
    const ffmpegSha256 = createHash('sha256').update(ffmpeg).digest('hex')
    const ffprobeSha256 = createHash('sha256').update(ffprobe).digest('hex')
    writeFileSync(join(media, 'ffmpeg.exe'), ffmpeg)
    writeFileSync(join(media, 'ffprobe.exe'), ffprobe)
    const manifest = Buffer.from(
      `${JSON.stringify({
        artifacts: [
          { path: 'media/ffmpeg.exe', role: 'ffmpeg', sha256: ffmpegSha256, size: ffmpeg.length },
          { path: 'media/ffprobe.exe', role: 'ffprobe', sha256: ffprobeSha256, size: ffprobe.length }
        ],
        authenticode: { signer: null, status: 'NotSigned', timestamp: null },
        releaseAdmission: {
          legalClosure: 'incomplete',
          production: 'blocked',
          trustClass: 'unsigned-fixed-hash-engineering-candidate'
        },
        schema: 'nachuan.media-runtime-manifest.v1'
      })}\n`
    )
    writeFileSync(join(item.root, 'media-runtime-manifest.json'), manifest)
    const runtime = await attestPackagedMediaRuntime(item.root, {
      ffmpegSha256,
      ffprobeSha256,
      manifestSha256: createHash('sha256').update(manifest).digest('hex')
    })
    expect(runtime.ffmpegPath).toBe(join(media, 'ffmpeg.exe'))
    const env = bindAttestedMediaRuntimeEnvironment(
      { FFMPEG_BIN: 'C:\\attacker.exe', FFPROBE_SHA256: '0'.repeat(64) },
      runtime
    )
    expect(env.FFMPEG_BIN).toBe(runtime.ffmpegPath)
    expect(env.FFMPEG_SHA256).toBe(ffmpegSha256)
    expect(env.FFPROBE_BIN).toBe(runtime.ffprobePath)
    expect(env.FFPROBE_SHA256).toBe(ffprobeSha256)
    expect(env.NACHUAN_MEDIA_RUNTIME_MANIFEST).toBe(runtime.manifestPath)
  })

  it('rejects media sidecars and byte drift even when the writable manifest is changed too', async () => {
    const item = await fixture()
    const media = join(item.root, 'media')
    mkdirSync(media)
    writeFileSync(join(media, 'ffmpeg.exe'), peX64('ffmpeg'))
    writeFileSync(join(media, 'ffprobe.exe'), peX64('ffprobe'))
    writeFileSync(join(media, 'ffplay.exe'), peX64('ffplay'))
    writeFileSync(join(item.root, 'media-runtime-manifest.json'), '{}\n')
    await expect(
      attestPackagedMediaRuntime(item.root, {
        ffmpegSha256: 'a'.repeat(64),
        ffprobeSha256: 'b'.repeat(64),
        manifestSha256: createHash('sha256').update('{}\n').digest('hex')
      })
    ).rejects.toThrow(/schema|sidecar/i)
  })

  it('binds the exact store runtime profile bytes into the packaged engine environment', async () => {
    const item = await fixture()
    const profile = Buffer.from(
      `${JSON.stringify({
        capabilities: [
          'http-model-provider',
          'packaged-local-model-program',
          'packaged-media-program'
        ],
        connectionTypes: ['openai_compat', 'perplexity', 'volcano'],
        externalProgramAuthorities: ['final-payload-manifest'],
        externalProgramRoles: ['ffmpeg', 'ffprobe', 'llama-server'],
        frozenPythonExcludes: [
          'gateway.providers.claude_code',
          'gateway.providers.codex',
          'yt_dlp'
        ],
        name: 'store',
        providerTypes: ['echo', 'openai_compat', 'perplexity', 'volcano'],
        schema: 'nachuan.runtime-profile/v1'
      }, null, 2)}\n`,
      'utf8'
    )
    const profilePath = join(item.root, 'store-runtime-profile.v1.json')
    writeFileSync(profilePath, profile)
    const digest = createHash('sha256').update(profile).digest('hex')

    const attested = await attestPackagedStoreRuntimeProfile(item.root, digest)
    expect(attested.path).toBe(profilePath)
    expect(bindAttestedStoreRuntimeProfileEnvironment({}, attested)).toEqual({
      NACHUAN_RUNTIME_PROFILE: 'store',
      NACHUAN_STORE_RUNTIME_PROFILE_MANIFEST: profilePath,
      NACHUAN_STORE_RUNTIME_PROFILE_SHA256: digest
    })

    writeFileSync(profilePath, Buffer.concat([profile, Buffer.from(' ')]))
    await expect(attestPackagedStoreRuntimeProfile(item.root, digest)).rejects.toThrow(/profile|digest/i)
  })

  it('hashes large PE payloads in fixed chunks without materializing the full executable', async () => {
    const item = await fixture()
    const executable = join(item.root, 'large-media.exe')
    const bytes = Buffer.alloc(3 * 1024 * 1024 + 17, 0x5a)
    bytes.write('MZ')
    bytes.writeUInt32LE(128, 0x3c)
    bytes.write('PE\0\0', 128, 'ascii')
    bytes.writeUInt16LE(0x8664, 132)
    writeFileSync(executable, bytes)
    const chunks: number[] = []
    const result = hashStableBoundedPeFile(
      executable,
      item.root,
      4 * 1024 * 1024,
      'large packaged media',
      (count) => chunks.push(count)
    )
    expect(chunks.length).toBeGreaterThan(3)
    expect(Math.max(...chunks)).toBeLessThanOrEqual(1024 * 1024)
    expect(chunks.reduce((sum, count) => sum + count, 0)).toBe(bytes.length)
    expect(result.sha256).toBe(createHash('sha256').update(bytes).digest('hex'))
  })
})
