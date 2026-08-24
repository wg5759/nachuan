import { createHash } from 'node:crypto'
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { load as loadYaml } from 'js-yaml'
import { afterEach, describe, expect, it } from 'vitest'

import { createSettledAsarPackage } from './asar-test-fixture.mjs'
import { stageEnginePayload } from './engine-payload.mjs'
import {
  readPackagedMainBundle,
  verifyPackagedEngine,
  verifyPackagedGenericUpdateFeed,
  verifyPackagedMainEngineBinding,
  verifyPackagedMainRuntimeManifestBinding,
  verifyPackagedStoreRuntimeProfile,
  verifyPackagedUpdateTrustBinding
} from './_verify_pack.mjs'
import { renderUpdateTrustModule } from './write-update-trust.mjs'

const roots = []
const desktopRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const cleanPythonArchive = async () => ['engine_main', 'gateway.audio']

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'nachuan-packaged-integrity-'))
  roots.push(root)
  const sourceRoot = join(root, 'asar-source')
  const resourcesRoot = join(root, 'resources')
  const sourceEngine = join(root, 'engine.exe')
  mkdirSync(join(sourceRoot, 'out', 'main'), { recursive: true })
  mkdirSync(join(resourcesRoot, 'engine'), { recursive: true })
  writeFileSync(sourceEngine, 'controlled-engine-bytes')
  writeFileSync(join(resourcesRoot, 'engine', 'engine.exe'), 'controlled-engine-bytes')
  const digest = createHash('sha256').update('controlled-engine-bytes').digest('hex')
  return { root, sourceRoot, resourcesRoot, sourceEngine, digest }
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true })
})

describe('final packaged ASAR and engine binding', () => {
  it('stages the exact post-signing engine bytes through a non-signable builder source name', async () => {
    const { root, resourcesRoot, sourceEngine } = fixture()
    const preSigningDigest = createHash('sha256').update(readFileSync(sourceEngine)).digest('hex')

    // Authenticode changes PE bytes.  Appending a deterministic stand-in is
    // enough to reproduce the ordering bug without access to a real certificate.
    writeFileSync(sourceEngine, Buffer.concat([readFileSync(sourceEngine), Buffer.from('|signed-by-ci|')]))
    const stagedEngine = join(root, 'engine.payload')
    stageEnginePayload({ sourceEngine, stagedEngine })
    copyFileSync(stagedEngine, join(resourcesRoot, 'engine', 'engine.exe'))

    const result = await verifyPackagedEngine({
      resourcesRoot,
      sourceEngine: stagedEngine,
      engineName: 'engine.exe',
      inspectPythonArchive: cleanPythonArchive
    })
    expect(result.engineDigest).not.toBe(preSigningDigest)
    expect(result.engineDigest).toBe(
      createHash('sha256').update(readFileSync(sourceEngine)).digest('hex')
    )

    const config = loadYaml(readFileSync(join(desktopRoot, 'electron-builder.yml'), 'utf8'))
    const engineResource = config.win.extraResources.find((item) => item.to === 'engine/engine.exe')
    expect(engineResource).toEqual({ from: '../dist/engine.payload', to: 'engine/engine.exe' })
    expect(config.electronDist).toBe('build/electron-runtime')
    expect(config.extraResources.find((item) => item.to === 'licenses')).toEqual({
      from: 'build/license-evidence',
      to: 'licenses',
      filter: ['**/*']
    })
    expect(config.extraResources.find((item) => item.to === 'ENGINE_PYTHON_PAYLOAD.json')).toEqual({
      from: '../dist/ENGINE_PYTHON_PAYLOAD.json',
      to: 'ENGINE_PYTHON_PAYLOAD.json'
    })
    expect(config.extraResources.find((item) => item.to === 'store-runtime-profile.v1.json')).toEqual({
      from: '../config/store-runtime-profile.v1.json',
      to: 'store-runtime-profile.v1.json'
    })
  })

  it('keeps the real-certificate workflow in sign, bind, package, verify order', () => {
    const workflow = readFileSync(join(desktopRoot, '..', '.github', 'workflows', 'release.yml'), 'utf8')
    const orderedMarkers = [
      'node scripts/sign-engine.mjs',
      'node scripts/write-engine-digest.mjs',
      'npm exec --offline -- electron-builder --config electron-builder.production.yml --publish never',
      'node scripts/_verify_pack.mjs lean',
      'desktop/release/win-unpacked/resources/engine/engine.exe'
    ]
    const positions = orderedMarkers.map((marker) => workflow.indexOf(marker))
    expect(positions.every((position) => position >= 0)).toBe(true)
    expect(positions).toEqual([...positions].sort((left, right) => left - right))
    expect(workflow).toContain('signer_thumbprint=$thumbprint')
    expect(workflow).toContain(
      '$signature.SignerCertificate.Thumbprint -cne $env:EXPECTED_SIGNER_THUMBPRINT'
    )
    expect(workflow.indexOf('scripts/installer-closure.mjs install-verify')).toBeGreaterThan(
      workflow.indexOf('node scripts/_verify_pack.mjs lean')
    )
    const firstVerify = workflow.indexOf('node scripts/_verify_pack.mjs lean')
    const closure = workflow.indexOf('scripts/installer-closure.mjs install-verify')
    const postClosureVerify = workflow.indexOf('node scripts/_verify_pack.mjs lean', firstVerify + 1)
    expect(postClosureVerify).toBeGreaterThan(closure)
    expect(workflow).toContain('release/WIN_UNPACKED_MANIFEST.json')
  })

  it('checks out the immutable verified commit and retires the historical v0.1.0 identity', () => {
    const workflow = readFileSync(join(desktopRoot, '..', '.github', 'workflows', 'release.yml'), 'utf8')
    expect(workflow).toContain('release_commit: ${{ steps.release_identity.outputs.release_commit }}')
    expect(workflow).toContain('ref: ${{ needs.verify.outputs.release_commit }}')
    expect(workflow).toContain('$headCommit -cne $env:RELEASE_COMMIT')
    expect(workflow).toContain('$tagCommit -cne $env:RELEASE_COMMIT')
    expect(workflow).toContain("if ($version -ceq '0.1.0')")
  })

  it('guards the pinned builder contract that signs extra resources by source filename', () => {
    const packageJson = JSON.parse(readFileSync(join(desktopRoot, 'package.json'), 'utf8'))
    expect(packageJson.devDependencies['electron-builder']).toBe('26.15.3')

    const winPackager = readFileSync(
      join(desktopRoot, 'node_modules', 'app-builder-lib', 'out', 'winPackager.js'),
      'utf8'
    )
    expect(winPackager).toMatch(
      /return file => \{\s*if \(this\.shouldSignFile\(file\)\)[\s\S]*new builder_util_1\.CopyFileTransformer\(file => this\.signIf\(file\)\)/
    )

    const platformPackager = readFileSync(
      join(desktopRoot, 'node_modules', 'app-builder-lib', 'out', 'platformPackager.js'),
      'utf8'
    )
    expect(platformPackager).toContain('copyFiles)(extraResourceMatchers, transformerForExtraFiles)')
    const copyPosition = platformPackager.indexOf('copyFiles)(extraResourceMatchers, transformerForExtraFiles)')
    const afterPackPosition = platformPackager.indexOf('await this.info.emitAfterPack(packContext)')
    const signPosition = platformPackager.indexOf('await this.doSignAfterPack(')
    expect(copyPosition).toBeGreaterThanOrEqual(0)
    expect(afterPackPosition).toBeGreaterThan(copyPosition)
    expect(signPosition).toBeGreaterThan(afterPackPosition)

    const fileCopier = readFileSync(
      join(desktopRoot, 'node_modules', 'builder-util', 'out', 'fs.js'),
      'utf8'
    )
    expect(fileCopier).toMatch(/await afterCopyTransformer\(dest\)/)

    const afterPackHook = readFileSync(join(desktopRoot, 'scripts', 'after-pack.mjs'), 'utf8')
    const finalVerifier = readFileSync(join(desktopRoot, 'scripts', '_verify_pack.mjs'), 'utf8')
    expect(afterPackHook).toMatch(/finalizePackagedRuntime[\s\S]*verifyPackagedLicenseEvidence/)
    expect(afterPackHook).toContain("deferredNativeArtifacts: ['resources/elevate.exe']")
    expect(afterPackHook).toContain('verifyPackagedPythonPayloadProvenance')
    expect(finalVerifier).toContain(
      'verifyPackagedLicenseEvidence({ appOutDir: dirname(resourcesRoot), projectRoot: repoRoot })'
    )
    expect(finalVerifier).toContain('verifyPackagedPythonPayloadProvenance({')
  })

  it('pins the audited updater API and separates public unsigned early-access metadata', () => {
    const packageJson = JSON.parse(readFileSync(join(desktopRoot, 'package.json'), 'utf8'))
    expect(packageJson.version).toBe('0.2.0')
    expect(packageJson.dependencies['electron-updater']).toBe('6.8.9')
    const updaterTypes = readFileSync(
      join(desktopRoot, 'node_modules', 'electron-updater', 'out', 'AppUpdater.d.ts'),
      'utf8'
    )
    const eventTypes = readFileSync(
      join(desktopRoot, 'node_modules', 'electron-updater', 'out', 'types.d.ts'),
      'utf8'
    )
    expect(updaterTypes).toContain('downloadUpdate(cancellationToken?: CancellationToken): Promise<Array<string>>')
    expect(eventTypes).toMatch(/interface UpdateDownloadedEvent[\s\S]*downloadedFile: string/)

    const earlyConfig = loadYaml(
      readFileSync(join(desktopRoot, 'electron-builder.early-access.yml'), 'utf8')
    )
    expect(earlyConfig.win.artifactName).toContain('early-access-unsigned')
    expect(earlyConfig.publish).toHaveLength(1)
    expect(earlyConfig.publish[0].provider).toBe('generic')
    expect(earlyConfig.publish[0].url).toBe('${env.NACHUAN_UPDATE_BASE_URL}')
    expect(earlyConfig.publish[0].channel).toBe('early-access-${env.DMX_VARIANT}')

    const localConfigText = readFileSync(join(desktopRoot, 'electron-builder.yml'), 'utf8')
    const localConfig = loadYaml(localConfigText)
    expect(localConfig.publish).toBeUndefined()
    expect(localConfigText).not.toMatch(/GH_OWNER|GH_REPO/)
    const productionConfig = loadYaml(
      readFileSync(join(desktopRoot, 'electron-builder.production.yml'), 'utf8')
    )
    expect(productionConfig.publish).toEqual([
      {
        provider: 'generic',
        url: '${env.NACHUAN_UPDATE_BASE_URL}',
        channel: 'production-${env.DMX_VARIANT}'
      }
    ])
    const releaseWorkflow = readFileSync(
      join(desktopRoot, '..', '.github', 'workflows', 'release.yml'),
      'utf8'
    )
    expect(releaseWorkflow).toContain('--config electron-builder.production.yml --publish never')
    expect(releaseWorkflow).toContain(
      'NACHUAN_UPDATE_BASE_URL: ${{ vars.NACHUAN_PRODUCTION_UPDATE_BASE_URL }}'
    )

    expect(packageJson.scripts.build).toMatch(/^node scripts\/write-update-trust\.mjs && /)
    for (const scriptName of ['_build_pack', '_build_pack_early']) {
      expect(packageJson.scripts[scriptName]).toContain('node scripts/write-update-trust.mjs')
    }
    const localPowerShell = readFileSync(join(desktopRoot, '..', 'scripts', 'build-local.ps1'), 'utf8')
    const localShell = readFileSync(join(desktopRoot, '..', 'scripts', 'build-local.sh'), 'utf8')
    expect(localPowerShell).toContain("$env:NACHUAN_UPDATE_TIER = $null")
    expect(localPowerShell).toContain("@('scripts/write-update-trust.mjs')")
    expect(localPowerShell).toContain("$LlamaUri.Host -cne 'github.com'")
    expect(localPowerShell).toContain('NACHUAN_FULL_RUNTIME_TRUST_MANIFEST')
    expect(localShell).toContain('unset NACHUAN_UPDATE_TIER')
    expect(localShell).toContain('scripts/write-update-trust.mjs')
    expect(localShell).toContain('https://github.com/ggml-org/llama.cpp/releases/download/*')
    expect(localShell).toContain('NACHUAN_FULL_RUNTIME_TRUST_MANIFEST')
  })

  it('binds an exact disabled trust into ASAR and rejects stale or test release roots', async () => {
    const { root, sourceRoot, resourcesRoot } = fixture()
    const generatedDirectory = join(root, 'desktop', 'src', 'main')
    mkdirSync(generatedDirectory, { recursive: true })
    const disabled = {
      schema: 1,
      enabled: false,
      releaseTier: 'disabled',
      channel: '',
      variant: '',
      keyId: '',
      publicKeySpkiBase64: '',
      manifestUrl: '',
      currentSequence: 0,
      keyringSequence: 0,
      keyringSha256: '',
      publisherName: '',
      signerThumbprint: ''
    }
    const disabledModule = renderUpdateTrustModule(disabled)
    writeFileSync(join(generatedDirectory, 'generated-update-trust.ts'), disabledModule)
    writeFileSync(join(sourceRoot, 'out', 'main', 'index.js'), disabledModule)
    await createSettledAsarPackage(sourceRoot, join(resourcesRoot, 'app.asar'))

    expect(() =>
      verifyPackagedUpdateTrustBinding({ repoRoot: root, resourcesRoot, releaseTier: 'disabled' })
    ).not.toThrow()

    const testTrust = {
      ...disabled,
      enabled: true,
      releaseTier: 'early-access',
      channel: 'early-access-lean-win-x64',
      variant: 'lean',
      keyId: 'test-key',
      publicKeySpkiBase64: 'MCowBQYDK2VwAyEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
      manifestUrl: 'https://updates.example.test/channel.json',
      currentSequence: 1
    }
    const fake = fixture()
    const fakeGeneratedDirectory = join(fake.root, 'desktop', 'src', 'main')
    mkdirSync(fakeGeneratedDirectory, { recursive: true })
    const testModule = renderUpdateTrustModule(testTrust)
    writeFileSync(join(fakeGeneratedDirectory, 'generated-update-trust.ts'), testModule)
    writeFileSync(join(fake.sourceRoot, 'out', 'main', 'index.js'), testModule)
    await createSettledAsarPackage(fake.sourceRoot, join(fake.resourcesRoot, 'app.asar'))
    expect(() =>
      verifyPackagedUpdateTrustBinding({
        repoRoot: fake.root,
        resourcesRoot: fake.resourcesRoot,
        releaseTier: 'early-access'
      })
    ).toThrow(/test|non-public/i)

    writeFileSync(join(fakeGeneratedDirectory, 'generated-update-trust.ts'), disabledModule)
    expect(() =>
      verifyPackagedUpdateTrustBinding({
        repoRoot: fake.root,
        resourcesRoot: fake.resourcesRoot,
        releaseTier: 'disabled'
      })
    ).toThrow(/differs|stale/i)
  })

  it('requires a small regular generic update feed beside the final packaged ASAR', () => {
    const { resourcesRoot } = fixture()
    const trust = {
      schema: 1,
      enabled: true,
      releaseTier: 'early-access',
      channel: 'early-access-lean-win-x64',
      variant: 'lean',
      keyId: 'early-2026-01',
      publicKeySpkiBase64: 'unused-by-feed-gate',
      manifestUrl: 'https://updates.nachuan.ai/releases/early-access-lean-win-x64.json',
      currentSequence: 1,
      publisherName: '',
      signerThumbprint: ''
    }

    expect(() => verifyPackagedGenericUpdateFeed({ resourcesRoot, trust })).toThrow(/app-update.*missing/i)

    writeFileSync(
      join(resourcesRoot, 'app-update.yml'),
      [
        'provider: generic',
        'url: https://updates.nachuan.ai/releases/',
        'channel: early-access-lean',
        'updaterCacheDirName: aggregator-desktop-updater',
        ''
      ].join('\n')
    )
    expect(() => verifyPackagedGenericUpdateFeed({ resourcesRoot, trust })).not.toThrow()
  })

  it('rejects update feed authority drift, credentials, private sources, headers, and tokens', () => {
    const { resourcesRoot } = fixture()
    const trust = {
      schema: 1,
      enabled: true,
      releaseTier: 'early-access',
      channel: 'early-access-lean-win-x64',
      variant: 'lean',
      keyId: 'early-2026-01',
      publicKeySpkiBase64: 'unused-by-feed-gate',
      manifestUrl: 'https://updates.nachuan.ai/releases/early-access-lean-win-x64.json',
      currentSequence: 1,
      publisherName: '',
      signerThumbprint: ''
    }
    const invalidFeeds = [
      ['url: https://updates.nachuan.ai/releases/', 'channel: other'],
      ['url: https://updates.nachuan.ai/drift/', 'channel: early-access-lean'],
      ['url: https://user:secret@updates.nachuan.ai/releases/', 'channel: early-access-lean'],
      ['url: https://10.0.0.7/releases/', 'channel: early-access-lean'],
      [
        'url: https://updates.nachuan.ai/releases/',
        'channel: early-access-lean',
        'private: true'
      ],
      [
        'url: https://updates.nachuan.ai/releases/',
        'channel: early-access-lean',
        'requestHeaders:',
        '  Authorization: Bearer hidden'
      ],
      [
        'url: https://updates.nachuan.ai/releases/',
        'channel: early-access-lean',
        'token: hidden'
      ]
    ]

    for (const lines of invalidFeeds) {
      writeFileSync(
        join(resourcesRoot, 'app-update.yml'),
        ['provider: generic', ...lines, ''].join('\n')
      )
      expect(() => verifyPackagedGenericUpdateFeed({ resourcesRoot, trust })).toThrow()
    }
  })

  it('reads the final app.asar and binds its main bundle to the only packaged engine', async () => {
    const { sourceRoot, resourcesRoot, sourceEngine, digest } = fixture()
    writeFileSync(join(sourceRoot, 'out', 'main', 'index.js'), `const expected = '${digest}'`)
    await createSettledAsarPackage(sourceRoot, join(resourcesRoot, 'app.asar'))

    const result = await verifyPackagedEngine({
      resourcesRoot,
      sourceEngine,
      engineName: 'engine.exe',
      inspectPythonArchive: cleanPythonArchive
    })
    expect(result.engineDigest).toBe(digest)
    expect(readPackagedMainBundle(resourcesRoot)).toContain(digest)
    expect(() => verifyPackagedMainEngineBinding({ resourcesRoot, engineDigest: digest })).not.toThrow()
  })

  it('rejects an extra executable or payload beside the packaged engine', async () => {
    const { resourcesRoot, sourceEngine } = fixture()
    writeFileSync(join(resourcesRoot, 'engine', 'helper.dll'), 'unexpected')

    await expect(
      verifyPackagedEngine({
        resourcesRoot,
        sourceEngine,
        engineName: 'engine.exe',
        inspectPythonArchive: cleanPythonArchive
      })
    ).rejects.toThrow(/must contain only engine\.exe/)
  })

  it('rejects optional ASR packages, unresolved torch-complex, or evaluation-only terms in the engine payload', async () => {
    for (const token of [
      'kaldiio',
      'funasr',
      'torch',
      'torch_complex',
      'SOFTWARE LICENSE AGREEMENT FOR EVALUATION.txt'
    ]) {
      const { resourcesRoot, sourceEngine } = fixture()
      const bytes = `controlled-engine-bytes|${token}|`
      writeFileSync(sourceEngine, bytes)
      writeFileSync(join(resourcesRoot, 'engine', 'engine.exe'), bytes)
      await expect(
        verifyPackagedEngine({
          resourcesRoot,
          sourceEngine,
          engineName: 'engine.exe',
          inspectPythonArchive: async () => ['engine_main', token]
        })
      ).rejects.toThrow(/forbidden Python release payload entry/i)
    }
  })

  it('rejects an app.asar whose final main bundle lacks the engine digest', async () => {
    const { sourceRoot, resourcesRoot, digest } = fixture()
    writeFileSync(join(sourceRoot, 'out', 'main', 'index.js'), 'const expected = "wrong"')
    await createSettledAsarPackage(sourceRoot, join(resourcesRoot, 'app.asar'))

    expect(() => verifyPackagedMainEngineBinding({ resourcesRoot, engineDigest: digest })).toThrow(
      /final packaged app\.asar/
    )
  })

  it('binds the prepared local runtime manifest digest into the final app.asar', async () => {
    const { sourceRoot, resourcesRoot } = fixture()
    const digest = createHash('sha256').update('reviewed-runtime-manifest').digest('hex')
    writeFileSync(join(sourceRoot, 'out', 'main', 'index.js'), `const runtime = '${digest}'`)
    await createSettledAsarPackage(sourceRoot, join(resourcesRoot, 'app.asar'))

    expect(() =>
      verifyPackagedMainRuntimeManifestBinding({ resourcesRoot, manifestDigest: digest })
    ).not.toThrow()
    const other = createHash('sha256').update('replacement').digest('hex')
    expect(() =>
      verifyPackagedMainRuntimeManifestBinding({ resourcesRoot, manifestDigest: other })
    ).toThrow(/local runtime manifest digest/)
  })

  it('binds the final store profile bytes to ASAR and the engine import surface', async () => {
    const { root, sourceRoot, resourcesRoot } = fixture()
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
    const digest = createHash('sha256').update(profile).digest('hex')
    const runtimeProfileSource = Buffer.from('STORE_RUNTIME_PROFILE = load_manifest()\n')
    mkdirSync(join(root, 'config'))
    mkdirSync(join(root, 'gateway'))
    writeFileSync(join(root, 'config', 'store-runtime-profile.v1.json'), profile)
    writeFileSync(join(root, 'gateway', 'runtime_profile.py'), runtimeProfileSource)
    mkdirSync(join(root, 'desktop', 'src', 'main'), { recursive: true })
    writeFileSync(
      join(root, 'desktop', 'src', 'main', 'generated-engine-integrity.ts'),
      `export const EXPECTED_STORE_RUNTIME_PROFILE_SHA256 = '${digest}'\n`
    )
    writeFileSync(join(resourcesRoot, 'store-runtime-profile.v1.json'), profile)
    writeFileSync(
      join(sourceRoot, 'out', 'main', 'index.js'),
      [
        `const digest = '${digest}'`,
        'async function startEngineOnce() {',
        '  const profile = await attestPackagedStoreRuntimeProfile(resources, digest)',
        '  Object.assign(env, bindAttestedStoreRuntimeProfileEnvironment({}, profile))',
        '  spawn(engine)',
        '}'
      ].join('\n')
    )
    await createSettledAsarPackage(sourceRoot, join(resourcesRoot, 'app.asar'))
    const requiredImports = [
      'engine_main',
      'PYZ.pyz',
      'gateway.app',
      'gateway.local_model',
      'gateway.mcp_registry',
      'gateway.media_binary',
      'gateway.providers.cli_env',
      'gateway.runtime_profile',
      'orchestrator.studio',
      'orchestrator.tool_agent',
      'config/store-runtime-profile.v1.json'
    ]
    const pythonPayload = {
      archiveEntries: requiredImports,
      ownershipEntries: [
        {
          destination: 'config/store-runtime-profile.v1.json',
          owner: { kind: 'project-source', name: 'nachuan', version: 'release-source-snapshot' },
          scope: 'analysis-data',
          source: {
            path: 'project/config/store-runtime-profile.v1.json',
            sha256: digest,
            size: profile.length
          },
          type: 'DATA'
        },
        {
          destination: 'gateway.runtime_profile',
          owner: { kind: 'project-source', name: 'nachuan', version: 'release-source-snapshot' },
          scope: 'analysis-module',
          source: {
            path: 'project/gateway/runtime_profile.py',
            sha256: createHash('sha256').update(runtimeProfileSource).digest('hex'),
            size: runtimeProfileSource.length
          },
          type: 'PYMODULE'
        }
      ]
    }

    await expect(
      verifyPackagedStoreRuntimeProfile({ repoRoot: root, resourcesRoot, pythonPayload })
    ).resolves.toMatchObject({ profileDigest: digest })
    await expect(
      verifyPackagedStoreRuntimeProfile({
        repoRoot: root,
        resourcesRoot,
        pythonPayload: {
          ...pythonPayload,
          archiveEntries: [...requiredImports, 'yt_dlp.extractor']
        }
      })
    ).rejects.toThrow(/forbidden|yt_dlp/i)
  })
})
