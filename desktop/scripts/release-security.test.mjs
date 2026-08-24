import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises'
import { spawnSync } from 'node:child_process'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { afterEach, describe, expect, it } from 'vitest'

import { createSettledAsarPackage } from './asar-test-fixture.mjs'
import { prepareConnectionSeed, scanReleasePaths } from './release-security.mjs'

const workdirs = []
const script = join(dirname(fileURLToPath(import.meta.url)), 'release-security.mjs')

afterEach(async () => {
  await Promise.all(workdirs.splice(0).map((p) => rm(p, { recursive: true, force: true })))
})

describe('release secret gate', () => {
  it('blocks the legacy non-production video workflow from packaged resources', async () => {
    const root = await mkdtemp(join(tmpdir(), 'nachuan-release-non-production-'))
    workdirs.push(root)
    const legacyRoot = join(root, 'win-unpacked', 'resources', '视频工作流')
    await mkdir(join(legacyRoot, 'scripts'), { recursive: true })
    await writeFile(join(legacyRoot, 'scripts', 'doctor.py'), 'print("legacy")\n', 'utf8')

    const findings = await scanReleasePaths([root])

    expect(findings).toContainEqual({
      code: 'NON_PRODUCTION_WORKFLOW',
      file: legacyRoot,
      field: 'path'
    })
  })

  it('blocks a packaged connection seed containing a non-empty API key', async () => {
    const root = await mkdtemp(join(tmpdir(), 'nachuan-release-gate-'))
    workdirs.push(root)
    const resources = join(root, 'win-unpacked', 'resources')
    await mkdir(resources, { recursive: true })
    await writeFile(
      join(resources, 'seed-connections.json'),
      JSON.stringify({ provider: { api_key: 'test-secret-must-not-ship' } }),
      'utf8'
    )

    const findings = await scanReleasePaths([root])

    expect(findings).toEqual([
      expect.objectContaining({
        code: 'NON_EMPTY_SECRET',
        field: 'api_key',
        file: join(resources, 'seed-connections.json')
      })
    ])
  })

  it('blocks channel and OAuth credential field variants', async () => {
    const root = await mkdtemp(join(tmpdir(), 'nachuan-release-channel-gate-'))
    workdirs.push(root)
    await writeFile(
      join(root, 'channel.json'),
      JSON.stringify({ bot_token: 'channel-secret', oauth: { client_secret: 'oauth-secret' } }),
      'utf8'
    )

    const findings = await scanReleasePaths([root])

    expect(findings.map((item) => item.field).sort()).toEqual(['bot_token', 'client_secret'])
  })

  it('scans non-JSON text and opaque release binaries for credential assignments', async () => {
    const root = await mkdtemp(join(tmpdir(), 'nachuan-release-opaque-gate-'))
    workdirs.push(root)
    await writeFile(join(root, '.env'), 'SERVICE_API_KEY=release-secret-value\n', 'utf8')
    await writeFile(
      join(root, 'payload.exe'),
      Buffer.from('\u0000prefix\u0000bot_token="embedded-channel-secret"\u0000suffix\u0000')
    )

    const findings = await scanReleasePaths([root])

    expect(findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: 'TEXT_SECRET', field: 'SERVICE_API_KEY' }),
        expect.objectContaining({ code: 'EMBEDDED_SECRET', field: 'bot_token' })
      ])
    )
  })

  it('opens app.asar and scans its actual archived files', async () => {
    const root = await mkdtemp(join(tmpdir(), 'nachuan-release-asar-gate-'))
    workdirs.push(root)
    const source = join(root, 'asar-source')
    await mkdir(join(source, 'out', 'main'), { recursive: true })
    await writeFile(
      join(source, 'out', 'main', 'config.json'),
      JSON.stringify({ oauth: { client_secret: 'must-not-enter-asar' } }),
      'utf8'
    )
    const archive = join(root, 'app.asar')
    await createSettledAsarPackage(source, archive)

    const findings = await scanReleasePaths([archive])

    expect(findings).toContainEqual(
      expect.objectContaining({
        code: 'NON_EMPTY_SECRET',
        field: 'client_secret',
        file: expect.stringContaining('app.asar!/')
      })
    )
  })

  it('does not treat model tokenizer metadata as a credential', async () => {
    const root = await mkdtemp(join(tmpdir(), 'nachuan-release-tokenizer-gate-'))
    workdirs.push(root)
    await writeFile(
      join(root, 'tokenizer.json'),
      JSON.stringify({
        unk_token: '[UNK]',
        bos_token: '<s>',
        eos_token: '</s>',
        publicKeyToken: 'b77a5c561934e089'
      }),
      'utf8'
    )

    expect(await scanReleasePaths([root])).toEqual([])
  })

  it('does not treat source-code token object references as embedded credentials', async () => {
    const root = await mkdtemp(join(tmpdir(), 'nachuan-release-code-token-'))
    workdirs.push(root)
    await writeFile(
      join(root, 'updater.js'),
      [
        'this.cancellationToken = options.cancellationToken',
        'const bootToken = process.env.NACHUAN_ENGINE_BOOT_TOKEN',
        'exports.CancellationToken = CancellationToken',
        'config.api_key = source.api_key'
      ].join('\n'),
      'utf8'
    )
    await writeFile(
      join(root, 'engine.exe'),
      Buffer.from(
        '\u0000publicKeyToken=publicKeyToken\u0000cookie=localized_value_1\u0000' +
          'USE_CREDENTIALS="feature-switch"\u0000consume_token=value_1\u0000'
      )
    )

    expect(await scanReleasePaths([root])).toEqual([])
  })

  it('rejects local code-index installers and toolchain directories from distributables', async () => {
    const root = await mkdtemp(join(tmpdir(), 'nachuan-release-local-toolchain-'))
    workdirs.push(root)
    const installer = join(root, '.cbm', 'bin', 'install.ps1')
    await mkdir(dirname(installer), { recursive: true })
    await writeFile(installer, 'Write-Host "must never ship"\n', 'utf8')

    const findings = await scanReleasePaths([root])

    expect(findings).toContainEqual(
      expect.objectContaining({ code: 'NON_PRODUCTION_WORKFLOW', file: join(root, '.cbm') })
    )
  })

  it('rejects private-key file extensions, complete private-key blocks, and provider tokens without echoing bytes', async () => {
    const root = await mkdtemp(join(tmpdir(), 'nachuan-release-private-key-'))
    workdirs.push(root)
    await writeFile(join(root, 'signing.pfx'), Buffer.from([0x30, 0x82, 0x01, 0x02]))
    await writeFile(
      join(root, 'payload.bin'),
      Buffer.from(
        'prefix\u0000-----BEGIN OPENSSH ' + 'PRIVATE KEY-----\n' +
          'A'.repeat(96) +
          '\n-----END OPENSSH PRIVATE KEY-----\u0000dummy\u0000'
      )
    )
    await writeFile(join(root, 'token.txt'), 'provider=sk-AbCdEf0123456789_ZyxWvu\n', 'utf8')

    const findings = await scanReleasePaths([root])

    expect(findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: 'SENSITIVE_KEY_FILE', file: join(root, 'signing.pfx') }),
        expect.objectContaining({ code: 'EMBEDDED_SECRET', field: 'private_key_marker' }),
        expect.objectContaining({ code: 'TEXT_SECRET', field: 'provider_token' })
      ])
    )
    expect(JSON.stringify(findings)).not.toContain('dummy')
  })

  it('ignores generated token prefixes, localized credential prose, and OpenSSH parser literals', async () => {
    const root = await mkdtemp(join(tmpdir(), 'nachuan-release-secret-negative-'))
    workdirs.push(root)
    await writeFile(
      join(root, 'bundle.js'),
      [
        "const keyPattern = /^sk-nachuan-weixin-[0-9a-f]{64}$/",
        'const runtimeKey = `sk-nachuan-weixin-${randomBytes(32)}`',
        'const locale = { orphanCredential: "检测到已存凭据；它不会被沿用，断开后将删除。" }'
      ].join('\n'),
      'utf8'
    )
    await writeFile(
      join(root, 'parser.exe'),
      Buffer.from(
        '\u0000sk-ssh-ed25519@openssh.com\u0000sk-ecdsa-sha2-nistp256@openssh.com\u0000' +
          '-----BEGIN OPENSSH ' + 'PRIVATE KEY-----\u0000parser marker only\u0000' +
          '-----END OPENSSH PRIVATE KEY-----\u0000'
      )
    )

    expect(await scanReleasePaths([root])).toEqual([])
  })

  it('exits non-zero without echoing the secret when an existing artifact is unsafe', async () => {
    const root = await mkdtemp(join(tmpdir(), 'nachuan-release-gate-cli-'))
    workdirs.push(root)
    const secret = 'never-print-this-release-secret'
    await writeFile(join(root, 'seed-connections.json'), JSON.stringify({ api_key: secret }), 'utf8')

    const result = spawnSync(process.execPath, [script, 'scan', root], { encoding: 'utf8' })

    expect(result.status).toBe(1)
    expect(result.stdout).toContain('NON_EMPTY_SECRET')
    expect(result.stdout).not.toContain(secret)
  })

  it('always emits an empty packaged seed even when the local source contains keys', async () => {
    const root = await mkdtemp(join(tmpdir(), 'nachuan-release-seed-'))
    workdirs.push(root)
    const source = join(root, 'connections.json')
    const destination = join(root, 'dist', 'seed-connections.json')
    await writeFile(source, JSON.stringify({ provider: { api_key: 'local-only-secret' } }), 'utf8')

    await prepareConnectionSeed({ source, destination, variant: 'full' })

    expect(JSON.parse(await readFile(destination, 'utf8'))).toEqual({})
    expect(JSON.parse(await readFile(source, 'utf8'))).toEqual({
      provider: { api_key: 'local-only-secret' }
    })
  })
})
