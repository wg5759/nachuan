import { createHash } from 'node:crypto'
import { mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { describe, expect, it } from 'vitest'

import {
  SupportBundleError,
  createInstalledSupportBundle,
  createSupportBundle
} from './support-bundle'

const sha256 = (value: string): string =>
  createHash('sha256').update(value).digest('hex')

async function fixture(): Promise<{
  auditLog: string
  installRoot: string
  outputRoot: string
}> {
  const root = await mkdtemp(join(tmpdir(), 'nachuan-support-bundle-'))
  const installRoot = join(root, 'install')
  const outputRoot = join(root, 'output')
  const resources = join(installRoot, 'resources')
  await mkdir(join(resources, 'engine'), { recursive: true })
  await mkdir(outputRoot, { recursive: true })
  await writeFile(join(installRoot, 'Nachuan.exe'), 'desktop-final-bytes')
  await writeFile(join(resources, 'app.asar'), 'asar-final-bytes')
  await writeFile(join(resources, 'engine', 'engine.exe'), 'engine-final-bytes')
  await writeFile(join(resources, 'local-runtime-manifest.json'), '{"local":true}\n')
  await writeFile(join(resources, 'media-runtime-manifest.json'), '{"media":true}\n')
  const auditLog = join(root, 'desktop-main.jsonl')
  await writeFile(
    auditLog,
    [
      JSON.stringify({
        ts: '2026-07-18T01:02:03.000Z',
        event: 'engine.ready',
        token: 'audit-token-must-not-escape',
        prompt: 'customer-message-must-not-escape'
      }),
      JSON.stringify({
        ts: '2026-07-18T01:03:03.000Z',
        event: 'engine.ready',
        authorization: 'Bearer audit-bearer-must-not-escape'
      }),
      '{"event":"broken","secret":"malformed-secret-must-not-escape"'
    ].join('\n') + '\n',
    'utf8'
  )
  return { auditLog, installRoot, outputRoot }
}

describe('redacted support bundle', () => {
  it('exports only closed health fields, core hashes and aggregate audit events', async () => {
    const item = await fixture()
    const result = await createSupportBundle({
      installRoot: item.installRoot,
      outputRoot: item.outputRoot,
      version: '1.2.3',
      runtimeProfile: 'store',
      now: () => new Date('2026-07-18T02:03:04.000Z'),
      nonce: () => '0011223344556677',
      artifacts: [
        { kind: 'desktop-executable', relativePath: 'Nachuan.exe' },
        { kind: 'app-asar', relativePath: 'resources/app.asar' },
        { kind: 'engine-executable', relativePath: 'resources/engine/engine.exe' }
      ],
      auditLogPath: item.auditLog,
      health: {
        status: 'ok',
        readiness: 'degraded',
        pid: 4321,
        boot_proof: 'boot-proof-must-not-escape',
        injected_secret: 'health-secret-must-not-escape',
        checks: {
          database: {
            ready: false,
            checked: 9,
            failed: ['customer-account.db', 'secret-ledger.db']
          },
          connection_store: {
            ready: false,
            quarantined: ['customer-private-provider-name']
          },
          providers: {
            ready: true,
            count: 4,
            external_count: 3,
            model_count: 12,
            models: ['private-model-name']
          },
          weixin: {
            configured: true,
            state: 'healthy',
            fresh: true,
            ready: true,
            age_sec: 2,
            pending_inbound: 0,
            pending_outbound: 0,
            dead_inbound: 0,
            dead_outbound: 0,
            owner: 'private-weixin-owner'
          }
        }
      }
    })

    expect(result.path).toBe(
      join(item.outputRoot, 'nachuan-support-20260718T020304000Z-0011223344556677.json')
    )
    const raw = await readFile(result.path, 'utf8')
    for (const forbidden of [
      'audit-token-must-not-escape',
      'customer-message-must-not-escape',
      'audit-bearer-must-not-escape',
      'malformed-secret-must-not-escape',
      'boot-proof-must-not-escape',
      'health-secret-must-not-escape',
      'customer-account.db',
      'secret-ledger.db',
      'customer-private-provider-name',
      'private-model-name',
      'private-weixin-owner'
    ]) {
      expect(raw).not.toContain(forbidden)
    }

    const bundle = JSON.parse(raw)
    expect(Object.keys(bundle)).toEqual([
      'schema',
      'createdAt',
      'product',
      'health',
      'artifacts',
      'audit',
      'privacy',
      'integrity'
    ])
    expect(bundle.health).toMatchObject({
      available: true,
      status: 'ok',
      readiness: 'degraded',
      checks: {
        database: { ready: false, checked: 9, failedCount: 2 },
        connectionStore: { ready: false, quarantinedCount: 1 },
        providers: { ready: true, count: 4, externalCount: 3, modelCount: 12 },
        weixin: {
          configured: true,
          state: 'healthy',
          fresh: true,
          ready: true,
          ageSec: 2,
          pendingInbound: 0,
          pendingOutbound: 0,
          deadInbound: 0,
          deadOutbound: 0
        }
      }
    })
    expect(bundle.audit).toEqual({
      available: true,
      invalidLineCount: 1,
      lineCount: 3,
      events: [
        {
          count: 2,
          event: 'engine.ready',
          lastAt: '2026-07-18T01:03:03.000Z'
        }
      ]
    })
    expect(bundle.artifacts).toEqual([
      {
        kind: 'app-asar',
        path: 'resources/app.asar',
        sha256: sha256('asar-final-bytes'),
        size: 16
      },
      {
        kind: 'desktop-executable',
        path: 'Nachuan.exe',
        sha256: sha256('desktop-final-bytes'),
        size: 19
      },
      {
        kind: 'engine-executable',
        path: 'resources/engine/engine.exe',
        sha256: sha256('engine-final-bytes'),
        size: 18
      }
    ])
    expect(bundle.privacy).toEqual({
      auditFieldsIncluded: false,
      businessDataIncluded: false,
      databasesIncluded: false,
      localPathsIncluded: false,
      rawLogsIncluded: false,
      secretsIncluded: false
    })
    const { integrity, ...payload } = bundle
    expect(integrity).toEqual({
      algorithm: 'sha256',
      payloadSha256: sha256(`${JSON.stringify(payload)}\n`)
    })
  })

  it('rejects artifacts outside the installation root before reading them', async () => {
    const item = await fixture()
    const outside = join(item.installRoot, '..', 'outside-secret.txt')
    await writeFile(outside, 'must-not-hash')

    await expect(
      createSupportBundle({
        installRoot: item.installRoot,
        outputRoot: item.outputRoot,
        version: '1.2.3',
        runtimeProfile: 'store',
        artifacts: [{ kind: 'app-asar', relativePath: '../outside-secret.txt' }]
      })
    ).rejects.toBeInstanceOf(SupportBundleError)
  })

  it.each([
    'resources/app.asar:private-stream',
    'resources/app.asar ',
    'resources/CON.txt',
    'resources\\app.asar'
  ])('rejects unsafe Windows artifact path %s', async (relativePath) => {
    const item = await fixture()
    await expect(
      createSupportBundle({
        installRoot: item.installRoot,
        outputRoot: item.outputRoot,
        version: '1.2.3',
        runtimeProfile: 'store',
        artifacts: [{ kind: 'app-asar', relativePath }]
      })
    ).rejects.toBeInstanceOf(SupportBundleError)
  })

  it('rejects duplicate artifact kinds and non-canonical versions', async () => {
    const item = await fixture()
    await expect(
      createSupportBundle({
        installRoot: item.installRoot,
        outputRoot: item.outputRoot,
        version: '1.2.3-dev',
        runtimeProfile: 'store',
        artifacts: [
          { kind: 'app-asar', relativePath: 'resources/app.asar' },
          { kind: 'app-asar', relativePath: 'resources/engine/engine.exe' }
        ]
      })
    ).rejects.toBeInstanceOf(SupportBundleError)
  })

  it('derives the installed closed artifact set and degrades when health is offline', async () => {
    const item = await fixture()
    const userDataPath = join(item.outputRoot, 'user-data')
    await mkdir(userDataPath)
    const result = await createInstalledSupportBundle({
      isPackaged: true,
      executablePath: join(item.installRoot, 'Nachuan.exe'),
      resourcesPath: join(item.installRoot, 'resources'),
      userDataPath,
      version: '1.2.3',
      runtimeProfile: 'store',
      loadHealth: async () => {
        throw new Error('private engine diagnostics must not escape')
      },
      now: () => new Date('2026-07-18T04:05:06.000Z'),
      nonce: () => '8899aabbccddeeff'
    })
    const bundle = JSON.parse(await readFile(result.path, 'utf8'))
    expect(bundle.health).toEqual({
      available: false,
      reasonCode: 'health-unavailable',
      checks: {}
    })
    expect(bundle.artifacts.map((artifact: { kind: string }) => artifact.kind)).toEqual([
      'app-asar',
      'desktop-executable',
      'engine-executable',
      'engine-runtime-manifest',
      'media-runtime-manifest'
    ])
    expect(JSON.stringify(bundle)).not.toContain('private engine diagnostics')
  })

  it('does not create an installed bundle from a development process', async () => {
    const item = await fixture()
    await expect(
      createInstalledSupportBundle({
        isPackaged: false,
        executablePath: join(item.installRoot, 'Nachuan.exe'),
        resourcesPath: join(item.installRoot, 'resources'),
        userDataPath: item.outputRoot,
        version: '1.2.3',
        runtimeProfile: 'development',
        loadHealth: async () => ({ status: 'ok' })
      })
    ).rejects.toBeInstanceOf(SupportBundleError)
  })
})
