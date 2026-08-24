import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, describe, expect, it } from 'vitest'

import {
  loadOrCreateApprovalKey,
  loadOrCreatePaidMediaKey,
  SecureConfigError,
  hardenLocalSecretAcl,
  loadOrCreateEngineKey,
  readSecureConfig,
  writeSecureConfig,
  type SafeStringStorage
} from './secure-config'

const roots: string[] = []
const noAcl = (): void => undefined
const fakeStorage: SafeStringStorage = {
  isEncryptionAvailable: () => true,
  encryptString: (value) =>
    Buffer.from(Buffer.from(value, 'utf8').map((byte) => byte ^ 0xa5)),
  decryptString: (value) =>
    Buffer.from(Buffer.from(value).map((byte) => byte ^ 0xa5)).toString('utf8')
}
const paidMediaKeyA =
  'sk-paid-media-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
const paidMediaKeyB =
  'sk-paid-media-abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789'
const paidMediaKeyC =
  'sk-paid-media-1111111111111111111111111111111111111111111111111111111111111111'
const paidMediaKeyD =
  'sk-paid-media-2222222222222222222222222222222222222222222222222222222222222222'

function testPath(): string {
  const root = mkdtempSync(join(tmpdir(), 'nachuan-electron-secrets-'))
  roots.push(root)
  return join(root, 'config.json')
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true })
})

describe('Electron secure local config', () => {
  it('roundtrips an encrypted envelope without writing plaintext secrets', () => {
    const path = testPath()
    const config = { engineKey: 'sk-local-synthetic', updateToken: 'github-synthetic' }

    writeSecureConfig(path, config, fakeStorage, noAcl)

    const raw = readFileSync(path, 'utf8')
    expect(raw).not.toContain(config.engineKey)
    expect(raw).not.toContain(config.updateToken)
    expect(JSON.parse(raw)).toMatchObject({
      schema: 'nachuan.electron-secret-config.v1',
      protection: 'electron-safe-storage'
    })
    expect(readSecureConfig(path, fakeStorage, noAcl)).toEqual(config)
  })

  it('migrates legacy plaintext by revoking every locally cached bearer value', () => {
    const path = testPath()
    writeFileSync(
      path,
      JSON.stringify({
        engineKey: 'legacy-engine',
        approvalKey: 'legacy-approval',
        updateToken: 'legacy-update'
      })
    )

    expect(readSecureConfig(path, fakeStorage, noAcl)).toEqual({})
    const raw = readFileSync(path, 'utf8')
    expect(raw).not.toContain('legacy-engine')
    expect(raw).not.toContain('legacy-approval')
    expect(raw).not.toContain('legacy-update')
    expect(readSecureConfig(path, fakeStorage, noAcl)).toEqual({})
  })

  it('mints a new engine key instead of reusing a legacy plaintext key', () => {
    const path = testPath()
    writeFileSync(path, JSON.stringify({ engineKey: 'legacy-engine' }))

    expect(loadOrCreateEngineKey(path, fakeStorage, () => 'fresh-engine', noAcl)).toBe(
      'fresh-engine'
    )
    expect(readSecureConfig(path, fakeStorage, noAcl)).toEqual({ engineKey: 'fresh-engine' })
    expect(readFileSync(path, 'utf8')).not.toContain('legacy-engine')
  })

  it('fails closed for corrupt config or unavailable OS encryption', () => {
    const path = testPath()
    writeFileSync(path, '{not-json')
    expect(() => readSecureConfig(path, fakeStorage, noAcl)).toThrow(SecureConfigError)
    expect(() =>
      writeSecureConfig(
        path,
        { engineKey: 'never-write-plaintext' },
        { ...fakeStorage, isEncryptionAvailable: () => false },
        noAcl
      )
    ).toThrow(SecureConfigError)
  })

  it('creates one engine key and reuses the protected value', () => {
    const path = testPath()
    let generated = 0
    const makeKey = (): string => `sk-local-generated-${++generated}`

    expect(loadOrCreateEngineKey(path, fakeStorage, makeKey, noAcl)).toBe('sk-local-generated-1')
    expect(loadOrCreateEngineKey(path, fakeStorage, makeKey, noAcl)).toBe('sk-local-generated-1')
    expect(generated).toBe(1)
  })

  it('keeps approval authority encrypted and independent from runtime access', () => {
    const path = testPath()
    const runtime = loadOrCreateEngineKey(path, fakeStorage, () => 'runtime-key', noAcl)
    let generated = 0
    const approval = loadOrCreateApprovalKey(
      path,
      fakeStorage,
      runtime,
      () => `approval-key-${++generated}`,
      noAcl
    )
    expect(approval).toBe('approval-key-1')
    expect(loadOrCreateApprovalKey(path, fakeStorage, runtime, () => 'unused', noAcl)).toBe(
      approval
    )
    expect(readFileSync(path, 'utf8')).not.toContain(approval)
  })

  it('creates, encrypts, and reuses an independent paid-media capability', () => {
    const path = testPath()
    const runtimeKey = 'runtime-key'
    const approvalKey = 'approval-key'
    const generatedKey = paidMediaKeyA
    let generated = 0

    expect(
      loadOrCreatePaidMediaKey(
        path,
        fakeStorage,
        runtimeKey,
        approvalKey,
        () => {
          generated += 1
          return generatedKey
        },
        noAcl
      )
    ).toBe(generatedKey)
    expect(
      loadOrCreatePaidMediaKey(
        path,
        fakeStorage,
        runtimeKey,
        approvalKey,
        () => paidMediaKeyB,
        noAcl
      )
    ).toBe(generatedKey)
    expect(generated).toBe(1)
    expect(readFileSync(path, 'utf8')).not.toContain(generatedKey)
    expect(readSecureConfig(path, fakeStorage, noAcl)).toEqual({ paidMediaKey: generatedKey })
  })

  it('rotates an existing paid-media capability that overlaps runtime access', () => {
    const path = testPath()
    const runtimeKey = 'runtime-key'
    const replacement = paidMediaKeyC
    writeSecureConfig(path, { paidMediaKey: runtimeKey }, fakeStorage, noAcl)

    expect(
      loadOrCreatePaidMediaKey(
        path,
        fakeStorage,
        runtimeKey,
        'approval-key',
        () => replacement,
        noAcl
      )
    ).toBe(replacement)
    expect(readSecureConfig(path, fakeStorage, noAcl)).toEqual({ paidMediaKey: replacement })
  })

  it('rotates an existing paid-media capability that overlaps approval authority', () => {
    const path = testPath()
    const approvalKey = 'approval-key'
    const replacement = paidMediaKeyD
    writeSecureConfig(path, { paidMediaKey: approvalKey }, fakeStorage, noAcl)

    expect(
      loadOrCreatePaidMediaKey(
        path,
        fakeStorage,
        'runtime-key',
        approvalKey,
        () => replacement,
        noAcl
      )
    ).toBe(replacement)
    expect(readSecureConfig(path, fakeStorage, noAcl)).toEqual({ paidMediaKey: replacement })
  })

  it("rotates an existing paid-media capability outside the gateway's lowercase-hex contract", () => {
    const path = testPath()
    const replacement = paidMediaKeyB
    writeSecureConfig(
      path,
      { paidMediaKey: 'pmk_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG' },
      fakeStorage,
      noAcl
    )

    expect(
      loadOrCreatePaidMediaKey(
        path,
        fakeStorage,
        'runtime-key',
        'approval-key',
        () => replacement,
        noAcl
      )
    ).toBe(replacement)
    expect(readSecureConfig(path, fakeStorage, noAcl)).toEqual({ paidMediaKey: replacement })
  })

  it('fails closed without rewriting config when the paid-media key generator is weak', () => {
    const path = testPath()
    const original = { engineKey: 'preserve-runtime-record', paidMediaKey: 'legacy-invalid' }
    writeSecureConfig(path, original, fakeStorage, noAcl)

    expect(() =>
      loadOrCreatePaidMediaKey(
        path,
        fakeStorage,
        'runtime-key',
        'approval-key',
        () => 'not-a-256-bit-key',
        noAcl
      )
    ).toThrow(SecureConfigError)
    expect(readSecureConfig(path, fakeStorage, noAcl)).toEqual(original)
  })

  it('fails closed when a newly generated paid-media key overlaps runtime access', () => {
    const path = testPath()
    const runtimeKey = paidMediaKeyA

    expect(() =>
      loadOrCreatePaidMediaKey(
        path,
        fakeStorage,
        runtimeKey,
        'approval-key',
        () => runtimeKey,
        noAcl
      )
    ).toThrow(SecureConfigError)
    expect(readSecureConfig(path, fakeStorage, noAcl)).toEqual({})
  })

  it('fails closed when a newly generated paid-media key overlaps approval authority', () => {
    const path = testPath()
    const approvalKey = paidMediaKeyB

    expect(() =>
      loadOrCreatePaidMediaKey(
        path,
        fakeStorage,
        'runtime-key',
        approvalKey,
        () => approvalKey,
        noAcl
      )
    ).toThrow(SecureConfigError)
    expect(readSecureConfig(path, fakeStorage, noAcl)).toEqual({})
  })

  it('applies the real current-user plus SYSTEM ACL contract on Windows', () => {
    if (process.platform !== 'win32') return
    const path = testPath()
    writeFileSync(path, '{}')

    hardenLocalSecretAcl(path, false)
  }, 75_000)
})
