import { generateKeyPairSync } from 'node:crypto'
import { lstat, mkdtemp, readFile, realpath, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'

import {
  materializeUpdateTrustModule,
  renderUpdateTrustModule,
  updateTrustFromEnvironment
} from './write-update-trust.mjs'

const workdirs = []

afterEach(async () => {
  await Promise.all(workdirs.splice(0).map((path) => rm(path, { recursive: true, force: true })))
})

function identity(info) {
  return [info.dev, info.ino, info.size, info.mtimeNs, info.ctimeNs, info.birthtimeNs]
}

function publicKey() {
  return generateKeyPairSync('ed25519').publicKey.export({ format: 'der', type: 'spki' }).toString('base64')
}

describe('build-time update trust embedding', () => {
  it('supports a release check operation that leaves the generated trust module untouched', async () => {
    const root = await realpath(await mkdtemp(join(tmpdir(), 'nachuan-update-trust-')))
    workdirs.push(root)
    const output = join(root, 'generated-update-trust.ts')
    await materializeUpdateTrustModule({ output, env: {}, operation: 'write' })
    const beforeBytes = await readFile(output)
    const beforeIdentity = identity(await lstat(output, { bigint: true }))

    await expect(
      materializeUpdateTrustModule({ output, env: {}, operation: 'check' })
    ).resolves.toMatchObject({ operation: 'check' })
    expect(await readFile(output)).toEqual(beforeBytes)
    expect(identity(await lstat(output, { bigint: true }))).toEqual(beforeIdentity)
  })

  it('writes a disabled fail-closed trust object when no tier is configured', () => {
    expect(updateTrustFromEnvironment({})).toMatchObject({
      enabled: false,
      releaseTier: 'disabled',
      keyringSequence: 0,
      keyringSha256: ''
    })
  })

  it('renders the disabled default as the deterministic source-control template', () => {
    const source = renderUpdateTrustModule(updateTrustFromEnvironment({}))

    expect(source).toContain('Source-control template')
    expect(source).toContain('"enabled": false')
    expect(source).toContain('"releaseTier": "disabled"')
  })

  it('requires a complete HTTPS Ed25519 early-access trust boundary', () => {
    const trust = updateTrustFromEnvironment({
      NACHUAN_UPDATE_TIER: 'early-access',
      DMX_VARIANT: 'lean',
      NACHUAN_UPDATE_KEY_ID: 'early-2026-01',
      NACHUAN_UPDATE_PUBLIC_KEY_SPKI_BASE64: publicKey(),
      NACHUAN_UPDATE_MANIFEST_URL: 'https://updates.example.test/early-access-lean-win-x64.json',
      NACHUAN_UPDATE_SEQUENCE: '7',
      NACHUAN_UPDATE_KEYRING_SEQUENCE: '5',
      NACHUAN_UPDATE_KEYRING_SHA256: 'a'.repeat(64)
    })
    expect(trust).toMatchObject({
      enabled: true,
      releaseTier: 'early-access',
      channel: 'early-access-lean-win-x64',
      currentSequence: 7,
      keyringSequence: 5,
      keyringSha256: 'a'.repeat(64),
      publisherName: '',
      signerThumbprint: ''
    })
    expect(renderUpdateTrustModule(trust)).toContain('EMBEDDED_UPDATE_TRUST')
  })

  it('rejects HTTP, non-Ed25519 keys and incomplete production signer identity', () => {
    expect(() =>
      updateTrustFromEnvironment({
        NACHUAN_UPDATE_TIER: 'early-access',
        DMX_VARIANT: 'lean',
        NACHUAN_UPDATE_KEY_ID: 'early-2026-01',
        NACHUAN_UPDATE_PUBLIC_KEY_SPKI_BASE64: publicKey(),
        NACHUAN_UPDATE_MANIFEST_URL: 'http://updates.example.test/latest.json',
        NACHUAN_UPDATE_SEQUENCE: '1'
      })
    ).toThrow(/HTTPS/)
    expect(() =>
      updateTrustFromEnvironment({
        NACHUAN_UPDATE_TIER: 'production',
        DMX_VARIANT: 'lean',
        NACHUAN_UPDATE_KEY_ID: 'production-2026-01',
        NACHUAN_UPDATE_PUBLIC_KEY_SPKI_BASE64: publicKey(),
        NACHUAN_UPDATE_MANIFEST_URL: 'https://updates.example.test/latest.json',
        NACHUAN_UPDATE_SEQUENCE: '1'
      })
    ).toThrow(/publisher name and signer thumbprint/)
    expect(() =>
      updateTrustFromEnvironment({
        NACHUAN_UPDATE_TIER: 'early-access',
        DMX_VARIANT: 'lean',
        NACHUAN_UPDATE_KEY_ID: 'early-2026-01',
        NACHUAN_UPDATE_PUBLIC_KEY_SPKI_BASE64: publicKey(),
        NACHUAN_UPDATE_MANIFEST_URL: 'https://updates.example.test/latest.json',
        NACHUAN_UPDATE_SEQUENCE: '2',
        NACHUAN_UPDATE_KEYRING_SEQUENCE: '1'
      })
    ).toThrow(/KEYRING_SHA256/)
    expect(() =>
      updateTrustFromEnvironment({
        NACHUAN_UPDATE_TIER: 'early-access',
        DMX_VARIANT: 'lean',
        NACHUAN_UPDATE_KEY_ID: 'early-2026-01',
        NACHUAN_UPDATE_PUBLIC_KEY_SPKI_BASE64: publicKey(),
        NACHUAN_UPDATE_MANIFEST_URL: 'https://updates.example.test/latest.json',
        NACHUAN_UPDATE_SEQUENCE: '2',
        NACHUAN_UPDATE_KEYRING_SHA256: 'a'.repeat(64)
      })
    ).toThrow(/KEYRING_SEQUENCE.*KEYRING_SHA256|together/i)
  })
})
