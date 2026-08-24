import { generateKeyPairSync, sign } from 'node:crypto'
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, describe, expect, it } from 'vitest'

import {
  loadProductionSigningInputs,
  materializeProductionLeafSigningKeys,
  prepareProductionRootAuthorization
} from './production-update-envelope.mjs'
import { canonicalUpdateKeyring } from './update-envelope.mjs'

const roots = []

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true })
})

function fixture({ channel = 'production-lean-win-x64', threshold = 2, encryptedLeaves = true } = {}) {
  const workspace = mkdtempSync(join(tmpdir(), 'nachuan-production-envelope-'))
  roots.push(workspace)
  const root = generateKeyPairSync('ed25519')
  const leafA = generateKeyPairSync('ed25519')
  const leafB = generateKeyPairSync('ed25519')
  const leafAPath = join(workspace, 'leaf-a.pem')
  const leafBPath = join(workspace, 'leaf-b.pem')
  const authorizationPath = join(workspace, 'production-root-authorization.json')
  const descriptorPath = join(workspace, 'production-leaf-descriptor.json')
  const leafPem = (privateKey) =>
    privateKey.export({
      format: 'pem',
      type: 'pkcs8',
      ...(encryptedLeaves
        ? { cipher: 'aes-256-cbc', passphrase: 'production-leaf-passphrase' }
        : {})
    })
  writeFileSync(leafAPath, leafPem(leafA.privateKey))
  writeFileSync(leafBPath, leafPem(leafB.privateKey))
  const keyring = {
    schema: 1,
    channel,
    variant: 'lean',
    sequence: 8,
    threshold,
    keys: [
      {
        keyId: 'production-leaf-a',
        publicKeySpkiBase64: leafA.publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
        notBeforeSequence: 10,
        notAfterSequence: 100
      },
      {
        keyId: 'production-leaf-b',
        publicKeySpkiBase64: leafB.publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
        notBeforeSequence: 10,
        notAfterSequence: 100
      }
    ]
  }
  writeFileSync(
    authorizationPath,
    `${JSON.stringify({
      schema: 1,
      keyring,
      keyringSignature: {
        algorithm: 'Ed25519',
        keyId: 'production-root-2026-01',
        value: sign(null, Buffer.from(canonicalUpdateKeyring(keyring)), root.privateKey).toString('base64')
      }
    })}\n`
  )
  writeFileSync(
    descriptorPath,
    `${JSON.stringify({
      schema: 1,
      signingKeys: [
        { keyId: 'production-leaf-b', privateKeyPath: leafBPath },
        { keyId: 'production-leaf-a', privateKeyPath: leafAPath }
      ]
    })}\n`
  )
  return {
    authorizationPath,
    descriptorPath,
    leafA,
    leafB,
    publicKeySpkiBase64: root.publicKey.export({ format: 'der', type: 'spki' }).toString('base64')
  }
}

function environment(value) {
  return {
    DMX_VARIANT: 'lean',
    NACHUAN_PRODUCTION_UPDATE_CHANNEL: 'production-lean-win-x64',
    NACHUAN_PRODUCTION_UPDATE_KEY_ID: 'production-root-2026-01',
    NACHUAN_PRODUCTION_UPDATE_PUBLIC_KEY_SPKI_BASE64: value.publicKeySpkiBase64,
    NACHUAN_PRODUCTION_UPDATE_ROOT_AUTHORIZATION_FILE: value.authorizationPath,
    NACHUAN_PRODUCTION_UPDATE_LEAF_SIGNING_KEYS_FILE: value.descriptorPath,
    NACHUAN_PRODUCTION_UPDATE_LEAF_PRIVATE_KEY_PASSPHRASE: 'production-leaf-passphrase'
  }
}

describe('production schema2 update signing inputs', () => {
  it('accepts only the production root authorization and a distinct 2-leaf threshold', () => {
    const value = fixture()
    expect(loadProductionSigningInputs(environment(value))).toMatchObject({
      channel: 'production-lean-win-x64',
      keyId: 'production-leaf-a',
      rootKeyId: 'production-root-2026-01',
      signingKeys: [
        { keyId: 'production-leaf-a' },
        { keyId: 'production-leaf-b' }
      ],
      rootAuthorization: { keyring: { threshold: 2 } }
    })
  })

  it('rejects early authorization coordinates and every root or legacy private-key path', () => {
    const early = fixture({ channel: 'early-access-lean-win-x64' })
    expect(() => loadProductionSigningInputs(environment(early))).toThrow(/production.*channel/i)

    const value = fixture()
    const base = environment(value)
    for (const name of [
      'NACHUAN_PRODUCTION_UPDATE_ROOT_PRIVATE_KEY_FILE',
      'NACHUAN_UPDATE_ROOT_PRIVATE_KEY_FILE',
      'NACHUAN_UPDATE_PRIVATE_KEY_FILE',
      'NACHUAN_UPDATE_PRIVATE_KEY_PEM_BASE64'
    ]) {
      expect(() => loadProductionSigningInputs({ ...base, [name]: 'forbidden' })).toThrow(
        /private key.*must not|legacy.*must not/i
      )
    }
  })

  it('fails closed below a two-leaf production threshold', () => {
    const value = fixture({ threshold: 1 })
    expect(() => loadProductionSigningInputs(environment(value))).toThrow(/production.*threshold.*at least 2/i)
  })

  it('rejects a hand-written descriptor that bypasses encrypted leaf materialization', () => {
    const value = fixture({ encryptedLeaves: false })
    expect(() => loadProductionSigningInputs(environment(value))).toThrow(/encrypted PKCS#8 PEM/i)
  })

  it('materializes authorized encrypted leaves in canonical order only after public root verification', async () => {
    const value = fixture()
    const outputDirectory = join(value.authorizationPath, '..', 'materialized')
    mkdirSync(outputDirectory)
    const prepared = await prepareProductionRootAuthorization({
      authorizationBase64: readFileSync(value.authorizationPath).toString('base64'),
      rootKeyId: 'production-root-2026-01',
      publicKeySpkiBase64: value.publicKeySpkiBase64,
      channel: 'production-lean-win-x64',
      variant: 'lean',
      outputDirectory
    })
    expect(prepared).toMatchObject({ keyringSequence: 8 })
    expect(prepared.keyringSha256).toMatch(/^[0-9a-f]{64}$/)

    const encryptedPem = (privateKey) =>
      Buffer.from(
        privateKey.export({
          format: 'pem',
          type: 'pkcs8',
          cipher: 'aes-256-cbc',
          passphrase: 'production-leaf-passphrase'
        }),
        'utf8'
      )
    const bundle = {
      schema: 1,
      signingKeys: [
        {
          keyId: 'production-leaf-b',
          privateKeyPemBase64: encryptedPem(value.leafB.privateKey).toString('base64')
        },
        {
          keyId: 'production-leaf-a',
          privateKeyPemBase64: encryptedPem(value.leafA.privateKey).toString('base64')
        }
      ]
    }
    const materialized = await materializeProductionLeafSigningKeys({
      rootAuthorizationPath: prepared.path,
      rootKeyId: 'production-root-2026-01',
      publicKeySpkiBase64: value.publicKeySpkiBase64,
      channel: 'production-lean-win-x64',
      variant: 'lean',
      bundleBase64: Buffer.from(JSON.stringify(bundle)).toString('base64'),
      outputDirectory
    })
    const descriptor = JSON.parse(readFileSync(materialized.descriptorPath, 'utf8'))
    expect(descriptor.signingKeys.map(({ keyId }) => keyId)).toEqual([
      'production-leaf-a',
      'production-leaf-b'
    ])
    expect(materialized.privateKeyPaths).toHaveLength(2)
    for (const path of materialized.privateKeyPaths) {
      expect(readFileSync(path, 'ascii')).toMatch(/^-----BEGIN ENCRYPTED PRIVATE KEY-----\n/)
    }
  })

  it('removes every partially materialized leaf when a later bundle entry is not encrypted', async () => {
    const value = fixture()
    const outputDirectory = join(value.authorizationPath, '..', 'partial-materialization')
    mkdirSync(outputDirectory)
    const encryptedA = Buffer.from(
      value.leafA.privateKey.export({
        format: 'pem',
        type: 'pkcs8',
        cipher: 'aes-256-cbc',
        passphrase: 'production-leaf-passphrase'
      }),
      'utf8'
    )
    const bundle = {
      schema: 1,
      signingKeys: [
        { keyId: 'production-leaf-a', privateKeyPemBase64: encryptedA.toString('base64') },
        {
          keyId: 'production-leaf-b',
          privateKeyPemBase64: Buffer.from(
            value.leafB.privateKey.export({ format: 'pem', type: 'pkcs8' }),
            'utf8'
          ).toString('base64')
        }
      ]
    }
    await expect(
      materializeProductionLeafSigningKeys({
        rootAuthorizationPath: value.authorizationPath,
        rootKeyId: 'production-root-2026-01',
        publicKeySpkiBase64: value.publicKeySpkiBase64,
        channel: 'production-lean-win-x64',
        variant: 'lean',
        bundleBase64: Buffer.from(JSON.stringify(bundle)).toString('base64'),
        outputDirectory
      })
    ).rejects.toThrow(/encrypted PKCS#8 PEM/)
    expect(readdirSync(outputDirectory)).toEqual([])
  })
})
