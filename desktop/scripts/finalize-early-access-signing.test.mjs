import { generateKeyPairSync, sign } from 'node:crypto'
import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'

import { loadEarlyAccessSigningInputs } from './finalize-early-access.mjs'
import { canonicalUpdateKeyring } from './update-envelope.mjs'

const roots = []

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true })
})

function fixture() {
  const workspace = mkdtempSync(join(tmpdir(), 'nachuan-finalizer-signing-'))
  roots.push(workspace)
  const root = generateKeyPairSync('ed25519')
  const leafA = generateKeyPairSync('ed25519')
  const leafB = generateKeyPairSync('ed25519')
  const leafAPath = join(workspace, 'nachuan-leaf-0.pem')
  const leafBPath = join(workspace, 'nachuan-leaf-1.pem')
  const rootAuthorizationPath = join(workspace, 'nachuan-root-authorization.json')
  const signingKeysPath = join(workspace, 'nachuan-leaf-signing-keys.json')
  writeFileSync(leafAPath, leafA.privateKey.export({ format: 'pem', type: 'pkcs8' }))
  writeFileSync(leafBPath, leafB.privateKey.export({ format: 'pem', type: 'pkcs8' }))
  const keyring = {
    schema: 1,
    channel: 'early-access-lean-win-x64',
    variant: 'lean',
    sequence: 7,
    threshold: 2,
    keys: [
      {
        keyId: 'early-leaf-a',
        publicKeySpkiBase64: leafA.publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
        notBeforeSequence: 7,
        notAfterSequence: 20
      },
      {
        keyId: 'early-leaf-b',
        publicKeySpkiBase64: leafB.publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
        notBeforeSequence: 7,
        notAfterSequence: 20
      }
    ]
  }
  writeFileSync(
    rootAuthorizationPath,
    `${JSON.stringify({
      schema: 1,
      keyring,
      keyringSignature: {
        algorithm: 'Ed25519',
        keyId: 'early-root-2026-01',
        value: sign(null, Buffer.from(canonicalUpdateKeyring(keyring)), root.privateKey).toString('base64')
      }
    })}\n`
  )
  writeFileSync(
    signingKeysPath,
    `${JSON.stringify({
      schema: 1,
      signingKeys: [
        { keyId: 'early-leaf-a', privateKeyPath: leafAPath },
        { keyId: 'early-leaf-b', privateKeyPath: leafBPath }
      ]
    })}\n`
  )
  return { workspace, rootAuthorizationPath, signingKeysPath, leafAPath, leafBPath }
}

function signingEnv(fixture, extra = {}) {
  return {
    RUNNER_TEMP: fixture.workspace,
    NACHUAN_UPDATE_KEY_ID: 'early-root-2026-01',
    NACHUAN_UPDATE_ROOT_AUTHORIZATION_FILE: fixture.rootAuthorizationPath,
    NACHUAN_UPDATE_LEAF_SIGNING_KEYS_FILE: fixture.signingKeysPath,
    NACHUAN_UPDATE_LEAF_PRIVATE_KEY_PASSPHRASE: 'leaf-passphrase',
    ...extra
  }
}

describe('early-access finalizer signing inputs', () => {
  it('loads a pre-signed root authorization and a threshold of distinct leaf private keys', () => {
    const inputs = fixture()

    expect(
      loadEarlyAccessSigningInputs(signingEnv(inputs))
    ).toMatchObject({
      keyId: 'early-leaf-a',
      passphrase: 'leaf-passphrase',
      signingKeys: [{ keyId: 'early-leaf-a' }, { keyId: 'early-leaf-b' }],
      rootAuthorization: {
        schema: 1,
        keyring: { threshold: 2 },
        keyringSignature: { keyId: 'early-root-2026-01' }
      }
    })
  })

  it('rejects any root private key material in the online finalizer environment', () => {
    const inputs = fixture()

    expect(() =>
      loadEarlyAccessSigningInputs(signingEnv(inputs, {
        NACHUAN_UPDATE_ROOT_PRIVATE_KEY_FILE: join(tmpdir(), 'root.pem')
      }))
    ).toThrow(/root private key.*must not/i)
  })

  it('rejects every legacy single-private-key environment variable', () => {
    const inputs = fixture()
    const base = signingEnv(inputs)

    for (const name of [
      'NACHUAN_UPDATE_PRIVATE_KEY_FILE',
      'NACHUAN_UPDATE_PRIVATE_KEY_PEM_BASE64',
      'NACHUAN_UPDATE_PRIVATE_KEY_PASSPHRASE'
    ]) {
      expect(() => loadEarlyAccessSigningInputs({ ...base, [name]: 'legacy-secret' })).toThrow(
        /legacy single-private-key.*must not/i
      )
    }
  })

  it('fails closed when the root authorization, leaf descriptor, or threshold signer is missing', () => {
    const inputs = fixture()
    const { signingKeysPath, leafAPath } = inputs
    const base = signingEnv(inputs)

    expect(() =>
      loadEarlyAccessSigningInputs({ ...base, NACHUAN_UPDATE_ROOT_AUTHORIZATION_FILE: '' })
    ).toThrow(/root authorization.*required/i)
    expect(() =>
      loadEarlyAccessSigningInputs({ ...base, NACHUAN_UPDATE_LEAF_SIGNING_KEYS_FILE: '' })
    ).toThrow(/leaf signing key descriptor.*required/i)

    writeFileSync(
      signingKeysPath,
      `${JSON.stringify({
        schema: 1,
        signingKeys: [{ keyId: 'early-leaf-a', privateKeyPath: leafAPath }]
      })}\n`
    )
    expect(() => loadEarlyAccessSigningInputs(base)).toThrow(/threshold was not met.*required=2 provided=1/i)
  })

  it('requires the passphrase for the encrypted leaf private keys', () => {
    const inputs = fixture()

    expect(() =>
      loadEarlyAccessSigningInputs(signingEnv(inputs, {
        NACHUAN_UPDATE_LEAF_PRIVATE_KEY_PASSPHRASE: ''
      }))
    ).toThrow(/leaf private key passphrase.*required/i)
  })

  it('requires the exact fixed root and descriptor slots under RUNNER_TEMP', () => {
    const inputs = fixture()

    expect(() => loadEarlyAccessSigningInputs(signingEnv(inputs, { RUNNER_TEMP: '' }))).toThrow(
      /RUNNER_TEMP.*required/i
    )
    expect(() =>
      loadEarlyAccessSigningInputs(
        signingEnv(inputs, {
          NACHUAN_UPDATE_ROOT_AUTHORIZATION_FILE: join(inputs.workspace, 'other-root.json')
        })
      )
    ).toThrow(/fixed RUNNER_TEMP.*root authorization|root authorization.*fixed RUNNER_TEMP/i)
  })

  it('rejects a descriptor that redirects a leaf key outside the fixed RUNNER_TEMP slots', () => {
    const inputs = fixture()
    const outsideRoot = mkdtempSync(join(tmpdir(), 'nachuan-outside-leaf-'))
    roots.push(outsideRoot)
    const outsideLeaf = join(outsideRoot, 'nachuan-leaf-0.pem')
    writeFileSync(outsideLeaf, 'outside-key-material')
    writeFileSync(
      inputs.signingKeysPath,
      `${JSON.stringify({
        schema: 1,
        signingKeys: [
          { keyId: 'early-leaf-a', privateKeyPath: outsideLeaf },
          { keyId: 'early-leaf-b', privateKeyPath: inputs.leafBPath }
        ]
      })}\n`
    )

    expect(() => loadEarlyAccessSigningInputs(signingEnv(inputs))).toThrow(
      /fixed RUNNER_TEMP.*leaf|leaf.*fixed RUNNER_TEMP/i
    )
  })

  it('rejects a RUNNER_TEMP reached through a junction before reading signing files', () => {
    const inputs = fixture()
    const aliasParent = mkdtempSync(join(tmpdir(), 'nachuan-runner-alias-'))
    roots.push(aliasParent)
    const alias = join(aliasParent, 'runner-temp')
    symlinkSync(inputs.workspace, alias, 'junction')

    expect(() =>
      loadEarlyAccessSigningInputs(
        signingEnv(inputs, {
          RUNNER_TEMP: alias,
          NACHUAN_UPDATE_ROOT_AUTHORIZATION_FILE: join(alias, 'nachuan-root-authorization.json'),
          NACHUAN_UPDATE_LEAF_SIGNING_KEYS_FILE: join(alias, 'nachuan-leaf-signing-keys.json')
        })
      )
    ).toThrow(/RUNNER_TEMP.*reparse|redirected through a reparse/i)
  })
})
