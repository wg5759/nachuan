import { generateKeyPairSync, sign } from 'node:crypto'
import { mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, describe, expect, it } from 'vitest'

import {
  materializeLeafSigningKeys,
  materializeRootAuthorization
} from './materialize-early-access-signing-inputs.mjs'
import { canonicalUpdateKeyring } from './update-envelope.mjs'

const roots = []

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true })
})

function tempRoot(prefix) {
  const root = mkdtempSync(join(tmpdir(), prefix))
  roots.push(root)
  return root
}

function authorizationFixture() {
  const root = generateKeyPairSync('ed25519')
  const leaf = generateKeyPairSync('ed25519')
  const keyring = {
    schema: 1,
    channel: 'early-access-lean-win-x64',
    variant: 'lean',
    sequence: 5,
    threshold: 1,
    keys: [
      {
        keyId: 'early-leaf-a',
        publicKeySpkiBase64: leaf.publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
        notBeforeSequence: 5,
        notAfterSequence: 20
      }
    ]
  }
  const rootAuthorization = {
    schema: 1,
    keyring,
    keyringSignature: {
      algorithm: 'Ed25519',
      keyId: 'early-root-2026-01',
      value: sign(null, Buffer.from(canonicalUpdateKeyring(keyring)), root.privateKey).toString('base64')
    }
  }
  return { root, leaf, rootAuthorization }
}

describe('early-access signing input materialization', () => {
  it('materializes only fixed slots under a validated RUNNER_TEMP boundary', () => {
    const runnerTemp = tempRoot('nachuan-materializer-')
    const githubOutput = join(runnerTemp, 'github-output.txt')
    writeFileSync(githubOutput, '')
    const fixture = authorizationFixture()
    const rootResult = materializeRootAuthorization({
      runnerTemp,
      rootAuthorizationBase64: Buffer.from(JSON.stringify(fixture.rootAuthorization)).toString('base64'),
      expectedRootKeyId: 'early-root-2026-01',
      rootPublicKeySpkiBase64: fixture.root.publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
      githubOutput
    })
    const encryptedLeaf = fixture.leaf.privateKey.export({
      format: 'pem',
      type: 'pkcs8',
      cipher: 'aes-256-cbc',
      passphrase: 'test-passphrase'
    })
    const leafResult = materializeLeafSigningKeys({
      runnerTemp,
      rootAuthorizationFile: rootResult.rootAuthorizationFile,
      leafSigningKeysBundleBase64: Buffer.from(
        JSON.stringify({
          schema: 1,
          signingKeys: [
            { keyId: 'early-leaf-a', privateKeyPemBase64: Buffer.from(encryptedLeaf).toString('base64') }
          ]
        })
      ).toString('base64'),
      expectedRootKeyId: 'early-root-2026-01',
      githubOutput
    })

    expect(readdirSync(runnerTemp).sort()).toEqual([
      'github-output.txt',
      'nachuan-leaf-0.pem',
      'nachuan-leaf-signing-keys.json',
      'nachuan-root-authorization.json'
    ])
    expect(JSON.parse(readFileSync(leafResult.leafSigningKeysFile, 'utf8'))).toEqual({
      schema: 1,
      signingKeys: [
        { keyId: 'early-leaf-a', privateKeyPath: join(runnerTemp, 'nachuan-leaf-0.pem') }
      ]
    })
  })

  it('rejects a junctioned RUNNER_TEMP before decoding or materializing secrets', () => {
    const realRoot = tempRoot('nachuan-materializer-real-')
    const aliasParent = tempRoot('nachuan-materializer-alias-')
    const alias = join(aliasParent, 'runner-temp')
    symlinkSync(realRoot, alias, 'junction')

    expect(() =>
      materializeRootAuthorization({
        runnerTemp: alias,
        rootAuthorizationBase64: 'not-base64',
        expectedRootKeyId: 'early-root-2026-01',
        rootPublicKeySpkiBase64: 'not-base64',
        githubOutput: join(realRoot, 'missing-output')
      })
    ).toThrow(/RUNNER_TEMP.*reparse|redirected through a reparse/i)
    expect(readdirSync(realRoot)).toEqual([])

    expect(() =>
      materializeLeafSigningKeys({
        runnerTemp: alias,
        rootAuthorizationFile: join(alias, 'nachuan-root-authorization.json'),
        leafSigningKeysBundleBase64: 'not-base64',
        expectedRootKeyId: 'early-root-2026-01',
        githubOutput: join(realRoot, 'missing-output')
      })
    ).toThrow(/RUNNER_TEMP.*reparse|redirected through a reparse/i)
    expect(readdirSync(realRoot)).toEqual([])
  })
})
