import { generateKeyPairSync, sign } from 'node:crypto'
import { mkdtempSync, readFileSync, rmSync, truncateSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'

import { verifySignedUpdateEnvelope } from '../src/main/update-security'
import {
  canonicalUpdateKeyring,
  canonicalUpdateManifest,
  pathIsOutsideRoot,
  signUpdateManifest,
  verifySignedUpdateEnvelopeForRelease
} from './sign-update-manifest.mjs'

const roots = []

function signingFixtureTempRoot() {
  const root = process.env.NACHUAN_EXTERNAL_TEST_TEMP_ROOT
  return root ? resolve(root) : tmpdir()
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true })
})

describe('offline update manifest signer', () => {
  it('treats a private-key path on another Windows volume as outside the repository', () => {
    expect(pathIsOutsideRoot('C:\\source\\nachuan', 'D:\\runner-temp\\leaf.pem')).toBe(true)
    expect(pathIsOutsideRoot('C:\\source\\nachuan', 'C:\\source\\nachuan\\leaf.pem')).toBe(false)
  })

  it('rejects legacy schema1 signing for production even when the root private key is valid', async () => {
    const workspace = mkdtempSync(join(signingFixtureTempRoot(), 'nachuan-production-legacy-signer-'))
    roots.push(workspace)
    const root = generateKeyPairSync('ed25519')
    const privateKeyPath = join(workspace, 'production-root.pem')
    const installer = join(workspace, 'nachuan-1.4.0-lean-win.exe')
    writeFileSync(privateKeyPath, root.privateKey.export({ format: 'pem', type: 'pkcs8' }))
    writeFileSync(installer, '')
    truncateSync(installer, 25 * 1024 * 1024)

    await expect(
      signUpdateManifest({
        installer,
        privateKeyPath,
        output: join(workspace, 'production-lean-win-x64.json'),
        releaseTier: 'production',
        channel: 'production-lean-win-x64',
        variant: 'lean',
        version: '1.4.0',
        sequence: 11,
        keyId: 'production-root-2026-01',
        expectedPublicKeySpkiBase64: root.publicKey
          .export({ format: 'der', type: 'spki' })
          .toString('base64')
      })
    ).rejects.toThrow(/production.*schema2.*threshold|threshold.*production/i)
  })

  it('rejects an early-access channel and authorization in the production signer', async () => {
    const workspace = mkdtempSync(join(signingFixtureTempRoot(), 'nachuan-production-channel-isolation-'))
    roots.push(workspace)
    const root = generateKeyPairSync('ed25519')
    const leaf = generateKeyPairSync('ed25519')
    const leafPath = join(workspace, 'early-leaf.pem')
    const installer = join(workspace, 'nachuan-1.4.0-lean-win.exe')
    const channel = 'early-access-lean-win-x64'
    writeFileSync(leafPath, leaf.privateKey.export({ format: 'pem', type: 'pkcs8' }))
    writeFileSync(installer, '')
    truncateSync(installer, 25 * 1024 * 1024)
    const keyring = {
      schema: 1,
      channel,
      variant: 'lean',
      sequence: 3,
      threshold: 1,
      keys: [
        {
          keyId: 'early-leaf-a',
          publicKeySpkiBase64: leaf.publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
          notBeforeSequence: 3,
          notAfterSequence: 20
        }
      ]
    }

    await expect(
      signUpdateManifest({
        installer,
        signingKeys: [{ keyId: 'early-leaf-a', privateKeyPath: leafPath }],
        output: join(workspace, 'production-lean-win-x64.json'),
        releaseTier: 'production',
        channel,
        variant: 'lean',
        version: '1.4.0',
        sequence: 3,
        keyId: 'early-leaf-a',
        expectedPublicKeySpkiBase64: root.publicKey
          .export({ format: 'der', type: 'spki' })
          .toString('base64'),
        rootAuthorization: {
          schema: 1,
          keyring,
          keyringSignature: {
            algorithm: 'Ed25519',
            keyId: 'early-root-2026-01',
            value: sign(null, Buffer.from(canonicalUpdateKeyring(keyring)), root.privateKey).toString('base64')
          }
        }
      })
    ).rejects.toThrow(/production.*channel|channel.*production/i)
  })

  it('produces an envelope accepted by the runtime verifier and rejects a mismatched private key', async () => {
    const root = mkdtempSync(join(signingFixtureTempRoot(), 'nachuan-update-signer-'))
    roots.push(root)
    const pair = generateKeyPairSync('ed25519')
    const other = generateKeyPairSync('ed25519')
    const privateKeyPath = join(root, 'offline-private.pem')
    const installer = join(root, 'nachuan-1.1.0-lean-early-access-unsigned-win.exe')
    const output = join(root, 'early-access-lean-win-x64.json')
    writeFileSync(privateKeyPath, pair.privateKey.export({ format: 'pem', type: 'pkcs8' }))
    writeFileSync(installer, '')
    truncateSync(installer, 25 * 1024 * 1024)
    const publicKey = pair.publicKey.export({ format: 'der', type: 'spki' }).toString('base64')
    const options = {
      installer,
      privateKeyPath,
      output,
      releaseTier: 'early-access',
      channel: 'early-access-lean-win-x64',
      variant: 'lean',
      version: '1.1.0',
      sequence: 2,
      keyId: 'early-2026-01'
    }

    await signUpdateManifest({ ...options, expectedPublicKeySpkiBase64: publicKey })
    expect(
      verifySignedUpdateEnvelope(
        readFileSync(output),
        {
          schema: 1,
          enabled: true,
          releaseTier: 'early-access',
          channel: options.channel,
          variant: 'lean',
          keyId: options.keyId,
          publicKeySpkiBase64: publicKey,
          manifestUrl: `https://updates.example.test/${options.channel}.json`,
          currentSequence: 1,
          publisherName: '',
          signerThumbprint: ''
        },
        '1.0.0'
      ).artifact.name
    ).toBe(installer.split(/[\\/]/).pop())

    await expect(
      signUpdateManifest({
        ...options,
        expectedPublicKeySpkiBase64: other.publicKey
          .export({ format: 'der', type: 'spki' })
          .toString('base64')
      })
    ).rejects.toThrow(/does not match/)
  })

  it('shares a strict keyring contract without coupling policy sequence to release sequence', () => {
    const root = generateKeyPairSync('ed25519')
    const leaf = generateKeyPairSync('ed25519')
    const rootKeyId = 'early-root-2026-01'
    const leafKeyId = 'early-leaf-2026-02'
    const manifest = {
      schema: 1,
      channel: 'early-access-lean-win-x64',
      platform: 'win32',
      arch: 'x64',
      variant: 'lean',
      version: '1.2.0',
      sequence: 3,
      keyId: leafKeyId,
      artifact: {
        name: 'nachuan-1.2.0-lean-early-access-unsigned-win.exe',
        size: 25 * 1024 * 1024,
        sha256: 'a'.repeat(64)
      }
    }
    const keyring = {
      schema: 1,
      channel: manifest.channel,
      variant: manifest.variant,
      sequence: 5,
      threshold: 1,
      keys: [
        {
          keyId: leafKeyId,
          publicKeySpkiBase64: leaf.publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
          notBeforeSequence: 3,
          notAfterSequence: 10
        }
      ]
    }
    const envelope = Buffer.from(
      `${JSON.stringify({
        schema: 2,
        manifest,
        keyring,
        keyringSignature: {
          algorithm: 'Ed25519',
          keyId: rootKeyId,
          value: sign(null, Buffer.from(canonicalUpdateKeyring(keyring)), root.privateKey).toString('base64')
        },
        signatures: [
          {
            algorithm: 'Ed25519',
            keyId: leafKeyId,
            value: sign(null, Buffer.from(canonicalUpdateManifest(manifest)), leaf.privateKey).toString('base64')
          }
        ]
      })}\n`
    )
    const rootPublicKey = root.publicKey.export({ format: 'der', type: 'spki' }).toString('base64')

    const published = verifySignedUpdateEnvelopeForRelease({
      bytes: envelope,
      rootPublicKeySpkiBase64: rootPublicKey,
      expectedRootKeyId: rootKeyId,
      expectedChannel: manifest.channel,
      expectedVariant: manifest.variant
    })
    const runtime = verifySignedUpdateEnvelope(
      envelope,
      {
        schema: 1,
        enabled: true,
        releaseTier: 'early-access',
        channel: manifest.channel,
        variant: manifest.variant,
        keyId: rootKeyId,
        publicKeySpkiBase64: rootPublicKey,
        manifestUrl: 'https://updates.example.test/early-access-lean-win-x64.json',
        currentSequence: 1,
        keyringSequence: keyring.sequence,
        keyringSha256: published.keyringSha256,
        publisherName: '',
        signerThumbprint: ''
      },
      '1.0.0'
    )

    expect(published.manifest).toEqual(manifest)
    expect(runtime).toMatchObject({
      ...manifest,
      keyringSequence: keyring.sequence,
      keyringSha256: published.keyringSha256
    })
  })

  it('produces schema2 only after distinct leaf signers meet the offline root-authorized threshold', async () => {
    const workspace = mkdtempSync(join(signingFixtureTempRoot(), 'nachuan-threshold-update-signer-'))
    roots.push(workspace)
    const trustRoot = generateKeyPairSync('ed25519')
    const leafA = generateKeyPairSync('ed25519')
    const leafB = generateKeyPairSync('ed25519')
    const leafAPath = join(workspace, 'leaf-a.pem')
    const leafBPath = join(workspace, 'leaf-b.pem')
    const installer = join(workspace, 'nachuan-1.3.0-lean-early-access-unsigned-win.exe')
    const output = join(workspace, 'threshold.json')
    writeFileSync(leafAPath, leafA.privateKey.export({ format: 'pem', type: 'pkcs8' }))
    writeFileSync(leafBPath, leafB.privateKey.export({ format: 'pem', type: 'pkcs8' }))
    writeFileSync(installer, '')
    truncateSync(installer, 25 * 1024 * 1024)
    const channel = 'early-access-lean-win-x64'
    const keyring = {
      schema: 1,
      channel,
      variant: 'lean',
      sequence: 5,
      threshold: 2,
      keys: [
        {
          keyId: 'early-leaf-a',
          publicKeySpkiBase64: leafA.publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
          notBeforeSequence: 5,
          notAfterSequence: 20
        },
        {
          keyId: 'early-leaf-b',
          publicKeySpkiBase64: leafB.publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
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
        value: sign(null, Buffer.from(canonicalUpdateKeyring(keyring)), trustRoot.privateKey).toString('base64')
      }
    }
    const rootPublicKey = trustRoot.publicKey.export({ format: 'der', type: 'spki' }).toString('base64')

    await signUpdateManifest({
      installer,
      output,
      releaseTier: 'early-access',
      channel,
      variant: 'lean',
      version: '1.3.0',
      sequence: 5,
      keyId: 'early-leaf-a',
      expectedPublicKeySpkiBase64: rootPublicKey,
      rootAuthorization,
      signingKeys: [
        { keyId: 'early-leaf-a', privateKeyPath: leafAPath },
        { keyId: 'early-leaf-b', privateKeyPath: leafBPath }
      ]
    })

    const bytes = readFileSync(output)
    expect(JSON.parse(bytes.toString('utf8'))).toMatchObject({
      schema: 2,
      keyring: { threshold: 2 },
      signatures: [{ keyId: 'early-leaf-a' }, { keyId: 'early-leaf-b' }]
    })
    expect(
      verifySignedUpdateEnvelopeForRelease({
        bytes,
        rootPublicKeySpkiBase64: rootPublicKey,
        expectedRootKeyId: 'early-root-2026-01',
        expectedChannel: channel,
        expectedVariant: 'lean'
      }).manifest.keyId
    ).toBe('early-leaf-a')
  })

  it('rejects attempts to bring the offline root private key into online manifest signing', async () => {
    const root = mkdtempSync(join(signingFixtureTempRoot(), 'nachuan-rotated-update-signer-'))
    roots.push(root)
    const trustRoot = generateKeyPairSync('ed25519')
    const leaf = generateKeyPairSync('ed25519')
    const rootPrivateKeyPath = join(root, 'root.pem')
    const leafPrivateKeyPath = join(root, 'leaf.pem')
    const installer = join(root, 'nachuan-1.2.0-lean-early-access-unsigned-win.exe')
    const output = join(root, 'rotated.json')
    writeFileSync(rootPrivateKeyPath, trustRoot.privateKey.export({ format: 'pem', type: 'pkcs8' }))
    writeFileSync(leafPrivateKeyPath, leaf.privateKey.export({ format: 'pem', type: 'pkcs8' }))
    writeFileSync(installer, '')
    truncateSync(installer, 25 * 1024 * 1024)
    const rootPublicKey = trustRoot.publicKey.export({ format: 'der', type: 'spki' }).toString('base64')

    await expect(
      signUpdateManifest({
        installer,
        privateKeyPath: leafPrivateKeyPath,
        output,
        releaseTier: 'early-access',
        channel: 'early-access-lean-win-x64',
        variant: 'lean',
        version: '1.2.0',
        sequence: 4,
        keyId: 'early-leaf-2026-02',
        expectedPublicKeySpkiBase64: rootPublicKey,
        rootAuthorization: {
          rootPrivateKeyPath,
          rootKeyId: 'early-root-2026-01',
          keyringSequence: 4,
          notBeforeSequence: 4,
          notAfterSequence: 10
        }
      })
    ).rejects.toThrow(/pre-signed root authorization|offline root.*must not/i)
  })
})
