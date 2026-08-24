import { createHash, generateKeyPairSync, sign, type KeyObject } from 'node:crypto'
import { mkdtempSync, rmSync, truncateSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'

import {
  assertUpdateMetadataMatchesManifest,
  assertUpdaterDownloadedPathAgreement,
  attestDownloadedUpdateArtifact,
  canonicalUpdateKeyring,
  canonicalUpdateManifest,
  updateSecurityStateFor,
  verifySignedUpdateEnvelope,
  type EmbeddedUpdateTrust,
  type UpdateKeyringAuthorization,
  type VerifiedUpdateManifest
} from './update-security'

const roots: string[] = []
const ARTIFACT_SIZE = 25 * 1024 * 1024

function keyMaterial(): { privateKey: KeyObject; publicKey: string } {
  const pair = generateKeyPairSync('ed25519')
  return {
    privateKey: pair.privateKey,
    publicKey: pair.publicKey.export({ format: 'der', type: 'spki' }).toString('base64')
  }
}

function trust(publicKey: string, overrides: Partial<EmbeddedUpdateTrust> = {}): EmbeddedUpdateTrust {
  return {
    schema: 1,
    enabled: true,
    releaseTier: 'early-access',
    channel: 'early-access-lean-win-x64',
    variant: 'lean',
    keyId: 'nachuan-early-2026-01',
    publicKeySpkiBase64: publicKey,
    manifestUrl: 'https://updates.example.test/early-access-lean-win-x64.json',
    currentSequence: 1,
    publisherName: '',
    signerThumbprint: '',
    ...overrides
  }
}

function manifest(overrides: Partial<VerifiedUpdateManifest> = {}): VerifiedUpdateManifest {
  return {
    schema: 1,
    channel: 'early-access-lean-win-x64',
    platform: 'win32',
    arch: 'x64',
    variant: 'lean',
    version: '1.1.0',
    sequence: 2,
    keyId: 'nachuan-early-2026-01',
    artifact: {
      name: 'nachuan-1.1.0-lean-early-access-unsigned-win.exe',
      size: ARTIFACT_SIZE,
      sha256: '0'.repeat(64)
    },
    ...overrides
  }
}

function envelope(item: VerifiedUpdateManifest, privateKey: KeyObject): Buffer {
  const signature = sign(null, Buffer.from(canonicalUpdateManifest(item), 'utf8'), privateKey)
  return Buffer.from(
    `${JSON.stringify({
      schema: 1,
      manifest: item,
      signature: { algorithm: 'Ed25519', keyId: item.keyId, value: signature.toString('base64') }
    })}\n`,
    'utf8'
  )
}

function rotatedEnvelope(
  item: VerifiedUpdateManifest,
  rootKeyId: string,
  rootPrivateKey: KeyObject,
  keyring: UpdateKeyringAuthorization,
  signers: Array<{ keyId: string; privateKey: KeyObject }>
): Buffer {
  const keyringSignature = sign(
    null,
    Buffer.from(canonicalUpdateKeyring(keyring), 'utf8'),
    rootPrivateKey
  )
  return Buffer.from(
    `${JSON.stringify({
      schema: 2,
      manifest: item,
      keyring,
      keyringSignature: {
        algorithm: 'Ed25519',
        keyId: rootKeyId,
        value: keyringSignature.toString('base64')
      },
      signatures: signers.map(({ keyId, privateKey }) => ({
        algorithm: 'Ed25519',
        keyId,
        value: sign(null, Buffer.from(canonicalUpdateManifest(item), 'utf8'), privateKey).toString(
          'base64'
        )
      }))
    })}\n`,
    'utf8'
  )
}

function authorizedKey(
  keyId: string,
  publicKeySpkiBase64: string,
  notBeforeSequence = 2,
  notAfterSequence = 100
) {
  return { keyId, publicKeySpkiBase64, notBeforeSequence, notAfterSequence }
}

function keyring(
  keys: ReturnType<typeof authorizedKey>[],
  overrides: Partial<UpdateKeyringAuthorization> = {}
): UpdateKeyringAuthorization {
  return {
    schema: 1,
    channel: 'early-access-lean-win-x64',
    variant: 'lean',
    sequence: 2,
    threshold: 1,
    keys,
    ...overrides
  }
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true })
})

describe('independently signed desktop updates', () => {
  it('accepts a canonical newer Ed25519-signed manifest', () => {
    const key = keyMaterial()
    const item = manifest()

    expect(verifySignedUpdateEnvelope(envelope(item, key.privateKey), trust(key.publicKey), '1.0.0')).toEqual(
      item
    )
  })

  it('accepts a new signing key only through a root-authorized bounded keyring', () => {
    const root = keyMaterial()
    const leaf = keyMaterial()
    const leafKeyId = 'nachuan-early-2026-02'
    const item = manifest({ keyId: leafKeyId })
    const policy = keyring([authorizedKey(leafKeyId, leaf.publicKey)])

    const verified = verifySignedUpdateEnvelope(
      rotatedEnvelope(item, 'nachuan-early-2026-01', root.privateKey, policy, [
        { keyId: leafKeyId, privateKey: leaf.privateKey }
      ]),
      trust(root.publicKey),
      '1.0.0'
    )

    expect(verified).toMatchObject({
      keyId: leafKeyId,
      keyringSequence: 2,
      keyringSha256: expect.stringMatching(/^[0-9a-f]{64}$/)
    })
    expect(updateSecurityStateFor(verified)).toMatchObject({ schema: 2, keyringSequence: 2 })
  })

  it('keeps release sequence independent from the persisted keyring sequence across releases', () => {
    const root = keyMaterial()
    const leaf = keyMaterial()
    const leafKeyId = 'nachuan-early-leaf-stable'
    const policy = keyring([authorizedKey(leafKeyId, leaf.publicKey)], { sequence: 1 })
    const policySha256 = createHash('sha256').update(canonicalUpdateKeyring(policy)).digest('hex')
    const embeddedTrust = {
      ...trust(root.publicKey),
      keyringSequence: 1,
      keyringSha256: policySha256
    } as EmbeddedUpdateTrust
    const releaseTwo = manifest({ keyId: leafKeyId, sequence: 2, version: '1.1.0' })
    const verifiedReleaseTwo = verifySignedUpdateEnvelope(
      rotatedEnvelope(releaseTwo, 'nachuan-early-2026-01', root.privateKey, policy, [
        { keyId: leafKeyId, privateKey: leaf.privateKey }
      ]),
      embeddedTrust,
      '1.0.0'
    )
    const installedState = updateSecurityStateFor(verifiedReleaseTwo)
    if (installedState.schema !== 2) throw new Error('rotated release must persist keyring state')
    const releaseThree = manifest({ keyId: leafKeyId, sequence: 3, version: '1.2.0' })

    expect(
      verifySignedUpdateEnvelope(
        rotatedEnvelope(releaseThree, 'nachuan-early-2026-01', root.privateKey, policy, [
          { keyId: leafKeyId, privateKey: leaf.privateKey }
        ]),
        { ...embeddedTrust, currentSequence: 2 },
        '1.1.0',
        installedState
      )
    ).toMatchObject({
      sequence: 3,
      keyringSequence: 1,
      keyringSha256: installedState.keyringSha256
    })
  })

  it('enforces an embedded keyring floor without comparing it to the release sequence', () => {
    const root = keyMaterial()
    const leaf = keyMaterial()
    const forkLeaf = keyMaterial()
    const leafKeyId = 'nachuan-early-leaf-policy-five'
    const forkKeyId = 'nachuan-early-leaf-policy-five-fork'
    const policy = keyring([authorizedKey(leafKeyId, leaf.publicKey, 2, 10)], { sequence: 5 })
    const policySha256 = createHash('sha256').update(canonicalUpdateKeyring(policy)).digest('hex')
    const embeddedTrust = {
      ...trust(root.publicKey, { currentSequence: 2 }),
      keyringSequence: 5,
      keyringSha256: policySha256
    } as EmbeddedUpdateTrust
    const releaseThree = manifest({ keyId: leafKeyId, sequence: 3, version: '1.2.0' })

    expect(
      verifySignedUpdateEnvelope(
        rotatedEnvelope(releaseThree, 'nachuan-early-2026-01', root.privateKey, policy, [
          { keyId: leafKeyId, privateKey: leaf.privateKey }
        ]),
        embeddedTrust,
        '1.1.0'
      )
    ).toMatchObject({ sequence: 3, keyringSequence: 5, keyringSha256: policySha256 })

    const downgradedPolicy = keyring([authorizedKey(leafKeyId, leaf.publicKey, 2, 10)], {
      sequence: 4
    })
    expect(() =>
      verifySignedUpdateEnvelope(
        rotatedEnvelope(releaseThree, 'nachuan-early-2026-01', root.privateKey, downgradedPolicy, [
          { keyId: leafKeyId, privateKey: leaf.privateKey }
        ]),
        embeddedTrust,
        '1.1.0'
      )
    ).toThrow(/keyring.*embedded authority/i)

    const forkedPolicy = keyring([authorizedKey(forkKeyId, forkLeaf.publicKey, 2, 10)], {
      sequence: 5
    })
    const forkedRelease = manifest({ keyId: forkKeyId, sequence: 3, version: '1.2.0' })
    expect(() =>
      verifySignedUpdateEnvelope(
        rotatedEnvelope(forkedRelease, 'nachuan-early-2026-01', root.privateKey, forkedPolicy, [
          { keyId: forkKeyId, privateKey: forkLeaf.privateKey }
        ]),
        embeddedTrust,
        '1.1.0'
      )
    ).toThrow(/keyring.*embedded authority/i)
  })

  it('rejects legacy root authority when an embedded sequence-zero keyring floor exists', () => {
    const root = keyMaterial()
    const legacyRelease = manifest({
      keyId: 'nachuan-early-2026-01',
      sequence: 2,
      version: '1.1.0'
    })
    const embeddedTrust = {
      ...trust(root.publicKey),
      keyringSequence: 0,
      keyringSha256: 'a'.repeat(64)
    } as EmbeddedUpdateTrust

    expect(() =>
      verifySignedUpdateEnvelope(
        envelope(legacyRelease, root.privateKey),
        embeddedTrust,
        '1.0.0'
      )
    ).toThrow(/legacy.*keyring/i)
  })

  it('rejects an unknown signer, an unauthorized keyring root, and an unmet threshold', () => {
    const root = keyMaterial()
    const wrongRoot = keyMaterial()
    const first = keyMaterial()
    const second = keyMaterial()
    const firstId = 'nachuan-early-leaf-a'
    const secondId = 'nachuan-early-leaf-b'
    const item = manifest({ keyId: firstId })
    const policy = keyring(
      [authorizedKey(firstId, first.publicKey), authorizedKey(secondId, second.publicKey)],
      { threshold: 2 }
    )

    expect(() =>
      verifySignedUpdateEnvelope(
        rotatedEnvelope(item, 'nachuan-early-2026-01', wrongRoot.privateKey, policy, [
          { keyId: firstId, privateKey: first.privateKey },
          { keyId: secondId, privateKey: second.privateKey }
        ]),
        trust(root.publicKey),
        '1.0.0'
      )
    ).toThrow(/keyring signature is invalid/)
    expect(() =>
      verifySignedUpdateEnvelope(
        rotatedEnvelope(item, 'nachuan-early-2026-01', root.privateKey, policy, [
          { keyId: firstId, privateKey: first.privateKey }
        ]),
        trust(root.publicKey),
        '1.0.0'
      )
    ).toThrow(/threshold/)

    const unknown = keyMaterial()
    expect(() =>
      verifySignedUpdateEnvelope(
        rotatedEnvelope(
          manifest({ keyId: 'unknown-leaf' }),
          'nachuan-early-2026-01',
          root.privateKey,
          policy,
          [{ keyId: 'unknown-leaf', privateKey: unknown.privateKey }]
        ),
        trust(root.publicKey),
        '1.0.0'
      )
    ).toThrow(/unknown|authorized/)
  })

  it('enforces key bounds and persisted keyring anti-downgrade and anti-fork', () => {
    const root = keyMaterial()
    const oldLeaf = keyMaterial()
    const newLeaf = keyMaterial()
    const forkLeaf = keyMaterial()
    const oldId = 'nachuan-early-leaf-old'
    const newId = 'nachuan-early-leaf-new'
    const forkId = 'nachuan-early-leaf-fork'
    const acceptedItem = manifest({ keyId: newId, sequence: 4, version: '1.2.0' })
    const acceptedPolicy = keyring([authorizedKey(newId, newLeaf.publicKey, 4, 10)], { sequence: 4 })
    const accepted = verifySignedUpdateEnvelope(
      rotatedEnvelope(acceptedItem, 'nachuan-early-2026-01', root.privateKey, acceptedPolicy, [
        { keyId: newId, privateKey: newLeaf.privateKey }
      ]),
      trust(root.publicKey),
      '1.0.0'
    )
    const state = updateSecurityStateFor(accepted)

    const legacyRootRelease = manifest({
      keyId: 'nachuan-early-2026-01',
      sequence: 6,
      version: '1.4.0'
    })
    expect(() =>
      verifySignedUpdateEnvelope(
        envelope(legacyRootRelease, root.privateKey),
        trust(root.publicKey),
        '1.2.0',
        state
      )
    ).toThrow(/legacy.*roll back|keyring/i)

    const forkedPolicy = keyring([authorizedKey(forkId, forkLeaf.publicKey, 4, 10)], {
      sequence: 4
    })
    const forkedRelease = manifest({ keyId: forkId, sequence: 5, version: '1.3.0' })
    expect(() =>
      verifySignedUpdateEnvelope(
        rotatedEnvelope(forkedRelease, 'nachuan-early-2026-01', root.privateKey, forkedPolicy, [
          { keyId: forkId, privateKey: forkLeaf.privateKey }
        ]),
        trust(root.publicKey),
        '1.2.0',
        state
      )
    ).toThrow(/keyring.*fork/i)

    const downgradedPolicy = keyring([authorizedKey(oldId, oldLeaf.publicKey, 2, 3)], { sequence: 3 })
    const maliciousNewer = manifest({ keyId: oldId, sequence: 5, version: '1.3.0' })
    expect(() =>
      verifySignedUpdateEnvelope(
        rotatedEnvelope(maliciousNewer, 'nachuan-early-2026-01', root.privateKey, downgradedPolicy, [
          { keyId: oldId, privateKey: oldLeaf.privateKey }
        ]),
        trust(root.publicKey),
        '1.2.0',
        state
      )
    ).toThrow(/not-after|keyring.*roll back/i)

    const notYetValid = keyring([authorizedKey(newId, newLeaf.publicKey, 6, 10)], { sequence: 5 })
    expect(() =>
      verifySignedUpdateEnvelope(
        rotatedEnvelope(maliciousNewer, 'nachuan-early-2026-01', root.privateKey, notYetValid, [
          { keyId: newId, privateKey: newLeaf.privateKey }
        ]),
        trust(root.publicKey),
        '1.2.0',
        state
      )
    ).toThrow(/not-before/)
  })

  it('blocks manifest tampering after signature and a wrong embedded key', () => {
    const signer = keyMaterial()
    const wrong = keyMaterial()
    const item = manifest()
    const signed = JSON.parse(envelope(item, signer.privateKey).toString('utf8'))
    signed.manifest.artifact.sha256 = '1'.repeat(64)

    expect(() =>
      verifySignedUpdateEnvelope(JSON.stringify(signed), trust(signer.publicKey), '1.0.0')
    ).toThrow(/signature is invalid/)
    expect(() =>
      verifySignedUpdateEnvelope(envelope(item, signer.privateKey), trust(wrong.publicKey), '1.0.0')
    ).toThrow(/signature is invalid/)
  })

  it('blocks rollback and sequence reuse but permits an exact interrupted-install retry', () => {
    const key = keyMaterial()
    const item = manifest()
    const prior = { schema: 1, sequence: 3, version: '1.2.0', artifactSha256: '2'.repeat(64) }
    expect(() =>
      verifySignedUpdateEnvelope(envelope(item, key.privateKey), trust(key.publicKey), '1.0.0', prior)
    ).toThrow(/roll back|reuse release authority/)

    expect(
      verifySignedUpdateEnvelope(
        envelope(item, key.privateKey),
        trust(key.publicKey),
        '1.0.0',
        updateSecurityStateFor(item)
      )
    ).toEqual(item)
  })

  it('binds electron-updater metadata version, filename and size to the signed manifest', () => {
    const item = manifest()
    expect(() =>
      assertUpdateMetadataMatchesManifest(
        { version: item.version, files: [{ url: item.artifact.name, size: item.artifact.size - 1 }] },
        item
      )
    ).toThrow(/artifact does not match/)
    expect(() =>
      assertUpdateMetadataMatchesManifest(
        {
          version: item.version,
          path: 'other.exe',
          files: [{ url: item.artifact.name, size: item.artifact.size }]
        },
        item
      )
    ).toThrow(/legacy path/)
    expect(() =>
      assertUpdateMetadataMatchesManifest(
        {
          version: item.version,
          path: item.artifact.name,
          files: [{ url: item.artifact.name, size: item.artifact.size }]
        },
        item
      )
    ).not.toThrow()
  })

  it('rehashes the final returned installer and rejects post-download tampering', async () => {
    const root = mkdtempSync(join(tmpdir(), 'nachuan-update-security-'))
    roots.push(root)
    const path = join(root, manifest().artifact.name)
    writeFileSync(path, '')
    truncateSync(path, ARTIFACT_SIZE)
    const sha256 = createHash('sha256').update(Buffer.alloc(ARTIFACT_SIZE)).digest('hex')
    const item = manifest({ artifact: { ...manifest().artifact, sha256 } })

    await expect(attestDownloadedUpdateArtifact(path, item)).resolves.toMatchObject({
      path,
      size: ARTIFACT_SIZE,
      sha256
    })
    writeFileSync(path, Buffer.alloc(ARTIFACT_SIZE, 0x41))
    await expect(attestDownloadedUpdateArtifact(path, item)).rejects.toThrow(/SHA-256/)
  })

  it('requires the download promise and event to agree on exactly one signed installer', () => {
    const item = manifest()
    const path = join('C:\\cache', item.artifact.name)
    expect(assertUpdaterDownloadedPathAgreement([path], path, item)).toBe(resolve(path))
    expect(() => assertUpdaterDownloadedPathAgreement([path, `${path}.blockmap`], path, item)).toThrow(
      /exactly one/
    )
    expect(() => assertUpdaterDownloadedPathAgreement([path], `${path}.other`, item)).toThrow(
      /do not match/
    )
  })
})
