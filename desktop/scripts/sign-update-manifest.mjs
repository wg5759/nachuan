import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  sign
} from 'node:crypto'
import { createReadStream, lstatSync, readFileSync, realpathSync } from 'node:fs'
import { rename, rm, writeFile } from 'node:fs/promises'
import { basename, dirname, isAbsolute, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  canonicalUpdateKeyring,
  canonicalUpdateManifest,
  verifySignedUpdateEnvelopeForRelease
} from './update-envelope.mjs'

export {
  canonicalUpdateKeyring,
  canonicalUpdateManifest,
  verifySignedUpdateEnvelopeForRelease
} from './update-envelope.mjs'

const scriptPath = fileURLToPath(import.meta.url)
const desktopRoot = resolve(dirname(scriptPath), '..')
const repoRoot = resolve(desktopRoot, '..')
const SHA256 = /^[0-9a-f]{64}$/
const VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/
const KEY_ID = /^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$/
const CHANNEL = /^[a-z0-9]+(?:-[a-z0-9]+)*$/
const ARTIFACT = /^[0-9A-Za-z][0-9A-Za-z._-]{0,199}\.exe$/
const MAX_INSTALLER_BYTES = 4 * 1024 * 1024 * 1024

export function pathIsOutsideRoot(root, path) {
  const item = relative(resolve(root), resolve(path))
  // path.relative() returns an absolute path when Windows roots are on
  // different volumes. That is outside too, not an in-repository path.
  return isAbsolute(item) || item === '..' || item.startsWith(`..${sep}`)
}

function outsideRepo(path) {
  return pathIsOutsideRoot(repoRoot, path)
}

function checkedBase64(value, label, maxBytes) {
  value = String(value || '')
  if (!value || value.length > maxBytes * 2 || !/^[0-9A-Za-z+/]+={0,2}$/.test(value) || value.length % 4) {
    throw new Error(`${label} is invalid`)
  }
  const bytes = Buffer.from(value, 'base64')
  if (!bytes.length || bytes.length > maxBytes || bytes.toString('base64') !== value) {
    throw new Error(`${label} is not canonical base64`)
  }
  return bytes
}

async function sha256File(path) {
  const hash = createHash('sha256')
  await new Promise((accept, reject) => {
    const input = createReadStream(path)
    input.on('data', (chunk) => hash.update(chunk))
    input.once('error', reject)
    input.once('end', accept)
  })
  return hash.digest('hex')
}

function loadOfflinePrivateKey(pathValue, passphrase, label) {
  const path = resolve(pathValue)
  const info = lstatSync(path)
  const realPath = realpathSync.native(path)
  if (
    info.isSymbolicLink() ||
    !info.isFile() ||
    info.size <= 0 ||
    info.size > 64 * 1024 ||
    !outsideRepo(realPath)
  ) {
    throw new Error(`${label} must be a bounded regular file outside the repository`)
  }
  const bytes = readFileSync(realPath)
  try {
    const key = createPrivateKey({ key: bytes, format: 'pem', passphrase: passphrase || undefined })
    if (key.asymmetricKeyType !== 'ed25519') throw new Error(`${label} must be Ed25519`)
    return key
  } finally {
    bytes.fill(0)
  }
}

export async function signUpdateManifest({
  installer,
  privateKeyPath,
  signingKeys,
  output,
  releaseTier,
  channel,
  variant,
  version,
  sequence,
  keyId,
  expectedPublicKeySpkiBase64,
  rootAuthorization,
  passphrase = process.env.NACHUAN_UPDATE_PRIVATE_KEY_PASSPHRASE
}) {
  installer = resolve(installer)
  const usesThresholdSigners = signingKeys !== undefined
  if (!usesThresholdSigners) privateKeyPath = resolve(privateKeyPath)
  output = resolve(output)
  if (releaseTier !== 'early-access' && releaseTier !== 'production') {
    throw new Error('release tier must be early-access or production')
  }
  if (releaseTier === 'production' && !usesThresholdSigners) {
    throw new Error('production updates require schema2 threshold leaf signing; legacy root-key schema1 signing is forbidden')
  }
  if (variant !== 'lean' && variant !== 'full') throw new Error('variant must be lean or full')
  if (!CHANNEL.test(channel) || channel.length > 64) throw new Error('update channel is invalid')
  if (channel !== `${releaseTier}-${variant}-win-x64`) {
    throw new Error(`${releaseTier} update channel must be exactly ${releaseTier}-${variant}-win-x64`)
  }
  if (!VERSION.test(version)) throw new Error('update version must be stable canonical SemVer')
  if (!Number.isSafeInteger(sequence) || sequence < 0) throw new Error('update sequence is invalid')
  if (!KEY_ID.test(keyId)) throw new Error('update key id is invalid')

  const installerInfo = lstatSync(installer)
  const artifactName = basename(installer)
  if (
    installerInfo.isSymbolicLink() ||
    !installerInfo.isFile() ||
    installerInfo.size < 25 * 1024 * 1024 ||
    installerInfo.size > MAX_INSTALLER_BYTES ||
    !ARTIFACT.test(artifactName)
  ) {
    throw new Error('installer must be a bounded canonical Windows release artifact')
  }
  if (releaseTier === 'early-access' && !artifactName.includes('early-access-unsigned')) {
    throw new Error('early-access artifact must visibly include early-access-unsigned')
  }
  realpathSync.native(installer)

  const expectedPublicKey = checkedBase64(
    expectedPublicKeySpkiBase64,
    'expected embedded update public key',
    512
  )

  const artifactSha256 = await sha256File(installer)
  if (!SHA256.test(artifactSha256)) throw new Error('installer SHA-256 generation failed')
  const manifest = {
    schema: 1,
    channel,
    platform: 'win32',
    arch: 'x64',
    variant,
    version,
    sequence,
    keyId,
    artifact: { name: artifactName, size: installerInfo.size, sha256: artifactSha256 }
  }

  if (usesThresholdSigners) {
    if (!Array.isArray(signingKeys) || !signingKeys.length || signingKeys.length > 16) {
      throw new Error('threshold update signing keys are required')
    }
    if (
      !rootAuthorization ||
      rootAuthorization.schema !== 1 ||
      Object.keys(rootAuthorization).sort().join(',') !== 'keyring,keyringSignature,schema'
    ) {
      throw new Error('offline root authorization must be a canonical pre-signed object')
    }
    const rootKeyId = String(rootAuthorization.keyringSignature?.keyId || '')
    const signatures = signingKeys
      .map((signingKey) => {
        const signingKeyId = String(signingKey?.keyId || '')
        if (!KEY_ID.test(signingKeyId) || signingKeyId === rootKeyId) {
          throw new Error('threshold signer must be a valid leaf key distinct from the offline root')
        }
        const privateKey = loadOfflinePrivateKey(
          signingKey.privateKeyPath,
          signingKey.passphrase ?? passphrase,
          `update leaf private key ${signingKeyId}`
        )
        return {
          algorithm: 'Ed25519',
          keyId: signingKeyId,
          value: sign(
            null,
            Buffer.from(canonicalUpdateManifest(manifest), 'utf8'),
            privateKey
          ).toString('base64')
        }
      })
      .sort((left, right) => (left.keyId < right.keyId ? -1 : left.keyId > right.keyId ? 1 : 0))
    const envelope = {
      schema: 2,
      manifest,
      keyring: rootAuthorization.keyring,
      keyringSignature: rootAuthorization.keyringSignature,
      signatures
    }
    const bytes = Buffer.from(`${JSON.stringify(envelope, null, 2)}\n`, 'utf8')
    verifySignedUpdateEnvelopeForRelease({
      bytes,
      rootPublicKeySpkiBase64: expectedPublicKey.toString('base64'),
      expectedRootKeyId: rootKeyId,
      expectedChannel: channel,
      expectedVariant: variant
    })
    const temporary = `${output}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`
    await writeFile(temporary, bytes, { flag: 'wx' })
    await rm(output, { force: true })
    await rename(temporary, output)
    return { output, manifest }
  }

  if (rootAuthorization) {
    throw new Error('online manifest signing requires a pre-signed root authorization and leaf signing keys; offline root private key material must not be used')
  }
  const privateKey = loadOfflinePrivateKey(privateKeyPath, passphrase, 'offline update private key')
  const actualPublicKey = createPublicKey(privateKey).export({ format: 'der', type: 'spki' })
  if (!actualPublicKey.equals(expectedPublicKey)) {
    throw new Error('offline update private key does not match the public key embedded in the app')
  }
  const manifestSignature = sign(null, Buffer.from(canonicalUpdateManifest(manifest), 'utf8'), privateKey)
  const envelope = {
    schema: 1,
    manifest,
    signature: { algorithm: 'Ed25519', keyId, value: manifestSignature.toString('base64') }
  }
  const temporary = `${output}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`
  await writeFile(temporary, `${JSON.stringify(envelope, null, 2)}\n`, { encoding: 'utf8', flag: 'wx' })
  await rm(output, { force: true })
  await rename(temporary, output)
  return { output, manifest }
}

async function main(argv) {
  if (argv.length !== 9) {
    throw new Error(
      'usage: sign-update-manifest.mjs <installer> <private-key.pem> <output.json> <early-access|production> <channel> <lean|full> <version> <sequence> <key-id>'
    )
  }
  const [installer, privateKeyPath, output, releaseTier, channel, variant, version, rawSequence, keyId] = argv
  if (!/^\d+$/.test(rawSequence)) throw new Error('update sequence must be an integer')
  const result = await signUpdateManifest({
    installer,
    privateKeyPath,
    output,
    releaseTier,
    channel,
    variant,
    version,
    sequence: Number(rawSequence),
    keyId,
    expectedPublicKeySpkiBase64: process.env.NACHUAN_UPDATE_PUBLIC_KEY_SPKI_BASE64
  })
  console.log(
    `[update-manifest] SIGNED ${result.manifest.channel} v${result.manifest.version} sequence=${result.manifest.sequence} artifact=${result.manifest.artifact.name}`
  )
}

if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  try {
    await main(process.argv.slice(2))
  } catch (error) {
    console.error(`[update-manifest] BLOCKED: ${error instanceof Error ? error.message : String(error)}`)
    process.exitCode = 1
  }
}
