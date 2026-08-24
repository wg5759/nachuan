import { createHash, createPublicKey, randomBytes, verify } from 'node:crypto'
import { appendFileSync, createReadStream, lstatSync, readFileSync } from 'node:fs'
import { rename, rm, writeFile } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { verifyInstallerPayloadClosure } from './installer-closure.mjs'
import { verifyReleaseMetadata } from './release-metadata.mjs'
import { assertClosedReleaseOutput, verifyFinalReleaseOutput } from './release-output.mjs'
import { scanReleasePaths } from './release-security.mjs'
import { signUpdateManifest } from './sign-update-manifest.mjs'
import {
  canonicalUpdateKeyring,
  verifySignedUpdateEnvelopeForRelease
} from './update-envelope.mjs'

const scriptPath = fileURLToPath(import.meta.url)
const desktopRoot = resolve(dirname(scriptPath), '..')
const defaultReleaseRoot = join(desktopRoot, 'release')
const packageMetadata = JSON.parse(readFileSync(join(desktopRoot, 'package.json'), 'utf8'))
const KEY_ID = /^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$/

function exactKeys(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`)
  }
  if (Object.keys(value).sort().join(',') !== [...expected].sort().join(',')) {
    throw new Error(`${label} fields are not canonical`)
  }
}

function checkedBase64(value, label, maxBytes) {
  value = String(value || '')
  if (!value || value.length > maxBytes * 2 || value.length % 4 || !/^[0-9A-Za-z+/]+={0,2}$/.test(value)) {
    throw new Error(`${label} must be canonical base64`)
  }
  const bytes = Buffer.from(value, 'base64')
  if (!bytes.length || bytes.length > maxBytes || bytes.toString('base64') !== value) {
    throw new Error(`${label} must be canonical bounded base64`)
  }
  return bytes
}

function readBoundedJson(pathValue, label, maxBytes = 128 * 1024) {
  if (typeof pathValue !== 'string' || !pathValue) throw new Error(`${label} file is required`)
  const path = resolve(pathValue)
  const info = lstatSync(path)
  if (info.isSymbolicLink() || !info.isFile() || info.size <= 0 || info.size > maxBytes) {
    throw new Error(`${label} must be a bounded regular file`)
  }
  const bytes = readFileSync(path)
  const text = bytes.toString('utf8')
  if (!Buffer.from(text, 'utf8').equals(bytes) || text.startsWith('\uFEFF') || text.includes('\0')) {
    throw new Error(`${label} must be canonical UTF-8 JSON`)
  }
  try {
    return JSON.parse(text)
  } catch {
    throw new Error(`${label} must be valid JSON`)
  }
}

function parseBoundedJsonBytes(bytes, label, maxBytes) {
  if (!Buffer.isBuffer(bytes) || !bytes.length || bytes.length > maxBytes) {
    throw new Error(`${label} is empty or oversized`)
  }
  const text = bytes.toString('utf8')
  if (!Buffer.from(text, 'utf8').equals(bytes) || text.startsWith('\uFEFF') || text.includes('\0')) {
    throw new Error(`${label} must be canonical UTF-8 JSON`)
  }
  try {
    return JSON.parse(text)
  } catch {
    throw new Error(`${label} must be valid JSON`)
  }
}

function checkedProductionRootAuthorization({ rootAuthorization, rootKeyId, publicKeySpkiBase64, channel, variant }) {
  exactKeys(rootAuthorization, ['schema', 'keyring', 'keyringSignature'], 'production root authorization')
  exactKeys(
    rootAuthorization.keyringSignature,
    ['algorithm', 'keyId', 'value'],
    'production root authorization signature'
  )
  if (!KEY_ID.test(rootKeyId) || !rootKeyId.startsWith('production-root-')) {
    throw new Error('production root key id is invalid or outside the production trust domain')
  }
  if (
    rootAuthorization.schema !== 1 ||
    rootAuthorization.keyringSignature.algorithm !== 'Ed25519' ||
    rootAuthorization.keyringSignature.keyId !== rootKeyId
  ) {
    throw new Error('production root authorization does not use the embedded production root identity')
  }
  const keyring = rootAuthorization.keyring
  exactKeys(keyring, ['channel', 'keys', 'schema', 'sequence', 'threshold', 'variant'], 'production keyring')
  if (
    keyring.schema !== 1 ||
    keyring.channel !== channel ||
    channel !== `production-${variant}-win-x64` ||
    keyring.variant !== variant
  ) {
    throw new Error('production root authorization channel or variant is outside the production trust domain')
  }
  if (
    !Number.isSafeInteger(keyring.sequence) ||
    keyring.sequence < 0 ||
    !Number.isSafeInteger(keyring.threshold) ||
    keyring.threshold < 2 ||
    keyring.threshold > 16 ||
    !Array.isArray(keyring.keys) ||
    keyring.threshold > keyring.keys.length ||
    keyring.keys.length > 16
  ) {
    throw new Error('production keyring threshold must be at least 2 and covered by distinct leaves')
  }
  const authorizedIds = new Set()
  for (const key of keyring.keys) {
    exactKeys(
      key,
      ['keyId', 'notAfterSequence', 'notBeforeSequence', 'publicKeySpkiBase64'],
      'production keyring leaf'
    )
    if (
      !KEY_ID.test(String(key.keyId || '')) ||
      !String(key.keyId).startsWith('production-leaf-') ||
      authorizedIds.has(key.keyId)
    ) {
      throw new Error('production keyring leaves must have distinct production-only identities')
    }
    authorizedIds.add(key.keyId)
  }
  const publicKey = createPublicKey({
    key: checkedBase64(publicKeySpkiBase64, 'production root public key', 512),
    format: 'der',
    type: 'spki'
  })
  if (
    publicKey.asymmetricKeyType !== 'ed25519' ||
    !verify(
      null,
      Buffer.from(canonicalUpdateKeyring(keyring), 'utf8'),
      publicKey,
      checkedBase64(rootAuthorization.keyringSignature.value, 'production root signature', 64)
    )
  ) {
    throw new Error('production root authorization signature is invalid')
  }
  return { authorizedIds, keyring }
}

export async function prepareProductionRootAuthorization({
  authorizationBase64,
  rootKeyId,
  publicKeySpkiBase64,
  channel,
  variant,
  outputDirectory
}) {
  const bytes = checkedBase64(authorizationBase64, 'production root authorization', 128 * 1024)
  const rootAuthorization = parseBoundedJsonBytes(bytes, 'production root authorization', 128 * 1024)
  const { keyring } = checkedProductionRootAuthorization({
    rootAuthorization,
    rootKeyId,
    publicKeySpkiBase64,
    channel,
    variant
  })
  const directory = resolve(outputDirectory)
  const info = lstatSync(directory)
  if (info.isSymbolicLink() || !info.isDirectory()) {
    throw new Error('production root authorization output directory must be a real directory')
  }
  const path = join(directory, `nachuan-production-root-${process.pid}-${randomBytes(6).toString('hex')}.json`)
  await writeFile(path, bytes, { flag: 'wx', mode: 0o600 })
  return {
    keyringSequence: keyring.sequence,
    keyringSha256: createHash('sha256')
      .update(canonicalUpdateKeyring(keyring), 'utf8')
      .digest('hex'),
    path
  }
}

export async function materializeProductionLeafSigningKeys({
  rootAuthorizationPath,
  rootKeyId,
  publicKeySpkiBase64,
  channel,
  variant,
  bundleBase64,
  outputDirectory
}) {
  const rootAuthorization = readBoundedJson(
    rootAuthorizationPath,
    'production root authorization'
  )
  const { authorizedIds, keyring } = checkedProductionRootAuthorization({
    rootAuthorization,
    rootKeyId,
    publicKeySpkiBase64,
    channel,
    variant
  })
  const bundleBytes = checkedBase64(bundleBase64, 'production leaf signing key bundle', 1024 * 1024)
  const bundle = parseBoundedJsonBytes(
    bundleBytes,
    'production leaf signing key bundle',
    1024 * 1024
  )
  exactKeys(bundle, ['schema', 'signingKeys'], 'production leaf signing key bundle')
  if (bundle.schema !== 1 || !Array.isArray(bundle.signingKeys) || bundle.signingKeys.length > 16) {
    throw new Error('production leaf signing key bundle schema is invalid')
  }
  const keys = bundle.signingKeys
    .map((key) => {
      exactKeys(key, ['keyId', 'privateKeyPemBase64'], 'production leaf signing key bundle entry')
      const keyId = String(key.keyId || '')
      if (!keyId.startsWith('production-leaf-') || !authorizedIds.has(keyId)) {
        throw new Error('production leaf signing key bundle contains an unauthorized trust domain')
      }
      return { keyId, privateKeyPemBase64: key.privateKeyPemBase64 }
    })
    .sort((left, right) => left.keyId.localeCompare(right.keyId, 'en'))
  if (new Set(keys.map(({ keyId }) => keyId)).size !== keys.length) {
    throw new Error('production leaf signing key bundle ids must be distinct')
  }
  if (keys.length < keyring.threshold) {
    throw new Error(`production leaf threshold was not met: required=${keyring.threshold} provided=${keys.length}`)
  }
  const directory = resolve(outputDirectory)
  const directoryInfo = lstatSync(directory)
  if (directoryInfo.isSymbolicLink() || !directoryInfo.isDirectory()) {
    throw new Error('production leaf output directory must be a real directory')
  }
  const written = []
  try {
    const signingKeys = []
    for (const [index, key] of keys.entries()) {
      const pem = checkedBase64(
        key.privateKeyPemBase64,
        `production leaf private key ${key.keyId}`,
        64 * 1024
      )
      try {
        if (!pem.toString('ascii').startsWith('-----BEGIN ENCRYPTED PRIVATE KEY-----\n')) {
          throw new Error(`production leaf private key ${key.keyId} must be encrypted PKCS#8 PEM`)
        }
        const privateKeyPath = join(
          directory,
          `nachuan-production-leaf-${process.pid}-${index}-${randomBytes(6).toString('hex')}.pem`
        )
        await writeFile(privateKeyPath, pem, { flag: 'wx', mode: 0o600 })
        written.push(privateKeyPath)
        signingKeys.push({ keyId: key.keyId, privateKeyPath })
      } finally {
        pem.fill(0)
      }
    }
    const descriptorPath = join(
      directory,
      `nachuan-production-leaves-${process.pid}-${randomBytes(6).toString('hex')}.json`
    )
    await writeFile(descriptorPath, `${JSON.stringify({ schema: 1, signingKeys })}\n`, {
      encoding: 'utf8',
      flag: 'wx',
      mode: 0o600
    })
    written.push(descriptorPath)
    return { descriptorPath, privateKeyPaths: signingKeys.map(({ privateKeyPath }) => privateKeyPath) }
  } catch (error) {
    for (const path of written.reverse()) await rm(path, { force: true })
    throw error
  } finally {
    bundleBytes.fill(0)
  }
}

function checkedEncryptedLeafPrivateKeyPath(pathValue, keyId) {
  if (typeof pathValue !== 'string' || !pathValue) {
    throw new Error(`production leaf signing key ${keyId} private key file is required`)
  }
  const path = resolve(pathValue)
  const info = lstatSync(path)
  if (info.isSymbolicLink() || !info.isFile() || info.size <= 0 || info.size > 64 * 1024) {
    throw new Error(`production leaf signing key ${keyId} must be a bounded regular file`)
  }
  const bytes = readFileSync(path)
  try {
    const encryptedHeader = Buffer.from('-----BEGIN ENCRYPTED PRIVATE KEY-----\n', 'ascii')
    if (bytes.length <= encryptedHeader.length || !bytes.subarray(0, encryptedHeader.length).equals(encryptedHeader)) {
      throw new Error(`production leaf signing key ${keyId} must be encrypted PKCS#8 PEM`)
    }
  } finally {
    bytes.fill(0)
  }
  return path
}

export function loadProductionSigningInputs(env = process.env) {
  if (
    env.NACHUAN_UPDATE_PRIVATE_KEY_FILE ||
    env.NACHUAN_UPDATE_PRIVATE_KEY_PEM_BASE64 ||
    env.NACHUAN_UPDATE_PRIVATE_KEY_PASSPHRASE
  ) {
    throw new Error('legacy single-private-key material must not enter the production schema2 finalizer')
  }
  if (
    env.NACHUAN_PRODUCTION_UPDATE_ROOT_PRIVATE_KEY_FILE ||
    env.NACHUAN_PRODUCTION_UPDATE_ROOT_PRIVATE_KEY_PASSPHRASE ||
    env.NACHUAN_UPDATE_ROOT_PRIVATE_KEY_FILE ||
    env.NACHUAN_UPDATE_ROOT_PRIVATE_KEY_PASSPHRASE
  ) {
    throw new Error('root private key material must not enter the online production finalizer')
  }
  const variant = String(env.DMX_VARIANT || '').trim().toLowerCase()
  if (variant !== 'lean' && variant !== 'full') throw new Error('production update variant is invalid')
  const channel = String(env.NACHUAN_PRODUCTION_UPDATE_CHANNEL || '')
  const rootKeyId = String(env.NACHUAN_PRODUCTION_UPDATE_KEY_ID || '')
  const publicKeySpkiBase64 = String(env.NACHUAN_PRODUCTION_UPDATE_PUBLIC_KEY_SPKI_BASE64 || '')
  const rootAuthorization = readBoundedJson(
    env.NACHUAN_PRODUCTION_UPDATE_ROOT_AUTHORIZATION_FILE,
    'production root authorization'
  )
  const { authorizedIds } = checkedProductionRootAuthorization({
    rootAuthorization,
    rootKeyId,
    publicKeySpkiBase64,
    channel,
    variant
  })
  const descriptor = readBoundedJson(
    env.NACHUAN_PRODUCTION_UPDATE_LEAF_SIGNING_KEYS_FILE,
    'production leaf signing key descriptor',
    1024 * 1024
  )
  exactKeys(descriptor, ['schema', 'signingKeys'], 'production leaf signing key descriptor')
  if (descriptor.schema !== 1 || !Array.isArray(descriptor.signingKeys) || descriptor.signingKeys.length > 16) {
    throw new Error('production leaf signing key descriptor schema is invalid')
  }
  const signingKeys = descriptor.signingKeys.map((key) => {
    exactKeys(key, ['keyId', 'privateKeyPath'], 'production leaf signing key')
    const keyId = String(key.keyId || '')
    if (!keyId.startsWith('production-leaf-') || !authorizedIds.has(keyId)) {
      throw new Error('production leaf signing key is not authorized by the production keyring')
    }
    return {
      keyId,
      privateKeyPath: checkedEncryptedLeafPrivateKeyPath(key.privateKeyPath, keyId)
    }
  })
  signingKeys.sort((left, right) => left.keyId.localeCompare(right.keyId, 'en'))
  if (new Set(signingKeys.map(({ keyId }) => keyId)).size !== signingKeys.length) {
    throw new Error('production leaf signing key ids must be distinct')
  }
  if (signingKeys.length < rootAuthorization.keyring.threshold) {
    throw new Error(
      `production leaf threshold was not met: required=${rootAuthorization.keyring.threshold} provided=${signingKeys.length}`
    )
  }
  const passphrase = env.NACHUAN_PRODUCTION_UPDATE_LEAF_PRIVATE_KEY_PASSPHRASE
  if (typeof passphrase !== 'string' || !passphrase || passphrase.length > 4096 || passphrase.includes('\0')) {
    throw new Error('production encrypted leaf private key passphrase is required')
  }
  return {
    channel,
    keyId: signingKeys[0].keyId,
    passphrase,
    publicKeySpkiBase64,
    rootAuthorization,
    rootKeyId,
    signingKeys,
    variant
  }
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

async function writeChecksums(root, names) {
  const lines = []
  for (const name of names) {
    const path = join(root, name)
    const info = lstatSync(path)
    if (info.isSymbolicLink() || !info.isFile() || info.size <= 0) {
      throw new Error(`production checksum target is not a non-empty regular file: ${name}`)
    }
    lines.push(`${await sha256File(path)}  ${name}`)
  }
  const output = join(root, 'SHA256SUMS')
  const temporary = `${output}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`
  await writeFile(temporary, `${lines.join('\n')}\n`, { encoding: 'utf8', flag: 'wx' })
  await rm(output, { force: true })
  await rename(temporary, output)
}

export async function finalizeProductionEnvelope({
  variant,
  signingKeys,
  publicKeySpkiBase64,
  rootKeyId,
  keyId,
  rootAuthorization,
  passphrase,
  sequence,
  releaseTag,
  channel = `production-${variant}-win-x64`,
  releaseRoot = defaultReleaseRoot
}) {
  if (process.platform !== 'win32') throw new Error('production NSIS finalization is Windows-only')
  if (variant !== 'lean' && variant !== 'full') throw new Error('production release variant is invalid')
  const version = String(packageMetadata.version || '')
  if (version === '0.1.0') throw new Error('v0.1.0 is retired and cannot be finalized for production')
  const expected = assertClosedReleaseOutput({
    variant,
    releaseTier: 'production',
    releaseRoot
  })
  const installer = join(releaseRoot, expected.artifact)
  const payloadManifest = join(releaseRoot, 'WIN_UNPACKED_MANIFEST.json')
  await verifyReleaseMetadata({
    variant,
    releaseTier: 'production',
    releaseTag,
    releaseRoot,
    version
  })
  await verifyInstallerPayloadClosure({
    installer,
    unpackedRoot: join(releaseRoot, 'win-unpacked'),
    manifestPath: payloadManifest,
    version,
    variant,
    productName: '纳川'
  })
  const envelopePath = join(releaseRoot, expected.updateEnvelope)
  await signUpdateManifest({
    installer,
    signingKeys,
    output: envelopePath,
    releaseTier: 'production',
    channel,
    variant,
    version,
    sequence,
    keyId,
    expectedPublicKeySpkiBase64: publicKeySpkiBase64,
    rootAuthorization,
    passphrase
  })
  const findings = await scanReleasePaths([
    join(releaseRoot, 'win-unpacked'),
    installer,
    join(releaseRoot, expected.blockmap),
    join(releaseRoot, expected.channel),
    payloadManifest,
    envelopePath
  ])
  if (findings.length) {
    const summary = findings
      .slice(0, 5)
      .map((finding) => `${finding.code}:${finding.field}`)
      .join(',')
    throw new Error(`production release scan blocked findings=${findings.length} ${summary}`)
  }
  await writeChecksums(releaseRoot, [
    expected.artifact,
    expected.blockmap,
    expected.channel,
    'WIN_UNPACKED_MANIFEST.json',
    expected.updateEnvelope
  ])
  const bytes = readFileSync(envelopePath)
  verifySignedUpdateEnvelopeForRelease({
    bytes,
    rootPublicKeySpkiBase64: publicKeySpkiBase64,
    expectedRootKeyId: rootKeyId,
    expectedChannel: channel,
    expectedVariant: variant
  })
  return await verifyFinalReleaseOutput({
    variant,
    releaseTier: 'production',
    releaseRoot
  })
}

export async function verifyProductionRelease({
  variant,
  publicKeySpkiBase64,
  rootKeyId,
  channel = `production-${variant}-win-x64`,
  releaseRoot = defaultReleaseRoot,
  requireEvidence = true
}) {
  const expected = await verifyFinalReleaseOutput({
    variant,
    releaseTier: 'production',
    releaseRoot,
    requireEvidence
  })
  verifySignedUpdateEnvelopeForRelease({
    bytes: readFileSync(join(releaseRoot, expected.updateEnvelope)),
    rootPublicKeySpkiBase64: publicKeySpkiBase64,
    expectedRootKeyId: rootKeyId,
    expectedChannel: channel,
    expectedVariant: variant
  })
  return expected
}

async function main(argv, env = process.env) {
  const [operation, rawVariant = env.DMX_VARIANT] = argv
  const variant = String(rawVariant || '').trim().toLowerCase()
  const channel = String(env.NACHUAN_PRODUCTION_UPDATE_CHANNEL || `production-${variant}-win-x64`)
  if (operation === 'prepare-root') {
    const result = await prepareProductionRootAuthorization({
      authorizationBase64: env.NACHUAN_PRODUCTION_UPDATE_ROOT_AUTHORIZATION_BASE64,
      rootKeyId: env.NACHUAN_PRODUCTION_UPDATE_KEY_ID,
      publicKeySpkiBase64: env.NACHUAN_PRODUCTION_UPDATE_PUBLIC_KEY_SPKI_BASE64,
      channel,
      variant,
      outputDirectory: env.RUNNER_TEMP
    })
    if (!env.GITHUB_OUTPUT) throw new Error('GITHUB_OUTPUT is required')
    appendFileSync(
      env.GITHUB_OUTPUT,
      `root_authorization_file=${result.path}\nkeyring_sequence=${result.keyringSequence}\nkeyring_sha256=${result.keyringSha256}\n`,
      'utf8'
    )
    console.log(`[production-update] ROOT_OK sequence=${result.keyringSequence}`)
    return
  }
  if (operation === 'materialize-leaves') {
    const result = await materializeProductionLeafSigningKeys({
      rootAuthorizationPath: env.NACHUAN_PRODUCTION_UPDATE_ROOT_AUTHORIZATION_FILE,
      rootKeyId: env.NACHUAN_PRODUCTION_UPDATE_KEY_ID,
      publicKeySpkiBase64: env.NACHUAN_PRODUCTION_UPDATE_PUBLIC_KEY_SPKI_BASE64,
      channel,
      variant,
      bundleBase64: env.NACHUAN_PRODUCTION_UPDATE_LEAF_SIGNING_KEYS_BUNDLE_BASE64,
      outputDirectory: env.RUNNER_TEMP
    })
    if (!env.GITHUB_OUTPUT) throw new Error('GITHUB_OUTPUT is required')
    appendFileSync(env.GITHUB_OUTPUT, `leaf_signing_keys_file=${result.descriptorPath}\n`, 'utf8')
    console.log(`[production-update] LEAVES_OK count=${result.privateKeyPaths.length}`)
    return
  }
  if (operation === 'finalize') {
    const rawSequence = String(env.NACHUAN_PRODUCTION_UPDATE_SEQUENCE || '')
    if (!/^\d+$/.test(rawSequence)) throw new Error('production update sequence is required')
    const signing = loadProductionSigningInputs(env)
    const result = await finalizeProductionEnvelope({
      variant,
      signingKeys: signing.signingKeys,
      publicKeySpkiBase64: signing.publicKeySpkiBase64,
      rootKeyId: signing.rootKeyId,
      keyId: signing.keyId,
      rootAuthorization: signing.rootAuthorization,
      passphrase: signing.passphrase,
      sequence: Number(rawSequence),
      releaseTag: env.NACHUAN_RELEASE_TAG,
      channel
    })
    console.log(`[production-update] FINAL_OK ${result.artifact} envelope=${result.updateEnvelope}`)
    return
  }
  if (operation === 'verify') {
    const result = await verifyProductionRelease({
      variant,
      publicKeySpkiBase64: env.NACHUAN_PRODUCTION_UPDATE_PUBLIC_KEY_SPKI_BASE64,
      rootKeyId: env.NACHUAN_PRODUCTION_UPDATE_KEY_ID,
      channel
    })
    console.log(`[production-update] VERIFIED ${result.artifact} envelope=${result.updateEnvelope}`)
    return
  }
  throw new Error('usage: production-update-envelope.mjs prepare-root|materialize-leaves|finalize|verify <lean|full>')
}

if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  try {
    await main(process.argv.slice(2))
  } catch (error) {
    console.error(`[production-update] BLOCKED: ${error instanceof Error ? error.message : String(error)}`)
    process.exitCode = 1
  }
}
