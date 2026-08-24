import { createHash, randomBytes } from 'node:crypto'
import { createReadStream, lstatSync, readFileSync } from 'node:fs'
import { rename, rm, writeFile } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { verifyInstallerPayloadClosure } from './installer-closure.mjs'
import { generateReleaseEvidence } from './release-evidence.mjs'
import { verifyReleaseMetadata } from './release-metadata.mjs'
import { assertClosedReleaseOutput, verifyFinalReleaseOutput } from './release-output.mjs'
import { scanReleasePaths } from './release-security.mjs'
import { signUpdateManifest } from './sign-update-manifest.mjs'
import {
  checkedFixedSigningMaterialFile,
  checkedSigningMaterialRoot,
  LEAF_DESCRIPTOR_NAME,
  LEAF_SLOT_NAMES,
  ROOT_AUTHORIZATION_NAME
} from './signing-material-paths.mjs'

const scriptPath = fileURLToPath(import.meta.url)
const desktopRoot = resolve(dirname(scriptPath), '..')
const releaseRoot = join(desktopRoot, 'release')
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

function readBoundedJson(path, label) {
  const bytes = readFileSync(path)
  const text = bytes.toString('utf8')
  if (!Buffer.from(text, 'utf8').equals(bytes) || text.startsWith('\uFEFF') || text.includes('\0')) {
    throw new Error(`${label} must be canonical UTF-8`)
  }
  try {
    return JSON.parse(text)
  } catch {
    throw new Error(`${label} must be valid JSON`)
  }
}

export function loadEarlyAccessSigningInputs(env = process.env) {
  if (
    env.NACHUAN_UPDATE_PRIVATE_KEY_FILE ||
    env.NACHUAN_UPDATE_PRIVATE_KEY_PEM_BASE64 ||
    env.NACHUAN_UPDATE_PRIVATE_KEY_PASSPHRASE
  ) {
    throw new Error('legacy single-private-key material must not enter the schema2 finalizer')
  }
  if (
    env.NACHUAN_UPDATE_ROOT_PRIVATE_KEY_FILE ||
    env.NACHUAN_UPDATE_ROOT_PRIVATE_KEY_PASSPHRASE
  ) {
    throw new Error('offline root private key material must not enter the online finalizer')
  }
  const signingMaterialRoot = checkedSigningMaterialRoot(env.RUNNER_TEMP)
  const rootAuthorizationPath = checkedFixedSigningMaterialFile({
    root: signingMaterialRoot,
    pathValue: env.NACHUAN_UPDATE_ROOT_AUTHORIZATION_FILE,
    name: ROOT_AUTHORIZATION_NAME,
    label: 'offline root authorization',
    maxBytes: 128 * 1024
  })
  const rootAuthorization = readBoundedJson(rootAuthorizationPath, 'offline root authorization')
  exactKeys(rootAuthorization, ['schema', 'keyring', 'keyringSignature'], 'offline root authorization')
  if (rootAuthorization.schema !== 1) throw new Error('offline root authorization schema is invalid')
  exactKeys(
    rootAuthorization.keyringSignature,
    ['algorithm', 'keyId', 'value'],
    'offline root authorization signature'
  )
  const rootKeyId = String(env.NACHUAN_UPDATE_KEY_ID || '')
  if (
    !KEY_ID.test(rootKeyId) ||
    rootAuthorization.keyringSignature.algorithm !== 'Ed25519' ||
    rootAuthorization.keyringSignature.keyId !== rootKeyId
  ) {
    throw new Error('offline root authorization does not use the embedded root identity')
  }

  const descriptorPath = checkedFixedSigningMaterialFile({
    root: signingMaterialRoot,
    pathValue: env.NACHUAN_UPDATE_LEAF_SIGNING_KEYS_FILE,
    name: LEAF_DESCRIPTOR_NAME,
    label: 'leaf signing key descriptor',
    maxBytes: 128 * 1024
  })
  const descriptor = readBoundedJson(descriptorPath, 'leaf signing key descriptor')
  exactKeys(descriptor, ['schema', 'signingKeys'], 'leaf signing key descriptor')
  if (descriptor.schema !== 1 || !Array.isArray(descriptor.signingKeys)) {
    throw new Error('leaf signing key descriptor schema is invalid')
  }
  const threshold = rootAuthorization.keyring?.threshold
  if (!Number.isSafeInteger(threshold) || threshold < 1 || threshold > 16) {
    throw new Error('offline root authorization threshold is invalid')
  }
  const authorizedIds = new Set(
    Array.isArray(rootAuthorization.keyring?.keys)
      ? rootAuthorization.keyring.keys.map((key) => String(key?.keyId || ''))
      : []
  )
  if (descriptor.signingKeys.length > LEAF_SLOT_NAMES.length) {
    throw new Error('leaf signing key descriptor exceeds the fixed RUNNER_TEMP slot set')
  }
  const signingKeys = descriptor.signingKeys.map((signingKey, index) => {
    exactKeys(signingKey, ['keyId', 'privateKeyPath'], 'leaf signing key')
    const keyId = String(signingKey.keyId || '')
    if (!KEY_ID.test(keyId) || keyId === rootKeyId || !authorizedIds.has(keyId)) {
      throw new Error('leaf signing key is not authorized by the offline root keyring')
    }
    const privateKeyPath = checkedFixedSigningMaterialFile({
      root: signingMaterialRoot,
      pathValue: signingKey.privateKeyPath,
      name: LEAF_SLOT_NAMES[index],
      label: `leaf signing key ${keyId}`,
      maxBytes: 64 * 1024
    })
    return { keyId, privateKeyPath }
  })
  signingKeys.sort((left, right) => (left.keyId < right.keyId ? -1 : left.keyId > right.keyId ? 1 : 0))
  if (new Set(signingKeys.map(({ keyId }) => keyId)).size !== signingKeys.length) {
    throw new Error('leaf signing key ids must be distinct')
  }
  if (signingKeys.length < threshold) {
    throw new Error(`leaf signing key threshold was not met: required=${threshold} provided=${signingKeys.length}`)
  }
  const passphrase = env.NACHUAN_UPDATE_LEAF_PRIVATE_KEY_PASSPHRASE
  if (typeof passphrase !== 'string' || !passphrase || passphrase.length > 4096 || passphrase.includes('\0')) {
    throw new Error('encrypted leaf private key passphrase is required')
  }
  return {
    keyId: signingKeys[0].keyId,
    signingKeys,
    rootAuthorization,
    passphrase
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
      throw new Error(`checksum target is not a non-empty regular file: ${name}`)
    }
    lines.push(`${await sha256File(path)}  ${name}`)
  }
  const output = join(root, 'SHA256SUMS')
  const temporary = `${output}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`
  await writeFile(temporary, `${lines.join('\n')}\n`, { encoding: 'utf8', flag: 'wx' })
  await rm(output, { force: true })
  await rename(temporary, output)
}

export async function finalizeEarlyAccess({
  variant,
  signingKeys,
  publicKeySpkiBase64,
  keyId,
  rootAuthorization,
  passphrase,
  sequence,
  releaseTag,
  releaseCommit,
  runId,
  commandClient,
  osvClient,
  sourceControlClient,
  channel = `early-access-${variant}-win-x64`
}) {
  if (process.platform !== 'win32') throw new Error('early-access NSIS finalization is Windows-only')
  if (variant !== 'lean' && variant !== 'full') throw new Error('variant must be lean or full')
  const version = String(packageMetadata.version || '')
  if (version === '0.1.0') throw new Error('v0.1.0 is retired and cannot be finalized for distribution')
  const expected = assertClosedReleaseOutput({
    variant,
    releaseTier: 'early-access',
    releaseRoot
  })
  const installer = join(releaseRoot, expected.artifact)
  const payloadManifest = join(releaseRoot, 'WIN_UNPACKED_MANIFEST.json')
  await verifyReleaseMetadata({
    variant,
    releaseTier: 'early-access',
    releaseTag: `v${version}`,
    releaseRoot
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
    releaseTier: 'early-access',
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
    throw new Error(`early-access release scan blocked findings=${findings.length} ${summary}`)
  }
  const names = [
    expected.artifact,
    expected.blockmap,
    expected.channel,
    'WIN_UNPACKED_MANIFEST.json',
    expected.updateEnvelope
  ]
  await writeChecksums(releaseRoot, names)
  await generateReleaseEvidence({
    variant,
    releaseTier: 'early-access',
    releaseRoot,
    releaseTag,
    releaseCommit,
    runId,
    commandClient,
    osvClient,
    sourceControlClient
  })
  return await verifyFinalReleaseOutput({
    variant,
    releaseTier: 'early-access',
    releaseRoot,
    requireEvidence: true
  })
}

async function main(argv) {
  const [variant = process.env.DMX_VARIANT] = argv
  const rawSequence = String(process.env.NACHUAN_UPDATE_SEQUENCE || '')
  if (!/^\d+$/.test(rawSequence)) throw new Error('NACHUAN_UPDATE_SEQUENCE is required')
  const signing = loadEarlyAccessSigningInputs(process.env)
  const result = await finalizeEarlyAccess({
    variant,
    signingKeys: signing.signingKeys,
    publicKeySpkiBase64: process.env.NACHUAN_UPDATE_PUBLIC_KEY_SPKI_BASE64,
    keyId: signing.keyId,
    rootAuthorization: signing.rootAuthorization,
    passphrase: signing.passphrase,
    sequence: Number(rawSequence),
    releaseTag: process.env.NACHUAN_RELEASE_TAG,
    releaseCommit: process.env.NACHUAN_RELEASE_COMMIT,
    runId: process.env.NACHUAN_RELEASE_RUN_ID,
    channel: process.env.NACHUAN_UPDATE_CHANNEL || `early-access-${variant}-win-x64`
  })
  console.log(`[early-access] FINAL_OK ${result.artifact} envelope=${result.updateEnvelope}`)
}

if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  try {
    await main(process.argv.slice(2))
  } catch (error) {
    console.error(`[early-access] BLOCKED: ${error instanceof Error ? error.message : String(error)}`)
    process.exitCode = 1
  }
}
