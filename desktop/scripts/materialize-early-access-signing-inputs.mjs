import { createHash, createPublicKey, verify } from 'node:crypto'
import { appendFileSync, lstatSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  checkedFixedSigningMaterialFile,
  checkedSigningMaterialRoot,
  fixedSigningMaterialPath,
  LEAF_DESCRIPTOR_NAME,
  LEAF_SLOT_NAMES,
  ROOT_AUTHORIZATION_NAME
} from './signing-material-paths.mjs'
import { canonicalUpdateKeyring } from './update-envelope.mjs'

const scriptPath = fileURLToPath(import.meta.url)
const KEY_ID = /^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$/

function exactKeys(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`)
  }
  if (Object.keys(value).sort().join(',') !== [...expected].sort().join(',')) {
    throw new Error(`${label} fields are not canonical`)
  }
}

function decodeCanonicalBase64(value, label, maxBytes) {
  if (
    typeof value !== 'string' ||
    !value ||
    value.length % 4 ||
    !/^[0-9A-Za-z+/]+={0,2}$/.test(value)
  ) {
    throw new Error(`${label} must be canonical base64`)
  }
  const bytes = Buffer.from(value, 'base64')
  if (!bytes.length || bytes.length > maxBytes || bytes.toString('base64') !== value) {
    throw new Error(`${label} must be canonical bounded base64`)
  }
  return bytes
}

function parseCanonicalJson(bytes, label) {
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

function rollbackCreatedFiles(paths) {
  for (const path of [...paths].reverse()) {
    const info = lstatSync(path)
    if (!info.isFile() || info.isSymbolicLink()) {
      throw new Error(`refusing to roll back redirected signing material: ${path}`)
    }
    unlinkSync(path)
  }
}

function appendOutputs(outputPath, values) {
  if (typeof outputPath !== 'string' || !outputPath) throw new Error('GITHUB_OUTPUT is required')
  appendFileSync(
    outputPath,
    `${Object.entries(values).map(([name, value]) => `${name}=${value}`).join('\n')}\n`,
    'utf8'
  )
}

export function materializeRootAuthorization({
  runnerTemp,
  rootAuthorizationBase64,
  expectedRootKeyId,
  rootPublicKeySpkiBase64,
  githubOutput
}) {
  // Validate every parent before decoding or writing any signing input.
  const root = checkedSigningMaterialRoot(runnerTemp)
  const rootPath = fixedSigningMaterialPath(root, ROOT_AUTHORIZATION_NAME)
  const rootBytes = decodeCanonicalBase64(rootAuthorizationBase64, 'root authorization', 128 * 1024)
  const rootAuthorization = parseCanonicalJson(rootBytes, 'root authorization')
  exactKeys(rootAuthorization, ['schema', 'keyring', 'keyringSignature'], 'root authorization')
  exactKeys(rootAuthorization.keyringSignature, ['algorithm', 'keyId', 'value'], 'root authorization signature')
  if (
    rootAuthorization.schema !== 1 ||
    !KEY_ID.test(String(expectedRootKeyId || '')) ||
    rootAuthorization.keyringSignature.algorithm !== 'Ed25519' ||
    rootAuthorization.keyringSignature.keyId !== expectedRootKeyId
  ) {
    throw new Error('root authorization does not use the embedded root identity')
  }
  const threshold = rootAuthorization.keyring?.threshold
  if (!Number.isSafeInteger(threshold) || threshold < 1 || threshold > 16) {
    throw new Error('root authorization threshold is invalid')
  }
  if (!Number.isSafeInteger(rootAuthorization.keyring?.sequence) || rootAuthorization.keyring.sequence < 0) {
    throw new Error('root authorization keyring sequence is invalid')
  }
  const canonicalKeyring = canonicalUpdateKeyring(rootAuthorization.keyring)
  const keyringSha256 = createHash('sha256').update(canonicalKeyring, 'utf8').digest('hex')
  const rootPublicKey = createPublicKey({
    key: decodeCanonicalBase64(rootPublicKeySpkiBase64, 'embedded root public key', 512),
    format: 'der',
    type: 'spki'
  })
  const signature = decodeCanonicalBase64(
    rootAuthorization.keyringSignature.value,
    'root authorization signature',
    64
  )
  if (
    rootPublicKey.asymmetricKeyType !== 'ed25519' ||
    signature.length !== 64 ||
    !verify(null, Buffer.from(canonicalKeyring, 'utf8'), rootPublicKey, signature)
  ) {
    throw new Error('root authorization signature is invalid')
  }

  const written = []
  try {
    writeFileSync(rootPath, rootBytes, { flag: 'wx', mode: 0o600 })
    written.push(rootPath)
    appendOutputs(githubOutput, {
      root_authorization_file: rootPath,
      keyring_sequence: rootAuthorization.keyring.sequence,
      keyring_sha256: keyringSha256
    })
  } catch (error) {
    try {
      rollbackCreatedFiles(written)
    } catch (cleanupError) {
      throw new Error(`root authorization rollback failed: ${cleanupError.message}`, { cause: error })
    }
    throw error
  }
  return { rootAuthorizationFile: rootPath, keyringSequence: rootAuthorization.keyring.sequence, keyringSha256 }
}

export function materializeLeafSigningKeys({
  runnerTemp,
  rootAuthorizationFile,
  leafSigningKeysBundleBase64,
  expectedRootKeyId,
  githubOutput
}) {
  // This must precede both secret decoding and descriptor-controlled paths.
  const root = checkedSigningMaterialRoot(runnerTemp)
  const checkedRootAuthorizationFile = checkedFixedSigningMaterialFile({
    root,
    pathValue: rootAuthorizationFile,
    name: ROOT_AUTHORIZATION_NAME,
    label: 'root authorization',
    maxBytes: 128 * 1024
  })
  const rootAuthorization = parseCanonicalJson(readFileSync(checkedRootAuthorizationFile), 'root authorization')
  exactKeys(rootAuthorization, ['schema', 'keyring', 'keyringSignature'], 'root authorization')
  if (
    rootAuthorization.schema !== 1 ||
    rootAuthorization.keyringSignature?.keyId !== expectedRootKeyId
  ) {
    throw new Error('root authorization does not use the embedded root identity')
  }
  const threshold = rootAuthorization.keyring?.threshold
  if (!Number.isSafeInteger(threshold) || threshold < 1 || threshold > LEAF_SLOT_NAMES.length) {
    throw new Error('root authorization threshold is invalid')
  }
  const authorizedIds = new Set(
    Array.isArray(rootAuthorization.keyring?.keys)
      ? rootAuthorization.keyring.keys.map((key) => String(key?.keyId || ''))
      : []
  )

  const bundleBytes = decodeCanonicalBase64(
    leafSigningKeysBundleBase64,
    'leaf signing key bundle',
    1024 * 1024
  )
  const descriptorPath = fixedSigningMaterialPath(root, LEAF_DESCRIPTOR_NAME)
  const written = []
  try {
    const bundle = parseCanonicalJson(bundleBytes, 'leaf signing key bundle')
    exactKeys(bundle, ['schema', 'signingKeys'], 'leaf signing key bundle')
    if (
      bundle.schema !== 1 ||
      !Array.isArray(bundle.signingKeys) ||
      bundle.signingKeys.length > LEAF_SLOT_NAMES.length
    ) {
      throw new Error('leaf signing key bundle schema is invalid')
    }
    const keys = bundle.signingKeys
      .map((key) => {
        exactKeys(key, ['keyId', 'privateKeyPemBase64'], 'leaf signing key')
        if (
          !KEY_ID.test(String(key.keyId || '')) ||
          key.keyId === expectedRootKeyId ||
          !authorizedIds.has(key.keyId)
        ) {
          throw new Error('leaf signing key is not authorized by the offline root keyring')
        }
        return key
      })
      .sort((left, right) => (left.keyId < right.keyId ? -1 : left.keyId > right.keyId ? 1 : 0))
    if (new Set(keys.map((key) => key.keyId)).size !== keys.length) {
      throw new Error('leaf signing key ids must be distinct')
    }
    if (keys.length < threshold) {
      throw new Error(`leaf signing key threshold was not met: required=${threshold} provided=${keys.length}`)
    }

    const signingKeys = keys.map((key, index) => {
      const pem = decodeCanonicalBase64(key.privateKeyPemBase64, `leaf private key ${key.keyId}`, 64 * 1024)
      try {
        if (!pem.toString('ascii').startsWith('-----BEGIN ENCRYPTED PRIVATE KEY-----\n')) {
          throw new Error(`leaf private key ${key.keyId} must be encrypted PKCS#8 PEM`)
        }
        const privateKeyPath = fixedSigningMaterialPath(root, LEAF_SLOT_NAMES[index])
        writeFileSync(privateKeyPath, pem, { flag: 'wx', mode: 0o600 })
        written.push(privateKeyPath)
        return { keyId: key.keyId, privateKeyPath }
      } finally {
        pem.fill(0)
      }
    })
    writeFileSync(descriptorPath, `${JSON.stringify({ schema: 1, signingKeys })}\n`, {
      encoding: 'utf8', flag: 'wx', mode: 0o600
    })
    written.push(descriptorPath)
    appendOutputs(githubOutput, { leaf_signing_keys_file: descriptorPath })
  } catch (error) {
    try {
      rollbackCreatedFiles(written)
    } catch (cleanupError) {
      throw new Error(`leaf signing material rollback failed: ${cleanupError.message}`, { cause: error })
    }
    throw error
  } finally {
    bundleBytes.fill(0)
  }
  return { leafSigningKeysFile: descriptorPath }
}

function main(argv) {
  if (argv[0] === 'root') {
    const result = materializeRootAuthorization({
      runnerTemp: process.env.RUNNER_TEMP,
      rootAuthorizationBase64: process.env.ROOT_AUTHORIZATION_BASE64,
      expectedRootKeyId: process.env.EXPECTED_ROOT_KEY_ID,
      rootPublicKeySpkiBase64: process.env.ROOT_PUBLIC_KEY_SPKI_BASE64,
      githubOutput: process.env.GITHUB_OUTPUT
    })
    console.log(`[signing-materializer] ROOT_READY sequence=${result.keyringSequence}`)
    return
  }
  if (argv[0] === 'leaves') {
    materializeLeafSigningKeys({
      runnerTemp: process.env.RUNNER_TEMP,
      rootAuthorizationFile: process.env.ROOT_AUTHORIZATION_FILE,
      leafSigningKeysBundleBase64: process.env.LEAF_SIGNING_KEYS_BUNDLE_BASE64,
      expectedRootKeyId: process.env.EXPECTED_ROOT_KEY_ID,
      githubOutput: process.env.GITHUB_OUTPUT
    })
    console.log('[signing-materializer] LEAF_SLOTS_READY')
    return
  }
  throw new Error('usage: materialize-early-access-signing-inputs.mjs <root|leaves>')
}

if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  try {
    main(process.argv.slice(2))
  } catch (error) {
    console.error(`[signing-materializer] BLOCKED: ${error instanceof Error ? error.message : String(error)}`)
    process.exitCode = 1
  }
}
