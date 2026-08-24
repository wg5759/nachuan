import { createHash, createPublicKey, verify as verifySignature } from 'node:crypto'

const SHA256 = /^[0-9a-f]{64}$/
const VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/
const KEY_ID = /^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$/
const CHANNEL = /^[a-z0-9]+(?:-[a-z0-9]+)*$/
const ARTIFACT = /^[0-9A-Za-z][0-9A-Za-z._-]{0,199}\.exe$/
const MAX_ENVELOPE_BYTES = 128 * 1024
const MAX_ARTIFACT_BYTES = 4 * 1024 * 1024 * 1024

function exactKeys(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be an object`)
  if (Object.keys(value).sort().join(',') !== [...expected].sort().join(',')) {
    throw new Error(`${label} fields are not canonical`)
  }
}

function checkedSequence(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${label} is invalid`)
  return value
}

function checkedBase64(value, label, maxBytes) {
  if (typeof value !== 'string' || !value || value.length > maxBytes * 2 || !/^[0-9A-Za-z+/]+={0,2}$/.test(value) || value.length % 4) {
    throw new Error(`${label} is invalid`)
  }
  const bytes = Buffer.from(value, 'base64')
  if (!bytes.length || bytes.length > maxBytes || bytes.toString('base64') !== value) {
    throw new Error(`${label} is not canonical base64`)
  }
  return bytes
}

function checkedPublicKey(value, label) {
  const key = createPublicKey({ key: checkedBase64(value, label, 512), format: 'der', type: 'spki' })
  if (key.asymmetricKeyType !== 'ed25519') throw new Error(`${label} is not Ed25519`)
  return key
}

function checkedSignature(value, label) {
  exactKeys(value, ['algorithm', 'keyId', 'value'], label)
  if (value.algorithm !== 'Ed25519' || !KEY_ID.test(String(value.keyId || ''))) {
    throw new Error(`${label} identity is invalid`)
  }
  const signature = checkedBase64(value.value, `${label} value`, 64)
  if (signature.length !== 64) throw new Error(`${label} length is invalid`)
  return { keyId: value.keyId, signature }
}

export function canonicalUpdateManifest(manifest) {
  return `${JSON.stringify({
    schema: manifest.schema,
    channel: manifest.channel,
    platform: manifest.platform,
    arch: manifest.arch,
    variant: manifest.variant,
    version: manifest.version,
    sequence: manifest.sequence,
    keyId: manifest.keyId,
    artifact: {
      name: manifest.artifact.name,
      size: manifest.artifact.size,
      sha256: manifest.artifact.sha256
    }
  })}\n`
}

export function canonicalUpdateKeyring(keyring) {
  return `${JSON.stringify({
    schema: keyring.schema,
    channel: keyring.channel,
    variant: keyring.variant,
    sequence: keyring.sequence,
    threshold: keyring.threshold,
    keys: keyring.keys.map((key) => ({
      keyId: key.keyId,
      publicKeySpkiBase64: key.publicKeySpkiBase64,
      notBeforeSequence: key.notBeforeSequence,
      notAfterSequence: key.notAfterSequence
    }))
  })}\n`
}

function checkedManifest(value, expectedChannel, expectedVariant) {
  exactKeys(
    value,
    ['arch', 'artifact', 'channel', 'keyId', 'platform', 'schema', 'sequence', 'variant', 'version'],
    'signed update manifest'
  )
  exactKeys(value.artifact, ['name', 'sha256', 'size'], 'signed update artifact')
  if (
    value.schema !== 1 ||
    value.platform !== 'win32' ||
    value.arch !== 'x64' ||
    value.channel !== expectedChannel ||
    value.variant !== expectedVariant ||
    !VERSION.test(String(value.version || '')) ||
    !KEY_ID.test(String(value.keyId || '')) ||
    !ARTIFACT.test(String(value.artifact.name || '')) ||
    !Number.isSafeInteger(value.artifact.size) ||
    value.artifact.size < 25 * 1024 * 1024 ||
    value.artifact.size > MAX_ARTIFACT_BYTES ||
    !SHA256.test(String(value.artifact.sha256 || ''))
  ) {
    throw new Error('signed update manifest is invalid or targets a different release channel')
  }
  checkedSequence(value.sequence, 'signed update sequence')
  return value
}

function checkedKeyring(value, expectedChannel, expectedVariant) {
  exactKeys(value, ['channel', 'keys', 'schema', 'sequence', 'threshold', 'variant'], 'update keyring')
  if (
    value.schema !== 1 ||
    value.channel !== expectedChannel ||
    value.variant !== expectedVariant ||
    !Array.isArray(value.keys) ||
    !value.keys.length ||
    value.keys.length > 16 ||
    !Number.isSafeInteger(value.threshold) ||
    value.threshold < 1 ||
    value.threshold > value.keys.length
  ) {
    throw new Error('update keyring target or threshold is invalid')
  }
  checkedSequence(value.sequence, 'update keyring sequence')
  let previous = ''
  for (const key of value.keys) {
    exactKeys(
      key,
      ['keyId', 'notAfterSequence', 'notBeforeSequence', 'publicKeySpkiBase64'],
      'authorized update key'
    )
    if (!KEY_ID.test(String(key.keyId || '')) || (previous && key.keyId <= previous)) {
      throw new Error('authorized update key ids must be unique and ordinal-sorted')
    }
    previous = key.keyId
    checkedSequence(key.notBeforeSequence, 'authorized key not-before sequence')
    checkedSequence(key.notAfterSequence, 'authorized key not-after sequence')
    if (key.notAfterSequence < key.notBeforeSequence) throw new Error('authorized key sequence range is invalid')
    checkedPublicKey(key.publicKeySpkiBase64, `authorized update key ${key.keyId}`)
  }
  return value
}

export function verifySignedUpdateEnvelopeForRelease({
  bytes,
  rootPublicKeySpkiBase64,
  expectedRootKeyId,
  expectedChannel,
  expectedVariant
}) {
  if (!KEY_ID.test(String(expectedRootKeyId || ''))) throw new Error('expected update root key id is invalid')
  if (!CHANNEL.test(String(expectedChannel || '')) || !['lean', 'full'].includes(expectedVariant)) {
    throw new Error('expected update target is invalid')
  }
  bytes = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes || '')
  if (!bytes.length || bytes.length > MAX_ENVELOPE_BYTES) throw new Error('signed update envelope is outside the size bound')
  const text = bytes.toString('utf8')
  if (!Buffer.from(text, 'utf8').equals(bytes) || text.startsWith('\uFEFF') || text.includes('\0')) {
    throw new Error('signed update envelope is not canonical UTF-8')
  }
  let envelope
  try {
    envelope = JSON.parse(text)
  } catch {
    throw new Error('signed update envelope is invalid JSON')
  }
  exactKeys(
    envelope,
    envelope.schema === 1
      ? ['manifest', 'schema', 'signature']
      : ['keyring', 'keyringSignature', 'manifest', 'schema', 'signatures'],
    'signed update envelope'
  )
  if (envelope.schema !== 1 && envelope.schema !== 2) throw new Error('signed update envelope schema is invalid')
  const manifest = checkedManifest(envelope.manifest, expectedChannel, expectedVariant)
  const rootPublicKey = checkedPublicKey(rootPublicKeySpkiBase64, 'embedded update root public key')
  const manifestBytes = Buffer.from(canonicalUpdateManifest(manifest), 'utf8')

  if (envelope.schema === 1) {
    const signature = checkedSignature(envelope.signature, 'update signature')
    if (manifest.keyId !== expectedRootKeyId || signature.keyId !== expectedRootKeyId) {
      throw new Error('legacy signed update does not use the expected root key')
    }
    if (!verifySignature(null, manifestBytes, rootPublicKey, signature.signature)) {
      throw new Error('signed update envelope signature is invalid')
    }
    return { manifest, keyring: null, keyringSha256: null }
  }

  const keyring = checkedKeyring(envelope.keyring, expectedChannel, expectedVariant)
  const keyringBytes = Buffer.from(canonicalUpdateKeyring(keyring), 'utf8')
  const keyringSignature = checkedSignature(envelope.keyringSignature, 'update keyring signature')
  if (
    keyringSignature.keyId !== expectedRootKeyId ||
    !verifySignature(null, keyringBytes, rootPublicKey, keyringSignature.signature)
  ) {
    throw new Error('update keyring signature is invalid')
  }
  if (!Array.isArray(envelope.signatures) || !envelope.signatures.length || envelope.signatures.length > 16) {
    throw new Error('update manifest signatures are invalid')
  }
  const keys = new Map(keyring.keys.map((key) => [key.keyId, key]))
  const verified = new Set()
  let previous = ''
  for (const value of envelope.signatures) {
    const signature = checkedSignature(value, 'update manifest signature')
    if ((previous && signature.keyId <= previous) || verified.has(signature.keyId)) {
      throw new Error('update manifest signature ids must be unique and ordinal-sorted')
    }
    previous = signature.keyId
    const key = keys.get(signature.keyId)
    if (!key) throw new Error('update manifest signature uses an unknown authorized key')
    if (manifest.sequence < key.notBeforeSequence || manifest.sequence > key.notAfterSequence) {
      throw new Error('update manifest signature key is outside its authorized sequence range')
    }
    if (!verifySignature(null, manifestBytes, checkedPublicKey(key.publicKeySpkiBase64, `authorized update key ${key.keyId}`), signature.signature)) {
      throw new Error(`update manifest signature is invalid for ${key.keyId}`)
    }
    verified.add(signature.keyId)
  }
  if (verified.size < keyring.threshold) throw new Error('update manifest signature threshold was not met')
  if (!verified.has(manifest.keyId)) throw new Error('primary update key is not among the authorized signatures')
  return {
    manifest,
    keyring,
    keyringSha256: createHash('sha256').update(keyringBytes).digest('hex')
  }
}
