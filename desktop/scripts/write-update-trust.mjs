import { createPublicKey } from 'node:crypto'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { materializeGeneratedSourceModule } from './generated-source-module.mjs'

const here = dirname(fileURLToPath(import.meta.url))
const output = join(here, '..', 'src', 'main', 'generated-update-trust.ts')
const KEY_ID = /^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$/
const CHANNEL = /^[a-z0-9]+(?:-[a-z0-9]+)*$/
const THUMBPRINT = /^[0-9A-F]{40,128}$/
const SHA256 = /^[0-9a-f]{64}$/

function disabledTrust() {
  return {
    schema: 1,
    enabled: false,
    releaseTier: 'disabled',
    channel: '',
    variant: '',
    keyId: '',
    publicKeySpkiBase64: '',
    manifestUrl: '',
    currentSequence: 0,
    keyringSequence: 0,
    keyringSha256: '',
    publisherName: '',
    signerThumbprint: ''
  }
}

function canonicalBase64(value, label, maxBytes) {
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

export function updateTrustFromEnvironment(env = process.env) {
  const tier = String(env.NACHUAN_UPDATE_TIER || '').trim().toLowerCase()
  if (!tier) return disabledTrust()
  if (tier !== 'early-access' && tier !== 'production') {
    throw new Error('NACHUAN_UPDATE_TIER must be early-access or production')
  }
  const variant = String(env.DMX_VARIANT || '').trim().toLowerCase()
  if (variant !== 'lean' && variant !== 'full') throw new Error('DMX_VARIANT must be lean or full')
  const channel = String(env.NACHUAN_UPDATE_CHANNEL || `${tier}-${variant}-win-x64`).trim()
  if (!CHANNEL.test(channel) || channel.length > 64) throw new Error('NACHUAN_UPDATE_CHANNEL is invalid')
  const keyId = String(env.NACHUAN_UPDATE_KEY_ID || '').trim()
  if (!KEY_ID.test(keyId)) throw new Error('NACHUAN_UPDATE_KEY_ID is invalid')
  const publicKeySpkiBase64 = String(env.NACHUAN_UPDATE_PUBLIC_KEY_SPKI_BASE64 || '').trim()
  const keyBytes = canonicalBase64(publicKeySpkiBase64, 'NACHUAN_UPDATE_PUBLIC_KEY_SPKI_BASE64', 512)
  const publicKey = createPublicKey({ key: keyBytes, format: 'der', type: 'spki' })
  if (publicKey.asymmetricKeyType !== 'ed25519') throw new Error('update public key must be Ed25519')
  const manifestUrl = String(env.NACHUAN_UPDATE_MANIFEST_URL || '').trim()
  let url
  try {
    url = new URL(manifestUrl)
  } catch {
    throw new Error('NACHUAN_UPDATE_MANIFEST_URL is invalid')
  }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash || manifestUrl.length > 2048) {
    throw new Error('NACHUAN_UPDATE_MANIFEST_URL must be credential-free HTTPS')
  }
  if (!/^\d+$/.test(String(env.NACHUAN_UPDATE_SEQUENCE || ''))) {
    throw new Error('NACHUAN_UPDATE_SEQUENCE must be a non-negative integer')
  }
  const currentSequence = Number(env.NACHUAN_UPDATE_SEQUENCE)
  if (!Number.isSafeInteger(currentSequence) || currentSequence < 0) {
    throw new Error('NACHUAN_UPDATE_SEQUENCE is outside the safe integer range')
  }
  const hasKeyringSequence = Object.prototype.hasOwnProperty.call(
    env,
    'NACHUAN_UPDATE_KEYRING_SEQUENCE'
  )
  const hasKeyringSha256 = Object.prototype.hasOwnProperty.call(env, 'NACHUAN_UPDATE_KEYRING_SHA256')
  if (hasKeyringSequence !== hasKeyringSha256) {
    throw new Error('NACHUAN_UPDATE_KEYRING_SEQUENCE and NACHUAN_UPDATE_KEYRING_SHA256 must be set together')
  }
  const rawKeyringSequence = String(
    hasKeyringSequence ? env.NACHUAN_UPDATE_KEYRING_SEQUENCE : '0'
  )
  if (!/^\d+$/.test(rawKeyringSequence)) {
    throw new Error('NACHUAN_UPDATE_KEYRING_SEQUENCE must be a non-negative integer')
  }
  const keyringSequence = Number(rawKeyringSequence)
  if (!Number.isSafeInteger(keyringSequence) || keyringSequence < 0) {
    throw new Error('NACHUAN_UPDATE_KEYRING_SEQUENCE is outside the safe integer range')
  }
  const keyringSha256 = String(hasKeyringSha256 ? env.NACHUAN_UPDATE_KEYRING_SHA256 : '').trim()
  if ((keyringSequence !== 0 || keyringSha256 !== '') && !SHA256.test(keyringSha256)) {
    throw new Error('NACHUAN_UPDATE_KEYRING_SHA256 must bind the embedded keyring floor')
  }
  const publisherName = tier === 'production' ? String(env.NACHUAN_UPDATE_PUBLISHER_NAME || '').trim() : ''
  const signerThumbprint =
    tier === 'production'
      ? String(env.NACHUAN_UPDATE_SIGNER_THUMBPRINT || '').replace(/[^0-9A-Fa-f]/g, '').toUpperCase()
      : ''
  if (tier === 'production' && (!publisherName || !THUMBPRINT.test(signerThumbprint))) {
    throw new Error('production update publisher name and signer thumbprint are required')
  }
  return {
    schema: 1,
    enabled: true,
    releaseTier: tier,
    channel,
    variant,
    keyId,
    publicKeySpkiBase64,
    manifestUrl,
    currentSequence,
    keyringSequence,
    keyringSha256,
    publisherName,
    signerThumbprint
  }
}

export function renderUpdateTrustModule(trust) {
  const header =
    trust?.enabled === false
      ? '// Source-control template for clean-checkout tests; release workflows replace and separately freeze it.\n'
      : '// Generated by scripts/write-update-trust.mjs; do not hand-edit.\n'
  return (
    header +
    "import type { EmbeddedUpdateTrust } from './update-security'\n\n" +
    `export const EMBEDDED_UPDATE_TRUST: EmbeddedUpdateTrust = Object.freeze(${JSON.stringify(trust, null, 2)})\n`
  )
}

export async function materializeUpdateTrustModule({
  output: target = output,
  env = process.env,
  operation = 'write'
} = {}) {
  const trust = updateTrustFromEnvironment(env)
  const result = await materializeGeneratedSourceModule({
    output: target,
    content: renderUpdateTrustModule(trust),
    operation
  })
  return { ...result, trust }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  try {
    const operation = process.argv[2] || 'write'
    const { trust } = await materializeUpdateTrustModule({ operation })
    console.log(
      trust.enabled
        ? `[update-trust] ${operation === 'check' ? 'verified' : 'embedded'} ${trust.releaseTier}/${trust.channel} key=${trust.keyId}`
        : `[update-trust] ${operation === 'check' ? 'verified disabled module' : 'disabled (no update tier configured)'}`
    )
  } catch (error) {
    console.error(`[update-trust] BLOCKED: ${error instanceof Error ? error.message : String(error)}`)
    process.exitCode = 1
  }
}
