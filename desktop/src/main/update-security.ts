import {
  createHash,
  createPublicKey,
  timingSafeEqual,
  verify as verifySignature
} from 'node:crypto'
import {
  closeSync,
  createReadStream,
  fstatSync,
  lstatSync,
  openSync,
  realpathSync,
  type Stats
} from 'node:fs'
import { basename, normalize, resolve } from 'node:path'

const MAX_ENVELOPE_BYTES = 128 * 1024
const MAX_INSTALLER_BYTES = 4 * 1024 * 1024 * 1024
const SHA256 = /^[0-9a-f]{64}$/
const STABLE_SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/
const CANONICAL_NAME = /^[0-9A-Za-z][0-9A-Za-z._-]{0,199}\.exe$/
const KEY_ID = /^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$/
const CHANNEL = /^[a-z0-9]+(?:-[a-z0-9]+)*$/

export type UpdateReleaseTier = 'disabled' | 'early-access' | 'production'
export type UpdateVariant = 'lean' | 'full'

export interface EmbeddedUpdateTrust {
  schema: 1
  enabled: boolean
  releaseTier: UpdateReleaseTier
  channel: string
  variant: UpdateVariant | ''
  keyId: string
  publicKeySpkiBase64: string
  manifestUrl: string
  currentSequence: number
  keyringSequence?: number
  keyringSha256?: string
  publisherName: string
  signerThumbprint: string
}

export interface UpdateArtifact {
  name: string
  size: number
  sha256: string
}

export interface VerifiedUpdateManifest {
  schema: 1
  channel: string
  platform: 'win32'
  arch: 'x64'
  variant: UpdateVariant
  version: string
  sequence: number
  keyId: string
  artifact: UpdateArtifact
  keyringSequence?: number
  keyringSha256?: string
}

export interface UpdateSecurityStateV1 {
  schema: 1
  sequence: number
  version: string
  artifactSha256: string
}

export interface UpdateSecurityStateV2 {
  schema: 2
  sequence: number
  version: string
  artifactSha256: string
  keyringSequence: number
  keyringSha256: string
}

export type UpdateSecurityState = UpdateSecurityStateV1 | UpdateSecurityStateV2

export interface UpdateAuthorizedKey {
  keyId: string
  publicKeySpkiBase64: string
  notBeforeSequence: number
  notAfterSequence: number
}

export interface UpdateKeyringAuthorization {
  schema: 1
  channel: string
  variant: UpdateVariant
  sequence: number
  threshold: number
  keys: UpdateAuthorizedKey[]
}

export interface UpdateMetadataLike {
  version: string
  path?: string
  files: Array<{ url: string; size?: number }>
}

export interface AttestedUpdateArtifact {
  path: string
  realPath: string
  size: number
  sha256: string
  dev: number
  ino: number
}

export class UpdateSecurityError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options)
    this.name = 'UpdateSecurityError'
  }
}

function exactKeys(value: Record<string, unknown>, expected: string[], label: string): void {
  const actual = Object.keys(value).sort()
  const wanted = [...expected].sort()
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new UpdateSecurityError(`${label} fields are not canonical`)
  }
}

function asObject(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new UpdateSecurityError(`${label} must be an object`)
  }
  return value as Record<string, unknown>
}

function canonicalBase64(value: unknown, label: string, maxBytes: number): Buffer {
  if (typeof value !== 'string' || !value || value.length > maxBytes * 2) {
    throw new UpdateSecurityError(`${label} is invalid`)
  }
  if (!/^[0-9A-Za-z+/]+={0,2}$/.test(value) || value.length % 4 !== 0) {
    throw new UpdateSecurityError(`${label} is invalid`)
  }
  const bytes = Buffer.from(value, 'base64')
  if (!bytes.length || bytes.length > maxBytes || bytes.toString('base64') !== value) {
    throw new UpdateSecurityError(`${label} is not canonical base64`)
  }
  return bytes
}

function checkedEd25519PublicKey(value: unknown, label: string) {
  const bytes = canonicalBase64(value, label, 512)
  try {
    const key = createPublicKey({ key: bytes, format: 'der', type: 'spki' })
    if (key.asymmetricKeyType !== 'ed25519') throw new Error('not Ed25519')
    return key
  } catch (error) {
    throw new UpdateSecurityError(`${label} is not Ed25519`, { cause: error })
  }
}

function checkedStableVersion(value: unknown, label: string): string {
  const version = String(value || '')
  if (!STABLE_SEMVER.test(version)) throw new UpdateSecurityError(`${label} is not stable SemVer`)
  return version
}

function checkedSequence(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || Number(value) < 0) {
    throw new UpdateSecurityError(`${label} is not a non-negative safe integer`)
  }
  return Number(value)
}

function checkedArtifact(value: unknown, releaseTier: UpdateReleaseTier): UpdateArtifact {
  const artifact = asObject(value, 'update artifact')
  exactKeys(artifact, ['name', 'sha256', 'size'], 'update artifact')
  const name = String(artifact.name || '')
  if (!CANONICAL_NAME.test(name)) throw new UpdateSecurityError('update artifact name is invalid')
  if (releaseTier === 'early-access' && !name.includes('early-access-unsigned')) {
    throw new UpdateSecurityError('early-access installer is missing its unsigned warning label')
  }
  if (
    !Number.isSafeInteger(artifact.size) ||
    Number(artifact.size) < 25 * 1024 * 1024 ||
    Number(artifact.size) > MAX_INSTALLER_BYTES
  ) {
    throw new UpdateSecurityError('update artifact size is outside the release bounds')
  }
  const sha256 = String(artifact.sha256 || '')
  if (!SHA256.test(sha256)) throw new UpdateSecurityError('update artifact SHA-256 is invalid')
  return { name, size: Number(artifact.size), sha256 }
}

export function compareStableVersions(left: string, right: string): number {
  const a = checkedStableVersion(left, 'left version').split('.').map(Number)
  const b = checkedStableVersion(right, 'right version').split('.').map(Number)
  for (let index = 0; index < 3; index += 1) {
    if (a[index] !== b[index]) return a[index] < b[index] ? -1 : 1
  }
  return 0
}

export function validateEmbeddedUpdateTrust(value: EmbeddedUpdateTrust): EmbeddedUpdateTrust {
  const trust = asObject(value, 'embedded update trust')
  const hasKeyringSequence = Object.prototype.hasOwnProperty.call(trust, 'keyringSequence')
  const hasKeyringSha256 = Object.prototype.hasOwnProperty.call(trust, 'keyringSha256')
  if (hasKeyringSequence !== hasKeyringSha256) {
    throw new UpdateSecurityError('embedded update keyring floor is incomplete')
  }
  exactKeys(
    trust,
    [
      'channel',
      'currentSequence',
      'enabled',
      'keyId',
      ...(hasKeyringSequence ? ['keyringSequence', 'keyringSha256'] : []),
      'manifestUrl',
      'publicKeySpkiBase64',
      'publisherName',
      'releaseTier',
      'schema',
      'signerThumbprint',
      'variant'
    ],
    'embedded update trust'
  )
  if (trust.schema !== 1 || typeof trust.enabled !== 'boolean') {
    throw new UpdateSecurityError('embedded update trust schema is invalid')
  }
  const keyringSequence = checkedSequence(
    hasKeyringSequence ? trust.keyringSequence : 0,
    'embedded update keyring sequence'
  )
  const keyringSha256 = hasKeyringSha256 ? String(trust.keyringSha256 || '') : ''
  if (
    (keyringSha256 !== '' && !SHA256.test(keyringSha256)) ||
    (keyringSequence !== 0 && keyringSha256 === '')
  ) {
    throw new UpdateSecurityError('embedded update keyring floor is invalid')
  }
  if (!trust.enabled) {
    if (trust.releaseTier !== 'disabled') {
      throw new UpdateSecurityError('disabled update trust has an enabled release tier')
    }
    if (keyringSequence !== 0 || keyringSha256 !== '') {
      throw new UpdateSecurityError('disabled update trust has an enabled keyring floor')
    }
    return value
  }
  if (trust.releaseTier !== 'early-access' && trust.releaseTier !== 'production') {
    throw new UpdateSecurityError('embedded update release tier is invalid')
  }
  if (trust.variant !== 'lean' && trust.variant !== 'full') {
    throw new UpdateSecurityError('embedded update variant is invalid')
  }
  if (typeof trust.channel !== 'string' || !CHANNEL.test(trust.channel) || trust.channel.length > 64) {
    throw new UpdateSecurityError('embedded update channel is invalid')
  }
  if (typeof trust.keyId !== 'string' || !KEY_ID.test(trust.keyId)) {
    throw new UpdateSecurityError('embedded update key id is invalid')
  }
  checkedSequence(trust.currentSequence, 'embedded update sequence')
  let url: URL
  try {
    url = new URL(String(trust.manifestUrl || ''))
  } catch (error) {
    throw new UpdateSecurityError('embedded update manifest URL is invalid', { cause: error })
  }
  if (
    url.protocol !== 'https:' ||
    url.username ||
    url.password ||
    url.hash ||
    String(trust.manifestUrl).length > 2048
  ) {
    throw new UpdateSecurityError('embedded update manifest URL must be credential-free HTTPS')
  }
  checkedEd25519PublicKey(trust.publicKeySpkiBase64, 'embedded update public key')
  if (trust.releaseTier === 'production') {
    if (typeof trust.publisherName !== 'string' || !trust.publisherName.trim()) {
      throw new UpdateSecurityError('production update publisher is missing')
    }
    if (!/^[0-9A-F]{40,128}$/.test(String(trust.signerThumbprint || ''))) {
      throw new UpdateSecurityError('production update signer thumbprint is invalid')
    }
  } else if (trust.publisherName !== '' || trust.signerThumbprint !== '') {
    throw new UpdateSecurityError('early-access trust must not claim an Authenticode identity')
  }
  return value
}

function parseUpdateState(value: unknown): UpdateSecurityState | null {
  if (value === undefined || value === null) return null
  const state = asObject(value, 'local update security state')
  if (state.schema === 1) {
    exactKeys(state, ['artifactSha256', 'schema', 'sequence', 'version'], 'local update security state')
  } else if (state.schema === 2) {
    exactKeys(
      state,
      ['artifactSha256', 'keyringSequence', 'keyringSha256', 'schema', 'sequence', 'version'],
      'local update security state'
    )
  } else {
    throw new UpdateSecurityError('local update security state schema is invalid')
  }
  const sequence = checkedSequence(state.sequence, 'local update sequence')
  const version = checkedStableVersion(state.version, 'local update version')
  const artifactSha256 = String(state.artifactSha256 || '')
  if (!SHA256.test(artifactSha256)) {
    throw new UpdateSecurityError('local update artifact SHA-256 is invalid')
  }
  if (state.schema === 1) return { schema: 1, sequence, version, artifactSha256 }
  const keyringSequence = checkedSequence(state.keyringSequence, 'local update keyring sequence')
  const keyringSha256 = String(state.keyringSha256 || '')
  if (!SHA256.test(keyringSha256)) {
    throw new UpdateSecurityError('local update keyring SHA-256 is invalid')
  }
  return { schema: 2, sequence, version, artifactSha256, keyringSequence, keyringSha256 }
}

export function canonicalUpdateManifest(manifest: VerifiedUpdateManifest): string {
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

export function canonicalUpdateKeyring(keyring: UpdateKeyringAuthorization): string {
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

function checkedUpdateKeyring(value: unknown, trust: EmbeddedUpdateTrust): UpdateKeyringAuthorization {
  const source = asObject(value, 'update keyring authorization')
  exactKeys(
    source,
    ['channel', 'keys', 'schema', 'sequence', 'threshold', 'variant'],
    'update keyring authorization'
  )
  if (source.schema !== 1 || source.channel !== trust.channel || source.variant !== trust.variant) {
    throw new UpdateSecurityError('update keyring target does not match this build')
  }
  const sequence = checkedSequence(source.sequence, 'update keyring sequence')
  // Keyring policy revisions and release revisions are independent sequence domains.
  // Persisted keyring sequence/hash anti-downgrade is enforced after root verification below.
  if (!Array.isArray(source.keys) || !source.keys.length || source.keys.length > 16) {
    throw new UpdateSecurityError('update keyring keys must be a bounded non-empty array')
  }
  if (!Number.isSafeInteger(source.threshold) || Number(source.threshold) < 1 || Number(source.threshold) > source.keys.length) {
    throw new UpdateSecurityError('update keyring signature threshold is invalid')
  }
  let previous = ''
  const seen = new Set<string>()
  const keys = source.keys.map((value) => {
    const key = asObject(value, 'authorized update key')
    exactKeys(
      key,
      ['keyId', 'notAfterSequence', 'notBeforeSequence', 'publicKeySpkiBase64'],
      'authorized update key'
    )
    const keyId = String(key.keyId || '')
    if (!KEY_ID.test(keyId) || (previous && keyId <= previous) || seen.has(keyId)) {
      throw new UpdateSecurityError('authorized update keys must have unique ordinal-sorted ids')
    }
    previous = keyId
    seen.add(keyId)
    const notBeforeSequence = checkedSequence(key.notBeforeSequence, 'authorized key not-before sequence')
    const notAfterSequence = checkedSequence(key.notAfterSequence, 'authorized key not-after sequence')
    if (notAfterSequence < notBeforeSequence) {
      throw new UpdateSecurityError('authorized key validity sequence range is invalid')
    }
    checkedEd25519PublicKey(key.publicKeySpkiBase64, `authorized update key ${keyId}`)
    return {
      keyId,
      publicKeySpkiBase64: String(key.publicKeySpkiBase64),
      notBeforeSequence,
      notAfterSequence
    }
  })
  return {
    schema: 1,
    channel: trust.channel,
    variant: trust.variant as UpdateVariant,
    sequence,
    threshold: Number(source.threshold),
    keys
  }
}

export function verifySignedUpdateEnvelope(
  rawEnvelope: Buffer | string,
  trustValue: EmbeddedUpdateTrust,
  currentVersionValue: string,
  stateValue?: unknown
): VerifiedUpdateManifest {
  const trust = validateEmbeddedUpdateTrust(trustValue)
  if (!trust.enabled) throw new UpdateSecurityError('automatic updates are not configured in this build')
  const currentVersion = checkedStableVersion(currentVersionValue, 'current application version')
  const bytes = Buffer.isBuffer(rawEnvelope) ? rawEnvelope : Buffer.from(rawEnvelope, 'utf8')
  if (!bytes.length || bytes.length > MAX_ENVELOPE_BYTES) {
    throw new UpdateSecurityError('signed update envelope is outside the size bound')
  }
  const text = bytes.toString('utf8')
  if (!Buffer.from(text, 'utf8').equals(bytes) || text.startsWith('\uFEFF') || text.includes('\0')) {
    throw new UpdateSecurityError('signed update envelope is not canonical UTF-8')
  }
  let decoded: unknown
  try {
    decoded = JSON.parse(text)
  } catch (error) {
    throw new UpdateSecurityError('signed update envelope is invalid JSON', { cause: error })
  }
  const envelope = asObject(decoded, 'signed update envelope')
  if (envelope.schema === 1) {
    exactKeys(envelope, ['manifest', 'schema', 'signature'], 'signed update envelope')
  } else if (envelope.schema === 2) {
    exactKeys(
      envelope,
      ['keyring', 'keyringSignature', 'manifest', 'schema', 'signatures'],
      'signed update envelope'
    )
  } else {
    throw new UpdateSecurityError('signed update envelope schema is invalid')
  }

  const source = asObject(envelope.manifest, 'signed update manifest')
  exactKeys(
    source,
    ['arch', 'artifact', 'channel', 'keyId', 'platform', 'schema', 'sequence', 'variant', 'version'],
    'signed update manifest'
  )
  if (source.schema !== 1 || source.platform !== 'win32' || source.arch !== 'x64') {
    throw new UpdateSecurityError('signed update target is unsupported')
  }
  if (source.channel !== trust.channel || source.variant !== trust.variant) {
    throw new UpdateSecurityError('signed update channel or variant does not match this build')
  }
  if (typeof source.keyId !== 'string' || !KEY_ID.test(source.keyId)) {
    throw new UpdateSecurityError('signed update key id is invalid')
  }
  const manifest: VerifiedUpdateManifest = {
    schema: 1,
    channel: source.channel,
    platform: 'win32',
    arch: 'x64',
    variant: source.variant as UpdateVariant,
    version: checkedStableVersion(source.version, 'signed update version'),
    sequence: checkedSequence(source.sequence, 'signed update sequence'),
    keyId: source.keyId,
    artifact: checkedArtifact(source.artifact, trust.releaseTier)
  }
  const state = parseUpdateState(stateValue)

  if (envelope.schema === 1) {
    if (manifest.keyId !== trust.keyId) {
      throw new UpdateSecurityError('signed update key id does not match this build')
    }
    if (state?.schema === 2 || (trust.keyringSha256 ?? '') !== '') {
      throw new UpdateSecurityError('legacy update authority would roll back the accepted keyring')
    }
    const signatureDocument = asObject(envelope.signature, 'update signature')
    exactKeys(signatureDocument, ['algorithm', 'keyId', 'value'], 'update signature')
    if (signatureDocument.algorithm !== 'Ed25519' || signatureDocument.keyId !== manifest.keyId) {
      throw new UpdateSecurityError('update signature algorithm or key id is invalid')
    }
    const signature = canonicalBase64(signatureDocument.value, 'Ed25519 signature', 64)
    if (signature.length !== 64) throw new UpdateSecurityError('Ed25519 signature length is invalid')
    if (
      !verifySignature(
        null,
        Buffer.from(canonicalUpdateManifest(manifest), 'utf8'),
        checkedEd25519PublicKey(trust.publicKeySpkiBase64, 'embedded update public key'),
        signature
      )
    ) {
      throw new UpdateSecurityError('signed update manifest signature is invalid')
    }
  } else {
    const keyring = checkedUpdateKeyring(envelope.keyring, trust)
    const canonicalKeyring = canonicalUpdateKeyring(keyring)
    const keyringSha256 = createHash('sha256').update(canonicalKeyring).digest('hex')
    const rootSignatureDocument = asObject(envelope.keyringSignature, 'update keyring signature')
    exactKeys(rootSignatureDocument, ['algorithm', 'keyId', 'value'], 'update keyring signature')
    if (
      rootSignatureDocument.algorithm !== 'Ed25519' ||
      rootSignatureDocument.keyId !== trust.keyId
    ) {
      throw new UpdateSecurityError('update keyring signer does not match the embedded trust root')
    }
    const rootSignature = canonicalBase64(
      rootSignatureDocument.value,
      'update keyring Ed25519 signature',
      64
    )
    if (
      rootSignature.length !== 64 ||
      !verifySignature(
        null,
        Buffer.from(canonicalKeyring, 'utf8'),
        checkedEd25519PublicKey(trust.publicKeySpkiBase64, 'embedded update public key'),
        rootSignature
      )
    ) {
      throw new UpdateSecurityError('update keyring signature is invalid')
    }
    const embeddedKeyringSequence = trust.keyringSequence ?? 0
    const embeddedKeyringSha256 = trust.keyringSha256 ?? ''
    if (
      keyring.sequence < embeddedKeyringSequence ||
      (embeddedKeyringSha256 !== '' &&
        keyring.sequence === embeddedKeyringSequence &&
        keyringSha256 !== embeddedKeyringSha256)
    ) {
      throw new UpdateSecurityError('update keyring policy would roll back or fork embedded authority')
    }
    if (
      state?.schema === 2 &&
      (keyring.sequence < state.keyringSequence ||
        (keyring.sequence === state.keyringSequence && keyringSha256 !== state.keyringSha256))
    ) {
      throw new UpdateSecurityError('update keyring policy would roll back or fork accepted authority')
    }

    if (!Array.isArray(envelope.signatures) || !envelope.signatures.length || envelope.signatures.length > 16) {
      throw new UpdateSecurityError('update manifest signatures must be a bounded non-empty array')
    }
    const keys = new Map(keyring.keys.map((key) => [key.keyId, key]))
    const verified = new Set<string>()
    let previous = ''
    for (const value of envelope.signatures) {
      const signatureDocument = asObject(value, 'update manifest signature')
      exactKeys(signatureDocument, ['algorithm', 'keyId', 'value'], 'update manifest signature')
      const keyId = String(signatureDocument.keyId || '')
      if (signatureDocument.algorithm !== 'Ed25519' || !KEY_ID.test(keyId)) {
        throw new UpdateSecurityError('update manifest signature identity is invalid')
      }
      if ((previous && keyId <= previous) || verified.has(keyId)) {
        throw new UpdateSecurityError('update manifest signatures must have unique ordinal-sorted key ids')
      }
      previous = keyId
      const key = keys.get(keyId)
      if (!key) throw new UpdateSecurityError('update manifest signature uses an unknown authorized key')
      if (manifest.sequence < key.notBeforeSequence) {
        throw new UpdateSecurityError(`authorized update key ${keyId} not-before sequence has not been reached`)
      }
      if (manifest.sequence > key.notAfterSequence) {
        throw new UpdateSecurityError(`authorized update key ${keyId} not-after sequence was exceeded`)
      }
      const signature = canonicalBase64(signatureDocument.value, 'manifest Ed25519 signature', 64)
      if (
        signature.length !== 64 ||
        !verifySignature(
          null,
          Buffer.from(canonicalUpdateManifest(manifest), 'utf8'),
          checkedEd25519PublicKey(key.publicKeySpkiBase64, `authorized update key ${keyId}`),
          signature
        )
      ) {
        throw new UpdateSecurityError(`update manifest signature is invalid for authorized key ${keyId}`)
      }
      verified.add(keyId)
    }
    if (verified.size < keyring.threshold) {
      throw new UpdateSecurityError('update manifest signature threshold was not met')
    }
    if (!verified.has(manifest.keyId)) {
      throw new UpdateSecurityError('signed update primary key is not among the authorized signatures')
    }
    manifest.keyringSequence = keyring.sequence
    manifest.keyringSha256 = keyringSha256
  }

  if (compareStableVersions(manifest.version, currentVersion) <= 0) {
    throw new UpdateSecurityError('signed update is not newer than the installed version')
  }
  const floor = Math.max(trust.currentSequence, state?.sequence || 0)
  const exactRetry =
    state !== null &&
    manifest.sequence === state.sequence &&
    manifest.version === state.version &&
    manifest.artifact.sha256 === state.artifactSha256
  if (manifest.sequence < floor || (manifest.sequence === floor && !exactRetry)) {
    throw new UpdateSecurityError('signed update sequence would roll back or reuse release authority')
  }
  return manifest
}

function decodedArtifactName(value: string): string {
  try {
    const url = new URL(value, 'https://update-metadata.invalid/')
    return basename(decodeURIComponent(url.pathname))
  } catch (error) {
    throw new UpdateSecurityError('electron update metadata artifact URL is invalid', { cause: error })
  }
}

export function assertUpdateMetadataMatchesManifest(
  info: UpdateMetadataLike,
  manifest: VerifiedUpdateManifest
): void {
  if (!info || info.version !== manifest.version || !Array.isArray(info.files) || info.files.length !== 1) {
    throw new UpdateSecurityError('electron update metadata does not describe the signed release')
  }
  const file = info.files[0]
  if (
    !file ||
    decodedArtifactName(String(file.url || '')) !== manifest.artifact.name ||
    file.size !== manifest.artifact.size
  ) {
    throw new UpdateSecurityError('electron update metadata artifact does not match the signed manifest')
  }
  if (info.path && decodedArtifactName(info.path) !== manifest.artifact.name) {
    throw new UpdateSecurityError('electron update metadata legacy path does not match the signed manifest')
  }
}

function samePath(left: string, right: string): boolean {
  const a = normalize(resolve(left))
  const b = normalize(resolve(right))
  return process.platform === 'win32' ? a.toLowerCase() === b.toLowerCase() : a === b
}

function sameIdentity(left: Stats, right: Stats): boolean {
  return left.dev === right.dev && left.ino === right.ino
}

export async function attestDownloadedUpdateArtifact(
  pathValue: string,
  manifest: VerifiedUpdateManifest,
  options: { requireSignedName?: boolean } = {}
): Promise<AttestedUpdateArtifact> {
  const path = resolve(String(pathValue || ''))
  if (options.requireSignedName !== false && basename(path) !== manifest.artifact.name) {
    throw new UpdateSecurityError('downloaded installer filename does not match the signed manifest')
  }
  const pathBefore = lstatSync(path)
  if (
    pathBefore.isSymbolicLink() ||
    !pathBefore.isFile() ||
    pathBefore.size !== manifest.artifact.size ||
    pathBefore.size > MAX_INSTALLER_BYTES
  ) {
    throw new UpdateSecurityError('downloaded installer is not the signed bounded regular file')
  }
  const realPathBefore = realpathSync.native(path)
  let handle: number | null = null
  try {
    handle = openSync(path, 'r')
    const openedBefore = fstatSync(handle)
    if (
      !openedBefore.isFile() ||
      openedBefore.size !== manifest.artifact.size ||
      !sameIdentity(pathBefore, openedBefore)
    ) {
      throw new UpdateSecurityError('downloaded installer changed identity before hashing')
    }
    const hash = createHash('sha256')
    await new Promise<void>((accept, reject) => {
      const input = createReadStream(path, { fd: handle!, autoClose: false, start: 0 })
      input.on('data', (chunk) => hash.update(chunk))
      input.once('error', reject)
      input.once('end', accept)
    })
    const openedAfter = fstatSync(handle)
    const pathAfter = lstatSync(path)
    const realPathAfter = realpathSync.native(path)
    if (
      !sameIdentity(openedBefore, openedAfter) ||
      openedBefore.size !== openedAfter.size ||
      openedBefore.mtimeMs !== openedAfter.mtimeMs ||
      openedBefore.ctimeMs !== openedAfter.ctimeMs ||
      pathAfter.isSymbolicLink() ||
      !pathAfter.isFile() ||
      !sameIdentity(openedAfter, pathAfter) ||
      !samePath(realPathBefore, realPathAfter)
    ) {
      throw new UpdateSecurityError('downloaded installer changed while hashing')
    }
    const sha256 = hash.digest('hex')
    if (
      !timingSafeEqual(Buffer.from(sha256, 'hex'), Buffer.from(manifest.artifact.sha256, 'hex'))
    ) {
      throw new UpdateSecurityError('downloaded installer SHA-256 does not match the signed manifest')
    }
    return {
      path,
      realPath: realPathAfter,
      size: openedAfter.size,
      sha256,
      dev: openedAfter.dev,
      ino: openedAfter.ino
    }
  } finally {
    if (handle !== null) closeSync(handle)
  }
}

export function assertUpdaterDownloadedPathAgreement(
  returnedPaths: string[],
  eventPath: string,
  manifest: VerifiedUpdateManifest
): string {
  if (!Array.isArray(returnedPaths) || returnedPaths.length !== 1) {
    throw new UpdateSecurityError('updater did not return exactly one downloaded installer path')
  }
  const returned = resolve(String(returnedPaths[0] || ''))
  const event = resolve(String(eventPath || ''))
  if (!samePath(returned, event) || basename(returned) !== manifest.artifact.name) {
    throw new UpdateSecurityError('updater download return/event paths do not match the signed installer')
  }
  return returned
}

export function updateSecurityStateFor(manifest: VerifiedUpdateManifest): UpdateSecurityState {
  if (manifest.keyringSequence !== undefined || manifest.keyringSha256 !== undefined) {
    if (
      !Number.isSafeInteger(manifest.keyringSequence) ||
      Number(manifest.keyringSequence) < 0 ||
      !SHA256.test(String(manifest.keyringSha256 || ''))
    ) {
      throw new UpdateSecurityError('verified update keyring state is incomplete')
    }
    return {
      schema: 2,
      sequence: manifest.sequence,
      version: manifest.version,
      artifactSha256: manifest.artifact.sha256,
      keyringSequence: Number(manifest.keyringSequence),
      keyringSha256: String(manifest.keyringSha256)
    }
  }
  return {
    schema: 1,
    sequence: manifest.sequence,
    version: manifest.version,
    artifactSha256: manifest.artifact.sha256
  }
}
