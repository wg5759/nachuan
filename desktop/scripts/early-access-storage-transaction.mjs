import { createHash, randomBytes } from 'node:crypto'
import { createReadStream, lstatSync, readFileSync } from 'node:fs'
import { isIP } from 'node:net'
import { basename, dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { verifyFinalReleaseOutput } from './release-output.mjs'
import { RELEASE_EVIDENCE_FILES, verifyReleaseEvidence } from './release-evidence.mjs'
import { verifySignedUpdateEnvelopeForRelease } from './sign-update-manifest.mjs'
import { readPackagedUpdateTrust } from './_verify_pack.mjs'
import { verifyTreeAgainstManifest } from './installer-closure.mjs'

const scriptPath = fileURLToPath(import.meta.url)
const desktopRoot = resolve(dirname(scriptPath), '..')
const defaultReleaseRoot = join(desktopRoot, 'release')
const packageMetadata = JSON.parse(readFileSync(join(desktopRoot, 'package.json'), 'utf8'))
const SAFE_OBJECT = /^[0-9A-Za-z._/-]+$/
const MAX_SMALL_OBJECT_BYTES = 1024 * 1024
const PUBLIC_WRITE_DENIAL_STATUSES = new Set([401, 403, 404, 405, 501])
const COOPERATIVE_FETCH_DEADLINE_MS = 15 * 60 * 1000

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

function checkedBaseUrl(value, label, allowLocalHttp) {
  let url
  try {
    url = new URL(String(value || ''))
  } catch {
    throw new Error(`${label} is invalid`)
  }
  const local = allowLocalHttp && url.protocol === 'http:' && isLoopbackBase(url)
  if ((!local && url.protocol !== 'https:') || url.username || url.password || url.search || url.hash) {
    throw new Error(`${label} must be credential-free HTTPS`)
  }
  const host = url.hostname.toLowerCase()
  if (
    !local &&
    (host.endsWith('.test') ||
      host.endsWith('.invalid') ||
      host === 'example.com' ||
      host.endsWith('.example.com') ||
      host === 'localhost')
  ) {
    throw new Error(`${label} cannot use a test/non-public origin`)
  }
  if (!url.pathname.endsWith('/')) url.pathname += '/'
  return url
}

function objectUrl(base, key, verification = false) {
  if (!SAFE_OBJECT.test(key) || key.startsWith('/') || key.split('/').some((part) => !part || part === '.' || part === '..')) {
    throw new Error(`unsafe update object key: ${key}`)
  }
  const url = new URL(key.split('/').map(encodeURIComponent).join('/'), base)
  if (verification) url.searchParams.set('nachuan_verify', String(Date.now()))
  return url
}

function authorizationHeaders(token) {
  return token ? { authorization: `Bearer ${token}` } : {}
}

function isLoopbackBase(url) {
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, '')
  const family = isIP(host)
  if (family === 4) return Number(host.split('.')[0]) === 127
  // Deliberately reject IPv4-mapped IPv6 and every other IPv6 spelling.
  return family === 6 && host === '::1'
}

function checkedPublisherCredential(value, { allowMissing }) {
  const credential = String(value || '')
  if (!credential) {
    if (allowMissing) return ''
    throw new Error('a non-loopback update publisher credential is required')
  }
  if (credential.length > 16 * 1024 || /[\u0000-\u001f\u007f]/.test(credential)) {
    throw new Error('update publisher credential is invalid')
  }
  return credential
}

async function fetchChecked(fetchImpl, url, options) {
  return await fetchImpl(url, { ...options, signal: AbortSignal.timeout(120_000) })
}

async function drainFailure(response, label) {
  try {
    await response.body?.cancel()
  } catch {
    // The status is sufficient; never echo a server body that may reflect credentials.
  }
  throw new Error(`${label} failed HTTP ${response.status}`)
}

async function readBoundedResponse(response, maxBytes) {
  if (!response.body) return Buffer.alloc(0)
  const chunks = []
  let size = 0
  for await (const chunk of response.body) {
    size += chunk.length
    if (size > maxBytes) throw new Error('remote update object exceeds the bounded pointer size')
    chunks.push(Buffer.from(chunk))
  }
  return Buffer.concat(chunks, size)
}

async function remoteSmallObject({ fetchImpl, url, token = '', maxBytes = MAX_SMALL_OBJECT_BYTES }) {
  const response = await fetchChecked(fetchImpl, url, {
    method: 'GET',
    redirect: 'error',
    headers: { ...authorizationHeaders(token), 'cache-control': 'no-store' }
  })
  if (response.status === 404) return null
  if (!response.ok) await drainFailure(response, 'read update object')
  const bytes = await readBoundedResponse(response, maxBytes)
  const etag = response.headers.get('etag')
  if (!etag) throw new Error('update write endpoint did not return an ETag for atomic replacement')
  return { bytes, etag }
}

async function verifyPublicReadback({ fetchImpl, publicBase, key, expectedSize, expectedSha256 }) {
  const response = await fetchChecked(fetchImpl, objectUrl(publicBase, key, true), {
    method: 'GET',
    redirect: 'error',
    headers: { 'cache-control': 'no-store' }
  })
  if (!response.ok) await drainFailure(response, `public readback ${key}`)
  if (!response.body) throw new Error(`public readback ${key} has no body`)
  const hash = createHash('sha256')
  let size = 0
  for await (const chunk of response.body) {
    size += chunk.length
    if (size > expectedSize) throw new Error(`public readback ${key} exceeds expected size`)
    hash.update(chunk)
  }
  if (size !== expectedSize || hash.digest('hex') !== expectedSha256) {
    throw new Error(`public readback hash/size mismatch: ${key}`)
  }
}

async function provePublicEndpointReadOnly({ fetchImpl, publicBase, writeBase, token }) {
  const key = `probes/nachuan-public-write-${randomBytes(16).toString('hex')}.probe`
  const original = randomBytes(32)
  const attempted = Buffer.from(original)
  attempted[0] ^= 0xff
  const publicUrl = objectUrl(publicBase, key)
  let failure
  let result
  try {
    const putResponse = await fetchChecked(fetchImpl, publicUrl, {
      method: 'PUT',
      redirect: 'error',
      headers: {
        'content-length': String(attempted.length),
        'content-type': 'application/octet-stream',
        'if-none-match': '*'
      },
      body: attempted,
      duplex: 'half'
    })
    const putStatus = await responseStatus(putResponse)
    requireEndpointDenial(putStatus, 'PUT', 'public update endpoint')
    await verifyProbeAbsent({
      fetchImpl,
      base: publicBase,
      key,
      label: 'public PUT denial persisted bytes'
    })

    const create = await putBody({
      fetchImpl,
      url: objectUrl(writeBase, key),
      body: original,
      size: original.length,
      token,
      condition: { name: 'if-none-match', value: '*' },
      contentType: 'application/octet-stream'
    })
    if (create.conflict) throw new Error('public endpoint probe key unexpectedly existed before authenticated create')
    const writeState = await remoteSmallObject({
      fetchImpl,
      url: objectUrl(writeBase, key),
      token,
      maxBytes: 64
    })
    const publicState = await remoteSmallObject({
      fetchImpl,
      url: objectUrl(publicBase, key, true),
      maxBytes: 64
    })
    if (
      !writeState ||
      !publicState ||
      !writeState.bytes.equals(original) ||
      !publicState.bytes.equals(original) ||
      publicState.etag !== writeState.etag
    ) {
      throw new Error('public endpoint probe could not establish the original object bytes and ETag')
    }

    const deleteResponse = await fetchChecked(fetchImpl, publicUrl, {
      method: 'DELETE',
      redirect: 'error'
    })
    const deleteStatus = await responseStatus(deleteResponse)
    requireEndpointDenial(deleteStatus, 'DELETE', 'public update endpoint')
    const afterDelete = await remoteSmallObject({
      fetchImpl,
      url: objectUrl(publicBase, key, true),
      maxBytes: 64
    })
    if (
      !afterDelete ||
      afterDelete.etag !== publicState.etag ||
      !afterDelete.bytes.equals(original)
    ) {
      throw new Error('public DELETE denial removed or changed the original object bytes or ETag')
    }
    result = {
      method: 'PUT',
      status: putStatus,
      denied: true,
      putAbsent: true,
      deleteStatus,
      deletePreserved: true
    }
  } catch (error) {
    failure = error
  }
  try {
    await cleanupCapabilityProbe({ fetchImpl, writeBase, publicBase, key, token })
  } catch (cleanupError) {
    throw new Error(
      `public endpoint capability probe cleanup failed: ${cleanupError instanceof Error ? cleanupError.message : String(cleanupError)}`,
      { cause: failure || cleanupError }
    )
  }
  if (failure) throw failure
  return result
}

async function responseStatus(response) {
  const status = response.status
  try {
    await response.body?.cancel()
  } catch {
    // Capability proofs retain status only; response bodies are untrusted.
  }
  return status
}

function requireEndpointDenial(status, operation, endpointLabel) {
  if (!PUBLIC_WRITE_DENIAL_STATUSES.has(status)) {
    if (status >= 200 && status < 300) {
      throw new Error(`${endpointLabel} accepted an anonymous ${operation} (HTTP ${status})`)
    }
    throw new Error(`${endpointLabel} anonymous ${operation} denial could not be proven (HTTP ${status})`)
  }
}

function requireAnonymousDenial(status, operation) {
  requireEndpointDenial(status, operation, 'update write endpoint')
}

async function verifyProbeAbsent({ fetchImpl, base, key, token = '', label }) {
  const response = await fetchChecked(fetchImpl, objectUrl(base, key, true), {
    method: 'GET',
    redirect: 'error',
    headers: { ...authorizationHeaders(token), 'cache-control': 'no-store' }
  })
  if (response.status === 404) {
    await response.body?.cancel()
    return
  }
  await response.body?.cancel()
  throw new Error(`${label} left a readable residual object (HTTP ${response.status})`)
}

async function cleanupCapabilityProbe({ fetchImpl, writeBase, publicBase, key, token }) {
  const response = await fetchChecked(fetchImpl, objectUrl(writeBase, key), {
    method: 'DELETE',
    redirect: 'error',
    headers: {
      ...authorizationHeaders(token)
    }
  })
  const status = await responseStatus(response)
  if (![200, 204, 404].includes(status)) {
    throw new Error(`storage capability probe cleanup failed HTTP ${status}`)
  }
  await verifyProbeAbsent({ fetchImpl, base: writeBase, key, token, label: 'authenticated probe' })
  await verifyProbeAbsent({ fetchImpl, base: publicBase, key, label: 'public probe' })
}

async function proveObjectStoreCapabilities({ fetchImpl, publicBase, writeBase, token }) {
  const key = `probes/nachuan-storage-capability-${randomBytes(16).toString('hex')}.probe`
  const original = randomBytes(32)
  const replacement = Buffer.from(original)
  replacement[0] ^= 0xff
  let etag = ''
  let failure
  let result
  try {
    const anonymousPut = await fetchChecked(fetchImpl, objectUrl(writeBase, key), {
      method: 'PUT',
      redirect: 'error',
      headers: {
        'content-length': String(original.length),
        'content-type': 'application/octet-stream',
        'if-none-match': '*'
      },
      body: original,
      duplex: 'half'
    })
    const anonymousPutStatus = await responseStatus(anonymousPut)
    requireAnonymousDenial(anonymousPutStatus, 'PUT')
    await verifyProbeAbsent({
      fetchImpl,
      base: writeBase,
      key,
      token,
      label: 'anonymous PUT denial persisted bytes on the authenticated endpoint'
    })
    await verifyProbeAbsent({
      fetchImpl,
      base: publicBase,
      key,
      label: 'anonymous PUT denial persisted bytes on the public endpoint'
    })

    const create = await putBody({
      fetchImpl,
      url: objectUrl(writeBase, key),
      body: original,
      size: original.length,
      token,
      condition: { name: 'if-none-match', value: '*' },
      contentType: 'application/octet-stream'
    })
    if (create.conflict) throw new Error('storage capability probe key unexpectedly existed before create-only proof')
    const current = await remoteSmallObject({ fetchImpl, url: objectUrl(writeBase, key), token, maxBytes: 64 })
    if (!current || !current.bytes.equals(original)) {
      throw new Error('storage capability probe authenticated readback did not preserve the created bytes')
    }
    etag = current.etag

    const anonymousDelete = await fetchChecked(fetchImpl, objectUrl(writeBase, key), {
      method: 'DELETE',
      redirect: 'error'
    })
    const anonymousDeleteStatus = await responseStatus(anonymousDelete)
    requireAnonymousDenial(anonymousDeleteStatus, 'DELETE')
    const afterAnonymousDelete = await remoteSmallObject({
      fetchImpl,
      url: objectUrl(writeBase, key),
      token,
      maxBytes: 64
    })
    if (
      !afterAnonymousDelete ||
      afterAnonymousDelete.etag !== etag ||
      !afterAnonymousDelete.bytes.equals(original)
    ) {
      throw new Error('storage capability probe anonymous DELETE denial removed or changed the object')
    }
    await verifyPublicReadback({
      fetchImpl,
      publicBase,
      key,
      expectedSize: original.length,
      expectedSha256: createHash('sha256').update(original).digest('hex')
    })

    const createOnly = await putBody({
      fetchImpl,
      url: objectUrl(writeBase, key),
      body: replacement,
      size: replacement.length,
      token,
      condition: { name: 'if-none-match', value: '*' },
      contentType: 'application/octet-stream'
    })
    if (!createOnly.conflict) {
      throw new Error('storage capability probe create-only If-None-Match replacement was not rejected')
    }
    const afterCreateOnlyConflict = await remoteSmallObject({
      fetchImpl,
      url: objectUrl(writeBase, key),
      token,
      maxBytes: 64
    })
    if (
      !afterCreateOnlyConflict ||
      afterCreateOnlyConflict.etag !== etag ||
      !afterCreateOnlyConflict.bytes.equals(original)
    ) {
      throw new Error('storage capability probe create-only 412 changed the original bytes or ETag')
    }

    const matchingReplace = await putBody({
      fetchImpl,
      url: objectUrl(writeBase, key),
      body: replacement,
      size: replacement.length,
      token,
      condition: { name: 'if-match', value: etag },
      contentType: 'application/octet-stream'
    })
    if (matchingReplace.conflict) {
      throw new Error('storage capability probe matching ETag conditional replacement was not accepted')
    }

    const afterMatchingReplace = await remoteSmallObject({
      fetchImpl,
      url: objectUrl(writeBase, key),
      token,
      maxBytes: 64
    })
    if (
      !afterMatchingReplace ||
      afterMatchingReplace.etag === etag ||
      !afterMatchingReplace.bytes.equals(replacement)
    ) {
      throw new Error('storage capability probe readback did not change after the matching ETag replacement')
    }

    const oldEtagReplace = await putBody({
      fetchImpl,
      url: objectUrl(writeBase, key),
      body: original,
      size: original.length,
      token,
      condition: { name: 'if-match', value: etag },
      contentType: 'application/octet-stream'
    })
    if (!oldEtagReplace.conflict) {
      throw new Error('storage capability probe old ETag If-Match replacement was not rejected')
    }
    const afterOldEtagConflict = await remoteSmallObject({
      fetchImpl,
      url: objectUrl(writeBase, key),
      token,
      maxBytes: 64
    })
    if (
      !afterOldEtagConflict ||
      afterOldEtagConflict.etag !== afterMatchingReplace.etag ||
      !afterOldEtagConflict.bytes.equals(replacement)
    ) {
      throw new Error('storage capability probe content changed after the rejected old ETag replacement')
    }
    await verifyPublicReadback({
      fetchImpl,
      publicBase,
      key,
      expectedSize: replacement.length,
      expectedSha256: createHash('sha256').update(replacement).digest('hex')
    })
    result = {
      anonymousDeleteStatus,
      anonymousPutStatus,
      createOnlyConflict: true,
      matchingEtagReplace: true,
      oldEtagConflict: true
    }
  } catch (error) {
    failure = error
  }

  try {
    // A storage service could persist a body even when its response reports an
    // error. Always clean and prove absence after the first mutating probe.
    await cleanupCapabilityProbe({ fetchImpl, writeBase, publicBase, key, token })
  } catch (cleanupError) {
    throw new Error(
      `storage capability probe cleanup failed: ${cleanupError instanceof Error ? cleanupError.message : String(cleanupError)}`,
      { cause: failure || cleanupError }
    )
  }
  if (failure) throw failure
  return result
}

async function putBody({ fetchImpl, url, body, size, token, condition, contentType }) {
  const headers = {
    ...authorizationHeaders(token),
    'content-length': String(size),
    'content-type': contentType,
    [condition.name]: condition.value
  }
  const response = await fetchChecked(fetchImpl, url, {
    method: 'PUT',
    redirect: 'error',
    headers,
    body,
    duplex: 'half'
  })
  if (response.status === 412) return { conflict: true }
  if (!response.ok) await drainFailure(response, 'write update object')
  return { conflict: false }
}

function objectContentType(name) {
  if (name.endsWith('.json')) return 'application/json'
  if (name.endsWith('.yml')) return 'application/yaml'
  if (name.endsWith('.exe')) return 'application/vnd.microsoft.portable-executable'
  return 'application/octet-stream'
}

function immutableVersionPrefix(manifest) {
  return `channels/${manifest.channel}/variants/${manifest.variant}/versions/${manifest.version}/sequence-${manifest.sequence}`
}

async function putImmutableObject({ fetchImpl, writeBase, publicBase, key, object, token }) {
  const result = await putBody({
    fetchImpl,
    url: objectUrl(writeBase, key),
    body: object.bytes,
    size: object.size,
    token,
    condition: { name: 'if-none-match', value: '*' },
    contentType: objectContentType(key)
  })
  await verifyPublicReadback({
    fetchImpl,
    publicBase,
    key,
    expectedSize: object.size,
    expectedSha256: object.sha256
  })
  return { ...result, size: object.size, sha256: object.sha256 }
}

async function putImmutableBytes({ fetchImpl, writeBase, publicBase, key, bytes, token }) {
  const sha256 = createHash('sha256').update(bytes).digest('hex')
  await putBody({
    fetchImpl,
    url: objectUrl(writeBase, key),
    body: bytes,
    size: bytes.length,
    token,
    condition: { name: 'if-none-match', value: '*' },
    contentType: objectContentType(key)
  })
  await verifyPublicReadback({ fetchImpl, publicBase, key, expectedSize: bytes.length, expectedSha256: sha256 })
}

async function replacePointer({ fetchImpl, writeBase, publicBase, key, object, token, current }) {
  const result = await putBody({
    fetchImpl,
    url: objectUrl(writeBase, key),
    body: object.bytes,
    size: object.size,
    token,
    condition: current
      ? { name: 'if-match', value: current.etag }
      : { name: 'if-none-match', value: '*' },
    contentType: objectContentType(key)
  })
  if (result.conflict) throw new Error(`atomic update pointer compare-and-swap failed: ${key}`)
  await verifyPublicReadback({
    fetchImpl,
    publicBase,
    key,
    expectedSize: object.size,
    expectedSha256: object.sha256
  })
  return current
}

function releaseDescriptorMap(manifest, releaseRoot) {
  const descriptors = new Map()
  for (const descriptor of [...manifest.releaseFiles, ...manifest.reports]) {
    if (descriptors.has(descriptor.name)) throw new Error(`duplicate verified release descriptor: ${descriptor.name}`)
    descriptors.set(descriptor.name, { ...descriptor })
  }
  const manifestName = 'RELEASE_EVIDENCE_MANIFEST.json'
  const manifestBytes = readFileSync(join(releaseRoot, manifestName))
  const expectedManifestBytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, 'utf8')
  if (!manifestBytes.equals(expectedManifestBytes)) {
    throw new Error('verified release evidence manifest bytes drifted after verification')
  }
  descriptors.set(manifestName, {
    name: manifestName,
    size: manifestBytes.length,
    sha256: createHash('sha256').update(manifestBytes).digest('hex')
  })
  return descriptors
}

function freezeVerifiedObjects({ releaseRoot, names, descriptors, retainedEnvelopeName, retainedEnvelopeBytes }) {
  const frozen = new Map()
  for (const name of names) {
    const expected = descriptors.get(name)
    if (!expected) throw new Error(`verified release descriptor is missing: ${name}`)
    const path = join(releaseRoot, name)
    const info = lstatSync(path)
    if (info.isSymbolicLink() || !info.isFile() || info.size <= 0) {
      throw new Error(`verified release file is invalid: ${name}`)
    }
    const bytes = readFileSync(path)
    const digest = createHash('sha256').update(bytes).digest('hex')
    if (bytes.length !== expected.size || digest !== expected.sha256) {
      throw new Error(`verified release file drifted before upload freezing: ${name}`)
    }
    if (name === retainedEnvelopeName && !bytes.equals(retainedEnvelopeBytes)) {
      throw new Error(`verified release file drifted before upload freezing: ${name}`)
    }
    frozen.set(name, { bytes, name, sha256: expected.sha256, size: expected.size })
  }
  return frozen
}

async function verifySignedEnvelope({
  path,
  installerPath,
  variant,
  rootPublicKeySpkiBase64,
  expectedRootKeyId
}) {
  const info = lstatSync(path)
  if (info.isSymbolicLink() || !info.isFile() || info.size <= 0 || info.size > 128 * 1024) {
    throw new Error('signed update envelope must be a bounded regular file')
  }
  const bytes = readFileSync(path)
  const verified = verifySignedUpdateEnvelopeForRelease({
    bytes,
    rootPublicKeySpkiBase64,
    expectedRootKeyId,
    expectedChannel: `early-access-${variant}-win-x64`,
    expectedVariant: variant
  })
  const manifest = verified.manifest
  const installer = lstatSync(installerPath)
  if (
    manifest.version !== packageMetadata.version ||
    manifest.artifact.name !== basename(installerPath) ||
    manifest.artifact.size !== installer.size ||
    manifest.artifact.sha256 !== (await sha256File(installerPath))
  ) {
    throw new Error('signed update envelope does not bind this finalized release')
  }
  return { ...verified, bytes }
}

// Internal, testable storage transaction. This module intentionally has no
// CLI entry point; the public publisher remains fail-closed until signed,
// candidate-bound legal and fresh-audit receipts can be verified.
export async function executeEarlyAccessStorageTransaction({
  variant,
  releaseRoot = defaultReleaseRoot,
  publicBaseUrl,
  writeBaseUrl,
  publicKeySpkiBase64,
  expectedKeyId,
  bearerToken = '',
  fetchImpl,
  releaseTag,
  releaseCommit,
  releaseRunId,
  sourceControlClient,
  verificationBarrier
}) {
  if (typeof fetchImpl !== 'function') {
    throw new Error('internal storage transaction requires an explicitly injected fetch implementation')
  }
  if (variant !== 'lean' && variant !== 'full') throw new Error('variant must be lean or full')
  const publicBase = checkedBaseUrl(publicBaseUrl, 'public update base URL', true)
  const writeBase = checkedBaseUrl(writeBaseUrl, 'update write base URL', true)
  const loopback = isLoopbackBase(publicBase) && isLoopbackBase(writeBase)
  if (!loopback) {
    throw new Error('internal storage transaction is restricted to loopback public and write origins')
  }
  if (publicBase.origin === writeBase.origin) {
    throw new Error('internal storage transaction requires independent loopback public and write origins')
  }
  const injectedFetch = fetchImpl
  // This bounds cooperative fetch calls only. It cannot preempt synchronous
  // local hashing/verification, so a true whole-transaction deadline remains
  // a formal P2 reopening blocker rather than being falsely claimed here.
  const cooperativeFetchSignal = AbortSignal.timeout(COOPERATIVE_FETCH_DEADLINE_MS)
  fetchImpl = (url, options = {}) =>
    injectedFetch(url, {
      ...options,
      signal: options.signal
        ? AbortSignal.any([options.signal, cooperativeFetchSignal])
        : cooperativeFetchSignal
    })
  bearerToken = checkedPublisherCredential(bearerToken, { allowMissing: loopback })
  const projectRoot = resolve(releaseRoot, '..', '..')
  const evidenceManifest = await verifyReleaseEvidence({
    projectRoot,
    releaseRoot,
    variant,
    releaseTier: 'early-access',
    expectedTag: releaseTag,
    expectedCommit: releaseCommit,
    expectedRunId: releaseRunId,
    sourceControlClient,
    sourceComparison: 'portable'
  })
  const expected = await verifyFinalReleaseOutput({
    variant,
    releaseTier: 'early-access',
    releaseRoot,
    expectedParent: dirname(resolve(releaseRoot)),
    requireEvidence: true
  })
  const installerPath = join(releaseRoot, expected.artifact)
  const envelopePath = join(releaseRoot, expected.updateEnvelope)
  const payloadClosure = await verifyTreeAgainstManifest({
    root: join(releaseRoot, 'win-unpacked'),
    manifestPath: join(releaseRoot, 'WIN_UNPACKED_MANIFEST.json')
  })
  if (payloadClosure.version !== packageMetadata.version || payloadClosure.variant !== variant) {
    throw new Error('win-unpacked manifest identity does not match this early-access release')
  }
  const envelope = await verifySignedEnvelope({
    path: envelopePath,
    installerPath,
    variant,
    rootPublicKeySpkiBase64: publicKeySpkiBase64,
    expectedRootKeyId: expectedKeyId
  })
  const packagedTrust = readPackagedUpdateTrust(join(releaseRoot, 'win-unpacked', 'resources'))
  const expectedManifestUrl = new URL(expected.updateEnvelope, publicBase).toString()
  if (
    packagedTrust.schema !== 1 ||
    packagedTrust.enabled !== true ||
    packagedTrust.releaseTier !== 'early-access' ||
    packagedTrust.variant !== variant ||
    packagedTrust.channel !== envelope.manifest.channel ||
    packagedTrust.keyId !== expectedKeyId ||
    packagedTrust.publicKeySpkiBase64 !== publicKeySpkiBase64 ||
    packagedTrust.manifestUrl !== expectedManifestUrl ||
    packagedTrust.currentSequence !== envelope.manifest.sequence
  ) {
    throw new Error('packaged ASAR update trust does not exactly bind this public release activation')
  }
  if (verificationBarrier !== undefined) {
    if (typeof verificationBarrier !== 'function') throw new Error('publisher verification barrier is invalid')
    await verificationBarrier()
  }
  const immutableNames = [
    expected.artifact,
    expected.blockmap,
    expected.channel,
    expected.updateEnvelope,
    'WIN_UNPACKED_MANIFEST.json',
    'SHA256SUMS',
    ...RELEASE_EVIDENCE_FILES
  ]
  if (new Set(immutableNames).size !== immutableNames.length) {
    throw new Error('verified early-access release object set contains duplicates')
  }
  const descriptors = releaseDescriptorMap(evidenceManifest, releaseRoot)
  const frozenObjects = freezeVerifiedObjects({
    releaseRoot,
    names: immutableNames,
    descriptors,
    retainedEnvelopeName: expected.updateEnvelope,
    retainedEnvelopeBytes: envelope.bytes
  })
  const publicWriteProbe = await provePublicEndpointReadOnly({
    fetchImpl,
    publicBase,
    writeBase,
    token: bearerToken
  })
  const storageCapabilityProbe = await proveObjectStoreCapabilities({
    fetchImpl,
    publicBase,
    writeBase,
    token: bearerToken
  })

  // Read and validate the current authority before uploading any release
  // object. A stale/non-increasing publisher must not reserve immutable names
  // that could deny service to the real next release.
  const previousEnvelope = await remoteSmallObject({
    fetchImpl,
    url: objectUrl(writeBase, expected.updateEnvelope),
    token: bearerToken
  })
  if (previousEnvelope) {
    let previousVerified
    try {
      previousVerified = verifySignedUpdateEnvelopeForRelease({
        bytes: previousEnvelope.bytes,
        rootPublicKeySpkiBase64: publicKeySpkiBase64,
        expectedRootKeyId: expectedKeyId,
        expectedChannel: envelope.manifest.channel,
        expectedVariant: variant
      })
    } catch (error) {
      throw new Error('the currently activated update envelope is not valid release authority', {
        cause: error
      })
    }
    if (envelope.manifest.sequence <= previousVerified.manifest.sequence) {
      throw new Error(
        `new update sequence must be strictly greater than the activated sequence (${previousVerified.manifest.sequence})`
      )
    }
  }

  const versionPrefix = immutableVersionPrefix(envelope.manifest)
  const immutable = immutableNames.map((name) => [`${versionPrefix}/${name}`, name])
  for (const [key, name] of immutable) {
    await putImmutableObject({
      fetchImpl,
      writeBase,
      publicBase,
      key,
      object: frozenObjects.get(name),
      token: bearerToken
    })
  }

  // Preserve the previous activation document. The versioned channel metadata
  // above is immutable and the signed envelope is the only mutable activation
  // object; clients derive the immutable metadata prefix from its signed
  // channel, variant, version and sequence.
  if (previousEnvelope) {
    const historyId = createHash('sha256').update(previousEnvelope.bytes).digest('hex')
    await putImmutableBytes({
      fetchImpl,
      writeBase,
      publicBase,
      key: `history/${variant}/${historyId}/${expected.updateEnvelope}`,
      bytes: previousEnvelope.bytes,
      token: bearerToken
    })
  }

  // One compare-and-swap is the entire activation transaction. A crash before
  // this point leaves only unreachable immutable objects; a conflict leaves the
  // previously signed activation untouched.
  await replacePointer({
    fetchImpl,
    writeBase,
    publicBase,
    key: expected.updateEnvelope,
    object: frozenObjects.get(expected.updateEnvelope),
    token: bearerToken,
    current: previousEnvelope
  })
  return {
    version: envelope.manifest.version,
    sequence: envelope.manifest.sequence,
    channel: envelope.manifest.channel,
    artifact: expected.artifact,
    activatedObject: expected.updateEnvelope,
    metadataBaseUrl: new URL(`${versionPrefix}/`, publicBase).toString(),
    metadataChannel: expected.channel,
    publicWriteProbe,
    storageCapabilityProbe
  }
}
