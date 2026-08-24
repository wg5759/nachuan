import { createHash } from 'node:crypto'
import { createReadStream, existsSync, lstatSync, readFileSync, statSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { load as loadYaml } from 'js-yaml'

import { assertClosedReleaseOutput } from './release-output.mjs'

const scriptPath = fileURLToPath(import.meta.url)
const desktopRoot = resolve(dirname(scriptPath), '..')
const packageMetadata = JSON.parse(readFileSync(join(desktopRoot, 'package.json'), 'utf8'))
const MAX_UPDATE_METADATA_BYTES = 256 * 1024
const SHA512_BASE64 = /^[A-Za-z0-9+/]{86}==$|^[A-Za-z0-9+/]{87}=$/

function checkedVariant(value) {
  const variant = String(value || '').trim().toLowerCase()
  if (!['lean', 'full'].includes(variant)) throw new Error('release variant must be lean or full')
  return variant
}

function decodedArtifactName(value, field) {
  if (typeof value !== 'string' || !value || value.includes('\\') || value.includes('/')) {
    throw new Error(`update metadata ${field} must be a single artifact filename`)
  }
  try {
    return decodeURIComponent(value)
  } catch {
    throw new Error(`update metadata ${field} is not valid URI text`)
  }
}

async function sha512File(path) {
  const hash = createHash('sha512')
  await new Promise((resolvePromise, rejectPromise) => {
    const input = createReadStream(path)
    input.on('data', (chunk) => hash.update(chunk))
    input.once('error', rejectPromise)
    input.once('end', resolvePromise)
  })
  return hash.digest('base64')
}

export async function verifyReleaseMetadata({
  variant,
  releaseTag,
  releaseRoot = join(desktopRoot, 'release'),
  expectedParent = desktopRoot,
  platform = process.platform,
  version = packageMetadata.version,
  artifactStem = 'nachuan',
  releaseTier = 'production'
}) {
  variant = checkedVariant(variant)
  if (!/^v\d+\.\d+\.\d+$/.test(String(releaseTag || ''))) {
    throw new Error('release tag must be an explicit vX.Y.Z tag')
  }
  if (releaseTag !== `v${version}`) {
    throw new Error(`release tag ${releaseTag} does not match desktop version ${version}`)
  }

  const expected = assertClosedReleaseOutput({
    variant,
    releaseRoot,
    expectedParent,
    platform,
    version,
    artifactStem,
    releaseTier,
    allowChecksum: true,
    allowPayloadManifest: true
  })
  const metadataPath = join(releaseRoot, expected.channel)
  if (!existsSync(metadataPath)) throw new Error(`update metadata is missing: ${metadataPath}`)
  const info = lstatSync(metadataPath)
  if (info.isSymbolicLink() || !info.isFile() || info.size <= 0 || info.size > MAX_UPDATE_METADATA_BYTES) {
    throw new Error('update metadata must be a bounded regular file')
  }

  let metadata
  try {
    // Default js-yaml mode rejects duplicate mapping keys; accepting a
    // last-key-wins update manifest would make review and verification diverge.
    metadata = loadYaml(readFileSync(metadataPath, 'utf8'))
  } catch (error) {
    throw new Error(`update metadata is invalid YAML: ${error}`)
  }
  if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) {
    throw new Error('update metadata root must be an object')
  }
  if (String(metadata.version) !== version) {
    throw new Error(`update metadata version does not match desktop version ${version}`)
  }
  if (!Array.isArray(metadata.files) || metadata.files.length !== 1) {
    throw new Error('update metadata must describe exactly one installer')
  }
  const file = metadata.files[0]
  if (!file || typeof file !== 'object' || Array.isArray(file)) {
    throw new Error('update metadata installer entry must be an object')
  }
  if (decodedArtifactName(metadata.path, 'path') !== expected.artifact) {
    throw new Error('update metadata path does not match the expected installer')
  }
  if (decodedArtifactName(file.url, 'files[0].url') !== expected.artifact) {
    throw new Error('update metadata URL does not match the expected installer')
  }
  if (!SHA512_BASE64.test(String(metadata.sha512 || '')) || metadata.sha512 !== file.sha512) {
    throw new Error('update metadata SHA-512 fields are missing or inconsistent')
  }
  const artifactSize = statSync(join(releaseRoot, expected.artifact)).size
  if (!Number.isSafeInteger(file.size) || file.size !== artifactSize) {
    throw new Error('update metadata installer size does not match the final artifact')
  }
  const artifactSha512 = await sha512File(join(releaseRoot, expected.artifact))
  if (metadata.sha512 !== artifactSha512) {
    throw new Error('update metadata SHA-512 does not match the final installer bytes')
  }
  return { artifact: expected.artifact, version }
}

async function main(argv) {
  try {
    const [variant = process.env.DMX_VARIANT, releaseTag = process.env.RELEASE_TAG] = argv
    const result = await verifyReleaseMetadata({ variant, releaseTag })
    console.log(`[release-metadata] OK ${releaseTag}: ${result.artifact}`)
    return 0
  } catch (error) {
    console.error(`[release-metadata] BLOCKED: ${error instanceof Error ? error.message : String(error)}`)
    return 1
  }
}

if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  process.exitCode = await main(process.argv.slice(2))
}
