import { createHash } from 'node:crypto'
import {
  createReadStream,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync
} from 'node:fs'
import { basename, dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { verifyTreeAgainstManifest } from './installer-closure.mjs'

const scriptPath = fileURLToPath(import.meta.url)
const here = dirname(scriptPath)
const desktopRoot = resolve(here, '..')
const defaultReleaseRoot = join(desktopRoot, 'release')
const packageMetadata = JSON.parse(
  await import('node:fs/promises').then(({ readFile }) =>
    readFile(join(desktopRoot, 'package.json'), 'utf8')
  )
)

const PRUNABLE_NAMES = new Set([
  '.icon-ico',
  'builder-debug.yml',
  'builder-effective-config.yaml',
  'builder-effective-config.yml'
])
const MAX_CHECKSUM_BYTES = 32 * 1024
const PAYLOAD_MANIFEST_NAME = 'WIN_UNPACKED_MANIFEST.json'
export const RELEASE_EVIDENCE_FILES = Object.freeze([
  'NATIVE_SBOM.cdx.json',
  'NPM_AUDIT.json',
  'NPM_SBOM.cdx.json',
  'PYTHON_AUDIT.json',
  'PYTHON_SBOM.cdx.json',
  'RELEASE_EVIDENCE_MANIFEST.json'
])

function requireVariant(value) {
  const variant = String(value || '').trim().toLowerCase()
  if (!['lean', 'full'].includes(variant)) {
    throw new Error(`invalid release variant ${JSON.stringify(value)}; expected lean or full`)
  }
  return variant
}

function requireReleaseTier(value) {
  const tier = String(value || 'production').trim().toLowerCase()
  if (!['production', 'early-access'].includes(tier)) {
    throw new Error(`invalid release tier ${JSON.stringify(value)}; expected production or early-access`)
  }
  return tier
}

function assertFixedReleaseRoot(releaseRoot, expectedParent = desktopRoot) {
  const root = resolve(releaseRoot)
  const parent = realpathSync.native(resolve(expectedParent))
  const rootParent = realpathSync.native(dirname(root))
  const samePath = (left, right) =>
    process.platform === 'win32' ? left.toLowerCase() === right.toLowerCase() : left === right
  if (!samePath(rootParent, parent) || basename(root).toLowerCase() !== 'release') {
    throw new Error(`refusing release operation outside the fixed desktop/release directory: ${root}`)
  }
  if (existsSync(root)) {
    const info = lstatSync(root)
    if (!info.isDirectory() || info.isSymbolicLink()) {
      throw new Error('desktop/release must be a real directory, not a link or special file')
    }
    if (!samePath(realpathSync.native(root), join(parent, 'release'))) {
      throw new Error('desktop/release resolved through a filesystem redirect')
    }
  }
  return root
}

export function cleanReleaseOutput({ releaseRoot = defaultReleaseRoot, expectedParent = desktopRoot } = {}) {
  const root = assertFixedReleaseRoot(releaseRoot, expectedParent)
  if (existsSync(root)) rmSync(root, { recursive: true, force: true })
  mkdirSync(root, { recursive: false })
  if (readdirSync(root).length !== 0) throw new Error('release output was not recreated empty')
  return root
}

function expectedArtifactNames({ variant, platform, version, artifactStem, releaseTier }) {
  const platformToken = platform === 'win32' ? 'win' : platform === 'darwin' ? 'mac' : 'linux'
  const extension = platform === 'win32' ? 'exe' : platform === 'darwin' ? 'dmg' : 'AppImage'
  const warning = releaseTier === 'early-access' ? '-early-access-unsigned' : ''
  const artifact = `${artifactStem}-${version}-${variant}${warning}-${platformToken}.${extension}`
  return {
    artifact,
    blockmap: `${artifact}.blockmap`,
    channel: releaseTier === 'early-access' ? `early-access-${variant}.yml` : `${variant}.yml`,
    updateEnvelope:
      releaseTier === 'early-access'
        ? `early-access-${variant}-win-x64.json`
        : `production-${variant}-win-x64.json`,
    unpackedDirectory:
      platform === 'win32' ? 'win-unpacked' : platform === 'linux' ? 'linux-unpacked' : null
  }
}

export function pruneKnownBuilderMetadata({
  releaseRoot = defaultReleaseRoot,
  expectedParent = desktopRoot
} = {}) {
  const root = assertFixedReleaseRoot(releaseRoot, expectedParent)
  for (const name of PRUNABLE_NAMES) {
    const path = join(root, name)
    if (existsSync(path)) rmSync(path, { recursive: true, force: true })
  }
}

export function assertClosedReleaseOutput({
  variant,
  requireChecksum = false,
  allowChecksum = false,
  requirePayloadManifest = false,
  allowPayloadManifest = false,
  releaseRoot = defaultReleaseRoot,
  expectedParent = desktopRoot,
  platform = process.platform,
  version = packageMetadata.version,
  artifactStem = 'nachuan',
  releaseTier = 'production',
  requireChannel = true,
  requireUpdateEnvelope = false,
  allowUpdateEnvelope = false,
  requireEvidence = false,
  allowEvidence = false
}) {
  variant = requireVariant(variant)
  releaseTier = requireReleaseTier(releaseTier)
  const root = assertFixedReleaseRoot(releaseRoot, expectedParent)
  if (!existsSync(root)) throw new Error('release output directory is missing')
  const expected = expectedArtifactNames({ variant, platform, version, artifactStem, releaseTier })
  const requiredFiles = new Set([expected.artifact, expected.blockmap])
  const allowedFiles = new Set(requiredFiles)
  if (requireChannel) {
    requiredFiles.add(expected.channel)
    allowedFiles.add(expected.channel)
  }
  if (requireChecksum) {
    requiredFiles.add('SHA256SUMS')
    allowedFiles.add('SHA256SUMS')
  } else if (allowChecksum) {
    allowedFiles.add('SHA256SUMS')
  }
  if (requirePayloadManifest) {
    requiredFiles.add(PAYLOAD_MANIFEST_NAME)
    allowedFiles.add(PAYLOAD_MANIFEST_NAME)
  } else if (allowPayloadManifest) {
    allowedFiles.add(PAYLOAD_MANIFEST_NAME)
  }
  if (requireUpdateEnvelope) {
    if (!expected.updateEnvelope) throw new Error('this release tier has no independent update envelope name')
    requiredFiles.add(expected.updateEnvelope)
    allowedFiles.add(expected.updateEnvelope)
  } else if (allowUpdateEnvelope && expected.updateEnvelope) {
    allowedFiles.add(expected.updateEnvelope)
  }
  if (requireEvidence) {
    for (const name of RELEASE_EVIDENCE_FILES) {
      requiredFiles.add(name)
      allowedFiles.add(name)
    }
  } else if (allowEvidence) {
    for (const name of RELEASE_EVIDENCE_FILES) allowedFiles.add(name)
  }
  const allowedDirectories = new Set()
  if (expected.unpackedDirectory) allowedDirectories.add(expected.unpackedDirectory)
  if (platform === 'darwin') {
    // electron-builder names the unpacked application directory mac or mac-<arch>.
    for (const name of readdirSync(root)) {
      if (/^mac(?:-[A-Za-z0-9_-]+)?$/.test(name)) allowedDirectories.add(name)
    }
  }

  const seenFiles = new Set()
  const seenDirectories = new Set()
  for (const name of readdirSync(root)) {
    const path = join(root, name)
    const info = lstatSync(path)
    if (info.isSymbolicLink()) throw new Error(`release output contains a filesystem redirect: ${name}`)
    if (info.isDirectory()) {
      if (!allowedDirectories.has(name)) throw new Error(`unexpected release output directory: ${name}`)
      seenDirectories.add(name)
    } else if (info.isFile()) {
      if (!allowedFiles.has(name)) throw new Error(`unexpected release output file: ${name}`)
      seenFiles.add(name)
    } else {
      throw new Error(`release output contains a special file: ${name}`)
    }
  }

  for (const name of requiredFiles) {
    if (!seenFiles.has(name)) throw new Error(`required release artifact is missing: ${name}`)
  }
  for (const name of allowedDirectories) {
    if (!seenDirectories.has(name)) throw new Error(`required unpacked release directory is missing: ${name}`)
  }
  return { root, ...expected }
}

export async function verifyPackagedReleaseOutput(options) {
  const platform = options.platform || process.platform
  const allowPayloadManifest = platform === 'win32'
  const closedOptions = { ...options, platform, allowPayloadManifest }
  const expected = assertClosedReleaseOutput(closedOptions)
  const payloadManifest = join(expected.root, PAYLOAD_MANIFEST_NAME)
  if (existsSync(payloadManifest)) {
    if (!expected.unpackedDirectory) {
      throw new Error('win-unpacked manifest is unsupported for this release target')
    }
    const manifest = await verifyTreeAgainstManifest({
      root: join(expected.root, expected.unpackedDirectory),
      manifestPath: payloadManifest
    })
    const version = String(options.version || packageMetadata.version)
    const variant = requireVariant(options.variant)
    if (manifest.version !== version || manifest.variant !== variant) {
      throw new Error(
        `win-unpacked manifest identity mismatch: expected=${version}/${variant} actual=${manifest.version}/${manifest.variant}`
      )
    }
  }
  // Detect top-level residue introduced while the asynchronous tree hashes ran.
  assertClosedReleaseOutput(closedOptions)
  return expected
}

async function sha256File(path) {
  const hash = createHash('sha256')
  await new Promise((resolvePromise, rejectPromise) => {
    const input = createReadStream(path)
    input.on('data', (chunk) => hash.update(chunk))
    input.once('error', rejectPromise)
    input.once('end', resolvePromise)
  })
  return hash.digest('hex')
}

export async function verifyFinalReleaseOutput(options) {
  const requireUpdateEnvelope = true
  const expected = assertClosedReleaseOutput({
    ...options,
    requireChecksum: true,
    requirePayloadManifest: true,
    requireUpdateEnvelope,
    requireEvidence: options.requireEvidence === true
  })
  const checksumPath = join(expected.root, 'SHA256SUMS')
  const info = lstatSync(checksumPath)
  if (info.isSymbolicLink() || !info.isFile() || info.size <= 0 || info.size > MAX_CHECKSUM_BYTES) {
    throw new Error('SHA256SUMS must be a bounded regular file')
  }
  const text = readFileSync(checksumPath, 'utf8')
  if (text.startsWith('\uFEFF') || text.includes('\0')) {
    throw new Error('SHA256SUMS must be plain UTF-8 without BOM or NUL bytes')
  }
  const lines = text.split(/\r?\n/)
  if (lines.at(-1) === '') lines.pop()
  const names = [expected.artifact, expected.blockmap, expected.channel, PAYLOAD_MANIFEST_NAME]
  if (requireUpdateEnvelope && expected.updateEnvelope) names.push(expected.updateEnvelope)
  if (lines.length !== names.length) {
    throw new Error('SHA256SUMS must contain exactly the final release files')
  }
  for (let index = 0; index < names.length; index += 1) {
    const match = /^([0-9a-f]{64})  ([0-9A-Za-z._-]+)$/.exec(lines[index])
    if (!match || match[2] !== names[index]) {
      throw new Error(`SHA256SUMS entry ${index + 1} is invalid or out of order`)
    }
    const actual = await sha256File(join(expected.root, names[index]))
    if (match[1] !== actual) {
      throw new Error(`SHA256SUMS digest does not match ${names[index]}`)
    }
  }
  return expected
}

async function main(argv) {
  const [operation, rawVariant] = argv
  try {
    if (operation === 'clean') {
      cleanReleaseOutput()
      console.log('[release-output] CLEAN_OK desktop/release')
      return 0
    }
    if (operation === 'prune') {
      const variant = requireVariant(rawVariant || process.env.DMX_VARIANT)
      const configuredTier = String(process.env.NACHUAN_UPDATE_TIER || '').trim().toLowerCase()
      const releaseTier = requireReleaseTier(configuredTier || 'production')
      pruneKnownBuilderMetadata()
      const result = assertClosedReleaseOutput({
        variant,
        releaseTier,
        requireChannel: configuredTier === 'early-access' || configuredTier === 'production'
      })
      console.log(`[release-output] CLOSED_OK ${variant}: ${result.artifact}`)
      return 0
    }
    if (operation === 'assert-final') {
      const variant = requireVariant(rawVariant || process.env.DMX_VARIANT)
      const releaseTier = requireReleaseTier(process.env.NACHUAN_UPDATE_TIER || 'production')
      const result = await verifyFinalReleaseOutput({ variant, releaseTier })
      console.log(`[release-output] FINAL_OK ${variant}: ${result.artifact}`)
      return 0
    }
    throw new Error('usage: release-output.mjs clean | prune <lean|full> | assert-final <lean|full>')
  } catch (error) {
    console.error(`[release-output] BLOCKED: ${error instanceof Error ? error.message : String(error)}`)
    return 1
  }
}

if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  process.exitCode = await main(process.argv.slice(2))
}
