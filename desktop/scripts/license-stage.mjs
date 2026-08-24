import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import { existsSync, lstatSync, readFileSync, readdirSync } from 'node:fs'
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  buildNpmPayloadLicenseInventory,
  buildPlannedNativeLicenseInventory,
  buildThirdPartyNotices,
  createPythonLicenseEvidenceClient,
  LICENSE_EVIDENCE_FILES,
  validateNativeLicenseRegistry,
  validatePythonLicenseInventory,
  writeLicenseEvidenceFiles
} from './license-evidence.mjs'
import { verifyPreparedElectronRuntime } from './electron-runtime-policy.mjs'
import { createReleaseCommandClient } from './release-evidence.mjs'

const scriptPath = fileURLToPath(import.meta.url)
const defaultProjectRoot = resolve(dirname(scriptPath), '..', '..')
const SHA256 = /^[0-9a-f]{64}$/

export const LICENSE_STAGE_CONTENT_FILES = Object.freeze([
  'BUILD_ENVIRONMENT_PYTHON_SBOM.cdx.json',
  'NATIVE_PAYLOAD_LICENSES.json',
  'NPM_PAYLOAD_LICENSES.json',
  ...LICENSE_EVIDENCE_FILES
].sort())
export const LICENSE_STAGE_MANIFEST = 'LICENSE_EVIDENCE_STAGE_MANIFEST.json'
export const PACKAGED_LICENSE_FILES = Object.freeze([...LICENSE_STAGE_CONTENT_FILES, LICENSE_STAGE_MANIFEST].sort())

export function assertNoManualLegalReviewBlockers(npmInventory) {
  const legalBlockers = (npmInventory?.components || []).filter(
    (component) => component.manualLegalReviewRequired === true
  )
  if (legalBlockers.length) {
    throw new Error(
      `production license staging requires upstream license text or manual legal review: ${legalBlockers.map(({ name, version }) => `${name}@${version}`).join(',')}`
    )
  }
}

const canonicalValue = (value) =>
  Array.isArray(value)
    ? value.map(canonicalValue)
    : value && typeof value === 'object'
      ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalValue(value[key])]))
      : value

const canonicalBytes = (value) => Buffer.from(`${JSON.stringify(canonicalValue(value), null, 2)}\n`, 'utf8')
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex')

function fixedStageRoot(projectRoot) {
  return join(resolve(projectRoot), 'desktop', 'build', 'license-evidence')
}

function checkedDirectory(path, label) {
  const info = lstatSync(path)
  if (!info.isDirectory() || info.isSymbolicLink()) throw new Error(`${label} must be a real directory`)
  return path
}

function exactDirectoryFiles(root, names, label) {
  checkedDirectory(root, label)
  const actual = readdirSync(root).sort()
  if (JSON.stringify(actual) !== JSON.stringify([...names].sort())) {
    throw new Error(`${label} is not a closed file set`)
  }
  for (const name of actual) {
    const info = lstatSync(join(root, name))
    if (!info.isFile() || info.isSymbolicLink() || info.size <= 0 || info.size > 96 * 1024 * 1024) {
      throw new Error(`${label} contains an unsafe file: ${name}`)
    }
  }
}

function parseCanonicalJson(path, label) {
  const bytes = readFileSync(path)
  let value
  try {
    value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
  } catch {
    throw new Error(`${label} is not UTF-8 JSON`)
  }
  if (!bytes.equals(canonicalBytes(value))) throw new Error(`${label} is not canonical JSON`)
  return value
}

function execute(command, args, { cwd, env = {}, label } = {}) {
  return new Promise((accept, reject) => {
    execFile(command, args, {
      cwd,
      encoding: 'utf8',
      env: { ...process.env, ...env },
      maxBuffer: 96 * 1024 * 1024,
      timeout: 180_000,
      windowsHide: true
    }, (error, stdout, stderr) => {
      if (error) {
        reject(new Error(`${label || command} failed`, { cause: error }))
        return
      }
      accept({ code: 0, stderr, stdout })
    })
  })
}

function descriptor(root, name) {
  const bytes = readFileSync(join(root, name))
  return { name, sha256: sha256(bytes), size: bytes.length }
}

function readInputs(projectRoot) {
  return {
    packageLock: JSON.parse(readFileSync(join(projectRoot, 'desktop', 'package-lock.json'), 'utf8')),
    registry: JSON.parse(readFileSync(join(projectRoot, 'desktop', 'native-license-registry.json'), 'utf8'))
  }
}

export async function prepareLicenseEvidenceStage({ projectRoot = defaultProjectRoot, pythonSbom }) {
  projectRoot = resolve(projectRoot)
  const stageRoot = fixedStageRoot(projectRoot)
  const buildRoot = dirname(stageRoot)
  if (!existsSync(buildRoot)) await mkdir(buildRoot, { recursive: true })
  checkedDirectory(buildRoot, 'desktop build-resource directory')
  if (existsSync(stageRoot)) {
    checkedDirectory(stageRoot, 'license evidence staging directory')
    await rm(stageRoot, { force: true, recursive: true })
  }
  const npmInventory = buildNpmPayloadLicenseInventory({ projectRoot })
  assertNoManualLegalReviewBlockers(npmInventory)
  await mkdir(stageRoot, { recursive: false })
  try {
    const pythonLicenses = await createPythonLicenseEvidenceClient({ projectRoot, execute }).exportLicenses(pythonSbom)
    const electronRuntime = verifyPreparedElectronRuntime({ projectRoot })
    const { packageLock, registry } = readInputs(projectRoot)
    const nativeInventory = await buildPlannedNativeLicenseInventory({
      electronRuntimeRoot: electronRuntime.extractedRoot,
      packageLock,
      projectRoot,
      pythonLicenses,
      registry
    })
    await writeLicenseEvidenceFiles({ nativeInventory, npmInventory, outputRoot: stageRoot, pythonLicenses })
    await writeFile(join(stageRoot, 'BUILD_ENVIRONMENT_PYTHON_SBOM.cdx.json'), canonicalBytes(pythonSbom), { flag: 'wx' })
    await writeFile(join(stageRoot, 'NATIVE_PAYLOAD_LICENSES.json'), canonicalBytes(nativeInventory), { flag: 'wx' })
    await writeFile(join(stageRoot, 'NPM_PAYLOAD_LICENSES.json'), canonicalBytes(npmInventory), { flag: 'wx' })
    const manifest = canonicalValue({
      files: LICENSE_STAGE_CONTENT_FILES.map((name) => descriptor(stageRoot, name)),
      schema: 1
    })
    await writeFile(join(stageRoot, LICENSE_STAGE_MANIFEST), canonicalBytes(manifest), { flag: 'wx' })
    exactDirectoryFiles(stageRoot, PACKAGED_LICENSE_FILES, 'license evidence staging directory')
    return { manifest, nativeInventory, npmInventory, pythonLicenses, stageRoot }
  } catch (error) {
    if (existsSync(stageRoot)) {
      checkedDirectory(stageRoot, 'partial license evidence staging directory')
      await rm(stageRoot, { force: true, recursive: true })
    }
    throw error
  }
}

function checkedStageManifest(root) {
  const manifest = parseCanonicalJson(join(root, LICENSE_STAGE_MANIFEST), LICENSE_STAGE_MANIFEST)
  if (
    manifest?.schema !== 1 ||
    !Array.isArray(manifest.files) ||
    manifest.files.length !== LICENSE_STAGE_CONTENT_FILES.length
  ) {
    throw new Error('license evidence stage manifest schema is invalid')
  }
  for (let index = 0; index < LICENSE_STAGE_CONTENT_FILES.length; index += 1) {
    const item = manifest.files[index]
    const name = LICENSE_STAGE_CONTENT_FILES[index]
    if (
      Object.keys(item || {}).sort().join(',') !== 'name,sha256,size' ||
      item.name !== name ||
      !SHA256.test(String(item.sha256 || '')) ||
      !Number.isSafeInteger(item.size) ||
      item.size <= 0
    ) {
      throw new Error(`license evidence stage descriptor is invalid: ${name}`)
    }
    const actual = descriptor(root, name)
    if (actual.size !== item.size || actual.sha256 !== item.sha256) {
      throw new Error(`license evidence stage file drifted: ${name}`)
    }
  }
  return manifest
}

export async function verifyPackagedLicenseEvidence({
  appOutDir,
  deferredNativeArtifacts = [],
  projectRoot = defaultProjectRoot
}) {
  projectRoot = resolve(projectRoot)
  appOutDir = resolve(appOutDir)
  const stageRoot = fixedStageRoot(projectRoot)
  const packagedRoot = join(appOutDir, 'resources', 'licenses')
  const { manifest: stageManifest } = await verifyPackagedLicenseStageCopy({ packagedRoot, stageRoot })
  const pythonSbom = parseCanonicalJson(
    join(packagedRoot, 'BUILD_ENVIRONMENT_PYTHON_SBOM.cdx.json'),
    'packaged build-environment Python SBOM'
  )
  const pythonLicenses = parseCanonicalJson(join(packagedRoot, 'PYTHON_LICENSES.json'), 'packaged Python licenses')
  validatePythonLicenseInventory(pythonLicenses, pythonSbom)
  const npmInventory = buildNpmPayloadLicenseInventory({ projectRoot })
  assertNoManualLegalReviewBlockers(npmInventory)
  if (!canonicalBytes(npmInventory).equals(readFileSync(join(packagedRoot, 'NPM_PAYLOAD_LICENSES.json')))) {
    throw new Error('packaged npm payload license inventory drifted from the locked installed graph')
  }
  const { packageLock, registry } = readInputs(projectRoot)
  const nativeInventory = await validateNativeLicenseRegistry({
    deferredNativeArtifacts,
    packageLock,
    projectRoot,
    pythonLicenses,
    registry,
    unpackedRoot: appOutDir
  })
  if (!canonicalBytes(nativeInventory).equals(readFileSync(join(packagedRoot, 'NATIVE_PAYLOAD_LICENSES.json')))) {
    throw new Error('packaged native license inventory drifted from the staged plan')
  }
  const notices = buildThirdPartyNotices({ nativeInventory, npmInventory, pythonLicenses })
  if (
    !canonicalBytes(notices.json).equals(readFileSync(join(packagedRoot, 'THIRD_PARTY_NOTICES.json'))) ||
    !Buffer.from(notices.html, 'utf8').equals(readFileSync(join(packagedRoot, 'THIRD_PARTY_NOTICES.html')))
  ) {
    throw new Error('packaged third-party notices do not match independently recomputed payload evidence')
  }
  return { files: [...PACKAGED_LICENSE_FILES], manifest: stageManifest }
}

export async function verifyPackagedLicenseStageCopy({ packagedRoot, stageRoot }) {
  packagedRoot = resolve(packagedRoot)
  stageRoot = resolve(stageRoot)
  exactDirectoryFiles(stageRoot, PACKAGED_LICENSE_FILES, 'license evidence staging directory')
  exactDirectoryFiles(packagedRoot, PACKAGED_LICENSE_FILES, 'packaged license evidence directory')
  const stageManifest = checkedStageManifest(stageRoot)
  checkedStageManifest(packagedRoot)
  for (const name of PACKAGED_LICENSE_FILES) {
    const staged = await readFile(join(stageRoot, name))
    const packaged = await readFile(join(packagedRoot, name))
    if (!staged.equals(packaged)) throw new Error(`packaged license evidence differs from staging: ${name}`)
  }

  return { files: [...PACKAGED_LICENSE_FILES], manifest: stageManifest }
}

async function main(argv) {
  if (argv.length !== 1 || argv[0] !== 'prepare') {
    throw new Error('usage: license-stage.mjs prepare')
  }
  const pythonSbom = await createReleaseCommandClient({ projectRoot: defaultProjectRoot }).pythonSbom()
  const result = await prepareLicenseEvidenceStage({ projectRoot: defaultProjectRoot, pythonSbom })
  console.log(`[license-stage] PREPARED files=${result.manifest.files.length + 1}`)
}

if (resolve(process.argv[1] || '') === scriptPath) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(error?.stack || error)
    process.exitCode = 1
  })
}
