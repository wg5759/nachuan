// Prepare deterministic, reviewed inputs for electron-builder.
//
// Variants are intentionally explicit:
//   * lean: cloud/BYOK only; no llama runtime and no GGUF.
//   * full: offline local runtime; LLAMA_SRC and MODELS_SRC are mandatory.
//
// Runtime downloads are not a release mechanism. A local-capable package is
// accepted only when every native runtime file and GGUF is bound by SHA-256 in
// local-runtime-manifest.json.
import { createHash } from 'node:crypto'
import { createReadStream } from 'node:fs'
import {
  closeSync,
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  readdirSync,
  realpathSync,
  rmSync,
  writeFileSync
} from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { prepareConnectionSeed } from './release-security.mjs'
import { prepareMediaRuntime } from './media-runtime-policy.mjs'

const scriptPath = fileURLToPath(import.meta.url)
const here = dirname(scriptPath)
const defaultRepoRoot = resolve(here, '..', '..')
const MANIFEST_NAME = 'local-runtime-manifest.json'
const SERVER_NAMES = new Set(['llama-server', 'llama-server.exe'])
const NATIVE_LIBRARY = /(?:\.dll|\.dylib|\.so(?:\..*)?)$/i
const SHA256 = /^[0-9a-f]{64}$/
const MAX_TRUSTED_MANIFEST_BYTES = 1024 * 1024

function ordinalSort(values) {
  return values.sort((left, right) => (left < right ? -1 : left > right ? 1 : 0))
}

function requireVariant(variant) {
  const normalized = String(variant || '').toLowerCase()
  if (!['lean', 'full'].includes(normalized)) {
    throw new Error(`unknown package variant ${JSON.stringify(variant)}; expected lean or full`)
  }
  return normalized
}

function requireSourceDirectory(path, label) {
  if (!path || !existsSync(path)) throw new Error(`${label} is required for a full package`)
  const info = lstatSync(path)
  if (info.isSymbolicLink() || !info.isDirectory()) {
    throw new Error(`${label} must be a real directory, not a link or special file`)
  }
  return realpathSync(path)
}

function regularSourceFiles(root, predicate) {
  const names = ordinalSort(readdirSync(root))
  const selected = []
  const folded = new Set()
  for (const name of names) {
    if (!predicate(name)) continue
    const foldedName = name.toLowerCase()
    if (folded.has(foldedName)) throw new Error(`case-colliding release input: ${name}`)
    folded.add(foldedName)
    const path = join(root, name)
    const info = lstatSync(path)
    if (info.isSymbolicLink() || !info.isFile()) {
      throw new Error(`release input must be a regular file: ${path}`)
    }
    selected.push({ name, path })
  }
  return selected
}

function assertGgufMagic(path) {
  const handle = openSync(path, 'r')
  try {
    const magic = Buffer.alloc(4)
    if (readSync(handle, magic, 0, 4, 0) !== 4 || magic.toString('ascii') !== 'GGUF') {
      throw new Error(`model is not a GGUF file: ${path}`)
    }
  } finally {
    closeSync(handle)
  }
}

async function sha256File(path) {
  const hash = createHash('sha256')
  await new Promise((accept, reject) => {
    const input = createReadStream(path)
    input.on('data', (chunk) => hash.update(chunk))
    input.on('error', reject)
    input.on('end', accept)
  })
  return hash.digest('hex')
}

function readTrustedFullRuntimeManifest(path) {
  if (!path || !existsSync(path)) {
    throw new Error('NACHUAN_FULL_RUNTIME_TRUST_MANIFEST is required for a full package')
  }
  const info = lstatSync(path)
  if (info.isSymbolicLink() || !info.isFile() || info.size <= 0 || info.size > MAX_TRUSTED_MANIFEST_BYTES) {
    throw new Error('full runtime trust manifest must be a bounded regular file')
  }
  let payload
  try {
    payload = JSON.parse(readFileSync(path, 'utf8'))
  } catch (error) {
    throw new Error(`full runtime trust manifest is invalid JSON: ${error}`)
  }
  if (
    !payload ||
    typeof payload !== 'object' ||
    Array.isArray(payload) ||
    Object.keys(payload).sort().join(',') !== 'artifacts,schema' ||
    payload.schema !== 1 ||
    !Array.isArray(payload.artifacts) ||
    payload.artifacts.length < 2 ||
    payload.artifacts.length > 4096
  ) {
    throw new Error('full runtime trust manifest schema/artifacts are invalid')
  }
  const trusted = new Map()
  for (const item of payload.artifacts) {
    if (
      !item ||
      typeof item !== 'object' ||
      Array.isArray(item) ||
      Object.keys(item).sort().join(',') !== 'license,path,role,sha256,size,source'
    ) {
      throw new Error('full runtime trust manifest artifact fields are not canonical')
    }
    const pathValue = String(item.path || '')
    const name = pathValue.split('/').at(-1)?.toLowerCase() || ''
    const validRolePath =
      (item.role === 'llama-server' && pathValue.startsWith('llama/') && SERVER_NAMES.has(name)) ||
      (item.role === 'runtime-dependency' && pathValue.startsWith('llama/') && NATIVE_LIBRARY.test(name)) ||
      (item.role === 'model' && pathValue.startsWith('models/') && name.endsWith('.gguf'))
    if (
      !validRolePath ||
      pathValue.includes('\\') ||
      pathValue.split('/').some((part) => !part || part === '.' || part === '..') ||
      !SHA256.test(String(item.sha256 || '')) ||
      !Number.isSafeInteger(item.size) ||
      item.size <= 0 ||
      typeof item.license !== 'string' ||
      !item.license.trim() ||
      item.license.length > 256 ||
      typeof item.source !== 'string' ||
      item.source.length > 2048
    ) {
      throw new Error(`invalid reviewed full runtime artifact: ${pathValue}`)
    }
    let source
    try {
      source = new URL(item.source)
    } catch {
      throw new Error(`invalid reviewed source URL: ${pathValue}`)
    }
    if (source.protocol !== 'https:' || source.username || source.password || source.hash) {
      throw new Error(`reviewed source URL must be credential-free HTTPS: ${pathValue}`)
    }
    const folded = pathValue.toLowerCase()
    if (trusted.has(folded)) throw new Error(`duplicate reviewed full runtime path: ${pathValue}`)
    trusted.set(folded, item)
  }
  return trusted
}

async function verifyTrustedFullRuntimeFile(file, role, relativePath, trusted) {
  const expected = trusted.get(relativePath.toLowerCase())
  if (!expected || expected.role !== role) {
    throw new Error(`full runtime input is absent from the reviewed manifest: ${relativePath}`)
  }
  const info = lstatSync(file)
  if (info.size !== expected.size || (await sha256File(file)) !== expected.sha256) {
    throw new Error(`full runtime input differs from reviewed size/SHA-256: ${relativePath}`)
  }
}

async function artifact(path, role, relativePath) {
  return { role, path: relativePath.replaceAll('\\', '/'), sha256: await sha256File(path) }
}

function preparedRuntimeFiles(distRoot) {
  const distLlama = join(distRoot, 'llama')
  const distModels = join(distRoot, 'models')
  const files = []
  for (const name of ordinalSort(readdirSync(distLlama))) {
    const path = join(distLlama, name)
    const info = lstatSync(path)
    if (info.isSymbolicLink() || !info.isFile()) {
      throw new Error(`prepared llama runtime must contain only regular files: ${path}`)
    }
    const lower = name.toLowerCase()
    if (lower === 'llama-server.payload') {
      if (process.platform !== 'win32') throw new Error('llama-server.payload is Windows-only')
      files.push({ path, role: 'llama-server', relativePath: 'llama/llama-server.exe' })
    } else if (SERVER_NAMES.has(lower)) {
      if (process.platform === 'win32') {
        throw new Error('prepared Windows llama-server must use the non-executable .payload source name')
      }
      files.push({ path, role: 'llama-server', relativePath: `llama/${name}` })
    } else if (NATIVE_LIBRARY.test(lower)) {
      files.push({ path, role: 'runtime-dependency', relativePath: `llama/${name}` })
    } else {
      throw new Error(`unlisted file in prepared llama runtime: ${name}`)
    }
  }
  for (const name of ordinalSort(readdirSync(distModels))) {
    const path = join(distModels, name)
    const info = lstatSync(path)
    if (info.isSymbolicLink() || !info.isFile() || !name.toLowerCase().endsWith('.gguf')) {
      throw new Error(`prepared models must contain only regular GGUF files: ${path}`)
    }
    assertGgufMagic(path)
    files.push({ path, role: 'model', relativePath: `models/${name}` })
  }
  return files
}

/** Re-hash the prepared tree after any production code-signing mutation. */
export async function writePreparedRuntimeManifest({
  variant,
  distRoot = join(defaultRepoRoot, 'dist')
}) {
  variant = requireVariant(variant)
  distRoot = resolve(distRoot)
  const manifestPath = join(distRoot, MANIFEST_NAME)
  const files = preparedRuntimeFiles(distRoot)
  const servers = files.filter(({ role }) => role === 'llama-server')
  const models = files.filter(({ role }) => role === 'model')
  if (variant === 'full' && (servers.length !== 1 || models.length < 1)) {
    throw new Error(
      `full package requires one prepared llama-server and at least one GGUF; found servers=${servers.length}, models=${models.length}`
    )
  }
  if (variant === 'lean' && files.length) {
    throw new Error('lean package prepared runtime directories must be empty')
  }
  const artifacts = []
  for (const file of files) {
    artifacts.push(await artifact(file.path, file.role, file.relativePath))
  }
  artifacts.sort((left, right) =>
    left.path < right.path ? -1 : left.path > right.path ? 1 : left.role.localeCompare(right.role)
  )
  const manifest = { schema: 1, artifacts }
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8')
  return {
    manifestPath,
    artifactCount: artifacts.length,
    modelCount: models.length,
    runtimeDependencyCount: artifacts.filter(({ role }) => role === 'runtime-dependency').length
  }
}

/**
 * Build a deterministic local runtime tree and its path-bound audit manifest.
 * The returned manifest contains no timestamps or machine-specific absolute paths.
 */
export async function prepareLocalRuntime({
  variant,
  llamaSrc,
  modelsSrc,
  trustedManifestPath,
  distRoot = join(defaultRepoRoot, 'dist')
}) {
  variant = requireVariant(variant)
  distRoot = resolve(distRoot)
  const distLlama = join(distRoot, 'llama')
  const distModels = join(distRoot, 'models')
  const manifestPath = join(distRoot, MANIFEST_NAME)

  rmSync(distLlama, { recursive: true, force: true })
  rmSync(distModels, { recursive: true, force: true })
  rmSync(manifestPath, { force: true })
  mkdirSync(distLlama, { recursive: true })
  mkdirSync(distModels, { recursive: true })

  if (variant === 'full') {
    const trusted = readTrustedFullRuntimeManifest(trustedManifestPath)
    const reviewedLlamaRoot = requireSourceDirectory(llamaSrc, 'LLAMA_SRC')
    const reviewedModelsRoot = requireSourceDirectory(modelsSrc, 'MODELS_SRC')
    const runtimeFiles = regularSourceFiles(
      reviewedLlamaRoot,
      (name) => SERVER_NAMES.has(name.toLowerCase()) || NATIVE_LIBRARY.test(name)
    )
    const servers = runtimeFiles.filter(({ name }) => SERVER_NAMES.has(name.toLowerCase()))
    if (servers.length !== 1) {
      throw new Error(`full package requires exactly one llama-server executable; found ${servers.length}`)
    }

    const models = regularSourceFiles(reviewedModelsRoot, (name) => name.toLowerCase().endsWith('.gguf'))
    if (!models.length) throw new Error('full package requires at least one reviewed GGUF model')

    const selected = [
      ...runtimeFiles.map((file) => ({
        ...file,
        role: SERVER_NAMES.has(file.name.toLowerCase()) ? 'llama-server' : 'runtime-dependency',
        relativePath: `llama/${file.name}`
      })),
      ...models.map((file) => ({ ...file, role: 'model', relativePath: `models/${file.name}` }))
    ]
    if (trusted.size !== selected.length) {
      throw new Error(
        `reviewed full runtime manifest does not exactly match selected inputs: reviewed=${trusted.size}, selected=${selected.length}`
      )
    }
    for (const file of selected) {
      await verifyTrustedFullRuntimeFile(file.path, file.role, file.relativePath, trusted)
    }

    for (const file of runtimeFiles) {
      const isServer = SERVER_NAMES.has(file.name.toLowerCase())
      const destinationName = isServer && process.platform === 'win32' ? 'llama-server.payload' : file.name
      const destination = join(distLlama, destinationName)
      copyFileSync(file.path, destination)
    }
    for (const file of models) {
      assertGgufMagic(file.path)
      const destination = join(distModels, file.name)
      copyFileSync(file.path, destination)
    }
  }
  return writePreparedRuntimeManifest({ variant, distRoot })
}

export async function preparePackage({
  variant,
  repoRoot = defaultRepoRoot,
  llamaSrc = process.env.LLAMA_SRC,
  modelsSrc = process.env.MODELS_SRC,
  trustedManifestPath = process.env.NACHUAN_FULL_RUNTIME_TRUST_MANIFEST,
  mediaRuntimeSrc = process.env.NACHUAN_MEDIA_RUNTIME_SRC,
  targetPlatform = process.platform
}) {
  variant = requireVariant(variant)
  if (targetPlatform !== 'win32') {
    throw new Error('packaged paid-media runtime is approved only for Windows; macOS/Linux release is blocked')
  }
  const distRoot = join(resolve(repoRoot), 'dist')
  const mediaRuntime = await prepareMediaRuntime({
    repoRoot,
    sourceRoot: mediaRuntimeSrc,
    distRoot
  })
  const runtime = await prepareLocalRuntime({
    variant,
    llamaSrc,
    modelsSrc,
    trustedManifestPath,
    distRoot
  })
  const seedDestination = join(distRoot, 'seed-connections.json')
  await prepareConnectionSeed({ destination: seedDestination, variant })
  console.log(
    `[prepare-pack] ${variant}: local runtime manifest artifacts=${runtime.artifactCount}, models=${runtime.modelCount}`
  )
  console.log(
    `[prepare-pack] media runtime: ffmpeg=${mediaRuntime.ffmpeg.sha256} ffprobe=${mediaRuntime.ffprobe.sha256}`
  )
  console.log(`[prepare-pack] ${variant}: packaged connection seed is empty`)
  return { ...runtime, mediaRuntime, seedDestination }
}

async function main(argv) {
  try {
    await preparePackage({ variant: argv[0] || 'lean' })
    return 0
  } catch (error) {
    console.error(`[prepare-pack] BLOCKED: ${error instanceof Error ? error.message : String(error)}`)
    return 1
  }
}

if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  process.exitCode = await main(process.argv.slice(2))
}
