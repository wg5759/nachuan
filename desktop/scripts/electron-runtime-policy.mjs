import { createHash, randomUUID } from 'node:crypto'
import {
  createReadStream,
  createWriteStream,
  existsSync,
  lstatSync,
  readFileSync,
  readdirSync,
  realpathSync
} from 'node:fs'
import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises'
import { createRequire } from 'node:module'
import { dirname, join, relative, resolve, sep } from 'node:path'
import { pipeline } from 'node:stream/promises'
import { fileURLToPath } from 'node:url'

const scriptPath = fileURLToPath(import.meta.url)
const defaultProjectRoot = resolve(dirname(scriptPath), '..', '..')
const SHA256 = /^[0-9a-f]{64}$/
const ARCHIVE_NAME = /^electron-v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)-win32-x64\.zip$/
const MAX_REDIRECTS = 5
const MAX_RUNTIME_FILES = 4096
const MAX_RUNTIME_FILE_BYTES = 1024 * 1024 * 1024
const PROVENANCE_NAME = 'ELECTRON_RUNTIME_PROVENANCE.json'

export function resolveExtractArchiveApi(moduleValue) {
  const candidate = typeof moduleValue === 'function'
    ? moduleValue
    : moduleValue?.extract ?? moduleValue?.default
  if (typeof candidate !== 'function') {
    throw new TypeError('reviewed Electron archive extractor API is unavailable')
  }
  return candidate
}

const canonicalValue = (value) =>
  Array.isArray(value)
    ? value.map(canonicalValue)
    : value && typeof value === 'object'
      ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalValue(value[key])]))
      : value
const canonicalBytes = (value) => Buffer.from(`${JSON.stringify(canonicalValue(value), null, 2)}\n`, 'utf8')
const sha256Bytes = (bytes) => createHash('sha256').update(bytes).digest('hex')

function exactKeys(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be an object`)
  if (Object.keys(value).sort().join(',') !== [...expected].sort().join(',')) {
    throw new Error(`${label} fields are not canonical`)
  }
}

function checkedDirectory(path, label) {
  const info = lstatSync(path)
  if (!info.isDirectory() || info.isSymbolicLink()) throw new Error(`${label} must be a real directory`)
  return realpathSync.native(path)
}

function checkedFile(path, label, { sha256, size } = {}) {
  const info = lstatSync(path)
  if (info.isSymbolicLink() || !info.isFile() || info.size <= 0 || info.size > MAX_RUNTIME_FILE_BYTES) {
    throw new Error(`${label} must be a bounded regular file`)
  }
  if (size !== undefined && info.size !== size) throw new Error(`${label} size drifted`)
  const bytes = readFileSync(path)
  const digest = sha256Bytes(bytes)
  if (sha256 !== undefined && digest !== sha256) throw new Error(`${label} hash drifted`)
  return { sha256: digest, size: info.size }
}

function checkedRuntimeLock(document) {
  exactKeys(document, [
    'arch',
    'archive',
    'archiveSha256',
    'archiveSize',
    'electronNpmIntegrity',
    'electronNpmResolved',
    'licenseFiles',
    'platform',
    'schema',
    'shasumsUrl',
    'sourceUrl',
    'version'
  ], 'Electron runtime lock')
  if (
    document.schema !== 1 ||
    document.platform !== 'win32' ||
    document.arch !== 'x64' ||
    !/^\d+\.\d+\.\d+$/.test(String(document.version || '')) ||
    !ARCHIVE_NAME.test(String(document.archive || '')) ||
    document.archive !== `electron-v${document.version}-win32-x64.zip` ||
    !SHA256.test(String(document.archiveSha256 || '')) ||
    !Number.isSafeInteger(document.archiveSize) ||
    document.archiveSize <= 0
  ) {
    throw new Error('Electron runtime lock identity is invalid')
  }
  const releaseRoot = `https://github.com/electron/electron/releases/download/v${document.version}/`
  if (
    document.sourceUrl !== `${releaseRoot}${document.archive}` ||
    document.shasumsUrl !== `${releaseRoot}SHASUMS256.txt` ||
    document.electronNpmResolved !== `https://registry.npmjs.org/electron/-/electron-${document.version}.tgz` ||
    !/^sha512-[A-Za-z0-9+/]+={0,2}$/.test(String(document.electronNpmIntegrity || ''))
  ) {
    throw new Error('Electron runtime lock provenance is not the exact official release')
  }
  if (!Array.isArray(document.licenseFiles) || document.licenseFiles.length !== 2) {
    throw new Error('Electron runtime lock license set is invalid')
  }
  let previous = ''
  for (const item of document.licenseFiles) {
    exactKeys(item, ['path', 'sha256', 'size'], 'Electron runtime license descriptor')
    if (
      !['LICENSE', 'LICENSES.chromium.html'].includes(item.path) ||
      item.path <= previous ||
      !SHA256.test(String(item.sha256 || '')) ||
      !Number.isSafeInteger(item.size) ||
      item.size <= 0
    ) {
      throw new Error('Electron runtime license descriptor is invalid or unsorted')
    }
    previous = item.path
  }
  return canonicalValue(document)
}

export function readElectronRuntimeLock({ projectRoot = defaultProjectRoot, lockPath } = {}) {
  projectRoot = resolve(projectRoot)
  lockPath = resolve(lockPath || join(projectRoot, 'desktop', 'electron-runtime-lock.json'))
  const bytes = readFileSync(lockPath)
  let document
  try {
    document = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
  } catch {
    throw new Error('Electron runtime lock must be UTF-8 JSON')
  }
  if (!bytes.equals(canonicalBytes(document))) throw new Error('Electron runtime lock must be canonical JSON')
  return checkedRuntimeLock(document)
}

function verifyLockedNpmIdentity(projectRoot, lock) {
  const packageLock = JSON.parse(readFileSync(join(projectRoot, 'desktop', 'package-lock.json'), 'utf8'))
  const electron = packageLock?.packages?.['node_modules/electron']
  if (
    packageLock?.lockfileVersion !== 3 ||
    electron?.version !== lock.version ||
    electron?.resolved !== lock.electronNpmResolved ||
    electron?.integrity !== lock.electronNpmIntegrity ||
    electron?.hasInstallScript !== true
  ) {
    throw new Error('installed Electron runtime identity drifted from package-lock.json and runtime lock')
  }
  const packageRoot = join(projectRoot, 'desktop', 'node_modules', 'electron')
  checkedDirectory(packageRoot, 'installed Electron npm package')
  const packageJson = JSON.parse(readFileSync(join(packageRoot, 'package.json'), 'utf8'))
  const checksums = JSON.parse(readFileSync(join(packageRoot, 'checksums.json'), 'utf8'))
  if (packageJson.version !== lock.version || checksums[lock.archive] !== lock.archiveSha256) {
    throw new Error('installed Electron npm package does not attest the locked official archive checksum')
  }
  return packageRoot
}

function safeRemove(path, label) {
  if (!existsSync(path)) return Promise.resolve()
  const info = lstatSync(path)
  if (info.isSymbolicLink()) throw new Error(`refusing to remove redirected ${label}`)
  return rm(path, { force: true, recursive: info.isDirectory() })
}

async function downloadExact({ destination, expectedSha256, expectedSize, sourceUrl, fetchImpl = fetch }) {
  let current = new URL(sourceUrl)
  let response
  for (let redirects = 0; redirects <= MAX_REDIRECTS; redirects += 1) {
    if (current.protocol !== 'https:' || current.username || current.password || current.hash) {
      throw new Error('Electron runtime download URL must remain credential-free HTTPS')
    }
    if (!['github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com'].includes(current.hostname)) {
      throw new Error(`Electron runtime download redirected to an unapproved host: ${current.hostname}`)
    }
    response = await fetchImpl(current, { redirect: 'manual', signal: AbortSignal.timeout(300_000) })
    if (![301, 302, 303, 307, 308].includes(response.status)) break
    const location = response.headers.get('location')
    if (!location) throw new Error('Electron runtime redirect omitted Location')
    current = new URL(location, current)
  }
  if (!response?.ok || !response.body) throw new Error(`Electron runtime download failed with HTTP ${response?.status}`)
  const declared = response.headers.get('content-length')
  if (declared && Number(declared) !== expectedSize) throw new Error('Electron runtime Content-Length drifted')
  await pipeline(response.body, createWriteStream(destination, { flags: 'wx' }))
  checkedFile(destination, 'downloaded Electron runtime archive', {
    sha256: expectedSha256,
    size: expectedSize
  })
}

function runtimeTree(root) {
  checkedDirectory(root, 'prepared Electron runtime extraction')
  const files = []
  const visit = (directory) => {
    for (const name of readdirSync(directory).sort()) {
      const path = join(directory, name)
      const info = lstatSync(path)
      if (info.isSymbolicLink()) throw new Error('prepared Electron runtime contains a filesystem redirect')
      if (info.isDirectory()) {
        visit(path)
      } else if (info.isFile()) {
        const rel = relative(root, path).split(sep).join('/')
        files.push({ name: rel, ...checkedFile(path, `prepared Electron runtime file ${rel}`) })
      } else {
        throw new Error('prepared Electron runtime contains a special filesystem entry')
      }
      if (files.length > MAX_RUNTIME_FILES) throw new Error('prepared Electron runtime file count is unbounded')
    }
  }
  visit(root)
  return files
}

function validateExtractedRuntime(extractedRoot, lock) {
  const version = readFileSync(join(extractedRoot, 'version'), 'utf8').trim()
  if (version !== lock.version) throw new Error('extracted Electron runtime version drifted')
  checkedFile(join(extractedRoot, 'electron.exe'), 'extracted Electron executable')
  for (const descriptor of lock.licenseFiles) {
    checkedFile(join(extractedRoot, descriptor.path), `extracted Electron ${descriptor.path}`, descriptor)
  }
  const files = runtimeTree(extractedRoot)
  if (!files.some(({ name }) => name === 'electron.exe')) throw new Error('Electron runtime tree omits electron.exe')
  return files
}

function expectedProvenance({ archive, files, lock, lockBytes }) {
  return canonicalValue({
    archive: { name: lock.archive, ...archive, url: lock.sourceUrl },
    electronNpm: { integrity: lock.electronNpmIntegrity, resolved: lock.electronNpmResolved },
    files,
    lock: { sha256: sha256Bytes(lockBytes), size: lockBytes.length },
    officialShasums: {
      line: `${lock.archiveSha256} *${lock.archive}`,
      url: lock.shasumsUrl
    },
    schema: 1,
    target: { arch: lock.arch, platform: lock.platform, version: lock.version }
  })
}

export async function prepareElectronRuntime({
  projectRoot = defaultProjectRoot,
  lockPath,
  download = downloadExact,
  extractArchive
} = {}) {
  projectRoot = resolve(projectRoot)
  checkedDirectory(projectRoot, 'project root')
  const resolvedLockPath = resolve(lockPath || join(projectRoot, 'desktop', 'electron-runtime-lock.json'))
  const lockBytes = readFileSync(resolvedLockPath)
  const lock = readElectronRuntimeLock({ projectRoot, lockPath: resolvedLockPath })
  const electronPackageRoot = verifyLockedNpmIdentity(projectRoot, lock)
  const stageRoot = join(projectRoot, 'desktop', 'build', 'electron-runtime')
  await mkdir(stageRoot, { recursive: true })
  checkedDirectory(stageRoot, 'Electron runtime stage')
  const archivePath = join(stageRoot, lock.archive)
  if (existsSync(archivePath)) {
    try {
      checkedFile(archivePath, 'cached Electron runtime archive', {
        sha256: lock.archiveSha256,
        size: lock.archiveSize
      })
    } catch {
      await safeRemove(archivePath, 'Electron runtime archive')
    }
  }
  if (!existsSync(archivePath)) {
    const candidate = join(stageRoot, `.${lock.archive}.${randomUUID()}.download`)
    try {
      await download({
        destination: candidate,
        expectedSha256: lock.archiveSha256,
        expectedSize: lock.archiveSize,
        sourceUrl: lock.sourceUrl
      })
      checkedFile(candidate, 'candidate Electron runtime archive', {
        sha256: lock.archiveSha256,
        size: lock.archiveSize
      })
      await rename(candidate, archivePath)
    } finally {
      await safeRemove(candidate, 'Electron runtime download candidate')
    }
  }

  extractArchive ||= resolveExtractArchiveApi(
    createRequire(join(electronPackageRoot, 'package.json'))('extract-zip')
  )
  const extractedRoot = join(stageRoot, 'extracted')
  const candidateRoot = join(stageRoot, `.extracted.${randomUUID()}`)
  await safeRemove(candidateRoot, 'Electron runtime extraction candidate')
  await mkdir(candidateRoot, { recursive: false })
  try {
    await extractArchive(archivePath, { dir: candidateRoot })
    validateExtractedRuntime(candidateRoot, lock)
    await safeRemove(extractedRoot, 'prepared Electron runtime extraction')
    await rename(candidateRoot, extractedRoot)
  } finally {
    await safeRemove(candidateRoot, 'Electron runtime extraction candidate')
  }
  const files = validateExtractedRuntime(extractedRoot, lock)
  const archive = checkedFile(archivePath, 'prepared Electron runtime archive', {
    sha256: lock.archiveSha256,
    size: lock.archiveSize
  })
  const provenance = expectedProvenance({ archive, files, lock, lockBytes })
  await safeRemove(join(stageRoot, PROVENANCE_NAME), 'Electron runtime provenance')
  await writeFile(join(stageRoot, PROVENANCE_NAME), canonicalBytes(provenance), { flag: 'wx' })
  return { archivePath, extractedRoot, lock, provenance, stageRoot }
}

export function verifyPreparedElectronRuntime({ projectRoot = defaultProjectRoot, lockPath } = {}) {
  projectRoot = resolve(projectRoot)
  const resolvedLockPath = resolve(lockPath || join(projectRoot, 'desktop', 'electron-runtime-lock.json'))
  const lockBytes = readFileSync(resolvedLockPath)
  const lock = readElectronRuntimeLock({ projectRoot, lockPath: resolvedLockPath })
  verifyLockedNpmIdentity(projectRoot, lock)
  const stageRoot = join(projectRoot, 'desktop', 'build', 'electron-runtime')
  checkedDirectory(stageRoot, 'Electron runtime stage')
  const archivePath = join(stageRoot, lock.archive)
  const extractedRoot = join(stageRoot, 'extracted')
  const archive = checkedFile(archivePath, 'prepared Electron runtime archive', {
    sha256: lock.archiveSha256,
    size: lock.archiveSize
  })
  const files = validateExtractedRuntime(extractedRoot, lock)
  const provenancePath = join(stageRoot, PROVENANCE_NAME)
  const provenanceBytes = readFileSync(provenancePath)
  const provenance = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(provenanceBytes))
  if (!provenanceBytes.equals(canonicalBytes(provenance))) throw new Error('Electron runtime provenance is not canonical')
  const expected = expectedProvenance({ archive, files, lock, lockBytes })
  if (!canonicalBytes(provenance).equals(canonicalBytes(expected))) {
    throw new Error('Electron runtime provenance drifted from archive, lock, or extracted tree')
  }
  return { archivePath, extractedRoot, lock, provenance, stageRoot }
}

async function main(argv) {
  if (argv.length !== 1 || !['prepare', 'verify'].includes(argv[0])) {
    throw new Error('usage: electron-runtime-policy.mjs prepare|verify')
  }
  const result = argv[0] === 'prepare' ? await prepareElectronRuntime() : verifyPreparedElectronRuntime()
  console.log(
    `[electron-runtime] ${argv[0].toUpperCase()} version=${result.lock.version} sha256=${result.lock.archiveSha256}`
  )
}

if (resolve(process.argv[1] || '') === scriptPath) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(error?.stack || error)
    process.exitCode = 1
  })
}
