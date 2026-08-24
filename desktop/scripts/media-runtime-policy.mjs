import { createHash } from 'node:crypto'
import { createReadStream } from 'node:fs'
import {
  closeSync,
  constants,
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
import { dirname, isAbsolute, join, parse, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

const scriptPath = fileURLToPath(import.meta.url)
const defaultRepoRoot = resolve(dirname(scriptPath), '..', '..')

export const MEDIA_RUNTIME_LOCK_SCHEMA = 'nachuan.media-runtime-lock.v1'
export const MEDIA_RUNTIME_MANIFEST_SCHEMA = 'nachuan.media-runtime-manifest.v1'
export const MEDIA_RUNTIME_LOCK_NAME = 'media-runtime-lock.json'
export const MEDIA_RUNTIME_MANIFEST_NAME = 'media-runtime-manifest.json'
export const MEDIA_RUNTIME_STAGE_DIRECTORY = 'media'
export const MEDIA_RUNTIME_NOTICE_DIRECTORY = 'media-notices'

const SHA256 = /^[0-9a-f]{64}$/
const COMMIT = /^[0-9a-f]{40}$/
const REVIEW_DATE = /^20\d{2}-\d{2}-\d{2}$/
const MAX_LOCK_BYTES = 256 * 1024
const MAX_MANIFEST_BYTES = 256 * 1024
const MAX_EXECUTABLE_BYTES = 256 * 1024 * 1024
const MAX_NOTICE_BYTES = 4 * 1024 * 1024
const EXPECTED_ROOT_ENTRIES = Object.freeze(['LICENSE', 'README.txt', 'bin'])
const EXPECTED_BIN_ENTRIES = Object.freeze(['ffmpeg.exe', 'ffprobe.exe'])
const ARTIFACT_POLICY = Object.freeze({
  ffmpeg: Object.freeze({
    installedPath: 'media/ffmpeg.exe',
    sourcePath: 'bin/ffmpeg.exe',
    stagedName: 'ffmpeg.payload'
  }),
  ffprobe: Object.freeze({
    installedPath: 'media/ffprobe.exe',
    sourcePath: 'bin/ffprobe.exe',
    stagedName: 'ffprobe.payload'
  })
})

const canonicalValue = (value) =>
  Array.isArray(value)
    ? value.map(canonicalValue)
    : value && typeof value === 'object'
      ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalValue(value[key])]))
      : value

export const canonicalMediaRuntimeBytes = (value) =>
  Buffer.from(`${JSON.stringify(canonicalValue(value), null, 2)}\n`, 'utf8')

const sha256Bytes = (bytes) => createHash('sha256').update(bytes).digest('hex')

async function sha256File(path) {
  const hash = createHash('sha256')
  await new Promise((accept, reject) => {
    const stream = createReadStream(path)
    stream.on('data', (chunk) => hash.update(chunk))
    stream.once('error', reject)
    stream.once('end', accept)
  })
  return hash.digest('hex')
}

function exactKeys(value, names, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`)
  }
  if (Object.keys(value).sort().join(',') !== [...names].sort().join(',')) {
    throw new Error(`${label} fields are not canonical`)
  }
}

function ordinal(values) {
  return [...values].sort((left, right) => (left < right ? -1 : left > right ? 1 : 0))
}

function assertNoRedirectingComponents(path, label) {
  const absolute = resolve(path)
  const root = parse(absolute).root
  let cursor = root
  for (const part of absolute.slice(root.length).split(sep).filter(Boolean)) {
    cursor = join(cursor, part)
    if (!existsSync(cursor)) break
    if (lstatSync(cursor).isSymbolicLink()) {
      throw new Error(`${label} path must not contain filesystem redirects`)
    }
  }
}

function checkedDirectory(path, label) {
  const absolute = resolve(path)
  assertNoRedirectingComponents(absolute, label)
  const info = lstatSync(absolute)
  if (!info.isDirectory() || info.isSymbolicLink()) {
    throw new Error(`${label} must be a real directory`)
  }
  realpathSync.native(absolute)
  return absolute
}

function assertContained(root, candidate, label) {
  root = resolve(root)
  candidate = resolve(candidate)
  const child = relative(root, candidate)
  if (!child || child.startsWith(`..${sep}`) || child === '..' || isAbsolute(child)) {
    throw new Error(`${label} must be a strict child of the project root`)
  }
  return candidate
}

function checkedRelativePath(value, label) {
  const path = String(value || '')
  if (
    !path ||
    path.includes('\\') ||
    isAbsolute(path) ||
    path.split('/').some((part) => !part || part === '.' || part === '..')
  ) {
    throw new Error(`${label} must be a controlled relative path`)
  }
  return path
}

function checkedBoundedFile(root, relativePath, expectedSize, maxBytes, label) {
  relativePath = checkedRelativePath(relativePath, label)
  const absolute = resolve(root, ...relativePath.split('/'))
  const child = relative(resolve(root), absolute)
  if (!child || child.startsWith(`..${sep}`) || child === '..' || isAbsolute(child)) {
    throw new Error(`${label} escaped its reviewed source root`)
  }
  assertNoRedirectingComponents(absolute, label)
  const info = lstatSync(absolute)
  if (
    info.isSymbolicLink() ||
    !info.isFile() ||
    info.size <= 0 ||
    info.size > maxBytes ||
    info.size !== expectedSize
  ) {
    throw new Error(`${label} must be the exact bounded regular file from the lock`)
  }
  realpathSync.native(absolute)
  return absolute
}

function checkedHttpsUrl(value, label) {
  let parsed
  try {
    parsed = new URL(String(value || ''))
  } catch {
    throw new Error(`${label} is not a valid URL`)
  }
  if (
    parsed.protocol !== 'https:' ||
    parsed.username ||
    parsed.password ||
    parsed.hash ||
    parsed.search ||
    parsed.href !== value
  ) {
    throw new Error(`${label} must be a canonical credential-free HTTPS URL`)
  }
  return parsed
}

function assertExactEntries(root, expected, label) {
  const actual = ordinal(readdirSync(root))
  const wanted = ordinal(expected)
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) {
    throw new Error(`${label} must be a closed file set; found ${JSON.stringify(actual)}`)
  }
}

function assertPeX64(path, label) {
  const handle = openSync(path, 'r')
  try {
    const dos = Buffer.alloc(64)
    if (readSync(handle, dos, 0, dos.length, 0) !== dos.length || dos.toString('ascii', 0, 2) !== 'MZ') {
      throw new Error(`${label} is not a Windows PE executable`)
    }
    const peOffset = dos.readUInt32LE(0x3c)
    if (peOffset < 64 || peOffset > 1024 * 1024) {
      throw new Error(`${label} has an invalid PE header offset`)
    }
    const pe = Buffer.alloc(6)
    if (
      readSync(handle, pe, 0, pe.length, peOffset) !== pe.length ||
      pe.toString('ascii', 0, 4) !== 'PE\0\0' ||
      pe.readUInt16LE(4) !== 0x8664
    ) {
      throw new Error(`${label} is not an x64 PE executable`)
    }
  } finally {
    closeSync(handle)
  }
}

function decodedEvidence(path, label) {
  let text
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(readFileSync(path))
  } catch {
    throw new Error(`${label} must be valid UTF-8 text`)
  }
  if (!text.trim() || text.includes('\0')) throw new Error(`${label} is empty or contains NUL bytes`)
  return text
}

function validateLockPayload(lock) {
  exactKeys(
    lock,
    [
      'archive',
      'artifacts',
      'authenticode',
      'license',
      'platform',
      'readme',
      'releaseAdmission',
      'reviewedOn',
      'schema',
      'source',
      'version'
    ],
    'media runtime lock'
  )
  if (lock.schema !== MEDIA_RUNTIME_LOCK_SCHEMA) throw new Error('media runtime lock schema is unsupported')
  if (lock.platform !== 'win32-x64') throw new Error('media runtime lock platform must be win32-x64')
  if (!REVIEW_DATE.test(String(lock.reviewedOn || ''))) throw new Error('media runtime review date is invalid')
  if (typeof lock.version !== 'string' || !/^[0-9A-Za-z._-]{1,128}$/.test(lock.version)) {
    throw new Error('media runtime version is invalid')
  }
  exactKeys(lock.authenticode, ['signer', 'status', 'timestamp'], 'media runtime Authenticode')
  if (
    lock.authenticode.status !== 'NotSigned' ||
    lock.authenticode.signer !== null ||
    lock.authenticode.timestamp !== null
  ) {
    throw new Error('media runtime must record its actual unsigned Authenticode state')
  }
  exactKeys(
    lock.releaseAdmission,
    ['legalClosure', 'production', 'trustClass'],
    'media runtime release admission'
  )
  if (
    lock.releaseAdmission.legalClosure !== 'incomplete' ||
    lock.releaseAdmission.production !== 'blocked' ||
    lock.releaseAdmission.trustClass !== 'unsigned-fixed-hash-engineering-candidate'
  ) {
    throw new Error('Gyan media runtime release admission must remain blocked')
  }

  exactKeys(lock.archive, ['sha256', 'size', 'url'], 'media runtime archive')
  if (
    !SHA256.test(String(lock.archive.sha256 || '')) ||
    !Number.isSafeInteger(lock.archive.size) ||
    lock.archive.size <= 0 ||
    lock.archive.size > 1024 * 1024 * 1024
  ) {
    throw new Error('media runtime archive descriptor is invalid')
  }
  const archiveUrl = checkedHttpsUrl(lock.archive.url, 'media runtime archive URL')
  if (
    archiveUrl.hostname !== 'www.gyan.dev' ||
    !archiveUrl.pathname.endsWith(`/ffmpeg-${lock.version.replace('-www.gyan.dev', '')}.zip`)
  ) {
    throw new Error('media runtime archive URL is outside the reviewed Gyan release archive')
  }

  exactKeys(lock.source, ['commit', 'url'], 'media runtime source')
  if (!COMMIT.test(String(lock.source.commit || ''))) throw new Error('media runtime source commit is invalid')
  const sourceUrl = checkedHttpsUrl(lock.source.url, 'media runtime source URL')
  if (
    sourceUrl.hostname !== 'github.com' ||
    sourceUrl.pathname !== `/FFmpeg/FFmpeg/commit/${lock.source.commit}`
  ) {
    throw new Error('media runtime source URL is not bound to the reviewed FFmpeg commit')
  }

  exactKeys(lock.license, ['path', 'sha256', 'size', 'spdx'], 'media runtime license')
  if (
    lock.license.path !== 'LICENSE' ||
    lock.license.spdx !== 'GPL-3.0-or-later' ||
    !SHA256.test(String(lock.license.sha256 || '')) ||
    !Number.isSafeInteger(lock.license.size) ||
    lock.license.size <= 0 ||
    lock.license.size > MAX_NOTICE_BYTES
  ) {
    throw new Error('media runtime license descriptor is invalid')
  }

  exactKeys(lock.readme, ['path', 'sha256', 'size'], 'media runtime README')
  if (
    lock.readme.path !== 'README.txt' ||
    !SHA256.test(String(lock.readme.sha256 || '')) ||
    !Number.isSafeInteger(lock.readme.size) ||
    lock.readme.size <= 0 ||
    lock.readme.size > MAX_NOTICE_BYTES
  ) {
    throw new Error('media runtime README descriptor is invalid')
  }

  if (!Array.isArray(lock.artifacts) || lock.artifacts.length !== 2) {
    throw new Error('media runtime lock must contain exactly ffmpeg and ffprobe')
  }
  const roles = []
  for (const item of lock.artifacts) {
    exactKeys(
      item,
      ['installedPath', 'role', 'sha256', 'size', 'sourcePath', 'stagedName'],
      'media runtime artifact'
    )
    const policy = ARTIFACT_POLICY[item.role]
    if (
      !policy ||
      item.installedPath !== policy.installedPath ||
      item.sourcePath !== policy.sourcePath ||
      item.stagedName !== policy.stagedName ||
      !SHA256.test(String(item.sha256 || '')) ||
      !Number.isSafeInteger(item.size) ||
      item.size <= 0 ||
      item.size > MAX_EXECUTABLE_BYTES
    ) {
      throw new Error(`invalid reviewed media runtime artifact: ${String(item.role || '')}`)
    }
    roles.push(item.role)
  }
  if (roles.join(',') !== 'ffmpeg,ffprobe') {
    throw new Error('media runtime artifacts must be ordered ffmpeg then ffprobe')
  }
  return lock
}

export function readReviewedMediaRuntimeLock({
  repoRoot = defaultRepoRoot,
  lockPath = join(resolve(repoRoot), 'desktop', MEDIA_RUNTIME_LOCK_NAME)
} = {}) {
  repoRoot = checkedDirectory(resolve(repoRoot), 'project root')
  lockPath = resolve(lockPath)
  assertContained(repoRoot, lockPath, 'media runtime lock')
  assertNoRedirectingComponents(lockPath, 'media runtime lock')
  const info = lstatSync(lockPath)
  if (info.isSymbolicLink() || !info.isFile() || info.size <= 0 || info.size > MAX_LOCK_BYTES) {
    throw new Error('media runtime lock must be a bounded regular file')
  }
  const bytes = readFileSync(lockPath)
  let lock
  try {
    lock = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
  } catch {
    throw new Error('media runtime lock must be valid UTF-8 JSON')
  }
  validateLockPayload(lock)
  if (!bytes.equals(canonicalMediaRuntimeBytes(lock))) {
    throw new Error('media runtime lock must be canonical JSON')
  }
  return { lock, lockPath, lockSha256: sha256Bytes(bytes) }
}

export function defaultMediaRuntimeSource(repoRoot = defaultRepoRoot) {
  return join(resolve(repoRoot), '安装与维护', '构建输入', 'ffmpeg-8.0.1-essentials_build')
}

async function verifiedSource({ lock, sourceRoot }) {
  sourceRoot = checkedDirectory(sourceRoot, 'NACHUAN_MEDIA_RUNTIME_SRC')
  assertExactEntries(sourceRoot, EXPECTED_ROOT_ENTRIES, 'media runtime source root')
  const binRoot = checkedDirectory(join(sourceRoot, 'bin'), 'media runtime source bin directory')
  assertExactEntries(binRoot, EXPECTED_BIN_ENTRIES, 'media runtime source bin directory')

  const artifacts = []
  for (const item of lock.artifacts) {
    const path = checkedBoundedFile(
      sourceRoot,
      item.sourcePath,
      item.size,
      MAX_EXECUTABLE_BYTES,
      `${item.role} source`
    )
    assertPeX64(path, `${item.role} source`)
    if ((await sha256File(path)) !== item.sha256) {
      throw new Error(`${item.role} source differs from the reviewed SHA-256`)
    }
    artifacts.push({ ...item, path })
  }

  const licensePath = checkedBoundedFile(
    sourceRoot,
    lock.license.path,
    lock.license.size,
    MAX_NOTICE_BYTES,
    'FFmpeg license'
  )
  if ((await sha256File(licensePath)) !== lock.license.sha256) {
    throw new Error('FFmpeg license differs from the reviewed SHA-256')
  }
  const licenseText = decodedEvidence(licensePath, 'FFmpeg license')
  if (!licenseText.includes('GNU GENERAL PUBLIC LICENSE') || !licenseText.includes('Version 3')) {
    throw new Error('FFmpeg license text is not GPL version 3 evidence')
  }

  const readmePath = checkedBoundedFile(
    sourceRoot,
    lock.readme.path,
    lock.readme.size,
    MAX_NOTICE_BYTES,
    'Gyan FFmpeg README'
  )
  if ((await sha256File(readmePath)) !== lock.readme.sha256) {
    throw new Error('Gyan FFmpeg README differs from the reviewed SHA-256')
  }
  const readme = decodedEvidence(readmePath, 'Gyan FFmpeg README')
  if (
    !readme.includes(`Version: ${lock.version}`) ||
    !readme.includes('License: GPL v3') ||
    !readme.includes(`Source Code: https://github.com/FFmpeg/FFmpeg/commit/${lock.source.commit.slice(0, 10)}`)
  ) {
    throw new Error('Gyan FFmpeg README does not bind version, license, and source commit')
  }
  return { artifacts, licensePath, readmePath, sourceRoot }
}

function expectedManifest(lock, lockSha256) {
  return canonicalValue({
    artifacts: lock.artifacts.map(({ installedPath: path, role, sha256, size }) => ({
      path,
      role,
      sha256,
      size
    })),
    distribution: {
      archiveSha256: lock.archive.sha256,
      archiveSize: lock.archive.size,
      archiveUrl: lock.archive.url,
      lockSha256,
      sourceCommit: lock.source.commit,
      sourceUrl: lock.source.url
    },
    authenticode: lock.authenticode,
    license: {
      path: `${MEDIA_RUNTIME_NOTICE_DIRECTORY}/LICENSE`,
      sha256: lock.license.sha256,
      size: lock.license.size,
      spdx: lock.license.spdx
    },
    platform: lock.platform,
    readme: {
      path: `${MEDIA_RUNTIME_NOTICE_DIRECTORY}/README.txt`,
      sha256: lock.readme.sha256,
      size: lock.readme.size
    },
    releaseAdmission: lock.releaseAdmission,
    schema: MEDIA_RUNTIME_MANIFEST_SCHEMA,
    version: lock.version
  })
}

export function assertMediaRuntimeProductionAdmission(lock) {
  validateLockPayload(lock)
  if (
    lock.releaseAdmission.production !== 'approved' ||
    lock.releaseAdmission.legalClosure !== 'complete'
  ) {
    throw new Error(
      'MEDIA_RUNTIME_PRODUCTION_NO_GO: unsigned Gyan engineering candidate lacks corresponding-source/NOTICE closure'
    )
  }
}

function ensureStageParent(repoRoot, distRoot) {
  repoRoot = checkedDirectory(repoRoot, 'project root')
  distRoot = assertContained(repoRoot, distRoot, 'media runtime dist root')
  assertNoRedirectingComponents(distRoot, 'media runtime dist root')
  if (!existsSync(distRoot)) mkdirSync(distRoot, { recursive: true })
  return checkedDirectory(distRoot, 'media runtime dist root')
}

function resetRealDirectory(path, label) {
  if (existsSync(path)) {
    assertNoRedirectingComponents(path, label)
    const info = lstatSync(path)
    if (!info.isDirectory() || info.isSymbolicLink()) {
      throw new Error(`${label} must be a real directory before it can be replaced`)
    }
    // Re-check immediately before the recursive operation.  This is not a
    // same-SID sandbox, but it prevents a replaced junction from turning
    // cleanup into an out-of-tree recursive delete.
    assertNoRedirectingComponents(path, label)
    const finalInfo = lstatSync(path)
    if (!finalInfo.isDirectory() || finalInfo.isSymbolicLink()) {
      throw new Error(`${label} changed before recursive replacement`)
    }
    rmSync(path, { force: true, recursive: true })
  }
  mkdirSync(path, { recursive: false })
  checkedDirectory(path, label)
}

function removeRegularIfPresent(path, label) {
  if (!existsSync(path)) return
  assertNoRedirectingComponents(path, label)
  const info = lstatSync(path)
  if (!info.isFile() || info.isSymbolicLink()) {
    throw new Error(`${label} must be a regular file before it can be replaced`)
  }
  rmSync(path, { force: true })
}

function removeRealStageDirectoryIfPresent(path, label) {
  if (!existsSync(path)) return
  assertNoRedirectingComponents(path, label)
  const info = lstatSync(path)
  if (!info.isDirectory() || info.isSymbolicLink()) {
    throw new Error(`${label} changed into a redirect or special file; refusing recursive cleanup`)
  }
  assertNoRedirectingComponents(path, label)
  const finalInfo = lstatSync(path)
  if (!finalInfo.isDirectory() || finalInfo.isSymbolicLink()) {
    throw new Error(`${label} changed before recursive cleanup`)
  }
  rmSync(path, { force: true, recursive: true })
}

function cleanupPartialStage({ mediaRoot, noticeRoot, manifestPath }) {
  const failures = []
  for (const [path, label] of [
    [mediaRoot, 'partial media runtime directory'],
    [noticeRoot, 'partial media notice directory']
  ]) {
    try {
      removeRealStageDirectoryIfPresent(path, label)
    } catch (error) {
      failures.push(error instanceof Error ? error.message : String(error))
    }
  }
  try {
    removeRegularIfPresent(manifestPath, 'partial media runtime manifest')
  } catch (error) {
    failures.push(error instanceof Error ? error.message : String(error))
  }
  if (failures.length) {
    throw new Error(`media runtime cleanup BLOCKED: ${failures.join('; ')}`)
  }
}

async function verifyExactFile(path, expected, maxBytes, label, pe = false) {
  const info = lstatSync(path)
  if (
    info.isSymbolicLink() ||
    !info.isFile() ||
    info.size !== expected.size ||
    info.size <= 0 ||
    info.size > maxBytes
  ) {
    throw new Error(`${label} is not the exact bounded staged file`)
  }
  if (pe) assertPeX64(path, label)
  if ((await sha256File(path)) !== expected.sha256) {
    throw new Error(`${label} differs from the reviewed SHA-256`)
  }
}

export async function verifyPreparedMediaRuntime({
  repoRoot = defaultRepoRoot,
  distRoot = join(resolve(repoRoot), 'dist'),
  lockPath
} = {}) {
  repoRoot = checkedDirectory(resolve(repoRoot), 'project root')
  distRoot = checkedDirectory(assertContained(repoRoot, distRoot, 'media runtime dist root'), 'media runtime dist root')
  const { lock, lockSha256 } = readReviewedMediaRuntimeLock({ repoRoot, lockPath })
  const mediaRoot = checkedDirectory(join(distRoot, MEDIA_RUNTIME_STAGE_DIRECTORY), 'prepared media runtime directory')
  const noticeRoot = checkedDirectory(join(distRoot, MEDIA_RUNTIME_NOTICE_DIRECTORY), 'prepared media notice directory')
  assertExactEntries(mediaRoot, lock.artifacts.map(({ stagedName }) => stagedName), 'prepared media runtime directory')
  assertExactEntries(noticeRoot, ['LICENSE', 'README.txt'], 'prepared media notice directory')

  const stagedArtifacts = {}
  for (const item of lock.artifacts) {
    const path = join(mediaRoot, item.stagedName)
    await verifyExactFile(path, item, MAX_EXECUTABLE_BYTES, `prepared ${item.role}`, true)
    stagedArtifacts[item.role] = { path, sha256: item.sha256, size: item.size }
  }
  const licensePath = join(noticeRoot, 'LICENSE')
  const readmePath = join(noticeRoot, 'README.txt')
  await verifyExactFile(licensePath, lock.license, MAX_NOTICE_BYTES, 'prepared FFmpeg license')
  await verifyExactFile(readmePath, lock.readme, MAX_NOTICE_BYTES, 'prepared Gyan FFmpeg README')

  const manifestPath = join(distRoot, MEDIA_RUNTIME_MANIFEST_NAME)
  assertNoRedirectingComponents(manifestPath, 'prepared media runtime manifest')
  const manifestInfo = lstatSync(manifestPath)
  if (
    manifestInfo.isSymbolicLink() ||
    !manifestInfo.isFile() ||
    manifestInfo.size <= 0 ||
    manifestInfo.size > MAX_MANIFEST_BYTES
  ) {
    throw new Error('prepared media runtime manifest must be a bounded regular file')
  }
  const expectedBytes = canonicalMediaRuntimeBytes(expectedManifest(lock, lockSha256))
  const actualBytes = readFileSync(manifestPath)
  if (!actualBytes.equals(expectedBytes)) {
    throw new Error('prepared media runtime manifest differs from the reviewed lock')
  }
  return {
    ffmpeg: stagedArtifacts.ffmpeg,
    ffprobe: stagedArtifacts.ffprobe,
    licensePath,
    lock,
    lockSha256,
    manifestPath,
    manifestSha256: sha256Bytes(actualBytes),
    noticeRoot,
    readmePath
  }
}

export async function prepareMediaRuntime({
  repoRoot = defaultRepoRoot,
  sourceRoot,
  distRoot = join(resolve(repoRoot), 'dist'),
  lockPath,
  afterStageForAudit
} = {}) {
  repoRoot = checkedDirectory(resolve(repoRoot), 'project root')
  sourceRoot = resolve(sourceRoot || defaultMediaRuntimeSource(repoRoot))
  const { lock, lockSha256 } = readReviewedMediaRuntimeLock({ repoRoot, lockPath })
  distRoot = ensureStageParent(repoRoot, resolve(distRoot))
  const mediaRoot = join(distRoot, MEDIA_RUNTIME_STAGE_DIRECTORY)
  const noticeRoot = join(distRoot, MEDIA_RUNTIME_NOTICE_DIRECTORY)
  const manifestPath = join(distRoot, MEDIA_RUNTIME_MANIFEST_NAME)

  resetRealDirectory(mediaRoot, 'prepared media runtime directory')
  resetRealDirectory(noticeRoot, 'prepared media notice directory')
  removeRegularIfPresent(manifestPath, 'prepared media runtime manifest')
  try {
    // Test-only audit seam proving redirected cleanup is refused. Production
    // callers must omit it.
    afterStageForAudit?.({ manifestPath, mediaRoot, noticeRoot })
    const source = await verifiedSource({ lock, sourceRoot })
    for (const item of source.artifacts) {
      const destination = join(mediaRoot, item.stagedName)
      copyFileSync(item.path, destination, constants.COPYFILE_EXCL)
    }
    copyFileSync(source.licensePath, join(noticeRoot, 'LICENSE'), constants.COPYFILE_EXCL)
    copyFileSync(source.readmePath, join(noticeRoot, 'README.txt'), constants.COPYFILE_EXCL)
    writeFileSync(manifestPath, canonicalMediaRuntimeBytes(expectedManifest(lock, lockSha256)), { flag: 'wx' })
    return await verifyPreparedMediaRuntime({ repoRoot, distRoot, lockPath })
  } catch (error) {
    try {
      cleanupPartialStage({ manifestPath, mediaRoot, noticeRoot })
    } catch (cleanupError) {
      throw new Error(
        `${cleanupError instanceof Error ? cleanupError.message : String(cleanupError)}; original failure: ${error instanceof Error ? error.message : String(error)}`,
        { cause: error }
      )
    }
    throw error
  }
}
