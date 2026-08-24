import { createHash, randomBytes } from 'node:crypto'
import { link, lstat, mkdir, open, readdir, realpath, unlink } from 'node:fs/promises'
import { basename, dirname, isAbsolute, join, parse, relative, resolve, sep } from 'node:path'
import { pathToFileURL } from 'node:url'

const SHA256 = /^[0-9a-f]{64}$/
const COMMIT = /^[0-9a-f]{40}$/
const GIT_TREE = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/
const RUN_NUMBER = /^[1-9][0-9]{0,19}$/
const RELEASE_TAG = /^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?$/
const VERSION = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?$/
const REPOSITORY = /^[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/
const JOB = /^[A-Za-z0-9_.-]{1,100}$/
const VARIANTS = new Set(['lean', 'full'])
const USTAR_BLOCK_BYTES = 512
const MAX_FILES = 100_000
const MAX_FILE_BYTES = 0o77777777777
const MAX_TOTAL_BYTES = 32 * 1024 * 1024 * 1024
const MAX_PATH_BYTES = 255
const IO_CHUNK_BYTES = 1024 * 1024
const MANIFEST_MAX_BYTES = 64 * 1024 * 1024
const PAYLOAD_MANIFEST_PATH = '.nachuan/CANDIDATE_PAYLOAD_MANIFEST.json'
const MAX_CANONICAL_ARCHIVE_BYTES =
  MAX_TOTAL_BYTES +
  MANIFEST_MAX_BYTES +
  (MAX_FILES + 3) * USTAR_BLOCK_BYTES +
  (MAX_FILES + 1) * (USTAR_BLOCK_BYTES - 1)

export function maximumReleaseCandidateArchiveBytes() {
  return MAX_CANONICAL_ARCHIVE_BYTES
}

function exactKeys(value, keys, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`)
  }
  if (Object.keys(value).sort().join(',') !== [...keys].sort().join(',')) {
    throw new Error(`${label} fields are not canonical`)
  }
  return value
}

function canonicalValue(value) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new Error('candidate manifest has a non-canonical number')
    return value
  }
  if (Array.isArray(value)) return value.map(canonicalValue)
  if (value && typeof value === 'object') {
    const prototype = Object.getPrototypeOf(value)
    if (prototype !== Object.prototype && prototype !== null) {
      throw new Error('candidate manifest contains a non-plain object')
    }
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonicalValue(value[key])])
    )
  }
  throw new Error('candidate manifest contains an unsupported value')
}

export function canonicalCandidateManifestBytes(value) {
  return Buffer.from(`${JSON.stringify(canonicalValue(value), null, 2)}\n`, 'utf8')
}

function checkedIdentity(value, expected = value) {
  exactKeys(
    value,
    [
      'job',
      'releaseCommit',
      'releaseTag',
      'releaseTree',
      'repository',
      'runAttempt',
      'runId',
      'variant',
      'version',
      'workflowRef',
      'workflowSha'
    ],
    'release candidate identity'
  )
  const workflowRef = String(value.workflowRef || '')
  if (
    !RELEASE_TAG.test(String(value.releaseTag || '')) ||
    !COMMIT.test(String(value.releaseCommit || '')) ||
    !GIT_TREE.test(String(value.releaseTree || '')) ||
    !REPOSITORY.test(String(value.repository || '')) ||
    !workflowRef.startsWith(`${value.repository}/.github/workflows/`) ||
    !/^.{1,400}@(?:refs\/[A-Za-z0-9._\/-]+|[0-9a-f]{40})$/.test(workflowRef) ||
    !COMMIT.test(String(value.workflowSha || '')) ||
    !RUN_NUMBER.test(String(value.runId || '')) ||
    !RUN_NUMBER.test(String(value.runAttempt || '')) ||
    !JOB.test(String(value.job || '')) ||
    !VARIANTS.has(value.variant) ||
    !VERSION.test(String(value.version || '')) ||
    value.releaseTag !== `v${value.version}`
  ) {
    throw new Error('release candidate identity is invalid')
  }
  for (const key of Object.keys(value)) {
    if (value[key] !== expected[key]) {
      throw new Error(`release candidate identity mismatch: ${key}`)
    }
  }
  return canonicalValue(value)
}

function checkedRelativePath(value) {
  const path = String(value || '').replaceAll('\\', '/')
  const parts = path.split('/')
  if (path !== path.normalize('NFC')) {
    throw new Error(`release candidate path is not NFC-normalized: ${path}`)
  }
  const hasUnsafeWindowsSegment = parts.some(
    (part) =>
      /[<>:"|?*]/u.test(part) ||
      /[ .]$/u.test(part) ||
      /^(?:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|COM[1-9¹²³]|LPT[1-9¹²³])(?:\..*)?$/iu.test(part)
  )
  if (
    !path ||
    Buffer.byteLength(path, 'utf8') > MAX_PATH_BYTES ||
    path.startsWith('/') ||
    /^[A-Za-z]:/.test(path) ||
    parts.some((part) => !part || part === '.' || part === '..') ||
    hasUnsafeWindowsSegment ||
    /[\u0000-\u001f\u007f]/.test(path)
  ) {
    throw new Error(`release candidate path is not controlled and relative: ${path}`)
  }
  return path
}

function isReservedMetadataPath(path) {
  const key = path.toLowerCase()
  return key === '.nachuan' || key.startsWith('.nachuan/')
}

function fileIdentity(info) {
  return [
    info.dev,
    info.ino,
    info.mode,
    info.nlink,
    info.size,
    info.mtimeNs,
    info.ctimeNs
  ]
    .map(String)
    .join(':')
}

async function assertExistingPathChainHasNoRedirect(path) {
  const resolved = resolve(path)
  const root = parse(resolved).root
  const remainder = resolved.slice(root.length).split(sep).filter(Boolean)
  let cursor = root
  for (const part of remainder) {
    cursor = join(cursor, part)
    let info
    try {
      info = await lstat(cursor)
    } catch (error) {
      if (error?.code === 'ENOENT') return
      throw error
    }
    if (info.isSymbolicLink()) {
      throw new Error('release candidate path chain contains a filesystem redirect')
    }
  }
}

function pathIsWithin(parent, child) {
  const relation = relative(resolve(parent), resolve(child))
  return relation === '' || (!relation.startsWith(`..${sep}`) && relation !== '..' && !isAbsolute(relation))
}

async function hashStableFile(path, expectedSize = undefined) {
  await assertExistingPathChainHasNoRedirect(path)
  const pathBefore = await lstat(path, { bigint: true })
  if (pathBefore.isSymbolicLink() || !pathBefore.isFile() || pathBefore.nlink !== 1n) {
    if (pathBefore.isFile() && pathBefore.nlink !== 1n) {
      throw new Error('release candidate input is hard-linked')
    }
    throw new Error('release candidate input is not a regular file')
  }
  if (expectedSize !== undefined && pathBefore.size !== BigInt(expectedSize)) {
    throw new Error('release candidate input size changed')
  }
  const handle = await open(path, 'r')
  try {
    const before = await handle.stat({ bigint: true })
    if (!before.isFile() || fileIdentity(before) !== fileIdentity(pathBefore)) {
      throw new Error('release candidate input changed while it was opened')
    }
    const hash = createHash('sha256')
    const buffer = Buffer.allocUnsafe(IO_CHUNK_BYTES)
    let position = 0
    while (position < Number(before.size)) {
      const wanted = Math.min(buffer.length, Number(before.size) - position)
      const { bytesRead } = await handle.read(buffer, 0, wanted, position)
      if (bytesRead <= 0) throw new Error('release candidate input ended unexpectedly')
      hash.update(buffer.subarray(0, bytesRead))
      position += bytesRead
    }
    const after = await handle.stat({ bigint: true })
    const pathAfter = await lstat(path, { bigint: true })
    if (
      fileIdentity(after) !== fileIdentity(before) ||
      fileIdentity(pathAfter) !== fileIdentity(before)
    ) {
      throw new Error('release candidate input changed while it was read')
    }
    return { sha256: hash.digest('hex'), size: Number(before.size) }
  } finally {
    await handle.close()
  }
}

async function collectCandidateTargets(releaseRoot) {
  const requestedRoot = resolve(releaseRoot)
  await assertExistingPathChainHasNoRedirect(requestedRoot)
  const rootInfo = await lstat(requestedRoot, { bigint: true })
  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) {
    throw new Error('release candidate root must be a real directory')
  }
  const canonicalRoot = await realpath(requestedRoot)
  const canonicalInfo = await lstat(canonicalRoot, { bigint: true })
  if (fileIdentity(canonicalInfo) !== fileIdentity(rootInfo)) {
    throw new Error('release candidate root changed through a filesystem redirect')
  }
  const targets = []
  const folded = new Set()
  let totalBytes = 0

  async function visit(directory) {
    const entries = await readdir(directory, { withFileTypes: true })
    entries.sort((left, right) => (left.name < right.name ? -1 : left.name > right.name ? 1 : 0))
    for (const entry of entries) {
      const path = resolve(directory, entry.name)
      const info = await lstat(path)
      if (info.isSymbolicLink()) throw new Error('release candidate tree contains a filesystem redirect')
      if (info.isDirectory()) {
        await visit(path)
        continue
      }
      if (!info.isFile()) throw new Error('release candidate tree contains a special file')
      if (info.nlink !== 1) {
        throw new Error(`release candidate tree contains a hard-linked input: ${entry.name}`)
      }
      const relativePath = checkedRelativePath(relative(requestedRoot, path).split(sep).join('/'))
      if (isReservedMetadataPath(relativePath)) {
        throw new Error(`release candidate tree uses a reserved metadata path: ${relativePath}`)
      }
      const foldedPath = relativePath.toLowerCase()
      if (folded.has(foldedPath)) {
        throw new Error(`release candidate tree contains a case-colliding path: ${relativePath}`)
      }
      folded.add(foldedPath)
      if (!Number.isSafeInteger(info.size) || info.size < 0 || info.size > MAX_FILE_BYTES) {
        throw new Error(`release candidate input size is outside USTAR policy: ${relativePath}`)
      }
      totalBytes += info.size
      if (targets.length >= MAX_FILES || totalBytes > MAX_TOTAL_BYTES) {
        throw new Error('release candidate tree exceeds bounded policy')
      }
      const stable = await hashStableFile(path, info.size)
      targets.push({ path: relativePath, sha256: stable.sha256, size: stable.size })
    }
  }

  await visit(requestedRoot)
  if (!targets.length) throw new Error('release candidate tree is empty')
  targets.sort((left, right) => (left.path < right.path ? -1 : left.path > right.path ? 1 : 0))
  return { root: requestedRoot, targets }
}

function splitUstarPath(path) {
  const checked = checkedRelativePath(path)
  if (Buffer.byteLength(checked, 'utf8') <= 100) return { name: checked, prefix: '' }
  for (let index = checked.lastIndexOf('/'); index > 0; index = checked.lastIndexOf('/', index - 1)) {
    const prefix = checked.slice(0, index)
    const name = checked.slice(index + 1)
    if (Buffer.byteLength(prefix, 'utf8') <= 155 && Buffer.byteLength(name, 'utf8') <= 100) {
      return { name, prefix }
    }
  }
  throw new Error(`release candidate path does not fit canonical USTAR fields: ${checked}`)
}

function writeAscii(buffer, offset, length, value, label) {
  const bytes = Buffer.from(value, 'utf8')
  if (bytes.length > length) throw new Error(`${label} exceeds its USTAR field`)
  bytes.copy(buffer, offset)
}

function octalField(value, length) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error('USTAR numeric field is invalid')
  const digits = value.toString(8)
  if (digits.length > length - 1) throw new Error('USTAR numeric field exceeds policy')
  return `${digits.padStart(length - 1, '0')}\0`
}

function ustarHeader(target) {
  const { name, prefix } = splitUstarPath(target.path)
  const header = Buffer.alloc(USTAR_BLOCK_BYTES)
  writeAscii(header, 0, 100, name, 'USTAR name')
  writeAscii(header, 100, 8, octalField(0o644, 8), 'USTAR mode')
  writeAscii(header, 108, 8, octalField(0, 8), 'USTAR uid')
  writeAscii(header, 116, 8, octalField(0, 8), 'USTAR gid')
  writeAscii(header, 124, 12, octalField(target.size, 12), 'USTAR size')
  writeAscii(header, 136, 12, octalField(0, 12), 'USTAR mtime')
  header.fill(0x20, 148, 156)
  header[156] = '0'.charCodeAt(0)
  writeAscii(header, 257, 6, 'ustar\0', 'USTAR magic')
  writeAscii(header, 263, 2, '00', 'USTAR version')
  writeAscii(header, 345, 155, prefix, 'USTAR prefix')
  const checksum = [...header].reduce((total, byte) => total + byte, 0)
  writeAscii(header, 148, 8, `${checksum.toString(8).padStart(6, '0')}\0 `, 'USTAR checksum')
  return header
}

async function writeAll(handle, bytes) {
  let offset = 0
  while (offset < bytes.length) {
    const { bytesWritten } = await handle.write(bytes, offset, bytes.length - offset)
    if (bytesWritten <= 0) throw new Error('release candidate archive write made no progress')
    offset += bytesWritten
  }
}

async function appendStableFile({ archive, archiveHash, path, target }) {
  const pathBefore = await lstat(path, { bigint: true })
  const input = await open(path, 'r')
  try {
    const before = await input.stat({ bigint: true })
    if (
      !before.isFile() ||
      before.nlink !== 1n ||
      fileIdentity(before) !== fileIdentity(pathBefore) ||
      before.size !== BigInt(target.size)
    ) {
      throw new Error(`release candidate input changed before archiving: ${target.path}`)
    }
    const fileHash = createHash('sha256')
    const buffer = Buffer.allocUnsafe(IO_CHUNK_BYTES)
    let position = 0
    while (position < target.size) {
      const wanted = Math.min(buffer.length, target.size - position)
      const { bytesRead } = await input.read(buffer, 0, wanted, position)
      if (bytesRead <= 0) throw new Error(`release candidate input ended early: ${target.path}`)
      const chunk = buffer.subarray(0, bytesRead)
      fileHash.update(chunk)
      archiveHash.update(chunk)
      await writeAll(archive, chunk)
      position += bytesRead
    }
    const after = await input.stat({ bigint: true })
    const pathAfter = await lstat(path, { bigint: true })
    if (
      fileIdentity(after) !== fileIdentity(before) ||
      fileIdentity(pathAfter) !== fileIdentity(before) ||
      fileHash.digest('hex') !== target.sha256
    ) {
      throw new Error(`release candidate input changed while archiving: ${target.path}`)
    }
  } finally {
    await input.close()
  }
}

async function appendCanonicalBytes({ archive, archiveHash, bytes, target }) {
  if (
    bytes.length !== target.size ||
    createHash('sha256').update(bytes).digest('hex') !== target.sha256
  ) {
    throw new Error('release candidate embedded manifest identity changed')
  }
  archiveHash.update(bytes)
  await writeAll(archive, bytes)
}

async function writeArchive({ releaseRoot, outputPath, payloadManifest, targets }) {
  const archiveHash = createHash('sha256')
  const payloadManifestBytes = canonicalCandidateManifestBytes(payloadManifest)
  if (payloadManifestBytes.length > MANIFEST_MAX_BYTES) {
    throw new Error('release candidate embedded manifest exceeds bounded policy')
  }
  const payloadManifestTarget = {
    path: PAYLOAD_MANIFEST_PATH,
    sha256: createHash('sha256').update(payloadManifestBytes).digest('hex'),
    size: payloadManifestBytes.length
  }
  const archiveTargets = [payloadManifestTarget, ...targets].sort((left, right) =>
    left.path < right.path ? -1 : left.path > right.path ? 1 : 0
  )
  const archive = await open(outputPath, 'wx', 0o600)
  let size = 0
  try {
    for (const target of archiveTargets) {
      const header = ustarHeader(target)
      archiveHash.update(header)
      await writeAll(archive, header)
      size += header.length
      if (target.path === PAYLOAD_MANIFEST_PATH) {
        await appendCanonicalBytes({
          archive,
          archiveHash,
          bytes: payloadManifestBytes,
          target
        })
      } else {
        await appendStableFile({
          archive,
          archiveHash,
          path: resolve(releaseRoot, ...target.path.split('/')),
          target
        })
      }
      size += target.size
      const paddingBytes = (USTAR_BLOCK_BYTES - (target.size % USTAR_BLOCK_BYTES)) % USTAR_BLOCK_BYTES
      if (paddingBytes) {
        const padding = Buffer.alloc(paddingBytes)
        archiveHash.update(padding)
        await writeAll(archive, padding)
        size += padding.length
      }
    }
    const ending = Buffer.alloc(USTAR_BLOCK_BYTES * 2)
    archiveHash.update(ending)
    await writeAll(archive, ending)
    size += ending.length
    if (size > maximumReleaseCandidateArchiveBytes()) {
      throw new Error('release candidate archive exceeds bounded policy')
    }
    await archive.sync()
  } finally {
    await archive.close()
  }
  return {
    sha256: archiveHash.digest('hex'),
    size,
    payloadManifest: payloadManifestTarget
  }
}

async function writeCreateOnlyFile(path, bytes) {
  const handle = await open(path, 'wx', 0o600)
  try {
    await writeAll(handle, bytes)
    await handle.sync()
  } finally {
    await handle.close()
  }
}

function checkedTargetSet(
  value,
  { maxFiles = MAX_FILES, maxTotalBytes = MAX_TOTAL_BYTES } = {}
) {
  if (!Array.isArray(value) || !value.length || value.length > maxFiles) {
    throw new Error('release candidate manifest target set is invalid')
  }
  let previous = ''
  let totalBytes = 0
  const folded = new Set()
  return value.map((target) => {
    exactKeys(target, ['path', 'sha256', 'size'], 'release candidate target')
    const path = checkedRelativePath(target.path)
    if (
      path !== target.path ||
      path <= previous ||
      folded.has(path.toLowerCase()) ||
      !SHA256.test(String(target.sha256 || '')) ||
      !Number.isSafeInteger(target.size) ||
      target.size < 0 ||
      target.size > MAX_FILE_BYTES
    ) {
      throw new Error('release candidate manifest target set is not canonical')
    }
    previous = path
    folded.add(path.toLowerCase())
    totalBytes += target.size
    if (totalBytes > maxTotalBytes) {
      throw new Error('release candidate target bytes exceed policy')
    }
    return { path, sha256: target.sha256, size: target.size }
  })
}

function checkedReleaseTargetSet(value) {
  const targets = checkedTargetSet(value)
  if (targets.some((target) => isReservedMetadataPath(target.path))) {
    throw new Error('release candidate target set uses a reserved metadata path')
  }
  return targets
}

async function readStableBoundedFile(path, maxBytes, label) {
  await assertExistingPathChainHasNoRedirect(path)
  const before = await lstat(path, { bigint: true })
  if (
    before.isSymbolicLink() ||
    !before.isFile() ||
    before.nlink !== 1n ||
    before.size <= 0n ||
    before.size > BigInt(maxBytes)
  ) {
    throw new Error(`${label} is not a bounded regular file`)
  }
  const handle = await open(path, 'r')
  try {
    const opened = await handle.stat({ bigint: true })
    if (fileIdentity(opened) !== fileIdentity(before)) throw new Error(`${label} changed while opening`)
    const bytes = Buffer.alloc(Number(opened.size))
    let position = 0
    while (position < bytes.length) {
      const { bytesRead } = await handle.read(bytes, position, bytes.length - position, position)
      if (bytesRead <= 0) throw new Error(`${label} ended unexpectedly`)
      position += bytesRead
    }
    const after = await handle.stat({ bigint: true })
    const pathAfter = await lstat(path, { bigint: true })
    if (
      fileIdentity(after) !== fileIdentity(opened) ||
      fileIdentity(pathAfter) !== fileIdentity(opened)
    ) {
      throw new Error(`${label} changed while reading`)
    }
    return bytes
  } finally {
    await handle.close()
  }
}

function parseNullTerminated(bytes) {
  const nul = bytes.indexOf(0)
  return bytes.subarray(0, nul === -1 ? bytes.length : nul).toString('utf8')
}

function parseUstarOctal(bytes, label) {
  const text = bytes.toString('ascii').replace(/[\0 ]+$/u, '')
  if (!/^[0-7]+$/.test(text)) throw new Error(`${label} is not canonical USTAR octal`)
  const value = Number.parseInt(text, 8)
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${label} exceeds policy`)
  return value
}

async function readExact(handle, length, position, label) {
  const bytes = Buffer.alloc(length)
  let offset = 0
  while (offset < length) {
    const { bytesRead } = await handle.read(bytes, offset, length - offset, position + offset)
    if (bytesRead <= 0) throw new Error(`${label} ended unexpectedly`)
    offset += bytesRead
  }
  return bytes
}

async function inspectCanonicalUstar(path) {
  await assertExistingPathChainHasNoRedirect(path)
  const pathBefore = await lstat(path, { bigint: true })
  if (
    pathBefore.isSymbolicLink() ||
    !pathBefore.isFile() ||
    pathBefore.nlink !== 1n ||
    pathBefore.size <= 0n ||
    pathBefore.size > BigInt(maximumReleaseCandidateArchiveBytes())
  ) {
    throw new Error('release candidate archive is not a regular file')
  }
  const handle = await open(path, 'r')
  try {
    const before = await handle.stat({ bigint: true })
    if (fileIdentity(before) !== fileIdentity(pathBefore)) {
      throw new Error('release candidate archive changed while opening')
    }
    const archiveHash = createHash('sha256')
    const targets = []
    let totalPayloadBytes = 0
    let payloadManifestBytes
    let position = 0
    while (true) {
      const header = await readExact(handle, USTAR_BLOCK_BYTES, position, 'USTAR header')
      archiveHash.update(header)
      position += header.length
      if (header.every((byte) => byte === 0)) {
        const second = await readExact(handle, USTAR_BLOCK_BYTES, position, 'USTAR terminator')
        archiveHash.update(second)
        position += second.length
        if (!second.every((byte) => byte === 0)) {
          throw new Error('release candidate archive has a non-canonical terminator')
        }
        break
      }
      const name = parseNullTerminated(header.subarray(0, 100))
      const prefix = parseNullTerminated(header.subarray(345, 500))
      const pathValue = checkedRelativePath(prefix ? `${prefix}/${name}` : name)
      const size = parseUstarOctal(header.subarray(124, 136), 'USTAR size')
      if (targets.length >= MAX_FILES + 1) {
        throw new Error('release candidate archive entry count exceeds policy')
      }
      totalPayloadBytes += size
      if (totalPayloadBytes > MAX_TOTAL_BYTES + MANIFEST_MAX_BYTES) {
        throw new Error('release candidate archive payload bytes exceed policy')
      }
      const canonicalHeader = ustarHeader({ path: pathValue, size })
      if (!header.equals(canonicalHeader)) {
        throw new Error(`release candidate archive has non-canonical metadata: ${pathValue}`)
      }
      const fileHash = createHash('sha256')
      if (pathValue === PAYLOAD_MANIFEST_PATH && size > MANIFEST_MAX_BYTES) {
        throw new Error('release candidate embedded manifest exceeds bounded policy')
      }
      const captured = pathValue === PAYLOAD_MANIFEST_PATH ? Buffer.alloc(size) : undefined
      let capturedOffset = 0
      let remaining = size
      while (remaining > 0) {
        const length = Math.min(IO_CHUNK_BYTES, remaining)
        const chunk = await readExact(handle, length, position, `USTAR entry ${pathValue}`)
        archiveHash.update(chunk)
        fileHash.update(chunk)
        if (captured) {
          chunk.copy(captured, capturedOffset)
          capturedOffset += chunk.length
        }
        position += chunk.length
        remaining -= chunk.length
      }
      const paddingBytes = (USTAR_BLOCK_BYTES - (size % USTAR_BLOCK_BYTES)) % USTAR_BLOCK_BYTES
      if (paddingBytes) {
        const padding = await readExact(handle, paddingBytes, position, 'USTAR padding')
        archiveHash.update(padding)
        position += padding.length
        if (!padding.every((byte) => byte === 0)) {
          throw new Error(`release candidate archive has non-zero padding: ${pathValue}`)
        }
      }
      if (captured) {
        if (payloadManifestBytes !== undefined) {
          throw new Error('release candidate archive repeats its embedded manifest')
        }
        payloadManifestBytes = captured
      }
      targets.push({ path: pathValue, sha256: fileHash.digest('hex'), size })
    }
    if (position !== Number(before.size)) {
      throw new Error('release candidate archive has trailing bytes')
    }
    const after = await handle.stat({ bigint: true })
    const pathAfter = await lstat(path, { bigint: true })
    if (
      fileIdentity(after) !== fileIdentity(before) ||
      fileIdentity(pathAfter) !== fileIdentity(before)
    ) {
      throw new Error('release candidate archive changed while verifying')
    }
    const checkedArchiveTargets = checkedTargetSet(targets, {
      maxFiles: MAX_FILES + 1,
      maxTotalBytes: MAX_TOTAL_BYTES + MANIFEST_MAX_BYTES
    })
    const payloadTargets = checkedArchiveTargets.filter(
      (target) => target.path === PAYLOAD_MANIFEST_PATH
    )
    if (payloadTargets.length !== 1 || payloadManifestBytes === undefined) {
      throw new Error('release candidate archive is missing its embedded manifest')
    }
    return {
      sha256: archiveHash.digest('hex'),
      size: Number(before.size),
      payloadManifestBytes,
      payloadManifestTarget: payloadTargets[0],
      targets: checkedReleaseTargetSet(
        checkedArchiveTargets.filter((target) => target.path !== PAYLOAD_MANIFEST_PATH)
      )
    }
  } finally {
    await handle.close()
  }
}

export async function verifyReleaseCandidateArchive({ archivePath, manifestPath, identity }) {
  const expectedIdentity = checkedIdentity(identity)
  const manifestBytes = await readStableBoundedFile(
    manifestPath,
    MANIFEST_MAX_BYTES,
    'release candidate manifest'
  )
  let manifest
  try {
    manifest = JSON.parse(manifestBytes.toString('utf8'))
  } catch {
    throw new Error('release candidate manifest is not valid JSON')
  }
  exactKeys(
    manifest,
    ['archive', 'identity', 'payloadManifest', 'schema', 'targets'],
    'release candidate manifest'
  )
  if (manifest.schema !== 'nachuan.release-candidate/v1') {
    throw new Error('release candidate manifest schema is unsupported')
  }
  checkedIdentity(manifest.identity, expectedIdentity)
  const targets = checkedReleaseTargetSet(manifest.targets)
  const archive = exactKeys(
    manifest.archive,
    ['format', 'name', 'sha256', 'size'],
    'release candidate archive identity'
  )
  if (
    archive.format !== 'ustar' ||
    !SHA256.test(String(archive.sha256 || '')) ||
    !Number.isSafeInteger(archive.size) ||
    archive.size <= 0 ||
    archive.name !== `nachuan-${expectedIdentity.version}-${expectedIdentity.variant}-${archive.sha256}.tar` ||
    basename(resolve(archivePath)) !== archive.name ||
    basename(resolve(manifestPath)) !==
      `nachuan-${expectedIdentity.version}-${expectedIdentity.variant}-${archive.sha256}.candidate.json` ||
    relative(dirname(resolve(archivePath)), dirname(resolve(manifestPath))) !== ''
  ) {
    throw new Error('release candidate archive identity is invalid')
  }
  const inspected = await inspectCanonicalUstar(archivePath)
  const payloadManifestDescriptor = exactKeys(
    manifest.payloadManifest,
    ['path', 'sha256', 'size'],
    'release candidate embedded manifest identity'
  )
  if (
    inspected.sha256 !== archive.sha256 ||
    inspected.size !== archive.size ||
    payloadManifestDescriptor.path !== PAYLOAD_MANIFEST_PATH ||
    payloadManifestDescriptor.sha256 !== inspected.payloadManifestTarget.sha256 ||
    payloadManifestDescriptor.size !== inspected.payloadManifestTarget.size ||
    JSON.stringify(inspected.targets) !== JSON.stringify(targets)
  ) {
    throw new Error('release candidate archive does not match its manifest')
  }
  let payloadManifest
  try {
    payloadManifest = JSON.parse(inspected.payloadManifestBytes.toString('utf8'))
  } catch {
    throw new Error('release candidate embedded manifest is not valid JSON')
  }
  exactKeys(
    payloadManifest,
    ['identity', 'schema', 'targets'],
    'release candidate embedded manifest'
  )
  if (payloadManifest.schema !== 'nachuan.release-candidate-payload/v1') {
    throw new Error('release candidate embedded manifest schema is unsupported')
  }
  checkedIdentity(payloadManifest.identity, expectedIdentity)
  const embeddedTargets = checkedReleaseTargetSet(payloadManifest.targets)
  if (
    JSON.stringify(embeddedTargets) !== JSON.stringify(targets) ||
    !canonicalCandidateManifestBytes(payloadManifest).equals(inspected.payloadManifestBytes)
  ) {
    throw new Error('release candidate embedded manifest is not canonical or does not match')
  }
  if (!canonicalCandidateManifestBytes(manifest).equals(manifestBytes)) {
    throw new Error('release candidate manifest bytes are not canonical')
  }
  return {
    archiveSha256: inspected.sha256,
    archiveSize: inspected.size,
    manifestSha256: createHash('sha256').update(manifestBytes).digest('hex'),
    targetCount: inspected.targets.length
  }
}

export async function createReleaseCandidateArchive({ releaseRoot, outputDirectory, identity }) {
  const checked = checkedIdentity(identity)
  const root = resolve(releaseRoot)
  const output = resolve(outputDirectory)
  if (pathIsWithin(root, output) || pathIsWithin(output, root)) {
    throw new Error('release candidate output must be outside the release tree')
  }
  await assertExistingPathChainHasNoRedirect(root)
  await assertExistingPathChainHasNoRedirect(resolve(output, '..'))
  await mkdir(output, { recursive: false, mode: 0o700 })
  const collected = await collectCandidateTargets(root)
  const temporaryArchive = resolve(output, `.candidate-${randomBytes(16).toString('hex')}.tmp`)
  let archivePath
  let manifestPath
  try {
    const payloadManifest = canonicalValue({
      schema: 'nachuan.release-candidate-payload/v1',
      identity: checked,
      targets: collected.targets
    })
    const archive = await writeArchive({
      releaseRoot: collected.root,
      outputPath: temporaryArchive,
      payloadManifest,
      targets: collected.targets
    })
    const archiveName = `nachuan-${checked.version}-${checked.variant}-${archive.sha256}.tar`
    archivePath = resolve(output, archiveName)
    await link(temporaryArchive, archivePath)
    await unlink(temporaryArchive)
    const manifest = canonicalValue({
      schema: 'nachuan.release-candidate/v1',
      identity: checked,
      archive: {
        format: 'ustar',
        name: archiveName,
        sha256: archive.sha256,
        size: archive.size
      },
      payloadManifest: archive.payloadManifest,
      targets: collected.targets
    })
    manifestPath = resolve(
      output,
      `nachuan-${checked.version}-${checked.variant}-${archive.sha256}.candidate.json`
    )
    await writeCreateOnlyFile(manifestPath, canonicalCandidateManifestBytes(manifest))
    const verified = await verifyReleaseCandidateArchive({
      archivePath,
      manifestPath,
      identity: checked
    })
    return { archivePath, manifestPath, manifest, ...verified }
  } catch (error) {
    const cleanupErrors = []
    for (const path of [temporaryArchive, manifestPath, archivePath].filter(Boolean)) {
      try {
        await unlink(path)
      } catch (cleanupError) {
        if (cleanupError?.code !== 'ENOENT') cleanupErrors.push(cleanupError)
      }
    }
    if (cleanupErrors.length) throw new AggregateError([error, ...cleanupErrors])
    throw error
  }
}

const IDENTITY_FLAGS = Object.freeze({
  '--job': 'job',
  '--release-commit': 'releaseCommit',
  '--release-tag': 'releaseTag',
  '--release-tree': 'releaseTree',
  '--repository': 'repository',
  '--run-attempt': 'runAttempt',
  '--run-id': 'runId',
  '--variant': 'variant',
  '--version': 'version',
  '--workflow-ref': 'workflowRef',
  '--workflow-sha': 'workflowSha'
})

function parseCommandArguments(argv) {
  const command = argv[0]
  const commandFlags =
    command === 'create'
      ? ['--release-root', '--output-directory']
      : command === 'verify'
        ? ['--archive', '--manifest']
        : null
  if (commandFlags === null) {
    throw new Error('usage: release-candidate-archive.mjs <create|verify> <exact identity and paths>')
  }
  const allowed = new Set([...Object.keys(IDENTITY_FLAGS), ...commandFlags])
  const values = new Map()
  for (let index = 1; index < argv.length; index += 2) {
    const flag = argv[index]
    const value = argv[index + 1]
    if (!allowed.has(flag) || values.has(flag) || typeof value !== 'string' || !value) {
      throw new Error('release candidate command arguments are incomplete or non-canonical')
    }
    values.set(flag, value)
  }
  if (values.size !== allowed.size || argv.length !== 1 + allowed.size * 2) {
    throw new Error('release candidate command arguments are incomplete or non-canonical')
  }
  const identity = Object.fromEntries(
    Object.entries(IDENTITY_FLAGS).map(([flag, key]) => [key, values.get(flag)])
  )
  return command === 'create'
    ? {
        command,
        releaseRoot: values.get('--release-root'),
        outputDirectory: values.get('--output-directory'),
        identity
      }
    : {
        command,
        archivePath: values.get('--archive'),
        manifestPath: values.get('--manifest'),
        identity
      }
}

export async function releaseCandidateArchiveCommand(argv) {
  const parsed = parseCommandArguments(argv)
  const result =
    parsed.command === 'create'
      ? await createReleaseCandidateArchive(parsed)
      : await verifyReleaseCandidateArchive(parsed)
  const archivePath = resolve(
    parsed.command === 'create' ? result.archivePath : parsed.archivePath
  )
  const manifestPath = resolve(
    parsed.command === 'create' ? result.manifestPath : parsed.manifestPath
  )
  return canonicalCandidateManifestBytes({
    schema: 'nachuan.release-candidate-command/v1',
    archivePath,
    archiveSha256: result.archiveSha256,
    archiveSize: result.archiveSize,
    manifestPath,
    manifestSha256: result.manifestSha256,
    targetCount: result.targetCount,
    verified: true
  })
}

const invokedPath = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : ''
if (invokedPath === import.meta.url) {
  releaseCandidateArchiveCommand(process.argv.slice(2))
    .then((bytes) => process.stdout.write(bytes))
    .catch((error) => {
      process.stderr.write(
        `release candidate archive failed: ${error instanceof Error ? error.message : String(error)}\n`
      )
      process.exitCode = 1
    })
}
