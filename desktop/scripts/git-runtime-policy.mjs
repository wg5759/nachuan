import { createHash, randomUUID } from 'node:crypto'
import { spawn } from 'node:child_process'
import {
  createReadStream,
  createWriteStream,
  existsSync,
  lstatSync,
  readFileSync,
  readdirSync,
  realpathSync
} from 'node:fs'
import { mkdir, open, readFile, rename, rm, writeFile } from 'node:fs/promises'
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path'
import { pipeline } from 'node:stream/promises'
import { fileURLToPath } from 'node:url'

import { executeReleaseGitCommand } from './release-source-snapshot.mjs'

const scriptPath = fileURLToPath(import.meta.url)
const defaultProjectRoot = resolve(dirname(scriptPath), '..', '..')
const SHA256 = /^[0-9a-f]{64}$/u
const UPPER_SHA1 = /^[0-9A-F]{40}$/u
const VERSION = /^(\d+)\.(\d+)\.(\d+)\.windows\.([1-9]\d*)$/u
const MAX_REDIRECTS = 5
const MAX_RUNTIME_FILES = 20_000
const MAX_RUNTIME_FILE_BYTES = 512 * 1024 * 1024
const MAX_RUNTIME_BYTES = 1024 * 1024 * 1024
const MAX_COMMAND_OUTPUT_BYTES = 8 * 1024 * 1024
const PROVENANCE_NAME = 'GIT_RUNTIME_PROVENANCE.json'
const REQUIRED_PATHS = Object.freeze([
  'cmd/git.exe',
  'mingw64/bin/git.exe',
  'mingw64/bin/libiconv-2.dll',
  'mingw64/bin/libintl-8.dll',
  'mingw64/bin/libpcre2-8-0.dll',
  'mingw64/bin/libwinpthread-1.dll',
  'mingw64/bin/zlib1.dll',
  'mingw64/libexec/git-core/git.exe'
])
const REQUIRED_BUILTINS = Object.freeze([
  'cat-file',
  'diff',
  'hash-object',
  'ls-tree',
  'rev-parse',
  'status',
  'tag'
])

const canonicalValue = (value) =>
  Array.isArray(value)
    ? value.map(canonicalValue)
    : value && typeof value === 'object'
      ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalValue(value[key])]))
      : value
const canonicalBytes = (value) => Buffer.from(`${JSON.stringify(canonicalValue(value), null, 2)}\n`, 'utf8')
const sha256Bytes = (bytes) => createHash('sha256').update(bytes).digest('hex')

function ordinal(left, right) {
  return left < right ? -1 : left > right ? 1 : 0
}

function exactKeys(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be an object`)
  if (Object.keys(value).sort().join(',') !== [...expected].sort().join(',')) {
    throw new Error(`${label} fields are not canonical`)
  }
}

function pathKey(path) {
  const key = resolve(path).split(sep).join('/')
  return process.platform === 'win32' ? key.toLowerCase() : key
}

function samePath(left, right) {
  return pathKey(left) === pathKey(right)
}

function checkedDirectory(path, label) {
  const absolute = resolve(path)
  const info = lstatSync(absolute, { bigint: true })
  if (!info.isDirectory() || info.isSymbolicLink()) throw new Error(`${label} must be a real directory`)
  const canonical = realpathSync.native(absolute)
  if (!samePath(canonical, absolute)) throw new Error(`${label} traverses a symlink or junction`)
  return canonical
}

function checkedFile(path, label, { sha256, size } = {}) {
  const absolute = resolve(path)
  const info = lstatSync(absolute, { bigint: true })
  if (
    info.isSymbolicLink() ||
    !info.isFile() ||
    info.size <= 0n ||
    info.size > BigInt(MAX_RUNTIME_FILE_BYTES) ||
    info.size > BigInt(Number.MAX_SAFE_INTEGER)
  ) {
    throw new Error(`${label} must be a bounded non-empty regular file`)
  }
  const canonical = realpathSync.native(absolute)
  if (!samePath(canonical, absolute)) throw new Error(`${label} traverses a symlink or junction`)
  const numericSize = Number(info.size)
  if (size !== undefined && numericSize !== size) throw new Error(`${label} size drifted`)
  const digest = sha256Bytes(readFileSync(absolute))
  if (sha256 !== undefined && digest !== sha256) throw new Error(`${label} hash drifted`)
  return { sha256: digest, size: numericSize }
}

function checkedLock(document) {
  exactKeys(
    document,
    ['arch', 'archive', 'authenticode', 'builtins', 'platform', 'requiredFiles', 'runtime', 'schema', 'version'],
    'Git runtime lock'
  )
  const match = VERSION.exec(String(document.version || ''))
  if (document.schema !== 1 || document.platform !== 'win32' || document.arch !== 'x64' || !match) {
    throw new Error('Git runtime lock identity is invalid')
  }
  exactKeys(
    document.archive,
    ['contentType', 'githubApiDigest', 'name', 'publishedAt', 'releaseUrl', 'sha256', 'size', 'url'],
    'Git runtime archive lock'
  )
  const assetVersion = `${match[1]}.${match[2]}.${match[3]}.${match[4]}`
  const archiveName = `PortableGit-${assetVersion}-64-bit.7z.exe`
  const releaseRoot = `https://github.com/git-for-windows/git/releases`
  if (
    document.archive.name !== archiveName ||
    document.archive.releaseUrl !== `${releaseRoot}/tag/v${document.version}` ||
    document.archive.url !== `${releaseRoot}/download/v${document.version}/${archiveName}` ||
    document.archive.contentType !== 'application/executable' ||
    !SHA256.test(String(document.archive.sha256 || '')) ||
    document.archive.githubApiDigest !== `sha256:${document.archive.sha256}` ||
    !Number.isSafeInteger(document.archive.size) ||
    document.archive.size <= 0 ||
    !/^20\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ$/u.test(String(document.archive.publishedAt || ''))
  ) {
    throw new Error('Git runtime archive is not an exact official Git for Windows release asset')
  }
  exactKeys(
    document.authenticode,
    [
      'issuer',
      'notAfter',
      'notBefore',
      'serial',
      'status',
      'subject',
      'thumbprint',
      'timestampSubject',
      'timestampThumbprint'
    ],
    'Git runtime Authenticode lock'
  )
  if (
    document.authenticode.status !== 'Valid' ||
    !UPPER_SHA1.test(String(document.authenticode.thumbprint || '')) ||
    !UPPER_SHA1.test(String(document.authenticode.timestampThumbprint || '')) ||
    ['issuer', 'notAfter', 'notBefore', 'serial', 'subject', 'timestampSubject'].some(
      (key) => typeof document.authenticode[key] !== 'string' || !document.authenticode[key]
    )
  ) {
    throw new Error('Git runtime Authenticode identity is invalid')
  }
  if (JSON.stringify(document.builtins) !== JSON.stringify(REQUIRED_BUILTINS)) {
    throw new Error('Git runtime builtin command set is not canonical')
  }
  if (!Array.isArray(document.requiredFiles) || document.requiredFiles.length !== REQUIRED_PATHS.length) {
    throw new Error('Git runtime required file set is not closed')
  }
  for (let index = 0; index < REQUIRED_PATHS.length; index += 1) {
    const descriptor = document.requiredFiles[index]
    exactKeys(descriptor, ['path', 'sha256', 'size'], `Git runtime required file ${index + 1}`)
    if (
      descriptor.path !== REQUIRED_PATHS[index] ||
      !SHA256.test(String(descriptor.sha256 || '')) ||
      !Number.isSafeInteger(descriptor.size) ||
      descriptor.size <= 0
    ) {
      throw new Error('Git runtime required file descriptor is invalid or out of order')
    }
  }
  exactKeys(document.runtime, ['fileCount', 'totalBytes', 'treeSha256'], 'Git runtime tree lock')
  if (
    !Number.isSafeInteger(document.runtime.fileCount) ||
    document.runtime.fileCount < REQUIRED_PATHS.length ||
    document.runtime.fileCount > MAX_RUNTIME_FILES ||
    !Number.isSafeInteger(document.runtime.totalBytes) ||
    document.runtime.totalBytes <= 0 ||
    document.runtime.totalBytes > MAX_RUNTIME_BYTES ||
    !SHA256.test(String(document.runtime.treeSha256 || ''))
  ) {
    throw new Error('Git runtime tree identity is invalid')
  }
  return canonicalValue(document)
}

export function readGitRuntimeLock({ projectRoot = defaultProjectRoot, lockPath } = {}) {
  projectRoot = resolve(projectRoot)
  const resolved = resolve(lockPath || join(projectRoot, 'desktop', 'git-runtime-lock.json'))
  const bytes = readFileSync(resolved)
  let document
  try {
    document = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
  } catch {
    throw new Error('Git runtime lock must be UTF-8 JSON')
  }
  if (!bytes.equals(canonicalBytes(document))) throw new Error('Git runtime lock must be canonical JSON')
  return checkedLock(document)
}

function statIdentity(info) {
  return {
    device: info.dev.toString(),
    inode: info.ino.toString(),
    mode: info.mode.toString(8),
    links: info.nlink.toString(),
    size: info.size.toString(),
    modifiedNs: info.mtimeNs.toString(),
    changedNs: info.ctimeNs.toString(),
    bornNs: info.birthtimeNs.toString()
  }
}

function sameIdentity(left, right) {
  return JSON.stringify(left) === JSON.stringify(right)
}

function enumerateRuntimeTree(root) {
  root = checkedDirectory(root, 'prepared Git runtime')
  const files = []
  const directories = []
  const folded = new Set()
  const visit = (directory) => {
    const directoryInfo = lstatSync(directory, { bigint: true })
    directories.push({ path: relative(root, directory).split(sep).join('/'), identity: statIdentity(directoryInfo) })
    const names = readdirSync(directory).sort(ordinal)
    for (const name of names) {
      if (!name || /[\u0000-\u001f\u007f]/u.test(name)) throw new Error('Git runtime contains an unsafe path')
      const path = join(directory, name)
      const info = lstatSync(path, { bigint: true })
      if (info.isSymbolicLink()) throw new Error('Git runtime contains a filesystem redirect')
      const canonical = realpathSync.native(path)
      if (!samePath(canonical, path)) throw new Error('Git runtime path traverses a symlink or junction')
      if (info.isDirectory()) {
        visit(path)
        continue
      }
      if (!info.isFile()) throw new Error('Git runtime contains a special filesystem entry')
      const relativePath = relative(root, path).split(sep).join('/')
      const key = process.platform === 'win32' ? relativePath.toLowerCase() : relativePath
      if (folded.has(key)) throw new Error(`Git runtime contains a case-colliding path: ${relativePath}`)
      folded.add(key)
      // The official PortableGit tree intentionally contains zero-byte CA bundle placeholders.
      // They remain part of the closed-set path/hash manifest and must not be silently omitted.
      if (info.size < 0n || info.size > BigInt(MAX_RUNTIME_FILE_BYTES) || info.size > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new Error(`Git runtime file has an invalid or unbounded size: ${relativePath}`)
      }
      files.push({
        absolute: path,
        identity: statIdentity(info),
        path: relativePath,
        size: Number(info.size)
      })
      if (files.length > MAX_RUNTIME_FILES) throw new Error('Git runtime file count is unbounded')
    }
  }
  visit(root)
  files.sort((left, right) => ordinal(left.path, right.path))
  directories.sort((left, right) => ordinal(left.path, right.path))
  return { root, files, directories }
}

async function hashOpenedFile(file) {
  const handle = await open(file.absolute, 'r')
  let digest
  try {
    const opened = await handle.stat({ bigint: true })
    if (!opened.isFile() || !sameIdentity(file.identity, statIdentity(opened))) {
      throw new Error(`Git runtime file identity changed while opening: ${file.path}`)
    }
    const hash = createHash('sha256')
    const buffer = Buffer.allocUnsafe(64 * 1024)
    let total = 0
    while (true) {
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, null)
      if (bytesRead === 0) break
      total += bytesRead
      if (total > file.size) throw new Error(`Git runtime file grew while hashing: ${file.path}`)
      hash.update(buffer.subarray(0, bytesRead))
    }
    if (total !== file.size) throw new Error(`Git runtime file size changed while hashing: ${file.path}`)
    const afterHandle = await handle.stat({ bigint: true })
    if (!sameIdentity(file.identity, statIdentity(afterHandle))) {
      throw new Error(`Git runtime file identity changed while hashing: ${file.path}`)
    }
    digest = hash.digest('hex')
  } finally {
    await handle.close()
  }
  const afterPath = lstatSync(file.absolute, { bigint: true })
  if (!sameIdentity(file.identity, statIdentity(afterPath))) {
    throw new Error(`Git runtime file was replaced while hashing: ${file.path}`)
  }
  return { path: file.path, sha256: digest, size: file.size }
}

function assertEnumerationStable(before, after) {
  if (
    before.files.length !== after.files.length ||
    before.directories.length !== after.directories.length ||
    JSON.stringify(before.files.map(({ path }) => path)) !== JSON.stringify(after.files.map(({ path }) => path)) ||
    JSON.stringify(before.directories.map(({ path }) => path)) !== JSON.stringify(after.directories.map(({ path }) => path))
  ) {
    throw new Error('Git runtime file or directory set changed during inventory')
  }
  for (let index = 0; index < before.files.length; index += 1) {
    if (!sameIdentity(before.files[index].identity, after.files[index].identity)) {
      throw new Error(`Git runtime file identity changed during inventory: ${before.files[index].path}`)
    }
  }
  for (let index = 0; index < before.directories.length; index += 1) {
    if (!sameIdentity(before.directories[index].identity, after.directories[index].identity)) {
      throw new Error(`Git runtime directory identity changed during inventory: ${before.directories[index].path}`)
    }
  }
}

export async function runtimeTreeInventory(root) {
  const before = enumerateRuntimeTree(resolve(root))
  const files = []
  let totalBytes = 0
  const treeHash = createHash('sha256')
  for (const file of before.files) {
    const descriptor = await hashOpenedFile(file)
    totalBytes += descriptor.size
    if (totalBytes > MAX_RUNTIME_BYTES) throw new Error('Git runtime total byte size is unbounded')
    files.push(descriptor)
    treeHash.update(`${descriptor.path}\0${descriptor.size}\0${descriptor.sha256}\n`, 'utf8')
  }
  const after = enumerateRuntimeTree(before.root)
  assertEnumerationStable(before, after)
  return {
    fileCount: files.length,
    files,
    totalBytes,
    treeSha256: treeHash.digest('hex')
  }
}

function assertLockedRuntime(inventory, root, lock) {
  if (
    inventory.fileCount !== lock.runtime.fileCount ||
    inventory.totalBytes !== lock.runtime.totalBytes ||
    inventory.treeSha256 !== lock.runtime.treeSha256
  ) {
    throw new Error('prepared Git runtime tree drifted from the locked official archive')
  }
  const byPath = new Map(inventory.files.map((item) => [item.path, item]))
  for (const expected of lock.requiredFiles) {
    const actual = byPath.get(expected.path)
    if (!actual || actual.size !== expected.size || actual.sha256 !== expected.sha256) {
      throw new Error(`prepared Git runtime required file drifted: ${expected.path}`)
    }
    checkedFile(join(root, ...expected.path.split('/')), `prepared Git runtime ${expected.path}`, expected)
  }
}

function minimalWindowsEnvironment(extra = {}) {
  const environment = { ...extra }
  for (const key of ['SystemRoot', 'WINDIR', 'ComSpec', 'PATHEXT', 'TEMP', 'TMP']) {
    const value = process.env[key]
    if (value) environment[key] = value
  }
  return environment
}

function runBoundedProcess(executable, args, { cwd, env, timeoutMs, label }) {
  return new Promise((accept, reject) => {
    const child = spawn(executable, args, {
      cwd,
      env,
      shell: false,
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true
    })
    const stdout = []
    const stderr = []
    let outputBytes = 0
    let failure = null
    let settled = false
    const fail = (error) => {
      if (!failure) failure = error
      child.kill()
    }
    const collect = (target, chunk) => {
      if (failure) return
      const bytes = Buffer.from(chunk)
      outputBytes += bytes.length
      if (outputBytes > MAX_COMMAND_OUTPUT_BYTES) {
        fail(new Error(`${label} output exceeded the bound`))
        return
      }
      target.push(bytes)
    }
    child.stdout.on('data', (chunk) => collect(stdout, chunk))
    child.stderr.on('data', (chunk) => collect(stderr, chunk))
    child.once('error', (error) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      reject(error)
    })
    child.once('close', (exitCode, signal) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      if (failure) {
        reject(failure)
        return
      }
      if (exitCode !== 0 || signal) {
        reject(new Error(`${label} failed with exit ${exitCode}${signal ? ` signal ${signal}` : ''}`))
        return
      }
      accept({ stdout: Buffer.concat(stdout), stderr: Buffer.concat(stderr) })
    })
    const timer = setTimeout(() => fail(new Error(`${label} timed out`)), timeoutMs)
    timer.unref?.()
  })
}

export async function verifyArchiveAuthenticode({ archivePath }) {
  if (process.platform !== 'win32') throw new Error('Git runtime Authenticode verification requires Windows')
  const powershell = join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe')
  checkedFile(powershell, 'Windows PowerShell Authenticode verifier')
  const source = [
    "$ErrorActionPreference='Stop'",
    "$ProgressPreference='SilentlyContinue'",
    "$utf8=[Text.UTF8Encoding]::new($false)",
    '[Console]::OutputEncoding=$utf8',
    '$OutputEncoding=$utf8',
    "$signature=Get-AuthenticodeSignature -LiteralPath $env:NACHUAN_GIT_ARCHIVE_PATH -ErrorAction Stop",
    "[pscustomobject]@{issuer=$signature.SignerCertificate.Issuer;notAfter=$signature.SignerCertificate.NotAfter.ToUniversalTime().ToString('o');notBefore=$signature.SignerCertificate.NotBefore.ToUniversalTime().ToString('o');serial=$signature.SignerCertificate.SerialNumber;status=$signature.Status.ToString();subject=$signature.SignerCertificate.Subject;thumbprint=$signature.SignerCertificate.Thumbprint;timestampSubject=$signature.TimeStamperCertificate.Subject;timestampThumbprint=$signature.TimeStamperCertificate.Thumbprint} | ConvertTo-Json -Compress"
  ].join(';')
  const encoded = Buffer.from(source, 'utf16le').toString('base64')
  const result = await runBoundedProcess(
    powershell,
    ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encoded],
    {
      cwd: dirname(archivePath),
      env: minimalWindowsEnvironment({ NACHUAN_GIT_ARCHIVE_PATH: archivePath }),
      timeoutMs: 120_000,
      label: 'Git runtime Authenticode verification'
    }
  )
  if (result.stderr.length) {
    const detail = result.stderr.toString('utf8').replace(/[\u0000-\u001f\u007f]+/gu, ' ').trim().slice(0, 512)
    throw new Error(`Git runtime Authenticode verification produced stderr${detail ? `: ${detail}` : ''}`)
  }
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(result.stdout).trim())
  } catch {
    throw new Error('Git runtime Authenticode verification returned invalid JSON')
  }
}

function assertAuthenticode(actual, lock) {
  if (JSON.stringify(canonicalValue(actual)) !== JSON.stringify(lock.authenticode)) {
    throw new Error('Git runtime Authenticode identity drifted from the lock')
  }
}

async function downloadExact({ destination, expectedSha256, expectedSize, sourceUrl, fetchImpl = fetch }) {
  let current = new URL(sourceUrl)
  let response
  for (let redirects = 0; redirects <= MAX_REDIRECTS; redirects += 1) {
    if (current.protocol !== 'https:' || current.username || current.password || current.hash) {
      throw new Error('Git runtime download URL must remain credential-free HTTPS')
    }
    if (!['github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com'].includes(current.hostname)) {
      throw new Error(`Git runtime download redirected to an unapproved host: ${current.hostname}`)
    }
    response = await fetchImpl(current, { redirect: 'manual', signal: AbortSignal.timeout(900_000) })
    if (![301, 302, 303, 307, 308].includes(response.status)) break
    const location = response.headers.get('location')
    if (!location) throw new Error('Git runtime redirect omitted Location')
    current = new URL(location, current)
  }
  if (!response?.ok || !response.body) throw new Error(`Git runtime download failed with HTTP ${response?.status}`)
  const declared = response.headers.get('content-length')
  if (declared && Number(declared) !== expectedSize) throw new Error('Git runtime Content-Length drifted')
  await pipeline(response.body, createWriteStream(destination, { flags: 'wx' }))
  checkedFile(destination, 'downloaded Git runtime archive', { sha256: expectedSha256, size: expectedSize })
}

async function extractOfficialSfx(archivePath, destination) {
  const result = await runBoundedProcess(archivePath, ['-y', `-o${destination}`], {
    cwd: dirname(archivePath),
    env: minimalWindowsEnvironment(),
    timeoutMs: 300_000,
    label: 'official PortableGit self-extraction'
  })
  if (result.stderr.length) throw new Error('official PortableGit self-extraction produced stderr')
}

async function checkedGitProbe(executable, args, cwd, environment, label) {
  const result = await executeReleaseGitCommand({
    executable,
    args,
    cwd,
    env: environment,
    timeoutMs: 30_000,
    maxOutputBytes: MAX_COMMAND_OUTPUT_BYTES,
    shell: false
  })
  if (result.exitCode !== 0 || result.signal || result.stderr.length) throw new Error(`${label} failed`)
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(result.stdout).trim()
  } catch {
    throw new Error(`${label} returned non-UTF-8 text`)
  }
}

function minimalGitEnvironment(projectRoot, execPath) {
  return minimalWindowsEnvironment({
    GIT_ATTR_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: 'NUL',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_COUNT: '1',
    GIT_CONFIG_KEY_0: 'core.fsmonitor',
    GIT_CONFIG_VALUE_0: 'false',
    GIT_DISCOVERY_ACROSS_FILESYSTEM: '0',
    GIT_EXEC_PATH: execPath,
    GIT_EXTERNAL_DIFF: '',
    GIT_LITERAL_PATHSPECS: '1',
    GIT_NO_LAZY_FETCH: '1',
    GIT_NO_REPLACE_OBJECTS: '1',
    GIT_OPTIONAL_LOCKS: '0',
    GIT_PAGER: 'cat',
    GIT_TERMINAL_PROMPT: '0',
    HOME: projectRoot,
    LANG: 'C',
    LC_ALL: 'C',
    USERPROFILE: projectRoot
  })
}

async function probePreparedRuntime({ projectRoot, runtimeRoot, lock }) {
  const corePath = join(runtimeRoot, 'mingw64', 'bin', 'git.exe')
  const execPath = join(runtimeRoot, 'mingw64', 'libexec', 'git-core')
  checkedFile(corePath, 'prepared Git core', lock.requiredFiles.find(({ path }) => path === 'mingw64/bin/git.exe'))
  checkedDirectory(execPath, 'prepared Git exec path')
  const baseEnvironment = minimalGitEnvironment(projectRoot, execPath)
  const discoveryEnvironment = { ...baseEnvironment }
  delete discoveryEnvironment.GIT_EXEC_PATH
  const reportedExecPath = resolve(
    await checkedGitProbe(corePath, ['--no-pager', '--exec-path'], projectRoot, discoveryEnvironment, 'Git exec-path probe')
  )
  if (!samePath(reportedExecPath, execPath)) throw new Error('prepared Git core reported an unexpected exec-path')
  const versionText = await checkedGitProbe(
    corePath,
    ['--no-pager', '--version'],
    projectRoot,
    baseEnvironment,
    'Git version probe'
  )
  if (versionText !== `git version ${lock.version}`) throw new Error('prepared Git core version drifted')
  const commandText = await checkedGitProbe(
    corePath,
    ['--no-pager', '--list-cmds=builtins'],
    projectRoot,
    baseEnvironment,
    'Git builtin probe'
  )
  const available = new Set(commandText.split(/\s+/u).filter(Boolean))
  if (lock.builtins.some((command) => !available.has(command))) {
    throw new Error('prepared Git core no longer implements every release command as a builtin')
  }
  return { builtins: [...lock.builtins], corePath, execPath, version: lock.version }
}

function buildPaths(projectRoot, lock) {
  const buildRoot = join(projectRoot, 'build')
  return {
    archivePath: join(buildRoot, 'git-cache', lock.archive.name),
    buildRoot,
    cacheRoot: join(buildRoot, 'git-cache'),
    provenancePath: join(buildRoot, PROVENANCE_NAME),
    runtimeRoot: join(buildRoot, 'git-runtime')
  }
}

function ensureWithinBuild(buildRoot, path, label) {
  const displacement = relative(buildRoot, path)
  if (!displacement || displacement === '..' || displacement.startsWith(`..${sep}`) || isAbsolute(displacement)) {
    throw new Error(`${label} escapes the project build root`)
  }
}

async function safeRemove(buildRoot, path, label) {
  ensureWithinBuild(buildRoot, path, label)
  if (!existsSync(path)) return
  const info = lstatSync(path)
  if (info.isSymbolicLink()) throw new Error(`refusing to remove redirected ${label}`)
  await rm(path, { recursive: info.isDirectory(), force: true })
}

function expectedProvenance({ archive, authenticode, inventory, lock, lockBytes, probe }) {
  return canonicalValue({
    archive: { ...archive, name: lock.archive.name, url: lock.archive.url },
    authenticode,
    files: inventory.files,
    lock: { sha256: sha256Bytes(lockBytes), size: lockBytes.length },
    runtime: {
      builtins: probe.builtins,
      core: 'mingw64/bin/git.exe',
      execPath: 'mingw64/libexec/git-core',
      fileCount: inventory.fileCount,
      totalBytes: inventory.totalBytes,
      treeSha256: inventory.treeSha256
    },
    schema: 1,
    target: { arch: lock.arch, platform: lock.platform, version: lock.version }
  })
}

async function validateRuntime({ projectRoot, runtimeRoot, lock, probeRuntime }) {
  const inventory = await runtimeTreeInventory(runtimeRoot)
  assertLockedRuntime(inventory, runtimeRoot, lock)
  const probe = await (probeRuntime || probePreparedRuntime)({ projectRoot, runtimeRoot, lock, ...{
    corePath: join(runtimeRoot, 'mingw64', 'bin', 'git.exe'),
    execPath: join(runtimeRoot, 'mingw64', 'libexec', 'git-core'),
    builtins: [...lock.builtins]
  } })
  if (
    probe.version !== lock.version ||
    !samePath(probe.corePath, join(runtimeRoot, 'mingw64', 'bin', 'git.exe')) ||
    !samePath(probe.execPath, join(runtimeRoot, 'mingw64', 'libexec', 'git-core')) ||
    JSON.stringify(probe.builtins) !== JSON.stringify(lock.builtins)
  ) {
    throw new Error('prepared Git runtime probe result is invalid')
  }
  return { inventory, probe }
}

export function gitRuntimeCorePath(projectRoot = defaultProjectRoot) {
  return join(resolve(projectRoot), 'build', 'git-runtime', 'mingw64', 'bin', 'git.exe')
}

export async function prepareGitRuntime({
  projectRoot = defaultProjectRoot,
  lockPath,
  download = downloadExact,
  extractArchive = extractOfficialSfx,
  verifyAuthenticode = verifyArchiveAuthenticode,
  probeRuntime
} = {}) {
  projectRoot = resolve(projectRoot)
  checkedDirectory(projectRoot, 'project root')
  const resolvedLockPath = resolve(lockPath || join(projectRoot, 'desktop', 'git-runtime-lock.json'))
  const lockBytes = readFileSync(resolvedLockPath)
  const lock = readGitRuntimeLock({ projectRoot, lockPath: resolvedLockPath })
  const paths = buildPaths(projectRoot, lock)
  await mkdir(paths.cacheRoot, { recursive: true })
  checkedDirectory(paths.buildRoot, 'project build root')
  checkedDirectory(paths.cacheRoot, 'Git runtime cache')
  if (existsSync(paths.archivePath)) {
    try {
      checkedFile(paths.archivePath, 'cached Git runtime archive', lock.archive)
    } catch {
      await safeRemove(paths.buildRoot, paths.archivePath, 'Git runtime archive')
    }
  }
  if (!existsSync(paths.archivePath)) {
    const candidate = join(paths.cacheRoot, `.${lock.archive.name}.${randomUUID()}.download`)
    try {
      await download({
        destination: candidate,
        expectedSha256: lock.archive.sha256,
        expectedSize: lock.archive.size,
        sourceUrl: lock.archive.url
      })
      checkedFile(candidate, 'candidate Git runtime archive', lock.archive)
      await rename(candidate, paths.archivePath)
    } finally {
      await safeRemove(paths.buildRoot, candidate, 'Git runtime download candidate')
    }
  }
  const archive = checkedFile(paths.archivePath, 'prepared Git runtime archive', lock.archive)
  const authenticode = canonicalValue(await verifyAuthenticode({ archivePath: paths.archivePath }))
  assertAuthenticode(authenticode, lock)

  const candidateRoot = join(paths.buildRoot, `.git-runtime.${randomUUID()}`)
  await safeRemove(paths.buildRoot, candidateRoot, 'Git runtime extraction candidate')
  await mkdir(candidateRoot)
  try {
    await extractArchive(paths.archivePath, candidateRoot)
    await validateRuntime({ projectRoot, runtimeRoot: candidateRoot, lock, probeRuntime })
    await safeRemove(paths.buildRoot, paths.runtimeRoot, 'prepared Git runtime')
    await rename(candidateRoot, paths.runtimeRoot)
  } finally {
    await safeRemove(paths.buildRoot, candidateRoot, 'Git runtime extraction candidate')
  }
  const { inventory, probe } = await validateRuntime({
    projectRoot,
    runtimeRoot: paths.runtimeRoot,
    lock,
    probeRuntime
  })
  const provenance = expectedProvenance({ archive, authenticode, inventory, lock, lockBytes, probe })
  await safeRemove(paths.buildRoot, paths.provenancePath, 'Git runtime provenance')
  await writeFile(paths.provenancePath, canonicalBytes(provenance), { flag: 'wx' })
  return { ...paths, corePath: probe.corePath, lock, provenance }
}

export async function verifyPreparedGitRuntime({
  projectRoot = defaultProjectRoot,
  lockPath,
  verifyAuthenticode = verifyArchiveAuthenticode,
  probeRuntime
} = {}) {
  projectRoot = resolve(projectRoot)
  const resolvedLockPath = resolve(lockPath || join(projectRoot, 'desktop', 'git-runtime-lock.json'))
  const lockBytes = readFileSync(resolvedLockPath)
  const lock = readGitRuntimeLock({ projectRoot, lockPath: resolvedLockPath })
  const paths = buildPaths(projectRoot, lock)
  checkedDirectory(paths.buildRoot, 'project build root')
  checkedDirectory(paths.cacheRoot, 'Git runtime cache')
  const archive = checkedFile(paths.archivePath, 'prepared Git runtime archive', lock.archive)
  const authenticode = canonicalValue(await verifyAuthenticode({ archivePath: paths.archivePath }))
  assertAuthenticode(authenticode, lock)
  const { inventory, probe } = await validateRuntime({
    projectRoot,
    runtimeRoot: paths.runtimeRoot,
    lock,
    probeRuntime
  })
  const provenanceBytes = await readFile(paths.provenancePath)
  let provenance
  try {
    provenance = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(provenanceBytes))
  } catch {
    throw new Error('Git runtime provenance must be UTF-8 JSON')
  }
  if (!provenanceBytes.equals(canonicalBytes(provenance))) throw new Error('Git runtime provenance is not canonical')
  const expected = expectedProvenance({ archive, authenticode, inventory, lock, lockBytes, probe })
  if (!provenanceBytes.equals(canonicalBytes(expected))) {
    throw new Error('Git runtime provenance drifted from archive, lock, or extracted tree')
  }
  return { ...paths, corePath: probe.corePath, lock, provenance }
}

async function main(argv) {
  if (argv.length !== 1 || !['prepare', 'verify'].includes(argv[0])) {
    throw new Error('usage: git-runtime-policy.mjs prepare|verify')
  }
  const result = argv[0] === 'prepare' ? await prepareGitRuntime() : await verifyPreparedGitRuntime()
  console.log(`[git-runtime] ${argv[0].toUpperCase()} version=${result.lock.version} sha256=${result.lock.archive.sha256}`)
}

if (resolve(process.argv[1] || '') === scriptPath) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(`[git-runtime] BLOCKED: ${error?.stack || error}`)
    process.exitCode = 1
  })
}
