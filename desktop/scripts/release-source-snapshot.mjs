import { createHash } from 'node:crypto'
import { spawn } from 'node:child_process'
import { lstat, open, readdir, realpath } from 'node:fs/promises'
import { devNull } from 'node:os'
import { isAbsolute, join, posix, relative, resolve, sep } from 'node:path'

const SNAPSHOT_SCHEMA = 'nachuan.release-source-snapshot/v1'
const OID = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u
const SHA256 = /^[0-9a-f]{64}$/u
const CONTROL_CHARACTER = /[\u0000-\u001f\u007f]/u
const DEFAULT_LIMITS = Object.freeze({
  maxFiles: 50_000,
  maxFileBytes: 512 * 1024 * 1024,
  maxTotalBytes: 4 * 1024 * 1024 * 1024,
  maxGitOutputBytes: 16 * 1024 * 1024,
  gitTimeoutMs: 30_000
})
const HARD_LIMITS = Object.freeze({
  maxFiles: 100_000,
  maxFileBytes: 4 * 1024 * 1024 * 1024,
  maxTotalBytes: 16 * 1024 * 1024 * 1024,
  maxGitOutputBytes: 64 * 1024 * 1024,
  gitTimeoutMs: 120_000
})

export const RELEASE_FORBIDDEN_AMBIENT_PATHS = Object.freeze([
  '.env',
  '.env.*',
  'conftest.py',
  'desktop/.env',
  'desktop/.env.*',
  'sitecustomize.py',
  'usercustomize.py'
])
export const RELEASE_ALLOWED_AMBIENT_TEMPLATES = Object.freeze([
  '.env.example',
  'desktop/.env.example'
])
export const RELEASE_SEPARATELY_FROZEN_SOURCE_PATHS = Object.freeze([
  'desktop/src/main/generated-engine-integrity.ts',
  'desktop/src/main/generated-update-trust.ts'
])
export const RELEASE_SOURCE_SCOPE = Object.freeze({
  files: Object.freeze([
    '.gitattributes',
    '.gitignore',
    '.python-version',
    'desktop/.gitignore',
    'desktop/.npmrc',
    'desktop/electron-builder.early-access.yml',
    'desktop/electron-builder.production.yml',
    'desktop/electron-builder.yml',
    'desktop/electron.vite.config.ts',
    'desktop/native-license-registry.json',
    'desktop/package-lock.json',
    'desktop/package.json',
    'desktop/python-license-registry.json',
    'desktop/tsconfig.json',
    'engine.spec',
    'engine_main.py',
    'pyproject.toml',
    'uv.lock'
  ]),
  optionalFiles: Object.freeze([
    '.env.example',
    '.npmrc',
    '.pytest.ini',
    'pytest.ini',
    'pytest.toml',
    'setup.cfg',
    'tox.ini',
    'uv.toml'
  ]),
  directories: Object.freeze([
    '.github/workflows',
    'bridge',
    'config',
    'desktop',
    'gateway',
    'orchestrator',
    'scripts',
    'skills',
    'tests'
  ]),
  optionalDirectories: Object.freeze(['.github/actions']),
  excludedPaths: Object.freeze([
    'bridge/__pycache__',
    'config/__pycache__',
    'desktop/.vite',
    'desktop/build/electron-runtime',
    'desktop/build/license-evidence',
    'desktop/coverage',
    'desktop/node_modules',
    'desktop/out',
    'desktop/release',
    ...RELEASE_SEPARATELY_FROZEN_SOURCE_PATHS,
    'desktop/third-party-notices',
    'gateway/__pycache__',
    'gateway/providers/__pycache__',
    'orchestrator/__pycache__',
    'orchestrator/workflows/__pycache__',
    'scripts/__pycache__',
    'tests/__pycache__'
  ])
})

function ordinal(left, right) {
  return left < right ? -1 : left > right ? 1 : 0
}

function pathKey(path) {
  const key = resolve(path).split(sep).join('/')
  return process.platform === 'win32' ? key.toLowerCase() : key
}

function foldedSourcePath(path) {
  return path.toLowerCase()
}

function isForbiddenAmbientPath(path) {
  const folded = foldedSourcePath(path)
  if (['conftest.py', 'sitecustomize.py', 'usercustomize.py'].includes(folded)) return true
  const parts = folded.split('/')
  if (parts.length > 2 || (parts.length === 2 && parts[0] !== 'desktop')) return false
  const name = parts.at(-1)
  if (name === '.env.example') return false
  return name === '.env' || name.startsWith('.env.')
}

function checkedRelativePath(value, label = 'source path') {
  const path = String(value || '')
  if (
    !path ||
    path.includes('\\') ||
    CONTROL_CHARACTER.test(path) ||
    isAbsolute(path) ||
    posix.normalize(path) !== path ||
    path.split('/').some((part) => !part || part === '.' || part === '..')
  ) {
    throw new Error(`${label} is not a canonical repository-relative path: ${value}`)
  }
  return path
}

function uniqueSorted(values, checker, label) {
  if (!Array.isArray(values) || values.length === 0) throw new Error(`${label} must be a non-empty array`)
  const result = values.map((value) => checker(value)).sort(ordinal)
  const folded = new Set()
  for (const value of result) {
    const key = value.toLowerCase()
    if (folded.has(key)) throw new Error(`${label} contains a duplicate or case collision: ${value}`)
    folded.add(key)
  }
  return result
}

function optionalUniqueSorted(values, checker, label) {
  if (values === undefined) return []
  if (!Array.isArray(values)) throw new Error(`${label} must be an array`)
  if (values.length === 0) return []
  return uniqueSorted(values, checker, label)
}

function normalizeScope(scope = RELEASE_SOURCE_SCOPE) {
  if (!scope || typeof scope !== 'object' || Array.isArray(scope)) {
    throw new Error('release source scope must be an object')
  }
  const files = uniqueSorted(scope.files, (value) => checkedRelativePath(value, 'scope file'), 'scope files')
  const optionalFiles = optionalUniqueSorted(
    scope.optionalFiles,
    (value) => checkedRelativePath(value, 'optional scope file'),
    'optional scope files'
  )
  const directories = uniqueSorted(
    scope.directories,
    (value) => checkedRelativePath(value, 'scope directory'),
    'scope directories'
  )
  const optionalDirectories = optionalUniqueSorted(
    scope.optionalDirectories,
    (value) => checkedRelativePath(value, 'optional scope directory'),
    'optional scope directories'
  )
  const excludedPaths = optionalUniqueSorted(
    scope.excludedPaths,
    (value) => checkedRelativePath(value, 'excluded scope path'),
    'excluded scope paths'
  )
  const allRoots = new Set()
  for (const path of [...files, ...optionalFiles, ...directories, ...optionalDirectories]) {
    const key = foldedSourcePath(path)
    if (allRoots.has(key)) throw new Error(`release source scope contains an overlapping root: ${path}`)
    allRoots.add(key)
  }
  return { files, optionalFiles, directories, optionalDirectories, excludedPaths }
}

function isExcludedPath(path, excludedPaths) {
  const folded = foldedSourcePath(path)
  return excludedPaths.some((excludedPath) => {
    const excluded = foldedSourcePath(excludedPath)
    return folded === excluded || folded.startsWith(`${excluded}/`)
  })
}

export function isReleaseSourcePath(value, scope = RELEASE_SOURCE_SCOPE) {
  let path
  let normalized
  try {
    path = checkedRelativePath(value)
    normalized = normalizeScope(scope)
  } catch {
    return false
  }
  if (isExcludedPath(path, normalized.excludedPaths)) return false
  const folded = foldedSourcePath(path)
  if (normalized.files.some((file) => foldedSourcePath(file) === folded)) return true
  if (normalized.optionalFiles.some((file) => foldedSourcePath(file) === folded)) return true
  return [...normalized.directories, ...normalized.optionalDirectories].some((directory) => {
    const prefix = `${foldedSourcePath(directory)}/`
    return folded.startsWith(prefix)
  })
}

function checkedLimit(value, fallback, maximum, label) {
  const selected = value === undefined ? fallback : value
  if (!Number.isSafeInteger(selected) || selected <= 0 || selected > maximum) {
    throw new Error(`${label} must be a bounded positive integer`)
  }
  return selected
}

function normalizeLimits(limits = {}) {
  if (!limits || typeof limits !== 'object' || Array.isArray(limits)) {
    throw new Error('release source limits must be an object')
  }
  return {
    maxFiles: checkedLimit(limits.maxFiles, DEFAULT_LIMITS.maxFiles, HARD_LIMITS.maxFiles, 'maxFiles'),
    maxFileBytes: checkedLimit(
      limits.maxFileBytes,
      DEFAULT_LIMITS.maxFileBytes,
      HARD_LIMITS.maxFileBytes,
      'maxFileBytes'
    ),
    maxTotalBytes: checkedLimit(
      limits.maxTotalBytes,
      DEFAULT_LIMITS.maxTotalBytes,
      HARD_LIMITS.maxTotalBytes,
      'maxTotalBytes'
    ),
    maxGitOutputBytes: checkedLimit(
      limits.maxGitOutputBytes,
      DEFAULT_LIMITS.maxGitOutputBytes,
      HARD_LIMITS.maxGitOutputBytes,
      'maxGitOutputBytes'
    ),
    gitTimeoutMs: checkedLimit(
      limits.gitTimeoutMs,
      DEFAULT_LIMITS.gitTimeoutMs,
      HARD_LIMITS.gitTimeoutMs,
      'gitTimeoutMs'
    )
  }
}

function minimalGitEnvironment(repoRoot) {
  const environment = {
    GIT_ATTR_NOSYSTEM: '1',
    // Git for Windows rejects Node's \\.\nul spelling; its native NUL device is accepted.
    GIT_CONFIG_GLOBAL: process.platform === 'win32' ? 'NUL' : devNull,
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_COUNT: '1',
    GIT_CONFIG_KEY_0: 'core.fsmonitor',
    GIT_CONFIG_VALUE_0: 'false',
    GIT_DISCOVERY_ACROSS_FILESYSTEM: '0',
    GIT_EXTERNAL_DIFF: '',
    GIT_LITERAL_PATHSPECS: '1',
    GIT_NO_LAZY_FETCH: '1',
    GIT_NO_REPLACE_OBJECTS: '1',
    GIT_OPTIONAL_LOCKS: '0',
    GIT_PAGER: 'cat',
    GIT_TERMINAL_PROMPT: '0',
    HOME: repoRoot,
    LANG: 'C',
    LC_ALL: 'C',
    USERPROFILE: repoRoot
  }
  const inheritedKeys =
    process.platform === 'win32'
      ? ['SystemRoot', 'WINDIR', 'ComSpec', 'PATHEXT', 'TEMP', 'TMP']
      : ['TMPDIR']
  for (const key of inheritedKeys) {
    const value = process.env[key]
    if (value) environment[key] = value
  }
  return environment
}

function boundedBuffer(value, label, maximum) {
  const buffer = Buffer.isBuffer(value) ? value : Buffer.from(value || '')
  if (buffer.length > maximum) throw new Error(`${label} exceeded the bounded Git output limit`)
  return buffer
}

export async function executeReleaseGitCommand(request) {
  const {
    executable,
    args,
    cwd,
    env,
    timeoutMs,
    maxOutputBytes,
    shell = false
  } = request || {}
  if (!isAbsolute(String(executable || ''))) throw new Error('Git executable must be absolute')
  if (!Array.isArray(args) || args.some((argument) => typeof argument !== 'string')) {
    throw new Error('Git arguments must be a string array')
  }
  if (shell !== false) throw new Error('release Git commands must not use a shell')
  return new Promise((accept, reject) => {
    let child
    try {
      child = spawn(executable, args, {
        cwd,
        env,
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true
      })
    } catch (error) {
      reject(error)
      return
    }
    const stdout = []
    const stderr = []
    let outputBytes = 0
    let failure = null
    let settled = false

    const failAndTerminate = (error) => {
      if (!failure) failure = error
      child.kill()
    }
    const collect = (chunks, chunk) => {
      if (failure) return
      const buffer = Buffer.from(chunk)
      outputBytes += buffer.length
      if (outputBytes > maxOutputBytes) {
        failAndTerminate(new Error('Git command exceeded the bounded output limit'))
        return
      }
      chunks.push(buffer)
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
      accept({
        exitCode,
        signal,
        stdout: Buffer.concat(stdout),
        stderr: Buffer.concat(stderr)
      })
    })
    const timer = setTimeout(() => {
      failAndTerminate(new Error(`Git command timed out after ${timeoutMs}ms`))
    }, timeoutMs)
    timer.unref?.()
  })
}

async function checkedGitExecutable(gitPath) {
  if (!isAbsolute(String(gitPath || ''))) throw new Error('Git executable must be an absolute path')
  const absolute = resolve(gitPath)
  const info = await lstat(absolute)
  if (info.isSymbolicLink() || !info.isFile()) throw new Error('Git executable must be a real regular file')
  const canonical = await realpath(absolute)
  if (pathKey(canonical) !== pathKey(absolute)) {
    throw new Error('Git executable path must not traverse a symlink or junction')
  }
  return canonical
}

async function captureGitExecutableAttestation(gitPath, maxFileBytes) {
  const content = await hashReleaseSourceFile({
    path: gitPath,
    relativePath: 'Git executable',
    maxFileBytes
  })
  const { workingGitBlob: _unusedGitBlob, ...attestation } = content
  return { path: gitPath, ...attestation }
}

async function checkedRepositoryRoot(repoRoot) {
  const absolute = resolve(String(repoRoot || ''))
  const info = await lstat(absolute)
  if (info.isSymbolicLink() || !info.isDirectory()) {
    throw new Error('release source repository root must be a real directory')
  }
  return realpath(absolute)
}

function checkedOid(value, label) {
  const oid = String(value || '').toLowerCase()
  if (!OID.test(oid)) throw new Error(`${label} must be a full Git object ID`)
  return oid
}

function checkedTag(value) {
  const tag = String(value || '')
  if (
    !tag ||
    tag.length > 128 ||
    tag.startsWith('-') ||
    tag.startsWith('/') ||
    tag.endsWith('/') ||
    tag.endsWith('.') ||
    tag.endsWith('.lock') ||
    tag.includes('..') ||
    tag.includes('//') ||
    tag.includes('@{') ||
    tag.includes('\\') ||
    /[~^:?*[\u0000-\u0020\u007f]/u.test(tag)
  ) {
    throw new Error(`expected tag is not a canonical Git tag name: ${value}`)
  }
  return tag
}

async function runGit(context, args, acceptedExitCodes = [0], environment = context.environment) {
  const request = {
    executable: context.gitPath,
    args,
    cwd: context.repoRoot,
    env: environment,
    timeoutMs: context.limits.gitTimeoutMs,
    maxOutputBytes: context.limits.maxGitOutputBytes,
    shell: false
  }
  const raw = await context.executeGit(request)
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error('Git command executor returned an invalid result')
  }
  const stdout = boundedBuffer(raw.stdout, 'Git stdout', context.limits.maxGitOutputBytes)
  const stderr = boundedBuffer(raw.stderr, 'Git stderr', context.limits.maxGitOutputBytes)
  if (stdout.length + stderr.length > context.limits.maxGitOutputBytes) {
    throw new Error('Git command exceeded the combined bounded output limit')
  }
  const exitCode = raw.exitCode
  if (!Number.isInteger(exitCode) || !acceptedExitCodes.includes(exitCode)) {
    const detail = stderr.toString('utf8').trim().slice(0, 512)
    throw new Error(`Git command failed with exit ${exitCode}${detail ? `: ${detail}` : ''}`)
  }
  if (stderr.length) {
    throw new Error(`Git command produced unexpected stderr: ${stderr.toString('utf8').trim().slice(0, 512)}`)
  }
  return { exitCode, stdout }
}

async function gitLines(context, args, expectedCount, label) {
  const { stdout } = await runGit(context, args)
  let text
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(stdout).trim()
  } catch {
    throw new Error(`${label} returned non-UTF-8 text`)
  }
  const lines = text.split(/\r?\n/u)
  if (
    lines.length !== expectedCount ||
    lines.some((line) => !line || CONTROL_CHARACTER.test(line))
  ) {
    throw new Error(`${label} returned an unexpected number or shape of lines`)
  }
  return lines
}

async function captureGitBinding(context) {
  const [topLevel, objectFormat] = await gitLines(
    context,
    ['rev-parse', '--show-toplevel', '--show-object-format'],
    2,
    'Git repository metadata'
  )
  if (pathKey(topLevel) !== pathKey(context.repoRoot)) {
    throw new Error('Git top-level directory does not match the release repository root')
  }
  if (!['sha1', 'sha256'].includes(objectFormat)) throw new Error(`unsupported Git object format: ${objectFormat}`)
  const resolved = await gitLines(
    context,
    [
      'rev-parse',
      'HEAD^{commit}',
      `refs/tags/${context.expectedTag}^{commit}`,
      `refs/tags/${context.expectedTag}`,
      'HEAD^{tree}',
      `${context.expectedCommit}^{tree}`
    ],
    5,
    'Git release identity'
  )
  const headCommit = checkedOid(resolved[0], 'resolved HEAD commit')
  const tagCommit = checkedOid(resolved[1], 'resolved tag commit')
  const tagObject = checkedOid(resolved[2], 'resolved tag object')
  const headTree = checkedOid(resolved[3], 'resolved HEAD tree')
  const expectedCommitTree = checkedOid(resolved[4], 'resolved expected commit tree')
  if (headCommit !== context.expectedCommit) {
    throw new Error(`release HEAD does not match expected commit: ${headCommit}`)
  }
  if (tagCommit !== context.expectedCommit) {
    throw new Error(`release tag ${context.expectedTag} moved away from expected commit`)
  }
  if (headTree !== context.expectedTree || expectedCommitTree !== context.expectedTree) {
    throw new Error('release HEAD/commit tree does not match expected tree')
  }
  const expectedLength = objectFormat === 'sha1' ? 40 : 64
  if (
    context.expectedCommit.length !== expectedLength ||
    context.expectedTree.length !== expectedLength ||
    headCommit.length !== expectedLength ||
    headTree.length !== expectedLength ||
    tagCommit.length !== expectedLength ||
    tagObject.length !== expectedLength
  ) {
    throw new Error(`Git object IDs do not match the ${objectFormat} object format`)
  }
  return {
    objectFormat,
    expectedCommit: context.expectedCommit,
    expectedTag: context.expectedTag,
    expectedTree: context.expectedTree,
    headCommit,
    headTree,
    tagCommit,
    tagObject
  }
}

function scopePathspecs(scope) {
  const roots = [...scope.files, ...scope.optionalFiles, ...scope.directories, ...scope.optionalDirectories]
    .sort(ordinal)
    .map((path) => `:(top,literal)${path}`)
  const excluded = new Set(scope.excludedPaths)
  const separatelyFrozen = RELEASE_SEPARATELY_FROZEN_SOURCE_PATHS
    .filter((path) => excluded.has(path))
    .map((path) => `:(top,literal,exclude)${path}`)
  return [...roots, ...separatelyFrozen]
}

async function assertGitScopeClean(context) {
  const pathspecs = scopePathspecs(context.scope)
  const result = await runGit(
    context,
    ['diff', '--quiet', '--no-ext-diff', '--ignore-submodules=none', 'HEAD', '--', ...pathspecs],
    [0, 1],
    { ...context.environment, GIT_LITERAL_PATHSPECS: '0' }
  )
  if (result.exitCode === 1) {
    throw new Error('release source scope contains staged or working-tree byte/mode drift')
  }
}

function decodeTreeRecord(buffer) {
  let record
  try {
    record = new TextDecoder('utf-8', { fatal: true }).decode(buffer)
  } catch {
    throw new Error('Git tree contains a non-UTF-8 path')
  }
  const tab = record.indexOf('\t')
  if (tab <= 0) throw new Error('Git ls-tree returned a malformed record')
  const header = record.slice(0, tab).split(' ')
  if (header.length !== 3) throw new Error('Git ls-tree returned malformed metadata')
  return { mode: header[0], type: header[1], oid: header[2], path: checkedRelativePath(record.slice(tab + 1)) }
}

function parseTrackedTree(output, context) {
  const entries = []
  const folded = new Set()
  let start = 0
  while (start < output.length) {
    const end = output.indexOf(0, start)
    if (end < 0) throw new Error('Git ls-tree output is not NUL terminated')
    if (end === start) throw new Error('Git ls-tree output contains an empty record')
    const entry = decodeTreeRecord(output.subarray(start, end))
    start = end + 1
    if (isForbiddenAmbientPath(entry.path)) {
      throw new Error(`tracked release source contains a forbidden ambient auto-load input: ${entry.path}`)
    }
    if (!isReleaseSourcePath(entry.path, context.scope)) continue
    if (entry.type !== 'blob' || !['100644', '100755'].includes(entry.mode)) {
      throw new Error(`tracked release source must be a regular blob, not ${entry.mode} ${entry.type}: ${entry.path}`)
    }
    checkedOid(entry.oid, `Git blob for ${entry.path}`)
    const expectedLength = context.objectFormat === 'sha1' ? 40 : 64
    if (entry.oid.length !== expectedLength) {
      throw new Error(`Git blob object ID has the wrong ${context.objectFormat} length: ${entry.path}`)
    }
    const key = foldedSourcePath(entry.path)
    if (folded.has(key)) throw new Error(`tracked release source contains a case-colliding path: ${entry.path}`)
    folded.add(key)
    entries.push({ path: entry.path, gitMode: entry.mode, gitBlob: entry.oid })
    if (entries.length > context.limits.maxFiles) throw new Error('tracked release source exceeds the file-count bound')
  }
  entries.sort((left, right) => ordinal(left.path, right.path))
  return entries
}

async function assertForbiddenAmbientFilesystem(repoRoot) {
  const entries = await readdir(repoRoot, { withFileTypes: true })
  entries.sort((left, right) => ordinal(left.name, right.name))
  for (const entry of entries) {
    if (isForbiddenAmbientPath(entry.name)) {
      throw new Error(`release source contains a forbidden ambient auto-load input: ${entry.name}`)
    }
  }
  const desktopRoot = join(repoRoot, 'desktop')
  let desktopEntries
  try {
    await checkedRealPath(desktopRoot, 'directory', 'desktop source root')
    desktopEntries = await readdir(desktopRoot, { withFileTypes: true })
  } catch (error) {
    if (error?.code === 'ENOENT') return
    throw error
  }
  desktopEntries.sort((left, right) => ordinal(left.name, right.name))
  for (const entry of desktopEntries) {
    const path = `desktop/${entry.name}`
    if (isForbiddenAmbientPath(path)) {
      throw new Error(`release source contains a forbidden ambient auto-load input: ${path}`)
    }
  }
}

async function listTrackedTree(context) {
  const { stdout } = await runGit(context, [
    'ls-tree',
    '-r',
    '-z',
    '--full-tree',
    context.expectedCommit
  ])
  return parseTrackedTree(stdout, context)
}

function containedAbsolutePath(repoRoot, sourcePath) {
  const absolute = resolve(repoRoot, ...sourcePath.split('/'))
  const displacement = relative(repoRoot, absolute)
  if (!displacement || displacement === '..' || displacement.startsWith(`..${sep}`) || isAbsolute(displacement)) {
    throw new Error(`release source path escapes the repository root: ${sourcePath}`)
  }
  return absolute
}

async function checkedRealPath(path, expectedType, label) {
  const info = await lstat(path, { bigint: true })
  if (info.isSymbolicLink()) throw new Error(`${label} must not be a symlink or junction`)
  if (expectedType === 'directory' ? !info.isDirectory() : !info.isFile()) {
    throw new Error(`${label} must be a real ${expectedType}`)
  }
  const canonical = await realpath(path)
  if (pathKey(canonical) !== pathKey(path)) throw new Error(`${label} traverses a symlink or junction`)
  return info
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

async function enumerateScope(context) {
  const files = new Map()
  const directories = new Map()
  const foldedFiles = new Map()
  const foldedDirectories = new Map()
  const excluded = new Set(context.scope.excludedPaths.map((path) => foldedSourcePath(path)))

  const addFile = async (sourcePath, absolute) => {
    checkedRelativePath(sourcePath)
    const info = await checkedRealPath(absolute, 'file', `release source ${sourcePath}`)
    const key = foldedSourcePath(sourcePath)
    const previous = foldedFiles.get(key)
    if (previous && previous !== sourcePath) {
      throw new Error(`filesystem release source contains a case-colliding path: ${previous} / ${sourcePath}`)
    }
    foldedFiles.set(key, sourcePath)
    files.set(sourcePath, { absolute, identity: statIdentity(info) })
    if (files.size > context.limits.maxFiles) throw new Error('filesystem release source exceeds the file-count bound')
  }

  const addDirectory = async (sourcePath, absolute) => {
    checkedRelativePath(sourcePath, 'source directory')
    const info = await checkedRealPath(absolute, 'directory', `release source directory ${sourcePath}`)
    const identity = statIdentity(info)
    const key = foldedSourcePath(sourcePath)
    const previousPath = foldedDirectories.get(key)
    if (previousPath && previousPath !== sourcePath) {
      throw new Error(`filesystem release source contains a case-colliding directory: ${previousPath} / ${sourcePath}`)
    }
    const previous = directories.get(sourcePath)
    if (previous && !sameIdentity(previous.identity, identity)) {
      throw new Error(`release source directory identity drifted during enumeration: ${sourcePath}`)
    }
    foldedDirectories.set(key, sourcePath)
    directories.set(sourcePath, { absolute, identity })
    if (directories.size > context.limits.maxFiles) {
      throw new Error('filesystem release source exceeds the directory-count bound')
    }
  }

  const addAncestorDirectories = async (sourcePath) => {
    const parts = sourcePath.split('/')
    for (let depth = 1; depth < parts.length; depth += 1) {
      const ancestor = parts.slice(0, depth).join('/')
      await addDirectory(ancestor, containedAbsolutePath(context.repoRoot, ancestor))
    }
  }

  const visit = async (sourceDirectory, absoluteDirectory) => {
    await addDirectory(sourceDirectory, absoluteDirectory)
    const entries = await readdir(absoluteDirectory, { withFileTypes: true })
    entries.sort((left, right) => ordinal(left.name, right.name))
    for (const entry of entries) {
      const sourcePath = `${sourceDirectory}/${entry.name}`
      checkedRelativePath(sourcePath)
      const absolute = join(absoluteDirectory, entry.name)
      const info = await lstat(absolute, { bigint: true })
      if (entry.isSymbolicLink() || info.isSymbolicLink()) {
        throw new Error(`release source must not contain a symlink or junction: ${sourcePath}`)
      }
      if (info.isDirectory()) {
        await checkedRealPath(absolute, 'directory', `release source directory ${sourcePath}`)
        if (excluded.has(foldedSourcePath(sourcePath))) continue
        await visit(sourcePath, absolute)
        continue
      }
      if (!info.isFile()) throw new Error(`release source contains a special file: ${sourcePath}`)
      if (excluded.has(foldedSourcePath(sourcePath))) continue
      await addFile(sourcePath, absolute)
    }
  }

  for (const sourcePath of context.scope.files) {
    await addAncestorDirectories(sourcePath)
    await addFile(sourcePath, containedAbsolutePath(context.repoRoot, sourcePath))
  }
  for (const sourcePath of context.scope.optionalFiles) {
    await addAncestorDirectories(sourcePath)
    try {
      await addFile(sourcePath, containedAbsolutePath(context.repoRoot, sourcePath))
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error
    }
  }
  for (const sourceDirectory of context.scope.directories) {
    await addAncestorDirectories(sourceDirectory)
    await visit(sourceDirectory, containedAbsolutePath(context.repoRoot, sourceDirectory))
  }
  for (const sourceDirectory of context.scope.optionalDirectories) {
    await addAncestorDirectories(sourceDirectory)
    try {
      await visit(sourceDirectory, containedAbsolutePath(context.repoRoot, sourceDirectory))
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error
    }
  }
  return { files, directories }
}

function assertClosedFileSet(tracked, actual) {
  const trackedPaths = new Set(tracked.map((entry) => entry.path))
  for (const path of actual.keys()) {
    if (!trackedPaths.has(path)) throw new Error(`untracked or ignored file exists inside release source scope: ${path}`)
  }
  for (const entry of tracked) {
    if (!actual.has(entry.path)) throw new Error(`tracked release source file is missing: ${entry.path}`)
  }
  if (tracked.length !== actual.size) throw new Error('release source file set is not closed to the Git tree')
}

export async function hashReleaseSourceFile({
  path,
  relativePath = String(path || ''),
  maxFileBytes = DEFAULT_LIMITS.maxFileBytes,
  gitObjectFormat,
  onFileOpened
}) {
  const absolute = resolve(String(path || ''))
  const before = await checkedRealPath(absolute, 'file', `release source ${relativePath}`)
  if (before.size < 0n || before.size > BigInt(maxFileBytes) || before.size > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error(`release source file has an invalid or unbounded size: ${relativePath}`)
  }
  const beforeIdentity = statIdentity(before)
  const handle = await open(absolute, 'r')
  let digest
  try {
    const opened = await handle.stat({ bigint: true })
    if (!opened.isFile() || !sameIdentity(beforeIdentity, statIdentity(opened))) {
      throw new Error(`release source file identity changed while opening: ${relativePath}`)
    }
    if (onFileOpened) await onFileOpened({ path: absolute, relativePath, handle })
    const hash = createHash('sha256')
    const gitObjectHash = gitObjectFormat ? createHash(gitObjectFormat) : null
    gitObjectHash?.update(Buffer.from(`blob ${before.size}\0`, 'utf8'))
    const buffer = Buffer.allocUnsafe(64 * 1024)
    let total = 0
    while (true) {
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, null)
      if (bytesRead === 0) break
      total += bytesRead
      if (total > maxFileBytes || total > Number(before.size)) {
        throw new Error(`release source file grew while hashing: ${relativePath}`)
      }
      hash.update(buffer.subarray(0, bytesRead))
      gitObjectHash?.update(buffer.subarray(0, bytesRead))
    }
    if (total !== Number(before.size)) throw new Error(`release source file size changed while hashing: ${relativePath}`)
    const afterHandle = await handle.stat({ bigint: true })
    if (!sameIdentity(beforeIdentity, statIdentity(afterHandle))) {
      throw new Error(`release source file identity changed while hashing: ${relativePath}`)
    }
    digest = {
      sha256: hash.digest('hex'),
      workingGitBlob: gitObjectHash?.digest('hex')
    }
  } finally {
    await handle.close()
  }
  const afterPath = await checkedRealPath(absolute, 'file', `release source ${relativePath}`)
  if (!sameIdentity(beforeIdentity, statIdentity(afterPath))) {
    throw new Error(`release source file was replaced while hashing: ${relativePath}`)
  }
  if (!SHA256.test(digest.sha256)) throw new Error(`release source SHA-256 failed: ${relativePath}`)
  return { ...digest, size: Number(before.size), identity: beforeIdentity }
}

function assertEnumerationStable(files, directories, second) {
  if (files.length !== second.files.size) throw new Error('release source file set changed during snapshot capture')
  for (const file of files) {
    const current = second.files.get(file.path)
    if (!current) throw new Error(`release source file disappeared during snapshot capture: ${file.path}`)
    if (!sameIdentity(file.identity, current.identity)) {
      throw new Error(`release source file identity drifted during snapshot capture: ${file.path}`)
    }
  }
  if (directories.length !== second.directories.size) {
    throw new Error('release source directory set changed during snapshot capture')
  }
  for (const directory of directories) {
    const current = second.directories.get(directory.path)
    if (!current) throw new Error(`release source directory disappeared during snapshot capture: ${directory.path}`)
    if (!sameIdentity(directory.identity, current.identity)) {
      throw new Error(`release source directory identity drifted during snapshot capture: ${directory.path}`)
    }
  }
}

function sameGitBinding(left, right) {
  return JSON.stringify(left) === JSON.stringify(right)
}

export async function captureReleaseSourceSnapshot(options = {}) {
  const scope = normalizeScope(options.scope)
  const limits = normalizeLimits(options.limits)
  const repoRoot = await checkedRepositoryRoot(options.repoRoot)
  const gitPath = await checkedGitExecutable(options.gitPath)
  const expectedCommit = checkedOid(options.expectedCommit, 'expected commit')
  const expectedTree = checkedOid(options.expectedTree, 'expected tree')
  const expectedTag = checkedTag(options.expectedTag)
  const executeGit = options.executeGit || executeReleaseGitCommand
  if (typeof executeGit !== 'function') throw new Error('Git command executor must be a function')
  if (
    options.onGitExecutableAttested !== undefined &&
    typeof options.onGitExecutableAttested !== 'function'
  ) {
    throw new Error('Git executable attestation hook must be a function')
  }
  // Reject ambient auto-load inputs before hashing or accepting release toolchain evidence.
  await assertForbiddenAmbientFilesystem(repoRoot)
  const gitExecutable = await captureGitExecutableAttestation(gitPath, limits.maxFileBytes)
  if (options.onGitExecutableAttested) {
    await options.onGitExecutableAttested({
      phase: 'before',
      path: gitPath,
      attestation: structuredClone(gitExecutable)
    })
  }
  const context = {
    repoRoot,
    gitPath,
    expectedCommit,
    expectedTree,
    expectedTag,
    scope,
    limits,
    executeGit,
    environment: minimalGitEnvironment(repoRoot)
  }

  const git = await captureGitBinding(context)
  context.objectFormat = git.objectFormat
  await assertGitScopeClean(context)
  const tracked = await listTrackedTree(context)
  if (!tracked.length) throw new Error('release source scope has no tracked files')
  const actual = await enumerateScope(context)
  assertClosedFileSet(tracked, actual.files)
  const directories = [...actual.directories.entries()]
    .map(([path, details]) => ({ path, identity: details.identity }))
    .sort((left, right) => ordinal(left.path, right.path))

  const files = []
  let totalBytes = 0
  for (const entry of tracked) {
    const found = actual.files.get(entry.path)
    const content = await hashReleaseSourceFile({
      path: found.absolute,
      relativePath: entry.path,
      maxFileBytes: limits.maxFileBytes,
      gitObjectFormat: git.objectFormat,
      onFileOpened: options.onFileOpened
        ? (details) => options.onFileOpened({ ...details, entry: { ...entry } })
        : undefined
    })
    if (content.workingGitBlob !== entry.gitBlob) {
      throw new Error(`release source bytes do not match the committed Git blob: ${entry.path}`)
    }
    totalBytes += content.size
    if (totalBytes > limits.maxTotalBytes) throw new Error('release source exceeds the total-byte bound')
    const { workingGitBlob: _verifiedGitBlob, ...boundContent } = content
    files.push({ ...entry, ...boundContent })
  }

  const secondEnumeration = await enumerateScope(context)
  assertClosedFileSet(tracked, secondEnumeration.files)
  assertEnumerationStable(files, directories, secondEnumeration)
  await assertGitScopeClean(context)
  const finalGit = await captureGitBinding(context)
  if (!sameGitBinding(git, finalGit)) throw new Error('Git release identity changed during snapshot capture')
  const finalGitExecutable = await captureGitExecutableAttestation(gitPath, limits.maxFileBytes)
  if (JSON.stringify(gitExecutable) !== JSON.stringify(finalGitExecutable)) {
    throw new Error('Git executable attestation changed during release source snapshot capture')
  }

  return {
    schema: SNAPSHOT_SCHEMA,
    git,
    toolchain: {
      git: gitExecutable
    },
    scope: {
      files: [...scope.files],
      optionalFiles: [...scope.optionalFiles],
      directories: [...scope.directories],
      optionalDirectories: [...scope.optionalDirectories],
      excludedPaths: [...scope.excludedPaths]
    },
    directories,
    files,
    totalBytes
  }
}

function checkedSnapshot(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || value.schema !== SNAPSHOT_SCHEMA) {
    throw new Error(`${label} is not a release source snapshot`)
  }
  if (
    !value.git ||
    !value.toolchain?.git ||
    !value.scope ||
    !Array.isArray(value.directories) ||
    !Array.isArray(value.files)
  ) {
    throw new Error(`${label} release source snapshot is incomplete`)
  }
  return value
}

export function assertReleaseSourceSnapshotUnchanged(beforeValue, afterValue) {
  const before = checkedSnapshot(beforeValue, 'before')
  const after = checkedSnapshot(afterValue, 'after')
  if (JSON.stringify(before) === JSON.stringify(after)) return true
  if (JSON.stringify(before.git) !== JSON.stringify(after.git)) {
    throw new Error('release source snapshot Git binding changed')
  }
  if (JSON.stringify(before.toolchain) !== JSON.stringify(after.toolchain)) {
    throw new Error('release source snapshot toolchain attestation changed')
  }
  if (JSON.stringify(before.scope) !== JSON.stringify(after.scope)) {
    throw new Error('release source snapshot scope changed')
  }
  const beforeDirectoryPaths = before.directories.map((directory) => directory.path)
  const afterDirectoryPaths = after.directories.map((directory) => directory.path)
  if (JSON.stringify(beforeDirectoryPaths) !== JSON.stringify(afterDirectoryPaths)) {
    throw new Error('release source snapshot directory set changed (add/delete/case drift)')
  }
  for (let index = 0; index < before.directories.length; index += 1) {
    const earlier = before.directories[index]
    const later = after.directories[index]
    if (!sameIdentity(earlier.identity, later.identity)) {
      throw new Error(`release source directory filesystem identity changed: ${earlier.path}`)
    }
  }
  const beforePaths = before.files.map((file) => file.path)
  const afterPaths = after.files.map((file) => file.path)
  if (JSON.stringify(beforePaths) !== JSON.stringify(afterPaths)) {
    throw new Error('release source snapshot file set changed (add/delete/case drift)')
  }
  for (let index = 0; index < before.files.length; index += 1) {
    const earlier = before.files[index]
    const later = after.files[index]
    if (earlier.gitMode !== later.gitMode) throw new Error(`release source Git mode changed: ${earlier.path}`)
    if (earlier.gitBlob !== later.gitBlob) throw new Error(`release source Git blob changed: ${earlier.path}`)
    if (earlier.sha256 !== later.sha256 || earlier.size !== later.size) {
      throw new Error(`release source bytes changed: ${earlier.path}`)
    }
    if (!sameIdentity(earlier.identity, later.identity)) {
      throw new Error(`release source filesystem identity changed: ${earlier.path}`)
    }
  }
  throw new Error('release source snapshot changed')
}

export async function verifyReleaseSourceSnapshotUnchanged(before, options) {
  const after = await captureReleaseSourceSnapshot(options)
  assertReleaseSourceSnapshotUnchanged(before, after)
  return after
}
