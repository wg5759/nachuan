import { createHash } from 'node:crypto'
import { lstat, open, realpath } from 'node:fs/promises'
import { devNull } from 'node:os'
import { dirname, isAbsolute, join, resolve, sep } from 'node:path'

import { verifyPreparedGitRuntime } from './git-runtime-policy.mjs'
import { executeReleaseGitCommand } from './release-source-snapshot.mjs'

export const GIT_TOOLCHAIN_CLOSURE_SCHEMA = 'nachuan.git-toolchain-closure/v1'

const MAX_OUTPUT_BYTES = 1024 * 1024
const EXECUTION_PATHS = Object.freeze([
  'mingw64/bin/git.exe',
  'mingw64/bin/libiconv-2.dll',
  'mingw64/bin/libintl-8.dll',
  'mingw64/bin/libpcre2-8-0.dll',
  'mingw64/bin/libwinpthread-1.dll',
  'mingw64/bin/zlib1.dll',
  'mingw64/libexec/git-core/git.exe'
])

function ordinal(left, right) {
  return left < right ? -1 : left > right ? 1 : 0
}

function pathKey(path) {
  const key = resolve(path).split(sep).join('/')
  return process.platform === 'win32' ? key.toLowerCase() : key
}

function samePath(left, right) {
  return pathKey(left) === pathKey(right)
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

async function checkedRealPath(path, expectedType, label) {
  const absolute = resolve(String(path || ''))
  if (!isAbsolute(String(path || '')) || !samePath(path, absolute)) {
    throw new Error(`${label} must be canonical and absolute`)
  }
  const info = await lstat(absolute, { bigint: true })
  if (info.isSymbolicLink()) throw new Error(`${label} must not be a symlink or junction`)
  if (expectedType === 'directory' ? !info.isDirectory() : !info.isFile()) {
    throw new Error(`${label} must be a real ${expectedType}`)
  }
  const canonical = await realpath(absolute)
  if (!samePath(canonical, absolute)) throw new Error(`${label} traverses a symlink or junction`)
  return { path: canonical, info }
}

async function lockedFileDescriptor(runtimeRoot, locked, roles) {
  const absolute = join(runtimeRoot, ...locked.path.split('/'))
  const checked = await checkedRealPath(absolute, 'file', `locked Git execution file ${locked.path}`)
  if (checked.info.size !== BigInt(locked.size)) {
    throw new Error(`locked Git execution file size drifted: ${locked.path}`)
  }
  const beforeIdentity = statIdentity(checked.info)
  const handle = await open(checked.path, 'r')
  let sha256
  try {
    const opened = await handle.stat({ bigint: true })
    if (!opened.isFile() || !sameIdentity(beforeIdentity, statIdentity(opened))) {
      throw new Error(`locked Git execution file identity changed while opening: ${locked.path}`)
    }
    const hash = createHash('sha256')
    const buffer = Buffer.allocUnsafe(64 * 1024)
    let total = 0
    while (true) {
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, null)
      if (bytesRead === 0) break
      total += bytesRead
      if (total > locked.size) throw new Error(`locked Git execution file grew: ${locked.path}`)
      hash.update(buffer.subarray(0, bytesRead))
    }
    if (total !== locked.size) throw new Error(`locked Git execution file size changed: ${locked.path}`)
    const afterHandle = await handle.stat({ bigint: true })
    if (!sameIdentity(beforeIdentity, statIdentity(afterHandle))) {
      throw new Error(`locked Git execution file identity changed while hashing: ${locked.path}`)
    }
    sha256 = hash.digest('hex')
  } finally {
    await handle.close()
  }
  if (sha256 !== locked.sha256) throw new Error(`locked Git execution file hash drifted: ${locked.path}`)
  const afterPath = await checkedRealPath(checked.path, 'file', `locked Git execution file ${locked.path}`)
  if (!sameIdentity(beforeIdentity, statIdentity(afterPath.info))) {
    throw new Error(`locked Git execution file was replaced while hashing: ${locked.path}`)
  }
  return {
    path: checked.path,
    relativePath: locked.path,
    roles: [...roles].sort(ordinal),
    sha256,
    size: locked.size,
    identity: beforeIdentity
  }
}

async function directoryDescriptor(path, role) {
  const checked = await checkedRealPath(path, 'directory', `Git execution directory ${role}`)
  return { path: checked.path, role, identity: statIdentity(checked.info) }
}

function rolesFor(path) {
  if (path === 'mingw64/bin/git.exe') return ['runtime-core', 'selected-git-executable']
  if (path === 'mingw64/libexec/git-core/git.exe') return ['exec-path-sentinel']
  return ['adjacent-runtime-dll']
}

async function captureExecutionClosure(runtime) {
  const lockedByPath = new Map(runtime.lock.requiredFiles.map((item) => [item.path, item]))
  const files = []
  for (const path of EXECUTION_PATHS) {
    const locked = lockedByPath.get(path)
    if (!locked) throw new Error(`Git runtime lock omits an execution-closure file: ${path}`)
    files.push(await lockedFileDescriptor(runtime.runtimeRoot, locked, rolesFor(path)))
  }
  files.sort((left, right) => ordinal(pathKey(left.path), pathKey(right.path)))
  const runtimeBin = join(runtime.runtimeRoot, 'mingw64', 'bin')
  const execPath = join(runtime.runtimeRoot, 'mingw64', 'libexec', 'git-core')
  const directories = [
    await directoryDescriptor(runtimeBin, 'runtime-bin'),
    await directoryDescriptor(execPath, 'git-exec-path')
  ].sort((left, right) => ordinal(pathKey(left.path), pathKey(right.path)))
  return { directories, execPath, files, runtimeBin }
}

function minimalGitEnvironment(repoRoot, execPath, { discoverExecPath = false } = {}) {
  const environment = {
    GIT_ATTR_NOSYSTEM: '1',
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
  if (!discoverExecPath) environment.GIT_EXEC_PATH = execPath
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

async function runProbe({ gitPath, repoRoot, execPath, executeGit, argument, discoverExecPath = false }) {
  const result = await executeGit({
    executable: gitPath,
    args: ['--no-pager', argument],
    cwd: repoRoot,
    env: minimalGitEnvironment(repoRoot, execPath, { discoverExecPath }),
    timeoutMs: 30_000,
    maxOutputBytes: MAX_OUTPUT_BYTES,
    shell: false
  })
  if (
    !result ||
    result.exitCode !== 0 ||
    result.signal ||
    !Buffer.isBuffer(result.stdout) ||
    !Buffer.isBuffer(result.stderr) ||
    result.stderr.length ||
    result.stdout.length > MAX_OUTPUT_BYTES
  ) {
    throw new Error(`Git ${argument} probe returned an invalid result`)
  }
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(result.stdout).trim()
  } catch {
    throw new Error(`Git ${argument} probe returned non-UTF-8 text`)
  }
}

function checkedClosure(value, label) {
  if (
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    value.schema !== GIT_TOOLCHAIN_CLOSURE_SCHEMA ||
    !Array.isArray(value.files) ||
    !Array.isArray(value.directories)
  ) {
    throw new Error(`${label} is not a Git toolchain closure`)
  }
  return value
}

export function assertGitToolchainClosureUnchanged(beforeValue, afterValue) {
  const before = checkedClosure(beforeValue, 'before')
  const after = checkedClosure(afterValue, 'after')
  const stableKeys = [
    'schema',
    'version',
    'gitPath',
    'runtimeRoot',
    'runtimeBin',
    'execPath',
    'archiveSha256',
    'runtimeTreeSha256',
    'lockSha256'
  ]
  for (const key of stableKeys) {
    if (before[key] !== after[key]) throw new Error(`Git toolchain ${key} changed`)
  }
  const beforePaths = before.files.map((item) => item.path)
  const afterPaths = after.files.map((item) => item.path)
  if (JSON.stringify(beforePaths) !== JSON.stringify(afterPaths)) throw new Error('Git toolchain file set changed')
  for (let index = 0; index < before.files.length; index += 1) {
    if (JSON.stringify(before.files[index]) !== JSON.stringify(after.files[index])) {
      throw new Error(`Git toolchain file bytes or identity changed: ${before.files[index].path}`)
    }
  }
  if (JSON.stringify(before.directories) !== JSON.stringify(after.directories)) {
    throw new Error('Git toolchain directory identity changed')
  }
  return true
}

export async function recaptureGitToolchainExecutionClosure(baselineValue) {
  const baseline = checkedClosure(baselineValue, 'baseline')
  const files = []
  for (const previous of baseline.files) {
    if (
      !EXECUTION_PATHS.includes(previous.relativePath) ||
      !Array.isArray(previous.roles) ||
      typeof previous.sha256 !== 'string' ||
      !Number.isSafeInteger(previous.size)
    ) {
      throw new Error('baseline Git execution closure contains an invalid file descriptor')
    }
    files.push(
      await lockedFileDescriptor(
        baseline.runtimeRoot,
        { path: previous.relativePath, sha256: previous.sha256, size: previous.size },
        previous.roles
      )
    )
  }
  files.sort((left, right) => ordinal(pathKey(left.path), pathKey(right.path)))
  const directories = [
    await directoryDescriptor(baseline.runtimeBin, 'runtime-bin'),
    await directoryDescriptor(baseline.execPath, 'git-exec-path')
  ].sort((left, right) => ordinal(pathKey(left.path), pathKey(right.path)))
  const current = { ...baseline, directories, files }
  assertGitToolchainClosureUnchanged(baseline, current)
  return current
}

export async function captureGitToolchainClosure({
  gitPath,
  repoRoot,
  executeGit = executeReleaseGitCommand,
  runtimeVerifier = verifyPreparedGitRuntime
} = {}) {
  if (typeof executeGit !== 'function' || typeof runtimeVerifier !== 'function') {
    throw new Error('Git toolchain clients are incomplete')
  }
  const checkedRepo = await checkedRealPath(repoRoot, 'directory', 'Git probe repository root')
  const runtime = await runtimeVerifier({ projectRoot: checkedRepo.path })
  if (
    !runtime?.runtimeRoot ||
    !runtime?.corePath ||
    !runtime?.lock?.archive?.sha256 ||
    !runtime?.lock?.runtime?.treeSha256 ||
    !runtime?.provenance?.lock?.sha256
  ) {
    throw new Error('prepared Git runtime verification result is incomplete')
  }
  const selectedGit = resolve(String(gitPath || ''))
  if (!samePath(selectedGit, runtime.corePath)) {
    throw new Error('release Git path must be the locked project-local PortableGit core')
  }
  const before = await captureExecutionClosure(runtime)
  const reportedExecPath = resolve(
    await runProbe({
      gitPath: selectedGit,
      repoRoot: checkedRepo.path,
      execPath: before.execPath,
      executeGit,
      argument: '--exec-path',
      discoverExecPath: true
    })
  )
  if (!samePath(reportedExecPath, before.execPath)) {
    throw new Error('locked Git core reported an unexpected exec-path')
  }
  const version = await runProbe({
    gitPath: selectedGit,
    repoRoot: checkedRepo.path,
    execPath: before.execPath,
    executeGit,
    argument: '--version'
  })
  if (version !== `git version ${runtime.lock.version}`) throw new Error('locked Git core version drifted')
  const builtinText = await runProbe({
    gitPath: selectedGit,
    repoRoot: checkedRepo.path,
    execPath: before.execPath,
    executeGit,
    argument: '--list-cmds=builtins'
  })
  const builtins = new Set(builtinText.split(/\s+/u).filter(Boolean))
  if (runtime.lock.builtins.some((command) => !builtins.has(command))) {
    throw new Error('a release Git command is no longer a builtin')
  }
  const descriptor = (captured) => ({
    schema: GIT_TOOLCHAIN_CLOSURE_SCHEMA,
    version: runtime.lock.version,
    gitPath: selectedGit,
    runtimeRoot: runtime.runtimeRoot,
    runtimeBin: captured.runtimeBin,
    execPath: captured.execPath,
    archiveSha256: runtime.lock.archive.sha256,
    runtimeTreeSha256: runtime.lock.runtime.treeSha256,
    lockSha256: runtime.provenance.lock.sha256,
    directories: captured.directories,
    files: captured.files
  })
  let after
  try {
    after = await captureExecutionClosure(runtime)
    assertGitToolchainClosureUnchanged(descriptor(before), descriptor(after))
  } catch (error) {
    throw new Error('Git toolchain closure changed during version/exec-path probes', { cause: error })
  }
  return descriptor(after)
}
