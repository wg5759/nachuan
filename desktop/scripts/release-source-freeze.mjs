import { createHash } from 'node:crypto'
import { lstat, readFile, realpath, writeFile } from 'node:fs/promises'
import { dirname, isAbsolute, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

import { materializeGeneratedSourceModule } from './generated-source-module.mjs'
import {
  assertGitToolchainClosureUnchanged,
  captureGitToolchainClosure,
  GIT_TOOLCHAIN_CLOSURE_SCHEMA,
  recaptureGitToolchainExecutionClosure
} from './git-toolchain-closure.mjs'
import {
  assertReleaseSourceSnapshotUnchanged,
  captureReleaseSourceSnapshot,
  executeReleaseGitCommand,
  RELEASE_SEPARATELY_FROZEN_SOURCE_PATHS
} from './release-source-snapshot.mjs'

export const RELEASE_SOURCE_FREEZE_SCHEMA = 'nachuan.release-source-freeze/v2'
export const GENERATED_RELEASE_SOURCE_SCHEMA = 'nachuan.generated-release-source/v2'
export const GENERATED_RELEASE_SOURCE_PATHS = RELEASE_SEPARATELY_FROZEN_SOURCE_PATHS

const SHA256 = /^[0-9a-f]{64}$/u
const DECIMAL = /^(?:0|[1-9][0-9]*)$/u
const MAX_FREEZE_BYTES = 256 * 1024 * 1024
const MAX_GENERATED_SOURCE_BYTES = 1024 * 1024
const scriptPath = fileURLToPath(import.meta.url)
const defaultProjectRoot = resolve(dirname(scriptPath), '..', '..')

function canonicalValue(value) {
  if (Array.isArray(value)) return value.map(canonicalValue)
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonicalValue(value[key])])
    )
  }
  return value
}

function canonicalBytes(value) {
  return Buffer.from(`${JSON.stringify(canonicalValue(value), null, 2)}\n`, 'utf8')
}

function pathKey(path) {
  const key = resolve(path).split(sep).join('/')
  return process.platform === 'win32' ? key.toLowerCase() : key
}

function samePath(left, right) {
  return pathKey(left) === pathKey(right)
}

function statIdentity(info) {
  return `${info.dev}:${info.ino}:${info.size}:${info.mtimeNs}:${info.ctimeNs}:${info.birthtimeNs}`
}

function generatedFileIdentity(info) {
  return {
    device: info.dev.toString(),
    inode: info.ino.toString(),
    mode: info.mode.toString(),
    links: info.nlink.toString(),
    size: info.size.toString(),
    modifiedNs: info.mtimeNs.toString(),
    changedNs: info.ctimeNs.toString(),
    bornNs: info.birthtimeNs.toString()
  }
}

async function checkedDirectory(path, label) {
  const absolute = resolve(String(path || ''))
  const info = await lstat(absolute, { bigint: true })
  if (info.isSymbolicLink() || !info.isDirectory()) throw new Error(`${label} must be a real directory`)
  const canonical = await realpath(absolute)
  if (!samePath(canonical, absolute)) throw new Error(`${label} traverses a symlink or junction`)
  return canonical
}

function exactKeys(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`)
  }
  if (Object.keys(value).sort().join(',') !== [...expected].sort().join(',')) {
    throw new Error(`${label} fields are not canonical`)
  }
}

function checkedGeneratedFileIdentity(value, label) {
  exactKeys(
    value,
    ['bornNs', 'changedNs', 'device', 'inode', 'links', 'mode', 'modifiedNs', 'size'],
    label
  )
  for (const [name, raw] of Object.entries(value)) {
    if (!DECIMAL.test(String(raw))) throw new Error(`${label} ${name} is invalid`)
  }
  return canonicalValue(value)
}

function checkedGeneratedReleaseSource(value, label = 'generated release source') {
  exactKeys(value, ['files', 'schema'], label)
  if (value.schema !== GENERATED_RELEASE_SOURCE_SCHEMA) throw new Error(`${label} schema is invalid`)
  if (!Array.isArray(value.files) || value.files.length !== GENERATED_RELEASE_SOURCE_PATHS.length) {
    throw new Error(`${label} file set is incomplete`)
  }
  const files = value.files.map((file, index) => {
    exactKeys(file, ['contentBase64', 'identity', 'path', 'sha256', 'size'], `${label} file`)
    const expectedPath = GENERATED_RELEASE_SOURCE_PATHS[index]
    if (file.path !== expectedPath) throw new Error(`${label} file set is not canonical`)
    if (!SHA256.test(String(file.sha256 || ''))) throw new Error(`${label} file digest is invalid`)
    if (!Number.isSafeInteger(file.size) || file.size <= 0 || file.size > MAX_GENERATED_SOURCE_BYTES) {
      throw new Error(`${label} file size is invalid`)
    }
    const contentBase64 = String(file.contentBase64 || '')
    if (
      !contentBase64 ||
      contentBase64.length > MAX_GENERATED_SOURCE_BYTES * 2 ||
      contentBase64.length % 4 !== 0 ||
      !/^[0-9A-Za-z+/]+={0,2}$/u.test(contentBase64)
    ) {
      throw new Error(`${label} file content is not canonical base64`)
    }
    const content = Buffer.from(contentBase64, 'base64')
    if (
      content.length !== file.size ||
      content.toString('base64') !== contentBase64 ||
      createHash('sha256').update(content).digest('hex') !== file.sha256
    ) {
      throw new Error(`${label} file content does not match its size or digest`)
    }
    const identity = checkedGeneratedFileIdentity(file.identity, `${label} file identity`)
    if (identity.size !== String(file.size)) throw new Error(`${label} file identity size is inconsistent`)
    return canonicalValue({ ...file, contentBase64, identity })
  })
  return canonicalValue({ schema: value.schema, files })
}

export function assertGeneratedReleaseSourceUnchanged(beforeValue, afterValue) {
  const before = checkedGeneratedReleaseSource(beforeValue, 'before generated release source')
  const after = checkedGeneratedReleaseSource(afterValue, 'after generated release source')
  for (let index = 0; index < before.files.length; index += 1) {
    const beforeFile = before.files[index]
    const afterFile = after.files[index]
    if (beforeFile.path !== afterFile.path) throw new Error('generated release source file set changed')
    if (beforeFile.sha256 !== afterFile.sha256 || beforeFile.size !== afterFile.size) {
      throw new Error(`generated release source bytes changed: ${beforeFile.path}`)
    }
    if (JSON.stringify(beforeFile.identity) !== JSON.stringify(afterFile.identity)) {
      throw new Error(`generated release source file identity changed: ${beforeFile.path}`)
    }
  }
  return true
}

export async function captureGeneratedReleaseSource({ projectRoot = defaultProjectRoot } = {}) {
  projectRoot = await checkedDirectory(projectRoot, 'generated release source project root')
  const files = []
  for (const relativePath of GENERATED_RELEASE_SOURCE_PATHS) {
    const absolute = resolve(projectRoot, ...relativePath.split('/'))
    const before = await lstat(absolute, { bigint: true })
    if (
      before.isSymbolicLink() ||
      !before.isFile() ||
      before.size <= 0n ||
      before.size > BigInt(MAX_GENERATED_SOURCE_BYTES)
    ) {
      throw new Error(`generated release source must be a bounded regular file: ${relativePath}`)
    }
    if (!samePath(await realpath(absolute), absolute)) {
      throw new Error(`generated release source traverses a symlink or junction: ${relativePath}`)
    }
    const identity = generatedFileIdentity(before)
    const bytes = await readFile(absolute)
    const after = await lstat(absolute, { bigint: true })
    if (JSON.stringify(generatedFileIdentity(after)) !== JSON.stringify(identity)) {
      throw new Error(`generated release source changed while reading: ${relativePath}`)
    }
    files.push({
      path: relativePath,
      contentBase64: bytes.toString('base64'),
      sha256: createHash('sha256').update(bytes).digest('hex'),
      size: bytes.length,
      identity
    })
  }
  return checkedGeneratedReleaseSource({ schema: GENERATED_RELEASE_SOURCE_SCHEMA, files })
}

function checkedFreeze(value, label = 'release source freeze') {
  exactKeys(value, ['generatedSource', 'gitToolchain', 'schema', 'sourceSnapshot'], label)
  if (value.schema !== RELEASE_SOURCE_FREEZE_SCHEMA) throw new Error(`${label} schema is invalid`)
  if (value.gitToolchain?.schema !== GIT_TOOLCHAIN_CLOSURE_SCHEMA) {
    throw new Error(`${label} Git toolchain closure is invalid`)
  }
  if (value.sourceSnapshot?.schema !== 'nachuan.release-source-snapshot/v1') {
    throw new Error(`${label} source snapshot is invalid`)
  }
  const generatedSource = checkedGeneratedReleaseSource(
    value.generatedSource,
    `${label} generated source`
  )
  assertGitToolchainClosureUnchanged(value.gitToolchain, structuredClone(value.gitToolchain))
  assertReleaseSourceSnapshotUnchanged(value.sourceSnapshot, structuredClone(value.sourceSnapshot))
  const selected = value.gitToolchain.files.filter((file) =>
    Array.isArray(file?.roles) && file.roles.includes('selected-git-executable')
  )
  if (selected.length !== 1) throw new Error(`${label} must bind exactly one selected Git executable`)
  const sourceGit = value.sourceSnapshot.toolchain?.git
  const closureGit = selected[0]
  if (
    !sourceGit ||
    !samePath(sourceGit.path, value.gitToolchain.gitPath) ||
    !samePath(sourceGit.path, closureGit.path) ||
    sourceGit.sha256 !== closureGit.sha256 ||
    sourceGit.size !== closureGit.size ||
    JSON.stringify(sourceGit.identity) !== JSON.stringify(closureGit.identity)
  ) {
    throw new Error(`${label} source snapshot and Git closure bind different executables`)
  }
  return canonicalValue({ ...value, generatedSource })
}

export function assertReleaseSourceFreezeUnchanged(beforeValue, afterValue) {
  const before = checkedFreeze(beforeValue, 'before release source freeze')
  const after = checkedFreeze(afterValue, 'after release source freeze')
  assertGitToolchainClosureUnchanged(before.gitToolchain, after.gitToolchain)
  assertReleaseSourceSnapshotUnchanged(before.sourceSnapshot, after.sourceSnapshot)
  assertGeneratedReleaseSourceUnchanged(before.generatedSource, after.generatedSource)
  if (JSON.stringify(before) !== JSON.stringify(after)) throw new Error('release source freeze changed')
  return true
}

function portableFreezeValue(value) {
  const checked = checkedFreeze(value)
  return canonicalValue({
    schema: checked.schema,
    generatedSource: {
      schema: checked.generatedSource.schema,
      files: checked.generatedSource.files.map(({ contentBase64, path, sha256, size }) => ({
        contentBase64,
        path,
        sha256,
        size
      }))
    },
    gitToolchain: {
      schema: checked.gitToolchain.schema,
      version: checked.gitToolchain.version,
      archiveSha256: checked.gitToolchain.archiveSha256,
      runtimeTreeSha256: checked.gitToolchain.runtimeTreeSha256,
      lockSha256: checked.gitToolchain.lockSha256,
      directories: checked.gitToolchain.directories.map(({ role }) => ({ role })),
      files: checked.gitToolchain.files.map(({ relativePath, roles, sha256, size }) => ({
        relativePath,
        roles,
        sha256,
        size
      }))
    },
    sourceSnapshot: {
      schema: checked.sourceSnapshot.schema,
      git: checked.sourceSnapshot.git,
      toolchain: {
        git: {
          sha256: checked.sourceSnapshot.toolchain.git.sha256,
          size: checked.sourceSnapshot.toolchain.git.size
        }
      },
      scope: checked.sourceSnapshot.scope,
      directories: checked.sourceSnapshot.directories.map(({ path }) => ({ path })),
      files: checked.sourceSnapshot.files.map(({ path, gitMode, gitBlob, sha256, size }) => ({
        path,
        gitMode,
        gitBlob,
        sha256,
        size
      })),
      totalBytes: checked.sourceSnapshot.totalBytes
    }
  })
}

export function assertReleaseSourceFreezePortableEquivalent(beforeValue, afterValue) {
  const before = portableFreezeValue(beforeValue)
  const after = portableFreezeValue(afterValue)
  if (JSON.stringify(before) !== JSON.stringify(after)) {
    throw new Error('portable release source or Git toolchain evidence changed across runners')
  }
  return true
}

export async function captureReleaseSourceFreeze({
  projectRoot = defaultProjectRoot,
  gitPath = process.env.NACHUAN_RELEASE_GIT_PATH,
  releaseTag = process.env.NACHUAN_RELEASE_TAG,
  releaseCommit = process.env.NACHUAN_RELEASE_COMMIT,
  releaseTree = process.env.NACHUAN_RELEASE_TREE,
  captureGitClosure = captureGitToolchainClosure,
  captureGeneratedSource = captureGeneratedReleaseSource,
  captureSourceSnapshot = captureReleaseSourceSnapshot,
  executeGit = executeReleaseGitCommand
} = {}) {
  if (
    typeof captureGitClosure !== 'function' ||
    typeof captureGeneratedSource !== 'function' ||
    typeof captureSourceSnapshot !== 'function' ||
    typeof executeGit !== 'function'
  ) {
    throw new Error('release source freeze capture clients are incomplete')
  }
  projectRoot = resolve(projectRoot)
  gitPath = resolve(String(gitPath || ''))
  const gitBefore = await captureGitClosure({ gitPath, repoRoot: projectRoot })
  const generatedBefore = await captureGeneratedSource({ projectRoot })
  const guardedGitExecutor = async (request) => {
    if (
      !request ||
      !samePath(request.executable, gitBefore.gitPath) ||
      request.shell !== false ||
      !Array.isArray(request.args)
    ) {
      throw new Error('release source snapshot requested an unbound Git invocation')
    }
    const beforeCommand = await recaptureGitToolchainExecutionClosure(gitBefore)
    const args = request.args[0] === '--no-pager' ? [...request.args] : ['--no-pager', ...request.args]
    const commandIndex = args[0] === '--no-pager' ? 1 : 0
    if (args[commandIndex] === 'diff' && !args.includes('--no-textconv')) {
      args.splice(commandIndex + 1, 0, '--no-textconv')
    }
    const result = await executeGit({
      ...request,
      executable: gitBefore.gitPath,
      args,
      env: { ...request.env, GIT_EXEC_PATH: gitBefore.execPath },
      shell: false
    })
    const afterCommand = await recaptureGitToolchainExecutionClosure(gitBefore)
    assertGitToolchainClosureUnchanged(beforeCommand, afterCommand)
    return result
  }
  const sourceSnapshot = await captureSourceSnapshot({
    repoRoot: projectRoot,
    gitPath,
    expectedCommit: String(releaseCommit || '').toLowerCase(),
    expectedTree: String(releaseTree || '').toLowerCase(),
    expectedTag: releaseTag,
    executeGit: guardedGitExecutor
  })
  const generatedAfter = await captureGeneratedSource({ projectRoot })
  assertGeneratedReleaseSourceUnchanged(generatedBefore, generatedAfter)
  const gitAfter = await captureGitClosure({ gitPath, repoRoot: projectRoot })
  assertGitToolchainClosureUnchanged(gitBefore, gitAfter)
  return checkedFreeze({
    schema: RELEASE_SOURCE_FREEZE_SCHEMA,
    generatedSource: generatedAfter,
    gitToolchain: gitAfter,
    sourceSnapshot
  })
}

async function readBoundedFile(path, label) {
  const absolute = resolve(String(path || ''))
  if (!isAbsolute(String(path || '')) || !samePath(path, absolute)) {
    throw new Error(`${label} path must be canonical and absolute`)
  }
  const before = await lstat(absolute, { bigint: true })
  if (
    before.isSymbolicLink() ||
    !before.isFile() ||
    before.size <= 0n ||
    before.size > BigInt(MAX_FREEZE_BYTES) ||
    before.size > BigInt(Number.MAX_SAFE_INTEGER)
  ) {
    throw new Error(`${label} must be a bounded non-empty regular file`)
  }
  const canonical = await realpath(absolute)
  if (!samePath(canonical, absolute)) throw new Error(`${label} traverses a symlink or junction`)
  const identity = statIdentity(before)
  const bytes = await readFile(absolute)
  const after = await lstat(absolute, { bigint: true })
  if (statIdentity(after) !== identity || bytes.length !== Number(before.size)) {
    throw new Error(`${label} changed while reading`)
  }
  return bytes
}

export async function readReleaseSourceFreeze({ input, expectedSha256 } = {}) {
  const digest = String(expectedSha256 || '').toLowerCase()
  if (!SHA256.test(digest)) throw new Error('pre-build release source freeze digest is required')
  const bytes = await readBoundedFile(input, 'pre-build release source freeze')
  const actual = createHash('sha256').update(bytes).digest('hex')
  if (actual !== digest) throw new Error('release source freeze digest does not match the pre-build freeze')
  const text = bytes.toString('utf8')
  if (!Buffer.from(text, 'utf8').equals(bytes) || text.startsWith('\uFEFF') || text.includes('\0')) {
    throw new Error('pre-build release source freeze must be canonical UTF-8 JSON')
  }
  let document
  try {
    document = JSON.parse(text)
  } catch {
    throw new Error('pre-build release source freeze is not valid JSON')
  }
  if (!canonicalBytes(document).equals(bytes)) {
    throw new Error('pre-build release source freeze bytes are not canonical')
  }
  return checkedFreeze(document)
}

export async function restoreGeneratedReleaseSource({
  input,
  expectedSha256,
  projectRoot = defaultProjectRoot
} = {}) {
  const baseline = await readReleaseSourceFreeze({ input, expectedSha256 })
  projectRoot = await checkedDirectory(projectRoot, 'generated release source restore root')
  for (const file of baseline.generatedSource.files) {
    const output = resolve(projectRoot, ...file.path.split('/'))
    await materializeGeneratedSourceModule({
      output,
      content: Buffer.from(file.contentBase64, 'base64'),
      operation: 'write'
    })
  }
  const restored = await captureGeneratedReleaseSource({ projectRoot })
  for (let index = 0; index < restored.files.length; index += 1) {
    const expected = baseline.generatedSource.files[index]
    const actual = restored.files[index]
    if (
      actual.path !== expected.path ||
      actual.sha256 !== expected.sha256 ||
      actual.size !== expected.size ||
      actual.contentBase64 !== expected.contentBase64
    ) {
      throw new Error(`restored generated release source differs from producer evidence: ${expected.path}`)
    }
  }
  return restored
}

export async function writeReleaseSourceFreeze({
  output,
  frozen,
  ...captureOptions
} = {}) {
  const absolute = resolve(String(output || ''))
  if (!isAbsolute(String(output || '')) || !samePath(output, absolute)) {
    throw new Error('release source freeze output path must be canonical and absolute')
  }
  await checkedDirectory(dirname(absolute), 'release source freeze output parent')
  const document = checkedFreeze(frozen || await captureReleaseSourceFreeze(captureOptions))
  const bytes = canonicalBytes(document)
  if (bytes.length > MAX_FREEZE_BYTES) throw new Error('release source freeze document is oversized')
  await writeFile(absolute, bytes, { flag: 'wx' })
  const sha256 = createHash('sha256').update(bytes).digest('hex')
  const verified = await readReleaseSourceFreeze({ input: absolute, expectedSha256: sha256 })
  assertReleaseSourceFreezeUnchanged(document, verified)
  return { document, sha256, size: bytes.length }
}

export async function verifyFrozenReleaseSource({
  frozen,
  input,
  expectedSha256,
  captureCurrent,
  ...captureOptions
} = {}) {
  const baseline = frozen ? checkedFreeze(frozen) : await readReleaseSourceFreeze({ input, expectedSha256 })
  const current = await (captureCurrent || captureReleaseSourceFreeze)(captureOptions)
  assertReleaseSourceFreezeUnchanged(baseline, current)
  return baseline
}

async function main(argv) {
  const [operation, path] = argv
  if (!path) throw new Error('release source freeze file path is required')
  if (operation === 'write') {
    const result = await writeReleaseSourceFreeze({ output: path })
    console.log(`[release-source-freeze] WRITTEN sha256=${result.sha256} size=${result.size}`)
    return
  }
  if (operation === 'verify') {
    await verifyFrozenReleaseSource({
      input: path,
      expectedSha256: process.env.NACHUAN_RELEASE_SOURCE_FREEZE_SHA256
    })
    console.log('[release-source-freeze] VERIFIED')
    return
  }
  if (operation === 'restore-generated') {
    await restoreGeneratedReleaseSource({
      input: path,
      expectedSha256: process.env.NACHUAN_RELEASE_SOURCE_FREEZE_SHA256
    })
    console.log('[release-source-freeze] PRODUCER_GENERATED_SOURCE_RESTORED')
    return
  }
  throw new Error('usage: release-source-freeze.mjs write|verify|restore-generated <absolute-freeze.json>')
}

if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  try {
    await main(process.argv.slice(2))
  } catch (error) {
    console.error(`[release-source-freeze] BLOCKED: ${error instanceof Error ? error.message : String(error)}`)
    process.exitCode = 1
  }
}
