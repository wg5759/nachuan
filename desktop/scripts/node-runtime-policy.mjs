import { createHash, randomUUID } from 'node:crypto'
import { spawn } from 'node:child_process'
import { constants, existsSync, lstatSync, readFileSync, readdirSync, realpathSync } from 'node:fs'
import { copyFile, mkdir, open, readFile, rename, rm, writeFile } from 'node:fs/promises'
import { dirname, join, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

import { verifyArchiveAuthenticode } from './git-runtime-policy.mjs'

const scriptPath = fileURLToPath(import.meta.url)
const desktopRoot = resolve(dirname(scriptPath), '..')
const defaultProjectRoot = resolve(desktopRoot, '..')
const SHA256 = /^[0-9a-f]{64}$/u
const UPPER_SHA1 = /^[0-9A-F]{40}$/u
const VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/u
const MAX_BINARY_BYTES = 256 * 1024 * 1024
const MAX_TEXT_BYTES = 4 * 1024 * 1024
const MAX_COMMAND_OUTPUT_BYTES = 2 * 1024 * 1024
const MAX_REDIRECTS = 5
const PROVENANCE_NAME = 'NODE_RUNTIME_PROVENANCE.json'

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

function pathKey(path) {
  const key = resolve(path).split(sep).join('/')
  return process.platform === 'win32' ? key.toLowerCase() : key
}

// AV/indexer scans of a freshly written node.exe hold a transient handle on its
// directory; renaming the candidate right after verification can hit EPERM on
// Windows. Retry only lock-class errors, then give up loudly.
const TRANSIENT_LOCK_CODES = new Set(['EPERM', 'EACCES', 'EBUSY'])
const sleep = (ms) => new Promise((resolvePromise) => setTimeout(resolvePromise, ms))

export async function renameTransientLockRetry(source, target, { attempts = 61, delayMs = 500, renameImpl = rename, sleepImpl = sleep } = {}) {
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      await renameImpl(source, target)
      return
    } catch (error) {
      if (attempt === attempts || !TRANSIENT_LOCK_CODES.has(error?.code)) throw error
      await sleepImpl(delayMs)
    }
  }
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
    info.nlink !== 1n ||
    info.size <= 0n ||
    info.size > BigInt(MAX_BINARY_BYTES) ||
    info.size > BigInt(Number.MAX_SAFE_INTEGER)
  ) {
    throw new Error(`${label} must be a bounded, single-link, non-empty regular file`)
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
  exactKeys(document, ['arch', 'authenticode', 'binary', 'officialShasums', 'platform', 'schema', 'version'], 'Node runtime lock')
  if (
    document.schema !== 1 ||
    document.platform !== 'win32' ||
    document.arch !== 'x64' ||
    !VERSION.test(String(document.version || ''))
  ) {
    throw new Error('Node runtime lock identity is invalid')
  }
  exactKeys(document.binary, ['name', 'sha256', 'size', 'sourceUrl'], 'Node runtime binary lock')
  const releaseRoot = `https://nodejs.org/dist/v${document.version}`
  if (
    document.binary.name !== 'node.exe' ||
    document.binary.sourceUrl !== `${releaseRoot}/win-x64/node.exe` ||
    !SHA256.test(String(document.binary.sha256 || '')) ||
    !Number.isSafeInteger(document.binary.size) ||
    document.binary.size <= 0 ||
    document.binary.size > MAX_BINARY_BYTES
  ) {
    throw new Error('Node runtime binary is not an exact official Node.js release asset')
  }
  exactKeys(document.officialShasums, ['line', 'url'], 'Node runtime official checksum lock')
  if (
    document.officialShasums.url !== `${releaseRoot}/SHASUMS256.txt` ||
    document.officialShasums.line !== `${document.binary.sha256}  win-x64/node.exe`
  ) {
    throw new Error('Node runtime official checksum identity is invalid')
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
    'Node runtime Authenticode lock'
  )
  if (
    document.authenticode.status !== 'Valid' ||
    !UPPER_SHA1.test(String(document.authenticode.thumbprint || '')) ||
    !UPPER_SHA1.test(String(document.authenticode.timestampThumbprint || '')) ||
    ['issuer', 'notAfter', 'notBefore', 'serial', 'subject', 'timestampSubject'].some(
      (key) => typeof document.authenticode[key] !== 'string' || !document.authenticode[key]
    )
  ) {
    throw new Error('Node runtime Authenticode identity is invalid')
  }
  return canonicalValue(document)
}

export function readNodeRuntimeLock({ projectRoot = defaultProjectRoot, lockPath } = {}) {
  projectRoot = resolve(projectRoot)
  const resolved = resolve(lockPath || join(projectRoot, 'node-runtime-lock.json'))
  const bytes = readFileSync(resolved)
  let document
  try {
    document = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
  } catch {
    throw new Error('Node runtime lock must be UTF-8 JSON')
  }
  if (!bytes.equals(canonicalBytes(document))) throw new Error('Node runtime lock must be canonical JSON')
  return checkedLock(document)
}

function assertPackageBinding(projectRoot, lock) {
  const packagePath = join(projectRoot, 'desktop', 'package.json')
  if (!existsSync(packagePath)) return
  const packageDocument = JSON.parse(readFileSync(packagePath, 'utf8'))
  if (
    packageDocument.engines?.node !== lock.version ||
    packageDocument.engines?.npm !== '11.12.1' ||
    packageDocument.packageManager !== 'npm@11.12.1'
  ) {
    throw new Error('desktop package Node/npm release toolchain binding drifted')
  }
}

function runtimePaths(projectRoot, version) {
  const buildRoot = join(projectRoot, 'build')
  const cacheRoot = join(buildRoot, 'node-cache')
  const runtimeRoot = join(buildRoot, 'node-runtime')
  return {
    buildRoot,
    cacheRoot,
    cachePath: join(cacheRoot, `node-v${version}-win-x64.exe`),
    runtimeRoot,
    execPath: join(runtimeRoot, 'node.exe'),
    provenancePath: join(runtimeRoot, PROVENANCE_NAME)
  }
}

export function nodeRuntimePath(projectRoot = defaultProjectRoot) {
  return join(resolve(projectRoot), 'build', 'node-runtime', 'node.exe')
}

function assertOfficialNodeUrl(value) {
  const url = new URL(value)
  if (url.protocol !== 'https:' || url.hostname !== 'nodejs.org' || url.username || url.password || url.hash) {
    throw new Error('Node runtime download left the official HTTPS origin')
  }
  return url
}

async function fetchOfficial(url, { signal, fetchImpl = fetch } = {}) {
  let current = assertOfficialNodeUrl(url)
  for (let redirects = 0; redirects <= MAX_REDIRECTS; redirects += 1) {
    const response = await fetchImpl(current, { redirect: 'manual', signal })
    if (response.status >= 300 && response.status < 400) {
      if (redirects === MAX_REDIRECTS) throw new Error('Node runtime download exceeded redirect limit')
      const location = response.headers.get('location')
      if (!location) throw new Error('Node runtime redirect has no location')
      await response.body?.cancel()
      current = assertOfficialNodeUrl(new URL(location, current).href)
      continue
    }
    if (!response.ok) throw new Error(`Node runtime download failed with HTTP ${response.status}`)
    return response
  }
  throw new Error('Node runtime download redirect loop is invalid')
}

async function defaultDownloadText({ url, fetchImpl = fetch }) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), 30_000)
  try {
    const response = await fetchOfficial(url, { signal: controller.signal, fetchImpl })
    const declared = Number(response.headers.get('content-length') || 0)
    if (declared && (!Number.isSafeInteger(declared) || declared <= 0 || declared > MAX_TEXT_BYTES)) {
      throw new Error('Node runtime checksum response size is invalid')
    }
    const bytes = Buffer.from(await response.arrayBuffer())
    if (!bytes.length || bytes.length > MAX_TEXT_BYTES) throw new Error('Node runtime checksum response is unbounded')
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  } finally {
    clearTimeout(timer)
  }
}

async function defaultDownloadBinary({ destination, expectedSha256, expectedSize, sourceUrl, fetchImpl = fetch }) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), 120_000)
  let handle
  try {
    const response = await fetchOfficial(sourceUrl, { signal: controller.signal, fetchImpl })
    const declared = Number(response.headers.get('content-length') || 0)
    if (declared && declared !== expectedSize) throw new Error('Node runtime download content length drifted')
    if (!response.body) throw new Error('Node runtime download body is missing')
    handle = await open(destination, 'wx')
    const reader = response.body.getReader()
    const digest = createHash('sha256')
    let total = 0
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      total += value.byteLength
      if (total > expectedSize || total > MAX_BINARY_BYTES) throw new Error('Node runtime download exceeded its locked size')
      const chunk = Buffer.from(value)
      digest.update(chunk)
      await handle.write(chunk)
    }
    await handle.sync()
    await handle.close()
    handle = undefined
    if (total !== expectedSize) throw new Error('Node runtime download size drifted')
    if (digest.digest('hex') !== expectedSha256) throw new Error('Node runtime download hash drifted')
  } catch (error) {
    await handle?.close().catch(() => {})
    await rm(destination, { force: true }).catch(() => {})
    throw error
  } finally {
    clearTimeout(timer)
  }
}

async function boundedSpawn(executable, args, { timeoutMs = 20_000 } = {}) {
  return await new Promise((resolvePromise, reject) => {
    const child = spawn(executable, args, { windowsHide: true, shell: false, stdio: ['ignore', 'pipe', 'pipe'] })
    const stdout = []
    const stderr = []
    let outputBytes = 0
    let settled = false
    let timer
    const finish = (callback) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      callback()
    }
    const capture = (bucket) => (chunk) => {
      outputBytes += chunk.length
      if (outputBytes > MAX_COMMAND_OUTPUT_BYTES) {
        child.kill()
        finish(() => reject(new Error('Node runtime verification command output exceeded its bound')))
        return
      }
      bucket.push(chunk)
    }
    child.stdout.on('data', capture(stdout))
    child.stderr.on('data', capture(stderr))
    child.once('error', (error) => finish(() => reject(error)))
    child.once('close', (code, signal) =>
      finish(() => resolvePromise({
        code,
        signal,
        stderr: Buffer.concat(stderr).toString('utf8'),
        stdout: Buffer.concat(stdout).toString('utf8')
      }))
    )
    timer = setTimeout(() => {
      child.kill()
      finish(() => reject(new Error('Node runtime verification command timed out')))
    }, timeoutMs)
  })
}

async function defaultProbeRuntime({ execPath }) {
  const result = await boundedSpawn(execPath, ['--version'])
  if (result.code !== 0 || result.signal || result.stderr.trim()) throw new Error('Node runtime version probe failed')
  const match = /^v((?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*))\r?\n?$/u.exec(result.stdout)
  if (!match) throw new Error('Node runtime version probe returned a non-canonical version')
  return { execPath, version: match[1] }
}

async function defaultVerifyAuthenticode({ binaryPath }) {
  return await verifyArchiveAuthenticode({ archivePath: binaryPath })
}

function assertAuthenticode(actual, lock) {
  const normalized = canonicalValue(actual)
  if (JSON.stringify(normalized) !== JSON.stringify(lock.authenticode)) {
    throw new Error('Node runtime Authenticode identity drifted')
  }
  return normalized
}

function assertProbe(actual, lock) {
  if (!actual || actual.version !== lock.version) throw new Error('Node runtime version drifted')
  return { version: lock.version }
}

function expectedProvenance({ lock, lockBytes, authenticode, probe }) {
  return canonicalValue({
    arch: lock.arch,
    authenticode,
    binary: {
      name: lock.binary.name,
      sha256: lock.binary.sha256,
      size: lock.binary.size,
      sourceUrl: lock.binary.sourceUrl
    },
    lockSha256: sha256Bytes(lockBytes),
    officialShasums: lock.officialShasums,
    platform: lock.platform,
    probe,
    schema: 1,
    version: lock.version
  })
}

function checkedRuntimeTree(paths, lock) {
  checkedDirectory(paths.runtimeRoot, 'Node runtime directory')
  const names = readdirSync(paths.runtimeRoot).sort()
  if (JSON.stringify(names) !== JSON.stringify([PROVENANCE_NAME, 'node.exe'].sort())) {
    throw new Error('Node runtime file set is not closed')
  }
  return checkedFile(paths.execPath, 'Node runtime', lock.binary)
}

async function ensureCache({ lock, paths, downloadBinary, downloadText, verifyAuthenticode }) {
  if (!existsSync(paths.cachePath)) {
    const shasums = await downloadText({ url: lock.officialShasums.url })
    if (!shasums.split(/\r?\n/u).includes(lock.officialShasums.line)) {
      throw new Error('official Node.js SHASUMS256.txt does not contain the locked binary')
    }
    const candidate = `${paths.cachePath}.candidate-${randomUUID()}`
    try {
      await downloadBinary({
        destination: candidate,
        expectedSha256: lock.binary.sha256,
        expectedSize: lock.binary.size,
        sourceUrl: lock.binary.sourceUrl
      })
      checkedFile(candidate, 'Node runtime download', lock.binary)
      assertAuthenticode(await verifyAuthenticode({ binaryPath: candidate }), lock)
      try {
        await renameTransientLockRetry(candidate, paths.cachePath)
      } catch (error) {
        if (!existsSync(paths.cachePath)) throw error
        await rm(candidate, { force: true })
      }
    } finally {
      await rm(candidate, { force: true }).catch(() => {})
    }
  }
  checkedFile(paths.cachePath, 'Node runtime cache', lock.binary)
  assertAuthenticode(await verifyAuthenticode({ binaryPath: paths.cachePath }), lock)
}

export async function prepareNodeRuntime({
  projectRoot = defaultProjectRoot,
  lockPath,
  downloadBinary = defaultDownloadBinary,
  downloadText = defaultDownloadText,
  verifyAuthenticode = defaultVerifyAuthenticode,
  probeRuntime = defaultProbeRuntime
} = {}) {
  projectRoot = checkedDirectory(projectRoot, 'project root')
  const resolvedLockPath = resolve(lockPath || join(projectRoot, 'node-runtime-lock.json'))
  const lockBytes = readFileSync(resolvedLockPath)
  const lock = readNodeRuntimeLock({ projectRoot, lockPath: resolvedLockPath })
  assertPackageBinding(projectRoot, lock)
  const paths = runtimePaths(projectRoot, lock.version)
  if (existsSync(paths.runtimeRoot)) {
    return await verifyPreparedNodeRuntime({ projectRoot, lockPath: resolvedLockPath, verifyAuthenticode, probeRuntime })
  }
  await mkdir(paths.cacheRoot, { recursive: true })
  checkedDirectory(paths.buildRoot, 'Node runtime build directory')
  checkedDirectory(paths.cacheRoot, 'Node runtime cache directory')
  await ensureCache({ lock, paths, downloadBinary, downloadText, verifyAuthenticode })

  const candidateRoot = `${paths.runtimeRoot}.candidate-${randomUUID()}`
  try {
    await mkdir(candidateRoot)
    const candidateExec = join(candidateRoot, 'node.exe')
    await copyFile(paths.cachePath, candidateExec, constants.COPYFILE_EXCL)
    checkedFile(candidateExec, 'Node runtime candidate', lock.binary)
    const authenticode = assertAuthenticode(await verifyAuthenticode({ binaryPath: candidateExec }), lock)
    const probe = assertProbe(await probeRuntime({ execPath: candidateExec }), lock)
    checkedFile(candidateExec, 'Node runtime candidate', lock.binary)
    const provenance = expectedProvenance({ lock, lockBytes, authenticode, probe })
    await writeFile(join(candidateRoot, PROVENANCE_NAME), canonicalBytes(provenance), { flag: 'wx' })
    try {
      await renameTransientLockRetry(candidateRoot, paths.runtimeRoot)
    } catch (error) {
      if (!existsSync(paths.runtimeRoot)) throw error
      await rm(candidateRoot, { recursive: true, force: true })
      return await verifyPreparedNodeRuntime({ projectRoot, lockPath: resolvedLockPath, verifyAuthenticode, probeRuntime })
    }
    return { execPath: paths.execPath, provenance }
  } finally {
    await rm(candidateRoot, { recursive: true, force: true }).catch(() => {})
  }
}

export async function verifyPreparedNodeRuntime({
  projectRoot = defaultProjectRoot,
  lockPath,
  verifyAuthenticode = defaultVerifyAuthenticode,
  probeRuntime = defaultProbeRuntime
} = {}) {
  projectRoot = checkedDirectory(projectRoot, 'project root')
  const resolvedLockPath = resolve(lockPath || join(projectRoot, 'node-runtime-lock.json'))
  const lockBytes = readFileSync(resolvedLockPath)
  const lock = readNodeRuntimeLock({ projectRoot, lockPath: resolvedLockPath })
  assertPackageBinding(projectRoot, lock)
  const paths = runtimePaths(projectRoot, lock.version)
  checkedRuntimeTree(paths, lock)
  const authenticode = assertAuthenticode(await verifyAuthenticode({ binaryPath: paths.execPath }), lock)
  const probe = assertProbe(await probeRuntime({ execPath: paths.execPath }), lock)
  checkedRuntimeTree(paths, lock)
  const provenanceBytes = await readFile(paths.provenancePath)
  let provenance
  try {
    provenance = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(provenanceBytes))
  } catch {
    throw new Error('Node runtime provenance must be UTF-8 JSON')
  }
  if (!provenanceBytes.equals(canonicalBytes(provenance))) throw new Error('Node runtime provenance is not canonical')
  const expected = expectedProvenance({ lock, lockBytes, authenticode, probe })
  if (!provenanceBytes.equals(canonicalBytes(expected))) throw new Error('Node runtime provenance drifted')
  return { execPath: paths.execPath, provenance: expected }
}

async function runPinnedNode(argv) {
  if (!argv.length) throw new Error('pinned Node command is required')
  const prepared = await verifyPreparedNodeRuntime()
  const code = await new Promise((resolvePromise, reject) => {
    const child = spawn(prepared.execPath, argv, {
      cwd: desktopRoot,
      env: { ...process.env, NACHUAN_RELEASE_NODE_PATH: prepared.execPath },
      shell: false,
      stdio: 'inherit',
      windowsHide: true
    })
    child.once('error', reject)
    child.once('close', (exitCode, signal) => {
      if (signal) reject(new Error(`pinned Node command terminated by ${signal}`))
      else resolvePromise(exitCode ?? 1)
    })
  })
  process.exitCode = code
}

async function main(argv) {
  const [operation, ...rest] = argv
  if (operation === 'prepare') {
    const result = await prepareNodeRuntime()
    console.log(`[node-runtime] PREPARED version=${readNodeRuntimeLock().version} path=${result.execPath}`)
    return
  }
  if (operation === 'verify') {
    const result = await verifyPreparedNodeRuntime()
    console.log(`[node-runtime] VERIFIED version=${readNodeRuntimeLock().version} path=${result.execPath}`)
    return
  }
  if (operation === 'run') {
    await runPinnedNode(rest)
    return
  }
  throw new Error('usage: node-runtime-policy.mjs prepare|verify|run <node arguments...>')
}

if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  try {
    await main(process.argv.slice(2))
  } catch (error) {
    console.error(`[node-runtime] BLOCKED: ${error instanceof Error ? error.message : String(error)}`)
    process.exitCode = 1
  }
}
