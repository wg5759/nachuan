import { createHash, randomBytes } from 'node:crypto'
import { spawn } from 'node:child_process'
import { createReadStream } from 'node:fs'
import {
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  stat,
  writeFile
} from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { basename, dirname, isAbsolute, join, posix, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

import { scanReleasePaths } from './release-security.mjs'

const scriptPath = fileURLToPath(import.meta.url)
const SHA256 = /^[0-9a-f]{64}$/
const VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/
const MAX_FILES = 100_000
const MAX_FILE_BYTES = 4 * 1024 * 1024 * 1024
const MAX_TOTAL_BYTES = 16 * 1024 * 1024 * 1024
const MAX_MANIFEST_BYTES = 64 * 1024 * 1024

function checkedVersion(value) {
  const version = String(value || '')
  if (!VERSION.test(version)) throw new Error(`invalid canonical release version: ${value}`)
  return version
}

function checkedVariant(value) {
  const variant = String(value || '').toLowerCase()
  if (!['lean', 'full'].includes(variant)) throw new Error(`invalid release variant: ${value}`)
  return variant
}

function checkedRelativePath(value, label = 'manifest path') {
  const path = String(value || '')
  if (
    !path ||
    path.includes('\\') ||
    path.includes('\0') ||
    isAbsolute(path) ||
    posix.normalize(path) !== path ||
    path.split('/').some((part) => !part || part === '.' || part === '..')
  ) {
    throw new Error(`${label} is not a canonical relative path: ${value}`)
  }
  return path
}

async function sha256File(path) {
  const hash = createHash('sha256')
  await new Promise((accept, reject) => {
    const input = createReadStream(path)
    input.on('data', (chunk) => hash.update(chunk))
    input.once('error', reject)
    input.once('end', accept)
  })
  return hash.digest('hex')
}

async function assertRealDirectory(path, label) {
  const info = await lstat(path)
  if (info.isSymbolicLink() || !info.isDirectory()) {
    throw new Error(`${label} must be a real directory`)
  }
  await realpath(path)
}

async function enumerateTree(root) {
  root = resolve(root)
  await assertRealDirectory(root, 'payload root')
  const files = []
  const folded = new Set()
  let totalBytes = 0

  async function visit(directory, parts) {
    const entries = await readdir(directory, { withFileTypes: true })
    entries.sort((left, right) => (left.name < right.name ? -1 : left.name > right.name ? 1 : 0))
    for (const entry of entries) {
      const path = join(directory, entry.name)
      const info = await lstat(path)
      if (entry.isSymbolicLink() || info.isSymbolicLink()) {
        throw new Error(`payload tree must not contain filesystem redirects: ${path}`)
      }
      if (info.isDirectory()) {
        await visit(path, [...parts, entry.name])
        continue
      }
      if (!info.isFile()) throw new Error(`payload tree contains a special file: ${path}`)
      if (!Number.isSafeInteger(info.size) || info.size < 0 || info.size > MAX_FILE_BYTES) {
        throw new Error(`payload file has an invalid size: ${path}`)
      }
      const manifestPath = checkedRelativePath([...parts, entry.name].join('/'), 'payload path')
      const key = manifestPath.toLowerCase()
      if (folded.has(key)) throw new Error(`payload tree contains a case-colliding path: ${manifestPath}`)
      folded.add(key)
      totalBytes += info.size
      if (files.length >= MAX_FILES || totalBytes > MAX_TOTAL_BYTES) {
        throw new Error('payload tree exceeds the release manifest bounds')
      }
      files.push({ path: manifestPath, sha256: await sha256File(path), size: info.size })
    }
  }

  await visit(root, [])
  files.sort((left, right) => (left.path < right.path ? -1 : left.path > right.path ? 1 : 0))
  return { files, totalBytes }
}

function validateManifest(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new Error('win-unpacked manifest must be an object')
  }
  if (Object.keys(payload).sort().join(',') !== 'arch,files,platform,schema,variant,version') {
    throw new Error('win-unpacked manifest fields are not canonical')
  }
  if (payload.schema !== 1 || payload.platform !== 'win32' || payload.arch !== 'x64') {
    throw new Error('win-unpacked manifest target/schema is unsupported')
  }
  checkedVersion(payload.version)
  checkedVariant(payload.variant)
  if (!Array.isArray(payload.files) || !payload.files.length || payload.files.length > MAX_FILES) {
    throw new Error('win-unpacked manifest files must be a bounded non-empty array')
  }
  const seen = new Set()
  let previous = ''
  let totalBytes = 0
  for (const file of payload.files) {
    if (!file || typeof file !== 'object' || Array.isArray(file)) {
      throw new Error('win-unpacked manifest contains a non-object file')
    }
    if (Object.keys(file).sort().join(',') !== 'path,sha256,size') {
      throw new Error('win-unpacked manifest file fields are not canonical')
    }
    const path = checkedRelativePath(file.path)
    if (previous && path <= previous) throw new Error('win-unpacked manifest paths are not ordinal-sorted')
    previous = path
    const key = path.toLowerCase()
    if (seen.has(key)) throw new Error(`duplicate win-unpacked manifest path: ${path}`)
    seen.add(key)
    if (!SHA256.test(file.sha256)) throw new Error(`invalid manifest SHA-256: ${path}`)
    if (!Number.isSafeInteger(file.size) || file.size < 0 || file.size > MAX_FILE_BYTES) {
      throw new Error(`invalid manifest size: ${path}`)
    }
    totalBytes += file.size
    if (totalBytes > MAX_TOTAL_BYTES) throw new Error('win-unpacked manifest total size is unbounded')
  }
  return payload
}

async function readManifest(path) {
  const info = await lstat(path)
  if (info.isSymbolicLink() || !info.isFile() || info.size <= 0 || info.size > MAX_MANIFEST_BYTES) {
    throw new Error('win-unpacked manifest must be a bounded regular file')
  }
  let payload
  try {
    payload = JSON.parse(await readFile(path, 'utf8'))
  } catch (error) {
    throw new Error(`win-unpacked manifest is not valid JSON: ${error}`)
  }
  return validateManifest(payload)
}

export async function readTreeManifest(path) {
  return await readManifest(resolve(path))
}

export async function writeTreeManifest({ root, output, version, variant }) {
  root = resolve(root)
  output = resolve(output)
  const outputRelative = relative(root, output)
  if (!outputRelative || (!outputRelative.startsWith(`..${sep}`) && outputRelative !== '..')) {
    throw new Error('win-unpacked manifest output must be outside the payload root')
  }
  const tree = await enumerateTree(root)
  if (!tree.files.length) throw new Error('win-unpacked payload tree is empty')
  const payload = {
    schema: 1,
    platform: 'win32',
    arch: 'x64',
    version: checkedVersion(version),
    variant: checkedVariant(variant),
    files: tree.files
  }
  await mkdir(dirname(output), { recursive: true })
  const temporary = `${output}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`
  await writeFile(temporary, `${JSON.stringify(payload, null, 2)}\n`, { encoding: 'utf8', flag: 'wx' })
  await rm(output, { force: true })
  await rename(temporary, output)
  return { fileCount: tree.files.length, totalBytes: tree.totalBytes, manifestPath: output }
}

export async function verifyTreeAgainstManifest({ root, manifestPath, allowedExtraPaths = [] }) {
  const manifest = await readManifest(resolve(manifestPath))
  const allowed = new Set(allowedExtraPaths.map((path) => checkedRelativePath(path, 'allowed extra path').toLowerCase()))
  const declared = new Map(manifest.files.map((file) => [file.path.toLowerCase(), file]))
  for (const key of allowed) {
    if (declared.has(key)) throw new Error(`allowed extra path is already manifest-bound: ${key}`)
  }
  const actualTree = await enumerateTree(root)
  let allowedExtraCount = 0
  const actual = new Map()
  for (const file of actualTree.files) {
    const key = file.path.toLowerCase()
    if (allowed.has(key)) {
      allowedExtraCount += 1
      continue
    }
    actual.set(key, file)
  }
  if (actual.size !== declared.size) {
    throw new Error(`installed payload is not closed to its manifest: expected=${declared.size} actual=${actual.size}`)
  }
  for (const [key, expected] of declared) {
    const found = actual.get(key)
    if (!found) throw new Error(`installed payload is missing manifest file: ${expected.path}`)
    if (found.path !== expected.path) throw new Error(`installed payload path casing drifted: ${expected.path}`)
    if (found.size !== expected.size) throw new Error(`installed payload size mismatch: ${expected.path}`)
    if (found.sha256 !== expected.sha256) throw new Error(`installed payload SHA-256 mismatch: ${expected.path}`)
  }
  return {
    fileCount: declared.size,
    allowedExtraCount,
    totalBytes: manifest.files.reduce((sum, file) => sum + file.size, 0),
    version: manifest.version,
    variant: manifest.variant
  }
}

function runProcess(file, args, timeoutMs) {
  return new Promise((accept, reject) => {
    const child = spawn(file, args, { shell: false, windowsHide: true, stdio: 'inherit' })
    const timer = setTimeout(() => {
      child.kill()
      reject(new Error(`process timed out after ${timeoutMs}ms: ${file}`))
    }, timeoutMs)
    child.once('error', (error) => {
      clearTimeout(timer)
      reject(error)
    })
    child.once('exit', (code, signal) => {
      clearTimeout(timer)
      if (code === 0) accept()
      else reject(new Error(`process failed: ${file} exit=${code} signal=${signal || 'none'}`))
    })
  })
}

async function assertBoundedInstaller(path) {
  const info = await stat(path)
  if (!info.isFile() || info.size < 25 * 1024 * 1024 || info.size > MAX_FILE_BYTES) {
    throw new Error('installer must be a bounded regular release file')
  }
  if (!path.toLowerCase().endsWith('.exe')) throw new Error('installer must be a Windows executable')
}

export async function verifyInstallerPayloadClosure({
  installer,
  unpackedRoot,
  manifestPath,
  version,
  variant,
  productName
}) {
  if (process.platform !== 'win32') throw new Error('NSIS installer payload verification is Windows-only')
  installer = resolve(installer)
  await assertBoundedInstaller(installer)
  if (!productName || /[\\/\0]/.test(productName)) throw new Error('invalid installer product name')
  await writeTreeManifest({ root: unpackedRoot, output: manifestPath, version, variant })

  const sandbox = await mkdtemp(join(tmpdir(), 'nachuan-installer-payload-'))
  const installRoot = join(sandbox, 'app')
  const uninstallName = `Uninstall ${productName}.exe`
  const uninstaller = join(installRoot, uninstallName)
  try {
    await runProcess(installer, ['/S', `/D=${installRoot}`], 5 * 60 * 1000)
    const result = await verifyTreeAgainstManifest({
      root: installRoot,
      manifestPath,
      allowedExtraPaths: [uninstallName]
    })
    if (result.allowedExtraCount !== 1) {
      throw new Error(`installer did not create exactly one expected uninstaller: ${uninstallName}`)
    }
    const findings = await scanReleasePaths([installRoot])
    if (findings.length) {
      const summary = findings
        .slice(0, 5)
        .map((finding) => `${basename(finding.file)}:${finding.code}:${finding.field}`)
        .join(',')
      throw new Error(`installed payload secret/redirect scan blocked findings=${findings.length} ${summary}`)
    }
    return { ...result, installRoot, uninstaller }
  } finally {
    try {
      const uninstallerInfo = await lstat(uninstaller)
      if (uninstallerInfo.isFile() && !uninstallerInfo.isSymbolicLink()) {
        await runProcess(uninstaller, ['/S', `_?=${installRoot}`], 2 * 60 * 1000)
      }
    } catch {
      // Verification still fails on its original error; the sandbox is removed below.
    }
    const sandboxRelative = relative(resolve(tmpdir()), resolve(sandbox))
    if (!sandboxRelative || sandboxRelative === '..' || sandboxRelative.startsWith(`..${sep}`)) {
      throw new Error(`refusing to clean installer verification path outside temp: ${sandbox}`)
    }
    await rm(sandbox, { recursive: true, force: true })
  }
}

async function main(argv) {
  const [operation, ...args] = argv
  if (operation === 'write' && args.length === 4) {
    const result = await writeTreeManifest({
      root: args[0],
      output: args[1],
      version: args[2],
      variant: args[3]
    })
    console.log(`[installer-closure] manifest files=${result.fileCount} bytes=${result.totalBytes}`)
    return 0
  }
  if (operation === 'verify' && args.length >= 2) {
    const result = await verifyTreeAgainstManifest({
      root: args[0],
      manifestPath: args[1],
      allowedExtraPaths: args.slice(2)
    })
    console.log(`[installer-closure] tree verified files=${result.fileCount}`)
    return 0
  }
  if (operation === 'install-verify' && args.length === 6) {
    const result = await verifyInstallerPayloadClosure({
      installer: args[0],
      unpackedRoot: args[1],
      manifestPath: args[2],
      version: args[3],
      variant: args[4],
      productName: args[5]
    })
    console.log(`[installer-closure] NSIS payload verified files=${result.fileCount}`)
    return 0
  }
  console.error(
    'usage: installer-closure.mjs write <win-unpacked> <manifest> <version> <variant> | verify <tree> <manifest> [allowed-extra...] | install-verify <installer> <win-unpacked> <manifest> <version> <variant> <product-name>'
  )
  return 2
}

if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  try {
    process.exitCode = await main(process.argv.slice(2))
  } catch (error) {
    console.error(`[installer-closure] BLOCKED: ${error instanceof Error ? error.message : String(error)}`)
    process.exitCode = 1
  }
}
