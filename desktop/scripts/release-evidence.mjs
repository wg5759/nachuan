import { createHash } from 'node:crypto'
import { execFile } from 'node:child_process'
import { createReadStream, lstatSync, readFileSync, realpathSync } from 'node:fs'
import { writeFile } from 'node:fs/promises'
import { dirname, isAbsolute, join, parse as parsePath, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  RELEASE_EVIDENCE_FILES,
  verifyFinalReleaseOutput
} from './release-output.mjs'
import {
  verifyNativeCycloneDxSbom,
  writeNativeCycloneDxSbom
} from './license-evidence.mjs'
import {
  assertPythonReleaseSbomPolicy,
  filterPythonSbomForReleaseEnvironment,
  pyinstallerArchiveViewerDescriptor,
  pyinstallerArchiveViewerPath,
  PYINSTALLER_ARCHIVE_VIEWER_VERSION,
  PYTHON_RELEASE_SELECTION,
  pythonReleaseSbomArgs,
  selectedPythonPackagesFromUvLock
} from './python-release-policy.mjs'
import {
  assertReleaseSourceFreezePortableEquivalent,
  assertReleaseSourceFreezeUnchanged,
  captureReleaseSourceFreeze,
  readReleaseSourceFreeze,
  writeReleaseSourceFreeze
} from './release-source-freeze.mjs'

const scriptPath = fileURLToPath(import.meta.url)
const desktopRoot = resolve(dirname(scriptPath), '..')
const defaultProjectRoot = resolve(desktopRoot, '..')
const defaultReleaseRoot = join(desktopRoot, 'release')
const SHA256 = /^[0-9a-f]{64}$/
const RELEASE_TAG = /^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/
const COMMIT = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/
const RUN_ID = /^[1-9]\d{0,31}$/
export const RELEASE_TOOL_VERSIONS = Object.freeze({
  node: '24.14.0',
  npm: '11.12.1',
  pyinstallerArchiveViewer: PYINSTALLER_ARCHIVE_VIEWER_VERSION,
  python: '3.12.9',
  uv: '0.11.3'
})
const REPORT_NAMES = Object.freeze([
  ['npmAudit', 'NPM_AUDIT.json', 'application/json'],
  ['npmSbom', 'NPM_SBOM.cdx.json', 'application/vnd.cyclonedx+json'],
  ['pythonAudit', 'PYTHON_AUDIT.json', 'application/json'],
  ['pythonSbom', 'PYTHON_SBOM.cdx.json', 'application/vnd.cyclonedx+json']
])
const MAX_COMMAND_OUTPUT_BYTES = 96 * 1024 * 1024
const TOOL_DIGEST_CACHE = new Map()

export { RELEASE_EVIDENCE_FILES }

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

function exactKeys(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`)
  }
  if (Object.keys(value).sort().join(',') !== [...expected].sort().join(',')) {
    throw new Error(`${label} fields are not canonical`)
  }
}

function isPlainObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const prototype = Object.getPrototypeOf(value)
  return prototype === Object.prototype || prototype === null
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

function fileIdentity(path) {
  const info = lstatSync(path, { bigint: true })
  return `${info.dev}:${info.ino}:${info.size}:${info.mtimeNs}:${info.ctimeNs}`
}

async function toolFileDescriptor(path, name) {
  const info = checkedRegularFile(path, name, 256 * 1024 * 1024)
  const before = fileIdentity(path)
  const cached = TOOL_DIGEST_CACHE.get(path)
  if (cached?.identity === before) return { name, sha256: cached.sha256, size: info.size }
  const sha256 = await sha256File(path)
  const after = fileIdentity(path)
  if (after !== before) throw new Error(`release evidence ${name} tool changed while hashing`)
  TOOL_DIGEST_CACHE.set(path, { identity: after, sha256 })
  return { name, sha256, size: info.size }
}

function checkedRegularFile(path, label, maxBytes = 64 * 1024 * 1024) {
  const info = lstatSync(path)
  if (info.isSymbolicLink() || !info.isFile() || info.size <= 0 || info.size > maxBytes) {
    throw new Error(`${label} must be a bounded non-empty regular file`)
  }
  return info
}

function checkedAbsoluteRegularFile(path, label, maxBytes = 64 * 1024 * 1024) {
  if (typeof path !== 'string' || !isAbsolute(path) || resolve(path) !== path) {
    throw new Error(`${label} path must be canonical and absolute`)
  }
  let cursor = path
  const root = parsePath(path).root
  while (true) {
    const info = lstatSync(cursor)
    if (info.isSymbolicLink()) throw new Error(`${label} path chain must not contain reparse links`)
    if (cursor === path ? !info.isFile() : !info.isDirectory()) {
      throw new Error(`${label} path chain is not a regular file under ordinary directories`)
    }
    if (cursor === root) break
    const parent = dirname(cursor)
    if (parent === cursor) break
    cursor = parent
  }
  const real = realpathSync.native(path)
  if (resolve(real).toLowerCase() !== path.toLowerCase()) {
    throw new Error(`${label} path chain resolves through a reparse point`)
  }
  return checkedRegularFile(path, label, maxBytes)
}

function parseCanonicalJson(path, label, maxBytes = 64 * 1024 * 1024) {
  checkedRegularFile(path, label, maxBytes)
  const bytes = readFileSync(path)
  const text = bytes.toString('utf8')
  if (!Buffer.from(text, 'utf8').equals(bytes) || text.startsWith('\uFEFF') || text.includes('\0')) {
    throw new Error(`${label} must be canonical UTF-8 JSON`)
  }
  let value
  try {
    value = JSON.parse(text)
  } catch {
    throw new Error(`${label} must be valid JSON`)
  }
  if (!canonicalBytes(value).equals(bytes)) throw new Error(`${label} bytes are not canonical`)
  return value
}

function parseExternalJson(text, label) {
  const bytes = Buffer.from(String(text || ''), 'utf8')
  if (!bytes.length || bytes.length > MAX_COMMAND_OUTPUT_BYTES || text.startsWith('\uFEFF') || text.includes('\0')) {
    throw new Error(`${label} output is empty, oversized, or not plain UTF-8 JSON`)
  }
  try {
    return JSON.parse(text)
  } catch {
    throw new Error(`${label} output is not valid JSON`)
  }
}

function runExternal(
  command,
  args,
  { cwd, env = {}, label, allowNonZero = false, inheritEnv = true } = {}
) {
  const inherited = {}
  if (inheritEnv) {
    Object.assign(inherited, process.env)
  } else {
    const inheritedKeys =
      process.platform === 'win32'
        ? ['SystemRoot', 'WINDIR', 'ComSpec', 'PATHEXT', 'TEMP', 'TMP']
        : ['TMPDIR']
    for (const key of inheritedKeys) {
      if (process.env[key]) inherited[key] = process.env[key]
    }
  }
  return new Promise((accept, reject) => {
    execFile(
      command,
      args,
      {
        cwd,
        encoding: 'utf8',
        maxBuffer: MAX_COMMAND_OUTPUT_BYTES,
        timeout: 180_000,
        windowsHide: true,
        env: { ...inherited, PYTHONUTF8: '1', PYTHONIOENCODING: 'utf-8', ...env }
      },
      (error, stdout, stderr) => {
        const code = error && Number.isInteger(error.code) ? error.code : 0
        if (error && (!allowNonZero || !Number.isInteger(error.code))) {
          reject(new Error(`${label || command} failed or timed out`, { cause: error }))
          return
        }
        if (Buffer.byteLength(stdout, 'utf8') > MAX_COMMAND_OUTPUT_BYTES) {
          reject(new Error(`${label || command} output exceeded the release evidence limit`))
          return
        }
        accept({ code, stdout, stderr })
      }
    )
  })
}

function checkedNpmCliPath(explicitPath, env = process.env) {
  const path = explicitPath || env.NACHUAN_RELEASE_NPM_CLI_PATH
  if (!path || !String(path).toLowerCase().endsWith('npm-cli.js')) {
    throw new Error('the pinned npm CLI path is unavailable; PATH/npm shims are not accepted')
  }
  checkedAbsoluteRegularFile(path, 'pinned npm CLI', 2 * 1024 * 1024)
  return path
}

export function createReleaseCommandClient({
  projectRoot = defaultProjectRoot,
  npmCliPath,
  nodePath = process.env.NACHUAN_RELEASE_NODE_PATH,
  uvPath = process.env.NACHUAN_RELEASE_UV_PATH,
  pythonPath = process.env.NACHUAN_RELEASE_PYTHON_PATH,
  gitPath = process.env.NACHUAN_RELEASE_GIT_PATH,
  execute = runExternal
} = {}) {
  projectRoot = resolve(projectRoot)
  const npmCli = checkedNpmCliPath(npmCliPath)
  const nodeExecutable = nodePath
  checkedAbsoluteRegularFile(nodeExecutable, 'pinned Node executable', 256 * 1024 * 1024)
  if (resolve(process.execPath).toLowerCase() !== nodeExecutable.toLowerCase()) {
    throw new Error('the running Node executable does not match the pinned release path')
  }
  checkedAbsoluteRegularFile(uvPath, 'pinned uv executable', 256 * 1024 * 1024)
  checkedAbsoluteRegularFile(pythonPath, 'pinned Python executable', 256 * 1024 * 1024)
  checkedAbsoluteRegularFile(gitPath, 'pinned Git executable', 256 * 1024 * 1024)
  const archiveViewerPath = pyinstallerArchiveViewerPath(projectRoot)
  checkedAbsoluteRegularFile(archiveViewerPath, 'release-selected PyInstaller archive viewer', 2 * 1024 * 1024)
  for (const [name, path] of [['uv', uvPath], ['python', pythonPath], ['git', gitPath]]) {
    if (/\.(?:cmd|bat|ps1|js)$/i.test(path)) throw new Error(`the pinned ${name} tool cannot be a script shim`)
  }
  const gitExecPath = join(dirname(dirname(gitPath)), 'libexec', 'git-core')
  const gitEnvironment = {
    GIT_ATTR_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: process.platform === 'win32' ? 'NUL' : '/dev/null',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_COUNT: '1',
    GIT_CONFIG_KEY_0: 'core.fsmonitor',
    GIT_CONFIG_VALUE_0: 'false',
    GIT_DISCOVERY_ACROSS_FILESYSTEM: '0',
    GIT_EXEC_PATH: gitExecPath,
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
  }
  const runNpm = async (args, options = {}) =>
    await execute(nodeExecutable, [npmCli, ...args], {
      cwd: join(projectRoot, 'desktop'),
      label: options.label || `npm ${args[0]}`,
      allowNonZero: options.allowNonZero === true
    })
  const runUv = async (args, options = {}) =>
    await execute(uvPath, args, {
      cwd: projectRoot,
      label: options.label || `uv ${args[0]}`,
      allowNonZero: options.allowNonZero === true
    })
  return {
    async toolVersions() {
      const [npmResult, uvResult, pythonResult, gitResult, archiveViewer] = await Promise.all([
        runNpm(['--version'], { label: 'npm version' }),
        runUv(['--version'], { label: 'uv version' }),
        execute(pythonPath, ['-c', 'import platform; print(platform.python_version())'], {
          cwd: projectRoot,
          label: 'Python version'
        }),
        execute(gitPath, ['--no-pager', '--version'], {
          cwd: projectRoot,
          env: gitEnvironment,
          inheritEnv: false,
          label: 'Git version'
        }),
        pyinstallerArchiveViewerDescriptor(projectRoot)
      ])
      const uvMatch = /^uv\s+(\d+\.\d+\.\d+)\b/.exec(uvResult.stdout.trim())
      const gitMatch = /^git version\s+(.+)$/.exec(gitResult.stdout.trim())
      const values = {
        node: { path: nodeExecutable, version: process.versions.node },
        npm: { path: npmCli, version: npmResult.stdout.trim() },
        python: { path: pythonPath, version: pythonResult.stdout.trim() },
        uv: { path: uvPath, version: uvMatch?.[1] || '' },
        git: { path: gitPath, version: gitMatch?.[1] || '' }
      }
      const descriptors = Object.fromEntries(
        await Promise.all(Object.entries(values).map(async ([name, value]) => {
          const descriptor = await toolFileDescriptor(value.path, name)
          return [name, { ...descriptor, path: value.path, version: value.version }]
        }))
      )
      descriptors.pyinstallerArchiveViewer = archiveViewer
      return descriptors
    },
    async npmAudit() {
      const result = await runNpm(
        [
          'audit',
          '--json',
          '--package-lock-only',
          '--registry=https://registry.npmjs.org'
        ],
        { label: 'npm vulnerability audit' }
      )
      if (result.code !== 0) throw new Error('npm vulnerability audit did not exit zero')
      return parseExternalJson(result.stdout, 'npm vulnerability audit')
    },
    async npmSbom() {
      const result = await runNpm(
        ['sbom', '--sbom-format', 'cyclonedx', '--package-lock-only', '--json'],
        { label: 'npm CycloneDX export' }
      )
      return parseExternalJson(result.stdout, 'npm CycloneDX export')
    },
    async pythonSbom() {
      const result = await runUv(pythonReleaseSbomArgs(projectRoot), { label: 'uv CycloneDX export' })
      return filterPythonSbomForReleaseEnvironment(
        parseExternalJson(result.stdout, 'uv CycloneDX export'),
        { projectRoot }
      )
    }
  }
}

function createSourceControlClient({
  projectRoot = defaultProjectRoot,
  gitPath = process.env.NACHUAN_RELEASE_GIT_PATH,
  releaseTree = process.env.NACHUAN_RELEASE_TREE,
  frozenSourcePath = process.env.NACHUAN_RELEASE_SOURCE_FREEZE_PATH,
  frozenSourceSha256 = process.env.NACHUAN_RELEASE_SOURCE_FREEZE_SHA256,
  sourceComparison = 'unchanged'
} = {}) {
  projectRoot = resolve(projectRoot)
  if (sourceComparison !== 'unchanged' && sourceComparison !== 'portable') {
    throw new Error('release source comparison mode is invalid')
  }
  checkedAbsoluteRegularFile(gitPath, 'pinned Git executable', 256 * 1024 * 1024)
  if (/\.(?:cmd|bat|ps1|js)$/i.test(gitPath)) throw new Error('the pinned Git tool cannot be a script shim')
  return {
    async releaseSnapshot(releaseTag, releaseCommit) {
      if (!RELEASE_TAG.test(String(releaseTag || ''))) throw new Error('release tag is not canonical')
      if (!COMMIT.test(String(releaseCommit || ''))) throw new Error('release commit is not canonical')
      const normalizedCommit = releaseCommit.toLowerCase()
      const baseline = await readReleaseSourceFreeze({
        input: frozenSourcePath,
        expectedSha256: frozenSourceSha256
      })
      const current = await captureReleaseSourceFreeze({
        projectRoot,
        gitPath,
        releaseTag,
        releaseCommit: normalizedCommit,
        releaseTree
      })
      if (sourceComparison === 'portable') {
        assertReleaseSourceFreezePortableEquivalent(baseline, current)
      } else {
        assertReleaseSourceFreezeUnchanged(baseline, current)
      }
      return baseline
    }
  }
}

function checkedSourceSnapshot(snapshot, expectedCommit, label = 'release source snapshot', expectedTag) {
  if (!isPlainObject(snapshot)) throw new Error(`${label} must be an object`)
  assertReleaseSourceFreezeUnchanged(snapshot, structuredClone(snapshot))
  const binding = snapshot.sourceSnapshot?.git
  if (
    binding?.expectedCommit !== expectedCommit ||
    binding?.headCommit !== expectedCommit ||
    binding?.tagCommit !== expectedCommit ||
    !COMMIT.test(String(binding?.expectedTree || '')) ||
    binding?.headTree !== binding?.expectedTree ||
    (expectedTag !== undefined && binding?.expectedTag !== expectedTag)
  ) {
    throw new Error(`${label} commit/tag/tree identity is invalid`)
  }
  return canonicalValue(snapshot)
}

async function verifyFrozenSourceInputs(_projectRoot, sourceSnapshot, expectedCommit, label, expectedTag) {
  return checkedSourceSnapshot(sourceSnapshot, expectedCommit, label, expectedTag)
}

function sameSourceSnapshot(left, right) {
  return JSON.stringify(left) === JSON.stringify(right)
}

function sourceSnapshotCommit(value) {
  return value?.sourceSnapshot?.git?.expectedCommit
}

function checkedIdentity({ releaseTag, releaseCommit, runId, desktopVersion }) {
  const match = RELEASE_TAG.exec(String(releaseTag || ''))
  if (!match || releaseTag !== `v${desktopVersion}`) {
    throw new Error('release evidence tag must exactly match the desktop component version')
  }
  if (!COMMIT.test(String(releaseCommit || ''))) {
    throw new Error('release evidence commit must be a canonical full object id')
  }
  if (!RUN_ID.test(String(runId || ''))) {
    throw new Error('release evidence run id must be a canonical positive decimal id')
  }
}

function readComponentIdentity(projectRoot) {
  const desktopPackage = JSON.parse(readFileSync(join(projectRoot, 'desktop', 'package.json'), 'utf8'))
  const pyproject = readFileSync(join(projectRoot, 'pyproject.toml'), 'utf8')
  const sectionMatch = /^\[project\]\s*$/m.exec(pyproject)
  const afterHeader = sectionMatch ? pyproject.slice(sectionMatch.index + sectionMatch[0].length) : ''
  const nextSection = /^\[[^\]]+\]\s*$/m.exec(afterHeader)
  const projectSection = nextSection ? afterHeader.slice(0, nextSection.index) : afterHeader
  const engineName = /^name\s*=\s*"([^"]+)"\s*$/m.exec(projectSection)?.[1]
  const engineVersion = /^version\s*=\s*"([^"]+)"\s*$/m.exec(projectSection)?.[1]
  if (
    typeof desktopPackage.name !== 'string' ||
    typeof desktopPackage.version !== 'string' ||
    !engineName ||
    !engineVersion
  ) {
    throw new Error('desktop and engine component identities must be explicit')
  }
  return {
    desktop: { name: desktopPackage.name, version: desktopPackage.version },
    engine: { name: engineName, version: engineVersion }
  }
}

function normalizedPackageName(name, ecosystem) {
  if (typeof name !== 'string' || name !== name.trim() || !name) return ''
  const lowered = name.toLowerCase()
  return ecosystem === 'pypi' ? lowered.replace(/[-_.]+/g, '-') : lowered
}

function packagePurl(ecosystem, name, version) {
  const normalizedName = normalizedPackageName(name, ecosystem)
  if (!normalizedName || typeof version !== 'string' || version !== version.trim() || !version) return ''
  if (ecosystem === 'npm' && normalizedName.startsWith('@')) {
    const match = /^@([^/]+)\/([^/]+)$/.exec(normalizedName)
    if (!match) return ''
    return `pkg:npm/%40${encodeURIComponent(match[1])}/${encodeURIComponent(match[2])}@${encodeURIComponent(version)}`
  }
  return `pkg:${ecosystem}/${encodeURIComponent(normalizedName)}@${encodeURIComponent(version)}`
}

function npmNameFromLockPath(path, item) {
  if (typeof item?.name === 'string' && item.name) return item.name
  const marker = 'node_modules/'
  const offset = path.lastIndexOf(marker)
  if (offset < 0) return ''
  const tail = path.slice(offset + marker.length)
  const parts = tail.split('/')
  return tail.startsWith('@') ? parts.slice(0, 2).join('/') : parts[0]
}

function readLockedPackageSets(projectRoot) {
  const packageLock = JSON.parse(readFileSync(join(projectRoot, 'desktop', 'package-lock.json'), 'utf8'))
  if (packageLock?.lockfileVersion !== 3 || !isPlainObject(packageLock.packages)) {
    throw new Error('desktop/package-lock.json must be a lockfileVersion 3 package map')
  }
  const npmPackages = new Map()
  const npmEntries = Object.entries(packageLock.packages)
  for (const [path, item] of npmEntries) {
    if (!path || item?.link === true) continue
    if (!isPlainObject(item) || typeof item.version !== 'string' || !item.version) {
      throw new Error(`desktop/package-lock.json contains an invalid package entry: ${path}`)
    }
    const name = normalizedPackageName(npmNameFromLockPath(path, item), 'npm')
    const purl = packagePurl('npm', name, item.version)
    if (!name || !purl) throw new Error(`desktop/package-lock.json package identity is invalid: ${path}`)
    npmPackages.set(purl, { name, version: item.version, purl })
  }
  if (npmPackages.size === 0) throw new Error('desktop/package-lock.json has no locked packages')

  const dependencyCounts = {
    prod: npmEntries.filter(([, item]) => item?.dev !== true).length,
    dev: npmEntries.filter(([, item]) => item?.dev === true).length,
    optional: npmEntries.filter(([, item]) => item?.optional === true).length,
    peer: npmEntries.filter(([, item]) => item?.peer === true).length,
    peerOptional: npmEntries.filter(([, item]) => item?.peer === true && item?.optional === true).length,
    total: npmEntries.filter(([path, item]) => path && item?.link !== true).length
  }

  const uvLock = readFileSync(join(projectRoot, 'uv.lock'), 'utf8')
  if (!/^version = 1\s*$/m.test(uvLock)) throw new Error('uv.lock schema is invalid')
  const pythonPackages = new Map()
  for (const { name, version } of selectedPythonPackagesFromUvLock(uvLock, { projectRoot })) {
    const normalizedName = normalizedPackageName(name, 'pypi')
    const purl = packagePurl('pypi', normalizedName, version)
    if (!normalizedName || !purl) throw new Error('uv.lock contains an invalid registry package identity')
    if (pythonPackages.has(purl)) throw new Error(`uv.lock contains a duplicate selected registry package ${purl}`)
    pythonPackages.set(purl, { name: normalizedName, version, purl })
  }
  if (pythonPackages.size === 0) throw new Error('uv.lock has no release-selected registry packages')
  return { npmPackages, npmAuditDependencyCounts: dependencyCounts, pythonPackages }
}

function validateSbom(sbom, label, ecosystem, expectedPackages, expectedSetLabel = 'locked package set') {
  if (
    !isPlainObject(sbom) ||
    sbom.bomFormat !== 'CycloneDX' ||
    sbom.specVersion !== '1.5' ||
    !Number.isSafeInteger(sbom.version) ||
    sbom.version < 1 ||
    !Array.isArray(sbom.components) ||
    sbom.components.length === 0
  ) {
    throw new Error(`${label} must be a non-empty CycloneDX 1.5 document`)
  }
  const packages = new Map()
  const bomRefs = new Set()
  for (const component of sbom.components) {
    if (!isPlainObject(component) || component.type !== 'library') {
      throw new Error(`${label} contains a non-library component`)
    }
    const name = normalizedPackageName(component.name, ecosystem)
    const version = component.version
    const bomRef = component['bom-ref']
    const expectedPurl = packagePurl(ecosystem, name, version)
    if (!name || !expectedPurl) throw new Error(`${label} contains an unversioned component`)
    if (typeof bomRef !== 'string' || bomRef !== bomRef.trim() || !bomRef || bomRefs.has(bomRef)) {
      throw new Error(`${label} contains a missing or duplicate bom-ref`)
    }
    if (component.purl !== expectedPurl) {
      throw new Error(`${label} component purl does not match the ${ecosystem} ecosystem identity`)
    }
    if (packages.has(expectedPurl)) throw new Error(`${label} contains a duplicate component ${expectedPurl}`)
    bomRefs.add(bomRef)
    packages.set(expectedPurl, { name, version, purl: expectedPurl })
  }
  if (
    !(expectedPackages instanceof Map) ||
    packages.size !== expectedPackages.size ||
    [...expectedPackages.keys()].some((purl) => !packages.has(purl))
  ) {
    throw new Error(`${label} does not exactly cover its ${expectedSetLabel}`)
  }
  if (sbom.dependencies !== undefined) {
    if (!Array.isArray(sbom.dependencies)) throw new Error(`${label} dependencies must be an array`)
    const allowedRefs = new Set(bomRefs)
    const rootRef = sbom.metadata?.component?.['bom-ref']
    if (typeof rootRef === 'string' && rootRef) allowedRefs.add(rootRef)
    const dependencyRefs = new Set()
    for (const dependency of sbom.dependencies) {
      if (
        !isPlainObject(dependency) ||
        typeof dependency.ref !== 'string' ||
        !allowedRefs.has(dependency.ref) ||
        dependencyRefs.has(dependency.ref) ||
        !Array.isArray(dependency.dependsOn) ||
        dependency.dependsOn.some((ref) => typeof ref !== 'string' || !allowedRefs.has(ref))
      ) {
        throw new Error(`${label} contains an invalid dependency bom-ref closure`)
      }
      dependencyRefs.add(dependency.ref)
    }
  }
  return packages
}

function normalizedSbom(sbom) {
  const normalized = canonicalValue(sbom)
  delete normalized.serialNumber
  if (normalized.metadata && typeof normalized.metadata === 'object' && !Array.isArray(normalized.metadata)) {
    delete normalized.metadata.timestamp
  }
  if (Array.isArray(normalized.components)) {
    normalized.components.sort((left, right) => {
      const leftKey = `${left?.purl || ''}\0${left?.name || ''}\0${left?.version || ''}`
      const rightKey = `${right?.purl || ''}\0${right?.name || ''}\0${right?.version || ''}`
      return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0
    })
  }
  if (Array.isArray(normalized.dependencies)) {
    normalized.dependencies = normalized.dependencies
      .map((item) => ({ ...item, dependsOn: Array.isArray(item.dependsOn) ? [...item.dependsOn].sort() : item.dependsOn }))
      .sort((left, right) => String(left?.ref || '').localeCompare(String(right?.ref || ''), 'en'))
  }
  return canonicalValue(normalized)
}

function normalizedReports(reports) {
  const normalized = canonicalValue(reports)
  normalized.npmSbom = normalizedSbom(normalized.npmSbom)
  normalized.pythonSbom = normalizedSbom(normalized.pythonSbom)
  if (Array.isArray(normalized.pythonAudit?.packages)) {
    normalized.pythonAudit.packages.sort((left, right) => {
      const leftKey = `${left?.name || ''}\0${left?.version || ''}`
      const rightKey = `${right?.name || ''}\0${right?.version || ''}`
      return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0
    })
  }
  return canonicalValue(normalized)
}

function validateReports(reports, lockedPackages) {
  if (!isPlainObject(reports)) {
    throw new Error('release evidence reports are required')
  }
  if (!lockedPackages) throw new Error('release evidence locked package set is required')
  // Reject disallowed packages and restrictive evaluation grants before the
  // generic exact-set error so the evidence records the actionable blocker.
  assertPythonReleaseSbomPolicy(reports.pythonSbom)
  const npmPackages = validateSbom(
    reports.npmSbom,
    'npm SBOM',
    'npm',
    lockedPackages.npmPackages
  )
  const pythonPackages = validateSbom(
    reports.pythonSbom,
    'Python SBOM',
    'pypi',
    lockedPackages.pythonPackages,
    'release-selected locked package set'
  )
  const npmAudit = reports.npmAudit
  const vulnerabilityCounts = npmAudit?.metadata?.vulnerabilities
  const dependencyCounts = npmAudit?.metadata?.dependencies
  const severityKeys = ['info', 'low', 'moderate', 'high', 'critical', 'total']
  const dependencyKeys = ['prod', 'dev', 'optional', 'peer', 'peerOptional', 'total']
  if (
    !isPlainObject(npmAudit) ||
    npmAudit?.auditReportVersion !== 2 ||
    !isPlainObject(npmAudit.vulnerabilities) ||
    Object.keys(npmAudit.vulnerabilities).length !== 0 ||
    !isPlainObject(npmAudit.metadata) ||
    !isPlainObject(vulnerabilityCounts) ||
    Object.keys(vulnerabilityCounts).sort().join(',') !== severityKeys.sort().join(',') ||
    severityKeys.some((key) => !Number.isSafeInteger(vulnerabilityCounts[key]) || vulnerabilityCounts[key] !== 0) ||
    !isPlainObject(dependencyCounts) ||
    Object.keys(dependencyCounts).sort().join(',') !== dependencyKeys.sort().join(',') ||
    dependencyKeys.some((key) =>
      !Number.isSafeInteger(dependencyCounts[key]) ||
      dependencyCounts[key] < 0 ||
      dependencyCounts[key] !== lockedPackages.npmAuditDependencyCounts[key]
    )
  ) {
    throw new Error('npm vulnerability audit is missing, invalid, or non-zero')
  }
  const pythonAudit = reports.pythonAudit
  if (
    pythonAudit?.schema !== 1 ||
    pythonAudit?.ecosystem !== 'PyPI' ||
    pythonAudit?.source !== 'https://api.osv.dev/v1/querybatch' ||
    pythonAudit?.vulnerabilityCount !== 0 ||
    !Array.isArray(pythonAudit.packages)
  ) {
    throw new Error('Python vulnerability audit is missing, invalid, or non-zero')
  }
  const audited = new Map()
  for (const item of pythonAudit.packages) {
    if (!isPlainObject(item)) throw new Error('Python vulnerability audit contains an invalid package')
    const name = normalizedPackageName(item.name, 'pypi')
    const version = item.version
    if (!name || !version || !Array.isArray(item.vulnerabilities) || item.vulnerabilities.length !== 0) {
      throw new Error('Python vulnerability audit contains an invalid or vulnerable package')
    }
    const purl = packagePurl('pypi', name, version)
    if (audited.has(purl)) throw new Error('Python vulnerability audit contains a duplicate package')
    audited.set(purl, true)
  }
  if (
    audited.size !== pythonPackages.size ||
    [...pythonPackages.keys()].some((key) => !audited.has(key))
  ) {
    throw new Error('Python vulnerability audit does not exactly cover the Python SBOM')
  }
  return { npmPackages, pythonPackages }
}

async function checkedToolVersions(toolVersions) {
  const expected = ['git', 'node', 'npm', 'pyinstallerArchiveViewer', 'python', 'uv']
  if (
    !toolVersions ||
    typeof toolVersions !== 'object' ||
    Array.isArray(toolVersions) ||
    Object.keys(toolVersions).sort().join(',') !== expected.sort().join(',')
  ) {
    throw new Error('release evidence tool descriptors are not canonical')
  }
  for (const name of expected) {
    const descriptor = toolVersions[name]
    exactKeys(
      descriptor,
      name === 'pyinstallerArchiveViewer'
        ? [
            'implementationFileCount',
            'implementationSha256',
            'name',
            'path',
            'pythonPath',
            'pythonSha256',
            'pythonSize',
            'recordSha256',
            'sha256',
            'size',
            'version'
          ]
        : ['name', 'path', 'sha256', 'size', 'version'],
      `release evidence ${name} tool`
    )
    if (
      descriptor.name !== name ||
      !isAbsolute(descriptor.path) ||
      !SHA256.test(String(descriptor.sha256 || '')) ||
      !Number.isSafeInteger(descriptor.size) ||
      descriptor.size <= 0
    ) {
      throw new Error(`release evidence ${name} descriptor is invalid`)
    }
    checkedAbsoluteRegularFile(descriptor.path, `release evidence ${name} tool`, 256 * 1024 * 1024)
    const actual = await toolFileDescriptor(descriptor.path, name)
    if (actual.size !== descriptor.size || actual.sha256 !== descriptor.sha256) {
      throw new Error(`release evidence ${name} tool bytes drifted`)
    }
    if (name === 'pyinstallerArchiveViewer') {
      const actualViewer = await pyinstallerArchiveViewerDescriptor(defaultProjectRoot)
      if (JSON.stringify(canonicalValue(actualViewer)) !== JSON.stringify(canonicalValue(descriptor))) {
        throw new Error('release evidence PyInstaller implementation closure drifted')
      }
    }
    if (!/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+|\.windows\.\d+)?$/.test(String(descriptor.version || ''))) {
      throw new Error(`release evidence ${name} version is invalid`)
    }
    if (name !== 'git' && descriptor.version !== RELEASE_TOOL_VERSIONS[name]) {
      throw new Error(`${name} version does not match pinned release toolchain`)
    }
    if (name === 'npm' ? !descriptor.path.toLowerCase().endsWith('npm-cli.js') : /\.(?:cmd|bat|ps1|js)$/i.test(descriptor.path)) {
      throw new Error(`release evidence ${name} tool uses a forbidden script shim`)
    }
    if (
      name === 'pyinstallerArchiveViewer' &&
      descriptor.path.toLowerCase() !== pyinstallerArchiveViewerPath(defaultProjectRoot).toLowerCase()
    ) {
      throw new Error('release evidence PyInstaller archive viewer is outside the release-selected environment')
    }
    if (name === 'node' && resolve(process.execPath).toLowerCase() !== descriptor.path.toLowerCase()) {
      throw new Error('release evidence Node path does not match the verifying process')
    }
  }
  return canonicalValue(toolVersions)
}

function checkedPythonSelection(value) {
  if (JSON.stringify(canonicalValue(value)) !== JSON.stringify(canonicalValue(PYTHON_RELEASE_SELECTION))) {
    throw new Error('release evidence Python selection does not match the build selector')
  }
  return canonicalValue(value)
}

export async function collectReleaseEvidenceReports({
  projectRoot = defaultProjectRoot,
  commandClient,
  osvClient
}) {
  if (
    !commandClient ||
    typeof commandClient.toolVersions !== 'function' ||
    typeof commandClient.npmAudit !== 'function' ||
    typeof commandClient.npmSbom !== 'function' ||
    typeof commandClient.pythonSbom !== 'function'
  ) {
    throw new Error('release evidence command client is incomplete')
  }
  if (!osvClient || typeof osvClient.auditPython !== 'function') {
    throw new Error('release evidence OSV client is incomplete')
  }
  const [toolVersions, npmAudit, npmSbom, pythonSbom] = await Promise.all([
    commandClient.toolVersions(),
    commandClient.npmAudit(),
    commandClient.npmSbom(),
    commandClient.pythonSbom()
  ])
  const lockedPackages = readLockedPackageSets(resolve(projectRoot))
  const pythonPackages = [
    ...validateSbom(pythonSbom, 'Python SBOM', 'pypi', lockedPackages.pythonPackages).values()
  ].map(({ name, version }) => ({ name, version }))
  const pythonAudit = await osvClient.auditPython(pythonPackages)
  const reports = normalizedReports({ npmAudit, npmSbom, pythonAudit, pythonSbom })
  validateReports(reports, lockedPackages)
  return { reports, toolVersions: await checkedToolVersions(toolVersions) }
}

export async function reAuditReleaseEvidence({
  projectRoot = defaultProjectRoot,
  releaseRoot = defaultReleaseRoot,
  commandClient,
  osvClient
} = {}) {
  projectRoot = resolve(projectRoot)
  releaseRoot = resolve(releaseRoot)
  const lockedPackages = readLockedPackageSets(projectRoot)
  const frozenReports = {
    npmAudit: parseCanonicalJson(join(releaseRoot, 'NPM_AUDIT.json'), 'NPM_AUDIT.json'),
    npmSbom: parseCanonicalJson(join(releaseRoot, 'NPM_SBOM.cdx.json'), 'NPM_SBOM.cdx.json'),
    pythonAudit: parseCanonicalJson(join(releaseRoot, 'PYTHON_AUDIT.json'), 'PYTHON_AUDIT.json'),
    pythonSbom: parseCanonicalJson(join(releaseRoot, 'PYTHON_SBOM.cdx.json'), 'PYTHON_SBOM.cdx.json')
  }
  validateReports(frozenReports, lockedPackages)
  commandClient ||= createReleaseCommandClient({ projectRoot })
  osvClient ||= createOsvAuditClient()
  const fresh = await collectReleaseEvidenceReports({ projectRoot, commandClient, osvClient })
  for (const name of ['npmSbom', 'pythonSbom']) {
    if (JSON.stringify(fresh.reports[name]) !== JSON.stringify(frozenReports[name])) {
      throw new Error(`fresh publisher ${name} does not match the finalized locked dependency graph`)
    }
  }
  return fresh
}

export function createOsvAuditClient({ fetchImpl = fetch, batchSize = 100 } = {}) {
  if (typeof fetchImpl !== 'function') throw new Error('OSV fetch implementation is required')
  if (!Number.isSafeInteger(batchSize) || batchSize < 1 || batchSize > 1000) {
    throw new Error('OSV batch size is invalid')
  }
  return {
    async auditPython(packages) {
      if (!Array.isArray(packages) || packages.length === 0) {
        throw new Error('OSV Python audit requires a non-empty locked package set')
      }
      const checked = packages.map((item) => {
        const name = String(item?.name || '').trim().toLowerCase()
        const version = String(item?.version || '').trim()
        if (!name || !version) throw new Error('OSV Python audit package is unversioned')
        return { name, version }
      })
      if (new Set(checked.map(({ name, version }) => `${name}@${version}`)).size !== checked.length) {
        throw new Error('OSV Python audit package set contains duplicates')
      }
      const audited = []
      let vulnerabilityCount = 0
      for (let offset = 0; offset < checked.length; offset += batchSize) {
        const batch = checked.slice(offset, offset + batchSize)
        const response = await fetchImpl('https://api.osv.dev/v1/querybatch', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            queries: batch.map(({ name, version }) => ({
              package: { ecosystem: 'PyPI', name },
              version
            }))
          }),
          signal: AbortSignal.timeout(120_000)
        })
        if (!response?.ok) {
          throw new Error(`OSV Python audit failed HTTP ${response?.status || 0}`)
        }
        const declared = Number(response.headers?.get?.('content-length') || 0)
        if (declared > 64 * 1024 * 1024) throw new Error('OSV Python audit response is oversized')
        const bytes = Buffer.from(await response.arrayBuffer())
        if (!bytes.length || bytes.length > 64 * 1024 * 1024) {
          throw new Error('OSV Python audit response is empty or oversized')
        }
        let document
        try {
          document = JSON.parse(bytes.toString('utf8'))
        } catch {
          throw new Error('OSV Python audit response is not valid JSON')
        }
        if (!Array.isArray(document?.results) || document.results.length !== batch.length) {
          throw new Error('OSV Python audit response does not cover the requested batch')
        }
        for (let index = 0; index < batch.length; index += 1) {
          const result = document.results[index]
          if (!isPlainObject(result)) throw new Error('OSV Python audit result is invalid')
          const rawVulnerabilities = Object.hasOwn(result, 'vulns') ? result.vulns : []
          if (!Array.isArray(rawVulnerabilities)) {
            throw new Error('OSV Python audit vulnerability list is invalid')
          }
          const vulnerabilities = rawVulnerabilities.map((item) => {
            const id = String(item?.id || '')
            const modified = String(item?.modified || '')
            if (!id || !modified) throw new Error('OSV Python audit vulnerability identity is incomplete')
            return canonicalValue({
              aliases: Array.isArray(item.aliases) ? [...new Set(item.aliases.map(String))].sort() : [],
              id,
              modified
            })
          })
          vulnerabilities.sort((left, right) => left.id.localeCompare(right.id, 'en'))
          vulnerabilityCount += vulnerabilities.length
          audited.push({ ...batch[index], vulnerabilities })
        }
      }
      return canonicalValue({
        schema: 1,
        source: 'https://api.osv.dev/v1/querybatch',
        ecosystem: 'PyPI',
        packages: audited,
        vulnerabilityCount
      })
    }
  }
}

async function fileDescriptor(path, name, maxBytes = 64 * 1024 * 1024) {
  const info = checkedRegularFile(path, name, maxBytes)
  return { name, sha256: await sha256File(path), size: info.size }
}

export async function writeReleaseEvidenceBundle({
  projectRoot = defaultProjectRoot,
  releaseRoot = defaultReleaseRoot,
  variant,
  releaseTier,
  releaseTag,
  releaseCommit,
  runId,
  toolVersions,
  reports,
  sourceSnapshot,
  sourceControlClient
}) {
  projectRoot = resolve(projectRoot)
  releaseRoot = resolve(releaseRoot)
  const components = readComponentIdentity(projectRoot)
  checkedIdentity({ releaseTag, releaseCommit, runId, desktopVersion: components.desktop.version })
  reports = normalizedReports(reports)
  validateReports(reports, readLockedPackageSets(projectRoot))
  toolVersions = await checkedToolVersions(toolVersions)
  sourceSnapshot = await verifyFrozenSourceInputs(
    projectRoot,
    sourceSnapshot,
    releaseCommit,
    'release evidence source',
    releaseTag
  )
  const expected = await verifyFinalReleaseOutput({
    variant,
    releaseTier,
    releaseRoot,
    expectedParent: join(projectRoot, 'desktop'),
    platform: 'win32',
    version: components.desktop.version
  })
  await writeNativeCycloneDxSbom({
    manifestPath: join(releaseRoot, 'WIN_UNPACKED_MANIFEST.json'),
    output: join(releaseRoot, 'NATIVE_SBOM.cdx.json'),
    unpackedRoot: join(releaseRoot, 'win-unpacked')
  })

  const reportEntries = []
  for (const [key, name, mediaType] of REPORT_NAMES) {
    const bytes = canonicalBytes(reports[key])
    await writeFile(join(releaseRoot, name), bytes, { flag: 'wx' })
    reportEntries.push({ mediaType, name, sha256: createHash('sha256').update(bytes).digest('hex'), size: bytes.length })
  }
  const releaseNames = [
    expected.artifact,
    expected.blockmap,
    expected.channel,
    'WIN_UNPACKED_MANIFEST.json',
    ...(expected.updateEnvelope ? [expected.updateEnvelope] : []),
    'NATIVE_SBOM.cdx.json',
    'SHA256SUMS'
  ]
  const releaseFiles = []
  for (const name of releaseNames) releaseFiles.push(await fileDescriptor(join(releaseRoot, name), name))
  const manifest = canonicalValue({
    identity: {
      components,
      releaseCommit,
      releaseTag,
      releaseTier,
      runId: String(runId),
      variant
    },
    pythonSelection: checkedPythonSelection(PYTHON_RELEASE_SELECTION),
    releaseFiles,
    reports: reportEntries,
    schema: 3,
    source: sourceSnapshot,
    tools: toolVersions
  })
  await writeFile(join(releaseRoot, 'RELEASE_EVIDENCE_MANIFEST.json'), canonicalBytes(manifest), { flag: 'wx' })
  await verifyReleaseEvidence({
    projectRoot,
    releaseRoot,
    variant,
    releaseTier,
    expectedTag: releaseTag,
    expectedCommit: releaseCommit,
    expectedRunId: runId,
    sourceControlClient
  })
  return manifest
}

function exactDescriptorSet(items, names, label, fields = ['name', 'sha256', 'size']) {
  if (!Array.isArray(items) || items.length !== names.length) throw new Error(`${label} is not a closed set`)
  for (let index = 0; index < names.length; index += 1) {
    const item = items[index]
    exactKeys(item, fields, `${label} entry ${index + 1}`)
    if (
      item?.name !== names[index] ||
      !Number.isSafeInteger(item.size) ||
      item.size <= 0 ||
      !SHA256.test(String(item.sha256 || ''))
    ) {
      throw new Error(`${label} entry ${index + 1} is invalid or out of order`)
    }
  }
}

export async function verifyReleaseEvidence({
  projectRoot = defaultProjectRoot,
  releaseRoot = defaultReleaseRoot,
  variant,
  releaseTier,
  expectedTag,
  expectedCommit,
  expectedRunId,
  sourceControlClient,
  sourceComparison = 'unchanged'
}) {
  projectRoot = resolve(projectRoot)
  releaseRoot = resolve(releaseRoot)
  const components = readComponentIdentity(projectRoot)
  checkedIdentity({
    releaseTag: expectedTag,
    releaseCommit: expectedCommit,
    runId: expectedRunId,
    desktopVersion: components.desktop.version
  })
  const sourceBefore = await verifyRequestedSourceIdentity({
    projectRoot,
    releaseTag: expectedTag,
    releaseCommit: expectedCommit,
    sourceControlClient,
    sourceComparison
  })
  const expected = await verifyFinalReleaseOutput({
    variant,
    releaseTier,
    releaseRoot,
    expectedParent: join(projectRoot, 'desktop'),
    platform: 'win32',
    version: components.desktop.version,
    requireEvidence: true
  })
  const manifest = parseCanonicalJson(
    join(releaseRoot, 'RELEASE_EVIDENCE_MANIFEST.json'),
    'release evidence manifest',
    128 * 1024 * 1024
  )
  exactKeys(
    manifest,
    ['identity', 'pythonSelection', 'releaseFiles', 'reports', 'schema', 'source', 'tools'],
    'release evidence manifest'
  )
  exactKeys(
    manifest.identity,
    ['components', 'releaseCommit', 'releaseTag', 'releaseTier', 'runId', 'variant'],
    'release evidence identity'
  )
  exactKeys(manifest.identity.components, ['desktop', 'engine'], 'release evidence components')
  exactKeys(manifest.identity.components.desktop, ['name', 'version'], 'desktop component identity')
  exactKeys(manifest.identity.components.engine, ['name', 'version'], 'engine component identity')
  if (
    manifest?.schema !== 3 ||
    manifest.identity?.releaseTag !== expectedTag ||
    manifest.identity?.releaseCommit !== expectedCommit ||
    manifest.identity?.runId !== String(expectedRunId) ||
    manifest.identity?.releaseTier !== releaseTier ||
    manifest.identity?.variant !== variant ||
    JSON.stringify(manifest.identity?.components) !== JSON.stringify(components)
  ) {
    throw new Error('release evidence identity does not match the requested run/commit/tag/components')
  }
  checkedPythonSelection(manifest.pythonSelection)
  const manifestSource = await verifyFrozenSourceInputs(
    projectRoot,
    manifest.source,
    expectedCommit,
    'release evidence source',
    expectedTag
  )
  if (!sameSourceSnapshot(manifestSource, sourceBefore)) {
    throw new Error('release evidence source does not match the requested commit tree/blob snapshot')
  }
  await checkedToolVersions(manifest.tools)
  const reportNames = REPORT_NAMES.map(([, name]) => name)
  exactDescriptorSet(
    manifest.reports,
    reportNames,
    'release evidence reports',
    ['mediaType', 'name', 'sha256', 'size']
  )
  for (const item of manifest.reports) {
    const actual = await fileDescriptor(join(releaseRoot, item.name), item.name)
    if (actual.size !== item.size || actual.sha256 !== item.sha256) {
      throw new Error(`release evidence report hash drifted: ${item.name}`)
    }
    parseCanonicalJson(join(releaseRoot, item.name), item.name)
  }
  const releaseNames = [
    expected.artifact,
    expected.blockmap,
    expected.channel,
    'WIN_UNPACKED_MANIFEST.json',
    ...(expected.updateEnvelope ? [expected.updateEnvelope] : []),
    'NATIVE_SBOM.cdx.json',
    'SHA256SUMS'
  ]
  exactDescriptorSet(manifest.releaseFiles, releaseNames, 'release evidence release files')
  for (const item of manifest.releaseFiles) {
    const actual = await fileDescriptor(join(releaseRoot, item.name), item.name)
    if (actual.size !== item.size || actual.sha256 !== item.sha256) {
      throw new Error(`release evidence release file hash drifted: ${item.name}`)
    }
  }
  await verifyNativeCycloneDxSbom({
    manifestPath: join(releaseRoot, 'WIN_UNPACKED_MANIFEST.json'),
    sbomPath: join(releaseRoot, 'NATIVE_SBOM.cdx.json'),
    unpackedRoot: join(releaseRoot, 'win-unpacked')
  })
  const parsedReports = {
    npmAudit: parseCanonicalJson(join(releaseRoot, 'NPM_AUDIT.json'), 'NPM_AUDIT.json'),
    npmSbom: parseCanonicalJson(join(releaseRoot, 'NPM_SBOM.cdx.json'), 'NPM_SBOM.cdx.json'),
    pythonAudit: parseCanonicalJson(join(releaseRoot, 'PYTHON_AUDIT.json'), 'PYTHON_AUDIT.json'),
    pythonSbom: parseCanonicalJson(join(releaseRoot, 'PYTHON_SBOM.cdx.json'), 'PYTHON_SBOM.cdx.json')
  }
  validateReports(parsedReports, readLockedPackageSets(projectRoot))
  if (JSON.stringify(normalizedReports(parsedReports)) !== JSON.stringify(parsedReports)) {
    throw new Error('release evidence reports retain non-reproducible or non-canonical fields')
  }
  const sourceAfter = await verifyRequestedSourceIdentity({
    projectRoot,
    releaseTag: expectedTag,
    releaseCommit: expectedCommit,
    sourceControlClient,
    sourceComparison
  })
  if (!sameSourceSnapshot(sourceBefore, sourceAfter)) {
    throw new Error('release tag/HEAD/tree/blob identity drifted during evidence verification')
  }
  return manifest
}

async function verifyRequestedSourceIdentity({
  projectRoot,
  releaseTag,
  releaseCommit,
  sourceControlClient,
  sourceComparison = 'unchanged'
}) {
  const normalizedCommit = String(releaseCommit || '').toLowerCase()
  if (!COMMIT.test(normalizedCommit)) throw new Error('requested release commit is not canonical')
  sourceControlClient ||= createSourceControlClient({ projectRoot, sourceComparison })
  if (typeof sourceControlClient.releaseSnapshot !== 'function') {
    throw new Error('release source-control snapshot client is incomplete')
  }
  const sourceIdentity = await sourceControlClient.releaseSnapshot(releaseTag, normalizedCommit)
  return await verifyFrozenSourceInputs(
    projectRoot,
    sourceIdentity,
    normalizedCommit,
    'requested release source',
    releaseTag
  )
}

export async function prepareReleaseEvidence({
  projectRoot = defaultProjectRoot,
  output,
  variant,
  releaseTier,
  releaseTag,
  releaseCommit,
  runId,
  commandClient,
  osvClient,
  sourceControlClient
}) {
  projectRoot = resolve(projectRoot)
  output = resolve(output)
  if (variant !== 'lean' && variant !== 'full') throw new Error('prepared release evidence variant is invalid')
  if (releaseTier !== 'early-access' && releaseTier !== 'production') {
    throw new Error('prepared release evidence tier is invalid')
  }
  const components = readComponentIdentity(projectRoot)
  checkedIdentity({ releaseTag, releaseCommit, runId, desktopVersion: components.desktop.version })
  const sourceBefore = await verifyRequestedSourceIdentity({
    projectRoot,
    releaseTag,
    releaseCommit,
    sourceControlClient
  })
  commandClient ||= createReleaseCommandClient({ projectRoot })
  osvClient ||= createOsvAuditClient()
  const collected = await collectReleaseEvidenceReports({ projectRoot, commandClient, osvClient })
  const sourceAfter = await verifyRequestedSourceIdentity({
    projectRoot,
    releaseTag,
    releaseCommit,
    sourceControlClient
  })
  if (!sameSourceSnapshot(sourceBefore, sourceAfter)) {
    throw new Error('release source drifted while collecting prepared evidence')
  }
  const document = canonicalValue({
    identity: {
      components,
      releaseCommit: sourceSnapshotCommit(sourceAfter),
      releaseTag,
      releaseTier,
      runId: String(runId),
      variant
    },
    pythonSelection: checkedPythonSelection(PYTHON_RELEASE_SELECTION),
    reports: collected.reports,
    schema: 3,
    source: sourceAfter,
    tools: collected.toolVersions
  })
  await writeFile(output, canonicalBytes(document), { flag: 'wx' })
  return document
}

export async function finalizePreparedReleaseEvidence({
  projectRoot = defaultProjectRoot,
  releaseRoot = defaultReleaseRoot,
  input,
  variant,
  releaseTier,
  releaseTag,
  releaseCommit,
  runId,
  sourceControlClient
}) {
  projectRoot = resolve(projectRoot)
  releaseRoot = resolve(releaseRoot)
  const document = parseCanonicalJson(resolve(input), 'prepared release evidence', 256 * 1024 * 1024)
  exactKeys(
    document,
    ['identity', 'pythonSelection', 'reports', 'schema', 'source', 'tools'],
    'prepared release evidence'
  )
  exactKeys(
    document.identity,
    ['components', 'releaseCommit', 'releaseTag', 'releaseTier', 'runId', 'variant'],
    'prepared release evidence identity'
  )
  const components = readComponentIdentity(projectRoot)
  checkedIdentity({ releaseTag, releaseCommit, runId, desktopVersion: components.desktop.version })
  const sourceBefore = await verifyRequestedSourceIdentity({
    projectRoot,
    releaseTag,
    releaseCommit,
    sourceControlClient
  })
  if (
    document.schema !== 3 ||
    document.identity.releaseTag !== releaseTag ||
    document.identity.releaseCommit !== sourceSnapshotCommit(sourceBefore) ||
    document.identity.runId !== String(runId) ||
    document.identity.releaseTier !== releaseTier ||
    document.identity.variant !== variant ||
    JSON.stringify(document.identity.components) !== JSON.stringify(components)
  ) {
    throw new Error('prepared release evidence identity does not match the requested release')
  }
  checkedPythonSelection(document.pythonSelection)
  const preparedSource = await verifyFrozenSourceInputs(
    projectRoot,
    document.source,
    sourceSnapshotCommit(sourceBefore),
    'prepared release evidence source',
    releaseTag
  )
  if (!sameSourceSnapshot(preparedSource, sourceBefore)) {
    throw new Error('prepared release evidence source does not match the requested commit tree/blob snapshot')
  }
  const manifest = await writeReleaseEvidenceBundle({
    projectRoot,
    releaseRoot,
    variant,
    releaseTier,
    releaseTag,
    releaseCommit: sourceSnapshotCommit(sourceBefore),
    runId,
    toolVersions: document.tools,
    reports: document.reports,
    sourceSnapshot: sourceBefore,
    sourceControlClient
  })
  const sourceAfter = await verifyRequestedSourceIdentity({
    projectRoot,
    releaseTag,
    releaseCommit,
    sourceControlClient
  })
  if (!sameSourceSnapshot(sourceBefore, sourceAfter)) {
    throw new Error('release source drifted while finalizing prepared evidence')
  }
  return manifest
}

export async function generateReleaseEvidence({
  projectRoot = defaultProjectRoot,
  releaseRoot = defaultReleaseRoot,
  variant,
  releaseTier,
  releaseTag,
  releaseCommit,
  runId,
  commandClient,
  osvClient,
  sourceControlClient
}) {
  projectRoot = resolve(projectRoot)
  releaseRoot = resolve(releaseRoot)
  const sourceBefore = await verifyRequestedSourceIdentity({
    projectRoot,
    releaseTag,
    releaseCommit,
    sourceControlClient
  })
  commandClient ||= createReleaseCommandClient({ projectRoot })
  osvClient ||= createOsvAuditClient()
  const collected = await collectReleaseEvidenceReports({ projectRoot, commandClient, osvClient })
  const sourceAfter = await verifyRequestedSourceIdentity({
    projectRoot,
    releaseTag,
    releaseCommit,
    sourceControlClient
  })
  if (!sameSourceSnapshot(sourceBefore, sourceAfter)) {
    throw new Error('release source drifted while collecting release evidence')
  }
  return await writeReleaseEvidenceBundle({
    projectRoot,
    releaseRoot,
    variant,
    releaseTier,
    releaseTag,
    releaseCommit: sourceSnapshotCommit(sourceAfter),
    runId,
    toolVersions: collected.toolVersions,
    reports: collected.reports,
    sourceSnapshot: sourceAfter,
    sourceControlClient
  })
}

export async function materializeReleaseEvidenceSourceFreeze({
  projectRoot = defaultProjectRoot,
  releaseRoot = defaultReleaseRoot,
  output,
  variant,
  releaseTier,
  expectedTag,
  expectedCommit,
  expectedRunId
}) {
  projectRoot = resolve(projectRoot)
  releaseRoot = resolve(releaseRoot)
  expectedCommit = String(expectedCommit || '').toLowerCase()
  const components = readComponentIdentity(projectRoot)
  checkedIdentity({
    releaseTag: expectedTag,
    releaseCommit: expectedCommit,
    runId: expectedRunId,
    desktopVersion: components.desktop.version
  })
  const manifest = parseCanonicalJson(
    join(releaseRoot, 'RELEASE_EVIDENCE_MANIFEST.json'),
    'release evidence manifest source-freeze carrier',
    128 * 1024 * 1024
  )
  exactKeys(
    manifest,
    ['identity', 'pythonSelection', 'releaseFiles', 'reports', 'schema', 'source', 'tools'],
    'release evidence manifest source-freeze carrier'
  )
  exactKeys(
    manifest.identity,
    ['components', 'releaseCommit', 'releaseTag', 'releaseTier', 'runId', 'variant'],
    'release evidence source-freeze carrier identity'
  )
  if (
    manifest.schema !== 3 ||
    manifest.identity.releaseTag !== expectedTag ||
    manifest.identity.releaseCommit !== expectedCommit ||
    manifest.identity.runId !== String(expectedRunId) ||
    manifest.identity.releaseTier !== releaseTier ||
    manifest.identity.variant !== variant ||
    JSON.stringify(manifest.identity.components) !== JSON.stringify(components)
  ) {
    throw new Error('release evidence source-freeze carrier identity does not match the requested release')
  }
  const frozen = checkedSourceSnapshot(
    manifest.source,
    expectedCommit,
    'release evidence source-freeze carrier',
    expectedTag
  )
  return await writeReleaseSourceFreeze({ output, frozen })
}

async function main(argv) {
  const [operation, rawVariant, preparedPath] = argv
  const variant = rawVariant || process.env.DMX_VARIANT
  const releaseTier = process.env.NACHUAN_UPDATE_TIER || 'production'
  const expectedTag = process.env.NACHUAN_RELEASE_TAG
  const expectedCommit = String(process.env.NACHUAN_RELEASE_COMMIT || '').toLowerCase()
  const expectedRunId = process.env.NACHUAN_RELEASE_RUN_ID
  if (operation === 'materialize-source-freeze') {
    if (!preparedPath) throw new Error('release evidence source-freeze output path is required')
    const result = await materializeReleaseEvidenceSourceFreeze({
      output: preparedPath,
      variant,
      releaseTier,
      expectedTag,
      expectedCommit,
      expectedRunId
    })
    console.log(`[release-evidence] SOURCE_FREEZE_WRITTEN sha256=${result.sha256} size=${result.size}`)
    return
  }
  if (operation === 'prepare') {
    if (!preparedPath) throw new Error('prepared release evidence output path is required')
    const document = await prepareReleaseEvidence({
      output: preparedPath,
      variant,
      releaseTier,
      releaseTag: expectedTag,
      releaseCommit: expectedCommit,
      runId: expectedRunId
    })
    console.log(
      `[release-evidence] PREPARED tag=${document.identity.releaseTag} commit=${document.identity.releaseCommit} run=${document.identity.runId}`
    )
    return
  }
  if (operation === 'finalize-prepared') {
    if (!preparedPath) throw new Error('prepared release evidence input path is required')
    const manifest = await finalizePreparedReleaseEvidence({
      input: preparedPath,
      variant,
      releaseTier,
      releaseTag: expectedTag,
      releaseCommit: expectedCommit,
      runId: expectedRunId
    })
    console.log(
      `[release-evidence] FINALIZED tag=${manifest.identity.releaseTag} commit=${manifest.identity.releaseCommit} run=${manifest.identity.runId}`
    )
    return
  }
  if (operation === 'generate') {
    const manifest = await generateReleaseEvidence({
      variant,
      releaseTier,
      releaseTag: expectedTag,
      releaseCommit: expectedCommit,
      runId: expectedRunId
    })
    console.log(
      `[release-evidence] GENERATED tag=${manifest.identity.releaseTag} commit=${manifest.identity.releaseCommit} run=${manifest.identity.runId}`
    )
    return
  }
  if (operation === 'verify') {
    const manifest = await verifyReleaseEvidence({
      variant,
      releaseTier,
      expectedTag,
      expectedCommit,
      expectedRunId
    })
    console.log(
      `[release-evidence] VERIFIED tag=${manifest.identity.releaseTag} commit=${manifest.identity.releaseCommit} run=${manifest.identity.runId}`
    )
    return
  }
  if (operation === 'verify-portable') {
    const manifest = await verifyReleaseEvidence({
      variant,
      releaseTier,
      expectedTag,
      expectedCommit,
      expectedRunId,
      sourceComparison: 'portable'
    })
    console.log(
      `[release-evidence] VERIFIED_PORTABLE tag=${manifest.identity.releaseTag} commit=${manifest.identity.releaseCommit} run=${manifest.identity.runId}`
    )
    return
  }
  if (operation === 're-audit-portable') {
    const result = await reAuditReleaseEvidence()
    console.log(
      `[release-evidence] REAUDITED npm=${Object.keys(result.reports.npmAudit.vulnerabilities || {}).length} python=${result.reports.pythonAudit.vulnerabilityCount}`
    )
    return
  }
  throw new Error(
    'usage: release-evidence.mjs materialize-source-freeze|prepare|finalize-prepared|generate|verify|verify-portable|re-audit-portable <lean|full> [evidence-path.json]'
  )
}

if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  try {
    await main(process.argv.slice(2))
  } catch (error) {
    console.error(`[release-evidence] BLOCKED: ${error instanceof Error ? error.message : String(error)}`)
    process.exitCode = 1
  }
}
