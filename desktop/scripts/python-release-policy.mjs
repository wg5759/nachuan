import { execFile, spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { lstatSync, readFileSync, readdirSync, realpathSync } from 'node:fs'
import { dirname, isAbsolute, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { pythonMarkerEnvironment } from './license-evidence.mjs'

const scriptPath = fileURLToPath(import.meta.url)
const defaultProjectRoot = resolve(dirname(scriptPath), '..', '..')
const PROJECT_ROOT_TOKEN = '<project-root>'
export const PYINSTALLER_ARCHIVE_VIEWER_VERSION = '6.21.0'
const PYINSTALLER_WINDOWS_CLOSURE = Object.freeze({
  fileCount: 567,
  implementationSha256: 'b525a866c7010b67d6b4455d3431123116ba14ccbc794ac6a925faf1c71010bc',
  recordSha256: '819bbd6a6906096897e6df6957895bec7049d262d3713092dbf9248b3fd9425b'
})

const syncTemplate = Object.freeze([
  'sync',
  '--directory',
  PROJECT_ROOT_TOKEN,
  '--locked',
  '--no-default-groups',
  '--group',
  'dev',
  '--extra',
  'dev',
  '--python',
  '3.12.9',
  '--managed-python',
  '--no-python-downloads'
])
const sbomTemplate = Object.freeze([
  'export',
  '--directory',
  PROJECT_ROOT_TOKEN,
  '--frozen',
  '--preview-features',
  'sbom-export',
  '--format',
  'cyclonedx1.5',
  '--no-default-groups',
  '--group',
  'dev',
  '--extra',
  'dev',
  '--python',
  '3.12.9',
  '--no-emit-project'
])

export const PYTHON_RELEASE_SELECTION = Object.freeze({
  archiveViewer: Object.freeze({
    projectRelativePath: '.venv/Scripts/pyi-archive_viewer.exe',
    version: PYINSTALLER_ARCHIVE_VIEWER_VERSION
  }),
  buildCommand: Object.freeze({ args: syncTemplate, executable: 'uv' }),
  engineBuild: Object.freeze({
    args: Object.freeze(['--noconfirm', 'engine.spec', '--distpath', 'dist', '--workpath', 'build']),
    executableProjectRelativePath: '.venv/Scripts/python.exe',
    isolatedFlags: Object.freeze(['-X', 'utf8', '-I', '-S', '-B'])
  }),
  environment: Object.freeze({ platform: 'win32', pythonVersion: '3.12.9' }),
  evidenceCommand: Object.freeze({ args: sbomTemplate, executable: 'uv' }),
  extras: Object.freeze(['dev']),
  groups: Object.freeze(['dev']),
  includeDefaultGroups: false,
  schema: 2
})

export const FORBIDDEN_PYTHON_RELEASE_PACKAGES = Object.freeze([
  'ctranslate2',
  'faster-whisper',
  'funasr',
  'kaldiio',
  'onnxruntime',
  'sentencepiece',
  'tokenizers',
  'torch',
  'torch-complex'
])

const WINDOWS_RELEASE_MARKER_ENVIRONMENT = Object.freeze(
  {
    ...pythonMarkerEnvironment('3.12.9', {
      implementationName: 'cpython',
      osName: 'nt',
      platformMachine: 'AMD64',
      platformPythonImplementation: 'CPython',
      platformSystem: 'Windows',
      sysPlatform: 'win32'
    }),
    extra: '',
    implementation_version: '3.12.9',
    platform_release: '',
    platform_version: ''
  }
)

export function evaluateReleasePep508Markers(
  markers,
  { projectRoot = defaultProjectRoot, execute = spawnSync } = {}
) {
  if (!Array.isArray(markers) || markers.some((marker) => typeof marker !== 'string' || !marker.trim())) {
    throw new Error('release marker set is invalid')
  }
  const unique = [...new Set(markers)]
  if (unique.length === 0) return new Map()
  projectRoot = resolve(projectRoot)
  const environmentRoot = resolve(projectRoot, '.venv')
  const pythonPath = pythonReleaseInterpreterPath(projectRoot)
  const sitePackages = join(environmentRoot, 'Lib', 'site-packages')
  ordinaryPath(pythonPath, environmentRoot, 'release-selected Python executable')
  ordinaryPath(sitePackages, environmentRoot, 'release-selected site-packages', { directory: true })
  const payload = Buffer.from(JSON.stringify({
    environment: WINDOWS_RELEASE_MARKER_ENVIRONMENT,
    markers: unique
  }), 'utf8').toString('base64')
  const script = [
    'import base64,json,sys',
    `sys.path.insert(0,${JSON.stringify(sitePackages)})`,
    `p=json.loads(base64.b64decode(${JSON.stringify(payload)}))`,
    'from packaging.markers import Marker',
    "print(json.dumps([Marker(x).evaluate(environment=p['environment'],context='lock_file') for x in p['markers']],separators=(',',':')))"
  ].join(';')
  const result = execute(
    pythonPath,
    ['-X', 'utf8', '-I', '-S', '-B', '-c', script],
    {
      cwd: projectRoot,
      encoding: 'utf8',
      env: isolatedPythonEnvironment(),
      maxBuffer: 4 * 1024 * 1024,
      timeout: 30_000,
      windowsHide: true
    }
  )
  if (result.error) throw result.error
  if (result.signal || result.status !== 0 || String(result.stderr || '').trim()) {
    throw new Error(`official packaging marker evaluation failed: ${result.signal || result.status}`)
  }
  let evaluated
  try {
    evaluated = JSON.parse(String(result.stdout || ''))
  } catch {
    throw new Error('official packaging marker evaluation is not JSON')
  }
  if (!Array.isArray(evaluated) || evaluated.length !== unique.length || evaluated.some((value) => typeof value !== 'boolean')) {
    throw new Error('official packaging marker evaluation returned an invalid result set')
  }
  return new Map(unique.map((marker, index) => [marker, evaluated[index]]))
}

const EVALUATION_LICENSE_PATTERNS = Object.freeze([
  /software license agreement for evaluation/i,
  /\bevaluation[- ]only\b/i,
  /\bfor evaluation purposes only\b/i,
  /\binternal evaluation\b/i,
  /\bnon[- ]commercial use only\b/i
])

const normalizedPythonName = (value) => String(value || '').toLowerCase().replace(/[-_.]+/g, '-')

function materializeArgs(template, projectRoot) {
  const root = resolve(projectRoot)
  return template.map((value) => value === PROJECT_ROOT_TOKEN ? root : value)
}

export function pythonReleaseSyncArgs(projectRoot = defaultProjectRoot) {
  return materializeArgs(syncTemplate, projectRoot)
}

export function pythonReleaseSbomArgs(projectRoot = defaultProjectRoot) {
  return materializeArgs(sbomTemplate, projectRoot)
}

export function pyinstallerArchiveViewerPath(projectRoot = defaultProjectRoot) {
  return resolve(projectRoot, '.venv', 'Scripts', 'pyi-archive_viewer.exe')
}

export function pythonReleaseInterpreterPath(projectRoot = defaultProjectRoot) {
  return resolve(projectRoot, '.venv', 'Scripts', 'python.exe')
}

export function isolatedPythonEnvironment(source = process.env) {
  const allowed = new Set(['COMSPEC', 'SYSTEMDRIVE', 'SYSTEMROOT', 'TEMP', 'TMP', 'WINDIR'])
  const environment = {}
  for (const [key, value] of Object.entries(source || {})) {
    const normalized = key.toUpperCase()
    if (allowed.has(normalized) && typeof value === 'string' && value) environment[normalized] = value
  }
  return environment
}

export function assertNoSelectedPythonStartupHooks(projectRoot = defaultProjectRoot) {
  projectRoot = resolve(projectRoot)
  const environmentRoot = resolve(projectRoot, '.venv')
  const sitePackages = join(environmentRoot, 'Lib', 'site-packages')
  ordinaryPath(sitePackages, environmentRoot, 'release-selected site-packages', { directory: true })
  const forbidden = new Set(['sitecustomize.py', 'sitecustomize.pyc', 'usercustomize.py', 'usercustomize.pyc'])
  for (const entry of readdirSync(sitePackages, { withFileTypes: true })) {
    if (forbidden.has(entry.name.toLowerCase())) {
      throw new Error(`release-selected site-packages contains a forbidden startup hook: ${entry.name}`)
    }
  }
}

export function attestSelectedPythonEnvironment(projectRoot = defaultProjectRoot, execute = spawnSync) {
  projectRoot = resolve(projectRoot)
  const environmentRoot = resolve(projectRoot, '.venv')
  const pythonPath = pythonReleaseInterpreterPath(projectRoot)
  const sitePackages = join(environmentRoot, 'Lib', 'site-packages')
  ordinaryPath(pythonPath, environmentRoot, 'release-selected Python executable')
  ordinaryPath(sitePackages, environmentRoot, 'release-selected site-packages', { directory: true })
  assertNoSelectedPythonStartupHooks(projectRoot)
  const script = [
    'import importlib.metadata as m,json',
    `r=${JSON.stringify(sitePackages)}`,
    "p=sorted([{'name':(d.metadata.get('Name') or '').lower().replace('_','-'),'version':d.version} for d in m.distributions(path=[r])],key=lambda x:(x['name'],x['version']))",
    'print(json.dumps(p,separators=(\',\',\':\')))'
  ].join(';')
  const result = execute(
    pythonPath,
    ['-X', 'utf8', '-I', '-S', '-B', '-c', script],
    {
      cwd: projectRoot,
      encoding: 'utf8',
      env: isolatedPythonEnvironment(),
      maxBuffer: 4 * 1024 * 1024,
      timeout: 30_000,
      windowsHide: true
    }
  )
  if (result.error) throw result.error
  if (result.signal || result.status !== 0 || String(result.stderr || '').trim()) {
    throw new Error(`release-selected Python environment attestation failed: ${result.signal || result.status}`)
  }
  let installed
  try {
    installed = JSON.parse(String(result.stdout || ''))
  } catch {
    throw new Error('release-selected Python environment attestation is not JSON')
  }
  if (!Array.isArray(installed) || installed.some((item) => !item?.name || !item?.version)) {
    throw new Error('release-selected Python environment distribution set is invalid')
  }
  const duplicates = new Set(installed.map(({ name }) => normalizedPythonName(name)))
  if (duplicates.size !== installed.length) {
    throw new Error('release-selected Python environment contains duplicate distributions')
  }
  const lockText = readFileSync(join(projectRoot, 'uv.lock'), 'utf8')
  const expected = selectedPythonPackagesFromUvLock(lockText, { projectRoot }).map(({ name, version }) => ({
    name: normalizedPythonName(name),
    version
  }))
  const editableRoots = packageNodes(lockText).filter(({ editable }) => editable === '.')
  if (editableRoots.length === 1) {
    expected.push({
      name: editableRoots[0].name,
      version: editableRoots[0].version
    })
    expected.sort((left, right) => {
      const leftKey = `${left.name}\0${left.version}`
      const rightKey = `${right.name}\0${right.version}`
      return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0
    })
  }
  const actual = installed.map(({ name, version }) => ({ name: normalizedPythonName(name), version: String(version) }))
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`release-selected Python environment drifted: expected=${expected.length} actual=${actual.length}`)
  }
  inspectPyInstallerRecordClosure(projectRoot)
  return actual
}

function ordinaryPath(path, root, label, { directory = false } = {}) {
  path = resolve(path)
  root = resolve(root)
  const fromRoot = relative(root, path)
  if (!fromRoot || fromRoot.startsWith('..') || isAbsolute(fromRoot)) {
    if (path.toLowerCase() !== root.toLowerCase()) throw new Error(`${label} escapes the selected environment`)
  }
  let cursor = path
  while (true) {
    const info = lstatSync(cursor)
    if (info.isSymbolicLink()) throw new Error(`${label} traverses a path shim or reparse link`)
    if (cursor.toLowerCase() === root.toLowerCase()) break
    const parent = dirname(cursor)
    if (parent === cursor) throw new Error(`${label} escapes the selected environment`)
    cursor = parent
  }
  const info = lstatSync(path)
  if (directory ? !info.isDirectory() : !info.isFile()) throw new Error(`${label} has the wrong file type`)
  if (realpathSync.native(path).toLowerCase() !== path.toLowerCase()) {
    throw new Error(`${label} resolves through a path shim or reparse link`)
  }
  return info
}

function sha256Bytes(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

function recordRows(bytes) {
  const text = bytes.toString('utf8')
  if (!Buffer.from(text, 'utf8').equals(bytes) || text.startsWith('\uFEFF') || text.includes('\0')) {
    throw new Error('PyInstaller RECORD must be plain UTF-8')
  }
  const rows = []
  for (const [index, line] of text.split(/\r?\n/).entries()) {
    if (!line) continue
    const fields = line.split(',')
    if (fields.length !== 3 || fields.some((field) => field.includes('"'))) {
      throw new Error(`PyInstaller RECORD row ${index + 1} uses unsupported CSV syntax`)
    }
    const [path, hash, size] = fields
    if (
      !path ||
      path.includes('\\') ||
      path.startsWith('/') ||
      /^[A-Za-z]:/.test(path) ||
      path.split('/').some((part) => !part || part === '.')
    ) {
      throw new Error(`PyInstaller RECORD row ${index + 1} has an invalid path`)
    }
    rows.push({ hash, path, size })
  }
  if (rows.length === 0 || new Set(rows.map(({ path }) => path.toLowerCase())).size !== rows.length) {
    throw new Error('PyInstaller RECORD is empty or contains duplicate paths')
  }
  return rows
}

function recursiveFiles(root, environmentRoot, output = []) {
  ordinaryPath(root, environmentRoot, 'PyInstaller distribution directory', { directory: true })
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const path = join(root, entry.name)
    if (entry.isSymbolicLink()) throw new Error('PyInstaller distribution contains a path shim or reparse link')
    if (entry.isDirectory()) recursiveFiles(path, environmentRoot, output)
    else if (entry.isFile()) output.push(path)
    else throw new Error('PyInstaller distribution contains an unsupported filesystem entry')
  }
  return output
}

export function portablePyInstallerRecordDescriptors(descriptors) {
  return descriptors
    .filter(({ isRecord, path }) => !isRecord && !path.startsWith('../../Scripts/'))
    .map(({ path, recordHash, recordSize, sha256, size }) => ({
      path,
      recordHash,
      recordSize,
      sha256,
      size
    }))
    .sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0)
}

export function inspectPyInstallerRecordClosure(
  projectRoot = defaultProjectRoot,
  expected = PYINSTALLER_WINDOWS_CLOSURE
) {
  projectRoot = resolve(projectRoot)
  const environmentRoot = resolve(projectRoot, '.venv')
  const sitePackages = join(environmentRoot, 'Lib', 'site-packages')
  ordinaryPath(environmentRoot, environmentRoot, 'release-selected Python environment', { directory: true })
  ordinaryPath(sitePackages, environmentRoot, 'release-selected site-packages', { directory: true })
  const packageRoot = join(sitePackages, 'PyInstaller')
  const distInfos = readdirSync(sitePackages, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && /^pyinstaller-[^/]+\.dist-info$/i.test(entry.name))
    .map((entry) => join(sitePackages, entry.name))
  if (distInfos.length !== 1 || !distInfos[0].toLowerCase().endsWith(`pyinstaller-${PYINSTALLER_ARCHIVE_VIEWER_VERSION}.dist-info`)) {
    throw new Error('release-selected environment has an unexpected PyInstaller distribution identity')
  }
  const distInfo = distInfos[0]
  const recordPath = join(distInfo, 'RECORD')
  ordinaryPath(packageRoot, environmentRoot, 'PyInstaller package', { directory: true })
  ordinaryPath(distInfo, environmentRoot, 'PyInstaller dist-info', { directory: true })
  ordinaryPath(recordPath, environmentRoot, 'PyInstaller RECORD')
  const recordBytes = readFileSync(recordPath)
  const rows = recordRows(recordBytes)
  const descriptors = []
  const recordedPackageFiles = new Set()
  for (const row of rows) {
    const path = resolve(sitePackages, ...row.path.split('/'))
    const fromEnvironment = relative(environmentRoot, path)
    if (fromEnvironment.startsWith('..') || isAbsolute(fromEnvironment)) {
      throw new Error(`PyInstaller RECORD path escapes the selected environment: ${row.path}`)
    }
    const info = ordinaryPath(path, environmentRoot, `PyInstaller RECORD file ${row.path}`)
    const bytes = readFileSync(path)
    const digest = sha256Bytes(bytes)
    const isRecord = path.toLowerCase() === recordPath.toLowerCase()
    if (isRecord) {
      if (row.hash || row.size) throw new Error('PyInstaller RECORD self-row must omit hash and size')
    } else {
      if (!/^sha256=[A-Za-z0-9_-]{43}$/.test(row.hash) || !/^(?:0|[1-9]\d*)$/.test(row.size)) {
        throw new Error(`PyInstaller RECORD metadata is invalid for ${row.path}`)
      }
      const expectedDigest = Buffer.from(row.hash.slice(7), 'base64url').toString('hex')
      if (expectedDigest !== digest || Number(row.size) !== info.size || bytes.length !== info.size) {
        throw new Error(`PyInstaller RECORD hash or size drifted for ${row.path}`)
      }
    }
    const relativeSitePath = relative(sitePackages, path).replaceAll('\\', '/')
    if (
      relativeSitePath.startsWith('PyInstaller/') ||
      relativeSitePath.toLowerCase().startsWith(`pyinstaller-${PYINSTALLER_ARCHIVE_VIEWER_VERSION}.dist-info/`)
    ) {
      recordedPackageFiles.add(relativeSitePath.toLowerCase())
    }
    const descriptor = {
      isRecord,
      path: row.path,
      recordHash: row.hash,
      recordSize: row.size,
      sha256: digest,
      size: info.size
    }
    descriptors.push(descriptor)
    // uv's Windows console launchers embed the absolute virtual-environment
    // interpreter path. Their bytes (and the matching RECORD rows) therefore
    // differ across otherwise identical clean checkouts. Validate every row
    // above, but bind the portable package closure only to wheel-owned files.
  }
  const actualPackageFiles = withoutDerivedPyInstallerBytecode(
    [
      ...recursiveFiles(packageRoot, environmentRoot),
      ...recursiveFiles(distInfo, environmentRoot)
    ].map((path) => relative(sitePackages, path).replaceAll('\\', '/').toLowerCase())
  )
  if (
    actualPackageFiles.length !== recordedPackageFiles.size ||
    actualPackageFiles.some((path) => !recordedPackageFiles.has(path))
  ) {
    throw new Error('PyInstaller package contains files outside its locked RECORD closure')
  }
  descriptors.sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0)
  const portableDescriptors = portablePyInstallerRecordDescriptors(descriptors)
  const implementationSha256 = sha256Bytes(Buffer.from(
    portableDescriptors.map(({ path, sha256, size }) => `${path}\0${sha256}\0${size}\n`).join(''),
    'utf8'
  ))
  const recordSha256 = sha256Bytes(Buffer.from(
    portableDescriptors.map(({ path, recordHash, recordSize }) => `${path}\0${recordHash}\0${recordSize}\n`).join(''),
    'utf8'
  ))
  const launcher = descriptors.find(({ path }) => path === '../../Scripts/pyi-archive_viewer.exe')
  if (!launcher) throw new Error('PyInstaller RECORD does not bind pyi-archive_viewer.exe')
  const actual = {
    fileCount: portableDescriptors.length,
    implementationSha256,
    recordSha256
  }
  if (expected && JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`PyInstaller implementation closure drifted: ${JSON.stringify(actual)}`)
  }
  return {
    ...actual,
    launcherSha256: launcher.sha256,
    launcherSize: launcher.size,
    path: pyinstallerArchiveViewerPath(projectRoot),
    recordedFileCount: descriptors.length
  }
}

function executeUtf8(executable, args, options, execute = execFile) {
  return new Promise((accept, reject) => {
    execute(executable, args, options, (error, stdout, stderr) => {
      if (error) {
        reject(error)
        return
      }
      accept({ stdout, stderr })
    })
  })
}

export async function pyinstallerArchiveViewerDescriptor(
  projectRoot = defaultProjectRoot,
  execute = execFile
) {
  projectRoot = resolve(projectRoot)
  const closure = inspectPyInstallerRecordClosure(projectRoot)
  const environmentRoot = resolve(projectRoot, '.venv')
  const pythonPath = pythonReleaseInterpreterPath(projectRoot)
  const sitePackages = join(environmentRoot, 'Lib', 'site-packages')
  const pythonInfo = ordinaryPath(pythonPath, environmentRoot, 'release-selected Python executable')
  const pythonBytes = readFileSync(pythonPath)
  const result = await executeUtf8(
    pythonPath,
    [
      '-X',
      'utf8',
      '-I',
      '-S',
      '-B',
      '-c',
      `import sys;sys.path.insert(0,${JSON.stringify(sitePackages)});import PyInstaller;print(PyInstaller.__version__)`
    ],
    {
      cwd: projectRoot,
      encoding: 'utf8',
      env: isolatedPythonEnvironment(),
      maxBuffer: 64 * 1024,
      timeout: 30_000,
      windowsHide: true
    },
    execute
  )
  if (String(result.stderr || '').trim() || String(result.stdout || '').trim() !== PYINSTALLER_ARCHIVE_VIEWER_VERSION) {
    throw new Error('actual PyInstaller version does not match the release-selected lock')
  }
  return {
    implementationFileCount: closure.fileCount,
    implementationSha256: closure.implementationSha256,
    name: 'pyinstallerArchiveViewer',
    path: closure.path,
    pythonPath,
    pythonSha256: sha256Bytes(pythonBytes),
    pythonSize: pythonInfo.size,
    recordSha256: closure.recordSha256,
    sha256: closure.launcherSha256,
    size: closure.launcherSize,
    version: PYINSTALLER_ARCHIVE_VIEWER_VERSION
  }
}

function checkedArrayBody(text, key, label) {
  const match = new RegExp(`^\\s*${key.replace(/[.*+?^${}()|[\\]\\]/g, '\\$&')}\\s*=\\s*\\[`, 'm').exec(text)
  if (!match) return null
  const start = match.index + match[0].lastIndexOf('[')
  let depth = 0
  let quoted = false
  let escaped = false
  for (let index = start; index < text.length; index += 1) {
    const character = text[index]
    if (quoted) {
      if (escaped) escaped = false
      else if (character === '\\') escaped = true
      else if (character === '"') quoted = false
      continue
    }
    if (character === '"') quoted = true
    else if (character === '[') depth += 1
    else if (character === ']') {
      depth -= 1
      if (depth === 0) return text.slice(start + 1, index)
    }
  }
  throw new Error(`${label} has an unterminated ${key} array`)
}

function sectionBody(block, header) {
  const match = new RegExp(`^\\[${header.replace(/[.*+?^${}()|[\\]\\]/g, '\\$&')}\\]\\s*$`, 'm').exec(block)
  if (!match) return ''
  const start = match.index + match[0].length
  const tail = block.slice(start)
  const next = /^\[[^\r\n]+\]\s*$/m.exec(tail)
  return next ? tail.slice(0, next.index) : tail
}

function inlineTables(arrayBody, label) {
  if (arrayBody === null) return []
  const tables = []
  let start = -1
  let depth = 0
  let quoted = false
  let escaped = false
  for (let index = 0; index < arrayBody.length; index += 1) {
    const character = arrayBody[index]
    if (quoted) {
      if (escaped) escaped = false
      else if (character === '\\') escaped = true
      else if (character === '"') quoted = false
      continue
    }
    if (character === '"') quoted = true
    else if (character === '{') {
      if (depth === 0) start = index
      depth += 1
    } else if (character === '}') {
      depth -= 1
      if (depth < 0) throw new Error(`${label} has an invalid inline dependency table`)
      if (depth === 0) tables.push(arrayBody.slice(start, index + 1))
    }
  }
  if (quoted || depth !== 0) throw new Error(`${label} has an unterminated inline dependency table`)
  const remainder = arrayBody.replace(/\{(?:[^{}"']|"(?:\\.|[^"])*"|\{[^{}]*\})*\}/g, '').replace(/[\s,]/g, '')
  if (remainder) throw new Error(`${label} contains unsupported dependency syntax`)
  return tables
}

function dependencyItems(text, key, label) {
  const body = checkedArrayBody(text, key, label)
  return inlineTables(body, label).map((table) => {
    const name = /\bname\s*=\s*"([^"]+)"/.exec(table)?.[1]
    const version = /\bversion\s*=\s*"([^"]+)"/.exec(table)?.[1] || ''
    const registry = /\bsource\s*=\s*\{\s*registry\s*=\s*"([^"]+)"\s*\}/.exec(table)?.[1] || ''
    const marker = /\bmarker\s*=\s*"([^"]+)"/.exec(table)?.[1] || ''
    const extrasBody = /\bextras?\s*=\s*\[([^\]]*)\]/.exec(table)?.[1] || ''
    const extras = [...extrasBody.matchAll(/"([^"]+)"/g)].map((match) => match[1])
    if (!name || name !== name.trim()) throw new Error(`${label} contains an invalid dependency name`)
    return { extras, marker, name: normalizedPythonName(name), registry, version }
  })
}

function packageNodes(lockText) {
  if (typeof lockText !== 'string' || !/^version = 1\s*$/m.test(lockText)) {
    throw new Error('uv.lock schema is invalid')
  }
  return lockText.split(/^\[\[package\]\]\s*$/m).slice(1).map((block, index) => {
    const firstSection = /^\[package\.[^\r\n]+\]\s*$/m.exec(block)
    const top = firstSection ? block.slice(0, firstSection.index) : block
    const rawName = /^name = "([^"]+)"\s*$/m.exec(top)?.[1]
    const version = /^version = "([^"]+)"\s*$/m.exec(top)?.[1]
    const registry = /^source = \{ registry = "([^"]+)" \}\s*$/m.exec(top)?.[1] || ''
    const virtual = /^source = \{ virtual = "([^"]+)" \}\s*$/m.exec(top)?.[1] || ''
    const editable = /^source = \{ editable = "([^"]+)" \}\s*$/m.exec(top)?.[1] || ''
    if (!rawName || !version || (!registry && !virtual && !editable)) {
      throw new Error(`uv.lock package ${index + 1} has an unsupported or incomplete identity`)
    }
    return {
      block,
      dependencies: dependencyItems(top, 'dependencies', `uv.lock package ${rawName}`),
      editable,
      index,
      name: normalizedPythonName(rawName),
      optionalSection: sectionBody(block, 'package.optional-dependencies'),
      registry,
      version,
      virtual
    }
  })
}

export function selectedPythonPackagesFromUvLock(lockText, markerOptions = {}) {
  const nodes = packageNodes(lockText)
  const markers = [...lockText.matchAll(/\bmarker\s*=\s*"((?:\\.|[^"])*)"/g)].map((match) => {
    try {
      return JSON.parse(`"${match[1]}"`)
    } catch {
      throw new Error('uv.lock contains an invalid marker string')
    }
  })
  const markerResults = evaluateReleasePep508Markers(markers, markerOptions)
  const roots = nodes.filter(({ editable, virtual }) => virtual === '.' || editable === '.')
  if (roots.length !== 1) throw new Error('uv.lock must contain exactly one local project root')
  const byName = new Map()
  for (const node of nodes) {
    const entries = byName.get(node.name) || []
    entries.push(node)
    byName.set(node.name, entries)
  }

  const selected = new Set()
  const processedExtras = new Map()
  const queue = []
  const enqueue = (node, extras = []) => queue.push({ extras, node })
  const resolveDependency = (dependency, owner) => {
    if (dependency.marker && markerResults.get(dependency.marker) !== true) {
      return
    }
    let candidates = byName.get(dependency.name) || []
    if (dependency.version) candidates = candidates.filter(({ version }) => version === dependency.version)
    if (dependency.registry) candidates = candidates.filter(({ registry }) => registry === dependency.registry)
    if (candidates.length !== 1) {
      throw new Error(`uv.lock dependency ${owner.name}->${dependency.name} is missing or ambiguous`)
    }
    enqueue(candidates[0], dependency.extras)
  }
  const root = roots[0]
  enqueue(root, PYTHON_RELEASE_SELECTION.extras)
  const devSection = sectionBody(root.block, 'package.dev-dependencies')
  for (const group of PYTHON_RELEASE_SELECTION.groups) {
    for (const dependency of dependencyItems(devSection, group, `uv.lock development group ${group}`)) {
      resolveDependency(dependency, root)
    }
  }

  while (queue.length) {
    const { node, extras } = queue.shift()
    const firstVisit = !selected.has(node.index)
    if (firstVisit) {
      selected.add(node.index)
      for (const dependency of node.dependencies) resolveDependency(dependency, node)
    }
    const processed = processedExtras.get(node.index) || new Set()
    for (const extra of extras) {
      if (processed.has(extra)) continue
      processed.add(extra)
      for (const dependency of dependencyItems(node.optionalSection, extra, `uv.lock ${node.name} extra ${extra}`)) {
        resolveDependency(dependency, node)
      }
    }
    processedExtras.set(node.index, processed)
  }

  return nodes
    .filter((node) => selected.has(node.index) && node.registry)
    .map(({ name, version }) => ({ name, version }))
    .sort((left, right) => {
      const leftKey = `${left.name}\0${left.version}`
      const rightKey = `${right.name}\0${right.version}`
      return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0
    })
}

function licenseStrings(value, depth = 0) {
  if (depth > 8 || value === null || value === undefined) return []
  if (typeof value === 'string') return [value]
  if (Array.isArray(value)) return value.flatMap((item) => licenseStrings(item, depth + 1))
  if (typeof value === 'object') return Object.values(value).flatMap((item) => licenseStrings(item, depth + 1))
  return []
}

export function assertPythonReleaseSbomPolicy(sbom) {
  if (!sbom || typeof sbom !== 'object' || !Array.isArray(sbom.components)) {
    throw new Error('Python release SBOM is missing components')
  }
  const forbidden = new Set(FORBIDDEN_PYTHON_RELEASE_PACKAGES)
  for (const component of sbom.components) {
    const name = normalizedPythonName(component?.name)
    if (forbidden.has(name)) throw new Error(`forbidden Python release package appears in SBOM: ${name}`)
    for (const value of licenseStrings(component?.licenses)) {
      if (EVALUATION_LICENSE_PATTERNS.some((pattern) => pattern.test(value))) {
        throw new Error(`evaluation-only Python license appears in selected SBOM component: ${name || '<unknown>'}`)
      }
    }
  }
}

export function filterPythonSbomForReleaseEnvironment(sbom, markerOptions = {}) {
  if (!sbom || typeof sbom !== 'object' || Array.isArray(sbom) || !Array.isArray(sbom.components)) {
    throw new Error('Python release SBOM is missing components')
  }
  const filtered = structuredClone(sbom)
  const keptRefs = new Set()
  const componentMarkers = filtered.components.flatMap((component) => {
    const properties = component?.properties ?? []
    if (!Array.isArray(properties)) throw new Error('Python SBOM component properties must be an array')
    return properties
      .filter((property) => property?.name === 'uv:package:marker')
      .map((property) => String(property.value || ''))
  })
  const markerResults = evaluateReleasePep508Markers(componentMarkers, markerOptions)
  filtered.components = filtered.components.filter((component) => {
    const properties = component?.properties ?? []
    if (!Array.isArray(properties)) throw new Error('Python SBOM component properties must be an array')
    const markers = []
    for (const property of properties) {
      if (!property || typeof property !== 'object' || Array.isArray(property)) {
        throw new Error('Python SBOM component property is invalid')
      }
      if (property.name === 'uv:package:marker') markers.push(property.value)
    }
    if (markers.length > 1) throw new Error('Python SBOM component has duplicate environment markers')
    const keep = markers.length === 0 || markerResults.get(String(markers[0])) === true
    if (keep) {
      const ref = component?.['bom-ref']
      if (typeof ref !== 'string' || !ref || keptRefs.has(ref)) {
        throw new Error('Python SBOM component has a missing or duplicate bom-ref')
      }
      keptRefs.add(ref)
    }
    return keep
  })
  if (filtered.dependencies !== undefined) {
    if (!Array.isArray(filtered.dependencies)) throw new Error('Python SBOM dependencies must be an array')
    const rootRef = filtered.metadata?.component?.['bom-ref']
    filtered.dependencies = filtered.dependencies
      .filter((dependency) => dependency?.ref === rootRef || keptRefs.has(dependency?.ref))
      .map((dependency) => {
        if (!dependency || typeof dependency !== 'object' || !Array.isArray(dependency.dependsOn)) {
          throw new Error('Python SBOM dependency closure is invalid')
        }
        return {
          ...dependency,
          dependsOn: dependency.dependsOn.filter((ref) => ref === rootRef || keptRefs.has(ref))
        }
      })
  }
  assertPythonReleaseSbomPolicy(filtered)
  return filtered
}

function forbiddenArchiveEntry(entry) {
  const normalized = String(entry || '').trim().toLowerCase().replaceAll('\\', '/')
  if (!normalized || normalized.length > 4096 || normalized.includes('\0')) return ''
  if (EVALUATION_LICENSE_PATTERNS.some((pattern) => pattern.test(normalized))) return normalized
  const segments = normalized.split('/')
  for (const name of FORBIDDEN_PYTHON_RELEASE_PACKAGES) {
    const moduleName = name.replace(/-/g, '_')
    for (const segment of segments) {
      if (
        segment === moduleName ||
        segment.startsWith(`${moduleName}.`) ||
        (segment.endsWith('.dist-info') && segment.replaceAll('_', '-').startsWith(`${name}-`))
      ) {
        return name
      }
    }
  }
  return ''
}

export function assertNoForbiddenPythonArchiveEntries(entries, label = 'Python release payload') {
  if (!Array.isArray(entries) || entries.length === 0 || entries.length > 1_000_000) {
    throw new Error(`${label} PyInstaller archive closure is missing or oversized`)
  }
  for (const entry of entries) {
    const hit = forbiddenArchiveEntry(entry)
    if (hit) throw new Error(`${label} contains forbidden Python release payload entry: ${hit}`)
  }
}

export async function inspectPyInstallerArchive(path, {
  projectRoot = defaultProjectRoot,
  viewerPath = pyinstallerArchiveViewerPath(projectRoot),
  execute = execFile
} = {}) {
  path = resolve(path)
  projectRoot = resolve(projectRoot)
  const expectedViewer = pyinstallerArchiveViewerPath(projectRoot)
  viewerPath = resolve(viewerPath)
  if (viewerPath.toLowerCase() !== expectedViewer.toLowerCase()) {
    throw new Error('PyInstaller archive viewer path does not match the release-selected environment')
  }
  const descriptor = await pyinstallerArchiveViewerDescriptor(projectRoot)
  const pythonPath = descriptor.pythonPath
  const sitePackages = resolve(projectRoot, '.venv', 'Lib', 'site-packages')
  const isolatedScript = [
    'import sys',
    `sys.path.insert(0,${JSON.stringify(sitePackages)})`,
    `sys.argv=['pyi-archive-viewer','-r','-b',${JSON.stringify(path)}]`,
    'from PyInstaller.utils.cliutils.archive_viewer import run',
    'run()'
  ].join(';')
  return new Promise((accept, reject) => {
    execute(
      pythonPath,
      ['-X', 'utf8', '-I', '-S', '-B', '-c', isolatedScript],
      {
        cwd: projectRoot,
        encoding: 'utf8',
        env: isolatedPythonEnvironment(),
        maxBuffer: 64 * 1024 * 1024,
        timeout: 180_000,
        windowsHide: true
      },
      (error, stdout, stderr) => {
        if (error) {
          reject(new Error('PyInstaller archive closure inspection failed', { cause: error }))
          return
        }
        if (String(stderr || '').trim()) {
          reject(new Error('PyInstaller archive closure inspection emitted unexpected stderr'))
          return
        }
        if (typeof stdout !== 'string' || !stdout || stdout.includes('\0')) {
          reject(new Error('PyInstaller archive closure output is empty or invalid'))
          return
        }
        const entries = stdout
          .split(/\r?\n/)
          .filter((line) => /^\s/.test(line))
          .map((line) => line.trim())
          .filter((line) => line && !line.startsWith('pyi-contents-directory '))
        if (
          entries.length === 0 ||
          entries.length > 1_000_000 ||
          entries.some((entry) => entry.length > 4096 || /[\x00-\x1f\x7f]/.test(entry)) ||
          new Set(entries).size !== entries.length ||
          !entries.includes('engine_main') ||
          !entries.includes('PYZ.pyz')
        ) {
          reject(new Error('PyInstaller archive closure output is missing or oversized'))
          return
        }
        accept(entries)
      }
    )
  })
}

export async function assertNoForbiddenPythonPayload(
  path,
  label = 'Python release payload',
  inspect = inspectPyInstallerArchive
) {
  const entries = await inspect(path)
  assertNoForbiddenPythonArchiveEntries(entries, label)
}

// Derived bytecode caches (`__pycache__`/*.pyc) are deterministic artifacts of the
// RECORD-pinned sources, not payload: the sealed build's own PyInstaller isolated
// children regenerate them.  Excluding them keeps the closure exact for real payload.
export function withoutDerivedPyInstallerBytecode(paths) {
  return paths.filter((path) => !path.includes('/__pycache__/') && !path.endsWith('.pyc'))
}

function checkedProcessResult(result, label) {
  if (result.error) throw result.error
  if (result.signal || result.status !== 0) throw new Error(`${label} failed: ${result.signal || result.status}`)
}

function syncEnvironment(source = process.env) {
  return Object.fromEntries(Object.entries(source).filter(([key]) => !/^(?:UV|PIP|PYTHON)/i.test(key)))
}

function syncSelectedPythonEnvironment() {
  const uv = process.env.NACHUAN_RELEASE_UV_PATH || 'uv'
  checkedProcessResult(
    spawnSync(uv, pythonReleaseSyncArgs(), {
      cwd: defaultProjectRoot,
      env: syncEnvironment(),
      stdio: 'inherit',
      windowsHide: true
    }),
    'release-selected uv sync'
  )
  attestSelectedPythonEnvironment(defaultProjectRoot)
}

function buildSelectedPythonEngine() {
  attestSelectedPythonEnvironment(defaultProjectRoot)
  const pythonPath = pythonReleaseInterpreterPath(defaultProjectRoot)
  const sitePackages = resolve(defaultProjectRoot, '.venv', 'Lib', 'site-packages')
  const buildArgs = [...PYTHON_RELEASE_SELECTION.engineBuild.args]
  const script = [
    'import sys',
    `sys.path.insert(0,${JSON.stringify(sitePackages)})`,
    'from PyInstaller.__main__ import run',
    `run(${JSON.stringify(buildArgs)})`
  ].join(';')
  checkedProcessResult(
    spawnSync(pythonPath, ['-X', 'utf8', '-I', '-S', '-B', '-c', script], {
      cwd: defaultProjectRoot,
      env: isolatedPythonEnvironment(),
      stdio: 'inherit',
      windowsHide: true
    }),
    'release-selected isolated PyInstaller build'
  )
  attestSelectedPythonEnvironment(defaultProjectRoot)
}

export function selectedPythonTestInvocation({
  projectRoot = defaultProjectRoot,
  sourceEnvironment = process.env
} = {}) {
  projectRoot = resolve(projectRoot)
  const environmentRoot = resolve(projectRoot, '.venv')
  const pythonPath = pythonReleaseInterpreterPath(projectRoot)
  const sitePackages = join(environmentRoot, 'Lib', 'site-packages')
  const testsRoot = join(projectRoot, 'tests')
  ordinaryPath(pythonPath, environmentRoot, 'release-selected Python executable')
  ordinaryPath(sitePackages, environmentRoot, 'release-selected site-packages', { directory: true })
  ordinaryPath(testsRoot, projectRoot, 'owned Python test root', { directory: true })
  assertNoSelectedPythonStartupHooks(projectRoot)
  const pytestArgs = ['-q', '-p', 'no:cacheprovider', '-p', 'pytest_asyncio.plugin', testsRoot]
  const script = [
    'import os,sys',
    'base=list(sys.path)',
    "assert all(p and os.path.isabs(p) and 'site-packages' not in p.lower() for p in base)",
    `sys.path[:]=[${JSON.stringify(sitePackages)},${JSON.stringify(projectRoot)},${JSON.stringify(testsRoot)},*base]`,
    "os.environ['PYTEST_DISABLE_PLUGIN_AUTOLOAD']='1'",
    'from pytest import main',
    `raise SystemExit(main(${JSON.stringify(pytestArgs)}))`
  ].join(';')
  return {
    args: ['-X', 'utf8', '-I', '-S', '-B', '-c', script],
    command: pythonPath,
    options: {
      cwd: projectRoot,
      env: isolatedPythonEnvironment(sourceEnvironment),
      stdio: 'inherit',
      windowsHide: true
    }
  }
}

export function runSelectedPythonTests({
  projectRoot = defaultProjectRoot,
  execute = spawnSync,
  attest = attestSelectedPythonEnvironment,
  sourceEnvironment = process.env
} = {}) {
  projectRoot = resolve(projectRoot)
  attest(projectRoot)
  const invocation = selectedPythonTestInvocation({ projectRoot, sourceEnvironment })
  checkedProcessResult(
    execute(invocation.command, invocation.args, invocation.options),
    'release-selected isolated Python tests'
  )
  attest(projectRoot)
}

function main(argv) {
  if (argv.length !== 1 || !['sync', 'attest', 'test', 'build-engine'].includes(argv[0])) {
    throw new Error('usage: node python-release-policy.mjs sync | attest | test | build-engine')
  }
  if (argv[0] === 'sync') syncSelectedPythonEnvironment()
  else if (argv[0] === 'attest') attestSelectedPythonEnvironment(defaultProjectRoot)
  else if (argv[0] === 'test') runSelectedPythonTests()
  else buildSelectedPythonEngine()
}

if (resolve(process.argv[1] || '').toLowerCase() === resolve(scriptPath).toLowerCase()) {
  try {
    main(process.argv.slice(2))
  } catch (error) {
    console.error(`[python-release-policy] BLOCKED: ${error.message}`)
    process.exitCode = 1
  }
}
