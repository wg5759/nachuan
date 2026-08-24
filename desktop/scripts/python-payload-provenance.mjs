import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import { createReadStream, existsSync, lstatSync, readFileSync } from 'node:fs'
import { readFile, rm, writeFile } from 'node:fs/promises'
import { basename, dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  assertNoForbiddenPythonArchiveEntries,
  attestSelectedPythonEnvironment,
  inspectPyInstallerArchive,
  isolatedPythonEnvironment,
  pythonReleaseInterpreterPath
} from './python-release-policy.mjs'

const scriptPath = fileURLToPath(import.meta.url)
const defaultProjectRoot = resolve(dirname(scriptPath), '..', '..')
export const ENGINE_PYTHON_PAYLOAD_MANIFEST = 'ENGINE_PYTHON_PAYLOAD.json'
const TOC_NAMES = Object.freeze(['Analysis-00.toc', 'EXE-00.toc', 'PKG-00.toc', 'PYZ-00.toc'])
const SHA256 = /^[0-9a-f]{64}$/

const canonicalValue = (value) =>
  Array.isArray(value)
    ? value.map(canonicalValue)
    : value && typeof value === 'object'
      ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalValue(value[key])]))
      : value
const canonicalBytes = (value) => Buffer.from(`${JSON.stringify(canonicalValue(value), null, 2)}\n`, 'utf8')

async function descriptor(path, name = basename(path)) {
  const info = lstatSync(path)
  if (info.isSymbolicLink() || !info.isFile() || info.size <= 0 || info.size > 2 * 1024 * 1024 * 1024) {
    throw new Error(`payload evidence input must be a bounded regular file: ${name}`)
  }
  const hash = createHash('sha256')
  await new Promise((accept, reject) => {
    const source = createReadStream(path)
    source.on('data', (chunk) => hash.update(chunk))
    source.once('error', reject)
    source.once('end', accept)
  })
  return { name, sha256: hash.digest('hex'), size: info.size }
}

function normalizedArchiveName(value) {
  const name = String(value || '').trim().replaceAll('\\', '/')
  if (!name || name.length > 4096 || name.includes('\0') || name.startsWith('/') || name.split('/').includes('..')) {
    throw new Error('PyInstaller archive entry name is invalid')
  }
  return name
}

function checkedOwner(owner, selected) {
  const fields = Object.keys(owner || {}).sort().join(',')
  if (fields !== 'kind,name,version' || !owner.name || !owner.version) {
    throw new Error('PyInstaller payload owner identity is invalid')
  }
  if (owner.kind === 'python-distribution' || owner.kind === 'python-namespace-marker') {
    if (!selected.has(`${owner.name}\0${owner.version}`)) {
      throw new Error(`PyInstaller payload owner is absent from the selected lock: ${owner.name}@${owner.version}`)
    }
  } else if (
    ![
      'build-option',
      'build-output',
      'os-runtime',
      'project-source',
      'python-runtime'
    ].includes(owner.kind)
  ) {
    throw new Error(`PyInstaller payload uses an unsupported owner kind: ${owner.kind}`)
  }
}

export function assemblePythonPayloadProvenance({
  archiveEntries,
  engine,
  ownership,
  selectedDistributions,
  tocFiles
}) {
  if (!Array.isArray(archiveEntries) || archiveEntries.length === 0 || archiveEntries.length > 100_000) {
    throw new Error('engine archive entry set is empty or oversized')
  }
  assertNoForbiddenPythonArchiveEntries(archiveEntries, 'engine payload provenance')
  const normalizedEntries = archiveEntries.map(normalizedArchiveName).sort()
  if (new Set(normalizedEntries).size !== normalizedEntries.length) {
    throw new Error('engine archive entry set is duplicated')
  }
  if (!normalizedEntries.includes('engine_main') || !normalizedEntries.includes('PYZ.pyz')) {
    throw new Error('engine archive entry set omits the entry point or PYZ')
  }
  if (!engine || !SHA256.test(String(engine.sha256 || '')) || !Number.isSafeInteger(engine.size) || engine.size <= 0) {
    throw new Error('engine payload descriptor is invalid')
  }
  if (
    !Array.isArray(tocFiles) ||
    tocFiles.length !== TOC_NAMES.length ||
    tocFiles.some((item, index) =>
      item?.name !== TOC_NAMES[index] || !SHA256.test(String(item.sha256 || '')) || !Number.isSafeInteger(item.size) || item.size <= 0
    )
  ) {
    throw new Error('PyInstaller TOC descriptor set is incomplete or unsorted')
  }
  if (!Array.isArray(selectedDistributions) || selectedDistributions.length === 0) {
    throw new Error('selected Python distribution identity set is empty')
  }
  const selected = new Set()
  for (const item of selectedDistributions) {
    if (!item?.name || !item?.version || selected.has(`${item.name}\0${item.version}`)) {
      throw new Error('selected Python distribution identity set is invalid or duplicated')
    }
    selected.add(`${item.name}\0${item.version}`)
  }
  if (ownership?.schema !== 1 || !Array.isArray(ownership.entries) || ownership.entries.length === 0) {
    throw new Error('PyInstaller TOC ownership evidence is missing')
  }
  const archiveSet = new Set(normalizedEntries)
  const components = new Map()
  let previous = ''
  for (const item of ownership.entries) {
    if (
      Object.keys(item || {}).sort().join(',') !== 'destination,owner,scope,source,type' ||
      !item.destination ||
      !item.scope ||
      !item.type
    ) {
      throw new Error('PyInstaller TOC ownership entry is invalid')
    }
    checkedOwner(item.owner, selected)
    const sourcePath = item.source?.path || ''
    const key = `${item.scope}\0${item.destination}\0${item.type}\0${sourcePath}`
    if (key <= previous) throw new Error('PyInstaller TOC ownership entries are duplicated or unsorted')
    previous = key
    if (item.source !== null) {
      if (
        Object.keys(item.source || {}).sort().join(',') !== 'path,sha256,size' ||
        !item.source.path ||
        !SHA256.test(String(item.source.sha256 || '')) ||
        !Number.isSafeInteger(item.source.size) ||
        item.source.size < 0 ||
        (item.source.size === 0 &&
          item.source.sha256 !== 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
      ) {
        throw new Error('PyInstaller TOC source descriptor is invalid')
      }
    } else if (
      item.type !== 'OPTION' &&
      !(item.type === 'PYMODULE' && item.owner?.kind === 'python-namespace-marker')
    ) {
      throw new Error('only PyInstaller OPTION entries or namespace markers may omit a source descriptor')
    }
    if (['package', 'pyz'].includes(item.scope) && item.type !== 'OPTION' && item.source !== null) {
      const destination = normalizedArchiveName(item.destination)
      if (!archiveSet.has(destination)) {
        throw new Error(`PyInstaller TOC entry is absent from the final recursive archive: ${destination}`)
      }
    }
    const componentKey = `${item.owner.kind}:${item.owner.name}@${item.owner.version}`
    components.set(componentKey, item.owner)
  }
  return canonicalValue({
    archiveEntries: normalizedEntries,
    components: [...components.entries()]
      .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
      .map(([, owner]) => owner),
    engine,
    ownershipEntries: ownership.entries,
    schema: 1,
    selectedDistributions,
    tocFiles,
    tool: { name: 'nachuan-python-payload-provenance', version: '1.0.0' }
  })
}

function execute(command, args, options = {}) {
  return new Promise((accept, reject) => {
    execFile(command, args, {
      ...options,
      encoding: 'utf8',
      maxBuffer: 256 * 1024 * 1024,
      timeout: 180_000,
      windowsHide: true
    }, (error, stdout, stderr) => {
      if (error) {
        reject(new Error('PyInstaller TOC ownership export failed', { cause: error }))
        return
      }
      if (String(stderr || '').trim()) {
        reject(new Error('PyInstaller TOC ownership export emitted unexpected stderr'))
        return
      }
      accept(stdout)
    })
  })
}

async function collectOwnership(projectRoot, workRoot, executeCommand = execute) {
  const exporter = join(projectRoot, 'scripts', 'export_python_payload_ownership.py')
  const python = pythonReleaseInterpreterPath(projectRoot)
  const stdout = await executeCommand(
    python,
    [
      '-X',
      'utf8',
      '-I',
      '-S',
      '-B',
      exporter,
      '--project-root',
      projectRoot,
      '--work-root',
      workRoot
    ],
    { cwd: projectRoot, env: isolatedPythonEnvironment() }
  )
  let ownership
  try {
    ownership = JSON.parse(String(stdout || ''))
  } catch {
    throw new Error('PyInstaller TOC ownership export is not JSON')
  }
  return ownership
}

export async function buildPythonPayloadProvenance({
  enginePath,
  projectRoot = defaultProjectRoot,
  workRoot = join(resolve(projectRoot), 'build', 'engine'),
  inspectArchive = inspectPyInstallerArchive,
  collect = collectOwnership
}) {
  projectRoot = resolve(projectRoot)
  workRoot = resolve(workRoot)
  if (workRoot.toLowerCase() !== join(projectRoot, 'build', 'engine').toLowerCase()) {
    throw new Error('payload provenance requires the fixed build/engine work root')
  }
  enginePath = resolve(enginePath)
  const selectedDistributions = attestSelectedPythonEnvironment(projectRoot)
  const [engine, archiveEntries, ownership, ...tocFiles] = await Promise.all([
    descriptor(enginePath, 'engine.payload'),
    inspectArchive(enginePath),
    collect(projectRoot, workRoot),
    ...TOC_NAMES.map((name) => descriptor(join(workRoot, name), name))
  ])
  const document = assemblePythonPayloadProvenance({
    archiveEntries,
    engine,
    ownership,
    selectedDistributions,
    tocFiles
  })
  attestSelectedPythonEnvironment(projectRoot)
  return document
}

export async function writePythonPayloadProvenance({
  enginePath,
  outputPath = join(defaultProjectRoot, 'dist', ENGINE_PYTHON_PAYLOAD_MANIFEST),
  projectRoot = defaultProjectRoot
}) {
  outputPath = resolve(outputPath)
  const document = await buildPythonPayloadProvenance({ enginePath, projectRoot })
  if (existsSync(outputPath)) {
    const info = lstatSync(outputPath)
    if (info.isSymbolicLink() || !info.isFile()) throw new Error('refusing to replace redirected payload provenance')
    await rm(outputPath, { force: true })
  }
  await writeFile(outputPath, canonicalBytes(document), { flag: 'wx' })
  return document
}

export async function verifyPythonPayloadProvenance({
  enginePath,
  manifestPath,
  projectRoot = defaultProjectRoot
}) {
  const bytes = await readFile(resolve(manifestPath))
  let actual
  try {
    actual = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
  } catch {
    throw new Error('engine Python payload provenance is not UTF-8 JSON')
  }
  if (!bytes.equals(canonicalBytes(actual))) throw new Error('engine Python payload provenance is not canonical')
  const expected = await buildPythonPayloadProvenance({ enginePath, projectRoot })
  if (!bytes.equals(canonicalBytes(expected))) {
    throw new Error('engine Python payload provenance drifted from final engine, TOCs, or ownership')
  }
  return actual
}

export async function verifyPackagedPythonPayloadProvenance({
  appOutDir,
  engineName = process.platform === 'win32' ? 'engine.exe' : 'engine',
  projectRoot = defaultProjectRoot
}) {
  projectRoot = resolve(projectRoot)
  appOutDir = resolve(appOutDir)
  const stagedManifest = join(projectRoot, 'dist', ENGINE_PYTHON_PAYLOAD_MANIFEST)
  const packagedManifest = join(appOutDir, 'resources', ENGINE_PYTHON_PAYLOAD_MANIFEST)
  const stagedBytes = await readFile(stagedManifest)
  const packagedBytes = await readFile(packagedManifest)
  if (!stagedBytes.equals(packagedBytes)) {
    throw new Error('packaged engine Python payload provenance differs from the staged manifest')
  }
  const enginePath = join(appOutDir, 'resources', 'engine', engineName)
  return await verifyPythonPayloadProvenance({
    enginePath,
    manifestPath: packagedManifest,
    projectRoot
  })
}

async function main(argv) {
  const [operation, enginePath, manifestPath] = argv
  if (operation === 'generate' && enginePath && !manifestPath) {
    const result = await writePythonPayloadProvenance({ enginePath })
    console.log(`[python-payload] GENERATED entries=${result.ownershipEntries.length} engine=${result.engine.sha256}`)
    return
  }
  if (operation === 'verify' && enginePath && manifestPath) {
    const result = await verifyPythonPayloadProvenance({ enginePath, manifestPath })
    console.log(`[python-payload] VERIFIED entries=${result.ownershipEntries.length} engine=${result.engine.sha256}`)
    return
  }
  throw new Error('usage: python-payload-provenance.mjs generate <engine> | verify <engine> <manifest>')
}

if (resolve(process.argv[1] || '').toLowerCase() === resolve(scriptPath).toLowerCase()) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(`[python-payload] BLOCKED: ${error.message}`)
    process.exitCode = 1
  })
}
