import { createHash } from 'node:crypto'
import {
  closeSync,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  readdirSync,
  readSync,
  realpathSync
} from 'node:fs'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve, sep } from 'node:path'

import { readTreeManifest, verifyTreeAgainstManifest } from './installer-closure.mjs'


const SHA256 = /^[0-9a-f]{64}$/
const CYCLONEDX_15_SCHEMA = 'http://cyclonedx.org/schema/bom-1.5.schema.json'
const REVIEWED_NATIVE_ARTIFACT = /(?:\.exe|\.dll|\.node|\.pyd|\.so(?:\.[^/]*)?|\.dylib|\.gguf|\.onnx|\.pak|\.dat|\.bin)$/i
const MAX_NATIVE_HEADER_OFFSET = 1024 * 1024
const MACH_O_MAGICS = new Set(['feedface', 'cefaedfe', 'feedfacf', 'cffaedfe', 'cafebabe', 'bebafeca', 'cafebabf', 'bfbafeca'])
export const LICENSE_EVIDENCE_FILES = Object.freeze([
  'PYTHON_LICENSES.json',
  'THIRD_PARTY_NOTICES.json',
  'THIRD_PARTY_NOTICES.html'
])
const SPDX_TOKEN = /\s*(\(|\)|AND\b|OR\b|WITH\b|[A-Za-z0-9][A-Za-z0-9.+-]*)\s*/gy
const PEP508_TOKEN = /\s*(\(|\)|and\b|or\b|==|!=|<=|>=|<|>|[A-Za-z_][A-Za-z0-9_]*|'[^']*'|"[^"]*")\s*/gy
const SPDX_LICENSES = new Set([
  '0BSD',
  'AFL-2.1',
  'AFL-3.0',
  'Apache-1.1',
  'Apache-2.0',
  'Artistic-2.0',
  'BSD-2-Clause',
  'BSD-3-Clause',
  'BSD-4-Clause',
  'BSL-1.0',
  'BlueOak-1.0.0',
  'CC-BY-3.0',
  'CC-BY-4.0',
  'CC0-1.0',
  'CDDL-1.0',
  'CNRI-Python',
  'GPL-2.0-only',
  'GPL-2.0-or-later',
  'GPL-3.0-only',
  'GPL-3.0-or-later',
  'ISC',
  'LGPL-2.0-only',
  'LGPL-2.0-or-later',
  'LGPL-2.1-only',
  'LGPL-2.1-or-later',
  'LGPL-3.0-only',
  'LGPL-3.0-or-later',
  'MIT',
  'MPL-2.0',
  'OpenSSL',
  'PSF-2.0',
  'Python-2.0',
  'Unicode-3.0',
  'Unicode-DFS-2016',
  'Unlicense',
  'WTFPL',
  'Zlib'
])
const SPDX_EXCEPTIONS = new Set([
  'Autoconf-exception-3.0',
  'Bison-exception-2.2',
  'Classpath-exception-2.0',
  'GCC-exception-3.1',
  'LLVM-exception',
  'OpenJDK-assembly-exception-1.0'
])


function canonicalValue(value) {
  if (Array.isArray(value)) return value.map(canonicalValue)
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalValue(value[key])]))
  }
  return value
}


function canonicalBytes(value) {
  return Buffer.from(`${JSON.stringify(canonicalValue(value), null, 2)}\n`, 'utf8')
}


function exactKeys(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be an object`)
  if (Object.keys(value).sort().join(',') !== [...expected].sort().join(',')) {
    throw new Error(`${label} fields are not canonical`)
  }
}


function normalizedPythonName(value) {
  const name = String(value || '').trim().toLowerCase().replace(/[-_.]+/g, '-')
  if (!/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(name)) throw new Error('Python package name is invalid')
  return name
}


function checkedEvidenceTextFile(file, label) {
  exactKeys(file, ['path', 'sha256', 'size', 'text'], label)
  const path = String(file.path || '')
  const text = String(file.text ?? '')
  const bytes = Buffer.from(text, 'utf8')
  if (
    !path ||
    path.includes('\\') ||
    path.startsWith('/') ||
    /^[A-Za-z]:/.test(path) ||
    path.split('/').some((part) => !part || part === '.' || part === '..') ||
    !text.trim() ||
    text.includes('\0') ||
    !Number.isSafeInteger(file.size) ||
    file.size !== bytes.length ||
    !SHA256.test(String(file.sha256 || '')) ||
    createHash('sha256').update(bytes).digest('hex') !== file.sha256
  ) {
    throw new Error(`${label} text/path/size/SHA-256 is invalid`)
  }
  return canonicalValue(file)
}


export function checkedSpdxExpression(value, label = 'license', { allowLicenseRefs = false } = {}) {
  const expression = String(value || '').trim().replace(/\s+/g, ' ')
  if (!expression || /\b(?:UNKNOWN|NOASSERTION|UNLICENSED|NONE)\b/i.test(expression)) {
    throw new Error(`${label} is empty or unknown`)
  }
  const tokens = []
  SPDX_TOKEN.lastIndex = 0
  let offset = 0
  while (offset < expression.length) {
    SPDX_TOKEN.lastIndex = offset
    const match = SPDX_TOKEN.exec(expression)
    if (!match || match.index !== offset) throw new Error(`${label} is not a canonical SPDX expression`)
    tokens.push(match[1])
    offset = SPDX_TOKEN.lastIndex
  }
  let cursor = 0
  const primary = () => {
    const token = tokens[cursor++]
    if (token === '(') {
      disjunction()
      if (tokens[cursor++] !== ')') throw new Error(`${label} has unbalanced SPDX parentheses`)
      return false
    }
    if (
      !SPDX_LICENSES.has(token) &&
      !(allowLicenseRefs && /^LicenseRef-[A-Za-z0-9][A-Za-z0-9.-]*$/.test(token))
    ) {
      throw new Error(`${label} uses an unrecognized SPDX license id: ${token || ''}`)
    }
    return true
  }
  const withException = () => {
    const simpleLicense = primary()
    if (tokens[cursor] === 'WITH') {
      if (!simpleLicense) throw new Error(`${label} applies an SPDX exception to a compound expression`)
      cursor += 1
      const exception = tokens[cursor++]
      if (!SPDX_EXCEPTIONS.has(exception)) {
        throw new Error(`${label} uses an unrecognized SPDX exception id: ${exception || ''}`)
      }
    }
  }
  const conjunction = () => {
    withException()
    while (tokens[cursor] === 'AND') {
      cursor += 1
      withException()
    }
  }
  function disjunction() {
    conjunction()
    while (tokens[cursor] === 'OR') {
      cursor += 1
      conjunction()
    }
  }
  disjunction()
  if (cursor !== tokens.length) throw new Error(`${label} is not a canonical SPDX expression`)
  return expression
}


export function buildNpmLicenseInventory(sbom) {
  if (
    !sbom ||
    sbom.bomFormat !== 'CycloneDX' ||
    sbom.specVersion !== '1.5' ||
    !Array.isArray(sbom.components) ||
    sbom.components.length === 0
  ) {
    throw new Error('npm license evidence requires a non-empty CycloneDX 1.5 SBOM')
  }
  const components = []
  const seen = new Set()
  for (const component of sbom.components) {
    const name = String(component?.name || '').trim()
    const version = String(component?.version || '').trim()
    const purl = String(component?.purl || '').trim()
    if (!name || !version || !purl.startsWith('pkg:npm/') || seen.has(purl)) {
      throw new Error('npm SBOM contains an invalid or duplicate component')
    }
    seen.add(purl)
    if (!Array.isArray(component.licenses) || component.licenses.length !== 1) {
      throw new Error(`npm component ${name}@${version} must declare exactly one SPDX license expression`)
    }
    const entry = component.licenses[0]
    const fields = Object.keys(entry || {}).sort().join(',')
    let declared
    if (fields === 'expression') {
      declared = entry.expression
    } else if (
      fields === 'license' &&
      entry.license &&
      typeof entry.license === 'object' &&
      !Array.isArray(entry.license) &&
      Object.keys(entry.license).sort().join(',') === 'id'
    ) {
      declared = entry.license.id
    } else {
      throw new Error(`npm component ${name}@${version} license fields are not canonical SPDX evidence`)
    }
    components.push({
      licenseExpression: checkedSpdxExpression(declared, `npm component ${name}@${version} license`),
      name,
      purl,
      version
    })
  }
  components.sort((left, right) => left.purl.localeCompare(right.purl, 'en'))
  return canonicalValue({ components, ecosystem: 'npm', schema: 1 })
}


function npmLockDependencyPath(packages, ownerPath, name) {
  let owner = ownerPath
  while (true) {
    const candidate = `${owner ? `${owner}/` : ''}node_modules/${name}`
    if (packages[candidate]) return candidate
    const nested = owner.lastIndexOf('/node_modules/')
    if (nested < 0) break
    owner = owner.slice(0, nested)
  }
  const hoisted = `node_modules/${name}`
  return packages[hoisted] ? hoisted : ''
}


function npmPlatformCompatible(entry, platform = 'win32', architecture = 'x64') {
  const allows = (values, current) => {
    if (values === undefined) return true
    if (!Array.isArray(values) || values.some((value) => typeof value !== 'string' || !value)) return false
    if (values.includes(`!${current}`)) return false
    const positive = values.filter((value) => !value.startsWith('!'))
    return positive.length === 0 || positive.includes(current)
  }
  return allows(entry.os, platform) && allows(entry.cpu, architecture)
}


function npmPayloadLockPaths(packageLock) {
  if (!packageLock || packageLock.lockfileVersion !== 3 || !packageLock.packages?.['']) {
    throw new Error('npm payload inventory requires package-lock v3')
  }
  const packages = packageLock.packages
  const root = packages['']
  const queue = Object.keys(root.dependencies || {}).sort().map((name) => ({ kind: 'required', name, owner: '' }))
  const selected = new Set()
  while (queue.length) {
    const edge = queue.shift()
    const lockPath = npmLockDependencyPath(packages, edge.owner, edge.name)
    if (!lockPath) {
      if (edge.kind === 'optional') continue
      throw new Error(`npm payload dependency is absent from the lock: ${edge.owner || '<root>'}->${edge.name}`)
    }
    const entry = packages[lockPath]
    if (!npmPlatformCompatible(entry)) {
      if (edge.kind === 'optional') continue
      throw new Error(`required npm payload dependency excludes win32-x64: ${lockPath}`)
    }
    if (selected.has(lockPath)) continue
    selected.add(lockPath)
    for (const name of Object.keys(entry.dependencies || {}).sort()) {
      queue.push({ kind: 'required', name, owner: lockPath })
    }
    for (const name of Object.keys(entry.optionalDependencies || {}).sort()) {
      queue.push({ kind: 'optional', name, owner: lockPath })
    }
    for (const name of Object.keys(entry.peerDependencies || {}).sort()) {
      if (entry.peerDependenciesMeta?.[name]?.optional === true) continue
      queue.push({ kind: 'required', name, owner: lockPath })
    }
  }
  return [...selected].sort()
}


function canonicalNpmPurl(name, version) {
  const encodedName = name.startsWith('@') ? `%40${name.slice(1)}` : name
  return `pkg:npm/${encodedName}@${version}`
}


function readReviewedNpmRegistry(projectRoot) {
  const registryPath = join(projectRoot, 'desktop', 'npm-license-registry.json')
  const registry = JSON.parse(readFileSync(registryPath, 'utf8'))
  exactKeys(registry, ['components', 'schema'], 'reviewed npm license registry')
  if (registry.schema !== 2 || !Array.isArray(registry.components)) {
    throw new Error('reviewed npm license registry schema is invalid')
  }
  const byPath = new Map()
  for (const component of registry.components) {
    exactKeys(
      component,
      [
        'integrity',
        'licenseSource',
        'lockPath',
        'manualLegalReviewRequired',
        'name',
        'notice',
        'packageJsonSha256',
        'review',
        'sourceCommit',
        'sourceUrl',
        'spdxExpression',
        'version'
      ],
      'reviewed npm license registry component'
    )
    if (byPath.has(component.lockPath)) throw new Error('reviewed npm license registry contains duplicate lock paths')
    const isPending =
      component.licenseSource === 'metadata-reconstructed' &&
      component.manualLegalReviewRequired === true &&
      component.review === null
    const isReviewed =
      component.licenseSource === 'metadata-reconstructed-reviewed' &&
      component.manualLegalReviewRequired === false &&
      component.review !== null
    if (!isPending && !isReviewed) {
      throw new Error('reviewed npm registry exception review state is inconsistent')
    }
    if (isReviewed) {
      exactKeys(
        component.review,
        [
          'decision',
          'githubCommitUrl',
          'npmVersionUrl',
          'reviewedAt',
          'reviewerRole',
          'scope',
          'upstreamLicenseFileCount',
          'upstreamPackageJsonSha256'
        ],
        'reviewed npm registry engineering review'
      )
      const expectedCommitUrl = component.sourceUrl.replace('/tree/', '/commit/')
      const expectedRegistryName = encodeURIComponent(component.name)
      if (
        component.spdxExpression !== 'MIT' ||
        component.review.decision !== 'approved-for-binary-distribution-notice' ||
        component.review.githubCommitUrl !== expectedCommitUrl ||
        component.review.npmVersionUrl !== `https://registry.npmjs.org/${expectedRegistryName}/${component.version}` ||
        !/^20\d\d-\d\d-\d\d$/u.test(String(component.review.reviewedAt || '')) ||
        component.review.reviewerRole !== 'project-engineering' ||
        component.review.scope !== 'exact-version-metadata-and-standard-mit-notice' ||
        component.review.upstreamLicenseFileCount !== 0 ||
        !/^[0-9a-f]{64}$/u.test(String(component.review.upstreamPackageJsonSha256 || ''))
      ) {
        throw new Error('reviewed npm registry engineering review evidence is invalid')
      }
    }
    byPath.set(component.lockPath, component)
  }
  return byPath
}


export function buildNpmPayloadLicenseInventory({ projectRoot }) {
  projectRoot = resolve(projectRoot)
  const desktopRoot = join(projectRoot, 'desktop')
  const packageLock = JSON.parse(readFileSync(join(desktopRoot, 'package-lock.json'), 'utf8'))
  const registry = readReviewedNpmRegistry(projectRoot)
  const components = []
  const selectedPaths = npmPayloadLockPaths(packageLock)
  for (const lockPath of selectedPaths) {
    const lockEntry = packageLock.packages[lockPath]
    const packageJsonFile = containedRegularFile(desktopRoot, `${lockPath}/package.json`, `npm payload ${lockPath}`)
    const packageJsonBytes = readFileSync(packageJsonFile.path)
    const packageJsonSha256 = createHash('sha256').update(packageJsonBytes).digest('hex')
    let packageJson
    try {
      packageJson = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(packageJsonBytes))
    } catch {
      throw new Error(`npm payload package.json is invalid UTF-8 JSON: ${lockPath}`)
    }
    const name = checkedNpmPackageName(packageJson.name, `npm payload ${lockPath} name`)
    const version = String(packageJson.version || '')
    if (name !== lockPath.split('/node_modules/').at(-1)?.replace(/^node_modules\//, '') && !lockPath.endsWith(`/node_modules/${name}`) && lockPath !== `node_modules/${name}`) {
      throw new Error(`npm payload package path/name mismatch: ${lockPath}`)
    }
    if (version !== lockEntry.version || !/^sha512-[A-Za-z0-9+/]+={0,2}$/.test(String(lockEntry.integrity || ''))) {
      throw new Error(`npm payload package identity/integrity drifted: ${lockPath}`)
    }
    let source
    try {
      source = new URL(lockEntry.resolved)
    } catch {
      throw new Error(`npm payload package resolved URL is invalid: ${lockPath}`)
    }
    if (source.protocol !== 'https:' || source.username || source.password || source.hash) {
      throw new Error(`npm payload package resolved URL is unsafe: ${lockPath}`)
    }
    const licenseExpression = checkedSpdxExpression(packageJson.license, `npm payload ${name}@${version} license`)
    const packageRoot = join(desktopRoot, ...lockPath.split('/'))
    const noticeNames = readdirSync(packageRoot)
      .filter((fileName) => /^(?:licen[cs]e|copying|notice|copyright)(?:$|[._-])/i.test(fileName))
      .sort()
    const notices = noticeNames.map((fileName) => {
      const file = containedRegularFile(packageRoot, fileName, `npm payload ${name}@${version} notice`, 2 * 1024 * 1024)
      const bytes = readFileSync(file.path)
      const sha256 = createHash('sha256').update(bytes).digest('hex')
      let text
      try {
        text = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
      } catch {
        throw new Error(`npm payload notice is not UTF-8: ${lockPath}/${fileName}`)
      }
      return checkedEvidenceTextFile(
        { path: `npm/${lockPath}/${fileName}`, sha256, size: bytes.length, text },
        `npm payload ${name}@${version} notice`
      )
    })
    let licenseSource = 'installed-package-file'
    let manualLegalReviewRequired = false
    if (notices.length === 0) {
      const reviewed = registry.get(lockPath)
      if (
        !reviewed ||
        reviewed.name !== name ||
        reviewed.version !== version ||
        reviewed.integrity !== lockEntry.integrity ||
        reviewed.packageJsonSha256 !== packageJsonSha256 ||
        reviewed.spdxExpression !== licenseExpression ||
        !/^[0-9a-f]{40}$/.test(String(reviewed.sourceCommit || ''))
      ) {
        throw new Error(`npm payload has no installed or exact reviewed license text: ${lockPath}`)
      }
      const sourceUrl = new URL(reviewed.sourceUrl)
      if (sourceUrl.protocol !== 'https:' || !sourceUrl.pathname.includes(reviewed.sourceCommit)) {
        throw new Error(`reviewed npm license source is unsafe or unpinned: ${lockPath}`)
      }
      exactKeys(reviewed.notice, ['path', 'sha256', 'size'], `reviewed npm notice ${lockPath}`)
      const file = containedRegularFile(join(projectRoot, 'desktop'), reviewed.notice.path, `reviewed npm notice ${lockPath}`)
      if (file.info.size !== reviewed.notice.size) throw new Error(`reviewed npm notice size drifted: ${lockPath}`)
      notices.push(checkedNotice(
        file.path,
        `reviewed/npm/${name}@${version}/${reviewed.notice.path.split('/').at(-1)}`,
        reviewed.notice.sha256,
        `reviewed npm notice ${lockPath}`
      ))
      licenseSource = reviewed.licenseSource
      manualLegalReviewRequired = reviewed.manualLegalReviewRequired
    }
    components.push({
      integrity: lockEntry.integrity,
      licenseExpression,
      licenseSource,
      lockPath,
      manualLegalReviewRequired,
      name,
      notices,
      packageJsonSha256,
      purl: canonicalNpmPurl(name, version),
      resolved: source.href,
      version
    })
  }
  const unused = [...registry.keys()].filter((lockPath) => !selectedPaths.includes(lockPath))
  if (unused.length) throw new Error(`reviewed npm license registry contains unused entries: ${unused.join(',')}`)
  return canonicalValue({ components, ecosystem: 'npm-payload', platform: 'win32-x64', schema: 2 })
}


function compareMarkerValues(left, operator, right, versionComparison) {
  let comparison
  if (versionComparison) {
    const parse = (value) => String(value).split(/[.+-]/).map((part) => (/^\d+$/.test(part) ? Number(part) : part))
    const leftParts = parse(left)
    const rightParts = parse(right)
    comparison = 0
    for (let index = 0; index < Math.max(leftParts.length, rightParts.length); index += 1) {
      const a = leftParts[index] ?? 0
      const b = rightParts[index] ?? 0
      if (a === b) continue
      comparison = a < b ? -1 : 1
      break
    }
  } else {
    comparison = left === right ? 0 : left < right ? -1 : 1
  }
  if (operator === '==') return comparison === 0
  if (operator === '!=') return comparison !== 0
  if (operator === '<') return comparison < 0
  if (operator === '<=') return comparison <= 0
  if (operator === '>') return comparison > 0
  if (operator === '>=') return comparison >= 0
  throw new Error(`unsupported PEP 508 comparison operator: ${operator}`)
}


export function evaluatePep508Marker(marker, environment) {
  marker = String(marker || '').trim()
  if (!marker || marker.length > 4096) throw new Error('Python SBOM marker is empty or oversized')
  const tokens = []
  PEP508_TOKEN.lastIndex = 0
  let offset = 0
  while (offset < marker.length) {
    PEP508_TOKEN.lastIndex = offset
    const match = PEP508_TOKEN.exec(marker)
    if (!match || match.index !== offset) throw new Error('Python SBOM marker uses unsupported PEP 508 syntax')
    tokens.push(match[1])
    offset = PEP508_TOKEN.lastIndex
  }
  let cursor = 0
  const primary = () => {
    if (tokens[cursor] === '(') {
      cursor += 1
      const result = disjunction()
      if (tokens[cursor++] !== ')') throw new Error('Python SBOM marker has unbalanced parentheses')
      return result
    }
    const variable = tokens[cursor++]
    const operator = tokens[cursor++]
    const quoted = tokens[cursor++]
    if (
      !Object.hasOwn(environment, variable) ||
      !['==', '!=', '<', '<=', '>', '>='].includes(operator) ||
      !/^(['"]).*\1$/.test(String(quoted || ''))
    ) {
      throw new Error('Python SBOM marker comparison is unsupported or incomplete')
    }
    const expected = quoted.slice(1, -1)
    return compareMarkerValues(
      String(environment[variable]),
      operator,
      expected,
      variable === 'python_full_version' || variable === 'python_version'
    )
  }
  const conjunction = () => {
    let result = primary()
    while (tokens[cursor] === 'and') {
      cursor += 1
      const next = primary()
      result = result && next
    }
    return result
  }
  function disjunction() {
    let result = conjunction()
    while (tokens[cursor] === 'or') {
      cursor += 1
      const next = conjunction()
      result = result || next
    }
    return result
  }
  const result = disjunction()
  if (cursor !== tokens.length) throw new Error('Python SBOM marker has trailing unsupported syntax')
  return result
}


export function pythonMarkerEnvironment(runtimeVersion, overrides = {}) {
  const isWindows = process.platform === 'win32'
  const machine = isWindows
    ? process.arch === 'x64'
      ? 'AMD64'
      : process.arch
    : process.arch === 'x64'
      ? 'x86_64'
      : process.arch
  return {
    implementation_name: overrides.implementationName || 'cpython',
    os_name: overrides.osName || (isWindows ? 'nt' : 'posix'),
    platform_machine: overrides.platformMachine || machine,
    platform_python_implementation: overrides.platformPythonImplementation || 'CPython',
    platform_system: overrides.platformSystem || (isWindows ? 'Windows' : process.platform),
    python_full_version: runtimeVersion,
    python_version: runtimeVersion.split('.').slice(0, 2).join('.'),
    sys_platform: overrides.sysPlatform || process.platform
  }
}


export function validatePythonLicenseInventory(document, sbom) {
  exactKeys(document, ['components', 'runtime', 'schema', 'tool'], 'Python license evidence')
  exactKeys(document.tool, ['name', 'version'], 'Python license exporter identity')
  exactKeys(document.runtime, ['implementation', 'licenseFile', 'version'], 'Python runtime license evidence')
  if (
    document.schema !== 1 ||
    document.tool.name !== 'nachuan-python-license-exporter' ||
    document.tool.version !== '1.0.0' ||
    document.runtime.implementation !== 'CPython' ||
    !/^\d+\.\d+\.\d+$/.test(String(document.runtime.version || ''))
  ) {
    throw new Error('Python license evidence schema/tool/runtime identity is invalid')
  }
  checkedEvidenceTextFile(document.runtime.licenseFile, 'CPython runtime license file')
  if (
    !sbom ||
    sbom.bomFormat !== 'CycloneDX' ||
    sbom.specVersion !== '1.5' ||
    !Array.isArray(sbom.components) ||
    sbom.components.length === 0 ||
    !Array.isArray(document.components)
  ) {
    throw new Error('Python license evidence requires a non-empty CycloneDX 1.5 SBOM')
  }
  const expected = new Map()
  for (const component of sbom.components) {
    const name = normalizedPythonName(component?.name)
    const version = String(component?.version || '').trim()
    const purl = String(component?.purl || '')
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
    const key = `${name}@${version}`
    const versions = expected.get(name) || new Set()
    if (!version || !purl.startsWith('pkg:pypi/') || versions.has(version)) {
      throw new Error('Python SBOM contains an invalid or duplicate component')
    }
    versions.add(version)
    expected.set(name, versions)
  }
  const actual = new Map()
  let previousName = ''
  for (const component of document.components) {
    exactKeys(
      component,
      ['licenseExpression', 'licenseFiles', 'licenseSource', 'name', 'version'],
      'Python license component'
    )
    const name = normalizedPythonName(component.name)
    const version = String(component.version || '').trim()
    const key = `${name}@${version}`
    if (
      !version ||
      name <= previousName ||
      actual.has(name) ||
      ![
        'license-file',
        'metadata-license-expression',
        'metadata-classifier',
        'metadata-license',
        'registry'
      ].includes(
        component.licenseSource
      ) ||
      !Array.isArray(component.licenseFiles) ||
      component.licenseFiles.length === 0
    ) {
      throw new Error('Python license components are invalid, duplicated, or unsorted')
    }
    previousName = name
    checkedSpdxExpression(component.licenseExpression, `Python component ${key} license`)
    let previousPath = ''
    for (const file of component.licenseFiles) {
      checkedEvidenceTextFile(file, `Python component ${key} license file`)
      if (file.path <= previousPath) throw new Error(`Python component ${key} license files are unsorted`)
      previousPath = file.path
    }
    actual.set(name, version)
  }
  if (
    actual.size !== expected.size ||
    [...expected].some(([name, versions]) => !versions.has(actual.get(name)))
  ) {
    throw new Error('Python license evidence does not exactly cover the Python SBOM')
  }
  return canonicalValue(document)
}


function checkedRelativePath(value, label) {
  const path = String(value || '')
  if (
    !path ||
    path.includes('\\') ||
    path.startsWith('/') ||
    /^[A-Za-z]:/.test(path) ||
    path.split('/').some((part) => !part || part === '.' || part === '..')
  ) {
    throw new Error(`${label} must be a controlled relative path`)
  }
  return path
}


function containedRegularFile(root, relativePath, label, maxBytes = 32 * 1024 * 1024) {
  relativePath = checkedRelativePath(relativePath, label)
  const fixedRoot = resolve(root)
  let current = fixedRoot
  for (const part of relativePath.split('/')) {
    current = join(current, part)
    const info = lstatSync(current)
    if (info.isSymbolicLink()) throw new Error(`${label} traverses a filesystem redirect`)
  }
  const path = resolve(current)
  const prefix = fixedRoot.endsWith(sep) ? fixedRoot : `${fixedRoot}${sep}`
  const comparablePath = process.platform === 'win32' ? path.toLowerCase() : path
  const comparablePrefix = process.platform === 'win32' ? prefix.toLowerCase() : prefix
  const info = lstatSync(path)
  if (
    !comparablePath.startsWith(comparablePrefix) ||
    !info.isFile() ||
    info.size <= 0 ||
    info.size > maxBytes
  ) {
    throw new Error(`${label} must be a bounded regular file inside its declared root`)
  }
  return { info, path, relativePath }
}


function sameFileSystemPath(left, right) {
  return process.platform === 'win32'
    ? left.toLowerCase() === right.toLowerCase()
    : left === right
}


function nativeFileIdentity(info) {
  return `${info.dev}:${info.ino}:${info.size}:${info.mtimeNs}:${info.ctimeNs}`
}


function hasNativeExecutableMagic(path, label) {
  const before = lstatSync(path, { bigint: true })
  if (before.isSymbolicLink() || !before.isFile()) {
    throw new Error(`${label} must be an ordinary file before native header inspection`)
  }
  const handle = openSync(path, 'r')
  try {
    const opened = fstatSync(handle, { bigint: true })
    if (!opened.isFile() || nativeFileIdentity(opened) !== nativeFileIdentity(before)) {
      throw new Error(`${label} changed identity before native header inspection`)
    }
    const available = Number(opened.size < 64n ? opened.size : 64n)
    const header = Buffer.alloc(available)
    const count = available ? readSync(handle, header, 0, available, 0) : 0
    let detected = false
    if (count >= 4) {
      const magic = header.subarray(0, 4).toString('hex')
      detected =
        magic === '7f454c46' ||
        magic === '0061736d' ||
        MACH_O_MAGICS.has(magic)
    }
    if (!detected && count >= 64 && header[0] === 0x4d && header[1] === 0x5a) {
      const peOffset = header.readUInt32LE(0x3c)
      if (
        peOffset >= 64 &&
        peOffset <= MAX_NATIVE_HEADER_OFFSET &&
        BigInt(peOffset + 4) <= opened.size
      ) {
        const signature = Buffer.alloc(4)
        detected =
          readSync(handle, signature, 0, signature.length, peOffset) === signature.length &&
          signature.equals(Buffer.from([0x50, 0x45, 0x00, 0x00]))
      }
    }
    const after = fstatSync(handle, { bigint: true })
    if (nativeFileIdentity(after) !== nativeFileIdentity(opened)) {
      throw new Error(`${label} changed while inspecting its native header`)
    }
    return detected
  } finally {
    closeSync(handle)
  }
}


function isNativeArtifact(path, relativePath) {
  return REVIEWED_NATIVE_ARTIFACT.test(relativePath) || hasNativeExecutableMagic(path, relativePath)
}


function nativeArtifacts(root) {
  const fixedRoot = resolve(root)
  const rootInfo = lstatSync(fixedRoot)
  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) {
    throw new Error('packaged native inventory root must be a real directory')
  }
  const fixedRootReal = realpathSync.native(fixedRoot)
  const files = []
  const pending = [{ path: fixedRoot, realPath: fixedRootReal, relativePath: '' }]
  let directoryCount = 0
  let fileCount = 0
  while (pending.length) {
    const directory = pending.pop()
    directoryCount += 1
    if (directoryCount > 4096) throw new Error('packaged native inventory has too many directories')
    const entries = readdirSync(directory.path, { withFileTypes: true })
      .sort((left, right) => (left.name < right.name ? -1 : left.name > right.name ? 1 : 0))
    for (const entry of entries) {
      const relativePath = directory.relativePath ? `${directory.relativePath}/${entry.name}` : entry.name
      const path = join(directory.path, entry.name)
      const info = lstatSync(path)
      if (entry.isSymbolicLink() || info.isSymbolicLink()) {
        throw new Error(`packaged native inventory contains a redirect: ${relativePath}`)
      }
      const realPath = realpathSync.native(path)
      const expectedRealPath = join(directory.realPath, entry.name)
      if (!sameFileSystemPath(realPath, expectedRealPath)) {
        throw new Error(`packaged native inventory traverses a reparse point: ${relativePath}`)
      }
      if (info.isDirectory()) {
        pending.push({ path, realPath, relativePath })
      } else if (info.isFile()) {
        fileCount += 1
        if (fileCount > 100_000) throw new Error('packaged native inventory has too many files')
        if (isNativeArtifact(path, relativePath)) files.push(relativePath)
      } else {
        throw new Error(`packaged native inventory contains a special file: ${relativePath}`)
      }
    }
  }
  files.sort((left, right) => (left < right ? -1 : left > right ? 1 : 0))
  if (!files.length) throw new Error('packaged native inventory is empty')
  return files
}


function checkedNativeInventoryForSbom(document, actualArtifacts) {
  exactKeys(document, ['components', 'ecosystem', 'schema'], 'packaged native license inventory')
  if (document.schema !== 1 || document.ecosystem !== 'native' || !Array.isArray(document.components)) {
    throw new Error('packaged native license inventory schema is invalid')
  }
  const actual = new Set(actualArtifacts)
  const covered = new Set()
  const mappings = new Map(actualArtifacts.map((path) => [path, []]))
  const componentArtifacts = new Map()
  let previousId = ''
  const components = []
  for (const component of document.components) {
    exactKeys(
      component,
      ['artifacts', 'id', 'licenseExpression', 'name', 'notices', 'sourceUrl', 'version'],
      'packaged native license component'
    )
    const id = String(component.id || '')
    const name = String(component.name || '').trim()
    const version = String(component.version || '').trim()
    if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(id) || id <= previousId || !name || !version) {
      throw new Error('packaged native license component identity is invalid, duplicated, or unsorted')
    }
    previousId = id
    const licenseExpression = checkedSpdxExpression(
      component.licenseExpression,
      `packaged native license component ${id}`,
      { allowLicenseRefs: true }
    )
    let source
    try {
      source = new URL(component.sourceUrl)
    } catch {
      throw new Error(`packaged native license component ${id} source URL is invalid`)
    }
    if (source.protocol !== 'https:' || source.username || source.password || source.hash) {
      throw new Error(`packaged native license component ${id} source URL is unsafe`)
    }
    if (!Array.isArray(component.notices) || component.notices.length === 0) {
      throw new Error(`packaged native license component ${id} notice set is empty`)
    }
    for (const notice of component.notices) {
      checkedEvidenceTextFile(notice, `packaged native license component ${id} notice`)
    }
    if (!Array.isArray(component.artifacts) || component.artifacts.length === 0) {
      throw new Error(`packaged native license component ${id} artifact set is empty`)
    }
    let previousArtifact = ''
    const artifacts = []
    for (const rawPath of component.artifacts) {
      const path = checkedRelativePath(rawPath, `packaged native license component ${id} artifact`)
      if (path <= previousArtifact || !actual.has(path)) {
        throw new Error(`packaged native license component ${id} artifact is missing, duplicated, or unsorted: ${path}`)
      }
      previousArtifact = path
      covered.add(path)
      mappings.get(path).push({ id, licenseExpression })
      artifacts.push(path)
    }
    componentArtifacts.set(id, artifacts)
    components.push({
      'bom-ref': `native-license:${id}`,
      externalReferences: [{ type: 'distribution', url: source.href }],
      licenses: [{ expression: licenseExpression }],
      name,
      type: 'library',
      version
    })
  }
  if (covered.size !== actual.size || actualArtifacts.some((path) => !covered.has(path))) {
    throw new Error('packaged native license inventory does not exactly cover final native artifacts')
  }
  return { componentArtifacts, components, mappings }
}


function combinedNativeLicenseExpression(mapping, path) {
  const expressions = [...new Set(mapping.map(({ licenseExpression }) => licenseExpression))]
    .sort((left, right) => (left < right ? -1 : left > right ? 1 : 0))
  if (!expressions.length) throw new Error(`native artifact has no reviewed license expression: ${path}`)
  const expression = expressions.length === 1
    ? expressions[0]
    : expressions.map((item) => `(${item})`).join(' AND ')
  return checkedSpdxExpression(expression, `native artifact ${path} combined license`, {
    allowLicenseRefs: true
  })
}


function buildNativeDependencies({ componentArtifacts, fileComponents, licenseComponents, rootRef }) {
  const fileRefs = new Map(fileComponents.map((component) => [component.name, component['bom-ref']]))
  const dependencies = [
    {
      dependsOn: licenseComponents.map((component) => component['bom-ref'])
        .sort((left, right) => (left < right ? -1 : left > right ? 1 : 0)),
      ref: rootRef
    },
    ...licenseComponents.map((component) => {
      const id = component['bom-ref'].slice('native-license:'.length)
      const dependsOn = (componentArtifacts.get(id) || []).map((path) => {
        const ref = fileRefs.get(path)
        if (!ref) throw new Error(`native license component ${id} references an unbound file: ${path}`)
        return ref
      }).sort((left, right) => (left < right ? -1 : left > right ? 1 : 0))
      return { dependsOn, ref: component['bom-ref'] }
    }),
    ...fileComponents.map((component) => ({ dependsOn: [], ref: component['bom-ref'] }))
  ]
  dependencies.sort((left, right) => (left.ref < right.ref ? -1 : left.ref > right.ref ? 1 : 0))
  return dependencies
}


function checkedNativeCycloneDxDocument(document) {
  exactKeys(
    document,
    ['$schema', 'bomFormat', 'components', 'dependencies', 'metadata', 'specVersion', 'version'],
    'native CycloneDX document'
  )
  if (
    document.$schema !== CYCLONEDX_15_SCHEMA ||
    document.bomFormat !== 'CycloneDX' ||
    document.specVersion !== '1.5' ||
    document.version !== 1 ||
    !Array.isArray(document.components) ||
    !document.components.length ||
    !Array.isArray(document.dependencies)
  ) {
    throw new Error('native CycloneDX document identity is invalid')
  }
  exactKeys(document.metadata, ['component'], 'native CycloneDX metadata')
  const root = document.metadata.component
  exactKeys(root, ['bom-ref', 'name', 'properties', 'type', 'version'], 'native CycloneDX root component')
  if (
    typeof root['bom-ref'] !== 'string' ||
    !root['bom-ref'] ||
    root.type !== 'application' ||
    root.name !== 'Nachuan native payload' ||
    typeof root.version !== 'string' ||
    !root.version ||
    !Array.isArray(root.properties)
  ) {
    throw new Error('native CycloneDX root component is invalid')
  }

  const refs = new Set([root['bom-ref']])
  const libraryRefs = []
  const fileRefs = []
  const filesByLibrary = new Map()
  for (const component of document.components) {
    if (!component || typeof component !== 'object' || Array.isArray(component)) {
      throw new Error('native CycloneDX contains an invalid component')
    }
    const ref = component['bom-ref']
    if (typeof ref !== 'string' || !ref || refs.has(ref)) {
      throw new Error('native CycloneDX contains a missing or duplicate bom-ref')
    }
    refs.add(ref)
    if (!Array.isArray(component.licenses) || component.licenses.length !== 1) {
      throw new Error(`native CycloneDX component ${ref} must have exactly one SPDX expression`)
    }
    exactKeys(component.licenses[0], ['expression'], `native CycloneDX component ${ref} license`)
    checkedSpdxExpression(component.licenses[0].expression, `native CycloneDX component ${ref} license`, {
      allowLicenseRefs: true
    })
    if (component.type === 'library') {
      exactKeys(
        component,
        ['bom-ref', 'externalReferences', 'licenses', 'name', 'type', 'version'],
        `native CycloneDX library ${ref}`
      )
      if (!ref.startsWith('native-license:')) throw new Error(`native CycloneDX library ref is invalid: ${ref}`)
      libraryRefs.push(ref)
      filesByLibrary.set(ref, [])
      continue
    }
    if (component.type !== 'file') throw new Error(`native CycloneDX component type is invalid: ${ref}`)
    exactKeys(
      component,
      ['bom-ref', 'hashes', 'licenses', 'name', 'properties', 'type'],
      `native CycloneDX file ${ref}`
    )
    if (
      !Array.isArray(component.hashes) ||
      component.hashes.length !== 1 ||
      Object.keys(component.hashes[0] || {}).sort().join(',') !== 'alg,content' ||
      component.hashes[0].alg !== 'SHA-256' ||
      !SHA256.test(String(component.hashes[0].content || '')) ||
      typeof component.name !== 'string' ||
      !component.name ||
      !Array.isArray(component.properties)
    ) {
      throw new Error(`native CycloneDX file component is invalid: ${ref}`)
    }
    if (ref !== `native-file:${component.hashes[0].content}:${component.name}`) {
      throw new Error(`native artifact digest does not match its file bom-ref: ${ref}`)
    }
    const pathProperties = []
    const sizeProperties = []
    const licenseProperties = []
    for (const property of component.properties) {
      exactKeys(property, ['name', 'value'], `native CycloneDX file ${ref} property`)
      if (property.name === 'nachuan:native:path') pathProperties.push(property.value)
      else if (property.name === 'nachuan:native:size') sizeProperties.push(property.value)
      else if (property.name === 'nachuan:license-component-ref') licenseProperties.push(property.value)
      else throw new Error(`native CycloneDX file ${ref} has an unknown property`)
    }
    if (
      pathProperties.length !== 1 ||
      pathProperties[0] !== component.name ||
      sizeProperties.length !== 1 ||
      !/^(?:0|[1-9]\d*)$/.test(String(sizeProperties[0] || '')) ||
      !licenseProperties.length
    ) {
      throw new Error(`native CycloneDX file ${ref} properties are invalid`)
    }
    const sortedLicenseProperties = [...new Set(licenseProperties)]
      .sort((left, right) => (left < right ? -1 : left > right ? 1 : 0))
    if (JSON.stringify(licenseProperties) !== JSON.stringify(sortedLicenseProperties)) {
      throw new Error(`native CycloneDX file ${ref} license refs are duplicated or unsorted`)
    }
    fileRefs.push(ref)
    for (const libraryRef of licenseProperties) {
      if (!filesByLibrary.has(libraryRef)) {
        // The component list always places reviewed libraries before file
        // components; rejecting here also makes that deterministic ordering explicit.
        throw new Error(`native CycloneDX file ${ref} has a dangling license component ref`)
      }
      filesByLibrary.get(libraryRef).push(ref)
    }
  }
  libraryRefs.sort((left, right) => (left < right ? -1 : left > right ? 1 : 0))
  fileRefs.sort((left, right) => (left < right ? -1 : left > right ? 1 : 0))

  if (document.dependencies.length !== refs.size) {
    throw new Error('native CycloneDX dependency graph is not a closed ref set')
  }
  const dependencyByRef = new Map()
  let previousRef = ''
  for (const dependency of document.dependencies) {
    exactKeys(dependency, ['dependsOn', 'ref'], 'native CycloneDX dependency')
    if (
      typeof dependency.ref !== 'string' ||
      !refs.has(dependency.ref) ||
      dependency.ref <= previousRef ||
      dependencyByRef.has(dependency.ref) ||
      !Array.isArray(dependency.dependsOn)
    ) {
      throw new Error('native CycloneDX dependencies are unknown, duplicated, or unsorted')
    }
    previousRef = dependency.ref
    const sorted = [...new Set(dependency.dependsOn)]
      .sort((left, right) => (left < right ? -1 : left > right ? 1 : 0))
    if (
      JSON.stringify(sorted) !== JSON.stringify(dependency.dependsOn) ||
      sorted.some((target) => !refs.has(target) || target === dependency.ref)
    ) {
      throw new Error(`native CycloneDX dependency ${dependency.ref} has a dangling, duplicate, or unsorted target`)
    }
    dependencyByRef.set(dependency.ref, dependency.dependsOn)
  }
  if (JSON.stringify(dependencyByRef.get(root['bom-ref'])) !== JSON.stringify(libraryRefs)) {
    throw new Error('native CycloneDX root dependencies do not exactly cover reviewed libraries')
  }
  for (const libraryRef of libraryRefs) {
    const expectedFiles = filesByLibrary.get(libraryRef)
      .sort((left, right) => (left < right ? -1 : left > right ? 1 : 0))
    if (JSON.stringify(dependencyByRef.get(libraryRef)) !== JSON.stringify(expectedFiles)) {
      throw new Error(`native CycloneDX library dependency does not match mapped files: ${libraryRef}`)
    }
  }
  for (const fileRef of fileRefs) {
    if (JSON.stringify(dependencyByRef.get(fileRef)) !== '[]') {
      throw new Error(`native CycloneDX file must be a dependency leaf: ${fileRef}`)
    }
  }
  return canonicalValue(document)
}


export async function writeNativeCycloneDxSbom({ manifestPath, output, unpackedRoot }) {
  manifestPath = resolve(String(manifestPath || ''))
  output = resolve(String(output || ''))
  unpackedRoot = resolve(String(unpackedRoot || ''))
  await verifyTreeAgainstManifest({ root: unpackedRoot, manifestPath })
  const manifest = await readTreeManifest(manifestPath)
  const inventoryFile = containedRegularFile(
    unpackedRoot,
    'resources/licenses/NATIVE_PAYLOAD_LICENSES.json',
    'packaged native license inventory',
    96 * 1024 * 1024
  )
  const inventoryBytes = await readFile(inventoryFile.path)
  let inventory
  try {
    inventory = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(inventoryBytes))
  } catch {
    throw new Error('packaged native license inventory is not UTF-8 JSON')
  }
  if (!inventoryBytes.equals(canonicalBytes(inventory))) {
    throw new Error('packaged native license inventory bytes are not canonical')
  }
  const manifestFiles = new Map(manifest.files.map((file) => [file.path, file]))
  const nativeFiles = nativeArtifacts(unpackedRoot).map((path) => {
    const file = manifestFiles.get(path)
    if (!file) throw new Error(`native artifact is absent from the final payload manifest: ${path}`)
    return file
  })
  if (!nativeFiles.length) throw new Error('final payload contains no native artifacts')
  const { componentArtifacts, components: licenseComponents, mappings } = checkedNativeInventoryForSbom(
    inventory,
    nativeFiles.map((file) => file.path)
  )
  const fileComponents = nativeFiles.map((file) => {
    const mapping = mappings.get(file.path)
    return {
      'bom-ref': `native-file:${file.sha256}:${file.path}`,
      hashes: [{ alg: 'SHA-256', content: file.sha256 }],
      licenses: [{ expression: combinedNativeLicenseExpression(mapping, file.path) }],
      name: file.path,
      properties: [
        { name: 'nachuan:native:path', value: file.path },
        { name: 'nachuan:native:size', value: String(file.size) },
        ...mapping.map(({ id }) => ({
          name: 'nachuan:license-component-ref',
          value: `native-license:${id}`
        }))
      ],
      type: 'file'
    }
  })
  const rootRef = `nachuan-native-payload:${manifest.version}:${manifest.variant}:win32-x64`
  const document = checkedNativeCycloneDxDocument({
    $schema: CYCLONEDX_15_SCHEMA,
    bomFormat: 'CycloneDX',
    components: [...licenseComponents, ...fileComponents],
    dependencies: buildNativeDependencies({
      componentArtifacts,
      fileComponents,
      licenseComponents,
      rootRef
    }),
    metadata: {
      component: {
        'bom-ref': rootRef,
        name: 'Nachuan native payload',
        properties: [
          { name: 'nachuan:release:variant', value: manifest.variant },
          { name: 'nachuan:release:target', value: 'win32-x64' }
        ],
        type: 'application',
        version: manifest.version
      }
    },
    specVersion: '1.5',
    version: 1
  })
  const bytes = canonicalBytes(document)
  await writeFile(output, bytes, { flag: 'wx' })
  const written = await readFile(output)
  if (!written.equals(bytes)) throw new Error('native CycloneDX SBOM drifted while writing')
  const finalManifest = await readTreeManifest(manifestPath)
  if (JSON.stringify(finalManifest) !== JSON.stringify(manifest)) {
    throw new Error('win-unpacked manifest drifted while generating native CycloneDX SBOM')
  }
  await verifyTreeAgainstManifest({ root: unpackedRoot, manifestPath })
  return {
    fileCount: nativeFiles.length,
    output,
    sha256: createHash('sha256').update(bytes).digest('hex'),
    size: bytes.length
  }
}


export async function verifyNativeCycloneDxSbom({ manifestPath, sbomPath, unpackedRoot }) {
  sbomPath = resolve(String(sbomPath || ''))
  const info = lstatSync(sbomPath)
  if (info.isSymbolicLink() || !info.isFile() || info.size <= 0 || info.size > 96 * 1024 * 1024) {
    throw new Error('native CycloneDX SBOM must be a bounded regular file')
  }
  const actual = await readFile(sbomPath)
  let document
  try {
    document = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(actual))
  } catch {
    throw new Error('native CycloneDX SBOM is not UTF-8 JSON')
  }
  if (!actual.equals(canonicalBytes(document))) {
    throw new Error('native CycloneDX SBOM bytes are not canonical')
  }
  checkedNativeCycloneDxDocument(document)
  const workdir = await mkdtemp(join(tmpdir(), 'nachuan-native-sbom-verify-'))
  try {
    const expectedPath = join(workdir, 'NATIVE_SBOM.cdx.json')
    const expected = await writeNativeCycloneDxSbom({
      manifestPath,
      output: expectedPath,
      unpackedRoot
    })
    const expectedBytes = await readFile(expectedPath)
    if (!actual.equals(expectedBytes)) {
      throw new Error('native CycloneDX SBOM does not match the final payload manifest and license inventory')
    }
    const after = await readFile(sbomPath)
    if (!actual.equals(after)) throw new Error('native CycloneDX SBOM drifted while verifying')
    return { fileCount: expected.fileCount, sha256: expected.sha256, size: expected.size }
  } finally {
    await rm(workdir, { recursive: true, force: true })
  }
}


function checkedNotice(path, relativePath, expectedSha256, label) {
  if (!SHA256.test(String(expectedSha256 || ''))) throw new Error(`${label} SHA-256 is invalid`)
  const data = readFileSync(path)
  const actual = createHash('sha256').update(data).digest('hex')
  if (actual !== expectedSha256) throw new Error(`${label} hash drifted`)
  let text
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(data)
  } catch {
    throw new Error(`${label} must be UTF-8 text`)
  }
  if (!text.trim() || text.includes('\0')) throw new Error(`${label} has no usable text`)
  return { path: relativePath, sha256: actual, size: data.length, text }
}


function checkedNpmPackageName(value, label) {
  const name = String(value || '')
  if (!/^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/.test(name)) throw new Error(`${label} is invalid`)
  return name
}


function pythonLicenseComponent(pythonLicenses, packageName, label) {
  const normalized = normalizedPythonName(packageName)
  const matches = (pythonLicenses?.components || []).filter(
    (component) => normalizedPythonName(component?.name) === normalized
  )
  if (matches.length !== 1) throw new Error(`${label} is absent or duplicated in Python license evidence`)
  return matches[0]
}


function verifyNativeVersion({ component, packageLock, projectRoot, pythonLicenses }) {
  const id = component.id
  const proof = component.versionProof
  if (proof?.kind === 'npm-lock') {
    exactKeys(proof, ['kind', 'package'], `native component ${id} version proof`)
    const packageName = checkedNpmPackageName(proof.package, `native component ${id} npm package`)
    if (packageLock.packages[`node_modules/${packageName}`]?.version !== component.version) {
      throw new Error(`native component ${id} version drifted from npm lock`)
    }
    return
  }
  if (proof?.kind === 'python-runtime') {
    exactKeys(proof, ['kind'], `native component ${id} version proof`)
    if (pythonLicenses?.runtime?.implementation !== 'CPython' || pythonLicenses.runtime.version !== component.version) {
      throw new Error(`native component ${id} version drifted from the CPython runtime`)
    }
    return
  }
  if (proof?.kind === 'python-distribution') {
    exactKeys(proof, ['kind', 'package'], `native component ${id} version proof`)
    const distribution = pythonLicenseComponent(pythonLicenses, proof.package, `native component ${id}`)
    if (distribution.version !== component.version) {
      throw new Error(`native component ${id} version drifted from Python license evidence`)
    }
    return
  }
  if (proof?.kind === 'project-file') {
    exactKeys(proof, ['kind', 'path', 'sha256'], `native component ${id} version proof`)
    const file = containedRegularFile(projectRoot, proof.path, `native component ${id} version proof`)
    const actual = createHash('sha256').update(readFileSync(file.path)).digest('hex')
    if (!SHA256.test(String(proof.sha256 || '')) || actual !== proof.sha256) {
      throw new Error(`native component ${id} project version proof hash drifted`)
    }
    return
  }
  throw new Error(`native component ${id} version proof kind is unsupported`)
}


function resolveNativeNotice({
  component,
  notice,
  packageLock,
  planned,
  projectRoot,
  pythonLicenses,
  unpackedRoot
}) {
  const id = component.id
  const label = `native component ${id} notice`
  if (notice?.location === 'packaged' || notice?.location === 'project') {
    exactKeys(notice, ['location', 'path', 'sha256'], label)
    const root = notice.location === 'packaged' ? unpackedRoot : projectRoot
    // electron-builder renames the upstream Electron archive's LICENSE to
    // LICENSE.electron.txt.  The pre-pack plan reads the exact verified
    // upstream archive extraction while the post-pack gate reads the renamed
    // final file; both are bound to the same reviewed hash and display path.
    const sourcePath =
      planned && notice.location === 'packaged' && notice.path === 'LICENSE.electron.txt'
        ? 'LICENSE'
        : notice.path
    const file = containedRegularFile(root, sourcePath, label)
    const display = notice.location === 'packaged' ? notice.path : `project/${file.relativePath}`
    return checkedNotice(file.path, display, notice.sha256, label)
  }
  if (notice?.location === 'media-runtime') {
    exactKeys(notice, ['location', 'path', 'sha256'], label)
    const root = planned
      ? join(projectRoot, 'dist', 'media-notices')
      : join(unpackedRoot, 'resources', 'media-notices')
    const file = containedRegularFile(root, notice.path, label)
    return checkedNotice(
      file.path,
      `resources/media-notices/${file.relativePath}`,
      notice.sha256,
      label
    )
  }
  if (notice?.location === 'npm-package') {
    exactKeys(notice, ['location', 'package', 'path', 'sha256'], label)
    const packageName = checkedNpmPackageName(notice.package, `${label} npm package`)
    if (!packageLock.packages[`node_modules/${packageName}`]?.version) {
      throw new Error(`${label} npm package is absent from the lockfile`)
    }
    const packageRoot = join(projectRoot, 'desktop', 'node_modules', ...packageName.split('/'))
    const file = containedRegularFile(packageRoot, notice.path, label)
    return checkedNotice(file.path, `npm/${packageName}/${file.relativePath}`, notice.sha256, label)
  }
  if (notice?.location === 'python-runtime') {
    exactKeys(notice, ['location', 'path', 'sha256'], label)
    const file = pythonLicenses?.runtime?.licenseFile
    checkedEvidenceTextFile(file, label)
    if (file.path !== notice.path || file.sha256 !== notice.sha256) throw new Error(`${label} hash/path drifted`)
    return { ...canonicalValue(file), path: `python-runtime/${file.path}` }
  }
  if (notice?.location === 'python-distribution') {
    exactKeys(notice, ['location', 'package', 'path', 'sha256'], label)
    const distribution = pythonLicenseComponent(pythonLicenses, notice.package, label)
    const matches = (distribution.licenseFiles || []).filter(
      (file) => file?.path === notice.path && file?.sha256 === notice.sha256
    )
    if (matches.length !== 1) throw new Error(`${label} hash/path is absent or duplicated`)
    const file = checkedEvidenceTextFile(matches[0], label)
    return {
      ...file,
      path: `python-distribution/${normalizedPythonName(notice.package)}/${file.path}`
    }
  }
  throw new Error(`${label} location is unsupported`)
}


export async function validateNativeLicenseRegistry({
  deferredNativeArtifacts = [],
  packageLock,
  plannedUnpackedRoot,
  projectRoot,
  pythonLicenses,
  registry,
  unpackedRoot,
  planned = false
}) {
  exactKeys(registry, ['components', 'schema'], 'native license registry')
  if (registry.schema !== 1 || !Array.isArray(registry.components) || registry.components.length === 0) {
    throw new Error('native license registry must be a non-empty schema 1 document')
  }
  if (!packageLock || packageLock.lockfileVersion !== 3 || !packageLock.packages) {
    throw new Error('native license registry requires npm lockfile v3 package identities')
  }
  if (
    !Array.isArray(deferredNativeArtifacts) ||
    deferredNativeArtifacts.some((path, index) =>
      checkedRelativePath(path, 'deferred native artifact') !== path ||
      (index > 0 && deferredNativeArtifacts[index - 1] >= path)
    )
  ) {
    throw new Error('deferred native artifact set is invalid, duplicated, or unsorted')
  }
  if (planned && deferredNativeArtifacts.length) {
    throw new Error('planned native license inventory cannot defer final artifacts')
  }
  const actualArtifacts = planned
    ? [...new Set(registry.components.flatMap((component) => component?.artifacts || []))].sort()
    : nativeArtifacts(unpackedRoot)
  const gatedArtifacts = [...new Set([...actualArtifacts, ...deferredNativeArtifacts])].sort()
  const packagedNoticeRoot = planned
    ? resolve(plannedUnpackedRoot || join(projectRoot, 'desktop', 'node_modules', 'electron', 'dist'))
    : unpackedRoot
  const registeredArtifacts = new Set()
  const components = []
  let previousId = ''
  for (const component of registry.components) {
    exactKeys(
      component,
      [
        'artifacts',
        'id',
        'name',
        'noticeFiles',
        'sourceUrl',
        'spdxExpression',
        'version',
        'versionProof'
      ],
      'native license registry component'
    )
    const id = String(component.id || '')
    const name = String(component.name || '').trim()
    const version = String(component.version || '').trim()
    if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(id) || id <= previousId || !name || !version) {
      throw new Error('native license registry component identity is invalid, duplicated, or unsorted')
    }
    previousId = id
    let sourceUrl
    try {
      sourceUrl = new URL(component.sourceUrl)
    } catch {
      throw new Error(`native component ${id} source URL is invalid`)
    }
    if (sourceUrl.protocol !== 'https:' || sourceUrl.username || sourceUrl.password || sourceUrl.hash) {
      throw new Error(`native component ${id} source URL must be credential-free HTTPS`)
    }
    verifyNativeVersion({ component, packageLock, projectRoot, pythonLicenses })
    if (!Array.isArray(component.artifacts) || component.artifacts.length === 0) {
      throw new Error(`native component ${id} artifact set is empty`)
    }
    let previousArtifact = ''
    const artifacts = []
    for (const rawPath of component.artifacts) {
      const path = checkedRelativePath(rawPath, `native component ${id} artifact`)
      if (path <= previousArtifact || !gatedArtifacts.includes(path)) {
        throw new Error(`native component ${id} artifact is missing, duplicated, or unsorted: ${path}`)
      }
      previousArtifact = path
      registeredArtifacts.add(path)
      artifacts.push(path)
    }
    if (!Array.isArray(component.noticeFiles) || component.noticeFiles.length === 0) {
      throw new Error(`native component ${id} notice set is empty`)
    }
    const notices = []
    let previousNotice = ''
    for (const notice of component.noticeFiles) {
      const resolvedNotice = resolveNativeNotice({
        component,
        notice,
        packageLock,
        planned,
        projectRoot,
        pythonLicenses,
        unpackedRoot: packagedNoticeRoot
      })
      if (resolvedNotice.path <= previousNotice) {
        throw new Error(`native component ${id} notice files are duplicated or unsorted`)
      }
      previousNotice = resolvedNotice.path
      notices.push(resolvedNotice)
    }
    components.push({
      artifacts,
      id,
      licenseExpression: checkedSpdxExpression(component.spdxExpression, `native component ${id} license`, {
        allowLicenseRefs: true
      }),
      name,
      notices,
      sourceUrl: sourceUrl.href,
      version
    })
  }
  if (
    registeredArtifacts.size !== gatedArtifacts.length ||
    gatedArtifacts.some((path) => !registeredArtifacts.has(path))
  ) {
    throw new Error('native license registry does not exactly cover packaged native artifacts')
  }
  return canonicalValue({ components, ecosystem: 'native', schema: 1 })
}


export async function buildPlannedNativeLicenseInventory({
  electronRuntimeRoot,
  packageLock,
  projectRoot,
  pythonLicenses,
  registry
}) {
  return await validateNativeLicenseRegistry({
    packageLock,
    planned: true,
    plannedUnpackedRoot: electronRuntimeRoot,
    projectRoot,
    pythonLicenses,
    registry,
    unpackedRoot: null
  })
}


function htmlEscape(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;')
}


export function buildThirdPartyNotices({ nativeInventory, npmInventory, pythonLicenses }) {
  if (
    nativeInventory?.schema !== 1 ||
    nativeInventory?.ecosystem !== 'native' ||
    !Array.isArray(nativeInventory.components) ||
    npmInventory?.schema !== 2 ||
    npmInventory?.ecosystem !== 'npm-payload' ||
    !Array.isArray(npmInventory.components) ||
    pythonLicenses?.schema !== 1 ||
    pythonLicenses?.tool?.name !== 'nachuan-python-license-exporter' ||
    pythonLicenses?.tool?.version !== '1.0.0' ||
    !Array.isArray(pythonLicenses.components)
  ) {
    throw new Error('third-party notices require validated npm, Python, and native inventories')
  }
  const components = []
  for (const component of nativeInventory.components) {
    const notices = (component.notices || []).map((file) =>
      checkedEvidenceTextFile(file, `native notice ${component.id}`)
    )
    if (!notices.length) throw new Error(`native notice ${component.id} has no license text`)
    components.push({
      artifacts: [...component.artifacts],
      ecosystem: 'native',
      id: `native:${component.id}`,
      licenseExpression: checkedSpdxExpression(component.licenseExpression, `native notice ${component.id}`, {
        allowLicenseRefs: true
      }),
      name: component.name,
      notices,
      source: component.sourceUrl,
      version: component.version
    })
  }
  for (const component of npmInventory.components) {
    const notices = (component.notices || []).map((file) =>
      checkedEvidenceTextFile(file, `npm payload notice ${component.lockPath || component.name}`)
    )
    if (!notices.length) throw new Error(`npm payload notice ${component.name} has no license text`)
    components.push({
      artifacts: [],
      ecosystem: 'npm',
      id: `npm:${component.lockPath}`,
      licenseExpression: checkedSpdxExpression(component.licenseExpression, `npm notice ${component.name}`),
      name: component.name,
      notices,
      source: component.resolved,
      version: component.version
    })
  }
  for (const component of pythonLicenses.components) {
    const notices = (component.licenseFiles || []).map((file) =>
      checkedEvidenceTextFile(file, `Python notice ${component.name}`)
    )
    if (!notices.length) throw new Error(`Python notice ${component.name} has no license text`)
    components.push({
      artifacts: [],
      ecosystem: 'pypi',
      id: `pypi:${component.name}@${component.version}`,
      licenseExpression: checkedSpdxExpression(
        component.licenseExpression,
        `Python notice ${component.name}`
      ),
      name: component.name,
      notices,
      source: `pkg:pypi/${component.name}@${component.version}`,
      version: component.version
    })
  }
  components.sort((left, right) => left.id.localeCompare(right.id, 'en'))
  const ids = new Set()
  for (const component of components) {
    if (ids.has(component.id)) throw new Error(`third-party notice component is duplicated: ${component.id}`)
    ids.add(component.id)
  }
  const json = canonicalValue({
    components,
    schema: 1,
    tool: { name: 'nachuan-third-party-notices', version: '1.0.0' }
  })
  const sections = json.components.map((component) => {
    const artifacts = component.artifacts.length
      ? `<p><strong>Packaged artifacts:</strong> ${htmlEscape(component.artifacts.join(', '))}</p>`
      : ''
    const notices = component.notices.length
      ? component.notices
          .map(
            (notice) =>
              `<h3>${htmlEscape(notice.path)}</h3>\n` +
              `<p>SHA-256: <code>${htmlEscape(notice.sha256)}</code></p>\n` +
              `<pre>${htmlEscape(notice.text)}</pre>`
          )
          .join('\n')
      : '<p>No separate license text applies to this component.</p>'
    return (
      `<section id="${htmlEscape(component.id)}">\n` +
      `<h2>${htmlEscape(component.name)} ${htmlEscape(component.version)}</h2>\n` +
      `<p><strong>Ecosystem:</strong> ${htmlEscape(component.ecosystem)}<br>` +
      `<strong>License:</strong> <code>${htmlEscape(component.licenseExpression)}</code><br>` +
      `<strong>Source:</strong> ${htmlEscape(component.source)}</p>\n` +
      `${artifacts}\n${notices}\n</section>`
    )
  })
  const html =
    '<!doctype html>\n' +
    '<html lang="en">\n<head>\n<meta charset="utf-8">\n' +
    '<meta name="viewport" content="width=device-width, initial-scale=1">\n' +
    '<title>Nachuan Third-Party Notices</title>\n' +
    '<style>body{font-family:system-ui,sans-serif;max-width:72rem;margin:2rem auto;padding:0 1rem;line-height:1.5}' +
    'section{border-top:1px solid #ccc;padding:1rem 0}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f6f8fa;padding:1rem}' +
    'code{overflow-wrap:anywhere}</style>\n</head>\n<body>\n' +
    '<h1>Nachuan Third-Party Notices</h1>\n' +
    '<p>This document is generated from release-bound npm, Python, and native component evidence.</p>\n' +
    `${sections.join('\n')}\n</body>\n</html>\n`
  return { html, json }
}


export function createPythonLicenseEvidenceClient({ projectRoot, execute }) {
  projectRoot = resolve(projectRoot)
  if (typeof execute !== 'function') throw new Error('Python license evidence requires an explicit command executor')
  const python = join(projectRoot, '.venv', 'Scripts', 'python.exe')
  const exporter = join(projectRoot, 'scripts', 'export_python_licenses.py')
  const registry = join(projectRoot, 'desktop', 'python-license-registry.release.json')
  const frozenLock = join(projectRoot, 'uv.lock')
  return {
    async exportLicenses(pythonSbom) {
      const workdir = await mkdtemp(join(tmpdir(), 'nachuan-python-license-export-'))
      const sbomPath = join(workdir, 'PYTHON_SBOM.cdx.json')
      const outputPath = join(workdir, 'PYTHON_LICENSES.json')
      try {
        await writeFile(sbomPath, canonicalBytes(pythonSbom), { flag: 'wx' })
        const result = await execute(
          python,
          [
            '-I',
            '-B',
            exporter,
            '--sbom',
            sbomPath,
            '--registry',
            registry,
            '--lock',
            frozenLock,
            '--output',
            outputPath
          ],
          {
            cwd: projectRoot,
            env: { PYTHONDONTWRITEBYTECODE: '1', PYTHONNOUSERSITE: '1' },
            label: 'release-selected installed Python license export'
          }
        )
        if (result?.code !== 0) throw new Error('installed Python license export failed')
        const info = lstatSync(outputPath)
        if (info.isSymbolicLink() || !info.isFile() || info.size <= 0 || info.size > 64 * 1024 * 1024) {
          throw new Error('installed Python license export is missing, redirected, empty, or oversized')
        }
        const bytes = await readFile(outputPath)
        let document
        try {
          document = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
        } catch {
          throw new Error('installed Python license export is not UTF-8 JSON')
        }
        if (!bytes.equals(canonicalBytes(document))) {
          throw new Error('installed Python license export bytes are not canonical')
        }
        return validatePythonLicenseInventory(document, pythonSbom)
      } finally {
        await rm(workdir, { recursive: true, force: true })
      }
    }
  }
}


export async function writeLicenseEvidenceFiles({
  nativeInventory,
  npmInventory,
  outputRoot,
  pythonLicenses
}) {
  outputRoot = resolve(outputRoot)
  const info = lstatSync(outputRoot)
  if (!info.isDirectory() || info.isSymbolicLink()) {
    throw new Error('license evidence output root must be a real directory')
  }
  const notices = buildThirdPartyNotices({ nativeInventory, npmInventory, pythonLicenses })
  const payloads = new Map([
    ['PYTHON_LICENSES.json', canonicalBytes(pythonLicenses)],
    ['THIRD_PARTY_NOTICES.json', canonicalBytes(notices.json)],
    ['THIRD_PARTY_NOTICES.html', Buffer.from(notices.html, 'utf8')]
  ])
  for (const name of LICENSE_EVIDENCE_FILES) {
    await writeFile(join(outputRoot, name), payloads.get(name), { flag: 'wx' })
  }
  for (const name of LICENSE_EVIDENCE_FILES) {
    const path = join(outputRoot, name)
    const outputInfo = lstatSync(path)
    const actual = await readFile(path)
    if (
      outputInfo.isSymbolicLink() ||
      !outputInfo.isFile() ||
      outputInfo.size !== payloads.get(name).length ||
      !actual.equals(payloads.get(name))
    ) {
      throw new Error(`license evidence output drifted while writing: ${name}`)
    }
  }
  return { files: [...LICENSE_EVIDENCE_FILES], notices }
}
