// Post-package release gate. Validation targets the unpacked resources that
// electron-builder actually packaged, not only the mutable staging directory.
import { createHash } from 'node:crypto'
import { createReadStream } from 'node:fs'
import {
  closeSync,
  existsSync,
  lstatSync,
  openSync,
  readFileSync,
  readSync,
  readdirSync,
  statSync
} from 'node:fs'
import { dirname, isAbsolute, join, posix, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

import { extractFile, listPackage } from '@electron/asar'
import { FuseV1Options, getCurrentFuseWire } from '@electron/fuses'
import { load as loadYaml } from 'js-yaml'
import ts from 'typescript'

import { assertClosedReleaseOutput, verifyPackagedReleaseOutput } from './release-output.mjs'
import { scanReleasePaths } from './release-security.mjs'
import { assertNoForbiddenPythonPayload } from './python-release-policy.mjs'
import { verifyPackagedLicenseEvidence } from './license-stage.mjs'
import { verifyPackagedPythonPayloadProvenance } from './python-payload-provenance.mjs'
import {
  assertMediaRuntimeProductionAdmission,
  verifyPreparedMediaRuntime
} from './media-runtime-policy.mjs'
import { verifyInstallationRootInstallerContract } from './installation-root-installer.mjs'

const scriptPath = fileURLToPath(import.meta.url)
const here = dirname(scriptPath)
const defaultRepoRoot = resolve(here, '..', '..')
const MANIFEST_NAME = 'local-runtime-manifest.json'
const SHA256 = /^[0-9a-f]{64}$/
const SERVER_NAMES = new Set(['llama-server', 'llama-server.exe'])
const NATIVE_LIBRARY = /(?:\.dll|\.dylib|\.so(?:\..*)?)$/i
const MAX_MANIFEST_BYTES = 256 * 1024
const MAX_ASAR_BYTES = 512 * 1024 * 1024
const MAX_MAIN_BUNDLE_BYTES = 64 * 1024 * 1024
const MAX_PRELOAD_BUNDLE_BYTES = 8 * 1024 * 1024
const MAX_RENDERER_BUNDLE_BYTES = 16 * 1024 * 1024
const MAX_RENDERER_TOTAL_BYTES = 64 * 1024 * 1024
const MAX_RENDERER_JAVASCRIPT_FILES = 256
const MAX_RENDERER_HTML_BYTES = 1024 * 1024
const MAX_PACKAGED_PACKAGE_JSON_BYTES = 256 * 1024
const MAX_ENGINE_BYTES = 2 * 1024 * 1024 * 1024
const MAX_APP_UPDATE_BYTES = 32 * 1024
const MAX_STORE_RUNTIME_PROFILE_BYTES = 64 * 1024
const STORE_RUNTIME_PROFILE_NAME = 'store-runtime-profile.v1.json'

function ordinalSort(values) {
  return values.sort((left, right) => (left < right ? -1 : left > right ? 1 : 0))
}

function checkedVariant(value) {
  const variant = String(value || '').toLowerCase()
  if (!['lean', 'full'].includes(variant)) throw new Error(`invalid package variant: ${value}`)
  return variant
}

async function sha256File(path) {
  const hash = createHash('sha256')
  await new Promise((accept, reject) => {
    const input = createReadStream(path)
    input.on('data', (chunk) => hash.update(chunk))
    input.on('error', reject)
    input.on('end', accept)
  })
  return hash.digest('hex')
}

function assertGgufMagic(path) {
  const handle = openSync(path, 'r')
  try {
    const magic = Buffer.alloc(4)
    if (readSync(handle, magic, 0, 4, 0) !== 4 || magic.toString('ascii') !== 'GGUF') {
      throw new Error(`packaged model is not GGUF: ${path}`)
    }
  } finally {
    closeSync(handle)
  }
}

function readManifest(resourcesRoot) {
  const manifestPath = join(resourcesRoot, MANIFEST_NAME)
  if (!existsSync(manifestPath)) throw new Error(`local runtime manifest is missing: ${manifestPath}`)
  const info = lstatSync(manifestPath)
  if (info.isSymbolicLink() || !info.isFile() || info.size > MAX_MANIFEST_BYTES) {
    throw new Error('local runtime manifest must be a small regular file')
  }
  let payload
  try {
    payload = JSON.parse(readFileSync(manifestPath, 'utf8'))
  } catch (error) {
    throw new Error(`local runtime manifest is not valid JSON: ${error}`)
  }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload) || payload.schema !== 1) {
    throw new Error('local runtime manifest schema must be 1')
  }
  if (!Array.isArray(payload.artifacts) || payload.artifacts.length > 4096) {
    throw new Error('local runtime manifest artifacts must be a bounded array')
  }
  return { manifestPath, payload }
}

function validateManifestArtifact(resourcesRoot, value, seen) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('local runtime manifest contains a non-object artifact')
  }
  const keys = Object.keys(value).sort().join(',')
  if (keys !== 'path,role,sha256') throw new Error('local runtime manifest artifact fields are not canonical')
  const role = value.role
  const artifactPath = value.path
  const digest = String(value.sha256 || '').toLowerCase()
  if (!['llama-server', 'runtime-dependency', 'model'].includes(role)) {
    throw new Error(`local runtime manifest has invalid role: ${role}`)
  }
  if (
    typeof artifactPath !== 'string' ||
    !artifactPath ||
    artifactPath.includes('\\') ||
    artifactPath.includes('\0') ||
    isAbsolute(artifactPath) ||
    posix.normalize(artifactPath) !== artifactPath ||
    artifactPath.split('/').some((part) => !part || part === '.' || part === '..')
  ) {
    throw new Error(`local runtime manifest path is not controlled and relative: ${artifactPath}`)
  }
  if (!SHA256.test(digest)) throw new Error(`local runtime manifest has invalid SHA-256: ${artifactPath}`)
  const folded = artifactPath.toLowerCase()
  if (seen.has(folded)) throw new Error(`duplicate local runtime manifest path: ${artifactPath}`)
  seen.add(folded)

  const name = posix.basename(artifactPath).toLowerCase()
  const validRolePath =
    (role === 'llama-server' && artifactPath.startsWith('llama/') && SERVER_NAMES.has(name)) ||
    (role === 'runtime-dependency' && artifactPath.startsWith('llama/') && NATIVE_LIBRARY.test(name)) ||
    (role === 'model' && artifactPath.startsWith('models/') && name.endsWith('.gguf'))
  if (!validRolePath) throw new Error(`manifest role/path mismatch: ${role} ${artifactPath}`)

  const resolved = resolve(resourcesRoot, ...artifactPath.split('/'))
  const rel = relative(resolve(resourcesRoot), resolved)
  if (!rel || rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel)) {
    throw new Error(`local runtime manifest path escapes resources: ${artifactPath}`)
  }
  return { role, path: artifactPath, sha256: digest, resolved }
}

function scanLlamaDirectory(resourcesRoot, prepared = false) {
  const root = join(resourcesRoot, 'llama')
  if (!existsSync(root)) return []
  const rootInfo = lstatSync(root)
  if (rootInfo.isSymbolicLink() || !rootInfo.isDirectory()) {
    throw new Error('packaged llama root must be a real directory')
  }
  const artifacts = []
  for (const name of ordinalSort(readdirSync(root))) {
    const path = join(root, name)
    const info = lstatSync(path)
    if (info.isSymbolicLink() || info.isDirectory() || !info.isFile()) {
      throw new Error(`unexpected link/directory in packaged llama runtime: ${name}`)
    }
    const lower = name.toLowerCase()
    if (lower === 'llama-server.payload') {
      if (!prepared || process.platform !== 'win32') {
        throw new Error('llama-server.payload is only valid in the prepared Windows staging tree')
      }
      artifacts.push({ role: 'llama-server', path: 'llama/llama-server.exe', resolved: path })
    } else if (SERVER_NAMES.has(lower)) {
      if (prepared && process.platform === 'win32') {
        throw new Error('prepared Windows llama-server must use the non-executable .payload source name')
      }
      artifacts.push({ role: 'llama-server', path: `llama/${name}`, resolved: path })
    }
    else if (NATIVE_LIBRARY.test(lower)) {
      artifacts.push({ role: 'runtime-dependency', path: `llama/${name}`, resolved: path })
    } else {
      throw new Error(`unlisted executable/data file in packaged llama runtime: ${name}`)
    }
  }
  return artifacts
}

function scanModelsDirectory(resourcesRoot) {
  const root = join(resourcesRoot, 'models')
  if (!existsSync(root)) return []
  const rootInfo = lstatSync(root)
  if (rootInfo.isSymbolicLink() || !rootInfo.isDirectory()) {
    throw new Error('packaged models root must be a real directory')
  }
  const artifacts = []
  for (const name of ordinalSort(readdirSync(root))) {
    const path = join(root, name)
    const child = lstatSync(path)
    if (child.isSymbolicLink() || child.isDirectory() || !child.isFile()) {
      throw new Error(`unexpected link/directory in packaged models: ${name}`)
    }
    if (!name.toLowerCase().endsWith('.gguf')) {
      throw new Error(`unlisted non-GGUF file in packaged models: ${name}`)
    }
    assertGgufMagic(path)
    artifacts.push({ role: 'model', path: `models/${name}`, resolved: path })
  }
  return artifacts
}

/** Independently re-enumerate and hash the packaged runtime tree. */
export async function verifyLocalRuntimeLayout({ resourcesRoot, variant, prepared = false }) {
  resourcesRoot = resolve(resourcesRoot)
  variant = checkedVariant(variant)
  const { payload } = readManifest(resourcesRoot)
  const seen = new Set()
  const declared = payload.artifacts.map((value) => validateManifestArtifact(resourcesRoot, value, seen))
  const actual = [...scanLlamaDirectory(resourcesRoot, prepared), ...scanModelsDirectory(resourcesRoot)]
  const servers = actual.filter(({ role }) => role === 'llama-server')
  const models = actual.filter(({ role }) => role === 'model')
  const dependencies = actual.filter(({ role }) => role === 'runtime-dependency')

  if (variant === 'full' && (servers.length !== 1 || models.length < 1)) {
    throw new Error(
      `full package requires one llama-server and at least one GGUF; found servers=${servers.length}, models=${models.length}`
    )
  }
  if (variant === 'lean' && actual.length) {
    throw new Error('lean package must not contain llama-server, native runtime libraries, or GGUF files')
  }

  const declaredByPath = new Map(declared.map((item) => [item.path.toLowerCase(), item]))
  const actualByPath = new Map(actual.map((item) => [item.path.toLowerCase(), item]))
  if (declaredByPath.size !== actualByPath.size) {
    throw new Error('local runtime manifest does not exactly match packaged artifacts')
  }
  for (const item of actual) {
    const expected = declaredByPath.get(item.path.toLowerCase())
    if (!expected || expected.role !== item.role) {
      throw new Error(`unlisted packaged local-runtime artifact: ${item.path}`)
    }
    const actualDigest = await sha256File(item.resolved)
    if (actualDigest !== expected.sha256) {
      throw new Error(`local runtime SHA-256 mismatch: ${item.path}`)
    }
  }
  for (const item of declared) {
    if (!actualByPath.has(item.path.toLowerCase())) {
      throw new Error(`manifest references a missing packaged artifact: ${item.path}`)
    }
  }

  return {
    artifactCount: actual.length,
    modelCount: models.length,
    runtimeDependencyCount: dependencies.length
  }
}

function checkedPackagedAsarPath(resourcesRoot) {
  resourcesRoot = resolve(resourcesRoot)
  const resourcesInfo = lstatSync(resourcesRoot)
  if (resourcesInfo.isSymbolicLink() || !resourcesInfo.isDirectory()) {
    throw new Error('packaged resources root must be a real directory')
  }
  const asarPath = join(resourcesRoot, 'app.asar')
  if (!existsSync(asarPath)) throw new Error(`packaged app.asar is missing: ${asarPath}`)
  const asarInfo = lstatSync(asarPath)
  if (
    asarInfo.isSymbolicLink() ||
    !asarInfo.isFile() ||
    asarInfo.size <= 0 ||
    asarInfo.size > MAX_ASAR_BYTES
  ) {
    throw new Error('packaged app.asar must be a bounded regular file')
  }
  return asarPath
}

function readPackagedAsarFile(resourcesRoot, archivePath, maxBytes, label) {
  const asarPath = checkedPackagedAsarPath(resourcesRoot)
  let bundle
  try {
    // @electron/asar's lookup follows the host path separator (the archive
    // creation API normalizes names the same way on Windows).
    bundle = extractFile(asarPath, join(...archivePath.split('/')))
  } catch (error) {
    throw new Error(`cannot extract ${archivePath} from packaged app.asar: ${error}`)
  }
  if (!Buffer.isBuffer(bundle) || bundle.length <= 0 || bundle.length > maxBytes) {
    throw new Error(`packaged ${label} bundle must be a bounded non-empty file`)
  }
  const text = bundle.toString('utf8')
  if (!Buffer.from(text, 'utf8').equals(bundle) || text.startsWith('\uFEFF') || text.includes('\0')) {
    throw new Error(`packaged ${label} bundle must be canonical UTF-8 without NUL bytes`)
  }
  return text
}

function normalizedAsarEntries(resourcesRoot) {
  const asarPath = checkedPackagedAsarPath(resourcesRoot)
  let entries
  try {
    entries = listPackage(asarPath)
  } catch (error) {
    throw new Error(`cannot enumerate final packaged app.asar: ${error}`)
  }
  if (!Array.isArray(entries) || entries.length > 100_000) {
    throw new Error('final packaged app.asar entry list must be bounded')
  }
  return entries.map((entry) => String(entry).replace(/\\/g, '/').replace(/^\/+/, ''))
}

function verifyPackagedMainEntryPoint(resourcesRoot) {
  const text = readPackagedAsarFile(
    resourcesRoot,
    'package.json',
    MAX_PACKAGED_PACKAGE_JSON_BYTES,
    'package.json'
  )
  let manifest
  try {
    manifest = JSON.parse(text)
  } catch (error) {
    throw new Error(`final packaged ASAR package entry point is not valid JSON: ${error}`)
  }
  if (
    !manifest ||
    typeof manifest !== 'object' ||
    Array.isArray(manifest) ||
    manifest.main !== './out/main/index.js'
  ) {
    throw new Error(
      'final packaged ASAR package entry point must be exactly ./out/main/index.js'
    )
  }
}

function rendererHtmlEntryPoint(resourcesRoot, indexArchivePath) {
  const html = readPackagedAsarFile(
    resourcesRoot,
    'out/renderer/index.html',
    MAX_RENDERER_HTML_BYTES,
    'renderer HTML'
  )
  const executableHtml = html.replace(/<!--[\s\S]*?-->/g, '')
  if (/<base\b/i.test(executableHtml)) {
    throw new Error('final packaged renderer HTML script path must not be affected by a base element')
  }
  const openingTags = executableHtml.match(/<script\b/gi) ?? []
  const scripts = [...executableHtml.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi)]
  if (openingTags.length !== 1 || scripts.length !== 1) {
    throw new Error('final packaged renderer HTML script closure must contain exactly one script')
  }
  const [, attributes, body] = scripts[0]
  const type = attributes.match(/(?:^|\s)type\s*=\s*(["'])(.*?)\1/i)?.[2]
  const src = attributes.match(/(?:^|\s)src\s*=\s*(["'])(.*?)\1/i)?.[2]
  const expectedSrc = `./assets/${posix.basename(indexArchivePath)}`
  if (type !== 'module' || src !== expectedSrc || body.trim() !== '') {
    throw new Error(
      `final packaged renderer HTML script must load only ${expectedSrc} as an external module`
    )
  }
}

function readPackagedRendererBundles(resourcesRoot) {
  const entries = normalizedAsarEntries(resourcesRoot)
  const candidates = []
  const seen = new Set()
  for (const entry of entries) {
    const folded = entry.toLowerCase()
    if (
      folded.startsWith('out/renderer/') &&
      /\.(?:js|mjs|cjs)$/.test(folded)
    ) {
      if (!/^out\/renderer\/assets\/[A-Za-z0-9][A-Za-z0-9._-]*\.js$/.test(entry)) {
        throw new Error(`final packaged renderer JavaScript path is outside the closed asset set: ${entry}`)
      }
      if (seen.has(folded)) {
        throw new Error(`final packaged renderer JavaScript path is duplicated: ${entry}`)
      }
      seen.add(folded)
      candidates.push(entry)
    }
  }
  if (candidates.length === 0 || candidates.length > MAX_RENDERER_JAVASCRIPT_FILES) {
    throw new Error(
      `final packaged renderer JavaScript file count must be bounded; found ${candidates.length}`
    )
  }
  const indexes = candidates.filter((entry) =>
    /^out\/renderer\/assets\/index-[A-Za-z0-9_-]+\.js$/.test(entry)
  )
  if (indexes.length !== 1) {
    throw new Error(
      `final packaged app.asar must contain exactly one hashed renderer bundle; found ${indexes.length}`
    )
  }
  rendererHtmlEntryPoint(resourcesRoot, indexes[0])

  let totalBytes = 0
  const bundles = candidates.map((archivePath) => {
    const text = readPackagedAsarFile(
      resourcesRoot,
      archivePath,
      MAX_RENDERER_BUNDLE_BYTES,
      `renderer ${archivePath}`
    )
    totalBytes += Buffer.byteLength(text, 'utf8')
    if (totalBytes > MAX_RENDERER_TOTAL_BYTES) {
      throw new Error('packaged renderer JavaScript total must be bounded')
    }
    return { archivePath, text }
  })
  return bundles
}

function verifyPackagedPreloadClosure(resourcesRoot) {
  const candidates = normalizedAsarEntries(resourcesRoot).filter((entry) => {
    const folded = entry.toLowerCase()
    return folded.startsWith('out/preload/') && /\.(?:js|mjs|cjs)$/.test(folded)
  })
  if (candidates.length !== 1 || candidates[0] !== 'out/preload/index.js') {
    throw new Error(
      `final packaged ASAR paid-media preload control plane requires only out/preload/index.js; found ${JSON.stringify(candidates)}`
    )
  }
}

function parseJavaScriptBundle(text, label) {
  const sourceFile = ts.createSourceFile(label, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS)
  if ((sourceFile.parseDiagnostics ?? []).length > 0) {
    throw new Error(`final packaged ${label} is not syntactically valid JavaScript`)
  }
  return sourceFile
}

function someNode(root, predicate) {
  let matched = false
  const visit = (node) => {
    if (matched) return
    if (predicate(node)) {
      matched = true
      return
    }
    ts.forEachChild(node, visit)
  }
  visit(root)
  return matched
}

function propertyAccessParts(expression) {
  while (ts.isParenthesizedExpression(expression)) expression = expression.expression
  if (expression.kind === ts.SyntaxKind.ThisKeyword) return ['this']
  if (ts.isIdentifier(expression)) return [expression.text]
  if (!ts.isPropertyAccessExpression(expression)) return null
  const prefix = propertyAccessParts(expression.expression)
  return prefix ? [...prefix, expression.name.text] : null
}

function propertyAccessEndsWith(expression, expected) {
  const parts = propertyAccessParts(expression)
  return (
    parts !== null &&
    parts.length >= expected.length &&
    expected.every((part, index) => part === parts[parts.length - expected.length + index])
  )
}

function exactPropertyAccess(expression, expected) {
  const parts = propertyAccessParts(expression)
  return parts !== null && parts.length === expected.length && parts.every((part, index) => part === expected[index])
}

function objectProperty(object, name) {
  if (!object || !ts.isObjectLiteralExpression(object)) return null
  for (const property of object.properties) {
    if (!ts.isPropertyAssignment(property)) continue
    const propertyName =
      ts.isIdentifier(property.name) || ts.isStringLiteral(property.name)
        ? property.name.text
        : null
    if (propertyName === name) return property.initializer
  }
  return null
}

function variableInitializer(sourceFile, name) {
  let initializer = null
  someNode(sourceFile, (node) => {
    if (
      ts.isVariableDeclaration(node) &&
      ts.isIdentifier(node.name) &&
      node.name.text === name &&
      node.initializer
    ) {
      initializer = node.initializer
      return true
    }
    return false
  })
  return initializer
}

function hasCall(root, calleeSuffix, firstArgument) {
  return someNode(root, (node) => {
    if (!ts.isCallExpression(node) || !propertyAccessEndsWith(node.expression, calleeSuffix)) {
      return false
    }
    return firstArgument ? firstArgument(node.arguments[0]) : true
  })
}

function isStringLiteralValue(node, value) {
  return Boolean(node && (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) && node.text === value)
}

function verifyMainBundleStructure(mainBundle) {
  const sourceFile = parseJavaScriptBundle(mainBundle, 'main bundle')
  const channels = variableInitializer(sourceFile, 'PAID_MEDIA_IPC_CHANNELS')
  for (const [method, channel, serviceMethod] of [
    ['claim', 'paid-media:claim', 'claim'],
    ['execute', 'paid-media:execute', 'execute'],
    ['pollVideo', 'paid-media:poll-video', 'pollVideo'],
    ['recoverArchive', 'paid-media:recover-archive', 'recoverArchived'],
    ['listArchives', 'paid-media:list-archives', 'listRecoverableArchives']
  ]) {
    if (!isStringLiteralValue(objectProperty(channels, method), channel)) {
      throw new Error(
        `final packaged ASAR is missing paid-media main control plane channel mapping: ${method}`
      )
    }
    const handlerMapped = someNode(sourceFile, (node) => {
      if (
        !ts.isCallExpression(node) ||
        !propertyAccessEndsWith(node.expression, ['ipcMain', 'handle']) ||
        !exactPropertyAccess(node.arguments[0], ['PAID_MEDIA_IPC_CHANNELS', method])
      ) {
        return false
      }
      const handler = node.arguments[1]
      if (!handler || (!ts.isArrowFunction(handler) && !ts.isFunctionExpression(handler))) {
        return false
      }
      return hasCall(handler, ['service', serviceMethod])
    })
    if (!handlerMapped) {
      throw new Error(
        `final packaged ASAR is missing paid-media main control plane ${method} handler/service mapping`
      )
    }
  }

  const exactMainFrame = someNode(sourceFile, (node) =>
    ts.isBinaryExpression(node) &&
    node.operatorToken.kind === ts.SyntaxKind.EqualsEqualsEqualsToken &&
    exactPropertyAccess(node.left, ['event', 'senderFrame']) &&
    exactPropertyAccess(node.right, ['expectedWindow', 'webContents', 'mainFrame'])
  )
  if (!exactMainFrame) {
    throw new Error('final packaged ASAR is missing paid-media main control plane exact mainFrame authorization')
  }
  if (!hasCall(sourceFile, ['requestSingleInstanceLock'])) {
    throw new Error('final packaged ASAR is missing paid-media main control plane single-instance lock')
  }
  const paidEnvironment = someNode(sourceFile, (node) => {
    if (!ts.isPropertyAssignment(node)) return false
    return (
      (ts.isIdentifier(node.name) || ts.isStringLiteral(node.name)) &&
      node.name.text === 'NACHUAN_PAID_MEDIA_API_KEY'
    )
  })
  if (!paidEnvironment) {
    throw new Error('final packaged ASAR is missing paid-media main control plane paid environment binding')
  }

  const browserWindows = []
  const collectBrowserWindows = (node) => {
    if (
      ts.isNewExpression(node) &&
      propertyAccessEndsWith(node.expression, ['BrowserWindow'])
    ) {
      browserWindows.push(node)
    }
    ts.forEachChild(node, collectBrowserWindows)
  }
  collectBrowserWindows(sourceFile)
  if (browserWindows.length === 0) {
    throw new Error('final packaged ASAR paid-media main control plane has no BrowserWindow preload binding')
  }
  for (const browserWindow of browserWindows) {
    const options = browserWindow.arguments?.[0]
    const webPreferences = objectProperty(options, 'webPreferences')
    const bound =
      webPreferences &&
      ts.isCallExpression(webPreferences) &&
      propertyAccessEndsWith(webPreferences.expression, ['windowSecurityPreferences']) &&
      webPreferences.arguments[0] &&
      ts.isCallExpression(webPreferences.arguments[0]) &&
      propertyAccessEndsWith(webPreferences.arguments[0].expression, ['join']) &&
      webPreferences.arguments[0].arguments.some((argument) =>
        isStringLiteralValue(argument, '../preload/index.js')
      )
    if (!bound) {
      throw new Error(
        'final packaged ASAR paid-media main control plane BrowserWindow preload must resolve to ../preload/index.js'
      )
    }
  }

  verifyPaidMediaAssetV2Structure(sourceFile)
  verifyPaidMediaProtocolStructure(sourceFile)
}

function callStart(root, sourceFile, calleeSuffix) {
  let position = -1
  someNode(root, (node) => {
    if (
      ts.isCallExpression(node) &&
      propertyAccessEndsWith(node.expression, calleeSuffix)
    ) {
      position = node.getStart(sourceFile)
      return true
    }
    return false
  })
  return position
}

function callStarts(root, sourceFile, calleeSuffix) {
  const positions = []
  someNode(root, (node) => {
    if (
      ts.isCallExpression(node) &&
      propertyAccessEndsWith(node.expression, calleeSuffix)
    ) {
      positions.push(node.getStart(sourceFile))
    }
    return false
  })
  return positions
}

function recoverableKindStart(root, sourceFile, kind) {
  let position = -1
  someNode(root, (node) => {
    if (
      !ts.isCallExpression(node) ||
      !propertyAccessEndsWith(node.expression, ['runRecoverableMutation']) ||
      !node.arguments[0]
    ) {
      return false
    }
    const argument = node.arguments[0]
    const direct =
      ts.isObjectLiteralExpression(argument) &&
      isStringLiteralValue(objectProperty(argument, 'kind'), kind)
    let bound = false
    if (!direct && ts.isIdentifier(argument)) {
      const candidates = []
      someNode(root, (candidate) => {
        if (
          ts.isVariableDeclaration(candidate) &&
          ts.isIdentifier(candidate.name) &&
          candidate.name.text === argument.text &&
          candidate.initializer &&
          candidate.getStart(sourceFile) < node.getStart(sourceFile) &&
          someNode(candidate.initializer, (nested) =>
            ts.isObjectLiteralExpression(nested) &&
            isStringLiteralValue(objectProperty(nested, 'kind'), kind)
          )
        ) {
          candidates.push(candidate)
        }
        return false
      })
      bound = candidates.length === 1
    }
    if (!direct && !bound) return false
    position = node.getStart(sourceFile)
    return true
  })
  return position
}

function namedFunction(root, name) {
  let found = null
  someNode(root, (node) => {
    if (
      ts.isFunctionDeclaration(node) &&
      node.name?.text === name &&
      node.body
    ) {
      found = node
      return true
    }
    return false
  })
  return found
}

function namedClass(root, name) {
  let found = null
  someNode(root, (node) => {
    if (ts.isClassDeclaration(node) && node.name?.text === name) {
      found = node
      return true
    }
    return false
  })
  return found
}

function classMethod(classNode, name) {
  return classNode?.members.find(
    (member) =>
      ts.isMethodDeclaration(member) &&
      (ts.isIdentifier(member.name) || ts.isStringLiteral(member.name)) &&
      member.name.text === name &&
      member.body
  ) || null
}

function objectFunction(objectNode, name) {
  const value = objectProperty(objectNode, name)
  return value && (ts.isArrowFunction(value) || ts.isFunctionExpression(value)) ? value : null
}

function hasReadyGuard(root) {
  return Boolean(
    root &&
      someNode(root, (node) =>
        ts.isIfStatement(node) &&
        ts.isPrefixUnaryExpression(node.expression) &&
        node.expression.operator === ts.SyntaxKind.ExclamationToken &&
        ts.isIdentifier(node.expression.operand) &&
        node.expression.operand.text === 'paidMediaAssetV2StageReady'
      )
  )
}

export function verifyPaidMediaAssetV2Structure(sourceFile) {
  const controlPlane = namedFunction(sourceFile, 'initializePaidMediaControlPlane')
  let sessionClient = -1
  someNode(controlPlane || sourceFile, (node) => {
    if (
      ts.isNewExpression(node) &&
      propertyAccessEndsWith(node.expression, ['PaidMediaEngineSessionClient'])
    ) {
      sessionClient = node.getStart(sourceFile)
      return true
    }
    return false
  })
  let runtimeInstance = -1
  someNode(controlPlane || sourceFile, (node) => {
    if (
      ts.isNewExpression(node) &&
      propertyAccessEndsWith(node.expression, ['PaidMediaAssetV2Runtime'])
    ) {
      runtimeInstance = node.getStart(sourceFile)
      return true
    }
    return false
  })
  const stageInspection = callStart(controlPlane || sourceFile, sourceFile, ['inspectStageRecovery'])
  const stageReady = callStart(controlPlane || sourceFile, sourceFile, ['activatePaidMediaEngineSessionStage'])
  let readyLatch = -1
  someNode(controlPlane || sourceFile, (node) => {
    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      ts.isIdentifier(node.left) &&
      node.left.text === 'paidMediaAssetV2StageReady' &&
      node.right.kind === ts.SyntaxKind.TrueKeyword
    ) {
      readyLatch = node.getStart(sourceFile)
      return true
    }
    return false
  })

  let executor = null
  someNode(controlPlane || sourceFile, (node) => {
    if (
      ts.isVariableDeclaration(node) &&
      ts.isIdentifier(node.name) &&
      node.name.text === 'paidMediaAssetV2' &&
      node.initializer &&
      ts.isObjectLiteralExpression(node.initializer)
    ) {
      executor = node.initializer
      return true
    }
    return false
  })
  const executeEntry = objectFunction(executor, 'executeImage')
  const ackEntry = objectFunction(executor, 'convergeImageAck')
  const mainExecutorReady =
    hasReadyGuard(executeEntry) &&
    hasReadyGuard(ackEntry) &&
    hasCall(executeEntry, ['paidMediaAssetV2Runtime', 'executeImage']) &&
    hasCall(ackEntry, ['paidMediaAssetV2Runtime', 'convergeImageAck'])

  const runtimeClass = namedClass(sourceFile, 'PaidMediaAssetV2Runtime')
  const executeMethod = classMethod(runtimeClass, 'executeImage')
  const ackMethod = classMethod(runtimeClass, 'convergeImageAckOnce')
  const executeCalls = executeMethod
    ? [
        callStart(executeMethod, sourceFile, ['authority', 'assertOutboundReady']),
        recoverableKindStart(executeMethod, sourceFile, 'asset_v2_dispatch'),
        callStart(executeMethod, sourceFile, ['dependencies', 'createImageAssets']),
        recoverableKindStart(executeMethod, sourceFile, 'asset_v2_stage_reserve'),
        callStart(executeMethod, sourceFile, ['stageHandoff', 'takeStageOpenResult']),
        callStart(executeMethod, sourceFile, ['dependencies', 'downloadAsset']),
        callStart(executeMethod, sourceFile, ['dependencies', 'probeAsset']),
        recoverableKindStart(executeMethod, sourceFile, 'asset_v2_stage_archive'),
        callStart(executeMethod, sourceFile, ['vault', 'verifyArchive']),
        recoverableKindStart(executeMethod, sourceFile, 'asset_v2_result_ready_ack_intent'),
        callStart(executeMethod, sourceFile, ['convergeImageAck'])
      ]
    : []
  const executeIsCausal =
    executeCalls.length === 11 &&
    executeCalls.every((position) => position >= 0) &&
    executeCalls.every((position, index) => index === 0 || position > executeCalls[index - 1])

  const archiveRead = callStart(ackMethod || sourceFile, sourceFile, ['vault', 'verifyArchive'])
  const dispatchRead = callStart(ackMethod || sourceFile, sourceFile, ['vault', 'verifyAssetV2DispatchMarker'])
  const intentRead = callStart(ackMethod || sourceFile, sourceFile, ['vault', 'verifyAssetAckIntent'])
  const remoteAck = callStart(ackMethod || sourceFile, sourceFile, ['dependencies', 'acknowledgeAssets'])
  const ackCompletion = recoverableKindStart(ackMethod || sourceFile, sourceFile, 'asset_v2_ack_completion')
  const completionReadback = Math.max(
    -1,
    ...callStarts(ackMethod || sourceFile, sourceFile, ['vault', 'verifyAssetAckCompletion'])
  )
  const capacityRelease = recoverableKindStart(ackMethod || sourceFile, sourceFile, 'asset_v2_capacity_release')
  const releaseReadback = Math.max(
    -1,
    ...callStarts(ackMethod || sourceFile, sourceFile, ['vault', 'verifyAssetCapacityReleaseAuthorization'])
  )
  const ackIsCausal =
    [archiveRead, dispatchRead, intentRead].every((position) => position >= 0 && position < remoteAck) &&
    remoteAck >= 0 &&
    ackCompletion > remoteAck &&
    completionReadback > ackCompletion &&
    capacityRelease > completionReadback &&
    releaseReadback > capacityRelease
  const failures = [
    [!controlPlane, 'control-plane'],
    [sessionClient < 0, 'session-client'],
    [runtimeInstance <= sessionClient, 'runtime-instance-order'],
    [stageInspection < 0 || stageInspection <= runtimeInstance, 'stage-inspection-order'],
    [stageReady <= stageInspection, 'stage-ready-order'],
    [readyLatch <= stageReady, 'ready-latch-order'],
    [!executor, 'main-executor'],
    [!mainExecutorReady, 'main-executor-guard'],
    [!runtimeClass, 'runtime-class'],
    [!executeMethod, 'execute-method'],
    [!ackMethod, 'ack-method'],
    [!executeIsCausal, `execute-causality(${executeCalls.join('/')})`],
    [!ackIsCausal, `ack-causality(${[archiveRead, dispatchRead, intentRead, remoteAck, ackCompletion, completionReadback, capacityRelease, releaseReadback].join('/')})`]
  ].filter(([failed]) => failed).map(([, label]) => label)
  if (failures.length) {
    throw new Error(
      `final packaged ASAR asset-v2 session/stage/archive/ACK pipeline is incomplete or non-causal: ${failures.join(',')}`
    )
  }
}

function trueLiteral(node) {
  return Boolean(node && node.kind === ts.SyntaxKind.TrueKeyword)
}

function numericLiteralValue(node, expected) {
  return Boolean(node && ts.isNumericLiteral(node) && Number(node.text) === expected)
}

function verifyPaidMediaProtocolStructure(sourceFile) {
  const registered = someNode(sourceFile, (node) => {
    if (
      !ts.isCallExpression(node) ||
      !propertyAccessEndsWith(node.expression, ['protocol', 'registerSchemesAsPrivileged']) ||
      !node.arguments[0] ||
      !ts.isArrayLiteralExpression(node.arguments[0])
    ) {
      return false
    }
    return node.arguments[0].elements.some((entry) => {
      if (!ts.isObjectLiteralExpression(entry)) return false
      const privileges = objectProperty(entry, 'privileges')
      return (
        isStringLiteralValue(objectProperty(entry, 'scheme'), 'nachuan-paid-media') &&
        privileges &&
        ts.isObjectLiteralExpression(privileges) &&
        ['standard', 'secure', 'supportFetchAPI', 'stream'].every((name) =>
          trueLiteral(objectProperty(privileges, name))
        )
      )
    })
  })
  if (!registered) {
    throw new Error(
      'final packaged ASAR is missing privileged nachuan-paid-media protocol registration'
    )
  }

  const handled = someNode(sourceFile, (node) => {
    if (
      !ts.isCallExpression(node) ||
      !propertyAccessEndsWith(node.expression, ['protocol', 'handle']) ||
      !isStringLiteralValue(node.arguments[0], 'nachuan-paid-media')
    ) {
      return false
    }
    const handler = node.arguments[1]
    return Boolean(
      handler &&
        (ts.isArrowFunction(handler) || ts.isFunctionExpression(handler)) &&
        hasCall(handler, ['handlePaidMediaAssetRequest'])
    )
  })
  if (!handled) {
    throw new Error(
      'final packaged ASAR is missing nachuan-paid-media protocol-to-vault handler binding'
    )
  }

  let assetHandler = null
  someNode(sourceFile, (node) => {
    if (
      (ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node)) &&
      node.name?.text === 'handlePaidMediaAssetRequest' &&
      node.body
    ) {
      assetHandler = node
      return true
    }
    return false
  })
  const readsRange =
    assetHandler &&
    someNode(assetHandler, (node) =>
      ts.isCallExpression(node) &&
      propertyAccessEndsWith(node.expression, ['headers', 'get']) &&
      isStringLiteralValue(node.arguments[0], 'range')
    )
  const opensPinnedRange =
    assetHandler &&
    hasCall(assetHandler, ['handle', 'createReadStream']) &&
    hasCall(assetHandler, ['Readable', 'toWeb']) &&
    someNode(assetHandler, (node) =>
      ts.isPropertyAssignment(node) &&
      (ts.isIdentifier(node.name) || ts.isStringLiteral(node.name)) &&
      node.name.text === 'autoClose' &&
      trueLiteral(node.initializer)
    )
  const hasRangeHeaders =
    assetHandler &&
    ['Accept-Ranges', 'Content-Range', 'Content-Length'].every((header) =>
      someNode(assetHandler, (node) => isStringLiteralValue(node, header))
    )
  const hasRangeStatuses =
    assetHandler &&
    [200, 206, 416].every((status) =>
      someNode(assetHandler, (node) => numericLiteralValue(node, status))
    )
  const opensVaultAsset =
    assetHandler &&
    hasCall(assetHandler, ['vault', 'openAsset'])
  if (
    !assetHandler ||
    !readsRange ||
    !opensPinnedRange ||
    !hasRangeHeaders ||
    !hasRangeStatuses ||
    !opensVaultAsset
  ) {
    throw new Error(
      'final packaged ASAR nachuan-paid-media handler is missing pinned GET/HEAD Range semantics'
    )
  }
}

function verifyPreloadBundleStructure(preloadBundle) {
  const sourceFile = parseJavaScriptBundle(preloadBundle, 'preload bundle')
  let invokePaidMedia = null
  someNode(sourceFile, (node) => {
    if (ts.isFunctionDeclaration(node) && node.name?.text === 'invokePaidMedia' && node.body) {
      invokePaidMedia = node
      return true
    }
    return false
  })
  const invokesIpc =
    invokePaidMedia &&
    hasCall(
      invokePaidMedia,
      ['ipcRenderer', 'invoke'],
      (argument) => Boolean(argument && ts.isIdentifier(argument) && argument.text === 'channel')
    )
  const validatesReply =
    invokePaidMedia &&
    someNode(
      invokePaidMedia,
      (node) => isStringLiteralValue(node, 'Invalid paid media IPC reply')
    )
  if (!invokesIpc || !validatesReply) {
    throw new Error(
      'final packaged ASAR is missing paid-media preload control plane invokePaidMedia IPC validation'
    )
  }

  const api = variableInitializer(sourceFile, 'api')
  const mappings = [
    ['claimPaidMedia', 'paid-media:claim', 'invokePaidMedia'],
    ['executePaidMedia', 'paid-media:execute', 'invokePaidMedia'],
    ['pollPaidVideo', 'paid-media:poll-video', 'invokePaidMedia'],
    ['recoverPaidMediaArchive', 'paid-media:recover-archive', 'invokePaidMedia'],
    ['listPaidMediaArchives', 'paid-media:list-archives', 'invokePaidMedia'],
    ['cancelPaidMedia', 'paid-media:cancel', 'send'],
    ['listPaidMediaOperations', 'paid-media:list', 'invokePaidMedia'],
    ['acknowledgePaidMedia', 'paid-media:acknowledge', 'invokePaidMedia'],
    ['abandonPaidMediaClaim', 'paid-media:abandon', 'invokePaidMedia'],
    ['reconcilePaidMedia', 'paid-media:reconcile', 'invokePaidMedia'],
    ['importLegacyPaidMediaJournal', 'paid-media:import-legacy', 'invokePaidMedia']
  ]
  for (const [method, channel, callKind] of mappings) {
    const implementation = objectProperty(api, method)
    const mapped =
      implementation &&
      someNode(implementation, (node) => {
        if (!ts.isCallExpression(node) || !isStringLiteralValue(node.arguments[0], channel)) {
          return false
        }
        return callKind === 'invokePaidMedia'
          ? ts.isIdentifier(node.expression) && node.expression.text === 'invokePaidMedia'
          : propertyAccessEndsWith(node.expression, ['ipcRenderer', 'send'])
      })
    if (!mapped) {
      throw new Error(
        `final packaged ASAR is missing paid-media preload control plane method mapping: ${method}`
      )
    }
  }

  const exposed = someNode(sourceFile, (node) =>
    ts.isCallExpression(node) &&
    propertyAccessEndsWith(node.expression, ['contextBridge', 'exposeInMainWorld']) &&
    isStringLiteralValue(node.arguments[0], 'api') &&
    Boolean(node.arguments[1] && ts.isIdentifier(node.arguments[1]) && node.arguments[1].text === 'api')
  )
  if (!exposed) {
    throw new Error('final packaged ASAR is missing paid-media preload control plane contextBridge exposure')
  }
}

/** Read the actual main bundle from the final packaged ASAR, never from desktop/out. */
export function readPackagedMainBundle(resourcesRoot) {
  return readPackagedAsarFile(
    resourcesRoot,
    'out/main/index.js',
    MAX_MAIN_BUNDLE_BYTES,
    'main'
  )
}

/** Reject final archives that predate the independent paid-media authority. */
export function verifyPackagedPaidMediaControlPlane({ resourcesRoot }) {
  verifyPackagedMainEntryPoint(resourcesRoot)
  verifyPackagedPreloadClosure(resourcesRoot)
  const mainBundle = readPackagedMainBundle(resourcesRoot)
  verifyMainBundleStructure(mainBundle)

  const preloadBundle = readPackagedAsarFile(
    resourcesRoot,
    'out/preload/index.js',
    MAX_PRELOAD_BUNDLE_BYTES,
    'preload'
  )
  verifyPreloadBundleStructure(preloadBundle)

  const rendererBundles = readPackagedRendererBundles(resourcesRoot)
  const migrationSentinel = 'nachuan.paid-media.renderer-migrated.v2'
  if (!rendererBundles.some(({ text }) => text.includes(migrationSentinel))) {
    throw new Error(
      `final packaged ASAR is missing paid-media renderer control plane evidence: ${migrationSentinel}`
    )
  }
  for (const { archivePath, text } of rendererBundles) {
    const rendererFolded = text.toLowerCase()
    for (const forbidden of [
      'X-Nachuan-Paid-Media-Key',
      'NACHUAN_PAID_MEDIA_API_KEY',
      'Idempotency-Key'
    ]) {
      if (rendererFolded.includes(forbidden.toLowerCase())) {
        throw new Error(
          `final packaged ASAR contains forbidden paid-media renderer evidence in ${archivePath}: ${forbidden}`
        )
      }
    }
  }
}

/** Prove resources/engine contains exactly the engine built for this release. */
export async function verifyPackagedEngine({
  resourcesRoot,
  sourceEngine,
  engineName,
  inspectPythonArchive
}) {
  resourcesRoot = resolve(resourcesRoot)
  sourceEngine = resolve(sourceEngine)
  if (!existsSync(sourceEngine)) throw new Error(`source engine binary is missing: ${sourceEngine}`)
  const sourceInfo = lstatSync(sourceEngine)
  if (
    sourceInfo.isSymbolicLink() ||
    !sourceInfo.isFile() ||
    sourceInfo.size <= 0 ||
    sourceInfo.size > MAX_ENGINE_BYTES
  ) {
    throw new Error('source engine must be a bounded regular file')
  }

  const engineRoot = join(resourcesRoot, 'engine')
  if (!existsSync(engineRoot)) throw new Error(`packaged engine directory is missing: ${engineRoot}`)
  const rootInfo = lstatSync(engineRoot)
  if (rootInfo.isSymbolicLink() || !rootInfo.isDirectory()) {
    throw new Error('packaged engine root must be a real directory')
  }
  const entries = ordinalSort(readdirSync(engineRoot))
  if (entries.length !== 1 || entries[0] !== engineName) {
    throw new Error(
      `packaged engine directory must contain only ${engineName}; found ${JSON.stringify(entries)}`
    )
  }
  const packagedEngine = join(engineRoot, engineName)
  const packagedInfo = lstatSync(packagedEngine)
  if (
    packagedInfo.isSymbolicLink() ||
    !packagedInfo.isFile() ||
    packagedInfo.size <= 0 ||
    packagedInfo.size > MAX_ENGINE_BYTES
  ) {
    throw new Error('packaged engine must be a bounded regular file')
  }
  const engineDigest = await sha256File(sourceEngine)
  if (engineDigest !== (await sha256File(packagedEngine))) {
    throw new Error('packaged engine does not match the engine built for this release')
  }
  // The digest equality above proves both files have identical bytes, so one
  // bounded streaming scan gates both the staged and installed native payload.
  await assertNoForbiddenPythonPayload(sourceEngine, 'packaged engine', inspectPythonArchive)
  return { engineDigest, packagedEngine }
}

export function verifyPackagedMainEngineBinding({ resourcesRoot, engineDigest }) {
  if (!SHA256.test(engineDigest)) throw new Error('engine digest is not a lowercase SHA-256 value')
  const bundledMain = readPackagedMainBundle(resourcesRoot)
  if (!bundledMain.includes(engineDigest)) {
    throw new Error('final packaged app.asar main bundle is missing the packaged engine digest')
  }
}

export function verifyPackagedMainRuntimeManifestBinding({ resourcesRoot, manifestDigest }) {
  if (!SHA256.test(manifestDigest)) {
    throw new Error('local runtime manifest digest is not a lowercase SHA-256 value')
  }
  const bundledMain = readPackagedMainBundle(resourcesRoot)
  if (!bundledMain.includes(manifestDigest)) {
    throw new Error('final packaged app.asar main bundle is missing the local runtime manifest digest')
  }
}

function exactProfileStrings(value, expected) {
  return (
    Array.isArray(value) &&
    value.length === expected.length &&
    value.every((item, index) => item === expected[index])
  )
}

function readClosedStoreRuntimeProfile(path, label) {
  const info = lstatSync(path)
  if (
    info.isSymbolicLink() ||
    !info.isFile() ||
    info.size <= 0 ||
    info.size > MAX_STORE_RUNTIME_PROFILE_BYTES
  ) {
    throw new Error(`${label} must be a bounded regular file`)
  }
  const bytes = readFileSync(path)
  const text = bytes.toString('utf8')
  if (!Buffer.from(text, 'utf8').equals(bytes) || text.startsWith('\uFEFF') || text.includes('\0')) {
    throw new Error(`${label} must be canonical UTF-8`)
  }
  let payload
  try {
    payload = JSON.parse(text)
  } catch (error) {
    throw new Error(`${label} is not valid JSON: ${error}`)
  }
  const fields = Object.keys(payload || {}).sort().join(',')
  if (
    !payload ||
    typeof payload !== 'object' ||
    Array.isArray(payload) ||
    fields !== [
      'capabilities',
      'connectionTypes',
      'externalProgramAuthorities',
      'externalProgramRoles',
      'frozenPythonExcludes',
      'name',
      'providerTypes',
      'schema'
    ].join(',') ||
    payload.schema !== 'nachuan.runtime-profile/v1' ||
    payload.name !== 'store' ||
    !exactProfileStrings(payload.capabilities, [
      'http-model-provider',
      'packaged-local-model-program',
      'packaged-media-program'
    ]) ||
    !exactProfileStrings(payload.connectionTypes, ['openai_compat', 'perplexity', 'volcano']) ||
    !exactProfileStrings(payload.providerTypes, ['echo', 'openai_compat', 'perplexity', 'volcano']) ||
    !exactProfileStrings(payload.externalProgramAuthorities, ['final-payload-manifest']) ||
    !exactProfileStrings(payload.externalProgramRoles, ['ffmpeg', 'ffprobe', 'llama-server']) ||
    !exactProfileStrings(payload.frozenPythonExcludes, [
      'gateway.providers.claude_code',
      'gateway.providers.codex',
      'yt_dlp'
    ])
  ) {
    throw new Error(`${label} is not the closed v1 store policy`)
  }
  return {
    bytes,
    digest: createHash('sha256').update(bytes).digest('hex')
  }
}

/** Prove the final ASAR, resources profile, and recursive engine payload agree. */
export async function verifyPackagedStoreRuntimeProfile({
  repoRoot,
  resourcesRoot,
  pythonPayload
}) {
  repoRoot = resolve(repoRoot)
  resourcesRoot = resolve(resourcesRoot)
  const sourcePath = join(repoRoot, 'config', STORE_RUNTIME_PROFILE_NAME)
  const packagedPath = join(resourcesRoot, STORE_RUNTIME_PROFILE_NAME)
  const source = readClosedStoreRuntimeProfile(sourcePath, 'source store runtime profile')
  const packaged = readClosedStoreRuntimeProfile(packagedPath, 'packaged store runtime profile')
  if (!source.bytes.equals(packaged.bytes)) {
    throw new Error('packaged store runtime profile differs from the release source bytes')
  }

  const bundledMain = readPackagedMainBundle(resourcesRoot)
  const generatedBindingPath = join(
    repoRoot,
    'desktop',
    'src',
    'main',
    'generated-engine-integrity.ts'
  )
  const generatedBinding = readFileSync(generatedBindingPath, 'utf8').match(
    /EXPECTED_STORE_RUNTIME_PROFILE_SHA256\s*=\s*'([0-9a-f]{64})'/
  )
  if (!generatedBinding || generatedBinding[1] !== packaged.digest) {
    throw new Error('generated desktop source is not bound to the store runtime profile digest')
  }
  if (!bundledMain.includes(packaged.digest)) {
    throw new Error('final packaged ASAR is missing the store runtime profile digest')
  }
  const sourceFile = parseJavaScriptBundle(bundledMain, 'store runtime profile main bundle')
  let engineStarter = null
  someNode(sourceFile, (node) => {
    if (ts.isFunctionDeclaration(node) && node.name?.text === 'startEngineOnce' && node.body) {
      engineStarter = node.body
      return true
    }
    return false
  })
  const profileAttestation = engineStarter
    ? callStart(engineStarter, sourceFile, ['attestPackagedStoreRuntimeProfile'])
    : -1
  const environmentBinding = engineStarter
    ? callStart(engineStarter, sourceFile, ['bindAttestedStoreRuntimeProfileEnvironment'])
    : -1
  const engineSpawn = engineStarter ? callStart(engineStarter, sourceFile, ['spawn']) : -1
  if (
    !engineStarter ||
    profileAttestation < 0 ||
    environmentBinding <= profileAttestation ||
    engineSpawn <= environmentBinding
  ) {
    throw new Error(
      'final packaged ASAR does not attest and bind the store runtime profile before engine spawn'
    )
  }

  if (
    !pythonPayload ||
    !Array.isArray(pythonPayload.archiveEntries) ||
    !Array.isArray(pythonPayload.ownershipEntries)
  ) {
    throw new Error('engine Python payload provenance is unavailable for store profile closure')
  }
  const archiveEntries = pythonPayload.archiveEntries.map((value) =>
    String(value || '').replaceAll('\\', '/')
  )
  const archiveSet = new Set(archiveEntries)
  for (const required of [
    'engine_main',
    'PYZ.pyz',
    'gateway.app',
    'gateway.local_model',
    'gateway.mcp_registry',
    'gateway.media_binary',
    'gateway.providers.cli_env',
    'gateway.runtime_profile',
    'orchestrator.studio',
    'orchestrator.tool_agent',
    'config/store-runtime-profile.v1.json'
  ]) {
    if (!archiveSet.has(required)) {
      throw new Error(`engine import surface is missing store closure module/data: ${required}`)
    }
  }
  for (const entry of archiveEntries) {
    const moduleName = entry.toLowerCase().replaceAll('/', '.')
    for (const forbidden of [
      'gateway.providers.claude_code',
      'gateway.providers.codex',
      'scripts.webview_browser_mcp',
      'scripts.xreview',
      'yt_dlp'
    ]) {
      if (moduleName === forbidden || moduleName.startsWith(`${forbidden}.`)) {
        throw new Error(`engine import surface contains forbidden store module: ${entry}`)
      }
    }
  }

  const runtimeSourcePath = join(repoRoot, 'gateway', 'runtime_profile.py')
  const runtimeSourceDigest = await sha256File(runtimeSourcePath)
  const requiredOwnership = new Map([
    ['project/config/store-runtime-profile.v1.json', packaged.digest],
    ['project/gateway/runtime_profile.py', runtimeSourceDigest]
  ])
  for (const [sourceName, digest] of requiredOwnership) {
    const matches = pythonPayload.ownershipEntries.filter(
      (item) =>
        item?.owner?.kind === 'project-source' &&
        item?.source?.path === sourceName &&
        item?.source?.sha256 === digest
    )
    if (matches.length === 0) {
      throw new Error(`engine provenance is missing exact store closure source bytes: ${sourceName}`)
    }
  }
  return { profileDigest: packaged.digest, profilePath: packagedPath }
}

export async function verifyPackagedMediaRuntime({ repoRoot, resourcesRoot }) {
  const staged = await verifyPreparedMediaRuntime({ repoRoot })
  const mediaRoot = join(resourcesRoot, 'media')
  const noticeRoot = join(resourcesRoot, 'media-notices')
  for (const [root, expected, label] of [
    [mediaRoot, ['ffmpeg.exe', 'ffprobe.exe'], 'packaged media runtime'],
    [noticeRoot, ['LICENSE', 'README.txt'], 'packaged media notices']
  ]) {
    const info = lstatSync(root)
    if (!info.isDirectory() || info.isSymbolicLink()) throw new Error(`${label} must be a real directory`)
    const entries = readdirSync(root).sort()
    if (JSON.stringify(entries) !== JSON.stringify(expected)) {
      throw new Error(`${label} is not an exact closed file set`)
    }
  }
  const pairs = [
    [staged.ffmpeg.path, join(mediaRoot, 'ffmpeg.exe'), staged.ffmpeg.sha256, 'ffmpeg'],
    [staged.ffprobe.path, join(mediaRoot, 'ffprobe.exe'), staged.ffprobe.sha256, 'ffprobe'],
    [staged.licensePath, join(noticeRoot, 'LICENSE'), staged.lock.license.sha256, 'FFmpeg LICENSE'],
    [staged.readmePath, join(noticeRoot, 'README.txt'), staged.lock.readme.sha256, 'Gyan README']
  ]
  for (const [source, packaged, digest, label] of pairs) {
    if ((await sha256File(source)) !== digest || (await sha256File(packaged)) !== digest) {
      throw new Error(`packaged ${label} bytes differ from the reviewed staging lock`)
    }
  }
  const packagedManifest = join(resourcesRoot, 'media-runtime-manifest.json')
  if (!readFileSync(packagedManifest).equals(readFileSync(staged.manifestPath))) {
    throw new Error('packaged media runtime manifest differs from reviewed staging')
  }
  return staged
}

const UPDATE_TRUST_KEYS = [
  'channel',
  'currentSequence',
  'enabled',
  'keyId',
  'keyringSequence',
  'keyringSha256',
  'manifestUrl',
  'publicKeySpkiBase64',
  'publisherName',
  'releaseTier',
  'schema',
  'signerThumbprint',
  'variant'
]

function parseEmbeddedUpdateTrust(text, label) {
  const match = text.match(
    /EMBEDDED_UPDATE_TRUST[^=]*=\s*Object\.freeze\((\{[\s\S]*?\})\)\s*;?/
  )
  if (!match) throw new Error(`${label} is missing the generated update trust object`)
  let trust
  try {
    trust = JSON.parse(match[1])
  } catch (error) {
    throw new Error(`${label} update trust is not canonical JSON: ${error}`)
  }
  if (!trust || typeof trust !== 'object' || Array.isArray(trust)) {
    throw new Error(`${label} update trust must be an object`)
  }
  if (Object.keys(trust).sort().join(',') !== UPDATE_TRUST_KEYS.join(',')) {
    throw new Error(`${label} update trust fields are not canonical`)
  }
  return trust
}

export function readPackagedUpdateTrust(resourcesRoot) {
  return parseEmbeddedUpdateTrust(readPackagedMainBundle(resourcesRoot), 'final packaged app.asar')
}

function isPrivateIpv4(host) {
  if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) return false
  const parts = host.split('.').map(Number)
  if (parts.some((part) => part > 255)) return true
  const [first, second] = parts
  return (
    first === 0 ||
    first === 10 ||
    first === 127 ||
    first >= 224 ||
    (first === 100 && second >= 64 && second <= 127) ||
    (first === 169 && second === 254) ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && second === 168) ||
    (first === 198 && (second === 18 || second === 19))
  )
}

function checkedPublicUpdateUrl(value, label) {
  if (typeof value !== 'string' || !value || value.length > 2048) {
    throw new Error(`${label} is invalid`)
  }
  let url
  try {
    url = new URL(value)
  } catch {
    throw new Error(`${label} is invalid`)
  }
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, '')
  if (
    url.protocol !== 'https:' ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    !host ||
    host === 'localhost' ||
    host.endsWith('.localhost') ||
    host.endsWith('.local') ||
    host.endsWith('.internal') ||
    host.endsWith('.corp') ||
    host.endsWith('.lan') ||
    host.endsWith('.home') ||
    host.endsWith('.home.arpa') ||
    host.endsWith('.test') ||
    host.endsWith('.invalid') ||
    host === 'example.com' ||
    host.endsWith('.example.com') ||
    host.includes(':') ||
    isPrivateIpv4(host) ||
    (!host.includes('.') && !/^\d/.test(host))
  ) {
    throw new Error(`${label} must be a credential-free public HTTPS URL`)
  }
  return url
}

function assertNoSensitiveFeedOptions(value, seen = new Set()) {
  if (!value || typeof value !== 'object') return
  if (seen.has(value)) return
  seen.add(value)
  for (const [key, item] of Object.entries(value)) {
    if (/(?:header|token|authorization|credential|private|^auth$)/i.test(key)) {
      throw new Error(`packaged app-update.yml contains forbidden credential option: ${key}`)
    }
    assertNoSensitiveFeedOptions(item, seen)
  }
}

export function verifyPackagedGenericUpdateFeed({ resourcesRoot, trust }) {
  const path = join(resourcesRoot, 'app-update.yml')
  if (!existsSync(path)) throw new Error('packaged app-update.yml is missing')
  const info = lstatSync(path)
  if (
    info.isSymbolicLink() ||
    !info.isFile() ||
    info.size <= 0 ||
    info.size > MAX_APP_UPDATE_BYTES
  ) {
    throw new Error('packaged app-update.yml must be a small regular file')
  }
  const bytes = readFileSync(path)
  const text = bytes.toString('utf8')
  if (!Buffer.from(text, 'utf8').equals(bytes) || text.startsWith('\uFEFF') || text.includes('\0')) {
    throw new Error('packaged app-update.yml must be canonical UTF-8')
  }
  let feed
  try {
    feed = loadYaml(text)
  } catch (error) {
    throw new Error(`packaged app-update.yml is invalid YAML: ${error}`)
  }
  if (!feed || typeof feed !== 'object' || Array.isArray(feed) || feed.provider !== 'generic') {
    throw new Error('packaged app-update.yml must use the generic provider')
  }
  assertNoSensitiveFeedOptions(feed)
  if (!trust || trust.enabled !== true || !['early-access', 'production'].includes(trust.releaseTier)) {
    throw new Error('packaged app-update.yml requires enabled embedded update trust')
  }
  if (!['lean', 'full'].includes(trust.variant)) {
    throw new Error('packaged app-update.yml update variant is invalid')
  }
  const expectedSignedChannel = `${trust.releaseTier}-${trust.variant}-win-x64`
  const expectedFeedChannel = `${trust.releaseTier}-${trust.variant}`
  if (trust.channel !== expectedSignedChannel || feed.channel !== expectedFeedChannel) {
    throw new Error('packaged app-update.yml channel differs from embedded update trust')
  }
  const manifestUrl = checkedPublicUpdateUrl(
    trust.manifestUrl,
    'embedded signed update manifest URL'
  )
  if (!manifestUrl.pathname.endsWith(`/${expectedSignedChannel}.json`)) {
    throw new Error('embedded signed update manifest URL is outside its canonical channel pointer')
  }
  const feedUrl = checkedPublicUpdateUrl(feed.url, 'packaged generic update feed URL')
  const controlledBase = new URL('.', manifestUrl)
  if (feedUrl.toString() !== controlledBase.toString()) {
    throw new Error('packaged generic update feed URL drifted from the signed manifest base')
  }
  return feed
}

function assertNoTestUpdateTrust(trust) {
  if (
    !Number.isSafeInteger(trust.keyringSequence) ||
    trust.keyringSequence < 0 ||
    (trust.keyringSha256 !== '' && !SHA256.test(String(trust.keyringSha256 || ''))) ||
    (trust.keyringSequence !== 0 && trust.keyringSha256 === '')
  ) {
    throw new Error('distributable update trust has an invalid keyring floor')
  }
  let url
  try {
    url = new URL(String(trust.manifestUrl || ''))
  } catch {
    throw new Error('distributable update manifest URL is invalid')
  }
  const host = url.hostname.toLowerCase()
  if (
    url.protocol !== 'https:' ||
    url.username ||
    url.password ||
    host === 'localhost' ||
    host.endsWith('.localhost') ||
    host.endsWith('.test') ||
    host.endsWith('.invalid') ||
    host === 'example.com' ||
    host.endsWith('.example.com')
  ) {
    throw new Error('distributable update trust uses a test or non-public manifest URL')
  }
  if (/^(?:audit|example|test)(?:[._-]|$)/i.test(String(trust.keyId || ''))) {
    throw new Error('distributable update trust uses an audit/test key id')
  }
}

export function verifyPackagedUpdateTrustBinding({ repoRoot, resourcesRoot, releaseTier }) {
  const source = readFileSync(
    join(repoRoot, 'desktop', 'src', 'main', 'generated-update-trust.ts'),
    'utf8'
  )
  const bundledMain = readPackagedMainBundle(resourcesRoot)
  const sourceTrust = parseEmbeddedUpdateTrust(source, 'generated source')
  const packagedTrust = parseEmbeddedUpdateTrust(bundledMain, 'final packaged app.asar')
  if (JSON.stringify(sourceTrust) !== JSON.stringify(packagedTrust)) {
    throw new Error('final packaged app.asar update trust differs from generated source')
  }
  if (sourceTrust.schema !== 1) throw new Error('generated update trust schema must be 1')
  if (releaseTier === 'disabled') {
    const expectedDisabled = {
      schema: 1,
      enabled: false,
      releaseTier: 'disabled',
      channel: '',
      variant: '',
      keyId: '',
      publicKeySpkiBase64: '',
      manifestUrl: '',
      currentSequence: 0,
      keyringSequence: 0,
      keyringSha256: '',
      publisherName: '',
      signerThumbprint: ''
    }
    if (JSON.stringify(sourceTrust) !== JSON.stringify(expectedDisabled)) {
      throw new Error('update-disabled package contains stale or non-empty update trust')
    }
    return sourceTrust
  }
  if (releaseTier !== 'early-access' && releaseTier !== 'production') {
    throw new Error(`invalid expected update release tier: ${releaseTier}`)
  }
  if (!sourceTrust.enabled || sourceTrust.releaseTier !== releaseTier) {
    throw new Error(`packaged ${releaseTier} build did not embed matching enabled update trust`)
  }
  assertNoTestUpdateTrust(sourceTrust)
  return sourceTrust
}

function findPackagedResources(releaseRoot) {
  if (process.platform === 'win32') return join(releaseRoot, 'win-unpacked', 'resources')
  if (process.platform === 'linux') return join(releaseRoot, 'linux-unpacked', 'resources')
  const appRoots = []
  const visit = (directory, depth) => {
    if (depth > 3 || !existsSync(directory)) return
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name)
      if (entry.isDirectory() && entry.name.endsWith('.app')) appRoots.push(path)
      else if (entry.isDirectory()) visit(path, depth + 1)
    }
  }
  visit(releaseRoot, 0)
  if (appRoots.length !== 1) throw new Error(`expected one unpacked .app, found ${appRoots.length}`)
  return join(appRoots[0], 'Contents', 'Resources')
}

async function verifyPackagedElectronFuses(resourcesRoot) {
  let candidates = []
  if (process.platform === 'darwin') {
    candidates = [resolve(resourcesRoot, '..', '..')]
  } else {
    const appRoot = dirname(resourcesRoot)
    candidates = readdirSync(appRoot, { withFileTypes: true })
      .filter((entry) => entry.isFile())
      .map((entry) => join(appRoot, entry.name))
  }
  const readable = []
  for (const candidate of candidates) {
    try {
      readable.push({ candidate, wire: await getCurrentFuseWire(candidate) })
    } catch {
      // Only the Electron executable/framework contains the fuse sentinel.
    }
  }
  if (readable.length !== 1) {
    throw new Error(`expected exactly one packaged Electron fuse wire, found ${readable.length}`)
  }
  const wire = readable[0].wire
  const DISABLED = 48
  const ENABLED = 49
  const expected = new Map([
    [FuseV1Options.RunAsNode, DISABLED],
    [FuseV1Options.EnableCookieEncryption, ENABLED],
    [FuseV1Options.EnableNodeOptionsEnvironmentVariable, DISABLED],
    [FuseV1Options.EnableNodeCliInspectArguments, DISABLED],
    [FuseV1Options.EnableEmbeddedAsarIntegrityValidation, ENABLED],
    [FuseV1Options.OnlyLoadAppFromAsar, ENABLED],
    [FuseV1Options.LoadBrowserProcessSpecificV8Snapshot, DISABLED],
    [FuseV1Options.GrantFileProtocolExtraPrivileges, DISABLED]
  ])
  for (const [option, state] of expected) {
    if (wire[option] !== state) {
      throw new Error(`packaged Electron fuse ${FuseV1Options[option]} is not in its required state`)
    }
  }
}

async function verifyPack({ variant, repoRoot = defaultRepoRoot }) {
  variant = checkedVariant(variant)
  const configuredUpdateTier = String(process.env.NACHUAN_UPDATE_TIER || '').toLowerCase()
  const releaseTier =
    configuredUpdateTier === 'early-access'
      ? 'early-access'
      : 'production'
  repoRoot = resolve(repoRoot)
  verifyInstallationRootInstallerContract({
    desktopRoot: join(repoRoot, 'desktop'),
    projectRoot: repoRoot
  })
  const distRoot = join(repoRoot, 'dist')
  const releaseRoot = join(repoRoot, 'desktop', 'release')
  const requireChannel = configuredUpdateTier === 'early-access' || configuredUpdateTier === 'production'
  const expectedOutput = await verifyPackagedReleaseOutput({
    variant,
    releaseRoot,
    releaseTier,
    requireChannel
  })
  const resourcesRoot = findPackagedResources(releaseRoot)
  if (!existsSync(resourcesRoot)) throw new Error(`unpacked packaged resources are missing: ${resourcesRoot}`)
  verifyPackagedPaidMediaControlPlane({ resourcesRoot })
  await verifyPackagedElectronFuses(resourcesRoot)
  await verifyPackagedLicenseEvidence({ appOutDir: dirname(resourcesRoot), projectRoot: repoRoot })

  const stagedManifest = join(distRoot, MANIFEST_NAME)
  const packagedManifest = join(resourcesRoot, MANIFEST_NAME)
  const stagedResult = await verifyLocalRuntimeLayout({ resourcesRoot: distRoot, variant, prepared: true })
  const packagedResult = await verifyLocalRuntimeLayout({ resourcesRoot, variant })
  if (readFileSync(stagedManifest, 'utf8') !== readFileSync(packagedManifest, 'utf8')) {
    throw new Error('packaged local runtime manifest differs from the prepared manifest')
  }
  if (JSON.stringify(stagedResult) !== JSON.stringify(packagedResult)) {
    throw new Error('packaged local runtime contents differ from prepared contents')
  }

  const engineName = process.platform === 'win32' ? 'engine.exe' : 'engine'
  // This is the byte-for-byte payload frozen after explicit production
  // Authenticode signing.  electron-builder restores the installed filename
  // but must not mutate these bytes a second time.
  const sourceEngine = join(distRoot, 'engine.payload')
  const { engineDigest } = await verifyPackagedEngine({ resourcesRoot, sourceEngine, engineName })
  const pythonPayload = await verifyPackagedPythonPayloadProvenance({
    appOutDir: dirname(resourcesRoot),
    engineName,
    projectRoot: repoRoot
  })
  await verifyPackagedStoreRuntimeProfile({ repoRoot, resourcesRoot, pythonPayload })
  const generatedBinding = join(
    repoRoot,
    'desktop',
    'src',
    'main',
    'generated-engine-integrity.ts'
  )
  const bindingMatch = readFileSync(generatedBinding, 'utf8').match(
    /EXPECTED_PACKAGED_ENGINE_SHA256\s*=\s*'([0-9a-f]{64})'/
  )
  if (!bindingMatch || bindingMatch[1] !== engineDigest) {
    throw new Error('signed desktop source is not bound to the packaged engine digest')
  }
  verifyPackagedMainEngineBinding({ resourcesRoot, engineDigest })
  const mediaRuntime = await verifyPackagedMediaRuntime({ repoRoot, resourcesRoot })
  const mediaBindings = {
    EXPECTED_PACKAGED_FFMPEG_SHA256: mediaRuntime.ffmpeg.sha256,
    EXPECTED_PACKAGED_FFPROBE_SHA256: mediaRuntime.ffprobe.sha256,
    EXPECTED_MEDIA_RUNTIME_MANIFEST_SHA256: mediaRuntime.manifestSha256
  }
  const generatedMediaBinding = readFileSync(generatedBinding, 'utf8')
  const bundledMain = readPackagedMainBundle(resourcesRoot)
  for (const [name, digest] of Object.entries(mediaBindings)) {
    const match = generatedMediaBinding.match(new RegExp(`${name}\\s*=\\s*'([0-9a-f]{64})'`))
    if (!match || match[1] !== digest || !bundledMain.includes(digest)) {
      throw new Error(`final packaged ASAR is not bound to ${name}`)
    }
  }
  for (const marker of ['FFMPEG_BIN', 'FFMPEG_SHA256', 'FFPROBE_BIN', 'FFPROBE_SHA256']) {
    if (!bundledMain.includes(marker)) throw new Error(`packaged main is missing media env binding: ${marker}`)
  }
  if (configuredUpdateTier === 'early-access' || configuredUpdateTier === 'production') {
    assertMediaRuntimeProductionAdmission(mediaRuntime.lock)
  }
  const manifestDigest = await sha256File(stagedManifest)
  const manifestBindingMatch = readFileSync(generatedBinding, 'utf8').match(
    /EXPECTED_LOCAL_RUNTIME_MANIFEST_SHA256\s*=\s*'([0-9a-f]{64})'/
  )
  if (!manifestBindingMatch || manifestBindingMatch[1] !== manifestDigest) {
    throw new Error('signed desktop source is not bound to the local runtime manifest digest')
  }
  verifyPackagedMainRuntimeManifestBinding({ resourcesRoot, manifestDigest })
  const packagedUpdateTrust = verifyPackagedUpdateTrustBinding({
    repoRoot,
    resourcesRoot,
    releaseTier:
      configuredUpdateTier === 'early-access' || configuredUpdateTier === 'production'
        ? configuredUpdateTier
        : 'disabled'
  })
  if (configuredUpdateTier === 'early-access' || configuredUpdateTier === 'production') {
    verifyPackagedGenericUpdateFeed({ resourcesRoot, trust: packagedUpdateTrust })
  }

  const installer = {
    name: expectedOutput.artifact,
    path: join(releaseRoot, expectedOutput.artifact),
    mtimeMs: statSync(join(releaseRoot, expectedOutput.artifact)).mtimeMs
  }
  const preparedAt = statSync(stagedManifest).mtimeMs
  if (installer.mtimeMs + 2000 < preparedAt) {
    throw new Error(`latest ${variant} installer predates this package preparation`)
  }
  const sizeMB = statSync(installer.path).size / 1e6
  if (sizeMB < 25) throw new Error(`installer is implausibly small (${sizeMB.toFixed(0)} MB)`)

  const stagedSeed = join(distRoot, 'seed-connections.json')
  const packagedSeed = join(resourcesRoot, 'seed-connections.json')
  for (const seed of [stagedSeed, packagedSeed]) {
    if (!existsSync(seed)) throw new Error(`connection seed is missing: ${seed}`)
    const payload = JSON.parse(readFileSync(seed, 'utf8'))
    if (!payload || typeof payload !== 'object' || Array.isArray(payload) || Object.keys(payload).length) {
      throw new Error(`connection seed must be an empty object: ${seed}`)
    }
  }

  const secretFindings = await scanReleasePaths([packagedSeed, resourcesRoot])
  if (secretFindings.length) {
    const locations = secretFindings
      .slice(0, 5)
      .map((item) => `${item.file}#${item.field}`)
      .join('; ')
    throw new Error(`release secret gate found ${secretFindings.length} item(s): ${locations}`)
  }

  // Catch any residue or replacement introduced while the asynchronous hash/scan gates ran.
  await verifyPackagedReleaseOutput({
    variant,
    releaseRoot,
    releaseTier,
    requireChannel
  })
  assertClosedReleaseOutput({
    variant,
    releaseRoot,
    releaseTier,
    requireChannel,
    allowPayloadManifest: process.platform === 'win32'
  })

  return { installer: installer.name, sizeMB, ...packagedResult }
}

async function main(argv) {
  try {
    const variant = process.env.DMX_VARIANT || argv[0] || 'lean'
    const result = await verifyPack({ variant })
    console.log(
      `[verify-pack] OK ${variant}: ${result.installer}, ${result.sizeMB.toFixed(0)} MB, runtime artifacts=${result.artifactCount}`
    )
    return 0
  } catch (error) {
    console.error(`[verify-pack] BLOCKED: ${error instanceof Error ? error.message : String(error)}`)
    return 1
  }
}

if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  process.exitCode = await main(process.argv.slice(2))
}
