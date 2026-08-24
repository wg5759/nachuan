import { createReadStream } from 'node:fs'
import { lstat, mkdir, readFile, readdir, writeFile } from 'node:fs/promises'
import { basename, dirname, extname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { extractFile, listPackage, statFile } from '@electron/asar'

const NON_SECRET_MODEL_TOKEN_FIELDS = new Set([
  'unk_token',
  'bos_token',
  'eos_token',
  'pad_token',
  'mask_token',
  'cls_token',
  'sep_token',
  'public_key_token',
  'additional_special_tokens'
])
const NON_PRODUCTION_RELEASE_NAMES = new Set([
  '视频工作流',
  '.nachuan-non-production-workflow',
  '.cbm',
  'codebase-memory-mcp',
  'install.ps1'
])
const SENSITIVE_KEY_EXTENSIONS = new Set(['.key', '.p12', '.pem', '.pfx'])
const SENSITIVE_KEY_FILENAMES = new Set(['id_dsa', 'id_ecdsa', 'id_ed25519', 'id_rsa'])
const CODE_EXTENSIONS = new Set(['.cjs', '.js', '.jsx', '.mjs', '.ps1', '.py', '.ts', '.tsx'])
const TEXT_EXTENSIONS = new Set([
  '.cfg',
  '.conf',
  '.config',
  '.cjs',
  '.css',
  '.env',
  '.html',
  '.ini',
  '.js',
  '.json',
  '.jsx',
  '.md',
  '.mjs',
  '.properties',
  '.ps1',
  '.py',
  '.toml',
  '.ts',
  '.tsx',
  '.txt',
  '.xml',
  '.yaml',
  '.yml'
])
const MAX_STRUCTURED_BYTES = 16 * 1024 * 1024
const MAX_ASAR_BYTES = 1024 * 1024 * 1024
const MAX_ASAR_ENTRY_BYTES = 128 * 1024 * 1024
const MAX_ASAR_ENTRIES = 100_000
const BINARY_CHUNK_BYTES = 1024 * 1024
const BINARY_OVERLAP_BYTES = 2048
const KNOWN_TOKEN_PATTERNS = [
  ['provider_token', /\bsk-[A-Za-z0-9_-]{15,}[A-Za-z0-9_](?![A-Za-z0-9_-])/g],
  ['github_token', /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g],
  ['slack_token', /\bxox[baprs]-[A-Za-z0-9-]{16,}\b/g],
  ['aws_access_key', /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g],
  ['private_key_marker', /-----BEGIN (?:ENCRYPTED |RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g]
]
const COMPLETE_PRIVATE_KEY_PATTERN =
  /-----BEGIN ((?:ENCRYPTED |RSA |EC |DSA |OPENSSH )?)PRIVATE KEY-----[\r\n]+[A-Za-z0-9+/=\r\n]{64,131072}-----END \1PRIVATE KEY-----/g
const ASSIGNMENT_PATTERN =
  /(?:^|[\x00\s{,;])(["']?)([A-Za-z][A-Za-z0-9_.-]{1,100})\1\s*[:=]\s*(["']?)([^\x00\s"',;}\]\r\n]{8,512})\3/gm

function recordNonProductionPath(path, findings) {
  if (!NON_PRODUCTION_RELEASE_NAMES.has(basename(path))) return false
  findings.push({ code: 'NON_PRODUCTION_WORKFLOW', file: path, field: 'path' })
  return true
}

function recordNonProductionArchivePath(archivePath, entry, findings) {
  const parts = String(entry).split(/[\\/]/).filter(Boolean)
  const forbidden = parts.find((part) => NON_PRODUCTION_RELEASE_NAMES.has(part))
  if (!forbidden) return false
  findings.push({
    code: 'NON_PRODUCTION_WORKFLOW',
    file: `${archivePath}!/${parts.join('/')}`,
    field: 'path'
  })
  return true
}

function recordSensitiveKeyPath(path, findings, virtualPath = path) {
  const name = basename(path).toLowerCase()
  if (!SENSITIVE_KEY_EXTENSIONS.has(extname(name)) && !SENSITIVE_KEY_FILENAMES.has(name)) {
    return false
  }
  findings.push({ code: 'SENSITIVE_KEY_FILE', file: virtualPath, field: 'path' })
  return true
}

function normalizedSecretField(field) {
  return field
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .replace(/-/g, '_')
    .toLowerCase()
}

function isSecretField(field) {
  const normalized = normalizedSecretField(field)
  if (NON_SECRET_MODEL_TOKEN_FIELDS.has(normalized)) return false
  return (
    /(?:^|_)api_?key$/.test(normalized) ||
    /(?:^|_)(?:token|secret|password|passwd|authorization|private_key|secret_key|credential|credentials|cookie|cookies)$/.test(
      normalized
    )
  )
}

function isHighConfidenceOpaqueSecretField(field) {
  const normalized = normalizedSecretField(field)
  return (
    /(?:^|_)api_?key$/.test(normalized) ||
    /(?:^|_)(?:access_token|api_token|auth_token|bot_token|client_secret|private_key|refresh_token|secret_key|password|passwd|authorization)$/.test(
      normalized
    )
  )
}

function findSecrets(value, file, findings) {
  if (!value || typeof value !== 'object') return
  for (const [field, child] of Object.entries(value)) {
    if (isSecretField(field) && typeof child === 'string' && child.trim()) {
      findings.push({ code: 'NON_EMPTY_SECRET', file, field })
    }
    findSecrets(child, file, findings)
  }
}

function plausibleAssignedSecret(file, quote, value, code) {
  if (quote) {
    const name = basename(file).toLowerCase()
    if (CODE_EXTENSIONS.has(extname(name)) && /[^\x20-\x7e]/u.test(value)) return false
    return true
  }
  if (code === 'EMBEDDED_SECRET') return /[0-9_+\-/=]/.test(value)
  const name = basename(file).toLowerCase()
  if (name === '.env' || name.startsWith('.env.')) return true
  if (!CODE_EXTENSIONS.has(extname(name))) return true
  // Bare source identifiers/member expressions are references, not embedded
  // credentials (for example cancellationToken = this.cancellationToken).
  if (/[.()[\]{}?:]/.test(value) || /^(?:false|null|true|undefined)$/i.test(value)) return false
  return /[0-9_+\-/=]/.test(value)
}

function plausibleProviderTokenMatch(match, text) {
  const value = match[0]
  const tail = text.slice(match.index + value.length, match.index + value.length + 16)
  if (/^-(?:\[|\$\{)/u.test(tail)) return false
  if (/^sk-(?:ecdsa|ssh)-[a-z0-9._-]+$/iu.test(value) && /^@openssh\.com\b/iu.test(tail)) {
    return false
  }
  return true
}

function findAssignedSecrets(text, file, findings, code) {
  ASSIGNMENT_PATTERN.lastIndex = 0
  for (const match of text.matchAll(ASSIGNMENT_PATTERN)) {
    const field = match[2]
    if (field.includes('.')) continue
    if (code === 'EMBEDDED_SECRET' && !isHighConfidenceOpaqueSecretField(field)) continue
    if (isSecretField(field) && plausibleAssignedSecret(file, match[3], match[4], code)) {
      findings.push({ code, file, field })
    }
  }
  for (const [field, pattern] of KNOWN_TOKEN_PATTERNS) {
    pattern.lastIndex = 0
    if (field === 'private_key_marker' && code === 'EMBEDDED_SECRET') {
      COMPLETE_PRIVATE_KEY_PATTERN.lastIndex = 0
      if (COMPLETE_PRIVATE_KEY_PATTERN.test(text)) findings.push({ code, file, field })
      continue
    }
    const matches = [...text.matchAll(pattern)]
    if (field === 'provider_token') {
      if (matches.some((match) => plausibleProviderTokenMatch(match, text))) {
        findings.push({ code, file, field })
      }
      continue
    }
    if (matches.length) findings.push({ code, file, field })
  }
}

function looksTextual(path, bytes) {
  const name = basename(path).toLowerCase()
  if (name === '.env' || name.startsWith('.env.')) return true
  if (!TEXT_EXTENSIONS.has(extname(name))) return false
  return !bytes.subarray(0, Math.min(bytes.length, 8192)).includes(0)
}

function scanBoundedBytes(bytes, file, findings) {
  const textual = looksTextual(file, bytes)
  const extension = extname(file).toLowerCase()
  if (textual && extension === '.json') {
    try {
      findSecrets(JSON.parse(bytes.toString('utf8')), file, findings)
      return
    } catch {
      findings.push({ code: 'INVALID_RELEASE_JSON', file, field: 'parse' })
    }
  }
  findAssignedSecrets(bytes.toString(textual ? 'utf8' : 'latin1'), file, findings, textual ? 'TEXT_SECRET' : 'EMBEDDED_SECRET')
}

async function scanOpaqueFile(path, findings) {
  let overlap = Buffer.alloc(0)
  await new Promise((accept, reject) => {
    const input = createReadStream(path, { highWaterMark: BINARY_CHUNK_BYTES })
    input.on('data', (chunk) => {
      const bytes = overlap.length ? Buffer.concat([overlap, chunk]) : chunk
      findAssignedSecrets(bytes.toString('latin1'), path, findings, 'EMBEDDED_SECRET')
      overlap = bytes.subarray(Math.max(0, bytes.length - BINARY_OVERLAP_BYTES))
    })
    input.once('error', reject)
    input.once('end', accept)
  })
}

async function scanAsar(path, info, findings) {
  if (info.size <= 0 || info.size > MAX_ASAR_BYTES) {
    findings.push({ code: 'UNSCANNABLE_ASAR', file: path, field: 'size' })
    return
  }
  let entries
  try {
    entries = listPackage(path)
  } catch {
    findings.push({ code: 'INVALID_ASAR', file: path, field: 'header' })
    return
  }
  if (!Array.isArray(entries) || entries.length > MAX_ASAR_ENTRIES) {
    findings.push({ code: 'UNSCANNABLE_ASAR', file: path, field: 'entries' })
    return
  }
  for (const entry of [...entries].sort()) {
    if (recordNonProductionArchivePath(path, entry, findings)) continue
    const archiveEntry = String(entry).replace(/^[\\/]+/, '')
    const virtualPath = `${path}!/${archiveEntry.replaceAll('\\', '/')}`
    if (recordSensitiveKeyPath(archiveEntry, findings, virtualPath)) continue
    let metadata
    try {
      metadata = statFile(path, archiveEntry, false)
    } catch {
      findings.push({ code: 'INVALID_ASAR_ENTRY', file: virtualPath, field: 'stat' })
      continue
    }
    if (metadata?.link) {
      findings.push({ code: 'ASAR_LINK', file: virtualPath, field: 'link' })
      continue
    }
    if (metadata?.files) continue
    if (!Number.isSafeInteger(metadata?.size) || metadata.size < 0 || metadata.size > MAX_ASAR_ENTRY_BYTES) {
      findings.push({ code: 'UNSCANNABLE_ASAR_ENTRY', file: virtualPath, field: 'size' })
      continue
    }
    try {
      scanBoundedBytes(extractFile(path, archiveEntry, false), virtualPath, findings)
    } catch {
      findings.push({ code: 'INVALID_ASAR_ENTRY', file: virtualPath, field: 'extract' })
    }
  }
}

async function scanPath(path, findings) {
  if (recordNonProductionPath(path, findings)) return
  const info = await lstat(path)
  if (info.isSymbolicLink()) {
    findings.push({ code: 'FILESYSTEM_REDIRECT', file: path, field: 'path' })
    return
  }
  if (info.isDirectory()) {
    const entries = await readdir(path, { withFileTypes: true })
    entries.sort((left, right) => (left.name < right.name ? -1 : left.name > right.name ? 1 : 0))
    for (const entry of entries) {
      const child = resolve(path, entry.name)
      if (recordNonProductionPath(child, findings)) continue
      if (entry.isSymbolicLink()) {
        findings.push({ code: 'FILESYSTEM_REDIRECT', file: child, field: 'path' })
        continue
      }
      await scanPath(child, findings)
    }
    return
  }
  if (!info.isFile()) {
    findings.push({ code: 'SPECIAL_FILE', file: path, field: 'path' })
    return
  }
  if (recordSensitiveKeyPath(path, findings)) return
  if (path.toLowerCase().endsWith('.asar')) {
    await scanAsar(path, info, findings)
    return
  }
  if (info.size <= MAX_STRUCTURED_BYTES) {
    scanBoundedBytes(await readFile(path), path, findings)
    return
  }
  await scanOpaqueFile(path, findings)
}

export async function scanReleasePaths(paths) {
  const findings = []
  for (const path of paths) await scanPath(resolve(path), findings)
  const unique = new Map()
  for (const finding of findings) {
    unique.set(`${finding.code}\0${finding.file}\0${finding.field}`, finding)
  }
  return [...unique.values()].sort((left, right) => {
    const a = `${left.file}\0${left.code}\0${left.field}`
    const b = `${right.file}\0${right.code}\0${right.field}`
    return a < b ? -1 : a > b ? 1 : 0
  })
}

export async function prepareConnectionSeed({ destination }) {
  await mkdir(dirname(destination), { recursive: true })
  await writeFile(destination, '{}\n', 'utf8')
}

async function main(argv) {
  if (argv[0] !== 'scan' || argv.length < 2) {
    console.error('usage: node release-security.mjs scan <path...>')
    return 2
  }
  const findings = await scanReleasePaths(argv.slice(1))
  for (const finding of findings) {
    console.log(`${finding.code} ${finding.file} field=${finding.field}`)
  }
  if (findings.length) console.log(`BLOCKED findings=${findings.length}`)
  else console.log('RELEASE_SECRET_GATE_OK')
  return findings.length ? 1 : 0
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = await main(process.argv.slice(2))
}
