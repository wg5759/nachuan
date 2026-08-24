import { randomBytes } from 'node:crypto'
import {
  chmodSync,
  closeSync,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync
} from 'node:fs'
import { basename, dirname, join, resolve } from 'node:path'
import { spawnSync } from 'node:child_process'

import { prepareTrustedWindowsCommand } from './windows-system'

const SCHEMA = 'nachuan.electron-secret-config.v1'
const PROTECTION = 'electron-safe-storage'
const MAX_CONFIG_BYTES = 1024 * 1024
const PAID_MEDIA_KEY_PATTERN = /^sk-paid-media-[0-9a-f]{64}$/

function isIndependentPaidMediaKey(
  value: unknown,
  runtimeKey: string,
  approvalKey: string
): value is string {
  return (
    typeof value === 'string' &&
    PAID_MEDIA_KEY_PATTERN.test(value) &&
    value !== runtimeKey &&
    value !== approvalKey
  )
}

export interface SafeStringStorage {
  isEncryptionAvailable(): boolean
  encryptString(value: string): Buffer
  decryptString(value: Buffer): string
}

export type SecretConfig = Record<string, unknown>
export type AclHardener = (path: string, directory: boolean) => void

export class SecureConfigError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options)
    this.name = 'SecureConfigError'
  }
}

function requireEncryption(storage: SafeStringStorage): void {
  if (!storage.isEncryptionAvailable()) {
    throw new SecureConfigError('OS-backed secret encryption is unavailable; refusing plaintext fallback')
  }
}

type WindowsAclCommandName = 'whoami.exe' | 'icacls.exe' | 'powershell.exe'

interface LocalSecretAclInspection {
  identity: string
  directory: boolean
}

interface LocalSecretAclCommand {
  executable: string
  env: NodeJS.ProcessEnv
}

interface LocalSecretAclRunResult {
  status: number | null
  stdout: string | Buffer | null | undefined
}

export interface LocalSecretAclHardenerDependencies {
  platform: NodeJS.Platform
  inspect(path: string, directory: boolean): LocalSecretAclInspection
  chmod(path: string, mode: number): void
  prepareCommand(name: WindowsAclCommandName): LocalSecretAclCommand
  run(
    command: LocalSecretAclCommand,
    args: string[],
    options: { timeout: number }
  ): LocalSecretAclRunResult
}

const MAX_VERIFIED_ACL_IDENTITIES = 4096

function inspectLocalSecretAclTarget(path: string, directory: boolean): LocalSecretAclInspection {
  const info = lstatSync(path, { bigint: true })
  if (info.isSymbolicLink() || info.isDirectory() !== directory) {
    throw new SecureConfigError('Local secret ACL target type is invalid')
  }
  return {
    directory,
    identity: [
      info.dev,
      info.ino,
      info.mode,
      info.nlink,
      info.size,
      info.birthtimeNs,
      info.ctimeNs
    ]
      .map(String)
      .join(':')
  }
}

const defaultLocalSecretAclDependencies: LocalSecretAclHardenerDependencies = {
  platform: process.platform,
  inspect: inspectLocalSecretAclTarget,
  chmod: chmodSync,
  prepareCommand: prepareTrustedWindowsCommand,
  run(command, args, options) {
    return spawnSync(command.executable, args, {
      windowsHide: true,
      encoding: 'utf8',
      timeout: options.timeout,
      env: command.env
    })
  }
}

export function createLocalSecretAclHardener(
  dependencies: LocalSecretAclHardenerDependencies = defaultLocalSecretAclDependencies
): AclHardener {
  const verified = new Map<string, string>()
  let currentSid: string | null = null

  const requireCurrentSid = (): string => {
    if (currentSid !== null) return currentSid
    const command = dependencies.prepareCommand('whoami.exe')
    const result = dependencies.run(command, ['/user', '/fo', 'csv', '/nh'], {
      timeout: 10_000
    })
    const stdout = typeof result.stdout === 'string' ? result.stdout : result.stdout?.toString() || ''
    const sid = stdout.match(/S-1-(?:\d+-)+\d+/i)?.[0] || ''
    if (result.status !== 0 || !sid) {
      throw new SecureConfigError(
        'Cannot resolve the current Windows SID; refusing weak secret ACL'
      )
    }
    currentSid = sid
    return sid
  }

  return (path: string, directory: boolean): void => {
    if (dependencies.platform !== 'win32') {
      dependencies.chmod(path, directory ? 0o700 : 0o600)
      return
    }

    const cacheKey = `${directory ? 'directory' : 'file'}\0${resolve(path).toLowerCase()}`
    const before = dependencies.inspect(path, directory)
    if (before.directory !== directory) {
      throw new SecureConfigError('Local secret ACL target type is invalid')
    }
    if (verified.get(cacheKey) === before.identity) {
      // Refresh insertion order so the bounded map behaves as a small LRU.
      verified.delete(cacheKey)
      verified.set(cacheKey, before.identity)
      return
    }

    const sid = requireCurrentSid()
    const rights = directory ? '(OI)(CI)(F)' : '(F)'
    const icacls = dependencies.prepareCommand('icacls.exe')
    const update = dependencies.run(
      icacls,
      [
        path,
        '/inheritance:r',
        '/grant:r',
        `*${sid}:${rights}`,
        `*S-1-5-18:${rights}`,
        '/remove:g',
        '*S-1-1-0',
        '*S-1-5-11',
        '*S-1-5-32-545'
      ],
      { timeout: 15_000 }
    )
    if (update.status !== 0) {
      throw new SecureConfigError('Cannot restrict the local secret ACL')
    }

    // icacls is allowed to change the target's ctime. Freeze the resulting
    // object identity before the read-only verification so a path replacement
    // cannot be mistaken for the object whose ACL PowerShell actually read.
    const beforeVerification = dependencies.inspect(path, directory)
    if (beforeVerification.directory !== directory) {
      throw new SecureConfigError('Local secret ACL target type is invalid')
    }

    const verifyScript =
      "& { param([string]$p,[string]$expected) " +
      "$PSModuleAutoLoadingPreference='None'; " +
      '$rules=@((Get-Acl -LiteralPath $p).Access); ' +
      "if($rules.Count -ne 2){exit 1}; $allowed=@($expected,'S-1-5-18'); " +
      'foreach($rule in $rules){' +
      '$actual=$rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value; ' +
      "if($rule.IsInherited -or $rule.AccessControlType.ToString() -ne 'Allow' -or $allowed -notcontains $actual){exit 1}" +
      '}; exit 0 }'
    const powershell = dependencies.prepareCommand('powershell.exe')
    const verify = dependencies.run(
      powershell,
      ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', verifyScript, path, sid],
      { timeout: 60_000 }
    )
    if (verify.status !== 0) {
      throw new SecureConfigError('Local secret ACL is not limited to current-user and SYSTEM')
    }

    const afterVerification = dependencies.inspect(path, directory)
    if (afterVerification.directory !== directory) {
      throw new SecureConfigError('Local secret ACL target type is invalid')
    }
    if (afterVerification.identity !== beforeVerification.identity) {
      throw new SecureConfigError('Local secret ACL target changed during verification')
    }
    if (verified.size >= MAX_VERIFIED_ACL_IDENTITIES) {
      const oldest = verified.keys().next().value as string | undefined
      if (oldest !== undefined) verified.delete(oldest)
    }
    verified.set(cacheKey, afterVerification.identity)
  }
}

const defaultLocalSecretAclHardener = createLocalSecretAclHardener()

export function hardenLocalSecretAcl(path: string, directory: boolean): void {
  defaultLocalSecretAclHardener(path, directory)
}

function parseObject(raw: string, message: string): SecretConfig {
  try {
    const value: unknown = JSON.parse(raw)
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('not object')
    return value as SecretConfig
  } catch (error) {
    throw new SecureConfigError(message, { cause: error })
  }
}

function decodeCiphertext(value: unknown): Buffer {
  if (typeof value !== 'string' || !value || value.length > MAX_CONFIG_BYTES * 2) {
    throw new SecureConfigError('Encrypted local config envelope is invalid')
  }
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value) || value.length % 4 !== 0) {
    throw new SecureConfigError('Encrypted local config envelope is invalid')
  }
  return Buffer.from(value, 'base64')
}

export function writeSecureConfig(
  path: string,
  config: SecretConfig,
  storage: SafeStringStorage,
  harden: AclHardener = hardenLocalSecretAcl
): void {
  requireEncryption(storage)
  const parent = dirname(path)
  mkdirSync(parent, { recursive: true })
  harden(parent, true)
  const plaintext = JSON.stringify(config)
  if (Buffer.byteLength(plaintext, 'utf8') > MAX_CONFIG_BYTES) {
    throw new SecureConfigError('Local secret config exceeds the size limit')
  }
  let ciphertext: Buffer
  try {
    ciphertext = storage.encryptString(plaintext)
  } catch (error) {
    throw new SecureConfigError('OS-backed local config encryption failed', { cause: error })
  }
  const envelope = JSON.stringify({
    schema: SCHEMA,
    protection: PROTECTION,
    ciphertext: ciphertext.toString('base64')
  })
  const temp = join(parent, `.${basename(path)}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`)
  let handle: number | null = null
  try {
    handle = openSync(temp, 'wx', 0o600)
    writeFileSync(handle, envelope, 'utf8')
    fsyncSync(handle)
    closeSync(handle)
    handle = null
    harden(temp, false)
    renameSync(temp, path)
    harden(path, false)
  } catch (error) {
    throw error instanceof SecureConfigError
      ? error
      : new SecureConfigError('Atomic encrypted local config write failed', { cause: error })
  } finally {
    if (handle !== null) closeSync(handle)
    if (existsSync(temp)) unlinkSync(temp)
  }
}

export function readSecureConfig(
  path: string,
  storage: SafeStringStorage,
  harden: AclHardener = hardenLocalSecretAcl
): SecretConfig {
  requireEncryption(storage)
  if (!existsSync(path)) return {}
  const parent = dirname(path)
  harden(parent, true)
  harden(path, false)
  if (statSync(path).size > MAX_CONFIG_BYTES) {
    throw new SecureConfigError('Local secret config exceeds the size limit')
  }
  const document = parseObject(readFileSync(path, 'utf8'), 'Local secret config is corrupt')
  if (document.schema === SCHEMA) {
    if (document.protection !== PROTECTION) {
      throw new SecureConfigError('Unsupported local secret protection scheme')
    }
    let plaintext: string
    try {
      plaintext = storage.decryptString(decodeCiphertext(document.ciphertext))
    } catch (error) {
      if (error instanceof SecureConfigError) throw error
      throw new SecureConfigError('OS-backed local config decryption failed', { cause: error })
    }
    if (Buffer.byteLength(plaintext, 'utf8') > MAX_CONFIG_BYTES) {
      throw new SecureConfigError('Decrypted local secret config exceeds the size limit')
    }
    return parseObject(plaintext, 'Decrypted local secret config is corrupt')
  }
  if ('schema' in document || 'protection' in document || 'ciphertext' in document) {
    throw new SecureConfigError('Unknown local secret config envelope')
  }
  // Legacy config was plaintext and may have been readable by lower-trust local
  // principals.  Encrypting the same bearer values would preserve credentials
  // that must be treated as compromised.  Reset the legacy document entirely:
  // startup will mint fresh runtime/approval keys, while an update token must be
  // explicitly re-entered after it has been revoked at its issuer.
  const migrated: SecretConfig = {}
  writeSecureConfig(path, migrated, storage, harden)
  return migrated
}

export function loadOrCreateEngineKey(
  path: string,
  storage: SafeStringStorage,
  createKey: () => string,
  harden: AclHardener = hardenLocalSecretAcl
): string {
  const config = readSecureConfig(path, storage, harden)
  if (typeof config.engineKey === 'string' && config.engineKey) return config.engineKey
  const engineKey = createKey()
  writeSecureConfig(path, { ...config, engineKey }, storage, harden)
  return engineKey
}

export function loadOrCreateApprovalKey(
  path: string,
  storage: SafeStringStorage,
  runtimeKey: string,
  createKey: () => string,
  harden: AclHardener = hardenLocalSecretAcl
): string {
  const config = readSecureConfig(path, storage, harden)
  const existing = typeof config.approvalKey === 'string' ? config.approvalKey : ''
  if (existing && existing !== runtimeKey) return existing
  const approvalKey = createKey()
  if (!approvalKey || approvalKey === runtimeKey) {
    throw new SecureConfigError('Approval key must be independent from the runtime key')
  }
  writeSecureConfig(path, { ...config, approvalKey }, storage, harden)
  return approvalKey
}

export function loadOrCreatePaidMediaKey(
  path: string,
  storage: SafeStringStorage,
  runtimeKey: string,
  approvalKey: string,
  createKey: () => string,
  harden: AclHardener = hardenLocalSecretAcl
): string {
  const config = readSecureConfig(path, storage, harden)
  if (isIndependentPaidMediaKey(config.paidMediaKey, runtimeKey, approvalKey)) {
    return config.paidMediaKey
  }
  const paidMediaKey = createKey()
  if (!isIndependentPaidMediaKey(paidMediaKey, runtimeKey, approvalKey)) {
    throw new SecureConfigError(
      'Paid-media key must use the sk-paid-media- prefix with independent 256-bit lowercase hexadecimal key material'
    )
  }
  writeSecureConfig(path, { ...config, paidMediaKey }, storage, harden)
  return paidMediaKey
}
