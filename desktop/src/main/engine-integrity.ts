import { createHash, timingSafeEqual } from 'node:crypto'
import {
  closeSync,
  createReadStream,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
  readdirSync,
  realpathSync,
  type Stats
} from 'node:fs'
import { basename, dirname, isAbsolute, join, normalize, parse, resolve, sep } from 'node:path'

const MAX_ENGINE_BYTES = 1024 * 1024 * 1024
const MAX_RUNTIME_MANIFEST_BYTES = 256 * 1024
const MAX_STORE_RUNTIME_PROFILE_BYTES = 64 * 1024
const MAX_MEDIA_EXECUTABLE_BYTES = 256 * 1024 * 1024

export class EngineIntegrityError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options)
    this.name = 'EngineIntegrityError'
  }
}

function samePath(left: string, right: string): boolean {
  const a = normalize(left)
  const b = normalize(right)
  return process.platform === 'win32' ? a.toLowerCase() === b.toLowerCase() : a === b
}

function assertNoRedirectingComponents(path: string): void {
  const absolute = resolve(path)
  const root = parse(absolute).root
  const relative = absolute.slice(root.length)
  let cursor = root
  for (const part of relative.split(sep).filter(Boolean)) {
    cursor = join(cursor, part)
    if (lstatSync(cursor).isSymbolicLink()) {
      throw new EngineIntegrityError('packaged engine path contains a filesystem redirect')
    }
  }
}

function assertRealDirectory(path: string): string {
  const absolute = resolve(path)
  assertNoRedirectingComponents(absolute)
  const info = lstatSync(absolute)
  if (!info.isDirectory() || info.isSymbolicLink()) {
    throw new EngineIntegrityError('packaged engine directory is not a regular directory or is redirected')
  }
  // Force the OS to resolve the path now; short (8.3) aliases are legitimate
  // and therefore are not compared textually with the long canonical spelling.
  realpathSync.native(absolute)
  return absolute
}

function assertRealFile(
  path: string,
  expectedParent: string,
  maxBytes = MAX_ENGINE_BYTES,
  label = 'packaged engine'
): string {
  const absolute = resolve(path)
  if (!isAbsolute(absolute) || !samePath(dirname(absolute), expectedParent)) {
    throw new EngineIntegrityError(`${label} escaped its fixed directory`)
  }
  assertNoRedirectingComponents(absolute)
  const info = lstatSync(absolute)
  if (!info.isFile() || info.isSymbolicLink() || info.size <= 0 || info.size > maxBytes) {
    throw new EngineIntegrityError(`${label} is not an acceptable regular file`)
  }
  realpathSync.native(absolute)
  return absolute
}

function sameFileIdentity(left: Stats, right: Stats): boolean {
  return left.dev === right.dev && left.ino === right.ino
}

function sameOpenedFileState(left: Stats, right: Stats): boolean {
  return (
    sameFileIdentity(left, right) &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs
  )
}

/**
 * Read one exact file object through a single handle.  The optional synchronous
 * hook is an audit seam used to prove pathname replacement is detected; normal
 * callers must omit it.
 */
export function readStableBoundedFile(
  path: string,
  expectedParent: string,
  maxBytes: number,
  label: string,
  afterOpenForAudit?: () => void
): { path: string; bytes: Buffer } {
  const absolute = assertRealFile(path, expectedParent, maxBytes, label)
  const pathBefore = lstatSync(absolute)
  let handle: number | null = null
  try {
    handle = openSync(absolute, 'r')
    const openedBefore = fstatSync(handle)
    if (
      !openedBefore.isFile() ||
      openedBefore.size <= 0 ||
      openedBefore.size > maxBytes ||
      !sameFileIdentity(pathBefore, openedBefore)
    ) {
      throw new EngineIntegrityError(`${label} changed identity before it could be read`)
    }

    afterOpenForAudit?.()

    const bytes = Buffer.allocUnsafe(openedBefore.size)
    let offset = 0
    while (offset < bytes.length) {
      const count = readSync(handle, bytes, offset, bytes.length - offset, offset)
      if (count <= 0) throw new EngineIntegrityError(`${label} changed size while being read`)
      offset += count
    }
    const openedAfter = fstatSync(handle)
    if (!sameOpenedFileState(openedBefore, openedAfter)) {
      throw new EngineIntegrityError(`${label} changed while being read`)
    }

    const pathAfter = lstatSync(absolute)
    if (
      pathAfter.isSymbolicLink() ||
      !pathAfter.isFile() ||
      !sameFileIdentity(openedAfter, pathAfter)
    ) {
      throw new EngineIntegrityError(`${label} pathname was replaced while being read`)
    }
    assertNoRedirectingComponents(absolute)
    realpathSync.native(absolute)
    return { path: absolute, bytes }
  } finally {
    if (handle !== null) closeSync(handle)
  }
}

/** Hash a large native payload through one handle with a fixed 1 MiB buffer. */
export function hashStableBoundedPeFile(
  path: string,
  expectedParent: string,
  maxBytes: number,
  label: string,
  onChunkForAudit?: (bytes: number) => void
): { path: string; sha256: string; size: number } {
  const absolute = assertRealFile(path, expectedParent, maxBytes, label)
  const pathBefore = lstatSync(absolute)
  let handle: number | null = null
  try {
    handle = openSync(absolute, 'r')
    const openedBefore = fstatSync(handle)
    if (
      !openedBefore.isFile() ||
      openedBefore.size <= 0 ||
      openedBefore.size > maxBytes ||
      !sameFileIdentity(pathBefore, openedBefore)
    ) {
      throw new EngineIntegrityError(`${label} changed identity before it could be hashed`)
    }
    const dos = Buffer.alloc(64)
    if (readSync(handle, dos, 0, dos.length, 0) !== dos.length || dos.toString('ascii', 0, 2) !== 'MZ') {
      throw new EngineIntegrityError(`${label} is not a Windows PE executable`)
    }
    const peOffset = dos.readUInt32LE(0x3c)
    const pe = Buffer.alloc(6)
    if (
      peOffset < 64 ||
      peOffset + pe.length > openedBefore.size ||
      readSync(handle, pe, 0, pe.length, peOffset) !== pe.length ||
      pe.toString('ascii', 0, 4) !== 'PE\0\0' ||
      pe.readUInt16LE(4) !== 0x8664
    ) {
      throw new EngineIntegrityError(`${label} is not an x64 PE executable`)
    }

    const digest = createHash('sha256')
    const buffer = Buffer.allocUnsafe(Math.min(1024 * 1024, openedBefore.size))
    let offset = 0
    while (offset < openedBefore.size) {
      const count = readSync(handle, buffer, 0, Math.min(buffer.length, openedBefore.size - offset), offset)
      if (count <= 0) throw new EngineIntegrityError(`${label} changed size while being hashed`)
      digest.update(buffer.subarray(0, count))
      offset += count
      onChunkForAudit?.(count)
    }
    const openedAfter = fstatSync(handle)
    if (!sameOpenedFileState(openedBefore, openedAfter)) {
      throw new EngineIntegrityError(`${label} changed while being hashed`)
    }
    const pathAfter = lstatSync(absolute)
    if (pathAfter.isSymbolicLink() || !pathAfter.isFile() || !sameFileIdentity(openedAfter, pathAfter)) {
      throw new EngineIntegrityError(`${label} pathname was replaced while being hashed`)
    }
    assertNoRedirectingComponents(absolute)
    realpathSync.native(absolute)
    return { path: absolute, sha256: digest.digest('hex'), size: openedBefore.size }
  } finally {
    if (handle !== null) closeSync(handle)
  }
}

/** Bind the runtime manifest to the embedded ASAR before the engine may see it. */
export async function attestPackagedRuntimeManifest(
  resourcesDirectory: string,
  expectedSha256: string
): Promise<string> {
  const expected = String(expectedSha256 || '').trim().toLowerCase()
  if (!/^[0-9a-f]{64}$/.test(expected)) {
    throw new EngineIntegrityError('local runtime manifest was not bound by the release build')
  }
  const directory = assertRealDirectory(resourcesDirectory)
  const manifest = assertRealFile(
    join(directory, 'local-runtime-manifest.json'),
    directory,
    MAX_RUNTIME_MANIFEST_BYTES,
    'local runtime manifest'
  )
  const stable = readStableBoundedFile(
    manifest,
    directory,
    MAX_RUNTIME_MANIFEST_BYTES,
    'local runtime manifest'
  )
  const actual = createHash('sha256').update(stable.bytes).digest('hex')
  if (!timingSafeEqual(Buffer.from(actual, 'hex'), Buffer.from(expected, 'hex'))) {
    throw new EngineIntegrityError('local runtime manifest does not match the signed release binding')
  }
  let payload: unknown
  try {
    payload = JSON.parse(stable.bytes.toString('utf8'))
  } catch (error) {
    throw new EngineIntegrityError('local runtime manifest is not valid JSON', { cause: error })
  }
  if (
    !payload ||
    typeof payload !== 'object' ||
    Array.isArray(payload) ||
    (payload as { schema?: unknown }).schema !== 1 ||
    !Array.isArray((payload as { artifacts?: unknown }).artifacts) ||
    (payload as { artifacts: unknown[] }).artifacts.length > 4096
  ) {
    throw new EngineIntegrityError('local runtime manifest has an invalid bounded schema')
  }
  return stable.path
}

export interface AttestedPackagedStoreRuntimeProfile {
  path: string
  sha256: string
}

function exactSortedStrings(value: unknown, expected: readonly string[]): boolean {
  return (
    Array.isArray(value) &&
    value.length === expected.length &&
    value.every((item, index) => item === expected[index])
  )
}

/** Bind the immutable store capability profile to bytes embedded in the ASAR. */
export async function attestPackagedStoreRuntimeProfile(
  resourcesDirectory: string,
  expectedSha256: string
): Promise<AttestedPackagedStoreRuntimeProfile> {
  const expected = checkedDigest(expectedSha256, 'store runtime profile digest')
  const directory = assertRealDirectory(resourcesDirectory)
  const stable = readStableBoundedFile(
    join(directory, 'store-runtime-profile.v1.json'),
    directory,
    MAX_STORE_RUNTIME_PROFILE_BYTES,
    'store runtime profile'
  )
  const actual = createHash('sha256').update(stable.bytes).digest('hex')
  if (!timingSafeEqual(Buffer.from(actual, 'hex'), Buffer.from(expected, 'hex'))) {
    throw new EngineIntegrityError('store runtime profile digest differs from the embedded ASAR binding')
  }
  const text = stable.bytes.toString('utf8')
  if (
    !Buffer.from(text, 'utf8').equals(stable.bytes) ||
    text.startsWith('\uFEFF') ||
    text.includes('\0')
  ) {
    throw new EngineIntegrityError('store runtime profile must be canonical UTF-8')
  }
  let payload: any
  try {
    payload = JSON.parse(text)
  } catch (error) {
    throw new EngineIntegrityError('store runtime profile is not valid JSON', { cause: error })
  }
  const fields = Object.keys(payload || {}).sort()
  if (
    !payload ||
    typeof payload !== 'object' ||
    Array.isArray(payload) ||
    fields.join(',') !== [
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
    !exactSortedStrings(payload.capabilities, [
      'http-model-provider',
      'packaged-local-model-program',
      'packaged-media-program'
    ]) ||
    !exactSortedStrings(payload.connectionTypes, ['openai_compat', 'perplexity', 'volcano']) ||
    !exactSortedStrings(payload.providerTypes, ['echo', 'openai_compat', 'perplexity', 'volcano']) ||
    !exactSortedStrings(payload.externalProgramAuthorities, ['final-payload-manifest']) ||
    !exactSortedStrings(payload.externalProgramRoles, ['ffmpeg', 'ffprobe', 'llama-server']) ||
    !exactSortedStrings(payload.frozenPythonExcludes, [
      'gateway.providers.claude_code',
      'gateway.providers.codex',
      'yt_dlp'
    ])
  ) {
    throw new EngineIntegrityError('store runtime profile is not the closed v1 store policy')
  }
  return { path: stable.path, sha256: actual }
}

export function bindAttestedStoreRuntimeProfileEnvironment(
  environment: NodeJS.ProcessEnv,
  profile: AttestedPackagedStoreRuntimeProfile
): NodeJS.ProcessEnv {
  return {
    ...environment,
    NACHUAN_RUNTIME_PROFILE: 'store',
    NACHUAN_STORE_RUNTIME_PROFILE_MANIFEST: profile.path,
    NACHUAN_STORE_RUNTIME_PROFILE_SHA256: profile.sha256
  }
}

export async function sha256File(path: string): Promise<string> {
  const digest = createHash('sha256')
  await new Promise<void>((accept, reject) => {
    const input = createReadStream(path)
    input.on('data', (chunk) => digest.update(chunk))
    input.once('error', reject)
    input.once('end', accept)
  })
  return digest.digest('hex')
}

/**
 * Bind the executable launched by packaged Electron to a digest compiled into
 * the signed main bundle.  The directory is closed: adjacent DLL/script drops
 * are refused instead of being available to the Windows loader.
 */
export async function attestPackagedEngine(
  engineDirectory: string,
  engineName: string,
  expectedSha256: string
): Promise<string> {
  const expected = String(expectedSha256 || '').trim().toLowerCase()
  if (!/^[0-9a-f]{64}$/.test(expected)) {
    throw new EngineIntegrityError('packaged engine digest was not bound by the release build')
  }
  if (!engineName || basename(engineName) !== engineName) {
    throw new EngineIntegrityError('invalid packaged engine filename')
  }
  const directory = assertRealDirectory(engineDirectory)
  const entries = readdirSync(directory)
  if (entries.length !== 1 || entries[0] !== engineName) {
    throw new EngineIntegrityError('packaged engine directory contains unreviewed sidecar files')
  }
  const executable = assertRealFile(join(directory, engineName), directory)
  const actual = await sha256File(executable)
  if (!timingSafeEqual(Buffer.from(actual, 'hex'), Buffer.from(expected, 'hex'))) {
    throw new EngineIntegrityError('packaged engine SHA-256 does not match the signed release binding')
  }
  return executable
}

export interface AttestedPackagedMediaRuntime {
  ffmpegPath: string
  ffmpegSha256: string
  ffprobePath: string
  ffprobeSha256: string
  manifestPath: string
}

function checkedDigest(value: string, label: string): string {
  const digest = String(value || '').trim().toLowerCase()
  if (!/^[0-9a-f]{64}$/.test(digest)) {
    throw new EngineIntegrityError(`${label} was not bound by the release build`)
  }
  return digest
}

export async function attestPackagedMediaRuntime(
  resourcesDirectory: string,
  expected: {
    ffmpegSha256: string
    ffprobeSha256: string
    manifestSha256: string
  }
): Promise<AttestedPackagedMediaRuntime> {
  const ffmpegSha256 = checkedDigest(expected.ffmpegSha256, 'packaged ffmpeg digest')
  const ffprobeSha256 = checkedDigest(expected.ffprobeSha256, 'packaged ffprobe digest')
  const manifestSha256 = checkedDigest(expected.manifestSha256, 'media runtime manifest digest')
  const resources = assertRealDirectory(resourcesDirectory)
  const manifest = readStableBoundedFile(
    join(resources, 'media-runtime-manifest.json'),
    resources,
    MAX_RUNTIME_MANIFEST_BYTES,
    'media runtime manifest'
  )
  const actualManifest = createHash('sha256').update(manifest.bytes).digest('hex')
  if (!timingSafeEqual(Buffer.from(actualManifest, 'hex'), Buffer.from(manifestSha256, 'hex'))) {
    throw new EngineIntegrityError('media runtime manifest does not match the embedded ASAR binding')
  }
  let payload: any
  try {
    payload = JSON.parse(manifest.bytes.toString('utf8'))
  } catch (error) {
    throw new EngineIntegrityError('media runtime manifest is not valid JSON', { cause: error })
  }
  if (
    payload?.schema !== 'nachuan.media-runtime-manifest.v1' ||
    payload?.authenticode?.status !== 'NotSigned' ||
    payload?.authenticode?.signer !== null ||
    payload?.authenticode?.timestamp !== null ||
    payload?.releaseAdmission?.production !== 'blocked' ||
    payload?.releaseAdmission?.trustClass !== 'unsigned-fixed-hash-engineering-candidate' ||
    !Array.isArray(payload?.artifacts) ||
    payload.artifacts.length !== 2
  ) {
    throw new EngineIntegrityError('media runtime manifest schema/trust class is invalid')
  }
  const descriptors = new Map(payload.artifacts.map((item: any) => [item?.role, item]))
  const media = assertRealDirectory(join(resources, 'media'))
  const entries = readdirSync(media).sort()
  if (JSON.stringify(entries) !== JSON.stringify(['ffmpeg.exe', 'ffprobe.exe'])) {
    throw new EngineIntegrityError('packaged media directory contains unreviewed sidecar files')
  }
  const attest = (role: 'ffmpeg' | 'ffprobe', digest: string) => {
    const descriptor: any = descriptors.get(role)
    const name = `${role}.exe`
    if (
      descriptor?.path !== `media/${name}` ||
      descriptor?.sha256 !== digest ||
      !Number.isSafeInteger(descriptor?.size) ||
      descriptor.size <= 0 ||
      descriptor.size > MAX_MEDIA_EXECUTABLE_BYTES
    ) {
      throw new EngineIntegrityError(`packaged ${role} descriptor is invalid`)
    }
    const stable = hashStableBoundedPeFile(
      join(media, name),
      media,
      MAX_MEDIA_EXECUTABLE_BYTES,
      `packaged ${role}`
    )
    if (stable.size !== descriptor.size) {
      throw new EngineIntegrityError(`packaged ${role} size differs from the ASAR binding`)
    }
    if (!timingSafeEqual(Buffer.from(stable.sha256, 'hex'), Buffer.from(digest, 'hex'))) {
      throw new EngineIntegrityError(`packaged ${role} SHA-256 differs from the ASAR binding`)
    }
    return stable.path
  }
  return {
    ffmpegPath: attest('ffmpeg', ffmpegSha256),
    ffmpegSha256,
    ffprobePath: attest('ffprobe', ffprobeSha256),
    ffprobeSha256,
    manifestPath: manifest.path
  }
}

export function bindAttestedMediaRuntimeEnvironment(
  environment: NodeJS.ProcessEnv,
  runtime: AttestedPackagedMediaRuntime
): NodeJS.ProcessEnv {
  return {
    ...environment,
    FFMPEG_BIN: runtime.ffmpegPath,
    FFMPEG_SHA256: runtime.ffmpegSha256,
    FFPROBE_BIN: runtime.ffprobePath,
    FFPROBE_SHA256: runtime.ffprobeSha256,
    NACHUAN_MEDIA_RUNTIME_MANIFEST: runtime.manifestPath
  }
}

export function minimalPackagedEngineEnvironment(
  source: NodeJS.ProcessEnv = process.env
): NodeJS.ProcessEnv {
  const allowed = new Set([
    'SYSTEMROOT',
    'WINDIR',
    'SYSTEMDRIVE',
    'TEMP',
    'TMP',
    'TMPDIR',
    'LANG',
    'LC_ALL',
    'LC_CTYPE'
  ])
  const output: NodeJS.ProcessEnv = {}
  for (const [name, value] of Object.entries(source)) {
    if (value !== undefined && allowed.has(name.toUpperCase())) output[name] = value
  }
  output.PYTHONNOUSERSITE = '1'
  output.PYTHONDONTWRITEBYTECODE = '1'
  output.NO_PROXY = '127.0.0.1,localhost,::1'
  return output
}

/**
 * Development still launches a fixed .venv Python, but local Codex and
 * media tools need selected profile/PATH bootstrap values. Keep an exact list:
 * no API key, PAT, bot token, proxy credential, or wildcard *_KEY/*_TOKEN is
 * inherited merely because Electron was started from a developer shell.
 */
export function minimalDevelopmentEngineEnvironment(
  source: NodeJS.ProcessEnv = process.env
): NodeJS.ProcessEnv {
  const allowed = new Set([
    'SYSTEMROOT',
    'WINDIR',
    'SYSTEMDRIVE',
    'COMSPEC',
    'PATH',
    'PATHEXT',
    'USERPROFILE',
    'HOME',
    'APPDATA',
    'LOCALAPPDATA',
    'TEMP',
    'TMP',
    'TMPDIR',
    'LANG',
    'LC_ALL',
    'LC_CTYPE',
    'SSL_CERT_FILE',
    'SSL_CERT_DIR',
    'NODE_EXTRA_CA_CERTS',
    'CODEX_HOME',
    'CODEX_CLI_PATH',
    'CODEX_CLI_SHA256',
    'FFMPEG_BIN',
    'FFMPEG_SHA256',
    'FFPROBE_BIN',
    'FFPROBE_SHA256'
  ])
  const output: NodeJS.ProcessEnv = {}
  for (const [name, value] of Object.entries(source)) {
    if (value !== undefined && allowed.has(name.toUpperCase())) output[name] = value
  }
  output.PYTHONNOUSERSITE = '1'
  output.PYTHONDONTWRITEBYTECODE = '1'
  output.NO_PROXY = '127.0.0.1,localhost,::1'
  return output
}
