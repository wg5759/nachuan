import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync
} from 'node:fs'
import { spawnSync } from 'node:child_process'
import { dirname, basename, join, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

const scriptPath = fileURLToPath(import.meta.url)
const desktopRoot = resolve(dirname(scriptPath), '..')
const projectRoot = resolve(desktopRoot, '..')
const TEMP_PREFIX = 'desktop-vitest-'
const EXTERNAL_TEMP_PREFIX = 'nachuan-external-vitest-'

function sameWindowsPath(left, right) {
  const normalize = (value) => resolve(value).replaceAll('/', sep).toLowerCase()
  return normalize(left) === normalize(right)
}

function isInsidePath(candidate, parent) {
  const normalizedCandidate = resolve(candidate).replaceAll('/', sep).toLowerCase()
  const normalizedParent = resolve(parent).replaceAll('/', sep).toLowerCase()
  return (
    normalizedCandidate === normalizedParent ||
    normalizedCandidate.startsWith(`${normalizedParent}${sep}`)
  )
}

function createOwnedTempRoot(parent, prefix, label) {
  const parentInfo = lstatSync(parent)
  if (!parentInfo.isDirectory() || parentInfo.isSymbolicLink()) {
    throw new Error(`${label} parent must be a non-redirected directory`)
  }
  const trustedParent = realpathSync.native(parent)
  const tempRoot = mkdtempSync(join(trustedParent, prefix))
  const rootInfo = lstatSync(tempRoot)
  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) {
    throw new Error(`${label} root must be a non-redirected directory`)
  }
  return { tempRoot, trustedParent }
}

export function createIsolatedVitestTempEnvironment({
  projectRoot: requestedProjectRoot,
  baseEnv = process.env
}) {
  const requestedParent = resolve(requestedProjectRoot, 'build', 'test-temp')
  mkdirSync(requestedParent, { recursive: true })
  const isolated = createOwnedTempRoot(requestedParent, TEMP_PREFIX, 'Vitest isolated temp')
  const externalParentValue = baseEnv.TEMP || baseEnv.TMP
  if (!externalParentValue) {
    cleanupOwnedTempRoot({ ...isolated, prefix: TEMP_PREFIX })
    throw new Error('System TEMP or TMP is required for external signing fixtures')
  }
  const requestedExternalParent = resolve(externalParentValue)
  if (isInsidePath(requestedExternalParent, requestedProjectRoot)) {
    cleanupOwnedTempRoot({ ...isolated, prefix: TEMP_PREFIX })
    throw new Error('External signing fixture parent must stay outside the repository')
  }
  const external = createOwnedTempRoot(
    requestedExternalParent,
    EXTERNAL_TEMP_PREFIX,
    'Vitest external signing fixture'
  )
  return {
    tempRoot: isolated.tempRoot,
    trustedParent: isolated.trustedParent,
    externalTempRoot: external.tempRoot,
    externalTrustedParent: external.trustedParent,
    env: {
      ...baseEnv,
      TEMP: isolated.tempRoot,
      TMP: isolated.tempRoot,
      TMPDIR: isolated.tempRoot,
      NACHUAN_VITEST_TEMP_ROOT: isolated.tempRoot,
      NACHUAN_EXTERNAL_TEST_TEMP_ROOT: external.tempRoot
    }
  }
}

function cleanupOwnedTempRoot({ tempRoot, trustedParent, prefix }) {
  const resolvedRoot = resolve(tempRoot)
  const resolvedParent = resolve(trustedParent)
  if (
    !sameWindowsPath(dirname(resolvedRoot), resolvedParent) ||
    !basename(resolvedRoot).startsWith(prefix)
  ) {
    throw new Error('Refusing to clean a path outside the trusted test-temp parent')
  }
  if (!existsSync(resolvedRoot)) return
  const info = lstatSync(resolvedRoot)
  if (!info.isDirectory() || info.isSymbolicLink()) {
    throw new Error('Refusing to clean a redirected Vitest temp root')
  }
  rmSync(resolvedRoot, {
    recursive: true,
    force: false,
    maxRetries: 20,
    retryDelay: 250
  })
}

export function cleanupIsolatedVitestTempRoot(input) {
  cleanupOwnedTempRoot({
    tempRoot: input.tempRoot,
    trustedParent: input.trustedParent,
    prefix: TEMP_PREFIX
  })
  if (input.externalTempRoot || input.externalTrustedParent) {
    if (!input.externalTempRoot || !input.externalTrustedParent) {
      throw new Error('External signing fixture cleanup identity is incomplete')
    }
    cleanupOwnedTempRoot({
      tempRoot: input.externalTempRoot,
      trustedParent: input.externalTrustedParent,
      prefix: EXTERNAL_TEMP_PREFIX
    })
  }
}

function assertPinnedRuntime() {
  const expected = process.env.NACHUAN_RELEASE_NODE_PATH
  if (!expected || !sameWindowsPath(expected, process.execPath)) {
    throw new Error('Vitest runner must be launched through node-runtime-policy.mjs')
  }
}

export function runIsolatedVitest(argv) {
  if (argv[0] !== 'run') throw new Error('isolated Vitest runner accepts only the run command')
  assertPinnedRuntime()
  const vitestEntry = resolve(desktopRoot, 'node_modules', 'vitest', 'vitest.mjs')
  const entryInfo = lstatSync(vitestEntry)
  if (!entryInfo.isFile() || entryInfo.isSymbolicLink()) {
    throw new Error('Vitest entry must be a non-redirected regular file')
  }
  const isolated = createIsolatedVitestTempEnvironment({ projectRoot })
  let result
  let cleanupError = null
  try {
    result = spawnSync(process.execPath, [vitestEntry, ...argv], {
      cwd: desktopRoot,
      env: isolated.env,
      shell: false,
      stdio: 'inherit',
      windowsHide: true
    })
  } finally {
    try {
      cleanupIsolatedVitestTempRoot(isolated)
    } catch (error) {
      cleanupError = error
    }
  }
  if (result?.error) throw result.error
  if (cleanupError) throw cleanupError
  if (result?.signal) throw new Error(`Vitest terminated by ${result.signal}`)
  return result?.status ?? 1
}

if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  try {
    process.exitCode = runIsolatedVitest(process.argv.slice(2))
  } catch (error) {
    console.error(
      `[vitest-isolated] BLOCKED: ${error instanceof Error ? error.message : String(error)}`
    )
    process.exitCode = 1
  }
}
