import { spawnSync } from 'node:child_process'
import { existsSync, readdirSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const scriptPath = fileURLToPath(import.meta.url)
const defaultProjectRoot = resolve(dirname(scriptPath), '..', '..')

export const UNIX_PYTHON_VERSION = '3.12.9'

export function unixBackendSyncArgs(projectRoot = defaultProjectRoot) {
  return [
    'sync',
    '--directory',
    resolve(projectRoot),
    '--locked',
    '--no-default-groups',
    '--group',
    'dev',
    '--extra',
    'dev',
    '--python',
    UNIX_PYTHON_VERSION,
    '--managed-python',
    '--no-python-downloads'
  ]
}

export function unixBackendFilterExpression() {
  return 'not windows and not win32 and not dpapi and not icacls and not authenticode'
}

export function unixBackendIgnoredTestFiles(projectRoot = defaultProjectRoot) {
  const testsRoot = join(resolve(projectRoot), 'tests')
  if (!existsSync(testsRoot)) return []
  return readdirSync(testsRoot)
    .filter((name) => /^test_.*(?:windows|win32|dpapi|icacls|authenticode).*\.py$/i.test(name))
    .sort()
    .map((name) => join(testsRoot, name))
}

function cleanEnv(source = process.env) {
  return Object.fromEntries(
    Object.entries(source).filter(([key]) => !/^(?:UV|PIP|PYTHON)/i.test(key))
  )
}

function unixSitePackages(projectRoot) {
  const libDir = join(resolve(projectRoot), '.venv', 'lib')
  const pyDir = readdirSync(libDir).find((entry) => entry.startsWith('python'))
  if (!pyDir) throw new Error('Unix virtual environment site-packages directory is missing')
  return join(libDir, pyDir, 'site-packages')
}

function checked(result, label) {
  if (result.error) throw result.error
  if (result.signal || result.status !== 0) {
    throw new Error(`${label} failed: ${result.signal || result.status}`)
  }
}

export function runUnixBackendTests(projectRoot = defaultProjectRoot) {
  if (process.platform === 'win32') {
    throw new Error('unix-backend-ci-test.mjs is intended for Linux/macOS runners only')
  }
  const root = resolve(projectRoot)
  const spawnOpts = { cwd: root, env: cleanEnv(), stdio: 'inherit' }
  checked(spawnSync('uv', unixBackendSyncArgs(root), spawnOpts), 'locked unix uv sync')

  const pythonPath = join(root, '.venv', 'bin', 'python')
  const sitePackages = unixSitePackages(root)
  const testsRoot = join(root, 'tests')
  const ignoreArgs = unixBackendIgnoredTestFiles(root).flatMap((file) => ['--ignore', file])
  const pytestArgs = [
    '-q',
    '-p',
    'no:cacheprovider',
    '-p',
    'pytest_asyncio.plugin',
    '-k',
    unixBackendFilterExpression(),
    ...ignoreArgs,
    testsRoot
  ]
  const runner = [
    'import os,sys',
    'base=list(sys.path)',
    `sys.path[:]=[${JSON.stringify(sitePackages)},${JSON.stringify(root)},${JSON.stringify(testsRoot)},*base]`,
    "os.environ['PYTEST_DISABLE_PLUGIN_AUTOLOAD']='1'",
    'from pytest import main',
    `raise SystemExit(main(${JSON.stringify(pytestArgs)}))`
  ].join(';')

  checked(
    spawnSync(pythonPath, ['-X', 'utf8', '-I', '-S', '-B', '-c', runner], {
      cwd: root,
      env: {
        PATH: process.env.PATH || '/usr/bin:/bin',
        HOME: process.env.HOME || '',
        TMPDIR: process.env.TMPDIR || '/tmp',
        LANG: 'C.UTF-8',
        LC_ALL: 'C.UTF-8'
      },
      stdio: 'inherit'
    }),
    'isolated unix core backend tests'
  )
}

if (resolve(process.argv[1] || '') === resolve(scriptPath)) {
  try {
    runUnixBackendTests()
  } catch (error) {
    console.error(`[unix-backend-ci-test] FAILED: ${error.message}`)
    process.exitCode = 1
  }
}
