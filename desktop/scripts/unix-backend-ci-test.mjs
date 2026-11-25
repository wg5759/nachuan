import { spawnSync } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { existsSync, readdirSync, realpathSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const scriptPath = fileURLToPath(import.meta.url)
const defaultProjectRoot = resolve(dirname(scriptPath), '..', '..')

export const UNIX_PYTHON_VERSION = '3.12.9'

// Strictly Windows-exclusive test modules that directly require Windows APIs/tools:
// - PowerShell CIM / start_all.ps1 supervisor (test_start_all_supervisor.py)
// - WINDIR + Git for Windows bash.exe (test_xreview_roster.py)
// - Windows DPAPI / C:\ProgramData machine vault (test_installed_channel_config.py, test_installed_service_machine_vault.py)
// - Frozen Windows PyInstaller entrypoints that explicitly refuse os.name != 'nt' (test_engine_main.py)
// - Kimi subscription worker/login suite bound to Windows System32 cmd.exe + Job Objects (test_kimi_*.py)
const WINDOWS_ONLY_TEST_FILES = new Set([
  'test_engine_main.py',
  'test_installed_channel_config.py',
  'test_installed_service_machine_vault.py',
  'test_kimi_acp_private_client.py',
  'test_kimi_auth_probe_entrypoint.py',
  'test_kimi_login_entrypoint.py',
  'test_kimi_subscription_login.py',
  'test_kimi_subscription_provider.py',
  'test_kimi_subscription_routing.py',
  'test_kimi_subscription_worker.py',
  'test_kimi_worker_entrypoint.py',
  'test_start_all_supervisor.py',
  'test_xreview_roster.py'
])

function canonicalUnixDir(candidate, fallback = '') {
  const target = candidate || fallback
  if (!target) return ''
  try {
    return realpathSync(target)
  } catch {
    return target
  }
}

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
    .filter(
      (name) =>
        /^test_.*(?:windows|win32|dpapi|icacls|authenticode).*\.py$/i.test(name) ||
        WINDOWS_ONLY_TEST_FILES.has(name)
    )
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

  // Ephemeral per-run passphrase for headless Unix CI runners without a live desktop
  // Secret Service daemon; production fail-closed secret policy remains untouched.
  const ciSandboxPassphrase =
    process.env.NACHUAN_SECRET_FALLBACK_PASSPHRASE ||
    `nachuan-ci-sandbox-${randomBytes(24).toString('hex')}`
  const canonicalTmpDir = canonicalUnixDir(process.env.TMPDIR, '/tmp')
  const canonicalHomeDir = canonicalUnixDir(process.env.HOME, '')

  checked(
    spawnSync(pythonPath, ['-X', 'utf8', '-I', '-S', '-B', '-c', runner], {
      cwd: root,
      env: {
        PATH: process.env.PATH || '/usr/bin:/bin',
        HOME: canonicalHomeDir,
        TMPDIR: canonicalTmpDir,
        TMP: canonicalTmpDir,
        TEMP: canonicalTmpDir,
        LANG: 'C.UTF-8',
        LC_ALL: 'C.UTF-8',
        NACHUAN_SECRET_FALLBACK_PASSPHRASE: ciSandboxPassphrase
      },
      stdio: 'inherit',
      windowsHide: true
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
