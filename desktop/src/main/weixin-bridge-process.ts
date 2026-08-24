import { dirname, isAbsolute, join } from 'node:path'
import { lstatSync } from 'node:fs'

export interface WeixinBridgeLaunchInput {
  packaged: boolean
  engineExecutable: string
  repoRoot: string
  dataDirectory: string
  enginePort: number
  bridgeKey: string
  sourceEnvironment?: NodeJS.ProcessEnv
}

export interface WeixinBridgeLaunch {
  command: string
  args: string[]
  cwd: string
  env: NodeJS.ProcessEnv
}

export interface WeixinBridgeChild {
  pid?: number
  exitCode: number | null
  kill(): boolean
  once(event: 'error' | 'exit', listener: (...args: unknown[]) => void): unknown
}

export interface WeixinBridgeSupervisorAdapters {
  configured(dataDirectory: string): boolean
  spawn(launch: WeixinBridgeLaunch): WeixinBridgeChild
  schedule(callback: () => void, delayMs: number): unknown
  cancel(handle: unknown): void
}

const SAFE_ENVIRONMENT_NAMES = new Set([
  'SYSTEMROOT',
  'WINDIR',
  'SYSTEMDRIVE',
  'COMSPEC',
  'PATHEXT',
  'APPDATA',
  'LOCALAPPDATA',
  'USERPROFILE',
  'HOME',
  'TEMP',
  'TMP',
  'TMPDIR',
  'LANG',
  'LC_ALL',
  'LC_CTYPE',
  'NACHUAN_RUNTIME_PROFILE',
  'NACHUAN_STORE_RUNTIME_PROFILE_MANIFEST',
  'NACHUAN_STORE_RUNTIME_PROFILE_SHA256'
])

export function hasConfiguredWeixinLogin(dataDirectory: string): boolean {
  if (!isAbsolute(dataDirectory)) return false
  try {
    const info = lstatSync(join(dataDirectory, 'ilink_token.json'))
    return (
      info.isFile() &&
      !info.isSymbolicLink() &&
      info.size > 0 &&
      info.size <= 64 * 1024
    )
  } catch {
    return false
  }
}

/**
 * Build the only Desktop-managed Weixin launch contract. The channel child
 * receives one scoped loopback capability and no renderer/runtime/provider
 * credentials. Installed builds reuse the already attested signed engine
 * payload instead of depending on an ambient Python installation.
 */
export function buildWeixinBridgeLaunch(input: WeixinBridgeLaunchInput): WeixinBridgeLaunch {
  if (!Number.isInteger(input.enginePort) || input.enginePort < 1024 || input.enginePort > 65535) {
    throw new Error('invalid Weixin bridge engine port')
  }
  if (!/^sk-bridge-v2-weixin-[0-9a-f]{64}$/.test(input.bridgeKey)) {
    throw new Error('invalid Weixin bridge capability')
  }
  if (!isAbsolute(input.dataDirectory) || !isAbsolute(input.repoRoot)) {
    throw new Error('Weixin bridge directories must be absolute')
  }

  const env: NodeJS.ProcessEnv = {}
  for (const [name, value] of Object.entries(input.sourceEnvironment || process.env)) {
    if (value !== undefined && SAFE_ENVIRONMENT_NAMES.has(name.toUpperCase())) {
      env[name] = value
    }
  }
  env.NACHUAN_ENV = 'production'
  env.DATA_DIR = input.dataDirectory
  env.USAGE_DB_PATH = join(input.dataDirectory, 'usage.db')
  env.BRIDGE_API_KEY = input.bridgeKey
  env.BRIDGE_ENGINE_URL = `http://127.0.0.1:${input.enginePort}`
  env.NO_PROXY = '127.0.0.1,localhost,::1'
  env.PYTHONNOUSERSITE = '1'
  env.PYTHONDONTWRITEBYTECODE = '1'
  env.PYTHONUTF8 = '1'
  env.PYTHONIOENCODING = 'utf-8'
  env.PYTHONUNBUFFERED = '1'

  if (input.packaged) {
    if (!isAbsolute(input.engineExecutable)) {
      throw new Error('packaged Weixin bridge requires an absolute engine executable')
    }
    if (
      env.NACHUAN_RUNTIME_PROFILE !== 'store' ||
      !env.NACHUAN_STORE_RUNTIME_PROFILE_MANIFEST ||
      !isAbsolute(env.NACHUAN_STORE_RUNTIME_PROFILE_MANIFEST) ||
      !/^[0-9a-f]{64}$/.test(env.NACHUAN_STORE_RUNTIME_PROFILE_SHA256 || '')
    ) {
      throw new Error('packaged Weixin bridge requires the attested store profile binding')
    }
    return {
      command: input.engineExecutable,
      args: ['--nachuan-weixin-bridge'],
      cwd: dirname(input.engineExecutable),
      env
    }
  }

  return {
    command: join(
      input.repoRoot,
      '.venv',
      process.platform === 'win32' ? 'Scripts\\python.exe' : 'bin/python'
    ),
    args: ['-u', 'scripts/run_weixin_ilink_bridge.py'],
    cwd: input.repoRoot,
    env
  }
}

/** Keep one bridge bound to the latest verified Desktop engine generation. */
export class DesktopWeixinBridgeSupervisor {
  private active = false
  private input: WeixinBridgeLaunchInput | null = null
  private child: WeixinBridgeChild | null = null
  private restartHandle: unknown = null
  private restartAttempt = 0

  constructor(private readonly adapters: WeixinBridgeSupervisorAdapters) {}

  start(input: WeixinBridgeLaunchInput): boolean {
    this.stop()
    if (!this.adapters.configured(input.dataDirectory)) return false
    this.active = true
    this.input = { ...input }
    this.restartAttempt = 0
    return this.spawnCurrent()
  }

  stop(): void {
    this.active = false
    this.input = null
    if (this.restartHandle !== null) {
      this.adapters.cancel(this.restartHandle)
      this.restartHandle = null
    }
    const child = this.child
    this.child = null
    if (child && child.exitCode === null) child.kill()
  }

  private spawnCurrent(): boolean {
    if (!this.active || !this.input) return false
    const launch = buildWeixinBridgeLaunch(this.input)
    let child: WeixinBridgeChild
    try {
      child = this.adapters.spawn(launch)
    } catch {
      this.scheduleRestart()
      return true
    }
    this.child = child
    const terminal = (): void => {
      if (this.child !== child) return
      this.child = null
      this.scheduleRestart()
    }
    child.once('error', terminal)
    child.once('exit', terminal)
    return true
  }

  private scheduleRestart(): void {
    if (!this.active || !this.input || this.restartHandle !== null) return
    this.restartAttempt = Math.min(6, this.restartAttempt + 1)
    const delayMs = Math.min(30_000, 1000 * 2 ** (this.restartAttempt - 1))
    this.restartHandle = this.adapters.schedule(() => {
      this.restartHandle = null
      if (this.active) this.spawnCurrent()
    }, delayMs)
  }
}
