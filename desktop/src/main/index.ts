import {
  app,
  BrowserWindow,
  clipboard,
  desktopCapturer,
  dialog,
  globalShortcut,
  ipcMain,
  Menu,
  nativeImage,
  nativeTheme,
  powerMonitor,
  protocol,
  safeStorage,
  screen,
  session,
  shell,
  Tray
} from 'electron'
import { join, parse, resolve, sep } from 'node:path'
import { spawn, ChildProcess } from 'node:child_process'
import { randomBytes, randomUUID } from 'node:crypto'
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  realpathSync,
  statfsSync,
  statSync,
  writeFileSync
} from 'node:fs'
import { tmpdir } from 'node:os'
import { pathToFileURL } from 'node:url'

import {
  hardenLocalSecretAcl,
  loadOrCreateApprovalKey,
  loadOrCreateEngineKey,
  loadOrCreatePaidMediaKey,
  readSecureConfig,
  writeSecureConfig
} from './secure-config'
import { nodePaidMediaAtomicIO, PaidMediaLedger } from './paid-media-ledger'
import { PaidMediaCapacityManager } from './paid-media-capacity'
import { registerPaidMediaIpc, type PaidMediaIpcRegistration } from './paid-media-ipc'
import {
  nodePaidMediaTransport,
  PaidMediaService,
  type PaidMediaAssetV2Executor
} from './paid-media-service'
import {
  convergePaidMediaAssetV2StartupAcks,
  PaidMediaAssetV2Runtime
} from './paid-media-asset-v2-runtime'
import {
  nodePaidMediaRemoteFetcher,
  PaidMediaVault
} from './paid-media-vault'
import { handlePaidMediaAssetRequest } from './paid-media-protocol'
import { PaidMediaProbeClient } from './paid-media-probe-client'
import { PaidMediaEngineSessionClient } from './paid-media-engine-session-client'
import { activatePaidMediaEngineSessionStage } from './paid-media-engine-session-stage-client'
import {
  acknowledgePaidMediaAssets,
  createPaidMediaImageAssets,
  downloadPaidMediaAsset
} from './paid-media-asset-client'
import { probePaidMediaStagedAsset } from './paid-media-engine-session-probe-client'
import {
  attestPackagedEngine,
  attestPackagedMediaRuntime,
  attestPackagedRuntimeManifest,
  bindAttestedMediaRuntimeEnvironment,
  attestPackagedStoreRuntimeProfile,
  bindAttestedStoreRuntimeProfileEnvironment,
  minimalDevelopmentEngineEnvironment,
  minimalPackagedEngineEnvironment
} from './engine-integrity'
import {
  enforcePackagedFinancialLedger,
  selectLoopbackPort,
  waitForEngineReady
} from './engine-process'
import {
  DesktopWeixinBridgeSupervisor,
  hasConfiguredWeixinLogin,
  type WeixinBridgeChild
} from './weixin-bridge-process'
import { EngineRootSessionAuthority, type EngineBootAttempt } from './engine-root-session'
import { DesktopEngineSessionClient } from './desktop-engine-session-client'
import { DesktopPrivilegedSession } from './desktop-privileged-session'
import { RendererEngineProxy } from './renderer-engine-proxy'
import { registerRendererEngineProxyIpc } from './renderer-engine-ipc'
import { registerPluginUiIpc } from './plugin-ui-ipc'
import { InstallationRootClient } from './installation-root-client'
import { InstallationRootUpdaterAuthority } from './installation-root-updater'
import {
  nodePaidMediaInstallationRootAtomicIO,
  PaidMediaInstallationRootAuthority
} from './paid-media-installation-root'
import { PaidMediaMutationGate } from './paid-media-mutation-gate'
import { PaidMediaRecoveryExecutor } from './paid-media-recovery-executor'
import {
  PaidMediaRecoveryIntentStore,
  type PaidMediaRecoveryIntentPayload
} from './paid-media-recovery-intent'
import { PaidMediaRecoveryExecutorSlot } from './paid-media-recovery-wiring'
import {
  nodePaidMediaLegacySealAtomicIO,
  PaidMediaLegacySeal
} from './paid-media-legacy-seal'
import { decidePaidMediaStartup } from './paid-media-startup-policy'
import {
  EXPECTED_LOCAL_RUNTIME_MANIFEST_SHA256,
  EXPECTED_MEDIA_RUNTIME_MANIFEST_SHA256,
  EXPECTED_PACKAGED_FFMPEG_SHA256,
  EXPECTED_PACKAGED_FFPROBE_SHA256,
  EXPECTED_PACKAGED_ENGINE_SHA256,
  EXPECTED_STORE_RUNTIME_PROFILE_SHA256
} from './generated-engine-integrity'
import { assertFixedPackagedUserDataDirectory } from './startup-policy'
import { EMBEDDED_UPDATE_TRUST } from './generated-update-trust'
import { requireStrictAuthenticode } from './authenticode'
import {
  fetchBoundedSignedUpdateEnvelope,
  SecureAutoUpdater,
  type SecureUpdaterAdapter,
  type UpdateUiState
} from './secure-auto-updater'
import { UpdateCheckScheduler } from './update-scheduler'
import { DesktopAuditLog } from './desktop-audit-log'
import { createInstalledSupportBundle } from './support-bundle'
import {
  downloadPublicMedia,
  MAX_INLINE_MEDIA_BYTES,
  writeBoundedMediaBytes
} from './media-download'

import {
  automaticUpdatePolicy,
  debugPolicy,
  isHttpUrl,
  ipcSenderAllowed,
  isLoopbackRendererUrl,
  isTrustedRendererNavigation,
  permissionAllowed,
  windowSecurityPreferences
} from './security'

let engineProc: ChildProcess | null = null
let enginePort = 0
let engineStartPromise: Promise<void> | null = null
const engineRootSessions = new EngineRootSessionAuthority()
const desktopEngineSessionClient = new DesktopEngineSessionClient({
  session: () => engineRootSessions.session()
})
const desktopPrivilegedSession = new DesktopPrivilegedSession(desktopEngineSessionClient)
const rendererEngineProxy = new RendererEngineProxy({
  session: () => engineRootSessions.session(),
  runtimeKey: () => engineKey
})
const installationRootClient = new InstallationRootClient({
  session: () => engineRootSessions.session()
})
let engineKey = ''
let approvalKey = ''
let paidMediaKey = ''
let weixinBridgeKey = ''
let isQuitting = false
// 引擎看门狗：意外退出连续重启计数（稳定运行后清零）+ 退避定时器 + 健康清零定时器。
let engineRestarts = 0
let engineRestartTimer: ReturnType<typeof setTimeout> | null = null
let engineHealthyTimer: ReturnType<typeof setTimeout> | null = null
let mainWin: BrowserWindow | null = null
let paidMediaService: PaidMediaService | null = null
let paidMediaVault: PaidMediaVault | null = null
let paidMediaIpcRegistration: PaidMediaIpcRegistration | null = null
let desktopAuditLog: DesktopAuditLog | null = null
let secureAutoUpdater: SecureAutoUpdater | null = null
let updateScheduler: UpdateCheckScheduler | null = null
let latestUpdateState: UpdateUiState = { phase: 'disabled', reason: 'not-configured' }
let supportBundleInFlight: Promise<void> | null = null

protocol.registerSchemesAsPrivileged([
  {
    scheme: 'nachuan-paid-media',
    privileges: {
      standard: true,
      secure: true,
      supportFetchAPI: true,
      stream: true
    }
  }
])

function auditDesktop(event: string, fields: Record<string, unknown> = {}): void {
  desktopAuditLog?.write(event, fields)
}

const weixinBridgeSupervisor = new DesktopWeixinBridgeSupervisor({
  configured: hasConfiguredWeixinLogin,
  spawn: (launch) => {
    const child = spawn(launch.command, launch.args, {
      cwd: launch.cwd,
      env: launch.env,
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
      shell: false
    })
    child.stdout?.on('data', (data) => console.log('[weixin]', String(data).trim()))
    child.stderr?.on('data', (data) => console.error('[weixin]', String(data).trim()))
    auditDesktop('weixin_bridge.spawn', { pid: child.pid ?? 0 })
    return child as unknown as WeixinBridgeChild
  },
  schedule: (callback, delayMs) => setTimeout(callback, delayMs),
  cancel: (handle) => clearTimeout(handle as ReturnType<typeof setTimeout>)
})

function paidMediaPathKey(path: string): string {
  const normalized = resolve(path)
  return process.platform === 'win32' ? normalized.toLowerCase() : normalized
}

function canonicalExistingPaidMediaDirectory(
  path: string,
  label: string,
  allowCanonicalAlias = false
): string {
  const absolute = resolve(path)
  const root = parse(absolute).root
  let cursor = root
  for (const part of absolute.slice(root.length).split(sep).filter(Boolean)) {
    cursor = join(cursor, part)
    const component = lstatSync(cursor)
    if (component.isSymbolicLink()) {
      throw new Error(`${label} path must not contain filesystem redirects`)
    }
  }
  const info = lstatSync(absolute)
  if (!info.isDirectory() || info.isSymbolicLink()) {
    throw new Error(`${label} must be a real directory`)
  }
  const canonical = realpathSync.native(absolute)
  if (!allowCanonicalAlias && paidMediaPathKey(canonical) !== paidMediaPathKey(absolute)) {
    throw new Error(`${label} must already use its canonical filesystem path`)
  }
  return canonical
}

function canonicalPaidMediaTempRoot(): string {
  // Windows may return an 8.3 spelling for its real per-user temp directory.
  // Resolve that one OS alias once, then expose only the canonical path to the
  // capacity journal and the child process.
  const canonical = canonicalExistingPaidMediaDirectory(
    tmpdir(),
    'paid media OS temp directory',
    true
  )
  if (process.platform === 'win32' && !/^[a-z]:\\$/i.test(parse(canonical).root)) {
    throw new Error('paid media OS temp directory must use a stable local volume')
  }
  // Never harden or lease the shared OS temp root itself.  Engine scratch and
  // Desktop stage leaves live below one dedicated, current-user directory so
  // ACL repair cannot disturb unrelated applications using the same temp root.
  const runtimeRoot = ensurePaidMediaChildDirectory(
    canonical,
    'nachuan-runtime',
    'paid media dedicated runtime temp directory'
  )
  hardenLocalSecretAcl(runtimeRoot, true)
  return canonicalExistingPaidMediaDirectory(
    runtimeRoot,
    'paid media dedicated runtime temp directory'
  )
}

function canonicalPaidMediaStageRoot(runtimeRoot: string): string {
  const stageRoot = ensurePaidMediaChildDirectory(
    canonicalExistingPaidMediaDirectory(
      runtimeRoot,
      'paid media dedicated runtime temp directory'
    ),
    'paid-media-stage-v2',
    'paid media dedicated stage directory'
  )
  hardenLocalSecretAcl(stageRoot, true)
  return canonicalExistingPaidMediaDirectory(stageRoot, 'paid media dedicated stage directory')
}

function resolvePaidMediaVolume(path: string): { volumeId: string; root: string } {
  const canonical = canonicalExistingPaidMediaDirectory(path, 'paid media capacity role directory')
  const parsedRoot = parse(canonical).root
  if (process.platform === 'win32' && !/^[a-z]:\\$/i.test(parsedRoot)) {
    throw new Error('paid media capacity requires a stable local volume root')
  }
  const volumeRoot = canonicalExistingPaidMediaDirectory(
    parsedRoot,
    'paid media capacity volume root'
  )
  const directoryInfo = statSync(canonical, { bigint: true })
  const volumeInfo = statSync(volumeRoot, { bigint: true })
  if (directoryInfo.dev !== volumeInfo.dev) {
    throw new Error('paid media capacity directory changed volumes during resolution')
  }
  return { volumeId: `dev:${volumeInfo.dev.toString(10)}`, root: volumeRoot }
}

function paidMediaFreeBytes(root: string): bigint {
  const canonical = canonicalExistingPaidMediaDirectory(root, 'paid media capacity volume root')
  if (paidMediaPathKey(parse(canonical).root) !== paidMediaPathKey(canonical)) {
    throw new Error('paid media capacity free-space probe requires a volume root')
  }
  const space = statfsSync(canonical, { bigint: true })
  if (space.bavail < 0n || space.bsize <= 0n) {
    throw new Error('paid media capacity free-space result is invalid')
  }
  return space.bavail * space.bsize
}

function ensurePaidMediaChildDirectory(parent: string, name: string, label: string): string {
  const target = join(parent, name)
  if (!existsSync(target)) mkdirSync(target, { recursive: false })
  return canonicalExistingPaidMediaDirectory(target, label)
}

assertFixedPackagedUserDataDirectory({
  isPackaged: app.isPackaged,
  hasUserDataDirSwitch: app.commandLine.hasSwitch('user-data-dir')
})
const ownsSingleInstance = app.requestSingleInstanceLock()
if (!ownsSingleInstance) {
  isQuitting = true
  app.quit()
} else {
  app.on('second-instance', () => {
    if (!mainWin || mainWin.isDestroyed()) return
    if (mainWin.isMinimized()) mainWin.restore()
    mainWin.show()
    mainWin.focus()
  })
}

// CDP 只允许开发态显式开启。生产包绝不暴露调试口；开发态也只绑回环并拒绝 Origin 通配符。
const DEBUG = debugPolicy({
  isPackaged: app.isPackaged,
  enableCdp: process.env['NACHUAN_ENABLE_CDP'] === '1',
  enableDevTools: process.env['NACHUAN_DEVTOOLS'] === '1'
})
if (DEBUG.enableCdp) {
  const raw = Number(process.env['NACHUAN_CDP_PORT'] || 9222)
  const port = Number.isInteger(raw) && raw >= 1024 && raw <= 65535 ? raw : 9222
  app.commandLine.appendSwitch('remote-debugging-address', '127.0.0.1')
  app.commandLine.appendSwitch('remote-debugging-port', String(port))
  app.commandLine.appendSwitch(
    'remote-allow-origins',
    `http://127.0.0.1:${port},http://localhost:${port}`
  )
}

function readSupervisorSecretFile(filename: string, pattern: RegExp): string | null {
  const root = sourceRootForVersion()
  const path = root ? join(root, 'data', filename) : ''
  if (!path || !existsSync(path)) return null
  const st = lstatSync(path)
  if (!st.isFile() || st.isSymbolicLink() || st.size > 256) {
    throw new Error(`unsafe supervisor secret file: ${filename}`)
  }
  const value = readFileSync(path, 'utf8').trim()
  if (!pattern.test(value)) throw new Error(`invalid supervisor secret file: ${filename}`)
  return value
}

/** 读取或生成引擎访问 Key（优先配对 supervisor；否则 DPAPI 密文存储）。 */
function loadOrCreateKey(): string {
  const supervised = readSupervisorSecretFile(
    'gateway_api_key.txt',
    /^sk-local-[0-9a-f]{64}$/
  )
  if (supervised) return supervised
  const cfgPath = join(app.getPath('userData'), 'config.json')
  return loadOrCreateEngineKey(
    cfgPath,
    safeStorage,
    () => 'sk-local-' + randomBytes(16).toString('hex')
  )
}

/**
 * Keep approval authority out of the renderer.  When the supervisor already
 * owns the engine, reuse its ACL-protected key; otherwise keep an independent
 * DPAPI-encrypted key and pass it only to the child engine process.
 */
function loadApprovalKey(runtimeKey: string): string {
  const supervised = readSupervisorSecretFile(
    'approval_admin_key.txt',
    /^sk-approval-[0-9a-f]{64}$/
  )
  if (supervised) {
    if (supervised === runtimeKey) throw new Error('approval authority overlaps runtime key')
    return supervised
  }
  return loadOrCreateApprovalKey(
    join(app.getPath('userData'), 'config.json'),
    safeStorage,
    runtimeKey,
    () => 'sk-approval-' + randomBytes(32).toString('hex')
  )
}

/** Keep the paid-route capability in main/engine only; renderer never receives it. */
function loadPaidMediaKey(runtimeKey: string, privilegedKey: string): string {
  return loadOrCreatePaidMediaKey(
    join(app.getPath('userData'), 'config.json'),
    safeStorage,
    runtimeKey,
    privilegedKey,
    () => 'sk-paid-media-' + randomBytes(32).toString('hex')
  )
}

/** 开发期：app.getAppPath() = desktop 项目目录；Python 引擎在其上一级。 */
function repoRoot(): string {
  return join(app.getAppPath(), '..')
}

/** Supervisor secrets are a source-tree development contract, never ambient packaged state. */
function sourceRootForVersion(): string | null {
  if (app.isPackaged) return null
  const dev = repoRoot()
  if (existsSync(join(dev, 'gateway'))) return dev
  return null
}

/** 引擎看门狗：意外退出时按退避自动重启，免得"跑着跑着离线"要手动重开 app。
 *  退避 1→2→4→8→16→30s 封顶；引擎稳定跑满 30s 视为健康、清零计数（下次掉线又从 1s 起）。
 *  app 主动退出（isQuitting）时不拉起。 */
function scheduleEngineRestart(): void {
  if (isQuitting || engineRestartTimer) return
  engineRestarts += 1
  const delay = Math.min(30000, 1000 * 2 ** Math.min(engineRestarts - 1, 5))
  console.log(`[engine] 意外掉线，${delay / 1000}s 后自动重启（第 ${engineRestarts} 次）`)
  auditDesktop('engine.restart_scheduled', { attempt: engineRestarts, delay_ms: delay })
  engineRestartTimer = setTimeout(() => {
    engineRestartTimer = null
    if (!isQuitting) void startEngine().catch(fatalEngineFailure)
  }, delay)
}

function engineBaseUrl(): string {
  const current = engineRootSessions.session()
  if (
    current === null ||
    !Number.isInteger(enginePort) ||
    enginePort < 1024 ||
    current.port !== enginePort ||
    engineProc?.pid !== current.pid ||
    engineProc.exitCode !== null
  ) {
    throw new Error('engine endpoint is unavailable')
  }
  return `http://127.0.0.1:${current.port}`
}

function assertEngineAttemptCurrent(attempt: EngineBootAttempt, pid?: number): void {
  if (isQuitting) throw new Error('engine startup was cancelled')
  engineRootSessions.assertCurrent(attempt, pid)
}

function invalidateEngineAttempt(attempt: EngineBootAttempt, pid?: number): boolean {
  const invalidated = engineRootSessions.invalidate(attempt, pid)
  if (invalidated) enginePort = 0
  return invalidated
}

let engineFatalShown = false
function fatalEngineFailure(error: unknown): void {
  if (isQuitting || engineFatalShown) return
  engineFatalShown = true
  const message = error instanceof Error ? error.message : String(error)
  console.error('[engine] fatal startup/runtime failure:', error)
  auditDesktop('engine.fatal', {
    error_type: error instanceof Error ? error.name : typeof error
  })
  dialog.showErrorBox(
    '纳川引擎启动失败',
    `本次桌面进程未能验证自己启动的引擎，已安全停止，未连接未知端口。\n\n${message}`
  )
  isQuitting = true
  app.quit()
}

function packagedRuntimeDirectories(): {
  data: string
  workspaces: string
  semcache: string
  guardHome: string
} {
  const userData = app.getPath('userData')
  const data = join(userData, 'data')
  const workspaces = join(userData, 'workspaces')
  const semcache = join(data, 'semcache')
  for (const directory of [data, workspaces, semcache]) mkdirSync(directory, { recursive: true })
  return { data, workspaces, semcache, guardHome: app.getPath('home') }
}

async function startEngineOnce(): Promise<void> {
  if (engineProc && engineProc.exitCode === null) {
    const current = engineRootSessions.session()
    if (current && current.pid === engineProc.pid && current.port === enginePort) return
    throw new Error('running engine has no verified boot session')
  }
  const bootToken = randomBytes(32).toString('hex')
  const attempt = engineRootSessions.begin(bootToken)
  enginePort = 0
  let child: ChildProcess | null = null
  let candidatePort = 0
  let bridgeExecutable = ''
  let bridgeDataDirectory = join(repoRoot(), 'data')
  try {
    candidatePort = await selectLoopbackPort()
    assertEngineAttemptCurrent(attempt)
    engineRootSessions.assignPort(attempt, candidatePort)
    const env: NodeJS.ProcessEnv = {
      ...(app.isPackaged
        ? minimalPackagedEngineEnvironment(process.env)
        : minimalDevelopmentEngineEnvironment(process.env)),
      GATEWAY_API_KEYS: engineKey,
      APPROVAL_ADMIN_KEY: approvalKey,
      NACHUAN_PAID_MEDIA_API_KEY: paidMediaKey,
      NACHUAN_WEIXIN_BRIDGE_API_KEY: weixinBridgeKey,
      GATEWAY_HOST: '127.0.0.1',
      GATEWAY_PORT: String(candidatePort),
      NACHUAN_ENGINE_BOOT_TOKEN: bootToken,
      // The paid-media session envelope is bound to the exact Desktop boot
      // generation and listener port.  These are assignments from the same
      // authority that publishes the verified child session; inherited
      // values must never survive into a replacement engine.
      NACHUAN_ENGINE_GENERATION: String(attempt.generation),
      NACHUAN_ENGINE_PORT: String(candidatePort),
      PYTHONNOUSERSITE: '1',
      PYTHONDONTWRITEBYTECODE: '1',
      PYTHONUTF8: '1',
      PYTHONIOENCODING: 'utf-8'
    }
    const paidMediaTemp = canonicalPaidMediaTempRoot()
    env.TEMP = paidMediaTemp
    env.TMP = paidMediaTemp
    env.TMPDIR = paidMediaTemp
    // 打包版是 GUI 双击启动，进程环境里没有你终端里的代理 → 引擎 httpx 连不上国外上游
    // (Agnes 生图/视频、Claude/Codex)。读系统代理(Clash 等在 Windows 设的)注入，让引擎及其
    // 子进程的 httpx 自动走；本地回环(引擎自身/llama-server)不走代理。已有 HTTP_PROXY 则尊重不覆盖。
    try {
      const r = await session.defaultSession.resolveProxy('https://apihub.agnes-ai.com')
      assertEngineAttemptCurrent(attempt)
      const m = r && r.match(/PROXY\s+([^;\s]+)/i)
      if (m) {
        const p = `http://${m[1]}`
        env.HTTP_PROXY = env.HTTP_PROXY || p
        env.HTTPS_PROXY = env.HTTPS_PROXY || p
        env.http_proxy = env.http_proxy || p
        env.https_proxy = env.https_proxy || p
        env.NO_PROXY = env.NO_PROXY || '127.0.0.1,localhost'
        console.log('[engine] 已注入系统代理')
      }
    } catch (error) {
      // Proxy discovery is optional, but a stale/cancelled generation is not.
      assertEngineAttemptCurrent(attempt)
      console.error('[engine] 读系统代理失败(忽略):', error)
    }
    assertEngineAttemptCurrent(attempt)
    if (app.isPackaged) {
      // 正式包只运行本次构建并随签名发布的 bundled engine；绝不优先执行安装目录
      // 旁边可变的源码/venv，否则桌面签名无法证明实际被执行的后端代码。
      const exe = process.platform === 'win32' ? 'engine.exe' : 'engine'
      const engineDir = join(process.resourcesPath, 'engine')
      const enginePath = await attestPackagedEngine(
        engineDir,
        exe,
        EXPECTED_PACKAGED_ENGINE_SHA256
      )
      bridgeExecutable = enginePath
      assertEngineAttemptCurrent(attempt)
      const storeRuntimeProfile = await attestPackagedStoreRuntimeProfile(
        process.resourcesPath,
        EXPECTED_STORE_RUNTIME_PROFILE_SHA256
      )
      assertEngineAttemptCurrent(attempt)
      Object.assign(
        env,
        bindAttestedStoreRuntimeProfileEnvironment({}, storeRuntimeProfile)
      )
      const mediaRuntime = await attestPackagedMediaRuntime(process.resourcesPath, {
        ffmpegSha256: EXPECTED_PACKAGED_FFMPEG_SHA256,
        ffprobeSha256: EXPECTED_PACKAGED_FFPROBE_SHA256,
        manifestSha256: EXPECTED_MEDIA_RUNTIME_MANIFEST_SHA256
      })
      assertEngineAttemptCurrent(attempt)
      Object.assign(env, bindAttestedMediaRuntimeEnvironment({}, mediaRuntime))
      const runtime = packagedRuntimeDirectories()
      bridgeDataDirectory = runtime.data
      enforcePackagedFinancialLedger(env, runtime.data)
      env.DATA_DIR = runtime.data
      env.AGENT_EXEC_WORKDIR = runtime.workspaces
      env.NACHUAN_GUARD_HOME = runtime.guardHome
      env.SEMCACHE_DB_DIR = runtime.semcache
      env.SENSEVOICE_ASR = '0' // text-first 发行版不冻结本地语音实现；音频端点明确返回 503
      // 本地运行态只有在发布清单逐文件证明 llama、相邻原生库与 GGUF 时才启用。
      // 缺清单/缺模型一律安全隐藏，不在安装后静默下载浮动制品。
      const llamaExe = process.platform === 'win32' ? 'llama-server.exe' : 'llama-server'
      const llamaDir = join(process.resourcesPath, 'llama')
      const bundledModels = join(process.resourcesPath, 'models')
      const runtimeManifest = await attestPackagedRuntimeManifest(
        process.resourcesPath,
        EXPECTED_LOCAL_RUNTIME_MANIFEST_SHA256
      )
      assertEngineAttemptCurrent(attempt)
      const hasBundledGguf =
        existsSync(bundledModels) &&
        readdirSync(bundledModels).some((f) => f.toLowerCase().endsWith('.gguf'))
      if (
        existsSync(runtimeManifest) &&
        existsSync(join(llamaDir, llamaExe)) &&
        hasBundledGguf
      ) {
        env.LLAMA_SERVER_DIR = llamaDir
        env.LOCAL_MODEL_DIR = bundledModels
        env.NACHUAN_LOCAL_RUNTIME_MANIFEST = runtimeManifest
      }
      // 发布包不接受任何连接种子。云端密钥必须由安装后的用户在连接中心录入，
      // 避免构建机 data/connections.json 被复制进安装包并扩散到所有安装者。
      assertEngineAttemptCurrent(attempt)
      child = spawn(enginePath, [], {
        cwd: engineDir,
        env,
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
        shell: false
      })
    } else {
      const pythonPath = join(
        repoRoot(),
        '.venv',
        process.platform === 'win32' ? 'Scripts\\python.exe' : 'bin/python'
      )
      const pythonInfo = lstatSync(pythonPath)
      if (!pythonInfo.isFile() || pythonInfo.isSymbolicLink()) {
        throw new Error('development Python must be a fixed regular file in .venv')
      }
      bridgeExecutable = pythonPath
      assertEngineAttemptCurrent(attempt)
      child = spawn(pythonPath, ['-m', 'gateway.app'], {
        cwd: repoRoot(),
        env,
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true
      })
    }

    if (!child.pid) throw new Error('engine child did not expose a PID')
    engineRootSessions.bindChild(attempt, child.pid)
    assertEngineAttemptCurrent(attempt, child.pid)
    engineProc = child
    auditDesktop('engine.spawn', {
      pid: child.pid,
      port: candidatePort,
      packaged: app.isPackaged
    })
    child.stdout?.on('data', (d) => console.log('[engine]', String(d).trim()))
    child.stderr?.on('data', (d) => console.log('[engine]', String(d).trim()))
    let ready = false
    let restartAfterError = false
    const exitedBeforeReady = new Promise<never>((_resolve, reject) => {
      child?.once('error', (error) => {
        console.error('[engine] spawn error:', error)
        const pid = child?.pid ?? 0
        const owned = pid > 0 && invalidateEngineAttempt(attempt, pid)
        if (owned) weixinBridgeSupervisor.stop()
        if (owned && engineHealthyTimer) {
          clearTimeout(engineHealthyTimer)
          engineHealthyTimer = null
        }
        if (!ready) reject(error)
        else if (owned && !isQuitting) {
          restartAfterError = true
          try {
            child?.kill()
          } catch (killError) {
            fatalEngineFailure(killError)
          }
        }
      })
      child?.once('exit', (code, signal) => {
        const pid = child?.pid ?? 0
        console.log('[engine] exited with', code, signal || '')
        auditDesktop('engine.exit', { pid, code: code ?? -1, signal: signal ?? '' })
        const owned = pid > 0 && invalidateEngineAttempt(attempt, pid)
        if (owned || restartAfterError) weixinBridgeSupervisor.stop()
        if (engineProc === child) engineProc = null
        if (owned && engineHealthyTimer) {
          clearTimeout(engineHealthyTimer)
          engineHealthyTimer = null
        }
        if (!ready) {
          reject(
            new Error(
              `engine exited before readiness (code=${String(code)}, signal=${String(signal)})`
            )
          )
        } else if ((owned || restartAfterError) && !isQuitting) {
          scheduleEngineRestart()
        }
      })
    })
    if (!child.pid) throw new Error('engine child did not expose a PID')
    await Promise.race([
      waitForEngineReady(candidatePort, child.pid, bootToken),
      exitedBeforeReady
    ])
    assertEngineAttemptCurrent(attempt, child.pid)
    if (child.exitCode !== null) throw new Error('engine exited at readiness boundary')
    const published = engineRootSessions.publish(attempt, child.pid)
    enginePort = published.port
    ready = true
    if (engineHealthyTimer) clearTimeout(engineHealthyTimer)
    engineHealthyTimer = setTimeout(() => {
      if (engineRootSessions.ownsPublished(attempt, child?.pid ?? 0)) engineRestarts = 0
    }, 30000)
    console.log(`[engine] verified child pid=${child.pid} on loopback port ${published.port}`)
    auditDesktop('engine.ready', { pid: child.pid, port: published.port })
    try {
      const started = weixinBridgeSupervisor.start({
        packaged: app.isPackaged,
        engineExecutable: bridgeExecutable,
        repoRoot: repoRoot(),
        dataDirectory: bridgeDataDirectory,
        enginePort: published.port,
        bridgeKey: weixinBridgeKey,
        sourceEnvironment: env
      })
      auditDesktop(started ? 'weixin_bridge.ready_to_start' : 'weixin_bridge.not_configured')
    } catch (error) {
      auditDesktop('weixin_bridge.start_failed', {
        error_type: error instanceof Error ? error.name : typeof error
      })
      console.error('[weixin] managed bridge startup failed:', error)
    }
  } catch (error) {
    weixinBridgeSupervisor.stop()
    const pid = child?.pid
    invalidateEngineAttempt(attempt, pid && pid > 0 ? pid : undefined)
    if (child && child.exitCode === null) {
      try {
        child.kill()
      } catch {
        // Keep engineProc bound so before-quit makes one final termination attempt.
      }
    } else if (engineProc === child) {
      engineProc = null
    }
    throw error
  }
}

async function startEngine(): Promise<void> {
  if (engineStartPromise) return await engineStartPromise
  engineStartPromise = startEngineOnce()
  try {
    await engineStartPromise
  } finally {
    engineStartPromise = null
  }
}

async function loadRedactedSupportHealth(): Promise<unknown> {
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), 3000)
  try {
    const response = await fetch(`${engineBaseUrl()}/health`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
      redirect: 'error',
      signal: controller.signal
    })
    if (!response.ok || !response.body) throw new Error('support health is unavailable')
    const reader = response.body.getReader()
    const chunks: Uint8Array[] = []
    let total = 0
    for (;;) {
      const item = await reader.read()
      if (item.done) break
      total += item.value.byteLength
      if (total > 256 * 1024) {
        await reader.cancel()
        throw new Error('support health exceeded its closed size limit')
      }
      chunks.push(item.value)
    }
    const bytes = Buffer.concat(chunks.map((chunk) => Buffer.from(chunk)))
    return JSON.parse(bytes.toString('utf8'))
  } finally {
    clearTimeout(timeout)
  }
}

async function createRedactedSupportBundleFromMenu(zh: boolean): Promise<void> {
  if (supportBundleInFlight) return await supportBundleInFlight
  supportBundleInFlight = (async () => {
    try {
      const result = await createInstalledSupportBundle({
        isPackaged: app.isPackaged,
        executablePath: process.execPath,
        resourcesPath: process.resourcesPath,
        userDataPath: app.getPath('userData'),
        version: app.getVersion(),
        runtimeProfile: 'store',
        loadHealth: loadRedactedSupportHealth
      })
      auditDesktop('support_bundle.created', { size: result.size })
      const choice = await dialog.showMessageBox({
        type: 'info',
        title: zh ? '脱敏诊断包已生成' : 'Redacted Support Bundle Created',
        message: zh
          ? '诊断包不含原始日志、数据库、密钥、消息正文或本机绝对路径。'
          : 'The bundle excludes raw logs, databases, keys, message content and local absolute paths.',
        detail: result.path,
        buttons: zh ? ['打开所在文件夹', '关闭'] : ['Show in Folder', 'Close'],
        defaultId: 0,
        cancelId: 1,
        noLink: true
      })
      if (choice.response === 0) shell.showItemInFolder(result.path)
    } catch (error) {
      auditDesktop('support_bundle.failed', {
        error_type: error instanceof Error ? error.name : typeof error
      })
      dialog.showErrorBox(
        zh ? '无法生成脱敏诊断包' : 'Could Not Create Support Bundle',
        app.isPackaged
          ? zh
            ? '核心安装字节或输出目录未通过安全检查；没有生成不完整诊断包。'
            : 'Core installed bytes or the output directory failed validation; no incomplete bundle was created.'
          : zh
            ? '该入口只为正式安装版生成最终字节证据；开发态请运行项目测试和审计工具。'
            : 'This entry records final installed bytes and is available only in packaged builds.'
      )
    }
  })()
  try {
    await supportBundleInFlight
  } finally {
    supportBundleInFlight = null
  }
}

function buildMenu(lang?: string): void {
  const zh = (lang ?? app.getLocale()).toLowerCase().startsWith('zh')
  const label = (cn: string, en: string): string => (zh ? cn : en)
  const go = (view: string): (() => void) => () => mainWin?.webContents.send('set-view', view)
  const command = (name: string): (() => void) => () => mainWin?.webContents.send('app-command', name)
  const L = {
    file: label('文件', 'File'),
    newChat: label('新对话', 'New Chat'),
    newCodeChat: label('新建代码对话', 'New Code Chat'),
    newBrowserChat: label('新建浏览对话', 'New Browser Chat'),
    connections: label('连接中心', 'Connections'),
    sync: label('跨设备同步', 'Sync'),
    quit: label('退出纳川', 'Quit Nexus'),
    edit: label('编辑', 'Edit'),
    undo: label('撤销', 'Undo'),
    redo: label('重做', 'Redo'),
    cut: label('剪切', 'Cut'),
    copy: label('复制', 'Copy'),
    paste: label('粘贴', 'Paste'),
    selectAll: label('全选', 'Select All'),
    view: label('视图', 'View'),
    toggleNav: label('显示/隐藏导航栏', 'Toggle Navigation'),
    toggleBrowser: label('显示/隐藏浏览器栏', 'Toggle Browser'),
    browserNormal: label('浏览器栏：普通', 'Browser: Normal'),
    browserWide: label('浏览器栏：宽屏', 'Browser: Wide'),
    browserMax: label('浏览器栏：最大化', 'Browser: Max'),
    reload: label('重新加载', 'Reload'),
    forceReload: label('强制重新加载', 'Force Reload'),
    resetZoom: label('实际大小', 'Actual Size'),
    zoomIn: label('放大', 'Zoom In'),
    zoomOut: label('缩小', 'Zoom Out'),
    fullscreen: label('全屏', 'Toggle Fullscreen'),
    workspace: label('工作区', 'Workspace'),
    chat: label('聊天', 'Chat'),
    kb: label('知识库', 'Knowledge Base'),
    studio: label('视频工作室', 'Video Studio'),
    media: label('媒体处理', 'Media'),
    tools: label('工具与插件', 'Tools & MCP'),
    orchestrate: label('多模型协作', 'Multi-model Collaboration'),
    usage: label('用量与成本', 'Usage & Cost'),
    brain: label('进化记忆', 'Memory & Evolution'),
    window: label('窗口', 'Window'),
    minimize: label('最小化', 'Minimize'),
    close: label('关闭窗口', 'Close Window'),
    help: label('帮助', 'Help'),
    about: label('关于纳川', 'About Nexus'),
    dataDir: label('打开数据目录', 'Open Data Folder'),
    supportBundle: label('生成脱敏诊断包', 'Create Redacted Support Bundle'),
    devtools: label('开发者工具', 'Toggle DevTools'),
  }
  const helpItems: Electron.MenuItemConstructorOptions[] = [
    { label: L.about, click: go('about') },
    { label: L.dataDir, click: () => void shell.openPath(app.getPath('userData')) },
    {
      label: L.supportBundle,
      click: () => void createRedactedSupportBundleFromMenu(zh)
    }
  ]
  if (DEBUG.enableDevTools) {
    helpItems.push({ type: 'separator' }, { role: 'toggleDevTools', label: L.devtools })
  }
  const t: Electron.MenuItemConstructorOptions[] = [
    {
      label: L.file,
      submenu: [
        { label: L.newChat, accelerator: 'CmdOrCtrl+N', click: command('new-chat') },
        { label: L.newCodeChat, click: command('new-code-chat') },
        { label: L.newBrowserChat, click: command('new-browser-chat') },
        { type: 'separator' },
        { label: L.connections, click: go('connections') },
        { label: L.sync, click: go('sync') },
        { type: 'separator' },
        { role: 'quit', label: L.quit }
      ]
    },
    {
      label: L.edit,
      submenu: [
        { role: 'undo', label: L.undo },
        { role: 'redo', label: L.redo },
        { type: 'separator' },
        { role: 'cut', label: L.cut },
        { role: 'copy', label: L.copy },
        { role: 'paste', label: L.paste },
        { role: 'selectAll', label: L.selectAll }
      ]
    },
    {
      label: L.view,
      submenu: [
        { label: L.toggleNav, accelerator: 'CmdOrCtrl+B', click: command('toggle-left') },
        { label: L.toggleBrowser, accelerator: 'CmdOrCtrl+Shift+B', click: command('toggle-browser') },
        { type: 'separator' },
        { label: L.browserNormal, click: command('browser-normal') },
        { label: L.browserWide, click: command('browser-wide') },
        { label: L.browserMax, click: command('browser-max') },
        { type: 'separator' },
        { role: 'reload', label: L.reload },
        { role: 'forceReload', label: L.forceReload },
        { type: 'separator' },
        { role: 'resetZoom', label: L.resetZoom },
        { role: 'zoomIn', label: L.zoomIn },
        { role: 'zoomOut', label: L.zoomOut },
        { type: 'separator' },
        { role: 'togglefullscreen', label: L.fullscreen }
      ]
    },
    {
      label: L.workspace,
      submenu: [
        { label: L.chat, accelerator: 'CmdOrCtrl+1', click: go('chat') },
        { type: 'separator' },
        { label: L.kb, accelerator: 'CmdOrCtrl+2', click: go('kb') },
        { label: L.studio, accelerator: 'CmdOrCtrl+3', click: go('studio') },
        { label: L.media, accelerator: 'CmdOrCtrl+4', click: go('media') },
        { label: L.tools, accelerator: 'CmdOrCtrl+5', click: go('mcp') },
        { label: L.orchestrate, accelerator: 'CmdOrCtrl+6', click: go('orchestrate') },
        { type: 'separator' },
        { label: L.usage, click: go('usage') },
        { label: L.brain, click: go('brain') }
      ]
    },
    {
      label: L.window,
      submenu: [
        { role: 'minimize', label: L.minimize },
        { role: 'close', label: L.close }
      ]
    },
    {
      label: L.help,
      submenu: helpItems
    }
  ]
  Menu.setApplicationMenu(Menu.buildFromTemplate(t))
}

let tray: Tray | null = null

function createTray(): void {
  if (tray) return // 只建一次
  const zh = app.getLocale().startsWith('zh')
  let img = nativeImage.createEmpty()
  for (const p of [
    join(process.resourcesPath, 'icon.png'), // 打包版
    join(__dirname, '../../build/icon.png'), // dev
    join(__dirname, '../../../build/icon.png')
  ]) {
    if (existsSync(p)) {
      img = nativeImage.createFromPath(p)
      break
    }
  }
  tray = new Tray(img.isEmpty() ? img : img.resize({ width: 16, height: 16 }))
  tray.setToolTip('纳川 · Nexus')
  const show = (): void => {
    mainWin?.show()
    mainWin?.focus()
  }
  tray.setContextMenu(
    Menu.buildFromTemplate([
      { label: zh ? '显示纳川' : 'Show Nexus', click: show },
      { type: 'separator' },
      {
        label: zh ? '退出纳川' : 'Quit',
        click: () => {
          isQuitting = true
          app.quit()
        }
      }
    ])
  )
  tray.on('click', show)
  tray.on('double-click', show)
}

function lockLocalRendererNavigation(
  win: BrowserWindow,
  trustedEntry: string,
  openExternalLinks: boolean
): void {
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (openExternalLinks && isHttpUrl(url)) void shell.openExternal(url)
    return { action: 'deny' }
  })
  win.webContents.on('will-navigate', (event, url) => {
    if (!isTrustedRendererNavigation(url, trustedEntry)) event.preventDefault()
  })
}

function isExpectedIpcSender(
  event: { sender: { id: number }; senderFrame?: unknown },
  expectedWindow: BrowserWindow | null
): boolean {
  const expectedId =
    expectedWindow && !expectedWindow.isDestroyed() ? expectedWindow.webContents.id : null
  return (
    ipcSenderAllowed(event.sender.id, expectedId) &&
    expectedWindow !== null &&
    !expectedWindow.isDestroyed() &&
    event.senderFrame === expectedWindow.webContents.mainFrame
  )
}

function requireExpectedIpcSender(
  event: { sender: { id: number }; senderFrame?: unknown },
  expectedWindow: BrowserWindow | null
): void {
  if (!isExpectedIpcSender(event, expectedWindow)) throw new Error('unauthorized IPC sender')
}

async function initializePaidMediaControlPlane(): Promise<void> {
  const userDataRoot = canonicalExistingPaidMediaDirectory(
    app.getPath('userData'),
    'paid media user-data directory'
  )
  let rootSnapshot = (await installationRootClient.snapshot()).snapshot
  const dataPath = join(userDataRoot, 'data')
  const legacySealPath = join(dataPath, 'paid-media-legacy-seal.json')
  let initialDecision = decidePaidMediaStartup(
    rootSnapshot,
    existsSync(legacySealPath) ? 'closed' : 'missing'
  )
  if (initialDecision.createLocalDirectories) {
    const fresh = (await installationRootClient.snapshot()).snapshot
    if (
      fresh.installationId !== rootSnapshot.installationId ||
      fresh.epoch !== rootSnapshot.epoch ||
      fresh.components.desktop.identity !== rootSnapshot.components.desktop.identity
    ) {
      throw new Error('Installation Root changed during paid media first provisioning')
    }
    rootSnapshot = fresh
    initialDecision = decidePaidMediaStartup(
      rootSnapshot,
      existsSync(legacySealPath) ? 'closed' : 'missing'
    )
  }
  const dataRoot = initialDecision.createLocalDirectories
    ? ensurePaidMediaChildDirectory(userDataRoot, 'data', 'paid media data directory')
    : canonicalExistingPaidMediaDirectory(dataPath, 'paid media data directory')
  const legacySeal = new PaidMediaLegacySeal(legacySealPath, {
    safeStorage,
    harden: hardenLocalSecretAcl,
    now: () => Date.now(),
    atomicIO: nodePaidMediaLegacySealAtomicIO
  })
  if (initialDecision.provisionLegacySeal) await legacySeal.provisionOpen()
  const legacyStatus = await legacySeal.inspect()
  const startup = decidePaidMediaStartup(rootSnapshot, legacyStatus.state)
  const vaultPath = join(dataRoot, 'paid-media-vault')
  const vaultRoot = startup.createLocalDirectories
    ? ensurePaidMediaChildDirectory(dataRoot, 'paid-media-vault', 'paid media vault directory')
    : canonicalExistingPaidMediaDirectory(vaultPath, 'paid media vault directory')
  const tempRoot = canonicalPaidMediaTempRoot()
  const stageRoot = canonicalPaidMediaStageRoot(tempRoot)
  const ledger = new PaidMediaLedger(
    join(dataRoot, 'paid-media-ledger.json'),
    {
      safeStorage,
      harden: hardenLocalSecretAcl,
      now: () => Date.now(),
      uuid: () => randomUUID(),
      atomicIO: nodePaidMediaAtomicIO
    }
  )
  const paidMediaProbe = new PaidMediaProbeClient({
    baseUrl: engineBaseUrl,
    runtimeKey: () => engineKey,
    paidMediaKey: () => paidMediaKey
  })
  paidMediaVault = new PaidMediaVault(
    vaultRoot,
    {
      safeStorage,
      harden: hardenLocalSecretAcl,
      now: () => Date.now(),
      stageRoot: () => stageRoot,
      fetchRemote: nodePaidMediaRemoteFetcher,
      ensureMediaProbeReady: () => paidMediaProbe.ensureReady(),
      validateMediaAsset: (input) => paidMediaProbe.validate(input),
      onCleanupError: () => auditDesktop('paid_media.fetch_cleanup_failed')
    }
  )
  const capacity = new PaidMediaCapacityManager(
    join(dataRoot, 'paid-media-capacity.json'),
    vaultRoot,
    {
      safeStorage,
      harden: hardenLocalSecretAcl,
      now: () => Date.now(),
      atomicIO: nodePaidMediaAtomicIO,
      tempRoot: () => tempRoot,
      probeSpoolRoot: () => tempRoot,
      resolveVolume: resolvePaidMediaVolume,
      freeBytes: paidMediaFreeBytes
    }
  )
  const recoveryIntentRoot = ensurePaidMediaChildDirectory(
    dataRoot,
    'paid-media-recovery-intents',
    'paid media recovery intent directory'
  )
  const recoveryIntentStore = new PaidMediaRecoveryIntentStore(recoveryIntentRoot, {
    safeStorage,
    harden: hardenLocalSecretAcl
  })
  const recoveryExecutorSlot = new PaidMediaRecoveryExecutorSlot()
  const installationAuthority = new PaidMediaInstallationRootAuthority(
    join(dataRoot, 'paid-media-installation-authority.json'),
    {
      client: installationRootClient,
      safeStorage,
      harden: hardenLocalSecretAcl,
      atomicIO: nodePaidMediaInstallationRootAtomicIO,
      now: () => Date.now(),
      uuid: () => randomUUID(),
      recoverableExecutor: recoveryExecutorSlot
    }
  )
  const mutationGate = new PaidMediaMutationGate(installationAuthority)
  const recoveryExecutor = new PaidMediaRecoveryExecutor({
    authority: installationAuthority,
    gate: mutationGate,
    intentStore: recoveryIntentStore,
    ledger,
    vault: paidMediaVault,
    capacity
  })
  recoveryExecutorSlot.bind(recoveryExecutor.asRootExecutor())
  const paidMediaEngineSessionClient = new PaidMediaEngineSessionClient({
    session: () => engineRootSessions.session()
  })
  let paidMediaAssetV2StageReady = false
  const paidMediaAssetV2Runtime = new PaidMediaAssetV2Runtime({
    authority: installationAuthority,
    ledger,
    capacity,
    vault: paidMediaVault,
    stageHandoff: recoveryExecutor,
    createImageAssets: (input) =>
      createPaidMediaImageAssets({
        sessionClient: paidMediaEngineSessionClient,
        ...input
      }),
    downloadAsset: (input) =>
      downloadPaidMediaAsset({
        sessionClient: paidMediaEngineSessionClient,
        ...input
      }),
    probeAsset: (input) =>
      probePaidMediaStagedAsset({
        sessionClient: paidMediaEngineSessionClient,
        descriptor: input.descriptor,
        source: input.source,
        signal: input.signal
      }),
    acknowledgeAssets: (input) =>
      acknowledgePaidMediaAssets({
        sessionClient: paidMediaEngineSessionClient,
        ...input
      }),
    audit: auditDesktop
  })
  const runPaidMediaRootRecoverableMutation = async (
    payload: PaidMediaRecoveryIntentPayload
  ) => {
    const descriptor = await recoveryIntentStore.prepare(payload)
    if (
      descriptor.kind !== payload.kind ||
      descriptor.operationId !== payload.operationId
    ) {
      throw new Error('Paid media recovery intent descriptor binding conflicts')
    }
    const state = await installationAuthority.runRecoverableMutation(descriptor)
    if (state.mode !== 'ready') {
      throw new Error('Paid media recoverable Root mutation did not converge')
    }
    return descriptor
  }
  const paidMediaAssetV2: PaidMediaAssetV2Executor = {
    isReady: () => paidMediaAssetV2StageReady,
    executeImage: (input) => {
      if (!paidMediaAssetV2StageReady) {
        throw new Error('Paid media asset-v2 stage authority is unavailable')
      }
      return paidMediaAssetV2Runtime.executeImage(input)
    },
    convergeImageAck: (input) => {
      if (!paidMediaAssetV2StageReady) {
        throw new Error('Paid media asset-v2 stage authority is unavailable')
      }
      return paidMediaAssetV2Runtime.convergeImageAck(input)
    }
  }
  paidMediaService = new PaidMediaService({
    ledger,
    vault: paidMediaVault,
    capacity,
    baseUrl: engineBaseUrl,
    runtimeKey: () => engineKey,
    approvalKey: () => approvalKey,
    paidMediaKey: () => paidMediaKey,
    transport: nodePaidMediaTransport,
    installationRoot: installationAuthority,
    legacySeal,
    mutationGate,
    recoveryIntentStore,
    assetV2: paidMediaAssetV2
  })
  // Rooted v1 still performs remote fetch/probe work inside its result commit.
  // Latch it off before initialization so even a ready transition cannot
  // create a transient provider window. V2 is the only future remote path.
  paidMediaService.disableRemoteOperations()
  const prepared = await paidMediaService.prepareInstallationAuthority({
    provision: startup.provisionAuthority,
    provisionLocalState: startup.createLocalDirectories,
    allowLegacyBootstrap: startup.allowLegacyBootstrap
  })
  if ('authority' in prepared && prepared.authority.mode === 'ready') {
    const stageRecovery = await paidMediaVault.inspectStageRecovery()
    if (stageRecovery.leases.length === 0) {
      const vaultEvidence = await paidMediaVault.inspectAuthorityEvidence()
      await activatePaidMediaEngineSessionStage({
        session: () => engineRootSessions.session(),
        sessionClient: paidMediaEngineSessionClient,
        installationPrincipal: rootSnapshot.principalDigest,
        vaultEvidenceSha256: vaultEvidence.vaultStateDigest,
        signal: new AbortController().signal
      })
      paidMediaAssetV2StageReady = true
      void convergePaidMediaAssetV2StartupAcks({
        runtime: paidMediaAssetV2Runtime,
        operations: await ledger.listPublic(),
        runRecoverableMutation: runPaidMediaRootRecoverableMutation,
        signal: new AbortController().signal,
        onError: (operationId, error) => {
          auditDesktop('paid_media.asset_v2_startup_ack_convergence_failed', {
            operation_id: operationId,
            reason: error instanceof Error ? error.name : 'unknown'
          })
        }
      })
    } else {
      auditDesktop('paid_media.asset_v2_stage_recovery_required', {
        lease_count: stageRecovery.leases.length
      })
    }
  }
  auditDesktop('paid_media.control_plane_rooted_v1_disabled', {
    root_status: rootSnapshot.status,
    desktop_bound: rootSnapshot.components.desktop.bound,
    legacy_state:
      'state' in prepared && prepared.state === 'legacy_bootstrap_required'
        ? 'bootstrap_required'
        : 'closed',
    authority_mode: 'authority' in prepared ? prepared.authority.mode : 'not_initialized'
  })
  protocol.handle('nachuan-paid-media', async (request) => {
    if (!paidMediaVault) {
      return new Response('Not Found', { status: 404, headers: { 'Cache-Control': 'no-store' } })
    }
    return handlePaidMediaAssetRequest(request, paidMediaVault)
  })
  paidMediaIpcRegistration?.dispose()
  paidMediaIpcRegistration = registerPaidMediaIpc({
    ipcMain,
    service: paidMediaService,
    authorize: (event) => requireExpectedIpcSender(event, mainWin),
    ownerWindow: () => mainWin,
    dialog: {
      showMessageBox: (owner, options) =>
        dialog.showMessageBox(owner, options as unknown as Electron.MessageBoxOptions)
    }
  })
}

function createWindow(): void {
  buildMenu() // 本地化菜单：中文系统→中文菜单，英文→英文（不再是默认英文）
  // 全局浅色主题：强制原生表面(标题栏控件条/右键菜单/滚动条/对话框)走浅色。
  // 否则系统若是深色模式，Windows 会把右上角窗口控件条画成黑的（机主实测：那块还是黑）。
  nativeTheme.themeSource = 'light'
  const configuredDevUrl = process.env['ELECTRON_RENDERER_URL'] || ''
  const devUrl = !app.isPackaged && isLoopbackRendererUrl(configuredDevUrl) ? configuredDevUrl : ''
  const rendererFile = join(__dirname, '../renderer/index.html')
  const trustedRendererEntry = devUrl || pathToFileURL(rendererFile).href
  const win = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 1000,
    minHeight: 640,
    title: '纳川 · Nexus',
    backgroundColor: '#f5f5f5',
    titleBarStyle: 'hidden', // 隐藏原生标题栏，把它并进 App 顶栏 → 给聊天区腾高
    titleBarOverlay: { color: '#f5f5f5', symbolColor: '#171717', height: 44 }, // Win 右上角原生 最小化/最大化/关闭（浅色主题：浅底深符号才看得清）
    autoHideMenuBar: true, // 菜单默认收起(按 Alt 唤出)，再腾一行给聊天
    // 主窗确实承载内置浏览器，所以保留 webviewTag；其余窗口一律关闭。guest 在 will-attach-webview 再收紧。
    webPreferences: windowSecurityPreferences(join(__dirname, '../preload/index.js'), {
      webview: true,
      devTools: DEBUG.enableDevTools
    })
  })
  mainWin = win
  lockLocalRendererNavigation(win, trustedRendererEntry, true)

  // F12 = 开发者工具（机主排障取证用：F12 看 Console 红错；原生菜单里那项藏太深）
  if (DEBUG.enableDevTools) {
    win.webContents.on('before-input-event', (_e, input) => {
      if (input.type === 'keyDown' && input.key === 'F12') win.webContents.toggleDevTools()
    })
  }

  // 点关闭 = 最小化到系统托盘（不退出）；真退出走托盘菜单「退出」或 before-quit
  win.on('close', (e) => {
    if (!isQuitting) {
      e.preventDefault()
      win.hide()
    }
  })
  createTray()

  // 放行麦克风（语音转文字用 getUserMedia）。只给主程序窗口，内置浏览器里的网站拿不到，安全。
  session.defaultSession.setPermissionRequestHandler((wc, permission, callback) => {
    callback(permissionAllowed(permission, wc === win.webContents))
  })
  session.defaultSession.setPermissionCheckHandler(
    (wc, permission) => permissionAllowed(permission, wc === win.webContents)
  )

  // 不信任任何网页提供的 webview 偏好/preload。只准 http(s)，guest 强制沙箱且不能开 Node。
  win.webContents.on('will-attach-webview', (event, webPreferences, params) => {
    if (!isHttpUrl(params.src)) {
      event.preventDefault()
      return
    }
    delete webPreferences.preload
    webPreferences.contextIsolation = true
    webPreferences.nodeIntegration = false
    webPreferences.sandbox = true
    webPreferences.webSecurity = true
    webPreferences.devTools = DEBUG.enableDevTools
  })
  win.webContents.on('did-attach-webview', (_event, guest) => {
    guest.setWindowOpenHandler(({ url }) => {
      if (isHttpUrl(url)) void shell.openExternal(url)
      return { action: 'deny' }
    })
    const blockUnsafeGuestNavigation = (event: Electron.Event, url: string): void => {
      if (!isHttpUrl(url)) event.preventDefault()
    }
    guest.on('will-navigate', blockUnsafeGuestNavigation)
    guest.on('will-redirect', blockUnsafeGuestNavigation)
  })

  // 右键菜单：剪切置顶 → 复制/粘贴/全选，最后是截图（框选→提取文字/翻译）
  win.webContents.on('context-menu', () => {
    const zh = app.getLocale().toLowerCase().startsWith('zh')
    Menu.buildFromTemplate([
      { role: 'cut', label: zh ? '剪切' : 'Cut' },
      { role: 'copy', label: zh ? '复制' : 'Copy' },
      { role: 'paste', label: zh ? '粘贴' : 'Paste' },
      { role: 'selectAll', label: zh ? '全选' : 'Select All' },
      { type: 'separator' },
      {
        label: zh ? '📷 截图（框选 → 提取文字/翻译）' : '📷 Screenshot (select → OCR/translate)',
        accelerator: 'Control+Alt+A',
        click: () => void triggerSnip()
      }
    ]).popup()
  })

  if (devUrl) {
    win.loadURL(devUrl)
    // dev 默认不自动弹 DevTools（机主测试时嫌吵；那几条 Autofill 红错也是开 DevTools 才触发的无害噪音）。
    // 真要调试：设环境变量 NACHUAN_DEVTOOLS=1 再启动，或菜单/快捷键手动开。
    if (process.env['NACHUAN_DEVTOOLS'] === '1') win.webContents.openDevTools({ mode: 'detach' })
  } else {
    win.loadFile(rendererFile)
  }
}

registerRendererEngineProxyIpc(ipcMain, rendererEngineProxy, (event) => {
  requireExpectedIpcSender(
    event as unknown as Parameters<typeof requireExpectedIpcSender>[0],
    mainWin
  )
})

registerPluginUiIpc(ipcMain, desktopPrivilegedSession, (event) => {
  requireExpectedIpcSender(
    event as unknown as Parameters<typeof requireExpectedIpcSender>[0],
    mainWin
  )
})

ipcMain.handle('approval:list', (event, rawUserId: unknown) => {
  requireExpectedIpcSender(event, mainWin)
  if (
    typeof rawUserId !== 'string' ||
    rawUserId.length < 1 ||
    rawUserId.length > 128 ||
    /[\u0000-\u001f\u007f]/.test(rawUserId)
  ) {
    throw new Error('invalid approval user id')
  }
  return desktopPrivilegedSession.listApprovals(rawUserId)
})

ipcMain.handle('approval:resolve', async (event, raw: unknown) => {
  requireExpectedIpcSender(event, mainWin)
  if (!raw || typeof raw !== 'object') throw new Error('invalid approval decision')
  const value = raw as { id?: unknown; decision?: unknown; note?: unknown }
  if (!Number.isSafeInteger(value.id) || Number(value.id) <= 0) {
    throw new Error('invalid approval id')
  }
  if (!['approve', 'reject', 'revise'].includes(String(value.decision))) {
    throw new Error('invalid approval decision')
  }
  const note = value.note === undefined ? '' : value.note
  if (typeof note !== 'string' || note.length > 2000 || /[\u0000]/.test(note)) {
    throw new Error('invalid approval note')
  }
  const owner = mainWin
  if (!owner) throw new Error('approval window unavailable')
  const decisionText =
    value.decision === 'approve' ? '批准并授予一次性执行权' : value.decision === 'revise' ? '退回修改' : '拒绝'
  const confirmation = await dialog.showMessageBox(owner, {
    type: value.decision === 'approve' ? 'warning' : 'question',
    title: '纳川安全审批',
    message: `${decisionText}：审批 #${Number(value.id)}？`,
    detail: note ? `备注：${note.slice(0, 500)}` : '此裁决将写入本机审批账本。',
    buttons: ['取消', '确认裁决'],
    defaultId: 0,
    cancelId: 0,
    noLink: true
  })
  if (confirmation.response !== 1) throw new Error('approval cancelled by user')
  return desktopPrivilegedSession.resolveApproval(
    Number(value.id),
    value.decision as 'approve' | 'reject' | 'revise',
    note
  )
})

async function confirmPrivilegedChange(message: string, detail: string): Promise<void> {
  const owner = mainWin
  if (!owner) throw new Error('privileged window unavailable')
  const confirmation = await dialog.showMessageBox(owner, {
    type: 'warning',
    title: '纳川安全确认',
    message,
    detail,
    buttons: ['取消', '确认'],
    defaultId: 0,
    cancelId: 0,
    noLink: true
  })
  if (confirmation.response !== 1) throw new Error('privileged change cancelled by user')
}

function validatedProvider(raw: unknown): string {
  if (typeof raw !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(raw)) {
    throw new Error('invalid provider name')
  }
  return raw
}

ipcMain.handle('connection:save', async (event, raw: unknown) => {
  requireExpectedIpcSender(event, mainWin)
  if (!raw || typeof raw !== 'object') throw new Error('invalid connection configuration')
  const value = raw as {
    provider?: unknown
    type?: unknown
    api_key?: unknown
    base_url?: unknown
    enabled_models?: unknown
    preserve_existing_credential?: unknown
  }
  const observedKeys = Object.keys(value).sort()
  const expectedKeys = [
    'api_key',
    'base_url',
    'enabled_models',
    'preserve_existing_credential',
    'provider',
    'type'
  ]
  if (
    observedKeys.length !== expectedKeys.length ||
    observedKeys.some((key, index) => key !== expectedKeys[index])
  ) {
    throw new Error('invalid connection configuration')
  }
  const provider = validatedProvider(value.provider)
  if (
    typeof value.type !== 'string' ||
    value.type.length < 1 ||
    value.type.length > 128 ||
    /[\u0000-\u001f\u007f]/.test(value.type) ||
    typeof value.api_key !== 'string' ||
    value.api_key.length > 32768 ||
    /[\u0000]/.test(value.api_key) ||
    typeof value.base_url !== 'string' ||
    value.base_url.length > 2048 ||
    /[\u0000-\u001f\u007f]/.test(value.base_url) ||
    !Array.isArray(value.enabled_models) ||
    value.enabled_models.length > 200 ||
    value.enabled_models.some((item) => !item || typeof item !== 'object' || Array.isArray(item)) ||
    typeof value.preserve_existing_credential !== 'boolean'
  ) {
    throw new Error('invalid connection configuration')
  }
  const body = {
    type: value.type,
    api_key: value.api_key,
    base_url: value.base_url,
    enabled_models: value.enabled_models,
    preserve_existing_credential: value.preserve_existing_credential
  }
  if (Buffer.byteLength(JSON.stringify(body), 'utf8') > 512 * 1024) {
    throw new Error('connection configuration exceeded limit')
  }
  await confirmPrivilegedChange(
    `保存连接“${provider}”？`,
    `目标：${value.base_url || '内置默认端点'}\n模型：${
      value.enabled_models.length === 0
        ? '自动发现并验证 1 个推荐聊天模型'
        : `验证所选 ${value.enabled_models.length} 个`
    }。${
      value.preserve_existing_credential ? '沿用已保存密钥。' : '验证新密钥。'
    }云端模型验证会向每个所选模型发送最多 1-token 探测，可能产生极少费用；密钥不会显示在页面或日志中。`
  )
  return desktopPrivilegedSession.saveConnection(provider, {
    type: body.type,
    apiKey: body.api_key,
    baseUrl: body.base_url,
    enabledModels: body.enabled_models as Record<string, unknown>[],
    preserveExistingCredential: body.preserve_existing_credential
  })
})

ipcMain.handle('connection:delete', async (event, rawProvider: unknown) => {
  requireExpectedIpcSender(event, mainWin)
  const provider = validatedProvider(rawProvider)
  await confirmPrivilegedChange(
    `删除连接“${provider}”？`,
    '删除后该来源会立即从路由中移除；此操作不会回显或导出原密钥。'
  )
  return desktopPrivilegedSession.deleteConnection(provider)
})

ipcMain.handle('sync:config', async (event, raw: unknown) => {
  requireExpectedIpcSender(event, mainWin)
  if (!raw || typeof raw !== 'object') throw new Error('invalid sync configuration')
  const value = raw as { url?: unknown; anonKey?: unknown }
  if (
    typeof value.url !== 'string' ||
    value.url.length < 1 ||
    value.url.length > 2048 ||
    /[\u0000-\u001f\u007f]/.test(value.url) ||
    typeof value.anonKey !== 'string' ||
    value.anonKey.length < 1 ||
    value.anonKey.length > 16384 ||
    /[\u0000]/.test(value.anonKey)
  ) {
    throw new Error('invalid sync configuration')
  }
  await confirmPrivilegedChange(
    '更换云同步信任目标？',
    `目标：${value.url}\n目标或 anon key 变化会立即注销旧会话、关闭同步并清空旧游标。`
  )
  return desktopPrivilegedSession.configureSync(value.url, value.anonKey)
})

ipcMain.handle('sync:auth', async (event, raw: unknown) => {
  requireExpectedIpcSender(event, mainWin)
  if (!raw || typeof raw !== 'object') throw new Error('invalid sync credentials')
  const value = raw as { kind?: unknown; email?: unknown; password?: unknown }
  if (
    (value.kind !== 'login' && value.kind !== 'signup') ||
    typeof value.email !== 'string' ||
    value.email.length < 1 ||
    value.email.length > 320 ||
    /[\u0000-\u001f\u007f]/.test(value.email) ||
    typeof value.password !== 'string' ||
    value.password.length < 1 ||
    value.password.length > 1024 ||
    /[\u0000]/.test(value.password)
  ) {
    throw new Error('invalid sync credentials')
  }
  await confirmPrivilegedChange(
    value.kind === 'login' ? '登录云同步账户？' : '注册云同步账户？',
    `账户：${value.email}\n凭据只会发送到当前已确认的 Supabase 目标。`
  )
  return desktopPrivilegedSession.authenticateSync(value.kind, value.email, value.password)
})

ipcMain.handle('sync:toggle', async (event, rawEnabled: unknown) => {
  requireExpectedIpcSender(event, mainWin)
  if (typeof rawEnabled !== 'boolean') throw new Error('invalid sync toggle')
  await confirmPrivilegedChange(
    rawEnabled ? '开启云同步？' : '关闭云同步？',
    rawEnabled
      ? '本机记忆、案例和知识库将与当前账户双向合并。'
      : '关闭后不会再执行云端读写，本地数据保留。'
  )
  return desktopPrivilegedSession.setSyncEnabled(rawEnabled)
})

ipcMain.handle('sync:run', async (event) => {
  requireExpectedIpcSender(event, mainWin)
  await confirmPrivilegedChange(
    '立即执行一次云同步？',
    '将使用当前已确认目标和账户，双向合并记忆、案例与知识库。'
  )
  return desktopPrivilegedSession.runSync()
})
// ── 自制截图浮层（替代 Windows 截图工具；选区内可「提取文字 / 翻译」）──
type ChannelRecoveryChannel = 'weixin' | 'feishu'
type ChannelRecoveryKind = 'inbound' | 'delivery' | 'video' | 'inbox' | 'outbox'
const CHANNEL_RECOVERY_HEX = /^[0-9a-f]{64}$/
const CHANNEL_RECOVERY_ZERO = '0'.repeat(64)
const channelRecoveryAttempts = new Map<string, number>()
const CHANNEL_RECOVERY_ATTEMPT_TTL_MS = 15 * 60 * 1000
const CHANNEL_RECOVERY_ATTEMPT_LIMIT = 64

function exactChannelRecoveryObject(raw: unknown, expected: readonly string[]): Record<string, unknown> {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error('invalid channel recovery value')
  }
  const value = raw as Record<string, unknown>
  const observed = Object.keys(value).sort()
  const wanted = [...expected].sort()
  if (observed.length !== wanted.length || observed.some((key, index) => key !== wanted[index])) {
    throw new Error('invalid channel recovery value')
  }
  return value
}

function validatedChannelRecoveryTarget(raw: unknown): {
  channel: ChannelRecoveryChannel
  targetKind: ChannelRecoveryKind
  targetKey: string
} {
  const value = exactChannelRecoveryObject(raw, ['channel', 'targetKind', 'targetKey'])
  const channel = value.channel
  const targetKind = value.targetKind
  const targetKey = value.targetKey
  const allowed =
    channel === 'weixin'
      ? new Set(['inbound', 'delivery', 'video'])
      : channel === 'feishu'
        ? new Set(['inbox', 'outbox', 'video'])
        : null
  if (
    !allowed ||
    typeof targetKind !== 'string' ||
    !allowed.has(targetKind) ||
    typeof targetKey !== 'string' ||
    targetKey.length < 1 ||
    targetKey.length > 512 ||
    /[\u0000-\u001f\u007f]/.test(targetKey)
  ) {
    throw new Error('invalid channel recovery target')
  }
  return {
    channel: channel as ChannelRecoveryChannel,
    targetKind: targetKind as ChannelRecoveryKind,
    targetKey
  }
}

function validatedChannelRecoveryDigest(raw: unknown): string {
  if (
    typeof raw !== 'string' ||
    !CHANNEL_RECOVERY_HEX.test(raw) ||
    raw === CHANNEL_RECOVERY_ZERO
  ) {
    throw new Error('invalid channel recovery digest')
  }
  return raw
}

function validatedChannelRecoveryCounts(
  raw: unknown,
  channel: ChannelRecoveryChannel
): Record<string, number> {
  const fields = channel === 'weixin' ? ['inbound', 'delivery', 'video'] : ['inbox', 'outbox', 'video']
  const value = exactChannelRecoveryObject(raw, fields)
  for (const field of fields) {
    if (!Number.isSafeInteger(value[field]) || Number(value[field]) < 0) {
      throw new Error('invalid channel recovery counts')
    }
  }
  return Object.fromEntries(fields.map((field) => [field, Number(value[field])]))
}

function validatedChannelRecoverySnapshot(
  raw: unknown,
  target: ReturnType<typeof validatedChannelRecoveryTarget>
): {
  schema: 'nachuan.weixin-recovery-snapshot.v1' | 'nachuan.feishu-recovery-inspect.v1'
  targetKind: ChannelRecoveryKind
  targetKeySha256: string
  expectedBeforeDigest: string
  affectedCounts: Record<string, number>
  decisionId: string
  decidedAtMs: number
} {
  const value = exactChannelRecoveryObject(raw, [
    'affected_counts',
    'decided_at_ms',
    'decision_id',
    'expected_before_digest',
    ...(target.channel === 'weixin' ? ['principal_sha256'] : []),
    'schema',
    'target_key_sha256',
    'target_kind'
  ])
  const schema =
    target.channel === 'weixin'
      ? 'nachuan.weixin-recovery-snapshot.v1'
      : 'nachuan.feishu-recovery-inspect.v1'
  if (
    value.schema !== schema ||
    value.target_kind !== target.targetKind ||
    !Number.isSafeInteger(value.decided_at_ms) ||
    Number(value.decided_at_ms) < 0
  ) {
    throw new Error('invalid channel recovery snapshot')
  }
  if (target.channel === 'weixin') validatedChannelRecoveryDigest(value.principal_sha256)
  return {
    schema,
    targetKind: target.targetKind,
    targetKeySha256: validatedChannelRecoveryDigest(value.target_key_sha256),
    expectedBeforeDigest: validatedChannelRecoveryDigest(value.expected_before_digest),
    affectedCounts: validatedChannelRecoveryCounts(value.affected_counts, target.channel),
    decisionId: validatedChannelRecoveryDigest(value.decision_id),
    decidedAtMs: Number(value.decided_at_ms)
  }
}

function validatedChannelRecoveryResult(
  raw: unknown,
  channel: ChannelRecoveryChannel
): {
  schema: 'nachuan.channel-recovery-result.v1'
  operationDigest: string
  receiptSha256: string
  affectedCounts: Record<string, number>
  applied: boolean
} {
  const value = exactChannelRecoveryObject(raw, [
    'affected_counts',
    'applied',
    'operation_digest',
    'receipt_sha256',
    'schema'
  ])
  if (value.schema !== 'nachuan.channel-recovery-result.v1' || typeof value.applied !== 'boolean') {
    throw new Error('invalid channel recovery result')
  }
  return {
    schema: 'nachuan.channel-recovery-result.v1',
    operationDigest: validatedChannelRecoveryDigest(value.operation_digest),
    receiptSha256: validatedChannelRecoveryDigest(value.receipt_sha256),
    affectedCounts: validatedChannelRecoveryCounts(value.affected_counts, channel),
    applied: value.applied
  }
}

function pruneChannelRecoveryAttempts(now: number): void {
  for (const [key, createdAt] of channelRecoveryAttempts) {
    if (now - createdAt > CHANNEL_RECOVERY_ATTEMPT_TTL_MS) channelRecoveryAttempts.delete(key)
  }
  while (channelRecoveryAttempts.size >= CHANNEL_RECOVERY_ATTEMPT_LIMIT) {
    const oldest = channelRecoveryAttempts.keys().next().value as string | undefined
    if (!oldest) break
    channelRecoveryAttempts.delete(oldest)
  }
}

ipcMain.handle('channel-recovery:inspect', async (event, raw: unknown) => {
  requireExpectedIpcSender(event, mainWin)
  const target = validatedChannelRecoveryTarget(raw)
  const response = await desktopPrivilegedSession.inspectChannelRecovery(target)
  return validatedChannelRecoverySnapshot(response, target)
})

ipcMain.handle('channel-recovery:close', async (event, raw: unknown) => {
  requireExpectedIpcSender(event, mainWin)
  const value = exactChannelRecoveryObject(raw, [
    'channel',
    'confirmFinal',
    'decidedAtMs',
    'decisionId',
    'expectedBeforeDigest',
    'reason',
    'targetKey',
    'targetKeySha256',
    'targetKind',
    'userConfirmed'
  ])
  const target = validatedChannelRecoveryTarget({
    channel: value.channel,
    targetKind: value.targetKind,
    targetKey: value.targetKey
  })
  const targetKeySha256 = validatedChannelRecoveryDigest(value.targetKeySha256)
  const expectedBeforeDigest = validatedChannelRecoveryDigest(value.expectedBeforeDigest)
  const decisionId = validatedChannelRecoveryDigest(value.decisionId)
  if (
    !Number.isSafeInteger(value.decidedAtMs) ||
    Number(value.decidedAtMs) < 0 ||
    typeof value.reason !== 'string' ||
    value.reason.length < 1 ||
    value.reason.length > 2_048 ||
    /[\u0000-\u001f\u007f]/.test(value.reason) ||
    value.userConfirmed !== true ||
    value.confirmFinal !== true
  ) {
    throw new Error('invalid channel recovery decision')
  }

  const attemptKey = JSON.stringify({
    channel: target.channel,
    targetKind: target.targetKind,
    targetKey: target.targetKey,
    targetKeySha256,
    expectedBeforeDigest,
    decisionId,
    decidedAtMs: Number(value.decidedAtMs),
    reason: value.reason
  })
  const now = Date.now()
  pruneChannelRecoveryAttempts(now)
  const retry = channelRecoveryAttempts.has(attemptKey)
  if (!retry) {
    const fresh = validatedChannelRecoverySnapshot(
      await desktopPrivilegedSession.inspectChannelRecovery(target),
      target
    )
    if (
      fresh.targetKeySha256 !== targetKeySha256 ||
      fresh.expectedBeforeDigest !== expectedBeforeDigest
    ) {
      throw new Error('channel recovery target changed; inspect again')
    }
  }

  await confirmPrivilegedChange(
    retry ? '重试查询恢复结案回执？' : '永久结案这组平台结果未知记录？',
    `渠道：${target.channel}\n类型：${target.targetKind}\n目标摘要：${targetKeySha256}\n状态摘要：${expectedBeforeDigest}\n${
      retry
        ? '本次只使用同一操作查询既有回执；服务端不会重新读取或重放目标。'
        : '结案后不会恢复、不会重发、不会调用平台；该操作不可撤销。'
    }`
  )
  channelRecoveryAttempts.set(attemptKey, now)
  const response = await desktopPrivilegedSession.closeChannelRecovery({
    ...target,
    expectedBeforeDigest,
    decisionId,
    decidedAtMs: Number(value.decidedAtMs),
    reason: value.reason,
    userConfirmed: true,
    confirmFinal: true
  })
  return validatedChannelRecoveryResult(response, target.channel)
})

let snipWin: BrowserWindow | null = null
let snipResolve: ((v: { dataUrl: string; action: string } | null) => void) | null = null
let snipBgData: { dataUrl: string; width: number; height: number } | null = null

// 抓「光标所在显示器」的整屏冻结图（含高 DPI 缩放，保证裁切清晰）
async function captureCursorDisplay(): Promise<{
  disp: Electron.Display
  bg: { dataUrl: string; width: number; height: number }
} | null> {
  const disp = screen.getDisplayNearestPoint(screen.getCursorScreenPoint())
  const sf = disp.scaleFactor || 1
  try {
    const sources = await desktopCapturer.getSources({
      types: ['screen'],
      thumbnailSize: {
        width: Math.round(disp.size.width * sf),
        height: Math.round(disp.size.height * sf)
      }
    })
    const src = sources.find((s) => String(s.display_id) === String(disp.id)) ?? sources[0]
    if (!src) return null
    const img = src.thumbnail
    const sz = img.getSize()
    return { disp, bg: { dataUrl: img.toDataURL(), width: sz.width, height: sz.height } }
  } catch (e) {
    console.error('[snip] 截屏失败：', e)
    return null
  }
}

async function startSnip(): Promise<{ dataUrl: string; action: string } | null> {
  if (snipWin) return null // 已在截图中
  const cap = await captureCursorDisplay()
  if (!cap) return null
  snipBgData = cap.bg
  const { x, y, width, height } = cap.disp.bounds
  return new Promise((resolve) => {
    snipResolve = resolve
    const w = new BrowserWindow({
      x,
      y,
      width,
      height,
      frame: false,
      transparent: true,
      alwaysOnTop: true,
      skipTaskbar: true,
      resizable: false,
      movable: false,
      minimizable: false,
      maximizable: false,
      fullscreenable: false,
      hasShadow: false,
      enableLargerThanScreen: true,
      backgroundColor: '#00000000',
      show: false,
      webPreferences: windowSecurityPreferences(join(__dirname, '../preload/index.js'), {
        webview: false,
        devTools: false
      })
    })
    snipWin = w
    w.setAlwaysOnTop(true, 'screen-saver')
    const configuredDevUrl = process.env['ELECTRON_RENDERER_URL'] || ''
    const devUrl = !app.isPackaged && isLoopbackRendererUrl(configuredDevUrl) ? configuredDevUrl : ''
    const rendererFile = join(__dirname, '../renderer/index.html')
    const trustedRendererEntry = devUrl || pathToFileURL(rendererFile).href
    lockLocalRendererNavigation(w, trustedRendererEntry, false)
    if (devUrl) w.loadURL(`${devUrl}#snip`)
    else w.loadFile(rendererFile, { hash: 'snip' })
    // 兜底：1.5s 没收到 ready 也强制显示，避免卡黑
    const fallback = setTimeout(() => {
      if (!w.isDestroyed()) w.show()
    }, 1500)
    w.once('closed', () => {
      clearTimeout(fallback)
      snipWin = null
      snipBgData = null
      if (snipResolve) {
        snipResolve(null) // 未提交即关闭 = 取消
        snipResolve = null
      }
    })
  })
}

// 截图存盘：关窗后弹保存对话框，把裁切图写成 PNG（不阻塞关窗）
async function saveSnipImage(dataUrl: string): Promise<void> {
  try {
    const { canceled, filePath } = await dialog.showSaveDialog({
      title: '保存截图',
      defaultPath: `截图-${Date.now()}.png`,
      filters: [{ name: 'PNG 图片', extensions: ['png'] }]
    })
    if (canceled || !filePath) return
    writeFileSync(filePath, Buffer.from(dataUrl.split(',')[1] || '', 'base64'))
  } catch (e) {
    console.error('[snip] 保存失败：', e)
  }
}

// 提交/取消：copy 落剪贴板、save 弹存盘 → 关窗 → resolve 给触发方
function finishSnip(payload: { dataUrl: string; action: string } | null): void {
  if (payload && payload.action === 'copy' && payload.dataUrl) {
    try {
      clipboard.writeImage(nativeImage.createFromDataURL(payload.dataUrl))
    } catch {
      /* ignore */
    }
  }
  if (payload && payload.action === 'save' && payload.dataUrl) {
    void saveSnipImage(payload.dataUrl) // 异步弹框，不阻塞关窗
  }
  const r = snipResolve
  snipResolve = null // 先清空，避免随后的 'closed' 再次 resolve(null)
  if (snipWin && !snipWin.isDestroyed()) snipWin.close()
  if (r) r(payload)
}

// 触发一次截图；只有「嵌入对话」需要推回渲染端，copy/save 都在主进程就地处理
async function triggerSnip(): Promise<void> {
  const r = await startSnip()
  if (r && r.action === 'paste') mainWin?.webContents.send('snip:result', r)
}

ipcMain.handle('snip:bg', (event) => {
  requireExpectedIpcSender(event, snipWin)
  return snipBgData
})
ipcMain.handle('snip:start', async (event) => {
  requireExpectedIpcSender(event, mainWin)
  await triggerSnip()
  return { ok: true }
})
ipcMain.handle('dialog:pick-directory', async (event) => {
  requireExpectedIpcSender(event, mainWin)
  const opts = { properties: ['openDirectory' as const] }
  const r = mainWin ? await dialog.showOpenDialog(mainWin, opts) : await dialog.showOpenDialog(opts)
  return r.canceled ? '' : (r.filePaths[0] ?? '')
})
// 保存聊天里的图/视频：远程 URL 由主进程做公网 DNS/重定向/大小校验并流式落盘；
// data/blob 字节也有独立上限。任何拒绝都返回渲染层显示，不能绕回不受控 fetch。
ipcMain.handle(
  'media:save',
  async (event, p: { filename: string; bytes?: ArrayBuffer; url?: string }) => {
    requireExpectedIpcSender(event, mainWin)
    try {
      if (!p || typeof p.filename !== 'string') return { ok: false, error: 'invalid request' }
      const filename = p.filename
        .split(/[\\/]/)
        .pop()
        ?.replace(/[\u0000-\u001f<>:"/\\|?*]/g, '_')
        .slice(0, 160)
      if (!filename || !/\.(?:png|jpe?g|gif|webp|mp4|mov|webm|m4v|mp3|wav|m4a|aac)$/i.test(filename)) {
        return { ok: false, error: 'unsupported media filename' }
      }
      const hasBytes = p.bytes instanceof ArrayBuffer
      const hasUrl = typeof p.url === 'string' && p.url.length > 0
      if (hasBytes === hasUrl) return { ok: false, error: 'provide exactly one media source' }
      if (hasBytes && (p.bytes!.byteLength <= 0 || p.bytes!.byteLength > MAX_INLINE_MEDIA_BYTES)) {
        return { ok: false, error: 'inline media is empty or too large' }
      }
      const dlg = { defaultPath: filename }
      const r = mainWin ? await dialog.showSaveDialog(mainWin, dlg) : await dialog.showSaveDialog(dlg)
      if (r.canceled || !r.filePath) return { ok: false, error: 'canceled' }
      if (hasBytes) await writeBoundedMediaBytes(r.filePath, p.bytes!)
      else await downloadPublicMedia(p.url!, r.filePath)
      return { ok: true, path: r.filePath }
    } catch (e) {
      return { ok: false, error: e instanceof Error ? e.message : 'media save failed' }
    }
  }
)
ipcMain.on('snip:ready', (event) => {
  if (!isExpectedIpcSender(event, snipWin)) return
  if (snipWin && !snipWin.isDestroyed()) {
    snipWin.show()
    snipWin.focus()
  }
})
ipcMain.on('snip:done', (event, payload) => {
  if (isExpectedIpcSender(event, snipWin)) finishSnip(payload)
})
ipcMain.on('snip:cancel', (event) => {
  if (isExpectedIpcSender(event, snipWin)) finishSnip(null)
})
// 跟随 app 内中英切换重建原生菜单（含「功能」栏）
ipcMain.on('set-lang', (event, lang: string) => {
  if (isExpectedIpcSender(event, mainWin)) buildMenu(lang)
})

function publishUpdateState(state: UpdateUiState): void {
  latestUpdateState = state
  auditDesktop('desktop.update_state', {
    phase: state.phase,
    version: state.version || '',
    reason: state.reason || ''
  })
  if (mainWin && !mainWin.isDestroyed()) mainWin.webContents.send('update:state', state)
}

async function setupAutoUpdate(): Promise<void> {
  let authenticodeValid = false
  if (
    app.isPackaged &&
    process.platform === 'win32' &&
    EMBEDDED_UPDATE_TRUST.enabled &&
    EMBEDDED_UPDATE_TRUST.releaseTier === 'production'
  ) {
    try {
      await requireStrictAuthenticode(process.execPath, {
        publisherName: EMBEDDED_UPDATE_TRUST.publisherName,
        signerThumbprint: EMBEDDED_UPDATE_TRUST.signerThumbprint,
        requireTimestamp: true
      })
      authenticodeValid = true
    } catch {
      auditDesktop('desktop.update_current_signature_blocked')
    }
  }
  const policy = automaticUpdatePolicy({
    isPackaged: app.isPackaged && process.platform === 'win32',
    trustConfigured: EMBEDDED_UPDATE_TRUST.enabled,
    releaseTier: EMBEDDED_UPDATE_TRUST.releaseTier,
    authenticodeValid
  })
  if (!policy.enabled) {
    publishUpdateState({ phase: 'disabled', reason: 'not-configured' })
    return
  }

  let autoUpdater: typeof import('electron-updater').autoUpdater
  try {
    ;({ autoUpdater } = await import('electron-updater'))
  } catch {
    publishUpdateState({ phase: 'blocked', reason: 'failed' })
    return
  }
  const configPath = join(app.getPath('userData'), 'config.json')
  const readUpdateState = (): unknown =>
    readSecureConfig(configPath, safeStorage).updateSecurityState
  const writeUpdateState = (state: Parameters<InstallationRootUpdaterAuthority['commit']>[0]): void => {
    const config = readSecureConfig(configPath, safeStorage)
    writeSecureConfig(configPath, { ...config, updateSecurityState: state }, safeStorage)
  }
  const rootUpdater = new InstallationRootUpdaterAuthority({
    client: installationRootClient,
    readState: readUpdateState,
    writeState: writeUpdateState
  })
  // Early-access metadata/artifacts are hosted on a public read-only origin.
  // No shared GitHub token or bearer credential is embedded or inherited.
  const controller = new SecureAutoUpdater({
    trust: EMBEDDED_UPDATE_TRUST,
    currentVersion: app.getVersion(),
    updater: autoUpdater as unknown as SecureUpdaterAdapter,
    fetchEnvelope: () =>
      fetchBoundedSignedUpdateEnvelope(EMBEDDED_UPDATE_TRUST.manifestUrl),
    readState: readUpdateState,
    writeState: writeUpdateState,
    beforeCheck: () => rootUpdater.reconcile(),
    commitState: (state) => rootUpdater.commit(state),
    beforeInstall: (state) => rootUpdater.assertReady(state),
    notify: publishUpdateState,
    log: (message) => console.error(message)
  })
  secureAutoUpdater = controller
  updateScheduler = new UpdateCheckScheduler({ check: (reason) => controller.check(reason) })
  updateScheduler.start()
  powerMonitor.on('resume', () => void updateScheduler?.resumed().catch(() => undefined))
  publishUpdateState({ phase: 'idle' })
}

ipcMain.handle('update:state', (event) => {
  requireExpectedIpcSender(event, mainWin)
  return latestUpdateState
})

ipcMain.handle('update:check', async (event) => {
  requireExpectedIpcSender(event, mainWin)
  try {
    await updateScheduler?.trigger('manual')
  } catch {
    // The bounded state sent below tells the renderer whether this was a
    // network problem or a security block without exposing paths or secrets.
  }
  return latestUpdateState
})

ipcMain.handle('update:install', async (event) => {
  requireExpectedIpcSender(event, mainWin)
  if (!secureAutoUpdater?.hasPendingUpdate) return { ok: false }
  try {
    await secureAutoUpdater.installVerifiedUpdate('install-now')
    return { ok: true }
  } catch {
    publishUpdateState({ phase: 'blocked', reason: 'security' })
    return { ok: false }
  }
})

ipcMain.on('update:network-online', (event) => {
  if (isExpectedIpcSender(event, mainWin)) {
    void updateScheduler?.networkRecovered().catch(() => undefined)
  }
})

if (ownsSingleInstance) {
  void app.whenReady().then(async () => {
  try {
    desktopAuditLog = new DesktopAuditLog(join(app.getPath('userData'), 'logs'))
    auditDesktop('desktop.ready', { packaged: app.isPackaged, version: app.getVersion() })
  } catch (error) {
    console.error('[desktop] audit log unavailable:', error)
  }
  try {
    engineKey = loadOrCreateKey()
    approvalKey = loadApprovalKey(engineKey)
    paidMediaKey = loadPaidMediaKey(engineKey, approvalKey)
    weixinBridgeKey = `sk-bridge-v2-weixin-${randomBytes(32).toString('hex')}`
  } catch {
    dialog.showErrorBox(
      '安全存储不可用',
      '无法用当前 Windows 账户解密或保护本机密钥。为避免明文降级，纳川已停止启动；请检查账户与数据目录权限。'
    )
    app.quit()
    return
  }
  try {
    await startEngine()
  } catch (error) {
    fatalEngineFailure(error)
    return
  }
  // Paid-media Root reconciliation may involve disk and bounded engine IPC.
  // The ordinary chat window must not wait for, or be terminated by, that
  // optional paid control plane.
  createWindow()
  try {
    await initializePaidMediaControlPlane()
  } catch (error) {
    paidMediaService?.disableRemoteOperations()
    auditDesktop('paid_media.control_plane_degraded', {
      error_type: error instanceof Error ? error.name : typeof error
    })
    console.error('[paid-media] control plane initialization failed:', error)
  }
  void setupAutoUpdate() // 后台检查更新，不阻塞启动
  // 全局快捷键：随时随地截图（类似微信 Ctrl+Alt+A）；被占用则静默忽略
  try {
    globalShortcut.register('Control+Alt+A', () => void triggerSnip())
  } catch {
    /* ignore */
  }
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow()
  })
  })
}

app.on('window-all-closed', () => {
  // 关闭已最小化到托盘、窗口仍在，这里一般不触发；真退出走托盘「退出」。不主动 quit。
})

app.on('before-quit', (event) => {
  auditDesktop('desktop.before_quit')
  isQuitting = true // 让窗口 close 真正退出（不再拦截到托盘）；也让看门狗不再拉起引擎
  engineRootSessions.invalidateAll()
  enginePort = 0
  updateScheduler?.stop()
  paidMediaIpcRegistration?.dispose()
  paidMediaIpcRegistration = null
  paidMediaService = null
  paidMediaVault = null
  protocol.unhandle('nachuan-paid-media')
  globalShortcut.unregisterAll()
  if (engineRestartTimer) clearTimeout(engineRestartTimer)
  engineRestartTimer = null
  if (engineHealthyTimer) clearTimeout(engineHealthyTimer)
  engineHealthyTimer = null
  weixinBridgeSupervisor.stop()
  const child = engineProc
  engineProc = null
  child?.kill()
})
