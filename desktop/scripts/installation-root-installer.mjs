import { lstatSync, readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { load as loadYaml } from 'js-yaml'


const scriptPath = fileURLToPath(import.meta.url)
const defaultDesktopRoot = resolve(dirname(scriptPath), '..')
const defaultProjectRoot = resolve(defaultDesktopRoot, '..')


function readSmallRegular(path, maxBytes = 512 * 1024) {
  const info = lstatSync(path)
  if (info.isSymbolicLink() || !info.isFile() || info.size <= 0 || info.size > maxBytes) {
    throw new Error(`installer contract input must be a small regular file: ${path}`)
  }
  return readFileSync(path, 'utf8')
}


function requireOrdered(source, markers, label) {
  let cursor = -1
  for (const marker of markers) {
    const next = source.indexOf(marker, cursor + 1)
    if (next < 0 || next <= cursor) throw new Error(`${label} is missing ordered marker: ${marker}`)
    cursor = next
  }
}


export function verifyInstallationRootInstallerContract({
  desktopRoot = defaultDesktopRoot,
  projectRoot = defaultProjectRoot
} = {}) {
  desktopRoot = resolve(desktopRoot)
  projectRoot = resolve(projectRoot)
  const configPath = join(desktopRoot, 'electron-builder.yml')
  const includePath = join(desktopRoot, 'build', 'installer.nsh')
  const enginePath = join(projectRoot, 'engine_main.py')
  const specPath = join(projectRoot, 'engine.spec')

  const configSource = readSmallRegular(configPath)
  const config = loadYaml(configSource)
  const nsis = config && typeof config === 'object' ? config.nsis : null
  if (!nsis || typeof nsis !== 'object' || Array.isArray(nsis)) {
    throw new Error('electron-builder NSIS configuration is missing')
  }
  if (
    nsis.oneClick !== false ||
    nsis.perMachine !== true ||
    nsis.allowToChangeInstallationDirectory !== false
  ) {
    throw new Error('Installation Root requires an assisted per-machine installer')
  }
  if (nsis.include !== 'build/installer.nsh') {
    throw new Error('NSIS does not include the reviewed Installation Root hook')
  }
  if (nsis.deleteAppDataOnUninstall !== false) {
    throw new Error('ordinary uninstall must preserve application and authority data')
  }

  const include = readSmallRegular(includePath)
  if ((include.match(/!macro\s+customInstall\b/g) || []).length !== 1) {
    throw new Error('NSIS must define exactly one customInstall authority hook')
  }
  if (/!macro\s+customUnInstall\b/i.test(include)) {
    throw new Error('ordinary uninstall must not mutate Installation Root authority')
  }
  if (/\$(?:PROGRAMDATA|APPDATA)|%(?:PROGRAMDATA|APPDATA)%/i.test(include)) {
    throw new Error('NSIS must not resolve or pass an environment-derived authority path')
  }
  if (/\b(?:cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh(?:\.exe)?)\b/i.test(include)) {
    throw new Error('NSIS authority hook must execute the installed engine directly')
  }
  if (/^(?:\s*)(?:RMDir|Delete)\b[^\r\n]*(?:ProgramData|StateRoot|installation-root|gateway-paid)/im.test(include)) {
    throw new Error('installer/uninstaller hook must never delete authority state')
  }
  const command =
    'nsExec::ExecToStack /TIMEOUT=120000 \'"$INSTDIR\\resources\\engine\\engine.exe" --nachuan-provision-installation-root\''
  if ((include.split(command).length - 1) !== 1) {
    throw new Error('NSIS authority hook must use one exact installed-engine command')
  }
  requireOrdered(
    include,
    [
      command,
      'Pop $R8',
      'Pop $R9',
      '${If} $R8 != 0',
      'DeleteRegKey SHELL_CONTEXT "${INSTALL_REGISTRY_KEY}"',
      'RMDir /r "$INSTDIR"',
      'SetErrorLevel 1603',
      'Quit'
    ],
    'NSIS fail-closed rollback'
  )

  const engine = readSmallRegular(enginePath)
  const exactArgument = 'INSTALLATION_PROVISION_ARGUMENT = "--nachuan-provision-installation-root"'
  if ((engine.split(exactArgument).length - 1) !== 1) {
    throw new Error('frozen engine is missing the exact installer-only argument')
  }
  requireOrdered(
    engine,
    [
      'if args != [INSTALLATION_PROVISION_ARGUMENT]:',
      'if not bool(getattr(sys, "frozen", False)) or os.name != "nt":',
      'from gateway.installation_bootstrap import provision_fixed_authority',
      'provision_fixed_authority()',
      'enforce_frozen_financial_ledger()',
      'from gateway.app import main'
    ],
    'frozen engine installer dispatch'
  )
  if (!/Analysis\(\s*\[\s*['"]engine_main\.py['"]\s*\]/s.test(readSmallRegular(specPath))) {
    throw new Error('PyInstaller spec is not rooted at the reviewed engine entry point')
  }

  return Object.freeze({ configPath, includePath, enginePath, specPath })
}


async function main() {
  try {
    verifyInstallationRootInstallerContract()
    console.log('[installation-root-installer] OK')
    return 0
  } catch (error) {
    console.error(
      `[installation-root-installer] BLOCKED: ${error instanceof Error ? error.message : String(error)}`
    )
    return 1
  }
}


if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  process.exitCode = await main()
}
