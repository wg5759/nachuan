import { spawnSync } from 'node:child_process'
import {
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join, win32 } from 'node:path'

import { describe, expect, it } from 'vitest'

import {
  assertWindowsPathHasNoReparsePoints,
  prepareTrustedWindowsCommand,
  resolveTrustedWindowsExecutable
} from './windows-system'

describe('trusted Windows system command boundary', () => {
  it('never dispatches security-sensitive Windows commands through PATH lookup', () => {
    const mainDir = __dirname
    const secureConfig = readFileSync(join(mainDir, 'secure-config.ts'), 'utf8')
    const main = readFileSync(join(mainDir, 'index.ts'), 'utf8')

    expect(secureConfig).not.toMatch(/spawnSync\(\s*['"](?:whoami|icacls|powershell)\.exe['"]/i)
    expect(main).not.toMatch(/spawn\(\s*['"]powershell\.exe['"]/i)
  })

  it('resolves fixed System32 executables and launches with a closed environment', () => {
    if (process.platform !== 'win32') return

    const whoami = prepareTrustedWindowsCommand('whoami.exe')
    const powershell = prepareTrustedWindowsCommand('powershell.exe')
    expect(win32.isAbsolute(whoami.executable)).toBe(true)
    expect(whoami.executable.toLowerCase()).toContain('\\system32\\whoami.exe')
    expect(powershell.executable.toLowerCase()).toContain(
      '\\system32\\windowspowershell\\v1.0\\powershell.exe'
    )
    expect(realpathSync.native(whoami.executable).toLowerCase()).toBe(
      whoami.executable.toLowerCase()
    )
    expect(lstatSync(whoami.executable).isSymbolicLink()).toBe(false)
    expect(Object.keys(whoami.env).sort()).toEqual([
      'ComSpec',
      'POWERSHELL_TELEMETRY_OPTOUT',
      'POWERSHELL_UPDATECHECK',
      'SystemRoot',
      'WINDIR'
    ])
    expect(whoami.env.PATH).toBeUndefined()
    expect(whoami.env.PSModulePath).toBeUndefined()

    const result = spawnSync(whoami.executable, ['/user', '/fo', 'csv', '/nh'], {
      windowsHide: true,
      encoding: 'utf8',
      timeout: 10_000,
      env: whoami.env
    })
    expect(result.status).toBe(0)
    expect(result.stdout).toMatch(/S-1-(?:\d+-)+\d+/i)

    const signature = spawnSync(
      powershell.executable,
      [
        '-NoLogo',
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        "& { param([string]$p) $PSModuleAutoLoadingPreference='None'; $s=Get-AuthenticodeSignature -LiteralPath $p; if($s.Status -eq 'Valid'){exit 0}else{exit 1} }",
        whoami.executable
      ],
      { windowsHide: true, stdio: 'ignore', timeout: 60_000, env: powershell.env }
    )
    expect(signature.status).toBe(0)
  }, 75_000)

  it('rejects a directory junction before reaching a system executable', () => {
    if (process.platform !== 'win32') return
    const root = mkdtempSync(join(tmpdir(), 'nachuan-system-root-'))
    const redirected = mkdtempSync(join(tmpdir(), 'nachuan-system-redirect-'))
    try {
      mkdirSync(join(redirected, 'bin'))
      writeFileSync(join(redirected, 'bin', 'whoami.exe'), 'synthetic')
      symlinkSync(join(redirected, 'bin'), join(root, 'System32'), 'junction')
      const canonicalRoot = realpathSync.native(root)

      expect(() =>
        assertWindowsPathHasNoReparsePoints(
          canonicalRoot,
          join(canonicalRoot, 'System32', 'whoami.exe'),
          'file'
        )
      ).toThrow(/reparse point/i)
    } finally {
      rmSync(root, { recursive: true, force: true })
      rmSync(redirected, { recursive: true, force: true })
    }
  })

  it('does not trust a process-provided SystemRoot override', () => {
    if (process.platform !== 'win32') return
    const previous = process.env.SystemRoot
    process.env.SystemRoot = 'D:\\attacker-controlled-windows'
    try {
      const resolved = resolveTrustedWindowsExecutable('icacls.exe')
      expect(resolved.toLowerCase()).not.toContain('attacker-controlled-windows')
    } finally {
      if (previous === undefined) delete process.env.SystemRoot
      else process.env.SystemRoot = previous
    }
  })
})
