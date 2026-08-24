import { lstatSync, realpathSync } from 'node:fs'
import { win32 } from 'node:path'

const KERNEL_SYSTEM_ROOT = '\\\\?\\GLOBALROOT\\SystemRoot'

const SYSTEM_EXECUTABLES = {
  'cmd.exe': ['System32', 'cmd.exe'],
  'whoami.exe': ['System32', 'whoami.exe'],
  'icacls.exe': ['System32', 'icacls.exe'],
  'powershell.exe': ['System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe']
} as const

export type TrustedWindowsExecutable = keyof typeof SYSTEM_EXECUTABLES

export class WindowsSystemTrustError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options)
    this.name = 'WindowsSystemTrustError'
  }
}

function sameWindowsPath(left: string, right: string): boolean {
  return win32.normalize(left).toLocaleLowerCase('en-US') === win32.normalize(right).toLocaleLowerCase('en-US')
}

/**
 * Reject every filesystem alias between a trusted root and a command.  On
 * Windows, Node reports both symbolic links and directory junctions through
 * lstat().isSymbolicLink(); the realpath equality check is a second guard for
 * redirecting reparse points.
 */
export function assertWindowsPathHasNoReparsePoints(
  trustedRoot: string,
  target: string,
  targetKind: 'file' | 'directory'
): void {
  const root = win32.resolve(trustedRoot)
  const candidate = win32.resolve(target)
  const relative = win32.relative(root, candidate)
  if (relative === '..' || relative.startsWith(`..${win32.sep}`) || win32.isAbsolute(relative)) {
    throw new WindowsSystemTrustError('Windows system command escaped the trusted system root')
  }

  const parts = relative ? relative.split(win32.sep).filter(Boolean) : []
  let cursor = root
  for (let index = -1; index < parts.length; index += 1) {
    if (index >= 0) cursor = win32.join(cursor, parts[index])
    const info = lstatSync(cursor)
    if (info.isSymbolicLink()) {
      throw new WindowsSystemTrustError('Windows system command path contains a reparse point')
    }
    const canonical = realpathSync.native(cursor)
    if (!sameWindowsPath(canonical, cursor)) {
      throw new WindowsSystemTrustError('Windows system command path was redirected')
    }
    const final = index === parts.length - 1
    if (!final && !info.isDirectory()) {
      throw new WindowsSystemTrustError('Windows system command parent is not a directory')
    }
    if (final && targetKind === 'file' && !info.isFile()) {
      throw new WindowsSystemTrustError('Windows system command is not a regular file')
    }
    if (final && targetKind === 'directory' && !info.isDirectory()) {
      throw new WindowsSystemTrustError('Windows system root is not a directory')
    }
  }
}

function resolveKernelSystemRoot(): string {
  try {
    const root = realpathSync.native(KERNEL_SYSTEM_ROOT)
    if (!/^[A-Za-z]:\\/.test(root) || !win32.isAbsolute(root)) {
      throw new WindowsSystemTrustError('Windows kernel returned a non-local system root')
    }
    assertWindowsPathHasNoReparsePoints(root, root, 'directory')
    return root
  } catch (error) {
    if (error instanceof WindowsSystemTrustError) throw error
    throw new WindowsSystemTrustError('Cannot resolve the trusted Windows system root', { cause: error })
  }
}

/** Resolve a fixed executable through the kernel SystemRoot alias, never PATH. */
export function resolveTrustedWindowsExecutable(name: TrustedWindowsExecutable): string {
  if (process.platform !== 'win32') {
    throw new WindowsSystemTrustError('Trusted Windows commands are unavailable on this platform')
  }
  try {
    const root = resolveKernelSystemRoot()
    const segments = SYSTEM_EXECUTABLES[name]
    const expected = win32.join(root, ...segments)
    assertWindowsPathHasNoReparsePoints(root, expected, 'file')

    const kernelPath = win32.join(KERNEL_SYSTEM_ROOT, ...segments)
    const kernelResolved = realpathSync.native(kernelPath)
    if (!sameWindowsPath(kernelResolved, expected)) {
      throw new WindowsSystemTrustError('Windows system command did not resolve to its fixed System32 path')
    }
    return expected
  } catch (error) {
    if (error instanceof WindowsSystemTrustError) throw error
    throw new WindowsSystemTrustError(`Cannot validate trusted Windows executable: ${name}`, {
      cause: error
    })
  }
}

/**
 * Deliberately excludes PATH, PSModulePath, profiles, credentials and proxy
 * variables.  The executable is revalidated each time immediately before a
 * caller spawns it.
 */
export function prepareTrustedWindowsCommand(name: TrustedWindowsExecutable): {
  executable: string
  env: NodeJS.ProcessEnv
} {
  const executable = resolveTrustedWindowsExecutable(name)
  const systemRoot = resolveKernelSystemRoot()
  const comSpec = resolveTrustedWindowsExecutable('cmd.exe')
  return {
    executable,
    env: {
      SystemRoot: systemRoot,
      WINDIR: systemRoot,
      ComSpec: comSpec,
      POWERSHELL_TELEMETRY_OPTOUT: '1',
      POWERSHELL_UPDATECHECK: 'Off'
    }
  }
}
