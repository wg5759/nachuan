import { spawn } from 'node:child_process'
import { lstatSync, realpathSync } from 'node:fs'
import { resolve } from 'node:path'

import { prepareTrustedWindowsCommand } from './windows-system'

const THUMBPRINT = /^[0-9A-F]{40,128}$/

export interface AuthenticodeExpectation {
  publisherName: string
  signerThumbprint: string
  requireTimestamp: boolean
}

export interface AuthenticodeProbeResult {
  exitCode: number | null
  signal: NodeJS.Signals | null
  stdout: string
}

export type AuthenticodeProbe = (
  path: string,
  expectation: AuthenticodeExpectation
) => Promise<AuthenticodeProbeResult>

export class AuthenticodeError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options)
    this.name = 'AuthenticodeError'
  }
}

const PROBE_SCRIPT =
  "& { param([string]$p,[string]$publisher,[string]$thumb,[string]$needTimestamp) " +
  "$ErrorActionPreference='Stop'; $PSModuleAutoLoadingPreference='None'; " +
  'try {$s=Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop} catch {exit 20}; ' +
  "if($s.Status.ToString() -cne 'Valid' -or $null -eq $s.SignerCertificate){exit 21}; " +
  '$subject=[string]$s.SignerCertificate.Subject; ' +
  'if($subject.IndexOf($publisher,[StringComparison]::Ordinal) -lt 0){exit 22}; ' +
  "$actual=(([string]$s.SignerCertificate.Thumbprint) -replace '[^0-9A-Fa-f]','').ToUpperInvariant(); " +
  'if($actual -cne $thumb){exit 23}; ' +
  "if($needTimestamp -ceq '1' -and $null -eq $s.TimeStamperCertificate){exit 24}; " +
  '[Console]::Out.Write($actual); exit 0 }'

export async function runTrustedAuthenticodeProbe(
  path: string,
  expectation: AuthenticodeExpectation
): Promise<AuthenticodeProbeResult> {
  const command = prepareTrustedWindowsCommand('powershell.exe')
  return await new Promise<AuthenticodeProbeResult>((accept, reject) => {
    const child = spawn(
      command.executable,
      [
        '-NoLogo',
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        PROBE_SCRIPT,
        path,
        expectation.publisherName,
        expectation.signerThumbprint,
        expectation.requireTimestamp ? '1' : '0'
      ],
      { windowsHide: true, shell: false, env: command.env, stdio: ['ignore', 'pipe', 'ignore'] }
    )
    const chunks: Buffer[] = []
    let outputBytes = 0
    const timer = setTimeout(() => {
      child.kill()
      reject(new AuthenticodeError('trusted Authenticode probe timed out'))
    }, 20_000)
    child.stdout.on('data', (chunk: Buffer) => {
      outputBytes += chunk.length
      if (outputBytes <= 1024) chunks.push(Buffer.from(chunk))
    })
    child.once('error', (error) => {
      clearTimeout(timer)
      reject(new AuthenticodeError('trusted Authenticode probe could not start', { cause: error }))
    })
    child.once('exit', (exitCode, signal) => {
      clearTimeout(timer)
      accept({
        exitCode,
        signal,
        stdout: outputBytes <= 1024 ? Buffer.concat(chunks).toString('utf8') : ''
      })
    })
  })
}

export async function requireStrictAuthenticode(
  pathValue: string,
  expectation: AuthenticodeExpectation,
  probe: AuthenticodeProbe = runTrustedAuthenticodeProbe
): Promise<void> {
  const path = resolve(String(pathValue || ''))
  const info = lstatSync(path)
  if (info.isSymbolicLink() || !info.isFile() || info.size <= 0) {
    throw new AuthenticodeError('Authenticode target must be a non-empty regular file')
  }
  realpathSync.native(path)
  const publisherName = String(expectation.publisherName || '').trim()
  const signerThumbprint = String(expectation.signerThumbprint || '').toUpperCase()
  if (!publisherName || !THUMBPRINT.test(signerThumbprint)) {
    throw new AuthenticodeError('expected Authenticode identity is not configured')
  }
  let result: AuthenticodeProbeResult
  try {
    result = await probe(path, { ...expectation, publisherName, signerThumbprint })
  } catch (error) {
    throw error instanceof AuthenticodeError
      ? error
      : new AuthenticodeError('trusted Authenticode probe failed', { cause: error })
  }
  if (
    result.exitCode !== 0 ||
    result.signal !== null ||
    result.stdout.trim().toUpperCase() !== signerThumbprint
  ) {
    throw new AuthenticodeError('Authenticode signature, publisher, signer, or timestamp is invalid')
  }
}

export function createFailClosedElectronUpdaterSignatureVerifier(
  expectation: AuthenticodeExpectation,
  probe: AuthenticodeProbe = runTrustedAuthenticodeProbe
): (publisherNames: string[], path: string) => Promise<string | null> {
  return async (_publisherNames, path) => {
    try {
      await requireStrictAuthenticode(path, expectation, probe)
      return null
    } catch {
      return 'Nachuan strict Authenticode verification failed'
    }
  }
}
