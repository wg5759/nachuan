import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'

import {
  createFailClosedElectronUpdaterSignatureVerifier,
  requireStrictAuthenticode,
  type AuthenticodeExpectation,
  type AuthenticodeProbe
} from './authenticode'

const roots: string[] = []
const expectation: AuthenticodeExpectation = {
  publisherName: '杭州灵界科技有限公司',
  signerThumbprint: 'A'.repeat(40),
  requireTimestamp: true
}

function target(): string {
  const root = mkdtempSync(join(tmpdir(), 'nachuan-authenticode-'))
  roots.push(root)
  const path = join(root, 'installer.exe')
  writeFileSync(path, 'synthetic-installer')
  return path
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true })
})

describe('fail-closed Windows update signature verification', () => {
  it('accepts only the exact publisher, thumbprint and timestamp probe result', async () => {
    const probe: AuthenticodeProbe = async () => ({
      exitCode: 0,
      signal: null,
      stdout: expectation.signerThumbprint
    })
    await expect(requireStrictAuthenticode(target(), expectation, probe)).resolves.toBeUndefined()
  })

  it('blocks when both underlying PowerShell attempts fail instead of accepting null', async () => {
    let attempts = 0
    const failedProbe: AuthenticodeProbe = async () => {
      attempts += 1
      throw new Error('PowerShell and ConvertTo-Json unavailable')
    }
    const verify = createFailClosedElectronUpdaterSignatureVerifier(expectation, failedProbe)
    const path = target()

    await expect(verify([], path)).resolves.toMatch(/failed/)
    await expect(verify([], path)).resolves.toMatch(/failed/)
    expect(attempts).toBe(2)
  })

  it('blocks nonzero probe status, empty output, or signer drift', async () => {
    const path = target()
    await expect(
      requireStrictAuthenticode(path, expectation, async () => ({ exitCode: 21, signal: null, stdout: '' }))
    ).rejects.toThrow(/invalid/)
    await expect(
      requireStrictAuthenticode(path, expectation, async () => ({
        exitCode: 0,
        signal: null,
        stdout: 'B'.repeat(40)
      }))
    ).rejects.toThrow(/invalid/)
  })
})
