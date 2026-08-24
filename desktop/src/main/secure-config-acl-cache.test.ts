import { mkdirSync, mkdtempSync, rmSync, symlinkSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { describe, expect, it, vi } from 'vitest'

import { createLocalSecretAclHardener, hardenLocalSecretAcl } from './secure-config'

describe('local secret ACL verification cache', () => {
  it('reuses a verified unchanged file identity and revalidates an atomic replacement', () => {
    let identity = 'file-id-1'
    const run = vi.fn((command: { executable: string }) => {
      if (command.executable.endsWith('whoami.exe')) {
        return { status: 0, stdout: '"desktop","S-1-5-21-111-222-333-1001"' }
      }
      return { status: 0, stdout: '' }
    })
    const harden = createLocalSecretAclHardener({
      platform: 'win32',
      inspect: vi.fn(() => ({ identity, directory: false })),
      chmod: vi.fn(),
      prepareCommand: (name) => ({ executable: `C:\\Windows\\System32\\${name}`, env: {} }),
      run
    })

    harden('C:\\vault\\result.json', false)
    harden('C:\\vault\\result.json', false)

    expect(run.mock.calls.map(([command]) => command.executable)).toEqual([
      'C:\\Windows\\System32\\whoami.exe',
      'C:\\Windows\\System32\\icacls.exe',
      'C:\\Windows\\System32\\powershell.exe'
    ])

    identity = 'file-id-2'
    harden('C:\\vault\\result.json', false)

    expect(run.mock.calls.map(([command]) => command.executable)).toEqual([
      'C:\\Windows\\System32\\whoami.exe',
      'C:\\Windows\\System32\\icacls.exe',
      'C:\\Windows\\System32\\powershell.exe',
      'C:\\Windows\\System32\\icacls.exe',
      'C:\\Windows\\System32\\powershell.exe'
    ])
  })

  it('keeps file and directory rights in separate cache entries', () => {
    const run = vi.fn((command: { executable: string }) => ({
      status: 0,
      stdout: command.executable.endsWith('whoami.exe')
        ? '"desktop","S-1-5-21-111-222-333-1001"'
        : ''
    }))
    const harden = createLocalSecretAclHardener({
      platform: 'win32',
      inspect: vi.fn(() => ({ identity: 'same-id', directory: true })),
      chmod: vi.fn(),
      prepareCommand: (name) => ({ executable: `C:\\Windows\\System32\\${name}`, env: {} }),
      run
    })

    harden('C:\\vault', true)
    harden('C:\\vault', true)
    expect(() => harden('C:\\vault', false)).toThrow(/type/i)
    expect(run).toHaveBeenCalledTimes(3)
  })

  it('does not cache a replacement that appears during ACL verification', () => {
    const identities = [
      'old-before-update',
      'old-before-verify',
      'replacement-after-verify',
      'replacement-before-update',
      'replacement-before-verify',
      'replacement-before-verify'
    ]
    const run = vi.fn((command: { executable: string }) => ({
      status: 0,
      stdout: command.executable.endsWith('whoami.exe')
        ? '"desktop","S-1-5-21-111-222-333-1001"'
        : ''
    }))
    const harden = createLocalSecretAclHardener({
      platform: 'win32',
      inspect: vi.fn(() => ({ identity: identities.shift() ?? 'unexpected', directory: false })),
      chmod: vi.fn(),
      prepareCommand: (name) => ({ executable: `C:\\Windows\\System32\\${name}`, env: {} }),
      run
    })

    expect(() => harden('C:\\vault\\result.json', false)).toThrow(/changed/i)
    harden('C:\\vault\\result.json', false)

    expect(run.mock.calls.map(([command]) => command.executable)).toEqual([
      'C:\\Windows\\System32\\whoami.exe',
      'C:\\Windows\\System32\\icacls.exe',
      'C:\\Windows\\System32\\powershell.exe',
      'C:\\Windows\\System32\\icacls.exe',
      'C:\\Windows\\System32\\powershell.exe'
    ])
  })

  it('rejects a Windows junction before invoking an ACL subprocess', () => {
    if (process.platform !== 'win32') return
    const root = mkdtempSync(join(tmpdir(), 'nachuan-acl-reparse-'))
    const target = join(root, 'target')
    const redirected = join(root, 'redirected')
    try {
      mkdirSync(target)
      symlinkSync(target, redirected, 'junction')
      expect(() => hardenLocalSecretAcl(redirected, true)).toThrow(/type/i)
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })
})
