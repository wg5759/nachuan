import { spawnSync } from 'node:child_process'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { describe, expect, it, vi } from 'vitest'

import { publishEarlyAccess } from './publish-early-access.mjs'
import { executeEarlyAccessStorageTransaction } from './early-access-storage-transaction.mjs'

const scriptRoot = dirname(fileURLToPath(import.meta.url))
const publicEntry = resolve(scriptRoot, 'publish-early-access.mjs')
const CLOSED_GATE = /versioned legal policy.*external approval.*candidate-bound fresh audit receipt/i

describe('public early-access publishing entry', () => {
  it('fails closed before any network access and cannot be unlocked by booleans', async () => {
    const fetchImpl = vi.fn(() => {
      throw new Error('network must not be reached')
    })

    await expect(
      publishEarlyAccess({
        variant: 'lean',
        releaseRoot: 'Z:\\missing-release',
        publicBaseUrl: 'https://updates.nachuan.cn/',
        writeBaseUrl: 'https://publisher.nachuan.cn/',
        bearerToken: 'unused',
        fetchImpl,
        legalApproved: true,
        freshAuditApproved: true,
        legalApprovalReceipt: 'unverified',
        freshAuditReceipt: 'unverified'
      })
    ).rejects.toThrow(CLOSED_GATE)
    expect(fetchImpl).not.toHaveBeenCalled()
  })

  it('keeps the CLI closed even when environment booleans claim approval', () => {
    const result = spawnSync(process.execPath, [publicEntry, 'lean'], {
      cwd: resolve(scriptRoot, '..'),
      encoding: 'utf8',
      windowsHide: true,
      env: {
        ...process.env,
        NACHUAN_RELEASE_LEGAL_APPROVED: 'true',
        NACHUAN_RELEASE_FRESH_AUDIT_APPROVED: 'true',
        NACHUAN_UPDATE_PUBLIC_BASE_URL: 'https://updates.nachuan.cn/',
        NACHUAN_UPDATE_WRITE_BASE_URL: 'https://publisher.nachuan.cn/',
        NACHUAN_UPDATE_PUBLISH_BEARER_TOKEN: 'unused'
      }
    })

    expect(result.status).toBe(1)
    expect(`${result.stdout}\n${result.stderr}`).toMatch(CLOSED_GATE)
  })
})

describe('internal early-access storage transaction boundary', () => {
  it('requires an explicitly injected fetch implementation', async () => {
    await expect(
      executeEarlyAccessStorageTransaction({
        variant: 'lean',
        releaseRoot: 'Z:\\missing-release',
        publicBaseUrl: 'http://127.0.0.1:31001/',
        writeBaseUrl: 'http://127.0.0.1:31002/'
      })
    ).rejects.toThrow(/explicit.*fetch|fetch.*inject/i)
  })

  it('rejects non-loopback origins before calling the injected fetch', async () => {
    const fetchImpl = vi.fn()
    await expect(
      executeEarlyAccessStorageTransaction({
        variant: 'lean',
        releaseRoot: 'Z:\\missing-release',
        publicBaseUrl: 'https://updates.nachuan.cn/',
        writeBaseUrl: 'https://publisher.nachuan.cn/',
        bearerToken: 'unused',
        fetchImpl
      })
    ).rejects.toThrow(/loopback/i)
    expect(fetchImpl).not.toHaveBeenCalled()
  })

  it('requires independent loopback public and write origins', async () => {
    const fetchImpl = vi.fn()
    await expect(
      executeEarlyAccessStorageTransaction({
        variant: 'lean',
        releaseRoot: 'Z:\\missing-release',
        publicBaseUrl: 'http://127.0.0.1:31001/',
        writeBaseUrl: 'http://127.0.0.1:31001/',
        fetchImpl
      })
    ).rejects.toThrow(/independent.*loopback|loopback.*independent/i)
    expect(fetchImpl).not.toHaveBeenCalled()
  })

  it('rejects a DNS hostname that merely starts with 127.', async () => {
    const fetchImpl = vi.fn()
    await expect(
      executeEarlyAccessStorageTransaction({
        variant: 'lean',
        releaseRoot: 'Z:\\missing-release',
        publicBaseUrl: 'http://127.evil.example:31001/',
        writeBaseUrl: 'http://127.evil.example:31002/',
        fetchImpl
      })
    ).rejects.toThrow(/loopback|credential-free HTTPS/i)
    expect(fetchImpl).not.toHaveBeenCalled()
  })

  it.each([
    ['127.0.0.1', '127.0.0.1'],
    ['short 127.1', '127.1'],
    ['integer 2130706433', '2130706433'],
    ['IPv6 ::1', '[::1]']
  ])('accepts a genuine loopback spelling through URL normalization: %s', async (_label, host) => {
    const fetchImpl = vi.fn()
    let failure
    try {
      await executeEarlyAccessStorageTransaction({
        variant: 'lean',
        releaseRoot: 'Z:\\missing-release',
        publicBaseUrl: `http://${host}:31001/`,
        writeBaseUrl: `http://${host}:31002/`,
        fetchImpl
      })
    } catch (error) {
      failure = error
    }
    expect(failure).toBeInstanceOf(Error)
    expect(failure.message).not.toMatch(/loopback/i)
    expect(fetchImpl).not.toHaveBeenCalled()
  })

  it('rejects localhost because name resolution is outside the numeric loopback boundary', async () => {
    const fetchImpl = vi.fn()
    await expect(
      executeEarlyAccessStorageTransaction({
        variant: 'lean',
        releaseRoot: 'Z:\\missing-release',
        publicBaseUrl: 'http://localhost:31001/',
        writeBaseUrl: 'http://localhost:31002/',
        fetchImpl
      })
    ).rejects.toThrow(/loopback|credential-free HTTPS/i)
    expect(fetchImpl).not.toHaveBeenCalled()
  })

  it('rejects IPv4-mapped IPv6 instead of widening the loopback policy', async () => {
    const fetchImpl = vi.fn()
    await expect(
      executeEarlyAccessStorageTransaction({
        variant: 'lean',
        releaseRoot: 'Z:\\missing-release',
        publicBaseUrl: 'http://[::ffff:127.0.0.1]:31001/',
        writeBaseUrl: 'http://[::ffff:127.0.0.1]:31002/',
        fetchImpl
      })
    ).rejects.toThrow(/loopback|credential-free HTTPS/i)
    expect(fetchImpl).not.toHaveBeenCalled()
  })
})
