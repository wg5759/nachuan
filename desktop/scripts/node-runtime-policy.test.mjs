import { createHash } from 'node:crypto'
import { mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, describe, expect, it } from 'vitest'

import {
  nodeRuntimePath,
  prepareNodeRuntime,
  readNodeRuntimeLock,
  renameTransientLockRetry,
  verifyPreparedNodeRuntime
} from './node-runtime-policy.mjs'

const workdirs = []
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex')
const canonicalValue = (value) =>
  Array.isArray(value)
    ? value.map(canonicalValue)
    : value && typeof value === 'object'
      ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalValue(value[key])]))
      : value
const canonicalJson = (value) => `${JSON.stringify(canonicalValue(value), null, 2)}\n`

afterEach(async () => {
  await Promise.all(workdirs.splice(0).map((path) => rm(path, { recursive: true, force: true })))
}, 60_000)

async function fixture() {
  const projectRoot = await realpath(await mkdtemp(join(tmpdir(), 'nachuan-node-runtime-')))
  workdirs.push(projectRoot)
  const binaryBytes = Buffer.from('official node fixture')
  const digest = sha256(binaryBytes)
  const lock = {
    arch: 'x64',
    authenticode: {
      issuer: 'CN=Fixture Issuer',
      notAfter: '2026-02-26T22:18:42.0000000Z',
      notBefore: '2026-02-23T22:18:42.0000000Z',
      serial: 'ABCDEF',
      status: 'Valid',
      subject: 'CN=Fixture Signer',
      thumbprint: 'A'.repeat(40),
      timestampSubject: 'CN=Fixture Timestamp',
      timestampThumbprint: 'B'.repeat(40)
    },
    binary: {
      name: 'node.exe',
      sha256: digest,
      size: binaryBytes.length,
      sourceUrl: 'https://nodejs.org/dist/v24.14.0/win-x64/node.exe'
    },
    officialShasums: {
      line: `${digest}  win-x64/node.exe`,
      url: 'https://nodejs.org/dist/v24.14.0/SHASUMS256.txt'
    },
    platform: 'win32',
    schema: 1,
    version: '24.14.0'
  }
  const lockPath = join(projectRoot, 'node-runtime-lock.json')
  await writeFile(lockPath, canonicalJson(lock))
  const downloadCalls = []
  const downloadBinary = async (request) => {
    downloadCalls.push(request)
    await writeFile(request.destination, binaryBytes, { flag: 'wx' })
  }
  const downloadText = async ({ url }) => {
    expect(url).toBe(lock.officialShasums.url)
    return `${lock.officialShasums.line}\n`
  }
  const verifyAuthenticode = async () => structuredClone(lock.authenticode)
  const probeRuntime = async ({ execPath }) => ({ execPath, version: lock.version })
  return {
    projectRoot,
    lock,
    lockPath,
    binaryBytes,
    downloadBinary,
    downloadCalls,
    downloadText,
    verifyAuthenticode,
    probeRuntime
  }
}

describe('official project-local Node runtime policy', () => {
  it('accepts the canonical production lock and fixes the runtime path', () => {
    const projectRoot = join(process.cwd(), '..')
    const lock = readNodeRuntimeLock({ projectRoot })
    expect(lock.version).toBe('24.14.0')
    expect(lock.binary.sha256).toBe('63c259c81e5d472b5f11c8d506070130cb04a1ecf84b80377a34ed6ec9048088')
    expect(lock.binary.size).toBe(91380224)
    expect(nodeRuntimePath(projectRoot)).toBe(join(projectRoot, 'build', 'node-runtime', 'node.exe'))
  })

  it('routes local release evidence through the prepared pinned Node', async () => {
    const packageDocument = JSON.parse(await readFile(join(process.cwd(), 'package.json'), 'utf8'))
    expect(packageDocument.scripts['prepare:node-runtime']).toBe('node scripts/node-runtime-policy.mjs prepare')
    expect(packageDocument.scripts['verify:node-runtime']).toBe('node scripts/node-runtime-policy.mjs verify')
    expect(packageDocument.scripts['evidence:generate']).toContain(
      'node scripts/node-runtime-policy.mjs run scripts/release-evidence.mjs generate'
    )
    expect(packageDocument.scripts['evidence:verify']).toContain(
      'node scripts/node-runtime-policy.mjs run scripts/release-evidence.mjs verify'
    )
  })

  it('prepares once, records canonical provenance, and verifies offline', async () => {
    const paths = await fixture()
    const prepared = await prepareNodeRuntime(paths)
    expect(paths.downloadCalls).toHaveLength(1)
    expect(prepared.execPath).toBe(nodeRuntimePath(paths.projectRoot))
    expect(await readFile(prepared.execPath)).toEqual(paths.binaryBytes)
    const verified = await verifyPreparedNodeRuntime(paths)
    expect(verified.provenance).toEqual(prepared.provenance)
    expect(paths.downloadCalls).toHaveLength(1)
  })

  it('rejects binary substitution and Authenticode identity drift', async () => {
    const paths = await fixture()
    await prepareNodeRuntime(paths)
    await writeFile(nodeRuntimePath(paths.projectRoot), 'tampered node')
    await expect(verifyPreparedNodeRuntime(paths)).rejects.toThrow(/Node runtime (?:size|hash) drifted/i)

    const second = await fixture()
    await expect(
      prepareNodeRuntime({
        ...second,
        verifyAuthenticode: async () => ({ ...second.lock.authenticode, thumbprint: 'C'.repeat(40) })
      })
    ).rejects.toThrow(/Authenticode identity drifted/i)
  })

  it('retries only lock-class rename failures with a bounded attempt count', async () => {
    const eperm = () => Object.assign(new Error('operation not permitted'), { code: 'EPERM' })
    let calls = 0
    await renameTransientLockRetry('a', 'b', {
      renameImpl: async () => {
        calls += 1
        if (calls < 3) throw eperm()
      },
      sleepImpl: async () => {}
    })
    expect(calls).toBe(3)

    const enoent = Object.assign(new Error('no such file or directory'), { code: 'ENOENT' })
    let nonLockCalls = 0
    await expect(
      renameTransientLockRetry('a', 'b', {
        renameImpl: async () => {
          nonLockCalls += 1
          throw enoent
        },
        sleepImpl: async () => {}
      })
    ).rejects.toBe(enoent)
    expect(nonLockCalls).toBe(1)

    let exhaustedCalls = 0
    await expect(
      renameTransientLockRetry('a', 'b', {
        attempts: 3,
        renameImpl: async () => {
          exhaustedCalls += 1
          throw eperm()
        },
        sleepImpl: async () => {}
      })
    ).rejects.toThrow(/operation not permitted/i)
    expect(exhaustedCalls).toBe(3)
  })

  it('keeps the default Windows transient-lock window beyond the former five attempts', async () => {
    let calls = 0
    await renameTransientLockRetry('a', 'b', {
      renameImpl: async () => {
        calls += 1
        if (calls <= 8) {
          throw Object.assign(new Error('scanner still owns the freshly written runtime'), { code: 'EPERM' })
        }
      },
      sleepImpl: async () => {}
    })
    expect(calls).toBe(9)
  })

  it('rejects unknown fields and any official source URL drift', async () => {
    const paths = await fixture()
    await writeFile(paths.lockPath, canonicalJson({ ...paths.lock, extra: true }))
    expect(() => readNodeRuntimeLock(paths)).toThrow(/fields are not canonical/i)

    await writeFile(
      paths.lockPath,
      canonicalJson({
        ...paths.lock,
        binary: { ...paths.lock.binary, sourceUrl: 'https://example.invalid/node.exe' }
      })
    )
    expect(() => readNodeRuntimeLock(paths)).toThrow(/exact official Node\.js release asset/i)
  })
})
