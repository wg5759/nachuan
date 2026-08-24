import { createHash } from 'node:crypto'
import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'

import { afterEach, describe, expect, it } from 'vitest'

import {
  gitRuntimeCorePath,
  prepareGitRuntime,
  readGitRuntimeLock,
  runtimeTreeInventory,
  verifyPreparedGitRuntime
} from './git-runtime-policy.mjs'

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
})

const REQUIRED_PATHS = [
  'cmd/git.exe',
  'mingw64/bin/git.exe',
  'mingw64/bin/libiconv-2.dll',
  'mingw64/bin/libintl-8.dll',
  'mingw64/bin/libpcre2-8-0.dll',
  'mingw64/bin/libwinpthread-1.dll',
  'mingw64/bin/zlib1.dll',
  'mingw64/libexec/git-core/git.exe'
]

async function fixture() {
  const projectRoot = await realpath(await mkdtemp(join(tmpdir(), 'nachuan-git-runtime-')))
  workdirs.push(projectRoot)
  const sourceRoot = join(projectRoot, 'source-runtime')
  await mkdir(sourceRoot)
  for (const path of REQUIRED_PATHS) {
    const target = join(sourceRoot, ...path.split('/'))
    await mkdir(dirname(target), { recursive: true })
    await writeFile(target, `fixture:${path}\n`)
  }
  const inventory = await runtimeTreeInventory(sourceRoot)
  const archiveBytes = Buffer.from('official archive fixture')
  const requiredFiles = []
  for (const path of REQUIRED_PATHS) {
    const bytes = await readFile(join(sourceRoot, ...path.split('/')))
    requiredFiles.push({ path, sha256: sha256(bytes), size: bytes.length })
  }
  const lock = {
    arch: 'x64',
    archive: {
      contentType: 'application/executable',
      githubApiDigest: `sha256:${sha256(archiveBytes)}`,
      name: 'PortableGit-9.8.7.6-64-bit.7z.exe',
      publishedAt: '2026-07-02T13:38:39Z',
      releaseUrl: 'https://github.com/git-for-windows/git/releases/tag/v9.8.7.windows.6',
      sha256: sha256(archiveBytes),
      size: archiveBytes.length,
      url: 'https://github.com/git-for-windows/git/releases/download/v9.8.7.windows.6/PortableGit-9.8.7.6-64-bit.7z.exe'
    },
    authenticode: {
      issuer: 'CN=Fixture Issuer',
      notAfter: '2026-07-04T02:38:24.0000000Z',
      notBefore: '2026-07-01T02:38:24.0000000Z',
      serial: 'ABCDEF',
      status: 'Valid',
      subject: 'CN=Fixture Signer',
      thumbprint: 'A'.repeat(40),
      timestampSubject: 'CN=Fixture Timestamp',
      timestampThumbprint: 'B'.repeat(40)
    },
    builtins: ['cat-file', 'diff', 'hash-object', 'ls-tree', 'rev-parse', 'status', 'tag'],
    platform: 'win32',
    requiredFiles,
    runtime: {
      fileCount: inventory.fileCount,
      totalBytes: inventory.totalBytes,
      treeSha256: inventory.treeSha256
    },
    schema: 1,
    version: '9.8.7.windows.6'
  }
  const lockPath = join(projectRoot, 'git-runtime-lock.json')
  await writeFile(lockPath, canonicalJson(lock))
  const downloadCalls = []
  const download = async (request) => {
    downloadCalls.push(request)
    await writeFile(request.destination, archiveBytes, { flag: 'wx' })
  }
  const extractArchive = async (_archive, destination) => {
    for (const path of REQUIRED_PATHS) {
      const source = join(sourceRoot, ...path.split('/'))
      const target = join(destination, ...path.split('/'))
      await mkdir(dirname(target), { recursive: true })
      await writeFile(target, await readFile(source), { flag: 'wx' })
    }
  }
  const verifyAuthenticode = async () => structuredClone(lock.authenticode)
  const probeRuntime = async ({ corePath, execPath, builtins }) => ({
    corePath,
    execPath,
    version: lock.version,
    builtins
  })
  return {
    projectRoot,
    lock,
    lockPath,
    download,
    downloadCalls,
    extractArchive,
    verifyAuthenticode,
    probeRuntime
  }
}

describe('official project-local PortableGit runtime policy', () => {
  it('accepts the canonical production lock and fixes the release core path', () => {
    const projectRoot = join(process.cwd(), '..')
    const lock = readGitRuntimeLock({ projectRoot })
    expect(lock.version).toBe('2.55.0.windows.2')
    expect(lock.archive.sha256).toBe('b20d42da3afa228e9fa6174480de820282667e799440d655e308f700dfa0d0df')
    expect(lock.runtime.fileCount).toBe(9565)
    expect(lock.requiredFiles).toHaveLength(8)
    expect(gitRuntimeCorePath(projectRoot)).toBe(join(projectRoot, 'build', 'git-runtime', 'mingw64', 'bin', 'git.exe'))
  })

  it('prepares from an empty cache/runtime, writes a closed-tree provenance, and re-verifies offline', async () => {
    const paths = await fixture()
    const prepared = await prepareGitRuntime(paths)
    expect(paths.downloadCalls).toHaveLength(1)
    expect(prepared.corePath).toBe(gitRuntimeCorePath(paths.projectRoot))
    expect(prepared.provenance.files).toHaveLength(REQUIRED_PATHS.length)
    const verified = await verifyPreparedGitRuntime(paths)
    expect(verified.provenance).toEqual(prepared.provenance)
    expect(paths.downloadCalls).toHaveLength(1)
  })

  it('rejects archive substitution and any later runtime byte or file-set drift', async () => {
    const paths = await fixture()
    await prepareGitRuntime(paths)
    const archivePath = join(paths.projectRoot, 'build', 'git-cache', paths.lock.archive.name)
    await writeFile(archivePath, 'wrong archive')
    await expect(verifyPreparedGitRuntime(paths)).rejects.toThrow(/archive (?:size|hash) drifted/i)

    await writeFile(archivePath, 'official archive fixture')
    const dll = join(paths.projectRoot, 'build', 'git-runtime', 'mingw64', 'bin', 'zlib1.dll')
    await writeFile(dll, 'tampered runtime')
    await expect(verifyPreparedGitRuntime(paths)).rejects.toThrow(/runtime tree drifted/i)

    await writeFile(dll, 'fixture:mingw64/bin/zlib1.dll\n')
    await writeFile(join(paths.projectRoot, 'build', 'git-runtime', 'mingw64', 'bin', 'evil.dll'), 'evil')
    await expect(verifyPreparedGitRuntime(paths)).rejects.toThrow(/runtime tree drifted/i)
  })

  it('fails before extraction when the embedded Authenticode identity does not match the lock', async () => {
    const paths = await fixture()
    await expect(
      prepareGitRuntime({
        ...paths,
        verifyAuthenticode: async () => ({ ...paths.lock.authenticode, thumbprint: 'C'.repeat(40) })
      })
    ).rejects.toThrow(/Authenticode identity drifted/i)
    await expect(readFile(join(paths.projectRoot, 'build', 'git-runtime', 'mingw64', 'bin', 'git.exe'))).rejects.toThrow()
  })
})
