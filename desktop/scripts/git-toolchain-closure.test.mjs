import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

import { afterEach, describe, expect, it } from 'vitest'

import {
  captureGitToolchainClosure
} from './git-toolchain-closure.mjs'

const workdirs = []

afterEach(async () => {
  await Promise.all(workdirs.splice(0).map((path) => rm(path, { recursive: true, force: true })))
})

async function fixture() {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'nachuan-git-toolchain-')))
  workdirs.push(root)
  const gitRoot = join(root, 'Git')
  const launcherPath = join(gitRoot, 'cmd', 'git.exe')
  const runtimeBin = join(gitRoot, 'mingw64', 'bin')
  const gitPath = join(runtimeBin, 'git.exe')
  const execPath = join(gitRoot, 'mingw64', 'libexec', 'git-core')
  await mkdir(join(gitRoot, 'cmd'), { recursive: true })
  await mkdir(runtimeBin, { recursive: true })
  await mkdir(execPath, { recursive: true })
  await writeFile(launcherPath, 'launcher')
  await writeFile(gitPath, 'runtime')
  for (const name of ['libiconv-2.dll', 'libintl-8.dll', 'libpcre2-8-0.dll', 'libwinpthread-1.dll', 'zlib1.dll']) {
    await writeFile(join(runtimeBin, name), `runtime dll:${name}`)
  }
  await writeFile(join(runtimeBin, 'unrelated.txt'), 'not execution closure')
  await writeFile(join(execPath, 'git.exe'), 'core')
  await writeFile(join(execPath, 'git-rev-parse.exe'), 'unneeded helper')
  await writeFile(join(execPath, 'README'), 'not execution closure')

  const requiredPaths = [
    'cmd/git.exe',
    'mingw64/bin/git.exe',
    'mingw64/bin/libiconv-2.dll',
    'mingw64/bin/libintl-8.dll',
    'mingw64/bin/libpcre2-8-0.dll',
    'mingw64/bin/libwinpthread-1.dll',
    'mingw64/bin/zlib1.dll',
    'mingw64/libexec/git-core/git.exe'
  ]
  const requiredFiles = []
  for (const path of requiredPaths) {
    const bytes = await readFile(join(gitRoot, ...path.split('/')))
    requiredFiles.push({ path, sha256: createHash('sha256').update(bytes).digest('hex'), size: bytes.length })
  }
  const lock = {
    version: '2.55.0.windows.2',
    builtins: ['cat-file', 'diff', 'hash-object', 'ls-tree', 'rev-parse', 'status', 'tag'],
    requiredFiles,
    archive: { sha256: 'a'.repeat(64) },
    runtime: { treeSha256: 'b'.repeat(64) }
  }
  const runtimeVerifier = async () => ({
    corePath: resolve(gitPath),
    lock,
    provenance: { lock: { sha256: 'c'.repeat(64) } },
    runtimeRoot: resolve(gitRoot)
  })

  const calls = []
  const executeGit = async (request) => {
    calls.push(request)
    const probe = request.args.at(-1)
    if (probe === '--exec-path') {
      return { exitCode: 0, signal: null, stdout: Buffer.from(`${execPath}\n`), stderr: Buffer.alloc(0) }
    }
    if (probe === '--version') {
      return {
        exitCode: 0,
        signal: null,
        stdout: Buffer.from('git version 2.55.0.windows.2\n'),
        stderr: Buffer.alloc(0)
      }
    }
    if (probe === '--list-cmds=builtins') {
      return {
        exitCode: 0,
        signal: null,
        stdout: Buffer.from(`${lock.builtins.join('\n')}\n`),
        stderr: Buffer.alloc(0)
      }
    }
    throw new Error(`unexpected Git probe ${request.args.join(' ')}`)
  }
  return {
    root,
    gitPath: resolve(gitPath),
    runtimeBin,
    execPath: resolve(execPath),
    calls,
    executeGit,
    runtimeVerifier
  }
}

describe('Git for Windows release toolchain closure', () => {
  it('binds the fixed core, five loaded DLLs and exec-path sentinel under an isolated environment', async () => {
    const paths = await fixture()
    const closure = await captureGitToolchainClosure({
      gitPath: paths.gitPath,
      repoRoot: paths.root,
      executeGit: paths.executeGit,
      runtimeVerifier: paths.runtimeVerifier
    })

    expect(closure.schema).toBe('nachuan.git-toolchain-closure/v1')
    expect(closure.version).toBe('2.55.0.windows.2')
    expect(closure.execPath.toLowerCase()).toBe(paths.execPath.toLowerCase())
    const names = closure.files.map(({ path }) => path.toLowerCase())
    expect(names).toContain(paths.gitPath.toLowerCase())
    expect(names).toContain(join(paths.runtimeBin, 'libiconv-2.dll').toLowerCase())
    expect(names).toContain(join(paths.execPath, 'git.exe').toLowerCase())
    expect(names).not.toContain(join(paths.execPath, 'git-rev-parse.exe').toLowerCase())
    expect(names).not.toContain(join(paths.runtimeBin, 'unrelated.txt').toLowerCase())
    expect(names).not.toContain(join(paths.execPath, 'README').toLowerCase())
    expect(paths.calls).toHaveLength(3)
    for (const request of paths.calls) {
      expect(request.executable.toLowerCase()).toBe(paths.gitPath.toLowerCase())
      expect(request.shell).toBe(false)
      expect(request.env.PATH).toBeUndefined()
      expect(request.args[0]).toBe('--no-pager')
      if (request.args.at(-1) === '--exec-path') expect(request.env.GIT_EXEC_PATH).toBeUndefined()
      else expect(request.env.GIT_EXEC_PATH.toLowerCase()).toBe(paths.execPath.toLowerCase())
      expect(request.env.GIT_CONFIG_NOSYSTEM).toBe('1')
      expect(request.env.GIT_CONFIG_GLOBAL).toBe(process.platform === 'win32' ? 'NUL' : '/dev/null')
    }
  })

  it('fails closed when an adjacent DLL changes during a Git probe', async () => {
    const paths = await fixture()
    let calls = 0
    const executeGit = async (request) => {
      calls += 1
      if (calls === 1) await writeFile(join(paths.runtimeBin, 'libiconv-2.dll'), 'replaced runtime dll')
      return paths.executeGit(request)
    }
    await expect(
      captureGitToolchainClosure({
        gitPath: paths.gitPath,
        repoRoot: paths.root,
        executeGit,
        runtimeVerifier: paths.runtimeVerifier
      })
    ).rejects.toThrow(/Git toolchain closure changed during version\/exec-path probes/i)
  })

  it('rejects any later locked execution-file replacement', async () => {
    const paths = await fixture()
    await captureGitToolchainClosure({
      gitPath: paths.gitPath,
      repoRoot: paths.root,
      executeGit: paths.executeGit,
      runtimeVerifier: paths.runtimeVerifier
    })
    await writeFile(join(paths.runtimeBin, 'libiconv-2.dll'), 'same-size!!')
    await expect(
      captureGitToolchainClosure({
        gitPath: paths.gitPath,
        repoRoot: paths.root,
        executeGit: paths.executeGit,
        runtimeVerifier: paths.runtimeVerifier
      })
    ).rejects.toThrow(/locked Git execution file (?:size|hash) drifted/i)
  })
})
