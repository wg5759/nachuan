import { createHash } from 'node:crypto'
import { mkdir, mkdtemp, readFile, realpath, rename, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, describe, expect, it } from 'vitest'

import {
  assertReleaseSourceFreezePortableEquivalent,
  assertReleaseSourceFreezeUnchanged,
  assertGeneratedReleaseSourceUnchanged,
  captureGeneratedReleaseSource,
  captureReleaseSourceFreeze,
  readReleaseSourceFreeze,
  restoreGeneratedReleaseSource,
  verifyFrozenReleaseSource,
  writeReleaseSourceFreeze
} from './release-source-freeze.mjs'

const workdirs = []
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex')

afterEach(async () => {
  await Promise.all(workdirs.splice(0).map((path) => rm(path, { recursive: true, force: true })))
})

function identity(seed = '1', size = 4) {
  return {
    device: seed,
    inode: seed,
    mode: '100644',
    links: '1',
    size: String(size),
    modifiedNs: seed,
    changedNs: seed,
    bornNs: seed
  }
}

function gitClosure({ sha = 'b'.repeat(64), extraFile = false } = {}) {
  const gitPath = 'C:\\Program Files\\Git\\cmd\\git.exe'
  const files = [
    {
      path: gitPath,
      relativePath: 'mingw64/bin/git.exe',
      roles: ['launcher-adjacent', 'selected-git-executable'],
      sha256: sha,
      size: 4,
      identity: identity('1')
    }
  ]
  if (extraFile) {
    files.push({
      path: 'C:\\Program Files\\Git\\mingw64\\bin\\evil.dll',
      relativePath: 'mingw64/bin/evil.dll',
      roles: ['runtime-bin'],
      sha256: 'e'.repeat(64),
      size: 4,
      identity: identity('2')
    })
  }
  return {
    schema: 'nachuan.git-toolchain-closure/v1',
    version: '2.52.0.windows.1',
    gitPath,
    runtimeRoot: 'C:\\Program Files\\Git',
    installRoot: 'C:\\Program Files\\Git',
    architectureRoot: 'C:\\Program Files\\Git\\mingw64',
    runtimeBin: 'C:\\Program Files\\Git\\mingw64\\bin',
    execPath: 'C:\\Program Files\\Git\\mingw64\\libexec\\git-core',
    archiveSha256: 'c'.repeat(64),
    runtimeTreeSha256: 'd'.repeat(64),
    lockSha256: 'e'.repeat(64),
    directories: [],
    files,
    totalBytes: files.reduce((total, file) => total + file.size, 0)
  }
}

function sourceSnapshot({ sha = 'b'.repeat(64) } = {}) {
  const gitPath = 'C:\\Program Files\\Git\\cmd\\git.exe'
  return {
    schema: 'nachuan.release-source-snapshot/v1',
    git: {
      objectFormat: 'sha1',
      expectedCommit: 'a'.repeat(40),
      expectedTag: 'v0.2.0',
      expectedTree: 'c'.repeat(40),
      headCommit: 'a'.repeat(40),
      headTree: 'c'.repeat(40),
      tagCommit: 'a'.repeat(40),
      tagObject: 'd'.repeat(40)
    },
    toolchain: {
      git: { path: gitPath, sha256: sha, size: 4, identity: identity('1') }
    },
    scope: {
      files: ['pyproject.toml'],
      optionalFiles: [],
      directories: ['desktop'],
      optionalDirectories: [],
      excludedPaths: ['desktop/node_modules']
    },
    directories: [],
    files: [],
    totalBytes: 0
  }
}

function generatedSource() {
  const engine = Buffer.from('eng\n')
  const trust = Buffer.from('upd\n')
  return {
    schema: 'nachuan.generated-release-source/v2',
    files: [
      {
        path: 'desktop/src/main/generated-engine-integrity.ts',
        contentBase64: engine.toString('base64'),
        sha256: sha256(engine),
        size: engine.length,
        identity: identity('3', engine.length)
      },
      {
        path: 'desktop/src/main/generated-update-trust.ts',
        contentBase64: trust.toString('base64'),
        sha256: sha256(trust),
        size: trust.length,
        identity: identity('4', trust.length)
      }
    ]
  }
}

async function temporaryOutput() {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'nachuan-source-freeze-')))
  workdirs.push(root)
  return join(root, 'freeze.json')
}

describe('pre-build release source freeze', () => {
  it('binds fixed generated source bytes and detects an identity-changing same-byte rewrite', async () => {
    const root = await realpath(await mkdtemp(join(tmpdir(), 'nachuan-generated-freeze-')))
    workdirs.push(root)
    const generatedRoot = join(root, 'desktop', 'src', 'main')
    await mkdir(generatedRoot, { recursive: true })
    const engine = join(generatedRoot, 'generated-engine-integrity.ts')
    const trust = join(generatedRoot, 'generated-update-trust.ts')
    await writeFile(engine, "export const ENGINE = 'bound'\n")
    await writeFile(trust, "export const TRUST = 'bound'\n")

    const before = await captureGeneratedReleaseSource({ projectRoot: root })
    expect(before.files.map(({ path }) => path)).toEqual([
      'desktop/src/main/generated-engine-integrity.ts',
      'desktop/src/main/generated-update-trust.ts'
    ])
    const original = await readFile(engine)
    await rename(engine, `${engine}.before-freeze`)
    await writeFile(engine, original)
    const after = await captureGeneratedReleaseSource({ projectRoot: root })

    expect(after.files[0]).toMatchObject({ sha256: before.files[0].sha256, size: before.files[0].size })
    expect(after.files[0].contentBase64).toBe(original.toString('base64'))
    expect(() => assertGeneratedReleaseSourceUnchanged(before, after)).toThrow(/identity changed/i)
  })

  it('binds the complete source snapshot to the same Git executable closure before and after capture', async () => {
    const calls = []
    const closure = gitClosure()
    const source = sourceSnapshot()
    const generated = generatedSource()
    const frozen = await captureReleaseSourceFreeze({
      projectRoot: 'C:\\repo',
      gitPath: closure.gitPath,
      releaseTag: 'v0.2.0',
      releaseCommit: 'a'.repeat(40),
      releaseTree: 'c'.repeat(40),
      captureGitClosure: async () => {
        calls.push('git')
        return structuredClone(closure)
      },
      captureGeneratedSource: async () => {
        calls.push('generated')
        return structuredClone(generated)
      },
      captureSourceSnapshot: async () => {
        calls.push('source')
        return structuredClone(source)
      }
    })
    expect(calls).toEqual(['git', 'generated', 'source', 'generated', 'git'])
    expect(frozen.schema).toBe('nachuan.release-source-freeze/v2')
    expect(frozen.sourceSnapshot).toEqual(source)
    expect(frozen.generatedSource).toEqual(generated)
    expect(frozen.gitToolchain).toEqual(closure)
  })

  it('fails closed on a Git helper addition during source hashing', async () => {
    let call = 0
    await expect(
      captureReleaseSourceFreeze({
        projectRoot: 'C:\\repo',
        gitPath: gitClosure().gitPath,
        releaseTag: 'v0.2.0',
        releaseCommit: 'a'.repeat(40),
        releaseTree: 'c'.repeat(40),
        captureGitClosure: async () => gitClosure({ extraFile: call++ > 0 }),
        captureGeneratedSource: async () => generatedSource(),
        captureSourceSnapshot: async () => sourceSnapshot()
      })
    ).rejects.toThrow(/Git toolchain file set changed/i)
  })

  it('writes canonical create-once bytes and requires their out-of-band digest on every read', async () => {
    const output = await temporaryOutput()
    const frozen = {
      schema: 'nachuan.release-source-freeze/v2',
      generatedSource: generatedSource(),
      sourceSnapshot: sourceSnapshot(),
      gitToolchain: gitClosure()
    }
    const written = await writeReleaseSourceFreeze({ output, frozen })
    const bytes = await readFile(output)
    expect(written.sha256).toBe(sha256(bytes))
    await expect(readReleaseSourceFreeze({ input: output, expectedSha256: written.sha256 })).resolves.toEqual(frozen)
    await writeFile(output, Buffer.concat([bytes, Buffer.from(' ')]))
    await expect(readReleaseSourceFreeze({ input: output, expectedSha256: written.sha256 })).rejects.toThrow(
      /digest does not match the pre-build freeze/i
    )
  })

  it('restores exact producer generated bytes from an authenticated portable freeze, never local templates', async () => {
    const root = await realpath(await mkdtemp(join(tmpdir(), 'nachuan-generated-restore-')))
    workdirs.push(root)
    const generatedRoot = join(root, 'desktop', 'src', 'main')
    await mkdir(generatedRoot, { recursive: true })
    const enginePath = join(generatedRoot, 'generated-engine-integrity.ts')
    const trustPath = join(generatedRoot, 'generated-update-trust.ts')
    await writeFile(enginePath, 'tracked engine template\n')
    await writeFile(trustPath, 'tracked trust template\n')
    const output = join(root, 'producer-freeze.json')
    const frozen = {
      schema: 'nachuan.release-source-freeze/v2',
      generatedSource: generatedSource(),
      gitToolchain: gitClosure(),
      sourceSnapshot: sourceSnapshot()
    }
    const written = await writeReleaseSourceFreeze({ output, frozen })

    await restoreGeneratedReleaseSource({
      input: output,
      expectedSha256: written.sha256,
      projectRoot: root
    })

    expect(await readFile(enginePath)).toEqual(Buffer.from('eng\n'))
    expect(await readFile(trustPath)).toEqual(Buffer.from('upd\n'))
    const restored = await captureGeneratedReleaseSource({ projectRoot: root })
    expect(() => assertReleaseSourceFreezePortableEquivalent(
      frozen,
      { ...frozen, generatedSource: restored }
    )).not.toThrow()
  })

  it('rejects nested generated-source v1 instead of accepting evidence without producer bytes', async () => {
    const output = await temporaryOutput()
    const frozen = {
      schema: 'nachuan.release-source-freeze/v2',
      generatedSource: { ...generatedSource(), schema: 'nachuan.generated-release-source/v1' },
      gitToolchain: gitClosure(),
      sourceSnapshot: sourceSnapshot()
    }

    await expect(writeReleaseSourceFreeze({ output, frozen })).rejects.toThrow(/generated.*schema/i)
  })

  it('rejects a top-level source-freeze v1 downgrade instead of treating it as v2', async () => {
    const output = await temporaryOutput()
    const frozen = {
      schema: 'nachuan.release-source-freeze/v1',
      generatedSource: generatedSource(),
      gitToolchain: gitClosure(),
      sourceSnapshot: sourceSnapshot()
    }

    await expect(writeReleaseSourceFreeze({ output, frozen })).rejects.toThrow(/freeze.*schema/i)
  })

  it('compares a later capture to the immutable pre-build document', async () => {
    const frozen = {
      schema: 'nachuan.release-source-freeze/v2',
      generatedSource: generatedSource(),
      sourceSnapshot: sourceSnapshot(),
      gitToolchain: gitClosure()
    }
    await expect(
      verifyFrozenReleaseSource({ frozen, captureCurrent: async () => structuredClone(frozen) })
    ).resolves.toEqual(frozen)
    const drifted = structuredClone(frozen)
    drifted.sourceSnapshot.files.push({ path: 'desktop/injected.js' })
    await expect(
      verifyFrozenReleaseSource({ frozen, captureCurrent: async () => drifted })
    ).rejects.toThrow(/release source snapshot file set changed/i)
    expect(() => assertReleaseSourceFreezeUnchanged(frozen, frozen)).not.toThrow()
  })

  it('allows only filesystem identity/path relocation in a cross-runner portable comparison', () => {
    const frozen = {
      schema: 'nachuan.release-source-freeze/v2',
      generatedSource: generatedSource(),
      sourceSnapshot: sourceSnapshot(),
      gitToolchain: gitClosure()
    }
    const relocated = structuredClone(frozen)
    const relocatedGit = 'D:\\a\\nachuan\\build\\git-runtime\\mingw64\\bin\\git.exe'
    relocated.gitToolchain.gitPath = relocatedGit
    relocated.gitToolchain.runtimeRoot = 'D:\\a\\nachuan\\build\\git-runtime'
    relocated.gitToolchain.runtimeBin = 'D:\\a\\nachuan\\build\\git-runtime\\mingw64\\bin'
    relocated.gitToolchain.execPath = 'D:\\a\\nachuan\\build\\git-runtime\\mingw64\\libexec\\git-core'
    relocated.gitToolchain.files[0].path = relocatedGit
    relocated.gitToolchain.files[0].identity = identity('9')
    relocated.sourceSnapshot.toolchain.git.path = relocatedGit
    relocated.sourceSnapshot.toolchain.git.identity = identity('9')
    relocated.generatedSource.files[0].identity = identity('8')
    relocated.generatedSource.files[1].identity = identity('9')

    expect(() => assertReleaseSourceFreezePortableEquivalent(frozen, relocated)).not.toThrow()
    expect(() => assertReleaseSourceFreezeUnchanged(frozen, relocated)).toThrow()
    relocated.gitToolchain.archiveSha256 = 'f'.repeat(64)
    expect(() => assertReleaseSourceFreezePortableEquivalent(frozen, relocated)).toThrow(
      /portable release source or Git toolchain evidence changed/i
    )
  })
})
