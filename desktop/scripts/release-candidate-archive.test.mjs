import { createHash } from 'node:crypto'
import { link, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { basename, join } from 'node:path'

import { afterEach, describe, expect, it } from 'vitest'

import {
  canonicalCandidateManifestBytes,
  createReleaseCandidateArchive,
  maximumReleaseCandidateArchiveBytes,
  verifyReleaseCandidateArchive
} from './release-candidate-archive.mjs'

const workdirs = []
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex')

const IDENTITY = Object.freeze({
  releaseTag: 'v0.2.0',
  releaseCommit: 'a'.repeat(40),
  releaseTree: 'b'.repeat(40),
  repository: 'wg5759/nachuan',
  workflowRef:
    'wg5759/nachuan/.github/workflows/release.yml@refs/tags/v0.2.0',
  workflowSha: 'c'.repeat(40),
  runId: '123456789',
  runAttempt: '2',
  job: 'build',
  variant: 'lean',
  version: '0.2.0'
})

afterEach(async () => {
  await Promise.all(workdirs.splice(0).map((path) => rm(path, { recursive: true, force: true })))
})

async function releaseFixture(label) {
  const root = await mkdtemp(join(tmpdir(), `nachuan-candidate-${label}-`))
  workdirs.push(root)
  const releaseRoot = join(root, 'release')
  await mkdir(join(releaseRoot, 'win-unpacked', 'resources'), { recursive: true })
  await writeFile(join(releaseRoot, 'nachuan-0.2.0-lean-win.exe'), 'installer-bytes')
  await writeFile(join(releaseRoot, 'win-unpacked', '纳川.exe'), 'desktop-bytes')
  await writeFile(
    join(releaseRoot, 'win-unpacked', 'resources', 'engine.exe'),
    'engine-bytes'
  )
  return { root, releaseRoot }
}

describe('content-addressed immutable release candidate archive', () => {
  it('creates deterministic USTAR bytes and binds their independent digest in the candidate manifest', async () => {
    const first = await releaseFixture('first')
    const second = await releaseFixture('second')
    const firstResult = await createReleaseCandidateArchive({
      releaseRoot: first.releaseRoot,
      outputDirectory: join(first.root, 'candidate'),
      identity: IDENTITY
    })
    const secondResult = await createReleaseCandidateArchive({
      releaseRoot: second.releaseRoot,
      outputDirectory: join(second.root, 'candidate'),
      identity: IDENTITY
    })

    const firstArchive = await readFile(firstResult.archivePath)
    const secondArchive = await readFile(secondResult.archivePath)
    const manifest = JSON.parse(await readFile(firstResult.manifestPath, 'utf8'))
    const independentDigest = sha256(firstArchive)

    expect(firstArchive.equals(secondArchive)).toBe(true)
    expect(independentDigest).toBe(sha256(secondArchive))
    expect(basename(firstResult.archivePath)).toBe(
      `nachuan-0.2.0-lean-${independentDigest}.tar`
    )
    expect(manifest).toMatchObject({
      schema: 'nachuan.release-candidate/v1',
      identity: IDENTITY,
      archive: {
        format: 'ustar',
        name: basename(firstResult.archivePath),
        sha256: independentDigest,
        size: firstArchive.length
      }
    })
    expect(manifest.targets.map((target) => target.path)).toEqual([
      'nachuan-0.2.0-lean-win.exe',
      'win-unpacked/resources/engine.exe',
      'win-unpacked/纳川.exe'
    ])

    await expect(
      verifyReleaseCandidateArchive({
        archivePath: firstResult.archivePath,
        manifestPath: firstResult.manifestPath,
        identity: IDENTITY
      })
    ).resolves.toMatchObject({ archiveSha256: independentDigest, targetCount: 3 })
  })

  it('rejects hard-linked input aliases that could mutate candidate bytes outside the release path', async () => {
    const { root, releaseRoot } = await releaseFixture('hardlink')
    await link(
      join(releaseRoot, 'nachuan-0.2.0-lean-win.exe'),
      join(releaseRoot, 'installer-alias.exe')
    )

    await expect(
      createReleaseCandidateArchive({
        releaseRoot,
        outputDirectory: join(root, 'candidate'),
        identity: IDENTITY
      })
    ).rejects.toThrow(/hard-linked/i)
  })

  it('rejects non-NFC paths before producing a cross-platform scanner archive', async () => {
    const { root, releaseRoot } = await releaseFixture('unicode')
    await writeFile(join(releaseRoot, 'e\u0301vidence.txt'), 'ambiguous-name')

    await expect(
      createReleaseCandidateArchive({
        releaseRoot,
        outputDirectory: join(root, 'candidate'),
        identity: IDENTITY
      })
    ).rejects.toThrow(/NFC-normalized/i)
  })

  it('rejects archive byte replacement and manifest provenance replacement', async () => {
    const { root, releaseRoot } = await releaseFixture('tamper')
    const result = await createReleaseCandidateArchive({
      releaseRoot,
      outputDirectory: join(root, 'candidate'),
      identity: IDENTITY
    })

    await writeFile(result.archivePath, 'different-archive-bytes')
    await expect(
      verifyReleaseCandidateArchive({
        archivePath: result.archivePath,
        manifestPath: result.manifestPath,
        identity: IDENTITY
      })
    ).rejects.toThrow()

    const second = await releaseFixture('manifest-tamper')
    const secondResult = await createReleaseCandidateArchive({
      releaseRoot: second.releaseRoot,
      outputDirectory: join(second.root, 'candidate'),
      identity: IDENTITY
    })
    const manifest = JSON.parse(await readFile(secondResult.manifestPath, 'utf8'))
    manifest.identity.runAttempt = '3'
    await writeFile(secondResult.manifestPath, canonicalCandidateManifestBytes(manifest))
    await expect(
      verifyReleaseCandidateArchive({
        archivePath: secondResult.archivePath,
        manifestPath: secondResult.manifestPath,
        identity: IDENTITY
      })
    ).rejects.toThrow(/identity mismatch: runAttempt/i)
  })

  it('uses a create-only candidate directory so a prior artifact cannot be overwritten', async () => {
    const { root, releaseRoot } = await releaseFixture('create-only')
    const outputDirectory = join(root, 'candidate')
    await createReleaseCandidateArchive({
      releaseRoot,
      outputDirectory,
      identity: IDENTITY
    })

    await expect(
      createReleaseCandidateArchive({ releaseRoot, outputDirectory, identity: IDENTITY })
    ).rejects.toMatchObject({ code: 'EEXIST' })
  })

  it('commits workflow provenance inside the archive so one payload cannot reuse one archive SHA across attempts', async () => {
    const first = await releaseFixture('attempt-two')
    const second = await releaseFixture('attempt-three')
    const firstResult = await createReleaseCandidateArchive({
      releaseRoot: first.releaseRoot,
      outputDirectory: join(first.root, 'candidate'),
      identity: IDENTITY
    })
    const secondResult = await createReleaseCandidateArchive({
      releaseRoot: second.releaseRoot,
      outputDirectory: join(second.root, 'candidate'),
      identity: { ...IDENTITY, runAttempt: '3' }
    })

    expect(firstResult.archiveSha256).not.toBe(secondResult.archiveSha256)
    expect(firstResult.manifest.payloadManifest).toMatchObject({
      path: '.nachuan/CANDIDATE_PAYLOAD_MANIFEST.json',
      sha256: expect.stringMatching(/^[0-9a-f]{64}$/),
      size: expect.any(Number)
    })
  })

  it.each(['.nachuan', '.NACHUAN'])(
    'rejects payload file %s because it conflicts with the embedded metadata directory',
    async (reservedName) => {
      const { root, releaseRoot } = await releaseFixture(`reserved-${reservedName.slice(1)}`)
      await writeFile(join(releaseRoot, reservedName), 'metadata-parent-collision')

      await expect(
        createReleaseCandidateArchive({
          releaseRoot,
          outputDirectory: join(root, 'candidate'),
          identity: IDENTITY
        })
      ).rejects.toThrow(/reserved metadata path/i)
    }
  )

  it('budgets the worst-case USTAR padding for every payload and metadata entry', () => {
    expect(maximumReleaseCandidateArchiveBytes()).toBe(34_529_149_279)
  })
})
