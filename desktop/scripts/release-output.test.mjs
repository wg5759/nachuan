import { createHash } from 'node:crypto'
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, describe, expect, it } from 'vitest'

import {
  assertClosedReleaseOutput,
  cleanReleaseOutput,
  pruneKnownBuilderMetadata,
  verifyPackagedReleaseOutput,
  verifyFinalReleaseOutput
} from './release-output.mjs'
import { writeTreeManifest } from './installer-closure.mjs'

const roots = []

function fixture() {
  const parent = mkdtempSync(join(tmpdir(), 'nachuan-release-output-'))
  roots.push(parent)
  const releaseRoot = join(parent, 'release')
  mkdirSync(releaseRoot)
  return { parent, releaseRoot }
}

function expectedFiles(releaseRoot) {
  writeFileSync(join(releaseRoot, 'nachuan-0.1.0-lean-win.exe'), 'installer')
  writeFileSync(join(releaseRoot, 'nachuan-0.1.0-lean-win.exe.blockmap'), 'blockmap')
  writeFileSync(join(releaseRoot, 'lean.yml'), 'channel')
  mkdirSync(join(releaseRoot, 'win-unpacked'))
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true })
})

describe('closed release output', () => {
  it('recreates only the fixed release directory as empty', () => {
    const { parent, releaseRoot } = fixture()
    writeFileSync(join(releaseRoot, 'stale-secret.yml'), 'secret')

    expect(cleanReleaseOutput({ releaseRoot, expectedParent: parent })).toBe(releaseRoot)
    expectedFiles(releaseRoot)
    expect(
      assertClosedReleaseOutput({
        variant: 'lean',
        releaseRoot,
        expectedParent: parent,
        platform: 'win32',
        version: '0.1.0'
      }).artifact
    ).toBe('nachuan-0.1.0-lean-win.exe')
  })

  it('prunes only known builder metadata and rejects every other residual', () => {
    const { parent, releaseRoot } = fixture()
    expectedFiles(releaseRoot)
    writeFileSync(join(releaseRoot, 'builder-debug.yml'), 'absolute build paths')
    mkdirSync(join(releaseRoot, '.icon-ico'))
    pruneKnownBuilderMetadata({ releaseRoot, expectedParent: parent })
    writeFileSync(join(releaseRoot, 'old-full.yml'), 'stale')

    expect(() =>
      assertClosedReleaseOutput({
        variant: 'lean',
        releaseRoot,
        expectedParent: parent,
        platform: 'win32',
        version: '0.1.0'
      })
    ).toThrow(/unexpected release output file/)
  })

  it('refuses a redirected release root', () => {
    if (process.platform !== 'win32') return
    const parent = mkdtempSync(join(tmpdir(), 'nachuan-release-parent-'))
    const target = mkdtempSync(join(tmpdir(), 'nachuan-release-target-'))
    roots.push(parent, target)
    symlinkSync(target, join(parent, 'release'), 'junction')

    expect(() => cleanReleaseOutput({ releaseRoot: join(parent, 'release'), expectedParent: parent })).toThrow(
      /real directory|redirect/i
    )
  })

  it('keeps lean and full artifact names disjoint', () => {
    const { parent, releaseRoot } = fixture()
    writeFileSync(join(releaseRoot, 'nachuan-0.1.0-full-win.exe'), 'installer')
    writeFileSync(join(releaseRoot, 'nachuan-0.1.0-full-win.exe.blockmap'), 'blockmap')
    writeFileSync(join(releaseRoot, 'full.yml'), 'channel')
    mkdirSync(join(releaseRoot, 'win-unpacked'))

    const full = assertClosedReleaseOutput({
      variant: 'full',
      releaseRoot,
      expectedParent: parent,
      platform: 'win32',
      version: '0.1.0'
    })
    expect(full.artifact).toBe('nachuan-0.1.0-full-win.exe')
    expect(full.artifact).not.toBe('nachuan-0.1.0-lean-win.exe')
  })

  it.each(['lean', 'full'])('requires a variant-bound production %s envelope in the closed output', (variant) => {
    const { parent, releaseRoot } = fixture()
    writeFileSync(join(releaseRoot, `nachuan-0.1.0-${variant}-win.exe`), 'installer')
    writeFileSync(join(releaseRoot, `nachuan-0.1.0-${variant}-win.exe.blockmap`), 'blockmap')
    writeFileSync(join(releaseRoot, `${variant}.yml`), 'channel')
    writeFileSync(join(releaseRoot, `production-${variant}-win-x64.json`), 'production-envelope')
    mkdirSync(join(releaseRoot, 'win-unpacked'))

    expect(
      assertClosedReleaseOutput({
        variant,
        releaseRoot,
        expectedParent: parent,
        platform: 'win32',
        version: '0.1.0',
        requireUpdateEnvelope: true
      }).updateEnvelope
    ).toBe(`production-${variant}-win-x64.json`)
  })

  it('keeps update-disabled local output closed without generating a channel pointer', () => {
    const { parent, releaseRoot } = fixture()
    writeFileSync(join(releaseRoot, 'nachuan-0.1.0-lean-win.exe'), 'installer')
    writeFileSync(join(releaseRoot, 'nachuan-0.1.0-lean-win.exe.blockmap'), 'blockmap')
    mkdirSync(join(releaseRoot, 'win-unpacked'))

    expect(
      assertClosedReleaseOutput({
        variant: 'lean',
        releaseRoot,
        expectedParent: parent,
        platform: 'win32',
        version: '0.1.0',
        requireChannel: false
      })
    ).toMatchObject({ artifact: 'nachuan-0.1.0-lean-win.exe' })

    writeFileSync(join(releaseRoot, 'lean.yml'), 'must not exist in an update-disabled candidate')
    expect(() =>
      assertClosedReleaseOutput({
        variant: 'lean',
        releaseRoot,
        expectedParent: parent,
        platform: 'win32',
        version: '0.1.0',
        requireChannel: false
      })
    ).toThrow(/unexpected release output file/)
  })

  it('keeps pre-final verification repeatable after a bound installer-closure manifest is emitted', async () => {
    const { parent, releaseRoot } = fixture()
    expectedFiles(releaseRoot)
    const unpackedFile = join(releaseRoot, 'win-unpacked', '纳川.exe')
    writeFileSync(unpackedFile, 'verified unpacked payload')
    await writeTreeManifest({
      root: join(releaseRoot, 'win-unpacked'),
      output: join(releaseRoot, 'WIN_UNPACKED_MANIFEST.json'),
      version: '0.1.0',
      variant: 'lean'
    })

    await expect(
      verifyPackagedReleaseOutput({
        variant: 'lean',
        releaseRoot,
        expectedParent: parent,
        platform: 'win32',
        version: '0.1.0'
      })
    ).resolves.toMatchObject({ artifact: 'nachuan-0.1.0-lean-win.exe' })

    writeFileSync(unpackedFile, 'tampered payload')
    await expect(
      verifyPackagedReleaseOutput({
        variant: 'lean',
        releaseRoot,
        expectedParent: parent,
        platform: 'win32',
        version: '0.1.0'
      })
    ).rejects.toThrow(/size|SHA-256/)
  })

  it('keeps unsigned early-access artifacts visibly separate and closes the signed envelope', async () => {
    const { parent, releaseRoot } = fixture()
    const names = [
      'nachuan-0.1.0-lean-early-access-unsigned-win.exe',
      'nachuan-0.1.0-lean-early-access-unsigned-win.exe.blockmap',
      'early-access-lean.yml',
      'WIN_UNPACKED_MANIFEST.json',
      'early-access-lean-win-x64.json'
    ]
    for (const name of names) writeFileSync(join(releaseRoot, name), name)
    mkdirSync(join(releaseRoot, 'win-unpacked'))
    const lines = names.map(
      (name) => `${createHash('sha256').update(name).digest('hex')}  ${name}`
    )
    writeFileSync(join(releaseRoot, 'SHA256SUMS'), `${lines.join('\n')}\n`)

    await expect(
      verifyFinalReleaseOutput({
        variant: 'lean',
        releaseTier: 'early-access',
        releaseRoot,
        expectedParent: parent,
        platform: 'win32',
        version: '0.1.0'
      })
    ).resolves.toMatchObject({
      artifact: 'nachuan-0.1.0-lean-early-access-unsigned-win.exe',
      channel: 'early-access-lean.yml',
      updateEnvelope: 'early-access-lean-win-x64.json'
    })
  })

  it('recomputes every digest in the final checksum manifest', async () => {
    const { parent, releaseRoot } = fixture()
    expectedFiles(releaseRoot)
    const names = [
      'nachuan-0.1.0-lean-win.exe',
      'nachuan-0.1.0-lean-win.exe.blockmap',
      'lean.yml',
      'WIN_UNPACKED_MANIFEST.json',
      'production-lean-win-x64.json'
    ]
    const lines = names.map((name) => {
      const content = name.endsWith('.exe')
        ? 'installer'
        : name.endsWith('.blockmap')
          ? 'blockmap'
          : name.endsWith('.json')
            ? name === 'WIN_UNPACKED_MANIFEST.json'
              ? 'payload-manifest'
              : 'production-envelope'
            : 'channel'
      return `${createHash('sha256').update(content).digest('hex')}  ${name}`
    })
    writeFileSync(join(releaseRoot, 'WIN_UNPACKED_MANIFEST.json'), 'payload-manifest')
    writeFileSync(join(releaseRoot, 'production-lean-win-x64.json'), 'production-envelope')
    writeFileSync(join(releaseRoot, 'SHA256SUMS'), `${lines.join('\n')}\n`)

    await expect(
      verifyFinalReleaseOutput({
        variant: 'lean',
        releaseRoot,
        expectedParent: parent,
        platform: 'win32',
        version: '0.1.0'
      })
    ).resolves.toMatchObject({
      artifact: 'nachuan-0.1.0-lean-win.exe',
      updateEnvelope: 'production-lean-win-x64.json'
    })

    writeFileSync(join(releaseRoot, 'nachuan-0.1.0-lean-win.exe'), 'tampered')
    await expect(
      verifyFinalReleaseOutput({
        variant: 'lean',
        releaseRoot,
        expectedParent: parent,
        platform: 'win32',
        version: '0.1.0'
      })
    ).rejects.toThrow(/digest does not match/)
  })
})
