import { createHash } from 'node:crypto'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, describe, expect, it } from 'vitest'

import { verifyReleaseMetadata } from './release-metadata.mjs'

const roots = []
function fixture({
  metadataVersion = '0.1.0',
  metadataArtifact = 'nachuan-0.1.0-lean-win.exe',
  withChecksum = false
} = {}) {
  const parent = mkdtempSync(join(tmpdir(), 'nachuan-release-metadata-'))
  roots.push(parent)
  const releaseRoot = join(parent, 'release')
  mkdirSync(join(releaseRoot, 'win-unpacked'), { recursive: true })
  const artifact = 'nachuan-0.1.0-lean-win.exe'
  const installer = Buffer.from('installer bytes')
  const digest = createHash('sha512').update(installer).digest('base64')
  writeFileSync(join(releaseRoot, artifact), installer)
  writeFileSync(join(releaseRoot, `${artifact}.blockmap`), 'blockmap')
  writeFileSync(
    join(releaseRoot, 'lean.yml'),
    [
      `version: ${metadataVersion}`,
      'files:',
      `  - url: ${metadataArtifact}`,
      `    sha512: ${digest}`,
      `    size: ${installer.length}`,
      `path: ${metadataArtifact}`,
      `sha512: ${digest}`
    ].join('\n')
  )
  if (withChecksum) writeFileSync(join(releaseRoot, 'SHA256SUMS'), 'post-verification checksum\n')
  return { parent, releaseRoot, artifact, installerSize: installer.length }
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true })
})

describe('release version and update metadata gate', () => {
  it('requires tag, package version, artifact name and metadata to agree', async () => {
    const { parent, releaseRoot } = fixture()
    await expect(
      verifyReleaseMetadata({
        variant: 'lean',
        releaseTag: 'v0.1.0',
        releaseRoot,
        expectedParent: parent,
        platform: 'win32',
        version: '0.1.0'
      })
    ).resolves.toEqual({ artifact: 'nachuan-0.1.0-lean-win.exe', version: '0.1.0' })
  })

  it('blocks a tag/version mismatch', async () => {
    const { parent, releaseRoot } = fixture()
    await expect(
      verifyReleaseMetadata({
        variant: 'lean',
        releaseTag: 'v0.1.1',
        releaseRoot,
        expectedParent: parent,
        platform: 'win32',
        version: '0.1.0'
      })
    ).rejects.toThrow(/does not match desktop version/)
  })

  it('blocks update metadata that points at another artifact', async () => {
    const { parent, releaseRoot } = fixture({ metadataArtifact: 'other.exe' })
    await expect(
      verifyReleaseMetadata({
        variant: 'lean',
        releaseTag: 'v0.1.0',
        releaseRoot,
        expectedParent: parent,
        platform: 'win32',
        version: '0.1.0'
      })
    ).rejects.toThrow(/metadata path does not match/)
  })

  it('blocks installer bytes changed after update metadata was written', async () => {
    const { parent, releaseRoot, artifact, installerSize } = fixture()
    writeFileSync(join(releaseRoot, artifact), Buffer.alloc(installerSize, 9))

    await expect(
      verifyReleaseMetadata({
        variant: 'lean',
        releaseTag: 'v0.1.0',
        releaseRoot,
        expectedParent: parent,
        platform: 'win32',
        version: '0.1.0'
      })
    ).rejects.toThrow(/SHA-512 does not match/)
  })

  it('can be repeated after the final checksum file exists', async () => {
    const { parent, releaseRoot } = fixture({ withChecksum: true })

    await expect(
      verifyReleaseMetadata({
        variant: 'lean',
        releaseTag: 'v0.1.0',
        releaseRoot,
        expectedParent: parent,
        platform: 'win32',
        version: '0.1.0'
      })
    ).resolves.toMatchObject({ artifact: 'nachuan-0.1.0-lean-win.exe' })
  })
})
