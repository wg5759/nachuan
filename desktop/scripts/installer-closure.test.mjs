import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, describe, expect, it } from 'vitest'

import {
  verifyTreeAgainstManifest,
  writeTreeManifest
} from './installer-closure.mjs'

const workdirs = []

afterEach(async () => {
  await Promise.all(workdirs.splice(0).map((path) => rm(path, { recursive: true, force: true })))
})

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), 'nachuan-installer-closure-'))
  workdirs.push(root)
  const unpacked = join(root, 'win-unpacked')
  const manifest = join(root, 'WIN_UNPACKED_MANIFEST.json')
  await mkdir(join(unpacked, 'resources', 'engine'), { recursive: true })
  await writeFile(join(unpacked, '纳川.exe'), 'signed-desktop')
  await writeFile(join(unpacked, 'resources', 'app.asar'), 'reviewed-asar')
  await writeFile(join(unpacked, 'resources', 'engine', 'engine.exe'), 'signed-engine')
  return { root, unpacked, manifest }
}

describe('installer payload closure manifest', () => {
  it('writes a deterministic manifest and verifies the exact installed tree', async () => {
    const { unpacked, manifest } = await fixture()
    await writeTreeManifest({ root: unpacked, output: manifest, version: '1.2.3', variant: 'lean' })
    const first = await readFile(manifest, 'utf8')
    await writeTreeManifest({ root: unpacked, output: manifest, version: '1.2.3', variant: 'lean' })
    expect(await readFile(manifest, 'utf8')).toBe(first)
    await expect(verifyTreeAgainstManifest({ root: unpacked, manifestPath: manifest })).resolves.toEqual(
      expect.objectContaining({ fileCount: 3 })
    )
  })

  it('rejects a changed, missing, or extra installed payload file', async () => {
    const { unpacked, manifest } = await fixture()
    await writeTreeManifest({ root: unpacked, output: manifest, version: '1.2.3', variant: 'lean' })

    await writeFile(join(unpacked, 'resources', 'app.asar'), 'replacement')
    await expect(verifyTreeAgainstManifest({ root: unpacked, manifestPath: manifest })).rejects.toThrow(
      /SHA-256|size/
    )
    await writeFile(join(unpacked, 'resources', 'app.asar'), 'reviewed-asar')

    await writeFile(join(unpacked, 'resources', 'injected.dll'), 'unreviewed')
    await expect(verifyTreeAgainstManifest({ root: unpacked, manifestPath: manifest })).rejects.toThrow(
      /closed|extra|manifest/i
    )
  })

  it('allows only the exact installer-created uninstaller exception', async () => {
    const { unpacked, manifest } = await fixture()
    await writeTreeManifest({ root: unpacked, output: manifest, version: '1.2.3', variant: 'lean' })
    await writeFile(join(unpacked, 'Uninstall 纳川.exe'), 'installer-created')

    await expect(
      verifyTreeAgainstManifest({
        root: unpacked,
        manifestPath: manifest,
        allowedExtraPaths: ['Uninstall 纳川.exe']
      })
    ).resolves.toEqual(expect.objectContaining({ fileCount: 3, allowedExtraCount: 1 }))
    await writeFile(join(unpacked, 'other.exe'), 'not-allowed')
    await expect(
      verifyTreeAgainstManifest({
        root: unpacked,
        manifestPath: manifest,
        allowedExtraPaths: ['Uninstall 纳川.exe']
      })
    ).rejects.toThrow(/closed|extra|manifest/i)
  })

  it('globally ordinal-sorts root files and nested resources with the same rule used by validation', async () => {
    const { unpacked, manifest } = await fixture()
    await writeFile(join(unpacked, 'resources.pak'), 'root resource archive')

    await writeTreeManifest({ root: unpacked, output: manifest, version: '1.2.3', variant: 'lean' })
    const payload = JSON.parse(await readFile(manifest, 'utf8'))
    const paths = payload.files.map((item) => item.path)

    expect(paths).toEqual([...paths].sort((left, right) => (left < right ? -1 : left > right ? 1 : 0)))
    await expect(verifyTreeAgainstManifest({ root: unpacked, manifestPath: manifest })).resolves.toEqual(
      expect.objectContaining({ fileCount: 4 })
    )
  })
})
