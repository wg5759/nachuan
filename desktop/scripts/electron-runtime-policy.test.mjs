import { createHash } from 'node:crypto'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { afterEach, describe, expect, it } from 'vitest'

import {
  prepareElectronRuntime,
  readElectronRuntimeLock,
  resolveExtractArchiveApi,
  verifyPreparedElectronRuntime
} from './electron-runtime-policy.mjs'

const roots = []
const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..')
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex')
const canonical = (value) => `${JSON.stringify(value, null, 2)}\n`

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { force: true, recursive: true })
})

function fixture() {
  const projectRoot = mkdtempSync(join(tmpdir(), 'nachuan-electron-runtime-'))
  roots.push(projectRoot)
  const desktop = join(projectRoot, 'desktop')
  const electronRoot = join(desktop, 'node_modules', 'electron')
  mkdirSync(electronRoot, { recursive: true })
  const archiveBytes = Buffer.from('locked-electron-archive')
  const license = 'Electron license\n'
  const chromium = 'Chromium notices\n'
  const lock = {
    arch: 'x64',
    archive: 'electron-v39.8.5-win32-x64.zip',
    archiveSha256: sha256(archiveBytes),
    archiveSize: archiveBytes.length,
    electronNpmIntegrity: 'sha512-q6+LiQIcTadSyvtPgLDQkCtVA9jQJXQVMrQcctfOJILh6OFMN+UJJLRkuUTy8CZDYeCIBn1ZycqsL1dAXugxZA==',
    electronNpmResolved: 'https://registry.npmjs.org/electron/-/electron-39.8.5.tgz',
    licenseFiles: [
      { path: 'LICENSE', sha256: sha256(license), size: Buffer.byteLength(license) },
      { path: 'LICENSES.chromium.html', sha256: sha256(chromium), size: Buffer.byteLength(chromium) }
    ],
    platform: 'win32',
    schema: 1,
    shasumsUrl: 'https://github.com/electron/electron/releases/download/v39.8.5/SHASUMS256.txt',
    sourceUrl: 'https://github.com/electron/electron/releases/download/v39.8.5/electron-v39.8.5-win32-x64.zip',
    version: '39.8.5'
  }
  writeFileSync(join(desktop, 'electron-runtime-lock.json'), canonical(lock))
  writeFileSync(join(electronRoot, 'package.json'), canonical({ version: lock.version }))
  writeFileSync(join(electronRoot, 'checksums.json'), canonical({ [lock.archive]: lock.archiveSha256 }))
  writeFileSync(join(desktop, 'package-lock.json'), canonical({
    lockfileVersion: 3,
    packages: {
      'node_modules/electron': {
        version: lock.version,
        resolved: lock.electronNpmResolved,
        integrity: lock.electronNpmIntegrity,
        hasInstallScript: true
      }
    }
  }))
  return { archiveBytes, chromium, electronRoot, license, lock, projectRoot }
}

describe('pinned Electron runtime preparation', () => {
  it('accepts the reviewed Electron internal extractor named export and rejects unknown APIs', () => {
    const extract = async () => undefined
    expect(resolveExtractArchiveApi({ extract })).toBe(extract)
    expect(resolveExtractArchiveApi(extract)).toBe(extract)
    expect(() => resolveExtractArchiveApi({})).toThrow(/extractor API is unavailable/)
  })

  it('pins the real official Windows x64 archive URL, size, and SHASUMS256 digest', () => {
    const lock = readElectronRuntimeLock({ projectRoot: repoRoot })
    expect(lock).toMatchObject({
      archive: 'electron-v39.8.10-win32-x64.zip',
      archiveSha256: '4478410a35a8399b7745085096695a37877f176755182a71e27eddc245cd98d5',
      archiveSize: 136641055,
      sourceUrl: 'https://github.com/electron/electron/releases/download/v39.8.10/electron-v39.8.10-win32-x64.zip',
      shasumsUrl: 'https://github.com/electron/electron/releases/download/v39.8.10/SHASUMS256.txt'
    })
    const npmChecksums = JSON.parse(
      readFileSync(join(repoRoot, 'desktop', 'node_modules', 'electron', 'checksums.json'), 'utf8')
    )
    expect(npmChecksums[lock.archive]).toBe(lock.archiveSha256)
  })

  it('works from an empty project-local cache and absent Electron dist, then re-verifies every byte', async () => {
    const { archiveBytes, chromium, license, lock, projectRoot } = fixture()
    let requested
    const download = async (options) => {
      requested = options
      writeFileSync(options.destination, archiveBytes)
    }
    const extractArchive = async (_archive, { dir }) => {
      writeFileSync(join(dir, 'electron.exe'), 'signed-upstream-runtime')
      writeFileSync(join(dir, 'version'), lock.version)
      writeFileSync(join(dir, 'LICENSE'), license)
      writeFileSync(join(dir, 'LICENSES.chromium.html'), chromium)
    }

    const prepared = await prepareElectronRuntime({ projectRoot, download, extractArchive })

    expect(requested).toEqual({
      destination: expect.stringMatching(/\.download$/),
      expectedSha256: lock.archiveSha256,
      expectedSize: lock.archiveSize,
      sourceUrl: lock.sourceUrl
    })
    expect(prepared.provenance.officialShasums.line).toBe(`${lock.archiveSha256} *${lock.archive}`)
    expect(() => verifyPreparedElectronRuntime({ projectRoot })).not.toThrow()

    writeFileSync(join(prepared.extractedRoot, 'LICENSE'), 'replacement')
    expect(() => verifyPreparedElectronRuntime({ projectRoot })).toThrow(
      /size drifted|hash drifted|provenance drifted/
    )
  })

  it('rejects a downloaded archive whose bytes differ from the pinned checksum', async () => {
    const { chromium, license, lock, projectRoot } = fixture()
    await expect(
      prepareElectronRuntime({
        projectRoot,
        download: async ({ destination }) => writeFileSync(destination, 'tampered'),
        extractArchive: async (_archive, { dir }) => {
          writeFileSync(join(dir, 'electron.exe'), 'runtime')
          writeFileSync(join(dir, 'version'), lock.version)
          writeFileSync(join(dir, 'LICENSE'), license)
          writeFileSync(join(dir, 'LICENSES.chromium.html'), chromium)
        }
      })
    ).rejects.toThrow(/size drifted|hash drifted/)
  })
})
