import { createHash } from 'node:crypto'
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, describe, expect, it } from 'vitest'

import {
  assertMediaRuntimeProductionAdmission,
  canonicalMediaRuntimeBytes,
  defaultMediaRuntimeSource,
  MEDIA_RUNTIME_MANIFEST_SCHEMA,
  prepareMediaRuntime,
  readReviewedMediaRuntimeLock,
  verifyPreparedMediaRuntime
} from './media-runtime-policy.mjs'

const roots = []
const COMMIT = '894da5ca7d742e4429ffb2af534fcda0103ef593'
const VERSION = '8.0.1-essentials_build-www.gyan.dev'
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex')

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { force: true, recursive: true })
})

function peX64(marker) {
  const bytes = Buffer.alloc(512, 0)
  bytes.write('MZ', 0, 'ascii')
  bytes.writeUInt32LE(128, 0x3c)
  bytes.write('PE\0\0', 128, 'ascii')
  bytes.writeUInt16LE(0x8664, 132)
  bytes.write(marker, 160, 'utf8')
  return bytes
}

function fixture() {
  const repoRoot = mkdtempSync(join(tmpdir(), 'nachuan-media-runtime-policy-'))
  roots.push(repoRoot)
  const desktopRoot = join(repoRoot, 'desktop')
  const sourceRoot = join(repoRoot, '安装与维护', '构建输入', 'ffmpeg-8.0.1-essentials_build')
  const binRoot = join(sourceRoot, 'bin')
  const distRoot = join(repoRoot, 'dist')
  mkdirSync(desktopRoot)
  mkdirSync(binRoot, { recursive: true })
  mkdirSync(distRoot)

  const ffmpeg = peX64('reviewed-ffmpeg')
  const ffprobe = peX64('reviewed-ffprobe')
  const license = Buffer.from(
    'GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007\nGPL test evidence\n',
    'utf8'
  )
  const readme = Buffer.from(
    `FFmpeg 64-bit static Windows build from www.gyan.dev\n\n` +
      `Version: ${VERSION}\n\nLicense: GPL v3\n\n` +
      `Source Code: https://github.com/FFmpeg/FFmpeg/commit/${COMMIT.slice(0, 10)}\n`,
    'utf8'
  )
  writeFileSync(join(binRoot, 'ffmpeg.exe'), ffmpeg)
  writeFileSync(join(binRoot, 'ffprobe.exe'), ffprobe)
  writeFileSync(join(sourceRoot, 'LICENSE'), license)
  writeFileSync(join(sourceRoot, 'README.txt'), readme)

  const lock = {
    archive: {
      sha256: 'a'.repeat(64),
      size: 1024,
      url: 'https://www.gyan.dev/ffmpeg/builds/packages/ffmpeg-8.0.1-essentials_build.zip'
    },
    artifacts: [
      {
        installedPath: 'media/ffmpeg.exe',
        role: 'ffmpeg',
        sha256: sha256(ffmpeg),
        size: ffmpeg.length,
        sourcePath: 'bin/ffmpeg.exe',
        stagedName: 'ffmpeg.payload'
      },
      {
        installedPath: 'media/ffprobe.exe',
        role: 'ffprobe',
        sha256: sha256(ffprobe),
        size: ffprobe.length,
        sourcePath: 'bin/ffprobe.exe',
        stagedName: 'ffprobe.payload'
      }
    ],
    authenticode: {
      signer: null,
      status: 'NotSigned',
      timestamp: null
    },
    license: {
      path: 'LICENSE',
      sha256: sha256(license),
      size: license.length,
      spdx: 'GPL-3.0-or-later'
    },
    platform: 'win32-x64',
    readme: {
      path: 'README.txt',
      sha256: sha256(readme),
      size: readme.length
    },
    releaseAdmission: {
      legalClosure: 'incomplete',
      production: 'blocked',
      trustClass: 'unsigned-fixed-hash-engineering-candidate'
    },
    reviewedOn: '2026-07-16',
    schema: 'nachuan.media-runtime-lock.v1',
    source: {
      commit: COMMIT,
      url: `https://github.com/FFmpeg/FFmpeg/commit/${COMMIT}`
    },
    version: VERSION
  }
  const lockPath = join(desktopRoot, 'media-runtime-lock.json')
  writeFileSync(lockPath, canonicalMediaRuntimeBytes(lock))
  return { distRoot, ffmpeg, ffprobe, license, lock, lockPath, readme, repoRoot, sourceRoot }
}

describe('reviewed packaged media runtime staging', () => {
  it('stages only non-executable payload names plus exact license/provenance evidence', async () => {
    const item = fixture()
    const result = await prepareMediaRuntime(item)

    expect(readdirSync(join(item.distRoot, 'media')).sort()).toEqual([
      'ffmpeg.payload',
      'ffprobe.payload'
    ])
    expect(readdirSync(join(item.distRoot, 'media-notices')).sort()).toEqual([
      'LICENSE',
      'README.txt'
    ])
    expect(readFileSync(join(item.distRoot, 'media', 'ffmpeg.payload'))).toEqual(item.ffmpeg)
    expect(readFileSync(join(item.distRoot, 'media', 'ffprobe.payload'))).toEqual(item.ffprobe)
    expect(readFileSync(join(item.distRoot, 'media-notices', 'LICENSE'))).toEqual(item.license)
    expect(readFileSync(join(item.distRoot, 'media-notices', 'README.txt'))).toEqual(item.readme)

    const manifest = JSON.parse(readFileSync(result.manifestPath, 'utf8'))
    expect(manifest.schema).toBe(MEDIA_RUNTIME_MANIFEST_SCHEMA)
    expect(manifest.authenticode).toEqual({ signer: null, status: 'NotSigned', timestamp: null })
    expect(manifest.releaseAdmission.production).toBe('blocked')
    expect(manifest.artifacts).toEqual([
      {
        path: 'media/ffmpeg.exe',
        role: 'ffmpeg',
        sha256: sha256(item.ffmpeg),
        size: item.ffmpeg.length
      },
      {
        path: 'media/ffprobe.exe',
        role: 'ffprobe',
        sha256: sha256(item.ffprobe),
        size: item.ffprobe.length
      }
    ])
    expect(result.ffmpeg.sha256).toBe(sha256(item.ffmpeg))
    expect(result.ffprobe.sha256).toBe(sha256(item.ffprobe))
    expect(result.lockSha256).toMatch(/^[0-9a-f]{64}$/)
    expect(result.manifestSha256).toMatch(/^[0-9a-f]{64}$/)
  })

  it('keeps the unsigned GPL engineering candidate behind a production NO-GO', () => {
    const item = fixture()
    expect(() => assertMediaRuntimeProductionAdmission(item.lock)).toThrow(
      /MEDIA_RUNTIME_PRODUCTION_NO_GO/
    )
  })

  it('uses the one-project Chinese maintenance source path and never Program Files', () => {
    const item = fixture()
    const expected = join(
      item.repoRoot,
      '安装与维护',
      '构建输入',
      'ffmpeg-8.0.1-essentials_build'
    )
    expect(defaultMediaRuntimeSource(item.repoRoot)).toBe(expected)
    expect(expected).not.toMatch(/Program Files/i)
  })

  it('rejects ffplay and every other unreviewed source sidecar before staging', async () => {
    const item = fixture()
    writeFileSync(join(item.sourceRoot, 'bin', 'ffplay.exe'), peX64('unreviewed-ffplay'))

    await expect(prepareMediaRuntime(item)).rejects.toThrow(/closed file set/i)
    expect(existsSync(join(item.distRoot, 'media'))).toBe(false)
    expect(existsSync(join(item.distRoot, 'media-runtime-manifest.json'))).toBe(false)
  })

  it('rejects source-byte drift and removes partial output', async () => {
    const item = fixture()
    writeFileSync(join(item.sourceRoot, 'bin', 'ffprobe.exe'), peX64('replaced-ffprobe'))

    await expect(prepareMediaRuntime(item)).rejects.toThrow(/size|SHA-256/i)
    expect(existsSync(join(item.distRoot, 'media'))).toBe(false)
    expect(existsSync(join(item.distRoot, 'media-notices'))).toBe(false)
  })

  it('rehashes staged payloads and refuses post-prepare tampering', async () => {
    const item = fixture()
    await prepareMediaRuntime(item)
    writeFileSync(join(item.distRoot, 'media', 'ffmpeg.payload'), peX64('tampered'))

    await expect(verifyPreparedMediaRuntime(item)).rejects.toThrow(/staged file|SHA-256/i)
  })

  it('rejects a redirected source directory', async () => {
    const item = fixture()
    const link = join(item.repoRoot, 'redirected-media-source')
    symlinkSync(item.sourceRoot, link, process.platform === 'win32' ? 'junction' : 'dir')

    await expect(prepareMediaRuntime({ ...item, sourceRoot: link })).rejects.toThrow(/redirect/i)
  })

  it('refuses recursive cleanup when a staged directory is replaced by a junction', async () => {
    const item = fixture()
    const outside = mkdtempSync(join(tmpdir(), 'nachuan-media-runtime-outside-'))
    roots.push(outside)
    const sentinel = join(outside, 'must-survive.txt')
    writeFileSync(sentinel, 'outside-stage-sentinel')

    await expect(
      prepareMediaRuntime({
        ...item,
        afterStageForAudit: ({ mediaRoot }) => {
          rmSync(mediaRoot, { force: true, recursive: true })
          symlinkSync(outside, mediaRoot, process.platform === 'win32' ? 'junction' : 'dir')
          throw new Error('forced failure after redirect replacement')
        }
      })
    ).rejects.toThrow(/cleanup BLOCKED|redirect/i)
    expect(readFileSync(sentinel, 'utf8')).toBe('outside-stage-sentinel')
  })

  it('rejects non-canonical lock bytes before trusting any digest', () => {
    const item = fixture()
    writeFileSync(item.lockPath, JSON.stringify(item.lock))
    expect(() => readReviewedMediaRuntimeLock(item)).toThrow(/canonical JSON/i)
  })
})
