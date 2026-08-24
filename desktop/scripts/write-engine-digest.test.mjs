import { createHash } from 'node:crypto'
import { lstat, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, describe, expect, it } from 'vitest'

import {
  materializeEngineIntegrityModule,
  prepareEngineIntegrityBindings
} from './write-engine-digest.mjs'

const workdirs = []

afterEach(async () => {
  await Promise.all(workdirs.splice(0).map((path) => rm(path, { recursive: true, force: true })))
})

const bindings = {
  engineSha256: '1'.repeat(64),
  runtimeManifestSha256: '2'.repeat(64),
  ffmpegSha256: '3'.repeat(64),
  ffprobeSha256: '4'.repeat(64),
  mediaRuntimeManifestSha256: '5'.repeat(64),
  storeRuntimeProfileSha256: '6'.repeat(64)
}

function identity(info) {
  return [info.dev, info.ino, info.size, info.mtimeNs, info.ctimeNs, info.birthtimeNs]
}

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex')

describe('build-time engine integrity embedding', () => {
  it('checks the digest module without rewriting identical frozen source bytes', async () => {
    const root = await realpath(await mkdtemp(join(tmpdir(), 'nachuan-engine-digest-')))
    workdirs.push(root)
    const output = join(root, 'generated-engine-integrity.ts')
    await materializeEngineIntegrityModule({ output, bindings, operation: 'write' })
    const beforeBytes = await readFile(output)
    const beforeIdentity = identity(await lstat(output, { bigint: true }))

    await expect(
      materializeEngineIntegrityModule({ output, bindings, operation: 'check' })
    ).resolves.toMatchObject({ operation: 'check' })
    expect(await readFile(output)).toEqual(beforeBytes)
    expect(identity(await lstat(output, { bigint: true }))).toEqual(beforeIdentity)
    expect(beforeBytes.toString('utf8')).toContain(
      `EXPECTED_STORE_RUNTIME_PROFILE_SHA256 = '${'6'.repeat(64)}'`
    )
  })

  it('checks prepared payload and provenance without staging or writing either file', async () => {
    const root = await realpath(await mkdtemp(join(tmpdir(), 'nachuan-engine-check-')))
    workdirs.push(root)
    const dist = join(root, 'dist')
    await mkdir(dist)
    const engineName = process.platform === 'win32' ? 'engine.exe' : 'engine'
    const engine = join(dist, engineName)
    const payload = join(dist, 'engine.payload')
    const provenance = join(dist, 'ENGINE_PYTHON_PAYLOAD.json')
    const runtimeManifest = join(dist, 'local-runtime-manifest.json')
    const config = join(root, 'config')
    const runtimeProfile = join(config, 'store-runtime-profile.v1.json')
    const engineBytes = Buffer.from('signed-engine-bytes')
    const profileBytes = Buffer.from('{"schema":"nachuan.runtime-profile/v1"}\n')
    await mkdir(config)
    await writeFile(engine, engineBytes)
    await writeFile(payload, engineBytes)
    await writeFile(provenance, '{"schema":1}\n')
    await writeFile(runtimeManifest, '{}\n')
    await writeFile(runtimeProfile, profileBytes)
    const payloadBefore = {
      bytes: await readFile(payload),
      identity: identity(await lstat(payload, { bigint: true }))
    }
    const provenanceBefore = {
      bytes: await readFile(provenance),
      identity: identity(await lstat(provenance, { bigint: true }))
    }
    const calls = []
    const clients = {
      stageEnginePayload() {
        calls.push('stage')
        throw new Error('check mode attempted to stage the payload')
      },
      async writePythonPayloadProvenance() {
        calls.push('write-provenance')
        throw new Error('check mode attempted to write provenance')
      },
      async verifyPythonPayloadProvenance({ enginePath, manifestPath }) {
        calls.push(['verify-provenance', enginePath, manifestPath])
        await readFile(manifestPath)
      },
      async verifyPreparedMediaRuntime() {
        calls.push('verify-media')
        return {
          ffmpeg: { sha256: '3'.repeat(64) },
          ffprobe: { sha256: '4'.repeat(64) },
          manifestSha256: '5'.repeat(64)
        }
      }
    }

    await expect(
      prepareEngineIntegrityBindings({ projectRoot: root, operation: 'check', clients })
    ).resolves.toMatchObject({
      engineName,
      engineSha256: sha256(engineBytes),
      runtimeManifestSha256: sha256(Buffer.from('{}\n')),
      storeRuntimeProfileSha256: sha256(profileBytes)
    })
    expect(calls).toEqual([
      ['verify-provenance', payload, provenance],
      'verify-media'
    ])
    expect(await readFile(payload)).toEqual(payloadBefore.bytes)
    expect(identity(await lstat(payload, { bigint: true }))).toEqual(payloadBefore.identity)
    expect(await readFile(provenance)).toEqual(provenanceBefore.bytes)
    expect(identity(await lstat(provenance, { bigint: true }))).toEqual(provenanceBefore.identity)
  })

  it('rejects an invalid operation before any payload or provenance I/O', async () => {
    const calls = []
    const clients = {
      stageEnginePayload() {
        calls.push('stage')
      },
      async writePythonPayloadProvenance() {
        calls.push('write-provenance')
      },
      async verifyPythonPayloadProvenance() {
        calls.push('verify-provenance')
      },
      async verifyPreparedMediaRuntime() {
        calls.push('verify-media')
      }
    }

    await expect(
      prepareEngineIntegrityBindings({ projectRoot: join(tmpdir(), 'missing-engine-root'), operation: 'repair', clients })
    ).rejects.toThrow(/operation.*write or check/i)
    expect(calls).toEqual([])
  })
})
