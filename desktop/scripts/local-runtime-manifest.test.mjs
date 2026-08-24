import { createHash } from 'node:crypto'
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, describe, expect, it } from 'vitest'

import { prepareLocalRuntime, writePreparedRuntimeManifest } from './prepare-pack.mjs'
import { verifyLocalRuntimeLayout } from './_verify_pack.mjs'

const workdirs = []
const sha256 = (value) => createHash('sha256').update(value).digest('hex')

afterEach(async () => {
  await Promise.all(workdirs.splice(0).map((path) => rm(path, { recursive: true, force: true })))
})

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), 'nachuan-local-runtime-'))
  workdirs.push(root)
  const llamaSrc = join(root, 'source-llama')
  const modelsSrc = join(root, 'source-models')
  const distRoot = join(root, 'dist')
  await mkdir(llamaSrc, { recursive: true })
  await mkdir(modelsSrc, { recursive: true })
  await writeFile(join(llamaSrc, 'llama-server.exe'), 'reviewed-server')
  await writeFile(join(llamaSrc, 'ggml-base.dll'), 'reviewed-base')
  await writeFile(join(llamaSrc, 'ggml-cpu.dll'), 'reviewed-cpu')
  await writeFile(join(llamaSrc, 'libggml.so.1'), 'reviewed-versioned-so')
  await writeFile(join(llamaSrc, 'ignored-tool.exe'), 'must-not-ship')
  await writeFile(join(modelsSrc, 'qwen.gguf'), 'GGUFreviewed-model')
  await writeFile(join(modelsSrc, 'notes.txt'), 'must-not-ship')
  const trustedManifestPath = join(root, 'trusted-full-runtime.json')
  const reviewed = [
    ['llama/ggml-base.dll', 'runtime-dependency', 'reviewed-base'],
    ['llama/ggml-cpu.dll', 'runtime-dependency', 'reviewed-cpu'],
    ['llama/libggml.so.1', 'runtime-dependency', 'reviewed-versioned-so'],
    ['llama/llama-server.exe', 'llama-server', 'reviewed-server'],
    ['models/qwen.gguf', 'model', 'GGUFreviewed-model']
  ].map(([path, role, bytes]) => ({
    path,
    role,
    sha256: sha256(bytes),
    size: Buffer.byteLength(bytes),
    license: role === 'model' ? 'Apache-2.0' : 'MIT',
    source:
      role === 'model'
        ? 'https://huggingface.co/reviewed/model'
        : 'https://github.com/ggml-org/llama.cpp/releases/tag/reviewed'
  }))
  await writeFile(
    trustedManifestPath,
    `${JSON.stringify({ schema: 1, artifacts: reviewed }, null, 2)}\n`,
    'utf8'
  )
  return { root, llamaSrc, modelsSrc, distRoot, trustedManifestPath }
}

describe('local runtime release manifest', () => {
  it('deterministically binds the server, every adjacent native library, and every GGUF', async () => {
    const { llamaSrc, modelsSrc, distRoot, trustedManifestPath } = await fixture()

    const first = await prepareLocalRuntime({
      variant: 'full',
      llamaSrc,
      modelsSrc,
      trustedManifestPath,
      distRoot
    })
    const firstBytes = await readFile(first.manifestPath, 'utf8')
    const second = await prepareLocalRuntime({
      variant: 'full',
      llamaSrc,
      modelsSrc,
      trustedManifestPath,
      distRoot
    })
    const secondBytes = await readFile(second.manifestPath, 'utf8')

    expect(secondBytes).toBe(firstBytes)
    expect(JSON.parse(secondBytes)).toEqual({
      schema: 1,
      artifacts: [
        {
          role: 'runtime-dependency',
          path: 'llama/ggml-base.dll',
          sha256: sha256('reviewed-base')
        },
        {
          role: 'runtime-dependency',
          path: 'llama/ggml-cpu.dll',
          sha256: sha256('reviewed-cpu')
        },
        {
          role: 'runtime-dependency',
          path: 'llama/libggml.so.1',
          sha256: sha256('reviewed-versioned-so')
        },
        {
          role: 'llama-server',
          path: 'llama/llama-server.exe',
          sha256: sha256('reviewed-server')
        },
        { role: 'model', path: 'models/qwen.gguf', sha256: sha256('GGUFreviewed-model') }
      ]
    })
    await expect(
      verifyLocalRuntimeLayout({ resourcesRoot: distRoot, variant: 'full', prepared: true })
    ).resolves.toEqual(expect.objectContaining({ modelCount: 1, runtimeDependencyCount: 3 }))
  })

  it('fails closed when a full build has no reviewed runtime or GGUF', async () => {
    const { llamaSrc, modelsSrc, distRoot, trustedManifestPath } = await fixture()
    await expect(
      prepareLocalRuntime({ variant: 'full', llamaSrc, modelsSrc, distRoot })
    ).rejects.toThrow(/TRUST_MANIFEST|trust manifest/i)

    await writeFile(join(modelsSrc, 'qwen.gguf'), 'GGUFchanged-model')
    await expect(
      prepareLocalRuntime({ variant: 'full', llamaSrc, modelsSrc, trustedManifestPath, distRoot })
    ).rejects.toThrow(/reviewed size|SHA-256/i)
    await writeFile(join(modelsSrc, 'qwen.gguf'), 'GGUFreviewed-model')

    await rm(join(modelsSrc, 'qwen.gguf'))

    await expect(
      prepareLocalRuntime({ variant: 'full', llamaSrc, modelsSrc, trustedManifestPath, distRoot })
    ).rejects.toThrow(/GGUF/)

    await writeFile(join(modelsSrc, 'qwen.gguf'), 'GGUFmodel')
    await rm(join(llamaSrc, 'llama-server.exe'))
    await expect(
      prepareLocalRuntime({ variant: 'full', llamaSrc, modelsSrc, trustedManifestPath, distRoot })
    ).rejects.toThrow(/llama-server/)
  })

  it('rebuilds the manifest from the post-signing staged runtime bytes', async () => {
    const { llamaSrc, modelsSrc, distRoot, trustedManifestPath } = await fixture()
    const prepared = await prepareLocalRuntime({
      variant: 'full',
      llamaSrc,
      modelsSrc,
      trustedManifestPath,
      distRoot
    })
    const before = JSON.parse(await readFile(prepared.manifestPath, 'utf8'))
    const stagedServer = join(
      distRoot,
      'llama',
      process.platform === 'win32' ? 'llama-server.payload' : 'llama-server.exe'
    )
    const signedBytes = Buffer.concat([await readFile(stagedServer), Buffer.from('|signed-by-production|')])
    await writeFile(stagedServer, signedBytes)

    await writePreparedRuntimeManifest({ variant: 'full', distRoot })
    const after = JSON.parse(await readFile(prepared.manifestPath, 'utf8'))
    const beforeServer = before.artifacts.find((item) => item.role === 'llama-server')
    const afterServer = after.artifacts.find((item) => item.role === 'llama-server')
    expect(afterServer.path).toBe('llama/llama-server.exe')
    expect(afterServer.sha256).not.toBe(beforeServer.sha256)
    expect(afterServer.sha256).toBe(createHash('sha256').update(signedBytes).digest('hex'))
  })

  it('detects unlisted, missing, and tampered packaged artifacts', async () => {
    const { llamaSrc, modelsSrc, distRoot, trustedManifestPath } = await fixture()
    const prepared = await prepareLocalRuntime({
      variant: 'full',
      llamaSrc,
      modelsSrc,
      trustedManifestPath,
      distRoot
    })

    const manifestBytes = await readFile(prepared.manifestPath)
    await rm(prepared.manifestPath)
    await expect(
      verifyLocalRuntimeLayout({ resourcesRoot: distRoot, variant: 'full', prepared: true })
    ).rejects.toThrow(/manifest is missing/i)
    await writeFile(prepared.manifestPath, manifestBytes)

    await writeFile(join(distRoot, 'llama', 'injected.dll'), 'unreviewed')
    await expect(
      verifyLocalRuntimeLayout({ resourcesRoot: distRoot, variant: 'full', prepared: true })
    ).rejects.toThrow(/manifest|unlisted/i)

    await rm(join(distRoot, 'llama', 'injected.dll'))
    await writeFile(join(distRoot, 'models', 'notes.txt'), 'unreviewed sidecar')
    await expect(
      verifyLocalRuntimeLayout({ resourcesRoot: distRoot, variant: 'full', prepared: true })
    ).rejects.toThrow(/models|unlisted|manifest/i)
    await rm(join(distRoot, 'models', 'notes.txt'))
    await writeFile(join(distRoot, 'models', 'qwen.gguf'), 'GGUFtampered')
    await expect(
      verifyLocalRuntimeLayout({ resourcesRoot: distRoot, variant: 'full', prepared: true })
    ).rejects.toThrow(/SHA-256/)
  })

  it('emits an empty manifest for lean and rejects leaked local artifacts', async () => {
    const { llamaSrc, modelsSrc, distRoot } = await fixture()
    const result = await prepareLocalRuntime({ variant: 'lean', llamaSrc, modelsSrc, distRoot })

    expect(JSON.parse(await readFile(result.manifestPath, 'utf8'))).toEqual({
      schema: 1,
      artifacts: []
    })
    await expect(
      verifyLocalRuntimeLayout({ resourcesRoot: distRoot, variant: 'lean', prepared: true })
    ).resolves.toEqual(expect.objectContaining({ modelCount: 0, runtimeDependencyCount: 0 }))

    await writeFile(join(distRoot, 'models', 'injected.txt'), 'unreviewed sidecar')
    await expect(
      verifyLocalRuntimeLayout({ resourcesRoot: distRoot, variant: 'lean', prepared: true })
    ).rejects.toThrow(/models|unlisted|lean/i)
    await rm(join(distRoot, 'models', 'injected.txt'))
    await writeFile(join(distRoot, 'models', 'injected.gguf'), 'GGUFunreviewed')
    await expect(
      verifyLocalRuntimeLayout({ resourcesRoot: distRoot, variant: 'lean', prepared: true })
    ).rejects.toThrow(/lean/)
  })
})
