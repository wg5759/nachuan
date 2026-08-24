import { existsSync } from 'node:fs'
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, describe, expect, it } from 'vitest'

import { finalizePackagedRuntime } from './after-pack.mjs'

const roots = []

afterEach(async () => {
  await Promise.all(roots.splice(0).map((path) => rm(path, { recursive: true, force: true })))
})

async function fixture() {
  const appOutDir = await mkdtemp(join(tmpdir(), 'nachuan-after-pack-'))
  roots.push(appOutDir)
  const llama = join(appOutDir, 'resources', 'llama')
  await mkdir(llama, { recursive: true })
  return { appOutDir, llama }
}

describe('post-copy runtime payload finalization', () => {
  it('restores the signed non-executable source name to llama-server.exe on Windows full', async () => {
    const { appOutDir, llama } = await fixture()
    await writeFile(join(llama, 'llama-server.payload'), 'signed-runtime')

    await finalizePackagedRuntime({ appOutDir, variant: 'full', platform: 'win32' })

    expect(existsSync(join(llama, 'llama-server.exe'))).toBe(true)
    expect(existsSync(join(llama, 'llama-server.payload'))).toBe(false)
  })

  it('rejects a payload in lean and a missing payload in Windows full', async () => {
    const first = await fixture()
    await writeFile(join(first.llama, 'llama-server.payload'), 'unexpected')
    await expect(
      finalizePackagedRuntime({ appOutDir: first.appOutDir, variant: 'lean', platform: 'win32' })
    ).rejects.toThrow(/lean/i)

    const second = await fixture()
    await expect(
      finalizePackagedRuntime({ appOutDir: second.appOutDir, variant: 'full', platform: 'win32' })
    ).rejects.toThrow(/payload/i)
  })
})
