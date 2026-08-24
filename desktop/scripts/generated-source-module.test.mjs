import { lstat, mkdtemp, readFile, realpath, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, describe, expect, it } from 'vitest'

import { materializeGeneratedSourceModule } from './generated-source-module.mjs'

const workdirs = []

afterEach(async () => {
  await Promise.all(workdirs.splice(0).map((path) => rm(path, { recursive: true, force: true })))
})

function identity(info) {
  return {
    dev: info.dev,
    ino: info.ino,
    size: info.size,
    mtimeNs: info.mtimeNs,
    ctimeNs: info.ctimeNs,
    birthtimeNs: info.birthtimeNs
  }
}

describe('generated release source module', () => {
  it('checks expected bytes without changing either file bytes or file identity', async () => {
    const root = await realpath(await mkdtemp(join(tmpdir(), 'nachuan-generated-source-')))
    workdirs.push(root)
    const output = join(root, 'generated.ts')
    const content = "export const RELEASE_BINDING = 'frozen'\n"

    await materializeGeneratedSourceModule({ output, content, operation: 'write' })
    const beforeBytes = await readFile(output)
    const beforeIdentity = identity(await lstat(output, { bigint: true }))

    await expect(
      materializeGeneratedSourceModule({ output, content, operation: 'check' })
    ).resolves.toMatchObject({ operation: 'check', size: beforeBytes.length })

    expect(await readFile(output)).toEqual(beforeBytes)
    expect(identity(await lstat(output, { bigint: true }))).toEqual(beforeIdentity)
  })

  it('fails closed on different expected bytes without repairing or rewriting the frozen file', async () => {
    const root = await realpath(await mkdtemp(join(tmpdir(), 'nachuan-generated-source-')))
    workdirs.push(root)
    const output = join(root, 'generated.ts')
    const content = "export const RELEASE_BINDING = 'frozen'\n"
    await materializeGeneratedSourceModule({ output, content, operation: 'write' })
    const beforeBytes = await readFile(output)
    const beforeIdentity = identity(await lstat(output, { bigint: true }))

    await expect(
      materializeGeneratedSourceModule({
        output,
        content: "export const RELEASE_BINDING = 'drifted'\n",
        operation: 'check'
      })
    ).rejects.toThrow(/bytes do not match/i)
    expect(await readFile(output)).toEqual(beforeBytes)
    expect(identity(await lstat(output, { bigint: true }))).toEqual(beforeIdentity)
  })
})
