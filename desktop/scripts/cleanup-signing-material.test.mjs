import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, describe, expect, it } from 'vitest'

import { cleanupMaterializedSigningInputs } from './cleanup-signing-material.mjs'

const roots = []

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { force: true, recursive: true })))
})

async function tempRoot() {
  const root = await mkdtemp(join(tmpdir(), 'nachuan-signing-cleanup-'))
  roots.push(root)
  return root
}

describe('materialized signing input cleanup', () => {
  it('removes only the fixed bounded signing files and verifies that no residual remains', async () => {
    const runnerTemp = await tempRoot()
    const unrelated = join(runnerTemp, 'keep-me.txt')
    await writeFile(join(runnerTemp, 'nachuan-root-authorization.json'), '{}\n')
    await writeFile(join(runnerTemp, 'nachuan-leaf-signing-keys.json'), '{}\n')
    await writeFile(join(runnerTemp, 'nachuan-leaf-0.pem'), 'encrypted-key-0')
    await writeFile(join(runnerTemp, 'nachuan-leaf-15.pem'), 'encrypted-key-15')
    await writeFile(unrelated, 'preserved')

    const result = await cleanupMaterializedSigningInputs({ runnerTemp })

    expect(result.removed.sort()).toEqual([
      'nachuan-leaf-0.pem',
      'nachuan-leaf-15.pem',
      'nachuan-leaf-signing-keys.json',
      'nachuan-root-authorization.json'
    ])
    expect(await readFile(unrelated, 'utf8')).toBe('preserved')
  })

  it('rejects a reparse-point signing path and leaves a blocking residual', async () => {
    const runnerTemp = await tempRoot()
    const outside = await tempRoot()
    await mkdir(join(outside, 'target'))
    await symlink(join(outside, 'target'), join(runnerTemp, 'nachuan-leaf-0.pem'), 'junction')

    await expect(cleanupMaterializedSigningInputs({ runnerTemp })).rejects.toThrow(/reparse|symbolic|redirect/i)
  })

  it('rejects non-file signing material instead of silently claiming cleanup', async () => {
    const runnerTemp = await tempRoot()
    await mkdir(join(runnerTemp, 'nachuan-leaf-signing-keys.json'))

    await expect(cleanupMaterializedSigningInputs({ runnerTemp })).rejects.toThrow(/regular non-reparse file|non-file/i)
  })
})
