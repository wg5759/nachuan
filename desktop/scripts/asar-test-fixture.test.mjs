import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Writable } from 'node:stream'

import { afterEach, expect, it } from 'vitest'

import { createSettledAsarPackage } from './asar-test-fixture.mjs'

const roots = []

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { force: true, recursive: true })))
}, 60_000)

it('waits for an ASAR write stream that is returned before finish', async () => {
  const root = await mkdtemp(join(tmpdir(), 'nachuan-asar-settle-'))
  roots.push(root)
  const destination = join(root, 'app.asar')
  let streamFinished = false
  const stream = new Writable({
    write(_chunk, _encoding, callback) {
      callback()
    }
  })
  stream.once('finish', () => {
    streamFinished = true
  })

  const createPackage = async () => {
    setTimeout(() => stream.end(), 25)
    return stream
  }

  await createSettledAsarPackage(root, destination, {
    createPackage,
    verifyArchive: false
  })
  expect(streamFinished).toBe(true)
})
