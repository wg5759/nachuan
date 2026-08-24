import { lstatSync } from 'node:fs'
import { resolve } from 'node:path'
import { finished } from 'node:stream/promises'

import { createPackage as electronCreatePackage } from '@electron/asar'

export async function createSettledAsarPackage(
  source,
  destination,
  { createPackage = electronCreatePackage, verifyArchive = true } = {}
) {
  source = resolve(source)
  destination = resolve(destination)
  const output = await createPackage(source, destination)

  // @electron/asar 3.4.1 returns its WriteStream after calling end(), but
  // before the stream has emitted finish. Reading the archive immediately can
  // therefore produce a short read padded with NUL bytes on Windows.
  if (output && typeof output === 'object' && typeof output.once === 'function') {
    if (!output.writableFinished) await finished(output, { cleanup: true })
    if (output.errored) throw output.errored
  }

  if (verifyArchive) {
    const info = lstatSync(destination)
    if (info.isSymbolicLink() || !info.isFile() || info.size <= 8) {
      throw new Error('settled ASAR fixture must be a non-empty regular archive')
    }
  }
  return destination
}
