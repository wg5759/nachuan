import { existsSync, lstatSync, readdirSync, realpathSync, renameSync } from 'node:fs'
import { dirname, join, parse, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

import { sign } from '@electron/windows-sign'

import { writePreparedRuntimeManifest } from './prepare-pack.mjs'

const here = dirname(fileURLToPath(import.meta.url))
const repoRoot = resolve(here, '..', '..')
const enginePath = join(repoRoot, 'dist', 'engine.exe')
const MAX_ENGINE_BYTES = 1024 * 1024 * 1024
const MAX_RUNTIME_BYTES = 2 * 1024 * 1024 * 1024
const WINDOWS_RUNTIME_LIBRARY = /\.dll$/i

function assertNoRedirectingComponents(path, label) {
  const absolute = resolve(path)
  const root = parse(absolute).root
  let cursor = root
  for (const part of absolute.slice(root.length).split(sep).filter(Boolean)) {
    cursor = join(cursor, part)
    if (!existsSync(cursor)) throw new Error(`${label} path is missing`)
    if (lstatSync(cursor).isSymbolicLink()) {
      throw new Error(`${label} path must not contain filesystem redirects`)
    }
  }
  realpathSync.native(absolute)
}

function assertBoundedRegular(path, maxBytes, label) {
  assertNoRedirectingComponents(path, label)
  const info = lstatSync(path)
  if (info.isSymbolicLink() || !info.isFile() || info.size <= 0 || info.size > maxBytes) {
    throw new Error(`${label} must be a bounded regular file`)
  }
}

async function main() {
  if (process.platform !== 'win32') throw new Error('production engine signing is Windows-only')
  const certificateFileValue = String(process.env.WINDOWS_CERTIFICATE_FILE || '').trim()
  const certificatePassword = String(process.env.WINDOWS_CERTIFICATE_PASSWORD || '')
  if (!certificateFileValue || !certificatePassword) {
    throw new Error('WINDOWS_CERTIFICATE_FILE and WINDOWS_CERTIFICATE_PASSWORD are required')
  }
  const certificateFile = resolve(certificateFileValue)
  const variant = String(process.env.DMX_VARIANT || '').toLowerCase()
  if (!['lean', 'full'].includes(variant)) throw new Error('DMX_VARIANT must be lean or full')
  assertBoundedRegular(enginePath, MAX_ENGINE_BYTES, 'release engine')
  assertBoundedRegular(certificateFile, 16 * 1024 * 1024, 'signing certificate')

  const files = [enginePath]
  const llamaRoot = join(repoRoot, 'dist', 'llama')
  const payload = join(llamaRoot, 'llama-server.payload')
  const executable = join(llamaRoot, 'llama-server.exe')
  let serverRestoredForSigning = false
  if (variant === 'full') {
    assertBoundedRegular(payload, MAX_RUNTIME_BYTES, 'prepared llama-server payload')
    if (existsSync(executable)) throw new Error('prepared full runtime contains a second llama-server.exe')
    renameSync(payload, executable)
    serverRestoredForSigning = true
    files.push(executable)
    for (const name of readdirSync(llamaRoot).sort()) {
      if (!WINDOWS_RUNTIME_LIBRARY.test(name)) continue
      const path = join(llamaRoot, name)
      assertBoundedRegular(path, MAX_RUNTIME_BYTES, `prepared runtime library ${name}`)
      files.push(path)
    }
  }

  try {
    await sign({
      files,
      certificateFile,
      certificatePassword,
      hashes: ['sha256'],
      description: '纳川 Engine'
    })
  } finally {
    if (serverRestoredForSigning && existsSync(executable) && !existsSync(payload)) {
      renameSync(executable, payload)
    }
  }
  assertBoundedRegular(enginePath, MAX_ENGINE_BYTES, 'signed release engine')
  if (variant === 'full') assertBoundedRegular(payload, MAX_RUNTIME_BYTES, 'signed llama-server payload')
  const runtime = await writePreparedRuntimeManifest({ variant, distRoot: join(repoRoot, 'dist') })
  console.log(
    `[engine-signing] signed ${files.length} release binaries and rebuilt post-sign runtime manifest artifacts=${runtime.artifactCount}`
  )
}

try {
  await main()
} catch (error) {
  console.error(`[engine-signing] BLOCKED: ${error instanceof Error ? error.message : String(error)}`)
  process.exitCode = 1
}
