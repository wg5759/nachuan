import {
  constants,
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  realpathSync,
  rmSync
} from 'node:fs'
import { basename, dirname, join, parse, resolve, sep } from 'node:path'

const MAX_ENGINE_BYTES = 1024 * 1024 * 1024

function assertNoRedirectingComponents(path, label) {
  const absolute = resolve(path)
  const root = parse(absolute).root
  let cursor = root
  for (const part of absolute.slice(root.length).split(sep).filter(Boolean)) {
    cursor = join(cursor, part)
    if (!existsSync(cursor)) break
    if (lstatSync(cursor).isSymbolicLink()) {
      throw new Error(`${label} path must not contain filesystem redirects`)
    }
  }
}

function assertBoundedRegular(path, label) {
  assertNoRedirectingComponents(path, label)
  const info = lstatSync(path)
  if (info.isSymbolicLink() || !info.isFile() || info.size <= 0 || info.size > MAX_ENGINE_BYTES) {
    throw new Error(`${label} must be a bounded regular file`)
  }
  realpathSync.native(path)
}

/**
 * Freeze the exact engine bytes that electron-builder may package.
 *
 * Production CI signs dist/engine.exe first and only then calls this function.
 * The destination deliberately has no executable extension: electron-builder
 * 26 signs extraResources according to the source filename, so using the
 * signed .exe directly would append Authenticode after its digest was compiled
 * into app.asar.  electron-builder.yml restores the installed name engine.exe.
 */
export function stageEnginePayload({ sourceEngine, stagedEngine }) {
  sourceEngine = resolve(sourceEngine)
  stagedEngine = resolve(stagedEngine)
  if (basename(stagedEngine) !== 'engine.payload') {
    throw new Error('staged engine destination must be exactly engine.payload')
  }
  if (sourceEngine === stagedEngine) throw new Error('source and staged engine paths must differ')

  assertBoundedRegular(sourceEngine, 'release engine source')
  const parent = dirname(stagedEngine)
  mkdirSync(parent, { recursive: true })
  assertNoRedirectingComponents(parent, 'staged engine parent')
  const parentInfo = lstatSync(parent)
  if (parentInfo.isSymbolicLink() || !parentInfo.isDirectory()) {
    throw new Error('staged engine parent must be a real directory')
  }
  realpathSync.native(parent)

  if (existsSync(stagedEngine)) {
    const old = lstatSync(stagedEngine)
    if (old.isSymbolicLink() || !old.isFile()) {
      throw new Error('refusing to replace redirected or special staged engine')
    }
    rmSync(stagedEngine, { force: true })
  }
  copyFileSync(sourceEngine, stagedEngine, constants.COPYFILE_EXCL)
  assertBoundedRegular(stagedEngine, 'staged release engine')
  return stagedEngine
}
