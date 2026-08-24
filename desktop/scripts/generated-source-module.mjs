import { createHash } from 'node:crypto'
import { lstat, readFile, realpath, writeFile } from 'node:fs/promises'
import { dirname, isAbsolute, resolve, sep } from 'node:path'

const MAX_GENERATED_SOURCE_BYTES = 1024 * 1024

function pathKey(path) {
  const key = resolve(path).split(sep).join('/')
  return process.platform === 'win32' ? key.toLowerCase() : key
}

function samePath(left, right) {
  return pathKey(left) === pathKey(right)
}

function statIdentity(info) {
  return `${info.dev}:${info.ino}:${info.size}:${info.mtimeNs}:${info.ctimeNs}:${info.birthtimeNs}`
}

function checkedBytes(content) {
  const bytes = Buffer.isBuffer(content) ? Buffer.from(content) : Buffer.from(String(content), 'utf8')
  if (!bytes.length || bytes.length > MAX_GENERATED_SOURCE_BYTES) {
    throw new Error('generated source module bytes must be bounded and non-empty')
  }
  return bytes
}

async function checkedOutputPath(output) {
  const raw = String(output || '')
  const absolute = resolve(raw)
  if (!isAbsolute(raw) || !samePath(raw, absolute)) {
    throw new Error('generated source module path must be canonical and absolute')
  }
  const parent = dirname(absolute)
  const parentInfo = await lstat(parent)
  if (!parentInfo.isDirectory() || parentInfo.isSymbolicLink()) {
    throw new Error('generated source module parent must be a real directory')
  }
  if (!samePath(await realpath(parent), parent)) {
    throw new Error('generated source module parent must not traverse filesystem redirects')
  }
  return absolute
}

async function readStableRegularFile(path) {
  const before = await lstat(path, { bigint: true })
  if (
    !before.isFile() ||
    before.isSymbolicLink() ||
    before.size <= 0n ||
    before.size > BigInt(MAX_GENERATED_SOURCE_BYTES)
  ) {
    throw new Error('generated source module must be a bounded regular file')
  }
  if (!samePath(await realpath(path), path)) {
    throw new Error('generated source module must not traverse filesystem redirects')
  }
  const identity = statIdentity(before)
  const bytes = await readFile(path)
  const after = await lstat(path, { bigint: true })
  if (statIdentity(after) !== identity || bytes.length !== Number(before.size)) {
    throw new Error('generated source module changed while reading')
  }
  return { bytes, identity }
}

export async function materializeGeneratedSourceModule({ output, content, operation = 'write' } = {}) {
  if (operation !== 'write' && operation !== 'check') {
    throw new Error('generated source module operation must be write or check')
  }
  const path = await checkedOutputPath(output)
  const expected = checkedBytes(content)
  if (operation === 'write') {
    try {
      const current = await lstat(path)
      if (!current.isFile() || current.isSymbolicLink()) {
        throw new Error('generated source module destination must be a regular file')
      }
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error
    }
    await writeFile(path, expected, { flag: 'w' })
  }
  const actual = await readStableRegularFile(path)
  if (!actual.bytes.equals(expected)) {
    throw new Error('generated source module bytes do not match the frozen release inputs')
  }
  return {
    operation,
    sha256: createHash('sha256').update(actual.bytes).digest('hex'),
    size: actual.bytes.length
  }
}
