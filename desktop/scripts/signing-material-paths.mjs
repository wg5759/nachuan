import { lstatSync } from 'node:fs'
import { isAbsolute, join, parse, relative, resolve } from 'node:path'

export const ROOT_AUTHORIZATION_NAME = 'nachuan-root-authorization.json'
export const LEAF_DESCRIPTOR_NAME = 'nachuan-leaf-signing-keys.json'
export const LEAF_SLOT_NAMES = Object.freeze(
  Array.from({ length: 16 }, (_unused, index) => `nachuan-leaf-${index}.pem`)
)
export const FIXED_SIGNING_MATERIAL_NAMES = new Set([
  ROOT_AUTHORIZATION_NAME,
  LEAF_DESCRIPTOR_NAME,
  ...LEAF_SLOT_NAMES
])

function samePath(left, right) {
  const normalizedLeft = resolve(left)
  const normalizedRight = resolve(right)
  return process.platform === 'win32'
    ? normalizedLeft.toLowerCase() === normalizedRight.toLowerCase()
    : normalizedLeft === normalizedRight
}

export function checkedSigningMaterialRoot(value) {
  if (typeof value !== 'string' || !value || !isAbsolute(value)) {
    throw new Error('RUNNER_TEMP is required and must be an absolute signing material boundary')
  }
  const root = resolve(value)
  const volumeRoot = parse(root).root
  if (samePath(root, volumeRoot)) throw new Error('RUNNER_TEMP cannot be a filesystem root')

  let current = volumeRoot
  for (const part of relative(volumeRoot, root).split(/[\\/]+/).filter(Boolean)) {
    current = join(current, part)
    const info = lstatSync(current)
    if (info.isSymbolicLink()) {
      throw new Error('RUNNER_TEMP is redirected through a reparse point')
    }
  }
  const info = lstatSync(root)
  if (!info.isDirectory() || info.isSymbolicLink()) {
    throw new Error('RUNNER_TEMP must be a real non-reparse directory')
  }
  return root
}

export function fixedSigningMaterialPath(root, name) {
  if (!FIXED_SIGNING_MATERIAL_NAMES.has(name)) {
    throw new Error(`refusing an unbounded signing material slot: ${name}`)
  }
  const path = join(root, name)
  if (!samePath(resolve(path, '..'), root)) {
    throw new Error(`fixed signing material slot escaped RUNNER_TEMP: ${name}`)
  }
  return path
}

export function checkedFixedSigningMaterialFile({
  root,
  pathValue,
  name,
  label,
  maxBytes
}) {
  if (typeof pathValue !== 'string' || !pathValue) throw new Error(`${label} file is required`)
  const expected = fixedSigningMaterialPath(root, name)
  if (!samePath(pathValue, expected)) {
    throw new Error(`${label} must use the fixed RUNNER_TEMP slot ${name}`)
  }
  const info = lstatSync(expected)
  if (
    info.isSymbolicLink() ||
    !info.isFile() ||
    info.size <= 0 ||
    (Number.isSafeInteger(maxBytes) && info.size > maxBytes)
  ) {
    throw new Error(`${label} must be a bounded regular non-reparse file`)
  }
  return expected
}
