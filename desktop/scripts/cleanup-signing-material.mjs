import { readdir, unlink } from 'node:fs/promises'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  checkedFixedSigningMaterialFile,
  checkedSigningMaterialRoot,
  FIXED_SIGNING_MATERIAL_NAMES
} from './signing-material-paths.mjs'

const scriptPath = fileURLToPath(import.meta.url)
const MATERIALIZED_PREFIX = /^nachuan-(?:root-authorization\.json|leaf-(?:signing-keys\.json|\d+\.pem))$/

async function signingFiles(root) {
  const names = (await readdir(root)).filter((name) => MATERIALIZED_PREFIX.test(name)).sort()
  const unexpected = names.filter((name) => !FIXED_SIGNING_MATERIAL_NAMES.has(name))
  if (unexpected.length) {
    throw new Error(`unexpected signing material residual is outside the bounded set: ${unexpected.join(',')}`)
  }
  return names
}

export async function cleanupMaterializedSigningInputs({ runnerTemp }) {
  const root = checkedSigningMaterialRoot(runnerTemp)
  const names = await signingFiles(root)
  const paths = []
  for (const name of names) {
    paths.push([
      name,
      checkedFixedSigningMaterialFile({
        root,
        pathValue: resolve(root, name),
        name,
        label: `signing material ${name}`,
        maxBytes: 1024 * 1024
      })
    ])
  }
  const removed = []
  for (const [name, path] of paths) {
    await unlink(path)
    removed.push(name)
  }
  const residual = await signingFiles(root)
  if (residual.length) {
    throw new Error(`signing material cleanup left residual files: ${residual.join(',')}`)
  }
  return { removed }
}

async function main() {
  const result = await cleanupMaterializedSigningInputs({ runnerTemp: process.env.RUNNER_TEMP })
  console.log(`[signing-cleanup] REMOVED ${result.removed.length} bounded files`)
}

if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  try {
    await main()
  } catch (error) {
    console.error(`[signing-cleanup] BLOCKED: ${error instanceof Error ? error.message : String(error)}`)
    process.exitCode = 1
  }
}
