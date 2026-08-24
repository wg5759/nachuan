import { existsSync } from 'node:fs'
import { lstat, rename } from 'node:fs/promises'
import { join } from 'node:path'

import { verifyPackagedLicenseEvidence } from './license-stage.mjs'
import { verifyPackagedPythonPayloadProvenance } from './python-payload-provenance.mjs'

function checkedVariant(value) {
  const variant = String(value || '').toLowerCase()
  if (!['lean', 'full'].includes(variant)) throw new Error(`invalid package variant: ${value}`)
  return variant
}

export async function finalizePackagedRuntime({ appOutDir, variant, platform }) {
  variant = checkedVariant(variant)
  const llamaRoot = join(appOutDir, 'resources', 'llama')
  const payload = join(llamaRoot, 'llama-server.payload')
  const windowsServer = join(llamaRoot, 'llama-server.exe')
  const hasPayload = existsSync(payload)

  if (platform !== 'win32') {
    if (hasPayload) throw new Error('llama-server.payload is forbidden outside Windows packaging')
    return
  }
  if (variant === 'lean') {
    if (hasPayload || existsSync(windowsServer)) {
      throw new Error('lean package must not contain a llama-server payload')
    }
    return
  }
  if (!hasPayload) throw new Error('Windows full package is missing llama-server.payload')
  if (existsSync(windowsServer)) throw new Error('Windows full package contains two llama-server sources')
  const info = await lstat(payload)
  if (info.isSymbolicLink() || !info.isFile() || info.size <= 0) {
    throw new Error('llama-server.payload must be a non-empty regular file')
  }
  await rename(payload, windowsServer)
}

/** electron-builder hook: runs after extraResources copy and before final signing. */
export async function afterPack(context) {
  await finalizePackagedRuntime({
    appOutDir: context.appOutDir,
    variant: process.env.DMX_VARIANT,
    platform: context.electronPlatformName
  })
  await verifyPackagedPythonPayloadProvenance({
    appOutDir: context.appOutDir,
    engineName: context.electronPlatformName === 'win32' ? 'engine.exe' : 'engine'
  })
  await verifyPackagedLicenseEvidence({
    appOutDir: context.appOutDir,
    deferredNativeArtifacts: ['resources/elevate.exe']
  })
}
