import { describe, expect, it } from 'vitest'

import {
  assertRuntimeApiMatchesDeclaration,
  ELECTRON_RUNTIME_CAPABILITIES,
  WEB_RUNTIME_CAPABILITIES
} from './runtime-capabilities'

const EXPECTED_CAPABILITY_IDS = [
  'engineProxy',
  'paidMediaOperations',
  'paidMediaAssetMaterialization',
  'approvals',
  'connections',
  'channelRecovery',
  'sync',
  'appUpdates',
  'nativeNavigationEvents',
  'nativeLanguageMenu',
  'screenSnip',
  'directoryPicker',
  'embeddedBrowser',
  'mediaSave'
] as const

describe('renderer runtime capability declarations', () => {
  it('declares the same closed capability set for Web and Electron without claiming runtime proof', () => {
    expect(ELECTRON_RUNTIME_CAPABILITIES).toBe(WEB_RUNTIME_CAPABILITIES)
    expect(WEB_RUNTIME_CAPABILITIES).toMatchObject({
      schema: 'nachuan.client-port-capabilities.v1',
      portVersion: '1.0.0',
      claimScope: 'build-contract-only',
      authoritative: false,
      runtimeReadinessIncluded: false
    })
    expect(Object.keys(WEB_RUNTIME_CAPABILITIES.capabilities)).toEqual(
      EXPECTED_CAPABILITY_IDS
    )
    for (const capability of Object.values(WEB_RUNTIME_CAPABILITIES.capabilities)) {
      expect(Object.keys(capability.surfaces)).toEqual(['electron', 'localWeb', 'teamWeb'])
    }
    expect(JSON.stringify(WEB_RUNTIME_CAPABILITIES)).not.toMatch(/"(?:ready|verified)":true/)

    const capabilities = WEB_RUNTIME_CAPABILITIES.capabilities
    expect(capabilities.appUpdates.surfaces.localWeb.declaredSupport).toBe('unsupported')
    expect(capabilities.screenSnip.surfaces.localWeb.declaredSupport).toBe('unsupported')
    expect(capabilities.directoryPicker.surfaces.localWeb.declaredSupport).toBe('unsupported')
    expect(capabilities.embeddedBrowser.surfaces.localWeb.declaredSupport).toBe('unsupported')
    expect(capabilities.embeddedBrowser.surfaces.electron.declaredSupport).toBe('implemented')
    expect(capabilities.mediaSave.surfaces.localWeb.declaredSupport).toBe(
      'implemented-with-preconditions'
    )
    expect(capabilities.channelRecovery.surfaces.electron.adapter).toBe(
      'electron-ipc-engine-session'
    )
    expect(capabilities.channelRecovery.surfaces.localWeb.adapter).toBe(
      'same-origin-http-double-header'
    )
    expect(capabilities.channelRecovery.surfaces.teamWeb.declaredSupport).toBe('planned')
  })

  it('rejects missing and undeclared runtime API methods', () => {
    const declaredMethods = Object.values(WEB_RUNTIME_CAPABILITIES.capabilities).flatMap(
      (capability) => capability.surfaces.localWeb.apiMethods
    )
    const api = Object.fromEntries(declaredMethods.map((method) => [method, () => undefined]))

    expect(() =>
      assertRuntimeApiMatchesDeclaration(
        { ...api, runtimeKind: 'web', runtimeCapabilities: WEB_RUNTIME_CAPABILITIES },
        WEB_RUNTIME_CAPABILITIES
      )
    ).not.toThrow()

    const missing = { ...api }
    delete missing.engineRequest
    expect(() =>
      assertRuntimeApiMatchesDeclaration(
        { ...missing, runtimeKind: 'web', runtimeCapabilities: WEB_RUNTIME_CAPABILITIES },
        WEB_RUNTIME_CAPABILITIES
      )
    ).toThrow(/missing.*engineRequest/i)

    expect(() =>
      assertRuntimeApiMatchesDeclaration(
        {
          ...api,
          undeclaredMethod: () => undefined,
          runtimeKind: 'web',
          runtimeCapabilities: WEB_RUNTIME_CAPABILITIES
        },
        WEB_RUNTIME_CAPABILITIES
      )
    ).toThrow(/undeclared.*undeclaredMethod/i)
  })
})
