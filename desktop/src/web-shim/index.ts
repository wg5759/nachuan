// ADR-0013 Web 形态入口：在浏览器里安装与 Electron preload 同名同形的 window.api。
// 本脚本以经典 script（api-shim.js）先于 module app bundle 加载（vite.web.config.ts
// 注入 head 最前），因此 React 应用启动时 window.api 必然已就位。

import type { DesktopAPI } from '../renderer/src/env'
import {
  assertRuntimeApiMatchesDeclaration,
  WEB_RUNTIME_CAPABILITIES
} from '../runtime-capabilities'
import { createCredentialStore } from './credentials'
import { createWebHttpClient } from './http'
import { createWebEngineBridge } from './engine'
import { createWebPrivilegedApi } from './privileged'
import { createWebPaidMediaApi } from './paid-media'
import { createWebElectronOnlyApi } from './electron-only'
import { createLoginGate } from './gate'
import { establishLocalWebSession, persistLocalWebSession } from './session'

export function installWebShim(): DesktopAPI {
  const existing = (window as unknown as { api?: DesktopAPI }).api
  if (existing) {
    assertRuntimeApiMatchesDeclaration(existing, WEB_RUNTIME_CAPABILITIES)
    return existing
  }

  const credentials = createCredentialStore()
  const sessionReady = establishLocalWebSession()
  const gate = createLoginGate({
    credentials,
    verify: async (runtimeKey: string) => {
      try {
        // 裸 fetch：绕开 http 客户端，避免候选 Key 的 401 计入登录闸计数。
        const response = await fetch('/v1/models', {
          headers: { Authorization: `Bearer ${runtimeKey}` }
        })
        return response.status >= 200 && response.status < 300
      } catch {
        return false
      }
    },
    persist: (runtimeKey, approvalKey) =>
      persistLocalWebSession(runtimeKey, approvalKey),
    reload: () => {
      window.location.reload()
    }
  })
  const http = createWebHttpClient({
    credentials,
    beforeRequest: async () => {
      await sessionReady
    },
    onConsecutiveUnauthorized: () => gate.show('unauthorized')
  })
  const api: DesktopAPI = {
    runtimeKind: 'web',
    runtimeCapabilities: WEB_RUNTIME_CAPABILITIES,
    ...createWebEngineBridge(http),
    ...createWebPrivilegedApi(http),
    ...createWebPaidMediaApi(http),
    ...createWebElectronOnlyApi()
  }
  assertRuntimeApiMatchesDeclaration(api, WEB_RUNTIME_CAPABILITIES)
  ;(window as unknown as { api: DesktopAPI }).api = api
  void sessionReady.then((authenticated) => {
    if (!authenticated && !credentials.getRuntimeKey()) gate.show('missing')
  })
  return api
}

installWebShim()
