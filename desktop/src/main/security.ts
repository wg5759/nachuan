export function debugPolicy(input: {
  isPackaged: boolean
  enableCdp: boolean
  enableDevTools: boolean
}): { enableCdp: boolean; enableDevTools: boolean } {
  if (input.isPackaged) return { enableCdp: false, enableDevTools: false }
  return { enableCdp: input.enableCdp, enableDevTools: input.enableDevTools }
}

export function automaticUpdatePolicy(input: {
  isPackaged: boolean
  trustConfigured: boolean
  releaseTier: 'disabled' | 'early-access' | 'production'
  authenticodeValid: boolean
}): { enabled: boolean; autoDownload: boolean; autoInstallOnQuit: boolean } {
  const trustedTier =
    input.releaseTier === 'early-access' ||
    (input.releaseTier === 'production' && input.authenticodeValid)
  const enabled = input.isPackaged && input.trustConfigured && trustedTier
  // Both are always manual at the electron-updater layer. The project verifies
  // the independent manifest and final file before explicitly installing.
  return { enabled, autoDownload: false, autoInstallOnQuit: false }
}

export function windowSecurityPreferences(
  preload: string,
  options: { webview: boolean; devTools?: boolean }
): {
  preload: string
  contextIsolation: true
  nodeIntegration: false
  sandbox: true
  webviewTag: boolean
  webSecurity: true
  devTools: boolean
} {
  return {
    preload,
    contextIsolation: true,
    nodeIntegration: false,
    sandbox: true,
    webviewTag: options.webview,
    webSecurity: true,
    devTools: options.devTools === true
  }
}

export function permissionAllowed(permission: string, isTrustedMainRenderer: boolean): boolean {
  return permission === 'media' && isTrustedMainRenderer
}

export function ipcSenderAllowed(senderId: number, expectedSenderId: number | null): boolean {
  return Number.isInteger(senderId) && senderId > 0 && senderId === expectedSenderId
}

export function isHttpUrl(raw: string): boolean {
  try {
    const url = new URL(raw)
    return url.protocol === 'http:' || url.protocol === 'https:'
  } catch {
    return false
  }
}

export function isLoopbackRendererUrl(raw: string): boolean {
  try {
    const url = new URL(raw)
    return (
      (url.protocol === 'http:' || url.protocol === 'https:') &&
      (url.hostname === '127.0.0.1' || url.hostname === 'localhost' || url.hostname === '[::1]')
    )
  } catch {
    return false
  }
}

export function isTrustedRendererNavigation(raw: string, trustedEntry: string): boolean {
  try {
    const candidate = new URL(raw)
    const trusted = new URL(trustedEntry)
    if (candidate.protocol !== trusted.protocol) return false
    if (trusted.protocol === 'file:') {
      return (
        !candidate.host &&
        !candidate.username &&
        !candidate.password &&
        candidate.pathname === trusted.pathname
      )
    }
    if (!isLoopbackRendererUrl(trustedEntry)) return false
    return candidate.origin === trusted.origin && candidate.pathname === trusted.pathname
  } catch {
    return false
  }
}
