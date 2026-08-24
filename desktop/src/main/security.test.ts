import { describe, expect, it } from 'vitest'

import {
  automaticUpdatePolicy,
  debugPolicy,
  isHttpUrl,
  ipcSenderAllowed,
  isLoopbackRendererUrl,
  isTrustedRendererNavigation,
  permissionAllowed,
  windowSecurityPreferences
} from './security'

describe('Electron production security policy', () => {
  it('enables independent early updates but never delegates download/install policy to electron-updater', () => {
    expect(
      automaticUpdatePolicy({
        isPackaged: true,
        trustConfigured: true,
        releaseTier: 'early-access',
        authenticodeValid: false
      })
    ).toEqual({
      enabled: true,
      autoDownload: false,
      autoInstallOnQuit: false
    })
    expect(
      automaticUpdatePolicy({
        isPackaged: true,
        trustConfigured: true,
        releaseTier: 'production',
        authenticodeValid: true
      })
    ).toEqual({
      enabled: true,
      autoDownload: false,
      autoInstallOnQuit: false
    })
    expect(
      automaticUpdatePolicy({
        isPackaged: true,
        trustConfigured: true,
        releaseTier: 'production',
        authenticodeValid: false
      }).enabled
    ).toBe(false)
    expect(
      automaticUpdatePolicy({
        isPackaged: false,
        trustConfigured: true,
        releaseTier: 'early-access',
        authenticodeValid: false
      }).enabled
    ).toBe(false)
  })

  it('keeps production windows sandboxed and remote debugging disabled', () => {
    expect(debugPolicy({ isPackaged: true, enableCdp: true, enableDevTools: true })).toEqual({
      enableCdp: false,
      enableDevTools: false
    })
    expect(windowSecurityPreferences('C:\\app\\preload.js', { webview: false })).toEqual({
      preload: 'C:\\app\\preload.js',
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webviewTag: false,
      webSecurity: true,
      devTools: false
    })
  })

  it('allows microphone access only to the trusted main renderer and denies every other permission', () => {
    expect(permissionAllowed('media', true)).toBe(true)
    expect(permissionAllowed('media', false)).toBe(false)
    expect(permissionAllowed('geolocation', true)).toBe(false)
    expect(permissionAllowed('notifications', true)).toBe(false)
    expect(permissionAllowed('clipboard-read', true)).toBe(false)
  })

  it('authorizes IPC only for the explicitly expected renderer', () => {
    expect(ipcSenderAllowed(42, 42)).toBe(true)
    expect(ipcSenderAllowed(42, 41)).toBe(false)
    expect(ipcSenderAllowed(42, null)).toBe(false)
  })

  it('rejects executable URL schemes and non-loopback development renderers', () => {
    expect(isHttpUrl('https://example.com/path')).toBe(true)
    expect(isHttpUrl('http://example.com/path')).toBe(true)
    expect(isHttpUrl('javascript:alert(1)')).toBe(false)
    expect(isHttpUrl('file:///C:/secret.txt')).toBe(false)
    expect(isLoopbackRendererUrl('http://127.0.0.1:5173')).toBe(true)
    expect(isLoopbackRendererUrl('http://localhost:5173')).toBe(true)
    expect(isLoopbackRendererUrl('https://attacker.example/app')).toBe(false)
  })

  it('pins renderer navigation to the exact packaged document or loopback dev route', () => {
    expect(
      isTrustedRendererNavigation(
        'file:///D:/app/out/renderer/index.html#snip',
        'file:///D:/app/out/renderer/index.html'
      )
    ).toBe(true)
    expect(
      isTrustedRendererNavigation(
        'file:///D:/Users/attacker/payload.html',
        'file:///D:/app/out/renderer/index.html'
      )
    ).toBe(false)
    expect(
      isTrustedRendererNavigation('http://127.0.0.1:5173/#snip', 'http://127.0.0.1:5173/')
    ).toBe(true)
    expect(
      isTrustedRendererNavigation('http://127.0.0.1:5173.evil.test/', 'http://127.0.0.1:5173/')
    ).toBe(false)
  })
})
