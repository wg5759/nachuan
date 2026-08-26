import { createInstance, type i18n as I18nInstance } from 'i18next'
import React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { I18nextProvider, initReactI18next } from 'react-i18next'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'

import en from '../locales/en.json'
import zh from '../locales/zh.json'
import { useAppStore } from '../store'
import type { PluginUiSnapshot } from '../../../plugin-ui-contract'
import LeftPane, { workspaceViewsFromPluginSnapshot } from './LeftPane'

let originalState: ReturnType<typeof useAppStore.getState>

async function translationInstance(language: 'zh' | 'en'): Promise<I18nInstance> {
  const instance = createInstance()
  await instance.use(initReactI18next).init({
    resources: { zh: { translation: zh }, en: { translation: en } },
    lng: language,
    fallbackLng: 'en',
    interpolation: { escapeValue: false }
  })
  return instance
}

async function renderLeftPane(
  activePrimary: 'chat' | 'create' | 'connections' | 'files' | 'settings' = 'chat'
): Promise<string> {
  const i18n = await translationInstance('zh')
  return renderToStaticMarkup(
    <I18nextProvider i18n={i18n}>
      <LeftPane activePrimary={activePrimary} onPrimaryChange={() => undefined} />
    </I18nextProvider>
  )
}

describe('LeftPane unified navigation', () => {
  beforeEach(() => {
    originalState = useAppStore.getState()
    useAppStore.setState({
      view: 'chat',
      currentConvId: null,
      conversations: []
    })
  })

  afterEach(() => {
    useAppStore.setState(originalState, true)
  })

  it('renders the controlled five-destination primary navigation', async () => {
    const html = await renderLeftPane('files')

    expect(html.match(/data-primary-destination=/g)).toHaveLength(5)
    for (const destination of ['chat', 'create', 'connections', 'files', 'settings']) {
      expect(html).toContain(`data-primary-destination="${destination}"`)
    }
    expect(html).toMatch(/data-primary-destination="files"[^>]*aria-current="page"/)
  })

  it('keeps core workspaces static and admits orchestration only from its closed plugin slot', async () => {
    const html = await renderLeftPane('chat')

    for (const destination of [
      'brain',
      'kb',
      'studio',
      'sync',
      'mcp',
      'usage',
      'about'
    ]) {
      expect(html).toContain(`data-workspace-destination="${destination}"`)
    }
    expect(html).not.toContain('data-workspace-destination="orchestrate"')
    const snapshot: PluginUiSnapshot = {
      schema: 'nachuan.plugin-ui.snapshot.v1',
      slots: [
        {
          slot_id: 'workspace.orchestration',
          surface: 'workspace.menu',
          component: 'orchestrate',
          order: 600,
          plugin_id: 'com.nachuan.ui.orchestration',
          plugin_version: '1.0.0',
          artifact_sha256: 'a'.repeat(64)
        }
      ]
    }
    expect(workspaceViewsFromPluginSnapshot(snapshot)).toEqual([
      'brain',
      'kb',
      'studio',
      'sync',
      'mcp',
      'orchestrate',
      'usage',
      'about'
    ])
    expect(html).toContain('工作区')
    expect(html).not.toMatch(/[💻🌐💬🗄🗑]/u)
  })
})
