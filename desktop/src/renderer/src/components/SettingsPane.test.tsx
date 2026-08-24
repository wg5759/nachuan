import React from 'react'
import { readFileSync } from 'node:fs'
import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'

import { SettingsPaneView } from './SettingsPane'

describe('settings surface', () => {
  it('exposes only real persisted preferences and real destinations', () => {
    const html = renderToStaticMarkup(
      <SettingsPaneView
        language="zh"
        soundEnabled
        onLanguageChange={() => undefined}
        onSoundChange={() => undefined}
        onOpenConnections={() => undefined}
        onOpenAbout={() => undefined}
      />
    )

    expect(html).toContain('常规设置')
    expect(html).toContain('完成提示音')
    expect(html).toContain('简体中文')
    expect(html).toContain('连接中心')
    expect(html).toContain('关于纳川')
    expect(html).toContain('平台结果未知：人工结案')
    expect(html).toContain('只读检查')
    expect(html).toContain('NO REPLAY')
    expect(html).not.toContain('主题')
  })

  it('keeps the Electron native menu language synchronized', () => {
    const source = readFileSync(new URL('./SettingsPane.tsx', import.meta.url), 'utf8')
    expect(source).toContain('window.api.setLang(next)')
    expect(source).toContain('window.api.inspectChannelRecovery')
    expect(source).toContain('window.api.closeChannelRecovery')
    expect(source).toContain("window.api.runtimeKind === 'electron'")
    expect(source).toContain('我确认平台结果未知，禁止自动重放')
    expect(source).toContain('我确认只做结案，不恢复、不重发')
  })
})
