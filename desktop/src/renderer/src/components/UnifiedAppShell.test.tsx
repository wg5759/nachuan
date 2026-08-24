import React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'

import { AppShellFrame, PrimaryNavigation } from './UnifiedAppShell'

describe('unified graphical shell', () => {
  it('keeps the five customer-facing destinations stable on every graphical target', () => {
    const html = renderToStaticMarkup(
      <PrimaryNavigation
        active="create"
        onSelect={() => undefined}
        labels={{
          chat: '对话',
          create: '创作',
          connections: '连接',
          files: '文件',
          settings: '设置'
        }}
      />
    )

    expect(html.match(/data-primary-destination=/g)).toHaveLength(5)
    for (const destination of ['chat', 'create', 'connections', 'files', 'settings']) {
      expect(html).toContain(`data-primary-destination="${destination}"`)
    }
    for (const label of ['对话', '创作', '连接', '文件', '设置']) {
      expect(html).toContain(label)
    }
    expect(html).toMatch(/data-primary-destination="create"[^>]*aria-current="page"/)
  })

  it('keeps the conversation mounted and only exposes the creative drawer in creative mode', () => {
    const renderShell = (creative: boolean): string =>
      renderToStaticMarkup(
        <AppShellFrame
          creative={creative}
          navigation={<div data-region="navigation">navigation</div>}
          conversation={<main data-region="conversation">conversation</main>}
          creativeDrawer={<div data-region="creative-controls">creative controls</div>}
        />
      )

    const ordinaryChat = renderShell(false)
    expect(ordinaryChat).toContain('data-nachuan-shell="unified"')
    expect(ordinaryChat).toContain('data-region="navigation"')
    expect(ordinaryChat).toContain('data-region="conversation"')
    expect(ordinaryChat).not.toContain('aria-label="创作面板"')
    expect(ordinaryChat).not.toContain('data-region="creative-controls"')

    const creativeChat = renderShell(true)
    expect(creativeChat).toContain('data-region="conversation"')
    expect(creativeChat).toContain('aria-label="创作面板"')
    expect(creativeChat).toContain('data-region="creative-controls"')
  })

  it('keeps an accessible name when responsive CSS hides the visible labels', () => {
    const html = renderToStaticMarkup(
      <PrimaryNavigation
        active="chat"
        onSelect={() => undefined}
        labels={{
          chat: '对话',
          create: '创作',
          connections: '连接',
          files: '文件',
          settings: '设置'
        }}
      />
    )

    for (const label of ['对话', '创作', '连接', '文件', '设置']) {
      expect(html).toContain(`aria-label="${label}"`)
    }
  })
})
