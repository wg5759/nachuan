import React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'

import { AppHeaderView } from './AppHeader'

describe('unified app header', () => {
  it('keeps global model state in the header without duplicating primary navigation', () => {
    const html = renderToStaticMarkup(
      <AppHeaderView
        runtimeKind="web"
        engineTone="online"
        engineLabel="引擎在线"
        modelControl={<select aria-label="当前模型"><option>纳川·自动</option></select>}
        onToggleNavigation={() => undefined}
        onToggleBrowser={() => undefined}
      />
    )

    expect(html).toContain('纳川')
    expect(html).toContain('一处连接，协同所有模型')
    expect(html).toContain('引擎在线')
    expect(html).not.toContain('打开创作面板')
    expect(html).not.toContain('打开设置')
    expect(html).not.toContain('>创作<')
    expect(html).not.toContain('文件</button>')
    expect(html).not.toContain('内置浏览器')
    expect(html).toContain('nachuan-header--web')
  })

  it('keeps Electron-only browser control out of the Web header', () => {
    const html = renderToStaticMarkup(
      <AppHeaderView
        runtimeKind="electron"
        engineTone="offline"
        engineLabel="引擎离线"
        modelControl={null}
        onToggleNavigation={() => undefined}
        onToggleBrowser={() => undefined}
      />
    )

    expect(html).toContain('内置浏览器')
    expect(html).not.toContain('关闭创作面板')
    expect(html).toContain('nachuan-header--electron')
  })
})
