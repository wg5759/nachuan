import React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'

import FilesPane from './FilesPane'

describe('unified files workspace', () => {
  it('makes the knowledge base reachable from the primary Files destination', () => {
    const html = renderToStaticMarkup(<FilesPane />)

    expect(html).toContain('data-files-workspace="true"')
    expect(html).toContain('>知识库</button>')
    expect(html).toContain('>媒体工具</button>')
    expect(html).toContain('选择本地文本文件')
  })
})
