import React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it, vi } from 'vitest'

import KbPane, { prepareKbTextFile } from './KbPane'

describe('knowledge-base local text file preparation', () => {
  it('reads a supported local file into the editor without importing it', async () => {
    const readText = vi.fn(async () => '# 报销规则\n仅用于本地预填。')

    const prepared = await prepareKbTextFile({
      name: '公司报销规定.md',
      type: 'text/markdown',
      size: 38,
      text: readText
    })

    expect(prepared).toEqual({
      title: '公司报销规定.md',
      text: '# 报销规则\n仅用于本地预填。'
    })
    expect(readText).toHaveBeenCalledTimes(1)
  })

  it('offers an explicit local text-file picker before the existing import button', () => {
    const html = renderToStaticMarkup(<KbPane />)

    expect(html).toContain('type="file"')
    expect(html).toContain('选择本地文本文件')
    expect(html).toContain('.md')
    expect(html).toContain('>导入</button>')
  })

  it('rejects an oversized local text file before reading it into renderer memory', async () => {
    const readText = vi.fn(async () => '不应读取')

    await expect(
      prepareKbTextFile({
        name: '超大文档.md',
        type: 'text/markdown',
        size: 4 * 1024 * 1024 + 1,
        text: readText
      })
    ).rejects.toThrow(/4MB/)
    expect(readText).not.toHaveBeenCalled()
  })
})
