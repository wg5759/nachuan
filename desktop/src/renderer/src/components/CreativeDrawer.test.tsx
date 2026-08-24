import React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { afterEach, describe, expect, it, vi } from 'vitest'

import i18n from '../i18n'
import type { ModelInfo } from '../store'
import {
  CreativeDrawer,
  buildCreativeSubmission,
  type CreativeDrawerProps
} from './CreativeDrawer'

const models: ModelInfo[] = [
  { id: 'agnes-image', owned_by: 'agnes', modality: 'image', description: 'Agnes Image' },
  { id: 'agnes-video', owned_by: 'agnes', modality: 'video', description: 'Agnes Video' }
]

function props(
  overrides: Partial<CreativeDrawerProps> = {}
): CreativeDrawerProps {
  return {
    mode: 'image',
    onModeChange: () => undefined,
    models,
    currentModel: 'agnes-image',
    onCurrentModelChange: () => undefined,
    prompt: '一只纸船漂过西湖',
    onPromptChange: () => undefined,
    referenceImage: 'data:image/png;base64,reference',
    onReferenceImageChange: () => undefined,
    onSubmit: () => undefined,
    ...overrides
  }
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('CreativeDrawer', () => {
  it.each([
    ['image', 'agnes-image', '生成图片'],
    ['video', 'agnes-video', '生成视频']
  ] as const)(
    'SSR renders the controlled %s mode with only its real model choices',
    (mode, currentModel, submitLabel) => {
      const html = renderToStaticMarkup(
        <CreativeDrawer {...props({ mode, currentModel })} />
      )

      expect(html).toContain(`data-creative-mode="${mode}"`)
      expect(html).toContain(`value="${currentModel}" selected=""`)
      expect(html).toContain('一只纸船漂过西湖')
      if (mode === 'video') {
        expect(html).toContain('src="data:image/png;base64,reference"')
      } else {
        expect(html).not.toContain('参考图')
        expect(html).not.toContain('type="file"')
      }
      expect(html).toContain(submitLabel)
      expect(html).not.toMatch(/比例|分辨率|数量|时长/)
      expect(html).not.toContain(mode === 'image' ? 'agnes-video' : 'agnes-image')
    }
  )

  it('submits the exact controlled values without reading window.api', () => {
    const apiAccess = vi.fn(() => {
      throw new Error('CreativeDrawer must not read window.api')
    })
    const fakeWindow = {}
    Object.defineProperty(fakeWindow, 'api', { get: apiAccess })
    vi.stubGlobal('window', fakeWindow)
    expect(buildCreativeSubmission(
      'image',
      'agnes-image',
      '一只纸船漂过西湖',
      'data:image/png;base64,reference'
    )).toEqual({
      mode: 'image',
      model: 'agnes-image',
      prompt: '一只纸船漂过西湖',
      referenceImage: null
    })
    expect(apiAccess).not.toHaveBeenCalled()
  })

  it('offers a real reference-image picker without speculative media controls', () => {
    const html = renderToStaticMarkup(
      <CreativeDrawer {...props({ mode: 'video', currentModel: 'agnes-video', referenceImage: null })} />
    )

    expect(html).toContain('type="file"')
    expect(html).toContain('accept="image/*"')
    expect(html).toContain('添加参考图')
    expect(html).not.toMatch(/比例|分辨率|数量|时长/)
  })

  it('keeps the reference image only for a real video submission', () => {
    expect(buildCreativeSubmission(
      'video',
      'agnes-video',
      '一只纸船漂过西湖',
      'data:image/png;base64,reference'
    )).toEqual({
      mode: 'video',
      model: 'agnes-video',
      prompt: '一只纸船漂过西湖',
      referenceImage: 'data:image/png;base64,reference'
    })
  })

  it('renders the creation surface in English when the app language is English', async () => {
    await i18n.changeLanguage('en')
    const html = renderToStaticMarkup(
      <CreativeDrawer
        {...props({ mode: 'video', currentModel: 'agnes-video', referenceImage: null })}
      />
    )

    expect(html).toContain('Create')
    expect(html).toContain('Generate video')
    expect(html).not.toMatch(/创作|图片|视频|参考图|生成/)
    await i18n.changeLanguage('zh')
  })
})
