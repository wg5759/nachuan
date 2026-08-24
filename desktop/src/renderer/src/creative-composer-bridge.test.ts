import { describe, expect, it } from 'vitest'

import { prepareCreativeComposerSubmission } from './creative-composer-bridge'

describe('creative drawer to conversation bridge', () => {
  it('preserves the chosen model and turns the optional reference preview into a real composer file', async () => {
    const prepared = await prepareCreativeComposerSubmission({
      id: 42,
      mode: 'video',
      model: 'agnes-video',
      prompt: '让纸船沿着水面缓慢向前',
      referenceImage: 'data:image/png;base64,iVBORw0KGgo='
    })

    expect(prepared.id).toBe(42)
    expect(prepared.model).toBe('agnes-video')
    expect(prepared.prompt).toBe('让纸船沿着水面缓慢向前')
    expect(prepared.images).toHaveLength(1)
    expect(prepared.images[0]?.file).toBeInstanceOf(File)
    expect(prepared.images[0]?.file.type).toBe('image/png')
    expect(prepared.images[0]?.url).toBe('data:image/png;base64,iVBORw0KGgo=')
  })

  it('keeps a text-to-image request attachment-free', async () => {
    const prepared = await prepareCreativeComposerSubmission({
      id: 43,
      mode: 'image',
      model: 'agnes-image',
      prompt: '西湖上的纸船',
      referenceImage: null
    })

    expect(prepared.images).toEqual([])
  })
})
