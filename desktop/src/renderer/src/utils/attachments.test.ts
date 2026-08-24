import { describe, expect, it } from 'vitest'
import { MAX_PENDING_IMAGES, planPickedFiles, type PickableFile } from './attachments'

const file = (name: string, type: string): PickableFile => ({ name, type })

describe('planPickedFiles', () => {
  it('stages selected images instead of routing them as immediate sends', () => {
    const plan = planPickedFiles([file('a.png', 'image/png')], 0)
    expect(plan.images.map((f) => f.name)).toEqual(['a.png'])
    expect(plan.videos).toHaveLength(0)
    expect(plan.unsupported).toHaveLength(0)
  })

  it('caps pending images at ten including already staged images', () => {
    const many = Array.from({ length: 12 }, (_, i) => file(`${i}.jpg`, 'image/jpeg'))
    const full = planPickedFiles(many, 0)
    expect(full.images).toHaveLength(MAX_PENDING_IMAGES)
    expect(full.overflowImages).toBe(2)

    const almostFull = planPickedFiles([file('next.webp', 'image/webp'), file('extra.png', 'image/png')], 9)
    expect(almostFull.images.map((f) => f.name)).toEqual(['next.webp'])
    expect(almostFull.overflowImages).toBe(1)
  })

  it('keeps text, video, and unsupported files separate', () => {
    const plan = planPickedFiles([
      file('note.md', ''),
      file('clip.mp4', 'video/mp4'),
      file('archive.zip', 'application/zip')
    ])

    expect(plan.texts.map((f) => f.name)).toEqual(['note.md'])
    expect(plan.videos.map((f) => f.name)).toEqual(['clip.mp4'])
    expect(plan.unsupported.map((f) => f.name)).toEqual(['archive.zip'])
  })
})
