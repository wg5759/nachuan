import type { CreativeSubmission } from './components/CreativeDrawer'

export interface CreativeComposerRequest extends CreativeSubmission {
  id: number
}

export interface CreativeComposerImage {
  name: string
  file: File
  url: string
  dataUrl: string
}

export interface PreparedCreativeComposerSubmission {
  id: number
  model: string
  prompt: string
  images: CreativeComposerImage[]
}

function imageFromDataUrl(dataUrl: string): CreativeComposerImage {
  const match = /^data:([^;,]+);base64,(.*)$/s.exec(dataUrl)
  if (!match || !match[1]?.startsWith('image/')) {
    throw new Error('创作参考图不是有效的图片 data URL')
  }
  const mime = match[1]
  const bytes = Uint8Array.from(atob(match[2] ?? ''), (character) => character.charCodeAt(0))
  const extension = mime.split('/')[1]?.replace(/[^a-z0-9.+-]/gi, '') || 'png'
  const file = new File([bytes], `creative-reference.${extension}`, { type: mime })
  return { name: file.name, file, url: dataUrl, dataUrl }
}

export async function prepareCreativeComposerSubmission(
  request: CreativeComposerRequest
): Promise<PreparedCreativeComposerSubmission> {
  return {
    id: request.id,
    model: request.model,
    prompt: request.prompt.trim(),
    images: request.referenceImage ? [imageFromDataUrl(request.referenceImage)] : []
  }
}
