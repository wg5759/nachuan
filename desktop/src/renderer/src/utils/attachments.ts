export const MAX_PENDING_IMAGES = 10

export interface PickableFile {
  name: string
  type: string
}

export interface PickedFilesPlan<T extends PickableFile> {
  images: T[]
  texts: T[]
  videos: T[]
  unsupported: T[]
  overflowImages: number
}

export const isImageAttachmentFile = (f: PickableFile): boolean => f.type.startsWith('image/')

export const isVideoAttachmentFile = (f: PickableFile): boolean => f.type.startsWith('video/')

export const isTextAttachmentFile = (f: PickableFile): boolean =>
  f.type.startsWith('text/') ||
  /\.(md|markdown|txt|csv|tsv|json|log|ya?ml|ini|toml|xml|html?|tex|rtf|srt|vtt)$/i.test(f.name)

export function planPickedFiles<T extends PickableFile>(
  files: T[],
  existingImages = 0,
  maxImages = MAX_PENDING_IMAGES
): PickedFilesPlan<T> {
  const imageSlots = Math.max(0, maxImages - existingImages)
  const plan: PickedFilesPlan<T> = {
    images: [],
    texts: [],
    videos: [],
    unsupported: [],
    overflowImages: 0
  }

  for (const f of files) {
    if (isImageAttachmentFile(f)) {
      if (plan.images.length < imageSlots) plan.images.push(f)
      else plan.overflowImages += 1
    } else if (isTextAttachmentFile(f)) {
      plan.texts.push(f)
    } else if (isVideoAttachmentFile(f)) {
      plan.videos.push(f)
    } else {
      plan.unsupported.push(f)
    }
  }

  return plan
}
