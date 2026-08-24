export const KNOWLEDGE_DOCUMENTS_CHANGED_EVENT = 'nachuan:knowledge-documents-changed'

function browserEventTarget(target?: EventTarget): EventTarget {
  if (target) return target
  if (typeof window !== 'undefined') return window
  throw new Error('Knowledge refresh events require a browser event target')
}

export function publishKnowledgeDocumentsChanged(target?: EventTarget): void {
  browserEventTarget(target).dispatchEvent(new Event(KNOWLEDGE_DOCUMENTS_CHANGED_EVENT))
}

export function subscribeKnowledgeDocumentsChanged(
  listener: () => void,
  target?: EventTarget
): () => void {
  const eventTarget = browserEventTarget(target)
  const onChanged = (): void => listener()
  eventTarget.addEventListener(KNOWLEDGE_DOCUMENTS_CHANGED_EVENT, onChanged)
  return () => eventTarget.removeEventListener(KNOWLEDGE_DOCUMENTS_CHANGED_EVENT, onChanged)
}
