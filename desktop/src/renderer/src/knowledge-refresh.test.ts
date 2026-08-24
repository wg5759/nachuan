import { describe, expect, it, vi } from 'vitest'

import {
  publishKnowledgeDocumentsChanged,
  subscribeKnowledgeDocumentsChanged
} from './knowledge-refresh'

describe('knowledge document refresh signal', () => {
  it('notifies mounted knowledge views and supports clean unsubscription', () => {
    const target = new EventTarget()
    const listener = vi.fn()
    const unsubscribe = subscribeKnowledgeDocumentsChanged(listener, target)

    publishKnowledgeDocumentsChanged(target)
    expect(listener).toHaveBeenCalledTimes(1)

    unsubscribe()
    publishKnowledgeDocumentsChanged(target)
    expect(listener).toHaveBeenCalledTimes(1)
  })
})
