import type { Approval } from './api'
import type { ChatDisplayMsg } from './store'

type MessageUpdater =
  | ChatDisplayMsg[]
  | ((previous: ChatDisplayMsg[]) => ChatDisplayMsg[])

export type SetConversationMessages = (
  conversationId: string,
  updater: MessageUpdater
) => void

/** Return the exact task frozen by the server for an approved replay. */
export function approvalExecutionTask(approval: Approval): string {
  const rawSpec = approval.payload?.execution_spec
  if (rawSpec && typeof rawSpec === 'object' && !Array.isArray(rawSpec)) {
    const frozenTask = (rawSpec as Record<string, unknown>).task
    if (typeof frozenTask === 'string' && frozenTask.length > 0) return frozenTask
  }
  const payloadTask = approval.payload?.task
  if (typeof payloadTask === 'string' && payloadTask.length > 0) return payloadTask
  return approval.summary
}

function frozenConversationId(approval: Approval): string | null {
  const rawSpec = approval.payload?.execution_spec
  if (!rawSpec || typeof rawSpec !== 'object' || Array.isArray(rawSpec)) return null
  const conversationId = String(
    (rawSpec as Record<string, unknown>).conversation_id ?? ''
  ).trim()
  if (!conversationId || conversationId.length > 160) return null
  if ([...conversationId].some((character) => character.charCodeAt(0) < 32)) return null
  return conversationId
}

/** Route an asynchronous approval result to the conversation frozen by the server. */
export function routeApprovalExecutionResult({
  approval,
  text,
  meta,
  now = Date.now(),
  setConversationMessages
}: {
  approval: Approval
  text: string
  meta: string
  now?: number
  setConversationMessages: SetConversationMessages
}): boolean {
  const conversationId = frozenConversationId(approval)
  if (!conversationId || !text) return false
  setConversationMessages(conversationId, (previous) => [
    ...previous,
    {
      role: 'assistant',
      content: text,
      meta,
      ts: now,
      completedAt: now
    }
  ])
  return true
}
