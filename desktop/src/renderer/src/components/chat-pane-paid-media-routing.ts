import type { ChatDisplayMsg } from '../store'

type MessageUpdater = ChatDisplayMsg[] | ((previous: ChatDisplayMsg[]) => ChatDisplayMsg[])

export type SetConversationMessages = (
  conversationId: string,
  updater: MessageUpdater
) => void

export interface PaidMediaMessageTarget {
  conversationId: string
  messageTs?: number
  operationId?: string
}

export interface PaidVideoSubmissionGate {
  tryBegin(): boolean
  finish(): void
  isActive(): boolean
}

/**
 * One renderer may have only one user-initiated paid-video submission in flight.
 * The synchronous gate closes before the native confirmation can be reached, so
 * a repeated click or Enter cannot create a second confirmation/operation.
 */
export function createPaidVideoSubmissionGate(
  onActiveChange: (active: boolean) => void = () => {}
): PaidVideoSubmissionGate {
  let active = false
  return {
    tryBegin(): boolean {
      if (active) return false
      active = true
      onActiveChange(true)
      return true
    },
    finish(): void {
      if (!active) return
      active = false
      onActiveChange(false)
    },
    isActive(): boolean {
      return active
    }
  }
}

type PaidMediaMessagePatch =
  | Partial<ChatDisplayMsg>
  | ((message: ChatDisplayMsg) => ChatDisplayMsg)

/**
 * Patch the assistant bubble that owns one paid operation. The target is captured
 * before any prompt/IPC/provider await, so switching conversations or inserting
 * messages cannot redirect a financial recovery/result update.
 */
export function patchPaidMediaMessage(
  setConversationMessages: SetConversationMessages,
  target: PaidMediaMessageTarget,
  patch: PaidMediaMessagePatch
): boolean {
  if (!target.conversationId || (target.messageTs === undefined && !target.operationId)) {
    return false
  }

  let applied = false
  setConversationMessages(target.conversationId, (previous) => {
    const next = previous.map((candidate) => {
      if (applied || candidate.role !== 'assistant') return candidate
      if (target.messageTs !== undefined && candidate.ts !== target.messageTs) return candidate
      if (
        !target.operationId &&
        target.messageTs !== undefined &&
        candidate.startedAt !== target.messageTs
      ) {
        return candidate
      }
      if (
        target.operationId &&
        candidate.paidMediaOperation?.operationId !== target.operationId
      ) {
        return candidate
      }
      applied = true
      return typeof patch === 'function' ? patch(candidate) : { ...candidate, ...patch }
    })
    return applied ? next : previous
  })
  return applied
}

/** Flush only after the exact captured bubble was patched. */
export function patchPaidMediaMessageAndFlush(
  setConversationMessages: SetConversationMessages,
  target: PaidMediaMessageTarget,
  patch: PaidMediaMessagePatch,
  flush: () => boolean
): boolean {
  return patchPaidMediaMessage(setConversationMessages, target, patch) && flush()
}
