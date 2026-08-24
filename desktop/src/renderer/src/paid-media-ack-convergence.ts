import {
  isPaidMediaDeliveryProof,
  type PaidMediaDeliveryProof
} from './paid-media-journal'

export type PaidMediaAckAnchor = {
  conversationId: string
  messageTs: number
  operationId: string
  deliveryProof: PaidMediaDeliveryProof
} & (
  | { images: string[]; videoTask?: never }
  | { images?: never; videoTask: { task_id: string; model: string; prompt?: string } }
)

interface PaidMediaConversationLike {
  id: string
  messages: Array<{
    role: string
    ts?: number
    images?: string[]
    videoTask?: { task_id: string; model: string; prompt?: string }
    paidMediaOperation?: {
      operationId: string
      kind: 'image' | 'video'
      phase?: 'awaiting_result' | 'awaiting_ack'
      deliveryProof?: PaidMediaDeliveryProof
    }
  }>
}

interface PaidMediaOperationLike {
  operationId: string
  state: string
}

const MAX_ANCHORS = 128

function collectAnchors(conversations: PaidMediaConversationLike[]): PaidMediaAckAnchor[] {
  const anchors: PaidMediaAckAnchor[] = []
  for (const conversation of conversations) {
    for (const message of conversation.messages) {
      const operation = message.paidMediaOperation
      if (
        anchors.length >= MAX_ANCHORS ||
        message.role !== 'assistant' ||
        typeof message.ts !== 'number' ||
        !operation ||
        operation.phase !== 'awaiting_ack' ||
        !isPaidMediaDeliveryProof(operation.deliveryProof, operation.operationId)
      ) {
        continue
      }
      if (
        operation.kind === 'image' &&
        Array.isArray(message.images) &&
        message.images.length > 0 &&
        message.images.every((item) => typeof item === 'string' && item.length > 0)
      ) {
        anchors.push({
          conversationId: conversation.id,
          messageTs: message.ts,
          operationId: operation.operationId,
          deliveryProof: operation.deliveryProof,
          images: [...message.images]
        })
      } else if (
        operation.kind === 'video' &&
        message.videoTask?.task_id &&
        message.videoTask.model
      ) {
        anchors.push({
          conversationId: conversation.id,
          messageTs: message.ts,
          operationId: operation.operationId,
          deliveryProof: operation.deliveryProof,
          videoTask: { ...message.videoTask }
        })
      }
    }
  }
  return anchors
}

export async function convergePaidMediaAcknowledgements(input: {
  conversations: PaidMediaConversationLike[]
  unresolved: PaidMediaOperationLike[]
  verify: (anchor: PaidMediaAckAnchor) => boolean
  acknowledge: (deliveryProof: PaidMediaDeliveryProof) => Promise<unknown>
  clear: (anchor: PaidMediaAckAnchor) => boolean
}): Promise<{ acknowledged: string[]; cleared: string[] }> {
  const unresolved = new Map(
    input.unresolved.map((operation) => [operation.operationId, operation])
  )
  const acknowledged: string[] = []
  const cleared: string[] = []
  for (const anchor of collectAnchors(input.conversations)) {
    const operation = unresolved.get(anchor.operationId)
    if (!operation) {
      if (input.clear(anchor)) cleared.push(anchor.operationId)
      continue
    }
    if (operation.state !== 'result_ready' || !input.verify(anchor)) continue
    try {
      await input.acknowledge(anchor.deliveryProof)
    } catch {
      continue
    }
    acknowledged.push(anchor.operationId)
    if (input.clear(anchor)) cleared.push(anchor.operationId)
  }
  return { acknowledged, cleared }
}
