export type ChatTurnMode = 'direct' | 'agent' | 'exec'

export interface InitialChatTurnModeInput {
  hasImages: boolean
  forceExec: boolean
  actionTask: boolean
  hasTargetWorkdir: boolean
}

/**
 * Ordinary desktop text enters the unified Agent Turn.  Direct mode remains
 * only for multimodal/media paths that use their own typed endpoints, while
 * side effects stay behind the capability-gated execution path.
 */
export function initialChatTurnMode(input: InitialChatTurnModeInput): ChatTurnMode {
  if (input.hasImages) return 'direct'
  if (input.forceExec || input.actionTask || input.hasTargetWorkdir) return 'exec'
  return 'agent'
}

/** Fleet ids are routing policies, not concrete provider model ids. */
export function concreteAgentModel(selected: string | null | undefined): string | undefined {
  const value = String(selected ?? '').trim()
  if (!value || value === 'nachuan' || value === 'nachuan-ultra') return undefined
  return value
}

/** Human-readable projection of the backend's closed Agent outcome contract. */
export function agentOutcomeLabelZh(
  outcome: string | null | undefined,
  blocked?: boolean
): string {
  switch (outcome) {
    case 'completed':
      return '已完成并核验'
    case 'completed_unverified':
      return '已完成，未独立核验'
    case 'accepted_async':
      return '已受理，后台处理中'
    case 'rejected_capacity':
      return '未执行：容量已满'
    case 'partial':
      return '仅部分完成'
    case 'failed':
      return '执行失败'
    case 'blocked':
      return '已阻断'
    default:
      return blocked ? '已阻断' : '状态未确认'
  }
}
