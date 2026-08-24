import type {
  DebateResult,
  OrchestrationCapabilities,
  PanelResult
} from '../api'
import type { ModelInfo } from '../store'

const NON_DIRECT_WORKFLOW_MODEL_IDS = new Set(['echo', 'nachuan', 'nachuan-ultra'])

/**
 * Manual workflow endpoints resolve every selected id as a concrete route.
 * Fleet ids are valid at the unified chat entrance, but cannot be passed to
 * panel/debate/decompose/pipeline as if they were concrete providers.
 *
 * `chat_usable` is optional for compatibility with older engines: an explicit
 * false is honored, while absence does not hide a verified legacy chat route.
 */
export function manualCollaborationModels<T extends Pick<ModelInfo, 'id' | 'chat_usable'>>(
  models: readonly T[]
): T[] {
  return models.filter(
    (model) =>
      !NON_DIRECT_WORKFLOW_MODEL_IDS.has(model.id) && model.chat_usable !== false
  )
}

type SynthesisResult = Pick<
  PanelResult | DebateResult,
  'collaboration_type' | 'judge_vote_weight'
>

export type SynthesisSummaryKey =
  | 'orch.synthesisSummary'
  | 'orch.synthesisNoReviewVote'

/** Panel/debate aggregate sources; judge vote weight never turns that into review. */
export function synthesisSummaryKey(result: SynthesisResult): SynthesisSummaryKey {
  return result.judge_vote_weight > 0
    ? 'orch.synthesisSummary'
    : 'orch.synthesisNoReviewVote'
}

export type OrchestrationCapabilityId =
  | 'single_model'
  | 'single_review'
  | 'post_summary_final_review'
  | 'four_vendor_review'

export interface OrchestrationCapabilityRow {
  id: OrchestrationCapabilityId
  labelKey: string
  ready: boolean
  availableWhenReady: boolean
}

/** Keep the UI's four claims tied directly to the conservative engine snapshot. */
export function orchestrationCapabilityRows(
  capabilities: OrchestrationCapabilities
): OrchestrationCapabilityRow[] {
  return [
    {
      id: 'single_model',
      labelKey: 'orch.capabilities.singleModel',
      ready: capabilities.chat_model_count > 0,
      availableWhenReady: true
    },
    {
      id: 'single_review',
      labelKey: 'orch.capabilities.singleReview',
      ready: capabilities.single_review_ready,
      availableWhenReady: false
    },
    {
      id: 'post_summary_final_review',
      labelKey: 'orch.capabilities.postSummaryFinalReview',
      ready: capabilities.post_summary_final_review_ready,
      availableWhenReady: false
    },
    {
      id: 'four_vendor_review',
      labelKey: 'orch.capabilities.fourVendorReview',
      ready: capabilities.four_vendor_review_ready,
      availableWhenReady: false
    }
  ]
}

const CAPABILITY_REASON_KEYS: Readonly<Record<string, string>> = {
  no_chat_models: 'orch.capabilities.reason.noChatModels',
  no_trusted_chat_identity: 'orch.capabilities.reason.noTrustedChatIdentity',
  no_schedulable_strong_review_candidates:
    'orch.capabilities.reason.noStrongReviewCandidates',
  single_review_requires_independent_initiator_and_reviewer:
    'orch.capabilities.reason.singleReviewNeedsIndependentPair',
  post_summary_final_review_requires_two_independent_reviewers:
    'orch.capabilities.reason.postSummaryNeedsTwoReviewers',
  four_vendor_review_requires_four_independent_reviewers:
    'orch.capabilities.reason.fourVendorNeedsFourReviewers',
  routes_snapshot_unavailable: 'orch.capabilities.reason.snapshotUnavailable',
  routes_snapshot_invalid: 'orch.capabilities.reason.snapshotInvalid'
}

export function orchestrationCapabilityReasonKey(reason: string): string {
  return CAPABILITY_REASON_KEYS[reason] ?? 'orch.capabilities.reason.unknown'
}
