import { describe, expect, it } from 'vitest'
import type {
  DebateResult,
  OrchestrationCapabilities,
  PanelResult
} from '../api'
import {
  manualCollaborationModels,
  orchestrationCapabilityReasonKey,
  orchestrationCapabilityRows,
  synthesisSummaryKey
} from './orchestrate-contract'

describe('manual collaboration truthfulness contract', () => {
  it('types panel and debate as multi-source synthesis, never independent review', () => {
    const panel: Pick<PanelResult, 'collaboration_type' | 'judge_vote_weight'> = {
      collaboration_type: 'multi_source_synthesis',
      judge_vote_weight: 1
    }
    const debate: Pick<DebateResult, 'collaboration_type' | 'judge_vote_weight'> = {
      collaboration_type: 'multi_source_synthesis',
      judge_vote_weight: 0
    }
    const invalid: Pick<PanelResult, 'collaboration_type' | 'judge_vote_weight'> = {
      // @ts-expect-error panel/debate synthesis must never be typed as independent review
      collaboration_type: 'independent_review',
      judge_vote_weight: 1
    }

    expect(synthesisSummaryKey(panel)).toBe('orch.synthesisSummary')
    expect(synthesisSummaryKey(debate)).toBe('orch.synthesisNoReviewVote')
    expect(invalid.collaboration_type).toBe('independent_review')
  })

  it('keeps only directly resolvable chat routes for manual workflows', () => {
    const models = [
      { id: 'echo' },
      { id: 'nachuan', chat_usable: true },
      { id: 'nachuan-ultra', chat_usable: true },
      { id: 'openrouter::nachuan', chat_usable: true },
      { id: 'provider::chat', chat_usable: true },
      { id: 'provider::embedding', chat_usable: false },
      { id: 'legacy-chat' }
    ]

    expect(manualCollaborationModels(models).map((model) => model.id)).toEqual([
      'openrouter::nachuan',
      'provider::chat',
      'legacy-chat'
    ])
  })

  it('maps every advertised tier independently and never promotes a weaker tier', () => {
    const capabilities: OrchestrationCapabilities = {
      chat_model_count: 3,
      review_candidate_count: 2,
      independent_identity_count: 3,
      single_review_ready: true,
      post_summary_final_review_ready: true,
      four_vendor_review_ready: false,
      reason: 'four_vendor_review_requires_four_independent_reviewers'
    }

    expect(
      orchestrationCapabilityRows(capabilities).map(({ id, ready }) => ({ id, ready }))
    ).toEqual([
      { id: 'single_model', ready: true },
      { id: 'single_review', ready: true },
      { id: 'post_summary_final_review', ready: true },
      { id: 'four_vendor_review', ready: false }
    ])
  })

  it('localizes known reasons and keeps future engine reasons visible', () => {
    expect(orchestrationCapabilityReasonKey('no_chat_models')).toBe(
      'orch.capabilities.reason.noChatModels'
    )
    expect(orchestrationCapabilityReasonKey('future_reason')).toBe(
      'orch.capabilities.reason.unknown'
    )
  })
})
