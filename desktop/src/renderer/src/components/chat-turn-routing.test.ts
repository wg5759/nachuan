import { describe, expect, it } from 'vitest'
import {
  agentOutcomeLabelZh,
  concreteAgentModel,
  initialChatTurnMode
} from './chat-turn-routing'

describe('desktop unified Agent Turn routing', () => {
  it('routes ordinary text into the Agent Turn instead of direct chat completions', () => {
    expect(
      initialChatTurnMode({
        hasImages: false,
        forceExec: false,
        actionTask: false,
        hasTargetWorkdir: false
      })
    ).toBe('agent')
  })

  it('keeps media direct and side effects capability-gated', () => {
    expect(
      initialChatTurnMode({
        hasImages: true,
        forceExec: false,
        actionTask: false,
        hasTargetWorkdir: false
      })
    ).toBe('direct')
    expect(
      initialChatTurnMode({
        hasImages: false,
        forceExec: false,
        actionTask: true,
        hasTargetWorkdir: false
      })
    ).toBe('exec')
  })

  it('passes a concrete customer model but leaves fleet policy to the gateway', () => {
    expect(concreteAgentModel('glm-5.1')).toBe('glm-5.1')
    expect(concreteAgentModel('nachuan')).toBeUndefined()
    expect(concreteAgentModel('nachuan-ultra')).toBeUndefined()
    expect(concreteAgentModel(null)).toBeUndefined()
  })

  it('renders honest Agent outcomes instead of treating every HTTP 200 as completed', () => {
    expect(agentOutcomeLabelZh('completed')).toBe('已完成并核验')
    expect(agentOutcomeLabelZh('completed_unverified')).toBe('已完成，未独立核验')
    expect(agentOutcomeLabelZh('accepted_async')).toBe('已受理，后台处理中')
    expect(agentOutcomeLabelZh('rejected_capacity')).toBe('未执行：容量已满')
    expect(agentOutcomeLabelZh('partial')).toBe('仅部分完成')
    expect(agentOutcomeLabelZh('failed')).toBe('执行失败')
    expect(agentOutcomeLabelZh('blocked')).toBe('已阻断')
    expect(agentOutcomeLabelZh(undefined, true)).toBe('已阻断')
    expect(agentOutcomeLabelZh(undefined, false)).toBe('状态未确认')
  })
})
