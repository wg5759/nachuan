import { describe, expect, it } from 'vitest'

import type { Approval } from './api'
import type { ChatDisplayMsg } from './store'
import {
  approvalExecutionTask,
  routeApprovalExecutionResult
} from './approval-result-routing'

describe('approval result routing', () => {
  it('replays the frozen task without merging an approval note into its authority scope', () => {
    const approval: Approval = {
      id: 18,
      kind: 'action',
      summary: 'summary fallback',
      status: 'approved',
      payload: {
        task: 'mutable display task',
        execution_spec: { task: 'server-frozen task' }
      }
    }

    expect(approvalExecutionTask(approval)).toBe('server-frozen task')
  })

  it('writes an approved execution result back to its frozen source conversation', () => {
    const conversations: Record<string, ChatDisplayMsg[]> = {
      A: [{ role: 'user', content: '会话 A 的高风险任务', ts: 1 }],
      B: [{ role: 'user', content: '会话 B 的普通聊天', ts: 2 }]
    }
    const originalB = conversations.B.slice()
    const approval: Approval = {
      id: 17,
      kind: 'action',
      summary: '执行会话 A 的任务',
      status: 'approved',
      payload: {
        scope: 'agent_run',
        execution_spec: { conversation_id: 'A' }
      }
    }

    const routed = routeApprovalExecutionResult({
      approval,
      text: '会话 A 的执行结果',
      meta: '〔受控执行 · 已审批〕',
      now: 123,
      setConversationMessages: (conversationId, updater) => {
        const previous = conversations[conversationId] ?? []
        conversations[conversationId] =
          typeof updater === 'function' ? updater(previous) : updater
      }
    })

    expect(routed).toBe(true)
    expect(conversations.A.at(-1)).toMatchObject({
      role: 'assistant',
      content: '会话 A 的执行结果',
      meta: '〔受控执行 · 已审批〕',
      ts: 123,
      completedAt: 123
    })
    expect(conversations.B).toEqual(originalB)
  })
})
