import React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'

import { PaidMediaRecoveryCard } from './PaidMediaRecoveryCard'

const OPERATION_ID = 'desktop-op-123e4567-e89b-42d3-a456-426614174000'

function renderCard(blocked: boolean, recovering = false): string {
  return renderToStaticMarkup(
    <PaidMediaRecoveryCard
      operationId={OPERATION_ID}
      blocked={blocked}
      recovering={recovering}
      onRetry={() => undefined}
      onDiscard={() => undefined}
    />
  )
}

describe('PaidMediaRecoveryCard', () => {
  it.each([false, true])(
    'shows the same complete Nachuan diagnostic id when blocked=%s',
    (blocked) => {
      const html = renderCard(blocked)

      expect(html).toContain('纳川诊断编号')
      expect(html).toContain('aria-label="付费媒体诊断编号"')
      expect(html).toContain(OPERATION_ID)
      expect(html).not.toContain('prompt')
      expect(html).not.toContain('encodedBody')
      expect(html).not.toContain('deliveryProof')
    }
  )

  it('keeps retry disabled for blocked and in-flight recovery states', () => {
    expect(renderCard(true)).toMatch(/<button[^>]*disabled=""[^>]*>查询\/恢复原操作<\/button>/)
    expect(renderCard(false, true)).toMatch(/<button[^>]*disabled=""[^>]*>查询恢复中…<\/button>/)
  })
})
