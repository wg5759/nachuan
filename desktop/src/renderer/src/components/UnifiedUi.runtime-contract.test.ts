import { readFileSync } from 'node:fs'

import { describe, expect, it } from 'vitest'

const appSource = readFileSync(new URL('../App.tsx', import.meta.url), 'utf8')
const chatSource = readFileSync(new URL('./ChatPane.tsx', import.meta.url), 'utf8')
const cssSource = readFileSync(new URL('../index.css', import.meta.url), 'utf8')

function between(source: string, start: string, end: string): string {
  const from = source.indexOf(start)
  const to = source.indexOf(end, from + start.length)
  expect(from, `missing start marker: ${start}`).toBeGreaterThanOrEqual(0)
  expect(to, `missing end marker: ${end}`).toBeGreaterThan(from)
  return source.slice(from, to)
}

describe('unified UI runtime contracts', () => {
  it('uses the exact creative model without mutating the global chat model or re-running intent routing', () => {
    const submit = between(appSource, 'const handleCreativeSubmit', 'useEffect(() => {')
    const send = between(chatSource, 'const send = async', '// #12 纳川当默认大脑')
    const bridge = between(chatSource, '// 统一创作抽屉只负责收集参数', '// 首次进入确保有一个当前对话')

    expect(submit).not.toContain('setCurrentModel(submission.model)')
    expect(send).toContain('modelOverride?: string')
    expect(send).toContain('const turnModelId = modelOverride ?? currentModel')
    expect(chatSource).toContain('!modelOverride')
    expect(bridge).toContain('prepared.model')
    expect(bridge).not.toContain('currentModel !== creativeRequest.model')
  })

  it('locks the one-slot creative request and makes its pending state visible', () => {
    const submit = between(appSource, 'const handleCreativeSubmit', 'useEffect(() => {')

    expect(appSource).toContain('creativeRequestPendingRef')
    expect(submit).toContain('if (creativeRequestPendingRef.current) return')
    expect(submit).toContain('creativeRequestPendingRef.current = true')
    expect(appSource).toContain('disabled={creativeRequest !== null')
    expect(appSource).toContain('aria-live="polite"')
  })

  it('keeps mobile model, conversation, and workspace access through an overlay navigation drawer', () => {
    const mobileCss = cssSource.slice(cssSource.indexOf('@media (max-width: 760px)'))

    expect(appSource).toContain('nachuan-mobile-navigation')
    expect(appSource).toContain('mobileNavigationOpen')
    expect(appSource).toContain('nachuan-mobile-model-control')
    expect(mobileCss).toContain('.nachuan-mobile-navigation.is-open')
    expect(mobileCss).not.toMatch(/\.nachuan-conversation-list[\s\S]*?display:\s*none/)
    expect(mobileCss).not.toMatch(/\.nachuan-workspace-menu[\s\S]*?display:\s*none/)
  })
})
