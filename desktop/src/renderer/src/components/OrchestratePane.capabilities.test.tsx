import { createInstance, type i18n as I18nInstance } from 'i18next'
import React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { I18nextProvider, initReactI18next } from 'react-i18next'
import { describe, expect, it } from 'vitest'
import type { OrchestrationCapabilities } from '../api'
import en from '../locales/en.json'
import zh from '../locales/zh.json'
import { OrchestrationCapabilityStatus } from './OrchestratePane'

async function translationInstance(language: 'zh' | 'en'): Promise<I18nInstance> {
  const instance = createInstance()
  await instance.use(initReactI18next).init({
    resources: { zh: { translation: zh }, en: { translation: en } },
    lng: language,
    fallbackLng: 'en',
    interpolation: { escapeValue: false }
  })
  return instance
}

async function renderStatus(
  language: 'zh' | 'en',
  capabilities: OrchestrationCapabilities | null,
  state: 'loading' | 'ready' | 'error'
): Promise<string> {
  const i18n = await translationInstance(language)
  return renderToStaticMarkup(
    <I18nextProvider i18n={i18n}>
      <OrchestrationCapabilityStatus capabilities={capabilities} state={state} />
    </I18nextProvider>
  )
}

describe('OrchestratePane capability status', () => {
  it('shows four unavailable tiers and the concrete reason without a readiness claim', async () => {
    const html = await renderStatus(
      'zh',
      {
        chat_model_count: 0,
        review_candidate_count: 0,
        independent_identity_count: 0,
        single_review_ready: false,
        post_summary_final_review_ready: false,
        four_vendor_review_ready: false,
        reason: 'no_chat_models'
      },
      'ready'
    )

    expect(html).toContain('单模型可用')
    expect(html).toContain('四家独立互审')
    expect(html).toContain('没有可用聊天模型')
    expect(html.match(/data-capability-ready="false"/g)).toHaveLength(4)
    expect(html).not.toContain('已就绪')
  })

  it('shows each verified tier in English without turning schedulability into proof', async () => {
    const html = await renderStatus(
      'en',
      {
        chat_model_count: 5,
        review_candidate_count: 4,
        independent_identity_count: 5,
        single_review_ready: true,
        post_summary_final_review_ready: true,
        four_vendor_review_ready: true,
        reason: null
      },
      'ready'
    )

    expect(html).toContain('Second review after initiator summary')
    expect(html).toContain('Four-vendor independent review')
    expect(html.match(/data-capability-ready="true"/g)).toHaveLength(4)
    expect(html).toContain('every review must still verify the actually served model')
  })

  it('fails closed when the capability endpoint cannot be verified', async () => {
    const html = await renderStatus('zh', null, 'error')

    expect(html).toContain('暂时无法核验，全部按未就绪处理')
    expect(html).not.toContain('已就绪')
    expect(html).not.toContain('data-capability-ready="true"')
    expect(html.match(/data-capability-ready="false"/g)).toHaveLength(4)
  })
})
