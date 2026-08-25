import { createInstance, type i18n as I18nInstance } from 'i18next'
import React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { I18nextProvider, initReactI18next } from 'react-i18next'
import { describe, expect, it } from 'vitest'
import en from '../locales/en.json'
import zh from '../locales/zh.json'
import { FirstRunModelPrompt } from './FirstRunModelPrompt'

async function translations(language: 'zh' | 'en'): Promise<I18nInstance> {
  const instance = createInstance()
  await instance.use(initReactI18next).init({
    resources: { zh: { translation: zh }, en: { translation: en } },
    lng: language,
    fallbackLng: 'en',
    interpolation: { escapeValue: false }
  })
  return instance
}

describe('first-run model prompt', () => {
  it.each(['zh', 'en'] as const)('keeps %s onboarding to three customer steps', async (language) => {
    const i18n = await translations(language)
    const html = renderToStaticMarkup(
      <I18nextProvider i18n={i18n}>
        <FirstRunModelPrompt onConnect={() => undefined} />
      </I18nextProvider>
    )

    expect(html).toContain(language === 'zh' ? '连接一个模型' : 'Connect a model')
    expect(html).toContain('1.')
    expect(html).toContain('2.')
    expect(html).toContain('3.')
    expect(html).not.toMatch(/管理员|日志|发布|恢复|admin|logs|publish|recovery/i)
  })
})
