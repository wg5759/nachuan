import { createInstance, type i18n as I18nInstance } from 'i18next'
import React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { I18nextProvider, initReactI18next } from 'react-i18next'
import { describe, expect, it } from 'vitest'
import type { CatalogProvider, SubscriptionConnector } from '../api'
import en from '../locales/en.json'
import zh from '../locales/zh.json'
import {
  ConnectionQuickStart,
  ProviderCard,
  SubscriptionConnectorSection,
  connectionFailureMessage,
  loginConnectionFailureMessage
} from './ConnectionCenter'

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

async function renderConnectors(connectors: SubscriptionConnector[]): Promise<string> {
  const i18n = await translationInstance('zh')
  return renderToStaticMarkup(
    <I18nextProvider i18n={i18n}>
      <SubscriptionConnectorSection
        connectors={connectors}
        state="ready"
        onRefresh={() => undefined}
      />
    </I18nextProvider>
  )
}

function loginProvider(type: string, label: string): CatalogProvider {
  return {
    name: type,
    label,
    region: 'cn',
    auth: 'login',
    type,
    default_base_url: '',
    models: [
      {
        id: `${type}-subscription`,
        upstream_model: `${type}-subscription`,
        tier: 'premium',
        description: 'subscription'
      }
    ]
  }
}

async function renderLoginProvider(
  provider: CatalogProvider,
  language: 'zh' | 'en'
): Promise<string> {
  const i18n = await translationInstance(language)
  return renderToStaticMarkup(
    <I18nextProvider i18n={i18n}>
      <ProviderCard
        provider={provider}
        connected={false}
        onChanged={async () => undefined}
        onVerified={async () => true}
      />
    </I18nextProvider>
  )
}

describe('Connection Center subscription status', () => {
  it('keeps first use to choose, connect, and start without operator controls', async () => {
    const i18n = await translationInstance('zh')
    const chooseHtml = renderToStaticMarkup(
      <I18nextProvider i18n={i18n}>
        <ConnectionQuickStart
          verifiedConnections={0}
          onTarget={() => undefined}
          onStartChat={() => undefined}
        />
      </I18nextProvider>
    )
    const readyHtml = renderToStaticMarkup(
      <I18nextProvider i18n={i18n}>
        <ConnectionQuickStart
          verifiedConnections={1}
          onTarget={() => undefined}
          onStartChat={() => undefined}
        />
      </I18nextProvider>
    )

    expect(chooseHtml).toContain('DeepSeek API Key')
    expect(chooseHtml).toContain('Kimi API Key')
    expect(chooseHtml).toContain('Codex / Kimi 订阅')
    expect(chooseHtml).toContain('本地模型')
    expect(chooseHtml).not.toMatch(/管理员|日志|发布|恢复/)
    expect(readyHtml).toContain('开始对话')
  })

  it('shows only Codex and Kimi public status with a concrete local-login next step', async () => {
    const html = await renderConnectors([
      {
        id: 'codex',
        label: 'forged label',
        state: 'logged_out',
        auth: 'device_code',
        transport: 'stdio_jsonl',
        version: '0.144.5',
        capabilities: ['chat', 'code'],
        login_supported: true,
        logout_supported: true
      },
      {
        id: 'kimi-code',
        label: 'Kimi Code',
        state: 'not_installed',
        auth: 'device_code',
        transport: 'acp_stdio',
        version: null,
        capabilities: ['chat', 'code'],
        login_supported: true,
        logout_supported: false
      },
      {
        id: 'unexpected'
      } as unknown as SubscriptionConnector
    ])

    expect(html).toContain('个人订阅（官方 CLI）')
    expect(html).toContain('Codex')
    expect(html).toContain('未登录')
    expect(html).toContain('codex login --device-auth')
    expect(html).toContain('Kimi Code')
    expect(html).toContain('未安装')
    expect(html).toContain('先安装官方 Kimi Code CLI')
    expect(html).toContain('官方设备码登录')
    expect(html).toContain('聊天')
    expect(html).toContain('编程')
    expect(html).not.toContain('forged label')
    expect(html).not.toContain('unexpected')
    expect(html).not.toMatch(/api.?key|token|cookie|auth\.json|认证文件/i)
    expect(html).not.toContain('一键登录')
  })

  it('directs an authenticated Codex account to the lower connection card', async () => {
    const html = await renderConnectors([
      {
        id: 'codex',
        label: 'Codex',
        state: 'authenticated_unprobed',
        auth: 'device_code',
        transport: 'stdio_jsonl',
        version: null,
        capabilities: ['chat', 'code'],
        login_supported: true,
        logout_supported: true
      }
    ])

    expect(html).toContain('已登录，待能力核验')
    expect(html).toContain('下方 Codex 连接卡')
    expect(html).toContain('最小文本能力核验')
    expect(html).not.toContain('点“刷新状态”完成能力核验')
  })

  it.each(['logged_out', 'reauth_required'] as const)(
    'shows the Nachuan product login command for Kimi Code state %s',
    async (connectorState) => {
      const html = await renderConnectors([
        {
          id: 'kimi-code',
          label: 'Kimi Code',
          state: connectorState,
          auth: 'device_code',
          transport: 'acp_stdio',
          version: '0.27.0',
          capabilities: ['chat', 'code'],
          login_supported: true,
          logout_supported: false
        }
      ])

      expect(html).toContain('nachuan kimi login')
      expect(html).not.toContain('PowerShell 运行 kimi login')
    }
  )
})

describe('Connection Center catalog login cards', () => {
  it.each([
    ['invalid_credentials', 'API Key 无效'],
    ['quota_or_rate_limited', '额度不足'],
    ['model_or_endpoint_not_found', '没有找到该模型或接口地址'],
    ['network_or_timeout', '无法连接模型服务或响应超时'],
    ['upstream_unavailable', '模型服务暂时不可用'],
    ['invalid_request', '模型服务拒绝了当前配置']
  ] as const)('maps %s to a closed customer action', async (reason, expected) => {
    const i18n = await translationInstance('zh')
    expect(connectionFailureMessage(reason, i18n.t.bind(i18n))).toContain(expected)
  })

  it.each([
    [
      'reauth_required',
      'Kimi Code 登录已失效，请运行 nachuan kimi login 后再连接。'
    ],
    [
      'text_contract_rejected',
      'Kimi Code CLI 协议不兼容；请更新官方 CLI，再运行 nachuan kimi login 后连接。'
    ],
    [
      'connector_unavailable',
      'Kimi Code 连接器暂不可用；请到诊断中心查看详情，不要连续重复提交。'
    ]
  ] as const)(
    'maps the closed Kimi failure reason %s to an actionable message',
    async (reasonCode, expected) => {
      const i18n = await translationInstance('zh')

      expect(
        loginConnectionFailureMessage(
          reasonCode,
          'nachuan kimi login',
          i18n.t.bind(i18n)
        )
      ).toBe(expected)
    }
  )

  it('does not echo an unknown Kimi failure reason', async () => {
    const i18n = await translationInstance('zh')
    const unknown = 'SECRET_REMOTE_REASON'

    const message = loginConnectionFailureMessage(
      unknown,
      'nachuan kimi login',
      i18n.t.bind(i18n)
    )

    expect(message).toContain('nachuan kimi login')
    expect(message).not.toContain(unknown)
  })

  it('renders the Kimi Code product login command in both renderer languages', async () => {
    const provider = loginProvider('kimi_code', 'Kimi Code catalog')
    const zhHtml = await renderLoginProvider(provider, 'zh')
    const enHtml = await renderLoginProvider(provider, 'en')

    expect(zhHtml).toContain('Kimi Code')
    expect(zhHtml).toContain('nachuan kimi login')
    expect(zhHtml).toContain('下一步运行 nachuan kimi login')
    expect(zhHtml).not.toContain('codex login')
    expect(enHtml).toContain('Kimi Code')
    expect(enHtml).toContain('nachuan kimi login')
    expect(enHtml).toContain('Next, run nachuan kimi login')
    expect(enHtml).not.toContain('codex login')
  })

  it('keeps the established Codex device-code command', async () => {
    const html = await renderLoginProvider(loginProvider('codex', 'Codex catalog'), 'zh')

    expect(html).toContain('codex login --device-auth')
    expect(html).not.toContain('nachuan kimi login')
  })

  it('fails closed for an unknown login provider type without showing another command', async () => {
    const html = await renderLoginProvider(
      loginProvider('future_login_type', 'Unknown login catalog'),
      'zh'
    )

    expect(html).toContain('此登录连接类型尚未获得纳川支持')
    expect(html).not.toContain('codex login')
    expect(html).not.toContain('nachuan kimi login')
    expect(html).not.toContain('<code')
    expect(html).not.toContain('<button')
  })
})
