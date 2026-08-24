import { describe, expect, it, vi } from 'vitest'

import type { CatalogProvider, ConnectionSummary, LocalServer } from '../api'
import {
  canPreserveExistingCredential,
  connectionModelChoices,
  connectDetectedLocalServer,
  disconnectStoredConnection,
  formatVerifiedAt,
  hasCustomizedModelSelection,
  initialEnabledModelIds,
  loginModelForVerification,
  orphanConnectionEntries,
  recommendedCatalogChatModel,
  recommendedLocalChatModel,
  refreshVerifiedConnectionModels,
  selectedCatalogModelsForSave,
  shouldAutoDiscoverCatalogModels,
  shouldOfferDisconnect,
  shouldPreserveExistingCredential,
  shouldShowConnectionProvider
} from './connection-center-state'

describe('verified connection activation', () => {
  it('does not claim activation when the authoritative model refresh fails', async () => {
    const commit = vi.fn()

    await expect(
      refreshVerifiedConnectionModels(
        ['provider::chat-model'],
        vi.fn(async () => {
          throw new Error('engine temporarily unavailable')
        }),
        commit
      )
    ).resolves.toBe(false)
    expect(commit).not.toHaveBeenCalled()
  })

  it('commits an authoritative roster but keeps activation pending when the promoted model is absent', async () => {
    const roster = [{ id: 'existing-model', owned_by: 'existing' }]
    const commit = vi.fn()

    await expect(
      refreshVerifiedConnectionModels(
        ['provider::chat-model'],
        vi.fn(async () => roster),
        commit
      )
    ).resolves.toBe(false)
    expect(commit).toHaveBeenCalledWith(roster)
  })

  it('confirms activation only when every promoted model is in the live roster', async () => {
    const roster = [
      { id: 'provider::chat-a', owned_by: 'provider' },
      { id: 'provider::chat-b', owned_by: 'provider' }
    ]
    const commit = vi.fn()

    await expect(
      refreshVerifiedConnectionModels(
        ['provider::chat-a', 'provider::chat-b'],
        vi.fn(async () => roster),
        commit
      )
    ).resolves.toBe(true)
    expect(commit).toHaveBeenCalledWith(roster)
  })
})

describe('connection removal eligibility', () => {
  it.each([
    ['verified', { state: 'verified' }],
    ['legacy', { state: 'legacy_unverified' }],
    ['disabled', { state: 'disabled' }],
    ['unavailable provider with a stored credential', { credential_present: true }]
  ] satisfies [string, ConnectionSummary][])('offers removal for %s state', (_label, connection) => {
    expect(shouldOfferDisconnect(connection)).toBe(true)
  })

  it('does not offer removal when no connection exists', () => {
    expect(shouldOfferDisconnect(undefined)).toBe(false)
  })

  it('keeps an unavailable provider visible when its stored connection needs removal', () => {
    expect(shouldShowConnectionProvider(false, false, { credential_present: true })).toBe(true)
    expect(shouldShowConnectionProvider(false, false, { state: 'disabled' })).toBe(true)
    expect(shouldShowConnectionProvider(false, false, undefined)).toBe(false)
  })

  it('finds stored connections whose providers disappeared from the catalog', () => {
    expect(
      orphanConnectionEntries(
        [
          {
            name: 'known',
            label: 'Known',
            region: 'intl',
            auth: 'api_key',
            type: 'openai_compat',
            default_base_url: '',
            models: []
          }
        ],
        {
          known: { state: 'verified', credential_present: true },
          removed_provider: { state: 'legacy_unverified', credential_present: true }
        }
      )
    ).toEqual([
      {
        provider: 'removed_provider',
        connection: { state: 'legacy_unverified', credential_present: true }
      }
    ])
  })
})

describe('stored credential reuse', () => {
  it('allows reuse only for a verified receipt that confirms a stored credential', () => {
    expect(
      canPreserveExistingCredential(
        {
          state: 'verified',
          credential_present: true,
          type: 'openai_compat',
          base_url: 'HTTPS://API.OPENAI.COM:443/v1/'
        },
        'OPENAI_COMPAT',
        'https://api.openai.com/v1'
      )
    ).toBe(true)
    expect(
      canPreserveExistingCredential(
        {
          state: 'legacy_unverified',
          credential_present: true,
          type: 'openai_compat',
          base_url: 'https://api.openai.com/v1'
        },
        'openai_compat',
        'https://api.openai.com/v1'
      )
    ).toBe(false)
    expect(
      canPreserveExistingCredential(
        {
          state: 'disabled',
          credential_present: true,
          type: 'openai_compat',
          base_url: 'https://api.openai.com/v1'
        },
        'openai_compat',
        'https://api.openai.com/v1'
      )
    ).toBe(false)
    expect(canPreserveExistingCredential({ state: 'verified' }, 'openai_compat', '')).toBe(false)
    expect(canPreserveExistingCredential(undefined, 'openai_compat', '')).toBe(false)
  })

  it('forces key re-entry when the host, path, or protocol adapter changes', () => {
    const verified = {
      state: 'verified' as const,
      credential_present: true,
      type: 'openai_compat',
      base_url: 'https://api.openai.com/v1'
    }
    expect(canPreserveExistingCredential(verified, 'openai_compat', 'https://api.openai.com/v2')).toBe(false)
    expect(canPreserveExistingCredential(verified, 'openai_compat', 'https://api.moonshot.cn/v1')).toBe(false)
    expect(canPreserveExistingCredential(verified, 'perplexity', 'https://api.openai.com/v1')).toBe(false)
  })

  it('sends preserve only for a blank-key reconnect backed by a verified credential', () => {
    expect(
      shouldPreserveExistingCredential(
        {
          state: 'verified',
          credential_present: true,
          type: 'openai_compat',
          base_url: 'https://api.openai.com/v1'
        },
        '',
        'openai_compat',
        'https://api.openai.com/v1/'
      )
    ).toBe(true)
    expect(
      shouldPreserveExistingCredential(
        { state: 'legacy_unverified', credential_present: true },
        '',
        'openai_compat',
        'https://api.openai.com/v1'
      )
    ).toBe(false)
    expect(
      shouldPreserveExistingCredential(
        { state: 'verified', credential_present: true },
        'replacement-key',
        'openai_compat',
        'https://api.openai.com/v1'
      )
    ).toBe(false)
  })

  it('reuses a securely imported legacy credential only for its bound target', () => {
    const imported = {
      state: 'legacy_unverified' as const,
      credential_present: true,
      credential_reverification_available: true,
      type: 'openai_compat',
      base_url: 'https://apihub.agnes-ai.com/v1'
    }

    expect(
      canPreserveExistingCredential(
        imported,
        'openai_compat',
        'https://apihub.agnes-ai.com/v1'
      )
    ).toBe(true)
    expect(
      shouldPreserveExistingCredential(
        imported,
        '',
        'openai_compat',
        'https://apihub.agnes-ai.com/v1'
      )
    ).toBe(true)
    expect(
      canPreserveExistingCredential(
        imported,
        'openai_compat',
        'https://attacker.example/v1'
      )
    ).toBe(false)
  })
})

describe('default model enablement', () => {
  it('recommends one ranked chat model and excludes non-chat candidates', () => {
    expect(
      recommendedCatalogChatModel([
        {
          id: 'image-v1',
          upstream_model: 'image-v1',
          tier: 'default',
          description: 'image',
          modality: 'image',
          rank: 1
        },
        {
          id: 'text-embedding-3',
          upstream_model: 'text-embedding-3',
          tier: 'default',
          description: 'embedding',
          rank: 1
        },
        {
          id: 'chat-secondary',
          upstream_model: 'chat-secondary',
          tier: 'default',
          description: 'chat',
          modality: 'chat',
          rank: 2
        },
        {
          id: 'chat-recommended',
          upstream_model: 'chat-recommended',
          tier: 'default',
          description: 'chat',
          modality: 'chat',
          rank: 1
        }
      ])?.id
    ).toBe('chat-recommended')
  })

  it('enables only the recommendation for a new connection', () => {
    const models = [
      {
        id: 'recommended',
        upstream_model: 'recommended',
        tier: 'default',
        description: 'recommended',
        modality: 'chat',
        rank: 1
      },
      {
        id: 'advanced',
        upstream_model: 'advanced',
        tier: 'default',
        description: 'advanced',
        modality: 'chat',
        rank: 2
      }
    ]
    expect(initialEnabledModelIds(models, undefined)).toEqual(['recommended'])
  })

  it('enables catalog-declared image and video siblings with the recommended chat model', () => {
    const models = [
      {
        id: 'agnes-flash',
        upstream_model: 'agnes-2.0-flash',
        tier: 'free',
        description: 'chat',
        modality: 'chat',
        rank: 1
      },
      {
        id: 'agnes-image',
        upstream_model: 'agnes-image-2.1-flash',
        tier: 'free',
        description: 'image',
        modality: 'image'
      },
      {
        id: 'agnes-video',
        upstream_model: 'agnes-video-v2.0',
        tier: 'free',
        description: 'video',
        modality: 'video'
      },
      {
        id: 'other-chat',
        upstream_model: 'other-chat',
        tier: 'default',
        description: 'advanced chat',
        modality: 'chat',
        rank: 2
      }
    ]

    expect(initialEnabledModelIds(models, undefined)).toEqual([
      'agnes-flash',
      'agnes-image',
      'agnes-video'
    ])
  })

  it('preserves the exact stored choices for an existing connection', () => {
    const catalogModels = [
      { id: 'recommended', upstream_model: 'recommended', tier: 'default', description: '' }
    ]
    const storedModels = [
      { id: 'saved-a', upstream_model: 'saved-a', tier: 'default', description: '' },
      { id: 'saved-b', upstream_model: 'saved-b', tier: 'default', description: '' }
    ]
    expect(
      initialEnabledModelIds(catalogModels, {
        state: 'verified',
        credential_present: true,
        enabled_models: storedModels
      })
    ).toEqual(['saved-a', 'saved-b'])
    expect(initialEnabledModelIds(catalogModels, { state: 'legacy_unverified' })).toEqual([])
  })

  it('keeps all catalog choices in advanced while retaining stored aliases', () => {
    const catalogModels = [
      { id: 'saved', upstream_model: 'catalog-upstream', tier: 'default', description: '' },
      { id: 'advanced', upstream_model: 'advanced', tier: 'default', description: '' }
    ]
    const stored = {
      id: 'saved',
      upstream_model: 'stored-upstream',
      tier: 'default',
      description: 'saved alias'
    }
    const custom = {
      id: 'custom',
      upstream_model: 'private-model',
      tier: 'default',
      description: 'custom'
    }

    expect(
      connectionModelChoices(catalogModels, {
        state: 'verified',
        credential_present: true,
        enabled_models: [stored, custom]
      })
    ).toEqual([stored, catalogModels[1], custom])
  })

  it('auto-discovers a non-empty official catalog only for untouched first-time setup', () => {
    const provider: CatalogProvider = {
      name: 'moonshot',
      label: 'Kimi',
      region: 'cn',
      auth: 'api_key',
      type: 'openai_compat',
      default_base_url: 'https://api.moonshot.cn/v1',
      auto_discover_models: true,
      models: [
        { id: 'preset', upstream_model: 'preset', tier: 'default', description: '' }
      ]
    }

    expect(shouldAutoDiscoverCatalogModels(provider, undefined, false)).toBe(true)
    expect(
      selectedCatalogModelsForSave(provider.models, new Set(['preset']), true)
    ).toEqual([])
    expect(shouldAutoDiscoverCatalogModels(provider, undefined, true)).toBe(false)
    expect(
      shouldAutoDiscoverCatalogModels(
        provider,
        { state: 'legacy_unverified', credential_present: true },
        false
      )
    ).toBe(true)
    expect(
      shouldAutoDiscoverCatalogModels(
        provider,
        { state: 'verified', credential_present: true, enabled_models: provider.models },
        false
      )
    ).toBe(false)
  })

  it('returns to automatic discovery after an unfinished custom id is cleared', () => {
    const models = [
      { id: 'preset', upstream_model: 'preset', tier: 'default', description: '' }
    ]
    const selected = new Set(['preset'])
    expect(hasCustomizedModelSelection(models, selected, models, selected, 'custom')).toBe(true)
    expect(hasCustomizedModelSelection(models, selected, models, selected, '')).toBe(false)
    expect(
      hasCustomizedModelSelection(models, selected, models, new Set<string>(), '')
    ).toBe(true)
  })

  it('repairs a legacy login record to exactly one recommended chat model', () => {
    const models = [
      {
        id: 'recommended',
        upstream_model: 'recommended-upstream',
        tier: 'default',
        description: '',
        modality: 'chat',
        rank: 1
      },
      {
        id: 'other',
        upstream_model: 'other-upstream',
        tier: 'default',
        description: '',
        modality: 'chat',
        rank: 2
      }
    ]
    expect(
      loginModelForVerification(models, {
        state: 'legacy_unverified',
        enabled_models: [...models]
      })
    ).toEqual([models[0]])
  })
})

describe('detected local connection', () => {
  const server: LocalServer = {
    name: 'ollama',
    label: 'Ollama',
    base_url: 'http://127.0.0.1:11434/v1',
    alive: true,
    models: ['qwen3']
  }

  it('chooses one explainable chat candidate instead of embedding or reranking models', () => {
    expect(
      recommendedLocalChatModel([
        'nomic-embed-text',
        'bge-reranker-v2',
        'qwen3:latest',
        'llama-3.1-instruct'
      ])
    ).toBe('llama-3.1-instruct')
  })

  it('submits only the recommended local chat candidate', async () => {
    const save = vi.fn(async () => ({ ok: true, models: ['llama-3.1-instruct'] }))
    await connectDetectedLocalServer(
      {
        ...server,
        models: ['nomic-embed-text', 'qwen3:latest', 'llama-3.1-instruct']
      },
      save,
      vi.fn(async () => true)
    )

    expect(save).toHaveBeenCalledWith('ollama', {
      type: 'openai_compat',
      api_key: '',
      base_url: 'http://127.0.0.1:11434/v1',
      enabled_models: [
        {
          id: 'llama-3.1-instruct',
          upstream_model: 'llama-3.1-instruct',
          tier: 'local',
          description: 'Ollama'
        }
      ],
      preserve_existing_credential: false
    })
  })

  it('does not submit a local connection when every detected model is non-chat', async () => {
    const save = vi.fn(async () => ({ ok: true, models: [] }))
    const refresh = vi.fn(async () => true)

    await expect(
      connectDetectedLocalServer(
        { ...server, models: ['nomic-embed-text', 'bge-reranker-v2'] },
        save,
        refresh
      )
    ).resolves.toEqual({ ok: false, reason: 'rejected' })
    expect(save).not.toHaveBeenCalled()
    expect(refresh).not.toHaveBeenCalled()
  })

  it('reports a rejected verification and does not refresh it as connected', async () => {
    const refresh = vi.fn(async () => true)
    const result = await connectDetectedLocalServer(
      server,
      vi.fn(async () => ({ ok: false, models: [], error: 'verification failed' })),
      refresh
    )

    expect(result).toEqual({ ok: false, reason: 'rejected' })
    expect(refresh).not.toHaveBeenCalled()
  })

  it('turns a transport exception into a visible retryable failure result', async () => {
    const refresh = vi.fn(async () => true)
    const result = await connectDetectedLocalServer(
      server,
      vi.fn(async () => {
        throw new Error('engine unavailable')
      }),
      refresh
    )

    expect(result).toEqual({ ok: false, reason: 'exception' })
    expect(refresh).not.toHaveBeenCalled()
  })

  it('keeps a verified local save distinct from a later activation refresh failure', async () => {
    const result = await connectDetectedLocalServer(
      server,
      vi.fn(async () => ({ ok: true, models: ['qwen3'] })),
      vi.fn(async () => {
        throw new Error('model roster unavailable')
      })
    )

    expect(result).toEqual({
      ok: true,
      connected: 1,
      rejected: 0,
      activation: 'pending'
    })
  })

  it('never asks the backend to preserve a credential for a local reconnect', async () => {
    const save = vi.fn(async () => ({ ok: true, models: ['qwen3'] }))
    const refresh = vi.fn(async () => true)

    await expect(connectDetectedLocalServer(server, save, refresh)).resolves.toEqual({
      ok: true,
      connected: 1,
      rejected: 0,
      activation: 'confirmed'
    })
    expect(save).toHaveBeenCalledWith('ollama', {
      type: 'openai_compat',
      api_key: '',
      base_url: 'http://127.0.0.1:11434/v1',
      enabled_models: [
        {
          id: 'qwen3',
          upstream_model: 'qwen3',
          tier: 'local',
          description: 'Ollama'
        }
      ],
      preserve_existing_credential: false
    })
    expect(refresh).toHaveBeenCalledOnce()
  })

  it('reports partial local verification instead of presenting every candidate as successful', async () => {
    const result = await connectDetectedLocalServer(
      server,
      vi.fn(async () => ({
        ok: true,
        models: ['qwen3'],
        rejected_models: ['unsupported-chat-model']
      })),
      vi.fn(async () => true)
    )

    expect(result).toEqual({
      ok: true,
      connected: 1,
      rejected: 1,
      activation: 'confirmed'
    })
  })
})

describe('verification receipt time', () => {
  it('formats a parseable receipt timestamp without claiming live health', () => {
    expect(formatVerifiedAt('2026-07-17T02:03:04.000Z', 'UTC')).toBe('2026-07-17 02:03')
  })

  it('hides an invalid receipt timestamp', () => {
    expect(formatVerifiedAt('not-a-timestamp', 'UTC')).toBeNull()
  })
})

describe('stored connection removal', () => {
  it('keeps the connection visible when removal is rejected', async () => {
    const refresh = vi.fn(async () => undefined)
    const result = await disconnectStoredConnection(
      'volcano',
      vi.fn(async () => ({ ok: false })),
      refresh
    )

    expect(result).toEqual({ ok: false, reason: 'rejected' })
    expect(refresh).not.toHaveBeenCalled()
  })

  it('keeps the connection visible when removal throws', async () => {
    const refresh = vi.fn(async () => undefined)
    const result = await disconnectStoredConnection(
      'volcano',
      vi.fn(async () => {
        throw new Error('delete unavailable')
      }),
      refresh
    )

    expect(result).toEqual({ ok: false, reason: 'exception' })
    expect(refresh).not.toHaveBeenCalled()
  })

  it('does not report success until the refreshed state is visible', async () => {
    let releaseRefresh: (() => void) | undefined
    const refresh = vi.fn(
      () =>
        new Promise<void>((resolve) => {
          releaseRefresh = resolve
        })
    )
    let settled = false
    const pending = disconnectStoredConnection(
      'volcano',
      vi.fn(async () => ({ ok: true })),
      refresh
    ).then((result) => {
      settled = true
      return result
    })

    await Promise.resolve()
    expect(settled).toBe(false)
    releaseRefresh?.()
    await expect(pending).resolves.toEqual({ ok: true })
  })
})
