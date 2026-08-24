import { describe, expect, it } from 'vitest'

import {
  decidePaidMediaStartup,
  PaidMediaStartupPolicyError
} from './paid-media-startup-policy'

function snapshot(input: {
  status: 'provisioning' | 'active' | 'maintenance_locked' | 'retired'
  desktopBound: boolean
  lockKind?: 'none' | 'operator' | 'integrity' | 'reanchor' | 'retired'
  reanchorPending?: boolean
}) {
  return {
    status: input.status,
    lockKind: input.lockKind ?? 'none',
    reanchorPending: input.reanchorPending ?? false,
    components: {
      desktop: { bound: input.desktopBound },
      gateway: { bound: input.status === 'active' }
    }
  } as Parameters<typeof decidePaidMediaStartup>[0]
}

describe('paid media startup policy', () => {
  it('permits a missing seal only in the Root provisioning/Desktop-unbound window', () => {
    expect(
      decidePaidMediaStartup(
        snapshot({ status: 'provisioning', desktopBound: false }),
        'missing'
      )
    ).toEqual({
      provisionAuthority: true,
      createLocalDirectories: true,
      provisionLegacySeal: true,
      allowLegacyBootstrap: true
    })
  })

  it('fuses paid media when an active/bound installation loses its seal', () => {
    expect(() =>
      decidePaidMediaStartup(snapshot({ status: 'active', desktopBound: true }), 'missing')
    ).toThrow(PaidMediaStartupPolicyError)
  })

  it('rejects an open seal after Desktop binding while allowing a closed exact replay', () => {
    const boundProvisioning = snapshot({ status: 'provisioning', desktopBound: true })
    expect(() => decidePaidMediaStartup(boundProvisioning, 'open')).toThrow(
      /cannot remain open/
    )
    expect(decidePaidMediaStartup(boundProvisioning, 'closed')).toEqual({
      provisionAuthority: true,
      createLocalDirectories: false,
      provisionLegacySeal: false,
      allowLegacyBootstrap: false
    })
  })

  it('accepts an active upgrade only with the existing closed seal', () => {
    expect(
      decidePaidMediaStartup(snapshot({ status: 'active', desktopBound: true }), 'closed')
    ).toEqual({
      provisionAuthority: false,
      createLocalDirectories: false,
      provisionLegacySeal: false,
      allowLegacyBootstrap: false
    })
  })

  it('blocks locked and reanchor-pending roots before touching paid local state', () => {
    expect(() =>
      decidePaidMediaStartup(
        snapshot({ status: 'maintenance_locked', desktopBound: true, lockKind: 'integrity' }),
        'closed'
      )
    ).toThrow(/not available/)
    expect(() =>
      decidePaidMediaStartup(
        snapshot({ status: 'active', desktopBound: true, reanchorPending: true }),
        'closed'
      )
    ).toThrow(/not available/)
  })
})
