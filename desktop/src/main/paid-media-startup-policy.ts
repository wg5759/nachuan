import type { InstallationRootSnapshot } from './installation-root-client'

export type PaidMediaLegacySealPresence = 'missing' | 'open' | 'closed'

export interface PaidMediaStartupDecision {
  /** The local ledgers may be created or a pre-binding crash may be resumed. */
  provisionAuthority: boolean
  /** Only this window may create the project-owned data/vault directories. */
  createLocalDirectories: boolean
  /** Missing seal creation is a one-time installer/Root provisioning action. */
  provisionLegacySeal: boolean
  /** Renderer candidate|null may close an existing open seal only in this window. */
  allowLegacyBootstrap: boolean
}

export class PaidMediaStartupPolicyError extends Error {
  override readonly name = 'PaidMediaStartupPolicyError'
}

export function decidePaidMediaStartup(
  snapshot: Pick<
    InstallationRootSnapshot,
    'status' | 'lockKind' | 'reanchorPending' | 'components'
  >,
  seal: PaidMediaLegacySealPresence
): PaidMediaStartupDecision {
  if (
    !snapshot ||
    snapshot.lockKind !== 'none' ||
    snapshot.reanchorPending ||
    (snapshot.status !== 'provisioning' && snapshot.status !== 'active')
  ) {
    throw new PaidMediaStartupPolicyError(
      'Installation Root is not available for paid media startup'
    )
  }

  const desktopBound = snapshot.components.desktop.bound
  if (snapshot.status === 'active' && !desktopBound) {
    throw new PaidMediaStartupPolicyError(
      'Active Installation Root has no Desktop binding'
    )
  }
  const firstDesktopProvisioning = snapshot.status === 'provisioning' && !desktopBound

  if (seal === 'missing' && !firstDesktopProvisioning) {
    throw new PaidMediaStartupPolicyError(
      'Bound Desktop legacy seal is missing and cannot be recreated'
    )
  }
  if (seal === 'open' && !firstDesktopProvisioning) {
    throw new PaidMediaStartupPolicyError(
      'Bound Desktop legacy seal cannot remain open'
    )
  }

  return Object.freeze({
    provisionAuthority: snapshot.status === 'provisioning',
    createLocalDirectories: firstDesktopProvisioning,
    provisionLegacySeal: seal === 'missing',
    allowLegacyBootstrap: seal === 'open' || seal === 'missing'
  })
}
