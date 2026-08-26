const WEB_SESSION_HEADER = 'X-Nachuan-Web-Session'
const BOOTSTRAP_PREFIX = '#nachuan-bootstrap='
const BOOTSTRAP_RE = /^nc-web-bootstrap-v1-[A-Za-z0-9_-]{43,86}$/

export interface LocalWebLocation {
  readonly hash: string
  readonly pathname?: string
  readonly search?: string
}

export interface LocalWebHistory {
  replaceState(data: unknown, unused: string, url?: string): void
}

export interface LocalWebSessionDeps {
  readonly fetchImpl?: typeof fetch
  readonly location?: LocalWebLocation
  readonly history?: LocalWebHistory
}

async function accepted(response: Response): Promise<boolean> {
  if (!response.ok) return false
  try {
    const value = (await response.json()) as unknown
    return Boolean(
      value &&
        typeof value === 'object' &&
        !Array.isArray(value) &&
        (value as Record<string, unknown>).authenticated === true
    )
  } catch {
    return false
  }
}

function scrubBootstrap(location: LocalWebLocation, history: LocalWebHistory): string | null {
  const hash = typeof location.hash === 'string' ? location.hash : ''
  if (!hash.startsWith(BOOTSTRAP_PREFIX)) return null
  const candidate = hash.slice(BOOTSTRAP_PREFIX.length)
  history.replaceState(null, '', `${location.pathname ?? '/'}${location.search ?? ''}`)
  return BOOTSTRAP_RE.test(candidate) ? candidate : null
}

export async function establishLocalWebSession(
  deps: LocalWebSessionDeps = {}
): Promise<boolean> {
  const doFetch = deps.fetchImpl ?? ((input, init) => globalThis.fetch(input, init))
  const location = deps.location ?? window.location
  const history = deps.history ?? window.history
  const bootstrap = scrubBootstrap(location, history)
  const common = {
    credentials: 'same-origin' as const,
    cache: 'no-store' as const,
    headers: { [WEB_SESSION_HEADER]: '1' }
  }
  try {
    if (bootstrap) {
      const response = await doFetch('/v1/local-web/session/bootstrap', {
        ...common,
        method: 'POST',
        headers: {
          ...common.headers,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ token: bootstrap })
      })
      if (await accepted(response)) return true
    }
    return await accepted(
      await doFetch('/v1/local-web/session', {
        ...common,
        method: 'GET'
      })
    )
  } catch {
    return false
  }
}

export async function persistLocalWebSession(
  runtimeKey: string,
  approvalKey: string | null,
  fetchImpl: typeof fetch = (input, init) => globalThis.fetch(input, init)
): Promise<boolean> {
  if (!runtimeKey || !approvalKey) return false
  try {
    return await accepted(
      await fetchImpl('/v1/local-web/session/adopt', {
        method: 'POST',
        credentials: 'same-origin',
        cache: 'no-store',
        headers: {
          [WEB_SESSION_HEADER]: '1',
          Authorization: `Bearer ${runtimeKey}`,
          'X-Nachuan-Approval-Key': approvalKey
        }
      })
    )
  } catch {
    return false
  }
}

export { WEB_SESSION_HEADER }
