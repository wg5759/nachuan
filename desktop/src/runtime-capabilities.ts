import type { DesktopAPI } from './renderer/src/env'

export type RuntimeKind = 'electron' | 'web'
export type ClientPortSurface = 'electron' | 'localWeb' | 'teamWeb'
export type DeclaredSupport =
  | 'implemented'
  | 'implemented-with-preconditions'
  | 'unsupported'
  | 'planned'
export type RuntimeApiMethod = Exclude<keyof DesktopAPI, 'runtimeKind' | 'runtimeCapabilities'>

export interface SurfaceCapabilityDeclaration {
  readonly declaredSupport: DeclaredSupport
  readonly adapter: string
  readonly apiMethods: readonly RuntimeApiMethod[]
  readonly limitation?: string
}

export interface ClientPortCapabilityDeclaration {
  readonly securityDomain: string
  readonly surfaces: Readonly<Record<ClientPortSurface, SurfaceCapabilityDeclaration>>
}

export interface ClientPortCapabilityManifest {
  /** Static product wiring only. This object never grants server execution authority. */
  readonly schema: 'nachuan.client-port-capabilities.v1'
  readonly portVersion: '1.0.0'
  readonly claimScope: 'build-contract-only'
  readonly authoritative: false
  readonly runtimeReadinessIncluded: false
  readonly capabilities: Readonly<Record<RuntimeCapabilityId, ClientPortCapabilityDeclaration>>
}

/** Kept as the public API type name; both current runtimes expose the same canonical object. */
export type RuntimeCapabilityManifest = ClientPortCapabilityManifest

export type RuntimeCapabilityId =
  | 'engineProxy'
  | 'pluginUi'
  | 'paidMediaOperations'
  | 'paidMediaAssetMaterialization'
  | 'approvals'
  | 'connections'
  | 'channelRecovery'
  | 'sync'
  | 'appUpdates'
  | 'nativeNavigationEvents'
  | 'nativeLanguageMenu'
  | 'screenSnip'
  | 'directoryPicker'
  | 'embeddedBrowser'
  | 'mediaSave'

function surface(
  declaredSupport: DeclaredSupport,
  adapter: string,
  apiMethods: readonly RuntimeApiMethod[],
  limitation?: string
): SurfaceCapabilityDeclaration {
  return Object.freeze({
    declaredSupport,
    adapter,
    apiMethods: Object.freeze([...apiMethods]),
    ...(limitation ? { limitation } : {})
  })
}

function capability(
  securityDomain: string,
  electron: SurfaceCapabilityDeclaration,
  localWeb: SurfaceCapabilityDeclaration,
  teamWeb: SurfaceCapabilityDeclaration
): ClientPortCapabilityDeclaration {
  return Object.freeze({
    securityDomain,
    surfaces: Object.freeze({ electron, localWeb, teamWeb })
  })
}

const ENGINE_METHODS = ['engineRequest', 'engineStream', 'engineUpload', 'cancelEngineRequest'] as const
const PLUGIN_UI_METHODS = ['getPluginUiSnapshot'] as const
const PAID_MEDIA_METHODS = [
  'claimPaidMedia',
  'executePaidMedia',
  'pollPaidVideo',
  'recoverPaidMediaArchive',
  'listPaidMediaArchives',
  'cancelPaidMedia',
  'listPaidMediaOperations',
  'acknowledgePaidMedia',
  'abandonPaidMediaClaim',
  'reconcilePaidMedia',
  'importLegacyPaidMediaJournal'
] as const
const APPROVAL_METHODS = ['listApprovals', 'resolveApproval'] as const
const CONNECTION_METHODS = ['saveConnection', 'deleteConnection'] as const
const CHANNEL_RECOVERY_METHODS = ['inspectChannelRecovery', 'closeChannelRecovery'] as const
const SYNC_METHODS = ['configureSync', 'authenticateSync', 'toggleSync', 'runSync'] as const
const UPDATE_METHODS = [
  'getUpdateState',
  'checkForUpdates',
  'installVerifiedUpdate',
  'onUpdateState'
] as const
const NATIVE_NAVIGATION_METHODS = ['onSetView', 'onAppCommand'] as const
const SCREEN_SNIP_METHODS = [
  'snipBg',
  'startSnip',
  'snipReady',
  'snipDone',
  'snipCancel',
  'onSnipResult'
] as const

export const CLIENT_PORT_CAPABILITIES: ClientPortCapabilityManifest = Object.freeze({
  schema: 'nachuan.client-port-capabilities.v1',
  portVersion: '1.0.0',
  claimScope: 'build-contract-only',
  authoritative: false,
  runtimeReadinessIncluded: false,
  capabilities: Object.freeze({
    engineProxy: capability(
      'runtime',
      surface('implemented', 'electron-ipc', ENGINE_METHODS),
      surface('implemented', 'same-origin-http', ENGINE_METHODS),
      surface('planned', 'team-session-http', ENGINE_METHODS, 'Team Web transport is not implemented.')
    ),
    pluginUi: capability(
      'plugin-ui',
      surface(
        'implemented',
        'electron-ipc-engine-session',
        PLUGIN_UI_METHODS,
        'Main selects the signed Engine capability and Renderer receives only a closed declarative snapshot.'
      ),
      surface('implemented', 'same-origin-http', PLUGIN_UI_METHODS),
      surface(
        'planned',
        'team-session-http',
        PLUGIN_UI_METHODS,
        'Tenant-scoped plugin UI policy is not implemented.'
      )
    ),
    paidMediaOperations: capability(
      'paid-media-authority',
      surface(
        'implemented-with-preconditions',
        'electron-ipc',
        PAID_MEDIA_METHODS,
        'Requires a healthy local engine, paid-media authority, and explicit user approval.'
      ),
      surface(
        'implemented-with-preconditions',
        'same-origin-http',
        PAID_MEDIA_METHODS,
        'Requires a healthy gateway, both authority headers where required, and explicit browser confirmation.'
      ),
      surface(
        'planned',
        'team-session-http',
        PAID_MEDIA_METHODS,
        'Per-user paid-media authority and tenant isolation are not implemented.'
      )
    ),
    paidMediaAssetMaterialization: capability(
      'paid-media-delivery',
      surface(
        'implemented',
        'electron-native-protocol',
        [],
        'Durable nachuan-paid-media references are resolved by the Electron protocol handler.'
      ),
      surface(
        'implemented-with-preconditions',
        'same-origin-http-verified-blob',
        ['resolvePaidMediaAsset', 'releasePaidMediaAsset'],
        'Only attested same-origin durable assets are materialized.'
      ),
      surface(
        'planned',
        'team-session-http-verified-blob',
        ['resolvePaidMediaAsset', 'releasePaidMediaAsset'],
        'Tenant-scoped object delivery is not implemented.'
      )
    ),
    approvals: capability(
      'approval',
      surface('implemented-with-preconditions', 'electron-ipc', APPROVAL_METHODS, 'Requires approval authority.'),
      surface('implemented-with-preconditions', 'same-origin-http-double-header', APPROVAL_METHODS, 'Requires approval authority.'),
      surface('planned', 'team-session-http', APPROVAL_METHODS, 'Team principal and RBAC enforcement are not implemented.')
    ),
    connections: capability(
      'connection-admin',
      surface('implemented-with-preconditions', 'electron-ipc', CONNECTION_METHODS, 'Verification depends on the selected provider endpoint.'),
      surface('implemented-with-preconditions', 'same-origin-http-double-header', CONNECTION_METHODS, 'Verification depends on the selected provider endpoint.'),
      surface('planned', 'team-session-http', CONNECTION_METHODS, 'Per-user credential and worker isolation are not implemented.')
    ),
    channelRecovery: capability(
      'channel-recovery',
      surface(
        'implemented-with-preconditions',
        'electron-ipc-engine-session',
        CHANNEL_RECOVERY_METHODS,
        'Requires both runtime and approval authority; close is terminal and never replays the target.'
      ),
      surface(
        'implemented-with-preconditions',
        'same-origin-http-double-header',
        CHANNEL_RECOVERY_METHODS,
        'Requires both authority headers and two explicit operator confirmations.'
      ),
      surface(
        'planned',
        'team-session-http',
        CHANNEL_RECOVERY_METHODS,
        'Tenant-scoped recovery authority and operator attribution are not implemented.'
      )
    ),
    sync: capability(
      'sync',
      surface('implemented-with-preconditions', 'electron-ipc', SYNC_METHODS, 'Requires an explicitly configured sync service.'),
      surface('implemented-with-preconditions', 'same-origin-http-double-header', SYNC_METHODS, 'Requires an explicitly configured sync service.'),
      surface('planned', 'team-session-http', SYNC_METHODS, 'Team-owned sync semantics are not implemented.')
    ),
    appUpdates: capability(
      'distribution',
      surface('implemented-with-preconditions', 'electron-ipc', UPDATE_METHODS, 'Requires a configured and trusted update channel.'),
      surface('unsupported', 'fail-closed', UPDATE_METHODS, 'The pip or hosting deployment channel owns local Web updates.'),
      surface('unsupported', 'server-deployment', UPDATE_METHODS, 'The server deployment channel owns team Web updates.')
    ),
    nativeNavigationEvents: capability(
      'desktop-os',
      surface('implemented', 'electron-ipc', NATIVE_NAVIGATION_METHODS),
      surface('unsupported', 'no-op', NATIVE_NAVIGATION_METHODS, 'The browser has no Electron native menu event source.'),
      surface('unsupported', 'no-op', NATIVE_NAVIGATION_METHODS, 'The browser has no Electron native menu event source.')
    ),
    nativeLanguageMenu: capability(
      'desktop-os',
      surface('implemented', 'electron-ipc', ['setLang']),
      surface('unsupported', 'no-op', ['setLang'], 'Renderer language changes remain available; there is no native menu to rebuild.'),
      surface('unsupported', 'no-op', ['setLang'], 'Renderer language changes remain available; there is no native menu to rebuild.')
    ),
    screenSnip: capability(
      'desktop-os',
      surface('implemented', 'electron-ipc', SCREEN_SNIP_METHODS),
      surface('unsupported', 'fail-closed', SCREEN_SNIP_METHODS, 'The Electron desktop capture overlay is not exposed to local Web.'),
      surface('unsupported', 'fail-closed', SCREEN_SNIP_METHODS, 'The Electron desktop capture overlay is not exposed to team Web.')
    ),
    directoryPicker: capability(
      'desktop-os',
      surface('implemented', 'electron-ipc', ['pickDirectory']),
      surface('unsupported', 'fail-closed', ['pickDirectory'], 'Browser sandboxing does not expose an unrestricted native directory picker.'),
      surface('unsupported', 'fail-closed', ['pickDirectory'], 'Browser sandboxing does not expose an unrestricted native directory picker.')
    ),
    embeddedBrowser: capability(
      'desktop-os',
      surface('implemented', 'electron-webview', [], 'The embedded browser is rendered only in the Electron surface.'),
      surface('unsupported', 'not-rendered', [], 'Local Web uses the host browser and does not nest an Electron webview.'),
      surface('unsupported', 'not-rendered', [], 'Team Web uses the host browser and does not nest an Electron webview.')
    ),
    mediaSave: capability(
      'browser-local',
      surface('implemented', 'electron-ipc', ['saveMedia']),
      surface('implemented-with-preconditions', 'browser-download', ['saveMedia'], 'Supports bytes and data/blob URLs; remote cross-origin downloads fail closed.'),
      surface('planned', 'browser-download', ['saveMedia'], 'Team Web transport and tenant-scoped delivery are not implemented.')
    )
  })
})

/** Both adapters expose this exact canonical object; the active surface is `runtimeKind`. */
export const ELECTRON_RUNTIME_CAPABILITIES = CLIENT_PORT_CAPABILITIES
export const WEB_RUNTIME_CAPABILITIES = CLIENT_PORT_CAPABILITIES

export function runtimeCapabilitiesFor(_runtimeKind: RuntimeKind): RuntimeCapabilityManifest {
  return CLIENT_PORT_CAPABILITIES
}

/**
 * Fail fast when a preload or Web shim drifts from its declared callable surface.
 * This validates build wiring only; it deliberately performs no health or authority checks.
 */
export function assertRuntimeApiMatchesDeclaration(
  api: object,
  declaration: RuntimeCapabilityManifest
): void {
  const record = api as Record<string, unknown>
  const runtimeKind = record.runtimeKind
  if (runtimeKind !== 'electron' && runtimeKind !== 'web') {
    throw new Error('Runtime API kind does not select a capability surface')
  }
  if (record.runtimeCapabilities !== declaration) {
    throw new Error('Runtime API does not expose its exact capability declaration')
  }

  const surfaceName: ClientPortSurface = runtimeKind === 'electron' ? 'electron' : 'localWeb'
  const declaredList = Object.values(declaration.capabilities).flatMap(
    (item) => item.surfaces[surfaceName].apiMethods
  )
  const declared = new Set<string>(declaredList)
  if (declared.size !== declaredList.length) {
    throw new Error('Runtime capability declaration contains duplicate API methods')
  }
  const actual = new Set(
    Object.entries(record)
      .filter(([, value]) => typeof value === 'function')
      .map(([key]) => key)
  )
  const missing = [...declared].filter((key) => !actual.has(key)).sort()
  const undeclared = [...actual].filter((key) => !declared.has(key)).sort()
  if (missing.length > 0) {
    throw new Error(`Runtime API missing declared methods: ${missing.join(', ')}`)
  }
  if (undeclared.length > 0) {
    throw new Error(`Runtime API has undeclared methods: ${undeclared.join(', ')}`)
  }
}
