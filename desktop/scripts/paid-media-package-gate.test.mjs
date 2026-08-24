import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, expect, it } from 'vitest'

import { createSettledAsarPackage } from './asar-test-fixture.mjs'
import { verifyPackagedPaidMediaControlPlane } from './_verify_pack.mjs'

const roots = []
const legacyMain = `
const PAID_MEDIA_IPC_CHANNELS = {
  claim: 'paid-media:claim',
  execute: "paid-media:execute",
  pollVideo: 'paid-media:poll-video',
  recoverArchive: 'paid-media:recover-archive',
  listArchives: 'paid-media:list-archives'
}
const dependencies = {
  ipcMain: { handle() {} },
  service: {
    claim() {},
    execute() {},
    pollVideo() {},
    recoverArchived() {},
    listRecoverableArchives() {}
  }
}
dependencies.ipcMain.handle(
  PAID_MEDIA_IPC_CHANNELS.claim,
  async (_event, input) => dependencies.service.claim(input)
)
dependencies.ipcMain.handle(
  PAID_MEDIA_IPC_CHANNELS.execute,
  async (_event, input) => dependencies.service.execute(input)
)
dependencies.ipcMain.handle(
  PAID_MEDIA_IPC_CHANNELS.pollVideo,
  async (_event, input) => dependencies.service.pollVideo(input)
)
dependencies.ipcMain.handle(
  PAID_MEDIA_IPC_CHANNELS.recoverArchive,
  async (_event, input) => dependencies.service.recoverArchived(input.operationId)
)
dependencies.ipcMain.handle(
  PAID_MEDIA_IPC_CHANNELS.listArchives,
  async (_event, input) => dependencies.service.listRecoverableArchives(input)
)
const app = { requestSingleInstanceLock() { return true } }
const ownsSingleInstance = app.requestSingleInstanceLock()
const event = { senderFrame: null }
const expectedWindow = { webContents: { mainFrame: null } }
const exactFrame = event.senderFrame === expectedWindow.webContents.mainFrame
const paidMediaKey = 'fixture-only'
const engineEnvironment = { NACHUAN_PAID_MEDIA_API_KEY: paidMediaKey }
const electron = { BrowserWindow: class BrowserWindow {} }
const path = { join: (...parts) => parts.join('/') }
const windowSecurityPreferences = (preload, options) => ({ preload, ...options })
const mainWindow = new electron.BrowserWindow({
  webPreferences: windowSecurityPreferences(path.join(__dirname, '../preload/index.js'), {})
})
const protocol = {
  registerSchemesAsPrivileged() {},
  handle() {}
}
protocol.registerSchemesAsPrivileged([{
  scheme: 'nachuan-paid-media',
  privileges: { standard: true, secure: true, supportFetchAPI: true, stream: true }
}])
class Headers {
  get() { return null }
  set() {}
}
class Response {}
class PaidMediaRangeError extends Error {}
const Readable = { toWeb(value) { return value } }
async function handlePaidMediaAssetRequest(request, vault) {
  const asset = await vault.openAsset(request.url)
  const range = request.headers.get('range')
  const headers = new Headers({
    'Accept-Ranges': 'bytes',
    'Content-Length': String(asset.byteLength)
  })
  if (range) headers.set('Content-Range', 'bytes 0-1/2')
  if (range === 'bad') return new Response(null, { status: 416, headers })
  if (request.method === 'HEAD') return new Response(null, { status: range ? 206 : 200, headers })
  const source = asset.handle.createReadStream({ start: 0, end: 1, autoClose: true })
  return new Response(Readable.toWeb(source), { status: range ? 206 : 200, headers })
}
protocol.handle('nachuan-paid-media', async (request) =>
  handlePaidMediaAssetRequest(request, paidMediaVault)
)
`

const v2Main = `
let paidMediaAssetV2StageReady = false

class PaidMediaAssetV2Runtime {
  async executeImage(input) {
    await this.authority.assertOutboundReady()
    await this.runRecoverableMutation({ kind: 'asset_v2_dispatch' })
    const created = await this.dependencies.createImageAssets(input)
    await this.runRecoverableMutation({ kind: 'asset_v2_stage_reserve' })
    const opened = await this.stageHandoff.takeStageOpenResult(created)
    const downloaded = await this.dependencies.downloadAsset(opened)
    const probed = await this.dependencies.probeAsset(downloaded)
    await this.runRecoverableMutation({ kind: 'asset_v2_stage_archive' })
    const archived = await this.vault.verifyArchive(probed)
    await this.runRecoverableMutation({ kind: 'asset_v2_result_ready_ack_intent' })
    return await this.convergeImageAck(archived)
  }

  async convergeImageAckOnce(input) {
    const archived = await this.vault.verifyArchive(input)
    await this.vault.verifyAssetV2DispatchMarker(archived)
    const intent = await this.vault.verifyAssetAckIntent(archived)
    const acknowledged = await this.dependencies.acknowledgeAssets(intent)
    await this.runRecoverableMutation({ kind: 'asset_v2_ack_completion' })
    const completed = await this.vault.verifyAssetAckCompletion(acknowledged)
    await this.runRecoverableMutation({ kind: 'asset_v2_capacity_release' })
    return await this.vault.verifyAssetCapacityReleaseAuthorization(completed)
  }
}

async function initializePaidMediaControlPlane() {
  const paidMediaEngineSessionClient = new PaidMediaEngineSessionClient()
  const paidMediaAssetV2Runtime = new PaidMediaAssetV2Runtime()
  await paidMediaVault.inspectStageRecovery()
  await activatePaidMediaEngineSessionStage({ sessionClient: paidMediaEngineSessionClient })
  paidMediaAssetV2StageReady = true
  const paidMediaAssetV2 = {
    executeImage: async (input) => {
      if (!paidMediaAssetV2StageReady) throw new Error('stage unavailable')
      return await paidMediaAssetV2Runtime.executeImage(input)
    },
    convergeImageAck: async (input) => {
      if (!paidMediaAssetV2StageReady) throw new Error('stage unavailable')
      return await paidMediaAssetV2Runtime.convergeImageAck(input)
    }
  }
  void paidMediaAssetV2
}
void initializePaidMediaControlPlane
`

const validMain = `${legacyMain}\n${v2Main}`

const paidMethodLines = {
  claimPaidMedia: `claimPaidMedia: (input) => invokePaidMedia('paid-media:claim', input),`,
  executePaidMedia: `executePaidMedia: (input) => invokePaidMedia("paid-media:execute", input),`,
  pollPaidVideo: `pollPaidVideo: (input) => invokePaidMedia('paid-media:poll-video', input),`,
  recoverPaidMediaArchive: `recoverPaidMediaArchive: (operationId) => invokePaidMedia('paid-media:recover-archive', { operationId }),`,
  listPaidMediaArchives: `listPaidMediaArchives: (input) => invokePaidMedia('paid-media:list-archives', input),`,
  cancelPaidMedia: `cancelPaidMedia: (operationId) => electron.ipcRenderer.send('paid-media:cancel', { operationId }),`,
  listPaidMediaOperations: `listPaidMediaOperations: () => invokePaidMedia('paid-media:list'),`,
  acknowledgePaidMedia: `acknowledgePaidMedia: (operationId) => invokePaidMedia('paid-media:acknowledge', { operationId }),`,
  abandonPaidMediaClaim: `abandonPaidMediaClaim: (operationId, evidence) => invokePaidMedia('paid-media:abandon', { operationId, evidence }),`,
  reconcilePaidMedia: `reconcilePaidMedia: (input) => invokePaidMedia('paid-media:reconcile', input),`,
  importLegacyPaidMediaJournal: `importLegacyPaidMediaJournal: (input) => invokePaidMedia('paid-media:import-legacy', input),`
}

function preloadProgram({ omittedMethod, expose = true } = {}) {
  return `
const electron = require('electron')
async function invokePaidMedia(channel, ...args) {
  const reply = await electron.ipcRenderer.invoke(channel, ...args)
  if (!reply || typeof reply !== 'object') throw new Error('Invalid paid media IPC reply')
  return reply.value
}
const api = {
${Object.entries(paidMethodLines)
  .filter(([method]) => method !== omittedMethod)
  .map(([, line]) => line)
  .join('\n')}
}
${expose ? `electron.contextBridge.exposeInMainWorld('api', api)` : 'void api'}
`
}

const validPreload = preloadProgram()

async function packagedAsar({
  main,
  preload,
  renderer,
  rendererChunks = {},
  preloadChunks = {},
  packageMain = './out/main/index.js',
  rendererHtml
}) {
  const root = mkdtempSync(join(tmpdir(), 'nachuan-paid-media-package-gate-'))
  roots.push(root)
  const sourceRoot = join(root, 'source')
  const resourcesRoot = join(root, 'resources')
  mkdirSync(join(sourceRoot, 'out', 'main'), { recursive: true })
  mkdirSync(join(sourceRoot, 'out', 'preload'), { recursive: true })
  mkdirSync(join(sourceRoot, 'out', 'renderer', 'assets'), { recursive: true })
  mkdirSync(resourcesRoot, { recursive: true })
  writeFileSync(
    join(sourceRoot, 'package.json'),
    JSON.stringify({ name: 'paid-media-gate-fixture', version: '1.0.0', main: packageMain })
  )
  writeFileSync(join(sourceRoot, 'out', 'main', 'index.js'), main)
  writeFileSync(join(sourceRoot, 'out', 'preload', 'index.js'), preload)
  for (const [name, source] of Object.entries(preloadChunks)) {
    const output = join(sourceRoot, 'out', 'preload', ...name.split('/'))
    mkdirSync(join(output, '..'), { recursive: true })
    writeFileSync(output, source)
  }
  writeFileSync(join(sourceRoot, 'out', 'renderer', 'assets', 'index-Fixture123.js'), renderer)
  writeFileSync(
    join(sourceRoot, 'out', 'renderer', 'index.html'),
    rendererHtml ??
      '<!doctype html><html><body><div id="root"></div><script type="module" src="./assets/index-Fixture123.js"></script></body></html>'
  )
  for (const [name, source] of Object.entries(rendererChunks)) {
    const output = join(sourceRoot, 'out', 'renderer', 'assets', ...name.split('/'))
    mkdirSync(join(output, '..'), { recursive: true })
    writeFileSync(output, source)
  }
  await createSettledAsarPackage(sourceRoot, join(resourcesRoot, 'app.asar'))
  return resourcesRoot
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true })
})

it('rejects a structurally complete legacy ASAR without the paid-media main control plane', async () => {
  const resourcesRoot = await packagedAsar({
    main: 'const legacyMain = true',
    preload: 'const legacyPreload = true',
    renderer: 'const legacyRenderer = true'
  })

  expect(() => verifyPackagedPaidMediaControlPlane({ resourcesRoot })).toThrow(
    /paid-media main control plane/i
  )
})

it('rejects a packaged control plane without the asset-v2 request-to-ACK pipeline', async () => {
  const resourcesRoot = await packagedAsar({
    main: legacyMain,
    preload: validPreload,
    renderer: 'const schema = "nachuan.paid-media.renderer-migrated.v2"'
  })

  expect(() => verifyPackagedPaidMediaControlPlane({ resourcesRoot })).toThrow(
    /asset-v2.*(?:session|stage|archive|ACK)/i
  )
})

it('binds the inspected main bundle to the final ASAR package entry point', async () => {
  const resourcesRoot = await packagedAsar({
    main: validMain,
    preload: validPreload,
    renderer: 'const schema = "nachuan.paid-media.renderer-migrated.v2"',
    packageMain: './out/main/alternate.js'
  })

  expect(() => verifyPackagedPaidMediaControlPlane({ resourcesRoot })).toThrow(
    /package entry point/i
  )
})

it('rejects paid-media main evidence that exists only inside strings and comments', async () => {
  const resourcesRoot = await packagedAsar({
    main: `const inert = ${JSON.stringify(validMain)}\n/* ${validMain} */`,
    preload: validPreload,
    renderer: 'const schema = "nachuan.paid-media.renderer-migrated.v2"'
  })

  expect(() => verifyPackagedPaidMediaControlPlane({ resourcesRoot })).toThrow(
    /paid-media main control plane/i
  )
})

it('requires every recovery-capable handler-to-service mapping in main', async () => {
  for (const [serviceMethod, channelMethod, call] of [
    ['claim', 'claim', 'dependencies.service.claim(input)'],
    ['execute', 'execute', 'dependencies.service.execute(input)'],
    ['pollVideo', 'pollVideo', 'dependencies.service.pollVideo(input)'],
    ['recoverArchived', 'recoverArchive', 'dependencies.service.recoverArchived(input.operationId)'],
    ['listRecoverableArchives', 'listArchives', 'dependencies.service.listRecoverableArchives(input)']
  ]) {
    expect(validMain).toContain(call)
    const resourcesRoot = await packagedAsar({
      main: validMain.replace(call, 'dependencies.service.unrelated(input)'),
      preload: validPreload,
      renderer: 'const schema = "nachuan.paid-media.renderer-migrated.v2"'
    })

    expect(() => verifyPackagedPaidMediaControlPlane({ resourcesRoot })).toThrow(
      new RegExp(`paid-media main control plane.*${channelMethod}`, 'i')
    )
  }
})

it('requires the privileged custom protocol and its pinned GET/HEAD Range path', async () => {
  for (const mutation of [
    ["scheme: 'nachuan-paid-media'", "scheme: 'legacy-media'"],
    ["protocol.handle('nachuan-paid-media'", "protocol.handle('legacy-media'"],
    ["request.headers.get('range')", "request.headers.get('ignored')"],
    ["'Content-Range'", "'Legacy-Range'"],
    ['status: 416', 'status: 400'],
    ['autoClose: true', 'autoClose: false'],
    ['Readable.toWeb(source)', 'source']
  ]) {
    const resourcesRoot = await packagedAsar({
      main: validMain.replace(mutation[0], mutation[1]),
      preload: validPreload,
      renderer: 'const schema = "nachuan.paid-media.renderer-migrated.v2"'
    })
    expect(() => verifyPackagedPaidMediaControlPlane({ resourcesRoot })).toThrow(
      /nachuan-paid-media|Range semantics/i
    )
  }
})

it('requires structural exact-frame, single-instance, and paid environment bindings in main', async () => {
  const mutations = [
    ['exact mainFrame', 'event.senderFrame === expectedWindow.webContents.mainFrame', 'true'],
    ['single-instance', 'app.requestSingleInstanceLock()', 'true'],
    ['paid environment', 'NACHUAN_PAID_MEDIA_API_KEY: paidMediaKey', 'paidMediaKey']
  ]
  for (const [label, expected, replacement] of mutations) {
    const resourcesRoot = await packagedAsar({
      main: validMain.replace(expected, replacement),
      preload: validPreload,
      renderer: 'const schema = "nachuan.paid-media.renderer-migrated.v2"'
    })

    expect(() => verifyPackagedPaidMediaControlPlane({ resourcesRoot }), label).toThrow(
      /paid-media main control plane/i
    )
  }
})

it('rejects preload method/channel evidence that exists only inside strings and comments', async () => {
  const resourcesRoot = await packagedAsar({
    main: validMain,
    preload: `const inert = ${JSON.stringify(validPreload)}\n/* ${validPreload} */`,
    renderer: 'const schema = "nachuan.paid-media.renderer-migrated.v2"'
  })

  expect(() => verifyPackagedPaidMediaControlPlane({ resourcesRoot })).toThrow(
    /paid-media preload control plane/i
  )
})

it('requires every narrow paid-media preload method to map to its actual channel', async () => {
  for (const missing of Object.keys(paidMethodLines)) {
    const resourcesRoot = await packagedAsar({
      main: validMain,
      preload: preloadProgram({ omittedMethod: missing }),
      renderer: 'const schema = "nachuan.paid-media.renderer-migrated.v2"'
    })

    expect(() => verifyPackagedPaidMediaControlPlane({ resourcesRoot })).toThrow(
      new RegExp(`paid-media preload control plane.*${missing}`, 'i')
    )
  }
})

it('requires invokePaidMedia to call ipcRenderer.invoke and exposes the mapped API through contextBridge', async () => {
  for (const preload of [
    validPreload.replace('electron.ipcRenderer.invoke(channel, ...args)', 'Promise.resolve(args)'),
    preloadProgram({ expose: false })
  ]) {
    const resourcesRoot = await packagedAsar({
      main: validMain,
      preload,
      renderer: 'const schema = "nachuan.paid-media.renderer-migrated.v2"'
    })

    expect(() => verifyPackagedPaidMediaControlPlane({ resourcesRoot })).toThrow(
      /paid-media preload control plane/i
    )
  }
})

it('binds every BrowserWindow preload target to the only packaged preload JavaScript file', async () => {
  for (const fixture of [
    {
      main: validMain.replace('../preload/index.js', '../preload/evil.js'),
      preloadChunks: { 'evil.js': 'const bypass = true' }
    },
    {
      main: validMain,
      preloadChunks: { 'unused.js': 'const bypass = true' }
    }
  ]) {
    const resourcesRoot = await packagedAsar({
      ...fixture,
      preload: validPreload,
      renderer: 'const schema = "nachuan.paid-media.renderer-migrated.v2"'
    })

    expect(() => verifyPackagedPaidMediaControlPlane({ resourcesRoot })).toThrow(
      /paid-media (?:main|preload) control plane.*preload/i
    )
  }
})

it('discovers the hashed renderer bundle in the final ASAR and requires the migration sentinel', async () => {
  const resourcesRoot = await packagedAsar({
    main: validMain,
    preload: validPreload,
    renderer: 'const legacyRenderer = true'
  })

  expect(() => verifyPackagedPaidMediaControlPlane({ resourcesRoot })).toThrow(
    /paid-media renderer control plane.*nachuan\.paid-media\.renderer-migrated\.v2/i
  )
})

it('rejects renderer bundles that carry paid-media authority or direct idempotent-fetch evidence', async () => {
  for (const forbidden of [
    'X-Nachuan-Paid-Media-Key',
    'NACHUAN_PAID_MEDIA_API_KEY',
    'Idempotency-Key'
  ]) {
    const resourcesRoot = await packagedAsar({
      main: validMain,
      preload: validPreload,
      renderer: `nachuan.paid-media.renderer-migrated.v2\n${forbidden}`
    })

    expect(() => verifyPackagedPaidMediaControlPlane({ resourcesRoot })).toThrow(
      /forbidden paid-media renderer evidence/i
    )
  }
})

it('scans every renderer JavaScript chunk, not only the hashed index entry', async () => {
  const resourcesRoot = await packagedAsar({
    main: validMain,
    preload: validPreload,
    renderer: 'const schema = "nachuan.paid-media.renderer-migrated.v2"',
    rendererChunks: {
      'vendor-Evil456.js': `const stolen = 'X-Nachuan-Paid-Media-Key'`
    }
  })

  expect(() => verifyPackagedPaidMediaControlPlane({ resourcesRoot })).toThrow(
    /forbidden paid-media renderer evidence/i
  )
})

it('requires a closed flat renderer JavaScript asset path set and one hashed index entry', async () => {
  for (const rendererChunks of [
    { 'nested/evil.js': 'const hidden = true' },
    { 'index-Second456.js': 'const secondEntry = true' }
  ]) {
    const resourcesRoot = await packagedAsar({
      main: validMain,
      preload: validPreload,
      renderer: 'const schema = "nachuan.paid-media.renderer-migrated.v2"',
      rendererChunks
    })

    expect(() => verifyPackagedPaidMediaControlPlane({ resourcesRoot })).toThrow(
      /(?:renderer.*path|exactly one hashed renderer)/i
    )
  }
})

it('binds the unique renderer index entry to the only executable HTML script', async () => {
  for (const rendererHtml of [
    '<!doctype html><script type="module" src="./assets/alternate.js"></script>',
    '<!doctype html><script>window.evil = true</script><script type="module" src="./assets/index-Fixture123.js"></script>'
  ]) {
    const resourcesRoot = await packagedAsar({
      main: validMain,
      preload: validPreload,
      renderer: 'const schema = "nachuan.paid-media.renderer-migrated.v2"',
      rendererChunks: { 'alternate.js': 'const alternate = true' },
      rendererHtml
    })

    expect(() => verifyPackagedPaidMediaControlPlane({ resourcesRoot })).toThrow(
      /renderer HTML script/i
    )
  }
})

it('bounds each renderer JavaScript asset before inspecting it', async () => {
  const resourcesRoot = await packagedAsar({
    main: validMain,
    preload: validPreload,
    renderer: 'const schema = "nachuan.paid-media.renderer-migrated.v2"',
    rendererChunks: {
      'oversized-Fixture456.js': `/*${'x'.repeat(16 * 1024 * 1024)}*/`
    }
  })

  expect(() => verifyPackagedPaidMediaControlPlane({ resourcesRoot })).toThrow(
    /renderer.*bounded/i
  )
})

it('accepts a final ASAR whose main, preload, and hashed renderer bundles preserve the control plane', async () => {
  const resourcesRoot = await packagedAsar({
    main: validMain,
    preload: validPreload,
    renderer: 'const schema = "nachuan.paid-media.renderer-migrated.v2"'
  })

  expect(() => verifyPackagedPaidMediaControlPlane({ resourcesRoot })).not.toThrow()
})
