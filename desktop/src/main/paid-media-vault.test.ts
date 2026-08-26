import { createHash } from 'node:crypto'
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmdirSync,
  rmSync,
  statSync,
  unlinkSync,
  utimesSync,
  writeFileSync
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'

import type { PaidMediaSafeStorage } from './paid-media-ledger'
import {
  PAID_MEDIA_ASSET_RESULT_SCHEMA,
  paidMediaAssetResultDigest,
  paidMediaTokenSetDigest,
  type PaidMediaAssetResult
} from './paid-media-asset-protocol'
import {
  MAX_PAID_MEDIA_ARCHIVE_ASSET_BYTES,
  PaidMediaVault,
  PaidMediaVaultError,
  type PaidMediaArchivedAsset,
  type PaidMediaVaultAuthorityTailRecoveryInput,
  type PaidMediaSealedStageCapability,
  type PaidMediaVaultDependencies,
  type PaidMediaRemoteFetcher,
  type PaidMediaTrustedProbeResult
} from './paid-media-vault'

const OPERATION_ID = 'desktop-op-11111111-1111-4111-8111-111111111111'
const OTHER_OPERATION_ID = 'desktop-op-22222222-2222-4222-8222-222222222222'
// Cross-runtime provider Unix timestamp; this is never an asset count.
const PAID_MEDIA_RESULT_CREATED = 1_784_200_000

function sha256(value: Buffer | string): string {
  return createHash('sha256').update(value).digest('hex')
}

async function cleanupStageLease(
  vault: PaidMediaVault,
  leaseId: string,
  operationId = OPERATION_ID
): ReturnType<PaidMediaVault['cleanupStageLease']> {
  const inspection = await vault.inspectStageRecovery()
  const lease = inspection.leases.find((candidate) => candidate.leaseId === leaseId)
  if (!lease) throw new Error('expected active stage cleanup binding')
  return vault.cleanupStageLease({
    operationId,
    leaseId,
    generation: lease.generation,
    resultSha256: lease.resultSha256
  })
}

async function trustedProbe(input: {
  mediaType: PaidMediaTrustedProbeResult['mediaType']
  byteLength: number
  sha256: string
}): Promise<PaidMediaTrustedProbeResult> {
  const base = {
    schema: 'nachuan.trusted-media-validation.v2' as const,
    validatorVersion: 'nachuan.trusted-media-probe.v2' as const,
    validationPolicy: 'nachuan.trusted-media-policy.av-closed.v1' as const,
    fullyDecoded: true as const,
    mediaType: input.mediaType,
    byteLength: input.byteLength,
    sha256: input.sha256,
    attestedTools: { ffmpegSha256: 'a'.repeat(64), ffprobeSha256: 'b'.repeat(64) },
    metadata: {
      detectedKind: (input.mediaType.startsWith('image/') ? 'image' : 'video') as
        | 'image'
        | 'video',
      codecName: 'test-codec',
      audioCodecName: null,
      videoStreamCount: 1 as const,
      audioStreamCount: 0 as const,
      formatName: 'test-format',
      width: 1,
      height: 1,
      durationMs: input.mediaType.startsWith('image/') ? null : 1_000,
      decodedFrames: 1
    }
  }
  const canonical = {
    attestedTools: base.attestedTools,
    byteLength: base.byteLength,
    fullyDecoded: base.fullyDecoded,
    mediaType: base.mediaType,
    metadata: {
      audioCodecName: base.metadata.audioCodecName,
      audioStreamCount: base.metadata.audioStreamCount,
      codecName: base.metadata.codecName,
      decodedFrames: base.metadata.decodedFrames,
      detectedKind: base.metadata.detectedKind,
      durationMs: base.metadata.durationMs,
      formatName: base.metadata.formatName,
      height: base.metadata.height,
      videoStreamCount: base.metadata.videoStreamCount,
      width: base.metadata.width
    },
    schema: base.schema,
    sha256: base.sha256,
    validationPolicy: base.validationPolicy,
    validatorVersion: base.validatorVersion
  }
  return {
    ...base,
    receiptSha256: createHash('sha256')
      .update('nachuan.trusted-media-validation.v2\0', 'utf8')
      .update(JSON.stringify(canonical), 'ascii')
      .digest('hex')
  }
}
const PNG = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=',
  'base64'
)
const MP4_FTYP_ONLY = Buffer.from(
  '000000186674797069736f6d0000020069736f6d6d703431',
  'hex'
)

function mp4Box(type: string, payload: Buffer): Buffer {
  const box = Buffer.alloc(8 + payload.length)
  box.writeUInt32BE(box.length, 0)
  box.write(type, 4, 4, 'ascii')
  payload.copy(box, 8)
  return box
}

const MP4_STRUCTURAL_SHELL = Buffer.concat([
  MP4_FTYP_ONLY,
  mp4Box(
    'moov',
    Buffer.concat([
      mp4Box('mvhd', Buffer.alloc(4)),
      mp4Box('trak', mp4Box('mdia', Buffer.alloc(4)))
    ])
  ),
  mp4Box('mdat', Buffer.from([0]))
])
const MP4 = Buffer.from(
  'AAAAIGZ0eXBpc29tAAACAGlzb21pc28yYXZjMW1wNDEAAAMUbW9vdgAAAGxtdmhkAAAAAAAAAAAAAAAAAAAD6AAAAMgAAQAAAQAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAj90cmFrAAAAXHRraGQAAAADAAAAAAAAAAAAAAABAAAAAAAAAMgAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAABAAAAAABAAAAAQAAAAAAAkZWR0cwAAABxlbHN0AAAAAAAAAAEAAADIAAAAAAABAAAAAAG3bWRpYQAAACBtZGhkAAAAAAAAAAAAAAAAAAAoAAAACABVxAAAAAAALWhkbHIAAAAAAAAAAHZpZGUAAAAAAAAAAAAAAABWaWRlb0hhbmRsZXIAAAABYm1pbmYAAAAUdm1oZAAAAAEAAAAAAAAAAAAAACRkaW5mAAAAHGRyZWYAAAAAAAAAAQAAAAx1cmwgAAAAAQAAASJzdGJsAAAAvnN0c2QAAAAAAAAAAQAAAK5hdmMxAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAABAAEABIAAAASAAAAAAAAAABFUxhdmM2Mi4xMS4xMDAgbGlieDI2NAAAAAAAAAAAAAAAGP//AAAANGF2Y0MBZAAK/+EAF2dkAAqs2V7ARAAAAwAEAAADACg8SJZYAQAGaOvjyyLA/fj4AAAAABBwYXNwAAAAAQAAAAEAAAAUYnRydAAAAAAAAG6gAAAAAAAAABhzdHRzAAAAAAAAAAEAAAABAAAIAAAAABxzdHNjAAAAAAAAAAEAAAABAAAAAQAAAAEAAAAUc3RzegAAAAAAAALEAAAAAQAAABRzdGNvAAAAAAAAAAEAAANEAAAAYXVkdGEAAABZbWV0YQAAAAAAAAAhaGRscgAAAAAAAAAAbWRpcmFwcGwAAAAAAAAAAAAAAAAsaWxzdAAAACSpdG9vAAAAHGRhdGEAAAABAAAAAExhdmY2Mi4zLjEwMAAAAAhmcmVlAAACzG1kYXQAAAKtBgX//6ncRem95tlIt5Ys2CDZI+7veDI2NCAtIGNvcmUgMTY1IHIzMjIzIDA0ODBjYjAgLSBILjI2NC9NUEVHLTQgQVZDIGNvZGVjIC0gQ29weWxlZnQgMjAwMy0yMDI1IC0gaHR0cDovL3d3dy52aWRlb2xhbi5vcmcveDI2NC5odG1sIC0gb3B0aW9uczogY2FiYWM9MSByZWY9MyBkZWJsb2NrPTE6MDowIGFuYWx5c2U9MHgzOjB4MTEzIG1lPWhleCBzdWJtZT03IHBzeT0xIHBzeV9yZD0xLjAwOjAuMDAgbWl4ZWRfcmVmPTEgbWVfcmFuZ2U9MTYgY2hyb21hX21lPTEgdHJlbGxpcz0xIDh4OGRjdD0xIGNxbT0wIGRlYWR6b25lPTIxLDExIGZhc3RfcHNraXA9MSBjaHJvbWFfcXBfb2Zmc2V0PS0yIHRocmVhZHM9MSBsb29rYWhlYWRfdGhyZWFkcz0xIHNsaWNlZF90aHJlYWRzPTAgbnI9MCBkZWNpbWF0ZT0xIGludGVybGFjZWQ9MCBibHVyYXlfY29tcGF0PTAgY29uc3RyYWluZWRfaW50cmE9MCBiZnJhbWVzPTMgYl9weXJhbWlkPTIgYl9hZGFwdD0xIGJfYmlhcz0wIGRpcmVjdD0xIHdlaWdodGI9MSBvcGVuX2dvcD0wIHdlaWdodHA9MiBrZXlpbnQ9MjUwIGtleWludF9taW49NSBzY2VuZWN1dD00MCBpbnRyYV9yZWZyZXNoPTAgcmNfbG9va2FoZWFkPTQwIHJjPWNyZiBtYnRyZWU9MSBjcmY9MjMuMCBxY29tcD0wLjYwIHFwbWluPTAgcXBtYXg9NjkgcXBzdGVwPTQgaXBfcmF0aW89MS40MCBhcT0xOjEuMDAAgAAAAA9liIQAP//+92ifApteYbk=',
  'base64'
)

function testCrc32(bytes: Buffer): number {
  let crc = 0xffffffff
  for (const byte of bytes) {
    crc ^= byte
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc & 1) !== 0 ? 0xedb88320 ^ (crc >>> 1) : crc >>> 1
    }
  }
  return (crc ^ 0xffffffff) >>> 0
}

function pngWithAncillaryPadding(bytes: Buffer, paddingBytes: number): Buffer {
  const type = Buffer.from('npAD', 'ascii')
  const data = Buffer.alloc(paddingBytes, 0x5a)
  const chunk = Buffer.alloc(12 + data.length)
  chunk.writeUInt32BE(data.length, 0)
  type.copy(chunk, 4)
  data.copy(chunk, 8)
  chunk.writeUInt32BE(testCrc32(Buffer.concat([type, data])), 8 + data.length)
  return Buffer.concat([bytes.subarray(0, -12), chunk, bytes.subarray(-12)])
}

const fakeStorage: PaidMediaSafeStorage = {
  isEncryptionAvailable: () => true,
  encryptString: (value) => Buffer.from(`protected:${value}`, 'utf8'),
  decryptString: (value) => {
    const text = value.toString('utf8')
    if (!text.startsWith('protected:')) throw new Error('invalid ciphertext')
    return text.slice('protected:'.length)
  }
}

const roots: string[] = []

afterEach(() => {
  while (roots.length > 0) rmSync(roots.pop()!, { recursive: true, force: true })
}, 60_000)

function fixture(
  fetchRemote?: PaidMediaRemoteFetcher,
  extraDependencies: Partial<
    Pick<
    PaidMediaVaultDependencies,
    | 'beforeAuthorityHeadCommit'
    | 'onValidationMigrationDirectoryEnumeration'
    | 'beforeStageFileCreate'
    | 'beforeStageOpenedCommit'
    | 'beforeArchivedStageCleanupIntent'
    | 'stageCleanupIO'
    | 'onAuthorityJournalReplay'
    | 'onStageHandleUse'
    | 'onStageStreamChunk'
    | 'onStageArchiveAsset'
    | 'afterStageAssetPublished'
    | 'afterStageAssetLinkedBeforeAuthority'
    | 'validateMediaAsset'
    >
  > = {}
): {
  root: string
  stageRoot: string
  harden: ReturnType<typeof vi.fn>
  fetchRemote: ReturnType<typeof vi.fn<PaidMediaRemoteFetcher>>
  vault: PaidMediaVault
} {
  const root = mkdtempSync(join(tmpdir(), 'nachuan-paid-vault-'))
  const stageRoot = mkdtempSync(join(tmpdir(), 'nachuan-paid-stage-root-'))
  roots.push(root, stageRoot)
  const harden = vi.fn()
  const fetcher = vi.fn<PaidMediaRemoteFetcher>(
    fetchRemote ??
      (async (url) => ({
        bytes: PNG,
        contentType: 'image/png',
        finalUrl: url
      }))
  )
  return {
    root,
    stageRoot,
    harden,
    fetchRemote: fetcher,
    vault: new PaidMediaVault(root, {
      safeStorage: fakeStorage,
      harden,
      now: () => 1_800_000_000_000,
      fetchRemote: fetcher,
      ensureMediaProbeReady: async () => undefined,
      validateMediaAsset: trustedProbe,
      stageRoot: () => stageRoot,
      ...extraDependencies
    })
  }
}

function paidMediaStageResult(
  bytes: Buffer<ArrayBufferLike> = PNG,
  count = 1
): PaidMediaAssetResult {
  return {
    schema: PAID_MEDIA_ASSET_RESULT_SCHEMA,
    kind: 'image',
    created: PAID_MEDIA_RESULT_CREATED,
    turnId: 'd'.repeat(64),
    assets: Array.from({ length: count }, (_, ordinal) => {
      const tokenCharacter = String.fromCharCode('A'.charCodeAt(0) + ordinal)
      return {
        token: `nma1_${tokenCharacter.repeat(43)}`,
        mediaType: 'image/png',
        byteLength: bytes.length,
        sha256: createHash('sha256').update(bytes).digest('hex'),
        validationReceiptSha256: 'e'.repeat(64)
      }
    })
  }
}

function readProtectedDocument(path: string): Record<string, unknown> {
  const envelope = JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>
  const ciphertext = Buffer.from(String(envelope.ciphertext), 'base64').toString('utf8')
  if (!ciphertext.startsWith('protected:')) throw new Error('invalid protected test document')
  return JSON.parse(ciphertext.slice('protected:'.length)) as Record<string, unknown>
}

function writeProtectedDocument(path: string, document: Record<string, unknown>): void {
  const ciphertext = Buffer.from(`protected:${JSON.stringify(document)}`, 'utf8')
  writeFileSync(
    path,
    JSON.stringify({
      schema: 'nachuan.paid-media-vault.envelope.v1',
      protection: 'electron-safe-storage',
      ciphertext: ciphertext.toString('base64')
    })
  )
}

function encodeProtectedDocument(document: Record<string, unknown>): Buffer {
  const ciphertext = Buffer.from(`protected:${JSON.stringify(document)}`, 'utf8')
  return Buffer.from(
    JSON.stringify({
      schema: 'nachuan.paid-media-vault.envelope.v1',
      protection: 'electron-safe-storage',
      ciphertext: ciphertext.toString('base64')
    }),
    'utf8'
  )
}

function readAuthorityJournal(root: string): Record<string, unknown>[] {
  const bytes = readFileSync(`${root}.authority.journal`)
  const events: Record<string, unknown>[] = []
  let offset = 0
  while (offset < bytes.length) {
    const length = bytes.readUInt32BE(offset)
    offset += 4
    const envelope = JSON.parse(
      bytes.subarray(offset, offset + length).toString('utf8')
    ) as Record<string, unknown>
    const plaintext = Buffer.from(String(envelope.ciphertext), 'base64').toString('utf8')
    if (!plaintext.startsWith('protected:')) throw new Error('invalid protected journal event')
    events.push(JSON.parse(plaintext.slice('protected:'.length)) as Record<string, unknown>)
    offset += length
  }
  return events
}

function rewriteAuthorityJournal(root: string, events: Record<string, unknown>[]): void {
  const records = events.map((event) => {
    const payload = encodeProtectedDocument(event)
    const record = Buffer.allocUnsafe(4 + payload.length)
    record.writeUInt32BE(payload.length, 0)
    payload.copy(record, 4)
    return record
  })
  const journal = Buffer.concat(records)
  writeFileSync(`${root}.authority.journal`, journal)
  const headPath = `${root}.authority.json`
  const head = readProtectedDocument(headPath)
  head.journalByteLength = journal.length
  const finalState = events.at(-1)?.stateDigest
  if (typeof finalState === 'string') head.stateDigest = finalState
  writeProtectedDocument(headPath, head)
}

function recomputeStageEventDigests(event: Record<string, unknown>): void {
  const stage = event.stage as Record<string, unknown>
  const { leaseStateDigest: _oldLeaseDigest, ...stageBase } = stage
  stage.leaseStateDigest = createHash('sha256')
    .update('nachuan.desktop.paid-media-stage-lease-state.v2\0', 'ascii')
    .update(JSON.stringify(stageBase), 'utf8')
    .digest('hex')
  recomputeAuthorityEventDigest(event)
}

function recomputeAuthorityEventDigest(event: Record<string, unknown>): void {
  const { stateDigest: _oldStateDigest, ...eventBase } = event
  event.stateDigest = createHash('sha256')
    .update('nachuan.desktop.paid-media-vault-index-state.v1\0', 'ascii')
    .update(JSON.stringify(eventBase), 'utf8')
    .digest('hex')
}

function removeEmbeddedValidation(path: string, terminal: boolean): void {
  const document = readProtectedDocument(path)
  const target = terminal
    ? (document.asset as Record<string, unknown>)
    : ((document.assets as Record<string, unknown>[])[0] as Record<string, unknown>)
  delete target.validation
  const { receiptSha256: _discarded, ...base } = document
  writeProtectedDocument(path, {
    ...base,
    receiptSha256: createHash('sha256').update(JSON.stringify(base)).digest('hex')
  })
}

function legacyV1Validation(
  asset: Pick<PaidMediaArchivedAsset, 'mediaType' | 'byteLength' | 'sha256'>
): Record<string, unknown> {
  const base = {
    schema: 'nachuan.trusted-media-validation.v1',
    validatorVersion: 'nachuan.trusted-media-probe.v1',
    fullyDecoded: true,
    mediaType: asset.mediaType,
    byteLength: asset.byteLength,
    sha256: asset.sha256,
    attestedTools: { ffmpegSha256: '1'.repeat(64), ffprobeSha256: '2'.repeat(64) },
    metadata: {
      detectedKind: asset.mediaType.startsWith('image/') ? 'image' : 'video',
      codecName: 'legacy-codec',
      formatName: 'legacy-format',
      width: 1,
      height: 1,
      durationMs: asset.mediaType.startsWith('image/') ? null : 1_000,
      decodedFrames: 1
    }
  }
  const canonical = {
    attestedTools: base.attestedTools,
    byteLength: base.byteLength,
    fullyDecoded: base.fullyDecoded,
    mediaType: base.mediaType,
    metadata: {
      codecName: base.metadata.codecName,
      decodedFrames: base.metadata.decodedFrames,
      detectedKind: base.metadata.detectedKind,
      durationMs: base.metadata.durationMs,
      formatName: base.metadata.formatName,
      height: base.metadata.height,
      width: base.metadata.width
    },
    schema: base.schema,
    sha256: base.sha256,
    validatorVersion: base.validatorVersion
  }
  return {
    ...base,
    receiptSha256: createHash('sha256')
      .update('nachuan.trusted-media-validation.v1\0', 'utf8')
      .update(JSON.stringify(canonical), 'ascii')
      .digest('hex')
  }
}

function replaceEmbeddedValidation(
  path: string,
  terminal: boolean,
  validation: Record<string, unknown>
): void {
  const document = readProtectedDocument(path)
  const target = terminal
    ? (document.asset as Record<string, unknown>)
    : ((document.assets as Record<string, unknown>[])[0] as Record<string, unknown>)
  target.validation = validation
  const { receiptSha256: _discarded, ...base } = document
  writeProtectedDocument(path, {
    ...base,
    receiptSha256: createHash('sha256').update(JSON.stringify(base)).digest('hex')
  })
}

function writeLegacyV1Sidecar(
  root: string,
  asset: Pick<PaidMediaArchivedAsset, 'sha256'>,
  validation: Record<string, unknown>
): string {
  const base = {
    schema: 'nachuan.paid-media-vault.asset-validation.v1',
    assetSha256: asset.sha256,
    validation
  }
  const path = join(root, 'asset-validations', `${asset.sha256}.json`)
  writeProtectedDocument(path, {
    ...base,
    sidecarSha256: createHash('sha256').update(JSON.stringify(base)).digest('hex')
  })
  return path
}

async function recordImageClaim(
  vault: PaidMediaVault,
  encodedBody: string,
  operationId = OPERATION_ID
): Promise<void> {
  await vault.recordClaim({
    operationId,
    path: '/v1/images/generations',
    encodedBody
  })
}

async function collectSmallStageFixture(
  vault: PaidMediaVault,
  sealed: PaidMediaSealedStageCapability
): Promise<Buffer> {
  const source = vault.createSealedStageReadSource(sealed)
  const chunks: Buffer[] = []
  let total = 0
  for await (const raw of source.createReadStream()) {
    const chunk = Buffer.isBuffer(raw) ? raw : Buffer.from(raw)
    total += chunk.length
    if (total > 1024 * 1024) throw new Error('test-only stage collection exceeded 1 MiB')
    chunks.push(chunk)
  }
  return Buffer.concat(chunks, total)
}

async function v2SidecarResultFixture(): Promise<{
  validation: PaidMediaTrustedProbeResult
  result: PaidMediaAssetResult
  resultSha256: string
}> {
  const validation = await trustedProbe({
    mediaType: 'image/png',
    byteLength: PNG.length,
    sha256: sha256(PNG)
  })
  const initial = paidMediaStageResult()
  const result: PaidMediaAssetResult = {
    ...initial,
    assets: [
      {
        ...initial.assets[0]!,
        validationReceiptSha256: validation.receiptSha256
      }
    ]
  }
  return { validation, result, resultSha256: paidMediaAssetResultDigest(result) }
}

async function createArchivedV2RecoveryFixture(
  item: ReturnType<typeof fixture>,
  options: { dispatch?: boolean } = {}
): Promise<{
  result: PaidMediaAssetResult
  resultSha256: string
  archive: Awaited<ReturnType<PaidMediaVault['archiveSealedStageImageResult']>>
  dispatch: Awaited<ReturnType<PaidMediaVault['recordAssetV2DispatchMarker']>> | null
}> {
  const { validation, result, resultSha256 } = await v2SidecarResultFixture()
  const claim = await item.vault.recordClaim({
    operationId: OPERATION_ID,
    path: '/v1/images/generations',
    encodedBody: JSON.stringify({ model: 'image-model', prompt: 'v2 sidecar evidence' })
  })
  const dispatch =
    options.dispatch === false
      ? null
      : await item.vault.recordAssetV2DispatchMarker({
          operationId: OPERATION_ID,
          path: claim.path,
          requestSha256: claim.requestSha256,
          recoveryDomainSha256: '2'.repeat(64),
          paidPrincipalSha256: '3'.repeat(64),
          turnId: result.turnId,
          assetResultSha256: resultSha256
        })
  const opened = await item.vault.reserveAndOpenStageLeases({
    operationId: OPERATION_ID,
    result
  })
  if (!opened.ok) throw new Error('expected opened v2 sidecar stage lease')
  const writeCapability = opened.capabilities[0]!
  await writeCapability.write(PNG, 0)
  await writeCapability.sync()
  const sealed = await item.vault.sealStageWriteCapability(writeCapability)
  const archive = await item.vault.archiveSealedStageImageResult({
    operationId: OPERATION_ID,
    status: 200,
    result,
    assets: [{ ordinal: 0, sealed, validation }]
  })
  return { result, resultSha256, archive, dispatch }
}

async function recordV2AckChain(
  vault: PaidMediaVault,
  prepared: Awaited<ReturnType<typeof createArchivedV2RecoveryFixture>>,
  replayed = false
): Promise<{
  intent: Awaited<ReturnType<PaidMediaVault['recordAssetAckIntent']>>
  completion: Awaited<ReturnType<PaidMediaVault['recordAssetAckCompletion']>>
}> {
  if (!prepared.dispatch) throw new Error('expected a v2 dispatch marker')
  const tokens = prepared.result.assets.map((asset) => asset.token)
  const intent = await vault.recordAssetAckIntent({
    operationId: OPERATION_ID,
    turnId: prepared.result.turnId,
    tokens,
    tokenSetDigest: paidMediaTokenSetDigest(tokens),
    archiveReceiptSha256: prepared.archive.receipt.receiptSha256,
    assetResultSha256: prepared.resultSha256,
    dispatchReceiptSha256: prepared.dispatch.receiptSha256
  })
  const completion = await vault.recordAssetAckCompletion({
    operationId: OPERATION_ID,
    intentReceiptSha256: intent.receiptSha256,
    status: 200,
    response: {
      ok: true,
      turnId: prepared.result.turnId,
      replayed,
      cleanupComplete: true
    }
  })
  return { intent, completion }
}

// This suite intentionally exercises real atomic files, pinned handles,
// validation receipts and cleanup recovery. Keep the wider Windows durability
// budget local to the vault suite; ordinary Desktop tests remain at 30 seconds.
describe('PaidMediaVault', { timeout: 120_000 }, () => {
  it('fails closed before harden or mkdir when no dedicated stage root is configured', async () => {
    const root = mkdtempSync(join(tmpdir(), 'nachuan-paid-vault-'))
    roots.push(root)
    const harden = vi.fn()
    const vault = new PaidMediaVault(root, {
      safeStorage: fakeStorage,
      harden,
      now: () => 1_800_000_000_000,
      fetchRemote: async (url) => ({ bytes: PNG, finalUrl: url }),
      ensureMediaProbeReady: async () => undefined,
      validateMediaAsset: trustedProbe
    })
    await vault.provisionAuthorityVault()
    vault.setMutationGuard(() => undefined)
    const hardenCalls = harden.mock.calls.length
    const stageLeavesBefore = readdirSync(tmpdir()).filter((name) =>
      name.startsWith('nachuan-paid-media-stage-')
    )
    let failure: unknown = null
    let unexpectedlyOpened: Awaited<ReturnType<PaidMediaVault['reserveAndOpenStageLeases']>> | null =
      null
    try {
      unexpectedlyOpened = await vault.reserveAndOpenStageLeases({
        operationId: OPERATION_ID,
        result: paidMediaStageResult()
      })
    } catch (error) {
      failure = error
    }
    if (unexpectedlyOpened?.ok) {
      await cleanupStageLease(vault, unexpectedlyOpened.capabilities[0]!.leaseId)
    }
    expect(failure).toBeInstanceOf(PaidMediaVaultError)
    expect(String((failure as Error).message)).toMatch(/dedicated stage root.*required/i)
    expect(harden).toHaveBeenCalledTimes(hardenCalls)
    expect(
      readdirSync(tmpdir()).filter((name) => name.startsWith('nachuan-paid-media-stage-'))
    ).toEqual(stageLeavesBefore)
  })

  it('treats the cross-runtime created field as one timestamp for one or four assets', async () => {
    for (const count of [1, 4]) {
      const item = fixture()
      await item.vault.provisionAuthorityVault()
      item.vault.setMutationGuard(() => undefined)
      const result = paidMediaStageResult(PNG, count)
      expect(result.created).toBe(PAID_MEDIA_RESULT_CREATED)
      const opened = await item.vault.reserveAndOpenStageLeases({
        operationId: OPERATION_ID,
        result
      })
      if (!opened.ok) throw new Error('expected opened timestamp-bound stage leases')
      expect(opened.capabilities).toHaveLength(count)
      for (const capability of opened.capabilities) {
        await cleanupStageLease(item.vault, capability.leaseId)
      }
    }
  })

  it('rejects cleanup of another operation stage lease inside the current Root mutation', async () => {
    const item = fixture()
    await item.vault.provisionAuthorityVault()
    let activeOperationId = OTHER_OPERATION_ID
    item.vault.setMutationGuard(() => {
      if (!activeOperationId) throw new Error('outside Root transaction')
    })
    const opened = await item.vault.reserveAndOpenStageLeases({
      operationId: OTHER_OPERATION_ID,
      result: paidMediaStageResult()
    })
    if (!opened.ok) throw new Error('expected another operation stage lease')

    activeOperationId = OPERATION_ID
    await expect(
      cleanupStageLease(item.vault, opened.capabilities[0]!.leaseId, activeOperationId)
    ).rejects.toThrow(/operation.*match|binding.*conflict/i)
    await cleanupStageLease(
      item.vault,
      opened.capabilities[0]!.leaseId,
      OTHER_OPERATION_ID
    )
  })

  it('rejects a stale cleanup ticket after the same lease id is reopened in a new generation', async () => {
    const item = fixture()
    await item.vault.provisionAuthorityVault()
    item.vault.setMutationGuard(() => undefined)
    const result = paidMediaStageResult()
    const first = await item.vault.reserveAndOpenStageLeases({
      operationId: OPERATION_ID,
      result
    })
    if (!first.ok) throw new Error('expected first stage lease generation')
    const leaseId = first.capabilities[0]!.leaseId
    const firstInspection = await item.vault.inspectStageRecovery()
    const firstLease = firstInspection.leases.find((candidate) => candidate.leaseId === leaseId)
    if (!firstLease) throw new Error('expected first stage cleanup binding')
    const staleCleanupTicket = {
      operationId: OPERATION_ID,
      leaseId,
      generation: firstLease.generation,
      resultSha256: firstLease.resultSha256
    }
    await item.vault.cleanupStageLease(staleCleanupTicket)

    const reopened = await item.vault.reserveAndOpenStageLeases({
      operationId: OPERATION_ID,
      result
    })
    if (!reopened.ok) throw new Error('expected reopened stage lease generation')
    expect(reopened.capabilities[0]!.leaseId).toBe(leaseId)

    await expect(
      item.vault.cleanupStageLease(staleCleanupTicket)
    ).rejects.toThrow(/generation|stale|binding.*conflict/i)
    await cleanupStageLease(item.vault, leaseId)
  })

  it('durably reserves a stage lease before creating its private file', async () => {
    let vaultAtHook: PaidMediaVault | null = null
    const observedStates: string[] = []
    const item = fixture(undefined, {
      beforeStageFileCreate: async () => {
        const inspection = await vaultAtHook!.inspectStageRecovery()
        observedStates.push(...inspection.leases.map((lease) => lease.state))
        expect(readdirSync(item.stageRoot)).toEqual([])
      }
    })
    vaultAtHook = item.vault
    await item.vault.provisionAuthorityVault()
    let mutationContext = false
    item.vault.setMutationGuard(() => {
      if (!mutationContext) throw new Error('outside Root transaction')
    })

    await expect(
      item.vault.reserveAndOpenStageLeases({
        operationId: OPERATION_ID,
        result: paidMediaStageResult()
      })
    ).rejects.toThrow(/outside Root transaction/i)

    mutationContext = true
    const opened = await item.vault.reserveAndOpenStageLeases({
      operationId: OPERATION_ID,
      result: paidMediaStageResult()
    })
    expect(opened.ok).toBe(true)
    expect(observedStates).toEqual(['reserved'])
    await expect(item.vault.inspectStageRecovery()).resolves.toMatchObject({
      leases: [{ operationId: OPERATION_ID, state: 'opened', disposition: 'reclaim' }]
    })
    if (!opened.ok) throw new Error('expected opened stage lease')
    await expect(cleanupStageLease(item.vault, opened.capabilities[0]!.leaseId)).resolves.toEqual({
      status: 'cleaned'
    })
  })

  it('keeps the stage capability write-only, unforgeable, revocable, and on one handle', async () => {
    const witnesses: object[] = []
    const item = fixture(undefined, {
      onStageHandleUse: ({ witness }) => witnesses.push(witness)
    })
    await item.vault.provisionAuthorityVault()
    item.vault.setMutationGuard(() => undefined)
    const opened = await item.vault.reserveAndOpenStageLeases({
      operationId: OPERATION_ID,
      result: paidMediaStageResult()
    })
    if (!opened.ok) throw new Error('expected opened stage lease')
    const capability = opened.capabilities[0]!
    expect(Object.keys(capability).sort()).toEqual([
      'descriptor',
      'leaseId',
      'operationId',
      'ordinal',
      'sync',
      'turnId',
      'write'
    ])
    expect('path' in capability).toBe(false)
    expect('handle' in capability).toBe(false)
    expect('close' in capability).toBe(false)
    expect('rm' in capability).toBe(false)

    const forged = { ...capability }
    await expect(forged.write(PNG, 0)).rejects.toThrow(/forged|revoked/i)
    await expect(
      item.vault.sealStageWriteCapability(forged as typeof capability)
    ).rejects.toThrow(/forged|revoked/i)

    const split = Math.floor(PNG.length / 2)
    await expect(capability.write(PNG.subarray(0, split), 0)).resolves.toEqual({
      bytesWritten: split
    })
    await expect(capability.write(PNG.subarray(split), 0)).rejects.toThrow(/invalid/i)
    await expect(capability.write(PNG.subarray(split), split)).resolves.toEqual({
      bytesWritten: PNG.length - split
    })
    await capability.sync()
    const sealed = await item.vault.sealStageWriteCapability(capability)
    await expect(capability.write(Buffer.from([0]), PNG.length)).rejects.toThrow(
      /forged|revoked/i
    )
    await expect(collectSmallStageFixture(item.vault, sealed)).resolves.toEqual(PNG)
    expect(witnesses.length).toBeGreaterThanOrEqual(6)
    expect(witnesses.every((witness) => witness === witnesses[0])).toBe(true)
    await expect(cleanupStageLease(item.vault, capability.leaseId)).resolves.toEqual({
      status: 'cleaned'
    })
  })

  it('exposes a one-shot sealed-stage source with bounded chunks from the pinned handle', async () => {
    const bytes = pngWithAncillaryPadding(PNG, 256 * 1024)
    const chunks: number[] = []
    const item = fixture(undefined, {
      onStageStreamChunk: ({ phase, byteLength }) => {
        if (phase === 'probe') chunks.push(byteLength)
      }
    })
    await item.vault.provisionAuthorityVault()
    item.vault.setMutationGuard(() => undefined)
    const opened = await item.vault.reserveAndOpenStageLeases({
      operationId: OPERATION_ID,
      result: paidMediaStageResult(bytes)
    })
    if (!opened.ok) throw new Error('expected opened stage lease')
    for (let offset = 0; offset < bytes.length; offset += 64 * 1024) {
      await opened.capabilities[0]!.write(bytes.subarray(offset, offset + 64 * 1024), offset)
    }
    const sealed = await item.vault.sealStageWriteCapability(opened.capabilities[0]!)
    const source = item.vault.createSealedStageReadSource(sealed)
    expect(source).toMatchObject({ byteLength: bytes.length, sha256: sha256(bytes) })

    const digest = createHash('sha256')
    let byteLength = 0
    for await (const raw of source.createReadStream()) {
      const chunk = Buffer.isBuffer(raw) ? raw : Buffer.from(raw)
      digest.update(chunk)
      byteLength += chunk.length
    }

    expect(byteLength).toBe(bytes.length)
    expect(digest.digest('hex')).toBe(sha256(bytes))
    expect(chunks.length).toBeGreaterThan(1)
    expect(Math.max(...chunks)).toBeLessThanOrEqual(64 * 1024)
    expect(() => source.createReadStream()).toThrow(/already consumed/i)
    await cleanupStageLease(item.vault, sealed.leaseId)
  })

  it('allows only one active stage stream and releases it after cancellation for retry', async () => {
    const bytes = pngWithAncillaryPadding(PNG, 256 * 1024)
    const item = fixture()
    await item.vault.provisionAuthorityVault()
    item.vault.setMutationGuard(() => undefined)
    const opened = await item.vault.reserveAndOpenStageLeases({
      operationId: OPERATION_ID,
      result: paidMediaStageResult(bytes)
    })
    if (!opened.ok) throw new Error('expected opened stage lease')
    for (let offset = 0; offset < bytes.length; offset += 64 * 1024) {
      await opened.capabilities[0]!.write(bytes.subarray(offset, offset + 64 * 1024), offset)
    }
    const sealed = await item.vault.sealStageWriteCapability(opened.capabilities[0]!)
    const first = item.vault.createSealedStageReadSource(sealed)
    const competing = item.vault.createSealedStageReadSource(sealed)
    const firstStream = first.createReadStream()
    const iterator = firstStream[Symbol.asyncIterator]()
    await iterator.next()
    expect(() => competing.createReadStream()).toThrow(/already active/i)
    const closed = new Promise<void>((resolve) => firstStream.once('close', resolve))
    firstStream.destroy()
    await closed

    const retry = item.vault.createSealedStageReadSource(sealed)
    let byteLength = 0
    for await (const raw of retry.createReadStream()) {
      byteLength += Buffer.isBuffer(raw) ? raw.length : Buffer.byteLength(raw)
    }
    expect(byteLength).toBe(bytes.length)
    await cleanupStageLease(item.vault, sealed.leaseId)
  })

  it('rejects a stage path replacement detected after pinned streaming', async () => {
    const bytes = pngWithAncillaryPadding(PNG, 128 * 1024)
    const replacement = Buffer.from('replacement-must-survive')
    let stageFile = ''
    let replaced = false
    const item = fixture(undefined, {
      onStageStreamChunk: ({ phase }) => {
        if (phase !== 'probe' || replaced) return
        replaced = true
        renameSync(stageFile, `${stageFile}.displaced`)
        writeFileSync(stageFile, replacement)
      }
    })
    await item.vault.provisionAuthorityVault()
    item.vault.setMutationGuard(() => undefined)
    const opened = await item.vault.reserveAndOpenStageLeases({
      operationId: OPERATION_ID,
      result: paidMediaStageResult(bytes)
    })
    if (!opened.ok) throw new Error('expected opened stage lease')
    for (let offset = 0; offset < bytes.length; offset += 64 * 1024) {
      await opened.capabilities[0]!.write(bytes.subarray(offset, offset + 64 * 1024), offset)
    }
    const sealed = await item.vault.sealStageWriteCapability(opened.capabilities[0]!)
    stageFile = join(item.stageRoot, readdirSync(item.stageRoot)[0]!, 'asset.bin')
    const source = item.vault.createSealedStageReadSource(sealed)

    await expect(
      (async () => {
        for await (const _chunk of source.createReadStream()) void _chunk
      })()
    ).rejects.toThrow(/identity|changed/i)
    expect(readFileSync(stageFile)).toEqual(replacement)
    await expect(cleanupStageLease(item.vault, sealed.leaseId)).resolves.toEqual({
      status: 'held'
    })
  })

  it('aborts and exactly cleans all four leases after a mid-batch open failure', async () => {
    const item = fixture(undefined, {
      beforeStageOpenedCommit: ({ ordinal }) => {
        if (ordinal === 2) throw new Error('injected third-asset open failure')
      }
    })
    await item.vault.provisionAuthorityVault()
    item.vault.setMutationGuard(() => undefined)
    await expect(
      item.vault.reserveAndOpenStageLeases({
        operationId: OPERATION_ID,
        result: paidMediaStageResult(PNG, 4)
      })
    ).resolves.toEqual({ ok: false, cleanupPending: false, held: false })
    await expect(item.vault.inspectStageRecovery()).resolves.toMatchObject({ leases: [] })
    expect(readdirSync(item.stageRoot)).toEqual([])
  })

  it('holds a replaced stage path and never deletes the replacement', async () => {
    const replacement = Buffer.from('do-not-delete', 'ascii')
    const item = fixture(undefined, {
      beforeStageOpenedCommit: () => {
        const [directoryName] = readdirSync(item.stageRoot)
        const directory = join(item.stageRoot, directoryName!)
        renameSync(join(directory, 'asset.bin'), join(directory, 'original.bin'))
        writeFileSync(join(directory, 'asset.bin'), replacement)
      }
    })
    await item.vault.provisionAuthorityVault()
    item.vault.setMutationGuard(() => undefined)
    await expect(
      item.vault.reserveAndOpenStageLeases({
        operationId: OPERATION_ID,
        result: paidMediaStageResult()
      })
    ).resolves.toEqual({ ok: false, cleanupPending: false, held: true })
    const inspection = await item.vault.inspectStageRecovery()
    expect(inspection.leases).toMatchObject([
      { state: 'held', disposition: 'manual_only', reasonCode: 'stage_tree_outside_closed_set' }
    ])
    const [directoryName] = readdirSync(item.stageRoot)
    expect(readFileSync(join(item.stageRoot, directoryName!, 'asset.bin'))).toEqual(replacement)
  })

  it('keeps unlink failure pending and cleans it on an exact retry', async () => {
    let unlinkAttempts = 0
    const item = fixture(undefined, {
      stageCleanupIO: {
        unlinkStageFile: (path) => {
          unlinkAttempts += 1
          if (unlinkAttempts === 1) throw new Error('injected unlink failure')
          unlinkSync(path)
        },
        removeEmptyStageDirectory: (path) => rmdirSync(path)
      }
    })
    await item.vault.provisionAuthorityVault()
    item.vault.setMutationGuard(() => undefined)
    const opened = await item.vault.reserveAndOpenStageLeases({
      operationId: OPERATION_ID,
      result: paidMediaStageResult()
    })
    if (!opened.ok) throw new Error('expected opened stage lease')
    const leaseId = opened.capabilities[0]!.leaseId
    await expect(cleanupStageLease(item.vault, leaseId)).resolves.toEqual({ status: 'pending' })
    await expect(item.vault.inspectStageRecovery()).resolves.toMatchObject({
      leases: [{ leaseId, state: 'aborted_cleanup_pending', disposition: 'cleanup' }]
    })
    await expect(cleanupStageLease(item.vault, leaseId)).resolves.toEqual({ status: 'cleaned' })
    expect(unlinkAttempts).toBe(2)
    expect(readdirSync(item.stageRoot)).toEqual([])
  })

  it('replays mixed v1 and v2 authority once and reuses incremental stage indexes', async () => {
    let failUnlink = true
    const item = fixture(undefined, {
      stageCleanupIO: {
        unlinkStageFile: (path) => {
          if (failUnlink) {
            failUnlink = false
            throw new Error('leave one durable cleanup intent for restart')
          }
          unlinkSync(path)
        },
        removeEmptyStageDirectory: rmdirSync
      }
    })
    const initial = await item.vault.provisionAuthorityVault()
    item.vault.setMutationGuard(() => undefined)
    await item.vault.recordClaim({
      operationId: OPERATION_ID,
      path: '/v1/images/generations',
      encodedBody: JSON.stringify({ model: 'image-model', prompt: 'mixed replay' })
    })
    const opened = await item.vault.reserveAndOpenStageLeases({
      operationId: OPERATION_ID,
      result: paidMediaStageResult()
    })
    if (!opened.ok) throw new Error('expected opened stage lease')
    const leaseId = opened.capabilities[0]!.leaseId
    await expect(cleanupStageLease(item.vault, leaseId)).resolves.toEqual({ status: 'pending' })

    const replay = vi.fn()
    const restarted = new PaidMediaVault(item.root, {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_001,
      fetchRemote: async (url) => ({ bytes: PNG, contentType: 'image/png', finalUrl: url }),
      ensureMediaProbeReady: async () => undefined,
      validateMediaAsset: trustedProbe,
      stageRoot: () => item.stageRoot,
      onAuthorityJournalReplay: replay
    })
    restarted.setMutationGuard(() => undefined)
    await expect(restarted.inspectAuthorityEvidence()).resolves.toMatchObject({
      entryCount: initial.entryCount + 1
    })
    for (let iteration = 0; iteration < 20; iteration += 1) {
      await expect(restarted.inspectStageRecovery()).resolves.toMatchObject({
        leases: [{ leaseId, state: 'aborted_cleanup_pending', disposition: 'cleanup' }]
      })
    }
    expect(replay).toHaveBeenCalledTimes(1)
    await expect(cleanupStageLease(restarted, leaseId)).resolves.toEqual({ status: 'cleaned' })
  })

  it('restarts one crash-cleaned exact binding at generation plus one and rejects ABA variants', async () => {
    let failBeforeLeaf = true
    const item = fixture(undefined, {
      beforeStageFileCreate: async () => {
        if (failBeforeLeaf) {
          failBeforeLeaf = false
          throw new Error('injected crash before reserved leaf creation')
        }
      }
    })
    await item.vault.provisionAuthorityVault()
    item.vault.setMutationGuard(() => undefined)
    const request = { operationId: OPERATION_ID, result: paidMediaStageResult() }
    await expect(item.vault.reserveAndOpenStageLeases(request)).resolves.toEqual({
      ok: false,
      cleanupPending: false,
      held: false
    })
    expect(readdirSync(item.stageRoot)).toEqual([])

    await expect(
      item.vault.reserveAndOpenStageLeases({
        operationId: OPERATION_ID,
        result: { ...request.result, turnId: '2'.repeat(64) }
      })
    ).rejects.toThrow(/conflicts/i)

    const opened = await item.vault.reserveAndOpenStageLeases(request)
    if (!opened.ok) throw new Error('expected opened stage lease')
    const generations = readAuthorityJournal(item.root)
      .filter((event) => event.action === 'stage_transition')
      .map((event) => ({
        state: (event.stage as Record<string, unknown>).state,
        generation: (event.stage as Record<string, unknown>).generation
      }))
    expect(generations).toEqual([
      { state: 'reserved', generation: 0 },
      { state: 'aborted_cleanup_pending', generation: 0 },
      { state: 'aborted_cleaned', generation: 0 },
      { state: 'reserved', generation: 1 },
      { state: 'opened', generation: 1 }
    ])
    await cleanupStageLease(item.vault, opened.capabilities[0]!.leaseId)
    expect(readdirSync(item.stageRoot)).toEqual([])
  })

  it('reclaims an exact opened lease at generation plus one and fences every old capability', async () => {
    const validation = await trustedProbe({
      mediaType: 'image/png',
      byteLength: PNG.length,
      sha256: createHash('sha256').update(PNG).digest('hex')
    })
    const item = fixture()
    await item.vault.provisionAuthorityVault()
    item.vault.setMutationGuard(() => undefined)
    await recordImageClaim(item.vault, JSON.stringify({ model: 'image-model', prompt: 'reclaim' }))
    const baseResult = paidMediaStageResult()
    const result: PaidMediaAssetResult = {
      ...baseResult,
      assets: [
        {
          ...baseResult.assets[0]!,
          validationReceiptSha256: validation.receiptSha256
        }
      ]
    }
    const opened = await item.vault.reserveAndOpenStageLeases({
      operationId: OPERATION_ID,
      result
    })
    if (!opened.ok) throw new Error('expected opened stage lease')
    const oldCapability = opened.capabilities[0]!
    await oldCapability.write(PNG, 0)
    await oldCapability.sync()
    const oldSealed = await item.vault.sealStageWriteCapability(oldCapability)

    const reclaimed = await item.vault.reclaimStageLease({
      operationId: OPERATION_ID,
      result,
      leaseId: oldCapability.leaseId
    })
    if (!reclaimed.ok) throw new Error('expected reclaimed stage lease')
    await expect(oldCapability.write(PNG, 0)).rejects.toThrow(/revoked|authority/i)
    await expect(oldCapability.sync()).rejects.toThrow(/revoked|authority/i)
    await expect(item.vault.sealStageWriteCapability(oldCapability)).rejects.toThrow(
      /revoked|authority/i
    )
    await expect(collectSmallStageFixture(item.vault, oldSealed)).rejects.toThrow(/revoked|authority/i)
    await expect(
      item.vault.archiveSealedStageImageResult({
        operationId: OPERATION_ID,
        status: 200,
        result,
        assets: [{ ordinal: 0, sealed: oldSealed, validation }]
      })
    ).rejects.toThrow(/binding|revoked|authority/i)

    await reclaimed.capability.write(PNG, 0)
    await reclaimed.capability.sync()
    const sealed = await item.vault.sealStageWriteCapability(reclaimed.capability)
    await expect(collectSmallStageFixture(item.vault, sealed)).resolves.toEqual(PNG)
    const openedGenerations = readAuthorityJournal(item.root)
      .filter(
        (event) =>
          event.action === 'stage_transition' &&
          (event.stage as Record<string, unknown>).state === 'opened'
      )
      .map((event) => (event.stage as Record<string, unknown>).generation)
    expect(openedGenerations).toEqual([0, 1])
    await cleanupStageLease(item.vault, reclaimed.capability.leaseId)
  })

  it('holds a replaced reclaim leaf without deleting or opening the replacement', async () => {
    const replacement = Buffer.from('replacement-must-survive', 'ascii')
    const item = fixture()
    await item.vault.provisionAuthorityVault()
    item.vault.setMutationGuard(() => undefined)
    const result = paidMediaStageResult()
    const opened = await item.vault.reserveAndOpenStageLeases({
      operationId: OPERATION_ID,
      result
    })
    if (!opened.ok) throw new Error('expected opened stage lease')
    const capability = opened.capabilities[0]!
    const [directoryName] = readdirSync(item.stageRoot)
    const directory = join(item.stageRoot, directoryName!)
    renameSync(join(directory, 'asset.bin'), join(item.stageRoot, 'replaced-original.bin'))
    writeFileSync(join(directory, 'asset.bin'), replacement)

    await expect(
      item.vault.reclaimStageLease({
        operationId: OPERATION_ID,
        result,
        leaseId: capability.leaseId
      })
    ).resolves.toEqual({ ok: false, status: 'held' })
    expect(readFileSync(join(directory, 'asset.bin'))).toEqual(replacement)
    await expect(capability.write(PNG, 0)).rejects.toThrow(/revoked|authority/i)
    await expect(item.vault.inspectStageRecovery()).resolves.toMatchObject({
      leases: [{ state: 'held', disposition: 'manual_only' }]
    })
  })

  it('revokes and removes a reclaimed handle when the opened hook throws after commit', async () => {
    let openedHooks = 0
    const item = fixture(undefined, {
      onStageHandleUse: ({ phase }) => {
        if (phase === 'opened' && ++openedHooks === 2) {
          throw new Error('injected reclaim opened-hook failure')
        }
      }
    })
    await item.vault.provisionAuthorityVault()
    item.vault.setMutationGuard(() => undefined)
    const result = paidMediaStageResult()
    const opened = await item.vault.reserveAndOpenStageLeases({
      operationId: OPERATION_ID,
      result
    })
    if (!opened.ok) throw new Error('expected opened stage lease')
    const oldCapability = opened.capabilities[0]!
    await oldCapability.write(PNG.subarray(0, 8), 0)

    await expect(
      item.vault.reclaimStageLease({
        operationId: OPERATION_ID,
        result,
        leaseId: oldCapability.leaseId
      })
    ).resolves.toEqual({ ok: false, status: 'held' })
    expect(
      (item.vault as unknown as { stageOpenHandles: Map<string, unknown> }).stageOpenHandles.size
    ).toBe(0)
    await expect(oldCapability.write(PNG, 0)).rejects.toThrow(/revoked|authority/i)
    const [directoryName] = readdirSync(item.stageRoot)
    expect(statSync(join(item.stageRoot, directoryName!, 'asset.bin')).size).toBe(0)
    await expect(item.vault.inspectStageRecovery()).resolves.toMatchObject({
      leases: [
        {
          state: 'held',
          disposition: 'manual_only',
          reasonCode: 'stage_reclaim_failed'
        }
      ]
    })
  })

  it('fails closed on a recomputed v2 lease-sequence jump', async () => {
    const item = fixture()
    await item.vault.provisionAuthorityVault()
    item.vault.setMutationGuard(() => undefined)
    const opened = await item.vault.reserveAndOpenStageLeases({
      operationId: OPERATION_ID,
      result: paidMediaStageResult()
    })
    if (!opened.ok) throw new Error('expected opened stage lease')
    await cleanupStageLease(item.vault, opened.capabilities[0]!.leaseId)
    const events = readAuthorityJournal(item.root)
    const finalEvent = events.at(-1)!
    const stage = finalEvent.stage as Record<string, unknown>
    stage.leaseSequence = Number(stage.leaseSequence) + 2
    recomputeStageEventDigests(finalEvent)
    rewriteAuthorityJournal(item.root, events)

    const restarted = new PaidMediaVault(item.root, {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_001,
      fetchRemote: async (url) => ({ bytes: PNG, finalUrl: url }),
      ensureMediaProbeReady: async () => undefined,
      validateMediaAsset: trustedProbe,
      stageRoot: () => item.stageRoot
    })
    restarted.setMutationGuard(() => undefined)
    await expect(restarted.inspectStageRecovery()).rejects.toThrow(/transition.*illegal/i)
  })

  it('fails closed on an unknown v2 action and on a v2 uncommitted tail', async () => {
    const makeCleaned = async () => {
      const item = fixture()
      await item.vault.provisionAuthorityVault()
      item.vault.setMutationGuard(() => undefined)
      const opened = await item.vault.reserveAndOpenStageLeases({
        operationId: OPERATION_ID,
        result: paidMediaStageResult()
      })
      if (!opened.ok) throw new Error('expected opened stage lease')
      await cleanupStageLease(item.vault, opened.capabilities[0]!.leaseId)
      return item
    }
    const unknown = await makeCleaned()
    const unknownEvents = readAuthorityJournal(unknown.root)
    unknownEvents.at(-1)!.action = 'stage_unknown'
    rewriteAuthorityJournal(unknown.root, unknownEvents)
    const unknownRestart = new PaidMediaVault(unknown.root, {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_001,
      fetchRemote: async (url) => ({ bytes: PNG, finalUrl: url }),
      ensureMediaProbeReady: async () => undefined,
      validateMediaAsset: trustedProbe,
      stageRoot: () => unknown.stageRoot
    })
    unknownRestart.setMutationGuard(() => undefined)
    await expect(unknownRestart.inspectStageRecovery()).rejects.toThrow(/stage authority event.*invalid/i)

    const tail = await makeCleaned()
    const journalPath = `${tail.root}.authority.journal`
    writeFileSync(journalPath, Buffer.concat([readFileSync(journalPath), Buffer.from('tail')]))
    const tailRestart = new PaidMediaVault(tail.root, {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_001,
      fetchRemote: async (url) => ({ bytes: PNG, finalUrl: url }),
      ensureMediaProbeReady: async () => undefined,
      validateMediaAsset: trustedProbe,
      stageRoot: () => tail.stageRoot
    })
    tailRestart.setMutationGuard(() => undefined)
    await expect(tailRestart.inspectStageRecovery()).rejects.toThrow(/uncommitted tail/i)
  })

  it('archives a sealed stage image from its pinned handle without provider or probe work', async () => {
    const validation = await trustedProbe({
      mediaType: 'image/png',
      byteLength: PNG.length,
      sha256: createHash('sha256').update(PNG).digest('hex')
    })
    const baseResult = paidMediaStageResult()
    const result: PaidMediaAssetResult = {
      ...baseResult,
      assets: [
        {
          ...baseResult.assets[0]!,
          validationReceiptSha256: validation.receiptSha256
        }
      ]
    }
    const probe = vi.fn(async () => {
      throw new Error('archive must not invoke a probe')
    })
    const item = fixture(undefined, { validateMediaAsset: probe })
    await item.vault.provisionAuthorityVault()
    item.vault.setMutationGuard(() => undefined)
    await recordImageClaim(
      item.vault,
      JSON.stringify({ model: 'image-model', prompt: 'sealed stage archive' })
    )
    const opened = await item.vault.reserveAndOpenStageLeases({
      operationId: OPERATION_ID,
      result
    })
    if (!opened.ok) throw new Error('expected opened stage lease')
    const writeCapability = opened.capabilities[0]!
    await writeCapability.write(PNG, 0)
    await writeCapability.sync()
    const sealed = await item.vault.sealStageWriteCapability(writeCapability)

    const archived = await item.vault.archiveSealedStageImageResult({
      operationId: OPERATION_ID,
      status: 200,
      result,
      assets: [{ ordinal: 0, sealed, validation }]
    })
    const canonicalResult = Buffer.from(
      JSON.stringify({
        assets: [
          {
            byteLength: PNG.length,
            mediaType: 'image/png',
            sha256: createHash('sha256').update(PNG).digest('hex'),
            token: baseResult.assets[0]!.token,
            validationReceiptSha256: validation.receiptSha256
          }
        ],
        created: PAID_MEDIA_RESULT_CREATED,
        kind: 'image',
        schema: PAID_MEDIA_ASSET_RESULT_SCHEMA,
        turnId: result.turnId
      }),
      'ascii'
    )
    const expectedTokenSource = createHash('sha256')
      .update('nachuan-paid-media-asset-token-v1\0', 'ascii')
      .update(baseResult.assets[0]!.token, 'ascii')
      .digest('hex')
    expect(archived).toMatchObject({
      receipt: {
        operationId: OPERATION_ID,
        path: '/v1/images/generations',
        status: 200,
        kind: 'image',
        responseSha256: createHash('sha256').update(canonicalResult).digest('hex'),
        responseByteLength: canonicalResult.length,
        assets: [
          {
            sha256: createHash('sha256').update(PNG).digest('hex'),
            mediaType: 'image/png',
            byteLength: PNG.length,
            source: 'remote',
            sourceSha256: expectedTokenSource,
            validation
          }
        ]
      },
      result: {
        created: PAID_MEDIA_RESULT_CREATED,
        data: [{ url: expect.stringMatching(/^nachuan-paid-media:\/\/sha256\/[0-9a-f]{64}$/) }]
      },
      cleanupComplete: true
    })
    expect(probe).not.toHaveBeenCalled()
    expect(item.fetchRemote).not.toHaveBeenCalled()
    expect(JSON.stringify(archived)).not.toContain(baseResult.assets[0]!.token)
    expect(
      JSON.stringify(readProtectedDocument(join(item.root, 'archives', `${OPERATION_ID}.json`)))
    ).not.toContain(baseResult.assets[0]!.token)
    await expect(item.vault.inspectStageRecovery()).resolves.toMatchObject({ leases: [] })
    await expect(item.vault.recover(OPERATION_ID)).resolves.toMatchObject({
      cleanupComplete: true,
      result: archived.result
    })
  })

  it('rejects a mismatched trusted validation receipt without leaking its stage token', async () => {
    const validation = await trustedProbe({
      mediaType: 'image/png',
      byteLength: PNG.length,
      sha256: createHash('sha256').update(PNG).digest('hex')
    })
    const baseResult = paidMediaStageResult()
    const result: PaidMediaAssetResult = {
      ...baseResult,
      assets: [
        {
          ...baseResult.assets[0]!,
          validationReceiptSha256: validation.receiptSha256
        }
      ]
    }
    const item = fixture()
    await item.vault.provisionAuthorityVault()
    item.vault.setMutationGuard(() => undefined)
    await recordImageClaim(
      item.vault,
      JSON.stringify({ model: 'image-model', prompt: 'validation mismatch' })
    )
    const opened = await item.vault.reserveAndOpenStageLeases({
      operationId: OPERATION_ID,
      result
    })
    if (!opened.ok) throw new Error('expected opened stage lease')
    await opened.capabilities[0]!.write(PNG, 0)
    const sealed = await item.vault.sealStageWriteCapability(opened.capabilities[0]!)
    let failure: unknown
    try {
      await item.vault.archiveSealedStageImageResult({
        operationId: OPERATION_ID,
        status: 200,
        result,
        assets: [
          {
            ordinal: 0,
            sealed,
            validation: { ...validation, receiptSha256: 'f'.repeat(64) }
          }
        ]
      })
    } catch (error) {
      failure = error
    }
    expect(failure).toBeInstanceOf(PaidMediaVaultError)
    expect(String((failure as Error).message)).not.toContain(result.assets[0]!.token)
    expect(existsSync(join(item.root, 'archives', `${OPERATION_ID}.json`))).toBe(false)
    expect(readdirSync(join(item.root, 'assets'))).toEqual([])
    expect(readdirSync(item.stageRoot).join('/')).not.toContain(result.assets[0]!.token)
    await expect(collectSmallStageFixture(item.vault, sealed)).resolves.toEqual(PNG)
    await cleanupStageLease(item.vault, sealed.leaseId)
  })

  it('keeps a committed archive through cleanup failure and finishes it on duplicate archive', async () => {
    const validation = await trustedProbe({
      mediaType: 'image/png',
      byteLength: PNG.length,
      sha256: createHash('sha256').update(PNG).digest('hex')
    })
    const baseResult = paidMediaStageResult()
    const result: PaidMediaAssetResult = {
      ...baseResult,
      assets: [
        {
          ...baseResult.assets[0]!,
          validationReceiptSha256: validation.receiptSha256
        }
      ]
    }
    let unlinkAttempts = 0
    const item = fixture(undefined, {
      stageCleanupIO: {
        unlinkStageFile: (path) => {
          unlinkAttempts += 1
          if (unlinkAttempts === 1) throw new Error('injected post-archive unlink failure')
          unlinkSync(path)
        },
        removeEmptyStageDirectory: rmdirSync
      }
    })
    await item.vault.provisionAuthorityVault()
    item.vault.setMutationGuard(() => undefined)
    await recordImageClaim(item.vault, JSON.stringify({ model: 'image-model', prompt: 'retry' }))
    const opened = await item.vault.reserveAndOpenStageLeases({
      operationId: OPERATION_ID,
      result
    })
    if (!opened.ok) throw new Error('expected opened stage lease')
    await opened.capabilities[0]!.write(PNG, 0)
    const sealed = await item.vault.sealStageWriteCapability(opened.capabilities[0]!)
    const input = {
      operationId: OPERATION_ID,
      status: 200 as const,
      result,
      assets: [{ ordinal: 0, sealed, validation }]
    }
    const first = await item.vault.archiveSealedStageImageResult(input)
    expect(first.cleanupComplete).toBe(false)
    await expect(item.vault.inspectStageRecovery()).resolves.toMatchObject({
      leases: [{ state: 'archived_cleanup_pending', disposition: 'cleanup' }]
    })
    await expect(item.vault.recover(OPERATION_ID)).resolves.toMatchObject({
      receipt: { receiptSha256: first.receipt.receiptSha256 },
      cleanupComplete: false
    })

    const second = await item.vault.archiveSealedStageImageResult(input)
    expect(second.receipt.receiptSha256).toBe(first.receipt.receiptSha256)
    expect(second.cleanupComplete).toBe(true)
    expect(unlinkAttempts).toBe(2)
    await expect(item.vault.inspectStageRecovery()).resolves.toMatchObject({ leases: [] })
  })

  it('holds archived cleanup and preserves the stage when the final asset no longer verifies', async () => {
    const validation = await trustedProbe({
      mediaType: 'image/png',
      byteLength: PNG.length,
      sha256: createHash('sha256').update(PNG).digest('hex')
    })
    const baseResult = paidMediaStageResult()
    const result: PaidMediaAssetResult = {
      ...baseResult,
      assets: [
        {
          ...baseResult.assets[0]!,
          validationReceiptSha256: validation.receiptSha256
        }
      ]
    }
    let failUnlink = true
    const item = fixture(undefined, {
      stageCleanupIO: {
        unlinkStageFile: (path) => {
          if (failUnlink) {
            failUnlink = false
            throw new Error('leave stage pending for final-asset verification')
          }
          unlinkSync(path)
        },
        removeEmptyStageDirectory: rmdirSync
      }
    })
    await item.vault.provisionAuthorityVault()
    item.vault.setMutationGuard(() => undefined)
    await recordImageClaim(item.vault, JSON.stringify({ model: 'image-model', prompt: 'hold' }))
    const opened = await item.vault.reserveAndOpenStageLeases({
      operationId: OPERATION_ID,
      result
    })
    if (!opened.ok) throw new Error('expected opened stage lease')
    const leaseId = opened.capabilities[0]!.leaseId
    await opened.capabilities[0]!.write(PNG, 0)
    const sealed = await item.vault.sealStageWriteCapability(opened.capabilities[0]!)
    const archived = await item.vault.archiveSealedStageImageResult({
      operationId: OPERATION_ID,
      status: 200,
      result,
      assets: [{ ordinal: 0, sealed, validation }]
    })
    expect(archived.cleanupComplete).toBe(false)
    const asset = archived.receipt.assets[0]!
    writeFileSync(join(item.root, 'assets', `${asset.sha256}.${asset.extension}`), 'corrupt')

    await expect(cleanupStageLease(item.vault, leaseId)).resolves.toEqual({ status: 'held' })
    await expect(item.vault.inspectStageRecovery()).resolves.toMatchObject({
      leases: [
        {
          leaseId,
          state: 'held',
          disposition: 'manual_only',
          reasonCode: 'archive_cleanup_evidence_invalid'
        }
      ]
    })
    const [directoryName] = readdirSync(item.stageRoot)
    expect(readFileSync(join(item.stageRoot, directoryName!, 'asset.bin'))).toEqual(PNG)
  })

  it('archives four exact stage assets and retries only the one partial cleanup', async () => {
    const validation = await trustedProbe({
      mediaType: 'image/png',
      byteLength: PNG.length,
      sha256: createHash('sha256').update(PNG).digest('hex')
    })
    const baseResult = paidMediaStageResult(PNG, 4)
    const result: PaidMediaAssetResult = {
      ...baseResult,
      assets: baseResult.assets.map((asset) => ({
        ...asset,
        validationReceiptSha256: validation.receiptSha256
      }))
    }
    let unlinkAttempts = 0
    const item = fixture(undefined, {
      stageCleanupIO: {
        unlinkStageFile: (path) => {
          unlinkAttempts += 1
          if (unlinkAttempts === 2) throw new Error('injected second-asset cleanup failure')
          unlinkSync(path)
        },
        removeEmptyStageDirectory: rmdirSync
      }
    })
    await item.vault.provisionAuthorityVault()
    item.vault.setMutationGuard(() => undefined)
    await recordImageClaim(item.vault, JSON.stringify({ model: 'image-model', prompt: 'four' }))
    const opened = await item.vault.reserveAndOpenStageLeases({
      operationId: OPERATION_ID,
      result
    })
    if (!opened.ok) throw new Error('expected four opened stage leases')
    const sealed = await Promise.all(
      opened.capabilities.map(async (capability) => {
        await capability.write(PNG, 0)
        return item.vault.sealStageWriteCapability(capability)
      })
    )
    const input = {
      operationId: OPERATION_ID,
      status: 200 as const,
      result,
      assets: sealed.map((capability, ordinal) => ({
        ordinal,
        sealed: capability,
        validation
      }))
    }
    const first = await item.vault.archiveSealedStageImageResult(input)
    expect(first.receipt.assets).toHaveLength(4)
    expect(first.cleanupComplete).toBe(false)
    expect(unlinkAttempts).toBe(4)
    await expect(item.vault.inspectStageRecovery()).resolves.toMatchObject({
      leases: [{ state: 'archived_cleanup_pending', disposition: 'cleanup' }]
    })
    const archivedText = JSON.stringify(
      readProtectedDocument(join(item.root, 'archives', `${OPERATION_ID}.json`))
    )
    for (const asset of result.assets) expect(archivedText).not.toContain(asset.token)

    const second = await item.vault.archiveSealedStageImageResult(input)
    expect(second.receipt.receiptSha256).toBe(first.receipt.receiptSha256)
    expect(second.cleanupComplete).toBe(true)
    expect(unlinkAttempts).toBe(5)
    expect(readdirSync(item.stageRoot)).toEqual([])
  })

  it('archives four 24 MiB staged assets sequentially with bounded in-flight memory', async () => {
    const bytes = pngWithAncillaryPadding(
      PNG,
      MAX_PAID_MEDIA_ARCHIVE_ASSET_BYTES - PNG.length - 12
    )
    expect(bytes.length).toBe(MAX_PAID_MEDIA_ARCHIVE_ASSET_BYTES)
    const validation = await trustedProbe({
      mediaType: 'image/png',
      byteLength: bytes.length,
      sha256: sha256(bytes)
    })
    const baseResult = paidMediaStageResult(bytes, 4)
    const result: PaidMediaAssetResult = {
      ...baseResult,
      assets: baseResult.assets.map((asset) => ({
        ...asset,
        validationReceiptSha256: validation.receiptSha256
      }))
    }
    let activeAssets = 0
    let peakActiveAssets = 0
    const totals = [0, 0, 0, 0]
    const ordinals: number[] = []
    let maxChunk = 0
    const item = fixture(undefined, {
      onStageArchiveAsset: ({ phase }) => {
        activeAssets += phase === 'start' ? 1 : -1
        peakActiveAssets = Math.max(peakActiveAssets, activeAssets)
      },
      onStageStreamChunk: ({ phase, ordinal, byteLength }) => {
        if (phase !== 'archive') return
        totals[ordinal] = totals[ordinal]! + byteLength
        ordinals.push(ordinal)
        maxChunk = Math.max(maxChunk, byteLength)
      }
    })
    await item.vault.provisionAuthorityVault()
    item.vault.setMutationGuard(() => undefined)
    await recordImageClaim(
      item.vault,
      JSON.stringify({ model: 'image-model', prompt: 'bounded four asset archive' })
    )
    const opened = await item.vault.reserveAndOpenStageLeases({
      operationId: OPERATION_ID,
      result
    })
    if (!opened.ok) throw new Error('expected four opened stage leases')
    const sealed = []
    for (const capability of opened.capabilities) {
      for (let offset = 0; offset < bytes.length; offset += 64 * 1024) {
        await capability.write(bytes.subarray(offset, offset + 64 * 1024), offset)
      }
      sealed.push(await item.vault.sealStageWriteCapability(capability))
    }

    await item.vault.archiveSealedStageImageResult({
      operationId: OPERATION_ID,
      status: 200,
      result,
      assets: sealed.map((capability, ordinal) => ({ ordinal, sealed: capability, validation }))
    })

    expect(peakActiveAssets).toBe(1)
    expect(activeAssets).toBe(0)
    expect(maxChunk).toBeLessThanOrEqual(64 * 1024)
    // One archive chunk plus one openAsset verification chunk is a conservative
    // observable upper bound; both are sequential and the active asset count is one.
    expect(peakActiveAssets * maxChunk * 2).toBeLessThan(2 * 1024 * 1024)
    expect(totals).toEqual(Array(4).fill(bytes.length))
    expect(ordinals).toEqual([...ordinals].sort((left, right) => left - right))
  }, 300_000)

  it('archives exact restart-pinned stage evidence without recreating a sealed capability', async () => {
    const validation = await trustedProbe({
      mediaType: 'image/png',
      byteLength: PNG.length,
      sha256: sha256(PNG)
    })
    const initial = paidMediaStageResult()
    const result: PaidMediaAssetResult = {
      ...initial,
      assets: [
        { ...initial.assets[0]!, validationReceiptSha256: validation.receiptSha256 }
      ]
    }
    const item = fixture()
    await item.vault.provisionAuthorityVault()
    item.vault.setMutationGuard(() => undefined)
    await recordImageClaim(
      item.vault,
      JSON.stringify({ model: 'image-model', prompt: 'restart-pinned archive' })
    )
    const opened = await item.vault.reserveAndOpenStageLeases({
      operationId: OPERATION_ID,
      result
    })
    if (!opened.ok) throw new Error('expected opened stage lease')
    const capability = opened.capabilities[0]!
    await capability.write(PNG, 0)
    await capability.sync()
    await item.vault.sealStageWriteCapability(capability)
    const inspection = await item.vault.inspectStageRecovery()
    const lease = inspection.leases[0]!

    const abandoned = item.vault as unknown as {
      stageOpenHandles: Map<string, { handle: { close(): Promise<void> } }>
    }
    for (const record of abandoned.stageOpenHandles.values()) await record.handle.close()
    let failFirstCleanup = true
    const restarted = new PaidMediaVault(item.root, {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_001,
      fetchRemote: async () => {
        throw new Error('restart-pinned archive must not fetch remote media')
      },
      ensureMediaProbeReady: async () => {
        throw new Error('restart-pinned archive must not start a probe')
      },
      validateMediaAsset: async () => {
        throw new Error('restart-pinned archive must use its persisted validation receipt')
      },
      stageRoot: () => item.stageRoot,
      stageCleanupIO: {
        unlinkStageFile: (path) => {
          if (failFirstCleanup) {
            failFirstCleanup = false
            throw new Error('injected recovered archive cleanup interruption')
          }
          unlinkSync(path)
        },
        removeEmptyStageDirectory: rmdirSync
      }
    })
    restarted.setMutationGuard(() => undefined)
    const recoveryInput = {
      operationId: OPERATION_ID,
      status: 200 as const,
      result,
      leases: [
        {
          leaseId: lease.leaseId,
          ordinal: lease.ordinal,
          generation: lease.generation,
          resultSha256: lease.resultSha256,
          leaseStateDigest: lease.leaseStateDigest
        }
      ],
      validations: [validation]
    }

    await expect(
      restarted.archiveRecoveredStageImageResult({
        operationId: OPERATION_ID,
        status: 200,
        result,
        leases: [
          {
            leaseId: lease.leaseId,
            ordinal: lease.ordinal,
            generation: lease.generation + 1,
            resultSha256: lease.resultSha256,
            leaseStateDigest: lease.leaseStateDigest
          }
        ],
        validations: [validation]
      })
    ).rejects.toThrow(/binding conflicts/i)
    await expect(
      restarted.archiveRecoveredStageImageResult({
        operationId: OPERATION_ID,
        status: 200,
        result,
        leases: [
          {
            leaseId: lease.leaseId,
            ordinal: lease.ordinal,
            generation: lease.generation,
            resultSha256: lease.resultSha256,
            leaseStateDigest: 'f'.repeat(64)
          }
        ],
        validations: [validation]
      })
    ).rejects.toThrow(/binding conflicts/i)

    const archived = await restarted.archiveRecoveredStageImageResult(recoveryInput)

    expect(archived.cleanupComplete).toBe(false)
    await expect(restarted.inspectStageRecovery()).resolves.toMatchObject({
      leases: [{ state: 'archived_cleanup_pending', disposition: 'cleanup' }]
    })
    const resumed = new PaidMediaVault(item.root, {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_002,
      fetchRemote: async () => {
        throw new Error('archive cleanup resume must not fetch remote media')
      },
      ensureMediaProbeReady: async () => {
        throw new Error('archive cleanup resume must not start a probe')
      },
      validateMediaAsset: async () => {
        throw new Error('archive cleanup resume must use persisted validation')
      },
      stageRoot: () => item.stageRoot
    })
    resumed.setMutationGuard(() => undefined)
    const completed = await resumed.archiveRecoveredStageImageResult(recoveryInput)

    expect(completed.cleanupComplete).toBe(true)
    expect(completed.receipt.receiptSha256).toBe(archived.receipt.receiptSha256)
    expect(completed.receipt.assets[0]).toMatchObject({
      sha256: sha256(PNG),
      byteLength: PNG.length,
      validation: { receiptSha256: validation.receiptSha256 }
    })
    await expect(resumed.inspectStageRecovery()).resolves.toMatchObject({ leases: [] })
  })

  it('adopts publish-before-journal output and rewrites a partial deterministic temp after restart', async () => {
    for (const residual of ['published', 'partial-temp'] as const) {
      const bytes = pngWithAncillaryPadding(PNG, 128 * 1024)
      const validation = await trustedProbe({
        mediaType: 'image/png',
        byteLength: bytes.length,
        sha256: sha256(bytes)
      })
      const baseResult = paidMediaStageResult(bytes)
      const result: PaidMediaAssetResult = {
        ...baseResult,
        assets: [
          { ...baseResult.assets[0]!, validationReceiptSha256: validation.receiptSha256 }
        ]
      }
      const item = fixture(undefined, {
        afterStageAssetLinkedBeforeAuthority: () => {
          if (residual === 'published') {
            throw new Error('simulated link-before-authority power loss')
          }
        }
      })
      await item.vault.provisionAuthorityVault()
      item.vault.setMutationGuard(() => undefined)
      await recordImageClaim(
        item.vault,
        JSON.stringify({ model: 'image-model', prompt: `restart-${residual}` })
      )
      const opened = await item.vault.reserveAndOpenStageLeases({
        operationId: OPERATION_ID,
        result
      })
      if (!opened.ok) throw new Error('expected opened stage lease')
      const leaseId = opened.capabilities[0]!.leaseId
      for (let offset = 0; offset < bytes.length; offset += 64 * 1024) {
        await opened.capabilities[0]!.write(bytes.subarray(offset, offset + 64 * 1024), offset)
      }
      const initialSealed = await item.vault.sealStageWriteCapability(
        opened.capabilities[0]!
      )
      const finalPath = join(item.root, 'assets', `${sha256(bytes)}.png`)
      const tempPath = join(item.root, 'assets', `.stage-${leaseId}.tmp`)
      if (residual === 'published') {
        await expect(
          item.vault.archiveSealedStageImageResult({
            operationId: OPERATION_ID,
            status: 200,
            result,
            assets: [{ ordinal: 0, sealed: initialSealed, validation }]
          })
        ).rejects.toThrow(/link-before-authority power loss/i)
        expect(readFileSync(finalPath)).toEqual(bytes)
        expect(existsSync(tempPath)).toBe(false)
      } else {
        writeFileSync(tempPath, bytes.subarray(0, 17), { flag: 'wx' })
      }
      // Simulate process death: the OS closes the old process's pinned handle
      // without writing another authority event.
      const abandoned = item.vault as unknown as {
        stageOpenHandles: Map<string, { handle: { close(): Promise<void> } }>
      }
      for (const record of abandoned.stageOpenHandles.values()) await record.handle.close()

      const restarted = new PaidMediaVault(item.root, {
        safeStorage: fakeStorage,
        harden: () => undefined,
        now: () => 1_800_000_000_001,
        fetchRemote: async (url) => ({ bytes: PNG, finalUrl: url }),
        ensureMediaProbeReady: async () => undefined,
        validateMediaAsset: trustedProbe,
        stageRoot: () => item.stageRoot
      })
      restarted.setMutationGuard(() => undefined)
      const reclaimed = await restarted.reclaimStageLease({
        operationId: OPERATION_ID,
        result,
        leaseId
      })
      if (!reclaimed.ok) throw new Error(`expected reclaimed stage after ${residual}`)
      for (let offset = 0; offset < bytes.length; offset += 64 * 1024) {
        await reclaimed.capability.write(bytes.subarray(offset, offset + 64 * 1024), offset)
      }
      const sealed = await restarted.sealStageWriteCapability(reclaimed.capability)
      const archived = await restarted.archiveSealedStageImageResult({
        operationId: OPERATION_ID,
        status: 200,
        result,
        assets: [{ ordinal: 0, sealed, validation }]
      })

      expect(archived.cleanupComplete).toBe(true)
      expect(archived.receipt.assets[0]).toMatchObject({
        sha256: sha256(bytes),
        byteLength: bytes.length
      })
      expect(existsSync(tempPath)).toBe(false)
      await expect(restarted.verifyArchive(OPERATION_ID)).resolves.toMatchObject({
        receipt: { operationId: OPERATION_ID }
      })
    }
  })

  it('never replaces a conflicting pre-existing content-addressed target', async () => {
    const validation = await trustedProbe({
      mediaType: 'image/png',
      byteLength: PNG.length,
      sha256: sha256(PNG)
    })
    const baseResult = paidMediaStageResult()
    const result: PaidMediaAssetResult = {
      ...baseResult,
      assets: [
        { ...baseResult.assets[0]!, validationReceiptSha256: validation.receiptSha256 }
      ]
    }
    const item = fixture()
    await item.vault.provisionAuthorityVault()
    item.vault.setMutationGuard(() => undefined)
    await recordImageClaim(
      item.vault,
      JSON.stringify({ model: 'image-model', prompt: 'target conflict' })
    )
    const opened = await item.vault.reserveAndOpenStageLeases({
      operationId: OPERATION_ID,
      result
    })
    if (!opened.ok) throw new Error('expected opened stage lease')
    await opened.capabilities[0]!.write(PNG, 0)
    const sealed = await item.vault.sealStageWriteCapability(opened.capabilities[0]!)
    const target = join(item.root, 'assets', `${sha256(PNG)}.png`)
    const conflict = Buffer.from('conflicting-target')
    writeFileSync(target, conflict, { flag: 'wx' })

    await expect(
      item.vault.archiveSealedStageImageResult({
        operationId: OPERATION_ID,
        status: 200,
        result,
        assets: [{ ordinal: 0, sealed, validation }]
      })
    ).rejects.toThrow(/conflict|length|evidence/i)
    expect(readFileSync(target)).toEqual(conflict)
    expect(existsSync(join(item.root, 'archives', `${OPERATION_ID}.json`))).toBe(false)
    await cleanupStageLease(item.vault, sealed.leaseId)
  })

  it('resumes a committed archive cleanup after process restart without any capability', async () => {
    const validation = await trustedProbe({
      mediaType: 'image/png',
      byteLength: PNG.length,
      sha256: createHash('sha256').update(PNG).digest('hex')
    })
    const baseResult = paidMediaStageResult()
    const result: PaidMediaAssetResult = {
      ...baseResult,
      assets: [
        {
          ...baseResult.assets[0]!,
          validationReceiptSha256: validation.receiptSha256
        }
      ]
    }
    let failUnlink = true
    const item = fixture(undefined, {
      stageCleanupIO: {
        unlinkStageFile: (path) => {
          if (failUnlink) {
            failUnlink = false
            throw new Error('injected crash after archive commit')
          }
          unlinkSync(path)
        },
        removeEmptyStageDirectory: rmdirSync
      }
    })
    await item.vault.provisionAuthorityVault()
    item.vault.setMutationGuard(() => undefined)
    await recordImageClaim(item.vault, JSON.stringify({ model: 'image-model', prompt: 'resume' }))
    const opened = await item.vault.reserveAndOpenStageLeases({
      operationId: OPERATION_ID,
      result
    })
    if (!opened.ok) throw new Error('expected opened stage lease')
    await opened.capabilities[0]!.write(PNG, 0)
    const sealed = await item.vault.sealStageWriteCapability(opened.capabilities[0]!)
    await expect(
      item.vault.archiveSealedStageImageResult({
        operationId: OPERATION_ID,
        status: 200,
        result,
        assets: [{ ordinal: 0, sealed, validation }]
      })
    ).resolves.toMatchObject({ cleanupComplete: false })

    const restarted = new PaidMediaVault(item.root, {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_001,
      fetchRemote: async (url) => ({ bytes: PNG, contentType: 'image/png', finalUrl: url }),
      ensureMediaProbeReady: async () => undefined,
      validateMediaAsset: trustedProbe,
      stageRoot: () => item.stageRoot
    })
    restarted.setMutationGuard(() => undefined)
    await expect(restarted.resumeArchivedStageCleanup(OPERATION_ID)).resolves.toMatchObject({
      receipt: { operationId: OPERATION_ID },
      cleanupComplete: true
    })
    expect(readdirSync(item.stageRoot)).toEqual([])
    await expect(restarted.inspectStageRecovery()).resolves.toMatchObject({ leases: [] })
  })

  it('recovers an archive committed before cleanup intent after restart and fences the old process', async () => {
    const validation = await trustedProbe({
      mediaType: 'image/png',
      byteLength: PNG.length,
      sha256: createHash('sha256').update(PNG).digest('hex')
    })
    const baseResult = paidMediaStageResult()
    const result: PaidMediaAssetResult = {
      ...baseResult,
      assets: [
        {
          ...baseResult.assets[0]!,
          validationReceiptSha256: validation.receiptSha256
        }
      ]
    }
    let crashBeforeIntent = true
    const item = fixture(undefined, {
      beforeArchivedStageCleanupIntent: () => {
        if (crashBeforeIntent) {
          crashBeforeIntent = false
          throw new Error('injected crash before archived cleanup intent')
        }
      }
    })
    await item.vault.provisionAuthorityVault()
    item.vault.setMutationGuard(() => undefined)
    await recordImageClaim(
      item.vault,
      JSON.stringify({ model: 'image-model', prompt: 'crash before intent' })
    )
    const opened = await item.vault.reserveAndOpenStageLeases({
      operationId: OPERATION_ID,
      result
    })
    if (!opened.ok) throw new Error('expected opened stage lease')
    const leaseId = opened.capabilities[0]!.leaseId
    await opened.capabilities[0]!.write(PNG, 0)
    const sealed = await item.vault.sealStageWriteCapability(opened.capabilities[0]!)
    await expect(
      item.vault.archiveSealedStageImageResult({
        operationId: OPERATION_ID,
        status: 200,
        result,
        assets: [{ ordinal: 0, sealed, validation }]
      })
    ).rejects.toThrow(/crash before archived cleanup intent/i)
    expect(existsSync(join(item.root, 'archives', `${OPERATION_ID}.json`))).toBe(true)
    await expect(item.vault.inspectStageRecovery()).resolves.toMatchObject({
      leases: [{ state: 'opened', disposition: 'reclaim' }]
    })

    const restarted = new PaidMediaVault(item.root, {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_001,
      fetchRemote: async (url) => ({ bytes: PNG, contentType: 'image/png', finalUrl: url }),
      ensureMediaProbeReady: async () => undefined,
      validateMediaAsset: trustedProbe,
      stageRoot: () => item.stageRoot
    })
    restarted.setMutationGuard(() => undefined)
    await expect(cleanupStageLease(restarted, leaseId)).resolves.toEqual({ status: 'cleaned' })
    await expect(restarted.verifyArchive(OPERATION_ID)).resolves.toMatchObject({
      receipt: { operationId: OPERATION_ID },
      cleanupComplete: true
    })
    await expect(collectSmallStageFixture(item.vault, sealed)).rejects.toThrow(/revoked|authority/i)
    expect(readdirSync(item.stageRoot)).toEqual([])
  })

  it('commits one exact legacy-import receipt inside the Root transaction gate', async () => {
    const item = fixture()
    const initial = await item.vault.provisionAuthorityVault()
    let mutationContext = false
    item.vault.setMutationGuard(() => {
      if (!mutationContext) throw new Error('outside Root transaction')
    })
    const decisionSha256 = 'd'.repeat(64)

    await expect(
      item.vault.recordLegacyImportReceipt({ decisionSha256, operationId: OPERATION_ID })
    ).rejects.toThrow(/outside Root transaction/i)
    await expect(
      item.vault.hasLegacyImportReceipt({ decisionSha256, operationId: OPERATION_ID })
    ).resolves.toBe(false)

    mutationContext = true
    await expect(
      item.vault.recordLegacyImportReceipt({ decisionSha256, operationId: OPERATION_ID })
    ).resolves.toBeUndefined()
    mutationContext = false
    await expect(
      item.vault.hasLegacyImportReceipt({ decisionSha256, operationId: OPERATION_ID })
    ).resolves.toBe(true)

    const evidence = await item.vault.inspectAuthorityEvidence()
    expect(evidence.entryCount).toBe(initial.entryCount + 1)
  })

  it('commits the closed vault tree and blocks every durable write outside the Root transaction', async () => {
    const item = fixture()
    const initial = await item.vault.provisionAuthorityVault()
    let mutationContext = false
    item.vault.setMutationGuard(() => {
      if (!mutationContext) throw new Error('outside Root transaction')
    })

    await expect(item.vault.inspectAuthorityEvidence()).resolves.toEqual(initial)
    await expect(
      item.vault.recordClaim({
        operationId: OPERATION_ID,
        path: '/v1/images/generations',
        encodedBody: JSON.stringify({ model: 'image-model', prompt: 'root gate' })
      })
    ).rejects.toThrow(/outside Root transaction/i)

    mutationContext = true
    await item.vault.recordClaim({
      operationId: OPERATION_ID,
      path: '/v1/images/generations',
      encodedBody: JSON.stringify({ model: 'image-model', prompt: 'root gate' })
    })
    mutationContext = false
    const changed = await item.vault.inspectAuthorityEvidence()
    expect(changed.entryCount).toBe(initial.entryCount + 1)
    expect(changed.vaultStateDigest).not.toBe(initial.vaultStateDigest)

    unlinkSync(join(item.root, 'claims', `${OPERATION_ID}.json`))
    const deleted = await item.vault.inspectAuthorityEvidence()
    expect(deleted.vaultStateDigest).toBe(changed.vaultStateDigest)
    await expect(item.vault.readExactRequest(OPERATION_ID)).rejects.toThrow(/missing|unavailable/i)
  })

  it('returns an exact read-only capture inventory for a closed quiescent vault', async () => {
    const item = fixture()
    await item.vault.provisionAuthorityVault()
    item.vault.setMutationGuard(() => undefined)
    await item.vault.recordClaim({
      operationId: OPERATION_ID,
      path: '/v1/images/generations',
      encodedBody: JSON.stringify({ model: 'image-model', prompt: 'capture inventory' })
    })
    const claimPath = join(item.root, 'claims', `${OPERATION_ID}.json`)
    const claimBytes = readFileSync(claimPath)
    const authority = await item.vault.inspectAuthorityEvidence()
    const hardenCallsBeforeInspection = item.harden.mock.calls.length

    await expect(item.vault.inspectCaptureInventory()).resolves.toEqual({
      vaultStateDigest: authority.vaultStateDigest,
      entryCount: 1,
      entries: [
        {
          path: `claims/${OPERATION_ID}.json`,
          byteLength: claimBytes.length,
          sha256: sha256(claimBytes)
        }
      ],
      quiescence: {
        activeStageLeases: 0,
        stageOpenHandles: 0,
        activeStageStream: null,
        cleanupRetries: 0,
        cleanupFlights: 0,
        terminalArchiveFlights: 0,
        cleanupPendingEntries: 0,
        stageRootEntries: 0
      }
    })
    expect(item.harden).toHaveBeenCalledTimes(hardenCallsBeforeInspection)
  })

  it('rejects an unindexed physical vault file without removing it', async () => {
    const item = fixture()
    await item.vault.provisionAuthorityVault()
    item.vault.setMutationGuard(() => undefined)
    const orphanPath = join(item.root, 'claims', 'orphan.json')
    const orphanBytes = Buffer.from('unindexed capture orphan', 'utf8')
    writeFileSync(orphanPath, orphanBytes)

    await expect(item.vault.inspectCaptureInventory()).rejects.toThrow(
      /capture inventory.*authority index/i
    )
    expect(readFileSync(orphanPath)).toEqual(orphanBytes)
  })

  it('rejects a registered vault file whose physical bytes changed', async () => {
    const item = fixture()
    await item.vault.provisionAuthorityVault()
    item.vault.setMutationGuard(() => undefined)
    await item.vault.recordClaim({
      operationId: OPERATION_ID,
      path: '/v1/images/generations',
      encodedBody: JSON.stringify({ model: 'image-model', prompt: 'capture tamper' })
    })
    const claimPath = join(item.root, 'claims', `${OPERATION_ID}.json`)
    const replacement = Buffer.alloc(readFileSync(claimPath).length, 0x7b)
    writeFileSync(claimPath, replacement)

    await expect(item.vault.inspectCaptureInventory()).rejects.toThrow(
      /capture inventory.*authority index/i
    )
    expect(readFileSync(claimPath)).toEqual(replacement)
  })

  it('rejects capture while a durable stage lease and its write handle are active', async () => {
    const item = fixture()
    await item.vault.provisionAuthorityVault()
    item.vault.setMutationGuard(() => undefined)
    const opened = await item.vault.reserveAndOpenStageLeases({
      operationId: OPERATION_ID,
      result: paidMediaStageResult()
    })
    expect(opened.ok).toBe(true)

    await expect(item.vault.inspectCaptureInventory()).rejects.toThrow(
      /capture is not quiescent.*activeStageLeases=1.*stageOpenHandles=1/i
    )

    const [lease] = (await item.vault.inspectStageRecovery()).leases
    await expect(
      item.vault.cleanupStageLease({
        operationId: OPERATION_ID,
        leaseId: lease!.leaseId,
        generation: lease!.generation,
        resultSha256: lease!.resultSha256
      })
    ).resolves.toEqual({ status: 'cleaned' })
  })

  it('rejects an untracked physical stage-root residual without deleting it', async () => {
    const item = fixture()
    await item.vault.provisionAuthorityVault()
    item.vault.setMutationGuard(() => undefined)
    const residualPath = join(item.stageRoot, 'untracked-stage-residual.bin')
    const residualBytes = Buffer.from('untracked stage residual', 'utf8')
    writeFileSync(residualPath, residualBytes)

    await expect(item.vault.inspectCaptureInventory()).rejects.toThrow(
      /capture.*stage root.*not empty/i
    )
    expect(readFileSync(residualPath)).toEqual(residualBytes)
  })

  it('rejects a cleanup-pending residual without consuming recovery evidence', async () => {
    const item = fixture()
    await item.vault.provisionAuthorityVault()
    item.vault.setMutationGuard(() => undefined)
    const markerPath = join(item.root, 'cleanup-pending', 'untracked-cleanup.json')
    const markerBytes = Buffer.from('cleanup evidence must survive capture inspection', 'utf8')
    writeFileSync(markerPath, markerBytes)

    await expect(item.vault.inspectCaptureInventory()).rejects.toThrow(
      /capture cleanup-pending directory is not empty/i
    )
    expect(readFileSync(markerPath)).toEqual(markerBytes)
  })

  it('fails capture explicitly when the dedicated stage root cannot be enumerated', async () => {
    const item = fixture()
    await item.vault.provisionAuthorityVault()
    const restarted = new PaidMediaVault(item.root, {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_001,
      fetchRemote: async (url) => ({
        bytes: PNG,
        contentType: 'image/png',
        finalUrl: url
      }),
      ensureMediaProbeReady: async () => undefined,
      validateMediaAsset: trustedProbe
    })
    restarted.setMutationGuard(() => undefined)

    await expect(restarted.inspectCaptureInventory()).rejects.toThrow(
      /dedicated stage root is required/i
    )
  })

  it('does not invoke the ACL hardener while inspecting capture state', async () => {
    const item = fixture()
    await item.vault.provisionAuthorityVault()
    const harden = vi.fn()
    const restarted = new PaidMediaVault(item.root, {
      safeStorage: fakeStorage,
      harden,
      now: () => 1_800_000_000_001,
      fetchRemote: async (url) => ({
        bytes: PNG,
        contentType: 'image/png',
        finalUrl: url
      }),
      ensureMediaProbeReady: async () => undefined,
      validateMediaAsset: trustedProbe,
      stageRoot: () => item.stageRoot
    })
    restarted.setMutationGuard(() => undefined)

    await expect(restarted.inspectCaptureInventory()).resolves.toMatchObject({
      entryCount: 0,
      entries: []
    })
    expect(harden).not.toHaveBeenCalled()
  })

  it('uses an incremental authority manifest and rejects file/manifest split-brain evidence', async () => {
    const item = fixture()
    await item.vault.provisionAuthorityVault()
    let mutationContext = true
    item.vault.setMutationGuard(() => {
      if (!mutationContext) throw new Error('outside Root transaction')
    })
    const firstBody = JSON.stringify({ model: 'image-model', prompt: 'first manifest leaf' })
    await item.vault.recordClaim({
      operationId: OPERATION_ID,
      path: '/v1/images/generations',
      encodedBody: firstBody
    })
    const manifestPath = `${item.root}.authority.json`
    const firstManifest = readFileSync(manifestPath)
    const firstEvidence = await item.vault.inspectAuthorityEvidence()

    const secondOperationId = 'desktop-op-22222222-2222-4222-8222-222222222222'
    await item.vault.recordClaim({
      operationId: secondOperationId,
      path: '/v1/images/generations',
      encodedBody: JSON.stringify({ model: 'image-model', prompt: 'second manifest leaf' })
    })
    const secondEvidence = await item.vault.inspectAuthorityEvidence()
    expect(secondEvidence.vaultStateDigest).not.toBe(firstEvidence.vaultStateDigest)

    // Simulate a file commit followed by loss/rollback of the manifest head.
    writeFileSync(manifestPath, firstManifest)
    await expect(item.vault.inspectAuthorityEvidence()).rejects.toThrow(/uncommitted tail/i)
    await expect(item.vault.readExactRequest(secondOperationId)).rejects.toThrow(/uncommitted tail/i)

    // Authority evidence no longer hashes every historical payload. Actual
    // bytes are pinned and verified at the point of use.
    const firstPath = join(item.root, 'claims', `${OPERATION_ID}.json`)
    writeFileSync(firstPath, Buffer.from('tampered-without-manifest-update', 'utf8'))
    await expect(item.vault.inspectAuthorityEvidence()).rejects.toThrow(/uncommitted tail/i)
    await expect(item.vault.readExactRequest(OPERATION_ID)).rejects.toThrow()
    mutationContext = false
  })

  it('poisons an appended authority delta when its head cannot commit and rejects it after restart', async () => {
    let failHead = true
    const item = fixture(undefined, {
      beforeAuthorityHeadCommit: () => {
        if (failHead) throw new Error('simulated head replacement failure')
      }
    })
    await item.vault.provisionAuthorityVault()
    item.vault.setMutationGuard(() => undefined)

    await expect(
      item.vault.recordClaim({
        operationId: OPERATION_ID,
        path: '/v1/images/generations',
        encodedBody: JSON.stringify({ model: 'image-model', prompt: 'split commit' })
      })
    ).rejects.toThrow(/could not be committed/i)
    await expect(item.vault.inspectAuthorityEvidence()).rejects.toThrow(/poisoned/i)

    failHead = false
    const restarted = new PaidMediaVault(item.root, {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_001,
      fetchRemote: async (url) => ({
        bytes: PNG,
        contentType: 'image/png',
        finalUrl: url
      }),
      ensureMediaProbeReady: async () => undefined,
      validateMediaAsset: trustedProbe
    })
    restarted.setMutationGuard(() => undefined)
    await expect(restarted.inspectAuthorityEvidence()).rejects.toThrow(/uncommitted tail/i)
  })

  it('recovers one exact committed-prefix next event only through the explicit Root mutation API', async () => {
    let failHead = true
    let mutationContext = true
    const validateMediaAsset = vi.fn(trustedProbe)
    const item = fixture(undefined, {
      beforeAuthorityHeadCommit: () => {
        if (failHead) throw new Error('injected recoverable authority head failure')
      },
      validateMediaAsset
    })
    await item.vault.provisionAuthorityVault()
    item.vault.setMutationGuard(() => {
      if (!mutationContext) throw new Error('outside Root transaction')
    })
    const encodedBody = JSON.stringify({
      model: 'image-model',
      prompt: 'recover exactly one authority event'
    })
    await expect(
      item.vault.recordClaim({
        operationId: OPERATION_ID,
        path: '/v1/images/generations',
        encodedBody
      })
    ).rejects.toThrow(/could not be committed/i)
    mutationContext = false
    await expect(item.vault.inspectAuthorityEvidence()).rejects.toThrow(/poisoned/i)
    await expect(item.vault.readExactRequest(OPERATION_ID)).rejects.toThrow(/poisoned/i)
    const blockedOperationId = 'desktop-op-33333333-3333-4333-8333-333333333333'
    mutationContext = true
    await expect(
      item.vault.recordClaim({
        operationId: blockedOperationId,
        path: '/v1/images/generations',
        encodedBody: JSON.stringify({ model: 'image-model', prompt: 'must not be written' })
      })
    ).rejects.toThrow(/poisoned/i)
    expect(existsSync(join(item.root, 'claims', `${blockedOperationId}.json`))).toBe(false)
    mutationContext = false

    const committed = await item.vault.inspectCommittedAuthorityPrefixForRecovery()
    expect(committed).toMatchObject({
      recoveryOnly: true,
      outboundReady: false,
      uncommittedTailEventCount: 1
    })
    expect(committed.uncommittedTailByteLength).toBeGreaterThan(4)
    const headPath = `${item.root}.authority.json`
    const journalPath = `${item.root}.authority.journal`
    const headBefore = readFileSync(headPath)
    const journalBefore = readFileSync(journalPath)
    const claimPath = join(item.root, 'claims', `${OPERATION_ID}.json`)
    const claimBytes = readFileSync(claimPath)
    const recoveryInput = {
      operationId: OPERATION_ID,
      committedVaultStateDigest: committed.committedVaultStateDigest,
      boundary: {
        kind: 'file_event' as const,
        action: 'create' as const,
        relativePath: `claims/${OPERATION_ID}.json`,
        byteLength: claimBytes.length,
        sha256: sha256(claimBytes)
      }
    }
    await expect(
      item.vault.recoverSingleAuthorityJournalTail(recoveryInput)
    ).rejects.toThrow(/outside Root transaction/i)
    expect(readFileSync(headPath)).toEqual(headBefore)

    mutationContext = true
    failHead = false
    const recovered = await item.vault.recoverSingleAuthorityJournalTail(recoveryInput)
    mutationContext = false
    expect(recovered).toMatchObject({
      operationId: OPERATION_ID,
      action: 'create',
      recovered: true,
      previousVaultStateDigest: committed.committedVaultStateDigest
    })
    expect(readFileSync(headPath)).not.toEqual(headBefore)
    expect(readFileSync(journalPath)).toEqual(journalBefore)
    await expect(item.vault.readExactRequest(OPERATION_ID)).resolves.toMatchObject({
      operationId: OPERATION_ID,
      encodedBody
    })

    const restarted = new PaidMediaVault(item.root, {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_001,
      fetchRemote: item.fetchRemote,
      ensureMediaProbeReady: async () => undefined,
      validateMediaAsset,
      stageRoot: () => item.stageRoot
    })
    restarted.setMutationGuard(() => undefined)
    await expect(restarted.readExactRequest(OPERATION_ID)).resolves.toMatchObject({
      operationId: OPERATION_ID,
      encodedBody
    })
    expect(item.fetchRemote).not.toHaveBeenCalled()
    expect(validateMediaAsset).not.toHaveBeenCalled()
  })

  it('recovers the same exact authority tail after restart while ordinary restart load stays closed', async () => {
    const item = fixture(undefined, {
      beforeAuthorityHeadCommit: () => {
        throw new Error('injected pre-restart authority head failure')
      }
    })
    await item.vault.provisionAuthorityVault()
    item.vault.setMutationGuard(() => undefined)
    const encodedBody = JSON.stringify({
      model: 'image-model',
      prompt: 'recover authority tail after restart'
    })
    await expect(
      item.vault.recordClaim({
        operationId: OPERATION_ID,
        path: '/v1/images/generations',
        encodedBody
      })
    ).rejects.toThrow(/could not be committed/i)

    const validateMediaAsset = vi.fn(trustedProbe)
    const restarted = new PaidMediaVault(item.root, {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_001,
      fetchRemote: item.fetchRemote,
      ensureMediaProbeReady: async () => undefined,
      validateMediaAsset,
      stageRoot: () => item.stageRoot
    })
    restarted.setMutationGuard(() => undefined)
    await expect(restarted.inspectAuthorityEvidence()).rejects.toThrow(/uncommitted tail/i)
    const committed = await restarted.inspectCommittedAuthorityPrefixForRecovery()
    const claimBytes = readFileSync(join(item.root, 'claims', `${OPERATION_ID}.json`))
    await expect(
      restarted.recoverSingleAuthorityJournalTail({
        operationId: OPERATION_ID,
        committedVaultStateDigest: committed.committedVaultStateDigest,
        boundary: {
          kind: 'file_event',
          action: 'create',
          relativePath: `claims/${OPERATION_ID}.json`,
          byteLength: claimBytes.length,
          sha256: sha256(claimBytes)
        }
      })
    ).resolves.toMatchObject({ recovered: true, operationId: OPERATION_ID })
    await expect(restarted.readExactRequest(OPERATION_ID)).resolves.toMatchObject({
      operationId: OPERATION_ID,
      encodedBody
    })
    expect(item.fetchRemote).not.toHaveBeenCalled()
    expect(validateMediaAsset).not.toHaveBeenCalled()
  })

  it('rejects every non-singleton, mismatched, or unverifiable authority tail without moving head', async () => {
    const setup = async (): Promise<{
      item: ReturnType<typeof fixture>
      input: PaidMediaVaultAuthorityTailRecoveryInput
      headPath: string
      journalPath: string
      claimPath: string
      committedJournalByteLength: number
      allowHeadCommit: () => void
      setHeadCommitAction: (action: () => void) => void
    }> => {
      let failHead = true
      let headCommitAction: (() => void) | null = null
      const item = fixture(undefined, {
        beforeAuthorityHeadCommit: () => {
          if (failHead) throw new Error('injected authority recovery head failure')
          headCommitAction?.()
        }
      })
      await item.vault.provisionAuthorityVault()
      item.vault.setMutationGuard(() => undefined)
      await expect(
        item.vault.recordClaim({
          operationId: OPERATION_ID,
          path: '/v1/images/generations',
          encodedBody: JSON.stringify({ model: 'image-model', prompt: 'tail reject matrix' })
        })
      ).rejects.toThrow(/could not be committed/i)
      const committed = await item.vault.inspectCommittedAuthorityPrefixForRecovery()
      const claimPath = join(item.root, 'claims', `${OPERATION_ID}.json`)
      const claimBytes = readFileSync(claimPath)
      return {
        item,
        input: {
          operationId: OPERATION_ID,
          committedVaultStateDigest: committed.committedVaultStateDigest,
          boundary: {
            kind: 'file_event',
            action: 'create',
            relativePath: `claims/${OPERATION_ID}.json`,
            byteLength: claimBytes.length,
            sha256: sha256(claimBytes)
          }
        },
        headPath: `${item.root}.authority.json`,
        journalPath: `${item.root}.authority.journal`,
        claimPath,
        committedJournalByteLength: committed.committedJournalByteLength,
        allowHeadCommit: () => {
          failHead = false
        },
        setHeadCommitAction: (action) => {
          failHead = false
          headCommitAction = action
        }
      }
    }

    for (const mutation of ['partial', 'random', 'two'] as const) {
      const scenario = await setup()
      const headBefore = readFileSync(scenario.headPath)
      const journal = readFileSync(scenario.journalPath)
      const prefix = journal.subarray(0, scenario.committedJournalByteLength)
      const tail = journal.subarray(scenario.committedJournalByteLength)
      if (mutation === 'partial') {
        writeFileSync(
          scenario.journalPath,
          Buffer.concat([prefix, tail.subarray(0, tail.length - 1)])
        )
      } else if (mutation === 'random') {
        writeFileSync(
          scenario.journalPath,
          Buffer.concat([prefix, Buffer.from('not-a-framed-authority-event', 'utf8')])
        )
      } else {
        writeFileSync(scenario.journalPath, Buffer.concat([prefix, tail, tail]))
      }
      const evidence = await scenario.item.vault.inspectCommittedAuthorityPrefixForRecovery()
      expect(evidence).toMatchObject({
        recoveryOnly: true,
        outboundReady: false,
        uncommittedTailEventCount: null
      })
      await expect(
        scenario.item.vault.recoverSingleAuthorityJournalTail(scenario.input)
      ).rejects.toThrow(/tail|exactly one/i)
      expect(readFileSync(scenario.headPath)).toEqual(headBefore)
    }

    for (const mutation of ['chain', 'sequence', 'digest', 'semantic'] as const) {
      const scenario = await setup()
      const headBefore = readFileSync(scenario.headPath)
      const events = readAuthorityJournal(scenario.item.root)
      const event = events.at(-1)!
      let input = scenario.input
      if (mutation === 'chain') {
        event.previousStateDigest = 'f'.repeat(64)
        recomputeAuthorityEventDigest(event)
      } else if (mutation === 'sequence') {
        event.sequence = Number(event.sequence) + 1
        recomputeAuthorityEventDigest(event)
      } else if (mutation === 'digest') {
        event.stateDigest = 'f'.repeat(64)
      } else {
        event.action = 'delete'
        recomputeAuthorityEventDigest(event)
        const boundary = scenario.input.boundary
        if (boundary.kind !== 'file_event') throw new Error('expected file boundary')
        input = { ...scenario.input, boundary: { ...boundary, action: 'delete' } }
      }
      rewriteAuthorityJournal(scenario.item.root, events)
      writeFileSync(scenario.headPath, headBefore)
      await expect(
        scenario.item.vault.recoverSingleAuthorityJournalTail(input)
      ).rejects.toThrow(
        mutation === 'digest'
          ? /digest/i
          : mutation === 'semantic'
            ? /delete conflicts/i
            : /chain/i
      )
      expect(readFileSync(scenario.headPath)).toEqual(headBefore)
    }

    {
      const scenario = await setup()
      const headBefore = readFileSync(scenario.headPath)
      await expect(
        scenario.item.vault.recoverSingleAuthorityJournalTail({
          ...scenario.input,
          committedVaultStateDigest: 'f'.repeat(64)
        })
      ).rejects.toThrow(/committed prefix/i)
      expect(readFileSync(scenario.headPath)).toEqual(headBefore)
    }

    {
      const scenario = await setup()
      const headBefore = readFileSync(scenario.headPath)
      const boundary = scenario.input.boundary
      if (boundary.kind !== 'file_event') throw new Error('expected file boundary')
      await expect(
        scenario.item.vault.recoverSingleAuthorityJournalTail({
          ...scenario.input,
          boundary: { ...boundary, sha256: 'f'.repeat(64) }
        })
      ).rejects.toThrow(/boundary/i)
      expect(readFileSync(scenario.headPath)).toEqual(headBefore)
    }

    {
      const scenario = await setup()
      const headBefore = readFileSync(scenario.headPath)
      const events = readAuthorityJournal(scenario.item.root)
      const event = events.at(-1)!
      const entry = event.entry as Record<string, unknown>
      const relativePath = `claims/${OPERATION_ID}.arbitrary.json`
      entry.path = relativePath
      recomputeAuthorityEventDigest(event)
      rewriteAuthorityJournal(scenario.item.root, events)
      writeFileSync(scenario.headPath, headBefore)
      const boundary = scenario.input.boundary
      if (boundary.kind !== 'file_event') throw new Error('expected file boundary')
      await expect(
        scenario.item.vault.recoverSingleAuthorityJournalTail({
          ...scenario.input,
          boundary: { ...boundary, relativePath }
        })
      ).rejects.toThrow(/not bound to its operation/i)
      expect(readFileSync(scenario.headPath)).toEqual(headBefore)
    }

    {
      const scenario = await setup()
      const headBefore = readFileSync(scenario.headPath)
      writeFileSync(scenario.claimPath, Buffer.from('wrong committed file postcondition', 'utf8'))
      await expect(
        scenario.item.vault.recoverSingleAuthorityJournalTail(scenario.input)
      ).rejects.toThrow(/postcondition/i)
      expect(readFileSync(scenario.headPath)).toEqual(headBefore)
    }

    {
      const scenario = await setup()
      const headBefore = readFileSync(scenario.headPath)
      scenario.setHeadCommitAction(() => {
        writeFileSync(
          scenario.claimPath,
          Buffer.from('postcondition changed at head boundary', 'utf8')
        )
      })
      await expect(
        scenario.item.vault.recoverSingleAuthorityJournalTail(scenario.input)
      ).rejects.toThrow(/postcondition/i)
      expect(readFileSync(scenario.headPath)).toEqual(headBefore)
    }

    {
      const scenario = await setup()
      const headBefore = readFileSync(scenario.headPath)
      await expect(
        scenario.item.vault.recoverSingleAuthorityJournalTail(scenario.input)
      ).rejects.toThrow(/injected authority recovery head failure/i)
      expect(readFileSync(scenario.headPath)).toEqual(headBefore)
      scenario.allowHeadCommit()
      await expect(
        scenario.item.vault.recoverSingleAuthorityJournalTail(scenario.input)
      ).resolves.toMatchObject({ recovered: true })
      const committedHead = readFileSync(scenario.headPath)
      await expect(
        scenario.item.vault.recoverSingleAuthorityJournalTail(scenario.input)
      ).rejects.toThrow(/already committed/i)
      expect(readFileSync(scenario.headPath)).toEqual(committedHead)
    }
  })

  it('recovers an exact reserved stage tail and rejects a contradictory stage leaf', async () => {
    let failHead = true
    const item = fixture(undefined, {
      beforeAuthorityHeadCommit: () => {
        if (failHead) throw new Error('injected reserved stage head failure')
      }
    })
    await item.vault.provisionAuthorityVault()
    item.vault.setMutationGuard(() => undefined)
    await expect(
      item.vault.reserveAndOpenStageLeases({
        operationId: OPERATION_ID,
        result: paidMediaStageResult()
      })
    ).rejects.toThrow(/reserved stage head failure/i)
    const committed = await item.vault.inspectCommittedAuthorityPrefixForRecovery()
    const event = readAuthorityJournal(item.root).at(-1)!
    const stage = event.stage as Record<string, unknown>
    const input: PaidMediaVaultAuthorityTailRecoveryInput = {
      operationId: OPERATION_ID,
      committedVaultStateDigest: committed.committedVaultStateDigest,
      boundary: {
        kind: 'stage_transition',
        leaseId: String(stage.leaseId),
        leaseSequence: Number(stage.leaseSequence),
        state: String(stage.state) as 'reserved',
        leaseStateDigest: String(stage.leaseStateDigest)
      }
    }
    const headPath = `${item.root}.authority.json`
    const headBefore = readFileSync(headPath)
    const unexpectedDirectory = join(item.stageRoot, String(stage.directoryName))
    mkdirSync(unexpectedDirectory)
    failHead = false
    await expect(item.vault.recoverSingleAuthorityJournalTail(input)).rejects.toThrow(
      /postcondition/i
    )
    expect(readFileSync(headPath)).toEqual(headBefore)
    rmdirSync(unexpectedDirectory)

    await expect(item.vault.recoverSingleAuthorityJournalTail(input)).resolves.toMatchObject({
      operationId: OPERATION_ID,
      action: 'stage_transition',
      recovered: true
    })
    await expect(item.vault.inspectStageRecovery()).resolves.toMatchObject({
      leases: [{ operationId: OPERATION_ID, state: 'reserved', disposition: 'cleanup' }],
      requiresRootMutation: true,
      ageBasedDecision: false
    })
  })

  it('preserves the exact request bytes and archives inline image bytes by content digest', async () => {
    const { root, harden, vault } = fixture()
    const encodedBody = '{"model":"image-model", "prompt":"exact spacing survives"}'
    await recordImageClaim(vault, encodedBody)

    await expect(vault.readExactRequest(OPERATION_ID)).resolves.toMatchObject({
      path: '/v1/images/generations',
      encodedBody,
      requestSha256: createHash('sha256').update(encodedBody, 'utf8').digest('hex')
    })

    const responseJson = JSON.stringify({
      created: 1,
      data: [{ b64_json: PNG.toString('base64') }]
    })
    const archived = await vault.archiveResult({
      operationId: OPERATION_ID,
      path: '/v1/images/generations',
      status: 200,
      responseJson
    })

    expect(archived.receipt).toMatchObject({
      operationId: OPERATION_ID,
      path: '/v1/images/generations',
      kind: 'image',
      status: 200,
      responseSha256: createHash('sha256').update(responseJson, 'utf8').digest('hex'),
      assets: [
        {
          sha256: createHash('sha256').update(PNG).digest('hex'),
          mediaType: 'image/png',
          byteLength: PNG.byteLength,
          reference: expect.stringMatching(/^nachuan-paid-media:\/\/sha256\/[0-9a-f]{64}$/)
        }
      ]
    })
    expect(archived.receipt.receiptSha256).toMatch(/^[0-9a-f]{64}$/)
    expect(harden).toHaveBeenCalled()

    const recovered = await vault.recover(OPERATION_ID)
    expect(recovered.recoveryJson).not.toContain(PNG.toString('base64'))
    expect(recovered.result).toMatchObject({
      created: 1,
      data: [{ url: archived.receipt.assets[0].reference }]
    })
    expect(recovered.receipt).toEqual(archived.receipt)
    await expect(vault.readAsset(archived.receipt.assets[0].reference)).resolves.toMatchObject({
      bytes: PNG,
      mediaType: 'image/png'
    })
    expect(existsSync(join(root, 'assets'))).toBe(true)
  })

  it('downloads HTTPS image URLs before issuing a durable receipt and rejects unsafe redirects', async () => {
    const { fetchRemote, vault } = fixture()
    const encodedBody = JSON.stringify({ model: 'image-model', prompt: 'remote image' })
    await recordImageClaim(vault, encodedBody)
    const responseJson = JSON.stringify({ data: [{ url: 'https://cdn.example/result.png' }] })

    const archived = await vault.archiveResult({
      operationId: OPERATION_ID,
      path: '/v1/images/generations',
      status: 201,
      responseJson
    })
    expect(fetchRemote).toHaveBeenCalledWith(
      'https://cdn.example/result.png',
      MAX_PAID_MEDIA_ARCHIVE_ASSET_BYTES
    )
    expect(archived.receipt.assets[0]).toMatchObject({ source: 'remote', mediaType: 'image/png' })
    expect(archived.result).toMatchObject({
      data: [{ url: archived.receipt.assets[0].reference }]
    })

    const blocked = fixture(async () => ({
      bytes: PNG,
      contentType: 'image/png',
      finalUrl: 'https://127.0.0.1/admin'
    }))
    await recordImageClaim(blocked.vault, encodedBody)
    await expect(
      blocked.vault.archiveResult({
        operationId: OPERATION_ID,
        path: '/v1/images/generations',
        status: 200,
        responseJson
      })
    ).rejects.toThrow(/public|forbidden|redirect/i)
  })

  it('attempts only controlled staging cleanup when durable marker encryption fails', async () => {
    const root = mkdtempSync(join(tmpdir(), 'nachuan-paid-vault-'))
    const stagingRoot = mkdtempSync(join(tmpdir(), 'nachuan-paid-media-fetch-'))
    roots.push(root, stagingRoot)
    const stagingFile = join(stagingRoot, 'asset.bin')
    writeFileSync(stagingFile, PNG)
    const unlinkStagedFile = vi.fn(unlinkSync)
    const removeEmptyStagingDirectory = vi.fn(rmdirSync)
    const vault = new PaidMediaVault(root, {
      safeStorage: {
        ...fakeStorage,
        encryptString: (value) => {
          if (value.includes('nachuan.paid-media-vault.cleanup-pending.v1')) {
            throw new Error('synthetic cleanup marker encryption failure')
          }
          return fakeStorage.encryptString(value)
        }
      },
      harden: () => undefined,
      now: () => 1_800_000_000_000,
      fetchRemote: async (url) => ({
        filePath: stagingFile,
        byteLength: PNG.byteLength,
        contentType: 'image/png',
        finalUrl: url
      }),
      ensureMediaProbeReady: async () => undefined,
      validateMediaAsset: trustedProbe,
      cleanupIO: {
        unlinkStagedFile,
        removeEmptyStagingDirectory,
        unlinkMarker: unlinkSync
      }
    })
    const encodedBody = JSON.stringify({ model: 'image-model', prompt: 'marker failure' })
    await recordImageClaim(vault, encodedBody)

    await expect(
      vault.archiveResult({
        operationId: OPERATION_ID,
        path: '/v1/images/generations',
        status: 200,
        responseJson: JSON.stringify({ data: [{ url: 'https://cdn.example/result.png' }] })
      })
    ).rejects.toThrow(/marker encryption failure/i)
    expect(unlinkStagedFile).toHaveBeenCalledWith(stagingFile)
    expect(removeEmptyStagingDirectory).toHaveBeenCalledWith(stagingRoot)
    expect(existsSync(stagingRoot)).toBe(false)
  })

  it('rejects an uncontrolled file-backed fetch without deleting its path', async () => {
    const stagingRoot = mkdtempSync(join(tmpdir(), 'nachuan-paid-uncontrolled-'))
    roots.push(stagingRoot)
    const stagingFile = join(stagingRoot, 'asset.bin')
    writeFileSync(stagingFile, PNG)
    const item = fixture(async (url) => ({
      filePath: stagingFile,
      byteLength: PNG.byteLength,
      contentType: 'image/png',
      finalUrl: url
    }))
    const encodedBody = JSON.stringify({ model: 'image-model', prompt: 'uncontrolled path' })
    await recordImageClaim(item.vault, encodedBody)

    await expect(
      item.vault.archiveResult({
        operationId: OPERATION_ID,
        path: '/v1/images/generations',
        status: 200,
        responseJson: JSON.stringify({ data: [{ url: 'https://cdn.example/result.png' }] })
      })
    ).rejects.toThrow(/staging contract/i)
    expect(readFileSync(stagingFile)).toEqual(PNG)
  })

  it('rejects HTTP, invalid magic, declared type mismatch, and oversized remote output', async () => {
    const http = fixture()
    const encodedBody = JSON.stringify({ model: 'image-model', prompt: 'unsafe asset' })
    await recordImageClaim(http.vault, encodedBody)
    await expect(
      http.vault.archiveResult({
        operationId: OPERATION_ID,
        path: '/v1/images/generations',
        status: 200,
        responseJson: JSON.stringify({ data: [{ url: 'http://cdn.example/result.png' }] })
      })
    ).rejects.toThrow(/HTTPS/i)
    expect(http.fetchRemote).not.toHaveBeenCalled()

    for (const remote of [
      async (url: string) => ({
        bytes: Buffer.from('<html>not an image</html>'),
        contentType: 'text/html',
        finalUrl: url
      }),
      async (url: string) => ({
        bytes: PNG,
        contentType: 'image/jpeg',
        finalUrl: url
      }),
      async (url: string) => ({
        bytes: Buffer.alloc(MAX_PAID_MEDIA_ARCHIVE_ASSET_BYTES + 1, 1),
        contentType: 'application/octet-stream',
        finalUrl: url
      })
    ] satisfies PaidMediaRemoteFetcher[]) {
      const candidate = fixture(remote)
      await recordImageClaim(candidate.vault, encodedBody)
      await expect(
        candidate.vault.archiveResult({
          operationId: OPERATION_ID,
          path: '/v1/images/generations',
          status: 200,
          responseJson: JSON.stringify({ data: [{ url: 'https://cdn.example/result.png' }] })
        })
      ).rejects.toBeInstanceOf(PaidMediaVaultError)
    }
  })

  it('archives a video creation task receipt without pretending the final video exists', async () => {
    const { fetchRemote, vault } = fixture()
    const encodedBody = JSON.stringify({ model: 'video-model', prompt: 'queued task' })
    await vault.recordClaim({
      operationId: OPERATION_ID,
      path: '/v1/videos/generations',
      encodedBody
    })
    const responseJson = JSON.stringify({ task_id: 'task-provider-1', status: 'queued' })
    const archived = await vault.archiveResult({
      operationId: OPERATION_ID,
      path: '/v1/videos/generations',
      status: 202,
      responseJson
    })

    expect(archived.receipt).toMatchObject({
      kind: 'video_task',
      taskReceiptIdSha256: createHash('sha256').update('task-provider-1').digest('hex'),
      assets: []
    })
    expect(fetchRemote).not.toHaveBeenCalled()
    await expect(vault.recover(OPERATION_ID)).resolves.toMatchObject({
      result: { task_id: 'task-provider-1', status: 'queued' }
    })
  })

  it('binds a terminal video poll to its task receipt and archives the final media bytes', async () => {
    const taskAlias = `nvt1_${'a'.repeat(64)}`
    const item = fixture(async (url) => ({
      bytes: MP4,
      contentType: 'video/mp4',
      finalUrl: url
    }))
    const encodedBody = JSON.stringify({ model: 'video-model', prompt: 'terminal asset' })
    await item.vault.recordClaim({
      operationId: OPERATION_ID,
      path: '/v1/videos/generations',
      encodedBody
    })
    await item.vault.archiveResult({
      operationId: OPERATION_ID,
      path: '/v1/videos/generations',
      status: 202,
      responseJson: JSON.stringify({ task_id: taskAlias, status: 'queued' })
    })
    await expect(item.vault.verifyVideoTaskBinding(taskAlias)).resolves.toMatchObject({
      operationId: OPERATION_ID,
      taskAliasSha256: createHash('sha256').update(taskAlias).digest('hex'),
      creationReceiptSha256: expect.stringMatching(/^[0-9a-f]{64}$/)
    })

    const terminal = await item.vault.archiveTerminalMediaForTask(taskAlias, {
      task_id: taskAlias,
      status: 'completed',
      video_url: 'https://cdn.example/final.mp4'
    })

    expect(terminal).toMatchObject({
      operationId: OPERATION_ID,
      receiptSha256: expect.stringMatching(/^[0-9a-f]{64}$/),
      asset: {
        byteLength: MP4.byteLength,
        mediaType: 'video/mp4',
        reference: expect.stringMatching(/^nachuan-paid-media:\/\/sha256\//)
      },
      result: {
        task_id: taskAlias,
        status: 'completed',
        video_url: expect.stringMatching(/^nachuan-paid-media:\/\/sha256\//)
      }
    })
    expect(terminal.asset).toBeDefined()
    await expect(item.vault.readAsset(terminal.asset!.reference)).resolves.toMatchObject({
      bytes: MP4,
      mediaType: 'video/mp4'
    })

    const restarted = new PaidMediaVault(item.root, {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_001,
      fetchRemote: item.fetchRemote,
      ensureMediaProbeReady: async () => undefined,
      validateMediaAsset: trustedProbe
    })
    await expect(restarted.verifyTerminalMediaForTask(taskAlias)).resolves.toEqual(terminal)
  })

  it('singleflights concurrent terminal archive downloads for the same task alias', async () => {
    const taskAlias = `nvt1_${'b'.repeat(64)}`
    let releaseFetch!: () => void
    const fetchGate = new Promise<void>((resolve) => {
      releaseFetch = resolve
    })
    const item = fixture(async (url) => {
      await fetchGate
      return { bytes: MP4, contentType: 'video/mp4', finalUrl: url }
    })
    const encodedBody = JSON.stringify({ model: 'video-model', prompt: 'one download' })
    await item.vault.recordClaim({
      operationId: OPERATION_ID,
      path: '/v1/videos/generations',
      encodedBody
    })
    await item.vault.archiveResult({
      operationId: OPERATION_ID,
      path: '/v1/videos/generations',
      status: 202,
      responseJson: JSON.stringify({ task_id: taskAlias, status: 'queued' })
    })
    const providerResult = {
      task_id: taskAlias,
      status: 'completed',
      video_url: 'https://cdn.example/one.mp4'
    }
    const first = item.vault.archiveTerminalMediaForTask(taskAlias, providerResult)
    const second = item.vault.archiveTerminalMediaForTask(taskAlias, providerResult)
    await vi.waitFor(() => expect(item.fetchRemote).toHaveBeenCalledTimes(1))
    releaseFetch()

    const [left, right] = await Promise.all([first, second])
    expect(left).toEqual(right)
    expect(item.fetchRemote).toHaveBeenCalledTimes(1)
  })

  it('rejects a conflicting concurrent terminal result for one task alias', async () => {
    const taskAlias = `nvt1_${'c'.repeat(64)}`
    let releaseFetch!: () => void
    const fetchGate = new Promise<void>((resolve) => {
      releaseFetch = resolve
    })
    const item = fixture(async (url) => {
      await fetchGate
      return { bytes: MP4, contentType: 'video/mp4', finalUrl: url }
    })
    await item.vault.recordClaim({
      operationId: OPERATION_ID,
      path: '/v1/videos/generations',
      encodedBody: JSON.stringify({ model: 'video-model', prompt: 'conflict' })
    })
    await item.vault.archiveResult({
      operationId: OPERATION_ID,
      path: '/v1/videos/generations',
      status: 202,
      responseJson: JSON.stringify({ task_id: taskAlias, status: 'queued' })
    })
    const first = item.vault.archiveTerminalMediaForTask(taskAlias, {
      task_id: taskAlias,
      status: 'completed',
      video_url: 'https://cdn.example/first.mp4'
    })
    await vi.waitFor(() => expect(item.fetchRemote).toHaveBeenCalledTimes(1))
    await expect(
      item.vault.archiveTerminalMediaForTask(taskAlias, {
        task_id: taskAlias,
        status: 'completed',
        video_url: 'https://cdn.example/other.mp4'
      })
    ).rejects.toThrow(/conflict/i)
    releaseFetch()
    await expect(first).resolves.toMatchObject({ operationId: OPERATION_ID })
    expect(item.fetchRemote).toHaveBeenCalledTimes(1)
  })

  it('archives a provider success JSON above 24 MiB when its decoded asset remains in policy', async () => {
    const { vault } = fixture()
    const encodedBody = JSON.stringify({ model: 'image-model', prompt: 'large but bounded result' })
    await recordImageClaim(vault, encodedBody)
    const largePng = pngWithAncillaryPadding(PNG, 18 * 1024 * 1024)
    const responseJson = JSON.stringify({
      created: 2,
      data: [{ b64_json: largePng.toString('base64') }]
    })
    expect(Buffer.byteLength(responseJson, 'utf8')).toBeGreaterThan(24 * 1024 * 1024)

    const archived = await vault.archiveResult({
      operationId: OPERATION_ID,
      path: '/v1/images/generations',
      status: 200,
      responseJson
    })

    expect(archived.receipt).toMatchObject({
      responseByteLength: Buffer.byteLength(responseJson, 'utf8'),
      assets: [{ byteLength: largePng.byteLength }]
    })
    expect(Buffer.byteLength(archived.recoveryJson, 'utf8')).toBeLessThan(4096)
    await expect(vault.verifyArchive(OPERATION_ID)).resolves.toMatchObject({
      result: { data: [{ url: archived.receipt.assets[0].reference }] }
    })
  })

  it('fails archive verification after a content-addressed asset is replaced', async () => {
    const { root, vault } = fixture()
    const encodedBody = JSON.stringify({ model: 'image-model', prompt: 'tamper evidence' })
    await recordImageClaim(vault, encodedBody)
    const archived = await vault.archiveResult({
      operationId: OPERATION_ID,
      path: '/v1/images/generations',
      status: 200,
      responseJson: JSON.stringify({ data: [{ b64_json: PNG.toString('base64') }] })
    })
    const asset = archived.receipt.assets[0]
    writeFileSync(join(root, 'assets', `${asset.sha256}.${asset.extension}`), Buffer.from('tampered'))

    await expect(vault.verifyArchive(OPERATION_ID)).rejects.toThrow(/digest|magic|length/i)
  })

  it('rejects v1 evidence on ordinary read and migrates it only through an explicit plan', async () => {
    const { root, fetchRemote, vault } = fixture()
    await recordImageClaim(
      vault,
      JSON.stringify({ model: 'image-model', prompt: 'legacy v1 is not trusted v2' })
    )
    const archived = await vault.archiveResult({
      operationId: OPERATION_ID,
      path: '/v1/images/generations',
      status: 200,
      responseJson: JSON.stringify({ data: [{ b64_json: PNG.toString('base64') }] })
    })
    const legacyValidation = legacyV1Validation(archived.receipt.assets[0])
    replaceEmbeddedValidation(
      join(root, 'archives', `${OPERATION_ID}.json`),
      false,
      legacyValidation
    )
    const legacySidecarPath = writeLegacyV1Sidecar(
      root,
      archived.receipt.assets[0],
      legacyValidation
    )
    const v2SidecarPath = join(
      root,
      'asset-validations',
      `${archived.receipt.assets[0].sha256}.trusted-v2.json`
    )
    const ordinaryReadProbe = vi.fn(async () => {
      throw new Error('ordinary read must not probe')
    })
    const offline = new PaidMediaVault(root, {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_001,
      fetchRemote,
      ensureMediaProbeReady: async () => undefined,
      validateMediaAsset: ordinaryReadProbe
    })

    await expect(offline.verifyArchive(OPERATION_ID)).rejects.toThrow(/explicit startup migration/i)
    expect(ordinaryReadProbe).not.toHaveBeenCalled()
    expect(existsSync(legacySidecarPath)).toBe(true)
    expect(existsSync(v2SidecarPath)).toBe(false)

    const migrate = vi.fn(trustedProbe)
    const online = new PaidMediaVault(root, {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_002,
      fetchRemote,
      ensureMediaProbeReady: async () => undefined,
      validateMediaAsset: migrate
    })
    const batch = await online.prepareTrustedValidationMigrationBatch()
    expect(batch.items).toHaveLength(1)
    expect(batch.items[0]).toMatchObject({
      source: { kind: 'archive', receiptSha256: expect.stringMatching(/^[0-9a-f]{64}$/) },
      asset: {
        reference: archived.receipt.assets[0].reference,
        sha256: archived.receipt.assets[0].sha256,
        byteLength: archived.receipt.assets[0].byteLength,
        mediaType: archived.receipt.assets[0].mediaType
      }
    })
    await expect(online.commitTrustedValidationMigrations(batch.items)).resolves.toEqual({
      committed: 1,
      alreadyPresent: 0
    })
    expect(migrate).toHaveBeenCalledTimes(1)
    expect(existsSync(legacySidecarPath)).toBe(true)
    expect(existsSync(v2SidecarPath)).toBe(true)

    const recoveredOffline = new PaidMediaVault(root, {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_003,
      fetchRemote,
      ensureMediaProbeReady: async () => undefined,
      validateMediaAsset: ordinaryReadProbe
    })
    await expect(recoveredOffline.verifyArchive(OPERATION_ID)).resolves.toMatchObject({
      receipt: { operationId: OPERATION_ID }
    })
    expect(ordinaryReadProbe).not.toHaveBeenCalled()
  })

  it('pins a legacy image outside Root and commits its sidecar only in the exact mutation context', async () => {
    const { root, fetchRemote, vault } = fixture()
    await recordImageClaim(
      vault,
      JSON.stringify({ model: 'image-model', prompt: 'legacy validation migration' })
    )
    const archived = await vault.archiveResult({
      operationId: OPERATION_ID,
      path: '/v1/images/generations',
      status: 200,
      responseJson: JSON.stringify({ data: [{ b64_json: PNG.toString('base64') }] })
    })
    const asset = archived.receipt.assets[0]
    removeEmbeddedValidation(join(root, 'archives', `${OPERATION_ID}.json`), false)
    const sidecarPath = join(
      root,
      'asset-validations',
      `${asset.sha256}.trusted-v2.json`
    )
    expect(existsSync(sidecarPath)).toBe(false)

    const migrateValidation = vi.fn(trustedProbe)
    const migrator = new PaidMediaVault(root, {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_002,
      fetchRemote,
      ensureMediaProbeReady: async () => undefined,
      validateMediaAsset: migrateValidation
    })
    await migrator.provisionAuthorityVault()
    let inRootMutation = false
    migrator.setMutationGuard(() => {
      if (!inRootMutation) throw new Error('no Root transaction capability')
    })
    const batch = await migrator.prepareTrustedValidationMigrationBatch()
    expect(batch.items).toHaveLength(1)
    await expect(migrator.verifyArchive(OPERATION_ID)).rejects.toThrow(
      /explicit startup migration/i
    )
    await expect(
      migrator.commitTrustedValidationMigrations(batch.items)
    ).rejects.toThrow(/no Root transaction capability/i)
    expect(existsSync(sidecarPath)).toBe(false)

    inRootMutation = true
    await expect(migrator.commitTrustedValidationMigrations(batch.items)).resolves.toEqual({
      committed: 1,
      alreadyPresent: 0
    })
    inRootMutation = false
    expect(migrateValidation).toHaveBeenCalledTimes(1)
    expect(existsSync(sidecarPath)).toBe(true)

    const offlineValidation = vi.fn(async () => {
      throw new Error('ordinary replay must not probe')
    })
    const recoveredOffline = new PaidMediaVault(root, {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_003,
      fetchRemote,
      ensureMediaProbeReady: async () => undefined,
      validateMediaAsset: offlineValidation
    })
    await expect(recoveredOffline.verifyArchive(OPERATION_ID)).resolves.toMatchObject({
      result: { data: [{ url: asset.reference }] }
    })
    expect(offlineValidation).not.toHaveBeenCalled()
  })

  it('freezes one large migration snapshot and deduplicates one asset across source pages', async () => {
    const item = fixture()
    const operationIds = Array.from(
      { length: 40 },
      (_, index) =>
        `desktop-op-10000000-0000-4000-8000-${String(index + 1).padStart(12, '0')}`
    )
    const firstOperationId = operationIds[0]
    const encodedBody = JSON.stringify({
      model: 'image-model',
      prompt: 'shared legacy migration asset'
    })
    await recordImageClaim(item.vault, encodedBody, firstOperationId)
    await item.vault.archiveResult({
      operationId: firstOperationId,
      path: '/v1/images/generations',
      status: 200,
      responseJson: JSON.stringify({ data: [{ b64_json: PNG.toString('base64') }] })
    })
    const firstArchivePath = join(item.root, 'archives', `${firstOperationId}.json`)
    removeEmbeddedValidation(firstArchivePath, false)
    const template = readProtectedDocument(firstArchivePath)
    const { receiptSha256: _discardedTemplateDigest, ...templateBase } = template
    for (const operationId of operationIds.slice(1)) {
      const base = { ...templateBase, operationId }
      writeProtectedDocument(join(item.root, 'archives', `${operationId}.json`), {
        ...base,
        receiptSha256: createHash('sha256').update(JSON.stringify(base)).digest('hex')
      })
    }

    const enumeratedDirectories = vi.fn()
    const migrationProbe = vi.fn(trustedProbe)
    const migrator = new PaidMediaVault(item.root, {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_100,
      fetchRemote: item.fetchRemote,
      ensureMediaProbeReady: async () => undefined,
      validateMediaAsset: migrationProbe,
      onValidationMigrationDirectoryEnumeration: enumeratedDirectories
    })
    const itemCounts: number[] = []
    let firstCursor: string | undefined
    let cursor: string | undefined
    do {
      const batch = await migrator.prepareTrustedValidationMigrationBatch({
        ...(cursor === undefined ? {} : { cursor }),
        limit: 16
      })
      itemCounts.push(batch.items.length)
      if (batch.items.length > 0) {
        await migrator.commitTrustedValidationMigrations(batch.items)
      }
      firstCursor ??= batch.nextCursor
      cursor = batch.nextCursor
    } while (cursor !== undefined)

    expect(itemCounts).toEqual([1, 0, 0])
    expect(migrationProbe).toHaveBeenCalledTimes(1)
    expect(enumeratedDirectories).toHaveBeenCalledTimes(4)
    expect(enumeratedDirectories.mock.calls.map(([path]) => path)).toEqual([
      join(item.root, 'archives'),
      join(item.root, 'video-terminals'),
      join(item.root, 'archives'),
      join(item.root, 'video-terminals')
    ])
    expect(firstCursor).toMatch(/^[0-9a-f]{64}:16$/)
    await expect(
      migrator.prepareTrustedValidationMigrationBatch({ cursor: firstCursor, limit: 16 })
    ).rejects.toThrow(/cursor is stale/i)
    expect(enumeratedDirectories).toHaveBeenCalledTimes(4)
    expect(operationIds).toHaveLength(40)
  })

  it('migrates a legacy terminal validation sidecar explicitly before offline recovery', async () => {
    const taskAlias = `nvt1_${'e'.repeat(64)}`
    const item = fixture(async (url) => ({
      bytes: MP4,
      contentType: 'video/mp4',
      finalUrl: url
    }))
    await item.vault.recordClaim({
      operationId: OPERATION_ID,
      path: '/v1/videos/generations',
      encodedBody: JSON.stringify({ model: 'video-model', prompt: 'legacy terminal' })
    })
    await item.vault.archiveResult({
      operationId: OPERATION_ID,
      path: '/v1/videos/generations',
      status: 202,
      responseJson: JSON.stringify({ task_id: taskAlias, status: 'queued' })
    })
    const terminal = await item.vault.archiveTerminalMediaForTask(taskAlias, {
      task_id: taskAlias,
      data: { status: 'completed', video_url: 'https://cdn.example/legacy.mp4' }
    })
    const terminalPath = join(
      item.root,
      'video-terminals',
      `${createHash('sha256').update(taskAlias).digest('hex')}.json`
    )
    const legacyValidation = legacyV1Validation(terminal.asset!)
    replaceEmbeddedValidation(terminalPath, true, legacyValidation)
    const legacySidecarPath = writeLegacyV1Sidecar(
      item.root,
      terminal.asset!,
      legacyValidation
    )
    const sidecarPath = join(
      item.root,
      'asset-validations',
      `${terminal.asset!.sha256}.trusted-v2.json`
    )

    const offlineValidation = vi.fn(async () => {
      throw new Error('ordinary terminal replay must not probe')
    })
    const offline = new PaidMediaVault(item.root, {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_010,
      fetchRemote: item.fetchRemote,
      ensureMediaProbeReady: async () => undefined,
      validateMediaAsset: offlineValidation
    })
    await expect(offline.verifyTerminalMediaForTask(taskAlias)).rejects.toThrow(
      /explicit startup migration/i
    )
    expect(offlineValidation).not.toHaveBeenCalled()
    expect(existsSync(legacySidecarPath)).toBe(true)
    expect(existsSync(sidecarPath)).toBe(false)

    const migrateValidation = vi.fn(trustedProbe)
    const migrator = new PaidMediaVault(item.root, {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_011,
      fetchRemote: item.fetchRemote,
      ensureMediaProbeReady: async () => undefined,
      validateMediaAsset: migrateValidation
    })
    const batch = await migrator.prepareTrustedValidationMigrationBatch()
    expect(batch.items).toEqual([
      expect.objectContaining({ source: expect.objectContaining({ kind: 'terminal' }) })
    ])
    await expect(migrator.commitTrustedValidationMigrations(batch.items)).resolves.toEqual({
      committed: 1,
      alreadyPresent: 0
    })
    expect(migrateValidation).toHaveBeenCalledTimes(1)
    expect(existsSync(sidecarPath)).toBe(true)

    const recoveredOffline = new PaidMediaVault(item.root, {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_012,
      fetchRemote: item.fetchRemote,
      ensureMediaProbeReady: async () => undefined,
      validateMediaAsset: offlineValidation
    })
    await expect(recoveredOffline.verifyTerminalMediaForTask(taskAlias)).resolves.toMatchObject({
      result: terminal.result
    })
    expect(offlineValidation).not.toHaveBeenCalled()
  })

  it('rejects magic-only MP4 and oversized PNG decode dimensions', async () => {
    const taskAlias = `nvt1_${'d'.repeat(64)}`
    for (const badBytes of [MP4_FTYP_ONLY, MP4_STRUCTURAL_SHELL]) {
      const video = fixture(async (url) => ({
        bytes: badBytes,
        contentType: 'video/mp4',
        finalUrl: url
      }))
      await video.vault.recordClaim({
        operationId: OPERATION_ID,
        path: '/v1/videos/generations',
        encodedBody: JSON.stringify({ model: 'video-model', prompt: 'bad container' })
      })
      await video.vault.archiveResult({
        operationId: OPERATION_ID,
        path: '/v1/videos/generations',
        status: 202,
        responseJson: JSON.stringify({ task_id: taskAlias, status: 'queued' })
      })
      await expect(
        video.vault.archiveTerminalMediaForTask(taskAlias, {
          task_id: taskAlias,
          status: 'completed',
          video_url: 'https://cdn.example/magic-only.mp4'
        })
      ).rejects.toThrow(/complete|playable|container/i)
    }

    const image = fixture()
    await recordImageClaim(
      image.vault,
      JSON.stringify({ model: 'image-model', prompt: 'decode bomb dimensions' })
    )
    const hugeHeader = Buffer.from(PNG)
    hugeHeader.writeUInt32BE(100_000, 16)
    hugeHeader.writeUInt32BE(testCrc32(hugeHeader.subarray(12, 29)), 29)
    await expect(
      image.vault.archiveResult({
        operationId: OPERATION_ID,
        path: '/v1/images/generations',
        status: 200,
        responseJson: JSON.stringify({ data: [{ b64_json: hugeHeader.toString('base64') }] })
      })
    ).rejects.toThrow(/dimension|decode budget/i)
  })

  it('does not silently replace a claim with different exact bytes', async () => {
    const { vault } = fixture()
    await recordImageClaim(vault, JSON.stringify({ model: 'image-model', prompt: 'first' }))
    await expect(
      recordImageClaim(vault, JSON.stringify({ model: 'image-model', prompt: 'second' }))
    ).rejects.toThrow(/conflict|request/i)
    expect(readFileSync).toBeDefined()
  })

  it('uses create-only publication when a destination appears during commit', async () => {
    const root = mkdtempSync(join(tmpdir(), 'nachuan-paid-vault-race-'))
    roots.push(root)
    const target = join(root, 'claims', `${OPERATION_ID}.json`)
    const racingBytes = Buffer.from('racing destination must survive', 'utf8')
    let planted = false
    const vault = new PaidMediaVault(root, {
      safeStorage: fakeStorage,
      harden: (path, directory) => {
        if (
          !planted &&
          !directory &&
          path.startsWith(`${join(root, 'claims')}\\.`) &&
          path.endsWith('.tmp')
        ) {
          planted = true
          writeFileSync(target, racingBytes, { flag: 'wx' })
        }
      },
      now: () => 1_800_000_000_000,
      fetchRemote: async (url) => ({ bytes: PNG, contentType: 'image/png', finalUrl: url }),
      ensureMediaProbeReady: async () => undefined,
      validateMediaAsset: trustedProbe
    })

    await expect(
      recordImageClaim(vault, JSON.stringify({ model: 'image-model', prompt: 'publication race' }))
    ).rejects.toThrow(/already exists/i)
    expect(planted).toBe(true)
    expect(readFileSync(target)).toEqual(racingBytes)
  })

  it('lists recent orphan archives as bounded secret-free recovery DTOs', async () => {
    const { vault } = fixture()
    const encodedBody = JSON.stringify({
      model: 'image-model',
      prompt: 'this private prompt must not appear in discovery'
    })
    await recordImageClaim(vault, encodedBody)
    await vault.archiveResult({
      operationId: OPERATION_ID,
      path: '/v1/images/generations',
      status: 200,
      responseJson: JSON.stringify({
        data: [{ url: 'https://signed.example/private-token.png' }]
      })
    })

    const page = await vault.listRecoverableArchives()
    const listed = page.items
    expect(listed).toEqual([
      expect.objectContaining({
        operationId: OPERATION_ID,
        path: '/v1/images/generations',
        kind: 'image',
        status: 200,
        receiptSha256: expect.stringMatching(/^[0-9a-f]{64}$/),
        assets: [
          expect.objectContaining({
            reference: expect.stringMatching(/^nachuan-paid-media:\/\/sha256\//),
            mediaType: 'image/png'
          })
        ]
      })
    ])
    expect(JSON.stringify(listed)).not.toMatch(
      /private prompt|private-token|requestSha256|responseSha256|b64_json/i
    )
  })

  it('paginates every archive without a silent top-50 truncation', async () => {
    const { vault } = fixture()
    const ids = [
      'desktop-op-11111111-1111-4111-8111-111111111111',
      'desktop-op-22222222-2222-4222-8222-222222222222',
      'desktop-op-33333333-3333-4333-8333-333333333333'
    ]
    for (const operationId of ids) {
      const encodedBody = JSON.stringify({ model: 'image-model', prompt: operationId })
      await recordImageClaim(vault, encodedBody, operationId)
      await vault.archiveResult({
        operationId,
        path: '/v1/images/generations',
        status: 200,
        responseJson: JSON.stringify({ data: [{ b64_json: PNG.toString('base64') }] })
      })
    }

    const discovered: string[] = []
    let cursor: string | undefined
    do {
      const page = await vault.listRecoverableArchives({ limit: 1, ...(cursor ? { cursor } : {}) })
      discovered.push(...page.items.map((item) => item.operationId))
      cursor = page.nextCursor
    } while (cursor)

    expect(discovered).toEqual(ids)
    expect(new Set(discovered).size).toBe(ids.length)
  })

  it('discovers fifty four-asset archives without deep-reading asset bytes', async () => {
    const { root, fetchRemote } = fixture()
    const archivedAt = 1_800_000_000_000
    const assetSha256 = createHash('sha256').update(PNG).digest('hex')
    const assets = Array.from({ length: 4 }, () => ({
      reference: `nachuan-paid-media://sha256/${assetSha256}`,
      mediaType: 'image/png',
      byteLength: MAX_PAID_MEDIA_ARCHIVE_ASSET_BYTES,
      sha256: assetSha256
    }))
    mkdirSync(join(root, 'archives'), { recursive: true })
    mkdirSync(join(root, 'discoveries'), { recursive: true })
    for (let index = 1; index <= 50; index += 1) {
      const head = index.toString(16).padStart(8, '0')
      const tail = index.toString(16).padStart(12, '0')
      const operationId = `desktop-op-${head}-1111-4111-8111-${tail}`
      const base = {
        schema: 'nachuan.paid-media-vault.discovery.v1',
        operationId,
        path: '/v1/images/generations',
        model: 'image-model',
        status: 200,
        kind: 'image',
        archivedAt,
        receiptSha256: createHash('sha256').update(`receipt:${index}`).digest('hex'),
        responseByteLength: 128,
        assets
      }
      const document = {
        ...base,
        discoverySha256: createHash('sha256')
          .update(JSON.stringify(base))
          .digest('hex')
      }
      const ciphertext = Buffer.from(`protected:${JSON.stringify(document)}`, 'utf8')
      const envelope = JSON.stringify({
        schema: 'nachuan.paid-media-vault.envelope.v1',
        protection: 'electron-safe-storage',
        ciphertext: ciphertext.toString('base64')
      })
      writeFileSync(
        join(
          root,
          'discoveries',
          `${String(archivedAt).padStart(16, '0')}_${operationId}.json`
        ),
        envelope
      )
      // Discovery must only check that the immutable receipt exists. The file
      // is intentionally not a valid envelope: reading it here would fail.
      writeFileSync(join(root, 'archives', `${operationId}.json`), 'not-read-by-discovery')
    }

    const harden = vi.fn()
    const restarted = new PaidMediaVault(root, {
      safeStorage: fakeStorage,
      harden,
      now: () => 1_800_000_000_001,
      fetchRemote,
      ensureMediaProbeReady: async () => undefined,
      validateMediaAsset: trustedProbe
    })
    const first = await restarted.listRecoverableArchives({ limit: 50 })
    expect(first.items).toHaveLength(50)
    expect(first.items.every((item) => item.assets.length === 4)).toBe(true)
    expect(first.items.every((item) => item.model === 'image-model')).toBe(true)
    const hardenedAfterFirstPage = harden.mock.calls.length
    await expect(restarted.listRecoverableArchives({ limit: 50 })).resolves.toEqual(first)
    expect(harden).toHaveBeenCalledTimes(hardenedAfterFirstPage)
    await expect(restarted.verifyArchive(first.items[0].operationId)).rejects.toThrow(
      /envelope|invalid/i
    )
  })

  it('does not re-run ACL hardening for unchanged vault objects', async () => {
    const { harden, vault } = fixture()
    const encodedBody = JSON.stringify({ model: 'image-model', prompt: 'bounded hardening' })
    await recordImageClaim(vault, encodedBody)
    const archived = await vault.archiveResult({
      operationId: OPERATION_ID,
      path: '/v1/images/generations',
      status: 200,
      responseJson: JSON.stringify({ data: [{ b64_json: PNG.toString('base64') }] })
    })
    const callsAfterCommit = harden.mock.calls.length

    await vault.listRecoverableArchives()
    await vault.verifyArchive(OPERATION_ID)
    await vault.readAsset(archived.receipt.assets[0].reference)
    await vault.listRecoverableArchives()
    await vault.verifyArchive(OPERATION_ID)
    await vault.readAsset(archived.receipt.assets[0].reference)

    expect(harden).toHaveBeenCalledTimes(callsAfterCommit)
  })

  it('does not cache a replacement that wins the verification-to-pin race', async () => {
    const { root, fetchRemote, vault } = fixture()
    await recordImageClaim(
      vault,
      JSON.stringify({ model: 'image-model', prompt: 'pin race' })
    )
    const archived = await vault.archiveResult({
      operationId: OPERATION_ID,
      path: '/v1/images/generations',
      status: 200,
      responseJson: JSON.stringify({ data: [{ b64_json: PNG.toString('base64') }] })
    })
    let replaced = false
    const restarted = new PaidMediaVault(root, {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_001,
      fetchRemote,
      ensureMediaProbeReady: async () => undefined,
      validateMediaAsset: trustedProbe,
      beforeAssetPin: (path) => {
        if (replaced) return
        replaced = true
        renameSync(path, `${path}.verified-displaced`)
        writeFileSync(path, Buffer.alloc(PNG.length, 0x41))
      }
    })
    const reference = archived.receipt.assets[0].reference

    await expect(restarted.openAsset(reference)).rejects.toThrow(/changed|pinned/i)
    await expect(restarted.openAsset(reference)).rejects.toThrow(/digest|magic|unsupported/i)
  })

  it('rejects changed bytes when the complete metadata cache identity collides', async () => {
    const { root, vault } = fixture()
    await recordImageClaim(
      vault,
      JSON.stringify({ model: 'image-model', prompt: 'same inode cache invalidation' })
    )
    const archived = await vault.archiveResult({
      operationId: OPERATION_ID,
      path: '/v1/images/generations',
      status: 200,
      responseJson: JSON.stringify({ data: [{ b64_json: PNG.toString('base64') }] })
    })
    const asset = archived.receipt.assets[0]
    const path = join(root, 'assets', `${asset.sha256}.${asset.extension}`)
    const initial = statSync(path)
    utimesSync(
      path,
      new Date(Math.trunc(initial.atimeMs)),
      new Date(Math.trunc(initial.mtimeMs))
    )
    const warmed = await vault.openAsset(asset.reference)
    await warmed.handle.close()
    const before = statSync(path)
    writeFileSync(path, Buffer.alloc(before.size, 0x41), { flag: 'r+' })
    utimesSync(path, before.atime, before.mtime)
    const after = statSync(path)
    const afterPrecise = statSync(path, { bigint: true })
    expect(after.ino).toBe(before.ino)
    expect(after.birthtimeMs).toBe(before.birthtimeMs)
    expect(after.size).toBe(before.size)
    expect(after.mtimeMs).toBe(before.mtimeMs)
    const cache = (
      vault as unknown as {
        verifiedAssets?: Map<
          string,
          {
            dev: bigint
            ino: bigint
            birthtimeNs: bigint
            size: bigint
            mtimeNs: bigint
            ctimeNs: bigint
          }
        >
      }
    ).verifiedAssets
    if (cache) {
      const cached = cache.get(resolve(path))
      expect(cached).toBeDefined()
      Object.assign(cached!, {
        dev: afterPrecise.dev,
        ino: afterPrecise.ino,
        birthtimeNs: afterPrecise.birthtimeNs,
        size: afterPrecise.size,
        mtimeNs: afterPrecise.mtimeNs,
        ctimeNs: afterPrecise.ctimeNs
      })
    }

    await expect(vault.openAsset(asset.reference)).rejects.toThrow(/digest|magic|changed/i)
  })

  it('persists the four encrypted v2 recovery sidecars and authorizes capacity only from exact local evidence', async () => {
    const mediaProbe = vi.fn(trustedProbe)
    const sessionTransport = vi.fn()
    const provider = vi.fn()
    const item = fixture(undefined, { validateMediaAsset: mediaProbe })
    const initialAuthority = await item.vault.provisionAuthorityVault()
    item.vault.setMutationGuard(() => undefined)
    const prepared = await createArchivedV2RecoveryFixture(item)
    if (!prepared.dispatch) throw new Error('expected a v2 dispatch marker')
    const archivedAuthority = await item.vault.inspectAuthorityEvidence()
    expect(archivedAuthority.vaultStateDigest).not.toBe(initialAuthority.vaultStateDigest)

    const { intent, completion } = await recordV2AckChain(item.vault, prepared)
    const completionReplay = await item.vault.recordAssetAckCompletion({
      operationId: OPERATION_ID,
      intentReceiptSha256: intent.receiptSha256,
      status: 200,
      response: {
        ok: true,
        turnId: prepared.result.turnId,
        replayed: true,
        cleanupComplete: true
      }
    })
    expect(completionReplay).toEqual(completion)
    const completedAuthority = await item.vault.inspectAuthorityEvidence()
    expect(completedAuthority.vaultStateDigest).not.toBe(
      archivedAuthority.vaultStateDigest
    )

    const authorization = await item.vault.recordAssetCapacityReleaseAuthorization({
      operationId: OPERATION_ID,
      archive: {
        receiptSha256: prepared.archive.receipt.receiptSha256,
        cleanupComplete: true
      },
      dispatch: { receiptSha256: prepared.dispatch.receiptSha256 },
      ackCompletion: { receiptSha256: completion.receiptSha256 }
    })
    expect(authorization).toMatchObject({
      operationId: OPERATION_ID,
      cleanupComplete: true,
      archiveReceiptSha256: prepared.archive.receipt.receiptSha256,
      dispatchReceiptSha256: prepared.dispatch.receiptSha256,
      ackCompletionReceiptSha256: completion.receiptSha256
    })
    expect(Object.isFrozen(prepared.dispatch)).toBe(true)
    expect(Object.isFrozen(intent)).toBe(true)
    expect(Object.isFrozen(completion)).toBe(true)
    expect(Object.isFrozen(authorization)).toBe(true)
    expect(intent).not.toHaveProperty('tokens')
    expect(JSON.stringify(intent)).not.toContain(prepared.result.assets[0]!.token)

    const intentPath = join(
      item.root,
      'claims',
      `${OPERATION_ID}.asset-ack-intent.json`
    )
    expect(readFileSync(intentPath, 'utf8')).not.toContain(
      prepared.result.assets[0]!.token
    )
    expect(readdirSync(join(item.root, 'claims')).sort()).toEqual(
      [
        `${OPERATION_ID}.asset-ack-completion.json`,
        `${OPERATION_ID}.asset-ack-intent.json`,
        `${OPERATION_ID}.asset-capacity-release.json`,
        `${OPERATION_ID}.asset-v2-dispatch.json`,
        `${OPERATION_ID}.json`
      ].sort()
    )
    const releasedAuthority = await item.vault.inspectAuthorityEvidence()
    expect(releasedAuthority.vaultStateDigest).not.toBe(
      completedAuthority.vaultStateDigest
    )

    const restarted = new PaidMediaVault(item.root, {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_001,
      fetchRemote: item.fetchRemote,
      ensureMediaProbeReady: async () => undefined,
      validateMediaAsset: mediaProbe,
      stageRoot: () => item.stageRoot
    })
    restarted.setMutationGuard(() => undefined)
    await expect(restarted.verifyAssetV2DispatchMarker(OPERATION_ID)).resolves.toEqual(
      prepared.dispatch
    )
    await expect(restarted.verifyAssetAckIntent(OPERATION_ID)).resolves.toEqual(intent)
    await expect(restarted.verifyAssetAckCompletion(OPERATION_ID)).resolves.toEqual(
      completion
    )
    await expect(
      restarted.verifyAssetCapacityReleaseAuthorization(OPERATION_ID)
    ).resolves.toEqual(authorization)
    expect(item.fetchRemote).not.toHaveBeenCalled()
    expect(mediaProbe).not.toHaveBeenCalled()
    expect(sessionTransport).not.toHaveBeenCalled()
    expect(provider).not.toHaveBeenCalled()
  })

  it('withholds capacity authorization when ACK completion is missing', async () => {
    const item = fixture()
    await item.vault.provisionAuthorityVault()
    item.vault.setMutationGuard(() => undefined)
    const prepared = await createArchivedV2RecoveryFixture(item)
    if (!prepared.dispatch) throw new Error('expected a v2 dispatch marker')
    const tokens = prepared.result.assets.map((asset) => asset.token)
    await item.vault.recordAssetAckIntent({
      operationId: OPERATION_ID,
      turnId: prepared.result.turnId,
      tokens,
      tokenSetDigest: paidMediaTokenSetDigest(tokens),
      archiveReceiptSha256: prepared.archive.receipt.receiptSha256,
      assetResultSha256: prepared.resultSha256,
      dispatchReceiptSha256: prepared.dispatch.receiptSha256
    })

    await expect(
      item.vault.recordAssetCapacityReleaseAuthorization({
        operationId: OPERATION_ID,
        archive: {
          receiptSha256: prepared.archive.receipt.receiptSha256,
          cleanupComplete: true
        },
        dispatch: { receiptSha256: prepared.dispatch.receiptSha256 },
        ackCompletion: { receiptSha256: 'a'.repeat(64) }
      })
    ).rejects.toThrow(/completion|registered|missing/i)
    expect(
      existsSync(
        join(item.root, 'claims', `${OPERATION_ID}.asset-capacity-release.json`)
      )
    ).toBe(false)
  })

  it('withholds capacity authorization for v1 or any operation without the v2 dispatch marker', async () => {
    const item = fixture()
    await item.vault.provisionAuthorityVault()
    item.vault.setMutationGuard(() => undefined)
    const prepared = await createArchivedV2RecoveryFixture(item, { dispatch: false })

    await expect(
      item.vault.recordAssetCapacityReleaseAuthorization({
        operationId: OPERATION_ID,
        archive: {
          receiptSha256: prepared.archive.receipt.receiptSha256,
          cleanupComplete: true
        },
        dispatch: { receiptSha256: 'b'.repeat(64) },
        ackCompletion: { receiptSha256: 'c'.repeat(64) }
      })
    ).rejects.toThrow(/dispatch|registered|missing/i)
    expect(
      existsSync(
        join(item.root, 'claims', `${OPERATION_ID}.asset-capacity-release.json`)
      )
    ).toBe(false)
  })

  it('withholds capacity authorization when a completed ACK outlives its exact archive', async () => {
    const item = fixture()
    await item.vault.provisionAuthorityVault()
    item.vault.setMutationGuard(() => undefined)
    const prepared = await createArchivedV2RecoveryFixture(item)
    if (!prepared.dispatch) throw new Error('expected a v2 dispatch marker')
    const { completion } = await recordV2AckChain(item.vault, prepared)
    unlinkSync(join(item.root, 'archives', `${OPERATION_ID}.json`))

    await expect(
      item.vault.recordAssetCapacityReleaseAuthorization({
        operationId: OPERATION_ID,
        archive: {
          receiptSha256: prepared.archive.receipt.receiptSha256,
          cleanupComplete: true
        },
        dispatch: { receiptSha256: prepared.dispatch.receiptSha256 },
        ackCompletion: { receiptSha256: completion.receiptSha256 }
      })
    ).rejects.toThrow(/archive|missing/i)
    expect(
      existsSync(
        join(item.root, 'claims', `${OPERATION_ID}.asset-capacity-release.json`)
      )
    ).toBe(false)
  })

  it('allows remote ACK evidence from an opened crash window but keeps local capacity held', async () => {
    const item = fixture(undefined, {
      beforeArchivedStageCleanupIntent: async () => {
        throw new Error('injected link-to-cleanup-intent crash window')
      }
    })
    await item.vault.provisionAuthorityVault()
    item.vault.setMutationGuard(() => undefined)
    await expect(createArchivedV2RecoveryFixture(item)).rejects.toThrow(
      /cleanup-intent crash window/i
    )
    const { result, resultSha256 } = await v2SidecarResultFixture()
    const dispatch = await item.vault.verifyAssetV2DispatchMarker(OPERATION_ID)
    const archive = await item.vault.verifyArchive(OPERATION_ID)
    expect(archive.cleanupComplete).toBe(false)
    await expect(item.vault.inspectStageRecovery()).resolves.toMatchObject({
      leases: [{ state: 'opened' }]
    })
    const { completion } = await recordV2AckChain(item.vault, {
      result,
      resultSha256,
      archive,
      dispatch
    })

    await expect(
      item.vault.recordAssetCapacityReleaseAuthorization({
        operationId: OPERATION_ID,
        archive: {
          receiptSha256: archive.receipt.receiptSha256,
          cleanupComplete: true
        },
        dispatch: { receiptSha256: dispatch.receiptSha256 },
        ackCompletion: { receiptSha256: completion.receiptSha256 }
      })
    ).rejects.toThrow(/cleanup|incomplete|evidence/i)
    expect(
      existsSync(
        join(item.root, 'claims', `${OPERATION_ID}.asset-capacity-release.json`)
      )
    ).toBe(false)
  })

  it('allows remote ACK evidence from a held stage only while capacity remains manual-only', async () => {
    let unlinkAttempts = 0
    const item = fixture(undefined, {
      stageCleanupIO: {
        unlinkStageFile: (path) => {
          unlinkAttempts += 1
          if (unlinkAttempts === 1) throw new Error('leave stage cleanup pending')
          unlinkSync(path)
        },
        removeEmptyStageDirectory: rmdirSync
      }
    })
    await item.vault.provisionAuthorityVault()
    item.vault.setMutationGuard(() => undefined)
    const prepared = await createArchivedV2RecoveryFixture(item)
    if (!prepared.dispatch) throw new Error('expected a v2 dispatch marker')
    expect(prepared.archive.cleanupComplete).toBe(false)
    const inspection = await item.vault.inspectStageRecovery()
    expect(inspection).toMatchObject({
      leases: [{ state: 'archived_cleanup_pending', disposition: 'cleanup' }]
    })
    const leaseId = inspection.leases[0]!.leaseId
    const [directoryName] = readdirSync(item.stageRoot)
    const stagePath = join(item.stageRoot, directoryName!, 'asset.bin')
    renameSync(stagePath, `${stagePath}.identity-before`)
    writeFileSync(stagePath, PNG)
    await expect(cleanupStageLease(item.vault, leaseId)).resolves.toEqual({
      status: 'held'
    })
    await expect(item.vault.inspectStageRecovery()).resolves.toMatchObject({
      leases: [{ state: 'held', disposition: 'manual_only' }]
    })
    const archive = await item.vault.verifyArchive(OPERATION_ID)
    expect(archive.cleanupComplete).toBe(false)
    const { completion } = await recordV2AckChain(item.vault, {
      ...prepared,
      archive
    })

    await expect(
      item.vault.recordAssetCapacityReleaseAuthorization({
        operationId: OPERATION_ID,
        archive: {
          receiptSha256: archive.receipt.receiptSha256,
          cleanupComplete: true
        },
        dispatch: { receiptSha256: prepared.dispatch.receiptSha256 },
        ackCompletion: { receiptSha256: completion.receiptSha256 }
      })
    ).rejects.toThrow(/cleanup|incomplete|evidence/i)
    expect(
      existsSync(
        join(item.root, 'claims', `${OPERATION_ID}.asset-capacity-release.json`)
      )
    ).toBe(false)
  })

  it('makes exact sidecar replay idempotent while rejecting drift, extra fields, non-200 ACKs, and replacement', async () => {
    const item = fixture()
    await item.vault.provisionAuthorityVault()
    item.vault.setMutationGuard(() => undefined)
    const prepared = await createArchivedV2RecoveryFixture(item)
    if (!prepared.dispatch) throw new Error('expected a v2 dispatch marker')
    const { intent, completion } = await recordV2AckChain(item.vault, prepared)
    const authorizationInput = {
      operationId: OPERATION_ID,
      archive: {
        receiptSha256: prepared.archive.receipt.receiptSha256,
        cleanupComplete: true as const
      },
      dispatch: { receiptSha256: prepared.dispatch.receiptSha256 },
      ackCompletion: { receiptSha256: completion.receiptSha256 }
    }
    const authorization = await item.vault.recordAssetCapacityReleaseAuthorization(
      authorizationInput
    )

    await expect(
      item.vault.recordAssetV2DispatchMarker({
        operationId: OPERATION_ID,
        path: prepared.dispatch.path,
        requestSha256: prepared.dispatch.requestSha256,
        recoveryDomainSha256: prepared.dispatch.recoveryDomainSha256,
        paidPrincipalSha256: prepared.dispatch.paidPrincipalSha256,
        turnId: prepared.dispatch.turnId,
        assetResultSha256: prepared.dispatch.assetResultSha256
      })
    ).resolves.toEqual(prepared.dispatch)
    await expect(recordV2AckChain(item.vault, prepared, true)).resolves.toEqual({
      intent,
      completion
    })
    await expect(
      item.vault.recordAssetCapacityReleaseAuthorization(authorizationInput)
    ).resolves.toEqual(authorization)

    await expect(
      item.vault.recordAssetV2DispatchMarker({
        operationId: OPERATION_ID,
        path: prepared.dispatch.path,
        requestSha256: prepared.dispatch.requestSha256,
        recoveryDomainSha256: prepared.dispatch.recoveryDomainSha256,
        paidPrincipalSha256: '4'.repeat(64),
        turnId: prepared.dispatch.turnId,
        assetResultSha256: prepared.dispatch.assetResultSha256
      })
    ).rejects.toThrow(/conflict/i)
    const conflictingTokens = [`nma1_${'Z'.repeat(43)}`]
    await expect(
      item.vault.recordAssetAckIntent({
        operationId: OPERATION_ID,
        turnId: prepared.result.turnId,
        tokens: conflictingTokens,
        tokenSetDigest: paidMediaTokenSetDigest(conflictingTokens),
        archiveReceiptSha256: prepared.archive.receipt.receiptSha256,
        assetResultSha256: prepared.resultSha256,
        dispatchReceiptSha256: prepared.dispatch.receiptSha256
      })
    ).rejects.toThrow(/conflict/i)
    await expect(
      item.vault.recordAssetAckCompletion({
        operationId: OPERATION_ID,
        intentReceiptSha256: intent.receiptSha256,
        status: 200,
        response: {
          ok: true,
          turnId: 'f'.repeat(64),
          replayed: false,
          cleanupComplete: true
        }
      })
    ).rejects.toThrow(/conflict/i)
    await expect(
      item.vault.recordAssetV2DispatchMarker({
        operationId: OPERATION_ID,
        path: prepared.dispatch.path,
        requestSha256: prepared.dispatch.requestSha256,
        recoveryDomainSha256: prepared.dispatch.recoveryDomainSha256,
        paidPrincipalSha256: prepared.dispatch.paidPrincipalSha256,
        turnId: prepared.dispatch.turnId,
        assetResultSha256: prepared.dispatch.assetResultSha256,
        extra: true
      } as never)
    ).rejects.toThrow(/input is invalid/i)
    await expect(
      item.vault.recordAssetAckCompletion({
        operationId: OPERATION_ID,
        intentReceiptSha256: intent.receiptSha256,
        status: 202,
        response: {
          ok: true,
          turnId: prepared.result.turnId,
          replayed: false,
          cleanupComplete: true
        }
      } as never)
    ).rejects.toThrow(/input is invalid/i)
    await expect(
      item.vault.recordAssetCapacityReleaseAuthorization({
        ...authorizationInput,
        ackCompletion: { receiptSha256: 'd'.repeat(64) }
      })
    ).rejects.toThrow(/completion|evidence|match/i)

    const releasePath = join(
      item.root,
      'claims',
      `${OPERATION_ID}.asset-capacity-release.json`
    )
    renameSync(releasePath, `${releasePath}.replaced`)
    writeFileSync(releasePath, '{}')
    await expect(
      item.vault.verifyAssetCapacityReleaseAuthorization(OPERATION_ID)
    ).rejects.toThrow(/authority|match|size|envelope/i)
  })
})
