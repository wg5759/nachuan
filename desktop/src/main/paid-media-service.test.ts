import { createHash } from 'node:crypto'
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmdirSync,
  rmSync,
  statSync,
  unlinkSync,
  utimesSync,
  writeFileSync
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'

import {
  nodePaidMediaAtomicIO,
  PaidMediaLedger,
  type PaidMediaSafeStorage
} from './paid-media-ledger'
import { PaidMediaCapacityManager } from './paid-media-capacity'
import {
  PAID_MEDIA_RECOVERABLE_HANDLER_VERSION,
  type PaidMediaInstallationRootState,
  type PaidMediaAuthorityMutationContext,
  type PaidMediaAuthorityMutationInput
} from './paid-media-installation-root'
import type { PaidMediaLegacySealStatus } from './paid-media-legacy-seal'
import {
  PaidMediaVault,
  type PaidMediaVaultDependencies,
  type PaidMediaRemoteFetcher,
  type PaidMediaTrustedProbeResult
} from './paid-media-vault'
import {
  PaidMediaService,
  PaidMediaServiceError,
  type PaidMediaAssetV2ExecutionInput,
  type PaidMediaInstallationAuthority,
  type PaidMediaTransport
} from './paid-media-service'

const UUID_ONE = '11111111-1111-4111-8111-111111111111'
const PNG = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=',
  'base64'
)
// 16x16, one-frame H.264 MP4 generated locally with FFmpeg's color source.
const MP4 = Buffer.from(
  'AAAAIGZ0eXBpc29tAAACAGlzb21pc28yYXZjMW1wNDEAAAMUbW9vdgAAAGxtdmhkAAAAAAAAAAAAAAAAAAAD6AAAAMgAAQAAAQAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAj90cmFrAAAAXHRraGQAAAADAAAAAAAAAAAAAAABAAAAAAAAAMgAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAABAAAAAABAAAAAQAAAAAAAkZWR0cwAAABxlbHN0AAAAAAAAAAEAAADIAAAAAAABAAAAAAG3bWRpYQAAACBtZGhkAAAAAAAAAAAAAAAAAAAoAAAACABVxAAAAAAALWhkbHIAAAAAAAAAAHZpZGUAAAAAAAAAAAAAAABWaWRlb0hhbmRsZXIAAAABYm1pbmYAAAAUdm1oZAAAAAEAAAAAAAAAAAAAACRkaW5mAAAAHGRyZWYAAAAAAAAAAQAAAAx1cmwgAAAAAQAAASJzdGJsAAAAvnN0c2QAAAAAAAAAAQAAAK5hdmMxAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAABAAEABIAAAASAAAAAAAAAABFUxhdmM2Mi4xMS4xMDAgbGlieDI2NAAAAAAAAAAAAAAAGP//AAAANGF2Y0MBZAAK/+EAF2dkAAqs2V7ARAAAAwAEAAADACg8SJZYAQAGaOvjyyLA/fj4AAAAABBwYXNwAAAAAQAAAAEAAAAUYnRydAAAAAAAAG6gAAAAAAAAABhzdHRzAAAAAAAAAAEAAAABAAAIAAAAABxzdHNjAAAAAAAAAAEAAAABAAAAAQAAAAEAAAAUc3RzegAAAAAAAALEAAAAAQAAABRzdGNvAAAAAAAAAAEAAANEAAAAYXVkdGEAAABZbWV0YQAAAAAAAAAhaGRscgAAAAAAAAAAbWRpcmFwcGwAAAAAAAAAAAAAAAAsaWxzdAAAACSpdG9vAAAAHGRhdGEAAAABAAAAAExhdmY2Mi4zLjEwMAAAAAhmcmVlAAACzG1kYXQAAAKtBgX//6ncRem95tlIt5Ys2CDZI+7veDI2NCAtIGNvcmUgMTY1IHIzMjIzIDA0ODBjYjAgLSBILjI2NC9NUEVHLTQgQVZDIGNvZGVjIC0gQ29weWxlZnQgMjAwMy0yMDI1IC0gaHR0cDovL3d3dy52aWRlb2xhbi5vcmcveDI2NC5odG1sIC0gb3B0aW9uczogY2FiYWM9MSByZWY9MyBkZWJsb2NrPTE6MDowIGFuYWx5c2U9MHgzOjB4MTEzIG1lPWhleCBzdWJtZT03IHBzeT0xIHBzeV9yZD0xLjAwOjAuMDAgbWl4ZWRfcmVmPTEgbWVfcmFuZ2U9MTYgY2hyb21hX21lPTEgdHJlbGxpcz0xIDh4OGRjdD0xIGNxbT0wIGRlYWR6b25lPTIxLDExIGZhc3RfcHNraXA9MSBjaHJvbWFfcXBfb2Zmc2V0PS0yIHRocmVhZHM9MSBsb29rYWhlYWRfdGhyZWFkcz0xIHNsaWNlZF90aHJlYWRzPTAgbnI9MCBkZWNpbWF0ZT0xIGludGVybGFjZWQ9MCBibHVyYXlfY29tcGF0PTAgY29uc3RyYWluZWRfaW50cmE9MCBiZnJhbWVzPTMgYl9weXJhbWlkPTIgYl9hZGFwdD0xIGJfYmlhcz0wIGRpcmVjdD0xIHdlaWdodGI9MSBvcGVuX2dvcD0wIHdlaWdodHA9MiBrZXlpbnQ9MjUwIGtleWludF9taW49NSBzY2VuZWN1dD00MCBpbnRyYV9yZWZyZXNoPTAgcmNfbG9va2FoZWFkPTQwIHJjPWNyZiBtYnRyZWU9MSBjcmY9MjMuMCBxY29tcD0wLjYwIHFwbWluPTAgcXBtYXg9NjkgcXBzdGVwPTQgaXBfcmF0aW89MS40MCBhcT0xOjEuMDAAgAAAAA9liIQAP//+92ifApteYbk=',
  'base64'
)

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
  const data = Buffer.alloc(paddingBytes, 0x33)
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

function removeArchiveEmbeddedValidation(path: string): void {
  const envelope = JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>
  const plaintext = Buffer.from(String(envelope.ciphertext), 'base64').toString('utf8')
  if (!plaintext.startsWith('protected:')) throw new Error('invalid test archive envelope')
  const document = JSON.parse(plaintext.slice('protected:'.length)) as Record<string, unknown>
  const asset = (document.assets as Record<string, unknown>[])[0]
  delete asset.validation
  const { receiptSha256: _discarded, ...base } = document
  const updated = {
    ...base,
    receiptSha256: createHash('sha256').update(JSON.stringify(base)).digest('hex')
  }
  writeFileSync(
    path,
    JSON.stringify({
      schema: 'nachuan.paid-media-vault.envelope.v1',
      protection: 'electron-safe-storage',
      ciphertext: Buffer.from(`protected:${JSON.stringify(updated)}`, 'utf8').toString('base64')
    }),
    'utf8'
  )
}

function fixture(
  transport?: PaidMediaTransport,
  fetchRemote?: PaidMediaRemoteFetcher,
  ensureMediaProbeReady: () => Promise<void> = async () => undefined,
  freeBytes: () => bigint = () => 64n * 1024n * 1024n * 1024n,
  cleanupIO?: NonNullable<PaidMediaVaultDependencies['cleanupIO']>
): {
  root: string
  service: PaidMediaService
  ledger: PaidMediaLedger
  vault: PaidMediaVault
  capacity: PaidMediaCapacityManager
  request: ReturnType<typeof vi.fn<PaidMediaTransport>>
} {
  const root = mkdtempSync(join(tmpdir(), 'nachuan-paid-service-'))
  roots.push(root)
  let now = 1_800_000_000_000
  let uuid = 0
  const ledger = new PaidMediaLedger(join(root, 'ledger.json'), {
    safeStorage: fakeStorage,
    harden: () => undefined,
    now: () => ++now,
    uuid: () => `10000000-0000-4000-8000-${String(++uuid).padStart(12, '0')}`,
    atomicIO: nodePaidMediaAtomicIO
  })
  const request = vi.fn<PaidMediaTransport>(
    transport ??
      (async () => ({
        status: 200,
        headers: {},
        body: JSON.stringify({ created: 1, data: [{ url: 'https://media.invalid/one.png' }] })
      }))
  )
  const vault = new PaidMediaVault(join(root, 'vault'), {
    safeStorage: fakeStorage,
    harden: () => undefined,
    now: () => ++now,
    fetchRemote:
      fetchRemote ??
      (async (url) => ({
        bytes: PNG,
        contentType: 'image/png',
        finalUrl: url
      })),
    ensureMediaProbeReady,
    validateMediaAsset: trustedProbe,
    cleanupIO
  })
  const capacity = new PaidMediaCapacityManager(
    join(root, 'capacity.json'),
    join(root, 'vault'),
    {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => ++now,
      atomicIO: nodePaidMediaAtomicIO,
      tempRoot: () => root,
      probeSpoolRoot: () => root,
      resolveVolume: () => ({ volumeId: 'volume-one', root }),
      freeBytes
    }
  )
  return {
    root,
    ledger,
    vault,
    capacity,
    request,
    service: new PaidMediaService({
      ledger,
      vault,
      capacity,
      baseUrl: () => 'http://127.0.0.1:19001',
      runtimeKey: () => 'sk-local-runtime',
      approvalKey: () => 'sk-approval-independent',
      paidMediaKey: () => 'sk-paid-media-independent',
      transport: request
    })
  }
}

function restartFixture(
  item: Pick<ReturnType<typeof fixture>, 'root'>,
  cleanupIO?: NonNullable<PaidMediaVaultDependencies['cleanupIO']>,
  onCleanupError?: (error: unknown) => void
): Pick<ReturnType<typeof fixture>, 'service' | 'ledger' | 'vault' | 'capacity'> {
  let now = 1_900_000_000_000
  let uuid = 0
  const ledger = new PaidMediaLedger(join(item.root, 'ledger.json'), {
    safeStorage: fakeStorage,
    harden: () => undefined,
    now: () => ++now,
    uuid: () => `20000000-0000-4000-8000-${String(++uuid).padStart(12, '0')}`,
    atomicIO: nodePaidMediaAtomicIO
  })
  const vault = new PaidMediaVault(join(item.root, 'vault'), {
    safeStorage: fakeStorage,
    harden: () => undefined,
    now: () => ++now,
    fetchRemote: async () => {
      throw new Error('restart recovery must not fetch remote media')
    },
    ensureMediaProbeReady: async () => undefined,
    validateMediaAsset: trustedProbe,
    cleanupIO,
    onCleanupError
  })
  const capacity = new PaidMediaCapacityManager(
    join(item.root, 'capacity.json'),
    join(item.root, 'vault'),
    {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => ++now,
      atomicIO: nodePaidMediaAtomicIO,
      tempRoot: () => item.root,
      probeSpoolRoot: () => item.root,
      resolveVolume: () => ({ volumeId: 'volume-one', root: item.root }),
      freeBytes: () => 64n * 1024n * 1024n * 1024n
    }
  )
  return {
    ledger,
    vault,
    capacity,
    service: new PaidMediaService({
      ledger,
      vault,
      capacity,
      baseUrl: () => 'http://127.0.0.1:19001',
      runtimeKey: () => 'sk-local-runtime',
      approvalKey: () => 'sk-approval-independent',
      paidMediaKey: () => 'sk-paid-media-independent',
      transport: async () => {
        throw new Error('restart recovery must not call transport')
      }
    })
  }
}

async function prepareVideoPollBinding(
  item: Pick<ReturnType<typeof fixture>, 'vault' | 'capacity'>,
  taskAlias: string,
  model = 'video-model'
): Promise<void> {
  const operationId = `desktop-op-${UUID_ONE}`
  const encodedBody = JSON.stringify({ model, prompt: 'bound poll task' })
  await item.vault.recordClaim({
    operationId,
    path: '/v1/videos/generations',
    encodedBody
  })
  await item.capacity.ensureReservation({
    operationId,
    path: '/v1/videos/generations',
    allowCreate: true
  })
  const archived = await item.vault.archiveResult({
    operationId,
    path: '/v1/videos/generations',
    status: 202,
    responseJson: JSON.stringify({ task_id: taskAlias, status: 'queued' })
  })
  await item.capacity.bindVideoTask({
    operationId,
    taskAliasSha256: archived.receipt.taskReceiptIdSha256!
  })
}

function cleanupHeldVideoFixture(
  taskAlias: string,
  stagingFile: string,
  cleanupIO: NonNullable<PaidMediaVaultDependencies['cleanupIO']>
): ReturnType<typeof fixture> {
  return fixture(
    async (request) =>
      request.method === 'POST'
        ? {
            status: 202,
            headers: {},
            body: JSON.stringify({ task_id: taskAlias, status: 'queued' })
          }
        : {
            status: 200,
            headers: {},
            body: JSON.stringify({
              task_id: taskAlias,
              status: 'completed',
              video_url: 'https://cdn.example/final.mp4'
            })
          },
    async (url) => ({
      filePath: stagingFile,
      byteLength: MP4.byteLength,
      contentType: 'video/mp4',
      finalUrl: url
    }),
    async () => undefined,
    () => 64n * 1024n * 1024n * 1024n,
    cleanupIO
  )
}

async function archiveCleanupHeldVideo(
  item: ReturnType<typeof fixture>,
  taskAlias: string
): Promise<string> {
  const encodedBody = JSON.stringify({ model: 'video-model', prompt: 'cleanup restart hold' })
  const claimed = await item.service.claim({ path: '/v1/videos/generations', encodedBody })
  await item.service.execute({
    operationId: claimed.operationId,
    path: '/v1/videos/generations',
    encodedBody
  })
  await expect(
    item.service.pollVideo({ taskAlias, model: 'video-model' })
  ).resolves.toMatchObject({ status: 'completed' })
  await expect(item.vault.verifyTerminalMediaForTask(taskAlias)).resolves.toMatchObject({
    cleanupComplete: false
  })
  return claimed.operationId
}

// This suite intentionally drives the real ledger, vault, capacity and Root
// atomic-file paths. Keep its Windows durability budget local so the rest of
// the repository retains the default 30 second test boundary.
describe('PaidMediaService', { timeout: 120_000 }, () => {
  it('routes every rooted claim, provider dispatch, and delivery ACK through composite authority while replay stays local', async () => {
    const item = fixture()
    const mutations: string[] = []
    let inRootMutation = false
    let evidenceReader: (() => Promise<unknown> | unknown) | null = null
    let rootAvailable = true
    let pauseNextMutation = false
    let announcePaused: (() => void) | null = null
    let releasePaused: () => void = () => undefined
    let authorityState: PaidMediaInstallationAuthority['state'] = {
      mode: 'detached',
      reasonCode: 'test-detached'
    }
    const outboundProof = vi.fn(async () => {
      if (!rootAvailable) throw new Error('Root restarting')
      return authorityState
    })
    const installationRoot: PaidMediaInstallationAuthority = {
      get state() {
        return authorityState
      },
      attachEvidenceReader(reader: () => Promise<unknown> | unknown) {
        evidenceReader = reader
      },
      async provision() {
        await evidenceReader?.()
        authorityState = { mode: 'ready', reasonCode: 'test-ready' }
        return authorityState
      },
      async reconcileStartup() {
        await evidenceReader?.()
        authorityState = { mode: 'ready', reasonCode: 'test-ready' }
        return authorityState
      },
      localPaidPrincipal: () => 'a'.repeat(64),
      assertMutationContext() {
        if (!inRootMutation) throw new Error('outside composite Root')
      },
      assertOutboundReady: outboundProof,
      async runMutation<T>(
        input: PaidMediaAuthorityMutationInput,
        action: (context: PaidMediaAuthorityMutationContext) => Promise<T>
      ): Promise<T> {
        mutations.push(input.kind)
        inRootMutation = true
        try {
          if (pauseNextMutation) {
            pauseNextMutation = false
            announcePaused?.()
            await new Promise<void>((resolve) => {
              releasePaused = resolve
            })
          }
          const value = await action({
            transactionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
            assertOutboundReady: async () => {
              await outboundProof()
            }
          })
          await evidenceReader?.()
          return value
        } finally {
          inRootMutation = false
        }
      }
    }
    const transport = vi.fn<PaidMediaTransport>(async () => {
      expect(inRootMutation).toBe(false)
      return {
        status: 200,
        headers: {},
        body: JSON.stringify({ created: 1, data: [{ b64_json: PNG.toString('base64') }] })
      }
    })
    const dependencies = {
      ledger: item.ledger,
      vault: item.vault,
      capacity: item.capacity,
      baseUrl: () => 'http://127.0.0.1:19001',
      runtimeKey: () => 'sk-local-runtime',
      approvalKey: () => 'sk-approval-independent',
      paidMediaKey: () => 'sk-paid-media-independent',
      transport,
      installationRoot,
      legacySeal: {
        inspect: async () => ({
          state: 'closed' as const,
          closedAt: 1,
          decision: { kind: 'empty' as const, decisionSha256: 'b'.repeat(64) }
        }),
        close: async () => ({
          state: 'closed' as const,
          closedAt: 1,
          decision: { kind: 'empty' as const, decisionSha256: 'b'.repeat(64) }
        })
      }
    }
    const service = new PaidMediaService(dependencies)

    await service.initializeInstallationAuthority({
      provision: true,
      provisionLocalState: true
    })
    const wrapped = service.withAuthorities({
      runtimeKey: () => 'sk-local-runtime',
      approvalKey: () => 'sk-approval-independent',
      paidMediaKey: () => 'sk-paid-media-independent'
    })
    const encodedBody = JSON.stringify({ model: 'image-model', prompt: 'rooted paid request' })
    pauseNextMutation = true
    const paused = new Promise<void>((resolve) => {
      announcePaused = resolve
    })
    const claimPromise = wrapped.claim({ path: '/v1/images/generations', encodedBody })
    await paused
    await expect(
      item.capacity.ensureReservation({
        operationId: 'desktop-op-99999999-9999-4999-8999-999999999999',
        path: '/v1/images/generations',
        allowCreate: true
      })
    ).rejects.toThrow(/no active context|no Root transaction capability/i)
    releasePaused()
    const claimed = await claimPromise
    const executed = await service.execute({
      operationId: claimed.operationId,
      path: '/v1/images/generations',
      encodedBody
    })
    expect(executed.ok).toBe(true)
    expect(mutations).toEqual(['claim', 'dispatch_prepare', 'execute_result'])
    expect(outboundProof).toHaveBeenCalled()

    const mutationCount = mutations.length
    rootAvailable = false
    await expect(
      service.claim({
        path: '/v1/images/generations',
        encodedBody,
        retryOperationId: claimed.operationId
      })
    ).resolves.toMatchObject({ operationId: claimed.operationId })
    await expect(
      service.execute({
        operationId: claimed.operationId,
        path: '/v1/images/generations',
        encodedBody
      })
    ).resolves.toMatchObject({ ok: true })
    expect(mutations).toHaveLength(mutationCount)
    expect(transport).toHaveBeenCalledTimes(1)

    rootAvailable = true
    if (!executed.ok) throw new Error('expected paid media success')
    await service.acknowledgeDelivered(executed.deliveryProof)
    expect(mutations).toEqual([
      'claim',
      'dispatch_prepare',
      'execute_result',
      'ack_delivery'
    ])
  })

  it('resumes an exact recoverable startup ticket locally before enabling the service', async () => {
    const item = fixture()
    const pendingInput = {
      handlerVersion: PAID_MEDIA_RECOVERABLE_HANDLER_VERSION,
      kind: 'asset_v2_dispatch' as const,
      operationId: `desktop-op-${UUID_ONE}`,
      intentSha256: '7'.repeat(64)
    }
    let authorityState: PaidMediaInstallationRootState = {
      mode: 'detached',
      reasonCode: 'test-detached'
    }
    let evidenceReader: (() => Promise<unknown> | unknown) | null = null
    const resumeRecoverableMutation = vi.fn(async (input: typeof pendingInput) => {
      expect(input).toEqual(pendingInput)
      authorityState = { mode: 'ready', reasonCode: 'test-recovered' }
      return authorityState
    })
    const installationRoot: PaidMediaInstallationAuthority = {
      get state() {
        return authorityState
      },
      attachEvidenceReader(reader) {
        evidenceReader = reader
      },
      async provision() {
        await evidenceReader?.()
        authorityState = {
          mode: 'recovery_pending',
          reasonCode: 'test-recovery-pending',
          pendingRecovery: {
            ...pendingInput,
            preparedAt: 1_800_000_000_000,
            beforeCompositeDigest: '8'.repeat(64)
          }
        }
        return authorityState
      },
      async reconcileStartup() {
        return authorityState
      },
      localPaidPrincipal: () => '9'.repeat(64),
      assertMutationContext: () => undefined,
      async assertOutboundReady() {
        return authorityState
      },
      async runMutation<T>(
        _input: PaidMediaAuthorityMutationInput,
        action: (context: PaidMediaAuthorityMutationContext) => Promise<T>
      ): Promise<T> {
        return action({
          transactionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
          assertOutboundReady: async () => undefined
        })
      },
      resumeRecoverableMutation
    }
    const service = new PaidMediaService({
      ledger: item.ledger,
      vault: item.vault,
      capacity: item.capacity,
      baseUrl: () => 'http://127.0.0.1:19001',
      runtimeKey: () => 'sk-local-runtime',
      approvalKey: () => 'sk-approval-independent',
      paidMediaKey: () => 'sk-paid-media-independent',
      transport: item.request,
      installationRoot,
      legacySeal: {
        inspect: async () => ({
          state: 'closed',
          closedAt: 1,
          decision: { kind: 'empty', decisionSha256: 'a'.repeat(64) }
        }),
        close: vi.fn()
      }
    })

    await expect(
      service.initializeInstallationAuthority({ provision: true, provisionLocalState: true })
    ).resolves.toMatchObject({ authority: { mode: 'ready' } })
    expect(resumeRecoverableMutation).toHaveBeenCalledTimes(1)
    expect(item.request).not.toHaveBeenCalled()
  })

  it('does not probe or mutate legacy assets again in the boot that just recovered an exact ticket', async () => {
    const item = fixture()
    const encodedBody = JSON.stringify({ model: 'image-model', prompt: 'legacy after recovery' })
    const claimed = await item.service.claim({ path: '/v1/images/generations', encodedBody })
    await item.service.execute({
      operationId: claimed.operationId,
      path: '/v1/images/generations',
      encodedBody
    })
    removeArchiveEmbeddedValidation(
      join(item.root, 'vault', 'archives', `${claimed.operationId}.json`)
    )

    const migrationProbe = vi.fn(trustedProbe)
    const rootedVault = new PaidMediaVault(join(item.root, 'vault'), {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_900_000_000_050,
      fetchRemote: async () => {
        throw new Error('recovered startup must not fetch legacy media')
      },
      ensureMediaProbeReady: async () => undefined,
      validateMediaAsset: migrationProbe
    })
    await item.ledger.provisionAuthorityLedger()
    await rootedVault.provisionAuthorityVault()
    await item.capacity.provisionAuthorityJournal()

    const pendingInput = {
      handlerVersion: PAID_MEDIA_RECOVERABLE_HANDLER_VERSION,
      kind: 'asset_v2_dispatch' as const,
      operationId: `desktop-op-${UUID_ONE}`,
      intentSha256: '7'.repeat(64)
    }
    let authorityState: PaidMediaInstallationRootState = {
      mode: 'recovery_pending',
      reasonCode: 'test-recovery-pending',
      pendingRecovery: {
        ...pendingInput,
        preparedAt: 1_800_000_000_000,
        beforeCompositeDigest: '8'.repeat(64)
      }
    }
    const resumeRecoverableMutation = vi.fn(async (input: typeof pendingInput) => {
      expect(input).toEqual(pendingInput)
      authorityState = { mode: 'ready', reasonCode: 'test-recovered' }
      return authorityState
    })
    const installationRoot: PaidMediaInstallationAuthority = {
      get state() {
        return authorityState
      },
      attachEvidenceReader: vi.fn(),
      async provision() {
        return authorityState
      },
      async reconcileStartup() {
        return authorityState
      },
      localPaidPrincipal: () => '9'.repeat(64),
      assertMutationContext: () => undefined,
      async assertOutboundReady() {
        return authorityState
      },
      async runMutation() {
        throw new Error('recovered startup must not begin a second local mutation')
      },
      resumeRecoverableMutation
    }
    const transport = vi.fn<PaidMediaTransport>(async () => {
      throw new Error('recovered startup must not call transport')
    })
    const service = new PaidMediaService({
      ledger: item.ledger,
      vault: rootedVault,
      capacity: item.capacity,
      baseUrl: () => 'http://127.0.0.1:19001',
      runtimeKey: () => 'sk-local-runtime',
      approvalKey: () => 'sk-approval-independent',
      paidMediaKey: () => 'sk-paid-media-independent',
      transport,
      installationRoot,
      legacySeal: {
        inspect: async () => ({
          state: 'closed',
          closedAt: 1,
          decision: { kind: 'empty', decisionSha256: 'a'.repeat(64) }
        }),
        close: vi.fn()
      }
    })

    await expect(
      service.initializeInstallationAuthority({ provision: false, provisionLocalState: false })
    ).resolves.toMatchObject({
      authority: { mode: 'ready', reasonCode: 'test-recovered' },
      legacyImported: false,
      capacity: null
    })
    expect(resumeRecoverableMutation).toHaveBeenCalledTimes(1)
    expect(migrationProbe).not.toHaveBeenCalled()
    expect(transport).not.toHaveBeenCalled()
  })

  it('returns a readable manual-only control plane in the same boot when recovery refuses a stage kind', async () => {
    const item = fixture()
    const pendingInput = {
      handlerVersion: PAID_MEDIA_RECOVERABLE_HANDLER_VERSION,
      kind: 'asset_v2_dispatch' as const,
      operationId: `desktop-op-${UUID_ONE}`,
      intentSha256: '7'.repeat(64)
    }
    let authorityState: PaidMediaInstallationRootState = {
      mode: 'detached',
      reasonCode: 'test-detached'
    }
    const resumeRecoverableMutation = vi.fn(async () => {
      authorityState = { mode: 'manual_only', reasonCode: 'unsupported-recovery-kind' }
      throw new Error('stage recovery is intentionally refused')
    })
    const installationRoot: PaidMediaInstallationAuthority = {
      get state() {
        return authorityState
      },
      attachEvidenceReader: vi.fn(),
      async provision() {
        authorityState = {
          mode: 'recovery_pending',
          reasonCode: 'test-recovery-pending',
          pendingRecovery: {
            ...pendingInput,
            preparedAt: 1_800_000_000_000,
            beforeCompositeDigest: '8'.repeat(64)
          }
        }
        return authorityState
      },
      async reconcileStartup() {
        return authorityState
      },
      localPaidPrincipal: () => '9'.repeat(64),
      assertMutationContext: () => undefined,
      async assertOutboundReady() {
        return authorityState
      },
      async runMutation<T>(
        _input: PaidMediaAuthorityMutationInput,
        action: (context: PaidMediaAuthorityMutationContext) => Promise<T>
      ): Promise<T> {
        return action({
          transactionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
          assertOutboundReady: async () => undefined
        })
      },
      resumeRecoverableMutation
    }
    const service = new PaidMediaService({
      ledger: item.ledger,
      vault: item.vault,
      capacity: item.capacity,
      baseUrl: () => 'http://127.0.0.1:19001',
      runtimeKey: () => 'sk-local-runtime',
      approvalKey: () => 'sk-approval-independent',
      paidMediaKey: () => 'sk-paid-media-independent',
      transport: item.request,
      installationRoot,
      legacySeal: {
        inspect: async () => ({
          state: 'closed',
          closedAt: 1,
          decision: { kind: 'empty', decisionSha256: 'a'.repeat(64) }
        }),
        close: vi.fn()
      }
    })

    await expect(
      service.initializeInstallationAuthority({ provision: true, provisionLocalState: true })
    ).resolves.toMatchObject({
      authority: { mode: 'manual_only', reasonCode: 'unsupported-recovery-kind' },
      legacyImported: false,
      capacity: null
    })
    await expect(service.listUnresolved()).resolves.toEqual([])
    expect(resumeRecoverableMutation).toHaveBeenCalledTimes(1)
    expect(item.request).not.toHaveBeenCalled()
  })

  it('shares bootstrap state across wrappers and treats a closed seal as read-only replay authority', async () => {
    const item = fixture()
    let authorityState: PaidMediaInstallationAuthority['state'] = {
      mode: 'detached',
      reasonCode: 'test-detached'
    }
    let activeTransaction: string | null = null
    let evidenceReader: (() => Promise<unknown> | unknown) | null = null
    const installationRoot: PaidMediaInstallationAuthority = {
      get state() {
        return authorityState
      },
      attachEvidenceReader(reader) {
        evidenceReader = reader
      },
      async provision() {
        await evidenceReader?.()
        authorityState = { mode: 'ready', reasonCode: 'test-ready' }
        return authorityState
      },
      async reconcileStartup() {
        await evidenceReader?.()
        authorityState = { mode: 'ready', reasonCode: 'test-ready' }
        return authorityState
      },
      localPaidPrincipal: () => 'c'.repeat(64),
      assertMutationContext(transactionId) {
        if (!transactionId || activeTransaction !== transactionId) {
          throw new Error('outside test Root transaction')
        }
      },
      async assertOutboundReady() {
        return authorityState
      },
      async runMutation<T>(
        input: PaidMediaAuthorityMutationInput,
        action: (context: PaidMediaAuthorityMutationContext) => Promise<T>
      ): Promise<T> {
        const transactionId = `aaaaaaaa-aaaa-4aaa-8aaa-${String(input.kind.length).padStart(12, '0')}`
        activeTransaction = transactionId
        try {
          const result = await action({
            transactionId,
            assertOutboundReady: async () => undefined
          })
          await evidenceReader?.()
          return result
        } finally {
          activeTransaction = null
        }
      }
    }
    let sealStatus: PaidMediaLegacySealStatus = { state: 'open' }
    const close = vi.fn(async (decision: { kind: string }) => {
      if (decision.kind !== 'empty') throw new Error('unexpected test decision')
      sealStatus = {
        state: 'closed',
        closedAt: 1_800_000_000_000,
        decision: { kind: 'empty', decisionSha256: 'd'.repeat(64) }
      }
      return sealStatus as Extract<PaidMediaLegacySealStatus, { state: 'closed' }>
    })
    const service = new PaidMediaService({
      ledger: item.ledger,
      vault: item.vault,
      capacity: item.capacity,
      baseUrl: () => 'http://127.0.0.1:19001',
      runtimeKey: () => 'sk-local-runtime',
      approvalKey: () => 'sk-approval-independent',
      paidMediaKey: () => 'sk-paid-media-independent',
      transport: item.request,
      installationRoot,
      legacySeal: { inspect: async () => sealStatus, close }
    })

    await expect(
      service.prepareInstallationAuthority({
        provision: true,
        provisionLocalState: true,
        allowLegacyBootstrap: true
      })
    ).resolves.toEqual({ state: 'legacy_bootstrap_required' })
    const wrapped = service.withAuthorities({
      runtimeKey: () => 'sk-local-runtime',
      approvalKey: () => 'sk-approval-independent',
      paidMediaKey: () => 'sk-paid-media-independent'
    })
    await expect(wrapped.bootstrapLegacyMigration(null)).resolves.toEqual({
      state: 'closed',
      decisionSha256: 'd'.repeat(64)
    })

    const encodedBody = JSON.stringify({ model: 'image-model', prompt: 'shared bootstrap' })
    const claimed = await wrapped.claim({ path: '/v1/images/generations', encodedBody })
    await expect(
      wrapped.execute({
        operationId: claimed.operationId,
        path: '/v1/images/generations',
        encodedBody
      })
    ).resolves.toMatchObject({ ok: true })
    await expect(wrapped.listUnresolved()).resolves.toHaveLength(1)
    await expect(wrapped.bootstrapLegacyMigration({ kind: 'migrated' })).resolves.toEqual({
      state: 'closed',
      decisionSha256: 'd'.repeat(64)
    })
    service.disableRemoteOperations()
    await service.initializeInstallationAuthority({
      provision: false,
      provisionLocalState: false
    })
    await expect(
      wrapped.claim({
        path: '/v1/images/generations',
        encodedBody: JSON.stringify({ model: 'image-model', prompt: 'must remain disabled' })
      })
    ).rejects.toThrow(/remote operations are disabled/i)

    const before = await Promise.all([
      item.ledger.inspectAuthorityEvidence(),
      item.vault.inspectAuthorityEvidence(),
      item.capacity.inspectAuthorityEvidence()
    ])
    await expect(
      service.bootstrapLegacyMigration({
        operationId: `desktop-op-${UUID_ONE}`,
        path: '/v1/images/generations',
        requestSha256: 'e'.repeat(64),
        createdAt: 1_750_000_000_000,
        updatedAt: 1_750_000_000_001,
        state: 'pending'
      })
    ).rejects.toThrow(/conflicts with the sealed decision/)
    const after = await Promise.all([
      item.ledger.inspectAuthorityEvidence(),
      item.vault.inspectAuthorityEvidence(),
      item.capacity.inspectAuthorityEvidence()
    ])
    expect(after).toEqual(before)
    expect(close).toHaveBeenCalledTimes(1)
  })

  it('does not let a forged migrated marker close an open seal', async () => {
    const item = fixture()
    const close = vi.fn()
    const installationRoot = {
      state: { mode: 'detached', reasonCode: 'test-detached' },
      attachEvidenceReader: vi.fn(),
      provision: vi.fn(),
      reconcileStartup: vi.fn(),
      localPaidPrincipal: () => 'f'.repeat(64),
      assertMutationContext: vi.fn(),
      assertOutboundReady: vi.fn(),
      runMutation: vi.fn()
    } as unknown as PaidMediaInstallationAuthority
    const service = new PaidMediaService({
      ledger: item.ledger,
      vault: item.vault,
      capacity: item.capacity,
      baseUrl: () => 'http://127.0.0.1:19001',
      runtimeKey: () => 'sk-local-runtime',
      approvalKey: () => 'sk-approval-independent',
      paidMediaKey: () => 'sk-paid-media-independent',
      transport: item.request,
      installationRoot,
      legacySeal: { inspect: async () => ({ state: 'open' }), close }
    })
    await service.prepareInstallationAuthority({
      provision: true,
      provisionLocalState: true,
      allowLegacyBootstrap: true
    })

    await expect(service.bootstrapLegacyMigration({ kind: 'migrated' })).rejects.toThrow(
      /cannot close the durable legacy seal/
    )
    expect(close).not.toHaveBeenCalled()
    await expect(service.listUnresolved()).rejects.toThrow(/initialization succeeds/)
  })

  it('migrates a legacy validation receipt before Root bind and keeps every later replay read-only', async () => {
    const item = fixture()
    const encodedBody = JSON.stringify({ model: 'image-model', prompt: 'legacy rooted replay' })
    const claimed = await item.service.claim({ path: '/v1/images/generations', encodedBody })
    await item.service.execute({
      operationId: claimed.operationId,
      path: '/v1/images/generations',
      encodedBody
    })
    const archivePath = join(item.root, 'vault', 'archives', `${claimed.operationId}.json`)
    removeArchiveEmbeddedValidation(archivePath)
    const migrationProbe = vi.fn(trustedProbe)
    const rootedVault = new PaidMediaVault(join(item.root, 'vault'), {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_900_000_000_001,
      fetchRemote: async () => {
        throw new Error('legacy migration must use pinned local bytes')
      },
      ensureMediaProbeReady: async () => undefined,
      validateMediaAsset: migrationProbe
    })
    let authorityState: PaidMediaInstallationAuthority['state'] = {
      mode: 'detached',
      reasonCode: 'test-detached'
    }
    let evidenceReader: (() => Promise<unknown> | unknown) | null = null
    let activeTransaction: string | null = null
    const authority: PaidMediaInstallationAuthority = {
      get state() {
        return authorityState
      },
      attachEvidenceReader(reader) {
        evidenceReader = reader
      },
      async provision() {
        await evidenceReader?.()
        authorityState = { mode: 'ready', reasonCode: 'test-ready' }
        return authorityState
      },
      async reconcileStartup() {
        authorityState = { mode: 'ready', reasonCode: 'test-ready' }
        return authorityState
      },
      localPaidPrincipal: () => '9'.repeat(64),
      assertMutationContext(transactionId) {
        if (!transactionId || transactionId !== activeTransaction) {
          throw new Error('outside validation migration Root transaction')
        }
      },
      async assertOutboundReady() {
        return authorityState
      },
      async runMutation<T>(
        _input: PaidMediaAuthorityMutationInput,
        action: (context: PaidMediaAuthorityMutationContext) => Promise<T>
      ): Promise<T> {
        activeTransaction = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
        try {
          return await action({
            transactionId: activeTransaction,
            assertOutboundReady: async () => undefined
          })
        } finally {
          activeTransaction = null
        }
      }
    }
    const rooted = new PaidMediaService({
      ledger: item.ledger,
      vault: rootedVault,
      capacity: item.capacity,
      baseUrl: () => 'http://127.0.0.1:19001',
      runtimeKey: () => 'sk-local-runtime',
      approvalKey: () => 'sk-approval-independent',
      paidMediaKey: () => 'sk-paid-media-independent',
      transport: item.request,
      installationRoot: authority,
      legacySeal: {
        inspect: async () => ({
          state: 'closed',
          closedAt: 1,
          decision: { kind: 'empty', decisionSha256: '8'.repeat(64) }
        }),
        close: vi.fn()
      }
    })

    await rooted.initializeInstallationAuthority({
      provision: true,
      provisionLocalState: true
    })
    expect(migrationProbe).toHaveBeenCalledTimes(1)
    await expect(rooted.recoverArchived(claimed.operationId)).resolves.toMatchObject({
      operationId: claimed.operationId
    })
    expect(migrationProbe).toHaveBeenCalledTimes(1)

    const ordinaryReadProbe = vi.fn(async () => {
      throw new Error('ordinary rooted replay must not probe')
    })
    const reopened = new PaidMediaVault(join(item.root, 'vault'), {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_900_000_000_002,
      fetchRemote: async () => {
        throw new Error('ordinary rooted replay must not fetch')
      },
      ensureMediaProbeReady: async () => undefined,
      validateMediaAsset: ordinaryReadProbe
    })
    reopened.setMutationGuard(() => {
      throw new Error('ordinary rooted replay attempted a write')
    })
    await expect(reopened.verifyArchive(claimed.operationId)).resolves.toMatchObject({
      receipt: { operationId: claimed.operationId }
    })
    expect(ordinaryReadProbe).not.toHaveBeenCalled()
  })

  it('leaves a Root-visible failed migration intent when legacy probing cannot complete', async () => {
    const item = fixture()
    const encodedBody = JSON.stringify({ model: 'image-model', prompt: 'failed migration intent' })
    const claimed = await item.service.claim({ path: '/v1/images/generations', encodedBody })
    await item.service.execute({
      operationId: claimed.operationId,
      path: '/v1/images/generations',
      encodedBody
    })
    removeArchiveEmbeddedValidation(
      join(item.root, 'vault', 'archives', `${claimed.operationId}.json`)
    )
    const failingVault = new PaidMediaVault(join(item.root, 'vault'), {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_900_000_000_010,
      fetchRemote: async () => {
        throw new Error('migration fetch forbidden')
      },
      ensureMediaProbeReady: async () => {
        throw new Error('trusted probe unavailable')
      },
      validateMediaAsset: trustedProbe
    })
    await item.ledger.provisionAuthorityLedger()
    await failingVault.provisionAuthorityVault()
    await item.capacity.provisionAuthorityJournal()
    let authorityState: PaidMediaInstallationAuthority['state'] = {
      mode: 'detached',
      reasonCode: 'test-detached'
    }
    const mutations: string[] = []
    const authority = {
      get state() {
        return authorityState
      },
      attachEvidenceReader: vi.fn(),
      provision: vi.fn(),
      async reconcileStartup() {
        authorityState = { mode: 'ready', reasonCode: 'test-ready' }
        return authorityState
      },
      localPaidPrincipal: () => '7'.repeat(64),
      assertMutationContext: vi.fn(),
      async assertOutboundReady() {
        return authorityState
      },
      async runMutation<T>(
        input: PaidMediaAuthorityMutationInput,
        action: (context: PaidMediaAuthorityMutationContext) => Promise<T>
      ): Promise<T> {
        mutations.push(input.kind)
        try {
          return await action({
            transactionId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
            assertOutboundReady: async () => undefined
          })
        } catch (error) {
          authorityState = { mode: 'fused', reasonCode: 'mutation-action-failed' }
          throw error
        }
      }
    } as PaidMediaInstallationAuthority
    const rooted = new PaidMediaService({
      ledger: item.ledger,
      vault: failingVault,
      capacity: item.capacity,
      baseUrl: () => 'http://127.0.0.1:19001',
      runtimeKey: () => 'sk-local-runtime',
      approvalKey: () => 'sk-approval-independent',
      paidMediaKey: () => 'sk-paid-media-independent',
      transport: item.request,
      installationRoot: authority,
      legacySeal: {
        inspect: async () => ({
          state: 'closed',
          closedAt: 1,
          decision: { kind: 'empty', decisionSha256: '6'.repeat(64) }
        }),
        close: vi.fn()
      }
    })

    await expect(
      rooted.initializeInstallationAuthority({
        provision: false,
        provisionLocalState: false
      })
    ).rejects.toThrow(/initialization failed/)
    expect(mutations).toContain('validation_migration')
    expect(authority.state).toMatchObject({
      mode: 'fused',
      reasonCode: 'mutation-action-failed'
    })
    await expect(rooted.recoverArchived(claimed.operationId)).rejects.toThrow(
      /initialization succeeds/
    )
  })

  it('fuses Root when the frozen validation migration source snapshot drifts between pages', async () => {
    const item = fixture()
    const encodedBody = JSON.stringify({ model: 'image-model', prompt: 'migration drift' })
    const claimed = await item.service.claim({ path: '/v1/images/generations', encodedBody })
    await item.service.execute({
      operationId: claimed.operationId,
      path: '/v1/images/generations',
      encodedBody
    })
    const firstArchivePath = join(
      item.root,
      'vault',
      'archives',
      `${claimed.operationId}.json`
    )
    removeArchiveEmbeddedValidation(firstArchivePath)
    const envelope = JSON.parse(readFileSync(firstArchivePath, 'utf8')) as Record<
      string,
      unknown
    >
    const plaintext = Buffer.from(String(envelope.ciphertext), 'base64').toString('utf8')
    if (!plaintext.startsWith('protected:')) throw new Error('invalid test archive envelope')
    const template = JSON.parse(plaintext.slice('protected:'.length)) as Record<
      string,
      unknown
    >
    const { receiptSha256: _discardedTemplateDigest, ...templateBase } = template
    for (let index = 2; index <= 17; index += 1) {
      const operationId = `desktop-op-10000000-0000-4000-8000-${String(index).padStart(12, '0')}`
      const base = { ...templateBase, operationId }
      const document = {
        ...base,
        receiptSha256: createHash('sha256').update(JSON.stringify(base)).digest('hex')
      }
      writeFileSync(
        join(item.root, 'vault', 'archives', `${operationId}.json`),
        JSON.stringify({
          schema: 'nachuan.paid-media-vault.envelope.v1',
          protection: 'electron-safe-storage',
          ciphertext: Buffer.from(
            `protected:${JSON.stringify(document)}`,
            'utf8'
          ).toString('base64')
        }),
        'utf8'
      )
    }

    let sourceDirectoryEnumerations = 0
    const driftingVault = new PaidMediaVault(join(item.root, 'vault'), {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_900_000_000_020,
      fetchRemote: async () => {
        throw new Error('migration must use pinned local bytes')
      },
      ensureMediaProbeReady: async () => undefined,
      validateMediaAsset: trustedProbe,
      onValidationMigrationDirectoryEnumeration: () => {
        sourceDirectoryEnumerations += 1
        if (sourceDirectoryEnumerations === 3) {
          const info = statSync(firstArchivePath)
          utimesSync(
            firstArchivePath,
            new Date(info.atimeMs),
            new Date(info.mtimeMs + 60_000)
          )
        }
      }
    })
    await item.ledger.provisionAuthorityLedger()
    await driftingVault.provisionAuthorityVault()
    await item.capacity.provisionAuthorityJournal()

    let authorityState: PaidMediaInstallationAuthority['state'] = {
      mode: 'detached',
      reasonCode: 'test-detached'
    }
    const mutations: string[] = []
    const authority = {
      get state() {
        return authorityState
      },
      attachEvidenceReader: vi.fn(),
      provision: vi.fn(),
      async reconcileStartup() {
        authorityState = { mode: 'ready', reasonCode: 'test-ready' }
        return authorityState
      },
      localPaidPrincipal: () => '5'.repeat(64),
      assertMutationContext: vi.fn(),
      async assertOutboundReady() {
        return authorityState
      },
      async runMutation<T>(
        input: PaidMediaAuthorityMutationInput,
        action: (context: PaidMediaAuthorityMutationContext) => Promise<T>
      ): Promise<T> {
        mutations.push(input.kind)
        try {
          return await action({
            transactionId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
            assertOutboundReady: async () => undefined
          })
        } catch (error) {
          authorityState = { mode: 'fused', reasonCode: 'mutation-action-failed' }
          throw error
        }
      }
    } as PaidMediaInstallationAuthority
    const rooted = new PaidMediaService({
      ledger: item.ledger,
      vault: driftingVault,
      capacity: item.capacity,
      baseUrl: () => 'http://127.0.0.1:19001',
      runtimeKey: () => 'sk-local-runtime',
      approvalKey: () => 'sk-approval-independent',
      paidMediaKey: () => 'sk-paid-media-independent',
      transport: item.request,
      installationRoot: authority,
      legacySeal: {
        inspect: async () => ({
          state: 'closed',
          closedAt: 1,
          decision: { kind: 'empty', decisionSha256: '4'.repeat(64) }
        }),
        close: vi.fn()
      }
    })

    await expect(
      rooted.initializeInstallationAuthority({
        provision: false,
        provisionLocalState: false
      })
    ).rejects.toThrow(/initialization failed/)
    expect(sourceDirectoryEnumerations).toBe(4)
    expect(mutations.filter((kind) => kind === 'validation_migration')).toHaveLength(2)
    expect(authority.state).toMatchObject({
      mode: 'fused',
      reasonCode: 'mutation-action-failed'
    })
    await expect(rooted.recoverArchived(claimed.operationId)).rejects.toThrow(
      /initialization succeeds/
    )
  })

  it('shares the operation fence and remote circuit breaker across authority wrappers', async () => {
    const item = fixture(async () => {
      await new Promise<void>((resolve) => setTimeout(resolve, 25))
      return {
        status: 200,
        headers: {},
        body: JSON.stringify({ created: 1, data: [{ b64_json: PNG.toString('base64') }] })
      }
    })
    const encodedBody = JSON.stringify({ model: 'image-model', prompt: 'one shared winner' })
    const claimed = await item.service.claim({
      path: '/v1/images/generations',
      encodedBody
    })
    const authorities = {
      runtimeKey: () => 'sk-local-runtime',
      approvalKey: () => 'sk-approval-independent',
      paidMediaKey: () => 'sk-paid-media-independent'
    }
    const left = item.service.withAuthorities(authorities)
    const right = item.service.withAuthorities(authorities)

    const [first, second] = await Promise.all([
      left.execute({
        operationId: claimed.operationId,
        path: '/v1/images/generations',
        encodedBody
      }),
      right.execute({
        operationId: claimed.operationId,
        path: '/v1/images/generations',
        encodedBody
      })
    ])
    expect(first.ok).toBe(true)
    expect(second.ok).toBe(true)
    expect(item.request).toHaveBeenCalledTimes(1)
    await expect(item.ledger.listPublic()).resolves.toMatchObject([
      { operationId: claimed.operationId, dispatchCount: 1 }
    ])

    item.service.disableRemoteOperations()
    await expect(
      left.claim({
        path: '/v1/images/generations',
        encodedBody: JSON.stringify({ model: 'image-model', prompt: 'must stay disabled' })
      })
    ).rejects.toThrow(/disabled/i)
  })

  it('polls an owner-bound video alias through main without exposing paid authority', async () => {
    const item = fixture(async () => ({
      status: 200,
      headers: { 'retry-after': '8' },
      body: JSON.stringify({
        status: 'processing',
        progress: 12,
        video_url: 'https://cdn.example/preview.mp4'
      })
    }))
    const taskAlias = `nvt1_${'a'.repeat(64)}`
    await prepareVideoPollBinding(item, taskAlias)

    await expect(
      item.service.pollVideo({ taskAlias, model: 'video-model' })
    ).resolves.toEqual({
      status: 'processing',
      progress: 12,
      video_url: 'https://cdn.example/preview.mp4'
    })

    expect(item.request).toHaveBeenCalledTimes(1)
    const outbound = item.request.mock.calls[0][0]
    expect(outbound).toMatchObject({
      method: 'GET',
      path: `/v1/videos/${taskAlias}`,
      encodedBody: '',
      headers: {
        Authorization: 'Bearer sk-local-runtime',
        'X-Nachuan-Paid-Media-Key': 'sk-paid-media-independent',
        Accept: 'application/json'
      }
    })
    expect(outbound.headers).not.toHaveProperty('Idempotency-Key')
  })

  it.each([
    {
      name: 'nested queued status wins over a preview URL',
      result: { data: { status: 'queued', url: 'https://cdn.example/preview.mp4' } }
    },
    {
      name: 'a status containing a success-like substring is not terminal',
      result: { status: 'unsuccessful', url: 'https://cdn.example/preview.mp4' }
    }
  ])('keeps polling when $name', async ({ result }) => {
    const item = fixture(async () => ({
      status: 200,
      headers: {},
      body: JSON.stringify(result)
    }))
    const taskAlias = `nvt1_${'9'.repeat(64)}`
    await prepareVideoPollBinding(item, taskAlias)

    await expect(
      item.service.pollVideo({ taskAlias, model: 'video-model' })
    ).resolves.toEqual(result)
  })

  it('rejects an unbound video alias before authority lookup or transport', async () => {
    const { service, request } = fixture()

    await expect(
      service.pollVideo({ taskAlias: `nvt1_${'8'.repeat(64)}`, model: 'video-model' })
    ).rejects.toThrow(/task index|binding/i)
    expect(request).not.toHaveBeenCalled()
  })

  it('blocks new paid remote work after the startup capacity circuit breaker opens', async () => {
    const ensureMediaProbeReady = vi.fn(async () => undefined)
    const item = fixture(undefined, undefined, ensureMediaProbeReady)
    item.service.disableRemoteOperations()

    await expect(
      item.service.claim({
        path: '/v1/images/generations',
        encodedBody: JSON.stringify({ model: 'image-model', prompt: 'must stay local' })
      })
    ).rejects.toThrow(/remote operations are disabled/i)
    expect(ensureMediaProbeReady).not.toHaveBeenCalled()
    expect(item.request).not.toHaveBeenCalled()
    await expect(item.ledger.listPublic()).resolves.toEqual([])
    await expect(item.capacity.listReservations()).resolves.toEqual([])
  })

  it('returns only a Main-archived stable reference for a terminal paid video URL', async () => {
    const taskAlias = `nvt1_${'b'.repeat(64)}`
    const { root, service, ledger, vault, capacity } = fixture(
      async (request) =>
        request.method === 'POST'
          ? {
              status: 202,
              headers: {},
              body: JSON.stringify({ task_id: taskAlias, status: 'queued' })
            }
          : {
              status: 200,
              headers: {},
               body: JSON.stringify({
                 task_id: taskAlias,
                 data: {
                   status: 'completed',
                   video_url: 'https://cdn.example/final.mp4'
                 }
               })
            },
      async (url) => ({ bytes: MP4, contentType: 'video/mp4', finalUrl: url })
    )
    const encodedBody = JSON.stringify({ model: 'video-model', prompt: 'archive terminal' })
    const claimed = await service.claim({ path: '/v1/videos/generations', encodedBody })
    await expect(
      service.execute({
        operationId: claimed.operationId,
        path: '/v1/videos/generations',
        encodedBody
      })
    ).resolves.toMatchObject({ ok: true, result: { task_id: taskAlias } })
    await expect(
      capacity.verifyVideoTaskBinding({
        operationId: claimed.operationId,
        taskAliasSha256: createHash('sha256').update(taskAlias).digest('hex')
      })
    ).resolves.toMatchObject({ phase: 'video_bound' })

    const terminal = await service.pollVideo({ taskAlias, model: 'video-model' })
    expect(terminal).toMatchObject({
      task_id: taskAlias,
      data: {
        status: 'completed',
        video_url: expect.stringMatching(/^nachuan-paid-media:\/\/sha256\//)
      }
    })
    expect(JSON.stringify(terminal)).not.toContain('https://cdn.example/final.mp4')
    const terminalArchive = await vault.verifyTerminalMediaForTask(taskAlias)
    expect(terminalArchive).toMatchObject({
      result: terminal
    })
    await expect(
      capacity.verifyVideoTaskBinding({
        operationId: claimed.operationId,
        taskAliasSha256: createHash('sha256').update(taskAlias).digest('hex')
      })
    ).rejects.toThrow(/conflict/i)

    const offlineProbe = vi.fn(async () => {
      throw new Error('probe offline')
    })
    const offlineValidation = vi.fn(async () => {
      throw new Error('validation offline')
    })
    const offlineTransport = vi.fn<PaidMediaTransport>(async () => {
      throw new Error('gateway offline')
    })
    const offlineCapacity = {
      ensureReservation: vi.fn(async () => {
        throw new Error('capacity journal corrupt')
      }),
      bindVideoTask: vi.fn(async () => {
        throw new Error('capacity journal corrupt')
      }),
      verifyVideoTaskBinding: vi.fn(async () => {
        throw new Error('capacity journal corrupt')
      }),
      ensureReleasedWithAuthorization: vi.fn(async () => {
        throw new Error('capacity journal corrupt')
      }),
      listReservations: vi.fn(async () => {
        throw new Error('capacity journal corrupt')
      })
    } as unknown as PaidMediaCapacityManager
    const offlineVault = new PaidMediaVault(join(root, 'vault'), {
      safeStorage: fakeStorage,
      harden: () => undefined,
      now: () => 1_800_000_000_999,
      fetchRemote: vi.fn(async () => {
        throw new Error('remote unavailable')
      }),
      ensureMediaProbeReady: offlineProbe,
      validateMediaAsset: offlineValidation
    })
    const restarted = new PaidMediaService({
      ledger,
      vault: offlineVault,
      capacity: offlineCapacity,
      baseUrl: () => {
        throw new Error('gateway process is unavailable')
      },
      runtimeKey: () => {
        throw new Error('runtime authority unavailable')
      },
      approvalKey: () => {
        throw new Error('approval authority unavailable')
      },
      paidMediaKey: () => {
        throw new Error('paid authority unavailable')
      },
      transport: offlineTransport
    })
    restarted.disableRemoteOperations()

    await expect(restarted.pollVideo({ taskAlias, model: 'video-model' })).resolves.toEqual(
      terminal
    )
    await expect(restarted.pollVideo({ taskAlias, model: 'other-video-model' })).rejects.toThrow(
      /creation model/i
    )
    expect(offlineProbe).not.toHaveBeenCalled()
    expect(offlineValidation).not.toHaveBeenCalled()
    expect(offlineTransport).not.toHaveBeenCalled()
    expect(offlineCapacity.verifyVideoTaskBinding).not.toHaveBeenCalled()
    expect(offlineCapacity.ensureReleasedWithAuthorization).toHaveBeenCalledWith({
      operationId: claimed.operationId,
      authorizationReceiptSha256: terminalArchive.receiptSha256
    })
  })

  it('fails a terminal paid video poll when Main cannot archive the remote asset', async () => {
    const taskAlias = `nvt1_${'c'.repeat(64)}`
    const { service, vault } = fixture(
      async (request) =>
        request.method === 'POST'
          ? {
              status: 202,
              headers: {},
              body: JSON.stringify({ task_id: taskAlias, status: 'queued' })
            }
          : {
              status: 200,
              headers: {},
              body: JSON.stringify({
                task_id: taskAlias,
                status: 'completed',
                video_url: 'https://cdn.example/final.mp4'
              })
            },
      async () => {
        throw new Error('synthetic archive failure')
      }
    )
    const encodedBody = JSON.stringify({ model: 'video-model', prompt: 'fail closed terminal' })
    const claimed = await service.claim({ path: '/v1/videos/generations', encodedBody })
    await service.execute({
      operationId: claimed.operationId,
      path: '/v1/videos/generations',
      encodedBody
    })

    await expect(service.pollVideo({ taskAlias, model: 'video-model' })).rejects.toThrow(
      /archive|fetch/i
    )
    await expect(vault.verifyTerminalMediaForTask(taskAlias)).rejects.toThrow(/missing/i)
  })

  it('holds video capacity through cleanup failure and releases after the pinned retry succeeds', async () => {
    vi.useFakeTimers()
    try {
      const taskAlias = `nvt1_${'6'.repeat(64)}`
      const stagingRoot = mkdtempSync(join(tmpdir(), 'nachuan-paid-media-fetch-'))
      roots.push(stagingRoot)
      const stagingFile = join(stagingRoot, 'asset.bin')
      writeFileSync(stagingFile, MP4)
      let cleanupAttempts = 0
      const item = fixture(
        async (request) =>
          request.method === 'POST'
            ? {
                status: 202,
                headers: {},
                body: JSON.stringify({ task_id: taskAlias, status: 'queued' })
              }
            : {
                status: 200,
                headers: {},
                body: JSON.stringify({
                  task_id: taskAlias,
                  status: 'completed',
                  video_url: 'https://cdn.example/final.mp4'
                })
              },
        async (url) => ({
          filePath: stagingFile,
          byteLength: MP4.byteLength,
          contentType: 'video/mp4',
          finalUrl: url
        }),
        async () => undefined,
        () => 64n * 1024n * 1024n * 1024n,
        {
          unlinkStagedFile: (path) => {
            cleanupAttempts += 1
            if (cleanupAttempts === 1) throw new Error('synthetic cleanup failure')
            unlinkSync(path)
          },
          removeEmptyStagingDirectory: rmdirSync,
          unlinkMarker: unlinkSync
        }
      )
      const encodedBody = JSON.stringify({ model: 'video-model', prompt: 'cleanup hold' })
      const claimed = await item.service.claim({ path: '/v1/videos/generations', encodedBody })
      await item.service.execute({
        operationId: claimed.operationId,
        path: '/v1/videos/generations',
        encodedBody
      })

      await expect(
        item.service.pollVideo({ taskAlias, model: 'video-model' })
      ).resolves.toMatchObject({ status: 'completed' })
      await expect(item.vault.verifyTerminalMediaForTask(taskAlias)).resolves.toMatchObject({
        cleanupComplete: false
      })
      await expect(item.capacity.listReservations()).resolves.toEqual([
        expect.objectContaining({ operationId: claimed.operationId, phase: 'video_bound' })
      ])

      await vi.advanceTimersByTimeAsync(30_000)
      await vi.waitFor(async () => {
        await expect(item.capacity.listReservations()).resolves.toEqual([])
      })
      expect(cleanupAttempts).toBe(2)
    } finally {
      vi.useRealTimers()
    }
  })

  it('singleflights concurrent cleanup recovery and cancels the stale scheduled retry', async () => {
    vi.useFakeTimers()
    try {
      const taskAlias = `nvt1_${'4'.repeat(64)}`
      const stagingRoot = mkdtempSync(join(tmpdir(), 'nachuan-paid-media-fetch-'))
      roots.push(stagingRoot)
      const stagingFile = join(stagingRoot, 'asset.bin')
      writeFileSync(stagingFile, MP4)
      let cleanupAttempts = 0
      const item = cleanupHeldVideoFixture(taskAlias, stagingFile, {
        unlinkStagedFile: (path) => {
          cleanupAttempts += 1
          if (cleanupAttempts === 1) throw new Error('synthetic first cleanup failure')
          unlinkSync(path)
        },
        removeEmptyStagingDirectory: rmdirSync,
        unlinkMarker: unlinkSync
      })
      await archiveCleanupHeldVideo(item, taskAlias)
      expect(cleanupAttempts).toBe(1)

      const [left, right] = await Promise.all([
        item.vault.recoverPendingCleanup(),
        item.vault.recoverPendingCleanup()
      ])
      expect(left).toEqual({ inspected: 1, recovered: 1, held: 0 })
      expect(right).toEqual({ inspected: 1, recovered: 1, held: 0 })
      expect(cleanupAttempts).toBe(2)

      await vi.advanceTimersByTimeAsync(30_000)
      expect(cleanupAttempts).toBe(2)
    } finally {
      vi.useRealTimers()
    }
  })

  it('treats a missing cleanup marker as converged before opening a Root transaction', async () => {
    vi.useFakeTimers()
    try {
      const taskAlias = `nvt1_${'5'.repeat(64)}`
      const stagingRoot = mkdtempSync(join(tmpdir(), 'nachuan-paid-media-fetch-'))
      roots.push(stagingRoot)
      const stagingFile = join(stagingRoot, 'asset.bin')
      writeFileSync(stagingFile, MP4)
      const item = cleanupHeldVideoFixture(taskAlias, stagingFile, {
        unlinkStagedFile: () => {
          throw new Error('synthetic cleanup failure')
        },
        removeEmptyStagingDirectory: rmdirSync,
        unlinkMarker: unlinkSync
      })
      await archiveCleanupHeldVideo(item, taskAlias)
      const cleanupRunner = vi.spyOn(
        item.service as unknown as {
          runMaintenanceTrackedWork: (
            action: () => Promise<unknown>
          ) => Promise<unknown>
        },
        'runMaintenanceTrackedWork'
      )
      const markerDirectory = join(item.root, 'vault', 'cleanup-pending')
      const markerNames = readdirSync(markerDirectory)
      expect(markerNames).toHaveLength(1)
      unlinkSync(join(markerDirectory, markerNames[0]))

      await vi.advanceTimersByTimeAsync(30_000)

      expect(cleanupRunner).not.toHaveBeenCalled()
      expect(existsSync(stagingFile)).toBe(true)
    } finally {
      vi.useRealTimers()
    }
  })

  it('recovers a pinned cleanup marker after restart before releasing video capacity', async () => {
    const taskAlias = `nvt1_${'7'.repeat(64)}`
    const stagingRoot = mkdtempSync(join(tmpdir(), 'nachuan-paid-media-fetch-'))
    roots.push(stagingRoot)
    const stagingFile = join(stagingRoot, 'asset.bin')
    writeFileSync(stagingFile, MP4)
    const item = cleanupHeldVideoFixture(taskAlias, stagingFile, {
      unlinkStagedFile: () => {
        throw new Error('synthetic pre-crash cleanup failure')
      },
      removeEmptyStagingDirectory: rmdirSync,
      unlinkMarker: unlinkSync
    })
    const operationId = await archiveCleanupHeldVideo(item, taskAlias)
    expect(existsSync(stagingFile)).toBe(true)
    await expect(item.capacity.listReservations()).resolves.toEqual([
      expect.objectContaining({ operationId, phase: 'video_bound' })
    ])

    const restarted = restartFixture(item)
    await expect(restarted.service.reconcileCapacityOnStartup()).resolves.toEqual({
      inspected: 1,
      released: 1,
      bound: 0,
      held: 0
    })
    expect(existsSync(stagingRoot)).toBe(false)
    await expect(restarted.capacity.listReservations()).resolves.toEqual([])
    await expect(restarted.vault.verifyTerminalMediaForTask(taskAlias)).resolves.toMatchObject({
      cleanupComplete: true
    })
  })

  it('recovers a marker-only cleanup after restart when marker unlink previously failed', async () => {
    const taskAlias = `nvt1_${'8'.repeat(64)}`
    const stagingRoot = mkdtempSync(join(tmpdir(), 'nachuan-paid-media-fetch-'))
    roots.push(stagingRoot)
    const stagingFile = join(stagingRoot, 'asset.bin')
    writeFileSync(stagingFile, MP4)
    const item = cleanupHeldVideoFixture(taskAlias, stagingFile, {
      unlinkStagedFile: unlinkSync,
      removeEmptyStagingDirectory: rmdirSync,
      unlinkMarker: () => {
        throw new Error('synthetic marker unlink failure')
      }
    })
    const operationId = await archiveCleanupHeldVideo(item, taskAlias)
    expect(existsSync(stagingRoot)).toBe(false)
    await expect(item.capacity.listReservations()).resolves.toEqual([
      expect.objectContaining({ operationId, phase: 'video_bound' })
    ])

    const restarted = restartFixture(item)
    await expect(restarted.service.reconcileCapacityOnStartup()).resolves.toEqual({
      inspected: 1,
      released: 1,
      bound: 0,
      held: 0
    })
    await expect(restarted.capacity.listReservations()).resolves.toEqual([])
    await expect(restarted.vault.verifyTerminalMediaForTask(taskAlias)).resolves.toMatchObject({
      cleanupComplete: true
    })
  })

  it('keeps capacity held when restart cleanup observes staged identity drift', async () => {
    const taskAlias = `nvt1_${'9'.repeat(64)}`
    const stagingRoot = mkdtempSync(join(tmpdir(), 'nachuan-paid-media-fetch-'))
    roots.push(stagingRoot)
    const stagingFile = join(stagingRoot, 'asset.bin')
    writeFileSync(stagingFile, MP4)
    const item = cleanupHeldVideoFixture(taskAlias, stagingFile, {
      unlinkStagedFile: () => {
        throw new Error('synthetic pre-drift cleanup failure')
      },
      removeEmptyStagingDirectory: rmdirSync,
      unlinkMarker: unlinkSync
    })
    const operationId = await archiveCleanupHeldVideo(item, taskAlias)
    unlinkSync(stagingFile)
    writeFileSync(stagingFile, Buffer.concat([MP4, Buffer.from([0])]))
    const cleanupErrors = vi.fn()

    const restarted = restartFixture(item, undefined, cleanupErrors)
    await expect(restarted.service.reconcileCapacityOnStartup()).resolves.toEqual({
      inspected: 1,
      released: 0,
      bound: 0,
      held: 1
    })
    expect(cleanupErrors).toHaveBeenCalled()
    expect(existsSync(stagingFile)).toBe(true)
    await expect(restarted.capacity.listReservations()).resolves.toEqual([
      expect.objectContaining({ operationId, phase: 'video_bound' })
    ])
    await expect(restarted.vault.verifyTerminalMediaForTask(taskAlias)).resolves.toMatchObject({
      cleanupComplete: false
    })
  })

  it('converges an explicit failed status without fetching its stale URL', async () => {
    const taskAlias = `nvt1_${'d'.repeat(64)}`
    const fetchRemote = vi.fn<PaidMediaRemoteFetcher>()
    const { service, vault } = fixture(
      async (request) =>
        request.method === 'POST'
          ? {
              status: 202,
              headers: {},
              body: JSON.stringify({ task_id: taskAlias, status: 'queued' })
            }
          : {
              status: 200,
              headers: {},
              body: JSON.stringify({
                task_id: taskAlias,
                status: 'failed',
                error: 'provider rejected the job',
                video_url: 'https://cdn.example/stale-preview.mp4'
              })
            },
      fetchRemote
    )
    const encodedBody = JSON.stringify({ model: 'video-model', prompt: 'failed task' })
    const claimed = await service.claim({ path: '/v1/videos/generations', encodedBody })
    await service.execute({
      operationId: claimed.operationId,
      path: '/v1/videos/generations',
      encodedBody
    })

    await expect(service.pollVideo({ taskAlias, model: 'video-model' })).resolves.toMatchObject({
      task_id: taskAlias,
      status: 'failed',
      error: 'provider rejected the job'
    })
    expect(fetchRemote).not.toHaveBeenCalled()
    await expect(vault.verifyTerminalMediaForTask(taskAlias)).resolves.toMatchObject({
      result: { status: 'failed' }
    })
    expect((await vault.verifyTerminalMediaForTask(taskAlias)).asset).toBeUndefined()
  })

  it('rejects a request larger than the Gateway 24 MiB contract before claiming', async () => {
    const { service, request } = fixture()
    const encodedBody = JSON.stringify({
      model: 'video-model',
      prompt: 'x'.repeat(24 * 1024 * 1024)
    })

    await expect(
      service.claim({ path: '/v1/videos/generations', encodedBody })
    ).rejects.toThrow(/size limit/i)
    expect(await service.listUnresolved()).toEqual([])
    expect(request).not.toHaveBeenCalled()
  })

  it('binds each claimed operation to its exact request bytes in the Main vault', async () => {
    const { service, vault } = fixture()
    const encodedBody = '{"model":"image-model", "prompt":"preserve exact spaces"}'
    const claimed = await service.claim({ path: '/v1/images/generations', encodedBody })

    await expect(vault.readExactRequest(claimed.operationId)).resolves.toMatchObject({
      operationId: claimed.operationId,
      path: '/v1/images/generations',
      encodedBody
    })
  })

  it('archives a successful JSON body above the old 24 MiB limit before result_ready', async () => {
    const largePng = pngWithAncillaryPadding(PNG, 18 * 1024 * 1024)
    const responseBody = JSON.stringify({ data: [{ b64_json: largePng.toString('base64') }] })
    expect(Buffer.byteLength(responseBody, 'utf8')).toBeGreaterThan(24 * 1024 * 1024)
    const { service, request } = fixture(async () => ({
      status: 200,
      headers: {},
      body: responseBody
    }))
    const encodedBody = JSON.stringify({ model: 'image-model', prompt: 'large response archive' })
    const claimed = await service.claim({ path: '/v1/images/generations', encodedBody })

    const result = await service.execute({
      operationId: claimed.operationId,
      path: '/v1/images/generations',
      encodedBody
    })
    expect(result).toMatchObject({
      ok: true,
      operation: { state: 'result_ready' },
      result: { data: [{ url: expect.stringMatching(/^nachuan-paid-media:\/\/sha256\//) }] }
    })
    expect(request).toHaveBeenCalledTimes(1)
    await expect(service.recoverArchived(claimed.operationId)).resolves.toMatchObject({
      archive: {
        responseByteLength: Buffer.byteLength(responseBody, 'utf8'),
        assets: [{ byteLength: largePng.byteLength }]
      }
    })
  })

  it.each([
    [
      '/v1/images/generations' as const,
      { model: 'image-model', prompt: 'draw', provider_cost_override: 99 }
    ],
    [
      '/v1/videos/generations' as const,
      {
        model: 'video-model',
        prompt: 'film',
        extra_body: { image: ['aGVsbG8='], hidden_provider_option: { credits: 99 } }
      }
    ]
  ])('rejects non-versioned paid parameters before claiming: %s', async (path, body) => {
    const { service, request } = fixture()

    await expect(service.claim({ path, encodedBody: JSON.stringify(body) })).rejects.toThrow(
      /unsupported|field/i
    )
    expect(await service.listUnresolved()).toEqual([])
    expect(request).not.toHaveBeenCalled()
  })

  it('keeps both capabilities and the idempotency key out of public claim/results', async () => {
    const { service, request } = fixture()
    const encodedBody = JSON.stringify({ model: 'image-model', prompt: 'river' })

    const claimed = await service.claim({
      path: '/v1/images/generations',
      encodedBody
    })
    expect(JSON.stringify(claimed)).not.toMatch(/idempotency|requestSha|sk-local|sk-paid/i)
    expect(request).not.toHaveBeenCalled()

    const result = await service.execute({
      operationId: claimed.operationId,
      path: '/v1/images/generations',
      encodedBody
    })
    expect(result.ok).toBe(true)
    expect(JSON.stringify(result)).not.toMatch(/idempotency|requestSha|sk-local|sk-paid/i)

    expect(request).toHaveBeenCalledTimes(1)
    const outbound = request.mock.calls[0][0]
    expect(outbound.headers).toMatchObject({
      Authorization: 'Bearer sk-local-runtime',
      'X-Nachuan-Paid-Media-Key': 'sk-paid-media-independent',
      'Idempotency-Key': expect.stringMatching(/^desktop-[0-9a-f-]{36}$/)
    })
  })

  it('rejects a modified retry body before any transport call', async () => {
    const { service, request } = fixture()
    const claimed = await service.claim({
      path: '/v1/videos/generations',
      encodedBody: JSON.stringify({ model: 'video-model', prompt: 'first' })
    })

    await expect(
      service.execute({
        operationId: claimed.operationId,
        path: '/v1/videos/generations',
        encodedBody: JSON.stringify({ model: 'video-model', prompt: 'changed' })
      })
    ).rejects.toThrow(/match/i)
    expect(request).not.toHaveBeenCalled()
  })

  it('reuses one internal idempotency key after an unknown transport outcome', async () => {
    let attempts = 0
    const { service, request } = fixture(async () => {
      attempts += 1
      if (attempts === 1) throw new TypeError('socket reset')
      return {
        status: 200,
        headers: {},
        body: JSON.stringify({ id: 'video-task-1', status: 'queued' })
      }
    })
    const encodedBody = JSON.stringify({ model: 'video-model', prompt: 'safe retry' })
    const claimed = await service.claim({
      path: '/v1/videos/generations',
      encodedBody
    })

    const unknown = await service.execute({
      operationId: claimed.operationId,
      path: '/v1/videos/generations',
      encodedBody
    })
    expect(unknown).toMatchObject({ ok: false, status: 0, recoverable: true })

    const retried = await service.execute({
      operationId: claimed.operationId,
      path: '/v1/videos/generations',
      encodedBody
    })
    expect(retried.ok).toBe(true)
    expect(request).toHaveBeenCalledTimes(2)
    expect(request.mock.calls[1][0].headers['Idempotency-Key']).toBe(
      request.mock.calls[0][0].headers['Idempotency-Key']
    )
  })

  it('fails closed after restart when dispatching has no durable archive', async () => {
    const item = fixture()
    const encodedBody = JSON.stringify({ model: 'image-model', prompt: 'crash after dispatch fence' })
    const claimed = await item.service.claim({
      path: '/v1/images/generations',
      encodedBody
    })
    await item.ledger.markDispatching(claimed.operationId)

    await expect(
      item.service.execute({
        operationId: claimed.operationId,
        path: '/v1/images/generations',
        encodedBody
      })
    ).rejects.toThrow(/dispatch outcome is unknown; manual recovery is required/)
    expect(item.request).not.toHaveBeenCalled()
    await expect(item.ledger.listPublic()).resolves.toEqual([
      expect.objectContaining({
        operationId: claimed.operationId,
        state: 'dispatching',
        dispatchCount: 1
      })
    ])
  })

  it('fails closed before claiming when the paid capability overlaps another authority', async () => {
    const { service, request } = fixture()
    const unsafe = service.withAuthorities({
      runtimeKey: () => 'same-key',
      approvalKey: () => 'sk-approval-independent',
      paidMediaKey: () => 'same-key'
    })
    const encodedBody = JSON.stringify({ model: 'image-model', prompt: 'no dispatch' })
    await expect(
      unsafe.claim({ path: '/v1/images/generations', encodedBody })
    ).rejects.toBeInstanceOf(PaidMediaServiceError)
    expect(request).not.toHaveBeenCalled()
  })

  it('rejects a retry after paid capability rotation before any transport call', async () => {
    const { service, request } = fixture()
    const encodedBody = JSON.stringify({ model: 'image-model', prompt: 'stable domain' })
    const claimed = await service.claim({ path: '/v1/images/generations', encodedBody })
    const rotated = service.withAuthorities({
      runtimeKey: () => 'sk-local-runtime',
      approvalKey: () => 'sk-approval-independent',
      paidMediaKey: () => 'sk-paid-media-rotated'
    })

    await expect(
      rotated.execute({
        operationId: claimed.operationId,
        path: '/v1/images/generations',
        encodedBody
      })
    ).rejects.toThrow(/recovery domain|match/i)
    expect(request).not.toHaveBeenCalled()
  })

  it('allows runtime Bearer rotation because recovery is bound only to the paid capability', async () => {
    const { service, request } = fixture()
    const encodedBody = JSON.stringify({ model: 'image-model', prompt: 'runtime rotation' })
    const claimed = await service.claim({ path: '/v1/images/generations', encodedBody })
    const rotatedRuntime = service.withAuthorities({
      runtimeKey: () => 'sk-local-runtime-rotated',
      approvalKey: () => 'sk-approval-independent',
      paidMediaKey: () => 'sk-paid-media-independent'
    })

    await expect(
      rotatedRuntime.execute({
        operationId: claimed.operationId,
        path: '/v1/images/generations',
        encodedBody
      })
    ).resolves.toMatchObject({ ok: true })
    expect(request.mock.calls[0][0].headers.Authorization).toBe(
      'Bearer sk-local-runtime-rotated'
    )
  })

  it('keeps a success unresolved until the renderer acknowledges durable delivery', async () => {
    const { service } = fixture()
    const encodedBody = JSON.stringify({ model: 'image-model', prompt: 'receipt' })
    const claimed = await service.claim({ path: '/v1/images/generations', encodedBody })
    const result = await service.execute({
      operationId: claimed.operationId,
      path: '/v1/images/generations',
      encodedBody
    })
    expect(result).toMatchObject({ ok: true, operation: { state: 'result_ready' } })
    expect(await service.listUnresolved()).toHaveLength(1)

    if (!result.ok) throw new Error('expected paid media success')
    await service.acknowledgeDelivered(result.deliveryProof)
    expect(await service.listUnresolved()).toEqual([])
  })

  it('requires the exact Main archive proof before clearing a durable result', async () => {
    const { service } = fixture()
    const encodedBody = JSON.stringify({ model: 'image-model', prompt: 'proof-bound delivery' })
    const claimed = await service.claim({ path: '/v1/images/generations', encodedBody })
    const result = await service.execute({
      operationId: claimed.operationId,
      path: '/v1/images/generations',
      encodedBody
    })

    expect(result).toMatchObject({
      ok: true,
      operation: { state: 'result_ready' },
      deliveryProof: {
        operationId: claimed.operationId,
        resultSha256: expect.stringMatching(/^[0-9a-f]{64}$/),
        archiveReceiptSha256: expect.stringMatching(/^[0-9a-f]{64}$/)
      }
    })
    if (!result.ok) throw new Error('expected paid media success')

    await expect(
      service.acknowledgeDelivered({
        ...result.deliveryProof,
        archiveReceiptSha256: 'f'.repeat(64)
      })
    ).rejects.toThrow(/archive proof|archive receipt|does not match/i)
    await expect(service.listUnresolved()).resolves.toEqual([
      expect.objectContaining({ operationId: claimed.operationId, state: 'result_ready' })
    ])

    await expect(service.acknowledgeDelivered(result.deliveryProof)).resolves.toMatchObject({
      operationId: claimed.operationId,
      state: 'delivered'
    })
    await expect(service.listUnresolved()).resolves.toEqual([])
  })

  it('retains the replay body when a caller supplies only a bare operation id', async () => {
    const { service, request } = fixture()
    const encodedBody = JSON.stringify({ model: 'image-model', prompt: 'reject bare ack' })
    const claimed = await service.claim({ path: '/v1/images/generations', encodedBody })
    const first = await service.execute({
      operationId: claimed.operationId,
      path: '/v1/images/generations',
      encodedBody
    })
    expect(first).toMatchObject({ ok: true, operation: { state: 'result_ready' } })

    await expect(
      service.acknowledgeDelivered(claimed.operationId as never)
    ).rejects.toThrow(/delivery proof is invalid/i)
    await expect(service.listUnresolved()).resolves.toEqual([
      expect.objectContaining({ operationId: claimed.operationId, state: 'result_ready' })
    ])

    const replayed = await service.execute({
      operationId: claimed.operationId,
      path: '/v1/images/generations',
      encodedBody
    })
    expect(replayed).toEqual(first)
    expect(request).toHaveBeenCalledTimes(1)
  })

  it('rejects a proof-bound acknowledgement when Main can no longer verify its archive', async () => {
    const { root, service } = fixture()
    const encodedBody = JSON.stringify({ model: 'image-model', prompt: 'must survive renderer ack' })
    const claimed = await service.claim({ path: '/v1/images/generations', encodedBody })
    const result = await service.execute({
      operationId: claimed.operationId,
      path: '/v1/images/generations',
      encodedBody
    })
    expect(result).toMatchObject({ ok: true, operation: { state: 'result_ready' } })
    if (!result.ok) throw new Error('expected paid media success')
    rmSync(join(root, 'vault', 'archives', `${claimed.operationId}.json`), { force: true })

    await expect(service.acknowledgeDelivered(result.deliveryProof)).rejects.toThrow(/archive receipt/i)
    await expect(service.listUnresolved()).resolves.toEqual([
      expect.objectContaining({ operationId: claimed.operationId, state: 'result_ready' })
    ])
  })

  it('replays the encrypted main result after renderer persistence fails without a second dispatch', async () => {
    const responseBody = JSON.stringify({ created: 7, data: [{ url: 'https://invalid/replayed.png' }] })
    const { service, request } = fixture(async () => ({
      status: 201,
      headers: {},
      body: responseBody
    }))
    const encodedBody = JSON.stringify({ model: 'image-model', prompt: 'renderer flush fails' })
    const claimed = await service.claim({ path: '/v1/images/generations', encodedBody })

    const first = await service.execute({
      operationId: claimed.operationId,
      path: '/v1/images/generations',
      encodedBody
    })
    // Simulate onResultDurablyCommitted rejecting: no acknowledgeDelivered call.
    const replayed = await service.execute({
      operationId: claimed.operationId,
      path: '/v1/images/generations',
      encodedBody
    })

    expect(first).toMatchObject({
      ok: true,
      status: 201,
      result: { data: [{ url: expect.stringMatching(/^nachuan-paid-media:\/\/sha256\//) }] }
    })
    expect(replayed).toEqual(first)
    expect(request).toHaveBeenCalledTimes(1)
  })

  it('replays result-ready data after restart even when the gateway transport is unavailable', async () => {
    const responseBody = JSON.stringify({ id: 'video-task-local', status: 'queued' })
    const { service, ledger, vault, capacity } = fixture(async () => ({ status: 202, headers: {}, body: responseBody }))
    const encodedBody = JSON.stringify({ model: 'video-model', prompt: 'gateway disappears' })
    const claimed = await service.claim({ path: '/v1/videos/generations', encodedBody })
    await service.execute({
      operationId: claimed.operationId,
      path: '/v1/videos/generations',
      encodedBody
    })
    const unavailable = vi.fn<PaidMediaTransport>(async () => {
      throw new TypeError('gateway is offline')
    })
    const restarted = new PaidMediaService({
      ledger,
      vault,
      capacity,
      baseUrl: () => {
        throw new Error('gateway process is unavailable')
      },
      runtimeKey: () => 'sk-local-runtime',
      approvalKey: () => 'sk-approval-independent',
      paidMediaKey: () => 'sk-paid-media-independent',
      transport: unavailable
    })

    await expect(
      restarted.execute({
        operationId: claimed.operationId,
        path: '/v1/videos/generations',
        encodedBody
      })
    ).resolves.toMatchObject({ ok: true, status: 202, result: JSON.parse(responseBody) })
    expect(unavailable).not.toHaveBeenCalled()
  })

  it('blocks a fresh dispatch before transport when the trusted probe becomes unavailable', async () => {
    let ready = true
    const ensureReady = vi.fn(async () => {
      if (!ready) throw new Error('probe offline')
    })
    const { service, request } = fixture(undefined, undefined, ensureReady)
    const encodedBody = JSON.stringify({ model: 'image-model', prompt: 'fail before dispatch' })
    const claimed = await service.claim({ path: '/v1/images/generations', encodedBody })
    ready = false

    await expect(
      service.execute({
        operationId: claimed.operationId,
        path: '/v1/images/generations',
        encodedBody
      })
    ).rejects.toThrow(/probe/i)
    expect(request).not.toHaveBeenCalled()
    await expect(service.listUnresolved()).resolves.toEqual([
      expect.objectContaining({ operationId: claimed.operationId, state: 'claimed', dispatchCount: 0 })
    ])
  })

  it('blocks a fresh dispatch before transport when its durable capacity hold cannot be admitted', async () => {
    const { service, request } = fixture(
      undefined,
      undefined,
      async () => undefined,
      () => 0n
    )
    const encodedBody = JSON.stringify({ model: 'image-model', prompt: 'no disk budget' })
    const claimed = await service.claim({ path: '/v1/images/generations', encodedBody })

    await expect(
      service.execute({
        operationId: claimed.operationId,
        path: '/v1/images/generations',
        encodedBody
      })
    ).rejects.toThrow(/capacity|insufficient/i)
    expect(request).not.toHaveBeenCalled()
    await expect(service.listUnresolved()).resolves.toEqual([
      expect.objectContaining({
        operationId: claimed.operationId,
        state: 'claimed',
        dispatchCount: 0
      })
    ])
  })

  it('releases an image hold only after its archive and result-ready receipt commit', async () => {
    const { service, request, capacity } = fixture()
    const encodedBody = JSON.stringify({ model: 'image-model', prompt: 'release image hold' })
    const claimed = await service.claim({ path: '/v1/images/generations', encodedBody })

    await expect(
      service.execute({
        operationId: claimed.operationId,
        path: '/v1/images/generations',
        encodedBody
      })
    ).resolves.toMatchObject({ ok: true, operation: { state: 'result_ready' } })
    expect(request).toHaveBeenCalledTimes(1)
    await expect(capacity.listReservations()).resolves.toEqual([])
  })

  it('retries a failed image release during durable local replay without another transport', async () => {
    const { service, request, capacity } = fixture()
    const encodedBody = JSON.stringify({ model: 'image-model', prompt: 'retry release' })
    const claimed = await service.claim({ path: '/v1/images/generations', encodedBody })
    const originalRelease = capacity.ensureReleasedWithAuthorization.bind(capacity)
    const release = vi
      .spyOn(capacity, 'ensureReleasedWithAuthorization')
      .mockRejectedValueOnce(new Error('synthetic release commit failure'))
      .mockImplementation(originalRelease)

    await expect(
      service.execute({
        operationId: claimed.operationId,
        path: '/v1/images/generations',
        encodedBody
      })
    ).rejects.toThrow(/synthetic release/i)
    await expect(
      service.execute({
        operationId: claimed.operationId,
        path: '/v1/images/generations',
        encodedBody
      })
    ).resolves.toMatchObject({ ok: true, operation: { state: 'result_ready' } })
    expect(request).toHaveBeenCalledTimes(1)
    expect(release).toHaveBeenCalledTimes(2)
    await expect(capacity.listReservations()).resolves.toEqual([])
  })

  it('finishes a pre-existing dispatch archive without requiring the probe or gateway', async () => {
    let ready = true
    const ensureReady = vi.fn(async () => {
      if (!ready) throw new Error('probe offline')
    })
    const { service, ledger, vault, request } = fixture(undefined, undefined, ensureReady)
    const encodedBody = JSON.stringify({ model: 'image-model', prompt: 'commit archived result' })
    const claimed = await service.claim({ path: '/v1/images/generations', encodedBody })
    await ledger.markDispatching(claimed.operationId)
    const archived = await vault.archiveResult({
      operationId: claimed.operationId,
      path: '/v1/images/generations',
      status: 200,
      responseJson: JSON.stringify({ data: [{ b64_json: PNG.toString('base64') }] })
    })
    ready = false

    await expect(
      service.execute({
        operationId: claimed.operationId,
        path: '/v1/images/generations',
        encodedBody
      })
    ).resolves.toMatchObject({
      ok: true,
      status: 200,
      result: archived.result,
      operation: { state: 'result_ready' }
    })
    expect(request).not.toHaveBeenCalled()
  })

  it('reconciles a verified startup image archive without issuing transport', async () => {
    const { service, ledger, vault, capacity, request } = fixture()
    const encodedBody = JSON.stringify({ model: 'image-model', prompt: 'startup reconcile' })
    const claimed = await service.claim({ path: '/v1/images/generations', encodedBody })
    await capacity.ensureReservation({
      operationId: claimed.operationId,
      path: '/v1/images/generations',
      allowCreate: true
    })
    await ledger.markDispatching(claimed.operationId)
    await vault.archiveResult({
      operationId: claimed.operationId,
      path: '/v1/images/generations',
      status: 200,
      responseJson: JSON.stringify({ data: [{ b64_json: PNG.toString('base64') }] })
    })

    await expect(service.reconcileCapacityOnStartup()).resolves.toEqual({
      inspected: 1,
      released: 1,
      bound: 0,
      held: 0
    })
    expect(request).not.toHaveBeenCalled()
    await expect(capacity.listReservations()).resolves.toEqual([])
    await expect(
      service.execute({
        operationId: claimed.operationId,
        path: '/v1/images/generations',
        encodedBody
      })
    ).resolves.toMatchObject({ ok: true, operation: { state: 'result_ready' } })
    expect(request).not.toHaveBeenCalled()
  })

  it('releases a verified terminal video at startup but holds an unknown dispatch', async () => {
    const taskAlias = `nvt1_${'7'.repeat(64)}`
    const terminalFixture = fixture(async () => ({
      status: 202,
      headers: {},
      body: JSON.stringify({ task_id: taskAlias, status: 'queued' })
    }))
    const encodedBody = JSON.stringify({ model: 'video-model', prompt: 'startup terminal' })
    const claimed = await terminalFixture.service.claim({
      path: '/v1/videos/generations',
      encodedBody
    })
    await terminalFixture.service.execute({
      operationId: claimed.operationId,
      path: '/v1/videos/generations',
      encodedBody
    })
    await terminalFixture.vault.archiveTerminalMediaForTask(taskAlias, {
      task_id: taskAlias,
      status: 'failed',
      error: 'provider rejected the job'
    })

    await expect(terminalFixture.service.reconcileCapacityOnStartup()).resolves.toEqual({
      inspected: 1,
      released: 1,
      bound: 0,
      held: 0
    })
    await expect(terminalFixture.capacity.listReservations()).resolves.toEqual([])

    const unknownFixture = fixture()
    const unknownBody = JSON.stringify({ model: 'video-model', prompt: 'unknown dispatch' })
    const unknown = await unknownFixture.service.claim({
      path: '/v1/videos/generations',
      encodedBody: unknownBody
    })
    await unknownFixture.capacity.ensureReservation({
      operationId: unknown.operationId,
      path: '/v1/videos/generations',
      allowCreate: true
    })
    await unknownFixture.ledger.markDispatching(unknown.operationId)
    await unknownFixture.ledger.markRecoverable({ operationId: unknown.operationId, status: 0 })

    await expect(unknownFixture.service.reconcileCapacityOnStartup()).resolves.toEqual({
      inspected: 1,
      released: 0,
      bound: 0,
      held: 1
    })
    await expect(unknownFixture.capacity.listReservations()).resolves.toEqual([
      expect.objectContaining({ operationId: unknown.operationId, phase: 'active' })
    ])
  })

  it('keeps a successful response over the gateway durable 24 MiB limit recoverable', async () => {
    const { service } = fixture(async () => ({
      status: 200,
      headers: {},
      body: JSON.stringify({ data: 'x'.repeat(24 * 1024 * 1024) })
    }))
    const encodedBody = JSON.stringify({ model: 'image-model', prompt: 'oversized response' })
    const claimed = await service.claim({ path: '/v1/images/generations', encodedBody })

    await expect(
      service.execute({
        operationId: claimed.operationId,
        path: '/v1/images/generations',
        encodedBody
      })
    ).resolves.toMatchObject({
      ok: false,
      status: 200,
      recoverable: true,
      operation: { state: 'recoverable' }
    })
  })

  it('rechecks capacity after transport and holds the reservation when disk space changed', async () => {
    let free = 64n * 1024n * 1024n * 1024n
    const item = fixture(
      async () => {
        free = 0n
        return {
          status: 200,
          headers: {},
          body: JSON.stringify({ data: [{ b64_json: PNG.toString('base64') }] })
        }
      },
      undefined,
      async () => undefined,
      () => free
    )
    const encodedBody = JSON.stringify({ model: 'image-model', prompt: 'stage recheck' })
    const claimed = await item.service.claim({ path: '/v1/images/generations', encodedBody })

    await expect(
      item.service.execute({
        operationId: claimed.operationId,
        path: '/v1/images/generations',
        encodedBody
      })
    ).resolves.toMatchObject({
      ok: false,
      recoverable: true,
      detail: 'Paid media success could not be safely archived'
    })
    expect(item.request).toHaveBeenCalledTimes(1)
    expect(item.vault.hasArchive(claimed.operationId)).toBe(false)
    await expect(item.capacity.listReservations()).resolves.toEqual([
      expect.objectContaining({ operationId: claimed.operationId, phase: 'active' })
    ])
  })

  it('can abandon only a never-dispatched claim without erasing its tombstone', async () => {
    const { service, request, capacity } = fixture()
    const encodedBody = JSON.stringify({ model: 'image-model', prompt: 'anchor failed' })
    const claimed = await service.claim({ path: '/v1/images/generations', encodedBody })
    await capacity.ensureReservation({
      operationId: claimed.operationId,
      path: '/v1/images/generations',
      allowCreate: true
    })

    const reconciled = await service.abandonUndispatchedClaim(
      claimed.operationId,
      'renderer recovery anchor failed before dispatch'
    )
    expect(reconciled).toMatchObject({ state: 'reconciled', dispatchCount: 0 })
    expect(await service.listUnresolved()).toEqual([])
    await expect(capacity.listReservations()).resolves.toEqual([])
    expect(request).not.toHaveBeenCalled()

    await expect(
      service.abandonUndispatchedClaim(claimed.operationId, 'second attempt')
    ).rejects.toThrow(/never-dispatched/i)
  })

  it('records bounded manual reconciliation evidence instead of deleting history', async () => {
    const { service, capacity } = fixture()
    const encodedBody = JSON.stringify({ model: 'video-model', prompt: 'manual check' })
    const claimed = await service.claim({ path: '/v1/videos/generations', encodedBody })
    await capacity.ensureReservation({
      operationId: claimed.operationId,
      path: '/v1/videos/generations',
      allowCreate: true
    })

    const reconciled = await service.reconcileManually({
      operationId: claimed.operationId,
      reason: 'provider-console-checked',
      evidence: 'invoice-2026-07-16: no duplicate charge'
    })
    expect(reconciled).toMatchObject({
      state: 'reconciled',
      reconciliation: {
        reason: 'provider-console-checked',
        evidence: 'invoice-2026-07-16: no duplicate charge'
      }
    })
    expect(await service.listUnresolved()).toEqual([])
    await expect(capacity.listReservations()).resolves.toEqual([])
  })

  it('turns renderer cancellation into an unknown recoverable outcome', async () => {
    let transportStarted!: () => void
    const started = new Promise<void>((resolve) => {
      transportStarted = resolve
    })
    const { service, capacity } = fixture(
      (request) =>
        new Promise((_resolve, reject) => {
          transportStarted()
          request.signal.addEventListener(
            'abort',
            () => reject(new DOMException('aborted', 'AbortError')),
            { once: true }
          )
        })
    )
    const encodedBody = JSON.stringify({ model: 'video-model', prompt: 'cancel safely' })
    const claimed = await service.claim({ path: '/v1/videos/generations', encodedBody })
    const executing = service.execute({
      operationId: claimed.operationId,
      path: '/v1/videos/generations',
      encodedBody
    })
    await started

    expect(service.cancel(claimed.operationId)).toBe(true)
    await expect(executing).resolves.toMatchObject({
      ok: false,
      status: 0,
      recoverable: true
    })
    await expect(
      capacity.ensureReservation({
        operationId: claimed.operationId,
        path: '/v1/videos/generations',
        allowCreate: false
      })
    ).resolves.toMatchObject({ phase: 'active' })
    expect(service.cancel(claimed.operationId)).toBe(false)
  })

  it('does not lose cancellation while the ledger retry claim is still awaiting', async () => {
    const { service, ledger, request, capacity } = fixture()
    const encodedBody = JSON.stringify({ model: 'video-model', prompt: 'cancel before controller' })
    const claimed = await service.claim({ path: '/v1/videos/generations', encodedBody })
    const originalClaim = ledger.claim.bind(ledger)
    let releaseClaim!: () => void
    const claimReleased = new Promise<void>((resolve) => {
      releaseClaim = resolve
    })
    let claimEntered!: () => void
    const entered = new Promise<void>((resolve) => {
      claimEntered = resolve
    })
    vi.spyOn(ledger, 'claim').mockImplementationOnce(async (input) => {
      claimEntered()
      await claimReleased
      return originalClaim(input)
    })

    const executing = service.execute({
      operationId: claimed.operationId,
      path: '/v1/videos/generations',
      encodedBody
    })
    await entered
    expect(service.cancel(claimed.operationId)).toBe(true)
    releaseClaim()

    await expect(executing).resolves.toMatchObject({
      ok: false,
      status: 0,
      recoverable: true,
      operation: { state: 'claimed', dispatchCount: 0 }
    })
    expect(request).not.toHaveBeenCalled()
    await expect(capacity.listReservations()).resolves.toEqual([])
  })

  it('keeps the hold when cancellation lands after dispatching but before transport', async () => {
    const { service, ledger, request, capacity } = fixture()
    const encodedBody = JSON.stringify({ model: 'video-model', prompt: 'cancel dispatch gap' })
    const claimed = await service.claim({ path: '/v1/videos/generations', encodedBody })
    const originalMarkDispatching = ledger.markDispatching.bind(ledger)
    vi.spyOn(ledger, 'markDispatching').mockImplementationOnce(async (operationId) => {
      const operation = await originalMarkDispatching(operationId)
      expect(service.cancel(operationId)).toBe(true)
      return operation
    })

    await expect(
      service.execute({
        operationId: claimed.operationId,
        path: '/v1/videos/generations',
        encodedBody
      })
    ).resolves.toMatchObject({
      ok: false,
      recoverable: true,
      operation: { state: 'recoverable', dispatchCount: 1 }
    })
    expect(request).not.toHaveBeenCalled()
    await expect(
      capacity.ensureReservation({
        operationId: claimed.operationId,
        path: '/v1/videos/generations',
        allowCreate: false
      })
    ).resolves.toMatchObject({ phase: 'active' })
  })

  it.each([402, 422])(
    'keeps HTTP %i provider outcomes recoverable instead of auto-reconciling them',
    async (status) => {
      const { service, request } = fixture(async () => ({
        status,
        headers: {},
        body: JSON.stringify({ error: 'provider outcome intentionally ambiguous' })
      }))
      const encodedBody = JSON.stringify({ model: 'image-model', prompt: `ambiguous-${status}` })
      const claimed = await service.claim({ path: '/v1/images/generations', encodedBody })

      await expect(
        service.execute({
          operationId: claimed.operationId,
          path: '/v1/images/generations',
          encodedBody
        })
      ).resolves.toMatchObject({
        ok: false,
        status,
        recoverable: true,
        operation: { state: 'recoverable', lastStatus: status }
      })
      expect(request).toHaveBeenCalledTimes(1)
      expect(await service.listUnresolved()).toHaveLength(1)
    }
  )

  it('imports a legacy unresolved record without accepting its secret key', async () => {
    const { service } = fixture()
    const imported = await service.importLegacyUnresolved({
      operationId: `desktop-op-${UUID_ONE}`,
      path: '/v1/images/generations',
      requestSha256: 'a'.repeat(64),
      createdAt: 1_750_000_000_000,
      updatedAt: 1_750_000_000_010,
      state: 'recoverable',
      lastStatus: 503,
      retryAfterSeconds: 3
    })

    expect(imported).toMatchObject({
      operationId: `desktop-op-${UUID_ONE}`,
      state: 'recoverable',
      dispatchCount: 1
    })
    expect(JSON.stringify(imported)).not.toMatch(/idempotency|requestSha/i)
    await expect(service.listUnresolved()).resolves.toEqual([imported])
  })

  it('seals asset-v2 intents and enters the recoverable Root instead of the legacy mutation path', async () => {
    const item = fixture()
    const legacyKinds: string[] = []
    const recoverableInputs: unknown[] = []
    let evidenceReader: (() => Promise<unknown> | unknown) | null = null
    let activeTransaction: string | null = null
    let authorityState: PaidMediaInstallationAuthority['state'] = {
      mode: 'detached',
      reasonCode: 'test-detached'
    }
    const installationRoot = {
      get state() {
        return authorityState
      },
      attachEvidenceReader(reader: () => Promise<unknown> | unknown) {
        evidenceReader = reader
      },
      async provision() {
        await evidenceReader?.()
        authorityState = { mode: 'ready', reasonCode: 'test-ready' }
        return authorityState
      },
      async reconcileStartup() {
        await evidenceReader?.()
        authorityState = { mode: 'ready', reasonCode: 'test-ready' }
        return authorityState
      },
      localPaidPrincipal: () => 'a'.repeat(64),
      assertMutationContext(transactionId?: string) {
        if (transactionId === undefined || transactionId !== activeTransaction) {
          throw new Error('outside composite Root')
        }
      },
      async assertOutboundReady() {
        return authorityState
      },
      async runMutation<T>(
        input: PaidMediaAuthorityMutationInput,
        action: (context: PaidMediaAuthorityMutationContext) => Promise<T>
      ): Promise<T> {
        legacyKinds.push(input.kind)
        activeTransaction = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
        try {
          const result = await action({
            transactionId: activeTransaction,
            assertOutboundReady: async () => undefined
          })
          await evidenceReader?.()
          return result
        } finally {
          activeTransaction = null
        }
      },
      async runRecoverableMutation(input: unknown) {
        recoverableInputs.push(input)
        return authorityState
      }
    }
    const prepare = vi.fn(async (payload: Record<string, unknown>) => ({
      handlerVersion: PAID_MEDIA_RECOVERABLE_HANDLER_VERSION,
      kind: payload.kind,
      operationId: payload.operationId,
      intentSha256: 'c'.repeat(64)
    }))
    const assetV2 = {
      isReady: () => true,
      executeImage: vi.fn(async (input: PaidMediaAssetV2ExecutionInput) => {
        await input.runRecoverableMutation({
          kind: 'asset_v2_dispatch',
          operationId: input.operationId,
          claim: {
            path: '/v1/images/generations',
            requestSha256: input.requestSha256,
            recoveryDomainSha256: input.recoveryDomainSha256
          },
          paidPrincipalSha256: input.recoveryDomainSha256
        })
        const operation = (await item.ledger.listPublic()).find(
          (candidate) => candidate.operationId === input.operationId
        )!
        return {
          ok: false as const,
          status: 503,
          detail: 'test stop after rooted dispatch',
          operation
        }
      })
    }
    const service = new PaidMediaService({
      ledger: item.ledger,
      vault: item.vault,
      capacity: item.capacity,
      baseUrl: () => 'http://127.0.0.1:19001',
      runtimeKey: () => 'sk-local-runtime',
      approvalKey: () => 'sk-approval-independent',
      paidMediaKey: () => 'sk-paid-media-independent',
      transport: async () => {
        throw new Error('asset-v2 wiring test must not call legacy transport')
      },
      installationRoot,
      legacySeal: {
        inspect: async () => ({
          state: 'closed' as const,
          closedAt: 1,
          decision: { kind: 'empty' as const, decisionSha256: 'b'.repeat(64) }
        }),
        close: async () => ({
          state: 'closed' as const,
          closedAt: 1,
          decision: { kind: 'empty' as const, decisionSha256: 'b'.repeat(64) }
        })
      },
      recoveryIntentStore: { prepare },
      assetV2
    } as never)
    await service.initializeInstallationAuthority({
      provision: true,
      provisionLocalState: true
    })
    const encodedBody = JSON.stringify({ model: 'image-model', prompt: 'recoverable wiring' })
    const claimed = await service.claim({ path: '/v1/images/generations', encodedBody })

    await expect(
      service.execute({
        operationId: claimed.operationId,
        path: '/v1/images/generations',
        encodedBody
      })
    ).resolves.toMatchObject({ ok: false, status: 503, recoverable: true })

    expect(prepare).toHaveBeenCalledTimes(1)
    expect(recoverableInputs).toEqual([
      {
        handlerVersion: PAID_MEDIA_RECOVERABLE_HANDLER_VERSION,
        kind: 'asset_v2_dispatch',
        operationId: claimed.operationId,
        intentSha256: 'c'.repeat(64)
      }
    ])
    expect(legacyKinds).not.toContain('asset_v2_dispatch')
  })

  it('routes a same-operation v2 result replay into ACK convergence without provider execution', async () => {
    const item = fixture()
    const encodedBody = JSON.stringify({ model: 'image-model', prompt: 'ACK replay only' })
    const requestSha256 = createHash('sha256').update(encodedBody, 'utf8').digest('hex')
    const recoveryDomainSha256 = createHash('sha256')
      .update('nachuan:paid-media:recovery-domain:v1\0', 'utf8')
      .update('sk-paid-media-independent', 'utf8')
      .digest('hex')
    const dispatchReceiptSha256 = 'b'.repeat(64)
    const ackIntentReceiptSha256 = 'c'.repeat(64)
    const claimed = await item.ledger.claim({
      path: '/v1/images/generations',
      requestSha256,
      recoveryDomainSha256
    })
    await item.ledger.ensureV2DispatchingOnce({
      operationId: claimed.operation.operationId,
      path: '/v1/images/generations',
      requestSha256,
      recoveryDomainSha256,
      dispatchReceiptSha256
    })
    const recoveryJson = JSON.stringify({
      data: [{ url: 'nachuan-paid-media://sha256/archive' }],
      created: 1_784_200_000
    })
    await item.ledger.ensureV2ResultReadyOnce({
      operationId: claimed.operation.operationId,
      dispatchReceiptSha256,
      ackIntentReceiptSha256,
      status: 200,
      responseJson: recoveryJson
    })
    const convergeImageAck = vi.fn(async () => true)
    const executeImage = vi.fn(async () => {
      throw new Error('same-operation result replay must not execute the provider path')
    })
    const verifyExactRequest = vi.fn(async () => ({
      operationId: claimed.operation.operationId,
      path: '/v1/images/generations' as const,
      requestSha256,
      encodedBody
    }))
    const verifyArchive = vi.fn(async () => ({
      receipt: {
        operationId: claimed.operation.operationId,
        status: 200,
        recoverySha256: createHash('sha256').update(recoveryJson, 'utf8').digest('hex'),
        receiptSha256: 'd'.repeat(64),
        kind: 'image' as const
      },
      recoveryJson,
      result: { data: [{ url: 'nachuan-paid-media://sha256/archive' }] },
      cleanupComplete: true
    }))
    const service = new PaidMediaService({
      ledger: item.ledger,
      vault: {
        verifyExactRequest,
        verifyArchive,
        setCleanupRecoveredHandler: vi.fn()
      } as unknown as PaidMediaVault,
      capacity: item.capacity,
      baseUrl: () => 'http://127.0.0.1:19001',
      runtimeKey: () => 'sk-local-runtime',
      approvalKey: () => 'sk-approval-independent',
      paidMediaKey: () => 'sk-paid-media-independent',
      transport: async () => {
        throw new Error('same-operation result replay must not call legacy transport')
      },
      assetV2: {
        isReady: () => true,
        executeImage,
        convergeImageAck
      }
    })

    await expect(
      service.execute({
        operationId: claimed.operation.operationId,
        path: '/v1/images/generations',
        encodedBody
      })
    ).resolves.toMatchObject({
      ok: true,
      operation: {
        operationId: claimed.operation.operationId,
        state: 'result_ready'
      }
    })
    expect(convergeImageAck).toHaveBeenCalledOnce()
    expect(convergeImageAck).toHaveBeenCalledWith(
      expect.objectContaining({ operationId: claimed.operation.operationId })
    )
    expect(executeImage).not.toHaveBeenCalled()
    expect(verifyExactRequest).toHaveBeenCalledOnce()
    expect(verifyArchive).toHaveBeenCalledOnce()
  })
})

describe('PaidMediaService maintenance drain', { timeout: 120_000 }, () => {
  it('freezes an idle service, rejects new ingress, and resumes only by explicit release', async () => {
    const item = fixture()

    const evidence = await item.service.enterMaintenanceDrain()

    expect(Object.isFrozen(evidence)).toBe(true)
    expect(evidence).toMatchObject({
      schema: 'nachuan.paid-media-service-quiescence.v1',
      scope: 'desktop-main-paid-media-service',
      drainGeneration: 1,
      acceptedSequence: 0,
      completedSequence: 0,
      activeWorkCount: 0,
      operationMutexCount: 0,
      activeRequestCount: 0,
      executingOperationCount: 0,
      pendingCancellationCount: 0,
      legacyBootstrapIdle: true,
      evidenceSha256: expect.stringMatching(/^[0-9a-f]{64}$/)
    })
    expect(item.service.inspectMaintenanceDrain()).toMatchObject({
      phase: 'quiescent',
      drainGeneration: 1,
      activeWorkCount: 0
    })
    await expect(
      item.service.claim({
        path: '/v1/images/generations',
        encodedBody: JSON.stringify({ model: 'image-model', prompt: 'must stay blocked' })
      })
    ).rejects.toThrow('Paid media maintenance drain is active')
    expect(item.request).not.toHaveBeenCalled()

    expect(item.service.releaseMaintenanceDrain(evidence)).toBe(true)
    expect(item.service.releaseMaintenanceDrain(evidence)).toBe(true)
    expect(item.service.inspectMaintenanceDrain()).toMatchObject({ phase: 'accepting' })
    await expect(
      item.service.claim({
        path: '/v1/images/generations',
        encodedBody: JSON.stringify({ model: 'image-model', prompt: 'accepted after release' })
      })
    ).resolves.toMatchObject({ state: 'claimed' })
  })

  it('waits through an accepted provider download and durable result commit', async () => {
    let announceDownload!: () => void
    const downloadStarted = new Promise<void>((resolve) => {
      announceDownload = resolve
    })
    let releaseDownload!: () => void
    const downloadReleased = new Promise<void>((resolve) => {
      releaseDownload = resolve
    })
    const item = fixture(undefined, async (url) => {
      announceDownload()
      await downloadReleased
      return { bytes: PNG, contentType: 'image/png', finalUrl: url }
    })
    const encodedBody = JSON.stringify({
      model: 'image-model',
      prompt: 'download and commit must drain'
    })
    const claimed = await item.service.claim({
      path: '/v1/images/generations',
      encodedBody
    })
    const executing = item.service.execute({
      operationId: claimed.operationId,
      path: '/v1/images/generations',
      encodedBody
    })
    await downloadStarted

    let drainResolved = false
    const draining = item.service.enterMaintenanceDrain().then((evidence) => {
      drainResolved = true
      return evidence
    })
    const duringDownload = item.service.inspectMaintenanceDrain()
    await Promise.resolve()
    expect(drainResolved).toBe(false)
    releaseDownload()
    const result = await executing

    expect(duringDownload).toMatchObject({ phase: 'draining', activeWorkCount: 1 })
    expect(result).toMatchObject({ ok: true, operation: { state: 'result_ready' } })
    const evidence = await draining
    expect(evidence).toMatchObject({
      acceptedSequence: 2,
      completedSequence: 2,
      activeWorkCount: 0
    })
    expect(item.service.releaseMaintenanceDrain(evidence)).toBe(true)
  })

  it('waits through an accepted terminal video poll, media download, and commit', async () => {
    let announceDownload!: () => void
    const downloadStarted = new Promise<void>((resolve) => {
      announceDownload = resolve
    })
    let releaseDownload!: () => void
    const downloadReleased = new Promise<void>((resolve) => {
      releaseDownload = resolve
    })
    const taskAlias = `nvt1_${'b'.repeat(64)}`
    const item = fixture(
      async () => ({
        status: 200,
        headers: {},
        body: JSON.stringify({
          task_id: taskAlias,
          status: 'completed',
          video_url: 'https://cdn.example/drain-final.mp4'
        })
      }),
      async (url) => {
        announceDownload()
        await downloadReleased
        return { bytes: MP4, contentType: 'video/mp4', finalUrl: url }
      }
    )
    await prepareVideoPollBinding(item, taskAlias)

    const polling = item.service.pollVideo({ taskAlias, model: 'video-model' })
    await downloadStarted
    const draining = item.service.enterMaintenanceDrain()
    const duringDownload = item.service.inspectMaintenanceDrain()
    releaseDownload()
    const result = await polling

    expect(duringDownload).toMatchObject({ phase: 'draining', activeWorkCount: 1 })
    expect(result).toMatchObject({ task_id: taskAlias, status: 'completed' })
    const evidence = await draining
    expect(evidence).toMatchObject({ acceptedSequence: 1, completedSequence: 1 })
    expect(item.service.releaseMaintenanceDrain(evidence)).toBe(true)
  })

  it('waits through an accepted proof-bound delivery acknowledgement commit', async () => {
    const item = fixture()
    const encodedBody = JSON.stringify({
      model: 'image-model',
      prompt: 'delivery acknowledgement must drain'
    })
    const claimed = await item.service.claim({ path: '/v1/images/generations', encodedBody })
    const executed = await item.service.execute({
      operationId: claimed.operationId,
      path: '/v1/images/generations',
      encodedBody
    })
    if (!executed.ok) throw new Error('expected paid media success')

    let announceCommit!: () => void
    const commitStarted = new Promise<void>((resolve) => {
      announceCommit = resolve
    })
    let releaseCommit!: () => void
    const commitReleased = new Promise<void>((resolve) => {
      releaseCommit = resolve
    })
    const markDelivered = item.ledger.markDelivered.bind(item.ledger)
    vi.spyOn(item.ledger, 'markDelivered').mockImplementation(async (input) => {
      announceCommit()
      await commitReleased
      return markDelivered(input)
    })

    const acknowledging = item.service.acknowledgeDelivered(executed.deliveryProof)
    await commitStarted
    const draining = item.service.enterMaintenanceDrain()
    const duringCommit = item.service.inspectMaintenanceDrain()
    releaseCommit()
    const delivered = await acknowledging

    expect(duringCommit).toMatchObject({ phase: 'draining', activeWorkCount: 1 })
    expect(delivered).toMatchObject({ operationId: claimed.operationId, state: 'delivered' })
    const evidence = await draining
    expect(evidence).toMatchObject({ acceptedSequence: 3, completedSequence: 3 })
    expect(item.service.releaseMaintenanceDrain(evidence)).toBe(true)
  })

  it('waits through an accepted startup reconciliation scan', async () => {
    const item = fixture()
    let announceScan!: () => void
    const scanStarted = new Promise<void>((resolve) => {
      announceScan = resolve
    })
    let releaseScan!: () => void
    const scanReleased = new Promise<void>((resolve) => {
      releaseScan = resolve
    })
    const listReservations = item.capacity.listReservations.bind(item.capacity)
    vi.spyOn(item.capacity, 'listReservations').mockImplementation(async () => {
      announceScan()
      await scanReleased
      return listReservations()
    })

    const reconciling = item.service.reconcileCapacityOnStartup()
    await scanStarted
    const draining = item.service.enterMaintenanceDrain()
    const duringScan = item.service.inspectMaintenanceDrain()
    releaseScan()
    const result = await reconciling

    expect(duringScan).toMatchObject({ phase: 'draining', activeWorkCount: 1 })
    expect(result).toEqual({ inspected: 0, released: 0, bound: 0, held: 0 })
    const evidence = await draining
    expect(evidence).toMatchObject({ acceptedSequence: 1, completedSequence: 1 })
    expect(item.service.releaseMaintenanceDrain(evidence)).toBe(true)
  })

  it('rejects every mutating or remote asynchronous ingress while keeping reads available', async () => {
    const item = fixture()
    const evidence = await item.service.enterMaintenanceDrain()
    const operationId = `desktop-op-${UUID_ONE}`
    const attempts: Array<() => Promise<unknown>> = [
      () =>
        item.service.initializeInstallationAuthority({
          provision: false,
          provisionLocalState: false
        }),
      () =>
        item.service.prepareInstallationAuthority({
          provision: false,
          provisionLocalState: false,
          allowLegacyBootstrap: false
        }),
      () => item.service.bootstrapLegacyMigration(null),
      () => item.service.ensureMediaProbeReady(),
      () =>
        item.service.claim({
          path: '/v1/images/generations',
          encodedBody: JSON.stringify({ model: 'image-model', prompt: 'blocked claim' })
        }),
      () =>
        item.service.pollVideo({
          taskAlias: `nvt1_${'c'.repeat(64)}`,
          model: 'video-model'
        }),
      () =>
        item.service.execute({
          operationId,
          path: '/v1/images/generations',
          encodedBody: JSON.stringify({ model: 'image-model', prompt: 'blocked execution' })
        }),
      () =>
        item.service.acknowledgeDelivered({
          operationId,
          resultSha256: 'd'.repeat(64),
          archiveReceiptSha256: 'e'.repeat(64)
        }),
      () => item.service.abandonUndispatchedClaim(operationId, 'blocked abandonment'),
      () =>
        item.service.reconcileManually({
          operationId,
          reason: 'blocked-reconciliation',
          evidence: 'maintenance fence'
        }),
      () => item.service.reconcileCapacityOnStartup(),
      () => item.service.importLegacyUnresolved({} as never)
    ]

    for (const attempt of attempts) {
      await expect(attempt()).rejects.toThrow('Paid media maintenance drain is active')
    }
    await expect(item.service.listRecoverableArchives()).resolves.toMatchObject({ items: [] })
    await expect(item.service.listUnresolved()).resolves.toEqual([])
    expect(item.service.inspectMaintenanceDrain()).toMatchObject({
      phase: 'quiescent',
      acceptedSequence: 0,
      completedSequence: 0,
      activeWorkCount: 0
    })
    expect(item.request).not.toHaveBeenCalled()
    expect(item.service.releaseMaintenanceDrain(evidence)).toBe(true)
  })

  it('keeps archived recovery and ledger discovery read-only outside the active-work count', async () => {
    const item = fixture()
    const encodedBody = JSON.stringify({ model: 'image-model', prompt: 'read-only drain view' })
    const claimed = await item.service.claim({ path: '/v1/images/generations', encodedBody })
    await expect(
      item.service.execute({
        operationId: claimed.operationId,
        path: '/v1/images/generations',
        encodedBody
      })
    ).resolves.toMatchObject({ ok: true, operation: { state: 'result_ready' } })
    const evidence = await item.service.enterMaintenanceDrain()
    const beforeReads = item.service.inspectMaintenanceDrain()

    const [recovered, archives, unresolved] = await Promise.all([
      item.service.recoverArchived(claimed.operationId),
      item.service.listRecoverableArchives(),
      item.service.listUnresolved()
    ])

    expect(recovered).toMatchObject({ operationId: claimed.operationId })
    expect(archives.items).toEqual([
      expect.objectContaining({ operationId: claimed.operationId })
    ])
    expect(unresolved).toEqual([
      expect.objectContaining({ operationId: claimed.operationId, state: 'result_ready' })
    ])
    expect(item.service.inspectMaintenanceDrain()).toEqual(beforeReads)
    expect(beforeReads).toMatchObject({
      phase: 'quiescent',
      acceptedSequence: 2,
      completedSequence: 2,
      activeWorkCount: 0
    })
    expect(item.service.releaseMaintenanceDrain(evidence)).toBe(true)
  })

  it('drains an accepted legacy preparation while its shared lifecycle mutex is held', async () => {
    const item = fixture()
    let announceInspect!: () => void
    const inspectStarted = new Promise<void>((resolve) => {
      announceInspect = resolve
    })
    let releaseInspect!: () => void
    const inspectReleased = new Promise<void>((resolve) => {
      releaseInspect = resolve
    })
    const installationRoot = {
      state: { mode: 'detached', reasonCode: 'maintenance-test' },
      attachEvidenceReader: vi.fn(),
      provision: vi.fn(),
      reconcileStartup: vi.fn(),
      localPaidPrincipal: () => 'f'.repeat(64),
      assertMutationContext: vi.fn(),
      assertOutboundReady: vi.fn(),
      runMutation: vi.fn()
    } as unknown as PaidMediaInstallationAuthority
    const service = new PaidMediaService({
      ledger: item.ledger,
      vault: item.vault,
      capacity: item.capacity,
      baseUrl: () => 'http://127.0.0.1:19001',
      runtimeKey: () => 'sk-local-runtime',
      approvalKey: () => 'sk-approval-independent',
      paidMediaKey: () => 'sk-paid-media-independent',
      transport: item.request,
      installationRoot,
      legacySeal: {
        inspect: async () => {
          announceInspect()
          await inspectReleased
          return { state: 'open' as const }
        },
        close: vi.fn()
      }
    })

    const preparing = service.prepareInstallationAuthority({
      provision: true,
      provisionLocalState: true,
      allowLegacyBootstrap: true
    })
    await inspectStarted
    const drainOutcome = service.enterMaintenanceDrain().then(
      (evidence) => ({ evidence, error: null }),
      (error: unknown) => ({ evidence: null, error })
    )
    const duringInspect = service.inspectMaintenanceDrain()
    releaseInspect()
    await expect(preparing).resolves.toEqual({ state: 'legacy_bootstrap_required' })

    expect(duringInspect).toMatchObject({ phase: 'draining', activeWorkCount: 1 })
    const outcome = await drainOutcome
    if (outcome.error) throw outcome.error
    expect(outcome.evidence).toMatchObject({
      acceptedSequence: 1,
      completedSequence: 1,
      legacyBootstrapIdle: true
    })
    expect(service.releaseMaintenanceDrain(outcome.evidence!)).toBe(true)
  })

  it('tracks an already-started autonomous vault cleanup retry and fences later retries', async () => {
    vi.useFakeTimers()
    let releaseRetry: (() => void) | undefined
    try {
      const taskAlias = `nvt1_${'d'.repeat(64)}`
      const stagingRoot = mkdtempSync(join(tmpdir(), 'nachuan-paid-media-fetch-'))
      roots.push(stagingRoot)
      const stagingFile = join(stagingRoot, 'asset.bin')
      writeFileSync(stagingFile, MP4)
      let cleanupAttempts = 0
      const item = cleanupHeldVideoFixture(taskAlias, stagingFile, {
        unlinkStagedFile: (path) => {
          cleanupAttempts += 1
          if (cleanupAttempts === 1) throw new Error('synthetic cleanup hold before drain')
          unlinkSync(path)
        },
        removeEmptyStagingDirectory: rmdirSync,
        unlinkMarker: unlinkSync
      })
      await archiveCleanupHeldVideo(item, taskAlias)
      expect(cleanupAttempts).toBe(1)
      item.vault.setCleanupRecoveredHandler(null)

      let announceRetry!: () => void
      const retryStarted = new Promise<void>((resolve) => {
        announceRetry = resolve
      })
      const retryReleased = new Promise<void>((resolve) => {
        releaseRetry = resolve
      })
      const internals = item.service as unknown as {
        runMaintenanceTrackedWork: (
          action: () => Promise<unknown>
        ) => Promise<unknown>
      }
      const runTracked = internals.runMaintenanceTrackedWork.bind(item.service)
      const tracked = vi
        .spyOn(internals, 'runMaintenanceTrackedWork')
        .mockImplementation((action) =>
          runTracked(async () => {
            announceRetry()
            await retryReleased
            return action()
          })
        )

      vi.advanceTimersByTime(30_000)
      await Promise.resolve()
      expect(tracked).toHaveBeenCalledOnce()
      await retryStarted
      const draining = item.service.enterMaintenanceDrain()
      const duringRetry = item.service.inspectMaintenanceDrain()
      let unresolved: Awaited<ReturnType<PaidMediaService['listUnresolved']>>
      try {
        unresolved = await item.service.listUnresolved()
      } finally {
        releaseRetry?.()
      }

      const evidence = await draining
      expect(duringRetry).toMatchObject({ phase: 'draining', activeWorkCount: 1 })
      expect(unresolved).toEqual([
        expect.objectContaining({ operationId: expect.stringMatching(/^desktop-op-/) })
      ])
      expect(evidence).toMatchObject({ acceptedSequence: 4, completedSequence: 4 })
      expect(cleanupAttempts).toBe(2)
      expect(item.service.releaseMaintenanceDrain(evidence)).toBe(true)
    } finally {
      releaseRetry?.()
      vi.useRealTimers()
    }
  })

  it('allows cancellation to settle an accepted provider failure without leaking drain state', async () => {
    let announceTransport!: () => void
    const transportStarted = new Promise<void>((resolve) => {
      announceTransport = resolve
    })
    const item = fixture(
      (request) =>
        new Promise((_resolve, reject) => {
          announceTransport()
          const rejectCancelled = (): void => reject(new Error('synthetic provider cancellation'))
          if (request.signal.aborted) {
            rejectCancelled()
            return
          }
          request.signal.addEventListener('abort', rejectCancelled, { once: true })
        })
    )
    const encodedBody = JSON.stringify({
      model: 'image-model',
      prompt: 'cancelled work must still finish its durable failure path'
    })
    const claimed = await item.service.claim({ path: '/v1/images/generations', encodedBody })
    const executing = item.service.execute({
      operationId: claimed.operationId,
      path: '/v1/images/generations',
      encodedBody
    })
    await transportStarted

    const draining = item.service.enterMaintenanceDrain()
    const duringTransport = item.service.inspectMaintenanceDrain()
    await expect(
      item.service.claim({
        path: '/v1/images/generations',
        encodedBody: JSON.stringify({ model: 'image-model', prompt: 'must be fenced' })
      })
    ).rejects.toThrow('Paid media maintenance drain is active')
    expect(item.service.cancel(claimed.operationId)).toBe(true)
    const result = await executing

    expect(duringTransport).toMatchObject({ phase: 'draining', activeWorkCount: 1 })
    expect(result).toMatchObject({
      ok: false,
      recoverable: true,
      operation: { operationId: claimed.operationId, state: 'recoverable' }
    })
    const evidence = await draining
    expect(evidence).toMatchObject({
      acceptedSequence: 2,
      completedSequence: 2,
      activeWorkCount: 0,
      activeRequestCount: 0,
      executingOperationCount: 0,
      pendingCancellationCount: 0
    })
    expect(item.service.cancel(claimed.operationId)).toBe(false)
    expect(item.service.releaseMaintenanceDrain(evidence)).toBe(true)
  })

  it('atomically closes admission across wrappers while an accepted claim is queued', async () => {
    const item = fixture()
    const peer = item.service.withAuthorities({
      runtimeKey: () => 'sk-local-runtime',
      approvalKey: () => 'sk-approval-independent',
      paidMediaKey: () => 'sk-paid-media-independent'
    })
    let announceClaim!: () => void
    const claimStarted = new Promise<void>((resolve) => {
      announceClaim = resolve
    })
    let releaseClaim!: () => void
    const claimReleased = new Promise<void>((resolve) => {
      releaseClaim = resolve
    })
    const ledgerClaim = item.ledger.claim.bind(item.ledger)
    const claimSpy = vi.spyOn(item.ledger, 'claim').mockImplementation(async (input) => {
      announceClaim()
      await claimReleased
      return ledgerClaim(input)
    })
    const acceptedBody = JSON.stringify({ model: 'image-model', prompt: 'accepted before drain' })
    const accepted = item.service.claim({
      path: '/v1/images/generations',
      encodedBody: acceptedBody
    })
    await claimStarted

    const draining = peer.enterMaintenanceDrain()
    const rejected = Array.from({ length: 8 }, (_, index) =>
      (index % 2 === 0 ? item.service : peer).claim({
        path: '/v1/images/generations',
        encodedBody: JSON.stringify({ model: 'image-model', prompt: `fenced-${index}` })
      })
    )
    const settled = await Promise.allSettled(rejected)
    expect(settled).toEqual(
      Array.from({ length: 8 }, () =>
        expect.objectContaining({
          status: 'rejected',
          reason: expect.objectContaining({
            message: 'Paid media maintenance drain is active'
          })
        })
      )
    )
    expect(peer.inspectMaintenanceDrain()).toMatchObject({
      phase: 'draining',
      acceptedSequence: 1,
      completedSequence: 0,
      activeWorkCount: 1
    })
    expect(claimSpy).toHaveBeenCalledOnce()
    releaseClaim()
    await expect(accepted).resolves.toMatchObject({ state: 'claimed' })

    const evidence = await draining
    expect(evidence).toMatchObject({ acceptedSequence: 1, completedSequence: 1 })
    expect(item.service.releaseMaintenanceDrain(evidence)).toBe(true)
  })

  it('deduplicates drain and release while rejecting stale or forged evidence', async () => {
    const item = fixture()
    const firstDrain = item.service.enterMaintenanceDrain()
    const duplicateFirstDrain = item.service.enterMaintenanceDrain()
    const [first, duplicateFirst] = await Promise.all([firstDrain, duplicateFirstDrain])
    expect(duplicateFirst).toBe(first)
    expect(first.drainGeneration).toBe(1)
    expect(item.service.releaseMaintenanceDrain(first)).toBe(true)
    expect(item.service.releaseMaintenanceDrain(first)).toBe(true)

    let announceProbe!: () => void
    const probeStarted = new Promise<void>((resolve) => {
      announceProbe = resolve
    })
    let releaseProbe!: () => void
    const probeReleased = new Promise<void>((resolve) => {
      releaseProbe = resolve
    })
    const ensureProbeReady = item.vault.ensureMediaProbeReady.bind(item.vault)
    vi.spyOn(item.vault, 'ensureMediaProbeReady').mockImplementation(async () => {
      announceProbe()
      await probeReleased
      return ensureProbeReady()
    })
    const probing = item.service.ensureMediaProbeReady()
    await probeStarted
    const secondDrain = item.service.enterMaintenanceDrain()
    const duplicateSecondDrain = item.service.enterMaintenanceDrain()

    expect(item.service.releaseMaintenanceDrain(first)).toBe(false)
    expect(
      item.service.releaseMaintenanceDrain({
        ...first,
        drainGeneration: 2
      })
    ).toBe(false)
    expect(item.service.inspectMaintenanceDrain()).toMatchObject({
      phase: 'draining',
      drainGeneration: 2,
      activeWorkCount: 1
    })
    releaseProbe()
    await expect(probing).resolves.toBeUndefined()
    const [second, duplicateSecond] = await Promise.all([secondDrain, duplicateSecondDrain])

    expect(duplicateSecond).toBe(second)
    expect(second.drainGeneration).toBe(2)
    expect(item.service.releaseMaintenanceDrain(first)).toBe(false)
    expect(
      item.service.releaseMaintenanceDrain({
        ...second,
        completedSequence: second.completedSequence + 1
      })
    ).toBe(false)
    expect(item.service.releaseMaintenanceDrain(second)).toBe(true)
    expect(item.service.releaseMaintenanceDrain(second)).toBe(true)

    const third = await item.service.enterMaintenanceDrain()
    expect(third.drainGeneration).toBe(3)
    expect(item.service.releaseMaintenanceDrain(second)).toBe(false)
    expect(item.service.releaseMaintenanceDrain(third)).toBe(true)
  })

  it('freezes aggregate-only status and evidence without operation, prompt, or authority leakage', async () => {
    let announceTransport!: () => void
    const transportStarted = new Promise<void>((resolve) => {
      announceTransport = resolve
    })
    let releaseTransport!: (response: Awaited<ReturnType<PaidMediaTransport>>) => void
    const transportReleased = new Promise<Awaited<ReturnType<PaidMediaTransport>>>((resolve) => {
      releaseTransport = resolve
    })
    const item = fixture(async () => {
      announceTransport()
      return transportReleased
    })
    const sensitivePrompt = 'private-drain-prompt-7f3c'
    const encodedBody = JSON.stringify({ model: 'private-model-name', prompt: sensitivePrompt })
    const claimed = await item.service.claim({ path: '/v1/images/generations', encodedBody })
    const executing = item.service.execute({
      operationId: claimed.operationId,
      path: '/v1/images/generations',
      encodedBody
    })
    await transportStarted

    const draining = item.service.enterMaintenanceDrain()
    const status = item.service.inspectMaintenanceDrain()
    expect(Object.isFrozen(status)).toBe(true)
    expect(Object.keys(status).sort()).toEqual(
      [
        'schema',
        'scope',
        'phase',
        'drainGeneration',
        'acceptedSequence',
        'completedSequence',
        'activeWorkCount'
      ].sort()
    )
    const serializedStatus = JSON.stringify(status)
    for (const secret of [
      claimed.operationId,
      sensitivePrompt,
      'private-model-name',
      'sk-local-runtime',
      'sk-approval-independent',
      'sk-paid-media-independent'
    ]) {
      expect(serializedStatus).not.toContain(secret)
    }
    releaseTransport({
      status: 200,
      headers: {},
      body: JSON.stringify({ created: 1, data: [{ b64_json: PNG.toString('base64') }] })
    })
    await expect(executing).resolves.toMatchObject({ ok: true })

    const evidence = await draining
    expect(Object.isFrozen(evidence)).toBe(true)
    expect(Object.keys(evidence).sort()).toEqual(
      [
        'schema',
        'scope',
        'drainGeneration',
        'acceptedSequence',
        'completedSequence',
        'activeWorkCount',
        'operationMutexCount',
        'activeRequestCount',
        'executingOperationCount',
        'pendingCancellationCount',
        'legacyBootstrapIdle',
        'evidenceSha256'
      ].sort()
    )
    const serializedEvidence = JSON.stringify(evidence)
    expect(serializedEvidence).not.toContain(claimed.operationId)
    expect(serializedEvidence).not.toContain(sensitivePrompt)
    expect(serializedEvidence).not.toContain('private-model-name')
    expect(item.service.releaseMaintenanceDrain(evidence)).toBe(true)
  })
})
