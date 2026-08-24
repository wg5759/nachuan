import { createHash } from 'node:crypto'
import {
  mkdtempSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  symlinkSync,
  truncateSync,
  writeFileSync
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, describe, expect, it } from 'vitest'

import {
  PaidMediaRecoveryIntentStore,
  type PaidMediaRecoveryIntentStoreDependencies
} from './paid-media-recovery-intent'
import { paidMediaAssetResultDigest } from './paid-media-asset-protocol'

const OPERATION_ID = 'desktop-op-aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
const OPERATION_ID_B = 'desktop-op-bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
const REQUEST_SHA256 = '1'.repeat(64)
const RECOVERY_DOMAIN_SHA256 = '2'.repeat(64)
const PAID_PRINCIPAL_SHA256 = '3'.repeat(64)
const TURN_ID = '4'.repeat(64)
const ASSET_SHA256 = '5'.repeat(64)
const VALIDATION_RECEIPT_SHA256 = '6'.repeat(64)
const LEASE_ID = '7'.repeat(64)
const LEASE_ID_B = 'a'.repeat(64)
const STAGE_RESULT_SHA256 = 'f'.repeat(64)
const LEASE_STATE_DIGEST = '8'.repeat(64)
const ARCHIVE_RECEIPT_SHA256 = 'b'.repeat(64)
const DISPATCH_RECEIPT_SHA256 = 'c'.repeat(64)
const ACK_INTENT_RECEIPT_SHA256 = 'd'.repeat(64)
const ACK_COMPLETION_RECEIPT_SHA256 = 'e'.repeat(64)
const TOKEN = `nma1_${'A'.repeat(43)}`

function assetResult(validationReceiptSha256 = VALIDATION_RECEIPT_SHA256) {
  return {
    schema: 'nachuan.paid-media-result.v2' as const,
    kind: 'image' as const,
    created: 1_784_200_000,
    turnId: TURN_ID,
    assets: [
      {
        token: TOKEN,
        mediaType: 'image/png',
        byteLength: 68,
        sha256: ASSET_SHA256,
        validationReceiptSha256
      }
    ]
  }
}

function dispatchPayload() {
  return {
    kind: 'asset_v2_dispatch' as const,
    operationId: OPERATION_ID,
    claim: {
      path: '/v1/images/generations' as const,
      requestSha256: REQUEST_SHA256,
      recoveryDomainSha256: RECOVERY_DOMAIN_SHA256
    },
    paidPrincipalSha256: PAID_PRINCIPAL_SHA256
  }
}

function trustedValidation() {
  const base = {
    schema: 'nachuan.trusted-media-validation.v2' as const,
    validatorVersion: 'nachuan.trusted-media-probe.v2' as const,
    validationPolicy: 'nachuan.trusted-media-policy.av-closed.v1' as const,
    fullyDecoded: true as const,
    mediaType: 'image/png' as const,
    byteLength: 68,
    sha256: ASSET_SHA256,
    attestedTools: { ffmpegSha256: '8'.repeat(64), ffprobeSha256: '9'.repeat(64) },
    metadata: {
      detectedKind: 'image' as const,
      codecName: 'png',
      audioCodecName: null,
      videoStreamCount: 1 as const,
      audioStreamCount: 0 as const,
      formatName: 'png_pipe',
      width: 1,
      height: 1,
      durationMs: null,
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

const roots: string[] = []

function fakeEncrypt(value: string): Buffer {
  const bytes = Buffer.from(value, 'utf8')
  for (let index = 0; index < bytes.length; index += 1) bytes[index] ^= 0xa5
  return bytes
}

function fakeDecrypt(value: Buffer): string {
  const bytes = Buffer.from(value)
  for (let index = 0; index < bytes.length; index += 1) bytes[index] ^= 0xa5
  return bytes.toString('utf8')
}

function dependencies(): PaidMediaRecoveryIntentStoreDependencies {
  return {
    safeStorage: {
      isEncryptionAvailable: () => true,
      encryptString: fakeEncrypt,
      decryptString: fakeDecrypt
    },
    harden: () => undefined
  }
}

function fixture(
  overrides: Partial<PaidMediaRecoveryIntentStoreDependencies> = {}
): { root: string; store: PaidMediaRecoveryIntentStore } {
  const root = mkdtempSync(join(tmpdir(), 'nachuan-recovery-intent-'))
  roots.push(root)
  return {
    root,
    store: new PaidMediaRecoveryIntentStore(root, {
      ...dependencies(),
      ...overrides
    })
  }
}

function finalFiles(root: string): string[] {
  return readdirSync(root).filter((name) => !name.startsWith('.'))
}

function onlyFinalPath(root: string): string {
  const files = finalFiles(root)
  expect(files).toHaveLength(1)
  return join(root, files[0]!)
}

function expectDeepFrozen(value: unknown, seen = new Set<object>()): void {
  if (value === null || typeof value !== 'object' || seen.has(value)) return
  seen.add(value)
  expect(Object.isFrozen(value)).toBe(true)
  for (const descriptor of Object.values(Object.getOwnPropertyDescriptors(value))) {
    if ('value' in descriptor) expectDeepFrozen(descriptor.value, seen)
  }
}

function rewriteEncryptedDocument(
  path: string,
  mutate: (document: Record<string, unknown>) => void
): void {
  const envelope = JSON.parse(readFileSync(path, 'utf8')) as {
    ciphertext: string
  }
  const document = JSON.parse(
    fakeDecrypt(Buffer.from(envelope.ciphertext, 'base64'))
  ) as Record<string, unknown>
  mutate(document)
  envelope.ciphertext = fakeEncrypt(JSON.stringify(document)).toString('base64')
  writeFileSync(path, JSON.stringify(envelope), 'utf8')
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true })
})

describe('PaidMediaRecoveryIntentStore', () => {
  it('prepares and reopens an exact dispatch payload through a public Root descriptor', async () => {
    const item = fixture()
    const payload = {
      kind: 'asset_v2_dispatch' as const,
      operationId: OPERATION_ID,
      claim: {
        path: '/v1/images/generations' as const,
        requestSha256: REQUEST_SHA256,
        recoveryDomainSha256: RECOVERY_DOMAIN_SHA256
      },
      paidPrincipalSha256: PAID_PRINCIPAL_SHA256
    }

    const descriptor = await item.store.prepare(payload)

    expect(descriptor).toEqual({
      handlerVersion: 1,
      kind: 'asset_v2_dispatch',
      operationId: OPERATION_ID,
      intentSha256: expect.stringMatching(/^[0-9a-f]{64}$/)
    })
    expect(Object.isFrozen(descriptor)).toBe(true)
    expect(finalFiles(item.root)).toEqual([
      `${descriptor.intentSha256}.prepared-intent.json`
    ])
    expect(JSON.stringify(descriptor)).not.toContain(PAID_PRINCIPAL_SHA256)

    const restarted = new PaidMediaRecoveryIntentStore(item.root, dependencies())
    const restored = restarted.read(descriptor)
    expect(restored).toEqual(payload)
    expectDeepFrozen(restored)
  })

  it('canonicalizes a fresh stage reservation through the existing asset result contract', async () => {
    const item = fixture()
    const payload = {
      kind: 'asset_v2_stage_reserve' as const,
      operationId: OPERATION_ID,
      mode: 'fresh' as const,
      result: assetResult()
    }

    const descriptor = await item.store.prepare(payload)
    const restored = item.store.read(descriptor)

    expect(descriptor).toMatchObject({ kind: 'asset_v2_stage_reserve' })
    expect(restored).toEqual(payload)
    expectDeepFrozen(restored)
  })

  it('binds reclaim stage reservations to exact generation and lease-state evidence', async () => {
    const item = fixture()
    const result = assetResult()
    const payload = {
      kind: 'asset_v2_stage_reserve' as const,
      operationId: OPERATION_ID,
      mode: 'reclaim' as const,
      result,
      leases: [
        {
          leaseId: LEASE_ID,
          ordinal: 0,
          generation: 3,
          resultSha256: paidMediaAssetResultDigest(result),
          leaseStateDigest: '7'.repeat(64)
        }
      ]
    }

    const descriptor = await item.store.prepare(payload)
    const restored = item.store.read(descriptor)

    expect(restored).toEqual(payload)
    expectDeepFrozen(restored)
  })

  it('binds stage archive to aligned leases and strict trusted validation receipts', async () => {
    const item = fixture()
    const validation = trustedValidation()
    const result = assetResult(validation.receiptSha256)
    const payload = {
      kind: 'asset_v2_stage_archive' as const,
      operationId: OPERATION_ID,
      result,
      leases: [
        {
          leaseId: LEASE_ID,
          ordinal: 0,
          generation: 3,
          resultSha256: paidMediaAssetResultDigest(result),
          leaseStateDigest: LEASE_STATE_DIGEST
        }
      ],
      validations: [validation]
    }

    const descriptor = await item.store.prepare(payload)
    const restored = item.store.read(descriptor)

    expect(restored).toEqual(payload)
    expectDeepFrozen(restored)
  })

  it('canonicalizes stage cleanup as exact generation/result/state-bound leases', async () => {
    const item = fixture()
    const lease = {
      leaseId: LEASE_ID,
      generation: 3,
      resultSha256: STAGE_RESULT_SHA256,
      leaseStateDigest: LEASE_STATE_DIGEST
    }
    const leaseB = {
      leaseId: LEASE_ID_B,
      generation: 1,
      resultSha256: '1'.repeat(64),
      leaseStateDigest: '2'.repeat(64)
    }
    const descriptor = await item.store.prepare({
      kind: 'asset_v2_stage_cleanup',
      operationId: OPERATION_ID,
      leases: [leaseB, lease]
    })

    const restored = item.store.read(descriptor)
    expect(restored).toEqual({
      kind: 'asset_v2_stage_cleanup',
      operationId: OPERATION_ID,
      leases: [lease, leaseB]
    })
    expectDeepFrozen(restored)
  })

  it('rejects duplicated lease ids even when a stale generation claims different evidence', async () => {
    const item = fixture()
    const lease = {
      leaseId: LEASE_ID,
      generation: 0,
      resultSha256: STAGE_RESULT_SHA256,
      leaseStateDigest: LEASE_STATE_DIGEST
    }
    await expect(
      item.store.prepare({
        kind: 'asset_v2_stage_cleanup',
        operationId: OPERATION_ID,
        leases: [lease, { ...lease, generation: 1, leaseStateDigest: '9'.repeat(64) }]
      })
    ).rejects.toThrow(/duplicated/i)
  })

  it('keeps result-ready ACK tokens private while binding archive and dispatch evidence', async () => {
    const item = fixture()
    const payload = {
      kind: 'asset_v2_result_ready_ack_intent' as const,
      operationId: OPERATION_ID,
      result: assetResult(),
      archive: {
        receiptSha256: ARCHIVE_RECEIPT_SHA256,
        cleanupComplete: false
      },
      dispatch: { receiptSha256: DISPATCH_RECEIPT_SHA256 },
      ack: {
        schema: 'nachuan.paid-media-asset-ack.v1' as const,
        turnId: TURN_ID,
        tokens: [TOKEN],
        archiveReceiptSha256: ARCHIVE_RECEIPT_SHA256
      }
    }

    const descriptor = await item.store.prepare(payload)

    expect(JSON.stringify(descriptor)).not.toContain(TOKEN)
    const raw = readFileSync(onlyFinalPath(item.root), 'utf8')
    expect(raw).not.toContain(TOKEN)
    expect(raw).not.toContain(TURN_ID)
    expect(raw).not.toContain('"payload"')
    const restored = item.store.read(descriptor)
    expect(restored).toEqual(payload)
    expectDeepFrozen(restored)
  })

  it('stores only an exact semantic HTTP 200 ACK completion response', async () => {
    const item = fixture()
    const payload = {
      kind: 'asset_v2_ack_completion' as const,
      operationId: OPERATION_ID,
      intentReceiptSha256: ACK_INTENT_RECEIPT_SHA256,
      status: 200 as const,
      response: {
        ok: true as const,
        turnId: TURN_ID,
        replayed: true,
        cleanupComplete: true as const
      }
    }

    const descriptor = await item.store.prepare(payload)

    expect(JSON.stringify(descriptor)).not.toContain(TURN_ID)
    const restored = item.store.read(descriptor)
    expect(restored).toEqual(payload)
    expectDeepFrozen(restored)
  })

  it('binds capacity release to archive, dispatch, and ACK completion receipts', async () => {
    const item = fixture()
    const payload = {
      kind: 'asset_v2_capacity_release' as const,
      operationId: OPERATION_ID,
      archive: {
        receiptSha256: ARCHIVE_RECEIPT_SHA256,
        cleanupComplete: true as const
      },
      dispatch: { receiptSha256: DISPATCH_RECEIPT_SHA256 },
      ackCompletion: { receiptSha256: ACK_COMPLETION_RECEIPT_SHA256 }
    }

    const descriptor = await item.store.prepare(payload)

    const restored = item.store.read(descriptor)
    expect(restored).toEqual(payload)
    expectDeepFrozen(restored)
  })

  it.each<[string, () => unknown]>([
    [
      'an extra payload field',
      () => ({ ...dispatchPayload(), extra: true })
    ],
    [
      'a symbol field',
      () => Object.assign(dispatchPayload(), { [Symbol('private')]: true })
    ],
    [
      'a hidden field',
      () => {
        const payload = dispatchPayload()
        Object.defineProperty(payload, 'hidden', { value: true })
        return payload
      }
    ],
    [
      'a cyclic graph',
      () => {
        const payload = dispatchPayload() as ReturnType<typeof dispatchPayload> & {
          self?: unknown
        }
        payload.self = payload
        return payload
      }
    ],
    [
      'a sparse lease array',
      () => ({
        kind: 'asset_v2_stage_cleanup',
        operationId: OPERATION_ID,
        leases: new Array(1)
      })
    ],
    [
      'an extended lease array',
      () => {
        const leases = [
          {
            leaseId: LEASE_ID,
            generation: 0,
            resultSha256: STAGE_RESULT_SHA256,
            leaseStateDigest: LEASE_STATE_DIGEST
          }
        ] as Array<Record<string, unknown>> & { extra?: boolean }
        leases.extra = true
        return {
          kind: 'asset_v2_stage_cleanup',
          operationId: OPERATION_ID,
          leases
        }
      }
    ],
    [
      'a non-finite number',
      () => ({
        kind: 'asset_v2_ack_completion',
        operationId: OPERATION_ID,
        intentReceiptSha256: ACK_INTENT_RECEIPT_SHA256,
        status: 200,
        response: {
          ok: true,
          turnId: TURN_ID,
          replayed: Number.POSITIVE_INFINITY,
          cleanupComplete: true
        }
      })
    ],
    [
      'a zero digest',
      () => ({
        ...dispatchPayload(),
        paidPrincipalSha256: '0'.repeat(64)
      })
    ],
    [
      'a trusted validation receipt with an extra field',
      () => {
        const validation = { ...trustedValidation(), extra: true }
        const result = assetResult(validation.receiptSha256)
        return {
          kind: 'asset_v2_stage_archive',
          operationId: OPERATION_ID,
          result,
          leases: [
            {
              leaseId: LEASE_ID,
              ordinal: 0,
              generation: 3,
              resultSha256: paidMediaAssetResultDigest(result),
              leaseStateDigest: LEASE_STATE_DIGEST
            }
          ],
          validations: [validation]
        }
      }
    ],
    [
      'a trusted validation receipt bound to a different asset descriptor',
      () => {
        const result = assetResult('f'.repeat(64))
        return {
          kind: 'asset_v2_stage_archive',
          operationId: OPERATION_ID,
          result,
          leases: [
            {
              leaseId: LEASE_ID,
              ordinal: 0,
              generation: 3,
              resultSha256: paidMediaAssetResultDigest(result),
              leaseStateDigest: LEASE_STATE_DIGEST
            }
          ],
          validations: [trustedValidation()]
        }
      }
    ],
    [
      'a non-200 ACK completion',
      () => ({
        kind: 'asset_v2_ack_completion',
        operationId: OPERATION_ID,
        intentReceiptSha256: ACK_INTENT_RECEIPT_SHA256,
        status: 201,
        response: {
          ok: true,
          turnId: TURN_ID,
          replayed: false,
          cleanupComplete: true
        }
      })
    ],
    [
      'an ACK completion response with an extra field',
      () => ({
        kind: 'asset_v2_ack_completion',
        operationId: OPERATION_ID,
        intentReceiptSha256: ACK_INTENT_RECEIPT_SHA256,
        status: 200,
        response: {
          ok: true,
          turnId: TURN_ID,
          replayed: false,
          cleanupComplete: true,
          body: 'private'
        }
      })
    ],
    [
      'a result-ready ACK bound to different tokens',
      () => ({
        kind: 'asset_v2_result_ready_ack_intent',
        operationId: OPERATION_ID,
        result: assetResult(),
        archive: { receiptSha256: ARCHIVE_RECEIPT_SHA256, cleanupComplete: false },
        dispatch: { receiptSha256: DISPATCH_RECEIPT_SHA256 },
        ack: {
          schema: 'nachuan.paid-media-asset-ack.v1',
          turnId: TURN_ID,
          tokens: [`nma1_${'B'.repeat(43)}`],
          archiveReceiptSha256: ARCHIVE_RECEIPT_SHA256
        }
      })
    ],
    [
      'a fresh stage reservation carrying reclaim leases',
      () => ({
        kind: 'asset_v2_stage_reserve',
        operationId: OPERATION_ID,
        mode: 'fresh',
        result: assetResult(),
        leaseIds: [LEASE_ID]
      })
    ],
    [
      'a capacity release without completed archive cleanup',
      () => ({
        kind: 'asset_v2_capacity_release',
        operationId: OPERATION_ID,
        archive: { receiptSha256: ARCHIVE_RECEIPT_SHA256, cleanupComplete: false },
        dispatch: { receiptSha256: DISPATCH_RECEIPT_SHA256 },
        ackCompletion: { receiptSha256: ACK_COMPLETION_RECEIPT_SHA256 }
      })
    ]
  ])('rejects %s', async (_label, build) => {
    const item = fixture()
    await expect(item.store.prepare(build())).rejects.toThrow()
    expect(readdirSync(item.root)).toEqual([])
  })

  it('rejects accessors without invoking them', async () => {
    let reads = 0
    const payload = dispatchPayload()
    Object.defineProperty(payload, 'paidPrincipalSha256', {
      enumerable: true,
      get: () => {
        reads += 1
        return PAID_PRINCIPAL_SHA256
      }
    })
    const item = fixture()

    await expect(item.store.prepare(payload)).rejects.toThrow('accessor')
    expect(reads).toBe(0)
    expect(readdirSync(item.root)).toEqual([])
  })

  it('fails closed without OS-backed encryption before creating any file', async () => {
    const item = fixture({
      safeStorage: {
        isEncryptionAvailable: () => false,
        encryptString: () => {
          throw new Error('must not encrypt without availability')
        },
        decryptString: () => {
          throw new Error('must not decrypt without availability')
        }
      }
    })

    await expect(item.store.prepare(dispatchPayload())).rejects.toThrow(
      'encryption is unavailable'
    )
    expect(readdirSync(item.root)).toEqual([])
  })

  it('rejects a same-address payload conflict on both read and EEXIST prepare', async () => {
    const item = fixture()
    const descriptor = await item.store.prepare(dispatchPayload())
    rewriteEncryptedDocument(onlyFinalPath(item.root), (document) => {
      const payload = document.payload as Record<string, unknown>
      payload.paidPrincipalSha256 = 'f'.repeat(64)
    })

    expect(() => item.store.read(descriptor)).toThrow('digest or binding')
    await expect(item.store.prepare(dispatchPayload())).rejects.toThrow('digest or binding')
    expect(finalFiles(item.root)).toHaveLength(1)
    expect(readdirSync(item.root).filter((name) => name.startsWith('.'))).toEqual([])
  })

  it('uses different content addresses for different canonical private payloads', async () => {
    const item = fixture()
    const leftPayload = dispatchPayload()
    const rightPayload = { ...dispatchPayload(), paidPrincipalSha256: 'f'.repeat(64) }

    const left = await item.store.prepare(leftPayload)
    const right = await item.store.prepare(rightPayload)

    expect(left.intentSha256).not.toBe(right.intentSha256)
    expect(finalFiles(item.root)).toHaveLength(2)
    expect(item.store.read(left)).toEqual(leftPayload)
    expect(item.store.read(right)).toEqual(rightPayload)
  })

  it.each(['truncated file', 'corrupt envelope'])(
    'rejects a %s instead of treating it as authoritative',
    async (failure) => {
      const item = fixture()
      const descriptor = await item.store.prepare(dispatchPayload())
      const path = onlyFinalPath(item.root)
      if (failure === 'truncated file') truncateSync(path, 0)
      else writeFileSync(path, '{}', 'utf8')

      expect(() => item.store.read(descriptor)).toThrow()
    }
  )

  it('rejects descriptor extensions, zero digests, and cross-operation or cross-kind files', async () => {
    const item = fixture()
    const descriptor = await item.store.prepare(dispatchPayload())

    expect(() => item.store.read({ ...descriptor, privateToken: TOKEN })).toThrow('descriptor')
    expect(() => item.store.read({ ...descriptor, intentSha256: '0'.repeat(64) })).toThrow(
      'digest'
    )

    const crossOperation = { ...descriptor, operationId: OPERATION_ID_B }
    expect(() => item.store.read(crossOperation)).toThrow('does not match its descriptor')

    const crossKind = { ...descriptor, kind: 'asset_v2_stage_cleanup' as const }
    expect(() => item.store.read(crossKind)).toThrow('does not match its descriptor')
  })

  it('rejects a final intent file replaced between metadata check and open', async () => {
    let armed = false
    let original = ''
    const shared = dependencies()
    shared.harden = (path, directory) => {
      if (!armed || directory || !path.endsWith('.prepared-intent.json')) return
      armed = false
      renameSync(path, `${path}.replaced`)
      writeFileSync(path, original, 'utf8')
    }
    const item = fixture(shared)
    const descriptor = await item.store.prepare(dispatchPayload())
    original = readFileSync(onlyFinalPath(item.root), 'utf8')
    armed = true

    expect(() => item.store.read(descriptor)).toThrow('changed before reading')
  })

  it('rejects final-file and root-directory reparse redirection', async () => {
    const item = fixture()
    const descriptor = await item.store.prepare(dispatchPayload())
    const finalPath = onlyFinalPath(item.root)
    const target = join(item.root, 'redirected-intent.json')
    renameSync(finalPath, target)
    symlinkSync(target, finalPath, 'file')

    expect(() => item.store.read(descriptor)).toThrow('redirected')

    const rootLink = `${item.root}-junction`
    symlinkSync(item.root, rootLink, 'junction')
    roots.push(rootLink)
    expect(() => new PaidMediaRecoveryIntentStore(rootLink, dependencies())).toThrow(
      'root is redirected'
    )
  })

  it('leaves an interrupted pre-publish temp orphan non-authoritative across restart', async () => {
    let captured: unknown
    const item = fixture({
      onPublishPhase: async (phase, context) => {
        if (phase === 'after_temp_fsync_before_publish') {
          captured = context.descriptor
          throw new Error('simulated power loss before publication')
        }
      }
    })

    await expect(item.store.prepare(dispatchPayload())).rejects.toThrow(
      'atomic publish failed'
    )
    expect(captured).toBeDefined()
    expect(readdirSync(item.root).filter((name) => !name.startsWith('.'))).toEqual([])
    expect(readdirSync(item.root).filter((name) => name.startsWith('.'))).toHaveLength(1)

    const restarted = new PaidMediaRecoveryIntentStore(item.root, dependencies())
    expect(() => restarted.read(captured)).toThrow()
    const descriptor = await restarted.prepare(dispatchPayload())
    expect(restarted.read(descriptor)).toEqual(dispatchPayload())
  })

  it('makes a fully linked intent authoritative before post-publish interruption', async () => {
    let captured: unknown
    const item = fixture({
      onPublishPhase: async (phase, context) => {
        if (phase === 'after_publish_before_verify') {
          captured = context.descriptor
          throw new Error('simulated power loss after publication')
        }
      }
    })

    await expect(item.store.prepare(dispatchPayload())).rejects.toThrow(
      'publish verification failed'
    )
    expect(captured).toBeDefined()
    expect(finalFiles(item.root)).toHaveLength(1)

    const restarted = new PaidMediaRecoveryIntentStore(item.root, dependencies())
    expect(restarted.read(captured)).toEqual(dispatchPayload())
  })

  it('publishes one create-only file for concurrent and repeated identical intents', async () => {
    let arrivals = 0
    let release!: () => void
    const gate = new Promise<void>((resolve) => {
      release = resolve
    })
    const shared = dependencies()
    shared.onPublishPhase = async (phase) => {
      if (phase !== 'after_temp_fsync_before_publish') return
      arrivals += 1
      if (arrivals === 2) release()
      await gate
    }
    const item = fixture(shared)
    const peer = new PaidMediaRecoveryIntentStore(item.root, shared)

    const [left, right] = await Promise.all([
      item.store.prepare(dispatchPayload()),
      peer.prepare(dispatchPayload())
    ])

    expect(left).toEqual(right)
    expect(finalFiles(item.root)).toHaveLength(1)
    expect(readdirSync(item.root).filter((name) => name.startsWith('.'))).toEqual([])

    const repeated = await item.store.prepare(dispatchPayload())
    expect(repeated).toEqual(left)
    expect(finalFiles(item.root)).toHaveLength(1)
  })
})
