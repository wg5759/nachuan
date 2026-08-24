import { readFileSync } from 'node:fs'
import { afterEach, describe, expect, it, vi } from 'vitest'

import {
  listRecoverablePaidMediaArchives,
  recoverPaidMediaArchive
} from './paid-media-journal'

afterEach(() => {
  Reflect.deleteProperty(globalThis, 'window')
})

describe('renderer Main-owned paid media archive recovery', () => {
  it('discovers and recovers an archive without a renderer-held operation anchor', async () => {
    const operationId = 'desktop-op-11111111-1111-4111-8111-111111111111'
    const archives = [
      {
        operationId,
        path: '/v1/images/generations' as const,
        status: 200,
        kind: 'image' as const,
        archivedAt: 1_800_000_000_000,
        receiptSha256: 'a'.repeat(64),
        responseByteLength: 128,
        assets: []
      }
    ]
    const recovered = {
      operationId,
      path: '/v1/images/generations' as const,
      model: 'image-model',
      status: 200,
      result: { data: [{ url: `nachuan-paid-media://sha256/${'b'.repeat(64)}` }] },
      deliveryProof: {
        operationId,
        resultSha256: 'd'.repeat(64),
        archiveReceiptSha256: 'a'.repeat(64)
      },
      archive: {
        receiptSha256: 'a'.repeat(64),
        responseSha256: 'c'.repeat(64),
        responseByteLength: 128,
        assets: []
      }
    }
    const archivePage = { items: archives }
    const listPaidMediaArchives = vi.fn(async () => archivePage)
    const recoverPaidMediaArchiveIpc = vi.fn(async () => recovered)
    Object.defineProperty(globalThis, 'window', {
      configurable: true,
      value: {
        api: {
          listPaidMediaArchives,
          recoverPaidMediaArchive: recoverPaidMediaArchiveIpc
        }
      }
    })

    await expect(listRecoverablePaidMediaArchives()).resolves.toEqual(archivePage)
    await expect(recoverPaidMediaArchive(operationId)).resolves.toEqual(recovered)
    expect(recoverPaidMediaArchiveIpc).toHaveBeenCalledWith(operationId)
  })

  it('keeps startup discovery visible and persists stable vault references', () => {
    const appSource = readFileSync(new URL('./App.tsx', import.meta.url), 'utf8')
    const storeSource = readFileSync(new URL('./store.ts', import.meta.url), 'utf8')

    expect(appSource).toContain('listRecoverablePaidMediaArchives')
    expect(appSource).toContain('恢复到新对话')
    expect(appSource).toContain('recoverPaidMediaArchive(archive.operationId)')
    expect(appSource).toContain('setConvMessages(conversationId')
    expect(storeSource).toContain('nachuan-paid-media:')
  })
})
