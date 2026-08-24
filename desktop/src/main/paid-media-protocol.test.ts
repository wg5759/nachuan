import { mkdtempSync, renameSync, rmSync, writeFileSync } from 'node:fs'
import { open as openFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { handlePaidMediaAssetRequest } from './paid-media-protocol'
import type { PaidMediaOpenAsset } from './paid-media-vault'

const roots: string[] = []

afterEach(() => {
  while (roots.length > 0) rmSync(roots.pop()!, { recursive: true, force: true })
}, 60_000)

function fixture(): {
  url: string
  bytes: Buffer
  openAsset: ReturnType<
    typeof vi.fn<(reference: string) => Promise<PaidMediaOpenAsset>>
  >
} {
  const root = mkdtempSync(join(tmpdir(), 'nachuan-paid-protocol-'))
  roots.push(root)
  const bytes = Buffer.from('0123456789', 'ascii')
  const path = join(root, 'asset.mp4')
  writeFileSync(path, bytes)
  const url = `nachuan-paid-media://sha256/${'a'.repeat(64)}`
  const openAsset = vi.fn<(reference: string) => Promise<PaidMediaOpenAsset>>(async () => ({
    handle: await openFile(path, 'r'),
    byteLength: bytes.length,
    mediaType: 'video/mp4' as const,
    sha256: 'a'.repeat(64)
  }))
  return { url, bytes, openAsset }
}

describe('paid media asset protocol', () => {
  it('streams full GET and metadata-only HEAD responses', async () => {
    const item = fixture()
    const get = await handlePaidMediaAssetRequest(new Request(item.url), {
      openAsset: item.openAsset
    })
    expect(get.status).toBe(200)
    expect(get.headers.get('accept-ranges')).toBe('bytes')
    expect(get.headers.get('content-length')).toBe(String(item.bytes.length))
    expect(Buffer.from(await get.arrayBuffer())).toEqual(item.bytes)

    const head = await handlePaidMediaAssetRequest(
      new Request(item.url, { method: 'HEAD' }),
      { openAsset: item.openAsset }
    )
    expect(head.status).toBe(200)
    expect(head.headers.get('content-length')).toBe(String(item.bytes.length))
    expect(await head.text()).toBe('')
  })

  it('serves one bounded byte range with 206 and supports suffix ranges', async () => {
    const item = fixture()
    const middle = await handlePaidMediaAssetRequest(
      new Request(item.url, { headers: { Range: 'bytes=2-5' } }),
      { openAsset: item.openAsset }
    )
    expect(middle.status).toBe(206)
    expect(middle.headers.get('content-range')).toBe('bytes 2-5/10')
    expect(middle.headers.get('content-length')).toBe('4')
    expect(await middle.text()).toBe('2345')

    const suffix = await handlePaidMediaAssetRequest(
      new Request(item.url, { headers: { Range: 'bytes=-3' } }),
      { openAsset: item.openAsset }
    )
    expect(suffix.status).toBe(206)
    expect(await suffix.text()).toBe('789')
  })

  it('fails closed for multiple or unsatisfiable ranges and non-read methods', async () => {
    const item = fixture()
    for (const range of ['bytes=0-1,3-4', 'bytes=99-100', 'items=0-1']) {
      const response = await handlePaidMediaAssetRequest(
        new Request(item.url, { headers: { Range: range } }),
        { openAsset: item.openAsset }
      )
      expect(response.status).toBe(416)
      expect(response.headers.get('content-range')).toBe('bytes */10')
    }
    const post = await handlePaidMediaAssetRequest(
      new Request(item.url, { method: 'POST' }),
      { openAsset: item.openAsset }
    )
    expect(post.status).toBe(405)
    expect(item.openAsset).toHaveBeenCalledTimes(3)
  })

  it('streams the pinned file object when its pathname is replaced after verification', async () => {
    const root = mkdtempSync(join(tmpdir(), 'nachuan-paid-protocol-pin-'))
    roots.push(root)
    const path = join(root, 'asset.mp4')
    const displaced = join(root, 'verified.mp4')
    const original = Buffer.from('verified-original', 'ascii')
    writeFileSync(path, original)
    const openAsset = vi.fn(async () => {
      const handle = await openFile(path, 'r')
      renameSync(path, displaced)
      writeFileSync(path, 'attacker-replacement')
      return {
        handle,
        byteLength: original.length,
        mediaType: 'video/mp4' as const,
        sha256: 'b'.repeat(64)
      }
    })

    const response = await handlePaidMediaAssetRequest(
      new Request(`nachuan-paid-media://sha256/${'b'.repeat(64)}`),
      { openAsset }
    )
    expect(response.status).toBe(200)
    expect(Buffer.from(await response.arrayBuffer())).toEqual(original)
  })
})
