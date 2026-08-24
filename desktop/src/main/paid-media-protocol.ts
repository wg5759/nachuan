import { Readable } from 'node:stream'

import type { PaidMediaOpenAsset } from './paid-media-vault'

interface PaidMediaAssetOpener {
  openAsset(reference: string): Promise<PaidMediaOpenAsset>
}

class PaidMediaRangeError extends Error {}

function parseSingleRange(
  raw: string | null,
  byteLength: number
): { start: number; end: number } | null {
  if (raw === null) return null
  if (raw.length > 128 || raw.includes(',')) throw new PaidMediaRangeError('invalid range')
  const matched = /^bytes=(\d*)-(\d*)$/.exec(raw.trim())
  if (!matched || (!matched[1] && !matched[2])) {
    throw new PaidMediaRangeError('invalid range')
  }
  if (!matched[1]) {
    const suffix = Number(matched[2])
    if (!Number.isSafeInteger(suffix) || suffix < 1) {
      throw new PaidMediaRangeError('invalid range')
    }
    return { start: Math.max(0, byteLength - suffix), end: byteLength - 1 }
  }
  const start = Number(matched[1])
  const requestedEnd = matched[2] ? Number(matched[2]) : byteLength - 1
  if (
    !Number.isSafeInteger(start) ||
    !Number.isSafeInteger(requestedEnd) ||
    start < 0 ||
    start >= byteLength ||
    requestedEnd < start
  ) {
    throw new PaidMediaRangeError('unsatisfiable range')
  }
  return { start, end: Math.min(requestedEnd, byteLength - 1) }
}

function baseHeaders(asset: PaidMediaOpenAsset): Headers {
  return new Headers({
    'Content-Type': asset.mediaType,
    'Accept-Ranges': 'bytes',
    'Cache-Control': 'private, no-store',
    'X-Content-Type-Options': 'nosniff'
  })
}

export async function handlePaidMediaAssetRequest(
  request: Request,
  vault: PaidMediaAssetOpener
): Promise<Response> {
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    return new Response('Method Not Allowed', {
      status: 405,
      headers: {
        Allow: 'GET, HEAD',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff'
      }
    })
  }
  let asset: PaidMediaOpenAsset
  try {
    asset = await vault.openAsset(request.url)
  } catch {
    return new Response('Not Found', {
      status: 404,
      headers: {
        'Content-Type': 'text/plain; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff'
      }
    })
  }

  let range: { start: number; end: number } | null
  try {
    range = parseSingleRange(request.headers.get('range'), asset.byteLength)
  } catch (error) {
    if (!(error instanceof PaidMediaRangeError)) throw error
    await asset.handle.close().catch(() => undefined)
    return new Response(null, {
      status: 416,
      headers: {
        'Content-Range': `bytes */${asset.byteLength}`,
        'Accept-Ranges': 'bytes',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff'
      }
    })
  }

  const start = range?.start ?? 0
  const end = range?.end ?? asset.byteLength - 1
  const responseLength = end - start + 1
  const headers = baseHeaders(asset)
  headers.set('Content-Length', String(responseLength))
  if (range) headers.set('Content-Range', `bytes ${start}-${end}/${asset.byteLength}`)
  if (request.method === 'HEAD') {
    await asset.handle.close().catch(() => undefined)
    return new Response(null, { status: range ? 206 : 200, headers })
  }
  const source = asset.handle.createReadStream({ start, end, autoClose: true })
  const body = Readable.toWeb(source) as unknown as BodyInit
  return new Response(body, { status: range ? 206 : 200, headers })
}
