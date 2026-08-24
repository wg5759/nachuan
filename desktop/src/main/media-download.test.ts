import { mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Readable, Writable } from 'node:stream'
import { pipeline } from 'node:stream/promises'

import { afterEach, describe, expect, it } from 'vitest'

import {
  downloadPublicMedia,
  isPublicMediaAddress,
  MediaByteLimitTransform,
  resolvePublicMediaTarget,
  writeBoundedMediaBytes
} from './media-download'

const roots: string[] = []

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })))
})

describe('bounded public media download policy', () => {
  it('classifies public addresses narrowly and rejects every local/special family', () => {
    expect(isPublicMediaAddress('93.184.216.34')).toBe(true)
    expect(isPublicMediaAddress('2606:4700:4700::1111')).toBe(true)
    for (const address of [
      '0.0.0.0',
      '10.0.0.1',
      '100.64.0.1',
      '127.0.0.1',
      '169.254.1.1',
      '172.16.0.1',
      '192.168.1.1',
      '198.18.0.1',
      '203.0.113.8',
      '224.0.0.1',
      '::1',
      '::ffff:127.0.0.1',
      'fc00::1',
      'fe80::1',
      '2001:db8::1'
    ]) {
      expect(isPublicMediaAddress(address), address).toBe(false)
    }
  })

  it('accepts only all-public DNS and rejects private, mixed, credentialed, and odd-port URLs', async () => {
    const publicResolver = async (): Promise<{ address: string; family: number }[]> => [
      { address: '93.184.216.34', family: 4 },
      { address: '2606:4700:4700::1111', family: 6 }
    ]
    const target = await resolvePublicMediaTarget('https://cdn.example/media.mp4#ignored', publicResolver)
    expect(target.url.toString()).toBe('https://cdn.example/media.mp4')
    expect(target.address).toBe('93.184.216.34')

    const mixedResolver = async (): Promise<{ address: string; family: number }[]> => [
      { address: '93.184.216.34', family: 4 },
      { address: '127.0.0.1', family: 4 }
    ]
    await expect(resolvePublicMediaTarget('https://cdn.example/x', mixedResolver)).rejects.toThrow(
      /exclusively to public/
    )
    await expect(resolvePublicMediaTarget('http://127.0.0.1/x')).rejects.toThrow(/public/)
    await expect(resolvePublicMediaTarget('http://2130706433/x')).rejects.toThrow(/public/)
    await expect(resolvePublicMediaTarget('https://user:pass@cdn.example/x', publicResolver)).rejects.toThrow(
      /credentials/
    )
    await expect(resolvePublicMediaTarget('https://cdn.example:444/x', publicResolver)).rejects.toThrow(
      /default port/
    )
  })

  it('writes inline bytes atomically within the configured bound', async () => {
    const root = await mkdtemp(join(tmpdir(), 'nachuan-media-write-'))
    roots.push(root)
    const destination = join(root, 'image.png')
    const bytes = new Uint8Array([1, 2, 3]).buffer
    await expect(writeBoundedMediaBytes(destination, bytes, 3)).resolves.toBe(3)
    expect([...new Uint8Array(await readFile(destination))]).toEqual([1, 2, 3])

    const rejected = join(root, 'too-large.png')
    await expect(writeBoundedMediaBytes(rejected, bytes, 2)).rejects.toThrow(/size limit/)
    await expect(stat(rejected)).rejects.toMatchObject({ code: 'ENOENT' })
  })

  it('rejects loopback before opening a destination file', async () => {
    const root = await mkdtemp(join(tmpdir(), 'nachuan-media-download-'))
    roots.push(root)
    const destination = join(root, 'blocked.mp4')
    await expect(downloadPublicMedia('http://127.0.0.1/private', destination)).rejects.toThrow(
      /public/
    )
    await expect(stat(destination)).rejects.toMatchObject({ code: 'ENOENT' })
  })

  it('revalidates every redirect target and rejects a private second hop', async () => {
    const root = await mkdtemp(join(tmpdir(), 'nachuan-media-redirect-'))
    roots.push(root)
    const destination = join(root, 'redirect.mp4')
    const resolved: string[] = []
    const resolver = async (hostname: string): Promise<{ address: string; family: number }[]> => {
      resolved.push(hostname)
      return [
        {
          address: hostname === 'private.example' ? '127.0.0.1' : '93.184.216.34',
          family: 4
        }
      ]
    }
    const attempt = async (): Promise<{ redirect: string }> => ({
      redirect: 'https://private.example/secret.mp4'
    })
    await expect(
      downloadPublicMedia('https://public.example/start', destination, 1024, {
        resolver,
        attempt,
        totalTimeoutMs: 1000
      })
    ).rejects.toThrow(/exclusively to public/)
    expect(resolved).toEqual(['public.example', 'private.example'])
    await expect(stat(destination)).rejects.toMatchObject({ code: 'ENOENT' })
  })

  it('commits a successful redirected download and removes partial files after failure', async () => {
    const root = await mkdtemp(join(tmpdir(), 'nachuan-media-atomic-'))
    roots.push(root)
    const resolver = async (): Promise<{ address: string; family: number }[]> => [
      { address: '93.184.216.34', family: 4 }
    ]
    const destination = join(root, 'ok.mp4')
    let attempts = 0
    const deadlines: number[] = []
    const attempt = async (
      _target: unknown,
      temporaryPath: string,
      _maxBytes: number,
      deadline: number
    ): Promise<{ redirect: string } | { bytes: number }> => {
      attempts += 1
      deadlines.push(deadline)
      if (attempts === 1) return { redirect: 'https://cdn2.example/final.mp4' }
      await writeFile(temporaryPath, Buffer.from([4, 5, 6]), { flag: 'wx' })
      return { bytes: 3 }
    }
    await expect(
      downloadPublicMedia('https://cdn1.example/start', destination, 1024, {
        resolver,
        attempt,
        totalTimeoutMs: 1000
      })
    ).resolves.toBe(3)
    expect([...new Uint8Array(await readFile(destination))]).toEqual([4, 5, 6])
    expect(deadlines).toHaveLength(2)
    expect(new Set(deadlines).size).toBe(1)

    const failed = join(root, 'failed.mp4')
    const partialAttempt = async (_target: unknown, temporaryPath: string): Promise<never> => {
      await writeFile(temporaryPath, Buffer.from([9, 9]), { flag: 'wx' })
      throw new Error('synthetic transport failure')
    }
    await expect(
      downloadPublicMedia('https://cdn.example/fail', failed, 1024, {
        resolver,
        attempt: partialAttempt,
        totalTimeoutMs: 1000
      })
    ).rejects.toThrow(/synthetic transport/)
    await expect(stat(failed)).rejects.toMatchObject({ code: 'ENOENT' })
    expect(await readdir(root)).toEqual(['ok.mp4'])
  })

  it('bounds unknown-length streams and applies one deadline to DNS before any request', async () => {
    const limiter = new MediaByteLimitTransform(3)
    await expect(
      pipeline(
        Readable.from([Buffer.from([1, 2]), Buffer.from([3, 4])]),
        limiter,
        new Writable({ write(_chunk, _encoding, callback): void { callback() } })
      )
    ).rejects.toThrow(/size limit/)

    const root = await mkdtemp(join(tmpdir(), 'nachuan-media-deadline-'))
    roots.push(root)
    const destination = join(root, 'timeout.mp4')
    const neverResolver = async (): Promise<{ address: string; family: number }[]> =>
      await new Promise(() => undefined)
    const started = Date.now()
    await expect(
      downloadPublicMedia('https://slow.example/file.mp4', destination, 1024, {
        resolver: neverResolver,
        totalTimeoutMs: 30
      })
    ).rejects.toThrow(/DNS resolution timeout/)
    expect(Date.now() - started).toBeLessThan(1000)
    await expect(stat(destination)).rejects.toMatchObject({ code: 'ENOENT' })
  })
})
