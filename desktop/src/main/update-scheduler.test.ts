import { describe, expect, it, vi } from 'vitest'

import { UpdateCheckScheduler } from './update-scheduler'

describe('long-running update checks', () => {
  it('uses a delayed startup check, 4-6 hour jitter, and single-flight execution', async () => {
    let callback: (() => void) | null = null
    const delays: number[] = []
    let release!: () => void
    const check = vi.fn(
      () =>
        new Promise<void>((resolve) => {
          release = resolve
        })
    )
    const scheduler = new UpdateCheckScheduler({
      check,
      random: () => 0.5,
      setTimer: (next, delay) => {
        callback = next
        delays.push(delay)
        return 1 as unknown as ReturnType<typeof setTimeout>
      },
      clearTimer: () => undefined
    })

    scheduler.start()
    expect(delays[0]).toBe(75_000)
    callback!()
    const concurrent = scheduler.trigger('manual')
    expect(check).toHaveBeenCalledTimes(1)
    release()
    await concurrent
    expect(delays.at(-1)).toBe(5 * 60 * 60 * 1000)
  })

  it('backs off failures and lets network recovery retry after the debounce window', async () => {
    let now = 1_000_000
    const delays: number[] = []
    const check = vi.fn().mockRejectedValueOnce(new Error('offline')).mockResolvedValue(undefined)
    const scheduler = new UpdateCheckScheduler({
      check,
      now: () => now,
      random: () => 0,
      setTimer: (_next, delay) => {
        delays.push(delay)
        return 1 as unknown as ReturnType<typeof setTimeout>
      },
      clearTimer: () => undefined
    })
    scheduler.start()

    await expect(scheduler.trigger('startup')).rejects.toThrow(/offline/)
    expect(delays.at(-1)).toBe(5 * 60 * 1000)
    await scheduler.networkRecovered()
    expect(check).toHaveBeenCalledTimes(1)
    now += 61_000
    await scheduler.networkRecovered()
    expect(check).toHaveBeenCalledTimes(2)
  })
})
