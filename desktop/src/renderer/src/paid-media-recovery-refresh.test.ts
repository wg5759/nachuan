import { describe, expect, it, vi } from 'vitest'

import { LatestOnlyRefresh } from './paid-media-recovery-refresh'

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (reason?: unknown) => void
  const promise = new Promise<T>((done, fail) => {
    resolve = done
    reject = fail
  })
  return { promise, resolve, reject }
}

describe('paid media recovery latest-only refresh', () => {
  it('does not overlap polls and ignores an old response after manual reconciliation', async () => {
    const first = deferred<string[]>()
    const load = vi.fn(() => first.promise)
    const applied: string[][] = []
    const refresh = new LatestOnlyRefresh<string[]>()

    const running = refresh.run(load, (value) => applied.push(value))
    await refresh.run(load, (value) => applied.push(value))
    expect(load).toHaveBeenCalledTimes(1)

    refresh.invalidate()
    first.resolve(['stale-operation'])
    await running

    expect(applied).toEqual([])
    expect(refresh.running).toBe(false)
  })

  it('applies the next completed generation after an invalidated poll settles', async () => {
    const refresh = new LatestOnlyRefresh<string[]>()
    refresh.invalidate()
    const applied: string[][] = []

    await refresh.run(async () => ['current-operation'], (value) => applied.push(value))

    expect(applied).toEqual([['current-operation']])
  })

  it('does not surface an invalidated stale failure as a current ledger outage', async () => {
    const pending = deferred<string[]>()
    const refresh = new LatestOnlyRefresh<string[]>()
    const failed = vi.fn()
    const running = refresh.run(() => pending.promise, vi.fn(), failed)

    refresh.invalidate()
    pending.reject(new Error('stale read failed'))
    await running

    expect(failed).not.toHaveBeenCalled()
  })
})
