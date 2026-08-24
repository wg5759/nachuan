import { beforeEach, describe, expect, it, vi } from 'vitest'

const STORAGE_KEY = 'nachuan.paid-media.pending.v1'
const UUID = '11111111-1111-4111-8111-111111111111'

function storage(initial?: string): Storage {
  const values = new Map<string, string>()
  if (initial !== undefined) values.set(STORAGE_KEY, initial)
  return {
    get length() {
      return values.size
    },
    clear: vi.fn(() => values.clear()),
    getItem: vi.fn((key: string) => values.get(key) ?? null),
    key: vi.fn((index: number) => [...values.keys()][index] ?? null),
    removeItem: vi.fn((key: string) => values.delete(key)),
    setItem: vi.fn((key: string, value: string) => values.set(key, value))
  }
}

function legacyRecord(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    schema: 1,
    records: [
      {
        operationId: `desktop-op-${UUID}`,
        idempotencyKey: `desktop-${UUID}`,
        path: '/v1/images/generations',
        requestSha256: 'a'.repeat(64),
        createdAt: 1_750_000_000_000,
        updatedAt: 1_750_000_000_010,
        state: 'recoverable',
        lastStatus: 503,
        retryAfterSeconds: 3,
        ...overrides
      }
    ]
  })
}

describe('legacy paid media renderer migration', () => {
  beforeEach(() => {
    vi.resetModules()
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  it('imports one strict legacy operation without sending its idempotency key', async () => {
    const localStorage = storage(legacyRecord())
    const importLegacyPaidMediaJournal = vi.fn().mockResolvedValue(undefined)
    vi.stubGlobal('localStorage', localStorage)
    vi.stubGlobal('window', { api: { importLegacyPaidMediaJournal } })
    const { ensureLegacyPaidMediaMigrated } = await import('./paid-media-legacy-migration')

    await ensureLegacyPaidMediaMigrated()

    expect(importLegacyPaidMediaJournal).toHaveBeenCalledWith({
      operationId: `desktop-op-${UUID}`,
      path: '/v1/images/generations',
      requestSha256: 'a'.repeat(64),
      createdAt: 1_750_000_000_000,
      updatedAt: 1_750_000_000_010,
      state: 'recoverable',
      lastStatus: 503,
      retryAfterSeconds: 3
    })
    expect(JSON.stringify(importLegacyPaidMediaJournal.mock.calls)).not.toContain('idempotencyKey')
    expect(localStorage.getItem(STORAGE_KEY)).toMatch(/renderer-migrated\.v2/)
  })

  it('leaves the old journal untouched when main import fails', async () => {
    const raw = legacyRecord()
    const localStorage = storage(raw)
    vi.stubGlobal('localStorage', localStorage)
    vi.stubGlobal('window', {
      api: { importLegacyPaidMediaJournal: vi.fn().mockRejectedValue(new Error('ledger unavailable')) }
    })
    const { ensureLegacyPaidMediaMigrated } = await import('./paid-media-legacy-migration')

    await expect(ensureLegacyPaidMediaMigrated()).rejects.toThrow('ledger unavailable')
    expect(localStorage.getItem(STORAGE_KEY)).toBe(raw)
  })

  it('fails closed on a mismatched legacy key before invoking main', async () => {
    const raw = legacyRecord({ idempotencyKey: 'desktop-22222222-2222-4222-8222-222222222222' })
    const localStorage = storage(raw)
    const importLegacyPaidMediaJournal = vi.fn()
    vi.stubGlobal('localStorage', localStorage)
    vi.stubGlobal('window', { api: { importLegacyPaidMediaJournal } })
    const { ensureLegacyPaidMediaMigrated, PaidMediaLegacyMigrationError } = await import(
      './paid-media-legacy-migration'
    )

    await expect(ensureLegacyPaidMediaMigrated()).rejects.toBeInstanceOf(
      PaidMediaLegacyMigrationError
    )
    expect(importLegacyPaidMediaJournal).not.toHaveBeenCalled()
    expect(localStorage.getItem(STORAGE_KEY)).toBe(raw)
  })

  it('writes a downgrade-blocking sentinel even when no old record exists', async () => {
    const localStorage = storage()
    const importLegacyPaidMediaJournal = vi.fn()
    vi.stubGlobal('localStorage', localStorage)
    vi.stubGlobal('window', { api: { importLegacyPaidMediaJournal } })
    const { ensureLegacyPaidMediaMigrated } = await import('./paid-media-legacy-migration')

    await ensureLegacyPaidMediaMigrated()

    expect(importLegacyPaidMediaJournal).toHaveBeenCalledWith(null)
    expect(localStorage.getItem(STORAGE_KEY)).toMatch(/renderer-migrated\.v2/)
  })

  it('submits the exact bounded migration marker to Main on later starts', async () => {
    const sentinel = JSON.stringify({
      schema: 'nachuan.paid-media.renderer-migrated.v2',
      migratedAt: 1_800_000_000_000
    })
    const localStorage = storage(sentinel)
    const importLegacyPaidMediaJournal = vi.fn()
    vi.stubGlobal('localStorage', localStorage)
    vi.stubGlobal('window', { api: { importLegacyPaidMediaJournal } })
    const { ensureLegacyPaidMediaMigrated } = await import('./paid-media-legacy-migration')

    await ensureLegacyPaidMediaMigrated()

    expect(importLegacyPaidMediaJournal).toHaveBeenCalledWith({ kind: 'migrated' })
    expect(localStorage.setItem).not.toHaveBeenCalled()
  })

  it('does not let a forged renderer sentinel replace a missing closed Main seal', async () => {
    const sentinel = JSON.stringify({
      schema: 'nachuan.paid-media.renderer-migrated.v2',
      migratedAt: 1_800_000_000_000
    })
    const localStorage = storage(sentinel)
    const importLegacyPaidMediaJournal = vi
      .fn()
      .mockRejectedValue(new Error('durable legacy seal is open'))
    vi.stubGlobal('localStorage', localStorage)
    vi.stubGlobal('window', { api: { importLegacyPaidMediaJournal } })
    const { ensureLegacyPaidMediaMigrated } = await import('./paid-media-legacy-migration')

    await expect(ensureLegacyPaidMediaMigrated()).rejects.toThrow('durable legacy seal is open')

    expect(importLegacyPaidMediaJournal).toHaveBeenCalledWith({ kind: 'migrated' })
    expect(localStorage.setItem).not.toHaveBeenCalled()
    expect(localStorage.getItem(STORAGE_KEY)).toBe(sentinel)
  })
})
