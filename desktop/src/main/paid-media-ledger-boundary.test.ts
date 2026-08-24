import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import { describe, expect, it } from 'vitest'

describe('paid media desktop trust boundary', () => {
  it('keeps the durable ledger incapable of provider, session, or transport calls', () => {
    const ledger = readFileSync(join(__dirname, 'paid-media-ledger.ts'), 'utf8')

    expect(ledger).not.toMatch(/\bfetch\s*\(|https?\.request\s*\(|EngineSession|providerClient/i)
  })

  it('keeps paid operation state out of renderer-owned storage', () => {
    const rendererRoot = join(__dirname, '..', 'renderer', 'src')
    const journal = readFileSync(join(rendererRoot, 'paid-media-journal.ts'), 'utf8')

    expect(journal).not.toMatch(/\b(?:localStorage|sessionStorage)\b/)
  })

  it('keeps paid idempotency keys out of renderer request code', () => {
    const rendererRoot = join(__dirname, '..', 'renderer', 'src')
    const api = readFileSync(join(rendererRoot, 'api.ts'), 'utf8')

    expect(api).not.toContain("'Idempotency-Key'")
  })

  it('injects the paid capability only into the main-owned engine child', () => {
    const main = readFileSync(join(__dirname, 'index.ts'), 'utf8')

    expect(main).toContain('NACHUAN_PAID_MEDIA_API_KEY: paidMediaKey')
    expect(main).toContain('registerPaidMediaIpc')
    expect(main).not.toMatch(/return\s*\{[^}]*paidMediaKey/s)
  })

  it('authorizes financial IPC against the exact main frame', () => {
    const main = readFileSync(join(__dirname, 'index.ts'), 'utf8')

    expect(main).toMatch(/senderFrame\s*===\s*expectedWindow\.webContents\.mainFrame/)
  })

  it('prevents two desktop main processes from racing the encrypted ledger', () => {
    const main = readFileSync(join(__dirname, 'index.ts'), 'utf8')

    expect(main).toContain('app.requestSingleInstanceLock()')
    expect(main).toContain("app.on('second-instance'")
  })
})
