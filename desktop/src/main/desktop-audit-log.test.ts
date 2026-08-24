import { readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'

import { DesktopAuditLog } from './desktop-audit-log'

const roots: string[] = []

afterEach(async () => {
  const { rm } = await import('node:fs/promises')
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })))
})

describe('desktop production audit log', () => {
  it('redacts sensitive fields and rotates bounded files', async () => {
    const { mkdtemp } = await import('node:fs/promises')
    const { tmpdir } = await import('node:os')
    const root = await mkdtemp(join(tmpdir(), 'nachuan-desktop-log-'))
    roots.push(root)
    const log = new DesktopAuditLog(root, 32, 2)
    log.write('engine.spawn', { pid: 123, engineKey: 'must-not-leak', payload: 'private' })
    const first = readFileSync(log.path, 'utf8')
    expect(first).toContain('engine.spawn')
    expect(first).toContain('[redacted]')
    expect(first).not.toContain('must-not-leak')
    writeFileSync(log.path, 'x'.repeat(64), 'utf8')
    log.write('engine.ready', { pid: 123 })
    expect(readFileSync(`${log.path}.1`, 'utf8')).toHaveLength(64)
    expect(readFileSync(log.path, 'utf8')).toContain('engine.ready')
  })
})
