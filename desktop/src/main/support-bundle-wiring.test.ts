import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import { describe, expect, it } from 'vitest'

describe('support bundle Main wiring', () => {
  it('keeps creation in Main and exposes a single help-menu action', () => {
    const source = readFileSync(join(__dirname, 'index.ts'), 'utf8')
    expect(source).toContain("import { createInstalledSupportBundle } from './support-bundle'")
    expect(source).toContain("label('生成脱敏诊断包', 'Create Redacted Support Bundle')")
    expect(source).toContain('createRedactedSupportBundleFromMenu(zh)')
    expect(source).toContain("runtimeProfile: 'store'")
    expect(source).toContain('loadHealth: loadRedactedSupportHealth')
    expect(source.match(/createInstalledSupportBundle\(/g)).toHaveLength(1)
  })

  it('bounds the local health response and never sends an engine key', () => {
    const source = readFileSync(join(__dirname, 'index.ts'), 'utf8')
    const start = source.indexOf('async function loadRedactedSupportHealth')
    const end = source.indexOf('async function createRedactedSupportBundleFromMenu', start)
    const health = source.slice(start, end)
    expect(start).toBeGreaterThan(0)
    expect(end).toBeGreaterThan(start)
    expect(health).toContain('total > 256 * 1024')
    expect(health).toContain("redirect: 'error'")
    expect(health).toContain('controller.abort()')
    expect(health).not.toContain('engineKey')
    expect(health).not.toContain('approvalKey')
    expect(health).not.toContain('paidMediaKey')
  })
})
