import { readFileSync } from 'node:fs'

import { describe, expect, it } from 'vitest'

import { assertFixedPackagedUserDataDirectory } from './startup-policy'

describe('packaged profile authority', () => {
  it('rejects a packaged --user-data-dir override before single-instance ownership', () => {
    expect(() =>
      assertFixedPackagedUserDataDirectory({ isPackaged: true, hasUserDataDirSwitch: true })
    ).toThrow(/PACKAGED_USER_DATA_DIR_OVERRIDE_FORBIDDEN/)
  })

  it('does not reject development profiles or a normal packaged launch', () => {
    expect(() =>
      assertFixedPackagedUserDataDirectory({ isPackaged: false, hasUserDataDirSwitch: true })
    ).not.toThrow()
    expect(() =>
      assertFixedPackagedUserDataDirectory({ isPackaged: true, hasUserDataDirSwitch: false })
    ).not.toThrow()
  })

  it('enforces the packaged profile policy before requesting single-instance ownership', () => {
    const source = readFileSync(new URL('./index.ts', import.meta.url), 'utf8')
    const policyIndex = source.indexOf('assertFixedPackagedUserDataDirectory({')
    const ownershipIndex = source.indexOf('app.requestSingleInstanceLock()')

    expect(policyIndex).toBeGreaterThan(-1)
    expect(ownershipIndex).toBeGreaterThan(policyIndex)
  })
})
