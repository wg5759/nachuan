import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

import { describe, expect, it } from 'vitest'
import { storeMsixReadiness } from './store-msix-readiness.mjs'


const valid = Object.freeze({
  NACHUAN_STORE_APPLICATION_ID: 'Nachuan',
  NACHUAN_STORE_IDENTITY_NAME: 'Reserved.PartnerCenter.Nachuan',
  NACHUAN_STORE_PUBLISHER: 'CN=Reserved Publisher, O=Reserved Company, C=CN',
  NACHUAN_STORE_PUBLISHER_DISPLAY_NAME: 'Reserved Publisher'
})

describe('Microsoft Store MSIX readiness', () => {
  it('fails closed until every Partner Center identity field exists', () => {
    expect(storeMsixReadiness({})).toEqual({
      ready: false,
      reason: 'partner_center_identity_missing',
      missing: [
        'NACHUAN_STORE_APPLICATION_ID',
        'NACHUAN_STORE_IDENTITY_NAME',
        'NACHUAN_STORE_PUBLISHER',
        'NACHUAN_STORE_PUBLISHER_DISPLAY_NAME'
      ]
    })
  })

  it('accepts an exact reserved identity without claiming certification', () => {
    expect(storeMsixReadiness(valid)).toMatchObject({
      ready: true,
      version: '0.2.0',
      target: 'appx',
      signing: 'microsoft_store_resigns_after_certification'
    })
  })

  it.each([
    ['NACHUAN_STORE_APPLICATION_ID', 'Nachuan App'],
    ['NACHUAN_STORE_IDENTITY_NAME', 'bad identity'],
    ['NACHUAN_STORE_PUBLISHER', 'not-a-subject'],
    ['NACHUAN_STORE_PUBLISHER_DISPLAY_NAME', 'bad\nname']
  ])('rejects unsafe %s', (field, value) => {
    expect(() => storeMsixReadiness({ ...valid, [field]: value })).toThrow()
  })

  it('keeps the committed builder config identity-free and AppX-only', () => {
    const config = readFileSync(resolve(process.cwd(), 'electron-builder.store-msix.yml'), 'utf8')
    expect(config).toContain('target:\n    - appx')
    expect(config).not.toContain('- nsis')
    expect(config).toContain('${env.NACHUAN_STORE_IDENTITY_NAME}')
    expect(config).toContain('${env.NACHUAN_STORE_PUBLISHER}')
    expect(config).not.toContain('CN=杭州')
  })
})
