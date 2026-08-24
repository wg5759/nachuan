import { createHash } from 'node:crypto'
import { copyFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { afterEach, describe, expect, it } from 'vitest'

import { buildNpmPayloadLicenseInventory } from './license-evidence.mjs'
import {
  assertNoManualLegalReviewBlockers,
  LICENSE_STAGE_CONTENT_FILES,
  LICENSE_STAGE_MANIFEST,
  verifyPackagedLicenseStageCopy
} from './license-stage.mjs'

const roots = []
const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..')
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex')

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { force: true, recursive: true })
})

describe('two-stage packaged license evidence', () => {
  it('accepts the two exact npm MIT notice reconstructions only after version-pinned engineering review', () => {
    const inventory = buildNpmPayloadLicenseInventory({ projectRoot })
    const blockers = inventory.components
      .filter(({ manualLegalReviewRequired }) => manualLegalReviewRequired)
      .map(({ name, version }) => `${name}@${version}`)
    const reviewed = inventory.components
      .filter(({ licenseSource }) => licenseSource === 'metadata-reconstructed-reviewed')
      .map(({ name, version }) => `${name}@${version}`)

    expect(inventory.components).toHaveLength(28)
    expect(reviewed).toEqual(['html-parse-stringify@3.0.1', 'lazy-val@1.0.5'])
    expect(blockers).toEqual([])
    expect(() => assertNoManualLegalReviewBlockers(inventory)).not.toThrow()
    expect(() =>
      assertNoManualLegalReviewBlockers({
        components: [{ name: 'unreviewed', version: '1.0.0', manualLegalReviewRequired: true }]
      })
    ).toThrow(/upstream license text or manual legal review/i)
  })

  it('accepts only an exact byte-for-byte packaged copy of the closed staged file set', async () => {
    const root = mkdtempSync(join(tmpdir(), 'nachuan-license-stage-copy-'))
    roots.push(root)
    const stageRoot = join(root, 'stage')
    const packagedRoot = join(root, 'packaged')
    mkdirSync(stageRoot)
    for (const name of LICENSE_STAGE_CONTENT_FILES) {
      writeFileSync(join(stageRoot, name), Buffer.from(`evidence:${name}\n`, 'utf8'))
    }
    const manifest = {
      files: LICENSE_STAGE_CONTENT_FILES.map((name) => {
        const bytes = Buffer.from(`evidence:${name}\n`, 'utf8')
        return { name, sha256: sha256(bytes), size: bytes.length }
      }),
      schema: 1
    }
    writeFileSync(join(stageRoot, LICENSE_STAGE_MANIFEST), `${JSON.stringify(manifest, null, 2)}\n`)
    mkdirSync(packagedRoot)
    for (const name of [...LICENSE_STAGE_CONTENT_FILES, LICENSE_STAGE_MANIFEST]) {
      copyFileSync(join(stageRoot, name), join(packagedRoot, name))
    }

    await expect(verifyPackagedLicenseStageCopy({ packagedRoot, stageRoot })).resolves.toMatchObject({
      files: expect.arrayContaining([LICENSE_STAGE_MANIFEST, 'THIRD_PARTY_NOTICES.html'])
    })

    writeFileSync(join(packagedRoot, 'THIRD_PARTY_NOTICES.html'), 'replacement\n')
    await expect(verifyPackagedLicenseStageCopy({ packagedRoot, stageRoot })).rejects.toThrow(
      /drifted|differs/i
    )
  })
})
