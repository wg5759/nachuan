import { describe, expect, it } from 'vitest'

import { assemblePythonPayloadProvenance } from './python-payload-provenance.mjs'

const hash = 'a'.repeat(64)
const source = (path) => ({ path, sha256: hash, size: 10 })
const owner = (kind, name, version) => ({ kind, name, version })

function fixture() {
  return {
    archiveEntries: ['PYZ.pyz', 'demo', 'engine_main'],
    engine: { name: 'engine.payload', sha256: 'b'.repeat(64), size: 100 },
    ownership: {
      entries: [
        {
          destination: 'engine_main.py',
          owner: owner('project-source', 'nachuan', 'release-source-snapshot'),
          scope: 'analysis-entry-script',
          source: source('project/engine_main.py'),
          type: 'PYSOURCE'
        },
        {
          destination: 'PYZ.pyz',
          owner: owner('build-output', 'pyinstaller', '6.21.0'),
          scope: 'package',
          source: source('build/engine/PYZ-00.pyz'),
          type: 'PYZ'
        },
        {
          destination: 'demo',
          owner: owner('python-distribution', 'demo', '1.0.0'),
          scope: 'pyz',
          source: source('site-packages/demo/__init__.py'),
          type: 'PYMODULE'
        }
      ],
      schema: 1
    },
    selectedDistributions: [{ name: 'demo', version: '1.0.0' }],
    tocFiles: ['Analysis-00.toc', 'EXE-00.toc', 'PKG-00.toc', 'PYZ-00.toc'].map((name) => ({
      name,
      sha256: hash,
      size: 20
    }))
  }
}

describe('actual PyInstaller payload provenance', () => {
  it('binds final archive entries, TOCs, engine bytes, and exact selected owners', () => {
    const result = assemblePythonPayloadProvenance(fixture())
    expect(result.schema).toBe(1)
    expect(result.engine.sha256).toBe('b'.repeat(64))
    expect(result.archiveEntries).toEqual(['PYZ.pyz', 'demo', 'engine_main'])
    expect(result.components).toEqual([
      owner('build-output', 'pyinstaller', '6.21.0'),
      owner('project-source', 'nachuan', 'release-source-snapshot'),
      owner('python-distribution', 'demo', '1.0.0')
    ])
  })

  it('fails closed on an unselected owner or a TOC destination absent from final archive', () => {
    const unselected = fixture()
    unselected.ownership.entries[2].owner.version = '9.9.9'
    expect(() => assemblePythonPayloadProvenance(unselected)).toThrow(/absent from the selected lock/i)

    const missing = fixture()
    missing.archiveEntries = ['PYZ.pyz', 'engine_main']
    expect(() => assemblePythonPayloadProvenance(missing)).toThrow(/absent from the final recursive archive/i)
  })

  it('fails closed on forbidden Python modules even when TOC ownership claims are valid', () => {
    const forbidden = fixture()
    forbidden.archiveEntries.push('torch')
    expect(() => assemblePythonPayloadProvenance(forbidden)).toThrow(/forbidden Python release payload/i)
  })

  it('accepts legitimately empty source files and python namespace markers', () => {
    const f = fixture()
    // 条目按 scope\0destination\0type\0sourcePath 严格排序插入
    f.ownership.entries.splice(
      1,
      0,
      {
        destination: 'urllib/__init__.py',
        owner: owner('python-runtime', 'cpython', '3.12.9'),
        scope: 'analysis-stdlib',
        source: {
          path: 'python-runtime/Lib/urllib/__init__.py',
          sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
          size: 0
        },
        type: 'PYMODULE'
      }
    )
    f.ownership.entries.push({
      destination: 'setuptools._vendor.jaraco',
      owner: owner('python-namespace-marker', 'setuptools', '83.0.0'),
      scope: 'pyz',
      source: null,
      type: 'PYMODULE'
    })
    f.selectedDistributions.push({ name: 'setuptools', version: '83.0.0' })
    const result = assemblePythonPayloadProvenance(f)
    expect(result.ownershipEntries).toHaveLength(5)
  })

  it('still rejects a null source on real modules and bogus empty-source hashes', () => {
    const realModule = fixture()
    realModule.ownership.entries[2].source = null
    expect(() => assemblePythonPayloadProvenance(realModule)).toThrow(/omit a source descriptor/i)

    const badEmpty = fixture()
    badEmpty.ownership.entries[2].source.size = 0
    expect(() => assemblePythonPayloadProvenance(badEmpty)).toThrow(/source descriptor is invalid/i)

    const unselectedMarker = fixture()
    unselectedMarker.ownership.entries.push({
      destination: 'ghost.ns',
      owner: owner('python-namespace-marker', 'ghost', '1.0.0'),
      scope: 'pyz',
      source: null,
      type: 'PYMODULE'
    })
    expect(() => assemblePythonPayloadProvenance(unselectedMarker)).toThrow(/absent from the selected lock/i)
  })
})
