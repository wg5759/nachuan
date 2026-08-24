import { createHash } from 'node:crypto'
import { mkdir, mkdtemp, readFile, rm, unlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import Ajv from 'ajv'
import { describe, expect, it } from 'vitest'

import {
  buildNpmLicenseInventory,
  buildThirdPartyNotices,
  checkedSpdxExpression,
  createPythonLicenseEvidenceClient,
  LICENSE_EVIDENCE_FILES,
  validateNativeLicenseRegistry,
  validatePythonLicenseInventory,
  verifyNativeCycloneDxSbom,
  writeLicenseEvidenceFiles,
  writeNativeCycloneDxSbom
} from './license-evidence.mjs'
import { writeTreeManifest } from './installer-closure.mjs'

const sha256 = (value) => createHash('sha256').update(value).digest('hex')

const CYCLONEDX_15_SCHEMA = 'http://cyclonedx.org/schema/bom-1.5.schema.json'

// Pinned subset of the official CycloneDX 1.5 JSON schema that guards the
// licenseChoice branch used by this exporter.  In 1.5 an SPDX expression is a
// single array item; several obligations must be combined into that one SPDX
// expression rather than emitted as several expression objects.
const cycloneDx15NativeConstraints = {
  type: 'object',
  required: ['$schema', 'bomFormat', 'components', 'dependencies', 'metadata', 'specVersion', 'version'],
  properties: {
    $schema: { const: CYCLONEDX_15_SCHEMA },
    bomFormat: { const: 'CycloneDX' },
    specVersion: { const: '1.5' },
    version: { type: 'integer', minimum: 1 },
    components: {
      type: 'array',
      minItems: 1,
      items: {
        type: 'object',
        required: ['bom-ref', 'licenses', 'name', 'type'],
        properties: {
          'bom-ref': { type: 'string', minLength: 1 },
          licenses: {
            oneOf: [
              {
                type: 'array',
                minItems: 1,
                items: {
                  type: 'object',
                  required: ['license'],
                  properties: { license: { type: 'object' } },
                  additionalProperties: false
                }
              },
              {
                type: 'array',
                minItems: 1,
                maxItems: 1,
                items: {
                  type: 'object',
                  required: ['expression'],
                  properties: { expression: { type: 'string', minLength: 1 } },
                  additionalProperties: false
                }
              }
            ]
          },
          name: { type: 'string', minLength: 1 },
          type: { enum: ['application', 'file', 'library'] }
        }
      }
    },
    dependencies: {
      type: 'array',
      minItems: 1,
      items: {
        type: 'object',
        required: ['dependsOn', 'ref'],
        properties: {
          dependsOn: { type: 'array', uniqueItems: true, items: { type: 'string', minLength: 1 } },
          ref: { type: 'string', minLength: 1 }
        },
        additionalProperties: false
      }
    }
  }
}

function minimalPeBytes() {
  const bytes = Buffer.alloc(0x84)
  bytes.write('MZ', 0, 'ascii')
  bytes.writeUInt32LE(0x80, 0x3c)
  bytes.write('PE\0\0', 0x80, 'binary')
  return bytes
}


async function createSingleArtifactNativeFixture(prefix) {
  const root = await mkdtemp(join(tmpdir(), prefix))
  const unpackedRoot = join(root, 'win-unpacked')
  const licensesRoot = join(unpackedRoot, 'resources', 'licenses')
  const manifestPath = join(root, 'WIN_UNPACKED_MANIFEST.json')
  const sbomPath = join(root, 'NATIVE_SBOM.cdx.json')
  await mkdir(licensesRoot, { recursive: true })
  await writeFile(join(unpackedRoot, 'app.exe'), 'native-app')
  await writeFile(
    join(licensesRoot, 'NATIVE_PAYLOAD_LICENSES.json'),
    `${JSON.stringify({
      components: [
        {
          artifacts: ['app.exe'],
          id: 'electron-runtime',
          licenseExpression: 'MIT',
          name: 'Electron runtime',
          notices: [
            {
              path: 'LICENSE.electron.txt',
              sha256: 'fb4331de5e879f8e43710612b381a10a19cf10292b9f38edb81cbf7b3a81124c',
              size: 18,
              text: 'Electron license.\n'
            }
          ],
          sourceUrl: 'https://github.com/electron/electron/releases/tag/v39.8.5',
          version: '39.8.5'
        }
      ],
      ecosystem: 'native',
      schema: 1
    }, null, 2)}\n`
  )
  await writeTreeManifest({ root: unpackedRoot, output: manifestPath, variant: 'lean', version: '0.2.0' })
  return { manifestPath, root, sbomPath, unpackedRoot }
}


describe('third-party license evidence', () => {
  it('extracts a canonical SPDX license inventory from the npm CycloneDX SBOM', () => {
    const result = buildNpmLicenseInventory({
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      version: 1,
      components: [
        {
          type: 'library',
          name: 'react',
          version: '18.3.1',
          purl: 'pkg:npm/react@18.3.1',
          licenses: [{ license: { id: 'MIT' } }]
        },
        {
          type: 'library',
          name: 'dual-license',
          version: '2.0.0',
          purl: 'pkg:npm/dual-license@2.0.0',
          licenses: [{ expression: 'MIT OR Apache-2.0' }]
        }
      ]
    })

    expect(result).toEqual({
      components: [
        {
          licenseExpression: 'MIT OR Apache-2.0',
          name: 'dual-license',
          purl: 'pkg:npm/dual-license@2.0.0',
          version: '2.0.0'
        },
        {
          licenseExpression: 'MIT',
          name: 'react',
          purl: 'pkg:npm/react@18.3.1',
          version: '18.3.1'
        }
      ],
      ecosystem: 'npm',
      schema: 1
    })
  })

  it.each(['UNKNOWN', 'NOASSERTION', '', 'Made-Up-License-1.0'])(
    'fails closed on an unknown npm license declaration (%s)',
    (declared) => {
      expect(() =>
        buildNpmLicenseInventory({
          bomFormat: 'CycloneDX',
          specVersion: '1.5',
          version: 1,
          components: [
            {
              type: 'library',
              name: 'unsafe-license',
              version: '1.0.0',
              purl: 'pkg:npm/unsafe-license@1.0.0',
              licenses: [{ license: { id: declared } }]
            }
          ]
        })
      ).toThrow(/empty or unknown|unrecognized SPDX license id/)
    }
  )

  it('allows an explicit SPDX LicenseRef only for a reviewed native registry', () => {
    expect(() => checkedSpdxExpression('LicenseRef-Reviewed-Bundle')).toThrow(/unrecognized SPDX/)
    expect(
      checkedSpdxExpression('LicenseRef-Reviewed-Bundle', 'native bundle license', {
        allowLicenseRefs: true
      })
    ).toBe('LicenseRef-Reviewed-Bundle')
  })

  it('accepts the official SPDX ids emitted by the frozen Python environment', () => {
    expect(checkedSpdxExpression('Apache-2.0 AND CNRI-Python')).toBe(
      'Apache-2.0 AND CNRI-Python'
    )
    expect(checkedSpdxExpression('Apache-2.0 AND BSL-1.0')).toBe(
      'Apache-2.0 AND BSL-1.0'
    )
  })

  it('accepts only schema/tool-bound Python license evidence covering the Python SBOM exactly', () => {
    const licenseText = 'MIT license text.\n'
    const runtimeText = 'CPython license text.\n'
    const document = {
      components: [
        {
          licenseExpression: 'MIT',
          licenseFiles: [
            {
              path: 'demo-1.0.dist-info/licenses/LICENSE',
              sha256: sha256(licenseText),
              size: Buffer.byteLength(licenseText),
              text: licenseText
            }
          ],
          licenseSource: 'metadata-license-expression',
          name: 'demo',
          version: '1.0'
        }
      ],
      runtime: {
        implementation: 'CPython',
        licenseFile: {
          path: 'LICENSE.txt',
          sha256: sha256(runtimeText),
          size: Buffer.byteLength(runtimeText),
          text: runtimeText
        },
        version: '3.12.9'
      },
      schema: 1,
      tool: { name: 'nachuan-python-license-exporter', version: '1.0.0' }
    }
    const sbom = {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      components: [{ type: 'library', name: 'demo', version: '1.0', purl: 'pkg:pypi/demo@1.0' }]
    }

    expect(validatePythonLicenseInventory(document, sbom)).toEqual(document)
  })

  it('accepts one installed Python version from same-name lock marker candidates', () => {
    const text = 'MIT license.\n'
    const document = {
      components: [
        {
          licenseExpression: 'MIT',
          licenseFiles: [
            { path: 'demo-2.0.dist-info/LICENSE', sha256: sha256(text), size: text.length, text }
          ],
          licenseSource: 'metadata-license-expression',
          name: 'demo',
          version: '2.0'
        }
      ],
      runtime: {
        implementation: 'CPython',
        licenseFile: { path: 'LICENSE.txt', sha256: sha256(text), size: text.length, text },
        version: '3.12.9'
      },
      schema: 1,
      tool: { name: 'nachuan-python-license-exporter', version: '1.0.0' }
    }
    const sbom = {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      components: [
        { type: 'library', name: 'demo', version: '1.5', purl: 'pkg:pypi/demo@1.5' },
        { type: 'library', name: 'demo', version: '2.0', purl: 'pkg:pypi/demo@2.0' }
      ]
    }

    expect(validatePythonLicenseInventory(document, sbom)).toEqual(document)
  })

  it('requires callers to pass the already marker-filtered Python SBOM', () => {
    const text = 'MIT license.\n'
    const document = {
      components: [
        {
          licenseExpression: 'MIT',
          licenseFiles: [
            { path: 'demo-1.0.dist-info/LICENSE', sha256: sha256(text), size: text.length, text }
          ],
          licenseSource: 'metadata-license-expression',
          name: 'demo',
          version: '1.0'
        }
      ],
      runtime: {
        implementation: 'CPython',
        licenseFile: { path: 'LICENSE.txt', sha256: sha256(text), size: text.length, text },
        version: '3.12.9'
      },
      schema: 1,
      tool: { name: 'nachuan-python-license-exporter', version: '1.0.0' }
    }
    const sbom = {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      components: [
        { type: 'library', name: 'demo', version: '1.0', purl: 'pkg:pypi/demo@1.0' },
        {
          type: 'library',
          name: 'linux-only',
          version: '9.0',
          purl: 'pkg:pypi/linux-only@9.0',
          properties: [{ name: 'uv:package:marker', value: "sys_platform == 'linux'" }]
        }
      ]
    }

    expect(() => validatePythonLicenseInventory(document, sbom)).toThrow(/exactly cover/i)
    expect(
      validatePythonLicenseInventory(document, {
        ...sbom,
        components: [sbom.components[0]]
      })
    ).toEqual(document)
  })

  it('binds every actual native artifact to a versioned registry component and notice hash', async () => {
    const projectRoot = await mkdtemp(join(tmpdir(), 'nachuan-native-license-'))
    try {
      const unpackedRoot = join(projectRoot, 'desktop', 'release', 'win-unpacked')
      await mkdir(unpackedRoot, { recursive: true })
      await writeFile(join(unpackedRoot, 'app.exe'), 'native-app')
      await writeFile(join(unpackedRoot, 'ffmpeg.dll'), 'native-library')
      const noticeText = 'Electron MIT license text.\n'
      await writeFile(join(unpackedRoot, 'LICENSE.electron.txt'), noticeText)
      const registry = {
        components: [
          {
            artifacts: ['app.exe', 'ffmpeg.dll'],
            id: 'electron-runtime',
            name: 'Electron runtime',
            noticeFiles: [
              {
                location: 'packaged',
                path: 'LICENSE.electron.txt',
                sha256: sha256(noticeText)
              }
            ],
            sourceUrl: 'https://github.com/electron/electron/releases/tag/v39.8.5',
            spdxExpression: 'MIT',
            version: '39.8.5',
            versionProof: { kind: 'npm-lock', package: 'electron' }
          }
        ],
        schema: 1
      }
      const result = await validateNativeLicenseRegistry({
        packageLock: {
          lockfileVersion: 3,
          packages: { 'node_modules/electron': { version: '39.8.5' } }
        },
        projectRoot,
        pythonLicenses: null,
        registry,
        unpackedRoot
      })

      expect(result).toEqual({
        components: [
          {
            artifacts: ['app.exe', 'ffmpeg.dll'],
            id: 'electron-runtime',
            licenseExpression: 'MIT',
            name: 'Electron runtime',
            notices: [
              {
                path: 'LICENSE.electron.txt',
                sha256: sha256(noticeText),
                size: Buffer.byteLength(noticeText),
                text: noticeText
              }
            ],
            sourceUrl: 'https://github.com/electron/electron/releases/tag/v39.8.5',
            version: '39.8.5'
          }
        ],
        ecosystem: 'native',
        schema: 1
      })
    } finally {
      await rm(projectRoot, { recursive: true, force: true })
    }
  })

  it('binds staged and final paid-media binaries to the same packaged raw notices', async () => {
    const projectRoot = await mkdtemp(join(tmpdir(), 'nachuan-media-native-license-'))
    try {
      const unpackedRoot = join(projectRoot, 'desktop', 'release', 'win-unpacked')
      const stagedNotices = join(projectRoot, 'dist', 'media-notices')
      const packagedNotices = join(unpackedRoot, 'resources', 'media-notices')
      const packagedMedia = join(unpackedRoot, 'resources', 'media')
      await mkdir(stagedNotices, { recursive: true })
      await mkdir(packagedNotices, { recursive: true })
      await mkdir(packagedMedia, { recursive: true })

      const license = 'GPL version 3 or later.\n'
      const readme = 'FFmpeg build provenance.\n'
      const lock = '{"schema":"nachuan.media-runtime-lock.v1"}\n'
      await writeFile(join(projectRoot, 'desktop', 'media-runtime-lock.json'), lock)
      for (const root of [stagedNotices, packagedNotices]) {
        await writeFile(join(root, 'LICENSE'), license)
        await writeFile(join(root, 'README.txt'), readme)
      }
      await writeFile(join(packagedMedia, 'ffmpeg.exe'), Buffer.from('MZ ffmpeg'))
      await writeFile(join(packagedMedia, 'ffprobe.exe'), Buffer.from('MZ ffprobe'))

      const registry = {
        components: [
          {
            artifacts: ['resources/media/ffmpeg.exe', 'resources/media/ffprobe.exe'],
            id: 'ffmpeg-gyan-engineering-candidate',
            name: 'FFmpeg Gyan essentials engineering candidate',
            noticeFiles: [
              { location: 'media-runtime', path: 'LICENSE', sha256: sha256(license) },
              { location: 'media-runtime', path: 'README.txt', sha256: sha256(readme) }
            ],
            sourceUrl: 'https://www.gyan.dev/ffmpeg/builds/packages/ffmpeg-8.0.1-essentials_build.zip',
            spdxExpression: 'GPL-3.0-or-later',
            version: '8.0.1-essentials_build-www.gyan.dev',
            versionProof: {
              kind: 'project-file',
              path: 'desktop/media-runtime-lock.json',
              sha256: sha256(lock)
            }
          }
        ],
        schema: 1
      }
      const context = {
        packageLock: { lockfileVersion: 3, packages: {} },
        projectRoot,
        pythonLicenses: null,
        registry
      }
      const planned = await validateNativeLicenseRegistry({
        ...context,
        planned: true,
        plannedUnpackedRoot: join(projectRoot, 'unused-electron-runtime'),
        unpackedRoot: null
      })
      const final = await validateNativeLicenseRegistry({ ...context, unpackedRoot })

      expect(final).toEqual(planned)
      expect(final.components[0]).toMatchObject({
        artifacts: ['resources/media/ffmpeg.exe', 'resources/media/ffprobe.exe'],
        id: 'ffmpeg-gyan-engineering-candidate',
        licenseExpression: 'GPL-3.0-or-later',
        notices: [
          { path: 'resources/media-notices/LICENSE', sha256: sha256(license) },
          { path: 'resources/media-notices/README.txt', sha256: sha256(readme) }
        ]
      })
    } finally {
      await rm(projectRoot, { recursive: true, force: true })
    }
  })

  it('writes a canonical CycloneDX SBOM binding final native bytes to reviewed license component refs', async () => {
    const root = await mkdtemp(join(tmpdir(), 'nachuan-native-sbom-'))
    try {
      const unpackedRoot = join(root, 'win-unpacked')
      const licensesRoot = join(unpackedRoot, 'resources', 'licenses')
      const manifestPath = join(root, 'WIN_UNPACKED_MANIFEST.json')
      const output = join(root, 'NATIVE_SBOM.cdx.json')
      await mkdir(licensesRoot, { recursive: true })
      await writeFile(join(unpackedRoot, 'app.exe'), 'native-app')
      await writeFile(join(unpackedRoot, 'ffmpeg.dll'), 'native-library')
      const inventory = {
        components: [
          {
            artifacts: ['app.exe', 'ffmpeg.dll'],
            id: 'electron-runtime',
            licenseExpression: 'MIT',
            name: 'Electron runtime',
            notices: [
              {
                path: 'LICENSE.electron.txt',
                sha256: 'fb4331de5e879f8e43710612b381a10a19cf10292b9f38edb81cbf7b3a81124c',
                size: 18,
                text: 'Electron license.\n'
              }
            ],
            sourceUrl: 'https://github.com/electron/electron/releases/tag/v39.8.5',
            version: '39.8.5'
          }
        ],
        ecosystem: 'native',
        schema: 1
      }
      await writeFile(
        join(licensesRoot, 'NATIVE_PAYLOAD_LICENSES.json'),
        `${JSON.stringify(inventory, null, 2)}\n`
      )
      await writeTreeManifest({
        root: unpackedRoot,
        output: manifestPath,
        variant: 'lean',
        version: '0.2.0'
      })

      const result = await writeNativeCycloneDxSbom({ manifestPath, output, unpackedRoot })

      expect(result).toEqual({
        fileCount: 2,
        output,
        sha256: expect.stringMatching(/^[0-9a-f]{64}$/),
        size: expect.any(Number)
      })
      expect(JSON.parse(await readFile(output, 'utf8'))).toEqual({
        $schema: CYCLONEDX_15_SCHEMA,
        bomFormat: 'CycloneDX',
        components: [
          {
            'bom-ref': 'native-license:electron-runtime',
            externalReferences: [
              {
                type: 'distribution',
                url: 'https://github.com/electron/electron/releases/tag/v39.8.5'
              }
            ],
            licenses: [{ expression: 'MIT' }],
            name: 'Electron runtime',
            type: 'library',
            version: '39.8.5'
          },
          {
            'bom-ref': 'native-file:a1cbf10f3a24a037f304d3ba411996f20a6131fbf9927bdeab2a11738ac689de:app.exe',
            hashes: [
              {
                alg: 'SHA-256',
                content: 'a1cbf10f3a24a037f304d3ba411996f20a6131fbf9927bdeab2a11738ac689de'
              }
            ],
            licenses: [{ expression: 'MIT' }],
            name: 'app.exe',
            properties: [
              { name: 'nachuan:native:path', value: 'app.exe' },
              { name: 'nachuan:native:size', value: '10' },
              { name: 'nachuan:license-component-ref', value: 'native-license:electron-runtime' }
            ],
            type: 'file'
          },
          {
            'bom-ref': 'native-file:01307e18b53bf651632b9119874fdff0771bfe2f2dafc10af8a901b394842a70:ffmpeg.dll',
            hashes: [
              {
                alg: 'SHA-256',
                content: '01307e18b53bf651632b9119874fdff0771bfe2f2dafc10af8a901b394842a70'
              }
            ],
            licenses: [{ expression: 'MIT' }],
            name: 'ffmpeg.dll',
            properties: [
              { name: 'nachuan:native:path', value: 'ffmpeg.dll' },
              { name: 'nachuan:native:size', value: '14' },
              { name: 'nachuan:license-component-ref', value: 'native-license:electron-runtime' }
            ],
            type: 'file'
          }
        ],
        dependencies: [
          {
            dependsOn: ['native-license:electron-runtime'],
            ref: 'nachuan-native-payload:0.2.0:lean:win32-x64'
          },
          {
            dependsOn: [],
            ref: 'native-file:01307e18b53bf651632b9119874fdff0771bfe2f2dafc10af8a901b394842a70:ffmpeg.dll'
          },
          {
            dependsOn: [],
            ref: 'native-file:a1cbf10f3a24a037f304d3ba411996f20a6131fbf9927bdeab2a11738ac689de:app.exe'
          },
          {
            dependsOn: [
              'native-file:01307e18b53bf651632b9119874fdff0771bfe2f2dafc10af8a901b394842a70:ffmpeg.dll',
              'native-file:a1cbf10f3a24a037f304d3ba411996f20a6131fbf9927bdeab2a11738ac689de:app.exe'
            ],
            ref: 'native-license:electron-runtime'
          }
        ],
        metadata: {
          component: {
            'bom-ref': 'nachuan-native-payload:0.2.0:lean:win32-x64',
            name: 'Nachuan native payload',
            properties: [
              { name: 'nachuan:release:variant', value: 'lean' },
              { name: 'nachuan:release:target', value: 'win32-x64' }
            ],
            type: 'application',
            version: '0.2.0'
          }
        },
        specVersion: '1.5',
        version: 1
      })
      expect(await readFile(output, 'utf8')).toBe(
        `${JSON.stringify(JSON.parse(await readFile(output, 'utf8')), null, 2)}\n`
      )
    } finally {
      await rm(root, { recursive: true, force: true })
    }
  })

  it('rejects a native CycloneDX SBOM whose artifact digest disagrees with the final payload manifest', async () => {
    const root = await mkdtemp(join(tmpdir(), 'nachuan-native-sbom-drift-'))
    try {
      const unpackedRoot = join(root, 'win-unpacked')
      const licensesRoot = join(unpackedRoot, 'resources', 'licenses')
      const manifestPath = join(root, 'WIN_UNPACKED_MANIFEST.json')
      const sbomPath = join(root, 'NATIVE_SBOM.cdx.json')
      await mkdir(licensesRoot, { recursive: true })
      await writeFile(join(unpackedRoot, 'app.exe'), 'native-app')
      await writeFile(
        join(licensesRoot, 'NATIVE_PAYLOAD_LICENSES.json'),
        `${JSON.stringify({
          components: [
            {
              artifacts: ['app.exe'],
              id: 'electron-runtime',
              licenseExpression: 'MIT',
              name: 'Electron runtime',
              notices: [
                {
                  path: 'LICENSE.electron.txt',
                  sha256: 'fb4331de5e879f8e43710612b381a10a19cf10292b9f38edb81cbf7b3a81124c',
                  size: 18,
                  text: 'Electron license.\n'
                }
              ],
              sourceUrl: 'https://github.com/electron/electron/releases/tag/v39.8.5',
              version: '39.8.5'
            }
          ],
          ecosystem: 'native',
          schema: 1
        }, null, 2)}\n`
      )
      await writeTreeManifest({ root: unpackedRoot, output: manifestPath, variant: 'lean', version: '0.2.0' })
      await writeNativeCycloneDxSbom({ manifestPath, output: sbomPath, unpackedRoot })
      const tampered = JSON.parse(await readFile(sbomPath, 'utf8'))
      tampered.components.find(({ type }) => type === 'file').hashes[0].content = '0'.repeat(64)
      await writeFile(sbomPath, `${JSON.stringify(tampered, null, 2)}\n`)

      await expect(
        verifyNativeCycloneDxSbom({ manifestPath, sbomPath, unpackedRoot })
      ).rejects.toThrow(/native CycloneDX SBOM.*manifest|native artifact.*digest/i)
    } finally {
      await rm(root, { recursive: true, force: true })
    }
  })

  it('rejects final native artifact bytes replaced after the installer manifest was written', async () => {
    const fixture = await createSingleArtifactNativeFixture('nachuan-native-byte-drift-')
    try {
      await writeFile(join(fixture.unpackedRoot, 'app.exe'), 'replaced-native-app')

      await expect(
        writeNativeCycloneDxSbom({
          manifestPath: fixture.manifestPath,
          output: fixture.sbomPath,
          unpackedRoot: fixture.unpackedRoot
        })
      ).rejects.toThrow(/payload SHA-256 mismatch|installed payload.*mismatch/i)
    } finally {
      await rm(fixture.root, { recursive: true, force: true })
    }
  })

  it('rejects a native artifact present in the final manifest but absent from the license inventory', async () => {
    const fixture = await createSingleArtifactNativeFixture('nachuan-native-unregistered-')
    try {
      await writeFile(join(fixture.unpackedRoot, 'rogue.dll'), 'unregistered-native')
      await writeTreeManifest({
        root: fixture.unpackedRoot,
        output: fixture.manifestPath,
        variant: 'lean',
        version: '0.2.0'
      })

      await expect(
        writeNativeCycloneDxSbom({
          manifestPath: fixture.manifestPath,
          output: fixture.sbomPath,
          unpackedRoot: fixture.unpackedRoot
        })
      ).rejects.toThrow(/license inventory does not exactly cover final native artifacts/i)
    } finally {
      await rm(fixture.root, { recursive: true, force: true })
    }
  })

  it.each([
    ['renamed PE .bin', 'renamed-pe.bin', minimalPeBytes()],
    ['reviewed Electron pak', 'runtime-resource.pak', Buffer.from('electron-pak')],
    ['reviewed Electron dat', 'runtime-resource.dat', Buffer.from('electron-dat')],
    ['PE driver', 'driver.sys', minimalPeBytes()],
    ['PE COM control', 'control.ocx', minimalPeBytes()],
    ['extensionless PE', 'native-payload', minimalPeBytes()],
    ['extensionless ELF', 'elf-payload', Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0])],
    ['extensionless Mach-O', 'macho-payload', Buffer.from([0xfe, 0xed, 0xfa, 0xcf, 0, 0, 0, 0])],
    ['renamed WebAssembly', 'wasm-payload.asset', Buffer.from([0x00, 0x61, 0x73, 0x6d, 1, 0, 0, 0])]
  ])('rejects an unregistered native payload detected independently of its name: %s', async (_case, name, bytes) => {
    const fixture = await createSingleArtifactNativeFixture('nachuan-native-magic-')
    try {
      await writeFile(join(fixture.unpackedRoot, name), bytes)
      await writeTreeManifest({
        root: fixture.unpackedRoot,
        output: fixture.manifestPath,
        variant: 'lean',
        version: '0.2.0'
      })

      await expect(
        writeNativeCycloneDxSbom({
          manifestPath: fixture.manifestPath,
          output: fixture.sbomPath,
          unpackedRoot: fixture.unpackedRoot
        })
      ).rejects.toThrow(/license inventory does not exactly cover final native artifacts/i)
    } finally {
      await rm(fixture.root, { recursive: true, force: true })
    }
  })

  it('emits one CycloneDX 1.5 SPDX expression and a closed standard dependency graph for shared bytes', async () => {
    const root = await mkdtemp(join(tmpdir(), 'nachuan-native-shared-bytes-'))
    try {
      const unpackedRoot = join(root, 'win-unpacked')
      const licensesRoot = join(unpackedRoot, 'resources', 'licenses')
      const manifestPath = join(root, 'WIN_UNPACKED_MANIFEST.json')
      const output = join(root, 'NATIVE_SBOM.cdx.json')
      await mkdir(licensesRoot, { recursive: true })
      await writeFile(join(unpackedRoot, 'engine.exe'), 'native-engine')
      const notice = {
        path: 'LICENSE.txt',
        sha256: 'fb4331de5e879f8e43710612b381a10a19cf10292b9f38edb81cbf7b3a81124c',
        size: 18,
        text: 'Electron license.\n'
      }
      await writeFile(
        join(licensesRoot, 'NATIVE_PAYLOAD_LICENSES.json'),
        `${JSON.stringify({
          components: [
            {
              artifacts: ['engine.exe'],
              id: 'component-a',
              licenseExpression: 'MIT',
              name: 'Component A',
              notices: [notice],
              sourceUrl: 'https://example.com/component-a/1.0.0',
              version: '1.0.0'
            },
            {
              artifacts: ['engine.exe'],
              id: 'component-b',
              licenseExpression: 'Python-2.0',
              name: 'Component B',
              notices: [notice],
              sourceUrl: 'https://example.com/component-b/2.0.0',
              version: '2.0.0'
            }
          ],
          ecosystem: 'native',
          schema: 1
        }, null, 2)}\n`
      )
      await writeTreeManifest({ root: unpackedRoot, output: manifestPath, variant: 'lean', version: '0.2.0' })
      await writeNativeCycloneDxSbom({ manifestPath, output, unpackedRoot })
      const document = JSON.parse(await readFile(output, 'utf8'))
      const fileRef = `native-file:${sha256('native-engine')}:engine.exe`
      const rootRef = 'nachuan-native-payload:0.2.0:lean:win32-x64'
      const file = document.components.find((component) => component.type === 'file')

      expect(file.licenses).toEqual([{ expression: '(MIT) AND (Python-2.0)' }])
      expect(document.dependencies).toEqual([
        { dependsOn: ['native-license:component-a', 'native-license:component-b'], ref: rootRef },
        { dependsOn: [], ref: fileRef },
        { dependsOn: [fileRef], ref: 'native-license:component-a' },
        { dependsOn: [fileRef], ref: 'native-license:component-b' }
      ])
      const validate = new Ajv({ allErrors: true, strict: false }).compile(cycloneDx15NativeConstraints)
      expect(validate(document), validate.errors?.map((error) => error.message).join('; ')).toBe(true)

      const legacyInvalid = structuredClone(document)
      legacyInvalid.components.find((component) => component.type === 'file').licenses = [
        { expression: 'MIT' },
        { expression: 'Python-2.0' }
      ]
      expect(validate(legacyInvalid)).toBe(false)
    } finally {
      await rm(root, { recursive: true, force: true })
    }
  })

  it.each([
    ['dangling target', (document) => {
      document.dependencies.find(({ ref }) => ref.startsWith('nachuan-native-payload:')).dependsOn = [
        'native-license:missing'
      ]
    }],
    ['duplicate target', (document) => {
      const root = document.dependencies.find(({ ref }) => ref.startsWith('nachuan-native-payload:'))
      root.dependsOn = [root.dependsOn[0], root.dependsOn[0]]
    }],
    ['duplicate ref entry', (document) => {
      document.dependencies.push(structuredClone(document.dependencies.at(-1)))
      document.dependencies.sort((left, right) => left.ref.localeCompare(right.ref, 'en'))
    }]
  ])('rejects a native CycloneDX dependency graph with a %s', async (_case, mutate) => {
    const fixture = await createSingleArtifactNativeFixture('nachuan-native-dependency-drift-')
    try {
      await writeNativeCycloneDxSbom({
        manifestPath: fixture.manifestPath,
        output: fixture.sbomPath,
        unpackedRoot: fixture.unpackedRoot
      })
      const document = JSON.parse(await readFile(fixture.sbomPath, 'utf8'))
      mutate(document)
      await writeFile(fixture.sbomPath, `${JSON.stringify(document, null, 2)}\n`)

      await expect(
        verifyNativeCycloneDxSbom({
          manifestPath: fixture.manifestPath,
          sbomPath: fixture.sbomPath,
          unpackedRoot: fixture.unpackedRoot
        })
      ).rejects.toThrow(/dependency/i)
    } finally {
      await rm(fixture.root, { recursive: true, force: true })
    }
  })

  it('keeps every reviewed Electron pak/dat/bin runtime byte in both native source mappings', async () => {
    const registry = JSON.parse(
      await readFile(new URL('../native-license-registry.json', import.meta.url), 'utf8')
    )
    const locales = [
      'af', 'am', 'ar', 'bg', 'bn', 'ca', 'cs', 'da', 'de', 'el', 'en-GB', 'en-US', 'es-419', 'es', 'et',
      'fa', 'fi', 'fil', 'fr', 'gu', 'he', 'hi', 'hr', 'hu', 'id', 'it', 'ja', 'kn', 'ko', 'lt', 'lv',
      'ml', 'mr', 'ms', 'nb', 'nl', 'pl', 'pt-BR', 'pt-PT', 'ro', 'ru', 'sk', 'sl', 'sr', 'sv', 'sw',
      'ta', 'te', 'th', 'tr', 'uk', 'ur', 'vi', 'zh-CN', 'zh-TW'
    ].map((name) => `locales/${name}.pak`)
    const expected = [
      'chrome_100_percent.pak',
      'chrome_200_percent.pak',
      'icudtl.dat',
      ...locales,
      'resources.pak',
      'snapshot_blob.bin',
      'v8_context_snapshot.bin'
    ]
    expect(expected).toHaveLength(61)
    for (const id of ['chromium-third-party-bundle', 'electron-runtime']) {
      const component = registry.components.find((item) => item.id === id)
      expect(component.artifacts.filter((path) => /\.(?:pak|dat|bin)$/i.test(path))).toEqual(expected)
    }
  })

  it('keeps the real paid-media native registry entry bound to the reviewed runtime lock', async () => {
    const registry = JSON.parse(
      await readFile(new URL('../native-license-registry.json', import.meta.url), 'utf8')
    )
    const ids = registry.components.map(({ id }) => id)
    expect(ids).toEqual([...ids].sort())

    const media = registry.components.find(
      ({ id }) => id === 'ffmpeg-gyan-engineering-candidate'
    )
    const lock = await readFile(new URL('../media-runtime-lock.json', import.meta.url))
    expect(media).toMatchObject({
      artifacts: ['resources/media/ffmpeg.exe', 'resources/media/ffprobe.exe'],
      noticeFiles: [
        {
          location: 'media-runtime',
          path: 'LICENSE',
          sha256: '8ceb4b9ee5adedde47b31e975c1d90c73ad27b6b165a1dcd80c7c545eb65b903'
        },
        {
          location: 'media-runtime',
          path: 'README.txt',
          sha256: 'a0e976df3cf1d781264c41db8ee3421978c1278be92ed00edbc96337529670be'
        }
      ],
      spdxExpression: 'GPL-3.0-or-later',
      versionProof: {
        kind: 'project-file',
        path: 'desktop/media-runtime-lock.json',
        sha256: sha256(lock)
      }
    })
  })

  it.each([
    ['unregistered native artifact', async ({ unpackedRoot }) => writeFile(join(unpackedRoot, 'rogue.dll'), 'rogue')],
    ['missing notice', async ({ unpackedRoot }) => unlink(join(unpackedRoot, 'LICENSE.electron.txt'))],
    ['notice hash drift', async ({ registry }) => { registry.components[0].noticeFiles[0].sha256 = '0'.repeat(64) }],
    ['component version drift', async ({ registry }) => { registry.components[0].version = '99.0.0' }]
  ])('fails closed on native registry drift: %s', async (_case, mutate) => {
    const projectRoot = await mkdtemp(join(tmpdir(), 'nachuan-native-drift-'))
    try {
      const unpackedRoot = join(projectRoot, 'desktop', 'release', 'win-unpacked')
      await mkdir(unpackedRoot, { recursive: true })
      await writeFile(join(unpackedRoot, 'app.exe'), 'native-app')
      const noticeText = 'Electron MIT license text.\n'
      await writeFile(join(unpackedRoot, 'LICENSE.electron.txt'), noticeText)
      const registry = {
        components: [
          {
            artifacts: ['app.exe'],
            id: 'electron-runtime',
            name: 'Electron runtime',
            noticeFiles: [
              { location: 'packaged', path: 'LICENSE.electron.txt', sha256: sha256(noticeText) }
            ],
            sourceUrl: 'https://github.com/electron/electron/releases/tag/v39.8.5',
            spdxExpression: 'MIT',
            version: '39.8.5',
            versionProof: { kind: 'npm-lock', package: 'electron' }
          }
        ],
        schema: 1
      }
      const context = { projectRoot, registry, unpackedRoot }
      await mutate(context)

      await expect(
        validateNativeLicenseRegistry({
          packageLock: {
            lockfileVersion: 3,
            packages: { 'node_modules/electron': { version: '39.8.5' } }
          },
          projectRoot,
          pythonLicenses: null,
          registry,
          unpackedRoot
        })
      ).rejects.toThrow()
    } finally {
      await rm(projectRoot, { recursive: true, force: true })
    }
  })

  it('resolves CPython, PyInstaller, npm helper, and built-in skill notices from bound sources', async () => {
    const projectRoot = await mkdtemp(join(tmpdir(), 'nachuan-native-sources-'))
    try {
      const unpackedRoot = join(projectRoot, 'desktop', 'release', 'win-unpacked')
      await mkdir(join(unpackedRoot, 'resources', 'engine'), { recursive: true })
      await writeFile(join(unpackedRoot, 'resources', 'engine', 'engine.exe'), 'engine')
      await mkdir(join(unpackedRoot, 'resources'), { recursive: true })
      await writeFile(join(unpackedRoot, 'resources', 'elevate.exe'), 'elevate')
      await mkdir(join(projectRoot, 'skills'), { recursive: true })
      const skillNotice = 'Agency Agents MIT license.\n'
      await writeFile(join(projectRoot, 'skills', 'LICENSE.agency-agents'), skillNotice)
      await mkdir(join(projectRoot, 'desktop', 'node_modules', 'electron-builder'), { recursive: true })
      const builderNotice = 'electron-builder MIT license.\n'
      await writeFile(join(projectRoot, 'desktop', 'node_modules', 'electron-builder', 'LICENSE'), builderNotice)
      const runtimeNotice = 'CPython license.\n'
      const pyinstallerNotice = 'PyInstaller GPL exception license.\n'
      const pythonLicenses = {
        components: [
          {
            licenseExpression: 'GPL-2.0-or-later',
            licenseFiles: [
              {
                path: 'pyinstaller-6.21.0.dist-info/licenses/COPYING.txt',
                sha256: sha256(pyinstallerNotice),
                size: Buffer.byteLength(pyinstallerNotice),
                text: pyinstallerNotice
              }
            ],
            licenseSource: 'registry',
            name: 'pyinstaller',
            version: '6.21.0'
          }
        ],
        runtime: {
          implementation: 'CPython',
          licenseFile: {
            path: 'LICENSE.txt',
            sha256: sha256(runtimeNotice),
            size: Buffer.byteLength(runtimeNotice),
            text: runtimeNotice
          },
          version: '3.12.9'
        },
        schema: 1,
        tool: { name: 'nachuan-python-license-exporter', version: '1.0.0' }
      }
      const registry = {
        components: [
          {
            artifacts: ['resources/engine/engine.exe'],
            id: 'agency-agents-skills',
            name: 'agency-agents built-in skills',
            noticeFiles: [
              { location: 'project', path: 'skills/LICENSE.agency-agents', sha256: sha256(skillNotice) }
            ],
            sourceUrl: 'https://github.com/msitarzewski/agency-agents/tree/00fb28a4cf60a719363dce0de67fafc6301857ce',
            spdxExpression: 'MIT',
            version: '00fb28a4cf60a719363dce0de67fafc6301857ce',
            versionProof: {
              kind: 'project-file',
              path: 'skills/LICENSE.agency-agents',
              sha256: sha256(skillNotice)
            }
          },
          {
            artifacts: ['resources/engine/engine.exe'],
            id: 'cpython-runtime',
            name: 'CPython runtime',
            noticeFiles: [
              { location: 'python-runtime', path: 'LICENSE.txt', sha256: sha256(runtimeNotice) }
            ],
            sourceUrl: 'https://www.python.org/downloads/release/python-3129/',
            spdxExpression: 'Python-2.0',
            version: '3.12.9',
            versionProof: { kind: 'python-runtime' }
          },
          {
            artifacts: ['resources/elevate.exe'],
            id: 'electron-builder-helper',
            name: 'electron-builder elevate helper',
            noticeFiles: [
              {
                location: 'npm-package',
                package: 'electron-builder',
                path: 'LICENSE',
                sha256: sha256(builderNotice)
              }
            ],
            sourceUrl: 'https://github.com/electron-userland/electron-builder/releases/tag/v26.15.3',
            spdxExpression: 'MIT',
            version: '26.15.3',
            versionProof: { kind: 'npm-lock', package: 'electron-builder' }
          },
          {
            artifacts: ['resources/engine/engine.exe'],
            id: 'pyinstaller-bootloader',
            name: 'PyInstaller bootloader',
            noticeFiles: [
              {
                location: 'python-distribution',
                package: 'pyinstaller',
                path: 'pyinstaller-6.21.0.dist-info/licenses/COPYING.txt',
                sha256: sha256(pyinstallerNotice)
              }
            ],
            sourceUrl: 'https://github.com/pyinstaller/pyinstaller/releases/tag/v6.21.0',
            spdxExpression: 'GPL-2.0-or-later',
            version: '6.21.0',
            versionProof: { kind: 'python-distribution', package: 'pyinstaller' }
          }
        ],
        schema: 1
      }

      const result = await validateNativeLicenseRegistry({
        packageLock: {
          lockfileVersion: 3,
          packages: { 'node_modules/electron-builder': { version: '26.15.3' } }
        },
        projectRoot,
        pythonLicenses,
        registry,
        unpackedRoot
      })

      expect(result.components.map(({ id }) => id)).toEqual([
        'agency-agents-skills',
        'cpython-runtime',
        'electron-builder-helper',
        'pyinstaller-bootloader'
      ])
      expect(result.components.flatMap(({ notices }) => notices.map(({ path }) => path))).toEqual([
        'project/skills/LICENSE.agency-agents',
        'python-runtime/LICENSE.txt',
        'npm/electron-builder/LICENSE',
        'python-distribution/pyinstaller/pyinstaller-6.21.0.dist-info/licenses/COPYING.txt'
      ])

      await rm(join(unpackedRoot, 'resources', 'elevate.exe'))
      await expect(
        validateNativeLicenseRegistry({
          packageLock: {
            lockfileVersion: 3,
            packages: { 'node_modules/electron-builder': { version: '26.15.3' } }
          },
          projectRoot,
          pythonLicenses,
          registry,
          unpackedRoot
        })
      ).rejects.toThrow(/electron-builder-helper artifact is missing/i)
      await expect(
        validateNativeLicenseRegistry({
          deferredNativeArtifacts: ['resources/elevate.exe'],
          packageLock: {
            lockfileVersion: 3,
            packages: { 'node_modules/electron-builder': { version: '26.15.3' } }
          },
          projectRoot,
          pythonLicenses,
          registry,
          unpackedRoot
        })
      ).resolves.toMatchObject({ components: expect.arrayContaining([expect.objectContaining({ id: 'electron-builder-helper' })]) })
    } finally {
      await rm(projectRoot, { recursive: true, force: true })
    }
  })

  it('generates deterministic canonical JSON and safe standalone HTML notices', () => {
    const pythonText = 'Python package license with <tag> & rights.\n'
    const nativeText = 'Native notice text.\n'
    const input = {
      nativeInventory: {
        components: [
          {
            artifacts: ['app.exe'],
            id: 'native-demo',
            licenseExpression: 'MIT',
            name: 'Native Demo',
            notices: [
              {
                path: 'LICENSE.native.txt',
                sha256: sha256(nativeText),
                size: Buffer.byteLength(nativeText),
                text: nativeText
              }
            ],
            sourceUrl: 'https://example.test/native/v1',
            version: '1.0'
          }
        ],
        ecosystem: 'native',
        schema: 1
      },
      npmInventory: {
        components: [
          {
            licenseExpression: 'MIT',
            licenseSource: 'installed-package-file',
            lockPath: 'node_modules/npm-demo',
            manualLegalReviewRequired: false,
            name: 'npm-demo',
            notices: [
              {
                path: 'LICENSE',
                sha256: sha256(nativeText),
                size: Buffer.byteLength(nativeText),
                text: nativeText
              }
            ],
            resolved: 'https://registry.npmjs.org/npm-demo/-/npm-demo-2.0.0.tgz',
            version: '2.0.0'
          }
        ],
        ecosystem: 'npm-payload',
        schema: 2
      },
      pythonLicenses: {
        components: [
          {
            licenseExpression: 'Apache-2.0',
            licenseFiles: [
              {
                path: 'python_demo-3.0.dist-info/licenses/LICENSE',
                sha256: sha256(pythonText),
                size: Buffer.byteLength(pythonText),
                text: pythonText
              }
            ],
            licenseSource: 'metadata-license-expression',
            name: 'python-demo',
            version: '3.0'
          }
        ],
        runtime: {
          implementation: 'CPython',
          licenseFile: {
            path: 'LICENSE.txt',
            sha256: sha256('runtime'),
            size: 7,
            text: 'runtime'
          },
          version: '3.12.9'
        },
        schema: 1,
        tool: { name: 'nachuan-python-license-exporter', version: '1.0.0' }
      }
    }
    const result = buildThirdPartyNotices(input)

    expect(result.json.schema).toBe(1)
    expect(result.json.components.map(({ id }) => id)).toEqual([
      'native:native-demo',
      'npm:node_modules/npm-demo',
      'pypi:python-demo@3.0'
    ])
    expect(result.html).toContain('<!doctype html>')
    expect(result.html).toContain('Python package license with &lt;tag&gt; &amp; rights.')
    expect(result.html).not.toContain('<tag>')
    expect(result.html.endsWith('\n')).toBe(true)
    expect(buildThirdPartyNotices(input)).toEqual(result)
  })

  it('invokes the pinned Python exporter through uv and validates its canonical result', async () => {
    const projectRoot = await mkdtemp(join(tmpdir(), 'nachuan-python-license-client-'))
    try {
      await mkdir(join(projectRoot, 'desktop'), { recursive: true })
      await writeFile(join(projectRoot, 'desktop', 'python-license-registry.release.json'), '{"entries":[],"schema":3}\n')
      const licenseText = 'MIT license.\n'
      const runtimeText = 'CPython license.\n'
      const document = {
        components: [
          {
            licenseExpression: 'MIT',
            licenseFiles: [
              {
                path: 'demo-1.0.dist-info/licenses/LICENSE',
                sha256: sha256(licenseText),
                size: Buffer.byteLength(licenseText),
                text: licenseText
              }
            ],
            licenseSource: 'metadata-license-expression',
            name: 'demo',
            version: '1.0'
          }
        ],
        runtime: {
          implementation: 'CPython',
          licenseFile: {
            path: 'LICENSE.txt',
            sha256: sha256(runtimeText),
            size: Buffer.byteLength(runtimeText),
            text: runtimeText
          },
          version: '3.12.9'
        },
        schema: 1,
        tool: { name: 'nachuan-python-license-exporter', version: '1.0.0' }
      }
      const sbom = {
        bomFormat: 'CycloneDX',
        specVersion: '1.5',
        components: [{ type: 'library', name: 'demo', version: '1.0', purl: 'pkg:pypi/demo@1.0' }]
      }
      let invocation
      const client = createPythonLicenseEvidenceClient({
        execute: async (command, args, options) => {
          invocation = { args, command, options }
          const outputPath = args[args.indexOf('--output') + 1]
          await writeFile(outputPath, `${JSON.stringify(document, null, 2)}\n`)
          return { code: 0, stdout: '', stderr: '' }
        },
        projectRoot
      })

      await expect(client.exportLicenses(sbom)).resolves.toEqual(document)
      expect(invocation.command).toBe(join(projectRoot, '.venv', 'Scripts', 'python.exe'))
      expect(invocation.args.slice(0, 3)).toEqual([
        '-I',
        '-B',
        join(projectRoot, 'scripts', 'export_python_licenses.py')
      ])
      expect(invocation.args[invocation.args.indexOf('--lock') + 1]).toBe(join(projectRoot, 'uv.lock'))
      expect(invocation.options.cwd).toBe(projectRoot)
      expect(invocation.options.env).toMatchObject({
        PYTHONDONTWRITEBYTECODE: '1',
        PYTHONNOUSERSITE: '1'
      })
    } finally {
      await rm(projectRoot, { recursive: true, force: true })
    }
  })

  it('writes the three canonical release notice files as a closed set', async () => {
    const outputRoot = await mkdtemp(join(tmpdir(), 'nachuan-license-output-'))
    try {
      const text = 'MIT license.\n'
      const pythonLicenses = {
        components: [
          {
            licenseExpression: 'MIT',
            licenseFiles: [
              { path: 'demo-1.0.dist-info/LICENSE', sha256: sha256(text), size: text.length, text }
            ],
            licenseSource: 'metadata-license-expression',
            name: 'demo',
            version: '1.0'
          }
        ],
        runtime: {
          implementation: 'CPython',
          licenseFile: { path: 'LICENSE.txt', sha256: sha256(text), size: text.length, text },
          version: '3.12.9'
        },
        schema: 1,
        tool: { name: 'nachuan-python-license-exporter', version: '1.0.0' }
      }
      const result = await writeLicenseEvidenceFiles({
        nativeInventory: {
          components: [
            {
              artifacts: ['app.exe'],
              id: 'native-demo',
              licenseExpression: 'MIT',
              name: 'Native Demo',
              notices: [{ path: 'LICENSE.native', sha256: sha256(text), size: text.length, text }],
              sourceUrl: 'https://example.test/native',
              version: '1.0'
            }
          ],
          ecosystem: 'native',
          schema: 1
        },
        npmInventory: {
          components: [
            {
              licenseExpression: 'MIT',
              licenseSource: 'installed-package-file',
              lockPath: 'node_modules/npm-demo',
              manualLegalReviewRequired: false,
              name: 'npm-demo',
              notices: [{ path: 'LICENSE', sha256: sha256(text), size: text.length, text }],
              resolved: 'https://registry.npmjs.org/npm-demo/-/npm-demo-1.0.0.tgz',
              version: '1.0'
            }
          ],
          ecosystem: 'npm-payload',
          schema: 2
        },
        outputRoot,
        pythonLicenses
      })

      expect(LICENSE_EVIDENCE_FILES).toEqual([
        'PYTHON_LICENSES.json',
        'THIRD_PARTY_NOTICES.json',
        'THIRD_PARTY_NOTICES.html'
      ])
      expect(result.files).toEqual(LICENSE_EVIDENCE_FILES)
      expect(await readFile(join(outputRoot, 'PYTHON_LICENSES.json'), 'utf8')).toBe(
        `${JSON.stringify(pythonLicenses, null, 2)}\n`
      )
      expect(JSON.parse(await readFile(join(outputRoot, 'THIRD_PARTY_NOTICES.json'), 'utf8')).schema).toBe(1)
      expect(await readFile(join(outputRoot, 'THIRD_PARTY_NOTICES.html'), 'utf8')).toContain(
        '<!doctype html>'
      )
    } finally {
      await rm(outputRoot, { recursive: true, force: true })
    }
  })
})
