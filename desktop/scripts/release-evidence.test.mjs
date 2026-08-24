import { createHash } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { copyFile, mkdir, mkdtemp, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'

import { afterEach, describe, expect, it } from 'vitest'

import {
  collectReleaseEvidenceReports,
  createReleaseCommandClient,
  createOsvAuditClient,
  finalizePreparedReleaseEvidence,
  generateReleaseEvidence,
  materializeReleaseEvidenceSourceFreeze,
  prepareReleaseEvidence,
  RELEASE_EVIDENCE_FILES,
  reAuditReleaseEvidence,
  verifyReleaseEvidence,
  writeReleaseEvidenceBundle
} from './release-evidence.mjs'
import {
  filterPythonSbomForReleaseEnvironment,
  pyinstallerArchiveViewerDescriptor,
  PYTHON_RELEASE_SELECTION,
  pythonReleaseSbomArgs,
  selectedPythonPackagesFromUvLock
} from './python-release-policy.mjs'
import { writeTreeManifest } from './installer-closure.mjs'

const workdirs = []
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex')
const canonicalValue = (value) =>
  Array.isArray(value)
    ? value.map(canonicalValue)
    : value && typeof value === 'object'
      ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalValue(value[key])]))
      : value
const canonicalJson = (value) => `${JSON.stringify(canonicalValue(value), null, 2)}\n`
const IDENTITY = {
  releaseTag: 'v0.2.0',
  releaseCommit: 'a'.repeat(40),
  runId: '123456789'
}
function generatedIdentity(seed) {
  return {
    device: seed,
    inode: seed,
    mode: '33188',
    links: '1',
    size: '4',
    modifiedNs: seed,
    changedNs: seed,
    bornNs: seed
  }
}
function generatedSource() {
  const engine = Buffer.from('eng\n')
  const trust = Buffer.from('upd\n')
  return {
    schema: 'nachuan.generated-release-source/v2',
    files: [
      {
        path: 'desktop/src/main/generated-engine-integrity.ts',
        contentBase64: engine.toString('base64'),
        sha256: sha256(engine),
        size: engine.length,
        identity: generatedIdentity('3')
      },
      {
        path: 'desktop/src/main/generated-update-trust.ts',
        contentBase64: trust.toString('base64'),
        sha256: sha256(trust),
        size: trust.length,
        identity: generatedIdentity('4')
      }
    ]
  }
}
function checkedCommand(command, args) {
  const result = spawnSync(command, args, { encoding: 'utf8', windowsHide: true })
  if (result.status !== 0) throw new Error(`test tool discovery failed: ${command} ${args.join(' ')}`)
  return result.stdout.trim()
}

const npmCliPath = process.env.npm_execpath || join(
  process.env.npm_config_prefix,
  'node_modules',
  'npm',
  'bin',
  'npm-cli.js'
)
const toolSeeds = {
  node: { path: process.execPath, version: process.versions.node },
  npm: { path: npmCliPath, version: checkedCommand(process.execPath, [npmCliPath, '--version']) },
  pyinstallerArchiveViewer: {
    path: resolve(process.cwd(), '..', '.venv', 'Scripts', 'pyi-archive_viewer.exe'),
    version: '6.21.0'
  },
  python: {
    path: checkedCommand('uv', ['python', 'find', '3.12.9']),
    version: '3.12.9'
  },
  uv: {
    path: checkedCommand('where.exe', ['uv']).split(/\r?\n/)[0],
    version: '0.11.3'
  },
  git: {
    path: checkedCommand('where.exe', ['git']).split(/\r?\n/)[0],
    version: checkedCommand('git', ['--version']).replace(/^git version\s+/, '')
  }
}
const TOOL_VERSIONS = Object.fromEntries(
  await Promise.all(Object.entries(toolSeeds).map(async ([name, value]) => {
    if (name === 'pyinstallerArchiveViewer') {
      return [name, await pyinstallerArchiveViewerDescriptor(resolve(process.cwd(), '..'))]
    }
    const bytes = await readFile(value.path)
    return [name, {
      name,
      path: value.path,
      sha256: sha256(bytes),
      size: bytes.length,
      version: value.version
    }]
  }))
)
const SOURCE_INPUT_NAMES = [
  'pyproject.toml',
  'uv.lock',
  'desktop/package.json',
  'desktop/package-lock.json'
]

afterEach(async () => {
  await Promise.all(workdirs.splice(0).map((path) => rm(path, { recursive: true, force: true })))
})

function reports() {
  return {
    npmAudit: {
      auditReportVersion: 2,
      vulnerabilities: {},
      metadata: {
        vulnerabilities: { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 },
        dependencies: { prod: 2, dev: 0, optional: 0, peer: 0, peerOptional: 0, total: 1 }
      }
    },
    npmSbom: {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      version: 1,
      components: [
        {
          'bom-ref': 'react@18.3.1',
          type: 'library',
          name: 'react',
          version: '18.3.1',
          purl: 'pkg:npm/react@18.3.1'
        }
      ]
    },
    pythonAudit: {
      schema: 1,
      source: 'https://api.osv.dev/v1/querybatch',
      ecosystem: 'PyPI',
      packages: [{ name: 'anyio', version: '4.14.0', vulnerabilities: [] }],
      vulnerabilityCount: 0
    },
    pythonSbom: {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      version: 1,
      components: [
        {
          'bom-ref': 'anyio-1@4.14.0',
          type: 'library',
          name: 'anyio',
          version: '4.14.0',
          purl: 'pkg:pypi/anyio@4.14.0'
        }
      ]
    }
  }
}

async function fixture({ releaseTier = 'early-access', complete = true } = {}) {
  const projectRoot = await realpath(await mkdtemp(join(tmpdir(), 'nachuan-release-evidence-')))
  workdirs.push(projectRoot)
  const desktopRoot = join(projectRoot, 'desktop')
  const releaseRoot = join(desktopRoot, 'release')
  const unpackedRoot = join(releaseRoot, 'win-unpacked')
  const licensesRoot = join(unpackedRoot, 'resources', 'licenses')
  await mkdir(licensesRoot, { recursive: true })
  await writeFile(join(unpackedRoot, 'app.exe'), 'native-app')
  await writeFile(
    join(licensesRoot, 'NATIVE_PAYLOAD_LICENSES.json'),
    canonicalJson({
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
    })
  )
  await mkdir(join(projectRoot, '.venv', 'Scripts'), { recursive: true })
  await copyFile(
    toolSeeds.pyinstallerArchiveViewer.path,
    join(projectRoot, '.venv', 'Scripts', 'pyi-archive_viewer.exe')
  )
  await writeFile(
    join(projectRoot, 'pyproject.toml'),
    '[project]\nname = "llm-aggregator"\nversion = "0.1.0"\n'
  )
  await writeFile(
    join(projectRoot, 'uv.lock'),
    'version = 1\n\n[[package]]\nname = "anyio"\nversion = "4.14.0"\nsource = { registry = "https://pypi.org/simple" }\n\n[[package]]\nname = "llm-aggregator"\nversion = "0.1.0"\nsource = { virtual = "." }\ndependencies = [\n    { name = "anyio" },\n]\n'
  )
  await writeFile(
    join(desktopRoot, 'package.json'),
    `${JSON.stringify({ name: 'aggregator-desktop', version: '0.2.0' })}\n`
  )
  await writeFile(
    join(desktopRoot, 'package-lock.json'),
    `${JSON.stringify({
      name: 'aggregator-desktop',
      version: '0.2.0',
      lockfileVersion: 3,
      packages: {
        '': { name: 'aggregator-desktop', version: '0.2.0', dependencies: { react: '18.3.1' } },
        'node_modules/react': { version: '18.3.1' }
      }
    })}\n`
  )

  const names =
    releaseTier === 'production'
      ? [
          'nachuan-0.2.0-lean-win.exe',
          'nachuan-0.2.0-lean-win.exe.blockmap',
          'lean.yml',
          'WIN_UNPACKED_MANIFEST.json',
          ...(complete ? ['production-lean-win-x64.json'] : [])
        ]
      : [
          'nachuan-0.2.0-lean-early-access-unsigned-win.exe',
          'nachuan-0.2.0-lean-early-access-unsigned-win.exe.blockmap',
          'early-access-lean.yml',
          'WIN_UNPACKED_MANIFEST.json',
          'early-access-lean-win-x64.json'
        ]
  for (const name of names) {
    if (name !== 'WIN_UNPACKED_MANIFEST.json') {
      await writeFile(join(releaseRoot, name), `fixture:${name}\n`)
    }
  }
  await writeTreeManifest({
    root: unpackedRoot,
    output: join(releaseRoot, 'WIN_UNPACKED_MANIFEST.json'),
    variant: 'lean',
    version: '0.2.0'
  })
  if (complete) {
    const checksumLines = []
    for (const name of names) {
      checksumLines.push(`${sha256(await readFile(join(releaseRoot, name)))}  ${name}`)
    }
    await writeFile(join(releaseRoot, 'SHA256SUMS'), `${checksumLines.join('\n')}\n`)
  }
  const inputs = []
  for (const name of SOURCE_INPUT_NAMES) {
    const bytes = await readFile(join(projectRoot, ...name.split('/')))
    inputs.push({
      path: name,
      gitMode: '100644',
      gitBlob: createHash('sha1')
        .update(Buffer.from(`blob ${bytes.length}\0`))
        .update(bytes)
        .digest('hex'),
      sha256: sha256(bytes),
      size: bytes.length,
      identity: { fixture: name, revision: '1' }
    })
  }
  const tree = createHash('sha1').update(canonicalJson(inputs), 'utf8').digest('hex')
  const gitIdentity = {
    fixture: 'git',
    revision: '1'
  }
  const sourceSnapshot = {
    schema: 'nachuan.release-source-freeze/v2',
    generatedSource: generatedSource(),
    gitToolchain: {
      schema: 'nachuan.git-toolchain-closure/v1',
      version: toolSeeds.git.version,
      gitPath: TOOL_VERSIONS.git.path,
      runtimeRoot: dirname(TOOL_VERSIONS.git.path),
      runtimeBin: dirname(TOOL_VERSIONS.git.path),
      execPath: dirname(TOOL_VERSIONS.git.path),
      archiveSha256: 'e'.repeat(64),
      runtimeTreeSha256: 'f'.repeat(64),
      lockSha256: '1'.repeat(64),
      directories: [],
      files: [{
        path: TOOL_VERSIONS.git.path,
        relativePath: 'mingw64/bin/git.exe',
        roles: ['runtime-core', 'selected-git-executable'],
        sha256: TOOL_VERSIONS.git.sha256,
        size: TOOL_VERSIONS.git.size,
        identity: gitIdentity
      }]
    },
    sourceSnapshot: {
      schema: 'nachuan.release-source-snapshot/v1',
      git: {
        objectFormat: 'sha1',
        expectedCommit: IDENTITY.releaseCommit,
        expectedTag: IDENTITY.releaseTag,
        expectedTree: tree,
        headCommit: IDENTITY.releaseCommit,
        headTree: tree,
        tagCommit: IDENTITY.releaseCommit,
        tagObject: 'd'.repeat(40)
      },
      toolchain: {
        git: {
          path: TOOL_VERSIONS.git.path,
          sha256: TOOL_VERSIONS.git.sha256,
          size: TOOL_VERSIONS.git.size,
          identity: gitIdentity
        }
      },
      scope: {
        files: [...SOURCE_INPUT_NAMES],
        optionalFiles: [],
        directories: ['desktop'],
        optionalDirectories: [],
        excludedPaths: ['desktop/node_modules']
      },
      directories: [],
      files: inputs,
      totalBytes: inputs.reduce((total, item) => total + item.size, 0)
    }
  }
  const sourceControlClient = {
    async releaseSnapshot() {
      for (const expected of inputs) {
        const bytes = await readFile(join(projectRoot, ...expected.path.split('/')))
        const blob = createHash('sha1')
          .update(Buffer.from(`blob ${bytes.length}\0`))
          .update(bytes)
          .digest('hex')
        if (blob !== expected.gitBlob) {
          throw new Error(`tracked source input differs from release commit: ${expected.path}`)
        }
      }
      return structuredClone(sourceSnapshot)
    }
  }
  return { projectRoot, releaseRoot, sourceSnapshot, sourceControlClient }
}

async function replaceSourceInput(paths, name, content) {
  const path = join(paths.projectRoot, ...name.split('/'))
  await writeFile(path, content)
  const bytes = await readFile(path)
  Object.assign(
    paths.sourceSnapshot.sourceSnapshot.files.find((item) => item.path === name),
    {
      gitBlob: createHash('sha1')
        .update(Buffer.from(`blob ${bytes.length}\0`))
        .update(bytes)
        .digest('hex'),
      sha256: sha256(bytes),
      size: bytes.length,
      identity: { fixture: name, revision: String(Date.now()) }
    }
  )
  const tree = createHash('sha1')
    .update(canonicalJson(paths.sourceSnapshot.sourceSnapshot.files), 'utf8')
    .digest('hex')
  paths.sourceSnapshot.sourceSnapshot.git.expectedTree = tree
  paths.sourceSnapshot.sourceSnapshot.git.headTree = tree
}

async function copyOrdinaryDirectory(source, destination) {
  await mkdir(destination, { recursive: true })
  for (const entry of await readdir(source, { withFileTypes: true })) {
    if (entry.name === '__pycache__') continue
    const from = join(source, entry.name)
    const to = join(destination, entry.name)
    if (entry.isDirectory()) await copyOrdinaryDirectory(from, to)
    else if (entry.isFile()) await copyFile(from, to)
    else throw new Error(`test marker dependency contains a special entry: ${from}`)
  }
}

async function prepareMarkerEvaluationEnvironment(projectRoot) {
  const environmentRoot = join(projectRoot, '.venv')
  const selectedEnvironment = resolve(process.cwd(), '..', '.venv')
  await rm(environmentRoot, { recursive: true, force: true })
  await mkdir(join(environmentRoot, 'Scripts'), { recursive: true })
  await mkdir(join(environmentRoot, 'Lib', 'site-packages'), { recursive: true })
  await copyFile(join(selectedEnvironment, 'pyvenv.cfg'), join(environmentRoot, 'pyvenv.cfg'))
  await copyFile(
    join(selectedEnvironment, 'Scripts', 'python.exe'),
    join(environmentRoot, 'Scripts', 'python.exe')
  )
  await copyOrdinaryDirectory(
    join(selectedEnvironment, 'Lib', 'site-packages', 'packaging'),
    join(environmentRoot, 'Lib', 'site-packages', 'packaging')
  )
  await copyFile(
    toolSeeds.pyinstallerArchiveViewer.path,
    join(environmentRoot, 'Scripts', 'pyi-archive_viewer.exe')
  )
}

describe('release evidence closed bundle', () => {
  it('re-runs npm and OSV audits in the publisher and binds fresh SBOMs to the finalized graph', async () => {
    const paths = await fixture()
    const reportSet = reports()
    await writeReleaseEvidenceBundle({
      ...paths,
      variant: 'lean',
      releaseTier: 'early-access',
      releaseTag: IDENTITY.releaseTag,
      releaseCommit: IDENTITY.releaseCommit,
      runId: IDENTITY.runId,
      toolVersions: TOOL_VERSIONS,
      reports: reportSet,
      sourceControlClient: paths.sourceControlClient
    })
    const calls = []
    const commandClient = {
      async toolVersions() { calls.push('tools'); return TOOL_VERSIONS },
      async npmAudit() { calls.push('npm-audit'); return reportSet.npmAudit },
      async npmSbom() { calls.push('npm-sbom'); return reportSet.npmSbom },
      async pythonSbom() { calls.push('python-sbom'); return reportSet.pythonSbom }
    }
    const osvClient = {
      async auditPython() { calls.push('osv-python'); return reportSet.pythonAudit }
    }

    const result = await reAuditReleaseEvidence({ ...paths, commandClient, osvClient })

    expect(result.reports.pythonAudit.vulnerabilityCount).toBe(0)
    expect(calls.sort()).toEqual(['npm-audit', 'npm-sbom', 'osv-python', 'python-sbom', 'tools'].sort())
  })

  it('collects production evidence before leaf signing and finalizes it only after the schema3 envelope exists', async () => {
    const paths = await fixture({ releaseTier: 'production', complete: false })
    const preparedPath = join(paths.projectRoot, '..', `prepared-${Date.now()}.json`)
    workdirs.push(preparedPath)
    const reportSet = reports()
    const sourceControlClient = paths.sourceControlClient
    const commandClient = {
      async toolVersions() { return TOOL_VERSIONS },
      async npmAudit() { return reportSet.npmAudit },
      async npmSbom() { return reportSet.npmSbom },
      async pythonSbom() { return reportSet.pythonSbom }
    }
    const osvClient = {
      async auditPython() { return reportSet.pythonAudit }
    }

    await prepareReleaseEvidence({
      ...paths,
      output: preparedPath,
      variant: 'lean',
      releaseTier: 'production',
      ...IDENTITY,
      commandClient,
      osvClient,
      sourceControlClient
    })
    await expect(readFile(join(paths.releaseRoot, 'RELEASE_EVIDENCE_MANIFEST.json'))).rejects.toThrow()

    const envelope = 'fixture:production-lean-win-x64.json\n'
    await writeFile(join(paths.releaseRoot, 'production-lean-win-x64.json'), envelope)
    const names = [
      'nachuan-0.2.0-lean-win.exe',
      'nachuan-0.2.0-lean-win.exe.blockmap',
      'lean.yml',
      'WIN_UNPACKED_MANIFEST.json',
      'production-lean-win-x64.json'
    ]
    const checksumLines = []
    for (const name of names) {
      checksumLines.push(`${sha256(await readFile(join(paths.releaseRoot, name)))}  ${name}`)
    }
    await writeFile(join(paths.releaseRoot, 'SHA256SUMS'), `${checksumLines.join('\n')}\n`)

    const originalUvLock = await readFile(join(paths.projectRoot, 'uv.lock'))
    await writeFile(join(paths.projectRoot, 'uv.lock'), 'drifted after evidence collection\n')
    await expect(
      finalizePreparedReleaseEvidence({
        ...paths,
        input: preparedPath,
        variant: 'lean',
        releaseTier: 'production',
        ...IDENTITY,
        sourceControlClient
      })
    ).rejects.toThrow(/tracked source input differs from release commit: uv\.lock/i)
    await writeFile(join(paths.projectRoot, 'uv.lock'), originalUvLock)

    const manifest = await finalizePreparedReleaseEvidence({
      ...paths,
      input: preparedPath,
      variant: 'lean',
      releaseTier: 'production',
      ...IDENTITY,
      sourceControlClient
    })
    expect(manifest.releaseFiles.map(({ name }) => name)).toContain('production-lean-win-x64.json')
    const checksumNames = (await readFile(join(paths.releaseRoot, 'SHA256SUMS'), 'utf8'))
      .trimEnd()
      .split('\n')
      .map((line) => line.slice(66))
    expect(checksumNames).toEqual(names)
    expect(checksumNames).not.toContain('RELEASE_EVIDENCE_MANIFEST.json')
    expect(manifest.releaseFiles.at(-1)?.name).toBe('SHA256SUMS')
  }, 60_000)

  it('binds distinct desktop and engine identities in canonical bytes and verifies the bundle', async () => {
    const paths = await fixture()
    const manifest = await writeReleaseEvidenceBundle({
      ...paths,
      variant: 'lean',
      releaseTier: 'early-access',
      ...IDENTITY,
      toolVersions: TOOL_VERSIONS,
      reports: reports()
    })

    expect(manifest.identity.components).toEqual({
      desktop: { name: 'aggregator-desktop', version: '0.2.0' },
      engine: { name: 'llm-aggregator', version: '0.1.0' }
    })
    expect(await readFile(join(paths.releaseRoot, 'RELEASE_EVIDENCE_MANIFEST.json'), 'utf8')).toBe(
      `${JSON.stringify(manifest, null, 2)}\n`
    )
    expect(RELEASE_EVIDENCE_FILES).toEqual([
      'NATIVE_SBOM.cdx.json',
      'NPM_AUDIT.json',
      'NPM_SBOM.cdx.json',
      'PYTHON_AUDIT.json',
      'PYTHON_SBOM.cdx.json',
      'RELEASE_EVIDENCE_MANIFEST.json'
    ])
    expect(manifest.releaseFiles.map(({ name }) => name)).toEqual([
      'nachuan-0.2.0-lean-early-access-unsigned-win.exe',
      'nachuan-0.2.0-lean-early-access-unsigned-win.exe.blockmap',
      'early-access-lean.yml',
      'WIN_UNPACKED_MANIFEST.json',
      'early-access-lean-win-x64.json',
      'NATIVE_SBOM.cdx.json',
      'SHA256SUMS'
    ])
    expect(manifest.schema).toBe(3)
    expect(manifest.pythonSelection).toEqual(PYTHON_RELEASE_SELECTION)
    expect(manifest.source.sourceSnapshot.files.map(({ path }) => path)).toEqual([
      'pyproject.toml',
      'uv.lock',
      'desktop/package.json',
      'desktop/package-lock.json'
    ])
    const materializedFreeze = join(
      await realpath(paths.projectRoot),
      `materialized-source-freeze-${Date.now()}.json`
    )
    const materialized = await materializeReleaseEvidenceSourceFreeze({
      ...paths,
      output: materializedFreeze,
      variant: 'lean',
      releaseTier: 'early-access',
      expectedTag: IDENTITY.releaseTag,
      expectedCommit: IDENTITY.releaseCommit,
      expectedRunId: IDENTITY.runId
    })
    expect(JSON.parse(await readFile(materializedFreeze, 'utf8'))).toEqual(manifest.source)
    expect(materialized.sha256).toBe(sha256(await readFile(materializedFreeze)))

    await expect(
      verifyReleaseEvidence({
        ...paths,
        variant: 'lean',
        releaseTier: 'early-access',
        expectedTag: IDENTITY.releaseTag,
        expectedCommit: IDENTITY.releaseCommit,
        expectedRunId: IDENTITY.runId
      })
    ).resolves.toMatchObject({ identity: IDENTITY })
    await expect(
      verifyReleaseEvidence({
        ...paths,
        variant: 'lean',
        releaseTier: 'early-access',
        expectedTag: IDENTITY.releaseTag,
        expectedCommit: 'b'.repeat(40),
        expectedRunId: IDENTITY.runId
      })
    ).rejects.toThrow(/commit\/tag\/tree identity is invalid/)
    await expect(
      verifyReleaseEvidence({
        ...paths,
        variant: 'lean',
        releaseTier: 'early-access',
        expectedTag: IDENTITY.releaseTag,
        expectedCommit: IDENTITY.releaseCommit,
        expectedRunId: '987654321'
      })
    ).rejects.toThrow(/identity does not match the requested run\/commit\/tag/)
  }, 90_000)

  it('rejects canonical unknown manifest fields instead of ignoring forged semantics', async () => {
    const paths = await fixture()
    await writeReleaseEvidenceBundle({
      ...paths,
      variant: 'lean',
      releaseTier: 'early-access',
      ...IDENTITY,
      toolVersions: TOOL_VERSIONS,
      reports: reports()
    })
    const manifestPath = join(paths.releaseRoot, 'RELEASE_EVIDENCE_MANIFEST.json')
    const manifest = JSON.parse(await readFile(manifestPath, 'utf8'))
    manifest.forgedApproval = 'release-approved'
    await writeFile(manifestPath, canonicalJson(manifest))

    await expect(
      verifyReleaseEvidence({
        ...paths,
        variant: 'lean',
        releaseTier: 'early-access',
        expectedTag: IDENTITY.releaseTag,
        expectedCommit: IDENTITY.releaseCommit,
        expectedRunId: IDENTITY.runId
      })
    ).rejects.toThrow(/manifest fields are not canonical/)
  })

  it('fails closed on missing, extra, hash-drifted, and unparsable evidence files', async () => {
    const verify = (paths) =>
      verifyReleaseEvidence({
        ...paths,
        variant: 'lean',
        releaseTier: 'early-access',
        expectedTag: IDENTITY.releaseTag,
        expectedCommit: IDENTITY.releaseCommit,
        expectedRunId: IDENTITY.runId
      })
    const createBundle = async () => {
      const paths = await fixture()
      await writeReleaseEvidenceBundle({
        ...paths,
        variant: 'lean',
        releaseTier: 'early-access',
        ...IDENTITY,
        toolVersions: TOOL_VERSIONS,
        reports: reports()
      })
      return paths
    }

    const missing = await createBundle()
    await rm(join(missing.releaseRoot, 'NPM_AUDIT.json'))
    await expect(verify(missing)).rejects.toThrow()

    const extra = await createBundle()
    await writeFile(join(extra.releaseRoot, 'UNLISTED_EVIDENCE.json'), '{}\n')
    await expect(verify(extra)).rejects.toThrow(/unexpected release output file/)

    const drifted = await createBundle()
    await writeFile(join(drifted.releaseRoot, 'NPM_AUDIT.json'), canonicalJson({ forged: true }))
    await expect(verify(drifted)).rejects.toThrow(/report hash drifted/)

    const unparsable = await createBundle()
    const reportPath = join(unparsable.releaseRoot, 'NPM_AUDIT.json')
    const invalidBytes = Buffer.from('not-json\n', 'utf8')
    await writeFile(reportPath, invalidBytes)
    const manifestPath = join(unparsable.releaseRoot, 'RELEASE_EVIDENCE_MANIFEST.json')
    const manifest = JSON.parse(await readFile(manifestPath, 'utf8'))
    const descriptor = manifest.reports.find(({ name }) => name === 'NPM_AUDIT.json')
    descriptor.sha256 = sha256(invalidBytes)
    descriptor.size = invalidBytes.length
    await writeFile(manifestPath, canonicalJson(manifest))
    await expect(verify(unparsable)).rejects.toThrow(/must be valid JSON/)
  }, 120_000)

  it('fails closed when a source lock hash drifts after evidence generation', async () => {
    const paths = await fixture()
    await writeReleaseEvidenceBundle({
      ...paths,
      variant: 'lean',
      releaseTier: 'early-access',
      ...IDENTITY,
      toolVersions: TOOL_VERSIONS,
      reports: reports()
    })
    await writeFile(join(paths.projectRoot, 'uv.lock'), 'version = 2\n')

    await expect(
      verifyReleaseEvidence({
        ...paths,
        variant: 'lean',
        releaseTier: 'early-access',
        expectedTag: IDENTITY.releaseTag,
        expectedCommit: IDENTITY.releaseCommit,
        expectedRunId: IDENTITY.runId
      })
    ).rejects.toThrow(/tracked source input differs from release commit: uv\.lock/)
  })

  it('rejects a tracked package or pyproject input that differs from the release commit', async () => {
    const paths = await fixture()
    const preparedPath = join(paths.projectRoot, '..', `prepared-source-${Date.now()}.json`)
    workdirs.push(preparedPath)
    const reportSet = reports()
    const commandClient = {
      async toolVersions() { return TOOL_VERSIONS },
      async npmAudit() { return reportSet.npmAudit },
      async npmSbom() { return reportSet.npmSbom },
      async pythonSbom() { return reportSet.pythonSbom }
    }
    await prepareReleaseEvidence({
      ...paths,
      output: preparedPath,
      variant: 'lean',
      releaseTier: 'early-access',
      ...IDENTITY,
      commandClient,
      osvClient: { async auditPython() { return reportSet.pythonAudit } }
    })
    await writeFile(
      join(paths.projectRoot, 'desktop', 'package.json'),
      `${JSON.stringify({ name: 'aggregator-desktop', version: '0.2.0', forged: true })}\n`
    )

    await expect(
      finalizePreparedReleaseEvidence({
        ...paths,
        input: preparedPath,
        variant: 'lean',
        releaseTier: 'early-access',
        ...IDENTITY
      })
    ).rejects.toThrow(/tracked source input differs from release commit: desktop\/package\.json/)
  })

  it('rejects semver-looking tool versions that drift from the pinned release toolchain', async () => {
    const paths = await fixture()
    await expect(
      writeReleaseEvidenceBundle({
        ...paths,
        variant: 'lean',
        releaseTier: 'early-access',
        ...IDENTITY,
        toolVersions: {
          ...TOOL_VERSIONS,
          node: { ...TOOL_VERSIONS.node, version: '99.0.0' }
        },
        reports: reports()
      })
    ).rejects.toThrow(/node version does not match pinned release toolchain/)
  })

  it('rejects a tool descriptor whose absolute bytes drift or whose executable is a script shim', async () => {
    const paths = await fixture()
    await expect(
      writeReleaseEvidenceBundle({
        ...paths,
        variant: 'lean',
        releaseTier: 'early-access',
        ...IDENTITY,
        toolVersions: {
          ...TOOL_VERSIONS,
          uv: { ...TOOL_VERSIONS.uv, sha256: '0'.repeat(64) }
        },
        reports: reports()
      })
    ).rejects.toThrow(/uv tool bytes drifted/)

    await expect(() => createReleaseCommandClient({
      projectRoot: paths.projectRoot,
      npmCliPath: toolSeeds.npm.path,
      nodePath: toolSeeds.node.path,
      uvPath: toolSeeds.npm.path,
      pythonPath: toolSeeds.python.path,
      gitPath: toolSeeds.git.path
    })).toThrow(/uv tool cannot be a script shim/)
  })

  it('rejects an npm SBOM component whose purl does not match its locked ecosystem identity', async () => {
    const paths = await fixture()
    const forged = reports()
    forged.npmSbom.components[0].purl = 'pkg:pypi/react@18.3.1'

    await expect(
      writeReleaseEvidenceBundle({
        ...paths,
        variant: 'lean',
        releaseTier: 'early-access',
        ...IDENTITY,
        toolVersions: TOOL_VERSIONS,
        reports: forged
      })
    ).rejects.toThrow(/npm SBOM.*purl|npm SBOM.*ecosystem/i)
  })

  it('requires the Python SBOM and OSV audit to cover only the active Python marker fork', async () => {
    const complete = await fixture()
    await prepareMarkerEvaluationEnvironment(complete.projectRoot)
    const completeReports = reports()
    await writeFile(
      join(complete.projectRoot, 'uv.lock'),
      'version = 1\nresolution-markers = ["python_full_version < \'3.12\'", "python_full_version >= \'3.12\'"]\n\n[[package]]\nname = "anyio"\nversion = "4.14.0"\nsource = { registry = "https://pypi.org/simple" }\n\n[[package]]\nname = "demo"\nversion = "1.0.0"\nsource = { registry = "https://pypi.org/simple" }\nresolution-markers = ["python_full_version < \'3.12\'"]\n\n[[package]]\nname = "demo"\nversion = "2.0.0"\nsource = { registry = "https://pypi.org/simple" }\nresolution-markers = ["python_full_version >= \'3.12\'"]\n\n[[package]]\nname = "llm-aggregator"\nversion = "0.1.0"\nsource = { virtual = "." }\ndependencies = [\n    { name = "anyio" },\n    { name = "demo", version = "1.0.0", marker = "python_full_version < \'3.12\'" },\n    { name = "demo", version = "2.0.0", marker = "python_full_version >= \'3.12\'" },\n]\n'
    )
    const uvBytes = await readFile(join(complete.projectRoot, 'uv.lock'))
    Object.assign(
      complete.sourceSnapshot.sourceSnapshot.files.find(({ path }) => path === 'uv.lock'),
      {
        gitBlob: createHash('sha1')
          .update(Buffer.from(`blob ${uvBytes.length}\0`))
          .update(uvBytes)
          .digest('hex'),
        sha256: sha256(uvBytes),
        size: uvBytes.length
      }
    )
    const completeTree = createHash('sha1')
      .update(canonicalJson(complete.sourceSnapshot.sourceSnapshot.files), 'utf8')
      .digest('hex')
    complete.sourceSnapshot.sourceSnapshot.git.expectedTree = completeTree
    complete.sourceSnapshot.sourceSnapshot.git.headTree = completeTree
    completeReports.pythonSbom.components.push({
      'bom-ref': 'demo-2@2.0.0',
      type: 'library',
      name: 'demo',
      version: '2.0.0',
      purl: 'pkg:pypi/demo@2.0.0'
    })
    completeReports.pythonAudit.packages.push({ name: 'demo', version: '2.0.0', vulnerabilities: [] })
    await expect(
      writeReleaseEvidenceBundle({
        ...complete,
        variant: 'lean',
        releaseTier: 'early-access',
        ...IDENTITY,
        toolVersions: TOOL_VERSIONS,
        reports: completeReports
      })
    ).resolves.toBeDefined()

    const incomplete = await fixture()
    await prepareMarkerEvaluationEnvironment(incomplete.projectRoot)
    await writeFile(join(incomplete.projectRoot, 'uv.lock'), await readFile(join(complete.projectRoot, 'uv.lock')))
    const incompleteUvBytes = await readFile(join(incomplete.projectRoot, 'uv.lock'))
    Object.assign(
      incomplete.sourceSnapshot.sourceSnapshot.files.find(({ path }) => path === 'uv.lock'),
      {
        gitBlob: createHash('sha1')
          .update(Buffer.from(`blob ${incompleteUvBytes.length}\0`))
          .update(incompleteUvBytes)
          .digest('hex'),
        sha256: sha256(incompleteUvBytes),
        size: incompleteUvBytes.length
      }
    )
    const incompleteTree = createHash('sha1')
      .update(canonicalJson(incomplete.sourceSnapshot.sourceSnapshot.files), 'utf8')
      .digest('hex')
    incomplete.sourceSnapshot.sourceSnapshot.git.expectedTree = incompleteTree
    incomplete.sourceSnapshot.sourceSnapshot.git.headTree = incompleteTree
    const incompleteReports = reports()
    await expect(
      writeReleaseEvidenceBundle({
        ...incomplete,
        variant: 'lean',
        releaseTier: 'early-access',
        ...IDENTITY,
        toolVersions: TOOL_VERSIONS,
        reports: incompleteReports
      })
    ).rejects.toThrow(/Python SBOM does not exactly cover its release-selected locked package set/)
  }, 90_000)

  it('uses the fixed Windows CPython marker environment for both lock and CycloneDX closure', () => {
    const lock = `version = 1

[[package]]
name = "base"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "win-only"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "mac-only"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "linux-only"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "old-python"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "llm-aggregator"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "base" },
    { name = "win-only", marker = "sys_platform == 'win32' and platform_system == 'Windows'" },
    { name = "mac-only", marker = "sys_platform == 'darwin'" },
    { name = "linux-only", marker = "sys_platform == 'linux'" },
    { name = "old-python", marker = "python_full_version < '3.12'" },
]
`
    expect(selectedPythonPackagesFromUvLock(lock)).toEqual([
      { name: 'base', version: '1.0.0' },
      { name: 'win-only', version: '1.0.0' }
    ])
    const component = (name, marker) => ({
      'bom-ref': `${name}@1.0.0`,
      type: 'library',
      name,
      version: '1.0.0',
      purl: `pkg:pypi/${name}@1.0.0`,
      ...(marker ? { properties: [{ name: 'uv:package:marker', value: marker }] } : {})
    })
    const filtered = filterPythonSbomForReleaseEnvironment({
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      version: 1,
      components: [
        component('base'),
        component('win-only', "sys_platform == 'win32'"),
        component('mac-only', "sys_platform == 'darwin'"),
        component('linux-only', "sys_platform == 'linux'"),
        component('old-python', "python_full_version < '3.12'")
      ]
    })
    expect(filtered.components.map(({ name }) => name)).toEqual(['base', 'win-only'])
  })

  it('derives only the release-selected dev closure and rejects missing, extra, or all-extras reports', async () => {
    const paths = await fixture()
    const lock = `version = 1

[[package]]
name = "anyio"
version = "4.14.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "selected-demo"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "unused"
version = "9.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "funasr"
version = "1.3.14"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "kaldiio" },
    { name = "torch-complex" },
]

[[package]]
name = "kaldiio"
version = "2.18.1"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "torch"
version = "2.9.1"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "torch-complex"
version = "0.4.4"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "llm-aggregator"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "anyio" },
]

[package.optional-dependencies]
asr = [
    { name = "funasr" },
    { name = "torch" },
]
dev = [
    { name = "selected-demo" },
]
`
    await replaceSourceInput(paths, 'uv.lock', lock)
    expect(selectedPythonPackagesFromUvLock(lock)).toEqual([
      { name: 'anyio', version: '4.14.0' },
      { name: 'selected-demo', version: '1.0.0' }
    ])

    const complete = reports()
    complete.pythonSbom.components.push({
      'bom-ref': 'selected-demo@1.0.0',
      type: 'library',
      name: 'selected-demo',
      version: '1.0.0',
      purl: 'pkg:pypi/selected-demo@1.0.0'
    })
    complete.pythonAudit.packages.push({ name: 'selected-demo', version: '1.0.0', vulnerabilities: [] })
    await expect(
      writeReleaseEvidenceBundle({
        ...paths,
        variant: 'lean',
        releaseTier: 'early-access',
        ...IDENTITY,
        toolVersions: TOOL_VERSIONS,
        reports: complete
      })
    ).resolves.toBeDefined()

    const missing = reports()
    await expect(
      writeReleaseEvidenceBundle({
        ...paths,
        variant: 'lean',
        releaseTier: 'early-access',
        ...IDENTITY,
        toolVersions: TOOL_VERSIONS,
        reports: missing
      })
    ).rejects.toThrow(/Python SBOM does not exactly cover its release-selected locked package set/)

    const extra = structuredClone(complete)
    extra.pythonSbom.components.push({
      'bom-ref': 'unused@9.0.0',
      type: 'library',
      name: 'unused',
      version: '9.0.0',
      purl: 'pkg:pypi/unused@9.0.0'
    })
    extra.pythonAudit.packages.push({ name: 'unused', version: '9.0.0', vulnerabilities: [] })
    await expect(
      writeReleaseEvidenceBundle({
        ...paths,
        variant: 'lean',
        releaseTier: 'early-access',
        ...IDENTITY,
        toolVersions: TOOL_VERSIONS,
        reports: extra
      })
    ).rejects.toThrow(/Python SBOM does not exactly cover its release-selected locked package set/)

    const allExtras = structuredClone(complete)
    for (const [name, version] of [
      ['funasr', '1.3.14'],
      ['kaldiio', '2.18.1'],
      ['torch', '2.9.1'],
      ['torch-complex', '0.4.4']
    ]) {
      allExtras.pythonSbom.components.push({
        'bom-ref': `${name}@${version}`,
        type: 'library',
        name,
        version,
        purl: `pkg:pypi/${name}@${version}`
      })
      allExtras.pythonAudit.packages.push({ name, version, vulnerabilities: [] })
    }
    await expect(
      writeReleaseEvidenceBundle({
        ...paths,
        variant: 'lean',
        releaseTier: 'early-access',
        ...IDENTITY,
        toolVersions: TOOL_VERSIONS,
        reports: allExtras
      })
    ).rejects.toThrow(/forbidden Python release package.*(?:funasr|kaldiio|torch)/i)
  })

  it('rejects evaluation-only licensing in the selected Python SBOM', async () => {
    const paths = await fixture()
    const invalid = reports()
    invalid.pythonSbom.components[0].licenses = [
      { license: { name: 'SOFTWARE LICENSE AGREEMENT FOR EVALUATION' } }
    ]
    await expect(
      writeReleaseEvidenceBundle({
        ...paths,
        variant: 'lean',
        releaseTier: 'early-access',
        ...IDENTITY,
        toolVersions: TOOL_VERSIONS,
        reports: invalid
      })
    ).rejects.toThrow(/evaluation-only Python license/i)
  })

  it('uses the single explicit dev selector for the pinned Python SBOM export', async () => {
    const paths = await fixture()
    const calls = []
    const client = createReleaseCommandClient({
      projectRoot: paths.projectRoot,
      npmCliPath: toolSeeds.npm.path,
      nodePath: toolSeeds.node.path,
      uvPath: toolSeeds.uv.path,
      pythonPath: toolSeeds.python.path,
      gitPath: toolSeeds.git.path,
      execute: async (command, args) => {
        calls.push({ command, args })
        return { code: 0, stdout: `${JSON.stringify(reports().pythonSbom)}\n`, stderr: '' }
      }
    })
    await client.pythonSbom()
    const exportCall = calls.find(({ args }) => args[0] === 'export')
    expect(exportCall.args).toEqual(pythonReleaseSbomArgs(paths.projectRoot))
    expect(exportCall.args).toContain('dev')
    expect(exportCall.args).not.toContain('--all-extras')
    expect(exportCall.args).not.toContain('--all-groups')
  })

  it('requires canonical all-zero npm audit objects and exact lock dependency counts', async () => {
    for (const mutate of [
      (audit) => { audit.metadata.vulnerabilities = [] },
      (audit) => { audit.metadata.vulnerabilities.low = 0.5 },
      (audit) => { audit.metadata.dependencies.total = 0 }
    ]) {
      const paths = await fixture()
      const invalid = reports()
      mutate(invalid.npmAudit)
      await expect(
        writeReleaseEvidenceBundle({
          ...paths,
          variant: 'lean',
          releaseTier: 'early-access',
          ...IDENTITY,
          toolVersions: TOOL_VERSIONS,
          reports: invalid
        })
      ).rejects.toThrow(/npm vulnerability audit is missing, invalid, or non-zero/)
    }
  })

  it('rejects npm audit evidence unless the pinned CLI exits zero', async () => {
    const paths = await fixture()
    const client = createReleaseCommandClient({
      projectRoot: paths.projectRoot,
      npmCliPath: toolSeeds.npm.path,
      nodePath: toolSeeds.node.path,
      uvPath: toolSeeds.uv.path,
      pythonPath: toolSeeds.python.path,
      gitPath: toolSeeds.git.path,
      execute: async (_command, args) => ({
        code: args.includes('audit') ? 1 : 0,
        stdout: `${JSON.stringify(reports().npmAudit)}\n`,
        stderr: ''
      })
    })

    await expect(client.npmAudit()).rejects.toThrow(/did not exit zero/)
  })

  it('removes generator UUID and timestamp noise from canonical CycloneDX evidence', async () => {
    const first = await fixture()
    const second = await fixture()
    const firstReports = reports()
    const secondReports = reports()
    for (const [index, reportSet] of [firstReports, secondReports].entries()) {
      for (const key of ['npmSbom', 'pythonSbom']) {
        reportSet[key].serialNumber = `urn:uuid:00000000-0000-0000-0000-00000000000${index}`
        reportSet[key].metadata = { timestamp: `2026-07-15T00:00:0${index}.000Z` }
      }
    }
    for (const [paths, reportSet] of [
      [first, firstReports],
      [second, secondReports]
    ]) {
      await writeReleaseEvidenceBundle({
        ...paths,
        variant: 'lean',
        releaseTier: 'early-access',
        ...IDENTITY,
        toolVersions: TOOL_VERSIONS,
        reports: reportSet
      })
    }

    for (const name of ['NPM_SBOM.cdx.json', 'PYTHON_SBOM.cdx.json']) {
      expect(await readFile(join(first.releaseRoot, name))).toEqual(
        await readFile(join(second.releaseRoot, name))
      )
    }
  }, 90_000)

  it('collects locked SBOM and zero-vulnerability reports through explicit external boundaries', async () => {
    const paths = await fixture()
    const sourceReports = reports()
    const commandClient = {
      toolVersions: async () => TOOL_VERSIONS,
      npmAudit: async () => sourceReports.npmAudit,
      npmSbom: async () => sourceReports.npmSbom,
      pythonSbom: async () => sourceReports.pythonSbom
    }
    const osvClient = {
      auditPython: async (packages) => ({
        schema: 1,
        source: 'https://api.osv.dev/v1/querybatch',
        ecosystem: 'PyPI',
        packages: packages.map((item) => ({ ...item, vulnerabilities: [] })),
        vulnerabilityCount: 0
      })
    }

    await expect(
      collectReleaseEvidenceReports({ projectRoot: paths.projectRoot, commandClient, osvClient })
    ).resolves.toEqual({
      reports: sourceReports,
      toolVersions: TOOL_VERSIONS
    })
  })

  it('normalizes an OSV batch response and counts every vulnerable locked package', async () => {
    const client = createOsvAuditClient({
      fetchImpl: async () =>
        new Response(
          JSON.stringify({
            results: [
              {},
              {
                vulns: [
                  {
                    id: 'GHSA-test-0001',
                    aliases: ['CVE-2099-0001'],
                    modified: '2099-01-02T00:00:00Z'
                  }
                ]
              }
            ]
          }),
          { status: 200, headers: { 'content-type': 'application/json' } }
        )
    })

    await expect(
      client.auditPython([
        { name: 'anyio', version: '4.14.0' },
        { name: 'demo', version: '1.0.0' }
      ])
    ).resolves.toEqual({
      schema: 1,
      source: 'https://api.osv.dev/v1/querybatch',
      ecosystem: 'PyPI',
      packages: [
        { name: 'anyio', version: '4.14.0', vulnerabilities: [] },
        {
          name: 'demo',
          version: '1.0.0',
          vulnerabilities: [
            {
              aliases: ['CVE-2099-0001'],
              id: 'GHSA-test-0001',
              modified: '2099-01-02T00:00:00Z'
            }
          ]
        }
      ],
      vulnerabilityCount: 1
    })
  })

  it('accepts a missing OSV vulns field but rejects null, arrays, and non-array vulns', async () => {
    const audit = async (result) =>
      await createOsvAuditClient({
        fetchImpl: async () => new Response(JSON.stringify({ results: [result] }), { status: 200 })
      }).auditPython([{ name: 'anyio', version: '4.14.0' }])

    await expect(audit({})).resolves.toMatchObject({ vulnerabilityCount: 0 })
    await expect(audit(null)).rejects.toThrow(/result is invalid/)
    await expect(audit([])).rejects.toThrow(/result is invalid/)
    await expect(audit({ vulns: null })).rejects.toThrow(/vulnerability list is invalid/)
    await expect(audit({ vulns: {} })).rejects.toThrow(/vulnerability list is invalid/)
  })

  it('blocks a moved tag before collecting audit evidence', async () => {
    const paths = await fixture()
    let collected = false
    const commandClient = {
      toolVersions: async () => {
        collected = true
        return TOOL_VERSIONS
      },
      npmAudit: async () => reports().npmAudit,
      npmSbom: async () => reports().npmSbom,
      pythonSbom: async () => reports().pythonSbom
    }
    await expect(
      generateReleaseEvidence({
        ...paths,
        variant: 'lean',
        releaseTier: 'early-access',
        ...IDENTITY,
        commandClient,
        osvClient: { auditPython: async () => reports().pythonAudit },
        sourceControlClient: {
          releaseSnapshot: async () => {
            const moved = structuredClone(paths.sourceSnapshot)
            moved.sourceSnapshot.git.tagCommit = 'b'.repeat(40)
            return moved
          }
        }
      })
    ).rejects.toThrow(/commit\/tag\/tree identity is invalid/)
    expect(collected).toBe(false)
  })

  it('rechecks tag, HEAD, tree and blobs after evidence verification', async () => {
    const paths = await fixture()
    await writeReleaseEvidenceBundle({
      ...paths,
      variant: 'lean',
      releaseTier: 'early-access',
      ...IDENTITY,
      toolVersions: TOOL_VERSIONS,
      reports: reports()
    })
    let calls = 0
    const movingSource = {
      async releaseSnapshot() {
        calls += 1
        const snapshot = structuredClone(paths.sourceSnapshot)
        snapshot.sourceSnapshot.git.tagCommit = calls === 1 ? IDENTITY.releaseCommit : 'b'.repeat(40)
        return snapshot
      }
    }

    await expect(
      verifyReleaseEvidence({
        ...paths,
        variant: 'lean',
        releaseTier: 'early-access',
        expectedTag: IDENTITY.releaseTag,
        expectedCommit: IDENTITY.releaseCommit,
        expectedRunId: IDENTITY.runId,
        sourceControlClient: movingSource
      })
    ).rejects.toThrow(/commit\/tag\/tree identity is invalid/)
    expect(calls).toBe(2)
  }, 90_000)
})
