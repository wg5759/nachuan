import { createHash, generateKeyPairSync, sign } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { createServer } from 'node:http'
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'

import { afterAll, afterEach, describe, expect, it, vi } from 'vitest'

import { createSettledAsarPackage } from './asar-test-fixture.mjs'
import { canonicalUpdateManifest } from './sign-update-manifest.mjs'
import { executeEarlyAccessStorageTransaction } from './early-access-storage-transaction.mjs'
import {
  RELEASE_EVIDENCE_FILES,
  RELEASE_TOOL_VERSIONS,
  writeReleaseEvidenceBundle
} from './release-evidence.mjs'
import { renderUpdateTrustModule } from './write-update-trust.mjs'
import { writeTreeManifest } from './installer-closure.mjs'
import { pyinstallerArchiveViewerDescriptor } from './python-release-policy.mjs'

const workdirs = []
const servers = []
const sourceClients = new Map()
// This file deliberately hashes and serves real minimum-size (25 MiB)
// installer fixtures several times to prove post-write state. Keep the normal
// project default for other suites, but give these deterministic I/O tests a
// realistic per-test budget on slower Windows disks.
vi.setConfig({ testTimeout: 300_000 })
afterAll(() => vi.resetConfig())
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex')
const canonicalValue = (value) =>
  Array.isArray(value)
    ? value.map(canonicalValue)
    : value && typeof value === 'object'
      ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalValue(value[key])]))
      : value
const canonicalJson = (value) => `${JSON.stringify(canonicalValue(value), null, 2)}\n`
const MIN_INSTALLER_BYTES = 25 * 1024 * 1024
const RELEASE_IDENTITY = {
  releaseTag: 'v0.2.0',
  releaseCommit: 'a'.repeat(40),
  releaseRunId: '123456789'
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
const publishEarlyAccess = (options) =>
  executeEarlyAccessStorageTransaction({
    ...RELEASE_IDENTITY,
    sourceControlClient: sourceClients.get(options.releaseRoot),
    fetchImpl: globalThis.fetch,
    ...options
  })

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

async function closeTestServer(server) {
  await new Promise((accept, reject) => {
    server.close((error) => (error ? reject(error) : accept()))
    server.closeIdleConnections?.()
    server.closeAllConnections?.()
  })
}
const releaseToolSeeds = {
  node: { path: process.execPath, version: RELEASE_TOOL_VERSIONS.node },
  npm: { path: npmCliPath, version: RELEASE_TOOL_VERSIONS.npm },
  python: { path: checkedCommand('uv', ['python', 'find', RELEASE_TOOL_VERSIONS.python]), version: RELEASE_TOOL_VERSIONS.python },
  uv: { path: checkedCommand('where.exe', ['uv']).split(/\r?\n/)[0], version: RELEASE_TOOL_VERSIONS.uv },
  git: {
    path: checkedCommand('where.exe', ['git']).split(/\r?\n/)[0],
    version: checkedCommand('git', ['--version']).replace(/^git version\s+/, '')
  }
}
const RELEASE_TOOLS = Object.fromEntries(
  await Promise.all(Object.entries(releaseToolSeeds).map(async ([name, value]) => {
    const bytes = await readFile(value.path)
    return [name, { name, path: value.path, sha256: sha256(bytes), size: bytes.length, version: value.version }]
  }))
)
RELEASE_TOOLS.pyinstallerArchiveViewer = await pyinstallerArchiveViewerDescriptor(resolve(process.cwd(), '..'))

function releaseEvidenceReports() {
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

function signedEnvelopeBytes(manifest, privateKey) {
  const signature = sign(null, Buffer.from(canonicalUpdateManifest(manifest), 'utf8'), privateKey)
  return Buffer.from(
    `${JSON.stringify(
      {
        schema: 1,
        manifest,
        signature: { algorithm: 'Ed25519', keyId: manifest.keyId, value: signature.toString('base64') }
      },
      null,
      2
    )}\n`
  )
}

afterEach(async () => {
  sourceClients.clear()
  await Promise.all(servers.splice(0).map(closeTestServer))
  await Promise.all(workdirs.splice(0).map((path) => rm(path, { recursive: true, force: true })))
}, 90_000)

async function releaseFixture(
  publicBaseUrl,
  { invalidPayloadManifest = false, smallInstaller = false, badSignature = false, omitEvidence = false } = {}
) {
  const parent = await mkdtemp(join(tmpdir(), 'nachuan-early-publisher-'))
  workdirs.push(parent)
  const releaseRoot = join(parent, 'desktop', 'release')
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
  await writeFile(
    join(parent, 'pyproject.toml'),
    '[project]\nname = "llm-aggregator"\nversion = "0.1.0"\n'
  )
  await writeFile(
    join(parent, 'uv.lock'),
    'version = 1\n\n[[package]]\nname = "anyio"\nversion = "4.14.0"\nsource = { registry = "https://pypi.org/simple" }\n\n[[package]]\nname = "llm-aggregator"\nversion = "0.1.0"\nsource = { virtual = "." }\n\n[package.optional-dependencies]\ndev = [{ name = "anyio" }]\n\n[package.dev-dependencies]\ndev = [{ name = "anyio" }]\n'
  )
  await writeFile(
    join(parent, 'desktop', 'package.json'),
    `${JSON.stringify({ name: 'aggregator-desktop', version: '0.2.0' })}\n`
  )
  await writeFile(
    join(parent, 'desktop', 'package-lock.json'),
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
  const sourceInputNames = [
    'pyproject.toml',
    'uv.lock',
    'desktop/package.json',
    'desktop/package-lock.json'
  ]
  const sourceInputs = []
  for (const name of sourceInputNames) {
    const bytes = await readFile(join(parent, ...name.split('/')))
    sourceInputs.push({
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
  const gitIdentity = { fixture: 'git', revision: '1' }
  const sourceSnapshot = {
    schema: 'nachuan.release-source-freeze/v2',
    generatedSource: generatedSource(),
    gitToolchain: {
      schema: 'nachuan.git-toolchain-closure/v1',
      version: RELEASE_TOOLS.git.version,
      gitPath: RELEASE_TOOLS.git.path,
      runtimeRoot: dirname(RELEASE_TOOLS.git.path),
      runtimeBin: dirname(RELEASE_TOOLS.git.path),
      execPath: dirname(RELEASE_TOOLS.git.path),
      archiveSha256: 'e'.repeat(64),
      runtimeTreeSha256: 'f'.repeat(64),
      lockSha256: '1'.repeat(64),
      directories: [],
      files: [{
        path: RELEASE_TOOLS.git.path,
        relativePath: 'mingw64/bin/git.exe',
        roles: ['runtime-core', 'selected-git-executable'],
        sha256: RELEASE_TOOLS.git.sha256,
        size: RELEASE_TOOLS.git.size,
        identity: gitIdentity
      }]
    },
    sourceSnapshot: {
      schema: 'nachuan.release-source-snapshot/v1',
      git: {
        objectFormat: 'sha1',
        expectedCommit: RELEASE_IDENTITY.releaseCommit,
        expectedTag: RELEASE_IDENTITY.releaseTag,
        expectedTree: 'c'.repeat(40),
        headCommit: RELEASE_IDENTITY.releaseCommit,
        headTree: 'c'.repeat(40),
        tagCommit: RELEASE_IDENTITY.releaseCommit,
        tagObject: 'd'.repeat(40)
      },
      toolchain: {
        git: {
          path: RELEASE_TOOLS.git.path,
          sha256: RELEASE_TOOLS.git.sha256,
          size: RELEASE_TOOLS.git.size,
          identity: gitIdentity
        }
      },
      scope: {
        files: [...sourceInputNames],
        optionalFiles: [],
        directories: ['desktop'],
        optionalDirectories: [],
        excludedPaths: ['desktop/node_modules']
      },
      directories: [],
      files: sourceInputs,
      totalBytes: sourceInputs.reduce((total, item) => total + item.size, 0)
    }
  }
  const sourceControlClient = {
    async releaseSnapshot() {
      for (const expected of sourceInputs) {
        const bytes = await readFile(join(parent, ...expected.path.split('/')))
        const blob = createHash('sha1')
          .update(Buffer.from(`blob ${bytes.length}\0`))
          .update(bytes)
          .digest('hex')
        if (blob !== expected.gitBlob) throw new Error(`tracked source input differs from release commit: ${expected.path}`)
      }
      return structuredClone(sourceSnapshot)
    }
  }
  sourceClients.set(releaseRoot, sourceControlClient)
  const artifact = 'nachuan-0.2.0-lean-early-access-unsigned-win.exe'
  const blockmap = `${artifact}.blockmap`
  const channel = 'early-access-lean.yml'
  const envelopeName = 'early-access-lean-win-x64.json'
  const installerBytes = Buffer.alloc(smallInstaller ? 40 : MIN_INSTALLER_BYTES)
  installerBytes.write('MZ')
  const files = new Map([
    [artifact, installerBytes],
    [blockmap, Buffer.from('deterministic blockmap fixture')],
    [channel, Buffer.from(`version: 0.2.0\npath: ${artifact}\n`)]
  ])
  const pair = generateKeyPairSync('ed25519')
  const keyId = 'early-release-2026-07'
  const manifest = {
    schema: 1,
    channel: 'early-access-lean-win-x64',
    platform: 'win32',
    arch: 'x64',
    variant: 'lean',
    version: '0.2.0',
    sequence: 1,
    keyId,
    artifact: {
      name: artifact,
      size: files.get(artifact).length,
      sha256: sha256(files.get(artifact))
    }
  }
  let envelopeBytes = signedEnvelopeBytes(manifest, pair.privateKey)
  if (badSignature) {
    const envelope = JSON.parse(envelopeBytes.toString('utf8'))
    const signature = Buffer.from(envelope.signature.value, 'base64')
    signature[0] ^= 1
    envelope.signature.value = signature.toString('base64')
    envelopeBytes = Buffer.from(`${JSON.stringify(envelope, null, 2)}\n`)
  }
  files.set(envelopeName, envelopeBytes)
  for (const [name, bytes] of files) await writeFile(join(releaseRoot, name), bytes)
  const asarSource = join(parent, 'asar-source')
  await mkdir(join(asarSource, 'out', 'main'), { recursive: true })
  await writeFile(
    join(asarSource, 'out', 'main', 'index.js'),
    renderUpdateTrustModule({
      schema: 1,
      enabled: true,
      releaseTier: 'early-access',
      channel: manifest.channel,
      variant: 'lean',
      keyId,
      publicKeySpkiBase64: pair.publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
      manifestUrl: new URL(envelopeName, publicBaseUrl).toString(),
      currentSequence: 1,
      keyringSequence: 0,
      keyringSha256: '',
      publisherName: '',
      signerThumbprint: ''
    })
  )
  await createSettledAsarPackage(
    asarSource,
    join(unpackedRoot, 'resources', 'app.asar')
  )
  const payloadManifestPath = join(releaseRoot, 'WIN_UNPACKED_MANIFEST.json')
  await writeTreeManifest({
    root: unpackedRoot,
    output: payloadManifestPath,
    version: '0.2.0',
    variant: 'lean'
  })
  files.set('WIN_UNPACKED_MANIFEST.json', await readFile(payloadManifestPath))
  const checksumNames = [artifact, blockmap, channel, 'WIN_UNPACKED_MANIFEST.json', envelopeName]
  await writeFile(
    join(releaseRoot, 'SHA256SUMS'),
    `${checksumNames.map((name) => `${sha256(files.get(name))}  ${name}`).join('\n')}\n`
  )
  if (!omitEvidence) {
    await writeReleaseEvidenceBundle({
      projectRoot: parent,
      releaseRoot,
      variant: 'lean',
      releaseTier: 'early-access',
      releaseTag: RELEASE_IDENTITY.releaseTag,
      releaseCommit: RELEASE_IDENTITY.releaseCommit,
      runId: RELEASE_IDENTITY.releaseRunId,
      toolVersions: RELEASE_TOOLS,
      reports: releaseEvidenceReports(),
      sourceSnapshot,
      sourceControlClient
    })
  }
  if (invalidPayloadManifest) {
    await writeFile(payloadManifestPath, '{"schema":1,"files":[]}\n')
  }
  return {
    projectRoot: parent,
    releaseRoot,
    artifact,
    blockmap,
    channel,
    envelopeName,
    keyId,
    manifest,
    privateKey: pair.privateKey,
    publicKeySpkiBase64: pair.publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
    sourceSnapshot,
    sourceControlClient
  }
}

async function objectEndpoint({
  tamperKey = '',
  tamperStorageReadback = false,
  publicWritable = false,
  anonymousStoragePutAllowed = false,
  anonymousPutPersistsOnDenial = false,
  publicPutPersistsOnDenial = false,
  anonymousDeleteAllowed = false,
  anonymousDeleteRemovesOnDenial = false,
  ignoreCreateOnly = false,
  mutateCreateOnlyBefore412 = false,
  ignoreIfMatch = false,
  rejectMatchingIfMatch = false,
  failDelete = false,
  failPutKey = '',
  barrierGetKey = '',
  objects = new Map(),
  requests = [],
  role = 'endpoint'
} = {}) {
  let barrierReads = 0
  const barrierWaiters = []
  const server = createServer(async (request, response) => {
    const url = new URL(request.url, 'http://127.0.0.1')
    const key = decodeURIComponent(url.pathname.replace(/^\//, ''))
    requests.push({
      role,
      method: request.method,
      key,
      query: url.search,
      authorization: request.headers.authorization
    })
    if (request.method === 'GET') {
      if (key === barrierGetKey && !url.search) {
        barrierReads += 1
        if (barrierReads < 2) {
          await new Promise((accept) => barrierWaiters.push(accept))
        } else {
          for (const accept of barrierWaiters.splice(0)) accept()
        }
      }
      const current = objects.get(key)
      if (!current) {
        response.statusCode = 404
        response.end()
        return
      }
      let bytes = current.bytes
      if (key === tamperKey && url.searchParams.has('nachuan_verify')) {
        bytes = Buffer.from(bytes)
        bytes[0] ^= 1
      }
      if (tamperStorageReadback && key.startsWith('probes/nachuan-storage-capability-')) {
        bytes = Buffer.from(bytes)
        bytes[0] ^= 1
      }
      response.setHeader('etag', current.etag)
      response.setHeader('content-length', String(bytes.length))
      response.end(bytes)
      return
    }
    if (request.method === 'DELETE') {
      const authorized = request.headers.authorization === 'Bearer server-only-publisher-token'
      if (!authorized && !anonymousDeleteAllowed) {
        if (anonymousDeleteRemovesOnDenial) objects.delete(key)
        response.statusCode = 401
        response.end()
        return
      }
      if (failDelete) {
        response.statusCode = 500
        response.end()
        return
      }
      const current = objects.get(key)
      if (
        !ignoreIfMatch &&
        request.headers['if-match'] &&
        request.headers['if-match'] !== current?.etag
      ) {
        response.statusCode = 412
        response.end()
        return
      }
      objects.delete(key)
      response.statusCode = current ? 204 : 404
      response.end()
      return
    }
    if (request.method !== 'PUT') {
      response.statusCode = 405
      response.end()
      return
    }
    if (key === failPutKey) {
      response.statusCode = 500
      response.end()
      return
    }
    if (
      request.headers.authorization !== 'Bearer server-only-publisher-token' &&
      !publicWritable &&
      !(anonymousStoragePutAllowed && key.startsWith('probes/nachuan-storage-capability-'))
    ) {
      if (
        (anonymousPutPersistsOnDenial && key.startsWith('probes/nachuan-storage-capability-')) ||
        (publicPutPersistsOnDenial && key.startsWith('probes/nachuan-public-write-'))
      ) {
        const chunks = []
        for await (const chunk of request) chunks.push(Buffer.from(chunk))
        const bytes = Buffer.concat(chunks)
        objects.set(key, { bytes, etag: `"${sha256(bytes)}"` })
      }
      response.statusCode = 401
      response.end()
      return
    }
    const current = objects.get(key)
    if (!ignoreCreateOnly && request.headers['if-none-match'] === '*' && current) {
      if (mutateCreateOnlyBefore412) {
        const chunks = []
        for await (const chunk of request) chunks.push(Buffer.from(chunk))
        objects.set(key, { bytes: Buffer.concat(chunks), etag: current.etag })
      }
      response.statusCode = 412
      response.end()
      return
    }
    if (!ignoreIfMatch && request.headers['if-match'] && request.headers['if-match'] !== current?.etag) {
      response.statusCode = 412
      response.end()
      return
    }
    if (rejectMatchingIfMatch && request.headers['if-match'] && request.headers['if-match'] === current?.etag) {
      response.statusCode = 412
      response.end()
      return
    }
    const chunks = []
    for await (const chunk of request) chunks.push(Buffer.from(chunk))
    const bytes = Buffer.concat(chunks)
    const etag = `"${sha256(bytes)}"`
    objects.set(key, { bytes, etag })
    response.statusCode = 201
    response.setHeader('etag', etag)
    response.end()
  })
  await new Promise((accept) => server.listen(0, '127.0.0.1', accept))
  servers.push(server)
  const address = server.address()
  return { objects, requests, baseUrl: `http://127.0.0.1:${address.port}/` }
}

async function objectServer(options = {}) {
  const objects = new Map()
  const requests = []
  const publicEndpoint = await objectEndpoint({
    objects,
    requests,
    role: 'public',
    tamperKey: options.tamperKey,
    tamperStorageReadback: options.tamperStorageReadback,
    publicWritable: options.publicWritable,
    publicPutPersistsOnDenial: options.publicPutPersistsOnDenial,
    anonymousDeleteAllowed: options.publicDeleteAllowed,
    anonymousDeleteRemovesOnDenial: options.publicDeleteRemovesOnDenial
  })
  const writeEndpoint = await objectEndpoint({
    ...options,
    objects,
    requests,
    role: 'write',
    publicWritable: false,
    publicPutPersistsOnDenial: false,
    tamperKey: ''
  })
  return {
    objects,
    requests,
    baseUrl: publicEndpoint.baseUrl,
    publicBaseUrl: publicEndpoint.baseUrl,
    writeBaseUrl: writeEndpoint.baseUrl
  }
}

describe('early-access generic publisher', () => {
  it('rejects non-loopback publishing before touching release files even when the credential is missing', async () => {
    await expect(
      publishEarlyAccess({
        variant: 'lean',
        releaseRoot: 'Z:\\definitely-missing-nachuan-release',
        publicBaseUrl: 'https://updates.nachuan.cn/',
        writeBaseUrl: 'https://publisher.nachuan.cn/',
        publicKeySpkiBase64: 'unused',
        expectedKeyId: 'unused',
        bearerToken: ''
      })
    ).rejects.toThrow(/restricted to loopback/i)
  })

  it('rejects production origins before considering their origin independence', async () => {
    await expect(
      publishEarlyAccess({
        variant: 'lean',
        releaseRoot: 'Z:\\definitely-missing-nachuan-release',
        publicBaseUrl: 'https://updates.nachuan.cn/channel/',
        writeBaseUrl: 'https://updates.nachuan.cn/channel/',
        publicKeySpkiBase64: 'unused',
        expectedKeyId: 'unused',
        bearerToken: 'server-only-credential'
      })
    ).rejects.toThrow(/restricted to loopback/i)
  })

  it('rejects a signed 40-byte fake installer before any public activation', async () => {
    const remote = await objectServer()
    const fixture = await releaseFixture(remote.baseUrl, { smallInstaller: true })

    await expect(
      publishEarlyAccess({
        variant: 'lean',
        releaseRoot: fixture.releaseRoot,
        publicBaseUrl: remote.baseUrl,
        writeBaseUrl: remote.writeBaseUrl,
        publicKeySpkiBase64: fixture.publicKeySpkiBase64,
        expectedKeyId: fixture.keyId,
        bearerToken: 'server-only-publisher-token',
        allowLocalHttp: true
      })
    ).rejects.toThrow(/manifest.*invalid|different release channel/i)
    expect(remote.objects.has(fixture.envelopeName)).toBe(false)
  })

  it('rejects a canonical-length but invalid Ed25519 signature before activation', async () => {
    const remote = await objectServer()
    const fixture = await releaseFixture(remote.baseUrl, { badSignature: true })

    await expect(
      publishEarlyAccess({
        variant: 'lean',
        releaseRoot: fixture.releaseRoot,
        publicBaseUrl: remote.baseUrl,
        writeBaseUrl: remote.writeBaseUrl,
        publicKeySpkiBase64: fixture.publicKeySpkiBase64,
        expectedKeyId: fixture.keyId,
        bearerToken: 'server-only-publisher-token',
        allowLocalHttp: true
      })
    ).rejects.toThrow(/signature is invalid/i)
    expect(remote.objects.has(fixture.envelopeName)).toBe(false)
  })

  it('rejects a finalized artifact whose unpacked manifest does not close the real resources tree', async () => {
    const remote = await objectServer()
    const fixture = await releaseFixture(remote.baseUrl, { invalidPayloadManifest: true })

    await expect(
      publishEarlyAccess({
        variant: 'lean',
        releaseRoot: fixture.releaseRoot,
        publicBaseUrl: remote.baseUrl,
        writeBaseUrl: remote.writeBaseUrl,
        publicKeySpkiBase64: fixture.publicKeySpkiBase64,
        expectedKeyId: fixture.keyId,
        bearerToken: 'server-only-publisher-token',
        allowLocalHttp: true
      })
    ).rejects.toThrow(/manifest|payload|closed/i)
  })

  it('rejects a valid finalized closure when the source-run evidence bundle is missing', async () => {
    const remote = await objectServer()
    const fixture = await releaseFixture(remote.baseUrl, { omitEvidence: true })

    await expect(
      publishEarlyAccess({
        variant: 'lean',
        releaseRoot: fixture.releaseRoot,
        publicBaseUrl: remote.baseUrl,
        writeBaseUrl: remote.writeBaseUrl,
        publicKeySpkiBase64: fixture.publicKeySpkiBase64,
        expectedKeyId: fixture.keyId,
        bearerToken: 'server-only-publisher-token',
        allowLocalHttp: true,
        ...RELEASE_IDENTITY
      })
    ).rejects.toThrow(/release evidence|NPM_AUDIT|required release artifact|source freeze/i)
    expect(remote.requests).toEqual([])
  })

  it('uploads immutable assets, reads every byte back publicly, and activates the signed envelope last', async () => {
    const remote = await objectServer()
    const fixture = await releaseFixture(remote.baseUrl)
    expect(new URL(remote.baseUrl).origin).not.toBe(new URL(remote.writeBaseUrl).origin)

    const result = await publishEarlyAccess({
      variant: 'lean',
      releaseRoot: fixture.releaseRoot,
      publicBaseUrl: remote.baseUrl,
      writeBaseUrl: remote.writeBaseUrl,
      publicKeySpkiBase64: fixture.publicKeySpkiBase64,
      expectedKeyId: fixture.keyId,
      bearerToken: 'server-only-publisher-token',
      allowLocalHttp: true
    })

    expect(result).toEqual(
      expect.objectContaining({
        version: '0.2.0',
        sequence: 1,
        activatedObject: fixture.envelopeName,
        publicWriteProbe: {
          method: 'PUT',
          status: 401,
          denied: true,
          putAbsent: true,
          deleteStatus: 401,
          deletePreserved: true
        },
        storageCapabilityProbe: {
          anonymousDeleteStatus: 401,
          anonymousPutStatus: 401,
          createOnlyConflict: true,
          matchingEtagReplace: true,
          oldEtagConflict: true
        }
      })
    )
    const versionPrefix =
      'channels/early-access-lean-win-x64/variants/lean/versions/0.2.0/sequence-1'
    expect(remote.objects.has(fixture.artifact)).toBe(false)
    expect(remote.objects.has(fixture.blockmap)).toBe(false)
    expect(remote.objects.has(fixture.channel)).toBe(false)
    expect(remote.objects.has(`${versionPrefix}/${fixture.artifact}`)).toBe(true)
    expect(remote.objects.has(`${versionPrefix}/${fixture.blockmap}`)).toBe(true)
    expect(remote.objects.has(`${versionPrefix}/${fixture.channel}`)).toBe(true)
    expect(remote.objects.has(`${versionPrefix}/${fixture.envelopeName}`)).toBe(true)
    for (const name of RELEASE_EVIDENCE_FILES) {
      expect(remote.objects.has(`${versionPrefix}/${name}`)).toBe(true)
    }
    const writes = remote.requests.filter((item) => item.method === 'PUT')
    expect(writes.at(-1).key).toBe(fixture.envelopeName)
    const publicReadbacks = remote.requests.filter(
      (item) =>
        item.role === 'public' &&
        item.method === 'GET' &&
        item.key.startsWith(`${versionPrefix}/`) &&
        item.query.includes('nachuan_verify=')
    )
    expect(publicReadbacks.length).toBeGreaterThanOrEqual(7)
    expect(publicReadbacks.every((item) => item.authorization === undefined)).toBe(true)
  })

  it('blocks before activation when the public endpoint accepts an unauthenticated write', async () => {
    const remote = await objectServer({ publicWritable: true })
    const fixture = await releaseFixture(remote.baseUrl)

    await expect(
      publishEarlyAccess({
        variant: 'lean',
        releaseRoot: fixture.releaseRoot,
        publicBaseUrl: remote.baseUrl,
        writeBaseUrl: remote.writeBaseUrl,
        publicKeySpkiBase64: fixture.publicKeySpkiBase64,
        expectedKeyId: fixture.keyId,
        bearerToken: 'server-only-publisher-token',
        allowLocalHttp: true
      })
    ).rejects.toThrow(/accepted an (?:anonymous PUT|unauthenticated write)/i)
    expect(remote.objects.has(fixture.envelopeName)).toBe(false)
  })

  it('performs zero network writes when a verified release file is changed before upload freezing', async () => {
    const remote = await objectServer({ publicWritable: true })
    const fixture = await releaseFixture(remote.baseUrl)

    await expect(
      publishEarlyAccess({
        variant: 'lean',
        releaseRoot: fixture.releaseRoot,
        publicBaseUrl: remote.baseUrl,
        writeBaseUrl: remote.writeBaseUrl,
        publicKeySpkiBase64: fixture.publicKeySpkiBase64,
        expectedKeyId: fixture.keyId,
        bearerToken: 'server-only-publisher-token',
        allowLocalHttp: true,
        verificationBarrier: async () => {
          await writeFile(join(fixture.releaseRoot, fixture.blockmap), 'tampered after verification\n')
        }
      })
    ).rejects.toThrow(/verified release file drifted.*blockmap/i)
    expect(remote.requests).toEqual([])
  })

  it('leaves no mutable channel half-activation when the sole envelope CAS crashes', async () => {
    const envelopeName = 'early-access-lean-win-x64.json'
    const remote = await objectServer({ failPutKey: envelopeName })
    const fixture = await releaseFixture(remote.baseUrl)

    await expect(
      publishEarlyAccess({
        variant: 'lean',
        releaseRoot: fixture.releaseRoot,
        publicBaseUrl: remote.baseUrl,
        writeBaseUrl: remote.writeBaseUrl,
        publicKeySpkiBase64: fixture.publicKeySpkiBase64,
        expectedKeyId: fixture.keyId,
        bearerToken: 'server-only-publisher-token',
        allowLocalHttp: true
      })
    ).rejects.toThrow(/HTTP 500/i)
    expect(remote.objects.has(fixture.channel)).toBe(false)
    expect(remote.objects.has(envelopeName)).toBe(false)
    expect(
      remote.objects.has(
        `channels/early-access-lean-win-x64/variants/lean/versions/0.2.0/sequence-1/${fixture.channel}`
      )
    ).toBe(true)
  })

  it('serializes interleaved publishers at the single envelope CAS without a channel split-brain', async () => {
    const envelopeName = 'early-access-lean-win-x64.json'
    const remote = await objectServer({ barrierGetKey: envelopeName })
    const fixture = await releaseFixture(remote.baseUrl)
    const options = {
      variant: 'lean',
      releaseRoot: fixture.releaseRoot,
      publicBaseUrl: remote.baseUrl,
      writeBaseUrl: remote.writeBaseUrl,
      publicKeySpkiBase64: fixture.publicKeySpkiBase64,
      expectedKeyId: fixture.keyId,
      bearerToken: 'server-only-publisher-token',
      allowLocalHttp: true
    }

    const outcomes = await Promise.allSettled([
      publishEarlyAccess(options),
      publishEarlyAccess(options)
    ])
    expect(outcomes.filter((item) => item.status === 'fulfilled')).toHaveLength(1)
    const rejected = outcomes.find((item) => item.status === 'rejected')
    expect(rejected?.reason).toEqual(expect.objectContaining({ message: expect.stringMatching(/compare-and-swap/i) }))
    expect(remote.objects.has(fixture.channel)).toBe(false)
    expect(remote.objects.has(envelopeName)).toBe(true)
  })

  it('refuses to replace a valid activated envelope with a non-increasing sequence', async () => {
    const remote = await objectServer()
    const fixture = await releaseFixture(remote.baseUrl)
    const previousBytes = signedEnvelopeBytes(
      { ...fixture.manifest, sequence: fixture.manifest.sequence + 1 },
      fixture.privateKey
    )
    remote.objects.set(fixture.envelopeName, {
      bytes: previousBytes,
      etag: `"${sha256(previousBytes)}"`
    })

    await expect(
      publishEarlyAccess({
        variant: 'lean',
        releaseRoot: fixture.releaseRoot,
        publicBaseUrl: remote.baseUrl,
        writeBaseUrl: remote.writeBaseUrl,
        publicKeySpkiBase64: fixture.publicKeySpkiBase64,
        expectedKeyId: fixture.keyId,
        bearerToken: 'server-only-publisher-token',
        allowLocalHttp: true
      })
    ).rejects.toThrow(/sequence.*strictly greater|strictly greater.*sequence/i)
    expect(remote.objects.get(fixture.envelopeName)?.bytes).toEqual(previousBytes)
    expect(
      remote.requests.some(
        (request) =>
          request.method === 'PUT' &&
          request.key.startsWith('channels/early-access-lean-win-x64/variants/lean/versions/')
      )
    ).toBe(false)
  })

  it.each([
    [
      'public PUT persists despite a denial response',
      { publicPutPersistsOnDenial: true },
      /public.*put.*persisted|persisted.*public.*put/i
    ],
    ['public DELETE is accepted', { publicDeleteAllowed: true }, /public.*accepted.*delete/i],
    [
      'public DELETE removes despite a denial response',
      { publicDeleteRemovesOnDenial: true },
      /public.*delete.*removed|removed.*public.*delete/i
    ],
    ['anonymous PUT is accepted', { anonymousStoragePutAllowed: true }, /anonymous put/i],
    [
      'anonymous PUT persists despite a denial response',
      { anonymousPutPersistsOnDenial: true },
      /anonymous put.*persisted|persisted.*anonymous put/i
    ],
    ['anonymous DELETE is accepted', { anonymousDeleteAllowed: true }, /anonymous delete/i],
    [
      'anonymous DELETE removes despite a denial response',
      { anonymousDeleteRemovesOnDenial: true },
      /anonymous delete.*removed|removed.*anonymous delete/i
    ],
    ['create-only replacement is accepted', { ignoreCreateOnly: true }, /create-only|if-none-match/i],
    [
      'create-only 412 changes bytes while preserving the old ETag',
      { mutateCreateOnlyBefore412: true },
      /create-only.*changed|changed.*create-only/i
    ],
    [
      'a matching ETag replacement is rejected',
      { rejectMatchingIfMatch: true },
      /matching etag|conditional replacement/i
    ],
    ['a stale ETag replacement is accepted', { ignoreIfMatch: true }, /old etag|stale etag|if-match/i],
    ['authenticated readback is changed', { tamperStorageReadback: true }, /readback/i],
    ['probe cleanup fails', { failDelete: true }, /cleanup/i]
  ])('blocks before release objects when write storage semantics fail: %s', async (_label, serverOptions, error) => {
    const remote = await objectServer(serverOptions)
    const fixture = await releaseFixture(remote.baseUrl)

    await expect(
      publishEarlyAccess({
        variant: 'lean',
        releaseRoot: fixture.releaseRoot,
        publicBaseUrl: remote.baseUrl,
        writeBaseUrl: remote.writeBaseUrl,
        publicKeySpkiBase64: fixture.publicKeySpkiBase64,
        expectedKeyId: fixture.keyId,
        bearerToken: 'server-only-publisher-token',
        allowLocalHttp: true
      })
    ).rejects.toThrow(error)
    expect(
      remote.requests.some(
        (request) =>
          request.method === 'PUT' &&
          request.key.startsWith('channels/early-access-lean-win-x64/variants/lean/versions/')
      )
    ).toBe(false)
  })

  it('fails before activation when the public readback differs and rejects test origins', async () => {
    const remote = await objectServer({
      tamperKey:
        'channels/early-access-lean-win-x64/variants/lean/versions/0.2.0/sequence-1/nachuan-0.2.0-lean-early-access-unsigned-win.exe.blockmap'
    })
    const fixture = await releaseFixture(remote.baseUrl)
    await expect(
      publishEarlyAccess({
        variant: 'lean',
        releaseRoot: fixture.releaseRoot,
        publicBaseUrl: remote.baseUrl,
        writeBaseUrl: remote.writeBaseUrl,
        publicKeySpkiBase64: fixture.publicKeySpkiBase64,
        expectedKeyId: fixture.keyId,
        bearerToken: 'server-only-publisher-token',
        allowLocalHttp: true
      })
    ).rejects.toThrow(/readback hash\/size mismatch/i)
    expect(remote.objects.has(fixture.envelopeName)).toBe(false)

    await expect(
      publishEarlyAccess({
        variant: 'lean',
        releaseRoot: fixture.releaseRoot,
        publicBaseUrl: 'https://updates.example.test/',
        writeBaseUrl: 'https://write.example.test/',
        publicKeySpkiBase64: fixture.publicKeySpkiBase64,
        expectedKeyId: fixture.keyId
      })
    ).rejects.toThrow(/test|non-public/i)
  })
})
