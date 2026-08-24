import { execFileSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { copyFile, mkdir, mkdtemp, readFile, realpath, rename, rm, symlink, utimes, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { isAbsolute, join, resolve } from 'node:path'

import { afterEach, describe, expect, it } from 'vitest'

import {
  RELEASE_SOURCE_SCOPE,
  assertReleaseSourceSnapshotUnchanged,
  captureReleaseSourceSnapshot,
  executeReleaseGitCommand,
  isReleaseSourcePath
} from './release-source-snapshot.mjs'

const workdirs = []
const TEST_SCOPE = Object.freeze({
  files: Object.freeze(['engine_main.py']),
  optionalFiles: Object.freeze([
    '.env.example',
    '.npmrc',
    '.pytest.ini',
    'pytest.ini',
    'pytest.toml',
    'setup.cfg',
    'tox.ini',
    'uv.toml'
  ]),
  directories: Object.freeze(['.github/workflows', 'desktop/scripts', 'gateway', 'orchestrator', 'scripts', 'tests']),
  optionalDirectories: Object.freeze(['.github/actions']),
  excludedPaths: Object.freeze([
    'gateway/__pycache__',
    'orchestrator/__pycache__',
    'scripts/__pycache__',
    'tests/__pycache__'
  ])
})

function findGitExecutable() {
  const configured = process.env.NACHUAN_TEST_GIT
  if (configured && isAbsolute(configured) && existsSync(configured)) return resolve(configured)
  const locator = process.platform === 'win32' ? 'where.exe' : 'which'
  const output = execFileSync(locator, ['git'], { encoding: 'utf8', windowsHide: true })
  const first = output.split(/\r?\n/u).find(Boolean)
  if (!first) throw new Error('could not locate Git for release source snapshot tests')
  return resolve(first)
}

const gitPath = findGitExecutable()

function git(repoRoot, args, options = {}) {
  return execFileSync(gitPath, ['-C', repoRoot, ...args], {
    encoding: 'utf8',
    windowsHide: true,
    ...options
  }).trim()
}

afterEach(async () => {
  await Promise.all(
    workdirs.splice(0).map((path) => rm(path, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }))
  )
})

async function fixture() {
  const repoRoot = await mkdtemp(join(tmpdir(), 'nachuan-release-source-'))
  workdirs.push(repoRoot)
  await mkdir(join(repoRoot, '.github', 'workflows'), { recursive: true })
  await mkdir(join(repoRoot, 'desktop', 'build'), { recursive: true })
  await mkdir(join(repoRoot, 'desktop', 'scripts'), { recursive: true })
  await mkdir(join(repoRoot, 'gateway'), { recursive: true })
  await mkdir(join(repoRoot, 'orchestrator'), { recursive: true })
  await mkdir(join(repoRoot, 'scripts'), { recursive: true })
  await mkdir(join(repoRoot, 'tests'), { recursive: true })
  await writeFile(join(repoRoot, '.github', 'workflows', 'release.yml'), 'name: release\n')
  await writeFile(join(repoRoot, 'desktop', 'build', 'icon.png'), 'reviewed-icon')
  await writeFile(join(repoRoot, 'engine_main.py'), 'print("engine")\n')
  await writeFile(join(repoRoot, 'gateway', 'app.py'), 'APP = "ready"\n')
  await writeFile(join(repoRoot, 'orchestrator', 'agent.py'), 'READY = True\n')
  await writeFile(join(repoRoot, 'scripts', 'check_release.py'), 'RELEASE_CHECK = True\n')
  await writeFile(join(repoRoot, 'desktop', 'scripts', 'build.mjs'), 'export const ready = true\n')
  await writeFile(join(repoRoot, 'tests', 'test_release_contract.py'), 'def test_contract():\n    assert True\n')

  git(repoRoot, ['init', '--quiet'])
  git(repoRoot, ['config', 'user.name', 'Nachuan Release Test'])
  git(repoRoot, ['config', 'user.email', 'release-test@example.invalid'])
  git(repoRoot, ['config', 'core.autocrlf', 'false'])
  git(repoRoot, ['add', '--', '.'])
  git(repoRoot, ['commit', '--quiet', '-m', 'fixture'])
  git(repoRoot, ['tag', 'v1.0.0'])
  const expectedCommit = git(repoRoot, ['rev-parse', 'HEAD'])
  const expectedTree = git(repoRoot, ['rev-parse', 'HEAD^{tree}'])
  return { repoRoot, expectedCommit, expectedTree }
}

async function capture(source, overrides = {}) {
  return captureReleaseSourceSnapshot({
    ...source,
    gitPath,
    expectedTag: 'v1.0.0',
    scope: TEST_SCOPE,
    ...overrides
  })
}

describe('release source snapshot', () => {
  it('defines the complete source/config scope while excluding dependency and output trees', () => {
    expect(RELEASE_SOURCE_SCOPE.files).toEqual(
      expect.arrayContaining([
        '.gitattributes',
        '.gitignore',
        '.python-version',
        'engine_main.py',
        'engine.spec',
        'pyproject.toml',
        'uv.lock',
        'desktop/.gitignore',
        'desktop/.npmrc',
        'desktop/electron-builder.yml',
        'desktop/electron-builder.early-access.yml',
        'desktop/electron-builder.production.yml',
        'desktop/electron.vite.config.ts',
        'desktop/native-license-registry.json',
        'desktop/package.json',
        'desktop/package-lock.json',
        'desktop/python-license-registry.json',
        'desktop/tsconfig.json'
      ])
    )
    expect(RELEASE_SOURCE_SCOPE.directories).toEqual(
      expect.arrayContaining([
        '.github/workflows',
        'bridge',
        'config',
        'gateway',
        'orchestrator',
        'scripts',
        'skills',
        'tests',
        'desktop'
      ])
    )
    expect(RELEASE_SOURCE_SCOPE.optionalFiles).toEqual(
      expect.arrayContaining([
        '.env.example',
        '.npmrc',
        '.pytest.ini',
        'pytest.ini',
        'pytest.toml',
        'setup.cfg',
        'tox.ini',
        'uv.toml'
      ])
    )
    expect(RELEASE_SOURCE_SCOPE.optionalDirectories).toEqual(['.github/actions'])
    expect(RELEASE_SOURCE_SCOPE.excludedPaths).toEqual(
      expect.arrayContaining([
        'desktop/.vite',
        'desktop/build/electron-runtime',
        'desktop/build/license-evidence',
        'desktop/src/main/generated-engine-integrity.ts',
        'desktop/src/main/generated-update-trust.ts',
        'desktop/node_modules',
        'desktop/out',
        'desktop/third-party-notices',
        'gateway/__pycache__',
        'orchestrator/__pycache__',
        'tests/__pycache__'
      ])
    )
    expect(isReleaseSourcePath('gateway/app.py')).toBe(true)
    expect(isReleaseSourcePath('.github/actions/publish/action.yml')).toBe(true)
    expect(isReleaseSourcePath('desktop/src/main/index.ts')).toBe(true)
    expect(isReleaseSourcePath('desktop/build/icon.png')).toBe(true)
    expect(isReleaseSourcePath('desktop/build/electron-runtime/electron.exe')).toBe(false)
    expect(isReleaseSourcePath('desktop/build/license-evidence/THIRD_PARTY_NOTICES.json')).toBe(false)
    expect(isReleaseSourcePath('desktop/src/main/generated-engine-integrity.ts')).toBe(false)
    expect(isReleaseSourcePath('desktop/src/main/generated-update-trust.ts')).toBe(false)
    expect(isReleaseSourcePath('gateway/__pycache__/app.pyc')).toBe(false)
    expect(isReleaseSourcePath('desktop/node_modules/pkg/index.js')).toBe(false)
    expect(isReleaseSourcePath('desktop/out/main/index.js')).toBe(false)
  })

  it('binds expected commit, tag, HEAD, tree, Git blob, content, mode, and stable file identity', async () => {
    const source = await fixture()
    const before = await capture(source)
    const after = await capture(source)

    expect(before.schema).toBe('nachuan.release-source-snapshot/v1')
    expect(before.git).toEqual({
      objectFormat: 'sha1',
      expectedCommit: source.expectedCommit,
      expectedTag: 'v1.0.0',
      expectedTree: source.expectedTree,
      headCommit: source.expectedCommit,
      headTree: source.expectedTree,
      tagCommit: source.expectedCommit,
      tagObject: source.expectedCommit
    })
    expect(before.files.map((file) => file.path)).toEqual([
      '.github/workflows/release.yml',
      'desktop/scripts/build.mjs',
      'engine_main.py',
      'gateway/app.py',
      'orchestrator/agent.py',
      'scripts/check_release.py',
      'tests/test_release_contract.py'
    ])
    for (const file of before.files) {
      expect(file.gitBlob).toMatch(/^[0-9a-f]{40}$/u)
      expect(file.gitMode).toBe('100644')
      expect(file.sha256).toMatch(/^[0-9a-f]{64}$/u)
      expect(file.size).toBeGreaterThan(0)
      expect(file.identity).toEqual(
        expect.objectContaining({
          device: expect.any(String),
          inode: expect.any(String),
          mode: expect.any(String),
          modifiedNs: expect.any(String),
          changedNs: expect.any(String)
        })
      )
    }
    expect(assertReleaseSourceSnapshotUnchanged(before, after)).toBe(true)
  })

  it('rejects tracked tampering and ignored additions under the root tests contract', async () => {
    const tampered = await fixture()
    await writeFile(
      join(tampered.repoRoot, 'tests', 'test_release_contract.py'),
      'def test_contract():\n    assert False\n'
    )
    await expect(capture(tampered)).rejects.toThrow(/byte|working-tree|drift/i)

    const ignored = await fixture()
    await writeFile(join(ignored.repoRoot, '.git', 'info', 'exclude'), 'tests/ignored_contract.py\n')
    await writeFile(join(ignored.repoRoot, 'tests', 'ignored_contract.py'), 'assert True\n')
    await expect(capture(ignored)).rejects.toThrow(/untracked|ignored|closed/i)
  })

  it('rejects tracked tampering and ignored additions under GitHub workflow contracts', async () => {
    const tampered = await fixture()
    await writeFile(join(tampered.repoRoot, '.github', 'workflows', 'release.yml'), 'name: bypassed-release\n')
    await expect(capture(tampered)).rejects.toThrow(/byte|working-tree|drift/i)

    const ignored = await fixture()
    await writeFile(join(ignored.repoRoot, '.git', 'info', 'exclude'), '.github/workflows/ignored-release.yml\n')
    await writeFile(join(ignored.repoRoot, '.github', 'workflows', 'ignored-release.yml'), 'name: hidden-release\n')
    await expect(capture(ignored)).rejects.toThrow(/untracked|ignored|closed/i)
  })

  it('treats optional GitHub actions as source when present while allowing the directory to be absent', async () => {
    const absent = await fixture()
    await expect(capture(absent)).resolves.toEqual(expect.objectContaining({ schema: 'nachuan.release-source-snapshot/v1' }))

    const injected = await fixture()
    await mkdir(join(injected.repoRoot, '.github', 'actions', 'hidden'), { recursive: true })
    await writeFile(join(injected.repoRoot, '.git', 'info', 'exclude'), '.github/actions/hidden/action.yml\n')
    await writeFile(join(injected.repoRoot, '.github', 'actions', 'hidden', 'action.yml'), 'runs: hidden\n')
    await expect(capture(injected)).rejects.toThrow(/untracked|ignored|closed/i)
  })

  it('rejects ignored backdoors and untracked DLL/data payloads inside source directories', async () => {
    const ignored = await fixture()
    await writeFile(join(ignored.repoRoot, '.git', 'info', 'exclude'), 'gateway/ignored-backdoor.py\n')
    await writeFile(join(ignored.repoRoot, 'gateway', 'ignored-backdoor.py'), 'exec("backdoor")\n')
    await expect(capture(ignored)).rejects.toThrow(/untracked|ignored|closed/i)

    const payload = await fixture()
    await writeFile(join(payload.repoRoot, 'gateway', 'native-payload.dll'), 'MZ-not-reviewed')
    await writeFile(join(payload.repoRoot, 'gateway', 'model-payload.data'), 'not-reviewed')
    await expect(capture(payload)).rejects.toThrow(/untracked|ignored|closed/i)
  })

  it('does not hide source-root payloads merely because their directory is named build, out, or release', async () => {
    const source = await fixture()
    await mkdir(join(source.repoRoot, 'gateway', 'build'), { recursive: true })
    await mkdir(join(source.repoRoot, 'orchestrator', 'out'), { recursive: true })
    await mkdir(join(source.repoRoot, 'scripts', 'release'), { recursive: true })
    await writeFile(
      join(source.repoRoot, '.git', 'info', 'exclude'),
      'gateway/build/evil.py\norchestrator/out/data.dll\nscripts/release/hidden.py\n'
    )
    await writeFile(join(source.repoRoot, 'gateway', 'build', 'evil.py'), 'exec("hidden")\n')
    await writeFile(join(source.repoRoot, 'orchestrator', 'out', 'data.dll'), 'MZ-hidden')
    await writeFile(join(source.repoRoot, 'scripts', 'release', 'hidden.py'), 'exec("hidden release")\n')

    await expect(capture(source)).rejects.toThrow(/untracked|ignored|closed/i)
  }, 120_000)

  it('allows only explicitly named desktop dependency, generated evidence, output, and cache paths', async () => {
    const source = await fixture()
    await mkdir(join(source.repoRoot, 'desktop', 'node_modules', 'pkg'), { recursive: true })
    await mkdir(join(source.repoRoot, 'desktop', 'out', 'main'), { recursive: true })
    await mkdir(join(source.repoRoot, 'desktop', '.vite', 'tool'), { recursive: true })
    await mkdir(join(source.repoRoot, 'desktop', 'build', 'electron-runtime'), { recursive: true })
    await mkdir(join(source.repoRoot, 'desktop', 'build', 'license-evidence'), { recursive: true })
    await mkdir(join(source.repoRoot, 'desktop', 'src', 'main'), { recursive: true })
    await writeFile(
      join(source.repoRoot, '.git', 'info', 'exclude'),
      'desktop/node_modules/\ndesktop/out/\ndesktop/.vite/\n' +
        'desktop/build/electron-runtime/\ndesktop/build/license-evidence/\n' +
        'desktop/src/main/generated-engine-integrity.ts\n' +
        'desktop/src/main/generated-update-trust.ts\n'
    )
    await writeFile(join(source.repoRoot, 'desktop', 'node_modules', 'pkg', 'index.js'), 'dependency')
    await writeFile(join(source.repoRoot, 'desktop', 'out', 'main', 'index.js'), 'generated output')
    await writeFile(join(source.repoRoot, 'desktop', '.vite', 'tool', 'cache.bin'), 'generated cache')
    await writeFile(join(source.repoRoot, 'desktop', 'build', 'electron-runtime', 'electron.exe'), 'MZ-runtime')
    await writeFile(
      join(source.repoRoot, 'desktop', 'build', 'license-evidence', 'THIRD_PARTY_NOTICES.json'),
      '{"generated":true}\n'
    )
    await writeFile(
      join(source.repoRoot, 'desktop', 'src', 'main', 'generated-engine-integrity.ts'),
      'export const ENGINE = "bound"\n'
    )
    await writeFile(
      join(source.repoRoot, 'desktop', 'src', 'main', 'generated-update-trust.ts'),
      'export const TRUST = "bound"\n'
    )

    await expect(
      capture(source, {
        scope: {
          files: ['engine_main.py'],
          optionalFiles: [],
          directories: ['desktop'],
          optionalDirectories: [],
          excludedPaths: RELEASE_SOURCE_SCOPE.excludedPaths
        }
      })
    ).resolves.toEqual(expect.objectContaining({ schema: 'nachuan.release-source-snapshot/v1' }))
  })

  it('does not let the two separately frozen generated paths hide an adjacent untracked source file', async () => {
    const source = await fixture()
    await mkdir(join(source.repoRoot, 'desktop', 'src', 'main'), { recursive: true })
    await writeFile(
      join(source.repoRoot, 'desktop', 'src', 'main', 'generated-engine-integrity.ts'),
      'export const ENGINE = "bound"\n'
    )
    await writeFile(
      join(source.repoRoot, 'desktop', 'src', 'main', 'generated-update-trust.ts'),
      'export const TRUST = "bound"\n'
    )
    await writeFile(
      join(source.repoRoot, 'desktop', 'src', 'main', 'generated-engine-integrity.ts.backdoor'),
      'export const HIDDEN = true\n'
    )

    await expect(
      capture(source, {
        scope: {
          files: ['engine_main.py'],
          optionalFiles: [],
          directories: ['desktop'],
          optionalDirectories: [],
          excludedPaths: RELEASE_SOURCE_SCOPE.excludedPaths
        }
      })
    ).rejects.toThrow(/untracked|ignored|closed/i)
  })

  it('allows tracked generated templates to be replaced only because v2 freezes those exact paths separately', async () => {
    const source = await fixture()
    await mkdir(join(source.repoRoot, 'desktop', 'src', 'main'), { recursive: true })
    const engine = join(source.repoRoot, 'desktop', 'src', 'main', 'generated-engine-integrity.ts')
    const trust = join(source.repoRoot, 'desktop', 'src', 'main', 'generated-update-trust.ts')
    await writeFile(engine, 'export const ENGINE = "template"\n')
    await writeFile(trust, 'export const TRUST = "template"\n')
    git(source.repoRoot, ['add', '--', 'desktop/src/main/generated-engine-integrity.ts', 'desktop/src/main/generated-update-trust.ts'])
    git(source.repoRoot, ['commit', '--quiet', '-m', 'tracked generated templates'])
    git(source.repoRoot, ['tag', '--force', 'v1.0.0'])
    const committed = {
      repoRoot: source.repoRoot,
      expectedCommit: git(source.repoRoot, ['rev-parse', 'HEAD']),
      expectedTree: git(source.repoRoot, ['rev-parse', 'HEAD^{tree}'])
    }
    await writeFile(engine, 'export const ENGINE = "producer"\n')
    await writeFile(trust, 'export const TRUST = "producer"\n')
    expect(
      git(source.repoRoot, [
        'diff',
        '--name-only',
        'HEAD',
        '--',
        'desktop',
        ':(top,literal,exclude)desktop/src/main/generated-engine-integrity.ts',
        ':(top,literal,exclude)desktop/src/main/generated-update-trust.ts'
      ])
    ).toBe('')

    await expect(
      capture(committed, {
        scope: {
          files: ['engine_main.py'],
          optionalFiles: [],
          directories: ['desktop'],
          optionalDirectories: [],
          excludedPaths: [
            'desktop/src/main/generated-engine-integrity.ts',
            'desktop/src/main/generated-update-trust.ts'
          ]
        }
      })
    ).resolves.toEqual(expect.objectContaining({ schema: 'nachuan.release-source-snapshot/v1' }))
  })

  it('binds desktop build inputs such as the packaged application icon', async () => {
    expect(isReleaseSourcePath('desktop/build/icon.png')).toBe(true)
    const source = await fixture()
    await writeFile(join(source.repoRoot, 'desktop', 'build', 'icon.png'), 'tampered-icon')

    await expect(
      capture(source, {
        scope: {
          files: ['engine_main.py'],
          optionalFiles: [],
          directories: ['desktop'],
          optionalDirectories: [],
          excludedPaths: RELEASE_SOURCE_SCOPE.excludedPaths
        }
      })
    ).rejects.toThrow(/byte|working-tree|drift|Git blob/i)
  })

  it('binds excluded-directory parent creation while allowing internals of a precreated output tree to vary', async () => {
    const broadDesktopScope = {
      files: ['engine_main.py'],
      optionalFiles: [],
      directories: ['desktop'],
      optionalDirectories: [],
      excludedPaths: RELEASE_SOURCE_SCOPE.excludedPaths
    }

    const precreated = await fixture()
    await mkdir(join(precreated.repoRoot, 'desktop', 'out', 'main'), { recursive: true })
    await writeFile(join(precreated.repoRoot, 'desktop', 'out', 'main', 'before.js'), 'generated before\n')
    const before = await capture(precreated, { scope: broadDesktopScope })
    await writeFile(join(precreated.repoRoot, 'desktop', 'out', 'main', 'during.js'), 'generated during\n')
    const after = await capture(precreated, { scope: broadDesktopScope })
    expect(assertReleaseSourceSnapshotUnchanged(before, after)).toBe(true)

    const createdLate = await fixture()
    const beforeCreation = await capture(createdLate, { scope: broadDesktopScope })
    await mkdir(join(createdLate.repoRoot, 'desktop', 'out', 'main'), { recursive: true })
    await writeFile(join(createdLate.repoRoot, 'desktop', 'out', 'main', 'late.js'), 'generated late\n')
    const afterCreation = await capture(createdLate, { scope: broadDesktopScope })
    expect(() => assertReleaseSourceSnapshotUnchanged(beforeCreation, afterCreation)).toThrow(
      /directory.*identity|identity.*directory/i
    )
  }, 120_000)

  it('forbids root Python auto-load hooks before release toolchain attestation, even when Git ignores them', async () => {
    const hooks = ['conftest.py', 'sitecustomize.py', 'usercustomize.py']
    const source = await fixture()
    await writeFile(join(source.repoRoot, '.git', 'info', 'exclude'), `${hooks.join('\n')}\n`)

    let attestationCalls = 0
    for (const hook of hooks) {
      const hookPath = join(source.repoRoot, hook)
      await writeFile(hookPath, 'raise RuntimeError("ambient hook executed")\n')
      await expect(
        capture(source, {
          onGitExecutableAttested: () => {
            attestationCalls += 1
          }
        })
      ).rejects.toThrow(/forbidden.*ambient|ambient.*forbidden|auto-load/i)
      expect(attestationCalls).toBe(0)
      await rm(hookPath)
    }
  })

  it('forbids real dotenv inputs at the repository and desktop roots', async () => {
    for (const path of ['.env', '.env.production', 'desktop/.env', 'desktop/.env.local']) {
      const source = await fixture()
      await writeFile(join(source.repoRoot, '.git', 'info', 'exclude'), `${path}\n`)
      await writeFile(join(source.repoRoot, ...path.split('/')), 'RELEASE_SECRET=ambient\n')
      await expect(capture(source)).rejects.toThrow(/forbidden.*ambient|dotenv|\.env/i)
    }
  }, 120_000)

  it('requires allowed root ambient configs and dotenv templates to be tracked and snapshot-bound', async () => {
    for (const path of ['.env.example', '.npmrc', 'pytest.ini']) {
      const source = await fixture()
      await writeFile(join(source.repoRoot, '.git', 'info', 'exclude'), `${path}\n`)
      await writeFile(join(source.repoRoot, path), 'reviewed = false\n')
      await expect(capture(source)).rejects.toThrow(/untracked|ignored|closed/i)
    }

    const tracked = await fixture()
    await writeFile(join(tracked.repoRoot, '.env.example'), 'EXAMPLE_ONLY=1\n')
    git(tracked.repoRoot, ['add', '--', '.env.example'])
    git(tracked.repoRoot, ['commit', '--quiet', '-m', 'tracked dotenv template'])
    git(tracked.repoRoot, ['tag', '--force', 'v1.0.0'])
    const expectedCommit = git(tracked.repoRoot, ['rev-parse', 'HEAD'])
    const expectedTree = git(tracked.repoRoot, ['rev-parse', 'HEAD^{tree}'])
    const snapshot = await capture({ ...tracked, expectedCommit, expectedTree })
    expect(snapshot.files.map((file) => file.path)).toContain('.env.example')
  }, 120_000)

  it('rejects a symlink or Windows junction anywhere inside a source scope', async () => {
    const source = await fixture()
    const target = join(source.repoRoot, 'outside-scope')
    await mkdir(target)
    await writeFile(join(target, 'payload.py'), 'outside = true\n')
    await symlink(
      target,
      join(source.repoRoot, 'gateway', 'redirected-source'),
      process.platform === 'win32' ? 'junction' : 'dir'
    )

    await expect(capture(source)).rejects.toThrow(/symlink|junction|redirect/i)
  })

  it('rejects a release tag moved away from the expected commit even when HEAD is restored', async () => {
    const source = await fixture()
    await writeFile(join(source.repoRoot, 'gateway', 'later.py'), 'LATER = true\n')
    git(source.repoRoot, ['add', '--', 'gateway/later.py'])
    git(source.repoRoot, ['commit', '--quiet', '-m', 'later commit'])
    git(source.repoRoot, ['tag', '--force', 'v1.0.0'])
    git(source.repoRoot, ['checkout', '--quiet', '--detach', source.expectedCommit])

    await expect(capture(source)).rejects.toThrow(/tag.*moved|tag.*expected commit/i)
  })

  it('rejects tracked byte drift before producing a release snapshot', async () => {
    const source = await fixture()
    await writeFile(join(source.repoRoot, 'gateway', 'app.py'), 'APP = "tampered"\n')

    await expect(capture(source)).rejects.toThrow(/byte|working-tree|drift/i)
  })

  it('recomputes the raw Git blob so a lying diff/filter cannot hide byte drift', async () => {
    const source = await fixture()
    await writeFile(join(source.repoRoot, 'gateway', 'app.py'), 'APP = "hidden tampering"\n')
    const executeGit = async (request) => {
      if (request.args[0] === 'diff') {
        return { exitCode: 0, signal: null, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) }
      }
      return executeReleaseGitCommand(request)
    }

    await expect(capture(source, { executeGit })).rejects.toThrow(/Git blob|committed blob|byte drift/i)
  })

  it('detects a postinstall-style temporary modification even after the original bytes are restored', async () => {
    const source = await fixture()
    const path = join(source.repoRoot, 'gateway', 'app.py')
    const before = await capture(source)
    const original = await readFile(path)
    await writeFile(path, 'APP = "temporary postinstall mutation"\n')
    await writeFile(path, original)
    const changedTime = new Date(Date.now() + 2_000)
    await utimes(path, changedTime, changedTime)
    const after = await capture(source)

    expect(after.files.find((file) => file.path === 'gateway/app.py').sha256).toBe(
      before.files.find((file) => file.path === 'gateway/app.py').sha256
    )
    expect(() => assertReleaseSourceSnapshotUnchanged(before, after)).toThrow(/identity|changed/i)
  })

  it('detects a source file temporarily added for the build and deleted before the post-snapshot', async () => {
    const source = await fixture()
    const gateway = join(source.repoRoot, 'gateway')
    const temporary = join(gateway, 'evil.py')
    const before = await capture(source)
    await writeFile(temporary, 'exec("temporary build payload")\n')
    await rm(temporary)
    const changedTime = new Date(Date.now() + 2_000)
    await utimes(gateway, changedTime, changedTime)
    const after = await capture(source)

    expect(after.files.map((file) => file.path)).toEqual(before.files.map((file) => file.path))
    expect(() => assertReleaseSourceSnapshotUnchanged(before, after)).toThrow(/directory.*identity|identity.*directory/i)
  })

  it('detects replacement of the path after the file handle opens but before hashing completes', async () => {
    const source = await fixture()
    const replacement = join(source.repoRoot, 'replacement.py')
    await writeFile(replacement, 'APP = "replacement"\n')
    let replaced = false

    await expect(
      capture(source, {
        onFileOpened: async ({ path, relativePath }) => {
          if (replaced || relativePath !== 'gateway/app.py') return
          replaced = true
          await rename(path, `${path}.opened-original`)
          await rename(replacement, path)
        }
      })
    ).rejects.toThrow(/replaced|identity changed|identity drift/i)
    expect(replaced).toBe(true)
  })

  it('rejects case-colliding Git paths before trusting the filesystem view', async () => {
    const source = await fixture()
    const executeGit = async (request) => {
      const result = await executeReleaseGitCommand(request)
      if (request.args[0] !== 'ls-tree') return result
      const marker = Buffer.from('\tgateway/app.py\0')
      const markerOffset = result.stdout.indexOf(marker)
      if (markerOffset < 0) throw new Error('test fixture did not produce gateway/app.py')
      const recordStart = result.stdout.lastIndexOf(0, markerOffset) + 1
      const recordEnd = result.stdout.indexOf(0, markerOffset)
      const duplicate = Buffer.from(
        `${result.stdout.subarray(recordStart, recordEnd).toString('utf8').replace('gateway/app.py', 'gateway/APP.py')}\0`
      )
      return { ...result, stdout: Buffer.concat([result.stdout, duplicate]) }
    }

    await expect(capture(source, { executeGit })).rejects.toThrow(/case-colliding/i)
  })

  it.each([
    ['120000', 'blob', 'symlink'],
    ['160000', 'commit', 'submodule']
  ])('rejects a tracked %s %s entry as a %s', async (mode, type) => {
    const source = await fixture()
    const executeGit = async (request) => {
      const result = await executeReleaseGitCommand(request)
      if (request.args[0] !== 'ls-tree') return result
      const firstEnd = result.stdout.indexOf(0)
      const first = result.stdout.subarray(0, firstEnd).toString('utf8')
      const replacement = first.replace(/^100644 blob/u, `${mode} ${type}`)
      return {
        ...result,
        stdout: Buffer.concat([Buffer.from(replacement), Buffer.from([0]), result.stdout.subarray(firstEnd + 1)])
      }
    }

    await expect(capture(source, { executeGit })).rejects.toThrow(/regular blob/i)
  })

  it('requires an absolute real Git executable and invokes it without a shell or secret-rich environment', async () => {
    const source = await fixture()
    await expect(capture(source, { gitPath: 'git' })).rejects.toThrow(/absolute/i)

    const calls = []
    const hostileEnvironment = {
      GIT_ALTERNATE_OBJECT_DIRECTORIES: 'hostile-alternates',
      GIT_DIR: 'hostile-git-dir',
      GIT_EXEC_PATH: 'hostile-exec-path',
      GIT_INDEX_FILE: 'hostile-index',
      GIT_OBJECT_DIRECTORY: 'hostile-objects',
      GIT_SSH_COMMAND: 'hostile-ssh-command',
      GIT_WORK_TREE: 'hostile-work-tree',
      NACHUAN_SNAPSHOT_TEST_SECRET: 'must-not-be-forwarded',
      NODE_OPTIONS: '--require hostile-bootstrap.cjs'
    }
    const previousEnvironment = new Map(
      Object.keys(hostileEnvironment).map((key) => [key, process.env[key]])
    )
    Object.assign(process.env, hostileEnvironment)
    let snapshot
    try {
      const executeGit = async (request) => {
        calls.push(request)
        return executeReleaseGitCommand(request)
      }
      snapshot = await capture(source, { executeGit })
    } finally {
      for (const [key, value] of previousEnvironment) {
        if (value === undefined) delete process.env[key]
        else process.env[key] = value
      }
    }
    expect(snapshot.toolchain.git).toEqual({
      path: gitPath,
      sha256: expect.stringMatching(/^[0-9a-f]{64}$/u),
      size: expect.any(Number),
      identity: expect.objectContaining({
        device: expect.any(String),
        inode: expect.any(String),
        mode: expect.any(String),
        modifiedNs: expect.any(String),
        changedNs: expect.any(String)
      })
    })
    expect(calls.length).toBeGreaterThan(0)
    for (const request of calls) {
      expect(request.executable).toBe(gitPath)
      expect(isAbsolute(request.executable)).toBe(true)
      expect(request.shell).toBe(false)
      expect(request.env).not.toHaveProperty('PATH')
      expect(request.env).not.toHaveProperty('NACHUAN_SNAPSHOT_TEST_SECRET')
      expect(request.env).not.toHaveProperty('GIT_ALTERNATE_OBJECT_DIRECTORIES')
      expect(request.env).not.toHaveProperty('GIT_DIR')
      expect(request.env).not.toHaveProperty('GIT_EXEC_PATH')
      expect(request.env).not.toHaveProperty('GIT_INDEX_FILE')
      expect(request.env).not.toHaveProperty('GIT_OBJECT_DIRECTORY')
      expect(request.env).not.toHaveProperty('GIT_SSH_COMMAND')
      expect(request.env).not.toHaveProperty('GIT_WORK_TREE')
      expect(request.env).not.toHaveProperty('NODE_OPTIONS')
      expect(request.env.GIT_CONFIG_NOSYSTEM).toBe('1')
      if (request.args[0] === 'diff') {
        expect(request.env.GIT_LITERAL_PATHSPECS).toBe('0')
        const separator = request.args.indexOf('--')
        expect(separator).toBeGreaterThan(-1)
        for (const pathspec of request.args.slice(separator + 1)) {
          expect(pathspec).toMatch(/^:\(top,literal(?:,exclude)?\)/u)
        }
      } else {
        expect(request.env.GIT_LITERAL_PATHSPECS).toBe('1')
      }
      expect(request.env.GIT_NO_LAZY_FETCH).toBe('1')
      expect(request.env.GIT_NO_REPLACE_OBJECTS).toBe('1')
      expect(request.env.GIT_TERMINAL_PROMPT).toBe('0')
    }
  }, 120_000)

  it('rejects Git executable replacement between its pre- and post-capture attestations', async () => {
    const source = await fixture()
    const copiedGitPath = join(source.repoRoot, process.platform === 'win32' ? 'bound-git.exe' : 'bound-git')
    await copyFile(gitPath, copiedGitPath)
    const copiedGit = await realpath(copiedGitPath)
    let replaced = false
    const executeGit = (request) => executeReleaseGitCommand({ ...request, executable: gitPath })

    await expect(
      capture(source, {
        gitPath: copiedGit,
        executeGit,
        onGitExecutableAttested: async ({ phase, path }) => {
          if (phase !== 'before' || replaced) return
          replaced = true
          await writeFile(path, 'tampered Git executable\n')
        }
      })
    ).rejects.toThrow(/Git executable.*changed|toolchain.*changed|attestation.*changed/i)
    expect(replaced).toBe(true)
  }, 120_000)

  it('enforces the output bound even when a custom Git executor violates it', async () => {
    const source = await fixture()
    const executeGit = async () => ({
      exitCode: 0,
      signal: null,
      stdout: Buffer.alloc(65, 0x61),
      stderr: Buffer.alloc(0)
    })

    await expect(
      capture(source, { executeGit, limits: { maxGitOutputBytes: 64 } })
    ).rejects.toThrow(/bounded.*output|output.*bound/i)
  })

  it('reports add/delete, mode, byte, and identity drift with exact snapshot comparison', async () => {
    const source = await fixture()
    const baseline = await capture(source)
    const clone = () => structuredClone(baseline)

    const added = clone()
    added.files.push({ ...structuredClone(added.files.at(-1)), path: 'gateway/new.py' })
    expect(() => assertReleaseSourceSnapshotUnchanged(baseline, added)).toThrow(/file set|add\/delete/i)

    const deleted = clone()
    deleted.files.pop()
    expect(() => assertReleaseSourceSnapshotUnchanged(baseline, deleted)).toThrow(/file set|add\/delete/i)

    const mode = clone()
    mode.files[0].gitMode = '100755'
    expect(() => assertReleaseSourceSnapshotUnchanged(baseline, mode)).toThrow(/mode/i)

    const bytes = clone()
    bytes.files[0].sha256 = 'f'.repeat(64)
    expect(() => assertReleaseSourceSnapshotUnchanged(baseline, bytes)).toThrow(/bytes/i)

    const identity = clone()
    identity.files[0].identity.changedNs = `${BigInt(identity.files[0].identity.changedNs) + 1n}`
    expect(() => assertReleaseSourceSnapshotUnchanged(baseline, identity)).toThrow(/identity/i)
  })
})
