import { spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join, resolve } from 'node:path'

import { describe, expect, it } from 'vitest'

import {
  attestSelectedPythonEnvironment,
  assertNoSelectedPythonStartupHooks,
  evaluateReleasePep508Markers,
  filterPythonSbomForReleaseEnvironment,
  inspectPyInstallerArchive,
  isolatedPythonEnvironment,
  portablePyInstallerRecordDescriptors,
  pythonReleaseInterpreterPath,
  runSelectedPythonTests,
  selectedPythonTestInvocation,
  selectedPythonPackagesFromUvLock,
  withoutDerivedPyInstallerBytecode
} from './python-release-policy.mjs'

const projectRoot = resolve(process.cwd(), '..')
const projectDocument = readFileSync(resolve(projectRoot, 'pyproject.toml'), 'utf8')
const projectVersionMatch = /^version\s*=\s*"([^"]+)"$/mu.exec(
  projectDocument.slice(projectDocument.indexOf('[project]'))
)
if (!projectVersionMatch) throw new Error('project version is missing from pyproject.toml')
const projectVersion = projectVersionMatch[1]

describe('release-selected Python policy', () => {
  it('delegates wildcard and platform marker semantics to packaging.markers', () => {
    const result = evaluateReleasePep508Markers([
      "python_version == '3.12.*'",
      "sys_platform == 'win32'",
      "sys_platform == 'darwin'"
    ], { projectRoot })

    expect(result.get("python_version == '3.12.*'")).toBe(true)
    expect(result.get("sys_platform == 'win32'")).toBe(true)
    expect(result.get("sys_platform == 'darwin'")).toBe(false)
  })

  it('uses the same official marker result for the selected lock graph and SBOM', () => {
    const lock = `version = 1

[[package]]
name = "demo"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "llm-aggregator"
version = "0.1.0"
source = { editable = "." }
dependencies = [
  { name = "demo", marker = "python_version == '3.12.*'" },
]
`
    expect(selectedPythonPackagesFromUvLock(lock, { projectRoot })).toEqual([
      { name: 'demo', version: '1.0.0' }
    ])

    const filtered = filterPythonSbomForReleaseEnvironment({
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      components: [
        {
          'bom-ref': 'demo',
          name: 'demo',
          purl: 'pkg:pypi/demo@1.0.0',
          properties: [{ name: 'uv:package:marker', value: "python_version == '3.12.*'" }],
          type: 'library',
          version: '1.0.0'
        },
        {
          'bom-ref': 'darwin-only',
          name: 'darwin-only',
          purl: 'pkg:pypi/darwin-only@1.0.0',
          properties: [{ name: 'uv:package:marker', value: "sys_platform == 'darwin'" }],
          type: 'library',
          version: '1.0.0'
        }
      ],
      dependencies: [
        { ref: 'demo', dependsOn: [] },
        { ref: 'darwin-only', dependsOn: [] }
      ]
    }, { projectRoot })
    expect(filtered.components.map(({ name }) => name)).toEqual(['demo'])
    expect(filtered.dependencies).toEqual([{ ref: 'demo', dependsOn: [] }])
  })

  it('attests the installed environment as an exact bidirectional closure including the build frontend', () => {
    const installed = attestSelectedPythonEnvironment(projectRoot)

    const lock = readFileSync(resolve(projectRoot, 'uv.lock'), 'utf8')
    const expected = selectedPythonPackagesFromUvLock(lock, { projectRoot })
    expect(installed.filter(({ name }) => name !== 'llm-aggregator')).toEqual(expected)
    expect(installed).toContainEqual({ name: 'llm-aggregator', version: projectVersion })
    expect(installed.map(({ name }) => name)).toEqual(
      expect.arrayContaining(['build', 'pyproject-hooks'])
    )
    const extra = [...installed, { name: 'rogue-package', version: '9.9.9' }]
    const missing = installed.slice(0, -1)
    const fake = (packages) => () => ({
      error: null,
      signal: null,
      status: 0,
      stderr: '',
      stdout: JSON.stringify(packages)
    })
    expect(() => attestSelectedPythonEnvironment(projectRoot, fake(extra))).toThrow(/environment drifted/)
    expect(() => attestSelectedPythonEnvironment(projectRoot, fake(missing))).toThrow(/environment drifted/)
  })

  it('removes every PYTHON variable and invokes archive parsing with -I -S -B', async () => {
    expect(isolatedPythonEnvironment({
      SystemRoot: 'C:\\Windows',
      PYTHONPATH: 'C:\\attacker',
      PYTHONSTARTUP: 'C:\\attacker.py',
      PYTHONINSPECT: '1'
    })).toEqual({ SYSTEMROOT: 'C:\\Windows' })

    let invocation
    const entries = await inspectPyInstallerArchive('C:\\fixture\\engine.exe', {
      projectRoot,
      execute(command, args, options, callback) {
        invocation = { args, command, options }
        callback(null, ' engine_main\n PYZ.pyz\n', '')
      }
    })
    expect(entries).toEqual(['engine_main', 'PYZ.pyz'])
    expect(invocation.command).toBe(pythonReleaseInterpreterPath(projectRoot))
    expect(invocation.args.slice(0, 5)).toEqual(['-X', 'utf8', '-I', '-S', '-B'])
    expect(Object.keys(invocation.options.env).some((key) => key.toUpperCase().startsWith('PYTHON'))).toBe(false)
    expect(invocation.args.at(-1)).toContain('PyInstaller.utils.cliutils.archive_viewer')
  }, 60_000)

  it('tolerates derived bytecode caches while keeping the RECORD closure exact for payload files', () => {
    const actual = [
      'pyinstaller/__init__.py',
      'pyinstaller/__pycache__/__init__.cpython-312.pyc',
      'pyinstaller/building/build_main.py',
      'pyinstaller/building/__pycache__/build_main.cpython-312.pyc',
      'pyinstaller-6.21.0.dist-info/record'
    ]
    expect(withoutDerivedPyInstallerBytecode(actual).sort()).toEqual([
      'pyinstaller-6.21.0.dist-info/record',
      'pyinstaller/__init__.py',
      'pyinstaller/building/build_main.py'
    ])
    // 真实载荷新增不得被过滤吞掉
    expect(withoutDerivedPyInstallerBytecode([...actual, 'pyinstaller/evil.py'])).toContain(
      'pyinstaller/evil.py'
    )
  })

  it('keeps the locked PyInstaller payload portable across checkout-specific uv launchers', () => {
    const payload = {
      isRecord: false,
      path: 'PyInstaller/archive/readers.py',
      recordHash: 'sha256=payload',
      recordSize: '123',
      sha256: 'payload-digest',
      size: 123
    }
    const first = portablePyInstallerRecordDescriptors([
      payload,
      {
        isRecord: false,
        path: '../../Scripts/pyi-archive_viewer.exe',
        recordHash: 'sha256=checkout-a',
        recordSize: '47616',
        sha256: 'checkout-a',
        size: 47616
      },
      { isRecord: true, path: 'pyinstaller-6.21.0.dist-info/RECORD' }
    ])
    const second = portablePyInstallerRecordDescriptors([
      payload,
      {
        isRecord: false,
        path: '../../Scripts/pyi-archive_viewer.exe',
        recordHash: 'sha256=checkout-b',
        recordSize: '47616',
        sha256: 'checkout-b',
        size: 47616
      },
      { isRecord: true, path: 'pyinstaller-6.21.0.dist-info/RECORD' }
    ])

    expect(first).toEqual([{
      path: payload.path,
      recordHash: payload.recordHash,
      recordSize: payload.recordSize,
      sha256: payload.sha256,
      size: payload.size
    }])
    expect(second).toEqual(first)
  })

  it('launches pytest only through the fixed -I -S -B closure and rejects startup-hook residue', () => {
    const invocation = selectedPythonTestInvocation({
      projectRoot,
      sourceEnvironment: {
        SystemRoot: 'C:\\Windows',
        PYTHONPATH: 'C:\\attacker',
        PYTHONSTARTUP: 'C:\\attacker.py',
        PYTHONUSERBASE: 'C:\\attacker-user',
        PYTEST_ADDOPTS: '--trace'
      }
    })
    expect(invocation.command).toBe(pythonReleaseInterpreterPath(projectRoot))
    expect(invocation.args.slice(0, 5)).toEqual(['-X', 'utf8', '-I', '-S', '-B'])
    expect(invocation.args.at(-1)).toContain("PYTEST_DISABLE_PLUGIN_AUTOLOAD")
    expect(invocation.args.at(-1)).toContain(
      JSON.stringify(resolve(projectRoot, '.venv', 'Lib', 'site-packages'))
    )
    expect(invocation.args.at(-1)).toContain(JSON.stringify(resolve(projectRoot, 'tests')))
    expect(invocation.options.env).toEqual({ SYSTEMROOT: 'C:\\Windows' })

    let captured
    let attested = 0
    runSelectedPythonTests({
      projectRoot,
      attest: () => { attested += 1 },
      execute: (command, args, options) => {
        captured = { args, command, options }
        return { error: null, signal: null, status: 0 }
      },
      sourceEnvironment: { SystemRoot: 'C:\\Windows', PYTHONPATH: 'C:\\attacker' }
    })
    expect(attested).toBe(2)
    expect(captured.args.slice(0, 5)).toEqual(['-X', 'utf8', '-I', '-S', '-B'])

    const attackerRoot = mkdtempSync(join(projectRoot, '.nachuan-sitecustomize-test-'))
    try {
      mkdirSync(join(attackerRoot, '.venv', 'Lib', 'site-packages'), { recursive: true })
      writeFileSync(join(attackerRoot, '.venv', 'Lib', 'site-packages', 'sitecustomize.py'), 'raise SystemExit(99)\n')
      expect(() => assertNoSelectedPythonStartupHooks(attackerRoot)).toThrow(/startup hook/i)
    } finally {
      rmSync(attackerRoot, { force: true, recursive: true })
    }
  })

  it('proves PYTHONPATH, PYTHONSTARTUP, sitecustomize, and usercustomize cannot execute at startup', () => {
    const attackerRoot = mkdtempSync(join(projectRoot, '.nachuan-python-startup-attack-'))
    const marker = join(attackerRoot, 'ATTACK_EXECUTED')
    try {
      const payload = `from pathlib import Path\nPath(${JSON.stringify(marker)}).write_text('executed')\n`
      writeFileSync(join(attackerRoot, 'sitecustomize.py'), payload)
      writeFileSync(join(attackerRoot, 'usercustomize.py'), payload)
      writeFileSync(join(attackerRoot, 'startup.py'), payload)
      const result = spawnSync(
        pythonReleaseInterpreterPath(projectRoot),
        [
          '-X',
          'utf8',
          '-I',
          '-S',
          '-B',
          '-c',
          "import sys;assert 'sitecustomize' not in sys.modules;assert 'usercustomize' not in sys.modules"
        ],
        {
          cwd: projectRoot,
          encoding: 'utf8',
          env: isolatedPythonEnvironment({
            ...process.env,
            PYTHONPATH: attackerRoot,
            PYTHONSTARTUP: join(attackerRoot, 'startup.py'),
            PYTHONUSERBASE: attackerRoot
          }),
          timeout: 30_000,
          windowsHide: true
        }
      )
      expect(result.status).toBe(0)
      expect(result.stderr).toBe('')
      expect(existsSync(marker)).toBe(false)
    } finally {
      rmSync(attackerRoot, { force: true, recursive: true })
    }
  })
})
