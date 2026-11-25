import { readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { load as loadYaml } from 'js-yaml'
import { describe, expect, it } from 'vitest'

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..')
const source = readFileSync(join(projectRoot, '.github', 'workflows', 'ci.yml'), 'utf8')
const workflow = loadYaml(source)
const communitySource = readFileSync(
  join(projectRoot, '.github', 'workflows', 'community-release.yml'),
  'utf8'
)
const communityWorkflow = loadYaml(communitySource)

describe('clean-runner CI supply-chain contract', () => {
  it('uses the same isolated Python policy, lifecycle-disabled npm install, and pinned Electron runtime', () => {
    expect(workflow.jobs.frontend['runs-on']).toBe('windows-latest')
    const frontend = workflow.jobs.frontend.steps
    const backend = workflow.jobs.backend.steps
    const npmCi = frontend.filter((step) => String(step.run || '').includes('npm ci'))
    const electronRuntime = frontend.find((step) => String(step.name || '').includes('checksum-pinned Electron runtime'))
    const nodeRuntime = frontend.find((step) => String(step.name || '').includes('checksum-pinned Node runtime'))
    const backendNpmCi = backend.filter((step) => String(step.run || '').includes('npm --prefix desktop ci'))
    const frontendRuns = frontend.map((step) => String(step.run || '')).join('\n')
    const backendRuns = backend.map((step) => String(step.run || '')).join('\n')

    expect(npmCi).toHaveLength(1)
    expect(npmCi[0].run).toBe('npm ci --ignore-scripts')
    expect(electronRuntime?.run).toBe('node scripts/electron-runtime-policy.mjs prepare')
    expect(nodeRuntime?.run).toBe('node scripts/node-runtime-policy.mjs prepare')
    expect(frontendRuns).toContain('node scripts/python-release-policy.mjs sync')
    expect(frontendRuns).toContain('node scripts/python-release-policy.mjs attest')
    expect(frontend.findIndex((step) => String(step.name || '').includes('Sync and attest'))).toBeLessThan(
      frontend.findIndex((step) => String(step.run || '') === 'npm test')
    )
    expect(backendNpmCi).toHaveLength(1)
    expect(backendNpmCi[0].run).toBe('npm --prefix desktop ci --ignore-scripts')
    expect(backend.indexOf(backendNpmCi[0])).toBeLessThan(
      backend.findIndex((step) => String(step.name || '').includes('Sync and attest'))
    )
    expect(backendRuns).toContain('node desktop/scripts/python-release-policy.mjs sync')
    expect(backendRuns).toContain('node desktop/scripts/python-release-policy.mjs attest')
    expect(backendRuns).toContain('node desktop/scripts/python-release-policy.mjs test')
    expect(backendRuns).toContain("Join-Path $env:GITHUB_WORKSPACE 'build\\ci-python-temp'")
    const backendTest = backend.find((step) => String(step.name || '').includes('Backend tests'))
    expect(backendTest?.env).toEqual({
      TEMP: '${{ github.workspace }}\\build\\ci-python-temp',
      TMP: '${{ github.workspace }}\\build\\ci-python-temp'
    })
    expect(source).not.toMatch(/\buv\s+sync\b/i)
    expect(source).not.toMatch(/\buv\s+run\b/i)
    expect(source).not.toMatch(/python(?:\.exe)?[^\r\n]*\s-m\s+pytest/i)
    expect(source).not.toMatch(/(?:^|\s)pytest(?:\.exe)?(?:\s|$)/im)
  })

  it('clears ambient Node, Electron, and Python startup controls before any job starts', () => {
    for (const name of [
      'NODE_OPTIONS',
      'NODE_PATH',
      'NODE_EXTRA_CA_CERTS',
      'NODE_TLS_REJECT_UNAUTHORIZED',
      'ELECTRON_RUN_AS_NODE',
      'ELECTRON_MIRROR',
      'ELECTRON_BUILDER_BINARIES_MIRROR',
      'ELECTRON_CUSTOM_DIR',
      'ELECTRON_CUSTOM_FILENAME',
      'ELECTRON_CUSTOM_VERSION',
      'ELECTRON_OVERRIDE_DIST_PATH',
      'ESBUILD_BINARY_PATH',
      'npm_config_electron_builder_binaries_mirror',
      'npm_config_electron_override_dist_path',
      'npm_config_esbuild_binary_path',
      'npm_config_node_options',
      'PYTHONHOME',
      'PYTHONPATH',
      'PYTHONSTARTUP',
      'PYTHONUSERBASE'
    ]) {
      expect(workflow.env[name]).toBe('')
    }
    expect(workflow.env.npm_config_script_shell).toBe('')
    expect(workflow.env.NPM_CONFIG_STRICT_SSL).toBe('true')
  })

  it('enforces CI concurrency, web smoke build, and cross-platform Unix backend matrix', () => {
    expect(workflow.concurrency).toBeTruthy()
    expect(String(workflow.concurrency.group || '')).toContain('github.ref')
    expect(workflow.concurrency['cancel-in-progress']).toBeTruthy()

    const frontendRuns = workflow.jobs.frontend.steps.map((step) => String(step.run || '')).join('\n')
    expect(frontendRuns).toContain('npm run build:web')

    const backendUnix = workflow.jobs['backend-unix']
    expect(backendUnix).toBeTruthy()
    expect(backendUnix.strategy?.matrix?.os).toEqual(['ubuntu-latest', 'macos-latest'])
    const unixRuns = backendUnix.steps.map((step) => String(step.run || '')).join('\n')
    expect(unixRuns).toContain('node desktop/scripts/unix-backend-ci-test.mjs')
  })

  it('provides a clean-runner open-source community release workflow with SHA256SUMS and licenses', () => {
    expect(communityWorkflow.on?.push?.tags).toContain('v*')
    expect(communityWorkflow.on?.workflow_dispatch).toBeDefined()
    expect(communityWorkflow.permissions?.contents).toBe('read')
    expect(communityWorkflow.concurrency?.['cancel-in-progress']).toBe(false)
    expect(communityWorkflow.env?.NPM_CONFIG_STRICT_SSL).toBe('true')

    const buildJob = communityWorkflow.jobs?.['build-community']
    expect(buildJob).toBeTruthy()
    const matrixTargets = (buildJob.strategy?.matrix?.include || []).map((entry) => entry.os)
    expect(matrixTargets).toEqual(
      expect.arrayContaining(['ubuntu-latest', 'macos-latest', 'windows-latest'])
    )

    const buildRuns = buildJob.steps.map((step) => String(step.run || '')).join('\n')
    expect(buildRuns).toContain('npm ci --ignore-scripts')
    expect(buildRuns).toContain('npm run typecheck')
    expect(buildRuns).toContain('npm run build:web')
    expect(buildRuns).toContain('SHA256SUMS')
    expect(buildRuns).toContain('npm-license-registry.json')

    // 开源社区流不硬锁私有商业签名证书
    expect(communitySource).not.toContain('WINDOWS_CSC_LINK')
    expect(communitySource).not.toContain('CSC_LINK')
    expect(communitySource).not.toContain('WINDOWS_CSC_KEY_PASSWORD')
  })
})
