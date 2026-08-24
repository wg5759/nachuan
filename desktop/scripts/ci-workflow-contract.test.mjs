import { readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { load as loadYaml } from 'js-yaml'
import { describe, expect, it } from 'vitest'

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..')
const source = readFileSync(join(projectRoot, '.github', 'workflows', 'ci.yml'), 'utf8')
const workflow = loadYaml(source)

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
})
