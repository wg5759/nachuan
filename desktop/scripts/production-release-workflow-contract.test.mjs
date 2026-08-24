import { readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { load as loadYaml } from 'js-yaml'
import { describe, expect, it } from 'vitest'

const desktopRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const workflowPath = join(desktopRoot, '..', '.github', 'workflows', 'release.yml')
const source = readFileSync(workflowPath, 'utf8')
const workflow = loadYaml(source)
const buildSteps = workflow.jobs.build.steps
const verifySteps = workflow.jobs.verify.steps

const named = (text) => buildSteps.find((step) => String(step.name || '').includes(text))
const indexOf = (text) => buildSteps.findIndex((step) => String(step.name || '').includes(text))
const verifyNamed = (text) => verifySteps.find((step) => String(step.name || '').includes(text))

describe('production schema2 release workflow contract', () => {
  it('keeps production root and leaf authority isolated from early-access and legacy schema1 inputs', () => {
    const root = named('Prepare production update root authorization and keyring floor')
    const leaves = named('Materialize production threshold leaf signing keys')
    const build = named('Build desktop')
    const signingIdentity = named('Materialize isolated production signing identity')

    expect(source).not.toContain('NACHUAN_UPDATE_ROOT_PRIVATE_KEY')
    expect(source).not.toContain('NACHUAN_UPDATE_PRIVATE_KEY_PEM_BASE64')
    expect(source).not.toContain('NACHUAN_UPDATE_PRIVATE_KEY_FILE')
    expect(root?.env).toMatchObject({
      NACHUAN_PRODUCTION_UPDATE_ROOT_AUTHORIZATION_BASE64:
        '${{ vars.NACHUAN_PRODUCTION_UPDATE_ROOT_AUTHORIZATION_BASE64 }}',
      NACHUAN_PRODUCTION_UPDATE_KEY_ID: '${{ vars.NACHUAN_PRODUCTION_UPDATE_KEY_ID }}',
      NACHUAN_PRODUCTION_UPDATE_PUBLIC_KEY_SPKI_BASE64:
        '${{ vars.NACHUAN_PRODUCTION_UPDATE_PUBLIC_KEY_SPKI_BASE64 }}'
    })
    expect(leaves?.env).toMatchObject({
      NACHUAN_PRODUCTION_UPDATE_LEAF_SIGNING_KEYS_BUNDLE_BASE64:
        '${{ secrets.NACHUAN_PRODUCTION_UPDATE_LEAF_SIGNING_KEYS_BUNDLE_BASE64 }}',
      NACHUAN_PRODUCTION_UPDATE_ROOT_AUTHORIZATION_FILE:
        '${{ steps.production_update_root.outputs.root_authorization_file }}'
    })
    expect(build?.env).toMatchObject({
      NACHUAN_UPDATE_TIER: 'production',
      NACHUAN_UPDATE_CHANNEL: 'production-lean-win-x64',
      NACHUAN_UPDATE_KEY_ID: '${{ vars.NACHUAN_PRODUCTION_UPDATE_KEY_ID }}',
      NACHUAN_UPDATE_PUBLIC_KEY_SPKI_BASE64:
        '${{ vars.NACHUAN_PRODUCTION_UPDATE_PUBLIC_KEY_SPKI_BASE64 }}',
      NACHUAN_UPDATE_MANIFEST_URL: '${{ vars.NACHUAN_PRODUCTION_UPDATE_MANIFEST_URL }}',
      NACHUAN_UPDATE_SEQUENCE: '${{ vars.NACHUAN_PRODUCTION_UPDATE_SEQUENCE }}',
      NACHUAN_UPDATE_KEYRING_SEQUENCE:
        '${{ steps.production_update_root.outputs.keyring_sequence }}',
      NACHUAN_UPDATE_KEYRING_SHA256:
        '${{ steps.production_update_root.outputs.keyring_sha256 }}'
    })
    expect(signingIdentity?.run).toContain('[IO.FileMode]::CreateNew')
    expect(signingIdentity?.run).toContain('[Array]::Clear($bytes, 0, $bytes.Length)')
    expect(signingIdentity?.run).not.toContain('[IO.File]::WriteAllBytes')
  })

  it('materializes leaves only after Authenticode, installer closure, and frozen evidence inputs', () => {
    const rootIndex = indexOf('Prepare production update root authorization and keyring floor')
    const buildIndex = indexOf('Build desktop')
    const authenticodeIndex = indexOf('Verify installer, desktop and packaged engine signatures')
    const closureIndex = indexOf('Prove the NSIS installer embeds the exact verified unpacked payload')
    const evidenceIndex = indexOf('Collect and freeze production release evidence before online signing')
    const leafIndex = indexOf('Materialize production threshold leaf signing keys')
    const envelopeIndex = indexOf('Generate schema2 production envelope and checksum closure')
    const cleanupIndex = indexOf('Remove production update signing inputs')
    const finalizeEvidenceIndex = indexOf('Finalize and re-verify production release evidence')
    const independentVerifyIndex = indexOf('Independently verify schema2 production closure')
    const certificateCleanup = named('Remove the materialized signing identity')
    const preparedEvidenceCleanup = named('Remove prepared production evidence and source freeze inputs')

    expect(rootIndex).toBeGreaterThan(-1)
    expect(buildIndex).toBeGreaterThan(rootIndex)
    expect(authenticodeIndex).toBeGreaterThan(buildIndex)
    expect(closureIndex).toBeGreaterThan(authenticodeIndex)
    expect(evidenceIndex).toBeGreaterThan(closureIndex)
    expect(leafIndex).toBeGreaterThan(evidenceIndex)
    for (const prerequisiteIndex of [authenticodeIndex, closureIndex, evidenceIndex]) {
      expect(buildSteps[prerequisiteIndex]?.['continue-on-error']).not.toBe(true)
    }
    expect(buildSteps[leafIndex]?.if).not.toBe('always()')
    expect(envelopeIndex).toBeGreaterThan(leafIndex)
    expect(cleanupIndex).toBeGreaterThan(envelopeIndex)
    expect(finalizeEvidenceIndex).toBeGreaterThan(cleanupIndex)
    expect(independentVerifyIndex).toBeGreaterThan(finalizeEvidenceIndex)
    expect(certificateCleanup?.if).toBe('always()')
    expect(certificateCleanup?.run).toContain('$env:RUNNER_TEMP')
    expect(certificateCleanup?.run).toContain('nachuan-production-signing.pfx')
    expect(certificateCleanup?.run).not.toContain('$env:CERTIFICATE_FILE')
    expect(buildSteps[cleanupIndex]?.if).toBe('always()')
    expect(buildSteps[cleanupIndex]?.run).toContain('$env:RUNNER_TEMP')
    expect(buildSteps[cleanupIndex]?.run).toContain('nachuan-production-')
    expect(buildSteps[cleanupIndex]?.run).not.toContain('ConvertFrom-Json')
    expect(buildSteps[cleanupIndex]?.run).not.toContain('privateKeyPath')
    expect(preparedEvidenceCleanup?.if).toBe('always()')
    expect(preparedEvidenceCleanup?.run).toContain('$env:RUNNER_TEMP')
    expect(preparedEvidenceCleanup?.run).toContain('nachuan-production-release-evidence.json')
    expect(preparedEvidenceCleanup?.run).toContain('nachuan-release-source-freeze.json')
    expect(preparedEvidenceCleanup?.run).not.toContain('$env:PREPARED_EVIDENCE_FILE')
    expect(preparedEvidenceCleanup?.run).not.toContain('$env:NACHUAN_RELEASE_SOURCE_FREEZE_PATH')
  })

  it('binds production URL, channel, keyring floor, and release sequence through final shared verification', () => {
    const toolchain = named('Pin and verify build toolchain')
    const gitRuntime = named('Prepare checksum-pinned project-local Git runtime')
    const prepareEvidence = named('Collect and freeze production release evidence before online signing')
    const envelope = named('Generate schema2 production envelope and checksum closure')
    const finalizeEvidence = named('Finalize and re-verify production release evidence')
    const independent = named('Independently verify schema2 production closure')
    const upload = buildSteps.find((step) => String(step.uses || '').startsWith('actions/upload-artifact@'))

    expect(indexOf('Pin and verify build toolchain')).toBeLessThan(
      indexOf('Collect and freeze production release evidence before online signing')
    )
    for (const variable of [
      'NACHUAN_RELEASE_NODE_PATH',
      'NACHUAN_RELEASE_NPM_CLI_PATH',
      'NACHUAN_RELEASE_UV_PATH',
      'NACHUAN_RELEASE_PYTHON_PATH'
    ]) {
      expect(toolchain?.run).toContain(`"${variable}=$`)
      expect(toolchain?.run).toContain('$env:GITHUB_ENV')
    }
    expect(toolchain?.run).toContain('[IO.Path]::IsPathFullyQualified')
    expect(toolchain?.run).toContain('Test-Path -LiteralPath $toolPath -PathType Leaf')
    expect(toolchain?.run).not.toContain('Get-Command git')
    expect(toolchain?.run).not.toContain('NACHUAN_RELEASE_GIT_PATH')
    expect(gitRuntime?.run).toContain('git-runtime-policy.mjs prepare')
    expect(gitRuntime?.run).toContain('git-runtime-policy.mjs verify')
    expect(gitRuntime?.run).toContain('build\\git-runtime\\mingw64\\bin\\git.exe')
    expect(gitRuntime?.run).toContain('NACHUAN_RELEASE_GIT_PATH=$gitPath')
    expect(prepareEvidence?.run).toContain('release-evidence.mjs prepare lean')
    expect(envelope?.env).toMatchObject({
      NACHUAN_PRODUCTION_UPDATE_CHANNEL: 'production-lean-win-x64',
      NACHUAN_PRODUCTION_UPDATE_SEQUENCE: '${{ vars.NACHUAN_PRODUCTION_UPDATE_SEQUENCE }}',
      NACHUAN_PRODUCTION_UPDATE_ROOT_AUTHORIZATION_FILE:
        '${{ steps.production_update_root.outputs.root_authorization_file }}',
      NACHUAN_PRODUCTION_UPDATE_LEAF_SIGNING_KEYS_FILE:
        '${{ steps.production_update_leaves.outputs.leaf_signing_keys_file }}'
    })
    expect(envelope?.run).toContain('production-update-envelope.mjs finalize lean')
    expect(finalizeEvidence?.run).toContain('release-evidence.mjs finalize-prepared lean')
    expect(finalizeEvidence?.shell).toBe('pwsh')
    expect(finalizeEvidence?.run).toMatch(
      /finalize-prepared lean[\s\S]*\$LASTEXITCODE[\s\S]*release-evidence\.mjs verify lean[\s\S]*\$LASTEXITCODE/
    )
    expect(independent?.shell).toBe('pwsh')
    expect(independent?.env).toMatchObject({
      NACHUAN_RELEASE_TAG: '${{ needs.verify.outputs.release_tag }}',
      NACHUAN_RELEASE_COMMIT: '${{ needs.verify.outputs.release_commit }}',
      NACHUAN_RELEASE_RUN_ID: '${{ github.run_id }}'
    })
    expect(independent?.run).toContain('release-source-freeze.mjs verify')
    expect(independent?.run).toContain('$env:NACHUAN_RELEASE_SOURCE_FREEZE_PATH')
    expect(independent?.run).not.toContain('git rev-parse')
    expect(independent?.run).toContain('release-evidence.mjs verify lean')
    expect(independent?.run).toContain('production-update-envelope.mjs verify lean')
    expect(independent.run.indexOf('release-evidence.mjs verify lean')).toBeLessThan(
      independent.run.indexOf('production-update-envelope.mjs verify lean')
    )
    expect(upload?.with?.path).toContain('${{ steps.candidate_archive.outputs.archive_path }}')
    expect(upload?.with?.path).toContain('${{ steps.candidate_archive.outputs.manifest_path }}')
  })

  it('still cannot publish any production artifact', () => {
    const publishStep = workflow.jobs.publish.steps.find((step) =>
      String(step.name || '').includes('Fail closed')
    )
    expect(publishStep?.run).toMatch(/BLOCKED[\s\S]*exit 1/i)
    expect(source).not.toMatch(/electron-builder[^\n]*--publish\s+(?:always|onTagOrDraft)/i)
  })

  it('freezes the final tree into one content-addressed archive and makes it the only upload payload', () => {
    const candidate = named('Create and verify content-addressed release candidate archive')
    const candidateIndex = indexOf('Create and verify content-addressed release candidate archive')
    const malwareIndex = indexOf('Validate candidate-bound Defender and ClamAV receipts')
    const upload = buildSteps.find((step) =>
      String(step.uses || '').startsWith('actions/upload-artifact@')
    )
    const uploadIndex = buildSteps.indexOf(upload)

    expect(candidateIndex).toBeGreaterThan(indexOf('Independently verify schema2 production closure'))
    expect(candidateIndex).toBeLessThan(malwareIndex)
    expect(malwareIndex).toBeLessThan(uploadIndex)
    expect(candidate?.id).toBe('candidate_archive')
    expect(candidate?.if).toBeUndefined()
    expect(candidate?.['continue-on-error']).not.toBe(true)
    expect(candidate?.['working-directory']).toBe('desktop')
    expect(candidate?.env).toMatchObject({
      NACHUAN_RELEASE_TAG: '${{ needs.verify.outputs.release_tag }}',
      NACHUAN_RELEASE_COMMIT: '${{ needs.verify.outputs.release_commit }}',
      NACHUAN_RELEASE_TREE: '${{ needs.verify.outputs.release_tree }}',
      NACHUAN_RELEASE_REPOSITORY: '${{ github.repository }}',
      NACHUAN_RELEASE_WORKFLOW_REF: '${{ github.workflow_ref }}',
      NACHUAN_RELEASE_WORKFLOW_SHA: '${{ github.workflow_sha }}',
      NACHUAN_RELEASE_RUN_ID: '${{ github.run_id }}',
      NACHUAN_RELEASE_RUN_ATTEMPT: '${{ github.run_attempt }}',
      NACHUAN_RELEASE_JOB: '${{ github.job }}',
      NACHUAN_RELEASE_VARIANT: 'lean',
      NACHUAN_RELEASE_VERSION: '${{ needs.verify.outputs.release_version }}'
    })
    expect(candidate?.run).toContain('release-candidate-archive.mjs create')
    expect(candidate?.run).toContain('release-candidate-archive.mjs verify')
    for (const output of [
      'archive_path',
      'archive_sha256',
      'archive_size',
      'manifest_path',
      'manifest_sha256'
    ]) {
      expect(candidate?.run).toContain(`${output}=`)
      expect(candidate?.run).toContain('$env:GITHUB_OUTPUT')
    }
    expect(String(upload?.with?.path || '').trim().split(/\r?\n/u)).toEqual([
      '${{ steps.candidate_archive.outputs.archive_path }}',
      '${{ steps.candidate_archive.outputs.manifest_path }}'
    ])
    expect(upload?.with?.name).toContain('${{ steps.candidate_archive.outputs.archive_sha256 }}')
    expect(upload?.with?.['compression-level']).toBe(0)
    expect(upload?.with?.path).not.toContain('desktop/release/')
  })

  it('unconditionally validates candidate-bound claims and fails closed without trusted attestations', () => {
    const malware = named('Validate candidate-bound Defender and ClamAV receipts')
    const malwareIndex = indexOf('Validate candidate-bound Defender and ClamAV receipts')
    const uploadIndex = buildSteps.findIndex((step) =>
      String(step.uses || '').startsWith('actions/upload-artifact@')
    )

    expect(malwareIndex).toBeGreaterThan(indexOf('Independently verify schema2 production closure'))
    expect(malwareIndex).toBeLessThan(uploadIndex)
    expect(malware?.if).toBeUndefined()
    expect(malware?.['continue-on-error']).not.toBe(true)
    expect(malware?.['working-directory']).toBe('desktop')
    expect(malware?.shell).toBe('pwsh')
    expect(malware?.env).toMatchObject({
      NACHUAN_RELEASE_TAG: '${{ needs.verify.outputs.release_tag }}',
      NACHUAN_RELEASE_COMMIT: '${{ needs.verify.outputs.release_commit }}',
      NACHUAN_RELEASE_TREE: '${{ needs.verify.outputs.release_tree }}',
      NACHUAN_RELEASE_REPOSITORY: '${{ github.repository }}',
      NACHUAN_RELEASE_WORKFLOW_REF: '${{ github.workflow_ref }}',
      NACHUAN_RELEASE_WORKFLOW_SHA: '${{ github.workflow_sha }}',
      NACHUAN_RELEASE_RUN_ID: '${{ github.run_id }}',
      NACHUAN_RELEASE_RUN_ATTEMPT: '${{ github.run_attempt }}',
      NACHUAN_RELEASE_BUILD_JOB: '${{ github.job }}',
      NACHUAN_RELEASE_VARIANT: 'lean',
      NACHUAN_RELEASE_VERSION: '${{ needs.verify.outputs.release_version }}',
      NACHUAN_CANDIDATE_ARCHIVE: '${{ steps.candidate_archive.outputs.archive_path }}',
      NACHUAN_CANDIDATE_MANIFEST: '${{ steps.candidate_archive.outputs.manifest_path }}',
      NACHUAN_DEFENDER_RECEIPT: '${{ runner.temp }}/nachuan-malware-defender.json',
      NACHUAN_CLAMAV_RECEIPT: '${{ runner.temp }}/nachuan-malware-clamav.json'
    })
    expect(malware?.run).toContain('release-malware-evidence.mjs verify')
    for (const argument of [
      '--archive',
      '--candidate-manifest',
      '--release-tag',
      '--release-commit',
      '--release-tree',
      '--repository',
      '--workflow-ref',
      '--workflow-sha',
      '--run-id',
      '--run-attempt',
      '--build-job',
      '--variant',
      '--version',
      '--defender-receipt',
      '--clamav-receipt'
    ]) {
      expect(malware?.run).toContain(argument)
    }
    expect(malware?.run).toContain('$env:NACHUAN_RELEASE_NODE_PATH')
    expect(malware?.run).not.toContain('--release-root')
    expect(malware?.run).not.toMatch(/\bcreate\b|createMalwareScanReceipt/u)
    expect(workflow.jobs.publish.needs).toBe('build')
  })

  it('uses one shared non-mutating Python selector for synchronization and engine build', () => {
    const syncSteps = buildSteps.filter((step) =>
      String(step.run || '').includes('python-release-policy.mjs sync')
    )
    const engineBuild = named('Build engine')

    expect(syncSteps.length).toBeGreaterThan(0)
    expect(engineBuild?.run).toBe('node desktop/scripts/python-release-policy.mjs build-engine')
    expect(verifyNamed('Verify exact Python runtime')?.run).toBe(
      'node desktop/scripts/python-release-policy.mjs attest'
    )
    expect(verifyNamed('Backend tests')?.run).toBe('node desktop/scripts/python-release-policy.mjs test')
    expect(source).not.toMatch(/uv\s+sync\b/)
    expect(source).not.toMatch(/uv\s+run\b/)
    expect(source).not.toMatch(/python(?:\.exe)?[^\r\n]*\s-m\s+pytest/i)
    expect(source).not.toMatch(/uv\s+run[^\r\n]*pytest/i)
    expect(source).not.toMatch(/(?:^|\s)pytest(?:\.exe)?(?:\s|$)/im)
    expect(source).not.toMatch(/(?:uv|python)\s+[^\n]*pyinstaller/i)
    for (const step of buildSteps.filter((step) => String(step.run || '').includes('npm ci'))) {
      expect(step.run).toContain('npm ci --ignore-scripts')
    }
  })

  it('closes ambient startup injection and prepares a hash-pinned Electron runtime plus licenses before packaging', () => {
    const dependencySync = indexOf('Sync locked desktop dependencies')
    const gitRuntime = named('Prepare checksum-pinned project-local Git runtime')
    const runtime = named('Prepare checksum-pinned Electron runtime')
    const licenses = named('Stage complete payload license evidence')
    const packageStep = named('Package the digest-bound engine')

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
    expect(workflow.env.npm_config_script_shell).toBe('C:\\Windows\\System32\\cmd.exe')
    expect(workflow.env.NPM_CONFIG_STRICT_SSL).toBe('true')
    expect(runtime?.run).toBe('node scripts/electron-runtime-policy.mjs prepare')
    expect(licenses?.run).toBe('node scripts/license-stage.mjs prepare')
    expect(runtime?.['continue-on-error']).not.toBe(true)
    expect(licenses?.['continue-on-error']).not.toBe(true)
    expect(gitRuntime?.['continue-on-error']).not.toBe(true)
    expect(indexOf('Prepare checksum-pinned project-local Git runtime')).toBeGreaterThan(dependencySync)
    expect(indexOf('Prepare checksum-pinned Electron runtime')).toBeGreaterThan(dependencySync)
    expect(indexOf('Stage complete payload license evidence')).toBeGreaterThan(
      indexOf('Prepare checksum-pinned Electron runtime')
    )
    expect(indexOf('Package the digest-bound engine')).toBeGreaterThan(
      indexOf('Stage complete payload license evidence')
    )
    expect(packageStep?.run).toContain('--config electron-builder.production.yml')
  })

  it('materializes and freezes generated release modules before post-freeze check-only builds', () => {
    const cleanIndex = indexOf('Clean release output before the source freeze')
    const stabilizeIndex = indexOf('Stabilize all excluded build roots before the source freeze')
    const freezeIndex = indexOf('Freeze complete release source and Git execution closure before build')
    const engineIndex = indexOf('Build engine')
    const generatedIndex = indexOf('Materialize generated release modules before source freeze')
    const desktopIndex = indexOf('Build desktop')
    const packageIndex = indexOf('Package the digest-bound engine')
    const freeze = buildSteps[freezeIndex]
    const stabilize = buildSteps[stabilizeIndex]
    const generated = buildSteps[generatedIndex]
    const desktop = buildSteps[desktopIndex]

    expect(workflow.jobs.verify.outputs.release_tree).toBe(
      '${{ steps.release_identity.outputs.release_tree }}'
    )
    expect(workflow.jobs.build.env).toMatchObject({
      NACHUAN_RELEASE_TAG: '${{ needs.verify.outputs.release_tag }}',
      NACHUAN_RELEASE_COMMIT: '${{ needs.verify.outputs.release_commit }}',
      NACHUAN_RELEASE_TREE: '${{ needs.verify.outputs.release_tree }}',
      NACHUAN_RELEASE_RUN_ID: '${{ github.run_id }}'
    })
    expect(cleanIndex).toBeGreaterThan(indexOf('Stage complete payload license evidence'))
    expect(stabilizeIndex).toBeGreaterThan(cleanIndex)
    expect(freezeIndex).toBeGreaterThan(stabilizeIndex)
    expect(engineIndex).toBeLessThan(generatedIndex)
    expect(generatedIndex).toBeLessThan(cleanIndex)
    expect(desktopIndex).toBeGreaterThan(freezeIndex)
    expect(packageIndex).toBeGreaterThan(desktopIndex)
    expect(generated?.run).toContain('write-engine-digest.mjs')
    expect(generated?.run).toContain('write-update-trust.mjs')
    expect(generated?.run).not.toMatch(/write-(?:engine-digest|update-trust)\.mjs\s+check/u)
    expect(desktop?.run).toContain('write-engine-digest.mjs check')
    expect(desktop?.run).toContain('write-update-trust.mjs check')
    expect(desktop?.run).toContain('electron-vite build')
    expect(desktop?.run).not.toContain('npm run build')
    expect(freeze?.run).toContain('release-source-freeze.mjs write')
    expect(freeze?.run).toContain('nachuan-release-source-freeze.json')
    expect(freeze?.id).toBe('release_source_freeze')
    expect(freeze?.run).toContain('source_freeze_path=$freeze')
    expect(freeze?.run).toContain('source_freeze_sha256=$digest')
    expect(freeze?.run).toContain('$env:GITHUB_OUTPUT')
    expect(freeze?.run).not.toContain('$env:GITHUB_ENV')
    for (const excludedRoot of [
      'bridge/__pycache__',
      'config/__pycache__',
      'desktop/.vite',
      'desktop/build/electron-runtime',
      'desktop/build/license-evidence',
      'desktop/coverage',
      'desktop/node_modules',
      'desktop/out',
      'desktop/release',
      'desktop/third-party-notices',
      'gateway/__pycache__',
      'gateway/providers/__pycache__',
      'orchestrator/__pycache__',
      'orchestrator/workflows/__pycache__',
      'scripts/__pycache__',
      'tests/__pycache__'
    ]) {
      expect(stabilize?.run).toContain(`'${excludedRoot}'`)
    }
    expect(buildSteps.filter((step) => String(step.run || '').includes('release-output.mjs clean'))).toHaveLength(1)
  })

  it('keeps the pre-build freeze binding in immutable step outputs for every evidence consumer', () => {
    const freezePath = '${{ steps.release_source_freeze.outputs.source_freeze_path }}'
    const freezeSha256 = '${{ steps.release_source_freeze.outputs.source_freeze_sha256 }}'
    const consumers = [
      named('Collect and freeze production release evidence'),
      named('Finalize and re-verify production release evidence'),
      named('Independently verify schema2 production closure')
    ]

    expect(source).not.toMatch(/NACHUAN_RELEASE_SOURCE_FREEZE_(?:PATH|SHA256)=.*GITHUB_ENV/u)
    for (const consumer of consumers) {
      expect(consumer?.env).toMatchObject({
        NACHUAN_RELEASE_SOURCE_FREEZE_PATH: freezePath,
        NACHUAN_RELEASE_SOURCE_FREEZE_SHA256: freezeSha256
      })
    }
  })

  it('ships deterministic non-production generated templates in a clean tag checkout', () => {
    const engineTemplate = readFileSync(
      join(desktopRoot, 'src', 'main', 'generated-engine-integrity.ts'),
      'utf8'
    )
    const trustTemplate = readFileSync(
      join(desktopRoot, 'src', 'main', 'generated-update-trust.ts'),
      'utf8'
    )

    expect(engineTemplate).toContain('Source-control template')
    expect(engineTemplate.match(/'0{64}'/gu)).toHaveLength(6)
    expect(trustTemplate).toContain('Source-control template')
    expect(trustTemplate).toContain('"enabled": false')
    expect(trustTemplate).toContain('"releaseTier": "disabled"')
  })
})
