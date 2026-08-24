import { createHash, generateKeyPairSync, sign } from 'node:crypto'
import { mkdtempSync, readFileSync, readdirSync, rmSync, truncateSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

import { load as loadYaml } from 'js-yaml'
import { describe, expect, it } from 'vitest'

import { loadEarlyAccessSigningInputs } from './finalize-early-access.mjs'
import { signUpdateManifest } from './sign-update-manifest.mjs'
import { canonicalUpdateKeyring, verifySignedUpdateEnvelopeForRelease } from './update-envelope.mjs'

const desktopRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const workflowRoot = join(desktopRoot, '..', '.github', 'workflows')

function signingFixtureTempRoot() {
  const root = process.env.NACHUAN_EXTERNAL_TEST_TEMP_ROOT
  return root ? resolve(root) : tmpdir()
}

function workflows() {
  return readdirSync(workflowRoot)
    .filter((name) => name.endsWith('.yml') || name.endsWith('.yaml'))
    .map((name) => ({
      name,
      document: loadYaml(readFileSync(join(workflowRoot, name), 'utf8'))
    }))
}

function workflowSteps(workflow) {
  return Object.values(workflow.document.jobs || {}).flatMap((job) => job.steps || [])
}

describe('early-access workflow artifact contract', () => {
  it('binds the publisher to the unique successful finalize workflow and exact live artifact digest', () => {
    const workflow = workflows().find(({ name }) => name === 'publish-early-access.yml')
    const steps = workflowSteps(workflow)
    const identity = steps.find((step) =>
      String(step.name || '').includes('Verify immutable tag and source run identity')
    )
    const download = steps.find((step) =>
      String(step.name || '').includes('Download exact finalized artifact')
    )

    expect(identity?.run).toContain('actions/workflows/finalize-early-access.yml')
    expect(identity?.run).toContain('$run.workflow_id')
    expect(identity?.run).toContain("$run.path -cne '.github/workflows/finalize-early-access.yml'")
    expect(identity?.run).toContain("$run.event -cne 'workflow_dispatch'")
    expect(identity?.run).toContain("actions/runs/$env:RELEASE_RUN_ID/artifacts?per_page=100")
    expect(identity?.run).toContain('$matches.Count -ne 1')
    expect(identity?.run).toContain('$artifact.expired')
    expect(identity?.run).toMatch(/digest.*sha256:/i)
    expect(identity?.run).toContain('MAX_FINALIZER_AGE_HOURS')
    expect(identity?.run).toContain('$run.updated_at')
    expect(identity?.run).toMatch(/finalizer.*too old|fresh finalizer/i)
    expect(download?.run).toContain('actions/artifacts/$env:RELEASE_ARTIFACT_ID/zip')
    expect(download?.run).toContain('Get-FileHash')
    expect(download?.run).toContain('$env:RELEASE_ARTIFACT_SHA256')
  })

  it('re-audits the locked dependency graph in the publisher before any remote publish', () => {
    const workflow = workflows().find(({ name }) => name === 'publish-early-access.yml')
    const steps = workflowSteps(workflow)
    const auditIndex = steps.findIndex((step) =>
      /re-run current dependency security audits/i.test(String(step.name || ''))
    )
    const publishIndex = steps.findIndex((step) =>
      String(step.name || '').includes('Publish immutable assets')
    )

    expect(auditIndex).toBeGreaterThan(-1)
    expect(publishIndex).toBeGreaterThan(auditIndex)
    expect(steps[auditIndex]?.run).toContain('release-evidence.mjs re-audit-portable')
    expect(steps[auditIndex]?.run).toContain('release-security.mjs scan release')
  })

  it('keeps early access fail-closed until a versioned license allowlist and external legal approval exist', () => {
    for (const workflowName of ['finalize-early-access.yml', 'publish-early-access.yml']) {
      const workflow = workflows().find(({ name }) => name === workflowName)
      const steps = workflowSteps(workflow)
      const legalGateIndex = steps.findIndex((step) =>
        String(step.name || '').includes('Fail closed until release legal policy is approved')
      )
      const remotePublishIndex = steps.findIndex((step) =>
        String(step.name || '').includes('Publish immutable assets')
      )
      const legalGate = steps[legalGateIndex]

      expect(legalGateIndex).toBeGreaterThan(-1)
      if (remotePublishIndex >= 0) expect(remotePublishIndex).toBeGreaterThan(legalGateIndex)
      expect(legalGate?.run).toMatch(/license allowlist/i)
      expect(legalGate?.run).toMatch(/external legal approval/i)
      expect(legalGate?.run).toMatch(/throw|exit 1/i)
    }
    const publicPublisher = readFileSync(
      join(desktopRoot, 'scripts', 'publish-early-access.mjs'),
      'utf8'
    )
    expect(publicPublisher).toMatch(/versioned legal policy.*external approval/i)
    expect(publicPublisher).toMatch(/candidate-bound fresh audit receipt verifier/i)
    expect(publicPublisher).not.toContain('early-access-storage-transaction.mjs')
    expect(publicPublisher).not.toMatch(/process\.env\..*(?:LEGAL|AUDIT).*APPROV/i)
  })

  it('uses bounded fail-closed signing material cleanup under RUNNER_TEMP', () => {
    const workflow = workflows().find(({ name }) => name === 'finalize-early-access.yml')
    const cleanup = workflowSteps(workflow).find((step) =>
      String(step.name || '').includes('Remove materialized update signing inputs')
    )

    expect(cleanup?.if).toBe('always()')
    expect(cleanup?.run).toContain('cleanup-signing-material.mjs')
    expect(cleanup?.run).not.toContain('SilentlyContinue')
  })

  it('installs without lifecycle scripts, tests, and pins project-local Git before any artifact build/download', () => {
    for (const workflowName of ['finalize-early-access.yml', 'publish-early-access.yml']) {
      const workflow = workflows().find(({ name }) => name === workflowName)
      const steps = workflowSteps(workflow)
      const artifactIndex = steps.findIndex((step) =>
        workflowName.startsWith('finalize')
          ? String(step.name || '').includes('Build the real early-access package')
          : String(step.name || '').includes('Download exact finalized artifact')
      )
      const gateIndex = steps.findIndex((step) =>
        String(step.name || '').includes(
          workflowName.startsWith('finalize')
            ? 'Install and test the locked source checkout'
            : 'Install and test the locked publisher checkout'
        )
      )
      const gate = steps[gateIndex]
      const gitIndex = steps.findIndex((step) =>
        String(step.name || '').includes('Prepare checksum-pinned project-local Git runtime')
      )
      const gitRuntime = steps[gitIndex]

      expect(gateIndex).toBeGreaterThan(-1)
      expect(artifactIndex).toBeGreaterThan(gateIndex)
      expect(gitIndex).toBeGreaterThan(gateIndex)
      expect(artifactIndex).toBeGreaterThan(gitIndex)
      expect(gate?.run).toContain('npm ci --ignore-scripts')
      expect(gate?.run).toContain('npm test')
      expect(gate?.run).toContain('npm run typecheck')
      expect(gate?.run).not.toContain('git diff')
      expect(gate?.run).not.toContain('git status')
      expect(gitRuntime?.run).toContain('git-runtime-policy.mjs prepare')
      expect(gitRuntime?.run).toContain('git-runtime-policy.mjs verify')
      expect(gitRuntime?.run).toContain('NACHUAN_RELEASE_GIT_PATH=$gitPath')
      for (const step of steps.slice(artifactIndex + 1)) {
        expect(String(step.run || '')).not.toMatch(/npm\s+(?:ci|install)|uv\s+sync/i)
      }
    }
  })

  it('uploads the finalized closure under the exact name consumed by the publisher', () => {
    const documents = workflows()
    const publisher = documents.find(({ name }) => name === 'publish-early-access.yml')
    expect(publisher).toBeDefined()

    const download = workflowSteps(publisher).find((step) =>
      String(step.name || '').includes('Download exact finalized artifact')
    )
    expect(download?.run).toContain(
      '$artifact = "nachuan-early-access-$env:RELEASE_VERSION-$env:VARIANT-final"'
    )

    const uploads = documents.flatMap((workflow) =>
      workflowSteps(workflow)
        .filter((step) => String(step.uses || '').startsWith('actions/upload-artifact@'))
        .map((step) => ({ workflow: workflow.name, step }))
    )
    const producer = uploads.find(
      ({ step }) =>
        step.with?.name ===
        'nachuan-early-access-${{ steps.release_identity.outputs.release_version }}-${{ inputs.variant }}-final'
    )

    expect(producer).toBeDefined()
    expect(producer.workflow).toBe('finalize-early-access.yml')
    expect(producer.step.with['if-no-files-found']).toBe('error')
    expect(producer.step.with.path).toContain('desktop/release/win-unpacked/**')
    expect(producer.step.with.path).toContain('desktop/release/early-access-${{ inputs.variant }}.yml')
    expect(producer.step.with.path).toContain(
      'desktop/release/early-access-${{ inputs.variant }}-win-x64.json'
    )
    expect(producer.step.with.path).toContain('desktop/release/WIN_UNPACKED_MANIFEST.json')
    expect(producer.step.with.path).toContain('desktop/release/SHA256SUMS')
  })

  it('binds generated release evidence to the immutable tag, commit and source run on both sides', () => {
    const documents = workflows()
    const finalizer = documents.find(({ name }) => name === 'finalize-early-access.yml')
    const publisher = documents.find(({ name }) => name === 'publish-early-access.yml')
    const finalizeSteps = workflowSteps(finalizer)
    const publishSteps = workflowSteps(publisher)
    const finalize = finalizeSteps.find((step) =>
      String(step.name || '').includes('Finalize installer closure and signed update envelope')
    )
    const reverify = finalizeSteps.find((step) =>
      String(step.name || '').includes('Re-verify finalized early-access closure')
    )
    const producer = finalizeSteps.find((step) =>
      String(step.uses || '').startsWith('actions/upload-artifact@')
    )
    const consumerVerify = publishSteps.find((step) =>
      String(step.name || '').includes('Verify downloaded final closure')
    )
    const materializeSource = publishSteps.find((step) =>
      String(step.name || '').includes('Materialize the producer source freeze')
    )
    const publish = publishSteps.find((step) =>
      String(step.name || '').includes('Publish immutable assets')
    )

    expect(finalize?.env).toMatchObject({
      NACHUAN_RELEASE_TAG: '${{ inputs.release_tag }}',
      NACHUAN_RELEASE_COMMIT: '${{ github.sha }}',
      NACHUAN_RELEASE_RUN_ID: '${{ github.run_id }}'
    })
    expect(readFileSync(join(desktopRoot, 'scripts', 'finalize-early-access.mjs'), 'utf8')).toContain(
      'generateReleaseEvidence'
    )
    expect(reverify?.run).toContain('release-evidence.mjs verify')
    for (const name of [
      'NATIVE_SBOM.cdx.json',
      'NPM_AUDIT.json',
      'NPM_SBOM.cdx.json',
      'PYTHON_AUDIT.json',
      'PYTHON_SBOM.cdx.json',
      'RELEASE_EVIDENCE_MANIFEST.json'
    ]) {
      expect(producer?.with?.path).toContain(`desktop/release/${name}`)
    }
    expect(materializeSource?.env).toMatchObject({
      NACHUAN_RELEASE_TAG: '${{ inputs.release_tag }}',
      NACHUAN_RELEASE_RUN_ID: '${{ inputs.release_run_id }}'
    })
    expect(materializeSource?.run).toContain('release-evidence.mjs materialize-source-freeze')
    expect(materializeSource?.run).toContain('source_freeze_sha256=$digest')
    expect(consumerVerify?.env).toMatchObject({
      NACHUAN_RELEASE_TAG: '${{ inputs.release_tag }}',
      NACHUAN_RELEASE_RUN_ID: '${{ inputs.release_run_id }}'
    })
    expect(consumerVerify?.run).toContain('release-evidence.mjs verify-portable')
    expect(publish?.env).toMatchObject({
      NACHUAN_RELEASE_TAG: '${{ inputs.release_tag }}',
      NACHUAN_RELEASE_RUN_ID: '${{ inputs.release_run_id }}'
    })
    expect(publish?.run).toContain('publish-early-access.mjs')
  })

  it('keeps the offline root out of CI and passes a root authorization plus threshold leaf keys to the finalizer', () => {
    const workflowPath = join(workflowRoot, 'finalize-early-access.yml')
    const source = readFileSync(workflowPath, 'utf8')
    const workflow = workflows().find(({ name }) => name === 'finalize-early-access.yml')
    const steps = workflowSteps(workflow)
    const rootAuthorization = steps.find((step) =>
      String(step.name || '').includes('Prepare signed root authorization and keyring floor')
    )
    const materialize = steps.find((step) =>
      String(step.name || '').includes('Materialize threshold leaf signing keys')
    )
    const finalize = steps.find((step) =>
      String(step.name || '').includes('Finalize installer closure and signed update envelope')
    )
    const build = steps.find((step) =>
      String(step.name || '').includes('Build the real early-access package')
    )

    expect(source).not.toContain('NACHUAN_UPDATE_ROOT_PRIVATE_KEY')
    expect(source).not.toContain('NACHUAN_UPDATE_PRIVATE_KEY_PEM_BASE64')
    expect(source).not.toContain('NACHUAN_UPDATE_PRIVATE_KEY_FILE')
    expect(materialize?.id).toBe('update_signing_inputs')
    expect(rootAuthorization?.id).toBe('update_root_authorization')
    expect(rootAuthorization?.env).toMatchObject({
      ROOT_AUTHORIZATION_BASE64: '${{ vars.NACHUAN_UPDATE_ROOT_AUTHORIZATION_BASE64 }}',
      EXPECTED_ROOT_KEY_ID: '${{ vars.NACHUAN_UPDATE_KEY_ID }}',
      ROOT_PUBLIC_KEY_SPKI_BASE64: '${{ vars.NACHUAN_UPDATE_PUBLIC_KEY_SPKI_BASE64 }}'
    })
    expect(materialize?.env).toMatchObject({
      ROOT_AUTHORIZATION_FILE:
        '${{ steps.update_root_authorization.outputs.root_authorization_file }}',
      LEAF_SIGNING_KEYS_BUNDLE_BASE64:
        '${{ secrets.NACHUAN_UPDATE_LEAF_SIGNING_KEYS_BUNDLE_BASE64 }}',
      EXPECTED_ROOT_KEY_ID: '${{ vars.NACHUAN_UPDATE_KEY_ID }}'
    })
    expect(finalize?.env).toMatchObject({
      NACHUAN_UPDATE_ROOT_AUTHORIZATION_FILE:
        '${{ steps.update_root_authorization.outputs.root_authorization_file }}',
      NACHUAN_UPDATE_LEAF_SIGNING_KEYS_FILE:
        '${{ steps.update_signing_inputs.outputs.leaf_signing_keys_file }}',
      NACHUAN_UPDATE_LEAF_PRIVATE_KEY_PASSPHRASE:
        '${{ secrets.NACHUAN_UPDATE_LEAF_PRIVATE_KEY_PASSPHRASE }}'
    })
    expect(build?.env).toMatchObject({
      NACHUAN_UPDATE_KEYRING_SEQUENCE:
        '${{ steps.update_root_authorization.outputs.keyring_sequence }}',
      NACHUAN_UPDATE_KEYRING_SHA256:
        '${{ steps.update_root_authorization.outputs.keyring_sha256 }}'
    })
    expect(rootAuthorization?.run).toContain('materialize-early-access-signing-inputs.mjs root')
    expect(materialize?.run).toContain('materialize-early-access-signing-inputs.mjs leaves')
    const materializerSource = readFileSync(
      join(desktopRoot, 'scripts', 'materialize-early-access-signing-inputs.mjs'),
      'utf8'
    )
    expect(materializerSource).toContain('checkedSigningMaterialRoot(runnerTemp)')
    expect(materializerSource).toContain('keyring_sha256')

    const finalizerSource = readFileSync(
      join(desktopRoot, 'scripts', 'finalize-early-access.mjs'),
      'utf8'
    )
    for (const name of [
      'NACHUAN_UPDATE_ROOT_AUTHORIZATION_FILE',
      'NACHUAN_UPDATE_LEAF_SIGNING_KEYS_FILE',
      'NACHUAN_UPDATE_LEAF_PRIVATE_KEY_PASSPHRASE'
    ]) {
      expect(finalizerSource).toContain(`env.${name}`)
    }
  })

  it('materializes leaf private keys only after the untrusted build scripts have finished', () => {
    const workflow = workflows().find(({ name }) => name === 'finalize-early-access.yml')
    const steps = workflowSteps(workflow)
    const rootIndex = steps.findIndex((step) =>
      String(step.name || '').includes('Prepare signed root authorization and keyring floor')
    )
    const buildIndex = steps.findIndex((step) =>
      String(step.name || '').includes('Build the real early-access package')
    )
    const leafIndex = steps.findIndex((step) =>
      String(step.name || '').includes('Materialize threshold leaf signing keys')
    )
    const finalizeIndex = steps.findIndex((step) =>
      String(step.name || '').includes('Finalize installer closure and signed update envelope')
    )

    expect(rootIndex).toBeGreaterThan(-1)
    expect(buildIndex).toBeGreaterThan(rootIndex)
    expect(leafIndex).toBeGreaterThan(buildIndex)
    expect(finalizeIndex).toBeGreaterThan(leafIndex)
    expect(steps[rootIndex]?.env).not.toHaveProperty('LEAF_SIGNING_KEYS_BUNDLE_BASE64')
    expect(steps[buildIndex]?.env).not.toHaveProperty('LEAF_SIGNING_KEYS_BUNDLE_BASE64')
  })

  it('freezes all early-access source before building and uses portable source proof in the isolated publisher', () => {
    const documents = workflows()
    const finalizer = documents.find(({ name }) => name === 'finalize-early-access.yml')
    const publisher = documents.find(({ name }) => name === 'publish-early-access.yml')
    const finalizeSteps = workflowSteps(finalizer)
    const publishSteps = workflowSteps(publisher)
    const packageScripts = JSON.parse(readFileSync(join(desktopRoot, 'package.json'), 'utf8')).scripts
    const prepareIndex = finalizeSteps.findIndex((step) =>
      String(step.name || '').includes('Prepare all excluded early-access build inputs')
    )
    const stabilizeIndex = finalizeSteps.findIndex((step) =>
      String(step.name || '').includes('Stabilize all excluded early-access roots')
    )
    const freezeIndex = finalizeSteps.findIndex((step) =>
      String(step.name || '').includes('Freeze complete early-access source')
    )
    const buildIndex = finalizeSteps.findIndex((step) =>
      String(step.name || '').includes('Build the real early-access package')
    )
    const reverify = finalizeSteps.find((step) =>
      String(step.name || '').includes('Re-verify finalized early-access closure')
    )
    const cleanup = finalizeSteps.find((step) =>
      String(step.name || '').includes('Remove early-access source freeze input')
    )
    const materializeIndex = publishSteps.findIndex((step) =>
      String(step.name || '').includes('Materialize the producer source freeze')
    )
    const verifyIndex = publishSteps.findIndex((step) =>
      String(step.name || '').includes('Verify downloaded final closure')
    )
    const restoreIndex = publishSteps.findIndex((step) =>
      String(step.name || '').includes('Restore exact producer generated release modules')
    )
    const publishIndex = publishSteps.findIndex((step) =>
      String(step.name || '').includes('Publish immutable assets')
    )
    const publisherCleanup = publishSteps.find((step) =>
      String(step.name || '').includes('Remove publisher source freeze input')
    )

    expect(prepareIndex).toBeGreaterThan(-1)
    expect(stabilizeIndex).toBeGreaterThan(prepareIndex)
    expect(freezeIndex).toBeGreaterThan(stabilizeIndex)
    expect(buildIndex).toBeGreaterThan(freezeIndex)
    expect(finalizeSteps[prepareIndex]?.run).toContain('python-release-policy.mjs build-engine')
    expect(finalizeSteps[prepareIndex]?.run).toContain('write-engine-digest.mjs')
    expect(finalizeSteps[prepareIndex]?.run).toContain('write-update-trust.mjs')
    expect(finalizeSteps[buildIndex]?.run).toBe('npm run _build_pack_early_frozen')
    expect(packageScripts._build_pack_early_frozen).toContain('write-engine-digest.mjs check')
    expect(packageScripts._build_pack_early_frozen).toContain('write-update-trust.mjs check')
    expect(packageScripts._build_pack_early_frozen).not.toContain('python-release-policy.mjs build-engine')
    expect(reverify?.run).toContain('release-source-freeze.mjs verify')
    expect(cleanup?.if).toBe('always()')
    expect(cleanup?.run).toContain('nachuan-early-access-source-freeze.json')
    expect(materializeIndex).toBeGreaterThan(-1)
    expect(verifyIndex).toBeGreaterThan(materializeIndex)
    expect(publishIndex).toBeGreaterThan(verifyIndex)
    expect(publisherCleanup?.if).toBe('always()')
    expect(publisherCleanup?.run).toContain('nachuan-publisher-source-freeze.json')
    expect(restoreIndex).toBeGreaterThan(materializeIndex)
    expect(verifyIndex).toBeGreaterThan(restoreIndex)
    expect(publishSteps[restoreIndex]?.run).toContain('release-source-freeze.mjs restore-generated')
    expect(
      readFileSync(join(desktopRoot, 'scripts', 'early-access-storage-transaction.mjs'), 'utf8')
    ).toContain("sourceComparison: 'portable'")
    for (const workflow of [finalizer.document, publisher.document]) {
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
    }
  })

  it('uses immutable source-freeze step outputs instead of a mutable cross-step environment baseline', () => {
    const documents = workflows()
    const finalizer = documents.find(({ name }) => name === 'finalize-early-access.yml')
    const publisher = documents.find(({ name }) => name === 'publish-early-access.yml')
    const finalizeSteps = workflowSteps(finalizer)
    const publishSteps = workflowSteps(publisher)
    const finalizerFreeze = finalizeSteps.find((step) =>
      String(step.name || '').includes('Freeze complete early-access source')
    )
    const publisherFreeze = publishSteps.find((step) =>
      String(step.name || '').includes('Materialize the producer source freeze')
    )
    const finalizerBinding = {
      NACHUAN_RELEASE_SOURCE_FREEZE_PATH:
        '${{ steps.release_source_freeze.outputs.source_freeze_path }}',
      NACHUAN_RELEASE_SOURCE_FREEZE_SHA256:
        '${{ steps.release_source_freeze.outputs.source_freeze_sha256 }}'
    }
    const publisherBinding = {
      NACHUAN_RELEASE_SOURCE_FREEZE_PATH:
        '${{ steps.producer_source_freeze.outputs.source_freeze_path }}',
      NACHUAN_RELEASE_SOURCE_FREEZE_SHA256:
        '${{ steps.producer_source_freeze.outputs.source_freeze_sha256 }}'
    }

    expect(finalizerFreeze?.id).toBe('release_source_freeze')
    expect(publisherFreeze?.id).toBe('producer_source_freeze')
    for (const step of [finalizerFreeze, publisherFreeze]) {
      expect(step?.run).toContain('source_freeze_path=$freeze')
      expect(step?.run).toContain('source_freeze_sha256=$digest')
      expect(step?.run).toContain('$env:GITHUB_OUTPUT')
      expect(step?.run).not.toContain('$env:GITHUB_ENV')
    }
    for (const step of finalizeSteps.filter((candidate) =>
      ['Finalize installer closure', 'Re-verify finalized'].some((name) =>
        String(candidate.name || '').includes(name)
      )
    )) {
      expect(step.env).toMatchObject(finalizerBinding)
    }
    for (const step of publishSteps.filter((candidate) =>
      [
        'Restore exact producer generated release modules',
        'Verify downloaded final closure',
        'Publish immutable assets'
      ].some((name) => String(candidate.name || '').includes(name))
    )) {
      expect(step.env).toMatchObject(publisherBinding)
    }
    for (const workflow of [finalizer, publisher]) {
      expect(readFileSync(join(workflowRoot, workflow.name), 'utf8')).not.toMatch(
        /NACHUAN_RELEASE_SOURCE_FREEZE_(?:PATH|SHA256)=.*GITHUB_ENV/u
      )
    }
  })

  it('generates and re-verifies production evidence while production publishing stays hard-blocked', () => {
    const workflow = workflows().find(({ name }) => name === 'release.yml')
    const buildSteps = workflow.document.jobs.build.steps
    const preparedEvidence = buildSteps.find((step) =>
      String(step.name || '').includes('Collect and freeze production release evidence')
    )
    const finalizedEvidence = buildSteps.find((step) =>
      String(step.name || '').includes('Finalize and re-verify production release evidence')
    )
    const sharedVerification = buildSteps.find((step) =>
      String(step.name || '').includes('Independently verify schema2 production closure')
    )
    const upload = buildSteps.find((step) =>
      String(step.uses || '').startsWith('actions/upload-artifact@')
    )
    const publishSteps = workflow.document.jobs.publish.steps
    const hardBlock = publishSteps.find((step) => String(step.name || '').includes('Fail closed'))

    expect(preparedEvidence?.env).toMatchObject({
      NACHUAN_RELEASE_TAG: '${{ needs.verify.outputs.release_tag }}',
      NACHUAN_RELEASE_COMMIT: '${{ needs.verify.outputs.release_commit }}',
      NACHUAN_RELEASE_RUN_ID: '${{ github.run_id }}',
      NACHUAN_UPDATE_TIER: 'production'
    })
    expect(preparedEvidence?.run).toContain('release-evidence.mjs prepare lean')
    expect(finalizedEvidence?.run).toContain('release-evidence.mjs finalize-prepared lean')
    expect(sharedVerification?.run).toContain('release-evidence.mjs verify lean')
    expect(upload?.with?.path).toContain(
      '${{ steps.candidate_archive.outputs.archive_path }}'
    )
    expect(upload?.with?.path).toContain(
      '${{ steps.candidate_archive.outputs.manifest_path }}'
    )
    expect(upload?.with?.path).not.toContain('desktop/release/')
    expect(hardBlock?.run).toContain(
      'third-party license gate has unresolved manual-legal-review blockers'
    )
    expect(hardBlock?.run).toMatch(/signed production update envelope[\s\S]*exit 1/i)
  })

  it('keeps release-evidence and workflow contracts as an explicit normal CI gate', () => {
    const workflow = workflows().find(({ name }) => name === 'ci.yml')
    const step = workflowSteps(workflow).find((item) => item.name === 'Release evidence contracts')

    expect(step?.run).toContain('npm exec --offline -- vitest run')
    expect(step?.run).toContain('scripts/release-evidence.test.mjs')
    expect(step?.run).toContain('scripts/early-access-workflow-contract.test.mjs')
  })

  it('materializes the workflow inputs into the exact schema2 finalizer contract', async () => {
    const workflow = workflows().find(({ name }) => name === 'finalize-early-access.yml')
    const steps = workflowSteps(workflow)
    const prepareRoot = steps.find((step) =>
      String(step.name || '').includes('Prepare signed root authorization and keyring floor')
    )
    const materializeLeaves = steps.find((step) =>
      String(step.name || '').includes('Materialize threshold leaf signing keys')
    )
    const workspace = mkdtempSync(join(signingFixtureTempRoot(), 'nachuan-workflow-signing-'))
    const rootOutputFile = join(workspace, 'github-root-output.txt')
    const leafOutputFile = join(workspace, 'github-leaf-output.txt')
    const passphrase = 'test-only-leaf-passphrase-2026'
    const trustRoot = generateKeyPairSync('ed25519')
    const leafA = generateKeyPairSync('ed25519')
    const leafB = generateKeyPairSync('ed25519')
    const encryptedPem = (pair) =>
      pair.privateKey.export({
        format: 'pem',
        type: 'pkcs8',
        cipher: 'aes-256-cbc',
        passphrase
      })
    const keyring = {
      schema: 1,
      channel: 'early-access-lean-win-x64',
      variant: 'lean',
      sequence: 9,
      threshold: 2,
      keys: [
        {
          keyId: 'early-leaf-a',
          publicKeySpkiBase64: leafA.publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
          notBeforeSequence: 1,
          notAfterSequence: 20
        },
        {
          keyId: 'early-leaf-b',
          publicKeySpkiBase64: leafB.publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
          notBeforeSequence: 1,
          notAfterSequence: 20
        }
      ]
    }
    const rootAuthorization = {
      schema: 1,
      keyring,
      keyringSignature: {
        algorithm: 'Ed25519',
        keyId: 'early-root-2026-01',
        value: sign(null, Buffer.from(canonicalUpdateKeyring(keyring)), trustRoot.privateKey).toString('base64')
      }
    }
    const bundle = {
      schema: 1,
      signingKeys: [
        { keyId: 'early-leaf-b', privateKeyPemBase64: Buffer.from(encryptedPem(leafB)).toString('base64') },
        { keyId: 'early-leaf-a', privateKeyPemBase64: Buffer.from(encryptedPem(leafA)).toString('base64') }
      ]
    }

    try {
      writeFileSync(rootOutputFile, '')
      writeFileSync(leafOutputFile, '')
      const rootPublicKeySpkiBase64 = trustRoot.publicKey
        .export({ format: 'der', type: 'spki' })
        .toString('base64')
      const rootResult = spawnSync(
        'powershell.exe',
        ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', prepareRoot.run],
        {
          cwd: join(desktopRoot, '..'),
          env: {
            ...process.env,
            ROOT_AUTHORIZATION_BASE64: Buffer.from(`${JSON.stringify(rootAuthorization)}\n`).toString('base64'),
            EXPECTED_ROOT_KEY_ID: 'early-root-2026-01',
            ROOT_PUBLIC_KEY_SPKI_BASE64: rootPublicKeySpkiBase64,
            RUNNER_TEMP: workspace,
            GITHUB_OUTPUT: rootOutputFile
          },
          encoding: 'utf8'
        }
      )
      expect(rootResult.status, `${rootResult.stdout}\n${rootResult.stderr}`).toBe(0)
      const parseOutputs = (path) => Object.fromEntries(
        readFileSync(path, 'utf8')
          .trim()
          .split(/\r?\n/)
          .map((line) => {
            const separator = line.indexOf('=')
            return [line.slice(0, separator), line.slice(separator + 1)]
          })
      )
      const rootOutputs = parseOutputs(rootOutputFile)
      const leafResult = spawnSync(
        'powershell.exe',
        ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', materializeLeaves.run],
        {
          cwd: join(desktopRoot, '..'),
          env: {
            ...process.env,
            ROOT_AUTHORIZATION_FILE: rootOutputs.root_authorization_file,
            LEAF_SIGNING_KEYS_BUNDLE_BASE64: Buffer.from(`${JSON.stringify(bundle)}\n`).toString('base64'),
            EXPECTED_ROOT_KEY_ID: 'early-root-2026-01',
            RUNNER_TEMP: workspace,
            GITHUB_OUTPUT: leafOutputFile
          },
          encoding: 'utf8'
        }
      )
      expect(leafResult.status, `${leafResult.stdout}\n${leafResult.stderr}`).toBe(0)
      const outputs = { ...rootOutputs, ...parseOutputs(leafOutputFile) }
      expect(outputs).toMatchObject({
        keyring_sequence: '9',
        keyring_sha256: createHash('sha256')
          .update(canonicalUpdateKeyring(keyring), 'utf8')
          .digest('hex')
      })
      const signing = loadEarlyAccessSigningInputs({
          RUNNER_TEMP: workspace,
          NACHUAN_UPDATE_KEY_ID: 'early-root-2026-01',
          NACHUAN_UPDATE_ROOT_AUTHORIZATION_FILE: outputs.root_authorization_file,
          NACHUAN_UPDATE_LEAF_SIGNING_KEYS_FILE: outputs.leaf_signing_keys_file,
          NACHUAN_UPDATE_LEAF_PRIVATE_KEY_PASSPHRASE: passphrase
        })
      expect(signing).toMatchObject({
        keyId: 'early-leaf-a',
        signingKeys: [{ keyId: 'early-leaf-a' }, { keyId: 'early-leaf-b' }]
      })
      const installer = join(workspace, 'nachuan-1.3.0-lean-early-access-unsigned-win.exe')
      const envelopePath = join(workspace, 'early-access-lean-win-x64.json')
      writeFileSync(installer, '')
      truncateSync(installer, 25 * 1024 * 1024)
      await signUpdateManifest({
        installer,
        output: envelopePath,
        releaseTier: 'early-access',
        channel: keyring.channel,
        variant: keyring.variant,
        version: '1.3.0',
        sequence: 4,
        keyId: signing.keyId,
        expectedPublicKeySpkiBase64: rootPublicKeySpkiBase64,
        rootAuthorization: signing.rootAuthorization,
        signingKeys: signing.signingKeys,
        passphrase: signing.passphrase
      })
      const envelopeBytes = readFileSync(envelopePath)
      expect(JSON.parse(envelopeBytes.toString('utf8'))).toMatchObject({
        schema: 2,
        keyring: { sequence: 9, threshold: 2 },
        manifest: { sequence: 4 },
        signatures: [{ keyId: 'early-leaf-a' }, { keyId: 'early-leaf-b' }]
      })
      expect(
        verifySignedUpdateEnvelopeForRelease({
          bytes: envelopeBytes,
          rootPublicKeySpkiBase64,
          expectedRootKeyId: 'early-root-2026-01',
          expectedChannel: keyring.channel,
          expectedVariant: keyring.variant
        }).manifest.sequence
      ).toBe(4)
    } finally {
      rmSync(workspace, { recursive: true, force: true })
    }
  })
})
