import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

describe('paid media production main integration', () => {
  const source = readFileSync(join(process.cwd(), 'src', 'main', 'index.ts'), 'utf8')
  const runtimeSource = readFileSync(
    join(process.cwd(), 'src', 'main', 'paid-media-asset-v2-runtime.ts'),
    'utf8'
  )
  const recoveryExecutorSource = readFileSync(
    join(process.cwd(), 'src', 'main', 'paid-media-recovery-executor.ts'),
    'utf8'
  )

  it('creates ordinary chat before paid Root reconciliation and never quits for paid degradation', () => {
    const start = source.indexOf('await startEngine()')
    const window = source.indexOf('createWindow()', start)
    const paid = source.indexOf('await initializePaidMediaControlPlane()', start)
    expect(start).toBeGreaterThan(-1)
    expect(window).toBeGreaterThan(start)
    expect(window).toBeLessThan(paid)

    const catchStart = source.indexOf('paidMediaService?.disableRemoteOperations()', paid)
    const updateStart = source.indexOf('void setupAutoUpdate()', catchStart)
    const degradedBlock = source.slice(catchStart, updateStart)
    expect(degradedBlock).toContain("auditDesktop('paid_media.control_plane_degraded'")
    expect(degradedBlock).not.toContain('app.quit()')
    expect(degradedBlock).not.toContain('showErrorBox')
  })

  it('binds ledger, vault, capacity and seal to Installation Root while v1 remote stays latched off', () => {
    const controlPlane = source.slice(
      source.indexOf('async function initializePaidMediaControlPlane'),
      source.indexOf('function createWindow')
    )
    expect(controlPlane).toContain('new PaidMediaInstallationRootAuthority')
    expect(controlPlane).toContain('installationRoot: installationAuthority')
    expect(controlPlane).toContain('legacySeal')
    expect(controlPlane).toContain('provisionLocalState: startup.createLocalDirectories')
    const service = controlPlane.indexOf('new PaidMediaService')
    const disabled = controlPlane.indexOf('disableRemoteOperations()', service)
    const prepared = controlPlane.indexOf('prepareInstallationAuthority', disabled)
    expect(service).toBeGreaterThan(-1)
    expect(disabled).toBeGreaterThan(service)
    expect(prepared).toBeGreaterThan(-1)
    expect(disabled).toBeLessThan(prepared)
  })

  it('wires the production asset-v2 session, stage, archive, and remote ACK pipeline', () => {
    const controlPlane = source.slice(
      source.indexOf('async function initializePaidMediaControlPlane'),
      source.indexOf('function createWindow')
    )
    const sessionClient = controlPlane.indexOf('new PaidMediaEngineSessionClient')
    const runtimeStart = controlPlane.indexOf(
      'const paidMediaAssetV2Runtime = new PaidMediaAssetV2Runtime'
    )
    const runtimeEnd = controlPlane.indexOf(
      'const runPaidMediaRootRecoverableMutation',
      runtimeStart
    )
    const runtimeWiring = controlPlane.slice(runtimeStart, runtimeEnd)
    const stageHandoff = runtimeWiring.indexOf('stageHandoff: recoveryExecutor')
    const createClient = runtimeWiring.indexOf('createPaidMediaImageAssets', stageHandoff)
    const downloadClient = runtimeWiring.indexOf('downloadPaidMediaAsset', createClient)
    const probeClient = runtimeWiring.indexOf('probePaidMediaStagedAsset', downloadClient)
    const acknowledgeClient = runtimeWiring.indexOf('acknowledgePaidMediaAssets', probeClient)
    const executorStart = controlPlane.indexOf(
      'const paidMediaAssetV2: PaidMediaAssetV2Executor',
      runtimeEnd
    )
    const executorEnd = controlPlane.indexOf(
      'paidMediaService = new PaidMediaService',
      executorStart
    )
    const executor = controlPlane.slice(executorStart, executorEnd)
    const executeReadyGuard = executor.indexOf('if (!paidMediaAssetV2StageReady)')
    const execute = executor.indexOf('paidMediaAssetV2Runtime.executeImage', executeReadyGuard)
    const convergeReadyGuard = executor.indexOf(
      'if (!paidMediaAssetV2StageReady)',
      executeReadyGuard + 1
    )
    const converge = executor.indexOf(
      'paidMediaAssetV2Runtime.convergeImageAck',
      convergeReadyGuard
    )
    const stageReady = controlPlane.indexOf('activatePaidMediaEngineSessionStage', sessionClient)
    const readyLatch = controlPlane.indexOf('paidMediaAssetV2StageReady = true', stageReady)

    expect(sessionClient).toBeGreaterThan(-1)
    expect(runtimeStart).toBeGreaterThan(sessionClient)
    expect(runtimeEnd).toBeGreaterThan(runtimeStart)
    expect(stageHandoff).toBeGreaterThan(-1)
    expect(createClient).toBeGreaterThan(stageHandoff)
    expect(downloadClient).toBeGreaterThan(createClient)
    expect(probeClient).toBeGreaterThan(downloadClient)
    expect(acknowledgeClient).toBeGreaterThan(probeClient)
    expect(executorStart).toBeGreaterThan(runtimeEnd)
    expect(executorEnd).toBeGreaterThan(executorStart)
    expect(executeReadyGuard).toBeGreaterThan(-1)
    expect(execute).toBeGreaterThan(executeReadyGuard)
    expect(convergeReadyGuard).toBeGreaterThan(execute)
    expect(converge).toBeGreaterThan(convergeReadyGuard)
    expect(stageReady).toBeGreaterThan(sessionClient)
    expect(readyLatch).toBeGreaterThan(stageReady)

    const runtimeExecute = runtimeSource.indexOf('async executeImage(')
    const dispatch = runtimeSource.indexOf("kind: 'asset_v2_dispatch'", runtimeExecute)
    const create = runtimeSource.indexOf('this.dependencies.createImageAssets', dispatch)
    const reserve = runtimeSource.indexOf("kind: 'asset_v2_stage_reserve'", create)
    const stageOpen = runtimeSource.indexOf(
      'this.dependencies.stageHandoff.takeStageOpenResult',
      reserve
    )
    const download = runtimeSource.indexOf('this.dependencies.downloadAsset', stageOpen)
    const probe = runtimeSource.indexOf('this.dependencies.probeAsset', download)
    const archive = runtimeSource.indexOf("kind: 'asset_v2_stage_archive'", probe)
    const archiveReadback = runtimeSource.indexOf(
      'this.dependencies.vault.verifyArchive',
      archive
    )
    const ackIntent = runtimeSource.indexOf(
      "kind: 'asset_v2_result_ready_ack_intent'",
      archiveReadback
    )
    const convergeAck = runtimeSource.indexOf('this.convergeImageAck', ackIntent)
    expect(runtimeExecute).toBeGreaterThan(-1)
    expect(dispatch).toBeGreaterThan(runtimeExecute)
    expect(create).toBeGreaterThan(dispatch)
    expect(reserve).toBeGreaterThan(create)
    expect(stageOpen).toBeGreaterThan(reserve)
    expect(download).toBeGreaterThan(stageOpen)
    expect(probe).toBeGreaterThan(download)
    expect(archive).toBeGreaterThan(probe)
    expect(archiveReadback).toBeGreaterThan(archive)
    expect(ackIntent).toBeGreaterThan(archiveReadback)
    expect(convergeAck).toBeGreaterThan(ackIntent)

    const recoveryDispatch = recoveryExecutorSource.indexOf(
      'private async executeDispatch'
    )
    const capacityReservation = recoveryExecutorSource.indexOf(
      'this.dependencies.capacity.ensureReservation',
      recoveryDispatch
    )
    const dispatchMarker = recoveryExecutorSource.indexOf(
      'this.dependencies.vault.recordAssetV2DispatchMarker',
      capacityReservation
    )
    const dispatchLedger = recoveryExecutorSource.indexOf(
      'this.dependencies.ledger.ensureV2DispatchingOnce',
      dispatchMarker
    )
    expect(recoveryDispatch).toBeGreaterThan(-1)
    expect(capacityReservation).toBeGreaterThan(recoveryDispatch)
    expect(dispatchMarker).toBeGreaterThan(capacityReservation)
    expect(dispatchLedger).toBeGreaterThan(dispatchMarker)

    const ackConvergence = runtimeSource.indexOf('private async convergeImageAckOnce')
    const remoteAck = runtimeSource.indexOf(
      'this.dependencies.acknowledgeAssets',
      ackConvergence
    )
    const ackCompletion = runtimeSource.indexOf(
      "kind: 'asset_v2_ack_completion'",
      remoteAck
    )
    const capacityRelease = runtimeSource.indexOf(
      "kind: 'asset_v2_capacity_release'",
      ackCompletion
    )
    expect(ackConvergence).toBeGreaterThan(-1)
    expect(remoteAck).toBeGreaterThan(ackConvergence)
    expect(ackCompletion).toBeGreaterThan(remoteAck)
    expect(capacityRelease).toBeGreaterThan(ackCompletion)
  })
})
