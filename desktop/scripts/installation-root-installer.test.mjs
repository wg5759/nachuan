import { cpSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'

import { afterEach, describe, expect, it } from 'vitest'

import { verifyInstallationRootInstallerContract } from './installation-root-installer.mjs'


const projectRoot = resolve(process.cwd(), '..')
const roots = []


async function fixture() {
  const root = await mkdtemp(join(tmpdir(), 'nachuan-installation-installer-'))
  roots.push(root)
  const desktopRoot = join(root, 'desktop')
  for (const source of [
    join(projectRoot, 'desktop', 'electron-builder.yml'),
    join(projectRoot, 'desktop', 'build', 'installer.nsh'),
    join(projectRoot, 'engine_main.py'),
    join(projectRoot, 'engine.spec')
  ]) {
    const relative = source.slice(projectRoot.length + 1)
    const target = join(root, relative)
    mkdirSync(dirname(target), { recursive: true })
    cpSync(source, target)
  }
  return { root, desktopRoot }
}


afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })))
})


describe('Installation Root NSIS/package contract', () => {
  it('accepts the reviewed per-machine, engine-owned provisioning chain', () => {
    const result = verifyInstallationRootInstallerContract()
    expect(result.includePath.endsWith(join('build', 'installer.nsh'))).toBe(true)
  })

  it('runs the installer contract from the final package verifier', () => {
    const verifier = readFileSync(join(projectRoot, 'desktop', 'scripts', '_verify_pack.mjs'), 'utf8')
    const contract = verifier.indexOf('verifyInstallationRootInstallerContract({')
    const packagedOutput = verifier.indexOf('verifyPackagedReleaseOutput({', contract)
    expect(contract).toBeGreaterThan(verifier.indexOf('async function verifyPack('))
    expect(packagedOutput).toBeGreaterThan(contract)
  })

  it('rejects an installer that could delete persistent authority', async () => {
    const { root, desktopRoot } = await fixture()
    const includePath = join(desktopRoot, 'build', 'installer.nsh')
    writeFileSync(
      includePath,
      `${readFileSync(includePath, 'utf8')}\nRMDir /r "$PROGRAMDATA\\Nachuan\\StateRoot"\n`
    )
    expect(() =>
      verifyInstallationRootInstallerContract({ desktopRoot, projectRoot: root })
    ).toThrow(/environment-derived authority path|never delete authority state/)
  })

  it('rejects loss of elevation or failure rollback', async () => {
    const { root, desktopRoot } = await fixture()
    const configPath = join(desktopRoot, 'electron-builder.yml')
    writeFileSync(
      configPath,
      readFileSync(configPath, 'utf8').replace('perMachine: true', 'perMachine: false')
    )
    expect(() =>
      verifyInstallationRootInstallerContract({ desktopRoot, projectRoot: root })
    ).toThrow(/per-machine installer/)

    writeFileSync(
      configPath,
      readFileSync(configPath, 'utf8').replace('perMachine: false', 'perMachine: true')
    )
    const includePath = join(desktopRoot, 'build', 'installer.nsh')
    writeFileSync(
      includePath,
      readFileSync(includePath, 'utf8').replace('SetErrorLevel 1603', 'SetErrorLevel 0')
    )
    expect(() =>
      verifyInstallationRootInstallerContract({ desktopRoot, projectRoot: root })
    ).toThrow(/ordered marker/)
  })
})
