import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'

import { afterEach, expect, it } from 'vitest'

import {
  cleanupIsolatedVitestTempRoot,
  createIsolatedVitestTempEnvironment
} from './vitest-isolated-runner.mjs'

const roots = []

afterEach(() => {
  for (const root of roots.splice(0)) {
    if (existsSync(root)) rmSync(root, { force: true, recursive: true })
  }
}, 60_000)

it('creates one project-local TEMP/TMP/TMPDIR root and removes only that root', () => {
  const projectRoot = mkdtempSync(join(tmpdir(), 'nachuan-vitest-runner-project-'))
  const externalParent = mkdtempSync(join(tmpdir(), 'nachuan-vitest-external-parent-'))
  roots.push(projectRoot, externalParent)
  const isolated = createIsolatedVitestTempEnvironment({
    projectRoot,
    baseEnv: { KEEP_ME: 'yes', TEMP: externalParent, TMP: externalParent }
  })

  expect(dirname(isolated.tempRoot)).toBe(
    resolve(projectRoot, 'build', 'test-temp')
  )
  expect(isolated.env).toMatchObject({
    KEEP_ME: 'yes',
    TEMP: isolated.tempRoot,
    TMP: isolated.tempRoot,
    TMPDIR: isolated.tempRoot
  })
  expect(dirname(isolated.externalTempRoot)).toBe(resolve(externalParent))
  expect(isolated.env.NACHUAN_EXTERNAL_TEST_TEMP_ROOT).toBe(isolated.externalTempRoot)
  writeFileSync(join(isolated.tempRoot, 'owned.txt'), 'owned', 'utf8')
  writeFileSync(join(isolated.externalTempRoot, 'offline-key.pem'), 'test-only', 'utf8')

  cleanupIsolatedVitestTempRoot(isolated)
  expect(existsSync(isolated.tempRoot)).toBe(false)
  expect(existsSync(isolated.externalTempRoot)).toBe(false)
})

it('refuses to clean a path outside the exact trusted test-temp parent', () => {
  const projectRoot = mkdtempSync(join(tmpdir(), 'nachuan-vitest-runner-boundary-'))
  roots.push(projectRoot)
  const trustedParent = resolve(projectRoot, 'build', 'test-temp')

  expect(() =>
    cleanupIsolatedVitestTempRoot({
      tempRoot: projectRoot,
      trustedParent
    })
  ).toThrow(/outside the trusted test-temp parent/i)
  expect(existsSync(projectRoot)).toBe(true)
})
