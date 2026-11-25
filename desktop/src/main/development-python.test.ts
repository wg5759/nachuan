import { existsSync, mkdtempSync, mkdirSync, writeFileSync, rmSync, realpathSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { developmentPythonLaunch } from './development-python'

const roots: string[] = []
function fixture(config?: string) {
  const root = mkdtempSync(join(tmpdir(), 'nachuan-dev-python-'))
  roots.push(root)
  const base = join(root, 'base')
  mkdirSync(join(root, '.venv/Scripts'), { recursive: true })
  mkdirSync(base)
  writeFileSync(join(root, '.venv/Scripts/python.exe'), 'redirector fixture')
  writeFileSync(join(base, 'python.exe'), 'base fixture')
  writeFileSync(join(root, '.venv/pyvenv.cfg'), config ?? `home = ${base}\nversion_info = 3.12.9\n`)
  return { root, base }
}
afterEach(() => roots.splice(0).forEach(root => rmSync(root, { recursive: true, force: true })))
describe('Windows development Python identity', () => {
  it('launches base directly and preserves the exact venv path', () => {
    const { root, base } = fixture()
    const plan = developmentPythonLaunch(root, 'win32')
    expect(plan.executable).toBe(join(base, 'python.exe'))
    expect(plan.environment.__PYVENV_LAUNCHER__).toBe(join(root, '.venv/Scripts/python.exe'))
  })
  it.each(['home = relative\n', 'version_info=3.12.9\n', 'home=C:/one\nhome=C:/two\n'])('rejects an ambiguous or relative home', config => {
    const { root } = fixture(config)
    expect(() => developmentPythonLaunch(root, 'win32')).toThrow()
  })
  const project = resolve(dirname(fileURLToPath(import.meta.url)), '../../..')
  it.skipIf(process.platform !== 'win32' || !existsSync(join(project, '.venv/pyvenv.cfg')))('keeps the actual PID, venv prefix and site-packages in a real child', () => {
    const plan = developmentPythonLaunch(project, 'win32')
    const child = spawnSync(plan.executable, ['-I', '-X', 'utf8', '-c',
      'import os,sys,json,fastapi;print(json.dumps({"pid":os.getpid(),"prefix":sys.prefix,"package":fastapi.__file__}))'], {
      env: { SYSTEMROOT: process.env.SYSTEMROOT, WINDIR: process.env.WINDIR, ...plan.environment },
      encoding: 'utf8', windowsHide: true, timeout: 15000
    })
    expect(child.status).toBe(0)
    const report = JSON.parse(child.stdout)
    expect(report.pid).toBe(child.pid)
    expect(realpathSync.native(report.prefix)).toBe(realpathSync.native(join(project, '.venv')))
    expect(report.package.toLowerCase().startsWith(join(project, '.venv', 'Lib', 'site-packages').toLowerCase())).toBe(true)
  })
})
