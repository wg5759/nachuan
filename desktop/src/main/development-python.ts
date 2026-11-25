import { lstatSync, readFileSync, realpathSync } from 'node:fs'
import { isAbsolute, join } from 'node:path'

function regularFile(path: string): string {
  const info = lstatSync(path)
  if (!info.isFile() || info.isSymbolicLink()) throw new Error('development Python must be a fixed regular file')
  return realpathSync.native(path)
}

export function developmentPythonLaunch(projectRoot: string, platform: NodeJS.Platform = process.platform) {
  if (!isAbsolute(projectRoot)) throw new Error('development root must be absolute')
  const venvExecutable = regularFile(join(projectRoot, '.venv', platform === 'win32' ? 'Scripts/python.exe' : 'bin/python'))
  if (platform !== 'win32') return { executable: venvExecutable, environment: {} as NodeJS.ProcessEnv }
  const configPath = regularFile(join(projectRoot, '.venv/pyvenv.cfg'))
  const config = readFileSync(configPath, 'utf8')
  if (config.length > 16_384) throw new Error('development venv config too large')
  const homes = config.split(/\r?\n/).filter(line => /^home\s*=/i.test(line.trim()))
  if (homes.length !== 1) throw new Error('development venv must bind exactly one Python home')
  const home = homes[0].slice(homes[0].indexOf('=') + 1).trim()
  if (!isAbsolute(home)) throw new Error('development Python home must be absolute')
  const executable = regularFile(join(home, 'python.exe'))
  if (executable.toLowerCase() === venvExecutable.toLowerCase()) throw new Error('Python redirector cannot be the base interpreter')
  // Windows venv python.exe is a redirector with a different child PID. Launch
  // its exact base directly, while retaining CPython's venv prefix semantics.
  // This preserves the strict child.pid + boot-HMAC contract without trusting
  // an arbitrary PID from a health response. Packaged launches never use this.
  return { executable, environment: { __PYVENV_LAUNCHER__: venvExecutable } }
}
