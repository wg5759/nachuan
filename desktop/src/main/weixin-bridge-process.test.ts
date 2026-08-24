import { EventEmitter } from 'node:events'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'

import {
  buildWeixinBridgeLaunch,
  DesktopWeixinBridgeSupervisor,
  hasConfiguredWeixinLogin,
  type WeixinBridgeChild
} from './weixin-bridge-process'

const bridgeKey = `sk-bridge-v2-weixin-${'ab'.repeat(32)}`
const temporaryDirectories: string[] = []

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true })
  }
})

describe('Desktop managed Weixin bridge launch', () => {
  it('uses the signed packaged engine as the bridge runtime with a scoped loopback capability', () => {
    const launch = buildWeixinBridgeLaunch({
      packaged: true,
      engineExecutable: 'C:\\Program Files\\Nachuan\\resources\\engine\\engine.exe',
      repoRoot: 'D:\\source',
      dataDirectory: 'C:\\Users\\owner\\AppData\\Roaming\\Nachuan\\data',
      enginePort: 43123,
      bridgeKey,
      sourceEnvironment: {
        SYSTEMROOT: 'C:\\Windows',
        USERPROFILE: 'C:\\Users\\owner',
        NACHUAN_RUNTIME_PROFILE: 'store',
        NACHUAN_STORE_RUNTIME_PROFILE_MANIFEST:
          'C:\\Program Files\\Nachuan\\resources\\store-runtime-profile.v1.json',
        NACHUAN_STORE_RUNTIME_PROFILE_SHA256: 'cd'.repeat(32),
        GATEWAY_API_KEYS: 'must-not-cross',
        OPENAI_API_KEY: 'must-not-cross'
      }
    })

    expect(launch.command).toBe(
      'C:\\Program Files\\Nachuan\\resources\\engine\\engine.exe'
    )
    expect(launch.args).toEqual(['--nachuan-weixin-bridge'])
    expect(launch.cwd).toBe('C:\\Program Files\\Nachuan\\resources\\engine')
    expect(launch.env.BRIDGE_API_KEY).toBe(bridgeKey)
    expect(launch.env.BRIDGE_ENGINE_URL).toBe('http://127.0.0.1:43123')
    expect(launch.env.USAGE_DB_PATH).toBe(
      'C:\\Users\\owner\\AppData\\Roaming\\Nachuan\\data\\usage.db'
    )
    expect(launch.env.NACHUAN_RUNTIME_PROFILE).toBe('store')
    expect(launch.env.NACHUAN_STORE_RUNTIME_PROFILE_MANIFEST).toBe(
      'C:\\Program Files\\Nachuan\\resources\\store-runtime-profile.v1.json'
    )
    expect(launch.env.NACHUAN_STORE_RUNTIME_PROFILE_SHA256).toBe('cd'.repeat(32))
    expect(launch.env.GATEWAY_API_KEYS).toBeUndefined()
    expect(launch.env.OPENAI_API_KEY).toBeUndefined()
  })

  it('restarts a configured bridge after an unexpected exit and never restarts after stop', () => {
    const children: Array<WeixinBridgeChild & EventEmitter> = []
    const scheduled: Array<() => void> = []
    let kills = 0
    const supervisor = new DesktopWeixinBridgeSupervisor({
      configured: () => true,
      spawn: () => {
        const child = Object.assign(new EventEmitter(), {
          pid: 1000 + children.length,
          exitCode: null as number | null,
          kill: () => {
            kills += 1
            return true
          }
        })
        children.push(child)
        return child
      },
      schedule: (callback) => {
        scheduled.push(callback)
        return callback
      },
      cancel: () => undefined
    })
    const input = {
      packaged: true,
      engineExecutable: 'C:\\Program Files\\Nachuan\\resources\\engine\\engine.exe',
      repoRoot: 'D:\\source',
      dataDirectory: 'C:\\Users\\owner\\AppData\\Roaming\\Nachuan\\data',
      enginePort: 43123,
      bridgeKey,
      sourceEnvironment: {
        SYSTEMROOT: 'C:\\Windows',
        NACHUAN_RUNTIME_PROFILE: 'store',
        NACHUAN_STORE_RUNTIME_PROFILE_MANIFEST:
          'C:\\Program Files\\Nachuan\\resources\\store-runtime-profile.v1.json',
        NACHUAN_STORE_RUNTIME_PROFILE_SHA256: 'cd'.repeat(32)
      }
    }

    expect(supervisor.start(input)).toBe(true)
    expect(children).toHaveLength(1)
    children[0].emit('exit', 1, null)
    expect(scheduled).toHaveLength(1)
    scheduled.shift()?.()
    expect(children).toHaveLength(2)

    supervisor.stop()
    expect(kills).toBe(1)
    children[1].emit('exit', 1, null)
    expect(scheduled).toHaveLength(0)
  })

  it('keeps retry ownership when the first process spawn is transiently unavailable', () => {
    const scheduled: Array<() => void> = []
    let attempts = 0
    const child = Object.assign(new EventEmitter(), {
      pid: 2001,
      exitCode: null as number | null,
      kill: () => true
    })
    const supervisor = new DesktopWeixinBridgeSupervisor({
      configured: () => true,
      spawn: () => {
        attempts += 1
        if (attempts === 1) throw new Error('transient spawn failure')
        return child
      },
      schedule: (callback) => {
        scheduled.push(callback)
        return callback
      },
      cancel: () => undefined
    })

    expect(
      supervisor.start({
        packaged: true,
        engineExecutable:
          'C:\\Program Files\\Nachuan\\resources\\engine\\engine.exe',
        repoRoot: 'D:\\source',
        dataDirectory: 'C:\\Users\\owner\\AppData\\Roaming\\Nachuan\\data',
        enginePort: 43123,
        bridgeKey,
        sourceEnvironment: {
          NACHUAN_RUNTIME_PROFILE: 'store',
          NACHUAN_STORE_RUNTIME_PROFILE_MANIFEST:
            'C:\\Program Files\\Nachuan\\resources\\store-runtime-profile.v1.json',
          NACHUAN_STORE_RUNTIME_PROFILE_SHA256: 'cd'.repeat(32)
        }
      })
    ).toBe(true)
    expect(scheduled).toHaveLength(1)
    scheduled.shift()?.()
    expect(attempts).toBe(2)
  })

  it('starts only from a bounded existing saved-login envelope', () => {
    const dataDirectory = mkdtempSync(join(tmpdir(), 'nachuan-weixin-login-'))
    temporaryDirectories.push(dataDirectory)

    expect(hasConfiguredWeixinLogin(dataDirectory)).toBe(false)
    writeFileSync(join(dataDirectory, 'ilink_token.json'), '')
    expect(hasConfiguredWeixinLogin(dataDirectory)).toBe(false)
    writeFileSync(join(dataDirectory, 'ilink_token.json'), '{"protected":true}')
    expect(hasConfiguredWeixinLogin(dataDirectory)).toBe(true)
    writeFileSync(join(dataDirectory, 'ilink_token.json'), Buffer.alloc(65 * 1024))
    expect(hasConfiguredWeixinLogin(dataDirectory)).toBe(false)
  })

  it('wires the bridge only after the exact Desktop engine generation proves ready', () => {
    const source = readFileSync(join(process.cwd(), 'src', 'main', 'index.ts'), 'utf8')
    const engineEnvironment = source.indexOf(
      'NACHUAN_WEIXIN_BRIDGE_API_KEY: weixinBridgeKey'
    )
    const waitForReady = source.indexOf('waitForEngineReady(candidatePort, child.pid, bootToken)')
    const publish = source.indexOf('engineRootSessions.publish(attempt, child.pid)', waitForReady)
    const startBridge = source.indexOf('weixinBridgeSupervisor.start({', publish)
    const quit = source.indexOf("app.on('before-quit'")
    const stopBridge = source.indexOf('weixinBridgeSupervisor.stop()', quit)

    expect(engineEnvironment).toBeGreaterThan(-1)
    expect(waitForReady).toBeGreaterThan(engineEnvironment)
    expect(publish).toBeGreaterThan(waitForReady)
    expect(startBridge).toBeGreaterThan(publish)
    expect(stopBridge).toBeGreaterThan(quit)
  })
})
