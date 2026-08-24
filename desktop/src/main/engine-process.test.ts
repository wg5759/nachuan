import { createHmac } from 'node:crypto'
import http from 'node:http'
import { afterEach, describe, expect, it } from 'vitest'

import {
  expectedBootProof,
  enforcePackagedFinancialLedger,
  selectLoopbackPort,
  validateEngineHealth,
  waitForEngineReady
} from './engine-process'

const servers: http.Server[] = []

afterEach(async () => {
  await Promise.all(
    servers.splice(0).map(
      (server) => new Promise<void>((resolve) => server.close(() => resolve()))
    )
  )
})

describe('desktop engine child authority', () => {
  it('forces the packaged child to use a separate required financial ledger', () => {
    const env: NodeJS.ProcessEnv = {
      NACHUAN_PROVIDER_CALL_LEDGER_MODE: 'off',
      NACHUAN_PROVIDER_CALL_LEDGER_PATH: 'D:\\attacker\\redirect.db'
    }
    enforcePackagedFinancialLedger(env, 'D:\\NachuanRuntime\\data')
    expect(env.NACHUAN_PROVIDER_CALL_LEDGER_MODE).toBe('required')
    expect(env.NACHUAN_PROVIDER_CALL_LEDGER_PATH).toBe(
      'D:\\NachuanRuntime\\data\\provider-calls.db'
    )
    expect(env.USAGE_DB_PATH).toBe('D:\\NachuanRuntime\\data\\usage.db')
    expect(() => enforcePackagedFinancialLedger(env, '.\\relative-data')).toThrow(/absolute/)
  })

  it('binds readiness to the exact token, challenge, PID, and database state', () => {
    const token = 'ab'.repeat(32)
    const challenge = 'cd'.repeat(32)
    const proof = expectedBootProof(token, challenge)
    const valid = {
      status: 'ok',
      readiness: 'ok',
      pid: 4321,
      boot_proof: proof,
      checks: {
        database: { ready: true },
        financial_ledger: { required: true, ready: true }
      }
    }
    expect(validateEngineHealth(valid, 4321, token, challenge)).toBe(true)
    expect(validateEngineHealth({ ...valid, pid: 4322 }, 4321, token, challenge)).toBe(false)
    expect(
      validateEngineHealth(
        { ...valid, boot_proof: createHmac('sha256', Buffer.from('ef'.repeat(32), 'hex')).update(challenge).digest('hex') },
        4321,
        token,
        challenge
      )
    ).toBe(false)
    expect(validateEngineHealth({ ...valid, checks: { database: { ready: false } } }, 4321, token, challenge)).toBe(false)
    expect(
      validateEngineHealth(
        {
          ...valid,
          checks: {
            database: { ready: true },
            financial_ledger: { required: true, ready: false }
          }
        },
        4321,
        token,
        challenge
      )
    ).toBe(false)
    expect(validateEngineHealth({ ...valid, readiness: 'degraded' }, 4321, token, challenge)).toBe(false)
  })

  it('rejects a healthy-looking port that cannot prove the child token', async () => {
    const port = await selectLoopbackPort()
    const server = http.createServer((_req, res) => {
      res.setHeader('Content-Type', 'application/json')
      res.end(
        JSON.stringify({
          status: 'ok',
          readiness: 'ok',
          pid: process.pid,
          boot_proof: '00'.repeat(32),
          checks: {
            database: { ready: true },
            financial_ledger: { required: true, ready: true }
          }
        })
      )
    })
    servers.push(server)
    await new Promise<void>((resolve) => server.listen(port, '127.0.0.1', resolve))
    await expect(waitForEngineReady(port, process.pid, '11'.repeat(32), 250)).rejects.toThrow(/prove readiness/)
  })
})
