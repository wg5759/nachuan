import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import http from 'node:http'
import { createServer } from 'node:net'
import { isAbsolute, join } from 'node:path'

const MAX_HEALTH_BYTES = 64 * 1024
const DEFAULT_READY_TIMEOUT_MS = 60_000

export function enforcePackagedFinancialLedger(
  env: NodeJS.ProcessEnv,
  dataDirectory: string
): void {
  if (!isAbsolute(dataDirectory)) {
    throw new Error('packaged financial ledger requires an absolute runtime data directory')
  }
  // These are assignments, not fallbacks: inherited environment variables
  // must never disable or redirect the production financial source of truth.
  env.USAGE_DB_PATH = join(dataDirectory, 'usage.db')
  env.NACHUAN_PROVIDER_CALL_LEDGER_MODE = 'required'
  env.NACHUAN_PROVIDER_CALL_LEDGER_PATH = join(dataDirectory, 'provider-calls.db')
}

export interface EngineHealthDocument {
  status?: unknown
  readiness?: unknown
  pid?: unknown
  boot_proof?: unknown
  checks?: {
    database?: { ready?: unknown }
    financial_ledger?: { required?: unknown; ready?: unknown }
  }
}

function exactHex(value: unknown, bytes: number): value is string {
  return typeof value === 'string' && new RegExp(`^[0-9a-f]{${bytes * 2}}$`).test(value)
}

export function expectedBootProof(bootToken: string, challenge: string): string {
  if (!exactHex(bootToken, 32) || !exactHex(challenge, 32)) {
    throw new Error('engine boot token and challenge must be 32-byte lowercase hex values')
  }
  return createHmac('sha256', Buffer.from(bootToken, 'hex')).update(challenge, 'ascii').digest('hex')
}

export function validateEngineHealth(
  document: EngineHealthDocument,
  expectedPid: number,
  bootToken: string,
  challenge: string
): boolean {
  if (
    document.status !== 'ok' ||
    document.readiness !== 'ok' ||
    !Number.isSafeInteger(document.pid) ||
    document.pid !== expectedPid ||
    document.checks?.database?.ready !== true ||
    document.checks?.financial_ledger?.required !== true ||
    document.checks?.financial_ledger?.ready !== true ||
    !exactHex(document.boot_proof, 32)
  ) {
    return false
  }
  const expected = Buffer.from(expectedBootProof(bootToken, challenge), 'hex')
  const actual = Buffer.from(document.boot_proof, 'hex')
  return expected.byteLength === actual.byteLength && timingSafeEqual(expected, actual)
}

/**
 * Ask the kernel for an unused loopback port.  The later boot-token/PID proof
 * is the authority check: if another process races to claim this port, startup
 * fails closed without ever sending it runtime or approval credentials.
 */
export async function selectLoopbackPort(): Promise<number> {
  return await new Promise<number>((resolve, reject) => {
    const server = createServer()
    server.unref()
    server.once('error', reject)
    server.listen({ host: '127.0.0.1', port: 0, exclusive: true }, () => {
      const address = server.address()
      if (!address || typeof address === 'string' || !Number.isInteger(address.port)) {
        server.close()
        reject(new Error('kernel did not allocate a loopback engine port'))
        return
      }
      const port = address.port
      server.close((error) => (error ? reject(error) : resolve(port)))
    })
  })
}

function probeEngine(
  port: number,
  expectedPid: number,
  bootToken: string,
  challenge: string
): Promise<boolean> {
  return new Promise((resolve) => {
    let settled = false
    const finish = (result: boolean): void => {
      if (settled) return
      settled = true
      resolve(result)
    }
    const req = http.get(
      {
        hostname: '127.0.0.1',
        port,
        path: `/health?challenge=${challenge}`,
        headers: { Accept: 'application/json', Connection: 'close' },
        timeout: 1_500
      },
      (res) => {
        const chunks: Buffer[] = []
        let total = 0
        res.on('data', (chunk: Buffer | string) => {
          const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
          total += bytes.byteLength
          if (total > MAX_HEALTH_BYTES) {
            res.destroy()
            finish(false)
            return
          }
          chunks.push(bytes)
        })
        res.once('error', () => finish(false))
        res.once('end', () => {
          if (res.statusCode !== 200) {
            finish(false)
            return
          }
          try {
            const document = JSON.parse(Buffer.concat(chunks).toString('utf8')) as EngineHealthDocument
            finish(validateEngineHealth(document, expectedPid, bootToken, challenge))
          } catch {
            finish(false)
          }
        })
      }
    )
    req.once('timeout', () => {
      req.destroy()
      finish(false)
    })
    req.once('error', () => finish(false))
  })
}

export async function waitForEngineReady(
  port: number,
  expectedPid: number,
  bootToken: string,
  timeoutMs = DEFAULT_READY_TIMEOUT_MS
): Promise<void> {
  if (!Number.isInteger(port) || port < 1024 || port > 65535) {
    throw new Error('invalid engine port')
  }
  if (!Number.isSafeInteger(expectedPid) || expectedPid <= 0) {
    throw new Error('engine process did not expose a valid PID')
  }
  if (!exactHex(bootToken, 32)) throw new Error('invalid engine boot token')
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    const challenge = randomBytes(32).toString('hex')
    if (await probeEngine(port, expectedPid, bootToken, challenge)) return
    await new Promise<void>((resolve) => setTimeout(resolve, 150))
  }
  throw new Error(`engine did not prove readiness within ${timeoutMs}ms`)
}
