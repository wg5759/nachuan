import type { InstallationRootEngineSession } from './installation-root-client'

const LOWER_HEX_64 = /^[0-9a-f]{64}$/
const ZERO_DIGEST = '0'.repeat(64)

export type EngineBootAttempt = Readonly<{
  generation: number
  bootToken: string
}>

type MutableAttempt = {
  generation: number
  bootToken: string
  port: number | null
  pid: number | null
}

function validGeneration(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) >= 1
}

function validPort(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) >= 1024 && Number(value) <= 65535
}

function validPid(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) >= 1
}

function validBootToken(value: unknown): value is string {
  return typeof value === 'string' && LOWER_HEX_64.test(value) && value !== ZERO_DIGEST
}

/**
 * Owns the Desktop -> Engine boot-session capability.
 *
 * A port or boot token is not a usable session until the exact child PID has
 * passed the HMAC readiness proof.  Every invalidation advances a monotonic
 * generation, so late events from an older child cannot clear or publish a
 * replacement session even when the operating system reuses the same port.
 */
export class EngineRootSessionAuthority {
  private generation = 0
  private attempt: MutableAttempt | null = null
  private published: InstallationRootEngineSession | null = null

  private nextGeneration(): number {
    if (this.generation >= Number.MAX_SAFE_INTEGER) {
      throw new Error('Engine boot-session generation is exhausted')
    }
    this.generation += 1
    return this.generation
  }

  begin(bootToken: string): EngineBootAttempt {
    if (!validBootToken(bootToken)) {
      throw new Error('Engine boot-session token is invalid')
    }
    const generation = this.nextGeneration()
    this.published = null
    this.attempt = { generation, bootToken, port: null, pid: null }
    return Object.freeze({ generation, bootToken })
  }

  private ownsAttempt(candidate: EngineBootAttempt): boolean {
    return (
      validGeneration(candidate?.generation) &&
      validBootToken(candidate?.bootToken) &&
      this.attempt !== null &&
      this.attempt.generation === candidate.generation &&
      this.attempt.bootToken === candidate.bootToken
    )
  }

  private requireAttempt(candidate: EngineBootAttempt): MutableAttempt {
    if (!this.ownsAttempt(candidate) || this.attempt === null) {
      throw new Error('Engine boot attempt is stale')
    }
    return this.attempt
  }

  assignPort(candidate: EngineBootAttempt, port: number): void {
    const current = this.requireAttempt(candidate)
    if (!validPort(port) || current.port !== null) {
      throw new Error('Engine boot attempt changed before port assignment')
    }
    current.port = port
  }

  bindChild(candidate: EngineBootAttempt, pid: number): void {
    const current = this.requireAttempt(candidate)
    if (
      !validPid(pid) ||
      current.port === null ||
      current.pid !== null
    ) {
      throw new Error('Engine boot attempt changed before child binding')
    }
    current.pid = pid
  }

  assertCurrent(candidate: EngineBootAttempt, pid?: number): void {
    const current = this.requireAttempt(candidate)
    if (pid !== undefined && current.pid !== pid) {
      throw new Error('Engine boot child is stale')
    }
  }

  publish(candidate: EngineBootAttempt, pid: number): InstallationRootEngineSession {
    this.assertCurrent(candidate, pid)
    const current = this.attempt
    if (current === null) throw new Error('Engine boot attempt is stale')
    if (current.port === null || current.pid === null || current.pid !== pid) {
      throw new Error('Engine boot attempt is not ready to publish')
    }
    const published = Object.freeze({
      generation: current.generation,
      pid: current.pid,
      port: current.port,
      bootToken: current.bootToken
    })
    this.published = published
    this.attempt = null
    return published
  }

  ownsPublished(candidate: EngineBootAttempt, pid: number): boolean {
    return (
      this.published !== null &&
      this.published.generation === candidate.generation &&
      this.published.bootToken === candidate.bootToken &&
      this.published.pid === pid
    )
  }

  owns(candidate: EngineBootAttempt, pid?: number): boolean {
    if (this.ownsAttempt(candidate)) {
      return pid === undefined || this.attempt?.pid === pid
    }
    return pid !== undefined && this.ownsPublished(candidate, pid)
  }

  invalidate(candidate: EngineBootAttempt, pid?: number): boolean {
    if (!this.owns(candidate, pid)) return false
    this.nextGeneration()
    this.attempt = null
    this.published = null
    return true
  }

  invalidateAll(): void {
    this.nextGeneration()
    this.attempt = null
    this.published = null
  }

  session(): InstallationRootEngineSession | null {
    return this.published
  }
}
