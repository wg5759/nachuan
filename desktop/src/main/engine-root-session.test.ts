import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'

import { EngineRootSessionAuthority } from './engine-root-session'

const token = (value: string): string => value.repeat(64)

function ready(
  authority: EngineRootSessionAuthority,
  value: string,
  port: number,
  pid: number
) {
  const attempt = authority.begin(token(value))
  authority.assignPort(attempt, port)
  authority.bindChild(attempt, pid)
  return { attempt, session: authority.publish(attempt, pid) }
}

describe('EngineRootSessionAuthority', () => {
  it('publishes only after an exact port and child binding', () => {
    const authority = new EngineRootSessionAuthority()
    const attempt = authority.begin(token('a'))
    expect(authority.session()).toBeNull()
    expect(() => authority.publish(attempt, 41)).toThrow(/not ready|child/i)

    authority.assignPort(attempt, 43111)
    authority.bindChild(attempt, 41)
    const session = authority.publish(attempt, 41)

    expect(session).toEqual({ generation: 1, pid: 41, port: 43111, bootToken: token('a') })
    expect(Object.isFrozen(session)).toBe(true)
    expect(authority.session()).toBe(session)
  })

  it('rejects a delayed readiness result from an invalidated attempt', () => {
    const authority = new EngineRootSessionAuthority()
    const stale = authority.begin(token('a'))
    authority.assignPort(stale, 43111)
    authority.bindChild(stale, 41)
    expect(authority.invalidate(stale, 41)).toBe(true)

    const current = authority.begin(token('b'))
    authority.assignPort(current, 43112)
    authority.bindChild(current, 42)

    expect(() => authority.publish(stale, 41)).toThrow(/stale/i)
    expect(authority.publish(current, 42).generation).toBeGreaterThan(stale.generation)
  })

  it('does not let an old child exit clear a newer published session', () => {
    const authority = new EngineRootSessionAuthority()
    const old = ready(authority, 'a', 43111, 41)
    expect(authority.invalidate(old.attempt, 41)).toBe(true)
    const current = ready(authority, 'b', 43112, 42)

    expect(authority.invalidate(old.attempt, 41)).toBe(false)
    expect(authority.session()).toBe(current.session)
  })

  it('fences port ABA by generation and token rather than port alone', () => {
    const authority = new EngineRootSessionAuthority()
    const old = ready(authority, 'a', 43111, 41)
    authority.invalidate(old.attempt, 41)
    const current = ready(authority, 'b', 43111, 42)

    expect(current.session.port).toBe(old.session.port)
    expect(current.session.generation).not.toBe(old.session.generation)
    expect(authority.invalidate(old.attempt, 41)).toBe(false)
    expect(authority.session()).toBe(current.session)
  })

  it('global shutdown invalidates both candidates and published sessions', () => {
    const authority = new EngineRootSessionAuthority()
    const current = ready(authority, 'c', 43111, 43)
    authority.invalidateAll()

    expect(authority.session()).toBeNull()
    expect(authority.owns(current.attempt, 43)).toBe(false)
  })

  it('never includes a boot token in validation failures', () => {
    const authority = new EngineRootSessionAuthority()
    const secret = token('d')
    const attempt = authority.begin(secret)
    let message = ''
    try {
      authority.assignPort(attempt, 80)
    } catch (error) {
      message = error instanceof Error ? error.message : String(error)
    }
    expect(message).not.toContain(secret)
  })
})

describe('Desktop engine session integration', () => {
  const source = readFileSync(new URL('./index.ts', import.meta.url), 'utf8')

  it('keeps candidate ports private until readiness publishes the exact session', () => {
    const begin = source.indexOf('engineRootSessions.begin(bootToken)')
    const select = source.indexOf('await selectLoopbackPort()', begin)
    const assign = source.indexOf('engineRootSessions.assignPort(attempt, candidatePort)', select)
    const bind = source.indexOf('engineRootSessions.bindChild(attempt, child.pid)', assign)
    const readiness = source.indexOf('waitForEngineReady(candidatePort, child.pid, bootToken)', bind)
    const publish = source.indexOf('engineRootSessions.publish(attempt, child.pid)', readiness)
    const exposePort = source.indexOf('enginePort = published.port', publish)

    expect([begin, select, assign, bind, readiness, publish, exposePort].every((value) => value >= 0)).toBe(
      true
    )
    expect(begin).toBeLessThan(select)
    expect(select).toBeLessThan(assign)
    expect(assign).toBeLessThan(bind)
    expect(bind).toBeLessThan(readiness)
    expect(readiness).toBeLessThan(publish)
    expect(publish).toBeLessThan(exposePort)
    expect(source).not.toContain('enginePort = await selectLoopbackPort()')
  })

  it('binds the child environment to the same boot generation and listener port', () => {
    expect(source).toContain('NACHUAN_ENGINE_GENERATION: String(attempt.generation)')
    expect(source).toContain('NACHUAN_ENGINE_PORT: String(candidatePort)')
    expect(source).toContain("GATEWAY_PORT: String(candidatePort)")
  })

  it('invalidates the session on child exit, failed readiness, and application shutdown', () => {
    expect(source).toContain('invalidateEngineAttempt(attempt, pid)')
    expect(source).toContain('invalidateEngineAttempt(attempt, pid && pid > 0 ? pid : undefined)')
    expect(source).toContain('engineRootSessions.invalidateAll()')
    expect(source).toContain('enginePort = 0')
  })

  it('constructs the root client only from the atomic current-session supplier', () => {
    expect(source).toContain('const installationRootClient = new InstallationRootClient({')
    expect(source).toContain('session: () => engineRootSessions.session()')
    expect(source).not.toContain('session: () => ({ generation:')
  })
})
