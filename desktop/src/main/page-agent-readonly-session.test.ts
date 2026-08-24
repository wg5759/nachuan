import { describe, expect, it } from 'vitest'

import { PageAgentReadonlySessionPolicy } from './page-agent-readonly-session'

const EMPTY_PAYLOAD_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
const SCROLL_PAYLOAD_SHA256 = 'b'.repeat(64)
const DEFAULT_NAVIGATION_EPOCHS = new WeakMap<
  PageAgentReadonlySessionPolicy,
  Map<string, number>
>()

function defaultNavigationEpoch(
  policy: PageAgentReadonlySessionPolicy,
  sessionId: string,
  webContentsId = 7
): number {
  let epochs = DEFAULT_NAVIGATION_EPOCHS.get(policy)
  if (!epochs) {
    epochs = new Map()
    DEFAULT_NAVIGATION_EPOCHS.set(policy, epochs)
  }
  const existing = epochs.get(sessionId)
  if (existing !== undefined) return existing
  policy.bindWebContents(sessionId, webContentsId)
  const epoch = policy.beginNavigation(sessionId, webContentsId)
  epochs.set(sessionId, epoch)
  return epoch
}

function mintDefaultElementHandle(
  policy: PageAgentReadonlySessionPolicy,
  sessionId: string,
  webContentsId = 7
): string {
  return policy.mintElementHandle({
    sessionId,
    webContentsId,
    origin: 'https://example.test',
    navigationEpoch: defaultNavigationEpoch(policy, sessionId, webContentsId),
    domSha256: 'a'.repeat(64),
    elementIdentitySha256: 'd'.repeat(64)
  })
}

describe('Page Agent read-only isolated session policy', () => {
  it('creates unique in-memory sessions with an exact locked-down WebPreferences policy', () => {
    const uuids = [
      '11111111-1111-4111-8111-111111111111',
      '22222222-2222-4222-8222-222222222222'
    ]
    const policy = new PageAgentReadonlySessionPolicy({
      randomUUID: () => {
        const value = uuids.shift()
        if (!value) throw new Error('test UUIDs exhausted')
        return value
      }
    })

    const first = policy.createSession()
    const second = policy.createSession()

    expect(first).toEqual({
      sessionId: '11111111-1111-4111-8111-111111111111',
      partition: 'nachuan-page-agent-readonly-11111111-1111-4111-8111-111111111111',
      webPreferences: {
        sandbox: true,
        contextIsolation: true,
        webSecurity: true,
        allowRunningInsecureContent: false,
        disableDialogs: true,
        navigateOnDragDrop: false,
        spellcheck: false,
        nodeIntegration: false,
        webviewTag: false,
        devTools: false
      }
    })
    expect(second.sessionId).not.toBe(first.sessionId)
    expect(second.partition).not.toBe(first.partition)
    expect(first.partition.startsWith('persist:')).toBe(false)
    expect(second.partition.startsWith('persist:')).toBe(false)
    expect('preload' in first.webPreferences).toBe(false)
  })

  it('never reuses a closed session identity and hard-bounds live and lifetime sessions', () => {
    const reusedUuid = '11111111-1111-4111-8111-111111111111'
    const replacementUuid = '22222222-2222-4222-8222-222222222222'
    const uuids = [reusedUuid, reusedUuid, replacementUuid]
    const policy = new PageAgentReadonlySessionPolicy({
      maxLiveSessions: 1,
      maxSessionCreations: 2,
      randomUUID: () => {
        const value = uuids.shift()
        if (!value) throw new Error('randomUUID must not run after lifetime exhaustion')
        return value
      }
    })

    const first = policy.createSession()
    expect(() => policy.createSession()).toThrow(/live session capacity/i)
    expect(policy.closeSession(first.sessionId)).toBe(true)
    expect(() => policy.createSession()).toThrow(/not unique/i)

    const replacement = policy.createSession()
    expect(replacement.sessionId).toBe(replacementUuid)
    expect(policy.closeSession(replacement.sessionId)).toBe(true)
    expect(() => policy.createSession()).toThrow(/lifetime session capacity/i)

    expect(() => new PageAgentReadonlySessionPolicy({ maxLiveSessions: 5_000 })).toThrow(
      /hard maximum/i
    )
    expect(() => new PageAgentReadonlySessionPolicy({ maxSessionCreations: 5_000 })).toThrow(
      /hard maximum/i
    )
  })

  it('binds each open session to one real positive WebContents identity exactly once', () => {
    const policy = new PageAgentReadonlySessionPolicy({
      randomUUID: () => '11111111-1111-4111-8111-111111111111'
    })
    const { sessionId } = policy.createSession()

    expect(() => policy.bindWebContents(sessionId, 7)).not.toThrow()
    expect(() => policy.bindWebContents(sessionId, 7)).toThrow(/already bound/i)
    expect(() => policy.bindWebContents(sessionId, 8)).toThrow(/already bound/i)

    const unbound = new PageAgentReadonlySessionPolicy({
      randomUUID: () => '22222222-2222-4222-8222-222222222222'
    })
    const second = unbound.createSession()
    for (const invalidId of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, new Number(9)]) {
      expect(() => unbound.bindWebContents(second.sessionId, invalidId)).toThrow(
        /positive safe integer/i
      )
    }
    expect(() => unbound.bindWebContents(second.sessionId, 9)).not.toThrow()
  })

  it('never binds one WebContents identity to another session, even after close', () => {
    const uuids = [
      '11111111-1111-4111-8111-111111111111',
      '22222222-2222-4222-8222-222222222222'
    ]
    const policy = new PageAgentReadonlySessionPolicy({
      randomUUID: () => {
        const value = uuids.shift()
        if (!value) throw new Error('test UUIDs exhausted')
        return value
      }
    })
    const first = policy.createSession()
    const second = policy.createSession()

    policy.bindWebContents(first.sessionId, 7)
    expect(() => policy.bindWebContents(second.sessionId, 7)).toThrow(/WebContents.*used/i)
    expect(policy.closeSession(first.sessionId)).toBe(true)
    expect(() => policy.bindWebContents(second.sessionId, 7)).toThrow(/WebContents.*used/i)
    expect(() => policy.bindWebContents(second.sessionId, 8)).not.toThrow()
  })

  it('mints DOM handles only for the bound WebContents at the Main-owned navigation epoch', () => {
    let randomByte = 1
    const policy = new PageAgentReadonlySessionPolicy({
      randomBytes: (size) => Buffer.alloc(size, randomByte++),
      randomUUID: () => '11111111-1111-4111-8111-111111111111'
    })
    const { sessionId } = policy.createSession()
    policy.bindWebContents(sessionId, 7)
    const navigationEpoch = policy.beginNavigation(sessionId, 7)
    const request = {
      sessionId,
      webContentsId: 7,
      origin: 'https://example.test',
      navigationEpoch,
      domSha256: 'a'.repeat(64),
      elementIdentitySha256: 'd'.repeat(64)
    }

    expect(navigationEpoch).toBe(1)
    expect(() => policy.mintElementHandle(request)).not.toThrow()
    expect(() => policy.mintElementHandle({ ...request, webContentsId: 8 })).toThrow(
      /bound WebContents/i
    )
    expect(() => policy.mintElementHandle({ ...request, navigationEpoch: 2 })).toThrow(
      /current navigation epoch/i
    )

    expect(policy.beginNavigation(sessionId, 7)).toBe(2)
    expect(() => policy.mintElementHandle(request)).toThrow(/current navigation epoch/i)
  })

  it('rejects a non-primitive UUID without invoking implicit string conversion', () => {
    let toStringCalls = 0
    const disguisedUuid = {
      toString() {
        toStringCalls += 1
        return '11111111-1111-4111-8111-111111111111'
      }
    }
    const policy = new PageAgentReadonlySessionPolicy({
      randomUUID: () => disguisedUuid as unknown as string
    })

    expect(() => policy.createSession()).toThrow(/identity is invalid/i)
    expect(toStringCalls).toBe(0)
  })

  it('accepts only inspect and scroll actions', () => {
    const policy = new PageAgentReadonlySessionPolicy()

    expect(policy.assertAction('inspect')).toBe('inspect')
    expect(policy.assertAction('scroll')).toBe('scroll')

    for (const action of ['click', 'type', 'select', 'eval', 'executeJavaScript', '', null, {}]) {
      expect(() => policy.assertAction(action)).toThrow(/read-only action/i)
    }
  })

  it('binds a canonical payload digest for both inspect and scroll actions', () => {
    let randomByte = 1
    const policy = new PageAgentReadonlySessionPolicy({
      now: () => 1_000,
      randomBytes: (size) => Buffer.alloc(size, randomByte++),
      randomUUID: () => '11111111-1111-4111-8111-111111111111'
    })
    const { sessionId } = policy.createSession()
    const base = {
      sessionId,
      webContentsId: 7,
      origin: 'https://example.test',
      navigationEpoch: defaultNavigationEpoch(policy, sessionId),
      domSha256: 'a'.repeat(64),
      elementHandle: mintDefaultElementHandle(policy, sessionId)
    }

    expect(() =>
      policy.issueCapability(
        { ...base, action: 'inspect', valueSha256: EMPTY_PAYLOAD_SHA256 },
        500
      )
    ).not.toThrow()
    expect(() =>
      policy.issueCapability(
        { ...base, action: 'inspect', valueSha256: SCROLL_PAYLOAD_SHA256 },
        500
      )
    ).toThrow(/inspect.*empty payload/i)
    expect(() =>
      policy.issueCapability(
        { ...base, action: 'scroll', valueSha256: EMPTY_PAYLOAD_SHA256 },
        500
      )
    ).toThrow(/scroll.*payload/i)
    expect(() =>
      policy.issueCapability(
        { ...base, action: 'scroll', valueSha256: SCROLL_PAYLOAD_SHA256 },
        500
      )
    ).not.toThrow()
  })

  it('accepts only policy-minted opaque handles bound to the exact DOM snapshot', () => {
    let randomByte = 1
    const policy = new PageAgentReadonlySessionPolicy({
      now: () => 1_000,
      randomBytes: (size) => Buffer.alloc(size, randomByte++),
      randomUUID: () => '11111111-1111-4111-8111-111111111111'
    })
    const { sessionId } = policy.createSession()
    const snapshot = {
      sessionId,
      webContentsId: 7,
      origin: 'https://example.test',
      navigationEpoch: defaultNavigationEpoch(policy, sessionId),
      domSha256: 'a'.repeat(64)
    }
    const elementHandle = policy.mintElementHandle({
      ...snapshot,
      elementIdentitySha256: 'd'.repeat(64)
    })
    const scope = {
      ...snapshot,
      elementHandle,
      action: 'inspect' as const,
      valueSha256: EMPTY_PAYLOAD_SHA256
    }

    expect(elementHandle).toMatch(/^el_[A-Za-z0-9_-]{43}$/)
    expect(() => policy.issueCapability(scope, 500)).not.toThrow()
    for (const forged of [
      '#x',
      '//button',
      'document.body',
      'button[name="x"]',
      'javascript:alert(1)',
      `el_${'z'.repeat(43)}`
    ]) {
      expect(() => policy.issueCapability({ ...scope, elementHandle: forged }, 500)).toThrow(
        /opaque element handle|not registered/i
      )
    }
    expect(() => policy.issueCapability({ ...scope, navigationEpoch: 4 }, 500)).toThrow(
      /snapshot (?:binding|authority)/i
    )
  })

  it('bounds handles per session and revokes stale snapshot handles and capabilities', () => {
    let randomByte = 1
    const policy = new PageAgentReadonlySessionPolicy({
      maxElementHandles: 4,
      maxElementHandlesPerSession: 2,
      now: () => 1_000,
      randomBytes: (size) => Buffer.alloc(size, randomByte++),
      randomUUID: () => '11111111-1111-4111-8111-111111111111'
    })
    const { sessionId } = policy.createSession()
    const firstNavigationEpoch = defaultNavigationEpoch(policy, sessionId)
    const mintRequest = (navigationEpoch: number, domSha256: string, identity: string) => ({
      sessionId,
      webContentsId: 7,
      origin: 'https://example.test',
      navigationEpoch,
      domSha256,
      elementIdentitySha256: identity
    })
    const firstRequest = mintRequest(firstNavigationEpoch, 'a'.repeat(64), 'd'.repeat(64))
    const firstHandle = policy.mintElementHandle(firstRequest)
    policy.mintElementHandle(mintRequest(firstNavigationEpoch, 'a'.repeat(64), 'e'.repeat(64)))
    expect(() =>
      policy.mintElementHandle(mintRequest(firstNavigationEpoch, 'a'.repeat(64), 'f'.repeat(64)))
    ).toThrow(/per-session.*capacity/i)
    const oldScope = {
      sessionId,
      webContentsId: 7,
      origin: 'https://example.test',
      navigationEpoch: defaultNavigationEpoch(policy, sessionId),
      domSha256: 'a'.repeat(64),
      elementHandle: firstHandle,
      action: 'inspect' as const,
      valueSha256: EMPTY_PAYLOAD_SHA256
    }
    const oldCapability = policy.issueCapability(oldScope, 500)

    const secondNavigationEpoch = policy.beginNavigation(sessionId, 7)
    const currentRequest = mintRequest(secondNavigationEpoch, 'b'.repeat(64), 'f'.repeat(64))
    const currentHandle = policy.mintElementHandle(currentRequest)
    expect(
      policy.consumeCapability(oldCapability.token, {
        ...oldScope,
        expiresAtMs: oldCapability.expiresAtMs
      })
    ).toBe(false)
    expect(() => policy.issueCapability(oldScope, 500)).toThrow(/not registered|current snapshot/i)
    expect(() =>
      policy.issueCapability(
        {
          sessionId,
          webContentsId: 7,
          origin: 'https://example.test',
          navigationEpoch: secondNavigationEpoch,
          domSha256: 'b'.repeat(64),
          elementHandle: currentHandle,
          action: 'inspect',
          valueSha256: EMPTY_PAYLOAD_SHA256
        },
        500
      )
    ).not.toThrow()
    expect(() => policy.mintElementHandle(firstRequest)).toThrow(/current navigation epoch/i)
    expect(() =>
      policy.mintElementHandle(mintRequest(secondNavigationEpoch, 'c'.repeat(64), 'f'.repeat(64)))
    ).toThrow(/snapshot fork/i)
    expect(
      () => new PageAgentReadonlySessionPolicy({ maxElementHandlesPerSession: 5_000 })
    ).toThrow(/hard maximum/i)
  })

  it('consumes an opaque capability exactly once for its complete binding', () => {
    const policy = new PageAgentReadonlySessionPolicy({
      now: () => 1_000,
      randomBytes: (size) => Buffer.alloc(size, 1),
      randomUUID: () => '11111111-1111-4111-8111-111111111111'
    })
    const { sessionId } = policy.createSession()
    const scope = {
      sessionId,
      webContentsId: 7,
      origin: 'https://example.test',
      navigationEpoch: defaultNavigationEpoch(policy, sessionId),
      domSha256: 'a'.repeat(64),
      elementHandle: mintDefaultElementHandle(policy, sessionId),
      action: 'inspect' as const,
      valueSha256: EMPTY_PAYLOAD_SHA256
    }

    const issued = policy.issueCapability(scope, 500)

    expect(issued).toEqual({
      token: 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE',
      expiresAtMs: 1_500
    })
    expect(policy.consumeCapability(issued.token, { ...scope, expiresAtMs: 1_500 })).toBe(true)
    expect(policy.consumeCapability(issued.token, { ...scope, expiresAtMs: 1_500 })).toBe(false)
  })

  it('turns one exact capability into one Main-only execution lease', () => {
    const policy = new PageAgentReadonlySessionPolicy({
      now: () => 1_000,
      randomBytes: (size) => Buffer.alloc(size, 1),
      randomUUID: () => '11111111-1111-4111-8111-111111111111'
    })
    const { sessionId } = policy.createSession()
    const scope = {
      sessionId,
      webContentsId: 7,
      origin: 'https://example.test',
      navigationEpoch: defaultNavigationEpoch(policy, sessionId),
      domSha256: 'a'.repeat(64),
      elementHandle: mintDefaultElementHandle(policy, sessionId),
      action: 'inspect' as const,
      valueSha256: EMPTY_PAYLOAD_SHA256
    }
    const issued = policy.issueCapability(scope, 500)
    const binding = { ...scope, expiresAtMs: issued.expiresAtMs }

    const lease = policy.beginExecution(issued.token, binding)

    expect(lease).not.toBeNull()
    expect(Object.keys(lease!).sort()).toEqual(['assertCurrent', 'close', 'signal'])
    expect(lease!.signal.aborted).toBe(false)
    expect(lease!.assertCurrent()).toBe(true)
    expect(policy.beginExecution(issued.token, binding)).toBeNull()
    expect(lease!.close()).toBe(true)
    expect(lease!.signal.aborted).toBe(true)
    expect(lease!.assertCurrent()).toBe(false)
    expect(lease!.close()).toBe(false)
  })

  it('never consults caller-shadowable AbortSignal properties for execution authority', () => {
    const policy = new PageAgentReadonlySessionPolicy({
      now: () => 1_000,
      randomBytes: (size) => Buffer.alloc(size, 1),
      randomUUID: () => '11111111-1111-4111-8111-111111111111'
    })
    const { sessionId } = policy.createSession()
    const scope = {
      sessionId,
      webContentsId: 7,
      origin: 'https://example.test',
      navigationEpoch: defaultNavigationEpoch(policy, sessionId),
      domSha256: 'a'.repeat(64),
      elementHandle: mintDefaultElementHandle(policy, sessionId),
      action: 'inspect' as const,
      valueSha256: EMPTY_PAYLOAD_SHA256
    }
    const issued = policy.issueCapability(scope, 500)
    const lease = policy.beginExecution(issued.token, {
      ...scope,
      expiresAtMs: issued.expiresAtMs
    })!
    let getterCalls = 0
    let nestedCloseResult: boolean | undefined
    Object.defineProperty(lease.signal, 'aborted', {
      configurable: true,
      get() {
        getterCalls += 1
        nestedCloseResult = lease.close()
        return false
      }
    })

    expect(lease.assertCurrent()).toBe(true)
    expect(getterCalls).toBe(0)
    expect(nestedCloseResult).toBeUndefined()
    expect(lease.close()).toBe(true)
    expect(lease.assertCurrent()).toBe(false)
  })

  it('guards assertCurrent clock callbacks against synchronous lease mutation', () => {
    let lease!: NonNullable<ReturnType<PageAgentReadonlySessionPolicy['beginExecution']>>
    let reenterNow = false
    let nestedCloseResult: boolean | undefined
    const policy = new PageAgentReadonlySessionPolicy({
      now: () => {
        if (reenterNow) {
          reenterNow = false
          nestedCloseResult = lease.close()
        }
        return 1_000
      },
      randomBytes: (size) => Buffer.alloc(size, 1),
      randomUUID: () => '11111111-1111-4111-8111-111111111111'
    })
    const { sessionId } = policy.createSession()
    const scope = {
      sessionId,
      webContentsId: 7,
      origin: 'https://example.test',
      navigationEpoch: defaultNavigationEpoch(policy, sessionId),
      domSha256: 'a'.repeat(64),
      elementHandle: mintDefaultElementHandle(policy, sessionId),
      action: 'inspect' as const,
      valueSha256: EMPTY_PAYLOAD_SHA256
    }
    const issued = policy.issueCapability(scope, 500)
    lease = policy.beginExecution(issued.token, { ...scope, expiresAtMs: issued.expiresAtMs })!

    reenterNow = true
    expect(lease.assertCurrent()).toBe(true)
    expect(nestedCloseResult).toBe(false)
    expect(lease.close()).toBe(true)
  })

  it('aborts active execution and revokes every old authority before navigation returns', () => {
    let randomByte = 1
    const policy = new PageAgentReadonlySessionPolicy({
      now: () => 1_000,
      randomBytes: (size) => Buffer.alloc(size, randomByte++),
      randomUUID: () => '11111111-1111-4111-8111-111111111111'
    })
    const { sessionId } = policy.createSession()
    const scope = {
      sessionId,
      webContentsId: 7,
      origin: 'https://example.test',
      navigationEpoch: defaultNavigationEpoch(policy, sessionId),
      domSha256: 'a'.repeat(64),
      elementHandle: mintDefaultElementHandle(policy, sessionId),
      action: 'inspect' as const,
      valueSha256: EMPTY_PAYLOAD_SHA256
    }
    const activeCapability = policy.issueCapability(scope, 500)
    const pendingCapability = policy.issueCapability(scope, 500)
    const activeBinding = { ...scope, expiresAtMs: activeCapability.expiresAtMs }
    const pendingBinding = { ...scope, expiresAtMs: pendingCapability.expiresAtMs }
    const lease = policy.beginExecution(activeCapability.token, activeBinding)!
    let abortObserved = false
    let currentInsideAbort: boolean | undefined
    let nestedNavigationError: unknown
    lease.signal.addEventListener(
      'abort',
      () => {
        abortObserved = true
        currentInsideAbort = lease.assertCurrent()
        try {
          policy.beginNavigation(sessionId, 7)
        } catch (error) {
          nestedNavigationError = error
        }
      },
      { once: true }
    )

    const nextEpoch = policy.beginNavigation(sessionId, 7)

    expect(nextEpoch).toBe(2)
    expect(abortObserved).toBe(true)
    expect(currentInsideAbort).toBe(false)
    expect(nestedNavigationError).toBeInstanceOf(Error)
    expect(String(nestedNavigationError)).toMatch(/re-entrant mutation/i)
    expect(lease.signal.aborted).toBe(true)
    expect(lease.assertCurrent()).toBe(false)
    expect(policy.consumeCapability(pendingCapability.token, pendingBinding)).toBe(false)
    expect(() => policy.issueCapability(scope, 500)).toThrow(/not registered|current snapshot/i)
  })

  it('aborts execution on session close and keeps a late Promise permanently stale', async () => {
    const policy = new PageAgentReadonlySessionPolicy({
      now: () => 1_000,
      randomBytes: (size) => Buffer.alloc(size, 1),
      randomUUID: () => '11111111-1111-4111-8111-111111111111'
    })
    const { sessionId } = policy.createSession()
    const scope = {
      sessionId,
      webContentsId: 7,
      origin: 'https://example.test',
      navigationEpoch: defaultNavigationEpoch(policy, sessionId),
      domSha256: 'a'.repeat(64),
      elementHandle: mintDefaultElementHandle(policy, sessionId),
      action: 'inspect' as const,
      valueSha256: EMPTY_PAYLOAD_SHA256
    }
    const issued = policy.issueCapability(scope, 500)
    const lease = policy.beginExecution(issued.token, {
      ...scope,
      expiresAtMs: issued.expiresAtMs
    })!
    let finishAction!: () => void
    const actionFinished = new Promise<void>((resolve) => {
      finishAction = resolve
    }).then(() => lease.assertCurrent())
    let abortObserved = false
    lease.signal.addEventListener('abort', () => {
      abortObserved = true
    })

    expect(policy.closeSession(sessionId)).toBe(true)
    expect(abortObserved).toBe(true)
    expect(lease.signal.aborted).toBe(true)
    expect(lease.assertCurrent()).toBe(false)
    finishAction()
    await expect(actionFinished).resolves.toBe(false)
    expect(lease.close()).toBe(false)
    expect(() => policy.beginNavigation(sessionId, 7)).toThrow(/not open/i)
  })

  it('hard-bounds active execution leases and burns a token rejected at capacity', () => {
    let randomByte = 1
    const policy = new PageAgentReadonlySessionPolicy({
      maxExecutionLeases: 1,
      now: () => 1_000,
      randomBytes: (size) => Buffer.alloc(size, randomByte++),
      randomUUID: () => '11111111-1111-4111-8111-111111111111'
    })
    const { sessionId } = policy.createSession()
    const scope = {
      sessionId,
      webContentsId: 7,
      origin: 'https://example.test',
      navigationEpoch: defaultNavigationEpoch(policy, sessionId),
      domSha256: 'a'.repeat(64),
      elementHandle: mintDefaultElementHandle(policy, sessionId),
      action: 'inspect' as const,
      valueSha256: EMPTY_PAYLOAD_SHA256
    }
    const issue = () => {
      const capability = policy.issueCapability(scope, 500)
      return {
        capability,
        binding: { ...scope, expiresAtMs: capability.expiresAtMs }
      }
    }
    const first = issue()
    const rejected = issue()
    const firstLease = policy.beginExecution(first.capability.token, first.binding)!

    expect(policy.beginExecution(rejected.capability.token, rejected.binding)).toBeNull()
    expect(firstLease.close()).toBe(true)
    expect(policy.beginExecution(rejected.capability.token, rejected.binding)).toBeNull()

    const replacement = issue()
    expect(policy.beginExecution(replacement.capability.token, replacement.binding)).not.toBeNull()
    expect(
      () => new PageAgentReadonlySessionPolicy({ maxExecutionLeases: 4_097 })
    ).toThrow(/hard maximum/i)
    expect(
      () =>
        new PageAgentReadonlySessionPolicy({
          maxExecutionLeases: new Number(1) as unknown as number
        })
    ).toThrow(/positive safe integer/i)
  })

  it('expires an active execution at its exact deadline and reclaims lease capacity', () => {
    let now = 1_000
    let randomByte = 1
    const policy = new PageAgentReadonlySessionPolicy({
      maxExecutionLeases: 1,
      now: () => now,
      randomBytes: (size) => Buffer.alloc(size, randomByte++),
      randomUUID: () => '11111111-1111-4111-8111-111111111111'
    })
    const { sessionId } = policy.createSession()
    const scope = {
      sessionId,
      webContentsId: 7,
      origin: 'https://example.test',
      navigationEpoch: defaultNavigationEpoch(policy, sessionId),
      domSha256: 'a'.repeat(64),
      elementHandle: mintDefaultElementHandle(policy, sessionId),
      action: 'inspect' as const,
      valueSha256: EMPTY_PAYLOAD_SHA256
    }
    const first = policy.issueCapability(scope, 500)
    const firstLease = policy.beginExecution(first.token, {
      ...scope,
      expiresAtMs: first.expiresAtMs
    })!

    now = 1_500
    expect(firstLease.assertCurrent()).toBe(false)
    expect(firstLease.signal.aborted).toBe(true)
    expect(firstLease.close()).toBe(false)

    const replacement = policy.issueCapability(scope, 500)
    expect(
      policy.beginExecution(replacement.token, {
        ...scope,
        expiresAtMs: replacement.expiresAtMs
      })
    ).not.toBeNull()
  })

  it('retires and aborts active executions when the policy clock moves backwards', () => {
    let now = 1_000
    const policy = new PageAgentReadonlySessionPolicy({
      now: () => now,
      randomBytes: (size) => Buffer.alloc(size, 1),
      randomUUID: () => '11111111-1111-4111-8111-111111111111'
    })
    const { sessionId } = policy.createSession()
    const scope = {
      sessionId,
      webContentsId: 7,
      origin: 'https://example.test',
      navigationEpoch: defaultNavigationEpoch(policy, sessionId),
      domSha256: 'a'.repeat(64),
      elementHandle: mintDefaultElementHandle(policy, sessionId),
      action: 'inspect' as const,
      valueSha256: EMPTY_PAYLOAD_SHA256
    }
    const issued = policy.issueCapability(scope, 500)
    const lease = policy.beginExecution(issued.token, {
      ...scope,
      expiresAtMs: issued.expiresAtMs
    })!

    now = 999
    expect(lease.assertCurrent()).toBe(false)
    expect(lease.signal.aborted).toBe(true)
    expect(lease.close()).toBe(false)
  })

  it('aborts existing leases and burns the candidate token when beginExecution sees clock rollback', () => {
    let now = 1_000
    let randomByte = 1
    const policy = new PageAgentReadonlySessionPolicy({
      now: () => now,
      randomBytes: (size) => Buffer.alloc(size, randomByte++),
      randomUUID: () => '11111111-1111-4111-8111-111111111111'
    })
    const { sessionId } = policy.createSession()
    const scope = {
      sessionId,
      webContentsId: 7,
      origin: 'https://example.test',
      navigationEpoch: defaultNavigationEpoch(policy, sessionId),
      domSha256: 'a'.repeat(64),
      elementHandle: mintDefaultElementHandle(policy, sessionId),
      action: 'inspect' as const,
      valueSha256: EMPTY_PAYLOAD_SHA256
    }
    const active = policy.issueCapability(scope, 500)
    const candidate = policy.issueCapability(scope, 500)
    const activeLease = policy.beginExecution(active.token, {
      ...scope,
      expiresAtMs: active.expiresAtMs
    })!
    const candidateBinding = { ...scope, expiresAtMs: candidate.expiresAtMs }

    now = 999
    expect(policy.beginExecution(candidate.token, candidateBinding)).toBeNull()
    expect(activeLease.signal.aborted).toBe(true)
    expect(activeLease.assertCurrent()).toBe(false)
    expect(policy.beginExecution(candidate.token, candidateBinding)).toBeNull()
  })

  it('prunes expired executions before applying the active lease capacity bound', () => {
    let now = 1_000
    let randomByte = 1
    const policy = new PageAgentReadonlySessionPolicy({
      maxExecutionLeases: 1,
      now: () => now,
      randomBytes: (size) => Buffer.alloc(size, randomByte++),
      randomUUID: () => '11111111-1111-4111-8111-111111111111'
    })
    const { sessionId } = policy.createSession()
    const scope = {
      sessionId,
      webContentsId: 7,
      origin: 'https://example.test',
      navigationEpoch: defaultNavigationEpoch(policy, sessionId),
      domSha256: 'a'.repeat(64),
      elementHandle: mintDefaultElementHandle(policy, sessionId),
      action: 'inspect' as const,
      valueSha256: EMPTY_PAYLOAD_SHA256
    }
    const first = policy.issueCapability(scope, 500)
    const firstLease = policy.beginExecution(first.token, {
      ...scope,
      expiresAtMs: first.expiresAtMs
    })!

    now = 1_500
    const replacement = policy.issueCapability(scope, 500)
    const replacementLease = policy.beginExecution(replacement.token, {
      ...scope,
      expiresAtMs: replacement.expiresAtMs
    })

    expect(replacementLease).not.toBeNull()
    expect(firstLease.signal.aborted).toBe(true)
    expect(firstLease.assertCurrent()).toBe(false)
  })

  it('burns execution tokens for accessor and Proxy bindings without invoking their traps', () => {
    let randomByte = 1
    const policy = new PageAgentReadonlySessionPolicy({
      now: () => 1_000,
      randomBytes: (size) => Buffer.alloc(size, randomByte++),
      randomUUID: () => '11111111-1111-4111-8111-111111111111'
    })
    const { sessionId } = policy.createSession()
    const scope = {
      sessionId,
      webContentsId: 7,
      origin: 'https://example.test',
      navigationEpoch: defaultNavigationEpoch(policy, sessionId),
      domSha256: 'a'.repeat(64),
      elementHandle: mintDefaultElementHandle(policy, sessionId),
      action: 'inspect' as const,
      valueSha256: EMPTY_PAYLOAD_SHA256
    }
    const first = policy.issueCapability(scope, 500)
    const firstBinding = { ...scope, expiresAtMs: first.expiresAtMs }
    let getterCalls = 0
    Object.defineProperty(firstBinding, 'origin', {
      enumerable: true,
      get() {
        getterCalls += 1
        return 'https://example.test'
      }
    })

    expect(policy.beginExecution(first.token, firstBinding)).toBeNull()
    expect(getterCalls).toBe(0)
    expect(
      policy.beginExecution(first.token, { ...scope, expiresAtMs: first.expiresAtMs })
    ).toBeNull()

    const second = policy.issueCapability(scope, 500)
    let proxyTrapCalls = 0
    const proxyBinding = new Proxy(
      { ...scope, expiresAtMs: second.expiresAtMs },
      {
        getPrototypeOf(target) {
          proxyTrapCalls += 1
          return Reflect.getPrototypeOf(target)
        },
        ownKeys(target) {
          proxyTrapCalls += 1
          return Reflect.ownKeys(target)
        }
      }
    )
    expect(policy.beginExecution(second.token, proxyBinding)).toBeNull()
    expect(proxyTrapCalls).toBe(0)
  })

  it('rejects execution re-entry without burning the nested capability', () => {
    let nowCalls = 0
    let reenter = false
    let nestedResult: unknown
    let nestedToken = ''
    let nestedBinding: Record<string, unknown> = {}
    let randomByte = 1
    let policy!: PageAgentReadonlySessionPolicy
    policy = new PageAgentReadonlySessionPolicy({
      now: () => {
        nowCalls += 1
        if (reenter) {
          reenter = false
          nestedResult = policy.beginExecution(nestedToken, nestedBinding)
        }
        return 1_000
      },
      randomBytes: (size) => Buffer.alloc(size, randomByte++),
      randomUUID: () => '11111111-1111-4111-8111-111111111111'
    })
    const { sessionId } = policy.createSession()
    const scope = {
      sessionId,
      webContentsId: 7,
      origin: 'https://example.test',
      navigationEpoch: defaultNavigationEpoch(policy, sessionId),
      domSha256: 'a'.repeat(64),
      elementHandle: mintDefaultElementHandle(policy, sessionId),
      action: 'inspect' as const,
      valueSha256: EMPTY_PAYLOAD_SHA256
    }
    const outer = policy.issueCapability(scope, 500)
    const nested = policy.issueCapability(scope, 500)
    nestedToken = nested.token
    nestedBinding = { ...scope, expiresAtMs: nested.expiresAtMs }

    reenter = true
    expect(
      policy.beginExecution(outer.token, { ...scope, expiresAtMs: outer.expiresAtMs })
    ).not.toBeNull()
    expect(nowCalls).toBeGreaterThan(0)
    expect(nestedResult).toBeNull()
    expect(policy.beginExecution(nestedToken, nestedBinding)).not.toBeNull()
  })

  it('revokes every session capability on close and enforces a bounded live total', () => {
    let randomByte = 1
    const uuids = [
      '11111111-1111-4111-8111-111111111111',
      '22222222-2222-4222-8222-222222222222'
    ]
    const policy = new PageAgentReadonlySessionPolicy({
      maxCapabilities: 2,
      now: () => 1_000,
      randomBytes: (size) => Buffer.alloc(size, randomByte++),
      randomUUID: () => {
        const value = uuids.shift()
        if (!value) throw new Error('test UUIDs exhausted')
        return value
      }
    })
    const first = policy.createSession()
    const scope = (sessionId: string, handle: string, webContentsId = 7) => ({
      sessionId,
      webContentsId,
      origin: 'https://example.test',
      navigationEpoch: defaultNavigationEpoch(policy, sessionId, webContentsId),
      domSha256: 'a'.repeat(64),
      elementHandle: handle,
      action: 'scroll' as const,
      valueSha256: SCROLL_PAYLOAD_SHA256
    })
    const firstScope = scope(first.sessionId, mintDefaultElementHandle(policy, first.sessionId))
    const secondScope = scope(first.sessionId, mintDefaultElementHandle(policy, first.sessionId))
    const firstCapability = policy.issueCapability(firstScope, 500)
    const secondCapability = policy.issueCapability(secondScope, 500)

    expect(() => policy.issueCapability(firstScope, 500)).toThrow(/capacity/i)
    expect(policy.closeSession(first.sessionId)).toBe(true)
    expect(
      policy.consumeCapability(firstCapability.token, {
        ...firstScope,
        expiresAtMs: firstCapability.expiresAtMs
      })
    ).toBe(false)
    expect(
      policy.consumeCapability(secondCapability.token, {
        ...secondScope,
        expiresAtMs: secondCapability.expiresAtMs
      })
    ).toBe(false)
    expect(() => policy.issueCapability(firstScope, 500)).toThrow(/not open/i)
    expect(policy.closeSession(first.sessionId)).toBe(false)

    const second = policy.createSession()
    const replacementScope = scope(
      second.sessionId,
      mintDefaultElementHandle(policy, second.sessionId, 8),
      8
    )
    expect(() => policy.issueCapability(replacementScope, 500)).not.toThrow()
  })

  it('does not allow dependency injection to configure away the hard capability bound', () => {
    expect(() => new PageAgentReadonlySessionPolicy({ maxCapabilities: 4_097 })).toThrow(
      /hard maximum/i
    )
  })

  it('reclaims expired entries before applying the live capability bound', () => {
    let now = 1_000
    let randomByte = 1
    const policy = new PageAgentReadonlySessionPolicy({
      maxCapabilities: 1,
      now: () => now,
      randomBytes: (size) => Buffer.alloc(size, randomByte++),
      randomUUID: () => '11111111-1111-4111-8111-111111111111'
    })
    const { sessionId } = policy.createSession()
    const scope = {
      sessionId,
      webContentsId: 7,
      origin: 'https://example.test',
      navigationEpoch: defaultNavigationEpoch(policy, sessionId),
      domSha256: 'a'.repeat(64),
      elementHandle: mintDefaultElementHandle(policy, sessionId),
      action: 'inspect' as const,
      valueSha256: EMPTY_PAYLOAD_SHA256
    }
    policy.issueCapability(scope, 500)

    now = 1_500
    expect(() => policy.issueCapability(scope, 500)).not.toThrow()
  })

  it('burns the token before rejecting every changed binding field', () => {
    let randomByte = 1
    const policy = new PageAgentReadonlySessionPolicy({
      now: () => 1_000,
      randomBytes: (size) => Buffer.alloc(size, randomByte++),
      randomUUID: () => '11111111-1111-4111-8111-111111111111'
    })
    const { sessionId } = policy.createSession()
    const scope = {
      sessionId,
      webContentsId: 7,
      origin: 'https://example.test',
      navigationEpoch: defaultNavigationEpoch(policy, sessionId),
      domSha256: 'a'.repeat(64),
      elementHandle: mintDefaultElementHandle(policy, sessionId),
      action: 'inspect' as const,
      valueSha256: EMPTY_PAYLOAD_SHA256
    }
    const changes: Array<Record<string, unknown>> = [
      { sessionId: '22222222-2222-4222-8222-222222222222' },
      { webContentsId: 8 },
      { origin: 'https://other.test' },
      { navigationEpoch: 4 },
      { domSha256: 'b'.repeat(64) },
      { elementHandle: `el_${'z'.repeat(43)}` },
      { action: 'scroll' },
      { valueSha256: 'c'.repeat(64) },
      { expiresAtMs: 1_501 }
    ]

    for (const change of changes) {
      const issued = policy.issueCapability(scope, 500)
      const exactBinding = { ...scope, expiresAtMs: issued.expiresAtMs }
      expect(policy.consumeCapability(issued.token, { ...exactBinding, ...change })).toBe(false)
      expect(policy.consumeCapability(issued.token, exactBinding)).toBe(false)
    }
  })

  it('burns an expired token at the exact expiry boundary', () => {
    let now = 1_000
    const policy = new PageAgentReadonlySessionPolicy({
      now: () => now,
      randomBytes: (size) => Buffer.alloc(size, 1),
      randomUUID: () => '11111111-1111-4111-8111-111111111111'
    })
    const { sessionId } = policy.createSession()
    const scope = {
      sessionId,
      webContentsId: 7,
      origin: 'https://example.test',
      navigationEpoch: defaultNavigationEpoch(policy, sessionId),
      domSha256: 'a'.repeat(64),
      elementHandle: mintDefaultElementHandle(policy, sessionId),
      action: 'inspect' as const,
      valueSha256: EMPTY_PAYLOAD_SHA256
    }
    const issued = policy.issueCapability(scope, 500)
    const binding = { ...scope, expiresAtMs: issued.expiresAtMs }

    now = 1_500
    expect(policy.consumeCapability(issued.token, binding)).toBe(false)
    now = 1_499
    expect(policy.consumeCapability(issued.token, binding)).toBe(false)
  })

  it('burns the token and fails closed when the injected clock moves backwards', () => {
    let now = 1_000
    const policy = new PageAgentReadonlySessionPolicy({
      now: () => now,
      randomBytes: (size) => Buffer.alloc(size, 1),
      randomUUID: () => '11111111-1111-4111-8111-111111111111'
    })
    const { sessionId } = policy.createSession()
    const scope = {
      sessionId,
      webContentsId: 7,
      origin: 'https://example.test',
      navigationEpoch: defaultNavigationEpoch(policy, sessionId),
      domSha256: 'a'.repeat(64),
      elementHandle: mintDefaultElementHandle(policy, sessionId),
      action: 'inspect' as const,
      valueSha256: EMPTY_PAYLOAD_SHA256
    }
    const issued = policy.issueCapability(scope, 500)
    const binding = { ...scope, expiresAtMs: issued.expiresAtMs }

    now = 999
    expect(policy.consumeCapability(issued.token, binding)).toBe(false)
    now = 1_000
    expect(policy.consumeCapability(issued.token, binding)).toBe(false)
  })

  it('requires a canonical exact HTTPS origin and rejects secret-shaped extra fields', () => {
    const policy = new PageAgentReadonlySessionPolicy({
      now: () => 1_000,
      randomBytes: (size) => Buffer.alloc(size, 1),
      randomUUID: () => '11111111-1111-4111-8111-111111111111'
    })
    const session = policy.createSession()
    const scope = {
      sessionId: session.sessionId,
      webContentsId: 7,
      origin: 'https://example.test',
      navigationEpoch: defaultNavigationEpoch(policy, session.sessionId),
      domSha256: 'a'.repeat(64),
      elementHandle: mintDefaultElementHandle(policy, session.sessionId),
      action: 'inspect' as const,
      valueSha256: EMPTY_PAYLOAD_SHA256
    }

    for (const origin of [
      'http://example.test',
      'https://example.test/',
      'https://example.test/path',
      'https://EXAMPLE.test'
    ]) {
      expect(() => policy.issueCapability({ ...scope, origin }, 500)).toThrow(/exact HTTPS origin/i)
    }
    for (const field of ['providerKey', 'runtimeKey', 'approvalKey']) {
      expect(() =>
        policy.issueCapability({ ...scope, [field]: 'must-not-leak' }, 500)
      ).toThrow(/unexpected fields/i)
    }

    const issued = policy.issueCapability(scope, 500)
    expect(Object.keys(session).sort()).toEqual(['partition', 'sessionId', 'webPreferences'])
    expect(Object.keys(issued).sort()).toEqual(['expiresAtMs', 'token'])
    expect(JSON.stringify({ session, issued })).not.toMatch(/providerKey|runtimeKey|approvalKey/i)
  })

  it('rejects accessors and Proxy scopes without invoking their traps', () => {
    const policy = new PageAgentReadonlySessionPolicy({
      now: () => 1_000,
      randomBytes: (size) => Buffer.alloc(size, 1),
      randomUUID: () => '11111111-1111-4111-8111-111111111111'
    })
    const { sessionId } = policy.createSession()
    const scope = {
      sessionId,
      webContentsId: 7,
      origin: 'https://example.test',
      navigationEpoch: defaultNavigationEpoch(policy, sessionId),
      domSha256: 'a'.repeat(64),
      elementHandle: mintDefaultElementHandle(policy, sessionId),
      action: 'inspect' as const,
      valueSha256: EMPTY_PAYLOAD_SHA256
    }
    let getterCalls = 0
    const accessorScope = { ...scope }
    Object.defineProperty(accessorScope, 'origin', {
      enumerable: true,
      get() {
        getterCalls += 1
        return 'https://example.test'
      }
    })
    let proxyTrapCalls = 0
    const proxyScope = new Proxy(
      { ...scope },
      {
        getPrototypeOf(target) {
          proxyTrapCalls += 1
          return Reflect.getPrototypeOf(target)
        },
        ownKeys(target) {
          proxyTrapCalls += 1
          return Reflect.ownKeys(target)
        }
      }
    )

    expect(() => policy.issueCapability(accessorScope, 500)).toThrow(/data properties/i)
    expect(getterCalls).toBe(0)
    expect(() => policy.issueCapability(proxyScope, 500)).toThrow(/Proxy/i)
    expect(proxyTrapCalls).toBe(0)
  })

  it('rejects a random callback re-entry without bypassing capability capacity', () => {
    let policy!: PageAgentReadonlySessionPolicy
    let scope!: {
      sessionId: string
      webContentsId: number
      origin: string
      navigationEpoch: number
      domSha256: string
      elementHandle: string
      action: 'inspect'
      valueSha256: string
    }
    let randomCalls = 0
    let reenterRandom = false
    let nestedError: unknown
    policy = new PageAgentReadonlySessionPolicy({
      maxCapabilities: 1,
      now: () => 1_000,
      randomBytes: (size) => {
        randomCalls += 1
        const byte = randomCalls
        if (reenterRandom) {
          reenterRandom = false
          try {
            policy.issueCapability(scope, 500)
          } catch (error) {
            nestedError = error
          }
        }
        return Buffer.alloc(size, byte)
      },
      randomUUID: () => '11111111-1111-4111-8111-111111111111'
    })
    const { sessionId } = policy.createSession()
    scope = {
      sessionId,
      webContentsId: 7,
      origin: 'https://example.test',
      navigationEpoch: defaultNavigationEpoch(policy, sessionId),
      domSha256: 'a'.repeat(64),
      elementHandle: mintDefaultElementHandle(policy, sessionId),
      action: 'inspect',
      valueSha256: EMPTY_PAYLOAD_SHA256
    }

    reenterRandom = true
    expect(() => policy.issueCapability(scope, 500)).not.toThrow()
    expect(nestedError).toBeInstanceOf(Error)
    expect(String(nestedError)).toMatch(/re-entrant mutation/i)
    expect(() => policy.issueCapability(scope, 500)).toThrow(/capacity/i)
  })

  it('rejects a capability random source whose typed-array subclass only fakes 32 bytes', () => {
    class ForgedLengthBytes extends Uint8Array {
      override get byteLength(): number {
        return 32
      }
    }

    let randomCalls = 0
    const policy = new PageAgentReadonlySessionPolicy({
      now: () => 1_000,
      randomBytes: (size) => {
        randomCalls += 1
        return randomCalls === 1 ? Buffer.alloc(size, 1) : new ForgedLengthBytes(0)
      },
      randomUUID: () => '11111111-1111-4111-8111-111111111111'
    })
    const { sessionId } = policy.createSession()
    const scope = {
      sessionId,
      webContentsId: 7,
      origin: 'https://example.test',
      navigationEpoch: defaultNavigationEpoch(policy, sessionId),
      domSha256: 'a'.repeat(64),
      elementHandle: mintDefaultElementHandle(policy, sessionId),
      action: 'inspect' as const,
      valueSha256: EMPTY_PAYLOAD_SHA256
    }

    expect(() => policy.issueCapability(scope, 500)).toThrow(/capability randomness is invalid/i)
  })

  it('rejects a capability random source whose zero-byte view only fakes length 32', () => {
    class ForgedLengthBytes extends Uint8Array {
      override get length(): number {
        return 32
      }
    }

    let randomCalls = 0
    const policy = new PageAgentReadonlySessionPolicy({
      now: () => 1_000,
      randomBytes: (size) => {
        randomCalls += 1
        return randomCalls === 1 ? Buffer.alloc(size, 1) : new ForgedLengthBytes(0)
      },
      randomUUID: () => '11111111-1111-4111-8111-111111111111'
    })
    const { sessionId } = policy.createSession()
    const scope = {
      sessionId,
      webContentsId: 7,
      origin: 'https://example.test',
      navigationEpoch: defaultNavigationEpoch(policy, sessionId),
      domSha256: 'a'.repeat(64),
      elementHandle: mintDefaultElementHandle(policy, sessionId),
      action: 'inspect' as const,
      valueSha256: EMPTY_PAYLOAD_SHA256
    }

    expect(() => policy.issueCapability(scope, 500)).toThrow(/capability randomness is invalid/i)
  })

  it('rejects an element-handle random source whose typed-array subclass only fakes 32 bytes', () => {
    class ForgedLengthBytes extends Uint8Array {
      override get byteLength(): number {
        return 32
      }
    }

    const policy = new PageAgentReadonlySessionPolicy({
      randomBytes: () => new ForgedLengthBytes(0),
      randomUUID: () => '11111111-1111-4111-8111-111111111111'
    })
    const { sessionId } = policy.createSession()

    expect(() =>
      policy.mintElementHandle({
        sessionId,
        webContentsId: 7,
        origin: 'https://example.test',
        navigationEpoch: defaultNavigationEpoch(policy, sessionId),
        domSha256: 'a'.repeat(64),
        elementIdentitySha256: 'd'.repeat(64)
      })
    ).toThrow(/element handle randomness is invalid/i)
  })

  it('rejects an element-handle random source whose zero-byte view only fakes length 32', () => {
    class ForgedLengthBytes extends Uint8Array {
      override get length(): number {
        return 32
      }
    }

    const forged = new ForgedLengthBytes(0)
    expect(forged.byteLength).toBe(0)
    expect(forged.length).toBe(32)

    const policy = new PageAgentReadonlySessionPolicy({
      randomBytes: () => forged,
      randomUUID: () => '11111111-1111-4111-8111-111111111111'
    })
    const { sessionId } = policy.createSession()

    expect(() =>
      policy.mintElementHandle({
        sessionId,
        webContentsId: 7,
        origin: 'https://example.test',
        navigationEpoch: defaultNavigationEpoch(policy, sessionId),
        domSha256: 'a'.repeat(64),
        elementIdentitySha256: 'd'.repeat(64)
      })
    ).toThrow(/element handle randomness is invalid/i)
  })

  it('uses TypedArray intrinsics without invoking hostile view surface accessors', () => {
    let surfaceAccessorCalls = 0
    class HostileSurfaceBytes extends Uint8Array {
      override get length(): number {
        surfaceAccessorCalls += 1
        throw new Error('surface length must not run')
      }

      override get byteLength(): number {
        surfaceAccessorCalls += 1
        throw new Error('surface byteLength must not run')
      }

      override get byteOffset(): number {
        surfaceAccessorCalls += 1
        throw new Error('surface byteOffset must not run')
      }

      override get buffer(): ArrayBuffer {
        surfaceAccessorCalls += 1
        throw new Error('surface buffer must not run')
      }
    }

    const hostileBytes = new HostileSurfaceBytes(32)
    const policy = new PageAgentReadonlySessionPolicy({
      now: () => 1_000,
      randomBytes: () => hostileBytes,
      randomUUID: () => '11111111-1111-4111-8111-111111111111'
    })
    const { sessionId } = policy.createSession()
    const navigationEpoch = defaultNavigationEpoch(policy, sessionId)
    const domSha256 = 'a'.repeat(64)
    const elementHandle = policy.mintElementHandle({
      sessionId,
      webContentsId: 7,
      origin: 'https://example.test',
      navigationEpoch,
      domSha256,
      elementIdentitySha256: 'd'.repeat(64)
    })
    const issued = policy.issueCapability(
      {
        sessionId,
        webContentsId: 7,
        origin: 'https://example.test',
        navigationEpoch,
        domSha256,
        elementHandle,
        action: 'inspect',
        valueSha256: EMPTY_PAYLOAD_SHA256
      },
      500
    )

    expect(elementHandle).toMatch(/^el_[A-Za-z0-9_-]{43}$/)
    expect(issued.token).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(surfaceAccessorCalls).toBe(0)
  })

  it('rejects SharedArrayBuffer-backed randomness for handles and capabilities', () => {
    const sharedBytes = new Uint8Array(new SharedArrayBuffer(32))
    const handlePolicy = new PageAgentReadonlySessionPolicy({
      randomBytes: () => sharedBytes,
      randomUUID: () => '11111111-1111-4111-8111-111111111111'
    })
    const handleSession = handlePolicy.createSession()
    expect(() =>
      handlePolicy.mintElementHandle({
        sessionId: handleSession.sessionId,
        webContentsId: 7,
        origin: 'https://example.test',
        navigationEpoch: defaultNavigationEpoch(handlePolicy, handleSession.sessionId),
        domSha256: 'a'.repeat(64),
        elementIdentitySha256: 'd'.repeat(64)
      })
    ).toThrow(/element handle randomness is invalid/i)

    let randomCalls = 0
    const capabilityPolicy = new PageAgentReadonlySessionPolicy({
      now: () => 1_000,
      randomBytes: (size) => {
        randomCalls += 1
        return randomCalls === 1 ? Buffer.alloc(size, 1) : sharedBytes
      },
      randomUUID: () => '22222222-2222-4222-8222-222222222222'
    })
    const capabilitySession = capabilityPolicy.createSession()
    const capabilityScope = {
      sessionId: capabilitySession.sessionId,
      webContentsId: 7,
      origin: 'https://example.test',
      navigationEpoch: defaultNavigationEpoch(capabilityPolicy, capabilitySession.sessionId),
      domSha256: 'a'.repeat(64),
      elementHandle: mintDefaultElementHandle(capabilityPolicy, capabilitySession.sessionId),
      action: 'inspect' as const,
      valueSha256: EMPTY_PAYLOAD_SHA256
    }
    expect(() => capabilityPolicy.issueCapability(capabilityScope, 500)).toThrow(
      /capability randomness is invalid/i
    )
  })

  it('rejects a re-entrant consume before it can burn an existing capability', () => {
    let policy!: PageAgentReadonlySessionPolicy
    let reenterConsume = false
    let nestedConsumeResult: boolean | undefined
    let existingToken = ''
    let existingBinding: Record<string, unknown> = {}
    let randomByte = 1
    policy = new PageAgentReadonlySessionPolicy({
      maxCapabilities: 2,
      now: () => 1_000,
      randomBytes: (size) => {
        if (reenterConsume) {
          reenterConsume = false
          nestedConsumeResult = policy.consumeCapability(existingToken, existingBinding)
        }
        return Buffer.alloc(size, randomByte++)
      },
      randomUUID: () => '11111111-1111-4111-8111-111111111111'
    })
    const { sessionId } = policy.createSession()
    const existingElementHandle = mintDefaultElementHandle(policy, sessionId)
    const outerElementHandle = mintDefaultElementHandle(policy, sessionId)
    const scope = {
      sessionId,
      webContentsId: 7,
      origin: 'https://example.test',
      navigationEpoch: defaultNavigationEpoch(policy, sessionId),
      domSha256: 'a'.repeat(64),
      elementHandle: existingElementHandle,
      action: 'inspect' as const,
      valueSha256: EMPTY_PAYLOAD_SHA256
    }
    const existing = policy.issueCapability(scope, 500)
    existingToken = existing.token
    existingBinding = { ...scope, expiresAtMs: existing.expiresAtMs }

    reenterConsume = true
    expect(() =>
      policy.issueCapability({ ...scope, elementHandle: outerElementHandle }, 500)
    ).not.toThrow()
    expect(nestedConsumeResult).toBe(false)
    expect(policy.consumeCapability(existing.token, existingBinding)).toBe(true)
  })
})
