import { describe, expect, it } from 'vitest'

import { PageAgentReadonlyPageReader } from './page-agent-readonly-page-reader'
import { PageAgentReadonlySessionPolicy } from './page-agent-readonly-session'

const ORIGIN = 'https://fixture.example'
const WEB_CONTENTS_ID = 7

function fixturePayload(nodes: ReadonlyArray<Record<string, unknown>>, overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    origin: ORIGIN,
    title: 'fixture',
    scrollY: 0,
    viewportHeight: 900,
    documentHeight: 5000,
    truncated: false,
    nodes,
    ...overrides
  })
}

function fixtureNodes(count: number): Record<string, unknown>[] {
  const nodes: Record<string, unknown>[] = []
  for (let index = 0; index < count; index += 1) {
    nodes.push({
      i: index,
      tag: index === 0 ? 'html' : 'section',
      id: index === 0 ? '' : `node-${index}`,
      role: '',
      text: `text-${index}`,
      y: index * 500
    })
  }
  return nodes
}

interface FakePage {
  reader: PageAgentReadonlyPageReader
  policy: PageAgentReadonlySessionPolicy
  sessionId: string
  scripts: string[]
  payload: unknown
  scrollY: number
  setPayload(payload: unknown): void
  setScrollY(scrollY: number): void
}

function createReader(payloadOverride?: unknown): FakePage {
  const policy = new PageAgentReadonlySessionPolicy()
  const spec = policy.createSession()
  policy.bindWebContents(spec.sessionId, WEB_CONTENTS_ID)
  policy.beginNavigation(spec.sessionId, WEB_CONTENTS_ID)
  const scripts: string[] = []
  const page: FakePage = {
    reader: undefined as unknown as PageAgentReadonlyPageReader,
    policy,
    sessionId: spec.sessionId,
    scripts,
    setPayload(payload: unknown) {
      page.payload = payload
    },
    setScrollY(scrollY: number) {
      page.scrollY = scrollY
    },
    payload: payloadOverride ?? fixturePayload(fixtureNodes(6)),
    scrollY: 0
  } as FakePage
  page.reader = new PageAgentReadonlyPageReader({
    policy,
    sessionId: spec.sessionId,
    webContentsId: WEB_CONTENTS_ID,
    controlledOrigin: ORIGIN,
    executeJavaScript: async (script: string) => {
      scripts.push(script)
      if (script.includes('TARGET')) {
        return JSON.stringify({ ok: true, scrollY: page.scrollY })
      }
      return page.payload
    }
  })
  return page
}

describe('page-agent readonly page reader (fake page port, real policy)', () => {
  it('inspects via the fixed extraction script and consumes the gated capability', async () => {
    const page = createReader()
    const result = await page.reader.inspect()
    expect(result.origin).toBe(ORIGIN)
    expect(result.navigationEpoch).toBe(1)
    expect(result.domSha256).toMatch(/^[0-9a-f]{64}$/)
    expect(result.capabilityEvidence).toEqual({ issued: true, consumed: true })
    expect(result.nodes).toHaveLength(6)
    expect(result.handles['node-3']).toMatch(/^el_[A-Za-z0-9_-]{43}$/)
    expect(page.scripts.length).toBeGreaterThan(0)
    expect(page.scripts[0]).not.toContain('fixturePayload')
  })

  it('rejects a DOM capture whose origin drifted from the controlled origin', async () => {
    const page = createReader(fixturePayload(fixtureNodes(3), { origin: 'https://evil.example' }))
    await expect(page.reader.captureDom()).rejects.toThrow(/drifted/)
  })

  it('rejects malformed or hostile capture payloads without minting handles', async () => {
    const page = createReader({ not: 'a string' })
    await expect(page.reader.captureDom()).rejects.toThrow(/invalid/)

    page.setPayload(fixturePayload([{ i: 5, tag: 'div', id: '', role: '', text: '', y: 0 }]))
    await expect(page.reader.captureDom()).rejects.toThrow(/order/)

    page.setPayload(
      fixturePayload(Array.from({ length: 200 }, (_v, index) => ({
        i: index, tag: 'div', id: '', role: '', text: '', y: 0
      })))
    )
    await expect(page.reader.captureDom()).rejects.toThrow(/invalid/)
  })

  it('refuses a DOM snapshot fork inside one navigation epoch', async () => {
    const page = createReader()
    await page.reader.inspect()
    page.setPayload(fixturePayload(fixtureNodes(9)))
    await expect(page.reader.inspect()).rejects.toThrow(/fork/)
  })

  it('scrolls through a minted handle with a value-bound capability', async () => {
    const page = createReader()
    const inspect = await page.reader.inspect()
    const handle = inspect.handles['node-4']
    page.setScrollY(2000)
    const result = await page.reader.scrollToHandle(handle)
    expect(result.index).toBe(4)
    expect(result.scrollYAfter).toBe(2000)
    expect(result.capabilityEvidence.consumed).toBe(true)
    const scrollScript = page.scripts.find((script) => script.includes('TARGET'))
    expect(scrollScript).toContain('const TARGET = 4;')
  })

  it('revokes minted handles when the session navigates', async () => {
    const page = createReader()
    const inspect = await page.reader.inspect()
    page.policy.beginNavigation(page.sessionId, WEB_CONTENTS_ID)
    await expect(page.reader.scrollToHandle(inspect.handles['node-2'])).rejects.toThrow(/revoked/)
  })

  it('rejects unknown handles and a closed reader', async () => {
    const page = createReader()
    await expect(page.reader.scrollToHandle('el_' + 'a'.repeat(43))).rejects.toThrow(/unknown/)
    page.reader.close()
    await expect(page.reader.captureDom()).rejects.toThrow(/closed/)
  })
})
