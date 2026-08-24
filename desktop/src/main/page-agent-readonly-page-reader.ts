import { createHash } from 'node:crypto'
import { types as utilTypes } from 'node:util'

import {
  PAGE_AGENT_EMPTY_PAYLOAD_SHA256,
  type PageAgentReadonlyCapabilityScope,
  type PageAgentReadonlySessionPolicy
} from './page-agent-readonly-session'

// Main-owned page reader for the isolated read-only PoC.  The two guest-page
// scripts below are compile-time constants owned by Main; neither the model
// nor the page can supply script text, selectors, or network targets.  Every
// action runs through the session policy's capability machinery so a
// navigation, fork, or close immediately revokes execution authority.

export interface PageAgentReadonlyDomNode {
  readonly index: number
  readonly tag: string
  readonly id: string
  readonly role: string
  readonly text: string
  readonly absoluteY: number
}

export interface PageAgentReadonlyDomCapture {
  readonly origin: string
  readonly title: string
  readonly scrollY: number
  readonly viewportHeight: number
  readonly documentHeight: number
  readonly truncated: boolean
  readonly nodes: readonly PageAgentReadonlyDomNode[]
}

export interface PageAgentReadonlyInspectResult extends PageAgentReadonlyDomCapture {
  readonly sessionId: string
  readonly webContentsId: number
  readonly navigationEpoch: number
  readonly domSha256: string
  readonly handles: Readonly<Record<string, string>>
  readonly capabilityEvidence: Readonly<{ issued: boolean; consumed: boolean }>
}

export interface PageAgentReadonlyScrollResult {
  readonly index: number
  readonly scrollYBefore: number
  readonly scrollYAfter: number
  readonly capabilityEvidence: Readonly<{ issued: boolean; consumed: boolean }>
}

export interface PageAgentReadonlyPageReaderOptions {
  readonly policy: PageAgentReadonlySessionPolicy
  readonly sessionId: string
  readonly webContentsId: number
  readonly controlledOrigin: string
  readonly executeJavaScript: (script: string) => Promise<unknown>
  readonly maxNodes?: number
  readonly capabilityTtlMs?: number
}

interface HandleEntry {
  readonly index: number
  readonly origin: string
  readonly navigationEpoch: number
  readonly domSha256: string
}

const MAX_NODES_HARD = 128
const MAX_TEXT_CHARS = 80
const DEFAULT_CAPABILITY_TTL_MS = 5_000

// Fixed extraction script: pre-order walk over elements with bounded node and
// text counts.  Returns a JSON string so the Main side can validate every
// field before trusting it.
const EXTRACTION_SCRIPT = `(() => {
  const MAX_NODES = ${MAX_NODES_HARD};
  const MAX_TEXT = ${MAX_TEXT_CHARS};
  const nodes = [];
  let truncated = false;
  const walk = (el) => {
    if (nodes.length >= MAX_NODES) { truncated = true; return; }
    let text = '';
    for (const child of el.childNodes) {
      if (child.nodeType === 3 && typeof child.textContent === 'string') text += child.textContent;
    }
    text = text.replace(/\\s+/g, ' ').trim().slice(0, MAX_TEXT);
    const rect = el.getBoundingClientRect();
    nodes.push({
      i: nodes.length,
      tag: String(el.tagName || '').toLowerCase(),
      id: typeof el.id === 'string' ? el.id : '',
      role: el.getAttribute('role') || '',
      text,
      y: Math.round(rect.top + window.scrollY)
    });
    for (const child of el.children) walk(child);
  };
  if (document.documentElement) walk(document.documentElement);
  return JSON.stringify({
    origin: location.origin,
    title: document.title,
    scrollY: Math.round(window.scrollY),
    viewportHeight: Math.round(window.innerHeight),
    documentHeight: Math.round(document.documentElement ? document.documentElement.scrollHeight : 0),
    truncated,
    nodes
  });
})()`

// Fixed scroll script template: the only interpolated value is a Main-owned
// validated safe integer node index; the walk order must match extraction.
function buildScrollScript(index: number): string {
  if (!Number.isSafeInteger(index) || index < 0) {
    throw new Error('Page Agent scroll target index is invalid')
  }
  return `(() => {
  const TARGET = ${index};
  const nodes = [];
  const walk = (el) => {
    nodes.push(el);
    for (const child of el.children) walk(child);
  };
  if (document.documentElement) walk(document.documentElement);
  const el = nodes[TARGET];
  if (!el) return JSON.stringify({ ok: false, reason: 'missing' });
  el.scrollIntoView({ block: 'start' });
  return JSON.stringify({ ok: true, scrollY: Math.round(window.scrollY) });
})()`
}

function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex')
}

function assertBoundedString(value: unknown, maxLength: number): string {
  if (typeof value !== 'string' || value.length > maxLength) {
    throw new Error('Page Agent DOM capture field is invalid')
  }
  return value
}

function parseCapture(rawValue: unknown, maxNodes: number): PageAgentReadonlyDomCapture {
  if (typeof rawValue !== 'string' || rawValue.length > 2 * 1024 * 1024) {
    throw new Error('Page Agent DOM capture payload is invalid')
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(rawValue)
  } catch {
    throw new Error('Page Agent DOM capture payload is invalid')
  }
  if (
    typeof parsed !== 'object' ||
    parsed === null ||
    Array.isArray(parsed) ||
    utilTypes.isProxy(parsed)
  ) {
    throw new Error('Page Agent DOM capture payload is invalid')
  }
  const record = parsed as Record<string, unknown>
  const rawNodes = record.nodes
  if (!Array.isArray(rawNodes) || rawNodes.length > MAX_NODES_HARD) {
    throw new Error('Page Agent DOM capture nodes are invalid')
  }
  const nodes: PageAgentReadonlyDomNode[] = rawNodes.map((node, position) => {
    if (typeof node !== 'object' || node === null || Array.isArray(node)) {
      throw new Error('Page Agent DOM capture node is invalid')
    }
    const entry = node as Record<string, unknown>
    const index = entry.i
    if (!Number.isSafeInteger(index) || index !== position || position >= maxNodes) {
      throw new Error('Page Agent DOM capture node order is invalid')
    }
    return Object.freeze({
      index: position,
      tag: assertBoundedString(entry.tag, 40),
      id: assertBoundedString(entry.id, 256),
      role: assertBoundedString(entry.role, 64),
      text: assertBoundedString(entry.text, MAX_TEXT_CHARS),
      absoluteY: Number.isSafeInteger(entry.y) ? Number(entry.y) : 0
    })
  })
  return Object.freeze({
    origin: assertBoundedString(record.origin, 256),
    title: assertBoundedString(record.title, 256),
    scrollY: Number.isSafeInteger(record.scrollY) ? Number(record.scrollY) : 0,
    viewportHeight: Number.isSafeInteger(record.viewportHeight) ? Number(record.viewportHeight) : 0,
    documentHeight: Number.isSafeInteger(record.documentHeight) ? Number(record.documentHeight) : 0,
    truncated: record.truncated === true,
    nodes: Object.freeze(nodes)
  })
}

export class PageAgentReadonlyPageReader {
  private readonly policy: PageAgentReadonlySessionPolicy
  private readonly sessionId: string
  private readonly webContentsId: number
  private readonly controlledOrigin: string
  private readonly executeJavaScript: (script: string) => Promise<unknown>
  private readonly maxNodes: number
  private readonly capabilityTtlMs: number
  private readonly handles = new Map<string, HandleEntry>()
  private closed = false

  constructor(options: PageAgentReadonlyPageReaderOptions) {
    this.policy = options.policy
    this.sessionId = options.sessionId
    this.webContentsId = options.webContentsId
    this.controlledOrigin = options.controlledOrigin
    this.executeJavaScript = options.executeJavaScript
    this.maxNodes = options.maxNodes ?? MAX_NODES_HARD
    if (!Number.isSafeInteger(this.maxNodes) || this.maxNodes <= 0 || this.maxNodes > MAX_NODES_HARD) {
      throw new Error('Page Agent page reader node capacity is invalid')
    }
    this.capabilityTtlMs = options.capabilityTtlMs ?? DEFAULT_CAPABILITY_TTL_MS
  }

  /** Ungated staleness probe: fixed read-only extraction, no handles or capability. */
  async captureDom(): Promise<PageAgentReadonlyDomCapture> {
    this.assertOpen()
    const capture = parseCapture(await this.executeJavaScript(EXTRACTION_SCRIPT), this.maxNodes)
    if (capture.origin !== this.controlledOrigin) {
      throw new Error('Page Agent DOM capture origin drifted from the controlled origin')
    }
    return capture
  }

  async inspect(): Promise<PageAgentReadonlyInspectResult> {
    this.assertOpen()
    const capture = await this.captureDom()
    const navigationEpoch = this.policy.currentNavigationEpoch(this.sessionId)
    if (navigationEpoch === null) {
      throw new Error('Page Agent page reader session authority is unavailable')
    }
    const domSha256 = sha256Hex(JSON.stringify(capture.nodes))
    const handles: Record<string, string> = {}
    for (const node of capture.nodes) {
      const elementHandle = this.policy.mintElementHandle({
        sessionId: this.sessionId,
        webContentsId: this.webContentsId,
        origin: capture.origin,
        navigationEpoch,
        domSha256,
        elementIdentitySha256: sha256Hex(
          `element:${node.index}:${node.tag}:${node.id}:${node.role}:${node.text}`
        )
      })
      this.handles.set(elementHandle, {
        index: node.index,
        origin: capture.origin,
        navigationEpoch,
        domSha256
      })
      handles[node.id || `#${node.index}`] = elementHandle
    }
    const rootHandle = Object.values(handles)[0]
    if (typeof rootHandle !== 'string') {
      throw new Error('Page Agent DOM capture contains no root element')
    }
    const consumed = this.runGated({
      sessionId: this.sessionId,
      webContentsId: this.webContentsId,
      origin: capture.origin,
      navigationEpoch,
      domSha256,
      elementHandle: rootHandle,
      action: 'inspect',
      valueSha256: PAGE_AGENT_EMPTY_PAYLOAD_SHA256
    })
    return Object.freeze({
      ...capture,
      sessionId: this.sessionId,
      webContentsId: this.webContentsId,
      navigationEpoch,
      domSha256,
      handles: Object.freeze({ ...handles }),
      capabilityEvidence: Object.freeze({ issued: true, consumed })
    })
  }

  async scrollToHandle(elementHandle: string): Promise<PageAgentReadonlyScrollResult> {
    this.assertOpen()
    const entry = this.handles.get(elementHandle)
    if (!entry) {
      throw new Error('Page Agent page reader element handle is unknown')
    }
    if (this.policy.currentNavigationEpoch(this.sessionId) !== entry.navigationEpoch) {
      throw new Error('Page Agent element handle authority was revoked by navigation')
    }
    const before = await this.captureDom()
    const consumed = this.runGated({
      sessionId: this.sessionId,
      webContentsId: this.webContentsId,
      origin: entry.origin,
      navigationEpoch: entry.navigationEpoch,
      domSha256: entry.domSha256,
      elementHandle,
      action: 'scroll',
      valueSha256: sha256Hex(JSON.stringify({ index: entry.index }))
    })
    const raw = await this.executeJavaScript(buildScrollScript(entry.index))
    if (typeof raw !== 'string') {
      throw new Error('Page Agent scroll execution returned an invalid payload')
    }
    let parsed: unknown
    try {
      parsed = JSON.parse(raw)
    } catch {
      throw new Error('Page Agent scroll execution returned an invalid payload')
    }
    const result = parsed as Record<string, unknown>
    if (result.ok !== true || !Number.isSafeInteger(result.scrollY)) {
      throw new Error('Page Agent scroll execution failed in the guest page')
    }
    return Object.freeze({
      index: entry.index,
      scrollYBefore: before.scrollY,
      scrollYAfter: Number(result.scrollY),
      capabilityEvidence: Object.freeze({ issued: true, consumed })
    })
  }

  close(): void {
    this.closed = true
    this.handles.clear()
  }

  private runGated(
    scope: PageAgentReadonlyCapabilityScope
  ): boolean {
    const issued = this.policy.issueCapability(scope, this.capabilityTtlMs)
    const lease = this.policy.beginExecution(
      issued.token,
      Object.freeze({ ...scope, expiresAtMs: issued.expiresAtMs })
    )
    if (!lease) return false
    try {
      return lease.assertCurrent()
    } finally {
      lease.close()
    }
  }

  private assertOpen(): void {
    if (this.closed) {
      throw new Error('Page Agent page reader is closed')
    }
  }
}
