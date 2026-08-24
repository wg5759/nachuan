import { describe, expect, it, vi } from 'vitest'

import { createCredentialStore, type KeyValueStorage } from './credentials'
import { createLoginGate, type GateDocument, type GateElement, type GateInput } from './gate'

class FakeElement implements GateElement {
  tag: string
  children: FakeElement[] = []
  style: Record<string, string> = {}
  textContent = ''
  removed = false
  parent: FakeElement | null = null
  private listeners = new Map<string, Array<(event: { preventDefault(): void }) => void>>()

  constructor(tag: string) {
    this.tag = tag
  }

  appendChild(child: FakeElement): void {
    child.parent = this
    this.children.push(child)
  }

  addEventListener(type: string, listener: (event: { preventDefault(): void }) => void): void {
    this.listeners.set(type, [...(this.listeners.get(type) ?? []), listener])
  }

  remove(): void {
    this.removed = true
    if (this.parent) {
      this.parent.children = this.parent.children.filter((child) => child !== this)
      this.parent = null
    }
  }

  dispatch(type: string, event: { preventDefault(): void } = { preventDefault: () => {} }): void {
    for (const listener of this.listeners.get(type) ?? []) listener(event)
  }

  findAll(tag: string): FakeElement[] {
    const found: FakeElement[] = []
    const walk = (node: FakeElement): void => {
      if (node.tag === tag) found.push(node)
      for (const child of node.children) walk(child)
    }
    walk(this)
    return found
  }
}

class FakeInput extends FakeElement implements GateInput {
  type = ''
  placeholder = ''
  value = ''
  disabled = false
}

class FakeDocument implements GateDocument {
  body: FakeElement | null = new FakeElement('body')
  private documentListeners = new Map<string, Array<() => void>>()

  createElement(tag: string): FakeElement {
    return tag === 'input' || tag === 'button' ? new FakeInput(tag) : new FakeElement(tag)
  }

  addEventListener(type: string, listener: () => void): void {
    this.documentListeners.set(type, [...(this.documentListeners.get(type) ?? []), listener])
  }

  fire(type: string): void {
    for (const listener of this.documentListeners.get(type) ?? []) listener()
    this.documentListeners.delete(type)
  }
}

function memoryStorage(): KeyValueStorage & { data: Record<string, string> } {
  const data: Record<string, string> = {}
  return {
    data,
    getItem: (key: string) => (key in data ? data[key] : null),
    setItem: (key: string, value: string) => {
      data[key] = value
    },
    removeItem: (key: string) => {
      delete data[key]
    }
  }
}

function harness(verify: (runtimeKey: string) => Promise<boolean>) {
  const storage = memoryStorage()
  const doc = new FakeDocument()
  const reload = vi.fn()
  const gate = createLoginGate({
    credentials: createCredentialStore(() => storage),
    verify,
    reload,
    doc
  })
  return { storage, doc, reload, gate }
}

function inputs(doc: FakeDocument): { runtime: FakeInput; approval: FakeInput; submit: FakeInput; error: FakeElement } {
  const body = doc.body as FakeElement
  const overlay = body.children[body.children.length - 1]
  const fields = overlay.findAll('input') as FakeInput[]
  const button = overlay.findAll('button')[0] as FakeInput
  const divs = overlay.findAll('div')
  const error = divs[divs.length - 1]
  return { runtime: fields[0], approval: fields[1], submit: button, error }
}

describe('web-shim login gate', () => {
  it('mounts the key entry view on show and stays a singleton', () => {
    const { doc, gate } = harness(async () => true)

    gate.show('missing')
    expect(gate.visible).toBe(true)
    expect((doc.body as FakeElement).findAll('button')).toHaveLength(1)

    gate.show('unauthorized')
    expect((doc.body as FakeElement).findAll('button')).toHaveLength(1)
  })

  it('uses the same light product surfaces as the shared renderer', () => {
    const { doc, gate } = harness(async () => true)

    gate.show('missing')
    const overlay = (doc.body as FakeElement).children[0]
    const panel = overlay.children[0]
    const submit = overlay.findAll('button')[0]

    expect(overlay.style.background).toContain('246,247,251')
    expect(panel.style.background).toBe('#ffffff')
    expect(panel.style.borderRadius).toBe('18px')
    expect(submit.style.background).toBe('#5557d9')
  })

  it('stores verified keys, hides, and replays the app', async () => {
    const verify = vi.fn(async () => true)
    const { storage, doc, reload, gate } = harness(verify)

    gate.show('missing')
    const { runtime, approval, submit } = inputs(doc)
    runtime.value = '  runtime-key  '
    approval.value = 'approval-key'
    submit.dispatch('click')

    await vi.waitFor(() => expect(reload).toHaveBeenCalledTimes(1))
    expect(verify).toHaveBeenCalledWith('runtime-key')
    expect(storage.data['nachuan.web.runtimeKey']).toBe('runtime-key')
    expect(storage.data['nachuan.web.approvalKey']).toBe('approval-key')
    expect(gate.visible).toBe(false)
  })

  it('preserves an existing approval key when only the runtime key is re-entered', async () => {
    const { storage, doc, reload, gate } = harness(async () => true)
    storage.data['nachuan.web.approvalKey'] = 'existing-approval'

    gate.show('unauthorized')
    const { runtime, approval, submit } = inputs(doc)
    runtime.value = 'replacement-runtime'
    approval.value = ''
    submit.dispatch('click')

    await vi.waitFor(() => expect(reload).toHaveBeenCalledTimes(1))
    expect(storage.data['nachuan.web.runtimeKey']).toBe('replacement-runtime')
    expect(storage.data['nachuan.web.approvalKey']).toBe('existing-approval')
  })

  it('keeps the gate open with an error when the gateway rejects the key', async () => {
    const { storage, doc, reload, gate } = harness(async () => false)

    gate.show('unauthorized')
    const { runtime, submit, error } = inputs(doc)
    runtime.value = 'wrong-key'
    submit.dispatch('click')

    await vi.waitFor(() => expect(error.textContent).toContain('GET /v1/models'))
    expect(reload).not.toHaveBeenCalled()
    expect('nachuan.web.runtimeKey' in storage.data).toBe(false)
    expect(gate.visible).toBe(true)
  })

  it('requires the runtime key before any verification', async () => {
    const verify = vi.fn(async () => true)
    const { doc, gate } = harness(verify)

    gate.show('missing')
    const { submit, error } = inputs(doc)
    submit.dispatch('click')

    await vi.waitFor(() => expect(error.textContent).toContain('运行时 Key 必填'))
    expect(verify).not.toHaveBeenCalled()
  })

  it('defers mounting until DOMContentLoaded when body is not parsed yet', () => {
    const { doc, gate } = harness(async () => true)
    doc.body = null

    gate.show('missing')
    expect(gate.visible).toBe(false)

    doc.body = new FakeElement('body')
    doc.fire('DOMContentLoaded')
    expect(gate.visible).toBe(true)
    expect(doc.body.findAll('button')).toHaveLength(1)
  })

  it('submits on Enter from the key inputs', async () => {
    const verify = vi.fn(async () => true)
    const { storage, doc, reload, gate } = harness(verify)

    gate.show('missing')
    const { runtime } = inputs(doc)
    runtime.value = 'runtime-key'
    runtime.dispatch('keydown', { key: 'Enter', preventDefault: () => {} } as never)

    await vi.waitFor(() => expect(reload).toHaveBeenCalledTimes(1))
    expect(storage.data['nachuan.web.runtimeKey']).toBe('runtime-key')
  })

  it('surfaces storage failures without clearing business data or reloading', async () => {
    const brokenStorage: KeyValueStorage = {
      getItem: () => null,
      setItem: () => {
        throw new Error('denied')
      },
      removeItem: () => {}
    }
    const doc = new FakeDocument()
    const reload = vi.fn()
    const gate = createLoginGate({
      credentials: createCredentialStore(() => brokenStorage),
      verify: async () => true,
      reload,
      doc
    })

    gate.show('missing')
    const { runtime, submit, error } = inputs(doc)
    runtime.value = 'runtime-key'
    submit.dispatch('click')

    await vi.waitFor(() => expect(error.textContent).toContain('denied'))
    expect(reload).not.toHaveBeenCalled()
  })
})
