import { describe, expect, it, vi } from 'vitest'

import { registerPluginUiIpc } from './plugin-ui-ipc'

function snapshot(): Record<string, unknown> {
  return {
    schema: 'nachuan.plugin-ui.snapshot.v1',
    slots: [
      {
        slot_id: 'workspace.orchestration',
        surface: 'workspace.menu',
        component: 'orchestrate',
        order: 600,
        plugin_id: 'com.nachuan.ui.orchestration',
        plugin_version: '1.0.0',
        artifact_sha256: 'a'.repeat(64)
      }
    ]
  }
}

describe('plugin UI Main IPC', () => {
  it('selects the no-input session method and returns only a validated snapshot', async () => {
    let handler: ((event: object, input?: unknown) => unknown) | undefined
    const ipc = {
      handle: vi.fn((_channel: string, value: typeof handler) => {
        handler = value
      }),
      removeHandler: vi.fn()
    }
    const session = { pluginUiSnapshot: vi.fn(async () => snapshot()) }
    const authorize = vi.fn()
    const dispose = registerPluginUiIpc(ipc, session, authorize)
    const event = {}

    await expect(handler?.(event)).resolves.toMatchObject({
      schema: 'nachuan.plugin-ui.snapshot.v1'
    })
    expect(authorize).toHaveBeenCalledWith(event)
    expect(session.pluginUiSnapshot).toHaveBeenCalledWith()
    await expect(handler?.(event, {})).rejects.toThrow(/input/i)

    dispose()
    expect(ipc.removeHandler).toHaveBeenCalledWith('plugin-ui:snapshot')
  })

  it('rejects a host response that tries to inject a remote renderer component', async () => {
    let handler: ((event: object, input?: unknown) => unknown) | undefined
    registerPluginUiIpc(
      {
        handle: (_channel, value) => {
          handler = value
        },
        removeHandler: () => undefined
      },
      {
        pluginUiSnapshot: async () => ({
          ...snapshot(),
          slots: [
            {
              ...((snapshot().slots as Record<string, unknown>[])[0] ?? {}),
              component: 'remote-script'
            }
          ]
        })
      },
      () => undefined
    )
    await expect(handler?.({})).rejects.toThrow('Invalid plugin UI snapshot')
  })
})
