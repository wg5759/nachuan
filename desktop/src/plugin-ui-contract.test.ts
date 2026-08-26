import { describe, expect, it } from 'vitest'

import { parsePluginUiSnapshot } from './plugin-ui-contract'

function validSnapshot(): Record<string, unknown> {
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

describe('plugin UI snapshot contract', () => {
  it('freezes the one closed built-in renderer mapping', () => {
    const result = parsePluginUiSnapshot(validSnapshot())
    expect(result.slots[0]).toMatchObject({
      slot_id: 'workspace.orchestration',
      component: 'orchestrate'
    })
    expect(Object.isFrozen(result)).toBe(true)
    expect(Object.isFrozen(result.slots)).toBe(true)
    expect(Object.isFrozen(result.slots[0])).toBe(true)
  })

  it.each([
    { extra: true },
    { schema: 'nachuan.plugin-ui.snapshot.v2', slots: [] },
    {
      schema: 'nachuan.plugin-ui.snapshot.v1',
      slots: [
        {
          ...((validSnapshot().slots as Record<string, unknown>[])[0] ?? {}),
          component: 'remote-script'
        }
      ]
    },
    {
      schema: 'nachuan.plugin-ui.snapshot.v1',
      slots: [
        {
          ...((validSnapshot().slots as Record<string, unknown>[])[0] ?? {}),
          url: 'https://evil.example/plugin.js'
        }
      ]
    }
  ])('rejects open, remote-code, or unsupported snapshots %#', (value) => {
    expect(() => parsePluginUiSnapshot(value)).toThrow('Invalid plugin UI snapshot')
  })
})
