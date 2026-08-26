const LOWER_ID = /^[a-z0-9][a-z0-9._-]{2,127}$/
const VERSION = /^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$/
const SHA256 = /^[0-9a-f]{64}$/
const MAX_SLOTS = 64

export type PluginUiSurface = 'workspace.menu'
export type PluginUiComponent = 'orchestrate'

export type PluginUiSlot = Readonly<{
  slot_id: 'workspace.orchestration'
  surface: PluginUiSurface
  component: PluginUiComponent
  order: number
  plugin_id: string
  plugin_version: string
  artifact_sha256: string
}>

export type PluginUiSnapshot = Readonly<{
  schema: 'nachuan.plugin-ui.snapshot.v1'
  slots: readonly PluginUiSlot[]
}>

function exactRecord(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Invalid plugin UI snapshot')
  }
  const prototype = Object.getPrototypeOf(value)
  if (prototype !== Object.prototype && prototype !== null) {
    throw new Error('Invalid plugin UI snapshot')
  }
  const observed = Object.keys(value).sort()
  const expected = [...keys].sort()
  if (
    observed.length !== expected.length ||
    observed.some((key, index) => key !== expected[index])
  ) {
    throw new Error('Invalid plugin UI snapshot')
  }
  return value as Record<string, unknown>
}

function parseSlot(value: unknown): PluginUiSlot {
  const slot = exactRecord(value, [
    'artifact_sha256',
    'component',
    'order',
    'plugin_id',
    'plugin_version',
    'slot_id',
    'surface'
  ])
  if (
    slot.slot_id !== 'workspace.orchestration' ||
    slot.surface !== 'workspace.menu' ||
    slot.component !== 'orchestrate' ||
    !Number.isSafeInteger(slot.order) ||
    Number(slot.order) < 0 ||
    Number(slot.order) > 10_000 ||
    typeof slot.plugin_id !== 'string' ||
    !LOWER_ID.test(slot.plugin_id) ||
    typeof slot.plugin_version !== 'string' ||
    !VERSION.test(slot.plugin_version) ||
    typeof slot.artifact_sha256 !== 'string' ||
    !SHA256.test(slot.artifact_sha256)
  ) {
    throw new Error('Invalid plugin UI snapshot')
  }
  return Object.freeze({
    slot_id: 'workspace.orchestration',
    surface: 'workspace.menu',
    component: 'orchestrate',
    order: Number(slot.order),
    plugin_id: slot.plugin_id,
    plugin_version: slot.plugin_version,
    artifact_sha256: slot.artifact_sha256
  })
}

export function parsePluginUiSnapshot(value: unknown): PluginUiSnapshot {
  const snapshot = exactRecord(value, ['schema', 'slots'])
  if (
    snapshot.schema !== 'nachuan.plugin-ui.snapshot.v1' ||
    !Array.isArray(snapshot.slots) ||
    snapshot.slots.length > MAX_SLOTS
  ) {
    throw new Error('Invalid plugin UI snapshot')
  }
  const slots = snapshot.slots.map(parseSlot)
  if (
    new Set(slots.map((slot) => slot.slot_id)).size !== slots.length ||
    slots.some(
      (slot, index) =>
        index > 0 &&
        (slots[index - 1]!.order > slot.order ||
          (slots[index - 1]!.order === slot.order &&
            slots[index - 1]!.slot_id.localeCompare(slot.slot_id) >= 0))
    )
  ) {
    throw new Error('Invalid plugin UI snapshot')
  }
  return Object.freeze({
    schema: 'nachuan.plugin-ui.snapshot.v1',
    slots: Object.freeze(slots)
  })
}
