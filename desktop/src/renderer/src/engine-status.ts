import type { EngineStatus } from './store'

export function canUseEngineRuntime(status: EngineStatus): boolean {
  return status === 'online' || status === 'degraded'
}
