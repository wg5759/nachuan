import type { ModelInfo } from './store'

/**
 * Commit one successful `/v1/models` response and report that the slow refresh
 * cadence may resume. An empty list is a successful authoritative snapshot,
 * not a transport failure.
 */
export function commitSuccessfulModelRefresh(
  models: ModelInfo[],
  setModels: (models: ModelInfo[]) => void
): boolean {
  setModels(models)
  return true
}
