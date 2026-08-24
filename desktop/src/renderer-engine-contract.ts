const RENDERER_ENGINE_REQUEST_ID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

/** Closed request-id boundary shared by Electron IPC and the local Web adapter. */
export function isRendererEngineRequestId(value: unknown): value is string {
  return typeof value === 'string' && RENDERER_ENGINE_REQUEST_ID.test(value)
}
