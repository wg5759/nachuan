import type { PluginUiSnapshot } from '../plugin-ui-contract'
import { parsePluginUiSnapshot } from '../plugin-ui-contract'

type IpcEvent = object

export interface PluginUiIpcMain {
  handle(channel: string, listener: (event: IpcEvent, input?: unknown) => unknown): void
  removeHandler(channel: string): void
}

export interface PluginUiSession {
  pluginUiSnapshot(): Promise<unknown>
}

export function registerPluginUiIpc(
  ipc: PluginUiIpcMain,
  session: PluginUiSession,
  authorize: (event: IpcEvent) => void
): () => void {
  if (
    !ipc ||
    typeof ipc.handle !== 'function' ||
    typeof ipc.removeHandler !== 'function' ||
    !session ||
    typeof session.pluginUiSnapshot !== 'function' ||
    typeof authorize !== 'function'
  ) {
    throw new Error('Plugin UI IPC is unavailable')
  }
  ipc.handle(
    'plugin-ui:snapshot',
    async (event: IpcEvent, input?: unknown): Promise<PluginUiSnapshot> => {
      authorize(event)
      if (input !== undefined) throw new Error('Plugin UI IPC input is forbidden')
      return parsePluginUiSnapshot(await session.pluginUiSnapshot())
    }
  )
  return () => ipc.removeHandler('plugin-ui:snapshot')
}
