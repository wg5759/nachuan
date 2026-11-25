import { isAbsolute, join } from 'node:path'

export function localPreviewPaths(isPackaged: boolean, requested: string | undefined, projectRoot: string) {
  if (!requested) return null
  if (isPackaged || requested !== 'LOCAL_ONLY' || !isAbsolute(projectRoot)) {
    throw new Error('LOCAL_PREVIEW_REQUIRES_EXPLICIT_SOURCE_MODE')
  }
  const userData = join(projectRoot, '安装与维护', '本机桌面体验版', '用户数据')
  return { userData, data: join(userData, 'data'), workspaces: join(userData, 'workspaces') }
}

export function localPreviewEngineEnvironment(paths: NonNullable<ReturnType<typeof localPreviewPaths>>) {
  return {
    NACHUAN_CONFIG_ENV_ONLY: '1',
    DATA_DIR: paths.data,
    USAGE_DB_PATH: join(paths.data, 'usage.db'),
    NACHUAN_CONNECTIONS_PATH: join(paths.data, 'connections.json'),
    NACHUAN_PROVIDER_CALL_LEDGER_PATH: join(paths.data, 'provider-calls.db'),
    NACHUAN_PROVIDER_CALL_LEDGER_MODE: 'required',
    AGENT_EXEC_WORKDIR: paths.workspaces,
    NACHUAN_GUARD_HOME: paths.workspaces,
    SEMCACHE_DB_DIR: join(paths.data, 'semcache')
  }
}
