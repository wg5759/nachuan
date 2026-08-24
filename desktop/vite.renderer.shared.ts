import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import type { PluginOption } from 'vite'

// electron-vite renderer 与网关托管 Web 构建（ADR-0013）共用的 renderer 插件集。
// 工厂函数：每次构建返回全新插件实例，避免跨构建共享插件内部状态。
export function rendererPlugins(): PluginOption[] {
  return [react(), tailwindcss()]
}
