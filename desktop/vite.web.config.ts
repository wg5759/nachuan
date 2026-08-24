import { defineConfig } from 'vite'
import { rendererPlugins } from './vite.renderer.shared'

// ADR-0013：网关托管纯 Web 构建。复用 electron-vite renderer 的插件配置与
// src/renderer 同一份源码，仅替换 root/outDir；Electron 桌面构建不受影响。
//
// api-shim.js 以经典 script 注入 head 最前：经典脚本在解析期同步执行，
// 必然先于 defer 语义的 module app bundle 完成 window.api 安装。
// index.html 的 CSP（default-src 'self'）对同源经典脚本天然放行，无需放宽。
export default defineConfig({
  root: 'src/renderer',
  base: './',
  plugins: [
    ...rendererPlugins(),
    {
      name: 'nachuan-inject-api-shim',
      apply: 'build',
      transformIndexHtml: {
        // post：在 vite 完成 bundle 标签注入后再插入，避免 vite 尝试打包 shim。
        // 锚定 module bundle 标签之前（CSP meta 已在更前），保证：
        // 1. CSP meta 先于 shim 标签生效；2. 经典 shim 脚本先于 app bundle 加载。
        order: 'post',
        handler(html: string) {
          const marker = '<script type="module"'
          if (!html.includes(marker)) {
            throw new Error('api-shim injection anchor (module bundle script) not found')
          }
          return html.replace(marker, '<script src="./api-shim.js"></script>\n    ' + marker)
        }
      }
    }
  ],
  build: {
    outDir: '../../out-web',
    emptyOutDir: true
  }
})
