// ADR-0013：把 src/web-shim（window.api 的 HTTP 适配层）构建为经典 IIFE 脚本
// out-web/api-shim.js。必须在 renderer Web 构建之后运行（renderer 构建会清空 out-web）。
import { build } from 'vite'
import { cp, rm } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import path from 'node:path'

const desktopRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const projectRoot = path.resolve(desktopRoot, '..')
const outWebRoot = path.resolve(desktopRoot, 'out-web')
const bundledWebRoot = path.resolve(projectRoot, 'gateway', 'web_ui')

await build({
  root: desktopRoot,
  configFile: false,
  logLevel: 'warn',
  build: {
    outDir: 'out-web',
    emptyOutDir: false,
    minify: 'esbuild',
    lib: {
      entry: path.join(desktopRoot, 'src/web-shim/index.ts'),
      formats: ['iife'],
      name: 'NachuanWebShim',
      fileName: () => 'api-shim.js'
    }
  }
})

// wheel 只能携带 Python package 目录内的数据。Web 构建完成后把同一份确定性
// 产物同步进 gateway/web_ui；网关安装后可直接从自身包目录托管，不依赖源码仓库。
if (path.dirname(bundledWebRoot) !== path.resolve(projectRoot, 'gateway')) {
  throw new Error(`refusing to replace unexpected bundled Web UI path: ${bundledWebRoot}`)
}
await rm(bundledWebRoot, { recursive: true, force: true })
await cp(outWebRoot, bundledWebRoot, { recursive: true })
