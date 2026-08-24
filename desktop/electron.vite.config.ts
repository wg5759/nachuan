import { defineConfig, externalizeDepsPlugin } from 'electron-vite'
import { rendererPlugins } from './vite.renderer.shared'

export default defineConfig({
  main: {
    plugins: [externalizeDepsPlugin()]
  },
  preload: {
    plugins: [externalizeDepsPlugin()]
  },
  renderer: {
    plugins: rendererPlugins()
  }
})
