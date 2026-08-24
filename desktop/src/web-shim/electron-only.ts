// ADR-0013 Web 形态：Electron 专属能力的 fail-closed 适配。
// - 应用更新由 pip 承担：状态恒 {phase:'disabled', reason:'not-configured'}（UpdateToast 据此不渲染）；
// - 截图浮层 / 原生菜单 / 目录选择器在浏览器里不存在：返回明确的不可用形状或拒绝；
// - 事件订阅类一律返回 no-op 退订函数，UI 不炸；
// - saveMedia 用浏览器 a[download] 落盘本地字节；远程 https 媒体受同源/CSP 约束，如实报错。

import type { DesktopAPI, DesktopUpdateState } from '../renderer/src/env'

type ElectronOnlyApi = Pick<
  DesktopAPI,
  | 'getUpdateState'
  | 'checkForUpdates'
  | 'installVerifiedUpdate'
  | 'onUpdateState'
  | 'onSetView'
  | 'onAppCommand'
  | 'setLang'
  | 'snipBg'
  | 'startSnip'
  | 'pickDirectory'
  | 'saveMedia'
  | 'snipReady'
  | 'snipDone'
  | 'snipCancel'
  | 'onSnipResult'
>

const UPDATE_DISABLED: DesktopUpdateState = Object.freeze({
  phase: 'disabled',
  reason: 'not-configured'
})

function unavailableError(feature: string): Error {
  return new Error(`Web 形态不可用：${feature}（该能力仅桌面端提供）`)
}

const noop = (): void => {}

/** a[download] 所需的最小 DOM 面；测试注入替身，浏览器默认全局 document/URL。 */
export interface SaveMediaDom {
  createElement(tag: 'a'): {
    href: string
    download: string
    rel: string
    click(): void
    remove(): void
  }
  body: { appendChild(node: unknown): void }
}

export interface SaveMediaUrlApi {
  createObjectURL(blob: Blob): string
  revokeObjectURL(url: string): void
}

export interface ElectronOnlyDeps {
  readonly document?: SaveMediaDom
  readonly urlApi?: SaveMediaUrlApi
  readonly fetchImpl?: typeof fetch
}

export function createWebElectronOnlyApi(deps: ElectronOnlyDeps = {}): ElectronOnlyApi {
  async function saveMedia(p: {
    filename: string
    bytes?: ArrayBuffer
    url?: string
  }): Promise<{ ok: boolean; path?: string; error?: string }> {
    try {
      if (!p || typeof p.filename !== 'string' || p.filename.trim().length === 0) {
        return { ok: false, error: '文件名无效' }
      }
      const fetchImpl = deps.fetchImpl ?? ((input, init) => globalThis.fetch(input, init))
      let blob: Blob
      if (p.bytes instanceof ArrayBuffer) {
        blob = new Blob([p.bytes])
      } else if (typeof p.url === 'string' && /^(data:|blob:)/i.test(p.url)) {
        blob = await (await fetchImpl(p.url)).blob()
      } else if (typeof p.url === 'string' && /^https?:/i.test(p.url)) {
        return {
          ok: false,
          error: 'Web 形态受同源策略限制无法代下远程媒体；请在图片上右键另存'
        }
      } else {
        return { ok: false, error: '缺少可保存的媒体内容' }
      }
      const doc =
        deps.document ??
        (typeof document !== 'undefined' ? (document as unknown as SaveMediaDom) : undefined)
      const urlApi =
        deps.urlApi ??
        (typeof URL !== 'undefined' ? (URL as unknown as SaveMediaUrlApi) : undefined)
      if (!doc || !urlApi || typeof urlApi.createObjectURL !== 'function') {
        return { ok: false, error: '浏览器下载能力不可用' }
      }
      const objectUrl = urlApi.createObjectURL(blob)
      try {
        const anchor = doc.createElement('a')
        anchor.href = objectUrl
        anchor.download = p.filename
        anchor.rel = 'noopener'
        doc.body.appendChild(anchor)
        anchor.click()
        anchor.remove()
      } finally {
        // click 已同步发起下载；推迟回收避免竞态吞掉保存。
        setTimeout(() => urlApi.revokeObjectURL(objectUrl), 0)
      }
      return { ok: true, path: p.filename }
    } catch (error) {
      return { ok: false, error: error instanceof Error ? error.message : String(error) }
    }
  }

  return Object.freeze({
    getUpdateState: () => Promise.resolve(UPDATE_DISABLED),
    checkForUpdates: () => Promise.resolve(UPDATE_DISABLED),
    installVerifiedUpdate: () => Promise.resolve({ ok: false }),
    onUpdateState: () => noop,
    onSetView: () => noop,
    onAppCommand: () => noop,
    setLang: noop,
    snipBg: () => Promise.resolve(null),
    startSnip: () => Promise.resolve({ ok: false }),
    pickDirectory: () => Promise.reject(unavailableError('选择目录')),
    saveMedia,
    snipReady: noop,
    snipDone: noop,
    snipCancel: noop,
    onSnipResult: () => noop
  })
}
