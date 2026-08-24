// ADR-0013 Web 形态：登录闸。
// 无运行时 Key（首次接入）或鉴权 401（已存 Key 被网关拒绝）时，在页面注入
// 极简密钥录入视图：运行时 Key 必填、审批 Key 选填但付费/管理操作需要；验证（GET /v1/models 2xx）
// 通过后存当前标签页 sessionStorage 并重载应用。绝不清动其他业务数据，
// 密钥不回显（password 输入）、不打日志、不进 URL。

import type { CredentialStore } from './credentials'

export type LoginGateReason = 'missing' | 'unauthorized'

export interface LoginGateDeps {
  readonly credentials: CredentialStore
  /** 用候选运行时 Key 探测 GET /v1/models；2xx 视为网关接受。 */
  readonly verify: (runtimeKey: string) => Promise<boolean>
  /** 密钥保存成功后的应用重放（生产为 location.reload()，测试注入替身）。 */
  readonly reload: () => void
  /** 测试注入替身；缺省取全局 document。 */
  readonly doc?: GateDocument
}

export interface LoginGate {
  show(reason: LoginGateReason): void
  hide(): void
  readonly visible: boolean
}

/** 登录闸用到的最小 DOM 面（fake 友好）。 */
export interface GateElement {
  style: Record<string, string>
  textContent: string
  appendChild(child: GateElement): void
  addEventListener(type: string, listener: (event: { preventDefault(): void }) => void): void
  remove(): void
}

export interface GateInput extends GateElement {
  type: string
  placeholder: string
  value: string
  disabled: boolean
}

export interface GateDocument {
  body: GateElement | null
  createElement(tag: string): GateElement
  addEventListener(type: string, listener: () => void, options?: { once: boolean }): void
}

const REASON_TEXT: Record<LoginGateReason, string> = {
  missing:
    '首次接入：请输入本机网关运行时 Key；付费媒体、审批、连接与同步还需独立审批 Key。',
  unauthorized: '当前标签页的访问密钥被网关拒绝，请重新录入。'
}

function resolveDoc(deps: LoginGateDeps): GateDocument | null {
  if (deps.doc) return deps.doc
  if (typeof document !== 'undefined') return document as unknown as GateDocument
  return null
}

export function createLoginGate(deps: LoginGateDeps): LoginGate {
  let overlay: GateElement | null = null
  let pending = false

  function mount(doc: GateDocument, reason: LoginGateReason): void {
    const box = doc.createElement('div')
    Object.assign(box.style, {
      position: 'fixed',
      inset: '0',
      zIndex: '2147483647',
      background: 'rgba(246,247,251,0.88)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '16px',
      backdropFilter: 'blur(16px)',
      fontFamily:
        '"Segoe UI Variable", "Segoe UI", "Microsoft YaHei", "PingFang SC", system-ui, sans-serif'
    })

    const panel = doc.createElement('div')
    Object.assign(panel.style, {
      background: '#ffffff',
      color: '#171921',
      borderRadius: '18px',
      border: '1px solid #e2e5ed',
      boxShadow: '0 22px 64px rgba(24,27,42,0.16)',
      padding: '28px',
      width: 'min(420px, calc(100vw - 32px))',
      boxSizing: 'border-box'
    })

    const title = doc.createElement('div')
    title.textContent = '纳川 · 接入本地网关'
    Object.assign(title.style, {
      fontSize: '20px',
      fontWeight: '700',
      letterSpacing: '-0.02em',
      marginBottom: '8px'
    })

    const desc = doc.createElement('div')
    desc.textContent = REASON_TEXT[reason]
    Object.assign(desc.style, {
      fontSize: '12px',
      lineHeight: '1.65',
      color: '#737887',
      marginBottom: '20px'
    })

    const runtimeInput = doc.createElement('input') as GateInput
    runtimeInput.type = 'password'
    runtimeInput.placeholder = '运行时 Key（必填）'
    runtimeInput.value = ''
    Object.assign(runtimeInput.style, inputStyle())

    const approvalInput = doc.createElement('input') as GateInput
    approvalInput.type = 'password'
    approvalInput.placeholder = deps.credentials.getApprovalKey()
      ? '审批 Key（已保存；留空保持不变）'
      : '审批 Key（付费媒体/审批/连接/同步需要）'
    approvalInput.value = ''
    Object.assign(approvalInput.style, inputStyle())

    const errorLine = doc.createElement('div')
    errorLine.textContent = ''
    Object.assign(errorLine.style, {
      fontSize: '12px',
      color: '#c84747',
      lineHeight: '1.45',
      minHeight: '18px',
      marginBottom: '12px'
    })

    const submitButton = doc.createElement('button') as GateInput
    submitButton.textContent = '接入'
    Object.assign(submitButton.style, {
      width: '100%',
      minHeight: '42px',
      padding: '9px 0',
      borderRadius: '11px',
      border: 'none',
      background: '#5557d9',
      color: '#ffffff',
      boxShadow: '0 8px 18px rgba(78,80,206,0.20)',
      fontWeight: '650',
      cursor: 'pointer'
    })

    const setError = (message: string): void => {
      errorLine.textContent = message
    }

    const submit = (): void => {
      if (pending) return
      const runtimeKey = runtimeInput.value.trim()
      if (!runtimeKey) {
        setError('运行时 Key 必填')
        return
      }
      pending = true
      submitButton.disabled = true
      setError('')
      void deps
        .verify(runtimeKey)
        .then((accepted) => {
          if (!accepted) {
            setError('网关未接受该运行时 Key（GET /v1/models 未返回 2xx）')
            return
          }
          try {
            deps.credentials.save(
              runtimeKey,
              approvalInput.value.trim() ? approvalInput.value : undefined
            )
          } catch (error) {
            setError(error instanceof Error ? error.message : String(error))
            return
          }
          api.hide()
          deps.reload()
        })
        .catch((error: unknown) => {
          setError(error instanceof Error ? error.message : String(error))
        })
        .finally(() => {
          pending = false
          submitButton.disabled = false
        })
    }

    submitButton.addEventListener('click', submit)
    for (const input of [runtimeInput, approvalInput]) {
      input.addEventListener('keydown', (event) => {
        if ((event as unknown as { key?: string }).key === 'Enter') submit()
      })
    }

    panel.appendChild(title)
    panel.appendChild(desc)
    panel.appendChild(runtimeInput)
    panel.appendChild(approvalInput)
    panel.appendChild(errorLine)
    panel.appendChild(submitButton)
    box.appendChild(panel)
    doc.body?.appendChild(box)
    overlay = box
  }

  function inputStyle(): Record<string, string> {
    return {
      width: '100%',
      boxSizing: 'border-box',
      minHeight: '42px',
      padding: '9px 11px',
      marginBottom: '11px',
      borderRadius: '10px',
      border: '1px solid #d3d7e2',
      outline: 'none',
      background: '#f8f9fc',
      color: '#3d4150'
    }
  }

  const api: LoginGate = {
    show(reason: LoginGateReason): void {
      if (overlay) return
      const doc = resolveDoc(deps)
      if (!doc) return
      if (doc.body) {
        mount(doc, reason)
      } else {
        // shim 先于 body 解析执行：等 DOMContentLoaded 再注入。
        doc.addEventListener('DOMContentLoaded', () => api.show(reason), { once: true })
      }
    },
    hide(): void {
      overlay?.remove()
      overlay = null
    },
    get visible(): boolean {
      return overlay !== null
    }
  }
  return api
}
