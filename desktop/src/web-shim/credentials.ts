// ADR-0013 Web 形态：网关访问密钥的浏览器侧存取。
//
// 纪律：
// - key 只经 Authorization / X-Nachuan-Approval-Key 头出站，绝不进 URL query、不打日志；
// - 本模块只读写自己名下的两个 sessionStorage 项，绝不清动其他业务数据；
//   sessionStorage 跨同一标签页 reload 保留，但关闭标签页即失效，避免把长期密钥
//   明文落入 durable localStorage；
// - 存储不可用（隐私模式等）时读取返回 null、保存显式报错，不静默吞。

const RUNTIME_KEY_ITEM = 'nachuan.web.runtimeKey'
const APPROVAL_KEY_ITEM = 'nachuan.web.approvalKey'

export interface KeyValueStorage {
  getItem(key: string): string | null
  setItem(key: string, value: string): void
  removeItem(key: string): void
}

export interface CredentialStore {
  getRuntimeKey(): string | null
  getApprovalKey(): string | null
  /** 审批 Key：undefined=保留，null/空串=明确移除，字符串=替换。 */
  save(runtimeKey: string, approvalKey: string | null | undefined): void
}

function defaultStorage(): KeyValueStorage | null {
  try {
    const candidate = (globalThis as { sessionStorage?: KeyValueStorage }).sessionStorage
    return candidate ?? null
  } catch {
    return null
  }
}

function clearLegacyDurableStorage(): void {
  try {
    const legacy = (globalThis as { localStorage?: KeyValueStorage }).localStorage
    legacy?.removeItem(RUNTIME_KEY_ITEM)
    legacy?.removeItem(APPROVAL_KEY_ITEM)
  } catch {
    // Access can be denied by browser privacy policy.  The active store remains
    // sessionStorage and never falls back to durable localStorage.
  }
}

function normalize(value: string | null | undefined): string | null {
  if (typeof value !== 'string') return null
  const trimmed = value.trim()
  return trimmed.length > 0 ? trimmed : null
}

function read(storage: () => KeyValueStorage | null, key: string): string | null {
  try {
    return normalize(storage()?.getItem(key))
  } catch {
    return null
  }
}

export function createCredentialStore(
  storage: () => KeyValueStorage | null = defaultStorage
): CredentialStore {
  if (storage === defaultStorage) clearLegacyDurableStorage()
  return Object.freeze({
    getRuntimeKey: () => read(storage, RUNTIME_KEY_ITEM),
    getApprovalKey: () => read(storage, APPROVAL_KEY_ITEM),
    save: (runtimeKey: string, approvalKey: string | null) => {
      const target = storage()
      if (!target) throw new Error('浏览器标签页会话存储不可用，无法保存访问密钥')
      const runtime = normalize(runtimeKey)
      if (!runtime) throw new Error('运行时 Key 不能为空')
      target.setItem(RUNTIME_KEY_ITEM, runtime)
      if (approvalKey === undefined) return
      const approval = normalize(approvalKey)
      if (approval) target.setItem(APPROVAL_KEY_ITEM, approval)
      else target.removeItem(APPROVAL_KEY_ITEM)
    }
  })
}
