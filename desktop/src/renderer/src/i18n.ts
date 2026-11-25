import React, { createContext, useContext, useMemo, useSyncExternalStore } from 'react'
import i18n, { type i18n as I18nInstance, type TFunction, type ThirdPartyModule } from 'i18next'
import zh from './locales/zh.json'
import en from './locales/en.json'

export type SupportedLanguage = 'zh' | 'en'

export const LANG_STORAGE_KEY = 'nachuan-language'
export const LANGUAGE_STORAGE_KEY = LANG_STORAGE_KEY

interface I18nSubscriptionBucket {
  version: number
  listeners: Set<() => void>
  attached: boolean
}

const subscriptionBuckets = new WeakMap<I18nInstance, I18nSubscriptionBucket>()

function getBucket(instance: I18nInstance): I18nSubscriptionBucket {
  let bucket = subscriptionBuckets.get(instance)
  if (!bucket) {
    bucket = { version: 0, listeners: new Set(), attached: false }
    subscriptionBuckets.set(instance, bucket)
  }
  return bucket
}

function attachInstanceEvents(instance: I18nInstance, bucket: I18nSubscriptionBucket): void {
  if (bucket.attached) return
  bucket.attached = true
  const notify = (): void => {
    bucket.version += 1
    for (const listener of bucket.listeners) listener()
  }
  instance.on('languageChanged', notify)
  instance.on('loaded', notify)
  instance.on('initialized', notify)
  instance.store?.on('added', notify)
  instance.store?.on('removed', notify)
}

function subscribeI18n(instance: I18nInstance, listener: () => void): () => void {
  const bucket = getBucket(instance)
  attachInstanceEvents(instance, bucket)
  bucket.listeners.add(listener)
  return () => {
    bucket.listeners.delete(listener)
  }
}

function getI18nSnapshot(instance: I18nInstance): string {
  const bucket = getBucket(instance)
  return `${instance.language ?? ''}:${instance.resolvedLanguage ?? ''}:${bucket.version}`
}

interface I18nContextValue {
  i18n: I18nInstance
  defaultNS?: string | string[]
}

const I18nContext = createContext<I18nContextValue | null>(null)

/**
 * 轻量级无依赖兼容插件：保持与历史 `.use(initReactI18next)` 调用方式 100% 兼容，
 * 同时彻底消除 `react-i18next` → `html-parse-stringify`（无上游 LICENSE 文件）依赖链。
 */
export const initReactI18next: ThirdPartyModule = {
  type: '3rdParty',
  init(): void {
    // React 绑定通过下方的 useSyncExternalStore + Context 完成，无需额外插件钩子。
  }
}

export interface I18nextProviderProps {
  i18n: I18nInstance
  defaultNS?: string | string[]
  children?: React.ReactNode
}

export function I18nextProvider({
  i18n: instance,
  defaultNS,
  children
}: I18nextProviderProps): React.ReactElement {
  const value = useMemo<I18nContextValue>(
    () => ({ i18n: instance, defaultNS }),
    [instance, defaultNS]
  )
  return React.createElement(I18nContext.Provider, { value }, children)
}

export interface UseTranslationResponse {
  t: TFunction
  i18n: I18nInstance
  ready: boolean
}

export function useTranslation(ns?: string | string[]): UseTranslationResponse {
  const ctx = useContext(I18nContext)
  const instance = ctx?.i18n ?? i18n
  const effectiveNs = ns ?? ctx?.defaultNS

  const snapshot = useSyncExternalStore(
    (onStoreChange) => subscribeI18n(instance, onStoreChange),
    () => getI18nSnapshot(instance),
    () => `${instance.language ?? ''}:${instance.resolvedLanguage ?? ''}:ssr`
  )

  const t = useMemo<TFunction>(() => {
    // 依赖 snapshot 确保语言或资源变更后 t 引用随之刷新，驱动所有下游 Hook 与 memo 更新。
    void snapshot
    return instance.getFixedT(instance.language || null, effectiveNs ?? null)
  }, [instance, effectiveNs, snapshot])

  return {
    t,
    i18n: instance,
    ready: Boolean(instance.isInitialized)
  }
}

function normalizeSupportedLanguage(raw: unknown): SupportedLanguage | null {
  if (typeof raw !== 'string') return null
  const trimmed = raw.trim().toLowerCase()
  if (!trimmed) return null
  if (trimmed.startsWith('zh')) return 'zh'
  if (trimmed.startsWith('en')) return 'en'
  return null
}

function readStoredLanguage(
  storage?: Pick<Storage, 'getItem'> | null
): SupportedLanguage | null {
  const target = storage ?? (typeof localStorage !== 'undefined' ? localStorage : null)
  if (!target) return null
  try {
    return normalizeSupportedLanguage(target.getItem(LANG_STORAGE_KEY))
  } catch {
    return null
  }
}

export function persistLanguagePreference(
  language: SupportedLanguage,
  storage?: Pick<Storage, 'setItem'> | null
): void {
  const target = storage ?? (typeof localStorage !== 'undefined' ? localStorage : null)
  if (!target) return
  try {
    target.setItem(LANG_STORAGE_KEY, language)
  } catch {
    /* 忽略受限存储环境的写入错误 */
  }
}

export const savePreferredLanguage = persistLanguagePreference

/**
 * 国际化默认语言自动检测：
 * 1. 若用户已手动在设置页选择过语言（存储在 localStorage），优先尊重用户设定；
 * 2. 否则依据浏览器 / 操作系统 navigator.languages / navigator.language 自动判断：
 *    中文区域（zh*）展示简体中文，其余国际区域默认展示专业英文界面；
 * 3. 无 navigator 信息时回退 fallback（detectPreferredLanguage 默认 'zh'，detectInitialLanguage 默认 'en'）。
 */
function resolvePreferredLanguage(
  options:
    | {
        storedLanguage?: string | null
        savedLanguage?: string | null
        storage?: Pick<Storage, 'getItem'> | null
        navigatorLanguages?: readonly string[] | null
        navigatorLanguage?: string | null
      }
    | undefined,
  emptyFallback: SupportedLanguage
): SupportedLanguage {
  const hasExplicitStored =
    options !== undefined &&
    ('storedLanguage' in options || 'savedLanguage' in options)
  const explicitStored = hasExplicitStored
    ? normalizeSupportedLanguage(options?.storedLanguage ?? options?.savedLanguage)
    : readStoredLanguage(options?.storage)
  if (explicitStored) return explicitStored

  const candidates: string[] = []
  const nav = typeof globalThis !== 'undefined' ? globalThis.navigator : undefined
  const languages =
    options && 'navigatorLanguages' in options ? options.navigatorLanguages : nav?.languages
  if (Array.isArray(languages)) {
    for (const item of languages) {
      if (typeof item === 'string' && item.trim()) candidates.push(item.trim().toLowerCase())
    }
  }
  const primary =
    options && 'navigatorLanguage' in options ? options.navigatorLanguage : nav?.language
  if (typeof primary === 'string' && primary.trim()) {
    candidates.push(primary.trim().toLowerCase())
  }

  for (const tag of candidates) {
    if (tag.startsWith('zh')) return 'zh'
    return 'en'
  }
  return emptyFallback
}

export function detectPreferredLanguage(options?: {
  storedLanguage?: string | null
  storage?: Pick<Storage, 'getItem'> | null
  navigatorLanguages?: readonly string[] | null
  navigatorLanguage?: string | null
}): SupportedLanguage {
  return resolvePreferredLanguage(options, 'zh')
}

export function detectInitialLanguage(options?: {
  savedLanguage?: string | null
  storage?: Pick<Storage, 'getItem'> | null
  navigatorLanguages?: readonly string[] | null
  navigatorLanguage?: string | null
}): SupportedLanguage {
  const hasPrimaryOverride = options !== undefined && 'navigatorLanguage' in options
  const normalizedOptions =
    hasPrimaryOverride && !('navigatorLanguages' in options)
      ? { ...options, navigatorLanguages: null }
      : options
  return resolvePreferredLanguage(normalizedOptions, 'en')
}

export async function setAppLanguage(
  language: SupportedLanguage,
  storage?: Pick<Storage, 'setItem'> | null
): Promise<void> {
  persistLanguagePreference(language, storage)
  await i18n.changeLanguage(language)
}

void i18n.init({
  resources: {
    zh: { translation: zh },
    en: { translation: en }
  },
  lng: detectPreferredLanguage(),
  fallbackLng: 'en',
  interpolation: { escapeValue: false }
})

export default i18n
