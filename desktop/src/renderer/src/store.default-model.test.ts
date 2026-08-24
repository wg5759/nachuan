// #12：默认大脑选择——「纳川·智脑」(nachuan) 扶正为默认（推翻批5旧约束，先快后升兜底省配额）。
import { describe, expect, it } from 'vitest'
import {
  nativeExecBackendForModel,
  preferredChatModel,
  validatedModelSelection,
  type ModelInfo
} from './store'

const M = (id: string, tier?: string, owned_by?: string, modality = 'chat'): ModelInfo => ({
  id,
  tier,
  owned_by,
  modality
})

const FLEET = M('nachuan', 'premium', 'fleet')
const ULTRA = M('nachuan-ultra', 'premium', 'fleet')
const AGNES = M('agnes-flash', 'cheap', 'agnes')
const GLM = M('glm', 'premium', 'volcano')

describe('preferredChatModel（#12 纳川当默认大脑）', () => {
  it('有舰队时，全新状态默认选纳川·智脑，而不是强模型', () => {
    expect(preferredChatModel([AGNES, GLM, FLEET, ULTRA], null)).toBe('nachuan')
  })

  it('弱模型 agnes-flash 只是老兜底 → 有舰队时升为纳川', () => {
    expect(preferredChatModel([AGNES, GLM, FLEET], 'agnes-flash')).toBe('nachuan')
  })

  it('用户主动选的具体模型要保留，不被舰队顶掉', () => {
    expect(preferredChatModel([AGNES, GLM, FLEET], 'glm')).toBe('glm')
  })

  it('空版无舰队 → 退回强模型逻辑（不炸）', () => {
    expect(preferredChatModel([AGNES, GLM], null)).toBe('glm')
  })

  it('只有弱模型、无舰队无强模型 → 拿得到的最好一个', () => {
    expect(preferredChatModel([AGNES], null)).toBe('agnes-flash')
  })

  it('舰队不会被当默认排除到图/视频模型后面（舰队优先于一切自动兜底）', () => {
    const IMG = M('sd', 'premium', 'sd', 'image')
    expect(preferredChatModel([IMG, FLEET], null)).toBe('nachuan')
  })
})

describe('nativeExecBackendForModel（执行路由只信服务端元数据）', () => {
  it('只允许当前启用的 Codex 原生执行器，旧 Claude 元数据不能重新激活入口', () => {
    const models: ModelInfo[] = [
      { id: 'codex-spark', owned_by: 'custom-codex', exec_backend: 'codex' },
      { id: 'my-reviewer', owned_by: 'custom-claude', exec_backend: 'claude' },
      { id: 'claude-looking-name', owned_by: 'openai-compatible' }
    ]

    expect(nativeExecBackendForModel(models, 'codex-spark')).toBe('codex')
    expect(nativeExecBackendForModel(models, 'my-reviewer')).toBeUndefined()
    expect(nativeExecBackendForModel(models, 'claude-looking-name')).toBeUndefined()
  })
})

describe('validatedModelSelection', () => {
  it('accepts only an exact id from the live model allowlist', () => {
    expect(validatedModelSelection([FLEET, GLM], 'glm')).toBe('glm')
    expect(validatedModelSelection([FLEET, GLM], 'forged-model')).toBeNull()
    expect(validatedModelSelection([], 'glm')).toBeNull()
    expect(validatedModelSelection([FLEET, GLM], null)).toBeNull()
  })
})
