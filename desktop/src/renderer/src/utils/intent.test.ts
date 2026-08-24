import { describe, it, expect } from 'vitest'
import {
  isActionTask,
  isDailyVideoWorkflow,
  isImageRequest,
  isVideoRequest,
  isLapianRequest,
  isStudioRequest,
  isStudioConfirm,
  isTranslateRequest,
  isKbRequest,
  parseTranslate,
  isWebReadRequest,
  extractUrl,
  VIDEO_URL
} from './intent'

describe('意图识别正则（#22 回归兜底）', () => {
  it('画图意图：命中"画一只猫"、海报，但不误伤问句', () => {
    expect(isImageRequest('画一只赛博朋克的猫')).toBe(true)
    expect(isImageRequest('给我做张海报')).toBe(true)
    expect(isImageRequest('今天天气怎么样')).toBe(false)
  })

  it('生视频意图：命中"做个视频"，排除链接/提问/介绍', () => {
    expect(isVideoRequest('生成一段宣传短视频')).toBe(true)
    expect(isVideoRequest('这段视频链接帮我下载')).toBe(false)
    expect(isVideoRequest('视频是怎么剪的')).toBe(false)
    expect(isVideoRequest('做个产品介绍短视频')).toBe(false) // "介绍"=讲解，不当生视频
    expect(isVideoRequest('按流程去生成今天的视频')).toBe(false)
  })

  it('每日视频工作流：按 RUNBOOK 点火，不走普通视频生成或问答', () => {
    expect(isDailyVideoWorkflow('按流程去生成今天的视频')).toBe(true)
    expect(isDailyVideoWorkflow('日更点火渲染今日视频')).toBe(true)
    expect(isDailyVideoWorkflow('做个普通宣传视频')).toBe(false)
    expect(isVideoRequest('按流程去生成今天的视频')).toBe(false)
  })

  it('拉片意图：要有视频链接 + 拆解词', () => {
    expect(isLapianRequest('https://v.douyin.com/abc 帮我拉片拆解')).toBe(true)
    expect(isLapianRequest('帮我拆解这个想法')).toBe(false) // 没链接不触发
    expect(isLapianRequest('https://v.douyin.com/abc 这视频不错')).toBe(false) // 没拆解词
  })

  it('VIDEO_URL：从整段分享口令里抠出真链接', () => {
    const share = '5.89 复制打开抖音，看看 https://v.douyin.com/WGLStaiKxX4/ kcN:/ w@F.hB'
    const m = share.match(VIDEO_URL)
    expect(m?.[0]).toBe('https://v.douyin.com/WGLStaiKxX4/')
  })

  it('视频工作室 vs 单段视频：只认多镜头/分镜', () => {
    expect(isStudioRequest('做个多镜头短视频讲产品')).toBe(true)
    expect(isStudioRequest('分镜脚本帮我写一下')).toBe(true)
    expect(isStudioRequest('做个视频')).toBe(false)
  })

  it('工作室确认词：整句匹配确认，不误伤长句', () => {
    expect(isStudioConfirm('就这个')).toBe(true)
    expect(isStudioConfirm('开始')).toBe(true)
    expect(isStudioConfirm('把第二个镜头改成夜景')).toBe(false)
  })

  it('翻译意图 + 解析目标语种与待译文本', () => {
    expect(isTranslateRequest('翻译成英文：你好世界')).toBe(true)
    expect(isTranslateRequest('今天吃什么')).toBe(false)
    expect(parseTranslate('翻译成日语：早上好')).toEqual({ target: 'ja', text: '早上好' })
    expect(parseTranslate('翻成英文 hello')).toEqual({ target: 'en', text: 'hello' })
  })

  it('知识库意图：据我文档/知识库', () => {
    expect(isKbRequest('根据我的知识库回答产品定价')).toBe(true)
    expect(isKbRequest('我的文档里有没有提到这个')).toBe(true)
    expect(isKbRequest('随便聊聊')).toBe(false)
    expect(isKbRequest('知识库是什么')).toBe(false) // Codex 审 #3：光提"知识库"不算查库
  })

  it('动手任务：操作/文件/命令类', () => {
    expect(isActionTask('打开浏览器搜索一下天气')).toBe(true)
    expect(isActionTask('帮我在 D 盘建个文件夹')).toBe(true)
    expect(isActionTask('协同审查本地文件夹 D:\\AI视频制作 和 D:\\AI知识库')).toBe(false)
    expect(isActionTask('马上查看我这个项目是什么原因')).toBe(false)
    expect(isActionTask('按流程去生成今天的视频')).toBe(true)
    expect(isActionTask('帮我写一首诗')).toBe(false)
    expect(isActionTask('检查这段话的逻辑')).toBe(false)
    expect(isActionTask('搜索算法是什么')).toBe(false)
    expect(isActionTask('分析方案')).toBe(false)
    expect(isActionTask('解释 D:\\foo 这个路径含义')).toBe(false)
    expect(isActionTask('比较 C:\\a 与 D:\\b')).toBe(false)
    expect(isActionTask('你是谁')).toBe(false)
  })

  it('网页抓正文：非视频链接 + 读/总结，或裸链接；视频链接归拉片', () => {
    expect(isWebReadRequest('帮我读下这篇 https://example.com/post')).toBe(true)
    expect(isWebReadRequest('https://example.com')).toBe(true) // 裸链接
    expect(isWebReadRequest('总结 https://news.site/a 这个网页')).toBe(true)
    expect(isWebReadRequest('https://v.douyin.com/abc 拉片')).toBe(false) // 视频→拉片
    expect(isWebReadRequest('今天天气怎么样')).toBe(false) // 没链接
    expect(extractUrl('看看 https://example.com/x。')).toBe('https://example.com/x')
  })
})
