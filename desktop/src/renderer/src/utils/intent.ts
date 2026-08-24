// 聊天框意图识别（前端快速正则；昂贵动作再用 /v1/intent 模型确认，见 #17）。
// 抽到独立模块是为了可单测（#22）——这些正则是误触发高风险点，必须有回归测试兜底。

// 每日视频工作流：这是 D:\AI视频制作 的 RUNBOOK 点火，不是“随便生成一段视频”。
export const isDailyVideoWorkflow = (s: string): boolean =>
  /按流程|工作流|RUNBOOK|runbook|日更|每日/.test(s) &&
  /今天的视频|今日视频|今天.*视频|今日.*视频|生成.*视频|渲染.*视频|点火/.test(s)

// 只识别“明确要求改变外部状态”的动手任务。分析/查看/搜索/写文章等模糊自然语言
// 必须留在 advisory，不能因为宽正则自动获得工具能力。
export const isActionTask = (s: string): boolean =>
  isDailyVideoWorkflow(s) ||
  /打开(浏览器|网页|网站|文件|目录)|点击|登录|填写|下单|下载|抓取|爬取|截图|安装|部署|运行|执行|跑(个|一下)?命令|上传|提交|推送|发布|写入|保存|覆盖|删除|移动|重命名|创建(文件|目录|文件夹)|新建(文件|目录|文件夹)|修改(文件|代码|配置)|改(文件|代码|配置)|读写文件|在.+(建|创建|新建).*(文件|目录|文件夹)/.test(
    s
  )

// 粗判"画图"意图——自动智能据此直接调图模型生成，把成品贴进聊天（像飞书那样）。
export const isImageRequest = (s: string): boolean =>
  /画(个|张|幅|只|一|条|头|副|出|成|的|得)|绘制|draw\b|paint/i.test(s) ||
  (/图片?|插画|海报|logo|头像|壁纸|配图|image|picture/i.test(s) &&
    /生成|做|搞|来|给我|create|make|generate/i.test(s))

// 粗判"生视频"意图——排除"怎么/链接/下载"等（那些更像提问/拉片）。
export const isVideoRequest = (s: string): boolean =>
  /视频|短视频|video|短片|影片|动图/i.test(s) &&
  !isDailyVideoWorkflow(s) &&
  !/怎么|如何|为什么|是不是|介绍|讲解|解读|总结|看这|看那|这段|那段|链接|地址|下载|按流程|流程|工作流|RUNBOOK|runbook|日更|今天的视频|今日视频/.test(s)

// 视频链接（抖音/油管/B站/快手/小红书等）——拉片意图判定用；顺带从整段分享口令里抠出真链接。
export const VIDEO_URL =
  /https?:\/\/[^\s，。、）)】」]*(douyin|tiktok|youtube|youtu\.be|bilibili|b23\.tv|kuaishou|xiaohongshu|xhslink|weibo|v\.qq|ixigua|vimeo|\.mp4|\.mov)[^\s，。、）)】」]*/i

// 粗判"拉片"意图——消息里有视频链接 + 拆解类词 → 自动下视频逐帧拆成拉片报告。
export const isLapianRequest = (s: string): boolean =>
  VIDEO_URL.test(s) &&
  /拉片|拆解|复刻|分镜|逐帧|解析|分析|怎么拍|怎么做的|脚本|sop|学(它|这|一下)/i.test(s)

// 粗判"视频工作室"意图（多镜头成片，区别于单段生视频）——只认明确的多镜头/分镜词，避免误触发慢流程。
export const isStudioRequest = (s: string): boolean =>
  /多镜头|分镜|镜头脚本|视频工作室|逐镜|混剪|口播视频|系列镜头|一镜到底/i.test(s)

// 视频工作室方案确认词：用户看完分镜回这些 → 开始成片；否则当作"改方案"的反馈
export const isStudioConfirm = (s: string): boolean =>
  /^(就这个|就这|开始|可以|确认|成片|好的?|行|ok|go|生成吧?|做吧|开干|没问题)$/i.test(s.trim())

// 粗判"翻译"意图——"翻译成X：文本 / 翻成英文" → 调翻译接口贴回译文。
export const isTranslateRequest = (s: string): boolean =>
  /^(请?帮?我?)?(翻译|翻成|译成|translate)\b/i.test(s.trim()) ||
  /翻译(成|为|一下|下)|翻成[中英日韩法德西俄]|译成[中英日韩法德西俄]/i.test(s)

// 目标语种识别（默认英文）
const TRANSLATE_LANG: Array<[RegExp, string]> = [
  [/英文|英语|english/i, 'en'],
  [/中文|汉语|chinese/i, 'zh'],
  [/日文|日语|japanese/i, 'ja'],
  [/韩文|韩语|korean/i, 'ko'],
  [/法文|法语|french/i, 'fr'],
  [/德文|德语|german/i, 'de'],
  [/西班牙|spanish/i, 'es'],
  [/俄文|俄语|russian/i, 'ru']
]

// 从"翻成英文：你好"里抠出 {目标语种, 待译文本}；待译为空则由调用方回退到上一条回复。
export const parseTranslate = (s: string): { target: string; text: string } => {
  let target = 'en'
  for (const [re, code] of TRANSLATE_LANG) {
    if (re.test(s)) {
      target = code
      break
    }
  }
  const text = s
    .replace(
      /^(请?帮?我?)?(把(这段|下面的?)?)?(翻译|翻成|译成|translate(\s+to)?)\s*[成为给]?\s*(英文|英语|english|中文|汉语|chinese|日文|日语|japanese|韩文|韩语|korean|法文|法语|french|德文|德语|german|西班牙\w*|spanish|俄文|俄语|russian)?\s*[：:，,。\s]*/i,
      ''
    )
    .trim()
  return { target, text }
}

// 粗判"知识库问答"——"据我文档/根据知识库/我资料里" → 走本地知识库检索回答。
export const isKbRequest = (s: string): boolean =>
  // 要有「据/根据…文档/知识库」语境；光提到"知识库"不算（Codex 审 #3，与引擎 _fallback_rule 同步）
  /(根据|据|按照|结合|参考)(我的?|本地)?(文档|资料|知识库|笔记|档案)|我(的)?(文档|资料|笔记|档案)(里|中)/i.test(
    s
  )

// 任意 http(s) 链接（网页抓正文用；视频链接归拉片，不在这）
export const ANY_URL = /https?:\/\/[^\s，。、）)】」]+/i
// 从一段话里抠出第一个链接（去掉尾部中英标点）
export const extractUrl = (s: string): string =>
  (s.match(ANY_URL)?.[0] || s).replace(/[，。、）)】」"']+$/, '')
// 粗判"读网页"意图——有非视频链接 + 读/总结类词，或整条消息基本就是个裸链接。
export const isWebReadRequest = (s: string): boolean => {
  if (!ANY_URL.test(s) || VIDEO_URL.test(s)) return false // 没链接、或视频链接(归拉片)→不是
  const rest = s.replace(ANY_URL, '').trim()
  return (
    /读|看看|看下|看一下|总结|概括|解析|抓|讲了?什么|说了?什么|什么内容|这篇|这个?链接|这网页|网页|介绍下?/.test(
      rest
    ) || rest.length < 6 // 基本就一个裸链接
  )
}
