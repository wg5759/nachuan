"""厂商预设目录（连接中心的"选厂商"来源）。

设计：绝大多数厂商都是 OpenAI 兼容（type=openai_compat），只需 base_url + Key + 模型。
- base_url 均可在 UI 里改（厂商偶尔调整）；不确定的标注 note。
- models 只给少量常用示例；连接后可用「拉取模型列表」实时获取（厂商支持 /v1/models 时）。
- type 决定引擎用哪个 provider 实现：
    openai_compat → 通用直连（已支持）
    codex         → 独立进程树内的只读文本 worker；不暴露主机 agent 工具
- region：cn 国内 / intl 海外 / local 本地
- auth：api_key 填密钥 / login 登录(订阅) / none 无需(本地)
"""

from __future__ import annotations

from typing import Any


# actual_served 展示值的闭集：今天两条订阅线都只能如实标 unproven；
# 未来某条官方线文真的能回执服役型号时再扩集合并附捕获证据。
_ACTUAL_SERVED_DISPLAY_VALUES = frozenset({"unproven"})


def rank_sort_key(value: Any) -> tuple[int, int]:
    """Return a stable ascending preference key for model ``rank`` metadata.

    Positive integers are explicit ranks (smaller is preferred).  ``0``, missing,
    malformed, boolean, negative, and fractional values are unranked and therefore
    sort after every explicit rank.  ``flagship`` is an independent policy signal;
    callers that may use a flagship must order that field separately.
    """
    if value is None or isinstance(value, bool):
        return (1, 0)
    if isinstance(value, float) and not value.is_integer():
        return (1, 0)
    try:
        rank = int(value)
    except (TypeError, ValueError, OverflowError):
        return (1, 0)
    return (0, rank) if rank > 0 else (1, 0)


def _m(
    mid: str, upstream: str, desc: str = "", tier: str = "default", modality: str = "chat",
    rank: int = 0, flagship: bool = False, tool_capable: bool = True,
    skills: list[str] | None = None, actual_served: str | None = None,
) -> dict[str, Any]:
    # rank：同档位内偏好（越小越优先，0=未排→兜底排最后）；flagship：王牌，仅「最强」显式动用，
    # 自动路由不烧它。让选型按「档位+偏好」动态决定，不在代码里写死型号名（厂商升版本也不过时）。
    # tool_capable：能否稳定 function-calling（编排器"带工具执行/审核官"择模型时据此过滤）；
    # 默认 True，本地/GGUF 等工具调用不可靠的模型可显式置 False。
    # skills：能力标签（如 ["code","math","zh","long","vision","tools"]），供「点将官」按题型择将；
    # 这是**数据**不是逻辑（不写死型号名做判断），未标注默认 []。
    # actual_served：纯展示字段，标记该渠道线文能否回执实际服役型号；缺省不出现该键，
    # 订阅 CLI（官方线文无型号字段）必须显式标 "unproven"，不得写任何型号名。
    entry = {
        "id": mid,
        "upstream_model": upstream,
        "tier": tier,
        "description": desc,
        "modality": modality,
        "rank": rank,
        "flagship": flagship,
        "tool_capable": tool_capable,
        "skills": skills or [],
    }
    if actual_served is not None:
        if actual_served not in _ACTUAL_SERVED_DISPLAY_VALUES:
            raise ValueError("actual_served 展示值不受支持")
        entry["actual_served"] = actual_served
    return entry


PROVIDER_PRESETS: list[dict[str, Any]] = [
    {
        "name": "kimi-code",
        "label": "Kimi Code（订阅 · 本机登录）",
        "region": "cn",
        "type": "kimi_code",
        "auth": "login",
        "base_url": "",
        "note": (
            "复用官方 Kimi Code 登录；只读文本会话，不接受 Moonshot API Key，"
            "实际服务型号不作虚假声明。"
        ),
        "models": [
            _m(
                "kimi-code-subscription",
                "kimi-code-subscription",
                "Kimi Code 订阅 · 账号服务模型（实际型号不作虚假声明）",
                "premium",
                tool_capable=False,
                skills=["code", "reasoning"],
                actual_served="unproven",
            ),
        ],
    },
    # ── 订阅 / 本机 CLI ──
    {
        "name": "codex", "label": "Codex（订阅 · 本机登录）", "region": "intl",
        "type": "codex", "auth": "login", "base_url": "",
        "note": "复用官方 Codex 登录；只读文本会话，不读取登录文件、不开放主机工具",
        "models": [
            _m(
                "codex-subscription",
                "codex-subscription-default",
                "Codex 订阅 · 账号默认模型（实际型号不作虚假声明）",
                "premium",
                tool_capable=False,
                skills=["code", "reasoning"],
                actual_served="unproven",
            ),
        ],
    },
    # ── 国内 ──
    {
        "name": "volcano", "label": "火山方舟 (Coding Plan)", "region": "cn",
        "type": "volcano", "auth": "api_key",
        "base_url": "https://ark.cn-beijing.volces.com/api/coding/v3",
        "note": "Coding Plan 用 /api/coding/v3；通用用 /api/v3。ModelId 从模型广场复制",
        "models": [_m("deepseek-flash", "deepseek-v4-flash", "DeepSeek-V4-Flash（火山·便宜快，ID 以模型广场为准）", "cheap", rank=2,
                      skills=["zh", "code", "fast"]),
                   _m("minimax", "minimax-m3", "MiniMax-M3", "cheap", rank=3, skills=["zh", "code"]),
                   _m("glm", "glm-latest", "智谱 GLM-5.2", "cheap", rank=4, skills=["zh", "code"]),
                   _m("kimi", "kimi-k2.7-code", "Kimi-K2.7-Code", "cheap", rank=5, skills=["zh", "code", "long"])],
    },
    {
        "name": "deepseek", "label": "DeepSeek 深度求索", "region": "cn",
        "type": "openai_compat", "auth": "api_key", "base_url": "https://api.deepseek.com/v1",
        "auto_discover_models": True,
        "models": [_m("deepseek-chat", "deepseek-chat", "DeepSeek-V3", "cheap", skills=["zh", "code"]),
                   _m("deepseek-reasoner", "deepseek-reasoner", "DeepSeek 推理", "cheap", skills=["zh", "reasoning", "math"])],
    },
    {
        "name": "zhipu", "label": "智谱 GLM（BigModel）", "region": "cn",
        "type": "openai_compat", "auth": "api_key", "base_url": "https://open.bigmodel.cn/api/paas/v4",
        "models": [_m("glm-4.6", "glm-4.6", "GLM-4.6", skills=["zh", "code"]),
                   _m("glm-4-flash", "glm-4-flash", "GLM-4-Flash 免费", "cheap", skills=["zh", "fast"])],
    },
    {
        "name": "zai_intl", "label": "Z.AI GLM（国际站）", "region": "intl",
        "type": "openai_compat", "auth": "api_key", "base_url": "https://api.z.ai/api/paas/v4",
        "note": "国际站通用 API；Coding Plan 是另一专用端点，不能混用",
        "models": [_m("glm-5.1", "glm-5.1", "GLM-5.1", rank=1,
                      skills=["code", "reasoning", "long"])],
    },
    {
        "name": "moonshot", "label": "月之暗面 Kimi", "region": "cn",
        "type": "openai_compat", "auth": "api_key", "base_url": "https://api.moonshot.cn/v1",
        "auto_discover_models": True,
        "models": [_m("kimi-k2.6", "kimi-k2.6", "Kimi K2.6", rank=1, skills=["zh", "code", "long"]),
                   _m("moonshot-128k", "moonshot-v1-128k", "Moonshot 128k", skills=["zh", "long"])],
    },
    {
        "name": "moonshot_intl", "label": "Kimi（国际站）", "region": "intl",
        "type": "openai_compat", "auth": "api_key", "base_url": "https://api.moonshot.ai/v1",
        "auto_discover_models": True,
        "note": "国际站账号请选择此项；中国站与国际站 Key 不混用",
        "models": [_m("kimi-k2.6", "kimi-k2.6", "Kimi K2.6", rank=1,
                      skills=["zh", "code", "long"])],
    },
    {
        "name": "qwen", "label": "阿里百炼 通义千问", "region": "cn",
        "type": "openai_compat", "auth": "api_key",
        "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "models": [_m("qwen3.7-plus", "qwen3.7-plus", "Qwen3.7-Plus", rank=1,
                      skills=["zh", "code", "reasoning"]),
                   _m("qwen-max", "qwen-max", "Qwen-Max", rank=2,
                      skills=["zh", "code", "reasoning"]),
                   _m("qwen-plus", "qwen-plus", "Qwen-Plus", "cheap", rank=3,
                      skills=["zh", "code"])],
    },
    {
        "name": "qwen_intl", "label": "Qwen（新加坡）", "region": "intl",
        "type": "openai_compat", "auth": "api_key",
        "base_url": "https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
        "note": "新加坡区域 Key；各区域 Key 不互通，Workspace 专属域名后续用企业向导接入",
        "models": [_m("qwen3.7-plus", "qwen3.7-plus", "Qwen3.7-Plus", rank=1,
                      skills=["zh", "code", "reasoning"])],
    },
    {
        "name": "qwen_us", "label": "Qwen（美国 Virginia）", "region": "intl",
        "type": "openai_compat", "auth": "api_key",
        "base_url": "https://dashscope-us.aliyuncs.com/compatible-mode/v1",
        "note": "美国区域 Key；各区域 Key 不互通",
        "models": [_m("qwen3.7-plus", "qwen3.7-plus", "Qwen3.7-Plus", rank=1,
                      skills=["code", "reasoning", "long"])],
    },
    {
        "name": "hunyuan", "label": "腾讯混元", "region": "cn",
        "type": "openai_compat", "auth": "api_key", "base_url": "https://api.hunyuan.cloud.tencent.com/v1",
        "models": [_m("hunyuan-turbo", "hunyuan-turbo", "混元 Turbo", skills=["zh", "fast"])],
    },
    {
        "name": "qianfan", "label": "百度千帆 文心", "region": "cn",
        "type": "openai_compat", "auth": "api_key", "base_url": "https://qianfan.baidubce.com/v2",
        "auto_discover_models": True,
        "note": "鉴权用千帆 v2 API Key",
        "models": [_m("ernie-4.5", "ernie-4.5-turbo-128k", "文心 4.5 Turbo", skills=["zh", "long"])],
    },
    {
        "name": "minimax_api", "label": "MiniMax 官方", "region": "cn",
        "type": "openai_compat", "auth": "api_key", "base_url": "https://api.minimaxi.com/v1",
        "auto_discover_models": True,
        "note": "base_url 以 MiniMax 控制台为准",
        "models": [_m("minimax-m2.7", "MiniMax-M2.7", "MiniMax M2.7", rank=1, skills=["zh", "code", "long"])],
    },
    {
        "name": "minimax_intl", "label": "MiniMax（国际站）", "region": "intl",
        "type": "openai_compat", "auth": "api_key", "base_url": "https://api.minimax.io/v1",
        "auto_discover_models": True,
        "note": "国际站账号请选择此项；无需手填 Base URL",
        "models": [],
    },
    {
        "name": "siliconflow", "label": "硅基流动 SiliconFlow", "region": "cn",
        "type": "openai_compat", "auth": "api_key", "base_url": "https://api.siliconflow.cn/v1",
        "auto_discover_models": True,
        "note": "聚合多家开源模型，支持 /models 拉取",
        "models": [],
    },
    {
        "name": "siliconflow_intl", "label": "SiliconFlow（国际站）", "region": "intl",
        "type": "openai_compat", "auth": "api_key", "base_url": "https://api.siliconflow.com/v1",
        "auto_discover_models": True,
        "note": "国际站账号请选择此项；无需手填 Base URL",
        "models": [],
    },
    {
        "name": "agnes", "label": "Agnes AI（Token Plan 套餐）", "region": "intl",
        "type": "openai_compat", "auth": "api_key", "base_url": "https://apihub.agnes-ai.com/v1",
        "note": "Token Plan Plus 套餐(付费) · 高 TPS(100~150) · 视频每日额度 500/天(吃量大户,长视频尤甚) · OpenAI兼容 · base_url=apihub.agnes-ai.com/v1（是 apihub 不是 api！）",
        "models": [
            # tool_capable=False（机主多轮实测定案）：function-calling 不可靠——CoT 泄进正文、
            # seconds 等参数偷懒不传、派发磨蹭(90s+派不出任务)。它是免费聊天/看图/润色的好手，
            # 但**绝不当动手执行第一棒**——动手活由 DeepSeek-Flash/MiniMax/GLM/Kimi 打头（丝滑根修）。
            _m("agnes-flash", "agnes-2.0-flash", "Agnes 2.0 Flash · 文本+视觉（聊天/看图/润色；不派动手活）", "free", "chat", rank=1,
               tool_capable=False, skills=["zh", "vision", "fast"]),
            _m("agnes-image", "agnes-image-2.1-flash", "Agnes 生图", "free", "image"),
            _m("agnes-video", "agnes-video-v2.0", "Agnes 生视频(异步)", "free", "video"),
        ],
    },
    # ── 海外 ──
    {
        "name": "openai", "label": "OpenAI", "region": "intl",
        "type": "openai_compat", "auth": "api_key", "base_url": "https://api.openai.com/v1",
        "auto_discover_models": True,
        "models": [_m("gpt-4o", "gpt-4o", "GPT-4o", skills=["code", "vision", "tools"]),
                   _m("gpt-4o-mini", "gpt-4o-mini", "GPT-4o mini", "cheap", skills=["code", "fast", "tools"])],
    },
    {
        "name": "gemini", "label": "Google Gemini", "region": "intl",
        "type": "openai_compat", "auth": "api_key",
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
        "models": [_m("gemini-2.0-flash", "gemini-2.0-flash", "Gemini 2.0 Flash", "cheap", skills=["vision", "long", "fast"])],
    },
    {
        "name": "xai", "label": "xAI Grok", "region": "intl",
        "type": "openai_compat", "auth": "api_key", "base_url": "https://api.x.ai/v1",
        "auto_discover_models": True,
        "models": [_m("grok", "grok-2-latest", "Grok 2", skills=["code", "reasoning"])],
    },
    {
        "name": "mistral", "label": "Mistral", "region": "intl",
        "type": "openai_compat", "auth": "api_key", "base_url": "https://api.mistral.ai/v1",
        "auto_discover_models": True,
        "models": [_m("mistral-large", "mistral-large-latest", "Mistral Large", skills=["code", "tools"])],
    },
    {
        "name": "groq", "label": "Groq（极速推理）", "region": "intl",
        "type": "openai_compat", "auth": "api_key", "base_url": "https://api.groq.com/openai/v1",
        "auto_discover_models": True,
        "models": [],
    },
    {
        "name": "openrouter", "label": "OpenRouter（聚合）", "region": "intl",
        "type": "openai_compat", "auth": "api_key", "base_url": "https://openrouter.ai/api/v1",
        "note": "默认用官方 openrouter/auto 自动选模型；聚合路由不计独立互审票，具体型号可在高级设置中填写",
        "models": [_m("openrouter-auto", "openrouter/auto", "OpenRouter Auto", skills=["reasoning", "code"])],
    },
    {
        "name": "perplexity", "label": "Perplexity", "region": "intl",
        "type": "perplexity", "auth": "api_key", "base_url": "https://api.perplexity.ai",
        "auto_discover_models": True,
        "note": "专用一键接入：聊天走 /chat/completions，模型目录走 /v1/models；/v1/sonar 尚未冒充兼容聊天协议",
        "models": [_m("sonar", "sonar", "Sonar 联网", skills=["search", "web"])],
    },
    # ── 本地 ──
    {
        "name": "ollama", "label": "Ollama（本地）", "region": "local",
        "type": "openai_compat", "auth": "none", "base_url": "http://localhost:11434/v1",
        "note": "本机 Ollama，免费，支持 /models 拉取",
        "models": [],
    },
    {
        "name": "lmstudio", "label": "LM Studio（本地）", "region": "local",
        "type": "openai_compat", "auth": "none", "base_url": "http://localhost:1234/v1",
        "note": "本机 LM Studio 服务，免费，支持 /models 拉取",
        "models": [],
    },
    {
        "name": "llamacpp", "label": "llama.cpp（本地）", "region": "local",
        "type": "openai_compat", "auth": "none", "base_url": "http://localhost:8080/v1",
        "note": "本机 llama.cpp server，免费，支持 /models 拉取",
        "models": [],
    },
    {
        "name": "jan", "label": "Jan（本地）", "region": "local",
        "type": "openai_compat", "auth": "none", "base_url": "http://localhost:1337/v1",
        "note": "本机 Jan 服务，免费，支持 /models 拉取",
        "models": [],
    },
    {
        "name": "vllm", "label": "vLLM（本地）", "region": "local",
        "type": "openai_compat", "auth": "none", "base_url": "http://localhost:8000/v1",
        "note": "本机 vLLM 服务，免费，支持 /models 拉取",
        "models": [],
    },
]


def preset(name: str) -> dict[str, Any] | None:
    return next((p for p in PROVIDER_PRESETS if p["name"] == name), None)


def preset_models(name: str) -> list[dict[str, Any]]:
    p = preset(name)
    return [dict(m) for m in p.get("models", [])] if p else []


def preset_meta(model_id: str) -> dict[str, Any]:
    """按模型 id 在所有预设里找它的 rank/flagship/tool_capable/skills/modality——
    给"连接中心存的老连接(没带偏好)"及"点将官/池子快照"补默认。

    tool_capable 默认 True：未在预设登记（自定义/拉取来的）的模型一律先当作能 function-calling，
    只有预设里显式标了 False 的（本地/GGUF 等）才不给它派带工具的活。
    skills 默认 []（未登记即无能力标签）；modality 默认 "chat"（未登记乐观按对话模型）。
    """
    for p in PROVIDER_PRESETS:
        for m in p.get("models", []):
            if m.get("id") == model_id:
                return {
                    "rank": m.get("rank", 0),
                    "flagship": m.get("flagship", False),
                    "tool_capable": m.get("tool_capable", True),
                    "skills": list(m.get("skills") or []),
                    "modality": m.get("modality", "chat"),
                }
    return {"rank": 0, "flagship": False, "tool_capable": True, "skills": [], "modality": "chat"}
