# Nachuan Plugin SDK v1

> 状态：PK-008 最小纵切。SDK、上游描述投影和隔离代理接线已实现；公共插件市场、真实第三方发行、Linux/macOS 隔离和动态 UI 仍未完成。

## 1. SDK 解决什么问题

`nachuan_sdk` 让插件作者可以确定性生成纳川现有运行时接受的三文件包：

- `manifest.json`：闭集 manifest、精确版本、资源上限和 Ed25519 签名；
- `plugin.py`：最多 1 MiB 的 UTF-8 `transform.json` worker；
- `sbom.json`：入口代码的版本、许可证和 SHA-256。

SDK 不保存私钥，不把密钥写入 manifest、SBOM、命令行或项目目录。目标目录必须不存在；构建先在同目录临时根自验签名、SBOM 和文件闭集，再原子发布。

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nachuan_sdk import (
    IsolatedTransformPluginSpecV1,
    build_signed_transform_bundle,
    default_isolated_limits,
)

private_key = Ed25519PrivateKey.generate()  # 示例；生产密钥由受保护签名环境提供
receipt = build_signed_transform_bundle(
    "dist/com.example.demo-1.0.0",
    spec=IsolatedTransformPluginSpecV1(
        plugin_id="com.example.demo",
        version="1.0.0",
        publisher_key_id="example.publisher",
        license="Apache-2.0",
        limits=default_isolated_limits(),
    ),
    plugin_source=b"def handle(value):\n    return value\n",
    private_key=private_key,
)
```

生成回执只含插件身份、文件名和摘要，不含私钥或客户数据。生产发布仍须由受保护 publisher key、撤销清单、SBOM/许可证和最终字节审计共同批准。

## 2. DeepSeek Harness bridge

已核对官方 `deepseek-ai/deepseek-harness` 提交 `b150a551b8d465e31e418e1b2eaf5e79bbb7d28e`。Cordis 插件以 `apply(ctx)` 动态执行，Service 通过 `ctx` 注册，`inject` 控制依赖和热卸载。

纳川 v1 只读取固定提交下的 `cordis.yml` 组合清单：

- 只接受有界 YAML list 和闭集 `name/config`；
- 禁止 alias、自定义 YAML tag、绝对路径、`..`、URL、重复插件和未知字段；
- config 只进入 SHA-256，不回传原值；
- `apply(ctx)`、动态 Service、client plugin 均标记 unsupported；
- 输出固定为 `isolated_worker_only`，宿主不得 import 模块。

这不是 Cordis 运行时替代品，也不承诺 Harness 任意插件可直接在纳川运行。

## 3. OpenClaw bundle/skill bridge

已核对官方 `openclaw/openclaw` 提交 `6f0395ec79f9eefe51575486279f44e595aeee2b`。其原生 `openclaw.plugin.json` 必须至少包含 `id + configSchema`，原生插件可在 Gateway 进程内注册 provider、channel、tool、hook、HTTP/RPC、service 等大量能力；兼容 bundle 的 skill/MCP/hook 映射边界更窄。

纳川 v1 只做数据投影：

- manifest 使用无重复字段 JSON，完整原文和安全子集分别绑定摘要；
- Skill 只接受 `skills/<id>/SKILL.md` 的直接子目录形态，最多 128 KiB、UTF-8、无 NUL；
- Skill 正文、description、configSchema 和未知字段值不进入宿主投影，只留摘要；
- 未支持字段按名字列入 diagnostics，不能静默变成能力；
- 原生 runtime、Hook、MCP、子进程、HTTP/RPC、工具和 Skill prompt 挂载全部不在宿主执行。

需要真正处理这些内容时，调用方必须指定精确签名的纳川 worker `id + version + artifact_sha256`，由 `ecosystem.bridge.project` 经 `isolated.plugin.execute` 执行。worker 只能返回 ecosystem 和原组件 ID 的闭集投影；多字段、改摘要、注入代码或新增组件会被拒绝并 quarantine 精确插件身份。

## 4. 版本与兼容原则

- SDK API：`nachuan_sdk.SDK_API_VERSION == "1"`；
- 上游必须使用 40 位精确 commit，拒绝 `main/master/latest`；
- 上游升级先生成新 plan 和回归，不覆盖旧适配结论；
- 外部插件绝不 in-process mount；
- worker 输出不是授权，不能注册任何宿主能力；
- 公共市场尚未实现，当前没有自动下载、自动信任、自动启用或自动升级第三方插件。

## 5. 当前验收边界

已覆盖确定性 bundle 构建、现有 verifier 互认、私钥不落盘、YAML/JSON 攻击输入、固定上游 commit、Skill 正文不入投影、隔离代理依赖、执行中卸载阻断、身份漂移零启动、恶意 worker 语义越界 quarantine 和 wheel 自包含。

未覆盖真实第三方作者签名、公共市场治理、签名密钥轮换、外部网络域白名单、Linux/macOS sandbox、动态第三方 UI、真实 OpenClaw/Cordis 代码执行、MCP/Hook/Channel/Provider 迁移或长期生态兼容。
