# 纳川官方 Windows 代码签名政策

## 当前结论

纳川开源并不自动获得 Windows 可信签名。源码版可以通过终端安装和运行；面向普通客户的官方桌面安装包、
企业受管安装包及其自动更新必须继续通过 Authenticode、可信时间戳、安装闭包和干净机验收门禁。

当前公开仓库刚建立，尚未获得 SignPath Foundation 批准，也没有可公开交付的官方签名二进制。
任何 `NotSigned` 文件都只能作为开发候选，不能改名或口头包装成客户正式版。

## 免费开源签名路线

纳川优先申请 SignPath Foundation 的开源项目免费代码签名。申请和批准是外部人工流程，不由开源许可证自动触发。

申请材料使用以下官方声明：

> Free code signing provided by SignPath.io, certificate by SignPath Foundation.

- 项目与源码：https://github.com/wg5759/nachuan
- 许可证：Apache-2.0
- 维护角色与决策规则：`GOVERNANCE.md`
- 隐私与数据生命周期：`docs/PRIVACY_DATA_LIFECYCLE_AND_INCIDENT_RESPONSE.md`
- 安全报告与支持范围：`SECURITY.md`
- 发行规则：本文件与 `PACKAGING.md`

只有收到 Foundation 明确批准，并在 SignPath 中建立组织、项目、签名策略、Artifact Configuration 和可信
GitHub 构建关联后，才配置仓库变量与 secret。联系人、MFA、API token、证书材料和签名私钥不得进入源码、
Issue、构建产物或知识库。

纳川安装包包含引擎、Electron 主程序和外层安装器，三者都必须以同一受批准发布者身份通过签名与时间戳复验。
在 SignPath Artifact Configuration 未实际证明能完成这套“内层字节冻结—打包—外层签名”顺序前，不接入一个
看似成功、实则只签外壳的工作流。

## 微软商店路线

MSIX 经 Microsoft Store 认证后由微软重签，可作为普通用户的另一条低摩擦发行路线；它不等同于直接分发
NSIS/MSI/EXE。直接提交传统 EXE/MSI 仍要求发布者先签名。纳川当前是 NSIS 构建，MSIX 转换、商店账户、
认证和升级迁移尚未验收，因此不能把“商店会重签”写成已获得免费证书。

## 付费证书后备路线

当客户交付时间早于免费签名批准时，可购买受信任的组织代码签名/云签名服务。证书或服务端密钥必须只存在于
受保护发布环境，不能落在开发工作区。无论免费或付费，签名都不能替代 SBOM、恶意软件扫描、安装/升级/卸载、
真实渠道和长稳验收。

## 客户交付判定

| 交付 | 当前状态 | 允许范围 |
|---|---|---|
| 开源源码版 | source alpha | 技术用户试用、自托管验证；不冒充企业生产支持 |
| 普通用户桌面版 | 未签名、发布门未闭环 | 内部构建验证；不得作为官方正式安装包交付 |
| 企业商用版 | 企业权限与部署验收未闭环 | 方案和受控试点；不得宣称多租户生产就绪 |

状态只由 `config/distribution-channels.v1.json` 和对应真实验收证据推进，不能只改本文表格。

代码签名不替代依赖安全。2026-08-25 公开仓库首轮 Dependabot 报告的三个高危项已按上游最低修复版本约束；
当前锁定 cryptography 50.0.0、yt-dlp 2026.8.19、hydra-core 1.3.5。无修复版的 GPTCache 0.1.44 已从锁文件和
可分发 extra 移除并在运行时故障关闭。正式候选仍须重新生成 SBOM 和扫描，不能只看告警数量。
