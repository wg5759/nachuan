# 纳川 Microsoft Store / MSIX 发布入口

> 当前状态：项目侧入口已准备；Partner Center 身份、商店认证和最终包验收未完成，继续 `NO-GO`。

## 为什么走 MSIX

Microsoft Store 会在 MSIX/AppX 通过认证后自动用微软证书重签，项目不需要购买 CA 证书。该免费签名只适用于
Store 的 MSIX/AppX 路线；传统 MSI/EXE 即使提交商店，也必须由发布者先做可信 Authenticode 签名。

## 外部前置（必须由账号所有者完成）

1. 在 Microsoft Store Developer / Partner Center 注册开发者账号并启用 MFA；
2. 预留“纳川”应用名称；
3. 从 Partner Center 复制精确的 Package/Identity/Name 与 Publisher subject；
4. 准备商店说明、隐私链接、截图、年龄分级和测试账号（如认证需要）；
5. 不把 Partner Center token、证书或账号信息写进仓库。

## 项目入口

把 Partner Center 返回的真实值只放在受保护发布环境：

```powershell
$env:NACHUAN_STORE_APPLICATION_ID = '<Partner Center Application Id>'
$env:NACHUAN_STORE_IDENTITY_NAME = '<Package Identity Name>'
$env:NACHUAN_STORE_PUBLISHER = '<Publisher subject>'
$env:NACHUAN_STORE_PUBLISHER_DISPLAY_NAME = '<Publisher display name>'
npm --prefix desktop run package:store:check
```

检查通过只表示身份字段与共享核心版本可进入 AppX 构建，不表示商店已认证、包已签名或允许发布。
实际 AppX 构建还必须复用当前 Engine/ASAR/SBOM/许可证/恶意软件/安装根门禁，并新增 Store 真机安装、升级、
卸载、数据迁移、自动更新和认证结果回读证据后才能开闸。

## SignPath 并行路线

直接下载的 NSIS 安装器仍优先申请 SignPath Foundation。申请要求包括：项目已有可签发行形态、OSI 许可证、
无专有组件、公开 Code signing policy、项目与 SignPath/GitHub MFA、明确作者/审核者/批准者角色、可验证自动构建，
且每个签名请求人工批准。基金会保留批准或拒绝权；未获明确批准前不配置 signing secret。

## 官方依据（2026-08-25 复核）

- https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options
- https://learn.microsoft.com/en-us/windows/apps/publish/publish-your-app/msix/app-package-requirements
- https://www.electron.build/docs/appx/
- https://signpath.org/terms.html
