# shou瓜田 前端

基于 Vue 3、TypeScript、Arco Design 与 Vite 的 shou瓜田主站前端，包含社区浏览发布、教育邮箱注册、FIDO2 安全中心、管理操作授权页、硬件管理凭证签发以及站内管理后台界面。

## 本地开发与构建

依赖版本以 [package.json](package.json) 和 [package-lock.json](package-lock.json) 为准（npm 11.12.1）：

```powershell
npm ci
npm run dev
npm run build
```

- **开发代理**：Vite 默认监听 `http://localhost:15173`，将 `/api` 转发到 `http://127.0.0.1:18000`。
- **生产部署**：配置同源反向代理去除 `/api/` 前缀后转至主站 Django 后端，并在主站正确设置 WebAuthn `RP ID` 与 `Origin`。
- **环境变量与图标资源**：复制 `.env.example` 为 `.env.local` 填写真实备案号与媒体地址；运行 `npm run generate-pwa-assets` 可从 SVG 矢量标识生成各尺寸 PNG / ICO。

## 安全与管理功能设计

### 独立特权管理站与确认授权

- 高权限管理功能（权限任命、用户档案编修、身份审核、全站审计日志、水印溯源等）位于独立部署且全站强制客户端证书（mTLS）的独立特权管理站，不在主站 `/admin` 路由内。
- 主站 [src/views/security/Approve.vue](src/views/security/Approve.vue)（`/security/approve`）只负责使用本次主站登录绑定的安全密钥核对并批准特定操作（支持「3 分钟只读查看授权」与写操作／高敏操作的单次确认），并通过精确 `Origin` 与 `window.opener` 校验回传授权结果。
- **分标签页隔离的临时代登录**：`/security/impersonate` 兑换来自特权管理站的 2 分钟一次性票据后进入最长 15 分钟的模拟会话。前端在模块加载最早期同步提取并抹除 `#ticket=` 片段，将模拟态隔离保存在当前标签页的 `sessionStorage` 中，不会覆写或丢失原超管标签页在 `localStorage` 中的登录状态。

### 安全中心与硬件凭证引导

- 安全中心位于「设置 → 安全」（`/settings/?tab=security`）。账号认证标识固定显示在注册主角色，并与隐私页面的「展示实名信息」同步；匿名角色不继承管理标记。
- 根据后端返回的核验等级展示标准绿标或高可信金标（悬停、聚焦或点击可展开 FIPS / CC 详情，适配深色模式与减少动画偏好）。
- **接触式 FIDO2 与硬件 PIV / TPM 签发**：
  - 支持经由电脑上的 `backend.fido_bridge` 使用接触式 FIDO2 智能卡完成登录、绑定和授权；常规 USB / NFC 密钥直接使用浏览器原生 WebAuthn。
  - 新任管理员首次登录（`admin_onboarding_required`）会自动弹出安全引导窗口（[src/views/security/AdminOnboardingModal.vue](src/views/security/AdminOnboardingModal.vue)），内嵌外置 FIDO2 安全密钥绑定、教育邮箱实名进阶认证签署与最终密钥确认三步流程；独立的管理员进阶认证已从日常安全中心隐藏。完成配置前账号仅保留管理身份徽章（有身份），不开放任何管理菜单或后台权限（无权限）。授予超管、全局读者或特权角色时自动弹出硬件制卡向导（[src/views/security/Issuance.vue](src/views/security/Issuance.vue)），支持浏览器的 WebUSB 直连兼容智能卡与一键唤起本机智能卡 / Windows TPM 2.0 助手（仅校验通过的 `127.0.0.1:10000–65535` 端口通信），**彻底移除且禁止任何 `.p12` 或浏览器软件私钥导出路径**。
  - 网页侧密码学源码位于 [src/scripts/webpiv/](src/scripts/webpiv/)，可通过以下命令重建同步脚本并在纯软件模拟环境下验证互操作：

```powershell
npm run build:smartcards
npm run test:smartcards
```

### 富文本安全、管理后台与动态水印

- **用户与内容管理**：后台用户与图片列表支持按数字 ID（`1` / `#1`）、用户名和实名搜索，支持直接创建用户（自动生成学号、无需验证码）、「老学究」开关和帖子置顶；前端路由守卫按权限细粒度限制访问，且列表/详情组件均对匿名或已删除作者做了空值与请求时序保护。
- **XSS 过滤**：文章正文、编辑器预览、评论和 Mermaid 渲染均经 [src/scripts/sanitizeMarkdown.ts](src/scripts/sanitizeMarkdown.ts) 与 [src/scripts/xss.ts](src/scripts/xss.ts)（基于 DOMPurify 白名单）严格清洗，拦截内联脚本、危险协议链接，并为外链强制添加 `rel="noopener noreferrer"`。
- **多通道管理水印**：源码位于 [src/scripts/watermarkRuntime.ts](src/scripts/watermarkRuntime.ts)，在管理视图附加零宽标记、实名明水印、空间像素微调与点阵、微块频域载荷和实际 R LSB 图层，并提供本地无损 PNG 截图下载。执行以下命令同步生成主站与独立管理站的公共运行文件和 Python 编码器副本：

```powershell
npm run build:watermark
```

## 浏览器端到端联合测试（Playwright E2E）

测试会在隔离临时目录（默认 `.test-work/ui`，可用 `SHOUGT_UI_WORK` 指定）建立测试 SQLite、测试 CA 及虚拟 WebAuthn 认证器，并在本地高端口（`15173`、`18000`、`18443` 等）拉起完整服务运行验证，结束后自动回收全部进程。运行前需先在主站后端、前端与特权管理站安装好各自依赖。

```powershell
npm run test:e2e
# 单独运行高可信密钥金色显示测试
$env:SHOUGT_UI_CERTIFIED_KEY = "1"
npm run test:e2e -- --grep "certified key shows gold"
Remove-Item Env:SHOUGT_UI_CERTIFIED_KEY
```

- 完整安全审计与实战红蓝演练报告见后端仓库 `SECURITY-AUDIT.md`。
- 本项目继续保留原 GPLv3 许可证。
