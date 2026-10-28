# 安全评审记录（security-judge v1.5.2）

> 本文件是 I-02 / I-03 / I-04 / I-05 / H-04 / H-05 的证据记录，随版本更新。

## 评审范围与方式

- 对象：`dsh-security-judge` 全部运行时代码（index.js、lib/*.js、client.js、bundle patch、locale/icon、分发包）。
- 方式：人工代码审计 + 自动检查（本插件规则引擎自查）+ 分发包自检 + 干净目录解包验证 + HTTP 鉴权实测。
- 环境：2026-10-28，Windows，Node v24；DSH 0.2.1-rc.3。

## 评审清单与结论

| 检查项 | 结论 | 证据 |
| --- | --- | --- |
| 动态代码执行 / 子进程 | 无 | 全库检索无 eval/new Function/child_process；HTTP 与扫描均为纯函数 + fs 只读 |
| 注入（XSS） | 无 | 面板全部 React 文本渲染；无 innerHTML/dangerouslySetInnerHTML |
| CSRF / 本地越权 | 已修复 | 写操作页面令牌 + 同源校验；实测无令牌 POST=401、跨站=403 |
| 路径处理 | 只读、限定范围 | 仅读会话改动过的代码文件与包目录；不跟随用户任意路径写文件 |
| 秘密管理 | 通过 | 无硬编码密钥；页面令牌内存态；发布签名密钥独立 |
| 依赖供应链 | 通过 | 无第三方运行时依赖；无 file:/link: 依赖；无安装脚本 |
| 分发包完整性 | 通过 | exports/files/patch/locale/icon 全存在；干净目录解包 import 成功 |
| SBOM | 已生成 | `dist/SBOM.cdx.json`（CycloneDX，含每个文件 SHA-256） |
| 产物签名 | 已签名 | `dist/dsh-security-judge-1.5.2.tgz.sig` + `dist/release-signing.pub.pem`（Ed25519） |
| 测试 | 通过 | 引擎/教学模式/分发自检/Host 共 457+ 项；见各 test/*.mjs |

## 静态扫描记录（I-03）

- `node --check`：全部 JS 通过。
- 秘密扫描：对运行时代码检索 `password|secret|token|api_key|private_key` 的硬编码赋值，仅命中规则文本/说明，无真实密钥。
- 危险 API 检索：无 eval / new Function / child_process / innerHTML。
- 依赖检查：`package.json` 无 dependencies；无安装脚本。

## 规则变更评审（I-04）

- 规则目录变更（如 1.3.0 新增 J 组、1.5.x 安全修复）均记录在 CHANGELOG，并附测试更新；
  单次发布由当前会话 AI + 用户共同确认。

## 抽查与演练（I-05 / I-06）

- I-05 季度抽查：本次按规则全量自查（自动检查 + 人工审计 + 分发自检），结果记录于本文件。
- I-06 渗透/红蓝演练：本项目为本地 DSH 插件，未单独开展外部渗透测试；建议下一季度做一次
  「跨站请求 + 同机进程 + 恶意会话内容」三项模拟演练，并把结果补到本文件。

## 告警与响应（H-04 / H-05）

- 告警通道：DSH Host 日志 + 面板错误提示；责任人：插件维护者（本工作区负责人）。
- 响应流程：发现 → 定位（日志/版本）→ 止血（停用插件/撤销授权/回滚版本）→ 复盘（记录 + 规则补充）。
- 至少演练一次：1.5.0 安全修复即一次真实响应（发现 → 修复 → 测试 → 发布），记录在 CHANGELOG。

## 数据最小化（D-08）

- 只保存：授权状态、设置、最多 80 条评审历史；不保存代码内容、不保存会话对话、不保存令牌。
