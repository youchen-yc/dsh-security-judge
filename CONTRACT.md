# 代码安全防御规则评审判官 · 接口契约（Host ↔ Client）

> 本文件是 `client.js`（Web 面板）与 Host 半边（`index.js` / `lib/*.js`）之间的唯一契约。
> 面板只通过下面两个 HTTP 接口取数与操作，不读宿主 DOM、不 import 宿主组件包、不写 `document.body`。

- 插件包名：`dsh-security-judge`
- 面板 id / 侧栏 id：`security-judge`
- HTTP 前缀：`/dsh-security-judge/api`
- 语言：界面文案简体中文（「進/漢/蕐/厦」例外规则不涉及本面板）

## 1. 接口

> **鉴权**：`POST /action` 等写操作必须带 `x-security-judge-token: <页面令牌>` 头（缺失/错误 401）；
> `GET` 只读接口不要求令牌（同源页面可直接读，跨站读被浏览器同源策略挡住）。
> 令牌由 Host 每次加载生成，只注入到当前 DSH 页面；带 Origin 的请求必须同源，否则 403。
> 面板客户端自动携带；Agent 侧走 `security_judge` 工具，不经 HTTP。

### GET `/dsh-security-judge/api/state`

返回 `application/json`：

```jsonc
{
  "ok": true,
  "version": "1.0.0",
  "generatedAt": 1730000000000,
  "authority": {
    "granted": false,
    "grantedAt": null,
    "requestedAt": null,
    "scope": "代码安全防御规则与架构的评审（只读审查 + 完成门禁）",
    "charter": "本评审判官权限低于用户最高权限，只用于审核评审会话是否按代码安全防御规则做了代码安全防御架构；不能修改代码、不能修改配置、不能代替用户做决定。",
    "canGate": false
  },
  "settings": {
    "mode": "block",                 // advisory | remind | block
    "autoScanMs": 15000,             // Host 自动扫描间隔
    "maxEnforcePerSession": 0,       // 单会话强制重做上限；0 = 合格为止（默认不限次数）
    "blockWithoutPass": true         // 是否在评审不合格时拦截回合结束（需授权）
  },
  "stats": {
    "liveSessions": 3,
    "codeSessions": 2,
    "passed": 0,
    "pending": 1,
    "failed": 1,
    "unjudged": 0,
    "conflicted": 2,
    "authority": false
  },
  "sessions": [ /* SessionView[]，见 §2 */ ],
  "catalog": {
    "ruleGroups": [ /* RuleGroup[]，见 §3.1 */ ],
    "architectures": [ /* Architecture[]，见 §3.2 */ ],
    "conflicts": [ /* Conflict[]，见 §3.3 */ ]
  }
}
```

### POST `/dsh-security-judge/api/action`

请求体：`{ "action": "...", "payload": { ... } }`。
响应：`{ "ok": true, ...result }` 或 `{ "ok": false, "error": { "code": "...", "message": "..." } }`。
任何 action 成功后都尽量附带一份最新的 `state`（同 GET 结构），面板可据此直接刷新。

| action | payload | 说明 |
| --- | --- | --- |
| `grant-authority` | `{ "confirm": true, "note"?: string }` | 用户点「授权」后调用；`confirm` 必须为 true（面板必须让用户二次确认，Host 校验后立即生效）。 |
| `revoke-authority` | `{ "confirm": true }` | 撤销授权。 |
| `settings-save` | `{ "patch": { "mode"?, "autoScanMs"?, "maxEnforcePerSession"? } }` | 保存设置。`mode` 枚举见上。 |
| `scan` | `{}` | 立即重扫所有活跃会话并重算评审状态。 |
| `review` / `request-review` | `{ "sessionId": "...", "text"?: string }` | 受理评审要求：回看该会话最多 2000 条历史事件、标记「用户已要求评审」、重算评审；（已授权时）注入受理通知。面板按钮「评审该会话」用它。 |
| `coach` | `{ "sessionId": "..." }` | 教学模式：返回结构化教学计划与中文教学文本（连续不合格后「怎么改」）。 |
| `remind` | `{ "sessionId": "...", "text"?: string }` | 向该代码会话注入一条「不合格必须重做」的评审提醒（非代码会话拒绝）。 |
| `pause-enforce` | `{ "sessionId": "...", "paused": true \| false }` | 用户最高权限：暂停 / 恢复强制重做；暂停后评审结论仍是不合格。 |
| `ack-conflict` | `{ "sessionId": "...", "conflictId": "...", "resolution": "..." }` | 登记架构冲突的处理结论。 |
| `waive` | `{ "sessionId": "...", "rule": "B-08", "reason": "..." }` | 豁免；仅 L2 / L3 可豁免，L1 强制项 Host 拒绝。 |
| `submit` | `{ "sessionId": "...", "payload": SubmitPayload }` | 代理会话内 AI 的评审提交（面板也可手动提交）。 |
| `session-detail` | `{ "sessionId": "..." }` | 返回单个 SessionView（`{ ok, session }`）。 |

错误码：`authority-required`、`not-code-session`、`unknown-session`、`unknown-action`、`bad-payload`、`l1-not-waivable`、`confirm-required`、`internal-error`。

## 2. SessionView

```jsonc
{
  "id": "session-id",
  "title": "会话标题",
  "cwd": "F:\\DSH1.0",
  "status": "running",                 // running | idle | unknown
  "createdAt": 1730000000000,
  "lastActivityAt": 1730000000000,
  "code": {
    "doing": true,                     // 本会话正在/最近做过代码
    "score": 72,                       // 0..100 代码工作强度
    "projectKind": "android",          // android | server | web | desktop | iot | cli | mixed | unknown
    "stacks": ["android", "java", "gradle"],
    "signals": [ { "kind": "file", "detail": "app/src/main/AndroidManifest.xml", "at": 1730000000000 } ],
    "files": ["app/src/main/AndroidManifest.xml"]
  },
  "architectures": [
    { "id": "asvs", "name": "OWASP ASVS 5.0", "layer": "method", "layerName": "方法层",
      "mandatory": true, "why": "应用安全验收基线（L2）", "doc": "资料汇编 §5.4" }
  ],
  "architectureCount": 3,               // 需要几种架构（1 / 2 / 多个）
  "conflicts": [
    { "id": "zt-vs-ip-allowlist", "title": "零信任 vs 内网/IP 白名单授权",
      "severity": "hard",               // hard | overlap | tension
      "a": "zero-trust", "b": "network-allowlist",
      "detail": "...", "resolution": "...", "rules": ["A-05"],
      "acknowledged": false, "ackNote": "" }
  ],
  "review": {
    "state": "failed",                  // none | pending | passed | failed | waived | na
    "verdict": "fail",                  // pass | fail | pending | none | na（只有 pass = 合格）
    "unqualified": true,                // 未合格（代码会话且 state !== passed）
    "redoCount": 3,                     // 被强制重做的次数
    "enforcePaused": false,             // 用户是否暂停了强制重做（暂停仍是不合格）
    "coaching": true,                   // 是否已进入教学模式（连续 2 次不合格后）
    "requestedAt": 1730000000000,       // 用户在会话里要求评审的时间（0 = 未要求）
    "requestedText": "检查审核评审该会话",
    "score": 41,
    "turn": 12,
    "attempts": 2,
    "enforced": 0,
    "lastAt": 1730000000000,
    "passedRules": ["A-02"],
    "failedRules": [
      { "id": "B-01", "level": "L1", "title": "口令必须使用自适应哈希", "reason": "自动检查命中弱哈希", "source": "auto" }
    ],
    "missingRules": [
      { "id": "C-01", "level": "L1", "title": "服务端强制授权校验" }
    ],
    "autoViolations": [
      { "id": "B-01", "level": "L1", "findings": [ { "file": "a.java", "line": 3, "snippet": "...", "why": "..." } ] }
    ],
    "attested": 5,
    "waived": []
  },
  "progress": { "inScope": 24, "l1": 16, "autoPass": 9, "attested": 5, "failed": 1 },
  "distributionTarget": true,           // 该会话是否会产出安装包（J 组规则是否进入范围）
  "distribution": {                     // Host 的分发包自检结果（lib/dist.js）；null = 未检测
    "ok": false,
    "checkedAt": 1730000000000,
    "packageName": "dsh-security-judge",
    "packageVersion": "1.3.0",
    "findings": [ { "file": "client.js", "why": "客户端入口不存在" } ]
  },
  "activity": { "lastTool": "write", "lastFile": "serve/server.js", "codeTurns": 3, "turns": 8 }
}
```

`architectureCount` 是「这个程序需要几种代码安全防御架构」的直接答案；`architectures` 是清单，`conflicts` 是架构两两冲突检查结果。

## 3. 目录结构

### 3.1 RuleGroup

```jsonc
{ "id": "A", "name": "总则：架构层", "rules": [
  { "id": "A-01", "level": "L1", "applies": "通", "title": "信任边界必须显式绘制",
    "criteria": "存在信任边界图；新增跨边界调用时同步更新，评审时可见。",
    "auto": false, "check": "" }
] }
```

`auto: true` 的规则由 Host 自动扫描代码文本给出命中；`auto: false` 需要会话 AI 在 `submit` 里提交证据。

### 3.2 Architecture

```jsonc
{ "id": "zero-trust", "name": "零信任（Zero Trust）", "layer": "skeleton", "layerName": "骨架层",
  "purpose": "网络位置不等于信任，每次访问都验证",
  "mandatory": false, "stacks": ["server"],
  "when": "有服务端 / API / 多服务调用时",
  "rules": ["A-05", "A-02", "C-01"],
  "conflictsWith": ["network-allowlist"],
  "doc": "资料汇编 §4.1；NIST SP 800-207" }
```

### 3.3 Conflict

```jsonc
{ "id": "zt-vs-ip-allowlist", "title": "零信任 vs 内网/IP 白名单授权", "severity": "hard",
  "a": "zero-trust", "b": "network-allowlist",
  "detail": "零信任要求每次验证身份与设备，位置即信任的白名单与它直接矛盾。",
  "resolution": "以零信任为准，白名单仅用于可观测性；授权判断必须基于身份/设备/上下文。",
  "rules": ["A-05"] }
```

## 4. 面板要求

1. 注册两处：
   - `sidebar.panellist`：`id: 'security-judge'`、`order: 21`、`label: () => '代码安全评审判官'`，图标为 16~24px 盾牌+放大镜（内联 SVG，颜色用 `currentColor` 与 `var(--dsw-alias-brand-primary)`）。
   - `main`：`key: 'security-judge'`，整个面板；点击侧栏图标时调用 `ctx.layout.selectPanel('security-judge')`。
2. 客户模块格式照抄 `F:\DSH1.0\system-guard\client.js` 的 `window.__ModuleLoader__.load({ id: 'dsh-security-judge', factory(require) {...} })`，返回 `{ inject: ['slots', 'layout'], apply(ctx) {...} }`；`require('react')` 后只使用 `React.createElement`。
3. 样式只用宿主主题 token（`--dsw-alias-*`、`--dsw-radius-*` 等），沿用 system-guard 面板的骨架（撑满、自管滚动、maxWidth 960、卡片 12px 圆角）。不引宿主组件库、不读宿主 DOM、不往 `document.body` 追加节点。
4. 面板结构（从上到下）：
   - 标题区：`代码安全防御规则评审判官`、副标题（规则版本 v1.0 · 强制规则）、刷新按钮、最后刷新时间。
   - 授权卡：未授权时醒目（说明权限边界 charter + 「请求用户授权」按钮 → 弹二次确认 → 调 `grant-authority`）；已授权显示授权时间、范围 charter 与「撤销授权」。
   - 统计条：活跃会话 / 正在做代码 / 已通过 / 未通过 / 待评审 / 架构冲突。
   - 会话列表：每行显示状态点、标题、cwd、running/idle、是否做代码（含项目类型）、需要几种架构、评审徽章（通过/未通过/待评审/未涉及）。点行展开：
     * 代码识别信号（最近几条，文件路径）
     * 需要的代码安全防御架构卡片（名称、层、为什么、是否强制基线），并显示「需要 1 种 / 2 种 / 多种」结论
     * 架构冲突（severity 用颜色区分：hard 红、overlap 橙、tension 黄；每条可展开 resolution，可点「登记处理结论」→ 调 `ack-conflict`，弹输入框）
     * 评审进度（inScope/L1/自动通过/已提交证据/失败）+ 失败项与缺失项列表
     * 操作按钮：`重新评审`（review）、`提醒该会话`（remind，仅做代码会话可用）、`会话详情` 可省略
   - 规则目录卡：按 A~I 分组可折叠，显示编号、等级徽章、端、标题、判定标准；自动检查的标「自动」。
   - 架构目录卡：按层（判据层/理论层/骨架层/方法层/供应链/AI/后量子…）分组，显示何时需要。
   - 冲突矩阵卡：列出全部冲突对与严重度、处理建议。
   - 设置卡：模式（只提示 advisory / 提醒 remind / 阻断 block）、自动扫描间隔、单会话强制续做上限；保存调 `settings-save`。
   - 页脚：权限边界一句话（charter）。
5. 容错：state 为空/字段缺失时不能白屏；用错误边界包住面板；接口失败显示可读错误与重试按钮；轮询 2.5s（页面可见时才轮询，可用 `document.visibilityState`）。
6. 交互态：按钮 busy 时禁用；授权/撤销/豁免/冲突登记需要二次确认（`window.confirm` 可用，但不依赖它——优先自绘确认条）。
7. 不修改宿主其它页面、不改 URL、不弹全局 toast。

## 5. 授权语义（必须如实展示）

- **会话内口令**：用户在任意会话里说「检查审核评审该会话」（以及「评审这个会话的代码」
  「代码安全防御评审」「review this session」等）时，Host 在 `user/message` 事件上识别并受理，
  回看该会话历史代码工作、标记 `review.requestedAt`；这是用户的明确要求，不需要额外授权即可受理与只读评审，
  但注入受理通知、强制重做仍需授权。
- 本插件权限**低于用户最高权限**，只在代码安全防御评审范围内使用。
- 它可以：读取/汇总会话里已经产生的代码与工具痕迹；向会话注入评审提醒；在用户授权后拦截「未通过评审的代码任务算完成」。
- 它不能：修改代码、修改配置、代替用户做决定、读取与代码安全防御无关的内容。
- 面板必须把上面三条写进授权卡（用 charter 文案 + 简短列表），不得含糊。
