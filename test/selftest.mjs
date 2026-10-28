/**
 * 评审判官引擎自测（不依赖 DSH 运行时）：
 *   node test/selftest.mjs
 */

import {
  createSessionState,
  ingestSessionEvent,
  refreshProfile,
  recommendArchitectures,
  detectConflicts,
  evaluate,
  submitReview,
  waiveRule,
  ackConflict,
  buildReminderText,
  buildSessionView,
  detectReviewRequest,
  distributionCandidate,
  rulesInScope,
  isServerKind,
  hasPythonServerEvidence,
  classifySession,
} from '../lib/engine.js'
import { RULES, RULE_BY_ID, ARCH_BY_ID, CONFLICTS, AUTO_CHECKS } from '../lib/catalog.js'

let passed = 0
let failed = 0
const failures = []

function ok(condition, name, detail = '') {
  if (condition) {
    passed += 1
  } else {
    failed += 1
    failures.push(`${name}${detail ? `：${detail}` : ''}`)
  }
}

function eq(actual, expected, name) {
  ok(actual === expected, name, `期望 ${JSON.stringify(expected)}，实际 ${JSON.stringify(actual)}`)
}

const at = Date.now()
let clock = at

function makeState(overrides = {}) {
  clock += 1000
  return createSessionState({ id: 's1', title: '测试会话', cwd: 'F:/DSH1.0/jizhang', createdAt: at, status: 'running', ...overrides })
}

function toolCall(tool, args, turn = 1, step = 1) {
  clock += 1000
  return {
    type: 'tool/call',
    seq: clock,
    time: clock,
    data: { turn, step, callId: `c-${clock}`, name: tool, arguments: JSON.stringify(args) },
  }
}

function ingestAll(state, events) {
  for (const event of events) {
    ingestSessionEvent(state, event)
    if (event.data && typeof event.data.turn === 'number') state.turns.current = event.data.turn
  }
  refreshProfile(state)
}

// ---------------------------------------------------------------------------
// 1. Android 代码会话：识别 + 推荐架构 + 自动违规
// ---------------------------------------------------------------------------
{
  const state = makeState()
  ingestAll(state, [
    toolCall('write', {
      file_path: 'app/src/main/AndroidManifest.xml',
      content: '<manifest><application><activity android:name=".Main" android:exported="true"/></application><application android:usesCleartextTraffic="true"/></manifest>',
    }),
    toolCall('edit', {
      file_path: 'app/src/main/java/com/gongdi/jizhang/Login.java',
      old_string: 'old',
      new_string: 'MessageDigest md = MessageDigest.getInstance("MD5"); String password = "Sup3rS3cretPass"; String sql = "SELECT * FROM users WHERE name = \'" + name + "\'";',
    }),
    toolCall('write', { file_path: 'app/build.gradle', content: 'android { buildTypes { release { minifyEnabled true } } }' }),
  ])
  eq(state.code.doing, true, 'Android 会话被识别为写代码')
  eq(state.code.projectKind, 'android', '技术栈判定为 Android')
  const recommendation = recommendArchitectures(state)
  ok(recommendation.count >= 5, '推荐的架构数量 >= 5', `实际 ${recommendation.count}`)
  ok(recommendation.core.some((arch) => arch.id === 'masvs'), '推荐包含 MASVS（Android 核心架构）')
  ok(recommendation.core.some((arch) => arch.id === 'asvs'), '推荐包含 ASVS（验收基线）')
  ok(recommendation.core.some((arch) => arch.id === 'sbom'), '推荐包含 SBOM（供应链）')
  eq(recommendation.families.includes('method'), true, '架构层面包含方法层')

  const evaluation = evaluate(state, { mode: 'block' })
  eq(evaluation.state, 'pending', '未提交时评审状态为 pending')
  eq(evaluation.verdict, 'fail', '未提交时评审不通过')
  const failedIds = evaluation.failed.map((item) => item.id)
  ok(failedIds.includes('B-01'), '自动检查命中弱哈希 B-01')
  ok(failedIds.includes('B-07') || failedIds.includes('D-04'), '自动检查命中硬编码凭证')
  ok(failedIds.includes('E-03'), '自动检查命中拼接 SQL E-03')
  ok(failedIds.includes('G-04'), '自动检查命中导出组件 G-04')
  ok(failedIds.includes('D-02') || failedIds.includes('G-05'), '自动检查命中明文流量')

  const conflicts = detectConflicts(state, recommendation)
  ok(Array.isArray(conflicts), '推荐架构冲突检查返回列表')
  for (const conflict of conflicts) {
    ok(typeof conflict.severity === 'string' && conflict.detail && conflict.resolution, `冲突 ${conflict.id} 带严重度/说明/建议`)
  }

  const view = buildSessionView(state, { mode: 'block' }, evaluation)
  ok(view.architectureCount >= 5, '会话视图给出需要几种架构')
  ok(typeof view.review.state === 'string', '会话视图带评审状态')

  const reminder = buildReminderText(state, { mode: 'block' })
  ok(reminder.includes('代码安全防御评审判官'), '提醒文本带评审判官标识')
  ok(reminder.includes('种核心代码安全防御架构'), '提醒文本说明需要几种架构')
}

// ---------------------------------------------------------------------------
// 2. 非代码会话不评审
// ---------------------------------------------------------------------------
{
  const state = makeState({ id: 's2', cwd: 'F:/DSH1.0/招聘文案' })
  ingestAll(state, [
    toolCall('write', { file_path: '文案/招聘.md', content: '# 招聘文案\n我们招人。' }),
  ])
  eq(state.code.doing, false, '只写 Markdown 不算写代码')
  const evaluation = evaluate(state, {})
  eq(evaluation.state, 'na', '非代码会话评审状态为 na')
  eq(evaluation.verdict, 'fail', '非代码会话不产生通过结论')
}

// ---------------------------------------------------------------------------
// 3. 服务端会话：推荐零信任 + 供应链，且「需要几种」合理
// ---------------------------------------------------------------------------
{
  const state = makeState({ id: 's3', cwd: 'F:/DSH1.0/serve' })
  ingestAll(state, [
    toolCall('write', { file_path: 'serve/package.json', content: '{"name":"serve","dependencies":{"express":"^4"}}' }),
    toolCall('write', { file_path: 'serve/pnpm-lock.yaml', content: 'lockfileVersion: 9' }),
    toolCall('edit', {
      file_path: 'serve/server.js',
      old_string: 'old',
      new_string: 'const sql = "SELECT * FROM updates WHERE id = " + req.query.id; app.get("/admin", (req,res)=>{ if (req.user.isAdmin) res.json({ok:true}) });',
    }),
  ])
  eq(state.code.projectKind, 'server', '技术栈判定为服务端')
  const recommendation = recommendArchitectures(state)
  ok(recommendation.core.some((arch) => arch.id === 'zero-trust'), '服务端推荐零信任')
  ok(recommendation.core.some((arch) => arch.id === 'slsa'), '推荐 SLSA（供应链）')
  ok(recommendation.count >= 5, '服务端核心架构数量 >= 5', `实际 ${recommendation.count}`)
  const evaluation = evaluate(state, {})
  const serverRules = evaluation.rules.filter((rule) => rule.applies === '服').map((rule) => rule.id)
  ok(serverRules.length > 0, '服务端规则（服）进入适用范围')
}

// ---------------------------------------------------------------------------
// 4. 冲突检测：手动选择互斥架构对
// ---------------------------------------------------------------------------
{
  const state = makeState({ id: 's4', cwd: 'F:/DSH1.0/serve' })
  ingestAll(state, [toolCall('write', { file_path: 'serve/a.ts', content: 'const x = 1' })])
  state.review.selectedArchitectures = ['rbac', 'abac', 'zero-trust', 'network-allowlist', 'slsa', 'local-sign']
  const recommendation = recommendArchitectures(state)
  const conflicts = detectConflicts(state, recommendation)
  const ids = conflicts.map((item) => item.id)
  ok(ids.includes('rbac-vs-abac'), '检出 RBAC 与 ABAC 重叠冲突')
  ok(ids.includes('zt-vs-ip-allowlist'), '检出零信任与 IP 白名单冲突')
  ok(ids.includes('slsa-vs-local-sign'), '检出 SLSA 与本地签名冲突')
  ok(conflicts.every((item) => item.detail && item.resolution), '冲突都带说明与处理建议')

  // 冲突未登记时不能通过
  const before = evaluate(state, {})
  ok(before.blockers.some((blocker) => blocker.code === 'architecture-conflict'), '冲突未登记处理结论会阻断评审')

  // 登记后不再因该条阻断
  let ackOk = true
  for (const conflict of conflicts) {
    const result = ackConflict(state, conflict.id, '按建议拆分职责并记录')
    ackOk = ackOk && result.ok
  }
  ok(ackOk, '冲突处理结论可以登记')
  const after = detectConflicts(state, recommendArchitectures(state))
  ok(after.every((item) => item.acknowledged), '登记后冲突标记为已处理')
}

// ---------------------------------------------------------------------------
// 5. 评审提交：L1 不可豁免、L2 可豁免、全满足后通过
// ---------------------------------------------------------------------------
{
  const state = makeState({ id: 's5', cwd: 'F:/DSH1.0/serve' })
  ingestAll(state, [
    toolCall('write', {
      file_path: 'serve/main.js',
      content: '// clean code, uses parameterized queries\nconst q = db.prepare("SELECT * FROM t WHERE id = ?");\n',
    }),
  ])
  refreshProfile(state)

  // 先登记所有推荐架构冲突（干净代码里可能仍推荐重叠架构）
  const recommendation = recommendArchitectures(state)
  for (const conflict of detectConflicts(state, recommendation)) ackConflict(state, conflict.id, '已按建议确定主模型')

  // L1 豁免被拒绝
  const l1 = RULES.find((rule) => rule.level === 'L1')
  const waive = waiveRule(state, l1.id, '不想做，给我豁免')
  eq(waive.ok, false, 'L1 强制项不允许豁免')
  eq(waive.error.code, 'l1-not-waivable', 'L1 豁免错误码正确')

  // 构造完整证据：所有适用规则都提交 pass
  const rules = {}
  const evaluation = evaluate(state, {})
  for (const rule of evaluation.rules) {
    rules[rule.id] = { verdict: 'pass', evidence: `已完成：${rule.title}（自测证据 ${rule.id}）` }
  }
  const submission = submitReview(state, { rules, notes: '自测提交' }, {})
  eq(submission.ok, true, '评审提交被接受')
  eq(submission.evaluation.verdict, 'pass', '全部规则有证据且无冲突后评审通过')
  eq(submission.evaluation.state, 'passed', '评审状态变为 passed')
  eq(submission.evaluation.blockers.length, 0, '通过时没有阻断项')

  // 通过后写新代码 → 评审失效
  ingestSessionEvent(state, toolCall('edit', { file_path: 'serve/main.js', old_string: 'a', new_string: 'const q = "SELECT * FROM t WHERE id=" + req.query.id' }, 2))
  refreshProfile(state)
  const afterEdit = evaluate(state, {})
  eq(afterEdit.state, 'pending', '通过后继续改代码，评审重新变为 pending（失效）')
  ok(afterEdit.dirty, '脏标记生效')
}

// ---------------------------------------------------------------------------
// 6. L2 豁免路径
// ---------------------------------------------------------------------------
{
  const state = makeState({ id: 's6', cwd: 'F:/DSH1.0/serve' })
  ingestAll(state, [toolCall('write', { file_path: 'serve/x.js', content: 'const a = 1;' })])
  const l2 = RULES.find((rule) => rule.level === 'L2' && rule.applies === '通')
  const result = waiveRule(state, l2.id, '本项目无此场景，补偿控制：集中审计入口已覆盖')
  eq(result.ok, true, 'L2 可以豁免')
  const evaluation = evaluate(state, {})
  const entry = evaluation.rules.find((rule) => rule.id === l2.id)
  eq(entry.status, 'waived', 'L2 豁免后状态为 waived')
  ok(state.review.waived[l2.id].expiresAt > Date.now(), '豁免带到期时间')
}

// ---------------------------------------------------------------------------
// 7. 反模式误报回归：服务端 isAdmin 不算客户端授权；客户端 localStorage 才算
// ---------------------------------------------------------------------------
{
  const server = makeState({ id: 's7-server', cwd: 'F:/DSH1.0/serve' })
  ingestAll(server, [
    toolCall('write', { file_path: 'serve/server.js', content: 'if (req.user.isAdmin) { return allow(req) }' }),
  ])
  const serverConflicts = detectConflicts(server, recommendArchitectures(server))
  ok(!serverConflicts.some((item) => item.id === 'zt-vs-client-authz'), '服务端集中鉴权不会被误判为客户端授权冲突')

  const android = makeState({ id: 's7-android', cwd: 'F:/DSH1.0/jizhang' })
  ingestAll(android, [
    toolCall('write', { file_path: 'app/src/main/AndroidManifest.xml', content: '<manifest/>' }),
    toolCall('write', { file_path: 'app/src/main/java/Main.java', content: 'boolean vip = localStorage.getItem("role").equals("vip");' }),
  ])
  ok(android.anti.some((item) => item.arch === 'client-authz'), '客户端 localStorage 权限判断被识别为反模式')
  const androidConflicts = detectConflicts(android, recommendArchitectures(android))
  ok(androidConflicts.some((item) => item.id === 'masvs-vs-client-authz'), '客户端授权反模式与 MASVS 验收基线冲突')

  const obscurity = makeState({ id: 's7-obscure', cwd: 'F:/DSH1.0' })
  ingestAll(obscurity, [
    toolCall('write', { file_path: 'tools/hide.ps1', content: 'Move-Item $p $hiddenBackupDir  # 隐藏备份目录，不进用户视野' }),
  ])
  ok(!obscurity.anti.some((item) => item.arch === 'security-by-obscurity'), '「隐藏备份目录」不会被误判为藏起来的安全')
}

// ---------------------------------------------------------------------------
// 8. 目录完整性：规则 / 架构 / 冲突 / 自动检查引用一致
// ---------------------------------------------------------------------------
{
  eq(RULES.length, 72, '规则总数为 72 条（A8+B8+C6+D9+E9+F9+G7+H5+I6+J5）')
  const levels = RULES.reduce((map, rule) => {
    map[rule.level] = (map[rule.level] || 0) + 1
    return map
  }, {})
  eq(levels.L1, 54, 'L1 规则 54 条')
  eq(levels.L2, 12, 'L2 规则 12 条')
  eq(levels.L3, 6, 'L3 规则 6 条')

  for (const rule of RULES) {
    if (rule.auto) ok(Boolean(AUTO_CHECKS[rule.id]), `自动规则 ${rule.id} 有对应检查`)
  }
  for (const arch of ARCH_BY_ID.values()) {
    for (const ruleId of arch.rules || []) {
      ok(RULE_BY_ID.has(ruleId), `架构 ${arch.id} 引用的规则 ${ruleId} 存在`)
    }
  }
  for (const conflict of CONFLICTS) {
    ok(ARCH_BY_ID.has(conflict.a), `冲突 ${conflict.id} 的架构 a 存在`)
    ok(ARCH_BY_ID.has(conflict.b), `冲突 ${conflict.id} 的架构 b 存在`)
    for (const ruleId of conflict.rules || []) {
      ok(RULE_BY_ID.has(ruleId), `冲突 ${conflict.id} 引用的规则 ${ruleId} 存在`)
    }
  }
  // 自动检查正则必须都能编译
  for (const [ruleId, check] of Object.entries(AUTO_CHECKS)) {
    const patterns = check.kind === 'text' ? check.patterns : (check.kind === 'file' ? check.files : [])
    for (const pattern of patterns) {
      let compiles = true
      try {
        new RegExp(pattern.re, pattern.flags || 'i')
      } catch {
        compiles = false
      }
      ok(compiles, `自动检查 ${ruleId} 的正则合法：${pattern.re}`)
    }
  }
}

// ---------------------------------------------------------------------------
// 9. 会话内评审口令识别
// ---------------------------------------------------------------------------
{
  const positives = [
    '检查审核评审该会话',
    '帮我审核评审这个会话的代码',
    '评审一下这个会话',
    '代码安全防御评审',
    '检查一下这个插件的代码安全',
    'review this session for security',
  ]
  for (const text of positives) {
    ok(detectReviewRequest(text), `口令识别命中：${text}`)
  }
  const negatives = [
    '不要评审这个会话',
    '不用检查代码',
    '停止评审',
    '评审一下架构方案',
    '这个设计怎么评审',
    '帮我看看这段代码',
    '今天天气不错',
  ]
  for (const text of negatives) {
    ok(!detectReviewRequest(text), `口令识别不误触发：${text}`)
  }

  const state = makeState({ id: 's9', cwd: 'F:/DSH1.0/security-judge' })
  ingestAll(state, [toolCall('write', { file_path: 'index.js', content: 'const a = 1' })])
  state.review.requestedAt = Date.now()
  const reminder = buildReminderText(state, {}, { phase: 'requested' })
  ok(reminder.includes('用户已在会话里要求评审'), '受理提醒说明用户要求评审')
  ok(reminder.includes('合格为止') || reminder.includes('直到合格'), '受理提醒保留合格为止语义')
}

// ---------------------------------------------------------------------------
// 10. 分发与可迁移性（J 组）：评审包含安装包自检
// ---------------------------------------------------------------------------
{
  const state = makeState({ id: 's10', cwd: 'F:/DSH1.0/security-judge' })
  ingestAll(state, [
    toolCall('write', { file_path: 'security-judge/package.json', content: '{"name":"demo","version":"1.0.0","files":["index.js"]}' }),
    toolCall('write', { file_path: 'security-judge/index.js', content: 'export const a = 1' }),
    toolCall('write', { file_path: 'security-judge/README.md', content: '# demo' }),
  ])
  eq(distributionCandidate(state), true, '有 package.json 的会话被识别为要产出安装包')
  const scope = rulesInScope(state).map((rule) => rule.id)
  for (const id of ['J-01', 'J-02', 'J-03', 'J-04', 'J-05']) {
    ok(scope.includes(id), `分发会话评审范围包含 ${id}`)
  }
  const recommendation = recommendArchitectures(state)
  ok(recommendation.architectures.some((arch) => arch.id === 'portable-dist'), '分发会话推荐「可分发安装架构」')

  // 没检测到分发包时不套 J 组规则
  const plain = makeState({ id: 's10-plain', cwd: 'F:/DSH1.0/serve' })
  ingestAll(plain, [toolCall('write', { file_path: 'serve/main.js', content: 'const a = 1' })])
  eq(distributionCandidate(plain), false, '没有安装包清单时不判定为分发会话')
  ok(!rulesInScope(plain).some((rule) => rule.applies === '发'), '非分发会话不套 J 组规则')

  // 分发自检结果直接进入评审：未通过 → J-04 违规；通过 → 自动通过
  state.distribution = { ok: false, findings: [{ file: 'client.js', why: '客户端入口不存在' }], checkedAt: Date.now() }
  const failed = evaluate(state, {})
  const j04fail = failed.rules.find((rule) => rule.id === 'J-04')
  eq(j04fail.status, 'violation', '分发自检未通过 → J-04 违规')
  ok(failed.failed.some((item) => item.id === 'J-04'), 'J-04 违规进入失败项')

  state.distribution = { ok: true, findings: [], checkedAt: Date.now() }
  const passed = evaluate(state, {})
  eq(passed.rules.find((rule) => rule.id === 'J-04').status, 'auto-clear', '分发自检通过 → J-04 自动通过')

  // 运行时文件里的本机绝对路径由 J-02 自动发现
  const absolute = makeState({ id: 's10-abs', cwd: 'F:/DSH1.0/serve' })
  ingestAll(absolute, [
    toolCall('write', { file_path: 'serve/package.json', content: '{"name":"demo","version":"1.0.0"}' }),
    toolCall('write', { file_path: 'serve/index.js', content: 'const secret = "F:\\\\DSH1.0\\\\private\\\\key.pem"' }),
  ])
  const absEval = evaluate(absolute, {})
  const j02 = absEval.rules.find((rule) => rule.id === 'J-02')
  ok(j02 && j02.status === 'violation', '硬编码本机绝对路径触发 J-02 违规')

  // 改好代码后：磁盘上的当前内容覆盖历史写入片段，不再误判
  absolute.fileTexts = {
    'serve/package.json': '{"name":"demo","version":"1.0.0"}',
    'serve/index.js': 'const secret = process.env.SECRET_PATH',
  }
  const fixedEval = evaluate(absolute, {})
  const j02fixed = fixedEval.rules.find((rule) => rule.id === 'J-02')
  ok(j02fixed && j02fixed.status !== 'violation', '磁盘当前内容已修复 → J-02 不再违规')

  // 扫描器自己的规则定义与 XML 命名空间不算违规代码
  const meta = makeState({ id: 's10-meta', cwd: 'F:/DSH1.0/security-judge' })
  ingestAll(meta, [
    toolCall('write', { file_path: 'lib/checks.js', content: "const checks = [{ re: '(?<![A-Za-z])md5\\\\s*\\\\(', why: '弱哈希' }, { re: 'AES/ECB|Cipher', why: 'ECB' }]\nconst svg = '<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>'\n" }),
  ])
  meta.fileTexts = {
    'lib/checks.js': "const checks = [{ re: '(?<![A-Za-z])md5\\\\s*\\\\(', why: '弱哈希' }, { re: 'AES/ECB|Cipher', why: 'ECB' }]\nconst svg = '<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>'\n",
  }
  const metaEval = evaluate(meta, {})
  const statusOf = (id) => (metaEval.rules.find((rule) => rule.id === id) || {}).status
  eq(statusOf('B-01'), 'auto-clear', '规则定义里的 md5( 不误判为弱哈希调用')
  eq(statusOf('D-05'), 'auto-clear', '规则定义里的 AES/ECB 不误判为 ECB 模式')
  eq(statusOf('D-02'), 'auto-clear', 'XML 命名空间 http://www.w3.org 不误判为明文传输')

  // 中文教学文本里引用的危险示例不算真实代码违规
  const doc = makeState({ id: 's10-doc', cwd: 'F:/DSH1.0/security-judge' })
  ingestAll(doc, [
    toolCall('write', { file_path: 'lib/coach.js', content: "const guide = '必须删除 md5( 调用，并移除 TrustAllCerts'\n" }),
  ])
  doc.fileTexts = { 'lib/coach.js': "const guide = '必须删除 md5( 调用，并移除 TrustAllCerts'\n" }
  const docEval = evaluate(doc, {})
  const docStatus = (id) => (docEval.rules.find((rule) => rule.id === id) || {}).status
  eq(docStatus('B-01'), 'auto-clear', '中文教学文本里的 md5( 示例不误判')
  eq(docStatus('D-02'), 'auto-clear', '中文教学文本里的 TrustAllCerts 示例不误判')

  const commentDoc = makeState({ id: 's10-comment', cwd: 'F:/DSH1.0/security-judge' })
  const commentText = '// 中文说明：必须删除 md5( 调用\nconst ok = 1\n'
  ingestAll(commentDoc, [toolCall('write', { file_path: 'lib/note.js', content: commentText })])
  commentDoc.fileTexts = { 'lib/note.js': commentText }
  const commentStatus = (id) => (evaluate(commentDoc, {}).rules.find((rule) => rule.id === id) || {}).status
  eq(commentStatus('B-01'), 'auto-clear', '中文注释里的 md5( 示例不误判')
}

// ---------------------------------------------------------------------------
// 11. 非写工具不算代码写入（present / read / grep 带 path 不应让评审失效）
// ---------------------------------------------------------------------------
{
  const state = makeState({ id: 's11', cwd: 'F:/DSH1.0/security-judge' })
  ingestAll(state, [
    toolCall('present', { files: [{ path: 'dist/sbom.cdx.json', description: 'SBOM' }] }),
    toolCall('read', { file_path: 'lib/core.js' }),
    toolCall('grep', { pattern: 'token', path: 'lib' }),
  ])
  eq(state.code.doing, false, 'present/read/grep 不产生代码写入')
  eq(state.code.writeCount, 0, '非写工具不增加写入计数')
}

// ---------------------------------------------------------------------------
// 12. Python 判定：独立脚本 ≠ 服务端；有清单或服务端框架/HTTP 迹象才算
// ---------------------------------------------------------------------------
{
  // 12.1 只写一个普通脚本（无清单、无框架）→ 不再判为 server
  const script = makeState({ id: 's12-script', cwd: 'F:/DSH1.0/tools' })
  const scriptText = 'import os\nprint("clean")\n'
  ingestAll(script, [toolCall('write', { file_path: 'tools/cleanup.py', content: scriptText })])
  script.fileTexts = { 'tools/cleanup.py': scriptText }
  refreshProfile(script)
  eq(script.code.projectKind, 'unknown', '普通 Python 脚本不再判为服务端')
  eq(isServerKind(script), false, '普通脚本不是服务端项目')
  eq(hasPythonServerEvidence(script), false, '普通脚本没有服务端证据')

  // 12.2 标准库 http.server 服务（漢舟·同心这类）→ 仍判 server
  const stdlib = makeState({ id: 's12-stdlib', cwd: 'F:/DSH1.0/teamhub' })
  const stdlibText = [
    'from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler',
    'class Handler(BaseHTTPRequestHandler):',
    '    pass',
    'ThreadingHTTPServer(("0.0.0.0", 8770), Handler).serve_forever()',
  ].join('\n') + '\n'
  ingestAll(stdlib, [toolCall('write', { file_path: 'teamhub/app.py', content: stdlibText })])
  stdlib.fileTexts = { 'teamhub/app.py': stdlibText }
  refreshProfile(stdlib)
  eq(stdlib.code.projectKind, 'server', '标准库 http.server 服务仍判为服务端')
  ok(hasPythonServerEvidence(stdlib), '标准库 HTTP 服务算服务端证据')

  // 12.3 有 requirements.txt 的项目 → server
  const manifest = makeState({ id: 's12-manifest', cwd: 'F:/DSH1.0/svc' })
  ingestAll(manifest, [
    toolCall('write', { file_path: 'svc/requirements.txt', content: 'flask==3.0.0\n' }),
    toolCall('write', { file_path: 'svc/main.py', content: 'print("x")\n' }),
  ])
  manifest.fileTexts = { 'svc/main.py': 'print("x")\n' }
  refreshProfile(manifest)
  eq(manifest.code.projectKind, 'server', '有 requirements.txt 的 Python 项目判为服务端')

  // 12.4 Flask 框架迹象 → server
  const flaskState = makeState({ id: 's12-flask', cwd: 'F:/DSH1.0/web' })
  const flaskText = 'from flask import Flask\napp = Flask(__name__)\n'
  ingestAll(flaskState, [toolCall('write', { file_path: 'web/app.py', content: flaskText })])
  flaskState.fileTexts = { 'web/app.py': flaskText }
  refreshProfile(flaskState)
  eq(flaskState.code.projectKind, 'server', 'Flask 框架迹象判为服务端')

  // 12.5 只是 requests 脚本 → 仍不是 server
  const requestScript = makeState({ id: 's12-requests', cwd: 'F:/DSH1.0/tools' })
  const reqText = 'import requests\nprint(requests.get("http://example.com").status_code)\n'
  ingestAll(requestScript, [toolCall('write', { file_path: 'tools/ping.py', content: reqText })])
  requestScript.fileTexts = { 'tools/ping.py': reqText }
  refreshProfile(requestScript)
  eq(requestScript.code.projectKind, 'unknown', 'requests 脚本不误判为服务端')
}

// ---------------------------------------------------------------------------
// 13. 会话分类：标题 + 用户要求 + 代码证据
// ---------------------------------------------------------------------------
{
  const dev = makeState({ id: 's13-dev', title: '代码安全防御规则评审判官插件', cwd: 'F:/DSH1.0/security-judge' })
  ingestAll(dev, [toolCall('write', { file_path: 'security-judge/lib/core.js', content: 'export const a = 1\n' })])
  eq(dev.category, 'dev', '插件开发会话分类为开发实现')
  eq(dev.categoryName, '开发实现', '会话分类带中文名称')

  const review = makeState({ id: 's13-review', title: '代码安全防御架构规则与评审', cwd: 'F:/DSH1.0' })
  const reviewPy = 'print("review")\n'
  ingestAll(review, [toolCall('write', { file_path: 'tools/a.py', content: reviewPy })])
  review.fileTexts = { 'tools/a.py': reviewPy }
  refreshProfile(review)
  eq(review.category, 'review', '架构评审/咨询标题分类为评审')

  const app = makeState({ id: 's13-app', title: 'APP功能开发、合规与部署咨询', cwd: 'F:/DSH1.0/jizhang' })
  ingestAll(app, [toolCall('write', { file_path: 'jizhang/AndroidManifest.xml', content: '<manifest/>' })])
  eq(app.category, 'dev', 'APP 开发会话分类为开发实现')

  const ops = makeState({ id: 's13-ops', title: '服务器部署与运维' })
  refreshProfile(ops)
  eq(ops.category, 'ops', '部署运维会话分类为运维部署')

  const docs = makeState({ id: 's13-docs', title: 'README 文档整理' })
  ingestAll(docs, [toolCall('write', { file_path: 'README.md', content: '# 文档\n' })])
  eq(docs.category, 'docs', '文档会话分类为文档知识')

  const byRequest = makeState({ id: 's13-req', title: '新会话' })
  byRequest.userRequests = [{ text: '请帮我做架构评审与咨询', at: Date.now() }]
  refreshProfile(byRequest)
  eq(byRequest.category, 'review', '用户要求命中评审关键词 → 评审分类')

  const view = buildSessionView(dev, {})
  eq(view.categoryName, '开发实现', '会话视图带分类名称')
  ok(Array.isArray(view.categoryWhy) && view.categoryWhy.length > 0, '会话视图带分类依据')
  ok(typeof classifySession(app).category === 'string', 'classifySession 可直接调用')
}

// ---------------------------------------------------------------------------
// 汇总
// ---------------------------------------------------------------------------
console.log(`\n自测结果：通过 ${passed} 项，失败 ${failed} 项`)
if (failed) {
  console.error('失败项：')
  for (const item of failures) console.error(`- ${item}`)
  process.exit(1)
}
console.log('全部通过')
