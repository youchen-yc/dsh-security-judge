/**
 * 教学模式（lib/coach.js）测试：连续不合格后教会话 AI「怎么改」。
 *   node test/coach-test.mjs
 */

import {
  createSessionState,
  ingestSessionEvent,
  refreshProfile,
  evaluate,
  recommendArchitectures,
} from '../lib/engine.js'
import { buildCoachPlan, renderCoachText } from '../lib/coach.js'

let passed = 0
let failed = 0
const failures = []
function ok(condition, name, detail = '') {
  if (condition) passed += 1
  else {
    failed += 1
    failures.push(`${name}${detail ? `：${detail}` : ''}`)
  }
}
function eq(actual, expected, name) {
  ok(actual === expected, name, `期望 ${JSON.stringify(expected)}，实际 ${JSON.stringify(actual)}`)
}

let clock = Date.now()
function toolCall(tool, args, turn = 1) {
  clock += 1000
  return { type: 'tool/call', time: clock, data: { turn, step: 1, callId: `c-${clock}`, name: tool, arguments: JSON.stringify(args) } }
}

// 会话：Android 代码 + 安装包清单 + 故意留弱哈希等违规
const state = createSessionState({ id: 'coach-1', title: '教学演示', cwd: 'F:/DSH1.0/jizhang', createdAt: Date.now(), status: 'running' })
for (const event of [
  toolCall('write', { file_path: 'app/package.json', content: '{"name":"demo","version":"1.0.0","files":["index.js"]}' }),
  toolCall('write', { file_path: 'app/index.js', content: 'MessageDigest md = MessageDigest.getInstance("MD5"); const q = "SELECT * FROM t WHERE id=" + id;' }),
  toolCall('write', { file_path: 'app/README.md', content: '# demo' }),
]) {
  ingestSessionEvent(state, event)
  state.turns.current = event.data.turn
}
refreshProfile(state)
state.review.redoCount = 2
state.review.attempts = 2

const evaluation = evaluate(state, {})
const recommendation = recommendArchitectures(state)
const plan = buildCoachPlan(state, evaluation, recommendation)

// 1. 自动命中项 → 逐条给「怎么改 / 交证据」
ok(plan.fixSteps.length > 0, '教学单包含自动命中修复步骤')
const b01 = plan.fixSteps.find((step) => step.rule === 'B-01')
ok(Boolean(b01), '教学单包含 B-01 弱哈希修复指引')
ok(String(b01 && b01.howTo).includes('BCrypt') || String(b01 && b01.howTo).includes('Argon2'), 'B-01 指引给出具体算法')
ok(String(b01 && b01.evidence).includes('B-01'), 'B-01 给出证据格式')
const e03 = plan.fixSteps.find((step) => step.rule === 'E-03')
ok(Boolean(e03) && String(e03.howTo).includes('参数化'), 'E-03 指引要求参数化查询')

// 2. 需要证据的规则 → 按判定标准给做法
ok(plan.attestSteps.some((step) => step.rule === 'A-01'), '教学单包含 A-01 需要证据的规则')
ok(plan.attestSteps.every((step) => step.howTo && step.evidence), '每条待证据规则都有做法与证据格式')

// 3. 架构与冲突教学
ok(plan.architectureSteps.length > 0, '教学单包含核心架构落地步骤')
ok(plan.architectureSteps.some((step) => step.id === 'asvs'), '包含 ASVS 验收架构的落地步骤')
ok(Array.isArray(plan.conflictSteps), '冲突教学可生成（无冲突时为空）')

// 4. 分发自检问题教学
state.distribution = { ok: false, findings: [{ file: 'client.js', why: '客户端入口不存在' }], checkedAt: Date.now() }
const distEval = evaluate(state, {})
const distPlan = buildCoachPlan(state, distEval, recommendation)
eq(distPlan.distributionSteps.length, 1, '教学单包含分发自检问题')
ok(String(distPlan.distributionSteps[0].howTo).includes('干净目录'), '分发自检问题给出干净环境修复步骤')

// 5. 渲染文本
const text = renderCoachText(plan)
ok(text.includes('教学'), '教学文本带教学模式标识')
ok(text.includes('怎么改'), '教学文本包含怎么改')
ok(text.includes('交证据'), '教学文本包含交证据')
ok(text.includes('提交格式'), '教学文本包含提交格式')
ok(text.includes('action=submit'), '教学文本包含下一步 submit')
ok(text.includes('需要补齐的核心代码安全防御架构'), '教学文本包含架构落地章节')
ok(text.includes('portable-dist') || text.includes('教学单过长') || text.includes('ASVS'), '教学文本包含具体架构或截断提示')

const longText = renderCoachText(plan, { maxChars: 200 })
ok(longText.length <= 200 + 60, '教学文本可截断（避免注入过长）')

console.log(`\n教学模式自测：通过 ${passed} 项，失败 ${failed} 项`)
if (failed) {
  console.error('失败项：')
  for (const item of failures) console.error(`- ${item}`)
  process.exit(1)
}
console.log('全部通过')
