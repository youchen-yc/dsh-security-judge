// 回归保护用例：锚定规则编号与规则集版本，不锚定代码内容。
// 运行：node test/regression.mjs
// 规则集版本：v1.0 / 2026-10-28（A–I 67 条安全规则 + J 5 条交付规则，插件共 72 条）
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  createSessionState, ingestSessionEvent, refreshProfile,
  submitReview, evaluate, LEVEL_REQUIREMENTS, parseSecurityLevel,
} from '../lib/engine.js'

const dir = path.dirname(fileURLToPath(import.meta.url))
const fixtures = path.join(dir, 'fixtures')
const load = (name) => JSON.parse(fs.readFileSync(path.join(fixtures, name), 'utf8'))

const ruleSet = load('rule-set-v1.0.json')
const sessionFixture = load('session-server.json')
const evidenceFixture = load('evidence-full.json')
const archPass = load('architectures-pass.json').architectures
const archPartial = load('architectures-partial.json').architectures
const archConflict = load('architectures-with-conflict.json').architectures
const archV15 = load('architectures-v15.json').architectures
const securityLevelV = fs.readFileSync(path.join(fixtures, 'security-level-V.txt'), 'utf8')
const securityLevelInvalid = fs.readFileSync(path.join(fixtures, 'security-level-VI.txt'), 'utf8')

const RULE_SET_VERSION = ruleSet.ruleSetVersion

function makeState() {
  const state = createSessionState(sessionFixture.session)
  for (const event of sessionFixture.events) ingestSessionEvent(state, event)
  refreshProfile(state)
  return state
}

function evidenceWithout(...ids) {
  const rules = { ...evidenceFixture.rules }
  for (const id of ids) delete rules[id]
  return rules
}

function submit(state, rules, architectures) {
  return submitReview(state, { rules, architectures, notes: `fixture ${RULE_SET_VERSION}` }, {})
}

function assert(condition, message) {
  if (!condition) throw new Error(message)
}

const results = []

function caseRun(name, ruleId, ruleSetVersion, fn) {
  try {
    fn()
    results.push({ name, ruleId, ruleSetVersion, ok: true })
  } catch (error) {
    results.push({ name, ruleId, ruleSetVersion, ok: false, message: error.message })
  }
}

// 1. 证据全齐 + 达到 III 级架构及格线 → pass
caseRun('case_pass_full_evidence_and_architectures', 'ALL', RULE_SET_VERSION, () => {
  const ev = submit(makeState(), evidenceFixture.rules, archPass)
  assert(ev.ok, '提交应被接受')
  assert(ev.evaluation.verdict === 'pass', `期望 pass，实际 ${ev.evaluation.verdict}`)
  assert(ev.evaluation.blockers.length === 0, 'pass 时不应有阻断项')
})

// 2–5. 缺单条 L1 证据 → fail，且阻断项精确指向该规则
for (const ruleId of ['A-01', 'A-03', 'A-04', 'A-05']) {
  const name = `case_${ruleId.replace(/-/g, '')}_missing_evidence`
  caseRun(name, ruleId, RULE_SET_VERSION, () => {
    const ev = submit(makeState(), evidenceWithout(ruleId), archPass)
    assert(ev.evaluation.verdict === 'fail', `缺 ${ruleId} 时应 fail，实际 ${ev.evaluation.verdict}`)
    const hit = ev.evaluation.blockers.some((item) => item.code === 'rule-missing' && item.rule === ruleId)
    assert(hit, `阻断项应包含 rule-missing ${ruleId}`)
  })
}

// 6. III 级项目只做 2 种架构（低于 8 种及格线）→ fail；推荐数只是建议
caseRun('case_architecture_below_level_requirement', `III/${LEVEL_REQUIREMENTS.III}`, RULE_SET_VERSION, () => {
  const ev = submit(makeState(), evidenceFixture.rules, archPartial)
  assert(ev.evaluation.verdict === 'fail', `架构数不足应 fail，实际 ${ev.evaluation.verdict}`)
  const hit = ev.evaluation.blockers.find((item) => item.code === 'architecture-level-missing')
  assert(hit, '阻断项应包含 architecture-level-missing')
  assert(hit.level === 'III', `阻断项应标明级别 III，实际 ${hit.level}`)
  assert(hit.required === LEVEL_REQUIREMENTS.III, `III 级及格线应为 ${LEVEL_REQUIREMENTS.III}，实际 ${hit.required}`)
})

// 6d. 非法声明的错误信息：不锁原文，只锁语义要素（知道错在哪 + 知道该填什么）
caseRun('case_security_level_invalid_message', 'security-level-invalid', RULE_SET_VERSION, () => {
  const invalid = parseSecurityLevel(securityLevelInvalid)
  const message = String(invalid.error || '')
  assert(message.trim().length > 0, '错误信息不能为空')
  assert(message.includes('VI'), '错误信息应包含非法值原文 "VI"')
  const legal = ['I', 'II', 'III', 'IV', 'V']
  for (const level of legal) {
    const hit = new RegExp(`\\b${level}\\b`).test(message)
    assert(hit, `错误信息应列出合法级别 ${level}，实际：${message}`)
  }
  // 合法级别集合应恰为 I–V：排除作为非法输入出现的 VI 后，不得多出其它级别。
  const tokens = [...new Set(message.match(/\b(I|II|III|IV|V|VI|VII|VIII|IX|X)\b/g) || [])].filter((token) => token !== 'VI')
  assert(tokens.length === legal.length && legal.every((level) => tokens.includes(level)),
    `错误信息中的合法级别集合应恰为 I–V，实际：${tokens.join(',') || '（空）'}`)
})
caseRun('case_level_declared_V_requires_15', 'V/15', RULE_SET_VERSION, () => {
  const v = parseSecurityLevel(securityLevelV)
  assert(v.valid && v.level === 'V', `.security-level 应解析为 V，实际 ${JSON.stringify(v)}`)
  const tooFew = makeState()
  tooFew.securityLevel = v
  const failEval = submit(tooFew, evidenceFixture.rules, archPass)
  assert(failEval.evaluation.verdict === 'fail', `V 级只选 8 种应 fail，实际 ${failEval.evaluation.verdict}`)
  const missing = failEval.evaluation.blockers.find((item) => item.code === 'architecture-level-missing')
  assert(missing && missing.level === 'V' && missing.required === LEVEL_REQUIREMENTS.V,
    `应阻断到 V 级 15 种，实际 ${JSON.stringify(missing)}`)
  const enough = makeState()
  enough.securityLevel = v
  const passEval = submit(enough, evidenceFixture.rules, archV15)
  assert(passEval.evaluation.verdict === 'pass', `V 级选 15 种应 pass，实际 ${passEval.evaluation.verdict}`)
  const invalid = parseSecurityLevel(securityLevelInvalid)
  assert(!invalid.valid && /非法值/.test(invalid.error || ''), `VI 应报非法值，实际 ${JSON.stringify(invalid)}`)
  const bad = makeState()
  bad.securityLevel = invalid
  const badEval = submit(bad, evidenceFixture.rules, archV15)
  assert(badEval.evaluation.verdict === 'fail', '非法声明应收敛为 fail')
  assert(badEval.evaluation.blockers.some((item) => item.code === 'security-level-invalid'), '阻断项应包含 security-level-invalid')
})
caseRun('case_architecture_requirement_monotonic', 'LEVELS', RULE_SET_VERSION, () => {
  const levels = ['I', 'II', 'III', 'IV', 'V'].filter((level) => level in LEVEL_REQUIREMENTS)
  assert(levels.length >= 4, '至少应有 I–IV 四级及格线')
  for (let i = 1; i < levels.length; i += 1) {
    const prev = LEVEL_REQUIREMENTS[levels[i - 1]]
    const current = LEVEL_REQUIREMENTS[levels[i]]
    assert(current > prev, `${levels[i]} 级及格线必须大于 ${levels[i - 1]} 级：${current} 不大于 ${prev}`)
  }
  assert(LEVEL_REQUIREMENTS.IV > LEVEL_REQUIREMENTS.III, 'IV 级及格线必须大于 III 级')
})

// 7. 架构冲突未登记 → fail
caseRun('case_conflict_unacknowledged', 'saltzer-vs-obscurity', RULE_SET_VERSION, () => {
  const ev = submit(makeState(), evidenceFixture.rules, archConflict)
  assert(ev.evaluation.verdict === 'fail', `冲突未登记应 fail，实际 ${ev.evaluation.verdict}`)
  const hit = ev.evaluation.blockers.some((item) => item.code === 'architecture-conflict' && item.conflict === 'saltzer-vs-obscurity')
  assert(hit, '阻断项应包含 architecture-conflict saltzer-vs-obscurity')
})

// 8. 已通过后修改代码 → 评审状态自动回到 pending（不再 passed）
caseRun('case_pass_then_code_change_returns_pending', 'DIRTY', RULE_SET_VERSION, () => {
  const state = makeState()
  const first = submit(state, evidenceFixture.rules, archPass)
  assert(first.evaluation.verdict === 'pass', '首次提交应 pass')
  assert(first.evaluation.state === 'passed', '首次提交状态应为 passed')
  ingestSessionEvent(state, sessionFixture.postPassEdit)
  refreshProfile(state)
  const after = evaluate(state, {})
  assert(after.dirty === true, '改代码后 dirty 应为 true')
  assert(after.state === 'pending', `改代码后状态应回到 pending，实际 ${after.state}`)
})

let failed = 0
for (const item of results) {
  if (!item.ok) failed += 1
  console.log(`${item.ok ? 'PASS' : 'FAIL'} ${item.name}  [rule ${item.ruleId} | ruleSet ${item.ruleSetVersion}]${item.ok ? '' : `\n     ${item.message}`}`)
}
console.log(`\n规则集：${ruleSet.ruleSetVersion} / ${ruleSet.ruleSetDate}（安全规则 ${ruleSet.securityRuleCount} 条；插件合计 ${ruleSet.pluginRuleCount} 条）`)
console.log(`回归结果：${results.length - failed}/${results.length} 通过`)
if (failed) {
  console.error('规则集或行为发生变化时，请同步更新 fixtures 与用例，不要放宽断言。')
  process.exit(1)
}
