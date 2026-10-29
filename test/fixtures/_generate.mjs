// 生成回归测试 fixture。规则集版本变化时重新运行本文件，并让回归用例暴露差异。
// 用法：node test/fixtures/_generate.mjs
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  createSessionState, ingestSessionEvent, refreshProfile,
  rulesInScope, recommendArchitectures, LEVEL_REQUIREMENTS,
} from '../../lib/engine.js'

const fixtureDir = path.dirname(fileURLToPath(import.meta.url))
const ruleSet = {
  ruleSetVersion: 'v1.0',
  ruleSetDate: '2026-10-28',
  securityRuleCount: 67,
  deliveryRuleCount: 5,
  pluginRuleCount: 72,
  note: 'A–I 为 67 条安全规则；J 组 5 条为交付规则，不计入安全规则总数。',
}

const session = { id: 'fixture-server', title: 'fixture: server with clean code', cwd: 'F:/fixtures/serve' }
const code = {
  'serve/package.json': '{"name":"fixture-server","version":"1.0.0","dependencies":{"express":"^4.19.0"}}\n',
  'serve/server.js': [
    "const express = require('express')",
    'const app = express()',
    "app.get('/api/items', (req, res) => {",
    '  const user = req.user',
    '  if (!user || !user.permissions.includes("items:read")) return res.status(403).json({ error: "forbidden" })',
    '  res.json({ ok: true })',
    '})',
    'app.listen(8080)',
    '',
  ].join('\n'),
}
const events = []
let seq = 1
for (const [file, content] of Object.entries(code)) {
  events.push({
    type: 'tool/call',
    seq: seq++,
    time: 1793220000000 + seq * 1000,
    data: { turn: 1, step: seq, callId: `fx-${seq}`, name: 'write', arguments: JSON.stringify({ file_path: file, content }) },
  })
}
const postPassEdit = {
  type: 'tool/call',
  seq: seq++,
  time: 1793220000000 + seq * 1000,
  data: { turn: 2, step: 1, callId: 'fx-edit', name: 'edit', arguments: JSON.stringify({ file_path: 'serve/server.js', old_string: 'res.json({ ok: true })', new_string: 'res.json({ ok: true, changed: true })' }) },
}

const state = createSessionState(session)
for (const event of events) ingestSessionEvent(state, event)
refreshProfile(state)
const scope = rulesInScope(state)
const recommendation = recommendArchitectures(state)
const rules = {}
for (const rule of scope) rules[rule.id] = { verdict: 'pass', evidence: `fixture-v1.0: ${rule.id} 已按规则落实` }
const coreIds = recommendation.core.map((arch) => arch.id)

const write = (name, value) => fs.writeFileSync(path.join(fixtureDir, name), JSON.stringify(value, null, 2) + '\n', 'utf8')
write('rule-set-v1.0.json', ruleSet)
write('session-server.json', {
  ruleSetVersion: 'v1.0',
  session,
  code,
  events,
  postPassEdit,
  expected: { inScope: scope.length, coreArchitectures: recommendation.count, level: 'III', levelRequirement: LEVEL_REQUIREMENTS.III },
})
write('evidence-full.json', { ruleSetVersion: 'v1.0', rules })
const levelPass = [...coreIds, 'stride', 'defense-in-depth']
write('architectures-pass.json', { ruleSetVersion: 'v1.0', architectures: levelPass })
write('architectures-core.json', { ruleSetVersion: 'v1.0', architectures: coreIds })
write('architectures-partial.json', { ruleSetVersion: 'v1.0', architectures: coreIds.slice(0, 2) })
write('architectures-with-conflict.json', { ruleSetVersion: 'v1.0', architectures: [...coreIds, 'stride', 'security-by-obscurity'] })
const level15 = [...recommendation.architectures.map((arch) => arch.id), 'governance'].slice(0, 15)
write('architectures-v15.json', { ruleSetVersion: 'v1.0', architectures: level15 })
fs.writeFileSync(path.join(fixtureDir, 'security-level-V.txt'), 'V\n', 'utf8')
fs.writeFileSync(path.join(fixtureDir, 'security-level-VI.txt'), 'VI\n', 'utf8')

console.log(JSON.stringify({ inScope: scope.length, core: recommendation.count, coreIds, levelPass, level15 }, null, 2))
