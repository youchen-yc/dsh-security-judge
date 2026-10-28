/**
 * Host 核心自测：用假的 Cordis ctx / Agent / Session 驱动 lib/core.js，
 * 验证会话跟踪、授权、提醒、回合门禁、工具动作与 HTTP 接口。
 *
 *   node test/core-test.mjs
 */

import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

import { createCore } from '../lib/core.js'
import { createApiHandler, API_PREFIX } from '../lib/httpapi.js'

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

function wait(ms = 0) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

function arrFind(list, predicate) {
  return (Array.isArray(list) ? list : []).find(predicate)
}

/** 每个测试用独立数据目录，避免授权/设置互相污染。 */
const tempDirs = []
function coreFor(harness, version = 'test') {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sj-core-test-'))
  tempDirs.push(dataDir)
  return createCore({ ctx: harness.ctx, config: { dataDir }, log: harness.ctx.logger, pluginVersion: version })
}
function cleanupTempDirs() {
  for (const dir of tempDirs) {
    try {
      fs.rmSync(dir, { recursive: true, force: true })
    } catch {
      // ignore
    }
  }
}

// ---------------------------------------------------------------------------
// 假的宿主环境
// ---------------------------------------------------------------------------
function createHarness() {
  const listeners = new Map()
  const services = {}
  const sections = []
  const contexts = []
  const registeredTools = []
  const routes = []

  const ctx = {
    logger: { info() {}, warn() {}, error() {}, debug() {} },
    on(name, handler, options) {
      const list = listeners.get(name) || []
      list.push({ handler, options })
      listeners.set(name, list)
      return () => {
        const current = listeners.get(name) || []
        const index = current.findIndex((item) => item.handler === handler)
        if (index >= 0) current.splice(index, 1)
      }
    },
    get(name) {
      return services[name]
    },
    effect(fn) {
      const disposer = fn()
      return () => {
        if (typeof disposer === 'function') disposer()
      }
    },
    inject(names, callback) {
      if (names.every((name) => services[name])) return { dispose: () => {} }
      return { dispose: () => {} }
    },
    tools: {
      register(definition) {
        registeredTools.push(definition)
        return () => {}
      },
    },
    systemPrompt: {
      section(section) {
        sections.push(section)
        return () => {}
      },
      context(context) {
        contexts.push(context)
        return () => {}
      },
    },
    webServer: {
      register(route) {
        routes.push(route)
        return () => {}
      },
      getOrigin() {
        return 'http://127.0.0.1:55269'
      },
    },
  }

  const sessions = new Map()
  const agents = new Map()
  services.agents = {
    list: () => [...agents.values()],
    roots: () => [...agents.values()],
    get: (id) => agents.get(String(id)),
  }
  services.sessionTitle = { get: (session) => (session.title ? { title: session.title } : undefined) }
  services.workingDirectory = { get: (session) => session.cwd }
  services.webServer = ctx.webServer
  services.systemPrompt = ctx.systemPrompt
  services.tools = ctx.tools

  /** 造一个会话 + agent。 */
  function addSession({ id, title, cwd, status = 'idle' }) {
    const events = []
    const session = {
      id,
      title,
      cwd,
      header: { id, createdAt: Date.now(), cwd },
      seq: 0,
      snapshotEvents(from = 0, to = 0) {
        return events.slice(from, to)
      },
    }
    const agent = {
      id,
      session,
      status,
      injected: [],
      steered: [],
      followed: [],
      inject(message) {
        this.injected.push(message)
      },
      steer(message) {
        this.steered.push(message)
        this.status = 'running'
      },
      followup(message) {
        this.followed.push(message)
        this.status = 'running'
      },
    }
    sessions.set(id, { session, events })
    agents.set(id, agent)
    return { session, agent, events }
  }

  function append(sessionId, type, data) {
    const entry = sessions.get(sessionId)
    const event = { type, seq: entry.events.length, time: Date.now(), data }
    entry.events.push(event)
    entry.session.seq = entry.events.length
    return event
  }

  async function emit(name, ...args) {
    const list = listeners.get(name) || []
    for (const { handler } of list) {
      await handler(...args)
    }
  }

  async function emitSessionEvent(sessionId, type, data) {
    const entry = sessions.get(sessionId)
    const event = append(sessionId, type, data)
    await emit('session/event', entry.session, event)
    return event
  }

  return {
    ctx,
    services,
    sessions,
    agents,
    addSession,
    append,
    emit,
    emitSessionEvent,
    registeredTools,
    sections,
    contexts,
    routes,
    listeners,
  }
}

function toolCallData(name, args, turn = 1, step = 1) {
  return { turn, step, callId: `call-${Math.random().toString(36).slice(2)}`, name, arguments: JSON.stringify(args) }
}

// ---------------------------------------------------------------------------
// 1. 会话跟踪 + 代码识别 + 授权前只读
// ---------------------------------------------------------------------------
{
  const harness = createHarness()
  const { session, agent, events } = harness.addSession({ id: 'session-1', title: '记账 App', cwd: 'F:/DSH1.0/jizhang', status: 'idle' })
  // 预置一个已存在的写入事件（模拟插件晚于会话启动）
  events.push({
    type: 'tool/call',
    seq: 0,
    time: Date.now() - 5000,
    data: toolCallData('write', { file_path: 'app/src/main/java/a.java', content: 'class A {}' }),
  })
  session.seq = 1

  const core = coreFor(harness)
  core.start()
  await wait(10)

  const view = core.getSessionView('session-1')
  ok(Boolean(view), '插件启动后能跟踪已存在的会话')
  eq(view && view.code.doing, true, '回放事件后识别为写代码')
  eq(core.getAuthority().granted, false, '默认未授权')

  // 未授权时：回合收尾不拦截
  await harness.emit('agent/turn-stopping', { agent, turn: 1, signal: { aborted: false } })
  eq(agent.steered.length, 0, '未授权时不拦截回合')

  // 写代码也不注入
  await harness.emitSessionEvent('session-1', 'tool/call', toolCallData('write', { file_path: 'app/src/main/java/b.java', content: 'class B {}' }))
  eq(agent.injected.length, 0, '未授权时不注入提醒')

  await core.dispose()
}

// ---------------------------------------------------------------------------
// 2. 授权 + 提醒 + 回合门禁
// ---------------------------------------------------------------------------
{
  const harness = createHarness()
  const { agent } = harness.addSession({ id: 'session-2', title: '服务端', cwd: 'F:/DSH1.0/serve', status: 'running' })
  const core = coreFor(harness)
  core.start()
  await wait(10)

  const grant = await core.dispatch('grant-authority', { confirm: true })
  eq(grant.ok, true, '用户可以授权')
  eq(core.getAuthority().granted, true, '授权状态已保存')
  const badGrant = await core.dispatch('grant-authority', { confirm: false })
  eq(badGrant.ok, false, '授权必须带 confirm:true')

  // 写代码 → 首次注入提醒
  await harness.emitSessionEvent('session-2', 'tool/call', toolCallData('write', { file_path: 'serve/server.js', content: 'app.get("/x", (req,res)=>res.json({ok:true}))' }))
  eq(agent.injected.length, 1, '授权后首次写代码会注入评审提醒')
  ok(String(agent.injected[0].content[0].text).includes('代码安全防御评审判官'), '注入的消息是评审提醒')

  // 回合收尾：不合格 → 要求重做（默认不设上限，合格为止）
  await harness.emit('agent/turn-stopping', { agent, turn: 1, signal: { aborted: false } })
  eq(agent.steered.length, 1, '不合格时回合收尾被拦截（steer 继续重做）')
  ok(String(agent.steered[0].content[0].text).includes('不合格'), '拦截消息明确写「不合格」')
  ok(String(agent.steered[0].content[0].text).includes('重做'), '拦截消息要求重做')
  ok(String(agent.steered[0].content[0].text).includes('合格为止'), '拦截消息说明合格为止')

  // 连续不合格：一直要求重做，不允许「催几次就放行」
  for (let i = 0; i < 9; i += 1) {
    await harness.emit('agent/turn-stopping', { agent, turn: 1, signal: { aborted: false } })
  }
  eq(agent.steered.length, 10, '持续不合格会一直要求重做，直到合格为止')
  const redoView = core.getSessionView('session-2')
  eq(redoView.review.redoCount, 10, '会话视图记录重做次数')
  eq(redoView.review.unqualified, true, '未合格会话标记为不合格')
  ok(String(agent.steered[2].content[0].text).includes('教学'), '第三次强制重做进入教学模式（教怎么做）')
  const coach = await core.toolCoach('session-2')
  eq(coach.ok, true, '工具 coach 可用')
  ok(String(coach.text).includes('怎么改'), '教学单包含怎么改')
  ok(Array.isArray(coach.plan.fixSteps), '教学单包含自动命中修复步骤字段')
  ok(Array.isArray(coach.plan.attestSteps) && coach.plan.attestSteps.length > 0, '教学单包含需要证据的规则')

  // 用户最高权限：可以暂停/恢复强制重做（暂停后结论仍是不合格）
  const pause = await core.dispatch('pause-enforce', { sessionId: 'session-2', paused: true })
  eq(pause.ok, true, '用户可以暂停强制重做')
  await harness.emit('agent/turn-stopping', { agent, turn: 1, signal: { aborted: false } })
  eq(agent.steered.length, 10, '暂停后不再强制重做')
  eq(core.getSessionView('session-2').review.unqualified, true, '暂停不代表合格')
  await core.dispatch('pause-enforce', { sessionId: 'session-2', paused: false })
  await harness.emit('agent/turn-stopping', { agent, turn: 1, signal: { aborted: false } })
  eq(agent.steered.length, 11, '恢复后继续强制重做')

  // 用户自设保护阈值：到点停止自动催办，但结论仍是不合格
  await core.dispatch('settings-save', { patch: { maxEnforcePerSession: 2 } })
  await harness.emit('agent/turn-stopping', { agent, turn: 1, signal: { aborted: false } })
  eq(agent.steered.length, 11, '达到用户设置的强制重做上限后停止自动催办')
  eq(core.getSessionView('session-2').review.unqualified, true, '达到上限也不代表合格')
  await core.dispatch('settings-save', { patch: { maxEnforcePerSession: 0 } })

  // 状态查询
  const status = await core.toolStatus('session-2')
  eq(status.ok, true, '工具 status 可用')
  eq(status.codeWork, true, '工具 status 识别到代码工作')
  ok(status.neededArchitectures >= 5, '工具 status 给出需要几种架构', `实际 ${status.neededArchitectures}`)
  ok(Array.isArray(status.architectures) && status.architectures.length > 0, '工具 status 返回推荐架构')
  eq(status.authority.granted, true, '工具 status 返回授权状态')

  // 提交评审：先全失败
  const failedSubmit = await core.toolSubmit('session-2', { rules: {} })
  eq(failedSubmit.ok, true, '空提交被接受但结论为未通过')
  eq(failedSubmit.verdict, 'fail', '空提交评审不通过')
  ok(failedSubmit.blockers.length > 0, '空提交给出不合格原因')
  ok(String(failedSubmit.reminder).includes('不合格'), '失败提交提示不合格')
  ok(String(failedSubmit.reminder).includes('重做'), '失败提交提示必须重做')
  ok(failedSubmit.coaching === true, '多次不合格后提交失败进入教学模式')
  ok(String(failedSubmit.coach || '').includes('怎么改'), '提交失败返回教学单')

  // 构造通过证据
  const checklist = await core.toolStatus('session-2', { detail: true })
  const rules = {}
  for (const rule of checklist.rules || []) {
    rules[rule.id] = { verdict: 'pass', evidence: `已按规则落实：${rule.title}` }
  }
  // 先登记架构冲突（如果有）
  const architectures = await core.toolArchitectures('session-2')
  for (const conflict of architectures.conflicts || []) {
    await core.dispatch('ack-conflict', { sessionId: 'session-2', conflictId: conflict.id, resolution: '确定单一主模型并记录' })
  }
  const passedSubmit = await core.toolSubmit('session-2', { rules, notes: '自测' })
  eq(passedSubmit.verdict, 'pass', '补齐证据且冲突登记后评审通过')
  eq(passedSubmit.reviewState, 'passed', '评审状态 passed')

  // 通过后回合收尾不再拦截
  await harness.emit('agent/turn-stopping', { agent, turn: 2, signal: { aborted: false } })
  eq(agent.steered.length, 11, '评审合格后不再拦截回合')
  eq(core.getSessionView('session-2').review.redoCount, 0, '合格后重做计数清零')

  // 通过后再写代码 → 评审失效，回合再次拦截并要求重做
  await harness.emitSessionEvent('session-2', 'tool/call', toolCallData('edit', { file_path: 'serve/server.js', old_string: 'a', new_string: 'const q = "SELECT * FROM t WHERE id=" + req.query.id' }, 2))
  await harness.emit('agent/turn-stopping', { agent, turn: 2, signal: { aborted: false } })
  eq(agent.steered.length, 12, '合格后改代码会让评审失效并再次拦截')
  eq(core.getSessionView('session-2').review.redoCount, 1, '失效后重新计重做次数')

  // 处置
  await core.dispose()
}

// ---------------------------------------------------------------------------
// 3. 非代码会话不提醒、不拦截
// ---------------------------------------------------------------------------
{
  const harness = createHarness()
  const { agent } = harness.addSession({ id: 'session-3', title: '文案', cwd: 'F:/DSH1.0/招聘文案', status: 'running' })
  const core = coreFor(harness)
  core.start()
  await wait(10)
  await core.dispatch('grant-authority', { confirm: true })
  await harness.emitSessionEvent('session-3', 'tool/call', toolCallData('write', { file_path: '招聘.md', content: '# 招聘' }))
  eq(agent.injected.length, 0, '非代码会话不注入提醒')
  await harness.emit('agent/turn-stopping', { agent, turn: 1, signal: { aborted: false } })
  eq(agent.steered.length, 0, '非代码会话不拦截回合')
  const status = await core.toolStatus('session-3')
  eq(status.codeWork, false, '非代码会话工具显示不做代码评审')
  eq(status.neededArchitectures, 0, '非代码会话不推荐架构')
  const remind = await core.dispatch('remind', { sessionId: 'session-3' })
  eq(remind.ok, false, '非代码会话拒绝手动提醒')
  await core.dispose()
}

// ---------------------------------------------------------------------------
// 4. 架构推荐与冲突动作
// ---------------------------------------------------------------------------
{
  const harness = createHarness()
  harness.addSession({ id: 'session-4', title: '服务端', cwd: 'F:/DSH1.0/serve', status: 'running' })
  const core = coreFor(harness)
  core.start()
  await wait(10)
  await harness.emitSessionEvent('session-4', 'tool/call', toolCallData('write', {
    file_path: 'serve/server.js',
    content: "const trusted = req.ip.startsWith('192.168.1.'); if (trusted) return allow(req);",
  }))
  const architectures = await core.toolArchitectures('session-4')
  eq(architectures.ok, true, '架构动作可用')
  ok(architectures.architectureCount >= 5, '服务端给出多种核心架构')
  ok(architectures.conflicts.some((item) => item.id === 'zt-vs-ip-allowlist'), '代码里的内网白名单判断触发零信任冲突')
  const ack = await core.dispatch('ack-conflict', { sessionId: 'session-4', conflictId: 'zt-vs-ip-allowlist', resolution: '白名单只做路由，授权改由服务端逐请求校验' })
  eq(ack.ok, true, '冲突处理结论可以登记')
  const waive = await core.dispatch('waive', { sessionId: 'session-4', rule: 'A-02', reason: '测试豁免' })
  eq(waive.ok, false, 'L1 不能从面板豁免')
  await core.dispose()
}

// ---------------------------------------------------------------------------
// 5. HTTP 接口
// ---------------------------------------------------------------------------
{
  const harness = createHarness()
  harness.addSession({ id: 'session-5', title: '接口会话', cwd: 'F:/DSH1.0/serve', status: 'running' })
  const core = coreFor(harness, '1.0.0')
  core.start()
  await wait(10)
  const PAGE_TOKEN = 'test-page-token'
  const ORIGIN = 'http://127.0.0.1:55269'
  const handler = createApiHandler({ core, log: harness.ctx.logger, pluginVersion: '1.0.0', getToken: () => PAGE_TOKEN })

  function fakeRequest(method, url, body, options = {}) {
    const token = options.token === undefined ? PAGE_TOKEN : options.token
    const requestOrigin = options.origin === undefined ? ORIGIN : options.origin
    const listeners = {}
    const headers = {}
    if (requestOrigin) headers.origin = requestOrigin
    if (token) headers['x-security-judge-token'] = token
    const req = {
      method,
      url,
      headers,
      on(name, callback) {
        listeners[name] = callback
        if (name === 'data' && body !== undefined) callback(Buffer.from(JSON.stringify(body)))
        if (name === 'end') callback()
        return req
      },
      destroy() {},
    }
    return req
  }

  async function call(method, url, body, options = {}) {
    const req = fakeRequest(method, url, body, options)
    const response = {
      statusCode: 0,
      headers: {},
      setHeader(name, value) {
        this.headers[name.toLowerCase()] = value
      },
      end(payload) {
        this.body = payload
      },
    }
    await handler(req, response)
    return { status: response.statusCode, headers: response.headers, body: response.body ? JSON.parse(response.body) : null }
  }

  // 1) 无令牌 GET 可以读（只读接口不要求令牌）；写操作没有令牌必须 401
  const readNoToken = await call('GET', API_PREFIX + '/state', undefined, { token: '' })
  eq(readNoToken.status, 200, '无令牌 GET /state 仍可读取（只读接口）')
  const writeNoToken = await call('POST', API_PREFIX + '/action', { action: 'grant-authority', payload: { confirm: true } }, { token: '' })
  eq(writeNoToken.status, 401, '无令牌写操作返回 401')
  eq(writeNoToken.body.error.code, 'unauthorized', '无令牌写操作错误码正确')
  eq(core.getAuthority().granted, false, '无令牌不能授予评审权限')

  // 2) 伪造令牌授权 → 401，且授权状态不变（防 CSRF 静默授权）
  const forged = await call('POST', API_PREFIX + '/action', { action: 'grant-authority', payload: { confirm: true } }, { token: 'forged-token' })
  eq(forged.status, 401, '伪造令牌不能调用接口')
  eq(core.getAuthority().granted, false, '伪造令牌不能授予评审权限')

  // 3) 跨站 Origin → 403
  const cross = await call('GET', API_PREFIX + '/state', undefined, { origin: 'https://evil.example' })
  eq(cross.status, 403, '跨站 Origin 被拒绝')

  // 4) 正常请求：带页面令牌
  const state = await call('GET', API_PREFIX + '/state')
  eq(state.status, 200, '带页面令牌 GET /state 返回 200')
  eq(state.body.ok, true, 'GET /state 返回 ok')
  ok(Array.isArray(state.body.sessions), 'GET /state 带 sessions')
  ok(Boolean(state.body.catalog && state.body.catalog.ruleGroups.length === 10), 'GET /state 带 10 组规则目录')
  eq(state.body.authority.granted, false, 'GET /state 默认未授权')

  const optionsResponse = await call('OPTIONS', API_PREFIX + '/state', undefined, { token: '', origin: ORIGIN })
  eq(optionsResponse.status, 204, 'CORS 预检返回 204')
  ok(String(optionsResponse.headers['access-control-allow-headers'] || '').includes('x-security-judge-token'), '预检允许页面令牌头')

  const granted = await call('POST', API_PREFIX + '/action', { action: 'grant-authority', payload: { confirm: true } })
  eq(granted.status, 200, 'POST grant-authority 返回 200')
  eq(granted.body.ok, true, 'POST grant-authority 成功')
  eq(granted.body.state.authority.granted, true, '授权后 state 同步更新')

  const bad = await call('POST', API_PREFIX + '/action', { action: 'nope' })
  eq(bad.body.ok, false, '未知 action 返回失败')
  eq(bad.body.error.code, 'unknown-action', '未知 action 错误码正确')

  const missing = await call('POST', API_PREFIX + '/action', { action: 'review', payload: { sessionId: 'missing' } })
  eq(missing.status, 404, '找不到会话返回 404')
  eq(missing.body.error.code, 'unknown-session', '找不到会话错误码正确')

  await core.dispose()
}

// ---------------------------------------------------------------------------
// 6. 会话内口令：检查审核评审该会话
// ---------------------------------------------------------------------------
{
  const harness = createHarness()
  const { session, agent, events } = harness.addSession({ id: 'session-6', title: '旧插件会话', cwd: 'F:/DSH1.0/security-judge', status: 'running' })
  // 三天前的代码工作：正常回放（24 小时窗口）不会拿到。
  events.push({
    type: 'tool/call',
    seq: 0,
    time: Date.now() - 3 * 24 * 60 * 60 * 1000,
    data: toolCallData('write', { file_path: 'security-judge/index.js', content: 'const a = 1' }),
  })
  session.seq = 1
  const core = coreFor(harness)
  core.start()
  await wait(10)
  eq(core.getSessionView('session-6').code.doing, false, '超过 24 小时的旧代码初始不回看')

  // 未授权：口令受理，但不注入（只读观察）
  await harness.emitSessionEvent('session-6', 'user/message', {
    content: [{ type: 'text', text: '检查审核评审该会话' }],
    source: { kind: 'user' },
  })
  const requestedView = core.getSessionView('session-6')
  eq(requestedView.code.doing, true, '评审口令把旧代码工作找回来')
  ok(requestedView.review.requestedAt > 0, '会话标记「用户已要求评审」')
  eq(agent.injected.length, 0, '未授权时受理评审不注入消息（只读）')
  ok(String(core.promptContextFor(agent)).includes('要求评审'), '系统提示告知评审要求')
  const requestedStatus = await core.toolStatus('session-6')
  eq(requestedStatus.requestedAt > 0, true, '工具状态带评审要求')
  eq(requestedStatus.unqualified, true, '受理后尚未合格')

  // 授权后：受理会注入通知，不合格会被要求重做
  await core.dispatch('grant-authority', { confirm: true })
  await harness.emitSessionEvent('session-6', 'user/message', {
    content: [{ type: 'text', text: '评审这个会话的代码' }],
    source: { kind: 'user' },
  })
  ok(agent.injected.length >= 1, '授权后受理会注入评审受理通知')
  const steeredBefore = agent.steered.length
  await harness.emit('agent/turn-stopping', { agent, turn: 1, signal: { aborted: false } })
  eq(agent.steered.length, steeredBefore + 1, '受理后不合格会被要求重做')

  // 补齐证据 → 合格 → 不再要求重做
  const checklist = await core.toolStatus('session-6', { detail: true })
  const distributionView = core.getSessionView('session-6')
  eq(distributionView.distribution && distributionView.distribution.ok, true, '有安装包的会话完成分发自检')
  const j04 = arrFind((distributionView.rules || []), (rule) => rule.id === 'J-04')
  ok(Boolean(j04) && j04.status === 'auto-clear', '分发自检通过 → J-04 自动通过')
  const rules = {}
  for (const rule of checklist.rules || []) {
    rules[rule.id] = { verdict: 'pass', evidence: `已按规则落实：${rule.title}` }
  }
  const architectures = await core.toolArchitectures('session-6')
  for (const conflict of architectures.conflicts || []) {
    await core.dispatch('ack-conflict', { sessionId: 'session-6', conflictId: conflict.id, resolution: '确定单一主模型并记录' })
  }
  const submit = await core.toolSubmit('session-6', { rules })
  eq(submit.verdict, 'pass', '被要求评审的会话补齐证据后合格')
  const steeredAfterPass = agent.steered.length
  await harness.emit('agent/turn-stopping', { agent, turn: 2, signal: { aborted: false } })
  eq(agent.steered.length, steeredAfterPass, '合格后不再要求重做')

  // 否定说法不触发
  const other = harness.addSession({ id: 'session-7', title: '普通会话', cwd: 'F:/DSH1.0', status: 'running' })
  await harness.emitSessionEvent('session-7', 'user/message', {
    content: [{ type: 'text', text: '不要评审这个会话' }],
    source: { kind: 'user' },
  })
  eq((core.sessions.get('session-7') || {}).review.requestedAt || 0, 0, '否定说法不会触发评审要求')

  await core.dispose()
}

// ---------------------------------------------------------------------------
// 汇总
// ---------------------------------------------------------------------------
cleanupTempDirs()
console.log(`\nHost 核心自测：通过 ${passed} 项，失败 ${failed} 项`)
if (failed) {
  console.error('失败项：')
  for (const item of failures) console.error(`- ${item}`)
  process.exit(1)
}
console.log('全部通过')
