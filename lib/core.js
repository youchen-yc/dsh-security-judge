/**
 * 代码安全防御评审判官 · Host 核心。
 *
 * 职责：
 *   1. 跟踪所有活跃会话，从 session/event 里识别「正在写代码」；
 *   2. 为每个代码会话推荐应该采用哪些代码安全防御架构（一种 / 两种 / 多种），
 *      并检查这些架构之间是否冲突；
 *   3. 用《代码安全防御架构规则》v1.0 自动检查 + 证据提交做评审；
 *   4. 用户授权后，在回合收尾时拦截「未通过评审的代码任务」，并提醒会话 AI；
 *   5. 给 Web 面板与 security_judge 工具提供状态与操作。
 *
 * 权限边界：本插件权限低于用户最高权限，只用于代码安全防御评审。
 * 未授权时只读观察，不向会话注入消息、不拦截回合。
 */

import fs from 'node:fs/promises'
import path from 'node:path'
import { randomUUID } from 'node:crypto'

import { createStore, CHARTER, AUTHORITY_SCOPE } from './store.js'
import {
  createSessionState,
  ingestSessionEvent,
  refreshProfile,
  buildSessionView,
  evaluate,
  recommendArchitectures,
  submitReview,
  waiveRule,
  ackConflict,
  buildReminderText,
  detectConflicts,
  detectReviewRequest,
  distributionCandidate,
} from './engine.js'
import { locatePackageDir, inspectPackage } from './dist.js'
import { buildCoachPlan, renderCoachText } from './coach.js'
import {
  RULE_GROUPS,
  RULE_VERSION,
  RULE_DATE,
  LEVEL_MEANING,
  APPLIES_MEANING,
  ARCHITECTURES,
  CONFLICTS,
  LAYER_NAMES,
} from './catalog.js'

const REPLAY_EVENTS = 400
const REPLAY_WINDOW_MS = 24 * 60 * 60 * 1000
const REVIEW_REPLAY_EVENTS = 2000
const VISIBLE_WINDOW_MS = 30 * 60 * 1000
const PROJECT_FILE_LIMIT = 80
const FILE_TEXT_LIMIT = 80
const FILE_TEXT_MAX_BYTES = 300 * 1024
const JUDGE_PREFIX = '【代码安全防御评审判官】'

function messageOf(error) {
  return String(error && error.message ? error.message : error)
}

function textOf(value) {
  return typeof value === 'string' ? value : ''
}

/** 构造注入用的用户消息（不依赖 dsh-llm 包，字段与 createUserMessage 一致）。 */
export function makeUserMessage(text) {
  return {
    id: `security-judge-${randomUUID()}`,
    role: 'user',
    content: [{ type: 'text', text: String(text) }],
    source: { kind: 'user' },
  }
}

export function createCore({ ctx, config = {}, log = console, pluginVersion = '1.0.0' }) {
  const store = createStore({ dataDir: config.dataDir, log })
  const sessions = new Map()
  const views = new Map() // id -> { revision, view }
  const disposers = []
  let scanTimer = null
  let bootstrapped = false
  let disposed = false
  let lastScanAt = 0

  const getService = (name) => {
    try {
      return typeof ctx.get === 'function' ? ctx.get(name) : undefined
    } catch {
      return undefined
    }
  }

  function bump(state) {
    state.revision = (state.revision || 0) + 1
    views.delete(state.id)
  }

  function agentOf(id) {
    const agents = getService('agents')
    try {
      return agents && typeof agents.get === 'function' ? agents.get(id) : undefined
    } catch {
      return undefined
    }
  }

  function rootAgents() {
    const agents = getService('agents')
    try {
      return agents && typeof agents.list === 'function' ? agents.list() : []
    } catch {
      return []
    }
  }

  function titleOf(session) {
    const titleService = getService('sessionTitle')
    try {
      const snapshot = titleService && typeof titleService.get === 'function' ? titleService.get(session) : undefined
      if (snapshot && snapshot.title) return String(snapshot.title)
    } catch {
      // 标题服务不可用就用 id
    }
    return ''
  }

  function cwdOf(session) {
    const workingDirectory = getService('workingDirectory')
    try {
      const value = workingDirectory && typeof workingDirectory.get === 'function' ? workingDirectory.get(session) : undefined
      if (value) return String(value)
    } catch {
      // fallthrough
    }
    return session && session.header && session.header.cwd ? String(session.header.cwd) : ''
  }

  function ensureState(session, agent) {
    const id = session && session.id ? String(session.id) : (agent && agent.id ? String(agent.id) : '')
    if (!id) return null
    let state = sessions.get(id)
    if (!state) {
      const header = session && session.header ? session.header : {}
      state = createSessionState({
        id,
        title: titleOf(session),
        cwd: cwdOf(session),
        createdAt: typeof header.createdAt === 'number' ? header.createdAt : Date.now(),
        status: agent && agent.status ? agent.status : 'idle',
      })
      state.revision = 0
      sessions.set(id, state)
      replay(state, session)
      refreshProfile(state)
      scanProjectFiles(state).catch(() => {})
      refreshFileTexts(state, { force: true }).catch(() => {})
      if (distributionCandidate(state)) ensureDistribution(state).catch(() => {})
      // 暂停状态持久化：DSH 重启后仍然暂停，不会自己恢复强制重做。
      if (store.isSessionPaused(id)) state.review.enforcePaused = true
    } else {
      const title = titleOf(session)
      if (title && title !== state.title) {
        state.title = title
        bump(state)
      }
      const cwd = cwdOf(session)
      if (cwd && cwd !== state.cwd) {
        state.cwd = cwd
        bump(state)
      }
      if (agent && agent.status && agent.status !== state.status) {
        state.status = agent.status
        bump(state)
      }
    }
    state.live = Boolean(agent)
    if (store.isSessionPaused(id)) state.review.enforcePaused = true
    return state
  }

  /** 回放最近一段会话事件，用于插件晚于会话启动时补齐代码识别。 */
  function replay(state, session) {
    if (!session || typeof session.snapshotEvents !== 'function') return
    try {
      const seq = Number(typeof session.seq === 'number' ? session.seq : 0)
      const from = Math.max(0, seq - REPLAY_EVENTS)
      const events = session.snapshotEvents(from, seq)
      const cutoff = Date.now() - REPLAY_WINDOW_MS
      for (const event of events || []) {
        // 只回放最近 24 小时的工作：很久以前完成的旧会话不追溯评审。
        if (typeof event.time === 'number' && event.time < cutoff) continue
        // 回放时也认会话内的评审口令，重启后用户之前的要求不丢。
        if (event.type === 'user/message') {
          const text = extractUserText(event)
          const sourceKind = textOf(event.data && event.data.source && event.data.source.kind)
          if (sourceKind === 'user' && text && !isJudgeMessage(text) && detectReviewRequest(text)) {
            state.review.requestedAt = Math.max(state.review.requestedAt || 0, event.time || Date.now())
            state.review.requestedText = text.slice(0, 300)
          }
        }
        ingestSessionEvent(state, event)
      }
      state.review.state = state.code.doing ? 'pending' : 'none'
    } catch (error) {
      log.warn?.(`[security-judge] 回放会话事件失败（${state.id}）：${messageOf(error)}`)
    }
  }

  async function scanProjectFiles(state) {
    if (!state.cwd) return
    try {
      const entries = await fs.readdir(state.cwd, { withFileTypes: true })
      const names = entries
        .filter((entry) => entry.isFile() || entry.isDirectory())
        .map((entry) => entry.name)
        .slice(0, PROJECT_FILE_LIMIT)
      const merged = [...new Set([...names, ...state.projectFiles])].slice(0, PROJECT_FILE_LIMIT * 2)
      if (merged.length !== state.projectFiles.length) {
        state.projectFiles = merged
        bump(state)
      }
    } catch {
      // 目录不存在或不可读时不阻塞
    }
  }

  /** 从磁盘读当前代码内容，自动检查针对「现在的代码」而不是历史写入片段。 */
  async function refreshFileTexts(state, { force = false } = {}) {
    if (!state || !state.cwd || !state.code.doing) return
    const now = Date.now()
    if (!force && now - (state.fileTextsAt || 0) < 5000) return
    const files = state.code.files.filter((file) => file.code).slice(-FILE_TEXT_LIMIT)
    const next = {}
    for (const file of files) {
      const absolute = path.isAbsolute(file.path) ? file.path : path.join(state.cwd, file.path)
      try {
        const stat = await fs.stat(absolute)
        if (!stat.isFile() || stat.size > FILE_TEXT_MAX_BYTES) continue
        next[file.path] = await fs.readFile(absolute, 'utf8')
      } catch {
        // 文件被删/不可读就跳过
      }
    }
    state.fileTexts = next
    state.fileTextsAt = now
    bump(state)
  }

  /** 分发包自检：包清单、入口、资源、绝对路径、依赖可安装性（对应规则组 J）。 */
  const distributionChecked = new Map()
  async function ensureDistribution(state, { force = false } = {}) {
    if (!state || !state.code.doing) return state ? state.distribution || null : null
    const now = Date.now()
    const last = distributionChecked.get(state.id) || 0
    if (!force && state.distribution && now - last < 30000) return state.distribution
    try {
      const touched = state.code.files.map((file) => file.path)
      const dir = await locatePackageDir(state.cwd, touched)
      let result
      if (!dir) {
        result = {
          ok: false,
          findings: [{ file: '', why: '检测到要产出安装包，但没有找到 package.json：别人无法安装（J-01/J-04）' }],
          package: null,
          packageDir: '',
          checkedAt: now,
        }
      } else {
        result = await inspectPackage(dir)
      }
      state.distribution = result
      distributionChecked.set(state.id, now)
      bump(state)
      return result
    } catch (error) {
      log.warn?.(`[security-judge] 分发自检失败（${state.id}）：${messageOf(error)}`)
      return state.distribution || null
    }
  }

  /** 用户要求评审时回看更多历史事件（不按 24 小时窗口裁剪），把旧代码工作找回来。 */
  function replayForReview(state, session) {
    if (!session || typeof session.snapshotEvents !== 'function') return
    try {
      const seq = Number(typeof session.seq === 'number' ? session.seq : 0)
      const from = Math.max(0, seq - REVIEW_REPLAY_EVENTS)
      const events = session.snapshotEvents(from, seq)
      for (const event of events || []) {
        ingestSessionEvent(state, event)
      }
      refreshProfile(state)
    } catch (error) {
      log.warn?.(`[security-judge] 评审要求回放失败（${state.id}）：${messageOf(error)}`)
    }
  }

  function extractUserText(event) {
    const data = event && event.data
    const message = data && Array.isArray(data.content)
      ? data
      : (data && data.message && Array.isArray(data.message.content) ? data.message : null)
    if (!message) return ''
    return message.content
      .filter((block) => block && block.type === 'text' && typeof block.text === 'string')
      .map((block) => block.text)
      .join('\n')
      .trim()
  }

  function isJudgeMessage(text) {
    return textOf(text).startsWith(JUDGE_PREFIX)
  }

  /**
   * 受理「检查审核评审该会话」这类会话内请求：
   * 回看该会话的代码工作 → 标记评审要求 → 重新评估 →（已授权时）注入受理通知。
   */
  function handleReviewRequest(state, session, text, from = 'chat') {
    if (!state) return null
    state.review.requestedAt = Date.now()
    state.review.requestedText = String(text || '').slice(0, 300)
    replayForReview(state, session)
    refreshFileTexts(state, { force: true }).catch(() => {})
    const evaluation = evaluate(state, store.getSettings())
    if (state.code.doing && distributionCandidate(state)) ensureDistribution(state).catch(() => {})
    if (state.code.doing && evaluation.state !== 'passed') {
      state.review.state = 'pending'
      state.review.verdict = 'pending'
    }
    bump(state)
    store.recordHistory({
      kind: 'review-requested',
      sessionId: state.id,
      title: state.title,
      from,
      codeWork: state.code.doing,
      architectureCount: state.code.doing ? recommendArchitectures(state).count : 0,
    })
    const settings = store.getSettings()
    const authority = store.getAuthority()
    if (authority.granted && settings.mode !== 'advisory' && !state.review.enforcePaused) {
      const agent = agentOf(state.id)
      if (agent) {
        const notice = state.code.doing
          ? buildReminderText(state, settings, { phase: 'requested' })
          : `${JUDGE_PREFIX}已受理评审要求，但本会话暂未检测到代码工作；如果确实有代码（例如在其他目录/历史回合），请在评审面板手动重扫或确认会话工作目录。`
        try {
          const message = makeUserMessage(notice)
          if (agent.status === 'running' && typeof agent.inject === 'function') agent.inject(message)
          else if (typeof agent.followup === 'function') agent.followup(message)
        } catch (error) {
          log.warn?.(`[security-judge] 注入评审受理通知失败（${state.id}）：${messageOf(error)}`)
        }
      }
    }
    log.info?.(`[security-judge] 已受理会话 ${state.id} 的评审要求（来源：${from}，代码工作：${state.code.doing ? '有' : '无'}）`)
    return evaluation
  }

  // -------------------------------------------------------------------------
  // 事件采集
  // -------------------------------------------------------------------------

  function onSessionEvent(session, event) {
    if (disposed || !session || !event) return
    try {
      const state = ensureState(session, agentOf(session.id))
      if (!state) return
      const previousTurn = state.turns.current
      const result = ingestSessionEvent(state, event)
      refreshProfile(state)
      bump(state)
      if (event.type === 'turn/start') {
        state.turns.current = Number(event.data && event.data.turn) || state.turns.current
      }
      if (state.review.state === 'passed') {
        // 新代码已经让通过结论失效（engine 里处理），这里只同步状态
      }
      if (result.wroteCode) {
        state.review.state = state.review.state === 'passed' ? 'pending' : (state.review.state === 'failed' ? 'failed' : 'pending')
        maybeRemind(state)
        refreshFileTexts(state).catch(() => {})
        if (distributionCandidate(state)) ensureDistribution(state).catch(() => {})
      }
      // 会话内口令：用户说「检查审核评审该会话」→ 受理评审要求。
      if (event.type === 'user/message') {
        const text = extractUserText(event)
        const sourceKind = textOf(event.data && event.data.source && event.data.source.kind)
        if (sourceKind === 'user' && text && !isJudgeMessage(text) && detectReviewRequest(text)) {
          handleReviewRequest(state, session, text, 'chat')
        }
      }
      if (previousTurn !== state.turns.current) views.delete(state.id)
    } catch (error) {
      log.warn?.(`[security-judge] 处理会话事件失败：${messageOf(error)}`)
    }
  }

  /** 连续不合格后的教学单（用户要求：超过两次不合格就教该会话 AI 怎么做）。 */
  function coachTextFor(state, evaluation = null) {
    try {
      const result = evaluation || evaluate(state, store.getSettings())
      const plan = buildCoachPlan(state, result, recommendArchitectures(state))
      return renderCoachText(plan)
    } catch (error) {
      log.warn?.(`[security-judge] 生成教学单失败（${state.id}）：${messageOf(error)}`)
      return ''
    }
  }

  /** 首次写代码时向会话 AI 注入提醒（需要用户授权；每个回合最多一次）。 */
  function maybeRemind(state) {
    const settings = store.getSettings()
    const authority = store.getAuthority()
    if (!authority.granted || settings.mode === 'advisory') return
    if (state.review.state === 'passed') return
    if (state.review.enforcePaused) return
    if (state.reminder.lastTurn === state.turns.current) return
    const agent = agentOf(state.id)
    if (!agent) return
    try {
      const text = buildReminderText(state, settings, { phase: 'detected' })
      agent.inject(makeUserMessage(text))
      state.reminder.lastTurn = state.turns.current
      state.reminder.lastAt = Date.now()
      log.info?.(`[security-judge] 已向会话 ${state.id} 注入代码安全防御评审提醒`)
    } catch (error) {
      log.warn?.(`[security-judge] 注入评审提醒失败（${state.id}）：${messageOf(error)}`)
    }
  }

  /**
   * 回合收尾门禁：用户授权 + block 模式时，评审不合格就要求重做，直到合格为止。
   * 默认不设次数上限（maxEnforcePerSession=0）；用户可自行设保护阈值或暂停强制重做。
   */
  async function onTurnStopping(payload) {
    if (disposed) return
    const agent = payload && payload.agent
    if (!agent || !agent.id) return
    try {
      const state = ensureState(agent.session, agent)
      if (!state) return
      const reviewWanted = (state.review.requestedAt || 0) > 0
      if (!state.code.doing && !reviewWanted) return
      const settings = store.getSettings()
      const authority = store.getAuthority()
      if (!authority.granted) return
      if (settings.mode !== 'block' || !settings.blockWithoutPass) return
      const evaluation = evaluate(state, settings)
      if (evaluation.state === 'passed') {
        // 合格：清零重做计数，本次任务才算完成。
        if (state.review.enforced || state.review.redoCount || state.review.limitNoted || state.review.noSubmitEnforced) {
          state.review.enforced = 0
          state.review.redoCount = 0
          state.review.limitNoted = false
          state.review.noSubmitEnforced = 0
          bump(state)
        }
        return
      }
      if (state.review.enforcePaused) return
      if (evaluation.state === 'na') return
      // 安全阀：连续强制重做多次却从未提交过评审（AI 在原地打转）→ 自动暂停，等用户介入。
      state.review.noSubmitEnforced = (state.review.noSubmitEnforced || 0) + 1
      if (state.review.noSubmitEnforced >= 5) {
        state.review.enforcePaused = true
        state.review.noSubmitEnforced = 0
        store.setSessionPaused(state.id, true)
        bump(state)
        store.recordHistory({
          kind: 'enforce-auto-paused',
          sessionId: state.id,
          title: state.title,
          reason: '连续 5 次强制重做仍未提交评审（AI 未调用 security_judge submit），已自动暂停强制重做，等待用户介入；结论仍是不合格。',
        })
        try {
          const agentNote = agentOf(state.id)
          if (agentNote && typeof agentNote.inject === 'function') {
            agentNote.inject(makeUserMessage(`${JUDGE_PREFIX}已自动暂停强制重做：连续 5 次要求重做但本会话从未提交评审（security_judge submit）。结论仍是不合格；请先处理代码与证据，再由用户点「恢复强制重做」或直接提交评审。`))
          }
        } catch {
          // 通知失败不影响暂停状态
        }
        return
      }
      const limit = Math.max(0, Number(settings.maxEnforcePerSession) || 0)
      if (limit > 0 && state.review.enforced >= limit) {
        // 用户自设了保护阈值：到点停止自动催办，但结论仍是不合格，等用户处理。
        if (!state.review.limitNoted) {
          state.review.limitNoted = true
          bump(state)
          store.recordHistory({
            kind: 'redo-limit-reached',
            sessionId: state.id,
            title: state.title,
            reason: `达到用户设置的强制重做上限 ${limit} 次，仍未合格`,
            blockers: evaluation.blockers.slice(0, 10).map((item) => item.message),
          })
        }
        return
      }
      if (payload.signal && payload.signal.aborted) return
      let text = buildReminderText(state, settings, { phase: 'redo' })
      // 超过两次不合格 → 进入教学模式：把「怎么改 / 交什么证据」一起教给会话 AI。
      if (state.review.redoCount >= 2) {
        const coach = coachTextFor(state, evaluation)
        if (coach) text = `${text}\n\n${coach}`
      }
      const message = makeUserMessage(text)
      try {
        if (typeof agent.steer === 'function' && agent.status === 'running') {
          agent.steer(message)
        } else if (typeof agent.followup === 'function') {
          agent.followup(message)
        } else {
          return
        }
      } catch (error) {
        log.warn?.(`[security-judge] 回合收尾拦截失败（${state.id}）：${messageOf(error)}`)
        return
      }
      state.review.enforced += 1
      state.review.redoCount += 1
      state.review.lastAt = Date.now()
      state.review.state = 'failed'
      state.review.verdict = 'fail'
      bump(state)
      // 历史记录不刷屏：第一次、以及每 5 次重做记一条。
      if (state.review.redoCount === 1 || state.review.redoCount % 5 === 0) {
        store.recordHistory({
          kind: 'redo-required',
          sessionId: state.id,
          title: state.title,
          turn: payload.turn,
          redoCount: state.review.redoCount,
          blockers: evaluation.blockers.slice(0, 10).map((item) => item.message),
          architectureCount: recommendArchitectures(state).count,
        })
      }
      log.info?.(`[security-judge] 会话 ${state.id} 第 ${payload.turn} 回合评审不合格，要求重做（第 ${state.review.redoCount} 次）`)
    } catch (error) {
      log.warn?.(`[security-judge] turn-stopping 处理失败：${messageOf(error)}`)
    }
  }

  // -------------------------------------------------------------------------
  // 注册与启动
  // -------------------------------------------------------------------------

  function trackExisting() {
    for (const agent of rootAgents()) {
      try {
        ensureState(agent.session, agent)
      } catch (error) {
        log.warn?.(`[security-judge] 初始化会话失败（${agent.id}）：${messageOf(error)}`)
      }
    }
    lastScanAt = Date.now()
  }

  function start() {
    if (bootstrapped) return
    bootstrapped = true
    store.ensureReady().then(() => {
      if (disposed) return
      trackExisting()
    }).catch((error) => {
      log.warn?.(`[security-judge] 读取持久化状态失败：${messageOf(error)}`)
      trackExisting()
    })

    const on = (name, handler, options) => {
      try {
        const disposer = ctx.on(name, handler, options || { global: true })
        if (typeof disposer === 'function') disposers.push(disposer)
      } catch (error) {
        log.warn?.(`[security-judge] 注册事件 ${name} 失败：${messageOf(error)}`)
      }
    }

    on('agent/created', ({ agent }) => {
      if (!agent) return
      try {
        ensureState(agent.session, agent)
      } catch (error) {
        log.warn?.(`[security-judge] 注册新会话失败：${messageOf(error)}`)
      }
    })
    on('agent/disposed', ({ agent }) => {
      if (!agent) return
      const state = sessions.get(String(agent.id))
      if (state) {
        state.live = false
        state.status = 'idle'
        bump(state)
      }
    })
    on('agent/status', ({ agent, status }) => {
      if (!agent) return
      const state = sessions.get(String(agent.id))
      if (state) {
        state.status = status
        state.live = status === 'running'
        bump(state)
      }
    })
    on('session/event', (session, event) => onSessionEvent(session, event))
    on('agent/turn-stopping', (payload) => onTurnStopping(payload))

    // 定时重扫：标题 / cwd / 状态 / 项目文件
    const scheduleScan = () => {
      const settings = store.getSettings()
      const delay = Math.max(3000, Number(settings.autoScanMs) || 15000)
      scanTimer = setInterval(() => {
        if (disposed) return
        try {
          trackExisting()
          for (const state of sessions.values()) {
            if (state.cwd) scanProjectFiles(state).catch(() => {})
          }
        } catch (error) {
          log.warn?.(`[security-judge] 定时扫描失败：${messageOf(error)}`)
        }
      }, delay)
      if (typeof scanTimer.unref === 'function') scanTimer.unref()
    }
    scheduleScan()
  }

  async function dispose() {
    disposed = true
    if (scanTimer) {
      clearInterval(scanTimer)
      scanTimer = null
    }
    for (const disposer of disposers) {
      try {
        disposer()
      } catch {
        // ignore
      }
    }
    disposers.length = 0
    await store.flush()
  }

  // -------------------------------------------------------------------------
  // 视图
  // -------------------------------------------------------------------------

  function sessionView(state) {
    if (!state) return null
    const settings = store.getSettings()
    const cached = views.get(state.id)
    if (cached && cached.revision === state.revision) return cached.view
    let evaluation
    try {
      evaluation = evaluate(state, settings)
    } catch (error) {
      log.warn?.(`[security-judge] 评审计算失败（${state.id}）：${messageOf(error)}`)
      evaluation = { state: 'none', verdict: 'none', conflicts: [], blockers: [], failed: [], missing: [], rules: [], score: 0, scopeSize: 0, l1Size: 0, autoPass: 0, attested: 0, failedCount: 0 }
    }
    const view = buildSessionView(state, settings, evaluation)
    view.live = state.live !== false && state.status !== 'idle' ? Boolean(agentOf(state.id)) : Boolean(state.live)
    if (state.live === true && !agentOf(state.id)) view.live = false
    views.set(state.id, { revision: state.revision, view })
    return view
  }

  function allSessionViews() {
    const list = []
    const cutoff = Date.now() - VISIBLE_WINDOW_MS
    for (const state of sessions.values()) {
      const running = state.status === 'running'
      const recentCode = state.code.doing && state.lastActivityAt >= cutoff
      const recentlyReviewed = state.review.lastSubmitAt >= cutoff
      if (!running && !recentCode && !recentlyReviewed) continue
      const view = sessionView(state)
      if (view) list.push(view)
    }
    list.sort((left, right) => {
      const codeDelta = Number(right.code.doing) - Number(left.code.doing)
      if (codeDelta !== 0) return codeDelta
      return right.lastActivityAt - left.lastActivityAt
    })
    return list
  }

  function statsOf(list) {
    const stats = {
      liveSessions: list.filter((view) => view.status === 'running').length,
      codeSessions: list.filter((view) => view.code.doing).length,
      passed: list.filter((view) => view.code.doing && view.review.state === 'passed').length,
      pending: list.filter((view) => view.code.doing && view.review.state === 'pending').length,
      failed: list.filter((view) => view.code.doing && view.review.state === 'failed').length,
      unjudged: list.filter((view) => view.code.doing && view.review.state === 'none').length,
      conflicted: list.reduce((sum, view) => sum + view.conflicts.filter((item) => !item.acknowledged).length, 0),
      authority: store.getAuthority().granted,
    }
    return stats
  }

  function catalogView() {
    return {
      ruleVersion: RULE_VERSION,
      ruleDate: RULE_DATE,
      levels: LEVEL_MEANING,
      applies: APPLIES_MEANING,
      layers: LAYER_NAMES,
      ruleGroups: RULE_GROUPS.map((group) => ({
        id: group.id,
        name: group.name,
        rules: group.rules.map((rule) => ({
          id: rule.id,
          level: rule.level,
          applies: rule.applies,
          title: rule.title,
          criteria: rule.criteria,
          auto: Boolean(rule.auto),
          check: rule.auto === 'text'
            ? '自动扫描本会话写入/编辑过的代码文本'
            : rule.auto === 'file'
              ? '自动检查本会话改到的文件（锁文件 / SBOM / 混淆 / 签名等）'
              : '',
        })),
      })),
      architectures: ARCHITECTURES.map((arch) => ({
        id: arch.id,
        name: arch.name,
        layer: arch.layer,
        layerName: arch.layerName,
        family: arch.family,
        tier: arch.tier,
        mandatory: arch.tier === 'core',
        discouraged: Boolean(arch.discouraged),
        stacks: arch.stacks,
        when: arch.when,
        purpose: arch.purpose,
        rules: arch.rules || [],
        conflictsWith: arch.conflictsWith || [],
        doc: arch.doc,
      })),
      conflicts: CONFLICTS.map((conflict) => ({
        id: conflict.id,
        title: conflict.title,
        severity: conflict.severity,
        a: conflict.a,
        b: conflict.b,
        detail: conflict.detail,
        resolution: conflict.resolution,
        rules: conflict.rules || [],
      })),
    }
  }

  async function getPanelState(version = pluginVersion) {
    await store.ensureReady()
    trackExisting()
    const list = allSessionViews()
    const authority = store.getAuthority()
    const settings = store.getSettings()
    return {
      ok: true,
      version,
      generatedAt: Date.now(),
      authority: {
        granted: Boolean(authority.granted),
        grantedAt: authority.grantedAt || null,
        requestedAt: authority.requestedAt || null,
        note: authority.note || '',
        scope: AUTHORITY_SCOPE,
        charter: CHARTER,
        canGate: Boolean(authority.granted) && settings.mode === 'block' && settings.blockWithoutPass === true,
      },
      settings,
      stats: statsOf(list),
      sessions: list,
      history: (store.state.history || []).slice(-20).reverse(),
      catalog: catalogView(),
      plugin: {
        version: pluginVersion,
        ruleVersion: RULE_VERSION,
        ruleDate: RULE_DATE,
        lastScanAt,
      },
    }
  }

  function getSessionView(id) {
    const state = sessions.get(String(id))
    if (!state) {
      const agent = agentOf(String(id))
      if (!agent) return null
      try {
        return sessionView(ensureState(agent.session, agent))
      } catch {
        return null
      }
    }
    return sessionView(state)
  }

  // -------------------------------------------------------------------------
  // 操作
  // -------------------------------------------------------------------------

  function findAgent(id) {
    return agentOf(String(id))
  }

  async function dispatch(action, payload = {}) {
    await store.ensureReady()
    const input = payload && typeof payload === 'object' ? payload : {}
    try {
      switch (action) {
        case 'grant-authority': {
          if (input.confirm !== true) {
            return { ok: false, error: { code: 'confirm-required', message: '授予权限必须由用户明确确认（confirm:true）' }, httpStatus: 400 }
          }
          if (store.getAuthority().granted) {
            return { ok: true, authority: store.getAuthority() }
          }
          const authority = store.grantAuthority(input.note || '')
          store.recordHistory({ kind: 'authority-granted', note: authority.note })
          log.info?.('[security-judge] 用户已授予代码安全防御评审权限（只用于评审）')
          return { ok: true, authority }
        }
        case 'revoke-authority': {
          if (input.confirm !== true) {
            return { ok: false, error: { code: 'confirm-required', message: '撤销权限需要确认' }, httpStatus: 400 }
          }
          store.revokeAuthority()
          store.recordHistory({ kind: 'authority-revoked' })
          return { ok: true }
        }
        case 'request-authority': {
          const authority = store.requestAuthority()
          return { ok: true, authority, message: '已请求用户授权：请在「代码安全防御评审判官」面板点「授权」，插件不能自行授权。' }
        }
        case 'settings-save': {
          const settings = store.saveSettings(input.patch || {})
          store.recordHistory({ kind: 'settings-saved', settings })
          return { ok: true, settings }
        }
        case 'scan': {
          trackExisting()
          for (const state of sessions.values()) {
            if (state.cwd) await scanProjectFiles(state)
            await refreshFileTexts(state, { force: true })
            if (state.code.doing && distributionCandidate(state)) await ensureDistribution(state, { force: true })
            bump(state)
          }
          lastScanAt = Date.now()
          return { ok: true, scannedAt: lastScanAt }
        }
        case 'request-review':
        case 'review': {
          const state = sessions.get(String(input.sessionId || ''))
          if (!state) return { ok: false, error: { code: 'unknown-session', message: `找不到会话：${input.sessionId}` }, httpStatus: 404 }
          const agent = findAgent(state.id)
          handleReviewRequest(state, agent ? agent.session : null, textOf(input.text) || '面板请求评审', 'panel')
          return { ok: true, session: sessionView(state) }
        }
        case 'session-detail': {
          const state = sessions.get(String(input.sessionId || ''))
          if (!state) return { ok: false, error: { code: 'unknown-session', message: `找不到会话：${input.sessionId}` }, httpStatus: 404 }
          return { ok: true, session: sessionView(state) }
        }
        case 'remind': {
          if (!store.getAuthority().granted) {
            return { ok: false, error: { code: 'authority-required', message: '向会话注入提醒属于评审权限，需要用户先在面板授权' }, httpStatus: 403 }
          }
          const state = sessions.get(String(input.sessionId || ''))
          if (!state) return { ok: false, error: { code: 'unknown-session', message: `找不到会话：${input.sessionId}` }, httpStatus: 404 }
          if (!state.code.doing) return { ok: false, error: { code: 'not-code-session', message: '这个会话没有在写代码，不进行评审提醒' }, httpStatus: 400 }
          const agent = findAgent(state.id)
          if (!agent) return { ok: false, error: { code: 'unknown-session', message: '会话当前不在运行，无法注入提醒' }, httpStatus: 400 }
          const text = String(input.text || '').trim() || buildReminderText(state, store.getSettings(), { phase: 'redo' })
          const message = makeUserMessage(text)
          try {
            if (agent.status === 'running' && typeof agent.steer === 'function') agent.steer(message)
            else if (typeof agent.followup === 'function') agent.followup(message)
            else return { ok: false, error: { code: 'internal-error', message: '当前会话不支持注入提醒' }, httpStatus: 500 }
          } catch (error) {
            return { ok: false, error: { code: 'internal-error', message: messageOf(error) }, httpStatus: 500 }
          }
          state.reminder.lastTurn = state.turns.current
          state.reminder.lastAt = Date.now()
          return { ok: true }
        }
        case 'pause-enforce': {
          const state = sessions.get(String(input.sessionId || ''))
          if (!state) return { ok: false, error: { code: 'unknown-session', message: `找不到会话：${input.sessionId}` }, httpStatus: 404 }
          state.review.enforcePaused = input.paused === true
          store.setSessionPaused(state.id, state.review.enforcePaused)
          if (!state.review.enforcePaused) state.review.noSubmitEnforced = 0
          bump(state)
          store.recordHistory({
            kind: state.review.enforcePaused ? 'enforce-paused' : 'enforce-resumed',
            sessionId: state.id,
            title: state.title,
          })
          return { ok: true, session: sessionView(state) }
        }
        case 'ack-conflict': {
          const state = sessions.get(String(input.sessionId || ''))
          if (!state) return { ok: false, error: { code: 'unknown-session', message: `找不到会话：${input.sessionId}` }, httpStatus: 404 }
          const result = ackConflict(state, String(input.conflictId || ''), input.resolution)
          if (!result.ok) return { ...result, httpStatus: 400 }
          bump(state)
          return { ok: true, session: sessionView(state) }
        }
        case 'waive': {
          const state = sessions.get(String(input.sessionId || ''))
          if (!state) return { ok: false, error: { code: 'unknown-session', message: `找不到会话：${input.sessionId}` }, httpStatus: 404 }
          const result = waiveRule(state, String(input.rule || ''), input.reason, input.actorNote)
          if (!result.ok) return { ...result, httpStatus: 400 }
          bump(state)
          return { ok: true, session: sessionView(state) }
        }
        case 'submit': {
          const state = sessions.get(String(input.sessionId || ''))
          if (!state) return { ok: false, error: { code: 'unknown-session', message: `找不到会话：${input.sessionId}` }, httpStatus: 404 }
          const result = submitReview(state, input.payload || {}, store.getSettings())
          if (!result.ok) return { ...result, httpStatus: 400 }
          bump(state)
          store.recordHistory({
            kind: result.evaluation.verdict === 'pass' ? 'review-passed' : 'review-failed',
            sessionId: state.id,
            title: state.title,
            verdict: result.evaluation.verdict,
            blockers: result.evaluation.blockers.slice(0, 10).map((item) => item.message),
            architectureCount: recommendArchitectures(state).count,
          })
          return { ok: true, verdict: result.evaluation.verdict, blockers: result.evaluation.blockers, evaluation: summarizeEvaluation(result.evaluation) }
        }
        default:
          return { ok: false, error: { code: 'unknown-action', message: `未知操作：${action}` }, httpStatus: 400 }
      }
    } catch (error) {
      log.warn?.(`[security-judge] 操作 ${action} 失败：${messageOf(error)}`)
      return { ok: false, error: { code: 'internal-error', message: messageOf(error) }, httpStatus: 500 }
    }
  }

  function summarizeEvaluation(evaluation) {
    return {
      state: evaluation.state,
      verdict: evaluation.verdict,
      score: evaluation.score,
      scopeSize: evaluation.scopeSize,
      failed: evaluation.failed,
      missing: evaluation.missing,
      blockers: evaluation.blockers,
      conflicts: evaluation.conflicts,
    }
  }

  // -------------------------------------------------------------------------
  // Agent 工具侧
  // -------------------------------------------------------------------------

  async function toolContext(agentId) {
    await store.ensureReady()
    if (!agentId) {
      return { ok: false, error: { code: 'no-session', message: '评审判官需要知道当前会话：请从会话内调用本工具' } }
    }
    let state = sessions.get(String(agentId))
    if (!state) {
      const agent = findAgent(agentId)
      if (!agent) return { ok: false, error: { code: 'unknown-session', message: '当前会话不在运行' } }
      state = ensureState(agent.session, agent)
    }
    if (!state) return { ok: false, error: { code: 'unknown-session', message: '无法初始化当前会话' } }
    return { ok: true, state }
  }

  function reviewSummary(view) {
    return {
      sessionId: view.id,
      title: view.title,
      codeWork: view.code.doing,
      projectKind: view.code.projectKind,
      stacks: view.code.stacks,
      neededArchitectures: view.architectureCount,
      architectures: view.architectures.map((arch) => ({ id: arch.id, name: arch.name, layerName: arch.layerName, mandatory: arch.mandatory, why: arch.why })),
      conflicts: view.conflicts,
      reviewState: view.review.state,
      verdict: view.review.verdict,
      unqualified: view.review.unqualified === true,
      redoCount: view.review.redoCount || 0,
      enforcePaused: view.review.enforcePaused === true,
      requestedAt: view.review.requestedAt || 0,
      coaching: (view.review.redoCount || 0) >= 2 || (view.review.attempts || 0) >= 2,
      progress: view.progress,
      failedRules: view.review.failedRules,
      missingRules: view.review.missingRules,
      autoViolations: view.review.autoViolations,
      distribution: view.distribution
        ? {
          ok: view.distribution.ok,
          checkedAt: view.distribution.checkedAt,
          packageName: view.distribution.packageName,
          packageVersion: view.distribution.packageVersion,
          findings: view.distribution.findings.slice(0, 10),
        }
        : null,
      authority: {
        granted: store.getAuthority().granted,
        charter: CHARTER,
      },
      nextSteps: view.code.doing
        ? [
          '调用 security_judge action=checklist 查看本会话适用规则与自动检查命中项。',
          '按规则修复代码、补齐架构（当前推荐架构见 architectures）。',
          '对自动检查覆盖不到的规则，在 action=submit 的 rules 里逐条提交证据。',
          '架构冲突需要在提交前登记处理结论（action=conflict-ack）。',
          '只有 action=submit 返回 verdict=pass（合格）才算完成；不合格必须重做，直到合格为止。',
          '已多次不合格时调用 action=coach 获取逐条教学单（改哪个文件、怎么改、交什么证据、提交格式）。',
        ]
        : ['本会话没有检测到写代码，按设计不做代码安全防御评审。'],
    }
  }

  async function toolStatus(agentId, { detail = false } = {}) {
    const context = await toolContext(agentId)
    if (!context.ok) return context
    const { state } = context
    await refreshFileTexts(state)
    await ensureDistribution(state)
    const view = getSessionView(state.id) || buildSessionView(state, store.getSettings())
    const summary = reviewSummary(view)
    if (!detail) return { ok: true, ...summary }
    return {
      ok: true,
      ...summary,
      rules: view.rules,
      rulesInScope: view.rules.filter((rule) => rule.status !== 'auto-clear').length,
    }
  }

  async function toolArchitectures(agentId) {
    const context = await toolContext(agentId)
    if (!context.ok) return context
    const { state } = context
    await refreshFileTexts(state)
    const recommendation = recommendArchitectures(state)
    const conflicts = detectConflicts(state, recommendation)
    return {
      ok: true,
      sessionId: state.id,
      codeWork: state.code.doing,
      projectKind: state.code.projectKind,
      stacks: state.code.stacks,
      architectureCount: recommendation.count,
      families: recommendation.families,
      conclusion: recommendation.count <= 1
        ? `这个程序需要 ${recommendation.count} 种核心代码安全防御架构。`
        : `这个程序需要 ${recommendation.count} 种核心代码安全防御架构（分属 ${recommendation.families.length} 个层面）。`,
      architectures: recommendation.architectures,
      conflicts,
    }
  }

  async function toolSubmit(agentId, payload) {
    const context = await toolContext(agentId)
    if (!context.ok) return context
    const { state } = context
    if (!state.code.doing) {
      return { ok: false, error: { code: 'not-code-session', message: '本会话没有检测到写代码，按设计不做代码安全防御评审' } }
    }
    await refreshFileTexts(state, { force: true })
    await ensureDistribution(state, { force: true })
    const result = submitReview(state, payload || {}, store.getSettings())
    if (!result.ok) return result
    bump(state)
    const evaluation = result.evaluation
    store.recordHistory({
      kind: evaluation.verdict === 'pass' ? 'review-passed' : 'review-failed',
      sessionId: state.id,
      title: state.title,
      verdict: evaluation.verdict,
      blockers: evaluation.blockers.slice(0, 10).map((item) => item.message),
      architectureCount: recommendArchitectures(state).count,
    })
    const view = getSessionView(state.id)
    const coaching = (state.review.redoCount || 0) >= 2 || (state.review.attempts || 0) >= 2
    const coach = evaluation.verdict === 'pass' ? '' : (coaching ? coachTextFor(state, evaluation) : '')
    return {
      ok: true,
      verdict: evaluation.verdict,
      reviewState: evaluation.state,
      unqualified: evaluation.state !== 'passed',
      score: evaluation.score,
      blockers: evaluation.blockers,
      failed: evaluation.failed,
      missing: evaluation.missing,
      conflicts: evaluation.conflicts,
      summary: reviewSummary(view || buildSessionView(state, store.getSettings(), evaluation)),
      coaching,
      coach,
      reminder: evaluation.verdict === 'pass'
        ? ''
        : `评审未通过 = 不合格，必须重做直到合格。\n${buildReminderText(state, store.getSettings(), { phase: 'redo' })}${coach ? `\n\n${coach}` : ''}`,
    }
  }

  /** 教学模式：把当前不合格项翻译成可执行步骤，供会话 AI 按单整改。 */
  async function toolCoach(agentId) {
    const context = await toolContext(agentId)
    if (!context.ok) return context
    const { state } = context
    await refreshFileTexts(state)
    await ensureDistribution(state)
    const evaluation = evaluate(state, store.getSettings())
    const plan = buildCoachPlan(state, evaluation, recommendArchitectures(state))
    const text = renderCoachText(plan)
    return {
      ok: true,
      sessionId: state.id,
      redoCount: state.review.redoCount || 0,
      attempts: state.review.attempts,
      reviewState: evaluation.state,
      plan,
      text,
    }
  }

  async function toolAuthority(agentId, action = 'status') {    await store.ensureReady()
    if (action === 'request') {
      const authority = store.requestAuthority()
      return {
        ok: true,
        granted: false,
        requestedAt: authority.requestedAt,
        message: '已向用户发出授权请求。插件不能自行授权：请用户打开「代码安全防御评审判官」面板，确认权限边界后点「授权」。',
      }
    }
    const authority = store.getAuthority()
    return {
      ok: true,
      granted: Boolean(authority.granted),
      grantedAt: authority.grantedAt,
      requestedAt: authority.requestedAt,
      scope: AUTHORITY_SCOPE,
      charter: CHARTER,
      message: authority.granted
        ? '用户已授权：插件可在代码会话未通过评审时拦截完成。'
        : '尚未获得用户授权：插件只读观察，不向会话注入提醒、不拦截回合。请让用户到面板授权。',
    }
  }

  /** 给 systemPrompt.context 用：每个代码会话的实时评审状态（短文本）。 */
  function promptContextFor(agent) {
    if (!agent || !agent.id) return ''
    const state = sessions.get(String(agent.id))
    if (!state) return ''
    const requested = (state.review.requestedAt || 0) > 0
    if (!state.code.doing && !requested) return ''
    try {
      if (!state.code.doing && requested) {
        return [
          '【代码安全防御评审判官·实时状态】',
          '用户已要求评审本会话（口令：检查审核评审该会话），但暂未检测到代码工作。',
          '如果本会话确实做过代码（例如在其他目录、历史回合或被清理过），请让用户在面板点「重扫全部会话 / 评审该会话」确认工作目录；没有代码则如实说明本会话不涉及代码安全防御评审。',
        ].join('\n')
      }
      const view = getSessionView(state.id)
      if (!view) return ''
      const archs = view.architectures.filter((arch) => arch.mandatory).map((arch) => arch.name).join('、')
      const blockers = view.review.failedRules.concat(view.review.missingRules).slice(0, 4).map((item) => item.id).join('、')
      const pending = view.review.state !== 'passed'
      const paused = view.review.enforcePaused === true
      const coaching = (view.review.redoCount || 0) >= 2 || (view.review.attempts || 0) >= 2
      const lines = [
        '【代码安全防御评审判官·实时状态】',
        requested ? '用户已在会话里要求评审本会话（检查审核评审该会话），评审判官已受理。' : '',
        paused ? '用户已暂停强制重做：不会再有自动催办或门禁拦截。停在当前进度，等用户恢复或直接提交评审；不要自行宣布合格，也不要继续自动重做。' : '',
        !paused && coaching ? '已连续多次不合格：教学模式已开启，调用 security_judge action=coach 获取「改哪里、怎么改、交什么证据」的逐条教学单。' : '',
        `本会话正在写代码（${view.code.projectKind}）。这个程序需要 ${view.architectureCount} 种核心代码安全防御架构：${archs || '待识别'}。`,
        pending
          ? (paused
              ? `当前评审：不合格（用户已暂停强制重做；待处理：${blockers || '规则证据未提交'}）。不要继续自动重做，等用户恢复或提交评审。`
              : `当前评审：不合格（${view.review.state === 'pending' ? '待评审' : '未通过'}；待处理：${blockers || '规则证据未提交'}）。不合格必须重做，直到调用 security_judge 提交评审并拿到合格（verdict=pass）为止。`)
          : '当前评审：合格；若继续改代码，评审会自动失效并需要重新提交。',
        paused ? '' : '规则是强制性的，不可用「先做完再说」绕过；架构冲突需登记处理结论。',
      ].filter(Boolean)
      if (view.distribution && view.distribution.ok === false) {
        lines.push(`分发自检未通过（J 组）：${view.distribution.findings.slice(0, 6).map((item) => `${item.file || '包'}：${item.why}`).join('；')}。修好安装包后再提交评审。`)
      }
      const text = lines.join('\n')
      return text.length > 900 ? `${text.slice(0, 900)}…` : text
    } catch {
      return ''
    }
  }

  return {
    store,
    sessions,
    start,
    dispose,
    ensureReady: () => store.ensureReady(),
    getPanelState,
    getSessionView,
    dispatch,
    toolStatus,
    toolArchitectures,
    toolSubmit,
    toolCoach,
    toolAuthority,
    promptContextFor,
    getAuthority: () => store.getAuthority(),
    getSettings: () => store.getSettings(),
    isAllowedOrigin(origin) {
      try {
        const web = getService('webServer')
        const own = web && typeof web.getOrigin === 'function' ? web.getOrigin() : ''
        if (!own) return false
        return new URL(origin).origin === new URL(own).origin
      } catch {
        return false
      }
    },
    version: pluginVersion,
    CHARTER,
    AUTHORITY_SCOPE,
  }
}

export default { createCore, makeUserMessage }
