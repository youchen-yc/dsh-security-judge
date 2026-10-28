/**
 * 代码安全防御评审判官 · 判定引擎。
 *
 * 纯逻辑：不碰文件系统、不碰 Cordis 服务；输入是会话累积状态（scanner 生成），
 * 输出是推荐架构、冲突、规则符合性与评审结论。
 *
 * 关卡语义（与规则 §「豁免与例外」一致）：
 *   L1 不可豁免，必须自动通过或带证据通过；
 *   L2 默认必须通过，可豁免（须理由+补偿控制，180 天内有效）；
 *   L3 只登记，不阻断。
 */

import {
  RULES,
  RULE_BY_ID,
  ARCHITECTURES,
  ARCH_BY_ID,
  CONFLICTS,
  CODE_WORK_THRESHOLD,
  CODE_EXTENSIONS,
  STACK_FILE_PATTERNS,
  CODE_COMMAND_PATTERNS,
  AUTO_CHECKS,
  ANTI_PATTERN_DETECTORS,
  LEVEL_BY_RULE,
  CODE_COMMAND_PATTERNS as COMMAND_PATTERNS,
} from './catalog.js'

const MAX_SNIPPETS = 60
const MAX_SNIPPET_CHARS = 4000
const MAX_CMD_CHARS = 2000
const WAIVE_DAYS = 180
/** 测试/夹具文件：自动检查跳过（测试数据里出现弱哈希样本不算生产代码违规）。 */
const TEST_FILE_RE = /(^|[\\/])(test|tests|spec|specs|__tests__|fixtures?|e2e)([\\/]|$)|\.(test|spec)\.[a-z]+$/i
/** 分发包候选：出现这些清单/构建文件就说明「要产出安装包」，J 组规则进入范围。 */
const DIST_FILE_RE = /(^|[\\/])(package\.json|pyproject\.toml|Cargo\.toml|pom\.xml|build\.gradle(\.kts)?|[^\\/]+\.csproj|cordis\.patch\.yml)$/i

/** 该会话是否要产出可分发安装包（决定 J 组规则是否进入评审范围）。 */
export function distributionCandidate(state) {
  if (!state) return false
  const files = [
    ...(Array.isArray(state.projectFiles) ? state.projectFiles : []),
    ...(Array.isArray(state.code && state.code.files) ? state.code.files.map((file) => file.path || '') : []),
  ]
  return files.some((file) => DIST_FILE_RE.test(String(file || '')))
}

/**
 * 识别会话内的「评审口令」。
 * 例：「检查审核评审该会话」「帮我评审这个会话的代码」「代码安全防御评审」
 *     「review this session」「audit the code of this session」。
 * 否定说法（不要评审 / 不用检查）不触发；泛泛讨论架构方案也不触发。
 */
export function detectReviewRequest(text) {
  const raw = textOf(text).trim()
  if (!raw) return false
  const action = '(检查|审核|评审|审查|核查|复查|代码评审|安全评审|audit|review)'
  const target = '(该会话|这个会话|本会话|当前会话|会话|代码安全|代码|插件|软件|程序|session|code|plugin)'
  if (!new RegExp(action, 'i').test(raw)) return false
  if (!new RegExp(target, 'i').test(raw)) return false
  if (/(不要|不用|无需|不必|别|停止|取消)[^。\n]{0,12}(检查|审核|评审|审查|核查|复查|audit|review)/i.test(raw)) return false
  return new RegExp(`${action}[^。\\n]{0,24}${target}`, 'i').test(raw)
    || new RegExp(`${target}[^。\\n]{0,24}${action}`, 'i').test(raw)
}

const now = () => Date.now()

function textOf(value) {
  return typeof value === 'string' ? value : ''
}

function pushCapped(list, item, cap) {
  list.push(item)
  if (list.length > cap) list.splice(0, list.length - cap)
}

export function createSessionState({ id, title = '', cwd = '', createdAt = now(), status = 'idle' }) {
  return {
    id,
    title,
    cwd,
    createdAt,
    lastActivityAt: createdAt,
    status,    code: {
      score: 0,
      doing: false,
      projectKind: 'unknown',
      stacks: [],
      files: [], // [{ path, count, firstAt, lastAt, code }]
      signals: [], // [{ kind, detail, at }]
      writeCount: 0,
      codeOpCount: 0,
    },
    snippets: [], // [{ tool, file, text, at }]
    commands: [], // [{ text, at }]
    projectFiles: [], // cwd 顶层文件名（Host 侧扫描）
    turns: { current: 0, total: 0, codeTurns: [], lastTurnCode: false },
    activity: { lastTool: '', lastFile: '', codeTurns: 0 },
    review: {
      state: 'none',
      verdict: 'none',
      attempts: 0,
      enforced: 0,
      redoCount: 0,
      enforcePaused: false,
      noSubmitEnforced: 0,
      limitNoted: false,
      requestedAt: 0,
      requestedText: '',
      lastAt: 0,
      lastSubmitAt: 0,
      submittedWriteCount: 0,
      attested: {},
      waived: {},
      ack: {},
      selectedArchitectures: [],
      notes: '',
      lastResult: null,
    },
    reminder: { lastTurn: -1, lastAt: 0 },
    anti: [], // [{ arch, why, file, at }]
  }
}

// ---------------------------------------------------------------------------
// 事件采集
// ---------------------------------------------------------------------------

function pick(obj, keys) {
  for (const key of keys) {
    if (obj && obj[key] !== undefined && obj[key] !== null) return obj[key]
  }
  return undefined
}

function basename(file) {
  const text = textOf(file)
  const parts = text.split(/[\\/]/)
  return parts[parts.length - 1] || text
}

function extOf(file) {
  const name = basename(file)
  const index = name.lastIndexOf('.')
  return index >= 0 ? name.slice(index).toLowerCase() : ''
}

/** 从一次工具调用里抽出「工具名 + 参数」。兼容 tool/call 的 JSON 字符串 arguments。 */
export function normalizeToolCall(event) {
  if (!event || typeof event !== 'object') return null
  const type = textOf(event.type)
  const data = event.data && typeof event.data === 'object' ? event.data : event
  if (type !== 'tool/call' && !/^tool\/call/i.test(type) && !/^tool_call/i.test(type)) return null
  const tool = textOf(pick(data, ['name', 'toolName', 'tool']))
  if (!tool) return null
  let input = {}
  const raw = pick(data, ['arguments', 'input', 'args', 'parameters'])
  if (typeof raw === 'string') {
    try {
      input = JSON.parse(raw)
    } catch {
      input = {}
    }
  } else if (raw && typeof raw === 'object') {
    input = raw
  }
  const callId = textOf(pick(data, ['callId', 'id', 'toolCallId']))
  return { tool, input: input && typeof input === 'object' ? input : {}, callId }
}

/** 只有真正的写文件工具才算代码写入（present/read/grep 等带 path 的工具不算）。 */
const WRITE_TOOL_NAMES = new Set(['write', 'edit', 'multi_edit', 'apply_patch', 'str_replace_editor', 'notebook_edit', 'create_file', 'write_file'])

function collectFileWrites(tool, input) {
  if (!WRITE_TOOL_NAMES.has(String(tool || '').toLowerCase())) return []
  const writes = []
  const file = textOf(pick(input, ['file_path', 'filePath', 'path', 'target', 'file']))
  const content = pick(input, ['content', 'text', 'newText', 'new_text', 'new_string', 'newString'])
  if (file && typeof content === 'string') {
    writes.push({ file, text: content })
  }
  // edit / str_replace_editor：只取新文本作为代码证据
  const replacement = pick(input, ['new_string', 'newString', 'new_str', 'replacement', 'newText'])
  if (file && typeof replacement === 'string' && !writes.length) {
    writes.push({ file, text: replacement })
  }
  const edits = input && Array.isArray(input.edits) ? input.edits : null
  if (edits) {
    for (const edit of edits) {
      if (!edit || typeof edit !== 'object') continue
      const editFile = textOf(pick(edit, ['file_path', 'filePath', 'path', 'file'])) || file
      const editText = pick(edit, ['newText', 'new_string', 'newString', 'new_str', 'content', 'text'])
      if (editFile) writes.push({ file: editFile, text: typeof editText === 'string' ? editText : '' })
    }
  }
  // 某些写入工具用 files: [{ path, content }]
  if (Array.isArray(input && input.files)) {
    for (const item of input.files) {
      if (!item || typeof item !== 'object') continue
      const itemFile = textOf(pick(item, ['path', 'file_path', 'filePath', 'file']))
      const itemText = pick(item, ['content', 'text'])
      if (itemFile) writes.push({ file: itemFile, text: typeof itemText === 'string' ? itemText : '' })
    }
  }
  return writes.filter((write) => write.file)
}

function commandOf(tool, input) {
  if (!input || typeof input !== 'object') return ''
  if (tool === 'bash' || tool === 'pwsh' || tool === 'shell' || tool === 'run_code' || tool === 'powershell') {
    return textOf(pick(input, ['command', 'script', 'code', 'cmd']))
  }
  if (tool === 'terminal_send') return textOf(pick(input, ['text', 'input']))
  return ''
}

function stackLabelForFile(file) {
  const stacks = []
  for (const pattern of STACK_FILE_PATTERNS) {
    if (pattern.re.test(file)) stacks.push(pattern.stack)
  }
  return stacks
}

function addStack(state, stack) {
  if (!stack) return
  if (stack === 'android-or-jvm') {
    // 由 projectKind 决定；先记为 jvm，后面若有 Android 特征再纠正。
    if (!state.code.stacks.includes('android')) {
      if (!state.code.stacks.includes('jvm')) state.code.stacks.push('jvm')
    }
    return
  }
  if (!state.code.stacks.includes(stack)) state.code.stacks.push(stack)
}

function addFile(state, path, isCode, at) {
  const list = state.code.files
  const found = list.find((item) => item.path === path)
  if (found) {
    found.count += 1
    found.lastAt = at
    found.code = found.code || isCode
  } else {
    list.push({ path, count: 1, firstAt: at, lastAt: at, code: isCode })
    if (list.length > 200) list.splice(0, list.length - 200)
  }
}

function addSignal(state, kind, detail, at) {
  const signals = state.code.signals
  if (signals.some((item) => item.kind === kind && item.detail === detail)) return
  signals.push({ kind, detail, at })
  if (signals.length > 40) signals.splice(0, signals.length - 40)
}

/** 吃一条 Session 事件；返回是否发生「写代码」动作。 */
export function ingestSessionEvent(state, event) {
  if (!state || !event) return { wroteCode: false }
  const at = typeof event.time === 'number' ? event.time : (typeof event.at === 'number' ? event.at : now())
  const type = textOf(event.type)
  state.lastActivityAt = at

  if (type === 'turn/start') {
    const turn = Number(event.data && event.data.turn)
    if (Number.isFinite(turn)) {
      state.turns.current = turn
      state.turns.total = Math.max(state.turns.total, turn)
      state.turns.lastTurnCode = false
    }
    return { wroteCode: false }
  }
  if (type === 'turn/end') {
    state.turns.lastTurnCode = false
    return { wroteCode: false }
  }

  const call = normalizeToolCall(event)
  if (!call) {
    if (type === 'session/message' || type === 'assistant/message') state.lastActivityAt = at
    return { wroteCode: false }
  }

  const { tool, input } = call
  state.activity.lastTool = tool
  if (event.data && typeof event.data.turn === 'number') {
    state.turns.current = event.data.turn
    state.turns.total = Math.max(state.turns.total, event.data.turn)
  }

  // 命令类：构建/测试/部署算代码工作。
  const command = commandOf(tool, input)
  if (command) {
    state.commands.push({ text: command.slice(0, MAX_CMD_CHARS), at })
    if (state.commands.length > 40) state.commands.splice(0, state.commands.length - 40)
    let commandScore = 0
    for (const pattern of COMMAND_PATTERNS) {
      if (pattern.re.test(command)) commandScore = Math.max(commandScore, 5)
    }
    if (commandScore > 0) {
      addScore(state, commandScore)
      addSignal(state, 'command', command.slice(0, 160), at)
    }
  }

  // 写文件类：写入/编辑代码文件。
  const writes = collectFileWrites(tool, input)
  if (!writes.length) return { wroteCode: false }

  let wroteCode = false
  for (const write of writes) {
    const file = write.file
    const ext = extOf(file)
    const isCode = CODE_EXTENSIONS.has(ext)
    const isConfig = ['.json', '.yaml', '.yml', '.toml', '.ini', '.conf', '.properties', '.xml'].includes(ext)
    const isProjectFile = /(AndroidManifest\.xml|build\.gradle|package\.json|pom\.xml|Cargo\.toml|go\.mod|requirements\.txt|pyproject\.toml|Dockerfile|docker-compose)/i.test(basename(file))
    const score = isCode ? (isProjectFile ? 14 : 12) : isConfig ? 4 : 0
    if (score > 0) {
      addScore(state, score)
      wroteCode = wroteCode || isCode || isProjectFile
    }
    addFile(state, file, isCode, at)
    state.activity.lastFile = file
    for (const stack of stackLabelForFile(file)) addStack(state, stack)
    if (write.text && (isCode || isConfig || isProjectFile)) {
      pushCapped(state.snippets, {
        tool,
        file,
        text: write.text.slice(0, MAX_SNIPPET_CHARS),
        at,
      }, MAX_SNIPPETS)
    }
    if (isCode || isProjectFile) {
      addSignal(state, 'file', file, at)
    }
  }

  if (wroteCode) {
    state.code.writeCount += 1
    state.code.codeOpCount += 1
    state.turns.lastTurnCode = true
    if (!state.turns.codeTurns.includes(state.turns.current)) {
      state.turns.codeTurns.push(state.turns.current)
      if (state.turns.codeTurns.length > 100) state.turns.codeTurns.shift()
      state.activity.codeTurns = state.turns.codeTurns.length
    }
    const lastTurn = state.turns.current
    if (lastTurn >= 0) addSignal(state, 'turn', `第 ${lastTurn} 回合写代码`, at)
    // 新代码让上一次评审结论失效。
    if (state.review.state === 'passed') {
      state.review.state = 'pending'
      state.review.verdict = 'pending'
    }
  }

  detectAntiPatterns(state)
  return { wroteCode }
}

function addScore(state, score) {
  state.code.score = Math.min(100, state.code.score + score)
  state.code.doing = state.code.score >= CODE_WORK_THRESHOLD || state.code.codeOpCount >= 2
}

/** 重新计算技术栈 / 项目类型。 */
export function refreshProfile(state) {
  const stacks = state.code.stacks
  const hasAndroid = stacks.includes('android')
  if (hasAndroid) {
    state.code.stacks = stacks.filter((stack) => stack !== 'jvm' && stack !== 'android-or-jvm')
  }
  if (state.code.files.some((file) => /AndroidManifest\.xml$/i.test(file.path)) && !state.code.stacks.includes('android')) {
    state.code.stacks.push('android')
  }
  const has = (name) => state.code.stacks.includes(name)
  const server = has('server') || has('node') || has('python') || has('go') || has('rust') || has('jvm')
  const client = has('android') || has('desktop') || has('web') || has('iot')
  let kind = 'unknown'
  if (has('iot')) kind = 'iot'
  else if (has('android')) kind = 'android'
  else if (has('desktop')) kind = 'desktop'
  else if (has('web') && !server) kind = 'web'
  else if (server && client) kind = 'mixed'
  else if (server) kind = 'server'
  else if (has('web')) kind = 'web'
  state.code.projectKind = kind
  state.code.doing = state.code.doing || state.code.score >= CODE_WORK_THRESHOLD
  return state
}

export function isClientKind(state) {
  const kind = state.code.projectKind
  return kind === 'android' || kind === 'desktop' || kind === 'web' || kind === 'mixed'
}

export function isServerKind(state) {
  const kind = state.code.projectKind
  return kind === 'server' || kind === 'mixed'
}

function hasLlmSignal(state) {
  const text = state.snippets.map((snippet) => snippet.text).join('\n') + '\n' + state.commands.map((cmd) => cmd.text).join('\n')
  return /(openai|anthropic|deepseek[-_ ]?(api|sdk)|langchain|llamaindex|llama\.cpp|transformers|vllm|ollama|chat\/completions|embeddings?|dsh-agent|mcp server)/i.test(text)
}

function triggerHit(state, keywords) {
  if (!Array.isArray(keywords) || !keywords.length) return false
  // 只看项目路径与改到的文件名，不扫代码文本：测试数据/文档里出现「账」不代表性。
  const haystack = [state.cwd || '', ...state.code.files.map((file) => file.path)].join('\n').toLowerCase()
  return keywords.some((keyword) => keyword && haystack.includes(String(keyword).toLowerCase()))
}

function stackMatch(arch, state) {
  if (!arch.stacks || arch.stacks.includes('any')) return true
  const stacks = state.code.stacks
  const client = isClientKind(state)
  const server = isServerKind(state)
  return arch.stacks.some((stack) => {
    if (stack === 'server') return server
    if (stack === 'web') return stacks.includes('web') || server
    if (stack === 'android') return stacks.includes('android')
    if (stack === 'desktop') return stacks.includes('desktop')
    if (stack === 'iot') return stacks.includes('iot')
    if (stack === 'llm') return hasLlmSignal(state)
    if (stack === 'enterprise') return false
    return stacks.includes(stack)
  }) && (client || server || stacks.length > 0 || arch.stacks.includes('any'))
}

/** 推荐架构（core / recommended），并给出「需要几种」。 */
export function recommendArchitectures(state) {
  const llm = hasLlmSignal(state)
  const distributable = distributionCandidate(state)
  const picked = []
  for (const arch of ARCHITECTURES) {
    if (arch.discouraged) continue
    if (arch.onlyWhen === 'distribution' && !distributable) continue
    const trigger = arch.triggers ? triggerHit(state, arch.triggers) : false
    const byStack = llm && arch.id === 'owasp-llm' ? true : stackMatch(arch, state)
    let tier = arch.tier
    if (trigger) tier = 'core'
    if (tier !== 'core' && tier !== 'recommended') continue
    if (!byStack) continue
    const whyParts = [arch.when]
    if (trigger) whyParts.push('项目特征命中（账务/资金类关键词）')
    if (arch.id === 'owasp-llm' && llm) whyParts.push('检测到程序接入大模型/Agent')
    picked.push({
      id: arch.id,
      name: arch.name,
      layer: arch.layer,
      layerName: arch.layerName,
      family: arch.family,
      mandatory: tier === 'core',
      discouraged: false,
      why: whyParts.join('；'),
      purpose: arch.purpose,
      rules: arch.rules || [],
      doc: arch.doc,
      selected: state.review.selectedArchitectures.includes(arch.id),
    })
  }
  const order = ['core', 'recommended']
  picked.sort((a, b) => {
    const tierDelta = order.indexOf(a.mandatory ? 'core' : 'recommended') - order.indexOf(b.mandatory ? 'core' : 'recommended')
    if (tierDelta !== 0) return tierDelta
    return a.layerName.localeCompare(b.layerName, 'zh-Hans-CN')
  })
  const core = picked.filter((arch) => arch.mandatory)
  const families = [...new Set(core.map((arch) => arch.family))]
  return { architectures: picked, count: core.length, core, recommended: picked.filter((arch) => !arch.mandatory), families }
}

/** 反模式检测（让冲突检测能看见真实代码结构）。每次全量重算，避免改好代码后旧反模式还挂着。 */
export function detectAntiPatterns(state) {
  const kind = state.code.projectKind
  const stacks = state.code.stacks
  const flags = {
    server: kind === 'server' || kind === 'mixed' || stacks.some((stack) => ['node', 'python', 'go', 'rust', 'jvm', 'server'].includes(stack)),
    android: kind === 'android' || stacks.includes('android'),
    web: kind === 'web' || stacks.includes('web'),
    desktop: kind === 'desktop' || stacks.includes('desktop'),
    mixed: kind === 'mixed',
  }
  const matchesKinds = (detector) => {
    if (!Array.isArray(detector.kinds) || !detector.kinds.length) return true
    return detector.kinds.some((candidate) => flags[candidate] === true)
  }
  const found = []
  for (const detector of ANTI_PATTERN_DETECTORS) {
    if (!matchesKinds(detector)) continue
    for (const snippet of codeSources(state)) {
      if (!snippet.text) continue
      if (TEST_FILE_RE.test(snippet.file || '')) continue
      for (const pattern of detector.patterns) {
        if (!new RegExp(pattern.re).test(snippet.text)) continue
        found.push({ arch: detector.arch, why: pattern.why, file: snippet.file, at: snippet.at || state.lastActivityAt })
      }
    }
  }
  const seen = new Set()
  state.anti = found.filter((item) => {
    const key = `${item.arch}|${item.why}|${item.file}`
    if (seen.has(key)) return false
    seen.add(key)
    return true
  }).slice(-40)
}

/** 架构冲突检查：推荐集 + AI 声明选择的架构 + 代码里检测到的反模式。 */
export function detectConflicts(state, recommendation) {
  const active = new Set(recommendation.architectures.map((arch) => arch.id))
  for (const id of state.review.selectedArchitectures) {
    if (ARCH_BY_ID.has(id)) active.add(id)
  }
  for (const item of state.anti) {
    if (ARCH_BY_ID.has(item.arch)) active.add(item.arch)
  }
  const conflicts = []
  for (const pair of CONFLICTS) {
    const a = pair.a
    const b = pair.b
    if (!active.has(a) || !active.has(b)) continue
    const ack = state.review.ack[pair.id]
    conflicts.push({
      id: pair.id,
      title: pair.title,
      severity: pair.severity,
      a,
      b,
      aName: ARCH_BY_ID.get(a)?.name || a,
      bName: ARCH_BY_ID.get(b)?.name || b,
      detail: pair.detail,
      resolution: pair.resolution,
      rules: pair.rules || [],
      acknowledged: Boolean(ack && ack.resolution),
      ackNote: ack ? ack.resolution : '',
      ackAt: ack ? ack.at : 0,
    })
  }
  const rank = { hard: 0, overlap: 1, tension: 2 }
  conflicts.sort((left, right) => (rank[left.severity] ?? 9) - (rank[right.severity] ?? 9))
  return conflicts
}

/** 该会话适用的规则（按端过滤）+ 规则状态计算。 */
export function rulesInScope(state) {
  const client = isClientKind(state)
  const server = isServerKind(state)
  const distributable = distributionCandidate(state)
  return RULES.filter((rule) => {
    if (rule.applies === '通') return true
    if (rule.applies === '端') return client
    if (rule.applies === '服') return server
    if (rule.applies === '发') return distributable
    return true
  })
}

function joinedText(state) {
  return state.snippets.map((snippet) => snippet.text).join('\n')
}

/**
 * 自动检查的代码来源：优先用 Host 从磁盘读到的**当前文件内容**（state.fileTexts），
 * 这样改好代码后不会因为历史写入片段还留着旧内容而一直被误判。
 * 只有拿不到磁盘内容时，才回退到「每个文件最近一次写入的片段」。
 */
function codeSources(state) {
  const fileTexts = state && state.fileTexts && typeof state.fileTexts === 'object' ? state.fileTexts : null
  if (fileTexts) {
    const entries = Object.entries(fileTexts).filter(([, text]) => typeof text === 'string' && text)
    if (entries.length) return entries.map(([file, text]) => ({ file, text, at: 0 }))
  }
  const latest = new Map()
  for (const snippet of state.snippets) {
    if (!snippet || typeof snippet.text !== 'string' || !snippet.text) continue
    latest.set(snippet.file || '', snippet)
  }
  return [...latest.values()]
}

function lineOf(text, index) {
  let line = 1
  for (let i = 0; i < index && i < text.length; i += 1) {
    if (text[i] === '\n') line += 1
  }
  return line
}

function findPatterns(state, patterns) {
  const findings = []
  for (const snippet of codeSources(state)) {
    if (!snippet.text) continue
    if (TEST_FILE_RE.test(snippet.file || '')) continue
    for (const pattern of patterns) {
      let re
      try {
        re = new RegExp(pattern.re, pattern.flags || 'i')
      } catch {
        continue
      }
      const match = re.exec(snippet.text)
      if (!match) continue
      // 扫描器自己的规则定义（re: / regex: / pattern:）不算违规代码，
      // 否则「检测弱哈希」的规则文本会把扫描器自己判成弱哈希。
      const lineStart = snippet.text.lastIndexOf('\n', Math.max(0, match.index - 1)) + 1
      const lineEndIndex = snippet.text.indexOf('\n', match.index)
      const lineText = snippet.text.slice(lineStart, lineEndIndex === -1 ? snippet.text.length : lineEndIndex)
      if (/(^|\s)(re|regex|pattern)\s*[:=]/i.test(lineText)) continue
      // 中文说明/教学文本里引用的危险示例（如「必须删除 md5( 调用」）不算真实代码违规；
      // 中文注释里的示例同样跳过（注释不会执行）。
      const trimmedLine = lineText.trim()
      if (/[\u4e00-\u9fff]/.test(lineText) && (/['"`]/.test(lineText) || /^(\/\/|#|\*|\/\*)/.test(trimmedLine))) continue
      const context = snippet.text.slice(Math.max(0, match.index - 80), match.index + 160)
      if (pattern.ignoreIf) {
        try {
          if (new RegExp(pattern.ignoreIf, 'i').test(context)) continue
        } catch {
          // ignore
        }
      }
      findings.push({
        file: snippet.file,
        line: lineOf(snippet.text, match.index),
        snippet: match[0].slice(0, 120),
        why: pattern.why || '',
        at: snippet.at,
      })
    }
  }
  return findings.slice(0, 20)
}

function findProjectFiles(state, patterns) {
  const files = [...state.projectFiles, ...state.code.files.map((file) => file.path)]
  const hits = []
  for (const file of files) {
    for (const pattern of patterns) {
      if (pattern.re.test(file)) {
        if (!hits.includes(file)) hits.push(file)
      }
    }
  }
  return hits.slice(0, 10)
}

/** 自动检查结果：ruleId -> { status, findings, evidenceFiles }。 */
export function computeAutoFindings(state) {
  const result = {}
  for (const rule of RULES) {
    const check = AUTO_CHECKS[rule.id]
    if (!check) continue
    if (check.kind === 'text') {
      const findings = findPatterns(state, check.patterns)
      result[rule.id] = {
        status: findings.length ? (check.warnOnly ? 'warn' : 'violation') : 'auto-clear',
        findings,
        evidenceFiles: [],
      }
    } else if (check.kind === 'file') {
      const evidenceFiles = findProjectFiles(state, check.files)
      result[rule.id] = {
        status: evidenceFiles.length ? 'auto-clear' : 'unverified',
        findings: [],
        evidenceFiles,
      }
    } else if (check.kind === 'dist') {
      // 由 Host 的分发包自检（lib/dist.js）写入 state.distribution。
      const dist = state.distribution
      if (!dist) {
        result[rule.id] = { status: 'unverified', findings: [], evidenceFiles: [] }
      } else if (dist.ok) {
        result[rule.id] = { status: 'auto-clear', findings: [], evidenceFiles: dist.packageDir ? [dist.packageDir] : [] }
      } else {
        result[rule.id] = {
          status: 'violation',
          findings: (dist.findings || []).map((item) => ({ file: item.file || '', line: 0, snippet: '', why: item.why || '' })),
          evidenceFiles: [],
        }
      }
    }
  }
  return result
}

function isPassingStatus(status) {
  return status === 'auto-clear' || status === 'attested' || status === 'waived'
}

/**
 * 评审计算。
 * @param {object} state 会话状态
 * @param {object} settings 插件设置
 * @param {{ explicit?: boolean }} [options]
 */
export function evaluate(state, settings = {}, options = {}) {
  const scope = rulesInScope(state)
  const auto = computeAutoFindings(state)
  const recommendation = recommendArchitectures(state)
  const conflicts = detectConflicts(state, recommendation)
  const review = state.review
  const dirty = state.code.writeCount > review.submittedWriteCount

  const ruleResults = []
  let autoPass = 0
  let attestedCount = 0
  let failedCount = 0
  const failed = []
  const missing = []
  const warnings = []

  for (const rule of scope) {
    const autoResult = auto[rule.id]
    let status = 'unverified'
    let findings = []
    let evidence = ''

    if (autoResult) {
      findings = autoResult.findings
      if (autoResult.status === 'violation') status = 'violation'
      else if (autoResult.status === 'warn') status = 'warn'
      else status = 'auto-clear'
      if (autoResult.status === 'unverified') status = 'unverified'
    }

    const attest = review.attested[rule.id]
    if (attest && attest.verdict === 'pass' && attest.evidence) {
      evidence = attest.evidence
      if (status !== 'violation') status = 'attested'
    }
    if (attest && attest.verdict === 'na' && rule.level !== 'L1' && (attest.evidence || attest.reason)) {
      status = 'waived'
      evidence = attest.evidence || attest.reason || ''
    }
    const waiver = review.waived[rule.id]
    if (waiver && waiver.reason && rule.level !== 'L1') {
      if (!waiver.expiresAt || waiver.expiresAt > now()) {
        status = 'waived'
        evidence = waiver.reason
      }
    }
    if (rule.level === 'L1' && (status === 'waived')) status = 'violation'

    if (status === 'auto-clear') autoPass += 1
    if (status === 'attested') attestedCount += 1
    if (status === 'warn') warnings.push(rule.id)

    if (isPassingStatus(status)) {
      // ok
    } else if (status === 'violation') {
      failedCount += 1
      failed.push({ id: rule.id, level: rule.level, title: rule.title, reason: findings.length ? '自动检查命中违规' : '强制项不满足', source: 'auto', findings })
    } else {
      missing.push({ id: rule.id, level: rule.level, title: rule.title })
      if (rule.level !== 'L3') failedCount += 1
    }

    ruleResults.push({
      id: rule.id,
      group: rule.group,
      level: rule.level,
      applies: rule.applies,
      title: rule.title,
      criteria: rule.criteria,
      auto: Boolean(autoResult),
      status,
      findings,
      evidence,
      evidenceFiles: autoResult ? autoResult.evidenceFiles : [],
    })
  }

  const blockers = []
  for (const item of failed) blockers.push({ code: 'rule-violation', rule: item.id, message: `${item.id} ${item.level} ${item.title}：${item.reason}` })
  for (const item of missing) {
    if (item.level === 'L1') blockers.push({ code: 'rule-missing', rule: item.id, message: `${item.id} L1 ${item.title}：强制项需要提交证据` })
    else if (item.level === 'L2') blockers.push({ code: 'rule-missing', rule: item.id, message: `${item.id} L2 ${item.title}：需满足或走豁免流程` })
  }
  for (const conflict of conflicts) {
    if (!conflict.acknowledged) {
      blockers.push({
        code: 'architecture-conflict',
        conflict: conflict.id,
        message: `架构冲突未登记处理结论：${conflict.title}（${conflict.severity}）`,
      })
    }
  }
  if (review.waived) {
    for (const id of Object.keys(review.waived)) {
      if (LEVEL_BY_RULE.get(id) === 'L1') blockers.push({ code: 'l1-not-waivable', rule: id, message: `${id} 是强制项，不可豁免（规则 §十）` })
    }
  }

  const verdict = blockers.length === 0 ? 'pass' : 'fail'
  const lastResult = review.lastResult
  let stateName
  if (!state.code.doing) {
    stateName = 'na'
  } else if (dirty) {
    // 上次提交之后又改了代码：通过结论失效，需要重新提交。
    stateName = lastResult && lastResult.verdict === 'fail' ? 'failed' : 'pending'
  } else if (review.lastSubmitAt && lastResult) {
    stateName = lastResult.verdict === 'pass' ? 'passed' : 'failed'
  } else {
    stateName = 'pending'
  }
  const score = scope.length ? Math.round((autoPass + attestedCount + Object.keys(review.waived).length) / scope.length * 100) : 100

  return {
    state: stateName,
    verdict,
    dirty,
    score,
    scopeSize: scope.length,
    l1Size: scope.filter((rule) => rule.level === 'L1').length,
    autoPass,
    attested: attestedCount,
    failedCount,
    failed,
    missing,
    warnings,
    blockers,
    conflicts,
    rules: ruleResults,
    conflictCount: conflicts.filter((item) => !item.acknowledged).length,
    explicit: Boolean(options.explicit),
  }
}

/** 组装给前端/工具的会话视图。 */
export function buildSessionView(state, settings = {}, evaluateResult) {
  const recommendation = recommendArchitectures(state)
  const evaluation = evaluateResult || evaluate(state, settings)
  // 非代码会话不评审，也不展示架构推荐（避免把「聊天会话」当成要做安全工作）。
  const showArchitectures = state.code.doing
  const distributable = distributionCandidate(state)
  return {
    id: state.id,
    title: state.title || '未命名会话',
    cwd: state.cwd || '',
    status: state.status,
    createdAt: state.createdAt,
    lastActivityAt: state.lastActivityAt,
    code: {
      doing: state.code.doing,
      score: state.code.score,
      projectKind: state.code.projectKind,
      stacks: [...state.code.stacks],
      signals: state.code.signals.slice(-8).map((signal) => ({ kind: signal.kind, detail: signal.detail, at: signal.at })),
      files: state.code.files.slice(-12).map((file) => file.path),
    },
    architectures: showArchitectures ? recommendation.architectures : [],
    architectureCount: showArchitectures ? recommendation.count : 0,
    architectureFamilies: showArchitectures ? recommendation.families : [],
    conflicts: evaluation.conflicts,
    review: {
      state: evaluation.state,
      verdict: evaluation.verdict,
      unqualified: state.code.doing && evaluation.state !== 'passed',
      score: evaluation.score,
      turn: state.turns.current,
      attempts: state.review.attempts,
      enforced: state.review.enforced,
      redoCount: state.review.redoCount || 0,
      enforcePaused: Boolean(state.review.enforcePaused),
      coaching: (state.review.redoCount || 0) >= 2 || (state.review.attempts || 0) >= 2,
      requestedAt: state.review.requestedAt || 0,
      requestedText: state.review.requestedText || '',
      lastAt: state.review.lastSubmitAt || state.review.lastAt,
      passedRules: evaluation.rules.filter((rule) => isPassingStatus(rule.status) && rule.status !== 'auto-clear').map((rule) => rule.id),
      failedRules: evaluation.failed.map((item) => ({ ...item })),
      missingRules: evaluation.missing.map((item) => ({ ...item })),
      autoViolations: evaluation.rules.filter((rule) => rule.status === 'violation').map((rule) => ({ id: rule.id, level: rule.level, findings: rule.findings })),
      attested: evaluation.attested,
      waived: Object.keys(state.review.waived),
      selectedArchitectures: [...state.review.selectedArchitectures],
      notes: state.review.notes || '',
    },
    progress: {
      inScope: evaluation.scopeSize,
      l1: evaluation.l1Size,
      autoPass: evaluation.autoPass,
      attested: evaluation.attested,
      failed: evaluation.failedCount,
    },
    activity: {
      lastTool: state.activity.lastTool,
      lastFile: state.activity.lastFile,
      codeTurns: state.turns.codeTurns.length,
      turns: state.turns.total,
    },
    distribution: state.distribution
      ? {
        ok: state.distribution.ok === true,
        checkedAt: state.distribution.checkedAt || 0,
        packageDir: state.distribution.packageDir || '',
        packageName: state.distribution.package ? state.distribution.package.name || '' : '',
        packageVersion: state.distribution.package ? state.distribution.package.version || '' : '',
        findings: Array.isArray(state.distribution.findings) ? state.distribution.findings.slice(0, 20) : [],
      }
      : null,
    distributionTarget: showArchitectures ? distributable : false,
    rules: evaluation.rules,
  }
}

// ---------------------------------------------------------------------------
// 提交 / 豁免 / 冲突登记
// ---------------------------------------------------------------------------

function normalizeRulePayload(payload) {
  const rules = {}
  const source = payload && typeof payload === 'object' && payload.rules && typeof payload.rules === 'object' ? payload.rules : {}
  for (const [id, value] of Object.entries(source)) {
    if (!RULE_BY_ID.has(id)) return { error: `未知规则编号：${id}` }
    if (typeof value === 'string') {
      rules[id] = { verdict: 'pass', evidence: value.trim() }
      continue
    }
    if (!value || typeof value !== 'object') return { error: `规则 ${id} 的提交格式不对` }
    const verdict = textOf(value.verdict || 'pass')
    if (!['pass', 'na', 'waived'].includes(verdict)) return { error: `规则 ${id} 的结论只能是 pass / na / waived` }
    const evidence = textOf(value.evidence || value.reason || '').trim()
    if (verdict === 'pass' && evidence.length < 6) return { error: `规则 ${id} 需要具体证据（至少 6 个字符）` }
    const level = LEVEL_BY_RULE.get(id)
    if (level === 'L1' && verdict !== 'pass') return { error: `${id} 是强制项（L1），不可标记为 ${verdict}` }
    rules[id] = { verdict, evidence }
  }
  return { rules }
}

/** 会话 AI 或面板提交评审。返回 { ok, evaluation } 或 { ok:false, error }。 */
export function submitReview(state, payload, settings = {}) {
  const normalized = normalizeRulePayload(payload)
  if (normalized.error) return { ok: false, error: { code: 'bad-payload', message: normalized.error } }
  const selected = Array.isArray(payload && payload.architectures)
    ? payload.architectures.filter((id) => typeof id === 'string' && ARCH_BY_ID.has(id))
    : []
  const badArch = Array.isArray(payload && payload.architectures)
    ? payload.architectures.filter((id) => typeof id === 'string' && !ARCH_BY_ID.has(id))
    : []
  if (badArch.length) {
    return { ok: false, error: { code: 'bad-payload', message: `未知架构 id：${badArch.join('、')}` } }
  }
  state.review.attested = normalized.rules
  state.review.selectedArchitectures = selected
  state.review.notes = textOf(payload && payload.notes).slice(0, 2000)
  state.review.attempts += 1
  state.review.lastSubmitAt = now()
  state.review.submittedWriteCount = state.code.writeCount
  state.review.noSubmitEnforced = 0
  const evaluation = evaluate(state, settings, { explicit: true })
  state.review.lastResult = { verdict: evaluation.verdict, state: evaluation.state, score: evaluation.score, blockers: evaluation.blockers, at: now() }
  // 刚提交过：结论直接按本次提交算，避免 evaluate 在 lastResult 写入前返回 pending。
  evaluation.state = evaluation.verdict === 'pass' ? 'passed' : 'failed'
  state.review.lastResult.state = evaluation.state
  state.review.state = evaluation.state
  state.review.verdict = evaluation.verdict
  state.review.lastAt = now()
  return { ok: true, evaluation }
}

export function waiveRule(state, ruleId, reason, actorNote = '') {
  const rule = RULE_BY_ID.get(ruleId)
  if (!rule) return { ok: false, error: { code: 'bad-payload', message: `未知规则编号：${ruleId}` } }
  if (rule.level === 'L1') return { ok: false, error: { code: 'l1-not-waivable', message: `${ruleId} 是 L1 强制项，规则 §十 明确不得豁免` } }
  const text = textOf(reason).trim()
  if (text.length < 6) return { ok: false, error: { code: 'bad-payload', message: '豁免必须写明不适用的原因与补偿控制（至少 6 个字符）' } }
  state.review.waived[ruleId] = {
    reason: text.slice(0, 1000),
    actorNote: textOf(actorNote).slice(0, 300),
    at: now(),
    expiresAt: now() + WAIVE_DAYS * 24 * 60 * 60 * 1000,
  }
  return { ok: true }
}

export function ackConflict(state, conflictId, resolution) {
  const pair = CONFLICTS.find((item) => item.id === conflictId)
  if (!pair) return { ok: false, error: { code: 'bad-payload', message: `未知冲突编号：${conflictId}` } }
  const text = textOf(resolution).trim()
  if (text.length < 4) return { ok: false, error: { code: 'bad-payload', message: '请写明这个冲突的处理结论（至少 4 个字符）' } }
  state.review.ack[conflictId] = { resolution: text.slice(0, 1000), at: now() }
  return { ok: true }
}

/** 评审判官要注入会话的提醒文本（按需精简）。 */
export function buildReminderText(state, settings = {}, { phase = 'detected' } = {}) {
  const evaluation = evaluate(state, settings)
  const recommendation = recommendArchitectures(state)
  const coreNames = recommendation.core.map((arch) => arch.name).join('、') || '（暂未识别到）'
  const conflicts = evaluation.conflicts.filter((item) => !item.acknowledged).map((item) => `${item.title}（${item.severity}）`)
  const failedTop = evaluation.failed.slice(0, 5).map((item) => `${item.id} ${item.title}`)
  const missingTop = evaluation.missing.slice(0, 6).map((item) => `${item.id} ${item.title}`)
  const lines = [
    '【代码安全防御评审判官】',
  ]
  if (phase === 'requested') {
    lines.push('用户已在会话里要求评审本会话（口令：检查审核评审该会话），评审判官已受理。')
  }
  lines.push(
    '本会话检测到正在写代码，按《代码安全防御架构规则》v1.0（强制性规则）必须完成代码安全防御评审且结论为「合格」才算完成用户任务。',
    `这个程序需要 ${recommendation.count} 种核心代码安全防御架构：${coreNames}。`,
  )
  if (conflicts.length) lines.push(`架构冲突检查发现 ${conflicts.length} 项未登记处理结论：${conflicts.join('；')}。`)
  if (phase === 'redo' || phase === 'turn-stop' || phase === 'requested') {
    lines.push('评审结论：不合格。不合格必须重做，直到合格为止；不能把「先做完」当作完成。')
  }
  if (evaluation.blockers.length) {
    lines.push(`当前不合格原因 ${evaluation.blockers.length} 项：`)
    for (const blocker of evaluation.blockers.slice(0, 10)) lines.push(`- ${blocker.message}`)
  } else {
    lines.push('当前自动检查未发现阻断项，但仍需你提交评审证据并取得「合格」结论。')
  }
  if (failedTop.length || missingTop.length) {
    lines.push(`优先重做：${[...failedTop, ...missingTop].slice(0, 8).join('；')}。`)
  }
  lines.push('下一步：调用 security_judge 工具，action=status 查看完整清单；按规则修复代码、补齐代码安全防御架构、登记架构冲突处理结论后 action=submit 提交评审，直到 verdict=pass（合格）。')
  if (phase === 'turn-stop' || phase === 'redo' || phase === 'requested') {
    lines.push('（本回合在评审合格前不能结束。继续重做：要么修复并重新提交评审，要么说明为什么本会话不算代码任务。）')
  }
  return lines.join('\n')
}

export default {
  createSessionState,
  ingestSessionEvent,
  refreshProfile,
  recommendArchitectures,
  detectConflicts,
  detectAntiPatterns,
  computeAutoFindings,
  rulesInScope,
  distributionCandidate,
  evaluate,
  buildSessionView,
  submitReview,
  waiveRule,
  ackConflict,
  buildReminderText,
  isClientKind,
  isServerKind,
}
