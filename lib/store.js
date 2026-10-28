/**
 * 代码安全防御评审判官 · 持久化。
 *
 * 只持久化三样东西：评审权限（authority）、设置（settings）、评审历史（history）。
 * 会话扫描与代码片段是运行期内存态，不落盘（会话日志本来就是权威来源）。
 *
 * 数据目录：优先环境变量 DSH_PROFILE_DIR，其次 ~/.dsh；插件目录为 security-judge-data。
 */

import fs from 'node:fs/promises'
import path from 'node:path'
import os from 'node:os'

const VERSION = 1
const HISTORY_LIMIT = 80

export const CHARTER = '本评审判官权限低于用户最高权限，只用于审核评审会话是否按代码安全防御规则做了代码安全防御架构；不能修改代码、不能修改配置、不能代替用户做决定。'
export const AUTHORITY_SCOPE = '代码安全防御规则与架构的评审（只读审查 + 完成门禁）'

export function defaultSettings() {
  return {
    mode: 'block', // advisory | remind | block（阻断需要用户先授权）
    autoScanMs: 15000,
    maxEnforcePerSession: 0, // 0 = 合格为止（不设上限）；>0 只作为用户自选的保护阈值
    blockWithoutPass: true,
  }
}

export function defaultAuthority() {
  return {
    granted: false,
    grantedAt: null,
    requestedAt: null,
    note: '',
  }
}

function resolveDataDir(configured) {
  if (typeof configured === 'string' && configured.trim()) return configured.trim()
  const base = process.env.DSH_PROFILE_DIR && process.env.DSH_PROFILE_DIR.trim()
    ? process.env.DSH_PROFILE_DIR.trim()
    : path.join(os.homedir(), '.dsh')
  return path.join(base, 'security-judge-data')
}

function clampSettings(raw, fallback) {
  const settings = { ...fallback }
  if (!raw || typeof raw !== 'object') return settings
  if (['advisory', 'remind', 'block'].includes(raw.mode)) settings.mode = raw.mode
  const number = (value, min, max, fallbackValue) => {
    const parsed = Number(value)
    if (!Number.isFinite(parsed)) return fallbackValue
    return Math.min(max, Math.max(min, Math.round(parsed)))
  }
  settings.autoScanMs = number(raw.autoScanMs, 3000, 120000, settings.autoScanMs)
  settings.maxEnforcePerSession = number(raw.maxEnforcePerSession, 0, 200, settings.maxEnforcePerSession)
  if (typeof raw.blockWithoutPass === 'boolean') settings.blockWithoutPass = raw.blockWithoutPass
  return settings
}

export function createStore({ dataDir, log }) {
  const dir = resolveDataDir(dataDir)
  const file = path.join(dir, 'state.json')
  const state = {
    version: VERSION,
    authority: defaultAuthority(),
    settings: defaultSettings(),
    history: [],
    pausedSessions: {}, // { sessionId: pausedAt } —— 重启后仍保持「暂停强制重做」
  }
  let ready = null
  let saveTimer = null
  let saving = null
  let dirty = false

  async function ensureReady() {
    if (ready) return ready
    ready = (async () => {
      try {
        const text = await fs.readFile(file, 'utf8')
        const parsed = JSON.parse(text)
        if (parsed && parsed.version === VERSION) {
          if (parsed.authority && typeof parsed.authority === 'object') {
            state.authority = { ...defaultAuthority(), ...parsed.authority }
          }
          state.settings = clampSettings(parsed.settings, defaultSettings())
          if (Array.isArray(parsed.history)) state.history = parsed.history.slice(-HISTORY_LIMIT)
          if (parsed.pausedSessions && typeof parsed.pausedSessions === 'object') {
            const entries = Object.entries(parsed.pausedSessions)
              .filter(([id, at]) => typeof id === 'string' && id && Number.isFinite(Number(at)))
              .sort((a, b) => Number(b[1]) - Number(a[1]))
              .slice(0, 300)
            state.pausedSessions = Object.fromEntries(entries)
          }
        }
      } catch (error) {
        if (error && error.code !== 'ENOENT') {
          log.warn?.(`[security-judge] 读取状态失败，按默认值启动：${String(error && error.message ? error.message : error)}`)
        }
      }
      return state
    })()
    return ready
  }

  async function writeNow() {
    const payload = JSON.stringify({
      version: VERSION,
      authority: state.authority,
      settings: state.settings,
      history: state.history.slice(-HISTORY_LIMIT),
      pausedSessions: state.pausedSessions,
    }, null, 2)
    await fs.mkdir(dir, { recursive: true })
    const temp = `${file}.${process.pid}.tmp`
    await fs.writeFile(temp, payload, 'utf8')
    await fs.rename(temp, file)
  }

  function scheduleSave() {
    dirty = true
    if (saveTimer) return
    saveTimer = setTimeout(() => {
      saveTimer = null
      if (!dirty) return
      dirty = false
      saving = writeNow().catch((error) => {
        log.warn?.(`[security-judge] 保存状态失败：${String(error && error.message ? error.message : error)}`)
      }).finally(() => {
        saving = null
      })
    }, 400)
    if (typeof saveTimer.unref === 'function') saveTimer.unref()
  }

  async function flush() {
    if (saveTimer) {
      clearTimeout(saveTimer)
      saveTimer = null
    }
    dirty = false
    try {
      await (saving || writeNow())
    } catch {
      // 已记日志，不阻断卸载
    }
  }

  return {
    dir,
    file,
    state,
    ensureReady,
    flush,
    getAuthority() {
      return state.authority
    },
    getSettings() {
      return state.settings
    },
    isSessionPaused(id) {
      return Boolean(id && state.pausedSessions[String(id)])
    },
    setSessionPaused(id, paused) {
      const key = String(id || '')
      if (!key) return false
      if (paused) state.pausedSessions[key] = Date.now()
      else delete state.pausedSessions[key]
      // 只保留最近 300 个会话，避免状态文件无限增长
      const entries = Object.entries(state.pausedSessions).sort((a, b) => Number(b[1]) - Number(a[1])).slice(0, 300)
      state.pausedSessions = Object.fromEntries(entries)
      scheduleSave()
      return Boolean(paused)
    },
    setAuthority(patch) {
      state.authority = { ...state.authority, ...patch }
      scheduleSave()
      return state.authority
    },
    grantAuthority(note = '') {
      state.authority = {
        granted: true,
        grantedAt: Date.now(),
        requestedAt: state.authority.requestedAt,
        note: String(note || '').slice(0, 500),
      }
      scheduleSave()
      return state.authority
    },
    revokeAuthority() {
      state.authority = { ...defaultAuthority(), requestedAt: state.authority.requestedAt }
      scheduleSave()
      return state.authority
    },
    requestAuthority() {
      state.authority = { ...state.authority, requestedAt: Date.now() }
      scheduleSave()
      return state.authority
    },
    saveSettings(patch) {
      state.settings = clampSettings({ ...state.settings, ...(patch || {}) }, state.settings)
      scheduleSave()
      return state.settings
    },
    recordHistory(entry) {
      state.history.push({ at: Date.now(), ...entry })
      if (state.history.length > HISTORY_LIMIT) state.history.splice(0, state.history.length - HISTORY_LIMIT)
      scheduleSave()
    },
  }
}
