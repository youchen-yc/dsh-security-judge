/**
 * 代码安全防御评审判官 · 面板 HTTP 接口（同源，前缀 /dsh-security-judge/api）。
 *
 *   GET  /dsh-security-judge/api/state        面板全量状态
 *   GET  /dsh-security-judge/api/session?id=  单个会话视图
 *   POST /dsh-security-judge/api/action       { action, payload }
 *
 * 鉴权（防 CSRF / 防本机其他进程偷偷授权）：
 *   - 每次插件加载生成一个随机 token，只通过 index 注入到页面；
 *   - 所有非预检请求必须带 `x-security-judge-token`，否则 401；
 *   - 带了 Origin 的请求必须与宿主同源，否则 403；
 *   - 跨站页面无法携带自定义头（会被 CORS 预检拦下），因此无法静默 grant-authority。
 *
 * 只服务面板；Agent 侧能力走 security_judge 工具。接口不提供任何修改代码的能力。
 */

import { timingSafeEqual } from 'node:crypto'

export const API_PREFIX = '/dsh-security-judge/api'
const TOKEN_HEADER = 'x-security-judge-token'

const MAX_BODY = 1024 * 1024

function sendJson(res, status, value) {
  const body = JSON.stringify(value)
  res.statusCode = status
  res.setHeader('content-type', 'application/json; charset=utf-8')
  res.setHeader('cache-control', 'no-store')
  res.setHeader('x-content-type-options', 'nosniff')
  res.end(body)
}

function tokenMatches(expected, actual) {
  if (typeof expected !== 'string' || !expected) return false
  if (typeof actual !== 'string' || !actual) return false
  const left = Buffer.from(expected, 'utf8')
  const right = Buffer.from(actual, 'utf8')
  if (left.length !== right.length) return false
  try {
    return timingSafeEqual(left, right)
  } catch {
    return false
  }
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0
    const chunks = []
    req.on('data', (chunk) => {
      size += chunk.length
      if (size > MAX_BODY) {
        reject(Object.assign(new Error('请求体过大'), { code: 'bad-payload' }))
        req.destroy()
        return
      }
      chunks.push(chunk)
    })
    req.on('end', () => {
      if (!chunks.length) return resolve({})
      try {
        const text = Buffer.concat(chunks).toString('utf8')
        resolve(text.trim() ? JSON.parse(text) : {})
      } catch (error) {
        reject(Object.assign(new Error('请求体不是合法 JSON'), { code: 'bad-payload' }))
      }
    })
    req.on('error', reject)
  })
}

export function createApiHandler({ core, log, pluginVersion, getToken }) {
  const tokenOf = () => {
    try {
      return typeof getToken === 'function' ? getToken() : ''
    } catch {
      return ''
    }
  }

  return async function handleApi(req, res) {
    try {
      const origin = req.headers.origin
      const allowedOrigin = origin ? core.isAllowedOrigin(origin) : true

      if (origin && allowedOrigin) {
        res.setHeader('access-control-allow-origin', origin)
        res.setHeader('vary', 'origin')
        res.setHeader('access-control-allow-methods', 'GET,POST,OPTIONS')
        res.setHeader('access-control-allow-headers', `content-type,accept,${TOKEN_HEADER}`)
      }
      if (req.method === 'OPTIONS') {
        res.statusCode = 204
        res.end()
        return
      }

      const url = new URL(req.url || '/', 'http://127.0.0.1')
      const pathname = url.pathname
      if (!pathname.startsWith(API_PREFIX)) {
        sendJson(res, 404, { ok: false, error: { code: 'not-found', message: '未知接口' } })
        return
      }
      if (origin && !allowedOrigin) {
        sendJson(res, 403, { ok: false, error: { code: 'bad-origin', message: '跨站请求被拒绝' } })
        return
      }
      // 读接口允许页面直接使用（只读、同源浏览器无法被跨站读取）；
      // 所有会改变状态的操作必须带页面令牌，防止 CSRF 与同机进程静默授权。
      if (req.method !== 'GET') {
        const supplied = req.headers[TOKEN_HEADER]
        if (!tokenMatches(tokenOf(), Array.isArray(supplied) ? supplied[0] : supplied)) {
          sendJson(res, 401, {
            ok: false,
            error: {
              code: 'unauthorized',
              message: '缺少或错误的评审判官页面令牌（请刷新页面；写操作只接受当前面板发起的请求）',
            },
          })
          return
        }
      }

      const rest = pathname.slice(API_PREFIX.length) || '/'
      await core.ensureReady()

      if (req.method === 'GET' && (rest === '/state' || rest === '/')) {
        sendJson(res, 200, await core.getPanelState(pluginVersion))
        return
      }
      if (req.method === 'GET' && rest === '/session') {
        const id = url.searchParams.get('id') || ''
        const session = core.getSessionView(id)
        if (!session) {
          sendJson(res, 404, { ok: false, error: { code: 'unknown-session', message: `找不到会话：${id}` } })
          return
        }
        sendJson(res, 200, { ok: true, session })
        return
      }
      if (req.method === 'POST' && rest === '/action') {
        const body = await readBody(req)
        const action = typeof body.action === 'string' ? body.action : ''
        const payload = body.payload && typeof body.payload === 'object' ? body.payload : {}
        const result = await core.dispatch(action, payload)
        if (result && result.ok) {
          sendJson(res, 200, { ...result, state: await core.getPanelState(pluginVersion) })
        } else {
          sendJson(res, result && result.httpStatus ? result.httpStatus : 200, result || { ok: false, error: { code: 'internal-error', message: '未知错误' } })
        }
        return
      }
      sendJson(res, 404, { ok: false, error: { code: 'not-found', message: '未知接口' } })
    } catch (error) {
      const code = error && error.code ? String(error.code) : 'internal-error'
      log.warn?.(`[security-judge] 面板接口失败：${String(error && error.message ? error.message : error)}`)
      sendJson(res, 500, { ok: false, error: { code, message: String(error && error.message ? error.message : error) } })
    }
  }
}

