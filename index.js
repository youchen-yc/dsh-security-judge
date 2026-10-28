/**
 * 代码安全防御规则评审判官（dsh-security-judge）· Host 插件入口。
 *
 * 它只做一件事：审核正在写代码的会话有没有按《代码安全防御架构规则》v1.0
 * 做代码安全防御、加入了哪些代码安全防御架构、这些架构之间是否冲突；
 * 并（在用户授权后）要求代码会话通过评审才算完成用户任务。
 *
 * 权限边界（底层逻辑，不可修改）：本插件权限低于用户最高权限，只用于代码安全
 * 防御规则与架构的评审；不能修改代码、不能修改配置、不能代替用户做决定。
 * 未获得用户授权时只读观察。
 *
 * 本文件只做装配：状态与判定在 lib/core.js、lib/engine.js，目录在 lib/catalog.js。
 */

import { randomBytes } from 'node:crypto'

import { createCore, makeUserMessage } from './lib/core.js'
import { createApiHandler, API_PREFIX } from './lib/httpapi.js'

export const name = 'security-judge'
export const inject = ['tools']

const VERSION = '1.6.0'

function messageOf(error) {
  return String(error && error.message ? error.message : error)
}

const TOOL_DESCRIPTION = [
  '代码安全防御规则评审判官：审核本会话是否按《代码安全防御架构规则》v1.0（强制性规则）做了代码安全防御与代码安全防御架构。',
  '它会自动识别本会话是否在写代码、判断这个程序需要几种核心代码安全防御架构（一种 / 两种 / 多种）、检查这些架构之间是否冲突，并给出必须满足的规则清单。',
  'action=status：查看本会话的代码识别、推荐架构、架构冲突、评审状态与待处理项。',
  'action=checklist：查看适用规则逐条状态（自动检查命中 / 需要提交证据 / 已通过）。',
  'action=architectures：只看这个程序需要的代码安全防御架构与冲突检查结论。',
  'action=submit：提交评审。payload = { architectures?: string[], rules: { "A-02": { verdict:"pass", evidence:"具体证据" }, ... }, notes?: string }。L1 强制项不可豁免；自动检查命中的违规必须先改代码。',
  'action=conflict-ack：登记架构冲突处理结论。payload = { conflictId, resolution }。',
  'action=coach：连续不合格时获取逐条教学单（先改哪个、怎么改、补哪个架构、交什么证据、提交格式）。',
  'action=authority：查看/请求评审权限（授权只能由用户在面板点，插件不能自行授权）。',
  '用户在会话里说「检查审核评审该会话」时，评审判官会自动受理：回看该会话的代码工作并开始评审；不合格就要求该会话按规则重做，直到合格。',
  '规则要求：代码会话必须通过本评审并拿到「合格」（verdict=pass）才算完成用户任务；不合格必须重做，直到合格为止。没有在写代码的会话不评审。',
].join('\n')

function renderToolValue(_args, value) {
  try {
    if (value && value.ok === false && value.error) {
      return [{ type: 'text', text: `失败（${value.error.code || 'error'}）：${value.error.message || '未知错误'}` }]
    }
    const text = JSON.stringify(value, null, 2)
    return [{ type: 'text', text: text.length > 16000 ? `${text.slice(0, 16000)}\n…（内容过长已截断，可用 action=checklist 分批查看）` : text }]
  } catch {
    return [{ type: 'text', text: String(value) }]
  }
}

export function apply(ctx, rawConfig = {}) {
  const log = ctx.logger ?? console
  const config = rawConfig && typeof rawConfig === 'object' ? rawConfig : {}
  const core = createCore({ ctx, config, log, pluginVersion: VERSION })

  // 启动采集（异步读取持久化状态后补齐会话）。
  core.start()

  // -------------------------------------------------------------------------
  // Agent 工具
  // -------------------------------------------------------------------------
  const tool = {
    name: 'security_judge',
    description: TOOL_DESCRIPTION,
    parameters: {
      type: 'object',
      properties: {
        action: {
          type: 'string',
          enum: ['status', 'checklist', 'architectures', 'submit', 'conflict-ack', 'coach', 'authority'],
          description: '要执行的动作',
        },
        payload: {
          type: 'object',
          additionalProperties: true,
          description: '动作参数。submit: {architectures?,rules,notes?}；conflict-ack: {conflictId,resolution}；authority: {request?:boolean}。',
        },
      },
      required: ['action'],
      additionalProperties: false,
    },
    output: {
      schema: { type: 'object', additionalProperties: true },
      render: renderToolValue,
    },
    timeoutMs: 120000,
    async execute(args = {}, exec = {}) {
      const agentId = exec && exec.agent && exec.agent.id ? String(exec.agent.id) : ''
      const action = String(args.action || '').trim()
      const payload = args.payload && typeof args.payload === 'object' ? args.payload : {}
      try {
        if (action === 'status') {
          const result = await core.toolStatus(agentId)
          if (result.ok === false && exec.deferContext) {
            exec.deferContext(makeUserMessage('【代码安全防御评审判官】请让用户打开评审判官面板，查看会话与授权状态。'))
          }
          return result
        }
        if (action === 'checklist') {
          return await core.toolStatus(agentId, { detail: true })
        }
        if (action === 'coach') {
          return await core.toolCoach(agentId)
        }
        if (action === 'architectures') {
          return await core.toolArchitectures(agentId)
        }
        if (action === 'submit') {
          const result = await core.toolSubmit(agentId, payload)
          if (result && result.ok && result.verdict !== 'pass' && exec.deferContext) {
            const lines = ['【代码安全防御评审判官】评审未通过 = 不合格；不合格必须重做，直到合格为止。本会话不能算完成。']
            if (result.blockers && result.blockers.length) {
              lines.push(`阻断项（${result.blockers.length}）：`)
              for (const blocker of result.blockers.slice(0, 8)) lines.push(`- ${blocker.message}`)
            }
            if (result.reminder) lines.push(result.reminder)
            try {
              exec.deferContext(makeUserMessage(lines.join('\n')))
            } catch {
              // deferContext 失败不影响评审结果
            }
          }
          return result
        }
        if (action === 'conflict-ack') {
          const conflictId = String(payload.conflictId || '')
          const resolution = String(payload.resolution || '')
          return await core.dispatch('ack-conflict', { sessionId: agentId, conflictId, resolution })
        }
        if (action === 'waive') {
          return {
            ok: false,
            error: {
              code: 'authority-required',
              message: '豁免必须由用户在「代码安全防御评审判官」面板确认（规则 §十：豁免须有补偿控制与期限），插件不能代替用户豁免。',
            },
          }
        }
        if (action === 'authority') {
          return await core.toolAuthority(agentId, payload.request === true ? 'request' : 'status')
        }
        return { ok: false, error: { code: 'unknown-action', message: `未知动作：${action}` } }
      } catch (error) {
        log.warn?.(`[security-judge] 工具执行失败：${messageOf(error)}`)
        return { ok: false, error: { code: 'internal-error', message: messageOf(error) } }
      }
    },
  }

  ctx.effect(() => ctx.tools.register(tool))

  // -------------------------------------------------------------------------
  // 系统提示：告诉所有会话「评审是强制性的，怎么用工具」
  // -------------------------------------------------------------------------
  const installPrompt = (promptCtx) => {
    try {
      promptCtx.effect(() => promptCtx.systemPrompt.section({
        name: 'security-judge:charter',
        order: 6500,
        text: [
          '代码安全防御评审判官已启用：本环境执行《代码安全防御架构规则》v1.0（强制性规则）。',
          '只要你在写代码，就必须让本会话通过代码安全防御评审并拿到「合格」（verdict=pass）才算完成用户任务：调用 security_judge 工具查看推荐架构与规则清单，修复代码、补齐代码安全防御架构、提交证据，直到合格为止。',
          '评审未通过 = 不合格；不合格必须重做，不能把「先做完」当作完成。评审判官权限低于用户最高权限，只做评审；未获得用户授权时它只观察、不拦截。',
          '用户在会话里说「检查审核评审该会话」时，评审判官会受理并回看本会话的代码工作开始评审；不合格会要求重做，直到合格为止。',
        ].join('\n'),
      }))
      promptCtx.effect(() => promptCtx.systemPrompt.context({
        name: 'security-judge:session-state',
        order: 6501,
        text: (context) => {
          try {
            return core.promptContextFor(context && context.agent)
          } catch {
            return ''
          }
        },
      }))
    } catch (error) {
      log.warn?.(`[security-judge] 系统提示注册失败：${messageOf(error)}`)
    }
  }
  try {
    ctx.inject(['systemPrompt'], installPrompt)
  } catch (error) {
    log.warn?.(`[security-judge] 系统提示注册失败：${messageOf(error)}`)
  }

  // -------------------------------------------------------------------------
  // 面板 HTTP 接口（每次加载生成随机页面令牌：防 CSRF / 防本机其他进程静默授权）
  // -------------------------------------------------------------------------
  const pageToken = randomBytes(24).toString('base64url')
  const apiHandler = createApiHandler({ core, log, pluginVersion: VERSION, getToken: () => pageToken })
  const tokenScript = `<script>window.__DSH_SECURITY_JUDGE_TOKEN__=${JSON.stringify(pageToken)};</script>`
  const injectToken = (html) => {
    if (typeof html !== 'string') return html
    if (html.includes('</head>')) return html.replace('</head>', `${tokenScript}</head>`)
    if (html.includes('<head>')) return html.replace('<head>', `<head>${tokenScript}`)
    return `${tokenScript}${html}`
  }
  const installHttp = (webCtx) => {
    try {
      webCtx.effect(() => webCtx.webServer.register({
        kind: 'prefix',
        path: API_PREFIX,
        handler: (req, res) => apiHandler(req, res),
      }))
    } catch (error) {
      log.warn?.(`[security-judge] 面板接口注册失败（Agent 工具不受影响）：${messageOf(error)}`)
    }
    try {
      webCtx.effect(() => webCtx.webServer.tapIndex(injectToken))
    } catch (error) {
      log.warn?.(`[security-judge] 页面令牌注入失败（面板会返回 401，请重启 DSH）：${messageOf(error)}`)
    }
  }
  try {
    ctx.inject(['webServer'], installHttp)
  } catch (error) {
    log.warn?.(`[security-judge] 面板接口注册失败（Agent 工具不受影响）：${messageOf(error)}`)
  }

  // -------------------------------------------------------------------------
  // 卸载
  // -------------------------------------------------------------------------
  ctx.effect(() => () => {
    core.dispose().catch(() => {})
  })

  return {
    version: VERSION,
  }
}
