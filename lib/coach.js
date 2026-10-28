/**
 * 评审判官 · 教学模式（连续不合格后教会话 AI 怎么做）。
 *
 * 用户要求：超过两次不合格，评审判官要教该会话 AI 怎么做。
 * 这里把「不合格项」翻译成可执行步骤：先修哪、怎么改、补哪个架构、交什么证据、按什么格式提交。
 *
 * 纯逻辑：输入会话状态与评审结果，输出结构化教学计划 + 中文教学文本。
 */

import {
  RULES,
  RULE_BY_ID,
  ARCH_BY_ID,
} from './catalog.js'

/** 高频规则的「怎么改」指引（其余规则回退到判定标准 + 证据模板）。 */
const FIX_GUIDES = {
  'A-01': '画一张信任边界图：列出前端 / 网关 / 服务 / 数据库与外部依赖，标出每个跨边界调用的方向、数据和身份转换点，放到 docs/security/trust-boundary.md；新增接口时同步更新。',
  'A-02': '把权限判断从业务代码收口到一个统一入口（中间件 / 拦截器 / 网关 / 策略服务）；业务层只调用入口，不再散落 if (isAdmin)。',
  'A-03': '默认拒绝：新接口未登记权限点时直接返回 403；补一条「未登记权限点访问被拒绝」的测试用例。',
  'A-04': '给每个关键资产（资金、身份、发布产物）写两层独立防线，例如「服务端鉴权 + 数据库归属校验」「签名校验 + 哈希核对」，两层不能依赖同一机制。',
  'A-05': '所有跨边界数据（客户端参数、内网服务返回、下游响应）先过统一校验层；不要因为「内网」就跳过。',
  'A-06': '检查是否存在「靠源码保密/混淆保证安全」的设计，改成依赖密钥与访问控制；源码公开后不应新增可利用路径。',
  'A-07': '列出服务账号、进程、令牌的权限清单，删掉默认全权限；数据库账号分读写，App 少申请权限。',
  'A-08': '高风险操作（改密、绑卡、大额、发布）在代码路径里同时检查两个独立条件（例如登录态 + 二次验证，或双人审批）。',
  'B-01': '把口令摘要换成自适应哈希：Java 用 BCrypt/Argon2id（spring-security-crypto），Node 用 bcrypt 或 argon2；删除 MessageDigest("MD5"/"SHA-1")、md5()、sha1() 调用；旧数据用「登录时重新哈希」迁移，不要继续存弱哈希。',
  'B-02': '令牌短期有效（如 15 分钟）+ 刷新令牌；服务端维护撤销列表或 token 版本号，登出/改密后旧令牌立即失效。',
  'B-03': '对登录/验证码接口加限速与渐进锁定（同一账号/IP 失败 N 次后延迟或锁定），补一条触发阈值的测试。',
  'B-04': '把 URL、日志、崩溃上报、埋点里的 token/password/secret 清掉，改为只记录脱敏 ID。',
  'B-06': '认证与授权分开：登录成功只代表「你是谁」；每个受保护资源仍要在服务端判断「你能不能做」，补「仅登录访问受保护资源被拒」用例。',
  'B-07': '删除代码/资源/构建产物里的密钥；Android 用 Android Keystore，服务端用 KMS/环境变量注入；密钥加载路径只保留一条。',
  'C-01': '服务端逐请求校验权限，客户端判断只做体验优化；用「绕过客户端直接调接口」用例证明会被拒绝。',
  'C-02': '授权判断改成「主体 + 资源 + 动作」三元组，不要只判断角色名；补「同角色对不同资源结果不同」用例。',
  'C-03': '按资源 ID 查询时校验归属（WHERE owner_id = 当前用户），替换他人 ID 应返回 403/404；列表同样处理。',
  'C-04': '批量/列表接口逐条校验归属与权限，不要只看第一个元素；混入一条越权数据时应整批拒绝或剔除该条。',
  'C-06': '管理接口与业务接口分开鉴权；普通用户令牌调用管理接口必须被拒绝。',
  'D-01': '删除自研加解密/自研协议，改用标准库（JCA、OpenSSL、Node crypto、libsodium）；算法选标准套件。',
  'D-02': '传输改 TLS 1.2+：清掉 http:// 地址与 cleartext 放行；Android 配 network_security_config 并启用证书绑定；删除 TrustAllCerts/ALLOW_ALL_HOSTNAME_VERIFIER。',
  'D-03': '静态敏感数据加密存储（AES-GCM / EncryptedSharedPreferences / SQLCipher），密钥与密文分开存（Keystore/KMS）。',
  'D-04': '密钥不进代码、资源文件、构建产物；从 Keystore / KMS / 环境注入；产物扫描确认无密钥。',
  'D-05': '加密用 GCM 等带认证模式，IV 每次随机且不可预测；删除 ECB、固定 IV、安全场景里的 Math.random，改 SecureRandom / crypto.randomBytes。',
  'D-06': '密码学操作失败必须关闭：校验/解密失败直接拒绝并记录，不得降级为明文或跳过；补一条注入失败用例。',
  'E-01': '输入校验改允许列表（格式/长度/枚举），不要黑名单；补边界与恶意样本用例。',
  'E-02': '按输出上下文编码：HTML 用转义、JSON 序列化、SQL 参数化、Shell 参数数组，不要一个通用转义走天下。',
  'E-03': '数据库访问全部参数化：PreparedStatement / 占位符 / ORM 参数绑定；删除字符串拼接 SQL（包括 ORDER BY、LIKE 的拼接）。',
  'E-04': '外部命令参数化或白名单：用数组传参（ProcessBuilder/execFile/spawn 数组），禁止拼 shell 字符串。',
  'E-05': '反序列化限制类型白名单，不反序列化不可信来源；配置白名单并补「非白名单类型失败」用例。',
  'E-06': '金额、数量、状态流转、优惠计算的最终校验放服务端；篡改客户端提交值应被拒绝或纠正。',
  'E-07': '上传校验类型、大小与真实内容（magic number），存储路径与执行路径分离，上传目录不可执行。',
  'E-08': 'WebView 去掉不必要的 addJavascriptInterface，接口最小白名单；关闭 setAllowFileAccess/FileAccessFromFileURLs/UniversalAccessFromFileURLs。',
  'F-01': '提交锁文件（package-lock.json / pnpm-lock.yaml / gradle.lockfile 等），依赖写死版本，不用浮动范围。',
  'F-02': 'CI 加依赖漏洞扫描（npm audit / OWASP Dependency-Check / Trivy），高危失败即阻断。',
  'F-03': '发布产物签名，并在构建后与发布前分别核对签名/哈希一致。',
  'F-04': '每次发布生成并归档 SBOM（SPDX 或 CycloneDX），放进发布目录可检索。',
  'F-06': '客户端开启 R8/ProGuard 混淆与压缩（minifyEnabled true + shrinkResources true），保留必要 keep 规则。',
  'F-07': '更新包双签名校验：manifest 与包体分别验签，签名不匹配拒绝安装并提示。',
  'F-08': '移除来源不明的二进制/预编译库；每个二进制依赖记录来源与哈希。',
  'G-01': '调试开关、测试后门、详细日志默认关闭；生产构建里确认关闭。',
  'G-02': '生产关闭调试接口与堆栈回显；请求调试端点应 404。',
  'G-03': '关掉未使用的端口、组件、接口、权限；导出的组件清单每一项都能说明用途。',
  'G-04': 'Android 组件显式 android:exported，非必要一律 false；检查 manifest 里所有 exported=true 是否必要。',
  'G-05': 'network_security_config 禁止 cleartext，域名白名单最小；删掉 cleartextTrafficPermitted/usesCleartextTraffic=true。',
  'G-07': '敏感配置不进仓库：改用环境变量/密钥管理；提交前 secret scan 拦截。',
  'H-01': '登录、授权失败、权限变更、发布操作都要留痕：记录主体、时间、动作、结果，且可检索。',
  'H-02': '日志脱敏：不记录口令、令牌、完整证件号/卡号；只记录脱敏 ID。',
  'H-03': '错误响应统一为通用信息，不返回堆栈、内部路径、SQL、依赖版本；异常细节只进服务端日志。',
  'I-01': '新功能上线前做一次 STRIDE 威胁建模（六类威胁逐条过），记录缓解措施。',
  'I-02': 'PR 模板加入安全评审清单，高风险改动有人复核。',
  'I-03': 'CI 里跑 SAST 与 secret scan，高危结果阻断合并。',
  'I-04': '安全规则变更走评审（提交历史 + 复核记录），禁止单人直接改。',
  'J-01': '让安装包自包含：package.json 的 files/exports 列出入口与资源，bundle patch、locale、icon 都随包发布；不引用开发机上的文件或软链接。',
  'J-02': '删除运行时文件里的本机绝对路径（盘符路径、/home/、/Users/），改成相对路径或环境变量；不要带本机密钥/证书。',
  'J-03': '依赖写进 package.json/pyproject 等显式声明，提交锁文件；删除 file:/link: 指向本地目录的运行时依赖，确认干净环境能还原。',
  'J-04': '在干净目录解包后验证：入口能 import、bundle patch 行与包名一致、exports/files 指向的文件都存在、locale/icon 齐全；把命令与结果记录进 dist/VERIFICATION.md。',
  'J-05': 'README 写清安装/卸载/升级步骤，版本号与 engines 兼容范围明确，附一次干净环境安装验证记录。',
}

/** 架构「怎么落地」的简短步骤。 */
const ARCH_HOWTO = {
  saltzer: '逐条对照八原则检查当前设计：最小权限、失败安全默认、机制经济性、完全仲裁、开放设计、权限分离、最小公共机制、心理可接受性。',
  'reference-monitor': '把权限判断收口到不可绕过的单一入口（网关/中间件/拦截器），业务层不允许自行判断。',
  'defense-in-depth': '给关键资产写两层独立控制，并确认两层不依赖同一机制。',
  rbac: '建立角色与权限点清单，服务端统一按「主体+资源+动作」判定，客户端只做展示。',
  'clark-wilson': '资金/账务操作走良构事务（校验→执行→记录），高风险动作加职责分离（双人/二次确认）。',
  'zero-trust': '服务端逐请求校验身份与令牌；服务间用 mTLS/短期凭证；删除「内网/白名单即可信」的授权逻辑。',
  asvs: '以 OWASP ASVS L2 为验收清单，逐项对照本会话代码，记录通过项与整改项。',
  masvs: 'Android 侧按 MASVS L2 检查：Keystore、证书绑定、exported 最小化、防截屏、备份白名单、R8。',
  sdl: '把安全检查嵌进开发流程：威胁建模、SAST/SCA/secret scan、发布门槛、事件响应。',
  stride: '对本次功能做 STRIDE 六类威胁清单，每条写缓解措施并确认代码里已实现。',
  slsa: '构建走隔离环境并生成 provenance；发布产物用平台签名，避免只在开发机本地签名。',
  sbom: '发布前生成 SBOM（SPDX/CycloneDX）并用 cosign 等对产物签名，归档可检索。',
  'portable-dist': '先修包结构与绝对路径，再在干净目录解包验证入口/资源/patch 行，结果写进 dist/VERIFICATION.md。',
}

/** 自动命中项的修复提示（按规则 why 归到对应指导）。 */
function fixForRule(ruleId) {
  return FIX_GUIDES[ruleId] || `按判定标准做到：${RULE_BY_ID.get(ruleId)?.criteria || '满足规则要求'}；然后提交可核对证据（文件路径 / 命令 / 测试结果）。`
}

function evidenceExample(rule) {
  if (rule.level === 'L3') return `可选：${rule.title} 的整改记录或说明`
  return `已完成 ${rule.id}：${rule.title}（文件：<路径>；命令/测试：<命令与结果>）`
}

/**
 * 生成结构化教学计划。
 * @param {object} state 会话状态
 * @param {object} evaluation evaluate() 结果
 * @param {object} recommendation recommendArchitectures() 结果
 */
export function buildCoachPlan(state, evaluation, recommendation) {
  const ruleResults = Array.isArray(evaluation.rules) ? evaluation.rules : []
  const failed = ruleResults.filter((rule) => rule.status === 'violation')
  const missing = ruleResults.filter((rule) => rule.status === 'unverified' && rule.level !== 'L3')
  const conflicts = (evaluation.conflicts || []).filter((item) => !item.acknowledged)
  const distFindings = state.distribution && state.distribution.ok === false ? state.distribution.findings || [] : []
  const architectures = (recommendation.architectures || []).filter((arch) => arch.mandatory)

  const steps = []
  for (const rule of failed.slice(0, 10)) {
    steps.push({
      kind: 'fix',
      rule: rule.id,
      level: rule.level,
      title: rule.title,
      why: '自动检查命中违规',
      findings: (rule.findings || []).slice(0, 3),
      howTo: fixForRule(rule.id),
      evidence: evidenceExample(rule),
    })
  }
  for (const rule of missing.slice(0, 12)) {
    const meta = RULE_BY_ID.get(rule.id)
    steps.push({
      kind: 'attest',
      rule: rule.id,
      level: rule.level,
      title: rule.title,
      why: '需要按判定标准落实并提交证据',
      findings: [],
      howTo: fixForRule(rule.id),
      evidence: evidenceExample(meta || rule),
    })
  }

  const architectureSteps = architectures.slice(0, 8).map((arch) => ({
    id: arch.id,
    name: arch.name,
    layerName: arch.layerName,
    howTo: ARCH_HOWTO[arch.id] || `${arch.purpose}。落地时对照「何时需要」：${arch.when}`,
  }))

  const conflictSteps = conflicts.slice(0, 6).map((item) => ({
    id: item.id,
    title: item.title,
    severity: item.severity,
    resolution: item.resolution,
    howTo: '按处理建议确定唯一主模型/边界，然后调用 security_judge action=conflict-ack 登记结论。',
  }))

  const distributionSteps = distFindings.slice(0, 8).map((item) => ({
    file: item.file || '安装包',
    why: item.why,
    howTo: fixForRule('J-04'),
  }))

  const submitExample = {
    architectures: architectures.map((arch) => arch.id),
    rules: Object.fromEntries(
      [...failed, ...missing].slice(0, 6).map((rule) => [rule.id, { verdict: 'pass', evidence: `<${rule.id} 的具体证据>` }]),
    ),
    notes: '可选：说明本次修复与遗留问题',
  }

  return {
    sessionId: state.id,
    title: state.title,
    summary: `已连续 ${state.review.redoCount || 0} 次不合格。先修 ${failed.length} 项自动命中，再为 ${missing.length} 条规则补证据；补 ${architectures.length} 个核心架构；处理 ${conflicts.length} 项架构冲突。`,
    fixSteps: steps.filter((step) => step.kind === 'fix'),
    attestSteps: steps.filter((step) => step.kind === 'attest'),
    architectureSteps,
    conflictSteps,
    distributionSteps,
    submitExample,
    nextActions: [
      '1) 先修自动命中项（这些是硬违规，改完代码再重跑评审）。',
      '2) 对「需要证据」的规则按判定标准落实，并把证据写进 action=submit 的 rules。',
      '3) 按教学步骤补齐核心架构；架构冲突先登记处理结论。',
      '4) 安装包项目先修分发自检问题（J 组），再在干净目录验证一次。',
      '5) action=submit 提交，直到 verdict=pass（合格）；不合格继续按本教学单重做。',
    ],
  }
}

/** 把教学计划渲染成中文文本（注入会话 / 工具输出用）。 */
export function renderCoachText(plan, { maxChars = 4200 } = {}) {
  const lines = ['【代码安全防御评审判官·教学】连续不合格，下面按顺序带你改：', plan.summary, '']
  if (plan.fixSteps.length) {
    lines.push('一、先修自动命中的硬违规（必须改代码）')
    plan.fixSteps.forEach((step, index) => {
      lines.push(`${index + 1}. ${step.rule}（${step.level}）${step.title}`)
      lines.push(`   怎么改：${step.howTo}`)
      if (step.findings.length) {
        lines.push(`   命中：${step.findings.map((item) => `${item.file || ''}${item.line ? `:${item.line}` : ''} ${item.snippet || ''}`).join('；')}`)
      }
      lines.push(`   交证据：${step.evidence}`)
    })
    lines.push('')
  }
  if (plan.attestSteps.length) {
    lines.push('二、需要落实并提交证据的规则（按判定标准做）')
    plan.attestSteps.forEach((step, index) => {
      lines.push(`${index + 1}. ${step.rule}（${step.level}）${step.title}`)
      lines.push(`   怎么改：${step.howTo}`)
      lines.push(`   交证据：${step.evidence}`)
    })
    lines.push('')
  }
  if (plan.architectureSteps.length) {
    lines.push('三、需要补齐的核心代码安全防御架构')
    plan.architectureSteps.forEach((step) => {
      lines.push(`- ${step.name}（${step.layerName}）：${step.howTo}`)
    })
    lines.push('')
  }
  if (plan.conflictSteps.length) {
    lines.push('四、架构冲突（先登记处理结论）')
    plan.conflictSteps.forEach((step) => {
      lines.push(`- ${step.title}（${step.severity}）：${step.resolution}`)
    })
    lines.push('')
  }
  if (plan.distributionSteps.length) {
    lines.push('五、分发自检问题（安装包发给别人也能装）')
    plan.distributionSteps.forEach((step) => {
      lines.push(`- ${step.file}：${step.why}`)
    })
    lines.push('')
  }
  lines.push('六、提交格式（照抄填）')
  lines.push(JSON.stringify(plan.submitExample, null, 2))
  lines.push('')
  lines.push('七、下一步')
  for (const action of plan.nextActions) lines.push(action)
  let text = lines.join('\n')
  if (text.length > maxChars) text = `${text.slice(0, maxChars)}\n…（教学单过长已截断，可调用 security_judge action=coach 查看完整计划）`
  return text
}

export default { buildCoachPlan, renderCoachText }
