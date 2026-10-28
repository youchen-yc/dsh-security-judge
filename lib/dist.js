/**
 * 分发包自检（对应规则组 J：分发与可迁移性）。
 *
 * 目标：评审合格不只是「代码没漏洞」，还要保证**安装包发给别人也装得上、用得了**。
 * 检查都是只读的：
 *   - package.json 是否可解析、name/version/engines 是否齐全；
 *   - exports / files / dsh.bundle.patch / dsh.client / locale / icon 引用的文件是否都存在；
 *   - bundle patch 行是否引用本包名；
 *   - 运行时文件里是否有本机绝对路径、本机密钥/证书、file:/link: 本地依赖；
 *   - 依赖是否显式声明（没有 file:/link:/../ 指向开发机目录）；
 *   - 安装脚本是否会在别人机器上执行（需要说明其可移植性）。
 *
 * 这些结果写入会话的 state.distribution，由规则 J-04（以及 J-01/J-02/J-05 的自动检查）使用。
 */

import fs from 'node:fs/promises'
import path from 'node:path'

const MAX_SCAN_BYTES = 400 * 1024
const ABS_PATH_PATTERNS = [
  { re: /[A-Za-z]:\\[^\s"'`]{2,}/, why: '运行时文件里硬编码 Windows 绝对路径' },
  { re: /[A-Za-z]:\/(Users|home)\//, why: '硬编码本机用户目录绝对路径' },
  { re: /\/home\/[a-z][a-z0-9_-]{1,}/, why: '硬编码 Linux 用户目录绝对路径' },
  { re: /\/Users\/[A-Za-z][A-Za-z0-9_-]{1,}/, why: '硬编码 macOS 用户目录绝对路径' },
]

async function exists(target) {
  try {
    await fs.access(target)
    return true
  } catch {
    return false
  }
}

async function readText(file, limit = MAX_SCAN_BYTES) {
  try {
    const stat = await fs.stat(file)
    if (!stat.isFile() || stat.size > limit) return null
    return await fs.readFile(file, 'utf8')
  } catch {
    return null
  }
}

function isPatternEntry(entry) {
  return entry.includes('*') || entry.includes('?')
}

/** 在会话工作目录 / 改动过的文件里找到真正的包目录（package.json 所在目录）。 */
export async function locatePackageDir(cwd, touchedFiles = []) {
  const candidates = []
  for (const file of touchedFiles) {
    const absolute = path.isAbsolute(file) ? file : path.join(cwd || '.', file)
    candidates.push(path.dirname(absolute))
  }
  if (cwd) candidates.push(cwd)
  const seen = new Set()
  for (const dir of candidates) {
    const normalized = path.resolve(dir)
    if (seen.has(normalized)) continue
    seen.add(normalized)
    if (await exists(path.join(normalized, 'package.json'))) return normalized
  }
  return null
}

/**
 * 检查一个包目录。
 * @param {string} dir 包目录
 * @returns {Promise<{ok:boolean, findings:{file:string,why:string}[], package:{name:string,version:string}|null, checkedAt:number}>}
 */
export async function inspectPackage(dir) {
  const findings = []
  const add = (file, why) => findings.push({ file: file || '', why })
  const checkedAt = Date.now()
  if (!dir) return { ok: false, findings: [{ file: '', why: '找不到可分发包的 package.json' }], package: null, checkedAt }

  const pkgPath = path.join(dir, 'package.json')
  const pkgText = await readText(pkgPath, 2 * 1024 * 1024)
  if (pkgText === null) {
    return { ok: false, findings: [{ file: 'package.json', why: '安装包里缺少 package.json（别人无法安装）' }], package: null, checkedAt }
  }
  let pkg
  try {
    pkg = JSON.parse(pkgText)
  } catch {
    return { ok: false, findings: [{ file: 'package.json', why: 'package.json 不是合法 JSON，安装器会直接失败' }], package: null, checkedAt }
  }
  const name = typeof pkg.name === 'string' ? pkg.name : ''
  const version = typeof pkg.version === 'string' ? pkg.version : ''
  if (!name) add('package.json', '缺少 name，无法安装')
  if (!version) add('package.json', '缺少 version，无法发布/升级')

  // exports 指向的文件必须存在（通配符子路径只检查目录存在）。
  if (pkg.exports && typeof pkg.exports === 'object') {
    for (const [subpath, target] of Object.entries(pkg.exports)) {
      if (typeof target !== 'string') continue
      if (isPatternEntry(subpath) || isPatternEntry(target)) {
        const base = target.split('*')[0]
        const baseDir = path.join(dir, path.dirname(base))
        if (!(await exists(baseDir))) add(`exports ${subpath}`, 'exports 通配路径指向的目录不存在')
        continue
      }
      const file = path.join(dir, target.replace(/^\.\//, ''))
      if (!(await exists(file))) add(`exports ${subpath}`, `exports 指向的 ${target} 不存在`)
    }
  }

  // files 里写死的条目必须存在。
  if (Array.isArray(pkg.files)) {
    for (const entry of pkg.files) {
      if (typeof entry !== 'string' || isPatternEntry(entry)) continue
      const file = path.join(dir, entry)
      if (!(await exists(file))) add(`files ${entry}`, `files 里声明的 ${entry} 不存在，发布后缺文件`)
    }
  }

  // DSH 插件 bundle 声明。
  const dsh = pkg.dsh && typeof pkg.dsh === 'object' ? pkg.dsh : null
  const patchEntry = dsh && dsh.bundle && typeof dsh.bundle.patch === 'string' ? dsh.bundle.patch : ''
  if (patchEntry) {
    const patchFile = path.join(dir, patchEntry.replace(/^\.\//, ''))
    const patchText = await readText(patchFile, 256 * 1024)
    if (patchText === null) add('cordis.patch.yml', `bundle patch 文件 ${patchEntry} 不存在，别人安装后插件不会出现`)
    else if (name && !patchText.includes(name)) add('cordis.patch.yml', `bundle patch 没有引用包名 ${name}，安装后入口可能对不上`)
    else {
      for (const row of patchText.split(/\r?\n/)) {
        const match = /^[ \t]*-?[ \t]*id:[ \t]*(\S+)/.exec(row)
        if (match && !/^[a-z0-9][a-z0-9-]*$/i.test(match[1])) add('cordis.patch.yml', `patch 行 id「${match[1]}」不是合法的插件行 id`)
        const nameMatch = /^[ \t]*name:[ \t]*(\S+)/.exec(row)
        if (nameMatch && name && nameMatch[1].replace(/['"]/g, '') !== name) add('cordis.patch.yml', `patch 行 name「${nameMatch[1]}」与包名 ${name} 不一致`)
      }
    }
  }
  if (dsh && dsh.client && typeof dsh.client === 'object') {
    const clientTarget = pkg.exports && typeof pkg.exports === 'object' ? pkg.exports['./client'] : ''
    if (typeof clientTarget === 'string') {
      const clientFile = path.join(dir, clientTarget.replace(/^\.\//, ''))
      if (!(await exists(clientFile))) add('client.js', 'dsh.client 声明了客户端，但 ./client 入口文件不存在')
      else {
        const clientText = await readText(clientFile)
        if (clientText === null) add('client.js', '客户端入口文件为空或过大，浏览器加载会失败')
        else if (!clientText.includes('__ModuleLoader__')) add('client.js', '客户端入口没有注册到 __ModuleLoader__，Web 面板不会出现')
      }
    } else {
      add('package.json', 'dsh.client 声明了客户端，但 exports 里没有 "./client" 入口')
    }
  }

  // locale / icon 资源。
  if (pkg.exports && typeof pkg.exports === 'object') {
    const localeEntry = Object.keys(pkg.exports).find((key) => key.includes('locale'))
    if (localeEntry) {
      const localeDir = path.join(dir, 'locale')
      let hasLocale = false
      try {
        const entries = await fs.readdir(localeDir)
        hasLocale = entries.some((entry) => entry.endsWith('.json'))
      } catch {
        hasLocale = false
      }
      if (!hasLocale) add('locale', '声明了 locale 导出但 locale/ 下没有语言文件')
    }
    const iconEntry = pkg.exports['./icon']
    if (typeof iconEntry === 'string') {
      if (!(await exists(path.join(dir, iconEntry.replace(/^\.\//, ''))))) add('icon.svg', '声明了 ./icon 但图标文件不存在')
    }
  }

  // 依赖：必须是显式、可还原的，不能指向开发机。
  const deps = pkg.dependencies && typeof pkg.dependencies === 'object' ? pkg.dependencies : {}
  for (const [depName, spec] of Object.entries(deps)) {
    if (typeof spec !== 'string') continue
    if (/^(file:|link:|\.\.?[\\/]|\/|[A-Za-z]:[\\/])/.test(spec)) add('package.json', `依赖 ${depName} 指向本地目录（${spec}），别人机器装不上`)
  }
  for (const scriptName of ['preinstall', 'install', 'postinstall', 'prepare']) {
    const script = pkg.scripts && typeof pkg.scripts[scriptName] === 'string' ? pkg.scripts[scriptName] : ''
    if (script && /(node_modules|\.\.\\|\.\.\/|[A-Za-z]:\\)/.test(script)) add('package.json', `安装脚本 ${scriptName} 依赖开发机路径，别人安装会失败`)
  }

  // 运行时文件里的本机绝对路径。
  const runtimeFiles = []
  for (const entry of ['index.js', 'client.js', 'main.js', 'server.js']) {
    if (await exists(path.join(dir, entry))) runtimeFiles.push(path.join(dir, entry))
  }
  try {
    const libDir = path.join(dir, 'lib')
    const libEntries = await fs.readdir(libDir)
    for (const entry of libEntries) {
      if (entry.endsWith('.js')) runtimeFiles.push(path.join(libDir, entry))
    }
  } catch {
    // 没有 lib 目录也算正常
  }
  for (const file of runtimeFiles) {
    const text = await readText(file)
    if (text === null) continue
    for (const pattern of ABS_PATH_PATTERNS) {
      if (pattern.re.test(text)) {
        add(path.relative(dir, file), `${pattern.why}（别人安装后找不到这个路径）`)
        break
      }
    }
  }

  return {
    ok: findings.length === 0,
    findings,
    package: name ? { name, version } : null,
    packageDir: dir,
    runtimeFiles: runtimeFiles.map((file) => path.relative(dir, file)),
    checkedAt,
  }
}

export default { locatePackageDir, inspectPackage }
