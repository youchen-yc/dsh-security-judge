/**
 * 分发包自检（lib/dist.js）测试：
 *   node test/dist-test.mjs
 */

import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

import { inspectPackage, locatePackageDir } from '../lib/dist.js'

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

const tempDirs = []
function makePackage(overrides = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sj-dist-'))
  tempDirs.push(dir)
  const pkg = {
    name: 'demo-portable-pkg',
    version: '1.2.3',
    type: 'module',
    exports: {
      '.': './index.js',
      './client': './client.js',
      './locale/*.json': './locale/*.json',
      './icon': './icon.svg',
    },
    files: ['index.js', 'client.js', 'lib/*.js', 'locale/*.json', 'icon.svg', 'cordis.patch.yml', 'README.md', 'CHANGELOG.md', 'LICENSE'],
    dsh: { bundle: { patch: './cordis.patch.yml' }, client: { platform: 'web', immediately: true } },
    ...overrides.pkg,
  }
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify(pkg, null, 2), 'utf8')
  fs.writeFileSync(path.join(dir, 'index.js'), 'export function apply() {}\n', 'utf8')
  fs.writeFileSync(path.join(dir, 'client.js'), 'window.__ModuleLoader__.load({ id: "demo-portable-pkg", factory() { return { apply() {} } } })\n', 'utf8')
  fs.mkdirSync(path.join(dir, 'lib'), { recursive: true })
  fs.writeFileSync(path.join(dir, 'lib', 'core.js'), 'export const ok = true\n', 'utf8')
  fs.mkdirSync(path.join(dir, 'locale'), { recursive: true })
  fs.writeFileSync(path.join(dir, 'locale', 'zh.json'), '{"meta":{"title":"演示"}}', 'utf8')
  fs.writeFileSync(path.join(dir, 'locale', 'en.json'), '{"meta":{"title":"Demo"}}', 'utf8')
  fs.writeFileSync(path.join(dir, 'icon.svg'), '<svg xmlns="http://www.w3.org/2000/svg"></svg>', 'utf8')
  fs.writeFileSync(path.join(dir, 'cordis.patch.yml'), '- insert:\n    - id: demo-portable-pkg\n      name: demo-portable-pkg\n      config: {}\n', 'utf8')
  fs.writeFileSync(path.join(dir, 'README.md'), '# Demo\n\n安装：npm i\n', 'utf8')
  fs.writeFileSync(path.join(dir, 'CHANGELOG.md'), '# CHANGELOG\n', 'utf8')
  fs.writeFileSync(path.join(dir, 'LICENSE'), 'MIT\n', 'utf8')
  for (const [name, content] of Object.entries(overrides.files || {})) {
    fs.writeFileSync(path.join(dir, name), content, 'utf8')
  }
  for (const name of overrides.remove || []) {
    fs.rmSync(path.join(dir, name), { force: true })
  }
  return dir
}

function cleanup() {
  for (const dir of tempDirs) {
    try {
      fs.rmSync(dir, { recursive: true, force: true })
    } catch {
      // ignore
    }
  }
}

// ---------------------------------------------------------------------------
// 1. 完整包：通过
// ---------------------------------------------------------------------------
{
  const dir = makePackage()
  const result = await inspectPackage(dir)
  eq(result.ok, true, '完整自包含安装包通过自检')
  eq(result.package.name, 'demo-portable-pkg', '自检返回包名')
  eq(result.findings.length, 0, '完整包没有发现问题')
  ok(result.runtimeFiles.includes('index.js'), '自检覆盖入口文件')

  const located = await locatePackageDir('/nonexistent', [path.join(dir, 'index.js')])
  eq(located, dir, '能从改动文件定位包目录')
}

// ---------------------------------------------------------------------------
// 2. 缺 bundle patch / 入口 / 图标 / 语言资源
// ---------------------------------------------------------------------------
{
  const dir = makePackage({ remove: ['cordis.patch.yml'] })
  const result = await inspectPackage(dir)
  eq(result.ok, false, '缺 bundle patch 时不通过')
  ok(result.findings.some((item) => item.file === 'cordis.patch.yml'), '指出缺 bundle patch')

  const dir2 = makePackage({ remove: ['client.js'] })
  const result2 = await inspectPackage(dir2)
  ok(result2.findings.some((item) => item.file === 'client.js'), '指出缺客户端入口')

  const dir3 = makePackage({ remove: ['icon.svg'] })
  const result3 = await inspectPackage(dir3)
  ok(result3.findings.some((item) => item.file === 'icon.svg'), '指出缺图标')

  const dir4 = makePackage()
  fs.rmSync(path.join(dir4, 'locale'), { recursive: true, force: true })
  const result4 = await inspectPackage(dir4)
  ok(result4.findings.some((item) => item.file === 'locale'), '指出缺语言资源')
}

// ---------------------------------------------------------------------------
// 3. 本机绝对路径 / 本地依赖 / 安装脚本
// ---------------------------------------------------------------------------
{
  const dir = makePackage({ files: { 'index.js': 'const p = "F:\\\\DSH1.0\\\\secret"\n' } })
  const result = await inspectPackage(dir)
  eq(result.ok, false, '运行时硬编码本机绝对路径不通过')
  ok(result.findings.some((item) => item.why.includes('绝对路径')), '指出硬编码绝对路径')

  const dir2 = makePackage({
    pkg: { dependencies: { 'local-lib': 'file:../local-lib' } },
  })
  const result2 = await inspectPackage(dir2)
  ok(result2.findings.some((item) => item.why.includes('本地目录')), '指出 file: 本地依赖')

  const dir3 = makePackage({ pkg: { scripts: { postinstall: 'node C:\\tools\\fix.js' } } })
  const result3 = await inspectPackage(dir3)
  ok(result3.findings.some((item) => item.why.includes('安装脚本')), '指出依赖开发机路径的安装脚本')
}

// ---------------------------------------------------------------------------
// 4. bundle patch 行与包名对不上
// ---------------------------------------------------------------------------
{
  const dir = makePackage({
    files: { 'cordis.patch.yml': '- insert:\n    - id: another-row\n      name: another-pkg\n      config: {}\n' },
  })
  const result = await inspectPackage(dir)
  eq(result.ok, false, 'patch 行与包名不一致不通过')
  ok(result.findings.some((item) => item.why.includes('包名')), '指出 patch 行包名不一致')
}

// ---------------------------------------------------------------------------
// 汇总
// ---------------------------------------------------------------------------
cleanup()
console.log(`\n分发自检：通过 ${passed} 项，失败 ${failed} 项`)
if (failed) {
  console.error('失败项：')
  for (const item of failures) console.error(`- ${item}`)
  process.exit(1)
}
console.log('全部通过')
