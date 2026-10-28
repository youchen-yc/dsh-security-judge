/**
 * 生成本插件发布证据：CycloneDX SBOM + Ed25519 签名 + 验签。
 *
 * 用法（对已打包的 tarball 与解包目录）：
 *   node scripts/make-release-evidence.mjs <解包目录> <tarball> <输出目录>
 *
 * 签名私钥默认保存在 ~/.dsh/security-judge-release.key（0600，不进包、不进仓库）。
 */

import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'
import crypto from 'node:crypto'

const [, , pkgDir, tarball, outDirArg] = process.argv
if (!pkgDir || !tarball) {
  console.error('用法: node scripts/make-release-evidence.mjs <解包目录> <tarball> [输出目录]')
  process.exit(2)
}
const outDir = outDirArg || path.join(process.cwd(), 'dist')
fs.mkdirSync(outDir, { recursive: true })

function walk(dir, base = dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) walk(full, base, out)
    else if (entry.isFile()) out.push(path.relative(base, full))
  }
  return out
}

const pkg = JSON.parse(fs.readFileSync(path.join(pkgDir, 'package.json'), 'utf8'))
const files = walk(pkgDir).sort()
const components = files.map((file) => {
  const data = fs.readFileSync(path.join(pkgDir, file))
  return {
    type: 'file',
    name: file.replace(/\\/g, '/'),
    hashes: [{ alg: 'SHA-256', content: crypto.createHash('sha256').update(data).digest('hex') }],
  }
})
const tarballBytes = fs.readFileSync(tarball)
const tarballHash = crypto.createHash('sha256').update(tarballBytes).digest('hex')
const sbom = {
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  serialNumber: `urn:uuid:${crypto.randomUUID()}`,
  version: 1,
  metadata: {
    timestamp: new Date().toISOString(),
    tools: [{ vendor: 'dsh-security-judge', name: 'make-release-evidence', version: '1.0.0' }],
    component: { type: 'application', name: pkg.name, version: pkg.version },
    properties: [
      { name: 'release:tarball', value: path.basename(tarball) },
      { name: 'release:tarball-sha256', value: tarballHash },
      { name: 'release:dependency-count', value: String(Object.keys(pkg.dependencies || {}).length) },
    ],
  },
  components,
}
const sbomPath = path.join(outDir, 'SBOM.cdx.json')
fs.writeFileSync(sbomPath, JSON.stringify(sbom, null, 2), 'utf8')

// Ed25519 签名：私钥留在用户目录，发布公钥与签名。
const keyDir = path.join(os.homedir(), '.dsh')
fs.mkdirSync(keyDir, { recursive: true })
const keyPath = path.join(keyDir, 'security-judge-release.key')
let privateKey
if (fs.existsSync(keyPath)) {
  privateKey = crypto.createPrivateKey({ key: fs.readFileSync(keyPath, 'utf8'), format: 'pem' })
} else {
  const pair = crypto.generateKeyPairSync('ed25519')
  privateKey = pair.privateKey
  fs.writeFileSync(keyPath, pair.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 })
  fs.writeFileSync(path.join(outDir, 'release-signing.pub.pem'), pair.publicKey.export({ type: 'spki', format: 'pem' }), 'utf8')
}
const publicKey = crypto.createPublicKey(privateKey)
const sig = crypto.sign(null, tarballBytes, privateKey)
const sigPath = path.join(outDir, `${path.basename(tarball)}.sig`)
fs.writeFileSync(sigPath, `${sig.toString('base64')}\n`, 'utf8')
const verified = crypto.verify(null, tarballBytes, publicKey, sig)
fs.writeFileSync(path.join(outDir, 'release-signing.pub.pem'), publicKey.export({ type: 'spki', format: 'pem' }), 'utf8')

console.log(JSON.stringify({
  package: `${pkg.name}@${pkg.version}`,
  files: components.length,
  sbom: sbomPath,
  tarball: path.basename(tarball),
  tarballSha256: tarballHash,
  signature: sigPath,
  publicKey: path.join(outDir, 'release-signing.pub.pem'),
  verified,
  privateKeyPath: keyPath,
}, null, 2))
if (!verified) process.exit(1)
