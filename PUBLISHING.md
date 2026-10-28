# 发布记录与操作手册（PUBLISHING）

> 更新：2026-10-29。已发布/待发布状态如实记录，未完成的写明缺失的凭据或规则门槛。

## 状态总览

| 渠道 | 状态 | 说明 |
| --- | --- | --- |
| GitHub 仓库 | ✅ 已发布 | https://github.com/youchen-yc/dsh-security-judge （最新 tag `v1.6.0`；`v1.5.3` 保留） |
| GitHub Release | ✅ 已发布 | https://github.com/youchen-yc/dsh-security-judge/releases/tag/v1.6.0 （tgz / sig / SBOM / VERIFICATION） |
| Gitee 镜像 | ✅ 已发布 | https://gitee.com/youchen-yc/dsh-security-judge （main + `v1.6.0` tag；代码镜像，发行版资产未上传） |
| npm | ⏳ 待新 token | https://www.npmjs.com/package/dsh-security-judge 最新仍为 `1.5.3`；`1.6.0` 发布时 token 返回 401（已失效/撤销），需 `npm login` 或新 token |
| 插件市场 | ⏳ 待满 1 天 | 条目文件已备好；awesome-dsh-plugin 要求目标仓库创建满 1 天才收 PR |

## npm

```sh
cd F:\DSH1.0\security-judge
npm login                    # 或用 NPM_TOKEN 环境变量
npm publish --access public  # 包名 dsh-security-judge
```

发布前已 `npm publish --dry-run` 通过（20 个文件，约 102.6 kB），`prepublishOnly` 无脚本。

## Gitee

1. 在 Gitee 创建空仓库 `youchen-yc/dsh-security-judge`（不要初始化 README）。
2. 运行：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\publish-gitee.ps1
```

脚本用 `~/.ssh/gitee_ed25519` 把 `main` 与 tags 推送到 `git@gitee.com:youchen-yc/dsh-security-judge.git`。

## 插件市场（awesome-dsh-plugin）

条目文件在 `market/youchen-yc__dsh-security-judge.yml`，格式符合 `data/plugins/<owner>__<repo>.yml`。
目标仓库需创建满 1 天后提交 PR：

```sh
# 在 awesome-dsh-plugin 仓库
cp market/youchen-yc__dsh-security-judge.yml data/plugins/youchen-yc__dsh-security-judge.yml
git checkout -b add-security-judge
git add data/plugins/youchen-yc__dsh-security-judge.yml
git commit -m "add youchen-yc/dsh-security-judge"
git push origin add-security-judge
gh pr create --title "add youchen-yc/dsh-security-judge" --body "Code security defense review judge for DSH."
```

## 产物校验

- tarball：`dist/dsh-security-judge-1.5.3.tgz`（102,561 字节）
- SHA-256：`a4f4e4d73e5da1d3d3a75f63860a93dd3163ddca4a93bca72dd6ae9efea1449b`
- 签名：`dist/dsh-security-judge-1.5.3.tgz.sig`（Ed25519）
- 公钥：`dist/release-signing.pub.pem`
- SBOM：`dist/SBOM.cdx.json`
