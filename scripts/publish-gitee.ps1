# 把本仓库 main + tags 推送到 Gitee 镜像（需先在 Gitee 建空仓库）
$ErrorActionPreference = 'Stop'
$key = Join-Path $env:USERPROFILE '.ssh\gitee_ed25519'
if (-not (Test-Path $key)) { throw "找不到 Gitee SSH 私钥：$key" }
$env:GIT_SSH_COMMAND = "ssh -o BatchMode=yes -i `"$key`""
Push-Location (Split-Path $PSScriptRoot -Parent)
try {
  git remote remove gitee 2>$null
  git remote add gitee 'git@gitee.com:youchen-yc/dsh-security-judge.git'
  git push gitee main --tags
  Write-Host 'Gitee 推送完成：https://gitee.com/youchen-yc/dsh-security-judge'
} finally {
  Pop-Location
}
