<#
.SYNOPSIS
    在本地开发机上启动 cproxy agent，把开发站点经公网服务器暴露给测试人员。

.DESCRIPTION
    生成 agent 配置（保存在 %LOCALAPPDATA%\cproxy\agent.json），然后以前台方式运行 agent。
    按 Ctrl+C 结束，测试人员随即无法访问，本地开发环境不受影响。

.EXAMPLE
    .\scripts\dev-share.ps1 -Server 203.0.113.10:8080 `
        -Token 'REPLACE_WITH_TOKEN' `
        -Fingerprint 'sha256:REPLACE_WITH_FINGERPRINT'

.EXAMPLE
    # 共享另一个本地端口，路径前缀改为 /higobase-admin-v2
    .\scripts\dev-share.ps1 -Server 203.0.113.10:8080 -Token $t -Fingerprint $fp `
        -Target 127.0.0.1:5175 -PathPrefix /higobase-admin-v2 -Name higobase-dev2
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Server,
    [Parameter(Mandatory = $true)][string]$Token,
    [Parameter(Mandatory = $true)][string]$Fingerprint,
    [string]$Target = '127.0.0.1:5174',
    [string]$PathPrefix = '/higobase-admin',
    [string]$AgentID = $env:COMPUTERNAME,
    [string]$Name = 'higobase-dev',
    [string]$UIListen = '127.0.0.1:7100',
    [string]$Binary = (Join-Path (Split-Path -Parent $PSScriptRoot) 'bin\cproxy.exe'),
    [string]$ConfigDir = (Join-Path $env:LOCALAPPDATA 'cproxy')
)

$ErrorActionPreference = 'Stop'

if ($Token.Length -lt 16) { throw 'token 至少需要 16 个字符' }
if ($Fingerprint -notmatch '^sha256:[0-9a-fA-F]{64}$') { throw 'fingerprint 形如 sha256:<64 位十六进制>' }
if ($PathPrefix -notmatch '^/') { throw 'PathPrefix 必须以 / 开头' }
if (-not (Test-Path $Binary)) { throw "找不到 $Binary，先在仓库根目录执行：go run build.go -targets=windows" }

$hostPort = $Server
$parts = $Server.Split(':')
if ($parts.Count -ne 2) { throw 'Server 需为 host:port，例如 203.0.113.10:8080' }

New-Item -ItemType Directory -Force -Path $ConfigDir | Out-Null
$configPath = Join-Path $ConfigDir 'agent.json'

$config = [ordered]@{
    server     = $hostPort
    agent_id   = $AgentID
    token      = $Token
    ui_listen  = $UIListen
    tunnel_tls = [ordered]@{ fingerprint = $Fingerprint }
    services   = @([ordered]@{
            name         = $Name
            path_prefix  = $PathPrefix
            target       = $Target
            strip_prefix = $false
        })
    log_level  = 'info'
    log_format = 'text'
}
$config | ConvertTo-Json -Depth 6 | Set-Content -Path $configPath -Encoding utf8

$publicURL = "http://$Server$PathPrefix/"
Write-Host "配置已写入: $configPath"
Write-Host "本地目标  : $Target"
Write-Host "本地管理页: http://$UIListen/   （可在线改路由，保存即生效）"
Write-Host "测试人员访问: $publicURL"
Write-Host ''

& $Binary check -f $configPath
& $Binary agent -f $configPath