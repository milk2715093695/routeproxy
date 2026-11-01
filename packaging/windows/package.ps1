param(
    [Parameter(Mandatory)]
    [string]$Binary,

    [string]$Version = ""
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

if ([string]::IsNullOrWhiteSpace($Version)) {
    $Version = (Get-Content (Join-Path $Root "VERSION") -Raw).Trim()
}
if ([string]::IsNullOrWhiteSpace($Version)) {
    throw "routeproxy VERSION 为空"
}
if (-not (Test-Path $Binary -PathType Leaf)) {
    throw "找不到 Windows 二进制：$Binary"
}

$VersionOutput = (& $Binary version 2>$null | Select-Object -First 1)
$BinaryVersion = $VersionOutput -split ' ' | Select-Object -Index 1
if ($BinaryVersion -ne $Version) {
    throw "routeproxy 二进制版本不匹配：期望 $Version，实际 $BinaryVersion"
}
if ($VersionOutput -match '@unknown' -or $VersionOutput -match 'dirty') {
    throw "拒绝打包不可复现的 Windows 二进制：$VersionOutput"
}
$BuildIdMatch = [regex]::Match($VersionOutput, 'routeproxy-build-id:([^|]+)\|')
if (-not $BuildIdMatch.Success) {
    throw "Windows 二进制缺少 build id：$VersionOutput"
}
$BuildId = $BuildIdMatch.Groups[1].Value
$At = $BuildId.IndexOf('@')
if ($At -lt 1 -or $At -eq $BuildId.Length - 1) {
    throw "Windows 二进制 build id 格式无效：$BuildId"
}
$BinaryCommit = $BuildId.Substring($At + 1)
$GitHead = (& git -C $Root rev-parse --short=12 HEAD 2>$null)
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($GitHead)) {
    throw "无法读取 git HEAD，拒绝打包"
}
if ($BinaryCommit -ne $GitHead.Trim()) {
    throw "Windows 二进制提交与 HEAD 不一致：$BinaryCommit != $GitHead"
}
$Dirty = (& git -C $Root status --porcelain 2>$null)
if ($LASTEXITCODE -ne 0 -or $Dirty) {
    throw "工作区不干净，拒绝打包 Windows"
}
$BinaryText = [System.Text.Encoding]::ASCII.GetString(
    [System.IO.File]::ReadAllBytes((Resolve-Path $Binary))
)
if ($BinaryText.Contains('/Users/') -or $BinaryText.Contains('/home/') -or
    $BinaryText.Contains('/data/data/com.termux/') -or
    $BinaryText.Contains('C:\Users\') -or $BinaryText.Contains('D:\a\')) {
    throw "Windows 二进制包含本地路径，请用 RUSTFLAGS=--remap-path-prefix 重新构建"
}

$Rules = Join-Path $Root "rules.toml"
if (-not (Test-Path $Rules -PathType Leaf)) {
    throw "找不到 rules.toml：$Rules"
}
$Config = Join-Path $Root "config.toml.example"
if (-not (Test-Path $Config -PathType Leaf)) {
    throw "找不到 config.toml.example：$Config"
}
$License = Join-Path $Root "LICENSE"
$LicenseData = Join-Path $Root "LICENSE-DATA"
$Notice = Join-Path $Root "NOTICE"
$ThirdParty = Join-Path $Root "THIRD_PARTY_NOTICES.md"
foreach ($file in @($License, $LicenseData, $Notice, $ThirdParty)) {
    if (-not (Test-Path $file -PathType Leaf)) {
        throw "找不到许可文件：$file"
    }
}
& cargo run --quiet --manifest-path (Join-Path $Root "Cargo.toml") -- rules check --file $Rules
if ($LASTEXITCODE -ne 0) {
    throw "rules check 失败：$Rules"
}
$Dist = Join-Path $Root "dist"
New-Item -ItemType Directory -Force -Path $Dist | Out-Null
$Asset = Join-Path $Dist "routeproxy-$Version-windows-x86_64.zip"
if (Test-Path $Asset) {
    Remove-Item -LiteralPath $Asset -Force
}

Compress-Archive -Path @($Binary, $Rules, $Config, $License, $LicenseData, $Notice, $ThirdParty) -DestinationPath $Asset -CompressionLevel Optimal
$Hash = (Get-FileHash -LiteralPath $Asset -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Output "$Hash  routeproxy-$Version-windows-x86_64.zip"
