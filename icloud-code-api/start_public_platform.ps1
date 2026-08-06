$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$EnvFile = Join-Path $Root ".env.platform"
$LogDir = Join-Path $Root "data\platform"
$TunnelDir = Join-Path $Root "data\cloudflared"
$Cloudflared = Join-Path $Root "bin\cloudflared.exe"
$TunnelConfig = Join-Path $TunnelDir "config.yml"
$TunnelIdFile = Join-Path $TunnelDir "tunnel.id"

New-Item -ItemType Directory -Force -Path $LogDir, $TunnelDir | Out-Null

# ConvertFrom-StringData must receive the whole file at once; piping each line
# would create one hashtable per line and silently drop the environment.
$Settings = ConvertFrom-StringData (Get-Content -LiteralPath $EnvFile -Raw)
foreach ($Key in $Settings.Keys) {
    Set-Item -Path ("Env:" + $Key) -Value ([string]$Settings[$Key])
}

$Python = Join-Path $env:LOCALAPPDATA "Programs\Python\Python312\python.exe"
if (-not (Test-Path -LiteralPath $Python)) {
    $Python = (Get-Command python.exe -ErrorAction Stop).Source
}

function Start-IfMissing {
    param(
        [string]$ProcessName,
        [string]$CommandPattern,
        [string]$FilePath,
        [string[]]$ArgumentList,
        [string]$Stdout,
        [string]$Stderr
    )

    $existing = Get-CimInstance Win32_Process | Where-Object {
        $_.Name -eq $ProcessName -and $_.CommandLine -match $CommandPattern
    }
    if ($existing) {
        return
    }
    Remove-Item -LiteralPath $Stdout, $Stderr -Force -ErrorAction SilentlyContinue
    Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -WorkingDirectory $Root `
        -WindowStyle Hidden -RedirectStandardOutput $Stdout -RedirectStandardError $Stderr | Out-Null
}

Start-IfMissing `
    -ProcessName "python.exe" `
    -CommandPattern "platform_app\.py" `
    -FilePath $Python `
    -ArgumentList @("platform_app.py") `
    -Stdout (Join-Path $LogDir "platform_app.stdout.log") `
    -Stderr (Join-Path $LogDir "platform_app.stderr.log")

Start-IfMissing `
    -ProcessName "python.exe" `
    -CommandPattern "platform_worker\.py" `
    -FilePath $Python `
    -ArgumentList @("platform_worker.py") `
    -Stdout (Join-Path $LogDir "platform_worker.stdout.log") `
    -Stderr (Join-Path $LogDir "platform_worker.stderr.log")

if ((Test-Path -LiteralPath $Cloudflared) -and (Test-Path -LiteralPath $TunnelConfig) -and (Test-Path -LiteralPath $TunnelIdFile)) {
    $TunnelId = (Get-Content -LiteralPath $TunnelIdFile -Raw).Trim()
    Start-IfMissing `
        -ProcessName "cloudflared.exe" `
        -CommandPattern ([regex]::Escape($TunnelConfig)) `
        -FilePath $Cloudflared `
        -ArgumentList @("tunnel", "--config", $TunnelConfig, "run", $TunnelId) `
        -Stdout (Join-Path $TunnelDir "cloudflared.stdout.log") `
        -Stderr (Join-Path $TunnelDir "cloudflared.stderr.log")
}
