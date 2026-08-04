param(
    [int]$IntervalSeconds = 300,
    [switch]$RunNow
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = Join-Path $root "hidemyemail-generator\.venv\Scripts\python.exe"
$script = Join-Path $root "hidemyemail-generator\refresh_cookie.py"
$taskName = "iCloud Hide My Email - Browser Session"

if (-not (Test-Path -LiteralPath $python)) {
    throw "Python runtime not found: $python"
}
if (-not (Test-Path -LiteralPath $script)) {
    throw "Cookie refresh script not found: $script"
}
if ($IntervalSeconds -lt 15) {
    throw "IntervalSeconds must be at least 15"
}

$action = New-ScheduledTaskAction `
    -Execute $python `
    -Argument "`"$script`" --headed --keep-alive --interval-seconds $IntervalSeconds" `
    -WorkingDirectory $root
$trigger = New-ScheduledTaskTrigger `
    -AtLogOn `
    -User "$env:USERDOMAIN\$env:USERNAME"
$settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -MultipleInstances IgnoreNew `
    -RestartCount 10 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit (New-TimeSpan -Days 3650)
$principal = New-ScheduledTaskPrincipal `
    -UserId "$env:USERDOMAIN\$env:USERNAME" `
    -LogonType Interactive `
    -RunLevel Limited

Register-ScheduledTask `
    -TaskName $taskName `
    -Action $action `
    -Trigger $trigger `
    -Settings $settings `
    -Principal $principal `
    -Description "Keep the isolated iCloud browser session alive and refresh cookie.txt." `
    -Force | Out-Null

Write-Host ("Task registered: " + $taskName)
Write-Host ("Profile: " + (Join-Path $root "hidemyemail-generator\data\browser-profile-independent"))
Write-Host ("Cookie refresh interval: " + $IntervalSeconds + " seconds")
Write-Host ("Session status: " + (Join-Path $root "hidemyemail-generator\data\browser-session-status.json"))
Write-Host ("Session log: " + (Join-Path $root "hidemyemail-generator\data\browser-session.log"))

if ($RunNow) {
    Start-ScheduledTask -TaskName $taskName
    Write-Host "Browser session task started. Complete iCloud login in the isolated Edge window if requested."
}
