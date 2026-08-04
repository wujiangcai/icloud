param(
    [int]$IntervalMinutes = 30,
    [switch]$RunInitial
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = Join-Path $root "hidemyemail-generator\.venv\Scripts\python.exe"
$script = Join-Path $root "schedule_generate.py"
$taskName = "iCloud Hide My Email - 30min"

if (-not (Test-Path -LiteralPath $python)) {
    throw "Python runtime not found: $python"
}
if (-not (Test-Path -LiteralPath $script)) {
    throw "Scheduler script not found: $script"
}
if ($IntervalMinutes -lt 1) {
    throw "IntervalMinutes must be at least 1"
}

$start = (Get-Date).AddMinutes($IntervalMinutes)
$action = New-ScheduledTaskAction `
    -Execute $python `
    -Argument "`"$script`" --scheduled" `
    -WorkingDirectory $root
$trigger = New-ScheduledTaskTrigger `
    -Once `
    -At $start `
    -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes) `
    -RepetitionDuration (New-TimeSpan -Days 3650)
$settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Minutes ([Math]::Max(1, $IntervalMinutes - 3)))
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
    -Description "Create 4 Hide My Email aliases on the first run, then 5 every 30 minutes." `
    -Force | Out-Null

Write-Host ("Task registered: " + $taskName)
$startText = $start.ToString("yyyy-MM-dd HH:mm:ss")
Write-Host ("First automatic run: " + $startText)
Write-Host "First batch: 4; later batches: 5; log: icloud-code-api\data\hme_schedule.log"

if ($RunInitial) {
    $statePath = Join-Path $root "icloud-code-api\data\hme_schedule_state.json"
    $completedRuns = 0
    if (Test-Path -LiteralPath $statePath) {
        try {
            $savedState = Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json
            $completedRuns = [int]$savedState.completed_runs
        } catch {
            $completedRuns = 0
        }
    }
    if ($completedRuns -eq 0) {
        Write-Host "Running the initial batch of 4 aliases..."
        & $python $script --count 4
        if ($LASTEXITCODE -ne 0) {
            throw "Initial batch failed with exit code $LASTEXITCODE. See icloud-code-api\data\hme_schedule.log"
        }
    } else {
        Write-Host "The initial batch was already completed; no immediate run was started."
    }
}
