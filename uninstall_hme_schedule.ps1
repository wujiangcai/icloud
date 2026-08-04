$ErrorActionPreference = "Stop"
$taskName = "iCloud Hide My Email - 30min"
$task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($task) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    Write-Host "已删除定时任务：$taskName"
} else {
    Write-Host "未找到定时任务：$taskName"
}
