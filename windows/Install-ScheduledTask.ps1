<#
.SYNOPSIS
    Creates a scheduled task that runs Detect-ArchiveStaging.ps1 on a recurring schedule.

.DESCRIPTION
    Must be run as Administrator.
    Registers a task that executes the detection script with elevated privileges under SYSTEM.
#>

[CmdletBinding()]
param(
    [string]$ScriptPath     = "$PSScriptRoot\Detect-ArchiveStaging.ps1",
    [int]$IntervalHours     = 1,
    [string]$TaskName       = "Ransomware-ArchiveStagingDetection",
    [string]$TaskPath       = "\"
)

# Require elevation
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

if (-not (Test-Path -LiteralPath $ScriptPath)) {
    Write-Error "Detection script not found: $ScriptPath"
    exit 1
}

$Action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$ScriptPath`""

$Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Hours $IntervalHours) `
    -RepetitionDuration ([TimeSpan]::MaxValue)

$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

$Settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RunOnlyIfNetworkAvailable `
    -MultipleInstances IgnoreNew

# Remove existing task if present
Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false -ErrorAction SilentlyContinue

Register-ScheduledTask `
    -TaskName $TaskName `
    -TaskPath $TaskPath `
    -Action $Action `
    -Trigger $Trigger `
    -Principal $Principal `
    -Settings $Settings `
    -Description "Detects suspicious archive staging (.zip/.rar/.7z) in temp and public directories and emails admin@domain.com. Part of ransomware / exfiltration detection."

Write-Host "Scheduled task created successfully:" -ForegroundColor Green
Write-Host "  Name     : $TaskName"
Write-Host "  Interval : every $IntervalHours hour(s)"
Write-Host "  Script   : $ScriptPath"
Write-Host ""
Write-Host "To verify :  Get-ScheduledTask -TaskName '$TaskName' | Get-ScheduledTaskInfo"
Write-Host "To run now:  Start-ScheduledTask -TaskName '$TaskName'"
Write-Host "Logs      :  C:\ProgramData\RansomwareDetection\archive-staging.log"
