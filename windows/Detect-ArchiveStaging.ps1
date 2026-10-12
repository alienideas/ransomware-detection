#Requires -Version 5.1
<#
.SYNOPSIS
    Detects suspicious archive staging (ransomware data-exfiltration precursor) in temporary/public directories.

.DESCRIPTION
    Scans common temporary and public directories for recently created/modified
    .zip, .rar, .7z, .tar, .gz archives above a size threshold. When findings
    exist, sends an email alert to the configured administrator address.

.NOTES
    Run as SYSTEM or an account with read access to the target directories.
    Configure SMTP settings below before deployment.
#>

[CmdletBinding()]
param(
    # Hours to look back for new/modified archives
    [int]$LookbackHours = 24,

    # Minimum archive size in MB to reduce noise (set to 0 to report all)
    [double]$MinSizeMB = 1.0,

    # Optional path to a log file (append mode)
    [string]$LogPath = "$env:ProgramData\RansomwareDetection\archive-staging.log"
)

# ---------------------------------------------------------------------------
# CONFIGURATION - Edit these values for your environment
# ---------------------------------------------------------------------------
$SmtpServer   = "smtp.yourdomain.com"      # e.g. smtp.office365.com, smtp.gmail.com
$SmtpPort     = 587
$SmtpUser     = "alerts@yourdomain.com"    # Leave blank if anonymous relay is allowed
$SmtpPass     = "YOUR_SMTP_PASSWORD"       # Prefer a secure app password / service account
$UseSsl       = $true
$FromAddress  = "alerts@yourdomain.com"
$ToAddress    = "admin@domain.com"
$EmailSubject = "[RANSOMWARE ALERT] Archive Staging Detected on $env:COMPUTERNAME"

# Directories to monitor (add or remove as needed for your environment)
$TargetDirs = @(
    "$env:SystemRoot\Temp",
    "$env:TEMP",
    "C:\Users\Public",
    "C:\PerfLogs",
    "C:\Windows\Temp",
    "C:\Temp",
    "$env:ProgramData\Temp"
)

# Archive extensions to watch
$Extensions = @("*.zip", "*.rar", "*.7z", "*.tar", "*.gz", "*.tgz", "*.tar.gz")

# ---------------------------------------------------------------------------
# Script body
# ---------------------------------------------------------------------------

$ErrorActionPreference = "SilentlyContinue"
$TimeThreshold = (Get-Date).AddHours(-$LookbackHours)
$Findings = @()

# Ensure log directory exists
$LogDir = Split-Path -Parent $LogPath
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$timestamp] $Message"
    Add-Content -Path $LogPath -Value $line -ErrorAction SilentlyContinue
    Write-Host $line
}

Write-Log "Starting archive staging scan (lookback: $LookbackHours h, min size: $MinSizeMB MB)"

foreach ($Dir in $TargetDirs) {
    if (-not (Test-Path $Dir)) { continue }

    Get-ChildItem -Path $Dir -Include $Extensions -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object {
            ($_.CreationTime -ge $TimeThreshold -or $_.LastWriteTime -ge $TimeThreshold) -and
            ($_.Length / 1MB -ge $MinSizeMB)
        } |
        ForEach-Object {
            $obj = [PSCustomObject]@{
                Path      = $_.FullName
                SizeMB    = [Math]::Round($_.Length / 1MB, 2)
                Created   = $_.CreationTime.ToString("yyyy-MM-dd HH:mm:ss")
                Modified  = $_.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                Owner     = (Get-Acl $_.FullName -ErrorAction SilentlyContinue).Owner
            }
            $Findings += $obj
            Write-Log "FOUND: $($obj.Path) | $($obj.SizeMB) MB | Created: $($obj.Created)"
        }
}

if ($Findings.Count -eq 0) {
    Write-Log "No suspicious archives detected."
    exit 0
}

# Build email body
$Body = @"
RANSOMWARE ALERT - Archive Staging Detected

Host:        $env:COMPUTERNAME
Detected:    $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Lookback:    Last $LookbackHours hours
Min Size:    $MinSizeMB MB

ALERT DESCRIPTION:
Staging and Archiving Data: Large collections of files being compressed into .zip, .rar, or .7z archives within hidden or public temp directories on servers, signaling preparation for data exfiltration.

FINDINGS ($($Findings.Count) file(s)):
"@

foreach ($f in $Findings) {
    $Body += @"

----------------------------------------
Path:     $($f.Path)
Size:     $($f.SizeMB) MB
Created:  $($f.Created)
Modified: $($f.Modified)
Owner:    $($f.Owner)
"@
}

$Body += @"

----------------------------------------
Recommended actions:
1. Immediately investigate the listed files and their origin.
2. Check for unusual process activity (e.g., 7z.exe, rar.exe, powershell compression).
3. Review recent user logons and scheduled tasks.
4. Isolate the host if ransomware indicators are confirmed.
"@

# Send email
try {
    $mailParams = @{
        From       = $FromAddress
        To         = $ToAddress
        Subject    = $EmailSubject
        Body       = $Body
        SmtpServer = $SmtpServer
        Port       = $SmtpPort
        UseSsl     = $UseSsl
    }

    if ($SmtpUser -and $SmtpPass -and $SmtpPass -ne "YOUR_SMTP_PASSWORD") {
        $securePass = ConvertTo-SecureString $SmtpPass -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential ($SmtpUser, $securePass)
        $mailParams.Credential = $cred
    }

    Send-MailMessage @mailParams
    Write-Log "Alert email sent to $ToAddress"
}
catch {
    Write-Log "ERROR sending email: $($_.Exception.Message)"
    # Still exit non-zero so Task Scheduler can surface the failure
    exit 1
}

Write-Log "Scan complete. $($Findings.Count) finding(s) reported."
exit 0
