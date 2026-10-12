# Windows – Archive Staging Detection (Ransomware Precursor)

This PowerShell script detects **staging of unauthorized archives** (`.zip`, `.rar`, `.7z`, etc.) in temporary and public directories. Such activity is a common precursor to ransomware data exfiltration.

**Alert message sent to admins:**
> Staging and Archiving Data: Large collections of files being compressed into .zip, .rar, or .7z archives within hidden or public temp directories on servers, signaling preparation for data exfiltration.

---

## 1. Prerequisites

- Windows Server 2016 / Windows 10 or later (PowerShell 5.1+)
- Outbound SMTP access (port 587 or 25) to your mail server
- An account that can read the target temporary directories (SYSTEM is recommended for scheduled runs)

## 2. Installation

1. Copy `Detect-ArchiveStaging.ps1` to a secure location, e.g.:
   ```
   C:\ProgramData\RansomwareDetection\Detect-ArchiveStaging.ps1
   ```

2. Open the script in a text editor and edit the **CONFIGURATION** section:
   ```powershell
   $SmtpServer   = "smtp.yourdomain.com"   # or smtp.office365.com / smtp.gmail.com
   $SmtpPort     = 587
   $SmtpUser     = "alerts@yourdomain.com"
   $SmtpPass     = "YOUR_SMTP_PASSWORD"    # use an app password / service account
   $UseSsl       = $true
   $FromAddress  = "alerts@yourdomain.com"
   $ToAddress    = "admin@domain.com"
   ```

3. (Optional) Adjust monitored directories (`$TargetDirs`), look-back window, or minimum size.

4. Create the log directory (the script will also try to create it):
   ```powershell
   New-Item -ItemType Directory -Path "C:\ProgramData\RansomwareDetection" -Force
   ```

## 3. Manual Test

Open an **elevated** PowerShell prompt and run:

```powershell
cd C:\ProgramData\RansomwareDetection
.\Detect-ArchiveStaging.ps1 -LookbackHours 24 -MinSizeMB 1
```

- If no archives are found you will see “No suspicious archives detected.”
- If findings exist, an email is sent and details are written to the log.

To force a test email you can temporarily lower `-MinSizeMB 0` and place a small `.zip` in `C:\Windows\Temp`.

## 4. Automate with Task Scheduler (recommended)

Run the following in an elevated PowerShell to create a scheduled task that executes every hour under the SYSTEM account:

```powershell
$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"C:\ProgramData\RansomwareDetection\Detect-ArchiveStaging.ps1`""

$Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Hours 1) -RepetitionDuration ([TimeSpan]::MaxValue)

$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable

Register-ScheduledTask -TaskName "Ransomware-ArchiveStagingDetection" `
    -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings `
    -Description "Detects suspicious archive staging in temp directories and emails admin@domain.com"
```

### Verify the task

```powershell
Get-ScheduledTask -TaskName "Ransomware-ArchiveStagingDetection" | Get-ScheduledTaskInfo
```

You can also open **Task Scheduler** → Task Scheduler Library → “Ransomware-ArchiveStagingDetection”.

### Alternative: run every 15 minutes

Change the repetition interval:

```powershell
$Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Minutes 15) `
    -RepetitionDuration ([TimeSpan]::MaxValue)
```

## 5. Log Location

```
C:\ProgramData\RansomwareDetection\archive-staging.log
```

## 6. Hardening Tips

- Prefer a dedicated low-privilege service account for SMTP authentication and store the password in a secure way (e.g. Credential Manager or encrypted DPAPI) instead of plain text in the script.
- Restrict NTFS permissions on the script folder so only Administrators can modify it.
- Consider adding the script path to AppLocker / WDAC allow-lists if you use application control.
- Pair this detector with EDR / file-integrity monitoring for higher confidence.

## 7. Troubleshooting

| Symptom | Possible cause / fix |
|---------|----------------------|
| No email received | Check SMTP server, credentials, firewall, and spam folder. Test with `Send-MailMessage` manually. |
| Access denied on some folders | Run the scheduled task as SYSTEM. |
| Script does nothing | Confirm `-ExecutionPolicy Bypass` is used and the file path is correct. |
| Too many false positives | Raise `$MinSizeMB` (e.g. 10) or shorten the look-back window. |

---

**Contact:** Configure `$ToAddress` to the security / operations distribution list that should receive ransomware precursor alerts.

## Helper: Install-ScheduledTask.ps1

A convenience script is also provided. After copying both files to the same folder and editing the detection script’s SMTP settings, run (elevated):

```powershell
.\Install-ScheduledTask.ps1 -IntervalHours 1
```

This registers the same task described above.
