# Ransomware Detection Scripts – Archive Staging & Data Exfiltration Detection

**Detect ransomware precursors, unauthorized archive creation, and data staging for exfiltration on Windows and Linux servers.**

[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-blue)]()
[![Language](https://img.shields.io/badge/Scripts-PowerShell%20%7C%20Bash-green)]()
[![Alerting](https://img.shields.io/badge/Alerting-Email%20SMTP-orange)]()
[![Automation](https://img.shields.io/badge/Automation-Task%20Scheduler%20%7C%20Cron%20%7C%20Systemd-purple)]()

---

## Table of Contents

- [Overview](#overview)
- [What Problem Does This Solve?](#what-problem-does-this-solve)
- [Detection Logic Explained](#detection-logic-explained)
  - [In Simple Terms (Layman’s Explanation)](#in-simple-terms-laymans-explanation)
  - [Technical Detection Criteria](#technical-detection-criteria)
  - [How the Scripts Work Step-by-Step](#how-the-scripts-work-step-by-step)
- [Alert Message](#alert-message)
- [Package Contents](#package-contents)
- [Windows Installation & Configuration](#windows-installation--configuration)
- [Linux Installation & Configuration](#linux-installation--configuration)
- [Automation (Scheduled Tasks & Cron)](#automation-scheduled-tasks--cron)
- [Email / SMTP Configuration](#email--smtp-configuration)
- [Logging](#logging)
- [Tuning & Best Practices](#tuning--best-practices)
- [Troubleshooting](#troubleshooting)
- [Security Hardening Recommendations](#security-hardening-recommendations)
- [Limitations & Complementary Controls](#limitations--complementary-controls)
- [Keywords for Search & Discovery](#keywords-for-search--discovery)
- [License & Disclaimer](#license--disclaimer)

---

## Overview

This project provides **production-ready ransomware detection scripts** for Windows (PowerShell) and Linux (Bash). The scripts specifically target a high-fidelity early indicator of ransomware and data-theft attacks:

> **Staging and Archiving Data** — Large collections of files being compressed into `.zip`, `.rar`, or `.7z` archives inside hidden or public temporary directories on servers, signaling preparation for data exfiltration.

The scripts continuously (or on a schedule) scan common temporary and publicly writable locations, identify newly created or modified archives above a size threshold, log the findings, and send an immediate email alert to security administrators.

**Primary use cases:**
- Ransomware precursor detection
- Data exfiltration staging detection
- Unauthorized archive creation monitoring
- Server temp-directory security monitoring
- SOC / blue-team early warning system
- Compliance evidence for data-protection controls

---

## What Problem Does This Solve?

Modern ransomware and data-extortion groups rarely encrypt files immediately. A common attack pattern is:

1. Gain access to a server.
2. Locate and collect sensitive data.
3. Compress the data into large archives (`.zip`, `.rar`, `.7z`).
4. Stage those archives in temporary folders.
5. Exfiltrate the archives or use them as part of double-extortion.

By the time traditional antivirus or EDR detects encryption activity, the data may already be staged or stolen. These scripts close that gap by detecting the **staging phase** itself — often hours or days before encryption begins.

---

## Detection Logic Explained

### In Simple Terms (Layman’s Explanation)

Imagine a thief who wants to steal many important documents from an office.

Instead of carrying each paper out one by one (slow and obvious), the thief first gathers everything, packs it into a few large boxes or suitcases, and hides those boxes in a quiet storage room or temporary closet. Later, when the coast is clear, the boxes are carried out.

That is exactly what many ransomware and data-theft attacks do with computer files:

- They collect sensitive files.
- They squeeze them into big compressed “boxes” (files ending in `.zip`, `.rar`, or `.7z`).
- They leave those boxes in temporary folders that are easy to write to.

The detection scripts act like a security guard who regularly checks those temporary storage rooms. If the guard finds any large, newly packed boxes, an immediate alert is sent to the administrator with full details of what was found.

If nothing suspicious appears, the scripts stay quiet.

### Technical Detection Criteria

| Criterion              | Default Value                          | Why It Matters |
|------------------------|----------------------------------------|----------------|
| **Location**           | Temp & public directories              | Attackers prefer writable, less-monitored paths |
| **File extensions**    | `.zip` `.rar` `.7z` `.tar` `.gz` `.tgz` `.tar.gz` | Most common formats used for data staging |
| **Recency**            | Last 24 hours (configurable)           | Focuses on new activity; ignores old files |
| **Minimum size**       | ≥ 1 MB (configurable)                  | Filters noise; “large collections” are the real threat |
| **Metadata captured**  | Path, size, created/modified time, owner | Enables rapid investigation |
| **Response**           | Log + email alert to `admin@domain.com`| Immediate notification with actionable details |

### How the Scripts Work Step-by-Step

1. **Define the search space**  
   Windows looks in `%SystemRoot%\Temp`, `%TEMP%`, `C:\Users\Public`, `C:\PerfLogs`, `C:\Temp`, etc.  
   Linux looks in `/tmp`, `/dev/shm`, `/var/tmp`, `/var/www/html`, `/run/user`, etc.

2. **Enumerate candidate files**  
   Recursively find files matching the archive extensions inside the target directories.

3. **Apply filters**  
   - File must have been **created or last modified** within the look-back window.  
   - File size must be **≥ minimum size threshold** (default 1 MB).

4. **Collect rich metadata** for every match  
   Full path, size in megabytes, creation timestamp, last-write timestamp, and file owner.

5. **Decision logic**  
   - **Zero matches** → Write a clean log entry and exit successfully (no alert).  
   - **One or more matches** → Build a detailed email containing:
     - The official alert description
     - Hostname and detection timestamp
     - Complete list of matching files with metadata
     - Recommended response actions
   - Send the email via SMTP.
   - Append everything to a persistent log file.
   - Exit with a non-zero code only if email delivery itself fails (so the scheduler can surface the problem).

6. **Automation layer**  
   The scripts are designed to run unattended under SYSTEM (Windows Task Scheduler) or root (Linux cron / systemd timer).

---

## Alert Message

When suspicious activity is detected, administrators receive an email with the following core description:

> **Staging and Archiving Data:** Large collections of files being compressed into `.zip`, `.rar`, or `.7z` archives within hidden or public temp directories on servers, signaling preparation for data exfiltration.

The email also includes:
- Hostname
- Exact detection time
- Look-back window and size threshold used
- Full list of matching files (path, size, timestamps, owner)
- Recommended investigation steps

Default recipient: `admin@domain.com` (fully configurable).

---

## Package Contents

```
ransomware-detection/
├── README.md                          # This documentation
├── windows/
│   ├── Detect-ArchiveStaging.ps1      # Main PowerShell detection + alerting script
│   ├── Install-ScheduledTask.ps1      # Helper to register Task Scheduler job
│   └── README.md                      # Windows-specific quick start
└── linux/
    ├── detect-archive-staging.sh      # Main Bash detection + alerting script
    └── README.md                      # Linux-specific quick start
```

---

## Windows Installation & Configuration

### Prerequisites
- Windows Server 2016 / Windows 10 or later
- PowerShell 5.1 or higher
- Outbound SMTP access (port 587 or 25)
- Account with read access to target directories (SYSTEM recommended)

### Installation Steps

1. Copy the scripts to a secure location:
   ```
   C:\ProgramData\RansomwareDetection\
   ```

2. Edit the **CONFIGURATION** section at the top of `Detect-ArchiveStaging.ps1`:
   ```powershell
   $SmtpServer   = "smtp.yourdomain.com"
   $SmtpPort     = 587
   $SmtpUser     = "alerts@yourdomain.com"
   $SmtpPass     = "YOUR_SMTP_PASSWORD"
   $UseSsl       = $true
   $FromAddress  = "alerts@yourdomain.com"
   $ToAddress    = "admin@domain.com"
   ```

3. (Optional) Adjust monitored directories, look-back hours, or minimum size.

4. Test manually (elevated PowerShell):
   ```powershell
   .\Detect-ArchiveStaging.ps1 -LookbackHours 24 -MinSizeMB 1
   ```

5. Register the scheduled task (see Automation section below) or run:
   ```powershell
   .\Install-ScheduledTask.ps1 -IntervalHours 1
   ```

---

## Linux Installation & Configuration

### Prerequisites
- Modern Linux distribution (RHEL 7+, Ubuntu 18.04+, Debian 10+, etc.)
- `bash`, `find`, `awk`
- Mail client: `mailx` / `mailutils`, `msmtp`, or `sendmail`

### Installation Steps

1. Install the script:
   ```bash
   sudo mkdir -p /opt/ransomware-detection
   sudo cp detect-archive-staging.sh /opt/ransomware-detection/
   sudo chmod 750 /opt/ransomware-detection/detect-archive-staging.sh
   sudo chown root:root /opt/ransomware-detection/detect-archive-staging.sh
   ```

2. Edit configuration variables at the top of the script:
   ```bash
   TO_ADDRESS="admin@domain.com"
   LOOKBACK_MINUTES=1440
   MIN_SIZE_MB=1
   MAIL_CMD="mailx"          # or msmtp / sendmail
   ```

3. Create log directory:
   ```bash
   sudo mkdir -p /var/log/ransomware-detection
   sudo chmod 750 /var/log/ransomware-detection
   ```

4. Test:
   ```bash
   sudo /opt/ransomware-detection/detect-archive-staging.sh
   ```

---

## Automation (Scheduled Tasks & Cron)

### Windows – Task Scheduler
Recommended: run every hour under the SYSTEM account.

```powershell
# Using the helper script
.\Install-ScheduledTask.ps1 -IntervalHours 1

# Or manually
$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"C:\ProgramData\RansomwareDetection\Detect-ArchiveStaging.ps1`""
$Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Hours 1) -RepetitionDuration ([TimeSpan]::MaxValue)
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "Ransomware-ArchiveStagingDetection" `
    -Action $Action -Trigger $Trigger -Principal $Principal
```

### Linux – Cron
```bash
sudo crontab -e
# Add:
0 * * * * /opt/ransomware-detection/detect-archive-staging.sh >/dev/null 2>&1
```

### Linux – systemd Timer (recommended on modern systems)
Create service + timer units as documented in the Linux README, then:
```bash
sudo systemctl enable --now archive-staging-detection.timer
```

---

## Email / SMTP Configuration

Both scripts support standard SMTP:

- Office 365 / Microsoft 365
- Google Workspace / Gmail (app passwords)
- Any authenticated SMTP relay
- Local MTA (Postfix, Exim, sendmail)
- `msmtp` (recommended on Linux for simple authenticated delivery)

Change the recipient address (`$ToAddress` / `TO_ADDRESS`) to a security distribution list or SIEM email connector as needed.

---

## Logging

| Platform | Log Path |
|----------|----------|
| Windows  | `C:\ProgramData\RansomwareDetection\archive-staging.log` |
| Linux    | `/var/log/ransomware-detection/archive-staging.log` |

Logs contain timestamps, scan parameters, every finding, and email delivery status. Consider adding log rotation (logrotate on Linux, or scheduled cleanup on Windows).

---

## Tuning & Best Practices

- **Raise `MinSizeMB`** (e.g. to 5 or 10) if you see false positives from legitimate software packaging.
- **Shorten the look-back window** on high-churn servers.
- **Add environment-specific directories** (application temp folders, NFS mounts, web-app upload directories).
- **Exclude known good paths** if your environment has legitimate large archives in temp locations.
- Run the scripts as highly privileged accounts (SYSTEM / root) so they can read all target directories.
- Pair with EDR process creation alerts for `7z.exe`, `rar.exe`, `tar`, `zip`, etc.

---

## Troubleshooting

| Symptom | Likely Cause / Fix |
|---------|--------------------|
| No email received | Verify SMTP host, credentials, firewall, TLS settings, and spam folder |
| “Access denied” on folders | Run as SYSTEM (Windows) or root (Linux) |
| Too many false positives | Increase minimum size threshold or reduce look-back time |
| Script does nothing | Confirm execution policy (Windows) or executable bit + shebang (Linux) |
| Mail command not found (Linux) | Install `mailutils`, `mailx`, or `msmtp` |

---

## Security Hardening Recommendations

- Store SMTP credentials securely (Windows Credential Manager, DPAPI, or Linux `msmtprc` with mode 600).
- Restrict NTFS / filesystem permissions on the script directory so only administrators can modify the scripts.
- Use AppLocker / WDAC (Windows) or equivalent application control on Linux.
- Monitor the scheduled task / cron entry itself for unauthorized changes.
- Feed the email alerts into a SIEM or ticketing system for auditability.

---

## Limitations & Complementary Controls

These scripts are **polling-based** (not real-time). They do not inspect the contents of archives or track the process that created them.

For higher fidelity, combine with:
- Endpoint Detection & Response (EDR) process and file telemetry
- File Integrity Monitoring (FIM)
- Linux `auditd` rules watching for archive creation
- Network detection of large outbound transfers
- Behavioral ransomware prevention features in modern antivirus / EDR platforms

---

## Keywords for Search & Discovery

**Primary keywords:**  
ransomware detection, archive staging detection, data exfiltration detection, ransomware precursor detection, unauthorized zip detection, temp directory monitoring, ransomware early warning

**Secondary keywords:**  
PowerShell ransomware script, Linux ransomware detection bash, detect zip rar 7z staging, data staging detection, server temp folder security, ransomware data exfiltration indicator, SOC early detection script, blue team ransomware detection, automated ransomware alert, Task Scheduler ransomware scan, cron ransomware detection

**Long-tail phrases:**  
how to detect ransomware staging on Windows servers, detect large archives in temp directories, PowerShell script to find suspicious zip files, Linux bash script for ransomware precursor detection, email alert for data exfiltration staging, monitor public temp folders for ransomware

---

## License & Disclaimer

Provided as-is for defensive security operations and educational purposes.  
Test thoroughly in a non-production environment before widespread deployment.  
The authors assume no liability for false positives, missed detections, or operational impact.

**Use responsibly. These tools are intended only for authorized security monitoring of systems you own or are permitted to monitor.**

---

*Last updated: October 2026*  
*Compatible with: Windows Server 2016+, Windows 10/11, RHEL 7+, Ubuntu 18.04+, Debian 10+, and most modern Linux distributions.*
