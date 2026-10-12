# Ransomware Precursor Detection – Archive Staging

Detects **staging of large unauthorized archives** (`.zip`, `.rar`, `.7z`, `.tar.gz`, …) inside temporary and public directories. This behaviour is a classic early indicator of ransomware data-exfiltration preparation.

**Alert text delivered to administrators:**
> Staging and Archiving Data: Large collections of files being compressed into .zip, .rar, or .7z archives within hidden or public temp directories on servers, signaling preparation for data exfiltration.

## Package Contents

```
ransomware-detection/
├── README.md                          (this file)
├── windows/
│   ├── Detect-ArchiveStaging.ps1      # PowerShell detection + email alert
│   └── README.md                      # Windows install, Task Scheduler, SMTP
└── linux/
    ├── detect-archive-staging.sh      # Bash detection + email alert
    └── README.md                      # Linux install, cron / systemd timer, SMTP
```

## Quick Start

| Platform | Install guide |
|----------|---------------|
| **Windows** | See [windows/README.md](windows/README.md) |
| **Linux**   | See [linux/README.md](linux/README.md) |

Both scripts:

1. Scan common temp / public locations for recently created or modified archives above a configurable size threshold.
2. Log findings.
3. Send an email to `admin@domain.com` containing the alert description and full file details (path, size, timestamps, owner).
4. Are designed to be run automatically (Task Scheduler on Windows, cron or systemd timer on Linux).

## Default Monitored Locations

**Windows**
- `%SystemRoot%\Temp`, `%TEMP%`, `C:\Users\Public`, `C:\PerfLogs`, `C:\Temp`, …

**Linux**
- `/tmp`, `/dev/shm`, `/var/tmp`, `/var/www/html`, `/run/user`, …

You can extend the lists in the configuration sections of each script.

## Email Configuration

Edit the SMTP / mail settings at the top of the respective script before first use. Both READMEs contain detailed examples for Office 365, Gmail, and local MTA / msmtp setups.

## Recommended Cadence

- **Hourly** is a good balance for most environments.
- High-security or high-risk servers can run every 15 minutes.
- Pair with EDR / file-integrity monitoring for real-time coverage.

## License / Usage

Provided as-is for defensive security operations. Test thoroughly in a non-production environment and adjust thresholds to match your baseline noise level.
