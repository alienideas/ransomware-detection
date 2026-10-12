# Linux – Archive Staging Detection (Ransomware Precursor)

This Bash script detects **staging of unauthorized archives** (`.zip`, `.rar`, `.7z`, `.tar.gz`, etc.) in temporary and shared directories. Such activity is a common precursor to ransomware data exfiltration.

**Alert message sent to admins:**
> Staging and Archiving Data: Large collections of files being compressed into .zip, .rar, or .7z archives within hidden or public temp directories on servers, signaling preparation for data exfiltration.

---

## 1. Prerequisites

- Any modern Linux distribution (RHEL/CentOS 7+, Ubuntu 18.04+, Debian 10+, etc.)
- `bash`, `find`, `awk`
- A mail transfer agent or client that can send outbound mail:
  - `mailx` / `mailutils` (simplest)
  - `msmtp` (recommended for authenticated SMTP)
  - `sendmail` / Postfix / Exim (if already configured)

## 2. Installation

1. Copy the script to a system location and make it executable:
   ```bash
   sudo mkdir -p /opt/ransomware-detection
   sudo cp detect-archive-staging.sh /opt/ransomware-detection/
   sudo chmod 750 /opt/ransomware-detection/detect-archive-staging.sh
   sudo chown root:root /opt/ransomware-detection/detect-archive-staging.sh
   ```

2. Edit the **CONFIGURATION** section at the top of the script:
   ```bash
   sudo nano /opt/ransomware-detection/detect-archive-staging.sh
   ```
   Key variables:
   ```bash
   TO_ADDRESS="admin@domain.com"
   FROM_ADDRESS="alerts@$(hostname -f)"
   LOOKBACK_MINUTES=1440          # 24 h
   MIN_SIZE_MB=1
   MAIL_CMD="mailx"               # or "msmtp", "mail", "sendmail"
   ```

3. Create the log directory:
   ```bash
   sudo mkdir -p /var/log/ransomware-detection
   sudo chmod 750 /var/log/ransomware-detection
   ```

### 2.1 Configure outbound email (choose one)

**Option A – mailutils (simple, often uses local MTA or null client)**
```bash
# Debian/Ubuntu
sudo apt-get update && sudo apt-get install -y mailutils

# RHEL/CentOS/Fedora
sudo yum install -y mailx
# or
sudo dnf install -y mailx
```

**Option B – msmtp (recommended for authenticated SMTP)**
```bash
# Debian/Ubuntu
sudo apt-get install -y msmtp msmtp-mta

# RHEL/CentOS
sudo yum install -y msmtp
```

Create `/etc/msmtprc` (root only):
```
defaults
auth           on
tls            on
tls_trust_file /etc/ssl/certs/ca-certificates.crt
logfile        /var/log/msmtp.log

account        default
host           smtp.yourdomain.com
port           587
from           alerts@yourdomain.com
user           alerts@yourdomain.com
password       YOUR_SMTP_PASSWORD
```
```bash
sudo chmod 600 /etc/msmtprc
```
Then set `MAIL_CMD="msmtp"` in the detection script (or keep `mailx` if the system is configured to use msmtp as the sendmail alternative).

## 3. Manual Test

```bash
sudo /opt/ransomware-detection/detect-archive-staging.sh
```

- Clean result → “No suspicious archives detected.”
- Findings → details logged and email sent to `admin@domain.com`.

To force a test, place a >1 MB archive in `/tmp` and re-run:
```bash
dd if=/dev/urandom of=/tmp/test-staging.zip bs=1M count=2
sudo /opt/ransomware-detection/detect-archive-staging.sh
rm /tmp/test-staging.zip
```

## 4. Automate with cron (recommended)

Create a root crontab entry that runs every hour:

```bash
sudo crontab -e
```

Add the line:
```
0 * * * * /opt/ransomware-detection/detect-archive-staging.sh >/dev/null 2>&1
```

### More frequent checks (every 15 minutes)
```
*/15 * * * * /opt/ransomware-detection/detect-archive-staging.sh >/dev/null 2>&1
```

### Alternative: systemd timer (modern systems)

Create `/etc/systemd/system/archive-staging-detection.service`:
```ini
[Unit]
Description=Ransomware Archive Staging Detection
After=network-online.target

[Service]
Type=oneshot
ExecStart=/opt/ransomware-detection/detect-archive-staging.sh
User=root
```

Create `/etc/systemd/system/archive-staging-detection.timer`:
```ini
[Unit]
Description=Run Archive Staging Detection hourly

[Timer]
OnBootSec=5min
OnUnitActiveSec=1h
Persistent=true

[Install]
WantedBy=timers.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now archive-staging-detection.timer
sudo systemctl list-timers | grep archive-staging
```

## 5. Log Location

```
/var/log/ransomware-detection/archive-staging.log
```

You may want to add a logrotate snippet:
```bash
sudo tee /etc/logrotate.d/ransomware-detection <<EOF
/var/log/ransomware-detection/*.log {
    weekly
    rotate 8
    compress
    missingok
    notifempty
    create 0640 root root
}
EOF
```

## 6. Hardening Tips

- Keep the script owned by root and mode 750 (or 700).
- Prefer `msmtp` or a properly locked-down local MTA over storing credentials in the script itself.
- Add extra directories that are relevant to your environment (web-app temp folders, shared NFS mounts, etc.) to the `TARGET_DIRS` array.
- Combine with auditd rules that watch for creation of large archives if you need real-time (instead of polling) detection.

## 7. Troubleshooting

| Symptom | Possible cause / fix |
|---------|----------------------|
| “No mail command found” | Install `mailutils` / `mailx` or `msmtp`. |
| Email not arriving | Check `/var/log/msmtp.log` or mail logs; verify SMTP credentials and firewall. |
| Permission denied on some paths | Script must run as root (or an account that can read the target dirs). |
| Too many false positives | Increase `MIN_SIZE_MB` (e.g. 10) or reduce `LOOKBACK_MINUTES`. |
| find errors on /run/user | Harmless; those directories may be empty or restricted. |

---

**Contact:** Set `TO_ADDRESS` to the security / operations distribution list that should receive ransomware precursor alerts.
