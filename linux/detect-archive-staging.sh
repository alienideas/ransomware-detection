#!/bin/bash
#
# detect-archive-staging.sh
# Detects suspicious archive staging (ransomware data-exfiltration precursor)
# in temporary and public directories on Linux servers.
#
# When findings exist, sends an email alert to the configured administrator.
#
# Requirements: bash, find, mailx or sendmail (or msmtp), optional: logger
#

set -euo pipefail

# ---------------------------------------------------------------------------
# CONFIGURATION - Edit these values for your environment
# ---------------------------------------------------------------------------
LOOKBACK_MINUTES=1440          # 24 hours (1440 minutes)
MIN_SIZE_MB=1                  # Minimum archive size in MB (0 = report all)
LOG_FILE="/var/log/ransomware-detection/archive-staging.log"

# Email settings
TO_ADDRESS="admin@domain.com"
FROM_ADDRESS="alerts@$(hostname -f 2>/dev/null || hostname)"
EMAIL_SUBJECT="[RANSOMWARE ALERT] Archive Staging Detected on $(hostname)"

# SMTP via mailx / msmtp (preferred) or plain mail.
# If using a relay that needs auth, configure /etc/msmtprc or ~/.msmtprc
# and set MAIL_CMD accordingly.
MAIL_CMD="mailx"               # or "mail", "sendmail", "msmtp"

# Directories to scan (add site-specific paths as needed)
TARGET_DIRS=(
    "/tmp"
    "/dev/shm"
    "/var/tmp"
    "/var/www/html"
    "/var/tmp"
    "/tmp/.X11-unix"
    "/run/user"
)

# Archive name patterns
ARCHIVE_PATTERNS=(
    "*.zip"
    "*.rar"
    "*.7z"
    "*.tar"
    "*.gz"
    "*.tgz"
    "*.tar.gz"
)

# ---------------------------------------------------------------------------
# Script body
# ---------------------------------------------------------------------------

# Ensure log directory exists
mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true

log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $*"
    echo "$msg" | tee -a "$LOG_FILE" 2>/dev/null || echo "$msg"
}

log "Starting archive staging scan (lookback: ${LOOKBACK_MINUTES} min, min size: ${MIN_SIZE_MB} MB)"

# Build find expression for name patterns
NAME_EXPR=()
for i in "${!ARCHIVE_PATTERNS[@]}"; do
    if [[ $i -eq 0 ]]; then
        NAME_EXPR+=(-name "${ARCHIVE_PATTERNS[$i]}")
    else
        NAME_EXPR+=(-o -name "${ARCHIVE_PATTERNS[$i]}")
    fi
done

FINDINGS=()
TMP_FINDINGS=$(mktemp)

for dir in "${TARGET_DIRS[@]}"; do
    if [[ ! -d "$dir" ]]; then
        continue
    fi

    # -mmin: modified in last N minutes
    # -size +Nm: larger than N megabytes
    find "$dir" -type f \( "${NAME_EXPR[@]}" \) \
        -mmin "-${LOOKBACK_MINUTES}" \
        -size "+${MIN_SIZE_MB}M" \
        -printf '%p|%s|%TY-%Tm-%Td %TH:%TM:%TS|%u\n' 2>/dev/null >> "$TMP_FINDINGS" || true
done

if [[ ! -s "$TMP_FINDINGS" ]]; then
    log "No suspicious archives detected."
    rm -f "$TMP_FINDINGS"
    exit 0
fi

# Collect findings
while IFS='|' read -r path size_bytes mtime owner; do
    size_mb=$(awk -v s="$size_bytes" 'BEGIN { printf "%.2f", s/1024/1024 }')
    FINDINGS+=("$path|$size_mb|$mtime|$owner")
    log "FOUND: $path | ${size_mb} MB | Modified: $mtime | Owner: $owner"
done < "$TMP_FINDINGS"
rm -f "$TMP_FINDINGS"

COUNT=${#FINDINGS[@]}

# Build email body
BODY=$(cat <<EOF
RANSOMWARE ALERT - Archive Staging Detected

Host:        $(hostname)
Detected:    $(date '+%Y-%m-%d %H:%M:%S')
Lookback:    Last ${LOOKBACK_MINUTES} minutes
Min Size:    ${MIN_SIZE_MB} MB

ALERT DESCRIPTION:
Staging and Archiving Data: Large collections of files being compressed into .zip, .rar, or .7z archives within hidden or public temp directories on servers, signaling preparation for data exfiltration.

FINDINGS (${COUNT} file(s)):
EOF
)

for entry in "${FINDINGS[@]}"; do
    IFS='|' read -r path size_mb mtime owner <<< "$entry"
    BODY+=$(cat <<EOF

----------------------------------------
Path:     $path
Size:     ${size_mb} MB
Modified: $mtime
Owner:    $owner
EOF
)
done

BODY+=$(cat <<EOF

----------------------------------------
Recommended actions:
1. Immediately investigate the listed files and their origin.
2. Check for unusual process activity (e.g., 7z, rar, tar, zip, python/perl compression).
3. Review recent user logons, sudo history, and cron jobs.
4. Isolate the host if ransomware indicators are confirmed.
EOF
)

# Send email
send_mail() {
    if command -v "$MAIL_CMD" >/dev/null 2>&1; then
        echo "$BODY" | "$MAIL_CMD" -s "$EMAIL_SUBJECT" -r "$FROM_ADDRESS" "$TO_ADDRESS" 2>>"$LOG_FILE"
        return $?
    elif command -v sendmail >/dev/null 2>&1; then
        {
            echo "To: $TO_ADDRESS"
            echo "From: $FROM_ADDRESS"
            echo "Subject: $EMAIL_SUBJECT"
            echo
            echo "$BODY"
        } | sendmail -t 2>>"$LOG_FILE"
        return $?
    else
        log "ERROR: No mail command found (mailx/mail/sendmail). Install mailutils or msmtp."
        return 1
    fi
}

if send_mail; then
    log "Alert email sent to $TO_ADDRESS"
else
    log "ERROR: Failed to send alert email"
    exit 1
fi

log "Scan complete. ${COUNT} finding(s) reported."
exit 0
