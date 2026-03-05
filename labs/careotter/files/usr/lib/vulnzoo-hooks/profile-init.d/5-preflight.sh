#!/bin/sh
# CareOtter Pre-Flight System Check Hook
# Verifies system is ready for deployment

LOG_FILE="/root/vulnzoo.log"

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$$] $1" >> "$LOG_FILE"
}

log_message "Running CareOtter pre-flight system check..."

ERRORS=0
WARNINGS=0

# Check directory structure
for dir in /root/careotter/core /root/careotter/api /root/careotter/config /root/careotter/data /root/careotter/logs; do
    if [ -d "$dir" ]; then
        log_message "Directory exists: $dir"
    else
        log_message "Creating directory: $dir"
        mkdir -p "$dir" || ERRORS=$((ERRORS + 1))
    fi
done

# Check Python3
if command -v python3 >/dev/null 2>&1; then
    PY_VERSION=$(python3 --version 2>&1)
    log_message "Python3 found: $PY_VERSION"
else
    log_message "ERROR: Python3 not found"
    ERRORS=$((ERRORS + 1))
fi

# Check Bluetooth (optional)
if command -v bluetoothctl >/dev/null 2>&1; then
    log_message "Bluetooth utilities available"
else
    log_message "WARNING: Bluetooth utilities not found"
    WARNINGS=$((WARNINGS + 1))
fi

# Check I2C (optional for sensors)
if [ -e /dev/i2c-1 ]; then
    log_message "I2C device available: /dev/i2c-1"
else
    log_message "INFO: I2C device not found (will use mock sensor)"
fi

# Check disk space (100MB minimum)
DISK_FREE=$(df /root 2>/dev/null | awk 'NR==2 {print $4}')
if [ -n "$DISK_FREE" ] && [ "$DISK_FREE" -gt 102400 ]; then
    log_message "Disk space OK: $((DISK_FREE / 1024)) MB available"
else
    log_message "WARNING: Low disk space"
    WARNINGS=$((WARNINGS + 1))
fi

# Summary
log_message "Pre-flight check complete: Errors=$ERRORS Warnings=$WARNINGS"

if [ $ERRORS -gt 0 ]; then
    log_message "Pre-flight check FAILED"
    exit 1
else
    log_message "Pre-flight check PASSED"
    exit 0
fi
