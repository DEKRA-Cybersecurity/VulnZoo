#!/bin/sh
# CareOtter Python Dependencies Verification Hook
# Checks if required Python packages are installed

LOG_FILE="/root/vulnzoo.log"

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$$] $1" >> "$LOG_FILE"
}

log_message "Checking Python dependencies..."

# Python version check
if command -v python3 >/dev/null 2>&1; then
    PY_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    log_message "Python version: $PY_VERSION"
else
    log_message "ERROR: Python3 not found"
    exit 1
fi

# Check required packages
# dbus_fast: used by ble_server.py for BlueZ D-Bus GATT server
REQUIRED_PACKAGES="dbus_fast"
MISSING_COUNT=0

for package in $REQUIRED_PACKAGES; do
    if python3 -c "import $package" 2>/dev/null; then
        log_message "Package OK: $package"
    else
        log_message "Missing package: $package — installing..."
        pip3 install "$package" >> "$LOG_FILE" 2>&1 \
            && log_message "Installed: $package" \
            || { log_message "ERROR: failed to install $package"; MISSING_COUNT=$((MISSING_COUNT + 1)); }
    fi
done

if [ $MISSING_COUNT -gt 0 ]; then
    log_message "WARNING: $MISSING_COUNT packages could not be installed"
fi

log_message "Python dependencies check complete"
exit 0
