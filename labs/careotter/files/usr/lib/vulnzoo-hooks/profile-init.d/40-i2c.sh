#!/bin/sh
#
# CareOtter I2C Enable Hook
# Ensures i2c-1 is enabled on Raspberry Pi by modifying config.txt if necessary
#

# Get device name from environment OR from UCI config (fallback)
VULNZOO_DEVICE="${VULNZOO_DEVICE:-$(uci -q get vulnzoo.state.current_device 2>/dev/null)}"

# Only run for careotter device
if [ "$VULNZOO_DEVICE" != "careotter" ]; then
    logger -t careotter-i2c "Skipping I2C hook for device: ${VULNZOO_DEVICE:-none}"
    exit 0
fi

LOG_FILE="/root/vulnzoo.log"

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$$] [careotter] $1" >> "$LOG_FILE"
}

log_message "Running I2C enable hook"

# Check if i2c-1 is already enabled
if [ -e /dev/i2c-1 ]; then
    log_message "i2c-1 already enabled"
    exit 0
fi

# Try to load i2c-dev module if available
if [ -f /lib/modules/$(uname -r)/i2c-dev.ko ] || modprobe i2c-dev 2>/dev/null; then
    log_message "i2c-dev module loaded"
else
    log_message "i2c-dev module not available, using config.txt method"
fi

# Run the init.d script to configure config.txt
if [ -f /etc/init.d/i2c ]; then
    /etc/init.d/i2c start
    log_message "I2C enable hook completed"
else
    log_message "WARNING: /etc/init.d/i2c not found"
fi

exit 0
