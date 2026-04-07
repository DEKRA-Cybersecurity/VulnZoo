#!/bin/sh
#
# CareOtter Cron/Logrotate Hook
# Configures log rotation for medical sensor logs
#

# Get device name from environment OR from UCI config (fallback)
VULNZOO_DEVICE="${VULNZOO_DEVICE:-$(uci -q get vulnzoo.state.current_device 2>/dev/null)}"

# Only run for careotter device
if [ "$VULNZOO_DEVICE" != "careotter" ]; then
    logger -t careotter-cron "Skipping cron hook for device: ${VULNZOO_DEVICE:-none}"
    exit 0
fi

LOG_FILE="/root/vulnzoo.log"

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$$] [careotter] $1" >> "$LOG_FILE"
}

log_message "Configuring cron and logrotate for careotter"

# Enable and start cron service
/etc/init.d/cron enable
/etc/init.d/cron restart

# Add logrotate entry ONLY if not already present (idempotent)
CRON_ENTRY="0 * * * * /usr/sbin/logrotate /etc/logrotate.d/medical-sensor"
if ! grep -qF "$CRON_ENTRY" /etc/crontabs/root 2>/dev/null; then
    echo "$CRON_ENTRY" >> /etc/crontabs/root
    log_message "Logrotate cron entry added"
else
    log_message "Logrotate cron entry already exists"
fi

# Reload cron to apply changes
/etc/init.d/cron reload 2>/dev/null || /etc/init.d/cron restart

log_message "Cron configuration completed"

exit 0
