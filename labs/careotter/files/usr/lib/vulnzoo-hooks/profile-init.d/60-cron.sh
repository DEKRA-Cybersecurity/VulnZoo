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

# Drop cron log level so job executions show up in logread.
# Default in OpenWRT is 8 (silent — only daemon start/stop). Level 0
# emits a "USER root pid X cmd Y" line on every dispatch, which is
# what you want when debugging.
uci set system.@system[0].cronloglevel='0'
uci commit system

# Normalize crontab ownership and mode. Busybox crond silently
# ignores crontabs not owned by root or that are group/other writable;
# scp from a dev box leaves the file as uid 1000:1000 mode 0664 and
# zero jobs fire. (Root-caused on the live Pi 2026-05-19.)
if [ -f /etc/crontabs/root ]; then
    chown root:root /etc/crontabs/root
    chmod 600 /etc/crontabs/root
fi

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

# Re-normalize perms in case the append created the file with wrong mode.
chown root:root /etc/crontabs/root 2>/dev/null
chmod 600       /etc/crontabs/root 2>/dev/null

# Reload cron to apply changes
/etc/init.d/cron reload 2>/dev/null || /etc/init.d/cron restart

log_message "Cron configuration completed (loglevel=0, root:root 0600)"

exit 0
