#!/bin/sh
#
# VulnZoo Router Crontab Hook 
#

VULNZOO_DEVICE="${VULNZOO_DEVICE:-$(uci -q get vulnzoo.state.current_device 2>/dev/null)}"

HOOK_NAME="crontab-config"
HOOK_VERSION="1.0"
LOG_FILE="/root/vulnzoo.log"

# Logging
hook_log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$$] [$HOOK_NAME] $1" >> "$LOG_FILE"
}

# Only run for routcoon device
if [ "$VULNZOO_DEVICE" != "routcoon" ]; then
    hook_log "Skipping crontab config for device: $VULNZOO_DEVICE"
    exit 0
fi

chown root:root /etc/crontabs/root

/etc/init.d/cron enable
/etc/init.d/cron start

hook_log "Crontab initialized and cron service started"
