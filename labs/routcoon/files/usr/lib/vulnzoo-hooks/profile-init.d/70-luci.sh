#!/bin/sh
#
# RoutCoon LuCI Cache Cleanup Hook
# Clears LuCI cache without restarting uhttpd (already done in 30-uhttpd-config.sh)
#

VULNZOO_DEVICE="${VULNZOO_DEVICE:-$(uci -q get vulnzoo.state.current_device 2>/dev/null)}"

HOOK_NAME="routcoon-luci"
HOOK_VERSION="1.0"
LOG_FILE="/root/vulnzoo.log"

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$$] [$HOOK_NAME] $1" >> "$LOG_FILE"
}

# Only run for routcoon device
if [ "$VULNZOO_DEVICE" != "routcoon" ]; then
    log_message "Skipping LuCI cleanup for device: $VULNZOO_DEVICE"
    exit 0
fi

log_message "Clearing LuCI cache..."

# Limpieza de cache de LuCI
rm -f /tmp/luci-indexcache 2>/dev/null
rm -f /tmp/luci-modulecache/* 2>/dev/null
rm -rf /tmp/luci-sessions/* 2>/dev/null
rm -f /tmp/luci-* 2>/dev/null

# Restart rpcd only (uhttpd already restarted in 30-uhttpd-config.sh)
/etc/init.d/rpcd restart >/dev/null 2>&1

log_message "LuCI cache cleared and rpcd restarted"

exit 0
