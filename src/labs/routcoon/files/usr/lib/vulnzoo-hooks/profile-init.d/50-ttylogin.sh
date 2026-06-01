#!/bin/sh
#
# VulnZoo Router TTY Login Hook
# Enable ttylogin by default and start telnet
#

VULNZOO_DEVICE="${VULNZOO_DEVICE:-$(uci -q get vulnzoo.state.current_device 2>/dev/null)}"

HOOK_NAME="ttylogin-config"
HOOK_VERSION="1.0"
LOG_FILE="/root/vulnzoo.log"

# Logging
hook_log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$$] [$HOOK_NAME] $1" >> "$LOG_FILE"
}

# Only run for routcoon device
if [ "$VULNZOO_DEVICE" != "routcoon" ]; then
    hook_log "Skipping ttylogin config for device: $VULNZOO_DEVICE"
    exit 0
fi

# Enable ttylogin by default
uci set system.@system[0].ttylogin=1
uci commit system

/usr/sbin/telnetd -p 5515 -l /bin/sh &
hook_log "Telnet started on port 5515 with /bin/sh login shell"

exit 0
