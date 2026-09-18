#!/bin/sh
#
# BulbBee LAN/TCP Plane Hook
# Enables and starts the AES-CCM local control port on :6668 (BULB-A4).
#

VULNZOO_DEVICE="${VULNZOO_DEVICE:-$(uci -q get vulnzoo.state.current_device 2>/dev/null)}"

if [ "$VULNZOO_DEVICE" != "bulbbee" ]; then
    logger -t bulbbee-lan "Skipping LAN plane hook for device: ${VULNZOO_DEVICE:-none}"
    exit 0
fi

LOG_FILE="/root/vulnzoo.log"

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$$] [bulbbee] $1" >> "$LOG_FILE"
}

log_message "Starting BulbBee LAN plane hook"

if [ ! -f /opt/bulbbee/local_tcp.py ]; then
    log_message "ERROR: local_tcp.py not found"
    exit 1
fi

if [ ! -f /etc/init.d/bulbbee-lan ]; then
    log_message "ERROR: /etc/init.d/bulbbee-lan not found"
    exit 1
fi

/etc/init.d/bulbbee-lan stop 2>/dev/null
sleep 1

log_message "Enabling LAN plane service..."
/etc/init.d/bulbbee-lan enable

log_message "Starting LAN plane service..."
if /etc/init.d/bulbbee-lan start; then
    sleep 2
    if pgrep -f local_tcp.py > /dev/null; then
        log_message "LAN plane started (PID: $(pgrep -f local_tcp.py))"
    else
        log_message "ERROR: LAN plane process not found after start"
    fi
else
    log_message "ERROR: Failed to start LAN plane service"
fi

exit 0
