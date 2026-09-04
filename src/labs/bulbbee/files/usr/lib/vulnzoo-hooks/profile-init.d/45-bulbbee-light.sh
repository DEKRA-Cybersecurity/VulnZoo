#!/bin/sh
#
# BulbBee Lighting Service Enable Hook
# Ensures the WS2812 lighting service is enabled and started.
#

# Get device name from environment OR from UCI config (fallback)
VULNZOO_DEVICE="${VULNZOO_DEVICE:-$(uci -q get vulnzoo.state.current_device 2>/dev/null)}"

# Only run for bulbbee device
if [ "$VULNZOO_DEVICE" != "bulbbee" ]; then
    logger -t bulbbee-light "Skipping lighting hook for device: ${VULNZOO_DEVICE:-none}"
    exit 0
fi

LOG_FILE="/root/vulnzoo.log"

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$$] [bulbbee] $1" >> "$LOG_FILE"
}

log_message "Running lighting service enable hook"

# Verify service files exist
if [ ! -f /opt/bulbbee/lighting_service.py ]; then
    log_message "ERROR: lighting_service.py not found"
    exit 1
fi
if [ ! -f /opt/bulbbee/ws2812.py ]; then
    log_message "ERROR: ws2812.py not found"
    exit 1
fi

# Runtime state dir (simulation frame buffer + persisted state)
mkdir -p /tmp/bulbbee

# Stop any existing instance first
/etc/init.d/bulbbee-light stop 2>/dev/null
sleep 1

log_message "Enabling lighting service..."
/etc/init.d/bulbbee-light enable

log_message "Starting lighting service on port 8082..."
if /etc/init.d/bulbbee-light start; then
    sleep 2
    if pgrep -f lighting_service.py > /dev/null; then
        log_message "Lighting service started (PID: $(pgrep -f lighting_service.py))"
        if wget -q -O - http://127.0.0.1:8082/health > /dev/null 2>&1; then
            log_message "Lighting service HTTP endpoint responding on port 8082"
        else
            log_message "WARNING: Lighting service HTTP endpoint not responding yet"
        fi
    else
        log_message "ERROR: Lighting service process not found after start"
    fi
else
    log_message "ERROR: Failed to start lighting service"
fi

exit 0
