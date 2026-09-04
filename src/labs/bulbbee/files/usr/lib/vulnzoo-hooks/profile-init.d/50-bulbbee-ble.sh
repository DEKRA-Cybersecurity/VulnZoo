#!/bin/sh
#
# BulbBee BLE Server Hook
# Starts the BLE GATT lighting-control server (the Android app's channel, BULB-A1).
#

VULNZOO_DEVICE="${VULNZOO_DEVICE:-$(uci -q get vulnzoo.state.current_device 2>/dev/null)}"

if [ "$VULNZOO_DEVICE" != "bulbbee" ]; then
    logger -t bulbbee-ble "Skipping BLE server hook for device: ${VULNZOO_DEVICE:-none}"
    exit 0
fi

LOG_FILE="/root/vulnzoo.log"

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$$] [bulbbee] $1" >> "$LOG_FILE"
}

log_message "Starting BulbBee BLE server hook"

if [ ! -f /opt/bulbbee/ble_light.py ]; then
    log_message "ERROR: ble_light.py not found"
    exit 1
fi

# Bluetooth adapter is required for the BLE control channel. Warn (do not fail)
# so the rest of the lab still loads on a Pi with no adapter.
if [ ! -e /sys/class/bluetooth/hci0 ]; then
    log_message "WARNING: Bluetooth adapter not found, BLE server will not start"
    exit 0
fi

if [ ! -f /etc/init.d/bulbbee-ble ]; then
    log_message "ERROR: /etc/init.d/bulbbee-ble not found"
    exit 1
fi

# Stop any existing instance first
/etc/init.d/bulbbee-ble stop 2>/dev/null
sleep 1

log_message "Enabling BLE server service..."
/etc/init.d/bulbbee-ble enable

log_message "Starting BLE server service..."
if /etc/init.d/bulbbee-ble start; then
    sleep 2
    if pgrep -f ble_light.py > /dev/null; then
        log_message "BLE server started (PID: $(pgrep -f ble_light.py))"
    else
        log_message "ERROR: BLE server process not found after start"
    fi
else
    log_message "ERROR: Failed to start BLE server service"
fi

exit 0
