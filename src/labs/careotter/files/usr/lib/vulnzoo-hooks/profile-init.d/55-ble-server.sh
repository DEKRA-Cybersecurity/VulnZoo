#!/bin/sh
#
# CareOtter BLE Server Hook
# Starts the Bluetooth Low Energy GATT server for mobile app connectivity
# Uses hcitool (no D-Bus dependency)
#

VULNZOO_DEVICE="${VULNZOO_DEVICE:-$(uci -q get vulnzoo.state.current_device 2>/dev/null)}"

if [ "$VULNZOO_DEVICE" != "careotter" ]; then
    logger -t careotter-ble "Skipping BLE server hook for device: ${VULNZOO_DEVICE:-none}"
    exit 0
fi

LOG_FILE="/root/vulnzoo.log"
PID_FILE="/var/run/careotter-ble.pid"

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$$] [careotter] $1" >> "$LOG_FILE"
}

log_message "Starting CareOtter BLE server..."

PYTHON_BIN=$(which python3)
log_message "DEBUG: Using Python: $PYTHON_BIN"

# Check if Bluetooth is available
if [ ! -e /sys/class/bluetooth/hci0 ]; then
    log_message "WARNING: Bluetooth adapter not found, BLE server will not start"
    exit 0
fi

# Check if BLE server script exists
if [ ! -f /opt/medical-sensor/ble_server.py ]; then
    log_message "ERROR: ble_server.py not found"
    exit 1
fi

# ============================================================================
# START SERVICE (via procd init script for auto-restart on boot)
# ============================================================================

# Ensure the init script is present
if [ ! -f /etc/init.d/ble-server ]; then
    log_message "ERROR: /etc/init.d/ble-server not found"
    exit 1
fi

# Stop any existing instance first
/etc/init.d/ble-server stop 2>/dev/null
sleep 1

# Enable auto-start on boot
log_message "Enabling BLE server service..."
/etc/init.d/ble-server enable

# Configure environment so procd inherits them
export DBUS_SYSTEM_BUS_ADDRESS="${DBUS_SYSTEM_BUS_ADDRESS:-unix:path=/run/dbus/system_bus_socket}"
export BLE_INTERVAL="${BLE_INTERVAL:-1}"
log_message "D-Bus system bus: ${DBUS_SYSTEM_BUS_ADDRESS}"
log_message "BLE emit interval: ${BLE_INTERVAL}s"

# Start the service via procd
log_message "Starting BLE GATT server via init script..."
if /etc/init.d/ble-server start; then
    sleep 3
    # Verify it started
    if [ -f /var/run/ble-server.pid ]; then
        ble_pid=$(cat /var/run/ble-server.pid 2>/dev/null)
        if kill -0 "$ble_pid" 2>/dev/null; then
            log_message "BLE server started successfully (PID: $ble_pid)"
            log_message "Device name: CareOtter_HR"
            log_message "BLE UUIDs: HR=0000180d-, SpO2=c0a10001-, Battery=00002a19-"
        else
            log_message "ERROR: BLE server PID file exists but process is dead"
            exit 1
        fi
    else
        log_message "WARNING: BLE server PID file not found after start — checking procd status"
    fi
else
    log_message "ERROR: BLE server init script failed to start"
    exit 1
fi

exit 0
