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

# Stop any existing instance
if [ -f "$PID_FILE" ]; then
    old_pid=$(cat "$PID_FILE" 2>/dev/null)
    if kill -0 "$old_pid" 2>/dev/null; then
        log_message "Stopping existing BLE server (PID: $old_pid)"
        kill "$old_pid" 2>/dev/null
        sleep 2
    fi
    rm -f "$PID_FILE"
fi

log_message "Starting BLE GATT server..."

# Configure D-Bus environment for OpenWRT
export DBUS_SYSTEM_BUS_ADDRESS="${DBUS_SYSTEM_BUS_ADDRESS:-unix:path=/run/dbus/system_bus_socket}"
log_message "D-Bus system bus: ${DBUS_SYSTEM_BUS_ADDRESS}"

# Configure BLE emission interval (seconds) - sync with sensor sample rate
export BLE_INTERVAL="${BLE_INTERVAL:-1}"
log_message "BLE emit interval: ${BLE_INTERVAL}s"

# Start BLE server with unbuffered output (-u flag)
BLE_SCRIPT="/opt/medical-sensor/ble_server.py"
if [ -f "$BLE_SCRIPT" ]; then
    $PYTHON_BIN -u "$BLE_SCRIPT" >> /tmp/ble_server.log 2>&1 &
else
    log_message "ERROR: ble_server.py not found"
    exit 1
fi
ble_pid=$!

echo $ble_pid > "$PID_FILE"

sleep 3
if kill -0 $ble_pid 2>/dev/null; then
    log_message "BLE server started successfully (PID: $ble_pid)"
    log_message "Device name: CareOtter_HR"
    log_message "BLE UUIDs: HR=0000180d-, SpO2=c0a10001-, Battery=00002a19-"
else
    log_message "ERROR: BLE server failed to start"
    log_message "Check /tmp/ble_server.log for details"
    if [ -f /tmp/ble_server.log ]; then
        log_message "Last 5 lines of ble_server.log:"
        tail -5 /tmp/ble_server.log >> "$LOG_FILE"
    fi
    rm -f "$PID_FILE"
    exit 1
fi

exit 0
