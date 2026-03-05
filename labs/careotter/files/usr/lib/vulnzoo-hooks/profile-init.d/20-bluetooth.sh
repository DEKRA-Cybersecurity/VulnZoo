#!/bin/sh
# CareOtter Bluetooth Configuration Hook
# Configures Bluetooth hardware and BLE adapter

LOG_FILE="/root/vulnzoo.log"

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$$] $1" >> "$LOG_FILE"
}

log_message "Configuring Bluetooth for CareOtter..."

# Check for Bluetooth utilities
if ! command -v bluetoothctl >/dev/null 2>&1; then
    log_message "WARNING: bluetoothctl not found - BLE may not work"
    exit 0  # Non-critical for systems without BLE
fi

# Power on Bluetooth adapter
if bluetoothctl power on >/dev/null 2>&1; then
    log_message "Bluetooth adapter powered on"
else
    log_message "ERROR: Failed to power on Bluetooth"
    exit 1
fi

# Set device name
if command -v hciconfig >/dev/null 2>&1; then
    if hciconfig hci0 name CareOtter_HR >/dev/null 2>&1; then
        log_message "Device name set to: CareOtter_HR"
    else
        log_message "WARNING: Could not set device name (non-critical)"
    fi
fi

# Enable pairing mode
if bluetoothctl pairable on >/dev/null 2>&1; then
    log_message "Pairing mode enabled"
else
    log_message "WARNING: Could not enable pairing mode"
fi

# Configure I2C permissions for sensor (if present)
if [ -e /dev/i2c-1 ]; then
    chmod 666 /dev/i2c-1 2>/dev/null || true
    log_message "I2C device permissions configured"
fi

log_message "Bluetooth configuration complete"
exit 0
