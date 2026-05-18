#!/bin/sh
#
# CareOtter Medical Sensor Enable Hook
# Ensures the medical sensor service is enabled and started
#

# Get device name from environment OR from UCI config (fallback)
VULNZOO_DEVICE="${VULNZOO_DEVICE:-$(uci -q get vulnzoo.state.current_device 2>/dev/null)}"

# Only run for careotter device
if [ "$VULNZOO_DEVICE" != "careotter" ]; then
    logger -t careotter-sensor "Skipping medical sensor hook for device: ${VULNZOO_DEVICE:-none}"
    exit 0
fi

LOG_FILE="/root/vulnzoo.log"

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$$] [careotter] $1" >> "$LOG_FILE"
}

log_message "Running medical sensor enable hook"

# Verify Python files exist
if [ ! -f /opt/medical-sensor/sensor_service.py ]; then
    log_message "ERROR: sensor_service.py not found"
    exit 1
fi

if [ ! -f /opt/medical-sensor/simulator.py ]; then
    log_message "ERROR: simulator.py not found"
    exit 1
fi

# Ensure log directory exists under /var/log for persistence across boots
mkdir -p /var/log/medical-logs
chmod 755 /var/log/medical-logs
touch /var/log/medical-logs/vitals.log
chmod 644 /var/log/medical-logs/vitals.log

# Legacy: ensure old location exists for compatibility
mkdir -p /opt/medical-sensor

# Stop any existing instance first
/etc/init.d/medical-sensor stop 2>/dev/null
sleep 1

# Enable and start service
log_message "Enabling medical sensor service..."
/etc/init.d/medical-sensor enable

log_message "Starting medical sensor service on port 8081..."
if /etc/init.d/medical-sensor start; then
    # Verify it started
    sleep 2
    if pgrep -f sensor_service.py > /dev/null; then
        log_message "Medical sensor service started successfully (PID: $(pgrep -f sensor_service.py))"
        # Verify HTTP endpoint
        if wget -q -O - http://127.0.0.1:8081/health > /dev/null 2>&1; then
            log_message "Medical sensor HTTP endpoint responding on port 8081"
        else
            log_message "WARNING: Medical sensor HTTP endpoint not responding yet"
        fi
    else
        log_message "ERROR: Medical sensor process not found after start"
    fi
else
    log_message "ERROR: Failed to start medical sensor service"
fi

exit 0
