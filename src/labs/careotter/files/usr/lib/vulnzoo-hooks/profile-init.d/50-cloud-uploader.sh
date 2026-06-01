#!/bin/sh
#
# CareOtter Cloud Uploader Hook
# Enables and starts the cloud-uploader procd service so the Pi pushes
# vitals/alerts to the Cloud API on boot and after every restart.
#

VULNZOO_DEVICE="${VULNZOO_DEVICE:-$(uci -q get vulnzoo.state.current_device 2>/dev/null)}"

if [ "$VULNZOO_DEVICE" != "careotter" ]; then
    logger -t careotter-cloud "Skipping cloud-uploader hook for device: ${VULNZOO_DEVICE:-none}"
    exit 0
fi

LOG_FILE="/root/vulnzoo.log"

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$$] [careotter] $1" >> "$LOG_FILE"
}

log_message "Starting CareOtter cloud-uploader hook..."

# Verify the init script is present
if [ ! -f /etc/init.d/cloud-uploader ]; then
    log_message "ERROR: /etc/init.d/cloud-uploader not found"
    exit 1
fi

# Verify the uploader script is present
if [ ! -f /opt/medical-sensor/cloud_uploader.py ]; then
    log_message "ERROR: /opt/medical-sensor/cloud_uploader.py not found"
    exit 1
fi

# Ensure log directory exists (cloud_uploader.py writes here)
LOG_DIR="/var/log/medical-logs"
mkdir -p "$LOG_DIR"
chmod 755 "$LOG_DIR"
log_message "Log directory ready: $LOG_DIR"

# Stop any existing instance first (idempotent)
/etc/init.d/cloud-uploader stop 2>/dev/null
sleep 1

# Enable auto-start on boot
log_message "Enabling cloud-uploader service..."
/etc/init.d/cloud-uploader enable

# Start the service via procd
log_message "Starting cloud-uploader via init script..."
if /etc/init.d/cloud-uploader start; then
    sleep 2
    # Verify it started
    if [ -f /var/run/cloud-uploader.pid ]; then
        cu_pid=$(cat /var/run/cloud-uploader.pid 2>/dev/null)
        if kill -0 "$cu_pid" 2>/dev/null; then
            log_message "Cloud uploader started successfully (PID: $cu_pid)"
        else
            log_message "WARNING: cloud-uploader PID file exists but process is dead — procd will respawn"
        fi
    else
        log_message "WARNING: cloud-uploader PID file not found after start — checking procd status"
    fi
else
    log_message "ERROR: cloud-uploader init script failed to start"
    exit 1
fi

log_message "Cloud-uploader hook completed (enabled for future reboots)"

exit 0
