#!/bin/sh
#
# CareOtter Admin Service Hook
# Starts the device administration service (careservice)
# Port 9999 - Binary IGP protocol
#
# This service is INDEPENDENT from the medical service (port 8081)
# Provides device administration functions with intentional vulnerabilities:
# - Format String in status
# - Integer Underflow in preferences
# - Hardcoded admin token (OtterMobile2026)
# - Information Disclosure (WiFi config)
#

VULNZOO_DEVICE="${VULNZOO_DEVICE:-$(uci -q get vulnzoo.state.current_device 2>/dev/null)}"

if [ "$VULNZOO_DEVICE" != "careotter" ]; then
    logger -t careotter-admin "Skipping admin service hook for device: ${VULNZOO_DEVICE:-none}"
    exit 0
fi

LOG_FILE="/root/vulnzoo.log"
PID_FILE="/var/run/careservice.pid"
CARESERVICE_BIN="/opt/careotter/careservice"
CARESERVICE_PORT=9999

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$$] [careotter] $1" >> "$LOG_FILE"
}

log_message "Starting CareOtter Admin Service hook..."

# ============================================================================
# IDEMPOTENCY CHECK: Verify if the service is already running
# ============================================================================
if [ -f "$PID_FILE" ]; then
    existing_pid=$(cat "$PID_FILE" 2>/dev/null)
    if kill -0 "$existing_pid" 2>/dev/null; then
        log_message "Admin service already running (PID: $existing_pid) - skipping"
        logger -t careotter-admin "Service already active on port $CARESERVICE_PORT"
        exit 0
    else
        log_message "Stale PID file found, removing..."
        rm -f "$PID_FILE"
    fi
fi

# Check for other careservice processes running (without PID file)
existing_procs=$(ps | grep "[c]areservice" | grep -v grep | awk '{print $1}')
if [ -n "$existing_procs" ]; then
    log_message "Found existing careservice processes: $existing_procs - stopping them"
    for pid in $existing_procs; do
        kill -9 "$pid" 2>/dev/null
    done
    sleep 1
fi

# ============================================================================
# PRE-FLIGHT CHECKS
# ============================================================================

# Verify that the binary exists
if [ ! -f "$CARESERVICE_BIN" ]; then
    log_message "ERROR: careservice binary not found at $CARESERVICE_BIN"
    logger -t careotter-admin "ERROR: Binary missing - compile careservice.c first"
    exit 1
fi

# Verify that it is executable
if [ ! -x "$CARESERVICE_BIN" ]; then
    log_message "Making careservice executable..."
    chmod +x "$CARESERVICE_BIN"
fi

# Verify that the port is not in use
port_check=$(netstat -tlnp 2>/dev/null | grep ":$CARESERVICE_PORT ")
if [ -n "$port_check" ]; then
    log_message "WARNING: Port $CARESERVICE_PORT is already in use: $port_check"
    logger -t careotter-admin "WARNING: Port $CARESERVICE_PORT occupied - attempting to free it"
    # Try to kill processes on that port
    fuser -k ${CARESERVICE_PORT}/tcp 2>/dev/null
    sleep 1
fi

# ============================================================================
# START SERVICE (via procd init script for auto-restart on boot)
# ============================================================================

# Ensure the init script is present
if [ ! -f /etc/init.d/careservice ]; then
    log_message "ERROR: /etc/init.d/careservice not found"
    exit 1
fi

# Enable auto-start on boot
log_message "Enabling careservice..."
/etc/init.d/careservice enable

# Start the service via procd
log_message "Starting careservice on port $CARESERVICE_PORT via init script..."
logger -t careotter-admin "Starting admin service (IGP protocol, port $CARESERVICE_PORT)"

if /etc/init.d/careservice start; then
    sleep 2
    # Verify it started
    if [ -f /var/run/careservice.pid ]; then
        service_pid=$(cat /var/run/careservice.pid 2>/dev/null)
        if kill -0 "$service_pid" 2>/dev/null; then
            log_message "Admin service started successfully (PID: $service_pid)"
            logger -t careotter-admin "Service active - Commands: 0x01=INFO, 0x02=AUTH, 0x03=WIFI, 0x04=PREFS, 0x05=STATUS"
            logger -t careotter-admin "Vulnerabilities: Format String, Integer Underflow, Hardcoded Token"
        else
            log_message "ERROR: careservice PID file exists but process is dead"
            exit 1
        fi
    else
        log_message "WARNING: careservice PID file not found after start — checking procd status"
    fi
else
    log_message "ERROR: careservice init script failed to start"
    logger -t careotter-admin "ERROR: Service failed - check /tmp/careservice.log"
    exit 1
fi

exit 0
