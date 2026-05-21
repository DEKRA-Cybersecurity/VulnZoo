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
# Use pidof on the binary path as the source of truth — NOT the pidfile.
# procd writes /var/run/careservice.pid asynchronously (and sometimes not at
# all under USE_PROCD=1), so trusting the pidfile here races with rc.d which
# may have already started careservice via /etc/rc.d/S70careservice. If we
# kill that rc.d-spawned instance and then start a new one, procd ends up
# with a stale pidfile from the first attempt while the second instance
# runs fine — the hook then mis-reports "process is dead".
existing_pid=$(pidof "$CARESERVICE_BIN" 2>/dev/null | awk '{print $1}')
if [ -n "$existing_pid" ]; then
    log_message "Admin service already running (PID: $existing_pid) - skipping"
    logger -t careotter-admin "Service already active on port $CARESERVICE_PORT"
    # Re-sync the pidfile in case procd never wrote it — keeps later
    # stop/restart paths (which DO read $PID_FILE) reliable.
    echo "$existing_pid" > "$PID_FILE"
    exit 0
fi

# No live instance: any pidfile is stale.
if [ -f "$PID_FILE" ]; then
    log_message "Stale PID file found (no live process), removing..."
    rm -f "$PID_FILE"
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

# Defensive: verify the rc.d symlink was actually created. `enable` is supposed
# to create /etc/rc.d/S70careservice, but on some procd builds it can fail
# silently if the procd cache is stale or if a prior watchdog reboot left
# the overlay in an inconsistent state. Without this symlink the service
# does NOT come back automatically after a Pi reboot.
RC_SYMLINK="/etc/rc.d/S70careservice"
if [ ! -L "$RC_SYMLINK" ]; then
    log_message "WARNING: $RC_SYMLINK missing after enable — creating manually"
    mkdir -p /etc/rc.d
    ln -sf ../init.d/careservice "$RC_SYMLINK"
    sync
fi
if [ -L "$RC_SYMLINK" ]; then
    log_message "Confirmed boot-time auto-start: $RC_SYMLINK -> $(readlink "$RC_SYMLINK")"
else
    log_message "ERROR: could not create $RC_SYMLINK — service will NOT auto-start after reboot"
fi

# Start the service via procd
log_message "Starting careservice on port $CARESERVICE_PORT via init script..."
logger -t careotter-admin "Starting admin service (IGP protocol, port $CARESERVICE_PORT)"

if /etc/init.d/careservice start; then
    # Post-start verification — pidof, not the pidfile.
    # procd's pidfile write is asynchronous; checking it at a fixed sleep
    # has caused false-negative "process is dead" reports even when the
    # service was running. Retry pidof for up to 5s, then fall back to a
    # full restart if still not detected.
    service_pid=""
    for attempt in 1 2 3 4 5; do
        sleep 1
        service_pid=$(pidof "$CARESERVICE_BIN" 2>/dev/null | awk '{print $1}')
        [ -n "$service_pid" ] && break
    done

    if [ -z "$service_pid" ]; then
        log_message "WARNING: careservice not detected after start (5s) — forcing restart"
        /etc/init.d/careservice restart >/dev/null 2>&1
        for attempt in 1 2 3 4 5; do
            sleep 1
            service_pid=$(pidof "$CARESERVICE_BIN" 2>/dev/null | awk '{print $1}')
            [ -n "$service_pid" ] && break
        done
    fi

    if [ -n "$service_pid" ]; then
        # Always sync the pidfile to the real PID — operators and stop_service
        # downstream rely on $PID_FILE pointing at a live process.
        echo "$service_pid" > "$PID_FILE"
        log_message "Admin service started successfully (PID: $service_pid)"
        logger -t careotter-admin "Service active - Commands: 0x01=INFO, 0x02=AUTH, 0x03=WIFI, 0x04=PREFS, 0x05=STATUS"
        logger -t careotter-admin "Vulnerabilities: Format String, Integer Underflow, Hardcoded Token"
    else
        log_message "ERROR: careservice still not running after start + restart attempts"
        logger -t careotter-admin "ERROR: Service failed - check /var/log/careservice.log"
        exit 1
    fi
else
    log_message "ERROR: careservice init script failed to start"
    logger -t careotter-admin "ERROR: Service failed - check /var/log/careservice.log"
    exit 1
fi

exit 0
