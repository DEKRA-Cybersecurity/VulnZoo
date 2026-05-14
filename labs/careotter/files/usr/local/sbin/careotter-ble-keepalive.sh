#!/bin/sh
#
# CareOtter BLE keepalive — L3 hard-recovery for the BLE stack.
#
# L1 (asyncio watchdog inside ble_server.py) handles the common case
# "BlueZ silently stopped advertising" by re-registering every 60 s and
# writing /tmp/ble_advertising_heartbeat on each tick.
#
# This script handles the residual case where the failure is deeper
# than D-Bus can reach: a wedged Cypress controller, a hung bluetoothd,
# or a dead Python process that procd happens not to have restarted yet.
# It is meant to run from cron every minute. If the L1 heartbeat is
# stale beyond STALE_MAX seconds, the BLE radio is reset at the HCI
# level and the user-space services are bounced.
#
# Exit codes:
#   0 — healthy, no action taken
#   1 — recovery action taken (logged via `logger`)
#

set -u

HEARTBEAT=${HEARTBEAT:-/tmp/ble_advertising_heartbeat}
STALE_MAX=${STALE_MAX:-180}          # 3 minutes
LOG_TAG=careotter-ble-keepalive

log() { logger -t "$LOG_TAG" "$1"; echo "[keepalive] $1"; }

now=$(date +%s)

# 1) ble_server.py must be running. procd should keep it alive, but check.
PID=$(pgrep -f /opt/medical-sensor/ble_server.py 2>/dev/null | head -1)
if [ -z "$PID" ]; then
    log "ble_server.py not running — starting via init.d"
    /etc/init.d/ble-server start
    exit 1
fi

# Process uptime in seconds — busybox-safe (no `stat`, no `etime`, no
# `getconf`). Compute from /proc/uptime (system uptime) minus
# starttime-in-clock-ticks from /proc/<pid>/stat (field 22) divided by
# the kernel clock tick rate. CLK_TCK is 100 on every Linux build we
# ship; if the platform ever differs the keepalive will be slightly off
# but will not malfunction.
HZ=100
if [ -r "/proc/$PID/stat" ] && [ -r /proc/uptime ]; then
    sys_uptime=$(awk '{print int($1)}' /proc/uptime 2>/dev/null)
    proc_ticks=$(awk '{print $22}' /proc/$PID/stat 2>/dev/null)
    # Defensive: if either parse failed, treat the process as young so we
    # do not flap into a restart loop during early boot.
    if [ -n "$sys_uptime" ] && [ -n "$proc_ticks" ]; then
        proc_age=$(( sys_uptime - proc_ticks / HZ ))
    else
        proc_age=0
    fi
else
    proc_age=0
fi

# 2) Heartbeat file must exist and be recent.
if [ ! -f "$HEARTBEAT" ]; then
    # First-boot grace: the L1 watchdog writes the heartbeat on its first
    # tick at +BLE_WATCHDOG_INTERVAL (60 s by default). Tolerate absence
    # while the process is still young.
    if [ "$proc_age" -lt "$STALE_MAX" ]; then
        exit 0
    fi
    log "heartbeat missing after ${proc_age}s of process uptime — restart ble-server"
    /etc/init.d/ble-server restart
    exit 1
fi

last=$(cat "$HEARTBEAT" 2>/dev/null | tr -dc '0-9')
last=${last:-0}
delta=$(( now - last ))

if [ "$delta" -le "$STALE_MAX" ]; then
    # Stack is healthy. Done.
    exit 0
fi

# 3) Heartbeat stale ⇒ stack is wedged. Hard recovery.
log "heartbeat stale (${delta}s > ${STALE_MAX}s) — hard reset of BLE stack"

/etc/init.d/ble-server stop 2>/dev/null
sleep 1

# Bring the HCI device down/up to unstick the Cypress radio.
if [ -e /sys/class/bluetooth/hci0 ]; then
    hciconfig hci0 down 2>/dev/null
    sleep 1
    hciconfig hci0 up   2>/dev/null
    sleep 1
fi

# Restart bluetoothd to clear stale GATT/advertisement registrations.
/etc/init.d/bluetoothd restart 2>/dev/null
sleep 2

/etc/init.d/ble-server start
log "hard reset complete"
exit 1
