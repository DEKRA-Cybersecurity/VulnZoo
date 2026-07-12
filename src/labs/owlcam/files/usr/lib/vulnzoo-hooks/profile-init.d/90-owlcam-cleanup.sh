#!/bin/sh
# 90-owlcam-cleanup.sh - remove/disable packages and services that are not
# needed by the OwlCam lab but may be present in the shared VulnZoo image.
#
# This hook runs after all OwlCam service hooks (10-22) so the lab is fully
# up before we trim unused components.
#
# NOTE: OwlCam is a camera lab. Unlike the OctoBot cleanup, it KEEPS the
# video/streaming stack (v4l2rtspserver, ffmpeg, mjpg-streamer) and the
# intentionally vulnerable SSH (dropbear) and web UI (uhttpd). It only trims
# services that belong to other labs' shared image (MQTT, Bluetooth, SNMP...).

VULNZOO_DEVICE="${VULNZOO_DEVICE:-$(uci -q get vulnzoo.state.current_device 2>/dev/null)}"

if [ "$VULNZOO_DEVICE" != "owlcam" ]; then
    logger -t owlcam-cleanup "Skipping cleanup hook for device: ${VULNZOO_DEVICE:-none}"
    exit 0
fi

LOG_FILE="/root/vulnzoo.log"

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [owlcam-cleanup] $1" >> "$LOG_FILE"
}

log_message "Starting OwlCam system cleanup..."

# Helper: stop and disable an init.d service if it exists.
disable_service() {
    local svc="$1"
    if [ -x "/etc/init.d/$svc" ]; then
        log_message "Stopping and disabling $svc..."
        "/etc/init.d/$svc" stop >/dev/null 2>&1
        "/etc/init.d/$svc" disable >/dev/null 2>&1
        log_message "$svc stopped and disabled"
    else
        log_message "$svc init script not present; skipping"
    fi
}

# MQTT broker: belongs to the OctoBot (industrial) lab, not used by OwlCam.
disable_service "mosquitto"

# Bluetooth stack: belongs to the CareOtter (BLE medical) lab, not used by OwlCam.
disable_service "bluetoothd"
disable_service "brcm-bluetooth"
disable_service "btagent"

# Network services OwlCam does not expose.
disable_service "snmpd"
disable_service "radius"

# dbus is typically only needed by BlueZ on these images.
# Disable it after the Bluetooth services; if another component needs it,
# procd or manual start will still work.
disable_service "dbus"

# Attempt opkg removal of the related packages. If a package is baked into
# the Squashfs base image this only records the removal in the overlay, but
# it prevents the service from being re-enabled on a firstboot reset.
# The camera/streaming packages (v4l2rtspserver, ffmpeg, mjpg-streamer) are
# deliberately NOT listed here: OwlCam needs them.
if command -v opkg >/dev/null 2>&1; then
    for pkg in mosquitto-ssl mosquitto-nossl mosquitto-client-ssl \
               mosquitto-client-nossl libmosquitto-ssl libmosquitto-nossl \
               bluez-daemon bluez-libs bluez-utils \
               snmpd snmp-mibs freeradius3-common freeradius3 \
               dbus dbus-utils; do
        if opkg list-installed 2>/dev/null | grep -q "^${pkg} "; then
            log_message "Removing package $pkg from overlay..."
            opkg remove "$pkg" >/dev/null 2>&1 \
                && log_message "Package $pkg removed from overlay" \
                || log_message "Package $pkg removal returned non-zero (may be Squashfs-baked)"
        fi
    done
else
    log_message "opkg not available; skipping package removal"
fi

log_message "OwlCam system cleanup completed."
exit 0
