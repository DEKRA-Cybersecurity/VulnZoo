#!/bin/sh
# 90-canary-cleanup.sh - remove/disable packages and services that are not
# needed by the Canary lab but may be present in the shared VulnZoo image.
#
# This hook runs after all Canary service hooks (and after the CAN overlay hook
# 80-canary-can-overlay.sh) so the lab is fully up before we trim unused
# components. Canary keeps its own CAN stack: the canary-can, canary-gateway and
# canary-bcm services, plus can-utils / iproute2 / the kmod-can + mcp251x modules
# they rely on. None of those are touched here.

VULNZOO_DEVICE="${VULNZOO_DEVICE:-$(uci -q get vulnzoo.state.current_device 2>/dev/null)}"

if [ "$VULNZOO_DEVICE" != "canary" ]; then
    logger -t canary-cleanup "Skipping cleanup hook for device: ${VULNZOO_DEVICE:-none}"
    exit 0
fi

LOG_FILE="/root/vulnzoo.log"

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [canary-cleanup] $1" >> "$LOG_FILE"
}

log_message "Starting Canary system cleanup..."

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

# Bluetooth stack: not used by Canary.
disable_service "bluetoothd"
disable_service "brcm-bluetooth"
disable_service "btagent"

# Camera / video streaming: not used by Canary.
disable_service "motion"
disable_service "mjpg-streamer"
disable_service "v4l2rtspserver"

# Network services Canary does not expose.
disable_service "miniupnpd"
disable_service "radius"
disable_service "snmpd"

# MQTT broker: pulled into the shared base image for OctoBot. Canary speaks
# SOME/IP over UDP and raw CAN, never MQTT, so mosquitto is dead weight here.
disable_service "mosquitto"

# File sharing and network discovery: not used by Canary. The shared base image
# ships two SMB servers (samba4's smbd/nmbd on :139 + :137-:138 and the kernel
# ksmbd on :445), the WS-Discovery/LLMNR responder wsdd2 (:5355 + :3702) that
# advertises those shares to Windows, and avahi mDNS. Canary exposes only its
# SOME/IP UDP endpoints and addresses everything by raw IP, so all four are dead
# weight.
disable_service "samba4"
disable_service "ksmbd"
disable_service "wsdd2"
disable_service "avahi-daemon"

# dbus is typically only needed by BlueZ on these images.
# Disable it after the Bluetooth services; if another component needs it,
# procd or manual start will still work.
disable_service "dbus"

# Wi-Fi access point daemon: Canary is an Ethernet-only lab (Pi at 192.168.2.1
# on eth0, tester reaches SOME/IP over Ethernet and CAN over a USB-CAN adapter),
# so the wireless stack is unused and wpad only leaves an idle hostapd/supplicant
# running. Disable it to shrink the attack surface.
disable_service "wpad"

# Attempt opkg removal of the related packages. If a package is baked into
# the Squashfs base image this only records the removal in the overlay, but
# it prevents the service from being re-enabled on a firstboot reset.
if command -v opkg >/dev/null 2>&1; then
    for pkg in bluez-daemon bluez-libs motion mjpg-streamer v4l2rtspserver \
               miniupnpd freeradius3-common freeradius3 snmpd snmp-mibs \
               mosquitto-nossl mosquitto-client-nossl \
               samba4-server samba4-libs ksmbd-server kmod-fs-ksmbd wsdd2 \
               avahi-dbus-daemon libavahi-client libavahi-dbus-support \
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

log_message "Canary system cleanup completed."
exit 0
