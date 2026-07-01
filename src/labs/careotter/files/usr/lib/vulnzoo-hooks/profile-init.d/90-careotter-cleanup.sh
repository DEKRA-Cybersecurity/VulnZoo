#!/bin/sh
# 90-careotter-cleanup.sh - remove/disable packages and services that are not
# needed by the CareOtter lab but may be present in the shared VulnZoo image.
#
# This hook runs after all CareOtter service hooks so the lab is fully up
# before we trim unused components.

VULNZOO_DEVICE="${VULNZOO_DEVICE:-$(uci -q get vulnzoo.state.current_device 2>/dev/null)}"

if [ "$VULNZOO_DEVICE" != "careotter" ]; then
    logger -t careotter-cleanup "Skipping cleanup hook for device: ${VULNZOO_DEVICE:-none}"
    exit 0
fi

LOG_FILE="/root/vulnzoo.log"

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$$] [careotter-cleanup] $1" >> "$LOG_FILE"
}

log_message "Starting CareOtter system cleanup..."

# mosquitto: pulled into the shared base image for OctoBot; CareOtter does not
# use MQTT, so stop, disable, and (if installed as an overlay package) remove it.
if [ -x /etc/init.d/mosquitto ]; then
    log_message "Stopping and disabling mosquitto service..."
    /etc/init.d/mosquitto stop >/dev/null 2>&1
    /etc/init.d/mosquitto disable >/dev/null 2>&1
    log_message "mosquitto service stopped and disabled"
else
    log_message "mosquitto init script not present; nothing to stop/disable"
fi

# Attempt opkg removal. If mosquitto is baked into the Squashfs base image this
# only records the removal in the overlay and does not delete the read-only
# files, but it prevents the service from being enabled on a firstboot reset.
if command -v opkg >/dev/null 2>&1; then
    if opkg list-installed 2>/dev/null | grep -q '^mosquitto'; then
        log_message "Removing mosquitto package(s) from overlay..."
        opkg remove mosquitto-nossl mosquitto-client-nossl 2>/dev/null \
            && log_message "mosquitto package(s) removed from overlay" \
            || log_message "mosquitto package removal returned non-zero (may be Squashfs-baked)"
    else
        log_message "No mosquitto package installed in overlay"
    fi
else
    log_message "opkg not available; skipping package removal"
fi

# Future cleanups go here: stop/disable/remove other lab-foreign services or
# packages that end up in the shared image but are not used by CareOtter.

log_message "CareOtter system cleanup completed."
exit 0
