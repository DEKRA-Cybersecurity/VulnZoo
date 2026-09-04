#!/bin/sh
# 90-bulbbee-cleanup.sh - stop lab-foreign services and remove their packages
# (opkg) that are baked into the shared VulnZoo base image but are NOT used by
# the BulbBee smart-light lab.
#
# Runs after all BulbBee service hooks (45-bulbbee-light, 50-bulbbee-ble) so the
# lab is fully up before unused components are trimmed.
#
# Basis: the services observed on a freshly loaded BulbBee image (netstat):
#   KEEP  dnsmasq (:53/:67 LAN DHCP+DNS), dropbear (:22 SSH),
#         uhttpd (:8080 VulnZoo Device Manager), python3 (:8082 lighting
#         service), plus BlueZ for the BLE control channel.
#   TRIM  samba4 smbd/nmbd (:139/:137/:138) + kernel ksmbd (:445) SMB shares,
#         wsdd2 (:5355/:3702 WS-Discovery), avahi-daemon (:5353 mDNS),
#         mosquitto (:1883 MQTT broker) - BulbBee shares nothing over SMB, needs
#         no service discovery, and its shipped code does not use MQTT.

VULNZOO_DEVICE="${VULNZOO_DEVICE:-$(uci -q get vulnzoo.state.current_device 2>/dev/null)}"

if [ "$VULNZOO_DEVICE" != "bulbbee" ]; then
    logger -t bulbbee-cleanup "Skipping cleanup hook for device: ${VULNZOO_DEVICE:-none}"
    exit 0
fi

LOG_FILE="/root/vulnzoo.log"

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$$] [bulbbee-cleanup] $1" >> "$LOG_FILE"
}

log_message "Starting BulbBee system cleanup..."

# 1. Stop and disable the lab-foreign services so their ports close now and they
#    do not come back on the next boot of this profile.
for svc in mosquitto samba4 ksmbd wsdd2 avahi-daemon; do
    if [ -x /etc/init.d/$svc ]; then
        log_message "Stopping and disabling lab-foreign service: $svc"
        /etc/init.d/$svc stop >/dev/null 2>&1
        /etc/init.d/$svc disable >/dev/null 2>&1
    else
        log_message "Service $svc not present; nothing to stop/disable"
    fi
done

# 2. Remove the corresponding packages with opkg. Best-effort: if a package is
#    baked into the read-only Squashfs base image the removal is only recorded in
#    the overlay (the files are not deleted), which still keeps the service from
#    being re-enabled on this profile. Servers are removed before their libs so
#    the dependency order is satisfied. A non-zero result (dependents, or a
#    Squashfs-baked package) is logged, not fatal.
if command -v opkg >/dev/null 2>&1; then
    for pkg in \
        mosquitto-nossl mosquitto-client-nossl mosquitto-ssl mosquitto-client-ssl \
        samba4-server samba4-client samba4-admin samba4-libs \
        ksmbd-server \
        wsdd2 \
        avahi-daemon avahi-dbus-daemon avahi-nodbus-daemon avahi-utils; do
        if opkg list-installed 2>/dev/null | grep -q "^$pkg "; then
            log_message "Removing package: $pkg"
            if opkg remove "$pkg" >/dev/null 2>&1; then
                log_message "Package $pkg removed from overlay"
            else
                log_message "Package $pkg removal returned non-zero (dependents or Squashfs-baked)"
            fi
        fi
    done
else
    log_message "opkg not available; skipping package removal"
fi

log_message "BulbBee system cleanup completed."
exit 0
