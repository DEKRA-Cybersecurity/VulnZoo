#!/bin/sh
# 99-canary-can-overlay.sh - ensure the MCP2515 device-tree overlays are in the Pi
# boot config, then reboot so they take effect.
#
# Runs LAST. Overlays are read by the firmware at boot, so the first load writes
# them and reboots. After the reboot the canary-can service (enabled) brings the
# lab up in hardware mode on its own, no hook re-run needed. Idempotent: it only
# reboots the time it actually adds the overlays (guarded), so no boot loop.
# Values come from UCI so the crystal and INT pins are configurable.
LOG=/root/vulnzoo.log

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [canary] $1" >> "$LOG_FILE"
}

BOOT=/boot/config.txt
if [ ! -f "$BOOT" ]; then
	log_message "no $BOOT (not a Pi boot layout), skipping CAN overlay"
	exit 0
fi

OSC="$(uci -q get canary.main.oscillator)"; OSC="${OSC:-8000000}"
CGW="$(uci -q get canary.main.cgw_iface)"; CGW="${CGW:-can0}"
BCM="$(uci -q get canary.main.bcm_iface)"; BCM="${BCM:-can1}"
CGW_INT="$(uci -q get canary.main.cgw_int)"; CGW_INT="${CGW_INT:-25}"
BCM_INT="$(uci -q get canary.main.bcm_int)"; BCM_INT="${BCM_INT:-24}"

changed=0
ensure() {
	# append line $1 only if a line matching pattern $2 is not already present
	if ! grep -qE "$2" "$BOOT"; then
		echo "$1" >> "$BOOT"
		changed=1
		log_message "config.txt += $1"
	fi
}

ensure "dtparam=spi=on" '^[[:space:]]*dtparam=spi=on'
ensure "dtoverlay=mcp2515-$CGW,oscillator=$OSC,interrupt=$CGW_INT" "^[[:space:]]*dtoverlay=mcp2515-$CGW([,[:space:]]|\$)"
ensure "dtoverlay=mcp2515-$BCM,oscillator=$OSC,interrupt=$BCM_INT" "^[[:space:]]*dtoverlay=mcp2515-$BCM([,[:space:]]|\$)"

if [ "$changed" = 1 ]; then
	sync
	if [ "$(uci -q get canary.main.can_overlay_reboot)" = "0" ]; then
		log_message "CAN overlays written to $BOOT. can_overlay_reboot=0: reboot the Pi manually to enter hardware mode."
	else
		log_message "CAN overlays written to $BOOT. Rebooting in 5s so they take effect (canary-can brings up hardware mode on boot)."
		(sleep 5; reboot) &
	fi
else
	log_message "CAN overlays already present in $BOOT"
fi
exit 0
