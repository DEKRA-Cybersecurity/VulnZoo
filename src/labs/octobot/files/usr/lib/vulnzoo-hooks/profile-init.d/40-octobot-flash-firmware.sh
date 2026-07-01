#!/bin/sh
# 40-octobot-flash-firmware.sh - conditional, idempotent Arduino flash.
# Runs BEFORE 50-octobot-services, so the serial bus is not yet holding the tty.
LOG=/root/vulnzoo.log
HEX=/opt/octobot/firmware/robot_arm.hex
STAMP=/tmp/octobot/flashed.md5

HW=$(uci -q get octobot.main.use_real_hardware)
DEV=$(uci -q get octobot.main.serial_port)

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [octobot] $1" >> "$LOG_FILE"
}

[ "$HW" = "1" ] || { log_message "Flash skipped (simulation mode)"; exit 0; }
[ -e "$DEV" ]    || { log_message "Flash skipped (no $DEV)"; exit 0; }
[ -f "$HEX" ]    || { log_message "Flash skipped (no $HEX)"; exit 0; }
command -v avrdude >/dev/null 2>&1 || { log_message "Avrdude missing"; exit 0; }

SUM=$(md5sum "$HEX" | awk '{print $1}')
if [ -f "$STAMP" ] && [ "$(cat "$STAMP")" = "$SUM" ]; then
	log_message "Firmware up to date, no reflash"
	exit 0
fi

log_message "Flashing $HEX -> $DEV"
avrdude -c arduino -p atmega328p -P "$DEV" -b 115200 -U flash:w:"$HEX":i >> "$LOG" 2>&1 \
	&& mkdir -p /tmp/octobot && echo "$SUM" > "$STAMP"
exit 0
