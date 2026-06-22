#!/bin/sh
# 40-octobot-flash-firmware.sh - conditional, idempotent Arduino flash.
# Runs BEFORE 50-octobot-services, so the serial bus is not yet holding the tty.
LOG=/root/vulnzoo.log
HEX=/opt/octobot/firmware/robot_arm.hex
STAMP=/tmp/octobot/flashed.md5

HW=$(uci -q get octobot.main.use_real_hardware)
DEV=$(uci -q get octobot.main.serial_port)

[ "$HW" = "1" ] || { echo "[octobot] flash skipped (simulation mode)" >> "$LOG"; exit 0; }
[ -e "$DEV" ]    || { echo "[octobot] flash skipped (no $DEV)" >> "$LOG"; exit 0; }
[ -f "$HEX" ]    || { echo "[octobot] flash skipped (no $HEX)" >> "$LOG"; exit 0; }
command -v avrdude >/dev/null 2>&1 || { echo "[octobot] avrdude missing" >> "$LOG"; exit 0; }

SUM=$(md5sum "$HEX" | awk '{print $1}')
if [ -f "$STAMP" ] && [ "$(cat "$STAMP")" = "$SUM" ]; then
	echo "[octobot] firmware up to date, no reflash" >> "$LOG"
	exit 0
fi

echo "[octobot] flashing $HEX -> $DEV" >> "$LOG"
avrdude -c arduino -p atmega328p -P "$DEV" -b 115200 -U flash:w:"$HEX":i >> "$LOG" 2>&1 \
	&& mkdir -p /tmp/octobot && echo "$SUM" > "$STAMP"
exit 0
