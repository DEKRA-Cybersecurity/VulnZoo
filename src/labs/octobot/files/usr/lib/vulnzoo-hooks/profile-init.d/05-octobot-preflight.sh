#!/bin/sh
# 05-octobot-preflight.sh - workspace + serial-device detection.
LOG=/root/vulnzoo.log
echo "[octobot] preflight $(date)" >> "$LOG"

mkdir -p /tmp/octobot

DEV=""
i=0
while [ "$i" -lt 16 ]; do            # up to ~8s for a slow CH340/FTDI to enumerate
	for d in /dev/ttyACM0 /dev/ttyACM1 /dev/ttyUSB0 /dev/ttyUSB1; do
		[ -e "$d" ] && DEV="$d" && break
	done
	[ -n "$DEV" ] && break
	i=$((i + 1))
	sleep 0.5
done

if [ -n "$DEV" ]; then
	echo "[octobot] serial device detected: $DEV" >> "$LOG"
	uci -q set octobot.main.serial_port="$DEV"
	uci -q set octobot.main.use_real_hardware='1'
else
	echo "[octobot] no serial device, simulation mode" >> "$LOG"
	uci -q set octobot.main.use_real_hardware='0'
fi
uci -q commit octobot
exit 0
