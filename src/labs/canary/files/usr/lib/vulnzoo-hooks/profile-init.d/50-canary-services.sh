#!/bin/sh
# 50-canary-services.sh - enable and start the canary services.
# CAN detection and interface bring-up live in the canary-can service (started
# first, and enabled so it self-heals on every boot). The gateway and BCM read
# the resulting use_real_hardware from UCI to pick their interface.
LOG=/root/vulnzoo.log

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [canary] $1" >> "$LOG_FILE"
}

log_message "Starting canary services"
chmod +x /opt/canary/*.py 2>/dev/null

for svc in canary-can canary-gateway canary-bcm; do
	if [ -x "/etc/init.d/$svc" ]; then
		"/etc/init.d/$svc" enable
		"/etc/init.d/$svc" restart
		log_message "Started $svc"
	fi
done
exit 0
