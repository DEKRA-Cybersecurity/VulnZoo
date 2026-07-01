#!/bin/sh
# 50-octobot-services.sh - enable and start the OctoBot services.
LOG=/root/vulnzoo.log

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [octobot] $1" >> "$LOG_FILE"
}

log_message "Starting OctoBot services"

chmod +x /opt/octobot/*.py 2>/dev/null

# Serial bus must come up first (owns the tty); the others forward to it.
SERVICES="octobot-serialbus octobot-gateway octobot-modbus"

# MQTT is optional: only start the bridge if the mosquitto broker is installed,
# otherwise the bridge's connect() crash-loops under procd respawn.
if [ -x /etc/init.d/mosquitto ]; then
	/etc/init.d/mosquitto enable
	/etc/init.d/mosquitto restart
	SERVICES="$SERVICES octobot-mqtt"
else
	log_message "Mosquitto not installed; skipping MQTT bridge"
	/etc/init.d/octobot-mqtt disable 2>/dev/null
fi

for svc in $SERVICES; do
	if [ -x "/etc/init.d/$svc" ]; then
		"/etc/init.d/$svc" enable
		"/etc/init.d/$svc" restart
		log_message "Started $svc"
	fi
done
exit 0
