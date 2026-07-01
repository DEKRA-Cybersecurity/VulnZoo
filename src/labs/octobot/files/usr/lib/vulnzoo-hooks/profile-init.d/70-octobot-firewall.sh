#!/bin/sh
# 70-octobot-firewall.sh - expose the gateway on the LAN (deliberately permissive).
# [IoT:I9] all OT ports reachable from the flat LAN, no segmentation.
LOG=/root/vulnzoo.log

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [octobot] $1" >> "$LOG_FILE"
}

log_message "firewall $(date)" >> "$LOG"

add_rule() {
	local name="$1" port="$2"
	# named section so delete+recreate is idempotent (no duplicate rules on re-load)
	uci -q delete firewall.octobot_$name
	uci set firewall.octobot_$name=rule
	uci set firewall.octobot_$name.name="octobot-$name"
	uci set firewall.octobot_$name.src='lan'
	uci set firewall.octobot_$name.proto='tcp'
	uci set firewall.octobot_$name.dest_port="$port"
	uci set firewall.octobot_$name.target='ACCEPT'
}

add_rule gateway "$(uci -q get octobot.main.http_port)"
add_rule serialbus "$(uci -q get octobot.main.bus_port)"
add_rule modbus "$(uci -q get octobot.main.modbus_port)"
add_rule mqtt 1883
uci commit firewall
/etc/init.d/firewall reload >> "$LOG" 2>&1
exit 0
