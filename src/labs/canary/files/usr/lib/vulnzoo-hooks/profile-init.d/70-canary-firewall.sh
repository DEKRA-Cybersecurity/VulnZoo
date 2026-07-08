#!/bin/sh
# 70-canary-firewall.sh - expose the SOME/IP service on the LAN (deliberately permissive).
# The CAN bus is reached with the tester's own USB-CAN adapter, so only the
# SOME/IP UDP endpoint needs a LAN rule here.
LOG=/root/vulnzoo.log

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [canary] $1" >> "$LOG_FILE"
}

log_message "firewall setup"

add_rule() {
	local name="$1" port="$2" proto="$3"
	# named section so delete+recreate is idempotent (no duplicate rules on re-load)
	uci -q delete firewall.canary_$name
	uci set firewall.canary_$name=rule
	uci set firewall.canary_$name.name="canary-$name"
	uci set firewall.canary_$name.src='lan'
	uci set firewall.canary_$name.proto="$proto"
	uci set firewall.canary_$name.dest_port="$port"
	uci set firewall.canary_$name.target='ACCEPT'
}

add_rule someip "$(uci -q get canary.main.someip_port)" udp
uci commit firewall
/etc/init.d/firewall reload >> "$LOG" 2>&1
exit 0
