#!/bin/sh
#
# VulnZoo Router DNSmasq Hook
# Añade reglas de firewall específicas del laboratorio sin eliminar configuraciones existentes
#

VULNZOO_DEVICE="${VULNZOO_DEVICE:-$(uci -q get vulnzoo.state.current_device 2>/dev/null)}"

HOOK_NAME="dnsmasq-config"
HOOK_VERSION="1.0"
LOG_FILE="/root/vulnzoo.log"

# Logging
hook_log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$$] [$HOOK_NAME] $1" >> "$LOG_FILE"
}

# Only run for routcoon device
if [ "$VULNZOO_DEVICE" != "routcoon" ]; then
    hook_log "Skipping dnsmasq config for device: $VULNZOO_DEVICE"
    exit 0
fi

chmod +x /etc/dnsmasq.script

# RC-V1: realize finding 2.7 (IoT2 DHCP/DNS) in UCI. The monolithic
# /etc/dnsmasq.conf is parked (shipped as dnsmasq.conf.reference) because it
# crash-looped dnsmasq, so these intended-insecure directives are set here in
# UCI where they actually take effect. Option names verified against
# /etc/init.d/dnsmasq (24.10).
# ponytail: this makes a documented-but-dead vuln live, it does not harden.
uci set dhcp.@dnsmasq[0].dhcpscript='/etc/dnsmasq.script'   # root-exec each DHCP event (OpenWrt wrapper runs it, jail-mounted)
uci set dhcp.@dnsmasq[0].leasefile='/tmp/dhcp.leases'       # world-writable lease DB (tampering)
uci set dhcp.@dnsmasq[0].dhcpleasemax='100000'              # no lease ceiling
uci set dhcp.@dnsmasq[0].cachesize='10000'                  # oversized cache
uci set dhcp.@dnsmasq[0].nonegcache='1'
uci set dhcp.@dnsmasq[0].rebind_protection='0'              # allow DNS rebinding (no private-range filtering)
uci set dhcp.@dnsmasq[0].logqueries='1'                     # DNS query history (privacy)
uci set dhcp.@dnsmasq[0].logdhcp='1'

uci add_list dhcp.@dnsmasq[0].address='/support.vulnzoo.com/203.0.113.100'
uci commit dhcp

/etc/init.d/dnsmasq restart

hook_log "DNSmasq configuration applied"
