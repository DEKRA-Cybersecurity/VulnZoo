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

uci add_list dhcp.@dnsmasq[0].address='/support.vulnzoo.com/203.0.113.100'
uci commit dhcp

/etc/init.d/dnsmasq restart

hook_log "DNSmasq configuration applied"
