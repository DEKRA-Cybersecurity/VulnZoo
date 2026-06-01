#!/bin/sh
#
# VulnZoo Router Firewall Hook
# Añade reglas de firewall específicas del laboratorio sin eliminar configuraciones existentes
#

VULNZOO_DEVICE="${VULNZOO_DEVICE:-$(uci -q get vulnzoo.state.current_device 2>/dev/null)}"

HOOK_NAME="router-firewall-config"
HOOK_VERSION="1.0"
LOG_FILE="/root/vulnzoo.log"

# Logging
hook_log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$$] [$HOOK_NAME] $1" >> "$LOG_FILE"
}

# Only run for routcoon device
if [ "$VULNZOO_DEVICE" != "routcoon" ]; then
    hook_log "Skipping firewall config for device: $VULNZOO_DEVICE"
    exit 0
fi

hook_log "Añadiendo reglas de firewall para FTP en el router vulnerable"

# Añadir regla para permitir FTP en la LAN (puerto 21 TCP)
uci add firewall rule
uci set firewall.@rule[-1].name='Allow-FTP'
uci set firewall.@rule[-1].src='lan'
uci set firewall.@rule[-1].dest_port='21'
uci set firewall.@rule[-1].target='ACCEPT'
uci set firewall.@rule[-1].proto='tcp'

uci commit firewall
/etc/init.d/firewall restart

hook_log "Reglas de firewall aplicadas correctamente"
