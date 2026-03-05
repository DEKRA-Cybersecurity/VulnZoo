#!/bin/sh
#
# OwlCam Firewall Configuration Hook
# Sets up firewall rules for camera streaming
#

# Get device name from environment OR from UCI config (fallback)
VULNZOO_DEVICE="${VULNZOO_DEVICE:-$(uci -q get vulnzoo.state.current_device 2>/dev/null)}"

# Only run for owlcam device
if [ "$VULNZOO_DEVICE" != "owlcam" ]; then
    logger -t owlcam-firewall "Skipping firewall config for device: ${VULNZOO_DEVICE:-none}"
    exit 0
fi

logger -t owlcam-firewall "Configuring firewall for owlcam..."

echo "" > /etc/config/firewall

uci add firewall rule
uci set firewall.@rule[-1].name='Allow-HTTP-Stream'
uci set firewall.@rule[-1].src='lan'
uci set firewall.@rule[-1].dest_port='8080'
uci set firewall.@rule[-1].proto='tcp'
uci set firewall.@rule[-1].target='ACCEPT'

uci add firewall rule
uci set firewall.@rule[-1].name='Allow-SSH'
uci set firewall.@rule[-1].src='lan'
uci set firewall.@rule[-1].dest_port='22'
uci set firewall.@rule[-1].proto='tcp'
uci set firewall.@rule[-1].target='ACCEPT'

# Permitir ICMP (ping) en la LAN
uci add firewall rule
uci set firewall.@rule[-1].name='Allow-Ping-LAN'
uci set firewall.@rule[-1].src='lan'
uci set firewall.@rule[-1].proto='icmp'
uci set firewall.@rule[-1].icmp_type='echo-request'
uci set firewall.@rule[-1].target='ACCEPT'

uci add firewall rule
uci set firewall.@rule[-1].name='Block-WAN-Inbound'
uci set firewall.@rule[-1].src='wan'
uci set firewall.@rule[-1].target='DROP'

uci add firewall rule
uci set firewall.@rule[-1].name='Allow-RTSP-Ports'
uci set firewall.@rule[-1].src='lan'
uci set firewall.@rule[-1].dest_port='8554-8557'
uci set firewall.@rule[-1].proto='tcp'
uci set firewall.@rule[-1].target='ACCEPT'

uci add firewall zone
uci set firewall.@zone[-1].name='lan'
uci set firewall.@zone[-1].network='lan'
uci set firewall.@zone[-1].input='ACCEPT'
uci set firewall.@zone[-1].output='ACCEPT'
uci set firewall.@zone[-1].forward='ACCEPT'

uci commit firewall
/etc/init.d/firewall restart

logger -t owlcam-firewall "Firewall configuration completed"
