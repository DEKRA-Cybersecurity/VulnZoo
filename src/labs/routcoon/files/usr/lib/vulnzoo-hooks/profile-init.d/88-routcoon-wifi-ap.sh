#!/bin/sh
#
# VulnZoo RoutCoon Wi-Fi AP Hook
# Brings up an intentionally weak WPA2-PSK access point on the onboard radio so an
# attacker can reach the router's vulnerable services over the air. The AP is its
# own network (192.168.3.0/24), the router is the gateway, and the services already
# listen on 0.0.0.0 so they answer at 192.168.3.1 for any associated client.
#

VULNZOO_DEVICE="${VULNZOO_DEVICE:-$(uci -q get vulnzoo.state.current_device 2>/dev/null)}"

HOOK_NAME="routcoon-wifi-ap"
HOOK_VERSION="1.0"
LOG_FILE="/root/vulnzoo.log"

# --- lab-tunable knobs (the intentional weakness lives here) ----------------
AP_SSID="RoutCoon"
# ponytail: weak PSK on purpose, present in rockyou so the captured handshake
#           cracks offline. Change AP_PSK to retarget the crack exercise.
AP_PSK="password123"
AP_CHANNEL="6"
AP_COUNTRY="US"
# ponytail: force 2.4GHz + NOHT. Board-detect leaves the CYW43455 on band=5g/VHT80,
#           and the brcmfmac FullMAC driver then rejects the HT capabilities hostapd
#           generates ("Driver does not support configured HT capability
#           [SHORT-GI-40]"), which leaves the AP DISABLED. 802.11g on ch6 comes up.
AP_BAND="2g"
AP_HTMODE="NOHT"
AP_NET="wlan"
AP_IP="192.168.3.1"
AP_MASK="255.255.255.0"
AP_DHCP_START="100"
AP_DHCP_LIMIT="150"
# ---------------------------------------------------------------------------

hook_log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$$] [$HOOK_NAME] $1" >> "$LOG_FILE"
}

# Only run for routcoon.
if [ "$VULNZOO_DEVICE" != "routcoon" ]; then
    hook_log "Skipping wifi-ap config for device: $VULNZOO_DEVICE"
    exit 0
fi

# Generate /etc/config/wireless from the detected radio if board-detect has not
# produced it yet.
if [ ! -s /etc/config/wireless ]; then
    wifi config >/dev/null 2>&1
fi

# First wifi-device (radio0 on the Pi onboard brcmfmac).
RADIO="$(uci -q show wireless | sed -n 's/^wireless\.\([^.]*\)=wifi-device$/\1/p' | head -n1)"
if [ -z "$RADIO" ]; then
    hook_log "WARNING: no wifi-device found (no radio detected). AP not started. A Pi 3B/3B+ onboard chip or a USB Wi-Fi adapter is required."
    exit 0
fi

# --- network: dedicated AP interface ---------------------------------------
uci set network.${AP_NET}=interface
uci set network.${AP_NET}.proto='static'
uci set network.${AP_NET}.ipaddr="$AP_IP"
uci set network.${AP_NET}.netmask="$AP_MASK"

# --- dhcp: pool for AP clients ---------------------------------------------
uci set dhcp.${AP_NET}=dhcp
uci set dhcp.${AP_NET}.interface="$AP_NET"
uci set dhcp.${AP_NET}.start="$AP_DHCP_START"
uci set dhcp.${AP_NET}.limit="$AP_DHCP_LIMIT"
uci set dhcp.${AP_NET}.leasetime='12h'

# --- wireless: radio up in AP mode -----------------------------------------
uci set wireless.${RADIO}.disabled='0'
uci set wireless.${RADIO}.band="$AP_BAND"
uci set wireless.${RADIO}.channel="$AP_CHANNEL"
uci set wireless.${RADIO}.htmode="$AP_HTMODE"
uci set wireless.${RADIO}.country="$AP_COUNTRY"

# Replace any board-detect default iface with our AP iface.
while uci -q delete wireless.@wifi-iface[0]; do :; done
uci add wireless wifi-iface >/dev/null
uci set wireless.@wifi-iface[-1].device="$RADIO"
uci set wireless.@wifi-iface[-1].mode='ap'
uci set wireless.@wifi-iface[-1].network="$AP_NET"
uci set wireless.@wifi-iface[-1].ssid="$AP_SSID"
uci set wireless.@wifi-iface[-1].encryption='psk2'
uci set wireless.@wifi-iface[-1].key="$AP_PSK"

# --- firewall: put the AP net in the lan zone so services are reachable -----
i=0
LANZONE=""
while uci -q get firewall.@zone[$i] >/dev/null 2>&1; do
    if [ "$(uci -q get firewall.@zone[$i].name)" = "lan" ]; then
        LANZONE="@zone[$i]"
        break
    fi
    i=$((i + 1))
done
if [ -n "$LANZONE" ]; then
    uci -q add_list firewall.${LANZONE}.network="$AP_NET"
else
    hook_log "WARNING: no 'lan' firewall zone found, AP net left unzoned."
fi

uci commit network
uci commit dhcp
uci commit wireless
uci commit firewall

/etc/init.d/network reload
/etc/init.d/dnsmasq restart
wifi reload

hook_log "AP '${AP_SSID}' up on ${RADIO} (WPA2-PSK), net ${AP_IP}/24, DHCP .${AP_DHCP_START}-.$((AP_DHCP_START + AP_DHCP_LIMIT - 1))"
