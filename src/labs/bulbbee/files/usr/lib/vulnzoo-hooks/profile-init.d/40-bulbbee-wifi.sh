#!/bin/sh
#
# BulbBee WiFi client hook (40-bulbbee-wifi.sh)
#
# Idempotently joins the Pi to a WiFi network as a client (STA) using the
# credentials provisioned over BLE (the client side of BULB-01). Persistent
# across reboots and lab reloads: the creds live in the `bulbbee_wifi` uci
# config, which is NOT shipped in the device tarball, so the base cold-boot
# re-extraction does not wipe them. This hook rebuilds the live station config
# from those creds on every boot/load, so it works on any image.
#
# The management network stays on Ethernet (lan, 192.168.2.1). This only adds a
# `wwan` DHCP client interface on radio0 and disables AP ifaces on that radio to
# avoid an AP+STA channel conflict (the AP is unused, management is Ethernet).
#

VULNZOO_DEVICE="${VULNZOO_DEVICE:-$(uci -q get vulnzoo.state.current_device 2>/dev/null)}"
if [ "$VULNZOO_DEVICE" != "bulbbee" ]; then
    logger -t bulbbee-wifi "Skipping WiFi hook for device: ${VULNZOO_DEVICE:-none}"
    exit 0
fi

LOG_FILE="/root/vulnzoo.log"
log() { echo "$(date '+%Y-%m-%d %H:%M:%S') [$$] [bulbbee-wifi] $1" >> "$LOG_FILE"; }

RADIO=radio0
STA=bulbbee_sta

# 1. Persistent creds store (survives reboot + lab reload; not in the tarball).
[ -f /etc/config/bulbbee_wifi ] || : > /etc/config/bulbbee_wifi
uci -q get bulbbee_wifi.sta >/dev/null 2>&1 || { uci set bulbbee_wifi.sta=creds; uci commit bulbbee_wifi; }
SSID="$(uci -q get bulbbee_wifi.sta.ssid)"
PSK="$(uci -q get bulbbee_wifi.sta.psk)"

# 2. wwan network (DHCP client).
if ! uci -q get network.wwan >/dev/null 2>&1; then
    uci set network.wwan=interface
    uci set network.wwan.proto=dhcp
    uci commit network
    log "created network.wwan (dhcp)"
fi

# 3. Firewall: add wwan to the 'wan' zone (routing/masq), by name, not index.
z=0
while uci -q get firewall.@zone[$z] >/dev/null 2>&1; do
    if [ "$(uci -q get firewall.@zone[$z].name)" = "wan" ]; then
        case " $(uci -q get firewall.@zone[$z].network) " in
            *" wwan "*) : ;;
            *) uci add_list firewall.@zone[$z].network=wwan; uci commit firewall; log "added wwan to wan zone" ;;
        esac
        break
    fi
    z=$((z + 1))
done

# 4. Enable the radio and disable AP ifaces on it (avoid AP+STA channel clash).
uci set wireless.$RADIO.disabled=0
uci set wireless.$RADIO.channel=auto
# Regulatory domain and band are optional overrides from bulbbee_wifi. A country
# is required for 5GHz to open its channels; band lets you force 2.4GHz (2g),
# which is far more reliable than 5GHz on the Pi 3B+ Cypress chip.
COUNTRY="$(uci -q get bulbbee_wifi.sta.country)"; [ -n "$COUNTRY" ] && uci set wireless.$RADIO.country="$COUNTRY"
BAND="$(uci -q get bulbbee_wifi.sta.band)"; [ -n "$BAND" ] && uci set wireless.$RADIO.band="$BAND"
i=0
while uci -q get wireless.@wifi-iface[$i] >/dev/null 2>&1; do
    if [ "$(uci -q get wireless.@wifi-iface[$i].device)" = "$RADIO" ] \
       && [ "$(uci -q get wireless.@wifi-iface[$i].mode)" = "ap" ]; then
        uci set wireless.@wifi-iface[$i].disabled=1
    fi
    i=$((i + 1))
done

# 5. Ensure our dedicated STA wifi-iface exists.
if ! uci -q get wireless.$STA >/dev/null 2>&1; then
    uci set wireless.$STA=wifi-iface
    uci set wireless.$STA.device=$RADIO
    uci set wireless.$STA.mode=sta
    uci set wireless.$STA.network=wwan
    log "created STA wifi-iface $STA"
fi

# 6. Apply the provisioned creds if present, otherwise leave the STA disabled.
if [ -n "$SSID" ]; then
    uci set wireless.$STA.ssid="$SSID"
    if [ -n "$PSK" ]; then
        uci set wireless.$STA.encryption=psk2
        uci set wireless.$STA.key="$PSK"
    else
        uci set wireless.$STA.encryption=none
        uci -q delete wireless.$STA.key
    fi
    uci set wireless.$STA.disabled=0
    log "STA configured for SSID=$SSID"
else
    uci set wireless.$STA.disabled=1
    log "no creds yet, STA left disabled"
fi

uci commit wireless
uci commit network

# 7. Bring up wireless. netifd brings up the wwan (dhcp) L3 by itself once the
# STA associates, because the wifi-iface declares `network wwan`. Do NOT reload
# the whole network stack here: on this board that hangs netifd with eth0/SSH
# active and trips the procd watchdog into a reboot.
wifi reload 2>/dev/null
[ -n "$SSID" ] && log "wifi reload done, joining $SSID"
exit 0
