#!/bin/sh
# Hook: configure WiFi client (station) mode for the careotter lab.
# The base image ships with WiFi disabled. This hook enables it and
# connects the device to an existing WPA2 network so the lab can
# simulate a realistic home-network environment.

# Enable radio in 2.4GHz mode (brcmfmac sched-scan fails on 5GHz)
uci set wireless.radio0.disabled='0'
uci set wireless.radio0.band='2g'
uci set wireless.radio0.channel='auto'
uci set wireless.radio0.htmode='HT20'
uci set wireless.radio0.country='ES'

# Configure the WiFi interface as a client
uci set wireless.default_radio0.device='radio0'
uci set wireless.default_radio0.mode='sta'
uci set wireless.default_radio0.network='wwan'
uci set wireless.default_radio0.ssid='TuRedWiFi'
uci set wireless.default_radio0.encryption='psk2'
uci set wireless.default_radio0.key='TuPasswordSegura'

# Create network interface for WiFi client (no ifname: netifd assigns it)
uci set network.wwan=interface
uci set network.wwan.proto='dhcp'

# Add wwan to WAN firewall zone without overwriting existing entries
uci -q del_list firewall.@zone[1].network='wwan'
uci add_list firewall.@zone[1].network='wwan'

uci commit wireless
uci commit network
uci commit firewall

wifi down
wifi up