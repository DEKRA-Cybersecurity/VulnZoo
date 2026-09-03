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
uci set wireless.default_radio0.ssid='YourSSID'
uci set wireless.default_radio0.encryption='psk2'
uci set wireless.default_radio0.key='YourPassword'

# Create network interface for WiFi client (no ifname: netifd assigns it)
uci set network.wwan=interface
uci set network.wwan.proto='dhcp'

# Add wwan to WAN firewall zone without overwriting existing entries
uci -q del_list firewall.@zone[1].network='wwan'
uci add_list firewall.@zone[1].network='wwan'

uci commit wireless
uci commit network
uci commit firewall

# Unload foreign out-of-tree Realtek USB-WiFi drivers before bringing WiFi up.
# The shared image bundles them but no Realtek device is attached here; their
# netdevice-rename notifier (rtl8812au rtw_proc.c:1225) oopses when the onboard
# brcmfmac is renamed wlan0 -> phy0-sta0 by 'wifi up', and with panic_on_oops=1
# that panics/reboots the board. rmmod is a no-op if a driver is in use or absent.
for _m in rtl8812au rtl8192cu rtl8xxxu; do rmmod "$_m" 2>/dev/null; done

wifi down
wifi up