#!/bin/sh
# Hook: rebuild /etc/config/firewall via UCI to match the CareOtter lab
# baseline (file reference: ./firewall_prueba — kept ONLY as documentation,
# this hook is the authoritative source).
#
# The hook is idempotent: every existing firewall section is wiped first and
# the configuration is reconstructed from scratch via `uci` calls. It MUST run
# before 80-wifi.sh, which appends `wwan` to the WAN zone — that step relies
# on the zone layout produced here (zone[0]=lan, zone[1]=wan).

LOG_FILE="/root/vulnzoo.log"
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$$] [firewall] $1" >> "$LOG_FILE"
}

log_message "Resetting /etc/config/firewall and rebuilding via UCI..."

# 1. Wipe every existing anonymous section. UCI section indices renumber after
#    each delete, so we keep deleting [0] until the section type is exhausted.
for section in defaults zone forwarding rule redirect include; do
    while uci -q delete "firewall.@${section}[0]" >/dev/null 2>&1; do :; done
done

# 2. Defaults — fully permissive, IPv6 enabled, no invalid-packet drop.
uci add firewall defaults >/dev/null
uci set firewall.@defaults[0].syn_flood='0'
uci set firewall.@defaults[0].input='ACCEPT'
uci set firewall.@defaults[0].output='ACCEPT'
uci set firewall.@defaults[0].forward='ACCEPT'
uci set firewall.@defaults[0].drop_invalid='0'
uci set firewall.@defaults[0].disable_ipv6='0'

# 3. LAN zone — index [0] after creation.
uci add firewall zone >/dev/null
uci set firewall.@zone[0].name='lan'
uci add_list firewall.@zone[0].network='lan'
uci set firewall.@zone[0].input='ACCEPT'
uci set firewall.@zone[0].output='ACCEPT'
uci set firewall.@zone[0].forward='ACCEPT'

# 4. WAN zone — index [1]. 80-wifi.sh appends 'wwan' to this zone's network list.
uci add firewall zone >/dev/null
uci set firewall.@zone[1].name='wan'
uci add_list firewall.@zone[1].network='wan'
uci add_list firewall.@zone[1].network='wan6'
uci add_list firewall.@zone[1].network='wwan'
uci set firewall.@zone[1].input='ACCEPT'
uci set firewall.@zone[1].output='ACCEPT'
uci set firewall.@zone[1].forward='ACCEPT'
uci set firewall.@zone[1].masq='1'
uci set firewall.@zone[1].mtu_fix='1'

# 5. Bidirectional forwarding lan <-> wan.
uci add firewall forwarding >/dev/null
uci set firewall.@forwarding[0].src='lan'
uci set firewall.@forwarding[0].dest='wan'

uci add firewall forwarding >/dev/null
uci set firewall.@forwarding[1].src='wan'
uci set firewall.@forwarding[1].dest='lan'

# 6. Rule generator — appends a new `config rule` with the supplied fields.
#    Args: <name> <proto> <dest_port> [family]
#       family is optional; pass empty string to skip.
add_rule() {
    name="$1"; proto="$2"; dest_port="$3"; family="$4"
    idx=$(uci add firewall rule)
    uci set "firewall.${idx}.name=${name}"
    uci set "firewall.${idx}.src=wan"
    uci set "firewall.${idx}.proto=${proto}"
    [ -n "$dest_port" ] && uci set "firewall.${idx}.dest_port=${dest_port}"
    [ -n "$family" ]    && uci set "firewall.${idx}.family=${family}"
    uci set "firewall.${idx}.target=ACCEPT"
}

# ICMP — host discovery, traceroute, OS fingerprinting from the WAN side.
add_rule 'Allow-All-ICMP-v4' 'icmp' ''     'ipv4'
add_rule 'Allow-All-ICMPv6'  'icmp' ''     'ipv6'

# Typical IoT/medical-device service ports left wide open. Documented even
# though the WAN zone is ACCEPT by default — kept here so hardening the zone
# later (input=REJECT) preserves the intended attack surface.
add_rule 'Allow-SSH'         'tcp'    '22'
add_rule 'Allow-Telnet'      'tcp'    '23'
add_rule 'Allow-HTTP-HTTPS'  'tcp'    '80 443 8080 8443'
add_rule 'Allow-FTP'         'tcp'    '21'
add_rule 'Allow-SNMP'        'udp'    '161 162'
add_rule 'Allow-MQTT'        'tcp'    '1883 8883'
add_rule 'Allow-CoAP'        'udp'    '5683 5684'
add_rule 'Allow-HL7'         'tcp'    '2575'
add_rule 'Allow-DICOM'       'tcp'    '104 11112'
add_rule 'Allow-Modbus'      'tcp'    '502'
add_rule 'Allow-UPnP-SSDP'   'udp'    '1900'
add_rule 'Allow-mDNS'        'udp'    '5353'
add_rule 'Allow-RTSP'        'tcp'    '554'
add_rule 'Allow-NetBIOS-SMB' 'tcp udp' '137 138 139 445'

# 7. Persist and reload.
uci commit firewall

if [ -x /etc/init.d/firewall ]; then
    /etc/init.d/firewall reload >/dev/null 2>&1 \
        && log_message "firewall reloaded" \
        || log_message "WARN: firewall reload returned non-zero"
else
    log_message "WARN: /etc/init.d/firewall not present — config staged but not applied"
fi

log_message "CareOtter baseline firewall rebuilt via UCI."