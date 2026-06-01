#!/bin/sh
# install.sh

/etc/init.d/miniupnpd stop 2>/dev/null
uci set upnpd.config.enabled='0'
uci commit upnpd

mkdir -p /etc/miniupnpd

cat > /etc/miniupnpd/miniupnpd.conf << 'EOF'
ext_ifname=eth0
listening_ip=eth0
ext_ip=1.2.3.4
port=5000
enable_upnp=yes
enable_natpmp=yes
secure_mode=no
bitrate_down=10240000
bitrate_up=10240000
uuid=05f16a8d-4cc7-4bb1-a894-98ca59bb3ea0
allow 0-65535 192.168.2.0/24 0-65535
deny 0-65535 0.0.0.0/0 0-65535
lease_file=/var/run/miniupnpd.leases
force_igd_desc_v1=yes
EOF

touch /var/run/miniupnpd.leases

# Iniciar directamente (sin el init script de UCI)
killall miniupnpd 2>/dev/null
sleep 1
start-stop-daemon -S -b -p /var/run/miniupnpd.pid -x /usr/sbin/miniupnpd -- -f /etc/miniupnpd/miniupnpd.conf

# Verificar
sleep 2
if netstat -tulnp | grep -q miniupnpd; then
    echo "[✓] miniupnpd running on port 5000 (UPnP) and 1900 (SSDP)"
    netstat -tulnp | grep miniupnpd
else
    echo "[!] miniupnpd failed to start"
fi