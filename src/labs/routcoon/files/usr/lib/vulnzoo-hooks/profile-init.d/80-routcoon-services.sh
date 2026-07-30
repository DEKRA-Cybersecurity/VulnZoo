#!/bin/sh
#
# RoutCoon Router Lab - Service Initialization Hook
# Starts SNMP, DHCPv6, NTP and UPnP services
#

VULNZOO_DEVICE="${VULNZOO_DEVICE:-$(uci -q get vulnzoo.state.current_device 2>/dev/null)}"

HOOK_NAME="routcoon-services"
HOOK_VERSION="1.0"
LOG_FILE="/root/vulnzoo.log"

log_message() {
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$$] [$HOOK_NAME] $1" >> "$LOG_FILE"
}

# Only run for routcoon device
if [ "$VULNZOO_DEVICE" != "routcoon" ]; then
    log_message "Skipping services initialization for device: $VULNZOO_DEVICE"
    exit 0
fi

log_message "=== Initializing RoutCoon router services ==="

# ===========
# SNMP Daemon
# ===========
if [ -f /etc/init.d/snmpd ]; then
    if [ -f /etc/snmp/snmpd.conf ]; then
        log_message "SNMP config found"
    else
        # Crear config vulnerable si no existe
        mkdir -p /etc/snmp
        cat > /etc/snmp/snmpd.conf << 'EOF'
rocommunity public
rwcommunity private
sysLocation "VulnZoo RoutCoon Lab"
sysContact "admin@vulnzoo.local"
EOF
        log_message "SNMP config created with vulnerable communities"
    fi
    
    /etc/init.d/snmpd enable
    if /etc/init.d/snmpd start; then
        log_message "SNMPd started successfully"
    else
        log_message "WARNING: SNMPd failed to start"
    fi
else
    log_message "ERROR: snmpd init script not found"
fi

# ========
#  DHCPv6
# ========
if [ -f /etc/init.d/odhcpd ]; then
    /etc/init.d/odhcpd enable
    if /etc/init.d/odhcpd start; then
        log_message "DHCPv6 (odhcpd) started successfully"
    else
        log_message "WARNING: odhcpd failed to start"
    fi
else
    log_message "ERROR: odhcpd init script not found"
fi

# ==========
# NTP Daemon
# ==========
if [ -f /etc/init.d/sysntpd ]; then
    /etc/init.d/sysntpd enable
    if /etc/init.d/sysntpd start; then
        log_message "sysntpd started successfully"
    else
        log_message "WARNING: sysntpd failed to start"
    fi
else
    log_message "ERROR: sysntpd init script not found"
fi

log_message "RoutCoon services initialization complete"

# ==========
# FTP Daemon
# ==========
if [ -f /etc/init.d/ftpd ]; then
    chown -R ftp:root /opt/oem-updates/
    chmod 755 /opt/oem-updates/
    chmod 777 /opt/oem-updates/pending/
    /etc/init.d/ftpd enable
    if /etc/init.d/ftpd start; then
        log_message "FTP server started successfully"
    else
        log_message "WARNING: FTP server failed to start"
    fi
else
    log_message "ERROR: ftpd init script not found"
fi

# ==========
# Samba (anonymous SMB guest share)
# ==========
# ponytail: serve the raw vulnerable /etc/samba/samba.conf directly. Two other SMB
# servers fight for :445 and must be stood down first or our 'public' share never
# binds: the samba4 package's own procd service (default config, no share) and
# ksmbd (kernel SMB server) which grabs :445 and answers with an empty config.
# Verified live: with both stopped, our smbd owns :445 and serves 'public'.
mkdir -p /mnt/sdcard/share
chmod 777 /mnt/sdcard/share
if command -v smbd >/dev/null 2>&1; then
    /etc/init.d/ksmbd disable 2>/dev/null
    /etc/init.d/ksmbd stop 2>/dev/null
    /etc/init.d/samba4 disable 2>/dev/null
    /etc/init.d/samba4 stop 2>/dev/null
    killall smbd nmbd 2>/dev/null
    sleep 1
    smbd -s /etc/samba/samba.conf &
    nmbd -s /etc/samba/samba.conf &
    log_message "Samba smbd started (ksmbd + samba4 stood down), guest share 'public' -> /mnt/sdcard/share"
else
    log_message "WARNING: smbd not found (samba4-server not installed), SMB share not started"
fi

exit 0
