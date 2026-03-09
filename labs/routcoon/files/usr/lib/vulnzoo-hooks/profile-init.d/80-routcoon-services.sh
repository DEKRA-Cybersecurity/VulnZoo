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
    /etc/init.d/ftpd enable
    if /etc/init.d/ftpd start; then
        log_message "FTP server started successfully"
    else
        log_message "WARNING: FTP server failed to start"
    fi
else
    log_message "ERROR: ftpd init script not found"
fi

exit 0
