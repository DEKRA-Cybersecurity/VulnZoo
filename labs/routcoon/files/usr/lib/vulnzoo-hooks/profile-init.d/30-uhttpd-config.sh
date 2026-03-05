#!/bin/sh
#
# RoutCoon uHTTPd Configuration Hook
# Configures uhttpd for router lab on port 80
#

VULNZOO_DEVICE="${VULNZOO_DEVICE:-$(uci -q get vulnzoo.state.current_device 2>/dev/null)}"

HOOK_NAME="routcoon-uhttpd-config"
HOOK_VERSION="1.1"
LOG_FILE="/root/vulnzoo.log"

# Logging function
hook_log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$$] [$HOOK_NAME] $1" >> "$LOG_FILE"
}

# Only run for routcoon device
if [ "$VULNZOO_DEVICE" != "routcoon" ]; then
    hook_log "Skipping uhttpd config for device: $VULNZOO_DEVICE"
    exit 0
fi

hook_log "=== Starting $HOOK_NAME v$HOOK_VERSION ==="

# Configure routcoon uhttpd main interface
configure_routcoon_uhttpd() {
    hook_log "Configuring uhttpd for RoutCoon lab (keeping vulnzoo menu on 8080)..."
    
    # Check if main section already exists and delete it to start fresh
    if uci -q get uhttpd.main >/dev/null 2>&1; then
        hook_log "Removing existing uhttpd main configuration"
        uci -q delete uhttpd.main 2>/dev/null || true
    fi
    
    # NOTE: We do NOT delete uhttpd.vulnzoo - it runs the menu on port 8080
    # Both services should coexist:
    # - vulnzoo: port 8080 (menu to switch labs)
    # - main: port 80 (RoutCoon LuCI interface)
    
    # Create main uhttpd configuration for routcoon
    uci set uhttpd.main=uhttpd
    uci set uhttpd.main.home='/www'
    uci set uhttpd.main.rfc1918_filter='0'
    uci set uhttpd.main.max_requests='3'
    uci set uhttpd.main.max_connections='100'
    uci set uhttpd.main.cgi_prefix='/cgi-bin'
    uci set uhttpd.main.lua_prefix='/cgi-bin/lua'
    uci set uhttpd.main.lua_handler='/usr/lib/lua/luci/uhttpd.lua'
    uci set uhttpd.main.script_timeout='60'
    uci set uhttpd.main.network_timeout='30'
    uci set uhttpd.main.http_keepalive='20'
    uci set uhttpd.main.tcp_keepalive='1'
    uci set uhttpd.main.ubus_prefix='/ubus'
    uci set uhttpd.main.x_forwardedfor='1'
    
    # Listen on port 80 (IPv4 and IPv6)
    uci add_list uhttpd.main.listen_http='0.0.0.0:80'
    uci add_list uhttpd.main.listen_http='[::]:80'
    
    # Commit configuration
    if uci commit uhttpd; then
        hook_log "uhttpd configuration committed successfully"
        return 0
    else
        hook_log "ERROR: Failed to commit uhttpd configuration"
        return 1
    fi
}

# Restart uhttpd service
restart_uhttpd() {
    hook_log "Restarting uhttpd service..."
    
    # Stop any existing uhttpd first
    /etc/init.d/uhttpd stop >/dev/null 2>&1
    sleep 1
    
    # Enable and start
    /etc/init.d/uhttpd enable
    if /etc/init.d/uhttpd start >/dev/null 2>&1; then
        hook_log "uhttpd started successfully"
        return 0
    else
        hook_log "ERROR: Failed to start uhttpd"
        return 1
    fi
}

# Verify uhttpd is running on port 80
verify_uhttpd() {
    hook_log "Verifying uhttpd on port 80..."
    
    # Give service time to start
    sleep 2
    
    # Check if listening on port 80
    if netstat -tuln 2>/dev/null | grep -q ':80 '; then
        hook_log "SUCCESS: uhttpd listening on port 80"
        return 0
    else
        hook_log "WARNING: uhttpd not detected on port 80"
        return 1
    fi
}

# Main execution
main() {
    local exit_code=0
    
    if ! configure_routcoon_uhttpd; then
        exit_code=1
    fi
    
    if ! restart_uhttpd; then
        exit_code=1
    fi
    
    verify_uhttpd
    
    if [ $exit_code -eq 0 ]; then
        hook_log "=== $HOOK_NAME completed successfully ==="
    else
        hook_log "=== $HOOK_NAME completed with errors ==="
    fi
    
    return $exit_code
}

main "$@"
