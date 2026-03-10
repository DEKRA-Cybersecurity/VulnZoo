#!/bin/sh

# VulnZoo Device Manager Script
# Manages switching between different vulnerable device profiles

# Simple test - if script is called with no parameters, show info
if [ -z "$REQUEST_METHOD" ]; then
    echo "VulnZoo Device Manager CGI Script"
    echo "This script should be called via HTTP"
    exit 0
fi

# Production mode - use system paths
DEVICES_DIR="/usr/lib/vulnzoo-devices"
LOG_FILE="/root/vulnzoo.log"
EXTRACTION_TARGET="/"

# UCI configuration management functions
get_current_device() {
    uci -q get vulnzoo.state.current_device 2>/dev/null || echo "none"
}

get_loaded_timestamp() {
    uci -q get vulnzoo.state.loaded_timestamp 2>/dev/null || echo ""
}

save_device_state() {
    local device="$1"
    local timestamp="$(date +%s)"
    
    # Update UCI configuration (OpenWrt native way)
    uci -q delete vulnzoo.state 2>/dev/null || true
    uci set vulnzoo.state=section
    uci set vulnzoo.state.current_device="$device"
    uci set vulnzoo.state.loaded_timestamp="$timestamp"
    uci commit vulnzoo
    
    log_message "Device state saved in UCI: $device (timestamp: $timestamp)"
}

clear_device_state() {
    # Clear UCI configuration
    uci -q delete vulnzoo.state 2>/dev/null || true
    uci set vulnzoo.state=section
    uci set vulnzoo.state.current_device="none"
    uci set vulnzoo.state.loaded_timestamp=""
    uci commit vulnzoo
    
    log_message "Device state cleared from UCI"
}

# Logging function
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$$] $1" >> "$LOG_FILE"
}

# Debug logging
log_message "CGI Script called - REQUEST_METHOD: $REQUEST_METHOD"
log_message "QUERY_STRING: $QUERY_STRING"
log_message "Current device from UCI: $(get_current_device)"

load_device() {
    local device_type="$1"
    local device_tar="$DEVICES_DIR/${device_type}.tar.gz"
    local current_device="$(get_current_device)"
    
    log_message "Loading device: $device_type"
    
    if [ ! -f "$device_tar" ]; then
        log_message "ERROR: Device configuration not found: $device_tar"
        echo "Content-Type: application/json"
        echo ""
        echo "{\"success\": false, \"message\": \"Device configuration not found: $device_type\"}"
        return 1
    fi
    
    # Check if device is already loaded
    if [ "$current_device" != "none" ] && [ "$current_device" != "" ]; then
        log_message "There's a device running: $current_device"
        log_message "ERROR: Cannot load new device while another is running"
        echo "Content-Type: application/json"
        echo ""
        echo "{\"success\": false, \"message\": \"Device '$current_device' is currently loaded\"}"
        return 1
    fi
    
    # Extract device configuration with root privileges
    log_message "Extracting device profile: $device_tar"
    if tar -xzf "$device_tar" -C "$EXTRACTION_TARGET" -o 2>/dev/null; then
        log_message "Device profile extracted successfully."
    else
        log_message "ERROR: Failed to extract device profile"
        echo "Content-Type: application/json"
        echo ""
        echo "{\"success\": false, \"message\": \"Failed to extract device profile\"}"
        return 1
    fi
    
    # Execute idempotent hooks instead of uci-defaults
    log_message "Executing VulnZoo idempotent hooks for device: $device_type"
    if [ -x "/usr/lib/vulnzoo-hooks/hook-manager.sh" ]; then
        if /usr/lib/vulnzoo-hooks/hook-manager.sh init "$device_type"; then
            log_message "Idempotent hooks executed successfully for $device_type"
        else
            log_message "WARNING: Some idempotent hooks failed for $device_type (continuing anyway)"
        fi
    else
        log_message "WARNING: Hook manager not found, skipping hook execution"
    fi

    # Execute device rc.local if it exists
    if [ -f "/etc/rc.local" ]; then
        log_message "Executing device rc.local script"
        /etc/rc.local >/dev/null 2>&1 &
        log_message "Device rc.local executed in background"
    else
        log_message "No rc.local found for device $device_type"
    fi
    
    # Restart web services - uhttpd configuration is handled by device hooks
    log_message "Restarting web services after device hooks execution"
    /etc/init.d/uhttpd restart >/dev/null 2>&1
    
    save_device_state "$device_type"

    log_message "Device $device_type loaded successfully"
    echo "Content-Type: application/json"
    echo ""
    echo "{\"success\": true, \"message\": \"Device $device_type loaded successfully\"}"
}

restore_original_system() {
    log_message "Manual system restore requested"
    log_message "Restoring original system configuration using firstboot"
    
    local current_device="$(get_current_device)"
    
    if [ "$current_device" = "none" ] || [ -z "$current_device" ]; then
        log_message "No active device found - system already in original state"
        echo "Content-Type: application/json"
        echo ""
        echo '{"success": true, "message": "System already in original state - no active device"}'
        return 0
    fi
    
    # Clear current device state before factory reset
    clear_device_state
    log_message "Current device state cleared"
    
    # Perform factory reset using firstboot
    log_message "Executing firstboot to restore factory defaults"
    if firstboot -y >/dev/null 2>&1; then
        log_message "Factory reset successful, system will reboot"
        echo "Content-Type: application/json"
        echo ""
        echo '{"success": true, "message": "Factory reset initiated - system will reboot to original state"}'
        
        # Schedule system reboot
        (sleep 2; reboot) &
        return 0
    else
        log_message "ERROR: Failed to execute firstboot"
        echo "Content-Type: application/json"
        echo ""
        echo '{"success": false, "message": "Failed to restore system to factory defaults"}'
        return 1
    fi
}

stop_device() {
    log_message "Stopping current device"
    
    local device_type="$(get_current_device)"
    
    if [ -z "$device_type" ] || [ "$device_type" = "none" ]; then
        log_message "No device currently loaded"
        echo "Content-Type: application/json"
        echo ""
        echo "{\"success\": false, \"message\": \"No device currently loaded\"}"
        return 1
    fi
    
    log_message "Stopping device: $device_type"
    stop_device_internal "$device_type"
    
    # Clear device state from UCI
    clear_device_state
    
    echo "Content-Type: application/json"
    echo ""
    echo "{\"success\": true, \"message\": \"Device $device_type stopped\"}"
}

stop_device_internal() {
    local device_type="$1"
    
    # Restore original system configuration
    log_message "Restoring original system after stopping device: $device_type"
    if restore_original_system; then
        log_message "System successfully restored to original state"
    else
        log_message "WARNING: Failed to restore original system state"
    fi
    
    log_message "Device $device_type stopped and system restored"
}

get_status() {
    local current_device="$(get_current_device)"
    local timestamp="$(get_loaded_timestamp)"
    
    # Use current timestamp as fallback if none stored
    if [ -z "$timestamp" ]; then
        timestamp="$(date +%s)"
    fi
    
    log_message "Getting status - Current device: $current_device"
    
    echo "Content-Type: application/json"
    echo ""
    echo "{\"current_device\": \"$current_device\", \"timestamp\": $timestamp}"
    
    log_message "Status response sent: current_device=$current_device, timestamp=$timestamp"
}

restart_services() {
    log_message "Restarting all services"
    /etc/init.d/uhttpd restart >/dev/null 2>&1
    
    local current_device="$(get_current_device)"
    
    # Restart device-specific services if a device is active
    if [ "$current_device" != "none" ] && [ -n "$current_device" ]; then
        start_device_services "$current_device"
    fi
    
    echo "Content-Type: application/json"
    echo ""
    echo "{\"success\": true, \"message\": \"Services restarted\"}"
}

# Function to safely parse URL parameters
parse_params() {
    local data="$1"
    # Initialize global variables
    action=""
    device=""
    
    # Debug logging
    log_message "Parsing data: $data"
    
    # Split by & and parse each key=value pair
    for param in $(echo "$data" | tr '&' '\n'); do
        if [ -n "$param" ]; then
            key=$(echo "$param" | cut -d'=' -f1)
            value=$(echo "$param" | cut -d'=' -f2- | sed 's/%20/ /g' | sed 's/%3D/=/g')
            
            log_message "Found param: key='$key', value='$value'"
            
            case "$key" in
                "action") action="$value" ;;
                "device") device="$value" ;;
            esac
        fi
    done
    
    log_message "Final parsed values: action='$action', device='$device'"
}

# Main script execution
# Parse query string and POST data
if [ "$REQUEST_METHOD" = "POST" ]; then
    read POST_DATA
    log_message "POST_DATA received: '$POST_DATA'"
    if [ -n "$POST_DATA" ]; then
        parse_params "$POST_DATA"
    else
        log_message "WARNING: Empty POST_DATA"
        action=""
        device=""
    fi
elif [ "$REQUEST_METHOD" = "GET" ]; then
    log_message "QUERY_STRING received: '$QUERY_STRING'"
    if [ -n "$QUERY_STRING" ]; then
        parse_params "$QUERY_STRING"
    else
        log_message "WARNING: Empty QUERY_STRING"
        action=""
        device=""
    fi
else
    log_message "WARNING: Unknown REQUEST_METHOD: '$REQUEST_METHOD'"
    action=""
    device=""
fi

# Log the action
log_message "Action: $action, Device: $device, Method: $REQUEST_METHOD"

case "$action" in
    "load")
        load_device "$device"
        ;;
    "stop") 
        stop_device "$device"
        ;;
    "status"|"get_status")
        get_status
        ;;
    "restart")
        restart_services
        ;;
    *)
        echo "Content-Type: application/json"
        echo ""
        echo '{"success": false, "message": "Invalid action"}'
        ;;
esac
