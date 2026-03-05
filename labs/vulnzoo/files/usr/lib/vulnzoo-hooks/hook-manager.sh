#!/bin/sh

# VulnZoo Hook Manager - Idempotent Profile Initialization System
# This script manages the execution of device-specific hooks in an idempotent manner
# Unlike uci-defaults, these hooks can be run multiple times safely

HOOKS_DIR="/usr/lib/vulnzoo-hooks/profile-init.d"
EXECUTION_LOG="/usr/lib/vulnzoo-hooks/execution.log"
UCI_PREFIX="vulnzoo.hooks"

# Initialize UCI hooks section if it doesn't exist
init_uci_hooks() {
    if ! uci -q get vulnzoo.hooks >/dev/null 2>&1; then
        uci set vulnzoo.hooks=section
        uci commit vulnzoo
    fi
}

# Log hook execution
log_hook() {
    local hook="$1"
    local action="$2"
    local result="$3"
    local timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    
    echo "[$timestamp] HOOK: $hook ACTION: $action RESULT: $result" >> "$EXECUTION_LOG"
}

# Check if hook has been executed for current device profile
is_hook_executed() {
    local hook="$1"
    local device="$2"
    local hook_key="${device}_$(basename "$hook" .sh)"

    uci -q get vulnzoo.hooks.${hook_key} >/dev/null 2>&1
}

# Mark hook as executed
mark_hook_executed() {
    local hook="$1"
    local device="$2"
    local timestamp="$(date +%s)"
    local hook_key="${device}_$(basename "$hook" .sh)"
    
    uci set vulnzoo.hooks.${hook_key}=$timestamp
    uci commit vulnzoo
    log_hook "$hook" "MARKED_EXECUTED" "SUCCESS"
}

# Execute hooks for a specific device
execute_device_hooks() {
    local device="$1"
    local force_run="$2"  # if "force", ignore execution marks
    
    if [ ! -d "$HOOKS_DIR" ]; then
        log_hook "SYSTEM" "NO_HOOKS_DIR" "WARNING"
        return 0
    fi
    
    init_uci_hooks
    
    log_hook "DEVICE_$device" "START_INIT" "INFO"
    
    local executed_count=0
    local skipped_count=0
    local failed_count=0
    
    # Execute hooks in alphabetical order
    for hook in "$HOOKS_DIR"/*.sh; do
        if [ ! -f "$hook" ] || [ ! -x "$hook" ]; then
            continue
        fi
        
        local hook_name="$(basename "$hook")"
        
        # Check if hook should be skipped (already executed and not forced)
        if [ "$force_run" != "force" ] && is_hook_executed "$hook" "$device"; then
            log_hook "$hook_name" "SKIPPED" "ALREADY_EXECUTED"
            skipped_count=$((skipped_count + 1))
            continue
        fi
        
        # Execute the hook
        log_hook "$hook_name" "EXECUTING" "START"
        
        # Export device name for hooks (environment variable takes precedence over UCI)
        export VULNZOO_DEVICE="$device"
        
        if "$hook" >> "$EXECUTION_LOG" 2>&1; then
            mark_hook_executed "$hook" "$device"
            log_hook "$hook_name" "EXECUTED" "SUCCESS"
            executed_count=$((executed_count + 1))
        else
            log_hook "$hook_name" "EXECUTED" "FAILED"
            failed_count=$((failed_count + 1))
        fi
    done
    
    log_hook "DEVICE_$device" "FINISHED_INIT" "executed=$executed_count skipped=$skipped_count failed=$failed_count"
    
    return $failed_count
}

# List hooks and their status
list_hooks_status() {
    local device="$1"
    
    echo "Hook execution status for device: $device"
    echo "========================================="
    
    if [ ! -d "$HOOKS_DIR" ]; then
        echo "No hooks directory found."
        return 0
    fi
    
    for hook in "$HOOKS_DIR"/*.sh; do
        if [ ! -f "$hook" ] || [ ! -x "$hook" ]; then
            continue
        fi
        
        local hook_name="$(basename "$hook")"
        if is_hook_executed "$hook" "$device"; then
            local hook_key="${device}_$(basename "$hook" .sh)"
            local timestamp="$(uci -q get "${UCI_PREFIX}.${hook_key}" 2>/dev/null || echo "unknown")"
            local readable_time="$(date -d "@$timestamp" 2>/dev/null || echo "unknown time")"
            echo "$hook_name: EXECUTED ($readable_time)"
        else
            echo "$hook_name: NOT_EXECUTED"
        fi
    done
}

# Main command handler
case "$1" in
    "init")
        device="$2"
        force="$3"
        if [ -z "$device" ]; then
            echo "Usage: $0 init <device_name> [force]"
            exit 1
        fi
        execute_device_hooks "$device" "$force"
        ;;
    "status")
        device="$2"
        if [ -z "$device" ]; then
            echo "Usage: $0 status <device_name>"
            exit 1
        fi
        list_hooks_status "$device"
        ;;
    *)
        echo "VulnZoo Hook Manager - Idempotent Profile Initialization System"
        echo ""
        echo "Usage: $0 <command> [arguments]"
        echo ""
        echo "Commands:"
        echo "  init <device> [force]     Initialize device profile hooks"
        echo "  status <device>           Show hook execution status for device"
        echo ""
        echo "Directories:"
        echo "  Init hooks:    $HOOKS_DIR"
        echo ""
        echo "Environment variables for hooks:"
        echo "  VULNZOO_DEVICE          Current device name being processed"
        exit 1
        ;;
esac
