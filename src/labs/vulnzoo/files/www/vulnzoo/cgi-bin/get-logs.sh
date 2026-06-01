#!/bin/sh

echo "Content-Type: text/plain"
echo ""

echo "=== VulnZoo System Logs ==="
echo "Generated: $(date)"
echo ""

# VulnZoo specific logs
if [ -f /root/vulnzoo.log ]; then
    echo "--- VulnZoo Activity Log ---"
    tail -50 /root/vulnzoo.log
    echo ""
else
    echo "--- VulnZoo Activity Log ---"
    echo "No VulnZoo activity log found"
    echo ""
fi

# Current device status
echo "--- Current Device Status ---"
# Variables should be available from environment, but load from profile as fallback
if [ -z "$VULNZOO_CURRENT_DEVICE" ]; then
    # Source profile to get variables if not already in environment
    . /etc/profile 2>/dev/null || true
fi

if [ "$VULNZOO_CURRENT_DEVICE" != "none" ] && [ -n "$VULNZOO_CURRENT_DEVICE" ]; then
    echo "Active device: $VULNZOO_CURRENT_DEVICE"
    echo "Loaded timestamp: $(date -d @$VULNZOO_LOADED_TIMESTAMP 2>/dev/null || echo "Unknown")"
else
    echo "No active device"
fi
echo ""

# Available profiles
echo "--- Available Device Profiles ---"
if [ -d /overlay/vulnzoo-devices ]; then
    profile_count=$(ls -1 /overlay/vulnzoo-devices/*.tar.gz 2>/dev/null | wc -l)
    echo "Total profiles: $profile_count"
    ls -1 /overlay/vulnzoo-devices/*.tar.gz 2>/dev/null | sed 's|.*/||; s|\.tar\.gz$||' | sed 's/^/  - /'
else
    echo "Profiles directory not found"
fi
echo ""

# System messages
echo "--- System Messages ---"
if [ -f /var/log/messages ]; then
    tail -20 /var/log/messages
elif command -v dmesg >/dev/null; then
    dmesg | tail -20
else
    echo "No system messages available"
fi
echo ""

# Network services
echo "--- Network Services ---"
netstat -tulpn 2>/dev/null | head -1
netstat -tulpn 2>/dev/null | grep -E ':(80|443|22|23|161|502|1883|5683)' || echo "No relevant services found"
echo ""

# Web server status
echo "--- Web Server Status ---"
if pgrep uhttpd >/dev/null; then
    echo "uhttpd: Running (PID: $(pgrep uhttpd | tr '\n' ' '))"
else
    echo "uhttpd: Not running"
fi
echo ""

# Running VulnZoo processes
echo "--- VulnZoo Related Processes ---"
ps aux | head -1
ps aux | grep -E '(vulnzoo|device-manager)' | grep -v grep || echo "No VulnZoo processes found"
echo ""

# Disk usage
echo "--- Disk Usage ---"
df -h | head -1
df -h | grep -E '(overlay|tmp|root)' || df -h
echo ""

# Memory usage
echo "--- Memory Usage ---" 
free -m 2>/dev/null || cat /proc/meminfo | head -3