#!/bin/sh
#
# OwlCam User Configuration Hook
# Sets up vulnerable root password
#

# Get device name from environment OR from UCI config (fallback)
VULNZOO_DEVICE="${VULNZOO_DEVICE:-$(uci -q get vulnzoo.state.current_device 2>/dev/null)}"

# Only run for owlcam device
if [ "$VULNZOO_DEVICE" != "owlcam" ]; then
    logger -t owlcam-users "Skipping user config for device: ${VULNZOO_DEVICE:-none}"
    exit 0
fi

LOG_FILE="/root/vulnzoo.log"

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$$] [owlcam] $1" >> "$LOG_FILE"
}

log_message "Setting owlcam root password..."

# Set vulnerable password hash
sed -i 's|^root:[^:]*|root:$5$/BwXdZAF8Ffbwwp5$UhB0XqwRs71Y6ESLbJm00X9OB8o7wfutwexvMqJZQV3|' "/etc/shadow"

log_message "Owlcam root password set"

exit 0
