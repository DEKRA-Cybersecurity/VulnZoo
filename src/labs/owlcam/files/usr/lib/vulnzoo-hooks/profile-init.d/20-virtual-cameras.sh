#!/bin/sh
#
# OwlCam Virtual Cameras Service Hook
# Starts virtual camera simulation
#

# Get device name from environment OR from UCI config (fallback)
VULNZOO_DEVICE="${VULNZOO_DEVICE:-$(uci -q get vulnzoo.state.current_device 2>/dev/null)}"

# Only run for owlcam device
if [ "$VULNZOO_DEVICE" != "owlcam" ]; then
    logger -t owlcam "Skipping virtual-cameras for device: ${VULNZOO_DEVICE:-none}"
    exit 0
fi

logger -t owlcam "Starting virtual-cameras service..."
/etc/init.d/virtual-cameras start
logger -t owlcam "Virtual-cameras service started"
