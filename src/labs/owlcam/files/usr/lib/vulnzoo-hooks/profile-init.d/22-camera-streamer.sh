#!/bin/sh
#
# OwlCam Camera Streamer Service Hook
#

# Get device name from environment OR from UCI config (fallback)
VULNZOO_DEVICE="${VULNZOO_DEVICE:-$(uci -q get vulnzoo.state.current_device 2>/dev/null)}"

# Only run for owlcam device
if [ "$VULNZOO_DEVICE" != "owlcam" ]; then
    logger -t owlcam "Skipping camera-streamer for device: ${VULNZOO_DEVICE:-none}"
    exit 0
fi

logger -t owlcam "Starting camera-streamer service..."
/etc/init.d/camera-streamer start
logger -t owlcam "Camera-streamer service started"
