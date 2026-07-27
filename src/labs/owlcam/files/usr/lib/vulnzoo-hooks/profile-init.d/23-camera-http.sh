#!/bin/sh
#
# OwlCam Camera HTTP Bridge Service Hook
# Publishes the local RTSP feed as HTTP MJPEG on :9090/video, the endpoint the
# cloud API polls to mark the Raspberry Pi camera active.
#

# Get device name from environment OR from UCI config (fallback)
VULNZOO_DEVICE="${VULNZOO_DEVICE:-$(uci -q get vulnzoo.state.current_device 2>/dev/null)}"

# Only run for owlcam device
if [ "$VULNZOO_DEVICE" != "owlcam" ]; then
    logger -t owlcam "Skipping camera-http for device: ${VULNZOO_DEVICE:-none}"
    exit 0
fi

logger -t owlcam "Starting camera-http service..."
/etc/init.d/camera-http start
logger -t owlcam "Camera-http service started"
