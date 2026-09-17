#!/bin/sh
#
# BulbBee SPI Enable Hook (99-bulbbee-spi.sh)
#
# Prepares the Pi boot config for the WS2812 ring, which ws2812.py drives by
# bit-banging over SPI0. Two things are needed and both live in /boot/config.txt:
#
#   1. dtparam=spi=on          -> creates /dev/spidev0.0 (the ring's data path).
#   2. core_freq=250 (pinned)  -> the SPI baud is derived from core_freq. If it is
#      + core_freq_min=250        not pinned, the firmware drops the core clock when
#                                 the CPU goes idle a few seconds after boot, the SPI
#                                 baud shifts, and the WS2812 bit timing (~1.25us) goes
#                                 out of spec -> the ring freezes on a garbage colour
#                                 and only a full reboot (clock back to turbo) recovers
#                                 it briefly. Pinning core_freq keeps the ring stable.
#
# These lines are read by the firmware at boot, so the first load writes whatever
# is missing and reboots once to apply. Idempotent and loop-safe: it reboots ONLY
# when it actually added a line AND the write is verified on disk, so a read-only
# boot fs cannot turn this into a boot loop. Set bulbbee.main.spi_reboot=0 to write
# the config but skip the automatic reboot (reboot the Pi manually instead).
#
# This only prepares the boot config. Driving the physical ring also needs
# "use_real_hardware": true in /opt/bulbbee/config.json (shipped true).
#

VULNZOO_DEVICE="${VULNZOO_DEVICE:-$(uci -q get vulnzoo.state.current_device 2>/dev/null)}"

if [ "$VULNZOO_DEVICE" != "bulbbee" ]; then
    logger -t bulbbee-spi "Skipping SPI hook for device: ${VULNZOO_DEVICE:-none}"
    exit 0
fi

LOG_FILE="/root/vulnzoo.log"

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$$] [bulbbee] $1" >> "$LOG_FILE"
}

BOOT=/boot/config.txt
if [ ! -f "$BOOT" ]; then
    log_message "SPI hook: no $BOOT (not a Pi boot layout), skipping"
    exit 0
fi

# /boot is a FAT partition and may be mounted read-only; remount rw best-effort.
mount -o remount,rw /boot 2>/dev/null

changed=0
write_failed=0

# Append line $1 only if a line matching regex $2 is not already present, and
# confirm the write actually landed (a read-only /boot must not fake a change).
ensure() {
    grep -qE "$2" "$BOOT" && return 0
    echo "$1" >> "$BOOT" 2>/dev/null
    if grep -qE "$2" "$BOOT"; then
        changed=1
        log_message "config.txt += $1"
    else
        write_failed=1
    fi
}

ensure "dtparam=spi=on"     '^[[:space:]]*dtparam=spi=on'
ensure "core_freq=250"      '^[[:space:]]*core_freq=250'
ensure "core_freq_min=250"  '^[[:space:]]*core_freq_min=250'

if [ "$write_failed" = 1 ]; then
    log_message "ERROR: could not write to $BOOT (read-only boot fs?); not rebooting"
    exit 1
fi

if [ "$changed" = 0 ]; then
    # Steady state (also the post-reboot pass): everything already present.
    if [ -e /dev/spidev0.0 ]; then
        log_message "SPI enabled + core_freq pinned, /dev/spidev0.0 present"
    else
        log_message "WARNING: config set but /dev/spidev0.0 absent (SPI kmod missing?); not rebooting"
    fi
    exit 0
fi

sync
if [ "$(uci -q get bulbbee.main.spi_reboot)" = "0" ]; then
    log_message "Boot config updated (SPI + pinned core_freq). spi_reboot=0: reboot manually to apply"
else
    log_message "Boot config updated (SPI + pinned core_freq). Rebooting in 5s to apply"
    (sleep 5; reboot) &
fi
exit 0
