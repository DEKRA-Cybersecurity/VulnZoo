#!/usr/bin/env bash
# cloudctl.sh — start / stop / restart the CareOtter Cloud API stack.
#
# `start` auto-detects the host's active WiFi interface, learns the SSID it is
# associated with and pulls the PSK out of NetworkManager so the API can push
# the same credentials to the Pi via IGP 0x06 SET_WIFI during /initialize_iot.
# Reading the PSK requires sudo because the connection file is root-only.
#
# Usage:
#   ./cloudctl.sh start          # build + up -d with auto WIFI_SSID/WIFI_PSK
#   ./cloudctl.sh start --no-wifi  # up -d without pushing credentials
#   ./cloudctl.sh stop           # docker compose down -v
#   ./cloudctl.sh restart        # stop + start
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Helpers ────────────────────────────────────────────────────────────────────

log()  { printf '\033[1;34m[cloudctl]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[cloudctl]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[cloudctl]\033[0m %s\n' "$*" >&2; exit 1; }

require() {
    command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

# Returns the first wlan-type iface that has carrier (associated to an AP).
# Prefers nmcli when available; falls back to /sys/class/net/*/phy80211 + /sys/.../carrier.
detect_wifi_iface() {
    if command -v nmcli >/dev/null 2>&1; then
        nmcli -t -f DEVICE,TYPE,STATE device status 2>/dev/null \
            | awk -F: '$2 == "wifi" && $3 == "connected" { print $1; exit }'
        return
    fi
    for entry in /sys/class/net/*/phy80211; do
        [ -e "$entry" ] || continue
        local iface
        iface="$(basename "$(dirname "$entry")")"
        if [ "$(cat "/sys/class/net/$iface/carrier" 2>/dev/null || echo 0)" = "1" ]; then
            echo "$iface"; return
        fi
    done
}

# SSID via nmcli (active connection) or iwgetid as a fallback.
detect_ssid() {
    local iface="$1"
    if command -v nmcli >/dev/null 2>&1; then
        nmcli -t -f active,ssid dev wifi 2>/dev/null \
            | awk -F: '$1 == "yes" { print $2; exit }'
        return
    fi
    if command -v iwgetid >/dev/null 2>&1; then
        iwgetid -r "$iface" 2>/dev/null
    fi
}

# PSK extraction. Requires sudo on most distros — NetworkManager keeps the file
# at /etc/NetworkManager/system-connections/<conn>.nmconnection, mode 0600 root.
detect_psk() {
    local ssid="$1"
    if ! command -v nmcli >/dev/null 2>&1; then
        warn "nmcli not available — cannot extract PSK automatically"
        return
    fi
    # `nmcli -s` ("show secrets") requires elevated privileges.
    sudo -n nmcli -s -g 802-11-wireless-security.psk connection show "$ssid" 2>/dev/null \
        || sudo nmcli -s -g 802-11-wireless-security.psk connection show "$ssid"
}

detect_host_wifi_ip() {
    local iface="$1"
    [ -n "$iface" ] || return
    ip -4 -o addr show dev "$iface" 2>/dev/null \
        | awk '{split($4, a, "/"); print a[1]; exit}'
}

# ── Actions ────────────────────────────────────────────────────────────────────

action_start() {
    require docker
    docker compose version >/dev/null 2>&1 || die "docker compose plugin not installed"

    local push_wifi=1
    [ "${1:-}" = "--no-wifi" ] && push_wifi=0

    local wifi_ssid="" wifi_psk="" host_ip="" iface=""

    if [ "$push_wifi" -eq 1 ]; then
        iface="$(detect_wifi_iface || true)"
        if [ -z "$iface" ]; then
            warn "No active WiFi interface — starting without WIFI_SSID/WIFI_PSK"
        else
            log "Detected WiFi interface: $iface"
            wifi_ssid="$(detect_ssid "$iface" || true)"
            host_ip="$(detect_host_wifi_ip "$iface" || true)"
            if [ -z "$wifi_ssid" ]; then
                warn "Could not resolve SSID on $iface — starting without credentials"
            else
                log "Detected SSID: $wifi_ssid"
                log "Reading PSK from NetworkManager (may prompt for sudo)…"
                wifi_psk="$(detect_psk "$wifi_ssid" || true)"
                if [ -z "$wifi_psk" ]; then
                    warn "PSK extraction failed — the API will start but will not push credentials"
                else
                    log "PSK obtained (length=${#wifi_psk})"
                fi
            fi
            [ -n "$host_ip" ] && log "Host WiFi IP: $host_ip"
        fi
    else
        log "--no-wifi: skipping WiFi auto-detection"
    fi

    log "docker compose up --build -d"
    WIFI_SSID="${wifi_ssid}" \
    WIFI_PSK="${wifi_psk}" \
    HOST_WIFI_IP="${host_ip}" \
        docker compose up --build -d

    docker compose ps
}

action_stop() {
    require docker
    log "docker compose down -v"
    docker compose down -v
}

action_restart() {
    action_stop
    action_start "$@"
}

# ── Entrypoint ─────────────────────────────────────────────────────────────────

case "${1:-}" in
    start)   shift; action_start "$@" ;;
    stop)    action_stop ;;
    restart) shift; action_restart "$@" ;;
    *)
        cat >&2 <<EOF
Usage: $0 {start|stop|restart} [--no-wifi]

  start    Build the image and bring the stack up. Auto-detects the host's
           WiFi interface and exports WIFI_SSID, WIFI_PSK, HOST_WIFI_IP so
           /initialize_iot can push the same credentials to the Pi.
           Use --no-wifi to skip WiFi credential injection.

  stop     docker compose down -v (drops the careotter_data volume).

  restart  stop + start (accepts --no-wifi like start).
EOF
        exit 1
        ;;
esac
