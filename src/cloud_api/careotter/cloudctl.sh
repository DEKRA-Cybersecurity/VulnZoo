#!/usr/bin/env bash
# cloudctl.sh — start / stop / restart the CareOtter Cloud API stack.
#
# `start` auto-detects the host's active WiFi interface, learns the SSID it is
# associated with and pulls the PSK out of NetworkManager so the API can push
# the same credentials to the Pi via IGP 0x06 SET_WIFI during /initialize_iot.
# Reading the PSK requires sudo because the connection file is root-only.
#
# Usage:
#   ./cloudctl.sh start                 # build + up -d (VULNERABLE mode, default)
#   ./cloudctl.sh start --secure        # build + up -d in SECURE mode (VULNERABLE=0)
#   ./cloudctl.sh start --no-wifi       # up -d without pushing WiFi credentials
#   ./cloudctl.sh stop                  # docker compose down (KEEPS the data volume)
#   ./cloudctl.sh restart [--secure]    # stop + start (non-destructive; data preserved)
#   ./cloudctl.sh reset                 # docker compose down -v (DROPS the seeded DB)
#   ./cloudctl.sh status                # docker compose ps
#   ./cloudctl.sh logs [service…]       # follow logs (e.g. logs careotter-proxy)
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

    local push_wifi=1 vulnerable=1
    while [ $# -gt 0 ]; do
        case "$1" in
            --no-wifi)            push_wifi=0 ;;
            --secure)             vulnerable=0 ;;
            --vulnerable|--vuln)  vulnerable=1 ;;
            *) die "Unknown option for start: $1 (try: --secure | --vulnerable | --no-wifi)" ;;
        esac
        shift
    done

    local mode_label
    if [ "$vulnerable" -eq 1 ]; then
        mode_label="VULNERABLE — proxy ACL bypassable (trailing-slash)"
    else
        mode_label="SECURE — normalized ACL (bypass closed)"
    fi
    log "Launch mode: $mode_label  (VULNERABLE=$vulnerable)"

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
    VULNERABLE="${vulnerable}" \
    WIFI_SSID="${wifi_ssid}" \
    WIFI_PSK="${wifi_psk}" \
    HOST_WIFI_IP="${host_ip}" \
        docker compose up --build -d

    docker compose ps

    local url_host="${host_ip:-localhost}"
    [ -n "$url_host" ] || url_host=localhost
    log "Mode: $mode_label"
    log "API reachable at http://${url_host}:5002  (external :5002 is the nginx proxy → API internal-only)"
}

action_stop() {
    require docker
    log "docker compose down  (data volume preserved — use 'reset' to wipe it)"
    docker compose down
}

# reset — tear down AND drop the careotter_data volume (seeded DB is lost).
action_reset() {
    require docker
    local assume_yes=0
    case "${1:-}" in -y|--yes) assume_yes=1 ;; esac
    if [ "$assume_yes" -ne 1 ] && [ -t 0 ]; then
        printf '\033[1;31m[cloudctl]\033[0m This DROPS the careotter_data volume (seeded users/vitals lost). Continue? [y/N] '
        local ans=""; read -r ans || true
        case "$ans" in y|Y|yes|YES) ;; *) die "Aborted — volume untouched." ;; esac
    fi
    log "docker compose down -v"
    docker compose down -v
}

action_status() {
    require docker
    docker compose ps
}

# logs [service…] — follow container logs (Ctrl+C to stop).
action_logs() {
    require docker
    docker compose logs --tail=200 -f "$@"
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
    reset)   shift; action_reset "$@" ;;
    status)  action_status ;;
    logs)    shift; action_logs "$@" ;;
    *)
        cat >&2 <<EOF
Usage: $0 {start|stop|restart|reset|status|logs} [options]

  start [--secure|--vulnerable] [--no-wifi]
           Build the image and bring the stack up (detached). Default mode is
           VULNERABLE (API8 proxy ACL bypassable via trailing slash); pass
           --secure to launch with VULNERABLE=0 (normalized ACL, bypass closed).
           Auto-detects the host's WiFi interface and exports WIFI_SSID,
           WIFI_PSK, HOST_WIFI_IP so /initialize_iot can push the same
           credentials to the Pi; use --no-wifi to skip that.

  stop     docker compose down — stops the stack but KEEPS the careotter_data
           volume (the seeded DB survives).

  restart [--secure|--vulnerable] [--no-wifi]
           stop + start; non-destructive (data preserved). Accepts the same
           flags as start, so you can flip mode on restart.

  reset [-y]
           docker compose down -v — tears down AND drops the careotter_data
           volume (seeded users/vitals are lost; the stack re-seeds on next
           start). Prompts for confirmation unless -y/--yes is given.

  status   docker compose ps.

  logs [service…]
           Follow container logs (e.g. logs careotter-proxy). Ctrl+C to stop.
EOF
        exit 1
        ;;
esac
