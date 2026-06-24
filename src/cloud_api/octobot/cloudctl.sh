#!/usr/bin/env bash
# cloudctl.sh — start / stop / restart the OctoBot Cloud API stack.
#
# Usage:
#   ./cloudctl.sh start                 # build + up -d
#   ./cloudctl.sh start --no-hosts      # skip writing /etc/hosts
#   ./cloudctl.sh stop                  # docker compose down (keeps data volume)
#   ./cloudctl.sh restart               # stop + start (non-destructive)
#   ./cloudctl.sh reset                 # docker compose down -v (drops the DB)
#   ./cloudctl.sh status                # docker compose ps
#   ./cloudctl.sh logs [service…]       # follow logs
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

# Detect the primary IP address used to reach the lab network.
# Prefers the WiFi (wlan) interface when associated; falls back to the default route.
detect_host_ip() {
    local iface
    iface="$(ip -4 -o route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}')"
    if [ -n "$iface" ]; then
        ip -4 -o addr show dev "$iface" 2>/dev/null | awk '{split($4, a, "/"); print a[1]; exit}'
    fi
}

# Map api.octobot.lab → the given IP in /etc/hosts (sudo).
# Idempotent: removes any prior entry for this name and writes one fresh line.
add_hosts_entry() {
    local ip="$1"
    local marker="# octobot-lab (managed by cloudctl)"
    local line="${ip}  api.octobot.lab  ${marker}"
    if [ -z "$ip" ]; then
        warn "No host IP detected — not touching /etc/hosts."
        warn "Add manually:  <host-ip>  api.octobot.lab"
        return
    fi
    if grep -qxF "$line" /etc/hosts 2>/dev/null; then
        log "/etc/hosts already maps api.octobot.lab → ${ip}"
        return
    fi
    log "Updating /etc/hosts (sudo) → ${ip}  api.octobot.lab"
    sudo sh -c "{ grep -vF 'api.octobot.lab' /etc/hosts 2>/dev/null || true; } > /etc/hosts.cloudctl && printf '%s\n' '${line}' >> /etc/hosts.cloudctl && cat /etc/hosts.cloudctl > /etc/hosts && rm -f /etc/hosts.cloudctl"
    if grep -qxF "$line" /etc/hosts 2>/dev/null; then
        log "/etc/hosts updated — api.octobot.lab → ${ip}"
    else
        warn "Could not update /etc/hosts (sudo failed?)."
        warn "Add manually:  ${ip}  api.octobot.lab"
    fi
}

# ── Actions ────────────────────────────────────────────────────────────────────

action_start() {
    require docker
    docker compose version >/dev/null 2>&1 || die "docker compose plugin not installed"

    local push_hosts=1
    while [ $# -gt 0 ]; do
        case "$1" in
            --no-hosts) push_hosts=0 ;;
            *) die "Unknown option for start: $1 (try: --no-hosts)" ;;
        esac
        shift
    done

    local host_ip=""
    host_ip="$(detect_host_ip || true)"
    [ -n "$host_ip" ] && log "Detected host IP: $host_ip"

    log "docker compose up --build -d"
    HOST_IP="${host_ip}" docker compose up --build -d

    docker compose ps

    local url_host="${host_ip:-localhost}"
    log "OctoBot Cloud API running at http://${url_host}:5003/"
    log "Managed DNS name: http://api.octobot.lab/"

    if [ "$push_hosts" -eq 1 ]; then
        local hosts_ip="${host_ip}"
        [ -n "$hosts_ip" ] || hosts_ip="$(detect_host_ip || true)"
        add_hosts_entry "$hosts_ip"
    else
        log "--no-hosts: skipping /etc/hosts. Add manually: <host-ip>  api.octobot.lab"
    fi
}

action_stop() {
    require docker
    log "docker compose down  (data volume preserved — use 'reset' to wipe it)"
    docker compose down
}

# reset — tear down AND drop the data volume (seeded DB is lost).
action_reset() {
    require docker
    local assume_yes=0
    case "${1:-}" in -y|--yes) assume_yes=1 ;; esac
    if [ "$assume_yes" -ne 1 ] && [ -t 0 ]; then
        printf '\033[1;31m[cloudctl]\033[0m This DROPS the octobot_data volume (seeded operator account lost). Continue? [y/N] '
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

  start [--no-hosts]
           Build the image and bring the OctoBot Cloud API up (detached).
           Detects the host's primary IP and exports HOST_IP. Writes
           api.octobot.lab → host IP in /etc/hosts via sudo so the browser,
           Burp and tools resolve the lab domain. Use --no-hosts to skip that.

  stop     docker compose down — stops the stack but KEEPS the octobot_data
           volume (the seeded operator account survives).

  restart  stop + start; non-destructive (data preserved).

  reset [-y]
           docker compose down -v — tears down AND drops the octobot_data
           volume (seeded operator account lost; the stack re-seeds on next
           start). Prompts for confirmation unless -y/--yes is given.

  status   docker compose ps.

  logs [service…]
           Follow container logs. Ctrl+C to stop.
EOF
        exit 1
        ;;
esac
