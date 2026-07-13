#!/usr/bin/env bash
# cloudctl.sh — start / stop / restart the OwlCam Cloud API stack.
#
# Usage:
#   ./cloudctl.sh start                 # build + up -d
#   ./cloudctl.sh start --no-hosts      # skip writing /etc/hosts
#   ./cloudctl.sh init                  # seed the MongoDB (/camerasdb/init)
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

# Map api.owlcam.lab → the given IP in /etc/hosts (sudo).
# Idempotent: removes any prior entry for this name and writes one fresh line.
add_hosts_entry() {
    local ip="$1"
    local marker="# owlcam-lab (managed by cloudctl)"
    local line="${ip}  api.owlcam.lab  ${marker}"
    if [ -z "$ip" ]; then
        warn "No host IP detected — not touching /etc/hosts."
        warn "Add manually:  <host-ip>  api.owlcam.lab"
        return
    fi
    if grep -qxF "$line" /etc/hosts 2>/dev/null; then
        log "/etc/hosts already maps api.owlcam.lab → ${ip}"
        return
    fi
    log "Updating /etc/hosts (sudo) → ${ip}  api.owlcam.lab"
    sudo sh -c "{ grep -vF 'api.owlcam.lab' /etc/hosts 2>/dev/null || true; } > /etc/hosts.cloudctl && printf '%s\n' '${line}' >> /etc/hosts.cloudctl && cat /etc/hosts.cloudctl > /etc/hosts && rm -f /etc/hosts.cloudctl"
    if grep -qxF "$line" /etc/hosts 2>/dev/null; then
        log "/etc/hosts updated — api.owlcam.lab → ${ip}"
    else
        warn "Could not update /etc/hosts (sudo failed?)."
        warn "Add manually:  ${ip}  api.owlcam.lab"
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
    docker compose up --build -d

    docker compose ps

    local url_host="${host_ip:-localhost}"
    log "OwlCam vulnerable API : http://${url_host}:5000/"
    log "OwlCam secure API     : http://${url_host}:5001/"
    log "C2 panel              : http://${url_host}:4999/panel  (password: letstechin)"
    log "MongoDB               : ${url_host}:27018  (admin/supersecret)"
    log "Managed DNS name      : http://api.owlcam.lab:5000/"
    log "First run: seed the DB with  ./cloudctl.sh init"

    if [ "$push_hosts" -eq 1 ]; then
        local hosts_ip="${host_ip}"
        [ -n "$hosts_ip" ] || hosts_ip="$(detect_host_ip || true)"
        add_hosts_entry "$hosts_ip"
    else
        log "--no-hosts: skipping /etc/hosts. Add manually: <host-ip>  api.owlcam.lab"
    fi
}

# init — seed MongoDB through the vulnerable API (/camerasdb/init). Required on
# first start so user 'john' and the default camera exist. Waits for the API to
# come up. Use /camerasdb/reset (documented) to wipe and re-seed the DB.
action_init() {
    require curl
    log "Seeding DB via http://localhost:5000/camerasdb/init ..."
    local i=0 resp=""
    while :; do
        if resp="$(curl -fsS http://localhost:5000/camerasdb/init 2>/dev/null)"; then
            break
        fi
        i=$((i + 1))
        [ "$i" -ge 15 ] && die "API not reachable on :5000 after ${i} tries (check ./cloudctl.sh status / logs)."
        sleep 2
    done
    log "DB seeded: ${resp:-ok}"
}

action_stop() {
    require docker
    log "docker compose down  (mongo data volume preserved — use 'reset' to wipe it)"
    docker compose down
}

# reset — tear down AND drop the MongoDB data (anonymous volume) so the seeded
# users/cameras are lost; re-seed with 'init' after the stack restarts.
action_reset() {
    require docker
    local assume_yes=0
    case "${1:-}" in -y|--yes) assume_yes=1 ;; esac
    if [ "$assume_yes" -ne 1 ] && [ -t 0 ]; then
        printf '\033[1;31m[cloudctl]\033[0m This DROPS the MongoDB data (seeded users/cameras lost). Continue? [y/N] '
        local ans=""; read -r ans || true
        case "$ans" in y|Y|yes|YES) ;; *) die "Aborted — volume untouched." ;; esac
    fi
    log "docker compose down -v"
    docker compose down -v
    action_restart
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
    init)    action_init ;;
    stop)    action_stop ;;
    restart) shift; action_restart "$@" ;;
    reset)   shift; action_reset "$@" ;;
    status)  action_status ;;
    logs)    shift; action_logs "$@" ;;
    *)
        cat >&2 <<EOF
Usage: $0 {start|init|stop|restart|reset|status|logs} [options]

  start [--no-hosts]
           Build the images and bring the OwlCam Cloud API up (detached):
           vulnerable API :5000, secure API :5001, C2 panel :4999, mongo :27018.
           Detects the host's primary IP and writes api.owlcam.lab → host IP in
           /etc/hosts via sudo so the browser, Burp and tools resolve the lab
           domain. Use --no-hosts to skip that.

  init     Seed MongoDB via http://localhost:5000/camerasdb/init (creates user
           'john' and the default camera). Run once after the first 'start'.

  stop     docker compose down — stops the stack but KEEPS the mongo data
           (seeded users/cameras survive).

  restart  stop + start; non-destructive (data preserved).

  reset [-y]
           docker compose down -v — tears down AND drops the mongo data (seeded
           users/cameras lost; re-seed with 'init' after it restarts). Prompts
           for confirmation unless -y/--yes is given.

  status   docker compose ps.

  logs [service…]
           Follow container logs. Ctrl+C to stop.
EOF
        exit 1
        ;;
esac
