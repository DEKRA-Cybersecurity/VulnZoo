#!/usr/bin/env bash
# cloudctl.sh — start / stop / delete / drive the BulbBee cloud stack.
#
# The stack is two services (docker-compose.yml):
#   bulbbee-cloud   Flask REST API on :5004 (the BULB-CLD BOLA + weak-JWT surface)
#   bulbbee-broker  eclipse-mosquitto on :1883 (plaintext) / :8883 (TLS) — the
#                   cloud emulator the device's outbound tunnel connects to (BULB-A3)
#
# There is no database: the API's users/bulbs are in-memory, so no seed step and
# nothing to lose on restart. 'reset' rebuilds the image from scratch.
#
# Usage:
#   ./cloudctl.sh start                 # build + up -d
#   ./cloudctl.sh stop                  # docker compose down
#   ./cloudctl.sh restart               # stop + start
#   ./cloudctl.sh reset [-y]            # down -v --rmi local (drop image, force clean rebuild)
#   ./cloudctl.sh status                # docker compose ps
#   ./cloudctl.sh logs [service…]       # follow logs (e.g. logs bulbbee-broker)
#   ./cloudctl.sh pub <device_id> '<json>'   # publish a command to the device via the broker
#   ./cloudctl.sh sub <device_id>            # watch the device's state topic
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

BROKER_SVC="bulbbee-broker"

# ── Helpers ────────────────────────────────────────────────────────────────────

log()  { printf '\033[1;34m[cloudctl]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[cloudctl]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[cloudctl]\033[0m %s\n' "$*" >&2; exit 1; }

require() {
    command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

require_stack() {
    require docker
    docker compose version >/dev/null 2>&1 || die "docker compose plugin not installed"
}

# Primary IP used to reach the lab network (from the default route). Only used to
# print the value to set as cloud_host in the device's /opt/bulbbee/config.json.
detect_host_ip() {
    local iface
    iface="$(ip -4 -o route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}')"
    if [ -n "$iface" ]; then
        ip -4 -o addr show dev "$iface" 2>/dev/null | awk '{split($4, a, "/"); print a[1]; exit}'
    fi
}

# ── Actions ────────────────────────────────────────────────────────────────────

action_start() {
    require_stack
    [ $# -eq 0 ] || die "start takes no options"

    log "docker compose up --build -d"
    docker compose up --build -d
    docker compose ps

    local host_ip; host_ip="$(detect_host_ip || true)"
    local url_host="${host_ip:-localhost}"
    log "Cloud REST API   : http://${url_host}:5004/  (login: POST /api/login {\"user\":\"alice\"})"
    log "Broker MQTT      : ${url_host}:1883  (plaintext, the tunnel default)"
    log "Broker MQTT/TLS  : ${url_host}:8883  (needs certs in ./certs, see mosquitto.conf)"
    if [ -n "$host_ip" ]; then
        log "Point the device at this host: set \"cloud_host\": \"${host_ip}\" in /opt/bulbbee/config.json,"
        log "then on the Pi:  /etc/init.d/bulbbee-tunnel enable && /etc/init.d/bulbbee-tunnel start"
        log "Drive it:  ./cloudctl.sh pub <device_id> '{\"scene\":\"rainbow\"}'"
    fi
}

action_stop() {
    require_stack
    log "docker compose down"
    docker compose down
}

# reset — tear down and drop the locally built image + any volumes, so the next
# start rebuilds cleanly. No persistent data exists, so nothing seeded is lost.
action_reset() {
    require_stack
    local assume_yes=0
    case "${1:-}" in -y|--yes) assume_yes=1 ;; "" ) ;; *) die "Unknown option for reset: $1 (try -y)" ;; esac
    if [ "$assume_yes" -ne 1 ] && [ -t 0 ]; then
        printf '\033[1;31m[cloudctl]\033[0m This tears down the stack and removes the built image (forces a clean rebuild). Continue? [y/N] '
        local ans=""; read -r ans || true
        case "$ans" in y|Y|yes|YES) ;; *) die "Aborted." ;; esac
    fi
    log "docker compose down -v --rmi local"
    docker compose down -v --rmi local
}

action_status() {
    require_stack
    docker compose ps
}

action_logs() {
    require_stack
    docker compose logs --tail=200 -f "$@"
}

action_restart() {
    action_stop
    action_start "$@"
}

# pub <device_id> '<json>' — publish a lighting command to bulbbee/<id>/cmd through
# the running broker container (uses the image's own mosquitto_pub, no host deps).
action_pub() {
    require_stack
    local dev="${1:-}" payload="${2:-}"
    [ -n "$dev" ] && [ -n "$payload" ] || die "usage: pub <device_id> '<json>'  e.g. pub abc123 '{\"scene\":\"rainbow\"}'"
    log "publish -> bulbbee/${dev}/cmd : ${payload}"
    docker compose exec -T "$BROKER_SVC" mosquitto_pub -h localhost -t "bulbbee/${dev}/cmd" -m "$payload"
}

# sub <device_id> — follow the device's state topic through the broker container.
action_sub() {
    require_stack
    local dev="${1:-}"
    [ -n "$dev" ] || die "usage: sub <device_id>"
    log "subscribe <- bulbbee/${dev}/state  (Ctrl+C to stop)"
    docker compose exec -T "$BROKER_SVC" mosquitto_sub -h localhost -t "bulbbee/${dev}/state" -v
}

# ── Entrypoint ─────────────────────────────────────────────────────────────────

case "${1:-}" in
    start)          shift; action_start "$@" ;;
    stop)           action_stop ;;
    restart)        shift; action_restart "$@" ;;
    reset|delete|rm) shift; action_reset "$@" ;;
    status)         action_status ;;
    logs)           shift; action_logs "$@" ;;
    pub)            shift; action_pub "$@" ;;
    sub)            shift; action_sub "$@" ;;
    *)
        cat >&2 <<EOF
Usage: $0 {start|stop|restart|reset|status|logs|pub|sub} [options]

  start    Build the images and bring the BulbBee cloud up (detached):
           REST API :5004 (bulbbee-cloud) and the MQTT broker :1883/:8883
           (bulbbee-broker) the device tunnel connects to. Prints the host IP
           to set as cloud_host in the device config.

  stop     docker compose down — stops and removes the containers.

  restart  stop + start.

  reset [-y]   (aliases: delete, rm)
           docker compose down -v --rmi local — tears down AND removes the built
           image and volumes so the next start rebuilds clean. No seeded data
           exists (the API is in-memory), so nothing is lost. Prompts unless -y.

  status   docker compose ps.

  logs [service…]
           Follow container logs (e.g. logs bulbbee-broker). Ctrl+C to stop.

  pub <device_id> '<json>'
           Publish a lighting command to bulbbee/<device_id>/cmd via the broker
           (drives the bulb over the cloud tunnel). e.g.
             $0 pub abc123 '{"scene":"rainbow"}'

  sub <device_id>
           Follow the device's bulbbee/<device_id>/state topic.
EOF
        exit 1
        ;;
esac
