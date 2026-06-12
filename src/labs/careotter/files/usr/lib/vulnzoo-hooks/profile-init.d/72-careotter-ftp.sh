#!/bin/sh
#
# CareOtter Field-Service FTP Hook (OWASP IoT I2 — Insecure Network Services)
# Starts the legacy vulnerable FTP daemon (careotter-ftp) on TCP :21.
#
# Advertises "220 (vsFTPd 2.3.4)" and reproduces the vsftpd 2.3.4 backdoor
# (CVE-2011-2523): USER "<x>:)" → root shell on :6200. The port is already
# opened by 75-firewall.sh (Allow-FTP). Independent from careservice (:9999)
# and the medical sensor (:8081).
#
# Secure/vulnerable toggle: UCI careotter.@careotter[0].ftp_secure (1 = secure
# → the init script decommissions the service and nothing listens on :21).
#

VULNZOO_DEVICE="${VULNZOO_DEVICE:-$(uci -q get vulnzoo.state.current_device 2>/dev/null)}"

if [ "$VULNZOO_DEVICE" != "careotter" ]; then
    logger -t careotter-ftp "Skipping FTP hook for device: ${VULNZOO_DEVICE:-none}"
    exit 0
fi

LOG_FILE="/root/vulnzoo.log"
PID_FILE="/var/run/careotter-ftp.pid"
FTP_BIN="/opt/careotter-ftp/careotter-ftp"
FTP_PORT=21

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$$] [careotter-ftp] $1" >> "$LOG_FILE"
}

log_message "Starting CareOtter field-service FTP hook..."

# Idempotency: trust pidof against the binary, not the (async) pidfile.
existing_pid=$(pidof "$FTP_BIN" 2>/dev/null | awk '{print $1}')
if [ -n "$existing_pid" ]; then
    log_message "FTP service already running (PID: $existing_pid) - skipping"
    echo "$existing_pid" > "$PID_FILE"
    exit 0
fi
[ -f "$PID_FILE" ] && { log_message "Removing stale PID file"; rm -f "$PID_FILE"; }

# Pre-flight: binary present + executable.
if [ ! -f "$FTP_BIN" ]; then
    log_message "ERROR: careotter-ftp binary not found at $FTP_BIN (build careotter-ftp.c first)"
    logger -t careotter-ftp "ERROR: binary missing — compile careotter-ftp.c"
    exit 1
fi
[ -x "$FTP_BIN" ] || { log_message "Making careotter-ftp executable..."; chmod +x "$FTP_BIN"; }

# Free port 21 if something else holds it.
port_check=$(netstat -tlnp 2>/dev/null | grep ":$FTP_PORT ")
if [ -n "$port_check" ]; then
    log_message "WARNING: Port $FTP_PORT in use: $port_check — freeing"
    fuser -k ${FTP_PORT}/tcp 2>/dev/null
    sleep 1
fi

# Enable auto-start + ensure the rc.d symlink exists (procd `enable` can fail
# silently on a stale cache — same self-heal as careservice).
[ -f /etc/init.d/careotter-ftp ] || { log_message "ERROR: /etc/init.d/careotter-ftp missing"; exit 1; }
/etc/init.d/careotter-ftp enable
RC_SYMLINK="/etc/rc.d/S72careotter-ftp"
if [ ! -L "$RC_SYMLINK" ]; then
    log_message "WARNING: $RC_SYMLINK missing after enable — creating manually"
    mkdir -p /etc/rc.d
    ln -sf ../init.d/careotter-ftp "$RC_SYMLINK"
    sync
fi

# Secure mode decommissions the service — starting is a no-op, do NOT treat the
# absence of a listening process as a failure.
FTP_SECURE=$(uci -q get careotter.@careotter[0].ftp_secure 2>/dev/null)
[ "$FTP_SECURE" = "1" ] || FTP_SECURE=0

log_message "Starting careotter-ftp (ftp_secure=$FTP_SECURE)..."
/etc/init.d/careotter-ftp start

if [ "$FTP_SECURE" = "1" ]; then
    log_message "secure_mode=1 — field-service FTP decommissioned (nothing on :$FTP_PORT). OK."
    logger -t careotter-ftp "Secure mode — FTP service decommissioned"
    exit 0
fi

# Vulnerable mode: verify it came up (retry pidof, like careservice).
service_pid=""
for attempt in 1 2 3 4 5; do
    sleep 1
    service_pid=$(pidof "$FTP_BIN" 2>/dev/null | awk '{print $1}')
    [ -n "$service_pid" ] && break
done

if [ -n "$service_pid" ]; then
    echo "$service_pid" > "$PID_FILE"
    log_message "Field-service FTP started (PID: $service_pid) on :$FTP_PORT — vsftpd 2.3.4 backdoor active"
    logger -t careotter-ftp "Service active on :$FTP_PORT (vsftpd 2.3.4 / CVE-2011-2523)"
    exit 0
fi

log_message "ERROR: careotter-ftp not detected after start — check /tmp/careotter-ftp.log"
logger -t careotter-ftp "ERROR: service failed to start"
exit 1
