#!/usr/bin/env python3
# /opt/medical-sensor/sensor_service.py
# Medical sensor service with log rotation support (SIGUSR1) and summary logging

import time
import json
import math
import signal
import sys
import threading
import os
import socket
import struct
import fcntl
from http.server import HTTPServer, BaseHTTPRequestHandler
from simulator import get_bus


def _get_eth0_mac() -> str:
    """Return the hardware MAC address of eth0 (or first available interface).
    Used by /health so the cloud API can identify this device without auth.
    """
    SIOCGIFHWADDR = 0x8927
    for iface in ("eth0", "eth1", "enp1s0", "enp2s0"):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            res = fcntl.ioctl(s.fileno(), SIOCGIFHWADDR, iface.encode().ljust(40, b"\x00"))
            s.close()
            mac_bytes = res[18:24]
            return ':'.join(f'{b:02X}' for b in mac_bytes)
        except OSError:
            pass
    # Fallback: read from /sys/class/net
    for iface in ("eth0", "eth1"):
        try:
            with open(f"/sys/class/net/{iface}/address") as f:
                return f.read().strip().upper()
        except OSError:
            pass
    return "00:00:00:00:00:00"


def _get_iface_ip(iface: str) -> str:
    """Return the IPv4 address bound to ``iface`` or '0.0.0.0' if missing/down.
    Same SIOCGIFADDR ioctl pattern that BLE server's ``_get_wlan0_ip`` uses.
    Consumed by /health so the cloud API can switch Config.DEVICE_IP from
    Ethernet to the freshly provisioned WiFi after a successful IGP 0x06."""
    SIOCGIFADDR = 0x8915
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        res = fcntl.ioctl(s.fileno(), SIOCGIFADDR, iface.encode().ljust(40, b"\x00"))
        s.close()
        return socket.inet_ntoa(res[20:24])
    except OSError:
        return "0.0.0.0"


def _list_wifi_candidates() -> list:
    """Return every netdev the kernel marks as wireless, in detection order.

    Three independent probes — OpenWRT 24.x with mac80211 only populates the
    third one, so all three are required for portability across distros:

      1. ``/proc/net/wireless`` (WEXT legacy) — present on most desktop distros
         when CONFIG_CFG80211_WEXT is enabled, but **absent** on OpenWRT 24.x
         which ships pure cfg80211/nl80211.
      2. ``/sys/class/net/<iface>/wireless/`` (WEXT sysfs view) — same backing
         as #1; absent on the same systems.
      3. ``/sys/class/net/<iface>/phy80211`` symlink (cfg80211/nl80211) — the
         canonical marker for any modern wireless netdev. Always present when
         a wireless interface is registered through ``mac80211`` (OpenWRT,
         recent kernels). Points to the underlying ``ieee80211/phyN``.
    """
    candidates: list = []
    seen = set()

    def add(name: str) -> None:
        if name and name not in seen:
            seen.add(name)
            candidates.append(name)

    try:
        with open("/proc/net/wireless") as f:
            for line in f.readlines()[2:]:
                add(line.split(":", 1)[0].strip())
    except OSError:
        pass
    try:
        for entry in sorted(os.listdir("/sys/class/net")):
            if os.path.isdir(f"/sys/class/net/{entry}/wireless"):
                add(entry)
    except OSError:
        pass
    try:
        for entry in sorted(os.listdir("/sys/class/net")):
            if os.path.islink(f"/sys/class/net/{entry}/phy80211"):
                add(entry)
    except OSError:
        pass
    return candidates


def _get_wifi_iface() -> str:
    """Auto-detect the WiFi station netdev regardless of driver naming.

    Returns the first wireless netdev reported by the kernel (any of the three
    probes in ``_list_wifi_candidates``). Empty string if no wireless iface is
    registered (e.g. dev box without a radio).
    """
    cand = _list_wifi_candidates()
    return cand[0] if cand else ""


def _get_wifi_ip() -> tuple:
    """Return ``(iface_name, ipv4)`` for the active WiFi station, or ``("","0.0.0.0")``.
    Iterates every wireless netdev exposed by the kernel and returns the first
    one that has a non-zero IPv4 bound — handles multi-radio Pis where the
    primary station might not be the first kernel entry.
    """
    candidates = _list_wifi_candidates()
    for name in candidates:
        ip = _get_iface_ip(name)
        if ip and ip != "0.0.0.0":
            return name, ip
    return (candidates[0] if candidates else ""), "0.0.0.0"


_DEVICE_MAC = _get_eth0_mac()

# ── Configuration ─────────────────────────────────────────
CONFIG_FILE = "/opt/medical-sensor/config.json"
THRESH_FILE = "/tmp/careotter.thresholds"

def load_config():
    try:
        with open(CONFIG_FILE) as f:
            return json.load(f)
    except Exception:
        return {}

cfg = load_config()
USE_REAL_HW = cfg.get("use_real_hardware", False)
BPM_BASE = cfg.get("bpm", 72)
SPO2_BASE = cfg.get("spo2", 98)
HTTP_PORT = cfg.get("http_port", 8081)
LOG_FILE = cfg.get("log_file", "/tmp/medical-logs/vitals.log")
SAMPLE_RATE_HZ = cfg.get("sample_rate", 10)
SUMMARY_EVERY = cfg.get("summary_every_s", 60)  # Seconds between summaries
LOG_BUFFER_MAX = cfg.get("log_buffer_max", 1440)  # Maximum entries in buffer
API_KEY = cfg.get("api_key", "careotter-2024-lab")

# ── Shared state ──────────────────────────────────────────
latest = {
    "bpm": BPM_BASE,
    "spo2": SPO2_BASE,
    "red_raw": 0,
    "ir_raw": 0,
    "timestamp": 0,
    "source": "simulator" if not USE_REAL_HW else "hardware",
}
lock = threading.Lock()
log_lock = threading.Lock()
log_buffer = []  # Circular log buffer

# Alert thresholds — writable via POST /thresholds, BLE characteristic, and IGP 0x08 (via file)
alert_thresholds = {"bpm_min": 40, "bpm_max": 120, "spo2_min": 90}
thresholds_lock = threading.Lock()

# ── Clinical alert dispatcher ─────────────────────────────
# Edge-triggered: only emit on healthy→fired and fired→cleared transitions to
# avoid flooding the log + cloud collector with one event per sensor cycle.
ALERT_LOG_FILE = "/tmp/medical-logs/alerts.log"
ALERT_BUFFER_MAX = 500
alerts_buffer = []          # circular, mirror of recent alert events
alerts_log_lock = threading.Lock()

# Per-condition latch — last edge state. False = healthy, True = currently firing.
_last_alert_state = {"bpm_low": False, "bpm_high": False, "spo2_low": False}
_alert_state_lock = threading.Lock()


def _alert_severity(kind: str, value: int, threshold: int) -> str:
    """Coarse severity: SpO2 below 90 or HR drift > 20 from threshold = critical."""
    if kind == "spo2_low":
        return "critical" if value < 90 else "warning"
    if kind == "bpm_low":
        return "critical" if value < max(0, threshold - 20) else "warning"
    if kind == "bpm_high":
        return "critical" if value > threshold + 30 else "warning"
    return "warning"


def _append_alert(event: dict) -> None:
    """Add an alert event to the circular buffer + append to alerts.log."""
    with alerts_log_lock:
        alerts_buffer.append(event)
        if len(alerts_buffer) > ALERT_BUFFER_MAX:
            alerts_buffer.pop(0)
    try:
        os.makedirs(os.path.dirname(ALERT_LOG_FILE), exist_ok=True)
        with open(ALERT_LOG_FILE, "a") as fh:
            fh.write(json.dumps(event) + "\n")
    except OSError as e:
        sys.stderr.write(f"[medical-sensor] Alert log write failed: {e}\n")


def _evaluate_alerts(bpm: int, spo2: int, ts: float) -> None:
    """Evaluate current vitals against thresholds and emit edge-triggered events.

    Three independent conditions latch in `_last_alert_state`. A `fired` event is
    emitted when a condition first crosses its threshold; a `cleared` event when
    it returns to healthy. Steady-state firing produces zero events — that's the
    whole point of using edges instead of level-triggering.
    """
    with thresholds_lock:
        thr = dict(alert_thresholds)

    conditions = {
        "bpm_low":  (bpm  < thr["bpm_min"],  bpm,  thr["bpm_min"]),
        "bpm_high": (bpm  > thr["bpm_max"],  bpm,  thr["bpm_max"]),
        "spo2_low": (spo2 < thr["spo2_min"], spo2, thr["spo2_min"]),
    }

    with _alert_state_lock:
        for kind, (firing, value, threshold) in conditions.items():
            previously_firing = _last_alert_state[kind]
            if firing and not previously_firing:
                _last_alert_state[kind] = True
                _append_alert({
                    "timestamp": ts,
                    "type":      kind,
                    "state":     "fired",
                    "value":     int(value),
                    "threshold": int(threshold),
                    "severity":  _alert_severity(kind, value, threshold),
                    "source":    "simulator" if not USE_REAL_HW else "hardware",
                })
            elif not firing and previously_firing:
                _last_alert_state[kind] = False
                _append_alert({
                    "timestamp": ts,
                    "type":      kind,
                    "state":     "cleared",
                    "value":     int(value),
                    "threshold": int(threshold),
                    "severity":  "info",
                    "source":    "simulator" if not USE_REAL_HW else "hardware",
                })


def _load_thresholds_from_file():
    """Load thresholds from THRESH_FILE written by careservice IGP 0x08 SET_THRESHOLD.
    Fails silently if the file does not exist or is malformed."""
    try:
        data = {}
        with open(THRESH_FILE) as fh:
            for line in fh:
                line = line.strip()
                if "=" in line:
                    k, v = line.split("=", 1)
                    data[k.strip()] = int(v.strip())
        with thresholds_lock:
            for key in ("bpm_min", "bpm_max", "spo2_min"):
                if key in data:
                    alert_thresholds[key] = data[key]
        return True
    except (FileNotFoundError, ValueError, OSError):
        return False


def _threshold_watcher():
    """Background thread: reload thresholds when careservice rewrites THRESH_FILE.
    Uses mtime to avoid redundant reads."""
    last_mtime = 0.0
    while True:
        try:
            mtime = os.path.getmtime(THRESH_FILE)
            if mtime != last_mtime:
                if _load_thresholds_from_file():
                    last_mtime = mtime
        except (FileNotFoundError, OSError):
            pass
        time.sleep(5)

# Stable snapshot served by /vitals — frozen every 30s by snapshot_loop().
# All consumers (cloud API collector, BLE server) read the same value regardless
# of when they poll, because latest changes every 100ms with random variation.
SNAPSHOT_INTERVAL = 10
vitals_snapshot: dict = {}
snapshot_lock = threading.Lock()

# ── Log rotation support ───────────────────────────────────
class LogReopener:
    """Handles log reopening on SIGUSR1."""
    def __init__(self, log_path):
        self.log_path = log_path
        self._file = None
        self._open()
    
    def _open(self):
        """Opens the log file."""
        try:
            if self._file:
                self._file.close()
            # Ensure the directory exists
            if self.log_path:
                os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
            self._file = open(self.log_path, "a") if self.log_path else None
        except Exception as e:
            sys.stderr.write(f"[medical-sensor] Error opening log: {e}\n")
    
    def reopen(self):
        """Reopens the file (called by SIGUSR1)."""
        sys.stdout.write("[medical-sensor] Reopening log file (SIGUSR1)\n")
        self._open()
    
    def write(self, data):
        """Writes data to the log."""
        if self._file:
            try:
                self._file.write(data)
                self._file.flush()
            except Exception as e:
                sys.stderr.write(f"[medical-sensor] Error writing log: {e}\n")
    
    def close(self):
        if self._file:
            self._file.close()

# Global logger instance
logger = LogReopener(LOG_FILE)

# ── Buffered logging function ────────────────────────────
def append_log(entry):
    """Adds an entry to the buffer and optionally to the file."""
    with log_lock:
        log_buffer.append(entry)
        if len(log_buffer) > LOG_BUFFER_MAX:
            log_buffer.pop(0)
    
    # Write to the file outside the lock (if configured)
    if LOG_FILE:
        try:
            logger.write(json.dumps(entry) + "\n")
        except Exception as e:
            sys.stderr.write(f"[medical-sensor] Error writing to log file: {e}\n")

# ── Signal handling ───────────────────────────────────────
def handle_sigusr1(signum, frame):
    """SIGUSR1 handler for log rotation."""
    logger.reopen()

def handle_sighup(signum, frame):
    """Reload clinical thresholds from THRESH_FILE on SIGHUP."""
    _load_thresholds_from_file()

def handle_shutdown(signum, frame):
    """SIGTERM/SIGINT handler."""
    sys.stdout.write("[medical-sensor] Shutting down...\n")
    logger.close()
    sys.exit(0)

# ── BPM calculation from PPG signal ───────────────────────
def calculate_bpm(red_samples, sample_rate):
    """Simple peak detection over a sample buffer."""
    if len(red_samples) < 4:
        return BPM_BASE
    mean = sum(red_samples) / len(red_samples)
    peaks = 0
    for i in range(1, len(red_samples) - 1):
        if red_samples[i] > mean * 1.02 and \
           red_samples[i] > red_samples[i-1] and \
           red_samples[i] > red_samples[i+1]:
            peaks += 1
    duration = len(red_samples) / sample_rate
    return int((peaks / duration) * 60) if duration > 0 else BPM_BASE

# ── Sensor read loop ──────────────────────────────────────
def sensor_loop():
    bus = get_bus(real=USE_REAL_HW, bpm=BPM_BASE, spo2=SPO2_BASE)
    red_buffer = []
    interval = 1.0 / SAMPLE_RATE_HZ
    
    # Accumulators for summaries
    bpm_accum = []
    spo2_accum = []
    sample_count = 0
    samples_per_summary = SUMMARY_EVERY * SAMPLE_RATE_HZ

    while True:
        try:
            raw = bus.read_i2c_block_data(0x57, 0x07, 6)
            red = (raw[0] << 16 | raw[1] << 8 | raw[2]) & 0x3FFFF
            ir = (raw[3] << 16 | raw[4] << 8 | raw[5]) & 0x3FFFF

            red_buffer.append(red)
            # 60-second buffer to keep enough samples at any sample rate
            if len(red_buffer) > SAMPLE_RATE_HZ * 60:
                red_buffer.pop(0)

            # In simulated mode, use healthy base values; on real hardware, calculate from the signal
            if USE_REAL_HW:
                bpm = calculate_bpm(red_buffer, SAMPLE_RATE_HZ)
                # SpO2 from the IR/RED ratio (real hardware only)
                spo2 = min(100, int(110 - 25 * (red / max(ir, 1))))
            else:
                # Simulation: constant healthy values
                import random
                # BPM: small variation around the base value (60-100 is normal at rest)
                bpm = max(60, min(100, BPM_BASE + random.randint(-3, 3)))
                # SpO2: constant at 98% (normal healthy range: 95-100%)
                spo2 = 98

            now_ts = time.time()
            with lock:
                latest.update({
                    "bpm": bpm,
                    "spo2": spo2,
                    "red_raw": red,
                    "ir_raw": ir,
                    "timestamp": now_ts,
                })

            # Edge-triggered alert dispatch — runs every sensor cycle but only
            # writes to buffer/log on healthy↔fired transitions, so steady-state
            # alerts cost ~0 disk + 0 cloud bandwidth.
            _evaluate_alerts(bpm, spo2, now_ts)

            # Accumulate for the summary
            bpm_accum.append(bpm)
            spo2_accum.append(spo2)
            sample_count += 1
            
            # Generate a summary when due
            if sample_count >= samples_per_summary:
                summary = {
                    "bpm_avg": round(sum(bpm_accum) / len(bpm_accum), 1),
                    "bpm_min": min(bpm_accum),
                    "bpm_max": max(bpm_accum),
                    "spo2_avg": round(sum(spo2_accum) / len(spo2_accum), 1),
                    "spo2_min": min(spo2_accum),
                    "spo2_max": max(spo2_accum),
                    "samples": sample_count,
                    "timestamp": time.time(),
                    "source": "simulator" if not USE_REAL_HW else "hardware",
                }
                append_log(summary)
                
                # Reset accumulators
                bpm_accum = []
                spo2_accum = []
                sample_count = 0

        except Exception as e:
            sys.stderr.write(f"[sensor] Error: {e}\n")

        time.sleep(interval)

# ── HTTP server ───────────────────────────────────────────
class VitalsHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # Silence default HTTP logging

    def _check_auth(self) -> bool:
        return self.headers.get("X-API-Key", "") == API_KEY

    def _send_401(self):
        body = json.dumps({"error": "unauthorized", "X-API-Key": "invalid"}).encode()
        self.send_response(401)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/vitals":
            if not self._check_auth():
                self._send_401()
                return
            with snapshot_lock:
                data = dict(vitals_snapshot) if vitals_snapshot else dict(latest)
            body = json.dumps(data).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)

        elif self.path == "/health":
            wifi_iface, wifi_ip = _get_wifi_ip()
            body = json.dumps({
                "status": "ok",
                "service": "careotter-sensor",
                "mac": _DEVICE_MAC,
                "eth0_ip": _get_iface_ip("eth0"),
                # New canonical fields — driver-agnostic (wlan0, phy0-sta0, wlp*, …)
                "wifi_iface": wifi_iface,
                "wifi_ip": wifi_ip,
                # Back-compat alias — old cloud builds still look for wlan0_ip
                "wlan0_ip": wifi_ip,
                "uptime": int(time.time()),
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)

        elif self.path == "/reload":
            if not self._check_auth():
                self._send_401()
                return
            """Endpoint to force log reopening (SIGUSR1 alternative)."""
            logger.reopen()
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"log reopened")
        
        elif self.path == "/log":
            if not self._check_auth():
                self._send_401()
                return
            """Returns the full log buffer."""
            with log_lock:
                data = list(log_buffer)  # Copy to avoid race conditions
            body = json.dumps(data).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)
        
        elif self.path == "/log/last":
            if not self._check_auth():
                self._send_401()
                return
            """Returns only the most recent log entry."""
            with log_lock:
                data = log_buffer[-1] if log_buffer else {}
            body = json.dumps(data).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)
        
        elif self.path == "/config":
            if not self._check_auth():
                self._send_401()
                return
            body = json.dumps(dict(cfg)).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)

        elif self.path == "/alerts":
            if not self._check_auth():
                self._send_401()
                return
            with lock:
                bpm = latest["bpm"]
                spo2 = latest["spo2"]
            with thresholds_lock:
                thresholds = dict(alert_thresholds)
            alert_firing = (
                bpm < thresholds["bpm_min"] or
                bpm > thresholds["bpm_max"] or
                spo2 < thresholds["spo2_min"]
            )
            data = {
                "thresholds": thresholds,
                "current_bpm": bpm,
                "current_spo2": spo2,
                "alert_firing": alert_firing,
                "alerts": {
                    "bpm_low":  bpm < thresholds["bpm_min"],
                    "bpm_high": bpm > thresholds["bpm_max"],
                    "spo2_low": spo2 < thresholds["spo2_min"],
                },
            }
            body = json.dumps(data).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)

        elif self.path.startswith("/alerts/history"):
            if not self._check_auth():
                self._send_401()
                return
            # Cloud collector poll: returns alert events with timestamp > since.
            # Without `since` returns the full in-memory buffer (up to ALERT_BUFFER_MAX).
            from urllib.parse import urlparse, parse_qs
            qs = parse_qs(urlparse(self.path).query)
            try:
                since = float(qs.get("since", ["0"])[0])
            except (ValueError, IndexError):
                since = 0.0
            with alerts_log_lock:
                events = [e for e in alerts_buffer if e.get("timestamp", 0) > since]
            body = json.dumps({"alerts": events, "count": len(events)}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)

        elif self.path.startswith("/history"):
            if not self._check_auth():
                self._send_401()
                return
            # VULNERABILITY: minutes parameter accepted without validation
            # minutes=99999 returns full buffer without error
            from urllib.parse import urlparse, parse_qs
            qs = parse_qs(urlparse(self.path).query)
            try:
                minutes = int(qs.get("minutes", ["60"])[0])
            except (ValueError, IndexError):
                minutes = 60
            cutoff = time.time() - (minutes * 60)
            with log_lock:
                # No validation on minutes — intentional
                if minutes >= LOG_BUFFER_MAX:
                    filtered = list(log_buffer)
                else:
                    filtered = [e for e in log_buffer if e.get("timestamp", 0) >= cutoff]
            body = json.dumps(filtered).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if not self._check_auth():
            self._send_401()
            return
        if self.path == "/thresholds":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            try:
                data = json.loads(body)
                with thresholds_lock:
                    if "bpm_min"  in data: alert_thresholds["bpm_min"]  = int(data["bpm_min"])
                    if "bpm_max"  in data: alert_thresholds["bpm_max"]  = int(data["bpm_max"])
                    if "spo2_min" in data: alert_thresholds["spo2_min"] = int(data["spo2_min"])
                    result = dict(alert_thresholds)
                # Persist to shared file so careservice and BLE stay in sync
                try:
                    with open(THRESH_FILE, "w") as fh:
                        fh.write(f"bpm_min={alert_thresholds['bpm_min']}\n")
                        fh.write(f"bpm_max={alert_thresholds['bpm_max']}\n")
                        fh.write(f"spo2_min={alert_thresholds['spo2_min']}\n")
                except OSError:
                    pass
                resp = json.dumps({"ok": True, "thresholds": result}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", len(resp))
                self.end_headers()
                self.wfile.write(resp)
            except (ValueError, KeyError) as e:
                err = json.dumps({"error": str(e)}).encode()
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", len(err))
                self.end_headers()
                self.wfile.write(err)
        else:
            self.send_response(404)
            self.end_headers()

def snapshot_loop():
    """Freeze a copy of latest every SNAPSHOT_INTERVAL seconds into vitals_snapshot.
    Uses the snapshot's own timestamp to schedule the next freeze:
    sleeps until snapshot_timestamp + SNAPSHOT_INTERVAL, so callers that do the
    same arithmetic always align to the same update boundary.
    """
    global vitals_snapshot
    while True:
        with lock:
            new_snap = dict(latest)
        with snapshot_lock:
            vitals_snapshot = new_snap
        sys.stdout.write(
            f"[medical-sensor] Snapshot: BPM={new_snap.get('bpm')} SpO2={new_snap.get('spo2')}\n"
        )
        sys.stdout.flush()
        # Sleep until snapshot_timestamp + SNAPSHOT_INTERVAL
        next_at = new_snap.get("timestamp", time.time()) + SNAPSHOT_INTERVAL
        delay = max(0.0, next_at - time.time())
        time.sleep(delay)


# ── Main ───────────────────────────────────────────────────
def main():
    # Configure signal handlers
    signal.signal(signal.SIGTERM, handle_shutdown)
    signal.signal(signal.SIGINT, handle_shutdown)
    signal.signal(signal.SIGUSR1, handle_sigusr1)  # For logrotate
    signal.signal(signal.SIGHUP,  handle_sighup)   # Reload thresholds from file

    # Background sensor thread
    t = threading.Thread(target=sensor_loop, daemon=True)
    t.start()

    # Snapshot thread — freezes latest every 30s for /vitals
    threading.Thread(target=snapshot_loop, daemon=True).start()

    # Foreground HTTP server
    server = HTTPServer(("0.0.0.0", HTTP_PORT), VitalsHandler)
    sys.stdout.write(f"[medical-sensor] Listening on :{HTTP_PORT}\n")
    sys.stdout.write(f"[medical-sensor] Log file: {LOG_FILE}\n")
    sys.stdout.write(f"[medical-sensor] Summary every: {SUMMARY_EVERY}s\n")
    sys.stdout.write(f"[medical-sensor] Buffer max: {LOG_BUFFER_MAX} entries\n")
    sys.stdout.write("[medical-sensor] Send SIGUSR1 to reopen logs (logrotate)\n")
    sys.stdout.flush()

    # Load thresholds from the careservice file if it already exists
    _load_thresholds_from_file()

    # Background thread: auto-reload thresholds when careservice updates the file
    threading.Thread(target=_threshold_watcher, daemon=True).start()

    sys.stdout.write("[medical-sensor] Send SIGHUP to reload thresholds from careservice\n")
    sys.stdout.flush()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        handle_shutdown(None, None)

if __name__ == "__main__":
    main()
