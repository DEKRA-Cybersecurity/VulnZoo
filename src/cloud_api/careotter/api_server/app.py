"""
app.py — CareOtter Cloud API

Intermediary Flask between HTTP clients (mobile app, operators) and the
binary IGP v4 protocol of the CareOtter device at 192.168.2.1:9999.

Architecture:
    HTTP Client → Flask API (this file)
                       ↓ IGP v4 (TCP :9999)
                   CareOtter Device
                       ↓ HTTP (TCP :8081)
                   Local medical sensor

Operating modes (environment var VULNERABLE):
    1 = vulnerable: exposes raw fields, debug active, detailed errors
    0 = safe:       filters sensitive data, debug disabled
"""

import os
import time
import threading
import socket
import fcntl
import struct
import logging
import secrets
import hmac
import base64
import hashlib
from collections import deque
import requests as http_requests
from flask import Flask, jsonify, request, render_template, redirect, url_for, make_response, g, send_from_directory
from werkzeug.utils import secure_filename
from werkzeug.exceptions import NotFound
from config import Config
from core.igp_client import IGPError
from core.jwt_service import JWTService
from core.decorators import token_required, admin_required, web_login_required, web_admin_required, web_patient_required, web_caregiver_required, api_caregiver_required, _decode_and_validate
from services.device_service import DeviceService
from services.database_service import DatabaseService
from services.store_service import StoreService
from services.appointment_service import AppointmentService
from services.diagnostics_service import DiagnosticsService

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def _get_wifi_ip() -> str:
    """Return the host's WiFi IPv4 address.

    Resolution order:
      1. Env var ``HOST_WIFI_IP`` — required when running in Docker bridge mode
         because the container cannot see the host's wlan0 / phy*-sta* interface.
         The operator sets it in ``.env`` or on the compose command line, e.g.::

             HOST_WIFI_IP=$(ip -4 -o addr show | \\
               awk '/wl|phy.*sta/{split($4,a,"/"); print a[1]; exit}')

      2. Direct interface probe (only works with ``network_mode: host``).
         Tries common WiFi names plus anything in ``/proc/net/wireless``.
    """
    env_ip = os.getenv('HOST_WIFI_IP', '').strip()
    if env_ip and env_ip != '0.0.0.0':
        return env_ip

    SIOCGIFADDR = 0x8915
    candidates: list[str] = []
    try:
        with open('/proc/net/wireless') as f:
            for line in f.readlines()[2:]:
                name = line.split(':', 1)[0].strip()
                if name:
                    candidates.append(name)
    except OSError:
        pass
    # Static fallbacks for hosts where /proc/net/wireless is empty (bridge mode)
    for name in ('wlan0', 'wlan1', 'wlp2s0', 'wlp3s0', 'phy0-sta0', 'phy1-sta0'):
        if name not in candidates:
            candidates.append(name)
    for iface in candidates:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            res = fcntl.ioctl(s.fileno(), SIOCGIFADDR,
                              iface.encode().ljust(40, b"\x00"))
            s.close()
            ip = socket.inet_ntoa(res[20:24])
            if ip and ip != '0.0.0.0':
                return ip
        except OSError:
            pass
    return "0.0.0.0"


app  = Flask(__name__)
# API8 (Security Misconfiguration): the app routes slash-insensitively, so "/x" and
# "/x/" hit the same handler. The reverse proxy (proxy/nginx.vuln.conf) ACLs the
# admin/debug/init paths with EXACT-match rules, so a trailing slash slips past the
# deny while still reaching the handler — a proxy↔app path-interpretation conflict.
app.url_map.strict_slashes = False
vuln = Config.VULNERABLE

# Service instances (stateless — thread-safe for Flask dev server)
device = DeviceService()

# Initialize database with error handling
try:
    db = DatabaseService()
    logger.info(f"[App] Database initialized at: {Config.DB_PATH}")

    # Per-device IP architecture: DEVICE_IP global is deprecated.
    # Each device's WiFi IP is stored in the SQLite devices table
    # (device_ip + igp_port) and resolved per-request from the JWT.
    # The global Config.DEVICE_IP is kept only as a legacy fallback for
    # code paths that have not yet migrated to per-device resolution.

    # NO default users are created at startup — the device must register itself
    # via POST /admin/device/register (or fallback GET /initialize_iot for lab operators).
    user_count = db.user_count() if db else 0
    logger.info(f"[App] Users in database: {user_count} (0 = waiting for device registration)")
except Exception as e:
    logger.error(f"[App] Failed to initialize database: {e}")
    db = None

# Health Store service (API6:2023 — sensitive business flow). Patient purchase
# flow with secure controls in StoreService; intentional vuln deferred to Phase 2.
store = StoreService(db) if db else None
# Teleconsultation booking service (API6:2023 — sensitive business flow)
appt = AppointmentService(db) if db else None
# Device diagnostics probe (API7:2023 — SSRF). URL-whitelist bypass in VULNERABLE mode.
diag = DiagnosticsService(db) if db else None

# ── Device MAC resolution ─────────────────────────────────────────────────────
# Per-device IP model: the background thread polls every device that has a
# device_ip in the SQLite devices table. If the sensor /health reports a
# different wifi_ip, the row is updated in-place.
# Falls back to the env var DEFAULT_DEVICE_MAC so the API still works in dev/CI.

DEVICE_MAC: str = os.getenv('DEFAULT_DEVICE_MAC', 'AA:BB:CC:DD:EE:FF')


def _fetch_device_mac() -> None:
    """Periodic background resolver for DEVICE_MAC + per-device IPs.

    Runs forever in a daemon thread. Each tick:
      1. Queries the SQLite devices table for every row with a non-null
         ``device_ip``.
      2. Polls ``/health`` on each IP to detect WiFi roaming.
      3. If ``wifi_ip`` (or legacy ``wlan0_ip``) differs from the stored
         ``device_ip``, updates the row in-place so subsequent IGP calls
         target the correct address.
      4. Updates the module-level ``DEVICE_MAC`` from the first reachable
         device.
    """
    global DEVICE_MAC
    INTERVAL_OK = 60
    INTERVAL_RETRY = 10
    while True:
        if not db:
            time.sleep(INTERVAL_RETRY)
            continue
        try:
            devices_with_ip = db.list_devices_with_ip()
        except Exception as e:
            logger.debug(f"[Device] Could not list devices with IP: {e}")
            time.sleep(INTERVAL_RETRY)
            continue

        if not devices_with_ip:
            logger.debug("[Device] No devices with IP yet — waiting for registration")
            time.sleep(INTERVAL_RETRY)
            continue

        reachable = False
        for dev in devices_with_ip:
            ip = dev.get('device_ip')
            mac = dev.get('mac', '').upper()
            if not ip:
                continue
            sensor_url = f"http://{ip}:{Config.HTTP_PORT}/health"
            try:
                resp = http_requests.get(sensor_url, timeout=3)
                resp.raise_for_status()
                payload = resp.json() or {}
                reported_mac = payload.get('mac', '').upper()
                if reported_mac and reported_mac != '00:00:00:00:00:00' and reported_mac != DEVICE_MAC:
                    DEVICE_MAC = reported_mac
                    logger.info(f"[Device] Resolved MAC from sensor: {DEVICE_MAC}")
                wlan_ip = payload.get('wifi_ip') or payload.get('wlan0_ip', '0.0.0.0')
                if wlan_ip and wlan_ip != '0.0.0.0' and wlan_ip != ip:
                    db.update_device_ip(mac, wlan_ip, dev.get('igp_port', 9999))
                    logger.info(
                        f"[Device] Device IP updated {mac}: {ip} -> {wlan_ip} "
                        f"(iface={payload.get('wifi_iface', '?')} via sensor /health)"
                    )
                    # Legacy: also update global Config.DEVICE_IP for backward compat
                    Config.DEVICE_IP = wlan_ip
                reachable = True
            except Exception as e:
                logger.debug(f"[Device] Sensor /health unreachable at {sensor_url}: {e}")

        time.sleep(INTERVAL_OK if reachable else INTERVAL_RETRY)


# Start MAC resolution immediately but don't block Flask startup
threading.Thread(target=_fetch_device_mac, daemon=True).start()


def _refresh_device_ip_from_sensor(host: str = None, attempts: int = 8, delay: float = 1.5) -> str | None:
    """Poll the sensor /health endpoint until wlan0 reports a non-zero IPv4.

    Called after a successful IGP 0x06 SET_WIFI so subsequent cloud→device
    traffic flows over the freshly provisioned WiFi link. Returns the new IP
    or ``None`` on timeout.
    """
    target = host or Config.DEVICE_IP
    if not target:
        logger.warning("[set_wifi] No host available to poll /health")
        return None
    sensor_url = f"http://{target}:{Config.HTTP_PORT}/health"
    for attempt in range(1, attempts + 1):
        try:
            resp = http_requests.get(sensor_url, timeout=3)
            resp.raise_for_status()
            payload = resp.json() or {}
            wlan_ip = payload.get('wifi_ip') or payload.get('wlan0_ip', '0.0.0.0')
            if wlan_ip and wlan_ip != '0.0.0.0':
                logger.info(f"[set_wifi] Device IP refreshed: {target} -> {wlan_ip} (via sensor /health)")
                return wlan_ip
            logger.debug(f"[set_wifi] /health attempt {attempt}/{attempts}: wlan0 still 0.0.0.0")
        except Exception as e:
            logger.debug(f"[set_wifi] /health attempt {attempt}/{attempts} failed: {e}")
        time.sleep(delay)
    logger.warning(f"[set_wifi] wlan0 IP did not converge after {attempts} polls ({attempts*delay:.0f}s)")
    return None

# ── Shared vitals cache (PUSH architecture) ──────────────────────────────────
# In the new push model the Pi sends vitals to POST /api/device/vitals.
# The latest reading is read directly from SQLite via db.get_latest_vitals().
# This dict is kept only for backward compatibility of any code that might
# reference it; it is no longer populated by a background collector.
_latest_vitals: dict = {}
_latest_vitals_lock = threading.Lock()


# ── Per-device IGP resolution helper ──────────────────────────────────────────

def _get_device_for_current_user() -> tuple[str | None, int | None, dict | None]:
    """Resolve the IGP endpoint (host, port, device_row) for the authenticated user.

    Reads ``g.current_user`` (set by ``@token_required``), looks up the user's
    device in the ``devices`` table, and returns ``(device_ip, igp_port, row)``.
    If the user has no associated device, returns ``(None, None, None)``.
    """
    payload = g.current_user if hasattr(g, 'current_user') else None
    if not payload:
        return None, None, None
    username = payload.get('sub') or payload.get('username', '')
    if not username or not db:
        return None, None, None
    # The admin panel manages the global CareOtter device (the Raspberry Pi),
    # not a per-patient owned device — admins own no row in `devices`, so the
    # per-patient lookup below would wrongly report "no device" and 404 every
    # admin endpoint (network / wifi / preferences / services / logs). Resolve
    # admins to the live Config.DEVICE_IP — the same address /api/device/ping
    # and /api/health already use — with no DB row (the row can be stale; the
    # in-memory IP is promoted by _refresh_device_ip_from_sensor). Patient and
    # caregiver resolution is unchanged, so the /api/config/thresholds BFLA
    # chain still resolves to the patient's own device.
    if payload.get('role') == 'admin':
        return (Config.DEVICE_IP or None, Config.IGP_PORT, None)
    device_row = db.get_device_by_patient(username)
    if not device_row:
        return None, None, None
    return (
        device_row.get('device_ip'),
        device_row.get('igp_port', 9999),
        device_row
    )


# ── Brute-force protection for /api/devices/register-by-hash ─────────────────
# Per-user sliding-window rate limit. Resets after RATE_LIMIT_WINDOW seconds
# of inactivity. Stops the trivial enumeration vector where a logged-in
# patient hammers the endpoint with candidate hashes.
RATE_LIMIT_MAX_ATTEMPTS = 5
RATE_LIMIT_WINDOW = 900      # 15 minutes
_register_attempts: dict[str, deque] = {}
_register_attempts_lock = threading.Lock()


def _register_rate_check(user_key: str) -> tuple[bool, float]:
    """Returns (allowed, retry_after_seconds). Call BEFORE attempting the
    lookup so an attacker doesn't get free probes; counter is incremented
    only by _register_record_fail() on confirmed failures."""
    now = time.time()
    with _register_attempts_lock:
        dq = _register_attempts.get(user_key)
        if dq is None:
            return True, 0.0
        # Evict expired entries from the left
        while dq and now - dq[0] >= RATE_LIMIT_WINDOW:
            dq.popleft()
        if len(dq) >= RATE_LIMIT_MAX_ATTEMPTS:
            retry_after = RATE_LIMIT_WINDOW - (now - dq[0])
            return False, max(retry_after, 1.0)
        return True, 0.0


def _register_record_fail(user_key: str) -> None:
    with _register_attempts_lock:
        dq = _register_attempts.setdefault(user_key, deque())
        dq.append(time.time())


# ── Brute-force protection for /api/auth/login/patient ───────────────────────
# Per-username sliding-window rate limit on the patient login endpoint.
#
# INTENTIONAL VULNERABILITY (VULNERABLE=1): in login_patient() the limiter is
# wired in *after* the patient-role gate, so any non-patient account (admin /
# caregiver) short-circuits to a 401/403 response BEFORE the counter is ever
# touched. That gives an attacker (a) unlimited brute-force attempts against an
# admin password — 429 never fires — and (b) a 401-vs-403 oracle that reveals
# when a guessed admin password is correct. With VULNERABLE=0 the limiter runs
# first and the role gate collapses into a uniform 401 (no oracle, every path
# throttled). Same sliding-window mechanism as the register limiter above.
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW = 300           # 5 minutes
_login_attempts: dict[str, deque] = {}
_login_attempts_lock = threading.Lock()


def _login_rate_check(user_key: str) -> tuple[bool, float]:
    """Returns (allowed, retry_after_seconds) for a login key. The counter is
    incremented only by _login_record_fail() on a confirmed credential failure,
    so a successful login never costs an attempt."""
    now = time.time()
    with _login_attempts_lock:
        dq = _login_attempts.get(user_key)
        if dq is None:
            return True, 0.0
        while dq and now - dq[0] >= LOGIN_WINDOW:
            dq.popleft()
        if len(dq) >= LOGIN_MAX_ATTEMPTS:
            retry_after = LOGIN_WINDOW - (now - dq[0])
            return False, max(retry_after, 1.0)
        return True, 0.0


def _login_record_fail(user_key: str) -> None:
    with _login_attempts_lock:
        dq = _login_attempts.setdefault(user_key, deque())
        dq.append(time.time())


def _login_reset(user_key: str) -> None:
    """Clear the failure window on a successful login (standard reset-on-success).
    Also keeps the mobile app's admin-first → patient-fallback flow from locking a
    patient out: the throwaway admin-endpoint 401 is wiped when the patient login
    that follows it succeeds."""
    with _login_attempts_lock:
        _login_attempts.pop(user_key, None)


# ── Cloud-side vitals simulator (alice_g67 + genuinebob49) ───────────────────
# Two virtual CareOtter devices live entirely inside the Cloud API container.
# They generate vitals with the same MAX30102Simulator model the bedside Pi
# uses, but insert directly into the database (no HTTP round-trip, no auth
# headers — those are for real devices). MAC prefix 02:CE:01:00:00:0X is in
# the locally-administered IEEE range (bit 1 of first octet = 1) so the
# address is syntactically valid but not assigned to any manufacturer.
#
# Aggregation + retention thread runs alongside: every minute it rolls up
# completed minute buckets into ``vitals_minute_agg``, every hour it folds
# minutes into ``vitals_hour_agg``, and every hour it prunes raw rows older
# than 24h and minute aggs older than 30d.

import math
import random

_CLOUD_SIM_DEVICES = [
    {
        'mac':              '02:CE:01:00:00:01',
        'patient_username': 'alice_g67',
        'device_name':      'CareOtter_HR (cloud-sim:alice)',
        'baseline_bpm':     74,
        'baseline_spo2':    98,
        'device_ip':        'careservice-alice',
        'igp_port':         9999,
    },
    {
        'mac':              '02:CE:01:00:00:02',
        'patient_username': 'genuinebob49',
        'device_name':      'CareOtter_HR (cloud-sim:bob)',
        'baseline_bpm':     68,
        'baseline_spo2':    97,
        'device_ip':        'careservice-bob',
        'igp_port':         9999,
    },
]
CLOUD_SIM_INTERVAL = 10   # seconds between inserts (matches Pi cron cadence)
AGGREGATOR_INTERVAL = 60  # seconds between rollup passes
PRUNE_INTERVAL = 3600     # seconds between retention sweeps


def _cloud_simulator_tick(device_cfg: dict, t0: float) -> dict:
    """Generate one (bpm, spo2) sample for a virtual device.
    Uses the same sinusoidal PPG + gaussian noise model as
    labs/careotter/files/opt/medical-sensor/simulator.py, but only outputs
    derived BPM/SpO2 since the cloud no longer stores raw ADC values.
    """
    bpm_base = device_cfg['baseline_bpm']
    spo2_base = device_cfg['baseline_spo2']
    t = time.time() - t0
    # Slow breathing-rate-style drift around the baseline
    drift = 2.0 * math.sin(2 * math.pi * t / 90.0)
    bpm = int(max(50, min(110, bpm_base + drift + random.gauss(0, 1.2))))
    spo2 = int(max(94, min(100, spo2_base + random.gauss(0, 0.4))))
    return {'bpm': bpm, 'spo2': spo2}


def _cloud_simulator_loop():
    """Background loop that inserts vitals for every entry in
    ``_CLOUD_SIM_DEVICES`` every ``CLOUD_SIM_INTERVAL`` seconds."""
    if not db:
        logger.warning("[CloudSim] DB unavailable — simulator thread exiting")
        return
    t0 = time.time()
    logger.info(f"[CloudSim] Starting virtual devices: "
                f"{[d['mac'] for d in _CLOUD_SIM_DEVICES]}")
    while True:
        for dev in _CLOUD_SIM_DEVICES:
            try:
                sample = _cloud_simulator_tick(dev, t0)
                payload = {
                    'timestamp': time.time(),
                    'bpm': sample['bpm'],
                    'spo2': sample['spo2'],
                    'source': 'cloud-simulator',
                }
                db.store_vitals(payload, device_mac=dev['mac'])
            except Exception as e:
                logger.error(f"[CloudSim] tick failed for {dev['mac']}: {e}")
        time.sleep(CLOUD_SIM_INTERVAL)


def _vitals_aggregator_loop():
    """Background loop that maintains the warm/cold tiers and prunes the hot
    tier. One thread handles both because the operations are cheap and run
    on different cadences (rollups every minute, prune every hour)."""
    if not db:
        logger.warning("[Aggregator] DB unavailable — aggregator thread exiting")
        return
    last_prune = 0.0
    logger.info("[Aggregator] Started (rollup 60s, prune 3600s)")
    while True:
        try:
            db.rollup_minute_aggregates()
            db.rollup_hour_aggregates()
            now = time.time()
            if now - last_prune >= PRUNE_INTERVAL:
                db.prune_vitals_tiers()
                last_prune = now
        except Exception as e:
            logger.error(f"[Aggregator] loop iteration failed: {e}")
        time.sleep(AGGREGATOR_INTERVAL)


def _ensure_cloud_sim_devices() -> None:
    """Seed the patient users + virtual device rows the simulator depends on.
    Idempotent — called once at startup right before launching the threads."""
    if not db:
        return
    db.create_or_update_user('alice_g67', 'Aliceisthebest!', 'patient')
    db.create_or_update_user('genuinebob49', 'spongebob1', 'patient')
    # API7 SSRF victim — a dedicated, re-seedable target the attacker deletes via the internal
    # admin endpoint reached through the diagnostics SSRF. Kept separate so the exploit never
    # has to delete john_doe / care_john (which would break the API1/API3 chains).
    db.create_or_update_user('target_tom', 'Target2026!', 'patient')
    # Health Store: ensure a virtual wallet (with salary) for every patient user.
    db.seed_store_wallets()
    # Teleconsultation: seed a scarce set of open appointment slots.
    db.seed_appointment_slots()
    for d in _CLOUD_SIM_DEVICES:
        db.register_device(
            d['mac'], d['patient_username'], d['device_name'],
            auth_hash=None,
            device_ip=d.get('device_ip'),
            igp_port=d.get('igp_port', 9999),
        )
        # Enforce single-device-per-patient — drop any legacy demo row that
        # earlier seeds left behind so the patient dashboard never shows two
        # competing devices for the same user.
        db.delete_other_devices_for_patient(d['patient_username'], keep_mac=d['mac'])


# ── Global error handling ──────────────────────────────────────────────────────

@app.errorhandler(Exception)
def handle_exception(e):
    """
    Catches unhandled errors.
    VULNERABILITY (vuln=1): exposes exception type and message including
    raw IGP responses that may contain device data.
    """
    if vuln == 1:
        return jsonify({
            'error': str(e),
            'type':  type(e).__name__
        }), 500
    return jsonify({'error': 'Internal server error'}), 500


# ── HTML Routes ────────────────────────────────────────────────────────────────

@app.route('/')
@web_patient_required
def index():
    """
    Patient home page — Medical device monitor.
    Displays real-time vital signs. Requires patient login.
    """
    return render_template('index.html')

@app.route('/admin/login')
def admin_login():
    return render_template('login.html')

@app.route('/admin/dashboard')
@web_admin_required
def admin_dashboard():
    return render_template('dashboard.html')

@app.route('/admin/network')
@web_admin_required
def admin_network():
    return render_template('network.html')

@app.route('/admin/config')
@web_admin_required
def admin_config():
    return render_template('config.html')

@app.route('/admin/services')
@web_admin_required
def admin_services():
    return render_template('services.html')

@app.route('/admin/logs')
@web_admin_required
def admin_logs():
    return render_template('logs.html')

@app.route('/admin/users')
@web_admin_required
def admin_users():
    return render_template('users.html')

@app.route('/patient/login')
def patient_login():
    return render_template('patient_login.html')

@app.route('/caregiver/dashboard')
@web_caregiver_required
def caregiver_dashboard():
    """Caregiver home page — Access patient vitals via BOLA endpoint."""
    return render_template('caregiver_dashboard.html')

@app.route('/history')
@web_patient_required
def history_page():
    """
    Patient history page — View all historical vitals from database.
    Requires patient login.
    Fetches current clinical thresholds from the device so charts and
    badges reflect the real configuration rather than hardcoded defaults.
    """
    try:
        thresh = device.get_thresholds()
        thresholds = {
            'bpm_min':  thresh.get('bpm_min', 60),
            'bpm_max':  thresh.get('bpm_max', 100),
            'spo2_min': thresh.get('spo2_min', 95)
        }
    except Exception:
        thresholds = {'bpm_min': 60, 'bpm_max': 100, 'spo2_min': 95}
    return render_template('history.html', thresholds=thresholds)


@app.route('/profile')
@web_patient_required
def profile_page():
    """Patient self-service profile page — change photo, password, username."""
    return render_template('profile.html')


@app.route('/store')
@web_patient_required
def store_page():
    """Patient Health Store page — browse products, draw salary, purchase."""
    return render_template('store.html')


# ── Health Store API (API6:2023 — sensitive business flow) ─────────────────────
# @token_required (patient access) is CORRECT — API6 is about unprotected automation
# of a sensitive flow, not auth. The wallet is a FIXED budget (no top-up endpoint).
# The secure control is the per-patient purchase quota in StoreService; with
# VULNERABLE=1 it is dropped so one patient can hoard the scarce inventory.

@app.route('/api/store/products', methods=['GET'])
@token_required
def store_products():
    if not store:
        return jsonify({'error': 'Store unavailable'}), 503
    return jsonify({'products': store.get_products()}), 200


@app.route('/api/store/products/<int:product_id>', methods=['GET'])
@token_required
def store_product(product_id):
    if not store:
        return jsonify({'error': 'Store unavailable'}), 503
    prod = store.get_product(product_id)
    if not prod:
        return jsonify({'error': 'Product not found'}), 404
    return jsonify({'product': prod}), 200


@app.route('/api/store/wallet', methods=['GET'])
@token_required
def store_wallet():
    if not store:
        return jsonify({'error': 'Store unavailable'}), 503
    username = g.current_user.get('sub') or g.current_user.get('username', '')
    wallet = store.get_wallet(username)
    if not wallet:
        return jsonify({'error': 'Wallet not found'}), 404
    return jsonify({'wallet': wallet}), 200


@app.route('/api/store/purchase', methods=['POST'])
@token_required
def store_purchase():
    if not store:
        return jsonify({'error': 'Store unavailable'}), 503
    username = g.current_user.get('sub') or g.current_user.get('username', '')
    data = request.get_json(force=True, silent=True) or {}
    try:
        product_id = int(data.get('product_id'))
        q = data.get('quantity')
        if Config.VULNERABLE == 1:
            # VULNERABLE (API3 Variant B — property tampering): the ONLY way to smuggle a
            # negative quantity is a FLOAT-FORMATTED STRING (e.g. "-1.0"). Native ints are
            # range-checked, native floats/bools are rejected, and plain integer strings
            # ("-1") are rejected — but a string containing a "." is coerced via
            # int(float(...)) and truncates, so "-1.0" → -1, and try_purchase's signed
            # arithmetic then credits the wallet / inflates stock.
            if isinstance(q, bool) or isinstance(q, float):
                raise ValueError("quantity must be an integer")
            elif isinstance(q, int):
                if q < 1:
                    raise ValueError("quantity must be a positive integer")
                quantity = q
            elif isinstance(q, str) and q.isdigit():
                quantity = int(q)                 # "5" → legit positive integer string
            elif isinstance(q, str) and '.' in q:
                quantity = int(float(q))          # "-1.0" → -1   (the vulnerable vector)
            else:
                # "-1", "abc", None, … — not a positive int and not a float literal
                raise ValueError("quantity must be a positive integer")
        else:
            # SECURE: require a genuine positive integer. Reject float/str/bool outright so the
            # type-confusion bypass can never produce a negative quantity. (bool is an int
            # subclass in Python, so it is excluded explicitly.)
            if isinstance(q, bool) or not isinstance(q, int) or q < 1:
                raise ValueError("quantity must be a positive integer")
            quantity = q
    except (TypeError, ValueError) as e:
        return jsonify({'error': str(e)}), 400
    result = store.purchase(username, product_id, quantity)
    if not result.get('ok'):
        err  = result.get('error')
        code = 404 if err == 'not_found' else (402 if err == 'insufficient_funds' else 409)
        return jsonify(result), code
    return jsonify(result), 201


@app.route('/api/store/orders', methods=['GET'])
@token_required
def store_orders():
    if not store:
        return jsonify({'error': 'Store unavailable'}), 503
    username = g.current_user.get('sub') or g.current_user.get('username', '')
    return jsonify({'orders': store.get_orders(username)}), 200


# ── Teleconsultation appointments (API6:2023 — sensitive business flow) ────────
# @token_required (patient access) is CORRECT — API6 is about the MISSING per-patient
# booking cap on a sensitive flow, not auth. The cap lives in AppointmentService; with
# VULNERABLE=1 it is dropped so one patient can book every slot (denial of care). The
# slot claim stays atomic in both modes (no double-booking) — clean API6, not a race.

@app.route('/appointments')
@web_patient_required
def appointments_page():
    """Patient teleconsultation booking page — browse open slots, book, cancel."""
    return render_template('appointments.html')


@app.route('/api/appointments/slots', methods=['GET'])
@token_required
def appointments_slots():
    if not appt:
        return jsonify({'error': 'Appointments unavailable'}), 503
    return jsonify({'slots': appt.get_slots()}), 200


@app.route('/api/appointments/mine', methods=['GET'])
@token_required
def appointments_mine():
    if not appt:
        return jsonify({'error': 'Appointments unavailable'}), 503
    username = g.current_user.get('sub') or g.current_user.get('username', '')
    return jsonify({'appointments': appt.get_mine(username)}), 200


@app.route('/api/appointments/book', methods=['POST'])
@token_required
def appointments_book():
    if not appt:
        return jsonify({'error': 'Appointments unavailable'}), 503
    username = g.current_user.get('sub') or g.current_user.get('username', '')
    data = request.get_json(force=True, silent=True) or {}
    try:
        slot_id = int(data.get('slot_id'))
    except (TypeError, ValueError):
        return jsonify({'error': 'slot_id must be an integer'}), 400
    result = appt.book(username, slot_id)
    if not result.get('ok'):
        return jsonify(result), 409
    return jsonify(result), 201


# The route accepts GET/DELETE alongside POST so the method check happens INSIDE the handler
# (in AppointmentService.cancel). The endpoint is only *meant* to be POST; with VULNERABLE=1
# the cancel flow decrements the per-patient counter before it verifies the method, so a
# non-POST request desyncs the counter without releasing the slot (API6 slot hoarding).
@app.route('/api/appointments/cancel', methods=['POST', 'GET', 'DELETE'])
@token_required
def appointments_cancel():
    if not appt:
        return jsonify({'error': 'Appointments unavailable'}), 503
    username = g.current_user.get('sub') or g.current_user.get('username', '')
    data = request.get_json(force=True, silent=True) or {}
    # slot_id may arrive in the JSON body (POST) or the query string (GET/DELETE).
    raw = data.get('slot_id', request.args.get('slot_id'))
    try:
        slot_id = int(raw)
    except (TypeError, ValueError):
        return jsonify({'error': 'slot_id must be an integer'}), 400
    result = appt.cancel(username, slot_id, http_method=request.method)
    if result.get('error') == 'method_not_allowed':
        return jsonify(result), 405
    if not result.get('ok'):
        return jsonify(result), 409
    return jsonify(result), 200


# ── Device Diagnostics (INTENTIONALLY VULNERABLE to SSRF — API7:2023) ──────────
# The cloud fetches a device URL server-side and reflects the response. In VULNERABLE=1 the
# host whitelist is bypassable via embedded credentials (a naive parser in DiagnosticsService),
# so `http://<device-host>@127.0.0.1:5002/api/users/...` reaches the loopback-only admin
# API → a patient escalates to deleting any user. Do NOT "fix" the parser or the loopback trust.

@app.route('/diagnostics')
@web_patient_required
def diagnostics_page():
    """Patient device-diagnostics page — linked from the index.html nav bar.
    Pre-fills the probe field with the LOGGED-IN PATIENT's own registered device
    IP (the `devices` row whose patient_username matches them) — NOT the global
    Config.DEVICE_IP. If the patient has not registered/claimed a device, the
    field is left empty and the placeholder prompts for their device IP."""
    payload = _decode_and_validate() or {}
    username = payload.get('sub') or payload.get('username', '')
    dev = db.get_device_by_patient(username) if (db and username) else None
    device_ip = (dev.get('device_ip') or '') if dev else ''
    return render_template('diagnostics.html', device_ip=device_ip)


@app.route('/api/device/diagnostics', methods=['POST'])
@token_required
def device_diagnostics():
    if not diag:
        return jsonify({'error': 'Diagnostics unavailable'}), 503
    username = g.current_user.get('sub') or g.current_user.get('username', '')
    data = request.get_json(force=True, silent=True) or {}
    probe_url = data.get('probe_url', '')
    # Protection: probe is validated against the requester's OWN registered device(s).
    result = diag.probe(probe_url, username)
    if not result.get('ok'):
        err = result.get('error')
        if err == 'no_device':
            code = 403          # patient must register a device before diagnosing
        elif err in ('invalid_url', 'host_not_allowed'):
            code = 400
        else:
            code = 502
        return jsonify(result), code
    return jsonify(result), 200


@app.route('/api/users', methods=['GET'])
@admin_required
def api_users_list():
    """List all users (admin only) — feeds the User Administration autocomplete.
    Projection excludes password_hash (db.list_users)."""
    return jsonify({'users': db.list_users() if db else []}), 200


# User-management endpoint — role-aware, but Branch C (loopback, no JWT) is the UNCHANGED API7 SSRF
# confused-deputy. Auth is layered IN FRONT: an admin JWT deletes any user (no confirmation); a
# non-admin JWT may delete ONLY itself and must supply its password. With no valid JWT a loopback
# caller still deletes any user (the SSRF); everyone else gets 404. INTENTIONAL — do NOT "fix" the
# loopback trust or the (API2) forgeable-admin-JWT path.
@app.route('/api/users/delete', methods=['GET', 'POST'])
def api_users_delete():
    payload = _decode_and_validate()   # Bearer header OR careotter_token cookie; None if absent/invalid

    # Branch A — authenticated admin: delete any chosen user, no confirmation.
    if payload and payload.get('role') == 'admin':
        username = request.args.get('username') or (request.get_json(silent=True) or {}).get('username', '')
        if not username:
            return jsonify({'ok': False, 'error': 'username required'}), 400
        deleted = bool(db.delete_user(username)) if db else False
        return jsonify({'ok': deleted, 'deleted': username if deleted else None,
                        'via': 'admin'}), (200 if deleted else 404)

    # Branch B — authenticated non-admin (patient/caregiver): self-delete only, password required.
    if payload:
        username = payload.get('sub') or payload.get('username', '')   # SELF ONLY — never client input
        data = request.get_json(silent=True) or {}
        password = data.get('password', '')
        if not password:
            return jsonify({'ok': False, 'error': 'password required'}), 400
        if not db or not db.verify_user(username, password):
            return jsonify({'ok': False, 'error': 'invalid password'}), 403
        deleted = bool(db.delete_user(username))
        return jsonify({'ok': deleted, 'deleted': username if deleted else None,
                        'via': 'self-service'}), (200 if deleted else 404)

    # Branch C — no valid JWT: the loopback-trust SSRF confused-deputy (API7), byte-identical.
    remote = request.remote_addr or ''
    if remote not in ('127.0.0.1', '::1', 'localhost'):
        return jsonify({'error': 'Not Found'}), 404
    username = request.args.get('username', '')
    if not username:
        return jsonify({'ok': False, 'error': 'username required'}), 400
    deleted = bool(db.delete_user(username)) if db else False
    return jsonify({'ok': deleted, 'deleted': username if deleted else None,
                    'via': 'internal-loopback'}), (200 if deleted else 404)


@app.route('/robots.txt')
def robots_txt():
    # Discovery clue (model D): hints at the privileged user-management path without exposing it.
    return ("User-agent: *\nDisallow: /api/users/\n", 200,
            {'Content-Type': 'text/plain; charset=utf-8'})


# ── Health ────────────────────────────────────────────────────────────────────

@app.route('/api/health')
def api_health():
    """API status — no authentication.
    Exposes wifi_ip so the BLE server (on the device) can embed the
    WiFi-reachable API address in ManufacturerData advertising.
    """
    return jsonify({
        'status':   'ok',
        'service':  'careotter-api',
        'version':  '1.0.0',
        'raspberry_pi_ip':   f"{Config.DEVICE_IP}:{Config.IGP_PORT}",
        'api_ip':  _get_wifi_ip(),
        'api_port': int(os.getenv('PORT', 5002)),
    })


# ── Authentication ────────────────────────────────────────────────────────────

@app.route('/api/auth/login', methods=['POST'])
def login():
    """
    Authenticates an administrator against the local SQLite user database
    (the admin panel login).

    Expects JSON body with 'username' and 'password'. Verifies credentials and
    requires role='admin'. On success, issues a JWT session token.

    This endpoint is deliberately NOT an oracle:
      * A per-username sliding-window rate limit (LOGIN_MAX_ATTEMPTS /
        LOGIN_WINDOW) is ALWAYS enforced — regardless of Config.VULNERABLE.
      * Any failed login returns an identical 401 whether the credentials were
        wrong OR the account is simply not an admin (no allowed_roles, no 403).
        So it reveals no difference between a patient and an admin username.
    The only intentional online admin-credential oracle in the lab is the 403
    differential on /api/auth/login/patient (see login_patient).

    NOTE: passwords are hashed with SHA-256 without salt — an intentional
    vulnerability for the lab (enables offline cracking of a leaked DB, not
    online brute force here).

    Body JSON:
        {"username": "admin", "password": "CareOtter2026!"}
    """
    data = request.get_json(force=True, silent=True) or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username:
        return jsonify({'error': 'Field "username" required', 'code': 'MISSING_FIELD'}), 400
    if not password:
        return jsonify({'error': 'Field "password" required', 'code': 'MISSING_FIELD'}), 400

    if db is None:
        return jsonify({'error': 'Database unavailable', 'code': 'DB_ERROR'}), 503

    # Rate-limit first — always on, no role branch, no VULNERABLE toggle.
    allowed, retry_after = _login_rate_check(username)
    if not allowed:
        resp = jsonify({'error': 'Too many login attempts. Try again later.', 'code': 'RATE_LIMITED'})
        resp.headers['Retry-After'] = str(int(retry_after))
        return resp, 429

    user = db.verify_user(username, password)
    # Admin-only, uniform failure: wrong credentials and non-admin accounts are
    # indistinguishable (both 401), so this endpoint leaks no role information.
    if user is None or user.get('role') != 'admin':
        _login_record_fail(username)
        return jsonify({
            'error': 'Invalid username or password',
            'code':  'AUTH_FAIL'
        }), 401

    _login_reset(username)   # successful login clears the failure window
    jwt_token = JWTService.generate_token(username=username, role=user.get('role', 'admin'))
    resp = make_response(jsonify({
        'token':      jwt_token,
        'expires_in': f"{Config.JWT_EXPIRATION_HOURS}h",
        'type':       'Bearer',
        'role':       user.get('role'),
        'username':   username
    }))
    resp.set_cookie('careotter_token', jwt_token, httponly=True, samesite='Lax', max_age=3600*Config.JWT_EXPIRATION_HOURS)
    return resp, 200


@app.route('/api/auth/login/patient', methods=['POST'])
def login_patient():
    """
    Patient-only login endpoint.

    Same authentication flow as /api/auth/login, but rejects non-patient roles.
    Used by the patient portal web UI and mobile app patient mode.

    Brute-force protection is per-username (LOGIN_MAX_ATTEMPTS / LOGIN_WINDOW).

    INTENTIONAL VULNERABILITY (VULNERABLE=1): the patient-role gate is evaluated
    BEFORE the rate-limit check, and the role is resolved by *username* (not by a
    successful password verification). So every non-patient account (admin /
    caregiver) returns 401/403 without ever incrementing the limiter. An attacker
    therefore (a) learns the username is a non-patient because 429 never fires
    no matter how many guesses, and (b) brute-forces the admin password with
    unlimited attempts, reading 401 (wrong) vs 403 (correct) as a "password
    correct" oracle. With VULNERABLE=0 the limiter runs first and every
    non-patient-success collapses into a uniform, rate-limited 401.
    """
    data = request.get_json(force=True, silent=True) or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username:
        return jsonify({'error': 'Field "username" required', 'code': 'MISSING_FIELD'}), 400
    if not password:
        return jsonify({'error': 'Field "password" required', 'code': 'MISSING_FIELD'}), 400

    if db is None:
        return jsonify({'error': 'Database unavailable', 'code': 'DB_ERROR'}), 503

    user = db.verify_user(username, password)          # dict iff username+password both valid

    if Config.VULNERABLE == 1:
        # BUG: role gate first, resolved by username — fires for any non-patient
        # account *before* the limiter, so this branch never rate-limits.
        account = db.get_user_by_username(username)
        if account is not None and account.get('role') != 'patient':
            if user is not None:                       # correct credentials → oracle: CORRECT
                return jsonify({
                    'error': 'Access denied for this role',
                    'code':  'FORBIDDEN'
                }), 403
            return jsonify({                           # wrong password → oracle: WRONG
                'error': 'Invalid username or password',
                'code':  'AUTH_FAIL'
            }), 401

        # Patients and unknown usernames: the (correctly) rate-limited path.
        allowed, retry_after = _login_rate_check(username)
        if not allowed:
            resp = jsonify({'error': 'Too many login attempts. Try again later.', 'code': 'RATE_LIMITED'})
            resp.headers['Retry-After'] = str(int(retry_after))
            return resp, 429
        if user is None:
            _login_record_fail(username)
            return jsonify({
                'error': 'Invalid username or password',
                'code':  'AUTH_FAIL'
            }), 401
    else:
        # Secure: rate-limit FIRST, then a uniform 401 for any failure or
        # non-patient role — no 401/403 oracle, every path counts toward the cap.
        allowed, retry_after = _login_rate_check(username)
        if not allowed:
            resp = jsonify({'error': 'Too many login attempts. Try again later.', 'code': 'RATE_LIMITED'})
            resp.headers['Retry-After'] = str(int(retry_after))
            return resp, 429
        if user is None or user.get('role') != 'patient':
            _login_record_fail(username)
            return jsonify({
                'error': 'Invalid username or password',
                'code':  'AUTH_FAIL'
            }), 401

    _login_reset(username)   # successful login clears the failure window
    jwt_token = JWTService.generate_token(username=username, role=user.get('role', 'patient'))
    resp = make_response(jsonify({
        'token':      jwt_token,
        'expires_in': f"{Config.JWT_EXPIRATION_HOURS}h",
        'type':       'Bearer',
        'role':       user.get('role'),
        'username':   username
    }))
    resp.set_cookie('careotter_token', jwt_token, httponly=True, samesite='Lax', max_age=3600*Config.JWT_EXPIRATION_HOURS)
    return resp, 200


# ── Patient caregiver management ──────────────────────────────────────────────

@app.route('/api/patient/caregivers', methods=['POST'])
@token_required
def add_patient_caregiver():
    """Patient adds a caregiver to their account.

    Body JSON: {"caregiver_username": "care_john"}
    """
    current = g.current_user
    patient_username = current.get('sub') or current.get('username', '')
    if current.get('role') not in ('patient', 'admin'):
        return jsonify({'error': 'Only patients can manage caregivers', 'code': 'FORBIDDEN'}), 403

    data = request.get_json(force=True, silent=True) or {}
    caregiver_username = data.get('caregiver_username', '').strip()
    if not caregiver_username:
        return jsonify({'error': 'caregiver_username is required'}), 400

    caregiver = db.get_user_by_username(caregiver_username) if db else None
    if not caregiver:
        return jsonify({'error': f'User "{caregiver_username}" not found'}), 404
    if caregiver.get('role') != 'caregiver':
        return jsonify({'error': f'User "{caregiver_username}" is not a caregiver'}), 400

    ok = db.add_caregiver_assignment(patient_username, caregiver_username)
    if not ok:
        return jsonify({'error': 'Failed to add caregiver assignment'}), 500
    return jsonify({'status': 'assigned', 'caregiver_username': caregiver_username}), 200


# ── Patient endpoint (INTENTIONALLY VULNERABLE to BOPLA — do NOT widen the vuln=0 whitelist) ──
@app.route('/api/patient/caregivers', methods=['GET'])
@token_required
def list_patient_caregivers():
    """Return caregivers assigned to the authenticated patient.

    VULNERABILITY (API3:2023 BOPLA — Broken Object Property Level Authorization):
    object-level authorization is correct — the patient only ever sees their *own*
    assigned caregivers (the query is scoped to patient_username). But at the
    property level the response over-exposes the caregiver object. In vuln=1 it
    returns the caregiver's private PII (display_name, email, phone, address,
    profile_photo) and internal fields (caregiver_id, password_hash). A patient can
    thus discover personal information about their caregiver; the leaked unsalted
    SHA-256 password_hash further enables a pivot to caregiver account takeover
    (and, via the caregiver role, the API1 BOLA endpoint). In vuln=0 the response is
    stripped back to the safe assignment whitelist (today's shape).
    """
    current = g.current_user
    patient_username = current.get('sub') or current.get('username', '')
    if current.get('role') not in ('patient', 'admin'):
        return jsonify({'error': 'Only patients can view their caregivers', 'code': 'FORBIDDEN'}), 403

    caregivers = db.get_caregivers_for_patient(patient_username) if db else []
    if vuln != 1:
        # Secure mode: expose only the assignment fields, never the caregiver's
        # PII or internal fields.
        safe = ('id', 'caregiver_username', 'patient_username', 'created_at', 'role')
        caregivers = [{k: c[k] for k in safe if k in c} for c in caregivers]
    return jsonify({'caregivers': caregivers, 'patient_username': patient_username}), 200


@app.route('/api/patient/caregivers/<caregiver_username>', methods=['DELETE'])
@token_required
def remove_patient_caregiver(caregiver_username):
    """Patient removes a caregiver from their account."""
    current = g.current_user
    patient_username = current.get('sub') or current.get('username', '')
    if current.get('role') not in ('patient', 'admin'):
        return jsonify({'error': 'Only patients can manage caregivers', 'code': 'FORBIDDEN'}), 403

    ok = db.remove_caregiver_assignment(patient_username, caregiver_username) if db else False
    if not ok:
        return jsonify({'error': 'Assignment not found'}), 404
    return jsonify({'status': 'removed', 'caregiver_username': caregiver_username}), 200


# ── Patient profile self-service ──────────────────────────────────────────────

# Profile photos are stored as files on disk under Config.UPLOAD_DIR/avatars and
# referenced by URL path in users.profile_photo — not inlined as base64 in the DB.
# Incoming uploads still arrive as a `data:image/*;base64,…` URI (the file input
# reads the picture with FileReader.readAsDataURL); the server decodes it, writes
# the bytes to a file, and persists only the short `/uploads/avatars/<file>` path.
_AVATAR_DIR = os.path.join(Config.UPLOAD_DIR, 'avatars')
# Incoming data-URI text cap (DoS guard before we even decode): ~2 MB image →
# ~2.7 MB base64; allow 4 MB of encoded text for headroom.
_MAX_PHOTO_DATA_URI = 4 * 1024 * 1024
# Decoded-image cap.
_MAX_PHOTO_BYTES = 2 * 1024 * 1024
# Allowed image types → file extension. SVG is deliberately excluded: serving it
# from our own origin (the /uploads route below) would be a stored-XSS the inline
# data-URI version never had.
_ALLOWED_IMAGE_TYPES = {
    'image/png': 'png', 'image/jpeg': 'jpg', 'image/jpg': 'jpg',
    'image/gif': 'gif', 'image/webp': 'webp',
}


def _store_avatar_file(username: str, data_uri: str) -> str | None:
    """Decode a ``data:image/*;base64,…`` URI, write it under the avatars dir, and
    return its public ``/uploads/avatars/<file>`` path. Returns ``None`` if the URI
    is malformed, the type is not an allowed image, or the decoded bytes exceed the
    cap. The filename embeds a content hash so re-uploads bust the browser cache."""
    try:
        header, b64 = data_uri.split(',', 1)
    except ValueError:
        return None
    if ';base64' not in header:
        return None
    mime = header[5:].split(';', 1)[0].strip().lower()   # strip leading "data:"
    ext = _ALLOWED_IMAGE_TYPES.get(mime)
    if not ext:
        return None
    try:
        raw = base64.b64decode(''.join(b64.split()), validate=True)   # tolerate stray whitespace
    except Exception:
        return None
    if not raw or len(raw) > _MAX_PHOTO_BYTES:
        return None
    os.makedirs(_AVATAR_DIR, exist_ok=True)
    safe = secure_filename(username) or 'user'
    digest = hashlib.sha256(raw).hexdigest()[:10]
    filename = f"{safe}-{digest}.{ext}"
    with open(os.path.join(_AVATAR_DIR, filename), 'wb') as fh:
        fh.write(raw)
    return f"/uploads/avatars/{filename}"


def _delete_avatar_if_local(stored: str) -> None:
    """Remove a previously stored avatar file when it is replaced. No-ops for a
    legacy inline data URI (only paths under /uploads/avatars/ map to a file)."""
    if not stored or not stored.startswith('/uploads/avatars/'):
        return
    try:
        os.remove(os.path.join(_AVATAR_DIR, os.path.basename(stored)))
    except OSError:
        pass


@app.route('/api/user/profile', methods=['GET'])
@token_required
def get_user_profile():
    """Return the authenticated user's profile (no password hash)."""
    current = g.current_user
    username = current.get('sub') or current.get('username', '')
    if not db:
        return jsonify({'error': 'Database unavailable'}), 503
    profile = db.get_user_profile(username)
    if not profile:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({'profile': profile}), 200


@app.route('/api/user/profile/password', methods=['POST'])
@token_required
def change_user_password():
    """Change the authenticated user's password.

    Requires the current password for confirmation. Body JSON:
    {"current_password": "...", "new_password": "..."}
    """
    current = g.current_user
    username = current.get('sub') or current.get('username', '')
    if not db:
        return jsonify({'error': 'Database unavailable'}), 503

    data = request.get_json(force=True, silent=True) or {}
    current_pw = data.get('current_password', '')
    new_pw     = data.get('new_password', '')

    if not new_pw or len(new_pw) < 6:
        return jsonify({'error': 'New password must be at least 6 characters'}), 400
    if not db.verify_user(username, current_pw):
        return jsonify({'error': 'Current password is incorrect'}), 403

    if not db.update_password(username, new_pw):
        return jsonify({'error': 'Failed to update password'}), 500
    db.log_event('password_change', details=username, ip_address=request.remote_addr)
    return jsonify({'status': 'password_updated'}), 200


@app.route('/api/user/profile/username', methods=['POST'])
@token_required
def change_username():
    """Rename the authenticated user. Username is a natural key throughout the
    schema, so the DB layer cascades the change. Because the JWT 'sub' claim
    embeds the username, a fresh token is issued and the session cookie is
    rotated — otherwise the old token would point at a user that no longer
    exists.

    Body JSON: {"new_username": "..."}
    """
    current = g.current_user
    old_username = current.get('sub') or current.get('username', '')
    role = current.get('role', 'patient')
    if not db:
        return jsonify({'error': 'Database unavailable'}), 503

    data = request.get_json(force=True, silent=True) or {}
    new_username = (data.get('new_username') or '').strip()

    if not new_username or len(new_username) < 3:
        return jsonify({'error': 'Username must be at least 3 characters'}), 400
    if new_username == old_username:
        return jsonify({'error': 'New username matches the current one'}), 400
    if db.get_user_by_username(new_username):
        return jsonify({'error': 'That username is already taken'}), 409

    if not db.rename_user(old_username, new_username):
        return jsonify({'error': 'Failed to rename user'}), 500

    # Rotate the session: issue a token bound to the new username.
    new_token = JWTService.generate_token(username=new_username, role=role)
    resp = make_response(jsonify({
        'status':       'username_updated',
        'username':     new_username,
        'token':        new_token,
    }))
    resp.set_cookie('careotter_token', new_token, httponly=True, samesite='Lax',
                    max_age=3600 * Config.JWT_EXPIRATION_HOURS)
    db.log_event('username_change', details=f"{old_username} -> {new_username}",
                 ip_address=request.remote_addr)
    return resp, 200


@app.route('/api/user/profile/photo', methods=['POST'])
@token_required
def upload_profile_photo():
    """Store a profile photo for the authenticated user.

    Body JSON: {"photo": "data:image/png;base64,…"}
    The image is stored inline as a base64 data URI on the user row.
    Also accepts {"display_name": "..."} in the same call for convenience.
    """
    current = g.current_user
    username = current.get('sub') or current.get('username', '')
    if not db:
        return jsonify({'error': 'Database unavailable'}), 503

    data = request.get_json(force=True, silent=True) or {}
    photo = data.get('photo')
    display_name = data.get('display_name')

    updated = []
    stored_path = None
    if photo is not None:
        if not isinstance(photo, str) or not photo.startswith('data:image/'):
            return jsonify({'error': 'photo must be a data:image/* base64 URI'}), 400
        if len(photo) > _MAX_PHOTO_DATA_URI:
            return jsonify({'error': 'Image too large (max ~3 MB)'}), 413
        stored_path = _store_avatar_file(username, photo)
        if not stored_path:
            return jsonify({'error': 'photo must be a valid data:image/(png|jpeg|gif|webp) base64 URI under 2 MB'}), 400
        # Persist the path (not the bytes); drop the user's previous avatar file.
        old_photo = (db.get_user_profile(username) or {}).get('profile_photo')
        if db.set_profile_photo(username, stored_path):
            if old_photo and old_photo != stored_path:
                _delete_avatar_if_local(old_photo)
            updated.append('photo')
    if display_name is not None:
        if db.set_display_name(username, display_name.strip()):
            updated.append('display_name')

    if not updated:
        return jsonify({'error': 'Nothing to update'}), 400
    resp = {'status': 'profile_updated', 'updated': updated}
    if stored_path:
        resp['photo'] = stored_path
    return jsonify(resp), 200


@app.route('/uploads/avatars/<path:filename>')
def serve_avatar(filename):
    """Serve a stored profile photo from disk. The bytes live under the avatars
    dir (see _store_avatar_file); the DB only holds the path. Public, like any
    profile image — an <img> can't send the auth token. send_from_directory uses
    werkzeug's safe_join, so path traversal (../) or a missing file raises
    NotFound — caught here for a clean 404 (otherwise the global Exception handler
    would surface it as a 500)."""
    try:
        return send_from_directory(_AVATAR_DIR, filename)
    except NotFound:
        return jsonify({'error': 'avatar not found'}), 404


@app.route('/api/auth/login/caregiver', methods=['POST'])
def login_caregiver():
    """
    Caregiver login endpoint.

    Same authentication flow as /api/auth/login, but for the 'caregiver' role.
    Returns a JWT that can be used to access the caregiver dashboard and
    (intentionally, due to BOLA) any patient's vitals endpoint.

    Like /api/auth/login, this endpoint is NOT an oracle: the per-username
    sliding-window rate limit is ALWAYS enforced, it is caregiver-only, and any
    failure (wrong credentials OR a non-caregiver account) returns an identical
    401 — no 403, no role/credential leak. The only intentional online
    admin-credential oracle in the lab is the 403 differential on
    /api/auth/login/patient.
    """
    data = request.get_json(force=True, silent=True) or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username:
        return jsonify({'error': 'Field "username" required', 'code': 'MISSING_FIELD'}), 400
    if not password:
        return jsonify({'error': 'Field "password" required', 'code': 'MISSING_FIELD'}), 400

    if db is None:
        return jsonify({'error': 'Database unavailable', 'code': 'DB_ERROR'}), 503

    # Rate-limit first — always on, no role branch, no VULNERABLE toggle.
    allowed, retry_after = _login_rate_check(username)
    if not allowed:
        resp = jsonify({'error': 'Too many login attempts. Try again later.', 'code': 'RATE_LIMITED'})
        resp.headers['Retry-After'] = str(int(retry_after))
        return resp, 429

    user = db.verify_user(username, password)
    # Caregiver-only, uniform failure: wrong credentials and non-caregiver
    # accounts are indistinguishable (both 401) — no 403, no oracle.
    if user is None or user.get('role') != 'caregiver':
        _login_record_fail(username)
        return jsonify({
            'error': 'Invalid username or password',
            'code':  'AUTH_FAIL'
        }), 401

    _login_reset(username)   # successful login clears the failure window
    jwt_token = JWTService.generate_token(username=username, role=user.get('role', 'caregiver'))
    resp = make_response(jsonify({
        'token':      jwt_token,
        'expires_in': f"{Config.JWT_EXPIRATION_HOURS}h",
        'type':       'Bearer',
        'role':       user.get('role'),
        'username':   username
    }))
    resp.set_cookie('careotter_token', jwt_token, httponly=True, samesite='Lax', max_age=3600*Config.JWT_EXPIRATION_HOURS)
    return resp, 200


@app.route('/api/auth/logout', methods=['POST'])
def logout():
    """Deletes the JWT session cookie."""
    resp = make_response(jsonify({'message': 'Logged out'}))
    resp.set_cookie('careotter_token', '', expires=0)
    return resp


# ── Device Information ────────────────────────────────────────────────────────

@app.route('/api/device/info')
def device_info():
    """
    IGP 0x01 — Public system information (kernel, architecture).
    No authentication required.
    """
    try:
        info = device.get_sys_info()
        return jsonify(info), 200
    except IGPError as e:
        return jsonify({'error': str(e)}), 503


@app.route('/api/device/status')
def device_status():
    """
    IGP 0x05 — Subsystem diagnostics. No authentication.

    Parameter: ?module=<name>  (default: 'CareOtter')
    Valid modules: CareOtter, BLE, Sensor, Network

    VULNERABILITY (vuln=1): the 'module' parameter is passed directly to
    the device without sanitization. The C server uses the value as snprintf()
    format — sending '%x.%x.%x' allows reading process stack data.
    In vuln=0 the module is forced to 'CareOtter' regardless of input.
    """
    module = request.args.get('module', 'CareOtter')

    if vuln != 1:
        # Safe mode: ignore parameter, always use base module
        module = 'CareOtter'

    try:
        status = device.get_status(module)
        return jsonify(status), 200
    except IGPError as e:
        return jsonify({'error': str(e)}), 503


@app.route('/api/device/ping')
@token_required
def device_ping():
    """
    TCP connectivity check to the device's IGP port (:9999).
    Does NOT require IGP authentication — it only opens and closes a TCP socket.

    Returns diagnostic hints when the Cloud API container cannot reach the Pi
    (common with Docker bridge mode + WiFi subnets).
    """
    host = request.args.get('host', Config.DEVICE_IP).strip() or Config.DEVICE_IP
    port = request.args.get('port', Config.IGP_PORT, type=int) or Config.IGP_PORT
    timeout = 3

    if not host:
        return jsonify({
            'reachable': False,
            'host': host,
            'port': port,
            'error': 'No device IP configured. Call /initialize_iot or register the device first.',
            'hint': 'DEVICE_IP is empty'
        }), 503

    try:
        t0 = time.time()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            elapsed = round((time.time() - t0) * 1000, 1)
            return jsonify({
                'reachable': True,
                'host': host,
                'port': port,
                'latency_ms': elapsed,
                'message': f'TCP connection to {host}:{port} established in {elapsed} ms.'
            }), 200
    except socket.timeout:
        return jsonify({
            'reachable': False,
            'host': host,
            'port': port,
            'error': f'TCP connection to {host}:{port} timed out after {timeout}s.',
            'hint': (
                'Common causes: (1) Docker bridge networking — the container may not have '
                'a route to the device WiFi subnet. Add "network_mode: host" to docker-compose.yml '
                'or run with --network host. (2) OpenWRT firewall blocks port 9999 on the WAN zone. '
                '(3) careservice is not running. (4) Wrong IP — the device may have changed IP '
                'after WiFi roaming.'
            )
        }), 504
    except ConnectionRefusedError:
        return jsonify({
            'reachable': False,
            'host': host,
            'port': port,
            'error': f'Connection refused on {host}:{port}.',
            'hint': 'The careservice daemon is not listening. Check /etc/init.d/careservice on the Pi.'
        }), 503
    except OSError as e:
        return jsonify({
            'reachable': False,
            'host': host,
            'port': port,
            'error': f'Network error: {e}',
            'hint': 'No route to host. Verify routing between the Cloud API host and the device.'
        }), 503


# ── Vitals ────────────────────────────────────────────────────────────────────

@app.route('/api/vitals')
def get_vitals():
    """
    Latest BPM and SpO2 — reads the most recent row stored in SQLite by the
    push endpoint (POST /api/device/vitals). No authentication.
    """
    mac = DEVICE_MAC
    latest = db.get_latest_vitals(device_mac=mac) if db else None
    if not latest:
        return jsonify({'error': 'No vitals received from device yet'}), 404
    # Normalize to the same shape the frontend expects.
    # ir_raw/red_raw removed in the tiered-storage refactor — those are local
    # ADC waveform values not used by any cloud consumer.
    return jsonify({
        'bpm': latest.get('bpm'),
        'spo2': latest.get('spo2'),
        'timestamp': latest.get('timestamp'),
        'source': latest.get('source', 'unknown'),
        'device_mac': latest.get('device_mac', mac),
    }), 200


@app.route('/api/vitals/history')
def get_vitals_history():
    """History of vital summaries — picks the storage tier from the requested
    range: ≤2h raw, ≤30d minute aggregates, otherwise hour aggregates.

    The ``tier`` field in the response tells the frontend which fields to
    expect (raw rows expose ``bpm``/``spo2``; aggregate rows expose
    ``bpm_avg``/``bpm_min``/``bpm_max`` plus the SpO2 counterparts).
    """
    hours = request.args.get('hours', 24, type=int)
    if not db:
        return jsonify({'tier': 'raw', 'history': []}), 200
    result = db.get_vitals_history_tiered(hours=hours, device_mac=DEVICE_MAC)
    return jsonify({
        'tier':    result.get('tier', 'raw'),
        'history': result.get('readings', []),
    }), 200


@app.route('/api/vitals/db/history')
def get_vitals_db_history():
    """Vital signs history from the database.
    Query params: ?hours=24 &limit=1000 &device_mac=AA:BB:CC:DD:EE:FF
    """
    hours      = request.args.get('hours', 24, type=int)
    limit      = request.args.get('limit', 1000, type=int)
    device_mac = request.args.get('device_mac', None)

    readings    = db.get_vitals_history(hours=hours, limit=limit, device_mac=device_mac)
    total_count = db.get_vitals_count(hours=hours)

    return jsonify({
        'hours':       hours,
        'count':       len(readings),
        'total_count': total_count,
        'device_mac':  device_mac,
        'readings':    readings
    }), 200


@app.route('/api/vitals/db/stats')
def get_vitals_db_stats():
    """Aggregated vital statistics.
    Query params: ?hours=24 &device_mac=AA:BB:CC:DD:EE:FF
    """
    hours      = request.args.get('hours', 24, type=int)
    device_mac = request.args.get('device_mac', None)
    stats      = db.get_vitals_stats(hours=hours, device_mac=device_mac)
    return jsonify(stats), 200


@app.route('/api/alerts/db/history')
def get_alerts_db_history():
    """Clinical alert events from the database.
    Query params: ?hours=24 &limit=500 &device_mac=AA:BB:CC:DD:EE:FF
    """
    hours      = request.args.get('hours', 24, type=int)
    limit      = request.args.get('limit', 500, type=int)
    device_mac = request.args.get('device_mac', None)

    events = db.get_alerts_history(hours=hours, limit=limit, device_mac=device_mac)
    return jsonify({
        'hours':      hours,
        'count':      len(events),
        'device_mac': device_mac,
        'alerts':     events
    }), 200


# ── Device push endpoints (Pi → Cloud) ────────────────────────────────────────

@app.route('/api/device/vitals', methods=['POST'])
def device_push_vitals():
    """Receive vital signs pushed by the bedside monitor.

    Authenticated via X-Device-MAC + X-Device-Hash headers.
    The Pi's cloud_uploader.py calls this every ~10 s.
    """
    mac = request.headers.get('X-Device-MAC', '').upper()
    auth_hash = request.headers.get('X-Device-Hash', '')
    data = request.get_json(force=True, silent=True) or {}

    if not mac or not auth_hash:
        return jsonify({'error': 'Missing X-Device-MAC or X-Device-Hash'}), 400

    if not db:
        return jsonify({'error': 'Database unavailable'}), 503

    # Canonicalise the header so storage and wire-format can diverge
    # (DB rows hold the stripped 12-hex form; the Pi still sends the
    # "CareOtter…" version that's printed on its label).
    candidate = DatabaseService.canonical_hash(auth_hash)
    device = db.get_device_by_mac(mac)
    if not device:
        # First-time push from a Pi whose seed row used a placeholder MAC
        # because /health was unreachable when initialize_iot ran. If the
        # signature matches a placeholder row, adopt the real MAC in-place
        # so subsequent pushes hit the normal path.
        if db.adopt_mac_for_signature(auth_hash, mac):
            device = db.get_device_by_mac(mac)
    stored = (device or {}).get('auth_hash') or ''
    if not device or not hmac.compare_digest(stored, candidate):
        return jsonify({'error': 'Invalid device credentials'}), 403

    # Store the reading.
    # Cloud clock is authoritative: the Pi has no RTC and on first boot its
    # wallclock can be off by hours/days, which puts every reading outside
    # the "last 24h" filter on the dashboard. Override the Pi-supplied
    # timestamp with server-side time.
    data['timestamp'] = time.time()
    db.store_vitals(data, device_mac=mac)

    # Update global active MAC so read endpoints know which device to query
    global DEVICE_MAC
    DEVICE_MAC = mac

    # Also update in-memory cache for any legacy consumers
    with _latest_vitals_lock:
        _latest_vitals.update({
            'bpm': data.get('bpm'),
            'spo2': data.get('spo2'),
            'timestamp': data['timestamp'],
            'source': data.get('source', 'unknown'),
            'device_mac': mac,
        })

    return jsonify({'status': 'ok', 'device_mac': mac}), 200


@app.route('/api/device/alerts', methods=['POST'])
def device_push_alerts():
    """Receive alert events pushed by the bedside monitor."""
    mac = request.headers.get('X-Device-MAC', '').upper()
    auth_hash = request.headers.get('X-Device-Hash', '')
    data = request.get_json(force=True, silent=True) or {}

    if not mac or not auth_hash:
        return jsonify({'error': 'Missing X-Device-MAC or X-Device-Hash'}), 400

    if not db:
        return jsonify({'error': 'Database unavailable'}), 503

    # Canonicalise the header so storage and wire-format can diverge
    # (DB rows hold the stripped 12-hex form; the Pi still sends the
    # "CareOtter…" version that's printed on its label).
    candidate = DatabaseService.canonical_hash(auth_hash)
    device = db.get_device_by_mac(mac)
    if not device:
        # First-time push from a Pi whose seed row used a placeholder MAC
        # because /health was unreachable when initialize_iot ran. If the
        # signature matches a placeholder row, adopt the real MAC in-place
        # so subsequent pushes hit the normal path.
        if db.adopt_mac_for_signature(auth_hash, mac):
            device = db.get_device_by_mac(mac)
    stored = (device or {}).get('auth_hash') or ''
    if not device or not hmac.compare_digest(stored, candidate):
        return jsonify({'error': 'Invalid device credentials'}), 403

    # Cloud clock is authoritative (the Pi has no RTC) — replace each
    # alert event's timestamp before persisting so the dashboard's 24h
    # window includes them.
    now_ts = time.time()
    for event in data.get('alerts', []):
        event['timestamp'] = now_ts
        db.store_alert(event, device_mac=mac)

    global DEVICE_MAC
    DEVICE_MAC = mac

    return jsonify({'status': 'ok', 'stored': len(data.get('alerts', []))}), 200


@app.route('/api/devices/register-by-hash', methods=['POST'])
@token_required
def register_device_by_hash():
    """Allow a patient to claim a device by providing its factory hash.

    The hash is the 12-character hex code printed on the device label (no
    prefix — the code IS the hash). Hardening applied vs the original:
      * Format guard: must be exactly 12 hex chars after normalisation, so
        garbage / drastically wrong-length inputs don't even hit the DB.
      * Per-user sliding window rate limit (5 failures / 15 min) so a
        logged-in attacker can't enumerate the hash space at line rate.
      * ``hmac.compare_digest`` instead of '==' to remove timing oracles.
      * ``DatabaseService.canonical_hash`` is still used so any legacy
        "CareOtter<hex>" inputs from older clients keep working.
      * Audit log on every failed attempt (caller IP + JWT username) so a
        burst is visible in the cloud logs.
    """
    data = request.get_json(force=True, silent=True) or {}
    raw_hash = data.get('device_hash', '')
    username = g.current_user.get('sub') or g.current_user.get('username') or '?'
    client_ip = request.remote_addr or '?'

    if not raw_hash:
        return jsonify({'error': 'device_hash is required'}), 400
    if not db:
        return jsonify({'error': 'Database unavailable'}), 503
    if username == '?':
        return jsonify({'error': 'Token missing username claim'}), 401

    # Gate BEFORE the DB lookup so an attacker can't probe under the limit.
    allowed, retry_after = _register_rate_check(username)
    if not allowed:
        logger.warning(
            f"[register-by-hash] RATE_LIMITED user={username} ip={client_ip} "
            f"retry_after={retry_after:.0f}s"
        )
        resp = jsonify({
            'error': 'Too many registration attempts. Try again later.',
            'retry_after_seconds': int(retry_after),
        })
        resp.headers['Retry-After'] = str(int(retry_after))
        return resp, 429

    # Canonical form for the DB query AND the constant-time comparison.
    candidate = DatabaseService.canonical_hash(raw_hash)

    # Reject obvious garbage cheaply (does NOT count as a rate-limited
    # failure: format errors are user typos, not credential probes).
    EXPECTED_LEN = 12
    if len(candidate) != EXPECTED_LEN or any(c not in '0123456789abcdefABCDEF' for c in candidate):
        logger.info(
            f"[register-by-hash] BAD_FORMAT user={username} ip={client_ip} "
            f"len={len(candidate)}"
        )
        return jsonify({
            'error': f'Device hash must be {EXPECTED_LEN} hexadecimal characters'
        }), 400
    device = db.get_device_by_hash(candidate)
    stored = (device or {}).get('auth_hash') or ''
    # compare_digest needs equal-length inputs to be branch-free, but it
    # already handles mismatched lengths safely; we still call it on the
    # canonical (stripped) values.
    if not device or not hmac.compare_digest(stored, candidate):
        _register_record_fail(username)
        logger.warning(
            f"[register-by-hash] FAIL user={username} ip={client_ip} "
            f"hash_len={len(raw_hash)}"
        )
        # Constant 404 regardless of whether the hash row existed at all,
        # so the attacker can't distinguish "unknown hash" from "wrong owner".
        return jsonify({'error': 'Invalid device hash'}), 404

    db.register_device(
        device['mac'], username, device.get('device_name', 'CareOtter_HR'),
        auth_hash=candidate,
    )

    global DEVICE_MAC
    DEVICE_MAC = device['mac']

    logger.info(
        f"[register-by-hash] OK user={username} ip={client_ip} mac={device['mac']}"
    )
    return jsonify({
        'status': 'registered',
        'device_mac': device['mac'],
        'device_name': device.get('device_name', 'CareOtter_HR'),
        'patient_username': username,
    }), 200


# ── User device endpoint ──────────────────────────────────────────────────────

@app.route('/api/user/devices')
@token_required
def user_devices():
    """Return the devices associated with the authenticated user.

    Reads the username from the JWT and queries the DB for their devices.
    The frontend calls this first to learn which device_mac to filter by.
    """
    from core.decorators import _decode_and_validate
    payload = _decode_and_validate()
    if not payload:
        return jsonify({'error': 'Invalid token'}), 401
    username = payload.get('sub') or payload.get('username', '')
    if not db:
        return jsonify({'error': 'Database unavailable'}), 503
    devices = db.get_devices_for_patient(username)
    return jsonify({'devices': devices, 'username': username}), 200


# ── Devices ───────────────────────────────────────────────────────────────────

@app.route('/api/devices', methods=['GET'])
@admin_required
def list_devices():
    """List all registered devices with their patient owner. Requires JWT."""
    return jsonify({'devices': db.list_devices()}), 200


@app.route('/api/devices', methods=['POST'])
@admin_required
def register_device():
    """Register or update a device MAC → patient association. Requires JWT.

    Body JSON: {"mac": "AA:BB:CC:DD:EE:FF", "patient_username": "patient",
                "device_name": "CareOtter_HR"}
    """
    data             = request.get_json(force=True, silent=True) or {}
    mac              = data.get('mac', '').strip()
    patient_username = data.get('patient_username', '').strip()
    device_name      = data.get('device_name', '').strip() or None

    if not mac or not patient_username:
        return jsonify({'error': 'Fields "mac" and "patient_username" required'}), 400

    if not db.get_user_by_username(patient_username):
        return jsonify({'error': f'User "{patient_username}" not found'}), 404

    ok = db.register_device(mac, patient_username, device_name)
    if not ok:
        return jsonify({'error': 'Failed to register device'}), 500

    return jsonify({'ok': True, 'mac': mac.upper(),
                    'patient_username': patient_username}), 200


@app.route('/api/devices/<mac>', methods=['GET'])
@admin_required
def get_device(mac):
    """Get device info and patient owner by MAC. Requires JWT."""
    device = db.get_device(mac)
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    return jsonify(device), 200


@app.route('/api/devices/me', methods=['GET'])
@token_required
def get_my_device():
    """
    Returns the device registered to the currently authenticated patient.
    Requires JWT. Returns 404 if no device is assigned.
    """
    auth_header = request.headers.get('Authorization', '')
    token = auth_header.split(' ', 1)[1].strip()
    result = JWTService.decode_token(token)
    payload = result.get('payload', {})
    username = payload.get('sub') or payload.get('username')

    if not username:
        return jsonify({'error': 'Unable to identify user from token'}), 400

    device = db.get_device_by_patient(username)
    if not device:
        return jsonify({'error': 'No device assigned to this patient'}), 404

    return jsonify(device), 200


@app.route('/api/devices/me', methods=['DELETE'])
@token_required
def delete_my_device():
    """Unregister the device associated with the authenticated patient."""
    current = g.current_user
    username = current.get('sub') or current.get('username', '')
    if current.get('role') not in ('patient', 'admin'):
        return jsonify({'error': 'Only patients can unregister their device', 'code': 'FORBIDDEN'}), 403

    ok = db.delete_device_for_patient(username) if db else False
    if not ok:
        return jsonify({'error': 'No device assigned to this patient'}), 404
    return jsonify({'status': 'unregistered', 'patient_username': username}), 200


# ── Caregiver endpoints ───────────────────────────────────────────────────────

@app.route('/api/caregiver/patients', methods=['GET'])
@api_caregiver_required
def caregiver_patients():
    """Return the patients assigned to the authenticated caregiver.

    Includes device info (mac, device_name) joined from the devices table.
    """
    caregiver_username = g.current_user.get('sub') or g.current_user.get('username', '')
    patients = db.get_patients_for_caregiver(caregiver_username) if db else []
    return jsonify({
        'caregiver_username': caregiver_username,
        'patients': patients
    }), 200


# ── Caregiver endpoint (INTENTIONALLY VULNERABLE to BOLA — do NOT add assignment checks) ──

@app.route('/api/caregiver/patient/<username>/vitals', methods=['GET'])
@token_required
def caregiver_patient_vitals(username):
    """Caregiver view of a patient's vitals, alerts, and device info.

    VULNERABILITY (BOLA): The endpoint accepts *any* username in the URL
    and does NOT verify that the authenticated user:
      1. Has the 'caregiver' role
      2. Is assigned to the requested patient
    Any authenticated JWT (including patient, admin, or caregiver) can
    substitute <username> with any existing user and exfiltrate their data.
    """
    hours = request.args.get('hours', 24, type=int)
    limit = request.args.get('limit', 1000, type=int)

    device = db.get_device_by_patient(username)
    if not device:
        return jsonify({
            'error': f'No device found for patient "{username}"'
        }), 404

    readings = db.get_vitals_history(hours=hours, limit=limit,
                                     device_mac=device.get('mac'))
    alerts = db.get_alerts_history(hours=hours, limit=limit,
                                   device_mac=device.get('mac'))

    return jsonify({
        'patient_username': username,
        'device':           device,
        'hours':            hours,
        'readings_count':   len(readings),
        'readings':         readings,
        'alerts_count':     len(alerts),
        'alerts':           alerts
    }), 200


# ── Network ───────────────────────────────────────────────────────────────────

@app.route('/api/network')
@admin_required
def get_network():
    """
    IGP 0x03 — Active network configuration. Requires JWT.

    VULNERABILITY (vuln=1): the response includes 'raw' field with complete
    /etc/config/wireless content, including WiFi PSK in plaintext. In vuln=0
    that field is omitted from the response.
    """
    ip, port, _ = _get_device_for_current_user()
    if not ip:
        return jsonify({'error': 'No device associated with this account'}), 404
    try:
        svc = DeviceService(host=ip, port=port)
        config = svc.get_network_config()
        if vuln != 1:
            config.pop('raw', None)
        return jsonify(config), 200
    except IGPError as e:
        return jsonify({'error': str(e)}), 503


@app.route('/api/network/wifi', methods=['POST'])
@admin_required
def set_wifi():
    """
    IGP 0x06 — Configures WiFi SSID and password. Requires JWT.

    Body JSON: {"ssid": "MyNetwork", "password": "password123"}
    """
    data     = request.get_json(force=True, silent=True) or {}
    ssid     = data.get('ssid', '').strip()
    password = data.get('password', '')

    if not ssid or not password:
        return jsonify({'error': 'Fields "ssid" and "password" required'}), 400

    ip, port, dev_row = _get_device_for_current_user()
    if not ip:
        return jsonify({'error': 'No device associated with this account'}), 404

    try:
        svc = DeviceService(host=ip, port=port)
        result = svc.set_wifi(ssid, password)
    except IGPError as e:
        return jsonify({'error': str(e)}), 503

    if result.get('success'):
        new_ip = _refresh_device_ip_from_sensor(host=ip)
        if new_ip and db and dev_row:
            db.update_device_ip(dev_row['mac'], new_ip, port or 9999)
            result['device_ip'] = new_ip
            result['device_ip_refreshed'] = True
        else:
            result['device_ip_refreshed'] = False
            result['device_ip_warning'] = (
                'wlan0 IP not yet visible via sensor /health within timeout; '
                'device_ip left unchanged. Re-trigger /api/network/wifi '
                'or POST /initialize_iot once the device joins the WiFi.'
            )

    if result.get('success'):
        return jsonify(result), 200

    result_text = result.get('result', '')
    if result_text.startswith('WIFI_CONNECT_FAIL'):
        return jsonify({
            'error': 'WiFi configuration was applied but the device could not connect. '
                     'Verify SSID and password are correct and the access point is reachable.',
            'detail': result_text
        }), 502

    return jsonify(result), 500


# ── Device Configuration ──────────────────────────────────────────────────────

@app.route('/api/config/preferences', methods=['POST'])
@admin_required
def set_preferences():
    """
    IGP 0x04 — App preferences in TLV format. Requires JWT.

    Body JSON: {"tlv_hex": "AA04446172..."}
    The tlv_hex value is the hexadecimal representation of the TLV payload.

    Valid TLV types:
        0xAA = visual theme name (e.g.: 4461726b = "Dark")
        0xAB = language code (e.g.: 6573 = "es")
        0xAC = screen mode (00=day, 01=night)
    """
    data    = request.get_json(force=True, silent=True) or {}
    tlv_hex = data.get('tlv_hex', '').strip()

    if not tlv_hex:
        return jsonify({'error': 'Field "tlv_hex" required'}), 400

    try:
        tlv_bytes = bytes.fromhex(tlv_hex)
    except ValueError:
        return jsonify({'error': 'tlv_hex is not valid hexadecimal'}), 400

    ip, port, _ = _get_device_for_current_user()
    if not ip:
        return jsonify({'error': 'No device associated with this account'}), 404
    try:
        svc = DeviceService(host=ip, port=port)
        result = svc.set_preferences(tlv_bytes)
        return jsonify(result), 200
    except IGPError as e:
        return jsonify({'error': str(e)}), 503


@app.route('/api/config/thresholds', methods=['POST'])
@token_required
def set_thresholds():
    """
    IGP 0x08 — Clinical alert thresholds for BPM and SpO2. Requires JWT.

    Body JSON:
        {"bpm_min": 50, "bpm_max": 120, "spo2_min": 90}

    Default clinical values: BPM 50–120, minimum SpO2 90%.
    """
    data     = request.get_json(force=True, silent=True) or {}
    bpm_min  = int(data.get('bpm_min',   50))
    bpm_max  = int(data.get('bpm_max',  120))
    spo2_min = int(data.get('spo2_min',  90))

    ip, port, _ = _get_device_for_current_user()
    if not ip:
        return jsonify({'error': 'No device associated with this account'}), 404
    try:
        svc = DeviceService(host=ip, port=port)
        result = svc.set_thresholds(bpm_min, bpm_max, spo2_min)
        # VULNERABILITY (vuln=1): leak the raw IGP request frame, whose first 4
        # bytes are the protocol MAGIC ("CARE"). A patient reaching this admin
        # endpoint (API6 BFLA) thus obtains the magic to craft valid IGP frames
        # for the API4 flood. In secure mode the field is omitted (mirrors
        # GET_NETWORK's 'raw' strip).
        if vuln != 1:
            result.pop('igp_request', None)
        return jsonify(result), 200
    except IGPError as e:
        return jsonify({'error': str(e)}), 503


# ── System Services ───────────────────────────────────────────────────────────

@app.route('/api/services/restart', methods=['POST'])
@admin_required
def restart_service():
    """
    IGP 0x09 — Restarts a device init.d service. Requires JWT.

    Body JSON: {"service": "medical-sensor"}
    Available services: medical-sensor, careservice, ble-server
    """
    data    = request.get_json(force=True, silent=True) or {}
    service = data.get('service', '').strip()

    if not service:
        return jsonify({'error': 'Field "service" required'}), 400

    ip, port, _ = _get_device_for_current_user()
    if not ip:
        return jsonify({'error': 'No device associated with this account'}), 404
    try:
        svc = DeviceService(host=ip, port=port)
        result = svc.restart_service(service)
        return jsonify(result), 200
    except IGPError as e:
        return jsonify({'error': str(e)}), 503


@app.route('/api/logs')
@admin_required
def get_logs():
    """
    IGP 0x0A — Last 512 bytes of device log. Requires JWT.
    """
    ip, port, _ = _get_device_for_current_user()
    if not ip:
        return jsonify({'error': 'No device associated with this account'}), 404
    try:
        svc = DeviceService(host=ip, port=port)
        result = svc.get_log()
        return jsonify(result), 200
    except IGPError as e:
        return jsonify({'error': str(e)}), 503


# ── Database Debug/Info ───────────────────────────────────────────────────────

@app.route('/api/db/info')
def get_db_info():
    """
    Debug endpoint — Returns information about the database.
    No authentication for debugging purposes.
    """
    if not db:
        return jsonify({'error': 'Database not initialized'}), 500
    
    info = db.get_db_info()
    return jsonify(info), 200


@app.route('/api/db/test')
def test_db_store():
    """
    Test endpoint — Stores a test reading and returns success status.
    Useful for verifying database connectivity.
    """
    if not db:
        return jsonify({'error': 'Database not initialized'}), 500
    
    test_data = {
        'timestamp': __import__('time').time(),
        'bpm': 72,
        'spo2': 98,
        'source': 'test'
    }
    
    success = db.store_vitals(test_data)
    count = db.get_vitals_count(hours=1)
    
    return jsonify({
        'store_success': success,
        'test_data': test_data,
        'readings_last_hour': count
    }), 200 if success else 500


# ── Hint endpoint (intentionally unauthenticated — guides attackers to BLE) ───

@app.route('/hint')
def hint():

    return (
        "OUT-OF-SCOPE HINT: This endpoint is intentionally unauthenticated and provides a hint for attackers. "
        "CareOtter is in an initial state where it needs an administrator "
        "to configure it before it can connect to the cloud API. "
        "The use of CareOtter Medical Service configuration software is not authorized, "
        "but you can analyze how this software initializes the device "
        "and introduces it into a common network."
        "You can also use /initialize_iot to create default users and trigger Ethernet mode, "
        "so you can test another analysis and attack path when the IoT device has been initialized without going through the BLE provisioning flow."
        "If you are in VULNERABLE MODE you have access to patient portals with user 'john_doe' and password 'johnny123'"
    ), 200


# ── Device registration (signature-based, WiFi-first) ─────────────────────────

@app.route('/admin/device/register', methods=['POST'])
@admin_required
def device_register():
    """Receive device registration from the bedside monitor after BLE provisioning.

    The Pi sends its factory signature, MAC, configured patient/admin accounts,
    and its own WiFi IP. On success the Cloud API learns the device IP and
    starts polling vitals over WiFi instead of Ethernet.

    VULNERABILITY: signature is hardcoded and identical across all devices.
    An attacker who intercepts this POST (e.g. by owning the cloud URL via
    cloud_set) can replay the signature and register a rogue device or
    overwrite the real device's admin credentials.
    """
    data = request.get_json(force=True, silent=True) or {}
    signature = data.get('signature', '')
    mac = data.get('mac', '').upper()
    device_ip = data.get('device_ip', '')
    patient = data.get('patient', {})
    admin = data.get('admin', {})

    if not signature or not mac or not device_ip:
        return jsonify({'error': 'Missing signature, mac or device_ip'}), 400

    if not db:
        return jsonify({'error': 'Database unavailable'}), 503

    ok = db.register_device_with_signature(
        mac=mac,
        signature=signature,
        patient_username=patient.get('username', ''),
        patient_password=patient.get('password', ''),
        admin_username=admin.get('username', ''),
        admin_password=admin.get('password', ''),
        device_ip=device_ip,
        device_name='CareOtter_HR'
    )
    if not ok:
        return jsonify({'error': 'Registration failed — invalid signature or DB error'}), 403

    # Update runtime config so IGP calls target the correct IP
    Config.DEVICE_IP = device_ip
    global DEVICE_MAC
    DEVICE_MAC = mac
    logger.info(f"[App] Device registered dynamically: {mac} @ {device_ip}")
    return jsonify({
        'status': 'registered',
        'device_mac': mac,
        'device_ip': device_ip
    }), 200

""" OUT-OF-SCOPE: The /initialize_iot endpoint is intended for lab operators to quickly bootstrap the system with default users and a seeded device. It is not part of the normal user flow and is intentionally left unauthenticated for convenience. However, it can be used by attackers to initialize the system in a known state, especially if they have access to the /hint endpoint that guides them towards this initialization path. In a production environment, this endpoint should be protected or removed."""
@app.route('/initialize_iot', methods=['GET'])
def initialize_iot():
    """Automatic lab bootstrap endpoint.

    Creates default admin + patient users in SQLite and registers the CareOtter
    device at its Ethernet address (192.168.2.1). If the environment variables
    WIFI_SSID and WIFI_PSK are provided, the Cloud API automatically pushes
    WiFi credentials to the Pi over IGP via the Ethernet link so the device
    can join the same network as the Cloud API container.

    No request body required — intended as a one-click GET for lab operators.

    Returns 409 if the system has already been initialized (users exist).
    """
    if not db:
        return jsonify({'error': 'Database unavailable'}), 503

    if db.user_count() > 0:
        return jsonify({
            'error': 'System already initialized. '
                     'Use /admin/device/register for signature-based registration.'
        }), 409

    # ── Bootstrap IP: prefer env var, then Ethernet fallback ──────────────────
    eth_ip = '192.168.2.1'
    device_ip = Config.DEVICE_IP or eth_ip

    # Seed users (no device — device must be registered separately).
    db.create_or_update_user('admin', 'CareOtter2026!', 'admin')
    db.create_or_update_user('john_doe', 'johnny123', 'patient')
    db.create_or_update_user('care_john', 'Caregiver2026!', 'caregiver')
    db.create_or_update_user('target_tom', 'Target2026!', 'patient')   # API7 SSRF victim (re-seedable)
    # Seed the caregiver's personal/contact info so the API3 BOPLA leak exposes
    # real PII. A patient must never be able to read these caregiver properties.
    db.set_user_pii(
        'care_john',
        display_name='John Carter, RN',
        email='j.carter@careotter-health.com',
        phone='+1-555-0147',
        address='42 Almond St, Boston, MA 02118',
        profile_photo='data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==',
    )

    # ── Seed the real Pi device ───────────────────────────────────────────────
    # alice_g67 and genuinebob49 are seeded by ``_ensure_cloud_sim_devices``
    # at startup, each bound to its virtual cloud-sim device (single device
    # per patient — no duplicate "demo" placeholders).
    pi_mac = '00:00:00:00:00:00'
    try:
        h = http_requests.get(f"http://{device_ip}:{Config.HTTP_PORT}/health", timeout=2)
        h.raise_for_status()
        detected = (h.json() or {}).get('mac', '').upper()
        if detected and detected != '00:00:00:00:00:00':
            pi_mac = detected
            logger.info(f"[init] Resolved Pi MAC from /health: {pi_mac}")
    except Exception as e:
        logger.info(f"[init] /health unreachable ({e}); using placeholder MAC for Pi")

    pi_device = {
        'mac':              pi_mac,
        'auth_hash':        db.EXPECTED_DEVICE_SIGNATURE,  # "9C0C306DEF2A"
        'device_name':      'CareOtter_HR',
        'patient_username': '',
        'ip':               device_ip,
    }

    seeded = []
    ok = db.register_device(
        pi_device['mac'], pi_device['patient_username'],
        pi_device['device_name'], auth_hash=pi_device['auth_hash'],
        device_ip=device_ip, igp_port=9999
    )
    seeded.append({
        'mac':              pi_device['mac'],
        'ip':               pi_device['ip'],
        'patient_username': pi_device['patient_username'],
        'auth_hash':        pi_device['auth_hash'],
        'stored':           ok,
    })

    # ── Optional auto-provision WiFi over Ethernet ─────────────────────────────
    wifi_ssid = os.getenv('WIFI_SSID', '').strip()
    wifi_psk  = os.getenv('WIFI_PSK',  '').strip()
    wifi_result = None

    if wifi_ssid and wifi_psk:
        try:
            # Force IGP traffic through the bootstrap link for this one-shot step
            original_ip = Config.DEVICE_IP
            Config.DEVICE_IP = device_ip
            eth_device = DeviceService()
            wifi_result = eth_device.set_wifi(wifi_ssid, wifi_psk)
            Config.DEVICE_IP = original_ip
            logger.info(
                f"[App] /initialize_iot pushed WiFi credentials to {device_ip}: "
                f"{wifi_result}"
            )
        except Exception as e:
            logger.warning(
                f"[App] /initialize_iot WiFi push to {device_ip} failed "
                f"(device may be offline or careservice not running): {e}"
            )
            wifi_result = {'error': str(e), 'success': False}
    else:
        logger.info(
            "[App] /initialize_iot: WIFI_SSID/WIFI_PSK not set — "
            "skipping automatic WiFi provisioning. The Pi will remain on Ethernet."
        )

    logger.warning(
        f"[App] /initialize_iot called — default users created, "
        f"device_ip={device_ip}, wifi_ssid={'<set>' if wifi_ssid else '<not set>'}"
    )
    return jsonify({
        'status':    'initialized',
        'message':   'Default users created. '
                     'For the real provisioning flow, discover the hidden BLE service (0xFF10).',
        'admin':     {'username': 'admin',   'password': 'CareOtter2026!'},
        'patient':   {'username': 'john_doe', 'password': 'johnny123'},
        'caregiver': {'username': 'care_john', 'password': 'Caregiver2026!'},
        'device_ip': device_ip,
        'device_registered': False,
        'device_mac': None,
        'message_device': 'In push mode the device registers itself via POST /api/device/vitals or the patient uses /api/devices/register-by-hash.',
        'wifi_provisioned': bool(wifi_ssid and wifi_psk and wifi_result and wifi_result.get('success')),
        'wifi_result': wifi_result,
        'devices_seeded': seeded
    }), 200


# ── Application initialization (shared by `python app.py` and Gunicorn) ───────

_app_initialized = False


def init_app() -> None:
    """Run one-time startup logic: auto-initialize DB, spawn background threads.

    This function is idempotent — calling it multiple times is safe. It is
    invoked automatically by ``wsgi.py`` when the app is loaded by Gunicorn,
    and manually by ``__main__`` when running ``python app.py`` directly.
    """
    global _app_initialized
    if _app_initialized:
        return
    _app_initialized = True

    # NOTE: Background collectors (_vitals_collector, _alerts_collector) have been
    # removed. In the push architecture the Pi sends data via POST /api/device/vitals
    # and POST /api/device/alerts, driven by cloud_uploader.py on the device.

    # ── Auto-initialize in vulnerable lab mode ──────────────────────────────────
    # When VULNERABLE=1 and the database has no users, automatically run
    # /initialize_iot so the lab is ready without manual operator intervention.
    # In production (vuln=0) this step is skipped — an admin must provision
    # the device via BLE or POST /admin/device/register.
    if vuln == 1 and db and db.user_count() == 0:
        logger.warning(
            "[App] VULNERABLE=1 detected and DB is empty — "
            "auto-executing /initialize_iot for lab bootstrap."
        )
        try:
            with app.app_context():
                result = initialize_iot()
            # initialize_iot() returns a Flask Response tuple (body, status)
            logger.info(f"[App] Auto-initialize result: {result[1]}")
        except Exception as e:
            logger.error(f"[App] Auto-initialize failed: {e}")

    # ── Cloud-side virtual devices + tiered storage threads ────────────────────
    # Spawn the simulator (alice_g67, genuinebob49) and the aggregator/pruner
    # AFTER initialize_iot may have created the users, so the FK on
    # devices.patient_username resolves immediately on the first insert.
    if db:
        try:
            _ensure_cloud_sim_devices()
            threading.Thread(target=_cloud_simulator_loop, daemon=True,
                             name='cloud-vitals-sim').start()
            threading.Thread(target=_vitals_aggregator_loop, daemon=True,
                             name='vitals-aggregator').start()
        except Exception as e:
            logger.error(f"[App] Failed to start cloud simulator/aggregator: {e}")


# ── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5002))

    init_app()

    # VULNERABILITY (vuln=1): debug=True activates Werkzeug interactive debugger
    # which allows arbitrary code execution on the server if the PIN is obtained
    # threaded=True so the dev server can serve the diagnostics SSRF's self-call to :5002
    # concurrently with the in-flight probe (gunicorn already runs --threads 4). Without it a
    # single-threaded dev server would deadlock on the loopback request.
    app.run(host='0.0.0.0', port=port, debug=(vuln == 1), use_reloader=False, threaded=True)
