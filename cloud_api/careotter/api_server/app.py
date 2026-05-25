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
from collections import deque
import requests as http_requests
from flask import Flask, jsonify, request, render_template, redirect, url_for, make_response, g
from config import Config
from core.igp_client import IGPError
from core.jwt_service import JWTService
from core.decorators import token_required, web_login_required, web_admin_required, web_patient_required, web_caregiver_required, api_caregiver_required
from services.device_service import DeviceService
from services.database_service import DatabaseService

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
vuln = Config.VULNERABLE

# Service instances (stateless — thread-safe for Flask dev server)
device = DeviceService()

# Initialize database with error handling
try:
    db = DatabaseService()
    logger.info(f"[App] Database initialized at: {Config.DB_PATH}")

    # Bootstrap DEVICE_IP from persisted DB value or Ethernet fallback.
    # This lets the API talk to the Pi immediately without requiring an
    # explicit /initialize_iot call on every container restart.
    persisted_ip = db.get_device_ip() if db else ''
    if persisted_ip:
        Config.DEVICE_IP = persisted_ip
        logger.info(f"[App] Restored DEVICE_IP from DB: {Config.DEVICE_IP}")
    else:
        eth_fallback = '192.168.2.1'
        Config.DEVICE_IP = eth_fallback
        logger.info(f"[App] No persisted device_ip — using Ethernet fallback: {Config.DEVICE_IP}")

    # NO default users are created at startup — the device must register itself
    # via POST /admin/device/register (or fallback GET /initialize_iot for lab operators).
    user_count = db.user_count() if db else 0
    logger.info(f"[App] Users in database: {user_count} (0 = waiting for device registration)")
except Exception as e:
    logger.error(f"[App] Failed to initialize database: {e}")
    db = None

# ── Device MAC resolution ─────────────────────────────────────────────────────
# Fetched once at startup from the medical sensor's /health endpoint over Ethernet
# (192.168.2.1:8081). The Raspberry Pi is always at that address via direct cable.
# Falls back to the env var DEFAULT_DEVICE_MAC so the API still works in dev/CI.

DEVICE_MAC: str = os.getenv('DEFAULT_DEVICE_MAC', 'AA:BB:CC:DD:EE:FF')


def _fetch_device_mac() -> None:
    """Periodic background resolver for DEVICE_MAC + DEVICE_IP.

    Runs forever in a daemon thread. Each tick:
      1. Polls the sensor ``/health`` on the currently known ``Config.DEVICE_IP``.
      2. If ``mac`` is reported, updates the module-level ``DEVICE_MAC``.
      3. If ``wifi_ip`` (or legacy ``wlan0_ip``) is non-zero AND differs from
         the current ``Config.DEVICE_IP``, promotes it so subsequent IGP / sensor
         calls flow over WiFi instead of the bootstrap Ethernet link.

    Why periodic and not one-shot at startup: the Pi may join WiFi *after* the
    cloud container is already up (admin pushes credentials via
    ``/api/network/wifi`` later, or BLE provisioning happens minutes after
    boot). A single attempt at startup misses every one of those cases.
    """
    global DEVICE_MAC
    INTERVAL_OK = 60        # seconds between checks when we already know the IP
    INTERVAL_RETRY = 10     # seconds between checks when Pi was unreachable
    while True:
        if not Config.DEVICE_IP:
            logger.debug("[Device] No DEVICE_IP yet — waiting for /admin/device/register or /initialize_iot")
            time.sleep(INTERVAL_RETRY)
            continue
        sensor_url = f"http://{Config.DEVICE_IP}:{Config.HTTP_PORT}/health"
        try:
            resp = http_requests.get(sensor_url, timeout=3)
            resp.raise_for_status()
            payload = resp.json() or {}
            mac = payload.get('mac', '').upper()
            if mac and mac != '00:00:00:00:00:00' and mac != DEVICE_MAC:
                DEVICE_MAC = mac
                logger.info(f"[Device] Resolved MAC from sensor: {DEVICE_MAC}")
            wlan_ip = payload.get('wifi_ip') or payload.get('wlan0_ip', '0.0.0.0')
            if wlan_ip and wlan_ip != '0.0.0.0' and wlan_ip != Config.DEVICE_IP:
                old_ip = Config.DEVICE_IP
                Config.DEVICE_IP = wlan_ip
                try:
                    if db:
                        db._set_config('device_ip', wlan_ip)
                except Exception as e:
                    logger.warning(f"[Device] Could not persist device_ip to DB: {e}")
                logger.info(
                    f"[Device] DEVICE_IP promoted {old_ip} -> {wlan_ip} "
                    f"(iface={payload.get('wifi_iface', '?')} via sensor /health)"
                )
            time.sleep(INTERVAL_OK)
        except Exception as e:
            logger.debug(f"[Device] Sensor /health unreachable at {sensor_url}: {e}")
            time.sleep(INTERVAL_RETRY)


# Start MAC resolution immediately but don't block Flask startup
threading.Thread(target=_fetch_device_mac, daemon=True).start()


def _refresh_device_ip_from_sensor(attempts: int = 8, delay: float = 1.5) -> str | None:
    """Poll the sensor /health endpoint until wlan0 reports a non-zero IPv4,
    then promote that address to ``Config.DEVICE_IP`` and persist it.

    Called after a successful IGP 0x06 SET_WIFI so subsequent cloud→device
    traffic flows over the freshly provisioned WiFi link instead of the
    bootstrap Ethernet path. The Pi's eth0 stays up during ``wifi reload``,
    so polling on the current ``Config.DEVICE_IP`` (Ethernet) is safe until
    we know the WiFi IP. Returns the new IP or ``None`` on timeout.
    """
    sensor_url = f"http://{Config.DEVICE_IP}:{Config.HTTP_PORT}/health"
    for attempt in range(1, attempts + 1):
        try:
            resp = http_requests.get(sensor_url, timeout=3)
            resp.raise_for_status()
            payload = resp.json() or {}
            # Prefer driver-agnostic ``wifi_ip`` (new sensor); fall back to
            # legacy ``wlan0_ip`` for older firmware images that still hardcode
            # the interface name.
            wlan_ip = payload.get('wifi_ip') or payload.get('wlan0_ip', '0.0.0.0')
            if wlan_ip and wlan_ip != '0.0.0.0':
                old_ip = Config.DEVICE_IP
                Config.DEVICE_IP = wlan_ip
                try:
                    db._set_config('device_ip', wlan_ip)
                except Exception as e:
                    logger.warning(f"[set_wifi] Could not persist device_ip to DB: {e}")
                logger.info(f"[set_wifi] Device IP refreshed: {old_ip} -> {wlan_ip} (via sensor /health)")
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
    },
    {
        'mac':              '02:CE:01:00:00:02',
        'patient_username': 'genuinebob49',
        'device_name':      'CareOtter_HR (cloud-sim:bob)',
        'baseline_bpm':     68,
        'baseline_spo2':    97,
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
    for d in _CLOUD_SIM_DEVICES:
        db.register_device(
            d['mac'], d['patient_username'], d['device_name'],
            auth_hash=None,  # virtual: no factory signature
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
    Authenticates operator against the local SQLite user database.

    Expects JSON body with 'username' and 'password'.
    Verifies credentials against the 'users' table and requires role='admin'.
    On success, issues a JWT session token.

    NOTE: passwords are hashed with SHA-256 without salt —
    an intentional vulnerability for the lab.

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

    user = db.verify_user(username, password)
    if not user:
        return jsonify({
            'error': 'Invalid username or password',
            'code':  'AUTH_FAIL'
        }), 401

    # Allow both 'admin' and 'patient' roles — role is returned so the mobile
    # app can route to the correct screen without a second request.
    allowed_roles = ('admin', 'patient')
    if user.get('role') not in allowed_roles:
        return jsonify({
            'error': 'Access denied for this role',
            'code':  'FORBIDDEN'
        }), 403

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


@app.route('/api/auth/login/patient', methods=['POST'])
def login_patient():
    """
    Patient-only login endpoint.

    Same authentication flow as /api/auth/login, but rejects non-patient roles.
    Used by the patient portal web UI and mobile app patient mode.
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

    user = db.verify_user(username, password)
    if not user:
        return jsonify({
            'error': 'Invalid username or password',
            'code':  'AUTH_FAIL'
        }), 401

    if user.get('role') != 'patient':
        return jsonify({
            'error': 'Access denied for this role',
            'code':  'FORBIDDEN'
        }), 403

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


@app.route('/api/patient/caregivers', methods=['GET'])
@token_required
def list_patient_caregivers():
    """Return caregivers assigned to the authenticated patient."""
    current = g.current_user
    patient_username = current.get('sub') or current.get('username', '')
    if current.get('role') not in ('patient', 'admin'):
        return jsonify({'error': 'Only patients can view their caregivers', 'code': 'FORBIDDEN'}), 403

    caregivers = db.get_caregivers_for_patient(patient_username) if db else []
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

# Max accepted profile photo size (base64 data URI). 2 MB of raw image →
# ~2.7 MB base64; cap at 4 MB of encoded text to leave headroom.
_MAX_PHOTO_DATA_URI = 4 * 1024 * 1024


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
    if photo is not None:
        if not isinstance(photo, str) or not photo.startswith('data:image/'):
            return jsonify({'error': 'photo must be a data:image/* base64 URI'}), 400
        if len(photo) > _MAX_PHOTO_DATA_URI:
            return jsonify({'error': 'Image too large (max ~3 MB)'}), 413
        if db.set_profile_photo(username, photo):
            updated.append('photo')
    if display_name is not None:
        if db.set_display_name(username, display_name.strip()):
            updated.append('display_name')

    if not updated:
        return jsonify({'error': 'Nothing to update'}), 400
    return jsonify({'status': 'profile_updated', 'updated': updated}), 200


@app.route('/api/auth/login/caregiver', methods=['POST'])
def login_caregiver():
    """
    Caregiver login endpoint.

    Same authentication flow as /api/auth/login/patient, but accepts the
    'caregiver' role. Returns a JWT that can be used to access the caregiver
    dashboard and (intentionally, due to BOLA) any patient's vitals endpoint.
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

    user = db.verify_user(username, password)
    if not user:
        return jsonify({
            'error': 'Invalid username or password',
            'code':  'AUTH_FAIL'
        }), 401

    if user.get('role') != 'caregiver':
        return jsonify({
            'error': 'Access denied for this role',
            'code':  'FORBIDDEN'
        }), 403

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
@token_required
def list_devices():
    """List all registered devices with their patient owner. Requires JWT."""
    return jsonify({'devices': db.list_devices()}), 200


@app.route('/api/devices', methods=['POST'])
@token_required
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
@token_required
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
@token_required
def get_network():
    """
    IGP 0x03 — Active network configuration. Requires JWT.

    VULNERABILITY (vuln=1): the response includes 'raw' field with complete
    /etc/config/wireless content, including WiFi PSK in plaintext. In vuln=0
    that field is omitted from the response.
    """
    try:
        config = device.get_network_config()
        if vuln != 1:
            # Safe mode: do not expose raw field with PSK
            config.pop('raw', None)
        return jsonify(config), 200
    except IGPError as e:
        return jsonify({'error': str(e)}), 503


@app.route('/api/network/wifi', methods=['POST'])
@token_required
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

    try:
        result = device.set_wifi(ssid, password)
    except IGPError as e:
        return jsonify({'error': str(e)}), 503

    # After a successful wifi reload on the Pi, wlan0 picks up an address from
    # the new network. Poll sensor /health (still reachable over the Ethernet
    # bootstrap link) to learn that IP and switch Config.DEVICE_IP so every
    # subsequent IGP / sensor call from the cloud takes the WiFi path.
    # IGP itself does NOT expose runtime interface IPs (see careservice.c —
    # 0x03 GET_NETWORK only returns /etc/config/wireless), hence the side
    # channel via the sensor's unauthenticated /health.
    if result.get('success'):
        new_ip = _refresh_device_ip_from_sensor()
        if new_ip:
            result['device_ip'] = new_ip
            result['device_ip_refreshed'] = True
        else:
            result['device_ip_refreshed'] = False
            result['device_ip_warning'] = (
                'wlan0 IP not yet visible via sensor /health within timeout; '
                'Config.DEVICE_IP left unchanged. Re-trigger /api/network/wifi '
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
@token_required
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

    try:
        result = device.set_preferences(tlv_bytes)
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

    try:
        result = device.set_thresholds(bpm_min, bpm_max, spo2_min)
        return jsonify(result), 200
    except IGPError as e:
        return jsonify({'error': str(e)}), 503


# ── System Services ───────────────────────────────────────────────────────────

@app.route('/api/services/restart', methods=['POST'])
@token_required
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

    try:
        result = device.restart_service(service)
        return jsonify(result), 200
    except IGPError as e:
        return jsonify({'error': str(e)}), 503


@app.route('/api/logs')
@token_required
def get_logs():
    """
    IGP 0x0A — Last 512 bytes of device log. Requires JWT.
    """
    try:
        result = device.get_log()
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

    # ── Ethernet fallback (direct cable) ───────────────────────────────────────
    eth_ip = '192.168.2.1'
    device_ip = Config.DEVICE_IP or eth_ip

    # Seed users (no device — device must be registered separately).
    db.create_or_update_user('admin', 'CareOtter2026!', 'admin')
    db.create_or_update_user('john_doe', 'johnny123', 'patient')
    db.create_or_update_user('care_john', 'Caregiver2026!', 'caregiver')
    db._set_config('device_ip', device_ip)
    Config.DEVICE_IP = device_ip

    # ── Seed the real Pi device ───────────────────────────────────────────────
    # alice_g67 and genuinebob49 are seeded by ``_ensure_cloud_sim_devices``
    # at startup, each bound to its virtual cloud-sim device (single device
    # per patient — no duplicate "demo" placeholders).
    pi_mac = '00:00:00:00:00:00'
    try:
        h = http_requests.get(f"http://{eth_ip}:{Config.HTTP_PORT}/health", timeout=2)
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
        'ip':               eth_ip,
    }

    seeded = []
    ok = db.register_device(
        pi_device['mac'], pi_device['patient_username'],
        pi_device['device_name'], auth_hash=pi_device['auth_hash']
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
            # Force IGP traffic through the Ethernet link for this bootstrap step
            original_ip = Config.DEVICE_IP
            Config.DEVICE_IP = eth_ip
            eth_device = DeviceService()
            wifi_result = eth_device.set_wifi(wifi_ssid, wifi_psk)
            Config.DEVICE_IP = original_ip
            logger.info(
                f"[App] /initialize_iot pushed WiFi credentials to {eth_ip}: "
                f"{wifi_result}"
            )
        except Exception as e:
            logger.warning(
                f"[App] /initialize_iot WiFi push to {eth_ip} failed "
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


# ── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5002))

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

    # VULNERABILITY (vuln=1): debug=True activates Werkzeug interactive debugger
    # which allows arbitrary code execution on the server if the PIN is obtained
    app.run(host='0.0.0.0', port=port, debug=(vuln == 1), use_reloader=False)
