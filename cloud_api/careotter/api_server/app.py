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
from flask import Flask, jsonify, request, render_template, redirect, url_for, make_response
from config import Config
from core.igp_client import IGPError
from core.jwt_service import JWTService
from core.decorators import token_required, web_login_required, web_admin_required, web_patient_required
from services.device_service import DeviceService
from services.vitals_service import VitalsService
from services.database_service import DatabaseService

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def _get_wifi_ip() -> str:
    """Return the IPv4 address of the first WiFi interface found (wlan0, wlan1, …).
    Falls back to any non-loopback, non-Ethernet (192.168.2.x), non-Docker (172.x)
    address so the result is always the WiFi-reachable IP.
    Requires network_mode: host in docker-compose so host interfaces are visible.
    """
    SIOCGIFADDR = 0x8915
    for iface in ("wlan0", "wlan1", "wlp2s0", "wlp3s0"):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            res = fcntl.ioctl(s.fileno(), SIOCGIFADDR,
                              iface.encode().ljust(40, b"\x00"))
            s.close()
            return socket.inet_ntoa(res[20:24])
        except OSError:
            pass
    # Generic fallback: iterate all addresses, skip loopback/eth/docker
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith("127.") \
               and not ip.startswith("192.168.2.") \
               and not ip.startswith("172."):
                return ip
    except Exception:
        pass
    return "0.0.0.0"


app  = Flask(__name__)
vuln = Config.VULNERABLE

# Service instances (stateless — thread-safe for Flask dev server)
device = DeviceService()
vitals = VitalsService()

# Inicializar base de datos con manejo de errores
try:
    db = DatabaseService()
    logger.info(f"[App] Database initialized at: {Config.DB_PATH}")
    # Asegurar usuario admin por defecto
    if db and db.ensure_default_users():
        logger.info("[App] Default admin user ensured")
except Exception as e:
    logger.error(f"[App] Failed to initialize database: {e}")
    db = None


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

@app.route('/patient/dashboard')
@web_patient_required
def patient_dashboard():
    return render_template('patient_dashboard.html')

@app.route('/history')
@web_patient_required
def history_page():
    """
    Patient history page — View all historical vitals from database.
    Requires patient login.
    """
    return render_template('history.html')


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
        'device':   f"{Config.DEVICE_IP}:{Config.IGP_PORT}",
        'wifi_ip':  _get_wifi_ip(),
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


@app.route('/api/auth/logout', methods=['POST'])
def logout():
    """Borra la cookie de sesión JWT."""
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


# ── Vitals ────────────────────────────────────────────────────────────────────

@app.route('/api/vitals')
def get_vitals():
    """
    Current BPM and SpO2 — direct query to sensor service on :8081.
    Stores reading in local database for persistence.
    No authentication (monitoring data is public).
    """
    result = vitals.get_current()
    if not result['success']:
        logger.warning(f"[API] Failed to get vitals: {result['error']}")
        return jsonify({'error': result['error']}), 503
    
    data = result['data']
    
    # Almacenar en base de datos (fire-and-forget)
    if db:
        device_mac = request.args.get('device_mac') or data.get('device_mac',
                     os.getenv('DEFAULT_DEVICE_MAC', 'AA:BB:CC:DD:EE:FF'))
        # Always use server time — sensor clock may be wrong (Raspberry Pi NTP drift)
        data['timestamp'] = time.time()
        success = db.store_vitals(data, device_mac=device_mac)
        if success:
            logger.debug(f"[API] Stored vitals: BPM={data.get('bpm')}, SpO2={data.get('spo2')}")
        else:
            logger.error("[API] Failed to store vitals in database")
    else:
        logger.warning("[API] Database not available, skipping storage")
    
    return jsonify(data), 200


@app.route('/api/vitals/history')
def get_vitals_history():
    """
    History of vital summaries from device (circular buffer, up to 24h).
    No authentication.
    """
    result = vitals.get_history()
    if not result['success']:
        return jsonify({'error': result['error']}), 503
    return jsonify({'history': result['history']}), 200


@app.route('/api/vitals/db/history')
def get_vitals_db_history():
    """Historial de vitales desde la base de datos.
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
    """Estadísticas agregadas de vitales.
    Query params: ?hours=24 &device_mac=AA:BB:CC:DD:EE:FF
    """
    hours      = request.args.get('hours', 24, type=int)
    device_mac = request.args.get('device_mac', None)
    stats      = db.get_vitals_stats(hours=hours, device_mac=device_mac)
    return jsonify(stats), 200


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
        status = 200 if result['success'] else 500
        return jsonify(result), status
    except IGPError as e:
        return jsonify({'error': str(e)}), 503


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
        'ir_raw': 50000,
        'red_raw': 50000,
        'source': 'test'
    }
    
    success = db.store_vitals(test_data)
    count = db.get_vitals_count(hours=1)
    
    return jsonify({
        'store_success': success,
        'test_data': test_data,
        'readings_last_hour': count
    }), 200 if success else 500


# ── Entrypoint ────────────────────────────────────────────────────────────────

def _vitals_collector():
    """Background thread: poll sensor every 30s and persist to DB.
    Runs independently of HTTP clients — history is recorded even when no
    browser or mobile app is connected.
    """
    default_mac = os.getenv('DEFAULT_DEVICE_MAC', 'AA:BB:CC:DD:EE:FF')
    logger.info("[Collector] Vitals collector started (interval=30s)")
    while True:
        try:
            result = vitals.get_current()
            if result['success'] and db:
                data = result['data']
                data['timestamp'] = time.time()
                db.store_vitals(data, device_mac=default_mac)
                logger.debug(f"[Collector] Stored BPM={data.get('bpm')} SpO2={data.get('spo2')}")
        except Exception as e:
            logger.warning(f"[Collector] Error: {e}")
        time.sleep(30)


if __name__ == '__main__':
    port = int(os.getenv('PORT', 5002))

    collector = threading.Thread(target=_vitals_collector, daemon=True)
    collector.start()

    # VULNERABILITY (vuln=1): debug=True activates Werkzeug interactive debugger
    # which allows arbitrary code execution on the server if the PIN is obtained
    app.run(host='0.0.0.0', port=port, debug=(vuln == 1), use_reloader=False)
