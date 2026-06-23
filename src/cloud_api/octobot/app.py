#!/usr/bin/env python3
# OctoBot cloud controller - REST API + web UI + Modbus/TCP master to the Pi.
# A single operator account (SQLite-backed) gates the control console with a
# signed Flask session. Functional auth, not a vuln target - the OctoBot IoT
# vulnerabilities live on the Pi (serial bus / Modbus / MQTT / gateway), which
# stay reachable directly regardless of this console.
import os
import sqlite3
import subprocess
from functools import wraps
from flask import (Flask, jsonify, request, render_template, redirect,
                   url_for, session, send_from_directory)
from werkzeug.security import generate_password_hash, check_password_hash
from pymodbus.client import ModbusTcpClient

MODBUS_HOST = os.getenv('MODBUS_HOST', '192.168.2.1')   # Raspberry Pi gateway
MODBUS_PORT = int(os.getenv('MODBUS_PORT', '502'))
HTTP_PORT = int(os.getenv('HTTP_PORT', '5003'))
DB_PATH = os.getenv('DB_PATH', '/app/data/octobot.db')
OPERATOR_USER = os.getenv('OPERATOR_USER', 'operator')
OPERATOR_PASSWORD = os.getenv('OPERATOR_PASSWORD', 'octobot')

# Firmware storage and Pi push configuration
FIRMWARE_DIR = os.getenv('FIRMWARE_DIR', '/app/firmware')
FIRMWARE_FILENAME = os.getenv('FIRMWARE_FILENAME', 'robot_arm.hex')
FIRMWARE_PATH = os.path.join(FIRMWARE_DIR, FIRMWARE_FILENAME)
PI_HOST = os.getenv('PI_HOST', MODBUS_HOST)
PI_USER = os.getenv('PI_USER', 'root')
PI_FIRMWARE_PATH = os.getenv('PI_FIRMWARE_PATH', '/opt/octobot/firmware/robot_arm.hex')

app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = os.getenv('SECRET_KEY', 'octobot-cloud-secret-2026')
client = ModbusTcpClient(MODBUS_HOST, port=MODBUS_PORT)


# --- auth / db -----------------------------------------------------------------
def init_db():
    os.makedirs(os.path.dirname(DB_PATH) or '.', exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.execute('CREATE TABLE IF NOT EXISTS users '
                '(id INTEGER PRIMARY KEY, username TEXT UNIQUE, pw_hash TEXT)')
    # Seed the single operator account on first run (idempotent: only if empty).
    if con.execute('SELECT COUNT(*) FROM users').fetchone()[0] == 0:
        con.execute('INSERT INTO users (username, pw_hash) VALUES (?, ?)',
                    (OPERATOR_USER,
                     generate_password_hash(OPERATOR_PASSWORD, method='pbkdf2:sha256')))
        con.commit()
    con.close()


def verify_user(username, password):
    con = sqlite3.connect(DB_PATH)
    row = con.execute('SELECT pw_hash FROM users WHERE username = ?',
                      (username,)).fetchone()
    con.close()
    return bool(row) and check_password_hash(row[0], password)


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get('user'):
            if request.path.startswith('/api/'):
                return jsonify(error='authentication required'), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if verify_user(request.form.get('username', ''),
                       request.form.get('password', '')):
            session['user'] = request.form.get('username', '')
            return redirect(url_for('index'))
        return render_template('login.html', error='Invalid credentials'), 401
    if session.get('user'):
        return redirect(url_for('index'))
    return render_template('login.html', error=None)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# --- control (login-gated) -----------------------------------------------------
def write_register(addr, value):
    client.connect()
    client.write_register(addr, int(value))
    client.close()


@app.route('/')
@login_required
def index():
    return render_template('index.html', username=session.get('user'))


@app.route('/api/servo/<int:n>', methods=['POST'])
@login_required
def set_servo(n):
    angle = request.json.get('angle', 90)
    write_register(n - 1, angle)        # 40001 -> offset 0
    return jsonify(servo=n, angle=angle)


@app.route('/api/command/<name>', methods=['POST'])
@login_required
def command(name):
    cmds = {'record': 1, 'play': 2, 'stop': 3, 'demo': 4}
    if name in cmds:
        write_register(4, cmds[name])   # 40005
    return jsonify(command=name)


@app.route('/api/state')
@login_required
def state():
    client.connect()
    rr = client.read_holding_registers(0, count=14)
    client.close()
    regs = getattr(rr, 'registers', [0] * 14)
    return jsonify(base=regs[0], left=regs[1], right=regs[2], claw=regs[3],
                   command=regs[4], speed=regs[5], status=regs[6],
                   feedback=regs[10:14])


# --- firmware management -------------------------------------------------------
def ensure_firmware_dir():
    os.makedirs(FIRMWARE_DIR, exist_ok=True)


def push_firmware_to_pi(local_path):
    """Copy the local firmware image to the Pi over SSH."""
    try:
        with open(local_path, 'rb') as fh:
            proc = subprocess.run(
                [
                    'ssh',
                    '-o', 'StrictHostKeyChecking=no',
                    '-o', 'UserKnownHostsFile=/dev/null',
                    '-o', 'BatchMode=yes',
                    f'{PI_USER}@{PI_HOST}',
                    f'cat > {PI_FIRMWARE_PATH}',
                ],
                stdin=fh,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
                check=True,
            )
        return True, ''
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def save_and_push_firmware(uploaded_file, version):
    ensure_firmware_dir()
    uploaded_file.save(FIRMWARE_PATH)
    pushed, note = push_firmware_to_pi(FIRMWARE_PATH)
    result = {
        'version': version,
        'filename': FIRMWARE_FILENAME,
        'path': FIRMWARE_PATH,
        'pushed': pushed,
    }
    if not pushed:
        result['note'] = note
    return jsonify(result)


@app.route('/api/v1/firmware', methods=['GET', 'PUT'])
def firmware_v1():
    # [IoT:I4] [API5:2023] Intentionally downgraded endpoint: no session check.
    if request.method == 'GET':
        if not os.path.isfile(FIRMWARE_PATH):
            return jsonify(error='firmware not found'), 404
        return send_from_directory(
            FIRMWARE_DIR,
            FIRMWARE_FILENAME,
            as_attachment=True,
            mimetype='application/octet-stream',
        )

    if 'file' not in request.files:
        return jsonify(error='no file provided'), 400
    return save_and_push_firmware(request.files['file'], 'v1'), 200


@app.route('/api/v2/firmware', methods=['GET', 'PUT'])
@login_required
def firmware_v2():
    if request.method == 'GET':
        if not os.path.isfile(FIRMWARE_PATH):
            return jsonify(error='firmware not found'), 404
        return send_from_directory(
            FIRMWARE_DIR,
            FIRMWARE_FILENAME,
            as_attachment=True,
            mimetype='application/octet-stream',
        )

    if 'file' not in request.files:
        return jsonify(error='no file provided'), 400

    uploaded_file = request.files['file']
    # [IoT:I4] Only the extension is checked; content is not verified.
    if not uploaded_file.filename or not uploaded_file.filename.lower().endswith('.hex'):
        return jsonify(error='only .hex files are allowed'), 400

    return save_and_push_firmware(uploaded_file, 'v2'), 200


ensure_firmware_dir()
init_db()   # launch-agnostic (python app.py or gunicorn); CREATE/seed is idempotent

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=HTTP_PORT)
