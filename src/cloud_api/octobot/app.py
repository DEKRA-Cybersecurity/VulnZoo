#!/usr/bin/env python3
"""
app.py — OctoBot Cloud API

Intermediary Flask controller between the operator web UI and the Raspberry Pi
Modbus/TCP gateway. Intentional IoT vulnerabilities live on the Pi and the
Arduino firmware. The cloud console now also contains an intentional
filter-bypass SQL injection vulnerability in /login for lab purposes.
"""

import os
from flask import (Flask, jsonify, request, render_template, redirect,
                   url_for, session, send_from_directory)

from config import Config
from core.decorators import login_required
from services.auth_service import AuthService
from services.modbus_service import ModbusService, ModbusAuthError
from services.firmware_service import FirmwareService

app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = Config.SECRET_KEY

# Service instances
auth = AuthService()
modbus = ModbusService()


# ── HTML Routes ────────────────────────────────────────────────────────────────

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if auth.verify_user(request.form.get('username', ''),
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


@app.route('/')
@login_required
def index():
    return render_template('index.html', username=session.get('user'))


# ── Robot Control API ──────────────────────────────────────────────────────────

@app.route('/api/servo/<int:n>', methods=['POST'])
@login_required
def set_servo(n):
    angle = request.json.get('angle', 90)
    try:
        modbus.write_register(n - 1, angle)        # 40001 -> offset 0
    except ModbusAuthError as e:
        # [IoT:I1] intentional information disclosure: the Pi leaks the password as a hint.
        return jsonify(error='actuator authentication failed', hint=e.hint), 403
    return jsonify(servo=n, angle=angle)


@app.route('/api/command/<name>', methods=['POST'])
@login_required
def command(name):
    cmds = {'record': 1, 'play': 2, 'stop': 3, 'demo': 4}
    if name in cmds:
        try:
            modbus.write_register(4, cmds[name])   # 40005
        except ModbusAuthError as e:
            return jsonify(error='actuator authentication failed', hint=e.hint), 403
    return jsonify(command=name)


@app.route('/api/state')
@login_required
def state():
    return jsonify(modbus.read_state())


# ── Firmware Management API ────────────────────────────────────────────────────
# [IoT:I4] Lack of Secure Update Mechanism
# [API5:2023] Broken Function Level Authorization

@app.route('/api/v0/firmware', methods=['GET', 'PUT'])
def firmware_v0():
    # [IoT:I4] [API5:2023] Intentionally downgraded endpoint: no session check.
    if request.method == 'GET':
        if not os.path.isfile(FirmwareService.FIRMWARE_PATH):
            return jsonify(error='firmware not found'), 404
        return send_from_directory(
            Config.FIRMWARE_DIR,
            Config.FIRMWARE_FILENAME,
            as_attachment=True,
            mimetype='application/octet-stream',
        )

    if 'file' not in request.files:
        return jsonify(error='no file provided'), 400
    return FirmwareService.save_and_push(request.files['file'], 'v1'), 200


@app.route('/api/v2/firmware/version', methods=['GET'])
def firmware_v2_version():
    version = FirmwareService.get_version()
    if version is None:
        return jsonify(error='version not found'), 404
    return jsonify(version=version)


@app.route('/api/v2/firmware', methods=['GET', 'PUT'])
@login_required
def firmware_v2():
    if request.method == 'GET':
        if not os.path.isfile(FirmwareService.FIRMWARE_PATH):
            return jsonify(error='firmware not found'), 404
        return send_from_directory(
            Config.FIRMWARE_DIR,
            Config.FIRMWARE_FILENAME,
            as_attachment=True,
            mimetype='application/octet-stream',
        )

    if 'file' not in request.files:
        return jsonify(error='no file provided'), 400

    uploaded_file = request.files['file']
    # [IoT:I4] Only the extension is checked; content is not verified.
    if not uploaded_file.filename or not uploaded_file.filename.lower().endswith('.hex'):
        return jsonify(error='only .hex files are allowed'), 400

    return FirmwareService.save_and_push(uploaded_file, 'v2'), 200


# ── Startup ────────────────────────────────────────────────────────────────────

FirmwareService.ensure_firmware_dir()
auth.init_db()   # launch-agnostic (python app.py or gunicorn); CREATE/seed is idempotent

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=Config.HTTP_PORT)
