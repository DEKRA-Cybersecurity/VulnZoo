#!/usr/bin/env python3
# octobot_gateway.py - OctoBot HMI / REST gateway. DELIBERATELY VULNERABLE.
#
# Northbound HTTP -> serial bus (127.0.0.1:2000). Each flaw is tagged with its
# OWASP IoT id. Do NOT harden: the vulnerabilities are the lab.
import os
import socket
import subprocess
from flask import Flask, request, jsonify, render_template_string

BUS_HOST = '127.0.0.1'
BUS_PORT = int(os.environ.get('OCTOBOT_BUS_PORT', '2000'))
LOG_PATH = os.environ.get('OCTOBOT_LOG', '/tmp/octobot/operator.log')
HTTP_PORT = int(os.environ.get('OCTOBOT_HTTP_PORT', '8090'))
SERIAL_DEV = os.environ.get('OCTOBOT_SERIAL', '/dev/ttyUSB0')

USERS = {'admin': 'admin'}                  # [IoT:I1] default credentials
API_KEY = 'octobot-industrial-2020'         # [IoT:I1] hardcoded key, never rotated

# Hardcoded actuator password shared with the serial bus and Arduino firmware. [IoT:I1]
HARD_CODED_PASSWORD = 'OctoSuperBot2026'

app = Flask(__name__)


def bus_send(cmd):
    with socket.create_connection((BUS_HOST, BUS_PORT), timeout=2) as s:
        s.sendall((f'PASS:{HARD_CODED_PASSWORD} {cmd.strip()}\n').encode())


@app.route('/api/move')                     # [IoT:I3] no auth, [IoT:I8] no rate limit
def move():
    servo = request.args.get('servo', '0')  # [IoT:I3] IDOR: any servo index accepted
    angle = request.args.get('angle', '90')
    bus_send(f'S{servo}:{angle}')
    return jsonify(ok=True, sent=f'S{servo}:{angle}')


@app.route('/api/claw')
def claw():
    state = request.args.get('state', 'CLOSE').upper()
    bus_send('S3:5' if state == 'CLOSE' else 'S3:30')
    return jsonify(ok=True, state=state)


@app.route('/login', methods=['POST'])      # [IoT:I1] trivial auth, not enforced elsewhere
def login():
    ok = USERS.get(request.form.get('user')) == request.form.get('pass')
    return jsonify(ok=ok)


@app.route('/admin')                        # [IoT:I3] SSTI/XSS: user input compiled as template
def admin():
    msg = request.args.get('msg', '')
    tmpl = ('<!doctype html><h1>OctoBot HMI - Cell 01</h1>'
            '<p>' + msg + '</p>'
            '<form method=post action=/login>'
            'user <input name=user> pass <input name=pass> <button>login</button></form>')
    return render_template_string(tmpl)


@app.route('/logs')                         # [IoT:I6] operator history, no auth
def logs():
    body = open(LOG_PATH).read() if os.path.exists(LOG_PATH) else 'no logs'
    return body, 200, {'Content-Type': 'text/plain'}


@app.route('/update', methods=['POST'])     # [IoT:I4] unsigned OTA, flashed over plain HTTP
def update():
    os.makedirs('/tmp/octobot', exist_ok=True)
    path = '/tmp/octobot/upload.hex'
    request.files['firmware'].save(path)
    if not os.path.exists(SERIAL_DEV):
        return jsonify(flashed=False, note='no Arduino attached (simulation mode)')
    # The serial bus holds the tty; avrdude needs it (DTR reset + STK500). Stop,
    # flash whatever was uploaded (no signature/origin check), restart.
    subprocess.run('/etc/init.d/octobot-serialbus stop', shell=True)
    cmd = (f'avrdude -c arduino -p atmega328p -P {SERIAL_DEV} '
           f'-b 115200 -U flash:w:{path}:i')   # [IoT:I4] flashes attacker-supplied firmware
    out = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    subprocess.run('/etc/init.d/octobot-serialbus start', shell=True)
    return jsonify(flashed=out.returncode == 0, log=out.stderr[-400:])


if __name__ == '__main__':
    # [IoT:I9] binds all interfaces, [IoT:I7] plain HTTP, no TLS
    app.run(host='0.0.0.0', port=HTTP_PORT)
