#!/usr/bin/env python3
# OctoBot cloud controller - REST API + web UI + Modbus/TCP master to the Pi.
# The Android app and the operator browser talk only to this; it abstracts the
# industrial protocol. Plaintext HTTP and unauthenticated by default (lab).
import os
from flask import Flask, jsonify, request, send_from_directory
from pymodbus.client import ModbusTcpClient

MODBUS_HOST = os.getenv('MODBUS_HOST', '192.168.2.1')   # Raspberry Pi gateway
MODBUS_PORT = int(os.getenv('MODBUS_PORT', '502'))
HTTP_PORT = int(os.getenv('HTTP_PORT', '5003'))

app = Flask(__name__, static_folder='static')
client = ModbusTcpClient(MODBUS_HOST, port=MODBUS_PORT)


def write_register(addr, value):
    client.connect()
    client.write_register(addr, int(value))
    client.close()


@app.route('/')
def index():
    return send_from_directory('static', 'index.html')


@app.route('/api/servo/<int:n>', methods=['POST'])
def set_servo(n):
    angle = request.json.get('angle', 90)
    write_register(n - 1, angle)        # 40001 -> offset 0
    return jsonify(servo=n, angle=angle)


@app.route('/api/command/<name>', methods=['POST'])
def command(name):
    cmds = {'record': 1, 'play': 2, 'stop': 3, 'demo': 4}
    if name in cmds:
        write_register(4, cmds[name])   # 40005
    return jsonify(command=name)


@app.route('/api/state')
def state():
    client.connect()
    rr = client.read_holding_registers(0, count=14)
    client.close()
    regs = getattr(rr, 'registers', [0] * 14)
    return jsonify(base=regs[0], left=regs[1], right=regs[2], claw=regs[3],
                   command=regs[4], speed=regs[5], status=regs[6],
                   feedback=regs[10:14])


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=HTTP_PORT)
