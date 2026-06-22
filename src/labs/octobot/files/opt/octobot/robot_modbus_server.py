#!/usr/bin/env python3
# robot_modbus_server.py - minimal Modbus/TCP server (stdlib socket) -> serial bus.
#
# pymodbus is not in the OpenWRT feed, so the Pi-side server is hand-rolled on the
# standard library. It implements the function codes the cloud master uses:
#   0x03 read holding registers, 0x06 write single, 0x10 write multiple.
# Modbus has no authentication by design, which is the point. [IoT:I2]
#
# Register map (see docs/OctoBot/OPENWRT_INTEGRATION.md Section 5):
#   40001-40004  base/left/right/claw angle (R/W)   -> offsets 0-3
#   40005        command: 1=RECORD 2=PLAY 3=STOP 4=DEMO (W) -> offset 4
#   40006        speed 1-10 (R/W)                   -> offset 5
import os
import socket
import struct
import threading

BUS_HOST = '127.0.0.1'
BUS_PORT = int(os.environ.get('OCTOBOT_BUS_PORT', '2000'))
MODBUS_PORT = int(os.environ.get('OCTOBOT_MODBUS_PORT', '502'))
ANGLES_FILE = '/tmp/octobot/angles'
MIN_ANGLE = [0, 10, 40, 0]
MAX_ANGLE = [180, 140, 170, 20]

# holding registers: 40001-40004 command angles, 40005 command, 40006 speed,
# 40011-40014 actual feedback angles (initialised to the arm's power-on pose).
regs = [90, 90, 90, 20, 0, 1, 0, 0, 0, 0] + [90, 90, 90, 20] + [0] * 6   # pose at 40011-40014 (offsets 10-13)
lock = threading.Lock()


def refresh_feedback():
    """Pull actual servo angles from serial_bus.py into feedback registers 40011-40014."""
    try:
        with open(ANGLES_FILE, 'r') as f:
            parts = f.read().strip().split(',')
        if len(parts) == 4:
            with lock:
                for i in range(4):
                    regs[10 + i] = int(parts[i])
    except (OSError, ValueError):
        pass


def bus_send(cmd):
    if not cmd:
        return
    try:
        with socket.create_connection((BUS_HOST, BUS_PORT), timeout=2) as s:
            s.sendall((cmd + '\n').encode())
    except OSError:
        pass


def write_reg(addr, val):
    val &= 0xFFFF
    with lock:
        if 0 <= addr < len(regs):
            regs[addr] = val
    if 0 <= addr <= 3:
        clamped = max(MIN_ANGLE[addr], min(val, MAX_ANGLE[addr]))
        bus_send(f'S{addr}:{clamped}')
        with lock:
            regs[addr + 10] = clamped   # mirror current angle feedback register
    elif addr == 4:
        bus_send({1: 'RECORD', 2: 'PLAY', 3: 'STOP', 4: 'DEMO'}.get(val, ''))
    elif addr == 5:
        bus_send(f'SPD:{max(1, min(val, 10))}')


def build_pdu(req):
    """req = PDU bytes (function code + data). Returns response PDU."""
    fc = req[0]
    if fc == 0x03:                                   # read holding registers
        start, qty = struct.unpack('>HH', req[1:5])
        refresh_feedback()                            # update 40011-40014 from serial_bus
        with lock:
            vals = [regs[start + i] if 0 <= start + i < len(regs) else 0
                    for i in range(qty)]
        body = b''.join(struct.pack('>H', v) for v in vals)
        return struct.pack('>BB', 0x03, len(body)) + body
    if fc == 0x06:                                   # write single register
        addr, val = struct.unpack('>HH', req[1:5])
        write_reg(addr, val)
        return req                                   # echo
    if fc == 0x10:                                   # write multiple registers
        start, qty = struct.unpack('>HH', req[1:5])
        for i in range(qty):
            write_reg(start + i, struct.unpack('>H', req[6 + i * 2:8 + i * 2])[0])
        return struct.pack('>BHH', 0x10, start, qty)
    return struct.pack('>BB', fc | 0x80, 0x01)       # illegal function


def recvn(conn, n):
    buf = b''
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return b''
        buf += chunk
    return buf


def handle(conn):
    try:
        while True:
            hdr = recvn(conn, 7)                      # MBAP: tid, pid, len, unit
            if len(hdr) < 7:
                break
            tid, _pid, length, unit = struct.unpack('>HHHB', hdr)
            req = recvn(conn, length - 1)             # length counts unit + PDU
            if not req:
                break
            resp = build_pdu(req)
            conn.sendall(struct.pack('>HHHB', tid, 0, len(resp) + 1, unit) + resp)
    except OSError:
        pass
    finally:
        conn.close()


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('0.0.0.0', MODBUS_PORT))               # [IoT:I2] no auth by design
    srv.listen(8)
    print(f'Modbus/TCP arm gateway on :{MODBUS_PORT}')
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == '__main__':
    main()
