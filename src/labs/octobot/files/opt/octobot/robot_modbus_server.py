#!/usr/bin/env python3
# robot_modbus_server.py - minimal Modbus/TCP server (stdlib socket) -> serial bus.
#
# pymodbus is not in the OpenWRT feed, so the Pi-side server is hand-rolled on the
# standard library. It implements the function codes the cloud master uses:
#   0x03 read holding registers, 0x06 write single, 0x10 write multiple.
#
# Register map (see docs/OctoBot/OPENWRT_INTEGRATION.md Section 5):
#   40001-40004  base/left/right/claw angle (R/W)              -> offsets 0-3
#   40005        command: 1=RECORD 2=PLAY 3=STOP 4=DEMO (W)    -> offset 4
#   40006        speed 1-10 (R/W)                              -> offset 5
#   40021-40036  encrypted actuator password chars (W)        -> offsets 20-35
#   40037        auth status (R): 0=none 1=ok 2=bad            -> offset 36
#   40038-40053  cleartext password hint on auth failure (R)  -> offsets 37-52
#
# Command registers (0-5) are now gated: the cloud must write the XOR-encrypted
# password to 40021-40036 first. A missing/invalid password causes the server to
# write the cleartext password into 40038-40053 and return an exception response.
# This is intentional: the "encryption" is a fixed XOR key and the hint leak is
# the vulnerability surface for the exercise. [IoT:I1] [IoT:I2] [IoT:I7]
import os
import socket
import struct
import threading

BUS_HOST = '127.0.0.1'
BUS_PORT = int(os.environ.get('OCTOBOT_BUS_PORT', '2000'))
MODBUS_PORT = int(os.environ.get('OCTOBOT_MODBUS_PORT', '502'))
ANGLES_FILE = '/tmp/octobot/angles'
MIN_ANGLE = [65, 80, 70, 5]
MAX_ANGLE = [135, 140, 120, 30]

# Hardcoded actuator password shared with the Arduino firmware and serial bus. [IoT:I1]
HARD_CODED_PASSWORD = 'OctoSuperBot2026'
PWD_LEN = len(HARD_CODED_PASSWORD)
AUTH_KEY = 0x55          # fixed XOR "encryption" key
PWD_OFFSET = 20          # 40021
PWD_STATUS = 36          # 40037
PWD_HINT = 37            # 40038

# holding registers: 40001-40004 command angles, 40005 command, 40006 speed,
# 40011-40014 actual feedback angles, 40021-40036 encrypted password chars,
# 40037 auth status, 40038-40053 cleartext hint buffer.
regs = ([90, 90, 90, 30, 0, 1, 0, 0, 0, 0] +
        [90, 90, 90, 30] + [0] * 6 +
        [0] * PWD_LEN + [0] + [0] * PWD_LEN)
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


def encrypt_password(pwd):
    return [ord(c) ^ AUTH_KEY for c in pwd]


def decrypt_password(chars):
    return ''.join(chr(c ^ AUTH_KEY) for c in chars)


def check_auth():
    """Validate the encrypted password in registers 40021-40036. On failure, write
    the cleartext password into 40038-40053 as a hint."""
    with lock:
        chars = [regs[PWD_OFFSET + i] & 0xFF for i in range(PWD_LEN)]
        if decrypt_password(chars) == HARD_CODED_PASSWORD:
            regs[PWD_STATUS] = 1
            for i in range(PWD_LEN):
                regs[PWD_HINT + i] = 0
            return True
        regs[PWD_STATUS] = 2
        for i, c in enumerate(HARD_CODED_PASSWORD):
            regs[PWD_HINT + i] = ord(c)
        return False


def bus_send(cmd):
    if not cmd:
        return
    try:
        with socket.create_connection((BUS_HOST, BUS_PORT), timeout=2) as s:
            s.sendall((cmd + '\n').encode())
    except OSError:
        pass


def _clear_password_regs():
    """Zero the encrypted-password register block so each command must re-auth."""
    with lock:
        for i in range(PWD_LEN):
            regs[PWD_OFFSET + i] = 0


def write_reg(addr, val):
    """Write a holding register. Returns True if the write succeeded, False if a
    command register was written without valid auth (hint is written to regs).
    The encrypted-password registers are cleared after every command-register
    access so the password must be supplied for each individual command."""
    val &= 0xFFFF
    with lock:
        if 0 <= addr < len(regs):
            regs[addr] = val

    # Password and hint registers are passive storage; auth status is managed by check_auth().
    if PWD_OFFSET <= addr < PWD_OFFSET + PWD_LEN or addr == PWD_STATUS or PWD_HINT <= addr < PWD_HINT + PWD_LEN:
        return True

    # Command registers require validated actuator password.
    if 0 <= addr <= 3 or addr == 4 or addr == 5:
        try:
            if not check_auth():
                return False
            if 0 <= addr <= 3:
                clamped = max(MIN_ANGLE[addr], min(val, MAX_ANGLE[addr]))
                bus_send(f'PASS:{HARD_CODED_PASSWORD} S{addr}:{clamped}')
                with lock:
                    regs[addr + 10] = clamped   # mirror current angle feedback register
            elif addr == 4:
                bus_send(f'PASS:{HARD_CODED_PASSWORD} ' + {1: 'RECORD', 2: 'PLAY', 3: 'STOP', 4: 'DEMO'}.get(val, ''))
            elif addr == 5:
                bus_send(f'PASS:{HARD_CODED_PASSWORD} SPD:{max(1, min(val, 10))}')
            return True
        finally:
            # Force the next command to re-supply the encrypted password.
            _clear_password_regs()
    return True


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
        if not write_reg(addr, val):
            return struct.pack('>BB', fc | 0x80, 0x06)  # auth failure (repurposed slave device busy)
        return req                                   # echo
    if fc == 0x10:                                   # write multiple registers
        start, qty = struct.unpack('>HH', req[1:5])
        for i in range(qty):
            if not write_reg(start + i, struct.unpack('>H', req[6 + i * 2:8 + i * 2])[0]):
                return struct.pack('>BB', fc | 0x80, 0x06)  # auth failure
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
