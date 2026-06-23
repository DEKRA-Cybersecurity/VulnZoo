#!/usr/bin/env python3
# serial_bus.py - OctoBot serial broker.
#
# Single owner of the Arduino serial device (a tty is exclusive-open, so exactly
# one process may hold it). Replaces the ser2net binary: ser2net cannot fabricate
# a port when no arm is attached, but this lab must load on a bare Pi, so the
# broker falls back to a SimSerial stand-in.
#
# It binds a raw, UNAUTHENTICATED line protocol on 0.0.0.0:2000. Any LAN host can
# drive the arm by sending "Sx:angle\n"; the gateway / Modbus / MQTT services
# forward to it over loopback. This IS the IoT:I2 serial-over-IP vector.
#
# Additionally reads the Arduino's ANG:base,left,right,claw reports and writes
# them to /tmp/octobot/angles so the Modbus feedback registers reflect the real
# servo positions.
#
# Movement commands forwarded to the real Arduino are prefixed with
# PASS:OctoSuperBot2026 so the firmware authenticates them. The password is
# hardcoded on both sides and is the IoT:I1 vector.
import os
import socket
import threading
import datetime
import time

SERIAL_DEV   = os.environ.get('OCTOBOT_SERIAL', '/dev/ttyACM0')
BAUD         = int(os.environ.get('OCTOBOT_BAUD', '115200'))
BUS_PORT     = int(os.environ.get('OCTOBOT_BUS_PORT', '2000'))
USE_HW       = os.environ.get('OCTOBOT_USE_HW', '0') == '1'
LOG_PATH     = os.environ.get('OCTOBOT_LOG', '/tmp/octobot/operator.log')
ANGLES_FILE  = '/tmp/octobot/angles'

# Hardcoded actuator password shared with the Arduino firmware. [IoT:I1]
HARD_CODED_PASSWORD = 'OctoSuperBot2026'
MOVEMENT_PREFIXES = ('S0:', 'S1:', 'S2:', 'S3:', 'RECORD', 'PLAY', 'STOP', 'DEMO', 'SPD:')

# servo clamps mirror the firmware (base, left, right, claw)
MIN_ANGLE = [65, 80, 70, 5]
MAX_ANGLE = [135, 140, 120, 30]

# Shared actual servo angles, updated from firmware ANG: reports.
current_angles = [90, 90, 90, 30]
angles_lock = threading.Lock()


def update_angles(angles):
    """Persist the latest actual servo angles for the Modbus feedback registers."""
    global current_angles
    with angles_lock:
        current_angles = [int(a) for a in angles]
    try:
        os.makedirs(os.path.dirname(ANGLES_FILE), exist_ok=True)
        with open(ANGLES_FILE, 'w') as f:
            f.write(','.join(str(a) for a in current_angles))
    except OSError:
        pass


class SimSerial:
    """Stand-in when no Arduino is attached so the lab runs on a bare Pi."""
    def __init__(self):
        self.angle = [90, 90, 90, 30]
        self._buf = b''

    def write(self, data):
        self._buf += data
        while b'\n' in self._buf:
            line, self._buf = self._buf.split(b'\n', 1)
            self._apply(line.decode(errors='replace').strip())

    def _apply(self, cmd):
        stripped = check_password(cmd)
        if stripped is None and is_movement(cmd):
            return
        if stripped is not None:
            cmd = stripped
        if len(cmd) >= 4 and cmd[0] == 'S' and cmd[2] == ':':
            try:
                s, a = int(cmd[1]), int(cmd[3:])
            except ValueError:
                return
            if 0 <= s < 4:
                self.angle[s] = max(MIN_ANGLE[s], min(a, MAX_ANGLE[s]))
                update_angles(self.angle)


def open_serial():
    if USE_HW and os.path.exists(SERIAL_DEV):
        import serial  # pyserial, only needed with real hardware
        # Disable DTR/RTS so opening the tty does not reset the Arduino UNO
        # (the bootloader would swallow the first commands otherwise).
        ser = serial.Serial(SERIAL_DEV, BAUD, timeout=0.05)
        ser.dtr = False
        ser.rts = False
        return ser
    return SimSerial()


ser = open_serial()
ser_lock = threading.Lock()


def log(client, cmd):
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    ts = datetime.datetime.now().isoformat(timespec='seconds')
    with open(LOG_PATH, 'a') as f:                 # [IoT:I6] cleartext operator log
        f.write(f'{ts} {client} {cmd}\n')


def is_movement(cmd):
    return cmd.strip().startswith(MOVEMENT_PREFIXES)


def authenticate(cmd):
    cmd = cmd.strip()
    if is_movement(cmd):
        return f'PASS:{HARD_CODED_PASSWORD} {cmd}'
    return cmd


def check_password(cmd):
    prefix = f'PASS:{HARD_CODED_PASSWORD} '
    cmd = cmd.strip()
    if cmd.startswith(prefix):
        return cmd[len(prefix):]
    return None


def forward(cmd, client='-'):
    cmd = cmd.strip()
    if not cmd:
        return
    log(client, cmd)
    with ser_lock:
        ser.write((authenticate(cmd) + '\n').encode())  # [IoT:I7] cleartext serial bus + [IoT:I1] password


def handle(conn, addr):
    client = addr[0]
    try:
        conn.sendall(b'OctoBot serial bus\r\n')
        for line in conn.makefile('r'):            # [IoT:I2] no auth, raw forward
            forward(line, client)
    except OSError:
        pass
    finally:
        conn.close()


def serial_reader():
    """Read ANG:base,left,right,claw reports from the real Arduino and persist them."""
    buf = b''
    while True:
        try:
            chunk = b''
            with ser_lock:
                iw = getattr(ser, 'in_waiting', 0)
                if iw > 0:
                    chunk = ser.read(iw)
            if chunk:
                buf += chunk
                while b'\n' in buf:
                    line, buf = buf.split(b'\n', 1)
                    text = line.decode(errors='replace').strip()
                    if text.startswith('ANG:'):
                        parts = text[4:].split(',')
                        if len(parts) == 4:
                            update_angles([int(p) for p in parts])
        except OSError:
            break
        except Exception:
            pass
        time.sleep(0.02)


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('0.0.0.0', BUS_PORT))                # [IoT:I9] binds all interfaces
    srv.listen(8)
    print(f'serial bus :{BUS_PORT} dev={SERIAL_DEV} '
          f'hw={USE_HW and os.path.exists(SERIAL_DEV)}')
    if USE_HW and os.path.exists(SERIAL_DEV):
        threading.Thread(target=serial_reader, daemon=True).start()
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


if __name__ == '__main__':
    main()
