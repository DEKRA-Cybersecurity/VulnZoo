#!/usr/bin/env python3
# serial_bus.py - OctoBot serial broker.
#
# Single owner of the Arduino serial device (a tty is exclusive-open, so exactly
# one process may hold it). Replaces the ser2net binary: ser2net cannot fabricate
# a port when no arm is attached, but this lab must load on a bare Pi, so the
# broker falls back to a SimSerial stand-in.
#
# It binds a raw line protocol on 0.0.0.0:2000. Any LAN host can reach it, but
# movement commands must now carry the hardcoded prefix PASS:OctoSuperBot2026;
# the broker no longer auto-injects it. The gateway / Modbus / MQTT services
# forward to it over loopback with the prefix already added. This IS the
# IoT:I2 serial-over-IP vector.
#
# Additionally reads the Arduino's ANG:base,left,right,claw reports and writes
# them to /tmp/octobot/angles so the Modbus feedback registers reflect the real
# servo positions.
#
# The actuator password is hardcoded on both sides and is the IoT:I1 vector.
import os
import socket
import threading
import datetime
import time

try:
    import paho.mqtt.publish as mqtt_publish
except ImportError:
    mqtt_publish = None

SERIAL_DEV   = os.environ.get('OCTOBOT_SERIAL', '/dev/ttyUSB0')
BAUD         = int(os.environ.get('OCTOBOT_BAUD', '115200'))
BUS_PORT     = int(os.environ.get('OCTOBOT_BUS_PORT', '2000'))
USE_HW       = os.environ.get('OCTOBOT_USE_HW', '0') == '1'
LOG_PATH     = os.environ.get('OCTOBOT_LOG', '/tmp/octobot/operator.log')
ANGLES_FILE  = '/tmp/octobot/angles'
MQTT_HOST    = os.environ.get('OCTOBOT_MQTT', '127.0.0.1')
TELEMETRY_TOPIC = os.environ.get('OCTOBOT_TELEMETRY_TOPIC', 'cell01/cmd/telemetry')

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


def check_password(cmd):
    prefix = f'PASS:{HARD_CODED_PASSWORD} '
    cmd = cmd.strip()
    if cmd.startswith(prefix):
        return cmd[len(prefix):]
    return None


def require_password(cmd):
    """Return (stripped_command, ok). Movement frames without PASS: are rejected."""
    cmd = cmd.strip()
    stripped = check_password(cmd)
    if stripped is not None:
        return stripped, True
    if is_movement(cmd):
        return cmd, False
    # Non-movement frames are passed through unchanged.
    return cmd, True


def _mqtt_telemetry(cmd):
    # [IoT:I2] [IoT:I7] Every command that reaches the serial bus is echoed to an
    # unauthenticated MQTT telemetry topic. The intention is operational logging,
    # but it leaks the command format and timing to any anonymous subscriber.
    if mqtt_publish is None:
        return
    try:
        mqtt_publish.single(TELEMETRY_TOPIC, payload=cmd.strip(), hostname=MQTT_HOST, port=1883)
    except Exception:
        pass


def forward(cmd, client='-', conn=None):
    cmd = cmd.strip()
    if not cmd:
        return
    log(client, cmd)
    payload, ok = require_password(cmd)
    if not ok:
        # [IoT:I1] password required on the raw serial bus; the auth-failure reply
        # leaks the hardcoded actuator password itself (the docs' :2000 leak vector).
        if conn is not None:
            try:
                conn.sendall(
                    f'ERR AUTH: movement commands require PASS:{HARD_CODED_PASSWORD} <cmd>\r\n'.encode()
                )
            except OSError:
                pass
        return
    # [IoT:I2] [IoT:I7] Echo the accepted command to the MQTT telemetry topic.
    _mqtt_telemetry(payload)
    with ser_lock:
        # The Arduino still expects PASS:... on the wire, so re-add the prefix.
        ser.write((f'PASS:{HARD_CODED_PASSWORD} {payload}\n').encode())  # [IoT:I7] cleartext serial bus + [IoT:I1] password


def handle(conn, addr):
    client = addr[0]
    try:
        conn.sendall(b'OctoBot serial bus\r\n')
        for line in conn.makefile('r'):            # [IoT:I2] reachable without auth, but movement needs PASS:
            forward(line, client, conn)
    except OSError:
        pass
    finally:
        conn.close()


def serial_reader():
    """Read ANG:base,left,right,claw reports from the real Arduino and persist them."""
    # Seed the feedback file immediately so Modbus feedback registers start valid.
    update_angles(current_angles)
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
            # Swallow transient read errors instead of killing the reader thread;
            # a permanent device failure will simply leave the file at the last
            # known angles and the operator log will show forwarded commands still
            # reaching the arm.
        except OSError:
            pass
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
