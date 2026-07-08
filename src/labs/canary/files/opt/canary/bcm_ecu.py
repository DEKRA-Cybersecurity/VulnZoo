#!/usr/bin/env python3
# bcm_ecu.py - canary Body Control Module (BCM) ECU.
#
# Listens on the CAN bus for LOCK_CMD (0x120), actuates the central lock, drives
# an optional indicator (state file + optional GPIO LED), and reports LOCK_STAT
# (0x121) on every change plus a 500 ms heartbeat so the bus is never silent.
#
# Phase 0: functional bring-up, no intentional vulnerabilities. Standard library
# only, raw AF_CAN sockets. Constants are duplicated from someip_gateway.py on
# purpose (house style: labs duplicate rather than share a module).
import os
import socket
import struct
import threading
import time

LOCK_CMD_ID = 0x120       # CGW -> BCM
LOCK_STAT_ID = 0x121      # BCM -> bus
CAN_FRAME_FMT = '=IB3x8s'  # struct can_frame: id, dlc, pad, data
HEARTBEAT_S = 0.5


def can_pack(can_id, data):
    return struct.pack(CAN_FRAME_FMT, can_id, len(data), data.ljust(8, b'\x00'))


def can_unpack(frame):
    can_id, dlc, data = struct.unpack(CAN_FRAME_FMT, frame)
    return can_id & 0x1FFFFFFF, data[:dlc]


def open_can(iface):
    s = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
    s.bind((iface,))
    return s


def drive_gpio(gpio, val):
    # ponytail: sysfs GPIO, best-effort. Deprecated but dependency-free and fine
    # for a single lock indicator LED. Switch to libgpiod if more pins are needed.
    base = '/sys/class/gpio'
    try:
        if not os.path.exists(f'{base}/gpio{gpio}'):
            with open(f'{base}/export', 'w') as f:
                f.write(gpio)
            with open(f'{base}/gpio{gpio}/direction', 'w') as f:
                f.write('out')
        with open(f'{base}/gpio{gpio}/value', 'w') as f:
            f.write('1' if val else '0')
    except OSError:
        pass


def write_state(path, gpio, lock):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as f:
            f.write('locked\n' if lock else 'unlocked\n')
    except OSError:
        pass
    if gpio:
        drive_gpio(gpio, lock)


def main():
    iface = os.environ.get('CANARY_IFACE', 'vcan0')
    state_path = os.environ.get('CANARY_STATE_PATH', '/tmp/canary/lock_state')
    gpio = os.environ.get('CANARY_INDICATOR_GPIO', '')
    can = open_can(iface)
    state = {'lock': 0}
    write_state(state_path, gpio, state['lock'])

    def heartbeat():
        while True:
            can.send(can_pack(LOCK_STAT_ID, bytes([state['lock']])))
            time.sleep(HEARTBEAT_S)

    threading.Thread(target=heartbeat, daemon=True).start()
    print(f'canary BCM iface={iface}')

    while True:
        can_id, data = can_unpack(can.recv(16))
        if can_id == LOCK_CMD_ID and data:
            state['lock'] = data[0] & 1
            write_state(state_path, gpio, state['lock'])
            can.send(can_pack(LOCK_STAT_ID, bytes([state['lock']])))


if __name__ == '__main__':
    main()
