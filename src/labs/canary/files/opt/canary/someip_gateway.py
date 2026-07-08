#!/usr/bin/env python3
# someip_gateway.py - canary Central Gateway (CGW) ECU.
#
# Hosts the CentralLockingService over SOME/IP (UDP) on eth0 and bridges it to the
# CAN bus. A SetLock request is translated into a LOCK_CMD frame (0x120) on can0;
# LOCK_STAT frames (0x121) from the BCM are tracked as the current state and, if a
# static event target is configured, pushed as a LockStatus notification.
#
# Phase 0: functional bring-up, no intentional vulnerabilities. Standard library
# only (no vsomeip, no python-can): the SOME/IP header is a fixed 16-byte layout
# and CAN frames are raw AF_CAN sockets.
import os
import socket
import struct
import threading

# SOME/IP CentralLockingService (see stages/01_spec/output/canary-spec.md section 5)
SERVICE_ID = 0x1401
M_SETLOCK = 0x0001
M_GETSTATE = 0x0002
E_LOCKSTATUS = 0x8001
PROTO_VER = 0x01
IFACE_VER = 0x01
MT_REQUEST = 0x00
MT_RESPONSE = 0x80
MT_NOTIFICATION = 0x02

# CAN frame IDs (classic CAN, 11-bit)
LOCK_CMD_ID = 0x120       # CGW -> BCM
LOCK_STAT_ID = 0x121      # BCM -> bus
CAN_FRAME_FMT = '=IB3x8s'  # struct can_frame: id, dlc, pad, data


def someip_pack(service, method, mtype, client, session, payload=b''):
    msg_id = (service << 16) | method
    req_id = (client << 16) | session
    length = 8 + len(payload)   # request id (4) + proto/iface/type/ret (4) + payload
    return struct.pack('>IIIBBBB', msg_id, length, req_id,
                       PROTO_VER, IFACE_VER, mtype, 0) + payload


def someip_parse(pkt):
    msg_id, length, req_id, _p, _i, mtype, _r = struct.unpack('>IIIBBBB', pkt[:16])
    payload = pkt[16:16 + (length - 8)]
    return msg_id >> 16, msg_id & 0xFFFF, mtype, req_id >> 16, req_id & 0xFFFF, payload


def can_pack(can_id, data):
    return struct.pack(CAN_FRAME_FMT, can_id, len(data), data.ljust(8, b'\x00'))


def can_unpack(frame):
    can_id, dlc, data = struct.unpack(CAN_FRAME_FMT, frame)
    return can_id & 0x1FFFFFFF, data[:dlc]


def open_can(iface):
    s = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
    s.bind((iface,))
    return s


def send_event(udp, target, state):
    if not target:
        return
    host, _, port = target.partition(':')
    if not port:
        return
    pkt = someip_pack(SERVICE_ID, E_LOCKSTATUS, MT_NOTIFICATION, 1, 0, bytes([state]))
    try:
        udp.sendto(pkt, (host, int(port)))
    except OSError:
        pass


def main():
    iface = os.environ.get('CANARY_IFACE', 'vcan0')
    port = int(os.environ.get('CANARY_SOMEIP_PORT', '30509'))
    event_target = os.environ.get('CANARY_EVENT_TARGET', '')
    can = open_can(iface)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp.bind(('0.0.0.0', port))
    state = {'lock': 0}

    def reader():
        while True:
            can_id, data = can_unpack(can.recv(16))
            if can_id == LOCK_STAT_ID and data:
                new = data[0] & 1
                if new != state['lock']:
                    state['lock'] = new
                    send_event(udp, event_target, new)

    threading.Thread(target=reader, daemon=True).start()
    print(f'canary CGW someip :{port} iface={iface}')

    while True:
        pkt, addr = udp.recvfrom(1024)
        if len(pkt) < 16:
            continue
        service, method, mtype, client, session, payload = someip_parse(pkt)
        if service != SERVICE_ID or mtype != MT_REQUEST:
            continue
        # Echo the request's Request ID (client + session) so SOME/IP tooling can
        # correlate the response to its request.
        if method == M_SETLOCK and payload:
            val = payload[0] & 1
            can.send(can_pack(LOCK_CMD_ID, bytes([val])))
            udp.sendto(someip_pack(SERVICE_ID, M_SETLOCK, MT_RESPONSE, client, session, bytes([val])), addr)
        elif method == M_GETSTATE:
            udp.sendto(someip_pack(SERVICE_ID, M_GETSTATE, MT_RESPONSE, client, session, bytes([state['lock']])), addr)


if __name__ == '__main__':
    main()
