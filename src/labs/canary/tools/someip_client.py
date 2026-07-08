#!/usr/bin/env python3
# someip_client.py - PC-side reference control client for canary CentralLockingService.
#
# Usage: someip_client.py <host> lock|unlock|state [port]
#   someip_client.py 192.168.2.1 lock
#   someip_client.py 192.168.2.1 state
#
# This is the legitimate driver used to exercise phase 0 from the tester PC. It is
# NOT part of the deployed vehicle image (lives under tools/, outside files/). It
# is also the client whose SOME/IP calls a later phase's attacker replays or forges.
import socket
import struct
import sys

SERVICE_ID = 0x1401
M_SETLOCK = 0x0001
M_GETSTATE = 0x0002
MT_REQUEST = 0x00


def pack(method, payload=b''):
    msg_id = (SERVICE_ID << 16) | method
    length = 8 + len(payload)
    return struct.pack('>IIIBBBB', msg_id, length, 0x00010001, 1, 1, MT_REQUEST, 0) + payload


def state_byte(pkt):
    length = struct.unpack('>I', pkt[4:8])[0]
    return pkt[16:16 + (length - 8)]


def main():
    if len(sys.argv) < 3:
        print('usage: someip_client.py <host> lock|unlock|state [port]')
        return
    host, action = sys.argv[1], sys.argv[2]
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 30509
    if action == 'lock':
        req = pack(M_SETLOCK, b'\x01')
    elif action == 'unlock':
        req = pack(M_SETLOCK, b'\x00')
    elif action == 'state':
        req = pack(M_GETSTATE)
    else:
        print('action must be lock|unlock|state')
        return
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2)
    s.sendto(req, (host, port))
    try:
        resp, _ = s.recvfrom(1024)
    except socket.timeout:
        print('no response')
        return
    b = state_byte(resp)
    print('locked' if b and b[0] else 'unlocked')


if __name__ == '__main__':
    main()
