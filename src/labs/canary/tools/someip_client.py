#!/usr/bin/env python3
# someip_client.py - PC-side reference control client for canary CentralLockingService.
#
# Usage: someip_client.py <host> lock|unlock|state [token]
#   someip_client.py 192.168.2.1 lock AGL-HEADUNIT-7c2f
#   someip_client.py 192.168.2.1 state
#
# The legitimate head unit holds the SetLock token; lock/unlock require it (the
# gateway rejects a tokenless SetLock). state is read-only and needs no token. NOT
# part of the deployed vehicle image (lives under tools/, outside files/). Port
# override via CANARY_SOMEIP_PORT.
import os
import socket
import struct
import sys

SERVICE_ID = 0x1401
M_SETLOCK = 0x0001
M_GETSTATE = 0x0002
MT_REQUEST = 0x00
MT_ERROR = 0x81


def pack(method, payload=b''):
    msg_id = (SERVICE_ID << 16) | method
    length = 8 + len(payload)
    return struct.pack('>IIIBBBB', msg_id, length, 0x00010001, 1, 1, MT_REQUEST, 0) + payload


def state_byte(pkt):
    length = struct.unpack('>I', pkt[4:8])[0]
    return pkt[16:16 + (length - 8)]


def main():
    if len(sys.argv) < 3:
        print('usage: someip_client.py <host> lock|unlock|state [token]')
        return
    host, action = sys.argv[1], sys.argv[2]
    token = sys.argv[3].encode() if len(sys.argv) > 3 else b''
    port = int(os.environ.get('CANARY_SOMEIP_PORT', '30509'))
    if action == 'lock':
        req = pack(M_SETLOCK, token + b'\x01')
    elif action == 'unlock':
        req = pack(M_SETLOCK, token + b'\x00')
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
    if resp[14] == MT_ERROR:
        print('rejected (bad or missing token)')
        return
    val = state_byte(resp)
    print('locked' if val and val[0] else 'unlocked')


if __name__ == '__main__':
    main()
