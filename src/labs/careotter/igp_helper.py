#!/usr/bin/env python3
"""IGP v4 helper for CareOtter pentesting."""
import socket
import struct
import sys

MAGIC = 0x43415245
HOST = sys.argv[3] if len(sys.argv) > 3 else '192.168.2.1'
PORT = 9999


def igp(cmd: int, payload: bytes = b'') -> bytes:
    hdr = struct.pack('>IBBH', MAGIC, cmd, 0, len(payload))
    with socket.create_connection((HOST, PORT), timeout=5) as s:
        s.sendall(hdr + payload)
        return s.recv(4096)


if __name__ == '__main__':
    cmd = int(sys.argv[1], 0) if len(sys.argv) > 1 else 0x01
    payload = sys.argv[2].encode() if len(sys.argv) > 2 else b''
    print(igp(cmd, payload).decode('utf-8', errors='replace'))
