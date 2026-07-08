#!/usr/bin/env python3
# test_canary.py - round-trip checks for the SOME/IP header and CAN frame packers.
# Run: python3 test_canary.py   (no framework, asserts only)
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'files', 'opt', 'canary'))
import someip_gateway as g
import bcm_ecu as b

# SOME/IP header round-trips through pack/parse, including the Request ID (client, session).
hdr = g.someip_pack(g.SERVICE_ID, g.M_SETLOCK, g.MT_REQUEST, 1, 7, b'\x01')
service, method, mtype, client, session, payload = g.someip_parse(hdr)
assert (service, method, mtype, client, session, payload) == (g.SERVICE_ID, g.M_SETLOCK, g.MT_REQUEST, 1, 7, b'\x01'), \
    (service, method, mtype, client, session, payload)

# GetLockState has an empty payload (length 8).
assert g.someip_parse(g.someip_pack(g.SERVICE_ID, g.M_GETSTATE, g.MT_REQUEST, 1, 1))[5] == b''

# CAN frame round-trips through pack/unpack (16-byte struct can_frame).
frame = b.can_pack(0x120, b'\x01')
assert len(frame) == 16
cid, data = b.can_unpack(frame)
assert cid == 0x120 and data == b'\x01', (cid, data)

# Gateway and BCM agree on the CAN wire format (both duplicate it).
assert g.can_unpack(g.can_pack(0x121, b'\x00')) == (0x121, b'\x00')

print('OK')
