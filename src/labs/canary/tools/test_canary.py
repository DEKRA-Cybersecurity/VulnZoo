#!/usr/bin/env python3
# test_canary.py - self-checks for the SOME/IP header, CAN frame packers, and the
# Jeep kill-chain gateway logic (AUTO-01/05/02). Run: python3 test_canary.py
# (no framework, asserts only).
import hashlib
import hmac
import os
import struct
import sys
import tempfile

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

# --- Jeep kill chain (AUTO-01/05/02) ---
pol = os.path.join(tempfile.mkdtemp(), 'gw_policy')
key = 'k'

# AUTO-01: legitimate SetLock is token-gated (this closes the front door).
assert g.check_token(b'\x01', 'TOK') == (False, 0)          # no token -> rejected
assert g.check_token(b'BAD\x01', 'TOK') == (False, 0)       # wrong token -> rejected
assert g.check_token(b'TOK\x01', 'TOK') == (True, 1)        # token + lock
assert g.check_token(b'TOK\x00', 'TOK') == (True, 0)        # token + unlock

# Invariant: no arbitrary CAN before the reflash (the RelayFrame gate reads this).
assert g.read_policy(pol)['allow_raw'] is False

# AUTO-05 (vulnerable): unsigned firmware is applied, signature never checked.
mal = b'\x00' * 32 + b'allow_raw=1'
assert g.apply_firmware(mal, 'vulnerable', key, pol) is True
assert g.read_policy(pol)['allow_raw'] is True             # gate now open -> RelayFrame works

# SECURE: the same unsigned firmware is rejected, the gate stays shut.
os.remove(pol)
assert g.apply_firmware(mal, 'secure', key, pol) is False
assert g.read_policy(pol)['allow_raw'] is False
# A correctly signed firmware is accepted in secure mode.
body = b'allow_raw=1'
sig = hmac.new(key.encode(), body, hashlib.sha256).digest()
assert g.apply_firmware(sig + body, 'secure', key, pol) is True

# Dynamic surface: the SD OfferService is well-formed and advertises the service at its endpoint.
sd = g.build_sd_offer('192.168.2.1', 30509)
svc, meth, mt, _c, _s, sdpl = g.someip_parse(sd)
assert (svc, meth, mt) == (g.SD_SERVICE, g.SD_METHOD, g.MT_NOTIFICATION), (svc, meth, mt)
assert struct.pack('>H', g.SERVICE_ID) in sdpl and struct.pack('>H', 30509) in sdpl

print('OK')
