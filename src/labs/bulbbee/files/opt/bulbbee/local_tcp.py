#!/usr/bin/env python3
"""BulbBee LAN/TCP local control plane (BULB-A4).

A Tuya-style local control port on :6668. The app (or an attacker) on the LAN
sends AES-CCM framed commands, which are relayed to the lighting daemon through
the BULB-A1 adapter (bulb_client -> single-owner :8082). Frames are
`nonce(11) || ciphertext || tag(16)`, each prefixed with a 2-byte big-endian
length.

Local key (vuln-consistent):
  default (secure=false): a static 16-byte key hardcoded in firmware, recoverable
                          from a shared image (the BULB-03 substrate). Proximity +
                          this key = control (the BULB-06 substrate).
  secure  (secure=true) : a per-device key derived from the per-device secret,
                          not recoverable from a shared firmware image.

Crypto is Crypto.Cipher.AES (python3-cryptodome), guarded like CareOtter so the
pure logic is testable and a missing dep degrades to a clean exit.
"""
import hashlib
import hmac
import json
import os
import socketserver
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bulb_client
import session_token

try:
    from Crypto.Cipher import AES
    _HAS_AES = True
except ImportError:
    _HAS_AES = False

CONFIG_PATH = os.environ.get("BULBBEE_CONFIG", "/opt/bulbbee/config.json")
LIGHT_KEYS = ("power", "brightness", "color", "scene")
LAN_PORT = 6668
NONCE_LEN = 11
TAG_LEN = 16
# BULB-03 substrate: identical 16-byte key in every device's firmware.
STATIC_LOCAL_KEY = b"bulbbee-local-16"


def derive_key(device_id, secure):
    if not secure:
        return STATIC_LOCAL_KEY
    secret = session_token._load_or_create_secret()
    return hmac.new(secret, ("lan:%s" % device_id).encode(), hashlib.sha256).digest()[:16]


def encrypt_frame(key, plaintext):
    nonce = os.urandom(NONCE_LEN)
    cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=TAG_LEN)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return nonce + ct + tag


def decrypt_frame(key, frame):
    """Return the plaintext, or None if the frame is malformed or fails the CCM
    authentication tag."""
    if len(frame) < NONCE_LEN + TAG_LEN:
        return None
    nonce, ct, tag = frame[:NONCE_LEN], frame[NONCE_LEN:-TAG_LEN], frame[-TAG_LEN:]
    cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=TAG_LEN)
    try:
        return cipher.decrypt_and_verify(ct, tag)
    except ValueError:
        return None


def parse_command(plaintext):
    """Pure: decrypted bytes -> the lighting command dict, or None."""
    try:
        msg = json.loads(plaintext.decode() if isinstance(plaintext, (bytes, bytearray)) else plaintext)
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(msg, dict):
        return None
    cmd = {k: msg[k] for k in LIGHT_KEYS if k in msg}
    return cmd or None


def _load_config():
    cfg = {"http_port": 8082, "secure": False, "device_id": ""}
    try:
        with open(CONFIG_PATH) as f:
            cfg.update(json.load(f))
    except (OSError, ValueError):
        pass
    if not cfg.get("device_id"):
        cfg["device_id"] = session_token.device_serial()
    return cfg


def _log(msg):
    print("[lan] %s" % msg, flush=True)


def _recvall(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        key = self.server.key
        client = self.server.client
        while True:
            hdr = _recvall(self.request, 2)
            if not hdr:
                return
            (n,) = struct.unpack(">H", hdr)
            frame = _recvall(self.request, n)
            if frame is None:
                return
            pt = decrypt_frame(key, frame)
            if pt is None:
                _log("frame failed AES-CCM auth")
                continue
            cmd = parse_command(pt)
            if cmd is None:
                continue
            try:
                client.apply(cmd)
                reply = encrypt_frame(key, json.dumps(client.state()).encode())
                self.request.sendall(struct.pack(">H", len(reply)) + reply)
            except Exception as e:                 # daemon transiently down — tolerate
                _log("apply/reply failed (%s)" % e)


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def run():
    if not _HAS_AES:
        _log("pycryptodome not available — cannot open LAN plane, exiting")
        sys.exit(1)
    cfg = _load_config()
    secure = bool(cfg.get("secure"))
    srv = _Server(("0.0.0.0", LAN_PORT), _Handler)
    srv.key = derive_key(cfg["device_id"], secure)
    srv.client = bulb_client.BulbClient(port=int(cfg.get("http_port", 8082)))
    _log("LAN/TCP plane listening on :%d (secure=%s)" % (LAN_PORT, secure))
    srv.serve_forever()


def _selfcheck():
    assert len(STATIC_LOCAL_KEY) == 16
    assert derive_key("dev-A", False) == STATIC_LOCAL_KEY
    k_sec = derive_key("dev-A", True)
    assert len(k_sec) == 16 and k_sec != STATIC_LOCAL_KEY
    assert parse_command(b'{"scene":"rainbow","junk":1}') == {"scene": "rainbow"}
    assert parse_command(b'not json') is None
    assert parse_command(b'{"nothing":1}') is None
    if _HAS_AES:
        f = encrypt_frame(STATIC_LOCAL_KEY, b'{"scene":"solid"}')
        assert decrypt_frame(STATIC_LOCAL_KEY, f) == b'{"scene":"solid"}'      # round-trip
        bad = bytearray(f); bad[-1] ^= 0x01
        assert decrypt_frame(STATIC_LOCAL_KEY, bytes(bad)) is None             # tampered -> None
        assert decrypt_frame(k_sec, f) is None                                 # BULB-03: static frame not readable under per-device key
        assert decrypt_frame(STATIC_LOCAL_KEY, b"short") is None               # malformed
        print("local_tcp selfcheck OK (crypto)")
    else:
        print("local_tcp selfcheck OK (pure only; pycryptodome absent)")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--selfcheck":
        _selfcheck()
    else:
        run()
