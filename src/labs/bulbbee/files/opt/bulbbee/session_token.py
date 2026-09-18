#!/usr/bin/env python3
"""BulbBee cloud session token (BULB-A3 issue/confirm, BULB-04 substrate).

The session token is the device's authority on the cloud tunnel: the device
presents it on connect and the cloud confirms it before relaying app commands.

  Default (vulnerable, the BULB-04 substrate): the signing key is derived only
  from the enumerable Pi serial plus a hardcoded vendor salt shipped in every
  device, so anyone who learns the (guessable) serial forges the device's
  authority.

  Secure (BULB-SEC): the key is a random per-device secret generated once and
  stored 0600 at /opt/bulbbee/.session_secret, rotatable, so the token cannot be
  forged from public device identifiers.

Stdlib only. HMAC-SHA256 over a base64url JSON body.
"""
import base64
import hashlib
import hmac
import json
import os
import time

SECRET_FILE = os.environ.get("BULBBEE_SECRET_FILE", "/opt/bulbbee/.session_secret")
VENDOR_SALT = "bulbbee-vendor-salt"     # BULB-04: identical in every device


def device_serial():
    """The Pi serial (enumerable), or a fallback. Guessable by design (BULB-04)."""
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith("Serial"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return "0000000000000000"


def _static_key(device_id):
    # BULB-04 substrate: key from the enumerable serial + a shared vendor salt.
    return hashlib.sha256(("%s:%s" % (VENDOR_SALT, device_id)).encode()).digest()


def _load_or_create_secret():
    try:
        with open(SECRET_FILE, "rb") as f:
            s = f.read().strip()
        if len(s) >= 32:
            return s
    except OSError:
        pass
    s = os.urandom(32).hex().encode()
    try:
        fd = os.open(SECRET_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.write(fd, s)
        os.close(fd)
    except OSError:
        pass
    return s


def _key(device_id, secure):
    return _load_or_create_secret() if secure else _static_key(device_id)


def _b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def issue(device_id, secure=False, ttl=3600, now=None):
    now = int(now if now is not None else time.time())
    body = json.dumps({"dev": device_id, "iat": now, "exp": now + ttl,
                       "nonce": os.urandom(8).hex()},
                      sort_keys=True, separators=(",", ":")).encode()
    sig = hmac.new(_key(device_id, secure), body, hashlib.sha256).hexdigest()
    return _b64(body) + "." + sig


def confirm(token, device_id, secure=False, now=None):
    """Return the token claims if the signature is valid and it is unexpired,
    else None."""
    now = int(now if now is not None else time.time())
    try:
        b64body, sig = token.rsplit(".", 1)
        body = _unb64(b64body)
    except (ValueError, TypeError):
        return None
    expect = hmac.new(_key(device_id, secure), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expect):
        return None
    try:
        claims = json.loads(body)
    except ValueError:
        return None
    if int(claims.get("exp", 0)) < now:
        return None
    return claims


def _selfcheck():
    t0 = 1_000_000
    # 1. issue -> confirm round-trip, tamper + expiry rejected
    tok = issue("dev-A", secure=False, ttl=100, now=t0)
    assert confirm(tok, "dev-A", secure=False, now=t0)["dev"] == "dev-A"
    assert confirm(tok, "dev-A", secure=False, now=t0 + 200) is None      # expired
    assert confirm(tok[:-1] + ("0" if tok[-1] != "0" else "1"),
                   "dev-A", secure=False, now=t0) is None                 # tampered sig
    # 2. BULB-04: default key derivable from the serial -> attacker forges it
    forged_body = json.dumps({"dev": "dev-A", "iat": t0, "exp": t0 + 100, "nonce": "00"},
                             sort_keys=True, separators=(",", ":")).encode()
    forged_sig = hmac.new(_static_key("dev-A"), forged_body, hashlib.sha256).hexdigest()
    forged = _b64(forged_body) + "." + forged_sig
    assert confirm(forged, "dev-A", secure=False, now=t0) is not None     # forge works (default)
    assert confirm(forged, "dev-A", secure=True, now=t0) is None          # forge fails (secure)
    # 3. secure per-device secret: cross-device token does not confirm
    import tempfile
    global SECRET_FILE
    d = tempfile.mkdtemp()
    SECRET_FILE = os.path.join(d, "secretA")
    tok_a = issue("dev-A", secure=True, ttl=100, now=t0)
    assert confirm(tok_a, "dev-A", secure=True, now=t0) is not None
    SECRET_FILE = os.path.join(d, "secretB")                              # different device
    assert confirm(tok_a, "dev-A", secure=True, now=t0) is None
    print("session_token selfcheck OK")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--selfcheck":
        _selfcheck()
    else:
        print(issue(device_serial(), secure=False))
